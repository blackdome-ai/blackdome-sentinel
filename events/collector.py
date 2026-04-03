from __future__ import annotations

import asyncio
from contextlib import suppress
from datetime import datetime, timezone
import logging
import os
from pathlib import Path
import re
import shutil

from .event import RawEvent
from .queue import EventQueue

LOGGER = logging.getLogger(__name__)

SENSITIVE_PATHS = [
    "/etc/cron.d",
    "/etc/crontab",
    "/var/spool/cron",
    "/etc/systemd/system",
    "/usr/lib/systemd/system",
    "/etc/rc.local",
    "/etc/init.d",
    "/usr/bin",
    "/usr/sbin",
    "/usr/local/bin",
    "/etc/passwd",
    "/etc/shadow",
    "/root/.ssh/authorized_keys",
    "/root/.bashrc",
    "/root/.profile",
]

AUDIT_MSG_RE = re.compile(r"msg=audit\((?P<timestamp>\d+(?:\.\d+)?):(?P<serial>\d+)\)")
AUDIT_EXE_RE = re.compile(r'exe="(?P<exe>[^"]+)"')
AUDIT_PID_RE = re.compile(r"\bpid=(?P<pid>\d+)\b")
AUDIT_PPID_RE = re.compile(r"\bppid=(?P<ppid>\d+)\b")
AUDIT_UID_RE = re.compile(r"\buid=(?P<uid>\d+)\b")
AUDIT_ARG_RE = re.compile(r'\ba(?P<index>\d+)=(?P<value>"(?:\\.|[^"])*"|[^\s]+)')


async def run_proc_poller(queue: EventQueue, interval: float = 3.0) -> None:
    known_pids = _list_proc_pids()

    while True:
        await asyncio.sleep(interval)
        current_pids = _list_proc_pids()
        new_pids = sorted(current_pids - known_pids, key=int)

        for pid in new_pids:
            event = _build_proc_event(pid)
            if event is not None:
                await queue.put(event)

        known_pids = current_pids


async def run_inotify_watcher(queue: EventQueue) -> None:
    if shutil.which("inotifywait") is None:
        LOGGER.error("inotifywait not found; file watcher is disabled")
        return

    active_paths = [path for path in SENSITIVE_PATHS if Path(path).exists()]
    if not active_paths:
        LOGGER.warning("no sensitive paths exist for inotify watcher")
        return

    command = [
        "inotifywait",
        "-m",
        "-r",
        "-e",
        "create,modify,attrib,moved_to",
        "--format",
        "%T %w%f %e",
        "--timefmt",
        "%s",
        *active_paths,
    ]
    process = await asyncio.create_subprocess_exec(
        *command,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stderr_task = asyncio.create_task(
        _drain_subprocess_stream(process.stderr, logging.WARNING, "inotifywait")
    )

    try:
        while True:
            line = await process.stdout.readline()
            if not line:
                break

            event = _parse_inotify_line(line.decode("utf-8", errors="replace").strip())
            if event is not None:
                await queue.put(event)
    except asyncio.CancelledError:
        raise
    finally:
        await _shutdown_process(process)
        stderr_task.cancel()
        with suppress(asyncio.CancelledError):
            await stderr_task


async def run_auditd_tailer(queue: EventQueue) -> None:
    audit_log = Path("/var/log/audit/audit.log")
    if not audit_log.exists():
        LOGGER.warning("%s does not exist; auditd tailer is disabled", audit_log)
        return

    process = await asyncio.create_subprocess_exec(
        "tail",
        "-F",
        "-n",
        "0",
        str(audit_log),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stderr_task = asyncio.create_task(
        _drain_subprocess_stream(process.stderr, logging.WARNING, "audit-tail")
    )
    pending_execve: dict[str, str] = {}

    try:
        while True:
            line = await process.stdout.readline()
            if not line:
                break

            decoded = line.decode("utf-8", errors="replace").strip()
            if "type=EXECVE" in decoded:
                serial = _parse_audit_serial(decoded)
                if serial is not None:
                    cmdline = _parse_execve_cmdline(decoded)
                    if cmdline:
                        pending_execve[serial] = cmdline
                continue

            if "type=SYSCALL" not in decoded:
                continue

            event = _parse_audit_syscall(decoded, pending_execve)
            if event is not None:
                await queue.put(event)
    except asyncio.CancelledError:
        raise
    finally:
        await _shutdown_process(process)
        stderr_task.cancel()
        with suppress(asyncio.CancelledError):
            await stderr_task


def _list_proc_pids() -> set[str]:
    try:
        return {entry for entry in os.listdir("/proc") if entry.isdigit()}
    except OSError:
        return set()


def _build_proc_event(pid: str) -> RawEvent | None:
    proc_root = Path("/proc") / pid

    try:
        exe_path = os.readlink(proc_root / "exe")
        cmdline = _read_cmdline(proc_root / "cmdline")
        ppid, uid = _read_status_fields(proc_root / "status")
    except (FileNotFoundError, PermissionError, ProcessLookupError, OSError):
        return None

    return RawEvent(
        timestamp=datetime.now(timezone.utc),
        source="proc",
        event_type="process_exec",
        subject={
            "pid": int(pid),
            "ppid": ppid,
            "uid": uid,
            "binary": exe_path,
            "cmdline": cmdline,
        },
        object={"exe_path": exe_path},
        metadata={},
    )


def _read_cmdline(cmdline_path: Path) -> str:
    raw = cmdline_path.read_bytes()
    parts = [part.decode("utf-8", errors="replace") for part in raw.split(b"\0") if part]
    return " ".join(parts)


def _read_status_fields(status_path: Path) -> tuple[int | None, int | None]:
    ppid = None
    uid = None

    for line in status_path.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.startswith("PPid:"):
            fields = line.split()
            if len(fields) > 1:
                ppid = int(fields[1])
        elif line.startswith("Uid:"):
            fields = line.split()
            if len(fields) > 1:
                uid = int(fields[1])

    return ppid, uid


def _parse_inotify_line(line: str) -> RawEvent | None:
    if not line:
        return None

    try:
        timestamp_text, remainder = line.split(" ", 1)
        file_path, events = remainder.rsplit(" ", 1)
        timestamp = datetime.fromtimestamp(float(timestamp_text), tz=timezone.utc)
    except (OSError, ValueError):
        LOGGER.debug("failed to parse inotify output line: %s", line)
        return None

    return RawEvent(
        timestamp=timestamp,
        source="inotify",
        event_type="file_write",
        subject={
            "pid": None,
            "ppid": None,
            "uid": None,
            "binary": "inotifywait",
            "cmdline": "inotifywait -m -r",
        },
        object={
            "path": file_path,
            "events": events,
        },
        metadata={},
    )


def _parse_audit_serial(line: str) -> str | None:
    match = AUDIT_MSG_RE.search(line)
    if match is None:
        return None
    return match.group("serial")


def _parse_execve_cmdline(line: str) -> str:
    args: list[tuple[int, str]] = []

    for match in AUDIT_ARG_RE.finditer(line):
        value = match.group("value")
        if value.startswith('"') and value.endswith('"'):
            value = value[1:-1]
        args.append((int(match.group("index")), value.encode("utf-8").decode("unicode_escape")))

    args.sort(key=lambda item: item[0])
    return " ".join(value for _, value in args)


def _parse_audit_syscall(
    line: str,
    pending_execve: dict[str, str],
) -> RawEvent | None:
    header = AUDIT_MSG_RE.search(line)
    exe = AUDIT_EXE_RE.search(line)
    pid = AUDIT_PID_RE.search(line)
    ppid = AUDIT_PPID_RE.search(line)
    uid = AUDIT_UID_RE.search(line)

    if None in (header, exe, pid, ppid, uid):
        LOGGER.debug("failed to parse audit syscall line: %s", line)
        return None

    serial = header.group("serial")
    timestamp = datetime.fromtimestamp(float(header.group("timestamp")), tz=timezone.utc)
    exe_path = exe.group("exe")
    cmdline = pending_execve.pop(serial, "")

    return RawEvent(
        timestamp=timestamp,
        source="auditd",
        event_type="process_exec",
        subject={
            "pid": int(pid.group("pid")),
            "ppid": int(ppid.group("ppid")),
            "uid": int(uid.group("uid")),
            "binary": exe_path,
            "cmdline": cmdline,
        },
        object={"exe_path": exe_path},
        metadata={"audit_serial": serial},
    )


async def _drain_subprocess_stream(
    stream: asyncio.StreamReader | None,
    level: int,
    label: str,
) -> None:
    if stream is None:
        return

    while True:
        line = await stream.readline()
        if not line:
            return
        LOGGER.log(level, "%s: %s", label, line.decode("utf-8", errors="replace").strip())


async def _shutdown_process(process: asyncio.subprocess.Process) -> None:
    if process.returncode is not None:
        return

    process.terminate()
    with suppress(ProcessLookupError, TimeoutError):
        await asyncio.wait_for(process.wait(), timeout=2.0)

    if process.returncode is None:
        process.kill()
        with suppress(ProcessLookupError):
            await process.wait()
