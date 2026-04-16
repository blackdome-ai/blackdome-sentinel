from __future__ import annotations

import asyncio
from collections import defaultdict
from collections.abc import Iterable
from datetime import datetime, timezone
import logging
from pathlib import Path
import re
import shlex
from typing import Any

from events.event import RawEvent
from events.queue import EventQueue

LOGGER = logging.getLogger(__name__)

AUDIT_LOG_PATH = Path("/var/log/audit/audit.log")
MONITORED_KEYS = {
    "systemd_persist",
    "cron_persist",
    "rc_local",
    "initd_persist",
    "user_cron",
    "ssh_keys",
    "shell_rc",
}
CRITICAL_KEYS = {"systemd_persist", "ssh_keys"}
HIGH_KEYS = {"cron_persist", "user_cron", "initd_persist", "rc_local"}
ALLOWLISTED_COMMS = {
    "systemd",
    "systemd-udevd",
    "dpkg",
    "apt",
    "apt-get",
    "unattended-upgr",
    "packagekitd",
    "auditd",
    "auditctl",
    "aureport",
}

AUDIT_MSG_RE = re.compile(r"msg=audit\((?P<timestamp>\d+(?:\.\d+)?):(?P<serial>\d+)\)")
TOKEN_RE = re.compile(r"([A-Za-z0-9_-]+)=((?:\"(?:\\.|[^\"])*\")|(?:'(?:\\.|[^'])*')|[^\s]+)")


class AuditCollector:
    def __init__(
        self,
        queue: EventQueue,
        *,
        audit_log_path: Path | str = AUDIT_LOG_PATH,
        poll_interval: float = 1.0,
    ) -> None:
        self.queue = queue
        self.audit_log_path = Path(audit_log_path)
        self.poll_interval = poll_interval
        self._partial_records: dict[str, dict[str, Any]] = {}
        self._last_serial: str | None = None

    async def run(self) -> None:
        if not self.audit_log_path.exists():
            LOGGER.warning("%s does not exist; audit collector is disabled", self.audit_log_path)
            return

        position = self._initial_position()
        inode = self._current_inode()

        while True:
            try:
                current_inode = self._current_inode()
                if inode is not None and current_inode is not None and inode != current_inode:
                    inode = current_inode
                    position = 0

                position, events = self._read_new_records(position)
                for event in events:
                    await self.queue.put(event)
            except asyncio.CancelledError:
                raise
            except FileNotFoundError:
                LOGGER.warning("%s disappeared; waiting for audit log to return", self.audit_log_path)
                position = 0
                inode = None
            except Exception:
                LOGGER.exception("audit collector iteration failed")

            if inode is None:
                inode = self._current_inode()
            await asyncio.sleep(self.poll_interval)

    def _initial_position(self) -> int:
        try:
            return self.audit_log_path.stat().st_size
        except OSError:
            return 0

    def _current_inode(self) -> int | None:
        try:
            return self.audit_log_path.stat().st_ino
        except OSError:
            return None

    def _read_new_records(self, position: int) -> tuple[int, list[RawEvent]]:
        with self.audit_log_path.open("r", encoding="utf-8", errors="replace") as handle:
            handle.seek(position)
            chunk = handle.read()
            new_position = handle.tell()

        if not chunk:
            return new_position, []

        events: list[RawEvent] = []
        for line in chunk.splitlines():
            event = self._consume_line(line.strip())
            if event is not None:
                events.append(event)

        return new_position, events

    def _consume_line(self, line: str) -> RawEvent | None:
        if not line or "msg=audit(" not in line:
            return None

        header = AUDIT_MSG_RE.search(line)
        if header is None:
            return None

        serial = header.group("serial")
        completed_event: RawEvent | None = None
        if self._last_serial is not None and serial != self._last_serial:
            completed_event = self._finalize_record(self._last_serial)

        record = self._partial_records.setdefault(
            serial,
            {
                "timestamp": datetime.fromtimestamp(float(header.group("timestamp")), tz=timezone.utc),
                "serial": serial,
                "types": set(),
                "fields": defaultdict(list),
            },
        )

        record_type = self._extract_record_type(line)
        if record_type:
            record["types"].add(record_type)

        for key, value in _parse_tokens(line):
            if key == "msg":
                continue
            record["fields"][key].append(value)

        self._last_serial = serial

        if record_type == "EOE":
            return self._finalize_record(serial) or completed_event

        self._prune_partial_records()
        return completed_event

    def _build_event(self, record: dict[str, Any]) -> RawEvent | None:
        fields: dict[str, list[str]] = record["fields"]
        key = _last_non_null(fields.get("key", []))
        if key not in MONITORED_KEYS:
            return None

        comm = _last_non_null(fields.get("comm", [])) or ""
        if comm in ALLOWLISTED_COMMS:
            return None

        exe_path = _last_non_null(fields.get("exe", [])) or ""
        target_path = _select_target_path(fields.get("name", []), key)
        pid = _coerce_int(_last_non_null(fields.get("pid", [])))
        ppid = _coerce_int(_last_non_null(fields.get("ppid", [])))
        uid = _coerce_int(_last_non_null(fields.get("uid", [])))

        return RawEvent(
            timestamp=record["timestamp"],
            source="auditd",
            event_type="audit_file_write",
            subject={
                "pid": pid,
                "ppid": ppid,
                "uid": uid,
                "comm": comm,
                "binary": exe_path,
            },
            object={
                "exe_path": exe_path,
                "file_path": target_path,
                "audit_key": key,
            },
            metadata={
                "severity": _severity_for_key(key),
                "tags": [f"audit_{key}"],
                "audit_serial": record["serial"],
            },
        )

    def _extract_record_type(self, line: str) -> str:
        prefix, _, _ = line.partition(" ")
        if not prefix.startswith("type="):
            return ""
        return prefix.removeprefix("type=")

    def _prune_partial_records(self) -> None:
        if len(self._partial_records) <= 512:
            return

        cutoff = datetime.now(timezone.utc).timestamp() - 60
        stale_serials = [
            serial
            for serial, record in self._partial_records.items()
            if record["timestamp"].timestamp() < cutoff
        ]
        for serial in stale_serials:
            self._partial_records.pop(serial, None)

    def _finalize_record(self, serial: str) -> RawEvent | None:
        record = self._partial_records.pop(serial, None)
        if record is None:
            return None
        if not {"SYSCALL", "PATH"}.issubset(record["types"]):
            return None
        return self._build_event(record)


async def run_audit_collector(queue: EventQueue, interval: float = 1.0) -> None:
    collector = AuditCollector(queue, poll_interval=interval)
    await collector.run()


def _parse_tokens(line: str) -> Iterable[tuple[str, str]]:
    for key, raw_value in TOKEN_RE.findall(line):
        yield key, _unquote(raw_value)


def _unquote(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
        try:
            return shlex.split(value)[0]
        except ValueError:
            return value[1:-1]
    return value


def _last_non_null(values: Iterable[str]) -> str | None:
    for value in reversed(list(values)):
        if value and value != "(null)":
            return value
    return None


def _select_target_path(paths: Iterable[str], audit_key: str) -> str:
    candidates = [path for path in paths if path and path != "(null)"]
    if not candidates:
        return ""

    for path in reversed(candidates):
        if audit_key == "systemd_persist" and "/systemd/" in path:
            return path
        if audit_key in {"cron_persist", "user_cron"} and "cron" in path:
            return path
        if audit_key == "ssh_keys" and path.endswith("authorized_keys"):
            return path
        if audit_key == "shell_rc" and path in {"/root/.bashrc", "/root/.profile"}:
            return path
        if audit_key == "rc_local" and path.endswith("/etc/rc.local"):
            return path
        if audit_key == "initd_persist" and "/init.d/" in path:
            return path

    return candidates[-1]


def _coerce_int(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except ValueError:
        return None


def _severity_for_key(audit_key: str) -> str:
    if audit_key in CRITICAL_KEYS:
        return "critical"
    if audit_key in HIGH_KEYS:
        return "high"
    return "medium"
