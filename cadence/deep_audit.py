from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from hashlib import sha256
import logging
from pathlib import Path
import subprocess
from typing import Any

from events.event import RawEvent
from events.queue import EventQueue

LOGGER = logging.getLogger(__name__)


async def run_deep_audit(
    queue: EventQueue,
    config: dict[str, Any],
    interval_seconds: float = 21600,
) -> None:
    del config

    while True:
        await asyncio.sleep(interval_seconds)

        try:
            for event in await _audit_package_drift():
                await queue.put(event)
        except Exception:
            LOGGER.exception("deep audit package verification failed")

        try:
            event = await _audit_suid_binaries()
            if event is not None:
                await queue.put(event)
        except Exception:
            LOGGER.exception("deep audit suid sweep failed")

        try:
            event = await _audit_authorized_keys()
            if event is not None:
                await queue.put(event)
        except Exception:
            LOGGER.exception("deep audit authorized_keys check failed")


async def _audit_package_drift() -> list[RawEvent]:
    result = await asyncio.to_thread(
        subprocess.run,
        ["dpkg", "--verify"],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )

    events: list[RawEvent] = []
    for line in [line.strip() for line in result.stdout.splitlines() if line.strip()][:50]:
        events.append(
            RawEvent(
                timestamp=datetime.now(timezone.utc),
                source="reconciliation",
                event_type="package_drift",
                subject={
                    "pid": None,
                    "ppid": None,
                    "uid": 0,
                    "binary": "dpkg",
                    "cmdline": "dpkg --verify",
                },
                object={"package_drift": line},
                metadata={"check": "dpkg_verify"},
            )
        )
    return events


async def _audit_suid_binaries() -> RawEvent | None:
    result = await asyncio.to_thread(
        subprocess.run,
        ["find", "/usr", "/bin", "/sbin", "-perm", "-4000", "-type", "f"],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    binaries = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    if not binaries:
        return None

    return RawEvent(
        timestamp=datetime.now(timezone.utc),
        source="reconciliation",
        event_type="suid_audit",
        subject={
            "pid": None,
            "ppid": None,
            "uid": 0,
            "binary": "find",
            "cmdline": "find /usr /bin /sbin -perm -4000 -type f",
        },
        object={"paths": binaries},
        metadata={"count": len(binaries)},
    )


async def _audit_authorized_keys() -> RawEvent | None:
    path = Path("/root/.ssh/authorized_keys")
    digest = None

    if path.exists():
        digest = await asyncio.to_thread(_hash_file, path)

    return RawEvent(
        timestamp=datetime.now(timezone.utc),
        source="reconciliation",
        event_type="auth_keys_audit",
        subject={
            "pid": None,
            "ppid": None,
            "uid": 0,
            "binary": "authorized_keys_audit",
            "cmdline": "hash /root/.ssh/authorized_keys",
        },
        object={"path": str(path), "sha256": digest},
        metadata={"exists": path.exists()},
    )


def _hash_file(path: Path) -> str | None:
    digest = sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(8192), b""):
                digest.update(chunk)
    except OSError:
        return None
    return digest.hexdigest()
