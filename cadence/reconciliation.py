from __future__ import annotations

import asyncio
import logging
from typing import Any

from collectors.auth_scanner import AuthScanner
from collectors.crontab_scanner import CrontabScanner
from collectors.file_scanner import FileScanner
from collectors.network_scanner import NetworkScanner
from collectors.process_scanner import ProcessScanner
from events.event import RawEvent
from events.queue import EventQueue

LOGGER = logging.getLogger(__name__)
PROMOTABLE_SEVERITIES = {"medium", "high", "critical"}

SCANNER_CLASSES = (
    ProcessScanner,
    CrontabScanner,
    FileScanner,
    NetworkScanner,
    AuthScanner,
)


async def run_reconciliation(
    queue: EventQueue,
    config: dict[str, Any],
    interval_seconds: float = 900,
) -> None:
    while True:
        await asyncio.sleep(interval_seconds)
        LOGGER.info("starting reconciliation sweep")

        for scanner_cls in SCANNER_CLASSES:
            scanner_name = scanner_cls.__name__
            scanner = scanner_cls(config)

            try:
                result = await asyncio.to_thread(_run_scanner, scanner)
            except Exception:
                LOGGER.exception("reconciliation scanner %s failed", scanner_name)
                continue

            findings = result.get("findings", []) if isinstance(result, dict) else []
            for finding in findings:
                if not isinstance(finding, dict):
                    continue
                severity = str(finding.get("severity", "")).lower()
                if severity not in PROMOTABLE_SEVERITIES:
                    continue

                event = _finding_to_event(scanner_name, finding)
                await queue.put(event)

        LOGGER.info("finished reconciliation sweep")


def _run_scanner(scanner: Any) -> dict[str, Any]:
    scan_method = getattr(scanner, "scan", None)
    if callable(scan_method):
        result = scan_method()
        return result if isinstance(result, dict) else {}

    collect_method = getattr(scanner, "collect", None)
    if callable(collect_method):
        return asyncio.run(collect_method())

    raise AttributeError(f"{scanner.__class__.__name__} does not implement scan() or collect()")


def _finding_to_event(scanner_name: str, finding: dict[str, Any]) -> RawEvent:
    evidence = finding.get("evidence", {})
    if not isinstance(evidence, dict):
        evidence = {"value": evidence}

    subject = {
        "pid": evidence.get("pid"),
        "ppid": evidence.get("ppid"),
        "uid": evidence.get("uid"),
        "binary": evidence.get("exe") or evidence.get("path") or scanner_name,
        "cmdline": evidence.get("line") or evidence.get("command") or finding.get("description", ""),
    }
    object_payload = {
        "path": evidence.get("path") or evidence.get("exe"),
        "dest_ip": evidence.get("remote_host") or evidence.get("source_ip"),
        "dest_port": evidence.get("remote_port"),
        "details": evidence,
    }

    return RawEvent(
        timestamp=_event_timestamp(finding),
        source="reconciliation",
        event_type=_event_type_for_finding(finding),
        subject=subject,
        object=object_payload,
        metadata={
            "scanner": scanner_name,
            "severity": finding.get("severity"),
            "category": finding.get("category"),
            "description": finding.get("description"),
            "tags": finding.get("tags", []),
        },
    )


def _event_timestamp(finding: dict[str, Any]):
    timestamp = finding.get("timestamp")
    if timestamp is None:
        from datetime import datetime, timezone

        return datetime.now(timezone.utc)

    from datetime import datetime, timezone

    if isinstance(timestamp, (int, float)):
        return datetime.fromtimestamp(float(timestamp), tz=timezone.utc)

    if isinstance(timestamp, str):
        try:
            parsed = datetime.fromisoformat(timestamp)
        except ValueError:
            return datetime.now(timezone.utc)
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)
        return parsed

    return datetime.now(timezone.utc)


def _event_type_for_finding(finding: dict[str, Any]) -> str:
    category = str(finding.get("category", "")).lower()
    tags = {str(tag).lower() for tag in finding.get("tags", [])}

    if category == "process":
        return "process_exec"
    if category == "network":
        return "net_connect"
    if category == "auth":
        return "priv_change"
    if category == "crontab" or "suspicious_cron" in tags:
        return "cron_change"
    if category == "service":
        return "service_change"
    return "file_write"
