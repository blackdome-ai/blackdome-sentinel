"""Authentication log scanner."""

from __future__ import annotations

import ipaddress
import math
import re
from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path

from .base import BaseCollector


class AuthScanner(BaseCollector):
    name = "auth_scanner"
    month_map = {
        "Jan": 1,
        "Feb": 2,
        "Mar": 3,
        "Apr": 4,
        "May": 5,
        "Jun": 6,
        "Jul": 7,
        "Aug": 8,
        "Sep": 9,
        "Oct": 10,
        "Nov": 11,
        "Dec": 12,
    }
    timestamp_pattern = re.compile(r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s(?P<clock>\d{2}:\d{2}:\d{2})\s")
    ip_pattern = re.compile(r"(?:(?:from|rhost=)\s*)(?P<ip>[0-9a-fA-F:.]+)")

    async def collect(self) -> dict:
        try:
            return await self.run_in_thread(self._collect_sync)
        except Exception as exc:  # pragma: no cover - defensive path
            self.logger.exception("Auth scanner failed")
            return self.build_error_result(str(exc))

    def _collect_sync(self) -> dict:
        window_seconds = self.scan_window_seconds()
        lines, source = self._load_recent_auth_lines(window_seconds)
        collectors_config = self.config.get("collectors", {}) if isinstance(self.config, dict) else {}
        configured_bad_ips = set(collectors_config.get("network_scanner", {}).get("known_bad_ips", [])) if isinstance(collectors_config, dict) else set()
        known_bad_ips = configured_bad_ips | self.load_hostile_ips()

        failed_logins = []
        successful_logins = []
        sudo_commands = []
        new_users = []

        for line in lines:
            ip = self._extract_ip(line)
            if "Failed password" in line:
                failed_logins.append({"source_ip": ip, "line": line})
            if "Accepted publickey" in line or "Accepted password" in line:
                method = "publickey" if "Accepted publickey" in line else "password"
                successful_logins.append({"source_ip": ip, "method": method, "line": line})
            if "sudo:" in line:
                sudo_commands.append({"line": line})
            if "useradd" in line or "adduser" in line:
                new_users.append({"line": line})

        failed_counts = Counter(item["source_ip"] for item in failed_logins if item["source_ip"])
        threshold = int(self.collector_config.get("brute_force_threshold", 20))

        findings = []
        for source_ip, count in failed_counts.most_common():
            if count <= threshold:
                continue
            findings.append(
                {
                    "severity": "critical",
                    "category": "auth",
                    "description": f"SSH brute force suspected: {count} failed logins from {source_ip} in the last {window_seconds}s",
                    "evidence": {"source_ip": source_ip, "count": count},
                    "tags": ["ssh_brute_force", "failed_password"],
                }
            )

        for event in successful_logins:
            source_ip = event["source_ip"]
            if not source_ip:
                continue
            if source_ip in known_bad_ips:
                severity = "critical"
                tags = ["known_bad_ip", f"accepted_{event['method']}"]
            elif self._is_public_ip(source_ip):
                severity = "medium"
                tags = ["public_ip_login", f"accepted_{event['method']}"]
            else:
                severity = "low"
                tags = [f"accepted_{event['method']}"]
            findings.append(
                {
                    "severity": severity,
                    "category": "auth",
                    "description": f"Successful SSH login via {event['method']} from {source_ip}",
                    "evidence": event,
                    "tags": tags,
                }
            )

        if sudo_commands:
            findings.append(
                {
                    "severity": "info",
                    "category": "auth",
                    "description": f"Observed {len(sudo_commands)} sudo activity entries in the last {window_seconds}s",
                    "evidence": {"count": len(sudo_commands), "sample": sudo_commands[:5]},
                    "tags": ["sudo_activity"],
                }
            )

        for event in new_users:
            findings.append(
                {
                    "severity": "high",
                    "category": "auth",
                    "description": "User creation activity detected in authentication logs",
                    "evidence": event,
                    "tags": ["useradd"],
                }
            )

        raw = {
            "log_source": source,
            "window_seconds": window_seconds,
            "failed_logins": failed_logins,
            "failed_by_ip": dict(failed_counts),
            "successful_logins": successful_logins,
            "sudo_commands": sudo_commands,
            "new_users": new_users,
            "known_bad_ips": sorted(known_bad_ips),
        }
        return self.build_result(findings, raw=raw)

    def _load_recent_auth_lines(self, window_seconds: int) -> tuple[list[str], str]:
        auth_log_path = Path("/var/log/auth.log")
        if auth_log_path.exists():
            result = self.run_command(["tail", "-n", "5000", str(auth_log_path)])
            cutoff = datetime.now().astimezone() - timedelta(seconds=window_seconds)
            filtered = [line for line in result["stdout"].splitlines() if self._is_recent_auth_line(line, cutoff)]
            return filtered, "auth.log"

        minutes = max(1, math.ceil(window_seconds / 60))
        result = self.run_command(["journalctl", "--since", f"{minutes} minutes ago", "--no-pager"])
        return [line for line in result["stdout"].splitlines() if line.strip()], "journalctl"

    def _is_recent_auth_line(self, line: str, cutoff: datetime) -> bool:
        match = self.timestamp_pattern.match(line)
        if not match:
            return False
        month = self.month_map.get(match.group("month"))
        if month is None:
            return False
        day = int(match.group("day"))
        clock = datetime.strptime(match.group("clock"), "%H:%M:%S").time()
        now = datetime.now().astimezone()
        try:
            candidate = now.replace(month=month, day=day, hour=clock.hour, minute=clock.minute, second=clock.second, microsecond=0)
        except ValueError:
            return False
        if candidate > now + timedelta(days=1):
            candidate = candidate.replace(year=candidate.year - 1)
        return candidate >= cutoff

    def _extract_ip(self, line: str) -> str | None:
        match = self.ip_pattern.search(line)
        if not match:
            return None
        return match.group("ip")

    @staticmethod
    def _is_public_ip(value: str) -> bool:
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            return False
        return not (address.is_private or address.is_loopback or address.is_link_local or address.is_reserved)
