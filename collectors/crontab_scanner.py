"""Crontab and persistence scanner."""

from __future__ import annotations

import re
from pathlib import Path

from .base import BaseCollector


class CrontabScanner(BaseCollector):
    name = "crontab_scanner"
    suspicious_patterns = [
        (re.compile(r"/tmp|/var/tmp|/dev/shm"), "high", "temp_path"),
        (re.compile(r"(curl|wget).*(bash|sh)", re.IGNORECASE), "critical", "download_exec"),
        (re.compile(r"\b(chattr|lsattr)\b", re.IGNORECASE), "high", "immutable_manipulation"),
        (re.compile(r"\b(base64\s+-d|nohup|nc\s+-e)\b", re.IGNORECASE), "high", "obfuscated_exec"),
        (re.compile(r"\b(python|perl|php)\b.*(-c|-r)", re.IGNORECASE), "medium", "inline_interpreter"),
    ]

    async def collect(self) -> dict:
        try:
            return await self.run_in_thread(self._collect_sync)
        except Exception as exc:  # pragma: no cover - defensive path
            self.logger.exception("Crontab scanner failed")
            return self.build_error_result(str(exc))

    def _collect_sync(self) -> dict:
        baseline = self.load_baseline()
        baseline_crontabs = baseline.get("crontabs", {}) if baseline else {}

        root_crontab_result = self.run_command(["crontab", "-l"])
        root_crontab = root_crontab_result["stdout"].strip() if root_crontab_result["ok"] else ""
        system_crontab = self.safe_read_text("/etc/crontab") or ""
        rc_local = self.safe_read_text("/etc/rc.local") or ""

        cron_d_files = {}
        cron_d_dir = Path("/etc/cron.d")
        if cron_d_dir.exists():
            for path in sorted(cron_d_dir.iterdir()):
                if path.is_file():
                    cron_d_files[str(path)] = self.safe_read_text(path) or ""

        init_d_entries = []
        init_d_dir = Path("/etc/init.d")
        if init_d_dir.exists():
            init_d_entries = sorted(path.name for path in init_d_dir.iterdir() if path.is_file())

        current_crontabs = {}
        if root_crontab:
            current_crontabs["user:root"] = {"sha256": self.sha256_text(root_crontab), "content": root_crontab}
        if Path("/etc/crontab").exists():
            current_crontabs["/etc/crontab"] = {"sha256": self.sha256_text(system_crontab), "content": system_crontab}
        for path, content in cron_d_files.items():
            current_crontabs[path] = {"sha256": self.sha256_text(content), "content": content}

        immutable_targets = ["/etc/crontab", "/etc/rc.local", "/var/spool/cron/crontabs/root", *cron_d_files.keys()]
        immutable_flags = self.list_immutable_flags(immutable_targets)

        findings = []
        if baseline_crontabs:
            for key in sorted(set(current_crontabs) - set(baseline_crontabs)):
                findings.append(
                    {
                        "severity": "low",
                        "category": "crontab",
                        "description": f"New cron persistence entry detected: {key}",
                        "evidence": {"path": key, "sha256": current_crontabs[key]["sha256"]},
                        "tags": ["new_crontab"],
                    }
                )
            for key in sorted(set(baseline_crontabs) - set(current_crontabs)):
                findings.append(
                    {
                        "severity": "medium",
                        "category": "crontab",
                        "description": f"Cron persistence entry missing from baseline: {key}",
                        "evidence": {"path": key},
                        "tags": ["removed_crontab"],
                    }
                )
            for key in sorted(set(current_crontabs) & set(baseline_crontabs)):
                if current_crontabs[key]["sha256"] != baseline_crontabs[key].get("sha256"):
                    findings.append(
                        {
                            "severity": "low",
                            "category": "crontab",
                            "description": f"Cron persistence entry changed from baseline: {key}",
                            "evidence": {"path": key, "sha256": current_crontabs[key]["sha256"]},
                            "tags": ["modified_crontab"],
                        }
                    )

            baseline_rc_local = baseline.get("rc_local", {}).get("sha256")
            rc_local_hash = self.sha256_text(rc_local) if rc_local else None
            if rc_local_hash and baseline_rc_local and rc_local_hash != baseline_rc_local:
                findings.append(
                    {
                        "severity": "low",
                        "category": "crontab",
                        "description": "rc.local contents changed from baseline",
                        "evidence": {"path": "/etc/rc.local", "sha256": rc_local_hash},
                        "tags": ["rc_local_changed"],
                    }
                )

        for path, attrs in immutable_flags.items():
            findings.append(
                {
                    "severity": "low",
                    "category": "crontab",
                    "description": f"Cron persistence file has immutable attributes: {path}",
                    "evidence": {"path": path, "attributes": attrs},
                    "tags": ["immutable_crontab"],
                }
            )

        locations = [("user:root", root_crontab), ("/etc/crontab", system_crontab)] + list(cron_d_files.items()) + [("/etc/rc.local", rc_local)]
        for location, content in locations:
            if not content:
                continue
            findings.extend(self._scan_suspicious_lines(location, content))

        raw = {
            "root_crontab": root_crontab,
            "system_crontab": system_crontab,
            "cron_d": cron_d_files,
            "init_d_entries": init_d_entries,
            "rc_local": rc_local,
            "immutable_flags": immutable_flags,
            "file_hashes": {key: value["sha256"] for key, value in current_crontabs.items()},
        }
        return self.build_result(findings, raw=raw)

    def _scan_suspicious_lines(self, location: str, content: str) -> list[dict]:
        findings = []
        for line_number, line in enumerate(content.splitlines(), start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if self.token_matches_process_whitelist(stripped):
                continue
            for pattern, severity, tag in self.suspicious_patterns:
                if not pattern.search(stripped):
                    continue
                findings.append(
                    {
                        "severity": severity,
                        "category": "crontab",
                        "description": f"Suspicious persistence command in {location}:{line_number}",
                        "evidence": {"path": location, "line_number": line_number, "line": stripped},
                        "tags": ["suspicious_cron", tag],
                    }
                )
        return findings
