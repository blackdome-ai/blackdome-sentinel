"""File integrity and persistence scanner."""

from __future__ import annotations

import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .base import BaseCollector


class FileScanner(BaseCollector):
    name = "file_scanner"
    temp_roots = ["/tmp", "/var/tmp", "/dev/shm"]
    immutable_sensitive_dirs = ["/etc/cron.d", "/etc/init.d", "/etc/ssh", "/etc/systemd", "/root/.ssh"]

    async def collect(self) -> dict:
        try:
            return await self.run_in_thread(self._collect_sync)
        except Exception as exc:  # pragma: no cover - defensive path
            self.logger.exception("File scanner failed")
            return self.build_error_result(str(exc))

    def _collect_sync(self) -> dict:
        baseline = self.load_baseline()
        baseline_bins = baseline.get("system_bins", {}) if baseline else {}
        baseline_authorized = baseline.get("authorized_keys", {}).get("/root/.ssh/authorized_keys") if baseline else None
        known_malware_hashes = self.known_malware_hashes()

        temp_exec_result = self.run_command(["find", *self.temp_roots, "-xdev", "-type", "f", "-executable", "-print"])
        temp_executables = sorted(path for path in temp_exec_result["stdout"].splitlines() if path.strip())
        temp_hashes = {path: self.sha256_file(path) for path in temp_executables}

        current_hashes = self._capture_system_hashes()
        if baseline_bins:
            new_files = sorted(path for path in current_hashes if path not in baseline_bins)
            modified_files = sorted(
                path for path in current_hashes if path in baseline_bins and self._extract_hash(current_hashes[path]) != self._extract_hash(baseline_bins[path])
            )
        else:
            new_files = []
            modified_files = []

        immutable_targets = [str(path) for path in Path("/usr/bin").iterdir() if path.is_file() or path.is_symlink()]
        immutable_targets.extend(str(path) for path in Path("/etc").iterdir() if path.is_file())
        for root in self.immutable_sensitive_dirs:
            root_path = Path(root)
            if not root_path.exists():
                continue
            immutable_targets.extend(str(path) for path in root_path.rglob("*") if path.is_file())
        immutable_flags = self.list_immutable_flags(immutable_targets)

        recent_sensitive_modifications = self._recently_modified_sensitive_files()
        authorized_keys_hash = self.sha256_file("/root/.ssh/authorized_keys")

        findings = []
        known_hash_hits = []
        for path, record in current_hashes.items():
            sha256 = self._extract_hash(record)
            if sha256 and sha256.lower() in known_malware_hashes:
                hit = {"path": path, "sha256": sha256}
                known_hash_hits.append(hit)
                findings.append(
                    {
                        "severity": "critical",
                        "category": "file",
                        "description": f"System binary matches known malware hash: {path}",
                        "evidence": hit,
                        "tags": ["known_malware_hash"],
                    }
                )

        for path, sha256 in temp_hashes.items():
            if sha256 and sha256.lower() in known_malware_hashes:
                hit = {"path": path, "sha256": sha256}
                known_hash_hits.append(hit)
                findings.append(
                    {
                        "severity": "critical",
                        "category": "file",
                        "description": f"Temporary executable matches known malware hash: {path}",
                        "evidence": hit,
                        "tags": ["known_malware_hash", "temp_executable"],
                    }
                )

        for path in temp_executables:
            if self.process_exe_whitelisted(path):
                continue
            findings.append(
                {
                    "severity": "high",
                    "category": "file",
                    "description": f"Executable file present in temporary directory: {path}",
                    "evidence": {"path": path, "sha256": temp_hashes.get(path)},
                    "tags": ["temp_executable"],
                }
            )
        for path in new_files:
            if self.process_exe_whitelisted(path):
                continue
            findings.append(
                {
                    "severity": "high",
                    "category": "file",
                    "description": f"New system binary not present in baseline: {path}",
                    "evidence": {"path": path, **self._ensure_record(current_hashes[path])},
                    "tags": ["new_binary"],
                }
            )
        for path in modified_files:
            if self.process_exe_whitelisted(path):
                continue
            findings.append(
                {
                    "severity": "high",
                    "category": "file",
                    "description": f"System binary hash changed from baseline: {path}",
                    "evidence": {"path": path, **self._ensure_record(current_hashes[path])},
                    "tags": ["modified_binary"],
                }
            )
        for path, attrs in immutable_flags.items():
            if self.process_exe_whitelisted(path):
                continue
            findings.append(
                {
                    "severity": "high",
                    "category": "file",
                    "description": f"File has immutable attributes set: {path}",
                    "evidence": {"path": path, "attributes": attrs},
                    "tags": ["immutable_file"],
                }
            )
        for entry in recent_sensitive_modifications[:50]:
            if self.process_exe_whitelisted(entry["path"]):
                continue
            findings.append(
                {
                    "severity": "medium" if entry["path"].startswith("/etc") else "high",
                    "category": "file",
                    "description": f"Sensitive file modified in the last 24 hours: {entry['path']}",
                    "evidence": entry,
                    "tags": ["recent_modification"],
                }
            )
        if authorized_keys_hash and baseline_authorized and authorized_keys_hash != baseline_authorized:
            findings.append(
                {
                    "severity": "high",
                    "category": "file",
                    "description": "/root/.ssh/authorized_keys changed from baseline",
                    "evidence": {"path": "/root/.ssh/authorized_keys", "sha256": authorized_keys_hash},
                    "tags": ["authorized_keys_changed"],
                }
            )

        raw = {
            "temp_executables": temp_executables,
            "temp_executable_hashes": temp_hashes,
            "current_system_hashes": current_hashes,
            "new_system_files": new_files,
            "modified_system_files": modified_files,
            "immutable_files": immutable_flags,
            "recent_sensitive_modifications": recent_sensitive_modifications,
            "authorized_keys_hash": authorized_keys_hash,
            "known_malware_hash_hits": known_hash_hits,
        }
        return self.build_result(findings, raw=raw)

    def _capture_system_hashes(self) -> dict[str, dict[str, Any]]:
        hashes: dict[str, dict[str, Any]] = {}
        for root in (Path("/usr/bin"), Path("/usr/sbin")):
            if not root.exists():
                continue
            for path in sorted(root.iterdir()):
                if not path.is_file() and not path.is_symlink():
                    continue
                hashes[str(path)] = self._best_effort_hash(path)
        return hashes

    def _best_effort_hash(self, path: Path) -> dict[str, Any]:
        try:
            if path.is_symlink():
                target = path.resolve(strict=False)
                if target.exists() and target.is_file():
                    return {"sha256": self.sha256_file(target) or f"unreadable:{target}"}
                return {"sha256": f"symlink:{path.readlink()}"}
            return {"sha256": self.sha256_file(path) or "unreadable"}
        except OSError as exc:
            return {"sha256": f"error:{exc.__class__.__name__}"}

    def _recently_modified_sensitive_files(self) -> list[dict]:
        cutoff = time.time() - 86400
        sensitive_roots = ["/usr/bin", "/usr/sbin", "/etc", "/root/.ssh"]
        recent = []
        for root in sensitive_roots:
            root_path = Path(root)
            if not root_path.exists():
                continue
            for current_root, _, filenames in os.walk(root, topdown=True):
                for filename in filenames:
                    path = Path(current_root) / filename
                    try:
                        stats = path.stat(follow_symlinks=False)
                    except OSError:
                        continue
                    if stats.st_mtime < cutoff:
                        continue
                    recent.append(
                        {
                            "path": str(path),
                            "modified_at": datetime.fromtimestamp(stats.st_mtime, tz=timezone.utc).isoformat(),
                            "size": stats.st_size,
                        }
                    )
        return sorted(recent, key=lambda item: item["modified_at"], reverse=True)

    @staticmethod
    def _extract_hash(value: Any) -> str | None:
        if isinstance(value, dict):
            hash_value = value.get("sha256")
            return str(hash_value) if hash_value else None
        if value is None:
            return None
        return str(value)

    def _ensure_record(self, value: Any) -> dict[str, Any]:
        if isinstance(value, dict):
            return dict(value)
        hash_value = self._extract_hash(value)
        return {"sha256": hash_value} if hash_value else {}
