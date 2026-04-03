"""Known-good baseline generation and drift detection."""

from __future__ import annotations

import fnmatch
import hashlib
import json
import logging
import pwd
import shutil
import socket
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .binary_verify import is_package_managed, verify_hash


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class BaselineGenerator:
    """Capture and diff a host baseline."""

    def __init__(self, project_root: str | Path | None = None, config: dict[str, Any] | None = None) -> None:
        self.project_root = Path(project_root) if project_root else PROJECT_ROOT
        self.config = config or {}
        self.logger = logging.getLogger(self.__class__.__name__)
        whitelist = self.config.get("whitelist", {}) if isinstance(self.config.get("whitelist"), dict) else {}
        self.kernel_ignore_patterns = [str(item) for item in whitelist.get("kernel_ignore_patterns", []) if str(item).strip()]

    def generate(self, include_verification: bool = False) -> dict[str, Any]:
        """Capture a full host baseline."""
        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "hostname": socket.gethostname(),
            "packages": self._capture_packages(),
            "system_bins": self._capture_system_binaries(include_verification=include_verification),
            "crontabs": self._capture_crontabs(),
            "enabled_services": self._capture_enabled_services(),
            "listening_ports": self._capture_listening_ports(),
            "authorized_keys": self._capture_authorized_keys(),
            "rc_local": self._capture_file_record(Path("/etc/rc.local")),
            "passwd": self._capture_file_record(Path("/etc/passwd")),
            "running_processes": self._capture_processes(),
        }

    generate_baseline = generate

    def save_baseline(self, baseline: dict[str, Any], path: str | Path) -> None:
        destination = Path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open("w", encoding="utf-8") as handle:
            json.dump(baseline, handle, indent=2, sort_keys=True)
            handle.write("\n")

    def load_baseline(self, path: str | Path) -> dict[str, Any]:
        baseline_path = Path(path)
        if not baseline_path.exists():
            return {}
        with baseline_path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
        return data if isinstance(data, dict) else {}

    def diff_baseline(self, current: dict[str, Any], baseline: dict[str, Any]) -> list[dict[str, str]]:
        if not baseline:
            return []

        current_processes = self._filter_ignored_processes(set(current.get("running_processes", [])))
        baseline_processes = self._filter_ignored_processes(set(baseline.get("running_processes", [])))

        changes: list[dict[str, str]] = []
        changes.extend(
            self._diff_set(
                category="process",
                label="process",
                current=current_processes,
                baseline=baseline_processes,
            )
        )
        changes.extend(
            self._diff_set(
                category="service",
                label="service",
                current=set(current.get("enabled_services", [])),
                baseline=set(baseline.get("enabled_services", [])),
            )
        )
        changes.extend(
            self._diff_set(
                category="port",
                label="listening port",
                current=set(current.get("listening_ports", [])),
                baseline=set(baseline.get("listening_ports", [])),
            )
        )
        changes.extend(
            self._diff_mapping_hashes(
                category="file",
                label="binary",
                current=current.get("system_bins", {}),
                baseline=baseline.get("system_bins", {}),
            )
        )
        changes.extend(
            self._diff_mapping_hashes(
                category="crontab",
                label="crontab",
                current=current.get("crontabs", {}),
                baseline=baseline.get("crontabs", {}),
            )
        )
        changes.extend(
            self._diff_mapping_hashes(
                category="file",
                label="authorized_keys",
                current=current.get("authorized_keys", {}),
                baseline=baseline.get("authorized_keys", {}),
            )
        )
        changes.extend(self._diff_scalar_hash("file", "package inventory", current.get("packages"), baseline.get("packages")))
        changes.extend(self._diff_scalar_hash("file", "/etc/rc.local", current.get("rc_local"), baseline.get("rc_local")))
        changes.extend(self._diff_scalar_hash("file", "/etc/passwd", current.get("passwd"), baseline.get("passwd")))
        return changes

    @staticmethod
    def file_hash(path: str | Path) -> str | None:
        file_path = Path(path)
        if not file_path.exists():
            return None
        digest = hashlib.sha256()
        with file_path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    def _capture_packages(self) -> dict[str, Any]:
        result = self._run_command(["dpkg", "-l"])
        return {
            "sha256": self._sha256_text(result),
            "source": "dpkg -l",
        }

    def _capture_system_binaries(self, include_verification: bool = False) -> dict[str, dict[str, Any]]:
        records: dict[str, dict[str, Any]] = {}
        for base_dir in (Path("/usr/bin"), Path("/usr/sbin")):
            if not base_dir.exists():
                continue
            for path in sorted(base_dir.iterdir()):
                if path.is_dir():
                    continue
                file_hash = self._best_effort_hash(path)
                record: dict[str, Any] = {"sha256": file_hash}
                if include_verification:
                    managed, package_name = is_package_managed(str(path))
                    record["package_managed"] = managed
                    record["package"] = package_name
                    verify_ok, verify_status = verify_hash(str(path)) if managed else (False, "unmanaged")
                    record["verify_ok"] = verify_ok
                    record["verify_status"] = verify_status
                records[str(path)] = record
        return records

    def _capture_crontabs(self) -> dict[str, dict[str, Any]]:
        crontabs: dict[str, dict[str, Any]] = {}

        for user in pwd.getpwall():
            username = user.pw_name
            result = subprocess.run(
                ["crontab", "-u", username, "-l"],
                capture_output=True,
                text=True,
                check=False,
            )
            if result.returncode == 0:
                content = result.stdout.strip()
                crontabs[f"user:{username}"] = {
                    "sha256": self._sha256_text(content),
                    "content": content,
                }

        for path in [Path("/etc/crontab"), *sorted(Path("/etc/cron.d").glob("*"))]:
            if path.is_file():
                content = path.read_text(encoding="utf-8", errors="replace")
                crontabs[str(path)] = {
                    "sha256": self._sha256_text(content),
                    "content": content,
                }

        return crontabs

    def _capture_enabled_services(self) -> list[str]:
        if shutil.which("systemctl") is None:
            return []
        result = subprocess.run(
            ["systemctl", "list-unit-files", "--state=enabled", "--type=service", "--no-legend", "--no-pager"],
            capture_output=True,
            text=True,
            check=False,
        )
        services: list[str] = []
        for raw_line in result.stdout.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            services.append(line.split()[0])
        return sorted(set(services))

    def _capture_listening_ports(self) -> list[str]:
        if shutil.which("ss") is None:
            return []
        result = subprocess.run(
            ["ss", "-lntupH"],
            capture_output=True,
            text=True,
            check=False,
        )
        ports: list[str] = []
        for raw_line in result.stdout.splitlines():
            parts = raw_line.split(None, 6)
            if len(parts) < 5:
                continue
            ports.append(f"{parts[0]}:{parts[4]}")
        return sorted(set(ports))

    def _capture_authorized_keys(self) -> dict[str, str]:
        hashes: dict[str, str] = {}
        candidate_paths = [Path("/root/.ssh/authorized_keys")]
        candidate_paths.extend(sorted(Path("/home").glob("*/.ssh/authorized_keys")))
        candidate_paths.extend(sorted(Path("/etc/ssh/authorized_keys").glob("*")) if Path("/etc/ssh/authorized_keys").exists() else [])

        for path in candidate_paths:
            if path.exists():
                file_hash = self.file_hash(path)
                if file_hash:
                    hashes[str(path)] = file_hash
        return hashes

    def _capture_processes(self) -> list[str]:
        result = subprocess.run(
            ["ps", "-eo", "comm,args", "--no-headers"],
            capture_output=True,
            text=True,
            check=False,
        )
        processes = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        return sorted(set(processes))

    def _capture_file_record(self, path: Path) -> dict[str, Any]:
        return {
            "path": str(path),
            "sha256": self.file_hash(path),
        }

    def _best_effort_hash(self, path: Path) -> str:
        try:
            if path.is_symlink():
                target = path.resolve(strict=False)
                if target.exists() and target.is_file():
                    return self.file_hash(target) or f"unreadable:{target}"
                return f"symlink:{path.readlink()}"
            return self.file_hash(path) or "unreadable"
        except OSError as exc:
            return f"error:{exc.__class__.__name__}"

    def _run_command(self, command: list[str]) -> str:
        result = subprocess.run(command, capture_output=True, text=True, check=False)
        if result.returncode != 0:
            self.logger.warning("Command failed: %s", " ".join(command))
        return result.stdout

    @staticmethod
    def _sha256_text(value: str) -> str:
        return hashlib.sha256(value.encode("utf-8")).hexdigest()

    def _filter_ignored_processes(self, values: set[str]) -> set[str]:
        if not self.kernel_ignore_patterns:
            return values
        filtered = set()
        for value in values:
            primary = value.split()[0] if value else ""
            if any(fnmatch.fnmatch(value, pattern) or fnmatch.fnmatch(primary, pattern) for pattern in self.kernel_ignore_patterns):
                continue
            filtered.add(value)
        return filtered

    @staticmethod
    def _diff_set(category: str, label: str, current: set[str], baseline: set[str]) -> list[dict[str, str]]:
        changes: list[dict[str, str]] = []
        for item in sorted(current - baseline):
            changes.append({"category": category, "type": "added", "detail": f"{label} added: {item}"})
        for item in sorted(baseline - current):
            changes.append({"category": category, "type": "removed", "detail": f"{label} removed: {item}"})
        return changes

    @staticmethod
    def _record_hash(value: Any) -> str | None:
        if isinstance(value, dict):
            if "sha256" in value and value["sha256"]:
                return str(value["sha256"])
            return hashlib.sha256(json.dumps(value, sort_keys=True).encode("utf-8")).hexdigest()
        if value is None:
            return None
        return str(value)

    def _diff_mapping_hashes(
        self,
        category: str,
        label: str,
        current: dict[str, Any],
        baseline: dict[str, Any],
    ) -> list[dict[str, str]]:
        changes: list[dict[str, str]] = []
        current_keys = set(current)
        baseline_keys = set(baseline)

        for item in sorted(current_keys - baseline_keys):
            changes.append({"category": category, "type": "added", "detail": f"{label} added: {item}"})
        for item in sorted(baseline_keys - current_keys):
            changes.append({"category": category, "type": "removed", "detail": f"{label} removed: {item}"})
        for item in sorted(current_keys & baseline_keys):
            if self._record_hash(current[item]) != self._record_hash(baseline[item]):
                changes.append({"category": category, "type": "modified", "detail": f"{label} modified: {item}"})
        return changes

    def _diff_scalar_hash(self, category: str, label: str, current: Any, baseline: Any) -> list[dict[str, str]]:
        current_hash = self._record_hash(current)
        baseline_hash = self._record_hash(baseline)
        if current_hash == baseline_hash:
            return []
        if current_hash is None and baseline_hash is not None:
            return [{"category": category, "type": "removed", "detail": f"{label} removed"}]
        if current_hash is not None and baseline_hash is None:
            return [{"category": category, "type": "added", "detail": f"{label} added"}]
        return [{"category": category, "type": "modified", "detail": f"{label} modified"}]
