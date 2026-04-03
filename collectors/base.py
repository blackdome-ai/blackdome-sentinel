"""Base collector class and helpers for host evidence gathering."""

from __future__ import annotations

import fnmatch
import hashlib
import json
import logging
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class BaseCollector:
    """Base collector contract for host evidence gathering."""

    name = "base_collector"
    command_timeout = 5

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        self.project_root = PROJECT_ROOT
        self.config = config or self._load_default_config()
        self.logger = logging.getLogger(f"collectors.{self.name}")
        self.sentinel_config = self.config.get("sentinel", {}) if isinstance(self.config, dict) else {}
        self.threat_intel_config = self.config.get("threat_intel", {}) if isinstance(self.config.get("threat_intel"), dict) else {}
        self.whitelist_config = self.config.get("whitelist", {}) if isinstance(self.config.get("whitelist"), dict) else {}
        self.collector_config = self._resolve_collector_config()
        self.baseline_path = self.resolve_path(self.sentinel_config.get("baseline_path", "state/baseline.json"))
        self.state_path = self.resolve_path(self.sentinel_config.get("state_path", "state/sentinel_state.json"))
        self.hostile_feed_path = self.resolve_path(self.threat_intel_config.get("hostile_feed_path", "state/hostile_ips.json"))

    async def collect(self) -> dict[str, Any]:
        raise NotImplementedError

    async def run_in_thread(self, callback: Any, *args: Any, **kwargs: Any) -> Any:
        return callback(*args, **kwargs)

    def resolve_path(self, value: str | Path) -> Path:
        path = Path(value)
        if path.is_absolute():
            return path
        return self.project_root / path

    def _load_default_config(self) -> dict[str, Any]:
        config_path = self.project_root / "config.yaml"
        if not config_path.exists():
            return {}
        with config_path.open("r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle) or {}
        return data if isinstance(data, dict) else {}

    def _resolve_collector_config(self) -> dict[str, Any]:
        collectors_section = self.config.get("collectors", {}) if isinstance(self.config, dict) else {}
        if isinstance(collectors_section, dict):
            settings = collectors_section.get(self.name, {})
            return settings if isinstance(settings, dict) else {}
        return {}

    def load_baseline(self) -> dict[str, Any]:
        if not self.baseline_path.exists():
            return {}
        with self.baseline_path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
        return data if isinstance(data, dict) else {}

    def load_state(self) -> dict[str, Any]:
        if not self.state_path.exists():
            return {}
        with self.state_path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
        return data if isinstance(data, dict) else {}

    def load_hostile_ips(self) -> set[str]:
        if not self.hostile_feed_path.exists():
            return set()
        try:
            with self.hostile_feed_path.open("r", encoding="utf-8") as handle:
                data = json.load(handle)
        except (OSError, json.JSONDecodeError):
            return set()
        if isinstance(data, list):
            return {str(item).strip() for item in data if str(item).strip()}
        if isinstance(data, dict) and isinstance(data.get("ips"), list):
            return {str(item).strip() for item in data["ips"] if str(item).strip()}
        return set()

    def known_malware_hashes(self) -> set[str]:
        values = self.threat_intel_config.get("known_malware_hashes", [])
        if not isinstance(values, list):
            return set()
        return {str(item).strip().lower() for item in values if str(item).strip()}

    def scan_window_seconds(self) -> int:
        default_window = int(self.sentinel_config.get("scan_interval_seconds", 300))
        state = self.load_state()
        last_scan_at = state.get("last_scan_at")
        if not last_scan_at:
            return default_window
        try:
            parsed = datetime.fromisoformat(str(last_scan_at))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            delta = time.time() - parsed.timestamp()
        except (TypeError, ValueError):
            return default_window
        if delta <= 0 or delta > 86400:
            return default_window
        return max(1, int(delta))

    def build_result(self, findings: list[dict[str, Any]], raw: dict[str, Any] | None = None, status: str = "ok") -> dict[str, Any]:
        return {
            "status": status,
            "timestamp": time.time(),
            "findings": findings,
            "raw": raw or {},
        }

    def build_error_result(self, message: str, raw: dict[str, Any] | None = None) -> dict[str, Any]:
        payload = raw or {}
        payload.setdefault("error", message)
        return self.build_result([], raw=payload, status="error")

    def run_command(self, command: list[str], timeout: int | float | None = None) -> dict[str, Any]:
        effective_timeout = timeout or self.command_timeout
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=effective_timeout,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return {
                "ok": False,
                "returncode": None,
                "stdout": "",
                "stderr": f"command timed out after {effective_timeout}s",
                "command": command,
            }
        except FileNotFoundError:
            return {
                "ok": False,
                "returncode": None,
                "stdout": "",
                "stderr": f"command not found: {command[0]}",
                "command": command,
            }
        return {
            "ok": result.returncode == 0,
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "command": command,
        }

    @staticmethod
    def sha256_file(path: str | Path) -> str | None:
        file_path = Path(path)
        if not file_path.exists():
            return None
        digest = hashlib.sha256()
        try:
            with file_path.open("rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(chunk)
        except OSError:
            return None
        return digest.hexdigest()

    @staticmethod
    def sha256_text(value: str) -> str:
        return hashlib.sha256(value.encode("utf-8")).hexdigest()

    @staticmethod
    def safe_read_text(path: str | Path) -> str | None:
        file_path = Path(path)
        if not file_path.exists():
            return None
        try:
            return file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None

    @staticmethod
    def chunked(items: list[str], chunk_size: int) -> list[list[str]]:
        return [items[index : index + chunk_size] for index in range(0, len(items), chunk_size)]

    @staticmethod
    def parse_lsattr_output(output: str) -> dict[str, str]:
        flags: dict[str, str] = {}
        for line in output.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            parts = stripped.split(maxsplit=1)
            if len(parts) != 2:
                continue
            flags[parts[1]] = parts[0]
        return flags

    def list_immutable_flags(self, paths: list[str]) -> dict[str, str]:
        existing = sorted({str(Path(path)) for path in paths if path and Path(path).exists()})
        if not existing:
            return {}

        flagged: dict[str, str] = {}
        for chunk in self.chunked(existing, 128):
            result = self.run_command(["lsattr", "-d", *chunk])
            if not result["stdout"]:
                continue
            for path, attrs in self.parse_lsattr_output(result["stdout"]).items():
                if "i" in attrs or "a" in attrs:
                    flagged[path] = attrs
        return flagged

    def path_matches_patterns(self, value: str, patterns: list[str]) -> bool:
        if not value:
            return False
        stripped = value.removesuffix(" (deleted)")
        basename = Path(stripped).name
        for pattern in patterns:
            candidate = str(pattern).strip()
            if not candidate:
                continue
            if fnmatch.fnmatch(value, candidate) or fnmatch.fnmatch(stripped, candidate) or fnmatch.fnmatch(basename, candidate):
                return True
        return False

    def process_exe_whitelisted(self, exe_path: str) -> bool:
        patterns = self._string_list(self.whitelist_config.get("process_exe_patterns", []))
        return self.path_matches_patterns(exe_path, patterns)

    def deleted_exe_ignored(self, exe_path: str) -> bool:
        patterns = self._string_list(self.whitelist_config.get("deleted_exe_ignore", []))
        return self.process_exe_whitelisted(exe_path) or self.path_matches_patterns(exe_path, patterns)

    def high_cpu_ignored(self, process_name: str) -> bool:
        ignored = {item.lower() for item in self._string_list(self.whitelist_config.get("high_cpu_ignore", []))}
        return process_name.lower() in ignored

    def process_names_whitelisted(self, process_names: list[str]) -> bool:
        if not process_names:
            return False
        ignored = {item.lower() for item in self._string_list(self.whitelist_config.get("high_cpu_ignore", []))}
        return all(str(name).lower() in ignored for name in process_names)

    def kernel_process_ignored(self, signature: str) -> bool:
        patterns = self._string_list(self.whitelist_config.get("kernel_ignore_patterns", []))
        primary = signature.split()[0] if signature else ""
        return self.path_matches_patterns(signature, patterns) or self.path_matches_patterns(primary, patterns)

    def token_matches_process_whitelist(self, value: str) -> bool:
        patterns = self._string_list(self.whitelist_config.get("process_exe_patterns", []))
        tokens = [token.strip('"\'\'(),') for token in value.split()]
        return any(self.path_matches_patterns(token, patterns) for token in tokens if token)

    @staticmethod
    def _string_list(value: Any) -> list[str]:
        if not isinstance(value, list):
            return []
        return [str(item) for item in value if str(item).strip()]
