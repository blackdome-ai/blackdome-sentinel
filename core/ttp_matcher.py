"""TTP pattern matching for deterministic behavioral attack chain detection."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

import yaml


log = logging.getLogger("sentinel.ttp_matcher")

DEFAULT_PATTERNS_PATH = Path(__file__).resolve().parents[1] / "ttp_patterns.yaml"
TEMP_ROOTS = ("/tmp", "/var/tmp", "/dev/shm")
SECURITY_TOOLS = ("chattr", "iptables", "ps", "ss", "lsof", "rm", "kill")
COMMON_PORTS = {20, 21, 22, 25, 53, 67, 68, 80, 110, 123, 143, 389, 443, 465, 587, 993, 995}


@dataclass(slots=True)
class TTPMatch:
    pattern_id: str
    name: str
    action: str
    matched_signals: list[str]
    window_seconds: int

    def __repr__(self) -> str:
        return f"TTPMatch({self.pattern_id}: {self.name} -> {self.action})"


def load_patterns(path: Path = DEFAULT_PATTERNS_PATH) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}
    return data.get("patterns", {})


def match_findings(findings: Sequence[dict[str, Any]], patterns: dict[str, Any] | None = None) -> list[TTPMatch]:
    """Match flattened findings against configured TTP patterns."""
    loaded_patterns = patterns or load_patterns()
    signals = _extract_signals(findings)
    matches: list[TTPMatch] = []

    for pattern_id, pattern in loaded_patterns.items():
        required = pattern.get("signals", [])
        matched: list[str] = []

        for signal_def in required:
            if not isinstance(signal_def, dict):
                continue
            if not all(_check_signal(signal_name, expected, signals) for signal_name, expected in signal_def.items()):
                continue
            matched.extend(signal_def.keys())

        if len(matched) == len(required):
            matches.append(
                TTPMatch(
                    pattern_id=pattern_id,
                    name=str(pattern.get("name") or pattern_id),
                    action=str(pattern.get("action") or "kill_and_quarantine"),
                    matched_signals=matched,
                    window_seconds=int(pattern.get("window_seconds", 0)),
                )
            )

    return matches


def _extract_signals(findings: Sequence[dict[str, Any]]) -> dict[str, Any]:
    signals: dict[str, Any] = {
        "new_binary": False,
        "binary_in_tmp": False,
        "chattr_immutable": False,
        "outbound_port": [],
        "downloads_binary": False,
        "self_deletes": False,
        "crontab_write": False,
        "systemd_write": False,
        "process_deleting_tools": [],
        "network_config_modified": False,
        "kernel_module_load": False,
        "not_from_package_manager": False,
        "new_process": False,
        "outbound_nonstandard_port": False,
        "stdio_redirected": False,
        "iptables_flush_or_delete": False,
        "not_admin_session": False,
        "new_ip_route": False,
        "unknown_gateway": False,
        "new_established_connection": False,
        "nonstandard_port": False,
        "process_not_in_baseline": False,
        "no_dns_for_destination": False,
        "new_listen_port": False,
    }

    for finding in findings:
        if not isinstance(finding, dict):
            continue

        evidence = finding.get("evidence")
        if not isinstance(evidence, dict):
            evidence = {}
        tags = {str(tag).lower() for tag in finding.get("tags", [])}
        description = str(finding.get("description", "")).lower()
        category = str(finding.get("category", "")).lower()
        path = str(evidence.get("path") or evidence.get("exe") or "")
        remote_port = _safe_port(evidence.get("remote_port") or evidence.get("port"))
        local_port = _safe_port(evidence.get("local_port"))
        user = str(evidence.get("user") or "").lower()
        process_names = [str(name).lower() for name in evidence.get("process_names", []) if name]

        if tags & {"new_binary", "new_executable", "modified_binary", "deleted_exe", "temp_executable"}:
            signals["new_binary"] = True
        if path.startswith(TEMP_ROOTS) or "temp_executable" in tags:
            signals["binary_in_tmp"] = True
        if tags & {"immutable_binary", "immutable_file", "immutable_crontab", "immutable_manipulation"} or any(
            token in description for token in ("immutable", "chattr", "lsattr")
        ):
            signals["chattr_immutable"] = True
        if remote_port is not None:
            signals["outbound_port"].append(remote_port)
            if remote_port not in COMMON_PORTS:
                signals["outbound_nonstandard_port"] = True
                signals["nonstandard_port"] = True
        if local_port is not None and local_port not in COMMON_PORTS:
            signals["nonstandard_port"] = True

        if "download_exec" in tags or any(token in description for token in ("curl", "wget", "download")):
            signals["downloads_binary"] = True
        if "deleted_exe" in tags or any(token in description for token in ("deletes self", "self delete", "(deleted)")):
            signals["self_deletes"] = True
        if category == "crontab" or tags & {"new_crontab", "modified_crontab", "suspicious_cron", "rc_local_changed"}:
            signals["crontab_write"] = True
        if "systemd" in description or path.startswith("/etc/systemd") or path.endswith(".service"):
            signals["systemd_write"] = True
        if any(tool in description for tool in SECURITY_TOOLS) and any(token in description for token in ("delete", "removed", "missing", "rm ")):
            signals["process_deleting_tools"].extend(tool for tool in SECURITY_TOOLS if tool in description)
        if any(token in description for token in ("resolv.conf", "tailscale", "iptables", "firewall", "route", "network config")):
            signals["network_config_modified"] = True
        if category == "kernel_module" or any(token in description for token in ("insmod", "modprobe", "kernel module")):
            signals["kernel_module_load"] = True
        if category in {"process", "network"} and not any(token in description for token in ("apt", "dpkg", "yum", "dnf", "package manager")):
            signals["not_from_package_manager"] = True
        if "new_process" in tags or "new process" in description or "new_processes_since_baseline" in description:
            signals["new_process"] = True
            signals["process_not_in_baseline"] = True
        if "stdin" in description or "stdout" in description or "redirect" in description or "pty" in description:
            signals["stdio_redirected"] = True
        if "iptables" in description and any(token in description for token in ("flush", "delete", "-f", "-d")):
            signals["iptables_flush_or_delete"] = True
            signals["network_config_modified"] = True
        if user and user not in {"root", "admin"} and "admin" not in description:
            signals["not_admin_session"] = True
        if "route" in description and any(token in description for token in ("add", "new", "gateway")):
            signals["new_ip_route"] = True
        if "unknown gateway" in description or ("gateway" in description and "unknown" in description):
            signals["unknown_gateway"] = True
        if category == "network" and str(evidence.get("state") or "").upper().startswith("ESTAB"):
            signals["new_established_connection"] = True
        if category == "network" and ("no dns" in description or "unresolved" in description):
            signals["no_dns_for_destination"] = True
        if category == "network" and (
            str(evidence.get("state") or "").upper().startswith("LISTEN") or "new_listener" in tags or "listening socket" in description
        ):
            signals["new_listen_port"] = True

        if "baseline" in description and "not" in description:
            signals["process_not_in_baseline"] = True
        if process_names and not _processes_whitelisted(process_names):
            signals["process_not_in_baseline"] = True

    deduped_tools = sorted(set(signals["process_deleting_tools"]))
    signals["process_deleting_tools"] = deduped_tools
    return signals


def _check_signal(name: str, expected: Any, signals: dict[str, Any]) -> bool:
    actual = signals.get(name)
    if actual is None:
        return False

    if isinstance(expected, bool):
        return bool(actual) == expected
    if isinstance(expected, list):
        if isinstance(actual, list):
            return bool(set(actual) & set(expected))
        return actual in expected
    return actual == expected


def _safe_port(value: Any) -> int | None:
    if value in (None, ""):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _processes_whitelisted(process_names: Sequence[str]) -> bool:
    allowed = {"systemd", "sshd", "nginx", "python3", "node", "ollama", "postgres", "pm2", "apt", "dpkg"}
    return all(name in allowed for name in process_names if name)
