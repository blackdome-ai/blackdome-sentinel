"""Situational threat escalation for degraded governance mode."""

from __future__ import annotations

import logging
import subprocess
import time
from typing import Any
from urllib import error as urllib_error
from urllib import request as urllib_request

from .control_plane import control_plane_config


log = logging.getLogger("sentinel.situational")


class SituationalScorer:
    """Deterministic connectivity-aware threat scoring."""

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        config = config or {}
        self.kill_threshold = int(config.get("situational_kill_threshold", 5))
        self.quarantine_threshold = int(config.get("situational_quarantine_threshold", 3))
        self.correlation_window = int(config.get("connectivity_correlation_window_seconds", 300))
        self._last_heartbeat_ok: float | None = None

    def record_heartbeat(self, success: bool) -> None:
        if success:
            self._last_heartbeat_ok = time.time()

    def score(self, findings: list[dict[str, Any]], connectivity: dict[str, bool]) -> dict[str, Any]:
        """Score findings observed during connectivity degradation."""
        score = 0
        reasons: list[str] = []

        if self._last_heartbeat_ok is not None:
            seconds_since = time.time() - self._last_heartbeat_ok
            if seconds_since < self.correlation_window:
                score += 2
                reasons.append(f"connectivity_dropped_{int(seconds_since)}s_ago")

        control_plane_up = bool(connectivity.get("control_plane", True))
        internet_up = bool(connectivity.get("internet", True))
        tailscale_up = bool(connectivity.get("tailscale", True))

        if not control_plane_up and internet_up:
            score += 2
            reasons.append("targeted_isolation")
        if not tailscale_up:
            score += 3
            reasons.append("tailscale_killed")

        for finding in findings:
            if not isinstance(finding, dict):
                continue
            description = str(finding.get("description", "")).lower()
            category = str(finding.get("category", "")).lower()
            tags = {str(tag).lower() for tag in finding.get("tags", [])}
            evidence = finding.get("evidence")
            if not isinstance(evidence, dict):
                evidence = {}

            path = str(evidence.get("path") or evidence.get("exe") or "").lower()
            line = str(evidence.get("line") or "").lower()
            remote_host = str(evidence.get("remote_host") or "").lower()
            state = str(evidence.get("state") or "").upper()

            if any(token in description for token in ("permission", "chmod", "chown")):
                score += 1
                reasons.append("permission_changes")
            if any(token in description for token in ("network", "firewall", "iptables", "tailscale", "resolv.conf")):
                score += 2
                reasons.append("network_config_modified")
            if any(token in description for token in ("chattr", "rm /usr", "rm /bin", "deleted")):
                score += 3
                reasons.append("security_tools_deleted")
            if category == "crontab" or any(token in description for token in ("cron", "systemd", "rc.local")):
                score += 2
                reasons.append("persistence_write")
            if "iptables" in description and any(token in description for token in ("flush", "-f", "delete", "-d")):
                score += 2
                reasons.append("iptables_tampered")
            if "route" in description and any(token in description for token in ("add", "new", "gateway")):
                score += 2
                reasons.append("route_added")
            if "resolv.conf" in description:
                score += 2
                reasons.append("dns_modified")
            if path.startswith(("/tmp", "/var/tmp", "/dev/shm")) or "temp_executable" in tags:
                score += 1
                reasons.append("temp_binary")
            if "new_binary" in tags or "modified_binary" in tags:
                score += 1
                reasons.append("novel_binary")

            if category == "network":
                if state.startswith("ESTAB") and "baseline" not in description:
                    score += 1
                    reasons.append("new_connection")
                if state.startswith("LISTEN") and "baseline" not in description:
                    score += 1
                    reasons.append("new_listener")
                if remote_host and remote_host not in {"127.0.0.1", "::1", "localhost"} and "baseline" not in description:
                    score += 1
                    reasons.append("remote_peer_activity")

            if any(token in line for token in ("curl", "wget", "bash", "sh")):
                score += 1
                reasons.append("download_exec_chain")

        if score >= self.kill_threshold:
            action = "kill"
        elif score >= self.quarantine_threshold:
            action = "quarantine"
        else:
            action = "observe"

        return {
            "score": score,
            "action": action,
            "reasons": _unique(reasons),
            "kill_threshold": self.kill_threshold,
            "quarantine_threshold": self.quarantine_threshold,
        }


def check_connectivity(config: dict[str, Any] | None = None) -> dict[str, bool]:
    """Check current control-plane, internet, and Tailscale reachability."""
    control_plane = control_plane_config(config)
    control_plane_url = str(control_plane.get("url") or "").rstrip("/")
    result = {"control_plane": False, "internet": False, "tailscale": False}

    ping_cmd = ["ping", "-c1", "-W2", "8.8.8.8"]
    if _run_ok(ping_cmd):
        result["internet"] = True

    if _run_ok(["tailscale", "status", "--json"]):
        result["tailscale"] = True

    if control_plane_url and _http_ok(control_plane_url):
        result["control_plane"] = True

    return result


def _run_ok(command: list[str]) -> bool:
    try:
        completed = subprocess.run(command, capture_output=True, timeout=5, check=False)
    except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError):
        return False
    return completed.returncode == 0


def _http_ok(url: str) -> bool:
    try:
        request = urllib_request.Request(url, method="GET")
        with urllib_request.urlopen(request, timeout=5) as response:
            return 200 <= int(getattr(response, "status", 0)) < 500
    except (urllib_error.URLError, ValueError):
        return False


def _unique(values: list[str]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        ordered.append(value)
    return ordered
