"""Emergency egress isolation actuator for disposable fight hosts."""

from __future__ import annotations

import socket
import subprocess
from typing import Any
from urllib.parse import urlparse

from core.actuator import BaseActuator


CHAIN_NAME = "SENTINEL_EMERGENCY_EGRESS"


def _control_plane_targets(target: Any) -> tuple[list[str], int]:
    raw = str(target or "").strip()
    if not raw:
        raise ValueError("Emergency isolation target must be a control-plane URL")

    parsed = urlparse(raw if "://" in raw else f"https://{raw}")
    host = (parsed.hostname or "").strip()
    if not host:
        raise ValueError(f"Invalid control-plane target: {raw}")

    port = parsed.port or (443 if parsed.scheme != "http" else 80)
    addresses = sorted({item[4][0] for item in socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)})
    if not addresses:
        raise ValueError(f"Could not resolve control-plane host: {host}")
    return addresses, port


def _run(command: list[str]) -> None:
    subprocess.run(command, check=True, capture_output=True)


def _ensure_jump(chain_name: str) -> None:
    check = subprocess.run(
        ["iptables", "-C", "OUTPUT", "-j", chain_name],
        check=False,
        capture_output=True,
        text=True,
    )
    if check.returncode != 0:
        _run(["iptables", "-I", "OUTPUT", "1", "-j", chain_name])


class EnterEmergencyIsolationActuator(BaseActuator):
    name = "enter_emergency_isolation"

    async def _do_action(self, target: Any) -> dict[str, Any]:
        control_plane_ips, control_plane_port = _control_plane_targets(target)
        _run(["iptables", "-N", CHAIN_NAME]) if subprocess.run(["iptables", "-L", CHAIN_NAME], check=False, capture_output=True).returncode != 0 else None
        _run(["iptables", "-F", CHAIN_NAME])
        _run(["iptables", "-A", CHAIN_NAME, "-o", "lo", "-j", "ACCEPT"])
        _run(["iptables", "-A", CHAIN_NAME, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"])
        _run(["iptables", "-A", CHAIN_NAME, "-p", "udp", "--dport", "53", "-j", "ACCEPT"])
        _run(["iptables", "-A", CHAIN_NAME, "-p", "tcp", "--dport", "53", "-j", "ACCEPT"])
        for ip in control_plane_ips:
            _run(["iptables", "-A", CHAIN_NAME, "-p", "tcp", "-d", ip, "--dport", str(control_plane_port), "-j", "ACCEPT"])
        _run(["iptables", "-A", CHAIN_NAME, "-j", "DROP"])
        _ensure_jump(CHAIN_NAME)
        return {
            "chain": CHAIN_NAME,
            "control_plane_ips": control_plane_ips,
            "control_plane_port": control_plane_port,
        }

    async def _verify(self, target: Any, result: dict[str, Any] | None = None) -> bool:
        iptables_output = subprocess.run(["iptables", "-S"], check=False, capture_output=True, text=True)
        output = iptables_output.stdout or ""
        if f"-A OUTPUT -j {CHAIN_NAME}" not in output:
            return False
        if f"-A {CHAIN_NAME} -j DROP" not in output:
            return False
        if not result:
            return True
        port = str(result.get("control_plane_port") or "")
        for ip in result.get("control_plane_ips") or []:
            if f"-A {CHAIN_NAME} -p tcp -d {ip} --dport {port} -j ACCEPT" not in output:
                return False
        return True


class EnterEmergencyIsolation(EnterEmergencyIsolationActuator):
    """Backward-compatible alias."""
