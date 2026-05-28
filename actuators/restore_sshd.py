"""Restore SSH service health after hostile tampering."""

from __future__ import annotations

import socket
import subprocess
from typing import Any

from core.actuator import BaseActuator

DEFAULT_EXPECTED_PORTS = (22, 6022)


def _run(command: list[str]) -> tuple[int, str, str]:
    completed = subprocess.run(command, check=False, capture_output=True, text=True)
    return completed.returncode, completed.stdout or "", completed.stderr or ""


def _candidate_units() -> list[str]:
    units: list[str] = []
    for unit in ("ssh.service", "sshd.service"):
        code, _, _ = _run(["systemctl", "status", unit])
        if code == 0:
            units.append(unit)
    return units


def _listening(port: int) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=1.0):
            return True
    except OSError:
        return False


def _expected_ports(target: Any) -> list[int]:
    if isinstance(target, dict):
        values = target.get("expected_ports")
        if isinstance(values, list):
            ports: list[int] = []
            for item in values:
                try:
                    ports.append(int(item))
                except (TypeError, ValueError):
                    continue
            if ports:
                return ports
    return list(DEFAULT_EXPECTED_PORTS)


class RestoreSshdActuator(BaseActuator):
    name = "restore_sshd"

    async def _do_action(self, target: Any) -> dict[str, Any]:
        expected_ports = _expected_ports(target)
        socket_unit_active = False
        code, stdout, _ = _run(["systemctl", "is-active", "ssh.socket"])
        if code == 0 and stdout.strip() in {"active", "activating"}:
            socket_unit_active = True
            _run(["systemctl", "disable", "--now", "ssh.socket"])
            _run(["systemctl", "mask", "ssh.socket"])

        units = _candidate_units()
        restarted: list[str] = []
        for unit in units:
            _run(["systemctl", "daemon-reload"])
            _run(["systemctl", "reset-failed", unit])
            _run(["systemctl", "restart", unit])
            restarted.append(unit)
        return {
            "target": str(target or ""),
            "units": units,
            "restarted": restarted,
            "ssh_socket_disabled": socket_unit_active,
            "expected_ports": expected_ports,
            "port_checks": {str(port): _listening(port) for port in expected_ports},
        }

    async def _verify(self, target: Any, result: dict[str, Any] | None = None) -> bool:
        if not result:
            return False
        expected_ports = [int(port) for port in result.get("expected_ports", _expected_ports(target))]
        if result.get("ssh_socket_disabled"):
            code, stdout, _ = _run(["systemctl", "is-active", "ssh.socket"])
            if code == 0 and stdout.strip() in {"active", "activating"}:
                return False
        for unit in result.get("units", []):
            code, stdout, _ = _run(["systemctl", "is-active", unit])
            if code != 0 or stdout.strip() not in {"active", "activating"}:
                return False
        return all(_listening(port) for port in expected_ports)


class RestoreSshd(RestoreSshdActuator):
    """Backward-compatible alias."""
