"""Block-IP actuator."""

from __future__ import annotations

import ipaddress
import subprocess
from typing import Any

from core.actuator import BaseActuator


def _extract_ip_target(target: Any) -> tuple[str | None, str]:
    if isinstance(target, dict):
        raw = str(target.get("ip") or target.get("address") or target.get("target") or "").strip()
    else:
        raw = str(target).strip()
    if not raw:
        return None, str(target)
    try:
        return str(ipaddress.ip_address(raw)), raw
    except ValueError:
        try:
            return str(ipaddress.ip_network(raw, strict=False)), raw
        except ValueError:
            return None, raw


class BlockIpActuator(BaseActuator):
    name = "block_ip"

    async def _do_action(self, target: Any) -> dict[str, Any]:
        ip_address, raw_target = _extract_ip_target(target)
        if ip_address is None:
            self.logger.warning("Skipping block_ip for invalid target %s", raw_target)
            return {"ip": raw_target, "skipped": True, "reason": "invalid_ip_target"}
        subprocess.run(["iptables", "-A", "OUTPUT", "-d", ip_address, "-j", "DROP"], check=True, capture_output=True)
        subprocess.run(["iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"], check=True, capture_output=True)
        return {"ip": ip_address, "rule": "INPUT+OUTPUT DROP"}

    async def _verify(self, target: Any, result: dict[str, Any] | None = None) -> bool:
        if result and result.get("skipped"):
            return True
        ip_address, _raw_target = _extract_ip_target(target)
        if ip_address is None:
            return True
        result = subprocess.run(["iptables", "-L", "-n"], capture_output=True, text=True, check=False)
        return ip_address in result.stdout


class BlockIp(BlockIpActuator):
    """Backward-compatible alias."""

