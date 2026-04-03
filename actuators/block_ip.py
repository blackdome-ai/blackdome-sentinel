"""Block-IP actuator."""

from __future__ import annotations

import subprocess
from typing import Any

from core.actuator import BaseActuator


class BlockIpActuator(BaseActuator):
    name = "block_ip"

    async def _do_action(self, target: Any) -> dict[str, Any]:
        ip_address = str(target).strip()
        subprocess.run(["iptables", "-A", "OUTPUT", "-d", ip_address, "-j", "DROP"], check=True, capture_output=True)
        subprocess.run(["iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"], check=True, capture_output=True)
        return {"ip": ip_address, "rule": "INPUT+OUTPUT DROP"}

    async def _verify(self, target: Any, result: dict[str, Any] | None = None) -> bool:
        ip_address = str(target).strip()
        result = subprocess.run(["iptables", "-L", "-n"], capture_output=True, text=True, check=False)
        return ip_address in result.stdout


class BlockIp(BlockIpActuator):
    """Backward-compatible alias."""

