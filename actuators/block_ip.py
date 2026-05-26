"""Block-IP actuator."""

from __future__ import annotations

import ipaddress
import subprocess
from typing import Any

from core.actuator import BaseActuator


# Friendly-infrastructure ranges that must NEVER be blocked, even when explicitly
# asked. Tailscale CGNAT (100.64.0.0/10) carries the control plane and operator
# nodes; a control-plane probe to a facade once self-blocked the DO sentinel
# (100.98.16.15) on 2026-05-26. Private/loopback/link-local/reserved are added as
# defence-in-depth. This guard is intentionally duplicated in core/hostile_feed.py
# so the actuator stays safe even if the feed module fails to import.
_NEVER_BLOCK_NETWORKS = (
    ipaddress.ip_network("100.64.0.0/10"),        # Tailscale CGNAT (IPv4)
    ipaddress.ip_network("fd7a:115c:a1e0::/48"),  # Tailscale ULA (IPv6)
)


def _is_never_block_target(value: str) -> bool:
    """True for tailnet / friendly-infra targets that must never be blocked."""
    try:
        obj: Any = ipaddress.ip_address(value)
    except ValueError:
        try:
            obj = ipaddress.ip_network(value, strict=False)
        except ValueError:
            return False
    if (
        obj.is_private
        or obj.is_loopback
        or obj.is_link_local
        or obj.is_reserved
        or obj.is_multicast
    ):
        return True
    for net in _NEVER_BLOCK_NETWORKS:
        if obj.version != net.version:
            continue
        if isinstance(obj, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
            if obj.overlaps(net):
                return True
        elif obj in net:
            return True
    return False


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
        if _is_never_block_target(ip_address):
            self.logger.warning("Refusing block_ip for friendly-infra IP %s (tailnet/private range)", ip_address)
            return {"ip": ip_address, "skipped": True, "reason": "friendly_infra_ip"}
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

