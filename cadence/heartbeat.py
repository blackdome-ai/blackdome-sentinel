from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import logging
import os
from typing import Any, Awaitable, Callable

from events.queue import EventQueue

LOGGER = logging.getLogger(__name__)


async def run_heartbeat(
    queue: EventQueue,
    send_heartbeat: Callable[[dict[str, Any]], Awaitable[dict[str, Any]]],
    agent_id: str,
    interval_seconds: float = 120,
) -> None:
    while True:
        payload = {
            "agent_id": agent_id,
            "collector_alive": True,
            "queue_depth": queue.depth,
            "system_stats": _system_stats(),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        try:
            response = await send_heartbeat(payload)
            if not isinstance(response, dict):
                LOGGER.warning("heartbeat callback returned non-dict response")
        except Exception:
            LOGGER.warning("heartbeat callback failed", exc_info=True)

        await asyncio.sleep(interval_seconds)


def _system_stats() -> dict[str, Any]:
    load_avg = (0.0, 0.0, 0.0)
    try:
        load_avg = os.getloadavg()
    except OSError:
        pass

    meminfo: dict[str, int] = {}
    try:
        with open("/proc/meminfo", "r", encoding="utf-8") as handle:
            for line in handle:
                key, _, value = line.partition(":")
                if not value:
                    continue
                meminfo[key] = int(value.strip().split()[0])
    except (OSError, ValueError):
        meminfo = {}

    total = float(meminfo.get("MemTotal", 0))
    available = float(meminfo.get("MemAvailable", meminfo.get("MemFree", 0)))
    mem_pct = 0.0
    if total > 0:
        mem_pct = round(max(0.0, min(100.0, ((total - available) / total) * 100.0)), 2)

    return {
        "load": {
            "one": round(float(load_avg[0]), 2),
            "five": round(float(load_avg[1]), 2),
            "fifteen": round(float(load_avg[2]), 2),
        },
        "mem_pct": mem_pct,
    }
