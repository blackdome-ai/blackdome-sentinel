"""Kill-process actuator."""

from __future__ import annotations

import os
import signal
from pathlib import Path
from typing import Any

from core.actuator import BaseActuator


def _parse_pid(target: Any) -> int:
    if isinstance(target, int):
        return target
    value = str(target).strip()
    if value.startswith("pid:"):
        value = value.split(":", 1)[1]
    return int(value)


class KillProcessActuator(BaseActuator):
    name = "kill_process"

    async def _do_action(self, target: Any) -> dict[str, Any]:
        pid = _parse_pid(target)
        os.kill(pid, signal.SIGKILL)
        return {"pid": pid, "signal": "SIGKILL"}

    async def _verify(self, target: Any, result: dict[str, Any] | None = None) -> bool:
        pid = _parse_pid(target)
        return not Path(f"/proc/{pid}").exists()


class KillProcess(KillProcessActuator):
    """Backward-compatible alias."""

