"""Kill an entire process tree rooted at the target PID."""

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


def _collect_ppids() -> dict[int, int]:
    mapping: dict[int, int] = {}
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        status_path = entry / "status"
        try:
            status_text = status_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        ppid = 0
        for line in status_text.splitlines():
            if line.startswith("PPid:"):
                try:
                    ppid = int(line.split(":", 1)[1].strip())
                except ValueError:
                    ppid = 0
                break
        mapping[int(entry.name)] = ppid
    return mapping


def _descendants(root_pid: int) -> list[int]:
    ppid_map = _collect_ppids()
    children_by_parent: dict[int, list[int]] = {}
    for pid, ppid in ppid_map.items():
        children_by_parent.setdefault(ppid, []).append(pid)

    ordered: list[int] = []
    stack = [root_pid]
    seen: set[int] = set()
    while stack:
        current = stack.pop()
        if current in seen:
            continue
        seen.add(current)
        ordered.append(current)
        stack.extend(children_by_parent.get(current, []))
    return ordered


class KillProcessTreeActuator(BaseActuator):
    name = "kill_process_tree"

    async def _do_action(self, target: Any) -> dict[str, Any]:
        root_pid = _parse_pid(target)
        tree = _descendants(root_pid)
        killed: list[int] = []
        for pid in reversed(tree):
            try:
                os.kill(pid, signal.SIGKILL)
                killed.append(pid)
            except ProcessLookupError:
                continue
        return {
            "pid": root_pid,
            "killed_pids": killed,
            "killed_count": len(killed),
        }

    async def _verify(self, target: Any, result: dict[str, Any] | None = None) -> bool:
        if not result:
            return False
        for pid in result.get("killed_pids", []):
            if Path(f"/proc/{pid}").exists():
                return False
        return True


class KillProcessTree(KillProcessTreeActuator):
    """Backward-compatible alias."""

