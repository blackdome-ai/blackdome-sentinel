"""Remove suspicious transient library preload hooks."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from core.actuator import BaseActuator


PRELOAD_PATH = Path("/etc/ld.so.preload")
SUSPICIOUS_TOKENS = ("/tmp/", "/var/tmp/", "/dev/shm/", "/run/user/")


def _is_suspicious(line: str) -> bool:
    normalized = line.strip()
    if not normalized:
        return False
    if any(token in normalized for token in SUSPICIOUS_TOKENS):
        return True
    if normalized.startswith("/home/") and "/." in normalized:
        return True
    if normalized.startswith("/root/."):
        return True
    return False


class RemoveLdPreloadActuator(BaseActuator):
    name = "remove_ld_preload"

    async def _do_action(self, target: Any) -> dict[str, Any]:
        if not PRELOAD_PATH.exists():
            return {"path": str(PRELOAD_PATH), "removed_entries": [], "present": False}

        content = PRELOAD_PATH.read_text(encoding="utf-8", errors="replace").splitlines()
        kept: list[str] = []
        removed: list[str] = []
        for line in content:
            if _is_suspicious(line):
                removed.append(line.strip())
            else:
                kept.append(line)

        if kept:
            PRELOAD_PATH.write_text("\n".join(kept) + "\n", encoding="utf-8")
        else:
            PRELOAD_PATH.unlink(missing_ok=True)

        return {
            "path": str(PRELOAD_PATH),
            "removed_entries": removed,
            "present": PRELOAD_PATH.exists(),
        }

    async def _verify(self, target: Any, result: dict[str, Any] | None = None) -> bool:
        if not PRELOAD_PATH.exists():
            return True
        content = PRELOAD_PATH.read_text(encoding="utf-8", errors="replace").splitlines()
        return not any(_is_suspicious(line) for line in content)


class RemoveLdPreload(RemoveLdPreloadActuator):
    """Backward-compatible alias."""

