"""Persistence-cleanup actuator."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

from core.actuator import BaseActuator


def _parse_spec(target: Any) -> dict[str, Any]:
    if isinstance(target, dict):
        return target
    if isinstance(target, str):
        return json.loads(target)
    raise TypeError(f"Unsupported clean_persistence target: {target!r}")


class CleanPersistenceActuator(BaseActuator):
    name = "clean_persistence"

    async def _do_action(self, target: Any) -> dict[str, Any]:
        spec = _parse_spec(target)
        cleaned: list[str] = []
        patterns = [str(pattern) for pattern in spec.get("patterns", [])]

        for file_path in spec.get("files", []):
            path = Path(str(file_path))
            if not path.exists():
                continue

            self._strip_immutable(path)
            if patterns:
                with path.open("r", encoding="utf-8", errors="replace") as handle:
                    lines = handle.readlines()
                with path.open("w", encoding="utf-8") as handle:
                    for line in lines:
                        if not any(pattern in line for pattern in patterns):
                            handle.write(line)
                cleaned.append(str(path))
            else:
                os.remove(path)
                cleaned.append(str(path))

        return {"cleaned": cleaned}

    async def _verify(self, target: Any, result: dict[str, Any] | None = None) -> bool:
        spec = _parse_spec(target)
        patterns = [str(pattern) for pattern in spec.get("patterns", [])]

        for file_path in spec.get("files", []):
            path = Path(str(file_path))
            if not path.exists():
                continue
            if not patterns:
                return False
            content = path.read_text(encoding="utf-8", errors="replace")
            if any(pattern in content for pattern in patterns):
                return False

        return True

    @staticmethod
    def _strip_immutable(path: Path) -> None:
        if shutil.which("chattr") is None:
            return
        subprocess.run(["chattr", "-ia", str(path)], capture_output=True, check=False)


class CleanPersistence(CleanPersistenceActuator):
    """Backward-compatible alias."""
