"""Persistence-cleanup actuator."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

from core.actuator import BaseActuator


def _noop_spec(target: Any) -> dict[str, Any]:
    return {
        "files": [],
        "patterns": [],
        "noop": True,
        "raw_target": str(target),
        "reason": "unstructured_target",
    }


def _parse_spec(target: Any) -> dict[str, Any]:
    if isinstance(target, dict):
        return target
    if isinstance(target, str):
        raw = target.strip()
        if not raw:
            return _noop_spec(target)
        if raw.startswith("{"):
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                return parsed
            return _noop_spec(target)
        return _noop_spec(target)
    raise TypeError(f"Unsupported clean_persistence target: {target!r}")


class CleanPersistenceActuator(BaseActuator):
    name = "clean_persistence"

    async def _do_action(self, target: Any) -> dict[str, Any]:
        spec = _parse_spec(target)
        if spec.get("noop"):
            skipped_target = str(spec.get("raw_target", target))
            self.logger.warning(
                "Skipping clean_persistence for unstructured target %s",
                skipped_target,
            )
            return {
                "cleaned": [],
                "skipped": [skipped_target],
                "reason": str(spec.get("reason", "unstructured_target")),
            }
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
        if spec.get("noop"):
            return True
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
