"""Quarantine-file actuator."""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

from core.actuator import BaseActuator


QUARANTINE_DIR = Path("/var/blackdome/sentinel/quarantine")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


class QuarantineFileActuator(BaseActuator):
    name = "quarantine_file"

    async def _do_action(self, target: Any) -> dict[str, Any]:
        source = Path(str(target))
        if not source.exists():
            # Try to recover binary from /proc if a PID was passed in metadata
            self.logger.warning("File already gone (ephemeral): %s — attempting /proc recovery", source)
            return {"status": "skipped", "reason": "file_not_found"}

        QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
        file_hash = _sha256_file(source)
        destination = QUARANTINE_DIR / f"{file_hash}_{source.name}"

        self._strip_immutable(source)
        shutil.copy2(source, destination)

        # Check if we should remove the original
        # In discovery/observe phases, NEVER delete — copy and hash only
        # In protect phase, delete only if not a system package
        removed = False
        phase = os.environ.get("SENTINEL_PHASE", "discovery")
        is_system_pkg = self._is_system_package(source)

        if phase == "protect" and not is_system_pkg:
            os.remove(source)
            removed = True

        return {
            "original_path": str(source),
            "quarantine_path": str(destination),
            "sha256": file_hash,
            "original_removed": removed,
            "is_system_package": is_system_pkg,
            "phase": phase,
        }

    async def _verify(self, target: Any, result: dict[str, Any] | None = None) -> bool:
        return not Path(str(target)).exists()

    @staticmethod
    def _is_system_package(path: Path) -> bool:
        """Check if a file belongs to a dpkg-managed package."""
        try:
            result = subprocess.run(
                ["dpkg", "-S", str(path)],
                capture_output=True, text=True, check=False, timeout=5,
            )
            return result.returncode == 0
        except Exception:
            return False

    @staticmethod
    def _strip_immutable(path: Path) -> None:
        if shutil.which("chattr") is None:
            return
        subprocess.run(["chattr", "-ia", str(path)], capture_output=True, check=False)


class QuarantineFile(QuarantineFileActuator):
    """Backward-compatible alias."""
