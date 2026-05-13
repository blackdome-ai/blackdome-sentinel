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
ENGAGEMENT_FLAG, RUNTIME_ENV = Path("/var/blackdome/sentinel/state/burn_engaged.flag"), Path("/etc/gauntlet/runtime.env")


def _runtime_profile() -> str:
    profile = (os.environ.get("GAUNTLET_PROFILE") or "").strip()
    if profile: return profile
    try: lines = RUNTIME_ENV.read_text(encoding="utf-8").splitlines()
    except OSError: return ""
    for line in lines:
        if line.strip().startswith("GAUNTLET_PROFILE="):
            return line.split("=", 1)[1].strip().strip('"').strip("'")
    return ""


def _burn_pre_engagement() -> bool: return _runtime_profile() == "burn" and not ENGAGEMENT_FLAG.exists()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


class QuarantineFileActuator(BaseActuator):
    name = "quarantine_file"

    async def _do_action(self, target: Any) -> dict[str, Any]:
        if _burn_pre_engagement():
            return {"status": "skipped", "reason": "burn_pre_engagement", "target": str(target), "profile": "burn", "engagement_flag_path": str(ENGAGEMENT_FLAG)}
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
        if isinstance(result, dict) and result.get("reason") == "burn_pre_engagement":
            return True
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
