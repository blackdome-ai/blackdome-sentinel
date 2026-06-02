"""Persistence-cleanup actuator."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

from core.actuator import BaseActuator


# --- gauntlet-burn-* deadman exemption (coord: burn-deadman-unit-deletion-20260602) ---
# clean_persistence was reaping claude-burn's dead-man's-switch systemd units
# (gauntlet-burn-selfterminate.{timer,service}, gauntlet-burn-panic.{path,service}) at boot
# because — unlike quarantine_file.py — it had NEITHER the _burn_pre_engagement() skip NOR a
# path exemption. Mirror quarantine_file's guards. PREFIX not SHA: the timer OnBootSec TTL is
# templated, so unit hashes are fragile. NARROW: fight-box clean_persistence is unaffected
# (attackers don't name persistence gauntlet-burn-*, and fight != burn_pre_engagement).
ENGAGEMENT_FLAG = Path("/var/blackdome/sentinel/state/burn_engaged.flag")
RUNTIME_ENV = Path("/etc/gauntlet/runtime.env")
_BURN_UNIT_PREFIX = "gauntlet-burn-"


def _runtime_profile() -> str:
    try:
        for line in RUNTIME_ENV.read_text(encoding="utf-8").splitlines():
            if line.strip().startswith("GAUNTLET_PROFILE="):
                return line.strip().split("=", 1)[1].strip().strip('"').lower()
    except Exception:
        return ""
    return ""


def _burn_pre_engagement() -> bool:
    return _runtime_profile() == "burn" and not ENGAGEMENT_FLAG.exists()


def _is_burn_unit_exempt(path: Path) -> bool:
    return path.name.startswith(_BURN_UNIT_PREFIX) and "/etc/systemd/system" in str(path)


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
        if _burn_pre_engagement():
            return {
                "cleaned": [],
                "skipped": [str(target)],
                "reason": "burn_pre_engagement",
                "profile": "burn",
                "engagement_flag_path": str(ENGAGEMENT_FLAG),
            }
        cleaned: list[str] = []
        skipped_burn: list[str] = []
        patterns = [str(pattern) for pattern in spec.get("patterns", [])]

        for file_path in spec.get("files", []):
            path = Path(str(file_path))
            if not path.exists():
                continue
            if _is_burn_unit_exempt(path):
                self.logger.warning(
                    "Skipping clean_persistence for exempt gauntlet-burn-* unit %s", path
                )
                skipped_burn.append(str(path))
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

        result: dict[str, Any] = {"cleaned": cleaned}
        if skipped_burn:
            result["skipped"] = skipped_burn
            result["skip_reason"] = "burn_unit_exempt"
        return result

    async def _verify(self, target: Any, result: dict[str, Any] | None = None) -> bool:
        spec = _parse_spec(target)
        if spec.get("noop"):
            return True
        if _burn_pre_engagement():
            return True
        patterns = [str(pattern) for pattern in spec.get("patterns", [])]

        for file_path in spec.get("files", []):
            path = Path(str(file_path))
            if not path.exists():
                continue
            if _is_burn_unit_exempt(path):
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
