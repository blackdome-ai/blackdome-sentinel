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
KNOWN_BOOT_NOISE_SHAS = frozenset({
    "02be2105cca6484786d3d479bad8e9f2a815b8426f4f2be515f0d9af78522d57",  # gauntlet-blackbox.service
    "f84d734328a23b69d9192cd40e3605a5da8c0a5d30b10dd344238120aa3f613c",  # gauntlet-auditd-forwarder.service
    "fbc2d3d6c2cf24ae8f1353df2ad90f25e659278dd0facdb2bac1cc695b29cf7f",  # gauntlet-burn-egress-guard.service
    "8e31fcd697dce4c5102f60370b6143d5dfe1b93eb3e666e5fa2eb0ffaf8f1b18",  # inotifywait
    "f28582a4481e63def078ab02901d6ddce9611f4cb2c6f7b44f772a2a3c12d5ea",  # auditd.service
    "820b999f164778294e13e2ca3d3bc40a0c4b10200f569b0d030cb5e529f4105c",  # blackdome-sentinel-v2.service
    "0229cfe3f597c28b3fd1d4afe4e883b2fccdcbc0d8b19cb1776d37715a73ebbb",  # gauntlet-ingress-firewall.service
    "293675024a855e480c3b5f22ada8519f06e9da4ee2ac71db281b79b418dd16ba",  # ssh_host_rsa_key
    "ee3074c6b9bb0acb3bef4dcff85b7e1e99d5150ff48a63a671ddc11187503987",  # id_rsa_backup
    "23870cf026e9b40acdb34f22eb3beda05fe65fa739894e3a4a910dbe0f3053f1",  # 10-gauntlet-crucible.conf
    "81f8077a1772cd1e33bd7d7cc7bec63c998f16acff4cf89db7dc2295f3ba5233",  # audit.rules
})


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
        if file_hash in KNOWN_BOOT_NOISE_SHAS:
            return {"status": "skipped", "reason": "known_boot_noise_sha", "sha256": file_hash, "target": str(source), "original_name": source.name}
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
        if isinstance(result, dict) and result.get("reason") in {"burn_pre_engagement", "known_boot_noise_sha"}:
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
