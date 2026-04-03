"""Toolkit vault helpers for cached essential binaries."""

from __future__ import annotations

import hashlib
import logging
import shutil
from pathlib import Path
from typing import Any


log = logging.getLogger("sentinel.toolkit")

TOOLKIT_DIR = Path("/opt/blackdome-sentinel/toolkit")
MANIFEST = TOOLKIT_DIR / ".toolkit.sha256"


def get_binary(name: str) -> str:
    """Return the preferred path to a binary, falling back to the toolkit cache."""
    system_path = shutil.which(name)
    toolkit_path = TOOLKIT_DIR / name

    if system_path and Path(system_path).exists():
        return system_path

    if toolkit_path.exists():
        log.warning("System binary '%s' missing; using toolkit cache", name)
        return str(toolkit_path)

    raise FileNotFoundError(f"Binary '{name}' not found in system or toolkit")


def verify_toolkit() -> dict[str, Any]:
    """Verify toolkit contents against the stored hash manifest."""
    result: dict[str, Any] = {"ok": True, "missing": [], "tampered": []}

    if not MANIFEST.exists():
        result["ok"] = False
        result["missing"].append(".toolkit.sha256")
        return result

    manifest_text = MANIFEST.read_text(encoding="utf-8").strip()
    if not manifest_text:
        result["ok"] = False
        result["tampered"].append(".toolkit.sha256")
        return result

    for line in manifest_text.splitlines():
        parts = line.split()
        if len(parts) != 2:
            continue
        expected_hash, filename = parts
        filepath = TOOLKIT_DIR / filename
        if not filepath.exists():
            result["ok"] = False
            result["missing"].append(filename)
            continue
        actual_hash = hashlib.sha256(filepath.read_bytes()).hexdigest()
        if actual_hash != expected_hash:
            result["ok"] = False
            result["tampered"].append(filename)

    return result
