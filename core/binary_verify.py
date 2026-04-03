"""Helpers for package ownership and binary verification."""

from __future__ import annotations

import subprocess


PACKAGE_TIMEOUT = 5
VERIFY_TIMEOUT = 10


def is_package_managed(path: str) -> tuple[bool, str]:
    """Check whether a binary is owned by a package."""
    try:
        result = subprocess.run(
            ["dpkg", "-S", path],
            capture_output=True,
            text=True,
            timeout=PACKAGE_TIMEOUT,
            check=False,
        )
    except FileNotFoundError:
        return False, "dpkg unavailable"
    except subprocess.TimeoutExpired:
        return False, "dpkg timeout"

    if result.returncode == 0:
        package = result.stdout.strip().split(":", 1)[0]
        return True, package
    return False, ""


def verify_hash(path: str) -> tuple[bool, str]:
    """Verify a binary against package checksums when available."""
    try:
        result = subprocess.run(
            ["debsums", "--changed", path],
            capture_output=True,
            text=True,
            timeout=VERIFY_TIMEOUT,
            check=False,
        )
    except FileNotFoundError:
        return False, "debsums unavailable"
    except subprocess.TimeoutExpired:
        return False, "debsums timeout"

    if result.returncode == 0 and not result.stdout.strip():
        return True, "matches"

    output = result.stdout.strip() or result.stderr.strip()
    return False, output or "unknown"
