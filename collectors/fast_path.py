"""Deterministic fast-path kill for /tmp binaries with outbound C2 connections.

Bypasses the LLM entirely — if a binary is running from a temp directory
AND has an established outbound TCP connection to a non-whitelisted IP,
it is quarantined and killed immediately (<1 second).

The LLM can still classify it after the fact for reporting.
"""

from __future__ import annotations

import hashlib
import ipaddress
import logging
import os
import shutil
import signal
import subprocess
from pathlib import Path
from typing import Any

log = logging.getLogger("sentinel.fast_path")

QUARANTINE_DIR = Path("/var/blackdome/sentinel/quarantine")
TEMP_DIRS = ("/tmp", "/var/tmp", "/dev/shm")

# IPs that are never suspicious for outbound connections
WHITELISTED_NETS = [
    ipaddress.ip_network("127.0.0.0/8"),      # localhost
    ipaddress.ip_network("100.64.0.0/10"),     # Tailscale CGNAT
    ipaddress.ip_network("10.0.0.0/8"),        # private
    ipaddress.ip_network("172.16.0.0/12"),     # private
    ipaddress.ip_network("192.168.0.0/16"),    # private
]


def _is_whitelisted_ip(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in WHITELISTED_NETS)
    except ValueError:
        return False


def _is_temp_path(exe: str) -> bool:
    cleaned = exe.removesuffix(" (deleted)")
    return any(cleaned.startswith(d) for d in TEMP_DIRS)


def _get_outbound_connections(pid: int) -> list[str]:
    """Return list of remote IPs this PID has ESTABLISHED TCP connections to."""
    remote_ips = []
    try:
        # Read /proc/net/tcp for established connections owned by this PID
        fd_dir = Path(f"/proc/{pid}/fd")
        if not fd_dir.exists():
            return []
        socket_inodes = set()
        for fd in fd_dir.iterdir():
            try:
                link = os.readlink(str(fd))
                if link.startswith("socket:["):
                    socket_inodes.add(link.split("[")[1].rstrip("]"))
            except OSError:
                continue

        if not socket_inodes:
            return []

        for line in Path("/proc/net/tcp").read_text().splitlines()[1:]:
            fields = line.split()
            if len(fields) < 10:
                continue
            # State 01 = ESTABLISHED
            if fields[3] != "01":
                continue
            if fields[9] in socket_inodes:
                # Parse remote address (hex encoded)
                remote_hex = fields[2]
                ip_hex, port_hex = remote_hex.split(":")
                ip_int = int(ip_hex, 16)
                # /proc/net/tcp stores in little-endian on x86
                ip_str = f"{ip_int & 0xFF}.{(ip_int >> 8) & 0xFF}.{(ip_int >> 16) & 0xFF}.{(ip_int >> 24) & 0xFF}"
                remote_ips.append(ip_str)
    except Exception as exc:
        log.debug("Failed to read connections for PID %d: %s", pid, exc)

    return remote_ips


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _quarantine_and_kill(pid: int, exe_path: str, remote_ips: list[str]) -> dict[str, Any]:
    """Copy binary, kill process, block IPs. Returns evidence dict."""
    exe = Path(exe_path.removesuffix(" (deleted)"))
    evidence: dict[str, Any] = {
        "pid": pid,
        "exe": exe_path,
        "remote_ips": remote_ips,
        "action": "FAST_PATH_KILL",
    }

    # Step 1: Copy binary to quarantine (before kill!)
    QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
    if exe.exists():
        file_hash = _sha256_file(exe)
        dest = QUARANTINE_DIR / f"{file_hash}_{exe.name}"
        shutil.copy2(exe, dest)
        evidence["sha256"] = file_hash
        evidence["quarantine_path"] = str(dest)
        log.info("FAST_PATH: quarantined %s → %s (sha256=%s)", exe, dest, file_hash[:12])
    elif Path(f"/proc/{pid}/exe").exists():
        # Binary deleted but process still running — recover from /proc
        try:
            dest = QUARANTINE_DIR / f"proc_{pid}_{exe.name}"
            shutil.copy2(f"/proc/{pid}/exe", dest)
            file_hash = _sha256_file(dest)
            final_dest = QUARANTINE_DIR / f"{file_hash}_{exe.name}"
            dest.rename(final_dest)
            evidence["sha256"] = file_hash
            evidence["quarantine_path"] = str(final_dest)
            log.info("FAST_PATH: recovered from /proc/%d/exe → %s", pid, final_dest)
        except Exception as exc:
            log.warning("FAST_PATH: failed to recover /proc/%d/exe: %s", pid, exc)

    # Step 2: SIGKILL
    try:
        os.kill(pid, signal.SIGKILL)
        evidence["killed"] = True
        log.info("FAST_PATH: SIGKILL sent to PID %d (%s)", pid, exe_path)
    except ProcessLookupError:
        evidence["killed"] = False
        log.info("FAST_PATH: PID %d already dead", pid)

    # Step 3: Verify dead
    evidence["verified_dead"] = not Path(f"/proc/{pid}").exists()

    # Step 4: Delete original from temp dir
    if exe.exists():
        try:
            os.remove(exe)
            evidence["original_removed"] = True
        except OSError:
            evidence["original_removed"] = False

    # Step 5: Block remote IPs via iptables
    blocked = []
    for ip in remote_ips:
        if not _is_whitelisted_ip(ip):
            try:
                subprocess.run(
                    ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
                    capture_output=True, check=False, timeout=5,
                )
                blocked.append(ip)
            except Exception:
                pass
    evidence["blocked_ips"] = blocked

    return evidence


def scan_and_kill(extra_whitelist_ips: set[str] | None = None) -> list[dict[str, Any]]:
    """Scan all processes. Kill any temp-dir binary with non-whitelisted outbound TCP.

    Returns list of evidence dicts for each kill (empty list = nothing found).
    Call this BEFORE the LLM reasoning step.
    """
    kills = []
    wl = extra_whitelist_ips or set()

    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        pid = int(entry.name)

        try:
            exe = os.readlink(f"/proc/{pid}/exe")
        except OSError:
            continue

        if not _is_temp_path(exe):
            continue

        remote_ips = _get_outbound_connections(pid)
        suspicious_ips = [ip for ip in remote_ips if not _is_whitelisted_ip(ip) and ip not in wl]

        if suspicious_ips:
            log.critical(
                "FAST_PATH: temp binary %s (PID %d) has outbound to %s — KILLING",
                exe, pid, suspicious_ips,
            )
            evidence = _quarantine_and_kill(pid, exe, suspicious_ips)
            kills.append(evidence)

    return kills
