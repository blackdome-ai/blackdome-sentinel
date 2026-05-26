"""Cached hostile IP feed sourced from BlackDome honeypot data."""

from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import subprocess
from pathlib import Path
from typing import Any

try:  # pragma: no cover - optional dependency in runtime environments
    import asyncpg
except ImportError:  # pragma: no cover - dependency may not be present in local verification
    asyncpg = None

from .control_plane import control_plane_config, control_plane_enabled, control_plane_headers, request_json


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DB_URL = os.getenv("DATABASE_URL", "postgresql://ku_app:ku_local_gex44@localhost:5432/defaultdb")
SCANNER_WHITELIST_ORGS = [
    "censys",
    "shodan",
    "reposify",
    "greynoise",
    "binary edge",
    "securitytrails",
    "rapid7",
    "qualys",
    "tenable",
]
SCANNER_WHITELIST_HOSTNAMES = [
    "censys.io",
    "shodan.io",
    "reposify.net",
    "greynoise.io",
    "binaryedge.io",
]
DEFAULT_CACHE_PATH = PROJECT_ROOT / "state" / "hostile_ips.json"

# Friendly-infrastructure ranges that must NEVER enter the hostile feed (and thus
# never drive an auto-block). Tailscale CGNAT (100.64.0.0/10) carries the control
# plane and operator nodes; a control-plane probe to a facade once poisoned the
# feed and self-blocked the DO sentinel (100.98.16.15) on 2026-05-26. The same
# guard is mirrored in actuators/block_ip.py as a last line of defence.
_NEVER_BLOCK_NETWORKS = (
    ipaddress.ip_network("100.64.0.0/10"),        # Tailscale CGNAT (IPv4)
    ipaddress.ip_network("fd7a:115c:a1e0::/48"),  # Tailscale ULA (IPv6)
)


def is_never_block_ip(ip: str) -> bool:
    """True if an IP must never be auto-blocked (tailnet / friendly infra)."""
    try:
        addr = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return False
    if (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_reserved
        or addr.is_multicast
        or addr.is_unspecified
    ):
        return True
    return any(addr in net for net in _NEVER_BLOCK_NETWORKS if addr.version == net.version)


async def fetch_hostile_ips(min_events: int = 3, days: int = 30, db_url: str | None = None) -> set[str]:
    """Fetch hostile IPs from honeypot data, excluding known scanners by org."""
    rows = await _fetch_rows(min_events=min_events, days=days, db_url=db_url)
    hostile: set[str] = set()
    for row in rows:
        ip = str(row.get("ip") or "").strip()
        org = str(row.get("org") or "").lower()
        if not ip:
            continue
        if any(scanner in org for scanner in SCANNER_WHITELIST_ORGS):
            continue
        if is_never_block_ip(ip):
            continue
        hostile.add(ip)
    return hostile


async def fetch_hostile_ips_with_hostnames(min_events: int = 3, days: int = 30, db_url: str | None = None) -> set[str]:
    """Fetch hostile IPs excluding known scanners by org and hostname."""
    rows = await _fetch_rows(min_events=min_events, days=days, db_url=db_url)
    hostile: set[str] = set()
    for row in rows:
        ip = str(row.get("ip") or "").strip()
        org = str(row.get("org") or "").lower()
        hostname = str(row.get("hostname") or "").lower()
        if not ip:
            continue
        if any(scanner in org for scanner in SCANNER_WHITELIST_ORGS):
            continue
        if any(scanner in hostname for scanner in SCANNER_WHITELIST_HOSTNAMES):
            continue
        if is_never_block_ip(ip):
            continue
        hostile.add(ip)
    return hostile


async def update_hostile_feed(
    path: str | Path | None = None,
    min_events: int = 3,
    days: int = 30,
    seed_ips: set[str] | list[str] | tuple[str, ...] | None = None,
    db_url: str | None = None,
    config: dict[str, Any] | None = None,
    state: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Refresh the cached hostile IP list, falling back to cached data when offline."""
    cache_path = Path(path) if path else DEFAULT_CACHE_PATH
    cached_ips = load_cached_hostile_ips(cache_path)
    seeded = {str(item).strip() for item in (seed_ips or []) if str(item).strip()}

    if control_plane_enabled(config, require_auth=True):
        control_plane = control_plane_config(config)
        endpoint = f"{str(control_plane.get('url', '')).rstrip('/')}/api/sentinel/feed/hostile-ips"
        try:
            status_code, response_payload = await request_json(
                "GET",
                endpoint,
                headers=control_plane_headers(config),
                timeout_seconds=float(control_plane.get("timeout_seconds", 30)),
            )
            if status_code == 200 and isinstance(response_payload, dict):
                remote_ips = {
                    str(item).strip()
                    for item in response_payload.get("ips", [])
                    if str(item).strip()
                }
                ips = sorted(remote_ips | seeded)
                save_cached_hostile_ips(ips, cache_path)
                if isinstance(state, dict):
                    state["hostile_feed_count"] = len(ips)
                return {
                    "status": "updated",
                    "reason": "control_plane",
                    "count": len(ips),
                    "ips": ips,
                }
        except Exception:
            pass

    try:
        fetched = await fetch_hostile_ips_with_hostnames(min_events=min_events, days=days, db_url=db_url)
        ips = sorted(fetched | seeded)
        save_cached_hostile_ips(ips, cache_path)
        if isinstance(state, dict):
            state["hostile_feed_count"] = len(ips)
        return {
            "status": "updated",
            "reason": "database",
            "count": len(ips),
            "ips": ips,
        }
    except Exception as exc:  # pragma: no cover - integration path
        ips = sorted(cached_ips | seeded)
        save_cached_hostile_ips(ips, cache_path)
        if isinstance(state, dict):
            state["hostile_feed_count"] = len(ips)
        return {
            "status": "cached",
            "reason": str(exc),
            "count": len(ips),
            "ips": ips,
        }


def load_cached_hostile_ips(path: str | Path | None = None) -> set[str]:
    """Load hostile IPs from the local cache."""
    cache_path = Path(path) if path else DEFAULT_CACHE_PATH
    if not cache_path.exists():
        return set()
    try:
        with cache_path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return set()

    if isinstance(data, list):
        items = data
    elif isinstance(data, dict) and isinstance(data.get("ips"), list):
        items = data["ips"]
    else:
        return set()
    # Self-heal: drop any friendly-infra IPs a poisoned cache may already contain.
    return {
        ip
        for item in items
        if (ip := str(item).strip()) and not is_never_block_ip(ip)
    }


def save_cached_hostile_ips(ips: list[str] | set[str], path: str | Path | None = None) -> Path:
    """Persist hostile IPs as a plain JSON list for offline use."""
    cache_path = Path(path) if path else DEFAULT_CACHE_PATH
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    payload = sorted({
        ip
        for item in ips
        if (ip := str(item).strip()) and not is_never_block_ip(ip)
    })
    with cache_path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)
        handle.write("\n")
    return cache_path


async def _fetch_rows(min_events: int, days: int, db_url: str | None = None) -> list[dict[str, Any]]:
    if asyncpg is None:
        return await asyncio.to_thread(_fetch_rows_via_psql, min_events, days, db_url or DB_URL)

    pool = await asyncpg.create_pool(dsn=db_url or DB_URL)
    try:
        async with pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT e.ip,
                       LOWER(COALESCE(e.geo->>'org', '')) AS org,
                       LOWER(COALESCE(e.payload->>'hostname', '')) AS hostname,
                       COUNT(*) AS event_count
                FROM blackdome_events e
                WHERE e.ip IS NOT NULL
                  AND e.source LIKE 'edge:%'
                  AND e.event_type IN ('auth_success', 'auth_attempt', 'command', 'login')
                  AND e.ts > NOW() - make_interval(days => $2)
                GROUP BY e.ip, LOWER(COALESCE(e.geo->>'org', '')), LOWER(COALESCE(e.payload->>'hostname', ''))
                HAVING COUNT(*) >= $1
                """,
                min_events,
                days,
            )
    finally:
        await pool.close()

    normalized: list[dict[str, Any]] = []
    for row in rows:
        normalized.append(
            {
                "ip": row.get("ip"),
                "org": row.get("org"),
                "hostname": row.get("hostname"),
                "event_count": int(row.get("event_count", 0)),
            }
        )
    return normalized


def _fetch_rows_via_psql(min_events: int, days: int, db_url: str) -> list[dict[str, Any]]:
    query = f"""
        SELECT e.ip,
               LOWER(COALESCE(e.geo->>'org', '')) AS org,
               LOWER(COALESCE(e.payload->>'hostname', '')) AS hostname,
               COUNT(*) AS event_count
        FROM blackdome_events e
        WHERE e.ip IS NOT NULL
          AND e.source LIKE 'edge:%'
          AND e.event_type IN ('auth_success', 'auth_attempt', 'command', 'login')
          AND e.ts > NOW() - INTERVAL '{int(days)} days'
        GROUP BY e.ip, LOWER(COALESCE(e.geo->>'org', '')), LOWER(COALESCE(e.payload->>'hostname', ''))
        HAVING COUNT(*) >= {int(min_events)}
    """
    try:
        result = subprocess.run(
            ["psql", db_url, "-At", "-F", "\t", "-c", query],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
    except FileNotFoundError as exc:
        raise RuntimeError("asyncpg unavailable and psql not installed") from exc
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("hostile feed query timed out") from exc

    if result.returncode != 0:
        stderr = (result.stderr or "").strip() or "psql query failed"
        raise RuntimeError(stderr)

    rows: list[dict[str, Any]] = []
    for line in (result.stdout or "").splitlines():
        parts = line.split("\t")
        if len(parts) != 4:
            continue
        ip, org, hostname, event_count = parts
        if not ip:
            continue
        rows.append(
            {
                "ip": ip,
                "org": org,
                "hostname": hostname,
                "event_count": int(event_count or 0),
            }
        )
    return rows
