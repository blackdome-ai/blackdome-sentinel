"""Lightweight host facades -- fake services on unused ports.

Detects per-host port scanning. If anything connects to a fake Redis
on a PostgreSQL-only server, that's a probe. Zero false positives.

These are TRIPWIRES, not full interactive honeypots. They accept the
connection, capture source IP + first bytes, emit a CRITICAL event,
then close. Minimal resource usage.
"""
from __future__ import annotations

import asyncio
import logging
import socket
from datetime import datetime, timezone
from typing import Any, Callable, Awaitable

log = logging.getLogger("sentinel.deception.facades")

# Facade definitions: port -> service name + banner
FACADE_CATALOG = {
    21: {"service": "ftp", "banner": b"220 ProFTPD 1.3.7 Server ready.\r\n"},
    25: {"service": "smtp", "banner": b"220 mail.localdomain ESMTP Postfix\r\n"},
    3306: {"service": "mysql", "banner": b"\x4a\x00\x00\x00\x0a5.7.42\x00"},
    6379: {"service": "redis", "banner": b"-ERR unknown command\r\n"},
    27017: {"service": "mongodb", "banner": b""},
    445: {"service": "smb", "banner": b""},
    5432: {"service": "postgresql", "banner": b""},
    8080: {"service": "http", "banner": b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.54\r\n\r\n"},
    11211: {"service": "memcached", "banner": b"VERSION 1.6.17\r\n"},
    9200: {"service": "elasticsearch", "banner": b'{"name":"node-1","cluster_name":"elasticsearch","version":{"number":"7.17.0"}}\n'},
}


def detect_used_ports() -> set[int]:
    """Scan which ports are actually in use on this host."""
    used = set()
    try:
        with open("/proc/net/tcp") as f:
            for line in f.readlines()[1:]:
                parts = line.split()
                if len(parts) >= 4:
                    local_addr = parts[1]
                    state = parts[3]
                    if state == "0A":  # LISTEN
                        port = int(local_addr.split(":")[1], 16)
                        used.add(port)
    except Exception as exc:
        log.warning("Failed to read /proc/net/tcp: %s", exc)
    try:
        with open("/proc/net/tcp6") as f:
            for line in f.readlines()[1:]:
                parts = line.split()
                if len(parts) >= 4:
                    local_addr = parts[1]
                    state = parts[3]
                    if state == "0A":
                        port = int(local_addr.split(":")[1], 16)
                        used.add(port)
    except Exception:
        pass
    return used


def select_facade_ports(
    config: dict[str, Any] | None = None,
) -> dict[int, dict[str, str]]:
    """Auto-detect used ports and select facades for unused ones."""
    used = detect_used_ports()
    config = config or {}
    auto_detect = config.get("auto_detect", True)
    exclude_ports = set(config.get("exclude_ports", []))
    force_enable = set(config.get("force_enable", []))
    force_disable = set(config.get("force_disable", []))

    selected = {}
    for port, info in FACADE_CATALOG.items():
        if port in force_disable:
            continue
        if port in force_enable:
            selected[port] = info
            continue
        if auto_detect and port not in used and port not in exclude_ports:
            selected[port] = info

    log.info(
        "Facade selection: used_ports=%s, selected_facades=%s",
        sorted(used & set(FACADE_CATALOG.keys())),
        {p: v["service"] for p, v in sorted(selected.items())},
    )
    return selected


class FacadeRunner:
    """Runs lightweight tripwire facades on unused ports."""

    def __init__(
        self,
        on_probe: Callable[[dict[str, Any]], Awaitable[None]],
        config: dict[str, Any] | None = None,
    ) -> None:
        self._on_probe = on_probe
        self._config = config or {}
        self._servers: list[asyncio.Server] = []

    async def start(self) -> int:
        """Start facades on available ports. Returns count of started facades."""
        selected = select_facade_ports(self._config)
        started = 0

        for port, info in selected.items():
            try:
                service = info["service"]
                banner = info["banner"]
                server = await asyncio.start_server(
                    lambda r, w, s=service, b=banner, p=port: self._handle_connection(r, w, s, b, p),
                    "0.0.0.0", port,
                )
                self._servers.append(server)
                started += 1
                log.info("Facade started: %s on port %d", service, port)
            except OSError as exc:
                log.debug("Cannot bind facade %s on port %d: %s", info["service"], port, exc)

        return started

    async def _handle_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        service: str,
        banner: bytes,
        port: int,
    ) -> None:
        """Handle a probe connection — capture, alert, close."""
        peer = writer.get_extra_info("peername")
        source_ip = peer[0] if peer else "unknown"
        source_port = peer[1] if peer else 0

        log.warning(
            "FACADE PROBE: %s:%d -> %s (port %d)",
            source_ip, source_port, service, port,
        )

        # Send banner if we have one
        if banner:
            try:
                writer.write(banner)
                await writer.drain()
            except Exception:
                pass

        # Try to read first bytes from the prober
        first_bytes = b""
        try:
            first_bytes = await asyncio.wait_for(reader.read(1024), timeout=5.0)
        except Exception:
            pass

        # Close connection
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

        # Emit CRITICAL event
        await self._on_probe({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source": "facade",
            "event_type": "facade_probe",
            "service": service,
            "port": port,
            "source_ip": source_ip,
            "source_port": source_port,
            "first_bytes": first_bytes[:256].hex() if first_bytes else "",
            "first_bytes_text": first_bytes[:256].decode(errors="replace") if first_bytes else "",
            "severity": "critical",
        })

    async def stop(self) -> None:
        """Stop all facade servers."""
        for server in self._servers:
            server.close()
            await server.wait_closed()
        self._servers.clear()

    async def refresh(self) -> int:
        """Re-detect ports and restart facades. Returns new count."""
        await self.stop()
        return await self.start()
