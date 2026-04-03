from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from datetime import datetime, timezone
from typing import Any

from events.event import RawEvent

from .packet import IncidentPacket

PERSISTENCE_PREFIXES = (
    "/etc/cron",
    "/var/spool/cron",
    "/etc/systemd",
    "/etc/rc.local",
    "/etc/init.d",
)


class MicroBatcher:
    def __init__(
        self,
        host_id: str,
        host_doctrine: dict[str, Any],
        on_packet: Callable[[IncidentPacket], Awaitable[None]],
        default_window: float = 30,
    ) -> None:
        self._host_id = host_id
        self._host_doctrine = dict(host_doctrine)
        self._on_packet = on_packet
        self._default_window = max(float(default_window), 0.0)
        self._active_packet: IncidentPacket | None = None
        self._close_deadline: float | None = None
        self._hard_deadline: float | None = None
        self._close_task: asyncio.Task[None] | None = None
        self._lock = asyncio.Lock()

    async def add_event(self, event: RawEvent) -> None:
        packet_to_emit: IncidentPacket | None = None

        async with self._lock:
            if self._active_packet is None:
                self._open_packet_locked(event)
                return

            active_events = self._packet_events_locked()
            if any(self._events_related(existing, event) for existing in active_events):
                self._active_packet.related_events.append(event)
                self._refresh_window_locked(event)
            else:
                packet_to_emit = self._emit_packet_locked()
                self._open_packet_locked(event)

        if packet_to_emit is not None:
            await self._on_packet(packet_to_emit)

    async def flush(self) -> None:
        packet_to_emit: IncidentPacket | None = None

        async with self._lock:
            packet_to_emit = self._emit_packet_locked()

        if packet_to_emit is not None:
            await self._on_packet(packet_to_emit)

    async def _close_after(self, seconds: float, packet_id: str) -> None:
        try:
            await asyncio.sleep(seconds)
        except asyncio.CancelledError:
            return

        packet_to_emit: IncidentPacket | None = None
        current_task = asyncio.current_task()

        async with self._lock:
            if self._active_packet is None or self._active_packet.packet_id != packet_id:
                return
            if self._close_deadline is not None:
                remaining = self._close_deadline - asyncio.get_running_loop().time()
                if remaining > 0.01:
                    return
            packet_to_emit = self._emit_packet_locked(current_task=current_task)

        if packet_to_emit is not None:
            await self._on_packet(packet_to_emit)

    def _open_packet_locked(self, event: RawEvent) -> None:
        loop = asyncio.get_running_loop()
        now = loop.time()

        self._active_packet = IncidentPacket(
            window_start=event.timestamp,
            window_end=event.timestamp,
            host_id=self._host_id,
            trigger_event=event,
            baseline_status=self._gather_baseline_status([event]),
            host_doctrine=dict(self._host_doctrine),
        )
        self._hard_deadline = now + 120.0
        self._schedule_close_locked(event)

    def _refresh_window_locked(self, event: RawEvent) -> None:
        if self._active_packet is None:
            return
        self._schedule_close_locked(event)

    def _schedule_close_locked(self, event: RawEvent) -> None:
        if self._active_packet is None:
            return

        loop = asyncio.get_running_loop()
        now = loop.time()
        hard_deadline = self._hard_deadline if self._hard_deadline is not None else now + 120.0
        window = 5.0 if self._is_high_urgency(event) else min(self._default_window, 120.0)
        deadline = min(now + window, hard_deadline)
        seconds = max(0.0, deadline - now)

        if self._close_task is not None:
            self._close_task.cancel()

        self._close_deadline = deadline
        self._close_task = asyncio.create_task(
            self._close_after(seconds, self._active_packet.packet_id)
        )

    def _emit_packet_locked(
        self,
        current_task: asyncio.Task[None] | None = None,
    ) -> IncidentPacket | None:
        packet = self._active_packet
        if packet is None:
            return None

        if self._close_task is not None and self._close_task is not current_task:
            self._close_task.cancel()

        events = self._packet_events_locked()
        packet.window_end = datetime.now(timezone.utc)
        packet.process_tree = self._gather_process_tree(events)
        packet.network_context = self._gather_network_context(events)
        packet.file_context = self._gather_file_context(events)
        packet.persistence_context = self._gather_persistence_context(events)
        packet.baseline_status = self._gather_baseline_status(events)
        packet.host_doctrine = dict(self._host_doctrine)

        self._active_packet = None
        self._close_deadline = None
        self._hard_deadline = None
        self._close_task = None
        return packet

    def _packet_events_locked(self) -> list[RawEvent]:
        if self._active_packet is None:
            return []
        return [self._active_packet.trigger_event, *self._active_packet.related_events]

    def _is_high_urgency(self, event: RawEvent) -> bool:
        exe_path = self._extract_binary_path(event)
        if exe_path.startswith("/tmp") or exe_path.startswith("/dev/shm"):
            return True
        return bool(event.metadata.get("deleted_exe"))

    def _events_related(self, a: RawEvent, b: RawEvent) -> bool:
        if self._shared_process_identity(a, b):
            return True
        if self._extract_binary_path(a) and self._extract_binary_path(a) == self._extract_binary_path(b):
            return True
        if self._extract_dest_ip(a) and self._extract_dest_ip(a) == self._extract_dest_ip(b):
            return True
        return bool(self._extract_file_paths(a) & self._extract_file_paths(b))

    def _gather_process_tree(self, events: list[RawEvent]) -> dict[str, Any]:
        processes: dict[str, dict[str, Any]] = {}

        for event in events:
            pid = event.subject.get("pid")
            if pid is None:
                continue

            key = str(pid)
            entry = processes.setdefault(
                key,
                {
                    "pid": pid,
                    "ppid": event.subject.get("ppid"),
                    "uid": event.subject.get("uid"),
                    "binary": event.subject.get("binary"),
                    "cmdline": event.subject.get("cmdline"),
                    "sources": [],
                    "event_ids": [],
                },
            )
            if event.source not in entry["sources"]:
                entry["sources"].append(event.source)
            entry["event_ids"].append(event.event_id)

        return {
            "root_pid": events[0].subject.get("pid") if events else None,
            "processes": list(processes.values()),
        }

    def _gather_network_context(self, events: list[RawEvent]) -> list[dict[str, Any]]:
        context: list[dict[str, Any]] = []
        seen: set[tuple[Any, ...]] = set()

        for event in events:
            dest_ip = self._extract_dest_ip(event)
            if not dest_ip:
                continue

            dest_port = event.object.get("dest_port", event.metadata.get("dest_port"))
            protocol = event.object.get("protocol", event.metadata.get("protocol"))
            record = {
                "event_id": event.event_id,
                "source": event.source,
                "dest_ip": dest_ip,
                "dest_port": dest_port,
                "protocol": protocol,
            }
            key = (dest_ip, dest_port, protocol)
            if key in seen:
                continue
            seen.add(key)
            context.append(record)

        return context

    def _gather_file_context(self, events: list[RawEvent]) -> list[dict[str, Any]]:
        context: list[dict[str, Any]] = []
        seen: set[tuple[str, str, str]] = set()

        for event in events:
            for key_name in ("path", "file_path", "exe_path"):
                path = event.object.get(key_name)
                if not isinstance(path, str) or not path:
                    continue

                signature = (path, event.source, key_name)
                if signature in seen:
                    continue
                seen.add(signature)
                context.append(
                    {
                        "event_id": event.event_id,
                        "source": event.source,
                        "path": path,
                        "field": key_name,
                        "event_type": event.event_type,
                    }
                )

        return context

    def _gather_persistence_context(self, events: list[RawEvent]) -> list[dict[str, Any]]:
        persistence: list[dict[str, Any]] = []

        for entry in self._gather_file_context(events):
            path = entry.get("path", "")
            if isinstance(path, str) and self._is_persistence_path(path):
                persistence.append(entry)

        return persistence

    def _gather_baseline_status(self, events: list[RawEvent]) -> dict[str, Any]:
        status: dict[str, Any] = {}

        for event in events:
            baseline = event.metadata.get("baseline_status")
            if isinstance(baseline, dict):
                status.update(baseline)

        return status

    @staticmethod
    def _extract_binary_path(event: RawEvent) -> str:
        for candidate in (
            event.object.get("exe_path"),
            event.subject.get("binary"),
        ):
            if isinstance(candidate, str) and candidate:
                return candidate
        return ""

    @staticmethod
    def _extract_dest_ip(event: RawEvent) -> str:
        for source in (event.object, event.metadata):
            value = source.get("dest_ip")
            if isinstance(value, str) and value:
                return value
        return ""

    @staticmethod
    def _extract_file_paths(event: RawEvent) -> set[str]:
        paths: set[str] = set()

        for key in ("path", "file_path", "exe_path"):
            value = event.object.get(key)
            if isinstance(value, str) and value:
                paths.add(value)

        return paths

    @staticmethod
    def _shared_process_identity(a: RawEvent, b: RawEvent) -> bool:
        process_ids = {
            a.subject.get("pid"),
            a.subject.get("ppid"),
        }
        other_ids = {
            b.subject.get("pid"),
            b.subject.get("ppid"),
        }
        process_ids.discard(None)
        other_ids.discard(None)
        return bool(process_ids & other_ids)

    @staticmethod
    def _is_persistence_path(path: str) -> bool:
        return any(path.startswith(prefix) for prefix in PERSISTENCE_PREFIXES)
