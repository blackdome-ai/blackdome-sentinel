from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from hashlib import sha256
import json
from typing import Any
from uuid import uuid4

from events.event import RawEvent


@dataclass(slots=True)
class IncidentPacket:
    window_start: datetime
    window_end: datetime
    host_id: str
    trigger_event: RawEvent
    related_events: list[RawEvent] = field(default_factory=list)
    process_tree: dict[str, Any] = field(default_factory=dict)
    network_context: list[dict[str, Any]] = field(default_factory=list)
    file_context: list[dict[str, Any]] = field(default_factory=list)
    persistence_context: list[dict[str, Any]] = field(default_factory=list)
    baseline_status: dict[str, Any] = field(default_factory=dict)
    host_doctrine: dict[str, Any] = field(default_factory=dict)
    packet_id: str = field(default_factory=lambda: uuid4().hex)

    @property
    def event_count(self) -> int:
        return (1 if self.trigger_event else 0) + len(self.related_events)

    @property
    def dedup_fingerprint(self) -> str:
        binary_path = self.trigger_event.subject.get("binary", "")
        exe_path = self.trigger_event.object.get("exe_path", "")
        cmdline = self.trigger_event.subject.get("cmdline", "")[:100]
        dest_ips = sorted(self._collect_dest_ips())
        file_paths = sorted(self._collect_file_paths())
        payload = {
            "binary_path": binary_path,
            "exe_path": exe_path,
            "cmdline": cmdline,
            "dest_ips": dest_ips,
            "file_paths": file_paths,
            "host_id": self.host_id,
        }
        canonical = json.dumps(payload, separators=(",", ":"), sort_keys=True)
        return sha256(canonical.encode("utf-8")).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {
            "packet_id": self.packet_id,
            "window_start": self.window_start.isoformat(),
            "window_end": self.window_end.isoformat(),
            "host_id": self.host_id,
            "trigger_event": self.trigger_event.to_dict(),
            "related_events": [event.to_dict() for event in self.related_events],
            "process_tree": self.process_tree,
            "network_context": self.network_context,
            "file_context": self.file_context,
            "persistence_context": self.persistence_context,
            "baseline_status": self.baseline_status,
            "host_doctrine": self.host_doctrine,
            "event_count": self.event_count,
            "dedup_fingerprint": self.dedup_fingerprint,
        }

    def _collect_dest_ips(self) -> set[str]:
        dest_ips: set[str] = set()

        for event in self._all_events():
            for source in (event.object, event.metadata):
                dest_ip = source.get("dest_ip")
                if isinstance(dest_ip, str) and dest_ip:
                    dest_ips.add(dest_ip)

        for entry in self.network_context:
            dest_ip = entry.get("dest_ip")
            if isinstance(dest_ip, str) and dest_ip:
                dest_ips.add(dest_ip)

        return dest_ips

    def _collect_file_paths(self) -> set[str]:
        file_paths: set[str] = set()

        for event in self._all_events():
            for key in ("path", "file_path", "exe_path"):
                value = event.object.get(key)
                if isinstance(value, str) and value:
                    file_paths.add(value)

        for entry in self.file_context:
            path = entry.get("path")
            if isinstance(path, str) and path:
                file_paths.add(path)

        return file_paths

    def _all_events(self) -> list[RawEvent]:
        return [self.trigger_event, *self.related_events]
