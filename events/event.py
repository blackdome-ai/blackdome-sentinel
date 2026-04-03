from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from hashlib import sha256
import json
from typing import Any


@dataclass(slots=True)
class RawEvent:
    timestamp: datetime
    source: str
    event_type: str
    subject: dict[str, Any] = field(default_factory=dict)
    object: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def event_id(self) -> str:
        payload = {
            "timestamp": self._iso_timestamp(),
            "source": self.source,
            "event_type": self.event_type,
            "subject": self.subject,
            "object": self.object,
            "metadata": self.metadata,
        }
        canonical = json.dumps(
            payload,
            default=str,
            separators=(",", ":"),
            sort_keys=True,
        )
        return sha256(canonical.encode("utf-8")).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "timestamp": self._iso_timestamp(),
            "source": self.source,
            "event_type": self.event_type,
            "subject": self.subject,
            "object": self.object,
            "metadata": self.metadata,
        }

    def _iso_timestamp(self) -> str:
        if self.timestamp.tzinfo is None:
            return self.timestamp.isoformat()
        return self.timestamp.astimezone(timezone.utc).isoformat()
