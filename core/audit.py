"""Immutable append-only JSONL audit trail."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class AuditTrail:
    """Append-only JSONL audit log."""

    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path else PROJECT_ROOT / "logs" / "audit.jsonl"

    def log_event(self, event_type: str, payload: dict[str, Any]) -> None:
        self._append({"event_type": event_type, "payload": payload})

    def log_scan(self, evidence_bundle: dict[str, Any], summary: dict[str, Any]) -> None:
        self._append(
            {
                "event_type": "scan_cycle",
                "payload": {
                    "evidence_bundle": evidence_bundle,
                    "summary": summary,
                },
            }
        )

    def log_action(self, action: dict[str, Any]) -> None:
        self._append({"event_type": "action", "payload": action})

    def log_decision(self, decision: dict[str, Any]) -> None:
        self._append({"event_type": "decision", "payload": decision})

    def _append(self, record: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        envelope = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            **record,
        }
        with self.path.open("a", encoding="utf-8") as handle:
            json.dump(envelope, handle, sort_keys=True)
            handle.write("\n")
