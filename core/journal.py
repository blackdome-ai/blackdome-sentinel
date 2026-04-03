"""Hash-chained event journal with write-ahead intent and replay."""

from __future__ import annotations

import hashlib
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


log = logging.getLogger("sentinel.journal")

DEFAULT_JOURNAL_PATH = "/var/blackdome/sentinel/event_journal.jsonl"
DEFAULT_CHECKPOINT_PATH = "/var/blackdome/sentinel/last_checkpoint.json"
GENESIS_HASH = "000000"


class EventJournal:
    """Append-only JSONL journal with a tamper-evident hash chain."""

    def __init__(self, path: str = DEFAULT_JOURNAL_PATH, checkpoint_path: str = DEFAULT_CHECKPOINT_PATH) -> None:
        self.path = Path(path)
        self.checkpoint_path = Path(checkpoint_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.checkpoint_path.parent.mkdir(parents=True, exist_ok=True)
        self._seq = self._load_last_seq()
        self._prev_hash = self._load_last_hash()

    def _load_last_seq(self) -> int:
        last_entry = self._load_last_entry()
        return int(last_entry.get("seq", 0)) if last_entry else 0

    def _load_last_hash(self) -> str:
        last_entry = self._load_last_entry()
        if not last_entry:
            return GENESIS_HASH
        return str(last_entry.get("entry_hash") or GENESIS_HASH)

    def _load_last_entry(self) -> dict[str, Any] | None:
        if not self.path.exists():
            return None

        last_entry: dict[str, Any] | None = None
        with self.path.open("r", encoding="utf-8") as handle:
            for raw_line in handle:
                line = raw_line.strip()
                if not line:
                    continue
                try:
                    last_entry = json.loads(line)
                except json.JSONDecodeError:
                    log.warning("Skipping malformed journal line while loading state")
        return last_entry

    def _hash_entry(self, entry: dict[str, Any]) -> str:
        canonical = json.dumps(
            {key: value for key, value in entry.items() if key != "entry_hash"},
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        ).encode("utf-8")
        return hashlib.sha256(canonical).hexdigest()

    def _next_entry(self, payload: dict[str, Any]) -> dict[str, Any]:
        self._seq += 1
        entry = {
            "seq": self._seq,
            "prev_hash": self._prev_hash,
            "ts": datetime.now(timezone.utc).isoformat(),
            **payload,
        }
        entry["entry_hash"] = self._hash_entry(entry)
        return entry

    def write_intent(
        self,
        action: str,
        target: str,
        reason: str,
        evidence: dict[str, Any] | None = None,
    ) -> int:
        """Write an INTENT entry before executing an action."""
        entry = self._next_entry(
            {
                "status": "intent",
                "type": action,
                "target": target,
                "reason": reason,
                "evidence": evidence or {},
            }
        )
        self._append(entry)
        return int(entry["seq"])

    def write_completed(
        self,
        intent_seq: int,
        action: str,
        target: str,
        result: str,
        details: dict[str, Any] | None = None,
    ) -> int:
        """Write a COMPLETED entry after an action executes."""
        entry = self._next_entry(
            {
                "status": "completed",
                "intent_seq": intent_seq,
                "type": action,
                "target": target,
                "result": result,
                "details": details or {},
            }
        )
        self._append(entry)
        return int(entry["seq"])

    def write_allow(self, path: str, file_hash: str) -> int:
        """Write a compact allow event for known-good activity."""
        entry = self._next_entry(
            {
                "status": "allow",
                "type": "allow",
                "path": path,
                "hash": file_hash,
            }
        )
        self._append(entry)
        return int(entry["seq"])

    def _append(self, entry: dict[str, Any]) -> None:
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, sort_keys=True, default=str))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        self._prev_hash = str(entry["entry_hash"])

    def get_unreplayed_entries(self) -> list[dict[str, Any]]:
        """Return entries after the last signed checkpoint for replay."""
        checkpoint_seq = 0
        if self.checkpoint_path.exists():
            try:
                checkpoint = json.loads(self.checkpoint_path.read_text(encoding="utf-8"))
                checkpoint_seq = int(checkpoint.get("last_verified_seq", 0))
            except (json.JSONDecodeError, OSError, TypeError, ValueError):
                log.warning("Unable to read journal checkpoint; replaying from start")

        entries: list[dict[str, Any]] = []
        if not self.path.exists():
            return entries

        with self.path.open("r", encoding="utf-8") as handle:
            for raw_line in handle:
                line = raw_line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    log.warning("Skipping malformed journal line during replay load")
                    continue
                if int(entry.get("seq", 0)) > checkpoint_seq:
                    entries.append(entry)
        return entries

    def save_checkpoint(self, checkpoint: dict[str, Any]) -> None:
        """Persist the latest signed checkpoint from the control plane."""
        self.checkpoint_path.write_text(json.dumps(checkpoint, sort_keys=True, default=str), encoding="utf-8")
