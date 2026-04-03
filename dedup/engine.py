from __future__ import annotations

from dataclasses import asdict, dataclass
import json
from pathlib import Path
import time


@dataclass(slots=True)
class DedupEntry:
    fingerprint: str
    first_seen: float
    last_seen: float
    count: int
    last_verdict: str | None = None
    escalated: bool = False


class DedupEngine:
    def __init__(
        self,
        state_path: str = "state/dedup_state.json",
        cooldown_hours: int = 6,
    ) -> None:
        self._state_path = Path(state_path)
        self._cooldown_seconds = max(int(cooldown_hours), 0) * 3600
        self._entries: dict[str, DedupEntry] = {}
        self._load()

    def should_analyze(self, fingerprint: str) -> tuple[bool, str]:
        now = time.time()
        if self._prune_expired(now):
            self._save()

        entry = self._entries.get(fingerprint)
        if entry is None:
            self._entries[fingerprint] = DedupEntry(
                fingerprint=fingerprint,
                first_seen=now,
                last_seen=now,
                count=1,
            )
            self._save()
            return True, "new fingerprint"

        if now - entry.last_seen >= self._cooldown_seconds:
            entry.first_seen = now
            entry.last_seen = now
            entry.count = 1
            entry.escalated = False
            self._save()
            return True, "cooldown expired"

        entry.last_seen = now
        entry.count += 1
        if entry.count >= 3:
            entry.escalated = True
            self._save()
            return True, "escalation threshold reached"

        self._save()
        return False, "within cooldown"

    def record_verdict(self, fingerprint: str, verdict: str) -> None:
        now = time.time()
        if self._prune_expired(now):
            self._save()

        entry = self._entries.get(fingerprint)
        if entry is None:
            entry = DedupEntry(
                fingerprint=fingerprint,
                first_seen=now,
                last_seen=now,
                count=1,
            )
            self._entries[fingerprint] = entry

        entry.last_seen = now
        entry.last_verdict = verdict
        self._save()

    def get_cached_verdict(self, fingerprint: str) -> str | None:
        now = time.time()
        if self._prune_expired(now):
            self._save()

        entry = self._entries.get(fingerprint)
        if entry is None:
            return None
        return entry.last_verdict

    def reset(self, fingerprint: str) -> None:
        if fingerprint in self._entries:
            del self._entries[fingerprint]
            self._save()

    def _prune_expired(self, now: float) -> bool:
        expired = [
            fingerprint
            for fingerprint, entry in self._entries.items()
            if now - entry.last_seen > 24 * 3600
        ]
        for fingerprint in expired:
            del self._entries[fingerprint]
        return bool(expired)

    def _load(self) -> None:
        if not self._state_path.exists():
            return

        try:
            payload = json.loads(self._state_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return

        entries = payload.get("entries", {})
        if not isinstance(entries, dict):
            return

        loaded: dict[str, DedupEntry] = {}
        for fingerprint, raw_entry in entries.items():
            if not isinstance(raw_entry, dict):
                continue
            try:
                loaded[fingerprint] = DedupEntry(
                    fingerprint=raw_entry.get("fingerprint", fingerprint),
                    first_seen=float(raw_entry["first_seen"]),
                    last_seen=float(raw_entry["last_seen"]),
                    count=int(raw_entry["count"]),
                    last_verdict=raw_entry.get("last_verdict"),
                    escalated=bool(raw_entry.get("escalated", False)),
                )
            except (KeyError, TypeError, ValueError):
                continue

        self._entries = loaded
        now = time.time()
        if self._prune_expired(now):
            self._save()

    def _save(self) -> None:
        self._state_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "entries": {
                fingerprint: asdict(entry)
                for fingerprint, entry in self._entries.items()
            }
        }
        self._state_path.write_text(
            json.dumps(payload, indent=2, sort_keys=True),
            encoding="utf-8",
        )
