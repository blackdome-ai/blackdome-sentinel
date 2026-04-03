"""JSON-backed persisted state store."""

from __future__ import annotations

import json
import os
from copy import deepcopy
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class StateStore:
    """Persist BlackDome Sentinel state as a JSON document."""

    DEFAULT_STATE = {
        "last_scan_at": None,
        "last_scan_result": "clean",
        "active_incidents": [],
        "quarantined_files": [],
        "blocked_ips": [],
        "scan_count": 0,
        "baseline_hash": None,
        "onboarding_phase": "health_check",
        "onboarding_started_at": None,
        "onboarding_phase_started_at": None,
        "baseline_confirmed_at": None,
        "protect_enabled_at": None,
        "compromised_reason": None,
        "hostile_feed_updated_at": None,
        "hostile_feed_count": 0,
    }

    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path else PROJECT_ROOT / "state" / "sentinel_state.json"

    def load(self) -> dict[str, Any]:
        if not self.path.exists():
            return deepcopy(self.DEFAULT_STATE)
        with self.path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
        if not isinstance(data, dict):
            return deepcopy(self.DEFAULT_STATE)
        merged = deepcopy(self.DEFAULT_STATE)
        merged.update(data)
        return merged

    def save(self, state: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = deepcopy(self.DEFAULT_STATE)
        payload.update(state)
        tmp_path = self.path.with_name(f"{self.path.name}.tmp")
        with tmp_path.open("w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
        os.replace(tmp_path, self.path)

    def update(self, key: str, value: Any) -> dict[str, Any]:
        state = self.load()
        state[key] = value
        self.save(state)
        return state
