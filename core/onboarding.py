"""Tenant onboarding lifecycle helpers."""

from __future__ import annotations

import json
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .hostile_feed import load_cached_hostile_ips


PHASES = ["health_check", "discovery", "confirmation_pending", "observe", "protect"]
COMPROMISED_PHASE = "compromised"


class OnboardingManager:
    """Manage onboarding phase transitions and candidate baseline growth."""

    def __init__(self, config: dict[str, Any], state_store: Any, baseline_generator: Any, baseline_path: str | Path) -> None:
        self.config = config
        self.state_store = state_store
        self.baseline_generator = baseline_generator
        self.baseline_path = Path(baseline_path)
        self.onboarding_config = config.get("onboarding", {}) if isinstance(config.get("onboarding"), dict) else {}
        self.threat_intel_config = config.get("threat_intel", {}) if isinstance(config.get("threat_intel"), dict) else {}
        self.hostile_feed_path = Path(self.threat_intel_config.get("hostile_feed_path", "state/hostile_ips.json"))
        if not self.hostile_feed_path.is_absolute():
            self.hostile_feed_path = self.baseline_generator.project_root / self.hostile_feed_path

    def ensure_state(self, state: dict[str, Any]) -> dict[str, Any]:
        now = self._now_iso()
        updated = deepcopy(state)
        if updated.get("onboarding_phase") not in PHASES + [COMPROMISED_PHASE]:
            updated["onboarding_phase"] = "health_check"
        updated.setdefault("onboarding_started_at", now)
        updated.setdefault("onboarding_phase_started_at", now)
        updated.setdefault("baseline_confirmed_at", None)
        updated.setdefault("protect_enabled_at", None)
        updated.setdefault("compromised_reason", None)
        updated.setdefault("hostile_feed_updated_at", None)
        updated.setdefault("hostile_feed_count", 0)
        return updated

    def current_phase(self, state: dict[str, Any]) -> str:
        ensured = self.ensure_state(state)
        return str(ensured.get("onboarding_phase", "health_check"))

    def discovery_days(self) -> int:
        return max(1, int(self.onboarding_config.get("discovery_days", 3)))

    def observe_days(self) -> int:
        return max(1, int(self.onboarding_config.get("observe_days", 11)))

    def phase_started_at(self, state: dict[str, Any]) -> datetime:
        value = self.ensure_state(state).get("onboarding_phase_started_at")
        return self._parse_datetime(value)

    def phase_age(self, state: dict[str, Any]) -> timedelta:
        return datetime.now(timezone.utc) - self.phase_started_at(state)

    def phase_age_days(self, state: dict[str, Any]) -> float:
        return self.phase_age(state).total_seconds() / 86400.0

    def set_phase(self, state: dict[str, Any], phase: str, reason: str | None = None) -> dict[str, Any]:
        if phase not in PHASES + [COMPROMISED_PHASE]:
            raise ValueError(f"Unsupported onboarding phase: {phase}")
        updated = self.ensure_state(state)
        now = self._now_iso()
        updated["onboarding_phase"] = phase
        updated["onboarding_phase_started_at"] = now
        if phase == "observe":
            updated["baseline_confirmed_at"] = now
        if phase == "protect":
            updated["protect_enabled_at"] = now
        if phase == COMPROMISED_PHASE:
            updated["compromised_reason"] = reason or "compromise indicators detected"
        elif reason is not None:
            updated["compromised_reason"] = reason
        return updated

    def reset(self, preserve_scan_count: bool = True) -> dict[str, Any]:
        current = self.ensure_state(self.state_store.load())
        preserved_scan_count = current.get("scan_count", 0) if preserve_scan_count else 0
        updated = self.set_phase(current, "health_check", reason=None)
        updated["compromised_reason"] = None
        updated["baseline_confirmed_at"] = None
        updated["protect_enabled_at"] = None
        updated["onboarding_started_at"] = self._now_iso()
        if preserve_scan_count:
            updated["scan_count"] = preserved_scan_count
        self.state_store.save(updated)
        return updated

    def confirm_baseline(self) -> dict[str, Any]:
        state = self.ensure_state(self.state_store.load())
        updated = self.set_phase(state, "observe", reason=None)
        self.state_store.save(updated)
        return updated

    def enable_protect(self) -> dict[str, Any]:
        state = self.ensure_state(self.state_store.load())
        updated = self.set_phase(state, "protect", reason=None)
        self.state_store.save(updated)
        return updated

    def merge_candidate_baseline(self, current_snapshot: dict[str, Any]) -> dict[str, Any]:
        existing = self.baseline_generator.load_baseline(self.baseline_path)
        merged = self.merge_baseline(existing, current_snapshot)
        self.baseline_generator.save_baseline(merged, self.baseline_path)
        return merged

    def build_status(self, state: dict[str, Any] | None = None) -> dict[str, Any]:
        current = self.ensure_state(state or self.state_store.load())
        phase = self.current_phase(current)
        hostile_ip_count = int(current.get("hostile_feed_count", len(load_cached_hostile_ips(self.hostile_feed_path))))
        payload = {
            "phase": phase,
            "phase_started_at": current.get("onboarding_phase_started_at"),
            "phase_age_days": round(self.phase_age_days(current), 2),
            "discovery_days": self.discovery_days(),
            "observe_days": self.observe_days(),
            "scan_count": int(current.get("scan_count", 0)),
            "last_scan_at": current.get("last_scan_at"),
            "last_scan_result": current.get("last_scan_result"),
            "baseline_hash": current.get("baseline_hash"),
            "hostile_feed_count": hostile_ip_count,
            "hostile_feed_updated_at": current.get("hostile_feed_updated_at"),
            "compromised_reason": current.get("compromised_reason"),
        }

        if phase == "discovery":
            payload["days_until_confirmation_pending"] = round(max(0.0, self.discovery_days() - self.phase_age_days(current)), 2)
        if phase == "observe":
            payload["days_until_protect"] = round(max(0.0, self.observe_days() - self.phase_age_days(current)), 2)
        return payload

    def build_baseline_report(self, baseline: dict[str, Any]) -> dict[str, Any]:
        return {
            "phase": "confirmation_pending",
            "hostname": baseline.get("hostname"),
            "generated_at": baseline.get("generated_at"),
            "summary": {
                "running_processes": len(baseline.get("running_processes", [])),
                "enabled_services": len(baseline.get("enabled_services", [])),
                "listening_ports": len(baseline.get("listening_ports", [])),
                "system_bins": len(baseline.get("system_bins", {})),
                "crontabs": len(baseline.get("crontabs", {})),
                "authorized_keys": len(baseline.get("authorized_keys", {})),
            },
            "next_step": "Run python3 sentinel.py --confirm-baseline to move to observe mode.",
        }

    def should_transition_from_discovery(self, state: dict[str, Any]) -> bool:
        return self.phase_age_days(state) >= float(self.discovery_days())

    def should_transition_from_observe(self, state: dict[str, Any]) -> bool:
        return self.phase_age_days(state) >= float(self.observe_days())

    @staticmethod
    def merge_baseline(existing: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
        merged = deepcopy(existing) if isinstance(existing, dict) else {}
        merged["generated_at"] = current.get("generated_at") or merged.get("generated_at")
        merged["hostname"] = current.get("hostname") or merged.get("hostname")

        for key in ("running_processes", "enabled_services", "listening_ports"):
            merged[key] = sorted(set(merged.get(key, [])) | set(current.get(key, [])))

        for key in ("system_bins", "crontabs", "authorized_keys"):
            merged_mapping = {}
            if isinstance(merged.get(key), dict):
                merged_mapping.update(merged[key])
            if isinstance(current.get(key), dict):
                merged_mapping.update(current[key])
            merged[key] = merged_mapping

        for key in ("packages", "rc_local", "passwd"):
            if current.get(key) is not None:
                merged[key] = current[key]
        return merged

    @staticmethod
    def dumps(payload: dict[str, Any]) -> str:
        return json.dumps(payload, indent=2, sort_keys=True)

    @staticmethod
    def _parse_datetime(value: Any) -> datetime:
        if not value:
            return datetime.now(timezone.utc)
        try:
            parsed = datetime.fromisoformat(str(value))
        except ValueError:
            return datetime.now(timezone.utc)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)

    @staticmethod
    def _now_iso() -> str:
        return datetime.now(timezone.utc).isoformat()
