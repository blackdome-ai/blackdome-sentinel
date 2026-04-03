"""YAML-configured HaltState policy engine."""

from __future__ import annotations

from typing import Any


class PolicyEngine:
    """Decide which actions are auto-approved by policy."""

    def __init__(self, policies: dict[str, Any]) -> None:
        self.policies = policies

    def evaluate(self, classification: str, confidence: float, actions: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        """Return approved and denied actions for the given classification."""
        policy = self.policies.get(classification, self.policies.get("default", {}))
        threshold = float(policy.get("confidence_threshold", 1.0))
        auto_actions = set(policy.get("auto_actions", []))
        requires_approval = set(policy.get("requires_approval", []))

        approved: list[dict[str, Any]] = []
        denied: list[dict[str, Any]] = []
        for action in actions:
            action_name = action.get("action")
            if confidence >= threshold:
                if action_name in auto_actions:
                    approved.append({**action, "decision": "auto_approved"})
                elif action_name in requires_approval:
                    denied.append({**action, "decision": "requires_approval"})
                else:
                    denied.append({**action, "decision": "not_in_policy"})
            else:
                denied.append({**action, "decision": "below_confidence"})
        return approved, denied
