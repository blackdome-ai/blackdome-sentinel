"""Bounded action execution with audit logging and verification."""

from __future__ import annotations

import importlib
import logging
from pathlib import Path
from typing import Any

from .audit import AuditTrail


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class BaseActuator:
    """Base contract for audited, bounded actuators."""

    name = "base_actuator"

    def __init__(self) -> None:
        self.logger = logging.getLogger(self.__class__.__name__)

    async def execute(
        self,
        target: Any,
        audit: AuditTrail,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        start_record = {
            "action": self.name,
            "target": target,
            "status": "executing",
        }
        if metadata:
            start_record["metadata"] = metadata
        audit.log_action(start_record)

        try:
            result = await self._do_action(target)
            verified = await self._verify(target, result)
            completion_record = {
                "action": self.name,
                "target": target,
                "status": "completed" if verified else "verification_failed",
                "verified": verified,
                "result": result,
            }
            if metadata:
                completion_record["metadata"] = metadata
            audit.log_action(completion_record)
            return {
                "ok": verified,
                "status": completion_record["status"],
                "result": result,
            }
        except Exception as exc:  # pragma: no cover - defensive path
            self.logger.exception("Actuator %s failed for target %s", self.name, target)
            failure_record = {
                "action": self.name,
                "target": target,
                "status": "failed",
                "error": str(exc),
            }
            if metadata:
                failure_record["metadata"] = metadata
            audit.log_action(failure_record)
            return {
                "ok": False,
                "status": "failed",
                "error": str(exc),
                "result": {},
            }

    async def _do_action(self, target: Any) -> dict[str, Any]:
        raise NotImplementedError

    async def _verify(self, target: Any, result: dict[str, Any] | None = None) -> bool:
        raise NotImplementedError


class ActionExecutor:
    """Dispatch approved actions to concrete actuator implementations."""

    def __init__(
        self,
        project_root: str | Path | None = None,
        audit_trail: AuditTrail | None = None,
    ) -> None:
        self.project_root = Path(project_root) if project_root else PROJECT_ROOT
        self.logger = logging.getLogger(self.__class__.__name__)
        self.audit_trail = audit_trail or AuditTrail(self.project_root / "logs" / "audit.jsonl")
        self._registry = self._build_registry()

    async def execute(self, actions: list[dict[str, Any]]) -> list[dict[str, Any]]:
        # Always quarantine BEFORE kill — preserves forensic evidence.
        # Sort: quarantine_file first, then everything else, kill_process last.
        _order = {"quarantine_file": 0, "snapshot_evidence": 1, "block_ip": 2, "clean_persistence": 3, "kill_process": 9}
        actions = sorted(actions, key=lambda a: _order.get(str(a.get("action", "")), 5))

        results: list[dict[str, Any]] = []
        for action in actions:
            action_name = str(action.get("action", "")).strip()
            actuator_cls = self._registry.get(action_name)
            if actuator_cls is None:
                unsupported = {
                    **action,
                    "ok": False,
                    "status": "unsupported",
                    "error": f"Unsupported action: {action_name or 'unknown'}",
                    "result": {},
                }
                self.audit_trail.log_action(unsupported)
                results.append(unsupported)
                continue

            actuator = actuator_cls()
            target = action.get("target")
            execution_result = await actuator.execute(target, self.audit_trail, metadata=action)
            results.append(
                {
                    **action,
                    **execution_result,
                }
            )
        return results

    def _build_registry(self) -> dict[str, type[BaseActuator]]:
        registry: dict[str, type[BaseActuator]] = {}
        for module_name in (
            "kill_process",
            "quarantine_file",
            "block_ip",
            "clean_persistence",
        ):
            module = importlib.import_module(f"actuators.{module_name}")
            for attribute_name in dir(module):
                attribute = getattr(module, attribute_name)
                if (
                    isinstance(attribute, type)
                    and issubclass(attribute, BaseActuator)
                    and attribute is not BaseActuator
                    and getattr(attribute, "name", None)
                ):
                    registry[attribute.name] = attribute
        return registry

