"""Scan orchestrator and evidence bundle assembly."""

from __future__ import annotations

import importlib
import logging
import socket
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .baseline import BaselineGenerator


PROJECT_ROOT = Path(__file__).resolve().parents[1]


@dataclass
class EvidenceBundle:
    """Combined output of one scan cycle."""

    timestamp: float
    hostname: str
    evidence: dict[str, Any]
    baseline_diff: list[dict[str, str]]
    current_snapshot: dict[str, Any] = field(default_factory=dict)

    @property
    def iso_timestamp(self) -> str:
        return datetime.fromtimestamp(self.timestamp, tz=timezone.utc).isoformat()

    def as_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["iso_timestamp"] = self.iso_timestamp
        return payload


class ScanOrchestrator:
    """Run configured collectors and assemble scan evidence."""

    def __init__(self, config: dict[str, Any], baseline: dict[str, Any], project_root: str | Path | None = None) -> None:
        self.config = config
        self.baseline_data = baseline
        self.project_root = Path(project_root) if project_root else PROJECT_ROOT
        self.logger = logging.getLogger(self.__class__.__name__)
        self.baseline_generator = BaselineGenerator(project_root=self.project_root, config=self.config)
        self.collectors = self._load_collectors()

    async def run_scan(self) -> EvidenceBundle:
        """Run all configured collectors and return a combined evidence bundle."""
        evidence: dict[str, Any] = {}

        for collector in self.collectors:
            try:
                result = await collector.collect()
                evidence[collector.name] = result
            except Exception as exc:  # pragma: no cover - defensive path
                self.logger.exception("Collector %s failed", collector.name)
                evidence[collector.name] = {"error": str(exc)}

        current_snapshot = self.baseline_generator.generate()
        baseline_diff = (
            self.baseline_generator.diff_baseline(current_snapshot, self.baseline_data)
            if self.baseline_data
            else []
        )

        return EvidenceBundle(
            timestamp=time.time(),
            hostname=socket.gethostname(),
            evidence=evidence,
            baseline_diff=baseline_diff,
            current_snapshot=current_snapshot,
        )

    def _load_collectors(self) -> list[Any]:
        collectors_config = self.config.get("collectors", [])
        if isinstance(collectors_config, dict):
            collector_names = collectors_config.get("enabled", [])
        else:
            collector_names = collectors_config
        loaded_collectors = []
        for collector_name in collector_names:
            module = importlib.import_module(f"collectors.{collector_name}")
            class_name = "".join(part.capitalize() for part in collector_name.split("_"))
            collector_cls = getattr(module, class_name)
            loaded_collectors.append(collector_cls(config=self.config))
        return loaded_collectors
