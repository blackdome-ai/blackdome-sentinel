#!/usr/bin/env python3

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import pwd
import re
import shutil
import socket
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import yaml

from api_client.v2 import SentinelV2Client
from batcher.batcher import MicroBatcher
from batcher.packet import IncidentPacket
from cadence.deep_audit import run_deep_audit
from cadence.heartbeat import run_heartbeat
from cadence.reconciliation import run_reconciliation
from core.actuator import ActionExecutor
from core.audit import AuditTrail
from core.journal import EventJournal
from core.reasoning import ReasoningEngine
from core.state_store import StateStore
from dedup.engine import DedupEngine
from events.collector import run_auditd_tailer, run_inotify_watcher, run_proc_poller
from deception.canaries import plant_canaries, get_canary_paths, is_canary_path
from deception.facades import FacadeRunner
from events.event import RawEvent
from events.queue import EventQueue
from promotion.filter import PromotionFilter

PROJECT_ROOT = Path(__file__).resolve().parent
# Facade probe buffer: collect probes, batch-analyze hourly
import time as _time

KNOWN_ACTUATOR_ACTIONS = {"kill_process", "quarantine_file", "block_ip", "clean_persistence"}
AUTH_ACCEPT_PATTERN = re.compile(
    r"Accepted (?:publickey|password) for (?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+)"
)
DEFAULT_BLOCK_TTL_HOURS = 24

DEFAULT_CONFIG = {
    "sentinel": {
        "version": "2",
        "host_id": "",
        "hostname": socket.gethostname(),
        "weight_class": "standard",
        "log_level": "INFO",
        "audit_log": "logs/audit.jsonl",
        "state_path": "state/sentinel_state.json",
    },
    "host_doctrine": {
        "role": "general",
        "description": "",
        "maintenance_windows": [],
    },
    "control_plane": {
        "url": "https://sentinel.blackdome.ai",
        "auth_token": "",
        "agent_id": "",
        "tenant_id": "",
        "signing_public_key": "",
        "timeout_seconds": 30,
    },
    "collectors": {
        "proc_poll_interval": 3,
        "enable_auditd": True,
        "enable_inotify": True,
    },
    "cadence": {
        "reconciliation_interval": 900,
        "deep_audit_interval": 21600,
        "heartbeat_interval": 120,
    },
    "batcher": {
        "default_window": 30,
        "short_window": 5,
        "max_window": 120,
    },
    "dedup": {
        "cooldown_hours": 6,
        "state_path": "state/dedup_state.json",
    },
    "llm": {
        "provider": "ollama",
        "model": "llama3.1:8b",
        "endpoint": "http://localhost:11434",
        "timeout_seconds": 30,
    },
    "baseline": {
        "path": "state/baseline.json",
    },
    "threat_intel": {
        "hostile_feed_path": "state/hostile_ips.json",
        "malware_hashes": [],
    },
    "journal": {
        "path": "logs/event_journal.jsonl",
    },
    "honeypot_pairing": {
        "enabled": False,
        "poll_interval": 10,
    },
}


class SentinelDaemon:
    def __init__(self, config: dict[str, Any]) -> None:
        self.config = _normalize_config(config)
        self.logger = logging.getLogger(self.__class__.__name__)
        self.queue = EventQueue()
        self._watched_internal_ips: set[str] = set()
        self._active_ttp_alerts: list[dict[str, Any]] = []
        self._credential_alerts: list[dict[str, Any]] = []
        self._uid_origin_cache: dict[int, str | None] = {}

        sentinel_config = self.config["sentinel"]
        control_plane = self.config["control_plane"]
        self.host_id = str(sentinel_config.get("host_id") or sentinel_config.get("hostname") or socket.gethostname())
        self.weight_class = str(sentinel_config.get("weight_class", "standard")).lower()

        if self.weight_class == "enterprise":
            from core.model_gate import check_model

            model_name = str(self.config.get("llm", {}).get("model", "unknown"))
            if not check_model(model_name):
                self.logger.warning(
                    "Local LLM %s FAILED smarts audit — falling back to Standard path (DO Sonnet)",
                    model_name,
                )
                self.weight_class = "standard"
                self.config["sentinel"]["weight_class"] = "standard"
            else:
                self.logger.info(
                    "Local LLM %s passed smarts audit — enterprise mode active",
                    model_name,
                )

        journal_path = _resolve_project_path(self.config["journal"]["path"])
        checkpoint_path = journal_path.parent / "last_checkpoint.json"
        audit_path = _resolve_project_path(sentinel_config.get("audit_log", "logs/audit.jsonl"))
        state_path = _resolve_project_path(
            sentinel_config.get("state_path", "state/sentinel_state.json")
        )

        self.journal = EventJournal(str(journal_path), checkpoint_path=str(checkpoint_path))
        self.audit_trail = AuditTrail(audit_path)
        self.state_store = StateStore(state_path)
        self.action_executor = ActionExecutor(project_root=PROJECT_ROOT, audit_trail=self.audit_trail)
        self.dedup_engine = DedupEngine(
            state_path=str(_resolve_project_path(self.config["dedup"]["state_path"])),
            cooldown_hours=int(self.config["dedup"]["cooldown_hours"]),
        )
        self.promotion = PromotionFilter(
            baseline_hashes=_load_baseline_hashes(_resolve_project_path(self.config["baseline"]["path"])),
            malware_hashes=_load_malware_hashes(self.config),
            hostile_ips=_load_hostile_ips(_resolve_project_path(self.config["threat_intel"]["hostile_feed_path"])),
        )
        self.promotion_filter = self.promotion
        self.api_client = SentinelV2Client(
            base_url=str(control_plane.get("url", "")),
            auth_token=str(control_plane.get("auth_token", "")),
            agent_id=str(control_plane.get("agent_id", "")),
            tenant_id=str(control_plane.get("tenant_id", "")),
        )
        self.client = self.api_client
        self.reasoner = ReasoningEngine(self.config)
        self.batcher = MicroBatcher(
            host_id=self.host_id,
            host_doctrine=self.config.get("host_doctrine", {}),
            on_packet=self._handle_packet,
            default_window=float(self.config["batcher"]["default_window"]),
        )
        state = self.state_store.load()
        self._trusted_ips = {
            str(item).strip()
            for item in state.get("trusted_ips", [])
            if str(item).strip()
        }
        self._block_records = self._normalize_block_records(state.get("block_records", []))
        self._refresh_dynamic_host_context()

    async def _handle_packet(self, packet: IncidentPacket) -> None:
        fingerprint = packet.dedup_fingerprint
        should_analyze, dedup_reason = self.dedup_engine.should_analyze(fingerprint)
        if not should_analyze:
            cached_verdict = self._decode_cached_verdict(self.dedup_engine.get_cached_verdict(fingerprint))
            cached_assessment = cached_verdict.get("assessment") if cached_verdict else "unknown"
            self.logger.info(
                "skipping packet %s due to dedup (%s, cached=%s)",
                packet.packet_id,
                dedup_reason,
                cached_assessment,
            )
            return

        governance_approved = False
        approved_actions = []

        if self.weight_class == "enterprise":
            verdict = await self._reason_local(packet)
            governance_payload = {
                "packet_id": packet.packet_id,
                "dedup_fingerprint": fingerprint,
                "event_count": packet.event_count,
                "verdict": str(verdict.get("assessment", "clean")),
                "confidence": float(verdict.get("confidence", 0.0) if isinstance(verdict.get("confidence"), (int, float)) else 0.0),
                "summary": str(verdict.get("summary", "")),
                "actions": verdict.get("recommended_actions", verdict.get("actions", [])) or [],
                "model_used": str(verdict.get("model", self.config.get("llm", {}).get("model", "unknown"))),
                "reasoning_time_ms": int(verdict.get("reasoning_time_ms", 0)),
                "token_usage": verdict.get("token_usage", {}),
            }
            try:
                response = await self.client.submit_verdict(governance_payload)
                status_code = int(response.get("status_code", 200))
                if status_code < 400:
                    governance_approved = True
                    approved_actions = response.get("actions", []) or self._extract_actions(verdict)
                else:
                    self.logger.warning(
                        "verdict submission returned %s for packet %s — actions withheld pending governance",
                        status_code,
                        packet.packet_id,
                    )
            except Exception:
                self.logger.warning("failed to submit enterprise verdict for packet %s — actions withheld", packet.packet_id, exc_info=True)
        else:
            verdict = await self._reason_remote(packet)
            governance_approved = True
            approved_actions = self._extract_actions(verdict)

        self.dedup_engine.record_verdict(
            fingerprint,
            json.dumps(verdict, sort_keys=True, default=str),
        )

        if governance_approved and approved_actions:
            # Filter to known actuator actions only — LLM may return analysis actions
            executable = [a for a in approved_actions if a.get("action") in KNOWN_ACTUATOR_ACTIONS]
            skipped = [a for a in approved_actions if a.get("action") not in KNOWN_ACTUATOR_ACTIONS]
            if skipped:
                self.logger.info("Filtered %d non-actuator actions: %s", len(skipped),
                                 [a.get("action") for a in skipped])
            approved_actions = executable
        if governance_approved and approved_actions:
            await self._execute_actions(
                approved_actions,
                reason=f"packet:{packet.packet_id}",
                evidence={
                    "packet": packet.to_dict(),
                    "verdict": verdict,
                    "dedup_reason": dedup_reason,
                },
            )
        elif not governance_approved:
            self.logger.info("actions withheld for packet %s — governance not approved", packet.packet_id)

    async def _reason_local(self, packet: IncidentPacket) -> dict[str, Any]:
        verdict = await self.reasoner.analyze(self._packet_findings(packet))
        if not isinstance(verdict, dict):
            verdict = {}
        verdict.setdefault("assessment", "error")
        verdict.setdefault("recommended_actions", [])
        verdict.setdefault("packet_id", packet.packet_id)
        verdict.setdefault("dedup_fingerprint", packet.dedup_fingerprint)
        return verdict

    async def _reason_remote(self, packet: IncidentPacket) -> dict[str, Any]:
        try:
            response = await self.client.submit_incident(packet.to_dict())
        except Exception:
            self.logger.warning("incident submission failed for packet %s; falling back to local reasoning", packet.packet_id, exc_info=True)
            return await self._reason_local(packet)

        verdict = response.get("verdict") if isinstance(response.get("verdict"), dict) else response
        if not isinstance(verdict, dict) or int(response.get("status_code", 200)) >= 400:
            self.logger.warning(
                "incident response invalid for packet %s; falling back to local reasoning",
                packet.packet_id,
            )
            return await self._reason_local(packet)
        return verdict

    async def _process_events(self) -> None:
        async for event in self.queue.consume():
            self._annotate_watched_internal_process_event(event)
            result = self.promotion.evaluate(event)

            if result.action == "log":
                self.logger.debug("skipping baseline event %s", event.event_id)
                continue

            if result.action == "kill":
                pid = event.subject.get("pid")
                await self._execute_actions(
                    [{"action": "kill_process", "target": f"pid:{pid}" if pid is not None else ""}],
                    reason=result.reason,
                    evidence={"event": event.to_dict(), "matched_ioc": result.matched_ioc},
                )
                continue

            if result.action == "block":
                dest_ip = _extract_dest_ip(event)
                await self._execute_actions(
                    [{"action": "block_ip", "target": dest_ip}],
                    reason=result.reason,
                    evidence={"event": event.to_dict(), "matched_ioc": result.matched_ioc},
                )
                continue

            # Canary file access = CRITICAL
            _epath = event.object.get("path", "")
            if _epath and is_canary_path(_epath):
                self.logger.critical("CANARY TRIGGERED: %s", _epath)
                self.journal._append({"type": "canary_triggered", "path": _epath, "event": event.to_dict()})
            # Facade probe — buffer for batch analysis, immediate action only for critical
            if event.metadata.get("facade"):
                action = event.metadata.get("action", "alert")
                src_ip = event.subject.get("source_ip", "")
                severity = event.metadata.get("severity", "noise")

                # Always log to journal (free)
                self.journal._append({"type": "facade_probe", "action": action, "severity": severity, "event": event.to_dict()})

                # Always add IP to hostile feed (free, immediate protection)
                if src_ip and severity != "noise":
                    self.promotion._hostile_ips.add(src_ip)

                # Block if configured
                if event.metadata.get("block_requested") and src_ip:
                    try:
                        await self._execute_actions(
                            [{"action": "block_ip", "target": src_ip, "priority": "immediate"}],
                            reason="facade:auto_block",
                            evidence={"event": event.to_dict(), "severity": severity},
                        )
                        self.logger.warning("Queued facade auto-block for IP %s", src_ip)
                    except Exception:
                        self.logger.warning("Facade auto-block failed for %s", src_ip, exc_info=True)

                # CRITICAL (internal/hostile) -> immediate hot path (rare, high value)
                if severity == "critical":
                    self.logger.critical("FACADE PROBE [%s]: %s -> %s:%s", action, src_ip, event.object.get("service"), event.object.get("port"))
                    await self.batcher.add_event(event)
                else:
                    # HIGH/other -> buffer for hourly batch (cheap)
                    if not hasattr(self, "_facade_probe_buffer"):
                        self._facade_probe_buffer = []
                        self._facade_buffer_last_flush = _time.time()
                    self._facade_probe_buffer.append(event.to_dict())
                    self.logger.info("Facade probe buffered [%s]: %s -> %s:%s (%d in buffer)",
                                     severity, src_ip, event.object.get("service"), event.object.get("port"),
                                     len(self._facade_probe_buffer))
                continue
            await self.batcher.add_event(event)

    async def run(self) -> None:
        collectors_config = self.config["collectors"]
        cadence_config = self.config["cadence"]
        control_plane = self.config["control_plane"]
        heartbeat_interval = float(cadence_config.get("heartbeat_interval", 120))
        if self.config.get("honeypot_pairing", {}).get("enabled"):
            heartbeat_interval = float(
                self.config.get("honeypot_pairing", {}).get("poll_interval", 10)
            )


        # === DECEPTION LAYER ===
        # Plant canary files
        from pathlib import Path as _Path
        _canary_state = _Path(self.config.get("deception", {}).get("canary_state", "state/canary_state.json"))
        try:
            _planted = plant_canaries(_canary_state)
            self.logger.info("Planted %d canary files", len(_planted))
        except Exception as _exc:
            self.logger.warning("Canary planting failed: %s", _exc)

        # Start host facades on unused ports
        async def _facade_probe_handler(probe_data):
            from events.event import RawEvent as _RE
            from datetime import datetime as _DT, timezone as _TZ
            _evt = _RE(
                timestamp=_DT.now(_TZ.utc), source="facade", event_type="facade_probe",
                subject={"source_ip": probe_data.get("source_ip", ""), "source_port": probe_data.get("source_port", 0)},
                object={"service": probe_data.get("service", ""), "port": probe_data.get("port", 0)},
                metadata={"severity": "critical", "first_bytes": probe_data.get("first_bytes_text", ""), "facade": True},
            )
            await self.queue.put(_evt)

        _facade_cfg = self.config.get("facades", {})
        if _facade_cfg.get("enabled", True):
            self._facade_runner = FacadeRunner(on_probe=_facade_probe_handler, config=_facade_cfg, hostile_ips=self.promotion._hostile_ips)
            _fc = await self._facade_runner.start()
            self.logger.info("Started %d host facades on unused ports", _fc)

        tasks = [
            asyncio.create_task(
                run_proc_poller(
                    self.queue,
                    interval=float(collectors_config.get("proc_poll_interval", 3)),
                )
            ),
            asyncio.create_task(self._process_events()),
            asyncio.create_task(
                run_heartbeat(
                    self.queue,
                    self._send_heartbeat,
                    str(control_plane.get("agent_id", "")),
                    interval_seconds=heartbeat_interval,
                )
            ),
            asyncio.create_task(
                run_reconciliation(
                    self.queue,
                    self.config,
                    interval_seconds=float(cadence_config.get("reconciliation_interval", 900)),
                )
            ),
            asyncio.create_task(
                run_deep_audit(
                    self.queue,
                    self.config,
                    interval_seconds=float(cadence_config.get("deep_audit_interval", 21600)),
                )
            ),
            asyncio.create_task(self._expire_blocks_loop()),
        ]

        if collectors_config.get("enable_inotify", True):
            tasks.append(asyncio.create_task(run_inotify_watcher(self.queue)))
        if collectors_config.get("enable_auditd", True):
            tasks.append(asyncio.create_task(run_auditd_tailer(self.queue)))


        # Facade probe batch flush — one LLM call per hour instead of per-probe
        async def _facade_flush_loop():
            while True:
                await asyncio.sleep(3600)  # 1 hour
                if not hasattr(self, "_facade_probe_buffer") or not self._facade_probe_buffer:
                    continue
                buffer = list(self._facade_probe_buffer)
                self._facade_probe_buffer.clear()
                self.logger.info("Flushing %d facade probes for batch analysis", len(buffer))

                # Build a summary for one cold-path LLM call
                unique_ips = set()
                port_counts = {}
                interactive = []
                for p in buffer:
                    ip = p.get("subject", {}).get("source_ip", "")
                    if ip:
                        unique_ips.add(ip)
                    port = p.get("object", {}).get("port", 0)
                    svc = p.get("object", {}).get("service", "")
                    port_counts[f"{svc}:{port}"] = port_counts.get(f"{svc}:{port}", 0) + 1
                    if "interactive" in p.get("metadata", {}).get("classification_reason", ""):
                        interactive.append(p)

                # Create a single summary event for the batcher
                from events.event import RawEvent
                from datetime import datetime, timezone
                summary_event = RawEvent(
                    timestamp=datetime.now(timezone.utc),
                    source="facade_batch",
                    event_type="facade_probe_summary",
                    subject={"unique_ips": len(unique_ips), "total_probes": len(buffer)},
                    object={"port_distribution": port_counts, "interactive_count": len(interactive)},
                    metadata={
                        "severity": "medium",
                        "facade_batch": True,
                        "top_ips": list(unique_ips)[:20],
                        "interactive_samples": interactive[:5],
                        "summary": f"{len(buffer)} probes from {len(unique_ips)} IPs in the last hour. Top ports: {dict(sorted(port_counts.items(), key=lambda x: -x[1])[:5])}",
                    },
                )
                await self.batcher.add_event(summary_event)
                self.logger.info("Facade batch: %d probes, %d unique IPs, %d interactive -> sent to LLM",
                                 len(buffer), len(unique_ips), len(interactive))

        tasks.append(asyncio.create_task(_facade_flush_loop()))

        await asyncio.gather(*tasks)

    def _apply_threat_updates(self, updates: dict[str, Any]) -> None:
        if not isinstance(updates, dict):
            return

        trusted_ips = updates.get("trusted_ips", [])
        if isinstance(trusted_ips, list):
            self._apply_trusted_ips(trusted_ips)

        for ip in updates.get("block_ips", []):
            value = str(ip).strip()
            if not value:
                continue
            self.promotion._hostile_ips.add(value)
            self.logger.info("applied threat update block_ip=%s", value)

        for file_hash in updates.get("block_hashes", []):
            value = str(file_hash).strip().lower()
            if not value:
                continue
            self.promotion._malware_hashes.add(value)
            self.logger.info("applied threat update block_hash=%s", value)

        watched_ips = {
            str(ip).strip()
            for ip in updates.get("watch_internal_ips", [])
            if str(ip).strip()
        }
        if watched_ips:
            self._watched_internal_ips.update(watched_ips)
            self.logger.info(
                "applied watched internal IP updates: %s",
                ", ".join(sorted(watched_ips)),
            )

        ttp_alerts = [item for item in updates.get("ttp_alerts", []) if isinstance(item, dict)]
        if ttp_alerts:
            self._active_ttp_alerts = ttp_alerts
            self.logger.info("applied %d active TTP alerts", len(ttp_alerts))

        credential_alerts = [
            item for item in updates.get("credential_alerts", []) if isinstance(item, dict)
        ]
        if credential_alerts:
            self._credential_alerts = credential_alerts
            self.logger.info("applied %d credential alerts", len(credential_alerts))

        self._refresh_dynamic_host_context()

    async def _send_heartbeat(self, payload: dict[str, Any]) -> dict[str, Any]:
        try:
            response = await self.api_client.send_heartbeat(payload)
            updates = response.get("threat_updates")
            if isinstance(updates, dict):
                self._apply_threat_updates(updates)
            trusted_ips = response.get("trusted_ips")
            if isinstance(trusted_ips, list):
                self._apply_trusted_ips(trusted_ips)
            await self._process_pending_commands(response)
            return response
        except Exception as exc:
            self.logger.warning("Heartbeat failed: %s", exc)
            raise

    async def _execute_actions(
        self,
        actions: list[dict[str, Any]],
        *,
        reason: str,
        evidence: dict[str, Any],
    ) -> None:
        if not actions:
            self.logger.warning("no executable actions produced for reason=%s", reason)
            return

        for action in actions:
            action_name = str(action.get("action", "")).strip() or "unknown"
            target = action.get("target")
            target_text = "" if target is None else str(target)
            intent_seq = self.journal.write_intent(action_name, target_text, reason, evidence)

            if not target_text:
                self.journal.write_completed(
                    intent_seq,
                    action_name,
                    target_text,
                    "skipped_missing_target",
                    {"action": action},
                )
                continue

            if action_name == "block_ip":
                allowed, skip_reason = self._can_execute_block(target_text, action)
                if not allowed:
                    self.logger.warning("Skipping block_ip for %s (%s)", target_text, skip_reason)
                    self.journal.write_completed(
                        intent_seq,
                        action_name,
                        target_text,
                        skip_reason,
                        {"action": action, "reason": skip_reason},
                    )
                    continue

            result_list = await self.action_executor.execute([action])
            result = result_list[0] if result_list else {"status": "unknown"}
            self.journal.write_completed(
                intent_seq,
                action_name,
                target_text,
                str(result.get("status", "unknown")),
                result,
            )
            if result.get("ok"):
                action_id = await self._report_action_execution(
                    action=action,
                    reason=reason,
                    result=result.get("result", {}) if isinstance(result.get("result"), dict) else {},
                )
                if action_name == "block_ip":
                    self._remember_block(target_text, action_id=action_id)

    def _packet_findings(self, packet: IncidentPacket) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        for event in [packet.trigger_event, *packet.related_events]:
            evidence = event.to_dict()
            tags = list(event.metadata.get("tags", []))
            if (
                event.source == "reconciliation"
                and str(event.metadata.get("scanner")) == "AuthScanner"
                and self._credential_alerts
            ):
                evidence["credential_alerts"] = list(self._credential_alerts)
                if "credential_alert_context" not in tags:
                    tags.append("credential_alert_context")
            findings.append(
                {
                    "severity": str(event.metadata.get("severity") or _default_severity(event)),
                    "category": str(event.metadata.get("category") or event.event_type),
                    "description": str(event.metadata.get("description") or _describe_event(event)),
                    "evidence": evidence,
                    "tags": tags,
                    "source": event.source,
                }
            )

        honeypot_alerts = packet.host_doctrine.get("honeypot_alerts", [])
        if honeypot_alerts:
            findings.append(
                {
                    "severity": "high",
                    "category": "honeypot",
                    "description": "Active honeypot TTP alerts correlate with this host context.",
                    "evidence": {"alerts": honeypot_alerts},
                    "tags": ["honeypot_alert_context"],
                    "source": "control_plane",
                }
            )

        watched_ips = packet.host_doctrine.get("watched_internal_ips", [])
        if watched_ips:
            findings.append(
                {
                    "severity": "high",
                    "category": "threat_intel",
                    "description": "Watched internal IPs are active for this host.",
                    "evidence": {"watched_internal_ips": watched_ips},
                    "tags": ["watched_internal_ip_context"],
                    "source": "control_plane",
                }
            )

        credential_alerts = packet.host_doctrine.get("credential_alerts", [])
        if credential_alerts:
            findings.append(
                {
                    "severity": "high",
                    "category": "auth",
                    "description": "Credential alerts are active for this host.",
                    "evidence": {"credential_alerts": credential_alerts},
                    "tags": ["credential_alert_context"],
                    "source": "control_plane",
                }
            )
        return findings

    @staticmethod
    def _decode_cached_verdict(payload: str | None) -> dict[str, Any] | None:
        if not payload:
            return None
        try:
            decoded = json.loads(payload)
        except json.JSONDecodeError:
            return None
        return decoded if isinstance(decoded, dict) else None

    @staticmethod
    def _extract_actions(verdict: dict[str, Any]) -> list[dict[str, Any]]:
        for key in ("recommended_actions", "actions"):
            actions = verdict.get(key)
            if isinstance(actions, list):
                return [action for action in actions if isinstance(action, dict)]
        return []

    def _refresh_dynamic_host_context(self) -> None:
        self.batcher._host_doctrine["honeypot_alerts"] = list(self._active_ttp_alerts)
        self.batcher._host_doctrine["watched_internal_ips"] = sorted(self._watched_internal_ips)
        self.batcher._host_doctrine["credential_alerts"] = list(self._credential_alerts)
        self.batcher._host_doctrine["trusted_ips"] = sorted(self._trusted_ips)

    @staticmethod
    def _normalize_block_records(payload: Any) -> list[dict[str, Any]]:
        if not isinstance(payload, list):
            return []
        records: list[dict[str, Any]] = []
        for item in payload:
            if not isinstance(item, dict):
                continue
            ip_address = str(item.get("ip") or "").strip()
            expires_at = str(item.get("expires_at") or "").strip()
            if not ip_address or not expires_at:
                continue
            records.append(
                {
                    "ip": ip_address,
                    "action_id": str(item.get("action_id") or "").strip() or None,
                    "created_at": str(item.get("created_at") or "").strip() or None,
                    "expires_at": expires_at,
                }
            )
        return records

    def _persist_state(self) -> None:
        state = self.state_store.load()
        state["trusted_ips"] = sorted(self._trusted_ips)
        state["block_records"] = list(self._block_records)
        state["blocked_ips"] = sorted({record["ip"] for record in self._block_records})
        self.state_store.save(state)

    def _remember_block(self, ip_address: str, *, action_id: str | None = None) -> dict[str, Any]:
        created_at = datetime.now(timezone.utc)
        expires_at = created_at + timedelta(hours=DEFAULT_BLOCK_TTL_HOURS)
        record = {
            "ip": ip_address,
            "action_id": action_id,
            "created_at": created_at.isoformat(),
            "expires_at": expires_at.isoformat(),
        }
        self._block_records = [item for item in self._block_records if item.get("ip") != ip_address]
        self._block_records.append(record)
        self._persist_state()
        return record

    def _clear_block_record(self, ip_address: str) -> dict[str, Any] | None:
        removed: dict[str, Any] | None = None
        remaining: list[dict[str, Any]] = []
        for item in self._block_records:
            if item.get("ip") == ip_address and removed is None:
                removed = item
                continue
            remaining.append(item)
        self._block_records = remaining
        self._persist_state()
        return removed

    def _apply_trusted_ips(self, values: list[Any]) -> None:
        trusted: set[str] = set()
        for item in values:
            candidate = str(item or "").strip()
            if not candidate:
                continue
            trusted.add(candidate)
        self._trusted_ips = trusted
        self._refresh_dynamic_host_context()
        self._persist_state()

    def _trusted_ip_match(self, ip_address: str) -> bool:
        try:
            candidate = ipaddress.ip_address(ip_address)
        except ValueError:
            return False

        for item in self._trusted_ips:
            try:
                if "/" in item:
                    if candidate in ipaddress.ip_network(item, strict=False):
                        return True
                elif candidate == ipaddress.ip_address(item):
                    return True
            except ValueError:
                continue
        return False

    @staticmethod
    def _is_internal_ip(ip_address: str) -> bool:
        try:
            candidate = ipaddress.ip_address(ip_address)
        except ValueError:
            return False
        return (
            candidate.is_private
            or candidate.is_loopback
            or candidate.is_link_local
            or candidate.is_reserved
            or candidate.is_multicast
        )

    @staticmethod
    def _flag_enabled(value: Any) -> bool:
        if isinstance(value, bool):
            return value
        if value is None:
            return False
        return str(value).strip().lower() in {"1", "true", "yes", "on"}

    def _can_execute_block(self, ip_address: str, action: dict[str, Any]) -> tuple[bool, str]:
        if self._trusted_ip_match(ip_address):
            return False, "trusted_ip"
        if self._is_internal_ip(ip_address) and not self._flag_enabled(
            action.get("confirmed_internal_block") or action.get("allow_internal_block")
        ):
            return False, "internal_ip_requires_confirmation"
        return True, ""

    @staticmethod
    def _unblock_ip(ip_address: str) -> dict[str, Any]:
        removed_rules = 0
        commands = (
            ["iptables", "-D", "OUTPUT", "-d", ip_address, "-j", "DROP"],
            ["iptables", "-D", "INPUT", "-s", ip_address, "-j", "DROP"],
        )
        for command in commands:
            while True:
                result = subprocess.run(command, capture_output=True, text=True, check=False)
                if result.returncode != 0:
                    break
                removed_rules += 1
        verify = subprocess.run(["iptables", "-L", "-n"], capture_output=True, text=True, check=False)
        return {
            "ip": ip_address,
            "removed_rules": removed_rules,
            "still_present": ip_address in (verify.stdout or ""),
        }

    @staticmethod
    def _restore_quarantined_file(original_path: str, quarantine_path: str) -> dict[str, Any]:
        source = Path(quarantine_path)
        destination = Path(original_path)
        if not source.exists():
            raise FileNotFoundError(f"Quarantine file not found: {quarantine_path}")
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
        return {
            "original_path": str(destination),
            "quarantine_path": str(source),
            "restored": destination.exists(),
        }

    async def _report_action_execution(
        self,
        *,
        action: dict[str, Any],
        reason: str,
        result: dict[str, Any],
    ) -> str | None:
        action_name = str(action.get("action", "")).strip()
        target = str(action.get("target") or "").strip()
        if not action_name or not target:
            return None

        payload: dict[str, Any] = {
            "action_type": action_name,
            "target": target,
            "reason": reason,
            "status": "active",
            "metadata": {
                "priority": action.get("priority"),
                "decision": action.get("decision"),
            },
            "result": result,
        }
        if action_name == "block_ip":
            payload["expires_at"] = (
                datetime.now(timezone.utc) + timedelta(hours=DEFAULT_BLOCK_TTL_HOURS)
            ).isoformat()
        try:
            response = await self.api_client.log_action(payload)
        except Exception:
            self.logger.warning("Failed to log action %s to control plane", action_name, exc_info=True)
            return None
        action_id = response.get("action_id")
        return str(action_id).strip() or None

    async def _update_control_plane_action_status(
        self,
        action_id: str | None,
        *,
        status: str,
        result: dict[str, Any],
    ) -> None:
        if not action_id:
            return
        try:
            await self.api_client.update_action_status(action_id, status=status, result=result)
        except Exception:
            self.logger.warning(
                "Failed to update action %s status=%s",
                action_id,
                status,
                exc_info=True,
            )

    async def _ack_command(
        self,
        command_id: str,
        *,
        status: str,
        result: dict[str, Any] | None = None,
        error: str | None = None,
    ) -> None:
        try:
            await self.api_client.ack_command(
                command_id,
                status=status,
                result=result or {},
                error=error,
            )
        except Exception:
            self.logger.warning("Failed to ack command %s", command_id, exc_info=True)

    async def _process_pending_commands(self, response: dict[str, Any]) -> None:
        commands = response.get("pending_commands")
        if not isinstance(commands, list):
            commands = response.get("pending_actions")
        if not isinstance(commands, list):
            return

        for command in commands:
            if not isinstance(command, dict):
                continue
            command_id = str(command.get("command_id") or "").strip()
            command_type = str(command.get("command_type") or command.get("action") or "").strip()
            payload = command.get("payload") if isinstance(command.get("payload"), dict) else {}
            try:
                if command_type == "unblock_ip":
                    target = str(payload.get("target") or "").strip()
                    if not target:
                        raise ValueError("Missing unblock target")
                    result = await asyncio.to_thread(self._unblock_ip, target)
                    self._clear_block_record(target)
                    await self._ack_command(command_id, status="success", result=result)
                elif command_type == "restore_quarantined_file":
                    original_path = str(payload.get("original_path") or "").strip()
                    quarantine_path = str(payload.get("quarantine_path") or "").strip()
                    if not original_path or not quarantine_path:
                        raise ValueError("Missing restore paths")
                    result = await asyncio.to_thread(
                        self._restore_quarantined_file,
                        original_path,
                        quarantine_path,
                    )
                    await self._ack_command(command_id, status="success", result=result)
                else:
                    await self._ack_command(
                        command_id,
                        status="skipped",
                        result={"reason": f"unsupported_command:{command_type}"},
                    )
            except Exception as exc:
                await self._ack_command(command_id, status="failed", error=str(exc))

    async def _expire_blocks_loop(self) -> None:
        while True:
            await asyncio.sleep(60)
            now = datetime.now(timezone.utc)
            for record in list(self._block_records):
                expires_at_raw = str(record.get("expires_at") or "").strip()
                if not expires_at_raw:
                    continue
                try:
                    expires_at = datetime.fromisoformat(expires_at_raw.replace("Z", "+00:00"))
                except ValueError:
                    continue
                if expires_at.tzinfo is None:
                    expires_at = expires_at.replace(tzinfo=timezone.utc)
                if expires_at > now:
                    continue

                ip_address = str(record.get("ip") or "").strip()
                if not ip_address:
                    continue
                try:
                    result = await asyncio.to_thread(self._unblock_ip, ip_address)
                    self._clear_block_record(ip_address)
                    await self._update_control_plane_action_status(
                        record.get("action_id"),
                        status="expired",
                        result=result,
                    )
                except Exception:
                    self.logger.warning("Failed to expire block for %s", ip_address, exc_info=True)

    def _annotate_watched_internal_process_event(self, event: RawEvent) -> None:
        if event.event_type != "process_exec" or not self._watched_internal_ips:
            return

        uid = event.subject.get("uid")
        if uid is None:
            return

        origin_ip = self._lookup_uid_origin_ip(uid)
        if not origin_ip or origin_ip not in self._watched_internal_ips:
            return

        event.metadata["watched_internal_ip"] = origin_ip
        event.metadata["severity"] = "high"
        tags = list(event.metadata.get("tags", []))
        if "watched_internal_ip" not in tags:
            tags.append("watched_internal_ip")
        event.metadata["tags"] = tags
        self.logger.warning(
            "high-priority process_exec for uid=%s tied to watched internal IP %s",
            uid,
            origin_ip,
        )

    def _lookup_uid_origin_ip(self, uid: Any) -> str | None:
        try:
            numeric_uid = int(uid)
        except (TypeError, ValueError):
            return None

        if numeric_uid in self._uid_origin_cache:
            return self._uid_origin_cache[numeric_uid]

        try:
            username = pwd.getpwuid(numeric_uid).pw_name
        except KeyError:
            self._uid_origin_cache[numeric_uid] = None
            return None

        for line in reversed(_recent_auth_lines()):
            match = AUTH_ACCEPT_PATTERN.search(line)
            if match and match.group("user") == username:
                origin_ip = match.group("ip")
                self._uid_origin_cache[numeric_uid] = origin_ip
                return origin_ip

        self._uid_origin_cache[numeric_uid] = None
        return None


def load_config(config_path: str | Path = "sentinel.yml") -> dict[str, Any]:
    resolved = _resolve_project_path(config_path)
    with resolved.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}
    if not isinstance(data, dict):
        raise ValueError("Config root must be a mapping")
    return _normalize_config(data)


def configure_logging(config: dict[str, Any]) -> None:
    log_level = str(config.get("sentinel", {}).get("log_level", "INFO")).upper()
    logging.basicConfig(
        level=getattr(logging, log_level, logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        stream=sys.stdout,
        force=True,
    )


def main() -> None:
    config = load_config("sentinel.yml")
    configure_logging(config)
    daemon = SentinelDaemon(config)
    asyncio.run(daemon.run())


def _normalize_config(config: dict[str, Any]) -> dict[str, Any]:
    normalized: dict[str, Any] = {}

    for section, defaults in DEFAULT_CONFIG.items():
        merged = dict(defaults)
        value = config.get(section)
        if isinstance(value, dict):
            merged.update(value)
        normalized[section] = merged

    normalized["host_doctrine"]["maintenance_windows"] = _as_list(
        normalized["host_doctrine"].get("maintenance_windows", [])
    )

    baseline_path = str(
        normalized["baseline"].get("path")
        or config.get("baseline", {}).get("path")
        or normalized["sentinel"].get("baseline_path")
        or DEFAULT_CONFIG["baseline"]["path"]
    )
    normalized["baseline"]["path"] = baseline_path
    normalized["sentinel"]["baseline_path"] = baseline_path

    hostile_feed_path = str(
        normalized["threat_intel"].get("hostile_feed_path")
        or DEFAULT_CONFIG["threat_intel"]["hostile_feed_path"]
    )
    normalized["threat_intel"]["hostile_feed_path"] = hostile_feed_path

    malware_hashes = normalized["threat_intel"].get("malware_hashes")
    if not isinstance(malware_hashes, list):
        malware_hashes = config.get("threat_intel", {}).get("known_malware_hashes", [])
    normalized["threat_intel"]["malware_hashes"] = _as_list(malware_hashes)
    normalized["threat_intel"]["known_malware_hashes"] = normalized["threat_intel"]["malware_hashes"]

    if not normalized["sentinel"]["hostname"]:
        normalized["sentinel"]["hostname"] = socket.gethostname()
    if not normalized["sentinel"]["host_id"]:
        normalized["sentinel"]["host_id"] = (
            normalized["control_plane"].get("agent_id")
            or normalized["sentinel"]["hostname"]
        )

    return normalized


def _resolve_project_path(path_value: str | Path) -> Path:
    path = Path(path_value)
    if path.is_absolute():
        return path
    return PROJECT_ROOT / path


def _as_list(value: Any) -> list[Any]:
    return list(value) if isinstance(value, list) else []


def _load_baseline_hashes(path: Path) -> set[str]:
    if not path.exists():
        return set()
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return set()
    hashes: set[str] = set()
    _collect_hashes(payload, hashes)
    return hashes


def _collect_hashes(payload: Any, hashes: set[str]) -> None:
    if isinstance(payload, dict):
        for key, value in payload.items():
            if key in {"hash", "sha256"} and isinstance(value, str) and value:
                hashes.add(value.lower())
            else:
                _collect_hashes(value, hashes)
    elif isinstance(payload, list):
        for item in payload:
            _collect_hashes(item, hashes)


def _load_hostile_ips(path: Path) -> set[str]:
    if not path.exists():
        return set()
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return set()

    hostile_ips: set[str] = set()
    if isinstance(payload, list):
        for item in payload:
            if isinstance(item, dict):
                ip_value = item.get("ip")
                if isinstance(ip_value, str) and ip_value:
                    hostile_ips.add(ip_value)
            elif isinstance(item, str) and item:
                hostile_ips.add(item)
    elif isinstance(payload, dict):
        for item in payload.get("ips", []):
            if isinstance(item, dict):
                ip_value = item.get("ip")
                if isinstance(ip_value, str) and ip_value:
                    hostile_ips.add(ip_value)
            elif isinstance(item, str) and item:
                hostile_ips.add(item)
    return hostile_ips


def _load_malware_hashes(config: dict[str, Any]) -> set[str]:
    values = config.get("threat_intel", {}).get("malware_hashes", [])
    return {str(value).strip().lower() for value in values if str(value).strip()}


def _extract_dest_ip(event: RawEvent) -> str:
    for source in (event.object, event.metadata):
        value = source.get("dest_ip")
        if isinstance(value, str) and value:
            return value
    return ""


def _default_severity(event: RawEvent) -> str:
    if event.event_type in {"package_drift", "auth_keys_audit", "service_change", "cron_change"}:
        return "high"
    if event.event_type in {"file_write", "process_exec", "net_connect", "priv_change", "suid_audit"}:
        return "medium"
    return "low"


def _describe_event(event: RawEvent) -> str:
    subject = event.subject.get("binary") or event.subject.get("cmdline") or "unknown subject"
    object_path = (
        event.object.get("path")
        or event.object.get("exe_path")
        or event.object.get("dest_ip")
        or event.object.get("package_drift")
        or event.event_type
    )
    return f"{event.source} {event.event_type}: {subject} -> {object_path}"


def _recent_auth_lines() -> list[str]:
    auth_log = Path("/var/log/auth.log")
    if auth_log.exists():
        try:
            return auth_log.read_text(encoding="utf-8", errors="replace").splitlines()[-2000:]
        except OSError:
            return []

    try:
        result = subprocess.run(
            ["journalctl", "-n", "2000", "--no-pager"],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        return []
    return [line for line in result.stdout.splitlines() if line.strip()]


__all__ = [
    "SentinelDaemon",
    "configure_logging",
    "load_config",
    "main",
]


if __name__ == "__main__":
    main()
