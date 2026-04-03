#!/usr/bin/env python3
"""BlackDome Sentinel - AI-driven host security agent."""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import platform
import shutil
import socket
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from core.actuator import ActionExecutor
from core.audit import AuditTrail
from core.baseline import BaselineGenerator
from core.control_plane import control_plane_config, control_plane_enabled, control_plane_headers, request_json
from core.hostile_feed import load_cached_hostile_ips, update_hostile_feed
from core.journal import EventJournal
from core.onboarding import COMPROMISED_PHASE, OnboardingManager
from core.policy import PolicyEngine
from core.reasoning import ReasoningEngine, severity_rank
from core.reporter import Reporter
from core.scanner import ScanOrchestrator
from core.situational import SituationalScorer, check_connectivity
from core.state_store import StateStore
from core.toolkit import TOOLKIT_DIR, verify_toolkit
from core.ttp_matcher import TTPMatch, match_findings
from core.verify import SignatureVerifier


PROJECT_ROOT = Path(__file__).resolve().parent
DEFAULT_CONTROL_PLANE_CONFIG = {
    "enabled": True,
    "url": "http://sentinel.blackdome.ai",
    "auth_token": "",
    "agent_id": "",
    "signing_public_key": "",
    "heartbeat_interval_seconds": 300,
    "timeout_seconds": 30,
}


def _resolve_project_path(path_value: str | Path) -> Path:
    path = Path(path_value)
    if path.is_absolute():
        return path
    return PROJECT_ROOT / path


def load_config(config_path: str | Path) -> dict[str, Any]:
    resolved = _resolve_project_path(config_path)
    with resolved.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}
    if not isinstance(data, dict):
        raise ValueError("Config root must be a mapping")
    return _normalize_config(data)


def save_config(config: dict[str, Any], config_path: str | Path = "config.yaml") -> Path:
    resolved = _resolve_project_path(config_path)
    resolved.parent.mkdir(parents=True, exist_ok=True)
    with resolved.open("w", encoding="utf-8") as handle:
        yaml.safe_dump(_normalize_config(config), handle, sort_keys=False)
    return resolved


def _normalize_config(config: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(config)
    reporting = normalized.get("reporting")
    reporting_control_plane = {}
    if isinstance(reporting, dict) and isinstance(reporting.get("control_plane"), dict):
        reporting_control_plane = dict(reporting["control_plane"])

    explicit_control_plane = normalized.get("control_plane")
    merged_control_plane = dict(DEFAULT_CONTROL_PLANE_CONFIG)
    if reporting_control_plane:
        merged_control_plane.update(reporting_control_plane)
    if isinstance(explicit_control_plane, dict):
        merged_control_plane.update(explicit_control_plane)
    normalized["control_plane"] = merged_control_plane

    if isinstance(reporting, dict) and "control_plane" in reporting:
        normalized_reporting = dict(reporting)
        normalized_reporting.pop("control_plane", None)
        normalized["reporting"] = normalized_reporting

    return normalized


def configure_logging(config: dict[str, Any]) -> None:
    sentinel_config = config.get("sentinel", {})
    override_level = os.getenv("SENTINEL_LOG_LEVEL_OVERRIDE", "").strip()
    log_level = str(override_level or sentinel_config.get("log_level", "INFO")).upper()
    logging.basicConfig(
        level=getattr(logging, log_level, logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        stream=sys.stdout,
        force=True,
    )


def derive_scan_result(
    baseline_diff: list[dict[str, Any]],
    approved_actions: list[dict[str, Any]],
    denied_actions: list[dict[str, Any]],
) -> str:
    if approved_actions:
        return "critical"
    if baseline_diff or denied_actions:
        return "warning"
    return "clean"


def resolve_scan_result(
    reasoning_result: dict[str, Any],
    baseline_diff: list[dict[str, Any]],
    approved_actions: list[dict[str, Any]],
    denied_actions: list[dict[str, Any]],
) -> str:
    assessment = str(reasoning_result.get("assessment", "clean")).lower()
    derived = derive_scan_result(baseline_diff, approved_actions, denied_actions)
    if assessment in {"critical", "high", "medium", "low"}:
        return assessment
    return derived


def deterministic_findings(findings: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    summary = {
        "critical_findings": [],
        "known_bad_ip": [],
        "known_malware_hash": [],
        "deleted_exe": [],
    }
    for finding in findings:
        severity = str(finding.get("severity", "info")).lower()
        tags = {str(tag) for tag in finding.get("tags", [])}
        if severity_rank(severity) >= severity_rank("critical"):
            summary["critical_findings"].append(finding)
        if "known_bad_ip" in tags:
            summary["known_bad_ip"].append(finding)
        if "known_malware_hash" in tags:
            summary["known_malware_hash"].append(finding)
        if "deleted_exe" in tags:
            summary["deleted_exe"].append(finding)
    return summary


def deterministic_actions(summary: dict[str, list[dict[str, Any]]]) -> list[dict[str, Any]]:
    actions = []
    seen: set[tuple[str, str]] = set()

    def add_action(action_name: str, target: Any, priority: str = "immediate", decision: str = "deterministic") -> None:
        target_value = str(target).strip()
        if not target_value:
            return
        key = (action_name, target_value)
        if key in seen:
            return
        seen.add(key)
        actions.append(
            {
                "action": action_name,
                "target": target_value,
                "priority": priority,
                "decision": decision,
            }
        )

    for finding in summary.get("known_bad_ip", []):
        evidence = finding.get("evidence", {}) if isinstance(finding.get("evidence"), dict) else {}
        target = evidence.get("remote_host") or evidence.get("source_ip") or evidence.get("remote_address")
        add_action("block_ip", target, decision="deterministic_known_bad_ip")

    for finding in summary.get("known_malware_hash", []):
        evidence = finding.get("evidence", {}) if isinstance(finding.get("evidence"), dict) else {}
        pid = evidence.get("pid")
        if pid is not None:
            add_action("kill_process", f"pid:{pid}", decision="deterministic_known_malware_hash")
        target = _normalize_executable_path(evidence.get("path")) or _normalize_executable_path(
            evidence.get("exe"),
            allow_deleted_suffix=True,
        )
        add_action("quarantine_file", target, decision="deterministic_known_malware_hash")

    # RECLASSIFIED: deleted_exe is AMBIGUOUS — goes to LLM, not deterministic action.
    # A deleted exe could be a package update (redis after apt upgrade) or malware hiding.
    # Only the LLM/council can distinguish these. See Redis incident 2026-04-02.

    return actions


def compromised_reasons(
    summary: dict[str, list[dict[str, Any]]],
    reasoning_result: dict[str, Any],
    ttp_matches: list[TTPMatch] | None = None,
) -> list[str]:
    reasons = []
    if summary.get("known_bad_ip"):
        reasons.append("hostile IP communication detected")
    if summary.get("known_malware_hash"):
        reasons.append("known malware hash detected")
    # deleted_exe alone does NOT indicate compromise (could be package update)
    if summary.get("critical_findings"):
        reasons.append("critical findings present during health check")
    if ttp_matches:
        reasons.append("deterministic TTP attack chain detected")
    if str(reasoning_result.get("assessment", "")).lower() == "critical":
        reasons.append("LLM assessment marked host as critical")
    return reasons


def json_print(payload: dict[str, Any]) -> None:
    print(json.dumps(payload, indent=2, sort_keys=True))


async def get_public_ip() -> str | None:
    for endpoint in (
        "https://ifconfig.me/ip",
        "https://api.ipify.org?format=json",
        "http://ifconfig.me/ip",
    ):
        try:
            status_code, payload = await request_json("GET", endpoint, timeout_seconds=5.0)
        except Exception:
            continue
        if status_code != 200 or payload is None:
            continue
        if isinstance(payload, dict) and payload.get("ip"):
            return str(payload["ip"]).strip()
        if isinstance(payload, str):
            candidate = payload.strip()
            if candidate:
                return candidate
    return None


def get_memory_percent() -> float:
    meminfo: dict[str, int] = {}
    try:
        with open("/proc/meminfo", "r", encoding="utf-8") as handle:
            for line in handle:
                key, _, value = line.partition(":")
                if not value:
                    continue
                meminfo[key] = int(value.strip().split()[0])
    except (OSError, ValueError):
        return 0.0

    total = float(meminfo.get("MemTotal", 0))
    available = float(meminfo.get("MemAvailable", meminfo.get("MemFree", 0)))
    if total <= 0:
        return 0.0
    used = max(0.0, total - available)
    return round((used / total) * 100.0, 2)


def get_disk_percent(path: str | Path = "/") -> float:
    try:
        usage = shutil.disk_usage(path)
    except OSError:
        return 0.0
    if usage.total <= 0:
        return 0.0
    used = max(0, usage.total - usage.free)
    return round((used / usage.total) * 100.0, 2)


def _degradation_config(config: dict[str, Any]) -> dict[str, Any]:
    governance = config.get("governance")
    if not isinstance(governance, dict):
        return {}
    degradation = governance.get("degradation")
    return degradation if isinstance(degradation, dict) else {}


def _prepare_toolkit(logger: logging.Logger, audit_trail: AuditTrail) -> dict[str, Any]:
    status = verify_toolkit()
    if status.get("ok"):
        toolkit_path = str(TOOLKIT_DIR)
        path_entries = os.environ.get("PATH", "").split(os.pathsep) if os.environ.get("PATH") else []
        if toolkit_path not in path_entries:
            os.environ["PATH"] = toolkit_path + (os.pathsep + os.environ["PATH"] if os.environ.get("PATH") else "")
        logger.info("Toolkit integrity verified")
        return status

    logger.critical("Toolkit integrity failed: %s", status)
    audit_trail.log_event("toolkit_integrity_failed", status)
    return status


def _merge_action_groups(*groups: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for group in groups:
        for action in group:
            if not isinstance(action, dict):
                continue
            key = (
                str(action.get("action", "")),
                str(action.get("target", "")),
                str(action.get("action_id") or action.get("id") or ""),
            )
            if key in seen:
                continue
            seen.add(key)
            merged.append(action)
    return merged


def _normalize_executable_path(value: Any, *, allow_deleted_suffix: bool = False) -> str | None:
    candidate = str(value or "").strip()
    if not candidate:
        return None
    if candidate.endswith(" (deleted)"):
        if not allow_deleted_suffix:
            return None
        candidate = candidate.removesuffix(" (deleted)").strip()
    if not candidate or candidate == "/" or not candidate.startswith("/"):
        return None
    if "/.git/" in candidate or candidate.endswith(".sample"):
        return None
    return candidate


def _is_actionable_process_target(finding: dict[str, Any]) -> bool:
    evidence = finding.get("evidence")
    if not isinstance(evidence, dict):
        return False

    category = str(finding.get("category", "")).lower()
    tags = {str(tag).lower() for tag in finding.get("tags", [])}

    if category == "network":
        return bool(evidence.get("pid")) and bool(tags & {"known_bad_ip", "known_bad_domain", "mining_pool_port"})

    if category != "process" or evidence.get("pid") is None:
        return False

    exe_path = _normalize_executable_path(evidence.get("exe"), allow_deleted_suffix=True)
    if "deleted_exe" in tags:
        return exe_path is not None
    if exe_path is not None:
        return True
    return bool(tags & {"known_malware_hash", "suspicious_name"})


def _extract_action_targets(findings: list[dict[str, Any]], *, process_only: bool = False) -> dict[str, str | None]:
    targets = {"pid": None, "path": None, "ip": None}
    strong_file_path: str | None = None
    for finding in findings:
        evidence = finding.get("evidence")
        if not isinstance(evidence, dict):
            continue
        category = str(finding.get("category", "")).lower()
        tags = {str(tag).lower() for tag in finding.get("tags", [])}
        severity = str(finding.get("severity", "")).lower()

        pid = evidence.get("pid")
        if (
            targets["pid"] is None
            and pid is not None
            and _is_actionable_process_target(finding)
        ):
            targets["pid"] = f"pid:{pid}"

        normalized_path = _normalize_executable_path(evidence.get("exe"), allow_deleted_suffix=True) or _normalize_executable_path(
            evidence.get("path")
        )
        if normalized_path:
            if (
                category == "process"
                and targets["path"] is None
                and _is_actionable_process_target(finding)
            ):
                targets["path"] = normalized_path
            elif (
                strong_file_path is None
                and not process_only
                and category in {"file", "process"}
                and _is_strong_executable_finding(finding)
                and "/.git/" not in normalized_path
                and not normalized_path.endswith(".sample")
            ):
                strong_file_path = normalized_path

        if targets["ip"] is None:
            remote_host = evidence.get("remote_host") or evidence.get("source_ip")
            if remote_host:
                targets["ip"] = str(remote_host)
            else:
                remote_address = str(evidence.get("remote_address") or "").strip()
                if remote_address:
                    targets["ip"] = remote_address.rsplit(":", 1)[0]

        if all(targets.values()):
            break
    if targets["path"] is None and strong_file_path is not None:
        targets["path"] = strong_file_path
    return targets


def _is_strong_executable_finding(finding: dict[str, Any]) -> bool:
    tags = {str(tag).lower() for tag in finding.get("tags", [])}
    category = str(finding.get("category", "")).lower()
    severity = str(finding.get("severity", "")).lower()
    evidence = finding.get("evidence")
    if not isinstance(evidence, dict):
        evidence = {}

    strong_tags = {
        "known_malware_hash",
        "deleted_exe",
        "suspicious_name",
        "immutable_binary",
        "immutable_file",
        "temp_executable",
        "new_binary",
        "modified_binary",
        "known_bad_ip",
        "known_bad_domain",
        "mining_pool_port",
    }
    if tags & strong_tags:
        return True

    path_value = str(evidence.get("path") or evidence.get("exe") or "")
    if severity in {"high", "critical"} and path_value.startswith(("/tmp", "/var/tmp", "/dev/shm")):
        return True

    if category == "network" and str(evidence.get("state") or "").upper().startswith(("ESTAB", "LISTEN")) and tags & {"new_listener"}:
        return True

    return False


def _build_actions_for_mode(
    mode: str,
    findings: list[dict[str, Any]],
    decision: str,
    *,
    targets: dict[str, str | None] | None = None,
) -> list[dict[str, Any]]:
    targets = targets or _extract_action_targets(findings)
    built: list[dict[str, Any]] = []
    lowered_mode = mode.lower()

    if "kill" in lowered_mode and targets["pid"]:
        built.append({"action": "kill_process", "target": targets["pid"], "priority": "immediate", "decision": decision})
    if "quarantine" in lowered_mode and targets["path"]:
        built.append({"action": "quarantine_file", "target": targets["path"], "priority": "immediate", "decision": decision})
    if "block" in lowered_mode and targets["ip"]:
        built.append({"action": "block_ip", "target": targets["ip"], "priority": "immediate", "decision": decision})

    return built


def _build_ttp_actions(matches: list[TTPMatch], findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    live_targets = _extract_action_targets(findings, process_only=True)
    action_groups = []
    for match in matches:
        if "kill" in match.action.lower() and not live_targets.get("pid"):
            continue
        action_groups.append(
            _build_actions_for_mode(
                match.action,
                findings,
                f"ttp:{match.pattern_id}",
                targets=live_targets,
            )
        )
    return _merge_action_groups(*action_groups)


def _degraded_reasoning_result(findings: list[dict[str, Any]], summary: str, source: str = "degraded") -> dict[str, Any]:
    if not findings:
        assessment = "clean"
    elif any(severity_rank(finding.get("severity")) >= severity_rank("critical") for finding in findings):
        assessment = "critical"
    elif any(severity_rank(finding.get("severity")) >= severity_rank("high") for finding in findings):
        assessment = "high"
    else:
        assessment = "low"
    return {
        "assessment": assessment,
        "hypotheses": [],
        "summary": summary,
        "classification": "default",
        "confidence": 0.0,
        "recommended_actions": [],
        "incident_ids": [],
        "finding_count": len(findings),
        "source": source,
    }


def _journal_payload(findings: list[dict[str, Any]], detection_layer: str, governance_state: str) -> dict[str, Any]:
    summarized_findings = []
    for finding in findings[:10]:
        summarized_findings.append(
            {
                "severity": finding.get("severity"),
                "category": finding.get("category"),
                "description": finding.get("description"),
                "evidence": finding.get("evidence", {}),
                "tags": finding.get("tags", []),
            }
        )
    return {
        "finding_count": len(findings),
        "findings": summarized_findings,
        "detection_layer": detection_layer,
        "governance_state": governance_state,
    }


async def _execute_actions_with_journal(
    action_executor: ActionExecutor,
    journal: EventJournal,
    actions: list[dict[str, Any]],
    *,
    findings: list[dict[str, Any]],
    detection_layer: str,
    governance_state: str,
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for action in actions:
        action_name = str(action.get("action", "")).strip()
        target = str(action.get("target", "")).strip()
        if not action_name or not target:
            continue
        reason = str(action.get("decision") or action.get("reason") or detection_layer)
        intent_seq = journal.write_intent(
            action_name,
            target,
            reason,
            _journal_payload(findings, detection_layer, governance_state),
        )
        action_result = (await action_executor.execute([action]))[0]
        details = {
            "ok": bool(action_result.get("ok")),
            "status": action_result.get("status"),
            "result": action_result.get("result", {}),
            "error": action_result.get("error"),
            "action_id": action_result.get("action_id") or action_result.get("id"),
            "detection_layer": detection_layer,
            "governance_state": governance_state,
        }
        journal.write_completed(intent_seq, action_name, target, str(action_result.get("status", "unknown")), details)
        results.append(action_result)
    return results


def _journal_escalation(
    journal: EventJournal,
    evidence_id: str,
    *,
    reason: str,
    findings: list[dict[str, Any]],
    detection_layer: str,
    governance_state: str,
    outcome: str,
) -> None:
    intent_seq = journal.write_intent("escalate", evidence_id, reason, _journal_payload(findings, detection_layer, governance_state))
    journal.write_completed(
        intent_seq,
        "escalate",
        evidence_id,
        outcome,
        {
            "detection_layer": detection_layer,
            "governance_state": governance_state,
            "finding_count": len(findings),
        },
    )


def _load_signature_verifier(
    config: dict[str, Any],
    state: dict[str, Any],
    logger: logging.Logger,
) -> SignatureVerifier | None:
    control_plane = control_plane_config(config)
    public_key = str(control_plane.get("signing_public_key") or "").strip()
    agent_id = str(control_plane.get("agent_id") or "").strip()
    if not public_key:
        logger.warning("Control plane signing_public_key not configured; signed actions will be rejected")
        return None
    try:
        return SignatureVerifier(
            public_key,
            last_nonce=int(state.get("last_control_plane_nonce", 0) or 0),
            agent_id=agent_id or None,
        )
    except Exception as exc:
        logger.warning("Unable to initialize signature verifier: %s", exc)
        return None


def _load_checkpoint_hash(journal: EventJournal) -> str:
    if not journal.checkpoint_path.exists():
        return "000000"
    try:
        checkpoint = json.loads(journal.checkpoint_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return "000000"
    return str(checkpoint.get("journal_hash") or "000000")


async def _replay_journal(
    config: dict[str, Any],
    journal: EventJournal,
    *,
    verifier: SignatureVerifier | None,
    logger: logging.Logger,
) -> dict[str, Any]:
    if not control_plane_enabled(config, require_auth=True):
        return {"status": "skipped", "reason": "control_plane_disabled", "replayed": 0}

    entries = journal.get_unreplayed_entries()
    if not entries:
        return {"status": "skipped", "reason": "no_entries", "replayed": 0}

    control_plane = control_plane_config(config)
    endpoint = f"{str(control_plane.get('url', '')).rstrip('/')}/api/sentinel/evidence/journal-replay"
    payload = {
        "entries": entries,
        "checkpoint_hash": _load_checkpoint_hash(journal),
    }

    try:
        status_code, response_payload = await request_json(
            "POST",
            endpoint,
            json_body=payload,
            headers=control_plane_headers(config),
            timeout_seconds=float(control_plane.get("timeout_seconds", 30)),
        )
    except Exception as exc:
        logger.warning("Journal replay failed: %s", exc)
        return {"status": "failed", "error": str(exc), "replayed": 0}

    if status_code != 200 or not isinstance(response_payload, dict):
        logger.warning("Journal replay returned %s: %s", status_code, response_payload)
        return {"status": "failed", "status_code": status_code, "response": response_payload, "replayed": 0}

    checkpoint_saved = False
    checkpoint = response_payload.get("checkpoint")
    if isinstance(checkpoint, dict) and verifier is not None and verifier.verify_signed_payload(checkpoint):
        journal.save_checkpoint(checkpoint)
        checkpoint_saved = True
    elif checkpoint:
        logger.warning("Rejected unsigned or invalid checkpoint from control plane")

    return {
        "status": "ok",
        "replayed": int(response_payload.get("received", len(entries)) or 0),
        "checkpoint_saved": checkpoint_saved,
    }


async def _execute_pending_signed_actions(
    config: dict[str, Any],
    heartbeat: dict[str, Any],
    *,
    verifier: SignatureVerifier | None,
    action_executor: ActionExecutor,
    journal: EventJournal,
    logger: logging.Logger,
) -> list[dict[str, Any]]:
    pending_actions = heartbeat.get("pending_actions", [])
    if not isinstance(pending_actions, list) or not pending_actions:
        return []
    if verifier is None:
        logger.warning("Pending actions received but verifier is unavailable; skipping execution")
        return []

    executed_results: list[dict[str, Any]] = []
    expected_agent_id = str(control_plane_config(config).get("agent_id") or "").strip() or None
    for item in pending_actions:
        if not isinstance(item, dict):
            continue
        envelope = item.get("envelope") if isinstance(item.get("envelope"), dict) else item
        if not isinstance(envelope, dict):
            continue
        if not verifier.verify_action(envelope, expected_agent_id=expected_agent_id):
            continue

        action = {
            "action": envelope.get("action"),
            "target": envelope.get("target"),
            "priority": "immediate",
            "decision": "control_plane_signed",
            "action_id": item.get("action_id") or item.get("id") or envelope.get("action_id") or envelope.get("id"),
        }
        findings = [
            {
                "severity": "high",
                "category": "control_plane",
                "description": f"Signed control plane action {envelope.get('action')} received",
                "evidence": envelope,
                "tags": ["signed_action"],
            }
        ]
        executed_results.extend(
            await _execute_actions_with_journal(
                action_executor,
                journal,
                [action],
                findings=findings,
                detection_layer="control_plane_signed",
                governance_state="healthy",
            )
        )
    return executed_results


def initial_runtime(config_path: str | Path) -> tuple[dict[str, Any], logging.Logger, StateStore, AuditTrail, BaselineGenerator, Path, OnboardingManager]:
    config = load_config(config_path)
    configure_logging(config)
    logger = logging.getLogger("sentinel")
    sentinel_config = config.get("sentinel", {})
    state_store = StateStore(_resolve_project_path(sentinel_config.get("state_path", "state/sentinel_state.json")))
    audit_trail = AuditTrail(_resolve_project_path(sentinel_config.get("audit_log", "logs/audit.jsonl")))
    baseline_generator = BaselineGenerator(project_root=PROJECT_ROOT, config=config)
    baseline_path = _resolve_project_path(sentinel_config.get("baseline_path", "state/baseline.json"))
    onboarding = OnboardingManager(config, state_store, baseline_generator, baseline_path)
    return config, logger, state_store, audit_trail, baseline_generator, baseline_path, onboarding


async def enroll_command(config_path: str = "config.yaml") -> dict[str, Any]:
    config, logger, state_store, audit_trail, baseline_generator, baseline_path, onboarding = initial_runtime(config_path)
    control_plane = control_plane_config(config)
    if not control_plane.get("enabled"):
        raise RuntimeError("Control plane enrollment requested but control_plane.enabled is false")
    if not control_plane.get("url"):
        raise RuntimeError("Control plane enrollment requested but control_plane.url is missing")

    public_ip = await get_public_ip()
    payload = {
        "hostname": socket.gethostname(),
        "os_info": platform.platform(),
        "agent_version": "0.1.0",
        "public_ip": public_ip,
    }
    endpoint = f"{str(control_plane.get('url', '')).rstrip('/')}/api/sentinel/enroll"
    status_code, response_payload = await request_json(
        "POST",
        endpoint,
        json_body=payload,
        timeout_seconds=float(control_plane.get("timeout_seconds", 30)),
    )
    if status_code != 200 or not isinstance(response_payload, dict):
        raise RuntimeError(f"Enrollment failed: status={status_code} payload={response_payload}")

    agent_id = str(response_payload.get("agent_id") or "").strip()
    auth_token = str(response_payload.get("auth_token") or "").strip()
    if not agent_id or not auth_token:
        raise RuntimeError(f"Enrollment response missing agent credentials: {response_payload}")

    config["control_plane"]["agent_id"] = agent_id
    config["control_plane"]["auth_token"] = auth_token
    if response_payload.get("signing_public_key"):
        config["control_plane"]["signing_public_key"] = str(response_payload["signing_public_key"]).strip()
    save_config(config, config_path)
    audit_trail.log_event(
        "control_plane_enrolled",
        {
            "agent_id": agent_id,
            "control_plane_url": control_plane.get("url"),
            "enrolled_at": datetime.now(timezone.utc).isoformat(),
        },
    )
    logger.info("Enrolled with control plane as %s", agent_id)
    print(f"Enrolled as {agent_id}")
    print("Auth token saved to config.yaml (KEEP THIS SAFE)")
    return {
        "agent_id": agent_id,
        "control_plane_url": control_plane.get("url"),
        "public_ip": public_ip,
        "saved_config": str(_resolve_project_path(config_path)),
    }


async def send_heartbeat(
    config: dict[str, Any],
    state: dict[str, Any],
    logger: logging.Logger | None = None,
) -> dict[str, Any]:
    if not control_plane_enabled(config, require_auth=True):
        return {"status": "skipped", "reason": "control_plane_disabled"}

    control_plane = control_plane_config(config)
    endpoint = f"{str(control_plane.get('url', '')).rstrip('/')}/api/sentinel/heartbeat"
    payload = {
        "phase": state.get("onboarding_phase", "unknown"),
        "scan_count": int(state.get("scan_count", 0)),
        "last_scan_at": state.get("last_scan_at"),
        "hostile_feed_count": int(state.get("hostile_feed_count", 0)),
        "system": {
            "load": os.getloadavg()[0] if hasattr(os, "getloadavg") else 0.0,
            "memory_percent": get_memory_percent(),
            "disk_percent": get_disk_percent(),
        },
    }

    try:
        status_code, response_payload = await request_json(
            "POST",
            endpoint,
            json_body=payload,
            headers=control_plane_headers(config),
            timeout_seconds=min(float(control_plane.get("timeout_seconds", 30)), 10.0),
        )
    except Exception as exc:  # pragma: no cover - integration path
        if logger is not None:
            logger.warning("Heartbeat failed: %s", exc)
        return {"status": "failed", "error": str(exc)}

    if status_code == 200 and isinstance(response_payload, dict):
        pending_actions = response_payload.get("pending_actions", [])
        if pending_actions and logger is not None:
            logger.info("Received %d pending actions from control plane", len(pending_actions))
        return {
            "status": "ok",
            "pending_action_count": len(pending_actions) if isinstance(pending_actions, list) else 0,
            "pending_actions": pending_actions if isinstance(pending_actions, list) else [],
        }

    if logger is not None:
        logger.warning("Heartbeat returned %s: %s", status_code, response_payload)
    return {"status": "failed", "status_code": status_code, "response": response_payload}


async def confirm_action(
    config: dict[str, Any],
    action_id: str | None,
    status: str,
    result: dict[str, Any],
    logger: logging.Logger | None = None,
) -> dict[str, Any]:
    if not action_id or not control_plane_enabled(config, require_auth=True):
        return {"status": "skipped", "reason": "missing_action_id_or_control_plane_disabled"}

    control_plane = control_plane_config(config)
    endpoint = f"{str(control_plane.get('url', '')).rstrip('/')}/api/sentinel/actions/{action_id}/confirm"
    payload = {
        "status": status,
        "result": result,
        "executed_at": datetime.now(timezone.utc).isoformat(),
    }
    try:
        status_code, response_payload = await request_json(
            "POST",
            endpoint,
            json_body=payload,
            headers=control_plane_headers(config),
            timeout_seconds=min(float(control_plane.get("timeout_seconds", 30)), 10.0),
        )
    except Exception as exc:  # pragma: no cover - integration path
        if logger is not None:
            logger.warning("Action confirmation failed: %s", exc)
        return {"status": "failed", "error": str(exc)}

    if status_code == 200:
        return {"status": "ok", "action_id": action_id}

    if logger is not None:
        logger.warning("Action confirmation returned %s: %s", status_code, response_payload)
    return {"status": "failed", "status_code": status_code, "response": response_payload}


async def run_cycle(config_path: str = "config.yaml") -> dict[str, Any]:
    """Execute one complete scan cycle respecting the current onboarding phase."""
    config, logger, state_store, audit_trail, baseline_generator, baseline_path, onboarding = initial_runtime(config_path)
    state = onboarding.ensure_state(state_store.load())
    state_store.save(state)
    phase = onboarding.current_phase(state)
    journal = EventJournal()
    toolkit_status = _prepare_toolkit(logger, audit_trail)
    toolkit_observe_only = not bool(toolkit_status.get("ok"))
    scorer = SituationalScorer(_degradation_config(config))
    try:
        scorer._last_heartbeat_ok = float(state.get("last_heartbeat_ok_ts")) if state.get("last_heartbeat_ok_ts") else None
    except (TypeError, ValueError):
        scorer._last_heartbeat_ok = None
    verifier = _load_signature_verifier(config, state, logger)

    if phase == COMPROMISED_PHASE:
        logger.error("Host is marked compromised; refusing to continue until operator reset")
        return onboarding.build_status(state)

    loaded_baseline = baseline_generator.load_baseline(baseline_path)
    if phase == "confirmation_pending":
        baseline_report = onboarding.build_baseline_report(loaded_baseline or baseline_generator.generate())
        logger.info("Baseline confirmation pending")
        json_print(baseline_report)
        return baseline_report

    if not loaded_baseline:
        logger.warning("No baseline found at %s; continuing with current phase logic", baseline_path)

    orchestrator = ScanOrchestrator(config=config, baseline=loaded_baseline, project_root=PROJECT_ROOT)
    evidence_bundle = await orchestrator.run_scan()

    for collector_name, collector_result in evidence_bundle.evidence.items():
        logger.info("Collector %s returned %s", collector_name, collector_result)

    reasoning_engine = ReasoningEngine(config)
    findings = reasoning_engine.extract_findings(evidence_bundle)
    summary = deterministic_findings(findings)
    ttp_matches = match_findings(findings)
    if ttp_matches:
        logger.info("Matched TTP patterns: %s", [match.pattern_id for match in ttp_matches])

    local_deterministic_actions = _merge_action_groups(
        deterministic_actions(summary),
        _build_ttp_actions(ttp_matches, findings),
    )
    control_plane_reachable = True
    connectivity = {"control_plane": True, "internet": True, "tailscale": True}
    if control_plane_enabled(config, require_auth=True):
        connectivity = check_connectivity(config)
        control_plane_reachable = bool(connectivity.get("control_plane"))

    governance_degraded = control_plane_enabled(config, require_auth=True) and not control_plane_reachable
    if control_plane_enabled(config, require_auth=True) and not governance_degraded:
        reasoning_result = await reasoning_engine._reason_remote(
            findings,
            evidence_bundle.baseline_diff,
            config,
            state=state,
        )
        if reasoning_result.get("source") != "remote":
            governance_degraded = True
            reasoning_result = _degraded_reasoning_result(
                findings,
                "Governance degraded; skipping single-model fallback and using deterministic controls.",
            )
    elif governance_degraded:
        reasoning_result = _degraded_reasoning_result(
            findings,
            "Control plane unreachable; using deterministic controls and situational scoring.",
        )
    else:
        reasoning_result = await reasoning_engine.analyze(evidence_bundle, state=state)
    logger.info("Reasoning source: %s", reasoning_result.get("source", "local"))

    policy_engine = PolicyEngine(config.get("policies", {}))
    policy_approved_actions, denied_actions = policy_engine.evaluate(
        classification=reasoning_result.get("classification", "default"),
        confidence=float(reasoning_result.get("confidence", 0.0)),
        actions=reasoning_result.get("recommended_actions", []),
    )

    updated_state = onboarding.ensure_state(state)
    phase_messages: list[str] = []
    scan_evidence_id = f"{evidence_bundle.hostname}:{int(evidence_bundle.timestamp)}"

    if phase == "health_check":
        reasons = compromised_reasons(summary, reasoning_result, ttp_matches)
        if reasons:
            updated_state = onboarding.set_phase(updated_state, COMPROMISED_PHASE, reason="; ".join(reasons))
            policy_approved_actions = []
            denied_actions = []
            phase_messages.append("marked_compromised")
        else:
            onboarding.merge_candidate_baseline(evidence_bundle.current_snapshot)
            updated_state = onboarding.set_phase(updated_state, "discovery", reason=None)
            denied_actions.extend(policy_approved_actions)
            policy_approved_actions = []
            phase_messages.append("advanced_to_discovery")
    elif phase == "discovery":
        onboarding.merge_candidate_baseline(evidence_bundle.current_snapshot)
        denied_actions.extend(policy_approved_actions)
        policy_approved_actions = []
        phase_messages.append("candidate_baseline_merged")
        if onboarding.should_transition_from_discovery(updated_state):
            updated_state = onboarding.set_phase(updated_state, "confirmation_pending", reason=None)
            phase_messages.append("advanced_to_confirmation_pending")
    elif phase == "observe":
        denied_actions.extend(policy_approved_actions)
        policy_approved_actions = []
        if onboarding.should_transition_from_observe(updated_state):
            updated_state = onboarding.set_phase(updated_state, "protect", reason=None)
            phase_messages.append("advanced_to_protect")

    situational_result: dict[str, Any] | None = None
    situational_actions: list[dict[str, Any]] = []
    current_phase_name = onboarding.current_phase(updated_state)
    protect_phase = current_phase_name == "protect"
    os.environ["SENTINEL_PHASE"] = current_phase_name
    if governance_degraded and findings:
        situational_result = scorer.score(findings, connectivity)
        if not local_deterministic_actions and not toolkit_observe_only and protect_phase:
            if situational_result.get("action") == "kill":
                situational_actions = _build_actions_for_mode("kill_and_quarantine", findings, "situational_escalation")
            elif situational_result.get("action") == "quarantine":
                situational_actions = _build_actions_for_mode("quarantine", findings, "situational_escalation")
    elif findings:
        situational_result = {"score": 0, "action": "observe", "reasons": [], "kill_threshold": None, "quarantine_threshold": None}

    approved_actions = _merge_action_groups(
        local_deterministic_actions,
        situational_actions,
        policy_approved_actions if protect_phase else [],
    )
    if toolkit_observe_only and approved_actions:
        denied_actions.extend([{**action, "decision": "toolkit_observe_only"} for action in approved_actions])
        approved_actions = []

    action_executor = ActionExecutor(project_root=PROJECT_ROOT, audit_trail=audit_trail)
    local_action_results: list[dict[str, Any]] = []
    governance_state = "toolkit_tampered" if toolkit_observe_only else ("agent_isolated" if governance_degraded else "healthy")

    if approved_actions:
        deterministic_queue = local_deterministic_actions if not toolkit_observe_only else []
        situational_queue = situational_actions if not toolkit_observe_only else []
        policy_queue = policy_approved_actions if protect_phase and not toolkit_observe_only else []

        if deterministic_queue:
            local_action_results.extend(
                await _execute_actions_with_journal(
                    action_executor,
                    journal,
                    deterministic_queue,
                    findings=findings,
                    detection_layer="deterministic_degraded" if governance_degraded else "deterministic",
                    governance_state=governance_state,
                )
            )
        if situational_queue:
            local_action_results.extend(
                await _execute_actions_with_journal(
                    action_executor,
                    journal,
                    situational_queue,
                    findings=findings,
                    detection_layer="situational_escalation",
                    governance_state=governance_state,
                )
            )
        if policy_queue:
            local_action_results.extend(
                await _execute_actions_with_journal(
                    action_executor,
                    journal,
                    policy_queue,
                    findings=findings,
                    detection_layer="policy",
                    governance_state=governance_state,
                )
            )
    else:
        if findings:
            if toolkit_observe_only:
                _journal_escalation(
                    journal,
                    scan_evidence_id,
                    reason="toolkit_integrity_failed",
                    findings=findings,
                    detection_layer="observe_only_degraded",
                    governance_state=governance_state,
                    outcome="toolkit_observe_only",
                )
            elif governance_degraded and (
                not protect_phase or (situational_result and situational_result.get("action") == "observe")
            ):
                _journal_escalation(
                    journal,
                    scan_evidence_id,
                    reason="governance_degraded_observe_only" if protect_phase else "governance_degraded_non_protect",
                    findings=findings,
                    detection_layer="observe_only_degraded",
                    governance_state=governance_state,
                    outcome="observe_only_degraded",
                )
            elif control_plane_enabled(config, require_auth=True):
                _journal_escalation(
                    journal,
                    scan_evidence_id,
                    reason="queued_for_governance",
                    findings=findings,
                    detection_layer="control_plane_governance",
                    governance_state=governance_state,
                    outcome="queued_for_control_plane",
                )
            else:
                _journal_escalation(
                    journal,
                    scan_evidence_id,
                    reason="local_observe_only",
                    findings=findings,
                    detection_layer="local_observe",
                    governance_state=governance_state,
                    outcome="observe_only",
                )
        elif evidence_bundle.baseline_diff:
            _journal_escalation(
                journal,
                scan_evidence_id,
                reason="baseline_drift_detected",
                findings=[],
                detection_layer="baseline_drift",
                governance_state=governance_state,
                outcome="drift_logged",
            )
        else:
            baseline_hash = baseline_generator.file_hash(baseline_path) if baseline_path.exists() else "unknown"
            journal.write_allow(str(baseline_path), baseline_hash or "unknown")

    if local_action_results:
        confirmation_tasks = []
        for action_result in local_action_results:
            action_id = str(action_result.get("action_id") or action_result.get("id") or "").strip() or None
            result_payload = action_result.get("result", {})
            if not isinstance(result_payload, dict):
                result_payload = {"value": result_payload}
            if action_result.get("error"):
                result_payload = {**result_payload, "error": action_result["error"]}
            confirmation_tasks.append(
                confirm_action(
                    config,
                    action_id=action_id,
                    status=str(action_result.get("status", "unknown")),
                    result=result_payload,
                    logger=logger,
                )
            )
        if confirmation_tasks:
            await asyncio.gather(*confirmation_tasks)

    scan_result = resolve_scan_result(reasoning_result, evidence_bundle.baseline_diff, approved_actions, denied_actions)
    if onboarding.current_phase(updated_state) == COMPROMISED_PHASE:
        scan_result = "critical"

    updated_state["last_scan_at"] = evidence_bundle.iso_timestamp
    updated_state["last_scan_result"] = scan_result
    updated_state["scan_count"] = int(updated_state.get("scan_count", 0)) + 1
    updated_state["active_incidents"] = reasoning_result.get("incident_ids", [])
    updated_state["hostile_feed_count"] = len(load_cached_hostile_ips(onboarding.hostile_feed_path))

    heartbeat = await send_heartbeat(config, updated_state, logger=logger)
    if heartbeat.get("status") == "ok":
        scorer.record_heartbeat(True)
        updated_state["last_heartbeat_ok_ts"] = datetime.now(timezone.utc).timestamp()
    pending_action_results = await _execute_pending_signed_actions(
        config,
        heartbeat,
        verifier=verifier,
        action_executor=action_executor,
        journal=journal,
        logger=logger,
    )
    if pending_action_results:
        confirmation_tasks = []
        for action_result in pending_action_results:
            action_id = str(action_result.get("action_id") or action_result.get("id") or "").strip() or None
            result_payload = action_result.get("result", {})
            if not isinstance(result_payload, dict):
                result_payload = {"value": result_payload}
            if action_result.get("error"):
                result_payload = {**result_payload, "error": action_result["error"]}
            confirmation_tasks.append(
                confirm_action(
                    config,
                    action_id=action_id,
                    status=str(action_result.get("status", "unknown")),
                    result=result_payload,
                    logger=logger,
                )
            )
        if confirmation_tasks:
            await asyncio.gather(*confirmation_tasks)
    if heartbeat.get("status") == "ok":
        heartbeat["journal_replay"] = await _replay_journal(config, journal, verifier=verifier, logger=logger)
    else:
        heartbeat["journal_replay"] = {"status": "skipped", "reason": "heartbeat_failed", "replayed": 0}
    if verifier is not None:
        updated_state["last_control_plane_nonce"] = verifier.last_nonce

    all_action_results = [*local_action_results, *pending_action_results]
    blocked_ips = set(updated_state.get("blocked_ips", []))
    quarantined_files = set(updated_state.get("quarantined_files", []))
    for action_result in all_action_results:
        if not action_result.get("ok"):
            continue
        if action_result.get("action") == "block_ip" and action_result.get("target"):
            blocked_ips.add(str(action_result["target"]))
        if action_result.get("action") == "quarantine_file":
            quarantine_path = action_result.get("result", {}).get("quarantine_path")
            if quarantine_path:
                quarantined_files.add(str(quarantine_path))
    updated_state["blocked_ips"] = sorted(blocked_ips)
    updated_state["quarantined_files"] = sorted(quarantined_files)
    if baseline_path.exists():
        updated_state["baseline_hash"] = baseline_generator.file_hash(baseline_path)
    state_store.save(updated_state)

    scan_summary = {
        "assessment": reasoning_result.get("assessment", scan_result),
        "classification": reasoning_result.get("classification", "default"),
        "confidence": reasoning_result.get("confidence", 0.0),
        "summary": reasoning_result.get("summary", "No summary"),
        "hypotheses": reasoning_result.get("hypotheses", []),
        "recommended_actions": reasoning_result.get("recommended_actions", []),
        "approved_actions": approved_actions,
        "denied_actions": denied_actions,
        "action_results": local_action_results,
        "heartbeat_pending_action_results": pending_action_results,
        "baseline_diff": evidence_bundle.baseline_diff,
        "scan_result": scan_result,
        "collector_count": len(evidence_bundle.evidence),
        "finding_count": len(findings),
        "scan_timestamp": evidence_bundle.iso_timestamp,
        "hostname": evidence_bundle.hostname,
        "onboarding_phase": onboarding.current_phase(updated_state),
        "phase_messages": phase_messages,
        "reasoning_source": reasoning_result.get("source", "local"),
        "ttp_matches": [match.pattern_id for match in ttp_matches],
        "situational": situational_result,
        "toolkit": toolkit_status,
        "connectivity": connectivity,
    }
    audit_trail.log_scan(evidence_bundle.as_dict(), scan_summary)
    for message in phase_messages:
        audit_trail.log_event("onboarding_phase_change", {"message": message, "phase": onboarding.current_phase(updated_state)})

    reporter = Reporter(config)
    await reporter.report(scan_summary)

    logger.info(
        "Scan complete: result=%s phase=%s anomalies=%d approved_actions=%d source=%s",
        scan_summary["scan_result"],
        scan_summary["onboarding_phase"],
        len(evidence_bundle.baseline_diff),
        len(approved_actions),
        scan_summary["reasoning_source"],
    )

    scan_summary["heartbeat"] = heartbeat

    if onboarding.current_phase(updated_state) == "confirmation_pending":
        json_print(onboarding.build_baseline_report(baseline_generator.load_baseline(baseline_path)))

    return scan_summary


async def regenerate_baseline(config_path: str = "config.yaml") -> dict[str, Any]:
    config, logger, state_store, audit_trail, baseline_generator, baseline_path, onboarding = initial_runtime(config_path)
    baseline = baseline_generator.generate(include_verification=True)
    baseline_generator.save_baseline(baseline, baseline_path)
    state = onboarding.ensure_state(state_store.load())
    state["baseline_hash"] = baseline_generator.file_hash(baseline_path)
    state_store.save(state)
    audit_trail.log_event(
        "baseline_generated",
        {
            "baseline_path": str(baseline_path),
            "baseline_hash": state["baseline_hash"],
        },
    )
    logger.info("Baseline saved to %s", baseline_path)
    return {"baseline_path": str(baseline_path), "baseline_hash": state["baseline_hash"]}


async def confirm_baseline(config_path: str = "config.yaml") -> dict[str, Any]:
    config, logger, state_store, audit_trail, baseline_generator, baseline_path, onboarding = initial_runtime(config_path)
    if not baseline_path.exists():
        baseline = baseline_generator.generate(include_verification=True)
        baseline_generator.save_baseline(baseline, baseline_path)
    state = onboarding.confirm_baseline()
    state["baseline_hash"] = baseline_generator.file_hash(baseline_path)
    state_store.save(state)
    audit_trail.log_event("baseline_confirmed", {"phase": "observe", "baseline_hash": state.get("baseline_hash")})
    logger.info("Baseline confirmed; phase is now observe")
    return onboarding.build_status(state)


async def enable_protect(config_path: str = "config.yaml") -> dict[str, Any]:
    config, logger, state_store, audit_trail, baseline_generator, baseline_path, onboarding = initial_runtime(config_path)
    state = onboarding.enable_protect()
    audit_trail.log_event("protect_enabled", {"phase": "protect", "enabled_at": state.get("protect_enabled_at")})
    logger.info("Protect mode enabled")
    return onboarding.build_status(state)


async def update_hostile_feed_command(config_path: str = "config.yaml") -> dict[str, Any]:
    config, logger, state_store, audit_trail, baseline_generator, baseline_path, onboarding = initial_runtime(config_path)
    threat_intel = config.get("threat_intel", {}) if isinstance(config.get("threat_intel"), dict) else {}
    collectors = config.get("collectors", {}) if isinstance(config.get("collectors"), dict) else {}
    configured_bad_ips = set(collectors.get("network_scanner", {}).get("known_bad_ips", [])) if isinstance(collectors, dict) else set()
    cache_path = onboarding.hostile_feed_path
    state = onboarding.ensure_state(state_store.load())
    result = await update_hostile_feed(
        path=cache_path,
        min_events=int(threat_intel.get("hostile_feed_min_events", 3)),
        days=int(threat_intel.get("hostile_feed_days", 30)),
        seed_ips=configured_bad_ips,
        config=config,
        state=state,
    )
    state["hostile_feed_updated_at"] = datetime.now(timezone.utc).isoformat()
    state["hostile_feed_count"] = int(result.get("count", 0))
    state_store.save(state)
    audit_trail.log_event("hostile_feed_updated", {"count": result.get("count", 0), "reason": result.get("reason")})
    logger.info("Hostile feed update result: %s", result)
    return result


def status_command(config_path: str = "config.yaml") -> dict[str, Any]:
    config, logger, state_store, audit_trail, baseline_generator, baseline_path, onboarding = initial_runtime(config_path)
    state = onboarding.ensure_state(state_store.load())
    state_store.save(state)
    return onboarding.build_status(state)


def reset_command(config_path: str = "config.yaml") -> dict[str, Any]:
    config, logger, state_store, audit_trail, baseline_generator, baseline_path, onboarding = initial_runtime(config_path)
    state = onboarding.reset()
    audit_trail.log_event("onboarding_reset", {"phase": state.get("onboarding_phase")})
    logger.info("Onboarding reset to health_check")
    return onboarding.build_status(state)


async def dispatch(args: argparse.Namespace) -> dict[str, Any]:
    if args.enroll:
        return await enroll_command(args.config)
    if args.status:
        return status_command(args.config)
    if args.reset:
        return reset_command(args.config)
    if args.baseline:
        return await regenerate_baseline(args.config)
    if args.confirm_baseline:
        return await confirm_baseline(args.config)
    if args.enable_protect:
        return await enable_protect(args.config)
    if args.update_hostile_feed:
        return await update_hostile_feed_command(args.config)
    return await run_cycle(args.config)


def main() -> None:
    parser = argparse.ArgumentParser(description="BlackDome Sentinel")
    parser.add_argument("--once", action="store_true", help="Run one cycle and exit")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging for this run")
    parser.add_argument("--enroll", action="store_true", help="Enroll this agent with the control plane")
    parser.add_argument("--baseline", action="store_true", help="Generate known-good baseline")
    parser.add_argument("--confirm-baseline", action="store_true", help="Confirm candidate baseline and enter observe phase")
    parser.add_argument("--enable-protect", action="store_true", help="Enable protect mode")
    parser.add_argument("--status", action="store_true", help="Show current onboarding phase and stats")
    parser.add_argument("--reset", action="store_true", help="Reset onboarding to health_check")
    parser.add_argument("--update-hostile-feed", action="store_true", help="Refresh hostile IP cache from the honeypot database")
    parser.add_argument("--config", default="config.yaml", help="Config file path")
    args = parser.parse_args()

    if args.verbose:
        os.environ["SENTINEL_LOG_LEVEL_OVERRIDE"] = "DEBUG"

    result = asyncio.run(dispatch(args))
    if args.status or args.reset or args.confirm_baseline or args.enable_protect or args.update_hostile_feed or args.baseline:
        json_print(result)


if __name__ == "__main__":
    main()
