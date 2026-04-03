"""LLM reasoning engine backed by a local Ollama model."""

from __future__ import annotations

import asyncio
import json
import logging
import re
import socket
from datetime import datetime, timezone
from typing import Any
from urllib import error as urllib_error
from urllib import request as urllib_request

try:  # pragma: no cover - exercised in integration environments
    import httpx
except ImportError:  # pragma: no cover - dependency may be installed later
    httpx = None

from .control_plane import control_plane_config, control_plane_enabled, request_json


SYSTEM_PROMPT = """
You are BlackDome Sentinel, an AI security agent monitoring a Linux host.
You receive evidence from security scanners and must classify threats.

Respond ONLY with valid JSON (no markdown, no explanation outside JSON).

Schema:
{
  "assessment": "critical|high|medium|low|clean",
  "hypotheses": [
    {
      "description": "Human-readable description of what you found",
      "classification": "crypto_miner|rootkit|backdoor|brute_force|unknown_binary|data_exfil|lateral_movement|benign",
      "confidence": 0.0 to 1.0,
      "evidence_refs": ["which findings support this"],
      "recommended_actions": [
        {"action": "kill_process|quarantine_file|block_ip|strip_immutable|clean_persistence|snapshot_evidence", "target": "specific target", "priority": "immediate|high|medium|low"}
      ],
      "mitre_techniques": ["T1496", "T1053"]
    }
  ],
  "summary": "One sentence overall assessment"
}

Rules:
- Only recommend actions you have strong evidence for
- If nothing suspicious, return assessment "clean" with empty hypotheses
- crypto_miner indicators: high CPU binary, connections to mining pools, chattr +ia, names like xmrig/softirq/minerd
- rootkit indicators: deleted executables still running, modified system binaries, hidden processes
- Do NOT flag normal system processes (systemd, sshd, postgres, node, python3, nginx, ollama, pm2)
- Do NOT flag package manager operations (apt, dpkg, pip, npm)
""".strip()

SEVERITY_RANK = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

POLICY_CLASSIFICATION_MAP = {
    "brute_force": "ssh_brute_force",
    "rootkit": "rootkit_suspected",
}

JSON_PATTERN = re.compile(r"\{.*\}", re.DOTALL)


def severity_rank(value: str | None) -> int:
    """Return an ordinal rank for a finding severity."""
    if not value:
        return SEVERITY_RANK["info"]
    return SEVERITY_RANK.get(str(value).strip().lower(), SEVERITY_RANK["info"])


def build_user_prompt(
    evidence_bundle: Any,
    baseline_diff: list[dict[str, Any]] | None,
    config: dict[str, Any] | None,
) -> str:
    """Assemble the prompt passed to the LLM."""
    reasoner = SentinelReasoner(config or {})
    findings = reasoner.extract_findings(evidence_bundle)
    sentinel_config = reasoner._sentinel_config(config or {})
    host_name = (
        sentinel_config.get("hostname")
        or getattr(evidence_bundle, "hostname", None)
        or socket.gethostname()
    )

    scan_time = getattr(evidence_bundle, "iso_timestamp", None)
    if not scan_time:
        timestamp = getattr(evidence_bundle, "timestamp", None)
        if timestamp is not None:
            scan_time = datetime.fromtimestamp(float(timestamp), tz=timezone.utc).isoformat()
        else:
            scan_time = datetime.now(timezone.utc).isoformat()

    sections = [
        f"Host: {host_name}",
        f"Scan time: {scan_time}",
    ]

    doctrine_lines = []
    for key in ("hostname", "role", "host_type", "description", "environment"):
        value = sentinel_config.get(key)
        if value:
            doctrine_lines.append(f"  {key}: {value}")
    if doctrine_lines:
        sections.append("HOST DOCTRINE:")
        sections.extend(doctrine_lines)

    if baseline_diff:
        sections.append("BASELINE CHANGES:")
        for change in baseline_diff:
            if not isinstance(change, dict):
                continue
            change_type = change.get("type", "changed")
            category = change.get("category", "unknown")
            detail = change.get("detail", "")
            sections.append(f"  [{change_type}] {category}: {detail}".rstrip())

    sections.append("EVIDENCE FINDINGS:")
    if not findings:
        sections.append("  [INFO] none: No findings were reported by the collectors.")
    for finding in sorted(findings, key=lambda item: severity_rank(item.get("severity")), reverse=True):
        sections.append(
            f"  [{str(finding.get('severity', 'info')).upper()}] "
            f"{finding.get('category', 'unknown')}: {finding.get('description', 'No description')}"
        )
        if finding.get("source"):
            sections.append(f"    source: {finding['source']}")
        evidence = finding.get("evidence")
        if isinstance(evidence, dict):
            for key, value in evidence.items():
                sections.append(f"    {key}: {value}")

    return "\n".join(sections)


class SentinelReasoner:
    """Classify evidence using a local Ollama-hosted model."""

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        self.config = config or {}
        self.logger = logging.getLogger(self.__class__.__name__)

    async def analyze(self, evidence_bundle: Any, state: dict[str, Any] | None = None) -> dict[str, Any]:
        baseline_diff = getattr(evidence_bundle, "baseline_diff", None)
        if baseline_diff is None and isinstance(evidence_bundle, dict):
            baseline_diff = evidence_bundle.get("baseline_diff")
        return await self.reason(evidence_bundle, baseline_diff or [], self.config, state=state)

    async def reason(
        self,
        evidence_bundle: Any,
        baseline_diff: list[dict[str, Any]] | None,
        config: dict[str, Any] | None = None,
        state: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        runtime_config = config or self.config
        findings = self.extract_findings(evidence_bundle)
        actionable_findings = [finding for finding in findings if severity_rank(finding.get("severity")) > severity_rank("info")]

        if not actionable_findings:
            return self._clean_result(findings)

        if control_plane_enabled(runtime_config, require_auth=True):
            remote_result = await self._reason_remote(findings, baseline_diff or [], runtime_config, state=state)
            if remote_result.get("source") == "remote":
                return remote_result
            return await self._reason_local(evidence_bundle, findings, baseline_diff or [], runtime_config)

        return await self._reason_local(evidence_bundle, findings, baseline_diff or [], runtime_config)

    async def _reason_local(
        self,
        evidence_bundle: Any,
        findings: list[dict[str, Any]],
        baseline_diff: list[dict[str, Any]],
        runtime_config: dict[str, Any],
    ) -> dict[str, Any]:
        actionable_findings = [finding for finding in findings if severity_rank(finding.get("severity")) > severity_rank("info")]
        prompt = build_user_prompt(evidence_bundle, baseline_diff, runtime_config)
        llm_config = self._llm_config(runtime_config)

        if not llm_config.get("endpoint") or not llm_config.get("model"):
            self.logger.warning("LLM configuration is incomplete; skipping reasoning")
            return self._error_result("missing_llm_config", findings)

        for attempt in range(2):
            try:
                result = await self._call_ollama(prompt, llm_config)
                normalized = self._normalize_response(result, findings)
                normalized["source"] = "local"
                if normalized["assessment"] == "clean" and actionable_findings:
                    normalized["finding_count"] = len(findings)
                return normalized
            except json.JSONDecodeError as exc:
                self.logger.warning("Failed to parse Ollama JSON response on attempt %d: %s", attempt + 1, exc)
                if attempt == 1:
                    return self._error_result("invalid_llm_json", findings)
            except TimeoutError:
                self.logger.warning("Timed out waiting for Ollama response")
                return self._error_result("timeout", findings)
            except Exception as exc:  # pragma: no cover - defensive integration path
                self.logger.warning("Ollama reasoning failed: %s", exc)
                return self._error_result(str(exc), findings)

        return self._error_result("reasoning_failed", findings)

    async def _reason_remote(
        self,
        findings: list[dict[str, Any]],
        baseline_diff: list[dict[str, Any]],
        runtime_config: dict[str, Any],
        state: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        control_plane = control_plane_config(runtime_config)
        endpoint = f"{str(control_plane.get('url', '')).rstrip('/')}/api/sentinel/evidence"
        # Truncate findings before sending to control plane.
        # Only send actionable findings — not the entire raw process list.
        actionable = [
            f for f in findings
            if str(f.get("severity", "")).lower() in ("high", "critical", "medium")
            or any(t in (f.get("tags") or []) for t in ["deleted_exe", "new_executable", "known_bad_ip"])
        ][:50]
        # Strip large evidence blobs
        truncated = []
        for f in (actionable or findings[:20]):
            fc = dict(f)
            if isinstance(fc.get("evidence"), dict):
                fc["evidence"] = {
                    k: (v[:500] + "...(truncated)" if isinstance(v, str) and len(v) > 500 else v[:10] if isinstance(v, list) and len(v) > 10 else v)
                    for k, v in fc["evidence"].items()
                }
            truncated.append(fc)

        payload = {
            "scan_timestamp": datetime.now(timezone.utc).isoformat(),
            "phase": (state or {}).get("onboarding_phase", "discovery"),
            "findings": truncated,
            "baseline_diff": baseline_diff[:10],
            "finding_count": len(findings),
            "critical_count": sum(1 for finding in findings if str(finding.get("severity", "")).lower() == "critical"),
            "high_count": sum(1 for finding in findings if str(finding.get("severity", "")).lower() == "high"),
        }

        try:
            status_code, response_payload = await request_json(
                "POST",
                endpoint,
                json_body=payload,
                headers={"Authorization": f"Bearer {control_plane.get('auth_token', '')}"},
                timeout_seconds=float(control_plane.get("timeout_seconds", 30)),
            )
        except TimeoutError:
            self.logger.warning("Control plane evidence submission timed out; falling back to local reasoning")
            return self._error_result("timeout", findings)
        except Exception as exc:  # pragma: no cover - integration path
            self.logger.warning("Control plane reasoning failed: %s", exc)
            return self._error_result(str(exc), findings)

        if status_code != 200:
            self.logger.warning("Control plane returned %s for evidence submission; falling back to local reasoning", status_code)
            return self._error_result(f"control_plane_{status_code}", findings)

        if not isinstance(response_payload, dict):
            self.logger.warning("Control plane response was not a JSON object; falling back to local reasoning")
            return self._error_result("invalid_control_plane_response", findings)

        verdict = response_payload.get("verdict", response_payload)
        if not isinstance(verdict, dict):
            self.logger.warning("Control plane verdict payload was invalid; falling back to local reasoning")
            return self._error_result("invalid_control_plane_verdict", findings)

        normalized = self._normalize_remote_response(verdict, findings)
        normalized["source"] = "remote"
        return normalized

    def extract_findings(self, evidence_bundle: Any) -> list[dict[str, Any]]:
        """Flatten collector output into a single list of findings."""
        findings: list[dict[str, Any]] = []

        if isinstance(evidence_bundle, list):
            for item in evidence_bundle:
                normalized = self._normalize_finding(item, None)
                if normalized:
                    findings.append(normalized)
            return findings

        if hasattr(evidence_bundle, "all_findings"):
            all_findings = evidence_bundle.all_findings()
            if isinstance(all_findings, list):
                for item in all_findings:
                    normalized = self._normalize_finding(item, None)
                    if normalized:
                        findings.append(normalized)
                return findings

        evidence = None
        if hasattr(evidence_bundle, "evidence"):
            evidence = getattr(evidence_bundle, "evidence")
        elif isinstance(evidence_bundle, dict):
            evidence = evidence_bundle.get("evidence", evidence_bundle)

        if not isinstance(evidence, dict):
            return findings

        for source_name, payload in evidence.items():
            findings.extend(self._extract_findings_from_payload(payload, source_name))

        return findings

    def _extract_findings_from_payload(self, payload: Any, source_name: str | None) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []

        if isinstance(payload, list):
            for item in payload:
                normalized = self._normalize_finding(item, source_name)
                if normalized:
                    findings.append(normalized)
            return findings

        if isinstance(payload, dict):
            if isinstance(payload.get("findings"), list):
                for item in payload["findings"]:
                    normalized = self._normalize_finding(item, source_name)
                    if normalized:
                        findings.append(normalized)
                return findings

            for key in ("alerts", "matches", "results", "events", "suspicious", "items"):
                value = payload.get(key)
                if isinstance(value, list):
                    for item in value:
                        normalized = self._normalize_finding(item, source_name)
                        if normalized:
                            findings.append(normalized)
                    if findings:
                        return findings

            normalized = self._normalize_finding(payload, source_name)
            if normalized:
                findings.append(normalized)

        return findings

    def _normalize_finding(self, finding: Any, source_name: str | None) -> dict[str, Any] | None:
        if not isinstance(finding, dict):
            return None

        if not any(key in finding for key in ("severity", "description", "category", "detail", "message", "evidence", "tags")):
            return None
        if "status" in finding and "severity" not in finding and "description" not in finding and "detail" not in finding:
            return None

        description = (
            finding.get("description")
            or finding.get("detail")
            or finding.get("message")
            or finding.get("summary")
        )
        if not description:
            return None

        normalized = dict(finding)
        normalized["severity"] = str(finding.get("severity", "info")).lower()
        normalized["category"] = str(finding.get("category") or source_name or "unknown")
        normalized["description"] = str(description)
        if source_name and "source" not in normalized:
            normalized["source"] = source_name
        if "evidence" in normalized and not isinstance(normalized["evidence"], dict):
            normalized["evidence"] = {"value": normalized["evidence"]}
        return normalized

    async def _call_ollama(self, prompt: str, llm_config: dict[str, Any]) -> dict[str, Any]:
        payload = {
            "model": llm_config["model"],
            "prompt": prompt,
            "system": SYSTEM_PROMPT,
            "stream": False,
            "format": "json",
        }
        endpoint = f"{str(llm_config['endpoint']).rstrip('/')}/api/generate"
        timeout_seconds = float(llm_config.get("timeout_seconds", 30))

        response_data = await self._post_json(endpoint, payload, timeout_seconds)
        if not isinstance(response_data, dict):
            raise json.JSONDecodeError("Response payload is not a JSON object", str(response_data), 0)

        error_text = str(response_data.get("error", ""))
        if error_text:
            lower = error_text.lower()
            if "model" in lower and any(token in lower for token in ("not found", "not loaded", "pull")):
                self.logger.warning("Ollama model %s is not loaded: %s", llm_config.get("model"), error_text)
            raise RuntimeError(error_text)

        raw_response = response_data.get("response")
        if isinstance(raw_response, dict):
            return raw_response
        if not isinstance(raw_response, str):
            raise json.JSONDecodeError("Ollama response field was not JSON text", json.dumps(response_data), 0)
        return self._parse_json_text(raw_response)

    async def _post_json(self, endpoint: str, payload: dict[str, Any], timeout_seconds: float) -> dict[str, Any]:
        if httpx is not None:
            try:
                async with httpx.AsyncClient(timeout=timeout_seconds) as client:
                    response = await client.post(endpoint, json=payload)
                    response.raise_for_status()
                    return response.json()
            except httpx.TimeoutException as exc:  # pragma: no cover - integration path
                raise TimeoutError from exc

        return await asyncio.to_thread(self._urllib_post_json, endpoint, payload, timeout_seconds)

    @staticmethod
    def _urllib_post_json(endpoint: str, payload: dict[str, Any], timeout_seconds: float) -> dict[str, Any]:
        request = urllib_request.Request(
            endpoint,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib_request.urlopen(request, timeout=timeout_seconds) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib_error.URLError as exc:  # pragma: no cover - integration path
            if isinstance(getattr(exc, "reason", None), TimeoutError):
                raise TimeoutError from exc
            raise RuntimeError(str(exc)) from exc

    def _normalize_response(self, assessment: dict[str, Any], findings: list[dict[str, Any]]) -> dict[str, Any]:
        level = str(assessment.get("assessment", "clean")).lower()
        if level not in {"critical", "high", "medium", "low", "clean"}:
            level = "clean" if not findings else "low"

        hypotheses_payload = assessment.get("hypotheses", [])
        hypotheses: list[dict[str, Any]] = []
        for raw_hypothesis in hypotheses_payload if isinstance(hypotheses_payload, list) else []:
            if not isinstance(raw_hypothesis, dict):
                continue
            classification = str(raw_hypothesis.get("classification", "benign")).lower()
            confidence = self._coerce_confidence(raw_hypothesis.get("confidence"))
            recommended_actions = self._normalize_actions(raw_hypothesis.get("recommended_actions"))
            hypotheses.append(
                {
                    "description": str(raw_hypothesis.get("description", "No description")),
                    "classification": classification,
                    "confidence": confidence,
                    "evidence_refs": [
                        str(item) for item in raw_hypothesis.get("evidence_refs", []) if item is not None
                    ],
                    "recommended_actions": recommended_actions,
                    "mitre_techniques": [
                        str(item) for item in raw_hypothesis.get("mitre_techniques", []) if item is not None
                    ],
                }
            )

        summary = str(assessment.get("summary") or self._default_summary(level, hypotheses))
        compatibility = self._compatibility_fields(level, hypotheses, findings)
        return {
            "assessment": level,
            "hypotheses": hypotheses,
            "summary": summary,
            "finding_count": len(findings),
            **compatibility,
        }

    def _normalize_remote_response(self, verdict: dict[str, Any], findings: list[dict[str, Any]]) -> dict[str, Any]:
        normalized = self._normalize_response(verdict, findings)
        top_level_actions = self._normalize_actions(verdict.get("actions") or verdict.get("recommended_actions"))
        if top_level_actions:
            normalized["recommended_actions"] = self._merge_actions(
                normalized.get("recommended_actions", []),
                top_level_actions,
            )

        classification = verdict.get("classification")
        if classification:
            normalized["classification"] = self._map_policy_classification(str(classification).lower())
        elif top_level_actions and not normalized.get("classification"):
            normalized["classification"] = "default"

        if "confidence" in verdict:
            normalized["confidence"] = self._coerce_confidence(verdict.get("confidence"))
        elif top_level_actions and not normalized.get("confidence"):
            normalized["confidence"] = 1.0

        incident_ids = verdict.get("incident_ids")
        if isinstance(incident_ids, list):
            normalized["incident_ids"] = [str(item) for item in incident_ids if item is not None]

        if verdict.get("summary"):
            normalized["summary"] = str(verdict["summary"])

        if top_level_actions and not normalized.get("hypotheses"):
            normalized["hypotheses"] = [
                {
                    "description": normalized.get("summary", self._default_summary(normalized["assessment"], [])),
                    "classification": normalized.get("classification", "default"),
                    "confidence": normalized.get("confidence", 0.0),
                    "evidence_refs": [],
                    "recommended_actions": normalized.get("recommended_actions", []),
                    "mitre_techniques": [],
                }
            ]

        return normalized

    def _compatibility_fields(
        self,
        assessment_level: str,
        hypotheses: list[dict[str, Any]],
        findings: list[dict[str, Any]],
    ) -> dict[str, Any]:
        non_benign = [item for item in hypotheses if item.get("classification") != "benign"]
        if not non_benign:
            return {
                "classification": "default",
                "confidence": 0.0,
                "recommended_actions": [],
                "incident_ids": [],
            }

        primary = max(non_benign, key=lambda hypothesis: float(hypothesis.get("confidence", 0.0)))
        policy_classification = self._map_policy_classification(primary.get("classification", "default"))
        incident_ids = [
            f"{self._map_policy_classification(item.get('classification', 'default'))}:{index}"
            for index, item in enumerate(non_benign, start=1)
        ]
        deduped_actions: list[dict[str, Any]] = []
        seen_actions: set[tuple[str, str]] = set()
        for item in non_benign:
            for action in item.get("recommended_actions", []):
                key = (action.get("action", ""), action.get("target", ""))
                if key in seen_actions:
                    continue
                seen_actions.add(key)
                deduped_actions.append(action)

        if assessment_level == "clean" and findings:
            policy_classification = "default"

        return {
            "classification": policy_classification,
            "confidence": float(primary.get("confidence", 0.0)),
            "recommended_actions": deduped_actions,
            "incident_ids": incident_ids,
        }

    def _normalize_actions(self, actions: Any) -> list[dict[str, Any]]:
        normalized: list[dict[str, Any]] = []
        if not isinstance(actions, list):
            return normalized
        for action in actions:
            if not isinstance(action, dict):
                continue
            action_name = str(action.get("action", "")).strip()
            target = action.get("target")
            if not action_name or target is None:
                continue
            normalized_action = {key: value for key, value in action.items() if key not in {"action", "target", "priority"}}
            normalized_action.update(
                {
                    "action": action_name,
                    "target": target,
                    "priority": str(action.get("priority", "medium")).lower(),
                }
            )
            normalized.append(normalized_action)
        return normalized

    @staticmethod
    def _merge_actions(*action_groups: list[dict[str, Any]]) -> list[dict[str, Any]]:
        merged: list[dict[str, Any]] = []
        seen: set[tuple[str, str, str]] = set()
        for group in action_groups:
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

    @staticmethod
    def _coerce_confidence(value: Any) -> float:
        try:
            return max(0.0, min(1.0, float(value)))
        except (TypeError, ValueError):
            return 0.0

    @staticmethod
    def _parse_json_text(raw_response: str) -> dict[str, Any]:
        try:
            parsed = json.loads(raw_response)
        except json.JSONDecodeError as exc:
            match = JSON_PATTERN.search(raw_response)
            if not match:
                raise exc
            parsed = json.loads(match.group(0))
        if not isinstance(parsed, dict):
            raise json.JSONDecodeError("Parsed JSON was not an object", raw_response, 0)
        return parsed

    @staticmethod
    def _map_policy_classification(classification: str) -> str:
        return POLICY_CLASSIFICATION_MAP.get(classification, classification or "default")

    @staticmethod
    def _default_summary(level: str, hypotheses: list[dict[str, Any]]) -> str:
        if level == "clean":
            return "No suspicious activity detected."
        if hypotheses:
            return hypotheses[0].get("description", "Suspicious activity detected.")
        return "Suspicious activity detected."

    @staticmethod
    def _llm_config(config: dict[str, Any]) -> dict[str, Any]:
        if isinstance(config.get("llm"), dict):
            return config["llm"]
        return config

    @staticmethod
    def _sentinel_config(config: dict[str, Any]) -> dict[str, Any]:
        if isinstance(config.get("sentinel"), dict):
            return config["sentinel"]
        return {}

    def _clean_result(self, findings: list[dict[str, Any]]) -> dict[str, Any]:
        return {
            "assessment": "clean",
            "hypotheses": [],
            "summary": "No actionable findings detected.",
            "classification": "default",
            "confidence": 0.0,
            "recommended_actions": [],
            "incident_ids": [],
            "finding_count": len(findings),
            "source": "local",
        }

    def _error_result(self, reason: str, findings: list[dict[str, Any]]) -> dict[str, Any]:
        return {
            "assessment": "error",
            "hypotheses": [],
            "summary": f"Reasoning failed: {reason}",
            "classification": "default",
            "confidence": 0.0,
            "recommended_actions": [],
            "incident_ids": [],
            "finding_count": len(findings),
            "source": "local",
        }


ReasoningEngine = SentinelReasoner
