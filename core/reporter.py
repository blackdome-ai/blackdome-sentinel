"""Console and email reporting for Sentinel scan results."""

from __future__ import annotations

import logging
import os
import socket
from datetime import datetime
from typing import Any

try:  # pragma: no cover - exercised in integration environments
    import httpx
except ImportError:  # pragma: no cover - dependency may be installed later
    httpx = None


async def send_alert(assessment: dict[str, Any], config: dict[str, Any]) -> dict[str, Any]:
    """Send a Postmark alert for high-severity assessments."""
    level = str(assessment.get("assessment", "clean")).lower()
    if level not in ("critical", "high"):
        return {"status": "skipped", "reason": "assessment_below_threshold"}

    report_config = Reporter.reporting_config(config).get("email", {})
    if not report_config.get("enabled"):
        return {"status": "skipped", "reason": "email_disabled"}

    postmark_key = os.environ.get("POSTMARK_API_KEY")
    if not postmark_key:
        return {"status": "skipped", "reason": "missing_postmark_key"}

    if httpx is None:
        return {"status": "skipped", "reason": "httpx_not_installed"}

    hostname = Reporter.hostname(config, assessment)
    subject = f"[BlackDome Sentinel] {level.upper()} - {hostname}"
    body = [
        f"Sentinel detected a {level} threat on {hostname}.",
        "",
        f"Summary: {assessment.get('summary', 'No summary')}",
        "",
    ]

    for hypothesis in assessment.get("hypotheses", []):
        if not isinstance(hypothesis, dict):
            continue
        body.append(
            f"Classification: {hypothesis.get('classification', 'unknown')} "
            f"(confidence: {hypothesis.get('confidence', 0.0)})"
        )
        body.append(f"Description: {hypothesis.get('description', 'No description')}")
        actions = hypothesis.get("recommended_actions", [])
        if actions:
            body.append("Actions:")
            for action in actions:
                body.append(f"  - {action.get('action')} -> {action.get('target')}")
        body.append("")

    async with httpx.AsyncClient(timeout=15.0) as client:
        response = await client.post(
            "https://api.postmarkapp.com/email",
            headers={
                "X-Postmark-Server-Token": postmark_key,
                "Content-Type": "application/json",
            },
            json={
                "From": report_config["from"],
                "To": ", ".join(report_config.get("to", [])),
                "Subject": subject,
                "TextBody": "\n".join(body).rstrip(),
                "Tag": "sentinel-alert",
            },
        )
        response.raise_for_status()

    return {"status": "sent", "subject": subject}


class Reporter:
    """Emit console summaries and optional email alerts."""

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        self.config = config or {}
        self.logger = logging.getLogger(self.__class__.__name__)

    async def report(self, payload: dict[str, Any]) -> dict[str, Any]:
        assessment = self._coerce_assessment(payload)
        console_line = self._build_console_line(payload, assessment)
        print(console_line, flush=True)

        try:
            email_result = await send_alert(assessment, self.config)
        except Exception as exc:  # pragma: no cover - network/runtime path
            self.logger.warning("Failed to send email alert: %s", exc)
            email_result = {"status": "failed", "error": str(exc)}

        return {
            "status": "ok",
            "console_line": console_line,
            "email": email_result,
        }

    def _coerce_assessment(self, payload: dict[str, Any]) -> dict[str, Any]:
        if "assessment" in payload:
            assessment = dict(payload)
        else:
            assessment = {
                "assessment": payload.get("scan_result", "clean"),
                "summary": payload.get("summary", "No summary"),
                "hypotheses": payload.get("hypotheses", []),
            }
        assessment.setdefault("summary", "No summary")
        assessment.setdefault("hypotheses", [])
        assessment.setdefault("hostname", payload.get("hostname"))
        return assessment

    def _build_console_line(self, payload: dict[str, Any], assessment: dict[str, Any]) -> str:
        timestamp = payload.get("scan_timestamp") or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if isinstance(timestamp, str):
            try:
                timestamp = datetime.fromisoformat(timestamp.replace("Z", "+00:00")).strftime("%Y-%m-%d %H:%M:%S")
            except ValueError:
                pass
        collector_count = int(payload.get("collector_count", 0))
        finding_count = int(payload.get("finding_count", 0))
        action_count = len(payload.get("approved_actions", []))
        level = str(assessment.get("assessment", "clean")).upper()
        source = str(payload.get("reasoning_source") or assessment.get("source") or "local").lower()

        detail = ""
        hypotheses = assessment.get("hypotheses", [])
        if hypotheses:
            primary = hypotheses[0]
            if isinstance(primary, dict) and primary.get("classification"):
                detail = f"{primary['classification']} detected"
        if not detail and assessment.get("summary") and level != "CLEAN":
            detail = str(assessment["summary"])

        parts = [
            "[SENTINEL]",
            timestamp,
            "|",
            level,
            "|",
            f"{collector_count} collectors",
            "|",
            f"{finding_count} findings",
        ]
        if detail:
            parts.extend(["|", detail])
        if action_count == 1:
            parts.extend(["|", "1 action auto-approved"])
        elif action_count > 1:
            parts.extend(["|", f"{action_count} actions auto-approved"])
        else:
            parts.extend(["|", "0 actions"])
        parts.extend(["|", f"source={source}"])
        return " ".join(parts)

    @staticmethod
    def reporting_config(config: dict[str, Any]) -> dict[str, Any]:
        if isinstance(config.get("reporting"), dict):
            return config["reporting"]
        return config

    @staticmethod
    def hostname(config: dict[str, Any], payload: dict[str, Any] | None = None) -> str:
        if payload and payload.get("hostname"):
            return str(payload["hostname"])
        sentinel_config = config.get("sentinel", {}) if isinstance(config, dict) else {}
        if isinstance(sentinel_config, dict) and sentinel_config.get("hostname"):
            return str(sentinel_config["hostname"])
        return socket.gethostname()
