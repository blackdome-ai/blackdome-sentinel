"""Model gate — runs smarts audit at startup and disables local LLM if it fails."""

from __future__ import annotations

import json
import logging
import subprocess
import sys
from pathlib import Path


log = logging.getLogger("sentinel.model_gate")
PROJECT_ROOT = Path(__file__).resolve().parent.parent
AUDIT_SCRIPT = PROJECT_ROOT / "scripts" / "llm_smarts_audit.py"
RESULTS_PATH = PROJECT_ROOT / "state" / "model_audit_results.json"


def _load_cached_results() -> dict | None:
    if not RESULTS_PATH.exists():
        return None
    try:
        payload = json.loads(RESULTS_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def check_model(model: str) -> bool:
    """Run smarts audit. Returns True if model passes, False if it should be disabled."""
    cached = _load_cached_results()
    if cached and cached.get("model") == model and cached.get("approved") is not None:
        approved = bool(cached["approved"])
        log.info(
            "Using cached audit result for %s: %s",
            model,
            "APPROVED" if approved else "REJECTED",
        )
        return approved

    if not AUDIT_SCRIPT.exists():
        log.error("Audit script missing: %s", AUDIT_SCRIPT)
        return False

    RESULTS_PATH.parent.mkdir(parents=True, exist_ok=True)
    log.info("Running smarts audit for model %s...", model)

    try:
        result = subprocess.run(
            [sys.executable, str(AUDIT_SCRIPT), "--model", model, "--output", str(RESULTS_PATH)],
            capture_output=True,
            text=True,
            timeout=600,
            check=False,
        )
    except subprocess.TimeoutExpired:
        log.error("Audit timed out for %s", model)
        return False
    except Exception as exc:
        log.error("Audit error for %s: %s", model, exc)
        return False

    if result.returncode != 0:
        stderr = result.stderr.strip()[:500]
        stdout = result.stdout.strip()[:500]
        log.error("Audit script failed for %s: %s", model, stderr or stdout or "no output")
        return False

    data = _load_cached_results()
    if not data:
        log.error("Audit script completed for %s but did not write parsable results", model)
        return False

    approved = bool(data.get("approved", False))
    log.info(
        "Audit result for %s: %s/%s — %s",
        model,
        data.get("passed", 0),
        data.get("total", 0),
        "APPROVED" if approved else "REJECTED",
    )
    return approved
