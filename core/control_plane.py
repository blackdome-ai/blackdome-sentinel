"""Control plane helpers shared across the Sentinel runtime."""

from __future__ import annotations

import asyncio
import json
from typing import Any
from urllib import error as urllib_error
from urllib import request as urllib_request

try:  # pragma: no cover - exercised in integration environments
    import httpx
except ImportError:  # pragma: no cover - dependency may be installed later
    httpx = None


def control_plane_config(config: dict[str, Any] | None = None) -> dict[str, Any]:
    """Return the normalized control plane config section."""
    payload = config or {}
    control_plane = payload.get("control_plane")
    if isinstance(control_plane, dict):
        return control_plane

    reporting = payload.get("reporting")
    if isinstance(reporting, dict) and isinstance(reporting.get("control_plane"), dict):
        return reporting["control_plane"]

    return {}


def control_plane_enabled(config: dict[str, Any] | None = None, require_auth: bool = False) -> bool:
    """Check whether the control plane is configured for use."""
    control_plane = control_plane_config(config)
    if not control_plane.get("enabled") or not control_plane.get("url"):
        return False
    if require_auth and not control_plane.get("auth_token"):
        return False
    return True


def control_plane_headers(config: dict[str, Any] | None = None) -> dict[str, str]:
    """Build auth headers for control plane requests."""
    token = str(control_plane_config(config).get("auth_token") or "").strip()
    if not token:
        return {}
    return {"Authorization": f"Bearer {token}"}


async def request_json(
    method: str,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    json_body: dict[str, Any] | None = None,
    timeout_seconds: float = 30.0,
) -> tuple[int, dict[str, Any] | list[Any] | str | None]:
    """Issue a JSON HTTP request with httpx or urllib fallback."""
    if httpx is not None:
        try:
            async with httpx.AsyncClient(timeout=timeout_seconds) as client:
                response = await client.request(method.upper(), url, json=json_body, headers=headers)
        except httpx.TimeoutException as exc:  # pragma: no cover - integration path
            raise TimeoutError from exc
        return response.status_code, _decode_json_text(response.text)

    return await asyncio.to_thread(
        _urllib_request_json,
        method.upper(),
        url,
        headers or {},
        json_body,
        timeout_seconds,
    )


def _urllib_request_json(
    method: str,
    url: str,
    headers: dict[str, str],
    json_body: dict[str, Any] | None,
    timeout_seconds: float,
) -> tuple[int, dict[str, Any] | list[Any] | str | None]:
    request_headers = dict(headers)
    data = None
    if json_body is not None:
        request_headers.setdefault("Content-Type", "application/json")
        data = json.dumps(json_body).encode("utf-8")

    request = urllib_request.Request(url, data=data, headers=request_headers, method=method)
    try:
        with urllib_request.urlopen(request, timeout=timeout_seconds) as response:
            payload = response.read().decode("utf-8")
            return response.status, _decode_json_text(payload)
    except urllib_error.HTTPError as exc:  # pragma: no cover - integration path
        payload = exc.read().decode("utf-8")
        return exc.code, _decode_json_text(payload)
    except urllib_error.URLError as exc:  # pragma: no cover - integration path
        if isinstance(getattr(exc, "reason", None), TimeoutError):
            raise TimeoutError from exc
        raise RuntimeError(str(exc)) from exc


def _decode_json_text(payload: str) -> dict[str, Any] | list[Any] | str | None:
    if not payload:
        return None
    try:
        return json.loads(payload)
    except json.JSONDecodeError:
        return payload
