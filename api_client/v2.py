from __future__ import annotations

from typing import Any

from core.control_plane import request_json


class SentinelV2Client:
    def __init__(
        self,
        base_url: str,
        auth_token: str,
        agent_id: str,
        tenant_id: str,
    ) -> None:
        self.base_url = str(base_url).rstrip("/")
        self.auth_token = str(auth_token)
        self.agent_id = str(agent_id)
        self.tenant_id = str(tenant_id)

    async def submit_incident(self, packet_dict: dict[str, Any]) -> dict[str, Any]:
        payload = dict(packet_dict)
        payload["agent_id"] = self.agent_id
        payload["tenant_id"] = self.tenant_id
        return await self._post("/api/sentinel/v2/incident", payload)

    async def submit_verdict(self, verdict_dict: dict[str, Any]) -> dict[str, Any]:
        payload = dict(verdict_dict)
        payload["agent_id"] = self.agent_id
        payload["tenant_id"] = self.tenant_id
        return await self._post("/api/sentinel/v2/verdict", payload)

    async def send_heartbeat(self, heartbeat: dict[str, Any]) -> dict[str, Any]:
        payload = dict(heartbeat)
        payload["agent_id"] = self.agent_id
        payload["tenant_id"] = self.tenant_id
        return await self._post("/api/sentinel/v2/heartbeat", payload)

    async def replay_journal(
        self,
        entries: list[dict[str, Any]],
        last_checkpoint_seq: int,
    ) -> dict[str, Any]:
        payload = {
            "agent_id": self.agent_id,
            "tenant_id": self.tenant_id,
            "entries": entries,
            "last_checkpoint_seq": last_checkpoint_seq,
        }
        return await self._post("/api/sentinel/v2/journal-replay", payload)

    async def log_action(self, action_dict: dict[str, Any]) -> dict[str, Any]:
        payload = dict(action_dict)
        payload["agent_id"] = self.agent_id
        payload["tenant_id"] = self.tenant_id
        return await self._post("/api/blackdome/sentinel/actions/log", payload)

    async def update_action_status(
        self,
        action_id: str,
        *,
        status: str,
        result: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        payload = {
            "tenant_id": self.tenant_id,
            "agent_id": self.agent_id,
            "status": status,
            "result": result or {},
        }
        return await self._post(f"/api/blackdome/sentinel/actions/{action_id}/status", payload)

    async def ack_command(
        self,
        command_id: str,
        *,
        status: str,
        result: dict[str, Any] | None = None,
        error: str | None = None,
    ) -> dict[str, Any]:
        payload = {
            "tenant_id": self.tenant_id,
            "agent_id": self.agent_id,
            "status": status,
            "result": result or {},
            "error": error,
        }
        return await self._post(f"/api/sentinel/v2/commands/{command_id}/ack", payload)

    async def submit_ioc_promotion(self, ips: list[str], packet_id: str) -> None:
        """Push confirmed hostile IPs to control plane for distribution (best effort)."""
        payload = {
            "ioc_type": "ip",
            "values": [str(ip).strip() for ip in ips if str(ip).strip()],
            "source_packet_id": packet_id,
            "ttl_hours": 168,
            "agent_id": self.agent_id,
            "tenant_id": self.tenant_id,
        }
        if not payload["values"]:
            return
        try:
            await self._post("/api/sentinel/v2/ioc-promote", payload)
        except Exception:
            pass

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self.auth_token}",
            "Content-Type": "application/json",
        }

    async def _post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        status_code, response_payload = await request_json(
            "POST",
            f"{self.base_url}{path}",
            headers=self._headers(),
            json_body=payload,
        )

        if isinstance(response_payload, dict):
            response = dict(response_payload)
        else:
            response = {"payload": response_payload}

        response.setdefault("status_code", status_code)
        return response
