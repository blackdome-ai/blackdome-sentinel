"""Ed25519 signature verification for control plane commands."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

from nacl.encoding import Base64Encoder
from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey


log = logging.getLogger("sentinel.verify")


class SignatureVerifier:
    """Verify signed control-plane payloads with an Ed25519 public key."""

    def __init__(self, public_key_b64: str, *, last_nonce: int = 0, agent_id: str | None = None) -> None:
        key_material = str(public_key_b64 or "").strip()
        if not key_material:
            raise ValueError("signing public key is required")
        self._verify_key = VerifyKey(key_material.encode("utf-8"), encoder=Base64Encoder)
        self._last_nonce = int(last_nonce)
        self._agent_id = str(agent_id).strip() if agent_id else None

    @property
    def last_nonce(self) -> int:
        return self._last_nonce

    def verify_signed_payload(self, payload: dict[str, Any]) -> bool:
        """Verify only the detached Ed25519 signature on a payload."""
        sig_field = str(payload.get("signature") or "")
        if not sig_field.startswith("ed25519:"):
            log.warning("Rejected unsigned payload")
            return False

        sig_b64 = sig_field[len("ed25519:") :].strip()
        canonical = self._canonical_bytes(payload)
        try:
            signature_bytes = Base64Encoder.decode(sig_b64.encode("utf-8"))
            self._verify_key.verify(canonical, signature_bytes)
        except (BadSignatureError, ValueError, TypeError):
            log.warning("Rejected payload with invalid signature")
            return False
        return True

    def verify_action(self, envelope: dict[str, Any], *, expected_agent_id: str | None = None) -> bool:
        """Verify a signed action envelope from the control plane."""
        if not self.verify_signed_payload(envelope):
            return False

        agent_id = str(envelope.get("agent_id") or "").strip()
        required_agent_id = str(expected_agent_id or self._agent_id or "").strip()
        if required_agent_id and agent_id != required_agent_id:
            log.warning("Rejected action for wrong agent_id: got=%s expected=%s", agent_id, required_agent_id)
            return False

        expires = str(envelope.get("expires_at") or "").strip()
        if expires:
            try:
                expires_at = datetime.fromisoformat(expires.replace("Z", "+00:00"))
            except ValueError:
                log.warning("Rejected action with invalid expires_at: %s", expires)
                return False
            if datetime.now(timezone.utc) > expires_at:
                log.warning("Rejected expired action: %s", envelope.get("action"))
                return False

        try:
            nonce = int(envelope.get("nonce", 0))
        except (TypeError, ValueError):
            log.warning("Rejected action with invalid nonce: %r", envelope.get("nonce"))
            return False
        if nonce <= self._last_nonce:
            log.warning("Rejected stale nonce %d (last=%d)", nonce, self._last_nonce)
            return False

        self._last_nonce = nonce
        return True

    def verify_feed(self, feed_data: dict[str, Any]) -> bool:
        """Verify a signed feed update such as hostile IPs or TTP patterns."""
        return self.verify_signed_payload(feed_data)

    @staticmethod
    def _canonical_bytes(payload: dict[str, Any]) -> bytes:
        canonical = json.dumps(
            {key: value for key, value in payload.items() if key != "signature"},
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        )
        return canonical.encode("utf-8")
