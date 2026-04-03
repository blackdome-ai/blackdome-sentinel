from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Iterable

from events.event import RawEvent


@dataclass(slots=True)
class PromotionResult:
    action: str
    event: RawEvent
    reason: str
    matched_ioc: str | None = None


class PromotionFilter:
    def __init__(
        self,
        baseline_hashes: set[str],
        malware_hashes: set[str],
        hostile_ips: set[str],
    ) -> None:
        self._baseline_hashes = set(baseline_hashes)
        self._malware_hashes = set(malware_hashes)
        self._hostile_ips = set(hostile_ips)

    def evaluate(self, event: RawEvent) -> PromotionResult:
        exe_path = self._extract_exe_path(event)
        binary_hash = self._hash_binary(exe_path) if exe_path is not None else None

        if binary_hash in self._baseline_hashes:
            return PromotionResult(
                action="log",
                event=event,
                reason="binary hash matched baseline",
                matched_ioc=binary_hash,
            )

        if binary_hash in self._malware_hashes:
            return PromotionResult(
                action="kill",
                event=event,
                reason="binary hash matched malware IOC",
                matched_ioc=binary_hash,
            )

        dest_ip = self._extract_dest_ip(event)
        if dest_ip in self._hostile_ips:
            return PromotionResult(
                action="block",
                event=event,
                reason="destination IP matched hostile IOC",
                matched_ioc=dest_ip,
            )

        return PromotionResult(
            action="promote",
            event=event,
            reason="no baseline or IOC match",
            matched_ioc=None,
        )

    def update_baseline(self, hashes: Iterable[str]) -> None:
        self._baseline_hashes.update(hashes)

    def update_malware_hashes(self, hashes: Iterable[str]) -> None:
        self._malware_hashes.update(hashes)

    def update_hostile_ips(self, ips: Iterable[str]) -> None:
        self._hostile_ips.update(ips)

    @staticmethod
    def _extract_exe_path(event: RawEvent) -> str | None:
        exe_path = event.object.get("exe_path")
        if isinstance(exe_path, str) and exe_path:
            return exe_path

        binary = event.subject.get("binary")
        if isinstance(binary, str) and binary.startswith("/"):
            return binary

        return None

    @staticmethod
    def _extract_dest_ip(event: RawEvent) -> str | None:
        for source in (event.object, event.metadata):
            dest_ip = source.get("dest_ip")
            if isinstance(dest_ip, str) and dest_ip:
                return dest_ip
        return None

    @staticmethod
    def _hash_binary(exe_path: str) -> str | None:
        path = Path(exe_path)
        if not path.is_file():
            return None

        digest = sha256()

        try:
            with path.open("rb") as handle:
                for chunk in iter(lambda: handle.read(8192), b""):
                    digest.update(chunk)
        except OSError:
            return None

        return digest.hexdigest()
