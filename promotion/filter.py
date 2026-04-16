from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Iterable

from collectors.process_scanner import ProcessScanner
from events.event import RawEvent


@dataclass(slots=True)
class PromotionResult:
    action: str
    event: RawEvent
    reason: str
    matched_ioc: str | None = None


class PromotionFilter:
    _kernel_thread_prefixes = (
        "softirq",
        "ksoftirqd",
        "kworker",
        "kthreadd",
        "migration",
        "rcu_sched",
        "watchdog",
    )
    _untrusted_exec_prefixes = ("/tmp/", "/var/tmp/", "/dev/shm/", "/run/user/")
    _mining_pool_ports = {3333, 4444, 5555, 8333, 14433, 14444, 45700}

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

        proc_name = self._extract_proc_name(event)
        if proc_name is not None and proc_name.lower() in ProcessScanner.suspicious_names:
            return PromotionResult(
                action="kill",
                event=event,
                reason=f"process name matched known-bad: {proc_name}",
                matched_ioc=proc_name,
            )

        if (
            proc_name is not None
            and exe_path is not None
            and self._is_kernel_thread_impersonation(proc_name, exe_path)
        ):
            return PromotionResult(
                action="kill",
                event=event,
                reason=f"kernel name impersonation: {proc_name} at {exe_path}",
                matched_ioc=proc_name,
            )

        if (
            binary_hash not in self._baseline_hashes
            and exe_path is not None
            and self._is_untrusted_exec_path(exe_path)
        ):
            return PromotionResult(
                action="kill",
                event=event,
                reason=f"untrusted executable not in baseline: {exe_path}",
                matched_ioc=exe_path,
            )

        dest_port = self._extract_dest_port(event)
        if dest_port in self._mining_pool_ports:
            return PromotionResult(
                action="kill",
                event=event,
                reason=f"outbound to mining pool port {dest_port}",
                matched_ioc=str(dest_port),
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
    def _extract_proc_name(event: RawEvent) -> str | None:
        for field_name in ("name", "comm", "process_name"):
            value = event.subject.get(field_name)
            if isinstance(value, str) and value:
                return value
        return None

    @staticmethod
    def _extract_dest_ip(event: RawEvent) -> str | None:
        for source in (event.object, event.metadata):
            dest_ip = source.get("dest_ip")
            if isinstance(dest_ip, str) and dest_ip:
                return dest_ip
        return None

    @staticmethod
    def _extract_dest_port(event: RawEvent) -> int | None:
        for source in (event.object, event.metadata):
            value = source.get("dest_port")
            if isinstance(value, bool):
                continue
            if isinstance(value, int):
                return value
            if isinstance(value, str):
                stripped = value.strip()
                if stripped.isdigit():
                    return int(stripped)
        return None

    @classmethod
    def _is_kernel_thread_impersonation(cls, proc_name: str, exe_path: str) -> bool:
        normalized_name = proc_name.strip().lower()
        normalized_path = exe_path.strip()
        if not normalized_name or not normalized_path:
            return False
        if not normalized_name.startswith(cls._kernel_thread_prefixes):
            return False
        return not (normalized_path.startswith("[") and normalized_path.endswith("]"))

    @classmethod
    def _is_untrusted_exec_path(cls, exe_path: str) -> bool:
        normalized_path = exe_path.removesuffix(" (deleted)")
        return any(normalized_path.startswith(prefix) for prefix in cls._untrusted_exec_prefixes)

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
