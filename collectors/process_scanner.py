"""Process scanner with /proc-backed evidence gathering."""

from __future__ import annotations

import os
import pwd
import time
from pathlib import Path

from .base import BaseCollector


def _name_entropy(name: str) -> float:
    """Shannon entropy of a string. Random binary names like 'boyl7molon' score high."""
    import math
    if not name:
        return 0.0
    freq: dict[str, int] = {}
    for ch in name:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(name)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


class ProcessScanner(BaseCollector):
    name = "process_scanner"
    suspicious_names = {
        "softirq", "xmrig", "ccminer", "minerd", "kinsing", "rondo",
        "ilwclin", "agjajrtwr", "boyl7molon",
    }
    temp_roots = ("/tmp", "/var/tmp", "/dev/shm")
    high_cpu_threshold = 50.0
    # Random binary names in temp dirs with entropy > 2.4 and length 6-20 are suspicious
    ENTROPY_THRESHOLD = 2.4
    ENTROPY_MIN_LEN = 6
    ENTROPY_MAX_LEN = 20

    async def collect(self) -> dict:
        try:
            return await self.run_in_thread(self._collect_sync)
        except Exception as exc:  # pragma: no cover - defensive path
            self.logger.exception("Process scanner failed")
            return self.build_error_result(str(exc))

    def _collect_sync(self) -> dict:
        baseline = self.load_baseline()
        baseline_processes = set(baseline.get("running_processes", [])) if baseline else set()
        known_malware_hashes = self.known_malware_hashes()

        first_total = self._read_total_cpu_ticks()
        first_ticks = {pid: ticks for pid in self._iter_pids() if (ticks := self._read_process_ticks(pid)) is not None}
        time.sleep(0.2)
        second_total = self._read_total_cpu_ticks()
        total_delta = max(1, second_total - first_total)

        processes = []
        process_signatures = []
        for pid in self._iter_pids():
            process_info = self._read_process_info(pid, first_ticks.get(pid), total_delta)
            if not process_info:
                continue
            processes.append(process_info)
            process_signatures.append(process_info["signature"])

        immutable_flags = self.list_immutable_flags(
            [process["exe"] for process in processes if process.get("exe") and "(deleted)" not in process["exe"]]
        )

        findings = []
        deleted_executables = []
        high_cpu_processes = []
        suspicious_processes = []
        temp_path_processes = []
        immutable_processes = []
        known_hash_hits = []

        for process in processes:
            name_lc = process["name"].lower()
            exe_path = process.get("exe", "")
            exe_name_lc = Path(exe_path.removesuffix(" (deleted)")).name.lower() if exe_path else ""
            exe_whitelisted = self.process_exe_whitelisted(exe_path)

            if known_malware_hashes and exe_path and "(deleted)" not in exe_path:
                exe_hash = self.sha256_file(exe_path)
                if exe_hash and exe_hash.lower() in known_malware_hashes:
                    hit = {
                        "pid": process["pid"],
                        "name": process["name"],
                        "exe": exe_path,
                        "sha256": exe_hash,
                    }
                    known_hash_hits.append(hit)
                    findings.append(
                        {
                            "severity": "critical",
                            "category": "process",
                            "description": f"Process executable matches known malware hash: PID {process['pid']} {exe_path}",
                            "evidence": hit,
                            "tags": ["known_malware_hash"],
                        }
                    )

            if exe_path.endswith(" (deleted)") and not self.deleted_exe_ignored(exe_path):
                deleted_executables.append(process)
                findings.append(
                    {
                        "severity": "critical",
                        "category": "process",
                        "description": f"Deleted executable running: PID {process['pid']} {exe_path}",
                        "evidence": {
                            "pid": process["pid"],
                            "exe": exe_path,
                            "cpu": process["cpu_percent"],
                            "user": process["user"],
                        },
                        "tags": ["deleted_exe"],
                    }
                )

            if not exe_whitelisted and (name_lc in self.suspicious_names or exe_name_lc in self.suspicious_names):
                suspicious_processes.append(process)
                findings.append(
                    {
                        "severity": "critical",
                        "category": "process",
                        "description": f"Suspicious process name detected: PID {process['pid']} {process['name']}",
                        "evidence": {
                            "pid": process["pid"],
                            "name": process["name"],
                            "exe": exe_path,
                            "cpu": process["cpu_percent"],
                        },
                        "tags": ["suspicious_name"],
                    }
                )

            if process["cpu_percent"] > self.high_cpu_threshold and not exe_whitelisted and not self.high_cpu_ignored(process["name"]):
                high_cpu_processes.append(process)
                findings.append(
                    {
                        "severity": "medium",
                        "category": "process",
                        "description": f"High CPU process detected: PID {process['pid']} {process['name']} using {process['cpu_percent']}% CPU",
                        "evidence": {
                            "pid": process["pid"],
                            "name": process["name"],
                            "exe": exe_path,
                            "cpu": process["cpu_percent"],
                        },
                        "tags": ["high_cpu"],
                    }
                )

            if exe_path and self._is_temp_path(exe_path) and not exe_whitelisted:
                temp_path_processes.append(process)
                # Check for random-looking binary name (entropy-based detection)
                bin_name = Path(exe_path.removesuffix(" (deleted)")).name
                entropy = _name_entropy(bin_name)
                is_high_entropy = (
                    self.ENTROPY_MIN_LEN <= len(bin_name) <= self.ENTROPY_MAX_LEN
                    and entropy > self.ENTROPY_THRESHOLD
                    and not bin_name.startswith(("python", "node", "npm", "pip", "uv", "test_", "tmp", "codex", "claude"))
                )
                severity = "critical" if is_high_entropy else "high"
                tags = ["temp_executable"]
                if is_high_entropy:
                    tags.append("high_entropy_name")
                findings.append(
                    {
                        "severity": severity,
                        "category": "process",
                        "description": f"Process executing from temp path: PID {process['pid']} {exe_path}"
                                       + (f" (high-entropy name: {entropy:.2f} bits)" if is_high_entropy else ""),
                        "evidence": {
                            "pid": process["pid"],
                            "exe": exe_path,
                            "user": process["user"],
                            "cpu": process["cpu_percent"],
                            "name_entropy": round(entropy, 2),
                        },
                        "tags": tags,
                    }
                )

            if exe_path and exe_path in immutable_flags and not exe_whitelisted:
                immutable_processes.append({"process": process, "attributes": immutable_flags[exe_path]})
                findings.append(
                    {
                        "severity": "high" if self._is_temp_path(exe_path) else "medium",
                        "category": "process",
                        "description": f"Process executable has immutable attributes: PID {process['pid']} {exe_path}",
                        "evidence": {
                            "pid": process["pid"],
                            "exe": exe_path,
                            "attributes": immutable_flags[exe_path],
                        },
                        "tags": ["immutable_binary"],
                    }
                )

        raw = {
            "all_processes": processes,
            "deleted_executables": deleted_executables,
            "high_cpu": high_cpu_processes,
            "known_bad_name_matches": suspicious_processes,
            "temp_path_processes": temp_path_processes,
            "immutable_executables": immutable_processes,
            "known_malware_hash_hits": known_hash_hits,
            "new_processes_since_baseline": sorted(
                signature for signature in process_signatures if signature not in baseline_processes and not self.kernel_process_ignored(signature)
            ) if baseline_processes else [],
        }
        return self.build_result(findings, raw=raw)

    @staticmethod
    def _iter_pids() -> list[int]:
        proc_dir = Path("/proc")
        return sorted(int(path.name) for path in proc_dir.iterdir() if path.is_dir() and path.name.isdigit())

    @staticmethod
    def _read_total_cpu_ticks() -> int:
        first_line = Path("/proc/stat").read_text(encoding="utf-8").splitlines()[0]
        return sum(int(value) for value in first_line.split()[1:])

    @staticmethod
    def _read_process_ticks(pid: int) -> int | None:
        stat_path = Path(f"/proc/{pid}/stat")
        try:
            content = stat_path.read_text(encoding="utf-8")
        except OSError:
            return None
        end = content.rfind(")")
        fields = content[end + 2 :].split()
        if len(fields) < 13:
            return None
        try:
            utime = int(fields[11])
            stime = int(fields[12])
        except ValueError:
            return None
        return utime + stime

    def _read_process_info(self, pid: int, first_ticks: int | None, total_delta: int) -> dict | None:
        status_path = Path(f"/proc/{pid}/status")
        cmdline_path = Path(f"/proc/{pid}/cmdline")
        exe_path = Path(f"/proc/{pid}/exe")

        try:
            status_lines = status_path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return None

        status_data = {}
        for line in status_lines:
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            status_data[key] = value.strip()

        name = status_data.get("Name", str(pid))
        ppid = int(status_data.get("PPid", "0"))
        uid = int(status_data.get("Uid", "0\t0\t0\t0").split()[0])
        try:
            user = pwd.getpwuid(uid).pw_name
        except KeyError:
            user = str(uid)

        try:
            exe = os.readlink(exe_path)
        except OSError:
            exe = ""

        try:
            cmdline_raw = cmdline_path.read_bytes()
            cmdline = cmdline_raw.replace(bytes([0]), b" ").decode("utf-8", errors="replace").strip()
        except OSError:
            cmdline = ""

        second_ticks = self._read_process_ticks(pid)
        if second_ticks is None:
            return None
        cpu_percent = 0.0
        if first_ticks is not None:
            cpu_percent = round(max(0, second_ticks - first_ticks) / total_delta * (os.cpu_count() or 1) * 100, 2)

        signature = f"{name} {cmdline}".strip() if cmdline else name
        return {
            "pid": pid,
            "name": name,
            "exe": exe,
            "cpu_percent": cpu_percent,
            "user": user,
            "ppid": ppid,
            "cmdline": cmdline,
            "signature": signature,
        }

    def _is_temp_path(self, path_value: str) -> bool:
        normalized = path_value.removesuffix(" (deleted)")
        return any(normalized.startswith(prefix) for prefix in self.temp_roots)
