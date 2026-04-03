"""Network activity scanner."""

from __future__ import annotations

import re
from pathlib import Path

from .base import BaseCollector


class NetworkScanner(BaseCollector):
    name = "network_scanner"
    default_bad_ips = {"45.125.66.100", "45.94.31.89"}
    mining_ports = {"3333", "4444", "5555", "8333", "14433", "45700"}
    listener_pattern = re.compile(
        r"^(?P<state>\S+)\s+"
        r"(?P<recv_q>\S+)\s+"
        r"(?P<send_q>\S+)\s+"
        r"(?P<local_address>\S+)\s+"
        r"(?P<remote_address>\S+)"
        r"(?:\s+(?P<process_field>.+))?$"
    )
    established_pattern = re.compile(
        r"^(?P<recv_q>\S+)\s+"
        r"(?P<send_q>\S+)\s+"
        r"(?P<local_address>\S+)\s+"
        r"(?P<remote_address>\S+)"
        r"(?:\s+(?P<process_field>.+))?$"
    )

    async def collect(self) -> dict:
        try:
            return await self.run_in_thread(self._collect_sync)
        except Exception as exc:  # pragma: no cover - defensive path
            self.logger.exception("Network scanner failed")
            return self.build_error_result(str(exc))

    def _collect_sync(self) -> dict:
        baseline = self.load_baseline()
        baseline_listeners = set(baseline.get("listening_ports", [])) if baseline else set()
        configured_bad_ips = set(self.collector_config.get("known_bad_ips", [])) or set(self.default_bad_ips)
        hostile_feed_ips = self.load_hostile_ips()
        known_bad_ips = configured_bad_ips | hostile_feed_ips
        known_bad_domains = set(self.collector_config.get("known_bad_domains", []))

        established_result = self.run_command(["ss", "-tnpH", "state", "established"])
        listening_result = self.run_command(["ss", "-tlnpH"])

        established = self._parse_ss_output(established_result["stdout"], default_state="ESTAB")
        listeners = self._parse_ss_output(listening_result["stdout"], default_state="LISTEN")

        findings = []
        bad_ip_hits = []
        mining_port_hits = []
        new_listeners = []

        for connection in established:
            remote_host = connection.get("remote_host")
            if remote_host in known_bad_ips:
                bad_ip_hits.append(connection)
                findings.append(
                    {
                        "severity": "critical",
                        "category": "network",
                        "description": f"Established connection to hostile IP: {remote_host}",
                        "evidence": connection,
                        "tags": ["known_bad_ip", "hostile_feed" if remote_host in hostile_feed_ips else "configured_bad_ip"],
                    }
                )
            if connection.get("remote_port") in self.mining_ports and not self.process_names_whitelisted(connection.get("process_names", [])):
                mining_port_hits.append(connection)
                findings.append(
                    {
                        "severity": "high",
                        "category": "network",
                        "description": f"Connection to common mining port {connection['remote_port']}: {connection['remote_address']}",
                        "evidence": connection,
                        "tags": ["mining_pool_port"],
                    }
                )

        if baseline_listeners:
            for listener in listeners:
                listener_key = f"{listener['netid']}:{listener['local_address']}"
                if listener_key not in baseline_listeners and not self.process_names_whitelisted(listener.get("process_names", [])):
                    new_listeners.append(listener)
                    findings.append(
                        {
                            "severity": "medium",
                            "category": "network",
                            "description": f"Listening socket not present in baseline: {listener['local_address']}",
                            "evidence": listener,
                            "tags": ["new_listener"],
                        }
                    )

        dns_hits = self._scan_dns_hits(known_bad_domains)
        for hit in dns_hits:
            findings.append(
                {
                    "severity": "high",
                    "category": "network",
                    "description": f"DNS query matched known bad domain: {hit['domain']}",
                    "evidence": hit,
                    "tags": ["known_bad_domain"],
                }
            )

        raw = {
            "established_connections": established,
            "listening_ports": listeners,
            "known_bad_ip_hits": bad_ip_hits,
            "mining_port_hits": mining_port_hits,
            "new_listeners": new_listeners,
            "dns_hits": dns_hits,
            "hostile_feed_ips": sorted(hostile_feed_ips),
        }
        return self.build_result(findings, raw=raw)

    def _parse_ss_output(self, output: str, default_state: str) -> list[dict]:
        entries = []
        for line in output.splitlines():
            stripped = line.strip()
            if not stripped:
                continue

            listener_match = self.listener_pattern.match(stripped)
            if listener_match and listener_match.group("state") in {"LISTEN", "ESTAB", "SYN-SENT", "SYN-RECV"}:
                state = listener_match.group("state")
                recv_q = listener_match.group("recv_q")
                send_q = listener_match.group("send_q")
                local_address = listener_match.group("local_address")
                remote_address = listener_match.group("remote_address")
                process_field = listener_match.group("process_field") or ""
            else:
                established_match = self.established_pattern.match(stripped)
                if not established_match:
                    continue
                state = default_state
                recv_q = established_match.group("recv_q")
                send_q = established_match.group("send_q")
                local_address = established_match.group("local_address")
                remote_address = established_match.group("remote_address")
                process_field = established_match.group("process_field") or ""

            local_host, local_port = self._split_address(local_address)
            remote_host, remote_port = self._split_address(remote_address)
            process_names = re.findall(r'"([^"]+)"', process_field)
            pid_match = re.search(r"pid=(\d+)", process_field)
            entries.append(
                {
                    "netid": "tcp",
                    "state": state,
                    "recv_q": recv_q,
                    "send_q": send_q,
                    "local_address": local_address,
                    "local_host": local_host,
                    "local_port": local_port,
                    "remote_address": remote_address,
                    "remote_host": remote_host,
                    "remote_port": remote_port,
                    "pid": int(pid_match.group(1)) if pid_match else None,
                    "process_names": process_names,
                }
            )
        return entries

    @staticmethod
    def _split_address(value: str) -> tuple[str, str]:
        cleaned = value.strip()
        if cleaned.startswith("[") and "]:" in cleaned:
            host, _, port = cleaned[1:].partition("]:")
            return NetworkScanner._normalize_host(host), port
        if cleaned.count(":") > 1 and cleaned.rsplit(":", 1)[1].isdigit():
            host, port = cleaned.rsplit(":", 1)
            return NetworkScanner._normalize_host(host), port
        if ":" in cleaned:
            host, port = cleaned.rsplit(":", 1)
            return NetworkScanner._normalize_host(host), port
        return NetworkScanner._normalize_host(cleaned), ""

    @staticmethod
    def _normalize_host(value: str) -> str:
        host = value.strip("[]")
        if host.startswith("::ffff:"):
            host = host.split("::ffff:", 1)[1]
        if "%" in host:
            host = host.split("%", 1)[0]
        return host

    def _scan_dns_hits(self, domains: set[str]) -> list[dict]:
        if not domains:
            return []
        syslog_path = Path("/var/log/syslog")
        if not syslog_path.exists():
            return []
        syslog_result = self.run_command(["tail", "-n", "2000", str(syslog_path)])
        hits = []
        for line in syslog_result["stdout"].splitlines():
            for domain in domains:
                if domain not in line:
                    continue
                hits.append({"domain": domain, "line": line})
        return hits
