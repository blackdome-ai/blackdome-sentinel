# BlackDome Sentinel

AI-powered host security agent with LLM reasoning, event-driven detection, and integrated deception.

Sentinel monitors Linux servers for threats using a combination of real-time event collection, lightweight deception (host canaries and fake services), and LLM-based reasoning. Unlike signature-based tools, Sentinel reasons about what it sees — detecting unknown threats that don't match any existing pattern.

## How It Works

```
Events (proc/inotify) → Promotion Filter → Micro-Batcher → LLM Reasoning → Action
                              ↓                                    ↑
                     Known-bad hash → KILL              Vector memory recall
                     Known hostile IP → BLOCK           (learns from past incidents)
                     Known-good → LOG
                     Everything else → LLM decides
```

**Three-rule promotion filter** — only mathematically certain decisions are made without the LLM. Known malware hash? Kill instantly. Known hostile IP? Block. Known-good baseline? Log. Everything else goes to the LLM for reasoning.

**Micro-batching** — related events are collected into 15-60 second incident windows before LLM analysis. "Download + chmod + execute + outbound connection" becomes one coherent packet, not four separate alerts.

**Dedup** — the same event fingerprint isn't re-analyzed for 6 hours. No alert fatigue from recurring benign patterns.

**Host deception** — every Sentinel agent plants canary files (fake credentials, SSH keys) and runs lightweight facades on unused ports. If anything touches a canary or connects to a fake service, that's a compromise indicator with zero false positive rate.

## Quick Start

### Managed (Sentinel Pro)

Sign up at [blackdome.ai](https://blackdome.ai), get your API key, then:

```bash
curl -sSL -H "Authorization: Bearer YOUR_API_KEY" \
    https://blackdome.ai/api/blackdome/install/sentinel | sudo bash
```

The agent enrolls with the BlackDome control plane, starts collecting events, and sends incidents for LLM analysis. You'll see results in your dashboard within minutes.

### Self-Hosted (Community)

Clone and configure manually:

```bash
git clone https://github.com/blackdome-ai/blackdome-sentinel.git /opt/blackdome-sentinel
cd /opt/blackdome-sentinel
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp sentinel.yml.example sentinel.yml
# Edit sentinel.yml with your settings
```

Community mode runs deterministic detection only (three-rule filter). LLM reasoning, vector memory, governance, and proof packs require the managed control plane.

## Requirements

- Linux (Ubuntu 20.04+, Debian 11+, RHEL 8+)
- Python 3.10+
- Root access
- `inotify-tools` (`apt install inotify-tools`)
- Outbound HTTPS to `sentinel.blackdome.ai` (managed mode)

## What Sentinel Detects

| Threat | How |
|--------|-----|
| **Malware execution** | Known hash → instant kill. Unknown binary → LLM analysis with process tree, network context, parent lineage |
| **Crypto miners** | Process behavior + network connections to mining pools + persistence mechanisms |
| **Rootkits** | Modified system binaries, hidden processes, kernel module loading |
| **Lateral movement** | Internal IP probing facades → attacker is already on your network |
| **Credential harvesting** | Canary files accessed → someone is reading fake credentials on your server |
| **Persistence** | Crontab, systemd, rc.local, init.d, bashrc changes detected and analyzed |
| **Port scanning** | Facades on unused ports detect per-host reconnaissance |
| **Reverse shells** | Outbound connections with stdin/stdout redirection |
| **Supply chain attacks** | curl\|bash, wget+chmod+exec, base64+exec patterns |

## Architecture

```
/opt/blackdome-sentinel/
├── sentinel_v2.py          # Main event-driven daemon
├── sentinel.yml            # Per-host configuration
├── events/                 # Event collectors (proc, inotify, auditd)
├── promotion/              # Three-rule deterministic filter
├── batcher/                # Micro-batching (15-60s incident windows)
├── dedup/                  # Fingerprint + cooldown engine
├── deception/
│   ├── canaries.py         # Fake credentials, SSH keys, AWS creds
│   └── facades.py          # Lightweight fake services on unused ports
├── cadence/
│   ├── heartbeat.py        # Operational health (1-5 min)
│   ├── reconciliation.py   # Safety net scan (15-30 min)
│   └── deep_audit.py       # Full baseline audit (6-24h)
├── api_client/             # Control plane communication
├── actuators/              # Bounded actions (kill, quarantine, block)
├── core/                   # Baseline, journal, policy, reasoning
├── collectors/             # Process, crontab, file, network, auth scanners
└── deploy/                 # systemd service file
```

## Configuration

See `sentinel.yml.example` for all options. Key settings:

```yaml
sentinel:
  weight_class: "standard"     # standard (cloud LLM) or enterprise (local LLM)

facades:
  enabled: true
  auto_detect: true            # scan real ports, facade the rest
  network_exposure: public     # public (filter noise) or internal (alert on everything)
  on_internal_probe: block     # block | alert | log | ignore
  on_targeted_probe: alert
  on_noise: log

cadence:
  heartbeat_interval: 120      # seconds
  reconciliation_interval: 900
  deep_audit_interval: 21600

dedup:
  cooldown_hours: 6
```

## Verdicts

Every incident gets one of five verdicts:

| Verdict | Meaning | Action |
|---------|---------|--------|
| `ALLOW` | Known-good, no concern | Log only |
| `ALLOW_AND_BASELINE` | New but legitimate | Add to baseline |
| `HOLD_FOR_ANALYSIS` | Uncertain, needs more context | Monitor, may escalate |
| `DENY_AND_QUARANTINE` | Malicious | Kill + quarantine + block |
| `ESCALATE` | Needs human decision | Queue for operator |

## Governance

Every verdict is:
- Signed with Ed25519 (tamper-proof)
- Recorded in a hash-chained audit journal
- Backed by a proof pack with full evidence chain

This makes every decision defensible and auditable for compliance.

## Resource Usage

Sentinel is designed for production servers:

- **Memory**: ~25-35 MB
- **CPU**: < 1% average (proc poll every 3s, inotify is event-driven)
- **Disk**: ~50 MB installed + logs
- **Network**: heartbeat every 2 min + incident packets as needed

## License

Source code is available for inspection and self-hosted use. See [LICENSE](LICENSE) for details.

## Links

- [BlackDome](https://blackdome.ai) — Product website
- [Dashboard](https://blackdome.ai/dashboard) — Customer portal
- [Documentation](https://blackdome.ai/docs/sentinel) — Full docs
