"""Host canary files -- planted fake credentials and keys.

Any access to these files = host compromise indicator.
Zero false positive rate -- no legitimate process reads these.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import secrets
from pathlib import Path
from typing import Any

log = logging.getLogger("sentinel.deception.canaries")

CANARY_DEFINITIONS = [
    {
        "path": "/root/.ssh/id_rsa_backup",
        "content": (
            "-----BEGIN OPENSSH PRIVATE KEY-----\n"
            "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAA\n"
            "{token}\n"
            "-----END OPENSSH PRIVATE KEY-----\n"
        ),
        "description": "Fake SSH private key backup",
        "mode": 0o600,
    },
    {
        "path": "/opt/.db_credentials.conf",
        "content": (
            "# Database credentials -- internal use only\n"
            "DB_HOST=10.0.1.50\nDB_PORT=5432\n"
            "DB_USER=admin_prod\nDB_PASS={token}\nDB_NAME=production\n"
        ),
        "description": "Fake database credentials",
        "mode": 0o640,
    },
    {
        "path": "/root/.aws/credentials",
        "content": (
            "[default]\n"
            "aws_access_key_id = AKIA{token_short}\n"
            "aws_secret_access_key = {token}\n"
            "region = us-east-1\n"
        ),
        "description": "Fake AWS credentials",
        "mode": 0o600,
    },
    {
        "path": "/var/backups/.mysql_root_pass",
        "content": "# MySQL root password\nMYSQL_ROOT_PASSWORD={token}\n",
        "description": "Fake MySQL root password",
        "mode": 0o600,
    },
    {
        "path": "/opt/.kube/config",
        "content": (
            "apiVersion: v1\nclusters:\n- cluster:\n"
            "    server: https://10.0.1.100:6443\n"
            "    certificate-authority-data: {token}\n"
            "  name: production\nkind: Config\nusers:\n- name: admin\n"
            "  user:\n    token: {token}\n"
        ),
        "description": "Fake Kubernetes config",
        "mode": 0o600,
    },
]

CANARY_MARKER = "# BDSNTL-CANARY-"


def plant_canaries(canary_state_path: Path) -> list[dict[str, str]]:
    """Plant canary files on the host. Returns list of planted canary metadata."""
    planted = []
    state = {}

    for defn in CANARY_DEFINITIONS:
        path = Path(defn["path"])
        try:
            if path.exists():
                content = path.read_text(errors="replace")
                if CANARY_MARKER not in content:
                    log.info("Skipping canary %s -- real file exists", path)
                    continue

            path.parent.mkdir(parents=True, exist_ok=True)

            token = secrets.token_hex(32)
            token_short = secrets.token_hex(8).upper()
            content = defn["content"].format(token=token, token_short=token_short)
            content += f"\n{CANARY_MARKER}{hashlib.sha256(str(path).encode()).hexdigest()[:12]}\n"

            path.write_text(content)
            os.chmod(str(path), defn["mode"])

            file_hash = hashlib.sha256(path.read_bytes()).hexdigest()
            planted.append({
                "path": str(path),
                "hash": file_hash,
                "description": defn["description"],
            })
            state[str(path)] = file_hash
            log.info("Planted canary: %s (%s)", path, defn["description"])

        except Exception as exc:
            log.warning("Failed to plant canary %s: %s", path, exc)

    canary_state_path.parent.mkdir(parents=True, exist_ok=True)
    canary_state_path.write_text(json.dumps(state, indent=2))
    return planted


def get_canary_paths() -> set[str]:
    """Return set of all canary file paths for inotify monitoring."""
    return {defn["path"] for defn in CANARY_DEFINITIONS}


def is_canary_path(path: str) -> bool:
    """Check if a path is a canary file."""
    canary_parents = {str(Path(defn["path"]).parent) for defn in CANARY_DEFINITIONS}
    return path in get_canary_paths() or any(path.startswith(p) for p in canary_parents)
