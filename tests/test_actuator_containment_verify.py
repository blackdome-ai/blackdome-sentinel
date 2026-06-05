import asyncio
from pathlib import Path

from actuators import kill_process_tree
from actuators.quarantine_file import QuarantineFileActuator
from actuators.kill_process_tree import KillProcessTreeActuator


class MemoryAudit:
    def __init__(self):
        self.records = []

    def log_action(self, record):
        self.records.append(record)


def _run(coro):
    return asyncio.run(coro)


def _patch_quarantine(monkeypatch, tmp_path, *, profile="fight", phase="discovery", system_pkg=False):
    quarantine_dir = tmp_path / "quarantine"
    monkeypatch.setattr("actuators.quarantine_file.QUARANTINE_DIR", quarantine_dir)
    monkeypatch.setattr("actuators.quarantine_file.ENGAGEMENT_FLAG", tmp_path / "burn_engaged.flag")
    monkeypatch.setenv("GAUNTLET_PROFILE", profile)
    monkeypatch.setenv("SENTINEL_PHASE", phase)
    monkeypatch.setattr(QuarantineFileActuator, "_strip_immutable", staticmethod(lambda path: None))
    monkeypatch.setattr(QuarantineFileActuator, "_is_system_package", staticmethod(lambda path: system_pkg))
    return quarantine_dir


def test_quarantine_regular_file_in_fight_profile_removes_original_and_verifies(monkeypatch, tmp_path):
    quarantine_dir = _patch_quarantine(monkeypatch, tmp_path)
    source = tmp_path / "dropper.bin"
    source.write_bytes(b"payload")

    result = _run(QuarantineFileActuator().execute(str(source), MemoryAudit()))

    assert result["status"] == "completed"
    assert result["ok"] is True
    assert result["result"]["original_removed"] is True
    assert result["result"]["is_directory"] is False
    assert not source.exists()
    assert Path(result["result"]["quarantine_path"]).exists()
    assert Path(result["result"]["quarantine_path"]).parent == quarantine_dir


def test_quarantine_directory_in_fight_profile_copytrees_removes_original_and_verifies(monkeypatch, tmp_path):
    _patch_quarantine(monkeypatch, tmp_path)
    source = tmp_path / "dropper_tree"
    source.mkdir()
    (source / "payload.sh").write_text("sh payload", encoding="utf-8")
    nested = source / "nested"
    nested.mkdir()
    (nested / "tool").write_bytes(b"tool")

    result = _run(QuarantineFileActuator().execute(str(source), MemoryAudit()))

    assert result["status"] == "completed"
    assert result["ok"] is True
    assert result["result"]["original_removed"] is True
    assert result["result"]["is_directory"] is True
    assert "tree_sha256" in result["result"]
    copied = Path(result["result"]["quarantine_path"])
    assert copied.is_dir()
    assert (copied / "payload.sh").read_text(encoding="utf-8") == "sh payload"
    assert (copied / "nested" / "tool").read_bytes() == b"tool"
    assert not source.exists()


def test_quarantine_fight_profile_neutralizes_even_in_discovery_phase(monkeypatch, tmp_path):
    _patch_quarantine(monkeypatch, tmp_path, profile="fight", phase="discovery")
    source = tmp_path / "discovery-dropper"
    source.write_text("dropper", encoding="utf-8")

    result = _run(QuarantineFileActuator().execute(str(source), MemoryAudit()))

    assert result["status"] == "completed"
    assert result["result"]["phase"] == "discovery"
    assert result["result"]["profile"] == "fight"
    assert result["result"]["original_removed"] is True
    assert not source.exists()


def test_quarantine_system_package_guard_keeps_original_but_verifies_capture(monkeypatch, tmp_path):
    _patch_quarantine(monkeypatch, tmp_path, profile="fight", phase="protect", system_pkg=True)
    source = tmp_path / "dpkg-owned"
    source.write_text("system file", encoding="utf-8")

    result = _run(QuarantineFileActuator().execute(str(source), MemoryAudit()))

    assert result["status"] == "completed"
    assert result["ok"] is True
    assert result["result"]["is_system_package"] is True
    assert result["result"]["original_removed"] is False
    assert source.exists()
    assert Path(result["result"]["quarantine_path"]).exists()


def test_quarantine_skip_short_circuits_verify_true_and_leaves_original(monkeypatch, tmp_path):
    _patch_quarantine(monkeypatch, tmp_path, profile="fight")
    source = tmp_path / "boot-noise"
    source.write_bytes(b"boot-noise")
    digest = "boot-noise-sha"
    monkeypatch.setattr("actuators.quarantine_file._sha256_file", lambda path: digest)
    monkeypatch.setattr("actuators.quarantine_file.KNOWN_BOOT_NOISE_SHAS", frozenset({digest}))

    boot_noise = _run(QuarantineFileActuator().execute(str(source), MemoryAudit()))

    assert boot_noise["status"] == "completed"
    assert boot_noise["result"]["reason"] == "known_boot_noise_sha"
    assert source.exists()

    monkeypatch.setenv("GAUNTLET_PROFILE", "burn")
    burn_skip = _run(QuarantineFileActuator().execute(str(source), MemoryAudit()))

    assert burn_skip["status"] == "completed"
    assert burn_skip["result"]["reason"] == "burn_pre_engagement"
    assert source.exists()


def _fake_proc(tmp_path, pid, *, state=None):
    proc_pid = tmp_path / "proc" / str(pid)
    proc_pid.mkdir(parents=True)
    if state:
        (proc_pid / "status").write_text(f"Name:\ttest\nState:\t{state} (fake)\n", encoding="utf-8")
    return proc_pid


def test_kill_process_tree_verify_treats_zombie_as_dead(monkeypatch, tmp_path):
    monkeypatch.setattr(kill_process_tree, "PROC_ROOT", tmp_path / "proc", raising=False)
    _fake_proc(tmp_path, 424242, state="Z")

    verified = _run(KillProcessTreeActuator()._verify("pid:424242", {"killed_pids": [424242]}))

    assert verified is True


def test_kill_process_tree_verify_treats_live_state_as_alive(monkeypatch, tmp_path):
    monkeypatch.setattr(kill_process_tree, "PROC_ROOT", tmp_path / "proc", raising=False)
    monkeypatch.setattr(kill_process_tree.time, "sleep", lambda seconds: None)
    monkeypatch.setattr(kill_process_tree.os, "kill", lambda pid, sig: None)
    _fake_proc(tmp_path, 424243, state="S")

    verified = _run(KillProcessTreeActuator()._verify("pid:424243", {"killed_pids": [424243]}))

    assert verified is False


def test_kill_process_tree_verify_treats_gone_proc_as_dead(monkeypatch, tmp_path):
    monkeypatch.setattr(kill_process_tree, "PROC_ROOT", tmp_path / "proc", raising=False)

    verified = _run(KillProcessTreeActuator()._verify("pid:424244", {"killed_pids": [424244]}))

    assert verified is True
