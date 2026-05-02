import asyncio
import logging
from unittest.mock import AsyncMock, Mock

from sentinel_v2 import SentinelDaemon


def _daemon(executor_result=None):
    daemon = object.__new__(SentinelDaemon)
    daemon.logger = logging.getLogger("test-pending-fight-actions")
    daemon.action_executor = Mock()
    daemon.action_executor.execute = AsyncMock(
        return_value=[{"ok": True}] if executor_result is None else executor_result
    )
    daemon._ack_command = AsyncMock()
    daemon._can_execute_block = Mock(return_value=(True, ""))
    daemon._remember_block = Mock()
    daemon._unblock_ip = Mock(return_value={"ok": True})
    daemon._clear_block_record = Mock()
    return daemon


def _run(command_type, payload, daemon=None, command_id="cmd-1"):
    daemon = daemon or _daemon()
    response = {
        "pending_commands": [
            {
                "command_id": command_id,
                "command_type": command_type,
                "payload": payload,
            }
        ]
    }
    asyncio.run(daemon._process_pending_commands(response))
    return daemon


def _ack_kwargs(daemon):
    daemon._ack_command.assert_awaited_once()
    return daemon._ack_command.await_args.kwargs


def test_block_ip_command_dispatches_via_action_executor():
    daemon = _daemon([{"ok": True, "rule": "INPUT+OUTPUT DROP", "ip": "1.2.3.4"}])

    _run("block_ip", {"target": "1.2.3.4", "reason": "fight_containment"}, daemon)

    daemon.action_executor.execute.assert_awaited_once_with(
        [{"action": "block_ip", "target": "1.2.3.4", "reason": "fight_containment"}]
    )
    assert _ack_kwargs(daemon)["status"] == "success"
    assert _ack_kwargs(daemon)["result"].get("execution_status") is None
    daemon._remember_block.assert_called_once_with("1.2.3.4", action_id="cmd-1")


def test_block_ip_skipped_when_target_is_trusted_ip():
    daemon = _daemon()
    daemon._can_execute_block.return_value = (False, "trusted_ip")

    _run("block_ip", {"target": "1.2.3.4"}, daemon)

    daemon.action_executor.execute.assert_not_called()
    assert _ack_kwargs(daemon)["status"] == "skipped"
    assert _ack_kwargs(daemon)["result"] == {"execution_status": "trusted_ip"}


def test_block_ip_skipped_when_internal_ip_without_confirmation():
    daemon = _daemon()
    daemon._can_execute_block.return_value = (False, "internal_ip_requires_confirmation")

    _run("block_ip", {"target": "10.0.0.5"}, daemon)

    daemon.action_executor.execute.assert_not_called()
    assert _ack_kwargs(daemon)["status"] == "skipped"
    assert _ack_kwargs(daemon)["result"] == {
        "execution_status": "internal_ip_requires_confirmation"
    }


def test_kill_process_tree_command_dispatches():
    daemon = _daemon([{"ok": True, "pids_killed": [1234, 1235]}])

    _run("kill_process_tree", {"target": "pid:1234"}, daemon)

    daemon.action_executor.execute.assert_awaited_once_with(
        [{"action": "kill_process_tree", "target": "pid:1234", "reason": "controller_dispatched"}]
    )
    assert _ack_kwargs(daemon)["status"] == "success"


def test_quarantine_file_command_dispatches():
    daemon = _daemon([{"ok": True, "quarantine_path": "/var/quarantine/dropper.sh"}])

    _run("quarantine_file", {"target": "/tmp/dropper.sh"}, daemon)

    daemon.action_executor.execute.assert_awaited_once_with(
        [{"action": "quarantine_file", "target": "/tmp/dropper.sh", "reason": "controller_dispatched"}]
    )
    assert _ack_kwargs(daemon)["status"] == "success"


def test_clean_persistence_command_dispatches():
    daemon = _daemon([{"ok": True, "removed": ["/etc/systemd/system/bad.service"]}])
    target = {"files": ["/etc/systemd/system/bad.service"]}

    _run("clean_persistence", {"target": target}, daemon)

    daemon.action_executor.execute.assert_awaited_once_with(
        [{"action": "clean_persistence", "target": target, "reason": "controller_dispatched"}]
    )
    assert _ack_kwargs(daemon)["status"] == "success"


def test_kill_process_command_dispatches():
    daemon = _daemon([{"ok": True, "pid": 9999}])

    _run("kill_process", {"target": "pid:9999"}, daemon)

    daemon.action_executor.execute.assert_awaited_once_with(
        [{"action": "kill_process", "target": "pid:9999", "reason": "controller_dispatched"}]
    )
    assert _ack_kwargs(daemon)["status"] == "success"


def test_unsupported_command_still_returns_unsupported_for_unknown_types():
    daemon = _daemon()

    _run("do_a_barrel_roll", {"target": "1.2.3.4"}, daemon)

    daemon.action_executor.execute.assert_not_called()
    assert _ack_kwargs(daemon)["status"] == "skipped"
    assert _ack_kwargs(daemon)["result"] == {
        "reason": "unsupported_command:do_a_barrel_roll"
    }


def test_existing_unblock_ip_path_unchanged():
    daemon = _daemon()

    _run("unblock_ip", {"target": "1.2.3.4"}, daemon)

    daemon._unblock_ip.assert_called_once_with("1.2.3.4")
    daemon.action_executor.execute.assert_not_called()
    assert _ack_kwargs(daemon)["status"] == "success"


def test_block_ip_failure_acks_failed():
    daemon = _daemon([{"ok": False, "status": "iptables_error", "error": "no such device"}])

    _run("block_ip", {"target": "1.2.3.4"}, daemon)

    assert _ack_kwargs(daemon)["status"] == "failed"
    assert "no such device" in _ack_kwargs(daemon)["error"]
    daemon._remember_block.assert_not_called()


def test_action_executor_returns_empty_list_acks_failed():
    daemon = _daemon([])

    _run("block_ip", {"target": "1.2.3.4"}, daemon)

    assert _ack_kwargs(daemon)["status"] == "failed"
    assert _ack_kwargs(daemon)["error"] == "unknown"


def test_missing_target_raises_and_exception_handler_acks_failed():
    daemon = _daemon()

    _run("block_ip", {}, daemon)

    daemon.action_executor.execute.assert_not_called()
    assert _ack_kwargs(daemon)["status"] == "failed"
    assert "Missing target" in _ack_kwargs(daemon)["error"]
