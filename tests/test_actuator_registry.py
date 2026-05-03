import asyncio
from core.actuator import ActionExecutor, BaseActuator
EXPECTED = {"kill_process", "kill_process_tree", "quarantine_file", "block_ip", "clean_persistence", "remove_ld_preload", "restore_sshd", "enter_emergency_isolation"}
EXISTING = {"kill_process", "quarantine_file", "block_ip", "clean_persistence"}
def _registry(tmp_path):
    return ActionExecutor(project_root=tmp_path)._registry
def test_registry_loads_all_8_actuators(tmp_path):
    assert set(_registry(tmp_path)) == EXPECTED
def test_each_actuator_class_subclasses_base_actuator(tmp_path):
    registry = _registry(tmp_path)
    assert all(issubclass(registry[name], BaseActuator) for name in EXPECTED)
def test_each_actuator_class_has_name_attribute(tmp_path):
    registry = _registry(tmp_path)
    assert all(getattr(registry[name], "name") == name for name in EXPECTED)
def test_unsupported_action_still_returns_status_unsupported(tmp_path):
    result = asyncio.run(ActionExecutor(project_root=tmp_path).execute([{"action": "nonexistent_actuator"}]))[0]
    assert result["status"] == "unsupported" and result["ok"] is False
def test_existing_4_actuators_still_register(tmp_path):
    assert EXISTING <= set(_registry(tmp_path))
