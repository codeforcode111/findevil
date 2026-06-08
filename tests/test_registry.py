import pytest
from findevil.tools.registry import CommandValidationError, ToolRegistry


@pytest.fixture
def registry():
    return ToolRegistry()


def test_allowed_tool_passes(registry):
    registry.validate("vol", ["-f", "/evidence/mem.dmp", "windows.pslist"])


def test_blocked_command_rejected(registry):
    with pytest.raises(CommandValidationError, match="blocked"):
        registry.validate("rm", ["-rf", "/evidence"])


def test_shell_metachar_rejected(registry):
    with pytest.raises(CommandValidationError, match="injection"):
        registry.validate("vol", ["-f", "/evidence/mem.dmp; rm -rf /"])


def test_path_traversal_rejected(registry):
    with pytest.raises(CommandValidationError, match="boundary"):
        registry.validate("vol", ["-f", "/etc/passwd"])


def test_path_within_evidence_allowed(registry):
    registry.validate("vol", ["-f", "/evidence/memory.dmp", "windows.pslist"])


def test_path_within_workspace_allowed(registry):
    registry.validate("vol", ["-f", "/evidence/mem.dmp", "-o", "/workspace/output"])


def test_get_tool_info(registry):
    info = registry.get_tool_info("vol")
    assert info is not None
    assert "description" in info


def test_list_available_tools(registry):
    tools = registry.list_tools()
    assert len(tools) > 0
    names = [t["name"] for t in tools]
    assert "vol" in names
    assert "hayabusa" in names
