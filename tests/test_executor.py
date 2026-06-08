import subprocess
from unittest.mock import MagicMock, patch

import pytest
from findevil.audit.ledger import AuditLedger
from findevil.tools.executor import DockerExecutor, ToolExecutionError
from findevil.tools.registry import ToolRegistry


@pytest.fixture
def ledger(tmp_path):
    return AuditLedger(tmp_path / "audit.jsonl")


@pytest.fixture
def executor(ledger):
    return DockerExecutor(
        container_name="findevil-sift",
        registry=ToolRegistry(),
        ledger=ledger,
    )


@patch("subprocess.run")
def test_successful_execution(mock_run, executor):
    mock_run.return_value = subprocess.CompletedProcess(
        args=[], returncode=0, stdout="PID  PPID  Name\n1234  1  svchost.exe\n", stderr=""
    )
    result = executor.execute("vol", ["-f", "/evidence/mem.dmp", "windows.pslist"])
    assert result.exit_code == 0
    assert "svchost.exe" in result.stdout


@patch("subprocess.run")
def test_execution_logs_to_audit(mock_run, executor, ledger):
    mock_run.return_value = subprocess.CompletedProcess(
        args=[], returncode=0, stdout="output", stderr=""
    )
    executor.execute("vol", ["-f", "/evidence/mem.dmp", "windows.pslist"])
    events = ledger.query(event_type="tool_call")
    assert len(events) == 1
    assert events[0]["data"]["tool"] == "vol"
    assert events[0]["data"]["exit_code"] == 0


@patch("subprocess.run")
def test_execution_failure_logged(mock_run, executor, ledger):
    mock_run.return_value = subprocess.CompletedProcess(
        args=[], returncode=1, stdout="", stderr="Error: invalid plugin"
    )
    result = executor.execute("vol", ["-f", "/evidence/mem.dmp", "windows.badplugin"])
    assert result.exit_code == 1
    events = ledger.query(event_type="tool_call")
    assert events[0]["data"]["exit_code"] == 1


def test_blocked_command_not_executed(executor):
    with pytest.raises(Exception):
        executor.execute("rm", ["-rf", "/evidence"])


@patch("subprocess.run")
def test_timeout_raises_error(mock_run, executor):
    mock_run.side_effect = subprocess.TimeoutExpired(cmd="vol", timeout=300)
    with pytest.raises(ToolExecutionError, match="timed out"):
        executor.execute("vol", ["-f", "/evidence/mem.dmp", "windows.pslist"])


@patch("subprocess.run")
def test_result_includes_run_id(mock_run, executor):
    mock_run.return_value = subprocess.CompletedProcess(
        args=[], returncode=0, stdout="output", stderr=""
    )
    result = executor.execute("vol", ["-f", "/evidence/mem.dmp", "windows.pslist"])
    assert result.run_id.startswith("run-")
