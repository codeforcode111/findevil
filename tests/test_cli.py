from click.testing import CliRunner

from findevil.audit.ledger import AuditLedger
from findevil.cli import cli


def test_audit_verify_valid(tmp_path):
    ledger = AuditLedger(tmp_path / "audit.jsonl")
    ledger.append("case_event", {"action": "start"})
    ledger.append("tool_call", {"run_id": "run-0001", "tool": "vol"})

    runner = CliRunner()
    result = runner.invoke(cli, ["audit", "verify", "--ledger", str(tmp_path / "audit.jsonl")])
    assert result.exit_code == 0
    assert "VALID" in result.output


def test_audit_verify_tampered(tmp_path):
    ledger = AuditLedger(tmp_path / "audit.jsonl")
    ledger.append("case_event", {"action": "start"})

    path = tmp_path / "audit.jsonl"
    path.write_text(path.read_text().replace("start", "TAMPERED"))

    runner = CliRunner()
    result = runner.invoke(cli, ["audit", "verify", "--ledger", str(path)])
    assert "INVALID" in result.output


def test_doctor_no_docker(tmp_path):
    runner = CliRunner()
    result = runner.invoke(cli, ["doctor"])
    assert result.exit_code == 0
