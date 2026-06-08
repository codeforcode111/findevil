import json

import pytest
from findevil.audit.ledger import AuditLedger


@pytest.fixture
def ledger(tmp_path):
    return AuditLedger(tmp_path / "audit.jsonl")


def test_append_event(ledger):
    ledger.append("tool_call", {"tool": "volatility3", "exit_code": 0})
    events = ledger.read_all()
    assert len(events) == 1
    assert events[0]["event_type"] == "tool_call"
    assert events[0]["data"]["tool"] == "volatility3"


def test_hash_chain_integrity(ledger):
    ledger.append("tool_call", {"tool": "vol3"})
    ledger.append("finding_event", {"finding_id": "F-001"})
    ledger.append("correction", {"type": "contradiction"})
    assert ledger.verify_chain() is True


def test_hash_chain_detects_tampering(ledger):
    ledger.append("tool_call", {"tool": "vol3"})
    ledger.append("finding_event", {"finding_id": "F-001"})

    lines = ledger.path.read_text().strip().split("\n")
    record = json.loads(lines[0])
    record["data"]["tool"] = "TAMPERED"
    lines[0] = json.dumps(record)
    ledger.path.write_text("\n".join(lines) + "\n")

    assert ledger.verify_chain() is False


def test_first_event_has_no_prev_hash(ledger):
    ledger.append("case_event", {"action": "start"})
    events = ledger.read_all()
    assert events[0]["prev_hash"] is None


def test_second_event_chains_to_first(ledger):
    ledger.append("case_event", {"action": "start"})
    ledger.append("tool_call", {"tool": "fls"})
    events = ledger.read_all()
    assert events[1]["prev_hash"] == events[0]["hash"]


def test_query_by_type(ledger):
    ledger.append("tool_call", {"tool": "vol3"})
    ledger.append("finding_event", {"finding_id": "F-001"})
    ledger.append("tool_call", {"tool": "fls"})
    tool_calls = ledger.query(event_type="tool_call")
    assert len(tool_calls) == 2


def test_query_by_finding_id(ledger):
    ledger.append("finding_event", {"finding_id": "F-001", "action": "created"})
    ledger.append("finding_event", {"finding_id": "F-002", "action": "created"})
    ledger.append("correction", {"finding_id": "F-001", "type": "downgrade"})
    results = ledger.query(finding_id="F-001")
    assert len(results) == 2
