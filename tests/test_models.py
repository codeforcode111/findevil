import pytest
from findevil.contracts.models import (
    AuditEvent,
    CorrectionRecord,
    Evidence,
    EvidenceStatus,
    Finding,
    ToolRun,
)


def test_evidence_status_values():
    assert EvidenceStatus.CONFIRMED == "confirmed"
    assert EvidenceStatus.PROBABLE == "probable"
    assert EvidenceStatus.INFERRED == "inferred"
    assert EvidenceStatus.REFUTED == "refuted"
    assert EvidenceStatus.UNKNOWN == "unknown"


def test_tool_run_creation():
    run = ToolRun(
        run_id="run-001",
        tool="volatility3",
        command="vol -f mem.dmp windows.pslist",
        args={"plugin": "windows.pslist"},
        exit_code=0,
        stdout_hash="abc123",
        duration_ms=1500,
    )
    assert run.run_id == "run-001"
    assert run.exit_code == 0


def test_evidence_creation():
    ev = Evidence(
        artifact_id="art-001",
        tool_run_id="run-001",
        source_file="/evidence/memory.dmp",
        content_hash="def456",
        excerpt="PID 1234 svchost.exe suspicious parent",
    )
    assert ev.artifact_id == "art-001"
    assert ev.tool_run_id == "run-001"


def test_finding_creation_confirmed():
    ev1 = Evidence(
        artifact_id="art-001",
        tool_run_id="run-001",
        source_file="/evidence/memory.dmp",
        content_hash="aaa",
        excerpt="malicious process",
    )
    ev2 = Evidence(
        artifact_id="art-002",
        tool_run_id="run-002",
        source_file="/evidence/Security.evtx",
        content_hash="bbb",
        excerpt="suspicious logon event",
    )
    finding = Finding(
        finding_id="F-001",
        claim="Cobalt Strike beacon process detected",
        status=EvidenceStatus.CONFIRMED,
        mitre_technique="T1059.001",
        evidence=[ev1, ev2],
        contradictions=[],
        confidence_basis="Two independent sources: memory process list and event log",
    )
    assert finding.finding_id == "F-001"
    assert finding.status == EvidenceStatus.CONFIRMED
    assert len(finding.evidence) == 2
    assert finding.tool_run_ids == ["run-001", "run-002"]


def test_finding_requires_evidence():
    with pytest.raises(ValueError):
        Finding(
            finding_id="F-002",
            claim="some claim",
            status=EvidenceStatus.CONFIRMED,
            mitre_technique="T1059",
            evidence=[],
            contradictions=[],
            confidence_basis="none",
        )


def test_correction_record():
    rec = CorrectionRecord(
        correction_type="contradiction",
        reason="Found valid code signature",
        before_status=EvidenceStatus.CONFIRMED,
        after_status=EvidenceStatus.REFUTED,
        finding_id="F-001",
    )
    assert rec.correction_type == "contradiction"
    assert rec.before_status == EvidenceStatus.CONFIRMED


def test_audit_event():
    evt = AuditEvent(
        event_id="evt-001",
        event_type="tool_call",
        data={"tool": "volatility3", "exit_code": 0},
    )
    assert evt.event_id == "evt-001"
    assert evt.prev_hash is None
