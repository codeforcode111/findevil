import pytest
from findevil.audit.ledger import AuditLedger
from findevil.contracts.compiler import ContractCompiler
from findevil.contracts.models import Evidence, EvidenceStatus, Finding
from findevil.correction.engine import CorrectionEngine


@pytest.fixture
def ledger(tmp_path):
    ledger = AuditLedger(tmp_path / "audit.jsonl")
    ledger.append("tool_call", {"run_id": "run-0001", "tool": "vol"})
    ledger.append("tool_call", {"run_id": "run-0002", "tool": "hayabusa"})
    return ledger


@pytest.fixture
def compiler(ledger):
    return ContractCompiler(ledger=ledger)


@pytest.fixture
def engine(ledger, compiler):
    return CorrectionEngine(ledger=ledger, compiler=compiler)


def _ev(art_id: str, run_id: str, src: str) -> Evidence:
    return Evidence(
        artifact_id=art_id,
        tool_run_id=run_id,
        source_file=src,
        content_hash="abc",
        excerpt="excerpt",
    )


def test_add_contradiction_downgrades_confirmed(engine):
    finding = Finding(
        finding_id="F-001",
        claim="Malware",
        status=EvidenceStatus.CONFIRMED,
        mitre_technique="T1059",
        evidence=[
            _ev("a1", "run-0001", "/evidence/mem.dmp"),
            _ev("a2", "run-0002", "/evidence/evtx"),
        ],
        confidence_basis="two sources",
    )
    contra = _ev("c1", "run-0002", "/evidence/sig.db")
    updated = engine.add_contradiction(finding, contra, "Valid code signature found")
    assert updated.status == EvidenceStatus.PROBABLE
    assert len(updated.contradictions) == 1
    assert len(updated.correction_history) == 1
    assert updated.correction_history[0].correction_type == "contradiction"


def test_contract_violation_downgrades(engine):
    finding = Finding(
        finding_id="F-002",
        claim="Persistence",
        status=EvidenceStatus.CONFIRMED,
        mitre_technique="T1547",
        evidence=[_ev("a1", "run-0001", "/evidence/mem.dmp")],
        confidence_basis="one source",
    )
    updated = engine.fix_contract_violation(finding)
    assert updated.status in (EvidenceStatus.PROBABLE, EvidenceStatus.INFERRED)
    assert len(updated.correction_history) == 1


def test_record_tool_failure(engine, ledger):
    engine.record_tool_failure(
        tool="vol",
        args=["-f", "/evidence/mem.dmp", "windows.pslist"],
        error="Unsupported memory format",
        suggested_alternative="psscan",
    )
    events = ledger.query(event_type="correction")
    assert len(events) == 1
    assert events[0]["data"]["correction_type"] == "tool_failure"
    assert events[0]["data"]["suggested_alternative"] == "psscan"


def test_correction_history_tracks_changes(engine):
    finding = Finding(
        finding_id="F-003",
        claim="Lateral movement",
        status=EvidenceStatus.CONFIRMED,
        mitre_technique="T1021",
        evidence=[
            _ev("a1", "run-0001", "/evidence/mem.dmp"),
            _ev("a2", "run-0002", "/evidence/evtx"),
        ],
        confidence_basis="two sources",
    )
    contra = _ev("c1", "run-0001", "/evidence/logs")
    updated = engine.add_contradiction(finding, contra, "Legitimate admin RDP session")
    assert updated.correction_history[0].before_status == EvidenceStatus.CONFIRMED
    assert updated.correction_history[0].after_status == EvidenceStatus.PROBABLE
