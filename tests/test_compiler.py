import pytest
from findevil.audit.ledger import AuditLedger
from findevil.contracts.compiler import ContractCompiler, ContractViolation
from findevil.contracts.models import Evidence, EvidenceStatus, Finding


@pytest.fixture
def ledger(tmp_path):
    ledger = AuditLedger(tmp_path / "audit.jsonl")
    ledger.append("tool_call", {"run_id": "run-0001", "tool": "vol"})
    ledger.append("tool_call", {"run_id": "run-0002", "tool": "hayabusa"})
    ledger.append("tool_call", {"run_id": "run-0003", "tool": "fls"})
    return ledger


@pytest.fixture
def compiler(ledger):
    return ContractCompiler(ledger=ledger)


def _make_evidence(art_id: str, run_id: str, source: str) -> Evidence:
    return Evidence(
        artifact_id=art_id,
        tool_run_id=run_id,
        source_file=source,
        content_hash="abc",
        excerpt="test excerpt",
    )


def test_confirmed_requires_two_sources(compiler):
    finding = Finding(
        finding_id="F-001",
        claim="Malware persistence",
        status=EvidenceStatus.CONFIRMED,
        mitre_technique="T1547.001",
        evidence=[_make_evidence("a1", "run-0001", "/evidence/memory.dmp")],
        confidence_basis="single source",
    )
    with pytest.raises(ContractViolation, match="requires.*2"):
        compiler.validate(finding)


def test_confirmed_with_two_sources_passes(compiler):
    finding = Finding(
        finding_id="F-001",
        claim="Malware persistence",
        status=EvidenceStatus.CONFIRMED,
        mitre_technique="T1547.001",
        evidence=[
            _make_evidence("a1", "run-0001", "/evidence/memory.dmp"),
            _make_evidence("a2", "run-0002", "/evidence/Security.evtx"),
        ],
        confidence_basis="memory and event log",
    )
    compiler.validate(finding)


def test_finding_with_contradictions_cannot_be_confirmed(compiler):
    finding = Finding(
        finding_id="F-001",
        claim="Malware process",
        status=EvidenceStatus.CONFIRMED,
        mitre_technique="T1059",
        evidence=[
            _make_evidence("a1", "run-0001", "/evidence/memory.dmp"),
            _make_evidence("a2", "run-0002", "/evidence/Security.evtx"),
        ],
        contradictions=[
            _make_evidence("c1", "run-0003", "/evidence/signatures.db"),
        ],
        confidence_basis="cross-validated but contradicted",
    )
    with pytest.raises(ContractViolation, match="contradictions"):
        compiler.validate(finding)


def test_inferred_requires_confidence_basis(compiler):
    finding = Finding(
        finding_id="F-001",
        claim="Possible data staging",
        status=EvidenceStatus.INFERRED,
        mitre_technique="T1074",
        evidence=[_make_evidence("a1", "run-0001", "/evidence/disk.img")],
        confidence_basis="",
    )
    with pytest.raises(ContractViolation, match="confidence_basis"):
        compiler.validate(finding)


def test_evidence_must_have_valid_run_id(compiler):
    finding = Finding(
        finding_id="F-001",
        claim="Something",
        status=EvidenceStatus.PROBABLE,
        mitre_technique="T1059",
        evidence=[_make_evidence("a1", "run-9999", "/evidence/disk.img")],
        confidence_basis="one source",
    )
    with pytest.raises(ContractViolation, match="run_id.*not found"):
        compiler.validate(finding)


def test_probable_with_one_source_passes(compiler):
    finding = Finding(
        finding_id="F-001",
        claim="Suspicious process",
        status=EvidenceStatus.PROBABLE,
        mitre_technique="T1059",
        evidence=[_make_evidence("a1", "run-0001", "/evidence/memory.dmp")],
        confidence_basis="strong memory evidence",
    )
    compiler.validate(finding)


def test_compile_report_rejects_invalid_findings(compiler):
    bad_finding = Finding(
        finding_id="F-001",
        claim="Invalid",
        status=EvidenceStatus.CONFIRMED,
        mitre_technique="T1059",
        evidence=[_make_evidence("a1", "run-0001", "/evidence/x")],
        confidence_basis="single source",
    )
    violations = compiler.compile([bad_finding])
    assert len(violations) == 1
    assert violations[0].finding_id == "F-001"


def test_compile_report_passes_valid_findings(compiler):
    good = Finding(
        finding_id="F-001",
        claim="Valid finding",
        status=EvidenceStatus.PROBABLE,
        mitre_technique="T1059",
        evidence=[_make_evidence("a1", "run-0001", "/evidence/memory.dmp")],
        confidence_basis="strong evidence",
    )
    violations = compiler.compile([good])
    assert len(violations) == 0
