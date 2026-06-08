import pytest
from findevil.audit.ledger import AuditLedger
from findevil.vault.evidence import EvidenceVault


@pytest.fixture
def ledger(tmp_workspace):
    return AuditLedger(tmp_workspace / "audit.jsonl")


@pytest.fixture
def vault(sample_evidence, tmp_workspace, ledger):
    return EvidenceVault(
        evidence_dir=sample_evidence,
        workspace_dir=tmp_workspace / "workspace",
        ledger=ledger,
    )


def test_initialize_hashes_evidence(vault, sample_evidence):
    vault.initialize()
    assert len(vault.file_hashes) == 3
    for fname in ["Security.evtx", "SYSTEM", "memory.dmp"]:
        assert fname in vault.file_hashes


def test_verify_integrity_passes(vault):
    vault.initialize()
    assert vault.verify_integrity() is True


def test_verify_integrity_detects_tampering(vault, sample_evidence):
    vault.initialize()
    (sample_evidence / "Security.evtx").write_bytes(b"TAMPERED")
    assert vault.verify_integrity() is False


def test_list_evidence_files(vault):
    vault.initialize()
    files = vault.list_files()
    assert len(files) == 3
    assert any(f["name"] == "Security.evtx" for f in files)


def test_path_boundary_allows_evidence(vault):
    vault.initialize()
    assert vault.is_path_allowed("/evidence/Security.evtx") is True


def test_path_boundary_blocks_outside(vault):
    vault.initialize()
    assert vault.is_path_allowed("/etc/passwd") is False
    assert vault.is_path_allowed("/evidence/../etc/passwd") is False


def test_initialize_logs_to_audit(vault, ledger):
    vault.initialize()
    events = ledger.query(event_type="evidence_hash")
    assert len(events) == 3
