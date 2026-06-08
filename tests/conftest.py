import tempfile
from pathlib import Path

import pytest


@pytest.fixture
def tmp_workspace(tmp_path):
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    return tmp_path


@pytest.fixture
def sample_evidence(tmp_workspace):
    evidence_dir = tmp_workspace / "evidence"
    evtx = evidence_dir / "Security.evtx"
    evtx.write_bytes(b"\x45\x6c\x66\x46\x69\x6c\x65" + b"\x00" * 100)
    reg = evidence_dir / "SYSTEM"
    reg.write_bytes(b"regf" + b"\x00" * 100)
    mem = evidence_dir / "memory.dmp"
    mem.write_bytes(b"\x00" * 200)
    return evidence_dir
