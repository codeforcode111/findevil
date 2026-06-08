# FinDevil Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build an Evidence-Contract Autonomous IR Agent that wins 1st place in the SANS FIND EVIL! hackathon.

**Architecture:** Claude Code serves as the agent brain, communicating via MCP protocol to a custom Python FastMCP server. The server wraps SIFT Workstation forensic tools running in Docker, enforcing evidence contracts (no finding without traceable tool output), self-correction loops, and hash-chained audit trails.

**Tech Stack:** Python 3.12, FastMCP, Pydantic v2, SQLite, Docker, Jinja2. DFIR tools: Volatility 3, Plaso, Sleuth Kit, Hayabusa, YARA, Zimmerman tools, RegRipper.

---

## File Map

```
findevil/
├── pyproject.toml
├── Dockerfile.sift
├── docker-compose.yml
├── src/findevil/
│   ├── __init__.py
│   ├── server.py               # FastMCP server — all MCP tools
│   ├── vault/
│   │   ├── __init__.py
│   │   └── evidence.py         # Evidence integrity management
│   ├── tools/
│   │   ├── __init__.py
│   │   ├── registry.py         # Tool allowlist/blocklist + validation
│   │   ├── executor.py         # docker exec wrapper + audit logging
│   │   ├── volatility.py       # Volatility 3 plugins
│   │   ├── sleuthkit.py        # Sleuth Kit disk analysis
│   │   ├── hayabusa.py         # EVTX + Sigma rules
│   │   ├── yara_scanner.py     # YARA scanning
│   │   ├── plaso.py            # Super-timeline
│   │   └── zimmerman.py        # MFT/Amcache/Prefetch/Registry
│   ├── contracts/
│   │   ├── __init__.py
│   │   ├── models.py           # Pydantic: Evidence, Finding, ToolRun, AuditEvent
│   │   ├── compiler.py         # Reject uncited claims
│   │   └── policies.py         # Corroboration rules per MITRE tactic
│   ├── correction/
│   │   ├── __init__.py
│   │   └── engine.py           # Self-correction state machine
│   ├── audit/
│   │   ├── __init__.py
│   │   └── ledger.py           # Hash-chained JSONL ledger
│   ├── report/
│   │   ├── __init__.py
│   │   ├── generator.py        # Markdown + JSON report compiler
│   │   └── templates/
│   │       └── report.md.j2    # Jinja2 report template
│   └── cli.py                  # trace / replay / bench / doctor
├── cases/
│   └── sample/
│       ├── README.md
│       └── ground_truth.json
├── tests/
│   ├── conftest.py
│   ├── test_models.py
│   ├── test_ledger.py
│   ├── test_vault.py
│   ├── test_registry.py
│   ├── test_executor.py
│   ├── test_compiler.py
│   ├── test_correction.py
│   ├── test_report.py
│   └── test_cli.py
└── .claude/
    └── settings.json           # MCP server registration
```

---

### Task 1: Project Scaffold

**Files:**
- Create: `pyproject.toml`
- Create: `src/findevil/__init__.py`
- Create: `src/findevil/vault/__init__.py`
- Create: `src/findevil/tools/__init__.py`
- Create: `src/findevil/contracts/__init__.py`
- Create: `src/findevil/correction/__init__.py`
- Create: `src/findevil/audit/__init__.py`
- Create: `src/findevil/report/__init__.py`
- Create: `tests/conftest.py`

- [ ] **Step 1: Create pyproject.toml**

```toml
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[project]
name = "findevil"
version = "0.1.0"
description = "Evidence-Contract Autonomous IR Agent for SANS FIND EVIL! Hackathon"
requires-python = ">=3.12"
license = "MIT"
dependencies = [
    "fastmcp>=2.0.0",
    "pydantic>=2.0.0",
    "jinja2>=3.1.0",
    "click>=8.1.0",
]

[project.scripts]
findevil = "findevil.cli:cli"

[tool.pytest.ini_options]
testpaths = ["tests"]
pythonpath = ["src"]
```

- [ ] **Step 2: Create all `__init__.py` files**

Create empty `__init__.py` in each package directory:
- `src/findevil/__init__.py`
- `src/findevil/vault/__init__.py`
- `src/findevil/tools/__init__.py`
- `src/findevil/contracts/__init__.py`
- `src/findevil/correction/__init__.py`
- `src/findevil/audit/__init__.py`
- `src/findevil/report/__init__.py`

- [ ] **Step 3: Create tests/conftest.py**

```python
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
```

- [ ] **Step 4: Install project in dev mode and verify**

Run: `cd /Users/jiaweiyu/workfiles/hackthron-june && pip install -e ".[dev]" 2>&1 | tail -5`

If pip complains about `[dev]`, run: `pip install -e .` then `pip install pytest`

Run: `python -c "import findevil; print('OK')"`

Expected: `OK`

- [ ] **Step 5: Commit**

```bash
git add pyproject.toml src/ tests/conftest.py
git commit -m "chore: scaffold project structure with dependencies"
```

---

### Task 2: Pydantic Data Models

**Files:**
- Create: `src/findevil/contracts/models.py`
- Create: `tests/test_models.py`

- [ ] **Step 1: Write failing tests for data models**

```python
# tests/test_models.py
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Users/jiaweiyu/workfiles/hackthron-june && python -m pytest tests/test_models.py -v`

Expected: FAIL — `ModuleNotFoundError: No module named 'findevil.contracts.models'`

- [ ] **Step 3: Implement data models**

```python
# src/findevil/contracts/models.py
from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field, model_validator


class EvidenceStatus(StrEnum):
    CONFIRMED = "confirmed"
    PROBABLE = "probable"
    INFERRED = "inferred"
    REFUTED = "refuted"
    UNKNOWN = "unknown"


class ToolRun(BaseModel):
    run_id: str
    tool: str
    command: str
    args: dict[str, Any] = Field(default_factory=dict)
    exit_code: int
    stdout_hash: str
    duration_ms: int
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class Evidence(BaseModel):
    artifact_id: str
    tool_run_id: str
    source_file: str
    content_hash: str
    excerpt: str


class CorrectionRecord(BaseModel):
    correction_type: str
    reason: str
    before_status: EvidenceStatus
    after_status: EvidenceStatus
    finding_id: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class Finding(BaseModel):
    finding_id: str
    claim: str
    status: EvidenceStatus
    mitre_technique: str
    evidence: list[Evidence]
    contradictions: list[Evidence] = Field(default_factory=list)
    confidence_basis: str
    correction_history: list[CorrectionRecord] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def tool_run_ids(self) -> list[str]:
        return [e.tool_run_id for e in self.evidence]

    @model_validator(mode="after")
    def validate_evidence_not_empty(self) -> Finding:
        if not self.evidence:
            raise ValueError("Finding must have at least one piece of evidence")
        return self


class AuditEvent(BaseModel):
    event_id: str
    event_type: str
    data: dict[str, Any] = Field(default_factory=dict)
    prev_hash: str | None = None
    hash: str | None = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/jiaweiyu/workfiles/hackthron-june && python -m pytest tests/test_models.py -v`

Expected: All 7 tests PASS

- [ ] **Step 5: Commit**

```bash
git add src/findevil/contracts/models.py tests/test_models.py
git commit -m "feat: add Pydantic data models for findings, evidence, and audit events"
```

---

### Task 3: Audit Ledger

**Files:**
- Create: `src/findevil/audit/ledger.py`
- Create: `tests/test_ledger.py`

- [ ] **Step 1: Write failing tests for the ledger**

```python
# tests/test_ledger.py
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Users/jiaweiyu/workfiles/hackthron-june && python -m pytest tests/test_ledger.py -v`

Expected: FAIL — cannot import `AuditLedger`

- [ ] **Step 3: Implement the audit ledger**

```python
# src/findevil/audit/ledger.py
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class AuditLedger:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self._counter = 0
        self._last_hash: str | None = None

        if self.path.exists():
            events = self.read_all()
            if events:
                self._counter = len(events)
                self._last_hash = events[-1]["hash"]

    def _compute_hash(self, record: dict[str, Any]) -> str:
        serialized = json.dumps(record, sort_keys=True, default=str)
        return hashlib.sha256(serialized.encode()).hexdigest()

    def append(self, event_type: str, data: dict[str, Any]) -> dict[str, Any]:
        self._counter += 1
        record = {
            "event_id": f"evt-{self._counter:04d}",
            "event_type": event_type,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "prev_hash": self._last_hash,
            "data": data,
        }
        record["hash"] = self._compute_hash(record)
        self._last_hash = record["hash"]

        with open(self.path, "a") as f:
            f.write(json.dumps(record, default=str) + "\n")

        return record

    def read_all(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        lines = self.path.read_text().strip().split("\n")
        return [json.loads(line) for line in lines if line.strip()]

    def verify_chain(self) -> bool:
        events = self.read_all()
        for i, event in enumerate(events):
            stored_hash = event.pop("hash")
            expected_hash = self._compute_hash(event)
            event["hash"] = stored_hash
            if stored_hash != expected_hash:
                return False
            if i == 0 and event["prev_hash"] is not None:
                return False
            if i > 0 and event["prev_hash"] != events[i - 1]["hash"]:
                return False
        return True

    def query(
        self,
        event_type: str | None = None,
        finding_id: str | None = None,
    ) -> list[dict[str, Any]]:
        results = []
        for event in self.read_all():
            if event_type and event["event_type"] != event_type:
                continue
            if finding_id and event["data"].get("finding_id") != finding_id:
                continue
            results.append(event)
        return results
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/jiaweiyu/workfiles/hackthron-june && python -m pytest tests/test_ledger.py -v`

Expected: All 7 tests PASS

- [ ] **Step 5: Commit**

```bash
git add src/findevil/audit/ledger.py tests/test_ledger.py
git commit -m "feat: add hash-chained audit ledger with tamper detection"
```

---

### Task 4: Evidence Vault

**Files:**
- Create: `src/findevil/vault/evidence.py`
- Create: `tests/test_vault.py`

- [ ] **Step 1: Write failing tests for the evidence vault**

```python
# tests/test_vault.py
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Users/jiaweiyu/workfiles/hackthron-june && python -m pytest tests/test_vault.py -v`

Expected: FAIL — cannot import `EvidenceVault`

- [ ] **Step 3: Implement evidence vault**

```python
# src/findevil/vault/evidence.py
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from findevil.audit.ledger import AuditLedger


class EvidenceVault:
    def __init__(
        self,
        evidence_dir: Path,
        workspace_dir: Path,
        ledger: AuditLedger,
    ) -> None:
        self.evidence_dir = Path(evidence_dir).resolve()
        self.workspace_dir = Path(workspace_dir).resolve()
        self.ledger = ledger
        self.file_hashes: dict[str, str] = {}
        self._initialized = False

    def _hash_file(self, path: Path) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()

    def initialize(self) -> None:
        if not self.evidence_dir.exists():
            raise FileNotFoundError(f"Evidence directory not found: {self.evidence_dir}")
        self.workspace_dir.mkdir(parents=True, exist_ok=True)

        for path in sorted(self.evidence_dir.rglob("*")):
            if path.is_file():
                file_hash = self._hash_file(path)
                rel_name = path.name
                self.file_hashes[rel_name] = file_hash
                self.ledger.append("evidence_hash", {
                    "file": rel_name,
                    "path": str(path),
                    "hash": file_hash,
                    "size": path.stat().st_size,
                })

        self._initialized = True
        self.ledger.append("case_event", {
            "action": "vault_initialized",
            "evidence_count": len(self.file_hashes),
        })

    def verify_integrity(self) -> bool:
        for path in self.evidence_dir.rglob("*"):
            if path.is_file():
                current_hash = self._hash_file(path)
                if self.file_hashes.get(path.name) != current_hash:
                    return False
        return True

    def list_files(self) -> list[dict[str, Any]]:
        files = []
        for path in sorted(self.evidence_dir.rglob("*")):
            if path.is_file():
                files.append({
                    "name": path.name,
                    "path": str(path),
                    "size": path.stat().st_size,
                    "hash": self.file_hashes.get(path.name, "unknown"),
                })
        return files

    def is_path_allowed(self, path: str) -> bool:
        resolved = Path(path).resolve()
        return (
            str(resolved).startswith(str(self.evidence_dir))
            or str(resolved).startswith(str(self.workspace_dir))
        )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/jiaweiyu/workfiles/hackthron-june && python -m pytest tests/test_vault.py -v`

Expected: All 7 tests PASS

- [ ] **Step 5: Commit**

```bash
git add src/findevil/vault/evidence.py tests/test_vault.py
git commit -m "feat: add evidence vault with hash integrity and path boundaries"
```

---

### Task 5: Tool Registry and Security

**Files:**
- Create: `src/findevil/tools/registry.py`
- Create: `tests/test_registry.py`

- [ ] **Step 1: Write failing tests for tool registry**

```python
# tests/test_registry.py
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Users/jiaweiyu/workfiles/hackthron-june && python -m pytest tests/test_registry.py -v`

Expected: FAIL — cannot import `ToolRegistry`

- [ ] **Step 3: Implement tool registry**

```python
# src/findevil/tools/registry.py
from __future__ import annotations

import re
from dataclasses import dataclass


class CommandValidationError(Exception):
    pass


@dataclass
class ToolDefinition:
    name: str
    binary: str
    description: str
    allowed_args_pattern: str | None = None


ALLOWED_TOOLS: dict[str, ToolDefinition] = {
    "vol": ToolDefinition("vol", "vol", "Volatility 3 memory forensics framework"),
    "fls": ToolDefinition("fls", "fls", "Sleuth Kit file listing"),
    "icat": ToolDefinition("icat", "icat", "Sleuth Kit file extraction by inode"),
    "mmls": ToolDefinition("mmls", "mmls", "Sleuth Kit partition table display"),
    "img_stat": ToolDefinition("img_stat", "img_stat", "Sleuth Kit image info"),
    "log2timeline": ToolDefinition("log2timeline", "log2timeline.py", "Plaso super-timeline"),
    "psort": ToolDefinition("psort", "psort.py", "Plaso timeline sorting/filtering"),
    "hayabusa": ToolDefinition("hayabusa", "hayabusa", "Windows EVTX analysis with Sigma"),
    "yara": ToolDefinition("yara", "yara", "YARA pattern matching"),
    "regripper": ToolDefinition("regripper", "rip.pl", "Registry analysis"),
    "mftecmd": ToolDefinition("mftecmd", "MFTECmd", "MFT parser"),
    "pecmd": ToolDefinition("pecmd", "PECmd", "Prefetch parser"),
    "amcacheparser": ToolDefinition("amcacheparser", "AmcacheParser", "Amcache parser"),
    "strings": ToolDefinition("strings", "strings", "Extract printable strings"),
    "sha256sum": ToolDefinition("sha256sum", "sha256sum", "Compute SHA-256 hash"),
}

BLOCKED_COMMANDS = frozenset({
    "rm", "rmdir", "dd", "mkfs", "fdisk", "shred",
    "chmod", "chown", "mount", "umount", "kill",
    "reboot", "shutdown", "poweroff", "curl", "wget",
    "nc", "ncat", "python", "python3", "bash", "sh",
    "perl", "ruby", "pip", "apt", "yum",
})

SHELL_METACHARS = re.compile(r"[;&|`$(){}]")

ALLOWED_PATHS = ("/evidence", "/workspace")


class ToolRegistry:
    def validate(self, command: str, args: list[str]) -> None:
        if command in BLOCKED_COMMANDS:
            raise CommandValidationError(
                f"Command '{command}' is blocked: destructive or dangerous operation"
            )

        if command not in ALLOWED_TOOLS:
            raise CommandValidationError(
                f"Command '{command}' is not in the allowed tools list"
            )

        full_args = " ".join(args)
        if SHELL_METACHARS.search(full_args):
            raise CommandValidationError(
                f"Shell metacharacter injection detected in arguments: {full_args}"
            )

        for arg in args:
            if arg.startswith("/") and not arg.startswith(ALLOWED_PATHS):
                resolved = arg.replace("/..", "")
                if not resolved.startswith(ALLOWED_PATHS):
                    raise CommandValidationError(
                        f"Path '{arg}' is outside the allowed boundary "
                        f"(must be under {ALLOWED_PATHS})"
                    )

    def get_tool_info(self, name: str) -> dict[str, str] | None:
        tool = ALLOWED_TOOLS.get(name)
        if tool is None:
            return None
        return {
            "name": tool.name,
            "binary": tool.binary,
            "description": tool.description,
        }

    def list_tools(self) -> list[dict[str, str]]:
        return [
            {"name": t.name, "binary": t.binary, "description": t.description}
            for t in ALLOWED_TOOLS.values()
        ]
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/jiaweiyu/workfiles/hackthron-june && python -m pytest tests/test_registry.py -v`

Expected: All 8 tests PASS

- [ ] **Step 5: Commit**

```bash
git add src/findevil/tools/registry.py tests/test_registry.py
git commit -m "feat: add tool registry with allowlist, blocklist, and injection detection"
```

---

### Task 6: Docker Executor

**Files:**
- Create: `src/findevil/tools/executor.py`
- Create: `tests/test_executor.py`

- [ ] **Step 1: Write failing tests for executor**

```python
# tests/test_executor.py
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Users/jiaweiyu/workfiles/hackthron-june && python -m pytest tests/test_executor.py -v`

Expected: FAIL — cannot import `DockerExecutor`

- [ ] **Step 3: Implement the docker executor**

```python
# src/findevil/tools/executor.py
from __future__ import annotations

import hashlib
import subprocess
import time
from dataclasses import dataclass, field

from findevil.audit.ledger import AuditLedger
from findevil.tools.registry import ToolRegistry


class ToolExecutionError(Exception):
    pass


@dataclass
class ExecutionResult:
    run_id: str
    tool: str
    command: str
    args: list[str]
    exit_code: int
    stdout: str
    stderr: str
    stdout_hash: str
    duration_ms: int


class DockerExecutor:
    def __init__(
        self,
        container_name: str,
        registry: ToolRegistry,
        ledger: AuditLedger,
        timeout: int = 300,
        max_retries: int = 2,
    ) -> None:
        self.container_name = container_name
        self.registry = registry
        self.ledger = ledger
        self.timeout = timeout
        self.max_retries = max_retries
        self._run_counter = 0

    def _next_run_id(self) -> str:
        self._run_counter += 1
        return f"run-{self._run_counter:04d}"

    def execute(
        self,
        tool: str,
        args: list[str],
        retry_count: int = 0,
    ) -> ExecutionResult:
        self.registry.validate(tool, args)

        tool_info = self.registry.get_tool_info(tool)
        binary = tool_info["binary"] if tool_info else tool

        docker_cmd = [
            "docker", "exec", self.container_name,
            binary, *args,
        ]

        run_id = self._next_run_id()
        start = time.monotonic()

        try:
            proc = subprocess.run(
                docker_cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )
        except subprocess.TimeoutExpired:
            duration_ms = int((time.monotonic() - start) * 1000)
            self.ledger.append("tool_call", {
                "run_id": run_id,
                "tool": tool,
                "command": " ".join(docker_cmd),
                "exit_code": -1,
                "error": "timed_out",
                "duration_ms": duration_ms,
            })
            raise ToolExecutionError(
                f"Tool '{tool}' timed out after {self.timeout}s"
            )

        duration_ms = int((time.monotonic() - start) * 1000)
        stdout_hash = hashlib.sha256(proc.stdout.encode()).hexdigest()

        result = ExecutionResult(
            run_id=run_id,
            tool=tool,
            command=" ".join(docker_cmd),
            args=args,
            exit_code=proc.returncode,
            stdout=proc.stdout,
            stderr=proc.stderr,
            stdout_hash=stdout_hash,
            duration_ms=duration_ms,
        )

        self.ledger.append("tool_call", {
            "run_id": run_id,
            "tool": tool,
            "command": result.command,
            "args": args,
            "exit_code": result.exit_code,
            "stdout_hash": stdout_hash,
            "stderr_snippet": proc.stderr[:500] if proc.stderr else "",
            "duration_ms": duration_ms,
        })

        return result
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/jiaweiyu/workfiles/hackthron-june && python -m pytest tests/test_executor.py -v`

Expected: All 6 tests PASS

- [ ] **Step 5: Commit**

```bash
git add src/findevil/tools/executor.py tests/test_executor.py
git commit -m "feat: add docker executor with timeout, audit logging, and security validation"
```

---

### Task 7: Contract Compiler

**Files:**
- Create: `src/findevil/contracts/compiler.py`
- Create: `src/findevil/contracts/policies.py`
- Create: `tests/test_compiler.py`

- [ ] **Step 1: Write failing tests for the contract compiler**

```python
# tests/test_compiler.py
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Users/jiaweiyu/workfiles/hackthron-june && python -m pytest tests/test_compiler.py -v`

Expected: FAIL — cannot import `ContractCompiler`

- [ ] **Step 3: Implement contract compiler and policies**

```python
# src/findevil/contracts/policies.py
from __future__ import annotations

CORROBORATION_POLICIES: dict[str, dict] = {
    "persistence": {
        "description": "Persistence claims require >=2 artifact types",
        "min_sources": 2,
        "mitre_tactics": ["TA0003"],
        "mitre_techniques_prefix": ["T1547", "T1053", "T1543", "T1546"],
    },
    "lateral_movement": {
        "description": "Lateral movement requires network + auth evidence",
        "min_sources": 2,
        "mitre_tactics": ["TA0008"],
        "mitre_techniques_prefix": ["T1021", "T1570"],
    },
    "exfiltration": {
        "description": "Exfiltration requires staging + transfer evidence",
        "min_sources": 2,
        "mitre_tactics": ["TA0010"],
        "mitre_techniques_prefix": ["T1041", "T1048", "T1567"],
    },
}


def get_min_sources_for_technique(technique: str) -> int:
    for policy in CORROBORATION_POLICIES.values():
        for prefix in policy["mitre_techniques_prefix"]:
            if technique.startswith(prefix):
                return policy["min_sources"]
    return 1
```

```python
# src/findevil/contracts/compiler.py
from __future__ import annotations

from dataclasses import dataclass

from findevil.audit.ledger import AuditLedger
from findevil.contracts.models import EvidenceStatus, Finding


@dataclass
class ContractViolation:
    finding_id: str
    rule: str
    message: str


class ContractCompiler:
    def __init__(self, ledger: AuditLedger) -> None:
        self.ledger = ledger

    def _get_valid_run_ids(self) -> set[str]:
        events = self.ledger.query(event_type="tool_call")
        return {e["data"]["run_id"] for e in events if "run_id" in e["data"]}

    def validate(self, finding: Finding) -> None:
        violations = self._check(finding)
        if violations:
            raise violations[0]

    def _check(self, finding: Finding) -> list[ContractViolation]:
        violations = []
        valid_run_ids = self._get_valid_run_ids()

        for ev in finding.evidence:
            if ev.tool_run_id not in valid_run_ids:
                violations.append(ContractViolation(
                    finding_id=finding.finding_id,
                    rule="evidence_traceability",
                    message=f"Evidence run_id '{ev.tool_run_id}' not found in audit ledger",
                ))

        if finding.status == EvidenceStatus.CONFIRMED:
            source_files = {e.source_file for e in finding.evidence}
            if len(source_files) < 2:
                violations.append(ContractViolation(
                    finding_id=finding.finding_id,
                    rule="confirmed_requires_multiple_sources",
                    message=(
                        f"CONFIRMED status requires >=2 independent evidence sources, "
                        f"got {len(source_files)}"
                    ),
                ))

        if finding.status == EvidenceStatus.CONFIRMED and finding.contradictions:
            violations.append(ContractViolation(
                finding_id=finding.finding_id,
                rule="contradictions_block_confirmed",
                message="Finding has contradictions and cannot be CONFIRMED",
            ))

        if finding.status == EvidenceStatus.INFERRED and not finding.confidence_basis.strip():
            violations.append(ContractViolation(
                finding_id=finding.finding_id,
                rule="inferred_requires_basis",
                message="INFERRED findings must have a non-empty confidence_basis",
            ))

        return violations

    def compile(self, findings: list[Finding]) -> list[ContractViolation]:
        all_violations = []
        for finding in findings:
            all_violations.extend(self._check(finding))
        return all_violations
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/jiaweiyu/workfiles/hackthron-june && python -m pytest tests/test_compiler.py -v`

Expected: All 8 tests PASS

- [ ] **Step 5: Commit**

```bash
git add src/findevil/contracts/compiler.py src/findevil/contracts/policies.py tests/test_compiler.py
git commit -m "feat: add contract compiler that rejects uncited or inconsistent findings"
```

---

### Task 8: Self-Correction Engine

**Files:**
- Create: `src/findevil/correction/engine.py`
- Create: `tests/test_correction.py`

- [ ] **Step 1: Write failing tests**

```python
# tests/test_correction.py
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Users/jiaweiyu/workfiles/hackthron-june && python -m pytest tests/test_correction.py -v`

Expected: FAIL — cannot import `CorrectionEngine`

- [ ] **Step 3: Implement self-correction engine**

```python
# src/findevil/correction/engine.py
from __future__ import annotations

from findevil.audit.ledger import AuditLedger
from findevil.contracts.compiler import ContractCompiler
from findevil.contracts.models import (
    CorrectionRecord,
    Evidence,
    EvidenceStatus,
    Finding,
)

DOWNGRADE_MAP: dict[EvidenceStatus, EvidenceStatus] = {
    EvidenceStatus.CONFIRMED: EvidenceStatus.PROBABLE,
    EvidenceStatus.PROBABLE: EvidenceStatus.INFERRED,
    EvidenceStatus.INFERRED: EvidenceStatus.UNKNOWN,
}


class CorrectionEngine:
    def __init__(self, ledger: AuditLedger, compiler: ContractCompiler) -> None:
        self.ledger = ledger
        self.compiler = compiler

    def add_contradiction(
        self,
        finding: Finding,
        contradiction: Evidence,
        reason: str,
    ) -> Finding:
        old_status = finding.status
        new_status = DOWNGRADE_MAP.get(old_status, EvidenceStatus.UNKNOWN)

        correction = CorrectionRecord(
            correction_type="contradiction",
            reason=reason,
            before_status=old_status,
            after_status=new_status,
            finding_id=finding.finding_id,
        )

        updated = finding.model_copy(update={
            "status": new_status,
            "contradictions": [*finding.contradictions, contradiction],
            "correction_history": [*finding.correction_history, correction],
            "confidence_basis": f"{finding.confidence_basis} [DOWNGRADED: {reason}]",
        })

        self.ledger.append("correction", {
            "finding_id": finding.finding_id,
            "correction_type": "contradiction",
            "reason": reason,
            "before_status": old_status.value,
            "after_status": new_status.value,
        })

        return updated

    def fix_contract_violation(self, finding: Finding) -> Finding:
        violations = self.compiler._check(finding)
        if not violations:
            return finding

        old_status = finding.status
        new_status = DOWNGRADE_MAP.get(old_status, EvidenceStatus.UNKNOWN)
        reason = "; ".join(v.message for v in violations)

        correction = CorrectionRecord(
            correction_type="contract_violation",
            reason=reason,
            before_status=old_status,
            after_status=new_status,
            finding_id=finding.finding_id,
        )

        updated = finding.model_copy(update={
            "status": new_status,
            "correction_history": [*finding.correction_history, correction],
            "confidence_basis": f"{finding.confidence_basis} [CONTRACT FIX: {reason}]",
        })

        self.ledger.append("correction", {
            "finding_id": finding.finding_id,
            "correction_type": "contract_violation",
            "reason": reason,
            "before_status": old_status.value,
            "after_status": new_status.value,
        })

        return updated

    def record_tool_failure(
        self,
        tool: str,
        args: list[str],
        error: str,
        suggested_alternative: str | None = None,
    ) -> None:
        self.ledger.append("correction", {
            "correction_type": "tool_failure",
            "tool": tool,
            "args": args,
            "error": error,
            "suggested_alternative": suggested_alternative,
        })
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/jiaweiyu/workfiles/hackthron-june && python -m pytest tests/test_correction.py -v`

Expected: All 4 tests PASS

- [ ] **Step 5: Commit**

```bash
git add src/findevil/correction/engine.py tests/test_correction.py
git commit -m "feat: add self-correction engine with contradiction and contract violation handling"
```

---

### Task 9: Forensic Tool Modules

**Files:**
- Create: `src/findevil/tools/volatility.py`
- Create: `src/findevil/tools/sleuthkit.py`
- Create: `src/findevil/tools/hayabusa.py`
- Create: `src/findevil/tools/yara_scanner.py`
- Create: `src/findevil/tools/plaso.py`
- Create: `src/findevil/tools/zimmerman.py`

Each module provides a high-level function that builds the correct command-line arguments for the executor. No tests needed here since these are thin wrappers — the executor + registry already validate and log everything.

- [ ] **Step 1: Implement volatility module**

```python
# src/findevil/tools/volatility.py
from __future__ import annotations

from findevil.tools.executor import DockerExecutor, ExecutionResult

PLUGINS = {
    "pslist": "windows.pslist.PsList",
    "psscan": "windows.psscan.PsScan",
    "netscan": "windows.netscan.NetScan",
    "malfind": "windows.malfind.Malfind",
    "cmdline": "windows.cmdline.CmdLine",
    "filescan": "windows.filescan.FileScan",
    "dlllist": "windows.dlllist.DllList",
    "handles": "windows.handles.Handles",
    "svcscan": "windows.svcscan.SvcScan",
    "hivelist": "windows.registry.hivelist.HiveList",
}


def run_plugin(
    executor: DockerExecutor,
    dump_path: str,
    plugin: str,
    extra_args: list[str] | None = None,
) -> ExecutionResult:
    plugin_class = PLUGINS.get(plugin, plugin)
    args = ["-f", dump_path, plugin_class]
    if extra_args:
        args.extend(extra_args)
    return executor.execute("vol", args)


def list_plugins() -> list[dict[str, str]]:
    return [{"name": k, "class": v} for k, v in PLUGINS.items()]
```

- [ ] **Step 2: Implement sleuthkit module**

```python
# src/findevil/tools/sleuthkit.py
from __future__ import annotations

from findevil.tools.executor import DockerExecutor, ExecutionResult


def list_files(
    executor: DockerExecutor,
    image_path: str,
    offset: int | None = None,
    path: str = "/",
    recursive: bool = False,
) -> ExecutionResult:
    args = []
    if offset is not None:
        args.extend(["-o", str(offset)])
    if recursive:
        args.append("-r")
    args.extend([image_path, path])
    return executor.execute("fls", args)


def extract_file(
    executor: DockerExecutor,
    image_path: str,
    inode: str,
    offset: int | None = None,
) -> ExecutionResult:
    args = []
    if offset is not None:
        args.extend(["-o", str(offset)])
    args.extend([image_path, inode])
    return executor.execute("icat", args)


def partition_table(
    executor: DockerExecutor,
    image_path: str,
) -> ExecutionResult:
    return executor.execute("mmls", [image_path])


def image_info(
    executor: DockerExecutor,
    image_path: str,
) -> ExecutionResult:
    return executor.execute("img_stat", [image_path])
```

- [ ] **Step 3: Implement hayabusa module**

```python
# src/findevil/tools/hayabusa.py
from __future__ import annotations

from findevil.tools.executor import DockerExecutor, ExecutionResult


def scan_evtx(
    executor: DockerExecutor,
    evtx_path: str,
    output_path: str = "/workspace/hayabusa_results.csv",
    min_level: str = "medium",
) -> ExecutionResult:
    args = [
        "csv-timeline",
        "-d", evtx_path,
        "-o", output_path,
        "--min-level", min_level,
        "-q",
    ]
    return executor.execute("hayabusa", args)


def logon_summary(
    executor: DockerExecutor,
    evtx_path: str,
    output_path: str = "/workspace/logon_summary.csv",
) -> ExecutionResult:
    args = [
        "logon-summary",
        "-d", evtx_path,
        "-o", output_path,
    ]
    return executor.execute("hayabusa", args)
```

- [ ] **Step 4: Implement yara_scanner module**

```python
# src/findevil/tools/yara_scanner.py
from __future__ import annotations

from findevil.tools.executor import DockerExecutor, ExecutionResult


def scan(
    executor: DockerExecutor,
    rules_path: str,
    target_path: str,
    recursive: bool = True,
) -> ExecutionResult:
    args = []
    if recursive:
        args.append("-r")
    args.extend([rules_path, target_path])
    return executor.execute("yara", args)
```

- [ ] **Step 5: Implement plaso module**

```python
# src/findevil/tools/plaso.py
from __future__ import annotations

from findevil.tools.executor import DockerExecutor, ExecutionResult


def create_timeline(
    executor: DockerExecutor,
    source_path: str,
    output_path: str = "/workspace/timeline.plaso",
) -> ExecutionResult:
    args = [
        "--status_view", "none",
        source_path,
        output_path,
    ]
    return executor.execute("log2timeline", args)


def sort_timeline(
    executor: DockerExecutor,
    plaso_path: str,
    output_path: str = "/workspace/timeline.csv",
    time_filter: str | None = None,
) -> ExecutionResult:
    args = [
        "-o", "l2tcsv",
        "-w", output_path,
        plaso_path,
    ]
    if time_filter:
        args.extend(["--slice", time_filter])
    return executor.execute("psort", args)
```

- [ ] **Step 6: Implement zimmerman module**

```python
# src/findevil/tools/zimmerman.py
from __future__ import annotations

from findevil.tools.executor import DockerExecutor, ExecutionResult


def parse_mft(
    executor: DockerExecutor,
    mft_path: str,
    output_path: str = "/workspace/mft_output.csv",
) -> ExecutionResult:
    args = ["-f", mft_path, "--csv", output_path]
    return executor.execute("mftecmd", args)


def parse_prefetch(
    executor: DockerExecutor,
    prefetch_dir: str,
    output_path: str = "/workspace/prefetch_output.csv",
) -> ExecutionResult:
    args = ["-d", prefetch_dir, "--csv", output_path]
    return executor.execute("pecmd", args)


def parse_amcache(
    executor: DockerExecutor,
    amcache_path: str,
    output_path: str = "/workspace/amcache_output.csv",
) -> ExecutionResult:
    args = ["-f", amcache_path, "--csv", output_path]
    return executor.execute("amcacheparser", args)


def analyze_registry(
    executor: DockerExecutor,
    hive_path: str,
    plugin: str | None = None,
) -> ExecutionResult:
    args = ["-r", hive_path]
    if plugin:
        args.extend(["-p", plugin])
    return executor.execute("regripper", args)
```

- [ ] **Step 7: Commit**

```bash
git add src/findevil/tools/volatility.py src/findevil/tools/sleuthkit.py \
  src/findevil/tools/hayabusa.py src/findevil/tools/yara_scanner.py \
  src/findevil/tools/plaso.py src/findevil/tools/zimmerman.py
git commit -m "feat: add forensic tool modules wrapping Volatility, Sleuth Kit, Hayabusa, YARA, Plaso, Zimmerman"
```

---

### Task 10: MCP Server

**Files:**
- Create: `src/findevil/server.py`

This is the central integration point. It wires together the vault, executor, contracts, correction engine, and audit ledger into MCP tool calls.

- [ ] **Step 1: Implement the MCP server**

```python
# src/findevil/server.py
from __future__ import annotations

import json
from pathlib import Path

from fastmcp import FastMCP

from findevil.audit.ledger import AuditLedger
from findevil.contracts.compiler import ContractCompiler
from findevil.contracts.models import Evidence, EvidenceStatus, Finding
from findevil.correction.engine import CorrectionEngine
from findevil.tools.executor import DockerExecutor, ToolExecutionError
from findevil.tools.registry import ToolRegistry
from findevil.vault.evidence import EvidenceVault
from findevil.tools import volatility, sleuthkit, hayabusa, yara_scanner, plaso, zimmerman

mcp = FastMCP(
    "findevil",
    description="Evidence-Contract Autonomous IR Agent for SANS FIND EVIL! Hackathon",
)

_state: dict = {}


def _get_state():
    return _state


# --- Investigation Management ---

@mcp.tool()
def investigate_case(evidence_path: str, workspace_path: str = "./workspace") -> str:
    """Initialize a new investigation. Hashes all evidence files and creates a secure workspace."""
    ledger = AuditLedger(Path(workspace_path) / "audit.jsonl")
    vault = EvidenceVault(
        evidence_dir=Path(evidence_path),
        workspace_dir=Path(workspace_path),
        ledger=ledger,
    )
    vault.initialize()
    registry = ToolRegistry()
    executor = DockerExecutor(
        container_name="findevil-sift",
        registry=registry,
        ledger=ledger,
    )
    compiler = ContractCompiler(ledger=ledger)
    correction = CorrectionEngine(ledger=ledger, compiler=compiler)

    _state.update({
        "vault": vault,
        "ledger": ledger,
        "executor": executor,
        "compiler": compiler,
        "correction": correction,
        "findings": {},
        "finding_counter": 0,
    })

    files = vault.list_files()
    ledger.append("case_event", {"action": "investigation_started", "evidence_count": len(files)})
    return json.dumps({
        "status": "initialized",
        "evidence_files": files,
        "evidence_count": len(files),
    }, indent=2)


@mcp.tool()
def get_case_status() -> str:
    """Get current investigation status: evidence files, findings count, corrections made."""
    s = _get_state()
    findings = s.get("findings", {})
    ledger = s.get("ledger")
    corrections = ledger.query(event_type="correction") if ledger else []
    tool_calls = ledger.query(event_type="tool_call") if ledger else []
    return json.dumps({
        "findings_count": len(findings),
        "findings_by_status": _count_by_status(findings),
        "tool_calls": len(tool_calls),
        "corrections": len(corrections),
    }, indent=2)


@mcp.tool()
def list_evidence() -> str:
    """List all available evidence files with types and sizes."""
    vault = _get_state().get("vault")
    if not vault:
        return json.dumps({"error": "No case initialized. Call investigate_case first."})
    return json.dumps(vault.list_files(), indent=2)


# --- Forensic Analysis Tools ---

@mcp.tool()
def analyze_memory(dump_path: str, plugin: str, extra_args: str = "") -> str:
    """Run a Volatility 3 plugin against a memory dump.
    
    Available plugins: pslist, psscan, netscan, malfind, cmdline, filescan, dlllist, handles, svcscan, hivelist.
    """
    executor = _get_state().get("executor")
    if not executor:
        return json.dumps({"error": "No case initialized."})
    try:
        extras = extra_args.split() if extra_args else None
        result = volatility.run_plugin(executor, dump_path, plugin, extras)
        return json.dumps({
            "run_id": result.run_id,
            "exit_code": result.exit_code,
            "output": result.stdout[:10000],
            "stderr": result.stderr[:2000] if result.stderr else "",
        }, indent=2)
    except (ToolExecutionError, Exception) as e:
        _get_state()["correction"].record_tool_failure(
            tool="vol", args=[dump_path, plugin], error=str(e),
        )
        return json.dumps({"error": str(e), "suggestion": "Try a different plugin or check the dump path"})


@mcp.tool()
def build_timeline(source_path: str, output_path: str = "/workspace/timeline.plaso") -> str:
    """Build a super-timeline from evidence using Plaso/log2timeline."""
    executor = _get_state().get("executor")
    if not executor:
        return json.dumps({"error": "No case initialized."})
    try:
        result = plaso.create_timeline(executor, source_path, output_path)
        return json.dumps({
            "run_id": result.run_id,
            "exit_code": result.exit_code,
            "output": result.stdout[:10000],
        }, indent=2)
    except (ToolExecutionError, Exception) as e:
        _get_state()["correction"].record_tool_failure(
            tool="log2timeline", args=[source_path], error=str(e),
        )
        return json.dumps({"error": str(e)})


@mcp.tool()
def analyze_filesystem(image_path: str, operation: str = "list", inode: str = "", offset: int = -1) -> str:
    """Analyze disk image using Sleuth Kit. Operations: list, extract, partitions, info."""
    executor = _get_state().get("executor")
    if not executor:
        return json.dumps({"error": "No case initialized."})
    off = offset if offset >= 0 else None
    try:
        if operation == "list":
            result = sleuthkit.list_files(executor, image_path, offset=off, recursive=True)
        elif operation == "extract":
            result = sleuthkit.extract_file(executor, image_path, inode, offset=off)
        elif operation == "partitions":
            result = sleuthkit.partition_table(executor, image_path)
        elif operation == "info":
            result = sleuthkit.image_info(executor, image_path)
        else:
            return json.dumps({"error": f"Unknown operation: {operation}"})
        return json.dumps({
            "run_id": result.run_id,
            "exit_code": result.exit_code,
            "output": result.stdout[:10000],
        }, indent=2)
    except (ToolExecutionError, Exception) as e:
        _get_state()["correction"].record_tool_failure(
            tool="sleuthkit", args=[image_path, operation], error=str(e),
        )
        return json.dumps({"error": str(e)})


@mcp.tool()
def scan_eventlogs(evtx_path: str, min_level: str = "medium") -> str:
    """Scan Windows EVTX event logs using Hayabusa with Sigma rules."""
    executor = _get_state().get("executor")
    if not executor:
        return json.dumps({"error": "No case initialized."})
    try:
        result = hayabusa.scan_evtx(executor, evtx_path, min_level=min_level)
        return json.dumps({
            "run_id": result.run_id,
            "exit_code": result.exit_code,
            "output": result.stdout[:10000],
        }, indent=2)
    except (ToolExecutionError, Exception) as e:
        _get_state()["correction"].record_tool_failure(
            tool="hayabusa", args=[evtx_path], error=str(e),
        )
        return json.dumps({"error": str(e)})


@mcp.tool()
def scan_yara(rules_path: str, target_path: str) -> str:
    """Scan files or memory dumps with YARA rules for malware signatures."""
    executor = _get_state().get("executor")
    if not executor:
        return json.dumps({"error": "No case initialized."})
    try:
        result = yara_scanner.scan(executor, rules_path, target_path)
        return json.dumps({
            "run_id": result.run_id,
            "exit_code": result.exit_code,
            "output": result.stdout[:10000],
        }, indent=2)
    except (ToolExecutionError, Exception) as e:
        _get_state()["correction"].record_tool_failure(
            tool="yara", args=[rules_path, target_path], error=str(e),
        )
        return json.dumps({"error": str(e)})


@mcp.tool()
def analyze_registry(hive_path: str, plugin: str = "") -> str:
    """Analyze Windows registry hive using RegRipper."""
    executor = _get_state().get("executor")
    if not executor:
        return json.dumps({"error": "No case initialized."})
    try:
        result = zimmerman.analyze_registry(executor, hive_path, plugin or None)
        return json.dumps({
            "run_id": result.run_id,
            "exit_code": result.exit_code,
            "output": result.stdout[:10000],
        }, indent=2)
    except (ToolExecutionError, Exception) as e:
        _get_state()["correction"].record_tool_failure(
            tool="regripper", args=[hive_path], error=str(e),
        )
        return json.dumps({"error": str(e)})


@mcp.tool()
def analyze_artifacts(artifact_type: str, path: str) -> str:
    """Parse Windows artifacts: mft, prefetch, amcache."""
    executor = _get_state().get("executor")
    if not executor:
        return json.dumps({"error": "No case initialized."})
    try:
        if artifact_type == "mft":
            result = zimmerman.parse_mft(executor, path)
        elif artifact_type == "prefetch":
            result = zimmerman.parse_prefetch(executor, path)
        elif artifact_type == "amcache":
            result = zimmerman.parse_amcache(executor, path)
        else:
            return json.dumps({"error": f"Unknown artifact type: {artifact_type}"})
        return json.dumps({
            "run_id": result.run_id,
            "exit_code": result.exit_code,
            "output": result.stdout[:10000],
        }, indent=2)
    except (ToolExecutionError, Exception) as e:
        _get_state()["correction"].record_tool_failure(
            tool=artifact_type, args=[path], error=str(e),
        )
        return json.dumps({"error": str(e)})


# --- Evidence Contract Tools ---

@mcp.tool()
def submit_finding(
    claim: str,
    status: str,
    mitre_technique: str,
    confidence_basis: str,
    evidence_items: str,
) -> str:
    """Submit a finding through the evidence contract compiler.
    
    Status must be one of: confirmed, probable, inferred, unknown.
    evidence_items is a JSON array of objects with: artifact_id, tool_run_id, source_file, content_hash, excerpt.
    The compiler will reject findings that violate evidence contract rules.
    """
    s = _get_state()
    compiler = s.get("compiler")
    correction = s.get("correction")
    ledger = s.get("ledger")
    if not compiler:
        return json.dumps({"error": "No case initialized."})

    try:
        ev_list = json.loads(evidence_items)
    except json.JSONDecodeError:
        return json.dumps({"error": "evidence_items must be valid JSON array"})

    s["finding_counter"] = s.get("finding_counter", 0) + 1
    fid = f"F-{s['finding_counter']:03d}"

    evidence = [Evidence(**e) for e in ev_list]

    finding = Finding(
        finding_id=fid,
        claim=claim,
        status=EvidenceStatus(status),
        mitre_technique=mitre_technique,
        evidence=evidence,
        confidence_basis=confidence_basis,
    )

    violations = compiler.compile([finding])
    if violations:
        finding = correction.fix_contract_violation(finding)
        ledger.append("finding_event", {
            "finding_id": fid,
            "action": "created_with_correction",
            "original_status": status,
            "corrected_status": finding.status.value,
            "violations": [v.message for v in violations],
        })
    else:
        ledger.append("finding_event", {
            "finding_id": fid,
            "action": "created",
            "status": finding.status.value,
        })

    s["findings"][fid] = finding

    return json.dumps({
        "finding_id": fid,
        "status": finding.status.value,
        "accepted": True,
        "corrections_applied": len(finding.correction_history),
        "claim": finding.claim,
    }, indent=2)


@mcp.tool()
def search_contradictions(finding_id: str) -> str:
    """Search for evidence that contradicts an existing finding. Returns contradiction candidates."""
    s = _get_state()
    finding = s.get("findings", {}).get(finding_id)
    if not finding:
        return json.dumps({"error": f"Finding {finding_id} not found"})

    return json.dumps({
        "finding_id": finding_id,
        "current_status": finding.status.value,
        "claim": finding.claim,
        "evidence_sources": [e.source_file for e in finding.evidence],
        "existing_contradictions": len(finding.contradictions),
        "instruction": (
            "To add a contradiction, use submit_finding with the contradicting evidence. "
            "The system will automatically downgrade the finding status."
        ),
    }, indent=2)


@mcp.tool()
def add_contradiction_to_finding(
    finding_id: str,
    artifact_id: str,
    tool_run_id: str,
    source_file: str,
    content_hash: str,
    excerpt: str,
    reason: str,
) -> str:
    """Add contradicting evidence to a finding, triggering automatic status downgrade."""
    s = _get_state()
    finding = s.get("findings", {}).get(finding_id)
    correction = s.get("correction")
    if not finding or not correction:
        return json.dumps({"error": f"Finding {finding_id} not found or no case initialized"})

    contra = Evidence(
        artifact_id=artifact_id,
        tool_run_id=tool_run_id,
        source_file=source_file,
        content_hash=content_hash,
        excerpt=excerpt,
    )

    updated = correction.add_contradiction(finding, contra, reason)
    s["findings"][finding_id] = updated

    return json.dumps({
        "finding_id": finding_id,
        "previous_status": finding.status.value,
        "new_status": updated.status.value,
        "contradiction_count": len(updated.contradictions),
        "correction_applied": True,
    }, indent=2)


# --- Audit and Reporting ---

@mcp.tool()
def trace_finding(finding_id: str) -> str:
    """Show the complete evidence chain for a finding: every tool call, evidence item, and correction."""
    s = _get_state()
    finding = s.get("findings", {}).get(finding_id)
    ledger = s.get("ledger")
    if not finding or not ledger:
        return json.dumps({"error": f"Finding {finding_id} not found"})

    run_ids = finding.tool_run_ids
    tool_calls = [
        e for e in ledger.query(event_type="tool_call")
        if e["data"].get("run_id") in run_ids
    ]
    finding_events = ledger.query(finding_id=finding_id)

    return json.dumps({
        "finding_id": finding_id,
        "claim": finding.claim,
        "status": finding.status.value,
        "mitre_technique": finding.mitre_technique,
        "evidence_chain": [
            {
                "artifact_id": e.artifact_id,
                "source_file": e.source_file,
                "tool_run_id": e.tool_run_id,
                "excerpt": e.excerpt,
            }
            for e in finding.evidence
        ],
        "contradictions": [
            {"source": c.source_file, "excerpt": c.excerpt}
            for c in finding.contradictions
        ],
        "tool_executions": tool_calls,
        "finding_events": finding_events,
        "corrections": [
            {
                "type": c.correction_type,
                "reason": c.reason,
                "before": c.before_status.value,
                "after": c.after_status.value,
            }
            for c in finding.correction_history
        ],
    }, indent=2, default=str)


@mcp.tool()
def generate_report(output_format: str = "json") -> str:
    """Generate the final investigation report. Format: json or markdown."""
    s = _get_state()
    findings = s.get("findings", {})
    ledger = s.get("ledger")
    vault = s.get("vault")
    compiler = s.get("compiler")
    if not ledger:
        return json.dumps({"error": "No case initialized."})

    violations = compiler.compile(list(findings.values())) if compiler else []

    if output_format == "json":
        return json.dumps({
            "findings": [f.model_dump(mode="json") for f in findings.values()],
            "violations": [{"finding": v.finding_id, "rule": v.rule, "msg": v.message} for v in violations],
            "stats": {
                "total_findings": len(findings),
                "by_status": _count_by_status(findings),
                "tool_calls": len(ledger.query(event_type="tool_call")),
                "corrections": len(ledger.query(event_type="correction")),
                "evidence_integrity": vault.verify_integrity() if vault else "unknown",
            },
        }, indent=2, default=str)
    else:
        return _generate_markdown_report(findings, ledger, vault)


@mcp.tool()
def get_audit_log(event_type: str = "", finding_id: str = "") -> str:
    """Query the audit ledger. Filter by event_type and/or finding_id."""
    ledger = _get_state().get("ledger")
    if not ledger:
        return json.dumps({"error": "No case initialized."})
    events = ledger.query(
        event_type=event_type or None,
        finding_id=finding_id or None,
    )
    return json.dumps(events[-50:], indent=2, default=str)


# --- Helpers ---

def _count_by_status(findings: dict) -> dict[str, int]:
    counts: dict[str, int] = {}
    for f in findings.values():
        s = f.status.value
        counts[s] = counts.get(s, 0) + 1
    return counts


def _generate_markdown_report(findings: dict, ledger, vault) -> str:
    lines = ["# Investigation Report", ""]
    lines.append("## Executive Summary")
    lines.append(f"- Total findings: {len(findings)}")
    lines.append(f"- Tool calls executed: {len(ledger.query(event_type='tool_call'))}")
    lines.append(f"- Self-corrections: {len(ledger.query(event_type='correction'))}")
    if vault:
        lines.append(f"- Evidence integrity: {'PASSED' if vault.verify_integrity() else 'FAILED'}")
    lines.append("")

    lines.append("## Findings")
    for f in findings.values():
        status_badge = f"[{f.status.value.upper()}]"
        lines.append(f"### {f.finding_id}: {f.claim} {status_badge}")
        lines.append(f"- MITRE ATT&CK: {f.mitre_technique}")
        lines.append(f"- Confidence: {f.confidence_basis}")
        lines.append("- Evidence:")
        for e in f.evidence:
            lines.append(f"  - `{e.source_file}` (run: {e.tool_run_id}): {e.excerpt}")
        if f.contradictions:
            lines.append("- Contradictions:")
            for c in f.contradictions:
                lines.append(f"  - `{c.source_file}`: {c.excerpt}")
        if f.correction_history:
            lines.append("- Corrections:")
            for cr in f.correction_history:
                lines.append(f"  - {cr.correction_type}: {cr.before_status.value} -> {cr.after_status.value} ({cr.reason})")
        lines.append("")

    lines.append("## Audit Trail Integrity")
    lines.append(f"- Hash chain valid: {ledger.verify_chain()}")
    lines.append(f"- Total audit events: {len(ledger.read_all())}")

    return "\n".join(lines)
```

- [ ] **Step 2: Verify MCP server loads**

Run: `cd /Users/jiaweiyu/workfiles/hackthron-june && python -c "from findevil.server import mcp; print(f'Tools: {len(mcp._tool_manager._tools)}')"`

Expected: `Tools: 16` (or similar count of registered tools)

- [ ] **Step 3: Commit**

```bash
git add src/findevil/server.py
git commit -m "feat: add FastMCP server wiring all components into 16 MCP tools"
```

---

### Task 11: Report Template

**Files:**
- Create: `src/findevil/report/templates/report.md.j2`
- Create: `src/findevil/report/generator.py`

- [ ] **Step 1: Create Jinja2 report template**

```jinja2
{# src/findevil/report/templates/report.md.j2 #}
# Incident Response Report

**Generated:** {{ timestamp }}
**Evidence Integrity:** {{ "PASSED" if integrity else "FAILED" }}

---

## Executive Summary

| Metric | Value |
|--------|-------|
| Total Findings | {{ findings | length }} |
| Confirmed | {{ findings | selectattr("status.value", "equalto", "confirmed") | list | length }} |
| Probable | {{ findings | selectattr("status.value", "equalto", "probable") | list | length }} |
| Inferred | {{ findings | selectattr("status.value", "equalto", "inferred") | list | length }} |
| Refuted | {{ findings | selectattr("status.value", "equalto", "refuted") | list | length }} |
| Tool Executions | {{ tool_call_count }} |
| Self-Corrections | {{ correction_count }} |

## Findings

{% for f in findings %}
### {{ f.finding_id }}: {{ f.claim }}

| Field | Value |
|-------|-------|
| Status | **{{ f.status.value | upper }}** |
| MITRE ATT&CK | {{ f.mitre_technique }} |
| Confidence Basis | {{ f.confidence_basis }} |

**Evidence:**
{% for e in f.evidence %}
- `{{ e.source_file }}` (run: {{ e.tool_run_id }}): {{ e.excerpt }}
{% endfor %}

{% if f.contradictions %}
**Contradictions:**
{% for c in f.contradictions %}
- `{{ c.source_file }}`: {{ c.excerpt }}
{% endfor %}
{% endif %}

{% if f.correction_history %}
**Correction History:**
{% for cr in f.correction_history %}
- {{ cr.correction_type }}: {{ cr.before_status.value }} → {{ cr.after_status.value }} — {{ cr.reason }}
{% endfor %}
{% endif %}

---

{% endfor %}

## Evidence Coverage Matrix

| Source | Analyzed | Tools Used |
|--------|----------|-----------|
{% for src in evidence_sources %}
| {{ src.name }} | {{ src.hash[:12] }}... | {{ src.tools | join(", ") if src.tools else "—" }} |
{% endfor %}

## Negative Findings

Items checked but no malicious activity found:
{% for nf in negative_findings %}
- {{ nf }}
{% endfor %}
{% if not negative_findings %}
- _(none recorded)_
{% endif %}

## Audit Trail

- Hash chain integrity: {{ "VALID" if chain_valid else "INVALID" }}
- Total events: {{ total_events }}
```

- [ ] **Step 2: Create report generator**

```python
# src/findevil/report/generator.py
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from findevil.audit.ledger import AuditLedger
from findevil.contracts.models import Finding
from findevil.vault.evidence import EvidenceVault


def generate_json_report(
    findings: dict[str, Finding],
    ledger: AuditLedger,
    vault: EvidenceVault | None,
    output_path: Path,
) -> Path:
    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "evidence_integrity": vault.verify_integrity() if vault else None,
        "findings": [f.model_dump(mode="json") for f in findings.values()],
        "statistics": {
            "total_findings": len(findings),
            "tool_calls": len(ledger.query(event_type="tool_call")),
            "corrections": len(ledger.query(event_type="correction")),
            "chain_valid": ledger.verify_chain(),
        },
    }
    output_path.write_text(json.dumps(report, indent=2, default=str))
    return output_path


def generate_markdown_report(
    findings: dict[str, Finding],
    ledger: AuditLedger,
    vault: EvidenceVault | None,
    output_path: Path,
) -> Path:
    template_dir = Path(__file__).parent / "templates"
    env = Environment(loader=FileSystemLoader(str(template_dir)))
    template = env.get_template("report.md.j2")

    tool_calls = ledger.query(event_type="tool_call")
    evidence_sources = []
    if vault:
        for f in vault.list_files():
            tools_used = [
                tc["data"]["tool"]
                for tc in tool_calls
                if f["name"] in " ".join(tc["data"].get("args", []))
            ]
            evidence_sources.append({**f, "tools": list(set(tools_used))})

    rendered = template.render(
        timestamp=datetime.now(timezone.utc).isoformat(),
        integrity=vault.verify_integrity() if vault else False,
        findings=list(findings.values()),
        tool_call_count=len(tool_calls),
        correction_count=len(ledger.query(event_type="correction")),
        evidence_sources=evidence_sources,
        negative_findings=[],
        chain_valid=ledger.verify_chain(),
        total_events=len(ledger.read_all()),
    )
    output_path.write_text(rendered)
    return output_path
```

- [ ] **Step 3: Commit**

```bash
git add src/findevil/report/generator.py src/findevil/report/templates/report.md.j2
git commit -m "feat: add Jinja2-based report generator with markdown and JSON output"
```

---

### Task 12: CLI

**Files:**
- Create: `src/findevil/cli.py`
- Create: `tests/test_cli.py`

- [ ] **Step 1: Write failing CLI tests**

```python
# tests/test_cli.py
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Users/jiaweiyu/workfiles/hackthron-june && pip install click && python -m pytest tests/test_cli.py -v`

Expected: FAIL — cannot import `cli`

- [ ] **Step 3: Implement CLI**

```python
# src/findevil/cli.py
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import click

from findevil.audit.ledger import AuditLedger


@click.group()
def cli():
    """FinDevil: Evidence-Contract Autonomous IR Agent"""
    pass


@cli.group()
def audit():
    """Audit ledger operations."""
    pass


@audit.command("verify")
@click.option("--ledger", required=True, type=click.Path(exists=True), help="Path to audit.jsonl")
def audit_verify(ledger: str):
    """Verify audit ledger hash chain integrity."""
    al = AuditLedger(Path(ledger))
    if al.verify_chain():
        events = al.read_all()
        click.echo(f"Hash chain: VALID ({len(events)} events)")
    else:
        click.echo("Hash chain: INVALID — possible tampering detected")


@cli.command()
@click.argument("finding_id")
@click.option("--ledger", required=True, type=click.Path(exists=True))
def trace(finding_id: str, ledger: str):
    """Show the complete evidence chain for a finding."""
    al = AuditLedger(Path(ledger))
    events = al.query(finding_id=finding_id)
    if not events:
        click.echo(f"No events found for {finding_id}")
        return
    click.echo(f"Evidence chain for {finding_id}:")
    click.echo(f"  Events: {len(events)}")
    for evt in events:
        click.echo(f"  [{evt['event_type']}] {evt['timestamp']} — {json.dumps(evt['data'], default=str)}")


@cli.command()
@click.argument("finding_id")
@click.option("--ledger", required=True, type=click.Path(exists=True))
def replay(finding_id: str, ledger: str):
    """Replay the tool execution sequence for a finding."""
    al = AuditLedger(Path(ledger))
    events = al.query(finding_id=finding_id)
    run_ids = set()
    for evt in events:
        if "run_id" in evt.get("data", {}):
            run_ids.add(evt["data"]["run_id"])

    tool_calls = al.query(event_type="tool_call")
    relevant = [tc for tc in tool_calls if tc["data"].get("run_id") in run_ids]

    click.echo(f"Tool execution replay for {finding_id}:")
    for tc in relevant:
        d = tc["data"]
        click.echo(f"  [{d.get('run_id')}] {d.get('tool')} — exit:{d.get('exit_code')} — {d.get('duration_ms', '?')}ms")
        if d.get("command"):
            click.echo(f"    cmd: {d['command']}")


@cli.command()
def doctor():
    """Check SIFT container health and tool availability."""
    click.echo("FinDevil Doctor")
    click.echo("=" * 40)

    docker = shutil.which("docker")
    if not docker:
        click.echo("[WARN] Docker not found in PATH")
    else:
        click.echo("[OK] Docker found")

    try:
        result = subprocess.run(
            ["docker", "ps", "--filter", "name=findevil-sift", "--format", "{{.Status}}"],
            capture_output=True, text=True, timeout=5,
        )
        if result.stdout.strip():
            click.echo(f"[OK] SIFT container: {result.stdout.strip()}")
        else:
            click.echo("[WARN] SIFT container not running. Start with: docker-compose up -d")
    except (subprocess.TimeoutExpired, FileNotFoundError):
        click.echo("[WARN] Cannot check Docker status")

    click.echo("=" * 40)


@cli.command()
@click.argument("case_dir", type=click.Path(exists=True))
@click.option("--ledger", required=True, type=click.Path(exists=True))
def bench(case_dir: str, ledger: str):
    """Run accuracy benchmark against a known case with ground truth."""
    ground_truth_path = Path(case_dir) / "ground_truth.json"
    if not ground_truth_path.exists():
        click.echo(f"No ground_truth.json found in {case_dir}")
        return

    gt = json.loads(ground_truth_path.read_text())
    al = AuditLedger(Path(ledger))
    finding_events = al.query(event_type="finding_event")

    click.echo(f"Benchmark: {case_dir}")
    click.echo(f"  Ground truth findings: {len(gt.get('expected_findings', []))}")
    click.echo(f"  Agent findings: {len(finding_events)}")
    click.echo("  (Detailed P/R/F1 scoring requires matching logic — run full evaluation)")
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/jiaweiyu/workfiles/hackthron-june && python -m pytest tests/test_cli.py -v`

Expected: All 3 tests PASS

- [ ] **Step 5: Commit**

```bash
git add src/findevil/cli.py tests/test_cli.py
git commit -m "feat: add CLI with audit verify, trace, replay, doctor, and bench commands"
```

---

### Task 13: Docker Configuration

**Files:**
- Create: `Dockerfile.sift`
- Create: `docker-compose.yml`

- [ ] **Step 1: Create Dockerfile.sift**

```dockerfile
# Dockerfile.sift
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    curl \
    git \
    python3 \
    python3-pip \
    sleuthkit \
    yara \
    libyara-dev \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install \
    volatility3 \
    plaso \
    dfvfs

RUN curl -sSL https://github.com/Yamato-Security/hayabusa/releases/latest/download/hayabusa-linux-x64-gnu.zip -o /tmp/hayabusa.zip \
    && apt-get update && apt-get install -y unzip \
    && unzip /tmp/hayabusa.zip -d /opt/hayabusa \
    && chmod +x /opt/hayabusa/hayabusa \
    && ln -s /opt/hayabusa/hayabusa /usr/local/bin/hayabusa \
    && rm /tmp/hayabusa.zip

RUN mkdir -p /evidence /workspace

VOLUME ["/evidence", "/workspace"]

CMD ["tail", "-f", "/dev/null"]
```

- [ ] **Step 2: Create docker-compose.yml**

```yaml
# docker-compose.yml
services:
  sift:
    container_name: findevil-sift
    build:
      context: .
      dockerfile: Dockerfile.sift
    volumes:
      - ./evidence:/evidence:ro
      - ./workspace:/workspace
    network_mode: none
    restart: unless-stopped
```

- [ ] **Step 3: Create evidence and workspace directories**

```bash
mkdir -p evidence workspace
```

- [ ] **Step 4: Commit**

```bash
git add Dockerfile.sift docker-compose.yml
git commit -m "feat: add Docker configuration for SIFT forensic tools container"
```

---

### Task 14: Claude Code Integration

**Files:**
- Create: `.claude/settings.json`
- Create: `CLAUDE.md`

- [ ] **Step 1: Create MCP server settings for Claude Code**

```json
{
  "mcpServers": {
    "findevil": {
      "command": "python",
      "args": ["-m", "findevil.server"],
      "cwd": "/Users/jiaweiyu/workfiles/hackthron-june"
    }
  }
}
```

Note: The exact path may need adjustment based on the user's setup. Alternatively, use `uv run` if using uv.

- [ ] **Step 2: Create CLAUDE.md with investigation guidance**

```markdown
# FinDevil: Evidence-Contract Autonomous IR Agent

## What This Is

An autonomous incident response agent. You (Claude Code) are the reasoning engine. The MCP server provides forensic tools, evidence contracts, and audit trails.

## Investigation Workflow

1. **Initialize**: Call `investigate_case` with the evidence directory path
2. **Triage**: Call `list_evidence` to see what's available
3. **Analyze**: Use forensic tools based on evidence types:
   - Memory dumps → `analyze_memory` (Volatility 3)
   - Disk images → `analyze_filesystem` (Sleuth Kit)
   - EVTX logs → `scan_eventlogs` (Hayabusa)
   - Registry hives → `analyze_registry` (RegRipper)
   - File scanning → `scan_yara` (YARA)
   - Timelines → `build_timeline` (Plaso)
   - Artifacts → `analyze_artifacts` (MFT, Prefetch, Amcache)
4. **Submit findings**: Call `submit_finding` — the contract compiler enforces evidence rules
5. **Self-correct**: If tools fail, try alternatives. If evidence contradicts, call `add_contradiction_to_finding`
6. **Report**: Call `generate_report` for the final output

## Rules

- Every finding MUST cite tool_run_ids from actual tool executions
- CONFIRMED status requires >=2 independent evidence sources
- If you find contradicting evidence, report it honestly via `add_contradiction_to_finding`
- When a tool fails, try an alternative before giving up
- Report what you checked but did NOT find (negative findings matter)
- Never claim certainty beyond what the evidence supports
```

- [ ] **Step 3: Add FastMCP __main__ entry point**

Add to the bottom of `src/findevil/server.py`:

```python
if __name__ == "__main__":
    mcp.run()
```

This line is already implied by FastMCP but make sure it exists so `python -m findevil.server` works.

- [ ] **Step 4: Create `src/findevil/__main__.py`**

```python
# src/findevil/__main__.py
from findevil.server import mcp

mcp.run()
```

- [ ] **Step 5: Commit**

```bash
git add .claude/settings.json CLAUDE.md src/findevil/__main__.py
git commit -m "feat: add Claude Code MCP integration and investigation workflow guide"
```

---

### Task 15: Sample Case Data and Ground Truth

**Files:**
- Create: `cases/sample/README.md`
- Create: `cases/sample/ground_truth.json`

- [ ] **Step 1: Create sample case README**

```markdown
# Sample Case Data

Place evidence files in this directory for testing.

## Supported Evidence Types

- `.E01`, `.raw`, `.dd` — Disk images
- `.dmp`, `.vmem`, `.raw` — Memory dumps
- `.evtx` — Windows Event Logs
- `SYSTEM`, `SOFTWARE`, `SAM`, `NTUSER.DAT` — Registry hives
- `*.pf` — Prefetch files
- `$MFT` — MFT table

## Getting Test Data

1. SANS DFIR sample images: check the hackathon Slack for shared datasets
2. Digital Corpora: https://digitalcorpora.org/
3. Create your own with a Windows VM snapshot
```

- [ ] **Step 2: Create ground truth template**

```json
{
  "case_name": "sample",
  "description": "Template for ground truth data used in accuracy benchmarking",
  "expected_findings": [
    {
      "claim": "Example: Malicious process persistence via registry Run key",
      "mitre_technique": "T1547.001",
      "expected_status": "confirmed",
      "evidence_types": ["registry", "prefetch", "timeline"]
    }
  ],
  "expected_negative": [
    "No lateral movement detected",
    "No data exfiltration confirmed"
  ]
}
```

- [ ] **Step 3: Commit**

```bash
git add cases/
git commit -m "feat: add sample case directory with ground truth template for benchmarking"
```

---

### Task 16: Run All Tests and Final Verification

- [ ] **Step 1: Run the full test suite**

Run: `cd /Users/jiaweiyu/workfiles/hackthron-june && python -m pytest tests/ -v --tb=short`

Expected: All tests PASS (approximately 29 tests across 7 test files)

- [ ] **Step 2: Verify MCP server can start**

Run: `cd /Users/jiaweiyu/workfiles/hackthron-june && timeout 3 python -m findevil.server 2>&1 || true`

Expected: Server starts (may hang waiting for stdin — that's correct for stdio MCP transport). No import errors.

- [ ] **Step 3: Verify CLI works**

Run: `cd /Users/jiaweiyu/workfiles/hackthron-june && python -m findevil.cli doctor`

Expected: Shows doctor output with Docker status

- [ ] **Step 4: Final commit with all remaining files**

```bash
git add -A
git status
git commit -m "chore: final verification — all tests pass, MCP server and CLI operational"
```
