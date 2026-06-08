# FinDevil: Evidence-Contract Autonomous IR Agent

## Overview

An autonomous incident response agent for the SANS FIND EVIL! hackathon. Uses Claude Code as the reasoning engine, a custom Python MCP Server as the investigation runtime, and SIFT Workstation tools running in Docker for forensic analysis.

The core differentiator: **the agent cannot produce a finding without traceable tool-execution evidence**. Hallucination prevention is architectural, not prompt-based.

## Architecture

```
Claude Code (Planning + Reasoning + Narrative)
    ↕ MCP Protocol (stdio)
Investigation Runtime MCP Server (Python 3.12 / FastMCP)
    ├── Evidence Vault         — read-only evidence, hash integrity
    ├── Tool Gateway           — Docker SIFT exec + security constraints
    ├── Contract Compiler      — reject uncited claims at build time
    ├── Self-Correction Engine — tool failure / contradiction / contract violation
    └── Audit Ledger           — hash-chained JSONL event log
        ↕ docker exec
    SIFT Docker Container (evidence mounted read-only, no network)
```

## Components

### 1. Evidence Vault (`src/findevil/vault/evidence.py`)

Manages evidence integrity throughout the investigation.

- Mount evidence directory read-only
- Compute SHA-256 hashes of all evidence files at case initialization
- Verify hashes remain unchanged at investigation end
- Copy-on-write workspace for tool output
- Reject any tool call that targets paths outside the evidence/workspace boundary

### 2. Tool Gateway (`src/findevil/tools/`)

Wraps SIFT forensic tools as MCP tool calls with security enforcement.

**Tool registry** (`registry.py`):
- Allowlist of permitted executables (volatility3, log2timeline, fls, hayabusa, yara, etc.)
- Blocklist of destructive commands (rm, dd, mkfs, chmod, etc.)
- Path boundary enforcement (only /evidence and /workspace accessible)
- Command injection detection (reject shell metacharacters in arguments)

**Executor** (`executor.py`):
- Execute tools via `docker exec` against the SIFT container
- Timeout enforcement: 5 minutes per tool call
- Retry logic: up to 2 retries on transient failures
- Output normalization: parse tool stdout into structured JSON
- Audit logging: command, args, exit code, stdout hash, duration, timestamp

**Tool modules** (one per SIFT tool family):
- `volatility.py`: pslist, psscan, netscan, malfind, cmdline, filescan, dlllist, handles
- `plaso.py`: log2timeline super-timeline generation, psort filtering
- `sleuthkit.py`: fls, icat, mmls, img_stat for disk/filesystem analysis
- `hayabusa.py`: Windows EVTX analysis with Sigma rules
- `yara.py`: YARA rule scanning against files and memory dumps
- `zimmerman.py`: MFTECmd, PECmd, AmcacheParser, RECmd for Windows artifacts

### 3. MCP Server (`src/findevil/server.py`)

FastMCP server exposing tools to Claude Code in 4 categories:

**Investigation management:**
- `investigate_case(evidence_path)` — initialize case, create vault, hash evidence
- `get_case_status()` — current investigation state, analyzed vs pending
- `list_evidence()` — available evidence files with types and sizes

**Forensic analysis (each wraps a SIFT tool):**
- `analyze_memory(dump_path, plugins)` — Volatility 3 analysis
- `build_timeline(evidence_path, filter)` — Plaso super-timeline
- `analyze_filesystem(image_path, operation)` — Sleuth Kit disk analysis
- `scan_eventlogs(evtx_path, rules)` — Hayabusa EVTX + Sigma
- `scan_yara(target_path, rules)` — YARA scanning
- `analyze_registry(hive_path)` — RegRipper registry analysis
- `analyze_artifacts(artifact_type, path)` — Zimmerman tools

**Evidence contract:**
- `submit_finding(claim, status, evidence, mitre_technique)` — submit finding through contract compiler
- `search_contradictions(finding_id)` — actively search for evidence contradicting a finding
- `get_corroboration(finding_id)` — check cross-validation status across evidence sources

**Audit and reporting:**
- `trace_finding(finding_id)` — full evidence chain for a finding
- `generate_report(format)` — compile final report (md/html/json)
- `get_audit_log(filter)` — query audit ledger

### 4. Claim-Evidence Contract (`src/findevil/contracts/`)

**Data models** (`models.py`):

```python
class EvidenceStatus(Enum):
    CONFIRMED = "confirmed"      # >=2 independent evidence sources cross-validated
    PROBABLE = "probable"        # 1 strong evidence source, no contradictions
    INFERRED = "inferred"        # logical inference, no direct evidence
    REFUTED = "refuted"          # contradicted by evidence
    UNKNOWN = "unknown"          # insufficient evidence

class Evidence:
    artifact_id: str             # linked evidence file
    tool_run_id: str             # tool execution that produced this
    source_file: str             # original file path
    content_hash: str            # output content hash
    excerpt: str                 # key excerpt from tool output

class Finding:
    finding_id: str              # F-001, F-002, ...
    claim: str                   # what is being claimed
    status: EvidenceStatus       # confidence level
    mitre_technique: str         # MITRE ATT&CK ID
    evidence: list[Evidence]     # supporting evidence
    contradictions: list[Evidence]  # contradicting evidence
    confidence_basis: str        # why this confidence level
    tool_run_ids: list[str]      # all related tool executions
    correction_history: list     # status change history
```

**Compiler rules** (`compiler.py`):
1. CONFIRMED requires >=2 evidence items from different artifact types
2. Every Finding must have >=1 Evidence link
3. Every Evidence must have a valid tool_run_id traceable in the audit ledger
4. If contradictions exist, status cannot be CONFIRMED
5. INFERRED must have a confidence_basis explaining the inference
6. Report generation fails if any rule is violated — agent must fix or downgrade

**Corroboration policies** (`policies.py`):
- Persistence claims require >=2 artifact types (e.g., registry + timeline + process)
- Lateral movement claims require network + authentication evidence
- Data exfiltration claims require staging + transfer evidence

### 5. Self-Correction Engine (`src/findevil/correction/engine.py`)

Three correction types:

**ToolFailureCorrection:**
- Trigger: tool execution fails (non-zero exit, timeout, parse error)
- Action: log failure, select alternate tool, retry with adjusted parameters
- Example: `volatility pslist` fails on profile → try `psscan` → log switch reason

**ContradictionCorrection:**
- Trigger: new evidence contradicts an existing finding
- Action: downgrade finding status, record contradiction details
- Example: initially suspect malicious process → discover valid signature → CONFIRMED → REFUTED

**ContractViolationCorrection:**
- Trigger: `submit_finding` rejected by contract compiler
- Action: agent must gather more evidence or downgrade status
- Example: claim "data exfiltration" with only staging evidence → rejected → downgrade to INFERRED

All corrections logged to audit ledger with before/after states.

### 6. Audit Ledger (`src/findevil/audit/ledger.py`)

Append-only JSONL with hash chaining for tamper detection.

**Event types:**
- `tool_call` — command, args, exit code, stdout hash, duration, timestamp
- `finding_event` — finding created/updated/downgraded/confirmed
- `correction` — correction type, reason, before state, after state
- `evidence_hash` — evidence file integrity verification
- `case_event` — investigation start/end/phase transition

**Each record:**
```json
{
  "event_id": "evt-001",
  "timestamp": "2026-06-08T12:00:00Z",
  "type": "tool_call",
  "prev_hash": "sha256-of-previous-record",
  "data": { ... },
  "hash": "sha256-of-this-record"
}
```

### 7. Report Generator (`src/findevil/report/generator.py`)

Two output formats:
- `findings.json` — machine-readable, all Finding objects
- `report.md` / `report.html` — human-readable report

**Report structure:**
1. Executive Summary
2. Timeline of Events
3. Findings (grouped by MITRE ATT&CK tactic)
   - Each: claim, status badge, evidence excerpts, contradictions, trace link
4. Evidence Coverage Matrix — what was analyzed / missing / failed / uncertain
5. Negative Findings — high-value items checked but not found
6. Tool Execution Statistics
7. Appendix: Full Audit Trail

### 8. CLI (`src/findevil/cli.py`)

```
findevil trace <finding-id>   — show full evidence chain for a finding
findevil replay <finding-id>  — display the tool execution sequence
findevil audit verify          — verify hash chain integrity
findevil bench <case-dir>     — run accuracy benchmark against known case
findevil doctor                — check SIFT container health and tool availability
```

## Docker Configuration

**Dockerfile.sift:**
- Base: Ubuntu 22.04
- Install: SIFT Workstation CLI tools (Volatility 3, Plaso, Sleuth Kit, Hayabusa, YARA, Zimmerman tools, RegRipper)
- No network access at runtime
- Evidence mounted read-only at /evidence
- Workspace writable at /workspace

**docker-compose.yml:**
- `sift` service: forensic tools container
- Volume mounts: `./evidence:/evidence:ro`, `./workspace:/workspace`
- Network: none

## Focus: Windows Endpoint Depth

Per judging criteria (depth > breadth), focus on Windows artifacts:
- EVTX event logs (Security, System, PowerShell, Defender)
- Registry (Run/RunOnce, Services, Shimcache, Amcache, UserAssist)
- Prefetch / MFT / USN Journal
- Scheduled Tasks
- PowerShell logs / script block logging
- Memory analysis (processes, network, injection, command history)

## Tech Stack

| Layer | Choice |
|-------|--------|
| Agent runtime | Claude Code |
| MCP framework | FastMCP (Python) |
| Language | Python 3.12 |
| Data models | Pydantic v2 |
| Storage | SQLite (audit ledger index) |
| Container | Docker + docker-compose |
| DFIR tools | Volatility 3, Plaso, Sleuth Kit, Hayabusa, YARA, Zimmerman, RegRipper |
| Report | Jinja2 templates → Markdown/HTML |

## Submission Deliverables Mapping

| Requirement | Covered by |
|-------------|-----------|
| Code repository | GitHub public repo, MIT license |
| Demo video (5min) | Live Claude Code session with self-correction demo |
| Architecture diagram | docs/architecture.md + diagram |
| Project description | Devpost description |
| Dataset documentation | cases/ directory + docs |
| Accuracy report | `findevil bench` output + docs/accuracy-report.md |
| Try-it-out instructions | README with Docker setup steps |
| Agent execution logs | Audit ledger JSONL output |
