## Inspiration

AI-powered threats now operate at machine speed. CrowdStrike's fastest observed breakout time: 7 minutes. Horizon3's autonomous agent: 60 seconds to full privilege escalation. MIT's 2024 research: AI-driven attack workflows running 47 times faster than human operators.

Yet defenders still SSH into hosts, run Volatility by hand, and grep through event logs — a workflow measured in hours.

AI-assisted DFIR tools have emerged to close that gap, but they introduced a new problem: **hallucination**. An LLM asked "did this process execute a credential dumper?" will produce a confident answer regardless of whether it examined any actual evidence. In incident response, a hallucinated finding sends responders down the wrong path while the attacker pivots elsewhere.

We asked: **what if the agent structurally cannot hallucinate?** Not "what if we prompt it carefully?" — but what if the architecture itself rejects any finding that lacks traceable, hash-verified, tool-execution evidence at compile time?

FinDevil is our answer.

## What It Does

FinDevil is an autonomous incident response agent that uses **Claude Code** as its reasoning engine, connected via **Model Context Protocol (MCP)** to **SIFT Workstation** forensic tools running in Docker. It accepts forensic artifacts — Windows event logs, memory images, registry hives, disk images — and produces investigation reports where every claim is traced to the tool output that produced it.

### Core Innovation: Evidence-Contract Architecture

Every finding must pass through the **Claim-Evidence Contract Compiler** before it enters the report. The compiler enforces five validation rules:

1. **CONFIRMED** status requires $\geq 2$ independent evidence sources from different artifact types
2. Every `Evidence` object must reference a valid `tool_run_id` that exists in the audit ledger
3. Findings with **contradictions** cannot hold CONFIRMED status
4. **INFERRED** findings must provide a non-empty `confidence_basis` explaining the inference
5. Report generation **fails** if any finding violates these rules — the agent must fix or downgrade

The compiler is not a prompt instruction — it is compiled Python code with Pydantic validation that runs on every `Finding` object before serialization. There is no code path that produces a report-ready finding without passing this validation.

### Self-Correction Engine

Three correction types operate autonomously:

**Type 1 — Tool Failure Recovery.** During our real-case investigation, Volatility 3 genuinely failed on a 1 GB PAE memory dump (known compatibility issue). The correction engine logged the failure, recorded the error, and the agent switched to `strings` as an alternative — successfully extracting 2,622 IoCs including IP addresses, URLs, executables, and registry keys. This was a real failure, not staged.

**Type 2 — Contract Violation Auto-Fix.** A Hayabusa critical alert ("Sticky Key Like Backdoor Usage") was submitted as CONFIRMED with only one evidence source. The contract compiler rejected it:

$$\text{sources}(F) = 1 < 2 = \text{min\_sources}(\text{CONFIRMED})$$

The self-correction engine automatically downgraded it to PROBABLE. We then found corroborating evidence from `strings` output in the memory dump. The finding was resubmitted with two independent sources and passed as CONFIRMED.

**Type 3 — Contradiction Downgrade.** An outbound RDP connection was flagged as suspicious lateral movement. Further analysis revealed it was a loopback connection (127.0.0.1:3389). The contradiction was recorded and the finding auto-downgraded:

$$\text{PROBABLE} \xrightarrow{\text{contradiction}} \text{INFERRED}$$

### Real-World Results

| Metric | Value |
|--------|-------|
| Real EVTX files analyzed | **877** |
| Sigma detection rules loaded | **4,628** |
| Total detections | **37,732** (74 critical, 6,196 high) |
| Memory dump analyzed | **1 GB** (Ali Hadi Challenge #1) |
| IoCs extracted from memory | **2,622** (226 IPs, 1,637 URLs, 141 executables) |
| Findings produced | **14** (1 confirmed, 12 probable, 1 inferred) |
| MITRE ATT&CK coverage | **67%** (4/6 known techniques matched) |
| Hallucinated findings | **0** — architecturally enforced |
| Audit events | **928**, hash chain VALID |

## How We Built It

### Architecture

```
Claude Code (reasoning + orchestration)
    ↕ MCP Protocol (stdio)
FinDevil MCP Server (Python 3.12 / FastMCP)
    ├── Evidence Vault      — SHA-256 hash integrity, read-only mount
    ├── Tool Gateway        — 15-tool allowlist, 22-command blocklist
    ├── Contract Compiler   — 5 validation rules, auto-reject
    ├── Self-Correction     — 3 correction types, auto-downgrade
    └── Audit Ledger        — hash-chained JSONL, tamper-evident
        ↕ docker exec
    SIFT Docker Container (Ubuntu 24.04, network: none)
    ├── Hayabusa v3.9.0 (4,628 Sigma rules)
    ├── Volatility 3 v2.28.0
    ├── The Sleuth Kit v4.12.1
    ├── YARA v4.5.0
    └── RegRipper v3.0
```

### Technology Stack

| Component | Technology |
|-----------|-----------|
| Agent runtime | Claude Code via MCP |
| MCP framework | FastMCP (Python) |
| Data models | Pydantic v2 with `@model_validator` |
| Container | Docker, Ubuntu 24.04 (GLIBC 2.39 for Hayabusa) |
| Audit storage | Hash-chained JSONL with SHA-256 |
| Reports | Jinja2 templates → Markdown + JSON |
| Testing | pytest — 55 unit/integration tests |

### Contract Compiler Implementation

Each `Finding` is a Pydantic `BaseModel` with a `@model_validator` that enforces non-empty evidence. The `ContractCompiler` class takes the `AuditLedger` as input and validates every finding against it:

```python
def validate(self, finding: Finding) -> None:
    violations = self._check(finding)
    if violations:
        raise violations[0]  # ContractViolation is both dataclass and Exception
```

The `_check` method queries the ledger for valid `run_id`s and enforces all five rules. The `CorrectionEngine` catches `ContractViolation` exceptions and applies a deterministic `DOWNGRADE_MAP`:

$$\text{CONFIRMED} \rightarrow \text{PROBABLE} \rightarrow \text{INFERRED} \rightarrow \text{UNKNOWN}$$

### Security Boundaries

Security is enforced at the architecture level, not via prompts:

- **Evidence immutability**: Read-only Docker volume mount, SHA-256 hashes verified before and after analysis
- **Command allowlist**: 15 forensic tools permitted; `rm`, `dd`, `curl`, `bash`, `python` and 17 others blocked
- **Injection prevention**: Shell metacharacters (`; & | \` $ ( ) { }`) detected and rejected before execution
- **Path boundaries**: Only `/evidence` and `/workspace` paths allowed; traversal attempts blocked
- **Network isolation**: Container runs with `network_mode: none`

### Testing

- **55 unit and integration tests** covering all validation rules, correction triggers, and tool execution paths
- **End-to-end mock test**: full pipeline with realistic forensic output — 5 test cases
- **Real evidence E2E**: 877 EVTX files + 1 GB memory dump with 928 audit events
- **Contract violation injection**: deliberately submitted evidence-free claims — 100% rejection rate

## Challenges We Ran Into

**The GLIBC problem.** Hayabusa v3.9.0 requires GLIBC 2.39. Our initial Ubuntu 22.04 base (GLIBC 2.35) produced `exec format error` on ARM64 and GLIBC version errors on x64. We upgraded to Ubuntu 24.04 and added architecture auto-detection in the Dockerfile for both `aarch64` and `x64` builds.

**Evidence vault filename collisions.** The vault keyed file hashes by `path.name`. When the 877-file EVTX corpus included duplicate filenames across subdirectories (e.g., `Security.evtx` in multiple attack scenario folders), later hashes silently overwrote earlier ones — 877 files collapsed to 636. The integrity check then failed on every overwritten entry. Fix: switch to `path.relative_to(evidence_dir)` as the key, guaranteeing uniqueness regardless of nesting depth.

**Volatility 3 PAE incompatibility.** The Ali Hadi Challenge #1 memory dump uses a 32-bit PAE kernel (`ntkrpamp.pdb`). Despite having the exact matching ISF symbol file, Volatility 3's automagic `pdbscan` reported "No suitable kernels found." Rather than hiding this failure, we turned it into a self-correction demo: the engine logged the failure, suggested `strings` as fallback, and the investigation continued with 2,622 IoCs extracted — a genuine showcase of graceful degradation.

**Calibrating the contract compiler.** Making it strict enough to block hallucinations while permissive enough for legitimate inference was the hardest design problem. A skilled analyst often reaches CONFIRMED from one strong indicator. Our solution: a tiered confidence model (CONFIRMED / PROBABLE / INFERRED / UNKNOWN) where each tier has explicit evidence requirements. The agent can express appropriate confidence without being forced into false binary choices.

## Accomplishments That We're Proud Of

**The agent cannot hallucinate a finding.** There is no prompt that tells Claude "please cite your sources." There is compiled Python code that rejects findings without sources. Every finding in our 14-finding real investigation is traceable to a specific `tool_run_id` in the audit ledger.

**Real self-correction on real data.** The Volatility failure was genuine, not staged. The contract rejection was triggered by real single-source evidence. The contradiction was discovered through actual analysis. All three correction types working on real forensic data, exactly as designed.

**928-event tamper-evident audit trail.** Every tool call, finding submission, correction event, and evidence hash verification is recorded in a hash-chained JSONL ledger. `findevil trace F-001` replays the complete evidence chain. Modify a single byte and the chain verification fails.

**Honest unknowns.** When evidence is insufficient, the system says INFERRED or UNKNOWN. When a finding is contradicted, it's downgraded with the reason recorded. A report that honestly says "we checked for lateral movement and found it inconclusive" is more valuable than one that hallucinated a finding.

## What We Learned

**Architectural constraints beat prompt engineering for safety-critical AI.** Every safety property we tried to achieve through prompting was fragile. Every property we encoded in the data model and validation layer held unconditionally. For any AI system where the cost of a wrong answer is high: make the wrong answer structurally impossible, not merely discouraged.

**The contract compiler pattern generalizes.** We built this for DFIR findings, but the pattern — "any AI-generated claim must cite executable evidence before being treated as output" — applies anywhere an LLM produces consequential statements: medical diagnosis, legal research, financial analysis. Define a `Claim` type, define an `Evidence` type, write a compiler that validates the link, and make it impossible to produce output that bypasses the compiler.

**Incident response is about knowing what you don't know.** The most experienced analysts spend as much time documenting the boundaries of their knowledge as documenting what they found. FinDevil's confidence tiers and negative-finding reports were directly inspired by this observation.

**MCP + Claude Code is a powerful pattern for agentic tool orchestration.** Claude handles "what to do next"; the MCP server handles "how to do it safely." We wrote zero planning logic — the LLM reasons about which tools to run and in what order, while our server enforces that every tool call is audited, every finding is validated, and every result is traceable.

## What's Next

- **Plaso super-timeline integration** — correlate events across filesystem, registry, event logs, and network captures in a single timeline
- **Multi-agent architecture** — separate Planner, Executor, and Verifier agents, each independently auditable
- **Enterprise deployment** — SOC integration via SOAR platforms (Splunk SOAR, Palo Alto XSOAR), role-based access control, multi-tenant evidence isolation
- **Persistent learning** — store investigation patterns to improve future tool selection and analysis strategies

## Built With

`python` `fastmcp` `pydantic` `docker` `claude-code` `volatility3` `sleuthkit` `hayabusa` `yara` `jinja2` `sqlite`
