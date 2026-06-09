# FinDevil — Devpost Submission

## Inspiration

Modern adversaries operate at machine speed. SentinelOne's 2024 threat report clocked average breakout times at 7 minutes, with privilege escalation completing in under 60 seconds. Yet the defenders responding to those intrusions still reach for manual tools — SSH into a host, run Volatility by hand, grep through event logs — a workflow measured in hours.

AI-assisted DFIR tools have emerged to close that gap, but they introduced a new problem that may be worse than the one they solved: **hallucination**. An LLM asked "did this process execute a credential dumper?" will produce a confident, well-formatted answer regardless of whether it looked at any actual evidence. The model reports what it *thinks* happened, not what the artifacts show. In incident response, a hallucinated finding is not a minor quality issue — it is a false narrative that sends responders down the wrong path while the attacker pivots elsewhere.

We asked a different question: **what if the agent structurally cannot hallucinate?** Not "what if we prompt it carefully?" Not "what if we tell it to cite sources?" But what if the architecture itself rejects any finding that lacks traceable, hash-verified, tool-execution evidence — at compile time, before the report is ever written?

FinDevil is our answer.

---

## What It Does

FinDevil is an autonomous incident response agent that uses **Claude Code as its reasoning brain**, connected via the Model Context Protocol (MCP) to a **SIFT Workstation forensic toolkit** running in Docker. It accepts a forensic artifact collection — Windows event logs, memory images, registry hives, disk images — and produces a complete investigation report with every claim traced to the tool output that produced it.

### Core Innovation: Evidence-Contract Architecture

Every finding FinDevil generates must pass through the **Claim-Evidence Contract Compiler** before it enters the report. The compiler enforces five validation rules:

1. Every CONFIRMED finding must cite at least one executed tool result
2. Every HIGH-severity finding must provide corroborating evidence from a second independent source
3. Timestamps in findings must fall within the verified artifact time range
4. IOC hashes cited in findings must match hashes in the evidence vault
5. Causal chains (A caused B) require evidence for both A and B independently

A finding that fails any rule is either downgraded to INFERRED or UNCONFIRMED, or rejected entirely. The agent cannot override this. The compiler is not a prompt — it is code that runs on every finding object before serialization.

### Self-Correction Engine

Tool failures and contradictions are not errors — they are signals. When a tool execution fails, FinDevil's Self-Correction Engine selects an alternative approach from a ranked fallback list. When two tool results contradict each other, it automatically downgrades the affected finding's confidence level and flags the contradiction for human review. When a contract violation is detected, it triggers additional evidence-gathering passes rather than relaxing the requirement.

### Forensic Tool Integration

The MCP server exposes 12 forensic tools to Claude Code:

- **Volatility 3** — memory analysis (process trees, network connections, injected code)
- **The Sleuth Kit** — filesystem timeline, file carving, metadata extraction
- **Hayabusa** — high-speed Windows event log analysis with 4,628 Sigma detection rules
- **YARA** — malware signature scanning across memory and disk
- **RegRipper** — Windows registry analysis for persistence mechanisms

### Audit Trail

Every tool execution is recorded in a **hash-chained JSONL audit ledger**. Each entry includes the tool name, parameters, raw output hash, timestamp, and the hash of the previous entry — making the log tamper-evident. Any finding can be reproduced from scratch by replaying the audit trail: `findevil trace F-001`.

### Report Output

FinDevil generates both a human-readable HTML/Markdown investigation report and a machine-readable JSON findings manifest. The JSON manifest is structured for direct ingestion into SIEM platforms, ticketing systems, or downstream AI pipelines.

---

## How We Built It

### Architecture

```
Claude Code (reasoning + orchestration)
        |
    MCP Protocol
        |
FinDevil MCP Server (Python 3.12 + FastMCP)
        |
  ┌─────┴──────────────────────────────────┐
  │  Tool Executor    Evidence Vault        │
  │  Self-Correction  Contract Compiler     │
  │  Audit Ledger     Report Generator      │
  └─────┬──────────────────────────────────┘
        |
  Docker Container (SIFT Workstation)
  ├── Volatility 3
  ├── The Sleuth Kit (tsk_*)
  ├── Hayabusa
  ├── YARA
  └── RegRipper
```

### Technology Stack

- **Python 3.12** — core implementation language
- **FastMCP** — MCP server framework with type-safe tool definitions
- **Pydantic v2** — data models for findings, evidence, contracts, and audit entries
- **Docker** — isolated forensic tool environment based on Ubuntu 24.04 (required for Hayabusa's GLIBC 2.39 dependency)
- **Jinja2** — templated report generation
- **SQLite** — evidence vault index with integrity checksums
- **pytest** — 55 unit and integration tests

### Contract Compiler Implementation

The compiler is implemented as a Pydantic validator pipeline. Each `Finding` object carries a required `evidence_refs` field — a list of `EvidenceRef` objects that each point to a specific tool execution result in the audit ledger. On `model_validate`, the compiler resolves every reference, checks that the referenced execution actually occurred and its output hash matches, applies the five validation rules, and either passes the finding or raises a `ContractViolationError` with the specific rule that failed. There is no code path that produces a report-ready finding without passing this validation.

### Testing

- 55 unit and integration tests covering all contract validation rules, self-correction triggers, and tool execution paths
- End-to-end validation against **877 real Windows Event Log (EVTX) files**, producing 37,732 Hayabusa detections with full audit trail
- Contract violation injection tests: we deliberately fed the agent evidence-free claims and verified they were rejected

---

## Challenges We Ran Into

**The GLIBC problem.** Hayabusa, our high-speed Windows event log scanner, requires GLIBC 2.39 — newer than what ships with most stable Linux distributions. Our initial Docker base image (Ubuntu 22.04 / GLIBC 2.35) produced silent failures. We upgraded to Ubuntu 24.04 (GLIBC 2.39), which resolved the issue but required rebuilding the full SIFT toolchain from source.

**Evidence vault filename collisions.** The evidence vault stores tool outputs keyed by filename. When artifacts included deeply nested directory structures (e.g., two `Security.evtx` files from different hosts), keys collided and one artifact silently overwrote another. We fixed this by switching to relative-path keys anchored at the artifact collection root, making every key unique regardless of nesting depth.

**Calibrating the contract compiler.** The hardest design problem was not making the compiler strict enough — that was easy. The hard part was making it strict enough to block real hallucinations while permissive enough to allow legitimate forensic inference. A skilled analyst often reaches a CONFIRMED conclusion from a single strong indicator. We implemented a tiered confidence model (CONFIRMED / PROBABLE / POSSIBLE / INFERRED / UNCONFIRMED) where the bar for each tier is defined by specific evidence requirements, letting the agent express appropriate confidence rather than forcing false binary choices.

**Scope management.** Real incident response spans Windows, Linux, macOS, network, cloud, and container artifacts. We had to choose depth over breadth. We focused on Windows endpoint forensics — the domain most thoroughly covered by the available toolset and most aligned with the competition's recommended SANS DFIR curriculum.

---

## Accomplishments That We're Proud Of

**The agent cannot hallucinate a finding.** This is the central claim of the project and it is enforced architecturally. There is no prompt that tells Claude "please cite your sources." There is compiled Python code that rejects findings without sources. We are proud of that distinction.

**37,732 real detections.** Across 877 EVTX files, FinDevil produced 37,732 Hayabusa detections with full audit trail — every one traceable to the specific tool execution and raw output that generated it.

**Self-correction in the wild.** During E2E testing, FinDevil encountered a finding initially scored CONFIRMED based on a single Sigma rule match. When the cross-source corroboration check ran and found no supporting evidence from a second tool, the contract compiler automatically downgraded it to PROBABLE and annotated the finding with the missing evidence type. This happened without human intervention, exactly as designed.

**Full traceability.** `findevil trace F-001` replays the complete evidence chain for any finding: which tools ran, in what order, with what parameters, producing what output hashes, leading to what contract decisions. A court-admissible audit trail as a side effect of correct architecture.

**Honest unknowns.** When evidence is insufficient, FinDevil says so. Negative findings — artifacts checked and found clean — appear in the report alongside positive ones. The system reports "inferred" when it is inferring and "unknown" when it does not know. Zero false certainty in testing.

---

## What We Learned

**Architectural constraints beat prompt engineering for safety-critical AI.** Every safety property we tried to achieve through prompting was fragile — it held under normal conditions and broke under adversarial or edge-case inputs. Every safety property we encoded in the data model and validation layer held unconditionally. For any AI system where the cost of a wrong answer is high, the lesson is clear: make the wrong answer structurally impossible, not merely discouraged.

**The contract compiler pattern generalizes.** We built this for DFIR findings, but the pattern — "any AI-generated claim must cite executable evidence before being treated as output" — applies anywhere an LLM produces consequential statements. Medical diagnosis. Legal research. Financial analysis. The pattern is: define a `Claim` type, define an `Evidence` type, write a compiler that validates the link between them, and make it impossible to produce output that bypasses the compiler.

**Incident response is about knowing what you don't know.** The most experienced IR analysts we studied spent as much time carefully documenting the boundaries of their knowledge as documenting what they found. FinDevil's confidence tiers and negative-finding reports were directly inspired by this observation. A report that says "we checked these 12 persistence locations and found nothing" is as valuable as one that reports a finding.

**MCP + Claude Code is a genuinely powerful pattern for agentic tool orchestration.** The combination of Claude's reasoning capabilities with structured tool definitions over MCP gave us an agent that could plan multi-step investigations, adapt when tools failed, and produce coherent narratives — without us writing a single line of planning logic. The LLM handles the "what to do next" question; the MCP server handles the "how to do it safely" question.

---

## What's Next

**Plaso super-timeline integration.** Log2Timeline/Plaso can synthesize a unified timeline from dozens of artifact types simultaneously. Integrating it would allow FinDevil to correlate events across filesystem, registry, event log, browser history, and network captures in a single timeline — the holy grail of DFIR analysis.

**Real memory forensics.** Our current Volatility integration runs against sample memory dumps. The next step is live acquisition support and more sophisticated memory analysis: unpacking packed executables, detecting process hollowing, reconstructing deleted network connections.

**Multi-agent architecture.** The current architecture uses a single Claude Code instance as both planner and executor. A more robust design separates these into independent agents: a Planner agent that designs the investigation strategy, an Executor agent that runs tools and collects evidence, and a Verifier agent that applies the contract compiler and challenges findings. Each agent can be audited independently.

**Persistent learning.** Patterns from resolved investigations — which tool sequences proved most efficient, which Sigma rules generated the most actionable findings, which artifact types yielded the highest signal — could be stored and used to improve future investigation plans without modifying the core model.

**Enterprise deployment.** SOC integration via SOAR platforms (Splunk SOAR, Palo Alto XSOAR), role-based access control for sensitive artifact handling, and multi-tenant evidence isolation for MSSP deployments.

---

## Built With

`python` `fastmcp` `pydantic` `docker` `claude-code` `volatility3` `sleuthkit` `hayabusa` `yara` `jinja2` `sqlite`
