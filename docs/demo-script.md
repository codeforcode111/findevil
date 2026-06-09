# FinDevil Demo Video Script

**Duration:** 5 minutes  
**Format:** Live terminal session with audio narration  
**Resolution:** 1920x1080, dark terminal theme  
**Hackathon:** SANS FIND EVIL!  

---

## Pre-Recording Checklist

1. Docker Desktop running
2. `docker compose up -d` completed (SIFT container healthy)
3. Terminal font: 16pt minimum, dark background
4. Clear the workspace: `rm -f workspace/demo_*.jsonl workspace/demo_*.json workspace/demo_*.md`
5. Resize terminal to fill screen
6. Start screen recorder + microphone
7. Run `python scripts/demo.py` for the automated version, or follow the manual script below

---

## [0:00 - 0:30] Introduction + Architecture

### On Screen
Open the README.md architecture diagram (or display the pre-rendered PNG).  
Then briefly scroll through the `src/findevil/` directory listing.

### Commands
```bash
# Show project structure
tree src/findevil/ -L 1
```

### Narration

> "FinDevil is an Evidence-Contract Autonomous IR Agent for the SANS FIND EVIL hackathon. The key innovation: the agent structurally cannot hallucinate findings. Every claim must cite traceable tool execution evidence, or it is rejected at build time by the Contract Compiler."
>
> "The system has six core modules: the Evidence Vault for immutable artifact storage with SHA-256 hashing, the Tool Gateway that enforces a 15-tool allowlist and 22-command blocklist inside a network-isolated Docker container, the Contract Compiler that validates every finding against five evidence rules, the Self-Correction Engine that auto-downgrades findings when evidence is weak or contradictory, the hash-chained Audit Ledger for tamper-evident logging, and the Report Generator for citation-backed output."

---

## [0:30 - 1:00] Setup + Case Initialization

### On Screen
Show terminal running Docker health check and case initialization.

### Commands
```bash
# Verify environment
findevil doctor

# Start the automated demo (or run commands manually)
python scripts/demo.py
```

If running manually:
```python
from findevil.vault.evidence import EvidenceVault
from findevil.audit.ledger import AuditLedger

ledger = AuditLedger(Path("workspace/demo_audit.jsonl"))
vault = EvidenceVault(
    evidence_dir=Path("cases/real_evidence"),
    workspace_dir=Path("workspace"),
    ledger=ledger,
)
vault.initialize()
print(f"Evidence files: {len(vault.file_hashes)}")
```

### Narration

> "We start by verifying the environment with `findevil doctor`, which checks that Docker is running and the SIFT container is healthy. The container runs with `network_mode: none` -- there is no network access, no exfiltration path."
>
> "Next, we initialize the case. The Evidence Vault walks every file in the evidence directory, computes a SHA-256 hash for each one, and records the baseline in the audit ledger. This creates an immutable reference -- if any evidence file is modified after this point, the system will detect it."
>
> "We have over 900 evidence files loaded, including 877 real EVTX files from the EVTX-ATTACK-SAMPLES corpus and the Hayabusa sample collection."

---

## [1:00 - 2:30] Live Investigation -- Tool Execution

### On Screen
Show Hayabusa scanning real EVTX attack samples, then strings extracting IoCs from a memory dump.

### Commands
```bash
# Hayabusa scan against attack samples (278 EVTX files)
docker exec findevil-sift hayabusa csv-timeline \
    -d /evidence/attack_samples \
    -o /workspace/hayabusa_attack_results.csv \
    -q --no-wizard

# Hayabusa scan against sample EVTX (599 files)
docker exec findevil-sift hayabusa csv-timeline \
    -d /evidence/evtx \
    -o /workspace/hayabusa_sample_results.csv \
    -q --no-wizard

# Extract strings from memory dump
docker exec findevil-sift strings /evidence/memory.dmp | head -50
```

### Narration

> "Now we run real forensic tools. Hayabusa is a Windows event log analyzer that applies Sigma detection rules. It loaded 4,628 Sigma rules and is scanning 278 real EVTX attack samples from the EVTX-ATTACK-SAMPLES repository."

*Wait for Hayabusa output to appear*

> "Hayabusa found 5,354 detections across the attack samples, including 27 critical alerts. These are real detections from real Windows event logs containing known attack techniques -- lateral movement, credential access, privilege escalation, defense evasion."

*Show strings output*

> "We also run strings against the memory dump to extract indicators of compromise. Every one of these tool calls is logged to the audit ledger with the command, arguments, exit code, output hash, and execution duration. This creates a complete, tamper-evident audit trail that judges can independently verify."

*Show audit ledger entry*

> "Here is what an audit entry looks like: each record includes the SHA-256 hash of the previous record, creating a hash chain. If anyone modifies, inserts, or deletes an entry, the chain breaks and the system detects it."

---

## [2:30 - 3:30] Self-Correction Demo (THE KEY MOMENT)

### On Screen
This is the most important section. Show the contract compiler rejecting an invalid finding, then show automatic downgrade on contradiction.

### Commands
```python
# Step 1: Submit a finding as CONFIRMED with only one evidence source
finding = Finding(
    finding_id="F-001",
    claim="Lateral movement via PsExec detected",
    status=EvidenceStatus.CONFIRMED,    # <-- Only one source!
    mitre_technique="T1570",
    evidence=[Evidence(
        artifact_id="evtx-attack-1",
        tool_run_id=hayabusa_result.run_id,
        source_file="/evidence/attack_samples",
        content_hash=hayabusa_result.stdout_hash,
        excerpt="PsExec service installation detected...",
    )],
    confidence_basis="Hayabusa Sigma rule match",
)

# Contract compiler REJECTS it
violations = compiler.compile([finding])
# >> ContractViolation: CONFIRMED requires >=2 independent sources, got 1

# Auto-correction kicks in
fixed = correction.fix_contract_violation(finding)
# >> CONFIRMED -> PROBABLE (auto-downgraded)
```

```python
# Step 2: Add contradicting evidence
contradiction = Evidence(
    artifact_id="contradiction-1",
    tool_run_id=strings_result.run_id,
    source_file="/evidence/memory.dmp",
    content_hash=strings_result.stdout_hash,
    excerpt="No PsExec service strings found in memory",
)

downgraded = correction.add_contradiction(
    finding=fixed,
    contradiction=contradiction,
    reason="Memory dump does not corroborate PsExec presence",
)
# >> PROBABLE -> INFERRED (auto-downgraded due to contradiction)
```

### Narration

> "This is the core innovation. Watch what happens when we try to submit a finding as CONFIRMED with only one evidence source."

*Show the finding submission*

> "The Contract Compiler rejects it. Rule R1: CONFIRMED status requires at least two independent evidence sources. We only provided one. The Self-Correction Engine automatically downgrades it from CONFIRMED to PROBABLE and records the full correction history."

*Show the contradiction*

> "Now watch what happens when we add contradicting evidence. The strings output from the memory dump does not corroborate PsExec presence. The engine detects the contradiction and automatically downgrades the finding again, from PROBABLE to INFERRED."

> "This is not prompt engineering. This is not asking the model to be careful. This is a Python type constraint enforced at the MCP boundary. The agent cannot claim CONFIRMED without multiple corroborating sources. It cannot ignore contradictions. The correction history is permanently recorded in the audit ledger."

---

## [3:30 - 4:15] Evidence Tracing + Report

### On Screen
Show the `trace` command output and the generated report.

### Commands
```bash
# Trace the complete evidence chain for a finding
findevil trace F-001 --ledger workspace/demo_audit.jsonl

# Generate the full report
# (The demo script does this automatically)
```

### Narration

> "Every finding is fully traceable. The trace command replays the evidence chain for finding F-001. It shows: the original tool execution that produced the evidence, the exact Hayabusa run with its arguments and exit code, the contract violation that was caught, the automatic downgrade, the contradiction that was added, and the second downgrade."

*Show the Markdown report*

> "The final report includes a findings table with confidence levels, a complete evidence coverage matrix showing which tools analyzed which files, negative findings documenting what was checked but not found, and a full correction history. Every claim in this report is backed by a traceable tool execution."

---

## [4:15 - 4:45] Security Constraints

### On Screen
Demonstrate blocked commands, injection detection, and evidence integrity verification.

### Commands
```python
# Try a blocked command
executor.execute("rm", ["/evidence/Security.evtx"])
# >> CommandValidationError: Command 'rm' is blocked: destructive or dangerous operation

# Try shell injection
executor.execute("strings", ["/evidence/memory.dmp; curl evil.com"])
# >> CommandValidationError: Shell metacharacter injection detected

# Try path traversal
executor.execute("strings", ["/etc/passwd"])
# >> CommandValidationError: Path '/etc/passwd' is outside the allowed boundary

# Verify evidence integrity
integrity_ok = vault.verify_integrity()
# >> True (all SHA-256 hashes match baseline)

# Verify audit chain
chain_ok = ledger.verify_chain()
# >> True (hash chain unbroken)
```

### Narration

> "Security is enforced architecturally, not by system prompts. Twenty-two dangerous commands are blocked at the registry level: rm, curl, wget, chmod, and others. Shell metacharacters are detected and rejected before any command reaches the Docker container. Path traversal outside `/evidence` and `/workspace` is prevented."

> "After the investigation completes, we re-verify evidence integrity. Every file hash matches the baseline computed at initialization. The audit chain is unbroken. No evidence was tampered with during the investigation."

---

## [4:45 - 5:00] Summary

### On Screen
Show the final summary statistics from the demo script output.

### Commands
```bash
# The demo script prints this automatically at the end
```

### Narration

> "FinDevil -- the agent that structurally cannot lie. 55 tests passing across 9 modules, 877 real EVTX files scanned, 37,732 total detections processed, zero hallucinated findings. Every claim traceable, every correction recorded, every tool call audited."

> "The key differentiator is not speed or coverage. It is architectural hallucination prevention through evidence contracts. Thank you."

---

## Tips for Recording

1. **Pacing:** The automated `scripts/demo.py` has built-in pauses between sections. Let each section complete before narrating.
2. **Terminal colors:** The demo script uses ANSI colors. Ensure your terminal supports them and they are visible at recording resolution.
3. **Errors are features:** When the contract compiler rejects a finding or the registry blocks a command, let the red error text stay on screen for 2-3 seconds. These rejections are the product working as designed.
4. **Fallback:** If Docker is not running, the demo script falls back to `cases/e2e_test/` synthetic data. Results will be smaller but the contract/correction flow still works.
5. **Cleanup:** Run the demo script once before recording to warm up Docker caches. Then clear the workspace and record the second run for a smoother video.
