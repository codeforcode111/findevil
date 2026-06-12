# Devpost Judge-Only Fields — 直接复制粘贴

> 这些内容只有评委和组织者能看到，不会显示在公开页面上。

---

## Field 1: Open Source Code Repository

```
https://github.com/codeforcode111/findevil
```

---

## Field 2: Live Deployment URL or Step-by-Step Instructions

粘贴以下全部内容：

---BEGIN PASTE---

## Running FinDevil Locally

### Prerequisites

- **Docker** (Docker Desktop, OrbStack, or Colima)
- **Python 3.12+**
- **Claude Code** CLI with an active subscription

### Step 1: Clone and Install

```bash
git clone https://github.com/codeforcode111/findevil.git
cd findevil
pip install -e .
```

### Step 2: Build and Start the SIFT Container

```bash
docker compose build
docker compose up -d
```

This builds an Ubuntu 24.04 container with Hayabusa v3.9.0 (4,628 Sigma rules), Volatility 3, Sleuth Kit, YARA, and RegRipper. Evidence is mounted read-only; the container has no network access.

Verify:
```bash
python -m findevil.cli doctor
```

### Step 3: Place Your Evidence

Put forensic artifacts in the `cases/` directory. For a quick test, use the included synthetic evidence:

```bash
# Already included: cases/e2e_test/ with synthetic EVTX, registry hive, and memory dump
```

Or download real EVTX attack samples (877 files, 180 MB):

```bash
mkdir -p cases/real_evidence/evtx
curl -sSL "https://github.com/Yamato-Security/hayabusa-sample-evtx/archive/refs/heads/main.zip" -o /tmp/evtx.zip
unzip -q /tmp/evtx.zip -d cases/real_evidence/evtx/
curl -sSL "https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/archive/refs/heads/master.zip" -o /tmp/attack.zip
unzip -q /tmp/attack.zip -d cases/real_evidence/
```

Update `docker-compose.yml` to mount your evidence directory:
```yaml
volumes:
  - ./cases/real_evidence:/evidence:ro
  - ./workspace:/workspace
```

Then restart: `docker compose down && docker compose up -d`

### Step 4: Run the Automated Investigation

```bash
# Full real-case investigation with colored output
python scripts/investigate_real_case.py
```

This will:
1. Hash all evidence files (SHA-256 integrity baseline)
2. Run Hayabusa with 4,628 Sigma rules against all EVTX files
3. Extract IoCs from memory dumps via `strings`
4. Submit findings through the Evidence-Contract Compiler
5. Demonstrate all 3 self-correction types on real data
6. Generate JSON + Markdown reports in `workspace/`
7. Verify audit chain integrity

### Step 5: Use via Claude Code MCP (Interactive Mode)

Add to your Claude Code project settings (`.claude/settings.json`):

```json
{
  "mcpServers": {
    "findevil": {
      "command": "python",
      "args": ["-m", "findevil.server"],
      "cwd": "/path/to/findevil"
    }
  }
}
```

Then in a new Claude Code session, the 16 MCP tools become available:

```
# Initialize a case
investigate_case(evidence_path="/path/to/evidence", workspace_path="./workspace")

# Run tools
scan_eventlogs(evtx_path="/evidence/Security.evtx")
analyze_memory(dump_path="/evidence/memdump.mem", plugin="pslist")

# Submit findings (compiler enforces evidence contracts)
submit_finding(claim="...", status="probable", evidence_items="[...]")

# Trace evidence chain
trace_finding(finding_id="F-0001")

# Generate report
generate_report(output_format="markdown")
```

### Step 6: Run Tests

```bash
python -m pytest tests/ -v
# Expected: 55 passed
```

### Output Files

After investigation, `workspace/` contains:
- `investigate_report.json` — machine-readable findings
- `investigate_report.md` — human-readable report
- `investigate_audit.jsonl` — 928-event hash-chained audit trail
- `investigate_self_assessment.json` — accuracy self-assessment
- `investigate_iocs.json` — extracted IoCs
- Hayabusa CSV timelines

### CLI Tools

```bash
findevil doctor                              # Check SIFT container health
findevil audit verify --ledger workspace/investigate_audit.jsonl  # Verify hash chain
findevil trace F-001 --ledger workspace/investigate_audit.jsonl   # Trace finding
```

---END PASTE---

---

## Field 3: Evidence Dataset Documentation

粘贴以下全部内容：

---BEGIN PASTE---

## Evidence Dataset Documentation

### Datasets Used

| Dataset | Source | Files | Size | Format | License |
|---------|--------|-------|------|--------|---------|
| EVTX-ATTACK-SAMPLES | [github.com/sbousseaden/EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) | 278 | 47 MB | Windows EVTX | Public |
| Hayabusa Sample EVTX | [github.com/Yamato-Security/hayabusa-sample-evtx](https://github.com/Yamato-Security/hayabusa-sample-evtx) | 599 | 133 MB | Windows EVTX | BSD-3-Clause |
| Ali Hadi DFIR Challenge #1 | [archive.org/details/dfir-case1](https://archive.org/details/dfir-case1) | 1 | 1 GB | Raw memory dump (.mem) | Public |
| **Total** | | **878** | **~1.2 GB** | | |

### EVTX-ATTACK-SAMPLES Coverage

This dataset contains real Windows Event Logs mapped to MITRE ATT&CK techniques, organized by tactic:

- Command and Control (RDP tunneling, C2 beacons)
- Credential Access (Mimikatz, LSASS dumping)
- Defense Evasion (timestomping, DLL sideloading, log clearing)
- Execution (PowerShell, rundll32, scheduled tasks)
- Lateral Movement (PsExec, RDP, WMI)
- Persistence (registry Run keys, services, scheduled tasks)
- Privilege Escalation (UAC bypass, token manipulation)
- Discovery (network scanning, enumeration)

### Hayabusa Sample EVTX

599 EVTX files covering a broad range of Windows security events, used by the Hayabusa project for Sigma rule testing. Includes samples from multiple Windows versions (XP through 11) and server editions.

### Ali Hadi Challenge #1 — Memory Dump

A 1 GB raw memory dump from a Windows system involved in a web server compromise investigation. Contains:
- Running processes and their command lines
- Network connection artifacts
- File paths and registry keys
- Potential malware indicators

**Note:** This memory dump uses a 32-bit PAE kernel (`ntkrpamp.pdb`), which is incompatible with Volatility 3's current automagic stacking. Our agent handles this gracefully via the Self-Correction Engine (Type 1: Tool Failure Recovery), falling back to `strings` extraction which yielded 2,622 IoCs.

### Synthetic Test Evidence

For unit and integration testing, we include synthetic evidence files in `cases/e2e_test/`:
- `Security.evtx` — EVTX file with ElfFile magic header (4 KB)
- `SYSTEM` — Registry hive with regf magic header (4 KB)
- `memory.dmp` — Memory dump with embedded suspicious strings (8 KB)
- `ground_truth.json` — Expected findings for automated validation

### Findings from Real Data

Our agent produced the following detections from the real datasets:

| Severity | Attack Samples (278 files) | Hayabusa Samples (599 files) | Combined |
|----------|---------------------------|------------------------------|----------|
| Critical | 27 | 47 | 74 |
| High | 582 | 5,614 | 6,196 |
| Medium | 944 | 2,099 | 3,043 |
| **Total** | **5,354** | **32,378** | **37,732** |

From the memory dump, `strings` extraction yielded:
- 226 IP addresses
- 1,637 URLs
- 141 executable paths
- 280 registry keys
- 338 suspicious strings

### MITRE ATT&CK Coverage

Against the known ground truth of the EVTX-ATTACK-SAMPLES dataset:

| Technique | ID | Detected |
|-----------|----|----------|
| Accessibility Features (Sticky Keys) | T1546.008 | Yes |
| Remote Desktop Protocol | T1021.001 | Yes |
| Clear Windows Event Logs | T1070.001 | Yes |
| OS Credential Dumping | T1003 | Yes |
| PowerShell Execution | T1059.001 | Partial |
| Windows Service Installation | T1543.003 | Partial |

**Coverage: 67% (4/6 known techniques fully matched)**

---END PASTE---

---

## Field 4: Accuracy Report

粘贴以下全部内容：

---BEGIN PASTE---

## Accuracy Report — Self-Assessment

### Executive Summary

FinDevil analyzed 877 real Windows EVTX files and a 1 GB memory dump, producing 37,732 detections and 14 findings with zero hallucinated claims. Every finding is traceable to specific tool executions in the 928-event hash-chained audit ledger.

### Methodology

1. All EVTX files were processed by Hayabusa v3.9.0 with 4,628 Sigma detection rules
2. Memory dump was analyzed with `strings` (Volatility 3 failed on PAE format — logged as self-correction event)
3. Findings were submitted through the Evidence-Contract Compiler, which enforces 5 validation rules
4. Contract violation injection tests verified 100% rejection rate for uncited claims
5. Evidence integrity verified before and after analysis (SHA-256, 919 files)
6. Audit chain integrity verified (hash-chained JSONL, 928 events)

### Detection Results

| Metric | Value |
|--------|-------|
| Total EVTX files scanned | 877 |
| Sigma rules loaded | 4,628 |
| Total detections | 37,732 |
| Critical detections | 74 (31 unique rules) |
| High detections | 6,196 (451 unique rules) |
| IoCs from memory | 2,622 |
| MITRE ATT&CK coverage | 67% (4/6 techniques) |

### Findings Accuracy

| Finding ID | Claim | Status | Evidence Sources | Corrections |
|-----------|-------|--------|-----------------|-------------|
| F-001 | Sticky Key Backdoor (T1546.008) | CONFIRMED | Hayabusa + strings (2 sources) | 1 (contract violation auto-fix) |
| F-002 to F-013 | Various Hayabusa critical/high alerts | PROBABLE | Single Hayabusa source each | 0 |
| F-014 | Outbound RDP (T1021.001) | INFERRED | Hayabusa (downgraded by contradiction) | 1 (contradiction) |

### Hallucination Prevention Results

| Test | Result |
|------|--------|
| Single-source claim submitted as CONFIRMED | **REJECTED** — auto-downgraded to PROBABLE |
| Claim with non-existent tool_run_id | **REJECTED** — "run_id not found in audit ledger" |
| CONFIRMED claim with contradicting evidence | **REJECTED** — "Finding has contradictions and cannot be CONFIRMED" |
| INFERRED claim without confidence_basis | **REJECTED** — "INFERRED findings must have a non-empty confidence_basis" |
| Hallucination injection rate | **0%** — no uncited finding can pass the compiler |

### Self-Correction Demonstrated

| Type | Trigger | Action | Outcome |
|------|---------|--------|---------|
| Tool Failure | Volatility 3 failed on PAE memory dump | Logged error, switched to `strings` | 2,622 IoCs recovered |
| Contract Violation | CONFIRMED with 1 source | Auto-downgrade CONFIRMED → PROBABLE | Finding preserved at correct confidence |
| Contradiction | RDP loopback evidence | Auto-downgrade PROBABLE → INFERRED | Reason recorded in correction_history |

### Known Limitations

| Limitation | Impact | Mitigation |
|-----------|--------|------------|
| Volatility 3 incompatible with PAE 32-bit dumps | Cannot analyze older Windows memory | strings fallback extracts IoCs; documented as self-correction |
| Disk image analysis not tested | No filesystem-level findings | Sleuth Kit integration is implemented, pending real E01/raw image |
| YARA requires external rule files | Not tested with real rules | YARA tool wrapper is functional, rules not bundled |
| Accuracy depends on Sigma rule quality | False positives from noisy rules | Tiered confidence model (PROBABLE, not CONFIRMED) for single-source |

### Integrity Verification

| Check | Result |
|-------|--------|
| Evidence files hashed (SHA-256) | 919/919 verified |
| Evidence integrity post-analysis | **PASSED** — all hashes match baseline |
| Audit ledger hash chain | **VALID** — 928 events, unbroken chain |
| Tamper detection test | Hash chain correctly fails on modified entries |

### Conclusion

FinDevil produced 14 findings from real forensic data with zero hallucinated claims. The Evidence-Contract Compiler enforces structural guarantees that no finding can exist without traceable tool-execution evidence. Known limitations (Volatility PAE, disk images, YARA rules) are documented honestly. The agent correctly labels single-source findings as PROBABLE and downgrades findings when contradicted.

---END PASTE---
