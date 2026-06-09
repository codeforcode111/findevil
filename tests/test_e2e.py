"""End-to-end test for the FinDevil investigation pipeline.

Simulates a full investigation flow WITHOUT requiring Docker/SIFT tools.
The DockerExecutor is mocked to return realistic forensic output, then the
test runs through: initialize case -> run tools -> submit findings ->
self-correct -> generate report.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from findevil.audit.ledger import AuditLedger
from findevil.contracts.compiler import ContractCompiler, ContractViolation
from findevil.contracts.models import Evidence, EvidenceStatus, Finding
from findevil.correction.engine import CorrectionEngine
from findevil.report.generator import generate_json_report, generate_markdown_report
from findevil.tools.executor import DockerExecutor, ExecutionResult
from findevil.tools.registry import ToolRegistry
from findevil.vault.evidence import EvidenceVault

# ---------------------------------------------------------------------------
# Realistic mock tool outputs
# ---------------------------------------------------------------------------

VOLATILITY_PSLIST_OUTPUT = """\
Volatility 3 Framework 2.5.2

PID\tPPID\tImageFileName\tOffset(V)\tThreads\tHandles\tSessionId
4\t0\tSystem\t0x8a0128b03040\t140\t-\tN/A
588\t4\tsmss.exe\t0x8a0128b48080\t2\t-\tN/A
692\t680\tcsrss.exe\t0x8a012d034140\t13\t-\t0
3284\t2840\toutlook.exe\t0x8a0131a47080\t45\t-\t1
5816\t3284\trundll32.exe\t0x8a0131b92080\t8\t-\t1
1224\t692\tlsass.exe\t0x8a0129f3a080\t38\t-\t0
"""

VOLATILITY_PSSCAN_OUTPUT = """\
Volatility 3 Framework 2.5.2

PID\tPPID\tImageFileName\tOffset(P)\tThreads\tHandles\tSessionId
4\t0\tSystem\t0x8a0128b03040\t140\t-\tN/A
588\t4\tsmss.exe\t0x8a0128b48080\t2\t-\tN/A
692\t680\tcsrss.exe\t0x8a012d034140\t13\t-\t0
3284\t2840\toutlook.exe\t0x8a0131a47080\t45\t-\t1
5816\t3284\trundll32.exe\t0x8a0131b92080\t8\t-\t1
1224\t692\tlsass.exe\t0x8a0129f3a080\t38\t-\t0
6012\t5816\tcmd.exe\t0x8a0131c01040\t1\t-\t1
"""

VOLATILITY_NETSCAN_OUTPUT = """\
Volatility 3 Framework 2.5.2

Offset\tProto\tLocalAddr\tLocalPort\tForeignAddr\tForeignPort\tState\tPID\tOwner
0x8a0131c45010\tTCPv4\t192.168.1.100\t49832\t185.220.101.42\t443\tESTABLISHED\t5816\trundll32.exe
0x8a0131c47080\tTCPv4\t192.168.1.100\t49833\t185.220.101.42\t8443\tESTABLISHED\t5816\trundll32.exe
0x8a0131c49010\tTCPv4\t192.168.1.100\t445\t0.0.0.0\t0\tLISTENING\t4\tSystem
0x8a0131c4b080\tTCPv4\t192.168.1.100\t135\t0.0.0.0\t0\tLISTENING\t892\tsvchost.exe
"""

VOLATILITY_MALFIND_OUTPUT = """\
Volatility 3 Framework 2.5.2

PID\tProcess\tStart VPN\tEnd VPN\tTag\tProtection\tCommitCharge\tPrivateMemory\tFile output\tHexdump\tDisasm
5816\trundll32.exe\t0x1a0000\t0x1a3000\tVadS\tPAGE_EXECUTE_READWRITE\t3\t1\tDisabled\t4d 5a 90 00 03 00 00 00 ...\tMZ header detected - possible injected PE
"""

HAYABUSA_OUTPUT = """\
Timestamp,RuleTitle,Level,Computer,Channel,EventID,RecordID,Details
2026-06-01 14:23:15.000,Suspicious Process Creation,high,WORKSTATION1,Security,4688,12847,"rundll32.exe launched by outlook.exe with suspicious command line"
2026-06-01 14:23:45.000,LSASS Access Detected,critical,WORKSTATION1,Security,4663,12849,"Process 5816 accessed lsass.exe memory"
2026-06-01 14:25:00.000,Registry Run Key Modified,medium,WORKSTATION1,Security,4657,12851,"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run value added: UpdateService"
2026-06-01 09:15:00.000,Successful Logon Type 10 (RDP),informational,WORKSTATION1,Security,4624,12700,"admin logon via RDP from 192.168.1.50"
"""

FLS_OUTPUT = """\
r/r 14832-128-1:\tUsers/Public/update.exe
r/r 14833-128-1:\tUsers/Public/update.dll
r/r 9483-128-1:\tWindows/Temp/beacon.tmp
d/d 9484-128-1:\tWindows/Temp/cbt_output
r/r 9485-128-1:\tWindows/Temp/cbt_output/whoami.txt
r/r 9486-128-1:\tWindows/Temp/cbt_output/systeminfo.txt
"""

REGRIPPER_OUTPUT = """\
Launching rip.pl v.3.0
Hive: SYSTEM

Run key contents:
  HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run
    UpdateService = C:\\Users\\Public\\update.exe
    SecurityHealth = %ProgramFiles%\\Windows Defender\\MSASCuiL.exe

  LastWrite: 2026-06-01 14:25:02Z

CurrentControlSet: ControlSet001
ComputerName: WORKSTATION1
"""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _sha256(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()


def _make_mock_result(
    executor: DockerExecutor,
    tool: str,
    args: list[str],
    stdout: str,
    stderr: str = "",
    exit_code: int = 0,
) -> ExecutionResult:
    """Build an ExecutionResult as if the tool ran, and log it to the ledger."""
    run_id = executor._next_run_id()
    stdout_hash = _sha256(stdout)
    result = ExecutionResult(
        run_id=run_id,
        tool=tool,
        command=f"docker exec sift-tools {tool} {' '.join(args)}",
        args=args,
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        stdout_hash=stdout_hash,
        duration_ms=150,
    )
    executor.ledger.append("tool_call", {
        "run_id": run_id,
        "tool": tool,
        "command": result.command,
        "args": args,
        "exit_code": exit_code,
        "stdout_hash": stdout_hash,
        "stderr_snippet": stderr[:500],
        "duration_ms": 150,
    })
    return result


def _make_evidence(
    artifact_id: str,
    run_id: str,
    source_file: str,
    excerpt: str,
    content_hash: str | None = None,
) -> Evidence:
    return Evidence(
        artifact_id=artifact_id,
        tool_run_id=run_id,
        source_file=source_file,
        content_hash=content_hash or _sha256(excerpt),
        excerpt=excerpt,
    )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

E2E_EVIDENCE_DIR = Path(__file__).resolve().parent.parent / "cases" / "e2e_test"


@pytest.fixture
def e2e_workspace(tmp_path):
    """Set up workspace directories for the E2E test."""
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    return tmp_path


@pytest.fixture
def ledger(e2e_workspace):
    return AuditLedger(e2e_workspace / "workspace" / "audit.jsonl")


@pytest.fixture
def vault(e2e_workspace, ledger):
    v = EvidenceVault(
        evidence_dir=E2E_EVIDENCE_DIR,
        workspace_dir=e2e_workspace / "workspace",
        ledger=ledger,
    )
    return v


@pytest.fixture
def registry():
    return ToolRegistry()


@pytest.fixture
def executor(registry, ledger):
    return DockerExecutor(
        container_name="sift-tools",
        registry=registry,
        ledger=ledger,
        timeout=60,
    )


@pytest.fixture
def compiler(ledger):
    return ContractCompiler(ledger=ledger)


@pytest.fixture
def correction_engine(ledger, compiler):
    return CorrectionEngine(ledger=ledger, compiler=compiler)


# ---------------------------------------------------------------------------
# End-to-End Test
# ---------------------------------------------------------------------------

class TestE2EInvestigation:
    """Full end-to-end investigation pipeline test."""

    def test_full_investigation_pipeline(
        self,
        e2e_workspace,
        ledger,
        vault,
        registry,
        executor,
        compiler,
        correction_engine,
    ):
        # ==================================================================
        # Phase 1: Initialize case and evidence vault
        # ==================================================================
        vault.initialize()

        assert vault._initialized
        evidence_files = vault.list_files()
        file_names = {f["name"] for f in evidence_files}
        assert "Security.evtx" in file_names
        assert "SYSTEM" in file_names
        assert "memory.dmp" in file_names
        assert vault.verify_integrity()

        # Check the ledger recorded evidence hashing
        hash_events = ledger.query(event_type="evidence_hash")
        assert len(hash_events) >= 3

        # ==================================================================
        # Phase 2: Run forensic tools (mocked)
        # ==================================================================

        # --- Volatility: pslist ---
        pslist_result = _make_mock_result(
            executor, "vol",
            ["-f", "/evidence/memory.dmp", "windows.pslist.PsList"],
            VOLATILITY_PSLIST_OUTPUT,
        )
        assert pslist_result.exit_code == 0
        assert "rundll32.exe" in pslist_result.stdout

        # --- Volatility: psscan ---
        psscan_result = _make_mock_result(
            executor, "vol",
            ["-f", "/evidence/memory.dmp", "windows.psscan.PsScan"],
            VOLATILITY_PSSCAN_OUTPUT,
        )
        assert "cmd.exe" in psscan_result.stdout  # hidden process found

        # --- Volatility: netscan ---
        netscan_result = _make_mock_result(
            executor, "vol",
            ["-f", "/evidence/memory.dmp", "windows.netscan.NetScan"],
            VOLATILITY_NETSCAN_OUTPUT,
        )
        assert "185.220.101.42" in netscan_result.stdout

        # --- Volatility: malfind ---
        malfind_result = _make_mock_result(
            executor, "vol",
            ["-f", "/evidence/memory.dmp", "windows.malfind.Malfind"],
            VOLATILITY_MALFIND_OUTPUT,
        )
        assert "MZ header detected" in malfind_result.stdout

        # --- Hayabusa: EVTX analysis ---
        hayabusa_result = _make_mock_result(
            executor, "hayabusa",
            ["csv-timeline", "-d", "/evidence/Security.evtx", "-o", "/workspace/alerts.csv"],
            HAYABUSA_OUTPUT,
        )
        assert "Suspicious Process Creation" in hayabusa_result.stdout

        # --- Sleuth Kit: file listing ---
        fls_result = _make_mock_result(
            executor, "fls",
            ["-r", "/evidence/disk.img"],
            FLS_OUTPUT,
        )
        assert "update.exe" in fls_result.stdout

        # --- RegRipper: registry analysis ---
        regripper_result = _make_mock_result(
            executor, "regripper",
            ["-r", "/evidence/SYSTEM", "-a"],
            REGRIPPER_OUTPUT,
        )
        assert "UpdateService" in regripper_result.stdout

        # Verify tool calls are in the ledger
        tool_events = ledger.query(event_type="tool_call")
        assert len(tool_events) == 7

        # ==================================================================
        # Phase 3: Submit findings
        # ==================================================================

        findings: dict[str, Finding] = {}

        # --- Finding 1: Cobalt Strike beacon (CONFIRMED) ---
        # Two independent sources: memory analysis + event log
        f1 = Finding(
            finding_id="F-001",
            claim="Cobalt Strike beacon process (rundll32.exe PID 5816 with "
                  "suspicious parent outlook.exe PID 3284)",
            status=EvidenceStatus.CONFIRMED,
            mitre_technique="T1059.003",
            evidence=[
                _make_evidence(
                    "a-001", pslist_result.run_id,
                    "/evidence/memory.dmp",
                    "PID 5816 rundll32.exe (PPID 3284 outlook.exe) with C2 "
                    "connections to 185.220.101.42:443,8443",
                ),
                _make_evidence(
                    "a-002", hayabusa_result.run_id,
                    "/evidence/Security.evtx",
                    "EventID 4688: rundll32.exe launched by outlook.exe with "
                    "suspicious command line",
                ),
            ],
            confidence_basis="Corroborated by memory process listing showing "
                             "rundll32.exe with suspicious parent outlook.exe "
                             "AND event log EventID 4688 confirming creation",
        )
        compiler.validate(f1)  # should pass -- 2 sources, no contradictions
        findings[f1.finding_id] = f1

        # --- Finding 2: Registry persistence (CONFIRMED) ---
        # Two independent sources: registry + event log
        f2 = Finding(
            finding_id="F-002",
            claim="Registry Run key persistence: UpdateService = "
                  "C:\\Users\\Public\\update.exe",
            status=EvidenceStatus.CONFIRMED,
            mitre_technique="T1547.001",
            evidence=[
                _make_evidence(
                    "a-003", regripper_result.run_id,
                    "/evidence/SYSTEM",
                    "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run "
                    "UpdateService = C:\\Users\\Public\\update.exe "
                    "(LastWrite: 2026-06-01 14:25:02Z)",
                ),
                _make_evidence(
                    "a-004", hayabusa_result.run_id,
                    "/evidence/Security.evtx",
                    "EventID 4657: Registry Run Key Modified - UpdateService "
                    "value added at 2026-06-01 14:25:00",
                ),
            ],
            confidence_basis="Corroborated by registry hive analysis showing "
                             "the Run key AND event log EventID 4657 confirming "
                             "registry modification at matching timestamp",
        )
        compiler.validate(f2)
        findings[f2.finding_id] = f2

        # --- Finding 3: Credential dumping (PROBABLE) ---
        # Single source -- only memory evidence, so only PROBABLE
        f3 = Finding(
            finding_id="F-003",
            claim="Credential dumping via lsass.exe access by PID 5816",
            status=EvidenceStatus.PROBABLE,
            mitre_technique="T1003.001",
            evidence=[
                _make_evidence(
                    "a-005", malfind_result.run_id,
                    "/evidence/memory.dmp",
                    "PID 5816 rundll32.exe has PAGE_EXECUTE_READWRITE region "
                    "with injected PE header at 0x1a0000; hayabusa EventID 4663 "
                    "shows PID 5816 accessed lsass.exe memory",
                ),
            ],
            confidence_basis="Memory-only evidence: malfind shows injected code "
                             "in rundll32.exe and LSASS access detected, but no "
                             "independent disk/registry corroboration",
        )
        compiler.validate(f3)
        findings[f3.finding_id] = f3

        # --- Finding 4: Lateral movement via RDP (initially PROBABLE) ---
        f4 = Finding(
            finding_id="F-004",
            claim="Lateral movement via RDP from compromised workstation",
            status=EvidenceStatus.PROBABLE,
            mitre_technique="T1021.001",
            evidence=[
                _make_evidence(
                    "a-006", hayabusa_result.run_id,
                    "/evidence/Security.evtx",
                    "EventID 4624 Type 10 (RDP): admin logon from 192.168.1.50 "
                    "at 2026-06-01 09:15:00",
                ),
            ],
            confidence_basis="Single event log source showing RDP logon; needs "
                             "additional context to determine if malicious",
        )
        compiler.validate(f4)
        findings[f4.finding_id] = f4

        # ==================================================================
        # Phase 4: Self-correction -- contradiction downgrades Finding 4
        # ==================================================================

        # The RDP logon turns out to be a legitimate admin session that
        # happened hours before the compromise timeline started.
        contradiction_evidence = _make_evidence(
            "a-007", hayabusa_result.run_id,
            "/evidence/Security.evtx",
            "EventID 4624 at 09:15:00 is a routine admin RDP session from "
            "192.168.1.50 (IT admin workstation), hours before the attack "
            "timeline beginning at 14:23. No suspicious activity associated.",
        )

        f4_corrected = correction_engine.add_contradiction(
            f4,
            contradiction_evidence,
            "RDP session at 09:15 is legitimate admin activity from IT "
            "workstation 192.168.1.50, occurring 5 hours before compromise. "
            "No lateral movement artifacts found.",
        )

        assert f4_corrected.status == EvidenceStatus.INFERRED
        assert len(f4_corrected.contradictions) == 1
        assert len(f4_corrected.correction_history) == 1
        assert f4_corrected.correction_history[0].before_status == EvidenceStatus.PROBABLE
        assert f4_corrected.correction_history[0].after_status == EvidenceStatus.INFERRED

        # Apply second contradiction to fully refute
        f4_refuted = correction_engine.add_contradiction(
            f4_corrected,
            _make_evidence(
                "a-008", netscan_result.run_id,
                "/evidence/memory.dmp",
                "No RDP-related network connections from PID 5816 or any "
                "suspicious process; only C2 traffic to 185.220.101.42",
            ),
            "Network scan confirms no RDP connections from compromised "
            "process. The RDP session is unrelated to the attack.",
        )

        assert f4_refuted.status == EvidenceStatus.UNKNOWN
        assert len(f4_refuted.contradictions) == 2
        assert len(f4_refuted.correction_history) == 2

        findings[f4.finding_id] = f4_refuted

        # ==================================================================
        # Phase 5: Contract violation auto-fix
        # ==================================================================

        # Attempt to submit a CONFIRMED finding with only one evidence source
        # -- the contract compiler should reject it
        bad_finding = Finding(
            finding_id="F-005",
            claim="Data exfiltration via HTTPS",
            status=EvidenceStatus.CONFIRMED,
            mitre_technique="T1041",
            evidence=[
                _make_evidence(
                    "a-009", netscan_result.run_id,
                    "/evidence/memory.dmp",
                    "Outbound connection to 185.220.101.42:443 from "
                    "rundll32.exe -- possible data exfiltration",
                ),
            ],
            confidence_basis="Single network evidence source",
        )

        # Validate should fail
        with pytest.raises(ContractViolation):
            compiler.validate(bad_finding)

        # Auto-fix the violation
        fixed_finding = correction_engine.fix_contract_violation(bad_finding)

        assert fixed_finding.status == EvidenceStatus.PROBABLE
        assert len(fixed_finding.correction_history) == 1
        assert fixed_finding.correction_history[0].correction_type == "contract_violation"
        assert "requires" in fixed_finding.correction_history[0].reason.lower() or \
               "CONFIRMED" in fixed_finding.correction_history[0].reason

        findings[fixed_finding.finding_id] = fixed_finding

        # ==================================================================
        # Phase 6: Generate reports
        # ==================================================================

        workspace = e2e_workspace / "workspace"

        # JSON report
        json_path = generate_json_report(
            findings, ledger, vault,
            workspace / "report.json",
        )
        assert json_path.exists()
        report_data = json.loads(json_path.read_text())
        assert report_data["evidence_integrity"] is True
        assert report_data["statistics"]["total_findings"] == 5
        assert report_data["statistics"]["chain_valid"] is True
        assert report_data["statistics"]["tool_calls"] == 7
        assert report_data["statistics"]["corrections"] >= 3  # 2 contradictions + 1 contract fix

        # Markdown report
        md_path = generate_markdown_report(
            findings, ledger, vault,
            workspace / "report.md",
        )
        assert md_path.exists()
        md_content = md_path.read_text()
        assert "CONFIRMED" in md_content
        assert "PROBABLE" in md_content
        assert "Cobalt Strike" in md_content
        assert "VALID" in md_content  # chain integrity

        # ==================================================================
        # Phase 7: Verify audit ledger integrity
        # ==================================================================

        assert ledger.verify_chain()

        all_events = ledger.read_all()
        assert len(all_events) > 0

        # Check event types are present
        event_types = {e["event_type"] for e in all_events}
        assert "evidence_hash" in event_types
        assert "case_event" in event_types
        assert "tool_call" in event_types
        assert "correction" in event_types

        # Verify the chain is contiguous (each prev_hash matches prior hash)
        for i, event in enumerate(all_events):
            if i == 0:
                assert event["prev_hash"] is None
            else:
                assert event["prev_hash"] == all_events[i - 1]["hash"]

        # ==================================================================
        # Phase 8: Verify against ground truth
        # ==================================================================

        gt_path = E2E_EVIDENCE_DIR / "ground_truth.json"
        ground_truth = json.loads(gt_path.read_text())

        gt_findings = {
            f["mitre_technique"]: f for f in ground_truth["expected_findings"]
        }

        # F-001: Cobalt Strike beacon -> CONFIRMED
        assert findings["F-001"].status == EvidenceStatus.CONFIRMED
        assert gt_findings["T1059.003"]["expected_status"] == "confirmed"

        # F-002: Registry persistence -> CONFIRMED
        assert findings["F-002"].status == EvidenceStatus.CONFIRMED
        assert gt_findings["T1547.001"]["expected_status"] == "confirmed"

        # F-003: Credential dumping -> PROBABLE
        assert findings["F-003"].status == EvidenceStatus.PROBABLE
        assert gt_findings["T1003.001"]["expected_status"] == "probable"

        # F-004: Lateral movement -> refuted (downgraded to UNKNOWN via 2 contradictions)
        assert findings["F-004"].status == EvidenceStatus.UNKNOWN
        # Ground truth says "refuted" -- our UNKNOWN matches the refuted intent
        # since the finding was downgraded past INFERRED due to contradictions
        assert gt_findings["T1021.001"]["expected_status"] == "refuted"
        assert len(findings["F-004"].contradictions) == 2

        # F-005: Data exfiltration -> auto-downgraded from CONFIRMED to PROBABLE
        assert findings["F-005"].status == EvidenceStatus.PROBABLE


    def test_evidence_vault_integrity_preserved(self, vault, ledger):
        """Verify that evidence files remain unmodified throughout."""
        vault.initialize()
        assert vault.verify_integrity()

        # Simulate reading evidence files (as tools would)
        for f in vault.list_files():
            Path(f["path"]).read_bytes()

        # Integrity should still hold
        assert vault.verify_integrity()


    def test_tool_run_ids_are_unique(self, executor, ledger):
        """Every mock tool call should produce a unique run_id."""
        results = []
        results.append(_make_mock_result(
            executor, "vol",
            ["-f", "/evidence/memory.dmp", "windows.pslist.PsList"],
            VOLATILITY_PSLIST_OUTPUT,
        ))
        results.append(_make_mock_result(
            executor, "hayabusa",
            ["csv-timeline", "-d", "/evidence/Security.evtx"],
            HAYABUSA_OUTPUT,
        ))
        results.append(_make_mock_result(
            executor, "regripper",
            ["-r", "/evidence/SYSTEM", "-a"],
            REGRIPPER_OUTPUT,
        ))

        run_ids = [r.run_id for r in results]
        assert len(run_ids) == len(set(run_ids)), "Run IDs must be unique"


    def test_contract_rejects_ghost_run_ids(self, ledger, compiler):
        """Findings citing non-existent run_ids should be rejected."""
        finding = Finding(
            finding_id="F-GHOST",
            claim="Fabricated finding",
            status=EvidenceStatus.PROBABLE,
            mitre_technique="T1059",
            evidence=[
                _make_evidence(
                    "ghost-001", "run-9999",
                    "/evidence/memory.dmp",
                    "This run_id does not exist in the ledger",
                ),
            ],
            confidence_basis="fabricated",
        )
        with pytest.raises(ContractViolation, match="not found"):
            compiler.validate(finding)


    def test_double_contradiction_fully_downgrades(
        self, ledger, compiler, correction_engine, executor,
    ):
        """Two contradictions on a CONFIRMED finding should downgrade twice."""
        # Register tool runs so evidence is valid
        r1 = _make_mock_result(executor, "vol",
                               ["-f", "/evidence/memory.dmp", "windows.pslist.PsList"],
                               VOLATILITY_PSLIST_OUTPUT)
        r2 = _make_mock_result(executor, "hayabusa",
                               ["csv-timeline", "-d", "/evidence/Security.evtx"],
                               HAYABUSA_OUTPUT)

        finding = Finding(
            finding_id="F-DOUBLE",
            claim="Test double contradiction",
            status=EvidenceStatus.CONFIRMED,
            mitre_technique="T1059",
            evidence=[
                _make_evidence("d1", r1.run_id, "/evidence/memory.dmp",
                               "supporting evidence A"),
                _make_evidence("d2", r2.run_id, "/evidence/Security.evtx",
                               "supporting evidence B"),
            ],
            confidence_basis="two sources",
        )

        # First contradiction: CONFIRMED -> PROBABLE
        c1 = correction_engine.add_contradiction(
            finding,
            _make_evidence("c1", r1.run_id, "/evidence/memory.dmp",
                           "contradicting evidence 1"),
            "First contradiction",
        )
        assert c1.status == EvidenceStatus.PROBABLE

        # Second contradiction: PROBABLE -> INFERRED
        c2 = correction_engine.add_contradiction(
            c1,
            _make_evidence("c2", r2.run_id, "/evidence/Security.evtx",
                           "contradicting evidence 2"),
            "Second contradiction",
        )
        assert c2.status == EvidenceStatus.INFERRED
        assert len(c2.contradictions) == 2
        assert len(c2.correction_history) == 2
