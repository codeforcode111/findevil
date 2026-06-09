#!/usr/bin/env python3
"""End-to-end test using REAL forensic evidence data.

Runs Hayabusa against 877 real Windows EVTX attack samples, then
uses the full FinDevil pipeline to process findings.

Usage:
    docker compose up -d
    python scripts/run_real_evidence_test.py
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from findevil.audit.ledger import AuditLedger
from findevil.contracts.compiler import ContractCompiler, ContractViolation
from findevil.contracts.models import Evidence, EvidenceStatus, Finding
from findevil.correction.engine import CorrectionEngine
from findevil.report.generator import generate_json_report, generate_markdown_report
from findevil.tools.executor import DockerExecutor, ToolExecutionError
from findevil.tools.registry import ToolRegistry
from findevil.vault.evidence import EvidenceVault


def _sha(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def section(title: str):
    print(f"\n{'='*70}")
    print(f"  {title}")
    print(f"{'='*70}")


def main():
    section("FinDevil Real Evidence E2E Test")

    evidence_dir = PROJECT_ROOT / "cases" / "real_evidence"
    workspace_dir = PROJECT_ROOT / "workspace"
    workspace_dir.mkdir(exist_ok=True)

    # Clean previous run
    audit_path = workspace_dir / "audit_real.jsonl"
    if audit_path.exists():
        audit_path.unlink()

    # Initialize components
    ledger = AuditLedger(audit_path)
    vault = EvidenceVault(evidence_dir=evidence_dir, workspace_dir=workspace_dir, ledger=ledger)
    registry = ToolRegistry()
    executor = DockerExecutor(container_name="findevil-sift", registry=registry, ledger=ledger)
    compiler = ContractCompiler(ledger=ledger)
    correction = CorrectionEngine(ledger=ledger, compiler=compiler)

    # ======================================================================
    # Phase 1: Initialize evidence vault
    # ======================================================================
    section("Phase 1: Initialize Evidence Vault")
    vault.initialize()
    evtx_files = [f for f in vault.list_files() if f["name"].endswith(".evtx")]
    print(f"  Total evidence files: {len(vault.file_hashes)}")
    print(f"  EVTX files: {len(evtx_files)}")
    print(f"  Evidence integrity: {'PASSED' if vault.verify_integrity() else 'FAILED'}")

    # ======================================================================
    # Phase 2: Run Hayabusa on EVTX attack samples
    # ======================================================================
    section("Phase 2: Hayabusa Scan — EVTX Attack Samples (MITRE ATT&CK)")
    print("  Scanning attack_samples/ directory (278 EVTX files)...")

    try:
        hayabusa_attack = executor.execute("hayabusa", [
            "csv-timeline",
            "-d", "/evidence/attack_samples",
            "-o", "/workspace/hayabusa_attack_results.csv",
            "-q", "--no-wizard",
        ])
        print(f"  [{'OK' if hayabusa_attack.exit_code == 0 else 'WARN'}] run_id={hayabusa_attack.run_id}, duration={hayabusa_attack.duration_ms}ms")

        # Parse results
        lines = hayabusa_attack.stdout.strip().split("\n")
        # Look for summary lines
        for line in lines:
            clean = line.replace("\x1b[0m", "").replace("\x1b[38;2;0;255;0m", "").replace("\x1b[38;2;255;175;0m", "").replace("\x1b[38;2;255;0;0m", "").replace("\x1b[38;2;255;255;0m", "")
            if any(kw in clean.lower() for kw in ["total", "detect", "critical", "high", "medium", "low", "informational", "unique"]):
                print(f"  | {clean.strip()}")
    except ToolExecutionError as e:
        print(f"  [FAIL] {e}")
        hayabusa_attack = None

    # ======================================================================
    # Phase 3: Run Hayabusa on hayabusa-sample-evtx
    # ======================================================================
    section("Phase 3: Hayabusa Scan — Hayabusa Sample EVTX (599 files)")
    print("  Scanning evtx/ directory...")

    try:
        hayabusa_samples = executor.execute("hayabusa", [
            "csv-timeline",
            "-d", "/evidence/evtx",
            "-o", "/workspace/hayabusa_sample_results.csv",
            "-q", "--no-wizard",
        ])
        print(f"  [{'OK' if hayabusa_samples.exit_code == 0 else 'WARN'}] run_id={hayabusa_samples.run_id}, duration={hayabusa_samples.duration_ms}ms")

        lines = hayabusa_samples.stdout.strip().split("\n")
        for line in lines:
            clean = line.replace("\x1b[0m", "").replace("\x1b[38;2;0;255;0m", "").replace("\x1b[38;2;255;175;0m", "").replace("\x1b[38;2;255;0;0m", "").replace("\x1b[38;2;255;255;0m", "")
            if any(kw in clean.lower() for kw in ["total", "detect", "critical", "high", "medium", "low", "informational", "unique"]):
                print(f"  | {clean.strip()}")
    except ToolExecutionError as e:
        print(f"  [FAIL] {e}")
        hayabusa_samples = None

    # ======================================================================
    # Phase 4: Read Hayabusa CSV results and create findings
    # ======================================================================
    section("Phase 4: Process Hayabusa Results into Findings")

    findings: dict[str, Finding] = {}
    finding_counter = 0

    # Read the CSV output from workspace
    csv_path = workspace_dir / "hayabusa_attack_results.csv"
    if csv_path.exists():
        csv_content = csv_path.read_text()
        csv_lines = [l for l in csv_content.strip().split("\n") if l.strip()]
        print(f"  Hayabusa attack results: {len(csv_lines) - 1} detections (excluding header)")

        # Parse critical and high alerts
        critical_alerts = []
        high_alerts = []
        for line in csv_lines[1:]:  # skip header
            if "critical" in line.lower() or "crit" in line.lower():
                critical_alerts.append(line)
            elif "high" in line.lower():
                high_alerts.append(line)

        print(f"  Critical alerts: {len(critical_alerts)}")
        print(f"  High alerts: {len(high_alerts)}")

        # Create findings from critical alerts (top 5)
        for i, alert_line in enumerate(critical_alerts[:5]):
            finding_counter += 1
            fid = f"F-{finding_counter:03d}"
            parts = alert_line.split(",")
            rule_title = parts[1] if len(parts) > 1 else "Unknown alert"
            details = parts[-1] if len(parts) > 5 else alert_line[:200]

            run_id = hayabusa_attack.run_id if hayabusa_attack else "unknown"

            f = Finding(
                finding_id=fid,
                claim=f"Critical alert: {rule_title.strip()[:100]}",
                status=EvidenceStatus.PROBABLE,
                mitre_technique="T1059",
                evidence=[Evidence(
                    artifact_id=f"evtx-attack-{i+1}",
                    tool_run_id=run_id,
                    source_file="/evidence/attack_samples",
                    content_hash=_sha(alert_line),
                    excerpt=alert_line[:300],
                )],
                confidence_basis=f"Single source: Hayabusa detection rule matched against real EVTX attack sample. "
                                 f"Rule: {rule_title.strip()[:80]}",
            )

            # Validate through contract compiler
            violations = compiler.compile([f])
            if violations:
                f = correction.fix_contract_violation(f)
                print(f"  [{fid}] {rule_title.strip()[:60]} — AUTO-CORRECTED to {f.status.value}")
            else:
                print(f"  [{fid}] {rule_title.strip()[:60]} — {f.status.value}")

            findings[fid] = f

        # Create findings from high alerts (top 5)
        for i, alert_line in enumerate(high_alerts[:5]):
            finding_counter += 1
            fid = f"F-{finding_counter:03d}"
            parts = alert_line.split(",")
            rule_title = parts[1] if len(parts) > 1 else "Unknown alert"
            run_id = hayabusa_attack.run_id if hayabusa_attack else "unknown"

            f = Finding(
                finding_id=fid,
                claim=f"High alert: {rule_title.strip()[:100]}",
                status=EvidenceStatus.PROBABLE,
                mitre_technique="T1059",
                evidence=[Evidence(
                    artifact_id=f"evtx-high-{i+1}",
                    tool_run_id=run_id,
                    source_file="/evidence/attack_samples",
                    content_hash=_sha(alert_line),
                    excerpt=alert_line[:300],
                )],
                confidence_basis=f"Single source: Hayabusa high-severity detection. Rule: {rule_title.strip()[:80]}",
            )
            findings[fid] = f
            print(f"  [{fid}] {rule_title.strip()[:60]} — {f.status.value}")

    else:
        print("  [WARN] No CSV results file found")

    # ======================================================================
    # Phase 5: Self-Correction Demo — Try to confirm single-source finding
    # ======================================================================
    section("Phase 5: Self-Correction Demo")

    if findings:
        first_fid = list(findings.keys())[0]
        first_finding = findings[first_fid]

        # Try to upgrade to CONFIRMED — should fail (single source)
        upgraded = first_finding.model_copy(update={"status": EvidenceStatus.CONFIRMED})
        violations = compiler.compile([upgraded])
        if violations:
            print(f"  Contract violation caught: {violations[0].message}")
            fixed = correction.fix_contract_violation(upgraded)
            print(f"  Auto-corrected: CONFIRMED → {fixed.status.value}")
            findings[first_fid] = fixed
        else:
            print(f"  [OK] Finding {first_fid} passed contract validation")

    # ======================================================================
    # Phase 6: Generate Reports
    # ======================================================================
    section("Phase 6: Generate Reports")

    json_path = generate_json_report(findings, ledger, vault, workspace_dir / "real_report.json")
    md_path = generate_markdown_report(findings, ledger, vault, workspace_dir / "real_report.md")

    print(f"  JSON report: {json_path}")
    print(f"  Markdown report: {md_path}")

    # ======================================================================
    # Phase 7: Final Summary
    # ======================================================================
    section("Final Summary")

    tool_events = ledger.query(event_type="tool_call")
    correction_events = ledger.query(event_type="correction")

    print(f"  Evidence files hashed: {len(vault.file_hashes)}")
    print(f"  EVTX files scanned: {len(evtx_files)}")
    print(f"  Tool calls executed: {len(tool_events)}")
    print(f"  Findings created: {len(findings)}")
    by_status = {}
    for f in findings.values():
        by_status[f.status.value] = by_status.get(f.status.value, 0) + 1
    for status, count in sorted(by_status.items()):
        print(f"    {status}: {count}")
    print(f"  Self-corrections: {len(correction_events)}")
    print(f"  Audit chain: {'VALID' if ledger.verify_chain() else 'INVALID'}")
    print(f"  Evidence integrity: {'PASSED' if vault.verify_integrity() else 'FAILED'}")
    print(f"  Total audit events: {len(ledger.read_all())}")

    # Verify chain
    assert ledger.verify_chain(), "Audit chain integrity check failed!"
    assert vault.verify_integrity(), "Evidence integrity check failed!"

    print(f"\n  [SUCCESS] Real evidence E2E test completed")


if __name__ == "__main__":
    main()
