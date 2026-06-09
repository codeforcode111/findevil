#!/usr/bin/env python3
"""End-to-end test using the real Docker SIFT container.

Usage:
    docker compose up -d
    python scripts/run_e2e_docker.py

This script initializes the investigation runtime, runs real forensic tools
against the synthetic evidence in cases/e2e_test/, and generates a report.
"""
from __future__ import annotations

import json
import subprocess
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


def check_container():
    """Verify the SIFT container is running."""
    result = subprocess.run(
        ["docker", "ps", "--filter", "name=findevil-sift", "--format", "{{.Status}}"],
        capture_output=True, text=True, timeout=5,
    )
    if not result.stdout.strip():
        print("[ERROR] SIFT container not running. Start with: docker compose up -d")
        sys.exit(1)
    print(f"[OK] SIFT container: {result.stdout.strip()}")


def run_tool_safe(executor: DockerExecutor, tool: str, args: list[str], desc: str):
    """Run a tool and handle errors gracefully."""
    print(f"\n{'='*60}")
    print(f"Running: {desc}")
    print(f"  Tool: {tool}")
    print(f"  Args: {' '.join(args)}")
    print(f"{'='*60}")
    try:
        result = executor.execute(tool, args)
        status = "OK" if result.exit_code == 0 else f"WARN (exit {result.exit_code})"
        print(f"  [{status}] run_id={result.run_id}, duration={result.duration_ms}ms")
        if result.stdout:
            lines = result.stdout.strip().split("\n")
            for line in lines[:20]:
                print(f"  | {line}")
            if len(lines) > 20:
                print(f"  | ... ({len(lines) - 20} more lines)")
        if result.stderr:
            print(f"  [STDERR] {result.stderr[:200]}")
        return result
    except ToolExecutionError as e:
        print(f"  [FAIL] {e}")
        return None


def main():
    print("=" * 60)
    print("FinDevil E2E Docker Test")
    print("=" * 60)

    check_container()

    evidence_dir = PROJECT_ROOT / "cases" / "e2e_test"
    workspace_dir = PROJECT_ROOT / "workspace"
    workspace_dir.mkdir(exist_ok=True)

    ledger = AuditLedger(workspace_dir / "audit.jsonl")
    vault = EvidenceVault(
        evidence_dir=evidence_dir,
        workspace_dir=workspace_dir,
        ledger=ledger,
    )
    registry = ToolRegistry()
    executor = DockerExecutor(
        container_name="findevil-sift",
        registry=registry,
        ledger=ledger,
    )
    compiler = ContractCompiler(ledger=ledger)
    correction = CorrectionEngine(ledger=ledger, compiler=compiler)

    # Phase 1: Initialize
    print("\n[Phase 1] Initializing evidence vault...")
    vault.initialize()
    print(f"  Evidence files: {len(vault.file_hashes)}")
    for name, h in vault.file_hashes.items():
        print(f"    {name}: {h[:16]}...")

    # Phase 2: Run tools
    print("\n[Phase 2] Running forensic tools...")

    # Test Sleuth Kit
    fls_result = run_tool_safe(
        executor, "fls", ["/evidence/Security.evtx"],
        "Sleuth Kit file listing on Security.evtx",
    )

    # Test strings
    strings_result = run_tool_safe(
        executor, "strings", ["/evidence/memory.dmp"],
        "Extract strings from memory dump",
    )

    # Test YARA (basic)
    yara_result = run_tool_safe(
        executor, "yara", ["/evidence/memory.dmp"],
        "YARA scan on memory dump (no rules, will fail — testing error handling)",
    )

    # Test Hayabusa
    hayabusa_result = run_tool_safe(
        executor, "hayabusa",
        ["csv-timeline", "-d", "/evidence", "-o", "/workspace/hayabusa_out.csv", "-q", "--no-wizard"],
        "Hayabusa EVTX timeline",
    )

    # Test Volatility (will fail on synthetic data — that's fine, testing self-correction)
    vol_result = run_tool_safe(
        executor, "vol",
        ["-f", "/evidence/memory.dmp", "windows.pslist.PsList"],
        "Volatility pslist (expected to fail on synthetic dump)",
    )

    # Phase 3: Check self-correction logging
    print("\n[Phase 3] Checking audit ledger...")
    tool_events = ledger.query(event_type="tool_call")
    correction_events = ledger.query(event_type="correction")
    print(f"  Tool calls logged: {len(tool_events)}")
    print(f"  Corrections logged: {len(correction_events)}")
    print(f"  Chain integrity: {'VALID' if ledger.verify_chain() else 'INVALID'}")

    # Phase 4: Generate report
    print("\n[Phase 4] Generating reports...")
    findings = {}

    # If any tool produced output, create a finding
    for result in [fls_result, strings_result, hayabusa_result, vol_result]:
        if result and result.exit_code == 0 and result.stdout.strip():
            f = Finding(
                finding_id=f"F-{len(findings)+1:03d}",
                claim=f"Tool {result.tool} produced output on synthetic evidence",
                status=EvidenceStatus.INFERRED,
                mitre_technique="T1059",
                evidence=[Evidence(
                    artifact_id=f"art-{len(findings)+1:03d}",
                    tool_run_id=result.run_id,
                    source_file=f"/evidence/{result.args[0] if result.args else 'unknown'}",
                    content_hash=result.stdout_hash,
                    excerpt=result.stdout[:200],
                )],
                confidence_basis="Synthetic test data — tool ran successfully",
            )
            findings[f.finding_id] = f

    json_path = generate_json_report(findings, ledger, vault, workspace_dir / "report.json")
    md_path = generate_markdown_report(findings, ledger, vault, workspace_dir / "report.md")

    print(f"  JSON report: {json_path}")
    print(f"  Markdown report: {md_path}")

    # Summary
    print("\n" + "=" * 60)
    print("E2E Docker Test Summary")
    print("=" * 60)
    print(f"  Evidence files: {len(vault.file_hashes)}")
    print(f"  Tool calls: {len(tool_events)}")
    print(f"  Findings: {len(findings)}")
    print(f"  Corrections: {len(correction_events)}")
    print(f"  Audit chain: {'VALID' if ledger.verify_chain() else 'INVALID'}")
    print(f"  Evidence integrity: {'PASSED' if vault.verify_integrity() else 'FAILED'}")
    print("=" * 60)


if __name__ == "__main__":
    main()
