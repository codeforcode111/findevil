"""FinDevil MCP Server -- exposes all forensic tools as MCP tools for Claude Code."""
from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

from fastmcp import FastMCP

from findevil.audit.ledger import AuditLedger
from findevil.contracts.compiler import ContractCompiler, ContractViolation
from findevil.contracts.models import Evidence, EvidenceStatus, Finding
from findevil.correction.engine import CorrectionEngine
from findevil.tools.executor import DockerExecutor, ToolExecutionError
from findevil.tools.registry import ToolRegistry
from findevil.tools import (
    volatility,
    plaso,
    sleuthkit,
    hayabusa,
    yara_scanner,
    zimmerman,
)
from findevil.vault.evidence import EvidenceVault

MAX_OUTPUT = 10_000

mcp = FastMCP("FinDevil")

# ---------------------------------------------------------------------------
# Shared mutable state -- initialised by ``investigate_case``
# ---------------------------------------------------------------------------
_state: dict[str, Any] = {}


def _truncate(text: str) -> str:
    if len(text) <= MAX_OUTPUT:
        return text
    return text[:MAX_OUTPUT] + "\n... [truncated]"


def _json(obj: Any) -> str:
    return _truncate(json.dumps(obj, default=str, indent=2))


def _result_to_dict(result: Any) -> dict[str, Any]:
    """Convert an ExecutionResult dataclass to a JSON-serialisable dict."""
    return {
        "run_id": result.run_id,
        "tool": result.tool,
        "command": result.command,
        "exit_code": result.exit_code,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "stdout_hash": result.stdout_hash,
        "duration_ms": result.duration_ms,
    }


# ===================================================================
# 1. Investigation Management
# ===================================================================


@mcp.tool()
def investigate_case(evidence_path: str, workspace_path: str) -> str:
    """Initialise a new forensic investigation case.

    Sets up the evidence vault, tool executor, contract compiler, and
    correction engine.  Hashes all evidence files and returns the file list.
    """
    evidence_dir = Path(evidence_path)
    workspace_dir = Path(workspace_path)

    ledger_path = workspace_dir / "audit_ledger.jsonl"
    workspace_dir.mkdir(parents=True, exist_ok=True)

    ledger = AuditLedger(ledger_path)
    vault = EvidenceVault(evidence_dir, workspace_dir, ledger)
    vault.initialize()

    registry = ToolRegistry()
    executor = DockerExecutor(
        container_name="findevil-tools",
        registry=registry,
        ledger=ledger,
    )
    compiler = ContractCompiler(ledger)
    correction = CorrectionEngine(ledger, compiler)

    _state.update({
        "vault": vault,
        "ledger": ledger,
        "registry": registry,
        "executor": executor,
        "compiler": compiler,
        "correction": correction,
        "findings": {},
        "finding_counter": 0,
    })

    files = vault.list_files()
    return _json({
        "status": "initialized",
        "evidence_count": len(files),
        "files": files,
    })


@mcp.tool()
def get_case_status() -> str:
    """Return current case status: findings count, tool calls, corrections."""
    if not _state:
        return _json({"error": "No case initialized. Call investigate_case first."})

    ledger: AuditLedger = _state["ledger"]
    findings: dict[str, Finding] = _state["findings"]

    tool_calls = ledger.query(event_type="tool_call")
    corrections = ledger.query(event_type="correction")

    status_counts: dict[str, int] = {}
    for f in findings.values():
        key = f.status.value
        status_counts[key] = status_counts.get(key, 0) + 1

    return _json({
        "findings_total": len(findings),
        "findings_by_status": status_counts,
        "tool_calls": len(tool_calls),
        "corrections": len(corrections),
    })


@mcp.tool()
def list_evidence() -> str:
    """List available evidence files in the vault."""
    if not _state:
        return _json({"error": "No case initialized. Call investigate_case first."})
    vault: EvidenceVault = _state["vault"]
    return _json(vault.list_files())


# ===================================================================
# 2. Forensic Analysis
# ===================================================================


@mcp.tool()
def analyze_memory(
    dump_path: str,
    plugin: str = "pslist",
    extra_args: str = "",
) -> str:
    """Run a Volatility 3 plugin against a memory dump.

    ``plugin`` can be a short name (pslist, netscan, ...) or a full class path.
    ``extra_args`` is a space-separated string of additional CLI flags.
    """
    if not _state:
        return _json({"error": "No case initialized. Call investigate_case first."})
    executor: DockerExecutor = _state["executor"]
    correction: CorrectionEngine = _state["correction"]
    extra = extra_args.split() if extra_args else None
    try:
        result = volatility.run_plugin(executor, dump_path, plugin, extra)
        return _json(_result_to_dict(result))
    except ToolExecutionError as exc:
        correction.record_tool_failure("vol", [dump_path, plugin], str(exc))
        return _json({"error": str(exc)})


@mcp.tool()
def build_timeline(
    source_path: str,
    output_path: str = "/workspace/timeline.plaso",
) -> str:
    """Create a super-timeline with Plaso (log2timeline + psort)."""
    if not _state:
        return _json({"error": "No case initialized. Call investigate_case first."})
    executor: DockerExecutor = _state["executor"]
    correction: CorrectionEngine = _state["correction"]
    try:
        result = plaso.create_timeline(executor, source_path, output_path)
        return _json(_result_to_dict(result))
    except ToolExecutionError as exc:
        correction.record_tool_failure("log2timeline", [source_path], str(exc))
        return _json({"error": str(exc)})


@mcp.tool()
def analyze_filesystem(
    image_path: str,
    operation: str = "list",
    inode: str = "",
    offset: int = 0,
) -> str:
    """Run Sleuth Kit operations on a disk image.

    ``operation``: list | extract | partitions | info
    ``inode``: required for extract
    ``offset``: partition offset in sectors (0 = auto)
    """
    if not _state:
        return _json({"error": "No case initialized. Call investigate_case first."})
    executor: DockerExecutor = _state["executor"]
    correction: CorrectionEngine = _state["correction"]
    off = offset if offset else None
    try:
        if operation == "extract":
            if not inode:
                return _json({"error": "inode is required for extract operation"})
            result = sleuthkit.extract_file(executor, image_path, inode, off)
        elif operation == "partitions":
            result = sleuthkit.partition_table(executor, image_path)
        elif operation == "info":
            result = sleuthkit.image_info(executor, image_path)
        else:
            result = sleuthkit.list_files(executor, image_path, off)
        return _json(_result_to_dict(result))
    except ToolExecutionError as exc:
        correction.record_tool_failure("fls", [image_path, operation], str(exc))
        return _json({"error": str(exc)})


@mcp.tool()
def scan_eventlogs(
    evtx_path: str,
    min_level: str = "medium",
) -> str:
    """Scan Windows EVTX logs with Hayabusa / Sigma rules."""
    if not _state:
        return _json({"error": "No case initialized. Call investigate_case first."})
    executor: DockerExecutor = _state["executor"]
    correction: CorrectionEngine = _state["correction"]
    try:
        result = hayabusa.scan_evtx(executor, evtx_path, min_level=min_level)
        return _json(_result_to_dict(result))
    except ToolExecutionError as exc:
        correction.record_tool_failure("hayabusa", [evtx_path], str(exc))
        return _json({"error": str(exc)})


@mcp.tool()
def scan_yara(
    rules_path: str,
    target_path: str,
) -> str:
    """Run YARA rules against a target file or directory."""
    if not _state:
        return _json({"error": "No case initialized. Call investigate_case first."})
    executor: DockerExecutor = _state["executor"]
    correction: CorrectionEngine = _state["correction"]
    try:
        result = yara_scanner.scan(executor, rules_path, target_path)
        return _json(_result_to_dict(result))
    except ToolExecutionError as exc:
        correction.record_tool_failure("yara", [rules_path, target_path], str(exc))
        return _json({"error": str(exc)})


@mcp.tool()
def analyze_registry(
    hive_path: str,
    plugin: str = "",
) -> str:
    """Analyse a Windows registry hive with RegRipper."""
    if not _state:
        return _json({"error": "No case initialized. Call investigate_case first."})
    executor: DockerExecutor = _state["executor"]
    correction: CorrectionEngine = _state["correction"]
    plug = plugin if plugin else None
    try:
        result = zimmerman.analyze_registry(executor, hive_path, plug)
        return _json(_result_to_dict(result))
    except ToolExecutionError as exc:
        correction.record_tool_failure("regripper", [hive_path], str(exc))
        return _json({"error": str(exc)})


@mcp.tool()
def analyze_artifacts(
    artifact_type: str,
    path: str,
) -> str:
    """Parse Windows artifacts with Zimmerman tools.

    ``artifact_type``: mft | prefetch | amcache
    """
    if not _state:
        return _json({"error": "No case initialized. Call investigate_case first."})
    executor: DockerExecutor = _state["executor"]
    correction: CorrectionEngine = _state["correction"]
    try:
        if artifact_type == "mft":
            result = zimmerman.parse_mft(executor, path)
        elif artifact_type == "prefetch":
            result = zimmerman.parse_prefetch(executor, path)
        elif artifact_type == "amcache":
            result = zimmerman.parse_amcache(executor, path)
        else:
            return _json({"error": f"Unknown artifact_type: {artifact_type}. Use mft, prefetch, or amcache."})
        return _json(_result_to_dict(result))
    except ToolExecutionError as exc:
        correction.record_tool_failure(artifact_type, [path], str(exc))
        return _json({"error": str(exc)})


# ===================================================================
# 3. Evidence Contract
# ===================================================================


@mcp.tool()
def submit_finding(
    claim: str,
    status: str = "probable",
    mitre_technique: str = "",
    confidence_basis: str = "",
    evidence_items: str = "[]",
) -> str:
    """Submit an investigative finding with supporting evidence.

    ``status``: confirmed | probable | inferred | refuted | unknown
    ``evidence_items``: JSON string -- list of dicts, each with keys:
        artifact_id, tool_run_id, source_file, content_hash, excerpt
    """
    if not _state:
        return _json({"error": "No case initialized. Call investigate_case first."})

    compiler: ContractCompiler = _state["compiler"]
    correction: CorrectionEngine = _state["correction"]
    ledger: AuditLedger = _state["ledger"]
    findings: dict[str, Finding] = _state["findings"]

    _state["finding_counter"] = _state.get("finding_counter", 0) + 1
    finding_id = f"F-{_state['finding_counter']:04d}"

    try:
        items = json.loads(evidence_items)
    except json.JSONDecodeError as exc:
        return _json({"error": f"Invalid evidence_items JSON: {exc}"})

    if not items:
        return _json({"error": "At least one evidence item is required"})

    evidence_list = [Evidence(**item) for item in items]
    ev_status = EvidenceStatus(status)

    finding = Finding(
        finding_id=finding_id,
        claim=claim,
        status=ev_status,
        mitre_technique=mitre_technique,
        evidence=evidence_list,
        confidence_basis=confidence_basis,
    )

    # Validate through compiler; auto-downgrade on violation
    try:
        compiler.validate(finding)
    except ContractViolation:
        finding = correction.fix_contract_violation(finding)

    findings[finding_id] = finding
    ledger.append("finding_submitted", {
        "finding_id": finding_id,
        "claim": claim,
        "status": finding.status.value,
    })

    return _json({
        "finding_id": finding_id,
        "status": finding.status.value,
        "evidence_count": len(finding.evidence),
        "corrections": len(finding.correction_history),
    })


@mcp.tool()
def search_contradictions(finding_id: str) -> str:
    """Show current evidence and contradictions for a finding."""
    if not _state:
        return _json({"error": "No case initialized. Call investigate_case first."})
    findings: dict[str, Finding] = _state["findings"]
    finding = findings.get(finding_id)
    if not finding:
        return _json({"error": f"Finding '{finding_id}' not found"})

    return _json({
        "finding_id": finding_id,
        "status": finding.status.value,
        "evidence": [e.model_dump() for e in finding.evidence],
        "contradictions": [c.model_dump() for c in finding.contradictions],
        "correction_history": [cr.model_dump() for cr in finding.correction_history],
    })


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
    """Add contradicting evidence to a finding, triggering auto-downgrade."""
    if not _state:
        return _json({"error": "No case initialized. Call investigate_case first."})
    findings: dict[str, Finding] = _state["findings"]
    correction: CorrectionEngine = _state["correction"]

    finding = findings.get(finding_id)
    if not finding:
        return _json({"error": f"Finding '{finding_id}' not found"})

    contradiction = Evidence(
        artifact_id=artifact_id,
        tool_run_id=tool_run_id,
        source_file=source_file,
        content_hash=content_hash,
        excerpt=excerpt,
    )

    updated = correction.add_contradiction(finding, contradiction, reason)
    findings[finding_id] = updated

    return _json({
        "finding_id": finding_id,
        "previous_status": finding.status.value,
        "new_status": updated.status.value,
        "contradictions_count": len(updated.contradictions),
    })


# ===================================================================
# 4. Audit & Reporting
# ===================================================================


@mcp.tool()
def trace_finding(finding_id: str) -> str:
    """Return the full evidence chain for a finding (evidence, tool runs, corrections)."""
    if not _state:
        return _json({"error": "No case initialized. Call investigate_case first."})

    findings: dict[str, Finding] = _state["findings"]
    ledger: AuditLedger = _state["ledger"]

    finding = findings.get(finding_id)
    if not finding:
        return _json({"error": f"Finding '{finding_id}' not found"})

    related_events = ledger.query(finding_id=finding_id)
    tool_run_events = [
        e for e in ledger.query(event_type="tool_call")
        if e["data"].get("run_id") in finding.tool_run_ids
    ]

    return _json({
        "finding_id": finding_id,
        "claim": finding.claim,
        "status": finding.status.value,
        "evidence": [e.model_dump() for e in finding.evidence],
        "contradictions": [c.model_dump() for c in finding.contradictions],
        "correction_history": [cr.model_dump() for cr in finding.correction_history],
        "related_audit_events": related_events,
        "tool_run_events": tool_run_events,
    })


@mcp.tool()
def generate_report(output_format: str = "json") -> str:
    """Generate a case report in JSON or Markdown format."""
    if not _state:
        return _json({"error": "No case initialized. Call investigate_case first."})

    findings: dict[str, Finding] = _state["findings"]
    ledger: AuditLedger = _state["ledger"]

    findings_data = []
    for f in findings.values():
        findings_data.append({
            "finding_id": f.finding_id,
            "claim": f.claim,
            "status": f.status.value,
            "mitre_technique": f.mitre_technique,
            "evidence_count": len(f.evidence),
            "contradictions_count": len(f.contradictions),
            "corrections_count": len(f.correction_history),
        })

    report = {
        "case_summary": {
            "total_findings": len(findings),
            "total_tool_calls": len(ledger.query(event_type="tool_call")),
            "total_corrections": len(ledger.query(event_type="correction")),
            "chain_valid": ledger.verify_chain(),
        },
        "findings": findings_data,
    }

    if output_format == "markdown":
        lines = ["# FinDevil Forensic Report", ""]
        summary = report["case_summary"]
        lines.append(f"**Findings:** {summary['total_findings']}  ")
        lines.append(f"**Tool Calls:** {summary['total_tool_calls']}  ")
        lines.append(f"**Corrections:** {summary['total_corrections']}  ")
        lines.append(f"**Audit Chain Valid:** {summary['chain_valid']}")
        lines.append("")
        lines.append("## Findings")
        lines.append("")
        for fd in findings_data:
            lines.append(f"### {fd['finding_id']}: {fd['claim']}")
            lines.append(f"- **Status:** {fd['status']}")
            lines.append(f"- **MITRE:** {fd['mitre_technique']}")
            lines.append(f"- **Evidence:** {fd['evidence_count']}")
            lines.append(f"- **Contradictions:** {fd['contradictions_count']}")
            lines.append(f"- **Corrections:** {fd['corrections_count']}")
            lines.append("")
        return _truncate("\n".join(lines))

    return _json(report)


@mcp.tool()
def get_audit_log(
    event_type: str = "",
    finding_id: str = "",
) -> str:
    """Query the audit ledger, optionally filtering by event_type and/or finding_id."""
    if not _state:
        return _json({"error": "No case initialized. Call investigate_case first."})

    ledger: AuditLedger = _state["ledger"]
    events = ledger.query(
        event_type=event_type if event_type else None,
        finding_id=finding_id if finding_id else None,
    )
    return _json({"count": len(events), "events": events})
