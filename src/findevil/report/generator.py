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
