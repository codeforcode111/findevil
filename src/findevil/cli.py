from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import click

from findevil.audit.ledger import AuditLedger


@click.group()
def cli():
    """FinDevil: Evidence-Contract Autonomous IR Agent"""
    pass


@cli.group()
def audit():
    """Audit ledger operations."""
    pass


@audit.command("verify")
@click.option("--ledger", required=True, type=click.Path(exists=True), help="Path to audit.jsonl")
def audit_verify(ledger: str):
    """Verify audit ledger hash chain integrity."""
    al = AuditLedger(Path(ledger))
    if al.verify_chain():
        events = al.read_all()
        click.echo(f"Hash chain: VALID ({len(events)} events)")
    else:
        click.echo("Hash chain: INVALID — possible tampering detected")


@cli.command()
@click.argument("finding_id")
@click.option("--ledger", required=True, type=click.Path(exists=True))
def trace(finding_id: str, ledger: str):
    """Show the complete evidence chain for a finding."""
    al = AuditLedger(Path(ledger))
    events = al.query(finding_id=finding_id)
    if not events:
        click.echo(f"No events found for {finding_id}")
        return
    click.echo(f"Evidence chain for {finding_id}:")
    click.echo(f"  Events: {len(events)}")
    for evt in events:
        click.echo(f"  [{evt['event_type']}] {evt['timestamp']} — {json.dumps(evt['data'], default=str)}")


@cli.command()
@click.argument("finding_id")
@click.option("--ledger", required=True, type=click.Path(exists=True))
def replay(finding_id: str, ledger: str):
    """Replay the tool execution sequence for a finding."""
    al = AuditLedger(Path(ledger))
    events = al.query(finding_id=finding_id)
    run_ids = set()
    for evt in events:
        if "run_id" in evt.get("data", {}):
            run_ids.add(evt["data"]["run_id"])

    tool_calls = al.query(event_type="tool_call")
    relevant = [tc for tc in tool_calls if tc["data"].get("run_id") in run_ids]

    click.echo(f"Tool execution replay for {finding_id}:")
    for tc in relevant:
        d = tc["data"]
        click.echo(f"  [{d.get('run_id')}] {d.get('tool')} — exit:{d.get('exit_code')} — {d.get('duration_ms', '?')}ms")
        if d.get("command"):
            click.echo(f"    cmd: {d['command']}")


@cli.command()
def doctor():
    """Check SIFT container health and tool availability."""
    click.echo("FinDevil Doctor")
    click.echo("=" * 40)

    docker = shutil.which("docker")
    if not docker:
        click.echo("[WARN] Docker not found in PATH")
    else:
        click.echo("[OK] Docker found")

    try:
        result = subprocess.run(
            ["docker", "ps", "--filter", "name=findevil-sift", "--format", "{{.Status}}"],
            capture_output=True, text=True, timeout=5,
        )
        if result.stdout.strip():
            click.echo(f"[OK] SIFT container: {result.stdout.strip()}")
        else:
            click.echo("[WARN] SIFT container not running. Start with: docker-compose up -d")
    except (subprocess.TimeoutExpired, FileNotFoundError):
        click.echo("[WARN] Cannot check Docker status")

    click.echo("=" * 40)


@cli.command()
@click.argument("case_dir", type=click.Path(exists=True))
@click.option("--ledger", required=True, type=click.Path(exists=True))
def bench(case_dir: str, ledger: str):
    """Run accuracy benchmark against a known case with ground truth."""
    ground_truth_path = Path(case_dir) / "ground_truth.json"
    if not ground_truth_path.exists():
        click.echo(f"No ground_truth.json found in {case_dir}")
        return

    gt = json.loads(ground_truth_path.read_text())
    al = AuditLedger(Path(ledger))
    finding_events = al.query(event_type="finding_event")

    click.echo(f"Benchmark: {case_dir}")
    click.echo(f"  Ground truth findings: {len(gt.get('expected_findings', []))}")
    click.echo(f"  Agent findings: {len(finding_events)}")
    click.echo("  (Detailed P/R/F1 scoring requires matching logic — run full evaluation)")
