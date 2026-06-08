from __future__ import annotations

from dataclasses import dataclass

from findevil.audit.ledger import AuditLedger
from findevil.contracts.models import EvidenceStatus, Finding


@dataclass
class ContractViolation(Exception):
    finding_id: str
    rule: str
    message: str

    def __str__(self) -> str:
        return self.message


class ContractCompiler:
    def __init__(self, ledger: AuditLedger) -> None:
        self.ledger = ledger

    def _get_valid_run_ids(self) -> set[str]:
        events = self.ledger.query(event_type="tool_call")
        return {e["data"]["run_id"] for e in events if "run_id" in e["data"]}

    def validate(self, finding: Finding) -> None:
        violations = self._check(finding)
        if violations:
            raise violations[0]

    def _check(self, finding: Finding) -> list[ContractViolation]:
        violations: list[ContractViolation] = []
        valid_run_ids = self._get_valid_run_ids()

        for ev in finding.evidence:
            if ev.tool_run_id not in valid_run_ids:
                violations.append(ContractViolation(
                    finding_id=finding.finding_id,
                    rule="evidence_traceability",
                    message=f"Evidence run_id '{ev.tool_run_id}' not found in audit ledger",
                ))

        if finding.status == EvidenceStatus.CONFIRMED:
            source_files = {e.source_file for e in finding.evidence}
            if len(source_files) < 2:
                violations.append(ContractViolation(
                    finding_id=finding.finding_id,
                    rule="confirmed_requires_multiple_sources",
                    message=(
                        f"CONFIRMED status requires >=2 independent evidence sources, "
                        f"got {len(source_files)}"
                    ),
                ))

        if finding.status == EvidenceStatus.CONFIRMED and finding.contradictions:
            violations.append(ContractViolation(
                finding_id=finding.finding_id,
                rule="contradictions_block_confirmed",
                message="Finding has contradictions and cannot be CONFIRMED",
            ))

        if finding.status == EvidenceStatus.INFERRED and not finding.confidence_basis.strip():
            violations.append(ContractViolation(
                finding_id=finding.finding_id,
                rule="inferred_requires_basis",
                message="INFERRED findings must have a non-empty confidence_basis",
            ))

        return violations

    def compile(self, findings: list[Finding]) -> list[ContractViolation]:
        all_violations: list[ContractViolation] = []
        for finding in findings:
            all_violations.extend(self._check(finding))
        return all_violations
