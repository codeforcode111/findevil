from __future__ import annotations

from findevil.audit.ledger import AuditLedger
from findevil.contracts.compiler import ContractCompiler
from findevil.contracts.models import (
    CorrectionRecord,
    Evidence,
    EvidenceStatus,
    Finding,
)

DOWNGRADE_MAP: dict[EvidenceStatus, EvidenceStatus] = {
    EvidenceStatus.CONFIRMED: EvidenceStatus.PROBABLE,
    EvidenceStatus.PROBABLE: EvidenceStatus.INFERRED,
    EvidenceStatus.INFERRED: EvidenceStatus.UNKNOWN,
}


class CorrectionEngine:
    def __init__(self, ledger: AuditLedger, compiler: ContractCompiler) -> None:
        self.ledger = ledger
        self.compiler = compiler

    def add_contradiction(
        self,
        finding: Finding,
        contradiction: Evidence,
        reason: str,
    ) -> Finding:
        old_status = finding.status
        new_status = DOWNGRADE_MAP.get(old_status, EvidenceStatus.UNKNOWN)

        correction = CorrectionRecord(
            correction_type="contradiction",
            reason=reason,
            before_status=old_status,
            after_status=new_status,
            finding_id=finding.finding_id,
        )

        updated = finding.model_copy(update={
            "status": new_status,
            "contradictions": [*finding.contradictions, contradiction],
            "correction_history": [*finding.correction_history, correction],
            "confidence_basis": f"{finding.confidence_basis} [DOWNGRADED: {reason}]",
        })

        self.ledger.append("correction", {
            "finding_id": finding.finding_id,
            "correction_type": "contradiction",
            "reason": reason,
            "before_status": old_status.value,
            "after_status": new_status.value,
        })

        return updated

    def fix_contract_violation(self, finding: Finding) -> Finding:
        violations = self.compiler._check(finding)
        if not violations:
            return finding

        old_status = finding.status
        new_status = DOWNGRADE_MAP.get(old_status, EvidenceStatus.UNKNOWN)
        reason = "; ".join(v.message for v in violations)

        correction = CorrectionRecord(
            correction_type="contract_violation",
            reason=reason,
            before_status=old_status,
            after_status=new_status,
            finding_id=finding.finding_id,
        )

        updated = finding.model_copy(update={
            "status": new_status,
            "correction_history": [*finding.correction_history, correction],
            "confidence_basis": f"{finding.confidence_basis} [CONTRACT FIX: {reason}]",
        })

        self.ledger.append("correction", {
            "finding_id": finding.finding_id,
            "correction_type": "contract_violation",
            "reason": reason,
            "before_status": old_status.value,
            "after_status": new_status.value,
        })

        return updated

    def record_tool_failure(
        self,
        tool: str,
        args: list[str],
        error: str,
        suggested_alternative: str | None = None,
    ) -> None:
        self.ledger.append("correction", {
            "correction_type": "tool_failure",
            "tool": tool,
            "args": args,
            "error": error,
            "suggested_alternative": suggested_alternative,
        })
