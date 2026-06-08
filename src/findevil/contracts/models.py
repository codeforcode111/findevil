from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field, model_validator


class EvidenceStatus(StrEnum):
    CONFIRMED = "confirmed"
    PROBABLE = "probable"
    INFERRED = "inferred"
    REFUTED = "refuted"
    UNKNOWN = "unknown"


class ToolRun(BaseModel):
    run_id: str
    tool: str
    command: str
    args: dict[str, Any] = Field(default_factory=dict)
    exit_code: int
    stdout_hash: str
    duration_ms: int
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class Evidence(BaseModel):
    artifact_id: str
    tool_run_id: str
    source_file: str
    content_hash: str
    excerpt: str


class CorrectionRecord(BaseModel):
    correction_type: str
    reason: str
    before_status: EvidenceStatus
    after_status: EvidenceStatus
    finding_id: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class Finding(BaseModel):
    finding_id: str
    claim: str
    status: EvidenceStatus
    mitre_technique: str
    evidence: list[Evidence]
    contradictions: list[Evidence] = Field(default_factory=list)
    confidence_basis: str
    correction_history: list[CorrectionRecord] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def tool_run_ids(self) -> list[str]:
        return [e.tool_run_id for e in self.evidence]

    @model_validator(mode="after")
    def validate_evidence_not_empty(self) -> Finding:
        if not self.evidence:
            raise ValueError("Finding must have at least one piece of evidence")
        return self


class AuditEvent(BaseModel):
    event_id: str
    event_type: str
    data: dict[str, Any] = Field(default_factory=dict)
    prev_hash: str | None = None
    hash: str | None = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
