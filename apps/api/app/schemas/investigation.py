"""Validated contracts for constrained, evidence-first investigations."""

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class InvestigationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    provider: Literal["mock", "failing"] = "mock"


class EvidenceClaim(BaseModel):
    model_config = ConfigDict(extra="forbid")

    claim: str = Field(min_length=1, max_length=1000)
    evidence_event_ids: list[str] = Field(default_factory=list, max_length=50)
    status: Literal["observed", "inferred", "unconfirmed", "disproven"] = "observed"


class Hypothesis(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=255)
    assessment: Literal[
        "supported",
        "partially_supported",
        "unsupported",
        "inconclusive",
    ]
    explanation: str = Field(min_length=1, max_length=1000)
    evidence_event_ids: list[str] = Field(default_factory=list, max_length=50)


class AffectedEntity(BaseModel):
    model_config = ConfigDict(extra="forbid")

    entity_id: str = Field(min_length=1, max_length=255)
    entity_type: str = Field(min_length=1, max_length=50)
    display_value: str = Field(min_length=1, max_length=255)
    evidence_event_ids: list[str] = Field(default_factory=list, max_length=50)


class RecommendedAction(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action_type: Literal["revoke_session"]
    target: str = Field(min_length=1, max_length=255)
    rationale: str = Field(min_length=1, max_length=1000)
    evidence_event_ids: list[str] = Field(default_factory=list, max_length=50)


class InvestigationResult(BaseModel):
    """The only provider output allowed to leave the investigation boundary."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1.0"] = "1.0"
    executive_summary: str = Field(min_length=1, max_length=2000)
    incident_assessment: str = Field(min_length=1, max_length=2000)
    competing_hypotheses: list[Hypothesis] = Field(max_length=10)
    observed_facts: list[EvidenceClaim] = Field(max_length=50)
    inferences: list[EvidenceClaim] = Field(max_length=50)
    contradicting_evidence: list[EvidenceClaim] = Field(max_length=50)
    missing_evidence: list[str] = Field(max_length=20)
    affected_entities: list[AffectedEntity] = Field(max_length=50)
    severity_explanation: str = Field(min_length=1, max_length=1000)
    confidence_explanation: str = Field(min_length=1, max_length=1000)
    recommended_actions: list[RecommendedAction] = Field(max_length=10)
    referenced_event_ids: list[str] = Field(max_length=100)
    limitations: list[str] = Field(max_length=20)


class InvestigationResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    run_id: str
    incident_id: str
    tenant_id: str
    provider: str
    status: Literal["running", "completed", "failed"]
    tool_call_count: int
    result: InvestigationResult | None = None
    error: dict[str, Any] | None = None
    created_at: str
    completed_at: str | None = None
