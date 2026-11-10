"""Validated contracts for simulated response actions."""

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class ResponsePlanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action_type: Literal["revoke_session"]
    target: str | dict[str, Any] | None = None
    target_session_id: str | None = Field(default=None, max_length=255)
    action_version: int | None = Field(default=None, ge=1)
    evidence_event_ids: list[str] = Field(min_length=1, max_length=50)
    rationale: str = Field(min_length=1, max_length=2000)
    risk: str = Field(min_length=1, max_length=1000)
    expected_outcome: str = Field(min_length=1, max_length=1000)
    operational_impact: str = Field(min_length=1, max_length=1000)
    preconditions: list[str] = Field(default_factory=list, max_length=20)
    rollback_plan: str = Field(min_length=1, max_length=1000)
    verification_method: str = Field(min_length=1, max_length=1000)
    expected_postcondition: dict[str, Any] = Field(
        default_factory=lambda: {"active": False},
    )
    actor_id: str = Field(default="analyst-demo", min_length=1, max_length=100)

    @model_validator(mode="after")
    def require_target(self) -> "ResponsePlanRequest":
        if self.target is None and self.target_session_id is None:
            raise ValueError("target or target_session_id is required")
        return self

    def session_id(self) -> str:
        target = self.target if self.target is not None else self.target_session_id
        if isinstance(target, dict):
            value = target.get("session_id") or target.get("target")
        else:
            value = target
        if not isinstance(value, str) or not value.strip():
            raise ValueError("revoke_session target must be a session identifier")
        return value.strip()


class ActionDecisionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action_version: int | None = Field(default=None, ge=1)
    actor_id: str = Field(default="analyst-demo", min_length=1, max_length=100)
    reason: str | None = Field(default=None, max_length=1000)


class ActionExecutionRequest(ActionDecisionRequest):
    pass


class ResponseActionResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action_id: str
    incident_id: str
    tenant_id: str
    action_type: Literal["revoke_session"]
    action_version: int
    target: str
    status: str
    evidence_event_ids: list[str]
    expected_postcondition: dict[str, Any]
    before_state: dict[str, Any] | None = None
    after_state: dict[str, Any] | None = None
    approval: dict[str, Any] | None = None
    execution: dict[str, Any] | None = None
    verification: dict[str, Any] | None = None
    created_at: str
    updated_at: str


class VerificationResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action_id: str
    incident_id: str
    status: Literal["verified", "verification_failed", "inconclusive"]
    expected_postcondition: dict[str, Any]
    observed_state: dict[str, Any] | None
    evidence: list[str]
    checked_at: str
