from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress, field_validator


class SourceEvent(BaseModel):
    """The supported source shape before application-owned fields are added."""

    model_config = ConfigDict(extra="allow")

    source_event_id: str | None = Field(default=None, max_length=255)
    source_type: Literal["authentication", "system", "endpoint", "network"]
    event_type: str = Field(min_length=1, max_length=100)
    event_time: datetime
    username: str | None = Field(default=None, max_length=255)
    host_id: str | None = Field(default=None, max_length=255)
    source_ip: IPvAnyAddress | None = None
    destination_ip: IPvAnyAddress | None = None
    session_id: str | None = Field(default=None, max_length=255)
    process_name: str | None = Field(default=None, max_length=255)
    outcome: Literal["success", "failure", "blocked", "unknown"] | None = None
    severity: str | None = Field(default=None, max_length=50)

    @field_validator("event_time")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("event_time must include a timezone offset")
        return value

    @field_validator(
        "source_event_id",
        "username",
        "host_id",
        "session_id",
        "process_name",
        "severity",
        "event_type",
    )
    @classmethod
    def normalize_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        if not normalized:
            raise ValueError("text values cannot be blank")
        return normalized


class EventBatchRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    events: list[dict[str, Any]] = Field(min_length=1, max_length=1000)
    source: str = Field(default="json-batch", min_length=1, max_length=100)


class IngestionErrorResponse(BaseModel):
    record_number: int
    source_event_id: str | None
    code: str
    message: str
    details: dict[str, Any]


class IngestionRunResponse(BaseModel):
    run_id: str
    tenant_id: str
    idempotency_key: str
    source: str
    status: str
    received: int
    accepted: int
    rejected: int
    duplicates: int
    failed: int
    errors: list[IngestionErrorResponse]
    candidate_incident_ids: list[str] = Field(default_factory=list)
