"""Audit response contracts."""

from typing import Any

from pydantic import BaseModel, ConfigDict


class AuditRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    audit_id: str
    tenant_id: str
    incident_id: str | None
    action_id: str | None
    actor_id: str
    event_type: str
    previous_state: str | None
    new_state: str | None
    reason: str | None
    metadata: dict[str, Any]
    created_at: str
