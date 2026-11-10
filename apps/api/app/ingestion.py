"""Normalization and deterministic identity helpers for source events."""

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from pydantic import ValidationError

from .schemas.events import SourceEvent


def utc_datetime(value: datetime) -> datetime:
    """Return an aware UTC datetime for storage and ordering."""

    return value.astimezone(UTC)


def utc_text(value: datetime) -> str:
    """Format a timestamp using the contract's canonical ``Z`` spelling."""

    return utc_datetime(value).isoformat().replace("+00:00", "Z")


def fingerprint_input(event: SourceEvent) -> dict[str, Any]:
    """Build the exact versioned fingerprint input from normalized fields."""

    return {
        "source_type": event.source_type,
        "event_type": event.event_type,
        "event_time": utc_text(event.event_time),
        "username": event.username,
        "host_id": event.host_id,
        "source_ip": str(event.source_ip) if event.source_ip is not None else None,
        "destination_ip": (str(event.destination_ip) if event.destination_ip is not None else None),
        "session_id": event.session_id,
        "process_name": event.process_name,
        "outcome": event.outcome or "unknown",
    }


def event_fingerprint(event: SourceEvent) -> str:
    canonical = json.dumps(
        fingerprint_input(event),
        sort_keys=True,
        separators=(",", ":"),
    )
    return f"sha256-v1:{hashlib.sha256(canonical.encode('utf-8')).hexdigest()}"


@dataclass(frozen=True)
class NormalizedEvent:
    event_id: str
    tenant_id: str
    source_event_id: str | None
    event_fingerprint: str
    source_type: str
    event_type: str
    event_time: datetime
    ingested_at: datetime
    username: str | None
    host_id: str | None
    source_ip: str | None
    destination_ip: str | None
    session_id: str | None
    process_name: str | None
    outcome: str
    severity: str | None
    raw_event: str
    normalized_fields: str


@dataclass(frozen=True)
class ParseFailure:
    message: str


def normalize_event(
    raw_event: dict[str, Any],
    *,
    tenant_id: str,
    ingested_at: datetime,
) -> NormalizedEvent:
    """Validate a source record and produce a persistence-ready event."""

    parsed = SourceEvent.model_validate(raw_event)
    fingerprint_fields = fingerprint_input(parsed)
    normalized = {
        **fingerprint_fields,
        "severity": parsed.severity,
    }
    return NormalizedEvent(
        event_id=str(uuid4()),
        tenant_id=tenant_id,
        source_event_id=parsed.source_event_id,
        event_fingerprint=event_fingerprint(parsed),
        source_type=parsed.source_type,
        event_type=parsed.event_type,
        event_time=utc_datetime(parsed.event_time),
        ingested_at=utc_datetime(ingested_at),
        username=parsed.username,
        host_id=parsed.host_id,
        source_ip=str(parsed.source_ip) if parsed.source_ip is not None else None,
        destination_ip=(str(parsed.destination_ip) if parsed.destination_ip is not None else None),
        session_id=parsed.session_id,
        process_name=parsed.process_name,
        outcome=parsed.outcome or "unknown",
        severity=parsed.severity,
        raw_event=json.dumps(raw_event, ensure_ascii=False, separators=(",", ":")),
        normalized_fields=json.dumps(
            normalized,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ),
    )


def validation_details(error: ValidationError) -> list[dict[str, Any]]:
    """Return safe, stable validation details without echoing source values."""

    return [
        {
            "location": list(item.get("loc", ())),
            "message": item.get("msg", "invalid value"),
            "type": item.get("type", "value_error"),
        }
        for item in error.errors()
    ]
