"""Small, allowlisted, read-only tools for the investigation provider."""

import json
import re
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import sqlalchemy as sa
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from sqlalchemy.engine import Connection, Engine

from .schema import entities, incident_events, incidents, security_events

MAX_TOOL_RESULTS = 100
PROMPT_INJECTION_PATTERN = re.compile(
    r"(?:ignore|disregard|override)\s+(?:all\s+)?(?:previous|prior|system|developer)\s+"
    r"(?:instructions?|rules?)|reveal\s+(?:the\s+)?(?:system|developer)\s+prompt|"
    r"(?:add|register|enable)\s+(?:a\s+)?(?:tool|permission)",
    re.IGNORECASE,
)


class ToolFailure(Exception):
    def __init__(self, code: str, message: str, details: dict[str, Any] | None = None):
        self.code = code
        self.message = message
        self.details = details or {}
        super().__init__(message)


class TimeRange(BaseModel):
    model_config = ConfigDict(extra="forbid")

    start: datetime | None = None
    end: datetime | None = None

    @classmethod
    def validate_range(cls, value: "TimeRange") -> "TimeRange":
        if value.start and value.start.tzinfo is None:
            raise ValueError("time range start must include a timezone")
        if value.end and value.end.tzinfo is None:
            raise ValueError("time range end must include a timezone")
        if value.start and value.end and value.start > value.end:
            raise ValueError("time range start must not be after end")
        return value


class IncidentEventsArguments(BaseModel):
    model_config = ConfigDict(extra="forbid")

    incident_id: str = Field(min_length=1, max_length=100)
    time_range: TimeRange | None = None
    filters: dict[str, str] = Field(default_factory=dict, max_length=10)
    limit: int = Field(default=MAX_TOOL_RESULTS, ge=1, le=MAX_TOOL_RESULTS)


class EventDetailsArguments(BaseModel):
    model_config = ConfigDict(extra="forbid")

    incident_id: str = Field(min_length=1, max_length=100)
    event_id: str = Field(min_length=1, max_length=36)


class RelatedEventsArguments(BaseModel):
    model_config = ConfigDict(extra="forbid")

    incident_id: str = Field(min_length=1, max_length=100)
    entity_id: str = Field(min_length=1, max_length=36)
    time_window_minutes: int = Field(default=60, ge=1, le=1440)
    limit: int = Field(default=MAX_TOOL_RESULTS, ge=1, le=MAX_TOOL_RESULTS)


class InvestigationToolRegistry:
    """Registry with no dynamic registration and no arbitrary query surface."""

    names = frozenset(
        {
            "get_incident_events",
            "get_event_details",
            "get_related_events",
        }
    )

    def __init__(
        self,
        engine: Engine,
        *,
        tenant_id: str,
        incident_id: str,
        step_hook: Callable[[str, dict[str, Any], dict[str, Any], str], None] | None = None,
    ) -> None:
        self.engine = engine
        self.tenant_id = tenant_id
        self.incident_id = incident_id
        self.step_hook = step_hook

    def call(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if name not in self.names:
            raise ToolFailure("tool_not_allowed", "tool is not registered", {"tool": name})
        try:
            if name == "get_incident_events":
                parsed = IncidentEventsArguments.model_validate(arguments)
                result = self.get_incident_events(parsed)
            elif name == "get_event_details":
                parsed = EventDetailsArguments.model_validate(arguments)
                result = self.get_event_details(parsed)
            else:
                parsed = RelatedEventsArguments.model_validate(arguments)
                result = self.get_related_events(parsed)
        except ValidationError as error:
            raise ToolFailure(
                "invalid_tool_arguments",
                "tool arguments failed validation",
                {"validation": [item["loc"] for item in error.errors()]},
            ) from error
        except ToolFailure:
            raise
        except (TypeError, ValueError) as error:
            raise ToolFailure("invalid_tool_arguments", str(error)) from error

        if self.step_hook is not None:
            self.step_hook(name, arguments, self._redacted_result(result), "completed")
        return result

    def get_incident_events(self, arguments: IncidentEventsArguments) -> dict[str, Any]:
        self._require_incident(arguments.incident_id)
        allowed_filters = {
            "event_type",
            "source_type",
            "username",
            "host_id",
            "session_id",
            "source_ip",
            "outcome",
        }
        unknown_filters = set(arguments.filters) - allowed_filters
        if unknown_filters:
            raise ToolFailure(
                "invalid_tool_arguments",
                "filters contain unsupported fields",
                {"fields": sorted(unknown_filters)},
            )

        with self.engine.connect() as connection:
            conditions = [
                incident_events.c.incident_id == self.incident_id,
                incident_events.c.event_id == security_events.c.event_id,
                security_events.c.tenant_id == self.tenant_id,
            ]
            for key, value in arguments.filters.items():
                conditions.append(getattr(security_events.c, key) == value)
            if arguments.time_range is not None:
                if arguments.time_range.start:
                    conditions.append(
                        security_events.c.event_time >= _aware(arguments.time_range.start)
                    )
                if arguments.time_range.end:
                    conditions.append(
                        security_events.c.event_time <= _aware(arguments.time_range.end)
                    )
            rows = connection.execute(
                sa.select(security_events)
                .select_from(
                    incident_events.join(
                        security_events,
                        incident_events.c.event_id == security_events.c.event_id,
                    )
                )
                .where(sa.and_(*conditions))
                .order_by(
                    security_events.c.event_time,
                    security_events.c.ingested_at,
                    security_events.c.event_id,
                )
                .limit(arguments.limit)
            ).mappings()
            items = [self._event_data(dict(row)) for row in rows]
        result = {"incident_id": self.incident_id, "items": items, "count": len(items)}
        return result

    def get_event_details(self, arguments: EventDetailsArguments) -> dict[str, Any]:
        self._require_incident(arguments.incident_id)
        with self.engine.connect() as connection:
            row = (
                connection.execute(
                    sa.select(security_events)
                    .join(incident_events, incident_events.c.event_id == security_events.c.event_id)
                    .where(
                        incident_events.c.incident_id == self.incident_id,
                        incident_events.c.event_id == arguments.event_id,
                        security_events.c.tenant_id == self.tenant_id,
                    )
                )
                .mappings()
                .first()
            )
            if row is None:
                raise ToolFailure(
                    "event_not_in_incident",
                    "event is not part of the requested incident",
                    {"event_id": arguments.event_id},
                )
            return self._event_data(dict(row), include_raw=True)

    def get_related_events(self, arguments: RelatedEventsArguments) -> dict[str, Any]:
        self._require_incident(arguments.incident_id)
        with self.engine.connect() as connection:
            entity = (
                connection.execute(
                    sa.select(entities).where(
                        entities.c.entity_id == arguments.entity_id,
                        entities.c.tenant_id == self.tenant_id,
                    )
                )
                .mappings()
                .first()
            )
            if entity is None or not self._entity_is_in_incident(connection, entity):
                raise ToolFailure(
                    "entity_not_in_incident",
                    "entity is not part of the requested incident",
                    {"entity_id": arguments.entity_id},
                )
            event_rows = self._incident_event_rows(connection)
            values = [
                self._event_data(event)
                for event in event_rows
                if _event_has_entity(event, entity["entity_type"], entity["display_value"])
            ]
            if values:
                timestamps = [
                    datetime.fromisoformat(item["event_time"].replace("Z", "+00:00"))
                    for item in values
                ]
                latest = max(timestamps)
                earliest = latest - timedelta(minutes=arguments.time_window_minutes)
                values = [
                    item
                    for item in values
                    if earliest
                    <= datetime.fromisoformat(item["event_time"].replace("Z", "+00:00"))
                    <= latest
                ]
            values = values[: arguments.limit]
        return {
            "incident_id": self.incident_id,
            "entity_id": arguments.entity_id,
            "items": values,
            "count": len(values),
        }

    def _require_incident(self, incident_id: str) -> None:
        if incident_id != self.incident_id:
            raise ToolFailure(
                "incident_boundary_violation",
                "tool call does not match the investigation incident",
                {"incident_id": incident_id},
            )
        with self.engine.connect() as connection:
            exists = connection.execute(
                sa.select(incidents.c.incident_id).where(
                    incidents.c.incident_id == incident_id,
                    incidents.c.tenant_id == self.tenant_id,
                )
            ).scalar_one_or_none()
        if exists is None:
            raise ToolFailure("incident_not_found", "incident was not found")

    def _incident_event_rows(self, connection: Connection) -> list[dict[str, Any]]:
        rows = connection.execute(
            sa.select(security_events)
            .join(incident_events, incident_events.c.event_id == security_events.c.event_id)
            .where(
                incident_events.c.incident_id == self.incident_id,
                security_events.c.tenant_id == self.tenant_id,
            )
            .order_by(
                security_events.c.event_time,
                security_events.c.ingested_at,
                security_events.c.event_id,
            )
            .limit(MAX_TOOL_RESULTS)
        ).mappings()
        return [dict(row) for row in rows]

    def _entity_is_in_incident(self, connection: Connection, entity: dict[str, Any]) -> bool:
        return any(
            _event_has_entity(event, entity["entity_type"], entity["display_value"])
            for event in self._incident_event_rows(connection)
        )

    @staticmethod
    def _event_data(event: dict[str, Any], *, include_raw: bool = False) -> dict[str, Any]:
        normalized = json.loads(event["normalized_fields"])
        data = {
            "event_id": event["event_id"],
            "source_event_id": event["source_event_id"],
            "event_type": event["event_type"],
            "source_type": event["source_type"],
            "event_time": _aware(event["event_time"]).isoformat().replace("+00:00", "Z"),
            "username": event["username"],
            "host_id": event["host_id"],
            "source_ip": event["source_ip"],
            "session_id": event["session_id"],
            "outcome": event["outcome"],
            "normalized_fields": normalized,
            "prompt_injection_detected": _contains_prompt_injection(event),
        }
        if include_raw:
            data["raw_event"] = json.loads(event["raw_event"])
        return data

    @staticmethod
    def _redacted_result(result: dict[str, Any]) -> dict[str, Any]:
        if "items" in result:
            return {
                "count": result.get("count", len(result["items"])),
                "event_ids": [item.get("event_id") for item in result["items"]],
                "prompt_injection_fields": sum(
                    bool(item.get("prompt_injection_detected")) for item in result["items"]
                ),
            }
        return {
            "event_id": result.get("event_id"),
            "prompt_injection_detected": result.get("prompt_injection_detected", False),
        }


def _aware(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _contains_prompt_injection(event: dict[str, Any]) -> bool:
    raw = json.dumps(event.get("raw_event", ""), ensure_ascii=False)
    return bool(PROMPT_INJECTION_PATTERN.search(raw))


def _event_has_entity(event: dict[str, Any], entity_type: str, value: str) -> bool:
    field_by_type = {
        "user": "username",
        "host": "host_id",
        "ip": "source_ip",
        "session": "session_id",
        "process": "process_name",
    }
    field = field_by_type.get(entity_type)
    return field is not None and event.get(field) == value
