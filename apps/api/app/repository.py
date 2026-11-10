"""Persistence and orchestration for the deterministic evidence slice."""

import json
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import sqlalchemy as sa
from pydantic import ValidationError
from sqlalchemy.engine import Connection, Engine

from .detection import Detection, detect, group_detections
from .ingestion import NormalizedEvent, ParseFailure, normalize_event, validation_details
from .schema import (
    entities,
    entity_relationships,
    finding_events,
    findings,
    incident_events,
    incidents,
    ingestion_errors,
    ingestion_runs,
    security_events,
)

TENANT_ID = "demo"
MAX_PAGE_SIZE = 100


def now_utc() -> datetime:
    return datetime.now(UTC)


def _aware(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


class EvidenceRepository:
    def __init__(self, engine: Engine, *, tenant_id: str = TENANT_ID) -> None:
        self.engine = engine
        self.tenant_id = tenant_id

    def ingest(
        self,
        records: list[Any],
        *,
        idempotency_key: str,
        source: str,
    ) -> dict[str, Any]:
        """Ingest a batch and synchronously materialize deterministic findings."""

        created_at = now_utc()
        with self.engine.begin() as connection:
            previous = (
                connection.execute(
                    sa.select(ingestion_runs).where(
                        ingestion_runs.c.tenant_id == self.tenant_id,
                        ingestion_runs.c.idempotency_key == idempotency_key,
                    )
                )
                .mappings()
                .first()
            )
            if previous is not None:
                return self._run_response(connection, previous)

            run_id = str(uuid4())
            connection.execute(
                sa.insert(ingestion_runs).values(
                    run_id=run_id,
                    tenant_id=self.tenant_id,
                    idempotency_key=idempotency_key,
                    source=source,
                    status="running",
                    received=len(records),
                    created_at=created_at,
                )
            )

            accepted = rejected = duplicates = failed = 0
            for record_number, raw_record in enumerate(records, start=1):
                source_event_id = (
                    raw_record.get("source_event_id") if isinstance(raw_record, dict) else None
                )
                if isinstance(raw_record, ParseFailure):
                    rejected += 1
                    self._insert_error(
                        connection,
                        run_id=run_id,
                        record_number=record_number,
                        source_event_id=None,
                        code="invalid_json",
                        message=raw_record.message,
                        details={},
                    )
                    continue
                try:
                    if not isinstance(raw_record, dict):
                        raise ValueError("record must be a JSON object")
                    event = normalize_event(
                        raw_record,
                        tenant_id=self.tenant_id,
                        ingested_at=created_at,
                    )
                except ValidationError as error:
                    rejected += 1
                    self._insert_error(
                        connection,
                        run_id=run_id,
                        record_number=record_number,
                        source_event_id=source_event_id,
                        code="malformed_record",
                        message="record failed schema validation",
                        details={"validation": validation_details(error)},
                    )
                    continue
                except (TypeError, ValueError) as error:
                    rejected += 1
                    self._insert_error(
                        connection,
                        run_id=run_id,
                        record_number=record_number,
                        source_event_id=source_event_id,
                        code="malformed_record",
                        message=str(error)[:500],
                        details={},
                    )
                    continue

                existing = connection.execute(
                    sa.select(security_events.c.event_id).where(
                        security_events.c.tenant_id == self.tenant_id,
                        security_events.c.event_fingerprint == event.event_fingerprint,
                    )
                ).first()
                if existing is not None:
                    duplicates += 1
                    continue

                connection.execute(sa.insert(security_events).values(**vars(event)))
                self._ensure_event_entities(connection, event)
                accepted += 1

            event_rows = self._event_rows(connection)
            candidate_incident_ids = self._materialize_detections(connection, event_rows)
            completed_at = now_utc()
            connection.execute(
                sa.update(ingestion_runs)
                .where(ingestion_runs.c.run_id == run_id)
                .values(
                    status="completed",
                    accepted=accepted,
                    rejected=rejected,
                    duplicates=duplicates,
                    failed=failed,
                    completed_at=completed_at,
                    candidate_incident_ids=_json(candidate_incident_ids),
                )
            )
            run = (
                connection.execute(
                    sa.select(ingestion_runs).where(ingestion_runs.c.run_id == run_id)
                )
                .mappings()
                .one()
            )
            return self._run_response(connection, run)

    def _insert_error(
        self,
        connection: Connection,
        *,
        run_id: str,
        record_number: int,
        source_event_id: str | None,
        code: str,
        message: str,
        details: dict[str, Any],
    ) -> None:
        connection.execute(
            sa.insert(ingestion_errors).values(
                error_id=str(uuid4()),
                run_id=run_id,
                record_number=record_number,
                source_event_id=source_event_id,
                code=code,
                message=message,
                details=_json(details),
            )
        )

    def _event_rows(self, connection: Connection) -> list[dict[str, Any]]:
        rows = connection.execute(
            sa.select(security_events)
            .where(security_events.c.tenant_id == self.tenant_id)
            .order_by(
                security_events.c.event_time,
                security_events.c.ingested_at,
                security_events.c.event_id,
            )
        ).mappings()
        return [dict(row) for row in rows]

    def _materialize_detections(
        self,
        connection: Connection,
        event_rows: list[dict[str, Any]],
    ) -> list[str]:
        detections = detect(event_rows)
        event_by_id = {event["event_id"]: event for event in event_rows}
        incident_ids: list[str] = []
        for group in group_detections(detections, event_by_id):
            incident_id = self._materialize_group(connection, group, event_by_id)
            incident_ids.append(incident_id)
        return list(dict.fromkeys(incident_ids))

    def _materialize_group(
        self,
        connection: Connection,
        detections: list[Detection],
        event_by_id: dict[str, dict[str, Any]],
    ) -> str:
        correlation_key = sorted(
            detections,
            key=lambda item: item.correlation_key,
        )[0].correlation_key
        event_ids = sorted(
            {event_id for detection in detections for event_id in detection.event_ids},
            key=lambda event_id: (
                _aware(event_by_id[event_id]["event_time"]),
                _aware(event_by_id[event_id]["ingested_at"]),
                event_id,
            ),
        )
        event_values = [event_by_id[event_id] for event_id in event_ids]
        observed_start = min(_aware(event["event_time"]) for event in event_values)
        observed_end = max(_aware(event["event_time"]) for event in event_values)
        full_sequence = {detection.rule_id for detection in detections} >= {
            "AUTH-SUCCESS-AFTER-BURST-001",
            "PRIVILEGED-FOLLOW-ON-001",
        }
        severity = "high" if full_sequence else "medium"
        confidence = "high" if full_sequence else "low"
        title = (
            "Candidate account compromise sequence"
            if full_sequence
            else "Candidate suspicious activity"
        )
        existing = (
            connection.execute(
                sa.select(incidents).where(
                    incidents.c.tenant_id == self.tenant_id,
                    incidents.c.correlation_key == correlation_key,
                )
            )
            .mappings()
            .first()
        )
        if existing is None:
            prefix = "INC-PRIMARY" if full_sequence else "INC-SIGNAL"
            incident_id = self._next_incident_id(connection, prefix)
            connection.execute(
                sa.insert(incidents).values(
                    incident_id=incident_id,
                    tenant_id=self.tenant_id,
                    correlation_key=correlation_key,
                    title=title,
                    status="investigating",
                    severity=severity,
                    confidence=confidence,
                    observed_start=observed_start,
                    observed_end=observed_end,
                    created_at=now_utc(),
                    updated_at=now_utc(),
                )
            )
        else:
            incident_id = existing["incident_id"]
            if existing["severity"] == "high" or severity == "high":
                severity = "high"
            else:
                severity = existing["severity"]
            if existing["confidence"] == "high" or confidence == "high":
                confidence = "high"
            connection.execute(
                sa.update(incidents)
                .where(incidents.c.incident_id == incident_id)
                .values(
                    title=title if full_sequence else existing["title"],
                    severity=severity,
                    confidence=confidence,
                    observed_start=min(_aware(existing["observed_start"]), observed_start),
                    observed_end=max(_aware(existing["observed_end"]), observed_end),
                    updated_at=now_utc(),
                )
            )

        for event_id in event_ids:
            exists = connection.execute(
                sa.select(incident_events.c.event_id).where(
                    incident_events.c.incident_id == incident_id,
                    incident_events.c.event_id == event_id,
                )
            ).first()
            if exists is None:
                connection.execute(
                    sa.insert(incident_events).values(
                        incident_id=incident_id,
                        event_id=event_id,
                        relationship_type="supporting",
                    )
                )

        for detection in detections:
            finding = (
                connection.execute(
                    sa.select(findings).where(
                        findings.c.incident_id == incident_id,
                        findings.c.rule_id == detection.rule_id,
                        findings.c.rule_version == detection.rule_version,
                    )
                )
                .mappings()
                .first()
            )
            finding_id = finding["finding_id"] if finding else str(uuid4())
            finding_values = {
                "finding_id": finding_id,
                "incident_id": incident_id,
                "status": detection.finding_status,
                "title": detection.title,
                "description": detection.description,
                "rule_id": detection.rule_id,
                "rule_version": detection.rule_version,
                "severity_factors": _json(detection.severity_factors),
                "updated_at": now_utc(),
            }
            if finding is None:
                connection.execute(
                    sa.insert(findings).values(created_at=now_utc(), **finding_values)
                )
            else:
                connection.execute(
                    sa.update(findings)
                    .where(findings.c.finding_id == finding_id)
                    .values(
                        **{
                            key: value
                            for key, value in finding_values.items()
                            if key != "finding_id"
                        }
                    )
                )
            for event_id in detection.event_ids:
                exists = connection.execute(
                    sa.select(finding_events.c.event_id).where(
                        finding_events.c.finding_id == finding_id,
                        finding_events.c.event_id == event_id,
                    )
                ).first()
                if exists is None:
                    connection.execute(
                        sa.insert(finding_events).values(
                            finding_id=finding_id,
                            event_id=event_id,
                            evidence_role="supporting",
                        )
                    )

        self._materialize_relationships(connection, incident_id, event_values)
        return incident_id

    def _next_incident_id(self, connection: Connection, prefix: str) -> str:
        existing = connection.execute(
            sa.select(incidents.c.incident_id).where(
                incidents.c.tenant_id == self.tenant_id,
                incidents.c.incident_id.like(f"{prefix}-%"),
            )
        ).scalars()
        used = {value for value in existing}
        counter = 1
        while f"{prefix}-{counter:03d}" in used:
            counter += 1
        return f"{prefix}-{counter:03d}"

    def _ensure_event_entities(self, connection: Connection, event: NormalizedEvent) -> None:
        values = [
            ("user", event.username),
            ("host", event.host_id),
            ("ip", event.source_ip),
            ("ip", event.destination_ip),
            ("session", event.session_id),
            ("process", event.process_name),
        ]
        for entity_type, value in values:
            if value:
                self._ensure_entity(connection, entity_type, value)

    def _ensure_entity(
        self,
        connection: Connection,
        entity_type: str,
        value: str,
    ) -> str:
        canonical_key = f"{entity_type}:{value}"
        existing = connection.execute(
            sa.select(entities.c.entity_id).where(
                entities.c.tenant_id == self.tenant_id,
                entities.c.canonical_key == canonical_key,
            )
        ).scalar_one_or_none()
        if existing:
            return existing
        entity_id = str(uuid4())
        connection.execute(
            sa.insert(entities).values(
                entity_id=entity_id,
                tenant_id=self.tenant_id,
                entity_type=entity_type,
                canonical_key=canonical_key,
                display_value=value,
            )
        )
        return entity_id

    def _materialize_relationships(
        self,
        connection: Connection,
        incident_id: str,
        event_values: list[dict[str, Any]],
    ) -> None:
        pairs: dict[tuple[str, str], set[str]] = {}
        for event in event_values:
            event_entities: list[str] = []
            for entity_type, field in (
                ("user", "username"),
                ("host", "host_id"),
                ("ip", "source_ip"),
                ("ip", "destination_ip"),
                ("session", "session_id"),
                ("process", "process_name"),
            ):
                if event.get(field):
                    event_entities.append(
                        self._ensure_entity(connection, entity_type, event[field])
                    )
            for left_index, left in enumerate(sorted(set(event_entities))):
                for right in sorted(set(event_entities))[left_index + 1 :]:
                    pairs.setdefault((left, right), set()).add(event["event_id"])
        for (left, right), evidence_ids in pairs.items():
            existing = connection.execute(
                sa.select(entity_relationships.c.relationship_id).where(
                    entity_relationships.c.incident_id == incident_id,
                    entity_relationships.c.from_entity_id == left,
                    entity_relationships.c.to_entity_id == right,
                    entity_relationships.c.relationship_type == "co_occurrence",
                )
            ).scalar_one_or_none()
            values = {
                "incident_id": incident_id,
                "from_entity_id": left,
                "to_entity_id": right,
                "relationship_type": "co_occurrence",
                "evidence_event_ids": _json(sorted(evidence_ids)),
                "evidence_status": "observed",
            }
            if existing:
                connection.execute(
                    sa.update(entity_relationships)
                    .where(entity_relationships.c.relationship_id == existing)
                    .values(**{key: value for key, value in values.items() if key != "incident_id"})
                )
            else:
                connection.execute(
                    sa.insert(entity_relationships).values(
                        relationship_id=str(uuid4()),
                        **values,
                    )
                )

    def _run_response(self, connection: Connection, run: dict[str, Any]) -> dict[str, Any]:
        errors = connection.execute(
            sa.select(ingestion_errors)
            .where(ingestion_errors.c.run_id == run["run_id"])
            .order_by(ingestion_errors.c.record_number)
        ).mappings()
        return {
            "run_id": run["run_id"],
            "tenant_id": run["tenant_id"],
            "idempotency_key": run["idempotency_key"],
            "source": run["source"],
            "status": run["status"],
            "received": run["received"],
            "accepted": run["accepted"],
            "rejected": run["rejected"],
            "duplicates": run["duplicates"],
            "failed": run["failed"],
            "errors": [
                {
                    "record_number": error["record_number"],
                    "source_event_id": error["source_event_id"],
                    "code": error["code"],
                    "message": error["message"],
                    "details": json.loads(error["details"]),
                }
                for error in errors
            ],
            "candidate_incident_ids": json.loads(run.get("candidate_incident_ids") or "[]"),
        }

    def get_run(self, run_id: str) -> dict[str, Any] | None:
        with self.engine.connect() as connection:
            run = (
                connection.execute(
                    sa.select(ingestion_runs).where(
                        ingestion_runs.c.run_id == run_id,
                        ingestion_runs.c.tenant_id == self.tenant_id,
                    )
                )
                .mappings()
                .first()
            )
            return self._run_response(connection, run) if run else None

    def get_run_by_idempotency_key(self, idempotency_key: str) -> dict[str, Any] | None:
        with self.engine.connect() as connection:
            run = (
                connection.execute(
                    sa.select(ingestion_runs).where(
                        ingestion_runs.c.tenant_id == self.tenant_id,
                        ingestion_runs.c.idempotency_key == idempotency_key,
                    )
                )
                .mappings()
                .first()
            )
            return self._run_response(connection, run) if run else None

    def list_events(
        self,
        *,
        limit: int,
        offset: int,
        source_event_id: str | None = None,
        event_type: str | None = None,
    ) -> tuple[list[dict[str, Any]], int]:
        with self.engine.connect() as connection:
            conditions = [security_events.c.tenant_id == self.tenant_id]
            if source_event_id:
                conditions.append(security_events.c.source_event_id == source_event_id)
            if event_type:
                conditions.append(security_events.c.event_type == event_type)
            where = sa.and_(*conditions)
            total = connection.execute(
                sa.select(sa.func.count()).select_from(security_events).where(where)
            ).scalar_one()
            rows = connection.execute(
                sa.select(security_events)
                .where(where)
                .order_by(
                    security_events.c.event_time,
                    security_events.c.ingested_at,
                    security_events.c.event_id,
                )
                .limit(limit)
                .offset(offset)
            ).mappings()
            return [self._event_response(dict(row)) for row in rows], total

    def _event_response(self, event: dict[str, Any]) -> dict[str, Any]:
        return {
            **{
                key: event[key]
                for key in (
                    "event_id",
                    "tenant_id",
                    "source_event_id",
                    "event_fingerprint",
                    "source_type",
                    "event_type",
                    "username",
                    "host_id",
                    "source_ip",
                    "destination_ip",
                    "session_id",
                    "process_name",
                    "outcome",
                    "severity",
                )
            },
            "event_time": _aware(event["event_time"]).isoformat().replace("+00:00", "Z"),
            "ingested_at": _aware(event["ingested_at"]).isoformat().replace("+00:00", "Z"),
            "raw_event": json.loads(event["raw_event"]),
            "normalized_fields": json.loads(event["normalized_fields"]),
        }

    def list_incidents(self, *, limit: int, offset: int) -> tuple[list[dict[str, Any]], int]:
        with self.engine.connect() as connection:
            where = incidents.c.tenant_id == self.tenant_id
            total = connection.execute(
                sa.select(sa.func.count()).select_from(incidents).where(where)
            ).scalar_one()
            rows = connection.execute(
                sa.select(incidents)
                .where(where)
                .order_by(incidents.c.observed_end.desc(), incidents.c.incident_id)
                .limit(limit)
                .offset(offset)
            ).mappings()
            return [dict(row) for row in rows], total

    def get_incident(self, incident_id: str) -> dict[str, Any] | None:
        with self.engine.connect() as connection:
            incident = (
                connection.execute(
                    sa.select(incidents).where(
                        incidents.c.incident_id == incident_id,
                        incidents.c.tenant_id == self.tenant_id,
                    )
                )
                .mappings()
                .first()
            )
            if incident is None:
                return None
            return self._incident_detail(connection, dict(incident))

    def _incident_detail(self, connection: Connection, incident: dict[str, Any]) -> dict[str, Any]:
        event_rows = [
            dict(row)
            for row in connection.execute(
                sa.select(security_events)
                .join(incident_events, incident_events.c.event_id == security_events.c.event_id)
                .where(incident_events.c.incident_id == incident["incident_id"])
                .order_by(
                    security_events.c.event_time,
                    security_events.c.ingested_at,
                    security_events.c.event_id,
                )
            ).mappings()
        ]
        finding_rows = connection.execute(
            sa.select(findings)
            .where(findings.c.incident_id == incident["incident_id"])
            .order_by(findings.c.rule_id)
        ).mappings()
        finding_output = []
        events_by_id = {event["event_id"]: event for event in event_rows}
        for finding in finding_rows:
            evidence_ids = list(
                connection.execute(
                    sa.select(finding_events.c.event_id)
                    .join(
                        security_events,
                        security_events.c.event_id == finding_events.c.event_id,
                    )
                    .where(finding_events.c.finding_id == finding["finding_id"])
                    .order_by(
                        security_events.c.event_time,
                        security_events.c.ingested_at,
                        security_events.c.event_id,
                    )
                ).scalars()
            )
            evidence_source_ids = [
                events_by_id[event_id]["source_event_id"]
                for event_id in evidence_ids
                if events_by_id[event_id]["source_event_id"] is not None
            ]
            finding_output.append(
                {
                    "finding_id": finding["finding_id"],
                    "incident_id": finding["incident_id"],
                    "status": finding["status"],
                    "title": finding["title"],
                    "description": finding["description"],
                    "rule_id": finding["rule_id"],
                    "rule_version": finding["rule_version"],
                    "severity_factors": json.loads(finding["severity_factors"]),
                    "evidence": evidence_source_ids,
                    "evidence_event_ids": evidence_ids,
                    "evidence_source_event_ids": evidence_source_ids,
                }
            )
        event_ids = [event["event_id"] for event in event_rows]
        entity_output = self._incident_entities(connection, event_ids)
        incident_output = self._incident_response(incident)
        incident_output["evidence_event_ids"] = event_ids
        incident_output["evidence_source_event_ids"] = [
            event["source_event_id"] for event in event_rows if event["source_event_id"] is not None
        ]
        incident_output["evidence"] = incident_output["evidence_source_event_ids"]
        return {
            "incident": incident_output,
            "events": [self._event_response(event) for event in event_rows],
            "findings": finding_output,
            "entities": entity_output,
        }

    def _incident_entities(
        self,
        connection: Connection,
        event_ids: list[str],
    ) -> list[dict[str, Any]]:
        if not event_ids:
            return []
        rows = connection.execute(
            sa.select(entities)
            .where(entities.c.tenant_id == self.tenant_id)
            .order_by(entities.c.entity_type, entities.c.canonical_key)
        ).mappings()
        # Entity rows are globally unique within the tenant; restrict the result
        # using the canonical fields present in the incident's evidence events.
        event_rows = connection.execute(
            sa.select(security_events).where(security_events.c.event_id.in_(event_ids))
        ).mappings()
        keys: set[str] = set()
        for event in event_rows:
            for entity_type, field in (
                ("user", "username"),
                ("host", "host_id"),
                ("ip", "source_ip"),
                ("ip", "destination_ip"),
                ("session", "session_id"),
                ("process", "process_name"),
            ):
                if event.get(field):
                    keys.add(f"{entity_type}:{event[field]}")
        return [
            {
                "entity_id": row["entity_id"],
                "entity_type": row["entity_type"],
                "canonical_key": row["canonical_key"],
                "display_value": row["display_value"],
            }
            for row in rows
            if row["canonical_key"] in keys
        ]

    def _incident_response(self, incident: dict[str, Any]) -> dict[str, Any]:
        return {
            "incident_id": incident["incident_id"],
            "tenant_id": incident["tenant_id"],
            "title": incident["title"],
            "status": incident["status"],
            "severity": incident["severity"],
            "confidence": incident["confidence"],
            "correlation_key": incident["correlation_key"],
            "observed_start": _aware(incident["observed_start"]).isoformat().replace("+00:00", "Z"),
            "observed_end": _aware(incident["observed_end"]).isoformat().replace("+00:00", "Z"),
            "created_at": _aware(incident["created_at"]).isoformat().replace("+00:00", "Z"),
            "updated_at": _aware(incident["updated_at"]).isoformat().replace("+00:00", "Z"),
        }

    def incident_timeline(self, incident_id: str) -> list[dict[str, Any]] | None:
        detail = self.get_incident(incident_id)
        return detail["events"] if detail else None

    def incident_findings(self, incident_id: str) -> list[dict[str, Any]] | None:
        detail = self.get_incident(incident_id)
        return detail["findings"] if detail else None

    def incident_graph(self, incident_id: str) -> dict[str, Any] | None:
        """Return the bounded, evidence-backed entity graph for one incident."""

        with self.engine.connect() as connection:
            incident = connection.execute(
                sa.select(incidents.c.incident_id).where(
                    incidents.c.incident_id == incident_id,
                    incidents.c.tenant_id == self.tenant_id,
                )
            ).scalar_one_or_none()
            if incident is None:
                return None
            detail = self.get_incident(incident_id)
            entity_ids = {entity["entity_id"] for entity in detail["entities"]}
            entity_rows = connection.execute(
                sa.select(entities).where(
                    entities.c.tenant_id == self.tenant_id,
                    entities.c.entity_id.in_(entity_ids),
                )
            ).mappings()
            entity_by_id = {row["entity_id"]: dict(row) for row in entity_rows}
            relationship_rows = connection.execute(
                sa.select(entity_relationships).where(
                    entity_relationships.c.incident_id == incident_id,
                    entity_relationships.c.from_entity_id.in_(entity_ids),
                    entity_relationships.c.to_entity_id.in_(entity_ids),
                )
            ).mappings()
            source_by_id = {
                event["event_id"]: event["source_event_id"]
                for event in detail["events"]
                if event["source_event_id"]
            }
            return {
                "incident_id": incident_id,
                "nodes": [
                    {
                        "entity_id": row["entity_id"],
                        "entity_type": row["entity_type"],
                        "canonical_key": row["canonical_key"],
                        "display_value": row["display_value"],
                    }
                    for row in entity_by_id.values()
                ],
                "edges": [
                    {
                        "from": row["from_entity_id"],
                        "to": row["to_entity_id"],
                        "relationship_type": row["relationship_type"],
                        "status": row["evidence_status"],
                        "evidence_event_ids": [
                            source_by_id.get(event_id, event_id)
                            for event_id in json.loads(row["evidence_event_ids"])
                        ],
                    }
                    for row in relationship_rows
                ],
            }
