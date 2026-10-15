"""SQLAlchemy Core schema for the deterministic evidence slice.

The tables intentionally use portable SQLAlchemy types.  JSON values are stored
as serialized JSON text so the same repository works with PostgreSQL and the
SQLite configuration used by local tests.
"""

import sqlalchemy as sa

metadata = sa.MetaData()

security_events = sa.Table(
    "security_events",
    metadata,
    sa.Column("event_id", sa.String(36), primary_key=True),
    sa.Column("tenant_id", sa.String(100), nullable=False),
    sa.Column("source_event_id", sa.String(255)),
    sa.Column("event_fingerprint", sa.String(80), nullable=False),
    sa.Column("source_type", sa.String(50), nullable=False),
    sa.Column("event_type", sa.String(100), nullable=False),
    sa.Column("event_time", sa.DateTime(timezone=True), nullable=False),
    sa.Column("ingested_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("username", sa.String(255)),
    sa.Column("host_id", sa.String(255)),
    sa.Column("source_ip", sa.String(64)),
    sa.Column("destination_ip", sa.String(64)),
    sa.Column("session_id", sa.String(255)),
    sa.Column("process_name", sa.String(255)),
    sa.Column("outcome", sa.String(20), nullable=False),
    sa.Column("severity", sa.String(50)),
    sa.Column("raw_event", sa.Text, nullable=False),
    sa.Column("normalized_fields", sa.Text, nullable=False),
    sa.UniqueConstraint("tenant_id", "event_fingerprint", name="uq_security_event_fingerprint"),
    sa.Index("ix_security_events_tenant_time", "tenant_id", "event_time", "ingested_at"),
    sa.Index("ix_security_events_tenant_source_id", "tenant_id", "source_event_id"),
)

ingestion_runs = sa.Table(
    "ingestion_runs",
    metadata,
    sa.Column("run_id", sa.String(36), primary_key=True),
    sa.Column("tenant_id", sa.String(100), nullable=False),
    sa.Column("idempotency_key", sa.String(255), nullable=False),
    sa.Column("source", sa.String(100), nullable=False),
    sa.Column("status", sa.String(30), nullable=False),
    sa.Column("accepted", sa.Integer, nullable=False, server_default="0"),
    sa.Column("rejected", sa.Integer, nullable=False, server_default="0"),
    sa.Column("duplicates", sa.Integer, nullable=False, server_default="0"),
    sa.Column("failed", sa.Integer, nullable=False, server_default="0"),
    sa.Column("received", sa.Integer, nullable=False, server_default="0"),
    sa.Column("candidate_incident_ids", sa.Text, nullable=False, server_default="[]"),
    sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("completed_at", sa.DateTime(timezone=True)),
    sa.UniqueConstraint("tenant_id", "idempotency_key", name="uq_ingestion_run_idempotency"),
)

ingestion_errors = sa.Table(
    "ingestion_errors",
    metadata,
    sa.Column("error_id", sa.String(36), primary_key=True),
    sa.Column("run_id", sa.String(36), nullable=False),
    sa.Column("record_number", sa.Integer, nullable=False),
    sa.Column("source_event_id", sa.String(255)),
    sa.Column("code", sa.String(100), nullable=False),
    sa.Column("message", sa.String(500), nullable=False),
    sa.Column("details", sa.Text, nullable=False),
    sa.ForeignKeyConstraint(["run_id"], ["ingestion_runs.run_id"]),
)

incidents = sa.Table(
    "incidents",
    metadata,
    sa.Column("incident_id", sa.String(100), primary_key=True),
    sa.Column("tenant_id", sa.String(100), nullable=False),
    sa.Column("correlation_key", sa.String(500), nullable=False),
    sa.Column("title", sa.String(255), nullable=False),
    sa.Column("status", sa.String(40), nullable=False),
    sa.Column("severity", sa.String(30), nullable=False),
    sa.Column("confidence", sa.String(30), nullable=False),
    sa.Column("observed_start", sa.DateTime(timezone=True), nullable=False),
    sa.Column("observed_end", sa.DateTime(timezone=True), nullable=False),
    sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    sa.UniqueConstraint("tenant_id", "correlation_key", name="uq_incident_correlation"),
)

incident_events = sa.Table(
    "incident_events",
    metadata,
    sa.Column("incident_id", sa.String(100), nullable=False),
    sa.Column("event_id", sa.String(36), nullable=False),
    sa.Column("relationship_type", sa.String(50), nullable=False),
    sa.PrimaryKeyConstraint("incident_id", "event_id"),
    sa.ForeignKeyConstraint(["incident_id"], ["incidents.incident_id"]),
    sa.ForeignKeyConstraint(["event_id"], ["security_events.event_id"]),
)

findings = sa.Table(
    "findings",
    metadata,
    sa.Column("finding_id", sa.String(36), primary_key=True),
    sa.Column("incident_id", sa.String(100), nullable=False),
    sa.Column("status", sa.String(30), nullable=False),
    sa.Column("title", sa.String(255), nullable=False),
    sa.Column("description", sa.Text, nullable=False),
    sa.Column("rule_id", sa.String(100), nullable=False),
    sa.Column("rule_version", sa.String(30), nullable=False),
    sa.Column("severity_factors", sa.Text, nullable=False),
    sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    sa.UniqueConstraint("incident_id", "rule_id", "rule_version", name="uq_finding_rule"),
    sa.ForeignKeyConstraint(["incident_id"], ["incidents.incident_id"]),
)

finding_events = sa.Table(
    "finding_events",
    metadata,
    sa.Column("finding_id", sa.String(36), nullable=False),
    sa.Column("event_id", sa.String(36), nullable=False),
    sa.Column("evidence_role", sa.String(50), nullable=False),
    sa.PrimaryKeyConstraint("finding_id", "event_id"),
    sa.ForeignKeyConstraint(["finding_id"], ["findings.finding_id"]),
    sa.ForeignKeyConstraint(["event_id"], ["security_events.event_id"]),
)

entities = sa.Table(
    "entities",
    metadata,
    sa.Column("entity_id", sa.String(36), primary_key=True),
    sa.Column("tenant_id", sa.String(100), nullable=False),
    sa.Column("entity_type", sa.String(30), nullable=False),
    sa.Column("canonical_key", sa.String(500), nullable=False),
    sa.Column("display_value", sa.String(255), nullable=False),
    sa.UniqueConstraint("tenant_id", "canonical_key", name="uq_entity_key"),
)

entity_relationships = sa.Table(
    "entity_relationships",
    metadata,
    sa.Column("relationship_id", sa.String(36), primary_key=True),
    sa.Column("incident_id", sa.String(100), nullable=False),
    sa.Column("from_entity_id", sa.String(36), nullable=False),
    sa.Column("to_entity_id", sa.String(36), nullable=False),
    sa.Column("relationship_type", sa.String(50), nullable=False),
    sa.Column("evidence_event_ids", sa.Text, nullable=False),
    sa.Column("evidence_status", sa.String(30), nullable=False),
    sa.UniqueConstraint(
        "incident_id",
        "from_entity_id",
        "to_entity_id",
        "relationship_type",
        name="uq_entity_relationship",
    ),
    sa.ForeignKeyConstraint(["incident_id"], ["incidents.incident_id"]),
    sa.ForeignKeyConstraint(["from_entity_id"], ["entities.entity_id"]),
    sa.ForeignKeyConstraint(["to_entity_id"], ["entities.entity_id"]),
)
