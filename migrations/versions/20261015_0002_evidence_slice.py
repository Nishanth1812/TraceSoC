"""Add the deterministic evidence slice persistence model.

Revision ID: 20261015_0002
Revises: 20261015_0001
"""

from alembic import op

from apps.api.app.schema import metadata

revision = "20261015_0002"
down_revision = "20261015_0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    metadata.create_all(op.get_bind())


def downgrade() -> None:
    # Drop only tables owned by this revision; schema_metadata belongs to 0001.
    for table_name in (
        "entity_relationships",
        "entities",
        "finding_events",
        "findings",
        "incident_events",
        "incidents",
        "ingestion_errors",
        "ingestion_runs",
        "security_events",
    ):
        metadata.tables[table_name].drop(op.get_bind(), checkfirst=True)
