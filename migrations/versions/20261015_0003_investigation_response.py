"""Add investigation, response, simulation, and audit tables.

Revision ID: 20261015_0003
Revises: 20261015_0002
"""

from alembic import op

from apps.api.app.schema import metadata

revision = "20261015_0003"
down_revision = "20261015_0002"
branch_labels = None
depends_on = None


TABLES = (
    "investigation_runs",
    "investigation_steps",
    "simulated_state",
    "response_actions",
    "response_executions",
    "audit_logs",
)


def upgrade() -> None:
    bind = op.get_bind()
    for table_name in TABLES:
        metadata.tables[table_name].create(bind, checkfirst=True)


def downgrade() -> None:
    bind = op.get_bind()
    for table_name in reversed(TABLES):
        metadata.tables[table_name].drop(bind, checkfirst=True)
