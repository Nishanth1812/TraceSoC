"""Create the initial schema marker.

Revision ID: 20261015_0001
Revises:
"""

import sqlalchemy as sa
from alembic import op

revision = "20261015_0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "schema_metadata",
        sa.Column("key", sa.String(length=100), primary_key=True),
        sa.Column("value", sa.String(length=255), nullable=False),
    )
    op.bulk_insert(
        sa.table(
            "schema_metadata",
            sa.column("key", sa.String),
            sa.column("value", sa.String),
        ),
        [{"key": "application", "value": "tracesoc"}],
    )


def downgrade() -> None:
    op.drop_table("schema_metadata")
