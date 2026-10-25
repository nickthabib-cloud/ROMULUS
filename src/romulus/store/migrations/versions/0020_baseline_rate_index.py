"""add witnesses and index persisted window hours for rate judgement

Revision ID: 0020
Revises: 0019
"""

import sqlalchemy as sa
from alembic import op

revision = "0020"
down_revision = "0019"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("baseline_window_scope_hour", sa.Column("first_event_id", sa.String(), nullable=True))
    op.add_column("baseline_window_scope_hour", sa.Column("first_event_refs", sa.JSON(), nullable=True))
    op.create_index(
        "ix_baseline_window_scope_rate",
        "baseline_window_scope_hour",
        ["hunt_id", "spec_id", "scope_kind", "scope", "hour", "target", "partition"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_baseline_window_scope_rate", table_name="baseline_window_scope_hour")
    op.drop_column("baseline_window_scope_hour", "first_event_refs")
    op.drop_column("baseline_window_scope_hour", "first_event_id")
