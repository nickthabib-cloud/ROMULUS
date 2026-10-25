"""persist per-hour hunt window material

Revision ID: 0022
Revises: 0021
"""

import sqlalchemy as sa
from alembic import op

revision = "0022"
down_revision = "0021"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "baseline_window_count",
        sa.Column("material_hour", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_table(
        "baseline_window_event_hour",
        sa.Column("hunt_id", sa.String(), nullable=False),
        sa.Column("spec_id", sa.String(), nullable=False),
        sa.Column("spec_version", sa.String(), nullable=False),
        sa.Column("target", sa.String(), nullable=False),
        sa.Column("partition", sa.String(), nullable=False),
        sa.Column("ordinal", sa.Integer(), nullable=False),
        sa.Column("hour", sa.DateTime(timezone=True), nullable=False),
        sa.Column("events", sa.Integer(), nullable=False),
        sa.CheckConstraint("events >= 0", name="ck_baseline_window_event_hour_events"),
        sa.ForeignKeyConstraint(["hunt_id"], ["hunt.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint(
            "hunt_id", "spec_id", "target", "partition", "ordinal",
            name="pk_baseline_window_event_hour",
        ),
    )
    op.create_index(
        "ix_baseline_window_event_hour_merge",
        "baseline_window_event_hour",
        ["hunt_id", "spec_id", "target", "hour", "partition"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_baseline_window_event_hour_merge", table_name="baseline_window_event_hour")
    op.drop_table("baseline_window_event_hour")
    op.drop_column("baseline_window_count", "material_hour")
