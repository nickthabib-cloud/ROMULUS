"""retain compact hunt-window counts for hunt-derived baseline segments

Revision ID: 0019
Revises: 0018
"""

import sqlalchemy as sa
from alembic import op

revision = "0019"
down_revision = "0018"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "baseline_window_count",
        sa.Column("hunt_id", sa.String(), nullable=False),
        sa.Column("spec_id", sa.String(), nullable=False),
        sa.Column("spec_version", sa.String(), nullable=False),
        sa.Column("target", sa.String(), nullable=False),
        sa.Column("partition", sa.String(), nullable=False),
        sa.Column("ordinal", sa.Integer(), nullable=False),
        sa.Column("scope_kind", sa.String(), nullable=False),
        sa.Column("scope", sa.String(), nullable=False),
        sa.Column("key_id", sa.String(), nullable=False),
        sa.Column("key_digest", sa.String(), nullable=False),
        sa.Column("key", sa.JSON(), nullable=False),
        sa.Column("bucket", sa.DateTime(timezone=True), nullable=False),
        sa.Column("count", sa.Integer(), nullable=False),
        sa.Column("first_ts", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_ts", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("count >= 1", name="ck_baseline_window_count_count"),
        sa.ForeignKeyConstraint(["hunt_id"], ["hunt.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint(
            "hunt_id", "spec_id", "target", "partition", "ordinal",
            name="pk_baseline_window_count",
        ),
    )
    op.create_table(
        "baseline_window_scope_hour",
        sa.Column("hunt_id", sa.String(), nullable=False),
        sa.Column("spec_id", sa.String(), nullable=False),
        sa.Column("spec_version", sa.String(), nullable=False),
        sa.Column("target", sa.String(), nullable=False),
        sa.Column("partition", sa.String(), nullable=False),
        sa.Column("ordinal", sa.Integer(), nullable=False),
        sa.Column("scope_kind", sa.String(), nullable=False),
        sa.Column("scope", sa.String(), nullable=False),
        sa.Column("hour", sa.DateTime(timezone=True), nullable=False),
        sa.Column("events", sa.Integer(), nullable=False),
        sa.CheckConstraint("events >= 0", name="ck_baseline_window_scope_hour_events"),
        sa.ForeignKeyConstraint(["hunt_id"], ["hunt.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint(
            "hunt_id", "spec_id", "target", "partition", "ordinal",
            name="pk_baseline_window_scope_hour",
        ),
    )
    op.create_table(
        "baseline_hunt_exclusion",
        sa.Column("hunt_id", sa.String(), nullable=False),
        sa.Column("site", sa.String(), nullable=False),
        sa.Column("target", sa.String(), nullable=False),
        sa.Column("spec_id", sa.String(), nullable=False),
        sa.Column("spec_version", sa.String(), nullable=False),
        sa.Column("key_version", sa.String(), nullable=False),
        sa.Column("key_digest", sa.String(), nullable=False),
        sa.Column("start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("end", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("end > start", name="ck_baseline_hunt_exclusion_span"),
        sa.ForeignKeyConstraint(["hunt_id"], ["hunt.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint(
            "hunt_id", "target", "spec_id", "key_digest",
            name="pk_baseline_hunt_exclusion",
        ),
    )
    op.create_index(
        "ix_baseline_hunt_exclusion_overlap", "baseline_hunt_exclusion",
        ["site", "target", "spec_id", "spec_version", "key_version", "start", "end"], unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_baseline_hunt_exclusion_overlap", table_name="baseline_hunt_exclusion")
    op.drop_table("baseline_hunt_exclusion")
    op.drop_table("baseline_window_scope_hour")
    op.drop_table("baseline_window_count")
