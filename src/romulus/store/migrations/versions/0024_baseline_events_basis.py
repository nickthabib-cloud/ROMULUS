"""one events_total definition for baseline segments; retained hunt window material: a ledger and merge indexes

Revision ID: 0024
Revises: 0023
"""

import sqlalchemy as sa
from alembic import op

revision = "0024"
down_revision = "0023"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Segments written before this revision counted events_total two ways (every typed event of the target hour,
    # or only the spec's own records). They keep basis 1 and are never selected again; their hours become gaps that
    # the lookback refills under the single definition.
    with op.batch_alter_table("baseline_segment") as batch:
        batch.add_column(sa.Column("events_basis", sa.Integer(), nullable=False, server_default="1"))
        batch.add_column(sa.Column("first_event_hour", sa.DateTime(timezone=True), nullable=True))
    op.create_table(
        "baseline_window_retention",
        sa.Column("hunt_id", sa.String(), nullable=False),
        sa.Column("bytes", sa.Integer(), nullable=False),
        sa.Column("retained_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("reason", sa.String(), nullable=False),
        sa.CheckConstraint("bytes >= 0", name="ck_baseline_window_retention_bytes"),
        sa.ForeignKeyConstraint(["hunt_id"], ["hunt.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("hunt_id", name="pk_baseline_window_retention"),
    )
    op.create_index(
        "ix_baseline_window_count_merge", "baseline_window_count",
        ["hunt_id", "spec_id", "target", "scope", "key_digest", "bucket"], unique=False,
    )
    op.create_index(
        "ix_baseline_window_scope_hour_merge", "baseline_window_scope_hour",
        ["hunt_id", "spec_id", "target", "scope", "hour"], unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_baseline_window_scope_hour_merge", table_name="baseline_window_scope_hour")
    op.drop_index("ix_baseline_window_count_merge", table_name="baseline_window_count")
    op.drop_table("baseline_window_retention")
    with op.batch_alter_table("baseline_segment") as batch:
        batch.drop_column("first_event_hour")
        batch.drop_column("events_basis")
