"""durable compact baseline window and history state and network-bound history

Revision ID: 0018
Revises: 0017
"""

import sqlalchemy as sa
from alembic import op

revision = "0018"
down_revision = "0017"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("baseline_segment", sa.Column("network_digest", sa.String(), nullable=True))
    op.add_column(
        "baseline_observation",
        sa.Column("first_event_refs", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
    )
    op.create_table(
        "baseline_window_cell",
        sa.Column("hunt_id", sa.String(), nullable=False),
        sa.Column("target", sa.String(), nullable=False),
        sa.Column("partition", sa.String(), nullable=False),
        sa.Column("spec_version", sa.String(), nullable=False),
        sa.Column("start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("end", sa.DateTime(timezone=True), nullable=False),
        sa.Column("target_applicable", sa.Integer(), nullable=False),
        sa.Column("source_complete", sa.Integer(), nullable=False),
        sa.Column("reasons", sa.JSON(), nullable=False),
        sa.Column("task_id", sa.String(), nullable=True),
        sa.Column("evaluated", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(["hunt_id"], ["hunt.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("hunt_id", "target", "partition", name="pk_baseline_window_cell"),
    )
    for name in ("observation", "pending"):
        op.create_table(
            f"baseline_window_{name}",
            sa.Column("hunt_id", sa.String(), nullable=False),
            sa.Column("target", sa.String(), nullable=False),
            sa.Column("partition", sa.String(), nullable=False),
            sa.Column("ordinal", sa.Integer(), nullable=False),
            sa.Column("body", sa.JSON(), nullable=False),
            sa.ForeignKeyConstraint(
                ["hunt_id", "target", "partition"],
                ["baseline_window_cell.hunt_id", "baseline_window_cell.target",
                 "baseline_window_cell.partition"],
                ondelete="CASCADE",
            ),
            sa.PrimaryKeyConstraint(
                "hunt_id", "target", "partition", "ordinal",
                name=f"pk_baseline_window_{name}",
            ),
        )
    op.create_table(
        "baseline_window_exec",
        sa.Column("hunt_id", sa.String(), nullable=False),
        sa.Column("target", sa.String(), nullable=False),
        sa.Column("partition", sa.String(), nullable=False),
        sa.Column("ordinal", sa.Integer(), nullable=False),
        sa.Column("host", sa.String(), nullable=True),
        sa.Column("boot", sa.String(), nullable=True),
        sa.Column("pid", sa.Integer(), nullable=True),
        sa.Column("ppid", sa.Integer(), nullable=True),
        sa.Column("ts", sa.DateTime(timezone=True), nullable=False),
        sa.Column("serial", sa.Integer(), nullable=True),
        sa.Column("executable", sa.String(), nullable=True),
        sa.Column("outcome", sa.String(), nullable=False),
        sa.Column("event_id", sa.String(), nullable=False),
        sa.ForeignKeyConstraint(
            ["hunt_id", "target", "partition"],
            ["baseline_window_cell.hunt_id", "baseline_window_cell.target",
             "baseline_window_cell.partition"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint(
            "hunt_id", "target", "partition", "ordinal", name="pk_baseline_window_exec",
        ),
    )
    op.create_table(
        "baseline_history_cell",
        sa.Column("hunt_id", sa.String(), nullable=False),
        sa.Column("target", sa.String(), nullable=False),
        sa.Column("spec_id", sa.String(), nullable=False),
        sa.Column("start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("end", sa.DateTime(timezone=True), nullable=False),
        sa.Column("events_total", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(["hunt_id"], ["hunt.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("hunt_id", "target", "spec_id", "start", name="pk_baseline_history_cell"),
    )
    op.create_table(
        "baseline_history_row",
        sa.Column("hunt_id", sa.String(), nullable=False),
        sa.Column("target", sa.String(), nullable=False),
        sa.Column("spec_id", sa.String(), nullable=False),
        sa.Column("start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("kind", sa.String(), nullable=False),
        sa.Column("ordinal", sa.Integer(), nullable=False),
        sa.Column("body", sa.JSON(), nullable=False),
        sa.ForeignKeyConstraint(
            ["hunt_id", "target", "spec_id", "start"],
            ["baseline_history_cell.hunt_id", "baseline_history_cell.target", "baseline_history_cell.spec_id",
             "baseline_history_cell.start"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint(
            "hunt_id", "target", "spec_id", "start", "kind", "ordinal", name="pk_baseline_history_row",
        ),
    )


def downgrade() -> None:
    op.drop_table("baseline_history_row")
    op.drop_table("baseline_history_cell")
    op.drop_table("baseline_window_exec")
    op.drop_table("baseline_window_pending")
    op.drop_table("baseline_window_observation")
    op.drop_table("baseline_window_cell")
    op.drop_column("baseline_observation", "first_event_refs")
    op.drop_column("baseline_segment", "network_digest")
