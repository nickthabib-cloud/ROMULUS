"""carry long-lived parent observations

Revision ID: 0021
Revises: 0020
"""

import sqlalchemy as sa
from alembic import op

revision = "0021"
down_revision = "0020"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "baseline_parent_observation",
        sa.Column("hunt_id", sa.String(), nullable=False),
        sa.Column("target", sa.String(), nullable=False),
        sa.Column("host", sa.String(), nullable=False),
        sa.Column("boot", sa.String(), nullable=False),
        sa.Column("pid", sa.Integer(), nullable=False),
        sa.Column("observed_ts", sa.DateTime(timezone=True), nullable=False),
        sa.Column("serial", sa.Integer(), nullable=True),
        sa.Column("executable", sa.String(), nullable=False),
        sa.Column("parent_pid", sa.Integer(), nullable=False),
        sa.Column("session", sa.Integer(), nullable=True),
        sa.Column("event_id", sa.String(), nullable=False),
        sa.CheckConstraint("pid >= 0", name="ck_baseline_parent_observation_pid"),
        sa.CheckConstraint("executable <> ''", name="ck_baseline_parent_observation_executable"),
        sa.ForeignKeyConstraint(["hunt_id"], ["hunt.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint(
            "hunt_id", "target", "host", "boot", "pid", "observed_ts", "event_id",
            name="pk_baseline_parent_observation",
        ),
    )
    op.create_index(
        "ix_baseline_parent_observation_lookup",
        "baseline_parent_observation",
        ["hunt_id", "target", "host", "boot", "pid", "observed_ts"],
        unique=False,
    )
    with op.batch_alter_table("baseline_window_exec") as batch:
        batch.add_column(sa.Column("family", sa.String(), nullable=False, server_default="process_exec"))
        batch.add_column(sa.Column("session", sa.Integer(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("baseline_window_exec") as batch:
        batch.drop_column("session")
        batch.drop_column("family")
    op.drop_index("ix_baseline_parent_observation_lookup", table_name="baseline_parent_observation")
    op.drop_table("baseline_parent_observation")
