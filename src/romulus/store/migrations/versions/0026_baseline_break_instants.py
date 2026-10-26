"""break instants and boot spans for the parent carry

Revision ID: 0026
Revises: 0025
"""

import sqlalchemy as sa
from alembic import op

revision = "0026"
down_revision = "0025"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Kept carry hours of format 1 recorded breaks as whole hours. They are never read again (format 2), so they go,
    # with their rows, and are read again when a hunt needs them.
    op.execute("DELETE FROM baseline_carry_hour")
    op.drop_table("baseline_carry_break")
    op.create_table(
        "baseline_carry_break",
        sa.Column("carry_seq", sa.Integer(), nullable=False),
        sa.Column("ref", sa.Integer(), nullable=False),
        sa.Column("start_us", sa.Integer(), nullable=False),
        sa.Column("end_us", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(["carry_seq"], ["baseline_carry_hour.seq"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("carry_seq", "ref", "start_us", name="pk_baseline_carry_break"),
        sqlite_with_rowid=False,
    )
    op.create_table(
        "baseline_parent_boot_span",
        sa.Column("hunt_id", sa.String(), nullable=False),
        sa.Column("target", sa.String(), nullable=False),
        sa.Column("host", sa.String(), nullable=False),
        sa.Column("boot", sa.String(), nullable=False),
        sa.Column("earliest", sa.DateTime(timezone=True), nullable=False),
        sa.Column("latest", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("latest >= earliest", name="ck_baseline_parent_boot_span_order"),
        sa.ForeignKeyConstraint(["hunt_id"], ["hunt.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("hunt_id", "target", "host", "boot", name="pk_baseline_parent_boot_span"),
    )


def downgrade() -> None:
    op.drop_table("baseline_parent_boot_span")
    op.execute("DELETE FROM baseline_carry_hour")
    op.drop_table("baseline_carry_break")
    op.create_table(
        "baseline_carry_break",
        sa.Column("carry_seq", sa.Integer(), nullable=False),
        sa.Column("ref", sa.Integer(), nullable=False),
        sa.Column("hour_us", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(["carry_seq"], ["baseline_carry_hour.seq"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("carry_seq", "ref", "hour_us", name="pk_baseline_carry_break"),
        sqlite_with_rowid=False,
    )
