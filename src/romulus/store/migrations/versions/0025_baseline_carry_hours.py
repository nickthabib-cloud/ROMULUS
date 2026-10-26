"""dedup tokens in hunt window material; persisted per-hour parent carry input

Revision ID: 0025
Revises: 0024
"""

import sqlalchemy as sa
from alembic import op

revision = "0025"
down_revision = "0024"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Null on material staged before tokens were kept; the writer then keeps refusing buckets that span cells.
    op.add_column("baseline_window_count", sa.Column("token", sa.String(), nullable=True))
    op.create_table(
        "baseline_carry_hour",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("site", sa.String(), nullable=False),
        sa.Column("target", sa.String(), nullable=False),
        sa.Column("hour", sa.DateTime(timezone=True), nullable=False),
        sa.Column("normalizer", sa.String(), nullable=False),
        sa.Column("format", sa.Integer(), nullable=False),
        sa.Column("hostless", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("hostless IN (0, 1)", name="ck_baseline_carry_hour_hostless"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_baseline_carry_hour_lookup", "baseline_carry_hour",
                    ["site", "target", "hour", "normalizer", "format"], unique=True)
    op.create_table(
        "baseline_carry_row",
        sa.Column("carry_id", sa.String(), nullable=False),
        sa.Column("kind", sa.String(), nullable=False),
        sa.Column("ordinal", sa.Integer(), nullable=False),
        sa.Column("body", sa.JSON(), nullable=False),
        sa.CheckConstraint("kind IN ('exec', 'observation', 'break')", name="ck_baseline_carry_row_kind"),
        sa.ForeignKeyConstraint(["carry_id"], ["baseline_carry_hour.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("carry_id", "kind", "ordinal", name="pk_baseline_carry_row"),
    )


def downgrade() -> None:
    op.drop_table("baseline_carry_row")
    op.drop_index("ix_baseline_carry_hour_lookup", table_name="baseline_carry_hour")
    op.drop_table("baseline_carry_hour")
    op.execute("ALTER TABLE baseline_window_count DROP COLUMN token")
