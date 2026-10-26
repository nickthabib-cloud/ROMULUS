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


def _child(name: str, *columns, primary_key: tuple[str, ...]) -> None:
    op.create_table(
        name,
        sa.Column("carry_seq", sa.Integer(), nullable=False),
        *columns,
        sa.ForeignKeyConstraint(["carry_seq"], ["baseline_carry_hour.seq"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint(*primary_key, name=f"pk_{name}"),
        sqlite_with_rowid=False,
    )


def upgrade() -> None:
    # Null on material staged before tokens were kept; the writer then keeps refusing buckets that span cells.
    op.add_column("baseline_window_count", sa.Column("token", sa.String(), nullable=True))
    op.create_table(
        "baseline_carry_hour",
        sa.Column("seq", sa.Integer(), nullable=False, autoincrement=True),
        sa.Column("site", sa.String(), nullable=False),
        sa.Column("target", sa.String(), nullable=False),
        sa.Column("hour", sa.DateTime(timezone=True), nullable=False),
        sa.Column("normalizer", sa.String(), nullable=False),
        sa.Column("format", sa.Integer(), nullable=False),
        sa.Column("hostless", sa.Integer(), nullable=False),
        sa.Column("bytes", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("hostless IN (0, 1)", name="ck_baseline_carry_hour_hostless"),
        sa.CheckConstraint("bytes >= 0", name="ck_baseline_carry_hour_bytes"),
        sa.PrimaryKeyConstraint("seq"),
    )
    op.create_index("ix_baseline_carry_hour_lookup", "baseline_carry_hour",
                    ["site", "target", "hour", "normalizer", "format"], unique=True)
    op.create_index("ix_baseline_carry_hour_age", "baseline_carry_hour", ["hour", "seq"], unique=False)
    _child("baseline_carry_host",
           sa.Column("ref", sa.Integer(), nullable=False), sa.Column("host", sa.String(), nullable=False),
           sa.Column("boot", sa.String(), nullable=True), primary_key=("carry_seq", "ref"))
    _child("baseline_carry_exec",
           sa.Column("ordinal", sa.Integer(), nullable=False), sa.Column("ref", sa.Integer(), nullable=False),
           sa.Column("pid", sa.Integer(), nullable=False), sa.Column("ts_us", sa.Integer(), nullable=False),
           sa.Column("serial", sa.Integer(), nullable=True), sa.Column("executable", sa.String(), nullable=False),
           sa.Column("parent_pid", sa.Integer(), nullable=True), sa.Column("raw_id", sa.String(), nullable=False),
           sa.Column("ambiguous", sa.Integer(), nullable=False),
           sa.Column("evicted_earliest_us", sa.Integer(), nullable=True),
           sa.Column("evicted_latest_us", sa.Integer(), nullable=True),
           primary_key=("carry_seq", "ordinal"))
    _child("baseline_carry_observation",
           sa.Column("ordinal", sa.Integer(), nullable=False), sa.Column("ref", sa.Integer(), nullable=False),
           sa.Column("pid", sa.Integer(), nullable=False), sa.Column("ts_us", sa.Integer(), nullable=False),
           sa.Column("serial", sa.Integer(), nullable=True), sa.Column("executable", sa.String(), nullable=False),
           sa.Column("parent_pid", sa.Integer(), nullable=False), sa.Column("session", sa.Integer(), nullable=True),
           sa.Column("event_id", sa.String(), nullable=False), primary_key=("carry_seq", "ordinal"))
    _child("baseline_carry_break",
           sa.Column("ref", sa.Integer(), nullable=False), sa.Column("hour_us", sa.Integer(), nullable=False),
           primary_key=("carry_seq", "ref", "hour_us"))


def downgrade() -> None:
    for name in ("baseline_carry_break", "baseline_carry_observation", "baseline_carry_exec", "baseline_carry_host"):
        op.drop_table(name)
    op.drop_index("ix_baseline_carry_hour_age", table_name="baseline_carry_hour")
    op.drop_index("ix_baseline_carry_hour_lookup", table_name="baseline_carry_hour")
    op.drop_table("baseline_carry_hour")
    op.execute("ALTER TABLE baseline_window_count DROP COLUMN token")
