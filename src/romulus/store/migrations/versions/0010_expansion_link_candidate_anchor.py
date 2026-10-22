"""key expansion links to candidates independently of scheduler anchors

Revision ID: 0010
Revises: 0009
"""
import sqlalchemy as sa
from alembic import op

revision = "0010"
down_revision = "0009"
branch_labels = None
depends_on = None

_COLUMNS = (
    "id", "hunt_id", "anchor_id", "link_type", "window_label", "window_start", "window_end",
    "strength", "key", "status", "event_ids", "evidence_ids", "task_ids", "coverage", "reasons",
    "duration_ms", "query_spend", "evaluated", "created_at", "updated_at",
)


def _create(name: str, anchor_table: str) -> None:
    op.create_table(
        name,
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("hunt_id", sa.String(), sa.ForeignKey("hunt.id"), nullable=False),
        sa.Column("anchor_id", sa.String(), sa.ForeignKey(f"{anchor_table}.id"), nullable=False),
        sa.Column("link_type", sa.String(), nullable=False),
        sa.Column("window_label", sa.String(), nullable=False),
        sa.Column("window_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("window_end", sa.DateTime(timezone=True), nullable=False),
        sa.Column("strength", sa.String(), nullable=False),
        sa.Column("key", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("event_ids", sa.JSON(), nullable=False),
        sa.Column("evidence_ids", sa.JSON(), nullable=False),
        sa.Column("task_ids", sa.JSON(), nullable=False),
        sa.Column("coverage", sa.JSON(), nullable=False),
        sa.Column("reasons", sa.JSON(), nullable=False),
        sa.Column("duration_ms", sa.Integer(), nullable=False),
        sa.Column("query_spend", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("evaluated", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )


def _rebuild(anchor_table: str) -> None:
    temporary = "expansion_link_rebuild"
    _create(temporary, anchor_table)
    columns = ", ".join(_COLUMNS)
    op.execute(sa.text(
        f"INSERT INTO {temporary} ({columns}) SELECT {columns} FROM expansion_link"
    ))
    op.drop_index("ix_expansion_link_anchor", table_name="expansion_link")
    op.drop_table("expansion_link")
    op.rename_table(temporary, "expansion_link")
    op.create_index("ix_expansion_link_anchor", "expansion_link", ["anchor_id", "link_type"])


def upgrade() -> None:
    _rebuild("candidate")


def downgrade() -> None:
    _rebuild("expansion_anchor")
