"""persist deterministic expansion anchors and links

Revision ID: 0004
Revises: 0003
"""
import sqlalchemy as sa
from alembic import op

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("candidate") as batch_op:
        batch_op.add_column(sa.Column("source_anchor_id", sa.String(), nullable=True))
        batch_op.add_column(sa.Column("source_link_id", sa.String(), nullable=True))
    op.create_table(
        "expansion_anchor",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("hunt_id", sa.String(), sa.ForeignKey("hunt.id"), nullable=False),
        sa.Column("candidate_id", sa.String(), sa.ForeignKey("candidate.id"), nullable=False),
        sa.Column("depth", sa.Integer(), nullable=False),
        sa.Column("parent_anchor_id", sa.String(), nullable=True),
        sa.Column("host", sa.String(), nullable=True),
        sa.Column("lane", sa.String(), nullable=False),
        sa.Column("severity", sa.String(), nullable=False),
        sa.Column("ts", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("reasons", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("hunt_id", "candidate_id", name="uq_expansion_anchor_candidate"),
    )
    op.create_index("ix_expansion_anchor_hunt_status", "expansion_anchor", ["hunt_id", "status"])
    op.create_table(
        "expansion_link",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("hunt_id", sa.String(), sa.ForeignKey("hunt.id"), nullable=False),
        sa.Column("anchor_id", sa.String(), sa.ForeignKey("expansion_anchor.id"), nullable=False),
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
        sa.Column("evaluated", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_expansion_link_anchor", "expansion_link", ["anchor_id", "link_type"])


def downgrade() -> None:
    op.drop_index("ix_expansion_link_anchor", table_name="expansion_link")
    op.drop_table("expansion_link")
    op.drop_index("ix_expansion_anchor_hunt_status", table_name="expansion_anchor")
    op.drop_table("expansion_anchor")
    with op.batch_alter_table("candidate") as batch_op:
        batch_op.drop_column("source_link_id")
        batch_op.drop_column("source_anchor_id")
