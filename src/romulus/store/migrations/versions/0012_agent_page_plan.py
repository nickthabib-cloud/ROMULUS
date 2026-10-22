"""persist bounded immutable agent page rows

Revision ID: 0012
Revises: 0011
"""
import sqlalchemy as sa
from alembic import op

revision = "0012"
down_revision = "0011"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "agent_page_plan",
        sa.Column("hunt_id", sa.String(), sa.ForeignKey("hunt.id"), primary_key=True),
        sa.Column("cursor", sa.String(), primary_key=True),
        sa.Column("identity", sa.JSON(), nullable=False),
        sa.Column("summary", sa.JSON(), nullable=False),
        sa.Column("item_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "agent_page_item",
        sa.Column("hunt_id", sa.String(), primary_key=True),
        sa.Column("cursor", sa.String(), primary_key=True),
        sa.Column("ordinal", sa.Integer(), primary_key=True),
        sa.Column("payload", sa.JSON(), nullable=False),
    )
    op.create_index(
        "ix_agent_page_item_lookup", "agent_page_item", ["hunt_id", "cursor", "ordinal"],
    )


def downgrade() -> None:
    op.drop_index("ix_agent_page_item_lookup", table_name="agent_page_item")
    op.drop_table("agent_page_item")
    op.drop_table("agent_page_plan")
