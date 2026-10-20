"""analyst-asserted links between findings (attack-path timeline)

Revision ID: 0007
Revises: 0006
"""
import sqlalchemy as sa
from alembic import op

revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "analyst_link",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("hunt_id", sa.String(), sa.ForeignKey("hunt.id"), nullable=False),
        sa.Column("from_finding", sa.String(), nullable=False),
        sa.Column("to_finding", sa.String(), nullable=False),
        sa.Column("relation", sa.String(), nullable=False),
        sa.Column("note", sa.Text()),
        sa.Column("actor", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_analyst_link_hunt", "analyst_link", ["hunt_id"])


def downgrade() -> None:
    op.drop_index("ix_analyst_link_hunt", table_name="analyst_link")
    op.drop_table("analyst_link")
