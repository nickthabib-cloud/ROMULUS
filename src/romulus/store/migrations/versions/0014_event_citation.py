"""scope raw citation provenance to each hunt

Revision ID: 0014
Revises: 0013
"""
import sqlalchemy as sa
from alembic import op

revision = "0014"
down_revision = "0013"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "event_citation",
        sa.Column("hunt_id", sa.String(), sa.ForeignKey("hunt.id"), primary_key=True),
        sa.Column("event_id", sa.String(), sa.ForeignKey("typed_event.id"), primary_key=True),
        sa.Column("event", sa.JSON(), nullable=False),
        sa.Column("raw_ids", sa.JSON(), nullable=False),
    )
    op.create_index("ix_event_citation_event", "event_citation", ["event_id"])


def downgrade() -> None:
    op.drop_index("ix_event_citation_event", table_name="event_citation")
    op.drop_table("event_citation")
