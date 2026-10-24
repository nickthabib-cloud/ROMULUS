"""a candidate names the records it cites only to support its claim's statements

Revision ID: 0017
Revises: 0016
"""
import sqlalchemy as sa
from alembic import op

revision = "0017"
down_revision = "0016"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # NULL for the candidates already stored: every record they cite is their own, as before
    op.add_column("candidate", sa.Column("context_event_ids", sa.JSON(), nullable=True))


def downgrade() -> None:
    op.drop_column("candidate", "context_event_ids")
