"""provider, endpoint, egress, reported model, finish reason and estimated cost on model calls

Revision ID: 0008
Revises: 0007
"""
import sqlalchemy as sa
from alembic import op

revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None

COLUMNS = (
    ("provider", sa.String()), ("endpoint_host", sa.String()), ("egress", sa.String()),
    ("model_reported", sa.String()), ("finish_reason", sa.String()), ("cost_usd_est", sa.Float()),
)


def upgrade() -> None:
    with op.batch_alter_table("model_call") as batch:
        for name, kind in COLUMNS:
            batch.add_column(sa.Column(name, kind, nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("model_call") as batch:
        for name, _kind in reversed(COLUMNS):
            batch.drop_column(name)
