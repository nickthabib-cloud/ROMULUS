"""bound evicted parent generations

Revision ID: 0023
Revises: 0022
"""

import sqlalchemy as sa
from alembic import op

revision = "0023"
down_revision = "0022"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("baseline_parent_carry") as batch:
        batch.add_column(sa.Column("evicted_earliest_ts", sa.DateTime(timezone=True), nullable=True))
        batch.add_column(sa.Column("evicted_latest_ts", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("baseline_parent_carry") as batch:
        batch.drop_column("evicted_latest_ts")
        batch.drop_column("evicted_earliest_ts")
