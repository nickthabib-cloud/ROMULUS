"""add durable investigator lease and idempotent case steps

Revision ID: 0002
Revises: 0001
"""
import sqlalchemy as sa
from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("hunt") as batch_op:
        batch_op.add_column(sa.Column("heartbeat_at", sa.DateTime(timezone=True), nullable=True))
        batch_op.add_column(sa.Column("lease_until", sa.DateTime(timezone=True), nullable=True))
    with op.batch_alter_table("case_step") as batch_op:
        batch_op.create_unique_constraint("uq_case_step_n", ["case_id", "n"])


def downgrade() -> None:
    with op.batch_alter_table("case_step") as batch_op:
        batch_op.drop_constraint("uq_case_step_n", type_="unique")
    with op.batch_alter_table("hunt") as batch_op:
        batch_op.drop_column("lease_until")
        batch_op.drop_column("heartbeat_at")
