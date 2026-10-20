"""checkpoint physical source queries and candidate group identity

Revision ID: 0006
Revises: 0005
"""
import sqlalchemy as sa
from alembic import op

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("task") as batch_op:
        batch_op.add_column(sa.Column(
            "source_queries", sa.Integer(), nullable=False, server_default="0",
        ))
    with op.batch_alter_table("candidate") as batch_op:
        batch_op.add_column(sa.Column(
            "group_key", sa.String(), nullable=False, server_default="",
        ))


def downgrade() -> None:
    with op.batch_alter_table("candidate") as batch_op:
        batch_op.drop_column("group_key")
    with op.batch_alter_table("task") as batch_op:
        batch_op.drop_column("source_queries")
