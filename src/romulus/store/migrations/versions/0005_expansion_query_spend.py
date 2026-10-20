"""persist expansion source-query spend

Revision ID: 0005
Revises: 0004
"""
import sqlalchemy as sa
from alembic import op

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("expansion_link") as batch_op:
        batch_op.add_column(sa.Column(
            "query_spend", sa.Integer(), nullable=False, server_default="0",
        ))
    # Pre-migration link rows have no durable physical-query count. Conservatively
    # consume the default expansion budget rather than let a resume exceed it.
    op.get_bind().execute(sa.text("""
        UPDATE expansion_link
        SET query_spend = 180
        WHERE id IN (
            SELECT MIN(id) FROM expansion_link
            WHERE status != 'unsupported'
            GROUP BY hunt_id
        )
    """))


def downgrade() -> None:
    with op.batch_alter_table("expansion_link") as batch_op:
        batch_op.drop_column("query_spend")
