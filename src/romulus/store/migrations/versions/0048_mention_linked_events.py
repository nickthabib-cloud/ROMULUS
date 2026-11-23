"""A mention keeps the typed events the normalizer made from its cited record when it offered it, so the findings
citing them are found by the candidate-event index instead of a search."""
import sqlalchemy as sa
from alembic import op

revision = "0048"
down_revision = "0047"
branch_labels = None
depends_on = None


def _begin():
    connection = op.get_bind()
    if connection.dialect.name == "sqlite" and not connection.connection.driver_connection.in_transaction:
        connection.exec_driver_sql("BEGIN")
    return connection


def upgrade():
    _begin()
    op.add_column("mention", sa.Column("linked_events", sa.JSON(), nullable=True))


def downgrade():
    _begin()
    with op.batch_alter_table("mention") as batch:
        batch.drop_column("linked_events")
