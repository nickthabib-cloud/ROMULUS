"""A refused agent tool call records why, as field paths and error types (never argument values)."""
from alembic import op

revision = "0041"
down_revision = "0040"
branch_labels = None
depends_on = None


def upgrade():
    c = op.get_bind()
    if c.dialect.name == "sqlite" and not c.connection.driver_connection.in_transaction:
        c.exec_driver_sql("BEGIN")
    c.exec_driver_sql("ALTER TABLE agent_tool_call ADD COLUMN refusal_reasons JSON")


def downgrade():
    c = op.get_bind()
    if c.dialect.name == "sqlite" and not c.connection.driver_connection.in_transaction:
        c.exec_driver_sql("BEGIN")
    c.exec_driver_sql("ALTER TABLE agent_tool_call DROP COLUMN refusal_reasons")
