"""A per-account session generation: every web session cookie carries the value it was issued under, and logout,
disabling the account, a role change or a password change raise it, so older cookies are refused."""
import sqlalchemy as sa
from alembic import op

revision = "0050"
down_revision = "0049"
branch_labels = None
depends_on = None


def _begin():
    connection = op.get_bind()
    if connection.dialect.name == "sqlite" and not connection.connection.driver_connection.in_transaction:
        connection.exec_driver_sql("BEGIN")
    return connection


def upgrade() -> None:
    _begin()
    op.add_column("user", sa.Column("session_generation", sa.Integer(), nullable=False, server_default="0"))


def downgrade() -> None:
    _begin()
    op.drop_column("user", "session_generation")
