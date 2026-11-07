"""Immutable local indicator versions and imported Sigma rule content."""
from alembic import op
from sqlalchemy import (
    JSON,
    CheckConstraint,
    Column,
    DateTime,
    ForeignKeyConstraint,
    Index,
    Integer,
    MetaData,
    PrimaryKeyConstraint,
    String,
    Table,
    Text,
)

revision = '0032'
down_revision = '0031'
branch_labels = None
depends_on = None
metadata = MetaData()

indicator_list = Table(
    "indicator_list", metadata,
    Column("id", String, nullable=False),
    Column("version", Integer, nullable=False),
    Column("name", String, nullable=False),
    Column("source", String, nullable=False),
    Column("author", String, nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("expires_at", DateTime(timezone=True), nullable=False),
    Column("digest", String, nullable=False),
    Column("status", String, nullable=False),
    Column("notes", Text, nullable=False, default=""),
    PrimaryKeyConstraint("id", "version"),
    CheckConstraint("version > 0", name="ck_indicator_list_version"),
    CheckConstraint("status IN ('active','expired','retired')", name="ck_indicator_list_status"),
)

indicator_value = Table(
    "indicator_value", metadata,
    Column("id", String, primary_key=True),
    Column("list_id", String, nullable=False),
    Column("list_version", Integer, nullable=False),
    Column("kind", String, nullable=False),
    Column("value", String, nullable=False),
    Column("label", String, nullable=False),
    Column("attack", JSON, nullable=False),
    Column("lane", String, nullable=False),
    Column("severity", String, nullable=False),
    Column("expires_at", DateTime(timezone=True)),
    ForeignKeyConstraint(
        ["list_id", "list_version"], ["indicator_list.id", "indicator_list.version"],
        ondelete="CASCADE",
    ),
)
Index("ix_indicator_value_lookup", indicator_value.c.kind, indicator_value.c.value,
      indicator_value.c.list_id, indicator_value.c.list_version)
Index("ix_indicator_value_version", indicator_value.c.list_id, indicator_value.c.list_version,
      indicator_value.c.kind, indicator_value.c.value)

sigma_rule = Table(
    "sigma_rule", metadata,
    Column("id", String, primary_key=True),
    Column("rule_id", String, nullable=False),
    Column("upstream", String, nullable=False),
    Column("upstream_commit", String, nullable=False),
    Column("upstream_path", String, nullable=False),
    Column("title", String, nullable=False),
    Column("author", String, nullable=False),
    Column("level", String, nullable=False),
    Column("sigma_status", String, nullable=False),
    Column("tags", JSON, nullable=False),
    Column("ast", JSON, nullable=False),
    Column("mapping", JSON, nullable=False),
    Column("digest", String, nullable=False),
    Column("status", String, nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("created_by", String, nullable=False),
    Column("activated_at", DateTime(timezone=True)),
    Column("lane", String, nullable=False, default="lead", server_default="lead"),
    Column("activation_reason", String, nullable=False, default="", server_default=""),
    CheckConstraint("status IN ('draft','reference-only','active','retired')", name="ck_sigma_rule_status"),
)


def upgrade():
    connection = op.get_bind()
    # Explicit BEGIN keeps SQLite DDL inside the caller's rehearsal transaction.
    if connection.dialect.name == 'sqlite' and not connection.connection.driver_connection.in_transaction:
        connection.exec_driver_sql('BEGIN')
    for table in (indicator_list, indicator_value, sigma_rule):
        table.create(connection)


def downgrade():
    connection = op.get_bind()
    if connection.dialect.name == 'sqlite' and not connection.connection.driver_connection.in_transaction:
        connection.exec_driver_sql('BEGIN')
    for table in (sigma_rule, indicator_value, indicator_list):
        table.drop(connection)
