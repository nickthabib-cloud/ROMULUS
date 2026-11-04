"""Preserve computed positives whose observation time could not be recovered."""
import sqlalchemy as sa
from alembic import op

revision = "0029"
down_revision = "0028"
branch_labels = None
depends_on = None


def _change(nullable):
    connection = op.get_bind()
    guarded = connection.dialect.name == "sqlite" and connection.exec_driver_sql("PRAGMA foreign_keys").scalar()
    if guarded:
        # pysqlite's legacy mode does not begin a transaction for DDL; an implicit DDL commit otherwise resets
        # defer_foreign_keys before the copy. Keep the whole replacement in the caller's transaction.
        if not connection.connection.driver_connection.in_transaction:
            connection.exec_driver_sql("BEGIN")
        # Direct Alembic callers may already be in a transaction, so foreign_keys cannot be disabled.
        # Defer non-cascading references and preserve the one CASCADE child in a temporary SQL table.
        # The application migrate() path already disables foreign keys around an atomic checked transaction.
        deferred = connection.exec_driver_sql("PRAGMA defer_foreign_keys").scalar()
        connection.exec_driver_sql("PRAGMA defer_foreign_keys=ON")
        connection.exec_driver_sql("CREATE TEMP TABLE candidate_host_0029 AS SELECT * FROM candidate_host")
    for table in ("candidate", "expansion_anchor"):
        with op.batch_alter_table(table) as batch:
            batch.alter_column("ts", existing_type=sa.DateTime(timezone=True), nullable=nullable)
    if guarded:
        connection.exec_driver_sql("INSERT INTO candidate_host SELECT * FROM candidate_host_0029")
        connection.exec_driver_sql("DROP TABLE candidate_host_0029")
        if connection.exec_driver_sql("PRAGMA foreign_key_check").first() is not None:
            raise RuntimeError("Nullable-time migration left invalid foreign-key references")
        if not deferred:
            connection.exec_driver_sql("PRAGMA defer_foreign_keys=OFF")


def upgrade():
    _change(True)


def downgrade():
    connection = op.get_bind()
    for table in ("candidate", "expansion_anchor"):
        if connection.execute(sa.text(f"SELECT 1 FROM {table} WHERE ts IS NULL LIMIT 1")).first():
            raise RuntimeError("Cannot remove nullable observation times while untimed positives exist")
    _change(False)
