"""Stage indicator imports without blocking live hunt writes."""
from alembic import op
from sqlalchemy import Column, String, text

revision = '0033'
down_revision = '0032'
branch_labels = None
depends_on = None


def _begin():
    connection = op.get_bind()
    if connection.dialect.name == 'sqlite' and not connection.connection.driver_connection.in_transaction:
        connection.exec_driver_sql('BEGIN')
    return connection


def _change(upgrading):
    connection = _begin()
    guarded = connection.dialect.name == 'sqlite' and connection.exec_driver_sql('PRAGMA foreign_keys').scalar()
    if guarded:
        # Direct Alembic callers can already have a transaction open, so preserve CASCADE children while
        # replacing their parent. The application's migration entry point disables enforcement beforehand.
        deferred = connection.exec_driver_sql('PRAGMA defer_foreign_keys').scalar()
        connection.exec_driver_sql('PRAGMA defer_foreign_keys=ON')
        connection.exec_driver_sql('CREATE TEMP TABLE indicator_value_0033 AS SELECT * FROM indicator_value')
    with op.batch_alter_table('indicator_list') as batch:
        batch.drop_constraint('ck_indicator_list_status', type_='check')
        if upgrading:
            batch.create_check_constraint('ck_indicator_list_status', "status IN ('importing','active','expired','retired')")
            batch.add_column(Column('lane', String, nullable=False, server_default='lead'))
            batch.add_column(Column('severity', String, nullable=False, server_default='medium'))
        else:
            batch.create_check_constraint('ck_indicator_list_status', "status IN ('active','expired','retired')")
            batch.drop_column('lane')
            batch.drop_column('severity')
    if guarded:
        connection.exec_driver_sql('INSERT INTO indicator_value SELECT * FROM indicator_value_0033')
        connection.exec_driver_sql('DROP TABLE indicator_value_0033')
        if connection.exec_driver_sql('PRAGMA foreign_key_check').first() is not None:
            raise RuntimeError('Indicator staging migration left invalid foreign-key references')
        if not deferred:
            connection.exec_driver_sql('PRAGMA defer_foreign_keys=OFF')


def upgrade():
    _change(True)


def downgrade():
    connection = _begin()
    if connection.execute(text("SELECT 1 FROM indicator_list WHERE status = 'importing' LIMIT 1")).first():
        raise RuntimeError('Cannot downgrade while an indicator import is staged')
    _change(False)
