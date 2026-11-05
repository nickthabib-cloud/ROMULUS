"""Durable immutable sensor visibility appendices."""
import sqlalchemy as sa
from alembic import op

revision = '0030'
down_revision = '0029'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('report_zeek_visibility',
        sa.Column('hunt_id',sa.String(),nullable=False),
        sa.Column('snapshot',sa.String(),nullable=False),
        sa.Column('ordinal',sa.Integer(),nullable=False),
        sa.Column('body',sa.JSON(),nullable=False),
        sa.ForeignKeyConstraint(['hunt_id'],['hunt.id'],ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('hunt_id','snapshot','ordinal'),sqlite_with_rowid=False)


def downgrade():
    connection = op.get_bind()
    # SQLite legacy mode does not begin a real transaction for DDL. A later
    # migration may refuse the downgrade; keep this table and its rows rollbackable.
    if connection.dialect.name == 'sqlite' and not connection.connection.driver_connection.in_transaction:
        connection.exec_driver_sql('BEGIN')
    op.drop_table('report_zeek_visibility')
