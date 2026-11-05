"""Checkpoint cumulative Zeek link limits across resumed key variants."""
import sqlalchemy as sa
from alembic import op

revision = '0031'
down_revision = '0030'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('zeek_link_budget',
        sa.Column('hunt_id', sa.String(), nullable=False),
        sa.Column('anchor_id', sa.String(), nullable=False),
        sa.Column('link_type', sa.String(), nullable=False),
        sa.Column('window_label', sa.String(), nullable=False),
        sa.Column('body', sa.JSON(), nullable=False),
        sa.ForeignKeyConstraint(['hunt_id'], ['hunt.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['anchor_id'], ['candidate.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('hunt_id', 'anchor_id', 'link_type', 'window_label'))
    # Old links omitted rejected records and intermediate hop keys. Never infer
    # remaining allowance from selected event IDs on an upgraded hunt.
    op.get_bind().execute(sa.text('''
        INSERT INTO zeek_link_budget (hunt_id, anchor_id, link_type, window_label, body)
        SELECT DISTINCT hunt_id, anchor_id, link_type, window_label,
            :body
        FROM expansion_link
        WHERE link_type IN ('zeek_uid','zeek_file','certificate','address_host')
    '''), {'body': '{"rows":10000,"queries":128,"keys":[],"legacy":true}'})


def downgrade():
    connection = op.get_bind()
    if connection.dialect.name == 'sqlite' and not connection.connection.driver_connection.in_transaction:
        connection.exec_driver_sql('BEGIN')
    op.drop_table('zeek_link_budget')
