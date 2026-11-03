"""Immutable, streamed host appendices referenced by report manifests."""
import sqlalchemy as sa
from alembic import op

revision = "0028"
down_revision = "0027"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "report_host",
        sa.Column("hunt_id", sa.String(), nullable=False),
        sa.Column("snapshot", sa.String(), nullable=False),
        sa.Column("host", sa.String(), nullable=False),
        sa.Column("first_event_id", sa.String(), nullable=False),
        sa.ForeignKeyConstraint(["hunt_id"], ["hunt.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("hunt_id", "snapshot", "host"),
        sqlite_with_rowid=False,
    )


def downgrade():
    op.drop_table("report_host")
