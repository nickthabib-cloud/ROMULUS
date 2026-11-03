"""Paged fleet host membership, separate from bounded candidate JSON."""
import sqlalchemy as sa
from alembic import op

revision = "0027"
down_revision = "0026"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "candidate_host",
        sa.Column("candidate_id", sa.String(), nullable=False),
        sa.Column("host", sa.String(), nullable=False),
        sa.Column("first_event_id", sa.String(), nullable=False),
        sa.ForeignKeyConstraint(["candidate_id"], ["candidate.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("candidate_id", "host"),
        sqlite_with_rowid=False,
    )


def downgrade():
    op.drop_table("candidate_host")
