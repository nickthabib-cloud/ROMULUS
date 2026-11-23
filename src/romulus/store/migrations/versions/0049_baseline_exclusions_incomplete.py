"""Hours whose finding-associated exclusions are not all known: one row per hunt, target and baseline spec while the
hunt has not finished the stages whose findings cite records. A frozen snapshot flags its member segments over such
hours, so a key seen only there is judged unresolved rather than common."""
import sqlalchemy as sa
from alembic import op

revision = "0049"
down_revision = "0048"
branch_labels = None
depends_on = None


def _begin():
    connection = op.get_bind()
    if connection.dialect.name == "sqlite" and not connection.connection.driver_connection.in_transaction:
        connection.exec_driver_sql("BEGIN")
    return connection


def upgrade() -> None:
    _begin()
    op.create_table(
        "baseline_exclusions_incomplete",
        sa.Column("hunt_id", sa.String(), nullable=False),
        sa.Column("site", sa.String(), nullable=False),
        sa.Column("target", sa.String(), nullable=False),
        sa.Column("spec_id", sa.String(), nullable=False),
        sa.Column("spec_version", sa.String(), nullable=False),
        sa.Column("key_version", sa.String(), nullable=False),
        sa.Column("start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("end", sa.DateTime(timezone=True), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("marked_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("end > start", name="ck_baseline_exclusions_incomplete_span"),
        sa.PrimaryKeyConstraint("hunt_id", "target", "spec_id", name="pk_baseline_exclusions_incomplete"),
    )
    op.create_index(
        "ix_baseline_exclusions_incomplete_overlap", "baseline_exclusions_incomplete",
        ["site", "target", "spec_id", "spec_version", "key_version", "start", "end"], unique=False,
    )
    op.add_column("baseline_snapshot_segment", sa.Column(
        "exclusions_incomplete", sa.Boolean(), nullable=False, server_default="0"))


def downgrade() -> None:
    _begin()
    op.execute(sa.text("ALTER TABLE baseline_snapshot_segment DROP COLUMN exclusions_incomplete"))
    op.drop_index("ix_baseline_exclusions_incomplete_overlap", table_name="baseline_exclusions_incomplete")
    op.drop_table("baseline_exclusions_incomplete")
