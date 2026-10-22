"""baseline S4 snapshot membership

Revision ID: 0013
Revises: 0009
"""
import sqlalchemy as sa
from alembic import op

revision = "0013"
down_revision = "0009"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # SQLite follows the child CASCADE while Alembic recreates the checked parent table. Preserve child rows
    # explicitly on this connection, then restore them after the metadata-only parent rewrite.
    op.execute(sa.text("CREATE TEMP TABLE _baseline_count_0013 AS SELECT * FROM baseline_count"))
    op.execute(sa.text("CREATE TEMP TABLE _baseline_scope_hour_0013 AS SELECT * FROM baseline_scope_hour"))
    with op.batch_alter_table("baseline_segment", recreate="always") as batch:
        batch.drop_constraint("ck_baseline_segment_status", type_="check")
        batch.create_check_constraint(
            "ck_baseline_segment_status", "status IN ('building', 'active', 'stale', 'revoked')",
        )
    op.execute(sa.text("INSERT INTO baseline_count SELECT * FROM _baseline_count_0013"))
    op.execute(sa.text("INSERT INTO baseline_scope_hour SELECT * FROM _baseline_scope_hour_0013"))
    op.execute(sa.text("DROP TABLE _baseline_count_0013"))
    op.execute(sa.text("DROP TABLE _baseline_scope_hour_0013"))
    op.create_table(
        "baseline_snapshot_segment",
        sa.Column(
            "hunt_id", sa.String(), sa.ForeignKey("baseline_snapshot.hunt_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "segment_id", sa.String(), sa.ForeignKey("baseline_segment.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("hunt_id", "segment_id", name="pk_baseline_snapshot_segment"),
    )
    op.create_index(
        "ix_baseline_snapshot_segment_segment", "baseline_snapshot_segment", ["segment_id"],
    )
    # Existing 0009 snapshots remain authoritative. SQLite's JSON table function expands their frozen
    # membership without materializing ids in application memory.
    op.execute(sa.text(
        "INSERT INTO baseline_snapshot_segment (hunt_id, segment_id) "
        "SELECT baseline_snapshot.hunt_id, json_each.value "
        "FROM baseline_snapshot, json_each(baseline_snapshot.segment_ids)"
    ))


def downgrade() -> None:
    op.drop_index("ix_baseline_snapshot_segment_segment", table_name="baseline_snapshot_segment")
    op.drop_table("baseline_snapshot_segment")
    op.execute(sa.text("DELETE FROM baseline_segment WHERE status = 'building'"))
    op.execute(sa.text("CREATE TEMP TABLE _baseline_count_0013 AS SELECT * FROM baseline_count"))
    op.execute(sa.text("CREATE TEMP TABLE _baseline_scope_hour_0013 AS SELECT * FROM baseline_scope_hour"))
    with op.batch_alter_table("baseline_segment", recreate="always") as batch:
        batch.drop_constraint("ck_baseline_segment_status", type_="check")
        batch.create_check_constraint(
            "ck_baseline_segment_status", "status IN ('active', 'stale', 'revoked')",
        )
    op.execute(sa.text("INSERT INTO baseline_count SELECT * FROM _baseline_count_0013"))
    op.execute(sa.text("INSERT INTO baseline_scope_hour SELECT * FROM _baseline_scope_hour_0013"))
    op.execute(sa.text("DROP TABLE _baseline_count_0013"))
    op.execute(sa.text("DROP TABLE _baseline_scope_hour_0013"))
