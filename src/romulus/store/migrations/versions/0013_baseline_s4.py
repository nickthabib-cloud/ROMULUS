"""baseline S4 snapshot membership

Revision ID: 0013
Revises: 0012
"""
import sqlalchemy as sa
from alembic import op

revision = "0013"
down_revision = "0012"
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
        sa.Column("spec_id", sa.String(), nullable=False),
        sa.Column(
            "segment_id", sa.String(), sa.ForeignKey("baseline_segment.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("target", sa.String(), nullable=False),
        sa.PrimaryKeyConstraint("hunt_id", "spec_id", "segment_id", name="pk_baseline_snapshot_segment"),
    )
    op.create_index(
        "ix_baseline_snapshot_segment_segment", "baseline_snapshot_segment", ["segment_id"],
    )
    # Existing 0009 snapshots remain authoritative. SQLite's JSON table function expands their frozen
    # membership without materializing ids in application memory.
    op.execute(sa.text(
        "INSERT INTO baseline_snapshot_segment (hunt_id, spec_id, segment_id, target) "
        "SELECT baseline_snapshot.hunt_id, baseline_segment.spec_id, baseline_segment.id, baseline_segment.target "
        "FROM baseline_snapshot, json_each(baseline_snapshot.segment_ids) "
        "JOIN baseline_segment ON baseline_segment.id = json_each.value"
    ))
    op.create_table(
        "baseline_parent_host_boot",
        sa.Column("hunt_id", sa.String(), sa.ForeignKey("hunt.id", ondelete="CASCADE"), nullable=False),
        sa.Column("target", sa.String(), nullable=False),
        sa.Column("host", sa.String(), nullable=False),
        sa.Column("boot", sa.String(), nullable=False),
        sa.Column("latest_ts", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("hunt_id", "target", "host", name="pk_baseline_parent_host_boot"),
    )
    op.create_index(
        "ix_baseline_parent_host_boot_host", "baseline_parent_host_boot", ["hunt_id", "host"],
    )
    op.create_table(
        "baseline_parent_observed",
        sa.Column("hunt_id", sa.String(), sa.ForeignKey("hunt.id", ondelete="CASCADE"), nullable=False),
        sa.Column("target", sa.String(), nullable=False),
        sa.Column("start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("end", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("hunt_id", "target", "start", name="pk_baseline_parent_observed"),
        sa.CheckConstraint("end > start", name="ck_baseline_parent_observed_span"),
    )
    op.create_table(
        "baseline_parent_break",
        sa.Column("hunt_id", sa.String(), sa.ForeignKey("hunt.id", ondelete="CASCADE"), nullable=False),
        sa.Column("target", sa.String(), nullable=False),
        sa.Column("host", sa.String(), nullable=False),
        sa.Column("start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("end", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("hunt_id", "target", "host", "start", name="pk_baseline_parent_break"),
        sa.CheckConstraint("end > start", name="ck_baseline_parent_break_span"),
    )
    op.create_table(
        "baseline_parent_carry",
        sa.Column("hunt_id", sa.String(), sa.ForeignKey("hunt.id", ondelete="CASCADE"), nullable=False),
        sa.Column("target", sa.String(), nullable=False),
        sa.Column("host", sa.String(), nullable=False),
        sa.Column("boot", sa.String(), nullable=False),
        sa.Column("pid", sa.Integer(), nullable=False),
        sa.Column("exec_ts", sa.DateTime(timezone=True), nullable=False),
        sa.Column("executable", sa.String(), nullable=False),
        sa.Column("parent_pid", sa.Integer(), nullable=True),
        sa.Column("raw_id", sa.String(), nullable=False),
        sa.Column("previous_exec_ts", sa.DateTime(timezone=True), nullable=True),
        sa.Column("previous_executable", sa.String(), nullable=True),
        sa.Column("previous_parent_pid", sa.Integer(), nullable=True),
        sa.Column("previous_raw_id", sa.String(), nullable=True),
        sa.PrimaryKeyConstraint(
            "hunt_id", "target", "host", "boot", "pid", name="pk_baseline_parent_carry",
        ),
        sa.CheckConstraint("pid >= 0", name="ck_baseline_parent_carry_pid"),
        sa.CheckConstraint("executable <> ''", name="ck_baseline_parent_carry_executable"),
    )


def downgrade() -> None:
    op.drop_table("baseline_parent_carry")
    op.drop_table("baseline_parent_break")
    op.drop_table("baseline_parent_observed")
    op.drop_index("ix_baseline_parent_host_boot_host", table_name="baseline_parent_host_boot")
    op.drop_table("baseline_parent_host_boot")
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
