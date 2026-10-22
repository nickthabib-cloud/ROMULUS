"""immutable baseline segments, hunt snapshots, and observations

Revision ID: 0010
Revises: 0009
"""
import sqlalchemy as sa
from alembic import op

revision = "0010"
down_revision = "0009"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "baseline_segment",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("site", sa.String(), nullable=False),
        sa.Column("target", sa.String(), nullable=False),
        sa.Column("spec_id", sa.String(), nullable=False),
        sa.Column("spec_version", sa.String(), nullable=False),
        sa.Column("key_version", sa.String(), nullable=False),
        sa.Column("normalizer", sa.String(), nullable=False),
        sa.Column("start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("end", sa.DateTime(timezone=True), nullable=False),
        sa.Column("bucket", sa.String(), nullable=False),
        sa.Column("origin", sa.String(), nullable=False),
        sa.Column("source_hunt_id", sa.String(), nullable=True),
        sa.Column("built_by_hunt_id", sa.String(), nullable=True),
        sa.Column("exclusion_digest", sa.String(), nullable=False),
        sa.Column("excluded_keys", sa.JSON(), nullable=False),
        sa.Column("hunted", sa.Integer(), nullable=False),
        sa.Column("events_total", sa.Integer(), nullable=False),
        sa.Column("rows_digest", sa.String(), nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("origin IN ('lookback', 'hunt')", name="ck_baseline_segment_origin"),
        sa.CheckConstraint("bucket IN ('day', 'hour')", name="ck_baseline_segment_bucket"),
        sa.CheckConstraint("status IN ('active', 'stale', 'revoked')", name="ck_baseline_segment_status"),
        sa.CheckConstraint("hunted IN (0, 1)", name="ck_baseline_segment_hunted"),
        sa.CheckConstraint("events_total >= 0", name="ck_baseline_segment_events"),
    )
    op.create_index(
        "ix_baseline_segment_cover", "baseline_segment",
        ["site", "target", "spec_id", "status", "start", "end"],
    )
    op.create_index("ix_baseline_segment_source_hunt", "baseline_segment", ["source_hunt_id"])
    op.create_index("ix_baseline_segment_built_hunt", "baseline_segment", ["built_by_hunt_id"])

    op.create_table(
        "baseline_count",
        sa.Column("segment_id", sa.String(), sa.ForeignKey("baseline_segment.id", ondelete="CASCADE"),
                  nullable=False),
        sa.Column("scope_kind", sa.String(), nullable=False),
        sa.Column("scope", sa.String(), nullable=False),
        sa.Column("key_id", sa.String(), nullable=False),
        sa.Column("key_digest", sa.String(), nullable=False),
        sa.Column("key", sa.JSON(), nullable=False),
        sa.Column("bucket", sa.DateTime(timezone=True), nullable=False),
        sa.Column("count", sa.Integer(), nullable=False),
        sa.Column("first_ts", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_ts", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("segment_id", "scope", "key_digest", "bucket", name="pk_baseline_count"),
        sa.CheckConstraint("count >= 1", name="ck_baseline_count_count"),
    )
    op.create_index("ix_baseline_count_key", "baseline_count", ["key_id", "scope_kind", "scope", "segment_id"])

    op.create_table(
        "baseline_scope_hour",
        sa.Column("segment_id", sa.String(), sa.ForeignKey("baseline_segment.id", ondelete="CASCADE"),
                  nullable=False),
        sa.Column("scope_kind", sa.String(), nullable=False),
        sa.Column("scope", sa.String(), nullable=False),
        sa.Column("hour", sa.DateTime(timezone=True), nullable=False),
        sa.Column("events", sa.Integer(), nullable=False),
        sa.PrimaryKeyConstraint("segment_id", "scope", "hour", name="pk_baseline_scope_hour"),
        sa.CheckConstraint("events >= 0", name="ck_baseline_scope_hour_events"),
    )
    op.create_index(
        "ix_baseline_scope_hour_lookup", "baseline_scope_hour", ["scope_kind", "scope", "segment_id", "hour"],
    )

    op.create_table(
        "baseline_snapshot",
        sa.Column("hunt_id", sa.String(), sa.ForeignKey("hunt.id"), primary_key=True),
        sa.Column("plan", sa.JSON(), nullable=False),
        sa.Column("store_cut", sa.JSON(), nullable=False),
        sa.Column("segment_ids", sa.JSON(), nullable=False),
        sa.Column("coverage", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("digest", sa.String(), nullable=False),
        sa.CheckConstraint(
            "status IN ('resolved', 'shortened', 'unresolved')", name="ck_baseline_snapshot_status",
        ),
    )

    op.create_table(
        "baseline_observation",
        sa.Column("hunt_id", sa.String(), sa.ForeignKey("hunt.id"), nullable=False),
        sa.Column("spec_id", sa.String(), nullable=False),
        sa.Column("spec_version", sa.String(), nullable=False),
        sa.Column("scope_kind", sa.String(), nullable=False),
        sa.Column("scope", sa.String(), nullable=False),
        sa.Column("key_id", sa.String(), nullable=False),
        sa.Column("key_digest", sa.String(), nullable=False),
        sa.Column("key", sa.JSON(), nullable=False),
        sa.Column("window_count", sa.Integer(), nullable=False),
        sa.Column("first_ts", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_ts", sa.DateTime(timezone=True), nullable=True),
        sa.Column("first_event_id", sa.String(), nullable=True),
        sa.Column("history_count", sa.Integer(), nullable=True),
        sa.Column("history_decayed", sa.Float(), nullable=True),
        sa.Column("peer_scopes_with_key", sa.Integer(), nullable=True),
        sa.Column("peer_scopes", sa.Integer(), nullable=True),
        sa.Column("threshold", sa.Float(), nullable=True),
        sa.Column("mean", sa.Float(), nullable=True),
        sa.Column("sigma", sa.Float(), nullable=True),
        sa.Column("n_hours", sa.Integer(), nullable=True),
        sa.Column("verdict", sa.String(), nullable=False),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("candidate_id", sa.String(), nullable=True),
        sa.PrimaryKeyConstraint(
            "hunt_id", "spec_id", "spec_version", "scope", "key_digest",
            name="pk_baseline_observation",
        ),
        sa.CheckConstraint("window_count >= 0", name="ck_baseline_observation_window_count"),
        sa.CheckConstraint(
            "verdict IN ('first_seen', 'rare', 'common', 'over_threshold', 'within_threshold', 'unresolved')",
            name="ck_baseline_observation_verdict",
        ),
    )
    op.create_index("ix_baseline_observation_first_event", "baseline_observation", ["first_event_id"])


def downgrade() -> None:
    op.drop_index("ix_baseline_observation_first_event", table_name="baseline_observation")
    op.drop_table("baseline_observation")
    op.drop_table("baseline_snapshot")
    op.drop_index("ix_baseline_scope_hour_lookup", table_name="baseline_scope_hour")
    op.drop_table("baseline_scope_hour")
    op.drop_index("ix_baseline_count_key", table_name="baseline_count")
    op.drop_table("baseline_count")
    op.drop_index("ix_baseline_segment_built_hunt", table_name="baseline_segment")
    op.drop_index("ix_baseline_segment_source_hunt", table_name="baseline_segment")
    op.drop_index("ix_baseline_segment_cover", table_name="baseline_segment")
    op.drop_table("baseline_segment")
