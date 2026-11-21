"""The mention pool: mentions the deterministic sweep found in unparsed text, their coverage, and which raw records
the sweep kept as their citations."""
import sqlalchemy as sa
from alembic import op

revision = "0047"
down_revision = "0046"
branch_labels = None
depends_on = None


def _begin():
    connection = op.get_bind()
    if connection.dialect.name == "sqlite" and not connection.connection.driver_connection.in_transaction:
        connection.exec_driver_sql("BEGIN")
    return connection


def upgrade():
    _begin()
    op.add_column("agent_raw_record", sa.Column("origin", sa.String(), nullable=False, server_default="agent"))
    op.create_index("ix_agent_raw_record_origin", "agent_raw_record", ["hunt_id", "origin"])
    op.create_table(
        "mention",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("hunt_id", sa.String(), sa.ForeignKey("hunt.id"), nullable=False),
        sa.Column("rank", sa.Integer(), nullable=False),
        sa.Column("pattern_id", sa.String(), nullable=False),
        sa.Column("pattern_title", sa.String(), nullable=False),
        sa.Column("strength", sa.String(), nullable=False),
        sa.Column("pattern_attack", sa.JSON(), nullable=False),
        sa.Column("pattern_source", sa.JSON(), nullable=False),
        sa.Column("also_matched", sa.JSON(), nullable=False),
        sa.Column("telemetry", sa.String(), nullable=False),
        sa.Column("telemetry_fit", sa.Boolean(), nullable=False),
        sa.Column("host", sa.String(), nullable=False),
        sa.Column("target", sa.String(), nullable=False),
        sa.Column("native_id", sa.String(), nullable=False),
        sa.Column("raw_id", sa.String(), nullable=False),
        sa.Column("first_ts", sa.DateTime(timezone=True)),
        sa.Column("last_ts", sa.DateTime(timezone=True)),
        sa.Column("count", sa.Integer(), nullable=False),
        sa.Column("pattern_hosts", sa.Integer(), nullable=False),
        sa.Column("pattern_lines", sa.Integer(), nullable=False),
        sa.Column("line", sa.Text(), nullable=False),
        sa.Column("line_chars", sa.Integer(), nullable=False),
        sa.Column("line_cut", sa.Boolean(), nullable=False),
        sa.Column("suspicious_content", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("strength IN ('strong','medium','weak')", name="ck_mention_strength"),
        sa.UniqueConstraint("hunt_id", "rank", name="uq_mention_rank"),
    )
    op.create_table(
        "mention_scan",
        sa.Column("hunt_id", sa.String(), sa.ForeignKey("hunt.id"), primary_key=True),
        sa.Column("summary", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )


def downgrade():
    connection = _begin()
    op.drop_table("mention_scan")
    op.drop_table("mention")
    # the sweep's raw records exist only as mention citations
    connection.exec_driver_sql("DELETE FROM agent_raw_record WHERE origin = 'mention_sweep'")
    op.drop_index("ix_agent_raw_record_origin", table_name="agent_raw_record")
    with op.batch_alter_table("agent_raw_record") as batch:
        batch.drop_column("origin")
