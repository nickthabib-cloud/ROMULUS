"""Raw records the AI agent can cite: returned rows no normalizer read, kept as bounded text with Q aliases."""
import sqlalchemy as sa
from alembic import op

revision = "0045"
down_revision = "0044"
branch_labels = None
depends_on = None


def _begin():
    connection = op.get_bind()
    if connection.dialect.name == "sqlite" and not connection.connection.driver_connection.in_transaction:
        connection.exec_driver_sql("BEGIN")
    return connection


def upgrade():
    _begin()
    op.create_table(
        "agent_raw_record",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("hunt_id", sa.String(), sa.ForeignKey("hunt.id"), nullable=False),
        sa.Column("target", sa.String(), nullable=False),
        sa.Column("native_id", sa.String(), nullable=False),
        sa.Column("source_kind", sa.String(), nullable=False),
        sa.Column("ts", sa.DateTime(timezone=True)),
        sa.Column("time_field", sa.String()),
        sa.Column("time_text", sa.String()),
        sa.Column("text", sa.Text(), nullable=False),
        sa.Column("text_cut", sa.Boolean(), nullable=False),
        sa.Column("text_bytes", sa.Integer(), nullable=False),
        sa.Column("digest", sa.String(), nullable=False),
        sa.Column("session_id", sa.String()),
        sa.Column("task_id", sa.String()),
        sa.Column("query_digest", sa.String(), nullable=False),
        sa.Column("query", sa.Text(), nullable=False),
        sa.Column("suspicious_content", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("source_kind IN ('index','arkime_session')", name="ck_agent_raw_record_source_kind"),
        sa.UniqueConstraint("hunt_id", "target", "native_id", name="uq_agent_raw_record_source"),
    )
    op.create_index("ix_agent_raw_record_hunt", "agent_raw_record", ["hunt_id", "created_at"])
    # SQLite rebuilds these tables for their CHECK changes; the batch copy keeps their rows and indexes.
    with op.batch_alter_table("agent_alias", recreate="always") as batch:
        batch.drop_constraint("ck_agent_alias_kind", type_="check")
        batch.create_check_constraint("ck_agent_alias_kind", "kind IN ('F','I','E','N','L','H','A','Q')")
    with op.batch_alter_table("agent_hypothesis_cite", recreate="always") as batch:
        batch.drop_constraint("ck_agent_hypothesis_cite_target_kind", type_="check")
        batch.create_check_constraint("ck_agent_hypothesis_cite_target_kind",
                                      "target_kind IN ('finding','evidence','link','agent_link','raw_record')")


def downgrade():
    connection = _begin()
    # Q aliases and raw-record cites have no meaning without the table and cannot satisfy the narrower CHECKs.
    connection.exec_driver_sql("DELETE FROM agent_hypothesis_cite WHERE target_kind = 'raw_record'")
    connection.exec_driver_sql("DELETE FROM agent_alias WHERE kind = 'Q'")
    with op.batch_alter_table("agent_hypothesis_cite", recreate="always") as batch:
        batch.drop_constraint("ck_agent_hypothesis_cite_target_kind", type_="check")
        batch.create_check_constraint("ck_agent_hypothesis_cite_target_kind",
                                      "target_kind IN ('finding','evidence','link','agent_link')")
    with op.batch_alter_table("agent_alias", recreate="always") as batch:
        batch.drop_constraint("ck_agent_alias_kind", type_="check")
        batch.create_check_constraint("ck_agent_alias_kind", "kind IN ('F','I','E','N','L','H','A')")
    op.drop_index("ix_agent_raw_record_hunt", table_name="agent_raw_record")
    op.drop_table("agent_raw_record")
