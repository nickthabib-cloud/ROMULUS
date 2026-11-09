"""Persist the hypothesis-driven AI investigation and its report outputs."""
from alembic import op
from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    MetaData,
    String,
    Table,
    Text,
    UniqueConstraint,
)

revision = "0035"
down_revision = "0034"
branch_labels = None
depends_on = None

metadata = MetaData()
Table("hunt", metadata, Column("id", String, primary_key=True))
Table("model_call", metadata, Column("id", String, primary_key=True))


def _begin():
    connection = op.get_bind()
    if connection.dialect.name == "sqlite" and not connection.connection.driver_connection.in_transaction:
        connection.exec_driver_sql("BEGIN")
    return connection


def _table(connection, name, *columns, constraints=()):
    table = Table(name, metadata, *columns, *constraints)
    table.create(connection)
    connection.exec_driver_sql(f"CREATE INDEX ix_{name}_hunt_id ON {name} (hunt_id)")


def _change_candidate(connection, *, downgrade):
    guarded = connection.dialect.name == "sqlite" and connection.exec_driver_sql("PRAGMA foreign_keys").scalar()
    if guarded:
        # Direct Alembic callers can have FK enforcement enabled. Rebuilding candidate fires ON DELETE CASCADE
        # on these children, so preserve them across the swap and defer the remaining candidate references.
        if not connection.connection.driver_connection.in_transaction:
            connection.exec_driver_sql("BEGIN")
        deferred = connection.exec_driver_sql("PRAGMA defer_foreign_keys").scalar()
        connection.exec_driver_sql("PRAGMA defer_foreign_keys=ON")
        for table in ("candidate_host", "zeek_link_budget"):
            connection.exec_driver_sql(f"CREATE TEMP TABLE agent_candidate_{table} AS SELECT * FROM {table}")
    with op.batch_alter_table("candidate", recreate="always") as batch:
        if downgrade:
            batch.drop_constraint("ck_candidate_provenance", type_="check")
            batch.drop_column("agent_hypothesis_id")
            batch.drop_column("provenance")
        else:
            batch.add_column(Column("provenance", String, nullable=False, server_default="deterministic"))
            batch.add_column(Column("agent_hypothesis_id", String,
                                    ForeignKey("agent_hypothesis.id", name="fk_candidate_agent_hypothesis")))
            batch.create_check_constraint("ck_candidate_provenance", "provenance IN ('deterministic','agent')")
    if guarded:
        for table in ("candidate_host", "zeek_link_budget"):
            connection.exec_driver_sql(f"INSERT INTO {table} SELECT * FROM agent_candidate_{table}")
            connection.exec_driver_sql(f"DROP TABLE agent_candidate_{table}")
        if connection.exec_driver_sql("PRAGMA foreign_key_check").first() is not None:
            raise RuntimeError("Agent migration left invalid foreign-key references")
        if not deferred:
            connection.exec_driver_sql("PRAGMA defer_foreign_keys=OFF")


def upgrade():
    connection = _begin()
    _table(connection, "agent_run",
           Column("hunt_id", String, ForeignKey("hunt.id"), primary_key=True),
           Column("state", String, nullable=False), Column("reason", Text),
           Column("prompt_digests", JSON, nullable=False), Column("provider", JSON, nullable=False),
           Column("lease_owner", String), Column("lease_until", DateTime(timezone=True)),
           Column("started_at", DateTime(timezone=True)), Column("ended_at", DateTime(timezone=True)),
           Column("updated_at", DateTime(timezone=True), nullable=False),
           constraints=(CheckConstraint("state IN ('pending','running','completed','partial','failed','skipped')",
                                        name="ck_agent_run_state"),))
    _table(connection, "agent_hypothesis",
           Column("id", String, primary_key=True), Column("hunt_id", String, ForeignKey("hunt.id"), nullable=False),
           Column("statement", Text, nullable=False), Column("techniques", JSON, nullable=False),
           Column("entity_ids", JSON, nullable=False), Column("status", String, nullable=False),
           Column("confidence", String, nullable=False), Column("questions", JSON, nullable=False),
           Column("created_session_id", String), Column("sessions_run", Integer, nullable=False, server_default="0"),
           Column("created_at", DateTime(timezone=True), nullable=False),
           Column("updated_at", DateTime(timezone=True), nullable=False),
           constraints=(CheckConstraint("length(statement) BETWEEN 1 AND 600",
                                        name="ck_agent_hypothesis_statement"),
                        CheckConstraint("status IN ('open','supported','weakened','refuted','abandoned')",
                                        name="ck_agent_hypothesis_status"),
                        CheckConstraint("confidence IN ('low','medium','high')",
                                        name="ck_agent_hypothesis_confidence")))
    connection.exec_driver_sql(
        "CREATE INDEX ix_agent_hypothesis_hunt_status ON agent_hypothesis (hunt_id, status)")
    _table(connection, "agent_session",
           Column("id", String, primary_key=True), Column("hunt_id", String, ForeignKey("hunt.id"), nullable=False),
           Column("hypothesis_id", String, ForeignKey("agent_hypothesis.id")),
           Column("purpose", String, nullable=False), Column("state", String, nullable=False),
           Column("tool_calls", Integer, nullable=False, server_default="0"),
           Column("summary", Text, nullable=False, server_default=""),
           Column("started_at", DateTime(timezone=True), nullable=False),
           Column("ended_at", DateTime(timezone=True)),
           constraints=(CheckConstraint("purpose IN ('orient','investigate','assess')",
                                        name="ck_agent_session_purpose"),
                        CheckConstraint("state IN ('running','finished','capped','context_full','refused','failed','interrupted','budget')",
                                        name="ck_agent_session_state"),
                        CheckConstraint("length(summary) <= 2000", name="ck_agent_session_summary")))
    connection.exec_driver_sql(
        "CREATE INDEX ix_agent_session_hypothesis ON agent_session (hypothesis_id, started_at)")

    # SQLite can add a nullable FK column without rebuilding the populated call ledger.
    with op.batch_alter_table("model_call") as batch:
        batch.add_column(Column("session_id", String, ForeignKey("agent_session.id", name="fk_model_call_session")))
    _change_candidate(connection, downgrade=False)

    # SQLite rebuilds this table for its CHECK change. Alembic's batch copy preserves the rows and index.
    with op.batch_alter_table("agent_alias", recreate="always") as batch:
        batch.drop_constraint("ck_agent_alias_kind", type_="check")
        batch.create_check_constraint("ck_agent_alias_kind", "kind IN ('F','I','E','N','L','H','A')")

    _table(connection, "agent_hypothesis_event",
           Column("id", String, primary_key=True), Column("hunt_id", String, ForeignKey("hunt.id"), nullable=False),
           Column("hypothesis_id", String, ForeignKey("agent_hypothesis.id"), nullable=False),
           Column("session_id", String, ForeignKey("agent_session.id")),
           Column("kind", String, nullable=False), Column("payload", JSON, nullable=False),
           Column("created_at", DateTime(timezone=True), nullable=False),
           constraints=(CheckConstraint("kind IN ('opened','updated','support_added','contradiction_added','note')",
                                        name="ck_agent_hypothesis_event_kind"),))
    connection.exec_driver_sql(
        "CREATE INDEX ix_agent_hypothesis_event_history ON agent_hypothesis_event "
        "(hypothesis_id, created_at, id)")
    _table(connection, "agent_hypothesis_cite",
           Column("hunt_id", String, ForeignKey("hunt.id"), nullable=False),
           Column("hypothesis_id", String, ForeignKey("agent_hypothesis.id"), nullable=False),
           Column("role", String, nullable=False), Column("target_kind", String, nullable=False),
           Column("target_id", String, nullable=False),
           constraints=(CheckConstraint("role IN ('support','contradiction')",
                                        name="ck_agent_hypothesis_cite_role"),
                        CheckConstraint("target_kind IN ('finding','evidence','link','agent_link')",
                                        name="ck_agent_hypothesis_cite_target_kind"),
                        UniqueConstraint("hypothesis_id", "role", "target_kind", "target_id",
                                         name="uq_agent_hypothesis_cite")))
    _table(connection, "agent_tool_call",
           Column("id", String, primary_key=True), Column("hunt_id", String, ForeignKey("hunt.id"), nullable=False),
           Column("session_id", String, ForeignKey("agent_session.id"), nullable=False),
           Column("seq", Integer, nullable=False), Column("name", String, nullable=False),
           Column("arguments", JSON, nullable=False), Column("arguments_truncated", Boolean, nullable=False,
                                                             server_default="0"),
           Column("status", String, nullable=False), Column("result_digest", String, nullable=False),
           Column("model_call_id", String, ForeignKey("model_call.id")),
           Column("created_at", DateTime(timezone=True), nullable=False),
           constraints=(UniqueConstraint("session_id", "seq", name="uq_agent_tool_call_seq"),))
    _table(connection, "agent_link",
           Column("id", String, primary_key=True), Column("hunt_id", String, ForeignKey("hunt.id"), nullable=False),
           Column("session_id", String, ForeignKey("agent_session.id"), nullable=False),
           Column("hypothesis_id", String, ForeignKey("agent_hypothesis.id")),
           Column("from_kind", String, nullable=False), Column("from_id", String, nullable=False),
           Column("to_kind", String, nullable=False), Column("to_id", String, nullable=False),
           Column("relation", String, nullable=False), Column("cites", JSON, nullable=False),
           Column("rationale", Text, nullable=False), Column("created_at", DateTime(timezone=True), nullable=False))
    _table(connection, "agent_note",
           Column("id", String, primary_key=True), Column("hunt_id", String, ForeignKey("hunt.id"), nullable=False),
           Column("session_id", String, ForeignKey("agent_session.id"), nullable=False),
           Column("target_kind", String, nullable=False), Column("target_id", String, nullable=False),
           Column("text", Text, nullable=False), Column("cites", JSON, nullable=False),
           Column("suspicious_content", Boolean, nullable=False, server_default="0"),
           Column("created_at", DateTime(timezone=True), nullable=False))
    connection.exec_driver_sql(
        "CREATE INDEX ix_agent_note_target ON agent_note (hunt_id, target_kind, target_id)")
    _table(connection, "agent_rule_request",
           Column("id", String, primary_key=True), Column("hunt_id", String, ForeignKey("hunt.id"), nullable=False),
           Column("session_id", String, ForeignKey("agent_session.id"), nullable=False),
           Column("hypothesis_id", String, ForeignKey("agent_hypothesis.id")),
           Column("pattern_description", Text, nullable=False), Column("cites", JSON, nullable=False),
           Column("created_at", DateTime(timezone=True), nullable=False))
    _table(connection, "agent_assessment",
           Column("id", String, primary_key=True), Column("hunt_id", String, ForeignKey("hunt.id"), nullable=False),
           Column("revision", Integer, nullable=False), Column("source", String, nullable=False),
           Column("model", JSON, nullable=False), Column("body", JSON, nullable=False),
           Column("checker", JSON, nullable=False), Column("created_at", DateTime(timezone=True), nullable=False),
           constraints=(CheckConstraint("source IN ('agent','template')", name="ck_agent_assessment_source"),
                        UniqueConstraint("hunt_id", "revision", name="uq_agent_assessment_revision")))

    connection.exec_driver_sql("""CREATE TRIGGER agent_hypothesis_event_no_replace BEFORE INSERT ON agent_hypothesis_event
        WHEN EXISTS(SELECT 1 FROM agent_hypothesis_event WHERE id=NEW.id)
        BEGIN SELECT RAISE(ABORT,'agent hypothesis history is append-only'); END""")
    connection.exec_driver_sql("""CREATE TRIGGER agent_hypothesis_event_no_update
        BEFORE UPDATE ON agent_hypothesis_event
        BEGIN SELECT RAISE(ABORT,'agent hypothesis history is append-only'); END""")
    # Whole-hunt deletion removes history child-first; replacement and mutation remain forbidden.


def downgrade():
    connection = _begin()
    for name in ("agent_hypothesis_event_no_replace", "agent_hypothesis_event_no_update"):
        connection.exec_driver_sql(f"DROP TRIGGER {name}")
    for name in ("agent_assessment", "agent_rule_request", "agent_note", "agent_link", "agent_tool_call",
                 "agent_hypothesis_cite", "agent_hypothesis_event"):
        op.drop_table(name)
    # H/A aliases have no meaning in the pre-0035 schema and cannot satisfy its narrower CHECK.
    connection.exec_driver_sql("DELETE FROM agent_alias WHERE kind IN ('H','A')")
    with op.batch_alter_table("agent_alias", recreate="always") as batch:
        batch.drop_constraint("ck_agent_alias_kind", type_="check")
        batch.create_check_constraint("ck_agent_alias_kind", "kind IN ('F','I','E','N','L')")
        batch.drop_index("ix_agent_alias_hunt_kind")
    op.create_index("ix_agent_alias_hunt_kind", "agent_alias", ["hunt_id", "kind"])
    # AI findings must never reappear as deterministic findings after provenance is removed.
    agent_candidates = "SELECT id FROM candidate WHERE provenance='agent'"
    for table, column in (("disposition_event", "candidate_id"), ("expansion_link", "anchor_id"),
                          ("expansion_anchor", "candidate_id"), ("candidate_host", "candidate_id"),
                          ("zeek_link_budget", "anchor_id")):
        connection.exec_driver_sql(f"DELETE FROM {table} WHERE {column} IN ({agent_candidates})")
    connection.exec_driver_sql(f"DELETE FROM agent_alias WHERE kind='F' AND target_id IN ({agent_candidates})")
    connection.exec_driver_sql("DELETE FROM candidate WHERE provenance='agent'")
    _change_candidate(connection, downgrade=True)
    with op.batch_alter_table("model_call") as batch:
        batch.drop_column("session_id")
    for name in ("agent_session", "agent_hypothesis", "agent_run"):
        op.drop_table(name)
