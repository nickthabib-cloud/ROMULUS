"""Indexes and trigger-kept lookups that let a hunt be deleted in short batches whose cost does not grow with other
hunts' data: which rows cite each raw copy, which hunts' investigation steps and expansion links cite each event another
hunt owns, and an index led by every column deletion selects by or SQLite checks a foreign key on.

Revision ID: 0051
Revises: 0050
"""
from alembic import op

revision = "0051"
down_revision = "0050"
branch_labels = None
depends_on = None

INDEXES = {
    "ix_audit_event_hunt": ("audit_event", "hunt_id"),
    "ix_hunt_parent": ("hunt", "parent_hunt_id"),
    "ix_case_hunt": ('"case"', "hunt_id"),
    "ix_entity_hunt": ("entity", "hunt_id"),
    "ix_normalization_error_hunt": ("normalization_error", "hunt_id"),
    "ix_source_profile_hunt": ("source_profile", "hunt_id"),
    "ix_expansion_link_hunt": ("expansion_link", "hunt_id"),
    "ix_raw_record_first_task": ("raw_record", "first_task_id"),
    "ix_expansion_anchor_candidate": ("expansion_anchor", "candidate_id"),
    "ix_zeek_link_budget_anchor": ("zeek_link_budget", "anchor_id"),
    "ix_model_call_session": ("model_call", "session_id"),
    "ix_candidate_agent_hypothesis": ("candidate", "agent_hypothesis_id"),
    "ix_agent_hypothesis_event_session": ("agent_hypothesis_event", "session_id"),
    "ix_agent_tool_call_model_call": ("agent_tool_call", "model_call_id"),
    "ix_agent_link_hypothesis": ("agent_link", "hypothesis_id"),
    "ix_agent_link_session": ("agent_link", "session_id"),
    "ix_agent_note_session": ("agent_note", "session_id"),
    "ix_agent_rule_request_hypothesis": ("agent_rule_request", "hypothesis_id"),
    "ix_agent_rule_request_session": ("agent_rule_request", "session_id"),
    "ix_candidate_event_event": ("candidate_event", "event_id, hunt_id"),
}

_CASE_STEP_BODY = """ON case_step BEGIN
        INSERT OR IGNORE INTO event_step_ref(hunt_id,event_id)
        SELECT c.hunt_id,e.id FROM "case" c, json_tree(NEW.decision) j JOIN typed_event e ON e.id=j.value
        WHERE c.id=NEW.case_id AND j.type='text' AND e.hunt_id!=c.hunt_id;
        INSERT OR IGNORE INTO event_step_ref(hunt_id,event_id)
        SELECT c.hunt_id,e.id FROM "case" c, json_tree(coalesce(NEW.result_digest,'null')) j
        JOIN typed_event e ON e.id=j.value
        WHERE c.id=NEW.case_id AND j.type='text' AND e.hunt_id!=c.hunt_id; END"""
_LINK_BODY = """ON expansion_link BEGIN
        INSERT OR IGNORE INTO event_step_ref(hunt_id,event_id)
        SELECT NEW.hunt_id,e.id FROM json_each(NEW.event_ids) j JOIN typed_event e ON e.id=j.value
        WHERE e.hunt_id!=NEW.hunt_id;
        INSERT OR IGNORE INTO event_step_ref(hunt_id,event_id)
        SELECT NEW.hunt_id,e.id FROM json_each(NEW.evidence_ids) j JOIN typed_event e ON e.id=j.value
        WHERE e.hunt_id!=NEW.hunt_id; END"""

TRIGGERS = {
    "event_raw_ref_insert": """AFTER INSERT ON typed_event BEGIN
        INSERT OR IGNORE INTO event_raw_ref(raw_id,event_id,holder)
        SELECT value,NEW.id,'' FROM json_each(NEW.raw_ids); END""",
    "event_raw_ref_update": """AFTER UPDATE OF raw_ids,id ON typed_event
        WHEN OLD.raw_ids IS NOT NEW.raw_ids OR OLD.id IS NOT NEW.id BEGIN
        DELETE FROM event_raw_ref WHERE event_id=OLD.id AND holder='';
        INSERT OR IGNORE INTO event_raw_ref(raw_id,event_id,holder)
        SELECT value,NEW.id,'' FROM json_each(NEW.raw_ids); END""",
    "event_raw_ref_delete": """BEFORE DELETE ON typed_event BEGIN
        DELETE FROM event_raw_ref WHERE event_id=OLD.id AND holder=''; END""",
    "citation_raw_ref_insert": """AFTER INSERT ON event_citation BEGIN
        INSERT OR IGNORE INTO event_raw_ref(raw_id,event_id,holder)
        SELECT value,NEW.event_id,NEW.hunt_id FROM json_each(NEW.raw_ids); END""",
    "citation_raw_ref_update": """AFTER UPDATE OF raw_ids,event_id,hunt_id ON event_citation
        WHEN OLD.raw_ids IS NOT NEW.raw_ids OR OLD.event_id IS NOT NEW.event_id OR OLD.hunt_id IS NOT NEW.hunt_id BEGIN
        DELETE FROM event_raw_ref WHERE event_id=OLD.event_id AND holder=OLD.hunt_id;
        INSERT OR IGNORE INTO event_raw_ref(raw_id,event_id,holder)
        SELECT value,NEW.event_id,NEW.hunt_id FROM json_each(NEW.raw_ids); END""",
    "citation_raw_ref_delete": """BEFORE DELETE ON event_citation BEGIN
        DELETE FROM event_raw_ref WHERE event_id=OLD.event_id AND holder=OLD.hunt_id; END""",
    "case_step_observe_insert": "AFTER INSERT\n        " + _CASE_STEP_BODY,
    "case_step_observe_update": "AFTER UPDATE OF decision,result_digest\n        " + _CASE_STEP_BODY,
    "expansion_link_observe_insert": "AFTER INSERT\n        " + _LINK_BODY,
    "expansion_link_observe_update": "AFTER UPDATE OF event_ids,evidence_ids\n        " + _LINK_BODY,
}


def upgrade() -> None:
    c = op.get_bind()
    if not c.connection.driver_connection.in_transaction:
        c.exec_driver_sql("BEGIN")
    c.exec_driver_sql("""CREATE TABLE event_raw_ref (
        raw_id VARCHAR NOT NULL, event_id VARCHAR NOT NULL, holder VARCHAR NOT NULL,
        PRIMARY KEY (raw_id, event_id, holder))""")
    c.exec_driver_sql("CREATE INDEX ix_event_raw_ref_event ON event_raw_ref(event_id, holder)")
    c.exec_driver_sql("INSERT OR IGNORE INTO event_raw_ref(raw_id,event_id,holder) "
                      "SELECT j.value,e.id,'' FROM typed_event e, json_each(e.raw_ids) j")
    c.exec_driver_sql("INSERT OR IGNORE INTO event_raw_ref(raw_id,event_id,holder) "
                      "SELECT j.value,c.event_id,c.hunt_id FROM event_citation c, json_each(c.raw_ids) j")
    c.exec_driver_sql("""CREATE TABLE event_step_ref (
        event_id VARCHAR NOT NULL, hunt_id VARCHAR NOT NULL, PRIMARY KEY (event_id, hunt_id))""")
    c.exec_driver_sql("CREATE INDEX ix_event_step_ref_hunt ON event_step_ref(hunt_id)")
    # every citation an investigation step or expansion link already holds
    for column in ("decision", "result_digest"):
        c.exec_driver_sql(
            "INSERT OR IGNORE INTO event_step_ref(hunt_id,event_id) "
            f"SELECT DISTINCT c.hunt_id,e.id FROM case_step s JOIN \"case\" c ON c.id=s.case_id, "
            f"json_tree(coalesce(s.{column},'null')) j JOIN typed_event e ON e.id=j.value "
            "WHERE j.type='text' AND e.hunt_id!=c.hunt_id")
    for column in ("event_ids", "evidence_ids"):
        c.exec_driver_sql(
            "INSERT OR IGNORE INTO event_step_ref(hunt_id,event_id) "
            f"SELECT DISTINCT l.hunt_id,e.id FROM expansion_link l, json_each(l.{column}) j "
            "JOIN typed_event e ON e.id=j.value WHERE e.hunt_id!=l.hunt_id")
    for name, (table, columns) in INDEXES.items():
        c.exec_driver_sql(f"CREATE INDEX {name} ON {table}({columns})")
    for name, body in TRIGGERS.items():
        c.exec_driver_sql(f"CREATE TRIGGER {name} {body}")


def downgrade() -> None:
    c = op.get_bind()
    if not c.connection.driver_connection.in_transaction:
        c.exec_driver_sql("BEGIN")
    for name in TRIGGERS:
        c.exec_driver_sql(f"DROP TRIGGER {name}")
    for name in INDEXES:
        c.exec_driver_sql(f"DROP INDEX {name}")
    c.exec_driver_sql("DROP TABLE event_step_ref")
    c.exec_driver_sql("DROP TABLE event_raw_ref")
