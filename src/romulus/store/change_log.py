"""SQLite statements that keep citation lookup and stream delivery transactional."""

INDEX_TRIGGERS = {
    "candidate_event_insert": """AFTER INSERT ON candidate BEGIN
        INSERT OR IGNORE INTO candidate_event(hunt_id,candidate_id,event_id)
        SELECT NEW.hunt_id,NEW.id,value FROM json_each(NEW.event_ids); END""",
    "candidate_event_update": """AFTER UPDATE OF event_ids,hunt_id ON candidate
        WHEN OLD.event_ids IS NOT NEW.event_ids OR OLD.hunt_id IS NOT NEW.hunt_id BEGIN
        DELETE FROM candidate_event WHERE candidate_id=OLD.id;
        INSERT OR IGNORE INTO candidate_event(hunt_id,candidate_id,event_id)
        SELECT NEW.hunt_id,NEW.id,value FROM json_each(NEW.event_ids); END""",
    "candidate_event_delete": """BEFORE DELETE ON candidate BEGIN
        DELETE FROM candidate_event WHERE candidate_id=OLD.id; END""",
}

# Explicit fields keep lease fences (UPDATE x SET x=x) from generating duplicate
# notifications, while every actual mutation remains visible in commit order.
CHANGE_COLUMNS = {
    "agent_run": ("run", "hunt_id", "hunt_id state reason prompt_digests provider lease_owner lease_until started_at ended_at updated_at"),
    "agent_hypothesis": ("hypothesis", "id", "id hunt_id statement techniques entity_ids status confidence questions created_session_id sessions_run created_at updated_at"),
    "agent_session": ("session", "id", "id hunt_id hypothesis_id purpose state tool_calls summary started_at ended_at"),
    "agent_tool_call": ("tool_call", "id", "id hunt_id session_id seq name arguments arguments_truncated status result_digest model_call_id created_at"),
    "candidate": ("finding", "id", "id hunt_id created_at rule_id rule_version claim claim_type event_ids context_event_ids predicate_fields entities ts severity confidence lane priority priority_reasons gate_results benign_alternatives next_checks group_key source_case_id source_anchor_id source_link_id provenance agent_hypothesis_id"),
}


def trigger_statements():
    statements = {name: f"CREATE TRIGGER {name} {body}" for name, body in INDEX_TRIGGERS.items()}
    for table, (kind, key, columns) in CHANGE_COLUMNS.items():
        body = ("BEGIN INSERT INTO agent_change(hunt_id,kind,row_id) "
                f"VALUES(NEW.hunt_id,'{kind}',NEW.{key}); END")
        for action in ("insert", "update"):
            name = f"agent_change_{table}_{action}"
            when = ""
            if action == "update":
                when = " WHEN " + " OR ".join(f"OLD.{col} IS NOT NEW.{col}" for col in columns.split())
            statements[name] = f"CREATE TRIGGER {name} AFTER {action.upper()} ON {table}{when} {body}"
    statements["agent_change_no_update"] = (
        "CREATE TRIGGER agent_change_no_update BEFORE UPDATE ON agent_change "
        "BEGIN SELECT RAISE(ABORT,'agent change history is append-only'); END")
    statements["agent_change_no_replace"] = (
        "CREATE TRIGGER agent_change_no_replace BEFORE INSERT ON agent_change "
        "WHEN EXISTS(SELECT 1 FROM agent_change WHERE seq=NEW.seq) "
        "BEGIN SELECT RAISE(ABORT,'agent change history is append-only'); END")
    return statements
