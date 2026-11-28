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
    # Which stored rows cite each raw copy (a stable event: holder ''; a hunt's citation overlay: holder = that hunt),
    # so deleting a hunt finds the copies nothing cites any more by index, never by scanning every event.
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
    # A hunt's investigation step or expansion link that cites an event another hunt owns is recorded (event_step_ref),
    # so deleting the owner keeps the event by an indexed lookup. It is not an observation marker: citing an id is not
    # retrieving a copy of the event.
    **{f"case_step_observe_{action}": f"""AFTER {action.upper()}{' OF decision,result_digest' if action == 'update' else ''}
        ON case_step BEGIN
        INSERT OR IGNORE INTO event_step_ref(hunt_id,event_id)
        SELECT c.hunt_id,e.id FROM "case" c, json_tree(NEW.decision) j JOIN typed_event e ON e.id=j.value
        WHERE c.id=NEW.case_id AND j.type='text' AND e.hunt_id!=c.hunt_id;
        INSERT OR IGNORE INTO event_step_ref(hunt_id,event_id)
        SELECT c.hunt_id,e.id FROM "case" c, json_tree(coalesce(NEW.result_digest,'null')) j
        JOIN typed_event e ON e.id=j.value
        WHERE c.id=NEW.case_id AND j.type='text' AND e.hunt_id!=c.hunt_id; END"""
       for action in ("insert", "update")},
    **{f"expansion_link_observe_{action}": f"""AFTER {action.upper()}{' OF event_ids,evidence_ids' if action == 'update' else ''}
        ON expansion_link BEGIN
        INSERT OR IGNORE INTO event_step_ref(hunt_id,event_id)
        SELECT NEW.hunt_id,e.id FROM json_each(NEW.event_ids) j JOIN typed_event e ON e.id=j.value
        WHERE e.hunt_id!=NEW.hunt_id;
        INSERT OR IGNORE INTO event_step_ref(hunt_id,event_id)
        SELECT NEW.hunt_id,e.id FROM json_each(NEW.evidence_ids) j JOIN typed_event e ON e.id=j.value
        WHERE e.hunt_id!=NEW.hunt_id; END"""
       for action in ("insert", "update")},
}

# Stream-visible fields omit lease/heartbeat housekeeping and no-op ownership
# fences; substantive changes remain visible in commit order.
CHANGE_COLUMNS = {
    "agent_run": ("run", "hunt_id", "hunt_id state reason prompt_digests provider started_at ended_at"),
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
