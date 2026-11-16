"""An agent session can end in the secret_guard state, when a reply of it held a configured secret's text.

Such a session cannot continue: its signed turns can be neither redacted nor sent again."""
import re

from alembic import op

revision = "0043"
down_revision = "0042"
branch_labels = None
depends_on = None

ADDED = "secret_guard"
CHECK = "ck_agent_session_state"
STATE_LIST = re.compile(r"(CONSTRAINT\s+" + CHECK + r"\s+CHECK\s*\(\s*state\s+IN\s*\()([^)]*)(\))")


def _states(table_sql):
    match = STATE_LIST.search(table_sql)
    if match is None or len(STATE_LIST.findall(table_sql)) != 1:
        raise RuntimeError("agent_session has no single state check to rewrite")
    return match, re.findall(r"'([^']+)'", match.group(2))


def _table_sql(connection):
    return connection.exec_driver_sql(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='agent_session'").scalar_one()


def _sqlite_rebuild(connection, states):
    """Replace the table under one transaction, keeping its rows, indexes and triggers exactly."""
    if not connection.connection.driver_connection.in_transaction:
        connection.exec_driver_sql("BEGIN")
    deferred = connection.exec_driver_sql("PRAGMA defer_foreign_keys").scalar()
    # the agent's tool calls, notes, links, rule requests, hypothesis events and model calls reference the table;
    # the drop below is checked at commit, after the rename
    connection.exec_driver_sql("PRAGMA defer_foreign_keys=ON")
    table_sql = _table_sql(connection)
    match, _ = _states(table_sql)
    listed = ",".join(f"'{state}'" for state in states)
    new_sql = table_sql[:match.start(2)] + listed + table_sql[match.end(2):]
    new_sql, renamed = re.subn(r"^CREATE TABLE\s+\"?agent_session\"?", "CREATE TABLE agent_session_0043", new_sql)
    if renamed != 1:
        raise RuntimeError("unexpected agent_session definition")
    # Triggers and indexes are dropped with the old table; their own SQL recreates them unchanged.
    attached = connection.exec_driver_sql(
        "SELECT type, sql FROM sqlite_master WHERE tbl_name='agent_session' AND type IN ('index','trigger') "
        "AND sql IS NOT NULL ORDER BY type, name").all()
    before = connection.exec_driver_sql("SELECT count(*) FROM agent_session").scalar_one()
    connection.exec_driver_sql(new_sql)
    connection.exec_driver_sql("INSERT INTO agent_session_0043 SELECT * FROM agent_session")
    connection.exec_driver_sql("DROP TABLE agent_session")
    connection.exec_driver_sql("ALTER TABLE agent_session_0043 RENAME TO agent_session")
    for _, sql in attached:
        connection.exec_driver_sql(sql)
    if connection.exec_driver_sql("SELECT count(*) FROM agent_session").scalar_one() != before:
        raise RuntimeError("agent_session rebuild changed its row count")
    if connection.exec_driver_sql("PRAGMA foreign_key_check").first() is not None:
        raise RuntimeError("agent_session rebuild left invalid foreign-key references")
    # Turning the pragma off resets SQLite's count of the violations the DROP recorded (the rename resolved them);
    # left on, COMMIT would still see them. Restore a caller's setting afterwards.
    connection.exec_driver_sql("PRAGMA defer_foreign_keys=OFF")
    if deferred:
        connection.exec_driver_sql("PRAGMA defer_foreign_keys=ON")


def _set_states(states):
    connection = op.get_bind()
    if connection.dialect.name == "sqlite":
        _sqlite_rebuild(connection, states)
        return
    listed = ",".join(f"'{state}'" for state in states)
    op.drop_constraint(CHECK, "agent_session", type_="check")
    op.create_check_constraint(CHECK, "agent_session", f"state IN ({listed})")


def _current():
    """The state list as this database declares it (SQLite), or as the investigation migration created it."""
    connection = op.get_bind()
    if connection.dialect.name != "sqlite":
        return ["running", "finished", "capped", "context_full", "refused", "failed", "interrupted", "budget"]
    return _states(_table_sql(connection))[1]


def upgrade():
    current = _current()
    if ADDED in current:
        return
    _set_states([*current, ADDED])


def downgrade():
    connection = op.get_bind()
    # a session the guard ended stays recorded as a failure, which is what the older schema can say
    connection.exec_driver_sql(f"UPDATE agent_session SET state='failed' WHERE state='{ADDED}'")
    _set_states([state for state in _current() if state != ADDED])
