"""Detection requests may name the mail and VPN session families that Linux text logs now produce."""
import re

import sqlalchemy as sa
from alembic import op

revision = "0038"
down_revision = "0037"
branch_labels = None
depends_on = None

ADDED = ("mail_message", "vpn_session")
# The family list the request migration created.
CREATED = ("account_change", "address_assignment", "app_tx", "application_compatibility", "asset_observed",
           "audit_config", "auth", "boot_configuration", "database_audit", "dcom_access", "defender_event",
           "directory_access", "directory_change", "dns_lookup", "dns_query", "ese_database", "file_change",
           "file_transfer", "http_access", "http_body", "http_tx", "ics_tx", "image_load", "kerberos_tx",
           "ldap_tx", "msi_install", "net_alert", "net_flow", "net_session", "net_socket", "network_filter",
           "ntlm_tx", "object_access", "pipe_event", "privilege_adjustment", "privilege_use", "process_access",
           "process_exec", "process_observed", "process_tampering", "process_termination", "registry_change",
           "remote_access", "remote_session", "remote_thread", "rpc_call", "rpc_tx", "scheduled_task",
           "script_block", "security_enumeration", "sensor_health", "service_change", "share_access",
           "silent_process_exit", "smb_tx", "ssh_session", "system_state", "tcp_stream", "tls_session",
           "web_error", "winsock_catalog", "wmi_subscription", "x509_certificate", "kernel_module", "file_access",
           "share_change", "unknown")
CHECK = "ck_detection_request_family"
FAMILY_LIST = re.compile(r"(CONSTRAINT\s+" + CHECK + r"\s+CHECK\s*\(\s*telemetry_family\s+IN\s*\()([^)]*)(\))")


def _families(table_sql):
    match = FAMILY_LIST.search(table_sql)
    if match is None or len(FAMILY_LIST.findall(table_sql)) != 1:
        raise RuntimeError("detection_request has no single family check to rewrite")
    return match, re.findall(r"'([^']+)'", match.group(2))


def _sqlite_rebuild(connection, families):
    """Replace the table under one transaction, keeping its rows, indexes and triggers exactly."""
    if not connection.connection.driver_connection.in_transaction:
        connection.exec_driver_sql("BEGIN")
    deferred = connection.exec_driver_sql("PRAGMA defer_foreign_keys").scalar()
    # detection_request_event references the table; the drop below is checked at commit, after the rename.
    connection.exec_driver_sql("PRAGMA defer_foreign_keys=ON")
    table_sql = connection.exec_driver_sql(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='detection_request'").scalar_one()
    match, _ = _families(table_sql)
    listed = ",".join(f"'{family}'" for family in families)
    new_sql = table_sql[:match.start(2)] + listed + table_sql[match.end(2):]
    new_sql, renamed = re.subn(r"^CREATE TABLE\s+\"?detection_request\"?", "CREATE TABLE detection_request_0038", new_sql)
    if renamed != 1:
        raise RuntimeError("unexpected detection_request definition")
    # Triggers and indexes are dropped with the old table; their own SQL recreates them unchanged.
    attached = connection.exec_driver_sql(
        "SELECT type, sql FROM sqlite_master WHERE tbl_name='detection_request' AND type IN ('index','trigger') "
        "AND sql IS NOT NULL ORDER BY type, name").all()
    before = connection.exec_driver_sql("SELECT count(*) FROM detection_request").scalar_one()
    connection.exec_driver_sql(new_sql)
    connection.exec_driver_sql("INSERT INTO detection_request_0038 SELECT * FROM detection_request")
    connection.exec_driver_sql("DROP TABLE detection_request")
    connection.exec_driver_sql("ALTER TABLE detection_request_0038 RENAME TO detection_request")
    for _, sql in attached:
        connection.exec_driver_sql(sql)
    if connection.exec_driver_sql("SELECT count(*) FROM detection_request").scalar_one() != before:
        raise RuntimeError("detection_request rebuild changed its row count")
    if connection.exec_driver_sql("PRAGMA foreign_key_check").first() is not None:
        raise RuntimeError("detection_request rebuild left invalid foreign-key references")
    # Turning the pragma off resets SQLite's count of the violations the DROP recorded (the rename resolved them);
    # left on, COMMIT would still see them. Restore a caller's setting afterwards.
    connection.exec_driver_sql("PRAGMA defer_foreign_keys=OFF")
    if deferred:
        connection.exec_driver_sql("PRAGMA defer_foreign_keys=ON")


def _set_families(families):
    connection = op.get_bind()
    if connection.dialect.name == "sqlite":
        _sqlite_rebuild(connection, families)
        return
    listed = ",".join(f"'{family}'" for family in families)
    op.drop_constraint(CHECK, "detection_request", type_="check")
    op.create_check_constraint(CHECK, "detection_request", f"telemetry_family IN ({listed})")


def _current():
    """The family list as this database declares it (SQLite), or as the request migration created it."""
    connection = op.get_bind()
    if connection.dialect.name != "sqlite":
        return list(CREATED)
    return _families(connection.exec_driver_sql(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='detection_request'").scalar_one())[1]


def upgrade():
    current = _current()
    if set(ADDED) <= set(current):
        return
    _set_families([*(family for family in current if family != "unknown"), *ADDED, "unknown"])


def downgrade():
    connection = op.get_bind()
    used = connection.execute(sa.text(
        "SELECT telemetry_family FROM detection_request WHERE telemetry_family IN :families LIMIT 1"
    ).bindparams(sa.bindparam("families", expanding=True)), {"families": list(ADDED)}).first()
    if used is not None:
        raise RuntimeError(f"Cannot remove the {used[0]} family while detection requests name it")
    _set_families([family for family in _current() if family not in ADDED])
