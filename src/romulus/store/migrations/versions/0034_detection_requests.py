"""Attributed detection requests with immutable status history."""
from alembic import op
from sqlalchemy import (
    JSON,
    CheckConstraint,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    MetaData,
    String,
    Table,
    Text,
)

revision = '0034'
down_revision = '0033'
branch_labels = None
depends_on = None

metadata = MetaData()
request = Table(
    'detection_request', metadata,
    Column('id', String, primary_key=True),
    Column('requester', String, nullable=False),
    Column('created_at', DateTime(timezone=True), nullable=False),
    Column('behavior', Text, nullable=False),
    Column('telemetry_family', String, nullable=False),
    Column('attack_ids', JSON, nullable=False),
    Column('example_candidate_id', String),
    Column('example_event_id', String),
    Column('status', String, nullable=False),
    Column('rule_id', String),
    Column('decline_reason', Text),
    Column('status_reason', Text, nullable=False, server_default=''),
    Column('updated_by', String, nullable=False),
    Column('updated_at', DateTime(timezone=True), nullable=False),
    CheckConstraint('length(trim(behavior)) BETWEEN 1 AND 4000', name='ck_detection_request_behavior'),
    CheckConstraint("telemetry_family IN ('account_change','address_assignment','app_tx','application_compatibility','asset_observed','audit_config','auth','boot_configuration','database_audit','dcom_access','defender_event','directory_access','directory_change','dns_lookup','dns_query','ese_database','file_change','file_transfer','http_access','http_body','http_tx','ics_tx','image_load','kerberos_tx','ldap_tx','msi_install','net_alert','net_flow','net_session','net_socket','network_filter','ntlm_tx','object_access','pipe_event','privilege_adjustment','privilege_use','process_access','process_exec','process_observed','process_tampering','process_termination','registry_change','remote_access','remote_session','remote_thread','rpc_call','rpc_tx','scheduled_task','script_block','security_enumeration','sensor_health','service_change','share_access','silent_process_exit','smb_tx','ssh_session','system_state','tcp_stream','tls_session','web_error','winsock_catalog','wmi_subscription','x509_certificate','kernel_module','file_access','share_change','unknown')",
                    name='ck_detection_request_family'),
    CheckConstraint("status IN ('requested','accepted','in_progress','active','declined')",
                    name='ck_detection_request_status'),
    CheckConstraint("status != 'active' OR (rule_id IS NOT NULL AND length(trim(rule_id)) > 0)",
                    name='ck_detection_request_active'),
    CheckConstraint("status != 'declined' OR (decline_reason IS NOT NULL AND length(trim(decline_reason)) > 0)",
                    name='ck_detection_request_decline'),
    CheckConstraint('example_event_id IS NULL OR example_candidate_id IS NOT NULL',
                    name='ck_detection_request_example'),
)
event = Table(
    'detection_request_event', metadata,
    Column('id', Integer, primary_key=True, autoincrement=True),
    Column('request_id', String, ForeignKey('detection_request.id'), nullable=False),
    Column('actor', String, nullable=False),
    Column('at', DateTime(timezone=True), nullable=False),
    Column('old_status', String),
    Column('new_status', String, nullable=False),
    Column('reason', Text, nullable=False),
    Column('rule_id', String),
)


def _begin():
    connection = op.get_bind()
    if connection.dialect.name == 'sqlite' and not connection.connection.driver_connection.in_transaction:
        connection.exec_driver_sql('BEGIN')
    return connection


def upgrade():
    connection = _begin()
    request.create(connection)
    event.create(connection)
    connection.exec_driver_sql("CREATE INDEX ix_candidate_catalog_rule_time ON candidate "
                               "(rule_id,created_at DESC,id DESC,hunt_id)")
    op.create_index('ix_candidate_catalog_rule_hunt', 'candidate', ['rule_id', 'hunt_id'])
    op.create_index('ix_disposition_catalog_candidate_status', 'disposition_event', ['candidate_id', 'status'])
    connection.exec_driver_sql("CREATE INDEX ix_hunt_catalog_created ON hunt (created_at DESC,id DESC)")
    connection.exec_driver_sql("CREATE INDEX ix_source_profile_catalog_latest ON source_profile "
                               "(target,captured_at DESC,id DESC)")
    op.create_index('ix_sigma_catalog_status_id', 'sigma_rule', ['status', 'id'])
    op.create_index('ix_audit_catalog_action_hunt', 'audit_event', ['action', 'hunt_id'])
    connection.exec_driver_sql("""CREATE TRIGGER detection_request_no_replace BEFORE INSERT ON detection_request
        WHEN EXISTS(SELECT 1 FROM detection_request WHERE id=NEW.id)
        BEGIN SELECT RAISE(ABORT,'detection request replacement is forbidden'); END""")
    connection.exec_driver_sql("""CREATE TRIGGER detection_request_event_no_replace BEFORE INSERT ON detection_request_event
        WHEN EXISTS(SELECT 1 FROM detection_request_event WHERE id=NEW.id)
        BEGIN SELECT RAISE(ABORT,'detection request history is append-only'); END""")
    op.create_index('ix_detection_request_status_id', 'detection_request', ['status', 'id'])
    op.create_index('ix_detection_request_requester_id', 'detection_request', ['requester', 'id'])
    op.create_index('ix_detection_request_event_request_id', 'detection_request_event', ['request_id', 'id'])
    connection.exec_driver_sql("""CREATE TRIGGER detection_request_created AFTER INSERT ON detection_request
        BEGIN INSERT INTO detection_request_event(request_id,actor,at,old_status,new_status,reason,rule_id)
        VALUES(NEW.id,NEW.requester,NEW.created_at,NULL,NEW.status,'',NEW.rule_id); END""")
    connection.exec_driver_sql("""CREATE TRIGGER detection_request_status_changed
        AFTER UPDATE OF status ON detection_request WHEN OLD.status != NEW.status
        BEGIN INSERT INTO detection_request_event(request_id,actor,at,old_status,new_status,reason,rule_id)
        VALUES(NEW.id,NEW.updated_by,NEW.updated_at,OLD.status,NEW.status,
        NEW.status_reason,NEW.rule_id); END""")
    connection.exec_driver_sql("""CREATE TRIGGER detection_request_event_no_update
        BEFORE UPDATE ON detection_request_event
        BEGIN SELECT RAISE(ABORT,'detection request history is append-only'); END""")
    connection.exec_driver_sql("""CREATE TRIGGER detection_request_event_no_delete
        BEFORE DELETE ON detection_request_event
        BEGIN SELECT RAISE(ABORT,'detection request history is append-only'); END""")


def downgrade():
    connection = _begin()
    for name in ('detection_request_created', 'detection_request_status_changed',
                 'detection_request_event_no_update', 'detection_request_event_no_delete',
                 'detection_request_no_replace', 'detection_request_event_no_replace'):
        connection.exec_driver_sql(f'DROP TRIGGER {name}')
    event.drop(connection)
    request.drop(connection)
    for name in ('ix_candidate_catalog_rule_time', 'ix_candidate_catalog_rule_hunt',
                 'ix_disposition_catalog_candidate_status', 'ix_hunt_catalog_created',
                 'ix_source_profile_catalog_latest', 'ix_sigma_catalog_status_id',
                 'ix_audit_catalog_action_hunt'):
        op.drop_index(name)
