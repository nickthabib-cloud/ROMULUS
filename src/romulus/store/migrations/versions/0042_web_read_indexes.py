"""Indexes for per-page web reads: lane counts by provenance, remote model calls, a rule's findings in order."""
from alembic import op

revision = "0042"
down_revision = "0041"
branch_labels = None
depends_on = None

ORDER = ("CASE lane WHEN 'urgent' THEN 0 WHEN 'high' THEN 1 WHEN 'lead' THEN 2 ELSE 3 END, "
         "priority DESC, coalesce(ts, '~'), id")
INDEXES = {
    "ix_candidate_hunt_provenance_lane": "candidate(hunt_id, provenance, lane)",
    "ix_candidate_rule_order": f"candidate(hunt_id, rule_id, {ORDER})",
    "ix_model_call_hunt_egress": "model_call(hunt_id, egress)",
}


def upgrade():
    c = op.get_bind()
    if c.dialect.name == "sqlite" and not c.connection.driver_connection.in_transaction:
        c.exec_driver_sql("BEGIN")
    for name, target in INDEXES.items():
        c.exec_driver_sql(f"CREATE INDEX {name} ON {target}")


def downgrade():
    c = op.get_bind()
    if c.dialect.name == "sqlite" and not c.connection.driver_connection.in_transaction:
        c.exec_driver_sql("BEGIN")
    for name in INDEXES:
        c.exec_driver_sql(f"DROP INDEX {name}")
