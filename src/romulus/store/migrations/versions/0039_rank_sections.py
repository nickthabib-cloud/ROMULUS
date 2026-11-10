"""Ranked findings record their report section, and the AI agent's findings get their own order index.

Pages follow report order from `ix_finding_rank_section`; the agent findings page reads `ix_candidate_provenance_order`
instead of walking the hunt's whole order index."""
from alembic import op

revision = "0039"
down_revision = "0038"
branch_labels = None
depends_on = None

# 0 confirmed (stored lane urgent), 1 reported by the evidence bar, 2 ranked but not reported.
SECTION_BACKFILL = """UPDATE finding_rank SET section = CASE
    WHEN EXISTS (SELECT 1 FROM candidate c WHERE c.id = finding_rank.candidate_id AND c.lane = 'urgent') THEN 0
    WHEN reported THEN 1 ELSE 2 END"""


def upgrade():
    c = op.get_bind()
    if c.dialect.name == "sqlite" and not c.connection.driver_connection.in_transaction:
        c.exec_driver_sql("BEGIN")
    c.exec_driver_sql("ALTER TABLE finding_rank ADD COLUMN section INTEGER NOT NULL DEFAULT 2")
    c.exec_driver_sql(SECTION_BACKFILL)
    c.exec_driver_sql('CREATE INDEX ix_finding_rank_section ON finding_rank(hunt_id, "pass", section, position)')
    c.exec_driver_sql("""CREATE INDEX ix_candidate_provenance_order ON candidate(
        hunt_id, provenance, CASE lane WHEN 'urgent' THEN 0 WHEN 'high' THEN 1 WHEN 'lead' THEN 2 ELSE 3 END,
        priority DESC, coalesce(ts, '~'), id)""")


def downgrade():
    c = op.get_bind()
    if c.dialect.name == "sqlite" and not c.connection.driver_connection.in_transaction:
        c.exec_driver_sql("BEGIN")
    c.exec_driver_sql("DROP INDEX ix_candidate_provenance_order")
    c.exec_driver_sql("DROP INDEX ix_finding_rank_section")
    c.exec_driver_sql("ALTER TABLE finding_rank DROP COLUMN section")
