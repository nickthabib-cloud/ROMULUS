"""The AI triage order: one row per deterministic finding group of a hunt's latest triage pass."""
from alembic import op
from sqlalchemy import (
    JSON,
    Column,
    ForeignKey,
    Index,
    Integer,
    MetaData,
    PrimaryKeyConstraint,
    String,
    Table,
    Text,
)

revision = "0040"
down_revision = "0039"
branch_labels = None
depends_on = None

metadata = MetaData()
Table("hunt", metadata, Column("id", String, primary_key=True))

ai_triage_group = Table(
    "ai_triage_group", metadata,
    Column("hunt_id", String, ForeignKey("hunt.id"), nullable=False),
    Column("pass", Integer, nullable=False),
    Column("group_id", String, nullable=False),
    Column("section", Integer, nullable=False),
    Column("position", Integer, nullable=False),
    Column("best_position", Integer, nullable=False),
    Column("rule_id", String, nullable=False),
    Column("entity_kind", String),
    Column("entity", String),
    Column("provenance", String, nullable=False),
    Column("finding_count", Integer, nullable=False),
    Column("finding_ids", JSON, nullable=False),
    Column("status", String, nullable=False),
    Column("reason", String),
    Column("assessment", String),
    Column("incident_label", String),
    Column("rationale", Text),
    Column("cites", JSON, nullable=False),
    Column("prompt_digest", String, nullable=False),
    Column("model", String, nullable=False),
    PrimaryKeyConstraint("hunt_id", "pass", "group_id", name="pk_ai_triage_group"),
)
# Bound to its table, so creating the table creates the index and dropping it drops it.
INDEXES = (
    Index("ix_ai_triage_group_position", ai_triage_group.c.hunt_id, ai_triage_group.c["pass"],
          ai_triage_group.c.position, unique=True),
)


def upgrade():
    ai_triage_group.create(op.get_bind())


def downgrade():
    ai_triage_group.drop(op.get_bind())
