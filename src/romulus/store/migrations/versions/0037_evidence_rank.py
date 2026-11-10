"""Evidence-based finding and entity ranks, one set per ranking pass."""
from alembic import op
from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    Column,
    Float,
    ForeignKey,
    Index,
    Integer,
    MetaData,
    PrimaryKeyConstraint,
    String,
    Table,
)

revision = "0037"
down_revision = "0035"
branch_labels = None
depends_on = None

metadata = MetaData()
Table("hunt", metadata, Column("id", String, primary_key=True))

finding_rank = Table(
    "finding_rank", metadata,
    Column("hunt_id", String, ForeignKey("hunt.id"), nullable=False),
    Column("pass", Integer, nullable=False),
    Column("candidate_id", String, nullable=False),
    Column("position", Integer, nullable=False),
    Column("score", Float, nullable=False),
    Column("reported", Boolean, nullable=False),
    Column("entity_kind", String),
    Column("entity", String),
    Column("reasons", JSON, nullable=False),
    PrimaryKeyConstraint("hunt_id", "pass", "candidate_id", name="pk_finding_rank"),
    CheckConstraint('"pass" IN (1, 2)', name="ck_finding_rank_pass"),
)
entity_rank = Table(
    "entity_rank", metadata,
    Column("hunt_id", String, ForeignKey("hunt.id"), nullable=False),
    Column("pass", Integer, nullable=False),
    Column("entity_kind", String, nullable=False),
    Column("entity", String, nullable=False),
    Column("position", Integer, nullable=False),
    Column("score", Float, nullable=False),
    Column("tactics", JSON, nullable=False),
    Column("rules", Integer, nullable=False),
    Column("cooccur", Integer, nullable=False),
    Column("confirmed", Integer, nullable=False),
    Column("findings", Integer, nullable=False),
    Column("reported", Boolean, nullable=False),
    Column("reasons", JSON, nullable=False),
    PrimaryKeyConstraint("hunt_id", "pass", "entity_kind", "entity", name="pk_entity_rank"),
    CheckConstraint('"pass" IN (1, 2)', name="ck_entity_rank_pass"),
)
# Bound to their tables, so creating a table creates its indexes and dropping it drops them.
INDEXES = (
    Index("ix_finding_rank_score", finding_rank.c.hunt_id, finding_rank.c["pass"], finding_rank.c.score.desc()),
    Index("ix_finding_rank_position", finding_rank.c.hunt_id, finding_rank.c["pass"], finding_rank.c.position,
          unique=True),
    Index("ix_entity_rank_score", entity_rank.c.hunt_id, entity_rank.c["pass"], entity_rank.c.score.desc()),
    Index("ix_entity_rank_position", entity_rank.c.hunt_id, entity_rank.c["pass"], entity_rank.c.position,
          unique=True),
)


def upgrade():
    connection = op.get_bind()
    for table in (finding_rank, entity_rank):
        table.create(connection)


def downgrade():
    connection = op.get_bind()
    for table in (entity_rank, finding_rank):
        table.drop(connection)
