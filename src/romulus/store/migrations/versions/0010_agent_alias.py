"""per-hunt durable agent aliases

Revision ID: 0010
Revises: 0009
"""
import sqlalchemy as sa
from alembic import op

revision = "0010"
down_revision = "0009"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "agent_alias",
        sa.Column("hunt_id", sa.String(), sa.ForeignKey("hunt.id"), nullable=False),
        sa.Column("alias", sa.String(), nullable=False),
        sa.Column("kind", sa.String(), nullable=False),
        sa.Column("target_id", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("kind IN ('F', 'I', 'E', 'N', 'L')", name="ck_agent_alias_kind"),
        sa.UniqueConstraint("hunt_id", "alias", name="uq_agent_alias_name"),
        sa.UniqueConstraint("hunt_id", "kind", "target_id", name="uq_agent_alias_target"),
    )
    op.create_index("ix_agent_alias_hunt_kind", "agent_alias", ["hunt_id", "kind"])


def downgrade() -> None:
    op.drop_index("ix_agent_alias_hunt_kind", table_name="agent_alias")
    op.drop_table("agent_alias")
