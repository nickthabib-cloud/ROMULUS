"""index persisted window hours for per-scope rate judgement

Revision ID: 0020
Revises: 0019
"""

from alembic import op

revision = "0020"
down_revision = "0019"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_index(
        "ix_baseline_window_scope_rate",
        "baseline_window_scope_hour",
        ["hunt_id", "spec_id", "scope_kind", "scope", "hour", "target", "partition"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_baseline_window_scope_rate", table_name="baseline_window_scope_hour")
