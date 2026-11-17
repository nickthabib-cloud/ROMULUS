"""Analyst controls over a hunt: stop requests, agent budget extensions, the worker process, budget grants."""
import sqlalchemy as sa
from alembic import op

revision = "0044"
down_revision = "0043"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "hunt_stop_request",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("hunt_id", sa.String(), sa.ForeignKey("hunt.id"), nullable=False),
        sa.Column("scope", sa.String(), nullable=False),
        sa.Column("requested_by", sa.String(), nullable=False),
        sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("state", sa.String(), nullable=False),
        sa.Column("honored_at", sa.DateTime(timezone=True)),
        sa.Column("closed_at", sa.DateTime(timezone=True)),
        sa.Column("closed_by", sa.String()),
        sa.Column("detail", sa.JSON(), nullable=False),
        sa.CheckConstraint("scope IN ('hunt','agent')", name="ck_hunt_stop_request_scope"),
        sa.CheckConstraint("state IN ('requested','honored','forced','cleared','unapplied')",
                           name="ck_hunt_stop_request_state"),
    )
    op.create_index("ix_hunt_stop_request_hunt_state", "hunt_stop_request", ["hunt_id", "state", "id"])
    op.create_table(
        "hunt_budget_extension",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("hunt_id", sa.String(), sa.ForeignKey("hunt.id"), nullable=False),
        sa.Column("added_by", sa.String(), nullable=False),
        sa.Column("role", sa.String(), nullable=False),
        sa.Column("added_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("profile", sa.String()),
        sa.Column("amounts", sa.JSON(), nullable=False),
        sa.Column("above_ceiling", sa.JSON(), nullable=False),
    )
    op.create_index("ix_hunt_budget_extension_hunt", "hunt_budget_extension", ["hunt_id", "id"])
    op.create_table(
        "hunt_process",
        sa.Column("hunt_id", sa.String(), sa.ForeignKey("hunt.id"), primary_key=True),
        sa.Column("pid", sa.Integer(), nullable=False),
        sa.Column("start_marker", sa.String(), nullable=False),
        sa.Column("host", sa.String(), nullable=False),
        sa.Column("command", sa.String(), nullable=False),
        sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("ended_at", sa.DateTime(timezone=True)),
    )
    op.create_table(
        "agent_budget_grant",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_by", sa.String(), nullable=False),
        sa.Column("role", sa.String(), nullable=False),
        sa.Column("choice", sa.JSON(), nullable=False),
    )


def downgrade():
    connection = op.get_bind()
    if connection.dialect.name == "sqlite" and not connection.connection.driver_connection.in_transaction:
        connection.exec_driver_sql("BEGIN")
    op.drop_table("agent_budget_grant")
    op.drop_table("hunt_process")
    op.drop_index("ix_hunt_budget_extension_hunt", table_name="hunt_budget_extension")
    op.drop_table("hunt_budget_extension")
    op.drop_index("ix_hunt_stop_request_hunt_state", table_name="hunt_stop_request")
    op.drop_table("hunt_stop_request")
