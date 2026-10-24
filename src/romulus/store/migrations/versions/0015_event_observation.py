"""record direct per-hunt event observations

Revision ID: 0015
Revises: 0014
"""
import sqlalchemy as sa
from alembic import op

revision = "0015"
down_revision = "0014"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "event_observation",
        sa.Column("hunt_id", sa.String(), sa.ForeignKey("hunt.id"), primary_key=True),
        sa.Column("event_id", sa.String(), sa.ForeignKey("typed_event.id"), primary_key=True),
    )
    op.create_index("ix_event_observation_event", "event_observation", ["event_id"])
    op.execute(
        "INSERT OR IGNORE INTO event_observation (hunt_id, event_id) "
        "SELECT hunt_id, id FROM typed_event"
    )
    op.execute(
        "INSERT OR IGNORE INTO event_observation (hunt_id, event_id) "
        "SELECT hunt_id, event_id FROM event_citation"
    )
    op.execute(
        "INSERT OR IGNORE INTO event_observation (hunt_id, event_id) "
        "SELECT DISTINCT entity.hunt_id, event_entity.event_id "
        "FROM event_entity JOIN entity ON entity.id = event_entity.entity_id"
    )


def downgrade() -> None:
    op.drop_index("ix_event_observation_event", table_name="event_observation")
    op.drop_table("event_observation")
