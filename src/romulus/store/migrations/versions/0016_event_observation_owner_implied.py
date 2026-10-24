"""an event's owning hunt observed it by owning its row: drop the owner's marker rows

Revision ID: 0016
Revises: 0015
"""
from alembic import op

revision = "0016"
down_revision = "0015"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        "DELETE FROM event_observation WHERE EXISTS (SELECT 1 FROM typed_event "
        "WHERE typed_event.id = event_observation.event_id AND typed_event.hunt_id = event_observation.hunt_id)"
    )


def downgrade() -> None:
    op.execute(
        "INSERT OR IGNORE INTO event_observation (hunt_id, event_id) "
        "SELECT hunt_id, id FROM typed_event"
    )
