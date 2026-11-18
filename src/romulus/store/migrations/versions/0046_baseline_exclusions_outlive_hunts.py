"""Cited-key exclusions outlive their hunt: baseline segments built from history stay site knowledge after the hunt
that cited the keys is deleted, so the keys it cited stay out of that history."""
import sqlalchemy as sa
from alembic import op

revision = "0046"
down_revision = "0045"
branch_labels = None
depends_on = None

_COLUMNS = ("hunt_id", "site", "target", "spec_id", "spec_version", "key_version", "key_digest", "start", "end")


def _begin():
    connection = op.get_bind()
    if connection.dialect.name == "sqlite" and not connection.connection.driver_connection.in_transaction:
        connection.exec_driver_sql("BEGIN")
    return connection


def _create(name, *, foreign_key):
    columns = [
        sa.Column("hunt_id", sa.String(), nullable=False),
        sa.Column("site", sa.String(), nullable=False),
        sa.Column("target", sa.String(), nullable=False),
        sa.Column("spec_id", sa.String(), nullable=False),
        sa.Column("spec_version", sa.String(), nullable=False),
        sa.Column("key_version", sa.String(), nullable=False),
        sa.Column("key_digest", sa.String(), nullable=False),
        sa.Column("start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("end", sa.DateTime(timezone=True), nullable=False),
    ]
    constraints = [
        sa.CheckConstraint("end > start", name="ck_baseline_hunt_exclusion_span"),
        sa.PrimaryKeyConstraint("hunt_id", "target", "spec_id", "key_digest", name="pk_baseline_hunt_exclusion"),
    ]
    if foreign_key:
        constraints.append(sa.ForeignKeyConstraint(["hunt_id"], ["hunt.id"], ondelete="CASCADE"))
    op.create_table(name, *columns, *constraints)


def _rebuild(*, foreign_key):
    connection = _begin()
    _create("baseline_hunt_exclusion_new", foreign_key=foreign_key)
    names = ", ".join(f'"{name}"' for name in _COLUMNS)
    if foreign_key:
        # a cascading key cannot hold rows of deleted hunts: those are dropped on the way down
        connection.exec_driver_sql(
            f"INSERT INTO baseline_hunt_exclusion_new ({names}) SELECT {names} FROM baseline_hunt_exclusion "
            "WHERE hunt_id IN (SELECT id FROM hunt)")
    else:
        connection.exec_driver_sql(
            f"INSERT INTO baseline_hunt_exclusion_new ({names}) SELECT {names} FROM baseline_hunt_exclusion")
    op.drop_index("ix_baseline_hunt_exclusion_overlap", table_name="baseline_hunt_exclusion")
    op.drop_table("baseline_hunt_exclusion")
    op.rename_table("baseline_hunt_exclusion_new", "baseline_hunt_exclusion")
    op.create_index(
        "ix_baseline_hunt_exclusion_overlap", "baseline_hunt_exclusion",
        ["site", "target", "spec_id", "spec_version", "key_version", "start", "end"], unique=False,
    )


def upgrade() -> None:
    _rebuild(foreign_key=False)


def downgrade() -> None:
    _rebuild(foreign_key=True)
