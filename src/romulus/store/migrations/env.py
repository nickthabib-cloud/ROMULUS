"""Alembic environment: runs against the connection supplied by romulus.store.db.migrate."""
from alembic import context
from sqlalchemy import create_engine

from romulus.store.schema import metadata

config = context.config
conn = config.attributes.get("connection")

if conn is None:
    engine = create_engine(config.get_main_option("sqlalchemy.url"))
    with engine.begin() as conn:
        context.configure(connection=conn, target_metadata=metadata, render_as_batch=True)
        with context.begin_transaction():
            context.run_migrations()
else:
    context.configure(connection=conn, target_metadata=metadata, render_as_batch=True)
    with context.begin_transaction():
        context.run_migrations()
