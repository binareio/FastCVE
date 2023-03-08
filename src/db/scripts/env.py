"""
Alembic related code

Copyright (c) 2020 to date, Binare Oy (license@binare.io) All rights reserved.
"""

from __future__ import with_statement
from alembic import context
import logging
import db.tables as tables
import generic

logger = logging.getLogger('alembic')
appctx = generic.ApplicationContext.instance()

# this is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config

def run_migrations_offline():
    """Run migrations in 'offline' mode.

    This configures the context with just a URL
    and not an Engine, though an Engine is acceptable
    here as well.  By skipping the Engine creation
    we don't even need a DBAPI to be available.

    Calls to context.execute() here emit the given string to the
    script output.

    """
    url = appctx.config.get_param('db.dsn','driver://user:pass@host/db')
    context.configure(url=url, target_metadata=tables.metadata, literal_binds=True, compare_type=True)

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online():
    """Run migrations in 'online' mode.

    In this scenario we need to create an Engine
    and associate a connection with the context.

    """
    connectable = appctx.db.engine

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=tables.metadata,
            include_schemas=True,
            compare_type=True
        )

        with context.begin_transaction():
            context.run_migrations()

if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
