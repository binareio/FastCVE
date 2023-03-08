#!/usr/bin/env python3
"""
Facilitates the run of alembic scripts.

Copyright (c) 2020 to date, Binare Oy (license@binare.io) All rights reserved.
"""

import logging
import importlib
import importlib.util
import argparse
import generic

# ------------------------------------------------------------------------------
logger = logging.getLogger(__name__)
appctx = None


# ------------------------------------------------------------------------------
def import_meta():
    # --------------------------------------------------------------------------
    # Import all table definitons as per {schema}.py file
    module = None
    schema = 'tables'

    if importlib.util.find_spec(schema, None) is not None:
        module = importlib.import_module(schema)

    if module is None:
        raise RuntimeError('Cannot continue wihtout module {}.'.format(schema))

    # --------------------------------------------------------------------------
    # move imported table definition to global scope
    module_dict = module.__dict__
    try:
        to_import = module.__all__
    except AttributeError:
        to_import = [name for name in module_dict if not name.startswith('_')]

    globals().update({name: module_dict[name] for name in to_import})


# ------------------------------------------------------------------------------
def create_schema_objs():

    """Tool to be used on order to create all objects defined in a particular
    python file that has all objects definition for a particulat schema which
    should be provided in input.

    Note: ``schema`` will expect to have corresponfing python file {schema}.py
          in the same directory from where create_schema is run and should
          contain all objects definitions as per SqlAlchemy syntax.

    """

    global appctx

    import_meta()

    # --------------------------------------------------------------------------
    # Create all schema objects Tables/Indeces/Sequences etc. defined
    # into Base as per imported objects from imported {schema}.py
    # --------------------------------------------------------------------------
    metadata.create_all(appctx.db.engine)

    print("Finnished Creating objects for schema: tables")


# --------------------------------------------------------------------------
def create_schema_diffs():

    """Generates (and applies the schema differences between metadata and DB)
    """
    from alembic.migration import MigrationContext
    from alembic.autogenerate import compare_metadata
    import pprint

    global appctx

    import_meta()
    conn = appctx.db.engine.connect()

    mc = MigrationContext.configure(connection=conn, opts={'include_schemas': True,
                                                           'target_metadata': metadata})

    diff = compare_metadata(mc, metadata)
    if diff:
        pprint.pprint(diff, indent=4)
    else:
        print('No differences found\n')


if __name__ == "__main__":

    # --------------------------------------------------------------------------
    # create application context
    appctx = generic.ApplicationContext.instance()

    # --------------------------------------------------------------------------
    # Parse the arguments and Validate
    parser = argparse.ArgumentParser(description="Schema objects creation")
    parser.add_argument('-d', '--diff', dest='diff_ind', action='store_true',
                        help="Indicates to generate a difference between metadata and DB")

    args = parser.parse_args()

    if args.diff_ind:
        create_schema_diffs()
    else:
        create_schema_objs()

