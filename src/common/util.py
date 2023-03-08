"""
Generic utility functions for the fastcve.

Copyright (c) 2020 to date, Binare Oy (license@binare.io) All rights reserved.
"""

import os
from alembic.config import Config
from alembic import command


class ValidationError(Exception): ...


# ------------------------------------------------------------------------------
# create/update the db schema using alembic
def init_db_schema():

    # ------------------------------------------------------------------------------
    home = os.environ.get("FCDB_HOME")
    if not home:
        raise ValidationError(f'Project home environment vars not properly set: {home}')

    # this is a time consuming activity thus we make sure we do it only once
    control_file_name = os.path.join(home, 'alembic_init_done')
    if not os.path.isfile(control_file_name):

        working_dir = os.path.join(home, 'db')
        cwd = os.getcwd()

        os.chdir(working_dir)

        alembic_cfg = Config("alembic.ini")

        # Run the alembic upgrade head command
        command.upgrade(alembic_cfg, "head")

        os.chdir(cwd)

        # create the file to indicate there is no need to run alembic update scripts
        # until next restart of the docker image
        # NOTE: Do not map the ${FCDB_HOME} directory to the HOST
        with open(control_file_name, "w"):
            pass


# ------------------------------------------------------------------------------
def setup_env():

    import subprocess

    home = os.environ.get("FCDB_HOME")
    if not home:
        raise ValidationError(f'Project home environment vars not properly set: {home}')

    # Run the bash script that exports needed environment variables
    script = os.path.join(home, 'config', 'setenv.sh')
    result = subprocess.run(["bash", script], stdout=subprocess.PIPE, universal_newlines=True)

    # Parse the output to extract the environment variables
    for line in result.stdout.split("\n"):
        if "=" in line:
            key, value = line.split("=", 1)
            os.environ[key] = value

