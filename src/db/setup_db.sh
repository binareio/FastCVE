#!/bin/bash 
# Description:  Should be used in order to setup postgres DB, Users, Schemas and access rights.
# Assumptions:  1) ${FCDB_HOME}/config/setenv.sh is executed first before executing this script
#
# Copyright (c) 2020 to date, Binare Oy (license@binare.io) All rights reserved.
#--------------------------------------------------------------------------------------------------
create_db()
#--------------------------------------------------------------------------------------------------
{
    DB=$1
    DB_OWNER=$2
    DB_CNT=$(echo "select count(1) from pg_database where datname = '$DB';" | psql -U postgres -t)
    [[ $? -ne 0 ]] && echo "Error executing postgres while creating DB $DB" && exit 1
    if [[ $DB_CNT -eq 0 ]]; then
        echo "Creating database $DB"
        echo -e "\\set ON_ERROR_STOP on\ncreate database $DB;" | psql -U postgres -t
        [[ $? -ne 0 ]] && echo "Error creating db $DB" && exit 1
        echo -e "\\set ON_ERROR_STOP on\nalter database $DB owner to $DB_OWNER;" | psql -U postgres -t
        [[ $? -ne 0 ]] && echo "Error alter db $DB owner to $DB_OWNER" && exit 1

    else
        echo "DB $DB already exists"
    fi
}

#--------------------------------------------------------------------------------------------------
create_user()
#--------------------------------------------------------------------------------------------------
{

    DB_USER=$1
    DB_USER_ROLES=$2
    DB_USER_PASS=$3

    DB_USER_CNT=$(echo -e "\\set ON_ERROR_STOP on\nselect count(1) from pg_user where usename = '$DB_USER';" | psql -U postgres -t)
    [[ $? -ne 0 ]] && echo "Error executing postgres" && exit 1

    if [[ $DB_USER_CNT -eq 0 ]]; then
        echo "Creating user $DB_USER"
        if [[ -z $DB_USER_PASS ]]; then
            echo -e "\\set ON_ERROR_STOP on\ncreate user $DB_USER $DB_USER_ROLES;" | psql -U postgres -t
        else
            echo -e "\\set ON_ERROR_STOP on\ncreate user $DB_USER $DB_USER_ROLES password '$DB_USER_PASS';" | psql -U postgres -t
        fi 
        [[ $? -ne 0 ]] && echo "Error creating user $DB_USER" && exit 1
    else
        echo "User $DB_USER already exists"
    fi
}

#--------------------------------------------------------------------------------------------------
# user creation
create_user ${FCDB_USER} "superuser" ${FCDB_PASS:-default$RANDOM}

#--------------------------------------------------------------------------------------------------
# DB creation
create_db ${FCDB_NAME} ${FCDB_USER}

exit 0