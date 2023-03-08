#!/usr/bin/env bash
#------------------------------------------------------------------------------
# Script to export all needed env variables
#------------------------------------------------------------------------------
# Here we should add all definitions of parameters for application which are env
# dependent. 
# This script has to be sourced once env is started (i.e. from ${HOME}/.profile)
# Input parameters:
#    1) --env INP_ENV_NAME [i.e. values:dev/test/prod]
#    2) --config INP_CFG_LIST [additional list of includes/application/module]
#
# Copyright (c) 2020 to date, Binare Oy (license@binare.io) All rights reserved.
#------------------------------------------------------------------------------
getOptions()
#------------------------------------------------------------------------------
{
    while [ -n "$1" ];
    do
        OPT="$1"
        case ${OPT} in
        --config)
            shift
            [ -n "$1" ] && INP_CFG_LIST=$1 && shift
            ;;
        --env)
            shift
            [ -n "$1" ] && export INP_ENV_NAME=$1 && shift
            ;;
        --home)
            shift
            [ -n "$1" ] && FCDB_HOME=$1 && shift
            ;;
        *)
            shift
            ;;
        esac
    done
    return 0
}

#--------------------------------------------------------------------------------------------------
#       Parse input arguments if any
#--------------------------------------------------------------------------------------------------
getOptions "$@"

#--------------------------------------------------------------------------------------------------
#       Main Section
#--------------------------------------------------------------------------------------------------

export FCDB_PRJ_NAME=fastcve

# root path for APPIOTS project
export FCDB_HOME=${FCDB_HOME:-${HOME}/projects/${FCDB_PRJ_NAME}}

# path where configuration files are placed
export FCDB_CFG_PATH=${FCDB_HOME}/config

# main configuration file
export FCDB_CFG_FILE=${FCDB_CFG_PATH}/setenv/config.ini

# path where configuration files for additional loggers are placed
export FCDB_CFG_LOG_PATH=${FCDB_CFG_PATH}/log

# path where application log files are created/logged
export FCDB_LOG_PATH=${FCDB_HOME}/logs

# define python path
export PYTHONPATH=${FCDB_HOME}

if [ ! -d "${FCDB_LOG_PATH}" -a ! -r "${FCDB_LOG_PATH}" ]; then
    mkdir ${FCDB_LOG_PATH}
fi

#--------------------------------------------------------------------------------------------------
#       env type [dev/test/prod] dependent parameters
#--------------------------------------------------------------------------------------------------
# set default to dev is not specified explicitly
if [ -z "$INP_ENV_NAME" ]; then
    INP_ENV_NAME=dev
fi

export INP_ENV_NAME

if [ -n "${INP_ENV_NAME}" ]; then

    # any available ini file per env should be named as setenv_{INP_ENV_NAME}.ini and
    # available under ${FCDB_CFG_PATH}
    if [ -r "${FCDB_CFG_PATH}/setenv/setenv_${INP_ENV_NAME}.ini" ]; then

        # any variable defined in these files should set variables names and values in following form:
        # ENV_{NAME}={VALUE}
        . ${FCDB_CFG_PATH}/setenv/setenv_${INP_ENV_NAME}.ini
    fi
fi

#--------------------------------------------------------------------------------------------------
export FCDB_STORAGE_INPUT="${ENV_FCDB_STORAGE_INPUT:-${FCDB_HOME}/input}"

#--------------------------------------------------------------------------------------------------
#       Log Config section
#--------------------------------------------------------------------------------------------------
export FCDB_LOG_CONSOLE_DEBUG_LVL=${FCDB_LOG_CONSOLE_DEBUG_LVL:-WARNING}
export FCDB_LOG_FILE_DEBUG_LVL=${FCDB_LOG_FILE_DEBUG_LVL:-WARNING}

env