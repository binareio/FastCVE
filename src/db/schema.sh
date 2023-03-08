#!/usr/bin/env sh
#------------------------------------------------------------------------------
# Shell script to facilitate the alembic scripts creation/execution/updates etc.
# Run this script with --help or -h to get description and how to use.
#
# Copyright (c) 2020 to date, Binare Oy (license@binare.io) All rights reserved.
#------------------------------------------------------------------------------
usage()
{
    SYNOPSYS="Usage: $(basename $0) [-h|--help] [-s|--sql] [-m|--message MESSAGE] [-d|--delete] [-p|--pattern PATTERN] [-r|--revision REV] action"
    FULL_TEXT="

    Where:

        action - specify what kind of action is expected to be done
            cr[eate]      - create all db related objects as per schema definition from DB.
            d[iff]        - show if there is any difference between current repository schema definition and current DB.
            l[ist]        - list all DB schema changes registered so far.
            h[ead]        - apply all needed schema changes to DB to bring it in sync with repository.
            u[grade]      - apply all needed schema changes to DB to bring it in sync with repository up to specified revision.
                            --revision is mandatory in this case.
            [down]g[rade] - remove all schema changes from DB to bring it in sync with repository down to specified revision.
                            --revision option is mandatory in this case.
            rev[ision]    - create a new revision for current existing differences between repository and DB.
                            --message option is mandatory if action specified as revision.
            ref[erence]   - load reference data from json (default) or csv files into its corresponding tables.
            s[ync]        - validates list of Action and Resources defined in the code with DB and synchronizes
                            Actions/Resources to Role mappings with DB. (action valid for auth schema only)

    Options:
        -h | --help       - will display this help
        -s | --sql        - cause to printout SQL statements instead of actual action
                            this option is relevant only for actions: list, head, upgrade, downgrade
        -m | --message    - specifies the revision message for a new revision which is being created
                            this option is mandatory and relevant only for action: revision
        -d | --delete     - causes to delete first record from reference tables
                            this option is relevant only for action: reference
        -p | --pattern    - specifies pattern to seach for csv files to load into reference tables
                            this option is relevant only for action: reference
        -r | --revision   - specifies DB revision change number that should be applied to DB
                            this option is relevant only for actions: upgrade and downgrade
    "
    echo ""
    echo "$SYNOPSYS"
    [ -n "$1" ] && echo "$FULL_TEXT"

}
#--------------------------------------------------------------
function getOptions
#--------------------------------------------------------------
{
    CNT=0
    while [ -n "$1" ];
    do
        OPT="$1"
        case ${OPT} in
        -s|--sql)
            let CNT+=1
            PRINT_SQL="--sql"
            ;;
        -m|--message)
            shift && let CNT+=1
            [ -n "$1" ] && REV_MSG="$1" && let CNT+=1
            ;;
        -d|--delete)
            let CNT+=1
            CSV_DEL_OPT="-d"
            ;;
        -p|--pattern)
            shift && let CNT+=1
            [ -n "$1" ] && CSV_PATT="$1" && let CNT+=1
            ;;
        -r|--revision)
            shift && let CNT+=1
            [ -n "$1" ] && REV="$1" && let CNT+=1
            ;;
        -h|--help)
            usage long && exit 0
            ;;
        -*)
           echo "Invalid option: $OPT" && usage >&2 || exit 1
           ;;
        esac
        shift
    done
    return $CNT
}


#--------------------------------------------------------------------------------------------------
#       Parse input arguments if any
#--------------------------------------------------------------------------------------------------
getOptions "$@"
shift $?

#------------------------------------------------------------------------------
actions="$@"
if [ -z "$actions" ]; then
    actions=head
fi

#------------------------------------------------------------------------------
# change current path from where this script is run
cd $(dirname ${0})

#--------------------------------------------------------------------------
. ${FCDB_HOME}/config/setenv.sh > /dev/null
for action in $(echo $actions | sed 's/[,|:;.]/ /g')
do
    # strip any extra characters from the actual db name
    case $action in
        cr|create)     python3 create_schema.py*                                        || exit 10 ;;
        d|diff)        python3 create_schema.py* -d                                     || exit 11 ;;
        h|head)        alembic -c alembic.ini upgrade head $PRINT_SQL                   || exit 3 ;;
        u|upgrade)     alembic -c alembic.ini upgrade "${REV}" $PRINT_SQL               || exit 4 ;;
        g|downgrade)   alembic -c alembic.ini downgrade "${REV}" $PRINT_SQL             || exit 5 ;;
        l|list)        alembic -c alembic.ini history $PRINT_SQL                        || exit 6 ;;
        rev|revision)  alembic -c alembic.ini revision --autogenerate -m "${REV_MSG}"   || exit 7 ;;
        *)     echo "Unknow action:$action" && usage ;;
    esac
done