#!/usr/bin/env bash

if [[ -n $FCDB_WEB_PARAMS ]]; then
    ( sleep 1
    . ./config/setenv.sh > /dev/null
    cd ${FCDB_HOME}/web
    nohup uvicorn app:app $FCDB_WEB_PARAMS > ${FCDB_HOME}/web_access.log 2>&1 & ) &
fi
