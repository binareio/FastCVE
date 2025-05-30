FROM postgres:16-alpine3.19

ARG APP_VERSION=notset

ENV FCDB_HOME=/fastcve FCDB_NAME=vuln_db POSTGRES_PASSWORD= FCDB_USER= FCDB_PASS= INP_ENV_NAME=dev
ENV PATH=${FCDB_HOME}:$PATH

RUN apk add gcc g++ build-base python3-dev py3-pip

WORKDIR ${FCDB_HOME}

COPY ./src/config/requirements.txt /tmp

RUN pip install --break-system-packages -r /tmp/requirements.txt

COPY ./docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
COPY ./start_web.sh /always-init.d/start_web.sh
COPY ./src ${FCDB_HOME}

RUN sed -i "1i\export APP_VERSION=${APP_VERSION}" ${FCDB_HOME}/config/setenv/setenv_*

RUN mkdir -p ${FCDB_HOME}/logs && chmod +wx ${FCDB_HOME}/logs \
    && chmod +x ${FCDB_HOME}/db/setup_db.sh \
    && chmod +x ${FCDB_HOME}/db/schema.sh \
    && chmod -x ${FCDB_HOME}/config/setenv.sh \
    && ln -s ${FCDB_HOME}/db/setup_db.sh /docker-entrypoint-initdb.d \
    && ln -s ${FCDB_HOME}/config/setenv.sh /docker-entrypoint-initdb.d \
    && chown -R postgres:postgres ${FCDB_HOME}

USER postgres
