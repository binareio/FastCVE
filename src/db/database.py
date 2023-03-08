"""
Database handlign module, Initialization and session management

Copyright (c) 2020 to date, Binare Oy (license@binare.io) All rights reserved.
"""

import os

import threading
import logging
import sqlalchemy
import sqlalchemy.orm

from sqlalchemy import event, exc

# ------------------------------------------------------------------------------
LOGGER = logging.getLogger(__name__)


# ------------------------------------------------------------------------------
class DataBase():
    """This class is repsonsible to be the interface with DB. Activitities that
    can be done with:

    *) retirieve a dedicated session for current Thread
    *) retrieve current sqlalchemy Engine.
    """
    __db_session_cls = None
    __db_engine = None

    def __init__(self, dsn, **kwargs):

        """Constructor method for DataBase class.

        Args:
            dsn: Database connection string
            **kwargs: additional parameters that are passed to engine instatiation for sqlAlchemy
        """

        self.__lock = threading.Lock()
        self.__locks = {}
        self.__thread_sessions = {}
        self.__db_engine = sqlalchemy.create_engine(dsn, **kwargs)
        # https://docs.sqlalchemy.org/en/13/faq/connections.html
        # how-do-i-use-engines-connections-sessions-with-python-multiprocessing-or-os-fork
        self.__db_engine.dispose()
        # https://docs.sqlalchemy.org/en/13/core/pooling.html
        self.__add_engine_pidguard()

        self.__db_session_cls = sqlalchemy.orm.sessionmaker(bind=self.__db_engine)

        self.__thread_sessions = {}

    # ------------------------------------------------------------------------------
    def __add_engine_pidguard(self):
        """Add multiprocessing guards.

        Forces a connection to be reconnected if it is detected
        as having been shared to a sub-process.
        """

        # --------------------------------------------------------------------------
        @event.listens_for(self.__db_engine, "connect")
        def connect(dbapi_connection, connection_record):
            connection_record.info['pid'] = os.getpid()

        # --------------------------------------------------------------------------
        @event.listens_for(self.__db_engine, "checkout")
        def checkout(dbapi_connection, connection_record, connection_proxy):
            pid = os.getpid()
            if connection_record.info['pid'] != pid:
                connection_record.connection = connection_proxy.connection = None
                raise exc.DisconnectionError(f"Connection record belongs to pid "
                                             f"{connection_record.info['pid']}, "
                                             f"attempting to check out in pid {pid}")

    # ------------------------------------------------------------------------------
    @property
    def engine(self):
        """Will return current sqlalchemy engine.

        Returns
            engine: class:``sqlalchemy.engine``: - current session's DB engine
        """
        return self.__db_engine

    def get_session(self, separate=False, **kwargs):
        """Will return a separate session for current sqlalchemy engine if separate
        parameter is set or the current session for current thread

        Returns
            session:class:``sqlalchemy.orm.session``: - instance corresponding to current thread
        """
        if separate:
            return self.__db_session_cls(**kwargs)
        else:
            return self.__enter__()

    def return_session(self, session=None, exception=None):
        """To be called after retrieving a session using `get_session`
        In case session was retrieved as as a separate session then it has to be
        provided here at the time of return

        Param:
            session - previous retrieved session in case it was retrieved separately
            exception - to send the exception in case any occured - will determine
            the commit/rollback result for the session.
        """

        if session is not None:
            try:
                if exception is None:
                    session.commit()
                else:
                    session.rollback()

            except Exception as exc:
                LOGGER.exception(exc)
                raise exc

            finally:
                session.close()

        else:
            self.__exit__(exception, None, None)

    def __enter__(self):

        """Yelds a new or current thread's DB session."""
        thread_id = threading.current_thread().name

        thread_lock = self.__locks.get(thread_id, None)
        if not thread_lock:
            with self.__lock:
                thread_lock = self.__locks.get(thread_id, None)
                if not thread_lock:
                    thread_lock = threading.Lock()
                    self.__locks[thread_id] = thread_lock

        thread_lock.acquire()
        try:

            if not thread_id in self.__thread_sessions:
                self.__thread_sessions[thread_id] = {}
                self.__thread_sessions[thread_id]['flow_level'] = 0

            if self.__thread_sessions[thread_id]['flow_level'] <= 0:
                self.__thread_sessions[thread_id]['flow_level'] = 0
                self.__thread_sessions[thread_id]['session'] = self.__db_session_cls()

            self.__thread_sessions[thread_id]['flow_level'] += 1

            return self.__thread_sessions[thread_id]['session']
        finally:
            thread_lock.release()

    def __exit__(self, exc_type, exc_value, traceback):

        """Takes care for previously yelded db session for transaction
        commit/roollback and closure."""

        thread_id = threading.current_thread().name

        thread_lock = self.__locks.get(thread_id, None)
        if not thread_lock:
            with self.__lock:
                thread_lock = self.__locks.get(thread_id, None)
                if not thread_lock:
                    thread_lock = threading.Lock()
                    self.__locks[thread_id] = thread_lock

        exc, session = None, None
        thread_lock.acquire()
        try:
            if self.__thread_sessions[thread_id]['flow_level'] > 0:
                self.__thread_sessions[thread_id]['flow_level'] -= 1

            if self.__thread_sessions[thread_id]['flow_level'] <= 0 or exc_type:
                self.__thread_sessions[thread_id]['flow_level'] = 0
                try:
                    session = self.__thread_sessions[thread_id]['session']
                    if exc_type is None:
                        session.commit()
                    else:
                        session.rollback()

                except Exception as err:
                    exc = err

                finally:
                    if session: session.close()
        finally:
            thread_lock.release()
            if exc:
                LOGGER.exception(exc)
                raise exc

