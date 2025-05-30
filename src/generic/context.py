"""
Application Context class (Singleton).
Through this class you can access all the application related information: Configuration, Logging, DB sessions, etc.

Copyright (c) 2020 to date, Binare Oy (license@binare.io) All rights reserved.
"""

import os
import threading
import logging
from multiprocessing import current_process
from common.util import setup_env

import db
import generic

import threading

class SingletonMeta(type):
    _instances = {}
    _lock = threading.Lock()  # Lock for thread safety

    def __call__(cls, *args, **kwargs):
        with cls._lock:
            if cls not in cls._instances:
                cls._instances[cls] = super().__call__(*args, **kwargs)
        return cls._instances[cls]

#------------------------------------------------------------------------------
APPCTX = None
#------------------------------------------------------------------------------
def appctx():
    """Hack for recursive imports of application context in the Flask App
    """
    global APPCTX
    if not APPCTX:
        APPCTX = ApplicationContext()
    return APPCTX

#------------------------------------------------------------------------------
class ApplicationContext(metaclass=SingletonMeta):
    """Class that implements central interface to provide configuration for an application.
    This is read-only while the application is running.

    An ApplicationContext provides:
        * Factory methods for accessing application components.
        * The ability to load file resources in a generic fashion.
        * The ability to publish events to registered listeners.
    """

    __cfg = None

    #--------------------------------------------------------------------------
    @classmethod
    def instance(cls, *args, **kwargs):
        """Instantiates only one instance of ``ApplicationContext`` for current process
        and returns it.
        """
        return ApplicationContext(*args, **kwargs)

    #--------------------------------------------------------------------------
    def __init__(self, **kwargs):
        """Initializes all classes that will be part of an ApplicationContext object:

            * Initialize an instance for :class:`generic.Configuration`
            * Initialize an instance for :class:`db.DataBase`
            * Initialize an instance for :class:`generic.LoggingManager`

        """

        #----------------------------------------------------------------------
        # If this class instance was already initialized then we skip the init
        if getattr(self, '__init_done', None):
            return

        setup_env()

        #------------------------------------------------------------------
        # prepare configuration parameters.
        ApplicationContext.__cfg = generic.Configuration(os.environ.get('FCDB_CFG_FILE', ''))

        #------------------------------------------------------------------
        # prepare Logger
        self._log_manager = generic.LoggingManager(appctx=self, **kwargs)
        ApplicationContext.__logger = logging.getLogger(__name__)

        # in case effective level is set as DEBUG we save resolved config parameters
        # to a file for debug purpose.
        log_level = self.config.get_param('log.level', 'NONE')
        if log_level == 'DEBUG':
            try:
                cfg_file_name = os.environ.get('FCDB_LOG_PATH', '') + \
                                            '/config_' + current_process().name + \
                                            '_' + str(os.getpid()) + '.ini'
                ApplicationContext.__cfg.save_config(cfg_file_name)
            except IOError:
                ApplicationContext.__logger.warning(f'Could not save config file {cfg_file_name} '
                                    'for debug purposes')

        #------------------------------------------------------------------
        # prepare db
        try:
            db_params = self.config.get_param('db.params', {})
            self.__db = db.DataBase(self.config.get_param('db.dsn'), **db_params)

        except Exception:
            ApplicationContext.__logger.exception("Exception occured while trying to initialize DB")
            raise

        #------------------------------------------------------------------
        ApplicationContext.__logger.debug('Finnished app context init')

        self.__init_done = "True"


    @property
    def config(self):
        """
        Returns configuration object :class:`~generic.Configuration`.
        """
        return ApplicationContext.__cfg

    #----------------------------------------------------------------------------------------------
    @property
    def db(self): # pylint: disable=C0103
        """
        Returns:
            :class:`~db.DataBase` - helper for DB sqlalchemy engine and sessions.

        """
        if self.__db is None:
            raise EnvironmentError('Application DB init failed or was not done yet')
        return self.__db

    @property
    def log_queue(self):
        return self._log_manager.log_queue

    def close(self):
        self._log_manager.finish()
