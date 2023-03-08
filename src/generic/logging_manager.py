"""
Logging management

Copyright (c) 2020 to date, Binare Oy (license@binare.io) All rights reserved.
"""

import os
import sys
import glob
import re
import logging
import logging.config
from datetime import datetime
from multiprocessing import Process, current_process, Event, Queue
from generic import exc as exceptions

import generic

# --------------------------------------------------------------------------------------------------
logger = logging.getLogger(__name__)


# --------------------------------------------------------------------------------------------------
class LoggingManager(Process):
    """Wrapper class to manage logging configuration load/reload based on project
    configuration setup.
    """
    # :int: Default Log File Size in case it was not specified in config.
    DEFAULT_LOG_FILE_SIZE = 10 * 1024 * 1024  # 10 Mb

    # :int: Default Max number of log files in case it was not specified in config.
    DEFAULT_LOG_FILE_COUNT = 10

    # :str: Default (current path) when expected variables (path related) are not set.
    DEFAULT_CURR_PATH = '.'

    # :str: Default search pattern for additional log configuration files.
    DEFAULT_LOG_CFG_FILE_PATT = 'log_config*.ini'

    # :str: Default log level.
    DEFAULT_LOG_LEVEL = 'DEBUG'

    # :bool: Default msg level propagation to upper handlers.
    DEFAULT_LOG_PROPAGATE = False

    def __init__(self, **kwargs):
        """Constructor method for LoggingManager.
        """
        self._appctx = kwargs.pop('appctx', None)
        self._log_queue: Queue = kwargs.pop('log_queue', None)
        self._event_finnish: Event = kwargs.pop('event_finnish', None)
        super().__init__()

        # -----------------------------------------------------------------------------------------
        self.__valid_dbg_values = {'DEBUG': logging.DEBUG, 'INFO': logging.INFO,
                                   'WARNING': logging.WARNING, 'ERROR': logging.ERROR,
                                   'CRITICAL': logging.CRITICAL, 'NOTSET': logging.NOTSET}
        # -----------------------------------------------------------------------------------------
        # get env variables values
        log_level = self._appctx.config.get_param('log.level', self.DEFAULT_LOG_LEVEL)

        if log_level not in self.__valid_dbg_values:
            raise ValueError('Invalid value for parameter log.level ')

        # -----------------------------------------------------------------------------------------
        # used in log file name resolutions
        self.__regex = re.compile(r'\%\(([a-z0-9_\.]+)\)')

        # -----------------------------------------------------------------------------------------
        # set level to 'root' logger as NOTSET - this will leave for the handlers' log level
        # to decide
        root_logger = logging.getLogger()

        # Disable the default handler
        logging.lastResort.propagate = False

        proc_name = current_process().name
        if proc_name == 'MainProcess':

            root_logger.setLevel(logging.NOTSET)

            # -----------------------------------------------------------------------------------------
            # define log Formatters
            # log_formatter_str = self._appctx.config.get_param('log.format.msg', None)
            # log_formatter_datefmt = self._appctx.config.get_param('log.format.datefmt', None)

            # if log_formatter_str is None:
            #     raise ValueError('Log Message format is missing <log.format.msg>')

            # -----------------------------------------------------------------------------------------
            # if log_formatter_datefmt is None:
            #     log_fmt = logging.Formatter(log_formatter_str)
            # else:
            #     log_fmt = logging.Formatter(log_formatter_str, datefmt=log_formatter_datefmt)

            # -----------------------------------------------------------------------------------------
            # define log Handler if current output is displayed on some terminal
            # if sys.stdout.isatty():
                # log_handler = logging.StreamHandler()
                # log_handler.setLevel(self.__valid_dbg_values[log_level])
                # log_handler.setFormatter(log_fmt)
                # logging.getLogger().addHandler(log_handler)

            self.__create_file_handler(self._appctx.config, process_name=proc_name, **kwargs)

            # -----------------------------------------------------------------------------------------
            # set custom log level and handlers for additional Loggers (if any)
            log_cfg_file_srch_patt = self._appctx.config.get_param('log.config.files.pattern',
                                                        self.DEFAULT_LOG_CFG_FILE_PATT)

            for log_cfg_file in glob.glob(os.environ.get('FCDB_CFG_LOG_PATH', self.DEFAULT_CURR_PATH)
                                                         + '/' + log_cfg_file_srch_patt):
                try:
                    logger.debug('Processing log config file:<{}>'.format(log_cfg_file))
                    log_cfg = generic.Configuration(log_cfg_file)
                    self.__create_file_handler(log_cfg, **kwargs)

                except Exception:   # pylint: disable=broad-except
                    logger.exception('Error occured while processing log '
                                     'file:{}'.format(log_cfg_file))

            # in case a log queue was specified in the input
            # start the process that would retieve any log messages from the children
            if self._log_queue is not None:
                import atexit
                atexit.register(self.finish)

                self.start()

        # else if this is not the main process
        else:

            # then we just create a handler that writes all the logs to the log queue
            if self._log_queue is not None:

                # we create a handler that is a Queue to the main Process
                handler = logging.handlers.QueueHandler(self._log_queue)
                root_logger.addHandler(handler)
                # send only those messages as per the config
                root_logger.setLevel(self.__valid_dbg_values[log_level])

            # if no queue was specified
            else:
                # then we create a handler that writes all the log messages to File
                self.__create_file_handler(self._appctx.config, process_name=proc_name, **kwargs)

    # ----------------------------------------------------------------------------------------------
    def run(self):

        while True:
            try:
                if self._event_finnish and self._event_finnish.is_set():
                    break

                record = self._log_queue.get()
                if record is None:
                    break

                _logger = logging.getLogger(record.name)
                # handle the log message that we got from the queue
                _logger.handle(record)

            except EOFError:
                break

            except Exception:
                import traceback
                print('Error durring log handling:', file=sys.stderr)
                traceback.print_exc(file=sys.stderr)

        sys.exit(0)

    @property
    def log_queue(self):
        return self._log_queue

    # ----------------------------------------------------------------------------------------------
    def finish(self):

        if current_process().name == 'MainProcess':
            logging.getLogger(__name__).info(f'Finnishing the Log Receiver process')
            if getattr(self, '_finnish_done', None) is None and self._log_queue:
                self._finnish_done = True
                self._log_queue.put(None)
                self.join()
                self.close()

    # ----------------------------------------------------------------------------------------------
    def __create_file_handler(self, config, **kwargs):
        """Adds additional Handlers for specific logger as per input configuration file.

        Args:
            config (str): config file where additional Logger config parameters are specified.
        """
        log_namespace = config.get_param('log.namespace')
        if log_namespace is not None:

            # --------------------------------------------------------------------------------------
            if log_namespace == 'root':
                cfg_logger = logging.getLogger()
            else:
                cfg_logger = logging.getLogger(log_namespace)

            log_level = config.get_param('log.level', self.DEFAULT_LOG_LEVEL)
            if log_level not in self.__valid_dbg_values:
                raise ValueError('Invalid value for parameter log.level')

            file_name = config.get_param('log.file.name', None)

            if file_name:
                # ----------------------------------------------------------------------------------
                # lets resolve first the references (if any) to any other configuration parameters
                inner_prms = self.__regex.findall(file_name)

                for inner_prm in inner_prms:
                    inner_prm_val = kwargs.get(inner_prm, None)
                    if inner_prm_val is None:
                        logger.warning(f'Could not find value for parameter <{inner_prm}> specified in the log file name: <{file_name}>')
                        file_name = file_name.replace('%(' + inner_prm + ')', inner_prm)
                    else:
                        file_name = file_name.replace('%(' + inner_prm + ')', str(inner_prm_val))

                file_name = datetime.now().strftime(file_name)

            # --------------------------------------------------------------------------------------
            file_max_size = config.get_param('log.file.max.size')
            if file_max_size is None:
                logger.warning('Parameter log.file.max.size was set to default value:{}'
                                .format(self.DEFAULT_LOG_FILE_SIZE))
                file_max_size = self.DEFAULT_LOG_FILE_SIZE

            # --------------------------------------------------------------------------------------
            file_max_count = config.get_param('log.file.max.count')
            if file_max_count is None:
                logger.warning('Parameter log.file.max.count was set to default value:{}'
                                .format(self.DEFAULT_LOG_FILE_COUNT))
                file_max_count = self.DEFAULT_LOG_FILE_COUNT

            # --------------------------------------------------------------------------------------
            file_format_msg = config.get_param('log.format.msg', None)
            file_format_datefmt = config.get_param('log.format.datefmt', None)

            # --------------------------------------------------------------------------------------
            # validate input values
            if file_name is None or file_format_msg is None:
                logger.error('Mandatory value for <file.name|file.format.msg> is not set '
                             'in log config file')

            # --------------------------------------------------------------------------------------
            # create new Formatter
            if file_format_datefmt is None:
                file_fmt = logging.Formatter(file_format_msg)
            else:
                file_fmt = logging.Formatter(file_format_msg, datefmt=file_format_datefmt)

            # --------------------------------------------------------------------------------------
            # create new Rotating File Handler
            log_file_handler = logging.handlers.RotatingFileHandler(
                            os.environ.get('FCDB_LOG_PATH', self.DEFAULT_CURR_PATH) + '/'
                            + file_name.strip(),
                            # + file_name.replace('.log', '_' + str(os.getpid()) + '.log'),
                            'a', file_max_size, file_max_count, delay=True)

            cfg_logger.setLevel(self.__valid_dbg_values[log_level])
            log_file_handler.setLevel(self.__valid_dbg_values[log_level])
            log_file_handler.setFormatter(file_fmt)

            cfg_logger.propagate = config.get_param('log.propagate', self.DEFAULT_LOG_PROPAGATE)
            cfg_logger.addHandler(log_file_handler)
