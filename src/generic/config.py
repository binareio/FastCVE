"""
Class to facilitate management of the application's configuration.

Copyright (c) 2020 to date, Binare Oy (license@binare.io) All rights reserved.
"""

import os
import logging
import configparser
import re

# --------------------------------------------------------------------------------------------------
LOGGER = logging.getLogger(__name__)
# --------------------------------------------------------------------------------------------------


class Configuration:
    """Configuration related class to retrieve and resolve configration parameters."""

    # ----------------------------------------------------------------------------------------------
    def __init__(self, config_file):
        """Constructor method for Configuration class.

        Args:
            config_file (str): Configuration file that should be read for config parameters

        Raises:
            RuntimeError: when the following will occur:
                - when `config_file` cannot be read or accessed
                - when `config_file` is not specified
        """


        self.__prms = {}
        self.__cfg = None
        self.__filename = None
        self.__parse_all_ind = False
        # ------------------------------------------------------------------------------------------
        if config_file is None:
            raise RuntimeError('Input Configuration file(s) was not specified')
        else:
            if not os.access(config_file, os.R_OK):
                raise RuntimeError('Specified configuration file '
                                   '<{}> cannot be read.'.format(config_file))

        # ------------------------------------------------------------------------------------------
        if self.__cfg is None:
            self.__cfg = configparser.RawConfigParser()

        try:
            self.__cfg.read(config_file)
            self.__filename = config_file
        except Exception:   # pylint: disable=broad-except
            raise RuntimeError('Error occured while trying to '
                               'read config file: <{}>'.format(config_file))

        # ------------------------------------------------------------------------------------------
        includes = self.get_param('include.config_files')
        if includes is not None:
            for include in includes.split(':'):
                if os.access(include, os.R_OK):
                    try:
                        self.__cfg.read(include)
                    except Exception:   # pylint: disable=broad-except
                        LOGGER.error(f'Error while reading include config file <{include}>')

    # ----------------------------------------------------------------------------------------------
    def __parse_all(self):
        """
        Parses and evaluate all parameters from input config file.
        """
        # ------------------------------------------------------------------------------------------
        # Parse all config params if it was not yet done
        if not self.__parse_all_ind:

            for section in self.__cfg:
                for param in self.__cfg[section]:
                    self.get_param(section + '.' + param)

        self.__parse_all_ind = True

    # ----------------------------------------------------------------------------------------------
    def check_params(self, search_name):
        """Returns a list of parameter names which contains ``search_name`` in their name.

        Args:
            search_name (str): search all parameters that contain ``search_name``
        """
        self.__parse_all()
        return list(filter(lambda x: search_name in x, self.__prms.keys()))

    # ----------------------------------------------------------------------------------------------
    def get_param(self, param_name, default_value=None, iteration=0):

        """Retrieves value of a given parameter name ``param_name`` as input.

        Args:
            param_name (str): Name of the parameter i.e. ``section.name.subname``.
            default_value (Any): default value to be returned in case ``param_name`` cannot
                be found. Optional parameter.
            iteration (int): used internally to avoid recurssion.

        Returns:
            value of parameter ``param_name`` if found, ``default_value`` otherwise.

        Raises:
           RecursionError: When infinite recurssion is identified.

        """
        # ------------------------------------------------------------------------------------------
        # in case such parameter was retrieved previously return it from cache
        if param_name in self.__prms:
            return self.__prms[param_name]

        # ------------------------------------------------------------------------------------------
        # split name of input parameter by . and check if there is such section in config file
        param_splt = param_name.split('.', 1)
        if param_splt[0] not in self.__cfg:
            return default_value

        # ------------------------------------------------------------------------------------------
        else:

            # if Section exists but parameter name doesn't
            if param_splt[1] not in self.__cfg[param_splt[0]]:
                return default_value
            else:
                prm_val = self.__cfg[param_splt[0]][param_splt[1]]

                # ----------------------------------------------------------------------------------
                # if we end up with a parameter that in order to resolve its value we need to
                # recursively call same method more than 10 times then we throw exception.
                iteration += 1
                if iteration > 10:
                    raise RecursionError('Recursion was identified for param: '
                                         '<{}>'.format(param_name))

                # ----------------------------------------------------------------------------------
                # lets resolve first the references (if any) to any other configuration parameters
                regex = re.compile(r'\${([a-z0-9_\.]+)}')
                inner_prms = regex.findall(prm_val)

                for inner_prm in inner_prms:
                    inner_prm_val = self.get_param(inner_prm, None, iteration)
                    if inner_prm_val is None:
                        LOGGER.warning(f'Inner config parameter: <{inner_prm}> is not defined.')
                    else:
                        prm_val = prm_val.replace('${' + inner_prm + '}', str(inner_prm_val))

                # ----------------------------------------------------------------------------------
                # resolve env variables (if any )
                regex = re.compile(r'\${([^}]+)}')
                inner_prms = regex.findall(prm_val)

                for inner_prm in inner_prms:
                    inner_prm_val = os.environ.get(inner_prm, '')
                    prm_val = prm_val.replace('${' + inner_prm + '}', str(inner_prm_val))

                # ----------------------------------------------------------------------------------
                try:
                    eval_prm_val = eval(prm_val)
                except Exception:   # pylint: disable=broad-except
                    pass
                else:
                    prm_val = eval_prm_val

                # ----------------------------------------------------------------------------------
                self.__prms[param_name] = prm_val
                self.__cfg[param_splt[0]][param_splt[1]] = str(prm_val)

                return prm_val

    # ----------------------------------------------------------------------------------------------
    def save_config(self, filename):
        """Saves current configuration settings from memory to a ini file.

        Note:
            This method is usefull for reference and debug.

        Args:
            filename(str): full file name where configuration file is expected to be saved.

        Raises:
             NotADirectoryError.

        """

        # ------------------------------------------------------------------------------------------
        if self.__filename is None:
            return False

        # ------------------------------------------------------------------------------------------
        # first make sure to parse all configuration settigs in order to resolve their values
        # before saving results to file
        self.__parse_all()

        # ------------------------------------------------------------------------------------------
        # Check first if provided path exists and its writable
        try:
            with open(filename, 'w') as configfile:
                self.__cfg.write(configfile)
            return True
        except Exception:   # pylint: disable=broad-except
            raise NotADirectoryError('Provided directory <{}> cannot be accessed '
                                     'or is not a directory'.format(os.path.dirname(filename)))

