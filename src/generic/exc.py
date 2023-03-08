"""
App defined exceptions

Copyright (c) 2020 to date, Binare Oy (license@binare.io) All rights reserved.
"""


class ApplicationException(Exception):
    """Generic Exception raised for all application related exceptions
    """


class ParameterException(ApplicationException):
    """Generic Exception raised for all application related exceptions
    """
    def __init__(self, parameter_name):
        super(ParameterException, self).__init__(
            f"Parameter is missing or not provided:{parameter_name}"
        )


# ------------------------------------------------------------------------------
class ValidationException(Exception):
    """Generic Exception raised for all validation activities
    """


# ------------------------------------------------------------------------------
class EntityNotFoundException(ValidationException):
    """Generic exception thrown at the event when needed entity is not found
    """
    def __init__(self, entity_type: str, entity_id: str, txt=''):
        super(EntityNotFoundException, self).__init__(
            f"{entity_type} ({entity_id}) not found {txt}"
        )
