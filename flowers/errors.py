import six
from http import HTTPStatus
from collections import namedtuple

from flowers.utils import Enum

ErrorDetail = namedtuple("ErrorDetail", ["kind", "type", "message", "details"])


class ErrorTypes(Enum):
    PermissionDenied = 1
    ValidationError = 2
    RequestAborted = 3
    InvalidAuthentication = 4
    InvalidAuthentication = 4


class Error(Exception):
    """Base class for other exceptions

    Eg: raise ValidationError(details=errors)
    """

    code = HTTPStatus.INTERNAL_SERVER_ERROR
    message = "A server error occurred."
    # The type of error returned
    type = "error"
    details = {}

    def __init__(self, type=None, message=None, details=None):
        self.type = type or self.type
        self.message = message or self.message
        self.details = details or self.details

        self._error = self._details(self.type, self.message, self.details)

    def _details(self, type, message, details):
        err = ErrorDetail(kind="error", type=type, message=message, details=details)

        return err._asdict()

    def __str__(self):
        return six.text_type(self._error)


class MaximumAPIKeysExceeded(Error):
    code = HTTPStatus.FORBIDDEN
    message = "You have exceeded maximum of 5 API keys"


class ValidationError(Error):
    code = HTTPStatus.BAD_REQUEST
    type = "invalid_params"
    message = "The parameters of your request were missing or invalid."


class PermissionDenied(Error):
    code = HTTPStatus.UNAUTHORIZED
    type = "permission_denied"
    message = "You do not have permission to perform this action."


class RequestAborted(Error):
    code = HTTPStatus.BAD_REQUEST
    type = "bad_request"
    message = "You do not have permission to perform this action."


class InvalidAuthentication(Error):
    """
    Authentication error due to invalid or missing authentication info.
    """

    code = HTTPStatus.FORBIDDEN
    message = "Invalid authentication"
    type = "authentication_error"


class RouteNotFound(Error):
    """Exception raised for errors when route is not found"""

    code = HTTPStatus.NOT_FOUND
    message = "Not found."
    type = "not_found"


class ServiceError(Error):
    # systemerror
    pass
