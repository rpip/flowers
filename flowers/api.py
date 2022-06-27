"""
Serverless API service handler.

TODO:
- Request and response schema for the API endpoints
- Internal and external API
- Authentication & Authorization: persistent API keys
"""
import os
import json
from contextlib import contextmanager
from functools import reduce

from flowers.utils import let, decode_auth_token, Enum
from flowers.errors import (
    InvalidAuthentication,
    MaximumAPIKeysExceeded,
    PermissionDenied,
    ValidationError,
    RequestAborted,
    RouteNotFound,
    ServiceError,
)
from flowers.db import APIKey, User

API_AUTH_HEADER_KEY = "X-FLOWERS-KEY"


class AuthTypes(Enum):
    Cognito = "cognito"
    APIKey = "apikey"


@contextmanager
def recovery(func, args):
    try:
        result = func(*args)
    except (
        MaximumAPIKeysExceeded,
        PermissionDenied,
        ValidationError,
        RequestAborted,
        InvalidAuthentication,
        RouteNotFound,
        ServiceError,
    ) as err:
        yield None, err
    else:
        yield result, None


class Service:
    routes = []
    middlewares = []
    _default_middlewares = []
    _default_headers = {"Content-Type": "application/json"}

    @classmethod
    def resolve(cls, method, path):
        """
        Attempts to find a match for the method and path to the configured service routes.

        Returns first matching route, otherwise None
        """
        # TODO: raise 404 on missing route. or routing check is done at the infra/network layer?
        results = list(
            filter(
                let(
                    lambda http_methods, http_path, _handler: method.lower()
                    in map(str.lower, http_methods)
                    and http_path.lower() == path.lower()
                ),
                cls.routes,
            )
        )

        if not results:
            route = None
            # if no match in define routes, use the fallback resolver
            if hasattr(cls, "fallback_resolver"):
                handler = cls.fallback_resolver(event)
                if handler:
                    route = (method, path, handler)

            if not route:
                raise RouteNotFound

        # return results[0] if results
        return results[0]

    @classmethod
    def handle(cls, event, context):
        """
         Calls the handler function/class to process the event and returns the results.
         Returns a Response object which is finally serialized to JSON.

        # TODO
         - auth error handling
         - validation errors
        """
        path = event["path"]
        method = event["httpMethod"]
        payload = json.loads(event.get("body") or "{}")
        # set env. TODO: maybe move to meta field?
        env = os.environ["FLOWERS_ENVIRONMENT"]
        event["flowers_environment"] = env
        # set meta fields: user ID, user IP etc
        event["meta"] = cls._build_meta(event)

        # find the handler
        (_methods, _path, handler) = cls.resolve(method, path)
        # (status, body, headers) = cls.middleware_chain(handler, event, context)
        with recovery(cls.middleware_chain, [handler, event, context]) as (result, err):
            headers = cls._default_headers
            if not err:
                (status, body, new_headers) = result
                headers.update(new_headers)
            else:
                # log err etc
                status, body = err.code, err._error

        # return response
        response = {
            "statusCode": status,
            "body": body,
            "headers": headers,
        }
        return response

    @classmethod
    def _build_meta(cls, event):
        jwt_sub = (
            event.get("requestContext", {})
            .get("authorizer", {})
            .get("claims", {})
            .get("sub")
        )
        return {
            "user_ip": event.get("requestContext", {})
            .get("identity", {})
            .get("sourceIp")
        }

    @classmethod
    def middleware_chain(cls, handler, event, context):
        # init middlewars with the service
        middlewares = [m(cls) for m in cls._default_middlewares + list(cls.middlewares)]
        # Code to be executed for each request before
        # the handler (and later middleware) are called.
        event_acc = reduce(
            lambda e_acc, m: m.process_event(e_acc)
            if hasattr(m, "process_event")
            else e_acc,
            middlewares,
            event,
        )
        response = handler(event_acc)
        # Code to be executed for each request/response after the handler is called.
        final_response = reduce(
            lambda r_acc, m: m.process_response(r_acc)
            if hasattr(m, "process_response")
            else r_acc,
            middlewares,
            response,
        )
        # check if response has headers
        # response = (status, body, headers) | (status, body)
        if len(final_response) == 3:
            (status, body, headers) = final_response
        else:
            (status, body, headers) = (*final_response, {})

        return (status, body, headers)

    @classmethod
    def run(cls, event, context):
        return cls.handle(event, context)


class Middleware:
    """
    Middlewares hook into the request/response processing.
    It's a light, low-level plugin system for globally altering the input or output.
    """

    def __init__(self, service):
        self.service = service

    def process_event(self, event):
        # pre event processing
        return event

    def process_response(self, response):
        # post event processing
        return response


def demo_function_middleware(f):
    "Example function showing how middlewares can be used"

    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Code to be executed for each request before
        # the handler (and later middleware) are called.
        response = f(*args, **kwargs)
        # Code to be executed for each request/response after
        # the handler is called.
        return response

    return decorated_function


class AuthenticationMiddleware(Middleware):
    """
    Checks if the event has validation annotations(api keys, JWT etc) and validates the event.

    Internal requests are authenticated by Cognito and auth info is in the requestContect.authorizer field.
    Unauthenticated internal requests, do not have the requestContext.authorizer field

    External requests are authenticated using API keys. If api key is present in the request header,
    validate that it's valid API key and proceed. Otherwise, abort if endpoint is proctected resource.

    If authentication is valid, adds the auth details to the event. Otherwise, raises InvalidAuthentication error

    {
        "is_authenticated": True,
        "type": "jwt | apikey",
        "user_id": username,
        "scope": "public | internal"
    }
    """

    def process_event(self, event):
        # event["meta"]["auth"] = auth_info
        # event['requestContext']['authorizer']['claims']['sub']}U"
        # first attempt to validate as external/API key
        authenticated = self._validate_apikey(event)

        # if that fails, try internal/JWT
        if not authenticated:
            authenticated = self._validate_jwt(event)

        # extract auth details
        if authenticated:
            (user_info, auth_type) = authenticated
            # TODO: ensure username ends with U suffix
            # for permissions, we'll need API key alias
            if not user_info["user_id"].endswith(User.Table.uuid_suffix):
                user_info["user_id"] = user_info["user_id"] + User.Table.uuid_suffix

            event["meta"]["auth"] = {"user": user_info, "type": auth_type}

            return event

        # else, raise Exception
        # TODO: maybe add auth_type to the exception to generate Cognito auth policy
        raise InvalidAuthentication

    def _is_apikey(self, event):
        apikey = event["headers"].get(API_AUTH_HEADER_KEY)
        return bool(apikey)

    def _is_jwt(self, event):
        jwt_authorizer = event.get("requestContext", {}).get("authorizer")
        auth_token = event["headers"].get("authorization")
        return jwt_authorizer and auth_token

    def _get_jwt_authorizer(self, event):
        "Returns auth detaisl from authenticated cognito session. Otherwise, returns Non"
        request_context = event.get("requestContext")
        if request_context and request_context.get("authorizer"):
            return request_context["authorizer"]["claims"]

    def _validate_jwt(self, event):
        if self._is_jwt(event):
            # If internal call and authenticated, should have JWT in the request context
            user_details = self._get_jwt_authorizer(event)
            if not user_details:
                # fallback on bearer authentication. AWS Cognito adds the bearer auth header
                auth_token = event["headers"].get("authorization")
                if auth_token:
                    # verify the JWT
                    user_details = decode_auth_token(auth_token)

            user_info = dict(user_id=user_details["username"])
            return (user_info, AuthTypes.Cognito) if user_details else None

    def _validate_apikey(self, event):
        # TODO: maybe use apikey.alias and username for logging and request-scope tagging
        # assume header key is string
        keypass = event["headers"].get(API_AUTH_HEADER_KEY)
        if keypass:
            try:
                apikey = APIKey.verify(keypass)
                if apikey:
                    user_info = dict(
                        user_id=apikey.owner_id,
                        apikey=dict(apikey_id=apikey.apikey_id, alias=apikey.alias),
                    )

                    return (
                        user_info,
                        AuthTypes.APIKey,
                    )
            except Exception as err:
                raise InvalidAuthentication


class LoggingMiddleware(Middleware):
    def process_event(self, event):
        pass


class RecoveryMiddleware(Middleware):
    """
    Recovery middleware recovers from any panics and writes a 500 if there was one.

    Also send 500x etc errors to PagerDuty
    """

    def process_event(self, event):
        pass
