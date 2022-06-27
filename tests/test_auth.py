from http import HTTPStatus

from flowers.api import (
    Service,
    AuthTypes,
    AuthenticationMiddleware,
    API_AUTH_HEADER_KEY,
)
from flowers.db import APIKey
from flowers.errors import InvalidAuthentication

from conftest import lambda_fixtures


class AuthService(Service):
    middlewares = (AuthenticationMiddleware,)

    # event handlers
    cognito = lambda event: (HTTPStatus.OK, event["meta"]["auth"])
    ext_apikey = lambda event: (HTTPStatus.OK, event["meta"]["auth"])

    routes = [(["GET"], "/cognito", cognito), (["GET"], "/ext", ext_apikey)]


class NoAuthService(Service):
    pass


class TestAPIAuth:
    def test_jwt(self):
        event_patch = {"httpMethod": "GET", "path": "/cognito", "resource": "/cognito"}
        (event, context) = lambda_fixtures(event_patch)
        response = AuthService.run(event, context)
        assert (
            response["statusCode"] == HTTPStatus.OK
            and response["body"]["type"] == AuthTypes.Cognito
        )

    def test_unauthenticated_jwt(self):
        # patch: 1) add unauthenticated request context, and 2) remove authorization header
        pass

    def test_valid_apikeys(self, flowers_fixtures):
        # generate api key -> add to header
        user = flowers_fixtures["user"]
        apikey, keypass = APIKey.create(user_id=user["user_id"])
        # patch: add apikey field

        def event_patch(evt):
            evt.update({"httpMethod": "GET", "path": "/ext", "resource": "/ext"})
            evt["headers"][API_AUTH_HEADER_KEY] = keypass
            evt["requestContext"] = _UNAUTHENTICATED_REQUEST_CONTEXT

        (event, context) = lambda_fixtures(event_patch)
        response = AuthService.run(event, context)
        assert (
            response["statusCode"] == HTTPStatus.OK
            and response["body"]["type"] == AuthTypes.APIKey
        )

    def test_null_apikeys(self, flowers_fixtures):
        # test missing no api key
        # patch: nullify apikey field
        # generate api key -> add to header
        user = flowers_fixtures["user"]
        # patch: add apikey field

        def event_patch(evt):
            evt.update({"httpMethod": "GET", "path": "/ext", "resource": "/ext"})
            evt["requestContext"] = _UNAUTHENTICATED_REQUEST_CONTEXT

        (event, context) = lambda_fixtures(event_patch)
        response = AuthService.run(event, context)
        assert (
            response["statusCode"] == HTTPStatus.FORBIDDEN
            and response["body"]["type"] == InvalidAuthentication.type
        )

    def test_invalid_apikeys(self, flowers_fixtures):
        # key is present, but invalid
        # patch: add invalid apikey field
        user = flowers_fixtures["user"]
        # patch: add apikey field

        def event_patch(evt):
            evt.update({"httpMethod": "GET", "path": "/ext", "resource": "/ext"})
            evt["requestContext"] = _UNAUTHENTICATED_REQUEST_CONTEXT
            evt["headers"][API_AUTH_HEADER_KEY] = "some-87567-random-3456-key"

        (event, context) = lambda_fixtures(event_patch)
        response = AuthService.run(event, context)
        assert (
            response["statusCode"] == HTTPStatus.FORBIDDEN
            and response["body"]["type"] == InvalidAuthentication.type
        )

    def test_revoked_apikey(self, flowers_fixtures):
        # key is present, but has been revoked
        # generate api key -> revoke -> make request
        # patch: add revoked apikey field
        user = flowers_fixtures["user"]
        apikey, keypass = APIKey.create(user_id=user["user_id"])

        def event_patch(evt):
            evt.update({"httpMethod": "GET", "path": "/ext", "resource": "/ext"})
            evt["headers"][API_AUTH_HEADER_KEY] = keypass
            evt["requestContext"] = _UNAUTHENTICATED_REQUEST_CONTEXT

        # revoke key
        apikey.delete()

        (event, context) = lambda_fixtures(event_patch)
        response = AuthService.run(event, context)
        assert (
            response["statusCode"] == HTTPStatus.FORBIDDEN
            and response["body"]["type"] == InvalidAuthentication.type
        )


_UNAUTHENTICATED_REQUEST_CONTEXT = {
    "requestContext": {
        "accountId": "498537461460",
        "apiId": "pni3sk6ezi",
        "domainName": "7cwrwu4xxi.execute-api.us-west-2.amazonaws.com",
        "domainPrefix": "7cwrwu4xxi",
        "extendedRequestId": "bNtghjMCvHcEJMw=",
        "httpMethod": "GET",
        "identity": {
            "accessKey": "None",
            "accountId": "None",
            "caller": "None",
            "cognitoAmr": "None",
            "cognitoAuthenticationProvider": "None",
            "cognitoAuthenticationType": "None",
            "cognitoIdentityId": "None",
            "cognitoIdentityPoolId": "None",
            "principalOrgId": "None",
            "sourceIp": "44.242.118.94",
            "user": "None",
            "userAgent": "Go-http-client/1.1",
            "userArn": "None",
        },
        "path": "/user",
        "protocol": "HTTP/1.1",
        "requestId": "bNtghjMCvHcEJMw=",
        "requestTime": "23/Feb/2021:19:50:01 +0000",
        "requestTimeEpoch": 1614109801658,
        "resourceId": "GET /user",
        "resourcePath": "/user",
        "stage": "$default",
    }
}
