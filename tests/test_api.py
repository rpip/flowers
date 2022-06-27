from flowers.api import Service, Middleware
from user_service import UserService

import os
from http import HTTPStatus
from conftest import lambda_fixtures


class PingPongService(Service):
    # event handlers
    ping = lambda event: (HTTPStatus.OK, "PONG")
    hello = lambda event: (HTTPStatus.OK, "Hello world!", headers)

    routes = [(["GET"], "/hello", hello), (["GET"], "/ping", ping)]


class TestAPI:
    def test_get_user(self):
        user_event_patch = {"httpMethod": "GET", "path": "/user", "resource": "/users"}
        (event, context) = lambda_fixtures(user_event_patch)
        response = UserService.run(event, context)
        assert response["statusCode"] == HTTPStatus.OK and response["body"]

    def test_pingpong_handlers(self):
        event_patch = {"httpMethod": "GET", "path": "/ping", "resource": "/ping"}
        (event, context) = lambda_fixtures(event_patch)
        response = PingPongService.run(event, context)
        assert response["statusCode"] == HTTPStatus.OK and response["body"] == "PONG"

    def test_find_route(self):
        method = "GET"
        path = "/hello"
        # route = (http_methods, path, handler)
        route = PingPongService.resolve(method, path)
        assert len(route[0]) == 1 and route[0][0] == method and route[1] == path.lower()

    def test_parameters_parse(self):
        pass


class PingLoggingMiddleware(Middleware):
    def process_event(self, event):
        import logging
        import json

        print(f"{self.service} ==> {json.dumps(event)}")
        return event


class HelloWorldService(Service):
    middlewares = (PingLoggingMiddleware,)
    hello = lambda event: (HTTPStatus.OK, "Hello world!")

    routes = [(["GET"], "/hello", hello)]


class TestMiddleware:
    def test_logging(self):
        event_patch = {"httpMethod": "GET", "path": "/hello", "resource": "/hello"}
        (event, context) = lambda_fixtures(event_patch)
        response = HelloWorldService.run(event, context)
        assert (
            response["statusCode"] == HTTPStatus.OK
            and response["body"] == "Hello world!"
        )
