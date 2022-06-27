Common libraries for writing services/applications.

A service is a routing layers that plugs in event handlers.

In each service, you map HTTP endpoints to corresponding event handlers.


## Requirements

* [pipenv dev workflow](https://pipenv.pypa.io/en/latest/)
* [jq command line JSON processir](https://stedolan.github.io/jq/)
* [DynamoDB Local](https://formulae.brew.sh/cask/dynamodb-local)

## Installation

* Overview of the Makefile commands: `$ make help`
* Install dependencies: `$ make init`
* Get into the shell: `$ pipenv shell`

## Documentation

### Basic Service

``` python
from flowers.api import Service

class PingPongService(Service):
    # event handlers
    ping = lambda event: (HTTPStatus.OK, "PONG")
    hello = lambda event: (HTTPStatus.OK, "Hello world!", headers)

    routes = [(["GET"], "/hello", hello), (["GET"], "/ping", ping)]

```

### Using middlewares

``` python
import logging
import json
from flowers.api import Service, Middleware

class AuthMiddleware(Middleware):
    def process_event(self, event):
        pass

class PingLoggingMiddleware(Middleware):
    def process_event(self, event):
        print(f"{self.service} ==> {json.dumps(event)}")
        return event


class HelloWorldService(Service):
    middlewares = (PingLoggingMiddleware, AuthMiddleware)
    hello = lambda event: (HTTPStatus.OK, "Hello world!")
```

See `tests` for more examples on how to use this.
