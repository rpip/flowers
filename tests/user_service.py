import logging
from http import HTTPStatus
import boto3

from flowers.db import User
from flowers.api import Service
from flowers.api import AuthenticationMiddleware
from flowers.serializers import UserSerializer


# TODO: runtime config of SSM with system env or pass in configs
ssm = boto3.client("ssm")

logging.basicConfig(level=logging.DEBUG)


def GetUser(event):
    # validate -> process -> reponse
    logging.debug("Running GetUser...")
    user_id = event["meta"]["auth"]["user"]["user_id"]
    user = User.get(user_id=user_id)

    serializer = UserSerializer()
    response = serializer.serialize(user, user)

    logging.debug("Returning user data")
    return (HTTPStatus.OK, response)


def CheckInvite(event):

    logging.debug("Running CheckInvite...")
    invite = event["payload"]["code"]
    logging.debug("%s Received code: ", invite)

    parameter = ssm.get_parameter(
        Name=f"/system/{event['flowers_environment']}/INVITE_CODES"
    )
    codes = parameter["Parameter"]["Value"].split(",")
    found = list(filter(lambda code: code.lower() == invite.lower(), codes))
    allowed = True if found else False

    logging.debug("%s Code is " + str(allowed))
    return (HTTPStatus.OK, {"granted": allowed})


class UserService(Service):

    # TODO: test route not found

    middlewares = (AuthenticationMiddleware,)

    routes = [(["GET"], "/user", GetUser), (["GET"], "/user/invite", CheckInvite)]
