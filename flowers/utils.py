import re
import enum
import secrets
import bcrypt
import inspect
from typing import Union, Optional

from haikunator import Haikunator
import jwt


def valid_uuid(uuid):
    # "^[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}[NUED]\Z"
    regex = re.compile(
        "^[a-f0-9]{8}-?[a-f0-9]{4}-?4[a-f0-9]{3}-?[89ab][a-f0-9]{3}-?[a-f0-9]{12}[NUED]\Z",
        re.I,
    )
    match = regex.match(uuid)
    return bool(match)


def let(*funcs):
    "Where each lambda receives arguments from the previous one."

    def wrap(args):
        result = args
        for func in funcs:
            if not isinstance(result, tuple):
                result = (result,)
            result = func(*result)
        return result

    return wrap


def decode_auth_token(auth_token: str, secret: str) -> Optional[dict]:
    """ Decodes the auth token """
    try:
        # remove "Bearer " from the token string.
        auth_token = auth_token.replace("Bearer ", "")
        # decode using system environ $SECRET_KEY, will crash if not set.
        return jwt.decode(auth_token.encode(), secret)
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        # TODO: move error handling to service process layer
        # 'Signature expired. Please log in again.'
        # 'Invalid token. Please log in again.'
        # return Error.INVALID_AUTH_TOKEN
        return


def generate_apikey():
    "Returns (salt, hashed) combination for API keys"
    keypass = password()
    (_salt, keyhash) = bhash2(keypass)
    # return pw as salt. hashed = bcrypt_salt + pw
    return (keyhash, keypass)


def password():
    # base64.b64encode(os.urandom(length))
    return secrets.token_hex(32).encode("utf-8")


def bhash2(key, rounds=None):
    """
    Adds a fixed-length cryptographically-strong random salt
    to the input to create unique hashes for every input
    """
    rounds = rounds or 14
    salt = bcrypt.gensalt(rounds=rounds)
    hashed = bcrypt.hashpw(key, salt)
    return (salt, hashed)


def check_hash(keypass, keyhash):
    "Returns True if hashed was created with the associated salt. Otherwise, False"
    return bcrypt.checkpw(keypass, keyhash)


class Enum:
    """
    Simple Enum module.

    Maps class attributes to values of any type
    """

    @classmethod
    def as_dict(cls):
        _d = {}

        for (name, val) in inspect.getmembers(cls):
            # Ignores anything starting with underscore
            # (that is, private and protected attributes)
            # Ignores methods
            if not name.startswith("_") and not inspect.ismethod(val):
                _d[name] = val

        return _d

    @classmethod
    def keys(cls):
        return cls.as_dict().keys()

    @classmethod
    def values(cls):
        return cls.as_dict().values()


def random_alias():
    "Generates unique random IDs for user API keys"
    namegen = Haikunator()
    return namegen.haikunate(token_hex=True, token_length=6)
