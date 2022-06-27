"""Database models"""
import os
import uuid
from datetime import datetime
from collections import namedtuple

from environs import Env
from dynamorm import DynaModel, GlobalIndex, ProjectAll

from flowers.utils import password, generate_apikey, random_alias, bhash2, check_hash
from flowers.errors import MaximumAPIKeysExceeded

from flowers.schema import (
    UserSchema,
    APIKeySchema,
    APIKeyStatus,
)


FLOWERS_ENVIRONMENT = os.environ.get("FLOWERS_ENVIRONMENT")


DBConfig = namedtuple(
    "DBConfig",
    ["region_name", "aws_access_key_id", "aws_secret_access_key", "environment"],
)


class Config:

    _default_env = "staging"
    session_config = {}

    @classmethod
    def from_env(cls):
        """
        Reads config environment, try .env and then system env.

        On AWS, envs are injected automatically in the Lambda environment.
        """
        env = Env(eager=False, expand_vars=True)
        env.read_env()  # read .env file, if it exists, no recursion

        region_name = (
            env("FLOWERS_AWS_REGION_NAME")
            if env
            else os.environ.get("FLOWERS_AWS_REGION_NAME")
        )
        aws_access_key_id = (
            env("FLOWERS_AWS_ACCESS_KEY_ID")
            if env
            else os.environ.get("FLOWERS_AWS_ACCESS_KEY_ID")
        )
        aws_secret_access_key = (
            env("FLOWERS_AWS_SECRET_ACCESS_KEY")
            if env
            else os.environ.get("FLOWERS_AWS_SECRET_ACCESS_KEY")
        )
        environment = (
            env("FLOWERS_ENVIRONMENT") if env else os.environ.get("FLOWERS_ENVIRONMENT")
        )

        # persist in class object
        cls.session_config = {
            "region_name": region_name,
            "aws_access_key_id": aws_access_key_id,
            "aws_secret_access_key": aws_secret_access_key,
        }

        cls.environment = environment or cls._default_env
        return cls

    @classmethod
    def from_object(cls, cfg):
        "Set config from a config object"
        cls.session_config = {
            "region_name": cfg.region_name,
            "aws_access_key_id": cfg.aws_access_key_id,
            "aws_secret_access_key": cfg.aws_secret_access_key,
        }

        cls.environment = cfg.environment


class ModelMixin:
    """
    Mixin class for adding common functionalities to models
    """

    @classmethod
    def new_uuid(cls):
        suffix = cls.Table.uuid_suffix
        return f"{str(uuid.uuid4())}{suffix}"


class User(DynaModel, ModelMixin):
    class Table:
        name = f"flowers-{FLOWERS_ENVIRONMENT}-users"
        hash_key = "user_id"
        read = 25
        write = 5
        session_kwargs = Config.from_env().session_config
        uuid_suffix = "U"

    class ByEmail(GlobalIndex):
        name = "email"
        hash_key = "email"
        read = 25
        write = 5
        projection = ProjectAll()

    # Define our data schema, each property here will become a property on instances of the User class
    Schema = UserSchema


class APIKey(DynaModel, ModelMixin):

    # user can have max only 5 api keys at a time
    MAX_USER_APIKEYS = 50

    class Table:
        name = f"flowers-{FLOWERS_ENVIRONMENT}-apikeys"
        hash_key = "apikey_id"
        range_key = "owner_id"
        read = 25
        write = 5
        session_kwargs = Config.from_env().session_config
        uuid_suffix = "A"

    # Define our data schema
    Schema = APIKeySchema

    @classmethod
    def create(cls, user_id, alias=None):
        apikeys = cls.get_user_keys(user_id)
        if len(apikeys) >= cls.MAX_USER_APIKEYS:
            raise MaximumAPIKeysExceeded

        # TODO: custom datetime field: https://github.com/marshmallow-code/marshmallow/issues/656#issuecomment-318587611
        now = datetime.utcnow().replace(microsecond=0)
        alias = alias or random_alias()
        keyhash, keypass = generate_apikey()
        apikey = cls(
            salt=keyhash,
            status=APIKeyStatus.active,
            apikey_id=cls.new_uuid(),
            owner_id=user_id,
            creation_date=str(now),
            alias=alias,
        )
        apikey.save()
        return (apikey, keypass)

    @classmethod
    def get_user_keys(cls, user_id):
        return list(cls.scan(owner_id=user_id, status=APIKeyStatus.active))

    @classmethod
    def get_by_alias(cls, alias):
        return cls.get(alias=alias, status=APIKeyStatus.active)

    @classmethod
    def verify_by_user(cls, user_id, keypass):
        # get apikeys belonging to user
        apikeys = cls.get_user_keys(user_id)
        # check if any of the user's apikeys passes hash check with the given hash
        return any(
            filter(lambda key: check_hash(keypass, key.salt.encode("utf-8")), apikeys)
        )

    @classmethod
    def verify(cls, keypass):
        """Iterates through all api keys and attempts to find a match"""
        apikeys = list(cls.scan(status=APIKeyStatus.active))
        # check if any of the user's apikeys passes hash check with the given hash
        results = list(
            filter(lambda key: check_hash(keypass, key.salt.encode("utf-8")), apikeys)
        )
        return results[0] if results else None

    @classmethod
    def get(cls, **kwargs):
        kwargs.update(status=APIKeyStatus.active)
        results = list(cls.scan(**kwargs))
        return results[0] if results else None

    @classmethod
    def revoke(cls, **kwargs):
        key = cls.get(**kwargs)
        # TODO: maybe mark as 'revoked' and don't delete
        # TODO: why this fails? key.update(status=APIKeyStatus.revoked)
        key.status = APIKeyStatus.revoked
        key.save()

    def delete(self):
        self.revoke(alias=self.alias)
