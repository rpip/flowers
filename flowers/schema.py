"""schema for the data types

TODO:
- represent enum fields
- custom validation for certain fields
"""
__all__ = [
    "UUIDField",
    "UserSchema",
    "APIKeySchema",
]


from datetime import date

from marshmallow import Schema, fields, validate

from flowers.utils import Enum


class UUIDField(fields.Field):
    """Field that represents the flowers UUID"""

    def _serialize(self, value, attr, obj, **kwargs):
        return value

    def _deserialize(self, value, attr, data, **kwargs):
        if value and (not valid_uuid(value)):
            raise ValidationError("Invalid UUID format")

        return value


class UserSchema(Schema):
    """
    User table schema

    Fields:
    * user ID: Unique flowers User ID
    * status: Whether the user is active or not
    * last_login: Last login date
    * mfa_enabled: Whether the user has MFA enabled or not
    * email: User's email they used to sign up
    * creation_date: Date user signed up
    * email_verified: Whether the user verified their email or not
    * last_email_sent: Tracks the last email sent to the user. Used for email rate limiting
    """

    user_id = fields.Str()
    # TODO: check the possible values. enabled | ...
    status = fields.Str()  #
    last_login = fields.DateTime()
    mfa_enabled = fields.Bool()
    email = fields.Email()
    creation_date = fields.DateTime()
    email_verified = fields.Bool()
    points_earned = fields.Int()
    photos = fields.Int()
    last_email_sent = fields.Dict()
    type = fields.Str()  # TODO: get list possible values. user | ...


class APIKeyStatus(Enum):
    revoked = "revoked"
    active = "active"


class APIKeySchema(Schema):
    """
    APIKey schema

    Fields
    -------
    * apikey_id: Unique ID of the API key
    * alias: alias name for the API key
    * owner_id: Owner ID of the API key
    * status: status of the keys: revoked | active
    * creation_date: Date the export was created
    """

    apikey_id = fields.Str()
    alias = fields.Str()
    owner_id = fields.Str()
    status = fields.Str(validate=validate.OneOf(choices=APIKeyStatus.values()))
    salt = fields.Str()
    creation_date = fields.DateTime()
