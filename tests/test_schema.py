import sys
import os


from flowers.schema import UserSchema


def test_invalid_model_field():
    """
    Should fail if an invalid/unknown field is specified in any operation
    """
    pass


class TestModelSchema:
    """
    Tests serialization and deserialization of data from/to the model

    Fails if defined schema does not match the retrieved data.
    """

    def test_user_schema(self, flowers_fixtures):
        schema = UserSchema()
        errors = schema.validate(data=flowers_fixtures["user"])
        assert errors == {}

    def test_uuid(self):
        """
        Check UUID field validates and catches invalid formats.

        1. Basic validation: digits-model-suffix, eg: 6afacbd3-77d6-4354-9ef5-ef90f5fd3dddU
        2. Enhanced validation: UUID is correct format and matches the model, so Node UUID should not be in a User model/schema
        """
        pass
