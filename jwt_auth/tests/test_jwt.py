"""Tests for the JWT class
"""
import pytest

import jwt

from jwt_auth.tests.fixtures import *  # noqa
from jwt_auth.jwt import JWT


class TestInit:
    """Test that the class is initialized properly
    """

    @staticmethod
    def test_payload(make_jwt):
        """Test that the payload is set properly
        """
        # Make some data
        payload = {
            'item1': 'value1',
            'item2': 2,
        }
        jwt_string = make_jwt(key='secret', **payload)

        # Initialize the JWT object
        token = JWT(jwt_string, ['secret'])

        # Test our expectataions
        assert token.payload == payload

    @staticmethod
    def test_multiple_keys(make_jwt):
        """Test that multiple keys are supported
        """
        # Make some data
        payload = {
            'item1': 'value1',
            'item2': 2,
        }
        jwt_string = make_jwt(key='secret', **payload)

        # Initialize the JWT object
        token = JWT(jwt_string, ['other secret', 'secret'])

        # Test our expectataions
        assert token.payload == payload

    @staticmethod
    def test_payload_bad_key(make_jwt):
        """Test that accessing the payload with a bad key gives an error.
        """
        # Make some data
        payload = {
            'item1': 'value1',
            'item2': 2,
        }
        jwt_string = make_jwt(key='not a good key', **payload)

        # Initialize the JWT object
        token = JWT(jwt_string, ['secret'])

        # Test our expectataions
        with pytest.raises(jwt.InvalidSignatureError):
            token.payload
