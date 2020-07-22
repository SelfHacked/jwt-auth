"""Tests for the JWS class."""
import responses
from django.test import override_settings

from jwt_auth.tests.fixtures import *  # noqa
from jwt_auth.jwt import JWT


class TestJws:
    """Test JWS token decode."""

    @staticmethod
    @responses.activate
    @override_settings(JWT_AUTH={'JWKS_ENDPOINT': 'http://test.com'})
    def test_payload(private_key):
        """Test that the payload is set properly."""
        responses.add(
            responses.GET, 'http://test.com',
            json=make_jwks(private_key),
        )

        # Make some data
        jws_string = make_jws(private_key, 'TEST_VALUE')

        # Initialize the JWT object
        token = JWT(jws_string, [])

        # Test our expectataions
        assert token.payload['value'] == 'TEST_VALUE'

    @staticmethod
    @responses.activate
    @override_settings(JWT_AUTH={'JWKS_ENDPOINT': 'http://test.com'})
    def test_payload_bad_key(private_key):
        """Test that accessing the payload with a bad key gives an error.
        """
        responses.add(
            responses.GET, 'http://test.com',
            json=make_jwks(private_key),
        )

        # Initialize the JWT object
        another_key = generate_private_key(
            public_exponent=435297,
            key_size=2048,
            backend=default_backend(),
        )
        jws_string = make_jws(another_key, 'TEST_VALUE')
        token = JWT(jws_string, [])

        # Test our expectataions
        with pytest.raises(jwt.InvalidSignatureError):
            _ = token.payload
