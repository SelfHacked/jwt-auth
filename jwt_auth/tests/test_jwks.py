"""Test JWKS."""
from jwt_auth.tests.fixtures import *  # noqa

import pytest
import responses
from django.core.exceptions import SuspiciousOperation
from django.test import override_settings
from jwt import PyJWS

from jwt_auth.jwks import Jwks


class TestJwks:
    """Test Jwks class."""

    @responses.activate
    @override_settings(JWT_AUTH={'JWKS_ENDPOINT': 'http://test.com'})
    def test_get_jwk(self, private_key):
        """Test that keys is fetched."""
        jwks = make_jwks(private_key)
        jws = make_jws(private_key, 'TEST')

        responses.add(
            responses.GET, 'http://test.com',
            json=jwks,  # noqa
        )
        jwk = Jwks().get_jwk(jwt.get_unverified_header(jws))

        assert PyJWS().decode(
            jws, jwk,
            options={'verify_signature': True},
        )

    @responses.activate
    @override_settings(JWT_AUTH={'JWKS_ENDPOINT': 'http://test.com'})
    def test_kid_not_found(self, private_key):
        """Test that keys is fetched."""
        jwks = make_jwks(private_key)
        jwks['keys'][0]['kid'] = 'invalid'
        jws = make_jws(private_key, 'TEST')

        responses.add(
            responses.GET, 'http://test.com',
            json=jwks,  # noqa
        )

        assert Jwks().get_jwk(jwt.get_unverified_header(jws)) is None

    @responses.activate
    @override_settings(JWT_AUTH={'JWKS_ENDPOINT': 'http://test.com'})
    def test_invalid_alg(self, private_key):
        """Test that keys is fetched."""
        jwks = make_jwks(private_key)
        jwks['keys'][0]['alg'] = 'invalid'
        jws = make_jws(private_key, 'TEST')

        responses.add(
            responses.GET, 'http://test.com',
            json=jwks,  # noqa
        )
        with pytest.raises(SuspiciousOperation) as exp:
            Jwks().get_jwk(jwt.get_unverified_header(jws))

    @responses.activate
    def test_endpoint_not_set(self, private_key):
        """Test that keys is fetched."""
        jwks = make_jwks(private_key)
        jwks['keys'][0]['kid'] = 'invalid'
        jws = make_jws(private_key, 'TEST')

        responses.add(
            responses.GET, 'http://test.com',
            json=jwks,  # noqa
        )

        assert Jwks().get_jwk(jwt.get_unverified_header(jws)) is None
