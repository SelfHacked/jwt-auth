"""Tests the JWTAuthentication class
"""
from uuid import uuid4
import datetime

import jwt

import pytest

from django.conf import settings
from django.http import HttpRequest

from rest_framework.exceptions import AuthenticationFailed

from jwt_auth.authentication import JWTAuthentication


class TestAuthenticate:
    """Test the JWTAuthentication.authenticate function."""

    @staticmethod
    def test_payload():
        """Test that the payload is parsed correctly."""

        # create payload for JWT
        payload = {
            'id': uuid4().hex,
            'something_else': 'random data',
            'subscription_type': ['sub1', 'sub2'],
            'role': ['role1', 'role2']
        }

        # Create a request
        key = settings.JWT_AUTH['OIDC_KEY']
        token = jwt.encode(payload, key, 'HS256').decode()
        header_string = 'JWT ' + token
        request = HttpRequest()
        request.META['HTTP_AUTHORIZATION'] = header_string

        # Invoke the function
        user, auth = JWTAuthentication().authenticate(request)

        # Define the expected result
        expected_user = {
            **payload,
        }
        expected_auth = token

        # Test our expectations
        assert user == expected_user
        assert auth == expected_auth

    @staticmethod
    def test_default_subscription():
        """Test that the default subscription_type is empty."""

        # create payload for JWT
        payload = {
            'id': str(uuid4()),
            'role': ['role1', 'role2']
        }

        # Create a request
        key = settings.JWT_AUTH['OIDC_KEY']
        token = jwt.encode(payload, key, 'HS256').decode()
        header_string = 'JWT ' + token
        request = HttpRequest()
        request.META['HTTP_AUTHORIZATION'] = header_string

        # Invoke the function
        user, auth = JWTAuthentication().authenticate(request)

        # Define the expected result
        expected_user = {
            **payload,
            'subscription_type': [],
        }
        expected_auth = token

        # Test our expectations
        assert user == expected_user
        assert auth == expected_auth

    @staticmethod
    def test_default_role():
        """Test that the default role is empty."""

        # create payload for JWT
        payload = {
            'id': str(uuid4()),
            'subscription_type': ['sub1', 'sub2'],
        }

        # Create a request
        key = settings.JWT_AUTH['OIDC_KEY']
        token = jwt.encode(payload, key, 'HS256').decode()
        header_string = 'JWT ' + token
        request = HttpRequest()
        request.META['HTTP_AUTHORIZATION'] = header_string

        # Invoke the function
        user, auth = JWTAuthentication().authenticate(request)

        # Define the expected result
        expected_user = {
            **payload,
            'role': [],
        }
        expected_auth = token

        # Test our expectations
        assert user == expected_user
        assert auth == expected_auth

    @staticmethod
    def test_error_on_no_id():
        """Test AuthenticationFailed is raised when id is missing."""

        # create payload for JWT
        payload = {
            'subscription_type': ['sub1', 'sub2'],
            'role': ['role1', 'role2'],
        }

        # Create a request
        key = settings.JWT_AUTH['OIDC_KEY']
        token = jwt.encode(payload, key, 'HS256').decode()
        header_string = 'JWT ' + token
        request = HttpRequest()
        request.META['HTTP_AUTHORIZATION'] = header_string

        # Test our expectations
        with pytest.raises(AuthenticationFailed):
            JWTAuthentication().authenticate(request)

    @staticmethod
    def test_no_token():
        """Test that `None` is returned when no token is present."""

        # Create a request
        request = HttpRequest()

        # Test our expectations
        assert JWTAuthentication().authenticate(request) is None

    @staticmethod
    def test_error_bad_key():
        """Test AuthenticationFailed is raised when the key is bad."""

        # create payload for JWT
        payload = {
            'id': str(uuid4()),
            'subscription_type': ['sub1', 'sub2'],
            'role': ['role1', 'role2']
        }

        # Create a request
        token = jwt.encode(payload, 'wrong key', 'HS256').decode()
        header_string = 'JWT ' + token
        request = HttpRequest()
        request.META['HTTP_AUTHORIZATION'] = header_string

        # Test our expectations
        with pytest.raises(AuthenticationFailed):
            JWTAuthentication().authenticate(request)

    @staticmethod
    def test_expired_token():
        """Test AuthenticationFailed is raised when token is expired."""

        # create a payload for JWT
        payload = {
            'id': str(uuid4()),
            'subscription_type': ['sub1', 'sub2'],
            'role': ['role1', 'role2'],
            'exp': datetime.datetime.utcnow() - datetime.timedelta(1)
        }

        # Create a request
        key = settings.JWT_AUTH['OIDC_KEY']
        token = jwt.encode(payload, key, 'HS256').decode()
        header_string = 'JWT ' + token
        request = HttpRequest()
        request.META['HTTP_AUTHORIZATION'] = header_string

        # Test our expectations
        with pytest.raises(AuthenticationFailed):
            JWTAuthentication().authenticate(request)

    @staticmethod
    def test_not_jwt():
        """Test that `None` is returned for tokens missing a 'JWT' prefix."""

        # Create a request
        header_string = 'Not a jwt'
        request = HttpRequest()
        request.META['HTTP_AUTHORIZATION'] = header_string

        # Invoke the function
        result = JWTAuthentication().authenticate(request)

        # Test our expectations
        assert result is None

    @staticmethod
    def test_multiple_keys():
        """Test multiple key support."""

        # create payload for JWT
        payload = {
            'id': str(uuid4()),
            'subscription_type': ['sub1', 'sub2'],
            'role': ['role1', 'role2']
        }

        # Create multiple keys
        settings.JWT_AUTH.update(
            {
                'OIDC_KEY': uuid4().hex,
                'test1_KEY': uuid4().hex,
                'test2_KEY': uuid4().hex,
                'SERVICE_KEY': uuid4().hex,
            }
        )

        # Create a request
        key = settings.JWT_AUTH['test2_KEY']
        token = jwt.encode(payload, key, 'HS256').decode()
        header_string = 'JWT ' + token
        request = HttpRequest()
        request.META['HTTP_AUTHORIZATION'] = header_string

        # Invoke the function
        user, auth = JWTAuthentication().authenticate(request)

        # Define the expected result
        expected_user = {
            **payload,
        }
        expected_auth = token

        # Test our expectations
        assert user == expected_user
        assert auth == expected_auth
