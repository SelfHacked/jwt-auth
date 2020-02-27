"""Tests for the JWTAuthentication class
"""

from django.http import HttpRequest
from uuid import UUID
from jwt_auth.authentication import ServiceTokenAuthentication


class TestAuthenticate:
    """Test the ServiceTokenAuthentication.authenticate function."""

    @staticmethod
    def test_no_token():
        """Test when there is no Token header."""
        request = HttpRequest()

        assert ServiceTokenAuthentication().authenticate(request) is None

    @staticmethod
    def test_invalid_token():
        """Test when the token is not equal SERVICE_SECRET_TOKEN."""
        header_string = 'bad secret'
        request = HttpRequest()
        request.META['HTTP_TOKEN'] = header_string

        assert ServiceTokenAuthentication().authenticate(request) is None

    @staticmethod
    def test_valid_token():
        """Test when token in header is valid."""
        header_string = 'super secret'
        request = HttpRequest()
        request.META['HTTP_TOKEN'] = header_string

        user, token = ServiceTokenAuthentication().authenticate(request)

        assert token == header_string

        assert user.email == 'service@selfdecode.com'
        assert user.uuid == UUID('00000000-0000-0000-0000-000000000000')
        assert user.is_active
        assert user.is_staff
        assert not user.is_superuser


class TestAuthenticateHeader:
    """
    Tests for the ServiceTokenAuthentication.authenticate_header function.
    """

    @staticmethod
    def test_no_www():
        """
        Test authenticate_header function when host has no www prefix.
        """
        request = HttpRequest()
        request.META['HTTP_HOST'] = 'example.com'

        expected = 'aps.example.com/user/accounts/login/'
        actual = ServiceTokenAuthentication().authenticate_header(request)
        assert actual == expected

    @staticmethod
    def test_with_www():
        """
        Test authenticate_header function when host www prefix.
        """
        request = HttpRequest()
        request.META['HTTP_HOST'] = 'www.example.com'

        expected = 'aps.example.com/user/accounts/login/'
        actual = ServiceTokenAuthentication().authenticate_header(request)
        assert actual == expected
