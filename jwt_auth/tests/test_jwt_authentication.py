"""Tests for the JWTAuthentication class
"""
import pytest

from django.http import HttpRequest

from rest_framework.exceptions import AuthenticationFailed

from jwt_auth.authentication import JWTAuthentication


class TestAuthenticate:
    """Test the JWTAuthentication.authenticate function
    """

    @staticmethod
    def test_no_token():
        """Test when there is no Authorization header
        """
        request = HttpRequest()

        assert JWTAuthentication().authenticate(request) is None

    @staticmethod
    def test_not_jwt():
        """Test when the token is not a JWT
        """
        header_string = 'some random string'
        request = HttpRequest()
        request.META['HTTP_AUTHORIZATION'] = header_string

        assert JWTAuthentication().authenticate(request) is None

    @staticmethod
    def test_bad_jwt():
        """Test when we have a bad JWT
        """
        header_string = 'JWT some random string'
        request = HttpRequest()
        request.META['HTTP_AUTHORIZATION'] = header_string

        with pytest.raises(AuthenticationFailed):
            print(JWTAuthentication().authenticate(request))


class TestAuthenticateHeader:
    """Tests for the JWTAuthentication.authenticate_header function
    """

    @staticmethod
    def test_no_www():
        """Test authenticate_header function when host has no www prefix
        """
        request = HttpRequest()
        request.META['HTTP_HOST'] = 'example.com'

        expected = 'aps.example.com/user/accounts/login/'
        actual = JWTAuthentication().authenticate_header(request)
        assert actual == expected

    @staticmethod
    def test_with_www():
        """Test authenticate_header function when host www prefix
        """
        request = HttpRequest()
        request.META['HTTP_HOST'] = 'www.example.com'

        expected = 'aps.example.com/user/accounts/login/'
        actual = JWTAuthentication().authenticate_header(request)
        assert actual == expected
