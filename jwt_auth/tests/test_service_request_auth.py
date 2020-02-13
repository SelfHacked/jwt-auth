"""Tests for the ServiceRequestAuth class
"""
from django.conf import settings
from jwt_auth.service_authorization import ServiceRequestAuth

import requests


class TestCall:
    """Tests for the ServiceRequestAuth.__call__ function
    """

    @staticmethod
    def test_header():
        """Test that is the header is properly set
        """
        # Make some data
        request = requests.Request()
        auth = ServiceRequestAuth()

        # Invoke the function
        auth(request)

        # Test our expectataions
        actual = request.headers['Token']
        expected = settings.JWT_AUTH['SERVICE_SECRET_TOKEN']
        assert actual == expected
