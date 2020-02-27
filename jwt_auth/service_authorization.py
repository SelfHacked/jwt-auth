from requests.auth import AuthBase

from django.conf import settings


class ServiceRequestAuth(AuthBase):
    """A custom class for authenticating requests with other micro-services."""

    def __call__(self, req):
        """Custom implementation for authentication."""
        token = settings.JWT_AUTH['SERVICE_SECRET_TOKEN']

        # Set the token in the request
        req.headers['Token'] = token
        return req
