"""Provides a custom authentication class for JWT based authentication.
"""

from typing import Union

import jwt

from django.http import HttpRequest
from django.conf import settings

from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed


class JWTAuthentication(BaseAuthentication):
    """Authenticate requests with JWTs
    """

    def authenticate(self, request: HttpRequest) -> Union[tuple, None]:
        """Used to authenticate the user

        Args:
            request: The request object. Must contain a headers `dict`.

        Returns:
            The `user` and `auth` for the request. Or None if JWT was not used.
        """
        token = self._get_token(request)
        if token:
            claims = self._decode_token(token)
            user = self._parse_jwt(claims)
            return (user, token)
        return None

    def authenticate_header(self, request: HttpRequest) -> str:
        """Generate a value WWW-Authenticate header value.

        Args:
            request: The request object

        Returns:
            The WWW-Authenticate header value to use.
        """
        host = request.get_host()
        host = host.replace('www', '')
        return 'aps.{host}/user/accounts/login/'.format(host=host)

    @staticmethod
    def _get_token(request: HttpRequest) -> Union[str, None]:
        """Get the JWT.

        Args:
            request: The http request from which to get the auth header.

        Returns:
            The JWT or `None` if the token did not contain a JWT
        """
        auth_header = request.headers.get('Authorization', None)
        if auth_header and auth_header.split()[0] == 'JWT':
            return auth_header.split()[1]
        return None

    @staticmethod
    def _decode_token(token: str) -> dict:
        """Decode a jwt.

        Args:
            token: The token to be decoded.

        Raises:
            AuthenticationFailed: If the signature does not match or the token
                is expired.

        Returns:
            The decoded JWT
        """
        for key in settings.JWT_AUTH:

            # If the setting contains a key try to decode the jwt with it
            if key.split('_')[-1] == 'KEY':
                jwt_key = settings.JWT_AUTH[key]
                try:
                    return jwt.decode(
                        token,
                        jwt_key,
                        algorithms=['HS256', 'RS256']
                    )

                # If an InvalidSignatureError was raised try another key
                except jwt.InvalidSignatureError:
                    continue

                # If some other exception was raised raise AuthenticationFailed
                except Exception:
                    raise AuthenticationFailed()

        # If none of the keys work raise AuthenticationFailed
        raise AuthenticationFailed()

    @staticmethod
    def _parse_jwt(claims: dict) -> dict:
        """Used for initializing missing values from the decoded JWT.

        Args:
            jwt: The decoded jwt

        Returns:
            dict: The contents of the JWT.
        """
        user = {
            **claims,
            'id': claims.get('id', None),
            'subscription_type': claims.get('subscription_type', []),
            'role': claims.get('role', []),
        }
        if not user['id']:
            raise AuthenticationFailed()
        return user
