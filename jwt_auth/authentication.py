"""Provides a custom authentication class for JWT based authentication."""
import logging
from typing import Union
from uuid import UUID

import requests

from django.http import HttpRequest
from django.conf import settings

from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed

from jwt_auth.jwt import JWT
from jwt_auth.models import User
from jwt_auth.service_authorization import ServiceRequestAuth


logger = logging.getLogger()


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
        logger.debug('JWT Authentication')
        token = self._get_token(request)
        if token:
            try:
                user = self._get_user(token)
            except Exception:
                logger.debug('JWT Authentication Failed')
                raise AuthenticationFailed()
            return user, token
        else:
            logger.debug('No token')
        return None

    def authenticate_header(self, request: HttpRequest) -> str:
        """Generate a value WWW-Authenticate header value.

        Args:
            request: The request object

        Returns:
            The WWW-Authenticate header value to use.
        """
        host = request.get_host()
        host = host.replace('www.', '')
        return 'aps.{host}/user/accounts/login/'.format(host=host)

    @classmethod
    def _get_user(cls, token: str) -> User:
        """Get the user represented by the given JWT.

        Args:
            request: The request being processed

        Returns:
            The user who made the request
        """
        keys = settings.JWT_AUTH.get('KEYS', [])

        jwt = JWT(token, keys)

        try:
            user = User(**jwt.payload)  # payload must have uuid and email.
            logger.debug('Extracted user.')
        except Exception as ex:
            logger.debug(str(ex))
            raise ex

        authorization = cls._get_authorization(user.id)
        logger.debug('Authorization completed.')

        user.set_authorization(authorization)

        return user

    @staticmethod
    def _get_authorization(user_id: UUID) -> dict:
        """Get the user's authorization data

        Args:
            user_id: The id for the user who's authorization we want.

        Returns:
            The authorization data.
        """
        url = settings.JWT_AUTH['PERMISSION_ENDPOINT']
        uuid_string = str(user_id)
        response = requests.get(
            url,
            params={'uuid': uuid_string},
            auth=ServiceRequestAuth(),
        )
        response.raise_for_status()
        return response.json()

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


class ServiceTokenAuthentication(BaseAuthentication):
    """Authenticate requests with Service Token."""

    def authenticate(self, request: HttpRequest) -> Union[tuple, None]:
        """Used to authenticate the service request

        Args:
            request: The request object. Must contain a headers `dict`.

        Returns:
            The `user` and `auth` for the request. Or None if JWT was not used.
        """
        token = self._get_token(request)
        service_token = settings.JWT_AUTH['SERVICE_SECRET_TOKEN']

        if not token or not service_token:
            return None

        if token != service_token:
            raise AuthenticationFailed()

        return self._get_user(), token

    def authenticate_header(self, request: HttpRequest) -> str:
        """Generate a value WWW-Authenticate header value.

        Args:
            request: The request object

        Returns:
            The WWW-Authenticate header value to use.
        """
        host = request.get_host()
        host = host.replace('www.', '')
        return 'aps.{host}/user/accounts/login/'.format(host=host)

    @classmethod
    def _get_user(cls) -> User:
        """Create the default service user.

        Returns:
            The user who made the request.
        """
        user = User(
            uuid='00000000-0000-0000-0000-000000000000',
            email='service@selfdecode.com',
        )
        user.set_service()
        return user

    @staticmethod
    def _get_token(request: HttpRequest) -> Union[str, None]:
        """Get the Service token.

        Args:
            request: The http request from which to get the auth header.

        Returns:
            The Service token or `None` if the Token not in request headers.
        """
        return request.headers.get('Token')
