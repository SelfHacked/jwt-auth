import typing
from django.conf import settings
from typing import Optional, List

import jwt
from jwt_auth.jwks import Jwks

# Load JSON Web Key Set globally, to cache the keys. Any service that
# uses this library should restart to reset the key set.
JWKS = Jwks()


class JWT:
    """Represents a JWT."""

    def __init__(self, token: str, keys: List[str]):
        self._token = token
        self._keys = keys

        self._payload: Optional[dict] = None

    @property
    def payload(self) -> dict:
        """The payload stored in the jwt."""
        if self._payload is None:
            # If RS256 header is detected, try to decode the token using
            # JWKS if endpoint is configured.
            keys = self._keys
            unverified_header = jwt.get_unverified_header(self._token)
            alg = unverified_header.get('alg')
            if alg == 'RS256':
                key = JWKS.get_jwk(unverified_header)
                if key:
                    # Use the fetched key because key is retrieved using
                    # kid in the header, and therefore it should be valid.
                    keys = [key]

            if not keys:
                raise ValueError('JWT_AUTH keys are not configured properly.')

            self._payload = self._decode(keys=keys, alg=alg)

        return self._payload

    def _decode(
            self,
            keys: list,
            alg: str = 'HS256',
    ) -> dict:
        """
        Decode the JWT and JWS.

        Returns:
            A dictionary containing the payload
        """
        verify_audience = settings.JWT_AUTH.get('VERIFY_AUD', True)
        for key in keys:
            try:
                return jwt.decode(
                    self._token,
                    key,
                    algorithms=[alg],
                    options={
                        'verify_signature': True,
                        'verify_aud': verify_audience,
                    }
                )
            # If an InvalidSignatureError was raised try another key
            except jwt.InvalidSignatureError:
                continue

        # If none of the keys work raise InvalidSignatureError
        raise jwt.InvalidSignatureError()
