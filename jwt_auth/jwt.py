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
            unverified_header = jwt.get_unverified_header(self._token)
            if unverified_header.get('alg') == 'RS256':
                self._payload = self._decode_rs256(unverified_header)

            if not self._payload:
                self._payload = self._decode()

        return self._payload

    def _decode_rs256(self, unverified_header: dict):
        """Decode JWS."""
        return jwt.decode(
            self._token,
            key=JWKS.get_jwk(unverified_header),
            algorithms=['RS256'],
            options={
                'verify_signature': True,
                'verify_aud': settings.JWT_AUTH.get('VERIFY_AUD', True),
            },
        )

    def _decode(self) -> dict:
        """
        Decode the JWT and JWS.

        Returns:
            A dictionary containing the payload
        """
        for key in self._keys:
            try:
                return jwt.decode(
                    self._token,
                    key,
                    algorithms=['HS256', 'RS256'],
                )
            # If an InvalidSignatureError was raised try another key
            except jwt.InvalidSignatureError:
                continue

        # If none of the keys work raise InvalidSignatureError
        raise jwt.InvalidSignatureError()
