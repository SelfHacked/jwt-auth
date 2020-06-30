import logging
from django.conf import settings
from typing import Optional, List

import jwt
from jwt_auth.jwks import Jwks


logger = logging.getLogger()


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
                logger.debug('RS256 algorithm.')
                key = JWKS.get_jwk(unverified_header)
                if key:
                    # Use the fetched key because key is retrieved using
                    # kid in the header, and therefore it should be valid.
                    keys = [key]
                    logger.debug('Use JWS RS256 Key.')

            if not keys:
                logger.debug('Keys not found.')
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
        logger.debug('Decode payload.')
        verify_audience = settings.JWT_AUTH.get('VERIFY_AUD', True)
        for key in keys:
            try:
                logger.debug('Payload decoding.')
                payload = jwt.decode(
                    self._token,
                    key,
                    algorithms=[alg],
                    options={
                        'verify_signature': True,
                        'verify_aud': verify_audience,
                    }
                )
                logger.debug('Payload decoded.')

                return payload
            # If an InvalidSignatureError was raised try another key
            except jwt.InvalidSignatureError:
                continue

        logger.debug('Failed to find a key.')

        # If none of the keys work raise InvalidSignatureError
        raise jwt.InvalidSignatureError()
