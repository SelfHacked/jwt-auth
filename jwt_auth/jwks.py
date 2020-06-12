"""Utilities related to JWT."""
import json

import requests
from django.conf import settings
from django.core.exceptions import SuspiciousOperation
from django.utils.encoding import force_str
from jwt.algorithms import RSAAlgorithm


class Jwks:
    """Represents JSON Web Key Set."""

    def __init__(self):
        """Initialize."""
        self._jwks = None

    def get_jwk(self, header: dict):
        """Get JWK matching the kid in the token."""
        if not self._jwks:
            self._jwks = self._get_jwks()

        key = self._find_jwk(header)
        if key is None:
            raise SuspiciousOperation('Could not find a valid JWKS.')

        return RSAAlgorithm.from_jwk(json.dumps(key))

    def _find_jwk(self, header):
        key = None
        for jwk in self._jwks['keys']:
            if jwk['kid'] == force_str(header['kid']):
                if 'alg' in jwk and jwk['alg'] != force_str(header['alg']):
                    raise SuspiciousOperation('alg values do not match.')

                key = jwk
                break
        return key

    @staticmethod
    def _get_jwks() -> dict:
        jwks_endpoint = settings.JWT_AUTH['JWKS_ENDPOINT']

        response = requests.get(jwks_endpoint)
        response.raise_for_status()

        return response.json()
