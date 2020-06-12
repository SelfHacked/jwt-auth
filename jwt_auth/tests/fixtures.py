import json

import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key, \
    RSAPrivateKey

from django.conf import settings

import jwt
from jwt import PyJWS
from jwt.algorithms import RSAAlgorithm

TEST_KID = 'TEST_KID'


@pytest.fixture
def make_authorization_data():
    """Factory function fixture for creating authorization data."""
    def _make_authorization_data(**kwargs):
        data = {
            'is_active': True,
            'role': {
                'is_staff': True,
                'is_superuser': False,
                'groups': ['Admin', 'Writer'],
            },
            'subscription': {
                'plan': 'Test-Subscription1',
                'status': 'active',
                'start_date_time': '2019-01-03T17:41:42Z',
                'end_date_time': '2019-09-03T16:41:42Z'
            },
        }
        data.update(kwargs)
        return data
    return _make_authorization_data


@pytest.fixture
def make_jwt():
    """Factory fixture for making JWTs."""
    def _make_jwt(**kwargs) -> str:
        key = kwargs.pop('key', None) or settings.JWT_AUTH['KEYS'][0]
        return jwt.encode(kwargs, key, 'HS256').decode()
    return _make_jwt


@pytest.fixture
def private_key() -> RSAPrivateKey:
    """Retuns a private key."""
    return generate_private_key(
        public_exponent=435297,
        key_size=2048,
        backend=default_backend(),
    )


def make_jwks(_private_key: RSAPrivateKey):
    """Returns JWKS."""
    jwk = json.loads(
        RSAAlgorithm.to_jwk(_private_key.public_key()),
    )
    jwk['kid'] = TEST_KID
    return {
        'keys': [jwk]
    }


def make_jws(_private_key, test_value: str):
    payload = json.dumps({'value': test_value}).encode('UTF-8')
    return PyJWS().encode(
        headers={'kid': TEST_KID},
        payload=payload,
        key=_private_key,
        algorithm='RS256',
    )
