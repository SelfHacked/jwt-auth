import pytest

from django.conf import settings

import jwt


@pytest.fixture
def make_authorization_data():
    """Factory function fixture for creating authorization data
    """
    def _make_authorization_data(**kwargs):
        data = {
            'is_active': True,
            'role': {
                'is_staff': True,
                'is_superuser': False,
                'groups': ['Admin', 'Writer'],
            },
            'subscriptions': [
                {
                    'type': 'Test-Subscription1',
                    'is_expired': False
                },
                {
                    'type': 'Test-Subscription2',
                    'is_expired': True
                },
                {
                    'type': 'Test-Subscription3',
                    'is_expired': False
                },
            ]
        }
        data.update(kwargs)
        return data
    return _make_authorization_data


@pytest.fixture
def make_jwt():
    """Factory fixture for making JWTs
    """
    def _make_jwt(**kwargs) -> str:
        key = kwargs.pop('key', None) or settings.JWT_AUTH['KEYS'][0]
        return jwt.encode(kwargs, key, 'HS256').decode()
    return _make_jwt
