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
    """Factory fixture for making JWTs
    """
    def _make_jwt(**kwargs) -> str:
        key = kwargs.pop('key', None) or settings.JWT_AUTH['KEYS'][0]
        return jwt.encode(kwargs, key, 'HS256').decode()
    return _make_jwt
