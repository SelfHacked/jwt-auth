from django.conf import settings


def pytest_configure():
    settings.configure()
    settings.JWT_AUTH = {
        'OIDC_KEY': 'Really secret key'
    }
