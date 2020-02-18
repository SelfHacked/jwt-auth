from django.conf import settings


def pytest_configure():
    settings.configure()
    settings.JWT_AUTH = {
        'KEYS': [
            'Really secret key',
            'A super secret key',
        ],
        'PERMISSION_ENDPOINT': '',
        'SERVICE_SECRET_TOKEN': 'super secret'
    }
    settings.ALLOWED_HOSTS = ['www.example.com', 'example.com']
