import os

import pytest

from django.conf import settings

JWT_AUTH = {
    'OIDC_KEY': os.environ.get('JWT_AUTH_OIDC_KEY'),
    'SERVICE_KEY': os.environ.get('JWT_AUTH_SERVICE_KEY')
}
DIRNAME = os.path.dirname(__file__)
settings.configure(DEBUG=True,
                   DATABASE_ENGINE='sqlite3',
                   DATABASE_NAME=os.path.join(DIRNAME, 'database.db'),
                   INSTALLED_APPS=('django.contrib.auth',
                                   'django.contrib.contenttypes',
                                   'django.contrib.sessions',
                                   'django.contrib.admin',),
                   JWT_AUTH=JWT_AUTH,
                   )

if __name__ == "__main__":
    pytest.main()
