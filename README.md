# JWT-Auth

This plunin is build for Django Rest Framework to allow authentication using a JSON web token (JWT). It provides the `JWTAuthentication` authentication class.

## Requirements

- Python 3.7
- pyjwt
- Django
- Django REST Framework


## Installation

using `pip`:
```
$ pip install ssh+git@bitbucket.org:selfdecode/jwt-auth.git
```

## Settings

The plugin looks for keys in django's settings. To add a key create a dict called `JWT_AUTH` in django's `settings.py` file with a field ending with '_KEY'. The plugin supports adding multiple keys. The following example creates two keys, one called `OIDC_KEY` and one called `SERVICE_KEY`:

```python
# settings.py

JWT_AUTH = {
    'OIDC_KEY': os.environ.get('JWT_AUTH_OIDC_KEY'),
    'SERVICE_KEY': os.environ.get('JWT_AUTH_SERVICE_KEY')
}
```

Don't forget to add jwt_auth to dhango's installed apps.

## Test

