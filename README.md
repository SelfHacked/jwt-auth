# JWT-Auth

This plugin is build for Django Rest Framework to allow authentication using a
JSON web token (JWT). It provides the `JWTAuthentication` authentication class.

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

## Authentication

The library currently supports Authentication for users using a JWT as well as
for services using token base authentication.

For services the `User` object is set with the email 'service@selfdecode.com'
and the uuid is `00000000-0000-0000-0000-000000000000`.

For the JWTs the library handles fetching the authorization details from the
PERMISSION_ENDPOINT set in the settings.py file. The

### Payloads

The PERMISSION_ENDPOINT must return the following payload:

```JSON
{
    "is_active": true,
    "role": {
        "is_staff": true,
        "is_superuser": false,
        "groups": ["Admin", "Writer"],
    },
    "subscription": {
        "plan": "professional-monthly",
        "status": "active",
        "start_date_time": "2019-01-03T17:41:42Z",
        "end_date_time": "2019-09-03T16:41:42Z",
    },
}
```

The JWT must have the following structure:

```JSON
{
    "uuid": "...",
    "email": "user@example.com"
}
```

## Settings

The plugin looks for keys in django's settings.
To add a key create a dict called `JWT_AUTH` in django's `settings.py` file
with a field 'KEYS'. The plugin supports adding multiple keys. The following
example creates two keys, one called `OIDC_KEY` and one called `SERVICE_KEY`:

```python
# settings.py

JWT_AUTH = {
    'KEYS': [
        os.environ.get('JWT_AUTH_OIDC_KEY'),
        os.environ.get('JWT_AUTH_SERVICE_KEY'),
    ],
    'PERMISSION_ENDPOINT': '',
    'SERVICE_SECRET_TOKEN': '',
}
```

`PERMISSION_ENDPOINT` URL used to validate and get the user authorization data.
`SERVICE_SECRET_TOKEN` is used to grant access for the other micro services.

Don't forget to add jwt_auth to django's installed apps.
