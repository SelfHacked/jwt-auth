from setuptools import setup

setup(
    name='jwt_auth',
    packages=['jwt_auth'],
    version='1.0.0',
    install_requires=[
        'cryptography',
        'pyjwt',
        'django',
        'djangorestframework',
        'requests',
    ]
)
