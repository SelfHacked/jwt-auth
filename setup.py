from setuptools import setup

setup(
    install_requires=[
        name='jwt_auth',
        packages=['jwt_auth'],
        'cryptography',
        'pyjwt',
    ]
)
