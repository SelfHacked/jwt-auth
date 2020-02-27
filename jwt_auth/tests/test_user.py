"""Tests the JWTAuthentication class
"""
from uuid import uuid4

from jwt_auth.models import User
from jwt_auth.tests.fixtures import *  # noqa


class TestInit:
    """Test that User is initialized properly."""

    @staticmethod
    def test_properties_set():
        """Test that the initialized properties are set properly."""
        # Create a user
        properties = {'attribute1': 1234, 'attribute2': 'Test'}
        user_id = uuid4()
        email = 'user@example.com'
        user = User(str(user_id), email, **properties)

        # Test our expectations
        assert user.attribute1 == properties['attribute1']
        assert user.attribute2 == properties['attribute2']

    @staticmethod
    def test_uuid_set():
        """Test that the uuid is set properly."""
        # Create a user
        properties = {'attribute1': 1234, 'attribute2': 'Test'}
        user_id = uuid4()
        email = 'user@example.com'
        user = User(str(user_id), email, **properties)

        # Test our expectations
        assert user.uuid == user_id

    @staticmethod
    def test_id_set():
        """Test that the id is set properly."""
        # Create a user
        properties = {'attribute1': 1234, 'attribute2': 'Test'}
        user_id = uuid4()
        email = 'user@example.com'
        user = User(str(user_id), email, **properties)

        # Test our expectations
        assert user.id == user_id

    @staticmethod
    def test_email_set():
        """Test that the email is set properly."""
        # Create a user
        properties = {'attribute1': 1234, 'attribute2': 'Test'}
        user_id = uuid4()
        email = 'user@example.com'
        user = User(str(user_id), email, **properties)

        # Test our expectations
        assert user.email == email

    @staticmethod
    def test_is_anonymous():
        """Test that is_anonymous is False
        """
        # Create a user
        properties = {'attribute1': 1234, 'attribute2': 'Test'}
        user_id = uuid4()
        email = 'user@example.com'
        user = User(str(user_id), email, **properties)

        # Test our expectations
        assert not user.is_anonymous

    @staticmethod
    def test_is_authenticated():
        """Test that is_authenticated is True
        """
        # Create a user
        properties = {'attribute1': 1234, 'attribute2': 'Test'}
        user_id = uuid4()
        email = 'user@example.com'
        user = User(str(user_id), email, **properties)

        # Test our expectations
        assert user.is_authenticated


class TestSetAuthorization:
    """Used to test the User.set_authorization function.
    """

    @staticmethod
    def test_is_active(make_authorization_data):
        """Test that the is_active flag is properly being set.
        """
        # Create a user
        user_id = uuid4()
        email = 'test_user@example.com'
        user = User(str(user_id), email)

        # make test date
        data = make_authorization_data(is_active=True)

        # invoke the function
        user.set_authorization(data)

        # Test our expectations
        assert user.is_active == data['is_active']

    @staticmethod
    def test_role(make_authorization_data):
        """Test that the is_active flag is properly being set.
        """
        # Create a user
        user_id = uuid4()
        email = 'test_user@example.com'
        user = User(str(user_id), email)

        # Make test date
        role = {
            'is_staff': True,
            'is_superuser': False,
            'groups': ['Admin', 'Writer'],
        }
        data = make_authorization_data(
            role=role
        )

        # invoke the function
        user.set_authorization(data)

        # Test our expectations
        assert user.is_staff == role['is_staff']
        assert user.is_superuser == role['is_superuser']
        assert user.groups == role['groups']

    @staticmethod
    def test_subscription(make_authorization_data):
        """Test that the subscription is set properly
        """
        # Create a user
        user_id = uuid4()
        email = 'test_user@example.com'
        user = User(str(user_id), email)

        # Make test date
        subscription = {
            'plan': 'test-subscription1',
            'status': 'active',
            'start_date_time': '2019-01-03T17:41:42Z',
            'end_date_time': '2019-09-03T16:41:42Z'
        }
        data = make_authorization_data(
            subscription=subscription
        )

        # invoke the function
        user.set_authorization(data)

        # test our expectations
        assert user.subscription == subscription


class TestCheckSubscription:
    """Test the User.check_subscription function.
    """

    @staticmethod
    def test_not_active(make_authorization_data):
        """Test when the subscription is not active
        """
        # Create a user
        user_id = uuid4()
        email = 'test_user@example.com'
        user = User(str(user_id), email)

        # Make some data
        subscription = {
            'plan': 'Test-Subscription1',
            'status': 'inactive',
            'start_date_time': '2019-01-03T17:41:42Z',
            'end_date_time': '2019-09-03T16:41:42Z'
        }
        data = make_authorization_data(subscription=subscription)
        user.set_authorization(data)

        # invoke the function
        actual = user.check_subscription('Test-Subscription2')

        # Test our expectations
        assert actual is False

    @staticmethod
    def test_active(make_authorization_data):
        """Test when the given subscription is active
        """
        # Create a user
        user_id = uuid4()
        email = 'test_user@example.com'
        user = User(str(user_id), email)

        # Make some data
        subscription = {
            'plan': 'Test-Subscription1',
            'status': 'active',
            'start_date_time': '2019-01-03T17:41:42Z',
            'end_date_time': '2019-09-03T16:41:42Z'
        }
        data = make_authorization_data(subscription=subscription)
        user.set_authorization(data)

        # invoke the function
        actual = user.check_subscription('Test-Subscription1')

        # Test our expectations
        assert actual

    @staticmethod
    def test_does_not_exist(make_authorization_data):
        """Test when the given subscription does not exist
        """
        # Create a user
        user_id = uuid4()
        email = 'test_user@example.com'
        user = User(str(user_id), email)

        # Make some data
        subscription = {
            'plan': 'Test-Subscription1',
            'status': 'active',
            'start_date_time': '2019-01-03T17:41:42Z',
            'end_date_time': '2019-09-03T16:41:42Z'
        }
        data = make_authorization_data(subscription=subscription)
        user.set_authorization(data)

        # invoke the function
        actual = user.check_subscription('Test-Subscription4')

        # Test our expectations
        assert actual is False
