"""Holds the data structures for this app.
"""
from functools import reduce
from typing import List, Optional
from uuid import UUID


class User:
    """Represents a user.
    """

    def __init__(
        self,
        uuid: str,
        email: str,
        subscriptions: Optional[List[dict]] = None,
        **kwargs
    ):
        self._uuid = UUID(uuid)
        self._email = email
        self._subscriptions = subscriptions or []
        self._properties = kwargs

    def __getattr__(self, name: str):
        """Allow dot notation access to the user's properties

        Args:
            name: The name of the property

        Returns:
            The value of the property
        """
        return self._properties[name]

    @property
    def email(self) -> str:
        """Read only property containing the user's email
        """
        return self._email

    @property
    def uuid(self) -> UUID:
        """Read only property containing the user's uuid
        """
        return self._uuid

    @property
    def id(self) -> UUID:
        """Read only property containing user's id
        """
        return self.uuid

    @property
    def is_authenticated(self):
        """Read only property that is always `True`
        """
        return True

    @property
    def is_anonymous(self):
        """Read only property that is always `False`
        """
        return False

    def set_authorization(self, authorization: dict):
        """Sets the user's authorization data.

        Args:
            authorization: The user's suthorization data

        Example:
            A sample authorization dictionary::
                {
                    'is_active': True,
                    'role': {
                        'is_staff': True,
                        'is_superuser': False,
                        'groups': ['Admin', 'Writer'],
                    },
                    'subscriptions': [
                        {
                            'type': 'professional-monthly',
                            'is_expired': False
                        },
                    ]
                }
        """
        data = authorization.copy()
        self._set_roles(data.pop('role'))
        self._set_subscriptions(data.pop('subscriptions'))
        self._properties['is_active'] = data.pop('is_active')
        self._properties.update(**data)

    def get_active_subscriptions(self) -> List[str]:
        """Get a list of the user's un-expired subscriptions.

        Returns:
            List of user's subscriptions that are not expired.
        """
        result = []
        for subscription in self._subscriptions:
            if not subscription['is_expired']:
                result.append(subscription['type'])
        return result

    def get_expired_subscriptions(self) -> List[str]:
        """Get the list of the user's expired subscriptions.

        Returns:
            The subscriptions with is_expired set to `True`.
        """
        result = []
        for subscription in self._subscriptions:
            if subscription['is_expired']:
                result.append(subscription['type'])
        return result

    def check_subscription(self, name: str) -> bool:
        """Check if the user has an un-expired subscription of the given type

        Args:
            name: The name of the subscription

        Returns:
            `True` if the user has the given subscription and it is not
            expired, `False` otherwise.
        """
        result = reduce(
            lambda acc, value: acc or value == name,
            self.get_active_subscriptions(),
            False,
        )
        return result

    def _set_roles(self, roles: dict):
        """Adds the given roles to this user.

        Args:
            roles: The roles for the user within the organization.

        Example:
            The roles dictionary must be of the form::
                {
                    'is_staff': True,
                    'is_superuser': False,
                    'groups': ['Admin', 'Writer'],
                }
        """
        self._properties.update(**roles)

    def _set_subscriptions(self, subscriptions: List[dict]):
        """Sets the user's subscriptions.

        Example:
            The subscriptions must be of the form::
                {
                    'type': 'professional-monthly',
                    'is_expired': False
                }
        """
        self._subscriptions = subscriptions
