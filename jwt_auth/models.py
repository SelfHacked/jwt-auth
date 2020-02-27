"""Holds the data structures for this app.
"""
from typing import Optional
from uuid import UUID


class User:
    """Represents a user.
    """

    def __init__(
        self,
        uuid: str,
        email: str,
        subscription: Optional[dict] = None,
        **kwargs
    ):
        self._uuid = UUID(uuid)
        self._email = email
        self._subscription = subscription or {}
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

    @property
    def subscription(self):
        """The user's subscription
        """
        return self._subscription

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
                    'subscription': {
                        'type': 'professional-monthly',
                        'is_expired': False
                    },
                }
        """
        data = authorization.copy()
        self._set_roles(data.pop('role'))
        self._set_subscription(data.pop('subscription'))
        self._properties['is_active'] = data.pop('is_active')
        self._properties.update(**data)

    def set_service(self) -> None:
        """Sets the system service user."""
        self._set_roles({
            'is_staff': True,
            'is_active': True,
            'is_superuser': False,
            'role': ['service'],
        })

    def check_subscription(self, name: str) -> bool:
        """Check if the user has an un-expired subscription of the given type

        Args:
            name: The name of the subscription

        Returns:
            `True` if the user has the given subscription and it is not
            expired, `False` otherwise.
        """
        has_plan = self.subscription['plan'] == name
        not_expired = self.subscription['status'] == 'active'
        return has_plan and not_expired

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

    def _set_subscription(self, subscription: dict):
        """Sets the user's subscriptions.

        Example:
            The subscriptions must be of the form::
                {
                    "plan": "professional-monthly",
                    "status": "active",
                    "start_date_time": "2019-01-03T17:41:42Z",
                    "end_date_time": "2019-09-03T16:41:42Z"
                }
        """
        self._subscription = subscription
