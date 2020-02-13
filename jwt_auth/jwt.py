from typing import Optional, List

import jwt


class JWT:
    """Represents a JWT
    """

    def __init__(self, token: str, keys: List[str]):
        self._token = token
        self._keys = keys
        self._payload: Optional[dict] = None

    @property
    def payload(self) -> dict:
        """The payload stored in the jwt
        """
        if self._payload is None:
            self._payload = self._decode()
        return self._payload

    def _decode(self) -> dict:
        """Decode the JWT

        Returns:
            A dictionary containing the payload
        """
        for key in self._keys:
            try:
                return jwt.decode(
                    self._token,
                    key,
                    algorithms=['HS256', 'RS256']
                )
            # If an InvalidSignatureError was raised try another key
            except jwt.InvalidSignatureError:
                continue
        # If none of the keys work raise InvalidSignatureError
        raise jwt.InvalidSignatureError()
