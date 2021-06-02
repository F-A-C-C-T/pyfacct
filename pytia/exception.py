"""

This module contains the set of integration exceptions.

"""


class ConnectionException(Exception):
    """A connection exception occurred."""

    pass


class InputException(Exception):
    """An invalid input exception occurred."""

    pass


class ParserException(Exception):
    """Internal parser exception occurred."""

    pass
