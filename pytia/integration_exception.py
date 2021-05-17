"""

This module contains the set of integration exceptions.

"""


class ConnectionException(Exception):
    """A connection error occurred."""

    pass


class InputException(Exception):
    """An invalid input error occurred."""

    pass
