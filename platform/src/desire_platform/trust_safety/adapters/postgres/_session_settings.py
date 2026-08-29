"""Exact PostgreSQL session-setting result checks.

PostgreSQL canonicalizes timeout displays (for example, ``2000ms`` becomes
``2s``).  Callers still need to prove that the server accepted the requested
duration while keeping ordinary and application GUCs byte-exact.
"""

from __future__ import annotations

from typing import Any


_TIMEOUT_SETTINGS = frozenset(
    {
        "lock_timeout",
        "statement_timeout",
        "idle_in_transaction_session_timeout",
    }
)


def set_config_result_matches(
    *, name: str, requested_value: str, row: Any
) -> bool:
    """Return whether one ``set_config`` result is semantically exact."""

    if (
        type(name) is not str
        or type(requested_value) is not str
        or type(row) is not tuple
        or len(row) != 1
        or type(row[0]) is not str
    ):
        return False
    observed_value = row[0]
    if name not in _TIMEOUT_SETTINGS:
        return observed_value == requested_value
    requested_ms = _timeout_milliseconds(requested_value)
    observed_ms = _timeout_milliseconds(observed_value)
    return requested_ms is not None and observed_ms == requested_ms


def _timeout_milliseconds(value: str) -> int | None:
    if value.endswith("ms"):
        digits = value[:-2]
        multiplier = 1
    elif value.endswith("s"):
        digits = value[:-1]
        multiplier = 1_000
    else:
        return None
    if not digits or not digits.isascii() or not digits.isdecimal():
        return None
    number = int(digits)
    if number <= 0 or str(number) != digits:
        return None
    milliseconds = number * multiplier
    return milliseconds if 1 <= milliseconds <= 30_000 else None


__all__ = ["set_config_result_matches"]
