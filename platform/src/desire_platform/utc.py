"""Strict UTC timestamp parsing shared by PostgreSQL-facing adapters."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import re


_UTC_TIMESTAMP_TEXT = re.compile(
    r"\A(?P<whole>[0-9]{4}-[0-9]{2}-[0-9]{2}T"
    r"[0-9]{2}:[0-9]{2}:[0-9]{2})"
    r"(?:\.(?P<fraction>[0-9]{1,6}))?"
    r"(?P<zone>Z|\+00:00)\Z"
)
_OFFSET_TIMESTAMP_TEXT = re.compile(
    r"\A(?P<whole>[0-9]{4}-[0-9]{2}-[0-9]{2}T"
    r"[0-9]{2}:[0-9]{2}:[0-9]{2})"
    r"(?:\.(?P<fraction>[0-9]{1,6}))?"
    r"(?P<zone>Z|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])\Z"
)


def parse_utc_timestamp(value: object) -> datetime:
    """Return an aware UTC datetime from the closed database timestamp forms.

    PostgreSQL JSON timestamps may contain any one-to-six-digit fractional
    second.  Python 3.9's ``datetime.fromisoformat`` accepts fewer fractional
    widths, so the text is validated first and then padded to six digits.
    """

    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        match = _UTC_TIMESTAMP_TEXT.fullmatch(value)
        if match is None:
            raise ValueError("UTC timestamp text is invalid")
        parsed = _parse_matched_text(match)
    else:
        raise ValueError("UTC timestamp value is invalid")

    if parsed.tzinfo is None:
        raise ValueError("UTC timestamp is not aware")
    try:
        offset = parsed.utcoffset()
        result = parsed.astimezone(timezone.utc)
    except (OverflowError, TypeError, ValueError):
        raise ValueError("UTC timestamp is invalid") from None
    if offset != timedelta(0):
        raise ValueError("UTC timestamp is not UTC")
    return result


def parse_offset_timestamp(value: object) -> datetime:
    """Normalize a canonical aware timestamp with any explicit offset to UTC."""

    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        match = _OFFSET_TIMESTAMP_TEXT.fullmatch(value)
        if match is None:
            raise ValueError("offset timestamp text is invalid")
        if match.group("zone") == "-00:00":
            raise ValueError("offset timestamp offset is unknown")
        parsed = _parse_matched_text(match)
    else:
        raise ValueError("offset timestamp value is invalid")

    if parsed.tzinfo is None:
        raise ValueError("offset timestamp is not aware")
    try:
        offset = parsed.utcoffset()
        result = parsed.astimezone(timezone.utc)
    except (OverflowError, TypeError, ValueError):
        raise ValueError("offset timestamp is invalid") from None
    if offset is None:
        raise ValueError("offset timestamp has no offset")
    return result


def _parse_matched_text(match: "re.Match[str]") -> datetime:
    fraction = match.group("fraction")
    encoded = match.group("whole")
    if fraction is not None:
        encoded += "." + fraction.ljust(6, "0")
    zone = match.group("zone")
    encoded += "+00:00" if zone == "Z" else zone
    try:
        return datetime.fromisoformat(encoded)
    except ValueError:
        raise ValueError("timestamp text is invalid") from None
