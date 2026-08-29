"""Cross-version contract for strict database UTC timestamp parsing."""

from datetime import datetime, timedelta, timezone

import pytest

from desire_platform.utc import parse_offset_timestamp, parse_utc_timestamp


@pytest.mark.parametrize("suffix", ("Z", "+00:00"))
@pytest.mark.parametrize(
    ("fraction", "microsecond"),
    (
        ("", 0),
        (".1", 100000),
        (".12", 120000),
        (".123", 123000),
        (".1234", 123400),
        (".12345", 123450),
        (".123456", 123456),
    ),
)
def test_accepts_every_postgres_fractional_width(
    suffix: str, fraction: str, microsecond: int
) -> None:
    parsed = parse_utc_timestamp(
        "2026-08-18T12:34:56" + fraction + suffix
    )

    assert parsed == datetime(
        2026, 8, 18, 12, 34, 56, microsecond, tzinfo=timezone.utc
    )
    assert parsed.tzinfo is timezone.utc


def test_accepts_and_normalizes_aware_utc_datetime() -> None:
    parsed = parse_utc_timestamp(
        datetime(2026, 8, 18, 12, 34, tzinfo=timezone(timedelta(0), "UTC0"))
    )

    assert parsed == datetime(2026, 8, 18, 12, 34, tzinfo=timezone.utc)
    assert parsed.tzinfo is timezone.utc


@pytest.mark.parametrize(
    ("value", "expected"),
    (
        (
            "2027-06-20T16:36:50.82245+08:00",
            datetime(2027, 6, 20, 8, 36, 50, 822450, tzinfo=timezone.utc),
        ),
        (
            "2027-06-20T02:06:50.1-05:30",
            datetime(2027, 6, 20, 7, 36, 50, 100000, tzinfo=timezone.utc),
        ),
        (
            "2027-06-20T08:36:50Z",
            datetime(2027, 6, 20, 8, 36, 50, tzinfo=timezone.utc),
        ),
    ),
)
def test_normalizes_canonical_explicit_offsets(
    value: str, expected: datetime
) -> None:
    assert parse_offset_timestamp(value) == expected


@pytest.mark.parametrize(
    "value",
    (
        "2027-06-20T16:36:50",
        "2027-06-20T16:36:50+8:00",
        "2027-06-20T16:36:50+24:00",
        "2027-06-20T16:36:50+00:60",
        "2027-06-20T16:36:50-00:60",
        "2027-06-20T16:36:50-00:00",
        "2027-06-20T16:36:50.1234567+08:00",
        datetime(2027, 6, 20, 16, 36, 50),
    ),
)
def test_rejects_ambiguous_or_invalid_explicit_offsets(value: object) -> None:
    with pytest.raises(ValueError):
        parse_offset_timestamp(value)


@pytest.mark.parametrize(
    "value",
    (
        "2026-08-18 12:34:56+00:00",
        "2026-08-18T12:34:56",
        "2026-08-18T12:34:56z",
        "2026-08-18T12:34:56+00",
        "2026-08-18T12:34:56+01:00",
        "2026-08-18T12:34:56.1234567Z",
        "2026-02-30T12:34:56Z",
        "2026-08-18T12:34:56Z\n",
        datetime(2026, 8, 18, 12, 34),
        datetime(2026, 8, 18, 12, 34, tzinfo=timezone(timedelta(hours=1))),
        None,
    ),
)
def test_rejects_ambiguous_non_utc_and_overprecision_values(value: object) -> None:
    with pytest.raises(ValueError):
        parse_utc_timestamp(value)
