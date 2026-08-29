from __future__ import annotations

import base64
import json
from datetime import datetime, timezone
from uuid import UUID

import pytest

from desire_platform.trust_safety.adapters.postgres.production import (
    TrustOwnedReportCursorKey,
    TrustOwnedReportCursorKeyring,
    _decode_owned_report_cursor,
    _encode_owned_report_cursor,
)


ACTOR = UUID("10000000-0000-4000-8000-000000000001")
OTHER_ACTOR = UUID("10000000-0000-4000-8000-000000000002")
ORGANIZATION = UUID("20000000-0000-4000-8000-000000000001")
OTHER_ORGANIZATION = UUID("20000000-0000-4000-8000-000000000002")
REPORT = UUID("30000000-0000-4000-8000-000000000001")
CREATED_AT = datetime(2026, 8, 24, 8, 0, tzinfo=timezone.utc)
ACTIVE = "trust-report-cursor-2026-02"
RETAINED = "trust-report-cursor-2026-01"


def _key(key_id: str, byte: bytes) -> TrustOwnedReportCursorKey:
    return TrustOwnedReportCursorKey(
        purpose="TRUST_REPORT_CURSOR",
        key_id=key_id,
        material=bytearray(byte * 32),
    )


def _keyring(
    *,
    active: str = ACTIVE,
    retained: tuple[str, ...] = (ACTIVE, RETAINED),
    active_material: bytes = b"a",
    retained_material: bytes = b"r",
) -> TrustOwnedReportCursorKeyring:
    material = {ACTIVE: active_material, RETAINED: retained_material}
    return TrustOwnedReportCursorKeyring(
        keys=tuple(_key(key_id, material[key_id]) for key_id in retained),
        active_key_id=active,
        retained_key_ids=retained,
    )


def _encode(keyring: TrustOwnedReportCursorKeyring) -> str:
    return _encode_owned_report_cursor(
        keyring=keyring,
        actor_user_id=ACTOR,
        organization_id=ORGANIZATION,
        limit=20,
        created_at=CREATED_AT,
        report_id=REPORT,
    )


def _decode(
    token: str,
    keyring: TrustOwnedReportCursorKeyring,
    *,
    actor: UUID = ACTOR,
    organization: UUID = ORGANIZATION,
    limit: int = 20,
):
    return _decode_owned_report_cursor(
        token,
        keyring=keyring,
        actor_user_id=actor,
        organization_id=organization,
        limit=limit,
    )


def test_cursor_is_canonical_signed_and_bound_to_authority_and_limit() -> None:
    keyring = _keyring()
    token = _encode(keyring)
    encoded, signature = token.split(".")
    claims = json.loads(
        base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
    )

    assert claims == {
        "actor_user_id": str(ACTOR),
        "created_at": "2026-08-24T08:00:00.000000Z",
        "key_id": ACTIVE,
        "limit": 20,
        "organization_id": str(ORGANIZATION),
        "report_id": str(REPORT),
        "version": "trust-owned-report-page-v1",
    }
    assert len(base64.urlsafe_b64decode(signature + "=")) == 32
    assert _decode(token, keyring) == (CREATED_AT, REPORT)
    for actor, organization, limit in (
        (OTHER_ACTOR, ORGANIZATION, 20),
        (ACTOR, OTHER_ORGANIZATION, 20),
        (ACTOR, ORGANIZATION, 19),
    ):
        with pytest.raises(ValueError, match="authority"):
            _decode(
                token,
                keyring,
                actor=actor,
                organization=organization,
                limit=limit,
            )


def test_cursor_rejects_byte_tampering_wrong_material_and_noncanonical_body() -> None:
    keyring = _keyring()
    token = _encode(keyring)
    encoded, signature = token.split(".")
    raw = bytearray(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
    raw[raw.index(ord("2"))] = ord("3")
    tampered = base64.urlsafe_b64encode(raw).decode().rstrip("=") + "." + signature
    with pytest.raises(ValueError):
        _decode(tampered, keyring)

    wrong_material = _keyring(active_material=b"x", retained_material=b"y")
    with pytest.raises(ValueError, match="authority"):
        _decode(token, wrong_material)

    document = json.loads(
        base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
    )
    padded = json.dumps(document, sort_keys=True).encode()
    noncanonical = (
        base64.urlsafe_b64encode(padded).decode().rstrip("=") + "." + signature
    )
    with pytest.raises(ValueError):
        _decode(noncanonical, keyring)


def test_active_first_rotation_accepts_retained_then_rejects_retired_key() -> None:
    old_issuer = _keyring(active=RETAINED, retained=(RETAINED,))
    old_token = _encode(old_issuer)
    rotated = _keyring()

    assert _decode(old_token, rotated) == (CREATED_AT, REPORT)
    assert json.loads(
        base64.urlsafe_b64decode(
            _encode(rotated).split(".")[0]
            + "=" * (-len(_encode(rotated).split(".")[0]) % 4)
        )
    )["key_id"] == ACTIVE

    current_only = _keyring(retained=(ACTIVE,))
    with pytest.raises(ValueError, match="authority"):
        _decode(old_token, current_only)


def test_unknown_signed_key_id_takes_fail_closed_verify_path() -> None:
    keyring = _keyring()
    token = _encode(keyring)
    encoded, signature = token.split(".")
    claims = json.loads(
        base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
    )
    claims["key_id"] = "trust-report-cursor-unknown"
    body = json.dumps(
        claims, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode("ascii")
    forged = base64.urlsafe_b64encode(body).decode().rstrip("=") + "." + signature

    with pytest.raises(ValueError, match="authority"):
        _decode(forged, keyring)


def test_close_zeroizes_every_retained_cursor_key_and_repr_is_redacted() -> None:
    first = _key(ACTIVE, b"a")
    second = _key(RETAINED, b"r")
    keyring = TrustOwnedReportCursorKeyring(
        keys=(first, second),
        active_key_id=ACTIVE,
        retained_key_ids=(ACTIVE, RETAINED),
    )
    token = _encode(keyring)
    assert "aaaaaaaa" not in repr(first)
    assert "material=<redacted>" in repr(keyring)

    keyring.close()

    assert first.material == bytearray(32)
    assert second.material == bytearray(32)
    with pytest.raises(LookupError):
        _encode(keyring)
    assert keyring.verify(key_id=ACTIVE, value=b"claims", signature=b"s" * 32) is False
    assert token not in repr(keyring)
