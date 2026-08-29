"""Versioned, domain-separated IAM digest and token derivation.

Long-lived key bytes remain behind a keyring port.  This module owns the public
protocol inputs so production behavior cannot accidentally live in a test fake.
"""

from __future__ import annotations

import base64
import json
from typing import Any, Protocol
import unicodedata


RECEIPT_CANONICALIZATION_VERSION = "restricted-canonical-json-v1"


class KeyUnavailableError(LookupError):
    """A configured key version has no usable material in the active keyring."""


class VersionedIamKeyring(Protocol):
    idempotency_key_digest_key_id: str
    payload_hash_key_id: str
    session_handle_digest_key_id: str
    csrf_key_id: str

    def keyed_digest_hex(self, *, key_id: str, canonical_bytes: bytes) -> str:
        ...


def require_key_material(
    keyring: VersionedIamKeyring,
    *,
    key_ids: tuple[str, ...],
) -> None:
    """Fail closed before business authorization if any required key is absent."""

    for key_id in dict.fromkeys(key_ids):
        if not isinstance(key_id, str) or not key_id:
            raise KeyUnavailableError("IAM key id is missing")
        keyring.keyed_digest_hex(
            key_id=key_id,
            canonical_bytes=canonical_json_bytes(
                {
                    "key_id": key_id,
                    "purpose": "IAM_KEY_AVAILABILITY_PREFLIGHT",
                }
            ),
        )


def idempotency_key_digest(keyring: VersionedIamKeyring, raw_key: str) -> str:
    return keyring.keyed_digest_hex(
        key_id=keyring.idempotency_key_digest_key_id,
        canonical_bytes=canonical_json_bytes(
            {"idempotency_key": unicodedata.normalize("NFC", raw_key)}
        ),
    )


def accept_payload_hash(keyring: VersionedIamKeyring, command: Any) -> str:
    return keyring.keyed_digest_hex(
        key_id=keyring.payload_hash_key_id,
        canonical_bytes=canonical_accept_payload_bytes(command),
    )


def canonical_accept_payload_bytes(command: Any) -> bytes:
    """Return the closed Accept request projection for receipt HMAC input."""

    return canonical_json_bytes(
        {
            "body": {
                "consent_grants": [
                    {
                        "affirmed": choice.affirmed,
                        "consent_offer_id": choice.consent_offer_id,
                        "content_sha256": choice.content_sha256,
                        "document_id": choice.document_id,
                    }
                    for choice in command.consent_grants
                ],
                "policy_acceptances": [
                    {
                        "affirmed": acceptance.affirmed,
                        "content_sha256": acceptance.content_sha256,
                        "document_id": acceptance.document_id,
                    }
                    for acceptance in command.policy_acceptances
                ],
                "policy_bundle_id": command.policy_bundle_id,
            },
            "canonicalization_version": RECEIPT_CANONICALIZATION_VERSION,
            "command_name": "AcceptAccessInvitation",
            "command_version": 1,
            "http_method": "POST",
            "if_match_version": command.expected_version,
            "path": "/v1/access-invitations/%s/accept" % command.invitation_id,
            "target_id": command.invitation_id,
            "target_kind": "AccessInvitation",
        }
    )


def session_handle_digest(
    keyring: VersionedIamKeyring,
    raw_session_handle: str,
) -> str:
    return session_handle_digest_for_key(
        keyring,
        raw_session_handle=raw_session_handle,
        key_id=keyring.session_handle_digest_key_id,
    )


def session_handle_digest_for_key(
    keyring: VersionedIamKeyring,
    *,
    raw_session_handle: str,
    key_id: str,
) -> str:
    """Derive one retained-key candidate without silently using the active key."""

    return keyring.keyed_digest_hex(
        key_id=key_id,
        canonical_bytes=canonical_json_bytes(
            {"raw_session_handle": raw_session_handle}
        ),
    )


def derive_csrf_token(
    keyring: VersionedIamKeyring,
    *,
    raw_session_handle: str,
    csrf_salt: Any,
    session_id: str,
    generation: int,
    key_id: str,
) -> str:
    salt_bytes = coerce_secret_bytes(csrf_salt)
    message = canonical_json_bytes(
        {
            "csrf_key_id": key_id,
            "csrf_salt": base64.urlsafe_b64encode(salt_bytes).decode("ascii"),
            "generation": generation,
            "raw_session_handle": raw_session_handle,
            "session_id": session_id,
        }
    )
    digest = bytes.fromhex(
        keyring.keyed_digest_hex(key_id=key_id, canonical_bytes=message)
    )
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def csrf_digest(
    keyring: VersionedIamKeyring,
    *,
    csrf_token: str,
    key_id: str,
) -> str:
    return keyring.keyed_digest_hex(
        key_id=key_id,
        canonical_bytes=canonical_json_bytes({"csrf_token": csrf_token}),
    )


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        _normalize_canonical_strings(value),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _normalize_canonical_strings(value: Any) -> Any:
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if isinstance(value, dict):
        return {
            unicodedata.normalize("NFC", str(key)): _normalize_canonical_strings(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_normalize_canonical_strings(item) for item in value]
    if isinstance(value, tuple):
        return [_normalize_canonical_strings(item) for item in value]
    if isinstance(value, float):
        raise ValueError("restricted-canonical-json-v1 rejects floats")
    return value


def coerce_secret_bytes(value: Any) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    if isinstance(value, str):
        try:
            return bytes.fromhex(value)
        except ValueError:
            return value.encode("utf-8")
    raise ValueError("persisted secret material must be bytes or an encoded string")
