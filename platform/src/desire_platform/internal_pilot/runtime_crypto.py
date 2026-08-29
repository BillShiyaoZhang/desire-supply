"""Purpose-separated runtime cryptography adapters for INTERNAL_SANDBOX."""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import hmac
import json
import re
import secrets
from typing import Any, Callable, Mapping, Tuple
import unicodedata

from desire_platform.identity_access.ports.recipient_binding import (
    RecipientBindingTuple,
)
from desire_platform.identity_access.ports.read_models import (
    ReadModelCursorClaims,
    ReadModelCursorInvalidError,
    ReadModelCursorUnavailableError,
    SessionBootstrapCsrfMaterial,
    SessionBootstrapCsrfUnavailableError,
)
from desire_platform.identity_access.security.cryptography import (
    csrf_digest,
    derive_csrf_token,
)


_KEY_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$")
_PURPOSES = frozenset(
    (
        "OIDC_STATE",
        "OIDC_BROWSER_BINDING",
        "OIDC_NONCE",
        "SESSION_HANDLE",
        "CSRF",
        "OIDC_PROTOCOL_AEAD",
        "OIDC_RECIPIENT_BINDING",
        "IAM_READ_CURSOR",
    )
)
_HMAC_PURPOSES = (
    "OIDC_STATE",
    "OIDC_BROWSER_BINDING",
    "OIDC_NONCE",
    "SESSION_HANDLE",
    "CSRF",
)
_CIPHERTEXT = re.compile(r"^[A-Za-z0-9_-]{40,8192}$")
_AEAD_ASSOCIATED_DATA = b"desire-oidc-protocol-v1"
_RECIPIENT_BINDING_DOMAIN = b"desire:iam:recipient-binding:v1\x00EMAIL\x00"
_IAM_READ_CURSOR_DOMAIN = b"desire:iam:read-model-cursor:v1\x00"
_IAM_READ_CURSOR_TOKEN = re.compile(r"^[A-Za-z0-9_-]{64,1900}\.[A-Za-z0-9_-]{43}$")


@dataclass(repr=False)
class RuntimeKeyMaterial:
    purpose: str
    key_id: str
    material: bytearray = field(repr=False)

    def __post_init__(self) -> None:
        if self.purpose not in _PURPOSES:
            raise ValueError("runtime key purpose is not closed")
        if not isinstance(self.key_id, str) or _KEY_ID.fullmatch(self.key_id) is None:
            raise ValueError("runtime key ID is invalid")
        if (
            not isinstance(self.material, bytearray)
            or not 32 <= len(self.material) <= 64
            or not any(self.material)
        ):
            raise ValueError("runtime key material is unavailable")

    def __repr__(self) -> str:
        return (
            "RuntimeKeyMaterial("
            f"purpose={self.purpose!r}, key_id={self.key_id!r}, "
            "material=<redacted>)"
        )


class HmacRuntimeKeyring:
    """One closed HMAC key registry for OIDC, Session and CSRF protocols."""

    def __init__(
        self,
        *,
        keys: Tuple[RuntimeKeyMaterial, ...],
        active_key_ids: Mapping[str, str],
        retained_key_ids: Mapping[str, Tuple[str, ...]],
    ) -> None:
        if (
            not isinstance(keys, tuple)
            or not keys
            or any(not isinstance(item, RuntimeKeyMaterial) for item in keys)
            or any(item.purpose not in _HMAC_PURPOSES for item in keys)
            or not isinstance(active_key_ids, Mapping)
            or set(active_key_ids) != set(_HMAC_PURPOSES)
            or not isinstance(retained_key_ids, Mapping)
            or set(retained_key_ids) != set(_HMAC_PURPOSES)
        ):
            raise TypeError("HMAC runtime keyring registry is unavailable")
        registry = {(item.purpose, item.key_id): item for item in keys}
        if len(registry) != len(keys):
            raise ValueError("HMAC runtime key identities are duplicated")
        owner_by_id: dict[str, str] = {}
        for purpose, key_id in registry:
            owner = owner_by_id.setdefault(key_id, purpose)
            if owner != purpose:
                raise ValueError("HMAC key ID aliases multiple purposes")
        retained: dict[str, Tuple[str, ...]] = {}
        for purpose in _HMAC_PURPOSES:
            active = active_key_ids[purpose]
            values = retained_key_ids[purpose]
            if (
                not isinstance(active, str)
                or not isinstance(values, tuple)
                or not 1 <= len(values) <= 8
                or len(set(values)) != len(values)
                or values[0] != active
                or any((purpose, key_id) not in registry for key_id in values)
            ):
                raise ValueError("HMAC active or retained key registry is invalid")
            retained[purpose] = values
        if set(registry) != {
            (purpose, key_id)
            for purpose, key_ids in retained.items()
            for key_id in key_ids
        }:
            raise ValueError("HMAC key registry contains unreviewed material")
        self._keys = registry
        self._key_id_purpose = owner_by_id
        self._active = dict(active_key_ids)
        self._retained = retained

        self.state_digest_key_id = self._active["OIDC_STATE"]
        self.retained_state_digest_key_ids = retained["OIDC_STATE"]
        self.browser_binding_digest_key_id = self._active[
            "OIDC_BROWSER_BINDING"
        ]
        self.retained_browser_binding_digest_key_ids = retained[
            "OIDC_BROWSER_BINDING"
        ]
        self.nonce_digest_key_id = self._active["OIDC_NONCE"]
        self.retained_nonce_digest_key_ids = retained["OIDC_NONCE"]
        self.session_handle_digest_key_id = self._active["SESSION_HANDLE"]
        self.retained_session_handle_digest_key_ids = retained["SESSION_HANDLE"]
        self.csrf_key_id = self._active["CSRF"]
        self.retained_csrf_key_ids = retained["CSRF"]

    def digest_text(self, *, key_id: str, value: str) -> str:
        if (
            not isinstance(value, str)
            or not value
            or len(value) > 8_192
            or self._key_id_purpose.get(key_id)
            not in {"OIDC_STATE", "OIDC_BROWSER_BINDING", "OIDC_NONCE"}
        ):
            raise LookupError("protocol digest key is unavailable")
        return self._hmac(key_id, value.encode("utf-8", errors="strict"))

    def keyed_digest_hex(self, *, key_id: str, canonical_bytes: bytes) -> str:
        if (
            self._key_id_purpose.get(key_id) not in _HMAC_PURPOSES
            or not isinstance(canonical_bytes, bytes)
            or not canonical_bytes
            or len(canonical_bytes) > 1_048_576
        ):
            raise LookupError("HMAC runtime key is unavailable")
        return self._hmac(key_id, canonical_bytes)

    def _hmac(self, key_id: str, value: bytes) -> str:
        purpose = self._key_id_purpose.get(key_id)
        if purpose is None:
            raise LookupError("HMAC runtime key is unavailable")
        key = self._keys.get((purpose, key_id))
        if key is None:
            raise LookupError("HMAC runtime key is unavailable")
        return hmac.new(bytes(key.material), value, hashlib.sha256).hexdigest()

    def __repr__(self) -> str:
        return (
            "HmacRuntimeKeyring("
            f"key_count={len(self._keys)}, material=<redacted>)"
        )


class HmacRecipientBinding:
    """Canonicalize one verified email into the v1 blind HMAC tuple."""

    def __init__(
        self,
        *,
        key: RuntimeKeyMaterial | None = None,
        keys: Tuple[RuntimeKeyMaterial, ...] = (),
        active_key_id: str | None = None,
    ) -> None:
        registry = keys or ((key,) if key is not None else ())
        selected_active = active_key_id or (key.key_id if key is not None else None)
        if (
            not 1 <= len(registry) <= 4
            or selected_active is None
            or registry[0].key_id != selected_active
            or len({item.key_id for item in registry}) != len(registry)
            or any(
                not isinstance(item, RuntimeKeyMaterial)
                or item.purpose != "OIDC_RECIPIENT_BINDING"
                for item in registry
            )
        ):
            raise TypeError("OIDC recipient-binding key is unavailable")
        self._keys = registry

    def bind_verified(
        self,
        *,
        contact_type: str,
        verified_locator: str,
    ) -> RecipientBindingTuple:
        if contact_type != "EMAIL" or not isinstance(verified_locator, str):
            raise ValueError("verified recipient locator is unavailable")
        return self.bind_verified_candidates(
            contact_type=contact_type,
            verified_locator=verified_locator,
        )[0]

    def bind_verified_candidates(
        self,
        *,
        contact_type: str,
        verified_locator: str,
    ) -> Tuple[RecipientBindingTuple, ...]:
        if contact_type != "EMAIL" or not isinstance(verified_locator, str):
            raise ValueError("verified recipient locator is unavailable")
        try:
            normalized = unicodedata.normalize(
                "NFC", verified_locator.strip().casefold()
            )
            encoded = normalized.encode("utf-8", errors="strict")
        except (UnicodeEncodeError, UnicodeError):
            raise ValueError("verified recipient locator is unavailable") from None
        if not normalized or any(
            unicodedata.category(character) in {"Cc", "Cs"}
            for character in normalized
        ):
            raise ValueError("verified recipient locator is unavailable")
        candidates = []
        for key in self._keys:
            if not any(key.material):
                raise ValueError("verified recipient locator is unavailable")
            candidates.append(
                RecipientBindingTuple(
                    contact_type="EMAIL",
                    binding_digest=hmac.new(
                        bytes(key.material),
                        _RECIPIENT_BINDING_DOMAIN + encoded,
                        hashlib.sha256,
                    ).hexdigest(),
                    digest_key_id=key.key_id,
                )
            )
        return tuple(candidates)

    def __repr__(self) -> str:
        return (
            "HmacRecipientBinding("
            f"active_key_id={self._keys[0].key_id!r}, "
            f"key_count={len(self._keys)}, material=<redacted>)"
        )


class HmacIamReadCursorCodec:
    """Purpose-separated, rotating HMAC codec for private IAM list cursors."""

    def __init__(
        self,
        *,
        keys: Tuple[RuntimeKeyMaterial, ...],
        active_key_id: str,
    ) -> None:
        if (
            not isinstance(keys, tuple)
            or not 1 <= len(keys) <= 4
            or any(
                not isinstance(item, RuntimeKeyMaterial)
                or item.purpose != "IAM_READ_CURSOR"
                for item in keys
            )
            or len({item.key_id for item in keys}) != len(keys)
            or not isinstance(active_key_id, str)
            or keys[0].key_id != active_key_id
        ):
            raise TypeError("IAM read cursor key registry is unavailable")
        self._keys = {item.key_id: item for item in keys}
        self.active_key_id = active_key_id

    def encode(self, claims: ReadModelCursorClaims) -> str:
        try:
            if (
                not isinstance(claims, ReadModelCursorClaims)
                or claims.key_id != self.active_key_id
            ):
                raise ValueError
            canonical = _cursor_canonical_bytes(claims)
            key = self._keys[self.active_key_id]
            tag = hmac.new(
                bytes(key.material),
                _IAM_READ_CURSOR_DOMAIN + canonical,
                hashlib.sha256,
            ).digest()
            encoded = _b64url(canonical) + "." + _b64url(tag)
            if len(encoded) > 2_048:
                raise ValueError
            return encoded
        except (KeyError, TypeError, UnicodeError, ValueError):
            raise ReadModelCursorUnavailableError from None

    def decode(self, raw_cursor: str) -> ReadModelCursorClaims:
        try:
            if (
                not isinstance(raw_cursor, str)
                or len(raw_cursor) > 2_048
                or _IAM_READ_CURSOR_TOKEN.fullmatch(raw_cursor) is None
            ):
                raise ValueError
            encoded, encoded_tag = raw_cursor.split(".", 1)
            canonical = _unb64url(encoded)
            tag = _unb64url(encoded_tag)
            if len(tag) != 32:
                raise ValueError
            document = json.loads(canonical.decode("utf-8", errors="strict"))
            if not isinstance(document, dict) or set(document) != {
                "actor_user_id",
                "after_created_at",
                "after_id",
                "expires_at",
                "issued_at",
                "key_id",
                "operation_id",
                "organization_id",
                "page_limit",
                "query_shape_digest",
                "snapshot_at",
                "version",
            }:
                raise ValueError
            key_id = document["key_id"]
            key = self._keys.get(key_id)
            if key is None:
                raise ValueError
            expected = hmac.new(
                bytes(key.material),
                _IAM_READ_CURSOR_DOMAIN + canonical,
                hashlib.sha256,
            ).digest()
            if not hmac.compare_digest(tag, expected):
                raise ValueError
            claims = ReadModelCursorClaims(
                version=_cursor_text(document["version"]),
                key_id=_cursor_text(key_id),
                operation_id=_cursor_text(document["operation_id"]),
                actor_user_id=_cursor_text(document["actor_user_id"]),
                organization_id=(
                    None
                    if document["organization_id"] is None
                    else _cursor_text(document["organization_id"])
                ),
                page_limit=_cursor_int(document["page_limit"]),
                query_shape_digest=_cursor_text(document["query_shape_digest"]),
                snapshot_at=_cursor_time(document["snapshot_at"]),
                after_created_at=_cursor_time(document["after_created_at"]),
                after_id=_cursor_text(document["after_id"]),
                issued_at=_cursor_time(document["issued_at"]),
                expires_at=_cursor_time(document["expires_at"]),
            )
            if _cursor_canonical_bytes(claims) != canonical:
                raise ValueError
            return claims
        except (binascii.Error, KeyError, TypeError, UnicodeError, ValueError):
            raise ReadModelCursorInvalidError from None

    def __repr__(self) -> str:
        return (
            "HmacIamReadCursorCodec("
            f"active_key_id={self.active_key_id!r}, retained={len(self._keys)}, "
            "material=<redacted>)"
        )


def _cursor_canonical_bytes(claims: ReadModelCursorClaims) -> bytes:
    document = {
        "actor_user_id": _cursor_text(claims.actor_user_id),
        "after_created_at": _cursor_time_text(claims.after_created_at),
        "after_id": _cursor_text(claims.after_id),
        "expires_at": _cursor_time_text(claims.expires_at),
        "issued_at": _cursor_time_text(claims.issued_at),
        "key_id": _cursor_text(claims.key_id),
        "operation_id": _cursor_text(claims.operation_id),
        "organization_id": (
            None
            if claims.organization_id is None
            else _cursor_text(claims.organization_id)
        ),
        "page_limit": _cursor_int(claims.page_limit),
        "query_shape_digest": _cursor_text(claims.query_shape_digest),
        "snapshot_at": _cursor_time_text(claims.snapshot_at),
        "version": _cursor_text(claims.version),
    }
    return json.dumps(
        document,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def _cursor_text(value: Any) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 256
        or value != value.strip()
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
    ):
        raise ValueError
    return value


def _cursor_int(value: Any) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= 100:
        raise ValueError
    return value


def _cursor_time(value: Any) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError
    parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    if parsed.tzinfo != timezone.utc:
        raise ValueError
    return parsed


def _cursor_time_text(value: Any) -> str:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() is None
        or value.utcoffset().total_seconds() != 0
    ):
        raise ValueError
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _unb64url(value: str) -> bytes:
    return base64.b64decode(
        value + "=" * (-len(value) % 4),
        altchars=b"-_",
        validate=True,
    )


class AesGcmProtocolSecretBox:
    """Authenticated envelope for persisted OIDC nonce and PKCE verifier."""

    def __init__(
        self,
        *,
        keys: Tuple[RuntimeKeyMaterial, ...],
        active_key_id: str,
        nonce_source: Callable[[int], bytes] = secrets.token_bytes,
    ) -> None:
        if (
            not isinstance(keys, tuple)
            or not 1 <= len(keys) <= 4
            or any(
                not isinstance(item, RuntimeKeyMaterial)
                or item.purpose != "OIDC_PROTOCOL_AEAD"
                or len(item.material) != 32
                for item in keys
            )
            or len({item.key_id for item in keys}) != len(keys)
            or active_key_id not in {item.key_id for item in keys}
            or not callable(nonce_source)
        ):
            raise TypeError("OIDC AEAD key registry is unavailable")
        self._keys = {item.key_id: item for item in keys}
        self.key_id = active_key_id
        self._nonce_source = nonce_source

    def encrypt(self, *, plaintext: str, key_id: str) -> str:
        if key_id != self.key_id:
            raise LookupError("OIDC AEAD key is unavailable")
        key = self._key(key_id)
        if (
            not isinstance(plaintext, str)
            or not plaintext
            or len(plaintext) > 4_096
        ):
            raise ValueError("OIDC plaintext is invalid")
        try:
            encoded = plaintext.encode("utf-8", errors="strict")
            nonce = self._nonce_source(12)
            if not isinstance(nonce, bytes) or len(nonce) != 12:
                raise ValueError
            cipher = _aesgcm(bytes(key.material))
            ciphertext = cipher.encrypt(nonce, encoded, _AEAD_ASSOCIATED_DATA)
        except (UnicodeEncodeError, TypeError, ValueError):
            raise ValueError("OIDC encryption is unavailable") from None
        return base64.urlsafe_b64encode(nonce + ciphertext).rstrip(b"=").decode(
            "ascii"
        )

    def decrypt(self, *, ciphertext: Any, key_id: str) -> str:
        key = self._key(key_id)
        if not isinstance(ciphertext, (str, bytes)):
            raise ValueError("OIDC ciphertext is invalid")
        encoded = (
            ciphertext.decode("ascii", errors="strict")
            if isinstance(ciphertext, bytes)
            else ciphertext
        )
        if _CIPHERTEXT.fullmatch(encoded) is None:
            raise ValueError("OIDC ciphertext is invalid")
        try:
            padded = encoded + "=" * (-len(encoded) % 4)
            sealed = base64.urlsafe_b64decode(padded.encode("ascii"))
            if len(sealed) < 29:
                raise ValueError
            plaintext = _aesgcm(bytes(key.material)).decrypt(
                sealed[:12], sealed[12:], _AEAD_ASSOCIATED_DATA
            )
            return plaintext.decode("utf-8", errors="strict")
        except Exception:
            raise ValueError("OIDC ciphertext authentication failed") from None

    def _key(self, key_id: str) -> RuntimeKeyMaterial:
        try:
            return self._keys[key_id]
        except (KeyError, TypeError):
            raise LookupError("OIDC AEAD key is unavailable") from None

    def __repr__(self) -> str:
        return (
            "AesGcmProtocolSecretBox("
            f"key_id={self.key_id!r}, retained={len(self._keys)}, "
            "material=<redacted>)"
        )


def _aesgcm(material: bytes) -> Any:
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except (ImportError, ModuleNotFoundError):
        raise ValueError("OIDC AEAD implementation is unavailable") from None
    return AESGCM(material)


class PostgresSessionBootstrapCsrfTokens:
    """Re-derive the browser token and prove its stored PostgreSQL digest."""

    def __init__(self, *, keyring: HmacRuntimeKeyring) -> None:
        if not isinstance(keyring, HmacRuntimeKeyring):
            raise TypeError("session bootstrap CSRF keyring is unavailable")
        self._keyring = keyring

    def derive(
        self,
        *,
        raw_session_handle: str,
        material: SessionBootstrapCsrfMaterial,
    ) -> str:
        try:
            if not isinstance(material, SessionBootstrapCsrfMaterial):
                raise ValueError
            if material.csrf_key_id not in self._keyring.retained_csrf_key_ids:
                raise LookupError
            token = derive_csrf_token(
                self._keyring,
                raw_session_handle=raw_session_handle,
                csrf_salt=material.csrf_salt,
                session_id=material.session_id,
                generation=material.generation,
                key_id=material.csrf_key_id,
            )
            derived_digest = bytes.fromhex(
                csrf_digest(
                    self._keyring,
                    csrf_token=token,
                    key_id=material.csrf_key_id,
                )
            )
            if (
                not isinstance(material.csrf_digest, bytes)
                or len(material.csrf_digest) != 32
                or not hmac.compare_digest(derived_digest, material.csrf_digest)
            ):
                raise ValueError
            return token
        except (LookupError, TypeError, ValueError):
            raise SessionBootstrapCsrfUnavailableError from None


__all__ = [
    "AesGcmProtocolSecretBox",
    "HmacIamReadCursorCodec",
    "HmacRecipientBinding",
    "HmacRuntimeKeyring",
    "PostgresSessionBootstrapCsrfTokens",
    "RuntimeKeyMaterial",
]
