from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import unittest

from desire_platform.identity_access.ports.read_models import (
    ReadModelCursorClaims,
    ReadModelCursorInvalidError,
    SessionBootstrapCsrfMaterial,
    SessionBootstrapCsrfUnavailableError,
)
from desire_platform.identity_access.security.cryptography import (
    csrf_digest,
    derive_csrf_token,
)
from desire_platform.internal_pilot.runtime_crypto import (
    AesGcmProtocolSecretBox,
    HmacIamReadCursorCodec,
    HmacRecipientBinding,
    HmacRuntimeKeyring,
    PostgresSessionBootstrapCsrfTokens,
    RuntimeKeyMaterial,
)


RAW_HANDLE = "session-handle-abcdefghijklmnopqrstuvwxyz-012345"


def key(purpose: str, key_id: str, byte: bytes) -> RuntimeKeyMaterial:
    return RuntimeKeyMaterial(
        purpose=purpose,
        key_id=key_id,
        material=bytearray(byte * 32),
    )


class RuntimeCryptoTests(unittest.TestCase):
    def test_iam_read_cursor_rotation_retains_old_tokens_then_fails_closed(self) -> None:
        now = datetime(2026, 8, 16, 1, 2, 3, tzinfo=timezone.utc)
        old = key("IAM_READ_CURSOR", "iam-read-cursor-v1", b"o")
        new = key("IAM_READ_CURSOR", "iam-read-cursor-v2", b"n")
        old_codec = HmacIamReadCursorCodec(keys=(old,), active_key_id=old.key_id)
        claims = ReadModelCursorClaims(
            version="iam-read-cursor-v1",
            key_id=old.key_id,
            operation_id="listOrganizationMemberships",
            actor_user_id="10000000-0000-4000-8000-000000000001",
            organization_id="20000000-0000-4000-8000-000000000002",
            page_limit=25,
            query_shape_digest="a" * 64,
            snapshot_at=now,
            after_created_at=now - timedelta(seconds=1),
            after_id="30000000-0000-4000-8000-000000000003",
            issued_at=now,
            expires_at=now + timedelta(minutes=15),
        )
        old_token = old_codec.encode(claims)
        rotated = HmacIamReadCursorCodec(
            keys=(new, old),
            active_key_id=new.key_id,
        )

        self.assertEqual(rotated.decode(old_token), claims)
        with self.assertRaises(ReadModelCursorInvalidError):
            HmacIamReadCursorCodec(
                keys=(new,), active_key_id=new.key_id
            ).decode(old_token)
        with self.assertRaises(ReadModelCursorInvalidError):
            rotated.decode(old_token[:-1] + ("A" if old_token[-1] != "A" else "B"))
        with self.assertRaises(TypeError):
            HmacIamReadCursorCodec(keys=(old, new), active_key_id=new.key_id)
        self.assertNotIn((b"o" * 32).decode(), repr(rotated))

    def test_recipient_binding_uses_closed_email_canonicalization_and_domain(self) -> None:
        material = key("OIDC_RECIPIENT_BINDING", "recipient-v1", b"r")
        binding = HmacRecipientBinding(key=material)

        result = binding.bind_verified(
            contact_type="EMAIL",
            verified_locator="  Pe\N{COMBINING ACUTE ACCENT}RSON@Example.TEST  ",
        )

        canonical = "p\N{LATIN SMALL LETTER E WITH ACUTE}rson@example.test"
        expected = hmac.new(
            b"r" * 32,
            b"desire:iam:recipient-binding:v1\x00EMAIL\x00"
            + canonical.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        self.assertEqual(result.contact_type, "EMAIL")
        self.assertEqual(result.binding_digest, expected)
        self.assertEqual(result.digest_key_id, "recipient-v1")
        self.assertNotIn("person@example.test", repr(binding).casefold())
        self.assertNotIn("person@example.test", repr(result).casefold())

    def test_recipient_binding_rotation_emits_active_then_retained_candidates(self) -> None:
        old = key("OIDC_RECIPIENT_BINDING", "recipient-v1", b"o")
        new = key("OIDC_RECIPIENT_BINDING", "recipient-v2", b"n")
        old_binding = HmacRecipientBinding(keys=(old,), active_key_id=old.key_id)
        old_result = old_binding.bind_verified(
            contact_type="EMAIL", verified_locator="Person@Example.test"
        )
        rotated = HmacRecipientBinding(
            keys=(new, old), active_key_id=new.key_id
        )

        candidates = rotated.bind_verified_candidates(
            contact_type="EMAIL", verified_locator="person@example.test"
        )

        self.assertEqual(
            tuple(item.digest_key_id for item in candidates),
            ("recipient-v2", "recipient-v1"),
        )
        self.assertEqual(candidates[1], old_result)
        self.assertEqual(rotated.bind_verified(
            contact_type="EMAIL", verified_locator="person@example.test"
        ), candidates[0])
        self.assertNotIn((b"o" * 32).decode(), repr(rotated))

    def test_recipient_binding_rejects_phone_empty_controls_and_wrong_key_purpose(self) -> None:
        binding = HmacRecipientBinding(
            key=key("OIDC_RECIPIENT_BINDING", "recipient-v1", b"r")
        )
        for contact_type, locator in (
            ("PHONE", "+12025550100"),
            ("SMS", "person@example.test"),
            ("email", "person@example.test"),
            ("EMAIL", "   "),
            ("EMAIL", "person\x00@example.test"),
        ):
            with self.subTest(contact_type=contact_type, locator=locator):
                with self.assertRaises(ValueError):
                    binding.bind_verified(
                        contact_type=contact_type,
                        verified_locator=locator,
                    )
        with self.assertRaises((TypeError, ValueError)):
            HmacRecipientBinding(key=key("OIDC_STATE", "state-v1", b"s"))

    def test_hmac_keyring_is_purpose_separated_retained_and_redacted(self) -> None:
        keys = (
            key("OIDC_STATE", "state-v1", b"s"),
            key("OIDC_STATE", "state-v0", b"S"),
            key("OIDC_BROWSER_BINDING", "browser-v1", b"b"),
            key("OIDC_NONCE", "nonce-v1", b"n"),
            key("SESSION_HANDLE", "session-v1", b"h"),
            key("CSRF", "csrf-v1", b"c"),
        )
        keyring = HmacRuntimeKeyring(
            keys=keys,
            active_key_ids={
                "OIDC_STATE": "state-v1",
                "OIDC_BROWSER_BINDING": "browser-v1",
                "OIDC_NONCE": "nonce-v1",
                "SESSION_HANDLE": "session-v1",
                "CSRF": "csrf-v1",
            },
            retained_key_ids={
                "OIDC_STATE": ("state-v1", "state-v0"),
                "OIDC_BROWSER_BINDING": ("browser-v1",),
                "OIDC_NONCE": ("nonce-v1",),
                "SESSION_HANDLE": ("session-v1",),
                "CSRF": ("csrf-v1",),
            },
        )

        self.assertEqual(keyring.state_digest_key_id, "state-v1")
        self.assertEqual(
            keyring.retained_state_digest_key_ids, ("state-v1", "state-v0")
        )
        self.assertEqual(len(keyring.digest_text(key_id="state-v0", value="x")), 64)
        with self.assertRaises(LookupError):
            keyring.digest_text(key_id="csrf-v1", value="cross-purpose")
        self.assertNotIn((b"s" * 32).decode(), repr(keyring))

    def test_aes_gcm_box_binds_key_id_and_detects_tampering(self) -> None:
        box = AesGcmProtocolSecretBox(
            keys=(key("OIDC_PROTOCOL_AEAD", "aead-v1", b"a"),),
            active_key_id="aead-v1",
            nonce_source=lambda size: b"z" * size,
        )

        sealed = box.encrypt(plaintext="nonce-secret", key_id="aead-v1")

        self.assertEqual(box.decrypt(ciphertext=sealed, key_id="aead-v1"), "nonce-secret")
        with self.assertRaises(ValueError):
            box.decrypt(ciphertext=sealed[:-1] + "A", key_id="aead-v1")
        with self.assertRaises(LookupError):
            box.decrypt(ciphertext=sealed, key_id="missing")
        self.assertNotIn("nonce-secret", repr(box))

    def test_session_bootstrap_csrf_rederives_and_verifies_database_digest(self) -> None:
        keyring = HmacRuntimeKeyring(
            keys=(
                key("OIDC_STATE", "state-v1", b"s"),
                key("OIDC_BROWSER_BINDING", "browser-v1", b"b"),
                key("OIDC_NONCE", "nonce-v1", b"n"),
                key("SESSION_HANDLE", "session-v1", b"h"),
                key("CSRF", "csrf-v1", b"c"),
            ),
            active_key_ids={
                "OIDC_STATE": "state-v1",
                "OIDC_BROWSER_BINDING": "browser-v1",
                "OIDC_NONCE": "nonce-v1",
                "SESSION_HANDLE": "session-v1",
                "CSRF": "csrf-v1",
            },
            retained_key_ids={
                "OIDC_STATE": ("state-v1",),
                "OIDC_BROWSER_BINDING": ("browser-v1",),
                "OIDC_NONCE": ("nonce-v1",),
                "SESSION_HANDLE": ("session-v1",),
                "CSRF": ("csrf-v1",),
            },
        )
        expected = derive_csrf_token(
            keyring,
            raw_session_handle=RAW_HANDLE,
            csrf_salt=b"salt-salt-salt-salt",
            session_id="20000000-0000-4000-8000-000000000002",
            generation=1,
            key_id="csrf-v1",
        )
        digest = bytes.fromhex(
            csrf_digest(keyring, csrf_token=expected, key_id="csrf-v1")
        )
        tokens = PostgresSessionBootstrapCsrfTokens(keyring=keyring)
        material = SessionBootstrapCsrfMaterial(
            session_id="20000000-0000-4000-8000-000000000002",
            generation=1,
            csrf_salt=b"salt-salt-salt-salt",
            csrf_key_id="csrf-v1",
            csrf_digest=digest,
        )

        self.assertEqual(
            tokens.derive(raw_session_handle=RAW_HANDLE, material=material),
            expected,
        )
        corrupt = SessionBootstrapCsrfMaterial(
            session_id=material.session_id,
            generation=1,
            csrf_salt=material.csrf_salt,
            csrf_key_id="csrf-v1",
            csrf_digest=b"x" * 32,
        )
        with self.assertRaises(SessionBootstrapCsrfUnavailableError):
            tokens.derive(raw_session_handle=RAW_HANDLE, material=corrupt)


if __name__ == "__main__":
    unittest.main()
