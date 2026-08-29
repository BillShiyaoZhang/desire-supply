from __future__ import annotations

import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

from desire_platform.internal_pilot.secrets import (
    FileSecretManifestEntry,
    FilesystemSecretProvider,
    ManagedRuntimeSecrets,
    SecretManifestError,
    SecretProviderError,
    parse_file_secret_manifest,
)
from desire_platform.runtime.config import DatabaseProfile


NOW = datetime(2026, 8, 12, 8, 0, tzinfo=timezone.utc)
RAW_SECRET = b"synthetic-secret-material-that-must-never-leak"


def profile() -> DatabaseProfile:
    return DatabaseProfile(
        capability_id="IAM_SESSION",
        online_role="iam_session_authenticator",
        credential_ref="secret://sandbox-db/iam-session#v1",
        application_name="desire-api-iam-session",
        max_pool_size=2,
        checkout_timeout_ms=500,
        statement_timeout_ms=2_000,
        lock_timeout_ms=500,
        idle_in_transaction_timeout_ms=5_000,
    )


def binding(value: DatabaseProfile) -> bytes:
    return hashlib.sha256(
        b"runtime-db-credential-v1\x00"
        + value.capability_id.encode()
        + b"\x00"
        + value.online_role.encode()
        + b"\x00"
        + value.credential_ref.encode()
    ).digest()


class FilesystemSecretProviderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        (self.root / "database-password").write_bytes(RAW_SECRET + b"\n")
        (self.root / "session-key").write_bytes(b"k" * 32)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def entries(self):
        return (
            FileSecretManifestEntry(
                kind="DATABASE_CREDENTIAL",
                file_name="database-password",
                credential_ref="secret://sandbox-db/iam-session#v1",
                purpose="DATABASE_CREDENTIAL:IAM_SESSION",
                key_id="v1",
                not_before=NOW - timedelta(days=1),
                not_after=NOW + timedelta(days=30),
                status="ACTIVE",
            ),
            FileSecretManifestEntry(
                kind="KEY",
                file_name="session-key",
                credential_ref=None,
                purpose="SESSION_HANDLE",
                key_id="session-v1",
                not_before=NOW - timedelta(days=1),
                not_after=NOW + timedelta(days=30),
                status="ACTIVE",
            ),
        )

    def test_resolves_exact_credential_and_key_into_destructible_redacted_carriers(self) -> None:
        provider = FilesystemSecretProvider(
            allowed_root=self.root,
            entries=self.entries(),
        )

        credential = provider.resolve_credential(profile())
        key = provider.resolve_key("SESSION_HANDLE", "session-v1")

        self.assertEqual(bytes(credential.material), RAW_SECRET)
        self.assertEqual(credential.purpose, "DATABASE_CREDENTIAL:IAM_SESSION")
        self.assertEqual(credential.binding_sha256, binding(profile()))
        self.assertEqual(bytes(key.material), b"k" * 32)
        self.assertNotIn(RAW_SECRET.decode(), repr(provider))
        self.assertNotIn(RAW_SECRET.decode(), repr(credential))
        credential.destroy()
        key.destroy()
        self.assertEqual(set(credential.material), {0})
        self.assertEqual(set(key.material), {0})

    def test_managed_registry_keeps_carriers_ready_then_zeroizes_on_close(self) -> None:
        provider = FilesystemSecretProvider(
            allowed_root=self.root,
            entries=self.entries(),
        )
        credential = provider.resolve_credential(profile())
        key = provider.resolve_key("SESSION_HANDLE", "session-v1")
        registry = ManagedRuntimeSecrets(
            carriers=(credential, key),
            clock=lambda: NOW,
        )

        self.assertIsNone(registry.check_readiness(timeout_ms=100))
        self.assertEqual(registry.carriers, (credential, key))
        self.assertNotIn(RAW_SECRET.decode(), repr(registry))
        registry.close()
        registry.close()
        self.assertEqual(set(credential.material), {0})
        self.assertEqual(set(key.material), {0})
        with self.assertRaises(SecretProviderError):
            registry.check_readiness(timeout_ms=100)

    def test_managed_registry_rejects_aliases_expiry_and_non_utc_clock(self) -> None:
        provider = FilesystemSecretProvider(
            allowed_root=self.root,
            entries=self.entries(),
        )
        key = provider.resolve_key("SESSION_HANDLE", "session-v1")
        with self.assertRaises(ValueError):
            ManagedRuntimeSecrets(carriers=(key, key), clock=lambda: NOW)
        registry = ManagedRuntimeSecrets(
            carriers=(key,),
            clock=lambda: key.not_after,
        )
        with self.assertRaises(SecretProviderError):
            registry.check_readiness(timeout_ms=100)
        registry.close()

    def test_missing_unknown_duplicate_or_reused_entry_fails_closed(self) -> None:
        duplicate = self.entries() + (self.entries()[0],)
        with self.assertRaises(ValueError):
            FilesystemSecretProvider(allowed_root=self.root, entries=duplicate)

        provider = FilesystemSecretProvider(
            allowed_root=self.root,
            entries=self.entries(),
        )
        with self.assertRaises(SecretProviderError) as raised:
            provider.resolve_key("CSRF", "missing")
        self.assertEqual(raised.exception.code, "SECRET_UNAVAILABLE")

        provider.resolve_credential(profile())
        with self.assertRaises(SecretProviderError) as raised:
            provider.resolve_credential(profile())
        self.assertEqual(raised.exception.code, "SECRET_ALREADY_RESOLVED")

    def test_path_escape_symlink_and_invalid_material_are_rejected(self) -> None:
        outside = self.root.parent / "outside-secret-sentinel"
        outside.write_bytes(RAW_SECRET)
        try:
            (self.root / "linked-secret").symlink_to(outside)
            entry = self.entries()[0]
            with self.assertRaises(ValueError):
                FileSecretManifestEntry(
                    **{**entry.__dict__, "file_name": "../outside-secret-sentinel"}
                )
            candidate = FileSecretManifestEntry(
                **{**entry.__dict__, "file_name": "linked-secret"}
            )
            provider = FilesystemSecretProvider(
                allowed_root=self.root,
                entries=(candidate,),
            )
            with self.assertRaises(SecretProviderError):
                provider.resolve_credential(profile())

            (self.root / "database-password").write_bytes(b"short")
            provider = FilesystemSecretProvider(
                allowed_root=self.root,
                entries=(self.entries()[0],),
            )
            with self.assertRaises(SecretProviderError) as raised:
                provider.resolve_credential(profile())
            self.assertEqual(raised.exception.code, "SECRET_INVALID")
        finally:
            outside.unlink(missing_ok=True)

    def test_manifest_facts_are_closed_and_secret_free(self) -> None:
        entry = self.entries()[0]
        for changed in (
            {**entry.__dict__, "kind": "RAW"},
            {**entry.__dict__, "file_name": "/run/secrets/raw"},
            {**entry.__dict__, "status": "REVOKED"},
            {**entry.__dict__, "not_after": entry.not_before},
        ):
            with self.subTest(changed=changed):
                with self.assertRaises((TypeError, ValueError)):
                    FileSecretManifestEntry(**changed)


class FileSecretManifestParserTests(unittest.TestCase):
    def test_parses_one_closed_secret_free_document(self) -> None:
        raw = b'''{
          "schema_name":"desire-file-secret-manifest-v1",
          "entries":[
            {
              "kind":"DATABASE_CREDENTIAL",
              "file_name":"iam-app-password",
              "credential_ref":"secret://sandbox-db/iam-app#v1",
              "purpose":"DATABASE_CREDENTIAL:IAM_APP",
              "key_id":"v1",
              "not_before":"2026-08-12T00:00:00Z",
              "not_after":"2027-08-12T00:00:00Z",
              "status":"ACTIVE"
            },
            {
              "kind":"KEY",
              "file_name":"session-hmac-v1",
              "credential_ref":null,
              "purpose":"SESSION_HANDLE",
              "key_id":"session-v1",
              "not_before":"2026-08-12T00:00:00Z",
              "not_after":"2027-08-12T00:00:00Z",
              "status":"ACTIVE"
            }
          ]
        }'''

        entries = parse_file_secret_manifest(raw)

        self.assertEqual(len(entries), 2)
        self.assertEqual(entries[0].purpose, "DATABASE_CREDENTIAL:IAM_APP")
        self.assertEqual(entries[1].key_id, "session-v1")
        self.assertNotIn("material", repr(entries).lower())

    def test_rejects_unknown_duplicate_or_aliased_manifest_facts(self) -> None:
        valid_entry = '''{
          "kind":"KEY",
          "file_name":"key-v1",
          "credential_ref":null,
          "purpose":"CSRF",
          "key_id":"v1",
          "not_before":"2026-08-12T00:00:00Z",
          "not_after":"2027-08-12T00:00:00Z",
          "status":"ACTIVE"
        }'''
        documents = (
            (
                '{"schema_name":"desire-file-secret-manifest-v1",'
                f'"entries":[{valid_entry}],"unknown":true}}'
            ),
            (
                '{"schema_name":"desire-file-secret-manifest-v1",'
                f'"schema_name":"desire-file-secret-manifest-v1","entries":[{valid_entry}]}}'
            ),
            (
                '{"schema_name":"desire-file-secret-manifest-v1",'
                f'"entries":[{valid_entry},{valid_entry}]}}'
            ),
            (
                '{"schema_name":"desire-file-secret-manifest-v1",'
                f'"entries":[{valid_entry.replace("00:00:00Z", "00:00:00+00:00")}]}}'
            ),
        )
        for document in documents:
            with self.subTest(document=document[:80]):
                with self.assertRaises(SecretManifestError) as raised:
                    parse_file_secret_manifest(document.encode("utf-8"))
                self.assertEqual(raised.exception.code, "INVALID_SECRET_MANIFEST")

        with self.assertRaises(SecretManifestError):
            parse_file_secret_manifest(b" " * (256 * 1024 + 1))


if __name__ == "__main__":
    unittest.main()
