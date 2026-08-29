"""TEST-DB-MIG-IAM-002 catalog bytes and path-policy semantic REDs."""

from __future__ import annotations

from dataclasses import FrozenInstanceError
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from desire_platform.identity_access.adapters.postgres.migrations import catalog as catalog_module

from desire_platform.identity_access.adapters.postgres.migrations import (
    IAM_MIGRATION_LAYOUT,
    IAM_SCHEMA_HEAD_VERSION,
    MigrationCatalog,
    MigrationCatalogError,
    MigrationDescriptor,
    MigrationPhase,
)


class IamMigrationCatalogTest(unittest.TestCase):
    def test_reviewed_layout_is_closed_contiguous_and_immutable(self) -> None:
        self.assertEqual(
            [item[0] for item in IAM_MIGRATION_LAYOUT],
            list(range(IAM_SCHEMA_HEAD_VERSION + 1)),
        )
        self.assertEqual(
            [item[1] for item in IAM_MIGRATION_LAYOUT],
            [MigrationPhase.EXPAND] * 7
            + [MigrationPhase.CONTRACT]
            + [MigrationPhase.EXPAND] * 2
            + [MigrationPhase.CONTRACT]
            + [MigrationPhase.EXPAND] * (IAM_SCHEMA_HEAD_VERSION - 10),
        )
        descriptor = MigrationDescriptor(
            component="iam",
            version=0,
            phase=MigrationPhase.EXPAND,
            name="schemas_and_ledger",
            relative_path="0000_expand__schemas_and_ledger.sql",
            checksum_sha256=b"x" * 32,
        )
        with self.assertRaises(FrozenInstanceError):
            descriptor.version = 1

    def test_valid_catalog_preserves_exact_sql_and_manifest_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest_bytes, sql_by_path = self._write_valid_catalog(root)

            catalog = MigrationCatalog.load(root)

            self.assertEqual(catalog.manifest_bytes, manifest_bytes)
            self.assertEqual(
                catalog.manifest_sha256,
                hashlib.sha256(manifest_bytes).digest(),
            )
            self.assertEqual(len(catalog.artifacts), len(IAM_MIGRATION_LAYOUT))
            for artifact, expected in zip(catalog.artifacts, IAM_MIGRATION_LAYOUT):
                version, phase, name, relative_path = expected
                self.assertEqual(artifact.descriptor.component, "iam")
                self.assertEqual(artifact.descriptor.version, version)
                self.assertEqual(artifact.descriptor.phase, phase)
                self.assertEqual(artifact.descriptor.name, name)
                self.assertEqual(artifact.descriptor.relative_path, relative_path)
                self.assertEqual(artifact.sql_bytes, sql_by_path[relative_path])
                self.assertEqual(
                    artifact.descriptor.checksum_sha256,
                    hashlib.sha256(sql_by_path[relative_path]).digest(),
                )

    def test_manifest_must_be_the_one_canonical_raw_byte_encoding(self) -> None:
        mutations = {
            "bom": lambda value: b"\xef\xbb\xbf" + value,
            "crlf": lambda value: value.replace(b"\n", b"\r\n"),
            "missing-final-lf": lambda value: value[:-1],
            "extra-final-lf": lambda value: value + b"\n",
            "leading-space": lambda value: b" " + value,
            "pretty-json": lambda value: json.dumps(
                json.loads(value), indent=2
            ).encode("ascii") + b"\n",
        }
        for label, mutate in mutations.items():
            with self.subTest(encoding=label), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                manifest_bytes, _ = self._write_valid_catalog(root)
                (root / "manifest.json").write_bytes(mutate(manifest_bytes))
                self._assert_catalog_error(root, "MIGRATION_MANIFEST_INVALID")

    def test_manifest_rejects_unknown_or_duplicate_keys(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest_bytes, _ = self._write_valid_catalog(root)
            unknown = manifest_bytes.replace(
                b'"sha256":',
                b'"unknown":"x","sha256":',
                1,
            )
            (root / "manifest.json").write_bytes(unknown)
            self._assert_catalog_error(root, "MIGRATION_MANIFEST_INVALID")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest_bytes, _ = self._write_valid_catalog(root)
            duplicate = manifest_bytes.replace(
                b'"component":"iam",',
                b'"component":"iam","component":"iam",',
                1,
            )
            (root / "manifest.json").write_bytes(duplicate)
            self._assert_catalog_error(root, "MIGRATION_MANIFEST_INVALID")

    def test_version_gap_duplicate_and_layout_drift_are_rejected(self) -> None:
        mutations = {
            "gap": lambda entries: entries[:3] + entries[4:],
            "duplicate": lambda entries: entries[:3] + [entries[2]] + entries[3:],
            "wrong-phase": lambda entries: self._replace_entry(
                entries, 3, phase="contract"
            ),
            "wrong-name": lambda entries: self._replace_entry(
                entries, 4, name="renamed_after_release"
            ),
        }
        for label, mutate in mutations.items():
            with self.subTest(sequence=label), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                _, sql_by_path = self._write_valid_catalog(root)
                entries = self._entries(sql_by_path)
                self._write_manifest(root, mutate(entries))
                self._assert_catalog_error(root, "MIGRATION_VERSION_SEQUENCE_INVALID")

    def test_paths_cannot_escape_scan_or_indirect_the_reviewed_root(self) -> None:
        malicious_paths = (
            "/tmp/0000_expand__schemas_and_ledger.sql",
            "../0000_expand__schemas_and_ledger.sql",
            "nested/0000_expand__schemas_and_ledger.sql",
            "https://example.invalid/migration.sql",
            "%2e%2e%2fmigration.sql",
        )
        for malicious_path in malicious_paths:
            with self.subTest(path=malicious_path), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                _, sql_by_path = self._write_valid_catalog(root)
                entries = self._entries(sql_by_path)
                entries[0] = dict(entries[0], path=malicious_path)
                self._write_manifest(root, entries)
                self._assert_catalog_error(root, "MIGRATION_PATH_INVALID")

    def test_symlinked_sql_is_rejected_even_when_its_bytes_match(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _, sql_by_path = self._write_valid_catalog(root)
            relative_path = IAM_MIGRATION_LAYOUT[0][3]
            sql_path = root / relative_path
            target = root / "unreviewed-target.sql"
            target.write_bytes(sql_by_path[relative_path])
            sql_path.unlink()
            sql_path.symlink_to(target)
            self._assert_catalog_error(root, "MIGRATION_PATH_INVALID")

    def test_sql_rejects_noncanonical_bytes_before_checksum_or_execution(self) -> None:
        mutations = {
            "bom": b"\xef\xbb\xbfSELECT 1;\n",
            "crlf": b"SELECT 1;\r\n",
            "invalid-utf8": b"SELECT '\xff';\n",
            "missing-final-lf": b"SELECT 1;",
            "double-final-lf": b"SELECT 1;\n\n",
        }
        for label, bad_bytes in mutations.items():
            with self.subTest(sql_bytes=label), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                _, sql_by_path = self._write_valid_catalog(root)
                relative_path = IAM_MIGRATION_LAYOUT[2][3]
                (root / relative_path).write_bytes(bad_bytes)
                entries = self._entries(sql_by_path)
                entries[2] = dict(
                    entries[2],
                    sha256=hashlib.sha256(bad_bytes).hexdigest(),
                )
                self._write_manifest(root, entries)
                self._assert_catalog_error(root, "MIGRATION_SQL_ENCODING_INVALID")

    def test_manifest_checksum_must_match_the_exact_sql_raw_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_valid_catalog(root)
            relative_path = IAM_MIGRATION_LAYOUT[5][3]
            (root / relative_path).write_bytes(b"SELECT 999;\n")
            self._assert_catalog_error(root, "MIGRATION_CHECKSUM_MISMATCH")

    def test_root_descriptor_is_closed_when_fstat_fails(self) -> None:
        """A failed root inspection cannot leak its already-open descriptor."""

        with tempfile.TemporaryDirectory() as directory:
            root_fd = os.open(directory, os.O_RDONLY)
            with patch.object(catalog_module.os, "open", return_value=root_fd), patch.object(
                catalog_module.os,
                "fstat",
                side_effect=OSError("scripted fstat failure"),
            ):
                self._assert_catalog_error(
                    Path(directory),
                    "MIGRATION_PATH_INVALID",
                )

            with self.assertRaises(OSError):
                os.fstat(root_fd)

    def _write_valid_catalog(self, root: Path):
        sql_by_path = {
            relative_path: ("SELECT %d;\n" % version).encode("ascii")
            for version, _phase, _name, relative_path in IAM_MIGRATION_LAYOUT
        }
        for relative_path, sql_bytes in sql_by_path.items():
            (root / relative_path).write_bytes(sql_bytes)
        manifest_bytes = self._write_manifest(root, self._entries(sql_by_path))
        return manifest_bytes, sql_by_path

    def _entries(self, sql_by_path):
        return [
            {
                "component": "iam",
                "version": version,
                "phase": phase.value,
                "name": name,
                "path": relative_path,
                "sha256": hashlib.sha256(sql_by_path[relative_path]).hexdigest(),
            }
            for version, phase, name, relative_path in IAM_MIGRATION_LAYOUT
        ]

    def _write_manifest(self, root: Path, entries):
        manifest_bytes = json.dumps(
            entries,
            ensure_ascii=True,
            separators=(",", ":"),
        ).encode("ascii") + b"\n"
        (root / "manifest.json").write_bytes(manifest_bytes)
        return manifest_bytes

    @staticmethod
    def _replace_entry(entries, index, **changes):
        changed = list(entries)
        changed[index] = dict(changed[index], **changes)
        return changed

    def _assert_catalog_error(self, root: Path, expected_code: str) -> None:
        with self.assertRaises(MigrationCatalogError) as raised:
            MigrationCatalog.load(root)
        self.assertEqual(raised.exception.code, expected_code)


if __name__ == "__main__":
    unittest.main()
