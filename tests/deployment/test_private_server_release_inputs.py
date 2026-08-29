"""Closed release-input snapshot contracts for private-server activation."""

from __future__ import annotations

import copy
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock

import scripts.private_server_release_inputs as release_inputs
from scripts.private_server_release_inputs import (
    PrivateServerReleaseInputError,
    measure_private_server_release_inputs,
    stage_private_server_release_inputs,
    verify_private_server_release_inputs,
)


IDENTITIES = {
    "access_admin_01.subject": b"sandbox:access-admin-01",
    "access_admin_01.email": b"sandbox-access-admin-01@example.test",
    "appeal_reviewer_01.subject": b"sandbox:appeal-reviewer-01",
    "appeal_reviewer_01.email": b"sandbox-appeal-reviewer-01@example.test",
    "creator_01.subject": b"sandbox:creator-01",
    "creator_01.email": b"sandbox-creator-01@example.test",
    "demand_owner_01.subject": b"sandbox:demand-owner-01",
    "demand_owner_01.email": b"sandbox-demand-owner-01@example.test",
    "finance_operator_01.subject": b"sandbox:finance-operator-01",
    "finance_operator_01.email": b"sandbox-finance-operator-01@example.test",
    "finance_operator_02.subject": b"sandbox:finance-operator-02",
    "finance_operator_02.email": b"sandbox-finance-operator-02@example.test",
    "operations_reviewer_01.subject": b"sandbox:operations-reviewer-01",
    "operations_reviewer_01.email": b"sandbox-operations-reviewer-01@example.test",
    "org_admin_01.subject": b"sandbox:org-admin-01",
    "org_admin_01.email": b"sandbox-org-admin-01@example.test",
    "trust_officer_01.subject": b"sandbox:trust-officer-01",
    "trust_officer_01.email": b"sandbox-trust-officer-01@example.test",
    "trust_officer_02.subject": b"sandbox:trust-officer-02",
    "trust_officer_02.email": b"sandbox-trust-officer-02@example.test",
}

API_CAPABILITIES = (
    ("IAM_APP", "iam_app", "db-iam-app-v1"),
    (
        "IAM_SESSION_AUTHENTICATOR",
        "iam_session_authenticator",
        "db-iam-session-authenticator-v1",
    ),
    ("IAM_ONBOARDING", "iam_onboarding", "db-iam-onboarding-v1"),
    ("PROFILE_APP", "profile_app", "db-profile-app-v1"),
    ("DEMAND_SELF", "demand_self", "db-demand-self-v1"),
    ("DEMAND_REVIEW", "demand_review", "db-demand-review-v1"),
    ("DEMAND_FINANCE", "demand_finance", "db-demand-finance-v1"),
    ("TRUST_SELF", "trust_self", "db-trust-self-v1"),
    ("TRUST_OFFICER", "trust_officer", "db-trust-officer-v1"),
    ("TRUST_APPEAL", "trust_appeal", "db-trust-appeal-v1"),
    ("TRUST_DECISION", "trust_decision", "db-trust-decision-v1"),
    ("MATCHING_CREATOR", "matching_creator", "db-matching-creator-v1"),
    ("MATCHING_SELECTOR", "matching_selector", "db-matching-selector-v1"),
    ("MATCHING_ASSIGNMENT", "matching_assignment", "db-matching-assignment-v1"),
    ("MATCHING_REVIEW", "matching_review", "db-matching-review-v1"),
)
MATCHING_RUNTIME_CAPABILITIES = (
    ("DEMAND_MATCHING", "demand_matching", "db-demand-matching-v1"),
    ("PROFILE_MATCHER", "profile_matcher", "db-profile-matcher-v1"),
    ("TRUST_DECISION", "trust_decision", "db-trust-decision-v1"),
    ("MATCHING_WORKER", "matching_worker", "db-matching-worker-v1"),
    (
        "MATCHING_COORDINATOR",
        "matching_coordinator",
        "db-matching-coordinator-v1",
    ),
)
ONLINE_CAPABILITIES = API_CAPABILITIES + tuple(
    item
    for item in MATCHING_RUNTIME_CAPABILITIES
    if item not in API_CAPABILITIES
)
CAPABILITIES = API_CAPABILITIES

API_KEYS = (
    ("key-oidc-state-v1", "OIDC_STATE", "oidc-state-v1", "ACTIVE"),
    (
        "key-oidc-browser-binding-v1",
        "OIDC_BROWSER_BINDING",
        "oidc-browser-binding-v1",
        "ACTIVE",
    ),
    ("key-oidc-nonce-v1", "OIDC_NONCE", "oidc-nonce-v1", "ACTIVE"),
    ("key-session-handle-v1", "SESSION_HANDLE", "session-handle-v1", "ACTIVE"),
    ("key-csrf-v1", "CSRF", "csrf-v1", "ACTIVE"),
    (
        "key-oidc-protocol-aead-v1",
        "OIDC_PROTOCOL_AEAD",
        "oidc-protocol-aead-v1",
        "ACTIVE",
    ),
    (
        "key-oidc-subject-digest-v1",
        "OIDC_SUBJECT_DIGEST",
        "oidc-subject-digest-v1",
        "ACTIVE",
    ),
    (
        "key-oidc-recipient-binding-v1",
        "OIDC_RECIPIENT_BINDING",
        "oidc-recipient-binding-v1",
        "ACTIVE",
    ),
    (
        "key-oidc-client-secret-v1",
        "OIDC_CLIENT_SECRET",
        "oidc-client-secret-v1",
        "ACTIVE",
    ),
    (
        "key-editor-id-derivation-v1",
        "EDITOR_ID_DERIVATION",
        "editor-id-derivation-v1",
        "ACTIVE",
    ),
    (
        "key-profile-idempotency-v1",
        "PROFILE_IDEMPOTENCY",
        "profile-idempotency-v1",
        "ACTIVE",
    ),
    (
        "key-profile-payload-hash-v1",
        "PROFILE_PAYLOAD_HASH",
        "profile-payload-hash-v1",
        "ACTIVE",
    ),
    (
        "key-demand-idempotency-v1",
        "DEMAND_IDEMPOTENCY",
        "demand-idempotency-2026-01",
        "ACTIVE",
    ),
    (
        "key-demand-idempotency-retained-2025-12",
        "DEMAND_IDEMPOTENCY",
        "demand-idempotency-retained-2025-12",
        "VERIFY_ONLY",
    ),
    (
        "key-demand-payload-hash-v1",
        "DEMAND_PAYLOAD_HASH",
        "demand-payload-2026-01",
        "ACTIVE",
    ),
    (
        "key-demand-payload-retained-2025-12",
        "DEMAND_PAYLOAD_HASH",
        "demand-payload-retained-2025-12",
        "VERIFY_ONLY",
    ),
    (
        "key-demand-client-reference-v1",
        "DEMAND_CLIENT_REFERENCE",
        "demand-client-reference-v1",
        "ACTIVE",
    ),
    (
        "key-iam-receipt-idempotency-hmac-2026-01",
        "PLATFORM_USER_IDEMPOTENCY",
        "iam-receipt-idempotency-hmac-2026-01",
        "ACTIVE",
    ),
    (
        "key-iam-receipt-payload-hmac-2026-01",
        "PLATFORM_USER_PAYLOAD_HASH",
        "iam-receipt-payload-hmac-2026-01",
        "ACTIVE",
    ),
    (
        "key-access-invitation-token-v1",
        "ACCESS_INVITATION_TOKEN",
        "access-invitation-token-v1",
        "ACTIVE",
    ),
    (
        "key-iam-read-cursor-v1",
        "IAM_READ_CURSOR",
        "iam-read-cursor-v1",
        "ACTIVE",
    ),
    (
        "key-trust-idempotency-v1",
        "TRUST_IDEMPOTENCY",
        "trust-idempotency-2026-01",
        "ACTIVE",
    ),
    (
        "key-trust-payload-hash-v1",
        "TRUST_PAYLOAD_HASH",
        "trust-payload-2026-01",
        "ACTIVE",
    ),
    (
        "key-trust-sealed-note-v1",
        "TRUST_SEALED_NOTE",
        "trust-sealed-note-v1",
        "ACTIVE",
    ),
    (
        "key-trust-report-cursor-v1",
        "TRUST_REPORT_CURSOR",
        "trust-report-cursor-2026-01",
        "ACTIVE",
    ),
    (
        "key-matching-idempotency-v1",
        "MATCHING_IDEMPOTENCY",
        "matching-idempotency-v1",
        "ACTIVE",
    ),
    (
        "key-matching-payload-v1",
        "MATCHING_PAYLOAD_HASH",
        "matching-payload-v1",
        "ACTIVE",
    ),
    (
        "key-matching-read-cursor-v1",
        "MATCHING_READ_CURSOR",
        "matching-read-cursor-v1",
        "ACTIVE",
    ),
)
MATCHING_RUNTIME_KEYS = (
    (
        "key-matching-worker-idempotency-v1",
        "MATCHING_WORKER_IDEMPOTENCY",
        "matching-worker-idempotency-v1",
        "ACTIVE",
    ),
    (
        "key-matching-worker-payload-hash-v1",
        "MATCHING_WORKER_PAYLOAD_HASH",
        "matching-worker-payload-hash-v1",
        "ACTIVE",
    ),
    (
        "key-matching-worker-lease-digest-v1",
        "MATCHING_WORKER_LEASE_DIGEST",
        "matching-worker-lease-digest-v1",
        "ACTIVE",
    ),
    (
        "key-matching-coordinator-idempotency-v1",
        "MATCHING_COORDINATOR_IDEMPOTENCY",
        "matching-coordinator-idempotency-v1",
        "ACTIVE",
    ),
    (
        "key-matching-coordinator-payload-hash-v1",
        "MATCHING_COORDINATOR_PAYLOAD_HASH",
        "matching-coordinator-payload-hash-v1",
        "ACTIVE",
    ),
    (
        "key-matching-coordinator-lease-digest-v1",
        "MATCHING_COORDINATOR_LEASE_DIGEST",
        "matching-coordinator-lease-digest-v1",
        "ACTIVE",
    ),
)
KEYS = API_KEYS


def _write(path: Path, value: bytes, mode: int) -> None:
    path.write_bytes(value)
    path.chmod(mode)


class PrivateServerReleaseInputTest(unittest.TestCase):
    def setUp(self) -> None:
        # The production gate deliberately reserves frozen v13 coordinates in
        # every supplied path.  TemporaryDirectory suffixes are random, so a
        # suffix can otherwise contain ``v13`` by chance and make this suite
        # nondeterministic.  Allocate outside that reserved namespace.
        for _attempt in range(100):
            self.temporary = tempfile.TemporaryDirectory()
            # macOS exposes TemporaryDirectory through /var -> /private/var.
            # Feed the API the canonical spelling it deliberately requires.
            parent = Path(self.temporary.name).resolve(strict=True)
            lowered = str(parent).encode("utf-8").lower()
            if not any(token in lowered for token in release_inputs._FROZEN_TOKENS):
                break
            self.temporary.cleanup()
        else:  # pragma: no cover - requires 100 consecutive reserved suffixes
            self.fail("could not allocate a non-reserved temporary directory")
        self.input_root = parent / "input"
        self.stage_root = parent / "stage"
        self.bundle_name = "internal-sandbox-bundle-private-a1"
        self.input_root.mkdir(mode=0o700)
        self.stage_root.mkdir(mode=0o700)
        self._build_fixture()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _build_fixture(self) -> None:
        _write(self.input_root / "compose.env", b"closed-compose-env\n", 0o600)
        _write(self.input_root / "compose.ipam.yaml", b"closed-ipam\n", 0o600)
        source_secrets = {
            "db_superuser_password.txt": b"A" * 48,
            "taxonomy_seed_workload_credential": b"B" * 48,
            "taxonomy_seed_receipt_hmac_key": b"C" * 32,
            "oidc-client-secret": b"D" * 48,
        }
        for name, value in source_secrets.items():
            _write(self.input_root / name, value, 0o600)

        identity = self.input_root / "internal-sandbox-identity-sources"
        identity.mkdir(mode=0o755)
        for name, value in IDENTITIES.items():
            _write(identity / name, value, 0o444)

        tls = self.input_root / "internal-sandbox-tls"
        tls.mkdir(mode=0o700)
        _write(tls / "root-ca.pem", b"synthetic root certificate\n", 0o444)
        _write(tls / "edge-tls-chain.pem", b"synthetic leaf and root chain\n", 0o444)
        _write(tls / "edge-tls-key.pem", b"synthetic private key\n", 0o400)

        bundle = self.input_root / self.bundle_name
        config = bundle / "config"
        materials = bundle / "runtime-secrets"
        config.mkdir(parents=True, mode=0o700)
        materials.mkdir(mode=0o700)
        bundle.chmod(0o700)

        profiles_by_capability = {}
        database_entries_by_capability = {}
        for capability, role, file_name in ONLINE_CAPABILITIES:
            slug = capability.lower().replace("_", "-")
            credential_ref = f"secret://sandbox-db/{slug}#v1"
            profiles_by_capability[capability] = {
                "capability_id": capability,
                "online_role": role,
                "credential_ref": credential_ref,
                "application_name": f"desire-{slug}",
                "max_pool_size": 4,
                "checkout_timeout_ms": 2_000,
                "statement_timeout_ms": 15_000,
                "lock_timeout_ms": 2_000,
                "idle_in_transaction_timeout_ms": 15_000,
            }
            database_entries_by_capability[capability] = {
                "kind": "DATABASE_CREDENTIAL",
                "file_name": file_name,
                "credential_ref": credential_ref,
                "purpose": f"DATABASE_CREDENTIAL:{capability}",
                "key_id": "v1",
                "not_before": "2026-01-01T00:00:00Z",
                "not_after": "2030-01-01T00:00:00Z",
                "status": "ACTIVE",
            }

        def key_entries(keys):
            return [
                {
                    "kind": "KEY",
                    "file_name": file_name,
                    "credential_ref": None,
                    "purpose": purpose,
                    "key_id": key_id,
                    "not_before": "2026-01-01T00:00:00Z",
                    "not_after": "2030-01-01T00:00:00Z",
                    "status": status,
                }
                for file_name, purpose, key_id, status in keys
            ]

        def key_requirements(keys):
            requirements = []
            for purpose in dict.fromkeys(item[1] for item in keys):
                entries = [item for item in keys if item[1] == purpose]
                active = next(item[2] for item in entries if item[3] == "ACTIVE")
                requirements.append(
                    {
                        "purpose": purpose,
                        "active_key_id": active,
                        "retained_key_ids": [item[2] for item in entries],
                    }
                )
            return requirements

        def runtime(capabilities, keys, *, instance_id, process_kind):
            return {
                "schema_name": "desire-runtime-config-v1",
                "identity": {
                    "environment_id": "internal-sandbox",
                    "deployment_id": "private-20260824-a1",
                    "release_id": "release-20260824-a1",
                    "region": "trusted-container-network",
                    "instance_id": instance_id,
                },
                "process": {
                    "kind": process_kind,
                    "capability_ids": [item[0] for item in capabilities],
                },
                "artifacts": [
                    {"artifact_id": "fixture-v1", "sha256": "a" * 64}
                ],
                "database_profiles": [
                    profiles_by_capability[item[0]] for item in capabilities
                ],
                "key_requirements": key_requirements(keys),
                "budgets": {
                    "startup_timeout_ms": 30_000,
                    "readiness_timeout_ms": 3_000,
                    "shutdown_timeout_ms": 15_000,
                },
            }

        def manifest(capabilities, keys):
            return {
                "schema_name": "desire-file-secret-manifest-v1",
                "entries": [
                    database_entries_by_capability[item[0]]
                    for item in capabilities
                ]
                + key_entries(keys),
            }

        deployment = {
            "schema_name": "desire-internal-sandbox-deployment-v1",
            "deployment_mode": "INTERNAL_SANDBOX",
            "external_participants_enabled": False,
            "internal_bff_origin": "http://api:8000",
            "runtime_config_path": "/run/desire/runtime-config.json",
            "secret_manifest_path": "/run/desire/secret-manifest.json",
            "secret_root": "/run/secrets",
            "postgres": {
                "host": "db",
                "port": 5432,
                "database": "desire",
                "transport_security": "TRUSTED_CONTAINER_NETWORK",
            },
            "oidc": {
                "issuer": "https://identity.example.test",
                "client_id": "desire-internal-sandbox",
                "client_secret_key_id": "oidc-client-secret-v1",
                "redirect_uri": "https://pilot.example.test/v1/auth/oidc/callback",
                "allowed_signing_algorithms": ["RS256"],
                "metadata_ttl_seconds": 300,
                "request_timeout_seconds": 3,
                "maximum_response_bytes": 262_144,
                "clock_skew_seconds": 30,
                "subject_digest_key_id": "oidc-subject-digest-v1",
                "network_binding": {
                    "mode": "SYSTEM_DNS_SYNTHETIC",
                    "pinned_public_ipv4": None,
                },
            },
            "system_actor_id": "10000000-0000-4000-8000-000000000001",
            "bind": {"host": "0.0.0.0", "port": 8000},
        }
        documents = {
            "deployment.json": deployment,
            "runtime-config.json": runtime(
                API_CAPABILITIES,
                API_KEYS,
                instance_id="api-0001",
                process_kind="web-api",
            ),
            "secret-manifest.json": manifest(API_CAPABILITIES, API_KEYS),
            "matching-deployment.json": {
                **deployment,
                "runtime_config_path": (
                    "/run/desire/matching-runtime-config.json"
                ),
                "secret_manifest_path": (
                    "/run/desire/matching-secret-manifest.json"
                ),
            },
            "matching-runtime-config.json": runtime(
                MATCHING_RUNTIME_CAPABILITIES,
                MATCHING_RUNTIME_KEYS,
                instance_id="matching-runtime-0001",
                process_kind="domain-process",
            ),
            "matching-secret-manifest.json": manifest(
                MATCHING_RUNTIME_CAPABILITIES,
                MATCHING_RUNTIME_KEYS,
            ),
            "online-credentials-deployment.json": {
                **deployment,
                "runtime_config_path": (
                    "/run/desire/online-credentials-runtime-config.json"
                ),
                "secret_manifest_path": (
                    "/run/desire/online-credentials-secret-manifest.json"
                ),
            },
            "online-credentials-runtime-config.json": runtime(
                ONLINE_CAPABILITIES,
                (),
                instance_id="online-credentials-0001",
                process_kind="migration",
            ),
            "online-credentials-secret-manifest.json": manifest(
                ONLINE_CAPABILITIES,
                (),
            ),
        }
        for name, document in documents.items():
            _write(
                config / name,
                json.dumps(document, separators=(",", ":")).encode("ascii"),
                0o600,
            )

        oidc_file = "key-oidc-client-secret-v1"
        material_names = {
            item[2] for item in ONLINE_CAPABILITIES
        } | {
            item[0] for item in API_KEYS + MATCHING_RUNTIME_KEYS
        }
        for name in sorted(material_names):
            if name == oidc_file:
                value = source_secrets["oidc-client-secret"]
            else:
                length = 32 if name == "key-oidc-protocol-aead-v1" else 48
                value = hashlib.sha512(("material:" + name).encode("ascii")).hexdigest()[
                    :length
                ].encode("ascii")
            _write(materials / name, value, 0o600)

    def _stage(self):
        return stage_private_server_release_inputs(
            input_root=self.input_root,
            bundle_name=self.bundle_name,
            attempt_stage_root=self.stage_root,
        )

    def _source_inventory(self):
        inventory = []
        for path in sorted(
            (self.input_root, *self.input_root.rglob("*")),
            key=lambda item: item.as_posix(),
        ):
            metadata = path.lstat()
            value = path.read_bytes() if path.is_file() else None
            inventory.append(
                (
                    path.relative_to(self.input_root).as_posix(),
                    metadata.st_dev,
                    metadata.st_ino,
                    metadata.st_mode,
                    metadata.st_uid,
                    metadata.st_gid,
                    metadata.st_nlink,
                    metadata.st_size,
                    metadata.st_mtime_ns,
                    metadata.st_ctime_ns,
                    value,
                )
            )
        return tuple(inventory)

    def test_measure_and_verify_are_read_only_and_match_the_staged_tree(self) -> None:
        before = self._source_inventory()
        real_open = release_inputs.os.open

        def read_only_open(path, flags, *arguments, **keywords):
            forbidden = (
                os.O_WRONLY
                | os.O_RDWR
                | os.O_CREAT
                | os.O_TRUNC
                | os.O_APPEND
            )
            self.assertEqual(flags & forbidden, 0)
            return real_open(path, flags, *arguments, **keywords)

        with (
            mock.patch.object(release_inputs.os, "open", side_effect=read_only_open),
            mock.patch.object(
                release_inputs.os,
                "mkdir",
                side_effect=AssertionError("measure must not create directories"),
            ),
            mock.patch.object(
                release_inputs.os,
                "write",
                side_effect=AssertionError("measure must not write"),
            ),
            mock.patch.object(
                release_inputs.os,
                "fsync",
                side_effect=AssertionError("measure must not fsync"),
            ),
            mock.patch.object(
                release_inputs,
                "_stage_tree",
                side_effect=AssertionError("measure must not stage"),
            ),
        ):
            measured = measure_private_server_release_inputs(
                input_root=self.input_root,
                bundle_name=self.bundle_name,
            )
            verified = verify_private_server_release_inputs(
                input_root=self.input_root,
                bundle_name=self.bundle_name,
                expected_tree_sha256=measured.tree_sha256,
            )
            with self.assertRaises(PrivateServerReleaseInputError):
                verify_private_server_release_inputs(
                    input_root=self.input_root,
                    bundle_name=self.bundle_name,
                    expected_tree_sha256="0" * 64,
                )

        self.assertEqual(measured, verified)
        self.assertEqual(measured.file_count, 91)
        self.assertRegex(measured.tree_sha256, r"^[0-9a-f]{64}$")
        self.assertNotIn(str(self.input_root), repr(measured))
        self.assertEqual(before, self._source_inventory())
        self.assertEqual(tuple(self.stage_root.iterdir()), ())

        staged = self._stage()
        self.assertEqual(staged.tree_sha256, measured.tree_sha256)

    def test_measure_and_verify_cli_outputs_are_closed_and_non_authoritative(self) -> None:
        measured = measure_private_server_release_inputs(
            input_root=self.input_root,
            bundle_name=self.bundle_name,
        )
        common = (
            "--input-root",
            str(self.input_root),
            "--bundle-name",
            self.bundle_name,
        )

        stdout = io.StringIO()
        stderr = io.StringIO()
        result = release_inputs.main(
            ("measure", *common),
            stdout=stdout,
            stderr=stderr,
        )
        expected_measure = {
            "authority": "NOT_AUTHORITY",
            "execution_permitted": False,
            "file_count": 91,
            "production_authorized": False,
            "status": "PRIVATE_SERVER_RELEASE_INPUTS_MEASURED_NOT_AUTHORITY",
            "tree_sha256": measured.tree_sha256,
        }
        self.assertEqual(result, 0)
        self.assertEqual(json.loads(stdout.getvalue()), expected_measure)
        self.assertEqual(
            stdout.getvalue(),
            json.dumps(
                expected_measure,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            )
            + "\n",
        )
        self.assertEqual(stderr.getvalue(), "")
        self.assertNotIn(str(self.input_root), stdout.getvalue())
        self.assertNotIn(self.bundle_name, stdout.getvalue())
        self.assertNotIn("A" * 48, stdout.getvalue())

        stdout = io.StringIO()
        stderr = io.StringIO()
        result = release_inputs.main(
            (
                "verify",
                *common,
                "--expected-tree-sha256",
                measured.tree_sha256,
            ),
            stdout=stdout,
            stderr=stderr,
        )
        expected_verify = dict(expected_measure)
        expected_verify["status"] = (
            "PRIVATE_SERVER_RELEASE_INPUTS_VERIFIED_NOT_AUTHORITY"
        )
        self.assertEqual(result, 0)
        self.assertEqual(json.loads(stdout.getvalue()), expected_verify)
        self.assertEqual(stderr.getvalue(), "")
        self.assertEqual(tuple(self.stage_root.iterdir()), ())

    def test_verify_cli_rejects_mismatch_and_hostile_arguments_without_reflection(self) -> None:
        blocked = (
            '{"code":"PRIVATE_SERVER_RELEASE_INPUT_INVALID",'
            '"status":"BLOCKED"}\n'
        )
        variants = (
            (
                "verify",
                "--input-root",
                str(self.input_root),
                "--bundle-name",
                self.bundle_name,
                "--expected-tree-sha256",
                "0" * 64,
            ),
            (
                "measure",
                "--input-root",
                str(self.input_root),
                "--bundle-name",
                "SECRET-PATH-MUST-NOT-REFLECT",
            ),
            ("measure", "--hostile-secret-option", "must-not-reflect"),
        )
        for argv in variants:
            with self.subTest(argv=argv[0:1]):
                stdout = io.StringIO()
                stderr = io.StringIO()
                result = release_inputs.main(argv, stdout=stdout, stderr=stderr)
                self.assertEqual((result, stdout.getvalue(), stderr.getvalue()), (78, "", blocked))
                self.assertNotIn("must-not-reflect", stderr.getvalue().casefold())
        self.assertEqual(tuple(self.stage_root.iterdir()), ())

    def test_stages_one_closed_tree_and_returns_only_immutable_metadata(self) -> None:
        report = self._stage()

        self.assertRegex(report.tree_sha256, r"^[0-9a-f]{64}$")
        self.assertEqual(len(report.source_to_staged), 91)
        self.assertNotIn("A" * 48, repr(report))
        with self.assertRaises(TypeError):
            report.source_to_staged[self.input_root / "new"] = self.stage_root / "new"
        for source, staged in report.source_to_staged.items():
            relative = source.relative_to(self.input_root)
            self.assertEqual(staged.relative_to(self.stage_root), relative)
            self.assertEqual(staged.read_bytes(), source.read_bytes())
            expected_mode = (
                0o600
                if relative.as_posix() in release_inputs._PRIVATE_STAGED_FILES
                else 0o444
            )
            self.assertEqual(stat.S_IMODE(staged.stat().st_mode), expected_mode)

    def test_platform_parser_sources_are_hash_pinned(self) -> None:
        for path, expected in (
            (
                release_inputs._RUNTIME_PARSER_PATH,
                release_inputs._RUNTIME_PARSER_SHA256,
            ),
            (
                release_inputs._SECRET_PARSER_PATH,
                release_inputs._SECRET_PARSER_SHA256,
            ),
        ):
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), expected)

    def test_snapshot_mapping_closes_the_real_compose_contract(self) -> None:
        from scripts.private_server_compose_contract import (
            build_canonical_private_server_compose,
        )
        from tests.deployment import test_private_server_compose_contract as fixture

        snapshot = self._stage()
        document, unused = fixture._raw_config()
        del unused
        old_root = "/srv/desire/input"
        template = (
            Path(__file__).resolve().parents[2]
            / "platform"
            / "examples"
            / "internal-sandbox-identity-bootstrap-template-v1.json"
        )
        old_template = document["configs"][
            "internal-sandbox-identity-template"
        ]["file"]

        def rewrite(value):
            if isinstance(value, dict):
                return {key: rewrite(item) for key, item in value.items()}
            if isinstance(value, list):
                return [rewrite(item) for item in value]
            bundle_root = old_root + "/bundle"
            if isinstance(value, str) and (
                value == bundle_root or value.startswith(bundle_root + "/")
            ):
                return str(self.input_root / self.bundle_name) + value[
                    len(bundle_root) :
                ]
            if isinstance(value, str) and value.startswith(old_root):
                return str(self.input_root) + value[len(old_root) :]
            if value == old_template:
                return str(template)
            return value

        document = rewrite(document)
        mapping = dict(snapshot.source_to_staged)
        staged_template = self.stage_root.parent / template.name
        mapping[template] = staged_template
        canonical, closed = build_canonical_private_server_compose(
            json.dumps(document),
            project=fixture.PROJECT,
            bind_ip=fixture.BIND_IP,
            subnets=fixture.SUBNETS,
            image_tag=fixture.IMAGE_TAG,
            source_to_staged=mapping,
            image_ref_to_id=fixture.IMAGE_IDS,
        )
        self.assertNotIn(str(self.input_root).encode(), canonical)
        identity = closed["services"]["identity-bootstrap"]["volumes"][0]
        self.assertEqual(
            identity["source"],
            str(self.stage_root / "internal-sandbox-identity-sources"),
        )

    def test_rejects_symlink_hardlink_and_extra_entry(self) -> None:
        identity = self.input_root / "internal-sandbox-identity-sources"
        victim = identity / "access_admin_01.subject"
        victim.unlink()
        victim.symlink_to(identity / "access_admin_01.email")
        with self.assertRaises(PrivateServerReleaseInputError):
            self._stage()

        self.tearDown()
        self.setUp()
        material = self.input_root / self.bundle_name / "runtime-secrets" / "db-iam-app-v1"
        os.link(material, Path(self.temporary.name) / "hardlink-alias")
        with self.assertRaises(PrivateServerReleaseInputError):
            self._stage()

        self.tearDown()
        self.setUp()
        _write(self.input_root / "unexpected", b"unexpected", 0o600)
        with self.assertRaises(PrivateServerReleaseInputError):
            self._stage()

    def test_rejects_frozen_json_coordinate_and_manifest_filename_mismatch(self) -> None:
        runtime_path = self.input_root / self.bundle_name / "config" / "runtime-config.json"
        runtime_raw = runtime_path.read_bytes().replace(
            b'"release_id":"release-20260824-a1"',
            b'"release_id":"release-v\\u00313-reuse"',
        )
        _write(runtime_path, runtime_raw, 0o600)
        with self.assertRaises(PrivateServerReleaseInputError):
            self._stage()

        self.tearDown()
        self.setUp()
        manifest_path = self.input_root / self.bundle_name / "config" / "secret-manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="ascii"))
        manifest["entries"] = manifest["entries"][:-1]
        _write(
            manifest_path,
            json.dumps(manifest, separators=(",", ":")).encode("ascii"),
            0o600,
        )
        with self.assertRaises(PrivateServerReleaseInputError):
            self._stage()

    def test_synthetic_deployment_requires_system_dns_network_binding(self) -> None:
        deployment_path = (
            self.input_root
            / self.bundle_name
            / "config/deployment.json"
        )
        deployment = json.loads(deployment_path.read_text(encoding="ascii"))
        for network_binding in (
            {
                "mode": "PINNED_PUBLIC_IP",
                "pinned_public_ipv4": "8.8.8.8",
            },
            {
                "mode": "SYSTEM_DNS_SYNTHETIC",
                "pinned_public_ipv4": "8.8.8.8",
            },
            None,
        ):
            candidate = copy.deepcopy(deployment)
            if network_binding is None:
                del candidate["oidc"]["network_binding"]
            else:
                candidate["oidc"]["network_binding"] = network_binding
            _write(
                deployment_path,
                json.dumps(candidate, separators=(",", ":")).encode("ascii"),
                0o600,
            )
            with self.subTest(network_binding=network_binding):
                with self.assertRaises(PrivateServerReleaseInputError):
                    self._stage()
        _write(
            deployment_path,
            json.dumps(deployment, separators=(",", ":")).encode("ascii"),
            0o600,
        )

    def test_source_mutation_after_read_does_not_change_staged_bytes(self) -> None:
        source = self.input_root / "db_superuser_password.txt"
        original = source.read_bytes()
        measurement = measure_private_server_release_inputs(
            input_root=self.input_root,
            bundle_name=self.bundle_name,
        )
        original_validator = release_inputs._validate_source_values

        def mutate_after_snapshot(records) -> None:
            original_validator(records)
            _write(source, b"Z" * len(original), 0o600)

        with mock.patch.object(
            release_inputs,
            "_validate_source_values",
            side_effect=mutate_after_snapshot,
        ):
            report = self._stage()
        staged = report.source_to_staged[source]

        self.assertEqual(staged.read_bytes(), original)
        self.assertNotEqual(staged.read_bytes(), source.read_bytes())
        self.assertEqual(report.tree_sha256, measurement.tree_sha256)

    def test_requires_current_owner_for_both_roots(self) -> None:
        with mock.patch(
            "scripts.private_server_release_inputs.os.geteuid",
            return_value=os.geteuid() + 1,
        ):
            with self.assertRaises(PrivateServerReleaseInputError):
                self._stage()


if __name__ == "__main__":
    unittest.main()
