"""Closed configuration and CLI contracts for online database credentials."""

from __future__ import annotations

from datetime import datetime, timezone
from io import StringIO
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from desire_platform.deployment import online_credentials
from desire_platform.deployment.online_credentials import (
    ONLINE_ROLE_CREDENTIAL_SPECS,
    OnlineRoleCredentialAction,
    OnlineRoleCredentialConfigurationError,
    OnlineRoleCredentialReport,
    load_online_role_credential_inputs,
)
from desire_platform.internal_pilot.deployment_config import (
    DEPLOYMENT_CONFIG_POINTER_ENV,
)


def _runtime_document() -> dict:
    capabilities = [spec.capability_id for spec in ONLINE_ROLE_CREDENTIAL_SPECS]
    return {
        "schema_name": "desire-runtime-config-v1",
        "identity": {
            "environment_id": "internal-sandbox",
            "deployment_id": "local",
            "release_id": "test",
            "region": "local",
            "instance_id": "api-1",
        },
        "process": {"kind": "migration", "capability_ids": capabilities},
        "artifacts": [{"artifact_id": "platform", "sha256": "a" * 64}],
        "database_profiles": [
            {
                "capability_id": spec.capability_id,
                "online_role": spec.online_role,
                "credential_ref": "secret://sandbox-db/%s#v1"
                % spec.online_role.replace("_", "-"),
                "application_name": "desire-%s"
                % spec.online_role.replace("_", "-"),
                "max_pool_size": 2,
                "checkout_timeout_ms": 2000,
                "statement_timeout_ms": 10000,
                "lock_timeout_ms": 2000,
                "idle_in_transaction_timeout_ms": 15000,
            }
            for spec in ONLINE_ROLE_CREDENTIAL_SPECS
        ],
        "key_requirements": [],
        "budgets": {
            "startup_timeout_ms": 30000,
            "readiness_timeout_ms": 10000,
            "shutdown_timeout_ms": 30000,
        },
    }


class OnlineCredentialConfigurationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix="desire-online-credential-config-"
        )
        root = Path(self.temporary.name)
        self.config_root = root / "config"
        self.secret_root = root / "secrets"
        self.config_root.mkdir()
        self.secret_root.mkdir()
        self.admin_secret = self.secret_root / "db-admin"
        self.admin_secret.write_text(
            "admin-database-password-material-2026",
            encoding="utf-8",
        )
        self.runtime_path = self.config_root / "runtime.json"
        self.manifest_path = self.config_root / "secret-manifest.json"
        self.deployment_path = self.config_root / "deployment.json"
        self.runtime_path.write_text(
            json.dumps(_runtime_document(), separators=(",", ":")),
            encoding="utf-8",
        )
        manifest_entries = []
        for spec in ONLINE_ROLE_CREDENTIAL_SPECS:
            file_name = "%s-v1" % spec.online_role
            (self.secret_root / file_name).write_text(
                "password-material-%s-2026" % spec.online_role,
                encoding="utf-8",
            )
            manifest_entries.append(
                {
                    "kind": "DATABASE_CREDENTIAL",
                    "file_name": file_name,
                    "credential_ref": "secret://sandbox-db/%s#v1"
                    % spec.online_role.replace("_", "-"),
                    "purpose": "DATABASE_CREDENTIAL:%s" % spec.capability_id,
                    "key_id": "v1",
                    "not_before": "2026-08-12T00:00:00Z",
                    "not_after": "2027-08-12T00:00:00Z",
                    "status": "ACTIVE",
                }
            )
        self.manifest_path.write_text(
            json.dumps(
                {
                    "schema_name": "desire-file-secret-manifest-v1",
                    "entries": manifest_entries,
                },
                separators=(",", ":"),
            ),
            encoding="utf-8",
        )
        self.deployment_path.write_text(
            json.dumps(
                {
                    "schema_name": "desire-internal-sandbox-deployment-v1",
                    "deployment_mode": "INTERNAL_SANDBOX",
                    "external_participants_enabled": False,
                    "internal_bff_origin": "http://api:8000",
                    "runtime_config_path": str(self.runtime_path.resolve()),
                    "secret_manifest_path": str(self.manifest_path.resolve()),
                    "secret_root": str(self.secret_root.resolve()),
                    "postgres": {
                        "host": "db",
                        "port": 5432,
                        "database": "desire",
                        "transport_security": "TRUSTED_CONTAINER_NETWORK",
                    },
                    "oidc": {
                        "issuer": "https://id.example.test",
                        "client_id": "desire-internal",
                        "client_secret_key_id": "oidc-client-v1",
                        "redirect_uri": "https://app.example.test/v1/auth/oidc/callback",
                        "allowed_signing_algorithms": ["RS256"],
                        "metadata_ttl_seconds": 300,
                        "request_timeout_seconds": 5,
                        "maximum_response_bytes": 262144,
                        "clock_skew_seconds": 30,
                        "subject_digest_key_id": "oidc-subject-v1",
                        "network_binding": {
                            "mode": "SYSTEM_DNS_SYNTHETIC",
                            "pinned_public_ipv4": None,
                        },
                    },
                    "system_actor_id": "11111111-1111-4111-8111-111111111111",
                    "bind": {"host": "0.0.0.0", "port": 8000},
                },
                separators=(",", ":"),
            ),
            encoding="utf-8",
        )
        self.environment = {
            "DESIRE_DEPLOYMENT_MODE": "INTERNAL_SANDBOX",
            "DESIRE_EXTERNAL_PARTICIPANTS_ENABLED": "false",
            "DESIRE_DATABASE_HOST": "db",
            "DESIRE_DATABASE_NAME": "desire",
            "DESIRE_DATABASE_ADMIN_USER": "postgres",
            "DESIRE_DATABASE_PASSWORD_FILE": str(self.admin_secret),
            DEPLOYMENT_CONFIG_POINTER_ENV: str(self.deployment_path.resolve()),
        }

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_module_cli_is_not_preimported_by_its_package(self) -> None:
        completed = subprocess.run(
            (
                sys.executable,
                "-W",
                "error::RuntimeWarning",
                "-m",
                "desire_platform.deployment.online_credentials",
                "--help",
            ),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
            timeout=30,
        )
        self.assertEqual(completed.returncode, 0)
        self.assertEqual(completed.stderr, "")

    def test_loader_accepts_only_the_exact_online_role_mapping(self) -> None:
        expected = (
            ("IAM_APP", "iam_app"),
            ("IAM_SESSION_AUTHENTICATOR", "iam_session_authenticator"),
            ("IAM_ONBOARDING", "iam_onboarding"),
            ("PROFILE_APP", "profile_app"),
            ("DEMAND_SELF", "demand_self"),
            ("DEMAND_REVIEW", "demand_review"),
            ("DEMAND_FINANCE", "demand_finance"),
            ("TRUST_SELF", "trust_self"),
            ("TRUST_OFFICER", "trust_officer"),
            ("TRUST_APPEAL", "trust_appeal"),
            ("TRUST_DECISION", "trust_decision"),
            ("MATCHING_CREATOR", "matching_creator"),
            ("MATCHING_SELECTOR", "matching_selector"),
            ("MATCHING_ASSIGNMENT", "matching_assignment"),
            ("MATCHING_REVIEW", "matching_review"),
            ("DEMAND_MATCHING", "demand_matching"),
            ("PROFILE_MATCHER", "profile_matcher"),
            ("MATCHING_WORKER", "matching_worker"),
            ("MATCHING_COORDINATOR", "matching_coordinator"),
        )
        self.assertEqual(
            tuple(
                (spec.capability_id, spec.online_role)
                for spec in ONLINE_ROLE_CREDENTIAL_SPECS
            ),
            expected,
        )
        inputs = load_online_role_credential_inputs(
            self.environment,
            allowed_secret_root=self.secret_root,
        )

        self.assertEqual(
            tuple(
                (profile.capability_id, profile.online_role)
                for profile in inputs.runtime_config.database_profiles
            ),
            expected,
        )
        self.assertNotIn(inputs.settings.admin_password, repr(inputs))
        self.assertEqual(inputs.secret_root, self.secret_root.resolve())

    def test_loader_rejects_any_ambient_or_role_mapping_expansion(self) -> None:
        cases = [
            {**self.environment, "DESIRE_DATABASE_PASSWORD": "inline-forbidden"},
            {
                key: value
                for key, value in self.environment.items()
                if key != DEPLOYMENT_CONFIG_POINTER_ENV
            },
        ]
        changed_runtime = _runtime_document()
        changed_runtime["database_profiles"][0]["online_role"] = "iam_system"
        self.runtime_path.write_text(
            json.dumps(changed_runtime, separators=(",", ":")),
            encoding="utf-8",
        )
        cases.append(self.environment)
        for index, environment in enumerate(cases):
            with self.subTest(index=index):
                if index < 2:
                    self.runtime_path.write_text(
                        json.dumps(_runtime_document(), separators=(",", ":")),
                        encoding="utf-8",
                    )
                else:
                    self.runtime_path.write_text(
                        json.dumps(changed_runtime, separators=(",", ":")),
                        encoding="utf-8",
                    )
                with self.assertRaises(OnlineRoleCredentialConfigurationError):
                    load_online_role_credential_inputs(
                        environment,
                        allowed_secret_root=self.secret_root,
                    )

    def test_cli_reports_only_safe_counts_and_action(self) -> None:
        inputs = load_online_role_credential_inputs(
            self.environment,
            allowed_secret_root=self.secret_root,
        )
        report = OnlineRoleCredentialReport(
            action=OnlineRoleCredentialAction.RECONCILE,
            online_roles=tuple(
                spec.online_role for spec in ONLINE_ROLE_CREDENTIAL_SPECS
            ),
        )
        stdout = StringIO()
        stderr = StringIO()
        with (
            patch.object(
                online_credentials,
                "load_online_role_credential_inputs",
                return_value=inputs,
            ),
            patch.object(
                online_credentials,
                "reconcile_online_role_credentials",
                return_value=report,
            ),
        ):
            result = online_credentials.main(
                ["reconcile"],
                environment=self.environment,
                stdout=stdout,
                stderr=stderr,
                clock=lambda: datetime(2026, 8, 12, tzinfo=timezone.utc),
            )

        self.assertEqual(result, 0)
        self.assertEqual(stderr.getvalue(), "")
        self.assertEqual(
            json.loads(stdout.getvalue()),
            {
                "action": "RECONCILE",
                "online_role_count": len(ONLINE_ROLE_CREDENTIAL_SPECS),
                "status": "ONLINE_CREDENTIALS_READY",
            },
        )
        self.assertNotIn(inputs.settings.admin_password, stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
