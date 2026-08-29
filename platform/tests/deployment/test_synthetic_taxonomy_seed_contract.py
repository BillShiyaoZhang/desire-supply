"""Closed configuration/CLI contract for the offline synthetic Taxonomy seed."""

from __future__ import annotations

from io import StringIO
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from desire_platform.deployment import synthetic_taxonomy_seed
from desire_platform.deployment.migrations import DeploymentMigrationSettings
from desire_platform.deployment.synthetic_taxonomy_seed import (
    InternalSandboxTaxonomySeedDeploymentConfigurationError,
    InternalSandboxTaxonomySeedDeploymentInputs,
    TAXONOMY_SEED_RECEIPT_HMAC_KEY_FILE_ENV,
    TAXONOMY_SEED_WORKLOAD_CREDENTIAL_FILE_ENV,
    load_internal_sandbox_taxonomy_seed_deployment_inputs,
)
from desire_platform.internal_pilot.synthetic_seed_postgres import (
    InternalSandboxSeedRuntimeMaterial,
    InternalSandboxTaxonomySeedResult,
)


class SyntheticTaxonomySeedDeploymentContractTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix="desire-synthetic-taxonomy-seed-contract-"
        )
        self.secret_root = Path(self.temporary.name)
        self.admin = self.secret_root / "database-admin"
        self.workload = self.secret_root / "taxonomy-workload"
        self.receipt = self.secret_root / "taxonomy-receipt-key"
        self.admin.write_bytes(b"admin-database-password-material-2026")
        self.workload.write_bytes(
            b"synthetic-taxonomy-workload-credential-material-2026"
        )
        self.receipt.write_bytes(bytes(range(1, 33)))
        self.environment = {
            "DESIRE_DEPLOYMENT_MODE": "INTERNAL_SANDBOX",
            "DESIRE_EXTERNAL_PARTICIPANTS_ENABLED": "false",
            "DESIRE_DATABASE_HOST": "db",
            "DESIRE_DATABASE_NAME": "desire",
            "DESIRE_DATABASE_ADMIN_USER": "postgres",
            "DESIRE_DATABASE_PASSWORD_FILE": str(self.admin),
            TAXONOMY_SEED_WORKLOAD_CREDENTIAL_FILE_ENV: str(self.workload),
            TAXONOMY_SEED_RECEIPT_HMAC_KEY_FILE_ENV: str(self.receipt),
        }

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_loader_accepts_only_three_direct_secret_files(self) -> None:
        inputs = load_internal_sandbox_taxonomy_seed_deployment_inputs(
            self.environment,
            allowed_secret_root=self.secret_root,
        )

        self.assertEqual(inputs.settings.host, "db")
        self.assertNotIn(self.admin.read_text(), repr(inputs))
        self.assertNotIn(self.workload.read_text(), repr(inputs))
        self.assertNotIn(self.receipt.read_bytes().hex(), repr(inputs))

    def test_loader_rejects_ambient_expansion_newline_and_wrong_key_size(self) -> None:
        cases = []
        cases.append({**self.environment, "DESIRE_UNREVIEWED": "true"})
        self.workload.write_bytes(b"w" * 32 + b"\n")
        cases.append(dict(self.environment))
        self.workload.write_bytes(b"w" * 32)
        self.receipt.write_bytes(b"r" * 31)
        cases.append(dict(self.environment))
        for index, environment in enumerate(cases):
            with self.subTest(index=index):
                if index == 0:
                    self.workload.write_bytes(b"w" * 32)
                    self.receipt.write_bytes(b"r" * 32)
                elif index == 1:
                    self.workload.write_bytes(b"w" * 32 + b"\n")
                    self.receipt.write_bytes(b"r" * 32)
                else:
                    self.workload.write_bytes(b"w" * 32)
                    self.receipt.write_bytes(b"r" * 31)
                with self.assertRaises(
                    InternalSandboxTaxonomySeedDeploymentConfigurationError
                ):
                    load_internal_sandbox_taxonomy_seed_deployment_inputs(
                        environment,
                        allowed_secret_root=self.secret_root,
                    )

    def test_cli_emits_only_safe_digest_bundle_and_replay_state(self) -> None:
        runtime = InternalSandboxSeedRuntimeMaterial(
            deployment_mode="INTERNAL_SANDBOX",
            workload_credential_id=(
                "synthetic-taxonomy-workload-credential-material-2026"
            ),
            receipt_hmac_key=bytes(range(1, 33)),
        )
        inputs = InternalSandboxTaxonomySeedDeploymentInputs(
            settings=DeploymentMigrationSettings(
                host="db",
                database="desire",
                admin_user="postgres",
                admin_password="admin-database-password-material-2026",
            ),
            runtime=runtime,
        )
        result = InternalSandboxTaxonomySeedResult(
            taxonomy_bundle_id="50000000-0000-4000-8000-000000000001",
            workload_authority_created=True,
            publication_replayed=False,
            consumer_authority_created=True,
            consumer_inbox_replayed=False,
            profile_marker_created=True,
        )
        stdout = StringIO()
        stderr = StringIO()
        with (
            patch.object(
                synthetic_taxonomy_seed,
                "load_internal_sandbox_taxonomy_seed_deployment_inputs",
                return_value=inputs,
            ),
            patch.object(
                synthetic_taxonomy_seed,
                "apply_internal_sandbox_taxonomy_seed",
                return_value=result,
            ),
        ):
            code = synthetic_taxonomy_seed.main(
                ["apply"],
                environment=self.environment,
                stdout=stdout,
                stderr=stderr,
            )

        self.assertEqual(code, 0)
        self.assertEqual(stderr.getvalue(), "")
        payload = json.loads(stdout.getvalue())
        self.assertEqual(
            payload,
            {
                "manifest_sha256": (
                    "418567e441e6be2744dcc2b3b295764fd"
                    "303d53c4e13922503130e5cd659552d"
                ),
                "replayed": False,
                "status": "INTERNAL_SANDBOX_TAXONOMY_SEED_READY",
                "taxonomy_bundle_id": (
                    "50000000-0000-4000-8000-000000000001"
                ),
            },
        )
        rendered = stdout.getvalue()
        self.assertNotIn(inputs.settings.admin_password, rendered)
        self.assertNotIn(runtime.workload_credential_id, rendered)
        self.assertNotIn(runtime.receipt_hmac_key.hex(), rendered)


if __name__ == "__main__":
    unittest.main()
