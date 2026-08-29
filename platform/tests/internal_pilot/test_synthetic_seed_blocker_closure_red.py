"""RED contract for the INTERNAL_SANDBOX Taxonomy seed closure."""

from __future__ import annotations

import unittest

from desire_platform.internal_pilot.synthetic_seed import (
    load_internal_sandbox_synthetic_seed,
)
from desire_platform.internal_pilot.synthetic_seed_postgres import (
    InternalSandboxSeedRuntimeMaterial,
    InternalSandboxSyntheticSeedPostgresError,
    PostgresInternalSandboxTaxonomySeedOrchestrator,
    PsycopgInternalSandboxProfileTaxonomyProjector,
    PsycopgInternalSandboxTaxonomyProvisioner,
)
from desire_platform.taxonomy.domain import taxonomy_artifact_sha256


WORKLOAD_CREDENTIAL = "internal-sandbox-taxonomy-workload-credential-test-v1"
RECEIPT_HMAC_KEY = b"r" * 32


class InternalSandboxTaxonomySeedClosureTests(unittest.TestCase):
    def test_reviewed_plan_is_executable_and_pins_the_real_release(self) -> None:
        plan = load_internal_sandbox_synthetic_seed()

        self.assertTrue(plan.is_executable)
        self.assertEqual(plan.blockers, ())
        self.assertIsNone(plan.require_executable())
        self.assertEqual(
            taxonomy_artifact_sha256(plan.taxonomy_release.candidate.manifest),
            plan.taxonomy_release.release_manifest_sha256,
        )
        self.assertEqual(
            plan.taxonomy_release.candidate.manifest.bundle_id,
            plan.taxonomy_bundle_id,
        )
        self.assertEqual(
            plan.taxonomy_credential_binding_mode,
            "RUNTIME_SHA256",
        )
        self.assertEqual(
            plan.taxonomy_profile_consumer_code,
            "PROFILE",
        )

    def test_runtime_material_and_public_surfaces_are_closed_and_secret_safe(self) -> None:
        runtime = InternalSandboxSeedRuntimeMaterial(
            deployment_mode="INTERNAL_SANDBOX",
            workload_credential_id=WORKLOAD_CREDENTIAL,
            receipt_hmac_key=RECEIPT_HMAC_KEY,
        )

        rendered = repr(runtime)
        self.assertNotIn(WORKLOAD_CREDENTIAL, rendered)
        self.assertNotIn(RECEIPT_HMAC_KEY.hex(), rendered)
        for value in (
            PostgresInternalSandboxTaxonomySeedOrchestrator,
            PsycopgInternalSandboxTaxonomyProvisioner,
            PsycopgInternalSandboxProfileTaxonomyProjector,
        ):
            self.assertNotIn("execute", value.__dict__)
            self.assertNotIn("query", value.__dict__)

        for kwargs in (
            {
                "deployment_mode": "PRODUCTION",
                "workload_credential_id": WORKLOAD_CREDENTIAL,
                "receipt_hmac_key": RECEIPT_HMAC_KEY,
            },
            {
                "deployment_mode": "INTERNAL_SANDBOX",
                "workload_credential_id": "short",
                "receipt_hmac_key": RECEIPT_HMAC_KEY,
            },
            {
                "deployment_mode": "INTERNAL_SANDBOX",
                "workload_credential_id": WORKLOAD_CREDENTIAL,
                "receipt_hmac_key": b"short",
            },
        ):
            with self.subTest(kwargs=kwargs):
                with self.assertRaises((TypeError, ValueError)):
                    InternalSandboxSeedRuntimeMaterial(**kwargs)

        self.assertEqual(
            str(InternalSandboxSyntheticSeedPostgresError("SEED_BLOCKED")),
            "SEED_BLOCKED",
        )


if __name__ == "__main__":
    unittest.main()
