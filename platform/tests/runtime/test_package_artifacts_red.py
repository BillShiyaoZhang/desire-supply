from __future__ import annotations

import hashlib
import importlib.resources
import unittest

from desire_platform.runtime import ArtifactRequirement


class PackageArtifactVerifierRedTests(unittest.TestCase):
    def _contract_bytes(self) -> bytes:
        return (
            importlib.resources.files("desire_platform.contracts")
            .joinpath("api", "iam-v1.openapi.yaml")
            .read_bytes()
        )

    def test_verifies_an_exact_packaged_resource_digest(self) -> None:
        from desire_platform.runtime import (
            PackageArtifactLocation,
            PackageArtifactVerifier,
        )

        payload = self._contract_bytes()
        verifier = PackageArtifactVerifier(
            locations=(
                PackageArtifactLocation(
                    artifact_id="iam-openapi-v1",
                    package="desire_platform.contracts",
                    resource_path="api/iam-v1.openapi.yaml",
                ),
            )
        )

        result = verifier.verify(
            ArtifactRequirement(
                artifact_id="iam-openapi-v1",
                sha256=hashlib.sha256(payload).hexdigest(),
            )
        )

        self.assertIsNone(result)

    def test_digest_mismatch_fails_without_disclosing_digest_or_path(self) -> None:
        from desire_platform.runtime import (
            PackageArtifactLocation,
            PackageArtifactVerifier,
            PackageArtifactVerificationError,
        )

        secret_digest = "f" * 64
        verifier = PackageArtifactVerifier(
            locations=(
                PackageArtifactLocation(
                    artifact_id="iam-openapi-v1",
                    package="desire_platform.contracts",
                    resource_path="api/iam-v1.openapi.yaml",
                ),
            )
        )

        with self.assertRaises(PackageArtifactVerificationError) as raised:
            verifier.verify(
                ArtifactRequirement(
                    artifact_id="iam-openapi-v1",
                    sha256=secret_digest,
                )
            )

        rendered = repr(raised.exception)
        self.assertEqual(str(raised.exception), "ARTIFACT_VERIFICATION_FAILED")
        self.assertNotIn(secret_digest, rendered)
        self.assertNotIn("iam-v1.openapi.yaml", rendered)
        self.assertNotIn("desire_platform.contracts", rendered)

    def test_unknown_or_missing_resource_fails_closed_with_the_same_public_error(self) -> None:
        from desire_platform.runtime import (
            PackageArtifactLocation,
            PackageArtifactVerifier,
            PackageArtifactVerificationError,
        )

        missing = PackageArtifactVerifier(
            locations=(
                PackageArtifactLocation(
                    artifact_id="missing-contract",
                    package="desire_platform.contracts",
                    resource_path="api/not-present.yaml",
                ),
            )
        )
        unknown = PackageArtifactVerifier(locations=())
        requirements = (
            (
                missing,
                ArtifactRequirement(
                    artifact_id="missing-contract",
                    sha256="0" * 64,
                ),
            ),
            (
                unknown,
                ArtifactRequirement(
                    artifact_id="unknown-contract",
                    sha256="0" * 64,
                ),
            ),
        )

        for verifier, requirement in requirements:
            with self.subTest(artifact_id=requirement.artifact_id):
                with self.assertRaises(PackageArtifactVerificationError) as raised:
                    verifier.verify(requirement)
                self.assertEqual(
                    str(raised.exception),
                    "ARTIFACT_VERIFICATION_FAILED",
                )

    def test_registry_rejects_duplicate_ids_and_unsafe_resource_paths(self) -> None:
        from desire_platform.runtime import (
            PackageArtifactLocation,
            PackageArtifactVerifier,
        )

        safe = PackageArtifactLocation(
            artifact_id="iam-openapi-v1",
            package="desire_platform.contracts",
            resource_path="api/iam-v1.openapi.yaml",
        )
        with self.assertRaisesRegex(ValueError, "duplicate artifact_id"):
            PackageArtifactVerifier(locations=(safe, safe))

        unsafe_paths = (
            "../secret",
            "/absolute/path",
            "api/../../secret",
            "api\\secret.yaml",
            "",
        )
        for resource_path in unsafe_paths:
            with self.subTest(resource_path=resource_path):
                with self.assertRaisesRegex(ValueError, "resource_path"):
                    PackageArtifactLocation(
                        artifact_id="unsafe",
                        package="desire_platform.contracts",
                        resource_path=resource_path,
                    )

    def test_registry_rejects_unsafe_package_names_and_invalid_limits(self) -> None:
        from desire_platform.runtime import PackageArtifactLocation

        for package in ("", ".contracts", "contracts.", "desire-platform", "a..b"):
            with self.subTest(package=package):
                with self.assertRaisesRegex(ValueError, "package"):
                    PackageArtifactLocation(
                        artifact_id="unsafe",
                        package=package,
                        resource_path="api/schema.yaml",
                    )

        with self.assertRaisesRegex(ValueError, "maximum_bytes"):
            PackageArtifactLocation(
                artifact_id="invalid-limit",
                package="desire_platform.contracts",
                resource_path="api/schema.yaml",
                maximum_bytes=0,
            )


if __name__ == "__main__":
    unittest.main()
