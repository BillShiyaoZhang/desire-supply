"""Static closure checks for the reviewed Trust23 IAM47 repin."""

from __future__ import annotations

import hashlib
from pathlib import Path

from desire_platform.trust_safety.adapters.postgres.migrations import (
    TRUST_MIGRATION_LAYOUT,
    TRUST_REQUIRED_DEMAND_CONTRACT_SHA256,
    TRUST_REQUIRED_DEMAND_SCHEMA_VERSION,
    TRUST_REQUIRED_IAM_CONTRACT_SHA256,
    TRUST_REQUIRED_IAM_SCHEMA_VERSION,
    TRUST_REVIEWED_COMBINED_CONTRACT_SHA256,
    TRUST_REVIEWED_MANIFEST_SHA256,
    TRUST_SCHEMA_HEAD_VERSION,
    TrustMigrationCatalog,
    TrustMigrationPhase,
)


PLATFORM_ROOT = Path(__file__).resolve().parents[3]
MIGRATION_ROOT = (
    PLATFORM_ROOT
    / "src/desire_platform/trust_safety/adapters/postgres/migrations"
)
MIGRATION = MIGRATION_ROOT / "0023_expand__iam47_dependency_repin.sql"


def test_trust23_is_the_registered_reviewed_dependency_head() -> None:
    catalog = TrustMigrationCatalog.load(MIGRATION_ROOT)
    artifact = catalog.artifacts[-1]

    assert TRUST_SCHEMA_HEAD_VERSION == 23
    assert TRUST_REQUIRED_IAM_SCHEMA_VERSION == 47
    assert TRUST_REQUIRED_DEMAND_SCHEMA_VERSION == 15
    assert TRUST_MIGRATION_LAYOUT[-1] == (
        23,
        TrustMigrationPhase.EXPAND,
        "iam47_dependency_repin",
        MIGRATION.name,
    )
    assert artifact.descriptor.checksum_sha256 == hashlib.sha256(
        MIGRATION.read_bytes()
    ).digest()
    assert artifact.descriptor.checksum_sha256.hex() == (
        "3ceeeea5a90812f29c56f293f4388f55694f1469a80c40763a6e28b16102c9b5"
    )
    assert catalog.manifest_sha256 == TRUST_REVIEWED_MANIFEST_SHA256
    assert catalog.manifest_sha256.hex() == (
        "0576a8872e2c9783e345d521f151b3d6f9bd7e1d9ee125ee1ef3810e01a05e47"
    )
    assert TRUST_REQUIRED_IAM_CONTRACT_SHA256.hex() == (
        "abc9924571cecb3027ec29ee7fdf34596bf8682d8b41c62d033964ec3094400f"
    )
    assert TRUST_REQUIRED_DEMAND_CONTRACT_SHA256.hex() == (
        "ea6887891134ffa2f451fed35d469ae1c5195c54649e228f587622d95696dddf"
    )
    assert TRUST_REVIEWED_COMBINED_CONTRACT_SHA256.hex() == (
        "96ff2fd0b3e32143b4570fff008948d13fbe5f537a746712878bd2cca77255fa"
    )


def test_trust23_changes_only_exact_iam_dependency_metadata() -> None:
    sql = MIGRATION.read_text(encoding="utf-8")
    for marker in (
        "schema_head_version = 22",
        "required_iam_schema_version = 46",
        "schema_head_version = 23",
        "required_iam_schema_version = 47",
        "required_demand_schema_version = 15",
        "TRUST22_SCHEMA_CONTRACT_BASELINE_MISMATCH",
        "14b0ae7a2ba2db7d6807b9b71080d40ab4b40b4e0e2664c5da0ac14fcb29c84d",
        TRUST_REQUIRED_IAM_CONTRACT_SHA256.hex(),
        TRUST_REQUIRED_DEMAND_CONTRACT_SHA256.hex(),
    ):
        assert marker in sql
    for forbidden in (
        "CREATE TABLE trust.",
        "ALTER TABLE trust.",
        "CREATE FUNCTION trust.",
        "CREATE POLICY",
        "GRANT ",
    ):
        assert forbidden not in sql
