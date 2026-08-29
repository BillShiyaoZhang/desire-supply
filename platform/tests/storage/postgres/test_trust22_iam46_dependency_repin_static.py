"""Static closure checks for the reviewed Trust22 IAM46 repin."""

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
MIGRATION = MIGRATION_ROOT / "0022_expand__iam46_dependency_repin.sql"


def test_trust22_is_the_registered_reviewed_dependency_head() -> None:
    catalog = TrustMigrationCatalog.load(MIGRATION_ROOT)
    artifact = catalog.artifacts[-1]

    assert TRUST_SCHEMA_HEAD_VERSION == 22
    assert TRUST_REQUIRED_IAM_SCHEMA_VERSION == 46
    assert TRUST_REQUIRED_DEMAND_SCHEMA_VERSION == 15
    assert TRUST_MIGRATION_LAYOUT[-1] == (
        22,
        TrustMigrationPhase.EXPAND,
        "iam46_dependency_repin",
        MIGRATION.name,
    )
    assert artifact.descriptor.checksum_sha256 == hashlib.sha256(
        MIGRATION.read_bytes()
    ).digest()
    assert artifact.descriptor.checksum_sha256.hex() == (
        "f0eceeb22f1f8832efdfcf9cf96107f0190c23db647b5f312aa2cdb6635143b8"
    )
    assert catalog.manifest_sha256 == TRUST_REVIEWED_MANIFEST_SHA256
    assert catalog.manifest_sha256.hex() == (
        "3fd3089db8139f4e70551f59f8e803fdf2543847d38d08f82f8a050c2dd921e8"
    )
    assert TRUST_REQUIRED_IAM_CONTRACT_SHA256.hex() == (
        "14b0ae7a2ba2db7d6807b9b71080d40ab4b40b4e0e2664c5da0ac14fcb29c84d"
    )
    assert TRUST_REQUIRED_DEMAND_CONTRACT_SHA256.hex() == (
        "ea6887891134ffa2f451fed35d469ae1c5195c54649e228f587622d95696dddf"
    )
    assert TRUST_REVIEWED_COMBINED_CONTRACT_SHA256.hex() == (
        "68f3c3e90088f6d4383e73b3fbc6f77297cee27bc78086db227708bc872613f6"
    )


def test_trust22_changes_only_exact_iam_dependency_metadata() -> None:
    sql = MIGRATION.read_text(encoding="utf-8")
    for marker in (
        "schema_head_version = 21",
        "required_iam_schema_version = 45",
        "schema_head_version = 22",
        "required_iam_schema_version = 46",
        "required_demand_schema_version = 15",
        "TRUST21_SCHEMA_CONTRACT_BASELINE_MISMATCH",
        "3a1619b3d21567534df7f1331c6c39bb09c049be67deebf7988ff3b841e384fa",
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
