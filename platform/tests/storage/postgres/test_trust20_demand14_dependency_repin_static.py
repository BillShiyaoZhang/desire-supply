"""Static closure checks for the Trust20 Demand14 dependency repin."""

from __future__ import annotations

import hashlib
from pathlib import Path

from desire_platform.trust_safety.adapters.postgres.migrations import (
    TRUST_MIGRATION_LAYOUT,
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
MIGRATION = MIGRATION_ROOT / "0020_expand__demand14_dependency_repin.sql"


def test_trust20_remains_registered_byte_exact_below_the_reviewed_head() -> None:
    catalog = TrustMigrationCatalog.load(MIGRATION_ROOT)
    artifact = catalog.artifacts[19]

    assert TRUST_SCHEMA_HEAD_VERSION == 22
    assert TRUST_MIGRATION_LAYOUT[19] == (
        20,
        TrustMigrationPhase.EXPAND,
        "demand14_dependency_repin",
        MIGRATION.name,
    )
    assert artifact.descriptor.checksum_sha256 == hashlib.sha256(
        MIGRATION.read_bytes()
    ).digest()
    assert artifact.descriptor.checksum_sha256.hex() == (
        "8a9cb1d8d86550ee299e2c30a885d5e256b14e99315afcaeb6ca8bd5c50f6cb4"
    )
    assert catalog.manifest_sha256 == TRUST_REVIEWED_MANIFEST_SHA256
    assert artifact.descriptor.prefix_manifest_sha256.hex() == (
        "4991f0fa80dbd7095c59cf7e1b1122e0d100c2776c2aa9e15943592d36ac777b"
    )


def test_trust20_changes_only_exact_dependency_metadata() -> None:
    sql = MIGRATION.read_text(encoding="utf-8")
    for marker in (
        "schema_head_version = 19",
        "required_iam_schema_version = 43",
        "required_demand_schema_version = 13",
        "schema_head_version = 20",
        "required_demand_schema_version = 14",
        "9dbe376213fff13656993946358514eb387d36f536d66ed15cb43fbcc8310cf7",
        "TRUST19_SCHEMA_CONTRACT_BASELINE_MISMATCH",
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
