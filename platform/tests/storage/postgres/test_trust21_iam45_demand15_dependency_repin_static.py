"""Static closure checks for the frozen Trust21 dependency repin."""

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
from desire_platform.trust_safety.adapters.postgres.migrations.runner import (
    TrustContractSources,
    combined_contract_sha256,
)


PLATFORM_ROOT = Path(__file__).resolve().parents[3]
MIGRATION_ROOT = (
    PLATFORM_ROOT
    / "src/desire_platform/trust_safety/adapters/postgres/migrations"
)
MIGRATION = MIGRATION_ROOT / "0021_expand__iam45_demand15_dependency_repin.sql"


def _sources() -> TrustContractSources:
    contracts = PLATFORM_ROOT / "contracts"
    return TrustContractSources(
        api_contract_bytes=(contracts / "api/trust-v1.openapi.yaml").read_bytes(),
        event_contract_bytes=(contracts / "events/trust-v1.schema.json").read_bytes(),
        report_contract_bytes=(contracts / "domain/trust-report-v1.schema.json").read_bytes(),
        triage_contract_bytes=(contracts / "domain/trust-triage-v1.schema.json").read_bytes(),
        appeal_api_contract_bytes=(contracts / "api/appeal-v1.openapi.yaml").read_bytes(),
        appeal_event_contract_bytes=(contracts / "events/appeal-v1.schema.json").read_bytes(),
        appeal_application_contract_bytes=(contracts / "domain/appeal-application-v1.schema.json").read_bytes(),
        appeal_review_contract_bytes=(contracts / "domain/appeal-review-v1.schema.json").read_bytes(),
    )


def test_trust21_is_the_frozen_reviewed_dependency_predecessor() -> None:
    catalog = TrustMigrationCatalog.load(MIGRATION_ROOT)
    artifact = catalog.artifacts[20]

    assert TRUST_SCHEMA_HEAD_VERSION == 22
    assert TRUST_REQUIRED_IAM_SCHEMA_VERSION == 46
    assert TRUST_REQUIRED_DEMAND_SCHEMA_VERSION == 15
    assert TRUST_MIGRATION_LAYOUT[20] == (
        21,
        TrustMigrationPhase.EXPAND,
        "iam45_demand15_dependency_repin",
        MIGRATION.name,
    )
    assert artifact.descriptor.checksum_sha256 == hashlib.sha256(
        MIGRATION.read_bytes()
    ).digest()
    assert artifact.descriptor.checksum_sha256.hex() == (
        "f9dd2595aab3a2f84f44498b64e05b25440918a5c5c9422071f56426d13efa66"
    )
    assert artifact.descriptor.prefix_manifest_sha256.hex() == (
        "9c65cf6ebe07b92a13c9d1d5a0e2da99d8aba7797b999afa1fbdfeec03d7c89c"
    )
    assert catalog.manifest_sha256 == TRUST_REVIEWED_MANIFEST_SHA256
    assert catalog.manifest_sha256.hex() == (
        "3fd3089db8139f4e70551f59f8e803fdf2543847d38d08f82f8a050c2dd921e8"
    )
    assert (
        "3a1619b3d21567534df7f1331c6c39bb09c049be67deebf7988ff3b841e384fa"
        in MIGRATION.read_text(encoding="utf-8")
    )
    assert TRUST_REQUIRED_DEMAND_CONTRACT_SHA256.hex() == (
        "ea6887891134ffa2f451fed35d469ae1c5195c54649e228f587622d95696dddf"
    )
    assert combined_contract_sha256(
        sources=_sources(),
        migration_manifest_sha256=catalog.manifest_sha256,
    ) == TRUST_REVIEWED_COMBINED_CONTRACT_SHA256


def test_trust21_changes_only_exact_dependency_metadata() -> None:
    sql = MIGRATION.read_text(encoding="utf-8")
    for marker in (
        "schema_head_version = 20",
        "required_iam_schema_version = 43",
        "required_demand_schema_version = 14",
        "schema_head_version = 21",
        "required_iam_schema_version = 45",
        "required_demand_schema_version = 15",
        "TRUST20_SCHEMA_CONTRACT_BASELINE_MISMATCH",
        "3a1619b3d21567534df7f1331c6c39bb09c049be67deebf7988ff3b841e384fa",
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
