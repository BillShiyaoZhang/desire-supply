"""Static closure checks for the Trust19 IAM43/Demand13 repin."""

from __future__ import annotations

import hashlib
from pathlib import Path
import re

from desire_platform.trust_safety.adapters.postgres.migrations import (
    TRUST_MIGRATION_LAYOUT,
    TrustContractSources,
    TrustMigrationCatalog,
    TrustMigrationPhase,
)
from desire_platform.trust_safety.adapters.postgres.migrations.runner import (
    _EXPECTED_DEMAND_API_SHA256,
    _EXPECTED_DEMAND_CONTENT_SHA256,
    _EXPECTED_DEMAND_EVENT_SHA256,
)


PLATFORM_ROOT = Path(__file__).resolve().parents[3]
MIGRATION_ROOT = (
    PLATFORM_ROOT
    / "src/desire_platform/trust_safety/adapters/postgres/migrations"
)
MIGRATION = (
    MIGRATION_ROOT / "0019_expand__iam43_demand13_dependency_repin.sql"
)

FROZEN_IAM42_CONTRACT_SHA256 = (
    "f88bf5f70343edbf06e55c0641b61b58cff27fda48ce00f6489e3f3f80db5a9e"
)
FROZEN_DEMAND12_CONTRACT_SHA256 = (
    "379b6cb8b05f7da03905e644d158cfb6ad03409f290d33f63ae80183d428f816"
)
FROZEN_TRUST18_SQL_SHA256 = (
    "8623df4ffbd74f360a67fcc05a2a9d3966269458264b042ae10d6f1fd0784c0e"
)
FROZEN_TRUST18_MANIFEST_SHA256 = (
    "0b7028c75c8f137bc4a55a76fe73ea956d0c5ada13031f80794b77c1c9535e19"
)
FROZEN_TRUST18_COMBINED_SHA256 = (
    "639100c2fd347cdc38e9d9d52686f1a95c17cdcca2fbabe506832d30fad495b1"
)
IAM43_CONTRACT_SHA256 = (
    "bb2b025fb26974cf06574117d8e055144d9413c81c035595458c24181f29c72e"
)
DEMAND13_CONTRACT_SHA256 = (
    "e3e7a77aeec447cc3035472c5f660c8675238fe260081ce9cedf4dc014b37001"
)
TRUST19_SQL_SHA256 = (
    "a8dc9b4ba6dbb8a4d1b2e89155745bf30fa617cdbe6fbe6c93a918f277d0c85e"
)
TRUST19_MANIFEST_SHA256 = (
    "5949f7b630376a59c643f9024210625811606a1a41f90f4bc99ee19dfb99d38c"
)
TRUST19_COMBINED_SHA256 = (
    "16913f8503da5e27be72321a3311025bba9a6cf454f8b8b5dad9b4a09ad3417d"
)
DEMAND13_MANIFEST_SHA256 = (
    "5663d8e14bb5fa6a5706828fe443a8c08ac2e62bad3e56403dd45bc6df939b29"
)


def _actual_sources() -> TrustContractSources:
    contract_root = PLATFORM_ROOT / "contracts"
    return TrustContractSources(
        api_contract_bytes=(contract_root / "api/trust-v1.openapi.yaml").read_bytes(),
        event_contract_bytes=(
            contract_root / "events/trust-v1.schema.json"
        ).read_bytes(),
        report_contract_bytes=(
            contract_root / "domain/trust-report-v1.schema.json"
        ).read_bytes(),
        triage_contract_bytes=(
            contract_root / "domain/trust-triage-v1.schema.json"
        ).read_bytes(),
        appeal_api_contract_bytes=(
            contract_root / "api/appeal-v1.openapi.yaml"
        ).read_bytes(),
        appeal_event_contract_bytes=(
            contract_root / "events/appeal-v1.schema.json"
        ).read_bytes(),
        appeal_application_contract_bytes=(
            contract_root / "domain/appeal-application-v1.schema.json"
        ).read_bytes(),
        appeal_review_contract_bytes=(
            contract_root / "domain/appeal-review-v1.schema.json"
        ).read_bytes(),
    )


def test_trust19_appends_after_the_byte_frozen_trust18_prefix() -> None:
    catalog = TrustMigrationCatalog.load(MIGRATION_ROOT)
    trust18 = catalog.artifacts[17].descriptor
    trust19 = catalog.artifacts[18].descriptor

    assert len(catalog.artifacts) >= 19
    assert TRUST_MIGRATION_LAYOUT[18] == (
        19,
        TrustMigrationPhase.EXPAND,
        "iam43_demand13_dependency_repin",
        MIGRATION.name,
    )
    assert trust18.checksum_sha256.hex() == FROZEN_TRUST18_SQL_SHA256
    assert trust18.prefix_manifest_sha256.hex() == (
        FROZEN_TRUST18_MANIFEST_SHA256
    )
    assert trust19.checksum_sha256.hex() == TRUST19_SQL_SHA256
    assert hashlib.sha256(MIGRATION.read_bytes()).digest() == (
        trust19.checksum_sha256
    )
    assert trust19.prefix_manifest_sha256.hex() == TRUST19_MANIFEST_SHA256


def test_trust19_pins_exact_iam43_and_demand13_dependency_contracts() -> None:
    demand_parts = (
        "desire:demand:trust-schema-dependency:v1",
        "13",
        "13",
        "13",
        "43",
        _EXPECTED_DEMAND_API_SHA256.hex(),
        _EXPECTED_DEMAND_EVENT_SHA256.hex(),
        _EXPECTED_DEMAND_CONTENT_SHA256.hex(),
        DEMAND13_MANIFEST_SHA256,
    )
    assert hashlib.sha256("\x1f".join(demand_parts).encode("utf-8")).hexdigest() == (
        DEMAND13_CONTRACT_SHA256
    )

    sources = _actual_sources()
    trust_parts = (
        "desire:trust:combined-contract:v2",
        IAM43_CONTRACT_SHA256,
        DEMAND13_CONTRACT_SHA256,
        hashlib.sha256(sources.api_contract_bytes).hexdigest(),
        hashlib.sha256(sources.event_contract_bytes).hexdigest(),
        hashlib.sha256(sources.report_contract_bytes).hexdigest(),
        hashlib.sha256(sources.triage_contract_bytes).hexdigest(),
        hashlib.sha256(sources.appeal_api_contract_bytes).hexdigest(),
        hashlib.sha256(sources.appeal_event_contract_bytes).hexdigest(),
        hashlib.sha256(sources.appeal_application_contract_bytes).hexdigest(),
        hashlib.sha256(sources.appeal_review_contract_bytes).hexdigest(),
        TRUST19_MANIFEST_SHA256,
    )
    assert hashlib.sha256("\x1f".join(trust_parts).encode("utf-8")).hexdigest() == (
        TRUST19_COMBINED_SHA256
    )


def test_trust19_requires_exact_trust18_baseline_then_repins_metadata() -> None:
    sql = MIGRATION.read_text(encoding="utf-8")
    compact = " ".join(sql.split())

    for marker in (
        "TRUST18_SCHEMA_CONTRACT_BASELINE_MISMATCH",
        "contract_count NOT BETWEEN 0 AND 1",
        "contract_count = 1 AND contract_is_exact IS NOT TRUE",
        "session_user IS DISTINCT FROM 'trust_migration_runner'",
        "current_user IS DISTINCT FROM 'trust_schema_owner'",
        "schema_head_version = 18",
        "min_app_compatible_version = 18",
        "max_app_compatible_version = 18",
        "required_iam_schema_version = 42",
        "required_demand_schema_version = 12",
        FROZEN_IAM42_CONTRACT_SHA256,
        FROZEN_DEMAND12_CONTRACT_SHA256,
        FROZEN_TRUST18_MANIFEST_SHA256,
        FROZEN_TRUST18_COMBINED_SHA256,
        "schema_head_version = 19",
        "min_app_compatible_version = 19",
        "max_app_compatible_version = 19",
        "required_iam_schema_version = 43",
        "required_demand_schema_version = 13",
        IAM43_CONTRACT_SHA256,
        DEMAND13_CONTRACT_SHA256,
        "desire:trust:combined-contract:v2",
    ):
        assert marker in sql

    assert sql.count("DELETE FROM trust_meta.schema_contracts") == 1
    assert compact.count("ALTER TABLE trust_meta.schema_contracts") == 2
    assert "DROP CONSTRAINT ck_trust_schema_contract_versions" in sql
    assert "DROP CONSTRAINT ck_trust_schema_contract_hashes" in sql
    assert "ADD CONSTRAINT ck_trust_schema_contract_versions" in sql
    assert "ADD CONSTRAINT ck_trust_schema_contract_hashes" in sql

    for forbidden in (
        "CREATE TABLE",
        "CREATE FUNCTION",
        "CREATE OR REPLACE FUNCTION",
        "CREATE VIEW",
        "CREATE TRIGGER",
        "CREATE POLICY",
        "DROP POLICY",
        "ENABLE ROW LEVEL SECURITY",
        "FORCE ROW LEVEL SECURITY",
        "ALTER TABLE trust.",
        "INSERT INTO",
        "UPDATE trust.",
    ):
        assert forbidden not in sql
    assert re.search(r"\b(?:GRANT|REVOKE)\b", sql) is None
    assert "EXECUTE format" not in sql
