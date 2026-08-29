from __future__ import annotations

import hashlib
from pathlib import Path
import re

from desire_platform.trust_safety.adapters.postgres.migrations import (
    TRUST_API_CONTRACT_SHA256,
    TRUST_MIGRATION_LAYOUT,
    TRUST_REVIEWED_COMBINED_CONTRACT_SHA256,
    TRUST_REVIEWED_MANIFEST_SHA256,
    TRUST_SCHEMA_HEAD_VERSION,
    TrustContractSources,
    TrustMigrationCatalog,
    TrustMigrationPhase,
    combined_contract_sha256,
)


PLATFORM_ROOT = Path(__file__).resolve().parents[3]
MIGRATION_ROOT = (
    PLATFORM_ROOT
    / "src/desire_platform/trust_safety/adapters/postgres/migrations"
)
MIGRATION = (
    MIGRATION_ROOT
    / "0017_expand__completed_case_history_http_contract.sql"
)

FROZEN_TRUST16_SQL_SHA256 = (
    "46bd5355dffb1028d11f277b785cc8e03266b49c3d9e5dbe0a5a954b0ecdb08d"
)
FROZEN_TRUST16_MANIFEST_SHA256 = (
    "71b61f666ea9d924a7edae14db1bf3cc20905618d806d0c8e76b94066c07672c"
)
FROZEN_TRUST16_API_SHA256 = (
    "a9923573365f1023aff3e4aaebb0b7e656c80eab7e721bbf30d9e9b038782f25"
)
FROZEN_TRUST16_COMBINED_SHA256 = (
    "d1df1117a20361e041a2da24b79a8408c05f4ea949c8a930e3cb3634d2f6a04e"
)
TRUST17_SQL_SHA256 = (
    "9ec66244773c7546537bb41a7c93c518f804947ddb88d8f14eb5e32e191b0854"
)
TRUST17_MANIFEST_SHA256 = (
    "57c0dd42e18bf3afa7233f9ad673ec3805b325166436a4a1e3021466cd62381f"
)
TRUST17_API_SHA256 = (
    "6647e16e9f8f0ab321ed9985eb2da4e591e2217fdaa43ba663355a4f152f44b2"
)
TRUST17_COMBINED_SHA256 = (
    "a1ec68f0d0e6685e0cbe842a6bd951f60f334682d26bec549ef9858c81f23d67"
)


def _actual_sources() -> TrustContractSources:
    contract_root = PLATFORM_ROOT / "contracts"
    return TrustContractSources(
        api_contract_bytes=(
            contract_root / "api/trust-v1.openapi.yaml"
        ).read_bytes(),
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


def test_trust17_appends_after_the_byte_frozen_trust16_prefix() -> None:
    catalog = TrustMigrationCatalog.load(MIGRATION_ROOT)
    trust16 = catalog.artifacts[15].descriptor
    trust17 = catalog.artifacts[16].descriptor

    assert TRUST_SCHEMA_HEAD_VERSION >= 17
    assert TRUST_MIGRATION_LAYOUT[16] == (
        17,
        TrustMigrationPhase.EXPAND,
        "completed_case_history_http_contract",
        MIGRATION.name,
    )
    assert trust16.checksum_sha256.hex() == FROZEN_TRUST16_SQL_SHA256
    assert (
        trust16.prefix_manifest_sha256.hex()
        == FROZEN_TRUST16_MANIFEST_SHA256
    )
    assert trust17.checksum_sha256.hex() == TRUST17_SQL_SHA256
    assert hashlib.sha256(MIGRATION.read_bytes()).digest() == (
        trust17.checksum_sha256
    )
    assert trust17.prefix_manifest_sha256.hex() == TRUST17_MANIFEST_SHA256
    assert catalog.manifest_sha256 == TRUST_REVIEWED_MANIFEST_SHA256
    assert TRUST_REVIEWED_MANIFEST_SHA256.hex() != TRUST17_MANIFEST_SHA256


def test_trust17_pins_the_exact_history_api_and_combined_contract() -> None:
    sources = _actual_sources()
    catalog = TrustMigrationCatalog.load(MIGRATION_ROOT)

    assert hashlib.sha256(sources.api_contract_bytes).hexdigest() == (
        TRUST17_API_SHA256
    )
    assert TRUST_API_CONTRACT_SHA256.hex() == TRUST17_API_SHA256
    assert combined_contract_sha256(
        sources=sources,
        migration_manifest_sha256=catalog.manifest_sha256,
    ) == TRUST_REVIEWED_COMBINED_CONTRACT_SHA256
    assert TRUST_REVIEWED_COMBINED_CONTRACT_SHA256.hex() != (
        TRUST17_COMBINED_SHA256
    )

    sql = MIGRATION.read_text(encoding="utf-8")
    for marker in (
        "TRUST16_SCHEMA_CONTRACT_BASELINE_MISMATCH",
        "contract_count NOT BETWEEN 0 AND 1",
        "contract_count = 1 AND contract_is_exact IS NOT TRUE",
        "session_user IS DISTINCT FROM 'trust_migration_runner'",
        "current_user IS DISTINCT FROM 'trust_schema_owner'",
        "schema_head_version = 16",
        "min_app_compatible_version = 16",
        "max_app_compatible_version = 16",
        "required_iam_schema_version = 42",
        "required_demand_schema_version = 12",
        "f88bf5f70343edbf06e55c0641b61b58cff27fda48ce00f6489e3f3f80db5a9e",
        "379b6cb8b05f7da03905e644d158cfb6ad03409f290d33f63ae80183d428f816",
        FROZEN_TRUST16_API_SHA256,
        "a26c410ca62c6d996fd13148863935729f480ca1a1fd9a44378a96ab13eae582",
        "29b0c97a576edf654b5517847c73ce7a059141158182b16008f2cce3ef996278",
        "de45a368bc75f7523e9135b83f61ab8753581a1e775cffe943c7a70cbe6f3084",
        "2a0bda244ae3c59921376732a1edd51cdce7c73ffad857223f387c94741c6522",
        "7d3916ab89ace8c677da6ba6b6b5a65cfae28b8d91cf0c71fc0b0d9a88a064ba",
        "3549b053c911da3b5bf5b526c8abfc9e1ef9cdafd1f81e177d43cb412cab8223",
        "08982687c6654d606040c52faedc15a14b7b50e1c5c80db560587bbf3e16f72b",
        FROZEN_TRUST16_COMBINED_SHA256,
        FROZEN_TRUST16_MANIFEST_SHA256,
        "generated_at IS NOT NULL",
        "schema_head_version = 17",
        "min_app_compatible_version = 17",
        "max_app_compatible_version = 17",
        TRUST17_API_SHA256,
        "desire:trust:combined-contract:v2",
    ):
        assert marker in sql


def test_trust17_is_metadata_only() -> None:
    sql = MIGRATION.read_text(encoding="utf-8")
    compact = " ".join(sql.split())

    assert sql.count("DELETE FROM trust_meta.schema_contracts") == 1
    assert compact.count("ALTER TABLE trust_meta.schema_contracts") == 2
    assert set(
        re.findall(
            r"(?:ALTER TABLE|DELETE FROM|INSERT INTO|UPDATE)\s+"
            r"([a-z_]+\.[a-z_]+)",
            sql,
        )
    ) == {"trust_meta.schema_contracts"}
    for forbidden in (
        "CREATE TABLE",
        "CREATE FUNCTION",
        "CREATE OR REPLACE FUNCTION",
        "CREATE VIEW",
        "CREATE TRIGGER",
        "CREATE POLICY",
        "DROP TABLE",
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
