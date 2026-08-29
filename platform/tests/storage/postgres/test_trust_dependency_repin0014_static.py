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


PLATFORM_ROOT = Path(__file__).resolve().parents[3]
MIGRATION_ROOT = (
    PLATFORM_ROOT
    / "src/desire_platform/trust_safety/adapters/postgres/migrations"
)
MIGRATION = MIGRATION_ROOT / "0014_expand__iam41_dependency_repin.sql"

FROZEN_IAM40_CONTRACT_SHA256 = (
    "981c425483ce3c89e6e376c8bc1fd8269a36499c8fd89890e8feeac5d94a1ae8"
)
FROZEN_IAM41_CONTRACT_SHA256 = (
    "b46a3a5592eb68af01b3a87cb86fb4970f9678ec54f8beffb3e9c6c926a032dd"
)
FROZEN_DEMAND11_CONTRACT_SHA256 = (
    "cfab70770b908b37aa4865ba2f52d5b8f59492cbc7979867229e006e99cd8d87"
)
FROZEN_TRUST_API_CONTRACT_SHA256 = (
    "a9923573365f1023aff3e4aaebb0b7e656c80eab7e721bbf30d9e9b038782f25"
)
FROZEN_APPEAL_API_CONTRACT_SHA256 = (
    "2a0bda244ae3c59921376732a1edd51cdce7c73ffad857223f387c94741c6522"
)
FROZEN_TRUST13_MANIFEST_SHA256 = (
    "c438a3fac4d9dea850089b8a14f92ab34a5c5a592b9babcb770860d3ecc513d8"
)
FROZEN_TRUST13_COMBINED_SHA256 = (
    "d843e20a45397931a572688cd86ccef9fe43b92a2577d3c8559d519fb0de2480"
)
TRUST14_SQL_SHA256 = (
    "d65a1823192164fa174875d8e76051549fb4f8ff22fdc97ab742c8d00eb3f4e2"
)
TRUST14_MANIFEST_SHA256 = (
    "7aa1b1533e1e23bdef9233c49aeffe9dbca172ad1d825ccdd0925e8c6a823cca"
)
TRUST14_COMBINED_SHA256 = (
    "f56404d56f8af5dc08ea7cd5e92d2c6f7719c56a3dae3bde89f140b604691980"
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


def test_trust14_remains_the_frozen_historical_prefix() -> None:
    catalog = TrustMigrationCatalog.load(MIGRATION_ROOT)
    descriptor = catalog.artifacts[13].descriptor

    assert TRUST_MIGRATION_LAYOUT[13] == (
        14,
        TrustMigrationPhase.EXPAND,
        "iam41_dependency_repin",
        MIGRATION.name,
    )
    assert descriptor.checksum_sha256.hex() == TRUST14_SQL_SHA256
    assert hashlib.sha256(MIGRATION.read_bytes()).digest() == (
        descriptor.checksum_sha256
    )
    assert catalog.artifacts[12].descriptor.prefix_manifest_sha256.hex() == (
        FROZEN_TRUST13_MANIFEST_SHA256
    )
    assert descriptor.prefix_manifest_sha256.hex() == TRUST14_MANIFEST_SHA256


def test_trust14_pins_exact_iam41_and_preserves_demand11_dependency() -> None:
    sources = _actual_sources()
    parts = (
        "desire:trust:combined-contract:v2",
        FROZEN_IAM41_CONTRACT_SHA256,
        FROZEN_DEMAND11_CONTRACT_SHA256,
        FROZEN_TRUST_API_CONTRACT_SHA256,
        hashlib.sha256(sources.event_contract_bytes).hexdigest(),
        hashlib.sha256(sources.report_contract_bytes).hexdigest(),
        hashlib.sha256(sources.triage_contract_bytes).hexdigest(),
        FROZEN_APPEAL_API_CONTRACT_SHA256,
        hashlib.sha256(sources.appeal_event_contract_bytes).hexdigest(),
        hashlib.sha256(sources.appeal_application_contract_bytes).hexdigest(),
        hashlib.sha256(sources.appeal_review_contract_bytes).hexdigest(),
        TRUST14_MANIFEST_SHA256,
    )
    assert hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest() == (
        TRUST14_COMBINED_SHA256
    )


def test_trust14_sql_requires_exact_trust13_baseline_then_repins_metadata() -> None:
    sql = MIGRATION.read_text(encoding="utf-8")
    compact = " ".join(sql.split())

    for marker in (
        "TRUST13_SCHEMA_CONTRACT_BASELINE_MISMATCH",
        "contract_count NOT BETWEEN 0 AND 1",
        "contract_count = 1 AND contract_is_exact IS NOT TRUE",
        "session_user IS DISTINCT FROM 'trust_migration_runner'",
        "current_user IS DISTINCT FROM 'trust_schema_owner'",
        "schema_head_version = 13",
        "min_app_compatible_version = 13",
        "max_app_compatible_version = 13",
        "required_iam_schema_version = 40",
        FROZEN_IAM40_CONTRACT_SHA256,
        FROZEN_TRUST13_MANIFEST_SHA256,
        FROZEN_TRUST13_COMBINED_SHA256,
        "schema_head_version = 14",
        "min_app_compatible_version = 14",
        "max_app_compatible_version = 14",
        "required_iam_schema_version = 41",
        FROZEN_IAM41_CONTRACT_SHA256,
        FROZEN_DEMAND11_CONTRACT_SHA256,
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
