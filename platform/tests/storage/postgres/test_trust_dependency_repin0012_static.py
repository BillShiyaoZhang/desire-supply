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
MIGRATION = MIGRATION_ROOT / "0012_expand__iam39_dependency_repin.sql"

FROZEN_IAM38_CONTRACT_SHA256 = (
    "908f3de6b6b90fd5d19004304e9df24d0e5738fe6edf88e1b2cb2b1a414c5e3e"
)
FROZEN_TRUST11_MANIFEST_SHA256 = (
    "6b7623d36259e4db00de3ca83a0e0470173a16159432d099c6dc54e51cdcd2e7"
)
FROZEN_TRUST11_COMBINED_SHA256 = (
    "583e4a03efec12b06c75710d0a6ccd7b79be18cb93f4faf58c207d228065c48d"
)
FROZEN_IAM39_CONTRACT_SHA256 = (
    "fdfb00e353ce823f6ef5695e47ec32443c219387413ade908d502925e5248258"
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
FROZEN_TRUST12_MANIFEST_SHA256 = (
    "5d2172c15c7919d6ea6576ef059e136b123eb523d884febf7b7a5d79b4b43ecc"
)
FROZEN_TRUST12_COMBINED_SHA256 = (
    "3e0af93a1411bc45ca8877f44dbe517f575eb50ce810f11019ea5d583fc4b1aa"
)
TRUST12_SQL_SHA256 = (
    "064f9feabd497bafcb410b8f926033775d2645e23438c0439e8ecf9981076a3d"
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


def test_trust12_is_one_forward_only_tail_after_frozen_trust11() -> None:
    catalog = TrustMigrationCatalog.load(MIGRATION_ROOT)
    descriptor = catalog.artifacts[11].descriptor

    assert TRUST_MIGRATION_LAYOUT[11] == (
        12,
        TrustMigrationPhase.EXPAND,
        "iam39_dependency_repin",
        MIGRATION.name,
    )
    assert descriptor.checksum_sha256.hex() == TRUST12_SQL_SHA256
    assert hashlib.sha256(MIGRATION.read_bytes()).digest() == (
        descriptor.checksum_sha256
    )
    assert catalog.artifacts[10].descriptor.prefix_manifest_sha256.hex() == (
        FROZEN_TRUST11_MANIFEST_SHA256
    )
    assert descriptor.prefix_manifest_sha256.hex() == (
        FROZEN_TRUST12_MANIFEST_SHA256
    )


def test_trust12_pins_exact_iam39_and_preserves_demand11_dependency() -> None:
    sources = _actual_sources()
    parts = (
        "desire:trust:combined-contract:v2",
        FROZEN_IAM39_CONTRACT_SHA256,
        FROZEN_DEMAND11_CONTRACT_SHA256,
        FROZEN_TRUST_API_CONTRACT_SHA256,
        hashlib.sha256(sources.event_contract_bytes).hexdigest(),
        hashlib.sha256(sources.report_contract_bytes).hexdigest(),
        hashlib.sha256(sources.triage_contract_bytes).hexdigest(),
        FROZEN_APPEAL_API_CONTRACT_SHA256,
        hashlib.sha256(sources.appeal_event_contract_bytes).hexdigest(),
        hashlib.sha256(sources.appeal_application_contract_bytes).hexdigest(),
        hashlib.sha256(sources.appeal_review_contract_bytes).hexdigest(),
        FROZEN_TRUST12_MANIFEST_SHA256,
    )
    assert hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest() == (
        FROZEN_TRUST12_COMBINED_SHA256
    )


def test_trust12_sql_requires_exact_trust11_baseline_then_repins_metadata() -> None:
    sql = MIGRATION.read_text(encoding="utf-8")
    compact = " ".join(sql.split())

    for marker in (
        "TRUST11_SCHEMA_CONTRACT_BASELINE_MISMATCH",
        "contract_count NOT BETWEEN 0 AND 1",
        "contract_count = 1 AND contract_is_exact IS NOT TRUE",
        "session_user IS DISTINCT FROM 'trust_migration_runner'",
        "current_user IS DISTINCT FROM 'trust_schema_owner'",
        "schema_head_version = 11",
        "min_app_compatible_version = 11",
        "max_app_compatible_version = 11",
        "required_iam_schema_version = 38",
        FROZEN_IAM38_CONTRACT_SHA256,
        FROZEN_TRUST11_MANIFEST_SHA256,
        FROZEN_TRUST11_COMBINED_SHA256,
        "schema_head_version = 12",
        "min_app_compatible_version = 12",
        "max_app_compatible_version = 12",
        "required_iam_schema_version = 39",
        FROZEN_IAM39_CONTRACT_SHA256,
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
