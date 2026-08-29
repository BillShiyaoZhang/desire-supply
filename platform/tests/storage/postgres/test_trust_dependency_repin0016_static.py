from __future__ import annotations

import hashlib
from pathlib import Path
import re

from desire_platform.trust_safety.adapters.postgres.migrations import (
    TRUST_MIGRATION_LAYOUT,
    TrustMigrationCatalog,
    TrustMigrationPhase,
)


PLATFORM_ROOT = Path(__file__).resolve().parents[3]
MIGRATION_ROOT = (
    PLATFORM_ROOT
    / "src/desire_platform/trust_safety/adapters/postgres/migrations"
)
MIGRATION = MIGRATION_ROOT / "0016_expand__demand12_dependency_repin.sql"

FROZEN_IAM42_CONTRACT_SHA256 = (
    "f88bf5f70343edbf06e55c0641b61b58cff27fda48ce00f6489e3f3f80db5a9e"
)
FROZEN_DEMAND11_CONTRACT_SHA256 = (
    "cfab70770b908b37aa4865ba2f52d5b8f59492cbc7979867229e006e99cd8d87"
)
FROZEN_TRUST15_MANIFEST_SHA256 = (
    "09a22506690138cf3b9c32e8b9d2bf8acbf31fc8cd80b37c8422bf4a93d2756c"
)
FROZEN_TRUST15_COMBINED_SHA256 = (
    "d88bb1f0e5cc9a50e7a3eac5597202a073414c42d780a7b769267ba80c14b0ca"
)
FROZEN_TRUST_API_CONTRACT_SHA256 = (
    "a9923573365f1023aff3e4aaebb0b7e656c80eab7e721bbf30d9e9b038782f25"
)
DEMAND12_MANIFEST_SHA256 = (
    "919d62a9b32dc29619a561940f9c79e21700562a0cdd9ef7e9f13a40cea43345"
)
DEMAND12_CONTRACT_SHA256 = (
    "379b6cb8b05f7da03905e644d158cfb6ad03409f290d33f63ae80183d428f816"
)
TRUST16_SQL_SHA256 = (
    "46bd5355dffb1028d11f277b785cc8e03266b49c3d9e5dbe0a5a954b0ecdb08d"
)
TRUST16_MANIFEST_SHA256 = (
    "71b61f666ea9d924a7edae14db1bf3cc20905618d806d0c8e76b94066c07672c"
)
TRUST16_COMBINED_SHA256 = (
    "d1df1117a20361e041a2da24b79a8408c05f4ea949c8a930e3cb3634d2f6a04e"
)


def test_trust16_remains_the_frozen_prefix_after_trust17() -> None:
    catalog = TrustMigrationCatalog.load(MIGRATION_ROOT)
    descriptor = catalog.artifacts[15].descriptor

    assert TRUST_MIGRATION_LAYOUT[15] == (
        16,
        TrustMigrationPhase.EXPAND,
        "demand12_dependency_repin",
        MIGRATION.name,
    )
    assert descriptor.checksum_sha256.hex() == TRUST16_SQL_SHA256
    assert hashlib.sha256(MIGRATION.read_bytes()).digest() == (
        descriptor.checksum_sha256
    )
    assert catalog.artifacts[14].descriptor.prefix_manifest_sha256.hex() == (
        FROZEN_TRUST15_MANIFEST_SHA256
    )
    assert descriptor.prefix_manifest_sha256.hex() == TRUST16_MANIFEST_SHA256


def test_trust16_pins_exact_demand12_dependency_and_frozen_iam42() -> None:
    demand_parts = (
        "desire:demand:trust-schema-dependency:v1",
        "12",
        "12",
        "12",
        "37",
        "10913dc4c1be5ab8eda83bb098c20f63791cefd0a19437dd4385780abf86d410",
        "69cae3deb570848ccb904b28ab78229e50681cf4cdfc201a350f8e099f449923",
        "4a3316ca66f58e92d23b946226b235578ad77e247f92f72863aa8f76c5b5c631",
        DEMAND12_MANIFEST_SHA256,
    )
    assert hashlib.sha256("\x1f".join(demand_parts).encode("utf-8")).hexdigest() == (
        DEMAND12_CONTRACT_SHA256
    )

    trust_parts = (
        "desire:trust:combined-contract:v2",
        FROZEN_IAM42_CONTRACT_SHA256,
        DEMAND12_CONTRACT_SHA256,
        FROZEN_TRUST_API_CONTRACT_SHA256,
        "a26c410ca62c6d996fd13148863935729f480ca1a1fd9a44378a96ab13eae582",
        "29b0c97a576edf654b5517847c73ce7a059141158182b16008f2cce3ef996278",
        "de45a368bc75f7523e9135b83f61ab8753581a1e775cffe943c7a70cbe6f3084",
        "2a0bda244ae3c59921376732a1edd51cdce7c73ffad857223f387c94741c6522",
        "7d3916ab89ace8c677da6ba6b6b5a65cfae28b8d91cf0c71fc0b0d9a88a064ba",
        "3549b053c911da3b5bf5b526c8abfc9e1ef9cdafd1f81e177d43cb412cab8223",
        "08982687c6654d606040c52faedc15a14b7b50e1c5c80db560587bbf3e16f72b",
        TRUST16_MANIFEST_SHA256,
    )
    assert hashlib.sha256(
        "\x1f".join(trust_parts).encode("utf-8")
    ).hexdigest() == (
        TRUST16_COMBINED_SHA256
    )


def test_trust16_requires_exact_trust15_baseline_then_repins_metadata() -> None:
    sql = MIGRATION.read_text(encoding="utf-8")
    compact = " ".join(sql.split())

    for marker in (
        "TRUST15_SCHEMA_CONTRACT_BASELINE_MISMATCH",
        "contract_count NOT BETWEEN 0 AND 1",
        "contract_count = 1 AND contract_is_exact IS NOT TRUE",
        "session_user IS DISTINCT FROM 'trust_migration_runner'",
        "current_user IS DISTINCT FROM 'trust_schema_owner'",
        "schema_head_version = 15",
        "min_app_compatible_version = 15",
        "max_app_compatible_version = 15",
        "required_iam_schema_version = 42",
        "required_demand_schema_version = 11",
        FROZEN_IAM42_CONTRACT_SHA256,
        FROZEN_DEMAND11_CONTRACT_SHA256,
        FROZEN_TRUST15_MANIFEST_SHA256,
        FROZEN_TRUST15_COMBINED_SHA256,
        "schema_head_version = 16",
        "min_app_compatible_version = 16",
        "max_app_compatible_version = 16",
        "required_demand_schema_version = 12",
        DEMAND12_CONTRACT_SHA256,
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
