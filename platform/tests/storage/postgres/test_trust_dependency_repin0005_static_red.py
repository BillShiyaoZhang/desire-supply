from __future__ import annotations

import hashlib
from pathlib import Path

from desire_platform.trust_safety.adapters.postgres.migrations import (
    TRUST_MIGRATION_LAYOUT,
    TrustMigrationCatalog,
    TrustMigrationPhase,
)


ROOT = Path(__file__).resolve().parents[3]
MIGRATIONS = (
    ROOT / "src/desire_platform/trust_safety/adapters/postgres/migrations"
)
TRUST0005 = MIGRATIONS / "0005_expand__demand9_dependency_repin.sql"

FROZEN_SQL_SHA256 = (
    "c4596cd745560fb4ff2e893def82a12da291f3860c363337a5b453afeeff46d4",
    "fee3eb63cc28277762a0a119b3905a3ca13021bae53e015333197f50bc256eb5",
    "b1a8be2bef32686a46dd35f71adc4448521ada9fa6880331f73883dd60f72217",
    "215701b79830951b6ce796bb41109eb67f84ddf080d5c7c3f18e3759823dd025",
)
FROZEN_PREFIX_SHA256 = (
    "9bd2be5ccbf62824569b07505e53902e3775675cdfa684524d0ba503846a2c13",
    "94a1e604044ea60845c44d191cd75c9794cd19731f2b8a52e28547e7172ddf93",
    "141057a29520dd4027570dda20c95e305053bbb2bb6f8d5a145e5e5b2d8e4863",
    "4bd6f0e8367e7853adccc28cf868fda1b3cf00b678c252b1d1ae635b422837a8",
)


def test_trust5_is_forward_only_after_the_byte_frozen_trust4_prefix() -> None:
    catalog = TrustMigrationCatalog.load(MIGRATIONS)

    assert TRUST_MIGRATION_LAYOUT[4] == (
        5,
        TrustMigrationPhase.EXPAND,
        "demand9_dependency_repin",
        TRUST0005.name,
    )
    assert tuple(
        hashlib.sha256(artifact.sql_bytes).hexdigest()
        for artifact in catalog.artifacts[:4]
    ) == FROZEN_SQL_SHA256
    assert tuple(
        artifact.descriptor.prefix_manifest_sha256.hex()
        for artifact in catalog.artifacts[:4]
    ) == FROZEN_PREFIX_SHA256
    assert catalog.artifacts[4].sql_bytes == TRUST0005.read_bytes()


def test_trust5_is_metadata_only_and_repins_both_exact_constraints() -> None:
    sql = TRUST0005.read_text(encoding="utf-8")

    assert "TRUST4_SCHEMA_CONTRACT_BASELINE_MISMATCH" in sql
    assert "TRUST4_SCHEMA_CONSTRAINT_BASELINE_MISMATCH" in sql
    assert "contract_count NOT BETWEEN 0 AND 1" in sql
    assert "contract_count = 1 AND contract_is_exact IS NOT TRUE" in sql
    assert "a3ade02769b8a31ae0fe17e6f00099476352a6f4d0c1fe039d3e8a3b317db931" in sql
    assert "e692f199880e8367f9224c8b13604f15caf87066f4430f2407dbe5573d8c17a4" in sql
    assert "DROP CONSTRAINT ck_trust_schema_contract_versions" in sql
    assert "DROP CONSTRAINT ck_trust_schema_contract_hashes" in sql
    assert "ADD CONSTRAINT ck_trust_schema_contract_versions" in sql
    assert "ADD CONSTRAINT ck_trust_schema_contract_hashes" in sql
    assert "schema_head_version = 5" in sql
    assert "min_app_compatible_version = 5" in sql
    assert "max_app_compatible_version = 5" in sql
    assert "required_iam_schema_version = 36" in sql
    assert "required_demand_schema_version = 9" in sql
    assert (
        "2ce5929295d30a91b55d9d907e0031707461498d3380e9e9e2e449eec06f9328"
        in sql
    )
    assert "desire:trust:combined-contract:v2" in sql
    assert sql.count("DELETE FROM trust_meta.schema_contracts") == 1
    assert sql.count("ALTER TABLE trust_meta.schema_contracts") == 2

    for forbidden in (
        "CREATE TABLE ",
        "CREATE VIEW ",
        "CREATE FUNCTION ",
        "CREATE TRIGGER ",
        "CREATE POLICY ",
        "ALTER TABLE trust.",
        "INSERT INTO ",
        "UPDATE trust.",
        "GRANT ",
        "REVOKE ",
    ):
        assert forbidden not in sql
