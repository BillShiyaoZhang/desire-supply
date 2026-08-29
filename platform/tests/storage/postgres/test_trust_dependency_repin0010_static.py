from __future__ import annotations

import hashlib
from pathlib import Path

from desire_platform.trust_safety.adapters.postgres.migrations import (
    TRUST_MIGRATION_LAYOUT,
    TrustMigrationCatalog,
)


PLATFORM_ROOT = Path(__file__).resolve().parents[3]
MIGRATION_ROOT = (
    PLATFORM_ROOT
    / "src/desire_platform/trust_safety/adapters/postgres/migrations"
)
MIGRATION = MIGRATION_ROOT / "0010_expand__demand11_dependency_repin.sql"
FROZEN_DEMAND11_CONTRACT_SHA256 = (
    "cfab70770b908b37aa4865ba2f52d5b8f59492cbc7979867229e006e99cd8d87"
)


def test_trust10_repins_only_the_reviewed_demand11_dependency() -> None:
    sql = MIGRATION.read_text(encoding="utf-8")
    catalog = TrustMigrationCatalog.load(MIGRATION_ROOT)

    assert TRUST_MIGRATION_LAYOUT[9][2:] == (
        "demand11_dependency_repin",
        MIGRATION.name,
    )
    assert hashlib.sha256(MIGRATION.read_bytes()).hexdigest() == (
        "97f7b3bee6772277e19b1239711bc4ea907b4bb5598a8ffd3e2fc82c21e9c2e2"
    )
    assert catalog.artifacts[9].descriptor.prefix_manifest_sha256.hex() == (
        "d01be3288358965a07503b08e648be79eaf4a4493dfbf1c9e7f0c6f96c2ea683"
    )
    assert FROZEN_DEMAND11_CONTRACT_SHA256 in sql
    for marker in (
        "schema_head_version = 9",
        "required_demand_schema_version = 10",
        "required_demand_schema_version = 11",
        "schema_head_version = 10",
        "required_iam_schema_version = 38",
        "desire:trust:combined-contract:v2",
    ):
        assert marker in sql
