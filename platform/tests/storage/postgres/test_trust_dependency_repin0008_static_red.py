"""Trust0008 metadata-only IAM38 dependency-repin contracts."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re

from desire_platform.trust_safety.adapters.postgres.migrations import (
    TRUST_MIGRATION_LAYOUT,
    TRUST_REQUIRED_DEMAND_CONTRACT_SHA256,
    TRUST_REQUIRED_DEMAND_SCHEMA_VERSION,
    TRUST_REQUIRED_IAM_SCHEMA_VERSION,
    TRUST_REVIEWED_MANIFEST_SHA256,
    TRUST_SCHEMA_HEAD_VERSION,
    TrustMigrationCatalog,
    TrustMigrationPhase,
)
from desire_platform.trust_safety.adapters.postgres.migrations.runner import (
    _EXPECTED_DEMAND_REQUIRED_IAM_SCHEMA_VERSION,
)


PLATFORM_ROOT = Path(__file__).resolve().parents[3]
MIGRATIONS = (
    PLATFORM_ROOT
    / "src/desire_platform/trust_safety/adapters/postgres/migrations"
)
TRUST0008 = MIGRATIONS / "0008_expand__iam38_demand10_dependency_repin.sql"

FROZEN_SQL_SHA256 = (
    "c4596cd745560fb4ff2e893def82a12da291f3860c363337a5b453afeeff46d4",
    "fee3eb63cc28277762a0a119b3905a3ca13021bae53e015333197f50bc256eb5",
    "b1a8be2bef32686a46dd35f71adc4448521ada9fa6880331f73883dd60f72217",
    "215701b79830951b6ce796bb41109eb67f84ddf080d5c7c3f18e3759823dd025",
    "2401744ef71647d373b7c67a943fc05e4878cf6db01538084201833571818d7b",
    "898a98ef2d4350d2aceda5f996499743a33a19d6a213e695a94544cceb4ce4ee",
    "16d383778cb794402c786f5cae8c32744af30627928d35fff9182a97128e1fc3",
)
FROZEN_PREFIX_SHA256 = (
    "9bd2be5ccbf62824569b07505e53902e3775675cdfa684524d0ba503846a2c13",
    "94a1e604044ea60845c44d191cd75c9794cd19731f2b8a52e28547e7172ddf93",
    "141057a29520dd4027570dda20c95e305053bbb2bb6f8d5a145e5e5b2d8e4863",
    "4bd6f0e8367e7853adccc28cf868fda1b3cf00b678c252b1d1ae635b422837a8",
    "8b02df9ea6717265e3d69d22b837c9b5455ebab74cebe0c6a112d15de22b1c04",
    "05a731b5ce1418e444384b765a22874173e200c3d03005276b507802a9b38415",
    "27a51c55bddfcb2a4f1bd16a3160abbb3a417425f14077f4886c3c41c22d5124",
)
FROZEN_IAM37_CONTRACT_SHA256 = (
    "595d5232153063b0b71a88b3776c737d1fcd5ecaef4a4b832c5e40434929c486"
)
FROZEN_DEMAND10_DEPENDENCY_SHA256 = (
    "27ec6b585a9340cbd7119d7a9b46d6098a3881f88ae1be9e00df3713c0107113"
)
FROZEN_TRUST7_COMBINED_SHA256 = (
    "ab857f25969d17afe63886afe136cda10814e538517c54c180503b82f5785c1b"
)
FROZEN_TRUST7_MANIFEST_SHA256 = FROZEN_PREFIX_SHA256[-1]
FROZEN_TRUST7_VERSION_CONSTRAINT_SHA256 = (
    "d9e87f27d46d52cd147b1a4ed7564b135f918295589a8f910ceaa7464ad2cbf4"
)
FROZEN_TRUST7_HASH_CONSTRAINT_SHA256 = (
    "9864baeaebc04bcc3928075af4d7c00f5b85badc53866aea888e46c7168baef1"
)
IAM38_CONTRACT_SHA256 = (
    "908f3de6b6b90fd5d19004304e9df24d0e5738fe6edf88e1b2cb2b1a414c5e3e"
)
TRUST8_SQL_SHA256 = (
    "c15ca1b6ac8a750dc4cd5b1cf815a367d7531ddb9088da9d60ec1a7a99ff241b"
)
TRUST8_MANIFEST_SHA256 = (
    "6d5e98529d07f684657820a8a1d405cd243fa8ac26518ecee02a966ccc02d722"
)


def test_trust8_is_one_forward_only_tail_after_frozen_trust1_through_7() -> None:
    catalog = TrustMigrationCatalog.load(MIGRATIONS)

    assert TRUST_SCHEMA_HEAD_VERSION >= 8
    assert TRUST_MIGRATION_LAYOUT[7] == (
        8,
        TrustMigrationPhase.EXPAND,
        "iam38_demand10_dependency_repin",
        TRUST0008.name,
    )
    assert tuple(
        hashlib.sha256(artifact.sql_bytes).hexdigest()
        for artifact in catalog.artifacts[:7]
    ) == FROZEN_SQL_SHA256
    assert tuple(
        artifact.descriptor.prefix_manifest_sha256.hex()
        for artifact in catalog.artifacts[:7]
    ) == FROZEN_PREFIX_SHA256
    assert catalog.artifacts[7].sql_bytes == TRUST0008.read_bytes()
    assert catalog.artifacts[7].descriptor.checksum_sha256.hex() == (
        TRUST8_SQL_SHA256
    )
    assert catalog.manifest_sha256 == TRUST_REVIEWED_MANIFEST_SHA256
    assert (
        catalog.artifacts[7].descriptor.prefix_manifest_sha256.hex()
        == TRUST8_MANIFEST_SHA256
    )

    entries = json.loads(catalog.manifest_bytes)
    assert tuple(entry["version"] for entry in entries[:8]) == tuple(range(1, 9))
    assert tuple(entry["sha256"] for entry in entries[:7]) == FROZEN_SQL_SHA256


def test_trust8_pins_direct_iam38_but_demand10_transitively_pins_iam37() -> None:
    assert TRUST_REQUIRED_IAM_SCHEMA_VERSION >= 38
    assert TRUST_REQUIRED_DEMAND_SCHEMA_VERSION >= 10
    assert _EXPECTED_DEMAND_REQUIRED_IAM_SCHEMA_VERSION >= 37
    assert IAM38_CONTRACT_SHA256 in TRUST0008.read_text(encoding="utf-8")
    assert FROZEN_DEMAND10_DEPENDENCY_SHA256 in TRUST0008.read_text(encoding="utf-8")


def test_trust8_sql_repins_the_exact_trust7_metadata_baseline() -> None:
    sql = TRUST0008.read_text(encoding="utf-8")

    assert "TRUST7_SCHEMA_CONTRACT_BASELINE_MISMATCH" in sql
    assert "TRUST7_SCHEMA_CONSTRAINT_BASELINE_MISMATCH" in sql
    assert "contract_count NOT BETWEEN 0 AND 1" in sql
    assert "contract_count = 1 AND contract_is_exact IS NOT TRUE" in sql
    assert "session_user IS DISTINCT FROM 'trust_migration_runner'" in sql
    assert "current_user IS DISTINCT FROM 'trust_schema_owner'" in sql
    assert "schema_head_version = 7" in sql
    assert "min_app_compatible_version = 7" in sql
    assert "max_app_compatible_version = 7" in sql
    assert "required_iam_schema_version = 37" in sql
    assert "required_demand_schema_version = 10" in sql
    assert FROZEN_IAM37_CONTRACT_SHA256 in sql
    assert FROZEN_DEMAND10_DEPENDENCY_SHA256 in sql
    assert FROZEN_TRUST7_COMBINED_SHA256 in sql
    assert FROZEN_TRUST7_MANIFEST_SHA256 in sql
    assert FROZEN_TRUST7_VERSION_CONSTRAINT_SHA256 in sql
    assert FROZEN_TRUST7_HASH_CONSTRAINT_SHA256 in sql
    assert sql.count("sha256(convert_to(pg_get_constraintdef(") == 2
    assert "DROP CONSTRAINT ck_trust_schema_contract_versions" in sql
    assert "DROP CONSTRAINT ck_trust_schema_contract_hashes" in sql
    assert "ADD CONSTRAINT ck_trust_schema_contract_versions" in sql
    assert "ADD CONSTRAINT ck_trust_schema_contract_hashes" in sql


def test_trust8_sql_is_metadata_only_acl_neutral_and_pins_iam38() -> None:
    sql = TRUST0008.read_text(encoding="utf-8")
    compact = " ".join(sql.split())

    assert "schema_head_version = 8" in sql
    assert "min_app_compatible_version = 8" in sql
    assert "max_app_compatible_version = 8" in sql
    assert "required_iam_schema_version = 38" in sql
    assert "required_demand_schema_version = 10" in sql
    assert IAM38_CONTRACT_SHA256 in sql
    assert FROZEN_DEMAND10_DEPENDENCY_SHA256 in sql
    assert "desire:trust:combined-contract:v2" in sql
    assert sql.count("DELETE FROM trust_meta.schema_contracts") == 1
    assert compact.count("ALTER TABLE trust_meta.schema_contracts") == 2

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
