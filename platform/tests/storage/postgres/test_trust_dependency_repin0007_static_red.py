"""Trust0007 metadata-only dependency-repin contracts."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re

from desire_platform.trust_safety.adapters.postgres.migrations import (
    TRUST_MIGRATION_LAYOUT,
    TrustMigrationCatalog,
    TrustMigrationPhase,
)


PLATFORM_ROOT = Path(__file__).resolve().parents[3]
MIGRATIONS = (
    PLATFORM_ROOT
    / "src/desire_platform/trust_safety/adapters/postgres/migrations"
)
TRUST0007 = MIGRATIONS / "0007_expand__iam37_demand10_dependency_repin.sql"

FROZEN_SQL_SHA256 = (
    "c4596cd745560fb4ff2e893def82a12da291f3860c363337a5b453afeeff46d4",
    "fee3eb63cc28277762a0a119b3905a3ca13021bae53e015333197f50bc256eb5",
    "b1a8be2bef32686a46dd35f71adc4448521ada9fa6880331f73883dd60f72217",
    "215701b79830951b6ce796bb41109eb67f84ddf080d5c7c3f18e3759823dd025",
    "2401744ef71647d373b7c67a943fc05e4878cf6db01538084201833571818d7b",
    "898a98ef2d4350d2aceda5f996499743a33a19d6a213e695a94544cceb4ce4ee",
)
FROZEN_PREFIX_SHA256 = (
    "9bd2be5ccbf62824569b07505e53902e3775675cdfa684524d0ba503846a2c13",
    "94a1e604044ea60845c44d191cd75c9794cd19731f2b8a52e28547e7172ddf93",
    "141057a29520dd4027570dda20c95e305053bbb2bb6f8d5a145e5e5b2d8e4863",
    "4bd6f0e8367e7853adccc28cf868fda1b3cf00b678c252b1d1ae635b422837a8",
    "8b02df9ea6717265e3d69d22b837c9b5455ebab74cebe0c6a112d15de22b1c04",
    "05a731b5ce1418e444384b765a22874173e200c3d03005276b507802a9b38415",
)
FROZEN_IAM37_CONTRACT_SHA256 = (
    "595d5232153063b0b71a88b3776c737d1fcd5ecaef4a4b832c5e40434929c486"
)
FROZEN_DEMAND10_DEPENDENCY_SHA256 = (
    "27ec6b585a9340cbd7119d7a9b46d6098a3881f88ae1be9e00df3713c0107113"
)


def test_trust7_is_one_forward_only_tail_after_frozen_trust1_through_6() -> None:
    catalog = TrustMigrationCatalog.load(MIGRATIONS)

    assert TRUST_MIGRATION_LAYOUT[6] == (
        7,
        TrustMigrationPhase.EXPAND,
        "iam37_demand10_dependency_repin",
        TRUST0007.name,
    )
    assert tuple(
        hashlib.sha256(artifact.sql_bytes).hexdigest()
        for artifact in catalog.artifacts[:6]
    ) == FROZEN_SQL_SHA256
    assert tuple(
        artifact.descriptor.prefix_manifest_sha256.hex()
        for artifact in catalog.artifacts[:6]
    ) == FROZEN_PREFIX_SHA256
    assert catalog.artifacts[6].sql_bytes == TRUST0007.read_bytes()

    entries = json.loads(catalog.manifest_bytes)
    assert tuple(entry["sha256"] for entry in entries[:6]) == FROZEN_SQL_SHA256
    assert tuple(entry["version"] for entry in entries[:7]) == tuple(range(1, 8))
    assert entries[6]["sha256"] == (
        "16d383778cb794402c786f5cae8c32744af30627928d35fff9182a97128e1fc3"
    )


def test_trust7_pins_frozen_iam37_and_demand10_dependencies() -> None:
    sql = TRUST0007.read_text(encoding="utf-8")

    assert "required_iam_schema_version = 37" in sql
    assert "required_demand_schema_version = 10" in sql
    assert FROZEN_IAM37_CONTRACT_SHA256 in sql
    assert FROZEN_DEMAND10_DEPENDENCY_SHA256 in sql


def test_trust7_sql_is_metadata_only_acl_neutral_and_exactly_guarded() -> None:
    sql = TRUST0007.read_text(encoding="utf-8")
    compact = " ".join(sql.split())

    assert "TRUST6_SCHEMA_CONTRACT_BASELINE_MISMATCH" in sql
    assert "TRUST6_SCHEMA_CONSTRAINT_BASELINE_MISMATCH" in sql
    assert "session_user IS DISTINCT FROM 'trust_migration_runner'" in sql
    assert "current_user IS DISTINCT FROM 'trust_schema_owner'" in sql
    assert "schema_head_version = 6" in sql
    assert "required_iam_schema_version = 36" in sql
    assert "required_demand_schema_version = 9" in sql
    assert (
        "c44c2cc028d5eec1f451e9715fe9c537883b6e5abd71f8f5f4610aedac13b90e"
        in sql
    )
    assert (
        "5b8050df445704d99606688aeacd8b36d5c3451a9ba85c6640a54a4e99b24694"
        in sql
    )
    assert "schema_head_version = 7" in sql
    assert "min_app_compatible_version = 7" in sql
    assert "max_app_compatible_version = 7" in sql
    assert "required_iam_schema_version = 37" in sql
    assert "required_demand_schema_version = 10" in sql
    assert FROZEN_IAM37_CONTRACT_SHA256 in sql
    assert FROZEN_DEMAND10_DEPENDENCY_SHA256 in sql

    assert sql.count("DELETE FROM trust_meta.schema_contracts") == 1
    assert compact.count("ALTER TABLE trust_meta.schema_contracts") == 2
    assert "CREATE TABLE" not in sql
    assert "CREATE FUNCTION" not in sql
    assert "CREATE OR REPLACE FUNCTION" not in sql
    assert "CREATE VIEW" not in sql
    assert "CREATE POLICY" not in sql
    assert "DROP POLICY" not in sql
    assert "ENABLE ROW LEVEL SECURITY" not in sql
    assert "FORCE ROW LEVEL SECURITY" not in sql
    assert re.search(r"\b(?:GRANT|REVOKE)\b", sql) is None
    assert "EXECUTE format" not in sql


def test_trust7_runner_keeps_sql_ledger_contract_update_in_one_transaction() -> None:
    runner = (
        PLATFORM_ROOT
        / "src/desire_platform/trust_safety/adapters/postgres/migrations/runner.py"
    ).read_text(encoding="utf-8")

    begin = runner.index('connection.execute("BEGIN ISOLATION LEVEL READ COMMITTED")')
    sql = runner.index('connection.execute(artifact.sql_bytes.decode("utf-8"))')
    ledger = runner.index(
        '"INSERT INTO trust_meta.schema_migrations ("',
        sql,
    )
    contract = runner.index(
        '"INSERT INTO trust_meta.schema_contracts ("',
        ledger,
    )
    commit = runner.index('connection.execute("COMMIT")', contract)
    assert begin < sql < ledger < contract < commit
    assert 'connection.execute("ROLLBACK")' in runner


def test_historical_v13_operations_pins_remain_frozen_at_trust7() -> None:
    backup = (
        PLATFORM_ROOT.parent / "deploy/postgres-backup-restore.sh"
    ).read_text(encoding="utf-8")
    verifier = (
        PLATFORM_ROOT.parent / "scripts/verify_container_stack.py"
    ).read_text(encoding="utf-8")
    for source in (backup, verifier):
        assert "18|37|37|3|3|10|10|7|7|2|2" in source
        assert FROZEN_IAM37_CONTRACT_SHA256 in source
        assert FROZEN_DEMAND10_DEPENDENCY_SHA256 in source
        assert (
            "ab857f25969d17afe63886afe136cda10814e538517c54c180503b82f5785c1b"
            in source
        )
        assert (
            "27a51c55bddfcb2a4f1bd16a3160abbb3a417425f14077f4886c3c41c22d5124"
            in source
        )


def test_historical_docs_distinguish_trust7_source_from_v12_trust6_evidence() -> None:
    operations_root = PLATFORM_ROOT.parent / "docs/operations"
    runbook = (operations_root / "run-and-check.md").read_text(encoding="utf-8")
    deployment = (
        operations_root / "container-deployment.md"
    ).read_text(encoding="utf-8")

    for document in (runbook, deployment):
        assert "Trust" in document and "`0007`" in document
        assert "IAM37/Demand10/Trust7" in document
        assert "v12/Trust6" in document
