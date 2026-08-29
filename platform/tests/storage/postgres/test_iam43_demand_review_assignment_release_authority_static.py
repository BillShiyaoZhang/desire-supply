"""Static closure checks for IAM43 Demand assignment-release authority."""

from __future__ import annotations

import hashlib
from pathlib import Path
import re

from desire_platform.identity_access.adapters.postgres.migrations import (
    IAM_MIGRATION_LAYOUT,
    IAM_REVIEWED_MANIFEST_SHA256,
    IAM_SCHEMA_HEAD_VERSION,
    MigrationCatalog,
    MigrationPhase,
)


PLATFORM_ROOT = Path(__file__).resolve().parents[3]
MIGRATION_ROOT = (
    PLATFORM_ROOT
    / "src/desire_platform/identity_access/adapters/postgres/migrations"
)
MIGRATION = (
    MIGRATION_ROOT
    / "0043_expand__demand_review_assignment_release_authority.sql"
)


def test_iam43_remains_the_registered_immutable_prefix() -> None:
    catalog = MigrationCatalog.load(MIGRATION_ROOT)
    artifact = catalog.artifacts[43]

    assert IAM_SCHEMA_HEAD_VERSION >= 43
    assert IAM_MIGRATION_LAYOUT[43] == (
        43,
        MigrationPhase.EXPAND,
        "demand_review_assignment_release_authority",
        MIGRATION.name,
    )
    assert artifact.descriptor.version == 43
    assert artifact.descriptor.checksum_sha256 == hashlib.sha256(
        MIGRATION.read_bytes()
    ).digest()
    assert catalog.manifest_sha256 == IAM_REVIEWED_MANIFEST_SHA256


def test_iam43_adds_exactly_one_operation_to_both_v2_closed_sets() -> None:
    sql = MIGRATION.read_text(encoding="utf-8")
    expected = (
        "REQUEST_CHANGES",
        "VERIFY",
        "RELEASE_REVIEW_ASSIGNMENT",
        "REQUEST_MATCHING",
        "CANCEL_REVIEW",
    )
    allowlists = re.findall(
        r"(?:exact|candidate)_operation NOT IN \(\s*(.*?)\s*\)",
        sql,
        flags=re.DOTALL,
    )

    assert len(allowlists) == 2
    assert all(tuple(re.findall(r"'([A-Z_]+)'", block)) == expected for block in allowlists)
    assert sql.count("'RELEASE_REVIEW_ASSIGNMENT'") >= 2
    assert "iam-demand-reviewer-duty-v2|' || exact_operation" in sql
    assert "iam-demand-reviewer-duty-v2|' || candidate_operation" in sql
    assert "iam-demand-reviewer-duty-v3" not in sql


def test_iam43_preserves_v2_abi_owner_acl_and_marker_only_boundary() -> None:
    sql = MIGRATION.read_text(encoding="utf-8")
    signatures = (
        (
            "iam_api.resolve_demand_reviewer_authority_marker_v2",
            "uuid, uuid, uuid, text, uuid, uuid",
        ),
        (
            "iam_api.lock_demand_reviewer_authority_v2",
            "uuid, uuid, uuid, uuid, uuid, text, bytea",
        ),
    )
    for function_name, signature in signatures:
        assert sql.count(f"CREATE OR REPLACE FUNCTION {function_name}(") == 1
        assert (
            f"ALTER FUNCTION {function_name}(\n    {signature}\n) "
            "OWNER TO schema_owner"
        ) in sql
        assert f"REVOKE ALL ON FUNCTION {function_name}(\n    {signature}\n) FROM PUBLIC" in sql
        assert (
            f"GRANT EXECUTE ON FUNCTION {function_name}(\n    {signature}\n) "
            "TO demand_review"
        ) in sql

    for marker in (
        "SECURITY DEFINER",
        "SET search_path = pg_catalog, iam",
        "duty.duty_code = 'OPERATIONS_REVIEWER'",
        "reviewer_duty.duty_code = 'OPERATIONS_REVIEWER'",
        "membership.status = 'ACTIVE'",
        "FOR UPDATE",
        "pg_get_functiondef",
        "IAM43_DEMAND_RELEASE_AUTHORITY_DRIFTED",
    ):
        assert marker in sql
    lowered = sql.lower()
    for forbidden in (
        "create table",
        "alter table",
        "drop table",
        "demand.demands",
        "demand.demand_review_assignments",
        "execute format",
        "execute immediate",
    ):
        assert forbidden not in lowered
