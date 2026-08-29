"""Static closure checks for IAM45 Matching reviewer authority."""

from __future__ import annotations

import hashlib
from pathlib import Path
import re

from desire_platform.deployment.migrations import DATABASE_ROLE_SPECS
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
MIGRATION = MIGRATION_ROOT / "0045_expand__matching_reviewer_authority.sql"
IAM44 = MIGRATION_ROOT / "0044_expand__candidate_selector_opt_in_authority.sql"


def test_iam45_remains_the_registered_immutable_prefix() -> None:
    catalog = MigrationCatalog.load(MIGRATION_ROOT)
    artifact = catalog.artifacts[45]

    assert IAM_SCHEMA_HEAD_VERSION >= 45
    assert IAM_MIGRATION_LAYOUT[45] == (
        45,
        MigrationPhase.EXPAND,
        "matching_reviewer_authority",
        MIGRATION.name,
    )
    assert artifact.descriptor.version == 45
    assert artifact.descriptor.checksum_sha256 == hashlib.sha256(
        MIGRATION.read_bytes()
    ).digest()
    assert catalog.manifest_sha256 == IAM_REVIEWED_MANIFEST_SHA256
    assert hashlib.sha256(IAM44.read_bytes()).hexdigest() == (
        "517efda9a3fec30ff0d705f557ef8231c64b559bd2ff5f5b60c10318d5fe9398"
    )


def test_resolver_has_the_exact_matching_review_abi_and_local_context() -> None:
    sql = MIGRATION.read_text(encoding="utf-8")
    signature = re.search(
        r"CREATE FUNCTION "
        r"iam_api\.resolve_matching_reviewer_authority_marker_v1\((.*?)\)"
        r"\nRETURNS TABLE \((.*?)\)\nLANGUAGE plpgsql",
        sql,
        flags=re.DOTALL,
    )
    assert signature is not None
    assert re.findall(
        r"^\s{4}(exact_[a-z0-9_]+) ([a-z]+),?$",
        signature.group(1),
        flags=re.MULTILINE,
    ) == [
        ("exact_actor_user_id", "uuid"),
        ("exact_session_id", "uuid"),
        ("exact_organization_id", "uuid"),
        ("exact_attempt_id", "uuid"),
        ("exact_match_run_id", "uuid"),
        ("exact_purpose_code", "text"),
        ("exact_claim_command_id", "uuid"),
    ]
    assert re.findall(
        r"^\s{4}([a-z0-9_]+) ([a-z]+),?$",
        signature.group(2),
        flags=re.MULTILINE,
    ) == [
        ("actor_user_id", "uuid"),
        ("session_id", "uuid"),
        ("organization_id", "uuid"),
        ("attempt_id", "uuid"),
        ("match_run_id", "uuid"),
        ("purpose_code", "varchar"),
        ("role_code", "varchar"),
        ("duty_code", "varchar"),
        ("duty_grant_id", "uuid"),
        ("duty_grant_version", "bigint"),
        ("authority_marker_sha256", "bytea"),
        ("evidence_sha256", "bytea"),
        ("valid_until", "timestamptz"),
    ]

    for setting in (
        "app.scope_kind",
        "app.operation",
        "app.actor_user_id",
        "app.session_id",
        "app.organization_id",
        "app.attempt_id",
        "app.match_run_id",
        "app.purpose_code",
        "app.command_id",
    ):
        assert setting in sql
    for purpose in (
        "MATCH_RETRY",
        "INVITATION_REVIEW",
        "ATTEMPT_REVIEW",
    ):
        assert purpose in sql


def test_marker_duty_conflict_and_bounded_evidence_are_derived() -> None:
    sql = MIGRATION.read_text(encoding="utf-8")

    assert "principal_marker := iam_api.editor_principal_marker_v1(" in sql
    assert "'MATCHING_REVIEWER'::varchar" in sql
    assert "'OPERATIONS_REVIEWER'::varchar" in sql
    assert "reviewer_duty.duty_code = 'OPERATIONS_REVIEWER'" in sql
    assert "NOT EXISTS (" in sql
    assert "conflict_membership.status = 'ACTIVE'" in sql
    assert "desire.iam.matching-reviewer-claim-evidence.v1" in sql
    for binding in (
        "|iam_head=45",
        "|operation=CLAIM_MATCHING_REVIEW",
        "|purpose_code=",
        "|role_code=MATCHING_REVIEWER",
        "|duty_code=OPERATIONS_REVIEWER",
        "|duty_status=ACTIVE",
        "|target_organization_status=ACTIVE",
        "|actor_user_id=",
        "|session_id=",
        "|organization_id=",
        "|attempt_id=",
        "|match_run_id=",
        "|claim_command_id=",
        "|user_version=",
        "|family_version=",
        "|session_version=",
        "|organization_version=",
        "|duty_grant_id=",
        "|duty_grant_version=",
        "|conflict_policy=TARGET_ACTIVE_MEMBERSHIP_ABSENT",
        "|target_active_membership_count=",
        "|principal_marker_sha256=",
        "|valid_until_epoch=",
    ):
        assert binding in sql

    assert "auth_time > server_now - interval '30 minutes'" in sql
    assert "server_now + interval '5 minutes'" in sql
    assert "auth_time + interval '30 minutes'" in sql
    assert "COALESCE(reviewer_duty.expires_at" in sql
    for active_fact in (
        "actor.status = 'ACTIVE'",
        "family.status = 'ACTIVE'",
        "active_session.status = 'ACTIVE'",
        "target_organization.status = 'ACTIVE'",
        "reviewer_duty.revoked_at IS NULL",
    ):
        assert active_fact in sql


def test_context_extension_preserves_all_prior_session_user_branches() -> None:
    sql = MIGRATION.read_text(encoding="utf-8")
    branches = re.findall(r"WHEN session_user = '([a-z_]+)' THEN", sql)

    assert branches == [
        "iam_app",
        "profile_app",
        "demand_self",
        "demand_review",
        "matching_assignment",
        "matching_review",
    ]
    assert "OPT_IN_CANDIDATE_SELECTOR" in sql
    assert "CLAIM_MATCHING_REVIEW" in sql


def test_boundary_is_force_rls_marker_only_and_least_privilege() -> None:
    sql = MIGRATION.read_text(encoding="utf-8")
    role_specs = dict(DATABASE_ROLE_SPECS)

    assert role_specs["matching_review"] is True
    assert sql.count("AS RESTRICTIVE") == 8
    assert sql.count("session_user <> 'matching_review'") == 8
    assert "rls_matching_review_target_organization_definer_v1" in sql
    assert "session_user IS DISTINCT FROM 'matching_review'" in sql
    assert "current_user IS DISTINCT FROM 'schema_owner'" in sql
    assert ") TO matching_review, matching_schema_owner;" in sql
    assert "FROM PUBLIC, matching_assignment, matching_review, matching_schema_owner" in sql
    assert "direct_relation_acl_count <> 0" in sql
    assert "unexpected_execute_acl_count <> 0" in sql
    assert "guard_policy_count <> 8" in sql
    assert "target_policy_count <> 1" in sql

    lowered = sql.lower()
    for forbidden in (
        "insert into iam.",
        "update iam.",
        "delete from iam.",
        "grant select on iam.",
        "grant insert on iam.",
        "grant update on iam.",
        "grant delete on iam.",
        "alter table iam.platform_duty_grants",
        "alter table iam.memberships",
        "execute format",
        "execute immediate",
    ):
        assert forbidden not in lowered
