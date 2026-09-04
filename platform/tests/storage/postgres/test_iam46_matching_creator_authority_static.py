"""Static closure checks for IAM46 Matching creator authority seams."""

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
MIGRATION = MIGRATION_ROOT / "0046_expand__matching_creator_authority.sql"
IAM45 = MIGRATION_ROOT / "0045_expand__matching_reviewer_authority.sql"


def test_iam46_remains_a_registered_reviewed_forward_only_migration() -> None:
    catalog = MigrationCatalog.load(MIGRATION_ROOT)
    artifact = catalog.artifacts[46]

    assert IAM_SCHEMA_HEAD_VERSION >= 46
    assert IAM_MIGRATION_LAYOUT[46] == (
        46,
        MigrationPhase.EXPAND,
        "matching_creator_authority",
        MIGRATION.name,
    )
    assert artifact.descriptor.version == 46
    assert artifact.descriptor.checksum_sha256 == hashlib.sha256(
        MIGRATION.read_bytes()
    ).digest()
    assert catalog.manifest_sha256 == IAM_REVIEWED_MANIFEST_SHA256
    assert hashlib.sha256(IAM45.read_bytes()).hexdigest() == (
        "a3ded4ec8c4bf232a341bf9f9e76a33d29e4bc8244bfc3a94032d2dbe526fb1e"
    )


def test_authenticated_creator_resolver_has_exact_abi_and_matrix() -> None:
    sql = MIGRATION.read_text(encoding="utf-8")
    signature = re.search(
        r"CREATE FUNCTION "
        r"iam_api\.resolve_matching_creator_authority_marker_v1\((.*?)\)"
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
        ("exact_operation_code", "text"),
        ("exact_invitation_id", "uuid"),
        ("exact_command_id", "uuid"),
    ]
    assert re.findall(
        r"^\s{4}([a-z0-9_]+) ([a-z]+),?$",
        signature.group(2),
        flags=re.MULTILINE,
    ) == [
        ("actor_user_id", "uuid"),
        ("session_id", "uuid"),
        ("operation_code", "varchar"),
        ("role_code", "varchar"),
        ("authority_marker_sha256", "bytea"),
        ("evidence_sha256", "bytea"),
        ("valid_until", "timestamptz"),
    ]

    for operation in (
        "LIST_MATCHING_INVITATIONS",
        "READ_MATCHING_INVITATION",
        "ACCEPT_MATCHING_INVITATION",
        "DECLINE_MATCHING_INVITATION",
        "WITHDRAW_MATCHING_INVITATION",
    ):
        assert operation in sql
    for setting in (
        "app.scope_kind",
        "app.operation",
        "app.actor_user_id",
        "app.session_id",
        "app.invitation_id",
        "app.command_id",
    ):
        assert setting in sql
    assert "exact_invitation_id IS NULL" in sql
    assert "exact_command_id IS NULL" in sql
    assert "exact_invitation_id <> zero_uuid" in sql
    assert "exact_command_id <> zero_uuid" in sql


def test_creator_marker_and_evidence_bind_current_eligible_creator_graph() -> None:
    sql = MIGRATION.read_text(encoding="utf-8")

    assert "principal_marker := iam_api.editor_principal_marker_v1(" in sql
    assert "'CREATOR'::varchar" in sql
    assert "desire.iam.matching-creator-authority-evidence.v1" in sql
    for binding in (
        "|iam_head=46",
        "|scope_kind=MATCHING_CREATOR",
        "|operation_code=",
        "|role_code=CREATOR",
        "|actor_user_id=",
        "|session_id=",
        "|invitation_id=",
        "|command_id=",
        "|user_version=",
        "|family_version=",
        "|session_version=",
        "|creator_grant_id=",
        "|creator_grant_version=",
        "|source_invitation_id=",
        "|enrollment_invitation_version=",
        "|policy_selector_digest=",
        "|selector_version=",
        "|current_bundle_id=",
        "|bundle_version=",
        "|policy_document_facts_sha256=",
        "|principal_marker_sha256=",
        "|valid_until_epoch=",
    ):
        assert binding in sql

    for active_fact in (
        "actor.status = 'ACTIVE'",
        "family.status = 'ACTIVE'",
        "active_session.status = 'ACTIVE'",
        "creator_grant.revoked_at IS NULL",
        "source_invitation.status = 'ACCEPTED'",
        "current_bundle.status = 'ACTIVE'",
    ):
        assert active_fact in sql
    assert "server_now + interval '5 minutes'" in sql
    assert "NOT EXISTS (" in sql
    assert "iam.policy_acceptances" in sql


def test_profile_match_eligibility_resolver_has_exact_abi_and_outer_context() -> None:
    sql = MIGRATION.read_text(encoding="utf-8")
    signature = re.search(
        r"CREATE FUNCTION "
        r"iam_api\.resolve_profile_match_creator_eligibility_v1\((.*?)\)"
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
        ("exact_candidate_user_id", "uuid"),
        ("exact_match_run_id", "uuid"),
        ("exact_workload_id", "uuid"),
        ("exact_authorization_digest", "bytea"),
        ("exact_demand_match_context_sha256", "bytea"),
    ]
    assert re.findall(
        r"^\s{4}([a-z0-9_]+) ([a-z]+),?$",
        signature.group(2),
        flags=re.MULTILINE,
    ) == [
        ("candidate_user_id", "uuid"),
        ("eligible", "boolean"),
        ("creator_user_version", "bigint"),
        ("creator_grant_id", "uuid"),
        ("creator_grant_version", "bigint"),
        ("source_invitation_id", "uuid"),
        ("source_invitation_version", "bigint"),
        ("policy_selector_digest", "bytea"),
        ("policy_selector_version", "bigint"),
        ("policy_bundle_id", "uuid"),
        ("policy_bundle_version", "bigint"),
        ("required_policy_acceptance_set_sha256", "bytea"),
        ("eligibility_evidence_sha256", "bytea"),
        ("valid_until", "timestamptz"),
    ]

    assert "session_user IS DISTINCT FROM 'profile_matcher'" in sql
    assert "PROFILE_MATCH_DERIVATION" in sql
    assert "CAPTURE_DERIVED_MATCH_INPUTS" in sql
    for setting in (
        "app.match_run_id",
        "app.workload_id",
        "app.authorization_digest",
        "app.demand_match_context_sha256",
        "app.iam_profile_candidate_user_id",
    ):
        assert setting in sql
    assert "encode(exact_authorization_digest, 'hex')" in sql
    assert "encode(\n            exact_demand_match_context_sha256" in sql


def test_profile_match_evidence_is_locked_versioned_and_contract_bound() -> None:
    sql = MIGRATION.read_text(encoding="utf-8")

    assert sql.count("FOR KEY SHARE") >= 3
    assert "server_now + interval '15 minutes'" in sql
    assert "schema_head_version = 46" in sql
    assert "min_app_compatible_version = 46" in sql
    assert "max_app_compatible_version = 46" in sql
    assert "desire.iam.profile-match-required-policy-acceptance-set.v1" in sql
    assert "desire.iam.profile-match-creator-eligibility-evidence.v1" in sql
    for binding in (
        "|iam_head=46",
        "|iam_manifest_sha256=",
        "|iam_contract_sha256=",
        "|decision=ELIGIBLE",
        "|candidate_user_id=",
        "|match_run_id=",
        "|workload_id=",
        "|authorization_digest=",
        "|demand_match_context_sha256=",
        "|creator_user_version=",
        "|creator_grant_id=",
        "|creator_grant_version=",
        "|source_invitation_id=",
        "|source_invitation_version=",
        "|policy_selector_digest=",
        "|policy_selector_version=",
        "|policy_bundle_id=",
        "|policy_bundle_version=",
        "|required_policy_acceptance_set_sha256=",
        "|valid_until_epoch=",
    ):
        assert binding in sql
    for fact in (
        "bundle_document.document_id::text",
        "document.status",
        "document.content_sha256",
        "acceptance.id::text",
        "acceptance.aggregate_version::text",
        "acceptance.accepted_at",
        "acceptance.auth_time",
    ):
        assert fact in sql


def test_both_boundaries_are_least_privilege_and_relation_grant_free() -> None:
    sql = MIGRATION.read_text(encoding="utf-8")
    role_specs = dict(DATABASE_ROLE_SPECS)

    assert role_specs["matching_creator"] is True
    assert role_specs["profile_matcher"] is True
    assert role_specs["profile_schema_owner"] is False
    assert sql.count("session_user <> 'matching_creator'") == 8
    assert "TO matching_creator, matching_schema_owner;" in sql
    assert (
        "privilege.grantee NOT IN (\n"
        "                schema_owner_oid, creator_oid, matching_owner_oid\n"
        "            )" in sql
    )
    assert (
        "TO profile_schema_owner;" in sql
    )
    assert (
        "FROM PUBLIC, profile_matcher, profile_schema_owner" in sql
    )
    assert "direct_relation_acl_count <> 0" in sql
    assert "unexpected_execute_acl_count <> 0" in sql

    lowered = sql.lower()
    for forbidden in (
        "insert into iam.",
        "update iam.",
        "delete from iam.",
        "grant select on iam.",
        "grant insert on iam.",
        "grant update on iam.",
        "grant delete on iam.",
        "execute format",
        "execute immediate",
    ):
        assert forbidden not in lowered


def test_context_extension_preserves_all_prior_editor_marker_branches() -> None:
    sql = MIGRATION.read_text(encoding="utf-8")
    first_function = sql.split(
        "ALTER FUNCTION iam_api.editor_principal_context_valid_v1()",
        1,
    )[0]
    branches = re.findall(
        r"WHEN session_user = '([a-z_]+)' THEN",
        first_function,
    )
    assert branches == [
        "iam_app",
        "profile_app",
        "demand_self",
        "demand_review",
        "matching_assignment",
        "matching_review",
        "matching_creator",
    ]
