"""Static closure checks for IAM44 Candidate Selector opt-in authority."""

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
MIGRATION = (
    MIGRATION_ROOT / "0044_expand__candidate_selector_opt_in_authority.sql"
)
IAM43 = (
    MIGRATION_ROOT
    / "0043_expand__demand_review_assignment_release_authority.sql"
)


def test_iam44_remains_the_registered_immutable_prefix() -> None:
    catalog = MigrationCatalog.load(MIGRATION_ROOT)
    artifact = catalog.artifacts[44]

    assert IAM_SCHEMA_HEAD_VERSION >= 44
    assert IAM_MIGRATION_LAYOUT[44] == (
        44,
        MigrationPhase.EXPAND,
        "candidate_selector_opt_in_authority",
        MIGRATION.name,
    )
    assert artifact.descriptor.version == 44
    assert artifact.descriptor.checksum_sha256 == hashlib.sha256(
        MIGRATION.read_bytes()
    ).digest()
    assert catalog.manifest_sha256 == IAM_REVIEWED_MANIFEST_SHA256
    assert hashlib.sha256(IAM43.read_bytes()).hexdigest() == (
        "1e6d005858bef6f8dfbcbba2db20f4d515970fa78000b766eed55db4bc4f89df"
    )


def test_resolver_has_the_exact_matching_v3_abi_and_local_context() -> None:
    sql = MIGRATION.read_text(encoding="utf-8")
    signature = re.search(
        r"CREATE FUNCTION "
        r"iam_api\.resolve_candidate_selector_opt_in_marker_v1\((.*?)\)"
        r"\nRETURNS TABLE \((.*?)\)\nLANGUAGE plpgsql",
        sql,
        flags=re.DOTALL,
    )
    assert signature is not None
    assert re.findall(
        r"^\s{4}(exact_[a-z0-9_]+) (uuid),?$",
        signature.group(1),
        flags=re.MULTILINE,
    ) == [
        ("exact_actor_user_id", "uuid"),
        ("exact_session_id", "uuid"),
        ("exact_organization_id", "uuid"),
        ("exact_selection_id", "uuid"),
        ("exact_demand_id", "uuid"),
        ("exact_command_id", "uuid"),
    ]
    assert re.findall(
        r"^\s{4}([a-z0-9_]+) ([a-z]+(?: with time zone)?),?$",
        signature.group(2),
        flags=re.MULTILINE,
    ) == [
        ("actor_user_id", "uuid"),
        ("session_id", "uuid"),
        ("organization_id", "uuid"),
        ("selection_id", "uuid"),
        ("demand_id", "uuid"),
        ("role_code", "varchar"),
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
        "app.selection_id",
        "app.demand_id",
        "app.command_id",
    ):
        assert setting in sql
    for purpose in (
        "MATCHING_ASSIGNMENT",
        "OPT_IN_CANDIDATE_SELECTOR",
        "CANDIDATE_SELECTOR",
    ):
        assert purpose in sql


def test_authority_marker_stays_editor_compatible_and_evidence_is_exact() -> None:
    sql = MIGRATION.read_text(encoding="utf-8")

    assert "principal_marker := iam_api.editor_principal_marker_v1(" in sql
    assert "principal_marker," in sql
    assert "desire.iam.candidate-selector-opt-in-evidence.v1" in sql
    for binding in (
        "|iam_head=44",
        "|purpose=OPT_IN_CANDIDATE_SELECTOR",
        "|actor_user_id=",
        "|session_id=",
        "|organization_id=",
        "|selection_id=",
        "|demand_id=",
        "|command_id=",
        "|user_version=",
        "|family_version=",
        "|session_version=",
        "|organization_version=",
        "|membership_version=",
        "|principal_marker_sha256=",
        "|valid_until_epoch=",
    ):
        assert binding in sql

    assert "active_session.auth_time > server_now - interval '30 minutes'" in sql
    assert "active_session.auth_time + interval '30 minutes'" in sql
    assert "membership.status = 'ACTIVE'" in sql
    assert "organization.status = 'ACTIVE'" in sql
    assert "actor.status = 'ACTIVE'" in sql
    assert "active_session.status = 'ACTIVE'" in sql
    assert "family.status = 'ACTIVE'" in sql


def test_boundary_is_marker_only_force_rls_and_least_privilege() -> None:
    sql = MIGRATION.read_text(encoding="utf-8")
    role_specs = dict(DATABASE_ROLE_SPECS)

    assert role_specs["matching_assignment"] is True
    assert sql.count("AS RESTRICTIVE") == 8
    assert sql.count("session_user <> 'matching_assignment'") == 8
    assert "session_user IS DISTINCT FROM 'matching_assignment'" in sql
    assert "current_user IS DISTINCT FROM 'schema_owner'" in sql
    assert (
        "TO matching_assignment, matching_schema_owner" in sql
    )
    assert (
        "FROM PUBLIC, matching_assignment, matching_schema_owner" in sql
    )
    assert "direct_relation_acl_count <> 0" in sql
    assert "unexpected_execute_acl_count <> 0" in sql
    assert "guard_policy_count <> 8" in sql

    lowered = sql.lower()
    for forbidden in (
        "insert into iam.",
        "update iam.",
        "delete from iam.",
        "grant select on iam.",
        "grant insert on iam.",
        "grant update on iam.",
        "grant delete on iam.",
        "alter table iam.access_invitations",
        "alter table iam.membership_role_grants",
        "execute format",
        "execute immediate",
    ):
        assert forbidden not in lowered
