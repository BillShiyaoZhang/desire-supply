"""Static review gates for Profile5 derived Matching inputs."""

from __future__ import annotations

import hashlib
from pathlib import Path

from desire_platform.creator_profile.adapters.postgres import (
    CREATOR_PROFILE_POSTGRES_STATEMENT_PROFILES,
    PROFILE_POSTGRES_SCHEMA_HEAD_VERSION,
    CreatorProfilePostgresOperation,
)
from desire_platform.creator_profile.adapters.postgres.migrations import (
    ProfileMigrationCatalog,
)


ROOT = Path(__file__).resolve().parents[3]
MIGRATIONS = (
    ROOT / "src/desire_platform/creator_profile/adapters/postgres/migrations"
)


def test_profile_historical_migration_bytes_are_frozen_and_head_is_five() -> None:
    expected = (
        "6c0853969cf2693e89ffe175601c3830ccd88fcd173257b8170d7b3680691f9b",
        "67e43d8282108136cb02ab35e46dad76f74b8417543b25997b11ab96e7382677",
        "8d69fb82f7ed84c73329ca5cc50542783c0f930ce2b672c36efcbc79d8aa853b",
        "9e1606dec9cb3bef5d2157bea0ca5503f6f6ee5f0cfe1dc8ebeef637049ffae4",
    )
    for version, digest in enumerate(expected, start=1):
        path = next(MIGRATIONS.glob(f"{version:04d}_*.sql"))
        assert hashlib.sha256(path.read_bytes()).hexdigest() == digest
    catalog = ProfileMigrationCatalog.load(MIGRATIONS)
    assert len(catalog.artifacts) == 5
    assert PROFILE_POSTGRES_SCHEMA_HEAD_VERSION == 5


def test_profile5_program_has_exact_fixed_security_and_privacy_surface() -> None:
    sql = (MIGRATIONS / "0005_expand__derived_matching_inputs.sql").read_text(
        encoding="utf-8"
    )
    for fragment in (
        "discover_and_capture_derived_creator_match_inputs_v1",
        "exact_match_run_id uuid",
        "exact_workload_id uuid",
        "exact_authorization_digest bytea",
        "exact_demand_match_context_bytes bytea",
        "exact_demand_match_context_sha256 bytea",
        "PROFILE_MATCH_DERIVATION",
        "CAPTURE_DERIVED_MATCH_INPUTS",
        "current_setting('transaction_isolation')",
        "'repeatable read'",
        "session_user IS DISTINCT FROM 'profile_matcher'",
        "current_user IS DISTINCT FROM 'profile_schema_owner'",
        "resolve_profile_match_creator_eligibility_v1",
        "candidate_count_local > 500",
        "WHERE receipt.match_run_id = exact_match_run_id",
        "profile-match-input-json-v1",
        "private_floor_evidence_digest",
        "evidence_version_digest",
        "REVOKE ALL ON profile.derived_match_capture_receipts",
    ):
        assert fragment in sql
    lowered = sql.lower()
    for forbidden in (
        "execute format",
        "grant select on iam.",
        "grant execute on function iam_api.",
        "grant all",
        "to public",
        "uq_profile_derived_match_capture_workload",
        "receipt.workload_id = exact_workload_id;",
        "profile-derived-match-workload:",
    ):
        assert forbidden not in lowered
    derived_build = sql[sql.index("SELECT jsonb_build_object(") :]
    for forbidden_private_key in (
        "'minimum_project_amount_minor',",
        "'direct_cost_amount_minor',",
        "'organization_id', source",
        "'evidence_id', source",
        "'safe_object_reference',",
    ):
        assert forbidden_private_key not in derived_build


def test_profile5_repository_is_one_statement_profile() -> None:
    profile = CREATOR_PROFILE_POSTGRES_STATEMENT_PROFILES[
        CreatorProfilePostgresOperation.CAPTURE_DERIVED_MATCH_INPUTS
    ]
    assert profile.runtime_role == "profile_matcher"
    assert profile.statement_budget == 1
    assert profile.statement_names == (
        "discover_and_capture_derived_creator_match_inputs_v1",
    )
    assert len(profile.query_shape_sha256) == 64
