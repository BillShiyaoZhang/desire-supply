from __future__ import annotations

import hashlib
from pathlib import Path

from desire_platform.trust_safety.adapters.postgres.migrations import (
    TRUST_MIGRATION_LAYOUT,
    TRUST_REVIEWED_MANIFEST_SHA256,
    TRUST_SCHEMA_HEAD_VERSION,
    TrustMigrationCatalog,
    TrustMigrationPhase,
)


PLATFORM_ROOT = Path(__file__).resolve().parents[3]
MIGRATION_ROOT = (
    PLATFORM_ROOT
    / "src/desire_platform/trust_safety/adapters/postgres/migrations"
)
MIGRATION = (
    MIGRATION_ROOT
    / "0018_expand__completed_appeal_review_history.sql"
)

FROZEN_TRUST17_SQL_SHA256 = (
    "9ec66244773c7546537bb41a7c93c518f804947ddb88d8f14eb5e32e191b0854"
)
FROZEN_TRUST17_MANIFEST_SHA256 = (
    "57c0dd42e18bf3afa7233f9ad673ec3805b325166436a4a1e3021466cd62381f"
)
TRUST18_SQL_SHA256 = (
    "8623df4ffbd74f360a67fcc05a2a9d3966269458264b042ae10d6f1fd0784c0e"
)
TRUST18_MANIFEST_SHA256 = (
    "0b7028c75c8f137bc4a55a76fe73ea956d0c5ada13031f80794b77c1c9535e19"
)


def test_trust18_appends_after_the_byte_frozen_trust17_prefix() -> None:
    catalog = TrustMigrationCatalog.load(MIGRATION_ROOT)
    trust17 = catalog.artifacts[16].descriptor
    trust18 = catalog.artifacts[17].descriptor

    assert TRUST_SCHEMA_HEAD_VERSION >= 18
    assert TRUST_MIGRATION_LAYOUT[17] == (
        18,
        TrustMigrationPhase.EXPAND,
        "completed_appeal_review_history",
        MIGRATION.name,
    )
    assert trust17.checksum_sha256.hex() == FROZEN_TRUST17_SQL_SHA256
    assert (
        trust17.prefix_manifest_sha256.hex()
        == FROZEN_TRUST17_MANIFEST_SHA256
    )
    assert trust18.checksum_sha256.hex() == TRUST18_SQL_SHA256
    assert hashlib.sha256(MIGRATION.read_bytes()).digest() == (
        trust18.checksum_sha256
    )
    assert trust18.prefix_manifest_sha256.hex() == TRUST18_MANIFEST_SHA256
    assert catalog.manifest_sha256 == TRUST_REVIEWED_MANIFEST_SHA256
    assert catalog.manifest_sha256 != trust18.prefix_manifest_sha256


def test_trust18_history_is_actor_bound_bounded_and_deterministic() -> None:
    sql = MIGRATION.read_text(encoding="utf-8")

    for marker in (
        "CREATE FUNCTION trust_api.list_my_completed_appeal_reviews_v1(",
        "APPEAL_COMPLETED_HISTORY_READ",
        "'READ_ASSIGNED_APPEAL'",
        "decision.decided_by_user_id = exact_actor_user_id",
        "assignment.reviewer_user_id = exact_actor_user_id",
        "root.current_assignment_id = decision.source_assignment_id",
        "review.edited_by_user_id = exact_actor_user_id",
        "review.sealed_review_note_purpose_code = 'APPEAL_REVIEW_NOTE'",
        "btrim(review.sealed_review_note_reference) <> ''",
        "octet_length(review.sealed_review_note_sha256) = 32",
        "ORDER BY decision.decided_at DESC, decision.appeal_id DESC",
        "LIMIT exact_limit + 1",
        "ORDER BY decided_at DESC, appeal_id DESC",
        "'has_more', document.has_more",
        "GRANT EXECUTE ON FUNCTION trust_api.list_my_completed_appeal_reviews_v1(",
    ):
        assert marker in sql

    item_start = sql.index(
        "jsonb_build_object(\n"
        "                'appeal_id', decision.appeal_id"
    )
    item_end = sql.index(") AS item", item_start)
    item_projection = sql[item_start:item_end]
    assert set(("'appeal_id'", "'decided_at'", "'decision_code'")) == {
        line.strip().split(",")[0]
        for line in item_projection.splitlines()
        if line.strip().startswith("'")
    }
    for forbidden in (
        "applicant",
        "reviewer",
        "duty",
        "organization",
        "assignment",
        "sealed",
        "restricted",
        "assessments",
        "reason_codes",
    ):
        assert forbidden not in item_projection


def test_trust18_detail_projection_is_exact_and_party_safe() -> None:
    sql = MIGRATION.read_text(encoding="utf-8")
    function_start = sql.index(
        "CREATE FUNCTION trust_api.read_my_completed_appeal_review_v1("
    )
    projection_start = sql.index("SELECT jsonb_build_object(", function_start)
    projection_end = sql.index("\n    FROM trust.appeals", projection_start)
    projection = sql[projection_start:projection_end]

    for marker in (
        "'appeal_id', root.appeal_id",
        "'application', jsonb_build_object(",
        "'grounds', to_jsonb(application.grounds)",
        "'new_evidence_reference_ids'",
        "'requested_outcome', application.requested_outcome",
        "'statement_recorded', true",
        "'submitted_at', application.submitted_at",
        "'decision', jsonb_build_object(",
        "'assessments', decision.assessments",
        "'decided_at', decision.decided_at",
        "'decision_code', decision.decision_code",
        "'decision_sha256', encode(decision.decision_sha256, 'hex')",
        "'decision_version_id', decision.decision_version_id",
        "'policy_version', decision.policy_version",
        "'reason_codes', to_jsonb(decision.reason_codes)",
        "'remedy_delta_codes', to_jsonb(decision.remedy_delta_codes)",
        "'entity_tag', trust.appeal_entity_tag_v1(",
        "'review_note_recorded', true",
        "'status', root.status",
    ):
        assert marker in projection

    for forbidden in (
        "aggregate_version',",
        "applicant",
        "reviewer",
        "duty_grant",
        "organization",
        "assignment_id",
        "sealed_review_note",
        "sealed_statement",
        "restricted_text",
        "source_case_id",
        "source_outcome",
    ):
        assert forbidden not in projection

    function = sql[function_start:]
    for marker in (
        "APPEAL_COMPLETED_DETAIL_READ",
        "root.status = 'DECIDED'",
        "decision.decided_by_user_id = exact_actor_user_id",
        "assignment.reviewer_user_id = exact_actor_user_id",
        "review.edited_by_user_id = exact_actor_user_id",
        "review.sealed_review_note_purpose_code = 'APPEAL_REVIEW_NOTE'",
        "GRANT EXECUTE ON FUNCTION trust_api.read_my_completed_appeal_review_v1(",
    ):
        assert marker in function


def test_trust18_policies_and_functions_are_closed_to_the_runtime_role() -> None:
    sql = MIGRATION.read_text(encoding="utf-8")

    for policy in (
        "rls_trust_my_completed_appeal_assignments_select_v1",
        "rls_trust_my_completed_appeal_roots_select_v1",
        "rls_trust_my_completed_appeal_decisions_select_v1",
        "rls_trust_my_completed_appeal_applications_select_v1",
        "rls_trust_my_completed_appeal_review_drafts_select_v1",
    ):
        assert f"CREATE POLICY {policy}" in sql

    assert sql.count("FOR SELECT TO trust_schema_owner") == 5
    assert sql.count("session_user = 'trust_appeal'") == 5
    assert sql.count("current_user = 'trust_schema_owner'") >= 5
    assert "GRANT SELECT" not in sql
    assert "TO PUBLIC" not in sql
    assert sql.count("FROM PUBLIC") == 2
    assert sql.count("TO trust_appeal") == 2


def test_trust18_preserves_exact_prior_baseline_and_advances_only_trust_head() -> None:
    sql = MIGRATION.read_text(encoding="utf-8")

    for marker in (
        "TRUST17_SCHEMA_CONTRACT_BASELINE_MISMATCH",
        "contract_count NOT BETWEEN 0 AND 1",
        "contract_count = 1 AND contract_is_exact IS NOT TRUE",
        "schema_head_version = 17",
        "min_app_compatible_version = 17",
        "max_app_compatible_version = 17",
        "schema_head_version = 18",
        "min_app_compatible_version = 18",
        "max_app_compatible_version = 18",
        "required_iam_schema_version = 42",
        "required_demand_schema_version = 12",
        "a1ec68f0d0e6685e0cbe842a6bd951f60f334682d26bec549ef9858c81f23d67",
        FROZEN_TRUST17_MANIFEST_SHA256,
        "desire:trust:combined-contract:v2",
    ):
        assert marker in sql

    assert sql.count("DELETE FROM trust_meta.schema_contracts") == 1
    assert sql.count("DROP CONSTRAINT ck_trust_schema_contract_versions") == 1
    assert sql.count("DROP CONSTRAINT ck_trust_schema_contract_hashes") == 1
