"""Static REDs for the independent Trust0001 PostgreSQL boundary.

These assertions intentionally stop before the still-unfrozen command
function signatures.  They pin the storage, role, RLS, receipt, audit, outbox,
and dependency surface that is independent of HTTP command-body decisions.
"""

from __future__ import annotations

from pathlib import Path
import re

from desire_platform.trust_safety.adapters.postgres.migrations import (
    TRUST_MIGRATION_LAYOUT,
    TRUST_REVIEWED_MANIFEST_SHA256,
    TrustMigrationCatalog,
)


MIGRATION_ROOT = (
    Path(__file__).resolve().parents[3]
    / "src/desire_platform/trust_safety/adapters/postgres/migrations"
)
MIGRATION = MIGRATION_ROOT / "0001_expand__demand_safety_case_v1.sql"


BUSINESS_TABLES = (
    "reports",
    "cases",
    "case_assignments",
    "case_assignment_releases",
    "triage_drafts",
    "triage_versions",
    "restricted_text_blobs",
    "safety_holds",
    "case_outcome_versions",
    "receipt_key_policy",
    "sealed_text_key_policy",
    "command_receipts",
)


def _sql() -> str:
    return MIGRATION.read_text(encoding="utf-8")


def test_actual_catalog_preserves_frozen_trust1_through_trust7_prefix() -> None:
    assert TRUST_MIGRATION_LAYOUT[:4] == (
        (
            1,
            TRUST_MIGRATION_LAYOUT[0][1],
            "demand_safety_case_v1",
            "0001_expand__demand_safety_case_v1.sql",
        ),
        (
            2,
            TRUST_MIGRATION_LAYOUT[1][1],
            "appeal_review_v1",
            "0002_expand__appeal_review_v1.sql",
        ),
        (
            3,
            TRUST_MIGRATION_LAYOUT[2][1],
            "appeal_runtime_policy_readiness_v1",
            "0003_expand__appeal_runtime_policy_readiness_v1.sql",
        ),
        (
            4,
            TRUST_MIGRATION_LAYOUT[3][1],
            "claim_receipt_http_status_v2",
            "0004_expand__claim_receipt_http_status_v2.sql",
        ),
    )
    assert TRUST_MIGRATION_LAYOUT[4] == (
        5,
        TRUST_MIGRATION_LAYOUT[4][1],
        "demand9_dependency_repin",
        "0005_expand__demand9_dependency_repin.sql",
    )
    assert TRUST_MIGRATION_LAYOUT[5] == (
        6,
        TRUST_MIGRATION_LAYOUT[5][1],
        "active_assignment_discovery",
        "0006_expand__active_assignment_discovery.sql",
    )
    assert TRUST_MIGRATION_LAYOUT[6] == (
        7,
        TRUST_MIGRATION_LAYOUT[6][1],
        "iam37_demand10_dependency_repin",
        "0007_expand__iam37_demand10_dependency_repin.sql",
    )
    catalog = TrustMigrationCatalog.load(MIGRATION_ROOT)
    assert tuple(item.descriptor.version for item in catalog.artifacts[:7]) == (
        1,
        2,
        3,
        4,
        5,
        6,
        7,
    )
    assert tuple(
        item.descriptor.prefix_manifest_sha256.hex()
        for item in catalog.artifacts[:7]
    ) == (
        "9bd2be5ccbf62824569b07505e53902e3775675cdfa684524d0ba503846a2c13",
        "94a1e604044ea60845c44d191cd75c9794cd19731f2b8a52e28547e7172ddf93",
        "141057a29520dd4027570dda20c95e305053bbb2bb6f8d5a145e5e5b2d8e4863",
        "4bd6f0e8367e7853adccc28cf868fda1b3cf00b678c252b1d1ae635b422837a8",
        "8b02df9ea6717265e3d69d22b837c9b5455ebab74cebe0c6a112d15de22b1c04",
        "05a731b5ce1418e444384b765a22874173e200c3d03005276b507802a9b38415",
        "27a51c55bddfcb2a4f1bd16a3160abbb3a417425f14077f4886c3c41c22d5124",
    )
    assert catalog.artifacts[0].descriptor.component == "trust"
    assert len(catalog.manifest_sha256) == 32
    assert catalog.manifest_sha256 == TRUST_REVIEWED_MANIFEST_SHA256


def test_roles_schemas_and_dependency_contract_are_closed() -> None:
    sql = _sql()
    for role in (
        "trust_schema_owner",
        "trust_migration_runner",
        "trust_self",
        "trust_officer",
        "trust_appeal",
        "trust_decision",
    ):
        assert role in sql
    assert "CREATE SCHEMA trust AUTHORIZATION trust_schema_owner" in sql
    assert "CREATE SCHEMA trust_meta AUTHORIZATION trust_schema_owner" in sql
    assert "CREATE SCHEMA trust_api AUTHORIZATION trust_schema_owner" in sql
    assert "required_iam_schema_version" in sql
    assert "required_demand_schema_version" in sql
    assert "required_iam_contract_sha256" in sql
    assert "required_demand_contract_sha256" in sql
    assert "required_iam_schema_version = 36" in sql
    assert "required_demand_schema_version = 8" in sql
    assert "REVOKE ALL ON SCHEMA trust, trust_meta, trust_api FROM PUBLIC" in sql


def test_all_business_tables_exist_with_force_rls_and_no_runtime_table_grants() -> None:
    sql = _sql()
    for table in BUSINESS_TABLES:
        assert f"CREATE TABLE trust.{table}" in sql
        assert f"ALTER TABLE trust.{table} ENABLE ROW LEVEL SECURITY" in sql
        assert f"ALTER TABLE trust.{table} FORCE ROW LEVEL SECURITY" in sql
    forbidden = re.compile(
        r"GRANT\s+(?:SELECT|INSERT|UPDATE|DELETE|ALL)[^;]*"
        r"ON\s+(?:TABLE\s+)?trust\.[a-z_]+[^;]*"
        r"TO\s+(?:trust_self|trust_officer|trust_appeal|trust_decision)",
        re.IGNORECASE | re.DOTALL,
    )
    assert forbidden.search(sql) is None
    assert "BYPASSRLS" not in sql


def test_sensitive_facts_are_sealed_and_absent_from_receipt_audit_outbox() -> None:
    sql = _sql()
    assert "CREATE TABLE trust.restricted_text_blobs" in sql
    assert "sealed_note_reference" in sql
    assert "sealed_note_sha256" in sql
    assert "encryption_key_id" in sql
    assert "encryption_nonce" in sql
    assert "ciphertext" in sql
    assert "plaintext_hmac_sha256" in sql
    assert "envelope_sha256" in sql
    assert "plaintext_sha256" not in sql
    assert "restricted_text_blobs_immutable" in sql
    assert "raw_note" not in sql
    assert "request_body" not in sql
    assert "reporter_user_id" in sql
    assert "safe_response" in sql
    assert "jsonb_has_exact_keys" in sql
    assert "GRANT INSERT ON audit.audit_events TO trust_schema_owner" in sql
    assert "GRANT INSERT ON infra.outbox_events TO trust_schema_owner" in sql
    assert "CREATE POLICY rls_trust_audit_insert" in sql
    assert "CREATE POLICY rls_trust_outbox_insert" in sql


def test_receipts_outcomes_and_holds_have_database_enforced_invariants() -> None:
    sql = _sql()
    for token in (
        "idempotency_key_digest_key_id",
        "idempotency_key_digest",
        "payload_hash_key_id",
        "payload_hash",
        "IN_PROGRESS",
        "COMPLETED",
        "ACTIVE",
        "RELEASED",
        "EXPIRED",
    ):
        assert token in sql
    assert "CONSTRAINT uq_trust_receipt_identity UNIQUE" in sql
    assert "receipt_key_policy" in sql
    assert "case_outcome_versions_immutable" in sql
    assert "independent" in sql.lower()
    assert "transaction_timestamp()" in sql


def test_hold_evaluation_is_one_exact_fixed_function_not_a_table_grant() -> None:
    sql = _sql()
    assert "CREATE FUNCTION trust_api.evaluate_demand_hold_v1(" in sql
    for argument in (
        "query_actor_id uuid",
        "query_organization_id uuid",
        "query_demand_id uuid",
        "query_prospective_aggregate_version bigint",
        "query_demand_version_id uuid",
        "query_content_sha256 bytea",
        "query_action text",
        "query_policy_version text",
    ):
        assert argument in sql
    assert "decision varchar" in sql
    assert "evidence_sha256 bytea" in sql
    assert "TO trust_decision" in sql


def test_authorized_reads_are_fixed_safe_projections() -> None:
    sql = _sql()
    for function_name in (
        "read_own_report_v1",
        "list_safety_case_queue_v1",
        "list_hold_release_queue_v1",
        "read_assigned_case_v1",
    ):
        assert f"CREATE FUNCTION trust_api.{function_name}(" in sql
    for operation in (
        "READ_OWN_REPORT",
        "LIST_CASE_QUEUE",
        "LIST_HOLD_RELEASE_QUEUE",
        "READ_ASSIGNED_CASE",
    ):
        assert operation in sql
    assert "iam_api.resolve_trust_reporter_authority_v1" in sql
    assert "iam_api.resolve_trust_officer_authority_v1" in sql
    read_start = sql.index("CREATE FUNCTION trust_api.read_own_report_v1(")
    read_end = sql.index(
        "REVOKE ALL ON FUNCTION trust_api.read_own_report_v1(",
        read_start,
    )
    assert "'reporter_user_id'" not in sql[read_start:read_end]


def test_runtime_key_readiness_is_fixed_and_policy_tables_remain_private() -> None:
    sql = _sql()
    start = sql.index(
        "CREATE FUNCTION trust_api.read_runtime_key_policy_v1()"
    )
    end = sql.index(
        "REVOKE ALL ON FUNCTION trust_api.read_runtime_key_policy_v1()",
        start,
    )
    body = sql[start:end]
    for column in (
        "active_idempotency_key_id",
        "retained_idempotency_key_ids",
        "active_payload_key_id",
        "retained_payload_key_ids",
        "active_canonicalization_version",
        "retained_canonicalization_versions",
        "active_sealed_text_key_id",
        "retained_sealed_text_key_ids",
    ):
        assert column in body
    assert "TRUST_RUNTIME_READINESS" in body
    assert "GRANT EXECUTE ON FUNCTION trust_api.read_runtime_key_policy_v1()" in sql


def test_outcome_evidence_source_is_safe_fixed_and_reproved_on_write() -> None:
    sql = _sql()
    start = sql.index(
        "CREATE FUNCTION trust_api.read_outcome_evidence_source_v1("
    )
    end = sql.index(
        "REVOKE ALL ON FUNCTION trust_api.read_outcome_evidence_source_v1(",
        start,
    )
    body = sql[start:end]
    assert "resolve_officer_authority_v1" in body
    assert "require_case_assignment_v1" in body
    assert "outcome_source_document_v1" in body
    for forbidden in (
        "sealed_note_reference",
        "sealed_note_sha256",
        "reporter_user_id",
        "issued_by_user_id",
    ):
        assert forbidden not in body
    publish_start = sql.index("CREATE FUNCTION trust_api.publish_outcome_v1(")
    publish_end = sql.index(
        "REVOKE ALL ON FUNCTION trust_api.publish_outcome_v1(", publish_start
    )
    publish = sql[publish_start:publish_end]
    assert "outcome_source_sha256_v1" in publish
    assert "outcome_evidence_packet_sha256_v1" in publish
    assert "evidence_valid_until IS DISTINCT FROM" in publish
    assert "evidence_evaluated_at + interval '5 minutes'" in publish
    assert "evidence_appeal_deadline IS DISTINCT FROM" in publish
    assert "evidence_evaluated_at + interval '7 days'" in publish


def test_nine_writes_have_closed_fixed_programs_and_shared_receipt_guard() -> None:
    sql = _sql()
    for function_name in (
        "submit_report_v1",
        "claim_case_v1",
        "release_case_assignment_v1",
        "save_triage_draft_v1",
        "publish_triage_v1",
        "place_hold_v1",
        "claim_hold_release_v1",
        "release_hold_v1",
        "publish_outcome_v1",
    ):
        assert f"CREATE FUNCTION trust_api.{function_name}(" in sql
    assert "CREATE FUNCTION trust.claim_or_replay_receipt_v1(" in sql
    assert "pg_advisory_xact_lock" in sql
    assert "retained_idempotency_key_ids" in sql
    assert "retained_payload_key_ids" in sql
    assert "execute_command" not in sql


def test_internal_completed_receipt_probe_is_closed_and_not_public() -> None:
    sql = _sql()
    start = sql.index(
        "CREATE FUNCTION trust_api.read_completed_command_receipt_v1("
    )
    end = sql.index(
        "REVOKE ALL ON FUNCTION trust_api.read_completed_command_receipt_v1(",
        start,
    )
    body = sql[start:end]
    for operation in (
        "SUBMIT_REPORT",
        "CLAIM_CASE",
        "RELEASE_CASE_ASSIGNMENT",
        "SAVE_TRIAGE_DRAFT",
        "PUBLISH_TRIAGE",
        "PLACE_HOLD",
        "CLAIM_HOLD_RELEASE",
        "RELEASE_HOLD",
        "PUBLISH_OUTCOME",
    ):
        assert operation in body
    assert body.index("resolve_officer_authority_v1") < body.index(
        "FROM trust.command_receipts"
    )
    assert body.index("resolve_trust_reporter_authority_v1") < body.index(
        "FROM trust.command_receipts"
    )
    assert "TRUST_RECEIPT_KEY_POLICY_UNAVAILABLE" in body
    assert "IDEMPOTENCY_KEY_REUSED" in body
    assert "COMMAND_OUTCOME_UNKNOWN" in body
    assert "GRANT EXECUTE ON FUNCTION trust_api.read_completed_command_receipt_v1" in sql
    grant_start = sql.index(
        "GRANT EXECUTE ON FUNCTION trust_api.read_completed_command_receipt_v1"
    )
    assert "TO trust_self, trust_officer" in sql[grant_start : grant_start + 500]


def test_current_authority_precedes_receipt_and_default_keys_are_active_only() -> None:
    sql = _sql()
    functions = (
        ("submit_report_v1", "resolve_trust_reporter_authority_v1"),
        ("claim_case_v1", "resolve_officer_authority_v1"),
        ("release_case_assignment_v1", "resolve_officer_authority_v1"),
        ("save_triage_draft_v1", "resolve_officer_authority_v1"),
        ("publish_triage_v1", "resolve_officer_authority_v1"),
        ("place_hold_v1", "resolve_officer_authority_v1"),
        ("claim_hold_release_v1", "resolve_officer_authority_v1"),
        ("release_hold_v1", "resolve_officer_authority_v1"),
        ("publish_outcome_v1", "resolve_officer_authority_v1"),
    )
    for function_name, authority_call in functions:
        start = sql.index(f"CREATE FUNCTION trust_api.{function_name}(")
        end = sql.index("$function$;", start)
        body = sql[start:end]
        assert body.index(authority_call) < body.index(
            "claim_or_replay_receipt_v1"
        )
    assert "ARRAY['trust-idempotency-2026-01']::text[]" in sql
    assert "ARRAY['trust-payload-2026-01']::text[]" in sql
    assert "trust-idempotency-retained-2025-12" not in sql
    assert "trust-payload-retained-2025-12" not in sql


def test_independent_hold_release_assignment_authorizes_case_read_only_while_live() -> None:
    sql = _sql()
    start = sql.index("CREATE FUNCTION trust_api.read_assigned_case_v1(")
    end = sql.index(
        "REVOKE ALL ON FUNCTION trust_api.read_assigned_case_v1(",
        start,
    )
    body = sql[start:end]
    for fact in (
        "assignment.assignment_purpose_code = 'HOLD_RELEASE'",
        "assigned_hold.release_assignment_id",
        "assignment.excluded_officer_user_id",
        "assignment.officer_user_id",
        "assignment.expires_at <= assigned_hold.expires_at",
        "assigned_hold.status = 'ACTIVE'",
        "release_record.assignment_id",
    ):
        assert fact in body
