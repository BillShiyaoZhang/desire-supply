from __future__ import annotations

import hashlib
from pathlib import Path

from desire_platform.trust_safety.adapters.postgres.migrations import (
    TRUST_SCHEMA_HEAD_VERSION,
    TrustMigrationCatalog,
)


PLATFORM_ROOT = Path(__file__).resolve().parents[3]
MIGRATION_ROOT = (
    PLATFORM_ROOT
    / "src/desire_platform/trust_safety/adapters/postgres/migrations"
)
MIGRATION = MIGRATION_ROOT / "0009_expand__owned_report_discovery.sql"
FROZEN_TRUST_API_CONTRACT_SHA256 = (
    "a9923573365f1023aff3e4aaebb0b7e656c80eab7e721bbf30d9e9b038782f25"
)


def _function(sql: str) -> str:
    start = sql.index("CREATE FUNCTION trust_api.list_own_reports_v1(")
    end = sql.index(
        "REVOKE ALL ON FUNCTION trust_api.list_own_reports_v1(", start
    )
    return sql[start:end]


def test_trust9_catalog_and_contract_pins_are_byte_exact() -> None:
    catalog = TrustMigrationCatalog.load(MIGRATION_ROOT)
    descriptor = catalog.artifacts[8].descriptor

    assert TRUST_SCHEMA_HEAD_VERSION >= 9
    assert descriptor.version == 9
    assert descriptor.name == "owned_report_discovery"
    assert descriptor.relative_path == MIGRATION.name
    assert descriptor.checksum_sha256.hex() == (
        "6cbab8db4ccbb5c9fe2a5b5af161327289da80a3de4c159407de9f1cb13093db"
    )
    assert hashlib.sha256(MIGRATION.read_bytes()).digest() == (
        descriptor.checksum_sha256
    )
    assert descriptor.prefix_manifest_sha256.hex() == (
        "8ef9c2321866e7509bf1a959acf64370fe74abb927635c0434618287a4348171"
    )
    assert FROZEN_TRUST_API_CONTRACT_SHA256 in MIGRATION.read_text("utf-8")


def test_program_authorizes_reporter_and_org_before_any_report_scan() -> None:
    body = _function(MIGRATION.read_text(encoding="utf-8"))
    authority = body.index("iam_api.resolve_trust_reporter_authority_v1")
    first_report_scan = body.index("FROM trust.reports AS cursor_report")

    assert "session_user IS DISTINCT FROM 'trust_self'" in body
    assert "current_user IS DISTINCT FROM 'trust_schema_owner'" in body
    assert "authority.role_code = 'DEMAND_OWNER'" in body
    assert "authority.organization_id = query_organization_id" in body
    assert "authority.actor_user_id = query_actor_user_id" in body
    assert authority < first_report_scan
    assert "cursor_report.reporter_user_id = query_actor_user_id" in body
    assert "report.reporter_user_id = query_actor_user_id" in body
    assert "report.organization_id = query_organization_id" in body
    assert "query_cursor_created_at IS NULL" in body
    assert "query_cursor_report_id IS NULL" in body


def test_program_uses_stable_limit_plus_one_keyset_and_minimal_projection() -> None:
    sql = MIGRATION.read_text(encoding="utf-8")
    body = _function(sql)
    item_start = body.index("jsonb_build_object(\n                'category'")
    item_end = body.index(") AS item", item_start)
    item_projection = body[item_start:item_end]

    assert "ORDER BY report.created_at DESC, report.report_id" in body
    assert "report.created_at < query_cursor_created_at" in body
    assert "report.report_id > query_cursor_report_id" in body
    assert "LIMIT query_limit + 1" in body
    assert "WHERE ordinal <= query_limit" in body
    assert "WHERE ordinal > query_limit" in body
    for safe_key in (
        "'category'",
        "'demand_id'",
        "'outcome'",
        "'report_id'",
        "'status'",
        "'submitted_at'",
        "'appeal_deadline'",
        "'appeal_eligibility_code'",
        "'decided_at'",
        "'outcome_code'",
        "'outcome_version_id'",
    ):
        assert safe_key in item_projection
    for sensitive_key in (
        "'reporter_user_id'",
        "'impact_codes'",
        "'evidence_reference_ids'",
        "'reason_codes'",
        "'action_codes'",
        "'content_sha256'",
        "'source_digest'",
        "'policy_version'",
        "'decided_by_user_id'",
    ):
        assert sensitive_key not in item_projection
    assert "GRANT EXECUTE ON FUNCTION trust_api.list_own_reports_v1(" in sql
    assert ") TO trust_self;" in sql
    assert "schema_head_version = 9" in sql
    assert FROZEN_TRUST_API_CONTRACT_SHA256 in sql
