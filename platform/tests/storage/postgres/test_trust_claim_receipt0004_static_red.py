from __future__ import annotations

import hashlib
from pathlib import Path

from desire_platform.trust_safety.adapters.postgres.migrations import (
    TRUST_MIGRATION_LAYOUT,
)


ROOT = Path(__file__).resolve().parents[3]
MIGRATIONS = ROOT / "src/desire_platform/trust_safety/adapters/postgres/migrations"
TRUST0001 = MIGRATIONS / "0001_expand__demand_safety_case_v1.sql"
TRUST0002 = MIGRATIONS / "0002_expand__appeal_review_v1.sql"
TRUST0003 = MIGRATIONS / "0003_expand__appeal_runtime_policy_readiness_v1.sql"
TRUST0004 = MIGRATIONS / "0004_expand__claim_receipt_http_status_v2.sql"


def _literal(sql: str, tag: str) -> str:
    marker = f"${tag}$"
    start = sql.index(marker) + len(marker)
    end = sql.index(marker, start)
    return sql[start:end]


def test_frozen_prefix_and_forward_only_claim_receipt_layout() -> None:
    assert hashlib.sha256(TRUST0001.read_bytes()).hexdigest() == (
        "c4596cd745560fb4ff2e893def82a12da291f3860c363337a5b453afeeff46d4"
    )
    assert hashlib.sha256(TRUST0002.read_bytes()).hexdigest() == (
        "fee3eb63cc28277762a0a119b3905a3ca13021bae53e015333197f50bc256eb5"
    )
    assert hashlib.sha256(TRUST0003.read_bytes()).hexdigest() == (
        "b1a8be2bef32686a46dd35f71adc4448521ada9fa6880331f73883dd60f72217"
    )
    assert TRUST_MIGRATION_LAYOUT[3] == (
        4,
        TRUST_MIGRATION_LAYOUT[3][1],
        "claim_receipt_http_status_v2",
        TRUST0004.name,
    )


def test_forward_reader_patches_exactly_two_frozen_0001_fragments() -> None:
    original_sql = TRUST0001.read_text("utf-8")
    forward_sql = TRUST0004.read_text("utf-8")
    old_case = _literal(forward_sql, "reader_old_status_case")
    new_case = _literal(forward_sql, "reader_new_status_case")
    old_guard = _literal(forward_sql, "reader_old_status_guard")
    new_guard = _literal(forward_sql, "reader_new_status_guard")
    assert original_sql.count(old_case) == 1
    assert original_sql.count(old_guard) == 1
    patched = original_sql.replace(old_case, new_case).replace(
        old_guard, new_guard
    )
    assert patched.count(new_case) == 1
    assert patched.count(new_guard) == 1
    assert patched.replace(new_case, old_case).replace(
        new_guard, old_guard
    ) == original_sql
    assert "pg_get_functiondef(" in forward_sql
    assert "reader_baseline_sha256 constant bytea" in forward_sql
    assert "sha256(convert_to(reader_definition, 'UTF8'))" in forward_sql
    assert (
        "46dd40efb9b41922a4febf4a089364de82704c56899781c537f95f918c225264"
        in forward_sql
    )
    assert "TRUST_RECEIPT_READER_BASELINE_MISMATCH" in forward_sql
    assert "EXECUTE reader_definition" in forward_sql
    assert forward_sql.count("aclexplode(") == 2
    assert forward_sql.count("count(DISTINCT privilege.grantee) = 3") == 2
    assert forward_sql.count("TRUST_RECEIPT_READER_ACL_BASELINE_MISMATCH") == 2


def test_claim_normalizer_is_narrow_and_acl_is_closed() -> None:
    sql = TRUST0004.read_text("utf-8")
    assert sql.count("CREATE FUNCTION ") == 1
    assert "BEFORE UPDATE ON trust.command_receipts" in sql
    assert "OLD.status = 'IN_PROGRESS'" in sql
    assert "NEW.status = 'COMPLETED'" in sql
    assert "NEW.response_http_status = 200" in sql
    assert "NEW.response_http_status := 201" in sql
    assert "NEW.command_name = 'CLAIM_CASE'" in sql
    assert "ARRAY['TrustCaseClaimed']::text[]" in sql
    assert "NEW.command_name = 'CLAIM_HOLD_RELEASE'" in sql
    assert "ARRAY['TrustHoldReleaseClaimed']::text[]" in sql
    assert "FROM PUBLIC" in sql
    assert "TO trust_self" in sql
    assert "TO trust_officer" in sql
    assert "TO trust_appeal" not in sql
    assert "TO trust_decision" not in sql
    assert "CREATE TABLE " not in sql
    assert "ALTER TABLE trust.command_receipts DISABLE TRIGGER" not in sql
