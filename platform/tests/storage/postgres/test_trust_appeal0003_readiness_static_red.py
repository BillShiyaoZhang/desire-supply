from __future__ import annotations

import hashlib
from pathlib import Path

from desire_platform.trust_safety.adapters.postgres.migrations import (
    TRUST_MIGRATION_LAYOUT,
)


ROOT = Path(__file__).resolve().parents[3]
MIGRATIONS = (
    ROOT / "src/desire_platform/trust_safety/adapters/postgres/migrations"
)
TRUST0001 = MIGRATIONS / "0001_expand__demand_safety_case_v1.sql"
TRUST0002 = MIGRATIONS / "0002_expand__appeal_review_v1.sql"
TRUST0003 = MIGRATIONS / "0003_expand__appeal_runtime_policy_readiness_v1.sql"


def test_frozen_prefix_and_forward_only_readiness_layout() -> None:
    assert hashlib.sha256(TRUST0001.read_bytes()).hexdigest() == (
        "c4596cd745560fb4ff2e893def82a12da291f3860c363337a5b453afeeff46d4"
    )
    assert hashlib.sha256(TRUST0002.read_bytes()).hexdigest() == (
        "fee3eb63cc28277762a0a119b3905a3ca13021bae53e015333197f50bc256eb5"
    )
    assert TRUST_MIGRATION_LAYOUT[2] == (
        3,
        TRUST_MIGRATION_LAYOUT[2][1],
        "appeal_runtime_policy_readiness_v1",
        TRUST0003.name,
    )


def test_probe_is_single_fixed_read_only_security_definer_surface() -> None:
    sql = TRUST0003.read_text("utf-8")
    signature = (
        "trust_api.assert_appeal_runtime_policy_v1(\n"
        "    text, text[], text, text[], text, text, text[]\n"
        ")"
    )
    assert sql.count("CREATE FUNCTION ") == 1
    assert "CREATE TABLE " not in sql
    assert "CREATE VIEW " not in sql
    assert "CREATE TRIGGER " not in sql
    assert "SECURITY DEFINER" in sql
    assert "STABLE" in sql
    assert "PARALLEL RESTRICTED" in sql
    assert "SET search_path = pg_catalog, trust" in sql
    assert "RETURNS TABLE (ready boolean)" in sql
    assert "session_user IN ('trust_self', 'trust_appeal')" in sql
    assert "current_user = 'trust_schema_owner'" in sql
    assert "appeal-command-json-v1" in sql
    assert "APPEAL_RUNTIME_READINESS" in sql
    assert "TRUST_RUNTIME_READINESS" in sql
    assert "trust.appeal_receipt_key_policy" in sql
    assert "trust.sealed_text_key_policy" in sql
    assert f"REVOKE ALL ON FUNCTION {signature} FROM PUBLIC" in sql
    assert f"GRANT EXECUTE ON FUNCTION {signature} TO trust_self" in sql
    assert f"GRANT EXECUTE ON FUNCTION {signature} TO trust_appeal" in sql
    for forbidden in (
        "GRANT SELECT ON",
        "GRANT INSERT ON",
        "GRANT UPDATE ON",
        "GRANT DELETE ON",
        "TO trust_officer",
        "TO trust_decision",
    ):
        assert forbidden not in sql
