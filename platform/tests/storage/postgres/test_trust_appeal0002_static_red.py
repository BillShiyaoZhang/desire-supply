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
APPEAL0002 = MIGRATIONS / "0002_expand__appeal_review_v1.sql"


FIXED_FUNCTIONS = {
    "open_appeal_v1": 15,
    "save_appeal_draft_v1": 20,
    "submit_appeal_v1": 16,
    "claim_appeal_v1": 15,
    "release_appeal_assignment_v1": 15,
    "save_appeal_review_draft_v1": 19,
    "decide_appeal_v1": 17,
    "read_completed_appeal_receipt_v1": 10,
    "store_appeal_restricted_text_v1": 19,
    "find_own_appeal_by_source_v1": 4,
    "read_own_appeal_v1": 4,
    "list_appeal_queue_v1": 3,
    "read_assigned_appeal_v1": 3,
}


def test_trust0001_bytes_remain_frozen_and_appeal_is_exact_prefix_two():
    assert hashlib.sha256(TRUST0001.read_bytes()).hexdigest() == (
        "c4596cd745560fb4ff2e893def82a12da291f3860c363337a5b453afeeff46d4"
    )
    assert TRUST_MIGRATION_LAYOUT[:2] == (
        (1, TRUST_MIGRATION_LAYOUT[0][1], "demand_safety_case_v1", TRUST0001.name),
        (2, TRUST_MIGRATION_LAYOUT[1][1], "appeal_review_v1", APPEAL0002.name),
    )


def test_appeal0002_declares_only_closed_fixed_programs_and_storage():
    sql = APPEAL0002.read_text("utf-8")
    for function, argument_count in FIXED_FUNCTIONS.items():
        declaration = f"CREATE FUNCTION trust_api.{function}("
        assert declaration in sql
        body = sql.split(declaration, 1)[1].split(")\nRETURNS", 1)[0]
        assert body.count("\n    exact_") == argument_count
    for table in (
        "appeals",
        "appeal_application_drafts",
        "appeal_application_versions",
        "appeal_review_assignments",
        "appeal_assignment_releases",
        "appeal_review_drafts",
        "appeal_decision_versions",
        "appeal_command_receipts",
    ):
        assert f"CREATE TABLE trust.{table}" in sql
        assert f"ALTER TABLE trust.{table} ENABLE ROW LEVEL SECURITY" in sql
        assert f"ALTER TABLE trust.{table} FORCE ROW LEVEL SECURITY" in sql
    assert "APPEAL_STATEMENT" in sql
    assert "APPEAL_REVIEW_NOTE" in sql
    assert "APPLICATION_STATEMENT" not in sql
    assert "REVIEW_NOTE'" not in sql.replace("APPEAL_REVIEW_NOTE'", "")


def test_appeal0002_acl_is_function_only_and_role_split():
    sql = APPEAL0002.read_text("utf-8")
    assert "GRANT SELECT ON trust." not in sql
    assert "GRANT INSERT ON trust." not in sql
    assert "GRANT UPDATE ON trust." not in sql
    assert "GRANT DELETE ON trust." not in sql
    assert "TO trust_self, trust_appeal" not in sql
    assert "FROM PUBLIC" in sql
