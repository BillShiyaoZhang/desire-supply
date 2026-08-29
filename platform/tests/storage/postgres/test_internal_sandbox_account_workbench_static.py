from __future__ import annotations

import hashlib
import json
from pathlib import Path

from desire_platform.identity_access.adapters.postgres.migrations import (
    IAM_MIGRATION_LAYOUT,
    IAM_REVIEWED_MANIFEST_SHA256,
    IAM_SCHEMA_HEAD_VERSION,
    MigrationPhase,
)


ROOT = Path(__file__).resolve().parents[3]
MIGRATION = (
    ROOT
    / "src/desire_platform/identity_access/adapters/postgres/migrations"
    / "0027_expand__internal_sandbox_account_workbench.sql"
)
MANIFEST = MIGRATION.parent / "manifest.json"
EXPECTED_SQL_SHA256 = (
    "b27c12bdaa9d3844f6f4b00e18cc2473cb50683f2eaf6afbf1a3ab9b29550e7f"
)
EXPECTED_MANIFEST_SHA256 = (
    "8cc1475d02a9d5205faa5b6cbd5b78b91bf376a0dcc5de26551a6a6f95a83913"
)


def test_0027_is_forward_only_account_workbench_boundary() -> None:
    assert IAM_SCHEMA_HEAD_VERSION >= 27
    assert IAM_MIGRATION_LAYOUT[27] == (
        27,
        MigrationPhase.EXPAND,
        "internal_sandbox_account_workbench",
        "0027_expand__internal_sandbox_account_workbench.sql",
    )
    assert hashlib.sha256(MIGRATION.read_bytes()).hexdigest() == EXPECTED_SQL_SHA256
    manifest = json.loads(MANIFEST.read_text(encoding="ascii"))
    frozen_prefix = json.dumps(
        manifest[:28],
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("ascii") + b"\n"
    assert hashlib.sha256(frozen_prefix).hexdigest() == EXPECTED_MANIFEST_SHA256
    assert hashlib.sha256(MANIFEST.read_bytes()).digest() == (
        IAM_REVIEWED_MANIFEST_SHA256
    )
    sql = MIGRATION.read_text(encoding="utf-8")
    for marker in (
        "INTERNAL_SANDBOX_ACCOUNT_ADMIN_READ",
        "LIST_ACCOUNTS",
        "GET_ACCOUNT",
        "iam_api.read_internal_sandbox_account_workbench_v1",
        "rls_sandbox_account_workbench_bootstrap_accounts",
        "rls_sandbox_account_workbench_users",
        "rls_sandbox_account_workbench_sessions",
        "rls_sandbox_account_workbench_duties",
        "session_user = 'iam_app'",
        "current_setting('transaction_read_only') = 'on'",
        "current_setting('transaction_isolation') = 'repeatable read'",
        "duty_code = 'ACCESS_ADMIN'",
        "BETWEEN 1 AND 16",
        "GRANT EXECUTE ON FUNCTION",
        "TO iam_app",
        "SECURITY DEFINER",
    ):
        assert marker in sql
    for forbidden in (
        "contact_points",
        "external_identities",
        "subject_digest",
        "current_recipient_binding_digest",
        "GRANT SELECT ON",
        "EXECUTE format",
        "EXECUTE IMMEDIATE",
    ):
        assert forbidden not in sql
