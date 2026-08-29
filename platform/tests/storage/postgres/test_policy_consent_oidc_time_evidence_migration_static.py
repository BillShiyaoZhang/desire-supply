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
MIGRATION_ROOT = (
    ROOT / "src/desire_platform/identity_access/adapters/postgres/migrations"
)
MIGRATION = MIGRATION_ROOT / "0028_expand__policy_consent_oidc_time_evidence.sql"
FROZEN_0014 = MIGRATION_ROOT / "0014_expand__policy_consent_self_uow.sql"
MANIFEST = MIGRATION_ROOT / "manifest.json"

EXPECTED_0014_SQL_SHA256 = (
    "79e6642f7f8200787cae7d7f73252b7fe732feb931604d65e3464cd2cf55481d"
)
EXPECTED_0028_SQL_SHA256 = (
    "8499f35ce44b52f7ee98c08712aef3a7b60e2c6784d4147efdbdc4e0b3076cde"
)
EXPECTED_0027_MANIFEST_PREFIX_SHA256 = (
    "8cc1475d02a9d5205faa5b6cbd5b78b91bf376a0dcc5de26551a6a6f95a83913"
)


def test_0028_is_forward_only_and_preserves_frozen_0014_bytes() -> None:
    assert IAM_SCHEMA_HEAD_VERSION >= 28
    assert IAM_MIGRATION_LAYOUT[28] == (
        28,
        MigrationPhase.EXPAND,
        "policy_consent_oidc_time_evidence",
        "0028_expand__policy_consent_oidc_time_evidence.sql",
    )
    assert hashlib.sha256(FROZEN_0014.read_bytes()).hexdigest() == (
        EXPECTED_0014_SQL_SHA256
    )
    assert hashlib.sha256(MIGRATION.read_bytes()).hexdigest() == (
        EXPECTED_0028_SQL_SHA256
    )

    manifest = json.loads(MANIFEST.read_text(encoding="ascii"))
    frozen_prefix = json.dumps(
        manifest[:28],
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("ascii") + b"\n"
    assert hashlib.sha256(frozen_prefix).hexdigest() == (
        EXPECTED_0027_MANIFEST_PREFIX_SHA256
    )
    assert hashlib.sha256(MANIFEST.read_bytes()).digest() == (
        IAM_REVIEWED_MANIFEST_SHA256
    )


def test_0028_keeps_exact_principal_graph_and_uses_ordered_oidc_time() -> None:
    sql = MIGRATION.read_text(encoding="utf-8")
    for marker in (
        "CREATE OR REPLACE FUNCTION iam.lock_policy_consent_principal_v1",
        "session_user IS DISTINCT FROM 'iam_app'",
        "locked_family.current_generation <> locked_session.generation",
        "locked_session.auth_transaction_id <> exact_auth_transaction_id",
        "locked_auth.status <> 'SUCCEEDED'",
        "locked_auth.purpose NOT IN ('LOGIN', 'STEP_UP')",
        "locked_auth.expected_user_id NOT IN (exact_actor_user_id)",
        "locked_auth.created_at > locked_auth.succeeded_at",
        "locked_auth.succeeded_at > locked_auth.deadline",
        "locked_auth.succeeded_at > transaction_timestamp()",
        "locked_auth.succeeded_at > locked_session.created_at",
        "locked_session.auth_time > locked_auth.succeeded_at",
        "CONSTRAINT = 'ck_policy_consent_principal_active'",
        "TO iam_app",
    ):
        assert marker in sql
    for forbidden in (
        "locked_auth.succeeded_at IS DISTINCT FROM locked_session.auth_time",
        "locked_auth.deadline <= transaction_timestamp()",
    ):
        assert forbidden not in sql
