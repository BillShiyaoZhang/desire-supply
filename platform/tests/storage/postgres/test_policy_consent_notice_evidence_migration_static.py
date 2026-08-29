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
FROZEN_0014 = MIGRATION_ROOT / "0014_expand__policy_consent_self_uow.sql"
FROZEN_0028 = MIGRATION_ROOT / "0028_expand__policy_consent_oidc_time_evidence.sql"
MIGRATION = MIGRATION_ROOT / "0029_expand__policy_consent_notice_evidence.sql"
MANIFEST = MIGRATION_ROOT / "manifest.json"

EXPECTED_0014_SQL_SHA256 = (
    "79e6642f7f8200787cae7d7f73252b7fe732feb931604d65e3464cd2cf55481d"
)
EXPECTED_0028_SQL_SHA256 = (
    "8499f35ce44b52f7ee98c08712aef3a7b60e2c6784d4147efdbdc4e0b3076cde"
)
EXPECTED_0029_SQL_SHA256 = (
    "84998a1c42ab7ab5cc334fb31002be62d8d3cf4e936e91a891be49a217600bd3"
)
EXPECTED_0028_MANIFEST_PREFIX_SHA256 = (
    "66cbf070c12e62ddf92dad4b7f6da2284dc6037151075d7b2b7ef0497c20fce6"
)


def test_0029_is_forward_only_and_preserves_prior_migration_bytes() -> None:
    assert IAM_SCHEMA_HEAD_VERSION >= 29
    assert IAM_MIGRATION_LAYOUT[29] == (
        29,
        MigrationPhase.EXPAND,
        "policy_consent_notice_evidence",
        "0029_expand__policy_consent_notice_evidence.sql",
    )
    assert hashlib.sha256(FROZEN_0014.read_bytes()).hexdigest() == (
        EXPECTED_0014_SQL_SHA256
    )
    assert hashlib.sha256(FROZEN_0028.read_bytes()).hexdigest() == (
        EXPECTED_0028_SQL_SHA256
    )
    assert hashlib.sha256(MIGRATION.read_bytes()).hexdigest() == (
        EXPECTED_0029_SQL_SHA256
    )

    manifest = json.loads(MANIFEST.read_text(encoding="ascii"))
    frozen_prefix = json.dumps(
        manifest[:29],
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("ascii") + b"\n"
    assert hashlib.sha256(frozen_prefix).hexdigest() == (
        EXPECTED_0028_MANIFEST_PREFIX_SHA256
    )
    assert hashlib.sha256(MANIFEST.read_bytes()).digest() == (
        IAM_REVIEWED_MANIFEST_SHA256
    )


def test_0029_is_mechanical_0014_self_lock_with_one_closed_semantic_change() -> None:
    original = FROZEN_0014.read_text(encoding="utf-8")
    original_start = original.index("CREATE FUNCTION iam.lock_policy_consent_self_v1(")
    original_end = original.index("\n$function$;", original_start) + len(
        "\n$function$;"
    )
    expected = original[original_start:original_end]
    expected = expected.replace(
        "CREATE FUNCTION iam.lock_policy_consent_self_v1(",
        "CREATE OR REPLACE FUNCTION iam.lock_policy_consent_self_v1(",
        1,
    )
    expected = expected.replace(
        "                      AND source_document.legal_effect = "
        "'CONTRACT_ACCEPTANCE'",
        "                      AND source_document.legal_effect IN (\n"
        "                          'NOTICE_ACKNOWLEDGEMENT',\n"
        "                          'CONTRACT_ACCEPTANCE'\n"
        "                      )",
        1,
    )

    replacement = MIGRATION.read_text(encoding="utf-8")
    replacement_start = replacement.index(
        "CREATE OR REPLACE FUNCTION iam.lock_policy_consent_self_v1("
    )
    replacement_end = replacement.index(
        "\n$function$;", replacement_start
    ) + len("\n$function$;")

    assert replacement[replacement_start:replacement_end] == expected
    assert "NOTICE_ACKNOWLEDGEMENT" in expected
    assert "'CONTRACT_ACCEPTANCE'" in expected
    assert "CONSENT_TEXT remains outside this path" in replacement
    assert "TO iam_app" in replacement
