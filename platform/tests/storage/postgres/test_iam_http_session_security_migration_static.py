from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import unittest

from desire_platform.identity_access.adapters.postgres.migrations import (
    IAM_MIGRATION_LAYOUT,
    IAM_REVIEWED_MANIFEST_SHA256,
    IAM_SCHEMA_HEAD_VERSION,
    MigrationCatalog,
    MigrationPhase,
)


PLATFORM_ROOT = Path(__file__).resolve().parents[3]
MIGRATION_ROOT = (
    PLATFORM_ROOT
    / "src/desire_platform/identity_access/adapters/postgres/migrations"
)
MIGRATION_PATH = MIGRATION_ROOT / "0024_expand__http_session_security_v2.sql"
EXPECTED_0024_SQL_SHA256 = (
    "a8c11e0e9e3b48d8c3bebd5a69af66c703997882df85a97a2aec966f09cce2cb"
)
EXPECTED_0024_PREFIX_MANIFEST_SHA256 = (
    "475afb7278a051c2e1c1f0a2151471f6127af1c69d29e6bf3c3a166bcac8e6ae"
)


class IamHttpSessionSecurityMigrationStaticTest(unittest.TestCase):
    def test_0024_remains_the_reviewed_forward_only_prefix(self) -> None:
        catalog = MigrationCatalog.load(MIGRATION_ROOT)
        self.assertGreaterEqual(IAM_SCHEMA_HEAD_VERSION, 24)
        self.assertEqual(
            IAM_MIGRATION_LAYOUT[24],
            (
                24,
                MigrationPhase.EXPAND,
                "http_session_security_v2",
                "0024_expand__http_session_security_v2.sql",
            ),
        )
        self.assertEqual(catalog.artifacts[24].sql_bytes, MIGRATION_PATH.read_bytes())
        self.assertEqual(
            hashlib.sha256(MIGRATION_PATH.read_bytes()).hexdigest(),
            EXPECTED_0024_SQL_SHA256,
        )
        entries = json.loads(catalog.manifest_bytes.decode("ascii"))
        prefix = (
            json.dumps(entries[:25], ensure_ascii=True, separators=(",", ":"))
            .encode("ascii")
            + b"\n"
        )
        self.assertEqual(
            hashlib.sha256(prefix).hexdigest(),
            EXPECTED_0024_PREFIX_MANIFEST_SHA256,
        )
        self.assertEqual(IAM_REVIEWED_MANIFEST_SHA256, catalog.manifest_sha256)

    def test_replay_program_stays_invoker_bound_and_has_no_owner_policy(self) -> None:
        sql = MIGRATION_PATH.read_text(encoding="utf-8")
        program = _routine_body(sql, "iam_api.revoke_replayed_session_family_v1")
        self.assertIn("SECURITY INVOKER", program)
        self.assertNotIn("SECURITY DEFINER", sql)
        self.assertNotRegex(sql, r"FOR (?:SELECT|INSERT|UPDATE|ALL) TO schema_owner")
        self.assertIn("session_user <> 'iam_session_authenticator'", program)
        self.assertIn("current_user <> 'iam_session_authenticator'", program)
        self.assertIn("FOR UPDATE", program)
        self.assertNotIn("EXECUTE ", program)

    def test_rls_binds_marker_audit_and_outbox_to_the_persisted_graph(self) -> None:
        sql = MIGRATION_PATH.read_text(encoding="utf-8")
        required = (
            "iam.replayed_session_matches_family(session_family_id)",
            "replay_family.status = 'REVOKED'",
            "current_session.status = 'REVOKED'",
            "current_session.revocation_reason_code =\n"
            "              'REPLAYED_SESSION_HANDLE'",
            "(target_id, after_version) = (",
            "(aggregate_id, aggregate_version) = (",
            "event_id = NULLIF(\n"
            "        current_setting('app.audit_event_id', true)",
            "event_id = NULLIF(\n"
            "        current_setting('app.outbox_event_id', true)",
            "available_at = occurred_at",
            "created_at = occurred_at",
        )
        for marker in required:
            with self.subTest(marker=marker):
                self.assertIn(marker, sql)
        self.assertEqual(sql.count("FOR INSERT TO iam_session_authenticator"), 3)
        self.assertIn(
            "ALTER TABLE iam.session_security_events FORCE ROW LEVEL SECURITY",
            sql,
        )
        self.assertIn(
            "REVOKE ALL ON FUNCTION "
            "iam.reject_session_security_event_mutation()\n    FROM PUBLIC",
            sql,
        )

    def test_sql_has_balanced_dollar_blocks_quotes_comments_and_parentheses(self) -> None:
        sql = MIGRATION_PATH.read_text(encoding="utf-8")
        self.assertTrue(sql.endswith("\n"))
        self.assertFalse(sql.endswith("\n\n"))
        self.assertEqual(sql.count("$function$"), 4)
        _assert_lexically_balanced(sql)


def _routine_body(sql: str, name: str) -> str:
    match = re.search(
        r"CREATE FUNCTION "
        + re.escape(name)
        + r"\(.*?\n\$function\$;",
        sql,
        flags=re.DOTALL,
    )
    if match is None:
        raise AssertionError("reviewed replay routine is missing")
    return match.group(0)


def _assert_lexically_balanced(sql: str) -> None:
    index = 0
    parentheses = 0
    state = "normal"
    dollar_tag = ""
    while index < len(sql):
        current = sql[index]
        following = sql[index + 1] if index + 1 < len(sql) else ""
        if state == "line_comment":
            if current == "\n":
                state = "normal"
            index += 1
            continue
        if state == "block_comment":
            if current == "*" and following == "/":
                state = "normal"
                index += 2
            else:
                index += 1
            continue
        if state == "single_quote":
            if current == "'" and following == "'":
                index += 2
            elif current == "'":
                state = "normal"
                index += 1
            else:
                index += 1
            continue
        if state == "double_quote":
            if current == '"' and following == '"':
                index += 2
            elif current == '"':
                state = "normal"
                index += 1
            else:
                index += 1
            continue
        if state == "dollar_quote":
            if sql.startswith(dollar_tag, index):
                state = "normal"
                index += len(dollar_tag)
            else:
                index += 1
            continue

        if current == "-" and following == "-":
            state = "line_comment"
            index += 2
        elif current == "/" and following == "*":
            state = "block_comment"
            index += 2
        elif current == "'":
            state = "single_quote"
            index += 1
        elif current == '"':
            state = "double_quote"
            index += 1
        elif current == "$":
            match = re.match(r"\$[A-Za-z_][A-Za-z0-9_]*\$|\$\$", sql[index:])
            if match is None:
                index += 1
            else:
                dollar_tag = match.group(0)
                state = "dollar_quote"
                index += len(dollar_tag)
        elif current == "(":
            parentheses += 1
            index += 1
        elif current == ")":
            parentheses -= 1
            if parentheses < 0:
                raise AssertionError("SQL closes an unopened parenthesis")
            index += 1
        else:
            index += 1
    if state != "normal" or parentheses != 0:
        raise AssertionError(
            "SQL lexical state is unbalanced: %s/%d" % (state, parentheses)
        )


if __name__ == "__main__":
    unittest.main()
