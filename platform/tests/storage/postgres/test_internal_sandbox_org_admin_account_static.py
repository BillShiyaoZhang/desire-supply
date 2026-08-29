from __future__ import annotations

import hashlib
from pathlib import Path
import unittest

from desire_platform.deployment.identity_bootstrap import _PROGRAM
from desire_platform.identity_access.adapters.postgres.migrations import (
    IAM_MIGRATION_LAYOUT,
    IAM_SCHEMA_HEAD_VERSION,
    MigrationPhase,
)


PLATFORM_ROOT = Path(__file__).resolve().parents[3]
MIGRATION_ROOT = (
    PLATFORM_ROOT
    / "src/desire_platform/identity_access/adapters/postgres/migrations"
)
MIGRATION_PATH = (
    MIGRATION_ROOT / "0033_expand__internal_sandbox_org_admin_account.sql"
)
TEMPLATE_PATH = (
    PLATFORM_ROOT
    / "examples/internal-sandbox-identity-bootstrap-template-v1.json"
)


class InternalSandboxOrgAdminAccountStaticTest(unittest.TestCase):
    def test_0033_remains_frozen_below_head_and_v6_is_the_callable_wrapper(self) -> None:
        self.assertGreaterEqual(IAM_SCHEMA_HEAD_VERSION, 36)
        self.assertEqual(
            IAM_MIGRATION_LAYOUT[33],
            (
                33,
                MigrationPhase.EXPAND,
                "internal_sandbox_org_admin_account",
                "0033_expand__internal_sandbox_org_admin_account.sql",
            ),
        )
        self.assertEqual(
            _PROGRAM,
            "iam_api.manage_internal_sandbox_identity_bootstrap_v6",
        )
        self.assertTrue(MIGRATION_PATH.is_file())
        self.assertTrue(TEMPLATE_PATH.is_file())
        self.assertNotEqual(
            hashlib.sha256(MIGRATION_PATH.read_bytes()).digest(),
            b"\x00" * 32,
        )

    def test_v4_closes_seven_account_org_admin_and_owner_marker_grant(self) -> None:
        sql = MIGRATION_PATH.read_text(encoding="utf-8")
        for marker in (
            "manage_internal_sandbox_identity_bootstrap_v4",
            "manage_internal_sandbox_identity_bootstrap_v1",
            "internal_sandbox_independent_role_graph_v4",
            "org_admin_01",
            "ORG_ADMIN",
            "BOOTSTRAP_ROLE_ISOLATION",
            "internal-sandbox-bootstrap-v4",
            "GRANT USAGE ON SCHEMA iam_api TO demand_schema_owner",
            "resolve_demand_owner_authority_marker_v1(",
            "TO demand_schema_owner",
            "REVOKE EXECUTE ON FUNCTION",
            "FROM iam_sandbox_bootstrap",
            "TO iam_sandbox_bootstrap",
            "SECURITY DEFINER",
            "SET search_path = pg_catalog, iam, infra, audit, iam_api",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, sql)
        self.assertNotIn("EXECUTE format", sql)
        self.assertNotIn("EXECUTE IMMEDIATE", sql)
        self.assertNotIn(
            "GRANT EXECUTE ON FUNCTION\n"
            "    iam_api.lock_demand_owner_authority_v1",
            sql,
        )


if __name__ == "__main__":
    unittest.main()
