from __future__ import annotations

import hashlib
import json
from pathlib import Path
import unittest

from desire_platform.deployment.identity_bootstrap import _PROGRAM
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
MIGRATION_PATH = (
    MIGRATION_ROOT
    / "0026_expand__internal_sandbox_independent_role_accounts.sql"
)
TEMPLATE_PATH = (
    PLATFORM_ROOT
    / "examples/internal-sandbox-identity-bootstrap-template-v1.json"
)
EXPECTED_SQL_SHA256 = (
    "88ce21f1928e7e988575c342697380001454d50ef2b24af7263674108aa44b21"
)
EXPECTED_MANIFEST_SHA256 = (
    "31fcd328c572f808f2863d789fabffeb6e2315d92d8fd5d076f22d331730ff6f"
)
EXPECTED_TEMPLATE_SHA256 = (
    "b7f5326f75f17eb97cec77d92f963fe6af6755a26a1acf7af8944f33ee6ba942"
)


class InternalSandboxIndependentRoleAccountsStaticTest(unittest.TestCase):
    def test_0026_is_digest_pinned_forward_only_prefix(self) -> None:
        catalog = MigrationCatalog.load(MIGRATION_ROOT)
        self.assertGreaterEqual(IAM_SCHEMA_HEAD_VERSION, 26)
        self.assertEqual(
            IAM_MIGRATION_LAYOUT[26],
            (
                26,
                MigrationPhase.EXPAND,
                "internal_sandbox_independent_role_accounts",
                "0026_expand__internal_sandbox_independent_role_accounts.sql",
            ),
        )
        self.assertEqual(
            hashlib.sha256(MIGRATION_PATH.read_bytes()).hexdigest(),
            EXPECTED_SQL_SHA256,
        )
        manifest = json.loads((MIGRATION_ROOT / "manifest.json").read_bytes())
        frozen_prefix = json.dumps(
            manifest[:27],
            ensure_ascii=True,
            separators=(",", ":"),
        ).encode("ascii") + b"\n"
        self.assertEqual(
            hashlib.sha256(frozen_prefix).hexdigest(),
            EXPECTED_MANIFEST_SHA256,
        )
        self.assertEqual(catalog.manifest_sha256, IAM_REVIEWED_MANIFEST_SHA256)
        self.assertEqual(
            hashlib.sha256(TEMPLATE_PATH.read_bytes()).hexdigest(),
            EXPECTED_TEMPLATE_SHA256,
        )

    def test_v2_closes_v1_and_isolates_exact_role_graph(self) -> None:
        sql = MIGRATION_PATH.read_text(encoding="utf-8")
        for marker in (
            "manage_internal_sandbox_identity_bootstrap_v2",
            "manage_internal_sandbox_identity_bootstrap_v1",
            "internal_sandbox_independent_role_graph_v2",
            "BOOTSTRAP_ROLE_ISOLATION",
            "app.bootstrap_role_isolation_transition",
            "access_admin_01",
            "creator_01",
            "demand_owner_01",
            "operations_reviewer_01",
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
        self.assertEqual(
            _PROGRAM,
            "iam_api.manage_internal_sandbox_identity_bootstrap_v6",
        )


if __name__ == "__main__":
    unittest.main()
