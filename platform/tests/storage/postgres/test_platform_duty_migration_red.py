from __future__ import annotations

from pathlib import Path
import unittest

from desire_platform.identity_access.adapters.postgres.migrations import (
    IAM_MIGRATION_LAYOUT,
    MigrationCatalog,
)


MIGRATION_ROOT = (
    Path(__file__).resolve().parents[3]
    / "src/desire_platform/identity_access/adapters/postgres/migrations"
)


class PlatformDutyMigrationRedTest(unittest.TestCase):
    def test_version_17_is_the_closed_platform_duty_expand_migration(self) -> None:
        self.assertEqual(
            IAM_MIGRATION_LAYOUT[17],
            (
                17,
                IAM_MIGRATION_LAYOUT[17][1].EXPAND,
                "platform_duty_grants",
                "0017_expand__platform_duty_grants.sql",
            ),
        )
        artifact = MigrationCatalog.load(MIGRATION_ROOT).artifacts[17]
        sql = artifact.sql_bytes.lower()
        for marker in (
            b"create table iam.platform_duty_grants",
            b"access_admin",
            b"operations_reviewer",
            b"finance_operator",
            b"trust_officer",
            b"appeal_reviewer",
            b"enable row level security",
            b"force row level security",
            b"ux_platform_duty_grant_active",
        ):
            self.assertIn(marker, sql)

    def test_platform_duty_table_is_time_bounded_and_fail_closed(self) -> None:
        sql = (MIGRATION_ROOT / "0017_expand__platform_duty_grants.sql").read_text()
        lowered = sql.lower()
        self.assertIn("expires_at", lowered)
        self.assertIn("revoked_at", lowered)
        self.assertIn("revocation_reason_code", lowered)
        self.assertIn("aggregate_version", lowered)
        self.assertIn("on delete restrict", lowered)
        self.assertIn("revoke all on table iam.platform_duty_grants from public", lowered)
        self.assertNotIn("password", lowered, "password storage does not belong in this slice")


if __name__ == "__main__":
    unittest.main()
