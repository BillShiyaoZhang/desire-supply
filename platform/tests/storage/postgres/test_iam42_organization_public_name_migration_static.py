"""Static closure checks for the forward-only IAM42 migration."""

from __future__ import annotations

from pathlib import Path
import re
import unittest

from desire_platform.deployment import identity_bootstrap


PLATFORM_ROOT = Path(__file__).resolve().parents[3]
IAM42 = (
    PLATFORM_ROOT
    / "src/desire_platform/identity_access/adapters/postgres/migrations/"
    "0042_expand__organization_public_name_management.sql"
)


class Iam42OrganizationPublicNameMigrationStaticTest(unittest.TestCase):
    def test_v3_is_v2_abi_plus_one_final_text_and_closes_v2(self) -> None:
        sql = IAM42.read_text(encoding="utf-8")
        signature = re.search(
            r"CREATE FUNCTION iam_api\.execute_organization_admin_v3\((.*?)\)"
            r"\nRETURNS jsonb",
            sql,
            flags=re.DOTALL,
        )
        self.assertIsNotNone(signature)
        parameters = re.findall(
            r"^\s{4}(exact_[a-z0-9_]+|new_[a-z0-9_]+)\s+([^,\n]+),?$",
            signature.group(1),
            flags=re.MULTILINE,
        )
        self.assertEqual(len(parameters), 51)
        self.assertEqual(parameters[-1], ("exact_public_name", "text"))
        self.assertIn("result := iam_api.execute_organization_admin_v2(", sql)
        self.assertIn("IF exact_public_name IS NOT NULL THEN", sql)
        self.assertIn(
            "REVOKE EXECUTE ON FUNCTION iam_api.execute_organization_admin_v2(",
            sql,
        )
        self.assertIn(
            "GRANT EXECUTE ON FUNCTION iam_api.execute_organization_admin_v3(",
            sql,
        )

    def test_new_branch_is_atomic_digest_only_and_six_command_unique(self) -> None:
        sql = IAM42.read_text(encoding="utf-8")
        for marker in (
            "uq_org_admin_raw_idempotency_key_v1",
            "UpdateOrganizationPublicName",
            "PUBLIC_NAME_CORRECTION",
            "OrganizationSummaryDto",
            "OrganizationPublicNameChanged",
            "'decision_code','PRECONDITION_FAILED'",
            "'current_entity_tag'",
            "INSERT INTO infra.command_receipts",
            "INSERT INTO audit.audit_events",
            "INSERT INTO infra.outbox_events",
            "UPDATE infra.command_receipts",
            "iam.organization_public_name_is_canonical_v1",
            "codepoint.value BETWEEN 2192 AND 2193",
            "codepoint.value BETWEEN 78896 AND 78911",
            "GRANT EXECUTE ON FUNCTION iam.organization_public_name_is_canonical_v1(text)\nTO iam_app, iam_onboarding, iam_system",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, sql)
        payload = re.search(
            r"event_payload := jsonb_build_object\((.*?)\);",
            sql,
            flags=re.DOTALL,
        )
        self.assertIsNotNone(payload)
        self.assertEqual(
            re.findall(r"'([a-z_]+)'", payload.group(1)),
            ["organization_id"],
        )
        self.assertNotIn("EXECUTE format", sql)
        self.assertNotIn("EXECUTE IMMEDIATE", sql)

    def test_bootstrap_v6_restores_names_and_is_the_only_callable_head(self) -> None:
        sql = IAM42.read_text(encoding="utf-8")
        self.assertEqual(
            identity_bootstrap._PROGRAM,
            "iam_api.manage_internal_sandbox_identity_bootstrap_v6",
        )
        for marker in (
            "manage_internal_sandbox_identity_bootstrap_v6",
            "manage_internal_sandbox_identity_bootstrap_v5",
            "app.bootstrap_public_name_compat",
            "saved_names",
            "ck_internal_sandbox_identity_bootstrap_v6_restore",
            "REVOKE EXECUTE ON FUNCTION iam_api.manage_internal_sandbox_identity_bootstrap_v5",
            "GRANT EXECUTE ON FUNCTION iam_api.manage_internal_sandbox_identity_bootstrap_v6",
            "IF session_user = 'iam_sandbox_bootstrap'\n       AND current_user = 'schema_owner' THEN\n        IF iam.internal_sandbox_bootstrap_context_v1()",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, sql)


if __name__ == "__main__":
    unittest.main()
