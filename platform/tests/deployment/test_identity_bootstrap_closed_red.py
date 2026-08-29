"""Closed manifest and deployment-source tests for sandbox identity bootstrap."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import unittest

from desire_platform.deployment.identity_bootstrap import (
    IdentityBootstrapConfigurationError,
    parse_internal_sandbox_identity_manifest,
)
from tests.support.identity_bootstrap_builders import (
    canonical_manifest,
    identity_bootstrap_document,
)


class IdentityBootstrapClosedTest(unittest.TestCase):
    def test_manifest_is_canonical_digest_only_and_has_ten_isolated_accounts(self) -> None:
        raw, digest = canonical_manifest(identity_bootstrap_document())
        manifest = parse_internal_sandbox_identity_manifest(
            raw,
            expected_sha256=digest,
            expected_issuer="https://id.example.test",
        )

        self.assertEqual(manifest.revision, 1)
        self.assertEqual(len(manifest.accounts), 10)
        self.assertEqual(
            {account.effective_role_code for account in manifest.accounts},
            {
                "ACCESS_ADMIN",
                "CREATOR",
                "DEMAND_OWNER",
                "FINANCE_OPERATOR",
                "OPERATIONS_REVIEWER",
                "ORG_ADMIN",
                "TRUST_OFFICER",
                "APPEAL_REVIEWER",
            },
        )
        self.assertEqual(
            {duty for account in manifest.accounts for duty in account.duty_codes},
            {
                "ACCESS_ADMIN",
                "FINANCE_OPERATOR",
                "OPERATIONS_REVIEWER",
                "TRUST_OFFICER",
                "APPEAL_REVIEWER",
            },
        )
        self.assertTrue(any(account.has_demand_owner for account in manifest.accounts))
        org_admin = next(
            account for account in manifest.accounts
            if account.account_code == "org_admin_01"
        )
        demand_owner = next(
            account for account in manifest.accounts
            if account.account_code == "demand_owner_01"
        )
        self.assertEqual(org_admin.organization_role_codes, ("ORG_ADMIN",))
        self.assertEqual(org_admin.organization_id, demand_owner.organization_id)
        self.assertFalse(org_admin.has_demand_owner)
        self.assertEqual(org_admin.duty_codes, ())
        for raw_identifier in (b"@", b"synthetic-subject", b"synthetic-recipient"):
            self.assertNotIn(raw_identifier, raw)
        self.assertNotIn(raw.decode(), repr(manifest))

    def test_manifest_rejects_hash_mismatch_noncanonical_unknown_and_digest_collision(self) -> None:
        document = identity_bootstrap_document()
        raw, digest = canonical_manifest(document)
        cases = []
        cases.append((raw, "0" * 64, "IDENTITY_BOOTSTRAP_MANIFEST_DIGEST_MISMATCH"))
        cases.append((json.dumps(document, indent=2).encode(), hashlib.sha256(json.dumps(document, indent=2).encode()).hexdigest(), "IDENTITY_BOOTSTRAP_MANIFEST_NOT_CANONICAL"))
        unknown = copy.deepcopy(document)
        unknown["raw_subject"] = "human@example.test"
        unknown_raw, unknown_digest = canonical_manifest(unknown)
        cases.append((unknown_raw, unknown_digest, "IDENTITY_BOOTSTRAP_CONFIGURATION_INVALID"))
        collision = copy.deepcopy(document)
        collision["accounts"][1]["external_identity"]["subject_digest_sha256"] = collision["accounts"][0]["external_identity"]["subject_digest_sha256"]
        collision_raw, collision_digest = canonical_manifest(collision)
        cases.append((collision_raw, collision_digest, "IDENTITY_BOOTSTRAP_SUBJECT_DIGEST_COLLISION"))
        for candidate, expected, code in cases:
            with self.subTest(code=code):
                with self.assertRaises(IdentityBootstrapConfigurationError) as caught:
                    parse_internal_sandbox_identity_manifest(
                        candidate,
                        expected_sha256=expected,
                    )
                self.assertEqual(caught.exception.code, code)

    def test_manifest_rejects_different_org_extra_role_or_duty_and_id_collision(self) -> None:
        cases = []
        different_org = identity_bootstrap_document()
        next(
            account
            for account in different_org["accounts"]
            if account["account_code"] == "org_admin_01"
        )["organization_grant"][
            "organization_id"
        ] = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        cases.append(different_org)

        extra_duty = identity_bootstrap_document()
        next(
            account
            for account in extra_duty["accounts"]
            if account["account_code"] == "org_admin_01"
        )["platform_duty_grants"] = [
            {
                "duty_code": "ACCESS_ADMIN",
                "grant_id": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
            }
        ]
        cases.append(extra_duty)

        extra_role = identity_bootstrap_document()
        next(
            account
            for account in extra_role["accounts"]
            if account["account_code"] == "org_admin_01"
        )["organization_grant"][
            "role_code"
        ] = "DEMAND_OWNER"
        cases.append(extra_role)

        collision = identity_bootstrap_document()
        next(
            account
            for account in collision["accounts"]
            if account["account_code"] == "org_admin_01"
        )["organization_grant"][
            "grant_id"
        ] = collision["accounts"][0]["user_id"]
        cases.append(collision)

        for document in cases:
            raw, digest = canonical_manifest(document)
            with self.assertRaises(IdentityBootstrapConfigurationError):
                parse_internal_sandbox_identity_manifest(
                    raw,
                    expected_sha256=digest,
                )

    def test_deployment_source_has_no_raw_active_identity_seed_sql(self) -> None:
        deployment_root = Path(__file__).resolve().parents[2] / "src" / "desire_platform" / "deployment"
        combined = "\n".join(
            path.read_text(encoding="utf-8").lower()
            for path in deployment_root.glob("*.py")
        )
        for forbidden in (
            "insert into iam.users",
            "insert into iam.external_identities",
            "insert into iam.user_role_grants",
            "alter role iam_sandbox_bootstrap password '",
        ):
            self.assertNotIn(forbidden, combined)


if __name__ == "__main__":
    unittest.main()
