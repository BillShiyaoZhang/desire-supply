"""Contract for ten isolated, fixed INTERNAL_SANDBOX login accounts."""

from __future__ import annotations

import json
from pathlib import Path

from desire_platform.deployment import identity_bootstrap
from desire_platform.synthetic_oidc import SYNTHETIC_ACCOUNTS


PLATFORM_ROOT = Path(__file__).resolve().parents[2]
TEMPLATE = (
    PLATFORM_ROOT
    / "examples/internal-sandbox-identity-bootstrap-template-v1.json"
)
IAM_MIGRATIONS = (
    PLATFORM_ROOT
    / "src/desire_platform/identity_access/adapters/postgres/migrations"
)

EXPECTED_IDENTITIES = (
    (
        "access_admin_01",
        "sandbox:access-admin-01",
        "sandbox-access-admin-01@example.test",
    ),
    (
        "appeal_reviewer_01",
        "sandbox:appeal-reviewer-01",
        "sandbox-appeal-reviewer-01@example.test",
    ),
    (
        "creator_01",
        "sandbox:creator-01",
        "sandbox-creator-01@example.test",
    ),
    (
        "demand_owner_01",
        "sandbox:demand-owner-01",
        "sandbox-demand-owner-01@example.test",
    ),
    (
        "finance_operator_01",
        "sandbox:finance-operator-01",
        "sandbox-finance-operator-01@example.test",
    ),
    (
        "finance_operator_02",
        "sandbox:finance-operator-02",
        "sandbox-finance-operator-02@example.test",
    ),
    (
        "operations_reviewer_01",
        "sandbox:operations-reviewer-01",
        "sandbox-operations-reviewer-01@example.test",
    ),
    (
        "org_admin_01",
        "sandbox:org-admin-01",
        "sandbox-org-admin-01@example.test",
    ),
    (
        "trust_officer_01",
        "sandbox:trust-officer-01",
        "sandbox-trust-officer-01@example.test",
    ),
    (
        "trust_officer_02",
        "sandbox:trust-officer-02",
        "sandbox-trust-officer-02@example.test",
    ),
)


def test_provider_exposes_exactly_ten_non_registerable_role_accounts() -> None:
    assert tuple(
        (account.account_code, account.subject, account.email)
        for account in SYNTHETIC_ACCOUNTS
    ) == EXPECTED_IDENTITIES


def test_bootstrap_template_has_one_intended_effective_role_per_account() -> None:
    document = json.loads(TEMPLATE.read_bytes())
    accounts = {account["account_code"]: account for account in document["accounts"]}
    assert tuple(sorted(accounts)) == tuple(sorted(row[0] for row in EXPECTED_IDENTITIES))

    assert accounts["creator_01"]["demand_owner_grant"] is None
    assert accounts["creator_01"]["platform_duty_grants"] == []

    assert accounts["demand_owner_01"]["demand_owner_grant"] is not None
    assert accounts["demand_owner_01"]["platform_duty_grants"] == []

    assert accounts["access_admin_01"]["demand_owner_grant"] is None
    assert [
        grant["duty_code"]
        for grant in accounts["access_admin_01"]["platform_duty_grants"]
    ] == ["ACCESS_ADMIN"]

    for account_code in ("finance_operator_01", "finance_operator_02"):
        assert accounts[account_code]["demand_owner_grant"] is None
        assert [
            grant["duty_code"]
            for grant in accounts[account_code]["platform_duty_grants"]
        ] == ["FINANCE_OPERATOR"]

    assert accounts["operations_reviewer_01"]["demand_owner_grant"] is None
    assert [
        grant["duty_code"]
        for grant in accounts["operations_reviewer_01"]["platform_duty_grants"]
    ] == ["OPERATIONS_REVIEWER"]

    for account_code in ("trust_officer_01", "trust_officer_02"):
        assert accounts[account_code]["demand_owner_grant"] is None
        assert [
            grant["duty_code"]
            for grant in accounts[account_code]["platform_duty_grants"]
        ] == ["TRUST_OFFICER"]

    assert accounts["appeal_reviewer_01"]["demand_owner_grant"] is None
    assert [
        grant["duty_code"]
        for grant in accounts["appeal_reviewer_01"]["platform_duty_grants"]
    ] == ["APPEAL_REVIEWER"]

    owner = accounts["demand_owner_01"]["demand_owner_grant"]
    org_admin = accounts["org_admin_01"]
    assert org_admin["demand_owner_grant"] is None
    assert org_admin["platform_duty_grants"] == []
    assert org_admin["organization_grant"]["role_code"] == "ORG_ADMIN"
    assert org_admin["organization_grant"]["organization_id"] == owner[
        "organization_id"
    ]
    assert {
        org_admin["organization_grant"][key]
        for key in ("grant_id", "invitation_id", "membership_id")
    }.isdisjoint(
        {
            owner[key]
            for key in ("grant_id", "invitation_id", "membership_id")
        }
    )


def test_online_bootstrap_invokes_forward_only_role_isolation_program() -> None:
    assert identity_bootstrap._PROGRAM == (
        "iam_api.manage_internal_sandbox_identity_bootstrap_v6"
    )
    migration = (
        IAM_MIGRATIONS
        / "0036_expand__trust_appeal_authority_and_current_logout.sql"
    ).read_text(encoding="utf-8")
    assert "manage_internal_sandbox_identity_bootstrap_v5" in migration
    assert "manage_internal_sandbox_identity_bootstrap_v4" in migration
    assert "BOOTSTRAP_ROLE_ISOLATION" in migration
    assert "creator_01" in migration
    assert "demand_owner_01" in migration
    assert "access_admin_01" in migration
    assert "operations_reviewer_01" in migration
    assert "finance_operator_01" in migration
    assert "finance_operator_02" in migration
    assert "org_admin_01" in migration
    assert "trust_officer_01" in migration
    assert "trust_officer_02" in migration
    assert "appeal_reviewer_01" in migration
    assert "ORG_ADMIN" in migration
    assert "TRUST_OFFICER" in migration
    assert "APPEAL_REVIEWER" in migration
