from __future__ import annotations

from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta, timezone
import unittest

from desire_platform.identity_access.domain.errors import IamError
from desire_platform.identity_access.domain.platform_duties import (
    PLATFORM_DUTY_CODES,
    PlatformDutyCode,
    PlatformDutyGrant,
)


NOW = datetime(2026, 8, 12, 9, 0, tzinfo=timezone.utc)


class PlatformDutyGrantDomainRedTest(unittest.TestCase):
    def test_platform_duty_vocabulary_is_closed_and_distinct_from_org_roles(self) -> None:
        self.assertEqual(
            tuple(code.value for code in PlatformDutyCode),
            (
                "ACCESS_ADMIN",
                "OPERATIONS_REVIEWER",
                "FINANCE_OPERATOR",
                "TRUST_OFFICER",
                "APPEAL_REVIEWER",
            ),
        )
        self.assertEqual(
            PLATFORM_DUTY_CODES,
            frozenset(code.value for code in PlatformDutyCode),
        )
        self.assertTrue(
            PLATFORM_DUTY_CODES.isdisjoint({"CREATOR", "ORG_ADMIN", "DEMAND_OWNER"})
        )

    def test_grant_is_immutable_time_bounded_and_active_only_inside_its_window(self) -> None:
        grant = PlatformDutyGrant(
            platform_duty_grant_id="platform_duty_grant_0001",
            user_id="user_operator_000001",
            duty_code=PlatformDutyCode.OPERATIONS_REVIEWER,
            granted_by_kind="USER",
            granted_by_id="user_access_admin_001",
            granted_at=NOW - timedelta(days=1),
            expires_at=NOW + timedelta(days=30),
            revoked_at=None,
            revocation_reason_code=None,
            aggregate_version=1,
        )

        self.assertTrue(grant.is_active_at(NOW))
        self.assertFalse(grant.is_active_at(grant.expires_at))
        with self.assertRaises(FrozenInstanceError):
            grant.aggregate_version = 2

    def test_revoked_grant_is_inactive_and_requires_closed_reason_shape(self) -> None:
        grant = PlatformDutyGrant(
            platform_duty_grant_id="platform_duty_grant_0002",
            user_id="user_finance_0000001",
            duty_code=PlatformDutyCode.FINANCE_OPERATOR,
            granted_by_kind="SYSTEM",
            granted_by_id="system_bootstrap_0001",
            granted_at=NOW - timedelta(days=2),
            expires_at=None,
            revoked_at=NOW - timedelta(days=1),
            revocation_reason_code="ROTATED_DUTY",
            aggregate_version=2,
        )
        self.assertFalse(grant.is_active_at(NOW))

        with self.assertRaises(IamError) as raised:
            PlatformDutyGrant(
                platform_duty_grant_id="platform_duty_grant_0003",
                user_id="user_finance_0000001",
                duty_code=PlatformDutyCode.FINANCE_OPERATOR,
                granted_by_kind="SYSTEM",
                granted_by_id="system_bootstrap_0001",
                granted_at=NOW,
                expires_at=None,
                revoked_at=NOW,
                revocation_reason_code=None,
                aggregate_version=2,
            )
        self.assertEqual(raised.exception.code, "INVALID_PLATFORM_DUTY_GRANT")

    def test_non_utc_or_empty_authority_coordinates_are_rejected(self) -> None:
        invalid = (
            {"granted_at": NOW.replace(tzinfo=None)},
            {"expires_at": NOW - timedelta(seconds=1)},
            {"platform_duty_grant_id": ""},
            {"user_id": ""},
            {"granted_by_kind": "ORG_ADMIN"},
            {"aggregate_version": 0},
        )
        base = {
            "platform_duty_grant_id": "platform_duty_grant_0004",
            "user_id": "user_trust_000000001",
            "duty_code": PlatformDutyCode.TRUST_OFFICER,
            "granted_by_kind": "USER",
            "granted_by_id": "user_access_admin_001",
            "granted_at": NOW,
            "expires_at": None,
            "revoked_at": None,
            "revocation_reason_code": None,
            "aggregate_version": 1,
        }
        for override in invalid:
            with self.subTest(override=override), self.assertRaises(IamError) as raised:
                PlatformDutyGrant(**dict(base, **override))
            self.assertEqual(raised.exception.code, "INVALID_PLATFORM_DUTY_GRANT")


if __name__ == "__main__":
    unittest.main()
