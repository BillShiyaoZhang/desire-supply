"""Closed platform-duty authority facts for the internal pilot.

Platform duties are deliberately separate from account roles and organization
membership roles.  A duty authorizes a narrow platform responsibility; the
downstream bounded context must still require an exact assignment and conflict
attestation for the concrete object being handled.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
import re
from typing import FrozenSet, Optional

from .errors import IamError


class PlatformDutyCode(str, Enum):
    ACCESS_ADMIN = "ACCESS_ADMIN"
    OPERATIONS_REVIEWER = "OPERATIONS_REVIEWER"
    FINANCE_OPERATOR = "FINANCE_OPERATOR"
    TRUST_OFFICER = "TRUST_OFFICER"
    APPEAL_REVIEWER = "APPEAL_REVIEWER"


PLATFORM_DUTY_CODES: FrozenSet[str] = frozenset(
    code.value for code in PlatformDutyCode
)
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{15,127}$")
_REASON_CODE = re.compile(r"^[A-Z][A-Z0-9_]{2,63}$")


@dataclass(frozen=True)
class PlatformDutyGrant:
    platform_duty_grant_id: str
    user_id: str
    duty_code: PlatformDutyCode
    granted_by_kind: str
    granted_by_id: str
    granted_at: datetime
    expires_at: Optional[datetime]
    revoked_at: Optional[datetime]
    revocation_reason_code: Optional[str]
    aggregate_version: int

    def __post_init__(self) -> None:
        identifiers = (
            self.platform_duty_grant_id,
            self.user_id,
            self.granted_by_id,
        )
        valid = (
            all(isinstance(value, str) and _IDENTIFIER.fullmatch(value) for value in identifiers)
            and isinstance(self.duty_code, PlatformDutyCode)
            and self.granted_by_kind in {"USER", "SYSTEM"}
            and _is_utc(self.granted_at)
            and isinstance(self.aggregate_version, int)
            and not isinstance(self.aggregate_version, bool)
            and self.aggregate_version >= 1
        )
        if self.expires_at is not None:
            valid = valid and _is_utc(self.expires_at) and self.expires_at > self.granted_at
        if self.revoked_at is None:
            valid = valid and self.revocation_reason_code is None
        else:
            valid = (
                valid
                and _is_utc(self.revoked_at)
                and self.revoked_at >= self.granted_at
                and isinstance(self.revocation_reason_code, str)
                and _REASON_CODE.fullmatch(self.revocation_reason_code) is not None
            )
        if not valid:
            raise IamError("INVALID_PLATFORM_DUTY_GRANT")

    def is_active_at(self, now: datetime) -> bool:
        if not _is_utc(now):
            raise IamError("INVALID_PLATFORM_DUTY_GRANT")
        return (
            self.revoked_at is None
            and self.granted_at <= now
            and (self.expires_at is None or now < self.expires_at)
        )


def _is_utc(value: object) -> bool:
    return (
        isinstance(value, datetime)
        and value.tzinfo is not None
        and value.utcoffset() == timedelta(0)
    )


__all__ = ["PLATFORM_DUTY_CODES", "PlatformDutyCode", "PlatformDutyGrant"]
