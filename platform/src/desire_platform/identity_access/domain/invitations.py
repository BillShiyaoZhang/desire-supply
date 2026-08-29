"""AccessInvitation target invariants and monotonic lifecycle."""

from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from enum import Enum
from typing import Optional

from .errors import IamError


class InvitationPurpose(str, Enum):
    CREATOR_ENROLLMENT = "CREATOR_ENROLLMENT"
    ORGANIZATION_MEMBERSHIP = "ORGANIZATION_MEMBERSHIP"


class InvitationStatus(str, Enum):
    ISSUED = "ISSUED"
    ACCEPTED = "ACCEPTED"
    REVOKED = "REVOKED"
    EXPIRED = "EXPIRED"


class TargetScope(str, Enum):
    USER = "USER"
    ORGANIZATION = "ORGANIZATION"


class TargetRole(str, Enum):
    CREATOR = "CREATOR"
    ORG_ADMIN = "ORG_ADMIN"
    DEMAND_OWNER = "DEMAND_OWNER"


@dataclass(frozen=True)
class InvitationBindingEvidence:
    invitation_id: str
    recipient_contact_id: str
    invitation_version: int


@dataclass(frozen=True)
class AccessInvitation:
    invitation_id: str
    purpose: InvitationPurpose
    target_scope: TargetScope
    target_role: TargetRole
    organization_id: Optional[str]
    is_initial_admin: bool
    recipient_contact_id: str
    issued_policy_bundle_id: str
    policy_selector_digest: str
    status: InvitationStatus
    expires_at: datetime
    aggregate_version: int
    created_at: Optional[datetime] = None
    masked_recipient_label: Optional[str] = None
    issuer_kind: Optional[str] = None
    issuer_id: Optional[str] = None
    nonce: Optional[str] = field(default=None, repr=False)
    token_key_id: Optional[str] = None
    token_format_version: Optional[str] = None
    updated_at: Optional[datetime] = None

    def __post_init__(self) -> None:
        creator_target = (
            self.purpose == InvitationPurpose.CREATOR_ENROLLMENT
            and self.target_scope == TargetScope.USER
            and self.target_role == TargetRole.CREATOR
            and self.organization_id is None
            and self.is_initial_admin is False
        )
        organization_target = (
            self.purpose == InvitationPurpose.ORGANIZATION_MEMBERSHIP
            and self.target_scope == TargetScope.ORGANIZATION
            and self.target_role in (TargetRole.ORG_ADMIN, TargetRole.DEMAND_OWNER)
            and bool(self.organization_id)
            and (
                not self.is_initial_admin
                or self.target_role == TargetRole.ORG_ADMIN
            )
        )
        if not (creator_target or organization_target):
            raise IamError("INVALID_INVITATION_TARGET")
        if self.aggregate_version < 1:
            raise IamError("INVALID_AGGREGATE_VERSION")
        _require_sha256(self.policy_selector_digest)
        _require_aware_utc(self.expires_at)
        if self.created_at is not None:
            _require_aware_utc(self.created_at)
            if self.created_at >= self.expires_at:
                raise IamError("INVALID_INVITATION_DEADLINE")
        if self.masked_recipient_label is not None and not (
            3 <= len(self.masked_recipient_label) <= 80
        ):
            raise IamError("INVALID_MASKED_RECIPIENT_LABEL")
        security_facts = (
            self.issuer_kind,
            self.issuer_id,
            self.nonce,
            self.token_key_id,
            self.token_format_version,
        )
        if any(value is not None for value in security_facts):
            if (
                self.issuer_kind not in ("SYSTEM", "USER")
                or not isinstance(self.issuer_id, str)
                or not self.issuer_id
                or not isinstance(self.nonce, str)
                or not self.nonce
                or not isinstance(self.token_key_id, str)
                or not self.token_key_id
                or not isinstance(self.token_format_version, str)
                or not self.token_format_version
                or self.created_at is None
            ):
                raise IamError("INVALID_INVITATION_SECURITY_FACTS")
        if self.updated_at is not None:
            _require_aware_utc(self.updated_at)
            if self.created_at is None or self.updated_at < self.created_at:
                raise IamError("INVALID_INVITATION_SERVER_TIME")

    def accept(
        self,
        *,
        now: datetime,
        expected_version: int,
        evidence: InvitationBindingEvidence,
    ) -> "AccessInvitation":
        self._require_current_issued(expected_version)
        _require_aware_utc(now)
        if now >= self.expires_at:
            raise IamError("ACCESS_INVITATION_EXPIRED")
        if (
            evidence.invitation_id != self.invitation_id
            or evidence.recipient_contact_id != self.recipient_contact_id
            or evidence.invitation_version != self.aggregate_version
        ):
            raise IamError("ACCESS_INVITATION_BINDING_MISMATCH")
        return self._transition(InvitationStatus.ACCEPTED)

    def revoke(self, *, now: datetime, expected_version: int) -> "AccessInvitation":
        self._require_current_issued(expected_version)
        _require_aware_utc(now)
        return self._transition(InvitationStatus.REVOKED)

    def expire(self, *, now: datetime, expected_version: int) -> "AccessInvitation":
        self._require_current_issued(expected_version)
        _require_aware_utc(now)
        if now < self.expires_at:
            raise IamError("ACCESS_INVITATION_NOT_EXPIRED")
        return self._transition(InvitationStatus.EXPIRED)

    def _require_current_issued(self, expected_version: int) -> None:
        if expected_version != self.aggregate_version:
            raise IamError("PRECONDITION_FAILED")
        if self.status != InvitationStatus.ISSUED:
            raise IamError("ACCESS_INVITATION_NOT_ISSUED")

    def _transition(self, status: InvitationStatus) -> "AccessInvitation":
        return replace(
            self,
            status=status,
            aggregate_version=self.aggregate_version + 1,
        )


def _require_aware_utc(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise IamError("INVALID_SERVER_TIME")


def _require_sha256(value: str) -> None:
    if not isinstance(value, str) or len(value) != 64 or any(
        character not in "0123456789abcdef" for character in value
    ):
        raise IamError("INVALID_CONTENT_HASH")
