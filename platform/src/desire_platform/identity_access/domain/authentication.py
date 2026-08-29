"""Closed authentication facts for the OIDC and BFF Session protocol.

This module intentionally owns only immutable value shapes in the RED slice.
State transitions remain default-deny until the application semantics are
implemented against the frozen authentication design.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from enum import Enum
from typing import Optional, Tuple

from .errors import IamError


class AuthPurpose(str, Enum):
    LOGIN = "LOGIN"
    ENROLLMENT = "ENROLLMENT"
    STEP_UP = "STEP_UP"


class AuthTransactionStatus(str, Enum):
    PENDING = "PENDING"
    EXCHANGING = "EXCHANGING"
    SUCCEEDED = "SUCCEEDED"
    RESULT_UNKNOWN = "RESULT_UNKNOWN"
    FAILED = "FAILED"


class ProviderErrorClass(str, Enum):
    REJECTED = "REJECTED"
    RESULT_UNKNOWN = "RESULT_UNKNOWN"
    MANUAL_REVIEW = "MANUAL_REVIEW"
    MISCONFIGURED = "MISCONFIGURED"


class SessionStatus(str, Enum):
    ACTIVE = "ACTIVE"
    REVOKED = "REVOKED"
    EXPIRED = "EXPIRED"


@dataclass(frozen=True)
class AuthTransaction:
    auth_transaction_id: str
    status: AuthTransactionStatus
    purpose: AuthPurpose
    browser_binding_digest: str = field(repr=False)
    browser_binding_digest_key_id: str
    initiating_session_id: Optional[str]
    initiating_user_id: Optional[str]
    expected_user_id: Optional[str]
    invitation_id: Optional[str]
    invitation_version: Optional[int]
    expected_contact_point_id: Optional[str]
    expected_contact_type: Optional[str]
    expected_contact_binding_digest: Optional[str] = field(repr=False)
    expected_contact_binding_digest_key_id: Optional[str]
    state_digest: str = field(repr=False)
    state_digest_key_id: str
    nonce_digest: str = field(repr=False)
    nonce_ciphertext: str = field(repr=False)
    nonce_encryption_key_id: str
    pkce_verifier_ciphertext: str = field(repr=False)
    pkce_encryption_key_id: str
    pkce_code_challenge: str
    pkce_code_challenge_method: str
    provider_issuer: str
    provider_audience: str
    redirect_uri: str
    return_to: str
    security_policy_version: str
    deadline: datetime
    attempt: int
    exchange_owner_id: Optional[str]
    exchange_claimed_at: Optional[datetime]
    provider_error_class: Optional[ProviderErrorClass]
    aggregate_version: int
    created_at: datetime
    updated_at: datetime

    def claim_exchange(
        self,
        *,
        owner_id: str,
        now: datetime,
    ) -> "AuthTransaction":
        _require_utc(now)
        if (
            self.status != AuthTransactionStatus.PENDING
            or self.aggregate_version != 1
            or self.attempt != 0
            or self.exchange_owner_id is not None
            or self.exchange_claimed_at is not None
            or not owner_id
            or now >= self.deadline
        ):
            raise IamError("AUTH_TRANSACTION_INVALID")
        return replace(
            self,
            status=AuthTransactionStatus.EXCHANGING,
            attempt=1,
            exchange_owner_id=owner_id,
            exchange_claimed_at=now,
            aggregate_version=2,
            updated_at=now,
        )

    def succeed(self, *, now: datetime) -> "AuthTransaction":
        self._require_exchanging(now)
        return replace(
            self,
            status=AuthTransactionStatus.SUCCEEDED,
            provider_error_class=None,
            aggregate_version=3,
            updated_at=now,
        )

    def fail(
        self,
        *,
        error_class: ProviderErrorClass,
        now: datetime,
    ) -> "AuthTransaction":
        _require_utc(now)
        if self.status not in (
            AuthTransactionStatus.PENDING,
            AuthTransactionStatus.EXCHANGING,
        ):
            raise IamError("AUTH_TRANSACTION_INVALID")
        if (
            self.status == AuthTransactionStatus.PENDING
            and self.aggregate_version != 1
        ) or (
            self.status == AuthTransactionStatus.EXCHANGING
            and self.aggregate_version != 2
        ):
            raise IamError("AUTH_TRANSACTION_INVALID")
        if error_class == ProviderErrorClass.RESULT_UNKNOWN:
            raise IamError("AUTH_TRANSACTION_INVALID")
        return replace(
            self,
            status=AuthTransactionStatus.FAILED,
            provider_error_class=error_class,
            aggregate_version=self.aggregate_version + 1,
            updated_at=now,
        )

    def mark_result_unknown(self, *, now: datetime) -> "AuthTransaction":
        self._require_exchanging(now, allow_expired=True)
        return replace(
            self,
            status=AuthTransactionStatus.RESULT_UNKNOWN,
            provider_error_class=ProviderErrorClass.RESULT_UNKNOWN,
            aggregate_version=3,
            updated_at=now,
        )

    def _require_exchanging(
        self,
        now: datetime,
        *,
        allow_expired: bool = False,
    ) -> None:
        _require_utc(now)
        if (
            self.status != AuthTransactionStatus.EXCHANGING
            or self.aggregate_version != 2
            or self.attempt != 1
            or not self.exchange_owner_id
            or self.exchange_claimed_at is None
            or (not allow_expired and now >= self.deadline)
        ):
            raise IamError("AUTH_TRANSACTION_INVALID")


@dataclass(frozen=True)
class SessionFamily:
    session_family_id: str
    user_id: str
    status: SessionStatus
    current_generation: int
    aggregate_version: int
    revoked_at: Optional[datetime]
    revocation_reason_code: Optional[str]


@dataclass(frozen=True)
class BffSession:
    session_id: str
    session_family_id: str
    user_id: str
    generation: int
    predecessor_session_id: Optional[str]
    status: SessionStatus
    verified_contact_point_id: Optional[str]
    verified_for_invitation_id: Optional[str]
    verified_at: Optional[datetime]
    auth_transaction_id: str
    auth_time: datetime
    acr_code: str
    amr_codes: Tuple[str, ...]
    created_at: datetime
    last_activity_at: datetime
    idle_expires_at: datetime
    absolute_expires_at: datetime
    updated_at: datetime
    handle_digest: str = field(repr=False)
    handle_digest_key_id: str
    csrf_salt: bytes = field(repr=False)
    csrf_key_id: str
    csrf_digest: str = field(repr=False)
    rotation_reason: str
    aggregate_version: int


def _require_utc(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise IamError("AUTH_TRANSACTION_INVALID")
