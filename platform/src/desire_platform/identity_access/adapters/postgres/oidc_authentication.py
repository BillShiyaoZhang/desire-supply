"""PostgreSQL 18 fixed programs for OIDC AuthTransaction and BFF Session.

This boundary persists only keyed digests, encrypted protocol evidence, and
verified subject digests.  It never accepts an authorization code, provider
token, raw subject, raw state/browser cookie, or raw Session handle.

The production slice finalizes LOGIN for an already provisioned ACTIVE
external identity and invitation-bound STEP_UP for that same active User.
Anonymous ENROLLMENT is open only when the transaction freezes one exact
Invitation version and EMAIL recipient binding.  It creates no Membership or
Role authority; those remain owned by invitation acceptance.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import hmac
import re
from typing import Any, Callable, Optional, Sequence, Tuple, TypeVar, Union
from urllib.parse import urlsplit
from uuid import UUID

from psycopg.pq import TransactionStatus

from ...domain.authentication import AuthTransactionStatus
from ...domain.errors import IamError


_KEY_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{1,63}$")
_POLICY_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{1,63}$")
_ACR = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
_AMR = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")
_T = TypeVar("_T")


class OidcPostgresPurpose(str, Enum):
    LOGIN = "LOGIN"
    ENROLLMENT = "ENROLLMENT"
    STEP_UP = "STEP_UP"


class OidcPostgresTerminalOutcome(str, Enum):
    REJECTED = "REJECTED"
    MISCONFIGURED = "MISCONFIGURED"
    RESULT_UNKNOWN = "RESULT_UNKNOWN"


@dataclass(frozen=True)
class OidcPostgresBeginRequest:
    auth_transaction_id: UUID
    purpose: OidcPostgresPurpose
    browser_binding_digest: bytes = field(repr=False)
    browser_binding_key_id: str
    initiating_session_id: Optional[UUID]
    initiating_user_id: Optional[UUID]
    expected_user_id: Optional[UUID]
    invitation_id: Optional[UUID]
    invitation_version: Optional[int]
    expected_contact_point_id: Optional[UUID]
    expected_contact_type: Optional[str]
    expected_contact_binding_digest: Optional[bytes] = field(repr=False)
    expected_contact_binding_key_id: Optional[str]
    state_digest: bytes = field(repr=False)
    state_digest_key_id: str
    nonce_digest: bytes = field(repr=False)
    nonce_digest_key_id: str
    nonce_ciphertext: bytes = field(repr=False)
    nonce_encryption_key_id: str
    pkce_verifier_ciphertext: bytes = field(repr=False)
    pkce_encryption_key_id: str
    pkce_code_challenge: str
    provider_issuer: str
    provider_audience: str
    redirect_uri: str
    return_to: str
    security_policy_version: str
    audit_event_id: UUID
    system_actor_id: UUID
    correlation_id: UUID
    trace_id: UUID

    def __post_init__(self) -> None:
        for label, value in (
            ("auth transaction", self.auth_transaction_id),
            ("audit event", self.audit_event_id),
            ("system actor", self.system_actor_id),
            ("correlation", self.correlation_id),
            ("trace", self.trace_id),
        ):
            _require_uuid(value, label)
        if len(
            {
                self.auth_transaction_id,
                self.audit_event_id,
                self.correlation_id,
                self.trace_id,
            }
        ) != 4:
            raise ValueError("OIDC begin generated IDs must be distinct")
        if not isinstance(self.purpose, OidcPostgresPurpose):
            raise ValueError("OIDC purpose is not closed")
        for label, value in (
            ("browser binding digest", self.browser_binding_digest),
            ("state digest", self.state_digest),
            ("nonce digest", self.nonce_digest),
        ):
            _require_digest(value, label)
        for label, value in (
            ("browser binding key", self.browser_binding_key_id),
            ("state digest key", self.state_digest_key_id),
            ("nonce digest key", self.nonce_digest_key_id),
            ("nonce encryption key", self.nonce_encryption_key_id),
            ("PKCE encryption key", self.pkce_encryption_key_id),
        ):
            _require_key_id(value, label)
        _require_ciphertext(self.nonce_ciphertext, "nonce")
        _require_ciphertext(self.pkce_verifier_ciphertext, "PKCE verifier")
        if (
            not isinstance(self.pkce_code_challenge, str)
            or not 43 <= len(self.pkce_code_challenge) <= 128
            or re.fullmatch(r"[A-Za-z0-9_-]+", self.pkce_code_challenge) is None
        ):
            raise ValueError("PKCE challenge is invalid")
        _require_https_url(self.provider_issuer, "provider issuer")
        if (
            not isinstance(self.provider_audience, str)
            or not self.provider_audience
            or len(self.provider_audience) > 512
        ):
            raise ValueError("provider audience is invalid")
        _require_https_url(self.redirect_uri, "OIDC redirect URI")
        if (
            not isinstance(self.return_to, str)
            or not self.return_to.startswith("/")
            or self.return_to.startswith("//")
            or len(self.return_to) > 2048
        ):
            raise ValueError("OIDC return_to is invalid")
        if (
            not isinstance(self.security_policy_version, str)
            or _POLICY_VERSION.fullmatch(self.security_policy_version) is None
        ):
            raise ValueError("OIDC security policy version is invalid")
        self._validate_purpose_shape()

    def _validate_purpose_shape(self) -> None:
        invitation_values = (
            self.invitation_id,
            self.invitation_version,
            self.expected_contact_point_id,
            self.expected_contact_type,
            self.expected_contact_binding_digest,
            self.expected_contact_binding_key_id,
        )
        if self.purpose is OidcPostgresPurpose.LOGIN:
            if any(value is not None for value in invitation_values):
                raise ValueError("LOGIN cannot bind invitation authority")
            if (self.initiating_session_id is None) != (
                self.initiating_user_id is None
            ):
                raise ValueError("LOGIN initiating Session/User shape is invalid")
            if self.initiating_session_id is None:
                if self.expected_user_id is not None:
                    raise ValueError("anonymous LOGIN cannot select an expected User")
            else:
                _require_uuid(self.initiating_user_id, "initiating user")
                _require_uuid(self.expected_user_id, "expected user")
                if self.expected_user_id != self.initiating_user_id:
                    raise ValueError("current LOGIN expected User must be the initiator")
        elif self.purpose is OidcPostgresPurpose.ENROLLMENT or (
            self.purpose is OidcPostgresPurpose.STEP_UP
            and any(value is not None for value in invitation_values)
        ):
            _require_uuid(self.invitation_id, "invitation")
            _require_uuid(self.expected_contact_point_id, "expected contact")
            if (
                not isinstance(self.invitation_version, int)
                or isinstance(self.invitation_version, bool)
                or self.invitation_version < 1
                or self.expected_contact_type not in ("EMAIL", "PHONE")
            ):
                raise ValueError("OIDC invitation evidence is invalid")
            _require_digest(
                self.expected_contact_binding_digest,
                "expected contact binding digest",
            )
            _require_key_id(
                self.expected_contact_binding_key_id,
                "expected contact binding key",
            )
            if self.purpose is OidcPostgresPurpose.ENROLLMENT:
                if any(
                    value is not None
                    for value in (
                        self.initiating_session_id,
                        self.initiating_user_id,
                        self.expected_user_id,
                    )
                ) or self.expected_contact_type != "EMAIL":
                    raise ValueError(
                        "ENROLLMENT must start anonymously with EMAIL evidence"
                    )
            else:
                _require_uuid(self.initiating_session_id, "initiating session")
                _require_uuid(self.initiating_user_id, "initiating user")
                _require_uuid(self.expected_user_id, "expected user")
                if self.initiating_user_id != self.expected_user_id:
                    raise ValueError("STEP_UP expected User must be the initiator")
        else:
            _require_uuid(self.initiating_session_id, "initiating session")
            _require_uuid(self.initiating_user_id, "initiating user")
            _require_uuid(self.expected_user_id, "expected user")
            if self.initiating_user_id != self.expected_user_id:
                raise ValueError("STEP_UP expected User must be the initiator")


@dataclass(frozen=True)
class OidcPostgresCallbackLookup:
    state_digest: bytes = field(repr=False)
    state_digest_key_id: str
    browser_binding_digest: bytes = field(repr=False)
    browser_binding_key_id: str

    def __post_init__(self) -> None:
        _require_digest(self.state_digest, "state digest")
        _require_digest(self.browser_binding_digest, "browser binding digest")
        _require_key_id(self.state_digest_key_id, "state digest key")
        _require_key_id(self.browser_binding_key_id, "browser binding key")


@dataclass(frozen=True)
class OidcPostgresExchangeClaim:
    auth_transaction_id: UUID
    exchange_owner_id: UUID
    invitation_id: Optional[UUID]

    def __post_init__(self) -> None:
        _require_uuid(self.auth_transaction_id, "auth transaction")
        _require_uuid(self.exchange_owner_id, "exchange owner")
        if self.invitation_id is not None:
            _require_uuid(self.invitation_id, "invitation")


@dataclass(frozen=True)
class OidcPostgresExchangeTerminal:
    auth_transaction_id: UUID
    exchange_owner_id: Optional[UUID]
    invitation_id: Optional[UUID]
    outcome: OidcPostgresTerminalOutcome
    audit_event_id: UUID
    system_actor_id: UUID
    correlation_id: UUID
    trace_id: UUID

    def __post_init__(self) -> None:
        for label, value in (
            ("auth transaction", self.auth_transaction_id),
            ("audit event", self.audit_event_id),
            ("system actor", self.system_actor_id),
            ("correlation", self.correlation_id),
            ("trace", self.trace_id),
        ):
            _require_uuid(value, label)
        if self.exchange_owner_id is not None:
            _require_uuid(self.exchange_owner_id, "exchange owner")
        if self.invitation_id is not None:
            _require_uuid(self.invitation_id, "invitation")
        if not isinstance(self.outcome, OidcPostgresTerminalOutcome):
            raise ValueError("OIDC terminal outcome is not closed")
        if (
            self.exchange_owner_id is None
            and self.outcome is OidcPostgresTerminalOutcome.RESULT_UNKNOWN
        ):
            raise ValueError("PENDING exchange cannot have unknown provider outcome")


@dataclass(frozen=True)
class OidcPostgresExistingLoginFinalize:
    auth_transaction_id: UUID
    exchange_owner_id: UUID
    provider_issuer: str
    subject_digest: bytes = field(repr=False)
    subject_digest_key_id: str
    new_session_family_id: UUID
    new_session_id: UUID
    handle_digest: bytes = field(repr=False)
    handle_digest_key_id: str
    csrf_salt: bytes = field(repr=False)
    csrf_key_id: str
    csrf_digest: bytes = field(repr=False)
    auth_time: datetime
    token_issued_at: datetime
    token_expires_at: datetime
    acr_code: str
    amr_codes: Tuple[str, ...]
    audit_event_id: UUID
    system_actor_id: UUID
    correlation_id: UUID
    trace_id: UUID

    def __post_init__(self) -> None:
        for label, value in (
            ("auth transaction", self.auth_transaction_id),
            ("exchange owner", self.exchange_owner_id),
            ("new session family", self.new_session_family_id),
            ("new session", self.new_session_id),
            ("audit event", self.audit_event_id),
            ("system actor", self.system_actor_id),
            ("correlation", self.correlation_id),
            ("trace", self.trace_id),
        ):
            _require_uuid(value, label)
        if len(
            {
                self.auth_transaction_id,
                self.exchange_owner_id,
                self.new_session_family_id,
                self.new_session_id,
                self.audit_event_id,
                self.correlation_id,
                self.trace_id,
            }
        ) != 7:
            raise ValueError("OIDC finalize generated IDs must be distinct")
        _require_https_url(self.provider_issuer, "provider issuer")
        _require_digest(self.subject_digest, "subject digest")
        _require_key_id(self.subject_digest_key_id, "subject digest key")
        _require_digest(self.handle_digest, "Session handle digest")
        _require_key_id(self.handle_digest_key_id, "Session handle digest key")
        _require_digest(self.csrf_salt, "CSRF salt")
        _require_key_id(self.csrf_key_id, "CSRF key")
        _require_digest(self.csrf_digest, "CSRF digest")
        _require_utc(self.auth_time, "OIDC auth_time")
        _require_utc(self.token_issued_at, "OIDC token issued_at")
        _require_utc(self.token_expires_at, "OIDC token expires_at")
        if not self.token_issued_at < self.token_expires_at:
            raise ValueError("OIDC token time window is invalid")
        if not isinstance(self.acr_code, str) or _ACR.fullmatch(self.acr_code) is None:
            raise ValueError("OIDC ACR code is invalid")
        if (
            not isinstance(self.amr_codes, tuple)
            or not 1 <= len(self.amr_codes) <= 16
            or tuple(sorted(set(self.amr_codes))) != self.amr_codes
            or any(_AMR.fullmatch(code) is None for code in self.amr_codes)
        ):
            raise ValueError("OIDC AMR codes must be closed, unique, and sorted")


@dataclass(frozen=True)
class OidcPostgresEnrollmentFinalize:
    auth_transaction_id: UUID
    exchange_owner_id: UUID
    invitation_id: UUID
    invitation_version: int
    expected_contact_point_id: UUID
    expected_contact_type: str
    expected_contact_binding_digest: bytes = field(repr=False)
    expected_contact_binding_key_id: str
    provider_issuer: str
    subject_digest: bytes = field(repr=False)
    subject_digest_key_id: str
    verified_contact_type: str
    verified_contact_binding_digest: bytes = field(repr=False)
    verified_contact_binding_key_id: str
    new_user_id: UUID
    new_external_identity_id: UUID
    new_session_family_id: UUID
    new_session_id: UUID
    handle_digest: bytes = field(repr=False)
    handle_digest_key_id: str
    csrf_salt: bytes = field(repr=False)
    csrf_key_id: str
    csrf_digest: bytes = field(repr=False)
    auth_time: datetime
    token_issued_at: datetime
    token_expires_at: datetime
    acr_code: str
    amr_codes: Tuple[str, ...]
    audit_event_id: UUID
    system_actor_id: UUID
    correlation_id: UUID
    trace_id: UUID

    def __post_init__(self) -> None:
        identifiers = (
            ("auth transaction", self.auth_transaction_id),
            ("exchange owner", self.exchange_owner_id),
            ("invitation", self.invitation_id),
            ("expected contact", self.expected_contact_point_id),
            ("new user", self.new_user_id),
            ("new external identity", self.new_external_identity_id),
            ("new session family", self.new_session_family_id),
            ("new session", self.new_session_id),
            ("audit event", self.audit_event_id),
            ("system actor", self.system_actor_id),
            ("correlation", self.correlation_id),
            ("trace", self.trace_id),
        )
        for label, value in identifiers:
            _require_uuid(value, label)
        generated = {
            self.auth_transaction_id,
            self.exchange_owner_id,
            self.new_user_id,
            self.new_external_identity_id,
            self.new_session_family_id,
            self.new_session_id,
            self.audit_event_id,
            self.correlation_id,
            self.trace_id,
        }
        if len(generated) != 9:
            raise ValueError("OIDC ENROLLMENT generated IDs must be distinct")
        if (
            not isinstance(self.invitation_version, int)
            or isinstance(self.invitation_version, bool)
            or self.invitation_version < 1
            or self.expected_contact_type != "EMAIL"
            or self.verified_contact_type != self.expected_contact_type
        ):
            raise ValueError("OIDC ENROLLMENT authority coordinates are invalid")
        _require_https_url(self.provider_issuer, "provider issuer")
        for label, value in (
            ("subject digest", self.subject_digest),
            ("expected contact binding digest", self.expected_contact_binding_digest),
            ("verified contact binding digest", self.verified_contact_binding_digest),
            ("Session handle digest", self.handle_digest),
            ("CSRF salt", self.csrf_salt),
            ("CSRF digest", self.csrf_digest),
        ):
            _require_digest(value, label)
        for label, value in (
            ("subject digest key", self.subject_digest_key_id),
            ("expected contact binding key", self.expected_contact_binding_key_id),
            ("verified contact binding key", self.verified_contact_binding_key_id),
            ("Session handle digest key", self.handle_digest_key_id),
            ("CSRF key", self.csrf_key_id),
        ):
            _require_key_id(value, label)
        if (
            not hmac.compare_digest(
                self.expected_contact_binding_digest,
                self.verified_contact_binding_digest,
            )
            or self.expected_contact_binding_key_id
            != self.verified_contact_binding_key_id
        ):
            raise ValueError("OIDC ENROLLMENT recipient binding does not match")
        for label, value in (
            ("OIDC auth_time", self.auth_time),
            ("OIDC token issued_at", self.token_issued_at),
            ("OIDC token expires_at", self.token_expires_at),
        ):
            _require_utc(value, label)
        if not self.token_issued_at < self.token_expires_at:
            raise ValueError("OIDC token time window is invalid")
        if not isinstance(self.acr_code, str) or _ACR.fullmatch(self.acr_code) is None:
            raise ValueError("OIDC ACR code is invalid")
        if (
            not isinstance(self.amr_codes, tuple)
            or not 1 <= len(self.amr_codes) <= 16
            or tuple(sorted(set(self.amr_codes))) != self.amr_codes
            or any(_AMR.fullmatch(code) is None for code in self.amr_codes)
        ):
            raise ValueError("OIDC AMR codes must be closed, unique, and sorted")


@dataclass(frozen=True)
class OidcPostgresStepUpSessionFacts:
    user_id: UUID
    initiating_session_id: UUID
    session_family_id: UUID
    current_generation: int

    def __post_init__(self) -> None:
        for label, value in (
            ("user", self.user_id),
            ("initiating session", self.initiating_session_id),
            ("session family", self.session_family_id),
        ):
            _require_uuid(value, label)
        if (
            not isinstance(self.current_generation, int)
            or isinstance(self.current_generation, bool)
            or self.current_generation < 1
        ):
            raise ValueError("OIDC STEP_UP Session generation is invalid")


@dataclass(frozen=True)
class OidcPostgresInvitationStepUpFinalize:
    auth_transaction_id: UUID
    exchange_owner_id: UUID
    invitation_id: UUID
    invitation_version: int
    expected_contact_point_id: UUID
    expected_contact_type: str
    expected_contact_binding_digest: bytes = field(repr=False)
    expected_contact_binding_key_id: str
    expected_user_id: UUID
    initiating_session_id: UUID
    session_family_id: UUID
    predecessor_generation: int
    provider_issuer: str
    subject_digest: bytes = field(repr=False)
    subject_digest_key_id: str
    verified_contact_type: str
    verified_contact_binding_digest: bytes = field(repr=False)
    verified_contact_binding_key_id: str
    new_session_id: UUID
    handle_digest: bytes = field(repr=False)
    handle_digest_key_id: str
    csrf_salt: bytes = field(repr=False)
    csrf_key_id: str
    csrf_digest: bytes = field(repr=False)
    auth_time: datetime
    token_issued_at: datetime
    token_expires_at: datetime
    acr_code: str
    amr_codes: Tuple[str, ...]
    audit_event_id: UUID
    system_actor_id: UUID
    correlation_id: UUID
    trace_id: UUID

    def __post_init__(self) -> None:
        for label, value in (
            ("auth transaction", self.auth_transaction_id),
            ("exchange owner", self.exchange_owner_id),
            ("invitation", self.invitation_id),
            ("expected contact", self.expected_contact_point_id),
            ("expected user", self.expected_user_id),
            ("initiating session", self.initiating_session_id),
            ("session family", self.session_family_id),
            ("new session", self.new_session_id),
            ("audit event", self.audit_event_id),
            ("system actor", self.system_actor_id),
            ("correlation", self.correlation_id),
            ("trace", self.trace_id),
        ):
            _require_uuid(value, label)
        if len(
            {
                self.auth_transaction_id,
                self.exchange_owner_id,
                self.invitation_id,
                self.expected_contact_point_id,
                self.expected_user_id,
                self.initiating_session_id,
                self.session_family_id,
                self.new_session_id,
                self.audit_event_id,
                self.correlation_id,
                self.trace_id,
            }
        ) != 11:
            raise ValueError("OIDC STEP_UP identifiers must be distinct")
        if (
            not isinstance(self.invitation_version, int)
            or isinstance(self.invitation_version, bool)
            or self.invitation_version < 1
            or not isinstance(self.predecessor_generation, int)
            or isinstance(self.predecessor_generation, bool)
            or self.predecessor_generation < 1
            or self.expected_contact_type not in ("EMAIL", "PHONE")
            or self.verified_contact_type != self.expected_contact_type
        ):
            raise ValueError("OIDC STEP_UP authority coordinates are invalid")
        _require_https_url(self.provider_issuer, "provider issuer")
        for label, value in (
            ("subject digest", self.subject_digest),
            ("expected contact binding digest", self.expected_contact_binding_digest),
            ("verified contact binding digest", self.verified_contact_binding_digest),
            ("Session handle digest", self.handle_digest),
            ("CSRF salt", self.csrf_salt),
            ("CSRF digest", self.csrf_digest),
        ):
            _require_digest(value, label)
        for label, value in (
            ("subject digest key", self.subject_digest_key_id),
            ("expected contact binding key", self.expected_contact_binding_key_id),
            ("verified contact binding key", self.verified_contact_binding_key_id),
            ("Session handle digest key", self.handle_digest_key_id),
            ("CSRF key", self.csrf_key_id),
        ):
            _require_key_id(value, label)
        for label, value in (
            ("OIDC auth_time", self.auth_time),
            ("OIDC token issued_at", self.token_issued_at),
            ("OIDC token expires_at", self.token_expires_at),
        ):
            _require_utc(value, label)
        if not self.token_issued_at < self.token_expires_at:
            raise ValueError("OIDC token time window is invalid")
        if not isinstance(self.acr_code, str) or _ACR.fullmatch(self.acr_code) is None:
            raise ValueError("OIDC ACR code is invalid")
        if (
            not isinstance(self.amr_codes, tuple)
            or not 1 <= len(self.amr_codes) <= 16
            or tuple(sorted(set(self.amr_codes))) != self.amr_codes
            or any(_AMR.fullmatch(code) is None for code in self.amr_codes)
        ):
            raise ValueError("OIDC AMR codes must be closed, unique, and sorted")


@dataclass(frozen=True)
class OidcPostgresGenericStepUpFinalize:
    auth_transaction_id: UUID
    exchange_owner_id: UUID
    expected_user_id: UUID
    initiating_session_id: UUID
    session_family_id: UUID
    predecessor_generation: int
    provider_issuer: str
    subject_digest: bytes = field(repr=False)
    subject_digest_key_id: str
    new_session_id: UUID
    handle_digest: bytes = field(repr=False)
    handle_digest_key_id: str
    csrf_salt: bytes = field(repr=False)
    csrf_key_id: str
    csrf_digest: bytes = field(repr=False)
    auth_time: datetime
    token_issued_at: datetime
    token_expires_at: datetime
    acr_code: str
    amr_codes: Tuple[str, ...]
    audit_event_id: UUID
    system_actor_id: UUID
    correlation_id: UUID
    trace_id: UUID

    def __post_init__(self) -> None:
        for label, value in (
            ("auth transaction", self.auth_transaction_id),
            ("exchange owner", self.exchange_owner_id),
            ("expected user", self.expected_user_id),
            ("initiating session", self.initiating_session_id),
            ("session family", self.session_family_id),
            ("new session", self.new_session_id),
            ("audit event", self.audit_event_id),
            ("system actor", self.system_actor_id),
            ("correlation", self.correlation_id),
            ("trace", self.trace_id),
        ):
            _require_uuid(value, label)
        if (
            not isinstance(self.predecessor_generation, int)
            or isinstance(self.predecessor_generation, bool)
            or self.predecessor_generation < 1
        ):
            raise ValueError("OIDC generic STEP_UP generation is invalid")
        _require_https_url(self.provider_issuer, "provider issuer")
        for label, value in (
            ("subject digest", self.subject_digest),
            ("Session handle digest", self.handle_digest),
            ("CSRF salt", self.csrf_salt),
            ("CSRF digest", self.csrf_digest),
        ):
            _require_digest(value, label)
        for label, value in (
            ("subject digest key", self.subject_digest_key_id),
            ("Session handle digest key", self.handle_digest_key_id),
            ("CSRF key", self.csrf_key_id),
        ):
            _require_key_id(value, label)
        for label, value in (
            ("OIDC auth_time", self.auth_time),
            ("OIDC token issued_at", self.token_issued_at),
            ("OIDC token expires_at", self.token_expires_at),
        ):
            _require_utc(value, label)
        if not self.token_issued_at < self.token_expires_at:
            raise ValueError("OIDC token time window is invalid")
        if not isinstance(self.acr_code, str) or _ACR.fullmatch(self.acr_code) is None:
            raise ValueError("OIDC ACR code is invalid")
        if (
            not isinstance(self.amr_codes, tuple)
            or not 1 <= len(self.amr_codes) <= 16
            or tuple(sorted(set(self.amr_codes))) != self.amr_codes
            or any(_AMR.fullmatch(code) is None for code in self.amr_codes)
        ):
            raise ValueError("OIDC AMR codes must be closed, unique, and sorted")


@dataclass(frozen=True)
class OidcPostgresTransaction:
    auth_transaction_id: UUID
    status: AuthTransactionStatus
    purpose: OidcPostgresPurpose
    attempt: int
    browser_binding_digest: bytes = field(repr=False)
    browser_binding_key_id: str
    initiating_session_id: Optional[UUID]
    initiating_user_id: Optional[UUID]
    expected_user_id: Optional[UUID]
    invitation_id: Optional[UUID]
    invitation_version: Optional[int]
    expected_contact_point_id: Optional[UUID]
    expected_contact_type: Optional[str]
    expected_contact_binding_digest: Optional[bytes] = field(repr=False)
    expected_contact_binding_key_id: Optional[str]
    state_digest: bytes = field(repr=False)
    state_digest_key_id: str
    nonce_digest: bytes = field(repr=False)
    nonce_digest_key_id: str
    nonce_ciphertext: bytes = field(repr=False)
    nonce_encryption_key_id: str
    pkce_verifier_ciphertext: bytes = field(repr=False)
    pkce_encryption_key_id: str
    pkce_code_challenge: str
    provider_issuer: str
    provider_audience: str
    redirect_uri: str
    return_to: str
    security_policy_version: str
    deadline: datetime
    exchange_owner_id: Optional[UUID]
    exchange_claimed_at: Optional[datetime]
    provider_error_class: Optional[str]
    aggregate_version: int
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True)
class OidcPostgresSessionResult:
    session_id: UUID
    session_family_id: UUID
    user_id: UUID
    user_status: str
    generation: int


@dataclass(frozen=True)
class OidcPostgresAuthenticationRejected:
    auth_transaction_id: UUID
    reason_code: str = "AUTHENTICATION_REJECTED"

    def __post_init__(self) -> None:
        _require_uuid(self.auth_transaction_id, "auth transaction")
        if self.reason_code != "AUTHENTICATION_REJECTED":
            raise ValueError("OIDC rejection reason is not closed")


class _ConnectionSource:
    def checkout(self) -> Any:
        raise NotImplementedError

    def release(self, connection: Any) -> None:
        raise NotImplementedError

    def discard(self, connection: Any) -> None:
        raise NotImplementedError


@dataclass(frozen=True)
class _Settings:
    runtime_role: str = "iam_onboarding"
    lock_timeout_ms: int = 2_000
    statement_timeout_ms: int = 10_000
    idle_in_transaction_timeout_ms: int = 15_000
    session_idle_ttl: timedelta = timedelta(minutes=30)
    session_absolute_ttl: timedelta = timedelta(hours=12)


class PsycopgOidcAuthenticationUnitOfWork:
    """Execute reviewed OIDC v2 programs with explicit commit boundaries."""

    def __init__(self, *, connections: _ConnectionSource) -> None:
        self._connections = connections
        self._settings = _Settings()

    def begin(self, request: OidcPostgresBeginRequest) -> OidcPostgresTransaction:
        if not isinstance(request, OidcPostgresBeginRequest):
            raise TypeError("OIDC begin request is invalid")
        return self._run_write(lambda connection: self._begin(connection, request))

    def read_callback(
        self,
        request: OidcPostgresCallbackLookup,
    ) -> OidcPostgresTransaction:
        if not isinstance(request, OidcPostgresCallbackLookup):
            raise TypeError("OIDC callback lookup is invalid")
        return self._run_read(lambda connection: self._read_callback(connection, request))

    def claim_exchange(
        self,
        request: OidcPostgresExchangeClaim,
    ) -> OidcPostgresTransaction:
        if not isinstance(request, OidcPostgresExchangeClaim):
            raise TypeError("OIDC exchange claim is invalid")
        return self._run_write(lambda connection: self._claim(connection, request))

    def finish_exchange(self, request: OidcPostgresExchangeTerminal) -> None:
        if not isinstance(request, OidcPostgresExchangeTerminal):
            raise TypeError("OIDC exchange terminal request is invalid")
        self._run_write(lambda connection: self._finish(connection, request))

    def finalize_existing_login(
        self,
        request: OidcPostgresExistingLoginFinalize,
    ) -> Union[OidcPostgresSessionResult, OidcPostgresAuthenticationRejected]:
        if not isinstance(request, OidcPostgresExistingLoginFinalize):
            raise TypeError("OIDC existing-login finalize request is invalid")
        return self._run_write(lambda connection: self._finalize_login(connection, request))

    def finalize_enrollment(
        self,
        request: OidcPostgresEnrollmentFinalize,
    ) -> Union[OidcPostgresSessionResult, OidcPostgresAuthenticationRejected]:
        if not isinstance(request, OidcPostgresEnrollmentFinalize):
            raise TypeError("OIDC enrollment finalize request is invalid")
        return self._run_write(
            lambda connection: self._finalize_enrollment(connection, request)
        )

    def resolve_invitation_step_up_session(
        self,
        *,
        auth_transaction_id: UUID,
        invitation_id: UUID,
        expected_user_id: UUID,
        initiating_session_id: UUID,
    ) -> OidcPostgresStepUpSessionFacts:
        for label, value in (
            ("auth transaction", auth_transaction_id),
            ("invitation", invitation_id),
            ("expected user", expected_user_id),
            ("initiating session", initiating_session_id),
        ):
            _require_uuid(value, label)
        return self._run_read(
            lambda connection: self._resolve_step_up_session(
                connection,
                auth_transaction_id=auth_transaction_id,
                invitation_id=invitation_id,
                expected_user_id=expected_user_id,
                initiating_session_id=initiating_session_id,
            )
        )

    def resolve_generic_step_up_session(
        self,
        *,
        auth_transaction_id: UUID,
        expected_user_id: UUID,
        initiating_session_id: UUID,
    ) -> OidcPostgresStepUpSessionFacts:
        for label, value in (
            ("auth transaction", auth_transaction_id),
            ("expected user", expected_user_id),
            ("initiating session", initiating_session_id),
        ):
            _require_uuid(value, label)
        return self._run_read(
            lambda connection: self._resolve_generic_step_up_session(
                connection,
                auth_transaction_id=auth_transaction_id,
                expected_user_id=expected_user_id,
                initiating_session_id=initiating_session_id,
            )
        )

    def finalize_invitation_step_up(
        self,
        request: OidcPostgresInvitationStepUpFinalize,
    ) -> Union[OidcPostgresSessionResult, OidcPostgresAuthenticationRejected]:
        if not isinstance(request, OidcPostgresInvitationStepUpFinalize):
            raise TypeError("OIDC invitation STEP_UP finalize request is invalid")
        return self._run_write(
            lambda connection: self._finalize_step_up(connection, request)
        )

    def finalize_generic_step_up(
        self,
        request: OidcPostgresGenericStepUpFinalize,
    ) -> Union[OidcPostgresSessionResult, OidcPostgresAuthenticationRejected]:
        if not isinstance(request, OidcPostgresGenericStepUpFinalize):
            raise TypeError("OIDC generic STEP_UP finalize request is invalid")
        return self._run_write(
            lambda connection: self._finalize_generic_step_up(connection, request)
        )

    def _begin(
        self,
        connection: Any,
        request: OidcPostgresBeginRequest,
    ) -> OidcPostgresTransaction:
        # ENROLLMENT is invitation-only: its exact version/contact binding is
        # frozen in the AuthTransaction before any User is created.
        if request.purpose not in {
            OidcPostgresPurpose.LOGIN,
            OidcPostgresPurpose.ENROLLMENT,
            OidcPostgresPurpose.STEP_UP,
        }:
            raise IamError("SERVICE_UNAVAILABLE")
        self._install_context(
            connection,
            operation="BEGIN",
            auth_transaction_id=request.auth_transaction_id,
            invitation_id=request.invitation_id,
            actor_user_id=request.system_actor_id,
            command_id=request.auth_transaction_id,
        )
        row = connection.execute(
            """
            INSERT INTO iam.auth_transactions (
                id,status,purpose,attempt,protocol_version,
                browser_binding_digest,browser_binding_key_id,
                initiating_session_id,initiating_user_id,expected_user_id,
                invitation_id,invitation_version,expected_contact_point_id,
                state_digest,state_digest_key_id,nonce_digest,nonce_digest_key_id,
                pkce_verifier_ciphertext,pkce_encryption_key_id,
                pkce_encryption_algorithm,redirect_uri,provider_error_class,
                deadline,succeeded_at,created_at,updated_at,
                expected_contact_type,expected_contact_binding_digest,
                expected_contact_binding_key_id,nonce_ciphertext,
                nonce_encryption_key_id,nonce_encryption_algorithm,
                pkce_code_challenge,pkce_code_challenge_method,provider_issuer,
                provider_audience,return_to,security_policy_version,
                exchange_owner_id,exchange_claimed_at,aggregate_version
            ) VALUES (
                %s,'PENDING',%s,0,2,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,
                %s,%s,'AES_256_GCM_V1',%s,NULL,
                transaction_timestamp() + interval '10 minutes',NULL,
                transaction_timestamp(),transaction_timestamp(),%s,%s,%s,%s,%s,
                'AES_256_GCM_V1',%s,'S256',%s,%s,%s,%s,NULL,NULL,1
            )
            RETURNING
                id,status,purpose,attempt,browser_binding_digest,
                browser_binding_key_id,initiating_session_id,initiating_user_id,
                expected_user_id,invitation_id,invitation_version,
                expected_contact_point_id,expected_contact_type,
                expected_contact_binding_digest,expected_contact_binding_key_id,
                state_digest,state_digest_key_id,nonce_digest,nonce_digest_key_id,
                nonce_ciphertext,nonce_encryption_key_id,
                pkce_verifier_ciphertext,pkce_encryption_key_id,
                pkce_code_challenge,provider_issuer,provider_audience,redirect_uri,
                return_to,security_policy_version,deadline,exchange_owner_id,
                exchange_claimed_at,provider_error_class,aggregate_version,
                created_at,updated_at
            """,
            (
                request.auth_transaction_id,
                request.purpose.value,
                request.browser_binding_digest,
                request.browser_binding_key_id,
                request.initiating_session_id,
                request.initiating_user_id,
                request.expected_user_id,
                request.invitation_id,
                request.invitation_version,
                request.expected_contact_point_id,
                request.state_digest,
                request.state_digest_key_id,
                request.nonce_digest,
                request.nonce_digest_key_id,
                request.pkce_verifier_ciphertext,
                request.pkce_encryption_key_id,
                request.redirect_uri,
                request.expected_contact_type,
                request.expected_contact_binding_digest,
                request.expected_contact_binding_key_id,
                request.nonce_ciphertext,
                request.nonce_encryption_key_id,
                request.pkce_code_challenge,
                request.provider_issuer,
                request.provider_audience,
                request.return_to,
                request.security_policy_version,
            ),
        ).fetchone()
        self._insert_audit(
            connection,
            event_id=request.audit_event_id,
            actor_kind="SYSTEM",
            actor_id=request.system_actor_id,
            action="BeginOidcAuthorization",
            auth_transaction_id=request.auth_transaction_id,
            purpose=request.purpose.value,
            result="SUCCEEDED",
            before_status=None,
            after_status="PENDING",
            before_version=None,
            after_version=1,
            correlation_id=request.correlation_id,
            trace_id=request.trace_id,
        )
        return _transaction(row)

    def _resolve_step_up_session(
        self,
        connection: Any,
        *,
        auth_transaction_id: UUID,
        invitation_id: UUID,
        expected_user_id: UUID,
        initiating_session_id: UUID,
    ) -> OidcPostgresStepUpSessionFacts:
        self._install_context(
            connection,
            operation="COMPLETE",
            auth_transaction_id=auth_transaction_id,
            invitation_id=invitation_id,
            actor_user_id=expected_user_id,
            session_id=initiating_session_id,
        )
        rows = connection.execute(
            "SELECT * FROM iam_api.resolve_oidc_step_up_session_v1(%s,%s,%s,%s)",
            (
                auth_transaction_id,
                invitation_id,
                expected_user_id,
                initiating_session_id,
            ),
        ).fetchall()
        if len(rows) != 1:
            raise IamError("AUTHENTICATION_REJECTED")
        row = rows[0]
        if len(row) != 4:
            raise IamError("SERVICE_UNAVAILABLE")
        try:
            return OidcPostgresStepUpSessionFacts(
                user_id=_as_uuid(row[0]),
                initiating_session_id=_as_uuid(row[1]),
                session_family_id=_as_uuid(row[2]),
                current_generation=int(row[3]),
            )
        except (TypeError, ValueError):
            raise IamError("SERVICE_UNAVAILABLE") from None

    def _resolve_generic_step_up_session(
        self,
        connection: Any,
        *,
        auth_transaction_id: UUID,
        expected_user_id: UUID,
        initiating_session_id: UUID,
    ) -> OidcPostgresStepUpSessionFacts:
        self._install_context(
            connection,
            operation="COMPLETE",
            auth_transaction_id=auth_transaction_id,
            actor_user_id=expected_user_id,
            session_id=initiating_session_id,
        )
        rows = connection.execute(
            "SELECT * FROM iam_api.resolve_oidc_generic_step_up_session_v1("
            "%s,%s,%s)",
            (auth_transaction_id, expected_user_id, initiating_session_id),
        ).fetchall()
        if len(rows) != 1:
            raise IamError("AUTHENTICATION_REJECTED")
        row = rows[0]
        if len(row) != 4:
            raise IamError("SERVICE_UNAVAILABLE")
        try:
            return OidcPostgresStepUpSessionFacts(
                user_id=_as_uuid(row[0]),
                initiating_session_id=_as_uuid(row[1]),
                session_family_id=_as_uuid(row[2]),
                current_generation=int(row[3]),
            )
        except (TypeError, ValueError):
            raise IamError("SERVICE_UNAVAILABLE") from None

    def _read_callback(
        self,
        connection: Any,
        request: OidcPostgresCallbackLookup,
    ) -> OidcPostgresTransaction:
        self._install_context(
            connection,
            operation="COMPLETE",
            state_digest=request.state_digest,
            state_digest_key_id=request.state_digest_key_id,
            browser_binding_digest=request.browser_binding_digest,
            browser_binding_key_id=request.browser_binding_key_id,
        )
        rows = connection.execute(
            "SELECT * FROM iam_api.read_oidc_callback_v2(%s,%s,%s,%s)",
            (
                request.state_digest_key_id,
                request.state_digest,
                request.browser_binding_key_id,
                request.browser_binding_digest,
            ),
        ).fetchall()
        if len(rows) != 1:
            raise IamError("AUTH_TRANSACTION_INVALID")
        return _transaction(rows[0])

    def _claim(
        self,
        connection: Any,
        request: OidcPostgresExchangeClaim,
    ) -> OidcPostgresTransaction:
        self._install_context(
            connection,
            operation="COMPLETE",
            auth_transaction_id=request.auth_transaction_id,
            invitation_id=request.invitation_id,
        )
        row = connection.execute(
            """
            UPDATE iam.auth_transactions
            SET status='EXCHANGING',attempt=1,exchange_owner_id=%s,
                exchange_claimed_at=transaction_timestamp(),aggregate_version=2,
                updated_at=transaction_timestamp()
            WHERE id=%s AND protocol_version=2 AND status='PENDING'
              AND aggregate_version=1 AND attempt=0
              AND exchange_owner_id IS NULL AND exchange_claimed_at IS NULL
              AND transaction_timestamp() < deadline
            RETURNING
                id,status,purpose,attempt,browser_binding_digest,
                browser_binding_key_id,initiating_session_id,initiating_user_id,
                expected_user_id,invitation_id,invitation_version,
                expected_contact_point_id,expected_contact_type,
                expected_contact_binding_digest,expected_contact_binding_key_id,
                state_digest,state_digest_key_id,nonce_digest,nonce_digest_key_id,
                nonce_ciphertext,nonce_encryption_key_id,
                pkce_verifier_ciphertext,pkce_encryption_key_id,
                pkce_code_challenge,provider_issuer,provider_audience,redirect_uri,
                return_to,security_policy_version,deadline,exchange_owner_id,
                exchange_claimed_at,provider_error_class,aggregate_version,
                created_at,updated_at
            """,
            (request.exchange_owner_id, request.auth_transaction_id),
        ).fetchone()
        if row is None:
            raise IamError("AUTH_TRANSACTION_INVALID")
        return _transaction(row)

    def _finish(
        self,
        connection: Any,
        request: OidcPostgresExchangeTerminal,
    ) -> None:
        self._install_context(
            connection,
            operation="COMPLETE",
            auth_transaction_id=request.auth_transaction_id,
            invitation_id=request.invitation_id,
            actor_user_id=request.system_actor_id,
            command_id=request.auth_transaction_id,
        )
        if request.exchange_owner_id is None:
            status = "FAILED"
            provider_error = request.outcome.value
            expected_status = "PENDING"
            expected_version = 1
            next_version = 2
            owner_clause = "exchange_owner_id IS NULL"
            parameters = (
                status,
                provider_error,
                next_version,
                request.auth_transaction_id,
            )
        else:
            status = (
                "RESULT_UNKNOWN"
                if request.outcome is OidcPostgresTerminalOutcome.RESULT_UNKNOWN
                else "FAILED"
            )
            provider_error = request.outcome.value
            expected_status = "EXCHANGING"
            expected_version = 2
            next_version = 3
            owner_clause = "exchange_owner_id=%s"
            parameters = (
                status,
                provider_error,
                next_version,
                request.auth_transaction_id,
                request.exchange_owner_id,
            )
        row = connection.execute(
            "UPDATE iam.auth_transactions SET status=%s,provider_error_class=%s,"
            "aggregate_version=%s,updated_at=transaction_timestamp() "
            "WHERE id=%s AND protocol_version=2 AND status='"
            + expected_status
            + "' AND aggregate_version="
            + str(expected_version)
            + " AND "
            + owner_clause
            + " RETURNING purpose",
            parameters,
        ).fetchone()
        if row is None:
            raise IamError("AUTH_TRANSACTION_INVALID")
        self._insert_audit(
            connection,
            event_id=request.audit_event_id,
            actor_kind="SYSTEM",
            actor_id=request.system_actor_id,
            action="CompleteOidcAuthentication",
            auth_transaction_id=request.auth_transaction_id,
            purpose=row[0],
            result=status,
            before_status=expected_status,
            after_status=status,
            before_version=expected_version,
            after_version=next_version,
            correlation_id=request.correlation_id,
            trace_id=request.trace_id,
        )

    def _finalize_login(
        self,
        connection: Any,
        request: OidcPostgresExistingLoginFinalize,
    ) -> Union[OidcPostgresSessionResult, OidcPostgresAuthenticationRejected]:
        self._install_context(
            connection,
            operation="COMPLETE",
            auth_transaction_id=request.auth_transaction_id,
            state_subject_issuer=request.provider_issuer,
            state_subject_digest=request.subject_digest,
            state_subject_digest_key_id=request.subject_digest_key_id,
            session_family_id=request.new_session_family_id,
            session_id=request.new_session_id,
            command_id=request.auth_transaction_id,
            actor_user_id=request.system_actor_id,
        )
        transaction = connection.execute(
            "SELECT purpose,deadline,provider_issuer FROM iam.auth_transactions "
            "WHERE id=%s AND protocol_version=2 AND status='EXCHANGING' "
            "AND aggregate_version=2 AND attempt=1 AND exchange_owner_id=%s "
            "AND invitation_id IS NULL AND initiating_session_id IS NULL "
            "AND initiating_user_id IS NULL AND expected_user_id IS NULL "
            "FOR UPDATE",
            (request.auth_transaction_id, request.exchange_owner_id),
        ).fetchone()
        if transaction is None or transaction[0] != "LOGIN":
            raise IamError("AUTHENTICATION_REJECTED")
        server_now = connection.execute("SELECT transaction_timestamp()").fetchone()[0]
        if transaction[1] <= server_now:
            return self._reject_login(connection, request)
        if transaction[2] != request.provider_issuer:
            return self._reject_login(connection, request)
        if (
            request.auth_time > server_now
            or request.token_issued_at > server_now
            or server_now >= request.token_expires_at
        ):
            return self._reject_login(connection, request)
        identity_rows = connection.execute(
            "SELECT * FROM iam_api.lock_oidc_identity_v2(%s,%s,%s)",
            (
                request.provider_issuer,
                request.subject_digest,
                request.subject_digest_key_id,
            ),
        ).fetchall()
        if len(identity_rows) != 1:
            return self._reject_login(connection, request)
        _identity_id, user_id, user_status, _user_version = identity_rows[0]
        if user_status != "ACTIVE":
            return self._reject_login(connection, request)
        self._set_context(connection, "app.actor_user_id", str(user_id))
        self._set_context(connection, "app.target_user_id", str(user_id))
        idle_expires_at = server_now + self._settings.session_idle_ttl
        absolute_expires_at = server_now + self._settings.session_absolute_ttl
        connection.execute(
            "INSERT INTO iam.session_families ("
            "id,user_id,status,current_generation,revoked_at,"
            "revocation_reason_code,aggregate_version,created_at,updated_at) "
            "VALUES (%s,%s,'ACTIVE',1,NULL,NULL,1,%s,%s)",
            (request.new_session_family_id, user_id, server_now, server_now),
        )
        connection.execute(
            "INSERT INTO iam.sessions ("
            "id,user_id,family_id,generation,predecessor_session_id,handle_digest,"
            "handle_digest_key_id,csrf_salt,csrf_key_id,csrf_digest,"
            "verified_contact_point_id,verified_at,verified_for_invitation_id,"
            "auth_transaction_id,auth_time,acr_code,amr_codes,created_at,"
            "last_activity_at,idle_expires_at,absolute_expires_at,updated_at,"
            "device_label,status,rotation_reason,revoked_at,"
            "revocation_reason_code,aggregate_version) VALUES ("
            "%s,%s,%s,1,NULL,%s,%s,%s,%s,%s,NULL,NULL,NULL,%s,%s,%s,%s,"
            "%s,%s,%s,%s,%s,'Browser','ACTIVE','LOGIN',NULL,NULL,1)",
            (
                request.new_session_id,
                user_id,
                request.new_session_family_id,
                request.handle_digest,
                request.handle_digest_key_id,
                request.csrf_salt,
                request.csrf_key_id,
                request.csrf_digest,
                request.auth_transaction_id,
                request.auth_time,
                request.acr_code,
                list(request.amr_codes),
                server_now,
                server_now,
                idle_expires_at,
                absolute_expires_at,
                server_now,
            ),
        )
        updated = connection.execute(
            "UPDATE iam.auth_transactions SET status='SUCCEEDED',succeeded_at=%s,"
            "aggregate_version=3,updated_at=%s WHERE id=%s "
            "AND status='EXCHANGING' AND aggregate_version=2 "
            "AND exchange_owner_id=%s RETURNING id",
            (
                server_now,
                server_now,
                request.auth_transaction_id,
                request.exchange_owner_id,
            ),
        ).fetchone()
        if updated != (request.auth_transaction_id,):
            raise IamError("AUTH_TRANSACTION_INVALID")
        self._insert_audit(
            connection,
            event_id=request.audit_event_id,
            actor_kind="USER",
            actor_id=user_id,
            action="CompleteOidcAuthentication",
            auth_transaction_id=request.auth_transaction_id,
            purpose="LOGIN",
            result="SUCCEEDED",
            before_status="EXCHANGING",
            after_status="SUCCEEDED",
            before_version=2,
            after_version=3,
            correlation_id=request.correlation_id,
            trace_id=request.trace_id,
        )
        return OidcPostgresSessionResult(
            session_id=request.new_session_id,
            session_family_id=request.new_session_family_id,
            user_id=user_id,
            user_status=user_status,
            generation=1,
        )

    def _finalize_enrollment(
        self,
        connection: Any,
        request: OidcPostgresEnrollmentFinalize,
    ) -> Union[OidcPostgresSessionResult, OidcPostgresAuthenticationRejected]:
        self._install_context(
            connection,
            operation="COMPLETE",
            auth_transaction_id=request.auth_transaction_id,
            invitation_id=request.invitation_id,
            actor_user_id=request.new_user_id,
            command_id=request.auth_transaction_id,
            session_family_id=request.new_session_family_id,
            session_id=request.new_session_id,
            state_subject_issuer=request.provider_issuer,
            state_subject_digest=request.subject_digest,
            state_subject_digest_key_id=request.subject_digest_key_id,
        )
        rows = connection.execute(
            "SELECT * FROM iam_api.finalize_oidc_invitation_enrollment_v1("
            + ",".join(("%s",) * 32)
            + ")",
            (
                request.auth_transaction_id,
                request.exchange_owner_id,
                request.invitation_id,
                request.invitation_version,
                request.expected_contact_point_id,
                request.expected_contact_type,
                request.expected_contact_binding_digest,
                request.expected_contact_binding_key_id,
                request.provider_issuer,
                request.subject_digest,
                request.subject_digest_key_id,
                request.verified_contact_type,
                request.verified_contact_binding_digest,
                request.verified_contact_binding_key_id,
                request.new_user_id,
                request.new_external_identity_id,
                request.new_session_family_id,
                request.new_session_id,
                request.handle_digest,
                request.handle_digest_key_id,
                request.csrf_salt,
                request.csrf_key_id,
                request.csrf_digest,
                request.auth_time,
                request.token_issued_at,
                request.token_expires_at,
                request.acr_code,
                list(request.amr_codes),
                request.audit_event_id,
                request.system_actor_id,
                request.correlation_id,
                request.trace_id,
            ),
        ).fetchall()
        if len(rows) != 1 or len(rows[0]) != 6:
            raise IamError("SERVICE_UNAVAILABLE")
        decision, session_id, family_id, user_id, user_status, generation = rows[0]
        if decision == "AUTHENTICATION_REJECTED":
            return OidcPostgresAuthenticationRejected(
                auth_transaction_id=request.auth_transaction_id
            )
        if decision != "AUTHORIZED":
            raise IamError("SERVICE_UNAVAILABLE")
        try:
            return OidcPostgresSessionResult(
                session_id=_as_uuid(session_id),
                session_family_id=_as_uuid(family_id),
                user_id=_as_uuid(user_id),
                user_status=str(user_status),
                generation=int(generation),
            )
        except (TypeError, ValueError):
            raise IamError("SERVICE_UNAVAILABLE") from None

    def _finalize_step_up(
        self,
        connection: Any,
        request: OidcPostgresInvitationStepUpFinalize,
    ) -> Union[OidcPostgresSessionResult, OidcPostgresAuthenticationRejected]:
        self._install_context(
            connection,
            operation="COMPLETE",
            auth_transaction_id=request.auth_transaction_id,
            invitation_id=request.invitation_id,
            actor_user_id=request.expected_user_id,
            command_id=request.auth_transaction_id,
            session_family_id=request.session_family_id,
            session_id=request.new_session_id,
            state_subject_issuer=request.provider_issuer,
            state_subject_digest=request.subject_digest,
            state_subject_digest_key_id=request.subject_digest_key_id,
        )
        rows = connection.execute(
            "SELECT * FROM iam_api.finalize_oidc_invitation_step_up_v1("
            + ",".join(("%s",) * 33)
            + ")",
            (
                request.auth_transaction_id,
                request.exchange_owner_id,
                request.invitation_id,
                request.invitation_version,
                request.expected_contact_point_id,
                request.expected_contact_type,
                request.expected_contact_binding_digest,
                request.expected_contact_binding_key_id,
                request.expected_user_id,
                request.initiating_session_id,
                request.session_family_id,
                request.predecessor_generation,
                request.provider_issuer,
                request.subject_digest,
                request.subject_digest_key_id,
                request.verified_contact_type,
                request.verified_contact_binding_digest,
                request.verified_contact_binding_key_id,
                request.new_session_id,
                request.handle_digest,
                request.handle_digest_key_id,
                request.csrf_salt,
                request.csrf_key_id,
                request.csrf_digest,
                request.auth_time,
                request.token_issued_at,
                request.token_expires_at,
                request.acr_code,
                list(request.amr_codes),
                request.audit_event_id,
                request.system_actor_id,
                request.correlation_id,
                request.trace_id,
            ),
        ).fetchall()
        if len(rows) != 1 or len(rows[0]) != 6:
            raise IamError("SERVICE_UNAVAILABLE")
        decision, session_id, family_id, user_id, user_status, generation = rows[0]
        if decision == "AUTHENTICATION_REJECTED":
            return OidcPostgresAuthenticationRejected(
                auth_transaction_id=request.auth_transaction_id
            )
        if decision != "AUTHORIZED":
            raise IamError("SERVICE_UNAVAILABLE")
        try:
            return OidcPostgresSessionResult(
                session_id=_as_uuid(session_id),
                session_family_id=_as_uuid(family_id),
                user_id=_as_uuid(user_id),
                user_status=str(user_status),
                generation=int(generation),
            )
        except (TypeError, ValueError):
            raise IamError("SERVICE_UNAVAILABLE") from None

    def _finalize_generic_step_up(
        self,
        connection: Any,
        request: OidcPostgresGenericStepUpFinalize,
    ) -> Union[OidcPostgresSessionResult, OidcPostgresAuthenticationRejected]:
        self._install_context(
            connection,
            operation="COMPLETE",
            auth_transaction_id=request.auth_transaction_id,
            actor_user_id=request.expected_user_id,
            command_id=request.auth_transaction_id,
            session_family_id=request.session_family_id,
            session_id=request.new_session_id,
            state_subject_issuer=request.provider_issuer,
            state_subject_digest=request.subject_digest,
            state_subject_digest_key_id=request.subject_digest_key_id,
        )
        rows = connection.execute(
            "SELECT * FROM iam_api.finalize_oidc_generic_step_up_v1("
            + ",".join(("%s",) * 24)
            + ")",
            (
                request.auth_transaction_id,
                request.exchange_owner_id,
                request.expected_user_id,
                request.initiating_session_id,
                request.session_family_id,
                request.predecessor_generation,
                request.provider_issuer,
                request.subject_digest,
                request.subject_digest_key_id,
                request.new_session_id,
                request.handle_digest,
                request.handle_digest_key_id,
                request.csrf_salt,
                request.csrf_key_id,
                request.csrf_digest,
                request.auth_time,
                request.token_issued_at,
                request.token_expires_at,
                request.acr_code,
                list(request.amr_codes),
                request.audit_event_id,
                request.system_actor_id,
                request.correlation_id,
                request.trace_id,
            ),
        ).fetchall()
        if len(rows) != 1 or len(rows[0]) != 6:
            raise IamError("SERVICE_UNAVAILABLE")
        decision, session_id, family_id, user_id, user_status, generation = rows[0]
        if decision == "AUTHENTICATION_REJECTED":
            return OidcPostgresAuthenticationRejected(
                auth_transaction_id=request.auth_transaction_id
            )
        if decision != "AUTHORIZED":
            raise IamError("SERVICE_UNAVAILABLE")
        try:
            return OidcPostgresSessionResult(
                session_id=_as_uuid(session_id),
                session_family_id=_as_uuid(family_id),
                user_id=_as_uuid(user_id),
                user_status=str(user_status),
                generation=int(generation),
            )
        except (TypeError, ValueError):
            raise IamError("SERVICE_UNAVAILABLE") from None

    def _reject_login(
        self,
        connection: Any,
        request: OidcPostgresExistingLoginFinalize,
    ) -> OidcPostgresAuthenticationRejected:
        updated = connection.execute(
            "UPDATE iam.auth_transactions SET status='FAILED',"
            "provider_error_class='REJECTED',aggregate_version=3,"
            "updated_at=transaction_timestamp() WHERE id=%s "
            "AND protocol_version=2 AND status='EXCHANGING' "
            "AND aggregate_version=2 AND attempt=1 AND exchange_owner_id=%s "
            "RETURNING purpose",
            (request.auth_transaction_id, request.exchange_owner_id),
        ).fetchone()
        if updated != ("LOGIN",):
            raise IamError("AUTH_TRANSACTION_INVALID")
        self._insert_audit(
            connection,
            event_id=request.audit_event_id,
            actor_kind="SYSTEM",
            actor_id=request.system_actor_id,
            action="CompleteOidcAuthentication",
            auth_transaction_id=request.auth_transaction_id,
            purpose="LOGIN",
            result="FAILED",
            before_status="EXCHANGING",
            after_status="FAILED",
            before_version=2,
            after_version=3,
            correlation_id=request.correlation_id,
            trace_id=request.trace_id,
        )
        return OidcPostgresAuthenticationRejected(
            auth_transaction_id=request.auth_transaction_id,
        )

    def _insert_audit(
        self,
        connection: Any,
        *,
        event_id: UUID,
        actor_kind: str,
        actor_id: UUID,
        action: str,
        auth_transaction_id: UUID,
        purpose: str,
        result: str,
        before_status: Optional[str],
        after_status: str,
        before_version: Optional[int],
        after_version: int,
        correlation_id: UUID,
        trace_id: UUID,
    ) -> None:
        connection.execute(
            "INSERT INTO audit.audit_events ("
            "event_id,occurred_at,actor_kind,actor_id,original_actor_id,"
            "action_code,target_kind,target_id,organization_id,before_status,"
            "after_status,before_version,after_version,role_code,purpose_code,"
            "reason_code,auth_strength_code,result_code,command_id,correlation_id,"
            "causation_id,trace_id,safe_attributes) VALUES ("
            "%s,transaction_timestamp(),%s,%s,NULL,%s,'AuthTransaction',%s,NULL,"
            "%s,%s,%s,%s,NULL,%s,NULL,NULL,%s,%s,%s,%s,%s,'{}'::jsonb)",
            (
                event_id,
                actor_kind,
                actor_id,
                action,
                auth_transaction_id,
                before_status,
                after_status,
                before_version,
                after_version,
                purpose,
                result,
                auth_transaction_id,
                correlation_id,
                auth_transaction_id,
                trace_id,
            ),
        )

    def _run_write(self, program: Callable[[Any], _T]) -> _T:
        return self._run(program, write=True)

    def _run_read(self, program: Callable[[Any], _T]) -> _T:
        return self._run(program, write=False)

    def _run(self, program: Callable[[Any], _T], *, write: bool) -> _T:
        connection = self._connections.checkout()
        transaction_started = False
        commit_sent = False
        released = False
        try:
            self._validate_connection(connection)
            connection.execute(
                "BEGIN TRANSACTION ISOLATION LEVEL READ COMMITTED"
                + ("" if write else " READ ONLY")
            )
            transaction_started = True
            self._configure_transaction(connection)
            result = program(connection)
            commit_sent = True
            connection.execute("COMMIT")
            transaction_started = False
            released = self._release_or_discard(connection)
            return result
        except IamError:
            self._abort_and_discard(connection, transaction_started=transaction_started)
            released = True
            raise
        except BaseException as error:
            self._abort_and_discard(connection, transaction_started=transaction_started)
            released = True
            if write and commit_sent:
                raise IamError("COMMAND_OUTCOME_UNKNOWN") from error
            raise IamError("SERVICE_UNAVAILABLE") from error
        finally:
            if not released:
                self._connections.discard(connection)

    def _validate_connection(self, connection: Any) -> None:
        if connection.info.transaction_status != TransactionStatus.IDLE:
            raise RuntimeError("OIDC checkout must be transaction-idle")
        _reset_connection(connection)
        identity = connection.execute(
            "SELECT current_user,session_user,"
            "current_setting('server_version_num')::integer"
        ).fetchone()
        if identity is None or identity[0:2] != (
            self._settings.runtime_role,
            self._settings.runtime_role,
        ):
            raise RuntimeError("OIDC connection identity is not iam_onboarding")
        if identity[2] // 10_000 != 18:
            raise RuntimeError("OIDC persistence requires PostgreSQL 18")

    def _configure_transaction(self, connection: Any) -> None:
        connection.execute("SET LOCAL TIME ZONE 'UTC'")
        connection.execute(
            "SET LOCAL lock_timeout = '%dms'" % self._settings.lock_timeout_ms
        )
        connection.execute(
            "SET LOCAL statement_timeout = '%dms'"
            % self._settings.statement_timeout_ms
        )
        connection.execute(
            "SET LOCAL idle_in_transaction_session_timeout = '%dms'"
            % self._settings.idle_in_transaction_timeout_ms
        )

    def _install_context(
        self,
        connection: Any,
        *,
        operation: str,
        auth_transaction_id: Optional[UUID] = None,
        invitation_id: Optional[UUID] = None,
        actor_user_id: Optional[UUID] = None,
        command_id: Optional[UUID] = None,
        session_family_id: Optional[UUID] = None,
        session_id: Optional[UUID] = None,
        state_digest: Optional[bytes] = None,
        state_digest_key_id: Optional[str] = None,
        browser_binding_digest: Optional[bytes] = None,
        browser_binding_key_id: Optional[str] = None,
        state_subject_issuer: Optional[str] = None,
        state_subject_digest: Optional[bytes] = None,
        state_subject_digest_key_id: Optional[str] = None,
    ) -> None:
        values = (
            ("app.scope_kind", "AUTH_PROTOCOL"),
            ("app.operation", operation),
            ("app.auth_transaction_id", _optional_text(auth_transaction_id)),
            ("app.target_invitation_id", _optional_text(invitation_id)),
            ("app.actor_user_id", _optional_text(actor_user_id)),
            ("app.target_user_id", _optional_text(actor_user_id)),
            ("app.command_id", _optional_text(command_id)),
            ("app.organization_id", ""),
            ("app.session_family_id", _optional_text(session_family_id)),
            ("app.session_id", _optional_text(session_id)),
            ("app.oidc_state_digest", _optional_hex(state_digest)),
            ("app.oidc_state_digest_key_id", state_digest_key_id or ""),
            ("app.oidc_browser_digest", _optional_hex(browser_binding_digest)),
            ("app.oidc_browser_digest_key_id", browser_binding_key_id or ""),
            ("app.oidc_subject_issuer", state_subject_issuer or ""),
            ("app.oidc_subject_digest", _optional_hex(state_subject_digest)),
            (
                "app.oidc_subject_digest_key_id",
                state_subject_digest_key_id or "",
            ),
        )
        for name, value in values:
            self._set_context(connection, name, value)

    @staticmethod
    def _set_context(connection: Any, name: str, value: str) -> None:
        installed = connection.execute(
            "SELECT pg_catalog.set_config(%s,%s,true)",
            (name, value),
        ).fetchone()
        if installed != (value,):
            raise RuntimeError("OIDC transaction context installation failed")

    def _release_or_discard(self, connection: Any) -> bool:
        try:
            if connection.info.transaction_status != TransactionStatus.IDLE:
                self._connections.discard(connection)
                return True
            _reset_connection(connection)
            identity = connection.execute(
                "SELECT current_user,session_user,current_setting("
                "'app.auth_transaction_id',true)"
            ).fetchone()
            if identity not in (
                (self._settings.runtime_role, self._settings.runtime_role, None),
                (self._settings.runtime_role, self._settings.runtime_role, ""),
            ):
                self._connections.discard(connection)
                return True
        except BaseException:
            self._connections.discard(connection)
            return True
        self._connections.release(connection)
        return True

    def _abort_and_discard(
        self,
        connection: Any,
        *,
        transaction_started: bool,
    ) -> None:
        try:
            if transaction_started:
                connection.execute("ROLLBACK")
            _reset_connection(connection)
        except BaseException:
            pass
        self._connections.discard(connection)


def _transaction(row: Optional[Sequence[Any]]) -> OidcPostgresTransaction:
    if row is None or len(row) != 36:
        raise IamError("SERVICE_UNAVAILABLE")
    byte_indexes = (4, 13, 15, 17, 19, 21)
    values = list(row)
    for index in byte_indexes:
        if isinstance(values[index], memoryview):
            values[index] = values[index].tobytes()
    try:
        return OidcPostgresTransaction(
            auth_transaction_id=values[0],
            status=AuthTransactionStatus(values[1]),
            purpose=OidcPostgresPurpose(values[2]),
            attempt=values[3],
            browser_binding_digest=values[4],
            browser_binding_key_id=values[5],
            initiating_session_id=values[6],
            initiating_user_id=values[7],
            expected_user_id=values[8],
            invitation_id=values[9],
            invitation_version=values[10],
            expected_contact_point_id=values[11],
            expected_contact_type=values[12],
            expected_contact_binding_digest=values[13],
            expected_contact_binding_key_id=values[14],
            state_digest=values[15],
            state_digest_key_id=values[16],
            nonce_digest=values[17],
            nonce_digest_key_id=values[18],
            nonce_ciphertext=values[19],
            nonce_encryption_key_id=values[20],
            pkce_verifier_ciphertext=values[21],
            pkce_encryption_key_id=values[22],
            pkce_code_challenge=values[23],
            provider_issuer=values[24],
            provider_audience=values[25],
            redirect_uri=values[26],
            return_to=values[27],
            security_policy_version=values[28],
            deadline=values[29],
            exchange_owner_id=values[30],
            exchange_claimed_at=values[31],
            provider_error_class=values[32],
            aggregate_version=values[33],
            created_at=values[34],
            updated_at=values[35],
        )
    except (TypeError, ValueError, IndexError) as error:
        raise IamError("SERVICE_UNAVAILABLE") from error


def _require_uuid(value: object, label: str) -> None:
    if not isinstance(value, UUID) or value.int == 0:
        raise ValueError("%s ID must be a non-zero UUID" % label)


def _as_uuid(value: object) -> UUID:
    parsed = value if isinstance(value, UUID) else UUID(str(value))
    if parsed.int == 0:
        raise ValueError("UUID must be non-zero")
    return parsed


def _require_digest(value: object, label: str) -> None:
    if not isinstance(value, bytes) or len(value) != 32:
        raise ValueError("%s must be exactly 32 bytes" % label)


def _require_ciphertext(value: object, label: str) -> None:
    if not isinstance(value, bytes) or not 1 <= len(value) <= 16_384:
        raise ValueError("%s ciphertext is invalid" % label)


def _require_key_id(value: object, label: str) -> None:
    if not isinstance(value, str) or _KEY_ID.fullmatch(value) is None:
        raise ValueError("%s ID is invalid" % label)


def _require_utc(value: object, label: str) -> None:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() != timedelta(0)
    ):
        raise ValueError("%s must be aware UTC" % label)


def _require_https_url(value: object, label: str) -> None:
    if not isinstance(value, str) or len(value) > 2048:
        raise ValueError("%s is invalid" % label)
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        raise ValueError("%s must be a closed HTTPS URL" % label)


def _optional_text(value: Optional[object]) -> str:
    return "" if value is None else str(value)


def _optional_hex(value: Optional[bytes]) -> str:
    return "" if value is None else value.hex()


def _reset_connection(connection: Any) -> None:
    connection.execute("RESET ROLE")
    connection.execute("RESET ALL")
    connection.execute("DISCARD TEMP")
