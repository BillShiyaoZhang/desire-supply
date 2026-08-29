"""Strict, independent security fixtures for the second Issue RED cycle.

This module wraps (but never changes) the first-cycle policy/issue fixture.  It
adds persisted USER authentication facts, a shared ordering timeline, rich
SafetyHold scripting, a rotating invitation-token keyring, and a closed SYSTEM
operation credential.  Every fake accepts the currently implemented call
shape so missing production semantics appear as assertions rather than fixture
or signature errors.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from typing import Any, Mapping, Optional, Tuple

from desire_platform.identity_access.application.issue_access_invitations import (
    InvitationIssuerContext,
    IssueAccessInvitationHandler,
    IssuerKind,
)
from desire_platform.identity_access.ports.safety_hold import (
    HoldDecision,
    SafetyHoldDecisionResult,
    SafetyHoldQuery,
    SafetyHoldUnavailableError,
)
from desire_platform.identity_access.security.cryptography import (
    KeyUnavailableError,
)
from tests.support.iam_policy_issue_builders import (
    SAFETY_HOLD_POLICY_VERSION,
    UTC_NOW,
    IssueFixture,
    creator_issue_fixture,
    organization_issue_fixture,
)


USER_ID = "user_issuer_admin_001"
SESSION_ID = "session_issuer_001"
SESSION_FAMILY_ID = "session_family_issuer_001"
MEMBERSHIP_ID = "membership_issuer_admin_001"
ROLE_GRANT_ID = "membership_role_issuer_admin_001"
ACTIVE_TOKEN_KEY_ID = "iam-access-invitation-token-2026-01"
ROTATED_TOKEN_KEY_ID = "iam-access-invitation-token-2026-02"
TOKEN_FORMAT_VERSION = "access-invitation-token-v1"


@dataclass(frozen=True)
class SystemOperationCredential:
    """Test-side closed value expected from authenticated workload policy."""

    credential_id: str
    system_id: str
    operation: str
    allowed_purposes: Tuple[str, ...]
    status: str
    valid_from: datetime
    valid_until: datetime


@dataclass(frozen=True)
class CredentialedSystemIssuer:
    """Duck-compatible actor that carries the missing formal credential."""

    actor_kind: IssuerKind
    actor_id: str
    session_id: Optional[str]
    original_actor_id: Optional[str]
    correlation_id: str
    causation_id: str
    trace_id: str
    auth_time: datetime
    acr_code: str
    amr_codes: Tuple[str, ...]
    operation_credential: Optional[SystemOperationCredential]


class TimelineUowFactory:
    """Records the first transaction boundary while preserving the strict UoW."""

    def __init__(self, delegate, timeline: list[str]) -> None:
        self.delegate = delegate
        self.timeline = timeline
        self.store = delegate.store

    @property
    def begin_count(self) -> int:
        return self.delegate.begin_count

    @property
    def commit_count(self) -> int:
        return self.delegate.commit_count

    @property
    def lock_calls(self):
        return self.delegate.lock_calls

    @property
    def write_calls(self):
        return self.delegate.write_calls

    def begin(self):
        self.timeline.append("uow.begin")
        return self.delegate.begin()


class TimelineIdSource:
    def __init__(self, delegate, timeline: list[str]) -> None:
        self.delegate = delegate
        self.timeline = timeline

    @property
    def calls(self):
        return self.delegate.calls

    def new_id(self, kind: str) -> str:
        self.timeline.append("id:" + kind)
        return self.delegate.new_id(kind)


class ScriptedIssueSafetyHold:
    """Returns a rich result while allowing one exact response-field mutation."""

    def __init__(
        self,
        *,
        timeline: list[str],
        decision: HoldDecision = HoldDecision.ALLOW,
        overrides: Optional[Mapping[str, Any]] = None,
        unavailable_error: bool = False,
    ) -> None:
        self.timeline = timeline
        self.decision = decision
        self.overrides = dict(overrides or {})
        self.unavailable_error = unavailable_error
        self.calls: list[SafetyHoldQuery] = []

    def evaluate(
        self,
        *,
        actor_id: str,
        action: str,
        target_type: str,
        target_id: str,
        target_version: int,
        organization_id: Optional[str],
        policy_version: str,
    ) -> SafetyHoldDecisionResult:
        self.timeline.append("hold.evaluate")
        query = SafetyHoldQuery(
            actor_id=actor_id,
            action=action,
            target_type=target_type,
            target_id=target_id,
            target_version=target_version,
            organization_id=organization_id,
            policy_version=policy_version,
        )
        self.calls.append(query)
        if self.unavailable_error:
            raise SafetyHoldUnavailableError("scripted unavailable")
        values = {
            "decision": self.decision,
            "action": action,
            "target_type": target_type,
            "target_id": target_id,
            "target_version": target_version,
            "organization_id": organization_id,
            "policy_version": policy_version,
            "evaluated_at": UTC_NOW,
            "valid_until": UTC_NOW + timedelta(seconds=30),
        }
        values.update(self.overrides)
        return SafetyHoldDecisionResult(**values)


class RotatingInvitationTokenCodec:
    """Retains old key/format material and records explicit selection."""

    def __init__(self) -> None:
        self.active_key_id = ACTIVE_TOKEN_KEY_ID
        self.active_format_version = TOKEN_FORMAT_VERSION
        self.retained: dict[tuple[str, str], bytes] = {
            (TOKEN_FORMAT_VERSION, ACTIVE_TOKEN_KEY_ID): b"old-key-material",
            (TOKEN_FORMAT_VERSION, ROTATED_TOKEN_KEY_ID): b"new-key-material",
        }
        self.calls: list[dict[str, Any]] = []

    @property
    def key_id(self) -> str:
        return self.active_key_id

    @property
    def format_version(self) -> str:
        return self.active_format_version

    def rotate(self) -> None:
        self.active_key_id = ROTATED_TOKEN_KEY_ID

    def drop_key(self, key_id: str) -> None:
        self.retained.pop((TOKEN_FORMAT_VERSION, key_id), None)

    def issue(
        self,
        *,
        invitation_id: str,
        nonce: str,
        expires_at: datetime,
        token_key_id: Optional[str] = None,
        token_format_version: Optional[str] = None,
    ) -> str:
        selected_key = token_key_id or self.active_key_id
        selected_format = token_format_version or self.active_format_version
        call = {
            "invitation_id": invitation_id,
            "nonce": nonce,
            "expires_at": expires_at,
            "token_key_id": selected_key,
            "token_format_version": selected_format,
            "explicit_key_id": token_key_id is not None,
            "explicit_format_version": token_format_version is not None,
        }
        self.calls.append(call)
        if (selected_format, selected_key) not in self.retained:
            raise KeyUnavailableError("retained invitation-token key unavailable")
        return "test-capability.%s.%s.%s.%s" % (
            selected_format,
            selected_key,
            invitation_id,
            nonce,
        )


@dataclass
class SecureIssueFixture:
    base: IssueFixture
    timeline: list[str]
    token_codec: RotatingInvitationTokenCodec
    hold: ScriptedIssueSafetyHold
    actor: Any

    def __getattr__(self, name: str) -> Any:
        return getattr(self.base, name)


def secure_user_issue_fixture(
    *,
    hold_decision: HoldDecision = HoldDecision.ALLOW,
    hold_overrides: Optional[Mapping[str, Any]] = None,
    hold_unavailable_error: bool = False,
) -> SecureIssueFixture:
    base = organization_issue_fixture()
    _seed_active_user_session(base)
    return _secure_fixture(
        base,
        actor=base.actor,
        hold_decision=hold_decision,
        hold_overrides=hold_overrides,
        hold_unavailable_error=hold_unavailable_error,
    )


def secure_system_issue_fixture(
    *,
    credential: Any = "valid",
) -> SecureIssueFixture:
    base = creator_issue_fixture()
    operation_credential = (
        valid_system_operation_credential(base.actor.actor_id)
        if credential == "valid"
        else credential
    )
    actor = credentialed_system_actor(
        base.actor,
        credential=operation_credential,
    )
    return _secure_fixture(base, actor=actor)


def valid_system_operation_credential(
    system_id: str = "system_invitation_issuer_001",
) -> SystemOperationCredential:
    return SystemOperationCredential(
        credential_id="system_operation_credential_issue_001",
        system_id=system_id,
        operation="IssueAccessInvitation",
        allowed_purposes=("CREATOR_ENROLLMENT",),
        status="ACTIVE",
        valid_from=UTC_NOW - timedelta(minutes=5),
        valid_until=UTC_NOW + timedelta(minutes=5),
    )


def credentialed_system_actor(
    actor: InvitationIssuerContext,
    *,
    credential: Optional[SystemOperationCredential],
) -> CredentialedSystemIssuer:
    return CredentialedSystemIssuer(
        actor_kind=actor.actor_kind,
        actor_id=actor.actor_id,
        session_id=actor.session_id,
        original_actor_id=actor.original_actor_id,
        correlation_id=actor.correlation_id,
        causation_id=actor.causation_id,
        trace_id=actor.trace_id,
        auth_time=actor.auth_time,
        acr_code=actor.acr_code,
        amr_codes=actor.amr_codes,
        operation_credential=credential,
    )


def with_transport_auth(
    actor: InvitationIssuerContext,
    *,
    auth_time: datetime,
    acr_code: str,
    amr_codes: Tuple[str, ...],
) -> InvitationIssuerContext:
    return replace(
        actor,
        auth_time=auth_time,
        acr_code=acr_code,
        amr_codes=amr_codes,
    )


def receipt_row(fixture: SecureIssueFixture) -> dict[str, Any]:
    return next(
        iter(fixture.store._tables.get("command_receipts", {}).values())
    )


def invitation_row(fixture: SecureIssueFixture):
    return next(iter(fixture.store._tables.get("invitations", {}).values()))


def replace_invitation(fixture: SecureIssueFixture, **changes: Any) -> None:
    invitation = invitation_row(fixture)
    fixture.store._tables["invitations"][invitation.invitation_id] = replace(
        invitation,
        **changes,
    )


def update_row(
    fixture: SecureIssueFixture,
    table: str,
    key: str,
    **changes: Any,
) -> None:
    row = dict(fixture.store._tables[table][key])
    row.update(changes)
    fixture.store._tables[table][key] = row


def expected_user_lock_order(fixture: SecureIssueFixture) -> list[tuple[str, str]]:
    return [
        ("session_families", SESSION_FAMILY_ID),
        ("sessions", SESSION_ID),
        ("users", USER_ID),
        ("organizations", fixture.command.organization_id),
        ("memberships", MEMBERSHIP_ID),
        ("membership_role_grants", ROLE_GRANT_ID),
        ("policy_selectors", fixture.selector_digest),
        ("policy_bundles", fixture.current_bundle.policy_bundle_id),
    ]


def _secure_fixture(
    base: IssueFixture,
    *,
    actor: Any,
    hold_decision: HoldDecision = HoldDecision.ALLOW,
    hold_overrides: Optional[Mapping[str, Any]] = None,
    hold_unavailable_error: bool = False,
) -> SecureIssueFixture:
    timeline: list[str] = []
    token_codec = RotatingInvitationTokenCodec()
    hold = ScriptedIssueSafetyHold(
        timeline=timeline,
        decision=hold_decision,
        overrides=hold_overrides,
        unavailable_error=hold_unavailable_error,
    )
    uow_factory = TimelineUowFactory(base.uow_factory, timeline)
    id_source = TimelineIdSource(base.id_source, timeline)
    base.uow_factory = uow_factory
    base.id_source = id_source
    base.hold = hold
    base.token_codec = token_codec
    base.actor = actor
    base.handler = IssueAccessInvitationHandler(
        uow_factory=uow_factory,
        clock=base.clock,
        platform_enrollment_policy=base.platform_policy,
        locale_resolver=base.locale_resolver,
        safety_hold=hold,
        safety_hold_policy_version=SAFETY_HOLD_POLICY_VERSION,
        release_token_codec=token_codec,
        recipient_binding=base.recipient_binding,
        receipt_codec=base.receipt_codec,
        id_source=id_source,
        secret_source=base.secret_source,
    )
    return SecureIssueFixture(
        base=base,
        timeline=timeline,
        token_codec=token_codec,
        hold=hold,
        actor=actor,
    )


def _seed_active_user_session(base: IssueFixture) -> None:
    base.store.seed(
        users={
            USER_ID: {
                "user_id": USER_ID,
                "status": "ACTIVE",
                "stable_handle": "issuer-admin",
                "aggregate_version": 7,
                "created_at": UTC_NOW - timedelta(days=90),
                "updated_at": UTC_NOW - timedelta(days=1),
            }
        },
        session_families={
            SESSION_FAMILY_ID: {
                "session_family_id": SESSION_FAMILY_ID,
                "user_id": USER_ID,
                "status": "ACTIVE",
                "current_generation": 3,
                "revoked_at": None,
                "revocation_reason_code": None,
                "aggregate_version": 3,
            }
        },
        sessions={
            SESSION_ID: {
                "session_id": SESSION_ID,
                "session_family_id": SESSION_FAMILY_ID,
                "user_id": USER_ID,
                "generation": 3,
                "predecessor_session_id": "session_issuer_previous_0002",
                "status": "ACTIVE",
                "auth_time": UTC_NOW - timedelta(minutes=2),
                "acr_code": "urn:desire:acr:mfa",
                "amr_codes": ("pwd", "otp"),
                "created_at": UTC_NOW - timedelta(minutes=2),
                "last_activity_at": UTC_NOW - timedelta(minutes=1),
                "idle_expires_at": UTC_NOW + timedelta(minutes=29),
                "absolute_expires_at": UTC_NOW + timedelta(hours=8),
                "updated_at": UTC_NOW - timedelta(minutes=1),
                "handle_digest": "persisted-session-handle-digest-only",
                "handle_digest_key_id": "session-handle-key-2026-01",
                "csrf_salt": b"s" * 32,
                "csrf_key_id": "session-csrf-key-2026-01",
                "csrf_digest": "persisted-csrf-digest-only",
                "verified_contact_point_id": None,
                "verified_for_invitation_id": None,
                "auth_transaction_id": None,
                "rotation_reason": "OIDC_LOGIN",
                "aggregate_version": 3,
            }
        },
    )
