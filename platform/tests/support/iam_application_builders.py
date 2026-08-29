"""Deterministic fact builders for IAM application-level semantic tests.

The builders in this module only preload facts that an OIDC callback and policy
publication would already have produced.  They deliberately do not decide whether
an invitation may be accepted or derive any authorization facts; those are the
responsibility of the production handler under test.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import inspect
from typing import Dict, Mapping, Optional, Sequence, Tuple

from desire_platform.identity_access.adapters.memory import (
    FaultInjector,
    InMemoryIamStore,
    MemoryUnitOfWorkFactory,
)
from desire_platform.identity_access.application.access_invitations import (
    AcceptAccessInvitationCommand,
    AcceptAccessInvitationHandler,
    ActorContext,
)
from desire_platform.identity_access.domain.invitations import (
    AccessInvitation,
    InvitationPurpose,
    InvitationStatus,
    TargetRole,
    TargetScope,
)
from desire_platform.identity_access.domain.policies import (
    ConsentOffer,
    ConsentOfferChoice,
    PolicyAcceptance,
    PolicyBundle,
    PolicyDocument,
    PolicyLegalEffect,
)
from desire_platform.identity_access.ports.safety_hold import (
    HoldDecision,
    StrictFakeSafetyHold,
)
from desire_platform.identity_access.security.cryptography import (
    KeyUnavailableError,
    RECEIPT_CANONICALIZATION_VERSION,
    accept_payload_hash as production_accept_payload_hash,
    canonical_accept_payload_bytes,
    csrf_digest as production_csrf_digest,
    derive_csrf_token as production_derive_csrf_token,
    idempotency_key_digest as production_idempotency_key_digest,
    session_handle_digest as production_session_handle_digest,
)


UTC_NOW = datetime(2026, 8, 7, 10, 30, tzinfo=timezone.utc)
PILOT_ENDS_AT = datetime(2026, 12, 31, 23, 59, tzinfo=timezone.utc)
TERMS_HASH = "a" * 64
PRIVACY_HASH = "b" * 64
RESEARCH_CONSENT_HASH = "c" * 64
HOLD_POLICY_VERSION = "safety-hold-v1"
RECEIPT_HASH_KEY_ID = "iam-command-receipt-hmac-2026-01"
SESSION_HANDLE_HASH_KEY_ID = "iam-session-handle-hmac-2026-01"
CSRF_KEY_ID = "iam-session-csrf-hmac-2026-01"
CREATOR_POLICY_SELECTOR_DIGEST = (
    "963381c9f1ac91b81159da1dd9309d2b49f3904e416a2e38a41a9bd5bf139d0c"
)
ORG_ADMIN_POLICY_SELECTOR_DIGEST = (
    "8cd9f3eb75f06804d9ea541649dffc57dfb71cce0f4f20b6d831c5be6287d0f2"
)
DEMAND_OWNER_POLICY_SELECTOR_DIGEST = (
    "25bb8b8d9e123076604b335e9ac6d19b348550643d9fcba7e3504819ace0e117"
)
# A different, valid published selector used to prove exact-digest binding.
OTHER_POLICY_SELECTOR_DIGEST = ORG_ADMIN_POLICY_SELECTOR_DIGEST


class FixedUtcClock:
    """A deterministic, aware UTC server clock."""

    def __init__(self, current: datetime = UTC_NOW) -> None:
        if current.tzinfo is None or current.utcoffset() != timedelta(0):
            raise ValueError("FixedUtcClock requires an aware UTC datetime")
        self._current = current

    def now(self) -> datetime:
        return self._current


class FixedIdSource:
    """Returns predeclared opaque IDs by fact kind and rejects hidden allocation."""

    def __init__(self, values: Mapping[str, Sequence[str]]) -> None:
        self._remaining: Dict[str, list[str]] = {
            kind: list(kind_values) for kind, kind_values in values.items()
        }
        self.calls: list[str] = []

    def new_id(self, kind: str) -> str:
        self.calls.append(kind)
        remaining = self._remaining.get(kind)
        if not remaining:
            raise AssertionError("unexpected or exhausted ID kind: %s" % kind)
        return remaining.pop(0)


class FixedSecretSource:
    """Deterministic entropy source; it contains no IAM policy or crypto logic."""

    def __init__(self, seed: bytes = b"synthetic-iam-acceptance-seed-v1") -> None:
        self._seed = seed
        self._counts: Dict[str, int] = {}
        self.calls: list[Tuple[str, int]] = []

    def token_bytes(self, purpose: str, length: int) -> bytes:
        if length < 1:
            raise ValueError("secret length must be positive")
        counter = self._counts.get(purpose, 0)
        self._counts[purpose] = counter + 1
        self.calls.append((purpose, length))
        material = b""
        block = 0
        while len(material) < length:
            material += hashlib.sha256(
                self._seed
                + b"\x00"
                + purpose.encode("utf-8")
                + b"\x00"
                + str(counter).encode("ascii")
                + b"\x00"
                + str(block).encode("ascii")
            ).digest()
            block += 1
        return material[:length]


class FixedVersionedKeyring:
    """Stable test-only keys that survive handler/process reconstruction.

    Entropy creates new handles and salts; it must never create the long-lived
    keys used to find a persisted receipt or validate a persisted Session.  The
    adapter exposes explicit key IDs so rotation can retain old verification keys.
    """

    idempotency_key_digest_key_id = RECEIPT_HASH_KEY_ID
    payload_hash_key_id = RECEIPT_HASH_KEY_ID
    session_handle_digest_key_id = SESSION_HANDLE_HASH_KEY_ID
    csrf_key_id = CSRF_KEY_ID

    _default_keys = {
        RECEIPT_HASH_KEY_ID: hashlib.sha256(
            b"synthetic-iam-command-receipt-key-v1"
        ).digest(),
        SESSION_HANDLE_HASH_KEY_ID: hashlib.sha256(
            b"synthetic-iam-session-handle-key-v1"
        ).digest(),
        CSRF_KEY_ID: hashlib.sha256(
            b"synthetic-iam-session-csrf-key-v1"
        ).digest(),
    }

    def __init__(self) -> None:
        self._keys = dict(self._default_keys)

    def remove_key_material(self, key_id: str) -> None:
        """Model a known configured key version whose material is unavailable."""

        self._keys.pop(key_id, None)

    def keyed_digest_hex(self, *, key_id: str, canonical_bytes: bytes) -> str:
        try:
            key = self._keys[key_id]
        except KeyError as error:
            raise KeyUnavailableError(
                "unavailable fixed IAM key id: %s" % key_id
            ) from error
        return hmac.new(key, canonical_bytes, hashlib.sha256).hexdigest()

    def idempotency_key_digest(self, raw_key: str) -> str:
        return production_idempotency_key_digest(self, raw_key)

    def accept_payload_hash(self, command: AcceptAccessInvitationCommand) -> str:
        return production_accept_payload_hash(self, command)

    def session_handle_digest(self, raw_session_handle: str) -> str:
        return production_session_handle_digest(self, raw_session_handle)

    def derive_csrf_token(
        self,
        *,
        raw_session_handle: str,
        csrf_salt,
        session_id: str,
        generation: int,
        key_id: str,
    ) -> str:
        return production_derive_csrf_token(
            self,
            raw_session_handle=raw_session_handle,
            csrf_salt=csrf_salt,
            session_id=session_id,
            generation=generation,
            key_id=key_id,
        )

    def csrf_digest(self, *, csrf_token: str, key_id: str) -> str:
        return production_csrf_digest(
            self,
            csrf_token=csrf_token,
            key_id=key_id,
        )


@dataclass(frozen=True)
class FixtureIds:
    # Keep fixture identifiers valid against the public OpaqueId contracts so
    # application-event/DTO tests cannot pass with values the wire rejects.
    user_id: str = "user_accept_0001"
    contact_point_id: str = "contact_accept_001"
    auth_transaction_id: str = "auth_tx_accept_001"
    session_family_id: str = "session_family_accept_001"
    session_id: str = "session_accept_bound_001"
    successor_session_id: str = "session_accept_successor_002"
    fresh_login_family_id: str = "session_family_fresh_login_001"
    fresh_login_session_id: str = "session_fresh_login_001"
    invitation_id: str = "access_invitation_accept_001"
    organization_id: str = "organization_initial_admin_001"
    policy_bundle_id: str = "policy_bundle_onboarding_v1"
    current_policy_bundle_id: str = "policy_bundle_onboarding_v2"
    terms_document_id: str = "policy_terms_v01"
    privacy_document_id: str = "policy_privacy_v1"
    research_document_id: str = "policy_research_consent_v1"
    research_offer_id: str = "consent_offer_research_v1"
    research_controller_id: str = "research_controller_v1"
    terms_acceptance_id: str = "policy_acceptance_terms_001"
    privacy_acceptance_id: str = "policy_acceptance_privacy_001"
    consent_grant_id: str = "consent_grant_research_001"
    user_role_grant_id: str = "user_role_grant_creator_001"
    membership_id: str = "membership_initial_admin_001"
    membership_role_grant_id: str = "membership_role_grant_admin_001"
    command_receipt_id: str = "command_receipt_accept_001"
    audit_event_id: str = "audit_accept_001"


@dataclass
class AcceptanceFixture:
    """All dependencies and stable identifiers for one isolated command test."""

    ids: FixtureIds
    invitation: AccessInvitation
    policy_selector_digest: str
    policy_bundle: PolicyBundle
    store: InMemoryIamStore
    fault_injector: FaultInjector
    hold: StrictFakeSafetyHold
    clock: FixedUtcClock
    id_source: FixedIdSource
    secret_source: FixedSecretSource
    keyring: FixedVersionedKeyring
    actor: ActorContext
    command: AcceptAccessInvitationCommand
    handler: AcceptAccessInvitationHandler

    def actor_for_session(
        self,
        session_id: str,
        *,
        correlation_id: str = "correlation_accept_retry_002",
        causation_id: str = "causation_accept_retry_002",
        trace_id: str = "trace_accept_retry_002",
    ) -> ActorContext:
        return ActorContext(
            actor_id=self.ids.user_id,
            session_id=session_id,
            original_actor_id=None,
            correlation_id=correlation_id,
            causation_id=causation_id,
            trace_id=trace_id,
        )

    def seed_fresh_unbound_login(self) -> ActorContext:
        """Preload an unrelated normal-login Session for completed-receipt replay."""

        self.store.seed(
            session_families={
                self.ids.fresh_login_family_id: {
                    "session_family_id": self.ids.fresh_login_family_id,
                    "user_id": self.ids.user_id,
                    "status": "ACTIVE",
                    "current_generation": 1,
                    "aggregate_version": 1,
                }
            },
            sessions={
                self.ids.fresh_login_session_id: {
                    "session_id": self.ids.fresh_login_session_id,
                    "session_family_id": self.ids.fresh_login_family_id,
                    "user_id": self.ids.user_id,
                    "generation": 1,
                    "predecessor_session_id": None,
                    "status": "ACTIVE",
                    "verified_contact_point_id": None,
                    "verified_for_invitation_id": None,
                    "auth_transaction_id": None,
                    "auth_time": self.clock.now() - timedelta(minutes=2),
                    "acr_code": "urn:desire:acr:mfa",
                    "amr_codes": ("pwd", "otp"),
                    "created_at": self.clock.now() - timedelta(minutes=2),
                    "last_activity_at": self.clock.now() - timedelta(minutes=1),
                    "idle_expires_at": self.clock.now() + timedelta(minutes=29),
                    "absolute_expires_at": self.clock.now() + timedelta(hours=8),
                    "updated_at": self.clock.now(),
                    "handle_digest": "digest-only-fresh-login-session",
                    "handle_digest_key_id": (
                        self.keyring.session_handle_digest_key_id
                    ),
                    "csrf_salt": hashlib.sha256(
                        b"synthetic-fresh-login-csrf-salt"
                    ).digest(),
                    "csrf_key_id": self.keyring.csrf_key_id,
                    "csrf_digest": "digest-only-fresh-login-csrf",
                    "rotation_reason": "OIDC_LOGIN",
                    "aggregate_version": 1,
                }
            },
        )
        return self.actor_for_session(
            self.ids.fresh_login_session_id,
            correlation_id="correlation_accept_recovery_003",
            causation_id="causation_accept_recovery_003",
            trace_id="trace_accept_recovery_003",
        )

    def restarted_handler(
        self,
        *,
        entropy_seed: bytes = b"synthetic-independent-process-entropy-v2",
    ) -> AcceptAccessInvitationHandler:
        """Reconstruct the handler while retaining only store and versioned keys."""

        return _construct_handler(
            store=self.store,
            fault_injector=FaultInjector(),
            hold=self.hold,
            clock=self.clock,
            id_source=FixedIdSource(_generated_ids(self.ids)),
            secret_source=FixedSecretSource(seed=entropy_seed),
            keyring=self.keyring,
        )


def creator_acceptance_fixture(
    *,
    hold_decision: HoldDecision = HoldDecision.ALLOW,
    fault_injector: Optional[FaultInjector] = None,
    include_policy_selector: bool = True,
) -> AcceptanceFixture:
    """Preload exact creator-enrollment facts, including an affirmative offer choice."""

    return _acceptance_fixture(
        purpose=InvitationPurpose.CREATOR_ENROLLMENT,
        target_scope=TargetScope.USER,
        target_role=TargetRole.CREATOR,
        organization_id=None,
        is_initial_admin=False,
        include_research_consent=True,
        user_status="PENDING_ENROLLMENT",
        auth_transaction_purpose="ENROLLMENT",
        hold_decision=hold_decision,
        fault_injector=fault_injector,
        include_policy_selector=include_policy_selector,
    )


def initial_admin_acceptance_fixture(
    *,
    hold_decision: HoldDecision = HoldDecision.ALLOW,
    fault_injector: Optional[FaultInjector] = None,
) -> AcceptanceFixture:
    """Preload exact initial-ORG_ADMIN facts without opting into optional consent."""

    return _acceptance_fixture(
        purpose=InvitationPurpose.ORGANIZATION_MEMBERSHIP,
        target_scope=TargetScope.ORGANIZATION,
        target_role=TargetRole.ORG_ADMIN,
        organization_id=FixtureIds().organization_id,
        is_initial_admin=True,
        include_research_consent=False,
        user_status="PENDING_ENROLLMENT",
        auth_transaction_purpose="ENROLLMENT",
        hold_decision=hold_decision,
        fault_injector=fault_injector,
        include_policy_selector=True,
    )


def active_creator_step_up_acceptance_fixture(
    *,
    hold_decision: HoldDecision = HoldDecision.ALLOW,
    fault_injector: Optional[FaultInjector] = None,
) -> AcceptanceFixture:
    """An already ACTIVE User receives a later exact creator step-up."""

    return _acceptance_fixture(
        purpose=InvitationPurpose.CREATOR_ENROLLMENT,
        target_scope=TargetScope.USER,
        target_role=TargetRole.CREATOR,
        organization_id=None,
        is_initial_admin=False,
        include_research_consent=True,
        user_status="ACTIVE",
        auth_transaction_purpose="STEP_UP",
        hold_decision=hold_decision,
        fault_injector=fault_injector,
        include_policy_selector=True,
    )


def existing_demand_owner_acceptance_fixture(
    *,
    hold_decision: HoldDecision = HoldDecision.ALLOW,
    fault_injector: Optional[FaultInjector] = None,
) -> AcceptanceFixture:
    """ACTIVE User + exact STEP_UP accepting a non-initial DEMAND_OWNER invite."""

    return _acceptance_fixture(
        purpose=InvitationPurpose.ORGANIZATION_MEMBERSHIP,
        target_scope=TargetScope.ORGANIZATION,
        target_role=TargetRole.DEMAND_OWNER,
        organization_id=FixtureIds().organization_id,
        is_initial_admin=False,
        include_research_consent=False,
        user_status="ACTIVE",
        auth_transaction_purpose="STEP_UP",
        hold_decision=hold_decision,
        fault_injector=fault_injector,
        include_policy_selector=True,
    )


def _acceptance_fixture(
    *,
    purpose: InvitationPurpose,
    target_scope: TargetScope,
    target_role: TargetRole,
    organization_id: Optional[str],
    is_initial_admin: bool,
    include_research_consent: bool,
    user_status: str,
    auth_transaction_purpose: str,
    hold_decision: HoldDecision,
    fault_injector: Optional[FaultInjector],
    include_policy_selector: bool,
) -> AcceptanceFixture:
    ids = FixtureIds()
    clock = FixedUtcClock()
    keyring = FixedVersionedKeyring()
    policy_selector_digest = _published_policy_selector_digest(
        purpose=purpose,
        target_role=target_role,
    )
    invitation = _access_invitation_fact(
        ids=ids,
        purpose=purpose,
        target_scope=target_scope,
        target_role=target_role,
        organization_id=organization_id,
        is_initial_admin=is_initial_admin,
        clock=clock,
        policy_selector_digest=policy_selector_digest,
    )
    policy_bundle = policy_bundle_fixture(
        ids,
        policy_bundle_id=ids.policy_bundle_id,
        selector_digest=policy_selector_digest,
        status="ACTIVE",
        effective_at=clock.now() - timedelta(days=1),
        effective_until=None,
    )
    store = InMemoryIamStore()
    store.seed(
        users={
            ids.user_id: {
                "user_id": ids.user_id,
                "status": user_status,
                "aggregate_version": (
                    1 if user_status == "PENDING_ENROLLMENT" else 2
                ),
                "stable_handle": "synthetic-onboarding-user",
            }
        },
        organizations=(
            {
                ids.organization_id: {
                    "organization_id": ids.organization_id,
                    "organization_type": "BUSINESS",
                    "public_name": "Synthetic Initial Admin Organization",
                    "jurisdiction": "CN",
                    "status": "PENDING_ADMIN" if is_initial_admin else "ACTIVE",
                    "aggregate_version": 1 if is_initial_admin else 2,
                }
            }
            if organization_id is not None
            else {}
        ),
        contact_points={
            ids.contact_point_id: {
                "contact_point_id": ids.contact_point_id,
                "user_id": ids.user_id,
                "type": "EMAIL",
                "status": "VERIFIED",
            }
        },
        auth_transactions={
            ids.auth_transaction_id: {
                "auth_transaction_id": ids.auth_transaction_id,
                "purpose": auth_transaction_purpose,
                "status": "SUCCEEDED",
                "expected_user_id": ids.user_id,
                "expected_contact_point_id": ids.contact_point_id,
                "invitation_id": ids.invitation_id,
                "invitation_version": invitation.aggregate_version,
            }
        },
        session_families={
            ids.session_family_id: {
                "session_family_id": ids.session_family_id,
                "user_id": ids.user_id,
                "status": "ACTIVE",
                "current_generation": 1,
                "aggregate_version": 1,
            }
        },
        sessions={
            ids.session_id: {
                "session_id": ids.session_id,
                "session_family_id": ids.session_family_id,
                "user_id": ids.user_id,
                "generation": 1,
                "predecessor_session_id": None,
                "status": "ACTIVE",
                "verified_contact_point_id": ids.contact_point_id,
                "verified_for_invitation_id": ids.invitation_id,
                "auth_transaction_id": ids.auth_transaction_id,
                "auth_time": clock.now() - timedelta(minutes=2),
                "acr_code": "urn:desire:acr:phishing-resistant-mfa",
                "amr_codes": ("pwd", "webauthn"),
                "created_at": clock.now() - timedelta(minutes=2),
                "last_activity_at": clock.now() - timedelta(minutes=1),
                "idle_expires_at": clock.now() + timedelta(minutes=29),
                "absolute_expires_at": clock.now() + timedelta(hours=8),
                "updated_at": clock.now(),
                "handle_digest": "digest-only-bound-onboarding-session",
                "handle_digest_key_id": keyring.session_handle_digest_key_id,
                "csrf_salt": hashlib.sha256(
                    b"synthetic-bound-onboarding-csrf-salt"
                ).digest(),
                "csrf_key_id": keyring.csrf_key_id,
                "csrf_digest": "digest-only-bound-onboarding-csrf",
                "rotation_reason": auth_transaction_purpose,
                "aggregate_version": 1,
            }
        },
        invitations={ids.invitation_id: invitation},
        policy_bundles={ids.policy_bundle_id: policy_bundle},
        policy_selectors=(
            {
                policy_selector_digest: _policy_selector_fact(
                    selector_digest=policy_selector_digest,
                    purpose=purpose,
                    target_scope=target_scope,
                    target_role=target_role,
                    current_bundle_id=ids.policy_bundle_id,
                )
            }
            if include_policy_selector
            else {}
        ),
        current_policy_bundles={
            (purpose.value, target_role.value): ids.policy_bundle_id
        },
        user_role_grants={},
        memberships={},
        membership_role_grants={},
        policy_acceptances={},
        consent_grants={},
        command_receipts={},
        audit_events={},
        outbox_events={},
    )

    active_fault_injector = fault_injector or FaultInjector()
    hold = StrictFakeSafetyHold(
        decision=hold_decision,
        evaluated_at=clock.now(),
        valid_until=clock.now() + timedelta(seconds=30),
    )
    id_source = FixedIdSource(_generated_ids(ids))
    secret_source = FixedSecretSource()
    handler = _construct_handler(
        store=store,
        fault_injector=active_fault_injector,
        hold=hold,
        clock=clock,
        id_source=id_source,
        secret_source=secret_source,
        keyring=keyring,
    )
    actor = ActorContext(
        actor_id=ids.user_id,
        session_id=ids.session_id,
        original_actor_id=None,
        correlation_id="correlation_accept_001",
        causation_id="causation_accept_001",
        trace_id="trace_accept_001",
    )
    command = AcceptAccessInvitationCommand(
        invitation_id=ids.invitation_id,
        expected_version=invitation.aggregate_version,
        idempotency_key="idem-accept-invitation-0001",
        policy_bundle_id=ids.policy_bundle_id,
        policy_acceptances=(
            PolicyAcceptance(
                document_id=ids.terms_document_id,
                content_sha256=TERMS_HASH,
                affirmed=True,
            ),
            PolicyAcceptance(
                document_id=ids.privacy_document_id,
                content_sha256=PRIVACY_HASH,
                affirmed=True,
            ),
        ),
        consent_grants=(
            (
                ConsentOfferChoice(
                    consent_offer_id=ids.research_offer_id,
                    document_id=ids.research_document_id,
                    content_sha256=RESEARCH_CONSENT_HASH,
                    affirmed=True,
                ),
            )
            if include_research_consent
            else ()
        ),
    )
    return AcceptanceFixture(
        ids=ids,
        invitation=invitation,
        policy_selector_digest=policy_selector_digest,
        policy_bundle=policy_bundle,
        store=store,
        fault_injector=active_fault_injector,
        hold=hold,
        clock=clock,
        id_source=id_source,
        secret_source=secret_source,
        keyring=keyring,
        actor=actor,
        command=command,
        handler=handler,
    )


def _construct_handler(
    *,
    store: InMemoryIamStore,
    fault_injector: FaultInjector,
    hold: StrictFakeSafetyHold,
    clock: FixedUtcClock,
    id_source: FixedIdSource,
    secret_source: FixedSecretSource,
    keyring: FixedVersionedKeyring,
) -> AcceptAccessInvitationHandler:
    """Pass the stable keyring once production exposes that dependency.

    Until then the handler remains importable and the restart/metadata tests fail
    on behavior, never because a test unconditionally supplied an unknown keyword.
    """

    arguments = {
        "uow_factory": MemoryUnitOfWorkFactory(
            store=store,
            fault_injector=fault_injector,
        ),
        "safety_hold": hold,
        "safety_hold_policy_version": HOLD_POLICY_VERSION,
        "clock": clock,
        "id_source": id_source,
        "secret_source": secret_source,
    }
    if "keyring" in inspect.signature(
        AcceptAccessInvitationHandler.__init__
    ).parameters:
        arguments["keyring"] = keyring
    return AcceptAccessInvitationHandler(**arguments)


def _access_invitation_fact(
    *,
    ids: FixtureIds,
    purpose: InvitationPurpose,
    target_scope: TargetScope,
    target_role: TargetRole,
    organization_id: Optional[str],
    is_initial_admin: bool,
    clock: FixedUtcClock,
    policy_selector_digest: str,
) -> AccessInvitation:
    """Seed the designed selector field without making a missing field an import error."""

    arguments = {
        "invitation_id": ids.invitation_id,
        "purpose": purpose,
        "target_scope": target_scope,
        "target_role": target_role,
        "organization_id": organization_id,
        "is_initial_admin": is_initial_admin,
        "recipient_contact_id": ids.contact_point_id,
        "issued_policy_bundle_id": ids.policy_bundle_id,
        "status": InvitationStatus.ISSUED,
        "expires_at": clock.now() + timedelta(days=7),
        "aggregate_version": 3,
        "created_at": clock.now() - timedelta(hours=1),
        "masked_recipient_label": "s***@example.invalid",
    }
    return _construct_fact_with_pending_fields(
        AccessInvitation,
        arguments=arguments,
        pending_fields={"policy_selector_digest": policy_selector_digest},
    )


def _published_policy_selector_digest(
    *,
    purpose: InvitationPurpose,
    target_role: TargetRole,
) -> str:
    """Return fixed digests independently generated from published selector facts."""

    digests = {
        (InvitationPurpose.CREATOR_ENROLLMENT, TargetRole.CREATOR): (
            CREATOR_POLICY_SELECTOR_DIGEST
        ),
        (InvitationPurpose.ORGANIZATION_MEMBERSHIP, TargetRole.ORG_ADMIN): (
            ORG_ADMIN_POLICY_SELECTOR_DIGEST
        ),
        (InvitationPurpose.ORGANIZATION_MEMBERSHIP, TargetRole.DEMAND_OWNER): (
            DEMAND_OWNER_POLICY_SELECTOR_DIGEST
        ),
    }
    try:
        return digests[(purpose, target_role)]
    except KeyError as error:
        raise AssertionError("fixture has no published selector digest") from error


def _policy_selector_fact(
    *,
    selector_digest: str,
    purpose: InvitationPurpose,
    target_scope: TargetScope,
    target_role: TargetRole,
    current_bundle_id: Optional[str],
) -> dict:
    """Represent immutable facts already published by the policy command."""

    return {
        "selector_digest": selector_digest,
        "canonicalization_version": "policy-selector-json-v1",
        "access_purpose": purpose.value,
        "scope_type": (
            "USER_ROLE"
            if target_scope == TargetScope.USER
            else "ORGANIZATION_ROLE"
        ),
        "target_role": target_role.value,
        "jurisdiction": "CN",
        "locale": "zh-CN",
        "current_bundle_id": current_bundle_id,
        "aggregate_version": 1,
    }


def policy_bundle_fixture(
    ids: FixtureIds,
    *,
    policy_bundle_id: str,
    selector_digest: str,
    status: str,
    effective_at: Optional[datetime],
    effective_until: Optional[datetime],
) -> PolicyBundle:
    """Build immutable published bundle facts for selector application tests."""

    terms = PolicyDocument(
        document_id=ids.terms_document_id,
        content_sha256=TERMS_HASH,
        legal_effect=PolicyLegalEffect.CONTRACT_ACCEPTANCE,
    )
    privacy = PolicyDocument(
        document_id=ids.privacy_document_id,
        content_sha256=PRIVACY_HASH,
        legal_effect=PolicyLegalEffect.NOTICE_ACKNOWLEDGEMENT,
    )
    research = PolicyDocument(
        document_id=ids.research_document_id,
        content_sha256=RESEARCH_CONSENT_HASH,
        legal_effect=PolicyLegalEffect.CONSENT_TEXT,
    )
    research_offer = ConsentOffer.pilot_research(
        consent_offer_id=ids.research_offer_id,
        aggregate_version=1,
        supporting_document_id=research.document_id,
        supporting_document_sha256=research.content_sha256,
        recipient_reference=ids.research_controller_id,
        pilot_ends_at=PILOT_ENDS_AT,
    )
    return _construct_fact_with_pending_fields(
        PolicyBundle,
        arguments={
            "policy_bundle_id": policy_bundle_id,
            "documents": (terms, privacy, research),
            "required_document_ids": (terms.document_id, privacy.document_id),
            "consent_offers": (research_offer,),
        },
        pending_fields={
            "selector_digest": selector_digest,
            "status": status,
            "effective_at": effective_at,
            "effective_until": effective_until,
        },
    )


def _construct_fact_with_pending_fields(factory, *, arguments, pending_fields):
    """Keep RED fixtures executable while production value objects catch up.

    Every pending field is attached to the immutable test fact even before its
    constructor declares it.  A separate structural RED still requires the
    production constructor to own the field; this compatibility seam prevents
    unrelated selector tests from failing during fixture construction.
    """

    parameters = inspect.signature(factory).parameters
    constructor_arguments = dict(arguments)
    constructor_arguments.update(
        {
            name: value
            for name, value in pending_fields.items()
            if name in parameters
        }
    )
    fact = factory(**constructor_arguments)
    for name, value in pending_fields.items():
        if name not in parameters:
            object.__setattr__(fact, name, value)
    return fact


def _generated_ids(ids: FixtureIds) -> Mapping[str, Sequence[str]]:
    return {
        "policy_acceptance": (
            ids.terms_acceptance_id,
            ids.privacy_acceptance_id,
        ),
        "consent_grant": (ids.consent_grant_id,),
        "user_role_grant": (ids.user_role_grant_id,),
        "membership": (ids.membership_id,),
        "membership_role_grant": (ids.membership_role_grant_id,),
        "session": (ids.successor_session_id,),
        "command_receipt": (ids.command_receipt_id,),
        "audit_event": (ids.audit_event_id,),
        "outbox_event": tuple(
            "outbox_accept_%03d" % number for number in range(1, 10)
        ),
    }
