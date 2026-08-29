"""Strict synthetic fixtures for the OIDC/AuthTransaction semantic RED."""

from __future__ import annotations

import base64
from copy import deepcopy
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import threading
from typing import Any, Mapping, Optional

from desire_platform.identity_access.adapters.fake_oidc import (
    DeterministicFakeOidcProvider,
    FakeOidcCode,
)
from desire_platform.identity_access.application.authentication import (
    BeginOidcAuthorizationCommand,
    BeginOidcAuthorizationHandler,
    CompleteOidcAuthenticationCommand,
    CompleteOidcAuthenticationHandler,
    OidcBrowserContext,
    OidcSecurityPolicy,
)
from desire_platform.identity_access.domain.errors import IamError
from desire_platform.identity_access.domain.invitations import (
    AccessInvitation,
    InvitationPurpose,
    InvitationStatus,
    TargetRole,
    TargetScope,
)
from desire_platform.identity_access.ports.access_invitation_capability import (
    VerifiedAccessInvitationCapability,
)
from desire_platform.identity_access.ports.identity_provider import (
    AuthenticatedSubject,
    ProviderExchangeRequest,
)
from desire_platform.identity_access.ports.recipient_binding import (
    RecipientBindingTuple,
)
from desire_platform.identity_access.security.cryptography import (
    session_handle_digest,
)


UTC_NOW = datetime(2026, 8, 8, 9, 0, tzinfo=timezone.utc)
AUTH_TRANSACTION_ID = "auth_transaction_oidc_0001"
INVITATION_ID = "access_invitation_oidc_0001"
CONTACT_POINT_ID = "contact_point_oidc_0001"
OTHER_CONTACT_POINT_ID = "contact_point_oidc_other_0002"
USER_ID = "user_oidc_existing_0001"
OTHER_USER_ID = "user_oidc_other_0002"
PENDING_USER_ID = "user_oidc_pending_0003"
SESSION_FAMILY_ID = "session_family_oidc_0001"
SESSION_ID = "session_oidc_current_0001"
SUCCESSOR_SESSION_ID = "session_oidc_successor_0002"
NEW_SESSION_FAMILY_ID = "session_family_oidc_new_0002"
NEW_SESSION_ID = "session_oidc_new_0003"
EXTERNAL_IDENTITY_ID = "external_identity_oidc_0001"
PROVIDER_ISSUER = "https://fake-idp.example.test"
PROVIDER_AUDIENCE = "desire-supply-synthetic-client"
REDIRECT_URI = "https://app.example.test/v1/auth/oidc/callback"
RETURN_TO = "/join"
RAW_SESSION_HANDLE = "session_handle_synthetic_00000000000000000001"
RAW_BROWSER_COOKIE = "browser_binding_synthetic_000000000000000001"
RAW_STATE = "state_synthetic_000000000000000000000000001"
RAW_NONCE = "nonce_synthetic_00000000000000000000000001"
RAW_CODE_VERIFIER = "verifier_synthetic_000000000000000000000001"
RAW_CODE = "code_synthetic_00000000000000000000000001"
RAW_INVITATION_TOKEN = "invitation_token_synthetic_00000000000000001"
SUBJECT_DIGEST_KEY_ID = "oidc-subject-digest-2026-01"
BINDING_DIGEST_KEY_ID = "recipient-binding-digest-2026-01"
SESSION_HANDLE_KEY_ID = "session-handle-digest-2026-01"
CSRF_KEY_ID = "session-csrf-digest-2026-01"
STATE_KEY_ID = "oidc-state-digest-2026-01"
BROWSER_KEY_ID = "oidc-browser-digest-2026-01"
PROTOCOL_ENCRYPTION_KEY_ID = "oidc-protocol-encryption-2026-01"
TOKEN_KEY_ID = "access-invitation-token-2026-01"
TOKEN_FORMAT_VERSION = "access-invitation-token-v1"
CONTACT_DIGEST = hashlib.sha256(b"applicant@example.test").hexdigest()
SUBJECT_DIGEST = hashlib.sha256(b"synthetic-subject-0001").hexdigest()


class FixedUtcClock:
    def now(self) -> datetime:
        return UTC_NOW


class AuthStore:
    def __init__(self) -> None:
        self._tables: dict[str, dict[Any, Any]] = {}
        self.transaction_lock = threading.RLock()

    def seed(self, **tables: Mapping[Any, Any]) -> None:
        for name, rows in tables.items():
            self._tables.setdefault(name, {}).update(deepcopy(dict(rows)))

    def snapshot(self) -> dict[str, dict[Any, Any]]:
        return deepcopy(self._tables)


class RecordingAuthUowFactory:
    def __init__(self, store: AuthStore) -> None:
        self.store = store
        self.begin_count = 0
        self.commit_count = 0
        self.lock_calls: list[tuple[str, Any]] = []
        self.write_calls: list[tuple[str, Any, str]] = []
        self.timeline: list[str] = []
        self.commit_unknown_at: set[int] = set()

    def snapshot(self) -> dict[str, dict[Any, Any]]:
        return self.store.snapshot()

    def begin(self) -> "RecordingAuthUow":
        self.begin_count += 1
        self.timeline.append("uow.begin")
        return RecordingAuthUow(self)


class RecordingAuthUow:
    def __init__(self, factory: RecordingAuthUowFactory) -> None:
        self.factory = factory
        self.tables: dict[str, dict[Any, Any]] = {}
        self.committed = False
        self._entered = False

    def __enter__(self) -> "RecordingAuthUow":
        self.factory.store.transaction_lock.acquire()
        self._entered = True
        self.tables = self.factory.store.snapshot()
        return self

    def __exit__(self, exception_type, exception, traceback) -> bool:
        try:
            if exception_type is None and self.committed:
                self.factory.store._tables = self.tables
        finally:
            if self._entered:
                self.factory.store.transaction_lock.release()
                self._entered = False
        return False

    def lock(self, table: str, key: Any) -> Any:
        self.factory.lock_calls.append((table, key))
        return self.tables.get(table, {}).get(key)

    def put(
        self,
        table: str,
        key: Any,
        value: Any,
        *,
        checkpoint: str,
    ) -> None:
        self.factory.write_calls.append((table, key, checkpoint))
        self.tables.setdefault(table, {})[key] = deepcopy(value)

    def commit(self) -> None:
        self.factory.commit_count += 1
        self.factory.timeline.append("uow.commit")
        self.committed = True
        if self.factory.commit_count in self.factory.commit_unknown_at:
            self.factory.store._tables = deepcopy(self.tables)
            raise RuntimeError("synthetic commit outcome unknown")


class FixedIdSource:
    def __init__(self) -> None:
        self.values = {
            "auth_transaction": [AUTH_TRANSACTION_ID],
            "exchange_owner": ["exchange_owner_oidc_0001"],
            "user": [PENDING_USER_ID],
            "external_identity": [EXTERNAL_IDENTITY_ID],
            "session_family": [NEW_SESSION_FAMILY_ID],
            "session": [NEW_SESSION_ID],
            "successor_session": [SUCCESSOR_SESSION_ID],
            "security_audit_event": [
                "security_audit_oidc_begin_0001",
                "security_audit_oidc_complete_0002",
            ],
        }
        self.calls: list[str] = []

    def new_id(self, kind: str) -> str:
        self.calls.append(kind)
        try:
            return self.values[kind].pop(0)
        except (KeyError, IndexError) as error:
            raise AssertionError("unexpected auth ID allocation: " + kind) from error


class FixedSecretSource:
    def __init__(self) -> None:
        self.calls: list[tuple[str, int]] = []

    def token_bytes(self, purpose: str, length: int) -> bytes:
        self.calls.append((purpose, length))
        seed = hashlib.sha256(("oidc-red:" + purpose).encode("utf-8")).digest()
        return (seed * ((length // len(seed)) + 1))[:length]


class FixedProtocolKeyring:
    state_digest_key_id = STATE_KEY_ID
    browser_binding_digest_key_id = BROWSER_KEY_ID
    subject_digest_key_id = SUBJECT_DIGEST_KEY_ID
    session_handle_digest_key_id = SESSION_HANDLE_KEY_ID
    csrf_key_id = CSRF_KEY_ID

    def __init__(self) -> None:
        self.keys = {
            STATE_KEY_ID: b"state-key",
            BROWSER_KEY_ID: b"browser-key",
            SUBJECT_DIGEST_KEY_ID: b"subject-key",
            SESSION_HANDLE_KEY_ID: b"session-key",
            CSRF_KEY_ID: b"csrf-key",
        }

    def keyed_digest_hex(self, *, key_id: str, canonical_bytes: bytes) -> str:
        try:
            key = self.keys[key_id]
        except KeyError as error:
            raise IamError("SERVICE_UNAVAILABLE") from error
        return hmac.new(key, canonical_bytes, hashlib.sha256).hexdigest()

    def digest_text(self, *, key_id: str, value: str) -> str:
        return self.keyed_digest_hex(
            key_id=key_id,
            canonical_bytes=value.encode("utf-8"),
        )


class FixedProtocolSecretBox:
    key_id = PROTOCOL_ENCRYPTION_KEY_ID

    def __init__(self) -> None:
        self.available = True

    def encrypt(self, *, plaintext: str, key_id: Optional[str] = None) -> str:
        if not self.available or key_id not in (None, self.key_id):
            raise IamError("SERVICE_UNAVAILABLE")
        return "ciphertext:" + base64.urlsafe_b64encode(
            plaintext.encode("utf-8")
        ).decode("ascii")

    def decrypt(self, *, ciphertext: str, key_id: str) -> str:
        if not self.available or key_id != self.key_id:
            raise IamError("SERVICE_UNAVAILABLE")
        encoded = ciphertext.removeprefix("ciphertext:")
        return base64.urlsafe_b64decode(encoded.encode("ascii")).decode("utf-8")


class StrictRecipientBinding:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    def bind_verified(
        self,
        *,
        contact_type: str,
        verified_locator: str,
    ) -> RecipientBindingTuple:
        self.calls.append((contact_type, verified_locator))
        normalized = verified_locator.strip().casefold()
        return RecipientBindingTuple(
            contact_type=contact_type,
            binding_digest=hashlib.sha256(normalized.encode("utf-8")).hexdigest(),
            digest_key_id=BINDING_DIGEST_KEY_ID,
        )


class StrictInvitationCapability:
    def __init__(self) -> None:
        self.calls = 0
        self.unavailable = False

    def verify(
        self,
        *,
        access_invitation_token: str,
        now: datetime,
    ) -> VerifiedAccessInvitationCapability:
        self.calls += 1
        if self.unavailable or access_invitation_token != RAW_INVITATION_TOKEN:
            raise IamError("ACCESS_INVITATION_UNAVAILABLE")
        return VerifiedAccessInvitationCapability(
            invitation_id=INVITATION_ID,
            invitation_nonce=hashlib.sha256(b"oidc-invitation-nonce").hexdigest(),
            expires_at=UTC_NOW + timedelta(days=7),
            token_key_id=TOKEN_KEY_ID,
            token_format_version=TOKEN_FORMAT_VERSION,
        )


@dataclass
class AuthenticationFixture:
    store: AuthStore
    uow_factory: RecordingAuthUowFactory
    clock: FixedUtcClock
    provider: DeterministicFakeOidcProvider
    recipient_binding: StrictRecipientBinding
    invitation_capability: StrictInvitationCapability
    protocol_keyring: FixedProtocolKeyring
    protocol_secret_box: FixedProtocolSecretBox
    id_source: FixedIdSource
    secret_source: FixedSecretSource
    security_policy: OidcSecurityPolicy
    begin_handler: BeginOidcAuthorizationHandler
    complete_handler: CompleteOidcAuthenticationHandler
    anonymous_context: OidcBrowserContext
    current_context: OidcBrowserContext
    begin_login_command: BeginOidcAuthorizationCommand
    begin_invitation_command: BeginOidcAuthorizationCommand
    complete_command: CompleteOidcAuthenticationCommand


def authentication_fixture() -> AuthenticationFixture:
    store = AuthStore()
    clock = FixedUtcClock()
    keyring = FixedProtocolKeyring()
    recipient_binding = StrictRecipientBinding()
    provider = DeterministicFakeOidcProvider(
        issuer=PROVIDER_ISSUER,
        audience=PROVIDER_AUDIENCE,
        recipient_binding=recipient_binding,
    )
    provider.register_code(valid_fake_code())
    capability = StrictInvitationCapability()
    uow_factory = RecordingAuthUowFactory(store)
    secret_box = FixedProtocolSecretBox()
    id_source = FixedIdSource()
    secret_source = FixedSecretSource()
    policy = OidcSecurityPolicy(
        policy_version="iam-security-v1",
        provider_issuer=PROVIDER_ISSUER,
        provider_audience=PROVIDER_AUDIENCE,
        redirect_uri=REDIRECT_URI,
        allowed_return_to=("/", "/join", "/app", "/privacy"),
    )
    store.seed(
        invitations={INVITATION_ID: valid_invitation()},
        contact_points={
            CONTACT_POINT_ID: valid_contact_point(),
            OTHER_CONTACT_POINT_ID: valid_contact_point(
                contact_point_id=OTHER_CONTACT_POINT_ID
            ),
        },
        users={},
        external_identities={},
        auth_transactions={},
        session_families={},
        sessions={},
        security_audit_events={},
    )
    begin_handler = BeginOidcAuthorizationHandler(
        uow_factory=uow_factory,
        clock=clock,
        provider=provider,
        invitation_capability=capability,
        protocol_keyring=keyring,
        protocol_secret_box=secret_box,
        id_source=id_source,
        secret_source=secret_source,
        security_policy=policy,
    )
    complete_handler = CompleteOidcAuthenticationHandler(
        uow_factory=uow_factory,
        clock=clock,
        provider=provider,
        recipient_binding=recipient_binding,
        protocol_keyring=keyring,
        protocol_secret_box=secret_box,
        session_keyring=keyring,
        id_source=id_source,
        secret_source=secret_source,
        security_policy=policy,
    )
    return AuthenticationFixture(
        store=store,
        uow_factory=uow_factory,
        clock=clock,
        provider=provider,
        recipient_binding=recipient_binding,
        invitation_capability=capability,
        protocol_keyring=keyring,
        protocol_secret_box=secret_box,
        id_source=id_source,
        secret_source=secret_source,
        security_policy=policy,
        begin_handler=begin_handler,
        complete_handler=complete_handler,
        anonymous_context=OidcBrowserContext(
            raw_session_handle=None,
            raw_oidc_browser_cookie=RAW_BROWSER_COOKIE,
            correlation_id="correlation_oidc_begin_0001",
            causation_id="causation_oidc_begin_0001",
            trace_id="trace_oidc_begin_0001",
        ),
        current_context=OidcBrowserContext(
            raw_session_handle=RAW_SESSION_HANDLE,
            raw_oidc_browser_cookie=RAW_BROWSER_COOKIE,
            correlation_id="correlation_oidc_begin_0001",
            causation_id="causation_oidc_begin_0001",
            trace_id="trace_oidc_begin_0001",
        ),
        begin_login_command=BeginOidcAuthorizationCommand(
            return_to=RETURN_TO,
        ),
        begin_invitation_command=BeginOidcAuthorizationCommand(
            return_to=RETURN_TO,
            access_invitation_token=RAW_INVITATION_TOKEN,
        ),
        complete_command=CompleteOidcAuthenticationCommand(
            state=RAW_STATE,
            code=RAW_CODE,
        ),
    )


def seed_current_session(
    fixture: AuthenticationFixture,
    *,
    user_status: str = "ACTIVE",
    session_status: str = "ACTIVE",
    family_status: str = "ACTIVE",
) -> None:
    fixture.store.seed(
        users={
            USER_ID: {
                "user_id": USER_ID,
                "status": user_status,
                "stable_handle": "synthetic-existing-user",
                "aggregate_version": 4,
                "created_at": UTC_NOW - timedelta(days=90),
                "updated_at": UTC_NOW - timedelta(days=1),
            }
        },
        session_families={
            SESSION_FAMILY_ID: {
                "session_family_id": SESSION_FAMILY_ID,
                "user_id": USER_ID,
                "status": family_status,
                "current_generation": 2,
                "aggregate_version": 2,
                "revoked_at": None,
                "revocation_reason_code": None,
            }
        },
        sessions={
            SESSION_ID: {
                "session_id": SESSION_ID,
                "session_family_id": SESSION_FAMILY_ID,
                "user_id": USER_ID,
                "generation": 2,
                "predecessor_session_id": "session_oidc_previous_0000",
                "status": session_status,
                "verified_contact_point_id": None,
                "verified_for_invitation_id": None,
                "verified_at": None,
                "auth_transaction_id": "auth_transaction_login_previous_0000",
                "auth_time": UTC_NOW - timedelta(minutes=5),
                "acr_code": "urn:desire:acr:mfa",
                "amr_codes": ("pwd", "otp"),
                "created_at": UTC_NOW - timedelta(hours=1),
                "last_activity_at": UTC_NOW - timedelta(minutes=1),
                "idle_expires_at": UTC_NOW + timedelta(minutes=29),
                "absolute_expires_at": UTC_NOW + timedelta(hours=11),
                "updated_at": UTC_NOW - timedelta(minutes=1),
                "handle_digest": session_handle_digest(
                    fixture.protocol_keyring,
                    RAW_SESSION_HANDLE,
                ),
                "handle_digest_key_id": SESSION_HANDLE_KEY_ID,
                "csrf_salt": hashlib.sha256(b"current-session-csrf").digest(),
                "csrf_key_id": CSRF_KEY_ID,
                "csrf_digest": hashlib.sha256(b"current-csrf-digest").hexdigest(),
                "rotation_reason": "OIDC_LOGIN",
                "aggregate_version": 2,
            }
        },
    )


def seed_existing_identity(
    fixture: AuthenticationFixture,
    *,
    user_id: str = USER_ID,
    user_status: str = "ACTIVE",
) -> None:
    if user_id not in fixture.store._tables.get("users", {}):
        fixture.store.seed(
            users={
                user_id: {
                    "user_id": user_id,
                    "status": user_status,
                    "stable_handle": "synthetic-existing-user",
                    "aggregate_version": 1,
                    "created_at": UTC_NOW - timedelta(days=30),
                    "updated_at": UTC_NOW - timedelta(days=1),
                }
            }
        )
    fixture.store.seed(
        external_identities={
            (PROVIDER_ISSUER, SUBJECT_DIGEST): {
                "external_identity_id": EXTERNAL_IDENTITY_ID,
                "user_id": user_id,
                "issuer": PROVIDER_ISSUER,
                "subject_digest": SUBJECT_DIGEST,
                "subject_digest_key_id": SUBJECT_DIGEST_KEY_ID,
                "status": "ACTIVE",
                "verified_at": UTC_NOW - timedelta(days=30),
            }
        }
    )


def valid_invitation() -> AccessInvitation:
    return AccessInvitation(
        invitation_id=INVITATION_ID,
        purpose=InvitationPurpose.CREATOR_ENROLLMENT,
        target_scope=TargetScope.USER,
        target_role=TargetRole.CREATOR,
        organization_id=None,
        is_initial_admin=False,
        recipient_contact_id=CONTACT_POINT_ID,
        issued_policy_bundle_id="policy_bundle_oidc_0001",
        policy_selector_digest=hashlib.sha256(b"oidc-selector").hexdigest(),
        status=InvitationStatus.ISSUED,
        expires_at=UTC_NOW + timedelta(days=7),
        aggregate_version=1,
        created_at=UTC_NOW - timedelta(days=1),
        masked_recipient_label="a***@example.test",
        issuer_kind="SYSTEM",
        issuer_id="system_oidc_issuer_0001",
        nonce=hashlib.sha256(b"oidc-invitation-nonce").hexdigest(),
        token_key_id=TOKEN_KEY_ID,
        token_format_version=TOKEN_FORMAT_VERSION,
        updated_at=UTC_NOW - timedelta(days=1),
    )


def valid_contact_point(
    *,
    contact_point_id: str = CONTACT_POINT_ID,
) -> dict[str, Any]:
    return {
        "contact_point_id": contact_point_id,
        "user_id": None,
        "type": "EMAIL",
        "locator_ciphertext": "ciphertext:synthetic-recipient",
        "binding_digest": CONTACT_DIGEST,
        "binding_digest_key_id": BINDING_DIGEST_KEY_ID,
        "status": "UNVERIFIED",
        "verified_at": None,
        "created_at": UTC_NOW - timedelta(days=1),
        "aggregate_version": 1,
    }


def valid_fake_code() -> FakeOidcCode:
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(RAW_CODE_VERIFIER.encode("ascii")).digest()
    ).rstrip(b"=").decode("ascii")
    return FakeOidcCode(
        code=RAW_CODE,
        state=RAW_STATE,
        nonce=RAW_NONCE,
        code_challenge=challenge,
        redirect_uri=REDIRECT_URI,
        issuer=PROVIDER_ISSUER,
        audiences=(PROVIDER_AUDIENCE,),
        authorized_party=None,
        raw_subject="synthetic-subject-0001",
        verified_contact_type="EMAIL",
        verified_locator="applicant@example.test",
        auth_time=UTC_NOW - timedelta(minutes=1),
        issued_at=UTC_NOW - timedelta(seconds=30),
        not_before=UTC_NOW - timedelta(seconds=30),
        expires_at=UTC_NOW + timedelta(minutes=5),
        acr_code="urn:desire:acr:mfa",
        amr_codes=("pwd", "otp"),
    )


def valid_exchange_request(**changes: Any) -> ProviderExchangeRequest:
    values = {
        "auth_transaction_id": AUTH_TRANSACTION_ID,
        "code": RAW_CODE,
        "state": RAW_STATE,
        "redirect_uri": REDIRECT_URI,
        "code_verifier": RAW_CODE_VERIFIER,
        "expected_nonce": RAW_NONCE,
        "expected_issuer": PROVIDER_ISSUER,
        "expected_audience": PROVIDER_AUDIENCE,
        "server_now": UTC_NOW,
    }
    values.update(changes)
    return ProviderExchangeRequest(**values)


def valid_authenticated_subject() -> AuthenticatedSubject:
    return AuthenticatedSubject(
        issuer=PROVIDER_ISSUER,
        subject_digest=SUBJECT_DIGEST,
        subject_digest_key_id=SUBJECT_DIGEST_KEY_ID,
        verified_recipient_binding=RecipientBindingTuple(
            contact_type="EMAIL",
            binding_digest=CONTACT_DIGEST,
            digest_key_id=BINDING_DIGEST_KEY_ID,
        ),
        auth_time=UTC_NOW - timedelta(minutes=1),
        acr_code="urn:desire:acr:mfa",
        amr_codes=("pwd", "otp"),
        token_issued_at=UTC_NOW - timedelta(seconds=30),
        token_expires_at=UTC_NOW + timedelta(minutes=5),
        provider_session_reference="provider-session-synthetic-0001",
    )


def seed_pending_auth_transaction(
    fixture: AuthenticationFixture,
    *,
    purpose: str = "ENROLLMENT",
    initiating_session_id: Optional[str] = None,
    initiating_user_id: Optional[str] = None,
    expected_user_id: Optional[str] = None,
    invitation_id: Optional[str] = INVITATION_ID,
    invitation_version: Optional[int] = 1,
    expected_contact_point_id: Optional[str] = CONTACT_POINT_ID,
) -> None:
    fixture.store.seed(
        auth_transactions={
            AUTH_TRANSACTION_ID: {
                "auth_transaction_id": AUTH_TRANSACTION_ID,
                "status": "PENDING",
                "purpose": purpose,
                "browser_binding_digest": fixture.protocol_keyring.digest_text(
                    key_id=BROWSER_KEY_ID,
                    value=RAW_BROWSER_COOKIE,
                ),
                "browser_binding_digest_key_id": BROWSER_KEY_ID,
                "initiating_session_id": initiating_session_id,
                "initiating_user_id": initiating_user_id,
                "expected_user_id": expected_user_id,
                "invitation_id": invitation_id,
                "invitation_version": invitation_version,
                "expected_contact_point_id": expected_contact_point_id,
                "expected_contact_type": (
                    "EMAIL" if expected_contact_point_id is not None else None
                ),
                "expected_contact_binding_digest": (
                    CONTACT_DIGEST
                    if expected_contact_point_id is not None
                    else None
                ),
                "expected_contact_binding_digest_key_id": (
                    BINDING_DIGEST_KEY_ID
                    if expected_contact_point_id is not None
                    else None
                ),
                "state_digest": fixture.protocol_keyring.digest_text(
                    key_id=STATE_KEY_ID,
                    value=RAW_STATE,
                ),
                "state_digest_key_id": STATE_KEY_ID,
                "nonce_digest": hashlib.sha256(RAW_NONCE.encode("utf-8")).hexdigest(),
                "nonce_ciphertext": fixture.protocol_secret_box.encrypt(
                    plaintext=RAW_NONCE
                ),
                "nonce_encryption_key_id": PROTOCOL_ENCRYPTION_KEY_ID,
                "pkce_verifier_ciphertext": fixture.protocol_secret_box.encrypt(
                    plaintext=RAW_CODE_VERIFIER
                ),
                "pkce_encryption_key_id": PROTOCOL_ENCRYPTION_KEY_ID,
                "pkce_code_challenge": valid_fake_code().code_challenge,
                "pkce_code_challenge_method": "S256",
                "provider_issuer": PROVIDER_ISSUER,
                "provider_audience": PROVIDER_AUDIENCE,
                "redirect_uri": REDIRECT_URI,
                "return_to": RETURN_TO,
                "security_policy_version": "iam-security-v1",
                "deadline": UTC_NOW + timedelta(minutes=10),
                "attempt": 0,
                "exchange_owner_id": None,
                "exchange_claimed_at": None,
                "provider_error_class": None,
                "aggregate_version": 1,
                "created_at": UTC_NOW,
                "updated_at": UTC_NOW,
            }
        }
    )


def invoke_begin(
    fixture: AuthenticationFixture,
    *,
    context: OidcBrowserContext,
    command: BeginOidcAuthorizationCommand,
):
    try:
        return fixture.begin_handler.handle(context=context, command=command), None
    except IamError as error:
        return None, error.code


def invoke_complete(
    fixture: AuthenticationFixture,
    *,
    context: Optional[OidcBrowserContext] = None,
    command: Optional[CompleteOidcAuthenticationCommand] = None,
):
    try:
        return (
            fixture.complete_handler.handle(
                context=context or fixture.anonymous_context,
                command=command or fixture.complete_command,
            ),
            None,
        )
    except IamError as error:
        return None, error.code


def replace_fake_code(script: FakeOidcCode, **changes: Any) -> FakeOidcCode:
    return replace(script, **changes)
