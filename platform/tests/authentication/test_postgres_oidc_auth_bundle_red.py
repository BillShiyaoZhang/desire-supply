"""TDD contract for the production PostgreSQL OIDC LOGIN composition bundle."""

from __future__ import annotations

from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta, timezone
import base64
import hashlib
import hmac
import unittest
from uuid import UUID, uuid4

from desire_platform.identity_access.adapters.postgres.oidc_authentication import (
    OidcPostgresSessionResult,
    OidcPostgresStepUpSessionFacts,
)
from desire_platform.identity_access.adapters.postgres.oidc_bundle import (
    PostgresIamAuthenticationBundle,
    build_postgres_iam_authentication_bundle,
)
from desire_platform.identity_access.application.authentication import (
    BeginOidcAuthorizationCommand,
    CompleteOidcAuthenticationCommand,
    OidcBrowserContext,
    OidcSecurityPolicy,
)
from desire_platform.identity_access.domain.errors import IamError
from desire_platform.identity_access.ports.identity_provider import (
    AuthenticatedSubject,
    ProviderAuthorization,
)
from desire_platform.identity_access.ports.recipient_binding import (
    RecipientBindingTuple,
)
from desire_platform.identity_access.ports.access_invitation_capability import (
    VerifiedAccessInvitationCapability,
)
from desire_platform.identity_access.ports.read_models import ReadModelSnapshot
from desire_platform.internal_pilot.runtime_crypto import (
    AesGcmProtocolSecretBox,
    RuntimeKeyMaterial,
)


NOW = datetime(2026, 8, 12, 9, 0, tzinfo=timezone.utc)
ISSUER = "https://id.example.test"
AUDIENCE = "desire-internal-pilot"
REDIRECT = "https://app.example.test/v1/auth/oidc/callback"
SYSTEM_ACTOR_ID = UUID("10000000-0000-4000-8000-000000000001")


class _Clock:
    def now(self):
        return NOW


class _Ids:
    def __init__(self):
        self.calls = []

    def new_id(self, kind):
        self.calls.append(kind)
        return uuid4()


class _Secrets:
    def token_bytes(self, purpose, length):
        seed = hashlib.sha256(purpose.encode("ascii")).digest()
        return (seed * 2)[:length]


class _Keyring:
    state_digest_key_id = "state-v1"
    retained_state_digest_key_ids = ("state-v1",)
    browser_binding_digest_key_id = "browser-v1"
    retained_browser_binding_digest_key_ids = ("browser-v1",)
    nonce_digest_key_id = "nonce-v1"
    retained_nonce_digest_key_ids = ("nonce-v1",)
    session_handle_digest_key_id = "session-v1"
    csrf_key_id = "csrf-v1"

    def __init__(self):
        self.keys = {
            key_id: ("key:" + key_id).encode("ascii")
            for key_id in (
                "state-v1",
                "browser-v1",
                "nonce-v1",
                "session-v1",
                "csrf-v1",
            )
        }

    def digest_text(self, *, key_id, value):
        return hmac.new(
            self.keys[key_id], value.encode("utf-8"), hashlib.sha256
        ).hexdigest()

    def keyed_digest_hex(self, *, key_id, canonical_bytes):
        return hmac.new(
            self.keys[key_id], canonical_bytes, hashlib.sha256
        ).hexdigest()


class _SecretBox:
    key_id = "protocol-aead-v1"

    def encrypt(self, *, plaintext, key_id):
        if key_id != self.key_id:
            raise AssertionError("wrong key")
        return b"sealed:" + base64.urlsafe_b64encode(plaintext.encode("utf-8"))

    def decrypt(self, *, ciphertext, key_id):
        if key_id != self.key_id or not ciphertext.startswith(b"sealed:"):
            raise AssertionError("wrong ciphertext")
        return base64.urlsafe_b64decode(ciphertext[7:]).decode("utf-8")


class _Provider:
    def __init__(self):
        self.begin_calls = []
        self.preflight_calls = []
        self.exchange_calls = []
        self.invalid_subject = False

    def preflight(self, **facts):
        self.preflight_calls.append(facts)

    def preflight_exchange(self, **facts):
        self.preflight_calls.append(facts)

    def begin(self, **facts):
        self.begin_calls.append(facts)
        return ProviderAuthorization(
            authorization_url="https://id.example.test/authorize?redacted",
            issuer=ISSUER,
            audience=AUDIENCE,
            redirect_uri=REDIRECT,
            code_challenge_method="S256",
        )

    def exchange(self, request):
        self.exchange_calls.append(request)
        subject = AuthenticatedSubject(
            issuer=ISSUER,
            subject_digest=hashlib.sha256(b"subject").hexdigest(),
            subject_digest_key_id="subject-v1",
            verified_recipient_binding=RecipientBindingTuple(
                contact_type="EMAIL",
                binding_digest=hashlib.sha256(b"person@example.test").hexdigest(),
                digest_key_id="contact-v1",
            ),
            auth_time=NOW - timedelta(minutes=1),
            acr_code="urn:desire:acr:mfa",
            amr_codes=("otp",),
            token_issued_at=NOW - timedelta(seconds=30),
            token_expires_at=NOW + timedelta(minutes=5),
        )
        if self.invalid_subject:
            return type(
                "InvalidSubject",
                (),
                dict(
                    vars(subject),
                    issuer="https://attacker.example.test",
                ),
            )()
        return subject


class _Uow:
    def __init__(self):
        self.transaction = None
        self.begin_requests = []
        self.lookup_requests = []
        self.claim_requests = []
        self.finish_requests = []
        self.finalize_requests = []
        self.enrollment_finalize_requests = []
        self.step_up_finalize_requests = []
        self.generic_step_up_finalize_requests = []
        self.claim_error = None

    def begin(self, request):
        from desire_platform.identity_access.adapters.postgres.oidc_authentication import (
            OidcPostgresTransaction,
        )
        from desire_platform.identity_access.domain.authentication import (
            AuthTransactionStatus,
        )

        self.begin_requests.append(request)
        self.transaction = OidcPostgresTransaction(
            auth_transaction_id=request.auth_transaction_id,
            status=AuthTransactionStatus.PENDING,
            purpose=request.purpose,
            attempt=0,
            browser_binding_digest=request.browser_binding_digest,
            browser_binding_key_id=request.browser_binding_key_id,
            initiating_session_id=request.initiating_session_id,
            initiating_user_id=request.initiating_user_id,
            expected_user_id=request.expected_user_id,
            invitation_id=request.invitation_id,
            invitation_version=request.invitation_version,
            expected_contact_point_id=request.expected_contact_point_id,
            expected_contact_type=request.expected_contact_type,
            expected_contact_binding_digest=request.expected_contact_binding_digest,
            expected_contact_binding_key_id=request.expected_contact_binding_key_id,
            state_digest=request.state_digest,
            state_digest_key_id=request.state_digest_key_id,
            nonce_digest=request.nonce_digest,
            nonce_digest_key_id=request.nonce_digest_key_id,
            nonce_ciphertext=request.nonce_ciphertext,
            nonce_encryption_key_id=request.nonce_encryption_key_id,
            pkce_verifier_ciphertext=request.pkce_verifier_ciphertext,
            pkce_encryption_key_id=request.pkce_encryption_key_id,
            pkce_code_challenge=request.pkce_code_challenge,
            provider_issuer=request.provider_issuer,
            provider_audience=request.provider_audience,
            redirect_uri=request.redirect_uri,
            return_to=request.return_to,
            security_policy_version=request.security_policy_version,
            deadline=NOW + timedelta(minutes=10),
            exchange_owner_id=None,
            exchange_claimed_at=None,
            provider_error_class=None,
            aggregate_version=1,
            created_at=NOW,
            updated_at=NOW,
        )
        return self.transaction

    def read_callback(self, request):
        self.lookup_requests.append(request)
        if self.transaction is None:
            raise IamError("AUTH_TRANSACTION_INVALID")
        if request.state_digest != self.transaction.state_digest:
            raise IamError("AUTH_TRANSACTION_INVALID")
        if request.browser_binding_digest != self.transaction.browser_binding_digest:
            raise IamError("AUTH_TRANSACTION_INVALID")
        return self.transaction

    def claim_exchange(self, request):
        from dataclasses import replace
        from desire_platform.identity_access.domain.authentication import (
            AuthTransactionStatus,
        )

        self.claim_requests.append(request)
        if self.claim_error is not None:
            raise IamError(self.claim_error)
        self.transaction = replace(
            self.transaction,
            status=AuthTransactionStatus.EXCHANGING,
            attempt=1,
            exchange_owner_id=request.exchange_owner_id,
            exchange_claimed_at=NOW,
            aggregate_version=2,
        )
        return self.transaction

    def finish_exchange(self, request):
        self.finish_requests.append(request)

    def finalize_existing_login(self, request):
        self.finalize_requests.append(request)
        return OidcPostgresSessionResult(
            session_id=request.new_session_id,
            session_family_id=request.new_session_family_id,
            user_id=UUID("20000000-0000-4000-8000-000000000001"),
            user_status="ACTIVE",
            generation=1,
        )

    def finalize_enrollment(self, request):
        self.enrollment_finalize_requests.append(request)
        return OidcPostgresSessionResult(
            session_id=request.new_session_id,
            session_family_id=request.new_session_family_id,
            user_id=request.new_user_id,
            user_status="PENDING_ENROLLMENT",
            generation=1,
        )

    def resolve_invitation_step_up_session(self, **facts):
        return OidcPostgresStepUpSessionFacts(
            user_id=facts["expected_user_id"],
            initiating_session_id=facts["initiating_session_id"],
            session_family_id=UUID("20000000-0000-4000-8000-000000000003"),
            current_generation=1,
        )

    def resolve_generic_step_up_session(self, **facts):
        return OidcPostgresStepUpSessionFacts(
            user_id=facts["expected_user_id"],
            initiating_session_id=facts["initiating_session_id"],
            session_family_id=UUID("20000000-0000-4000-8000-000000000003"),
            current_generation=1,
        )

    def finalize_invitation_step_up(self, request):
        self.step_up_finalize_requests.append(request)
        return OidcPostgresSessionResult(
            session_id=request.new_session_id,
            session_family_id=request.session_family_id,
            user_id=request.expected_user_id,
            user_status="ACTIVE",
            generation=request.predecessor_generation + 1,
        )

    def finalize_generic_step_up(self, request):
        self.generic_step_up_finalize_requests.append(request)
        return OidcPostgresSessionResult(
            session_id=request.new_session_id,
            session_family_id=request.session_family_id,
            user_id=request.expected_user_id,
            user_status="ACTIVE",
            generation=request.predecessor_generation + 1,
        )


class _InvitationCapabilities:
    def __init__(self, invitation_id, nonce):
        self._value = VerifiedAccessInvitationCapability(
            invitation_id=str(invitation_id),
            invitation_nonce=nonce,
            expires_at=NOW + timedelta(days=1),
            token_key_id="invitation-token-v1",
            token_format_version="access-invitation-token-v1",
        )

    def verify(self, *, access_invitation_token, now):
        if access_invitation_token != "closed-request-token" or now != NOW:
            raise ValueError("invalid token")
        return self._value


class _InvitationReads:
    def __init__(self, invitation_id, contact_id, nonce, *, target_role="DEMAND_OWNER"):
        self._invitation_id = invitation_id
        self._contact_id = contact_id
        self._nonce = nonce
        self._target_role = target_role

    def read_invitation_preview(self, *, capability):
        assert capability.invitation_id == str(self._invitation_id)
        return ReadModelSnapshot.from_mapping(
            transaction_time=NOW,
            statement_count=1,
            facts={
                "invitation": {
                    "invitation_id": str(self._invitation_id),
                    "recipient_contact_id": str(self._contact_id),
                    "token_nonce": self._nonce,
                    "token_key_id": "invitation-token-v1",
                    "token_format_version": "access-invitation-token-v1",
                    "expires_at": NOW + timedelta(days=1),
                    "status": "ISSUED",
                    "purpose": "ORGANIZATION_MEMBERSHIP",
                    "target_scope": "ORGANIZATION",
                    "target_role": self._target_role,
                    "is_initial_admin": False,
                    "aggregate_version": 1,
                },
                "recipient_binding": {
                    "contact_point_id": str(self._contact_id),
                    "contact_type": "EMAIL",
                    "binding_digest": hashlib.sha256(
                        b"person@example.test"
                    ).hexdigest(),
                    "binding_digest_key_id": "contact-v1",
                },
            },
        )


class _SessionSecurity:
    def __init__(self, user_id, session_id):
        self._user_id = user_id
        self._session_id = session_id

    def authenticate(self, *, raw_session_handle, trace_id):
        if raw_session_handle != "current-session-cookie" or not trace_id:
            return None
        return type(
            "Actor",
            (),
            {
                "actor_user_id": str(self._user_id),
                "session_id": str(self._session_id),
            },
        )()


def _bundle(
    *,
    secret_box=None,
    invitation_capabilities=None,
    invitation_reads=None,
    session_security=None,
):
    uow = _Uow()
    provider = _Provider()
    keyring = _Keyring()
    bundle = build_postgres_iam_authentication_bundle(
        oidc_uow=uow,
        provider=provider,
        protocol_keyring=keyring,
        protocol_secret_box=secret_box or _SecretBox(),
        session_keyring=keyring,
        clock=_Clock(),
        id_source=_Ids(),
        secret_source=_Secrets(),
        system_actor_id=SYSTEM_ACTOR_ID,
        security_policy=OidcSecurityPolicy(
            policy_version="iam-security-v1",
            provider_issuer=ISSUER,
            provider_audience=AUDIENCE,
            redirect_uri=REDIRECT,
            allowed_return_to=("/app",),
        ),
        invitation_capabilities=invitation_capabilities,
        invitation_reads=invitation_reads,
        session_security=session_security,
    )
    return bundle, uow, provider


class PostgresOidcAuthBundleRedTest(unittest.TestCase):
    def test_runtime_aes_box_is_accepted_by_the_postgres_bundle(self):
        box = AesGcmProtocolSecretBox(
            keys=(
                RuntimeKeyMaterial(
                    purpose="OIDC_PROTOCOL_AEAD",
                    key_id="protocol-aead-v1",
                    material=bytearray(b"a" * 32),
                ),
            ),
            active_key_id="protocol-aead-v1",
            nonce_source=lambda size: b"z" * size,
        )
        bundle, uow, _provider = _bundle(secret_box=box)

        bundle.begin_oidc_authorization.handle(
            context=OidcBrowserContext(trace_id="trace-runtime-box"),
            command=BeginOidcAuthorizationCommand(return_to="/app"),
        )

        self.assertEqual(len(uow.begin_requests), 1)
        self.assertIsInstance(uow.begin_requests[0].nonce_ciphertext, bytes)
        self.assertIsInstance(uow.begin_requests[0].pkce_verifier_ciphertext, bytes)

    def test_bundle_is_frozen_and_handlers_match_the_presenter_contract(self):
        bundle, _uow, _provider = _bundle()
        self.assertIsInstance(bundle, PostgresIamAuthenticationBundle)
        with self.assertRaises(FrozenInstanceError):
            bundle.begin_oidc_authorization = None
        self.assertTrue(callable(bundle.begin_oidc_authorization.handle))
        self.assertTrue(callable(bundle.complete_oidc_authorization.handle))

    def test_existing_identity_login_round_trip_and_secret_boundary(self):
        bundle, uow, provider = _bundle()
        begun = bundle.begin_oidc_authorization.handle(
            context=OidcBrowserContext(trace_id="trace-begin"),
            command=BeginOidcAuthorizationCommand(return_to="/app"),
        )
        self.assertEqual(len(uow.begin_requests), 1)
        persisted = uow.begin_requests[0]
        self.assertIsInstance(persisted.state_digest, bytes)
        self.assertEqual(len(persisted.state_digest), 32)
        self.assertNotIn(begun.oidc_browser_cookie, repr(persisted))
        raw_state = provider.begin_calls[0]["state"]

        completed = bundle.complete_oidc_authorization.handle(
            context=OidcBrowserContext(
                raw_oidc_browser_cookie=begun.oidc_browser_cookie,
                trace_id="trace-complete",
            ),
            command=CompleteOidcAuthenticationCommand(
                state=raw_state,
                code="one-time-code",
            ),
        )
        self.assertEqual(len(uow.claim_requests), 1)
        self.assertEqual(len(provider.exchange_calls), 1)
        self.assertEqual(len(uow.finalize_requests), 1)
        self.assertEqual(completed.return_to, "/app")
        self.assertEqual(completed.user_status, "ACTIVE")
        self.assertNotIn("one-time-code", repr(uow.finalize_requests[0]))

    def test_existing_user_invitation_step_up_rotates_bound_session(self):
        invitation_id = UUID("30000000-0000-4000-8000-000000000001")
        contact_id = UUID("30000000-0000-4000-8000-000000000002")
        user_id = UUID("20000000-0000-4000-8000-000000000001")
        session_id = UUID("20000000-0000-4000-8000-000000000002")
        nonce = (b"n" * 32).hex()
        capabilities = _InvitationCapabilities(invitation_id, nonce)
        reads = _InvitationReads(invitation_id, contact_id, nonce)
        session_security = _SessionSecurity(user_id, session_id)
        bundle, uow, provider = _bundle(
            invitation_capabilities=capabilities,
            invitation_reads=reads,
            session_security=session_security,
        )
        begun = bundle.begin_oidc_authorization.handle(
            context=OidcBrowserContext(
                raw_session_handle="current-session-cookie",
                trace_id="trace-step-up-begin",
            ),
            command=BeginOidcAuthorizationCommand(
                return_to="/app",
                access_invitation_token="closed-request-token",
            ),
        )
        self.assertEqual(uow.begin_requests[0].purpose.value, "STEP_UP")
        self.assertEqual(uow.begin_requests[0].invitation_id, invitation_id)
        raw_state = provider.begin_calls[0]["state"]
        completed = bundle.complete_oidc_authorization.handle(
            context=OidcBrowserContext(
                raw_session_handle="current-session-cookie",
                raw_oidc_browser_cookie=begun.oidc_browser_cookie,
                trace_id="trace-step-up-complete",
            ),
            command=CompleteOidcAuthenticationCommand(
                state=raw_state,
                code="one-time-code",
            ),
        )
        self.assertEqual(len(uow.step_up_finalize_requests), 1)
        finalize = uow.step_up_finalize_requests[0]
        self.assertEqual(finalize.invitation_id, invitation_id)
        self.assertEqual(finalize.expected_contact_point_id, contact_id)
        self.assertEqual(finalize.expected_user_id, user_id)
        self.assertEqual(finalize.initiating_session_id, session_id)
        self.assertEqual(completed.user_id, str(user_id))
        self.assertNotIn("closed-request-token", repr(finalize))
        self.assertNotIn("current-session-cookie", repr(finalize))

    def test_anonymous_invitation_enrollment_creates_only_pending_identity_session(self):
        invitation_id = UUID("30000000-0000-4000-8000-000000000001")
        contact_id = UUID("30000000-0000-4000-8000-000000000002")
        nonce = (b"n" * 32).hex()
        bundle, uow, provider = _bundle(
            invitation_capabilities=_InvitationCapabilities(invitation_id, nonce),
            invitation_reads=_InvitationReads(invitation_id, contact_id, nonce),
        )

        begun = bundle.begin_oidc_authorization.handle(
            context=OidcBrowserContext(trace_id="trace-enrollment-begin"),
            command=BeginOidcAuthorizationCommand(
                return_to="/app",
                access_invitation_token="closed-request-token",
            ),
        )
        begin_request = uow.begin_requests[0]
        self.assertEqual(begin_request.purpose.value, "ENROLLMENT")
        self.assertIsNone(begin_request.initiating_session_id)
        self.assertIsNone(begin_request.initiating_user_id)
        self.assertIsNone(begin_request.expected_user_id)
        self.assertEqual(begin_request.invitation_id, invitation_id)
        self.assertEqual(begin_request.invitation_version, 1)
        self.assertEqual(begin_request.expected_contact_point_id, contact_id)

        completed = bundle.complete_oidc_authorization.handle(
            context=OidcBrowserContext(
                raw_oidc_browser_cookie=begun.oidc_browser_cookie,
                trace_id="trace-enrollment-complete",
            ),
            command=CompleteOidcAuthenticationCommand(
                state=provider.begin_calls[0]["state"],
                code="one-time-code",
            ),
        )

        self.assertEqual(completed.user_status, "PENDING_ENROLLMENT")
        self.assertEqual(len(uow.enrollment_finalize_requests), 1)
        self.assertEqual(uow.finalize_requests, [])
        self.assertEqual(uow.step_up_finalize_requests, [])
        finalize = uow.enrollment_finalize_requests[0]
        self.assertEqual(finalize.invitation_id, invitation_id)
        self.assertEqual(finalize.invitation_version, 1)
        self.assertEqual(finalize.expected_contact_point_id, contact_id)
        self.assertEqual(
            finalize.expected_contact_binding_digest,
            finalize.verified_contact_binding_digest,
        )
        self.assertEqual(
            finalize.expected_contact_binding_key_id,
            finalize.verified_contact_binding_key_id,
        )
        self.assertNotIn("closed-request-token", repr(finalize))
        self.assertNotIn("one-time-code", repr(finalize))

    def test_anonymous_org_admin_enrollment_stays_closed_but_existing_user_step_up_remains_open(self):
        invitation_id = UUID("30000000-0000-4000-8000-000000000001")
        contact_id = UUID("30000000-0000-4000-8000-000000000002")
        user_id = UUID("20000000-0000-4000-8000-000000000001")
        session_id = UUID("20000000-0000-4000-8000-000000000002")
        nonce = (b"n" * 32).hex()
        capabilities = _InvitationCapabilities(invitation_id, nonce)
        reads = _InvitationReads(
            invitation_id,
            contact_id,
            nonce,
            target_role="ORG_ADMIN",
        )
        bundle, uow, _provider = _bundle(
            invitation_capabilities=capabilities,
            invitation_reads=reads,
            session_security=_SessionSecurity(user_id, session_id),
        )

        with self.assertRaises(IamError) as anonymous:
            bundle.begin_oidc_authorization.handle(
                context=OidcBrowserContext(trace_id="trace-org-admin-enrollment"),
                command=BeginOidcAuthorizationCommand(
                    return_to="/app",
                    access_invitation_token="closed-request-token",
                ),
            )
        self.assertEqual(anonymous.exception.code, "ACCESS_INVITATION_UNAVAILABLE")
        self.assertEqual(uow.begin_requests, [])

        begun = bundle.begin_oidc_authorization.handle(
            context=OidcBrowserContext(
                raw_session_handle="current-session-cookie",
                trace_id="trace-org-admin-step-up",
            ),
            command=BeginOidcAuthorizationCommand(
                return_to="/app",
                access_invitation_token="closed-request-token",
            ),
        )
        self.assertEqual(begun.auth_transaction_id is not None, True)
        self.assertEqual(uow.begin_requests[0].purpose.value, "STEP_UP")

    def test_authenticated_tokenless_step_up_rotates_same_user_family(self):
        user_id = UUID("20000000-0000-4000-8000-000000000001")
        session_id = UUID("20000000-0000-4000-8000-000000000002")
        session_security = _SessionSecurity(user_id, session_id)
        bundle, uow, provider = _bundle(session_security=session_security)

        begun = bundle.begin_oidc_authorization.handle(
            context=OidcBrowserContext(
                raw_session_handle="current-session-cookie",
                trace_id="trace-generic-step-up-begin",
            ),
            command=BeginOidcAuthorizationCommand(
                return_to="/app",
                reauthenticate=True,
            ),
        )
        request = uow.begin_requests[0]
        self.assertEqual(request.purpose.value, "STEP_UP")
        self.assertEqual(request.initiating_user_id, user_id)
        self.assertEqual(request.expected_user_id, user_id)
        self.assertEqual(request.initiating_session_id, session_id)
        self.assertIsNone(request.invitation_id)
        self.assertIsNone(request.expected_contact_point_id)

        completed = bundle.complete_oidc_authorization.handle(
            context=OidcBrowserContext(
                raw_session_handle="current-session-cookie",
                raw_oidc_browser_cookie=begun.oidc_browser_cookie,
                trace_id="trace-generic-step-up-complete",
            ),
            command=CompleteOidcAuthenticationCommand(
                state=provider.begin_calls[0]["state"],
                code="one-time-code",
            ),
        )

        self.assertEqual(len(uow.generic_step_up_finalize_requests), 1)
        self.assertEqual(uow.step_up_finalize_requests, [])
        finalize = uow.generic_step_up_finalize_requests[0]
        self.assertEqual(finalize.expected_user_id, user_id)
        self.assertEqual(finalize.initiating_session_id, session_id)
        self.assertEqual(completed.user_id, str(user_id))
        self.assertNotIn("current-session-cookie", repr(finalize))

    def test_unsupported_authority_and_ambiguous_claim_fail_closed(self):
        bundle, uow, provider = _bundle()
        with self.assertRaises(IamError) as invitation:
            bundle.begin_oidc_authorization.handle(
                context=OidcBrowserContext(trace_id="trace"),
                command=BeginOidcAuthorizationCommand(
                    return_to="/app",
                    access_invitation_token="not-yet-supported",
                ),
            )
        self.assertEqual(invitation.exception.code, "SERVICE_UNAVAILABLE")
        begun = bundle.begin_oidc_authorization.handle(
            context=OidcBrowserContext(trace_id="trace-begin"),
            command=BeginOidcAuthorizationCommand(return_to="/app"),
        )
        uow.claim_error = "COMMAND_OUTCOME_UNKNOWN"
        with self.assertRaises(IamError) as ambiguous:
            bundle.complete_oidc_authorization.handle(
                context=OidcBrowserContext(
                    raw_oidc_browser_cookie=begun.oidc_browser_cookie,
                    trace_id="trace-complete",
                ),
                command=CompleteOidcAuthenticationCommand(
                    state=provider.begin_calls[0]["state"],
                    code="one-time-code",
                ),
            )
        self.assertEqual(ambiguous.exception.code, "COMMAND_OUTCOME_UNKNOWN")
        self.assertEqual(provider.exchange_calls, [])

    def test_invalid_verified_subject_closes_the_claim_as_rejected(self):
        bundle, uow, provider = _bundle()
        begun = bundle.begin_oidc_authorization.handle(
            context=OidcBrowserContext(trace_id="trace-begin"),
            command=BeginOidcAuthorizationCommand(return_to="/app"),
        )
        provider.invalid_subject = True
        with self.assertRaises(IamError) as rejected:
            bundle.complete_oidc_authorization.handle(
                context=OidcBrowserContext(
                    raw_oidc_browser_cookie=begun.oidc_browser_cookie,
                    trace_id="trace-complete",
                ),
                command=CompleteOidcAuthenticationCommand(
                    state=provider.begin_calls[0]["state"],
                    code="one-time-code",
                ),
            )
        self.assertEqual(rejected.exception.code, "AUTHENTICATION_REJECTED")
        self.assertEqual(len(uow.finish_requests), 1)
        self.assertEqual(uow.finish_requests[0].outcome.value, "REJECTED")


if __name__ == "__main__":
    unittest.main()
