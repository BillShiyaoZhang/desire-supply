"""Production composition handlers for PostgreSQL OIDC authentication.

The generic authentication handlers remain the executable in-memory domain
oracle.  They intentionally cannot be adapted to PostgreSQL because they
enumerate snapshots.  This module exposes the same HTTP-presenter handler
shape over the exact, FORCE-RLS-compatible programs in
``oidc_authentication``.

Anonymous LOGIN never creates an identity.  Anonymous ENROLLMENT is open only
for one verified invitation capability and its frozen EMAIL recipient binding;
existing-User invitation STEP_UP remains a separate path.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import hashlib
import hmac
import re
from typing import Any, Mapping, Optional, Tuple
from uuid import UUID, uuid5

from ...application.authentication import (
    BeginOidcAuthorizationCommand,
    BeginOidcAuthorizationResult,
    CompleteOidcAuthenticationCommand,
    CompleteOidcAuthenticationResult,
    OidcBrowserContext,
    OidcSecurityPolicy,
)
from ...domain.authentication import AuthTransactionStatus
from ...domain.errors import IamError
from ...ports.identity_provider import (
    IdentityProviderMisconfiguredError,
    IdentityProviderRejectedError,
    IdentityProviderResultUnknownError,
    IdentityProviderUnavailableError,
    ProviderExchangeRequest,
)
from ...security.cryptography import (
    KeyUnavailableError,
    csrf_digest,
    derive_csrf_token,
    require_key_material,
    session_handle_digest,
)
from .oidc_authentication import (
    OidcPostgresBeginRequest,
    OidcPostgresAuthenticationRejected,
    OidcPostgresCallbackLookup,
    OidcPostgresEnrollmentFinalize,
    OidcPostgresExchangeClaim,
    OidcPostgresExchangeTerminal,
    OidcPostgresExistingLoginFinalize,
    OidcPostgresGenericStepUpFinalize,
    OidcPostgresInvitationStepUpFinalize,
    OidcPostgresPurpose,
    OidcPostgresSessionResult,
    OidcPostgresTerminalOutcome,
    OidcPostgresTransaction,
)


_LOWER_HEX_32 = re.compile(r"^[0-9a-f]{64}$")
_TRACE_NAMESPACE = UUID("616d38d1-37de-5c6e-9bc2-b908a923d43e")
_MAX_RETAINED_KEYS = 4
_EXPECTED_AUTH_TRANSACTION_TTL = timedelta(minutes=10)


@dataclass(frozen=True)
class _InvitationBeginPlan:
    user_id: Optional[UUID]
    session_id: Optional[UUID]
    invitation_id: Optional[UUID]
    invitation_version: Optional[int]
    contact_point_id: Optional[UUID]
    contact_type: Optional[str]
    binding_digest: Optional[bytes] = field(repr=False)
    binding_key_id: Optional[str]


@dataclass(frozen=True)
class PostgresIamAuthenticationBundle:
    """The two exact bindings consumed by ``IamHttpPresenterBindings``."""

    begin_oidc_authorization: Any = field(repr=False)
    complete_oidc_authorization: Any = field(repr=False)

    def __post_init__(self) -> None:
        if not callable(getattr(self.begin_oidc_authorization, "handle", None)):
            raise TypeError("PostgreSQL OIDC begin binding is unavailable")
        if not callable(getattr(self.complete_oidc_authorization, "handle", None)):
            raise TypeError("PostgreSQL OIDC complete binding is unavailable")


class PostgresBeginOidcAuthorizationHandler:
    """Create one anonymous v2 LOGIN transaction through an exact PG program."""

    def __init__(
        self,
        *,
        oidc_uow: Any,
        provider: Any,
        protocol_keyring: Any,
        protocol_secret_box: Any,
        clock: Any,
        id_source: Any,
        secret_source: Any,
        system_actor_id: UUID,
        security_policy: OidcSecurityPolicy,
        invitation_capabilities: Any = None,
        invitation_reads: Any = None,
        session_security: Any = None,
    ) -> None:
        self._uow = oidc_uow
        self._provider = provider
        self._protocol_keyring = protocol_keyring
        self._protocol_secret_box = protocol_secret_box
        self._clock = clock
        self._id_source = id_source
        self._secret_source = secret_source
        self._system_actor_id = system_actor_id
        self._security_policy = security_policy
        self._invitation_capabilities = invitation_capabilities
        self._invitation_reads = invitation_reads
        self._session_security = session_security

    def handle(
        self,
        *,
        context: OidcBrowserContext,
        command: BeginOidcAuthorizationCommand,
    ) -> BeginOidcAuthorizationResult:
        if not isinstance(context, OidcBrowserContext) or not isinstance(
            command, BeginOidcAuthorizationCommand
        ):
            raise IamError("INVALID_REQUEST")
        invitation_plan = self._invitation_plan(
            context=context,
            command=command,
        )
        if command.return_to not in self._security_policy.allowed_return_to:
            raise IamError("INVALID_REQUEST")
        _server_now(self._clock)
        auth_transaction_id = _new_uuid(self._id_source, "auth_transaction")
        audit_event_id = _new_uuid(self._id_source, "security_audit_event")
        state = _new_secret(self._secret_source, "oidc-state", 32)
        nonce = _new_secret(self._secret_source, "oidc-nonce", 32)
        verifier = _new_secret(self._secret_source, "oidc-pkce-verifier", 32)
        browser_secret = _new_secret(
            self._secret_source,
            "oidc-browser-binding",
            32,
        )
        challenge = _pkce_challenge(verifier)
        state_key_id = _active_key_id(
            self._protocol_keyring,
            "state_digest_key_id",
        )
        browser_key_id = _active_key_id(
            self._protocol_keyring,
            "browser_binding_digest_key_id",
        )
        nonce_key_id = _active_key_id(
            self._protocol_keyring,
            "nonce_digest_key_id",
        )
        encryption_key_id = _active_key_id(
            self._protocol_secret_box,
            "key_id",
        )
        state_digest = _digest_text(
            self._protocol_keyring,
            key_id=state_key_id,
            value=state,
        )
        browser_digest = _digest_text(
            self._protocol_keyring,
            key_id=browser_key_id,
            value=browser_secret,
        )
        nonce_digest = _digest_text(
            self._protocol_keyring,
            key_id=nonce_key_id,
            value=nonce,
        )
        nonce_ciphertext = _encrypt(
            self._protocol_secret_box,
            plaintext=nonce,
            key_id=encryption_key_id,
        )
        verifier_ciphertext = _encrypt(
            self._protocol_secret_box,
            plaintext=verifier,
            key_id=encryption_key_id,
        )
        _provider_preflight(self._provider, self._security_policy)
        try:
            authorization = self._provider.begin(
                auth_transaction_id=str(auth_transaction_id),
                redirect_uri=self._security_policy.redirect_uri,
                code_challenge=challenge,
                state=state,
                nonce=nonce,
                expected_issuer=self._security_policy.provider_issuer,
                expected_audience=self._security_policy.provider_audience,
            )
        except IdentityProviderUnavailableError as error:
            raise IamError("IDENTITY_PROVIDER_UNAVAILABLE") from error
        except (
            IdentityProviderRejectedError,
            IdentityProviderMisconfiguredError,
        ) as error:
            raise IamError("SERVICE_UNAVAILABLE") from error
        if (
            getattr(authorization, "issuer", None)
            != self._security_policy.provider_issuer
            or getattr(authorization, "audience", None)
            != self._security_policy.provider_audience
            or getattr(authorization, "redirect_uri", None)
            != self._security_policy.redirect_uri
            or getattr(authorization, "code_challenge_method", None) != "S256"
            or not isinstance(getattr(authorization, "authorization_url", None), str)
            or not authorization.authorization_url
        ):
            raise IamError("SERVICE_UNAVAILABLE")
        correlation_id = _context_uuid("correlation", context.correlation_id)
        trace_id = _context_uuid("trace", context.trace_id)
        request = OidcPostgresBeginRequest(
            auth_transaction_id=auth_transaction_id,
            purpose=(
                OidcPostgresPurpose.LOGIN
                if invitation_plan is None
                else (
                    OidcPostgresPurpose.ENROLLMENT
                    if invitation_plan.user_id is None
                    else OidcPostgresPurpose.STEP_UP
                )
            ),
            browser_binding_digest=browser_digest,
            browser_binding_key_id=browser_key_id,
            initiating_session_id=(
                None if invitation_plan is None else invitation_plan.session_id
            ),
            initiating_user_id=(
                None if invitation_plan is None else invitation_plan.user_id
            ),
            expected_user_id=(
                None if invitation_plan is None else invitation_plan.user_id
            ),
            invitation_id=(
                None if invitation_plan is None else invitation_plan.invitation_id
            ),
            invitation_version=(
                None if invitation_plan is None else invitation_plan.invitation_version
            ),
            expected_contact_point_id=(
                None if invitation_plan is None else invitation_plan.contact_point_id
            ),
            expected_contact_type=(
                None if invitation_plan is None else invitation_plan.contact_type
            ),
            expected_contact_binding_digest=(
                None if invitation_plan is None else invitation_plan.binding_digest
            ),
            expected_contact_binding_key_id=(
                None if invitation_plan is None else invitation_plan.binding_key_id
            ),
            state_digest=state_digest,
            state_digest_key_id=state_key_id,
            nonce_digest=nonce_digest,
            nonce_digest_key_id=nonce_key_id,
            nonce_ciphertext=nonce_ciphertext,
            nonce_encryption_key_id=encryption_key_id,
            pkce_verifier_ciphertext=verifier_ciphertext,
            pkce_encryption_key_id=encryption_key_id,
            pkce_code_challenge=challenge,
            provider_issuer=self._security_policy.provider_issuer,
            provider_audience=self._security_policy.provider_audience,
            redirect_uri=self._security_policy.redirect_uri,
            return_to=command.return_to,
            security_policy_version=self._security_policy.policy_version,
            audit_event_id=audit_event_id,
            system_actor_id=self._system_actor_id,
            correlation_id=correlation_id,
            trace_id=trace_id,
        )
        persisted = self._uow.begin(request)
        _validate_persisted_begin(persisted, request)
        return BeginOidcAuthorizationResult(
            auth_transaction_id=str(auth_transaction_id),
            authorization_url=authorization.authorization_url,
            expires_at=persisted.deadline,
            oidc_browser_cookie=browser_secret,
        )

    def _invitation_plan(
        self,
        *,
        context: OidcBrowserContext,
        command: BeginOidcAuthorizationCommand,
    ) -> Optional["_InvitationBeginPlan"]:
        token = command.access_invitation_token
        if not isinstance(command.reauthenticate, bool):
            raise IamError("INVALID_REQUEST")
        if token is not None and command.reauthenticate:
            raise IamError("INVALID_REQUEST")
        if token is None:
            if not command.reauthenticate:
                if context.raw_session_handle is not None:
                    raise IamError("INVALID_REQUEST")
                return None
            if context.raw_session_handle is None:
                raise IamError("AUTHENTICATION_REQUIRED")
            if (
                command.return_to != "/app"
                or not callable(getattr(self._session_security, "authenticate", None))
            ):
                raise IamError("SERVICE_UNAVAILABLE")
            actor = self._session_security.authenticate(
                raw_session_handle=context.raw_session_handle,
                trace_id=context.trace_id,
            )
            if actor is None:
                raise IamError("AUTHENTICATION_REQUIRED")
            try:
                return _InvitationBeginPlan(
                    user_id=UUID(actor.actor_user_id),
                    session_id=UUID(actor.session_id),
                    invitation_id=None,
                    invitation_version=None,
                    contact_point_id=None,
                    contact_type=None,
                    binding_digest=None,
                    binding_key_id=None,
                )
            except (TypeError, ValueError, AttributeError):
                raise IamError("SERVICE_UNAVAILABLE") from None
        if (
            not callable(getattr(self._invitation_capabilities, "verify", None))
            or not callable(
                getattr(self._invitation_reads, "read_invitation_preview", None)
            )
        ):
            raise IamError("SERVICE_UNAVAILABLE")
        now = _server_now(self._clock)
        try:
            capability = self._invitation_capabilities.verify(
                access_invitation_token=token,
                now=now,
            )
            snapshot = self._invitation_reads.read_invitation_preview(
                capability=capability
            )
        except IamError:
            raise
        except Exception:
            raise IamError("ACCESS_INVITATION_UNAVAILABLE") from None
        copier = getattr(snapshot, "facts_copy", None)
        facts = copier() if callable(copier) else getattr(snapshot, "facts", None)
        if not isinstance(facts, Mapping):
            raise IamError("SERVICE_UNAVAILABLE")
        invitation = facts.get("invitation")
        binding = facts.get("recipient_binding")
        if not isinstance(invitation, Mapping) or not isinstance(binding, Mapping):
            raise IamError("ACCESS_INVITATION_UNAVAILABLE")
        if (
            invitation.get("invitation_id") != capability.invitation_id
            or invitation.get("token_nonce") != capability.invitation_nonce
            or invitation.get("token_key_id") != capability.token_key_id
            or invitation.get("token_format_version")
            != capability.token_format_version
            or invitation.get("expires_at") != capability.expires_at
            or invitation.get("status") != "ISSUED"
            or invitation.get("purpose") != "ORGANIZATION_MEMBERSHIP"
            or invitation.get("target_scope") != "ORGANIZATION"
            or invitation.get("is_initial_admin") is True
            or invitation.get("target_role") not in {"ORG_ADMIN", "DEMAND_OWNER"}
            or binding.get("contact_point_id")
            != invitation.get("recipient_contact_id")
            or binding.get("contact_type") != "EMAIL"
        ):
            raise IamError("ACCESS_INVITATION_UNAVAILABLE")
        raw_digest = binding.get("binding_digest")
        key_id = binding.get("binding_digest_key_id")
        try:
            digest = bytes.fromhex(raw_digest)
        except (TypeError, ValueError):
            raise IamError("SERVICE_UNAVAILABLE") from None
        if len(digest) != 32 or not isinstance(key_id, str) or not key_id:
            raise IamError("SERVICE_UNAVAILABLE")
        if context.raw_session_handle is None:
            # This first production enrollment slice is deliberately narrower
            # than signed-in invitation STEP_UP: only a Demand Owner may be
            # created from an anonymous invitation. New ORG_ADMIN enrollment
            # remains closed until it has its own takeover/recovery review.
            if invitation.get("target_role") != "DEMAND_OWNER":
                raise IamError("ACCESS_INVITATION_UNAVAILABLE")
            try:
                return _InvitationBeginPlan(
                    user_id=None,
                    session_id=None,
                    invitation_id=UUID(capability.invitation_id),
                    invitation_version=int(invitation["aggregate_version"]),
                    contact_point_id=UUID(binding["contact_point_id"]),
                    contact_type="EMAIL",
                    binding_digest=digest,
                    binding_key_id=key_id,
                )
            except (KeyError, TypeError, ValueError, AttributeError):
                raise IamError("SERVICE_UNAVAILABLE") from None
        if not callable(getattr(self._session_security, "authenticate", None)):
            raise IamError("SERVICE_UNAVAILABLE")
        actor = self._session_security.authenticate(
            raw_session_handle=context.raw_session_handle,
            trace_id=context.trace_id,
        )
        if actor is None:
            raise IamError("AUTHENTICATION_REQUIRED")
        try:
            return _InvitationBeginPlan(
                user_id=UUID(actor.actor_user_id),
                session_id=UUID(actor.session_id),
                invitation_id=UUID(capability.invitation_id),
                invitation_version=int(invitation["aggregate_version"]),
                contact_point_id=UUID(binding["contact_point_id"]),
                contact_type="EMAIL",
                binding_digest=digest,
                binding_key_id=key_id,
            )
        except (KeyError, TypeError, ValueError, AttributeError):
            raise IamError("SERVICE_UNAVAILABLE") from None


class PostgresCompleteOidcAuthenticationHandler:
    """Claim one callback, exchange once, and atomically establish a Session."""

    def __init__(
        self,
        *,
        oidc_uow: Any,
        provider: Any,
        protocol_keyring: Any,
        protocol_secret_box: Any,
        session_keyring: Any,
        clock: Any,
        id_source: Any,
        secret_source: Any,
        system_actor_id: UUID,
        security_policy: OidcSecurityPolicy,
        session_security: Any = None,
    ) -> None:
        self._uow = oidc_uow
        self._provider = provider
        self._protocol_keyring = protocol_keyring
        self._protocol_secret_box = protocol_secret_box
        self._session_keyring = session_keyring
        self._clock = clock
        self._id_source = id_source
        self._secret_source = secret_source
        self._system_actor_id = system_actor_id
        self._security_policy = security_policy
        self._session_security = session_security

    def handle(
        self,
        *,
        context: OidcBrowserContext,
        command: CompleteOidcAuthenticationCommand,
    ) -> CompleteOidcAuthenticationResult:
        if not isinstance(context, OidcBrowserContext) or not isinstance(
            command, CompleteOidcAuthenticationCommand
        ):
            raise IamError("AUTH_TRANSACTION_INVALID")
        if (
            not isinstance(context.raw_oidc_browser_cookie, str)
            or not context.raw_oidc_browser_cookie
            or not isinstance(command.state, str)
            or not command.state
            or (command.code is None) == (command.provider_error is None)
            or (command.code is not None and not command.code)
        ):
            raise IamError("AUTH_TRANSACTION_INVALID")
        now = _server_now(self._clock)
        pending = self._lookup_unique_pending(
            raw_state=command.state,
            raw_browser_cookie=context.raw_oidc_browser_cookie,
        )
        _validate_pending(pending, self._security_policy, now)
        self._validate_callback_session(context=context, transaction=pending)
        if command.provider_error is not None:
            self._finish(
                transaction=pending,
                owner_id=None,
                outcome=OidcPostgresTerminalOutcome.REJECTED,
                context=context,
            )
            raise IamError("AUTHENTICATION_REJECTED")
        nonce = _decrypt(
            self._protocol_secret_box,
            ciphertext=pending.nonce_ciphertext,
            key_id=pending.nonce_encryption_key_id,
        )
        verifier = _decrypt(
            self._protocol_secret_box,
            ciphertext=pending.pkce_verifier_ciphertext,
            key_id=pending.pkce_encryption_key_id,
        )
        if not hmac.compare_digest(
            _digest_text(
                self._protocol_keyring,
                key_id=pending.nonce_digest_key_id,
                value=nonce,
            ),
            pending.nonce_digest,
        ) or not hmac.compare_digest(
            _pkce_challenge(verifier),
            pending.pkce_code_challenge,
        ):
            raise IamError("SERVICE_UNAVAILABLE")
        _provider_exchange_preflight(self._provider, self._security_policy)
        owner_id = _new_uuid(self._id_source, "exchange_owner")
        claimed = self._uow.claim_exchange(
            OidcPostgresExchangeClaim(
                auth_transaction_id=pending.auth_transaction_id,
                exchange_owner_id=owner_id,
                invitation_id=pending.invitation_id,
            )
        )
        _validate_claimed(claimed, pending, owner_id)
        try:
            subject = self._provider.exchange(
                ProviderExchangeRequest(
                    auth_transaction_id=str(pending.auth_transaction_id),
                    code=command.code or "",
                    state=command.state,
                    redirect_uri=pending.redirect_uri,
                    code_verifier=verifier,
                    expected_nonce=nonce,
                    expected_issuer=pending.provider_issuer,
                    expected_audience=pending.provider_audience,
                    server_now=now,
                )
            )
        except IdentityProviderRejectedError as error:
            self._finish(
                transaction=claimed,
                owner_id=owner_id,
                outcome=OidcPostgresTerminalOutcome.REJECTED,
                context=context,
            )
            raise IamError("AUTHENTICATION_REJECTED") from error
        except IdentityProviderMisconfiguredError as error:
            self._finish(
                transaction=claimed,
                owner_id=owner_id,
                outcome=OidcPostgresTerminalOutcome.MISCONFIGURED,
                context=context,
            )
            raise IamError("SERVICE_UNAVAILABLE") from error
        except (
            IdentityProviderResultUnknownError,
            IdentityProviderUnavailableError,
        ) as error:
            self._finish(
                transaction=claimed,
                owner_id=owner_id,
                outcome=OidcPostgresTerminalOutcome.RESULT_UNKNOWN,
                context=context,
            )
            raise IamError("IDENTITY_PROVIDER_UNAVAILABLE") from error
        except Exception as error:
            self._finish(
                transaction=claimed,
                owner_id=owner_id,
                outcome=OidcPostgresTerminalOutcome.RESULT_UNKNOWN,
                context=context,
            )
            raise IamError("IDENTITY_PROVIDER_UNAVAILABLE") from error
        final_now = _server_now(self._clock)
        try:
            (
                subject_digest,
                amr_codes,
                verified_contact_type,
                verified_contact_digest,
                verified_contact_key_id,
            ) = _validate_subject(
                subject,
                transaction=claimed,
                now=final_now,
            )
        except IamError as error:
            self._finish(
                transaction=claimed,
                owner_id=owner_id,
                outcome=(
                    OidcPostgresTerminalOutcome.REJECTED
                    if error.code == "AUTHENTICATION_REJECTED"
                    else OidcPostgresTerminalOutcome.MISCONFIGURED
                ),
                context=context,
            )
            raise
        step_up_facts = None
        enrollment_ids = None
        if claimed.purpose is OidcPostgresPurpose.LOGIN:
            family_id = _new_uuid(self._id_source, "session_family")
            session_id = _new_uuid(self._id_source, "session")
            generation = 1
        elif claimed.purpose is OidcPostgresPurpose.ENROLLMENT:
            enrollment_ids = (
                _new_uuid(self._id_source, "user"),
                _new_uuid(self._id_source, "external_identity"),
            )
            family_id = _new_uuid(self._id_source, "session_family")
            session_id = _new_uuid(self._id_source, "session")
            generation = 1
        else:
            if claimed.invitation_id is None:
                step_up_facts = self._uow.resolve_generic_step_up_session(
                    auth_transaction_id=claimed.auth_transaction_id,
                    expected_user_id=claimed.expected_user_id,
                    initiating_session_id=claimed.initiating_session_id,
                )
            else:
                step_up_facts = self._uow.resolve_invitation_step_up_session(
                    auth_transaction_id=claimed.auth_transaction_id,
                    invitation_id=claimed.invitation_id,
                    expected_user_id=claimed.expected_user_id,
                    initiating_session_id=claimed.initiating_session_id,
                )
            _validate_step_up_session_facts(step_up_facts, claimed)
            family_id = step_up_facts.session_family_id
            session_id = _new_uuid(self._id_source, "successor_session")
            generation = step_up_facts.current_generation + 1
        raw_session_handle = _new_secret(
            self._secret_source,
            "bff-session-handle",
            32,
        )
        csrf_salt = _new_secret_bytes(
            self._secret_source,
            "bff-csrf-salt",
            32,
        )
        handle_key_id = _active_key_id(
            self._session_keyring,
            "session_handle_digest_key_id",
        )
        csrf_key_id = _active_key_id(self._session_keyring, "csrf_key_id")
        try:
            require_key_material(
                self._session_keyring,
                key_ids=(handle_key_id, csrf_key_id),
            )
            handle_digest = _digest_bytes(
                session_handle_digest(
                    self._session_keyring,
                    raw_session_handle,
                )
            )
            csrf_token = derive_csrf_token(
                self._session_keyring,
                raw_session_handle=raw_session_handle,
                csrf_salt=csrf_salt,
                session_id=str(session_id),
                generation=generation,
                key_id=csrf_key_id,
            )
            persisted_csrf_digest = _digest_bytes(
                csrf_digest(
                    self._session_keyring,
                    csrf_token=csrf_token,
                    key_id=csrf_key_id,
                )
            )
        except (KeyUnavailableError, KeyError, TypeError, ValueError) as error:
            self._finish(
                transaction=claimed,
                owner_id=owner_id,
                outcome=OidcPostgresTerminalOutcome.RESULT_UNKNOWN,
                context=context,
            )
            raise IamError("SERVICE_UNAVAILABLE") from error
        common = {
            "auth_transaction_id": claimed.auth_transaction_id,
            "exchange_owner_id": owner_id,
            "provider_issuer": subject.issuer,
            "subject_digest": subject_digest,
            "subject_digest_key_id": subject.subject_digest_key_id,
            "new_session_id": session_id,
            "handle_digest": handle_digest,
            "handle_digest_key_id": handle_key_id,
            "csrf_salt": csrf_salt,
            "csrf_key_id": csrf_key_id,
            "csrf_digest": persisted_csrf_digest,
            "auth_time": subject.auth_time,
            "token_issued_at": subject.token_issued_at,
            "token_expires_at": subject.token_expires_at,
            "acr_code": subject.acr_code,
            "amr_codes": amr_codes,
            "audit_event_id": _new_uuid(self._id_source, "security_audit_event"),
            "system_actor_id": self._system_actor_id,
            "correlation_id": _context_uuid("correlation", context.correlation_id),
            "trace_id": _context_uuid("trace", context.trace_id),
        }
        if claimed.purpose is OidcPostgresPurpose.LOGIN:
            finalize = OidcPostgresExistingLoginFinalize(
                new_session_family_id=family_id,
                **common,
            )
            established = self._uow.finalize_existing_login(finalize)
        elif claimed.purpose is OidcPostgresPurpose.ENROLLMENT:
            if enrollment_ids is None:
                raise IamError("SERVICE_UNAVAILABLE")
            finalize = OidcPostgresEnrollmentFinalize(
                invitation_id=claimed.invitation_id,
                invitation_version=claimed.invitation_version,
                expected_contact_point_id=claimed.expected_contact_point_id,
                expected_contact_type=claimed.expected_contact_type,
                expected_contact_binding_digest=(
                    claimed.expected_contact_binding_digest
                ),
                expected_contact_binding_key_id=(
                    claimed.expected_contact_binding_key_id
                ),
                verified_contact_type=verified_contact_type,
                verified_contact_binding_digest=verified_contact_digest,
                verified_contact_binding_key_id=verified_contact_key_id,
                new_user_id=enrollment_ids[0],
                new_external_identity_id=enrollment_ids[1],
                new_session_family_id=family_id,
                **common,
            )
            established = self._uow.finalize_enrollment(finalize)
        elif claimed.invitation_id is not None:
            finalize = OidcPostgresInvitationStepUpFinalize(
                invitation_id=claimed.invitation_id,
                invitation_version=claimed.invitation_version,
                expected_contact_point_id=claimed.expected_contact_point_id,
                expected_contact_type=claimed.expected_contact_type,
                expected_contact_binding_digest=(
                    claimed.expected_contact_binding_digest
                ),
                expected_contact_binding_key_id=(
                    claimed.expected_contact_binding_key_id
                ),
                expected_user_id=claimed.expected_user_id,
                initiating_session_id=claimed.initiating_session_id,
                session_family_id=family_id,
                predecessor_generation=step_up_facts.current_generation,
                verified_contact_type=verified_contact_type,
                verified_contact_binding_digest=verified_contact_digest,
                verified_contact_binding_key_id=verified_contact_key_id,
                **common,
            )
            established = self._uow.finalize_invitation_step_up(finalize)
        else:
            finalize = OidcPostgresGenericStepUpFinalize(
                expected_user_id=claimed.expected_user_id,
                initiating_session_id=claimed.initiating_session_id,
                session_family_id=family_id,
                predecessor_generation=step_up_facts.current_generation,
                **common,
            )
            established = self._uow.finalize_generic_step_up(finalize)
        if isinstance(established, OidcPostgresAuthenticationRejected):
            raise IamError("AUTHENTICATION_REJECTED")
        _validate_established(
            established,
            session_id=session_id,
            family_id=family_id,
            expected_user_id=(
                claimed.expected_user_id
                if claimed.purpose is OidcPostgresPurpose.STEP_UP
                else None
            ),
            expected_user_status=(
                "PENDING_ENROLLMENT"
                if claimed.purpose is OidcPostgresPurpose.ENROLLMENT
                else "ACTIVE"
            ),
            generation=generation,
        )
        return CompleteOidcAuthenticationResult(
            return_to=claimed.return_to,
            session_id=str(established.session_id),
            user_id=str(established.user_id),
            user_status=established.user_status,
            raw_session_handle=raw_session_handle,
            csrf_token=csrf_token,
        )

    def _validate_callback_session(
        self,
        *,
        context: OidcBrowserContext,
        transaction: OidcPostgresTransaction,
    ) -> None:
        if transaction.purpose in {
            OidcPostgresPurpose.LOGIN,
            OidcPostgresPurpose.ENROLLMENT,
        }:
            if context.raw_session_handle is not None:
                raise IamError("AUTH_TRANSACTION_INVALID")
            return
        if (
            not isinstance(context.raw_session_handle, str)
            or not context.raw_session_handle
            or not callable(getattr(self._session_security, "authenticate", None))
        ):
            raise IamError("AUTHENTICATION_REQUIRED")
        actor = self._session_security.authenticate(
            raw_session_handle=context.raw_session_handle,
            trace_id=context.trace_id,
        )
        if (
            actor is None
            or actor.actor_user_id != str(transaction.expected_user_id)
            or actor.session_id != str(transaction.initiating_session_id)
        ):
            raise IamError("AUTHENTICATION_REJECTED")

    def _lookup_unique_pending(
        self,
        *,
        raw_state: str,
        raw_browser_cookie: str,
    ) -> OidcPostgresTransaction:
        state_ids = _retained_key_ids(
            self._protocol_keyring,
            active_attribute="state_digest_key_id",
            retained_attribute="retained_state_digest_key_ids",
        )
        browser_ids = _retained_key_ids(
            self._protocol_keyring,
            active_attribute="browser_binding_digest_key_id",
            retained_attribute="retained_browser_binding_digest_key_ids",
        )
        matches = []
        for state_key_id in state_ids:
            state_digest = _digest_text(
                self._protocol_keyring,
                key_id=state_key_id,
                value=raw_state,
            )
            for browser_key_id in browser_ids:
                browser_digest = _digest_text(
                    self._protocol_keyring,
                    key_id=browser_key_id,
                    value=raw_browser_cookie,
                )
                try:
                    transaction = self._uow.read_callback(
                        OidcPostgresCallbackLookup(
                            state_digest=state_digest,
                            state_digest_key_id=state_key_id,
                            browser_binding_digest=browser_digest,
                            browser_binding_key_id=browser_key_id,
                        )
                    )
                except IamError as error:
                    if error.code == "AUTH_TRANSACTION_INVALID":
                        continue
                    raise
                if (
                    not isinstance(transaction, OidcPostgresTransaction)
                    or transaction.state_digest_key_id != state_key_id
                    or not hmac.compare_digest(
                        transaction.state_digest,
                        state_digest,
                    )
                    or transaction.browser_binding_key_id != browser_key_id
                    or not hmac.compare_digest(
                        transaction.browser_binding_digest,
                        browser_digest,
                    )
                ):
                    raise IamError("SERVICE_UNAVAILABLE")
                matches.append(transaction)
        if len(matches) != 1:
            raise IamError("AUTH_TRANSACTION_INVALID")
        return matches[0]

    def _finish(
        self,
        *,
        transaction: OidcPostgresTransaction,
        owner_id: Optional[UUID],
        outcome: OidcPostgresTerminalOutcome,
        context: OidcBrowserContext,
    ) -> None:
        self._uow.finish_exchange(
            OidcPostgresExchangeTerminal(
                auth_transaction_id=transaction.auth_transaction_id,
                exchange_owner_id=owner_id,
                invitation_id=transaction.invitation_id,
                outcome=outcome,
                audit_event_id=_new_uuid(
                    self._id_source,
                    "security_audit_event",
                ),
                system_actor_id=self._system_actor_id,
                correlation_id=_context_uuid(
                    "correlation",
                    context.correlation_id,
                ),
                trace_id=_context_uuid("trace", context.trace_id),
            )
        )


def build_postgres_iam_authentication_bundle(
    *,
    oidc_uow: Any,
    provider: Any,
    protocol_keyring: Any,
    protocol_secret_box: Any,
    session_keyring: Any,
    clock: Any,
    id_source: Any,
    secret_source: Any,
    system_actor_id: UUID,
    security_policy: OidcSecurityPolicy,
    invitation_capabilities: Any = None,
    invitation_reads: Any = None,
    session_security: Any = None,
) -> PostgresIamAuthenticationBundle:
    """Validate exact dependencies and expose presenter-ready handlers."""

    if not isinstance(system_actor_id, UUID) or system_actor_id.int == 0:
        raise TypeError("OIDC system actor ID is invalid")
    if not isinstance(security_policy, OidcSecurityPolicy):
        raise TypeError("OIDC security policy is invalid")
    if security_policy.auth_transaction_ttl != _EXPECTED_AUTH_TRANSACTION_TTL:
        raise TypeError("OIDC AuthTransaction TTL must remain exactly ten minutes")
    required = (
        (oidc_uow, "begin"),
        (oidc_uow, "read_callback"),
        (oidc_uow, "claim_exchange"),
        (oidc_uow, "finish_exchange"),
        (oidc_uow, "finalize_existing_login"),
        (provider, "preflight"),
        (provider, "begin"),
        (provider, "exchange"),
        (protocol_keyring, "digest_text"),
        (protocol_secret_box, "encrypt"),
        (protocol_secret_box, "decrypt"),
        (session_keyring, "keyed_digest_hex"),
        (clock, "now"),
        (id_source, "new_id"),
        (secret_source, "token_bytes"),
    )
    if any(not callable(getattr(owner, method, None)) for owner, method in required):
        raise TypeError("OIDC production dependency contract is incomplete")
    if session_security is not None and any(
        not callable(getattr(owner, method, None))
        for owner, method in (
            (session_security, "authenticate"),
            (oidc_uow, "resolve_generic_step_up_session"),
            (oidc_uow, "finalize_generic_step_up"),
        )
    ):
        raise TypeError("OIDC generic STEP_UP dependency contract is incomplete")
    invitation_dependencies = (invitation_capabilities, invitation_reads)
    if any(value is not None for value in invitation_dependencies):
        if any(value is None for value in invitation_dependencies) or any(
            not callable(getattr(owner, method, None))
            for owner, method in (
                (invitation_capabilities, "verify"),
                (invitation_reads, "read_invitation_preview"),
                (oidc_uow, "finalize_enrollment"),
            )
        ):
            raise TypeError("OIDC invitation dependency contract is incomplete")
        if session_security is not None and any(
            not callable(getattr(owner, method, None))
            for owner, method in (
                (oidc_uow, "resolve_invitation_step_up_session"),
                (oidc_uow, "finalize_invitation_step_up"),
            )
        ):
            raise TypeError("OIDC invitation STEP_UP dependency contract is incomplete")
    for active, retained in (
        ("state_digest_key_id", "retained_state_digest_key_ids"),
        ("browser_binding_digest_key_id", "retained_browser_binding_digest_key_ids"),
        ("nonce_digest_key_id", "retained_nonce_digest_key_ids"),
    ):
        _retained_key_ids(
            protocol_keyring,
            active_attribute=active,
            retained_attribute=retained,
        )
    for owner, attribute in (
        (protocol_secret_box, "key_id"),
        (session_keyring, "session_handle_digest_key_id"),
        (session_keyring, "csrf_key_id"),
    ):
        _active_key_id(owner, attribute)
    begin = PostgresBeginOidcAuthorizationHandler(
        oidc_uow=oidc_uow,
        provider=provider,
        protocol_keyring=protocol_keyring,
        protocol_secret_box=protocol_secret_box,
        clock=clock,
        id_source=id_source,
        secret_source=secret_source,
        system_actor_id=system_actor_id,
        security_policy=security_policy,
        invitation_capabilities=invitation_capabilities,
        invitation_reads=invitation_reads,
        session_security=session_security,
    )
    complete = PostgresCompleteOidcAuthenticationHandler(
        oidc_uow=oidc_uow,
        provider=provider,
        protocol_keyring=protocol_keyring,
        protocol_secret_box=protocol_secret_box,
        session_keyring=session_keyring,
        clock=clock,
        id_source=id_source,
        secret_source=secret_source,
        system_actor_id=system_actor_id,
        security_policy=security_policy,
        session_security=session_security,
    )
    return PostgresIamAuthenticationBundle(
        begin_oidc_authorization=begin,
        complete_oidc_authorization=complete,
    )


def _provider_preflight(provider: Any, policy: OidcSecurityPolicy) -> None:
    try:
        provider.preflight(
            expected_issuer=policy.provider_issuer,
            expected_audience=policy.provider_audience,
            redirect_uri=policy.redirect_uri,
        )
    except IdentityProviderUnavailableError as error:
        raise IamError("IDENTITY_PROVIDER_UNAVAILABLE") from error
    except (
        IdentityProviderRejectedError,
        IdentityProviderMisconfiguredError,
    ) as error:
        raise IamError("SERVICE_UNAVAILABLE") from error


def _provider_exchange_preflight(provider: Any, policy: OidcSecurityPolicy) -> None:
    operation = getattr(provider, "preflight_exchange", None)
    if not callable(operation):
        operation = provider.preflight
    try:
        operation(
            expected_issuer=policy.provider_issuer,
            expected_audience=policy.provider_audience,
            redirect_uri=policy.redirect_uri,
        )
    except IdentityProviderUnavailableError as error:
        raise IamError("IDENTITY_PROVIDER_UNAVAILABLE") from error
    except (
        IdentityProviderRejectedError,
        IdentityProviderMisconfiguredError,
    ) as error:
        raise IamError("SERVICE_UNAVAILABLE") from error


def _validate_persisted_begin(
    transaction: Any,
    request: OidcPostgresBeginRequest,
) -> None:
    if (
        not isinstance(transaction, OidcPostgresTransaction)
        or transaction.auth_transaction_id != request.auth_transaction_id
        or transaction.status is not AuthTransactionStatus.PENDING
        or transaction.purpose is not request.purpose
        or transaction.aggregate_version != 1
        or transaction.attempt != 0
        or transaction.deadline - transaction.created_at
        != _EXPECTED_AUTH_TRANSACTION_TTL
        or transaction.provider_issuer != request.provider_issuer
        or transaction.provider_audience != request.provider_audience
        or transaction.redirect_uri != request.redirect_uri
        or transaction.return_to != request.return_to
        or transaction.security_policy_version != request.security_policy_version
        or transaction.state_digest_key_id != request.state_digest_key_id
        or not hmac.compare_digest(transaction.state_digest, request.state_digest)
        or transaction.browser_binding_key_id != request.browser_binding_key_id
        or not hmac.compare_digest(
            transaction.browser_binding_digest,
            request.browser_binding_digest,
        )
        or transaction.initiating_session_id != request.initiating_session_id
        or transaction.initiating_user_id != request.initiating_user_id
        or transaction.expected_user_id != request.expected_user_id
        or transaction.invitation_id != request.invitation_id
        or transaction.invitation_version != request.invitation_version
        or transaction.expected_contact_point_id
        != request.expected_contact_point_id
        or transaction.expected_contact_type != request.expected_contact_type
        or transaction.expected_contact_binding_digest
        != request.expected_contact_binding_digest
        or transaction.expected_contact_binding_key_id
        != request.expected_contact_binding_key_id
        or transaction.nonce_digest != request.nonce_digest
        or transaction.nonce_digest_key_id != request.nonce_digest_key_id
        or transaction.nonce_ciphertext != request.nonce_ciphertext
        or transaction.nonce_encryption_key_id
        != request.nonce_encryption_key_id
        or transaction.pkce_verifier_ciphertext
        != request.pkce_verifier_ciphertext
        or transaction.pkce_encryption_key_id
        != request.pkce_encryption_key_id
        or transaction.pkce_code_challenge != request.pkce_code_challenge
    ):
        raise IamError("SERVICE_UNAVAILABLE")


def _validate_pending(
    transaction: OidcPostgresTransaction,
    policy: OidcSecurityPolicy,
    now: datetime,
) -> None:
    if (
        transaction.status is not AuthTransactionStatus.PENDING
        or transaction.purpose
        not in {
            OidcPostgresPurpose.LOGIN,
            OidcPostgresPurpose.ENROLLMENT,
            OidcPostgresPurpose.STEP_UP,
        }
        or transaction.aggregate_version != 1
        or transaction.attempt != 0
        or transaction.provider_issuer != policy.provider_issuer
        or transaction.provider_audience != policy.provider_audience
        or transaction.redirect_uri != policy.redirect_uri
        or transaction.security_policy_version != policy.policy_version
        or transaction.return_to not in policy.allowed_return_to
        or transaction.deadline <= now
    ):
        raise IamError("AUTH_TRANSACTION_INVALID")
    invitation_coordinates = (
        transaction.invitation_id,
        transaction.invitation_version,
        transaction.expected_contact_point_id,
        transaction.expected_contact_type,
        transaction.expected_contact_binding_digest,
        transaction.expected_contact_binding_key_id,
    )
    if transaction.purpose is OidcPostgresPurpose.LOGIN:
        if (
            transaction.initiating_session_id is not None
            or transaction.initiating_user_id is not None
            or transaction.expected_user_id is not None
            or any(value is not None for value in invitation_coordinates)
        ):
                raise IamError("AUTH_TRANSACTION_INVALID")
    elif transaction.purpose is OidcPostgresPurpose.ENROLLMENT:
        if (
            transaction.initiating_session_id is not None
            or transaction.initiating_user_id is not None
            or transaction.expected_user_id is not None
            or any(value is None for value in invitation_coordinates)
            or transaction.expected_contact_type != "EMAIL"
        ):
            raise IamError("AUTH_TRANSACTION_INVALID")
    else:
        has_invitation = any(value is not None for value in invitation_coordinates)
        if (
            transaction.initiating_session_id is None
            or transaction.initiating_user_id is None
            or transaction.expected_user_id != transaction.initiating_user_id
            or (
                has_invitation
                and any(value is None for value in invitation_coordinates)
            )
        ):
            raise IamError("AUTH_TRANSACTION_INVALID")


def _validate_claimed(
    claimed: Any,
    pending: OidcPostgresTransaction,
    owner_id: UUID,
) -> None:
    if (
        not isinstance(claimed, OidcPostgresTransaction)
        or claimed.auth_transaction_id != pending.auth_transaction_id
        or claimed.status is not AuthTransactionStatus.EXCHANGING
        or claimed.aggregate_version != 2
        or claimed.attempt != 1
        or claimed.exchange_owner_id != owner_id
        or claimed.provider_issuer != pending.provider_issuer
        or claimed.provider_audience != pending.provider_audience
        or claimed.redirect_uri != pending.redirect_uri
        or claimed.return_to != pending.return_to
        or claimed.deadline != pending.deadline
        or claimed.state_digest != pending.state_digest
        or claimed.browser_binding_digest != pending.browser_binding_digest
        or claimed.purpose is not pending.purpose
        or claimed.initiating_session_id != pending.initiating_session_id
        or claimed.initiating_user_id != pending.initiating_user_id
        or claimed.expected_user_id != pending.expected_user_id
        or claimed.invitation_id != pending.invitation_id
        or claimed.invitation_version != pending.invitation_version
        or claimed.expected_contact_point_id != pending.expected_contact_point_id
        or claimed.expected_contact_type != pending.expected_contact_type
        or claimed.expected_contact_binding_digest
        != pending.expected_contact_binding_digest
        or claimed.expected_contact_binding_key_id
        != pending.expected_contact_binding_key_id
    ):
        raise IamError("SERVICE_UNAVAILABLE")


def _validate_subject(
    subject: Any,
    *,
    transaction: OidcPostgresTransaction,
    now: datetime,
) -> Tuple[bytes, Tuple[str, ...], Optional[str], Optional[bytes], Optional[str]]:
    values = (
        getattr(subject, "auth_time", None),
        getattr(subject, "token_issued_at", None),
        getattr(subject, "token_expires_at", None),
    )
    if any(
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() != timedelta(0)
        for value in values
    ):
        raise IamError("SERVICE_UNAVAILABLE")
    raw_digest = getattr(subject, "subject_digest", None)
    key_id = getattr(subject, "subject_digest_key_id", None)
    issuer = getattr(subject, "issuer", None)
    acr_code = getattr(subject, "acr_code", None)
    raw_amr = getattr(subject, "amr_codes", None)
    if (
        issuer != transaction.provider_issuer
        or not isinstance(raw_digest, str)
        or _LOWER_HEX_32.fullmatch(raw_digest) is None
        or not isinstance(key_id, str)
        or not key_id
        or subject.auth_time > now
        or subject.token_issued_at > now
        or now >= subject.token_expires_at
        or not isinstance(acr_code, str)
        or not acr_code
        or not isinstance(raw_amr, tuple)
        or not raw_amr
        or any(not isinstance(value, str) or not value for value in raw_amr)
    ):
        raise IamError("AUTHENTICATION_REJECTED")
    amr_codes = tuple(sorted(set(raw_amr)))
    if len(amr_codes) > 16:
        raise IamError("AUTHENTICATION_REJECTED")
    if (
        transaction.purpose is OidcPostgresPurpose.LOGIN
        or (
            transaction.purpose is OidcPostgresPurpose.STEP_UP
            and transaction.invitation_id is None
        )
    ):
        return bytes.fromhex(raw_digest), amr_codes, None, None, None
    raw_bindings = getattr(
        subject, "verified_recipient_binding_candidates", ()
    )
    if not raw_bindings:
        raw_bindings = (getattr(subject, "verified_recipient_binding", None),)
    if not isinstance(raw_bindings, tuple) or not 1 <= len(raw_bindings) <= 4:
        raise IamError("AUTHENTICATION_REJECTED")
    matching_bindings = tuple(
        binding
        for binding in raw_bindings
        if getattr(binding, "contact_type", None)
        == transaction.expected_contact_type
        and getattr(binding, "digest_key_id", None)
        == transaction.expected_contact_binding_key_id
    )
    if len(matching_bindings) != 1:
        raise IamError("AUTHENTICATION_REJECTED")
    binding = matching_bindings[0]
    contact_type = getattr(binding, "contact_type", None)
    binding_digest = getattr(binding, "binding_digest", None)
    binding_key_id = getattr(binding, "digest_key_id", None)
    try:
        digest = bytes.fromhex(binding_digest)
    except (TypeError, ValueError):
        raise IamError("AUTHENTICATION_REJECTED") from None
    if (
        contact_type != transaction.expected_contact_type
        or len(digest) != 32
        or binding_key_id != transaction.expected_contact_binding_key_id
    ):
        raise IamError("AUTHENTICATION_REJECTED")
    return (
        bytes.fromhex(raw_digest),
        amr_codes,
        contact_type,
        digest,
        binding_key_id,
    )


def _validate_established(
    established: Any,
    *,
    session_id: UUID,
    family_id: UUID,
    expected_user_id: Optional[UUID],
    expected_user_status: str,
    generation: int,
) -> None:
    if (
        not isinstance(established, OidcPostgresSessionResult)
        or established.session_id != session_id
        or established.session_family_id != family_id
        or established.user_status != expected_user_status
        or established.generation != generation
        or not isinstance(established.user_id, UUID)
        or established.user_id.int == 0
        or (
            expected_user_id is not None
            and established.user_id != expected_user_id
        )
    ):
        raise IamError("SERVICE_UNAVAILABLE")


def _validate_step_up_session_facts(
    facts: Any,
    transaction: OidcPostgresTransaction,
) -> None:
    if (
        facts is None
        or facts.user_id != transaction.expected_user_id
        or facts.initiating_session_id != transaction.initiating_session_id
        or not isinstance(facts.session_family_id, UUID)
        or facts.session_family_id.int == 0
        or not isinstance(facts.current_generation, int)
        or facts.current_generation < 1
    ):
        raise IamError("SERVICE_UNAVAILABLE")


def _server_now(clock: Any) -> datetime:
    try:
        value = clock.now()
    except Exception as error:
        raise IamError("SERVICE_UNAVAILABLE") from error
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() != timedelta(0)
    ):
        raise IamError("SERVICE_UNAVAILABLE")
    return value


def _new_uuid(source: Any, kind: str) -> UUID:
    try:
        value = source.new_id(kind)
        parsed = value if isinstance(value, UUID) else UUID(str(value))
    except (Exception, ValueError, TypeError, AttributeError) as error:
        raise IamError("SERVICE_UNAVAILABLE") from error
    if parsed.int == 0:
        raise IamError("SERVICE_UNAVAILABLE")
    return parsed


def _new_secret(source: Any, purpose: str, length: int) -> str:
    raw = _new_secret_bytes(source, purpose, length)
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _new_secret_bytes(source: Any, purpose: str, length: int) -> bytes:
    try:
        raw = source.token_bytes(purpose, length)
    except Exception as error:
        raise IamError("SERVICE_UNAVAILABLE") from error
    if not isinstance(raw, bytes) or len(raw) != length:
        raise IamError("SERVICE_UNAVAILABLE")
    return raw


def _pkce_challenge(verifier: str) -> str:
    try:
        digest = hashlib.sha256(verifier.encode("ascii")).digest()
    except (UnicodeEncodeError, AttributeError) as error:
        raise IamError("SERVICE_UNAVAILABLE") from error
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _active_key_id(owner: Any, attribute: str) -> str:
    value = getattr(owner, attribute, None)
    if not isinstance(value, str) or not value or len(value) > 64:
        raise TypeError("OIDC key ID contract is invalid")
    return value


def _retained_key_ids(
    owner: Any,
    *,
    active_attribute: str,
    retained_attribute: str,
) -> Tuple[str, ...]:
    active = _active_key_id(owner, active_attribute)
    retained = getattr(owner, retained_attribute, (active,))
    if (
        not isinstance(retained, tuple)
        or not 1 <= len(retained) <= _MAX_RETAINED_KEYS
        or retained[0] != active
        or len(set(retained)) != len(retained)
        or any(not isinstance(value, str) or not value for value in retained)
    ):
        raise TypeError("OIDC retained key contract is invalid")
    return retained


def _digest_text(keyring: Any, *, key_id: str, value: str) -> bytes:
    try:
        digest = keyring.digest_text(key_id=key_id, value=value)
    except Exception as error:
        raise IamError("SERVICE_UNAVAILABLE") from error
    return _digest_bytes(digest)


def _digest_bytes(value: Any) -> bytes:
    if not isinstance(value, str) or _LOWER_HEX_32.fullmatch(value) is None:
        raise IamError("SERVICE_UNAVAILABLE")
    return bytes.fromhex(value)


def _encrypt(secret_box: Any, *, plaintext: str, key_id: str) -> bytes:
    try:
        value = secret_box.encrypt(plaintext=plaintext, key_id=key_id)
        if isinstance(value, str):
            value = value.encode("ascii", errors="strict")
    except Exception as error:
        raise IamError("SERVICE_UNAVAILABLE") from error
    if not isinstance(value, bytes) or not 1 <= len(value) <= 16_384:
        raise IamError("SERVICE_UNAVAILABLE")
    return value


def _decrypt(secret_box: Any, *, ciphertext: bytes, key_id: str) -> str:
    try:
        value = secret_box.decrypt(ciphertext=ciphertext, key_id=key_id)
    except Exception as error:
        raise IamError("SERVICE_UNAVAILABLE") from error
    if not isinstance(value, str) or not value:
        raise IamError("SERVICE_UNAVAILABLE")
    return value


def _context_uuid(domain: str, value: Any) -> UUID:
    safe = value if isinstance(value, str) else ""
    return uuid5(_TRACE_NAMESPACE, "desire-iam-oidc-v1\x00" + domain + "\x00" + safe)


__all__ = [
    "PostgresBeginOidcAuthorizationHandler",
    "PostgresCompleteOidcAuthenticationHandler",
    "PostgresIamAuthenticationBundle",
    "build_postgres_iam_authentication_bundle",
]
