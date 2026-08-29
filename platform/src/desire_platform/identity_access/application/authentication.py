"""Default-deny OIDC/AuthTransaction application scaffold.

The public command and result shapes are intentionally closed and safe to
import.  The handlers remain a semantic RED until the frozen claim/exchange/
finalize protocol is implemented.
"""

from __future__ import annotations

import base64
from copy import deepcopy
from dataclasses import dataclass, field, fields
from datetime import datetime, timedelta
import hashlib
import hmac
from typing import Any, Mapping, Optional, Tuple

from ..domain.authentication import (
    AuthPurpose,
    AuthTransaction,
    AuthTransactionStatus,
    ProviderErrorClass,
)
from ..domain.errors import IamError
from ..domain.invitations import InvitationStatus
from ..ports.identity_provider import (
    IdentityProviderMisconfiguredError,
    IdentityProviderRejectedError,
    IdentityProviderResultUnknownError,
    IdentityProviderUnavailableError,
    ProviderExchangeRequest,
)
from ..security.cryptography import (
    KeyUnavailableError,
    canonical_json_bytes,
    csrf_digest,
    derive_csrf_token,
    require_key_material,
    session_handle_digest,
)


@dataclass(frozen=True)
class OidcSecurityPolicy:
    policy_version: str
    provider_issuer: str
    provider_audience: str
    redirect_uri: str
    allowed_return_to: Tuple[str, ...]
    auth_transaction_ttl: timedelta = timedelta(minutes=10)
    session_idle_ttl: timedelta = timedelta(minutes=30)
    session_absolute_ttl: timedelta = timedelta(hours=12)
    provider_clock_skew: timedelta = timedelta(seconds=30)


@dataclass(frozen=True)
class OidcBrowserContext:
    raw_session_handle: Optional[str] = field(default=None, repr=False)
    raw_oidc_browser_cookie: Optional[str] = field(default=None, repr=False)
    correlation_id: str = ""
    causation_id: str = ""
    trace_id: str = ""


@dataclass(frozen=True)
class BeginOidcAuthorizationCommand:
    return_to: str
    access_invitation_token: Optional[str] = field(default=None, repr=False)
    reauthenticate: bool = False


@dataclass(frozen=True)
class BeginOidcAuthorizationResult:
    auth_transaction_id: str
    authorization_url: str = field(repr=False)
    expires_at: datetime
    oidc_browser_cookie: str = field(repr=False)


@dataclass(frozen=True)
class CompleteOidcAuthenticationCommand:
    state: str = field(repr=False)
    code: Optional[str] = field(default=None, repr=False)
    provider_error: Optional[str] = field(default=None, repr=False)
    provider_error_description: Optional[str] = field(default=None, repr=False)


@dataclass(frozen=True)
class CompleteOidcAuthenticationResult:
    return_to: str
    session_id: str
    user_id: str
    user_status: str
    raw_session_handle: str = field(repr=False)
    csrf_token: str = field(repr=False)
    clear_oidc_browser_cookie: bool = True


class BeginOidcAuthorizationHandler:
    def __init__(
        self,
        *,
        uow_factory,
        clock,
        provider,
        invitation_capability,
        protocol_keyring,
        protocol_secret_box,
        id_source,
        secret_source,
        security_policy: OidcSecurityPolicy,
    ) -> None:
        self._uow_factory = uow_factory
        self._clock = clock
        self._provider = provider
        self._invitation_capability = invitation_capability
        self._protocol_keyring = protocol_keyring
        self._protocol_secret_box = protocol_secret_box
        self._id_source = id_source
        self._secret_source = secret_source
        self._security_policy = security_policy

    def handle(
        self,
        *,
        context: OidcBrowserContext,
        command: BeginOidcAuthorizationCommand,
    ) -> BeginOidcAuthorizationResult:
        now = _require_server_now(self._clock.now())
        if command.return_to not in self._security_policy.allowed_return_to:
            raise IamError("INVALID_REQUEST")

        snapshot = _snapshot(self._uow_factory)
        current = _resolve_current_session(
            snapshot=snapshot,
            raw_session_handle=context.raw_session_handle,
            keyring=self._protocol_keyring,
            now=now,
        )
        capability = None
        invitation = None
        contact = None
        if command.access_invitation_token is not None:
            try:
                capability = self._invitation_capability.verify(
                    access_invitation_token=command.access_invitation_token,
                    now=now,
                )
            except IamError as error:
                if error.code == "SERVICE_UNAVAILABLE":
                    raise
                raise IamError("ACCESS_INVITATION_UNAVAILABLE") from error
            invitation, contact = _resolve_capability_invitation(
                snapshot=snapshot,
                capability=capability,
                now=now,
            )

        if capability is None:
            purpose = AuthPurpose.LOGIN
        elif current is None:
            purpose = AuthPurpose.ENROLLMENT
        else:
            purpose = AuthPurpose.STEP_UP

        auth_transaction_id = self._id_source.new_id("auth_transaction")
        state = _new_secret(self._secret_source, "oidc-state", 32)
        nonce = _new_secret(self._secret_source, "oidc-nonce", 32)
        verifier = _new_secret(self._secret_source, "oidc-pkce-verifier", 32)
        browser_secret = _new_secret(
            self._secret_source,
            "oidc-browser-binding",
            32,
        )
        challenge = _pkce_challenge(verifier)

        state_key_id = _key_id(
            self._protocol_keyring,
            "state_digest_key_id",
        )
        browser_key_id = _key_id(
            self._protocol_keyring,
            "browser_binding_digest_key_id",
        )
        encryption_key_id = _key_id(
            self._protocol_secret_box,
            "key_id",
        )
        state_digest = _digest_text(
            self._protocol_keyring,
            state_key_id,
            state,
        )
        browser_digest = _digest_text(
            self._protocol_keyring,
            browser_key_id,
            browser_secret,
        )
        try:
            nonce_ciphertext = self._protocol_secret_box.encrypt(
                plaintext=nonce,
                key_id=encryption_key_id,
            )
            verifier_ciphertext = self._protocol_secret_box.encrypt(
                plaintext=verifier,
                key_id=encryption_key_id,
            )
        except IamError:
            raise
        except Exception as error:
            raise IamError("SERVICE_UNAVAILABLE") from error

        _provider_preflight(
            self._provider,
            issuer=self._security_policy.provider_issuer,
            audience=self._security_policy.provider_audience,
            redirect_uri=self._security_policy.redirect_uri,
        )
        try:
            authorization = self._provider.begin(
                auth_transaction_id=auth_transaction_id,
                redirect_uri=self._security_policy.redirect_uri,
                code_challenge=challenge,
                state=state,
                nonce=nonce,
                expected_issuer=self._security_policy.provider_issuer,
                expected_audience=self._security_policy.provider_audience,
            )
        except IdentityProviderUnavailableError as error:
            raise IamError("IDENTITY_PROVIDER_UNAVAILABLE") from error
        except (IdentityProviderRejectedError, IdentityProviderMisconfiguredError) as error:
            raise IamError("SERVICE_UNAVAILABLE") from error
        if (
            authorization.issuer != self._security_policy.provider_issuer
            or authorization.audience != self._security_policy.provider_audience
            or authorization.redirect_uri != self._security_policy.redirect_uri
            or authorization.code_challenge_method != "S256"
        ):
            raise IamError("SERVICE_UNAVAILABLE")

        initiating_session_id = current[0]["session_id"] if current else None
        initiating_user_id = current[0]["user_id"] if current else None
        expected_user_id = (
            initiating_user_id if purpose == AuthPurpose.STEP_UP else None
        )
        invitation_id = _fact(invitation, "invitation_id") if invitation else None
        invitation_version = (
            _fact(invitation, "aggregate_version") if invitation else None
        )
        contact_id = _fact(contact, "contact_point_id") if contact else None
        deadline = now + self._security_policy.auth_transaction_ttl
        transaction_row = {
            "auth_transaction_id": auth_transaction_id,
            "status": AuthTransactionStatus.PENDING.value,
            "purpose": purpose.value,
            "browser_binding_digest": browser_digest,
            "browser_binding_digest_key_id": browser_key_id,
            "initiating_session_id": initiating_session_id,
            "initiating_user_id": initiating_user_id,
            "expected_user_id": expected_user_id,
            "invitation_id": invitation_id,
            "invitation_version": invitation_version,
            "expected_contact_point_id": contact_id,
            "expected_contact_type": _fact(contact, "type") if contact else None,
            "expected_contact_binding_digest": (
                _fact(contact, "binding_digest") if contact else None
            ),
            "expected_contact_binding_digest_key_id": (
                _fact(contact, "binding_digest_key_id") if contact else None
            ),
            "state_digest": state_digest,
            "state_digest_key_id": state_key_id,
            "nonce_digest": hashlib.sha256(nonce.encode("utf-8")).hexdigest(),
            "nonce_ciphertext": nonce_ciphertext,
            "nonce_encryption_key_id": encryption_key_id,
            "pkce_verifier_ciphertext": verifier_ciphertext,
            "pkce_encryption_key_id": encryption_key_id,
            "pkce_code_challenge": challenge,
            "pkce_code_challenge_method": "S256",
            "provider_issuer": self._security_policy.provider_issuer,
            "provider_audience": self._security_policy.provider_audience,
            "redirect_uri": self._security_policy.redirect_uri,
            "return_to": command.return_to,
            "security_policy_version": self._security_policy.policy_version,
            "deadline": deadline,
            "attempt": 0,
            "exchange_owner_id": None,
            "exchange_claimed_at": None,
            "provider_error_class": None,
            "aggregate_version": 1,
            "created_at": now,
            "updated_at": now,
        }
        audit_id = self._id_source.new_id("security_audit_event")

        with self._uow_factory.begin() as uow:
            if current is not None:
                family_locked = uow.lock(
                    "session_families",
                    current[1]["session_family_id"],
                )
                session_locked = uow.lock("sessions", initiating_session_id)
                user_locked = uow.lock("users", initiating_user_id)
                locked_current = _validate_current_rows(
                    session=session_locked,
                    family=family_locked,
                    user=user_locked,
                    now=now,
                )
                if locked_current is None or session_locked != current[0]:
                    raise IamError("AUTH_TRANSACTION_INVALID")
            if invitation is not None:
                locked_invitation = uow.lock("invitations", invitation_id)
                locked_contact = uow.lock("contact_points", contact_id)
                _require_same_authority_fact(
                    locked_invitation,
                    invitation,
                    "ACCESS_INVITATION_UNAVAILABLE",
                )
                _require_same_authority_fact(
                    locked_contact,
                    contact,
                    "ACCESS_INVITATION_UNAVAILABLE",
                )
                _resolve_capability_invitation(
                    snapshot={
                        "invitations": {invitation_id: locked_invitation},
                        "contact_points": {contact_id: locked_contact},
                    },
                    capability=capability,
                    now=now,
                )
            if uow.lock("auth_transactions", auth_transaction_id) is not None:
                raise IamError("SERVICE_UNAVAILABLE")
            if any(
                isinstance(existing, Mapping)
                and _safe_equal(
                    existing.get("state_digest"),
                    state_digest,
                )
                and existing.get("state_digest_key_id") == state_key_id
                for existing in uow.tables.get(
                    "auth_transactions",
                    {},
                ).values()
            ):
                raise IamError("SERVICE_UNAVAILABLE")
            uow.put(
                "auth_transactions",
                auth_transaction_id,
                transaction_row,
                checkpoint="auth.begin.transaction",
            )
            uow.put(
                "security_audit_events",
                audit_id,
                {
                    "security_audit_event_id": audit_id,
                    "action": "BeginOidcAuthorization",
                    "auth_transaction_id": auth_transaction_id,
                    "purpose": purpose.value,
                    "initiating_user_id": initiating_user_id,
                    "invitation_id": invitation_id,
                    "occurred_at": now,
                    "correlation_id": context.correlation_id,
                    "causation_id": context.causation_id,
                    "trace_id": context.trace_id,
                },
                checkpoint="auth.begin.audit",
            )
            _commit(uow)

        return BeginOidcAuthorizationResult(
            auth_transaction_id=auth_transaction_id,
            authorization_url=authorization.authorization_url,
            expires_at=deadline,
            oidc_browser_cookie=browser_secret,
        )


class CompleteOidcAuthenticationHandler:
    def __init__(
        self,
        *,
        uow_factory,
        clock,
        provider,
        recipient_binding,
        protocol_keyring,
        protocol_secret_box,
        session_keyring,
        id_source,
        secret_source,
        security_policy: OidcSecurityPolicy,
    ) -> None:
        self._uow_factory = uow_factory
        self._clock = clock
        self._provider = provider
        self._recipient_binding = recipient_binding
        self._protocol_keyring = protocol_keyring
        self._protocol_secret_box = protocol_secret_box
        self._session_keyring = session_keyring
        self._id_source = id_source
        self._secret_source = secret_source
        self._security_policy = security_policy

    def handle(
        self,
        *,
        context: OidcBrowserContext,
        command: CompleteOidcAuthenticationCommand,
    ) -> CompleteOidcAuthenticationResult:
        now = _require_server_now(self._clock.now())
        if (
            not command.state
            or (command.code is None) == (command.provider_error is None)
            or (command.code is not None and not command.code)
            or not context.raw_oidc_browser_cookie
        ):
            raise IamError("AUTH_TRANSACTION_INVALID")

        snapshot = _snapshot(self._uow_factory)
        transaction_row = _find_transaction_by_state(
            snapshot=snapshot,
            raw_state=command.state,
            keyring=self._protocol_keyring,
        )
        _validate_callback_transaction(
            row=transaction_row,
            raw_browser_cookie=context.raw_oidc_browser_cookie,
            keyring=self._protocol_keyring,
            policy=self._security_policy,
            now=now,
        )
        _validate_transaction_invitation(snapshot, transaction_row, now)

        if command.provider_error is not None:
            self._finish_provider_error(
                transaction_row=transaction_row,
                context=context,
                raw_state=command.state,
                now=now,
            )
            raise IamError("AUTHENTICATION_REJECTED")

        try:
            nonce = self._protocol_secret_box.decrypt(
                ciphertext=transaction_row["nonce_ciphertext"],
                key_id=transaction_row["nonce_encryption_key_id"],
            )
            verifier = self._protocol_secret_box.decrypt(
                ciphertext=transaction_row["pkce_verifier_ciphertext"],
                key_id=transaction_row["pkce_encryption_key_id"],
            )
        except IamError:
            raise
        except Exception as error:
            raise IamError("SERVICE_UNAVAILABLE") from error
        if (
            not hmac.compare_digest(
                hashlib.sha256(nonce.encode("utf-8")).hexdigest(),
                transaction_row["nonce_digest"],
            )
            or _pkce_challenge(verifier)
            != transaction_row["pkce_code_challenge"]
        ):
            raise IamError("SERVICE_UNAVAILABLE")

        _provider_preflight(
            self._provider,
            issuer=transaction_row["provider_issuer"],
            audience=transaction_row["provider_audience"],
            redirect_uri=transaction_row["redirect_uri"],
        )
        owner_id = self._id_source.new_id("exchange_owner")
        claimed = self._claim_transaction(
            expected=transaction_row,
            owner_id=owner_id,
            raw_state=command.state,
            raw_browser_cookie=context.raw_oidc_browser_cookie,
            now=now,
        )

        try:
            subject = self._provider.exchange(
                ProviderExchangeRequest(
                    auth_transaction_id=claimed["auth_transaction_id"],
                    code=command.code or "",
                    state=command.state,
                    redirect_uri=claimed["redirect_uri"],
                    code_verifier=verifier,
                    expected_nonce=nonce,
                    expected_issuer=claimed["provider_issuer"],
                    expected_audience=claimed["provider_audience"],
                    server_now=now,
                )
            )
        except IdentityProviderRejectedError as error:
            self._finish_exchange_error(
                claimed=claimed,
                error_class=ProviderErrorClass.REJECTED,
                now=now,
            )
            raise IamError("AUTHENTICATION_REJECTED") from error
        except (
            IdentityProviderResultUnknownError,
            IdentityProviderUnavailableError,
        ) as error:
            self._finish_exchange_unknown(claimed=claimed, now=now)
            raise IamError("IDENTITY_PROVIDER_UNAVAILABLE") from error
        except IdentityProviderMisconfiguredError as error:
            self._finish_exchange_error(
                claimed=claimed,
                error_class=ProviderErrorClass.MISCONFIGURED,
                now=now,
            )
            raise IamError("SERVICE_UNAVAILABLE") from error
        except Exception as error:
            self._finish_exchange_unknown(claimed=claimed, now=now)
            raise IamError("IDENTITY_PROVIDER_UNAVAILABLE") from error

        final_now = _require_server_now(self._clock.now())
        try:
            _validate_authenticated_subject(
                subject=subject,
                transaction=claimed,
                now=final_now,
            )
        except IamError as error:
            self._finish_exchange_error(
                claimed=claimed,
                error_class=(
                    ProviderErrorClass.MISCONFIGURED
                    if error.code == "SERVICE_UNAVAILABLE"
                    else ProviderErrorClass.REJECTED
                ),
                now=final_now,
            )
            raise
        try:
            material = _prepare_session_material(
                transaction=claimed,
                subject=subject,
                snapshot=_snapshot(self._uow_factory),
                id_source=self._id_source,
                secret_source=self._secret_source,
                session_keyring=self._session_keyring,
            )
        except IamError:
            self._finish_exchange_unknown(claimed=claimed, now=final_now)
            raise
        return self._finalize_success(
            claimed=claimed,
            subject=subject,
            material=material,
            context=context,
            now=final_now,
        )

    def _claim_transaction(
        self,
        *,
        expected: Mapping[str, Any],
        owner_id: str,
        raw_state: str,
        raw_browser_cookie: str,
        now: datetime,
    ) -> dict[str, Any]:
        with self._uow_factory.begin() as uow:
            locked = uow.lock(
                "auth_transactions",
                expected["auth_transaction_id"],
            )
            _validate_callback_transaction(
                row=locked,
                raw_browser_cookie=raw_browser_cookie,
                keyring=self._protocol_keyring,
                policy=self._security_policy,
                now=now,
            )
            _require_same_authority_fact(
                locked,
                expected,
                "AUTH_TRANSACTION_INVALID",
            )
            _validate_state_binding(
                row=locked,
                raw_state=raw_state,
                keyring=self._protocol_keyring,
            )
            if locked.get("auth_transaction_id") != expected.get(
                "auth_transaction_id"
            ):
                raise IamError("AUTH_TRANSACTION_INVALID")
            _validate_transaction_invitation(uow.tables, locked, now)
            claimed = _auth_transaction_from_row(locked).claim_exchange(
                owner_id=owner_id,
                now=now,
            )
            claimed_row = _auth_transaction_to_row(claimed)
            uow.put(
                "auth_transactions",
                claimed.auth_transaction_id,
                claimed_row,
                checkpoint="auth.callback.claim",
            )
            _commit(uow)
            return claimed_row

    def _finish_provider_error(
        self,
        *,
        transaction_row: Mapping[str, Any],
        context: OidcBrowserContext,
        raw_state: str,
        now: datetime,
    ) -> None:
        audit_id = self._id_source.new_id("security_audit_event")
        with self._uow_factory.begin() as uow:
            locked = uow.lock(
                "auth_transactions",
                transaction_row["auth_transaction_id"],
            )
            _require_same_authority_fact(
                locked,
                transaction_row,
                "AUTH_TRANSACTION_INVALID",
            )
            _validate_callback_transaction(
                row=locked,
                raw_browser_cookie=context.raw_oidc_browser_cookie or "",
                keyring=self._protocol_keyring,
                policy=self._security_policy,
                now=now,
            )
            _validate_state_binding(
                row=locked,
                raw_state=raw_state,
                keyring=self._protocol_keyring,
            )
            _validate_transaction_invitation(uow.tables, locked, now)
            failed = _auth_transaction_from_row(locked).fail(
                error_class=ProviderErrorClass.REJECTED,
                now=now,
            )
            uow.put(
                "auth_transactions",
                failed.auth_transaction_id,
                _auth_transaction_to_row(failed),
                checkpoint="auth.callback.provider-error",
            )
            _put_callback_audit(
                uow,
                audit_id=audit_id,
                transaction=locked,
                outcome="REJECTED",
                context=context,
                now=now,
            )
            _commit(uow)

    def _finish_exchange_error(
        self,
        *,
        claimed: Mapping[str, Any],
        error_class: ProviderErrorClass,
        now: datetime,
    ) -> None:
        with self._uow_factory.begin() as uow:
            locked = _lock_claim_owner(uow, claimed)
            failed = _auth_transaction_from_row(locked).fail(
                error_class=error_class,
                now=now,
            )
            uow.put(
                "auth_transactions",
                failed.auth_transaction_id,
                _auth_transaction_to_row(failed),
                checkpoint="auth.callback.exchange-failed",
            )
            _commit(uow)

    def _finish_exchange_unknown(
        self,
        *,
        claimed: Mapping[str, Any],
        now: datetime,
    ) -> None:
        with self._uow_factory.begin() as uow:
            locked = _lock_claim_owner(uow, claimed)
            unknown = _auth_transaction_from_row(locked).mark_result_unknown(
                now=now,
            )
            uow.put(
                "auth_transactions",
                unknown.auth_transaction_id,
                _auth_transaction_to_row(unknown),
                checkpoint="auth.callback.exchange-unknown",
            )
            _commit(uow)

    def _finalize_success(
        self,
        *,
        claimed: Mapping[str, Any],
        subject,
        material: Mapping[str, Any],
        context: OidcBrowserContext,
        now: datetime,
    ) -> CompleteOidcAuthenticationResult:
        rejection_code: Optional[str] = None
        response_facts: Optional[dict[str, Any]] = None
        audit_id = self._id_source.new_id("security_audit_event")
        with self._uow_factory.begin() as uow:
            locked = _lock_claim_owner(uow, claimed)
            transaction = _auth_transaction_from_row(locked)
            try:
                response_facts = _apply_authenticated_subject(
                    uow=uow,
                    transaction=locked,
                    subject=subject,
                    material=material,
                    now=now,
                    security_policy=self._security_policy,
                )
            except IamError as error:
                rejection_code = error.code
                failed = transaction.fail(
                    error_class=ProviderErrorClass.REJECTED,
                    now=now,
                )
                uow.put(
                    "auth_transactions",
                    failed.auth_transaction_id,
                    _auth_transaction_to_row(failed),
                    checkpoint="auth.callback.business-rejected",
                )
                _put_callback_audit(
                    uow,
                    audit_id=audit_id,
                    transaction=locked,
                    outcome="REJECTED",
                    context=context,
                    now=now,
                )
            else:
                succeeded = transaction.succeed(now=now)
                uow.put(
                    "auth_transactions",
                    succeeded.auth_transaction_id,
                    _auth_transaction_to_row(succeeded),
                    checkpoint="auth.callback.succeeded",
                )
                _put_callback_audit(
                    uow,
                    audit_id=audit_id,
                    transaction=locked,
                    outcome="SUCCEEDED",
                    context=context,
                    now=now,
                )
            _commit(uow)

        if rejection_code is not None:
            raise IamError(rejection_code)
        if response_facts is None:
            raise IamError("SERVICE_UNAVAILABLE")
        return CompleteOidcAuthenticationResult(
            return_to=claimed["return_to"],
            session_id=response_facts["session_id"],
            user_id=response_facts["user_id"],
            user_status=response_facts["user_status"],
            raw_session_handle=material["raw_session_handle"],
            csrf_token=material["csrf_token"],
        )


def _require_server_now(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise IamError("SERVICE_UNAVAILABLE")
    return value


def _snapshot(uow_factory) -> dict[str, dict[Any, Any]]:
    try:
        if hasattr(uow_factory, "snapshot"):
            return deepcopy(uow_factory.snapshot())
        return deepcopy(uow_factory.store.snapshot())
    except Exception as error:
        raise IamError("SERVICE_UNAVAILABLE") from error


def _enum_value(value: Any) -> Any:
    return getattr(value, "value", value)


def _fact(value: Any, name: str, default: Any = None) -> Any:
    if isinstance(value, Mapping):
        return value.get(name, default)
    return getattr(value, name, default)


def _key_id(owner: Any, attribute: str) -> str:
    value = getattr(owner, attribute, None)
    if not isinstance(value, str) or not value:
        raise IamError("SERVICE_UNAVAILABLE")
    return value


def _digest_text(keyring, key_id: str, value: str) -> str:
    try:
        digest = keyring.digest_text(key_id=key_id, value=value)
    except IamError:
        raise
    except Exception as error:
        raise IamError("SERVICE_UNAVAILABLE") from error
    if not isinstance(digest, str) or not digest:
        raise IamError("SERVICE_UNAVAILABLE")
    return digest


def _session_handle_digest_for_key(
    keyring,
    *,
    key_id: str,
    raw_session_handle: str,
) -> str:
    try:
        return keyring.keyed_digest_hex(
            key_id=key_id,
            canonical_bytes=canonical_json_bytes(
                {"raw_session_handle": raw_session_handle}
            ),
        )
    except (KeyUnavailableError, KeyError, ValueError, TypeError) as error:
        raise IamError("SERVICE_UNAVAILABLE") from error


def _new_secret(secret_source, purpose: str, length: int) -> str:
    try:
        raw = secret_source.token_bytes(purpose, length)
    except Exception as error:
        raise IamError("SERVICE_UNAVAILABLE") from error
    if not isinstance(raw, bytes) or len(raw) != length:
        raise IamError("SERVICE_UNAVAILABLE")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _new_secret_bytes(secret_source, purpose: str, length: int) -> bytes:
    try:
        raw = secret_source.token_bytes(purpose, length)
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


def _provider_preflight(
    provider,
    *,
    issuer: str,
    audience: str,
    redirect_uri: str,
) -> None:
    try:
        provider.preflight(
            expected_issuer=issuer,
            expected_audience=audience,
            redirect_uri=redirect_uri,
        )
    except IdentityProviderUnavailableError as error:
        raise IamError("IDENTITY_PROVIDER_UNAVAILABLE") from error
    except IdentityProviderRejectedError as error:
        raise IamError("SERVICE_UNAVAILABLE") from error
    except IdentityProviderMisconfiguredError as error:
        raise IamError("SERVICE_UNAVAILABLE") from error


def _commit(uow) -> None:
    try:
        uow.commit()
    except Exception as error:
        raise IamError("COMMAND_OUTCOME_UNKNOWN") from error


def _resolve_current_session(
    *,
    snapshot: Mapping[str, Mapping[Any, Any]],
    raw_session_handle: Optional[str],
    keyring,
    now: datetime,
) -> Optional[tuple[dict[str, Any], dict[str, Any], dict[str, Any]]]:
    if not raw_session_handle:
        return None
    matched = None
    for session in snapshot.get("sessions", {}).values():
        key_id = _fact(session, "handle_digest_key_id")
        stored_digest = _fact(session, "handle_digest")
        if not isinstance(key_id, str) or not isinstance(stored_digest, str):
            continue
        candidate = _session_handle_digest_for_key(
            keyring,
            key_id=key_id,
            raw_session_handle=raw_session_handle,
        )
        if hmac.compare_digest(candidate, stored_digest):
            if matched is not None:
                raise IamError("SERVICE_UNAVAILABLE")
            matched = deepcopy(session)
    if matched is None:
        return None
    family = deepcopy(
        snapshot.get("session_families", {}).get(
            matched.get("session_family_id")
        )
    )
    user = deepcopy(snapshot.get("users", {}).get(matched.get("user_id")))
    return _validate_current_rows(
        session=matched,
        family=family,
        user=user,
        now=now,
    )


def _validate_current_rows(
    *,
    session: Any,
    family: Any,
    user: Any,
    now: datetime,
) -> Optional[tuple[dict[str, Any], dict[str, Any], dict[str, Any]]]:
    if not all(isinstance(value, Mapping) for value in (session, family, user)):
        return None
    session = dict(session)
    family = dict(family)
    user = dict(user)
    if (
        _enum_value(session.get("status")) != "ACTIVE"
        or _enum_value(family.get("status")) != "ACTIVE"
        or _enum_value(user.get("status"))
        not in ("ACTIVE", "PENDING_ENROLLMENT")
        or session.get("session_family_id") != family.get("session_family_id")
        or session.get("user_id") != family.get("user_id")
        or session.get("user_id") != user.get("user_id")
        or session.get("generation") != family.get("current_generation")
    ):
        return None
    deadlines = (
        session.get("idle_expires_at"),
        session.get("absolute_expires_at"),
    )
    for deadline in deadlines:
        if (
            not isinstance(deadline, datetime)
            or deadline.tzinfo is None
            or deadline.utcoffset() != timedelta(0)
            or now >= deadline
        ):
            return None
    return session, family, user


def _resolve_capability_invitation(
    *,
    snapshot: Mapping[str, Mapping[Any, Any]],
    capability,
    now: datetime,
) -> tuple[Any, Mapping[str, Any]]:
    if capability is None:
        raise IamError("ACCESS_INVITATION_UNAVAILABLE")
    invitation_id = _fact(capability, "invitation_id")
    invitation = snapshot.get("invitations", {}).get(invitation_id)
    if invitation is None:
        raise IamError("ACCESS_INVITATION_UNAVAILABLE")
    expires_at = _fact(invitation, "expires_at")
    capability_expires_at = _fact(capability, "expires_at")
    if (
        _enum_value(_fact(invitation, "status")) != InvitationStatus.ISSUED.value
        or not isinstance(expires_at, datetime)
        or expires_at.tzinfo is None
        or expires_at.utcoffset() != timedelta(0)
        or now >= expires_at
        or capability_expires_at != expires_at
        or now >= capability_expires_at
        or not _safe_equal(
            _fact(capability, "invitation_nonce"),
            _fact(invitation, "nonce"),
        )
        or _fact(capability, "token_key_id")
        != _fact(invitation, "token_key_id")
        or _fact(capability, "token_format_version")
        != _fact(invitation, "token_format_version")
    ):
        raise IamError("ACCESS_INVITATION_UNAVAILABLE")
    contact_id = _fact(invitation, "recipient_contact_id")
    contact = snapshot.get("contact_points", {}).get(contact_id)
    if (
        not isinstance(contact, Mapping)
        or contact.get("contact_point_id") != contact_id
        or not isinstance(contact.get("type"), str)
        or not isinstance(contact.get("binding_digest"), str)
        or not isinstance(contact.get("binding_digest_key_id"), str)
    ):
        raise IamError("ACCESS_INVITATION_UNAVAILABLE")
    return deepcopy(invitation), deepcopy(contact)


def _safe_equal(left: Any, right: Any) -> bool:
    if not isinstance(left, str) or not isinstance(right, str):
        return False
    return hmac.compare_digest(left, right)


def _require_same_authority_fact(
    locked: Any,
    expected: Any,
    error_code: str,
) -> None:
    if locked is None or locked != expected:
        raise IamError(error_code)


def _find_transaction_by_state(
    *,
    snapshot: Mapping[str, Mapping[Any, Any]],
    raw_state: str,
    keyring,
) -> dict[str, Any]:
    matched: list[dict[str, Any]] = []
    for transaction in snapshot.get("auth_transactions", {}).values():
        if not isinstance(transaction, Mapping):
            continue
        key_id = transaction.get("state_digest_key_id")
        stored_digest = transaction.get("state_digest")
        if not isinstance(key_id, str) or not isinstance(stored_digest, str):
            continue
        candidate = _digest_text(keyring, key_id, raw_state)
        if hmac.compare_digest(candidate, stored_digest):
            matched.append(deepcopy(dict(transaction)))
    if len(matched) != 1:
        raise IamError("AUTH_TRANSACTION_INVALID")
    return matched[0]


def _validate_callback_transaction(
    *,
    row: Any,
    raw_browser_cookie: str,
    keyring,
    policy: OidcSecurityPolicy,
    now: datetime,
) -> None:
    if not isinstance(row, Mapping):
        raise IamError("AUTH_TRANSACTION_INVALID")
    try:
        status = AuthTransactionStatus(_enum_value(row.get("status")))
        purpose = AuthPurpose(_enum_value(row.get("purpose")))
    except (TypeError, ValueError) as error:
        raise IamError("AUTH_TRANSACTION_INVALID") from error
    deadline = row.get("deadline")
    if (
        status != AuthTransactionStatus.PENDING
        or row.get("aggregate_version") != 1
        or not isinstance(deadline, datetime)
        or deadline.tzinfo is None
        or deadline.utcoffset() != timedelta(0)
        or now >= deadline
        or row.get("provider_issuer") != policy.provider_issuer
        or row.get("provider_audience") != policy.provider_audience
        or row.get("redirect_uri") != policy.redirect_uri
        or row.get("security_policy_version") != policy.policy_version
        or row.get("return_to") not in policy.allowed_return_to
        or row.get("pkce_code_challenge_method") != "S256"
    ):
        raise IamError("AUTH_TRANSACTION_INVALID")
    expected_browser = _digest_text(
        keyring,
        row.get("browser_binding_digest_key_id"),
        raw_browser_cookie,
    )
    if not _safe_equal(expected_browser, row.get("browser_binding_digest")):
        raise IamError("AUTH_TRANSACTION_INVALID")
    _validate_transaction_shape(row, purpose)


def _validate_state_binding(
    *,
    row: Mapping[str, Any],
    raw_state: str,
    keyring,
) -> None:
    expected = _digest_text(
        keyring,
        row.get("state_digest_key_id"),
        raw_state,
    )
    if not _safe_equal(expected, row.get("state_digest")):
        raise IamError("AUTH_TRANSACTION_INVALID")


def _validate_transaction_shape(
    row: Mapping[str, Any],
    purpose: AuthPurpose,
) -> None:
    initiating_session = row.get("initiating_session_id")
    initiating_user = row.get("initiating_user_id")
    expected_user = row.get("expected_user_id")
    invitation = row.get("invitation_id")
    invitation_version = row.get("invitation_version")
    contact = row.get("expected_contact_point_id")
    contact_type = row.get("expected_contact_type")
    contact_digest = row.get("expected_contact_binding_digest")
    contact_key_id = row.get("expected_contact_binding_digest_key_id")
    if purpose == AuthPurpose.LOGIN:
        if any(
            value is not None
            for value in (
                invitation,
                invitation_version,
                contact,
                contact_type,
                contact_digest,
                contact_key_id,
            )
        ):
            raise IamError("AUTH_TRANSACTION_INVALID")
        if (initiating_session is None) != (initiating_user is None):
            raise IamError("AUTH_TRANSACTION_INVALID")
        if expected_user is not None:
            raise IamError("AUTH_TRANSACTION_INVALID")
    elif purpose == AuthPurpose.ENROLLMENT:
        if (
            not invitation
            or not isinstance(invitation_version, int)
            or not contact
            or not contact_type
            or not contact_digest
            or not contact_key_id
            or any(
                value is not None
                for value in (initiating_session, initiating_user, expected_user)
            )
        ):
            raise IamError("AUTH_TRANSACTION_INVALID")
    elif purpose == AuthPurpose.STEP_UP:
        if (
            not all(
                isinstance(value, str) and value
                for value in (
                    initiating_session,
                    initiating_user,
                    expected_user,
                    invitation,
                    contact,
                    contact_type,
                    contact_digest,
                    contact_key_id,
                )
            )
            or not isinstance(invitation_version, int)
        ):
            raise IamError("AUTH_TRANSACTION_INVALID")
        if expected_user != initiating_user:
            raise IamError("AUTHENTICATION_REJECTED")


def _validate_transaction_invitation(
    snapshot: Mapping[str, Mapping[Any, Any]],
    transaction: Mapping[str, Any],
    now: datetime,
) -> tuple[Any, Optional[Mapping[str, Any]]]:
    try:
        purpose = AuthPurpose(_enum_value(transaction.get("purpose")))
    except (TypeError, ValueError) as error:
        raise IamError("AUTH_TRANSACTION_INVALID") from error
    _validate_transaction_shape(transaction, purpose)
    if purpose == AuthPurpose.LOGIN:
        return None, None
    invitation_id = transaction.get("invitation_id")
    invitation = snapshot.get("invitations", {}).get(invitation_id)
    contact_id = transaction.get("expected_contact_point_id")
    contact = snapshot.get("contact_points", {}).get(contact_id)
    expires_at = _fact(invitation, "expires_at")
    if (
        invitation is None
        or _enum_value(_fact(invitation, "status")) != InvitationStatus.ISSUED.value
        or _fact(invitation, "aggregate_version")
        != transaction.get("invitation_version")
        or _fact(invitation, "recipient_contact_id") != contact_id
        or not isinstance(expires_at, datetime)
        or expires_at.tzinfo is None
        or expires_at.utcoffset() != timedelta(0)
        or now >= expires_at
        or not isinstance(contact, Mapping)
        or contact.get("contact_point_id") != contact_id
        or contact.get("type") != transaction.get("expected_contact_type")
        or not _safe_equal(
            contact.get("binding_digest"),
            transaction.get("expected_contact_binding_digest"),
        )
        or contact.get("binding_digest_key_id")
        != transaction.get("expected_contact_binding_digest_key_id")
    ):
        raise IamError("ACCESS_INVITATION_UNAVAILABLE")
    return invitation, contact


def _auth_transaction_from_row(row: Mapping[str, Any]) -> AuthTransaction:
    if not isinstance(row, Mapping):
        raise IamError("AUTH_TRANSACTION_INVALID")
    values = {item.name: row.get(item.name) for item in fields(AuthTransaction)}
    try:
        values["status"] = AuthTransactionStatus(_enum_value(values["status"]))
        values["purpose"] = AuthPurpose(_enum_value(values["purpose"]))
        if values["provider_error_class"] is not None:
            values["provider_error_class"] = ProviderErrorClass(
                _enum_value(values["provider_error_class"])
            )
        return AuthTransaction(**values)
    except (TypeError, ValueError) as error:
        raise IamError("AUTH_TRANSACTION_INVALID") from error


def _auth_transaction_to_row(value: AuthTransaction) -> dict[str, Any]:
    row = {item.name: getattr(value, item.name) for item in fields(value)}
    row["status"] = value.status.value
    row["purpose"] = value.purpose.value
    row["provider_error_class"] = (
        value.provider_error_class.value
        if value.provider_error_class is not None
        else None
    )
    return row


def _lock_claim_owner(uow, claimed: Mapping[str, Any]) -> Mapping[str, Any]:
    locked = uow.lock(
        "auth_transactions",
        claimed["auth_transaction_id"],
    )
    if (
        not isinstance(locked, Mapping)
        or _enum_value(locked.get("status"))
        != AuthTransactionStatus.EXCHANGING.value
        or locked.get("aggregate_version") != 2
        or locked.get("exchange_owner_id") != claimed.get("exchange_owner_id")
        or locked.get("attempt") != claimed.get("attempt")
        or dict(locked) != dict(claimed)
    ):
        raise IamError("AUTH_TRANSACTION_INVALID")
    return locked


def _validate_authenticated_subject(
    *,
    subject,
    transaction: Mapping[str, Any],
    now: datetime,
) -> None:
    values = (
        subject.auth_time,
        subject.token_issued_at,
        subject.token_expires_at,
    )
    if any(
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() != timedelta(0)
        for value in values
    ):
        raise IamError("SERVICE_UNAVAILABLE")
    if (
        subject.issuer != transaction.get("provider_issuer")
        or not isinstance(subject.subject_digest, str)
        or not subject.subject_digest
        or not isinstance(subject.subject_digest_key_id, str)
        or not subject.subject_digest_key_id
        or subject.auth_time > now
        or subject.token_issued_at > now
        or now >= subject.token_expires_at
        or not isinstance(subject.acr_code, str)
        or not subject.acr_code
        or not subject.amr_codes
    ):
        raise IamError("AUTHENTICATION_REJECTED")


def _prepare_session_material(
    *,
    transaction: Mapping[str, Any],
    subject,
    snapshot: Mapping[str, Mapping[Any, Any]],
    id_source,
    secret_source,
    session_keyring,
) -> dict[str, Any]:
    identity_key = (subject.issuer, subject.subject_digest)
    existing_identity = snapshot.get("external_identities", {}).get(identity_key)
    purpose = AuthPurpose(_enum_value(transaction["purpose"]))
    new_user_id = None
    external_identity_id = None
    if existing_identity is None and purpose == AuthPurpose.ENROLLMENT:
        new_user_id = id_source.new_id("user")
        external_identity_id = id_source.new_id("external_identity")
    initiating_session_id = transaction.get("initiating_session_id")
    if initiating_session_id is None:
        session_family_id = id_source.new_id("session_family")
        session_id = id_source.new_id("session")
        generation = 1
    else:
        initiating_session = snapshot.get("sessions", {}).get(
            initiating_session_id
        )
        if not isinstance(initiating_session, Mapping):
            raise IamError("AUTHENTICATION_REJECTED")
        session_family_id = initiating_session.get("session_family_id")
        generation = initiating_session.get("generation", 0) + 1
        session_id = id_source.new_id("successor_session")
    raw_session_handle = _new_secret(
        secret_source,
        "bff-session-handle",
        32,
    )
    csrf_salt = _new_secret_bytes(secret_source, "bff-csrf-salt", 32)
    handle_key_id = _key_id(
        session_keyring,
        "session_handle_digest_key_id",
    )
    csrf_key_id = _key_id(session_keyring, "csrf_key_id")
    try:
        require_key_material(
            session_keyring,
            key_ids=(handle_key_id, csrf_key_id),
        )
        handle_digest = session_handle_digest(
            session_keyring,
            raw_session_handle,
        )
        csrf_token = derive_csrf_token(
            session_keyring,
            raw_session_handle=raw_session_handle,
            csrf_salt=csrf_salt,
            session_id=session_id,
            generation=generation,
            key_id=csrf_key_id,
        )
        persisted_csrf_digest = csrf_digest(
            session_keyring,
            csrf_token=csrf_token,
            key_id=csrf_key_id,
        )
    except (KeyUnavailableError, ValueError, TypeError) as error:
        raise IamError("SERVICE_UNAVAILABLE") from error
    return {
        "identity_key": identity_key,
        "new_user_id": new_user_id,
        "external_identity_id": external_identity_id,
        "new_session_family_id": session_family_id,
        "generation": generation,
        "session_id": session_id,
        "raw_session_handle": raw_session_handle,
        "handle_digest": handle_digest,
        "handle_digest_key_id": handle_key_id,
        "csrf_salt": csrf_salt,
        "csrf_key_id": csrf_key_id,
        "csrf_token": csrf_token,
        "csrf_digest": persisted_csrf_digest,
    }


def _apply_authenticated_subject(
    *,
    uow,
    transaction: Mapping[str, Any],
    subject,
    material: Mapping[str, Any],
    now: datetime,
    security_policy: OidcSecurityPolicy,
) -> dict[str, Any]:
    purpose = AuthPurpose(_enum_value(transaction["purpose"]))
    deadline = transaction.get("deadline")
    if (
        not isinstance(deadline, datetime)
        or deadline.tzinfo is None
        or deadline.utcoffset() != timedelta(0)
        or now >= deadline
    ):
        raise IamError("AUTH_TRANSACTION_INVALID")
    initiating_session = None
    initiating_family = None
    if transaction.get("initiating_session_id") is not None:
        session_id = transaction["initiating_session_id"]
        session_hint = uow.tables.get("sessions", {}).get(session_id)
        family_id = _fact(session_hint, "session_family_id")
        initiating_family = uow.lock("session_families", family_id)
        initiating_session = uow.lock("sessions", session_id)

    invitation = None
    contact = None
    if purpose != AuthPurpose.LOGIN:
        invitation = uow.lock("invitations", transaction["invitation_id"])
        contact = uow.lock(
            "contact_points",
            transaction["expected_contact_point_id"],
        )
    _validate_transaction_invitation(uow.tables, transaction, now)

    identity_key = material["identity_key"]
    identity = uow.lock("external_identities", identity_key)
    if identity is not None:
        if (
            identity.get("issuer") != subject.issuer
            or not _safe_equal(
                identity.get("subject_digest"),
                subject.subject_digest,
            )
            or identity.get("subject_digest_key_id")
            != subject.subject_digest_key_id
            or _enum_value(identity.get("status")) != "ACTIVE"
        ):
            raise IamError("AUTHENTICATION_REJECTED")
        user_id = identity.get("user_id")
        new_identity = False
    else:
        if purpose != AuthPurpose.ENROLLMENT:
            raise IamError("AUTHENTICATION_REJECTED")
        user_id = material.get("new_user_id")
        if not user_id or not material.get("external_identity_id"):
            raise IamError("SERVICE_UNAVAILABLE")
        new_identity = True

    user = uow.lock("users", user_id)
    if user is None:
        if not new_identity or purpose != AuthPurpose.ENROLLMENT:
            raise IamError("AUTHENTICATION_REJECTED")
        user = {
            "user_id": user_id,
            "status": "PENDING_ENROLLMENT",
            "stable_handle": "pending:" + user_id,
            "aggregate_version": 1,
            "created_at": now,
            "updated_at": now,
        }
    status = _enum_value(user.get("status"))
    if status not in ("ACTIVE", "PENDING_ENROLLMENT"):
        raise IamError("AUTHENTICATION_REJECTED")

    if purpose == AuthPurpose.STEP_UP:
        if (
            status != "ACTIVE"
            or user_id != transaction.get("expected_user_id")
        ):
            raise IamError("AUTHENTICATION_REJECTED")
    if transaction.get("initiating_user_id") is not None and (
        user_id != transaction.get("initiating_user_id")
    ):
        raise IamError("AUTHENTICATION_REJECTED")

    if purpose != AuthPurpose.LOGIN:
        binding = subject.verified_recipient_binding
        if (
            invitation is None
            or contact is None
            or _fact(invitation, "recipient_contact_id")
            != transaction.get("expected_contact_point_id")
            or contact.get("contact_point_id")
            != transaction.get("expected_contact_point_id")
            or contact.get("type") != binding.contact_type
            or not _safe_equal(
                contact.get("binding_digest"),
                binding.binding_digest,
            )
            or contact.get("binding_digest_key_id") != binding.digest_key_id
            or contact.get("user_id") not in (None, user_id)
        ):
            raise IamError("ACCESS_INVITATION_UNAVAILABLE")

    if initiating_session is not None:
        current = _validate_current_rows(
            session=initiating_session,
            family=initiating_family,
            user=user,
            now=now,
        )
        if current is None:
            raise IamError("AUTHENTICATION_REJECTED")

    if user_id not in uow.tables.get("users", {}):
        uow.put(
            "users",
            user_id,
            user,
            checkpoint="auth.callback.user",
        )
    if new_identity:
        uow.put(
            "external_identities",
            identity_key,
            {
                "external_identity_id": material["external_identity_id"],
                "user_id": user_id,
                "issuer": subject.issuer,
                "subject_digest": subject.subject_digest,
                "subject_digest_key_id": subject.subject_digest_key_id,
                "status": "ACTIVE",
                "verified_at": now,
            },
            checkpoint="auth.callback.external-identity",
        )
    if purpose != AuthPurpose.LOGIN:
        updated_contact = deepcopy(dict(contact))
        updated_contact.update(
            {
                "user_id": user_id,
                "status": "VERIFIED",
                "verified_at": now,
                "aggregate_version": contact.get("aggregate_version", 0) + 1,
            }
        )
        uow.put(
            "contact_points",
            updated_contact["contact_point_id"],
            updated_contact,
            checkpoint="auth.callback.contact",
        )

    if initiating_session is None:
        family_id = material["new_session_family_id"]
        generation = 1
        predecessor_id = None
        family = {
            "session_family_id": family_id,
            "user_id": user_id,
            "status": "ACTIVE",
            "current_generation": generation,
            "aggregate_version": 1,
            "revoked_at": None,
            "revocation_reason_code": None,
        }
        if uow.lock("session_families", family_id) is not None:
            raise IamError("SERVICE_UNAVAILABLE")
        uow.put(
            "session_families",
            family_id,
            family,
            checkpoint="auth.callback.session-family",
        )
    else:
        family_id = initiating_family["session_family_id"]
        generation = initiating_session["generation"] + 1
        predecessor_id = initiating_session["session_id"]
        family = deepcopy(dict(initiating_family))
        family["current_generation"] = generation
        family["aggregate_version"] = family.get("aggregate_version", 0) + 1
        predecessor = deepcopy(dict(initiating_session))
        predecessor["status"] = "REVOKED"
        predecessor["updated_at"] = now
        predecessor["aggregate_version"] = (
            predecessor.get("aggregate_version", 0) + 1
        )
        uow.put(
            "sessions",
            predecessor_id,
            predecessor,
            checkpoint="auth.callback.predecessor",
        )
        uow.put(
            "session_families",
            family_id,
            family,
            checkpoint="auth.callback.session-family-rotate",
        )

    session_id = material["session_id"]
    if uow.lock("sessions", session_id) is not None:
        raise IamError("SERVICE_UNAVAILABLE")
    invitation_id = (
        transaction.get("invitation_id")
        if purpose != AuthPurpose.LOGIN
        else None
    )
    contact_id = (
        transaction.get("expected_contact_point_id")
        if purpose != AuthPurpose.LOGIN
        else None
    )
    session = {
        "session_id": session_id,
        "session_family_id": family_id,
        "user_id": user_id,
        "generation": generation,
        "predecessor_session_id": predecessor_id,
        "status": "ACTIVE",
        "verified_contact_point_id": contact_id,
        "verified_for_invitation_id": invitation_id,
        "verified_at": now if invitation_id is not None else None,
        "auth_transaction_id": transaction["auth_transaction_id"],
        "auth_time": subject.auth_time,
        "acr_code": subject.acr_code,
        "amr_codes": tuple(subject.amr_codes),
        "created_at": now,
        "last_activity_at": now,
        "idle_expires_at": now + security_policy.session_idle_ttl,
        "absolute_expires_at": now + security_policy.session_absolute_ttl,
        "updated_at": now,
        "handle_digest": material["handle_digest"],
        "handle_digest_key_id": material["handle_digest_key_id"],
        "csrf_salt": material["csrf_salt"],
        "csrf_key_id": material["csrf_key_id"],
        "csrf_digest": material["csrf_digest"],
        "rotation_reason": "OIDC_" + purpose.value,
        "aggregate_version": 1,
    }
    uow.put(
        "sessions",
        session_id,
        session,
        checkpoint="auth.callback.session",
    )
    return {
        "session_id": session_id,
        "user_id": user_id,
        "user_status": status,
    }


def _put_callback_audit(
    uow,
    *,
    audit_id: str,
    transaction: Mapping[str, Any],
    outcome: str,
    context: OidcBrowserContext,
    now: datetime,
) -> None:
    uow.put(
        "security_audit_events",
        audit_id,
        {
            "security_audit_event_id": audit_id,
            "action": "CompleteOidcAuthentication",
            "auth_transaction_id": transaction["auth_transaction_id"],
            "purpose": _enum_value(transaction["purpose"]),
            "outcome": outcome,
            "occurred_at": now,
            "correlation_id": context.correlation_id,
            "causation_id": context.causation_id,
            "trace_id": context.trace_id,
        },
        checkpoint="auth.callback.audit",
    )
