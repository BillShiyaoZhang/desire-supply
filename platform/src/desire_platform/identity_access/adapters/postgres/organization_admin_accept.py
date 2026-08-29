"""Presenter-ready Organization Invitation acceptance over the fixed PG UoW."""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import hashlib
import hmac
import json
import unicodedata
from typing import Any, Mapping, Optional, Protocol, Tuple
from uuid import UUID

from psycopg.pq import TransactionStatus

from ...application.access_invitations import (
    AcceptAccessInvitationCommand,
    AcceptAccessInvitationResult,
    ActorContext,
    SessionRotation,
)
from ...domain.errors import IamError
from ...ports.safety_hold import (
    HoldDecision,
    SafetyHoldDecisionResult,
    SafetyHoldUnavailableError,
)
from ...security.cryptography import (
    KeyUnavailableError,
    RECEIPT_CANONICALIZATION_VERSION,
    canonical_accept_payload_bytes,
    canonical_json_bytes,
    csrf_digest,
    derive_csrf_token,
    require_key_material,
    session_handle_digest,
)
from .accept_access_invitation import (
    AcceptAccessInvitationDatabaseRequest,
    AcceptCommandOutcomeUnknownError,
    AcceptConsentOfferChoice,
    AcceptExecutionScope,
    AcceptGeneratedIds,
    AcceptHoldEvidence,
    AcceptPolicyAcceptanceChoice,
    AcceptPostgresConfigurationError,
    AcceptReceiptIdentity,
    AcceptSessionSuccessorFacts,
    PsycopgAcceptAccessInvitationUnitOfWorkFactory,
    _acceptance_response_has_exact_authority,
)
from .organization_admin_handlers import OrganizationAdminKeys


_RETAIN_FOR = timedelta(days=31)
_HOLD_TTL = timedelta(minutes=2)
_HOLD_POLICY_VERSION = "internal-sandbox-iam-invitation-hold-v1"
_IDEMPOTENCY_KEY_MINIMUM = 16


class OrganizationAcceptClock(Protocol):
    def now(self) -> datetime: ...


class OrganizationAcceptIdSource(Protocol):
    def new_id(self, purpose: str) -> UUID: ...


@dataclass(frozen=True)
class OrganizationAcceptResolvedScope:
    actor_user_id: UUID
    session_id: UUID
    session_family_id: UUID
    auth_transaction_id: UUID
    invitation_id: UUID
    organization_id: UUID
    policy_selector_digest: bytes = field(repr=False)
    policy_bundle_id: UUID
    current_generation: int
    user_status: str
    target_role: str
    invitation_status: str
    missing_policy_document_ids: Tuple[UUID, ...]
    missing_consent_offer_ids: Tuple[UUID, ...]

    def __post_init__(self) -> None:
        for value in (
            self.actor_user_id,
            self.session_id,
            self.session_family_id,
            self.auth_transaction_id,
            self.invitation_id,
            self.organization_id,
            self.policy_bundle_id,
        ):
            if not isinstance(value, UUID) or value.int == 0:
                raise ValueError("Accept scope contains an invalid UUID")
        if (
            not isinstance(self.policy_selector_digest, bytes)
            or len(self.policy_selector_digest) != 32
            or not isinstance(self.current_generation, int)
            or isinstance(self.current_generation, bool)
            or self.current_generation < 1
            or self.user_status not in {"PENDING_ENROLLMENT", "ACTIVE"}
            or self.target_role not in {"ORG_ADMIN", "DEMAND_OWNER"}
            or self.invitation_status not in {"ISSUED", "ACCEPTED"}
            or len(set(self.missing_policy_document_ids))
            != len(self.missing_policy_document_ids)
            or len(set(self.missing_consent_offer_ids))
            != len(self.missing_consent_offer_ids)
        ):
            raise ValueError("Accept scope facts are invalid")


class PsycopgOrganizationAcceptScopeResolver:
    """Resolve only the fixed invitation/session/policy coordinates for Accept."""

    def __init__(self, *, connections: Any) -> None:
        self.connections = connections

    def resolve(
        self,
        *,
        actor_user_id: UUID,
        session_id: UUID,
        invitation_id: UUID,
        policy_bundle_id: UUID,
        policy_acceptances: Tuple[AcceptPolicyAcceptanceChoice, ...],
        consent_choices: Tuple[AcceptConsentOfferChoice, ...],
    ) -> OrganizationAcceptResolvedScope:
        for value in (actor_user_id, session_id, invitation_id, policy_bundle_id):
            if not isinstance(value, UUID) or value.int == 0:
                raise IamError("INVALID_REQUEST")
        selection = json.dumps(
            {
                "policy_acceptances": [
                    {
                        "document_id": str(choice.document_id),
                        "content_sha256": choice.content_sha256.hex(),
                    }
                    for choice in policy_acceptances
                ],
                "consent_choices": [
                    {
                        "consent_offer_id": str(choice.consent_offer_id),
                        "document_id": str(choice.document_id),
                        "content_sha256": choice.content_sha256.hex(),
                    }
                    for choice in consent_choices
                ],
            },
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        connection = self.connections.checkout()
        begun = False
        disposed = False
        try:
            identity = connection.execute(
                "SELECT current_user,session_user,"
                "current_setting('server_version_num')::integer"
            ).fetchone()
            if (
                getattr(connection, "autocommit", None) is not True
                or connection.info.transaction_status != TransactionStatus.IDLE
                or identity is None
                or identity[:2] != ("iam_onboarding", "iam_onboarding")
                or identity[2] // 10_000 != 18
            ):
                raise AcceptPostgresConfigurationError(
                    "Accept scope resolver identity is invalid"
                )
            connection.execute("BEGIN ISOLATION LEVEL READ COMMITTED READ ONLY")
            begun = True
            connection.execute("SET LOCAL TIME ZONE 'UTC'")
            connection.execute("SET LOCAL lock_timeout = '2000ms'")
            connection.execute("SET LOCAL statement_timeout = '10000ms'")
            rows = connection.execute(
                "SELECT iam_api.resolve_accept_access_invitation_scope_v2("
                "%s,%s,%s,%s,%s::jsonb)",
                (
                    actor_user_id,
                    session_id,
                    invitation_id,
                    policy_bundle_id,
                    selection,
                ),
            ).fetchall()
            if len(rows) != 1 or len(rows[0]) != 1 or not isinstance(rows[0][0], Mapping):
                raise IamError("ACCESS_INVITATION_UNAVAILABLE")
            scope = _resolved_scope(rows[0][0])
            connection.execute("COMMIT")
            begun = False
        except (IamError, AcceptPostgresConfigurationError):
            if begun:
                try:
                    connection.execute("ROLLBACK")
                except BaseException:
                    self.connections.discard(connection)
                    disposed = True
            if not disposed:
                disposed = _clean_release(self.connections, connection)
            raise
        except BaseException:
            if begun:
                try:
                    connection.execute("ROLLBACK")
                except BaseException:
                    self.connections.discard(connection)
                    disposed = True
            if not disposed:
                disposed = _clean_release(self.connections, connection)
            raise IamError("SERVICE_UNAVAILABLE") from None
        else:
            disposed = _clean_release(self.connections, connection)
            return scope
        finally:
            if not disposed:
                self.connections.discard(connection)

    def resolve_receipt_replay(
        self,
        *,
        actor_user_id: UUID,
        session_id: UUID,
        invitation_id: UUID,
        expected_version: int,
        idempotency_candidates: Tuple[Tuple[str, bytes], ...],
        payload_hash_candidates: Tuple[Tuple[str, bytes], ...],
    ) -> Optional[Mapping[str, Any]]:
        """Return a retained completed receipt before any SafetyHold call.

        This is one purpose-fixed query under the existing ``iam_onboarding``
        receipt policy.  ``None`` means a true receipt miss; every ambiguous,
        conflicting, in-progress or expired row fails closed.
        """

        if (
            not isinstance(actor_user_id, UUID)
            or actor_user_id.int == 0
            or not isinstance(session_id, UUID)
            or session_id.int == 0
            or not isinstance(invitation_id, UUID)
            or invitation_id.int == 0
            or not isinstance(expected_version, int)
            or isinstance(expected_version, bool)
            or expected_version < 1
            or not 1 <= len(idempotency_candidates) <= 4
            or not 1 <= len(payload_hash_candidates) <= 4
            or len({key_id for key_id, _digest in idempotency_candidates})
            != len(idempotency_candidates)
            or len({key_id for key_id, _digest in payload_hash_candidates})
            != len(payload_hash_candidates)
            or any(
                not isinstance(key_id, str)
                or not key_id
                or not isinstance(digest, bytes)
                or len(digest) != 32
                for key_id, digest in (
                    idempotency_candidates + payload_hash_candidates
                )
            )
        ):
            raise IamError("SERVICE_UNAVAILABLE")
        connection = self.connections.checkout()
        begun = False
        disposed = False
        try:
            identity = connection.execute(
                "SELECT current_user,session_user,"
                "current_setting('server_version_num')::integer"
            ).fetchone()
            if (
                getattr(connection, "autocommit", None) is not True
                or connection.info.transaction_status != TransactionStatus.IDLE
                or identity is None
                or identity[:2] != ("iam_onboarding", "iam_onboarding")
                or identity[2] // 10_000 != 18
            ):
                raise AcceptPostgresConfigurationError(
                    "Accept receipt resolver identity is invalid"
                )
            connection.execute("BEGIN ISOLATION LEVEL READ COMMITTED READ ONLY")
            begun = True
            connection.execute("SET LOCAL TIME ZONE 'UTC'")
            connection.execute("SET LOCAL statement_timeout = '10000ms'")
            context = (
                ("app.scope_kind", "AUTH_PROTOCOL"),
                ("app.operation", "ACCEPT"),
                ("app.actor_user_id", str(actor_user_id)),
                ("app.target_user_id", str(actor_user_id)),
                ("app.session_id", str(session_id)),
                ("app.target_invitation_id", str(invitation_id)),
                ("app.command_name", "AcceptAccessInvitation"),
                ("app.command_version", "1"),
            )
            for name, value in context:
                configured = connection.execute(
                    "SELECT pg_catalog.set_config(%s,%s,true)", (name, value)
                ).fetchone()
                if configured != (value,):
                    raise AcceptPostgresConfigurationError(
                        "Accept receipt context was rejected"
                    )
            principal_rows = connection.execute(
                "SELECT iam_api.resolve_accept_receipt_principal_v1(%s,%s)",
                (actor_user_id, session_id),
            ).fetchall()
            if (
                len(principal_rows) != 1
                or len(principal_rows[0]) != 1
                or not isinstance(principal_rows[0][0], Mapping)
            ):
                raise IamError("SERVICE_UNAVAILABLE")
            principal = principal_rows[0][0]
            if principal.get("decision_code") == "AUTHENTICATION_REQUIRED":
                raise IamError("AUTHENTICATION_REQUIRED")
            if set(principal) != {
                "decision_code",
                "actor_user_id",
                "session_id",
                "session_family_id",
            } or principal.get("decision_code") != "AUTHORIZED":
                raise IamError("SERVICE_UNAVAILABLE")
            try:
                resolved_actor_id = _uuid(principal["actor_user_id"])
                resolved_session_id = _uuid(principal["session_id"])
                family_id = _uuid(principal["session_family_id"])
            except (KeyError, TypeError, ValueError):
                raise IamError("SERVICE_UNAVAILABLE") from None
            if (
                resolved_actor_id != actor_user_id
                or resolved_session_id != session_id
            ):
                raise IamError("SERVICE_UNAVAILABLE")
            configured = connection.execute(
                "SELECT pg_catalog.set_config(%s,%s,true)",
                ("app.session_family_id", str(family_id)),
            ).fetchone()
            if configured != (str(family_id),):
                raise AcceptPostgresConfigurationError(
                    "Accept receipt family context was rejected"
                )
            key_policy = connection.execute(
                "SELECT active_idempotency_key_id,active_payload_hash_key_id,"
                "active_canonicalization_version,retained_idempotency_key_ids,"
                "retained_payload_hash_key_ids "
                "FROM infra.iam_receipt_key_policy WHERE singleton_key"
            ).fetchone()
            runtime_idempotency_ids = tuple(
                key_id for key_id, _digest in idempotency_candidates
            )
            runtime_payload_ids = tuple(
                key_id for key_id, _digest in payload_hash_candidates
            )
            if (
                key_policy is None
                or len(key_policy) != 5
                or key_policy[2] != RECEIPT_CANONICALIZATION_VERSION
                or not isinstance(key_policy[3], (list, tuple))
                or not isinstance(key_policy[4], (list, tuple))
                or sorted(runtime_idempotency_ids)
                != sorted(tuple(key_policy[3]))
                or sorted(runtime_payload_ids)
                != sorted(tuple(key_policy[4]))
            ):
                raise IamError("SERVICE_UNAVAILABLE")
            now = connection.execute("SELECT transaction_timestamp()").fetchone()[0]

            rows = []
            for key_id, digest in idempotency_candidates:
                for name, value in (
                    ("app.idempotency_key_digest_key_id", key_id),
                    ("app.idempotency_key_digest", digest.hex()),
                ):
                    configured = connection.execute(
                        "SELECT pg_catalog.set_config(%s,%s,true)", (name, value)
                    ).fetchone()
                    if configured != (value,):
                        raise AcceptPostgresConfigurationError(
                            "Accept receipt candidate context was rejected"
                        )
                rows.extend(
                    connection.execute(
                        "SELECT target_kind,target_id,http_method,canonical_path,"
                        "if_match_version,payload_hash,payload_hash_key_id,"
                        "canonicalization_version,status,response_schema_version,"
                        "response_schema_name,response_http_status,"
                        "response_entity_tag,current_user_entity_tag,"
                        "safe_response_body,reconstruction_metadata,retain_until "
                        "FROM infra.command_receipts WHERE principal_kind='USER' "
                        "AND principal_id=%s AND command_name='AcceptAccessInvitation' "
                        "AND command_version=1 AND idempotency_key_digest_key_id=%s "
                        "AND idempotency_key_digest=%s ORDER BY id",
                        (actor_user_id, key_id, digest),
                    ).fetchall()
                )
            if not rows:
                if (
                    runtime_idempotency_ids[0] != key_policy[0]
                    or runtime_payload_ids[0] != key_policy[1]
                ):
                    raise IamError("SERVICE_UNAVAILABLE")
                replay = None
            elif len(rows) != 1:
                raise IamError("SERVICE_UNAVAILABLE")
            else:
                row = rows[0]
                payload_matches = any(
                    row[6] == key_id and bytes(row[5]) == digest
                    for key_id, digest in payload_hash_candidates
                )
                if not payload_matches:
                    raise IamError("IDEMPOTENCY_KEY_REUSED")
                if row[8] == "IN_PROGRESS":
                    raise IamError("COMMAND_IN_PROGRESS")
                if (
                    row[0] != "AccessInvitation"
                    or row[1] != invitation_id
                    or row[2] != "POST"
                    or row[3] != "/v1/access-invitations/%s/accept" % invitation_id
                    or row[4] != expected_version
                    or row[7] != RECEIPT_CANONICALIZATION_VERSION
                    or row[8] != "COMPLETED"
                    or row[9] != 1
                    or row[10] is not None
                    or row[11] is not None
                    or row[12] is not None
                    or row[13] is not None
                    or not isinstance(row[14], Mapping)
                    or row[15] is not None
                    or row[16] <= now
                    or row[14].get("invitation", {}).get("invitation_id")
                    != str(invitation_id)
                ):
                    raise IamError("SERVICE_UNAVAILABLE")
                replay = dict(row[14])
            connection.execute("COMMIT")
            begun = False
        except (IamError, AcceptPostgresConfigurationError):
            if begun:
                try:
                    connection.execute("ROLLBACK")
                except BaseException:
                    self.connections.discard(connection)
                    disposed = True
            if not disposed:
                disposed = _clean_release(self.connections, connection)
            raise
        except BaseException:
            if begun:
                try:
                    connection.execute("ROLLBACK")
                except BaseException:
                    self.connections.discard(connection)
                    disposed = True
            if not disposed:
                disposed = _clean_release(self.connections, connection)
            raise IamError("SERVICE_UNAVAILABLE") from None
        else:
            disposed = _clean_release(self.connections, connection)
            return replay
        finally:
            if not disposed:
                self.connections.discard(connection)


@dataclass(frozen=True, repr=False)
class OrganizationAcceptKeyring:
    receipt_keys: OrganizationAdminKeys = field(repr=False)
    session_keyring: Any = field(repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.receipt_keys, OrganizationAdminKeys) or not callable(
            getattr(self.session_keyring, "keyed_digest_hex", None)
        ):
            raise TypeError("Accept keyring is unavailable")
        object.__setattr__(
            self,
            "idempotency_key_digest_key_id",
            self.receipt_keys.idempotency_key_id,
        )
        object.__setattr__(self, "payload_hash_key_id", self.receipt_keys.payload_hash_key_id)
        object.__setattr__(
            self,
            "session_handle_digest_key_id",
            self.session_keyring.session_handle_digest_key_id,
        )
        object.__setattr__(self, "csrf_key_id", self.session_keyring.csrf_key_id)

    def keyed_digest_hex(self, *, key_id: str, canonical_bytes: bytes) -> str:
        if key_id == self.receipt_keys.idempotency_key_id:
            material = self.receipt_keys.idempotency_key
        elif key_id == self.receipt_keys.payload_hash_key_id:
            material = self.receipt_keys.payload_hash_key
        else:
            return self.session_keyring.keyed_digest_hex(
                key_id=key_id,
                canonical_bytes=canonical_bytes,
            )
        if not isinstance(canonical_bytes, bytes) or not canonical_bytes:
            raise KeyUnavailableError("Accept HMAC input is unavailable")
        return hmac.new(material, canonical_bytes, hashlib.sha256).hexdigest()

    def receipt_candidates(
        self, *, raw_idempotency_key: str, command: AcceptAccessInvitationCommand
    ) -> tuple[Tuple[Tuple[str, bytes], ...], Tuple[Tuple[str, bytes], ...]]:
        identity_input = canonical_json_bytes(
            {
                "idempotency_key": unicodedata.normalize(
                    "NFC", raw_idempotency_key
                )
            }
        )
        payload_input = canonical_accept_payload_bytes(command)
        identities = tuple(
            (key_id, hmac.new(material, identity_input, hashlib.sha256).digest())
            for key_id, material in self.receipt_keys.idempotency_keyring
        )
        payloads = tuple(
            (key_id, hmac.new(material, payload_input, hashlib.sha256).digest())
            for key_id, material in self.receipt_keys.payload_hash_keyring
        )
        return identities, payloads


class InternalSandboxInvitationSafetyHold:
    """Closed synthetic-only hold evidence source; never valid outside the sandbox."""

    policy_version = _HOLD_POLICY_VERSION

    def __init__(self, *, deployment_mode: str, clock: OrganizationAcceptClock) -> None:
        if deployment_mode != "INTERNAL_SANDBOX" or not callable(
            getattr(clock, "now", None)
        ):
            raise ValueError("Invitation hold provider is restricted to INTERNAL_SANDBOX")
        self._clock = clock
        self._closed = False

    def evaluate(self, **query: Any) -> SafetyHoldDecisionResult:
        if self._closed:
            raise IamError("SAFETY_DECISION_UNAVAILABLE")
        if (
            query.get("action") != "AcceptAccessInvitation"
            or query.get("target_type") != "AccessInvitation"
            or query.get("policy_version") != self.policy_version
            or not isinstance(query.get("target_version"), int)
            or query["target_version"] < 1
            or query.get("organization_id") is None
        ):
            raise IamError("SAFETY_DECISION_UNAVAILABLE")
        try:
            UUID(str(query["actor_id"]))
            UUID(str(query["target_id"]))
            UUID(str(query["organization_id"]))
        except (KeyError, TypeError, ValueError):
            raise IamError("SAFETY_DECISION_UNAVAILABLE") from None
        now = _utc(self._clock.now())
        return SafetyHoldDecisionResult(
            decision=HoldDecision.ALLOW,
            action="AcceptAccessInvitation",
            target_type="AccessInvitation",
            target_id=str(query["target_id"]),
            target_version=query["target_version"],
            organization_id=str(query["organization_id"]),
            policy_version=self.policy_version,
            evaluated_at=now,
            valid_until=now + _HOLD_TTL,
        )

    def check_readiness(self, *, timeout_ms: int) -> None:
        if self._closed or not isinstance(timeout_ms, int) or timeout_ms < 1:
            raise RuntimeError("Invitation hold provider is unavailable")

    def close(self) -> None:
        self._closed = True


class PostgresAcceptOrganizationAccessInvitationHandler:
    """Build exact PG Accept facts and rotate STEP_UP or ENROLLMENT once."""

    def __init__(
        self,
        *,
        scope_resolver: PsycopgOrganizationAcceptScopeResolver,
        uow_factory: PsycopgAcceptAccessInvitationUnitOfWorkFactory,
        safety_hold: InternalSandboxInvitationSafetyHold,
        keyring: OrganizationAcceptKeyring,
        clock: OrganizationAcceptClock,
        id_source: OrganizationAcceptIdSource,
        secret_source: Any,
    ) -> None:
        if (
            not isinstance(scope_resolver, PsycopgOrganizationAcceptScopeResolver)
            or not isinstance(uow_factory, PsycopgAcceptAccessInvitationUnitOfWorkFactory)
            or not isinstance(safety_hold, InternalSandboxInvitationSafetyHold)
            or not isinstance(keyring, OrganizationAcceptKeyring)
            or not callable(getattr(clock, "now", None))
            or not callable(getattr(id_source, "new_id", None))
            or not callable(getattr(secret_source, "token_bytes", None))
        ):
            raise TypeError("PostgreSQL invitation acceptance dependencies are incomplete")
        self._scope_resolver = scope_resolver
        self._uow_factory = uow_factory
        self._safety_hold = safety_hold
        self._keyring = keyring
        self._clock = clock
        self._ids = id_source
        self._secrets = secret_source

    def handle(
        self,
        *,
        actor: ActorContext,
        command: AcceptAccessInvitationCommand,
    ) -> AcceptAccessInvitationResult:
        now = _utc(self._clock.now())
        if (
            not isinstance(actor, ActorContext)
            or not isinstance(command, AcceptAccessInvitationCommand)
            or len(command.idempotency_key) < _IDEMPOTENCY_KEY_MINIMUM
            or command.expected_version < 1
            or not command.policy_acceptances
        ):
            raise IamError("INVALID_REQUEST")
        choices = _choices(command)
        actor_id = _uuid(actor.actor_id)
        current_session_id = _uuid(actor.session_id)
        invitation_id = _uuid(command.invitation_id)
        policy_bundle_id = _uuid(command.policy_bundle_id)
        try:
            identity_candidates, payload_candidates = (
                self._keyring.receipt_candidates(
                    raw_idempotency_key=command.idempotency_key,
                    command=command,
                )
            )
        except (KeyUnavailableError, LookupError, TypeError, ValueError):
            raise IamError("SERVICE_UNAVAILABLE") from None
        replay = self._scope_resolver.resolve_receipt_replay(
            actor_user_id=actor_id,
            session_id=current_session_id,
            invitation_id=invitation_id,
            expected_version=command.expected_version,
            idempotency_candidates=identity_candidates,
            payload_hash_candidates=payload_candidates,
        )
        if replay is not None:
            try:
                self._uow_factory.response_validator.validate(
                    replay, "AccessInvitationAcceptanceDto"
                )
            except (AssertionError, TypeError, ValueError):
                raise IamError("SERVICE_UNAVAILABLE") from None
            if not _receipt_response_matches(
                replay,
                actor_user_id=actor_id,
                invitation_id=invitation_id,
                expected_version=command.expected_version,
                policy_bundle_id=policy_bundle_id,
            ):
                raise IamError("SERVICE_UNAVAILABLE")
            return AcceptAccessInvitationResult(
                replayed=True,
                safe_response=dict(replay),
                session_rotation=None,
            )
        scope = self._scope_resolver.resolve(
            actor_user_id=actor_id,
            session_id=current_session_id,
            invitation_id=invitation_id,
            policy_bundle_id=policy_bundle_id,
            policy_acceptances=choices[0],
            consent_choices=choices[1],
        )
        if (
            scope.actor_user_id != actor_id
            or scope.session_id != current_session_id
            or scope.invitation_id != invitation_id
            or scope.policy_bundle_id != policy_bundle_id
        ):
            raise IamError("SERVICE_UNAVAILABLE")
        identity = identity_candidates[0][1]
        payload = payload_candidates[0][1]
        hold_query = {
            "actor_id": str(actor_id),
            "action": "AcceptAccessInvitation",
            "target_type": "AccessInvitation",
            "target_id": str(invitation_id),
            "target_version": command.expected_version,
            "organization_id": str(scope.organization_id),
            "policy_version": self._safety_hold.policy_version,
        }
        try:
            hold = self._safety_hold.evaluate(**hold_query)
        except SafetyHoldUnavailableError as error:
            raise IamError("SAFETY_DECISION_UNAVAILABLE") from error
        decision_now = _utc(self._clock.now())
        valid_hold = (
            isinstance(hold, SafetyHoldDecisionResult)
            and isinstance(hold.decision, HoldDecision)
            and all(
                getattr(hold, key) == hold_query[key]
                for key in (
                    "action",
                    "target_type",
                    "target_id",
                    "target_version",
                    "organization_id",
                    "policy_version",
                )
            )
            and _is_utc_datetime(hold.evaluated_at)
            and _is_utc_datetime(hold.valid_until)
            and hold.evaluated_at <= decision_now < hold.valid_until
        )
        if not valid_hold or hold.decision is HoldDecision.UNAVAILABLE:
            raise IamError("SAFETY_DECISION_UNAVAILABLE")
        if hold.decision is HoldDecision.BLOCK:
            raise IamError("SAFETY_HOLD_BLOCKED")
        if hold.decision is not HoldDecision.ALLOW:
            raise IamError("SAFETY_DECISION_UNAVAILABLE")
        try:
            require_key_material(
                self._keyring,
                key_ids=(
                    self._keyring.session_handle_digest_key_id,
                    self._keyring.csrf_key_id,
                ),
            )
            successor_id = _new(self._ids, "successor_session")
            raw_handle = _secret_text(self._secrets, "bff-session-handle", 32)
            csrf_salt = _secret_bytes(self._secrets, "bff-csrf-salt", 32)
            handle_digest = bytes.fromhex(
                session_handle_digest(self._keyring, raw_handle)
            )
            csrf_token = derive_csrf_token(
                self._keyring,
                raw_session_handle=raw_handle,
                csrf_salt=csrf_salt,
                session_id=str(successor_id),
                generation=scope.current_generation + 1,
                key_id=self._keyring.csrf_key_id,
            )
            persisted_csrf = bytes.fromhex(
                csrf_digest(
                    self._keyring,
                    csrf_token=csrf_token,
                    key_id=self._keyring.csrf_key_id,
                )
            )
        except (KeyUnavailableError, LookupError, TypeError, ValueError):
            raise IamError("SERVICE_UNAVAILABLE") from None
        missing_policy = set(scope.missing_policy_document_ids)
        missing_consent = set(scope.missing_consent_offer_ids)
        if not missing_policy.issubset({choice.document_id for choice in choices[0]}) or not missing_consent.issubset(
            {choice.consent_offer_id for choice in choices[1]}
        ):
            raise IamError("SERVICE_UNAVAILABLE")
        policy_ids = tuple(
            _new(self._ids, "policy_acceptance") for _item in sorted(missing_policy)
        )
        consent_ids = tuple(
            _new(self._ids, "consent_grant") for _item in sorted(missing_consent)
        )
        command_id = _new(self._ids, "command_receipt")
        request = AcceptAccessInvitationDatabaseRequest(
            scope=AcceptExecutionScope(
                actor_user_id=scope.actor_user_id,
                session_id=scope.session_id,
                session_family_id=scope.session_family_id,
                auth_transaction_id=scope.auth_transaction_id,
                invitation_id=scope.invitation_id,
                organization_id=scope.organization_id,
                policy_selector_digest=scope.policy_selector_digest,
                policy_bundle_id=scope.policy_bundle_id,
                target_role=scope.target_role,
                command_id=command_id,
                correlation_id=_uuid(actor.correlation_id),
                trace_id=_uuid(actor.trace_id),
            ),
            receipt=AcceptReceiptIdentity(
                receipt_id=command_id,
                principal_id=scope.actor_user_id,
                idempotency_key_digest=identity,
                idempotency_key_digest_key_id=(
                    self._keyring.idempotency_key_digest_key_id
                ),
                payload_hash=payload,
                payload_hash_key_id=self._keyring.payload_hash_key_id,
                canonicalization_version=RECEIPT_CANONICALIZATION_VERSION,
                retain_until=now + _RETAIN_FOR,
            ),
            hold=AcceptHoldEvidence(
                action=hold.action,
                target_type=hold.target_type,
                target_id=scope.invitation_id,
                target_version=hold.target_version,
                organization_id=scope.organization_id,
                policy_version=hold.policy_version,
                evaluated_at=_utc(hold.evaluated_at),
                valid_until=_utc(hold.valid_until),
            ),
            expected_invitation_version=command.expected_version,
            policy_acceptances=choices[0],
            consent_choices=choices[1],
            successor=AcceptSessionSuccessorFacts(
                session_id=successor_id,
                handle_digest=handle_digest,
                handle_digest_key_id=self._keyring.session_handle_digest_key_id,
                csrf_salt=csrf_salt,
                csrf_key_id=self._keyring.csrf_key_id,
                csrf_digest=persisted_csrf,
            ),
            generated_ids=AcceptGeneratedIds(
                policy_acceptance_ids=policy_ids,
                consent_grant_ids=consent_ids,
                user_role_grant_id=None,
                membership_id=_new(self._ids, "membership"),
                membership_role_grant_id=_new(self._ids, "membership_role_grant"),
                audit_event_id=_new(self._ids, "audit_event"),
                outbox_event_ids=tuple(
                    _new(self._ids, "outbox_event")
                    for _item in range(
                        len(policy_ids)
                        + len(consent_ids)
                        + 4
                    )
                ),
            ),
        )
        try:
            result = self._uow_factory.execute(request)
        except AcceptCommandOutcomeUnknownError:
            raise IamError("COMMAND_OUTCOME_UNKNOWN") from None
        except AcceptPostgresConfigurationError:
            raise IamError("SERVICE_UNAVAILABLE") from None
        try:
            self._uow_factory.response_validator.validate(
                result.safe_response, "AccessInvitationAcceptanceDto"
            )
        except (AssertionError, TypeError, ValueError):
            raise IamError("SERVICE_UNAVAILABLE") from None
        if not _receipt_response_matches(
            result.safe_response,
            actor_user_id=actor_id,
            invitation_id=invitation_id,
            expected_version=command.expected_version,
            policy_bundle_id=policy_bundle_id,
            policy_selector_digest=scope.policy_selector_digest,
            target_role=scope.target_role,
            organization_id=scope.organization_id,
        ):
            raise IamError("SERVICE_UNAVAILABLE")
        if result.replayed:
            if result.successor_session_id is not None:
                raise IamError("SERVICE_UNAVAILABLE")
            rotation = None
        else:
            if result.successor_session_id != successor_id:
                raise IamError("SERVICE_UNAVAILABLE")
            rotation = SessionRotation(
                session_id=str(successor_id),
                raw_session_handle=raw_handle,
                csrf_token=csrf_token,
            )
        return AcceptAccessInvitationResult(
            replayed=result.replayed,
            safe_response=dict(result.safe_response),
            session_rotation=rotation,
        )


def _choices(
    command: AcceptAccessInvitationCommand,
) -> Tuple[Tuple[AcceptPolicyAcceptanceChoice, ...], Tuple[AcceptConsentOfferChoice, ...]]:
    try:
        policy = tuple(
            AcceptPolicyAcceptanceChoice(
                document_id=_uuid(choice.document_id),
                content_sha256=bytes.fromhex(choice.content_sha256),
                affirmed=choice.affirmed,
            )
            for choice in command.policy_acceptances
        )
        consent = tuple(
            AcceptConsentOfferChoice(
                consent_offer_id=_uuid(choice.consent_offer_id),
                document_id=_uuid(choice.document_id),
                content_sha256=bytes.fromhex(choice.content_sha256),
                affirmed=choice.affirmed,
            )
            for choice in command.consent_grants
        )
    except (TypeError, ValueError):
        raise IamError("INVALID_REQUEST") from None
    if (
        len({item.document_id for item in policy}) != len(policy)
        or len({item.consent_offer_id for item in consent}) != len(consent)
    ):
        raise IamError("INVALID_REQUEST")
    return policy, consent


def _resolved_scope(value: Mapping[str, Any]) -> OrganizationAcceptResolvedScope:
    try:
        decision = value.get("decision_code")
        if decision != "AUTHORIZED":
            if decision in {
                "AUTHENTICATION_REQUIRED",
                "ACCESS_INVITATION_UNAVAILABLE",
                "POLICY_BUNDLE_CHANGED",
                "POLICY_CONFIGURATION_UNAVAILABLE",
            }:
                raise IamError(decision)
            raise IamError("SERVICE_UNAVAILABLE")
        return OrganizationAcceptResolvedScope(
            actor_user_id=_uuid(value["actor_user_id"]),
            session_id=_uuid(value["session_id"]),
            session_family_id=_uuid(value["session_family_id"]),
            auth_transaction_id=_uuid(value["auth_transaction_id"]),
            invitation_id=_uuid(value["invitation_id"]),
            organization_id=_uuid(value["organization_id"]),
            policy_selector_digest=bytes.fromhex(value["policy_selector_digest"]),
            policy_bundle_id=_uuid(value["policy_bundle_id"]),
            current_generation=int(value["current_generation"]),
            user_status=str(value["user_status"]),
            target_role=str(value["target_role"]),
            invitation_status=str(value["invitation_status"]),
            missing_policy_document_ids=tuple(
                _uuid(item) for item in value["missing_policy_document_ids"]
            ),
            missing_consent_offer_ids=tuple(
                _uuid(item) for item in value["missing_consent_offer_ids"]
            ),
        )
    except IamError:
        raise
    except (KeyError, TypeError, ValueError):
        raise IamError("SERVICE_UNAVAILABLE") from None


def _receipt_response_matches(
    value: Mapping[str, Any],
    *,
    actor_user_id: UUID,
    invitation_id: UUID,
    expected_version: int,
    policy_bundle_id: UUID,
    policy_selector_digest: Optional[bytes] = None,
    target_role: Optional[str] = None,
    organization_id: Optional[UUID] = None,
) -> bool:
    try:
        invitation = value["invitation"]
        me = value["me"]
        invitation_version = invitation["aggregate_version"]
        user_version = me["aggregate_version"]
        resolved_organization_id = organization_id or UUID(
            invitation["organization_id"]
        )
        resolved_target_role = target_role or invitation["target_role"]
        if policy_selector_digest is None:
            policy_selector_digest = _receipt_policy_selector_digest(
                me,
                target_role=resolved_target_role,
                organization_id=resolved_organization_id,
                policy_bundle_id=policy_bundle_id,
            )
            if policy_selector_digest is None:
                return False
        return (
            isinstance(invitation, Mapping)
            and isinstance(me, Mapping)
            and value["activated_scope"] == "ORGANIZATION_MEMBERSHIP"
            and invitation["invitation_id"] == str(invitation_id)
            and invitation["purpose"] == "ORGANIZATION_MEMBERSHIP"
            and resolved_organization_id.int != 0
            and resolved_target_role in {"ORG_ADMIN", "DEMAND_OWNER"}
            and invitation["status"] == "ACCEPTED"
            and type(invitation_version) is int
            and invitation_version == expected_version + 1
            and invitation["entity_tag"] == f'"v{invitation_version}"'
            and invitation["required_policy_bundle_id"] == str(policy_bundle_id)
            and me["user_id"] == str(actor_user_id)
            and me["status"] == "ACTIVE"
            and type(user_version) is int
            and user_version >= 1
            and me["entity_tag"] == f'"v{user_version}"'
            and _acceptance_response_has_exact_authority(
                value,
                actor_user_id=actor_user_id,
                invitation_id=invitation_id,
                expected_version=expected_version,
                policy_selector_digest=policy_selector_digest,
                policy_bundle_id=policy_bundle_id,
                target_role=resolved_target_role,
                organization_id=resolved_organization_id,
            )
        )
    except (KeyError, TypeError, ValueError):
        return False


def _receipt_policy_selector_digest(
    me: Mapping[str, Any],
    *,
    target_role: str,
    organization_id: UUID,
    policy_bundle_id: UUID,
) -> Optional[bytes]:
    """Extract one unambiguous Organization authority selector from a receipt."""

    try:
        requirements = me["policy_requirements"]
        if not isinstance(requirements, list) or any(
            not isinstance(item, Mapping) for item in requirements
        ):
            return None
        candidates = [
            item
            for item in requirements
            if item.get("purpose") == "ORGANIZATION_MEMBERSHIP"
            and item.get("role") == target_role
            and item.get("scope_type") == "ORGANIZATION_ROLE"
            and item.get("scope_id") == str(organization_id)
            and item.get("satisfied") is True
            and item.get("required_policy_bundle_id") == str(policy_bundle_id)
            and item.get("missing_document_ids") == []
        ]
        if len(candidates) != 1:
            return None
        selector = candidates[0].get("selector_digest")
        if not isinstance(selector, str) or len(selector) != 64:
            return None
        digest = bytes.fromhex(selector)
        return digest if len(digest) == 32 and selector == digest.hex() else None
    except (KeyError, TypeError, ValueError):
        return None


def _uuid(value: Any) -> UUID:
    parsed = value if isinstance(value, UUID) else UUID(str(value))
    if parsed.int == 0:
        raise ValueError("UUID must be non-zero")
    return parsed


def _new(source: OrganizationAcceptIdSource, purpose: str) -> UUID:
    try:
        return _uuid(source.new_id(purpose))
    except (AttributeError, TypeError, ValueError):
        raise IamError("SERVICE_UNAVAILABLE") from None


def _secret_bytes(source: Any, purpose: str, length: int) -> bytes:
    value = source.token_bytes(purpose, length)
    if not isinstance(value, bytes) or len(value) != length:
        raise IamError("SERVICE_UNAVAILABLE")
    return value


def _secret_text(source: Any, purpose: str, length: int) -> str:
    return base64.urlsafe_b64encode(
        _secret_bytes(source, purpose, length)
    ).rstrip(b"=").decode("ascii")


def _utc(value: Any) -> datetime:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() != timedelta(0)
    ):
        raise IamError("SERVICE_UNAVAILABLE")
    return value


def _is_utc_datetime(value: Any) -> bool:
    return (
        isinstance(value, datetime)
        and value.tzinfo is not None
        and value.utcoffset() == timedelta(0)
    )


def _clean_release(source: Any, connection: Any) -> bool:
    try:
        if connection.info.transaction_status != TransactionStatus.IDLE:
            source.discard(connection)
            return True
        connection.execute("RESET ALL")
        connection.execute("DISCARD TEMP")
        identity = connection.execute(
            "SELECT current_user,session_user,current_setting('app.scope_kind',true)"
        ).fetchone()
        if identity not in (
            ("iam_onboarding", "iam_onboarding", None),
            ("iam_onboarding", "iam_onboarding", ""),
        ):
            source.discard(connection)
            return True
    except BaseException:
        source.discard(connection)
        return True
    source.release(connection)
    return True


__all__ = [
    "InternalSandboxInvitationSafetyHold",
    "OrganizationAcceptKeyring",
    "OrganizationAcceptResolvedScope",
    "PostgresAcceptOrganizationAccessInvitationHandler",
    "PsycopgOrganizationAcceptScopeResolver",
]
