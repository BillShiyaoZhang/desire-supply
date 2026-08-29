"""Closed PostgreSQL bridge for first-login policy acceptance.

The public IAM presenter owns request parsing.  This adapter resolves the
current persisted Session/SessionFamily/auth-transaction and the exact policy
authority scope, then translates the already-normalized command into the
reviewed PostgreSQL request value.  Raw idempotency material never crosses the
PostgreSQL boundary.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
import hashlib
import hmac
import json
import re
from typing import Any, Mapping, Optional, Protocol, Union
from uuid import UUID

from desire_platform.identity_access.adapters.postgres.policy_consent_commands import (
    PolicyConsentPostgresAcceptanceChoice,
    PolicyConsentPostgresCommitOutcomeUnknownError,
    PolicyConsentPostgresConfigurationError,
    PolicyConsentPostgresDatabaseRequest,
    PolicyConsentPostgresExecutionScope,
    PolicyConsentPostgresGeneratedIds,
    PolicyConsentPostgresOperation,
    PolicyConsentReceiptIdentityDigest,
    PolicyConsentReceiptMaterial,
    PolicyConsentReceiptPayloadDigest,
)
from desire_platform.identity_access.application.policy_consent_commands import (
    AcceptCurrentPoliciesCommand,
    PolicyConsentActor,
    PolicyConsentCommandResult,
    PolicyRequirementReference,
    PolicyRequirementScopeType,
)
from desire_platform.identity_access.domain.errors import IamError
from desire_platform.identity_access.domain.policies import PolicyAcceptance

from .account_admin import PlatformUserAdminKeys


IAM_RECEIPT_IDEMPOTENCY_KEY_ID = "iam-receipt-idempotency-hmac-2026-01"
IAM_RECEIPT_PAYLOAD_KEY_ID = "iam-receipt-payload-hmac-2026-01"
_CANONICALIZATION_VERSION = "restricted-canonical-json-v1"
_IDENTITY_DOMAIN = "iam-self-command-idempotency-key-v1"
_RECEIPT_RETENTION = timedelta(days=30)
_MAXIMUM_ACCEPTANCES = 20
_SHA256 = re.compile(r"^[0-9a-f]{64}$")

_PRINCIPAL_SQL = """
/* internal_sandbox.resolve_policy_acceptance_principal_v1 */
SELECT
    session.family_id,
    session.auth_transaction_id
FROM iam.users AS actor
JOIN iam.sessions AS session
  ON session.user_id = actor.id
JOIN iam.session_families AS family
  ON family.id = session.family_id
 AND family.user_id = actor.id
WHERE actor.id = %s
  AND session.id = %s
  AND actor.status = 'ACTIVE'
  AND session.status = 'ACTIVE'
  AND family.status = 'ACTIVE'
  AND family.current_generation = session.generation
  AND session.auth_transaction_id IS NOT NULL
  AND session.auth_time IS NOT NULL
  AND session.auth_time <= transaction_timestamp()
  AND session.idle_expires_at > transaction_timestamp()
  AND session.absolute_expires_at > transaction_timestamp()
"""

_USER_AUTHORITY_SQL = """
/* internal_sandbox.resolve_policy_acceptance_user_authority_v1 */
SELECT count(*)
FROM iam.user_role_grants AS grant_row
WHERE grant_row.user_id = %s
  AND grant_row.policy_selector_digest = %s
  AND grant_row.revoked_at IS NULL
"""

_ORGANIZATION_AUTHORITY_SQL = """
/* internal_sandbox.resolve_policy_acceptance_organization_authority_v1 */
SELECT count(*)
FROM iam.membership_role_grants AS grant_row
JOIN iam.memberships AS membership
  ON membership.id = grant_row.membership_id
 AND membership.organization_id = grant_row.organization_id
 AND membership.user_id = grant_row.user_id
WHERE grant_row.user_id = %s
  AND grant_row.organization_id = %s
  AND grant_row.policy_selector_digest = %s
  AND grant_row.revoked_at IS NULL
  AND membership.status = 'ACTIVE'
"""


class PolicyAcceptanceConnectionSource(Protocol):
    def checkout(self) -> Any: ...

    def release(self, connection: Any) -> None: ...

    def discard(self, connection: Any) -> None: ...


@dataclass(frozen=True, repr=False)
class IamReceiptPolicyKeys:
    """The two IAM-wide receipt keys named by ``infra.iam_receipt_key_policy``.

    The current runtime bundle first introduced these carriers for the
    platform-user command slice.  Reuse here is explicit and permitted only
    because the database policy names the same IAM-wide key IDs; arbitrary
    cross-purpose aliases are rejected.
    """

    idempotency_key: Union[bytes, bytearray] = field(repr=False)
    payload_hash_key: Union[bytes, bytearray] = field(repr=False)
    idempotency_key_id: str = IAM_RECEIPT_IDEMPOTENCY_KEY_ID
    payload_hash_key_id: str = IAM_RECEIPT_PAYLOAD_KEY_ID

    def __post_init__(self) -> None:
        materials = (self.idempotency_key, self.payload_hash_key)
        if (
            self.idempotency_key_id != IAM_RECEIPT_IDEMPOTENCY_KEY_ID
            or self.payload_hash_key_id != IAM_RECEIPT_PAYLOAD_KEY_ID
            or any(
                not isinstance(value, (bytes, bytearray))
                or len(value) < 32
                or not any(value)
                for value in materials
            )
            or hmac.compare_digest(bytes(materials[0]), bytes(materials[1]))
        ):
            raise ValueError("IAM receipt policy keys are unavailable")

    @classmethod
    def from_platform_user_admin_keys(
        cls, keys: PlatformUserAdminKeys
    ) -> "IamReceiptPolicyKeys":
        if not isinstance(keys, PlatformUserAdminKeys):
            raise TypeError("IAM receipt policy source keys are unavailable")
        return cls(
            idempotency_key=keys.idempotency_key,
            payload_hash_key=keys.payload_hash_key,
            idempotency_key_id=keys.idempotency_key_id,
            payload_hash_key_id=keys.payload_hash_key_id,
        )

    def __repr__(self) -> str:
        return (
            "IamReceiptPolicyKeys("
            f"idempotency_key_id={self.idempotency_key_id!r}, "
            f"payload_hash_key_id={self.payload_hash_key_id!r}, "
            "material=<redacted>)"
        )


@dataclass(frozen=True)
class PolicyAcceptancePostgresScope:
    actor_user_id: UUID
    session_id: UUID
    session_family_id: UUID
    auth_transaction_id: UUID
    selector_digest: bytes = field(repr=False)
    authority_scope_type: str
    authority_scope_id: Optional[UUID]
    organization_id: Optional[UUID]

    def __post_init__(self) -> None:
        identifiers = (
            self.actor_user_id,
            self.session_id,
            self.session_family_id,
            self.auth_transaction_id,
        )
        if any(not isinstance(value, UUID) or value.int == 0 for value in identifiers):
            raise ValueError("policy acceptance principal scope is unavailable")
        if not isinstance(self.selector_digest, bytes) or len(self.selector_digest) != 32:
            raise ValueError("policy acceptance selector is unavailable")
        if self.authority_scope_type == "USER_ROLE":
            if self.authority_scope_id is not None or self.organization_id is not None:
                raise ValueError("USER_ROLE policy authority must have null scope")
        elif self.authority_scope_type == "ORGANIZATION_ROLE":
            if (
                not isinstance(self.authority_scope_id, UUID)
                or self.authority_scope_id.int == 0
                or self.organization_id != self.authority_scope_id
            ):
                raise ValueError("organization policy authority is unavailable")
        else:
            raise ValueError("policy authority scope type is unavailable")


class PsycopgPolicyAcceptanceScopeResolver:
    """Resolve only the persisted facts absent from ``AuthenticatedHttpActor``."""

    def __init__(self, *, connections: PolicyAcceptanceConnectionSource) -> None:
        for name in ("checkout", "release", "discard"):
            if not callable(getattr(connections, name, None)):
                raise TypeError("policy acceptance PostgreSQL connections are unavailable")
        self.connections = connections

    def resolve(
        self,
        *,
        actor: PolicyConsentActor,
        policy_requirement: PolicyRequirementReference,
    ) -> PolicyAcceptancePostgresScope:
        if not isinstance(actor, PolicyConsentActor) or not isinstance(
            policy_requirement, PolicyRequirementReference
        ):
            raise IamError("SERVICE_UNAVAILABLE")
        try:
            actor_id = _uuid(actor.actor_user_id)
            session_id = _uuid(actor.current_session_id)
            selector = bytes.fromhex(policy_requirement.selector_digest)
            scope_type = PolicyRequirementScopeType(policy_requirement.scope_type)
            scope_id = (
                None
                if policy_requirement.scope_id is None
                else _uuid(policy_requirement.scope_id)
            )
        except (TypeError, ValueError):
            raise IamError("INVALID_REQUEST") from None
        if len(selector) != 32:
            raise IamError("INVALID_REQUEST")

        connection = self.connections.checkout()
        transaction_started = False
        try:
            if getattr(connection, "autocommit", None) is not True:
                raise RuntimeError("policy acceptance connections require autocommit")
            _reset_connection(connection)
            connection.execute(
                "BEGIN TRANSACTION ISOLATION LEVEL READ COMMITTED READ ONLY"
            )
            transaction_started = True
            _install_scope_context(
                connection,
                actor_id=actor_id,
                session_id=session_id,
                selector_digest=selector,
                scope_type=scope_type.value,
                scope_id=scope_id,
            )
            principal_rows = connection.execute(
                _PRINCIPAL_SQL, (actor_id, session_id)
            ).fetchall()
            if len(principal_rows) != 1:
                raise IamError("AUTHENTICATION_REQUIRED")
            family_id, auth_transaction_id = principal_rows[0]
            if scope_type is PolicyRequirementScopeType.USER_ROLE:
                authority_rows = connection.execute(
                    _USER_AUTHORITY_SQL, (actor_id, selector)
                ).fetchall()
                organization_id = None
            else:
                if scope_id is None:
                    raise IamError("INVALID_REQUEST")
                authority_rows = connection.execute(
                    _ORGANIZATION_AUTHORITY_SQL,
                    (actor_id, scope_id, selector),
                ).fetchall()
                organization_id = scope_id
            if authority_rows != [(1,)]:
                raise IamError("RESOURCE_NOT_FOUND")
            resolved = PolicyAcceptancePostgresScope(
                actor_user_id=actor_id,
                session_id=session_id,
                session_family_id=_uuid(family_id),
                auth_transaction_id=_uuid(auth_transaction_id),
                selector_digest=selector,
                authority_scope_type=scope_type.value,
                authority_scope_id=scope_id,
                organization_id=organization_id,
            )
            connection.execute("COMMIT")
            transaction_started = False
            _reset_connection(connection)
            self.connections.release(connection)
            return resolved
        except IamError:
            _abort_and_discard(
                self.connections,
                connection,
                transaction_started=transaction_started,
            )
            raise
        except BaseException:
            _abort_and_discard(
                self.connections,
                connection,
                transaction_started=transaction_started,
            )
            raise IamError("SERVICE_UNAVAILABLE") from None

    def __repr__(self) -> str:
        return "PsycopgPolicyAcceptanceScopeResolver(connections=<redacted>)"


class PostgresAcceptCurrentPoliciesHandler:
    """Translate one normalized SELF command into the exact PG18 request."""

    def __init__(
        self,
        *,
        scope_resolver: Any,
        uow_factory: Any,
        keys: IamReceiptPolicyKeys,
        clock: Any,
        id_source: Any,
    ) -> None:
        if not callable(getattr(scope_resolver, "resolve", None)):
            raise TypeError("policy acceptance scope resolver is unavailable")
        if not callable(
            getattr(uow_factory, "execute_accept_current_policies", None)
        ):
            raise TypeError("policy acceptance PostgreSQL unit of work is unavailable")
        if not isinstance(keys, IamReceiptPolicyKeys):
            raise TypeError("IAM receipt policy keys are unavailable")
        if not callable(getattr(clock, "now", None)) or not callable(
            getattr(id_source, "new_id", None)
        ):
            raise TypeError("policy acceptance runtime sources are unavailable")
        self._scope_resolver = scope_resolver
        self._uow_factory = uow_factory
        self._keys = keys
        self._clock = clock
        self._id_source = id_source

    def handle(
        self,
        *,
        actor: PolicyConsentActor,
        command: AcceptCurrentPoliciesCommand,
    ) -> PolicyConsentCommandResult:
        if not isinstance(actor, PolicyConsentActor) or not isinstance(
            command, AcceptCurrentPoliciesCommand
        ):
            raise IamError("SERVICE_UNAVAILABLE")
        if actor.original_actor_id is not None:
            raise IamError("SERVICE_UNAVAILABLE")
        try:
            scope = self._scope_resolver.resolve(
                actor=actor,
                policy_requirement=command.policy_requirement,
            )
        except IamError as error:
            if error.code == "NOT_FOUND":
                raise IamError("RESOURCE_NOT_FOUND") from None
            raise
        if not isinstance(scope, PolicyAcceptancePostgresScope):
            raise IamError("SERVICE_UNAVAILABLE")
        request = self._request(actor=actor, command=command, scope=scope)
        try:
            result = self._uow_factory.execute_accept_current_policies(request)
        except PolicyConsentPostgresCommitOutcomeUnknownError:
            raise IamError("COMMAND_OUTCOME_UNKNOWN") from None
        except PolicyConsentPostgresConfigurationError:
            raise IamError("SERVICE_UNAVAILABLE") from None
        except IamError as error:
            if error.code == "NOT_FOUND":
                raise IamError("RESOURCE_NOT_FOUND") from None
            raise
        except BaseException:
            raise IamError("SERVICE_UNAVAILABLE") from None
        if (
            getattr(result, "operation", None)
            is not PolicyConsentPostgresOperation.ACCEPT_CURRENT_POLICIES
            or not isinstance(getattr(result, "safe_response", None), Mapping)
        ):
            raise IamError("SERVICE_UNAVAILABLE")
        return PolicyConsentCommandResult(
            operation_id="acceptCurrentPolicies",
            replayed=result.replayed,
            http_status=200,
            json_body=dict(result.safe_response),
            response_entity_tag=result.response_entity_tag,
            current_user_entity_tag=result.current_user_entity_tag,
        )

    def _request(
        self,
        *,
        actor: PolicyConsentActor,
        command: AcceptCurrentPoliciesCommand,
        scope: PolicyAcceptancePostgresScope,
    ) -> PolicyConsentPostgresDatabaseRequest:
        try:
            bundle_id = _uuid(command.policy_bundle_id)
            correlation_id = _uuid(actor.correlation_id)
            trace_id = _uuid(actor.trace_id)
            now = _utc(self._clock.now())
        except (TypeError, ValueError):
            raise IamError("INVALID_REQUEST") from None
        payload_projection = _accept_current_policies_payload_projection(
            actor_user_id=actor.actor_user_id,
            command=command,
        )
        choices = tuple(command.policy_acceptances)
        if not 1 <= len(choices) <= _MAXIMUM_ACCEPTANCES:
            raise IamError("INVALID_REQUEST")
        try:
            acceptances = tuple(
                PolicyConsentPostgresAcceptanceChoice(
                    document_id=_uuid(item.document_id),
                    content_sha256=bytes.fromhex(item.content_sha256),
                    affirmed=item.affirmed,
                )
                for item in sorted(
                    choices,
                    key=lambda item: (item.document_id, item.content_sha256),
                )
            )
        except (AttributeError, TypeError, ValueError):
            raise IamError("INVALID_REQUEST") from None
        command_id = self._new_id("policy_consent_command")
        acceptance_ids = tuple(
            self._new_id("policy_consent_acceptance") for _ in acceptances
        )
        audit_id = self._new_id("policy_consent_audit")
        outbox_ids = tuple(
            self._new_id("policy_consent_outbox")
            for _ in range(len(acceptances) + 1)
        )
        if len(
            {
                command_id,
                *acceptance_ids,
                audit_id,
                *outbox_ids,
            }
        ) != 2 * len(acceptances) + 3:
            raise IamError("SERVICE_UNAVAILABLE")

        identity_bytes = _canonical_bytes(
            {
                "domain": _IDENTITY_DOMAIN,
                "idempotency_key": command.idempotency_key,
            }
        )
        payload_bytes = _canonical_bytes(payload_projection)
        receipt = PolicyConsentReceiptMaterial(
            receipt_id=command_id,
            principal_id=scope.actor_user_id,
            identity_candidates=(
                PolicyConsentReceiptIdentityDigest(
                    key_id=self._keys.idempotency_key_id,
                    digest=_hmac(self._keys.idempotency_key, identity_bytes),
                ),
            ),
            active_identity_key_id=self._keys.idempotency_key_id,
            payload_candidates=(
                PolicyConsentReceiptPayloadDigest(
                    key_id=self._keys.payload_hash_key_id,
                    canonicalization_version=_CANONICALIZATION_VERSION,
                    digest=_hmac(self._keys.payload_hash_key, payload_bytes),
                ),
            ),
            active_payload_key_id=self._keys.payload_hash_key_id,
            active_canonicalization_version=_CANONICALIZATION_VERSION,
            retain_until=now + _RECEIPT_RETENTION,
        )
        return PolicyConsentPostgresDatabaseRequest(
            operation=PolicyConsentPostgresOperation.ACCEPT_CURRENT_POLICIES,
            scope=PolicyConsentPostgresExecutionScope(
                actor_user_id=scope.actor_user_id,
                session_id=scope.session_id,
                session_family_id=scope.session_family_id,
                auth_transaction_id=scope.auth_transaction_id,
                selector_digest=scope.selector_digest,
                authority_scope_type=scope.authority_scope_type,
                authority_scope_id=scope.authority_scope_id,
                organization_id=scope.organization_id,
                command_id=command_id,
                correlation_id=correlation_id,
                causation_id=command_id,
                trace_id=trace_id,
            ),
            receipt=receipt,
            expected_user_version=command.expected_user_version,
            policy_bundle_id=bundle_id,
            policy_acceptances=acceptances,
            consent_choice=None,
            generated_ids=PolicyConsentPostgresGeneratedIds(
                policy_acceptance_ids=acceptance_ids,
                consent_grant_id=None,
                audit_event_id=audit_id,
                outbox_event_ids=outbox_ids,
            ),
        )

    def _new_id(self, purpose: str) -> UUID:
        try:
            value = self._id_source.new_id(purpose)
        except BaseException:
            raise IamError("SERVICE_UNAVAILABLE") from None
        if not isinstance(value, UUID) or value.int == 0:
            raise IamError("SERVICE_UNAVAILABLE")
        return value

    def __repr__(self) -> str:
        return "PostgresAcceptCurrentPoliciesHandler(dependencies=<redacted>)"


def _install_scope_context(
    connection: Any,
    *,
    actor_id: UUID,
    session_id: UUID,
    selector_digest: bytes,
    scope_type: str,
    scope_id: Optional[UUID],
) -> None:
    values = (
        ("app.scope_kind", "SELF"),
        ("app.operation", "ACCEPT_CURRENT_POLICIES"),
        ("app.actor_user_id", str(actor_id)),
        ("app.session_id", str(session_id)),
        ("app.policy_selector_digest", selector_digest.hex()),
        ("app.authority_scope_type", scope_type),
        ("app.authority_scope_id", "" if scope_id is None else str(scope_id)),
        ("app.organization_id", "" if scope_id is None else str(scope_id)),
    )
    connection.execute("SET LOCAL TIME ZONE 'UTC'")
    connection.execute("SET LOCAL lock_timeout = '500ms'")
    connection.execute("SET LOCAL statement_timeout = '5000ms'")
    connection.execute("SET LOCAL idle_in_transaction_session_timeout = '10000ms'")
    identity = connection.execute(
        "SELECT current_user,session_user,current_setting('server_version_num')::integer"
    ).fetchone()
    if identity is None or identity[0:2] != ("iam_app", "iam_app"):
        raise RuntimeError("policy acceptance connection identity is unavailable")
    if not isinstance(identity[2], int) or identity[2] // 10_000 != 18:
        raise RuntimeError("policy acceptance requires PostgreSQL major 18")
    for name, value in values:
        configured = connection.execute(
            "SELECT pg_catalog.set_config(%s,%s,true)", (name, value)
        ).fetchone()
        if configured != (value,):
            raise RuntimeError("policy acceptance context installation failed")


def _abort_and_discard(
    source: PolicyAcceptanceConnectionSource,
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
    source.discard(connection)


def _reset_connection(connection: Any) -> None:
    connection.execute("RESET ROLE")
    connection.execute("RESET ALL")
    connection.execute("DISCARD TEMP")


def _uuid(value: Any) -> UUID:
    if isinstance(value, UUID):
        result = value
    elif isinstance(value, str):
        result = UUID(value)
    else:
        raise TypeError("UUID value is unavailable")
    if result.int == 0 or (isinstance(value, str) and str(result) != value):
        raise ValueError("UUID value is not canonical")
    return result


def _utc(value: Any) -> datetime:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() != timedelta(0)
    ):
        raise ValueError("UTC time is unavailable")
    return value.astimezone(timezone.utc)


def _policy_requirement_body(
    reference: PolicyRequirementReference,
) -> dict[str, Any]:
    if not isinstance(reference, PolicyRequirementReference):
        raise IamError("INVALID_REQUEST")
    try:
        scope_type = PolicyRequirementScopeType(reference.scope_type)
    except (TypeError, ValueError) as error:
        raise IamError("INVALID_REQUEST") from error
    if _SHA256.fullmatch(reference.selector_digest) is None:
        raise IamError("INVALID_REQUEST")
    if scope_type is PolicyRequirementScopeType.USER_ROLE:
        if reference.scope_id is not None:
            raise IamError("INVALID_REQUEST")
    elif not isinstance(reference.scope_id, str) or not reference.scope_id:
        raise IamError("INVALID_REQUEST")
    return {
        "selector_digest": reference.selector_digest,
        "scope_type": scope_type.value,
        "scope_id": reference.scope_id,
    }


def _accept_current_policies_payload_projection(
    *,
    actor_user_id: str,
    command: AcceptCurrentPoliciesCommand,
) -> dict[str, Any]:
    """Mechanical equivalent of the reviewed application command projection."""

    if not isinstance(actor_user_id, str) or not actor_user_id:
        raise IamError("AUTHENTICATION_REQUIRED")
    if (
        not isinstance(command.idempotency_key, str)
        or not command.idempotency_key
        or not isinstance(command.expected_user_version, int)
        or isinstance(command.expected_user_version, bool)
        or command.expected_user_version < 1
        or not isinstance(command.policy_bundle_id, str)
        or not command.policy_bundle_id
        or not isinstance(command.policy_acceptances, tuple)
    ):
        raise IamError("INVALID_REQUEST")
    acceptances = []
    for item in command.policy_acceptances:
        if not isinstance(item, PolicyAcceptance):
            raise IamError("INVALID_REQUEST")
        acceptances.append(
            {
                "document_id": item.document_id,
                "content_sha256": item.content_sha256,
                "affirmed": item.affirmed,
            }
        )
    body = {
        "policy_requirement": _policy_requirement_body(command.policy_requirement),
        "policy_bundle_id": command.policy_bundle_id,
        "policy_acceptances": sorted(
            acceptances,
            key=lambda item: (item["document_id"], item["content_sha256"]),
        ),
    }
    return {
        "body": body,
        "canonicalization_version": _CANONICALIZATION_VERSION,
        "command_name": "AcceptCurrentPolicies",
        "command_version": 1,
        "http_method": "POST",
        "if_match_version": command.expected_user_version,
        "path": "/v1/me/policy-acceptances",
        "target_id": actor_user_id,
        "target_kind": "User",
    }


def _timestamp(value: datetime) -> str:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() != timedelta(0)
    ):
        raise IamError("SERVICE_UNAVAILABLE")
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _canonical_bytes(value: object) -> bytes:
    def normalize(item: object) -> object:
        if isinstance(item, Mapping):
            return {str(key): normalize(child) for key, child in item.items()}
        if isinstance(item, (list, tuple)):
            return [normalize(child) for child in item]
        if isinstance(item, Enum):
            return item.value
        if isinstance(item, datetime):
            return _timestamp(item)
        if isinstance(item, float):
            raise IamError("INVALID_REQUEST")
        return item

    try:
        return json.dumps(
            normalize(value),
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except IamError:
        raise
    except (TypeError, ValueError, UnicodeError, OverflowError) as error:
        raise IamError("INVALID_REQUEST") from error


def _hmac(key: Union[bytes, bytearray], value: bytes) -> bytes:
    return hmac.new(bytes(key), value, hashlib.sha256).digest()


__all__ = [
    "IAM_RECEIPT_IDEMPOTENCY_KEY_ID",
    "IAM_RECEIPT_PAYLOAD_KEY_ID",
    "IamReceiptPolicyKeys",
    "PolicyAcceptancePostgresScope",
    "PostgresAcceptCurrentPoliciesHandler",
    "PsycopgPolicyAcceptanceScopeResolver",
]
