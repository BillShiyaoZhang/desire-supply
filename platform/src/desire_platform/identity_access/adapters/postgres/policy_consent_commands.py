"""PostgreSQL boundary for SELF policy-acceptance and consent commands.

This module exposes the reviewed immutable database request and the fixed
PostgreSQL 18 transaction program.  Raw Idempotency-Key, cookie, CSRF, policy
text and recipient material are deliberately absent from every public value
in this module.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
import hashlib
import hmac
from typing import Any, Dict, List, Mapping, Optional, Protocol, Sequence, Tuple
from uuid import UUID

from psycopg import DatabaseError
from psycopg.pq import TransactionStatus
from psycopg.types.json import Jsonb

from desire_platform.utc import parse_utc_timestamp

from ...domain.errors import IamError
from ...domain.policies import (
    ConsentOffer,
    ConsentPurpose,
    ConsentScopeType,
    DataCategory,
    canonical_consent_offer_bytes,
)


POSTGRES_POLICY_CONSENT_BEHAVIOR_NOT_AVAILABLE = (
    "IAM_POSTGRES_POLICY_CONSENT_BEHAVIOR_NOT_AVAILABLE"
)


class PolicyConsentPostgresBehaviorNotAvailable(RuntimeError):
    """Stable semantic-RED sentinel for the unimplemented SQL program."""


class PolicyConsentPostgresConfigurationError(RuntimeError):
    """The role, server, transaction, or closed deployment settings are unsafe."""


class PolicyConsentPostgresCommitOutcomeUnknownError(RuntimeError):
    """COMMIT was sent, so the current request cannot infer the outcome."""

    code = "COMMAND_OUTCOME_UNKNOWN"


class PolicyConsentPostgresOperation(str, Enum):
    ACCEPT_CURRENT_POLICIES = "AcceptCurrentPolicies"
    GRANT_CONSENT = "GrantConsent"


class PolicyConsentPostgresUnitOfWorkState(str, Enum):
    NEW = "NEW"
    BEGUN = "BEGUN"
    WRITING = "WRITING"
    COMMIT_SENT = "COMMIT_SENT"
    COMMITTED = "COMMITTED"
    ROLLED_BACK = "ROLLED_BACK"
    OUTCOME_UNKNOWN = "OUTCOME_UNKNOWN"


class PolicyConsentPostgresWriteCheckpoint(str, Enum):
    COMMAND_RECEIPT_CLAIM = "command_receipt.claim"
    POLICY_ACCEPTANCE_INSERT = "policy_acceptance.insert"
    CONSENT_GRANT_EXPIRE = "consent_grant.expire"
    CONSENT_GRANT_INSERT = "consent_grant.insert"
    CONSENT_GRANT_CATEGORY_INSERT = "consent_grant_category.insert"
    USER_VERSION_CAS = "user.version-cas"
    AUDIT_EVENT_INSERT = "audit_event.insert"
    OUTBOX_EVENT_INSERT = "outbox_event.insert"
    COMMAND_RECEIPT_COMPLETE = "command_receipt.complete"


POLICY_CONSENT_POSTGRES_WRITE_CHECKPOINTS: Tuple[
    PolicyConsentPostgresWriteCheckpoint, ...
] = tuple(PolicyConsentPostgresWriteCheckpoint)


class PolicyConsentPostgresConnectionSource(Protocol):
    """Role-bound pool boundary with reusable and tainted dispositions."""

    def checkout(self) -> Any: ...

    def release(self, connection: Any) -> None: ...

    def discard(self, connection: Any) -> None: ...


class PolicyConsentPostgresFaultInjector(Protocol):
    """Deterministic test hook immediately before one logical SQL write."""

    def before_write(
        self,
        checkpoint: PolicyConsentPostgresWriteCheckpoint,
        ordinal: int,
    ) -> None: ...


class PolicyConsentPostgresSchemaValidator(Protocol):
    """Closed event/response validator supplied by production composition."""

    def validate(
        self,
        value: Mapping[str, Any],
        schema_name: Optional[str] = None,
    ) -> None: ...


class NoPolicyConsentPostgresFaults:
    """Production default; it cannot alter statements or transaction state."""

    def before_write(
        self,
        checkpoint: PolicyConsentPostgresWriteCheckpoint,
        ordinal: int,
    ) -> None:
        del checkpoint, ordinal


@dataclass(frozen=True)
class PolicyConsentPostgresSettings:
    """Closed online-writer settings; owner/onboarding roles are invalid."""

    runtime_role: str = "iam_app"
    lock_timeout_ms: int = 2_000
    statement_timeout_ms: int = 10_000
    idle_in_transaction_timeout_ms: int = 15_000
    max_precommit_retries: int = 3

    def __post_init__(self) -> None:
        if self.runtime_role != "iam_app":
            raise ValueError("policy/consent runtime role must be iam_app")
        if not 1 <= self.lock_timeout_ms <= 10_000:
            raise ValueError("policy/consent lock timeout is outside reviewed bounds")
        if not 1 <= self.statement_timeout_ms <= 30_000:
            raise ValueError(
                "policy/consent statement timeout is outside reviewed bounds"
            )
        if not 1 <= self.idle_in_transaction_timeout_ms <= 30_000:
            raise ValueError(
                "policy/consent idle-in-transaction timeout is outside reviewed bounds"
            )
        if self.max_precommit_retries != 3:
            raise ValueError(
                "policy/consent pre-COMMIT retry count must be exactly 3"
            )


@dataclass(frozen=True)
class PolicyConsentReceiptIdentityDigest:
    """One retained keyed Idempotency-Key candidate; never the raw key."""

    key_id: str
    digest: bytes = field(repr=False)

    def __post_init__(self) -> None:
        _require_key_id(self.key_id, "receipt identity key ID")
        _require_digest(self.digest, "receipt identity digest")


@dataclass(frozen=True)
class PolicyConsentReceiptPayloadDigest:
    """Payload HMAC for one retained key/canonicalizer pair."""

    key_id: str
    canonicalization_version: str
    digest: bytes = field(repr=False)

    def __post_init__(self) -> None:
        _require_key_id(self.key_id, "receipt payload key ID")
        if self.canonicalization_version != "restricted-canonical-json-v1":
            raise ValueError("unsupported policy/consent receipt canonicalization")
        _require_digest(self.digest, "receipt payload digest")


@dataclass(frozen=True)
class PolicyConsentReceiptMaterial:
    """Closed receipt claim/replay material produced outside the repository."""

    receipt_id: UUID
    principal_id: UUID
    identity_candidates: Tuple[PolicyConsentReceiptIdentityDigest, ...] = field(
        repr=False
    )
    active_identity_key_id: str
    payload_candidates: Tuple[PolicyConsentReceiptPayloadDigest, ...] = field(
        repr=False
    )
    active_payload_key_id: str
    active_canonicalization_version: str
    retain_until: datetime

    def __post_init__(self) -> None:
        if self.receipt_id.int == 0 or self.principal_id.int == 0:
            raise ValueError("receipt and principal IDs must be non-zero")
        if not self.identity_candidates or not self.payload_candidates:
            raise ValueError("retained receipt candidates cannot be empty")
        identity_ids = tuple(item.key_id for item in self.identity_candidates)
        if len(identity_ids) != len(set(identity_ids)):
            raise ValueError("receipt identity key IDs must be unique")
        if self.active_identity_key_id not in identity_ids:
            raise ValueError("active receipt identity key is not retained")
        payload_pairs = tuple(
            (item.key_id, item.canonicalization_version)
            for item in self.payload_candidates
        )
        if len(payload_pairs) != len(set(payload_pairs)):
            raise ValueError("receipt payload key/canonicalizer pairs must be unique")
        active_pair = (
            self.active_payload_key_id,
            self.active_canonicalization_version,
        )
        if active_pair not in payload_pairs:
            raise ValueError("active receipt payload material is not retained")
        _require_utc(self.retain_until, "receipt retain_until")


@dataclass(frozen=True)
class PolicyConsentPostgresExecutionScope:
    """Exact persisted actor, Session and policy-authority identifiers."""

    actor_user_id: UUID
    session_id: UUID
    session_family_id: UUID
    auth_transaction_id: UUID
    selector_digest: bytes = field(repr=False)
    authority_scope_type: str
    authority_scope_id: Optional[UUID]
    organization_id: Optional[UUID]
    command_id: UUID
    correlation_id: UUID
    causation_id: UUID
    trace_id: UUID

    def __post_init__(self) -> None:
        _require_digest(self.selector_digest, "policy selector digest")
        required_ids = (
            self.actor_user_id,
            self.session_id,
            self.session_family_id,
            self.auth_transaction_id,
            self.command_id,
            self.correlation_id,
            self.causation_id,
            self.trace_id,
        )
        if any(value.int == 0 for value in required_ids):
            raise ValueError("policy/consent execution IDs must be non-zero")
        if self.authority_scope_type == "USER_ROLE":
            if self.authority_scope_id is not None or self.organization_id is not None:
                raise ValueError("USER_ROLE authority must have null scope")
        elif self.authority_scope_type == "ORGANIZATION_ROLE":
            if (
                self.authority_scope_id is None
                or self.organization_id != self.authority_scope_id
            ):
                raise ValueError(
                    "ORGANIZATION_ROLE authority must bind one exact organization"
                )
        else:
            raise ValueError("unsupported policy requirement authority scope")


@dataclass(frozen=True)
class PolicyConsentPostgresAcceptanceChoice:
    document_id: UUID
    content_sha256: bytes = field(repr=False)
    affirmed: bool

    def __post_init__(self) -> None:
        _require_digest(self.content_sha256, "policy document digest")
        if self.affirmed is not True:
            raise ValueError("policy acceptance must be explicitly affirmed")


@dataclass(frozen=True)
class PolicyConsentPostgresOfferChoice:
    consent_offer_id: UUID
    document_id: UUID
    content_sha256: bytes = field(repr=False)
    affirmed: bool

    def __post_init__(self) -> None:
        _require_digest(self.content_sha256, "consent document digest")
        if self.affirmed is not True:
            raise ValueError("consent choice must be explicitly affirmed")


@dataclass(frozen=True)
class PolicyConsentPostgresGeneratedIds:
    """Retry-stable identifiers; unused IDs are harmless on exact replay."""

    policy_acceptance_ids: Tuple[UUID, ...]
    consent_grant_id: Optional[UUID]
    audit_event_id: UUID
    outbox_event_ids: Tuple[UUID, ...]

    def __post_init__(self) -> None:
        values = (
            self.policy_acceptance_ids
            + self.outbox_event_ids
            + ((self.consent_grant_id,) if self.consent_grant_id is not None else ())
            + (self.audit_event_id,)
        )
        if any(value.int == 0 for value in values):
            raise ValueError("generated policy/consent IDs must be non-zero")
        if len(values) != len(set(values)):
            raise ValueError("generated policy/consent IDs must be unique")


@dataclass(frozen=True)
class PolicyConsentPostgresDatabaseRequest:
    """One closed SELF command persistence plan; contains no raw carrier."""

    operation: PolicyConsentPostgresOperation
    scope: PolicyConsentPostgresExecutionScope
    receipt: PolicyConsentReceiptMaterial
    expected_user_version: int
    policy_bundle_id: UUID
    policy_acceptances: Tuple[PolicyConsentPostgresAcceptanceChoice, ...]
    consent_choice: Optional[PolicyConsentPostgresOfferChoice]
    generated_ids: PolicyConsentPostgresGeneratedIds

    def __post_init__(self) -> None:
        if not isinstance(self.operation, PolicyConsentPostgresOperation):
            raise ValueError("policy/consent operation is not closed")
        if self.expected_user_version < 1:
            raise ValueError("expected User version must be positive")
        if self.receipt.receipt_id != self.scope.command_id:
            raise ValueError("receipt and command ID must be identical")
        if self.receipt.principal_id != self.scope.actor_user_id:
            raise ValueError("receipt principal must be the actor")
        if self.operation is PolicyConsentPostgresOperation.ACCEPT_CURRENT_POLICIES:
            if not self.policy_acceptances or self.consent_choice is not None:
                raise ValueError("AcceptCurrentPolicies request has an open shape")
            if self.generated_ids.consent_grant_id is not None:
                raise ValueError("AcceptCurrentPolicies generated IDs have an open shape")
            if len(self.generated_ids.policy_acceptance_ids) != len(
                self.policy_acceptances
            ):
                raise ValueError("acceptance generated IDs must match choices")
        elif self.operation is PolicyConsentPostgresOperation.GRANT_CONSENT:
            if self.policy_acceptances or self.consent_choice is None:
                raise ValueError("GrantConsent request has an open shape")
            if (
                self.generated_ids.consent_grant_id is None
                or self.generated_ids.policy_acceptance_ids
            ):
                raise ValueError("GrantConsent generated IDs have an open shape")
        _require_utc(self.receipt.retain_until, "receipt retain_until")


@dataclass(frozen=True)
class PolicyConsentPostgresDatabaseResult:
    operation: PolicyConsentPostgresOperation
    replayed: bool
    safe_response: Mapping[str, Any] = field(repr=False)
    response_entity_tag: str
    current_user_entity_tag: str


class PsycopgPolicyConsentCommandUnitOfWorkFactory:
    """Execute the two reviewed SELF command programs on PostgreSQL 18."""

    def __init__(
        self,
        *,
        connections: PolicyConsentPostgresConnectionSource,
        event_validator: PolicyConsentPostgresSchemaValidator,
        response_validator: PolicyConsentPostgresSchemaValidator,
        settings: Optional[PolicyConsentPostgresSettings] = None,
        fault_injector: Optional[PolicyConsentPostgresFaultInjector] = None,
    ) -> None:
        self.connections = connections
        self.event_validator = event_validator
        self.response_validator = response_validator
        self.settings = settings or PolicyConsentPostgresSettings()
        self.fault_injector = fault_injector or NoPolicyConsentPostgresFaults()

    def execute_accept_current_policies(
        self,
        request: PolicyConsentPostgresDatabaseRequest,
    ) -> PolicyConsentPostgresDatabaseResult:
        _require_operation(
            request,
            PolicyConsentPostgresOperation.ACCEPT_CURRENT_POLICIES,
        )
        return self._execute(
            request,
            PolicyConsentPostgresOperation.ACCEPT_CURRENT_POLICIES,
        )

    def execute_grant_consent(
        self,
        request: PolicyConsentPostgresDatabaseRequest,
    ) -> PolicyConsentPostgresDatabaseResult:
        return self._execute(
            request,
            PolicyConsentPostgresOperation.GRANT_CONSENT,
        )

    def _execute(
        self,
        request: PolicyConsentPostgresDatabaseRequest,
        expected: PolicyConsentPostgresOperation,
    ) -> PolicyConsentPostgresDatabaseResult:
        _require_operation(request, expected)
        total_attempts = self.settings.max_precommit_retries + 1
        for attempt in range(total_attempts):
            try:
                return self._execute_once(request)
            except BaseException as error:
                if (
                    attempt + 1 < total_attempts
                    and _is_retryable_precommit_error(error)
                ):
                    continue
                raise
        raise AssertionError("closed policy/consent retry loop did not terminate")

    def _execute_once(
        self,
        request: PolicyConsentPostgresDatabaseRequest,
    ) -> PolicyConsentPostgresDatabaseResult:
        connection = self.connections.checkout()
        state = PolicyConsentPostgresUnitOfWorkState.NEW
        disposed = False
        try:
            self._validate_connection_identity(connection)
            connection.execute("BEGIN ISOLATION LEVEL READ COMMITTED")
            state = PolicyConsentPostgresUnitOfWorkState.BEGUN
            self._configure_transaction(connection, request)
            state = PolicyConsentPostgresUnitOfWorkState.WRITING
            result = self._execute_transaction(connection, request)
            state = PolicyConsentPostgresUnitOfWorkState.COMMIT_SENT
            connection.execute("COMMIT")
            state = PolicyConsentPostgresUnitOfWorkState.COMMITTED
        except BaseException as error:
            if state == PolicyConsentPostgresUnitOfWorkState.COMMIT_SENT:
                self.connections.discard(connection)
                disposed = True
                raise PolicyConsentPostgresCommitOutcomeUnknownError() from error
            if state in (
                PolicyConsentPostgresUnitOfWorkState.BEGUN,
                PolicyConsentPostgresUnitOfWorkState.WRITING,
            ):
                try:
                    connection.execute("ROLLBACK")
                    state = PolicyConsentPostgresUnitOfWorkState.ROLLED_BACK
                except BaseException:
                    self.connections.discard(connection)
                    disposed = True
                else:
                    disposed = self._release_or_discard(connection)
            else:
                self.connections.discard(connection)
                disposed = True
            raise
        else:
            disposed = self._release_or_discard(connection)
            return result
        finally:
            if not disposed:
                self.connections.discard(connection)

    def _validate_connection_identity(self, connection: Any) -> None:
        if not _connection_is_idle(connection):
            raise PolicyConsentPostgresConfigurationError(
                "policy/consent checkout must be transaction-idle"
            )
        identity = connection.execute(
            "SELECT current_user,session_user,"
            "current_setting('server_version_num')::integer"
        ).fetchone()
        if identity is None or identity[0:2] != (
            self.settings.runtime_role,
            self.settings.runtime_role,
        ):
            raise PolicyConsentPostgresConfigurationError(
                "policy/consent connection identity is not iam_app"
            )
        if identity[2] // 10_000 != 18:
            raise PolicyConsentPostgresConfigurationError(
                "policy/consent commands require PostgreSQL major 18"
            )

    def _configure_transaction(
        self,
        connection: Any,
        request: PolicyConsentPostgresDatabaseRequest,
    ) -> None:
        connection.execute("SET LOCAL TIME ZONE 'UTC'")
        connection.execute(
            "SET LOCAL lock_timeout = '%dms'" % self.settings.lock_timeout_ms
        )
        connection.execute(
            "SET LOCAL statement_timeout = '%dms'"
            % self.settings.statement_timeout_ms
        )
        connection.execute(
            "SET LOCAL idle_in_transaction_session_timeout = '%dms'"
            % self.settings.idle_in_transaction_timeout_ms
        )
        identity = _active_identity_candidate(request.receipt)
        values = _transaction_context(request, identity)
        for name, value in values:
            configured = connection.execute(
                "SELECT pg_catalog.set_config(%s,%s,true)",
                (name, value),
            ).fetchone()
            if configured != (value,):
                raise PolicyConsentPostgresConfigurationError(
                    "policy/consent transaction context could not be installed"
                )
        for name, expected in values:
            actual = connection.execute(
                "SELECT current_setting(%s,true)",
                (name,),
            ).fetchone()
            if actual != (expected,):
                raise PolicyConsentPostgresConfigurationError(
                    "policy/consent transaction context readback failed"
                )

    def _execute_transaction(
        self,
        connection: Any,
        request: PolicyConsentPostgresDatabaseRequest,
    ) -> PolicyConsentPostgresDatabaseResult:
        ordinals: Dict[PolicyConsentPostgresWriteCheckpoint, int] = {}

        def before_write(checkpoint: PolicyConsentPostgresWriteCheckpoint) -> None:
            ordinal = ordinals.get(checkpoint, 0)
            self.fault_injector.before_write(checkpoint, ordinal)
            ordinals[checkpoint] = ordinal + 1

        key_policy = _load_and_validate_key_policy(connection, request.receipt)
        identity, existing_receipt = _find_retained_receipt(
            connection,
            request,
            key_policy,
        )
        _install_receipt_identity_context(connection, identity)
        if existing_receipt is not None:
            return self._replay_receipt(connection, request, existing_receipt)

        before_write(PolicyConsentPostgresWriteCheckpoint.COMMAND_RECEIPT_CLAIM)
        claimed = connection.execute(
            "INSERT INTO infra.command_receipts ("
            "id,principal_kind,principal_id,command_name,command_version,"
            "idempotency_key_digest,idempotency_key_digest_key_id,payload_hash,"
            "payload_hash_key_id,canonicalization_version,target_kind,target_id,"
            "http_method,canonical_path,if_match_version,status,"
            "response_schema_version,safe_response_body,reconstruction_metadata,"
            "response_http_status,response_schema_name,response_entity_tag,"
            "current_user_entity_tag,"
            "created_at,retain_until,completed_at) VALUES ("
            "%s,'USER',%s,%s,1,%s,%s,%s,%s,%s,'User',%s,'POST',%s,%s,"
            "'IN_PROGRESS',NULL,NULL,NULL,NULL,NULL,NULL,NULL,"
            "transaction_timestamp(),%s,NULL) "
            "ON CONFLICT DO NOTHING RETURNING id",
            (
                request.receipt.receipt_id,
                request.receipt.principal_id,
                request.operation.value,
                identity.digest,
                identity.key_id,
                _active_payload_candidate(request.receipt).digest,
                request.receipt.active_payload_key_id,
                request.receipt.active_canonicalization_version,
                request.scope.actor_user_id,
                _canonical_path(request.operation),
                request.expected_user_version,
                request.receipt.retain_until,
            ),
        ).fetchone()
        if claimed is None:
            raced = _load_exact_receipt(connection, request, identity)
            if raced is None:
                raise IamError("SERVICE_UNAVAILABLE")
            return self._replay_receipt(connection, request, raced)

        now = connection.execute("SELECT transaction_timestamp()").fetchone()[0]
        if request.receipt.retain_until <= now:
            raise IamError("SERVICE_UNAVAILABLE")
        plan = _load_locked_plan(connection, request)
        user_version = _positive_int(
            plan["principal"].get("user_version"),
            "POLICY_CONFIGURATION_UNAVAILABLE",
        )
        if user_version != request.expected_user_version:
            raise IamError("PRECONDITION_FAILED")
        bundle = _mapping(plan.get("bundle"), "POLICY_CONFIGURATION_UNAVAILABLE")
        if bundle.get("policy_bundle_id") != str(request.policy_bundle_id):
            raise IamError("POLICY_BUNDLE_CHANGED")
        if request.operation is PolicyConsentPostgresOperation.ACCEPT_CURRENT_POLICIES:
            return self._execute_accept(
                connection,
                request,
                plan,
                now,
                before_write,
            )
        return self._execute_grant(
            connection,
            request,
            plan,
            now,
            before_write,
        )

    def _replay_receipt(
        self,
        connection: Any,
        request: PolicyConsentPostgresDatabaseRequest,
        receipt: Mapping[str, Any],
    ) -> PolicyConsentPostgresDatabaseResult:
        payload = _payload_candidate_for_row(request.receipt, receipt)
        if payload is None:
            raise IamError("SERVICE_UNAVAILABLE")
        stored_payload = receipt.get("payload_hash")
        if not isinstance(stored_payload, bytes) or not hmac.compare_digest(
            stored_payload,
            payload.digest,
        ):
            raise IamError("IDEMPOTENCY_KEY_REUSED")
        expected_path = _canonical_path(request.operation)
        expected_http_status, expected_schema_name = _receipt_response_profile(
            request.operation
        )
        if (
            receipt.get("principal_id") != request.scope.actor_user_id
            or receipt.get("command_name") != request.operation.value
            or receipt.get("command_version") != 1
            or receipt.get("target_kind") != "User"
            or receipt.get("target_id") != request.scope.actor_user_id
            or receipt.get("http_method") != "POST"
            or receipt.get("canonical_path") != expected_path
            or receipt.get("if_match_version") != request.expected_user_version
            or receipt.get("status") != "COMPLETED"
            or receipt.get("response_schema_version") != 1
            or receipt.get("response_http_status") != expected_http_status
            or receipt.get("response_schema_name") != expected_schema_name
        ):
            raise IamError("SERVICE_UNAVAILABLE")
        now = connection.execute("SELECT transaction_timestamp()").fetchone()[0]
        retain_until = receipt.get("retain_until")
        if not isinstance(retain_until, datetime) or retain_until <= now:
            raise IamError("SERVICE_UNAVAILABLE")
        response = receipt.get("safe_response_body")
        if not isinstance(response, dict):
            raise IamError("SERVICE_UNAVAILABLE")
        principal = _load_locked_principal(connection, request)
        _require_response_binding(response, request)
        self._validate_response(response, request.operation)
        user_version = _positive_int(
            principal.get("user_version"),
            "SERVICE_UNAVAILABLE",
        )
        stored_response_etag = receipt.get("response_entity_tag")
        stored_user_etag = receipt.get("current_user_entity_tag")
        expected_user_etag = _entity_tag(user_version)
        if request.operation is PolicyConsentPostgresOperation.ACCEPT_CURRENT_POLICIES:
            expected_response_etag = expected_user_etag
        else:
            expected_response_etag = _entity_tag(
                _positive_int(response.get("aggregate_version"), "SERVICE_UNAVAILABLE")
            )
        if (
            stored_response_etag != expected_response_etag
            or stored_user_etag != expected_user_etag
        ):
            raise IamError("SERVICE_UNAVAILABLE")
        return PolicyConsentPostgresDatabaseResult(
            operation=request.operation,
            replayed=True,
            safe_response=response,
            response_entity_tag=stored_response_etag,
            current_user_entity_tag=stored_user_etag,
        )

    def _execute_accept(
        self,
        connection: Any,
        request: PolicyConsentPostgresDatabaseRequest,
        plan: Mapping[str, Any],
        now: datetime,
        before_write: Any,
    ) -> PolicyConsentPostgresDatabaseResult:
        principal = _mapping(plan.get("principal"), "POLICY_CONFIGURATION_UNAVAILABLE")
        authority = _mapping(plan.get("authority"), "POLICY_CONFIGURATION_UNAVAILABLE")
        bundle = _mapping(plan.get("bundle"), "POLICY_CONFIGURATION_UNAVAILABLE")
        documents = _plan_documents(plan)
        required_documents = tuple(
            item for item in documents if item["required"] is True
        )
        choices = {item.document_id: item for item in request.policy_acceptances}
        if len(choices) != len(request.policy_acceptances):
            raise IamError("INVALID_REQUEST")
        if set(choices) != {item["document_id"] for item in required_documents}:
            raise IamError("POLICY_ACCEPTANCE_REQUIRED")
        for document in required_documents:
            choice = choices[document["document_id"]]
            if not hmac.compare_digest(
                choice.content_sha256,
                document["content_sha256"],
            ):
                raise IamError("POLICY_BUNDLE_CHANGED")

        existing_by_document: Dict[UUID, Mapping[str, Any]] = {}
        for raw in _sequence(plan.get("acceptances"), "POLICY_CONFIGURATION_UNAVAILABLE"):
            acceptance = _mapping(raw, "POLICY_CONFIGURATION_UNAVAILABLE")
            document_id = _uuid(acceptance.get("document_id"), "POLICY_CONFIGURATION_UNAVAILABLE")
            if document_id in existing_by_document:
                raise IamError("POLICY_CONFIGURATION_UNAVAILABLE")
            _validate_existing_acceptance(acceptance, document_id)
            existing_by_document[document_id] = acceptance

        missing = tuple(
            item
            for item in required_documents
            if item["document_id"] not in existing_by_document
        )
        if len(request.generated_ids.policy_acceptance_ids) < len(missing):
            raise IamError("SERVICE_UNAVAILABLE")
        events: List[_PolicyConsentOutboxRecord] = []
        for index, document in enumerate(missing):
            acceptance_id = request.generated_ids.policy_acceptance_ids[index]
            before_write(
                PolicyConsentPostgresWriteCheckpoint.POLICY_ACCEPTANCE_INSERT
            )
            connection.execute(
                "INSERT INTO iam.policy_acceptances ("
                "id,user_id,document_id,content_sha256,bundle_id,accepted_at,"
                "session_id,auth_transaction_id,auth_time,acr_code,amr_codes,"
                "source_action,command_id,correlation_id,aggregate_version,created_at"
                ") VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'POLICY_ACCEPT',"
                "%s,%s,1,%s)",
                (
                    acceptance_id,
                    request.scope.actor_user_id,
                    document["document_id"],
                    document["content_sha256"],
                    request.policy_bundle_id,
                    now,
                    request.scope.session_id,
                    request.scope.auth_transaction_id,
                    _utc(principal.get("auth_time"), "POLICY_CONFIGURATION_UNAVAILABLE"),
                    _nonempty_text(principal.get("acr_code"), "POLICY_CONFIGURATION_UNAVAILABLE"),
                    list(_text_tuple(principal.get("amr_codes"), "POLICY_CONFIGURATION_UNAVAILABLE")),
                    request.scope.command_id,
                    request.scope.correlation_id,
                    now,
                ),
            )
            events.append(
                _PolicyConsentOutboxRecord(
                    event_type="PolicyAccepted",
                    aggregate_type="PolicyAcceptance",
                    aggregate_id=acceptance_id,
                    aggregate_version=1,
                    payload={
                        "policy_acceptance_id": str(acceptance_id),
                        "user_id": str(request.scope.actor_user_id),
                        "policy_bundle_id": str(request.policy_bundle_id),
                        "policy_document_id": str(document["document_id"]),
                        "policy_document_sha256": document["content_sha256"].hex(),
                        "legal_effect": document["legal_effect"],
                    },
                )
            )

        before_version = _positive_int(
            principal.get("user_version"),
            "POLICY_CONFIGURATION_UNAVAILABLE",
        )
        after_version = before_version
        if missing:
            before_write(PolicyConsentPostgresWriteCheckpoint.USER_VERSION_CAS)
            updated = connection.execute(
                "UPDATE iam.users SET aggregate_version=aggregate_version+1,"
                "updated_at=%s WHERE id=%s AND status='ACTIVE' "
                "AND aggregate_version=%s RETURNING aggregate_version",
                (now, request.scope.actor_user_id, before_version),
            ).fetchone()
            if updated is None:
                raise IamError("PRECONDITION_FAILED")
            after_version = updated[0]
            events.append(
                _PolicyConsentOutboxRecord(
                    event_type="PolicyRequirementsSatisfied",
                    aggregate_type="User",
                    aggregate_id=request.scope.actor_user_id,
                    aggregate_version=after_version,
                    payload={
                        "user_id": str(request.scope.actor_user_id),
                        "policy_bundle_id": str(request.policy_bundle_id),
                    },
                )
            )
        connection.execute(
            "SET CONSTRAINTS iam.trg_evidence_matches_session_auth IMMEDIATE"
        )
        response = {
            "selector_digest": bundle["selector_digest"],
            "purpose": authority["purpose"],
            "role": authority["role"],
            "scope_type": authority["scope_type"],
            "scope_id": authority.get("scope_id"),
            "satisfied": True,
            "required_policy_bundle_id": bundle["policy_bundle_id"],
            "missing_document_ids": [],
        }
        self._validate_response(response, request.operation)
        return self._persist_completion(
            connection=connection,
            request=request,
            principal=principal,
            authority=authority,
            response=response,
            before_user_version=before_version,
            after_user_version=after_version,
            changed=bool(missing),
            events=events,
            now=now,
            before_write=before_write,
            response_entity_tag=_entity_tag(after_version),
        )

    def _execute_grant(
        self,
        connection: Any,
        request: PolicyConsentPostgresDatabaseRequest,
        plan: Mapping[str, Any],
        now: datetime,
        before_write: Any,
    ) -> PolicyConsentPostgresDatabaseResult:
        principal = _mapping(plan.get("principal"), "POLICY_CONFIGURATION_UNAVAILABLE")
        authority = _mapping(plan.get("authority"), "POLICY_CONFIGURATION_UNAVAILABLE")
        documents = _plan_documents(plan)
        required_documents = tuple(
            item for item in documents if item["required"] is True
        )
        accepted_document_ids = set()
        for raw in _sequence(plan.get("acceptances"), "POLICY_CONFIGURATION_UNAVAILABLE"):
            acceptance = _mapping(raw, "POLICY_CONFIGURATION_UNAVAILABLE")
            document_id = _uuid(acceptance.get("document_id"), "POLICY_CONFIGURATION_UNAVAILABLE")
            _validate_existing_acceptance(acceptance, document_id)
            accepted_document_ids.add(document_id)
        if accepted_document_ids != {
            item["document_id"] for item in required_documents
        }:
            raise IamError("POLICY_ACCEPTANCE_REQUIRED")
        choice = request.consent_choice
        if choice is None:
            raise IamError("INVALID_REQUEST")
        offer = _select_and_validate_offer(plan, request, choice)
        active_grants = tuple(
            _mapping(item, "POLICY_CONFIGURATION_UNAVAILABLE")
            for item in _sequence(
                plan.get("active_grants"),
                "POLICY_CONFIGURATION_UNAVAILABLE",
            )
        )
        if len(active_grants) > 1:
            raise IamError("POLICY_CONFIGURATION_UNAVAILABLE")
        live_grant: Optional[Mapping[str, Any]] = None
        if active_grants:
            candidate = active_grants[0]
            expires_at = _utc(
                candidate.get("expires_at"),
                "POLICY_CONFIGURATION_UNAVAILABLE",
            )
            if expires_at <= now:
                grant_id = _uuid(
                    candidate.get("consent_grant_id"),
                    "POLICY_CONFIGURATION_UNAVAILABLE",
                )
                grant_version = _positive_int(
                    candidate.get("aggregate_version"),
                    "POLICY_CONFIGURATION_UNAVAILABLE",
                )
                before_write(
                    PolicyConsentPostgresWriteCheckpoint.CONSENT_GRANT_EXPIRE
                )
                expired = connection.execute(
                    "UPDATE iam.consent_grants SET status='EXPIRED',withdrawn_at=NULL,"
                    "aggregate_version=aggregate_version+1,updated_at=%s "
                    "WHERE id=%s AND user_id=%s AND status='ACTIVE' "
                    "AND aggregate_version=%s AND expires_at=%s "
                    "AND expires_at <= transaction_timestamp() RETURNING id",
                    (
                        now,
                        grant_id,
                        request.scope.actor_user_id,
                        grant_version,
                        expires_at,
                    ),
                ).fetchone()
                if expired != (grant_id,):
                    raise IamError("INVALID_STATE_TRANSITION")
            else:
                live_grant = candidate

        events: List[_PolicyConsentOutboxRecord] = []
        changed = live_grant is None
        if live_grant is not None:
            _validate_live_grant(live_grant, offer, principal, now)
            grant = live_grant
        else:
            grant_id = request.generated_ids.consent_grant_id
            if grant_id is None:
                raise IamError("SERVICE_UNAVAILABLE")
            expires_at = min(
                now + timedelta(days=offer["expiry_days"]),
                offer["not_after"],
            )
            before_write(PolicyConsentPostgresWriteCheckpoint.CONSENT_GRANT_INSERT)
            inserted = connection.execute(
                "INSERT INTO iam.consent_grants ("
                "id,user_id,consent_offer_id,consent_offer_version,policy_bundle_id,"
                "purpose,scope_type,scope_id,recipient_ref,recipient_label,document_id,"
                "document_content_sha256,granted_at,expires_at,session_id,"
                "auth_transaction_id,auth_time,acr_code,amr_codes,command_id,"
                "correlation_id,status,withdrawn_at,aggregate_version,created_at,updated_at"
                ") VALUES (%s,%s,%s,%s,%s,%s,%s,NULL,%s,%s,%s,%s,%s,%s,%s,%s,%s,"
                "%s,%s,%s,%s,'ACTIVE',NULL,1,%s,%s) "
                "ON CONFLICT (user_id,purpose,scope_type,scope_id) "
                "WHERE status='ACTIVE' DO NOTHING RETURNING id",
                (
                    grant_id,
                    request.scope.actor_user_id,
                    offer["consent_offer_id"],
                    offer["offer_version"],
                    request.policy_bundle_id,
                    offer["purpose"],
                    offer["scope_type"],
                    offer["recipient_ref"],
                    offer["recipient_label"],
                    offer["document_id"],
                    offer["document_content_sha256"],
                    now,
                    expires_at,
                    request.scope.session_id,
                    request.scope.auth_transaction_id,
                    _utc(principal.get("auth_time"), "POLICY_CONFIGURATION_UNAVAILABLE"),
                    _nonempty_text(principal.get("acr_code"), "POLICY_CONFIGURATION_UNAVAILABLE"),
                    list(_text_tuple(principal.get("amr_codes"), "POLICY_CONFIGURATION_UNAVAILABLE")),
                    request.scope.command_id,
                    request.scope.correlation_id,
                    now,
                    now,
                ),
            ).fetchone()
            if inserted != (grant_id,):
                raise IamError("INVALID_STATE_TRANSITION")
            for position, category in enumerate(offer["categories"], start=1):
                before_write(
                    PolicyConsentPostgresWriteCheckpoint.CONSENT_GRANT_CATEGORY_INSERT
                )
                connection.execute(
                    "INSERT INTO iam.consent_grant_data_categories "
                    "(grant_id,category,position) VALUES (%s,%s,%s)",
                    (grant_id, category, position),
                )
            grant = {
                "consent_grant_id": str(grant_id),
                "consent_offer_id": str(offer["consent_offer_id"]),
                "purpose": offer["purpose"],
                "scope_type": offer["scope_type"],
                "scope_id": None,
                "categories": list(offer["categories"]),
                "recipient_label": offer["recipient_label"],
                "document_id": str(offer["document_id"]),
                "document_content_sha256": offer["document_content_sha256"].hex(),
                "granted_at": now,
                "expires_at": expires_at,
                "status": "ACTIVE",
                "aggregate_version": 1,
            }
            events.append(
                _PolicyConsentOutboxRecord(
                    event_type="ConsentGranted",
                    aggregate_type="ConsentGrant",
                    aggregate_id=grant_id,
                    aggregate_version=1,
                    payload={
                        "consent_grant_id": str(grant_id),
                        "user_id": str(request.scope.actor_user_id),
                        "status": "ACTIVE",
                        "granted_at": _timestamp(now),
                        "derived_authorization": {
                            "consent_offer_id": str(offer["consent_offer_id"]),
                            "consent_offer_version": offer["offer_version"],
                            "policy_bundle_id": str(request.policy_bundle_id),
                            "purpose": offer["purpose"],
                            "scope_type": offer["scope_type"],
                            "scope_id": None,
                            "data_categories": list(offer["categories"]),
                            "supporting_policy_document_id": str(offer["document_id"]),
                            "supporting_document_sha256": offer[
                                "document_content_sha256"
                            ].hex(),
                            "expires_at": _timestamp(expires_at),
                        },
                    },
                )
            )

        connection.execute(
            "SET CONSTRAINTS iam.trg_evidence_matches_session_auth,"
            "iam.trg_consent_grant_matches_offer IMMEDIATE"
        )
        before_version = _positive_int(
            principal.get("user_version"),
            "POLICY_CONFIGURATION_UNAVAILABLE",
        )
        after_version = before_version
        if changed:
            before_write(PolicyConsentPostgresWriteCheckpoint.USER_VERSION_CAS)
            updated = connection.execute(
                "UPDATE iam.users SET aggregate_version=aggregate_version+1,"
                "updated_at=%s WHERE id=%s AND status='ACTIVE' "
                "AND aggregate_version=%s RETURNING aggregate_version",
                (now, request.scope.actor_user_id, before_version),
            ).fetchone()
            if updated is None:
                raise IamError("PRECONDITION_FAILED")
            after_version = updated[0]
        response = _grant_response(grant)
        self._validate_response(response, request.operation)
        return self._persist_completion(
            connection=connection,
            request=request,
            principal=principal,
            authority=authority,
            response=response,
            before_user_version=before_version,
            after_user_version=after_version,
            changed=changed,
            events=events,
            now=now,
            before_write=before_write,
            response_entity_tag=_entity_tag(
                _positive_int(response["aggregate_version"], "SERVICE_UNAVAILABLE")
            ),
        )

    def _persist_completion(
        self,
        *,
        connection: Any,
        request: PolicyConsentPostgresDatabaseRequest,
        principal: Mapping[str, Any],
        authority: Mapping[str, Any],
        response: Mapping[str, Any],
        before_user_version: int,
        after_user_version: int,
        changed: bool,
        events: Sequence["_PolicyConsentOutboxRecord"],
        now: datetime,
        before_write: Any,
        response_entity_tag: str,
    ) -> PolicyConsentPostgresDatabaseResult:
        before_write(PolicyConsentPostgresWriteCheckpoint.AUDIT_EVENT_INSERT)
        connection.execute(
            "INSERT INTO audit.audit_events ("
            "event_id,occurred_at,actor_kind,actor_id,original_actor_id,action_code,"
            "target_kind,target_id,organization_id,before_status,after_status,"
            "before_version,after_version,role_code,purpose_code,reason_code,"
            "auth_strength_code,result_code,command_id,correlation_id,causation_id,"
            "trace_id,safe_attributes) VALUES ("
            "%s,%s,'USER',%s,NULL,%s,'User',%s,%s,NULL,NULL,%s,%s,%s,%s,NULL,%s,%s,"
            "%s,%s,%s,%s,%s)",
            (
                request.generated_ids.audit_event_id,
                now,
                request.scope.actor_user_id,
                (
                    "POLICY_ACCEPT"
                    if request.operation
                    is PolicyConsentPostgresOperation.ACCEPT_CURRENT_POLICIES
                    else "CONSENT_GRANT"
                ),
                request.scope.actor_user_id,
                _optional_uuid(authority.get("organization_id"), "POLICY_CONFIGURATION_UNAVAILABLE"),
                before_user_version,
                after_user_version,
                authority["role"],
                authority["purpose"],
                principal["acr_code"],
                "CREATED" if changed else "REUSED",
                request.scope.command_id,
                request.scope.correlation_id,
                request.scope.causation_id,
                request.scope.trace_id,
                Jsonb({}),
            ),
        )
        if len(request.generated_ids.outbox_event_ids) < len(events):
            raise IamError("SERVICE_UNAVAILABLE")
        for index, event in enumerate(events):
            event_id = request.generated_ids.outbox_event_ids[index]
            envelope = _event_envelope(
                request=request,
                event_id=event_id,
                event=event,
                organization_id=_optional_uuid(
                    authority.get("organization_id"),
                    "POLICY_CONFIGURATION_UNAVAILABLE",
                ),
                occurred_at=now,
            )
            self._validate_event(envelope)
            before_write(PolicyConsentPostgresWriteCheckpoint.OUTBOX_EVENT_INSERT)
            connection.execute(
                "INSERT INTO infra.outbox_events ("
                "event_id,event_type,schema_version,occurred_at,aggregate_type,"
                "aggregate_id,aggregate_version,actor_kind,actor_id,original_actor_id,"
                "correlation_id,causation_id,trace_id,organization_id,payload,"
                "delivery_status,attempt_count,available_at,lease_owner,lease_until,"
                "published_at,last_error_code,created_at) VALUES ("
                "%s,%s,1,%s,%s,%s,%s,'USER',%s,NULL,%s,%s,%s,%s,%s,"
                "'PENDING',0,%s,NULL,NULL,NULL,NULL,%s)",
                (
                    event_id,
                    event.event_type,
                    now,
                    event.aggregate_type,
                    event.aggregate_id,
                    event.aggregate_version,
                    request.scope.actor_user_id,
                    request.scope.correlation_id,
                    request.scope.causation_id,
                    request.scope.trace_id,
                    _optional_uuid(
                        authority.get("organization_id"),
                        "POLICY_CONFIGURATION_UNAVAILABLE",
                    ),
                    Jsonb(event.payload),
                    now,
                    now,
                ),
            )
        before_write(PolicyConsentPostgresWriteCheckpoint.COMMAND_RECEIPT_COMPLETE)
        response_http_status, response_schema_name = _receipt_response_profile(
            request.operation
        )
        current_user_entity_tag = _entity_tag(after_user_version)
        completed = connection.execute(
            "UPDATE infra.command_receipts SET status='COMPLETED',"
            "response_schema_version=1,safe_response_body=%s,"
            "reconstruction_metadata=NULL,response_http_status=%s,"
            "response_schema_name=%s,response_entity_tag=%s,"
            "current_user_entity_tag=%s,completed_at=%s WHERE id=%s "
            "AND status='IN_PROGRESS' RETURNING id",
            (
                Jsonb(dict(response)),
                response_http_status,
                response_schema_name,
                response_entity_tag,
                current_user_entity_tag,
                now,
                request.receipt.receipt_id,
            ),
        ).fetchone()
        if completed != (request.receipt.receipt_id,):
            raise IamError("SERVICE_UNAVAILABLE")
        return PolicyConsentPostgresDatabaseResult(
            operation=request.operation,
            replayed=False,
            safe_response=response,
            response_entity_tag=response_entity_tag,
            current_user_entity_tag=current_user_entity_tag,
        )

    def _validate_event(self, envelope: Mapping[str, Any]) -> None:
        try:
            self.event_validator.validate(envelope)
        except (AssertionError, TypeError, ValueError) as error:
            raise IamError("SERVICE_UNAVAILABLE") from error

    def _validate_response(
        self,
        response: Mapping[str, Any],
        operation: PolicyConsentPostgresOperation,
    ) -> None:
        schema = (
            "PolicyRequirementStatusDto"
            if operation
            is PolicyConsentPostgresOperation.ACCEPT_CURRENT_POLICIES
            else "ConsentGrantDto"
        )
        try:
            self.response_validator.validate(response, schema)
        except (AssertionError, TypeError, ValueError) as error:
            raise IamError("SERVICE_UNAVAILABLE") from error

    def _release_or_discard(self, connection: Any) -> bool:
        try:
            if not _connection_is_idle(connection):
                self.connections.discard(connection)
                return True
            connection.execute("RESET ROLE")
            connection.execute("RESET ALL")
            connection.execute("DISCARD TEMP")
            identity = connection.execute(
                "SELECT current_user,session_user,"
                "current_setting('app.actor_user_id',true)"
            ).fetchone()
            if identity not in (
                (self.settings.runtime_role, self.settings.runtime_role, None),
                (self.settings.runtime_role, self.settings.runtime_role, ""),
            ):
                self.connections.discard(connection)
                return True
        except BaseException:
            self.connections.discard(connection)
            return True
        self.connections.release(connection)
        return True


@dataclass(frozen=True)
class _PolicyConsentOutboxRecord:
    event_type: str
    aggregate_type: str
    aggregate_id: UUID
    aggregate_version: int
    payload: Mapping[str, Any] = field(repr=False)


def _active_identity_candidate(
    material: PolicyConsentReceiptMaterial,
) -> PolicyConsentReceiptIdentityDigest:
    candidates = tuple(
        item
        for item in material.identity_candidates
        if item.key_id == material.active_identity_key_id
    )
    if len(candidates) != 1:
        raise PolicyConsentPostgresConfigurationError(
            "active receipt identity candidate is unavailable"
        )
    return candidates[0]


def _active_payload_candidate(
    material: PolicyConsentReceiptMaterial,
) -> PolicyConsentReceiptPayloadDigest:
    candidates = tuple(
        item
        for item in material.payload_candidates
        if item.key_id == material.active_payload_key_id
        and item.canonicalization_version
        == material.active_canonicalization_version
    )
    if len(candidates) != 1:
        raise PolicyConsentPostgresConfigurationError(
            "active receipt payload candidate is unavailable"
        )
    return candidates[0]


def _transaction_context(
    request: PolicyConsentPostgresDatabaseRequest,
    identity: PolicyConsentReceiptIdentityDigest,
) -> Tuple[Tuple[str, str], ...]:
    return (
        ("app.scope_kind", "SELF"),
        (
            "app.operation",
            (
                "ACCEPT_CURRENT_POLICIES"
                if request.operation
                is PolicyConsentPostgresOperation.ACCEPT_CURRENT_POLICIES
                else "GRANT_CONSENT"
            ),
        ),
        ("app.actor_user_id", str(request.scope.actor_user_id)),
        ("app.target_user_id", str(request.scope.actor_user_id)),
        ("app.session_id", str(request.scope.session_id)),
        ("app.session_family_id", str(request.scope.session_family_id)),
        ("app.auth_transaction_id", str(request.scope.auth_transaction_id)),
        ("app.command_id", str(request.scope.command_id)),
        ("app.command_name", request.operation.value),
        ("app.command_version", "1"),
        ("app.idempotency_key_digest_key_id", identity.key_id),
        ("app.idempotency_key_digest", identity.digest.hex()),
        ("app.policy_selector_digest", request.scope.selector_digest.hex()),
        ("app.policy_bundle_id", str(request.policy_bundle_id)),
        ("app.authority_scope_type", request.scope.authority_scope_type),
        (
            "app.authority_scope_id",
            (
                str(request.scope.authority_scope_id)
                if request.scope.authority_scope_id is not None
                else ""
            ),
        ),
        (
            "app.organization_id",
            (
                str(request.scope.organization_id)
                if request.scope.organization_id is not None
                else ""
            ),
        ),
    )


def _load_and_validate_key_policy(
    connection: Any,
    material: PolicyConsentReceiptMaterial,
) -> Mapping[str, Any]:
    rows = connection.execute(
        "SELECT active_idempotency_key_id,active_payload_hash_key_id,"
        "active_canonicalization_version,retained_idempotency_key_ids,"
        "retained_payload_hash_key_ids,retained_canonicalization_versions "
        "FROM infra.iam_receipt_key_policy WHERE singleton_key"
    ).fetchall()
    if len(rows) != 1:
        raise IamError("SERVICE_UNAVAILABLE")
    row = rows[0]
    retained_identity = tuple(row[3]) if isinstance(row[3], list) else ()
    retained_payload = tuple(row[4]) if isinstance(row[4], list) else ()
    retained_canonicalizers = tuple(row[5]) if isinstance(row[5], list) else ()
    if (
        row[0] != material.active_identity_key_id
        or row[1] != material.active_payload_key_id
        or row[2] != material.active_canonicalization_version
        or set(retained_identity)
        != {item.key_id for item in material.identity_candidates}
        or set(retained_payload)
        != {item.key_id for item in material.payload_candidates}
        or not all(
            item.canonicalization_version in retained_canonicalizers
            for item in material.payload_candidates
        )
        or material.active_canonicalization_version not in retained_canonicalizers
    ):
        raise IamError("SERVICE_UNAVAILABLE")
    return {
        "retained_identity": retained_identity,
        "retained_payload": retained_payload,
        "retained_canonicalizers": retained_canonicalizers,
    }


def _install_receipt_identity_context(
    connection: Any,
    identity: PolicyConsentReceiptIdentityDigest,
) -> None:
    for name, value in (
        ("app.idempotency_key_digest_key_id", identity.key_id),
        ("app.idempotency_key_digest", identity.digest.hex()),
    ):
        configured = connection.execute(
            "SELECT pg_catalog.set_config(%s,%s,true)",
            (name, value),
        ).fetchone()
        if configured != (value,):
            raise PolicyConsentPostgresConfigurationError(
                "receipt identity context could not be installed"
            )


def _find_retained_receipt(
    connection: Any,
    request: PolicyConsentPostgresDatabaseRequest,
    key_policy: Mapping[str, Any],
) -> Tuple[PolicyConsentReceiptIdentityDigest, Optional[Mapping[str, Any]]]:
    retained_order = tuple(key_policy["retained_identity"])
    by_key = {item.key_id: item for item in request.receipt.identity_candidates}
    found: List[Tuple[PolicyConsentReceiptIdentityDigest, Mapping[str, Any]]] = []
    for key_id in retained_order:
        identity = by_key.get(key_id)
        if identity is None:
            raise IamError("SERVICE_UNAVAILABLE")
        _install_receipt_identity_context(connection, identity)
        row = _load_exact_receipt(connection, request, identity)
        if row is not None:
            found.append((identity, row))
    if len(found) > 1:
        raise IamError("SERVICE_UNAVAILABLE")
    if found:
        return found[0]
    active = _active_identity_candidate(request.receipt)
    return active, None


def _load_exact_receipt(
    connection: Any,
    request: PolicyConsentPostgresDatabaseRequest,
    identity: PolicyConsentReceiptIdentityDigest,
) -> Optional[Mapping[str, Any]]:
    rows = connection.execute(
        "SELECT id,principal_id,command_name,command_version,payload_hash,"
        "payload_hash_key_id,canonicalization_version,target_kind,target_id,"
        "http_method,canonical_path,if_match_version,status,response_schema_version,"
        "safe_response_body,response_http_status,response_schema_name,"
        "response_entity_tag,current_user_entity_tag,retain_until "
        "FROM infra.command_receipts "
        "WHERE principal_kind='USER' AND principal_id=%s AND command_name=%s "
        "AND command_version=1 AND idempotency_key_digest_key_id=%s "
        "AND idempotency_key_digest=%s ORDER BY id FOR UPDATE",
        (
            request.scope.actor_user_id,
            request.operation.value,
            identity.key_id,
            identity.digest,
        ),
    ).fetchall()
    if not rows:
        return None
    if len(rows) != 1:
        raise IamError("SERVICE_UNAVAILABLE")
    row = rows[0]
    return {
        "id": row[0],
        "principal_id": row[1],
        "command_name": row[2],
        "command_version": row[3],
        "payload_hash": bytes(row[4]),
        "payload_hash_key_id": row[5],
        "canonicalization_version": row[6],
        "target_kind": row[7],
        "target_id": row[8],
        "http_method": row[9],
        "canonical_path": row[10],
        "if_match_version": row[11],
        "status": row[12],
        "response_schema_version": row[13],
        "safe_response_body": row[14],
        "response_http_status": row[15],
        "response_schema_name": row[16],
        "response_entity_tag": row[17],
        "current_user_entity_tag": row[18],
        "retain_until": row[19],
    }


def _payload_candidate_for_row(
    material: PolicyConsentReceiptMaterial,
    row: Mapping[str, Any],
) -> Optional[PolicyConsentReceiptPayloadDigest]:
    candidates = tuple(
        item
        for item in material.payload_candidates
        if item.key_id == row.get("payload_hash_key_id")
        and item.canonicalization_version == row.get("canonicalization_version")
    )
    return candidates[0] if len(candidates) == 1 else None


def _load_locked_principal(
    connection: Any,
    request: PolicyConsentPostgresDatabaseRequest,
) -> Mapping[str, Any]:
    try:
        row = connection.execute(
            "SELECT iam.lock_policy_consent_principal_v1(%s,%s,%s,%s)",
            (
                request.scope.actor_user_id,
                request.scope.session_id,
                request.scope.session_family_id,
                request.scope.auth_transaction_id,
            ),
        ).fetchone()
    except DatabaseError as error:
        mapped = _map_lock_error(error)
        if mapped is not None:
            raise mapped from error
        raise
    if row is None or len(row) != 1:
        raise IamError("SERVICE_UNAVAILABLE")
    return _mapping(row[0], "SERVICE_UNAVAILABLE")


def _load_locked_plan(
    connection: Any,
    request: PolicyConsentPostgresDatabaseRequest,
) -> Mapping[str, Any]:
    operation = (
        "ACCEPT_CURRENT_POLICIES"
        if request.operation is PolicyConsentPostgresOperation.ACCEPT_CURRENT_POLICIES
        else "GRANT_CONSENT"
    )
    try:
        row = connection.execute(
            "SELECT iam.lock_policy_consent_self_v1(%s,%s,%s,%s,%s,%s,%s)",
            (
                request.scope.actor_user_id,
                request.scope.session_id,
                request.scope.selector_digest,
                request.scope.authority_scope_type,
                request.scope.authority_scope_id,
                request.policy_bundle_id,
                operation,
            ),
        ).fetchone()
    except DatabaseError as error:
        mapped = _map_lock_error(error)
        if mapped is not None:
            raise mapped from error
        raise
    if row is None or len(row) != 1:
        raise IamError("POLICY_CONFIGURATION_UNAVAILABLE")
    plan = _mapping(row[0], "POLICY_CONFIGURATION_UNAVAILABLE")
    required = {
        "principal",
        "authority",
        "bundle",
        "documents",
        "offers",
        "acceptances",
        "active_grants",
    }
    if set(plan) != required:
        raise IamError("POLICY_CONFIGURATION_UNAVAILABLE")
    return plan


def _map_lock_error(error: DatabaseError) -> Optional[IamError]:
    constraint = getattr(error.diag, "constraint_name", None)
    if constraint == "ck_policy_consent_principal_active":
        return IamError("AUTHENTICATION_REQUIRED")
    if constraint == "ck_policy_consent_authority":
        return IamError("NOT_FOUND")
    if constraint in (
        "ck_policy_consent_selector",
        "ck_policy_consent_bundle",
    ):
        return IamError("POLICY_CONFIGURATION_UNAVAILABLE")
    if constraint in (
        "ck_policy_consent_principal_scope",
        "ck_policy_consent_graph_scope",
    ):
        return IamError("SERVICE_UNAVAILABLE")
    return None


def _plan_documents(plan: Mapping[str, Any]) -> Tuple[Mapping[str, Any], ...]:
    documents = []
    seen_ids = set()
    seen_positions = set()
    for raw in _sequence(plan.get("documents"), "POLICY_CONFIGURATION_UNAVAILABLE"):
        item = _mapping(raw, "POLICY_CONFIGURATION_UNAVAILABLE")
        document_id = _uuid(item.get("document_id"), "POLICY_CONFIGURATION_UNAVAILABLE")
        digest = _hex_digest(item.get("content_sha256"), "POLICY_CONFIGURATION_UNAVAILABLE")
        position = _positive_int(item.get("position"), "POLICY_CONFIGURATION_UNAVAILABLE")
        required = item.get("required")
        status = item.get("status")
        kind = item.get("kind")
        legal_effect = item.get("legal_effect")
        if (
            document_id in seen_ids
            or position in seen_positions
            or type(required) is not bool
            or status != "ACTIVE"
            or not isinstance(kind, str)
            or not isinstance(legal_effect, str)
            or (
                required
                and legal_effect
                not in {"NOTICE_ACKNOWLEDGEMENT", "CONTRACT_ACCEPTANCE"}
            )
        ):
            raise IamError("POLICY_CONFIGURATION_UNAVAILABLE")
        seen_ids.add(document_id)
        seen_positions.add(position)
        documents.append(
            {
                "document_id": document_id,
                "content_sha256": digest,
                "position": position,
                "required": required,
                "kind": kind,
                "legal_effect": legal_effect,
            }
        )
    if not documents or not any(item["required"] for item in documents):
        raise IamError("POLICY_CONFIGURATION_UNAVAILABLE")
    return tuple(sorted(documents, key=lambda item: (item["position"], item["document_id"].bytes)))


def _validate_existing_acceptance(
    acceptance: Mapping[str, Any],
    document_id: UUID,
) -> None:
    if (
        acceptance.get("source_valid") is not True
        or _uuid(acceptance.get("document_id"), "POLICY_CONFIGURATION_UNAVAILABLE")
        != document_id
        or len(_hex_digest(acceptance.get("content_sha256"), "POLICY_CONFIGURATION_UNAVAILABLE"))
        != 32
        or _uuid(acceptance.get("acceptance_id"), "POLICY_CONFIGURATION_UNAVAILABLE").int
        == 0
        or _uuid(acceptance.get("bundle_id"), "POLICY_CONFIGURATION_UNAVAILABLE").int
        == 0
        or _uuid(acceptance.get("session_id"), "POLICY_CONFIGURATION_UNAVAILABLE").int
        == 0
        or _uuid(acceptance.get("auth_transaction_id"), "POLICY_CONFIGURATION_UNAVAILABLE").int
        == 0
        or _uuid(acceptance.get("command_id"), "POLICY_CONFIGURATION_UNAVAILABLE").int
        == 0
        or _positive_int(acceptance.get("aggregate_version"), "POLICY_CONFIGURATION_UNAVAILABLE")
        < 1
    ):
        raise IamError("POLICY_CONFIGURATION_UNAVAILABLE")
    accepted_at = _utc(acceptance.get("accepted_at"), "POLICY_CONFIGURATION_UNAVAILABLE")
    auth_time = _utc(acceptance.get("auth_time"), "POLICY_CONFIGURATION_UNAVAILABLE")
    if auth_time > accepted_at:
        raise IamError("POLICY_CONFIGURATION_UNAVAILABLE")
    _nonempty_text(acceptance.get("acr_code"), "POLICY_CONFIGURATION_UNAVAILABLE")
    _text_tuple(acceptance.get("amr_codes"), "POLICY_CONFIGURATION_UNAVAILABLE")
    _nonempty_text(acceptance.get("source_action"), "POLICY_CONFIGURATION_UNAVAILABLE")


def _select_and_validate_offer(
    plan: Mapping[str, Any],
    request: PolicyConsentPostgresDatabaseRequest,
    choice: PolicyConsentPostgresOfferChoice,
) -> Mapping[str, Any]:
    documents = {item["document_id"]: item for item in _plan_documents(plan)}
    matches = []
    for raw in _sequence(plan.get("offers"), "POLICY_CONFIGURATION_UNAVAILABLE"):
        offer = _mapping(raw, "POLICY_CONFIGURATION_UNAVAILABLE")
        if offer.get("consent_offer_id") == str(choice.consent_offer_id):
            matches.append(offer)
    if len(matches) != 1:
        raise IamError("CONSENT_CHOICE_INVALID")
    raw = matches[0]
    offer_id = _uuid(raw.get("consent_offer_id"), "POLICY_CONFIGURATION_UNAVAILABLE")
    document_id = _uuid(raw.get("document_id"), "POLICY_CONFIGURATION_UNAVAILABLE")
    document_hash = _hex_digest(
        raw.get("document_content_sha256"),
        "POLICY_CONFIGURATION_UNAVAILABLE",
    )
    canonical_hash = _hex_digest(
        raw.get("canonical_offer_sha256"),
        "POLICY_CONFIGURATION_UNAVAILABLE",
    )
    categories = _text_tuple(raw.get("categories"), "POLICY_CONFIGURATION_UNAVAILABLE")
    not_after = _utc(raw.get("not_after"), "POLICY_CONFIGURATION_UNAVAILABLE")
    offer_version = _positive_int(raw.get("offer_version"), "POLICY_CONFIGURATION_UNAVAILABLE")
    expiry_days = _positive_int(raw.get("expiry_days"), "POLICY_CONFIGURATION_UNAVAILABLE")
    supporting = documents.get(document_id)
    if (
        offer_id != choice.consent_offer_id
        or document_id != choice.document_id
        or not hmac.compare_digest(document_hash, choice.content_sha256)
        or raw.get("purpose") != "PILOT_RESEARCH"
        or raw.get("scope_type") != "PLATFORM_PARTICIPATION"
        or raw.get("scope_derivation") != "PLATFORM_PARTICIPATION_NULL_SCOPE"
        or raw.get("expiry_rule")
        != "EARLIER_OF_GRANTED_AT_PLUS_365_DAYS_OR_NOT_AFTER"
        or expiry_days != 365
        or raw.get("optional") is not True
        or supporting is None
        or supporting["kind"] != "CONSENT_TEXT"
        or supporting["legal_effect"] != "CONSENT_TEXT"
        or not hmac.compare_digest(supporting["content_sha256"], document_hash)
    ):
        raise IamError("CONSENT_CHOICE_INVALID")
    recipient_ref = _nonempty_text(
        raw.get("recipient_ref"),
        "POLICY_CONFIGURATION_UNAVAILABLE",
    )
    recipient_label = _nonempty_text(
        raw.get("recipient_label"),
        "POLICY_CONFIGURATION_UNAVAILABLE",
    )
    try:
        domain_offer = ConsentOffer(
            consent_offer_id=str(offer_id),
            aggregate_version=offer_version,
            purpose=ConsentPurpose.PILOT_RESEARCH,
            scope_type=ConsentScopeType.PLATFORM_PARTICIPATION,
            data_categories=tuple(DataCategory(item) for item in categories),
            supporting_document_id=str(document_id),
            supporting_document_sha256=document_hash.hex(),
            recipient_reference=recipient_ref,
            pilot_ends_at=not_after,
            policy_bundle_id=str(request.policy_bundle_id),
            recipient_label=recipient_label,
            canonical_offer_sha256=canonical_hash.hex(),
        )
        actual_hash = hashlib.sha256(
            canonical_consent_offer_bytes(domain_offer)
        ).digest()
    except (IamError, TypeError, ValueError) as error:
        raise IamError("POLICY_CONFIGURATION_UNAVAILABLE") from error
    if not hmac.compare_digest(canonical_hash, actual_hash):
        raise IamError("POLICY_CONFIGURATION_UNAVAILABLE")
    return {
        "consent_offer_id": offer_id,
        "offer_version": offer_version,
        "purpose": "PILOT_RESEARCH",
        "scope_type": "PLATFORM_PARTICIPATION",
        "recipient_ref": recipient_ref,
        "recipient_label": recipient_label,
        "document_id": document_id,
        "document_content_sha256": document_hash,
        "expiry_days": expiry_days,
        "not_after": not_after,
        "categories": categories,
    }


def _validate_live_grant(
    grant: Mapping[str, Any],
    offer: Mapping[str, Any],
    principal: Mapping[str, Any],
    now: datetime,
) -> None:
    granted_at = _utc(grant.get("granted_at"), "POLICY_CONFIGURATION_UNAVAILABLE")
    expires_at = _utc(grant.get("expires_at"), "POLICY_CONFIGURATION_UNAVAILABLE")
    expected_expiry = min(
        granted_at + timedelta(days=offer["expiry_days"]),
        offer["not_after"],
    )
    auth_time = _utc(grant.get("auth_time"), "POLICY_CONFIGURATION_UNAVAILABLE")
    if (
        grant.get("consent_offer_id") != str(offer["consent_offer_id"])
        or grant.get("consent_offer_version") != offer["offer_version"]
        or grant.get("purpose") != offer["purpose"]
        or grant.get("scope_type") != offer["scope_type"]
        or grant.get("scope_id") is not None
        or grant.get("recipient_ref") != offer["recipient_ref"]
        or grant.get("recipient_label") != offer["recipient_label"]
        or grant.get("document_id") != str(offer["document_id"])
        or not hmac.compare_digest(
            _hex_digest(
                grant.get("document_content_sha256"),
                "POLICY_CONFIGURATION_UNAVAILABLE",
            ),
            offer["document_content_sha256"],
        )
        or tuple(grant.get("categories", ())) != offer["categories"]
        or expires_at != expected_expiry
        or expires_at <= now
        or grant.get("status") != "ACTIVE"
        or auth_time > granted_at
        or _positive_int(grant.get("aggregate_version"), "POLICY_CONFIGURATION_UNAVAILABLE")
        < 1
    ):
        raise IamError("INVALID_STATE_TRANSITION")
    del principal
    _uuid(grant.get("consent_grant_id"), "POLICY_CONFIGURATION_UNAVAILABLE")
    _uuid(grant.get("session_id"), "POLICY_CONFIGURATION_UNAVAILABLE")
    _uuid(grant.get("auth_transaction_id"), "POLICY_CONFIGURATION_UNAVAILABLE")
    _nonempty_text(grant.get("acr_code"), "POLICY_CONFIGURATION_UNAVAILABLE")
    _text_tuple(grant.get("amr_codes"), "POLICY_CONFIGURATION_UNAVAILABLE")


def _grant_response(grant: Mapping[str, Any]) -> Dict[str, Any]:
    version = _positive_int(grant.get("aggregate_version"), "SERVICE_UNAVAILABLE")
    document_hash_value = grant.get("document_content_sha256")
    document_hash = (
        document_hash_value
        if isinstance(document_hash_value, str)
        else _hex_digest(document_hash_value, "SERVICE_UNAVAILABLE").hex()
    )
    return {
        "consent_grant_id": str(
            _uuid(grant.get("consent_grant_id"), "SERVICE_UNAVAILABLE")
        ),
        "consent_offer_id": str(
            _uuid(grant.get("consent_offer_id"), "SERVICE_UNAVAILABLE")
        ),
        "purpose": grant.get("purpose"),
        "scope_type": grant.get("scope_type"),
        "scope_id": grant.get("scope_id"),
        "data_categories": list(
            _text_tuple(grant.get("categories"), "SERVICE_UNAVAILABLE")
        ),
        "recipient_label": _nonempty_text(
            grant.get("recipient_label"),
            "SERVICE_UNAVAILABLE",
        ),
        "document_id": str(_uuid(grant.get("document_id"), "SERVICE_UNAVAILABLE")),
        "content_sha256": document_hash,
        "granted_at": _timestamp(_utc(grant.get("granted_at"), "SERVICE_UNAVAILABLE")),
        "expires_at": _timestamp(_utc(grant.get("expires_at"), "SERVICE_UNAVAILABLE")),
        "status": grant.get("status"),
        "aggregate_version": version,
        "entity_tag": _entity_tag(version),
    }


def _require_response_binding(
    response: Mapping[str, Any],
    request: PolicyConsentPostgresDatabaseRequest,
) -> None:
    if request.operation is PolicyConsentPostgresOperation.ACCEPT_CURRENT_POLICIES:
        if (
            response.get("selector_digest") != request.scope.selector_digest.hex()
            or response.get("scope_type") != request.scope.authority_scope_type
            or response.get("scope_id")
            != (
                str(request.scope.authority_scope_id)
                if request.scope.authority_scope_id is not None
                else None
            )
            or response.get("required_policy_bundle_id")
            != str(request.policy_bundle_id)
            or response.get("satisfied") is not True
            or response.get("missing_document_ids") != []
        ):
            raise IamError("SERVICE_UNAVAILABLE")
        return
    choice = request.consent_choice
    if choice is None or (
        response.get("consent_offer_id") != str(choice.consent_offer_id)
        or response.get("document_id") != str(choice.document_id)
        or response.get("content_sha256") != choice.content_sha256.hex()
        or response.get("purpose") != "PILOT_RESEARCH"
        or response.get("scope_type") != "PLATFORM_PARTICIPATION"
        or response.get("scope_id") is not None
    ):
        raise IamError("SERVICE_UNAVAILABLE")


def _event_envelope(
    *,
    request: PolicyConsentPostgresDatabaseRequest,
    event_id: UUID,
    event: _PolicyConsentOutboxRecord,
    organization_id: Optional[UUID],
    occurred_at: datetime,
) -> Dict[str, Any]:
    return {
        "event_id": str(event_id),
        "event_type": event.event_type,
        "schema_version": 1,
        "occurred_at": _timestamp(occurred_at),
        "aggregate_type": event.aggregate_type,
        "aggregate_id": str(event.aggregate_id),
        "aggregate_version": event.aggregate_version,
        "actor_kind": "USER",
        "actor_id": str(request.scope.actor_user_id),
        "original_actor_id": None,
        "correlation_id": str(request.scope.correlation_id),
        "causation_id": str(request.scope.causation_id),
        "trace_id": str(request.scope.trace_id),
        "organization_id": str(organization_id) if organization_id else None,
        "payload": dict(event.payload),
    }


def _canonical_path(operation: PolicyConsentPostgresOperation) -> str:
    return (
        "/v1/me/policy-acceptances"
        if operation is PolicyConsentPostgresOperation.ACCEPT_CURRENT_POLICIES
        else "/v1/me/consents"
    )


def _receipt_response_profile(
    operation: PolicyConsentPostgresOperation,
) -> Tuple[int, str]:
    if operation is PolicyConsentPostgresOperation.ACCEPT_CURRENT_POLICIES:
        return 200, "PolicyRequirementStatusDto"
    if operation is PolicyConsentPostgresOperation.GRANT_CONSENT:
        return 201, "ConsentGrantDto"
    raise IamError("SERVICE_UNAVAILABLE")


def _mapping(value: object, code: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise IamError(code)
    return value


def _sequence(value: object, code: str) -> Sequence[Any]:
    if not isinstance(value, list):
        raise IamError(code)
    return value


def _positive_int(value: object, code: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise IamError(code)
    return value


def _nonempty_text(value: object, code: str) -> str:
    if not isinstance(value, str) or not value:
        raise IamError(code)
    return value


def _text_tuple(value: object, code: str) -> Tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        raise IamError(code)
    result = tuple(value)
    if (
        not result
        or not all(isinstance(item, str) and item for item in result)
        or len(result) != len(set(result))
    ):
        raise IamError(code)
    return result


def _uuid(value: object, code: str) -> UUID:
    try:
        parsed = value if isinstance(value, UUID) else UUID(str(value))
    except (TypeError, ValueError, AttributeError) as error:
        raise IamError(code) from error
    if parsed.int == 0:
        raise IamError(code)
    return parsed


def _optional_uuid(value: object, code: str) -> Optional[UUID]:
    return None if value is None else _uuid(value, code)


def _hex_digest(value: object, code: str) -> bytes:
    if isinstance(value, bytes):
        digest = value
    elif isinstance(value, str):
        try:
            digest = bytes.fromhex(value)
        except ValueError as error:
            raise IamError(code) from error
    else:
        raise IamError(code)
    if len(digest) != 32:
        raise IamError(code)
    return digest


def _utc(value: object, code: str) -> datetime:
    try:
        return parse_utc_timestamp(value)
    except ValueError as error:
        raise IamError(code) from error


def _timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _entity_tag(version: int) -> str:
    return '"v%d"' % version


def _connection_is_idle(connection: Any) -> bool:
    return connection.info.transaction_status == TransactionStatus.IDLE


def _is_retryable_precommit_error(error: BaseException) -> bool:
    if isinstance(error, PolicyConsentPostgresCommitOutcomeUnknownError):
        return False
    return getattr(error, "sqlstate", None) in ("40001", "40P01", "55P03")


def _require_operation(
    request: object,
    expected: PolicyConsentPostgresOperation,
) -> None:
    if not isinstance(request, PolicyConsentPostgresDatabaseRequest):
        raise TypeError("closed policy/consent database request is required")
    if request.operation is not expected:
        raise ValueError("policy/consent database request operation mismatch")


def _require_digest(value: object, label: str) -> None:
    if not isinstance(value, bytes) or len(value) != 32:
        raise ValueError(f"{label} must be a 32-byte digest")


def _require_key_id(value: object, label: str) -> None:
    if not isinstance(value, str) or not 1 <= len(value) <= 64:
        raise ValueError(f"{label} is invalid")


def _require_utc(value: object, label: str) -> None:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() != timedelta(0)
    ):
        raise ValueError(f"{label} must be aware UTC")


__all__ = [
    "NoPolicyConsentPostgresFaults",
    "POLICY_CONSENT_POSTGRES_WRITE_CHECKPOINTS",
    "POSTGRES_POLICY_CONSENT_BEHAVIOR_NOT_AVAILABLE",
    "PolicyConsentPostgresAcceptanceChoice",
    "PolicyConsentPostgresBehaviorNotAvailable",
    "PolicyConsentPostgresCommitOutcomeUnknownError",
    "PolicyConsentPostgresConfigurationError",
    "PolicyConsentPostgresConnectionSource",
    "PolicyConsentPostgresDatabaseRequest",
    "PolicyConsentPostgresDatabaseResult",
    "PolicyConsentPostgresExecutionScope",
    "PolicyConsentPostgresFaultInjector",
    "PolicyConsentPostgresGeneratedIds",
    "PolicyConsentPostgresOfferChoice",
    "PolicyConsentPostgresOperation",
    "PolicyConsentPostgresSchemaValidator",
    "PolicyConsentPostgresSettings",
    "PolicyConsentPostgresUnitOfWorkState",
    "PolicyConsentPostgresWriteCheckpoint",
    "PolicyConsentReceiptIdentityDigest",
    "PolicyConsentReceiptMaterial",
    "PolicyConsentReceiptPayloadDigest",
    "PsycopgPolicyConsentCommandUnitOfWorkFactory",
]
