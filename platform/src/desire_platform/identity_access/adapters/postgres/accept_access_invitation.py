"""Production PostgreSQL Unit of Work for ``AcceptAccessInvitation``.

The public values deliberately contain persisted digests rather than raw HTTP
or Session secrets.  The adapter uses the ``iam_onboarding`` role, transaction
local RLS context and one explicit PostgreSQL transaction.  It never falls
back to the Memory store and never retries after COMMIT has been sent.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
import hashlib
import hmac
from typing import Any, Dict, List, Mapping, Optional, Protocol, Tuple
from uuid import UUID

from psycopg import DatabaseError
from psycopg.pq import TransactionStatus
from psycopg.types.json import Jsonb

from desire_platform.utc import parse_offset_timestamp

from ...application.access_invitations import SESSION_IDLE_TTL
from ...application.read_models import project_canonical_me_dto
from ...domain.errors import IamError
from ...domain.policies import (
    ConsentOffer,
    ConsentPurpose,
    ConsentScopeType,
    DataCategory,
    canonical_consent_offer_bytes,
)


POSTGRES_ACCEPT_BEHAVIOR_NOT_AVAILABLE = (
    "IAM_POSTGRES_ACCEPT_BEHAVIOR_NOT_AVAILABLE"
)


class AcceptPostgresBehaviorNotAvailable(RuntimeError):
    """Stable RED sentinel for the unimplemented production persistence path."""


class AcceptPostgresConfigurationError(RuntimeError):
    """The connection identity or closed deployment settings are unsafe."""


class AcceptCommandOutcomeUnknownError(RuntimeError):
    """COMMIT was sent, so this request cannot infer or retry the outcome."""

    code = "COMMAND_OUTCOME_UNKNOWN"


class AcceptUnitOfWorkState(str, Enum):
    NEW = "NEW"
    BEGUN = "BEGUN"
    WRITING = "WRITING"
    COMMIT_SENT = "COMMIT_SENT"
    COMMITTED = "COMMITTED"
    ROLLED_BACK = "ROLLED_BACK"
    OUTCOME_UNKNOWN = "OUTCOME_UNKNOWN"


class AcceptWriteCheckpoint(str, Enum):
    COMMAND_RECEIPT_CLAIM = "command_receipt.claim"
    POLICY_ACCEPTANCE_INSERT = "policy_acceptance.insert"
    CONSENT_GRANT_EXPIRE = "consent_grant.expire"
    CONSENT_GRANT_INSERT = "consent_grant.insert"
    CONSENT_GRANT_CATEGORY_INSERT = "consent_grant_category.insert"
    USER_ACTIVATE_OR_GATE_VERSION = "user.activate-or-gate-version"
    USER_ROLE_GRANT_INSERT = "user_role_grant.insert"
    MEMBERSHIP_INSERT = "membership.insert"
    MEMBERSHIP_ROLE_GRANT_INSERT = "membership_role_grant.insert"
    ORGANIZATION_ACTIVATE = "organization.activate"
    ACCESS_INVITATION_ACCEPT = "access_invitation.accept"
    SESSION_PREDECESSOR_REVOKE = "session.predecessor.revoke"
    SESSION_FAMILY_ROTATE = "session_family.rotate"
    SESSION_SUCCESSOR_INSERT = "session.successor.insert"
    AUDIT_EVENT_INSERT = "audit_event.insert"
    OUTBOX_EVENT_INSERT = "outbox_event.insert"
    COMMAND_RECEIPT_COMPLETE = "command_receipt.complete"


ACCEPT_WRITE_CHECKPOINTS: Tuple[AcceptWriteCheckpoint, ...] = tuple(
    AcceptWriteCheckpoint
)


class AcceptConnectionSource(Protocol):
    """Pool boundary with explicit reusable versus permanently tainted exits."""

    def checkout(self) -> Any:
        ...

    def release(self, connection: Any) -> None:
        ...

    def discard(self, connection: Any) -> None:
        ...


class AcceptFaultInjector(Protocol):
    """Test-only deterministic barrier/fault hook before a logical write."""

    def before_write(
        self,
        checkpoint: AcceptWriteCheckpoint,
        ordinal: int,
    ) -> None:
        ...


class AcceptSchemaValidator(Protocol):
    """Closed machine-contract validator supplied by production composition."""

    def validate(
        self,
        value: Mapping[str, Any],
        schema_name: Optional[str] = None,
    ) -> None:
        ...


class NoAcceptFaults:
    """Production default; it cannot alter statements or transaction state."""

    def before_write(
        self,
        checkpoint: AcceptWriteCheckpoint,
        ordinal: int,
    ) -> None:
        del checkpoint, ordinal


@dataclass(frozen=True)
class AcceptPostgresSettings:
    runtime_role: str = "iam_onboarding"
    lock_timeout_ms: int = 2_000
    statement_timeout_ms: int = 10_000
    idle_in_transaction_timeout_ms: int = 15_000
    max_precommit_retries: int = 3

    def __post_init__(self) -> None:
        if self.runtime_role != "iam_onboarding":
            raise ValueError("Accept runtime role must be iam_onboarding")
        if not 1 <= self.lock_timeout_ms <= 10_000:
            raise ValueError("lock timeout is outside the reviewed bounds")
        if not 1 <= self.statement_timeout_ms <= 30_000:
            raise ValueError("statement timeout is outside the reviewed bounds")
        if not 1 <= self.idle_in_transaction_timeout_ms <= 30_000:
            raise ValueError(
                "idle-in-transaction timeout is outside the reviewed bounds"
            )
        if self.max_precommit_retries != 3:
            raise ValueError("Accept pre-COMMIT retry count must be exactly 3")


@dataclass(frozen=True)
class AcceptReceiptIdentity:
    receipt_id: UUID
    principal_id: UUID
    idempotency_key_digest: bytes = field(repr=False)
    idempotency_key_digest_key_id: str
    payload_hash: bytes = field(repr=False)
    payload_hash_key_id: str
    canonicalization_version: str
    retain_until: datetime

    def __post_init__(self) -> None:
        _require_digest(self.idempotency_key_digest, "idempotency digest")
        _require_digest(self.payload_hash, "payload hash")
        if self.canonicalization_version != "restricted-canonical-json-v1":
            raise ValueError("unsupported receipt canonicalization")
        _require_utc(self.retain_until, "receipt retain_until")


@dataclass(frozen=True)
class AcceptExecutionScope:
    actor_user_id: UUID
    session_id: UUID
    session_family_id: UUID
    auth_transaction_id: UUID
    invitation_id: UUID
    organization_id: Optional[UUID]
    policy_selector_digest: bytes = field(repr=False)
    policy_bundle_id: UUID
    target_role: str
    command_id: UUID
    correlation_id: UUID
    trace_id: UUID

    def __post_init__(self) -> None:
        _require_digest(self.policy_selector_digest, "policy selector digest")
        if self.target_role not in {"CREATOR", "ORG_ADMIN", "DEMAND_OWNER"}:
            raise ValueError("Accept target role is invalid")
        if (self.target_role == "CREATOR") != (self.organization_id is None):
            raise ValueError("Accept target role and organization have an open shape")
        if self.command_id.int == 0:
            raise ValueError("command ID must be non-zero")


@dataclass(frozen=True)
class AcceptHoldEvidence:
    action: str
    target_type: str
    target_id: UUID
    target_version: int
    organization_id: Optional[UUID]
    policy_version: str
    evaluated_at: datetime
    valid_until: datetime

    def __post_init__(self) -> None:
        if self.action != "AcceptAccessInvitation":
            raise ValueError("hold action is not AcceptAccessInvitation")
        if self.target_type != "AccessInvitation":
            raise ValueError("hold target type is not AccessInvitation")
        if self.target_version < 1 or not self.policy_version:
            raise ValueError("hold evidence is incomplete")
        _require_utc(self.evaluated_at, "hold evaluated_at")
        _require_utc(self.valid_until, "hold valid_until")
        if self.valid_until <= self.evaluated_at:
            raise ValueError("hold evidence has an empty validity window")


@dataclass(frozen=True)
class AcceptPolicyAcceptanceChoice:
    document_id: UUID
    content_sha256: bytes = field(repr=False)
    affirmed: bool

    def __post_init__(self) -> None:
        _require_digest(self.content_sha256, "policy content hash")
        if self.affirmed is not True:
            raise ValueError("policy acceptance must be explicitly affirmed")


@dataclass(frozen=True)
class AcceptConsentOfferChoice:
    consent_offer_id: UUID
    document_id: UUID
    content_sha256: bytes = field(repr=False)
    affirmed: bool

    def __post_init__(self) -> None:
        _require_digest(self.content_sha256, "consent document hash")
        if self.affirmed is not True:
            raise ValueError("consent choice must be explicitly affirmed")


@dataclass(frozen=True)
class AcceptSessionSuccessorFacts:
    session_id: UUID
    handle_digest: bytes = field(repr=False)
    handle_digest_key_id: str
    csrf_salt: bytes = field(repr=False)
    csrf_key_id: str
    csrf_digest: bytes = field(repr=False)

    def __post_init__(self) -> None:
        _require_digest(self.handle_digest, "Session handle digest")
        _require_digest(self.csrf_salt, "CSRF salt")
        _require_digest(self.csrf_digest, "CSRF digest")
        if not self.handle_digest_key_id or not self.csrf_key_id:
            raise ValueError("Session successor key IDs are required")


@dataclass(frozen=True)
class AcceptGeneratedIds:
    policy_acceptance_ids: Tuple[UUID, ...]
    consent_grant_ids: Tuple[UUID, ...]
    user_role_grant_id: Optional[UUID]
    membership_id: Optional[UUID]
    membership_role_grant_id: Optional[UUID]
    audit_event_id: UUID
    outbox_event_ids: Tuple[UUID, ...]

    def __post_init__(self) -> None:
        creator_shape = (
            self.user_role_grant_id is not None
            and self.membership_id is None
            and self.membership_role_grant_id is None
        )
        organization_shape = (
            self.user_role_grant_id is None
            and self.membership_id is not None
            and self.membership_role_grant_id is not None
        )
        if not (creator_shape or organization_shape):
            raise ValueError("generated authority IDs have an open shape")
        all_ids = (
            self.policy_acceptance_ids
            + self.consent_grant_ids
            + self.outbox_event_ids
        )
        if len(all_ids) != len(set(all_ids)):
            raise ValueError("generated repeatable IDs must be unique")


@dataclass(frozen=True)
class AcceptAccessInvitationDatabaseRequest:
    scope: AcceptExecutionScope
    receipt: AcceptReceiptIdentity
    hold: AcceptHoldEvidence
    expected_invitation_version: int
    policy_acceptances: Tuple[AcceptPolicyAcceptanceChoice, ...]
    consent_choices: Tuple[AcceptConsentOfferChoice, ...]
    successor: AcceptSessionSuccessorFacts
    generated_ids: AcceptGeneratedIds

    def __post_init__(self) -> None:
        if self.expected_invitation_version < 1:
            raise ValueError("expected invitation version must be positive")
        if self.receipt.receipt_id != self.scope.command_id:
            raise ValueError("receipt and command ID must be identical")
        if self.receipt.principal_id != self.scope.actor_user_id:
            raise ValueError("receipt principal must be the actor")
        if self.hold.target_id != self.scope.invitation_id:
            raise ValueError("hold target must be the exact invitation")
        if self.hold.organization_id != self.scope.organization_id:
            raise ValueError("hold organization must match the database scope")
        if self.hold.target_version != self.expected_invitation_version:
            raise ValueError("hold and If-Match versions must be identical")
        if self.receipt.retain_until <= self.hold.evaluated_at:
            raise ValueError("receipt retention must extend past command time")
        if not self.policy_acceptances:
            raise ValueError("at least one policy acceptance is required")


@dataclass(frozen=True)
class AcceptAccessInvitationDatabaseResult:
    replayed: bool
    safe_response: Mapping[str, Any] = field(repr=False)
    successor_session_id: Optional[UUID]


class PsycopgAcceptAccessInvitationUnitOfWorkFactory:
    """Execute the closed Accept persistence plan on real PostgreSQL."""

    def __init__(
        self,
        *,
        connections: AcceptConnectionSource,
        event_validator: AcceptSchemaValidator,
        response_validator: AcceptSchemaValidator,
        settings: Optional[AcceptPostgresSettings] = None,
        fault_injector: Optional[AcceptFaultInjector] = None,
    ) -> None:
        self.connections = connections
        self.event_validator = event_validator
        self.response_validator = response_validator
        self.settings = settings or AcceptPostgresSettings()
        self.fault_injector = fault_injector or NoAcceptFaults()

    def execute(
        self,
        request: AcceptAccessInvitationDatabaseRequest,
    ) -> AcceptAccessInvitationDatabaseResult:
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
        raise AssertionError("closed Accept retry loop did not return or raise")

    def _execute_once(
        self,
        request: AcceptAccessInvitationDatabaseRequest,
    ) -> AcceptAccessInvitationDatabaseResult:
        connection = self.connections.checkout()
        state = AcceptUnitOfWorkState.NEW
        disposed = False
        try:
            self._validate_connection_identity(connection)
            connection.execute("BEGIN ISOLATION LEVEL READ COMMITTED")
            state = AcceptUnitOfWorkState.BEGUN
            self._configure_transaction(connection, request)
            state = AcceptUnitOfWorkState.WRITING
            result = self._execute_transaction(connection, request)
            state = AcceptUnitOfWorkState.COMMIT_SENT
            connection.execute("COMMIT")
            state = AcceptUnitOfWorkState.COMMITTED
        except BaseException as error:
            if state == AcceptUnitOfWorkState.COMMIT_SENT:
                self.connections.discard(connection)
                disposed = True
                raise AcceptCommandOutcomeUnknownError() from error
            if state in (
                AcceptUnitOfWorkState.BEGUN,
                AcceptUnitOfWorkState.WRITING,
            ):
                try:
                    connection.execute("ROLLBACK")
                    state = AcceptUnitOfWorkState.ROLLED_BACK
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
            raise AcceptPostgresConfigurationError(
                "Accept checkout must be transaction-idle"
            )
        identity = connection.execute(
            "SELECT current_user,session_user,"
            "current_setting('server_version_num')::integer"
        ).fetchone()
        if identity is None or identity[0:2] != (
            self.settings.runtime_role,
            self.settings.runtime_role,
        ):
            raise AcceptPostgresConfigurationError(
                "Accept connection identity is not iam_onboarding"
            )
        if identity[2] // 10_000 != 18:
            raise AcceptPostgresConfigurationError(
                "Accept requires PostgreSQL major 18"
            )

    def _configure_transaction(
        self,
        connection: Any,
        request: AcceptAccessInvitationDatabaseRequest,
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
        values = _transaction_context(request)
        for name, value in values:
            configured = connection.execute(
                "SELECT pg_catalog.set_config(%s,%s,true)",
                (name, value),
            ).fetchone()
            if configured != (value,):
                raise AcceptPostgresConfigurationError(
                    "Accept transaction context could not be installed"
                )
        for name, expected in values:
            actual = connection.execute(
                "SELECT current_setting(%s,true)",
                (name,),
            ).fetchone()
            if actual != (expected,):
                raise AcceptPostgresConfigurationError(
                    "Accept transaction context readback failed"
                )

    def _execute_transaction(
        self,
        connection: Any,
        request: AcceptAccessInvitationDatabaseRequest,
    ) -> AcceptAccessInvitationDatabaseResult:
        ordinals: Dict[AcceptWriteCheckpoint, int] = {}

        def before_write(checkpoint: AcceptWriteCheckpoint) -> None:
            ordinal = ordinals.get(checkpoint, 0)
            self.fault_injector.before_write(checkpoint, ordinal)
            ordinals[checkpoint] = ordinal + 1

        before_write(AcceptWriteCheckpoint.COMMAND_RECEIPT_CLAIM)
        key_policy_locked = connection.execute(
            "SELECT iam_api.lock_accept_receipt_key_policy_v1(%s,%s,%s)",
            (
                request.receipt.idempotency_key_digest_key_id,
                request.receipt.payload_hash_key_id,
                request.receipt.canonicalization_version,
            ),
        ).fetchone()
        if key_policy_locked != (True,):
            raise AcceptPostgresConfigurationError(
                "Accept receipt key policy is unavailable"
            )

        claimed = connection.execute(
            "INSERT INTO infra.command_receipts ("
            "id,principal_kind,principal_id,command_name,command_version,"
            "idempotency_key_digest,idempotency_key_digest_key_id,payload_hash,"
            "payload_hash_key_id,canonicalization_version,target_kind,target_id,"
            "http_method,canonical_path,if_match_version,status,"
            "response_schema_version,safe_response_body,reconstruction_metadata,"
            "created_at,retain_until,completed_at) VALUES ("
            "%s,'USER',%s,'AcceptAccessInvitation',1,%s,%s,%s,%s,%s,"
            "'AccessInvitation',%s,'POST',%s,%s,'IN_PROGRESS',NULL,NULL,NULL,"
            "transaction_timestamp(),%s,NULL) "
            "ON CONFLICT DO NOTHING RETURNING id",
            (
                request.receipt.receipt_id,
                request.receipt.principal_id,
                request.receipt.idempotency_key_digest,
                request.receipt.idempotency_key_digest_key_id,
                request.receipt.payload_hash,
                request.receipt.payload_hash_key_id,
                request.receipt.canonicalization_version,
                request.scope.invitation_id,
                "/v1/access-invitations/%s/accept" % request.scope.invitation_id,
                request.expected_invitation_version,
                request.receipt.retain_until,
            ),
        ).fetchone()
        if claimed is None:
            return self._resolve_receipt_replay(connection, request)

        now = _read_transaction_timestamp_utc(connection)
        if request.receipt.retain_until <= now:
            raise IamError("SERVICE_UNAVAILABLE")
        if request.hold.evaluated_at > now or request.hold.valid_until <= now:
            raise IamError("SAFETY_DECISION_UNAVAILABLE")

        plan = self._load_and_validate_plan(connection, request, now)
        events: List[_OutboxRecord] = []

        next_acceptance_id = 0
        for choice in request.policy_acceptances:
            document = plan.policy_documents[choice.document_id]
            existing_acceptances = connection.execute(
                "SELECT id FROM iam.policy_acceptances WHERE user_id=%s "
                "AND document_id=%s AND content_sha256=%s "
                "ORDER BY id",
                (
                    request.scope.actor_user_id,
                    choice.document_id,
                    choice.content_sha256,
                ),
            ).fetchall()
            if len(existing_acceptances) > 1:
                raise IamError("POLICY_CONFIGURATION_UNAVAILABLE")
            if existing_acceptances:
                continue
            if next_acceptance_id >= len(
                request.generated_ids.policy_acceptance_ids
            ):
                raise IamError("SERVICE_UNAVAILABLE")
            before_write(AcceptWriteCheckpoint.POLICY_ACCEPTANCE_INSERT)
            acceptance_id = request.generated_ids.policy_acceptance_ids[
                next_acceptance_id
            ]
            next_acceptance_id += 1
            connection.execute(
                "INSERT INTO iam.policy_acceptances ("
                "id,user_id,document_id,content_sha256,bundle_id,accepted_at,"
                "session_id,auth_transaction_id,auth_time,acr_code,amr_codes,"
                "source_action,command_id,correlation_id,aggregate_version,created_at"
                ") VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,"
                "'ACCESS_INVITATION_ACCEPT',%s,%s,1,%s)",
                (
                    acceptance_id,
                    request.scope.actor_user_id,
                    choice.document_id,
                    choice.content_sha256,
                    request.scope.policy_bundle_id,
                    now,
                    request.scope.session_id,
                    request.scope.auth_transaction_id,
                    plan.session.auth_time,
                    plan.session.acr_code,
                    list(plan.session.amr_codes),
                    request.scope.command_id,
                    request.scope.correlation_id,
                    now,
                ),
            )
            events.append(
                _OutboxRecord(
                    "PolicyAccepted",
                    "PolicyAcceptance",
                    acceptance_id,
                    1,
                    {
                        "policy_acceptance_id": str(acceptance_id),
                        "user_id": str(request.scope.actor_user_id),
                        "policy_bundle_id": str(request.scope.policy_bundle_id),
                        "policy_document_id": str(choice.document_id),
                        "policy_document_sha256": choice.content_sha256.hex(),
                        "legal_effect": document.legal_effect,
                    },
                )
            )

        if next_acceptance_id != len(request.generated_ids.policy_acceptance_ids):
            raise IamError("SERVICE_UNAVAILABLE")

        next_consent_id = 0
        for choice in request.consent_choices:
            authorization = plan.consent_authorizations[choice.consent_offer_id]
            existing_grants = connection.execute(
                "SELECT id,consent_offer_id,consent_offer_version,policy_bundle_id,"
                "purpose,scope_type,scope_id,recipient_ref,recipient_label,"
                "document_id,document_content_sha256,granted_at,expires_at,status,"
                "aggregate_version "
                "FROM iam.consent_grants WHERE user_id=%s AND purpose=%s "
                "AND scope_type=%s AND scope_id IS NOT DISTINCT FROM %s "
                "AND status='ACTIVE' ORDER BY id FOR UPDATE",
                (
                    request.scope.actor_user_id,
                    authorization.purpose,
                    authorization.scope_type,
                    authorization.scope_id,
                ),
            ).fetchall()
            if len(existing_grants) > 1:
                raise IamError("POLICY_CONFIGURATION_UNAVAILABLE")
            if existing_grants:
                if existing_grants[0][12] <= now:
                    before_write(AcceptWriteCheckpoint.CONSENT_GRANT_EXPIRE)
                    expired = connection.execute(
                        "UPDATE iam.consent_grants SET status='EXPIRED',"
                        "withdrawn_at=NULL,aggregate_version=aggregate_version+1,"
                        "updated_at=%s WHERE id=%s AND user_id=%s "
                        "AND status='ACTIVE' AND aggregate_version=%s "
                        "AND expires_at=%s "
                        "AND expires_at <= transaction_timestamp() RETURNING id",
                        (
                            now,
                            existing_grants[0][0],
                            request.scope.actor_user_id,
                            existing_grants[0][14],
                            existing_grants[0][12],
                        ),
                    ).fetchone()
                    if expired != (existing_grants[0][0],):
                        raise IamError("INVALID_STATE_TRANSITION")
                    existing_grants = []
            if existing_grants:
                category_rows = connection.execute(
                    "SELECT category,position "
                    "FROM iam.consent_grant_data_categories WHERE grant_id=%s "
                    "ORDER BY position",
                    (existing_grants[0][0],),
                ).fetchall()
                if not _existing_consent_matches(
                    existing_grants[0],
                    category_rows,
                    authorization,
                    request.scope.policy_bundle_id,
                    now,
                ):
                    raise IamError("INVALID_STATE_TRANSITION")
                continue
            if next_consent_id >= len(request.generated_ids.consent_grant_ids):
                raise IamError("SERVICE_UNAVAILABLE")
            before_write(AcceptWriteCheckpoint.CONSENT_GRANT_INSERT)
            grant_id = request.generated_ids.consent_grant_ids[next_consent_id]
            next_consent_id += 1
            inserted_grant = connection.execute(
                "INSERT INTO iam.consent_grants ("
                "id,user_id,consent_offer_id,consent_offer_version,policy_bundle_id,"
                "purpose,scope_type,scope_id,recipient_ref,recipient_label,"
                "document_id,document_content_sha256,granted_at,expires_at,"
                "session_id,auth_transaction_id,auth_time,acr_code,amr_codes,"
                "command_id,correlation_id,status,withdrawn_at,aggregate_version,"
                "created_at,updated_at) VALUES ("
                "%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,"
                "%s,%s,'ACTIVE',NULL,1,%s,%s) "
                "ON CONFLICT (user_id,purpose,scope_type,scope_id) "
                "WHERE status='ACTIVE' DO NOTHING RETURNING id",
                (
                    grant_id,
                    request.scope.actor_user_id,
                    authorization.offer_id,
                    authorization.offer_version,
                    request.scope.policy_bundle_id,
                    authorization.purpose,
                    authorization.scope_type,
                    authorization.scope_id,
                    authorization.recipient_ref,
                    authorization.recipient_label,
                    authorization.document_id,
                    authorization.document_hash,
                    now,
                    authorization.expires_at,
                    request.scope.session_id,
                    request.scope.auth_transaction_id,
                    plan.session.auth_time,
                    plan.session.acr_code,
                    list(plan.session.amr_codes),
                    request.scope.command_id,
                    request.scope.correlation_id,
                    now,
                    now,
                ),
            ).fetchone()
            if inserted_grant != (grant_id,):
                raise IamError("INVALID_STATE_TRANSITION")
            for position, category in enumerate(authorization.categories, start=1):
                before_write(AcceptWriteCheckpoint.CONSENT_GRANT_CATEGORY_INSERT)
                connection.execute(
                    "INSERT INTO iam.consent_grant_data_categories "
                    "(grant_id,category,position) VALUES (%s,%s,%s)",
                    (grant_id, category, position),
                )
            events.append(
                _OutboxRecord(
                    "ConsentGranted",
                    "ConsentGrant",
                    grant_id,
                    1,
                    {
                        "consent_grant_id": str(grant_id),
                        "user_id": str(request.scope.actor_user_id),
                        "status": "ACTIVE",
                        "granted_at": _timestamp(now),
                        "derived_authorization": {
                            "consent_offer_id": str(authorization.offer_id),
                            "consent_offer_version": authorization.offer_version,
                            "policy_bundle_id": str(request.scope.policy_bundle_id),
                            "purpose": authorization.purpose,
                            "scope_type": authorization.scope_type,
                            "scope_id": (
                                str(authorization.scope_id)
                                if authorization.scope_id is not None
                                else None
                            ),
                            "data_categories": list(authorization.categories),
                            "supporting_policy_document_id": str(
                                authorization.document_id
                            ),
                            "supporting_document_sha256": (
                                authorization.document_hash.hex()
                            ),
                            "expires_at": _timestamp(authorization.expires_at),
                        },
                    },
                )
            )

        if next_consent_id != len(request.generated_ids.consent_grant_ids):
            raise IamError("SERVICE_UNAVAILABLE")

        before_write(AcceptWriteCheckpoint.USER_ACTIVATE_OR_GATE_VERSION)
        if plan.user.status == "PENDING_ENROLLMENT":
            activated_user = connection.execute(
                "UPDATE iam.users SET status='ACTIVE',"
                "aggregate_version=aggregate_version+1,updated_at=%s "
                "WHERE id=%s AND status='PENDING_ENROLLMENT' "
                "AND aggregate_version=%s RETURNING aggregate_version",
                (now, request.scope.actor_user_id, plan.user.aggregate_version),
            ).fetchone()
            if activated_user is None:
                raise IamError("ACCESS_INVITATION_UNAVAILABLE")
            user_version = activated_user[0]
            events.append(
                _OutboxRecord(
                    "UserActivated",
                    "User",
                    request.scope.actor_user_id,
                    user_version,
                    {
                        "user_id": str(request.scope.actor_user_id),
                        "status": "ACTIVE",
                        "access_invitation_id": str(request.scope.invitation_id),
                    },
                )
            )
        else:
            active_user = connection.execute(
                "UPDATE iam.users SET aggregate_version=aggregate_version+1,"
                "updated_at=%s WHERE id=%s AND status='ACTIVE' "
                "AND aggregate_version=%s RETURNING aggregate_version",
                (
                    now,
                    request.scope.actor_user_id,
                    plan.user.aggregate_version,
                ),
            ).fetchone()
            if active_user is None:
                raise IamError("ACCESS_INVITATION_UNAVAILABLE")
            user_version = active_user[0]
            events.append(
                _OutboxRecord(
                    "PolicyRequirementsSatisfied",
                    "User",
                    request.scope.actor_user_id,
                    user_version,
                    {
                        "user_id": str(request.scope.actor_user_id),
                        "policy_bundle_id": str(request.scope.policy_bundle_id),
                    },
                )
            )

        if plan.invitation.target_role == "CREATOR":
            before_write(AcceptWriteCheckpoint.USER_ROLE_GRANT_INSERT)
            grant_id = request.generated_ids.user_role_grant_id
            if grant_id is None:
                raise IamError("SERVICE_UNAVAILABLE")
            connection.execute(
                "INSERT INTO iam.user_role_grants ("
                "id,user_id,role_code,source_invitation_id,policy_selector_digest,"
                "granted_by_kind,granted_by_id,granted_at,revoked_at,"
                "revocation_reason_code,aggregate_version) VALUES ("
                "%s,%s,'CREATOR',%s,%s,'USER',%s,%s,NULL,NULL,1)",
                (
                    grant_id,
                    request.scope.actor_user_id,
                    request.scope.invitation_id,
                    request.scope.policy_selector_digest,
                    request.scope.actor_user_id,
                    now,
                ),
            )
            activated_scope = "USER_ROLE"
            events.append(
                _OutboxRecord(
                    "UserRoleGranted",
                    "UserRoleGrant",
                    grant_id,
                    1,
                    {
                        "user_role_grant_id": str(grant_id),
                        "user_id": str(request.scope.actor_user_id),
                        "target_role": "CREATOR",
                        "access_invitation_id": str(request.scope.invitation_id),
                    },
                )
            )
        else:
            membership_id = request.generated_ids.membership_id
            role_grant_id = request.generated_ids.membership_role_grant_id
            if membership_id is None or role_grant_id is None:
                raise IamError("SERVICE_UNAVAILABLE")
            before_write(AcceptWriteCheckpoint.MEMBERSHIP_INSERT)
            inserted_membership = connection.execute(
                "INSERT INTO iam.memberships ("
                "id,organization_id,user_id,status,source_invitation_id,"
                "aggregate_version,created_at,updated_at) VALUES ("
                "%s,%s,%s,'ACTIVE',%s,1,%s,%s) "
                "ON CONFLICT (organization_id,user_id) DO NOTHING RETURNING id",
                (
                    membership_id,
                    request.scope.organization_id,
                    request.scope.actor_user_id,
                    request.scope.invitation_id,
                    now,
                    now,
                ),
            ).fetchone()
            if inserted_membership != (membership_id,):
                raise IamError("INVALID_STATE_TRANSITION")
            events.append(
                _OutboxRecord(
                    "MembershipActivated",
                    "Membership",
                    membership_id,
                    1,
                    {
                        "membership_id": str(membership_id),
                        "user_id": str(request.scope.actor_user_id),
                        "status": "ACTIVE",
                        "access_invitation_id": str(request.scope.invitation_id),
                    },
                )
            )
            before_write(AcceptWriteCheckpoint.MEMBERSHIP_ROLE_GRANT_INSERT)
            connection.execute(
                "INSERT INTO iam.membership_role_grants ("
                "id,organization_id,membership_id,user_id,role_code,"
                "source_invitation_id,policy_selector_digest,granted_by_kind,"
                "granted_by_id,granted_at,revoked_at,revocation_reason_code,"
                "aggregate_version) VALUES ("
                "%s,%s,%s,%s,%s,%s,%s,'USER',%s,%s,NULL,NULL,1)",
                (
                    role_grant_id,
                    request.scope.organization_id,
                    membership_id,
                    request.scope.actor_user_id,
                    plan.invitation.target_role,
                    request.scope.invitation_id,
                    request.scope.policy_selector_digest,
                    request.scope.actor_user_id,
                    now,
                ),
            )
            events.append(
                _OutboxRecord(
                    "MembershipRoleGranted",
                    "MembershipRoleGrant",
                    role_grant_id,
                    1,
                    {
                        "membership_role_grant_id": str(role_grant_id),
                        "membership_id": str(membership_id),
                        "user_id": str(request.scope.actor_user_id),
                        "target_role": plan.invitation.target_role,
                        "access_invitation_id": str(request.scope.invitation_id),
                    },
                )
            )
            if plan.invitation.is_initial_admin:
                before_write(AcceptWriteCheckpoint.ORGANIZATION_ACTIVATE)
                organization_version = connection.execute(
                    "UPDATE iam.organizations SET status='ACTIVE',"
                    "aggregate_version=aggregate_version+1,updated_at=%s "
                    "WHERE id=%s AND status='PENDING_ADMIN' "
                    "RETURNING aggregate_version",
                    (now, request.scope.organization_id),
                ).fetchone()
                if organization_version is None:
                    raise IamError("ACCESS_INVITATION_UNAVAILABLE")
                events.append(
                    _OutboxRecord(
                        "OrganizationActivated",
                        "Organization",
                        request.scope.organization_id,
                        organization_version[0],
                        {
                            "organization_id": str(request.scope.organization_id),
                            "status": "ACTIVE",
                            "access_invitation_id": str(request.scope.invitation_id),
                            "initial_admin_membership_id": str(membership_id),
                        },
                    )
                )
            activated_scope = "ORGANIZATION_MEMBERSHIP"

        before_write(AcceptWriteCheckpoint.ACCESS_INVITATION_ACCEPT)
        invitation_version = connection.execute(
            "UPDATE iam.access_invitations SET status='ACCEPTED',"
            "accepted_by_user_id=%s,terminal_at=%s,terminal_reason_code=NULL,"
            "aggregate_version=aggregate_version+1,updated_at=%s "
            "WHERE id=%s AND status='ISSUED' AND aggregate_version=%s "
            "RETURNING aggregate_version",
            (
                request.scope.actor_user_id,
                now,
                now,
                request.scope.invitation_id,
                request.expected_invitation_version,
            ),
        ).fetchone()
        if invitation_version is None:
            raise IamError("ACCESS_INVITATION_UNAVAILABLE")
        events.append(
            _OutboxRecord(
                "AccessInvitationAccepted",
                "AccessInvitation",
                request.scope.invitation_id,
                invitation_version[0],
                {
                    "invitation_binding": {
                        "invitation_id": str(request.scope.invitation_id),
                        "bound_invitation_version": request.expected_invitation_version,
                        "issued_policy_bundle_id": str(
                            plan.invitation.issued_policy_bundle_id
                        ),
                        "purpose": plan.invitation.purpose,
                        "target_scope": plan.invitation.target_scope,
                        "target_role": plan.invitation.target_role,
                        "is_initial_admin": plan.invitation.is_initial_admin,
                    },
                    "status": "ACCEPTED",
                    "accepted_user_id": str(request.scope.actor_user_id),
                    "activation": (
                        {
                            "kind": "USER_ROLE",
                            "user_role_grant_id": str(
                                request.generated_ids.user_role_grant_id
                            ),
                        }
                        if activated_scope == "USER_ROLE"
                        else {
                            "kind": "ORGANIZATION_MEMBERSHIP",
                            "membership_id": str(
                                request.generated_ids.membership_id
                            ),
                            "membership_role_grant_id": str(
                                request.generated_ids.membership_role_grant_id
                            ),
                        }
                    ),
                },
            )
        )

        connection.execute(
            "SET CONSTRAINTS "
            "iam.trg_activation_matches_accepted_invitation,"
            "iam.trg_evidence_matches_session_auth,"
            "iam.trg_consent_grant_matches_offer IMMEDIATE"
        )

        before_write(AcceptWriteCheckpoint.SESSION_PREDECESSOR_REVOKE)
        revoked = connection.execute(
            "UPDATE iam.sessions SET status='REVOKED',revoked_at=%s,"
            "revocation_reason_code='INVITATION_ACCEPT_ROTATION',"
            "aggregate_version=aggregate_version+1,updated_at=%s "
            "WHERE id=%s AND status='ACTIVE' AND aggregate_version=%s "
            "RETURNING id",
            (
                now,
                now,
                request.scope.session_id,
                plan.session.aggregate_version,
            ),
        ).fetchone()
        if revoked is None:
            raise IamError("AUTHENTICATION_REQUIRED")
        before_write(AcceptWriteCheckpoint.SESSION_FAMILY_ROTATE)
        family_generation = connection.execute(
            "UPDATE iam.session_families SET current_generation=current_generation+1,"
            "aggregate_version=aggregate_version+1,updated_at=%s "
            "WHERE id=%s AND status='ACTIVE' AND current_generation=%s "
            "AND aggregate_version=%s RETURNING current_generation",
            (
                now,
                request.scope.session_family_id,
                plan.session.generation,
                plan.family_aggregate_version,
            ),
        ).fetchone()
        if family_generation is None:
            raise IamError("AUTHENTICATION_REQUIRED")
        before_write(AcceptWriteCheckpoint.SESSION_SUCCESSOR_INSERT)
        idle_expires_at = min(
            now + SESSION_IDLE_TTL,
            plan.session.absolute_expires_at,
        )
        connection.execute(
            "INSERT INTO iam.sessions ("
            "id,user_id,family_id,generation,predecessor_session_id,handle_digest,"
            "handle_digest_key_id,csrf_salt,csrf_key_id,csrf_digest,"
            "verified_contact_point_id,verified_at,verified_for_invitation_id,"
            "auth_transaction_id,auth_time,acr_code,amr_codes,created_at,"
            "last_activity_at,idle_expires_at,absolute_expires_at,updated_at,"
            "device_label,status,rotation_reason,revoked_at,revocation_reason_code,"
            "aggregate_version) VALUES ("
            "%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,NULL,NULL,NULL,NULL,%s,%s,%s,"
            "%s,%s,%s,%s,%s,%s,'ACTIVE','INVITATION_ACCEPT',NULL,NULL,1)",
            (
                request.successor.session_id,
                request.scope.actor_user_id,
                request.scope.session_family_id,
                family_generation[0],
                request.scope.session_id,
                request.successor.handle_digest,
                request.successor.handle_digest_key_id,
                request.successor.csrf_salt,
                request.successor.csrf_key_id,
                request.successor.csrf_digest,
                plan.session.auth_time,
                plan.session.acr_code,
                list(plan.session.amr_codes),
                now,
                now,
                idle_expires_at,
                plan.session.absolute_expires_at,
                now,
                plan.session.device_label,
            ),
        )

        canonical_me = _read_acceptance_me_snapshot(connection, now=now)
        safe_response = _safe_response(
            request=request,
            plan=plan,
            invitation_version=invitation_version[0],
            activated_scope=activated_scope,
            me=canonical_me,
        )
        self._validate_response(safe_response)
        if not _response_matches_request(safe_response, request):
            raise IamError("SERVICE_UNAVAILABLE")
        before_write(AcceptWriteCheckpoint.AUDIT_EVENT_INSERT)
        connection.execute(
            "INSERT INTO audit.audit_events ("
            "event_id,occurred_at,actor_kind,actor_id,original_actor_id,action_code,"
            "target_kind,target_id,organization_id,before_status,after_status,"
            "before_version,after_version,role_code,purpose_code,reason_code,"
            "auth_strength_code,result_code,command_id,correlation_id,causation_id,"
            "trace_id,safe_attributes) VALUES ("
            "%s,%s,'USER',%s,NULL,'AcceptAccessInvitation','AccessInvitation',%s,%s,"
            "'ISSUED','ACCEPTED',%s,%s,%s,%s,NULL,%s,'SUCCEEDED',%s,%s,%s,%s,%s)",
            (
                request.generated_ids.audit_event_id,
                now,
                request.scope.actor_user_id,
                request.scope.invitation_id,
                request.scope.organization_id,
                request.expected_invitation_version,
                invitation_version[0],
                plan.invitation.target_role,
                plan.invitation.purpose,
                plan.session.acr_code,
                request.scope.command_id,
                request.scope.correlation_id,
                request.scope.command_id,
                request.scope.trace_id,
                Jsonb({"activated_scope": activated_scope}),
            ),
        )

        if len(events) != len(request.generated_ids.outbox_event_ids):
            raise IamError("SERVICE_UNAVAILABLE")
        for ordinal, event in enumerate(events):
            envelope = _event_envelope(
                request=request,
                event_id=request.generated_ids.outbox_event_ids[ordinal],
                event=event,
                occurred_at=now,
            )
            self._validate_event(envelope)
            before_write(AcceptWriteCheckpoint.OUTBOX_EVENT_INSERT)
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
                    request.generated_ids.outbox_event_ids[ordinal],
                    event.event_type,
                    now,
                    event.aggregate_type,
                    event.aggregate_id,
                    event.aggregate_version,
                    request.scope.actor_user_id,
                    request.scope.correlation_id,
                    request.scope.command_id,
                    request.scope.trace_id,
                    request.scope.organization_id,
                    Jsonb(event.payload),
                    now,
                    now,
                ),
            )

        before_write(AcceptWriteCheckpoint.COMMAND_RECEIPT_COMPLETE)
        completed = connection.execute(
            "UPDATE infra.command_receipts SET status='COMPLETED',"
            "response_schema_version=1,safe_response_body=%s,"
            "reconstruction_metadata=NULL,completed_at=%s WHERE id=%s "
            "AND status='IN_PROGRESS' RETURNING id",
            (Jsonb(safe_response), now, request.receipt.receipt_id),
        ).fetchone()
        if completed is None:
            raise IamError("SERVICE_UNAVAILABLE")
        return AcceptAccessInvitationDatabaseResult(
            replayed=False,
            safe_response=safe_response,
            successor_session_id=request.successor.session_id,
        )

    def _resolve_receipt_replay(
        self,
        connection: Any,
        request: AcceptAccessInvitationDatabaseRequest,
    ) -> AcceptAccessInvitationDatabaseResult:
        rows = connection.execute(
            "SELECT payload_hash,payload_hash_key_id,canonicalization_version,"
            "status,safe_response_body,retain_until FROM infra.command_receipts "
            "WHERE principal_kind='USER' AND principal_id=%s "
            "AND command_name='AcceptAccessInvitation' AND command_version=1 "
            "AND idempotency_key_digest_key_id=%s AND idempotency_key_digest=%s "
            "ORDER BY id FOR UPDATE",
            (
                request.receipt.principal_id,
                request.receipt.idempotency_key_digest_key_id,
                request.receipt.idempotency_key_digest,
            ),
        ).fetchall()
        if len(rows) != 1:
            raise IamError("SERVICE_UNAVAILABLE")
        row = rows[0]
        if (
            bytes(row[0]) != request.receipt.payload_hash
            or row[1] != request.receipt.payload_hash_key_id
            or row[2] != request.receipt.canonicalization_version
        ):
            raise IamError("IDEMPOTENCY_KEY_REUSED")
        if row[3] != "COMPLETED" or not isinstance(row[4], dict):
            raise IamError("SERVICE_UNAVAILABLE")
        now = _read_transaction_timestamp_utc(connection)
        if row[5] <= now:
            raise IamError("SERVICE_UNAVAILABLE")
        self._validate_response(row[4])
        if not _response_matches_request(row[4], request):
            raise IamError("SERVICE_UNAVAILABLE")
        return AcceptAccessInvitationDatabaseResult(
            replayed=True,
            safe_response=row[4],
            successor_session_id=None,
        )

    def _validate_event(self, envelope: Mapping[str, Any]) -> None:
        try:
            self.event_validator.validate(envelope)
        except (AssertionError, TypeError, ValueError) as error:
            raise IamError("SERVICE_UNAVAILABLE") from error

    def _validate_response(self, response: Mapping[str, Any]) -> None:
        try:
            self.response_validator.validate(
                response,
                "AccessInvitationAcceptanceDto",
            )
        except (AssertionError, TypeError, ValueError) as error:
            raise IamError("SERVICE_UNAVAILABLE") from error

    def _load_and_validate_plan(
        self,
        connection: Any,
        request: AcceptAccessInvitationDatabaseRequest,
        now: datetime,
    ) -> "_AcceptPlan":
        family_row = connection.execute(
            "SELECT status,current_generation,aggregate_version "
            "FROM iam.session_families WHERE id=%s AND user_id=%s FOR UPDATE",
            (request.scope.session_family_id, request.scope.actor_user_id),
        ).fetchone()
        if family_row is None or family_row[0] != "ACTIVE":
            raise IamError("AUTHENTICATION_REQUIRED")

        session_row = connection.execute(
            "SELECT user_id,family_id,generation,verified_contact_point_id,"
            "verified_for_invitation_id,auth_transaction_id,auth_time,acr_code,"
            "amr_codes,created_at,last_activity_at,idle_expires_at,"
            "absolute_expires_at,device_label,status,aggregate_version "
            "FROM iam.sessions WHERE id=%s FOR UPDATE",
            (request.scope.session_id,),
        ).fetchone()
        if session_row is None:
            raise IamError("AUTHENTICATION_REQUIRED")
        session = _SessionFacts(*session_row)
        if (
            session.user_id != request.scope.actor_user_id
            or session.family_id != request.scope.session_family_id
            or session.status != "ACTIVE"
            or family_row[1] != session.generation
            or now >= session.idle_expires_at
            or now >= session.absolute_expires_at
        ):
            raise IamError("AUTHENTICATION_REQUIRED")

        invitation_row = connection.execute(
            "SELECT purpose,organization_id,target_scope,target_role,is_initial_admin,"
            "recipient_contact_id,masked_recipient_label,policy_selector_digest,"
            "issued_policy_bundle_id,status,expires_at,aggregate_version,created_at "
            "FROM iam.access_invitations WHERE id=%s FOR UPDATE",
            (request.scope.invitation_id,),
        ).fetchone()
        if invitation_row is None:
            raise IamError("ACCESS_INVITATION_UNAVAILABLE")
        invitation = _InvitationFacts(*invitation_row)
        if (
            invitation.status != "ISSUED"
            or invitation.aggregate_version != request.expected_invitation_version
            or now >= invitation.expires_at
            or invitation.organization_id != request.scope.organization_id
            or bytes(invitation.policy_selector_digest)
            != request.scope.policy_selector_digest
            or invitation.target_role != request.scope.target_role
            or session.verified_for_invitation_id != request.scope.invitation_id
            or session.verified_contact_point_id != invitation.recipient_contact_id
            or session.auth_transaction_id != request.scope.auth_transaction_id
        ):
            raise IamError("ACCESS_INVITATION_UNAVAILABLE")

        contact = connection.execute(
            "SELECT user_id,verified_at FROM iam.contact_points WHERE id=%s",
            (invitation.recipient_contact_id,),
        ).fetchone()
        if contact is None or contact[0] != request.scope.actor_user_id or contact[1] is None:
            raise IamError("ACCESS_INVITATION_UNAVAILABLE")
        auth = connection.execute(
            "SELECT status,purpose,expected_user_id,invitation_id,invitation_version,"
            "expected_contact_point_id,deadline FROM iam.auth_transactions "
            "WHERE id=%s",
            (request.scope.auth_transaction_id,),
        ).fetchone()
        if (
            auth is None
            or auth[0] != "SUCCEEDED"
            or auth[1] not in ("ENROLLMENT", "STEP_UP")
            or auth[2] not in (None, request.scope.actor_user_id)
            or auth[3] != request.scope.invitation_id
            or auth[4] != request.expected_invitation_version
            or auth[5] != invitation.recipient_contact_id
            or now >= auth[6]
        ):
            raise IamError("ACCESS_INVITATION_UNAVAILABLE")

        user_row = connection.execute(
            "SELECT status,display_handle,aggregate_version FROM iam.users "
            "WHERE id=%s FOR UPDATE",
            (request.scope.actor_user_id,),
        ).fetchone()
        if user_row is None or user_row[0] not in ("PENDING_ENROLLMENT", "ACTIVE"):
            raise IamError("ACCESS_INVITATION_UNAVAILABLE")
        user = _UserFacts(user_row[0], user_row[1], user_row[2])

        if invitation.target_role == "CREATOR":
            if (
                invitation.purpose != "CREATOR_ENROLLMENT"
                or invitation.target_scope != "USER"
                or invitation.organization_id is not None
                or invitation.is_initial_admin
                or user.status != "PENDING_ENROLLMENT"
            ):
                raise IamError("ACCESS_INVITATION_UNAVAILABLE")
        else:
            if (
                invitation.purpose != "ORGANIZATION_MEMBERSHIP"
                or invitation.target_scope != "ORGANIZATION"
                or invitation.target_role not in ("ORG_ADMIN", "DEMAND_OWNER")
                or invitation.organization_id is None
                or (
                    invitation.is_initial_admin
                    and invitation.target_role != "ORG_ADMIN"
                )
            ):
                raise IamError("ACCESS_INVITATION_UNAVAILABLE")

        organization: Optional[_OrganizationFacts] = None
        if invitation.organization_id is not None:
            organization_row = connection.execute(
                "SELECT organization_type,public_name,status,aggregate_version "
                "FROM iam.organizations "
                "WHERE id=%s FOR UPDATE",
                (invitation.organization_id,),
            ).fetchone()
            expected_organization_status = (
                "PENDING_ADMIN" if invitation.is_initial_admin else "ACTIVE"
            )
            if (
                organization_row is None
                or organization_row[2] != expected_organization_status
            ):
                raise IamError("ACCESS_INVITATION_UNAVAILABLE")
            organization = _OrganizationFacts(*organization_row)

        try:
            locked_graph = connection.execute(
                "SELECT * FROM iam.lock_accept_policy_graph_v1(%s,%s,%s)",
                (
                    request.scope.invitation_id,
                    request.scope.policy_selector_digest,
                    request.scope.policy_bundle_id,
                ),
            ).fetchall()
        except DatabaseError as error:
            if (
                error.sqlstate == "55000"
                and error.diag.constraint_name
                in (
                    "ck_accept_policy_lock_selector",
                    "ck_accept_policy_lock_bundle",
                )
            ):
                raise IamError("POLICY_CONFIGURATION_UNAVAILABLE") from error
            raise
        if len(locked_graph) != 1 or len(locked_graph[0]) != 9:
            raise IamError("POLICY_CONFIGURATION_UNAVAILABLE")
        graph = locked_graph[0]
        expected_scope = (
            "USER_ROLE"
            if invitation.target_role == "CREATOR"
            else "ORGANIZATION_ROLE"
        )
        if (
            graph[0] != invitation.purpose
            or graph[1] != expected_scope
            or graph[2] != invitation.target_role
        ):
            raise IamError("POLICY_CONFIGURATION_UNAVAILABLE")
        if graph[3] != request.scope.policy_bundle_id:
            raise IamError("POLICY_BUNDLE_CHANGED")
        if (
            graph[4] != "ACTIVE"
            or graph[5] is None
            or graph[5] > now
            or (graph[6] is not None and now >= graph[6])
        ):
            raise IamError("POLICY_BUNDLE_CHANGED")

        try:
            document_rows = graph[7]
            offer_rows = graph[8]
            if not isinstance(document_rows, list) or not isinstance(offer_rows, list):
                raise TypeError
            bundle_documents = {
                UUID(row["document_id"]): _PolicyDocument(
                    UUID(row["document_id"]),
                    bytes.fromhex(row["content_sha256"]),
                    row["status"],
                    row["kind"],
                    row["legal_effect"],
                    row["required"],
                    row["position"],
                )
                for row in document_rows
            }
        except (KeyError, TypeError, ValueError) as error:
            raise IamError("POLICY_CONFIGURATION_UNAVAILABLE") from error
        if (
            len(bundle_documents) != len(document_rows)
            or any(
                document.status != "ACTIVE"
                or len(document.content_hash) != 32
                or not isinstance(document.required, bool)
                or not isinstance(document.position, int)
                or document.position < 1
                for document in bundle_documents.values()
            )
            or len({document.position for document in bundle_documents.values()})
            != len(bundle_documents)
        ):
            raise IamError("POLICY_CONFIGURATION_UNAVAILABLE")
        policy_documents = {
            document_id: document
            for document_id, document in bundle_documents.items()
            if document.required
        }
        if not policy_documents:
            raise IamError("POLICY_CONFIGURATION_UNAVAILABLE")
        choices = {choice.document_id: choice for choice in request.policy_acceptances}
        if set(choices) != set(policy_documents):
            raise IamError("POLICY_ACCEPTANCE_REQUIRED")
        for document_id, document in policy_documents.items():
            if choices[document_id].content_sha256 != document.content_hash:
                raise IamError("POLICY_BUNDLE_CHANGED")
        authorizations: Dict[UUID, _ConsentAuthorization] = {}
        if len({choice.consent_offer_id for choice in request.consent_choices}) != len(
            request.consent_choices
        ):
            raise IamError("CONSENT_CHOICE_INVALID")
        try:
            locked_offers = {
                UUID(row["consent_offer_id"]): row for row in offer_rows
            }
        except (KeyError, TypeError, ValueError) as error:
            raise IamError("POLICY_CONFIGURATION_UNAVAILABLE") from error
        if len(locked_offers) != len(offer_rows):
            raise IamError("POLICY_CONFIGURATION_UNAVAILABLE")
        for choice in request.consent_choices:
            offer = locked_offers.get(choice.consent_offer_id)
            if (
                offer is None
                or offer.get("document_id") != str(choice.document_id)
                or offer.get("document_content_sha256")
                != choice.content_sha256.hex()
                or offer.get("scope_derivation")
                != "PLATFORM_PARTICIPATION_NULL_SCOPE"
                or offer.get("expiry_rule")
                != "EARLIER_OF_GRANTED_AT_PLUS_365_DAYS_OR_NOT_AFTER"
                or not isinstance(offer.get("expiry_days"), int)
                or not isinstance(offer.get("not_after"), str)
                or not isinstance(offer.get("categories"), list)
                or offer.get("optional") is not True
                or offer.get("supporting_document_status") != "ACTIVE"
                or offer.get("supporting_document_kind") != "CONSENT_TEXT"
                or offer.get("supporting_document_legal_effect") != "CONSENT_TEXT"
            ):
                raise IamError("CONSENT_CHOICE_INVALID")
            try:
                not_after = _parse_utc_timestamp(offer["not_after"])
                document_id = UUID(offer["document_id"])
                document_hash = bytes.fromhex(
                    offer["document_content_sha256"]
                )
                canonical_offer_hash = bytes.fromhex(
                    offer["canonical_offer_sha256"]
                )
                categories = tuple(offer["categories"])
            except (KeyError, TypeError, ValueError) as error:
                raise IamError("CONSENT_CHOICE_INVALID") from error
            supporting_document = bundle_documents.get(document_id)
            try:
                canonical_offer = ConsentOffer(
                    consent_offer_id=str(choice.consent_offer_id),
                    aggregate_version=offer["offer_version"],
                    purpose=ConsentPurpose(offer["purpose"]),
                    scope_type=ConsentScopeType(offer["scope_type"]),
                    data_categories=tuple(DataCategory(item) for item in categories),
                    supporting_document_id=str(document_id),
                    supporting_document_sha256=document_hash.hex(),
                    recipient_reference=offer["recipient_ref"],
                    pilot_ends_at=not_after,
                    policy_bundle_id=str(request.scope.policy_bundle_id),
                    recipient_label=offer["recipient_label"],
                    canonical_offer_sha256=canonical_offer_hash.hex(),
                )
                actual_offer_hash = hashlib.sha256(
                    canonical_consent_offer_bytes(canonical_offer)
                ).digest()
            except (IamError, KeyError, TypeError, ValueError) as error:
                raise IamError("POLICY_CONFIGURATION_UNAVAILABLE") from error
            if len(canonical_offer_hash) != 32 or not hmac.compare_digest(
                canonical_offer_hash,
                actual_offer_hash,
            ):
                raise IamError("POLICY_CONFIGURATION_UNAVAILABLE")
            if (
                supporting_document is None
                or supporting_document.status != "ACTIVE"
                or supporting_document.kind != "CONSENT_TEXT"
                or supporting_document.legal_effect != "CONSENT_TEXT"
                or supporting_document.content_hash != document_hash
                or not all(isinstance(category, str) for category in categories)
                or not categories
            ):
                raise IamError("CONSENT_CHOICE_INVALID")
            expires_at = min(
                now + timedelta(days=offer["expiry_days"]),
                not_after,
            )
            authorizations[choice.consent_offer_id] = _ConsentAuthorization(
                offer_id=choice.consent_offer_id,
                offer_version=offer["offer_version"],
                purpose=offer["purpose"],
                scope_type=offer["scope_type"],
                scope_id=None,
                recipient_ref=offer["recipient_ref"],
                recipient_label=offer["recipient_label"],
                document_id=document_id,
                document_hash=document_hash,
                expires_at=expires_at,
                not_after=not_after,
                expiry_days=offer["expiry_days"],
                categories=categories,
            )
        return _AcceptPlan(
            user=user,
            organization=organization,
            invitation=invitation,
            session=session,
            family_aggregate_version=family_row[2],
            policy_documents=policy_documents,
            consent_authorizations=authorizations,
        )

    def _release_or_discard(self, connection: Any) -> bool:
        try:
            if not _connection_is_idle(connection):
                self.connections.discard(connection)
                return True
            connection.execute("RESET ALL")
            identity = connection.execute(
                "SELECT current_user,session_user"
            ).fetchone()
            if identity != (self.settings.runtime_role, self.settings.runtime_role):
                self.connections.discard(connection)
                return True
        except BaseException:
            self.connections.discard(connection)
            return True
        self.connections.release(connection)
        return True


@dataclass(frozen=True)
class _UserFacts:
    status: str
    display_handle: str
    aggregate_version: int


@dataclass(frozen=True)
class _OrganizationFacts:
    organization_type: str
    public_name: str
    status: str
    aggregate_version: int


@dataclass(frozen=True)
class _InvitationFacts:
    purpose: str
    organization_id: Optional[UUID]
    target_scope: str
    target_role: str
    is_initial_admin: bool
    recipient_contact_id: UUID
    masked_recipient_label: str
    policy_selector_digest: bytes = field(repr=False)
    issued_policy_bundle_id: UUID
    status: str
    expires_at: datetime
    aggregate_version: int
    created_at: datetime


@dataclass(frozen=True)
class _SessionFacts:
    user_id: UUID
    family_id: UUID
    generation: int
    verified_contact_point_id: Optional[UUID]
    verified_for_invitation_id: Optional[UUID]
    auth_transaction_id: Optional[UUID]
    auth_time: datetime
    acr_code: str
    amr_codes: Tuple[str, ...]
    created_at: datetime
    last_activity_at: datetime
    idle_expires_at: datetime
    absolute_expires_at: datetime
    device_label: str
    status: str
    aggregate_version: int


@dataclass(frozen=True)
class _PolicyDocument:
    document_id: UUID
    content_hash: bytes = field(repr=False)
    status: str
    kind: str
    legal_effect: str
    required: bool
    position: int


@dataclass(frozen=True)
class _ConsentAuthorization:
    offer_id: UUID
    offer_version: int
    purpose: str
    scope_type: str
    scope_id: Optional[UUID]
    recipient_ref: str
    recipient_label: str
    document_id: UUID
    document_hash: bytes = field(repr=False)
    expires_at: datetime
    not_after: datetime
    expiry_days: int
    categories: Tuple[str, ...]


@dataclass(frozen=True)
class _AcceptPlan:
    user: _UserFacts
    organization: Optional[_OrganizationFacts]
    invitation: _InvitationFacts
    session: _SessionFacts
    family_aggregate_version: int
    policy_documents: Mapping[UUID, _PolicyDocument]
    consent_authorizations: Mapping[UUID, _ConsentAuthorization]


@dataclass(frozen=True)
class _OutboxRecord:
    event_type: str
    aggregate_type: str
    aggregate_id: UUID
    aggregate_version: int
    payload: Mapping[str, Any] = field(repr=False)


def _transaction_context(
    request: AcceptAccessInvitationDatabaseRequest,
) -> Tuple[Tuple[str, str], ...]:
    values = [
        ("app.scope_kind", "AUTH_PROTOCOL"),
        ("app.operation", "ACCEPT"),
        ("app.actor_user_id", str(request.scope.actor_user_id)),
        ("app.target_user_id", str(request.scope.actor_user_id)),
        ("app.target_invitation_id", str(request.scope.invitation_id)),
        ("app.session_id", str(request.scope.session_id)),
        ("app.session_family_id", str(request.scope.session_family_id)),
        ("app.auth_transaction_id", str(request.scope.auth_transaction_id)),
        ("app.policy_selector_digest", request.scope.policy_selector_digest.hex()),
        ("app.policy_bundle_id", str(request.scope.policy_bundle_id)),
        ("app.command_id", str(request.scope.command_id)),
        ("app.command_name", "AcceptAccessInvitation"),
        ("app.command_version", "1"),
        (
            "app.idempotency_key_digest_key_id",
            request.receipt.idempotency_key_digest_key_id,
        ),
        ("app.idempotency_key_digest", request.receipt.idempotency_key_digest.hex()),
    ]
    if request.scope.organization_id is not None:
        values.append(("app.organization_id", str(request.scope.organization_id)))
    return tuple(values)


def _event_envelope(
    *,
    request: AcceptAccessInvitationDatabaseRequest,
    event_id: UUID,
    event: _OutboxRecord,
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
        "causation_id": str(request.scope.command_id),
        "trace_id": str(request.scope.trace_id),
        "organization_id": (
            str(request.scope.organization_id)
            if request.scope.organization_id is not None
            else None
        ),
        "payload": dict(event.payload),
    }


def _response_matches_request(
    response: Mapping[str, Any],
    request: AcceptAccessInvitationDatabaseRequest,
) -> bool:
    return _acceptance_response_has_exact_authority(
        response,
        actor_user_id=request.scope.actor_user_id,
        invitation_id=request.scope.invitation_id,
        expected_version=request.expected_invitation_version,
        policy_selector_digest=request.scope.policy_selector_digest,
        policy_bundle_id=request.scope.policy_bundle_id,
        target_role=request.scope.target_role,
        organization_id=request.scope.organization_id,
    )


def _acceptance_response_has_exact_authority(
    response: Mapping[str, Any],
    *,
    actor_user_id: UUID,
    invitation_id: UUID,
    expected_version: int,
    policy_selector_digest: bytes,
    policy_bundle_id: UUID,
    target_role: str,
    organization_id: Optional[UUID],
) -> bool:
    """Return whether an Accept response contains the exact new authority.

    Schema validation closes the DTO shape separately.  This pure semantic
    guard binds the successful projection to the command and requires the one
    satisfied policy requirement that authorizes the authority just created.
    """

    if (
        not isinstance(response, Mapping)
        or not isinstance(actor_user_id, UUID)
        or actor_user_id.int == 0
        or not isinstance(invitation_id, UUID)
        or invitation_id.int == 0
        or type(expected_version) is not int
        or expected_version < 1
        or not isinstance(policy_selector_digest, bytes)
        or len(policy_selector_digest) != 32
        or not isinstance(policy_bundle_id, UUID)
        or policy_bundle_id.int == 0
        or target_role not in {"CREATOR", "ORG_ADMIN", "DEMAND_OWNER"}
        or (target_role == "CREATOR") != (organization_id is None)
        or (
            organization_id is not None
            and (not isinstance(organization_id, UUID) or organization_id.int == 0)
        )
    ):
        return False
    try:
        invitation = response["invitation"]
        me = response["me"]
        requirements = me["policy_requirements"]
        if (
            not isinstance(invitation, Mapping)
            or not isinstance(me, Mapping)
            or not isinstance(requirements, list)
            or any(not isinstance(item, Mapping) for item in requirements)
        ):
            return False
        purpose = (
            "CREATOR_ENROLLMENT"
            if target_role == "CREATOR"
            else "ORGANIZATION_MEMBERSHIP"
        )
        activated_scope = (
            "USER_ROLE" if target_role == "CREATOR" else "ORGANIZATION_MEMBERSHIP"
        )
        requirement_scope = (
            "USER_ROLE" if target_role == "CREATOR" else "ORGANIZATION_ROLE"
        )
        organization_text = (
            None if organization_id is None else str(organization_id)
        )
        if not (
            response["activated_scope"] == activated_scope
            and invitation["invitation_id"] == str(invitation_id)
            and invitation["purpose"] == purpose
            and invitation["organization_id"] == organization_text
            and invitation["target_role"] == target_role
            and invitation["status"] == "ACCEPTED"
            and invitation["required_policy_bundle_id"] == str(policy_bundle_id)
            and type(invitation["aggregate_version"]) is int
            and invitation["aggregate_version"] == expected_version + 1
            and me["user_id"] == str(actor_user_id)
            and me["status"] == "ACTIVE"
        ):
            return False
        exact_requirements = [
            requirement
            for requirement in requirements
            if requirement.get("selector_digest") == policy_selector_digest.hex()
            and requirement.get("purpose") == purpose
            and requirement.get("role") == target_role
            and requirement.get("scope_type") == requirement_scope
            and requirement.get("scope_id") == organization_text
            and requirement.get("satisfied") is True
            and requirement.get("required_policy_bundle_id")
            == str(policy_bundle_id)
            and requirement.get("missing_document_ids") == []
        ]
        if len(exact_requirements) != 1:
            return False
        if target_role == "CREATOR":
            user_roles = me["user_roles"]
            return isinstance(user_roles, list) and "CREATOR" in user_roles
        memberships = me["memberships"]
        if not isinstance(memberships, list):
            return False
        return any(
            isinstance(membership, Mapping)
            and membership.get("status") == "ACTIVE"
            and isinstance(membership.get("roles"), list)
            and target_role in membership["roles"]
            and isinstance(membership.get("organization"), Mapping)
            and membership["organization"].get("organization_id")
            == organization_text
            and membership["organization"].get("status") == "ACTIVE"
            for membership in memberships
        )
    except (KeyError, TypeError):
        return False


def _existing_consent_matches(
    row: Tuple[Any, ...],
    category_rows: List[Tuple[str, int]],
    authorization: _ConsentAuthorization,
    policy_bundle_id: UUID,
    now: datetime,
) -> bool:
    expected_expiry = min(
        row[11] + timedelta(days=authorization.expiry_days),
        authorization.not_after,
    )
    return (
        row[1] == authorization.offer_id
        and row[2] == authorization.offer_version
        and row[3] == policy_bundle_id
        and row[4] == authorization.purpose
        and row[5] == authorization.scope_type
        and row[6] == authorization.scope_id
        and row[7] == authorization.recipient_ref
        and row[8] == authorization.recipient_label
        and row[9] == authorization.document_id
        and hmac.compare_digest(bytes(row[10]), authorization.document_hash)
        and row[12] == expected_expiry
        and row[12] > now
        and row[13] == "ACTIVE"
        and category_rows
        == [
            (category, position)
            for position, category in enumerate(authorization.categories, start=1)
        ]
    )


def _safe_response(
    *,
    request: AcceptAccessInvitationDatabaseRequest,
    plan: _AcceptPlan,
    invitation_version: int,
    activated_scope: str,
    me: Mapping[str, Any],
) -> Dict[str, Any]:
    organization_id = request.scope.organization_id
    return {
        "invitation": {
            "invitation_id": str(request.scope.invitation_id),
            "purpose": plan.invitation.purpose,
            "organization_id": str(organization_id) if organization_id else None,
            "target_role": plan.invitation.target_role,
            "masked_recipient_label": plan.invitation.masked_recipient_label,
            "is_initial_admin": plan.invitation.is_initial_admin,
            "status": "ACCEPTED",
            "expires_at": _timestamp(plan.invitation.expires_at),
            "created_at": _timestamp(plan.invitation.created_at),
            "required_policy_bundle_id": str(request.scope.policy_bundle_id),
            "aggregate_version": invitation_version,
            "entity_tag": '"v%d"' % invitation_version,
        },
        "me": dict(me),
        "activated_scope": activated_scope,
    }


def _read_acceptance_me_snapshot(
    connection: Any,
    *,
    now: datetime,
) -> Mapping[str, Any]:
    rows = connection.execute(
        "SELECT iam_api.read_acceptance_me_snapshot_v2()"
    ).fetchall()
    if (
        len(rows) != 1
        or len(rows[0]) != 1
        or not isinstance(rows[0][0], Mapping)
        or set(rows[0][0])
        != {
            "user",
            "user_role_grants",
            "memberships",
            "source_invitations",
            "policies",
            "acceptances",
        }
    ):
        raise IamError("SERVICE_UNAVAILABLE")
    try:
        return project_canonical_me_dto(rows[0][0], at=now)
    except (IamError, KeyError, TypeError, ValueError) as error:
        raise IamError("SERVICE_UNAVAILABLE") from error


def _read_transaction_timestamp_utc(connection: Any) -> datetime:
    row = connection.execute("SELECT transaction_timestamp()").fetchone()
    try:
        value = row[0] if row is not None and len(row) == 1 else None
        return parse_offset_timestamp(value)
    except (IndexError, TypeError, ValueError) as error:
        raise AcceptPostgresConfigurationError(
            "Accept database transaction timestamp is unavailable"
        ) from error


def _timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_utc_timestamp(value: str) -> datetime:
    return parse_offset_timestamp(value)


def _connection_is_idle(connection: Any) -> bool:
    return connection.info.transaction_status == TransactionStatus.IDLE


def _is_retryable_precommit_error(error: BaseException) -> bool:
    if isinstance(error, AcceptCommandOutcomeUnknownError):
        return False
    return getattr(error, "sqlstate", None) in ("40001", "40P01", "55P03")


def _require_digest(value: bytes, label: str) -> None:
    if not isinstance(value, bytes) or len(value) != 32:
        raise ValueError("%s must be exactly 32 bytes" % label)


def _require_utc(value: datetime, label: str) -> None:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() != timedelta(0)
    ):
        raise ValueError("%s must be an aware UTC datetime" % label)
