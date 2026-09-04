"""Real PostgreSQL 18 semantic RED for the Accept business Unit of Work.

Migration and fixture failures are not accepted RED reasons.  Each test first
installs v0-v7 and commits a constraint-valid graph; the expected failures are
therefore the missing production repository/transaction semantics.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from collections import Counter
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import threading
from typing import Any, Dict, Iterable, Optional, Tuple
import unittest
import uuid

import psycopg
from psycopg import sql
from psycopg.types.json import Jsonb

from desire_platform.identity_access.adapters.postgres.accept_access_invitation import (
    ACCEPT_WRITE_CHECKPOINTS,
    POSTGRES_ACCEPT_BEHAVIOR_NOT_AVAILABLE,
    AcceptAccessInvitationDatabaseRequest,
    AcceptCommandOutcomeUnknownError,
    AcceptConnectionSource,
    AcceptConsentOfferChoice,
    AcceptExecutionScope,
    AcceptGeneratedIds,
    AcceptHoldEvidence,
    AcceptPolicyAcceptanceChoice,
    AcceptPostgresConfigurationError,
    AcceptPostgresSettings,
    AcceptPostgresBehaviorNotAvailable,
    AcceptReceiptIdentity,
    AcceptSessionSuccessorFacts,
    AcceptWriteCheckpoint,
    PsycopgAcceptAccessInvitationUnitOfWorkFactory,
)
from desire_platform.identity_access.adapters.postgres.organization_admin_accept import (
    PsycopgOrganizationAcceptScopeResolver,
)
from desire_platform.identity_access.adapters.postgres.read_models import (
    PsycopgIamReadModelRepository,
)
from desire_platform.identity_access.application.read_models import (
    project_canonical_me_dto,
)
from desire_platform.identity_access.adapters.postgres.migrations import (
    IamContractSources,
    IamMigrationRunner,
    MigrationCatalog,
    PsycopgMigrationDriver,
    PsycopgMigrationSettings,
)
from desire_platform.identity_access.domain.errors import IamError
from desire_platform.identity_access.domain.policies import (
    ConsentOffer,
    canonical_consent_offer_bytes,
)
from tests.storage.postgres.postgres18_harness import TemporaryPostgres18
from tests.support.iam_authority_lifecycle_builders import ClosedSchemaValidator


PLATFORM_ROOT = Path(__file__).resolve().parents[3]
MIGRATION_ROOT = (
    PLATFORM_ROOT
    / "src/desire_platform/identity_access/adapters/postgres/migrations"
)
IAM40_MIGRATION = (
    MIGRATION_ROOT / "0040_expand__invitation_enrollment_acceptance.sql"
)

RAW_IDEMPOTENCY_SENTINEL = "raw-idempotency-DO-NOT-PERSIST-7f6c"
RAW_SESSION_SENTINEL = "raw-session-DO-NOT-PERSIST-02bb"
RAW_CSRF_SENTINEL = "raw-csrf-DO-NOT-PERSIST-8aae"
RAW_CONTACT_SENTINEL = "raw-contact-DO-NOT-PERSIST@example.invalid"
RAW_SUBJECT_SENTINEL = "raw-subject-DO-NOT-PERSIST-9d31"
RAW_CONSENT_SENTINEL = "raw-consent-evidence-DO-NOT-PERSIST-cc10"
RAW_SENTINELS = (
    RAW_IDEMPOTENCY_SENTINEL,
    RAW_SESSION_SENTINEL,
    RAW_CSRF_SENTINEL,
    RAW_CONTACT_SENTINEL,
    RAW_SUBJECT_SENTINEL,
    RAW_CONSENT_SENTINEL,
)


def _digest(label: str) -> bytes:
    return hashlib.sha256(label.encode("utf-8")).digest()


def _selector_digest(*, purpose: str, scope_type: str, role: str) -> bytes:
    canonical = json.dumps(
        {
            "access_purpose": purpose,
            "scope_type": scope_type,
            "target_role": role,
            "jurisdiction": "CN",
            "locale": "zh-CN",
        },
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(canonical).digest()


def _new_id() -> uuid.UUID:
    return uuid.uuid4()


@dataclass(frozen=True)
class PolicyFixture:
    selector_digest: bytes
    bundle_id: uuid.UUID
    required_document_id: uuid.UUID
    required_document_hash: bytes
    consent_document_id: uuid.UUID
    consent_document_hash: bytes
    consent_offer_id: uuid.UUID


@dataclass(frozen=True)
class AcceptFixture:
    kind: str
    actor_id: uuid.UUID
    contact_id: uuid.UUID
    invitation_id: uuid.UUID
    organization_id: Optional[uuid.UUID]
    auth_transaction_id: uuid.UUID
    session_family_id: uuid.UUID
    session_id: uuid.UUID
    policy: PolicyFixture


@dataclass(frozen=True)
class PersistenceUnavailableOutcome:
    behavior_not_available: bool = True
    replayed: bool = False
    safe_response: Optional[Dict[str, Any]] = None
    successor_session_id: Optional[uuid.UUID] = None


class InjectedAcceptWriteFailure(RuntimeError):
    pass


class LateProtectedWriteRejected(RuntimeError):
    pass


class RaiseAtLogicalWrite:
    def __init__(self, target: Tuple[AcceptWriteCheckpoint, int]) -> None:
        self.target = target
        self._ordinals: Dict[AcceptWriteCheckpoint, int] = {}

    def before_write(
        self,
        checkpoint: AcceptWriteCheckpoint,
        ordinal: int,
    ) -> None:
        expected = self._ordinals.get(checkpoint, 0)
        if ordinal != expected:
            raise AssertionError("checkpoint ordinals must be contiguous")
        self._ordinals[checkpoint] = expected + 1
        if (checkpoint, ordinal) == self.target:
            raise InjectedAcceptWriteFailure(checkpoint.value)


class BarrierAtReceiptClaim:
    def __init__(self, parties: int = 2) -> None:
        self.barrier = threading.Barrier(parties, timeout=10)
        self._worker = threading.local()

    def before_write(
        self,
        checkpoint: AcceptWriteCheckpoint,
        ordinal: int,
    ) -> None:
        if checkpoint == AcceptWriteCheckpoint.COMMAND_RECEIPT_CLAIM:
            # A pre-COMMIT retry must not wait for the already-finished winner.
            if getattr(self._worker, "claimed", False):
                return
            self._worker.claimed = True
            self.barrier.wait()


class FailFirstThreeReceiptClaims:
    def __init__(self) -> None:
        self.attempts = 0

    def before_write(
        self,
        checkpoint: AcceptWriteCheckpoint,
        ordinal: int,
    ) -> None:
        if checkpoint != AcceptWriteCheckpoint.COMMAND_RECEIPT_CLAIM:
            return
        self.attempts += 1
        if ordinal != 0:
            raise AssertionError("each retry must start a fresh write ordinal")
        if self.attempts <= 3:
            raise psycopg.errors.LockNotAvailable(
                "synthetic bounded pre-COMMIT lock conflict"
            )


class InjectWrongEvidenceAtPhaseBoundary:
    """Prove deferred evidence is forced before, and immediate after, rotation."""

    def __init__(
        self,
        *,
        source: "TrackingRealConnectionSource",
        fixture: AcceptFixture,
        request: AcceptAccessInvitationDatabaseRequest,
        late: bool,
    ) -> None:
        self.source = source
        self.fixture = fixture
        self.request = request
        self.late = late
        self.injected = False
        self.rejected_constraint: Optional[str] = None

    def before_write(
        self,
        checkpoint: AcceptWriteCheckpoint,
        ordinal: int,
    ) -> None:
        target = (
            AcceptWriteCheckpoint.SESSION_PREDECESSOR_REVOKE
            if self.late
            else AcceptWriteCheckpoint.ACCESS_INVITATION_ACCEPT
        )
        if checkpoint != target or ordinal != 0:
            return
        connection = self.source.checked_out[-1]
        try:
            cursor = connection.execute(
                "INSERT INTO iam.policy_acceptances ("
                "id,user_id,document_id,content_sha256,bundle_id,accepted_at,"
                "session_id,auth_transaction_id,auth_time,acr_code,amr_codes,"
                "source_action,command_id,correlation_id,aggregate_version,created_at"
                ") SELECT %s,user_id,%s,%s,%s,transaction_timestamp(),id,"
                "auth_transaction_id,auth_time + interval '1 second',acr_code,"
                "amr_codes,'ACCESS_INVITATION_ACCEPT',%s,%s,1,"
                "transaction_timestamp() FROM iam.sessions WHERE id=%s",
                (
                    _new_id(),
                    self.fixture.policy.consent_document_id,
                    self.fixture.policy.consent_document_hash,
                    self.fixture.policy.bundle_id,
                    self.request.scope.command_id,
                    self.request.scope.correlation_id,
                    self.fixture.session_id,
                ),
            )
        except psycopg.errors.CheckViolation as error:
            self.rejected_constraint = error.diag.constraint_name
            if not self.late:
                raise AssertionError(
                    "pre-boundary deferred evidence fired at INSERT"
                ) from error
            raise LateProtectedWriteRejected() from error
        if cursor.rowcount != 1:
            raise AssertionError("wrong-evidence fixture did not insert one row")
        self.injected = True
        if self.late:
            raise AssertionError(
                "protected write escaped the IMMEDIATE phase boundary"
            )


class CommitAcknowledgementLossConnection:
    """Commit on real PG18, then close before the adapter receives an outcome."""

    def __init__(self, connection: Any) -> None:
        self._connection = connection
        self.commit_sent = False

    def execute(self, query: Any, parameters: Any = None, *args: Any, **kwargs: Any):
        normalized = str(query).strip().upper()
        if normalized == "COMMIT":
            self.commit_sent = True
            result = self._connection.execute(query, parameters, *args, **kwargs)
            self._connection.close()
            del result
            raise psycopg.OperationalError("synthetic COMMIT acknowledgement loss")
        return self._connection.execute(query, parameters, *args, **kwargs)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._connection, name)


class TransactionTimeZoneObservationConnection:
    """Observe the transaction-local PostgreSQL timezone after it is pinned."""

    def __init__(
        self,
        connection: Any,
        observations: list[Tuple[str, datetime]],
    ) -> None:
        self._connection = connection
        self._observations = observations

    def execute(self, query: Any, parameters: Any = None, *args: Any, **kwargs: Any):
        result = self._connection.execute(query, parameters, *args, **kwargs)
        if str(query).strip().upper() == "SET LOCAL TIME ZONE 'UTC'":
            observed = self._connection.execute(
                "SELECT current_setting('TimeZone'), transaction_timestamp()"
            ).fetchone()
            self._observations.append(observed)
        return result

    def __getattr__(self, name: str) -> Any:
        return getattr(self._connection, name)


class TrackingRealConnectionSource(AcceptConnectionSource):
    def __init__(
        self,
        conninfo: str,
        *,
        lose_first_commit_ack: bool = False,
        session_timezone_name: Optional[str] = None,
    ) -> None:
        self.conninfo = conninfo
        self.lose_first_commit_ack = lose_first_commit_ack
        self.session_timezone_name = session_timezone_name
        self.checked_out: list[Any] = []
        self.backend_pids: list[int] = []
        self.released: list[Any] = []
        self.discarded: list[Any] = []
        self.observed_server_times: list[datetime] = []
        self.observed_transaction_time_zones: list[Tuple[str, datetime]] = []

    def checkout(self) -> Any:
        connection: Any = psycopg.connect(self.conninfo, autocommit=True)
        self.backend_pids.append(connection.info.backend_pid)
        if self.session_timezone_name is not None:
            connection.execute(
                "SELECT pg_catalog.set_config('TimeZone',%s,false)",
                (self.session_timezone_name,),
            ).fetchone()
            self.observed_server_times.append(
                connection.execute(
                    "SELECT transaction_timestamp()"
                ).fetchone()[0]
            )
            connection = TransactionTimeZoneObservationConnection(
                connection,
                self.observed_transaction_time_zones,
            )
        if self.lose_first_commit_ack:
            self.lose_first_commit_ack = False
            connection = CommitAcknowledgementLossConnection(connection)
        self.checked_out.append(connection)
        return connection

    def release(self, connection: Any) -> None:
        self.released.append(connection)
        connection.close()

    def discard(self, connection: Any) -> None:
        self.discarded.append(connection)
        connection.close()


class RealPostgres18AcceptAccessInvitationUowRedTest(unittest.TestCase):
    """Production Accept must use PG18 facts, RLS, locks and commit boundary."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.postgres = TemporaryPostgres18().start()
        cls.catalog = MigrationCatalog.load(MIGRATION_ROOT)
        cls.contract_sources = IamContractSources(
            api_contract_bytes=(
                PLATFORM_ROOT / "contracts/api/iam-v1.openapi.yaml"
            ).read_bytes(),
            event_contract_bytes=(
                PLATFORM_ROOT / "contracts/events/iam-v1.schema.json"
            ).read_bytes(),
        )

    @classmethod
    def tearDownClass(cls) -> None:
        cls.postgres.stop()

    def setUp(self) -> None:
        self.database = self.postgres.create_database()
        report = self._run_migrations()
        self.assertEqual(
            report.applied_versions,
            tuple(artifact.descriptor.version for artifact in self.catalog.artifacts),
        )
        with self._connect_admin() as connection:
            self.creator_policy = self._seed_policy(
                connection,
                purpose="CREATOR_ENROLLMENT",
                scope_type="USER_ROLE",
                role="CREATOR",
            )
            self.admin_policy = self._seed_policy(
                connection,
                purpose="ORGANIZATION_MEMBERSHIP",
                scope_type="ORGANIZATION_ROLE",
                role="ORG_ADMIN",
            )
            self.member_policy = self._seed_policy(
                connection,
                purpose="ORGANIZATION_MEMBERSHIP",
                scope_type="ORGANIZATION_ROLE",
                role="DEMAND_OWNER",
            )

    def tearDown(self) -> None:
        self.postgres.drop_database(self.database)

    def _run_migrations(self):
        driver = PsycopgMigrationDriver(
            settings=PsycopgMigrationSettings(
                conninfo=self.postgres.conninfo(
                    database=self.database,
                    user="iam_migration_runner",
                ),
                application_name="desire-iam-accept-uow-red",
            ),
            dbapi=psycopg,
        )
        return IamMigrationRunner(
            driver=driver,
            runner_version="accept-uow-red/1",
        ).run(catalog=self.catalog, contract_sources=self.contract_sources)

    def _apply_iam40_preview(self) -> None:
        """Apply IAM40 until the reviewed catalog is repinned by release work."""

        with self._connect_admin(autocommit=True) as connection:
            installed = connection.execute(
                "SELECT count(*) FROM pg_catalog.pg_policies "
                "WHERE schemaname='iam' AND tablename='auth_transactions' "
                "AND policyname='rls_accept_scope_auth_exact_definer_v2'"
            ).fetchone()
            if installed == (1,):
                return
            connection.execute("SET ROLE schema_owner")
            connection.execute(IAM40_MIGRATION.read_text(encoding="utf-8"))

    def _resolve_receipt_principal(
        self,
        fixture: AcceptFixture,
        *,
        invitation_id: Optional[uuid.UUID] = None,
    ) -> Dict[str, Any]:
        target_invitation_id = invitation_id or fixture.invitation_id
        with self._connect_onboarding(autocommit=True) as connection:
            connection.execute("BEGIN ISOLATION LEVEL READ COMMITTED READ ONLY")
            for name, value in (
                ("app.scope_kind", "AUTH_PROTOCOL"),
                ("app.operation", "ACCEPT"),
                ("app.actor_user_id", str(fixture.actor_id)),
                ("app.target_user_id", str(fixture.actor_id)),
                ("app.session_id", str(fixture.session_id)),
                ("app.target_invitation_id", str(target_invitation_id)),
                ("app.command_name", "AcceptAccessInvitation"),
                ("app.command_version", "1"),
            ):
                configured = connection.execute(
                    "SELECT pg_catalog.set_config(%s,%s,true)", (name, value)
                ).fetchone()
                self.assertEqual(configured, (value,))
            row = connection.execute(
                "SELECT iam_api.resolve_accept_receipt_principal_v1(%s,%s)",
                (fixture.actor_id, fixture.session_id),
            ).fetchone()
            connection.execute("COMMIT")
        self.assertIsNotNone(row)
        self.assertIsInstance(row[0], dict)
        return row[0]

    def _resolve_accept_scope(
        self,
        fixture: AcceptFixture,
        request: AcceptAccessInvitationDatabaseRequest,
        *,
        invitation_id: Optional[uuid.UUID] = None,
    ) -> Any:
        return PsycopgOrganizationAcceptScopeResolver(
            connections=self._connection_source()
        ).resolve(
            actor_user_id=fixture.actor_id,
            session_id=fixture.session_id,
            invitation_id=invitation_id or fixture.invitation_id,
            policy_bundle_id=fixture.policy.bundle_id,
            policy_acceptances=request.policy_acceptances,
            consent_choices=request.consent_choices,
        )

    def _connect_admin(self, *, autocommit: bool = False):
        return psycopg.connect(
            self.postgres.admin_conninfo(database=self.database),
            autocommit=autocommit,
        )

    def _connect_onboarding(self, *, autocommit: bool = False):
        return psycopg.connect(
            self.postgres.conninfo(
                database=self.database,
                user="iam_onboarding",
            ),
            autocommit=autocommit,
        )

    def _connection_source(
        self,
        *,
        lose_first_commit_ack: bool = False,
        session_timezone_name: Optional[str] = None,
    ) -> TrackingRealConnectionSource:
        return TrackingRealConnectionSource(
            self.postgres.conninfo(
                database=self.database,
                user="iam_onboarding",
            ),
            lose_first_commit_ack=lose_first_commit_ack,
            session_timezone_name=session_timezone_name,
        )

    @staticmethod
    def _factory(**arguments: Any) -> PsycopgAcceptAccessInvitationUnitOfWorkFactory:
        return PsycopgAcceptAccessInvitationUnitOfWorkFactory(
            event_validator=ClosedSchemaValidator.for_events(),
            response_validator=ClosedSchemaValidator.for_openapi(),
            **arguments,
        )

    @staticmethod
    def _execute(
        factory: PsycopgAcceptAccessInvitationUnitOfWorkFactory,
        request: AcceptAccessInvitationDatabaseRequest,
    ) -> Any:
        """Translate only the reviewed RED sentinel into an assertion outcome."""

        try:
            return factory.execute(request)
        except AcceptPostgresBehaviorNotAvailable as error:
            if str(error) != POSTGRES_ACCEPT_BEHAVIOR_NOT_AVAILABLE:
                raise
            return PersistenceUnavailableOutcome()

    def _set_direct_accept_context(
        self,
        connection: Any,
        request: AcceptAccessInvitationDatabaseRequest,
    ) -> None:
        self._factory(
            connections=self._connection_source()
        )._configure_transaction(connection, request)

    @staticmethod
    def _direct_expire_consent(
        connection: Any,
        *,
        grant_id: uuid.UUID,
        actor_id: uuid.UUID,
        aggregate_version: int,
        expires_at: datetime,
        now: datetime,
        status: str = "EXPIRED",
    ) -> Optional[Tuple[Any, ...]]:
        return connection.execute(
            "UPDATE iam.consent_grants SET status=%s,withdrawn_at=NULL,"
            "aggregate_version=aggregate_version+1,updated_at=%s "
            "WHERE id=%s AND user_id=%s AND status='ACTIVE' "
            "AND aggregate_version=%s AND expires_at=%s "
            "AND expires_at <= transaction_timestamp() RETURNING id",
            (
                status,
                now,
                grant_id,
                actor_id,
                aggregate_version,
                expires_at,
            ),
        ).fetchone()

    def _seed_policy(
        self,
        connection: Any,
        *,
        purpose: str,
        scope_type: str,
        role: str,
    ) -> PolicyFixture:
        unique = uuid.uuid4().hex
        selector = _selector_digest(
            purpose=purpose,
            scope_type=scope_type,
            role=role,
        )
        bundle = _new_id()
        required_document = _new_id()
        consent_document = _new_id()
        offer = _new_id()
        command = _new_id()
        required_hash = hashlib.sha256(b"Required terms").digest()
        consent_hash = hashlib.sha256(b"Optional consent text").digest()
        semantic_version = (
            "2.0.0"
            if role == "ORG_ADMIN"
            else "3.0.0"
            if role == "DEMAND_OWNER"
            else "1.0.0"
        )
        now = datetime.now(timezone.utc)
        created = now - timedelta(days=2)
        effective = now - timedelta(days=1)
        offer_not_after = now + timedelta(days=300)
        canonical_offer = ConsentOffer.pilot_research(
            consent_offer_id=str(offer),
            aggregate_version=1,
            supporting_document_id=str(consent_document),
            supporting_document_sha256=consent_hash.hex(),
            recipient_reference="internal:research-controller",
            pilot_ends_at=offer_not_after,
            policy_bundle_id=str(bundle),
            recipient_label="Reviewed research controller",
            canonical_offer_sha256="0" * 64,
        )
        canonical_offer_hash = hashlib.sha256(
            canonical_consent_offer_bytes(canonical_offer)
        ).digest()

        connection.execute(
            "INSERT INTO iam.policy_selectors ("
            "selector_digest,canonicalization_version,access_purpose,scope_type,"
            "target_role,jurisdiction,locale,current_bundle_id,aggregate_version,"
            "created_at,updated_at) VALUES ("
            "%s,'policy-selector-json-v1',%s,%s,%s,'CN','zh-CN',NULL,1,%s,%s)",
            (selector, purpose, scope_type, role, created, created),
        )
        connection.execute(
            "INSERT INTO iam.policy_documents ("
            "id,kind,locale,semantic_version,canonical_body,content_sha256,"
            "legal_effect,jurisdiction,status,effective_at,"
            "superseded_by_document_id,publication_command_id,created_at,updated_at"
            ") VALUES "
            "(%s,'TERMS','zh-CN',%s,'Required terms',%s,"
            "'CONTRACT_ACCEPTANCE','CN','ACTIVE',%s,NULL,%s,%s,%s),"
            "(%s,'CONSENT_TEXT','zh-CN',%s,'Optional consent text',%s,"
            "'CONSENT_TEXT','CN','ACTIVE',%s,NULL,%s,%s,%s)",
            (
                required_document,
                semantic_version,
                required_hash,
                effective,
                command,
                created,
                effective,
                consent_document,
                semantic_version,
                consent_hash,
                effective,
                command,
                created,
                effective,
            ),
        )
        connection.execute(
            "INSERT INTO iam.policy_bundles ("
            "id,selector_digest,status,effective_at,effective_until,"
            "superseded_by_bundle_id,release_manifest_sha256,release_signature,"
            "release_signing_key_id,publication_command_id,aggregate_version,"
            "created_at,updated_at) VALUES ("
            "%s,%s,'DRAFT',NULL,NULL,NULL,%s,%s,'synthetic-signing-v1',%s,1,%s,%s)",
            (
                bundle,
                selector,
                _digest("manifest-" + unique),
                b"synthetic-signature",
                command,
                created,
                created,
            ),
        )
        connection.execute(
            "INSERT INTO iam.policy_bundle_documents "
            "(bundle_id,document_id,position,required) VALUES "
            "(%s,%s,1,true),(%s,%s,2,false)",
            (bundle, required_document, bundle, consent_document),
        )
        connection.execute(
            "INSERT INTO iam.consent_offers ("
            "id,bundle_id,offer_version,purpose,scope_type,scope_derivation,"
            "recipient_ref,recipient_label,document_id,document_content_sha256,"
            "expiry_rule,expiry_days,not_after,optional,canonical_offer_sha256,"
            "publication_command_id,created_at) VALUES ("
            "%s,%s,1,'PILOT_RESEARCH','PLATFORM_PARTICIPATION',"
            "'PLATFORM_PARTICIPATION_NULL_SCOPE','internal:research-controller',"
            "'Reviewed research controller',%s,%s,"
            "'EARLIER_OF_GRANTED_AT_PLUS_365_DAYS_OR_NOT_AFTER',365,%s,true,%s,%s,%s)",
            (
                offer,
                bundle,
                consent_document,
                consent_hash,
                offer_not_after,
                canonical_offer_hash,
                command,
                created,
            ),
        )
        connection.execute(
            "INSERT INTO iam.consent_offer_data_categories "
            "(offer_id,category,position) VALUES "
            "(%s,'PROFILE',1),(%s,'MATCHING',2),(%s,'RESEARCH',3)",
            (offer, offer, offer),
        )
        connection.execute(
            "UPDATE iam.policy_bundles SET status='ACTIVE',effective_at=%s,"
            "aggregate_version=2,updated_at=%s WHERE id=%s",
            (effective, effective, bundle),
        )
        connection.execute(
            "UPDATE iam.policy_selectors SET current_bundle_id=%s,"
            "aggregate_version=2,updated_at=%s WHERE selector_digest=%s",
            (bundle, effective, selector),
        )
        return PolicyFixture(
            selector_digest=selector,
            bundle_id=bundle,
            required_document_id=required_document,
            required_document_hash=required_hash,
            consent_document_id=consent_document,
            consent_document_hash=consent_hash,
            consent_offer_id=offer,
        )

    def _seed_accept_graph(
        self,
        *,
        kind: str,
        session_auth_time: Optional[datetime] = None,
    ) -> AcceptFixture:
        if kind not in ("creator", "admin", "member"):
            raise ValueError("unknown Accept fixture kind")
        actor = _new_id()
        contact = _new_id()
        invitation = _new_id()
        organization = _new_id() if kind in ("admin", "member") else None
        transaction = _new_id()
        family = _new_id()
        session = _new_id()
        policy = (
            self.admin_policy
            if kind == "admin"
            else self.member_policy
            if kind == "member"
            else self.creator_policy
        )
        now = datetime.now(timezone.utc)
        user_created = now - timedelta(days=1)
        protocol_created = now - timedelta(hours=1)
        session_created = now - timedelta(minutes=30)

        with self._connect_admin() as connection:
            connection.execute(
                "INSERT INTO iam.users "
                "(id,status,display_handle,aggregate_version,created_at,updated_at) "
                "VALUES (%s,%s,%s,%s,%s,%s)",
                (
                    actor,
                    "ACTIVE" if kind == "member" else "PENDING_ENROLLMENT",
                    "user_" + actor.hex[:12],
                    2 if kind == "member" else 1,
                    user_created,
                    user_created,
                ),
            )
            connection.execute(
                "INSERT INTO iam.contact_points ("
                "id,user_id,contact_type,locator_ciphertext,locator_encryption_key_id,"
                "locator_encryption_algorithm,binding_digest,binding_digest_key_id,"
                "verified_at,retention_until,created_at,updated_at) VALUES ("
                "%s,%s,'EMAIL',NULL,NULL,NULL,%s,'contact-hmac-v1',%s,%s,%s,%s)",
                (
                    contact,
                    actor,
                    _digest(RAW_CONTACT_SENTINEL + actor.hex),
                    protocol_created,
                    now + timedelta(days=365),
                    user_created,
                    protocol_created,
                ),
            )
            if organization is not None:
                connection.execute(
                    "INSERT INTO iam.organizations ("
                    "id,organization_type,public_name,jurisdiction,status,"
                    "client_reference_namespace,client_reference,aggregate_version,"
                    "created_at,updated_at) VALUES ("
                    "%s,'BUSINESS',%s,'CN',%s,'accept-uow-red',%s,%s,%s,%s)",
                    (
                        organization,
                        (
                            "Active Member Organization"
                            if kind == "member"
                            else "Pending Admin Organization"
                        ),
                        "ACTIVE" if kind == "member" else "PENDING_ADMIN",
                        organization.hex,
                        2 if kind == "member" else 1,
                        user_created,
                        user_created,
                    ),
                )
            purpose = (
                "ORGANIZATION_MEMBERSHIP" if organization else "CREATOR_ENROLLMENT"
            )
            target_scope = "ORGANIZATION" if organization else "USER"
            role = (
                "ORG_ADMIN"
                if kind == "admin"
                else "DEMAND_OWNER"
                if kind == "member"
                else "CREATOR"
            )
            connection.execute(
                "INSERT INTO iam.access_invitations ("
                "id,purpose,organization_id,target_scope,target_role,is_initial_admin,"
                "recipient_contact_id,masked_recipient_label,policy_selector_digest,"
                "issued_policy_bundle_id,status,expires_at,issuer_kind,issuer_user_id,"
                "token_nonce,token_key_id,accepted_by_user_id,terminal_at,"
                "terminal_reason_code,aggregate_version,created_at,updated_at) VALUES ("
                "%s,%s,%s,%s,%s,%s,%s,'r***@example.invalid',%s,%s,'ISSUED',%s,"
                "'SYSTEM',NULL,%s,'invitation-token-v1',NULL,NULL,NULL,1,%s,%s)",
                (
                    invitation,
                    purpose,
                    organization,
                    target_scope,
                    role,
                    kind == "admin",
                    contact,
                    policy.selector_digest,
                    policy.bundle_id,
                    now + timedelta(days=2),
                    _digest("invitation-nonce-" + invitation.hex),
                    protocol_created,
                    protocol_created,
                ),
            )
            connection.execute(
                "INSERT INTO iam.auth_transactions ("
                "id,status,purpose,attempt,protocol_version,browser_binding_digest,"
                "browser_binding_key_id,initiating_session_id,initiating_user_id,"
                "expected_user_id,invitation_id,invitation_version,"
                "expected_contact_point_id,state_digest,state_digest_key_id,"
                "nonce_digest,nonce_digest_key_id,pkce_verifier_ciphertext,"
                "pkce_encryption_key_id,pkce_encryption_algorithm,redirect_uri,"
                "provider_error_class,deadline,succeeded_at,created_at,updated_at) "
                "VALUES (%s,'SUCCEEDED','ENROLLMENT',1,1,%s,'browser-hmac-v1',"
                "NULL,NULL,NULL,%s,1,%s,%s,'state-hmac-v1',%s,'nonce-hmac-v1',"
                "%s,'pkce-aead-v1','AES_256_GCM_V1',"
                "'https://app.example.test/v1/auth/oidc/callback',NULL,%s,%s,%s,%s)",
                (
                    transaction,
                    _digest("browser-" + transaction.hex),
                    invitation,
                    contact,
                    _digest("state-" + transaction.hex),
                    _digest("nonce-" + transaction.hex),
                    b"synthetic-pkce-ciphertext",
                    now + timedelta(hours=2),
                    protocol_created + timedelta(minutes=10),
                    protocol_created,
                    protocol_created + timedelta(minutes=10),
                ),
            )
            connection.execute(
                "INSERT INTO iam.session_families ("
                "id,user_id,status,current_generation,revoked_at,"
                "revocation_reason_code,aggregate_version,created_at,updated_at) "
                "VALUES (%s,%s,'ACTIVE',1,NULL,NULL,1,%s,%s)",
                (family, actor, session_created, session_created),
            )
            connection.execute(
                "INSERT INTO iam.sessions ("
                "id,user_id,family_id,generation,predecessor_session_id,handle_digest,"
                "handle_digest_key_id,csrf_salt,csrf_key_id,csrf_digest,"
                "verified_contact_point_id,verified_at,verified_for_invitation_id,"
                "auth_transaction_id,auth_time,acr_code,amr_codes,created_at,"
                "last_activity_at,idle_expires_at,absolute_expires_at,updated_at,"
                "device_label,status,rotation_reason,revoked_at,"
                "revocation_reason_code,aggregate_version) VALUES ("
                "%s,%s,%s,1,NULL,%s,'session-hmac-v1',%s,'csrf-hmac-v1',%s,"
                "%s,%s,%s,%s,%s,'urn:desire:acr:mfa',ARRAY['pwd','otp']::text[],"
                "%s,%s,%s,%s,%s,'Browser','ACTIVE','ENROLLMENT',NULL,NULL,1)",
                (
                    session,
                    actor,
                    family,
                    _digest(RAW_SESSION_SENTINEL + session.hex),
                    _digest("csrf-salt-old-" + session.hex),
                    _digest(RAW_CSRF_SENTINEL + session.hex),
                    contact,
                    session_created,
                    invitation,
                    transaction,
                    session_auth_time
                    or session_created - timedelta(minutes=15),
                    session_created,
                    session_created,
                    now + timedelta(minutes=30),
                    now + timedelta(hours=12),
                    session_created,
                ),
            )
        return AcceptFixture(
            kind=kind,
            actor_id=actor,
            contact_id=contact,
            invitation_id=invitation,
            organization_id=organization,
            auth_transaction_id=transaction,
            session_family_id=family,
            session_id=session,
            policy=policy,
        )

    def _request(
        self,
        fixture: AcceptFixture,
        *,
        payload_label: str = "payload-a",
    ) -> AcceptAccessInvitationDatabaseRequest:
        now = datetime.now(timezone.utc)
        command_id = _new_id()
        outbox_count = {"admin": 7, "creator": 5, "member": 6}[fixture.kind]
        generated = AcceptGeneratedIds(
            policy_acceptance_ids=(_new_id(),),
            consent_grant_ids=(_new_id(),),
            user_role_grant_id=_new_id() if fixture.kind == "creator" else None,
            membership_id=_new_id() if fixture.kind != "creator" else None,
            membership_role_grant_id=(
                _new_id() if fixture.kind != "creator" else None
            ),
            audit_event_id=_new_id(),
            outbox_event_ids=tuple(_new_id() for _item in range(outbox_count)),
        )
        return AcceptAccessInvitationDatabaseRequest(
            scope=AcceptExecutionScope(
                actor_user_id=fixture.actor_id,
                session_id=fixture.session_id,
                session_family_id=fixture.session_family_id,
                auth_transaction_id=fixture.auth_transaction_id,
                invitation_id=fixture.invitation_id,
                organization_id=fixture.organization_id,
                policy_selector_digest=fixture.policy.selector_digest,
                policy_bundle_id=fixture.policy.bundle_id,
                target_role={
                    "creator": "CREATOR",
                    "admin": "ORG_ADMIN",
                    "member": "DEMAND_OWNER",
                }[fixture.kind],
                command_id=command_id,
                correlation_id=_new_id(),
                trace_id=_new_id(),
            ),
            receipt=AcceptReceiptIdentity(
                receipt_id=command_id,
                principal_id=fixture.actor_id,
                idempotency_key_digest=_digest(RAW_IDEMPOTENCY_SENTINEL),
                idempotency_key_digest_key_id=(
                    "iam-receipt-idempotency-hmac-2026-01"
                ),
                payload_hash=_digest(payload_label),
                payload_hash_key_id="iam-receipt-payload-hmac-2026-01",
                canonicalization_version="restricted-canonical-json-v1",
                retain_until=now + timedelta(days=30),
            ),
            hold=AcceptHoldEvidence(
                action="AcceptAccessInvitation",
                target_type="AccessInvitation",
                target_id=fixture.invitation_id,
                target_version=1,
                organization_id=fixture.organization_id,
                policy_version="iam-safety-v1",
                evaluated_at=now - timedelta(seconds=1),
                valid_until=now + timedelta(minutes=5),
            ),
            expected_invitation_version=1,
            policy_acceptances=(
                AcceptPolicyAcceptanceChoice(
                    document_id=fixture.policy.required_document_id,
                    content_sha256=fixture.policy.required_document_hash,
                    affirmed=True,
                ),
            ),
            consent_choices=(
                AcceptConsentOfferChoice(
                    consent_offer_id=fixture.policy.consent_offer_id,
                    document_id=fixture.policy.consent_document_id,
                    content_sha256=fixture.policy.consent_document_hash,
                    affirmed=True,
                ),
            ),
            successor=AcceptSessionSuccessorFacts(
                session_id=_new_id(),
                handle_digest=_digest(
                    RAW_SESSION_SENTINEL + "-successor-" + fixture.session_id.hex
                ),
                handle_digest_key_id="session-hmac-v1",
                csrf_salt=_digest("new-csrf-salt" + fixture.session_id.hex),
                csrf_key_id="csrf-hmac-v1",
                csrf_digest=_digest(RAW_CSRF_SENTINEL),
            ),
            generated_ids=generated,
        )

    def _seed_existing_evidence(
        self,
        fixture: AcceptFixture,
        *,
        include_policy_acceptance: bool,
        consent_policy: PolicyFixture,
        consent_granted_at: Optional[datetime] = None,
    ) -> Tuple[Optional[uuid.UUID], uuid.UUID]:
        accepted_at = datetime.now(timezone.utc) - timedelta(minutes=1)
        granted_at = consent_granted_at or accepted_at
        acceptance_id = _new_id() if include_policy_acceptance else None
        grant_id = _new_id()
        with self._connect_admin() as connection:
            session = connection.execute(
                "SELECT auth_transaction_id,auth_time,acr_code,amr_codes "
                "FROM iam.sessions WHERE id=%s",
                (fixture.session_id,),
            ).fetchone()
            offer = connection.execute(
                "SELECT offer_version,bundle_id,purpose,scope_type,recipient_ref,"
                "recipient_label,document_id,document_content_sha256,expiry_days,"
                "not_after FROM iam.consent_offers WHERE id=%s",
                (consent_policy.consent_offer_id,),
            ).fetchone()
            assert session is not None and offer is not None
            if acceptance_id is not None:
                connection.execute(
                    "INSERT INTO iam.policy_acceptances ("
                    "id,user_id,document_id,content_sha256,bundle_id,accepted_at,"
                    "session_id,auth_transaction_id,auth_time,acr_code,amr_codes,"
                    "source_action,command_id,correlation_id,aggregate_version,created_at"
                    ") VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,"
                    "'POLICY_ACCEPT',%s,%s,1,%s)",
                    (
                        acceptance_id,
                        fixture.actor_id,
                        fixture.policy.required_document_id,
                        fixture.policy.required_document_hash,
                        fixture.policy.bundle_id,
                        accepted_at,
                        fixture.session_id,
                        session[0],
                        session[1],
                        session[2],
                        session[3],
                        _new_id(),
                        _new_id(),
                        accepted_at,
                    ),
                )
            expires_at = min(
                granted_at + timedelta(days=offer[8]),
                offer[9],
            )
            connection.execute(
                "INSERT INTO iam.consent_grants ("
                "id,user_id,consent_offer_id,consent_offer_version,policy_bundle_id,"
                "purpose,scope_type,scope_id,recipient_ref,recipient_label,"
                "document_id,document_content_sha256,granted_at,expires_at,"
                "session_id,auth_transaction_id,auth_time,acr_code,amr_codes,"
                "command_id,correlation_id,status,withdrawn_at,aggregate_version,"
                "created_at,updated_at) VALUES ("
                "%s,%s,%s,%s,%s,%s,%s,NULL,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,"
                "%s,%s,'ACTIVE',NULL,1,%s,%s)",
                (
                    grant_id,
                    fixture.actor_id,
                    consent_policy.consent_offer_id,
                    offer[0],
                    offer[1],
                    offer[2],
                    offer[3],
                    offer[4],
                    offer[5],
                    offer[6],
                    offer[7],
                    granted_at,
                    expires_at,
                    fixture.session_id,
                    session[0],
                    session[1],
                    session[2],
                    session[3],
                    _new_id(),
                    _new_id(),
                    granted_at,
                    granted_at,
                ),
            )
            categories = connection.execute(
                "SELECT category,position FROM iam.consent_offer_data_categories "
                "WHERE offer_id=%s ORDER BY position",
                (consent_policy.consent_offer_id,),
            ).fetchall()
            for category, position in categories:
                connection.execute(
                    "INSERT INTO iam.consent_grant_data_categories "
                    "(grant_id,category,position) VALUES (%s,%s,%s)",
                    (grant_id, category, position),
                )
        return acceptance_id, grant_id

    def _seed_existing_policy_acceptance(self, fixture: AcceptFixture) -> uuid.UUID:
        acceptance_id = _new_id()
        accepted_at = datetime.now(timezone.utc) - timedelta(minutes=1)
        with self._connect_admin() as connection:
            session = connection.execute(
                "SELECT auth_transaction_id,auth_time,acr_code,amr_codes "
                "FROM iam.sessions WHERE id=%s",
                (fixture.session_id,),
            ).fetchone()
            connection.execute(
                "INSERT INTO iam.policy_acceptances ("
                "id,user_id,document_id,content_sha256,bundle_id,accepted_at,"
                "session_id,auth_transaction_id,auth_time,acr_code,amr_codes,"
                "source_action,command_id,correlation_id,aggregate_version,created_at"
                ") VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'POLICY_ACCEPT',"
                "%s,%s,1,%s)",
                (
                    acceptance_id,
                    fixture.actor_id,
                    fixture.policy.required_document_id,
                    fixture.policy.required_document_hash,
                    fixture.policy.bundle_id,
                    accepted_at,
                    fixture.session_id,
                    session[0],
                    session[1],
                    session[2],
                    session[3],
                    _new_id(),
                    _new_id(),
                    accepted_at,
                ),
            )
        return acceptance_id

    def _seed_existing_creator_authority(self, fixture: AcceptFixture) -> None:
        """Give an active membership fixture an older canonical User authority."""

        invitation_id = _new_id()
        accepted_at = datetime.now(timezone.utc) - timedelta(minutes=2)
        with self._connect_admin() as connection:
            session = connection.execute(
                "SELECT auth_transaction_id,auth_time,acr_code,amr_codes "
                "FROM iam.sessions WHERE id=%s",
                (fixture.session_id,),
            ).fetchone()
            assert session is not None
            connection.execute(
                "INSERT INTO iam.access_invitations ("
                "id,purpose,organization_id,target_scope,target_role,is_initial_admin,"
                "recipient_contact_id,masked_recipient_label,policy_selector_digest,"
                "issued_policy_bundle_id,status,expires_at,issuer_kind,issuer_user_id,"
                "token_nonce,token_key_id,accepted_by_user_id,terminal_at,"
                "terminal_reason_code,aggregate_version,created_at,updated_at) VALUES ("
                "%s,'CREATOR_ENROLLMENT',NULL,'USER','CREATOR',false,%s,"
                "'r***@example.invalid',%s,%s,'ACCEPTED',%s,'SYSTEM',NULL,%s,"
                "'invitation-token-v1',%s,%s,NULL,2,%s,%s)",
                (
                    invitation_id,
                    fixture.contact_id,
                    self.creator_policy.selector_digest,
                    self.creator_policy.bundle_id,
                    accepted_at + timedelta(days=2),
                    _digest("prior-creator-invitation-" + invitation_id.hex),
                    fixture.actor_id,
                    accepted_at,
                    accepted_at - timedelta(days=1),
                    accepted_at,
                ),
            )
            connection.execute(
                "INSERT INTO iam.user_role_grants ("
                "id,user_id,role_code,source_invitation_id,policy_selector_digest,"
                "granted_by_kind,granted_by_id,granted_at,revoked_at,"
                "revocation_reason_code,aggregate_version) VALUES ("
                "%s,%s,'CREATOR',%s,%s,'SYSTEM',%s,%s,NULL,NULL,1)",
                (
                    _new_id(),
                    fixture.actor_id,
                    invitation_id,
                    self.creator_policy.selector_digest,
                    _new_id(),
                    accepted_at,
                ),
            )
            connection.execute(
                "INSERT INTO iam.policy_acceptances ("
                "id,user_id,document_id,content_sha256,bundle_id,accepted_at,"
                "session_id,auth_transaction_id,auth_time,acr_code,amr_codes,"
                "source_action,command_id,correlation_id,aggregate_version,created_at"
                ") VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'POLICY_ACCEPT',"
                "%s,%s,1,%s)",
                (
                    _new_id(),
                    fixture.actor_id,
                    self.creator_policy.required_document_id,
                    self.creator_policy.required_document_hash,
                    self.creator_policy.bundle_id,
                    accepted_at,
                    fixture.session_id,
                    session[0],
                    session[1],
                    session[2],
                    session[3],
                    _new_id(),
                    _new_id(),
                    accepted_at,
                ),
            )

    def _seed_existing_membership(self, fixture: AcceptFixture) -> uuid.UUID:
        if fixture.organization_id is None:
            raise ValueError("membership fixture requires an organization")
        prior_invitation = _new_id()
        membership_id = _new_id()
        role_grant_id = _new_id()
        now = datetime.now(timezone.utc)
        with self._connect_admin() as connection:
            connection.execute(
                "INSERT INTO iam.access_invitations ("
                "id,purpose,organization_id,target_scope,target_role,is_initial_admin,"
                "recipient_contact_id,masked_recipient_label,policy_selector_digest,"
                "issued_policy_bundle_id,status,expires_at,issuer_kind,issuer_user_id,"
                "token_nonce,token_key_id,accepted_by_user_id,terminal_at,"
                "terminal_reason_code,aggregate_version,created_at,updated_at) VALUES ("
                "%s,'ORGANIZATION_MEMBERSHIP',%s,'ORGANIZATION','DEMAND_OWNER',false,"
                "%s,'r***@example.invalid',%s,%s,'ACCEPTED',%s,'SYSTEM',NULL,%s,"
                "'invitation-token-v1',%s,%s,NULL,2,%s,%s)",
                (
                    prior_invitation,
                    fixture.organization_id,
                    fixture.contact_id,
                    fixture.policy.selector_digest,
                    fixture.policy.bundle_id,
                    now + timedelta(days=1),
                    _digest("prior-invitation-" + prior_invitation.hex),
                    fixture.actor_id,
                    now,
                    now - timedelta(days=1),
                    now,
                ),
            )
            connection.execute(
                "INSERT INTO iam.memberships (id,organization_id,user_id,status,"
                "source_invitation_id,aggregate_version,created_at,updated_at) "
                "VALUES (%s,%s,%s,'ACTIVE',%s,1,%s,%s)",
                (
                    membership_id,
                    fixture.organization_id,
                    fixture.actor_id,
                    prior_invitation,
                    now,
                    now,
                ),
            )
            connection.execute(
                "INSERT INTO iam.membership_role_grants ("
                "id,organization_id,membership_id,user_id,role_code,"
                "source_invitation_id,policy_selector_digest,granted_by_kind,"
                "granted_by_id,granted_at,revoked_at,revocation_reason_code,"
                "aggregate_version) VALUES ("
                "%s,%s,%s,%s,'DEMAND_OWNER',%s,%s,'USER',%s,%s,NULL,NULL,1)",
                (
                    role_grant_id,
                    fixture.organization_id,
                    membership_id,
                    fixture.actor_id,
                    prior_invitation,
                    fixture.policy.selector_digest,
                    fixture.actor_id,
                    now,
                ),
            )
        return membership_id

    def _publish_replacement_policy(
        self,
        previous: PolicyFixture,
        *,
        reuse_required_document: bool = False,
    ) -> PolicyFixture:
        bundle = _new_id()
        required_document = (
            previous.required_document_id
            if reuse_required_document
            else _new_id()
        )
        consent_document = _new_id()
        offer = _new_id()
        command = _new_id()
        required_hash = (
            previous.required_document_hash
            if reuse_required_document
            else hashlib.sha256(b"Replacement terms").digest()
        )
        consent_hash = hashlib.sha256(b"Replacement consent").digest()
        now = datetime.now(timezone.utc)
        effective = now - timedelta(minutes=1)
        created = now - timedelta(minutes=2)
        not_after = now + timedelta(days=200)
        canonical_offer = ConsentOffer.pilot_research(
            consent_offer_id=str(offer),
            aggregate_version=1,
            supporting_document_id=str(consent_document),
            supporting_document_sha256=consent_hash.hex(),
            recipient_reference="internal:research-controller-v2",
            pilot_ends_at=not_after,
            policy_bundle_id=str(bundle),
            recipient_label="Reviewed research controller v2",
            canonical_offer_sha256="0" * 64,
        )
        offer_hash = hashlib.sha256(
            canonical_consent_offer_bytes(canonical_offer)
        ).digest()
        with self._connect_admin() as connection:
            if not reuse_required_document:
                connection.execute(
                    "INSERT INTO iam.policy_documents ("
                    "id,kind,locale,semantic_version,canonical_body,content_sha256,"
                    "legal_effect,jurisdiction,status,effective_at,"
                    "superseded_by_document_id,publication_command_id,created_at,updated_at"
                    ") VALUES (%s,'TERMS','zh-CN','99.0.0','Replacement terms',%s,"
                    "'CONTRACT_ACCEPTANCE','CN','ACTIVE',%s,NULL,%s,%s,%s)",
                    (
                        required_document,
                        required_hash,
                        effective,
                        command,
                        created,
                        effective,
                    ),
                )
            connection.execute(
                "INSERT INTO iam.policy_documents ("
                "id,kind,locale,semantic_version,canonical_body,content_sha256,"
                "legal_effect,jurisdiction,status,effective_at,"
                "superseded_by_document_id,publication_command_id,created_at,updated_at"
                ") VALUES (%s,'CONSENT_TEXT','zh-CN','99.0.0',"
                "'Replacement consent',%s,'CONSENT_TEXT','CN','ACTIVE',"
                "%s,NULL,%s,%s,%s)",
                (
                    consent_document,
                    consent_hash,
                    effective,
                    command,
                    created,
                    effective,
                ),
            )
            connection.execute(
                "INSERT INTO iam.policy_bundles ("
                "id,selector_digest,status,effective_at,effective_until,"
                "superseded_by_bundle_id,release_manifest_sha256,release_signature,"
                "release_signing_key_id,publication_command_id,aggregate_version,"
                "created_at,updated_at) VALUES ("
                "%s,%s,'DRAFT',NULL,NULL,NULL,%s,%s,'synthetic-signing-v2',%s,1,%s,%s)",
                (
                    bundle,
                    previous.selector_digest,
                    _digest("replacement-manifest-" + bundle.hex),
                    b"replacement-signature",
                    command,
                    created,
                    created,
                ),
            )
            connection.execute(
                "INSERT INTO iam.policy_bundle_documents "
                "(bundle_id,document_id,position,required) VALUES "
                "(%s,%s,1,true),(%s,%s,2,false)",
                (bundle, required_document, bundle, consent_document),
            )
            connection.execute(
                "INSERT INTO iam.consent_offers ("
                "id,bundle_id,offer_version,purpose,scope_type,scope_derivation,"
                "recipient_ref,recipient_label,document_id,document_content_sha256,"
                "expiry_rule,expiry_days,not_after,optional,canonical_offer_sha256,"
                "publication_command_id,created_at) VALUES ("
                "%s,%s,1,'PILOT_RESEARCH','PLATFORM_PARTICIPATION',"
                "'PLATFORM_PARTICIPATION_NULL_SCOPE','internal:research-controller-v2',"
                "'Reviewed research controller v2',%s,%s,"
                "'EARLIER_OF_GRANTED_AT_PLUS_365_DAYS_OR_NOT_AFTER',365,%s,true,%s,%s,%s)",
                (
                    offer,
                    bundle,
                    consent_document,
                    consent_hash,
                    not_after,
                    offer_hash,
                    command,
                    created,
                ),
            )
            connection.execute(
                "INSERT INTO iam.consent_offer_data_categories "
                "(offer_id,category,position) VALUES "
                "(%s,'PROFILE',1),(%s,'MATCHING',2),(%s,'RESEARCH',3)",
                (offer, offer, offer),
            )
            connection.execute(
                "UPDATE iam.policy_bundles SET status='SUPERSEDED',"
                "effective_until=%s,superseded_by_bundle_id=%s,"
                "aggregate_version=aggregate_version+1,updated_at=%s WHERE id=%s",
                (effective, bundle, effective, previous.bundle_id),
            )
            connection.execute(
                "UPDATE iam.policy_bundles SET status='ACTIVE',effective_at=%s,"
                "aggregate_version=2,updated_at=%s WHERE id=%s",
                (effective, effective, bundle),
            )
            connection.execute(
                "UPDATE iam.policy_selectors SET current_bundle_id=%s,"
                "aggregate_version=aggregate_version+1,updated_at=%s "
                "WHERE selector_digest=%s",
                (bundle, effective, previous.selector_digest),
            )
        return PolicyFixture(
            selector_digest=previous.selector_digest,
            bundle_id=bundle,
            required_document_id=required_document,
            required_document_hash=required_hash,
            consent_document_id=consent_document,
            consent_document_hash=consent_hash,
            consent_offer_id=offer,
        )

    def _snapshot(self, fixture: AcceptFixture, command_id: uuid.UUID) -> Dict[str, Any]:
        queries = {
            "user": ("SELECT * FROM iam.users WHERE id=%s", (fixture.actor_id,)),
            "invitation": (
                "SELECT * FROM iam.access_invitations WHERE id=%s",
                (fixture.invitation_id,),
            ),
            "organization": (
                "SELECT * FROM iam.organizations WHERE id=%s",
                (fixture.organization_id,),
            ) if fixture.organization_id else ("SELECT NULL WHERE false", ()),
            "memberships": (
                "SELECT * FROM iam.memberships WHERE user_id=%s ORDER BY id",
                (fixture.actor_id,),
            ),
            "user_roles": (
                "SELECT * FROM iam.user_role_grants WHERE user_id=%s ORDER BY id",
                (fixture.actor_id,),
            ),
            "membership_roles": (
                "SELECT * FROM iam.membership_role_grants WHERE user_id=%s ORDER BY id",
                (fixture.actor_id,),
            ),
            "acceptances": (
                "SELECT * FROM iam.policy_acceptances WHERE user_id=%s ORDER BY id",
                (fixture.actor_id,),
            ),
            "consents": (
                "SELECT * FROM iam.consent_grants WHERE user_id=%s ORDER BY id",
                (fixture.actor_id,),
            ),
            "sessions": (
                "SELECT * FROM iam.sessions WHERE family_id=%s ORDER BY generation",
                (fixture.session_family_id,),
            ),
            "family": (
                "SELECT * FROM iam.session_families WHERE id=%s",
                (fixture.session_family_id,),
            ),
            "receipts": (
                "SELECT * FROM infra.command_receipts WHERE id=%s",
                (command_id,),
            ),
            "audit": (
                "SELECT * FROM audit.audit_events WHERE command_id=%s",
                (command_id,),
            ),
            "outbox": (
                "SELECT * FROM infra.outbox_events WHERE causation_id=%s ORDER BY event_id",
                (command_id,),
            ),
        }
        with self._connect_admin() as connection:
            return {
                name: tuple(connection.execute(statement, parameters).fetchall())
                for name, (statement, parameters) in queries.items()
            }

    @staticmethod
    def _fault_targets(kind: str) -> Tuple[Tuple[AcceptWriteCheckpoint, int], ...]:
        targets = [
            (AcceptWriteCheckpoint.COMMAND_RECEIPT_CLAIM, 0),
            (AcceptWriteCheckpoint.POLICY_ACCEPTANCE_INSERT, 0),
            (AcceptWriteCheckpoint.CONSENT_GRANT_INSERT, 0),
            (AcceptWriteCheckpoint.CONSENT_GRANT_CATEGORY_INSERT, 0),
            (AcceptWriteCheckpoint.CONSENT_GRANT_CATEGORY_INSERT, 1),
            (AcceptWriteCheckpoint.CONSENT_GRANT_CATEGORY_INSERT, 2),
            (AcceptWriteCheckpoint.USER_ACTIVATE_OR_GATE_VERSION, 0),
        ]
        if kind == "creator":
            targets.append((AcceptWriteCheckpoint.USER_ROLE_GRANT_INSERT, 0))
            outbox_count = 5
        else:
            targets.extend(
                (
                    (AcceptWriteCheckpoint.MEMBERSHIP_INSERT, 0),
                    (AcceptWriteCheckpoint.MEMBERSHIP_ROLE_GRANT_INSERT, 0),
                    (AcceptWriteCheckpoint.ORGANIZATION_ACTIVATE, 0),
                )
            )
            outbox_count = 7
        targets.extend(
            (
                (AcceptWriteCheckpoint.ACCESS_INVITATION_ACCEPT, 0),
                (AcceptWriteCheckpoint.SESSION_PREDECESSOR_REVOKE, 0),
                (AcceptWriteCheckpoint.SESSION_FAMILY_ROTATE, 0),
                (AcceptWriteCheckpoint.SESSION_SUCCESSOR_INSERT, 0),
                (AcceptWriteCheckpoint.AUDIT_EVENT_INSERT, 0),
            )
        )
        targets.extend(
            (AcceptWriteCheckpoint.OUTBOX_EVENT_INSERT, ordinal)
            for ordinal in range(outbox_count)
        )
        targets.append((AcceptWriteCheckpoint.COMMAND_RECEIPT_COMPLETE, 0))
        return tuple(targets)

    def _assert_happy_facts(
        self,
        fixture: AcceptFixture,
        request: AcceptAccessInvitationDatabaseRequest,
        *,
        expected_policy_acceptance_count: int = 1,
    ) -> None:
        after = self._snapshot(fixture, request.scope.command_id)
        expected_user_version = 3 if fixture.kind == "member" else 2
        self.assertEqual(
            after["user"][0][1:4],
            ("ACTIVE", after["user"][0][2], expected_user_version),
        )
        self.assertEqual(after["invitation"][0][10], "ACCEPTED")
        self.assertEqual(after["invitation"][0][16], fixture.actor_id)
        self.assertEqual(
            len(after["acceptances"]), expected_policy_acceptance_count
        )
        self.assertEqual(len(after["consents"]), 1)
        self.assertEqual(len(after["sessions"]), 2)
        self.assertEqual(after["sessions"][0][23], "REVOKED")
        self.assertEqual(after["sessions"][1][23], "ACTIVE")
        self.assertEqual(after["sessions"][1][10:14], (None, None, None, None))
        self.assertEqual(after["family"][0][3], 2)
        self.assertEqual(len(after["receipts"]), 1)
        self.assertEqual(after["receipts"][0][15], "COMPLETED")
        self.assertEqual(len(after["audit"]), 1)
        if fixture.kind == "creator":
            self.assertEqual(len(after["user_roles"]), 1)
            self.assertFalse(after["memberships"])
            expected_events = Counter({
                "PolicyAccepted",
                "ConsentGranted",
                "UserActivated",
                "UserRoleGranted",
                "AccessInvitationAccepted",
            })
        elif fixture.kind == "admin":
            self.assertEqual(len(after["memberships"]), 1)
            self.assertEqual(len(after["membership_roles"]), 1)
            self.assertEqual(after["organization"][0][4], "ACTIVE")
            expected_events = Counter({
                "PolicyAccepted",
                "ConsentGranted",
                "UserActivated",
                "MembershipActivated",
                "MembershipRoleGranted",
                "OrganizationActivated",
                "AccessInvitationAccepted",
            })
        else:
            self.assertEqual(len(after["memberships"]), 1)
            self.assertEqual(len(after["membership_roles"]), 1)
            self.assertEqual(after["organization"][0][4], "ACTIVE")
            self.assertEqual(after["organization"][0][7], 2)
            expected_events = Counter({
                "PolicyAccepted",
                "ConsentGranted",
                "PolicyRequirementsSatisfied",
                "MembershipActivated",
                "MembershipRoleGranted",
                "AccessInvitationAccepted",
            })
        self.assertEqual(Counter(row[1] for row in after["outbox"]), expected_events)
        self._assert_committed_outbox_matches_iam_v1(request, expected_events)

    def _assert_committed_outbox_matches_iam_v1(
        self,
        request: AcceptAccessInvitationDatabaseRequest,
        expected_events: Counter[str],
    ) -> None:
        columns = (
            "event_id",
            "event_type",
            "schema_version",
            "occurred_at",
            "aggregate_type",
            "aggregate_id",
            "aggregate_version",
            "actor_kind",
            "actor_id",
            "original_actor_id",
            "correlation_id",
            "causation_id",
            "trace_id",
            "organization_id",
            "payload",
        )
        with self._connect_admin() as connection:
            rows = connection.execute(
                "SELECT " + ",".join(columns) + " FROM infra.outbox_events "
                "WHERE causation_id=%s ORDER BY event_id",
                (request.scope.command_id,),
            ).fetchall()
        validator = ClosedSchemaValidator.for_events()
        observed: Counter[str] = Counter()
        for row in rows:
            envelope = dict(zip(columns, row))
            for name in (
                "event_id",
                "aggregate_id",
                "actor_id",
                "original_actor_id",
                "correlation_id",
                "causation_id",
                "trace_id",
                "organization_id",
            ):
                if envelope[name] is not None:
                    envelope[name] = str(envelope[name])
            envelope["occurred_at"] = (
                envelope["occurred_at"]
                .astimezone(timezone.utc)
                .isoformat()
                .replace("+00:00", "Z")
            )
            validator.validate(envelope)
            observed[envelope["event_type"]] += 1
        self.assertEqual(observed, expected_events)

    def test_creator_and_initial_admin_happy_paths_persist_the_complete_graph(self) -> None:
        """TEST-DB-IAM-004.C01/C02: both closed authority shapes are atomic."""

        for kind in ("creator", "admin"):
            with self.subTest(kind=kind):
                fixture = self._seed_accept_graph(kind=kind)
                request = self._request(fixture)
                factory = self._factory(
                    connections=self._connection_source()
                )
                result = self._execute(factory, request)
                self.assertFalse(
                    getattr(result, "behavior_not_available", False),
                    "creator/admin PostgreSQL persistence is unavailable",
                )
                self.assertFalse(result.replayed)
                self.assertEqual(
                    result.successor_session_id,
                    request.successor.session_id,
                )
                self._assert_happy_facts(fixture, request)

    def test_non_utc_database_time_is_normalized_for_write_and_replay(self) -> None:
        fixture = self._seed_accept_graph(kind="creator")
        request = self._request(fixture)
        source = self._connection_source(
            session_timezone_name="Asia/Shanghai"
        )
        factory = self._factory(connections=source)

        committed = self._execute(factory, request)
        replayed = self._execute(factory, request)

        self.assertFalse(committed.replayed)
        self.assertTrue(replayed.replayed)
        self.assertEqual(replayed.safe_response, committed.safe_response)
        self.assertEqual(len(source.observed_server_times), 2)
        self.assertTrue(
            all(
                value.utcoffset() == timedelta(hours=8)
                for value in source.observed_server_times
            )
        )
        self.assertEqual(
            [name for name, _value in source.observed_transaction_time_zones],
            ["UTC", "UTC"],
        )
        self.assertTrue(
            all(
                value.utcoffset() == timedelta(0)
                for _name, value in source.observed_transaction_time_zones
            )
        )
        self.assertEqual(
            committed.safe_response["me"]["status"],
            "ACTIVE",
        )

    def test_active_user_accepts_non_initial_active_organization_invitation(self) -> None:
        """Existing active identity gains only the invited membership authority."""

        fixture = self._seed_accept_graph(kind="member")
        self._seed_existing_creator_authority(fixture)
        request = self._request(fixture)
        before = self._snapshot(fixture, request.scope.command_id)
        result = self._execute(
            self._factory(connections=self._connection_source()),
            request,
        )
        self.assertFalse(result.replayed)
        self.assertEqual(result.successor_session_id, request.successor.session_id)
        self._assert_happy_facts(
            fixture,
            request,
            expected_policy_acceptance_count=2,
        )
        after = self._snapshot(fixture, request.scope.command_id)
        self.assertEqual(after["user"][0][3], before["user"][0][3] + 1)
        self.assertEqual(result.safe_response["me"]["aggregate_version"], 3)
        self.assertEqual(result.safe_response["me"]["entity_tag"], '"v3"')
        self.assertEqual(result.safe_response["me"]["user_roles"], ["CREATOR"])
        self.assertEqual(
            sorted(
                requirement["role"]
                for requirement in result.safe_response["me"]["policy_requirements"]
            ),
            ["CREATOR", "DEMAND_OWNER"],
        )
        app_source = TrackingRealConnectionSource(
            self.postgres.conninfo(database=self.database, user="iam_app")
        )
        onboarding_source = TrackingRealConnectionSource(
            self.postgres.conninfo(database=self.database, user="iam_onboarding")
        )
        canonical_read = PsycopgIamReadModelRepository(
            app_connections=app_source,
            onboarding_connections=onboarding_source,
        ).read_me(
            actor_user_id=str(fixture.actor_id),
            session_id=str(request.successor.session_id),
        )
        self.assertEqual(
            result.safe_response["me"],
            project_canonical_me_dto(
                canonical_read.facts_copy(),
                at=canonical_read.transaction_time,
            ),
        )
        self.assertEqual(
            after["organization"][0][7],
            before["organization"][0][7],
        )
        self.assertNotIn(
            "UserActivated",
            {row[1] for row in after["outbox"]},
        )
        self.assertNotIn(
            "OrganizationActivated",
            {row[1] for row in after["outbox"]},
        )

    def test_historical_accept_cannot_reopen_the_definer_snapshot(self) -> None:
        """A freshly minted Receipt cannot authorize an old accepted Invitation."""

        fixture = self._seed_accept_graph(kind="creator")
        accepted_request = self._request(fixture, payload_label="accepted-once")
        accepted = self._execute(
            self._factory(connections=self._connection_source()),
            accepted_request,
        )
        self.assertFalse(accepted.replayed)

        forged = self._request(fixture, payload_label="historical-forgery")
        forged = replace(
            forged,
            receipt=replace(
                forged.receipt,
                idempotency_key_digest=_digest(
                    "historical-forgery-" + forged.scope.command_id.hex
                ),
            ),
        )
        with self._connect_onboarding(autocommit=True) as connection:
            connection.execute("BEGIN")
            self._set_direct_accept_context(connection, forged)
            claimed = connection.execute(
                "INSERT INTO infra.command_receipts ("
                "id,principal_kind,principal_id,command_name,command_version,"
                "idempotency_key_digest,idempotency_key_digest_key_id,payload_hash,"
                "payload_hash_key_id,canonicalization_version,target_kind,target_id,"
                "http_method,canonical_path,if_match_version,status,"
                "response_schema_version,safe_response_body,reconstruction_metadata,"
                "created_at,retain_until,completed_at) VALUES ("
                "%s,'USER',%s,'AcceptAccessInvitation',1,%s,%s,%s,%s,%s,"
                "'AccessInvitation',%s,'POST',%s,1,'IN_PROGRESS',NULL,NULL,NULL,"
                "transaction_timestamp(),%s,NULL) RETURNING id",
                (
                    forged.receipt.receipt_id,
                    forged.receipt.principal_id,
                    forged.receipt.idempotency_key_digest,
                    forged.receipt.idempotency_key_digest_key_id,
                    forged.receipt.payload_hash,
                    forged.receipt.payload_hash_key_id,
                    forged.receipt.canonicalization_version,
                    forged.scope.invitation_id,
                    "/v1/access-invitations/%s/accept"
                    % forged.scope.invitation_id,
                    forged.receipt.retain_until,
                ),
            ).fetchone()
            self.assertEqual(claimed, (forged.scope.command_id,))
            self.assertEqual(
                connection.execute(
                    "SELECT iam_api.read_acceptance_me_snapshot_v2()"
                ).fetchone(),
                (None,),
            )
            connection.execute("ROLLBACK")

    def test_iam40_exact_pending_enrollment_resolves_and_accepts_membership(
        self,
    ) -> None:
        """IAM0039's provider-only principal can reach the existing atomic UoW."""

        self._apply_iam40_preview()
        fixture = self._seed_accept_graph(kind="member")
        with self._connect_admin() as connection:
            connection.execute("SET LOCAL session_replication_role = 'replica'")
            connection.execute(
                "UPDATE iam.users SET status='PENDING_ENROLLMENT',"
                "aggregate_version=1,updated_at=transaction_timestamp() "
                "WHERE id=%s",
                (fixture.actor_id,),
            )
        request = self._request(fixture)

        self.assertEqual(
            self._resolve_receipt_principal(fixture),
            {
                "decision_code": "AUTHORIZED",
                "actor_user_id": str(fixture.actor_id),
                "session_id": str(fixture.session_id),
                "session_family_id": str(fixture.session_family_id),
            },
        )
        scope = self._resolve_accept_scope(fixture, request)
        self.assertEqual(scope.actor_user_id, fixture.actor_id)
        self.assertEqual(scope.auth_transaction_id, fixture.auth_transaction_id)
        self.assertEqual(scope.invitation_id, fixture.invitation_id)
        self.assertEqual(scope.user_status, "PENDING_ENROLLMENT")
        self.assertEqual(scope.target_role, "DEMAND_OWNER")

        result = self._execute(
            self._factory(connections=self._connection_source()),
            request,
        )
        self.assertFalse(result.replayed)
        self.assertEqual(result.successor_session_id, request.successor.session_id)
        with self._connect_admin() as connection:
            facts = connection.execute(
                "SELECT u.status,i.status,m.status,g.revoked_at "
                "FROM iam.users AS u "
                "JOIN iam.access_invitations AS i ON i.id=%s "
                "JOIN iam.memberships AS m ON m.source_invitation_id=i.id "
                "JOIN iam.membership_role_grants AS g "
                "ON g.source_invitation_id=i.id "
                "WHERE u.id=%s",
                (fixture.invitation_id, fixture.actor_id),
            ).fetchone()
        self.assertEqual(facts, ("ACTIVE", "ACCEPTED", "ACTIVE", None))

    def test_iam40_pending_enrollment_is_closed_for_every_inexact_shape(
        self,
    ) -> None:
        self._apply_iam40_preview()

        def pending_fixture() -> tuple[
            AcceptFixture, AcceptAccessInvitationDatabaseRequest
        ]:
            fixture = self._seed_accept_graph(kind="member")
            with self._connect_admin() as connection:
                connection.execute(
                    "SET LOCAL session_replication_role = 'replica'"
                )
                connection.execute(
                    "UPDATE iam.users SET status='PENDING_ENROLLMENT',"
                    "aggregate_version=1,updated_at=transaction_timestamp() "
                    "WHERE id=%s",
                    (fixture.actor_id,),
                )
            return fixture, self._request(fixture)

        wrong_invitation, wrong_invitation_request = pending_fixture()
        inexact_invitation_id = _new_id()
        ordinary_pending, ordinary_pending_request = pending_fixture()
        with self._connect_admin() as connection:
            connection.execute("SET LOCAL session_replication_role = 'replica'")
            connection.execute(
                "UPDATE iam.sessions SET rotation_reason='LOGIN' WHERE id=%s",
                (ordinary_pending.session_id,),
            )
        wrong_purpose, wrong_purpose_request = pending_fixture()
        with self._connect_admin() as connection:
            connection.execute("SET LOCAL session_replication_role = 'replica'")
            connection.execute(
                "UPDATE iam.auth_transactions SET purpose='STEP_UP',"
                "initiating_session_id=%s,initiating_user_id=%s,"
                "expected_user_id=%s WHERE id=%s",
                (
                    wrong_purpose.session_id,
                    wrong_purpose.actor_id,
                    wrong_purpose.actor_id,
                    wrong_purpose.auth_transaction_id,
                ),
            )

        cases = (
            (
                "wrong-invitation",
                wrong_invitation,
                wrong_invitation_request,
                inexact_invitation_id,
                "ACCESS_INVITATION_UNAVAILABLE",
            ),
            (
                "ordinary-pending",
                ordinary_pending,
                ordinary_pending_request,
                ordinary_pending.invitation_id,
                "ACCESS_INVITATION_UNAVAILABLE",
            ),
            (
                "wrong-auth-purpose",
                wrong_purpose,
                wrong_purpose_request,
                wrong_purpose.invitation_id,
                "ACCESS_INVITATION_UNAVAILABLE",
            ),
        )
        for label, fixture, request, invitation_id, scope_error in cases:
            with self.subTest(label=label):
                self.assertEqual(
                    self._resolve_receipt_principal(
                        fixture, invitation_id=invitation_id
                    ),
                    {"decision_code": "AUTHENTICATION_REQUIRED"},
                )
                with self.assertRaises(IamError) as captured:
                    self._resolve_accept_scope(
                        fixture,
                        request,
                        invitation_id=invitation_id,
                    )
                self.assertEqual(captured.exception.code, scope_error)

        for status in ("SUSPENDED", "CLOSED"):
            with self.subTest(user_status=status):
                fixture, request = pending_fixture()
                with self._connect_admin() as connection:
                    connection.execute(
                        "SET LOCAL session_replication_role = 'replica'"
                    )
                    connection.execute(
                        "UPDATE iam.users SET status=%s,"
                        "aggregate_version=2,updated_at=transaction_timestamp() "
                        "WHERE id=%s",
                        (status, fixture.actor_id),
                    )
                self.assertEqual(
                    self._resolve_receipt_principal(fixture),
                    {"decision_code": "AUTHENTICATION_REQUIRED"},
                )
                with self.assertRaises(IamError) as captured:
                    self._resolve_accept_scope(fixture, request)
                self.assertEqual(
                    captured.exception.code, "AUTHENTICATION_REQUIRED"
                )

    def test_iam40_preserves_exact_active_step_up_accept_scope(self) -> None:
        self._apply_iam40_preview()
        fixture = self._seed_accept_graph(kind="member")
        with self._connect_admin() as connection:
            connection.execute("SET LOCAL session_replication_role = 'replica'")
            connection.execute(
                "UPDATE iam.auth_transactions SET purpose='STEP_UP',"
                "initiating_session_id=%s,initiating_user_id=%s,"
                "expected_user_id=%s WHERE id=%s",
                (
                    fixture.session_id,
                    fixture.actor_id,
                    fixture.actor_id,
                    fixture.auth_transaction_id,
                ),
            )
            connection.execute(
                "UPDATE iam.sessions SET rotation_reason='STEP_UP' WHERE id=%s",
                (fixture.session_id,),
            )
        request = self._request(fixture)

        self.assertEqual(
            self._resolve_receipt_principal(fixture)["decision_code"],
            "AUTHORIZED",
        )
        scope = self._resolve_accept_scope(fixture, request)
        self.assertEqual(scope.auth_transaction_id, fixture.auth_transaction_id)
        self.assertEqual(scope.invitation_id, fixture.invitation_id)

    def test_exact_evidence_reuses_without_duplicate_events_and_conflict_rolls_back(self) -> None:
        exact_fixture = self._seed_accept_graph(kind="creator")
        acceptance_id, grant_id = self._seed_existing_evidence(
            exact_fixture,
            include_policy_acceptance=True,
            consent_policy=exact_fixture.policy,
        )
        exact_request = self._request(exact_fixture)
        exact_request = replace(
            exact_request,
            generated_ids=replace(
                exact_request.generated_ids,
                policy_acceptance_ids=(),
                consent_grant_ids=(),
                outbox_event_ids=exact_request.generated_ids.outbox_event_ids[:3],
            ),
        )
        result = self._execute(
            self._factory(connections=self._connection_source()),
            exact_request,
        )
        self.assertFalse(result.replayed)
        exact_after = self._snapshot(exact_fixture, exact_request.scope.command_id)
        self.assertEqual([row[0] for row in exact_after["acceptances"]], [acceptance_id])
        self.assertEqual([row[0] for row in exact_after["consents"]], [grant_id])
        self.assertEqual(
            Counter(row[1] for row in exact_after["outbox"]),
            Counter({"UserActivated", "UserRoleGranted", "AccessInvitationAccepted"}),
        )

        conflict_fixture = self._seed_accept_graph(kind="creator")
        self._seed_existing_evidence(
            conflict_fixture,
            include_policy_acceptance=False,
            consent_policy=self.member_policy,
        )
        conflict_request = self._request(conflict_fixture)
        before = self._snapshot(conflict_fixture, conflict_request.scope.command_id)
        with self.assertRaises(IamError) as captured:
            self._execute(
                self._factory(connections=self._connection_source()),
                conflict_request,
            )
        self.assertEqual(captured.exception.code, "INVALID_STATE_TRANSITION")
        self.assertEqual(
            self._snapshot(conflict_fixture, conflict_request.scope.command_id),
            before,
        )

    def test_expired_active_consent_is_cas_closed_then_regranted_atomically(self) -> None:
        now = datetime.now(timezone.utc)
        fixture = self._seed_accept_graph(
            kind="creator",
            session_auth_time=now - timedelta(days=400),
        )
        acceptance_id, expired_grant_id = self._seed_existing_evidence(
            fixture,
            include_policy_acceptance=True,
            consent_policy=fixture.policy,
            consent_granted_at=now - timedelta(days=366),
        )
        self.assertIsNotNone(acceptance_id)
        request = self._request(fixture)
        request = replace(
            request,
            generated_ids=replace(
                request.generated_ids,
                policy_acceptance_ids=(),
                outbox_event_ids=request.generated_ids.outbox_event_ids[:4],
            ),
        )
        before = self._snapshot(fixture, request.scope.command_id)
        old_row = next(
            row for row in before["consents"] if row[0] == expired_grant_id
        )
        self.assertEqual(old_row[21], "ACTIVE")
        self.assertLessEqual(old_row[13], now)

        for target in (
            AcceptWriteCheckpoint.CONSENT_GRANT_EXPIRE,
            AcceptWriteCheckpoint.CONSENT_GRANT_INSERT,
        ):
            with self.subTest(rollback_after=target.value):
                with self.assertRaises(InjectedAcceptWriteFailure):
                    self._execute(
                        self._factory(
                            connections=self._connection_source(),
                            fault_injector=RaiseAtLogicalWrite((target, 0)),
                        ),
                        request,
                    )
                self.assertEqual(
                    self._snapshot(fixture, request.scope.command_id),
                    before,
                )

        result = self._execute(
            self._factory(connections=self._connection_source()),
            request,
        )
        self.assertFalse(result.replayed)
        after = self._snapshot(fixture, request.scope.command_id)
        old_row = next(
            row for row in after["consents"] if row[0] == expired_grant_id
        )
        new_row = next(
            row
            for row in after["consents"]
            if row[0] == request.generated_ids.consent_grant_ids[0]
        )
        self.assertEqual((old_row[21], old_row[22], old_row[23]), (
            "EXPIRED",
            None,
            2,
        ))
        self.assertEqual(new_row[21], "ACTIVE")
        self.assertGreater(new_row[13], new_row[12])
        self.assertEqual(
            [row[0] for row in after["acceptances"]],
            [acceptance_id],
        )
        expected_events = Counter({
            "ConsentGranted",
            "UserActivated",
            "UserRoleGranted",
            "AccessInvitationAccepted",
        })
        self.assertEqual(
            Counter(row[1] for row in after["outbox"]),
            expected_events,
        )
        self._assert_committed_outbox_matches_iam_v1(request, expected_events)

    def test_expired_consent_cas_rls_is_exact_and_concurrent(self) -> None:
        with self._connect_admin() as connection:
            policies = connection.execute(
                "SELECT policyname,cmd,roles FROM pg_catalog.pg_policies "
                "WHERE schemaname='iam' AND tablename='consent_grants' "
                "AND policyname=ANY(%s) ORDER BY policyname",
                (
                    [
                        "rls_consent_grant_accept",
                        "rls_consent_grant_accept_expire",
                        "rls_consent_grant_accept_insert",
                    ],
                ),
            ).fetchall()
            can_delete = connection.execute(
                "SELECT has_table_privilege('iam_onboarding',"
                "'iam.consent_grants','DELETE')"
            ).fetchone()[0]
        self.assertEqual(
            policies,
            [
                ("rls_consent_grant_accept", "SELECT", ["iam_onboarding"]),
                (
                    "rls_consent_grant_accept_expire",
                    "UPDATE",
                    ["iam_onboarding"],
                ),
                (
                    "rls_consent_grant_accept_insert",
                    "INSERT",
                    ["iam_onboarding"],
                ),
            ],
        )
        self.assertFalse(can_delete)

        now = datetime.now(timezone.utc)
        fixture = self._seed_accept_graph(
            kind="creator",
            session_auth_time=now - timedelta(days=400),
        )
        _acceptance_id, expired_grant_id = self._seed_existing_evidence(
            fixture,
            include_policy_acceptance=False,
            consent_policy=fixture.policy,
            consent_granted_at=now - timedelta(days=366),
        )
        request = self._request(fixture)
        with self._connect_admin() as connection:
            expires_at = connection.execute(
                "SELECT expires_at FROM iam.consent_grants WHERE id=%s",
                (expired_grant_id,),
            ).fetchone()[0]

        with self._connect_onboarding(autocommit=True) as connection:
            connection.execute("BEGIN")
            self._set_direct_accept_context(connection, request)
            connection.execute(
                "SELECT pg_catalog.set_config('app.actor_user_id',%s,true)",
                (str(_new_id()),),
            )
            self.assertIsNone(
                self._direct_expire_consent(
                    connection,
                    grant_id=expired_grant_id,
                    actor_id=fixture.actor_id,
                    aggregate_version=1,
                    expires_at=expires_at,
                    now=now,
                )
            )
            connection.execute("ROLLBACK")

        with self._connect_onboarding(autocommit=True) as connection:
            connection.execute("BEGIN")
            self._set_direct_accept_context(connection, request)
            connection.execute(
                "SELECT pg_catalog.set_config('app.policy_bundle_id',%s,true)",
                (str(_new_id()),),
            )
            self.assertIsNone(
                self._direct_expire_consent(
                    connection,
                    grant_id=expired_grant_id,
                    actor_id=fixture.actor_id,
                    aggregate_version=1,
                    expires_at=expires_at,
                    now=now,
                )
            )
            connection.execute("ROLLBACK")

        with self._connect_onboarding(autocommit=True) as connection:
            connection.execute("BEGIN")
            self._set_direct_accept_context(connection, request)
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                self._direct_expire_consent(
                    connection,
                    grant_id=expired_grant_id,
                    actor_id=fixture.actor_id,
                    aggregate_version=1,
                    expires_at=expires_at,
                    now=now,
                    status="WITHDRAWN",
                )
            connection.execute("ROLLBACK")

        unexpired_fixture = self._seed_accept_graph(kind="creator")
        _unused, unexpired_grant_id = self._seed_existing_evidence(
            unexpired_fixture,
            include_policy_acceptance=False,
            consent_policy=unexpired_fixture.policy,
        )
        unexpired_request = self._request(unexpired_fixture)
        with self._connect_admin() as connection:
            unexpired_at = connection.execute(
                "SELECT expires_at FROM iam.consent_grants WHERE id=%s",
                (unexpired_grant_id,),
            ).fetchone()[0]
        with self._connect_onboarding(autocommit=True) as connection:
            connection.execute("BEGIN")
            self._set_direct_accept_context(connection, unexpired_request)
            self.assertIsNone(
                self._direct_expire_consent(
                    connection,
                    grant_id=unexpired_grant_id,
                    actor_id=unexpired_fixture.actor_id,
                    aggregate_version=1,
                    expires_at=unexpired_at,
                    now=now,
                )
            )
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                connection.execute(
                    "UPDATE iam.consent_grants SET status='EXPIRED',"
                    "aggregate_version=aggregate_version+1,updated_at=%s "
                    "WHERE id=%s",
                    (now, unexpired_grant_id),
                )
            connection.execute("ROLLBACK")

        second_started = threading.Event()

        def competing_cas() -> Optional[Tuple[Any, ...]]:
            with self._connect_onboarding(autocommit=True) as contender:
                contender.execute("BEGIN")
                self._set_direct_accept_context(contender, request)
                second_started.set()
                row = self._direct_expire_consent(
                    contender,
                    grant_id=expired_grant_id,
                    actor_id=fixture.actor_id,
                    aggregate_version=1,
                    expires_at=expires_at,
                    now=now,
                )
                contender.execute("COMMIT")
                return row

        with self._connect_onboarding(autocommit=True) as winner:
            winner.execute("BEGIN")
            self._set_direct_accept_context(winner, request)
            first = self._direct_expire_consent(
                winner,
                grant_id=expired_grant_id,
                actor_id=fixture.actor_id,
                aggregate_version=1,
                expires_at=expires_at,
                now=now,
            )
            with ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(competing_cas)
                self.assertTrue(second_started.wait(timeout=5))
                winner.execute("COMMIT")
                second = future.result(timeout=5)
        self.assertEqual(
            sorted(row is not None for row in (first, second)),
            [False, True],
        )
        with self._connect_admin() as connection:
            final = connection.execute(
                "SELECT status,aggregate_version,withdrawn_at "
                "FROM iam.consent_grants WHERE id=%s",
                (expired_grant_id,),
            ).fetchone()
        self.assertEqual(final, ("EXPIRED", 2, None))

    def test_existing_membership_rejects_new_invitation_without_partial_writes(self) -> None:
        fixture = self._seed_accept_graph(kind="member")
        self._seed_existing_membership(fixture)
        request = self._request(fixture)
        before = self._snapshot(fixture, request.scope.command_id)
        with self.assertRaises(IamError) as captured:
            self._execute(
                self._factory(connections=self._connection_source()),
                request,
            )
        self.assertEqual(captured.exception.code, "INVALID_STATE_TRANSITION")
        self.assertEqual(
            self._snapshot(fixture, request.scope.command_id),
            before,
        )

    def test_issued_bundle_history_can_accept_refreshed_current_bundle(self) -> None:
        fixture = self._seed_accept_graph(kind="creator")
        issued_bundle = fixture.policy.bundle_id
        current = self._publish_replacement_policy(fixture.policy)
        refreshed_fixture = replace(fixture, policy=current)
        request = self._request(refreshed_fixture)
        result = self._execute(
            self._factory(connections=self._connection_source()),
            request,
        )
        self.assertFalse(result.replayed)
        self.assertNotEqual(issued_bundle, current.bundle_id)
        self.assertEqual(
            result.safe_response["invitation"]["required_policy_bundle_id"],
            str(current.bundle_id),
        )
        after = self._snapshot(refreshed_fixture, request.scope.command_id)
        accepted_event = next(
            row for row in after["outbox"] if row[1] == "AccessInvitationAccepted"
        )
        self.assertEqual(
            accepted_event[14]["invitation_binding"]["issued_policy_bundle_id"],
            str(issued_bundle),
        )

    def test_prior_acceptance_identity_reuses_across_bundle_replacement(self) -> None:
        fixture = self._seed_accept_graph(kind="member")
        with self._connect_admin() as connection:
            connection.execute("SET LOCAL session_replication_role = 'replica'")
            connection.execute(
                "UPDATE iam.auth_transactions SET purpose='STEP_UP',"
                "initiating_session_id=%s,initiating_user_id=%s,"
                "expected_user_id=%s WHERE id=%s",
                (
                    fixture.session_id,
                    fixture.actor_id,
                    fixture.actor_id,
                    fixture.auth_transaction_id,
                ),
            )
            connection.execute(
                "UPDATE iam.sessions SET rotation_reason='STEP_UP' WHERE id=%s",
                (fixture.session_id,),
            )
        acceptance_id = self._seed_existing_policy_acceptance(fixture)
        current = self._publish_replacement_policy(
            fixture.policy,
            reuse_required_document=True,
        )
        refreshed_fixture = replace(fixture, policy=current)
        request = self._request(refreshed_fixture)
        request = replace(
            request,
            generated_ids=replace(
                request.generated_ids,
                policy_acceptance_ids=(),
                outbox_event_ids=request.generated_ids.outbox_event_ids[:5],
            ),
        )
        resolved = PsycopgOrganizationAcceptScopeResolver(
            connections=self._connection_source()
        ).resolve(
            actor_user_id=refreshed_fixture.actor_id,
            session_id=refreshed_fixture.session_id,
            invitation_id=refreshed_fixture.invitation_id,
            policy_bundle_id=current.bundle_id,
            policy_acceptances=request.policy_acceptances,
            consent_choices=request.consent_choices,
        )
        self.assertEqual(resolved.missing_policy_document_ids, ())
        self.assertEqual(
            resolved.missing_consent_offer_ids,
            (current.consent_offer_id,),
        )
        result = self._execute(
            self._factory(connections=self._connection_source()),
            request,
        )
        self.assertFalse(result.replayed)
        after = self._snapshot(refreshed_fixture, request.scope.command_id)
        self.assertEqual([row[0] for row in after["acceptances"]], [acceptance_id])
        self.assertNotIn(
            "PolicyAccepted",
            {row[1] for row in after["outbox"]},
        )

    def test_wrong_evidence_is_forced_before_session_rotation(self) -> None:
        fixture = self._seed_accept_graph(kind="creator")
        request = self._request(fixture)
        before = self._snapshot(fixture, request.scope.command_id)
        source = self._connection_source()
        injector = InjectWrongEvidenceAtPhaseBoundary(
            source=source,
            fixture=fixture,
            request=request,
            late=False,
        )
        factory = self._factory(
            connections=source,
            fault_injector=injector,
        )
        with self.assertRaises(psycopg.errors.CheckViolation) as captured:
            self._execute(factory, request)
        self.assertTrue(injector.injected)
        self.assertEqual(
            captured.exception.diag.constraint_name,
            "trg_evidence_matches_session_auth",
        )
        self.assertEqual(
            self._snapshot(fixture, request.scope.command_id),
            before,
        )

    def test_protected_evidence_write_is_immediate_after_phase_boundary(self) -> None:
        fixture = self._seed_accept_graph(kind="creator")
        request = self._request(fixture)
        before = self._snapshot(fixture, request.scope.command_id)
        source = self._connection_source()
        injector = InjectWrongEvidenceAtPhaseBoundary(
            source=source,
            fixture=fixture,
            request=request,
            late=True,
        )
        factory = self._factory(
            connections=source,
            fault_injector=injector,
        )
        with self.assertRaises(LateProtectedWriteRejected):
            self._execute(factory, request)
        self.assertFalse(injector.injected)
        self.assertEqual(
            injector.rejected_constraint,
            "trg_evidence_matches_session_auth",
        )
        self.assertEqual(
            self._snapshot(fixture, request.scope.command_id),
            before,
        )

    def test_every_actual_logical_write_fault_rolls_back_every_fact(self) -> None:
        """TEST-DB-IAM-004.C03: named/ordinal faults leave exact snapshots."""

        self.assertEqual(tuple(AcceptWriteCheckpoint), ACCEPT_WRITE_CHECKPOINTS)
        for kind in ("creator", "admin"):
            for target in self._fault_targets(kind):
                with self.subTest(kind=kind, checkpoint=target[0].value, ordinal=target[1]):
                    fixture = self._seed_accept_graph(kind=kind)
                    request = self._request(fixture)
                    before = self._snapshot(fixture, request.scope.command_id)
                    factory = self._factory(
                        connections=self._connection_source(),
                        fault_injector=RaiseAtLogicalWrite(target),
                    )
                    with self.assertRaises(InjectedAcceptWriteFailure):
                        self._execute(factory, request)
                    self.assertEqual(
                        self._snapshot(fixture, request.scope.command_id),
                        before,
                    )

    def test_same_key_two_real_connections_claim_once_then_replay(self) -> None:
        """TEST-DB-IAM-RECEIPT-001.C02: unique wait produces owner + replay."""

        fixture = self._seed_accept_graph(kind="creator")
        request = self._request(fixture)
        source = self._connection_source()
        # This case asserts two connections: wait for replay instead of retrying.
        factory = self._factory(
            connections=source,
            fault_injector=BarrierAtReceiptClaim(),
            settings=AcceptPostgresSettings(lock_timeout_ms=10_000),
        )
        with ThreadPoolExecutor(max_workers=2) as executor:
            outcomes = tuple(
                executor.map(
                    lambda _item: self._execute(factory, request),
                    range(2),
                )
            )
        self.assertEqual(sorted(result.replayed for result in outcomes), [False, True])
        self.assertEqual(len(set(source.backend_pids)), 2)
        self._assert_happy_facts(fixture, request)

    def test_three_precommit_retries_follow_the_initial_attempt(self) -> None:
        fixture = self._seed_accept_graph(kind="creator")
        request = self._request(fixture)
        source = self._connection_source()
        faults = FailFirstThreeReceiptClaims()
        result = self._execute(
            self._factory(
                connections=source,
                fault_injector=faults,
            ),
            request,
        )
        self.assertFalse(result.replayed)
        self.assertEqual(faults.attempts, 4)
        self.assertEqual(len(source.released), 4)
        self.assertFalse(source.discarded)
        self._assert_happy_facts(fixture, request)

    def test_same_key_different_payload_conflicts_before_business_guards(self) -> None:
        """TEST-DB-IAM-RECEIPT-001.C01: target is not part of receipt identity."""

        fixture = self._seed_accept_graph(kind="creator")
        request = self._request(fixture)
        factory = self._factory(
            connections=self._connection_source()
        )
        self._execute(factory, request)
        conflicting = replace(
            request,
            receipt=replace(request.receipt, payload_hash=_digest("payload-b")),
        )
        with self.assertRaises(IamError) as captured:
            self._execute(factory, conflicting)
        self.assertEqual(captured.exception.code, "IDEMPOTENCY_KEY_REUSED")
        self._assert_happy_facts(fixture, request)

    def test_corrupt_completed_receipt_body_is_never_replayed(self) -> None:
        """Closed DTO and request bindings gate every completed receipt replay."""

        mutations = (
            lambda body: {**body, "raw_secret": RAW_SESSION_SENTINEL},
            lambda body: {
                **body,
                "invitation": {
                    **body["invitation"],
                    "invitation_id": str(_new_id()),
                    "aggregate_version": 99,
                },
            },
            lambda body: {
                **body,
                "me": {**body["me"], "policy_requirements": []},
            },
            lambda body: {
                **body,
                "me": {
                    **body["me"],
                    "policy_requirements": [
                        {
                            **body["me"]["policy_requirements"][0],
                            "scope_type": "ORGANIZATION_ROLE",
                            "scope_id": str(_new_id()),
                        }
                    ],
                },
            },
            lambda body: {
                **body,
                "me": {
                    **body["me"],
                    "policy_requirements": [
                        {
                            **body["me"]["policy_requirements"][0],
                            "required_policy_bundle_id": str(_new_id()),
                        }
                    ],
                },
            },
            lambda body: {
                **body,
                "me": {
                    **body["me"],
                    "user_roles": [],
                },
            },
        )
        for mutate in mutations:
            with self.subTest(mutation=mutate.__code__.co_firstlineno):
                fixture = self._seed_accept_graph(kind="creator")
                request = self._request(fixture)
                factory = self._factory(connections=self._connection_source())
                original = self._execute(factory, request)
                corrupted = mutate(dict(original.safe_response))
                with self._connect_admin() as connection:
                    connection.execute(
                        "ALTER TABLE infra.command_receipts "
                        "DISABLE TRIGGER trg_command_receipt_transition"
                    )
                    connection.execute(
                        "ALTER TABLE infra.command_receipts "
                        "DISABLE TRIGGER trg_receipt_completed_at_commit"
                    )
                    connection.execute(
                        "UPDATE infra.command_receipts SET safe_response_body=%s "
                        "WHERE id=%s",
                        (Jsonb(corrupted), request.scope.command_id),
                    )
                    connection.execute(
                        "ALTER TABLE infra.command_receipts "
                        "ENABLE TRIGGER trg_command_receipt_transition"
                    )
                    connection.execute(
                        "ALTER TABLE infra.command_receipts "
                        "ENABLE TRIGGER trg_receipt_completed_at_commit"
                    )
                with self.assertRaises(IamError) as captured:
                    self._execute(factory, request)
                self.assertEqual(captured.exception.code, "SERVICE_UNAVAILABLE")

    def test_commit_ack_loss_discards_connection_and_new_connection_recovers(self) -> None:
        """TEST-DB-IAM-RECEIPT-001.C04: COMMIT_SENT is never auto-retried."""

        fixture = self._seed_accept_graph(kind="creator")
        request = self._request(fixture)
        source = self._connection_source(lose_first_commit_ack=True)
        factory = self._factory(connections=source)
        with self.assertRaises(AcceptCommandOutcomeUnknownError) as captured:
            self._execute(factory, request)
        self.assertEqual(captured.exception.code, "COMMAND_OUTCOME_UNKNOWN")
        self.assertEqual(len(source.discarded), 1)
        self.assertFalse(source.released)

        recovered = self._execute(factory, request)
        self.assertTrue(recovered.replayed)
        self.assertIsNone(recovered.successor_session_id)
        self.assertGreaterEqual(len(set(source.backend_pids)), 2)
        self._assert_happy_facts(fixture, request)

    def test_adapter_is_online_iam_onboarding_and_owner_cannot_be_configured(self) -> None:
        """TEST-DB-RLS-IAM-001.C03: production UoW has no owner bypass."""

        fixture = self._seed_accept_graph(kind="admin")
        request = self._request(fixture)
        with self.assertRaises(ValueError):
            AcceptPostgresSettings(runtime_role="schema_owner")
        with self._connect_onboarding() as connection:
            role = connection.execute(
                "SELECT current_user, session_user, rolsuper, rolbypassrls "
                "FROM pg_catalog.pg_roles WHERE rolname=current_user"
            ).fetchone()
            self.assertEqual(role, ("iam_onboarding", "iam_onboarding", False, False))
            visible = connection.execute(
                "SELECT id FROM iam.access_invitations WHERE id=%s",
                (fixture.invitation_id,),
            ).fetchall()
            self.assertEqual(visible, [])
            forced = connection.execute(
                "SELECT relrowsecurity,relforcerowsecurity,owner.rolname "
                "FROM pg_catalog.pg_class AS relation "
                "JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid=relation.relnamespace "
                "JOIN pg_catalog.pg_roles AS owner ON owner.oid=relation.relowner "
                "WHERE namespace.nspname='iam' AND relation.relname='access_invitations'"
            ).fetchone()
            self.assertEqual(forced, (True, True, "schema_owner"))

        source = self._connection_source()
        result = self._execute(
            self._factory(connections=source),
            request,
        )
        self.assertFalse(
            getattr(result, "behavior_not_available", False),
            "online iam_onboarding UoW is unavailable",
        )
        self.assertFalse(result.replayed)
        self.assertTrue(source.backend_pids)
        self._assert_happy_facts(fixture, request)

    def test_receipt_miss_rejects_runtime_keys_not_active_in_database(self) -> None:
        fixture = self._seed_accept_graph(kind="admin")
        request = self._request(fixture)
        request = replace(
            request,
            receipt=replace(
                request.receipt,
                idempotency_key_digest_key_id="unretained-idempotency-v1",
                payload_hash_key_id="unretained-payload-v1",
            ),
        )
        before = self._snapshot(fixture, request.scope.command_id)

        with self.assertRaises(AcceptPostgresConfigurationError):
            self._execute(
                self._factory(connections=self._connection_source()), request
            )

        self.assertEqual(
            self._snapshot(fixture, request.scope.command_id), before
        )

    def test_raw_secret_sentinels_never_cross_request_repr_or_database(self) -> None:
        """TEST-EVENT-AUDIT-IAM-001.C01: persisted business graph is secret-free."""

        fixture = self._seed_accept_graph(kind="creator")
        request = self._request(fixture)
        request_repr = repr(request)
        for sentinel in RAW_SENTINELS:
            self.assertNotIn(sentinel, request_repr)

        factory = self._factory(
            connections=self._connection_source()
        )
        result = self._execute(factory, request)
        self.assertFalse(
            getattr(result, "behavior_not_available", False),
            "secret-free persistence path is unavailable",
        )
        self.assertNotIn(RAW_SESSION_SENTINEL, repr(result))
        self._assert_database_has_no_raw_sentinel(RAW_SENTINELS)

    def _assert_database_has_no_raw_sentinel(self, sentinels: Iterable[str]) -> None:
        with self._connect_admin() as connection:
            columns = connection.execute(
                "SELECT table_schema,table_name,column_name "
                "FROM information_schema.columns "
                "WHERE table_schema IN ('iam','infra','audit') "
                "AND data_type IN ('text','character varying','json','jsonb','bytea') "
                "ORDER BY table_schema,table_name,ordinal_position"
            ).fetchall()
            for schema_name, table_name, column_name in columns:
                statement = sql.SQL(
                    "SELECT EXISTS (SELECT 1 FROM {}.{} WHERE {}::text LIKE %s)"
                ).format(
                    sql.Identifier(schema_name),
                    sql.Identifier(table_name),
                    sql.Identifier(column_name),
                )
                for sentinel in sentinels:
                    found = connection.execute(
                        statement,
                        ("%" + sentinel + "%",),
                    ).fetchone()[0]
                    self.assertFalse(
                        found,
                        "%s.%s.%s contains a raw sentinel"
                        % (schema_name, table_name, column_name),
                    )


if __name__ == "__main__":
    unittest.main()
