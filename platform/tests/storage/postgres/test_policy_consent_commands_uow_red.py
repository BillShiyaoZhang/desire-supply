"""Real PostgreSQL 18 semantic RED for the two IAM SELF write commands.

The canonical migration catalog and every fixture must be valid before the
default-deny production seam is called.  Only the exact reviewed behavior
sentinel is translated into an observation; migration, SQL, fixture, psycopg,
ImportError and programming failures remain test errors.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError, dataclass, field
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
from pathlib import Path
import threading
from typing import Any, Iterable, Mapping, Optional, Sequence, Tuple
import unittest
import uuid

import psycopg
from psycopg.types.json import Jsonb

from desire_platform.identity_access.adapters.postgres.migrations import (
    IamContractSources,
    IamMigrationRunner,
    MigrationCatalog,
    PsycopgMigrationDriver,
    PsycopgMigrationSettings,
)
from desire_platform.identity_access.adapters.postgres.oidc_authentication import (
    OidcPostgresBeginRequest,
    OidcPostgresExchangeClaim,
    OidcPostgresExistingLoginFinalize,
    OidcPostgresPurpose,
    PsycopgOidcAuthenticationUnitOfWork,
)
from desire_platform.identity_access.adapters.postgres.policy_consent_commands import (
    POLICY_CONSENT_POSTGRES_WRITE_CHECKPOINTS,
    POSTGRES_POLICY_CONSENT_BEHAVIOR_NOT_AVAILABLE,
    PolicyConsentPostgresAcceptanceChoice,
    PolicyConsentPostgresBehaviorNotAvailable,
    PolicyConsentPostgresCommitOutcomeUnknownError,
    PolicyConsentPostgresDatabaseRequest,
    PolicyConsentPostgresDatabaseResult,
    PolicyConsentPostgresExecutionScope,
    PolicyConsentPostgresGeneratedIds,
    PolicyConsentPostgresOfferChoice,
    PolicyConsentPostgresOperation,
    PolicyConsentPostgresSettings,
    PolicyConsentPostgresWriteCheckpoint,
    PolicyConsentReceiptIdentityDigest,
    PolicyConsentReceiptMaterial,
    PolicyConsentReceiptPayloadDigest,
    PsycopgPolicyConsentCommandUnitOfWorkFactory,
)
from desire_platform.identity_access.domain.errors import IamError
from desire_platform.identity_access.domain.policies import (
    ConsentOffer,
    PolicyAcceptance,
    canonical_consent_offer_bytes,
)
from desire_platform.identity_access.application.policy_consent_commands import (
    AcceptCurrentPoliciesCommand,
    PolicyConsentActor,
    PolicyRequirementReference,
    PolicyRequirementScopeType,
)
from desire_platform.internal_pilot.contract_validation import (
    IamPostgresContractValidator,
)
from desire_platform.internal_pilot.policy_acceptance import (
    IamReceiptPolicyKeys,
    PostgresAcceptCurrentPoliciesHandler,
    PsycopgPolicyAcceptanceScopeResolver,
)
from tests.storage.postgres.postgres18_harness import TemporaryPostgres18
from tests.support.iam_authority_lifecycle_builders import ClosedSchemaValidator


PLATFORM_ROOT = Path(__file__).resolve().parents[3]
MIGRATION_ROOT = (
    PLATFORM_ROOT
    / "src/desire_platform/identity_access/adapters/postgres/migrations"
)

RAW_IDEMPOTENCY_SENTINEL = "SELF-PG-RAW-IDEMPOTENCY-DO-NOT-PERSIST-74bb"
RAW_SESSION_SENTINEL = "SELF-PG-RAW-SESSION-DO-NOT-PERSIST-d114"
RAW_CSRF_SENTINEL = "SELF-PG-RAW-CSRF-DO-NOT-PERSIST-1cc0"
RAW_CONTACT_SENTINEL = "self-pg-contact-do-not-persist@example.invalid"
RAW_SUBJECT_SENTINEL = "SELF-PG-RAW-SUBJECT-DO-NOT-PERSIST-f2a8"
RAW_POLICY_BODY_SENTINEL = "SELF-PG-POLICY-BODY-DO-NOT-COPY-8c21"
RAW_RECIPIENT_SENTINEL = "internal:self-pg-recipient-do-not-copy-6b8e"
RAW_CARRIER_SENTINELS = (
    RAW_IDEMPOTENCY_SENTINEL,
    RAW_SESSION_SENTINEL,
    RAW_CSRF_SENTINEL,
    RAW_CONTACT_SENTINEL,
    RAW_SUBJECT_SENTINEL,
)
RAW_TRANSPORT_SENTINELS = RAW_CARRIER_SENTINELS + (
    RAW_POLICY_BODY_SENTINEL,
    RAW_RECIPIENT_SENTINEL,
)

IDENTITY_KEY_ID = "iam-receipt-idempotency-hmac-2026-01"
PAYLOAD_KEY_ID = "iam-receipt-payload-hmac-2026-01"
RETAINED_IDENTITY_KEY_ID = "iam-receipt-idempotency-hmac-2026-02"
RETAINED_PAYLOAD_KEY_ID = "iam-receipt-payload-hmac-2026-02"
CANONICALIZATION_VERSION = "restricted-canonical-json-v1"


def _new_id() -> uuid.UUID:
    return uuid.uuid4()


def _digest(value: str) -> bytes:
    return hashlib.sha256(value.encode("utf-8")).digest()


def _keyed(key_id: str, value: bytes) -> bytes:
    return hmac.new(
        ("test-material:" + key_id).encode("utf-8"),
        value,
        hashlib.sha256,
    ).digest()


def _selector_digest(
    *, purpose: str, scope_type: str, role: str, locale: str
) -> bytes:
    canonical = json.dumps(
        {
            "access_purpose": purpose,
            "scope_type": scope_type,
            "target_role": role,
            "jurisdiction": "CN",
            "locale": locale,
        },
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(canonical).digest()


@dataclass(frozen=True)
class PolicyGraph:
    selector_digest: bytes = field(repr=False)
    bundle_id: uuid.UUID
    required_document_id: uuid.UUID
    required_document_hash: bytes = field(repr=False)
    consent_document_id: Optional[uuid.UUID]
    consent_document_hash: Optional[bytes] = field(default=None, repr=False)
    consent_offer_id: Optional[uuid.UUID] = None
    consent_offer_not_after: Optional[datetime] = None


@dataclass(frozen=True)
class SelfGraph:
    actor_id: uuid.UUID
    contact_id: uuid.UUID
    organization_id: uuid.UUID
    membership_id: uuid.UUID
    creator_invitation_id: uuid.UUID
    organization_invitation_id: uuid.UUID
    session_family_id: uuid.UUID
    session_id: uuid.UUID
    auth_transaction_id: uuid.UUID


@dataclass(frozen=True)
class SemanticObservation:
    code: str
    replayed: bool = False


class InjectedPolicyConsentWriteFailure(RuntimeError):
    pass


class RaiseAtCheckpoint:
    def __init__(
        self,
        target: Tuple[PolicyConsentPostgresWriteCheckpoint, int],
    ) -> None:
        self.target = target
        self.ordinals: dict[PolicyConsentPostgresWriteCheckpoint, int] = {}

    def before_write(
        self,
        checkpoint: PolicyConsentPostgresWriteCheckpoint,
        ordinal: int,
    ) -> None:
        expected = self.ordinals.get(checkpoint, 0)
        if ordinal != expected:
            raise AssertionError("policy/consent checkpoint ordinals are not contiguous")
        self.ordinals[checkpoint] = expected + 1
        if (checkpoint, ordinal) == self.target:
            raise InjectedPolicyConsentWriteFailure(checkpoint.value)


class BarrierAtReceiptClaim:
    def __init__(self, parties: int = 2) -> None:
        self.barrier = threading.Barrier(parties, timeout=10)
        self._worker = threading.local()

    def before_write(
        self,
        checkpoint: PolicyConsentPostgresWriteCheckpoint,
        ordinal: int,
    ) -> None:
        if (
            checkpoint is PolicyConsentPostgresWriteCheckpoint.COMMAND_RECEIPT_CLAIM
            and ordinal == 0
        ):
            # A pre-COMMIT retry must not wait for the already-finished winner.
            if getattr(self._worker, "claimed", False):
                return
            self._worker.claimed = True
            self.barrier.wait()


class TrackingConnection:
    """Record statement text and never bind values."""

    def __init__(self, raw: Any, trace: list[str]) -> None:
        self._raw = raw
        self._trace = trace

    def execute(self, query: Any, parameters: Any = None, *args: Any, **kwargs: Any):
        self._trace.append(" ".join(str(query).strip().split()))
        return self._raw.execute(query, parameters, *args, **kwargs)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._raw, name)


class CommitAcknowledgementLossConnection(TrackingConnection):
    """Let PG18 process COMMIT, close the socket, then lose its acknowledgement."""

    def __init__(self, raw: Any, trace: list[str]) -> None:
        super().__init__(raw, trace)
        self.commit_sent = False

    def execute(self, query: Any, parameters: Any = None, *args: Any, **kwargs: Any):
        normalized = " ".join(str(query).strip().split()).upper()
        if normalized == "COMMIT":
            self._trace.append("COMMIT_SENT")
            self.commit_sent = True
            result = self._raw.execute(query, parameters, *args, **kwargs)
            self._raw.close()
            del result
            raise psycopg.OperationalError(
                "synthetic policy/consent COMMIT acknowledgement loss"
            )
        return super().execute(query, parameters, *args, **kwargs)


class TrackingIamAppConnectionSource:
    """Real iam_app pool seam with observable safe disposition only."""

    def __init__(
        self,
        conninfo: str,
        *,
        reuse_released: bool = False,
        lose_first_commit_ack: bool = False,
    ) -> None:
        self.conninfo = conninfo
        self.reuse_released = reuse_released
        self.lose_first_commit_ack = lose_first_commit_ack
        self.trace: list[str] = []
        self.checked_out: list[Any] = []
        self.backend_pids: list[int] = []
        self.released: list[Any] = []
        self.discarded: list[Any] = []
        self._reusable_raw: Optional[Any] = None

    def checkout(self) -> Any:
        raw = self._reusable_raw
        if raw is None or raw.closed or not self.reuse_released:
            raw = psycopg.connect(self.conninfo, autocommit=True)
            if self.reuse_released:
                self._reusable_raw = raw
        self.backend_pids.append(raw.info.backend_pid)
        if self.lose_first_commit_ack:
            self.lose_first_commit_ack = False
            connection: Any = CommitAcknowledgementLossConnection(raw, self.trace)
        else:
            connection = TrackingConnection(raw, self.trace)
        self.checked_out.append(connection)
        return connection

    def release(self, connection: Any) -> None:
        self.released.append(connection)
        if not self.reuse_released:
            connection.close()

    def discard(self, connection: Any) -> None:
        self.discarded.append(connection)
        connection.close()
        if self._reusable_raw is not None and self._reusable_raw.closed:
            self._reusable_raw = None

    def close(self) -> None:
        if self._reusable_raw is not None and not self._reusable_raw.closed:
            self._reusable_raw.close()


class IamOnboardingConnectionSource:
    """Minimal real iam_onboarding connection source for the OIDC UoW."""

    def __init__(self, conninfo: str) -> None:
        self._conninfo = conninfo

    def checkout(self) -> Any:
        return psycopg.connect(self._conninfo, autocommit=True)

    @staticmethod
    def release(connection: Any) -> None:
        connection.close()

    @staticmethod
    def discard(connection: Any) -> None:
        connection.close()


class RealPostgres18PolicyConsentCommandsUowRedTest(unittest.TestCase):
    """SELF commands require exact PG18 locks, RLS and commit semantics."""

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
        self.now = datetime.now(timezone.utc)
        report = self._run_migrations()
        self.assertEqual(
            report.applied_versions,
            tuple(artifact.descriptor.version for artifact in self.catalog.artifacts),
        )
        with self._admin() as connection:
            self.creator_policy = self._seed_policy(
                connection,
                purpose="CREATOR_ENROLLMENT",
                scope_type="USER_ROLE",
                role="CREATOR",
                locale="zh-CN",
                semantic_major=1,
                required_legal_effect="NOTICE_ACKNOWLEDGEMENT",
            )
            self.organization_policy = self._seed_policy(
                connection,
                purpose="ORGANIZATION_MEMBERSHIP",
                scope_type="ORGANIZATION_ROLE",
                role="DEMAND_OWNER",
                locale="en-US",
                semantic_major=2,
            )
        self.graph = self._seed_self_graph()
        self._assert_fixture_and_dynamic_head()
        self.sources: list[TrackingIamAppConnectionSource] = []

    def tearDown(self) -> None:
        for source in self.sources:
            source.close()
        self.postgres.drop_database(self.database)

    def _run_migrations(self):
        driver = PsycopgMigrationDriver(
            settings=PsycopgMigrationSettings(
                conninfo=self.postgres.conninfo(
                    database=self.database,
                    user="iam_migration_runner",
                ),
                application_name="desire-policy-consent-uow-red",
            ),
            dbapi=psycopg,
        )
        return IamMigrationRunner(
            driver=driver,
            runner_version="policy-consent-uow-red/1",
        ).run(catalog=self.catalog, contract_sources=self.contract_sources)

    def _admin(self, *, autocommit: bool = False):
        return psycopg.connect(
            self.postgres.admin_conninfo(database=self.database),
            autocommit=autocommit,
        )

    def _iam_app(self, *, autocommit: bool = False):
        return psycopg.connect(
            self.postgres.conninfo(database=self.database, user="iam_app"),
            autocommit=autocommit,
        )

    def _source(
        self,
        *,
        reuse_released: bool = False,
        lose_first_commit_ack: bool = False,
    ) -> TrackingIamAppConnectionSource:
        source = TrackingIamAppConnectionSource(
            self.postgres.conninfo(database=self.database, user="iam_app"),
            reuse_released=reuse_released,
            lose_first_commit_ack=lose_first_commit_ack,
        )
        self.sources.append(source)
        return source

    def _factory(
        self,
        *,
        source: Optional[TrackingIamAppConnectionSource] = None,
        fault_injector: Optional[Any] = None,
    ) -> PsycopgPolicyConsentCommandUnitOfWorkFactory:
        return PsycopgPolicyConsentCommandUnitOfWorkFactory(
            connections=source or self._source(),
            event_validator=ClosedSchemaValidator.for_events(),
            response_validator=ClosedSchemaValidator.for_openapi(),
            fault_injector=fault_injector,
        )

    @staticmethod
    def _observe(
        factory: PsycopgPolicyConsentCommandUnitOfWorkFactory,
        request: PolicyConsentPostgresDatabaseRequest,
    ) -> SemanticObservation:
        try:
            if request.operation is PolicyConsentPostgresOperation.ACCEPT_CURRENT_POLICIES:
                result = factory.execute_accept_current_policies(request)
            else:
                result = factory.execute_grant_consent(request)
        except PolicyConsentPostgresBehaviorNotAvailable as error:
            if str(error) != POSTGRES_POLICY_CONSENT_BEHAVIOR_NOT_AVAILABLE:
                raise
            return SemanticObservation(POSTGRES_POLICY_CONSENT_BEHAVIOR_NOT_AVAILABLE)
        except PolicyConsentPostgresCommitOutcomeUnknownError as error:
            if error.code != "COMMAND_OUTCOME_UNKNOWN":
                raise
            return SemanticObservation(error.code)
        except InjectedPolicyConsentWriteFailure:
            return SemanticObservation("INJECTED_WRITE_FAILURE")
        except IamError as error:
            return SemanticObservation(error.code)
        if not isinstance(result, PolicyConsentPostgresDatabaseResult):
            raise AssertionError("policy/consent PostgreSQL result is not closed")
        return SemanticObservation(
            "REPLAYED" if result.replayed else "SUCCEEDED",
            replayed=result.replayed,
        )

    def _accept_organization_policy_via_http_bridge(self):
        class Clock:
            @staticmethod
            def now() -> datetime:
                return datetime.now(timezone.utc)

        class Ids:
            @staticmethod
            def new_id(purpose: str) -> uuid.UUID:
                self.assertIn(
                    purpose,
                    {
                        "policy_consent_command",
                        "policy_consent_acceptance",
                        "policy_consent_audit",
                        "policy_consent_outbox",
                    },
                )
                return uuid.uuid4()

        source = self._source()
        validator = IamPostgresContractValidator()
        handler = PostgresAcceptCurrentPoliciesHandler(
            scope_resolver=PsycopgPolicyAcceptanceScopeResolver(
                connections=source
            ),
            uow_factory=PsycopgPolicyConsentCommandUnitOfWorkFactory(
                connections=source,
                event_validator=validator,
                response_validator=validator,
            ),
            keys=IamReceiptPolicyKeys(
                idempotency_key=("test-material:" + IDENTITY_KEY_ID).encode(),
                payload_hash_key=("test-material:" + PAYLOAD_KEY_ID).encode(),
            ),
            clock=Clock(),
            id_source=Ids(),
        )
        actor = PolicyConsentActor(
            actor_user_id=str(self.graph.actor_id),
            current_session_id=str(self.graph.session_id),
            original_actor_id=None,
            correlation_id=str(uuid.uuid4()),
            causation_id=str(uuid.uuid4()),
            trace_id=str(uuid.uuid4()),
        )
        command = AcceptCurrentPoliciesCommand(
            policy_requirement=PolicyRequirementReference(
                selector_digest=self.organization_policy.selector_digest.hex(),
                scope_type=PolicyRequirementScopeType.ORGANIZATION_ROLE,
                scope_id=str(self.graph.organization_id),
            ),
            policy_bundle_id=str(self.organization_policy.bundle_id),
            policy_acceptances=(
                PolicyAcceptance(
                    document_id=str(
                        self.organization_policy.required_document_id
                    ),
                    content_sha256=(
                        self.organization_policy.required_document_hash.hex()
                    ),
                    affirmed=True,
                ),
            ),
            expected_user_version=7,
            idempotency_key=RAW_IDEMPOTENCY_SENTINEL,
        )
        return (
            handler.handle(actor=actor, command=command),
            handler.handle(actor=actor, command=command),
        )

    def _replace_fixture_session_with_real_oidc_login(self) -> None:
        subject_digest = _digest("real-oidc-policy-acceptance-subject")
        with self._admin() as connection:
            connection.execute(
                "INSERT INTO iam.external_identities ("
                "id,user_id,issuer,subject_digest,subject_digest_key_id,"
                "verified_at,status,created_at) VALUES ("
                "%s,%s,'https://id.example.test',%s,'oidc-subject-v1',%s,"
                "'ACTIVE',%s)",
                (
                    _new_id(),
                    self.graph.actor_id,
                    subject_digest,
                    self.now - timedelta(days=1),
                    self.now - timedelta(days=1),
                ),
            )
        oidc = PsycopgOidcAuthenticationUnitOfWork(
            connections=IamOnboardingConnectionSource(
                self.postgres.conninfo(
                    database=self.database,
                    user="iam_onboarding",
                )
            )
        )
        transaction_id = _new_id()
        begin = OidcPostgresBeginRequest(
            auth_transaction_id=transaction_id,
            purpose=OidcPostgresPurpose.LOGIN,
            browser_binding_digest=_digest("real-oidc-browser"),
            browser_binding_key_id="oidc-browser-v1",
            initiating_session_id=None,
            initiating_user_id=None,
            expected_user_id=None,
            invitation_id=None,
            invitation_version=None,
            expected_contact_point_id=None,
            expected_contact_type=None,
            expected_contact_binding_digest=None,
            expected_contact_binding_key_id=None,
            state_digest=_digest("real-oidc-state"),
            state_digest_key_id="oidc-state-v1",
            nonce_digest=_digest("real-oidc-nonce"),
            nonce_digest_key_id="oidc-nonce-v1",
            nonce_ciphertext=b"reviewed-encrypted-nonce",
            nonce_encryption_key_id="oidc-nonce-aead-v1",
            pkce_verifier_ciphertext=b"reviewed-encrypted-verifier",
            pkce_encryption_key_id="oidc-pkce-aead-v1",
            pkce_code_challenge="A" * 43,
            provider_issuer="https://id.example.test",
            provider_audience="desire-internal-pilot",
            redirect_uri="https://app.example.test/v1/auth/oidc/callback",
            return_to="/app",
            security_policy_version="iam-security-v1",
            audit_event_id=_new_id(),
            system_actor_id=_new_id(),
            correlation_id=_new_id(),
            trace_id=_new_id(),
        )
        oidc.begin(begin)
        exchange_owner_id = _new_id()
        oidc.claim_exchange(
            OidcPostgresExchangeClaim(
                auth_transaction_id=transaction_id,
                exchange_owner_id=exchange_owner_id,
                invitation_id=None,
            )
        )
        new_family_id = _new_id()
        new_session_id = _new_id()
        jwt_auth_time = datetime.now(timezone.utc).replace(
            microsecond=0
        ) - timedelta(seconds=1)
        result = oidc.finalize_existing_login(
            OidcPostgresExistingLoginFinalize(
                auth_transaction_id=transaction_id,
                exchange_owner_id=exchange_owner_id,
                provider_issuer="https://id.example.test",
                subject_digest=subject_digest,
                subject_digest_key_id="oidc-subject-v1",
                new_session_family_id=new_family_id,
                new_session_id=new_session_id,
                handle_digest=_digest("real-oidc-session-handle"),
                handle_digest_key_id="session-handle-v1",
                csrf_salt=_digest("real-oidc-csrf-salt"),
                csrf_key_id="session-csrf-v1",
                csrf_digest=_digest("real-oidc-csrf-token"),
                auth_time=jwt_auth_time,
                token_issued_at=jwt_auth_time,
                token_expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
                acr_code="urn:desire:acr:mfa",
                amr_codes=("otp", "pwd"),
                audit_event_id=_new_id(),
                system_actor_id=_new_id(),
                correlation_id=_new_id(),
                trace_id=_new_id(),
            )
        )
        self.assertEqual(result.user_id, self.graph.actor_id)
        self.graph = SelfGraph(
            actor_id=self.graph.actor_id,
            contact_id=self.graph.contact_id,
            organization_id=self.graph.organization_id,
            membership_id=self.graph.membership_id,
            creator_invitation_id=self.graph.creator_invitation_id,
            organization_invitation_id=self.graph.organization_invitation_id,
            session_family_id=new_family_id,
            session_id=new_session_id,
            auth_transaction_id=transaction_id,
        )
        with self._admin() as connection:
            time_facts = connection.execute(
                "SELECT s.auth_time,t.created_at,t.succeeded_at,t.deadline,"
                "s.status,f.status FROM iam.sessions AS s "
                "JOIN iam.session_families AS f ON f.id=s.family_id "
                "JOIN iam.auth_transactions AS t ON t.id=s.auth_transaction_id "
                "WHERE s.id=%s",
                (new_session_id,),
            ).fetchone()
        self.assertLessEqual(time_facts[0], time_facts[2])
        self.assertLessEqual(time_facts[1], time_facts[2])
        self.assertNotEqual(time_facts[0], time_facts[2])
        self.assertEqual(time_facts[4:], ("ACTIVE", "ACTIVE"))

    def test_first_login_http_bridge_accepts_and_exactly_replays_on_real_pg18(self) -> None:
        first, replay = self._accept_organization_policy_via_http_bridge()

        self.assertFalse(first.replayed)
        self.assertTrue(replay.replayed)
        self.assertEqual(first.json_body, replay.json_body)
        self.assertTrue(first.json_body["satisfied"])
        self.assertEqual(first.response_entity_tag, '"v8"')
        with self._admin() as connection:
            acceptance_count = connection.execute(
                "SELECT count(*) FROM iam.policy_acceptances "
                "WHERE user_id=%s AND bundle_id=%s",
                (self.graph.actor_id, self.organization_policy.bundle_id),
            ).fetchone()[0]
            receipt_count = connection.execute(
                "SELECT count(*) FROM infra.command_receipts "
                "WHERE principal_id=%s AND command_name='AcceptCurrentPolicies'",
                (self.graph.actor_id,),
            ).fetchone()[0]
        self.assertEqual((acceptance_count, receipt_count), (1, 1))

    def test_real_oidc_finalize_then_policy_acceptance_uses_ordered_time_evidence(
        self,
    ) -> None:
        self._replace_fixture_session_with_real_oidc_login()

        first, replay = self._accept_organization_policy_via_http_bridge()

        self.assertFalse(first.replayed)
        self.assertTrue(replay.replayed)
        self.assertTrue(first.json_body["satisfied"])

    def test_completed_oidc_deadline_does_not_expire_an_active_session(self) -> None:
        with self._admin() as connection:
            facts = connection.execute(
                "SELECT t.deadline < transaction_timestamp(),s.status,f.status,"
                "s.idle_expires_at > transaction_timestamp(),"
                "s.absolute_expires_at > transaction_timestamp() "
                "FROM iam.sessions AS s "
                "JOIN iam.session_families AS f ON f.id=s.family_id "
                "JOIN iam.auth_transactions AS t ON t.id=s.auth_transaction_id "
                "WHERE s.id=%s",
                (self.graph.session_id,),
            ).fetchone()
        self.assertEqual(facts, (True, "ACTIVE", "ACTIVE", True, True))

        observed = self._observe(
            self._factory(),
            self._request(PolicyConsentPostgresOperation.ACCEPT_CURRENT_POLICIES),
        )

        self.assertEqual(observed.code, "SUCCEEDED")

    def test_creator_notice_acknowledgement_accepts_and_exactly_replays(
        self,
    ) -> None:
        request = self._request(
            PolicyConsentPostgresOperation.ACCEPT_CURRENT_POLICIES,
            policy=self.creator_policy,
        )
        factory = self._factory()

        first = self._observe(factory, request)
        replay = self._observe(factory, request)

        self.assertEqual(
            (first, replay),
            (
                SemanticObservation("SUCCEEDED"),
                SemanticObservation("REPLAYED", replayed=True),
            ),
        )

    def test_authentication_completed_after_protocol_deadline_is_rejected(
        self,
    ) -> None:
        self.graph = self._seed_self_graph(
            auth_succeeded_after_auth_time=timedelta(minutes=6),
            session_created_after_auth_time=timedelta(minutes=7),
        )
        with self._admin() as connection:
            facts = connection.execute(
                "SELECT t.created_at <= t.succeeded_at,"
                "t.deadline < t.succeeded_at,"
                "t.succeeded_at <= s.created_at "
                "FROM iam.sessions AS s "
                "JOIN iam.auth_transactions AS t ON t.id=s.auth_transaction_id "
                "WHERE s.id=%s",
                (self.graph.session_id,),
            ).fetchone()
        self.assertEqual(facts, (True, True, True))

        observed = self._observe(
            self._factory(),
            self._request(PolicyConsentPostgresOperation.ACCEPT_CURRENT_POLICIES),
        )

        self.assertEqual(observed.code, "AUTHENTICATION_REQUIRED")

    def test_authentication_success_after_session_creation_is_rejected(self) -> None:
        self.graph = self._seed_self_graph(
            auth_succeeded_after_auth_time=timedelta(minutes=2),
            session_created_after_auth_time=timedelta(minutes=1),
        )
        with self._admin() as connection:
            facts = connection.execute(
                "SELECT t.created_at <= t.succeeded_at,"
                "t.succeeded_at <= t.deadline,"
                "s.created_at < t.succeeded_at "
                "FROM iam.sessions AS s "
                "JOIN iam.auth_transactions AS t ON t.id=s.auth_transaction_id "
                "WHERE s.id=%s",
                (self.graph.session_id,),
            ).fetchone()
        self.assertEqual(facts, (True, True, True))

        observed = self._observe(
            self._factory(),
            self._request(PolicyConsentPostgresOperation.ACCEPT_CURRENT_POLICIES),
        )

        self.assertEqual(observed.code, "AUTHENTICATION_REQUIRED")

    def _seed_policy(
        self,
        connection: Any,
        *,
        purpose: str,
        scope_type: str,
        role: str,
        locale: str,
        semantic_major: int,
        required_legal_effect: str = "CONTRACT_ACCEPTANCE",
    ) -> PolicyGraph:
        selector = _selector_digest(
            purpose=purpose,
            scope_type=scope_type,
            role=role,
            locale=locale,
        )
        bundle_id = _new_id()
        required_document_id = _new_id()
        consent_document_id = _new_id()
        consent_offer_id = _new_id()
        publication_command_id = _new_id()
        created_at = self.now - timedelta(days=500)
        effective_at = self.now - timedelta(days=499)
        offer_not_after = self.now + timedelta(days=300)
        required_body = f"{role} reviewed terms. {RAW_POLICY_BODY_SENTINEL}"
        consent_body = f"{role} reviewed optional research consent."
        required_hash = hashlib.sha256(required_body.encode("utf-8")).digest()
        consent_hash = hashlib.sha256(consent_body.encode("utf-8")).digest()
        offer = ConsentOffer.pilot_research(
            consent_offer_id=str(consent_offer_id),
            aggregate_version=1,
            supporting_document_id=str(consent_document_id),
            supporting_document_sha256=consent_hash.hex(),
            recipient_reference=RAW_RECIPIENT_SENTINEL,
            pilot_ends_at=offer_not_after,
            policy_bundle_id=str(bundle_id),
            recipient_label="Reviewed research controller",
            canonical_offer_sha256="0" * 64,
        )
        canonical_offer_hash = hashlib.sha256(
            canonical_consent_offer_bytes(offer)
        ).digest()
        connection.execute(
            "INSERT INTO iam.policy_selectors ("
            "selector_digest,canonicalization_version,access_purpose,scope_type,"
            "target_role,jurisdiction,locale,current_bundle_id,aggregate_version,"
            "created_at,updated_at) VALUES ("
            "%s,'policy-selector-json-v1',%s,%s,%s,'CN',%s,NULL,1,%s,%s)",
            (selector, purpose, scope_type, role, locale, created_at, created_at),
        )
        connection.execute(
            "INSERT INTO iam.policy_documents ("
            "id,kind,locale,semantic_version,canonical_body,content_sha256,"
            "legal_effect,jurisdiction,status,effective_at,"
            "superseded_by_document_id,publication_command_id,created_at,updated_at"
            ") VALUES "
            "(%s,'TERMS',%s,%s,%s,%s,%s,'CN','ACTIVE',"
            "%s,NULL,%s,%s,%s),"
            "(%s,'CONSENT_TEXT',%s,%s,%s,%s,'CONSENT_TEXT','CN','ACTIVE',"
            "%s,NULL,%s,%s,%s)",
            (
                required_document_id,
                locale,
                f"{semantic_major}.0.0",
                required_body,
                required_hash,
                required_legal_effect,
                effective_at,
                publication_command_id,
                created_at,
                effective_at,
                consent_document_id,
                locale,
                f"{semantic_major}.0.0",
                consent_body,
                consent_hash,
                effective_at,
                publication_command_id,
                created_at,
                effective_at,
            ),
        )
        connection.execute(
            "INSERT INTO iam.policy_bundles ("
            "id,selector_digest,status,effective_at,effective_until,"
            "superseded_by_bundle_id,release_manifest_sha256,release_signature,"
            "release_signing_key_id,publication_command_id,aggregate_version,"
            "created_at,updated_at) VALUES ("
            "%s,%s,'DRAFT',NULL,NULL,NULL,%s,%s,'self-pg-signing-v1',%s,1,%s,%s)",
            (
                bundle_id,
                selector,
                _digest("manifest-" + bundle_id.hex),
                b"synthetic-reviewed-signature",
                publication_command_id,
                created_at,
                created_at,
            ),
        )
        connection.execute(
            "INSERT INTO iam.policy_bundle_documents "
            "(bundle_id,document_id,position,required) VALUES "
            "(%s,%s,1,true),(%s,%s,2,false)",
            (
                bundle_id,
                required_document_id,
                bundle_id,
                consent_document_id,
            ),
        )
        connection.execute(
            "INSERT INTO iam.consent_offers ("
            "id,bundle_id,offer_version,purpose,scope_type,scope_derivation,"
            "recipient_ref,recipient_label,document_id,document_content_sha256,"
            "expiry_rule,expiry_days,not_after,optional,canonical_offer_sha256,"
            "publication_command_id,created_at) VALUES ("
            "%s,%s,1,'PILOT_RESEARCH','PLATFORM_PARTICIPATION',"
            "'PLATFORM_PARTICIPATION_NULL_SCOPE',%s,'Reviewed research controller',"
            "%s,%s,'EARLIER_OF_GRANTED_AT_PLUS_365_DAYS_OR_NOT_AFTER',365,"
            "%s,true,%s,%s,%s)",
            (
                consent_offer_id,
                bundle_id,
                RAW_RECIPIENT_SENTINEL,
                consent_document_id,
                consent_hash,
                offer_not_after,
                canonical_offer_hash,
                publication_command_id,
                created_at,
            ),
        )
        connection.execute(
            "INSERT INTO iam.consent_offer_data_categories "
            "(offer_id,category,position) VALUES "
            "(%s,'PROFILE',1),(%s,'MATCHING',2),(%s,'RESEARCH',3)",
            (consent_offer_id, consent_offer_id, consent_offer_id),
        )
        connection.execute(
            "UPDATE iam.policy_bundles SET status='ACTIVE',effective_at=%s,"
            "aggregate_version=2,updated_at=%s WHERE id=%s",
            (effective_at, effective_at, bundle_id),
        )
        connection.execute(
            "UPDATE iam.policy_selectors SET current_bundle_id=%s,"
            "aggregate_version=2,updated_at=%s WHERE selector_digest=%s",
            (bundle_id, effective_at, selector),
        )
        return PolicyGraph(
            selector_digest=selector,
            bundle_id=bundle_id,
            required_document_id=required_document_id,
            required_document_hash=required_hash,
            consent_document_id=consent_document_id,
            consent_document_hash=consent_hash,
            consent_offer_id=consent_offer_id,
            consent_offer_not_after=offer_not_after,
        )

    def _seed_self_graph(
        self,
        *,
        auth_succeeded_after_auth_time: timedelta = timedelta(0),
        session_created_after_auth_time: timedelta = timedelta(days=1),
    ) -> SelfGraph:
        actor_id = _new_id()
        contact_id = _new_id()
        organization_id = _new_id()
        membership_id = _new_id()
        creator_invitation_id = _new_id()
        organization_invitation_id = _new_id()
        auth_transaction_id = _new_id()
        family_id = _new_id()
        session_id = _new_id()
        created_at = self.now - timedelta(days=450)
        accepted_at = self.now - timedelta(days=449)
        auth_time = self.now - timedelta(days=400)
        session_created_at = auth_time + session_created_after_auth_time
        auth_succeeded_at = auth_time + auth_succeeded_after_auth_time
        with self._admin() as connection:
            connection.execute(
                "INSERT INTO iam.users "
                "(id,status,display_handle,aggregate_version,created_at,updated_at) "
                "VALUES (%s,'ACTIVE',%s,7,%s,%s)",
                (actor_id, "self_pg_" + actor_id.hex[:12], created_at, accepted_at),
            )
            connection.execute(
                "INSERT INTO iam.contact_points ("
                "id,user_id,contact_type,locator_ciphertext,locator_encryption_key_id,"
                "locator_encryption_algorithm,binding_digest,binding_digest_key_id,"
                "verified_at,retention_until,created_at,updated_at) VALUES ("
                "%s,%s,'EMAIL',NULL,NULL,NULL,%s,'contact-hmac-v1',%s,%s,%s,%s)",
                (
                    contact_id,
                    actor_id,
                    _digest(RAW_CONTACT_SENTINEL),
                    accepted_at,
                    self.now + timedelta(days=365),
                    created_at,
                    accepted_at,
                ),
            )
            connection.execute(
                "INSERT INTO iam.organizations ("
                "id,organization_type,public_name,jurisdiction,status,"
                "client_reference_namespace,client_reference,aggregate_version,"
                "created_at,updated_at) VALUES ("
                "%s,'BUSINESS','Reviewed organization','CN','ACTIVE',"
                "'policy-consent-red',%s,3,%s,%s)",
                (organization_id, organization_id.hex, created_at, accepted_at),
            )
            invitation_rows = (
                (
                    creator_invitation_id,
                    "CREATOR_ENROLLMENT",
                    None,
                    "USER",
                    "CREATOR",
                    self.creator_policy,
                ),
                (
                    organization_invitation_id,
                    "ORGANIZATION_MEMBERSHIP",
                    organization_id,
                    "ORGANIZATION",
                    "DEMAND_OWNER",
                    self.organization_policy,
                ),
            )
            for invitation_id, purpose, organization, target_scope, role, policy in invitation_rows:
                connection.execute(
                    "INSERT INTO iam.access_invitations ("
                    "id,purpose,organization_id,target_scope,target_role,is_initial_admin,"
                    "recipient_contact_id,masked_recipient_label,policy_selector_digest,"
                    "issued_policy_bundle_id,status,expires_at,issuer_kind,issuer_user_id,"
                    "token_nonce,token_key_id,accepted_by_user_id,terminal_at,"
                    "terminal_reason_code,aggregate_version,created_at,updated_at) VALUES ("
                    "%s,%s,%s,%s,%s,false,%s,'s***@example.invalid',%s,%s,'ACCEPTED',"
                    "%s,'SYSTEM',NULL,%s,'invitation-token-v1',%s,%s,NULL,2,%s,%s)",
                    (
                        invitation_id,
                        purpose,
                        organization,
                        target_scope,
                        role,
                        contact_id,
                        policy.selector_digest,
                        policy.bundle_id,
                        self.now + timedelta(days=300),
                        _digest("invitation-nonce-" + invitation_id.hex),
                        actor_id,
                        accepted_at,
                        created_at,
                        accepted_at,
                    ),
                )
            connection.execute(
                "INSERT INTO iam.memberships ("
                "id,organization_id,user_id,status,source_invitation_id,"
                "aggregate_version,created_at,updated_at) VALUES ("
                "%s,%s,%s,'ACTIVE',%s,1,%s,%s)",
                (
                    membership_id,
                    organization_id,
                    actor_id,
                    organization_invitation_id,
                    accepted_at,
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
                    actor_id,
                    creator_invitation_id,
                    self.creator_policy.selector_digest,
                    _new_id(),
                    accepted_at,
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
                    _new_id(),
                    organization_id,
                    membership_id,
                    actor_id,
                    organization_invitation_id,
                    self.organization_policy.selector_digest,
                    actor_id,
                    accepted_at,
                ),
            )
            transaction_created = auth_time - timedelta(minutes=5)
            connection.execute(
                "INSERT INTO iam.auth_transactions ("
                "id,status,purpose,attempt,protocol_version,browser_binding_digest,"
                "browser_binding_key_id,initiating_session_id,initiating_user_id,"
                "expected_user_id,invitation_id,invitation_version,"
                "expected_contact_point_id,state_digest,state_digest_key_id,"
                "nonce_digest,nonce_digest_key_id,pkce_verifier_ciphertext,"
                "pkce_encryption_key_id,pkce_encryption_algorithm,redirect_uri,"
                "provider_error_class,deadline,succeeded_at,created_at,updated_at) "
                "VALUES (%s,'SUCCEEDED','LOGIN',1,1,%s,'browser-hmac-v1',"
                "NULL,NULL,NULL,NULL,NULL,NULL,%s,'state-hmac-v1',%s,'nonce-hmac-v1',"
                "%s,'pkce-aead-v1','AES_256_GCM_V1',"
                "'https://app.example.test/v1/auth/oidc/callback',NULL,%s,%s,%s,%s)",
                (
                    auth_transaction_id,
                    _digest("browser-" + auth_transaction_id.hex),
                    _digest("state-" + auth_transaction_id.hex),
                    _digest("nonce-" + auth_transaction_id.hex),
                    b"synthetic-pkce-ciphertext",
                    transaction_created + timedelta(minutes=10),
                    auth_succeeded_at,
                    transaction_created,
                    auth_succeeded_at,
                ),
            )
            connection.execute(
                "INSERT INTO iam.session_families ("
                "id,user_id,status,current_generation,revoked_at,"
                "revocation_reason_code,aggregate_version,created_at,updated_at) "
                "VALUES (%s,%s,'ACTIVE',1,NULL,NULL,1,%s,%s)",
                (family_id, actor_id, session_created_at, session_created_at),
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
                "NULL,NULL,NULL,%s,%s,'urn:desire:acr:mfa',ARRAY['otp','pwd']::text[],"
                "%s,%s,%s,%s,%s,'Browser','ACTIVE','LOGIN',NULL,NULL,1)",
                (
                    session_id,
                    actor_id,
                    family_id,
                    _digest(RAW_SESSION_SENTINEL + ":" + session_id.hex),
                    _digest(
                        "csrf-salt:" + RAW_CSRF_SENTINEL + ":" + session_id.hex
                    ),
                    _digest(RAW_CSRF_SENTINEL + ":" + session_id.hex),
                    auth_transaction_id,
                    auth_time,
                    session_created_at,
                    self.now - timedelta(minutes=1),
                    self.now + timedelta(minutes=30),
                    self.now + timedelta(days=30),
                    self.now - timedelta(minutes=1),
                ),
            )
        return SelfGraph(
            actor_id=actor_id,
            contact_id=contact_id,
            organization_id=organization_id,
            membership_id=membership_id,
            creator_invitation_id=creator_invitation_id,
            organization_invitation_id=organization_invitation_id,
            session_family_id=family_id,
            session_id=session_id,
            auth_transaction_id=auth_transaction_id,
        )

    def _assert_fixture_and_dynamic_head(self) -> None:
        expected_head = self.catalog.artifacts[-1].descriptor.version
        with self._admin() as connection:
            compatibility = connection.execute(
                "SELECT current_schema_version,schema_head_version "
                "FROM infra.iam_schema_compatibility"
            ).fetchone()
            facts = connection.execute(
                "SELECT "
                "(SELECT count(*) FROM iam.users WHERE id=%s),"
                "(SELECT count(*) FROM iam.sessions WHERE id=%s AND status='ACTIVE'),"
                "(SELECT count(*) FROM iam.user_role_grants WHERE user_id=%s AND revoked_at IS NULL),"
                "(SELECT count(*) FROM iam.membership_role_grants WHERE user_id=%s AND revoked_at IS NULL),"
                "(SELECT count(*) FROM iam.policy_bundles WHERE status='ACTIVE')",
                (
                    self.graph.actor_id,
                    self.graph.session_id,
                    self.graph.actor_id,
                    self.graph.actor_id,
                ),
            ).fetchone()
        self.assertEqual(compatibility, (expected_head, expected_head))
        self.assertEqual(facts, (1, 1, 1, 1, 2))

    def _request(
        self,
        operation: PolicyConsentPostgresOperation,
        *,
        raw_idempotency_key: str = RAW_IDEMPOTENCY_SENTINEL,
        expected_user_version: int = 7,
        policy: Optional[PolicyGraph] = None,
        receipt_id: Optional[uuid.UUID] = None,
        identity_key_ids: Sequence[str] = (IDENTITY_KEY_ID,),
        active_identity_key_id: str = IDENTITY_KEY_ID,
        payload_key_ids: Sequence[str] = (PAYLOAD_KEY_ID,),
        active_payload_key_id: str = PAYLOAD_KEY_ID,
    ) -> PolicyConsentPostgresDatabaseRequest:
        selected_policy = policy or (
            self.organization_policy
            if operation is PolicyConsentPostgresOperation.ACCEPT_CURRENT_POLICIES
            else self.creator_policy
        )
        command_id = receipt_id or _new_id()
        identity_bytes = json.dumps(
            {"idempotency_key": raw_idempotency_key},
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        payload_facts: dict[str, object] = {
            "operation": operation.value,
            "actor_user_id": str(self.graph.actor_id),
            "policy_bundle_id": str(selected_policy.bundle_id),
            "expected_user_version": expected_user_version,
            "selector_digest": selected_policy.selector_digest.hex(),
        }
        if operation is PolicyConsentPostgresOperation.ACCEPT_CURRENT_POLICIES:
            payload_facts["policy_acceptances"] = [
                {
                    "document_id": str(selected_policy.required_document_id),
                    "content_sha256": selected_policy.required_document_hash.hex(),
                    "affirmed": True,
                }
            ]
        else:
            payload_facts["consent_choice"] = {
                "consent_offer_id": str(selected_policy.consent_offer_id),
                "document_id": str(selected_policy.consent_document_id),
                "content_sha256": (
                    selected_policy.consent_document_hash.hex()
                    if selected_policy.consent_document_hash is not None
                    else None
                ),
                "affirmed": True,
            }
        payload_bytes = json.dumps(
            payload_facts,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        receipt = PolicyConsentReceiptMaterial(
            receipt_id=command_id,
            principal_id=self.graph.actor_id,
            identity_candidates=tuple(
                PolicyConsentReceiptIdentityDigest(
                    key_id=key_id,
                    digest=_keyed(key_id, identity_bytes),
                )
                for key_id in identity_key_ids
            ),
            active_identity_key_id=active_identity_key_id,
            payload_candidates=tuple(
                PolicyConsentReceiptPayloadDigest(
                    key_id=key_id,
                    canonicalization_version=CANONICALIZATION_VERSION,
                    digest=_keyed(key_id, payload_bytes),
                )
                for key_id in payload_key_ids
            ),
            active_payload_key_id=active_payload_key_id,
            active_canonicalization_version=CANONICALIZATION_VERSION,
            retain_until=self.now + timedelta(days=30),
        )
        organization_id = (
            self.graph.organization_id
            if (
                operation
                is PolicyConsentPostgresOperation.ACCEPT_CURRENT_POLICIES
                and selected_policy.selector_digest
                == self.organization_policy.selector_digest
            )
            else None
        )
        scope = PolicyConsentPostgresExecutionScope(
            actor_user_id=self.graph.actor_id,
            session_id=self.graph.session_id,
            session_family_id=self.graph.session_family_id,
            auth_transaction_id=self.graph.auth_transaction_id,
            selector_digest=selected_policy.selector_digest,
            authority_scope_type=(
                "ORGANIZATION_ROLE"
                if organization_id is not None
                else "USER_ROLE"
            ),
            authority_scope_id=organization_id,
            organization_id=organization_id,
            command_id=command_id,
            correlation_id=_new_id(),
            causation_id=command_id,
            trace_id=_new_id(),
        )
        if operation is PolicyConsentPostgresOperation.ACCEPT_CURRENT_POLICIES:
            acceptances = (
                PolicyConsentPostgresAcceptanceChoice(
                    document_id=selected_policy.required_document_id,
                    content_sha256=selected_policy.required_document_hash,
                    affirmed=True,
                ),
            )
            consent_choice = None
            generated = PolicyConsentPostgresGeneratedIds(
                policy_acceptance_ids=(_new_id(),),
                consent_grant_id=None,
                audit_event_id=_new_id(),
                outbox_event_ids=(_new_id(), _new_id()),
            )
        else:
            if (
                selected_policy.consent_offer_id is None
                or selected_policy.consent_document_id is None
                or selected_policy.consent_document_hash is None
            ):
                raise AssertionError("Grant fixture has no reviewed ConsentOffer")
            acceptances = ()
            consent_choice = PolicyConsentPostgresOfferChoice(
                consent_offer_id=selected_policy.consent_offer_id,
                document_id=selected_policy.consent_document_id,
                content_sha256=selected_policy.consent_document_hash,
                affirmed=True,
            )
            generated = PolicyConsentPostgresGeneratedIds(
                policy_acceptance_ids=(),
                consent_grant_id=_new_id(),
                audit_event_id=_new_id(),
                outbox_event_ids=(_new_id(),),
            )
        return PolicyConsentPostgresDatabaseRequest(
            operation=operation,
            scope=scope,
            receipt=receipt,
            expected_user_version=expected_user_version,
            policy_bundle_id=selected_policy.bundle_id,
            policy_acceptances=acceptances,
            consent_choice=consent_choice,
            generated_ids=generated,
        )

    def _seed_acceptance(
        self,
        policy: PolicyGraph,
        *,
        accepted_at: Optional[datetime] = None,
    ) -> uuid.UUID:
        acceptance_id = _new_id()
        timestamp = accepted_at or self.now - timedelta(days=100)
        with self._admin() as connection:
            session = connection.execute(
                "SELECT auth_transaction_id,auth_time,acr_code,amr_codes "
                "FROM iam.sessions WHERE id=%s",
                (self.graph.session_id,),
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
                    self.graph.actor_id,
                    policy.required_document_id,
                    policy.required_document_hash,
                    policy.bundle_id,
                    timestamp,
                    self.graph.session_id,
                    session[0],
                    session[1],
                    session[2],
                    session[3],
                    _new_id(),
                    _new_id(),
                    timestamp,
                ),
            )
        return acceptance_id

    def _seed_grant(
        self,
        policy: PolicyGraph,
        *,
        granted_at: datetime,
    ) -> uuid.UUID:
        if (
            policy.consent_offer_id is None
            or policy.consent_document_id is None
            or policy.consent_document_hash is None
            or policy.consent_offer_not_after is None
        ):
            raise AssertionError("ConsentGrant fixture has no offer")
        grant_id = _new_id()
        expires_at = min(
            granted_at + timedelta(days=365),
            policy.consent_offer_not_after,
        )
        with self._admin() as connection:
            session = connection.execute(
                "SELECT auth_transaction_id,auth_time,acr_code,amr_codes "
                "FROM iam.sessions WHERE id=%s",
                (self.graph.session_id,),
            ).fetchone()
            connection.execute(
                "INSERT INTO iam.consent_grants ("
                "id,user_id,consent_offer_id,consent_offer_version,policy_bundle_id,"
                "purpose,scope_type,scope_id,recipient_ref,recipient_label,document_id,"
                "document_content_sha256,granted_at,expires_at,session_id,"
                "auth_transaction_id,auth_time,acr_code,amr_codes,command_id,"
                "correlation_id,status,withdrawn_at,aggregate_version,created_at,updated_at"
                ") VALUES (%s,%s,%s,1,%s,'PILOT_RESEARCH','PLATFORM_PARTICIPATION',"
                "NULL,%s,'Reviewed research controller',%s,%s,%s,%s,%s,%s,%s,%s,%s,"
                "%s,%s,'ACTIVE',NULL,1,%s,%s)",
                (
                    grant_id,
                    self.graph.actor_id,
                    policy.consent_offer_id,
                    policy.bundle_id,
                    RAW_RECIPIENT_SENTINEL,
                    policy.consent_document_id,
                    policy.consent_document_hash,
                    granted_at,
                    expires_at,
                    self.graph.session_id,
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
            connection.execute(
                "INSERT INTO iam.consent_grant_data_categories "
                "(grant_id,category,position) VALUES "
                "(%s,'PROFILE',1),(%s,'MATCHING',2),(%s,'RESEARCH',3)",
                (grant_id, grant_id, grant_id),
            )
        return grant_id

    def _publish_replacement(self, previous: PolicyGraph) -> PolicyGraph:
        bundle_id = _new_id()
        consent_document_id = _new_id()
        consent_offer_id = _new_id()
        command_id = _new_id()
        created_at = self.now - timedelta(minutes=2)
        effective_at = self.now - timedelta(minutes=1)
        consent_body = "Replacement reviewed optional research consent."
        consent_hash = hashlib.sha256(consent_body.encode("utf-8")).digest()
        not_after = self.now + timedelta(days=200)
        offer = ConsentOffer.pilot_research(
            consent_offer_id=str(consent_offer_id),
            aggregate_version=1,
            supporting_document_id=str(consent_document_id),
            supporting_document_sha256=consent_hash.hex(),
            recipient_reference=RAW_RECIPIENT_SENTINEL,
            pilot_ends_at=not_after,
            policy_bundle_id=str(bundle_id),
            recipient_label="Reviewed research controller",
            canonical_offer_sha256="0" * 64,
        )
        offer_hash = hashlib.sha256(canonical_consent_offer_bytes(offer)).digest()
        with self._admin() as connection:
            previous_locale = connection.execute(
                "SELECT locale FROM iam.policy_documents WHERE id=%s",
                (previous.required_document_id,),
            ).fetchone()[0]
            connection.execute(
                "INSERT INTO iam.policy_documents ("
                "id,kind,locale,semantic_version,canonical_body,content_sha256,"
                "legal_effect,jurisdiction,status,effective_at,"
                "superseded_by_document_id,publication_command_id,created_at,updated_at"
                ") VALUES (%s,'CONSENT_TEXT',%s,%s,%s,%s,'CONSENT_TEXT','CN',"
                "'ACTIVE',%s,NULL,%s,%s,%s)",
                (
                    consent_document_id,
                    previous_locale,
                    "99.0." + str(int(bundle_id.hex[:6], 16)),
                    consent_body,
                    consent_hash,
                    effective_at,
                    command_id,
                    created_at,
                    effective_at,
                ),
            )
            connection.execute(
                "INSERT INTO iam.policy_bundles ("
                "id,selector_digest,status,effective_at,effective_until,"
                "superseded_by_bundle_id,release_manifest_sha256,release_signature,"
                "release_signing_key_id,publication_command_id,aggregate_version,"
                "created_at,updated_at) VALUES ("
                "%s,%s,'DRAFT',NULL,NULL,NULL,%s,%s,'self-pg-signing-v2',%s,1,%s,%s)",
                (
                    bundle_id,
                    previous.selector_digest,
                    _digest("replacement-manifest-" + bundle_id.hex),
                    b"synthetic-reviewed-replacement-signature",
                    command_id,
                    created_at,
                    created_at,
                ),
            )
            connection.execute(
                "INSERT INTO iam.policy_bundle_documents "
                "(bundle_id,document_id,position,required) VALUES "
                "(%s,%s,1,true),(%s,%s,2,false)",
                (
                    bundle_id,
                    previous.required_document_id,
                    bundle_id,
                    consent_document_id,
                ),
            )
            connection.execute(
                "INSERT INTO iam.consent_offers ("
                "id,bundle_id,offer_version,purpose,scope_type,scope_derivation,"
                "recipient_ref,recipient_label,document_id,document_content_sha256,"
                "expiry_rule,expiry_days,not_after,optional,canonical_offer_sha256,"
                "publication_command_id,created_at) VALUES ("
                "%s,%s,1,'PILOT_RESEARCH','PLATFORM_PARTICIPATION',"
                "'PLATFORM_PARTICIPATION_NULL_SCOPE',%s,'Reviewed research controller',"
                "%s,%s,'EARLIER_OF_GRANTED_AT_PLUS_365_DAYS_OR_NOT_AFTER',365,"
                "%s,true,%s,%s,%s)",
                (
                    consent_offer_id,
                    bundle_id,
                    RAW_RECIPIENT_SENTINEL,
                    consent_document_id,
                    consent_hash,
                    not_after,
                    offer_hash,
                    command_id,
                    created_at,
                ),
            )
            connection.execute(
                "INSERT INTO iam.consent_offer_data_categories "
                "(offer_id,category,position) VALUES "
                "(%s,'PROFILE',1),(%s,'MATCHING',2),(%s,'RESEARCH',3)",
                (consent_offer_id, consent_offer_id, consent_offer_id),
            )
            connection.execute(
                "UPDATE iam.policy_bundles SET status='SUPERSEDED',"
                "effective_until=%s,superseded_by_bundle_id=%s,"
                "aggregate_version=aggregate_version+1,updated_at=%s WHERE id=%s",
                (effective_at, bundle_id, effective_at, previous.bundle_id),
            )
            connection.execute(
                "UPDATE iam.policy_bundles SET status='ACTIVE',effective_at=%s,"
                "aggregate_version=2,updated_at=%s WHERE id=%s",
                (effective_at, effective_at, bundle_id),
            )
            connection.execute(
                "UPDATE iam.policy_selectors SET current_bundle_id=%s,"
                "aggregate_version=aggregate_version+1,updated_at=%s "
                "WHERE selector_digest=%s",
                (bundle_id, effective_at, previous.selector_digest),
            )
        return PolicyGraph(
            selector_digest=previous.selector_digest,
            bundle_id=bundle_id,
            required_document_id=previous.required_document_id,
            required_document_hash=previous.required_document_hash,
            consent_document_id=consent_document_id,
            consent_document_hash=consent_hash,
            consent_offer_id=consent_offer_id,
            consent_offer_not_after=not_after,
        )

    def _summary(self, request: PolicyConsentPostgresDatabaseRequest) -> Mapping[str, Any]:
        with self._admin() as connection:
            user_version = connection.execute(
                "SELECT aggregate_version FROM iam.users WHERE id=%s",
                (self.graph.actor_id,),
            ).fetchone()[0]
            acceptance_count = connection.execute(
                "SELECT count(*) FROM iam.policy_acceptances WHERE user_id=%s",
                (self.graph.actor_id,),
            ).fetchone()[0]
            grants = tuple(
                connection.execute(
                    "SELECT id,status,consent_offer_id,expires_at "
                    "FROM iam.consent_grants WHERE user_id=%s ORDER BY id",
                    (self.graph.actor_id,),
                ).fetchall()
            )
            receipts = tuple(
                connection.execute(
                    "SELECT status FROM infra.command_receipts WHERE id=%s",
                    (request.scope.command_id,),
                ).fetchall()
            )
            audits = connection.execute(
                "SELECT count(*) FROM audit.audit_events WHERE command_id=%s",
                (request.scope.command_id,),
            ).fetchone()[0]
            events = tuple(
                row[0]
                for row in connection.execute(
                    "SELECT event_type FROM infra.outbox_events "
                    "WHERE causation_id=%s ORDER BY event_type,event_id",
                    (request.scope.command_id,),
                ).fetchall()
            )
        return {
            "user_version": user_version,
            "acceptance_count": acceptance_count,
            "grants": grants,
            "receipts": receipts,
            "audit_count": audits,
            "event_types": events,
        }

    def _atomic_snapshot(self) -> Mapping[str, Tuple[Any, ...]]:
        statements = {
            "user": "SELECT * FROM iam.users WHERE id=%s",
            "acceptances": "SELECT * FROM iam.policy_acceptances WHERE user_id=%s ORDER BY id",
            "grants": "SELECT * FROM iam.consent_grants WHERE user_id=%s ORDER BY id",
            "categories": "SELECT category_row.* FROM iam.consent_grant_data_categories AS category_row JOIN iam.consent_grants AS grant_row ON grant_row.id=category_row.grant_id WHERE grant_row.user_id=%s ORDER BY category_row.grant_id,category_row.position",
            "receipts": "SELECT * FROM infra.command_receipts WHERE principal_id=%s ORDER BY id",
            "audit": "SELECT * FROM audit.audit_events WHERE actor_id=%s ORDER BY event_id",
            "outbox": "SELECT * FROM infra.outbox_events WHERE actor_id=%s ORDER BY event_id",
        }
        with self._admin() as connection:
            return {
                name: tuple(
                    connection.execute(statement, (self.graph.actor_id,)).fetchall()
                )
                for name, statement in statements.items()
            }

    @staticmethod
    def _expected_summary(
        *,
        user_version: int,
        acceptance_count: int,
        grant_count: int,
        event_types: Sequence[str],
    ) -> Mapping[str, Any]:
        return {
            "user_version": user_version,
            "acceptance_count": acceptance_count,
            "grant_count": grant_count,
            "receipt_status": "COMPLETED",
            "audit_count": 1,
            "event_types": tuple(sorted(event_types)),
        }

    @staticmethod
    def _project_summary(summary: Mapping[str, Any]) -> Mapping[str, Any]:
        receipts = summary["receipts"]
        return {
            "user_version": summary["user_version"],
            "acceptance_count": summary["acceptance_count"],
            "grant_count": len(summary["grants"]),
            "receipt_status": receipts[0][0] if len(receipts) == 1 else None,
            "audit_count": summary["audit_count"],
            "event_types": tuple(summary["event_types"]),
        }

    def test_contract_is_frozen_importable_and_closed(self) -> None:
        self.assertEqual(
            tuple(item.value for item in POLICY_CONSENT_POSTGRES_WRITE_CHECKPOINTS),
            (
                "command_receipt.claim",
                "policy_acceptance.insert",
                "consent_grant.expire",
                "consent_grant.insert",
                "consent_grant_category.insert",
                "user.version-cas",
                "audit_event.insert",
                "outbox_event.insert",
                "command_receipt.complete",
            ),
        )
        settings = PolicyConsentPostgresSettings()
        self.assertEqual(settings.runtime_role, "iam_app")
        with self.assertRaises(ValueError):
            PolicyConsentPostgresSettings(runtime_role="schema_owner")
        with self.assertRaises(ValueError):
            PolicyConsentPostgresSettings(runtime_role="iam_onboarding")
        request = self._request(
            PolicyConsentPostgresOperation.ACCEPT_CURRENT_POLICIES
        )
        with self.assertRaises(FrozenInstanceError):
            request.expected_user_version = 8  # type: ignore[misc]
        self.assertNotIn(RAW_IDEMPOTENCY_SENTINEL, repr(request))
        self.assertNotIn(request.receipt.identity_candidates[0].digest.hex(), repr(request))
        source = self._source()
        factory = self._factory(source=source)
        self.assertFalse(hasattr(factory, "execute"))
        observation = self._observe(factory, request)
        self.assertEqual(
            (
                observation,
                len(source.checked_out),
                len(source.released),
                len(source.discarded),
            ),
            (SemanticObservation("SUCCEEDED"), 1, 1, 0),
        )

    def test_accept_current_policies_happy_path_persists_complete_self_graph(self) -> None:
        request = self._request(
            PolicyConsentPostgresOperation.ACCEPT_CURRENT_POLICIES
        )
        observation = self._observe(self._factory(), request)
        actual = self._project_summary(self._summary(request))
        self.assertEqual(
            (observation, actual),
            (
                SemanticObservation("SUCCEEDED"),
                self._expected_summary(
                    user_version=8,
                    acceptance_count=1,
                    grant_count=0,
                    event_types=("PolicyAccepted", "PolicyRequirementsSatisfied"),
                ),
            ),
            "semantic RED: AcceptCurrentPolicies PostgreSQL UoW is unavailable",
        )

    def test_grant_consent_happy_path_persists_complete_self_graph(self) -> None:
        self._seed_acceptance(self.creator_policy)
        request = self._request(PolicyConsentPostgresOperation.GRANT_CONSENT)
        observation = self._observe(self._factory(), request)
        actual = self._project_summary(self._summary(request))
        self.assertEqual(
            (observation, actual),
            (
                SemanticObservation("SUCCEEDED"),
                self._expected_summary(
                    user_version=8,
                    acceptance_count=1,
                    grant_count=1,
                    event_types=("ConsentGranted",),
                ),
            ),
            "semantic RED: GrantConsent PostgreSQL UoW is unavailable",
        )

    def test_old_source_acceptance_reuses_under_replacement_current_bundle(self) -> None:
        self._seed_acceptance(self.organization_policy)
        replacement = self._publish_replacement(self.organization_policy)
        request = self._request(
            PolicyConsentPostgresOperation.ACCEPT_CURRENT_POLICIES,
            policy=replacement,
        )
        observation = self._observe(self._factory(), request)
        actual = self._project_summary(self._summary(request))
        self.assertEqual(
            (observation, actual),
            (
                SemanticObservation("SUCCEEDED"),
                self._expected_summary(
                    user_version=7,
                    acceptance_count=1,
                    grant_count=0,
                    event_types=(),
                ),
            ),
            "semantic RED: old-source exact acceptance is not reused",
        )

    def test_active_exact_consent_grant_reuses_without_extending_or_event(self) -> None:
        self._seed_acceptance(self.creator_policy)
        grant_id = self._seed_grant(
            self.creator_policy,
            granted_at=self.now - timedelta(minutes=5),
        )
        with self._admin() as connection:
            before = connection.execute(
                "SELECT expires_at,aggregate_version FROM iam.consent_grants WHERE id=%s",
                (grant_id,),
            ).fetchone()
        request = self._request(PolicyConsentPostgresOperation.GRANT_CONSENT)
        observation = self._observe(self._factory(), request)
        with self._admin() as connection:
            after = connection.execute(
                "SELECT expires_at,aggregate_version FROM iam.consent_grants WHERE id=%s",
                (grant_id,),
            ).fetchone()
        actual = self._project_summary(self._summary(request))
        self.assertEqual(
            (observation, before, after, actual),
            (
                SemanticObservation("SUCCEEDED"),
                before,
                before,
                self._expected_summary(
                    user_version=7,
                    acceptance_count=1,
                    grant_count=1,
                    event_types=(),
                ),
            ),
            "semantic RED: exact ACTIVE ConsentGrant is not replay-safe",
        )

    def test_expired_active_grant_materializes_then_new_current_offer_is_created(self) -> None:
        self._seed_acceptance(self.creator_policy)
        old_grant_id = self._seed_grant(
            self.creator_policy,
            granted_at=self.now - timedelta(days=366),
        )
        replacement = self._publish_replacement(self.creator_policy)
        request = self._request(
            PolicyConsentPostgresOperation.GRANT_CONSENT,
            policy=replacement,
        )
        observation = self._observe(self._factory(), request)
        with self._admin() as connection:
            rows = tuple(
                connection.execute(
                    "SELECT id,status,consent_offer_id FROM iam.consent_grants "
                    "WHERE user_id=%s ORDER BY created_at,id",
                    (self.graph.actor_id,),
                ).fetchall()
            )
        self.assertEqual(
            (observation, rows),
            (
                SemanticObservation("SUCCEEDED"),
                (
                    (old_grant_id, "EXPIRED", self.creator_policy.consent_offer_id),
                    (
                        request.generated_ids.consent_grant_id,
                        "ACTIVE",
                        replacement.consent_offer_id,
                    ),
                ),
            ),
            "semantic RED: expired authority is not atomically materialized/replaced",
        )

    def test_active_different_offer_conflicts_and_rolls_back(self) -> None:
        self._seed_acceptance(self.creator_policy)
        self._seed_grant(
            self.creator_policy,
            granted_at=self.now - timedelta(minutes=5),
        )
        replacement = self._publish_replacement(self.creator_policy)
        request = self._request(
            PolicyConsentPostgresOperation.GRANT_CONSENT,
            policy=replacement,
        )
        before = self._atomic_snapshot()
        observation = self._observe(self._factory(), request)
        after = self._atomic_snapshot()
        self.assertEqual(
            (observation, after),
            (SemanticObservation("INVALID_STATE_TRANSITION"), before),
            "semantic RED: different ACTIVE authority does not conflict",
        )

    def test_same_key_two_real_connections_execute_once_then_replay(self) -> None:
        first = self._request(
            PolicyConsentPostgresOperation.ACCEPT_CURRENT_POLICIES,
            raw_idempotency_key="same-key-concurrent",
        )
        second = self._request(
            PolicyConsentPostgresOperation.ACCEPT_CURRENT_POLICIES,
            raw_idempotency_key="same-key-concurrent",
        )
        source = self._source()
        factory = self._factory(
            source=source,
            fault_injector=BarrierAtReceiptClaim(),
        )
        with ThreadPoolExecutor(max_workers=2) as executor:
            observations = tuple(
                executor.map(lambda request: self._observe(factory, request), (first, second))
            )
        self.assertEqual(
            sorted(item.code for item in observations),
            ["REPLAYED", "SUCCEEDED"],
            "semantic RED: same-key claim does not converge",
        )

    def test_different_keys_serialize_on_user_version_without_double_effect(self) -> None:
        requests = (
            self._request(
                PolicyConsentPostgresOperation.ACCEPT_CURRENT_POLICIES,
                raw_idempotency_key="different-key-a",
            ),
            self._request(
                PolicyConsentPostgresOperation.ACCEPT_CURRENT_POLICIES,
                raw_idempotency_key="different-key-b",
            ),
        )
        source = self._source()
        factory = self._factory(
            source=source,
            fault_injector=BarrierAtReceiptClaim(),
        )
        with ThreadPoolExecutor(max_workers=2) as executor:
            observations = tuple(
                executor.map(lambda request: self._observe(factory, request), requests)
            )
        with self._admin() as connection:
            acceptance_count = connection.execute(
                "SELECT count(*) FROM iam.policy_acceptances WHERE user_id=%s",
                (self.graph.actor_id,),
            ).fetchone()[0]
        self.assertEqual(
            (sorted(item.code for item in observations), acceptance_count),
            (["PRECONDITION_FAILED", "SUCCEEDED"], 1),
            "semantic RED: different-key User CAS does not serialize",
        )

    def test_same_key_different_payload_conflicts_before_business_guard(self) -> None:
        first = self._request(
            PolicyConsentPostgresOperation.ACCEPT_CURRENT_POLICIES,
            raw_idempotency_key="same-key-different-payload",
        )
        second = self._request(
            PolicyConsentPostgresOperation.ACCEPT_CURRENT_POLICIES,
            raw_idempotency_key="same-key-different-payload",
            expected_user_version=6,
        )
        first_observation = self._observe(self._factory(), first)
        second_observation = self._observe(self._factory(), second)
        self.assertEqual(
            (first_observation.code, second_observation.code),
            ("SUCCEEDED", "IDEMPOTENCY_KEY_REUSED"),
            "semantic RED: payload conflict is not receipt-first",
        )

    def test_stale_if_match_is_precondition_failed_with_zero_writes(self) -> None:
        request = self._request(
            PolicyConsentPostgresOperation.ACCEPT_CURRENT_POLICIES,
            expected_user_version=6,
        )
        before = self._atomic_snapshot()
        observation = self._observe(self._factory(), request)
        after = self._atomic_snapshot()
        self.assertEqual(
            (observation, after),
            (SemanticObservation("PRECONDITION_FAILED"), before),
            "semantic RED: stale User If-Match is not rejected atomically",
        )

    def test_external_current_pointer_race_survives_command_rollback(self) -> None:
        request = self._request(
            PolicyConsentPostgresOperation.ACCEPT_CURRENT_POLICIES,
            policy=self.organization_policy,
        )
        replacement = self._publish_replacement(self.organization_policy)
        observation = self._observe(self._factory(), request)
        with self._admin() as connection:
            current = connection.execute(
                "SELECT current_bundle_id FROM iam.policy_selectors "
                "WHERE selector_digest=%s",
                (self.organization_policy.selector_digest,),
            ).fetchone()[0]
            command_writes = connection.execute(
                "SELECT "
                "(SELECT count(*) FROM infra.command_receipts WHERE id=%s),"
                "(SELECT count(*) FROM audit.audit_events WHERE command_id=%s),"
                "(SELECT count(*) FROM infra.outbox_events WHERE causation_id=%s)",
                (
                    request.scope.command_id,
                    request.scope.command_id,
                    request.scope.command_id,
                ),
            ).fetchone()
        self.assertEqual(
            (observation, current, command_writes),
            (SemanticObservation("POLICY_BUNDLE_CHANGED"), replacement.bundle_id, (0, 0, 0)),
            "semantic RED: committed current-pointer race is not classified safely",
        )

    def test_every_actual_logical_write_fault_rolls_back_every_fact(self) -> None:
        self._seed_acceptance(self.creator_policy)
        self._seed_grant(
            self.creator_policy,
            granted_at=self.now - timedelta(days=366),
        )
        replacement = self._publish_replacement(self.creator_policy)
        accept_targets = (
            (PolicyConsentPostgresWriteCheckpoint.COMMAND_RECEIPT_CLAIM, 0),
            (PolicyConsentPostgresWriteCheckpoint.POLICY_ACCEPTANCE_INSERT, 0),
            (PolicyConsentPostgresWriteCheckpoint.USER_VERSION_CAS, 0),
            (PolicyConsentPostgresWriteCheckpoint.AUDIT_EVENT_INSERT, 0),
            (PolicyConsentPostgresWriteCheckpoint.OUTBOX_EVENT_INSERT, 0),
            (PolicyConsentPostgresWriteCheckpoint.OUTBOX_EVENT_INSERT, 1),
            (PolicyConsentPostgresWriteCheckpoint.COMMAND_RECEIPT_COMPLETE, 0),
        )
        grant_targets = (
            (PolicyConsentPostgresWriteCheckpoint.COMMAND_RECEIPT_CLAIM, 0),
            (PolicyConsentPostgresWriteCheckpoint.CONSENT_GRANT_EXPIRE, 0),
            (PolicyConsentPostgresWriteCheckpoint.CONSENT_GRANT_INSERT, 0),
            (PolicyConsentPostgresWriteCheckpoint.CONSENT_GRANT_CATEGORY_INSERT, 0),
            (PolicyConsentPostgresWriteCheckpoint.CONSENT_GRANT_CATEGORY_INSERT, 1),
            (PolicyConsentPostgresWriteCheckpoint.CONSENT_GRANT_CATEGORY_INSERT, 2),
            (PolicyConsentPostgresWriteCheckpoint.USER_VERSION_CAS, 0),
            (PolicyConsentPostgresWriteCheckpoint.AUDIT_EVENT_INSERT, 0),
            (PolicyConsentPostgresWriteCheckpoint.OUTBOX_EVENT_INSERT, 0),
            (PolicyConsentPostgresWriteCheckpoint.COMMAND_RECEIPT_COMPLETE, 0),
        )
        for operation, policy, targets in (
            (
                PolicyConsentPostgresOperation.ACCEPT_CURRENT_POLICIES,
                self.organization_policy,
                accept_targets,
            ),
            (
                PolicyConsentPostgresOperation.GRANT_CONSENT,
                replacement,
                grant_targets,
            ),
        ):
            for target in targets:
                with self.subTest(operation=operation.value, checkpoint=target):
                    request = self._request(
                        operation,
                        raw_idempotency_key=f"fault-{operation.value}-{target[0].value}-{target[1]}",
                        policy=policy,
                    )
                    before = self._atomic_snapshot()
                    observation = self._observe(
                        self._factory(fault_injector=RaiseAtCheckpoint(target)),
                        request,
                    )
                    after = self._atomic_snapshot()
                    self.assertEqual(
                        (observation, after),
                        (SemanticObservation("INJECTED_WRITE_FAILURE"), before),
                        "semantic RED: logical write fault did not reach the SQL checkpoint",
                    )

    def test_commit_ack_loss_discards_old_connection_and_new_connection_recovers(self) -> None:
        request = self._request(
            PolicyConsentPostgresOperation.ACCEPT_CURRENT_POLICIES,
            raw_idempotency_key="commit-ack-loss-key",
        )
        lossy_source = self._source(lose_first_commit_ack=True)
        first = self._observe(self._factory(source=lossy_source), request)
        with self.subTest(phase="unknown-and-discard"):
            self.assertEqual(
                (first.code, len(lossy_source.discarded), len(lossy_source.released)),
                ("COMMAND_OUTCOME_UNKNOWN", 1, 0),
                "semantic RED: COMMIT_SENT connection was not discarded",
            )
        recovery_source = self._source()
        second = self._observe(self._factory(source=recovery_source), request)
        with self.subTest(phase="new-backend-replay"):
            self.assertEqual(
                (second.code, second.replayed, len(recovery_source.backend_pids)),
                ("REPLAYED", True, 1),
                "semantic RED: same-key recovery did not use the durable receipt",
            )

    def test_completed_receipt_replays_with_retained_row_keys_after_rotation(self) -> None:
        receipt_id = _new_id()
        request = self._request(
            PolicyConsentPostgresOperation.ACCEPT_CURRENT_POLICIES,
            raw_idempotency_key="retained-replay-key",
            policy=self.organization_policy,
            receipt_id=receipt_id,
            identity_key_ids=(IDENTITY_KEY_ID, RETAINED_IDENTITY_KEY_ID),
            active_identity_key_id=RETAINED_IDENTITY_KEY_ID,
            payload_key_ids=(PAYLOAD_KEY_ID, RETAINED_PAYLOAD_KEY_ID),
            active_payload_key_id=RETAINED_PAYLOAD_KEY_ID,
        )
        old_identity = next(
            item
            for item in request.receipt.identity_candidates
            if item.key_id == IDENTITY_KEY_ID
        )
        old_payload = next(
            item
            for item in request.receipt.payload_candidates
            if item.key_id == PAYLOAD_KEY_ID
        )
        safe_body = {
            "selector_digest": self.organization_policy.selector_digest.hex(),
            "purpose": "ORGANIZATION_MEMBERSHIP",
            "role": "DEMAND_OWNER",
            "scope_type": "ORGANIZATION_ROLE",
            "scope_id": str(self.graph.organization_id),
            "satisfied": True,
            "required_policy_bundle_id": str(self.organization_policy.bundle_id),
            "missing_document_ids": [],
        }
        with self._admin() as connection:
            connection.execute(
                "UPDATE infra.iam_receipt_key_policy SET policy_version=policy_version+1,"
                "active_idempotency_key_id=%s,active_payload_hash_key_id=%s,"
                "retained_idempotency_key_ids=ARRAY[%s,%s]::varchar(64)[],"
                "retained_payload_hash_key_ids=ARRAY[%s,%s]::varchar(64)[],"
                "updated_at=transaction_timestamp() WHERE singleton_key",
                (
                    RETAINED_IDENTITY_KEY_ID,
                    RETAINED_PAYLOAD_KEY_ID,
                    IDENTITY_KEY_ID,
                    RETAINED_IDENTITY_KEY_ID,
                    PAYLOAD_KEY_ID,
                    RETAINED_PAYLOAD_KEY_ID,
                ),
            )
            connection.execute(
                "INSERT INTO infra.command_receipts ("
                "id,principal_kind,principal_id,command_name,command_version,"
                "idempotency_key_digest,idempotency_key_digest_key_id,payload_hash,"
                "payload_hash_key_id,canonicalization_version,target_kind,target_id,"
                "http_method,canonical_path,if_match_version,status,"
                "response_schema_version,safe_response_body,reconstruction_metadata,"
                "response_http_status,response_schema_name,response_entity_tag,"
                "current_user_entity_tag,"
                "created_at,retain_until,completed_at) VALUES ("
                "%s,'USER',%s,'AcceptCurrentPolicies',1,%s,%s,%s,%s,%s,'User',%s,"
                "'POST','/v1/me/policy-acceptances',7,'COMPLETED',1,%s,NULL,"
                "%s,%s,%s,%s,%s,%s,%s)",
                (
                    receipt_id,
                    self.graph.actor_id,
                    old_identity.digest,
                    old_identity.key_id,
                    old_payload.digest,
                    old_payload.key_id,
                    old_payload.canonicalization_version,
                    self.graph.actor_id,
                    Jsonb(safe_body),
                    200,
                    "PolicyRequirementStatusDto",
                    '"v7"',
                    '"v7"',
                    self.now - timedelta(minutes=2),
                    self.now + timedelta(days=30),
                    self.now - timedelta(minutes=1),
                ),
            )
        replay_source = self._source()
        result = self._factory(source=replay_source).execute_accept_current_policies(
            request
        )
        self.assertEqual(
            (
                result.replayed,
                result.response_entity_tag,
                result.current_user_entity_tag,
                any(
                    "response_http_status,response_schema_name,"
                    "response_entity_tag,current_user_entity_tag" in statement
                    for statement in replay_source.trace
                ),
            ),
            (True, '"v7"', '"v7"', True),
            "semantic RED: retained row key/canonicalizer replay is unavailable",
        )

    def test_completed_receipt_metadata_drift_fails_closed_without_recomputation(
        self,
    ) -> None:
        request = self._request(
            PolicyConsentPostgresOperation.ACCEPT_CURRENT_POLICIES,
            raw_idempotency_key="receipt-metadata-drift",
            policy=self.organization_policy,
        )
        identity = next(
            item
            for item in request.receipt.identity_candidates
            if item.key_id == request.receipt.active_identity_key_id
        )
        payload = next(
            item
            for item in request.receipt.payload_candidates
            if item.key_id == request.receipt.active_payload_key_id
            and item.canonicalization_version
            == request.receipt.active_canonicalization_version
        )
        safe_body = {
            "selector_digest": self.organization_policy.selector_digest.hex(),
            "purpose": "ORGANIZATION_MEMBERSHIP",
            "role": "DEMAND_OWNER",
            "scope_type": "ORGANIZATION_ROLE",
            "scope_id": str(self.graph.organization_id),
            "satisfied": True,
            "required_policy_bundle_id": str(self.organization_policy.bundle_id),
            "missing_document_ids": [],
        }
        with self._admin() as connection:
            connection.execute(
                "INSERT INTO infra.command_receipts ("
                "id,principal_kind,principal_id,command_name,command_version,"
                "idempotency_key_digest,idempotency_key_digest_key_id,payload_hash,"
                "payload_hash_key_id,canonicalization_version,target_kind,target_id,"
                "http_method,canonical_path,if_match_version,status,"
                "response_schema_version,safe_response_body,reconstruction_metadata,"
                "response_http_status,response_schema_name,response_entity_tag,"
                "current_user_entity_tag,created_at,retain_until,completed_at"
                ") VALUES ("
                "%s,'USER',%s,'AcceptCurrentPolicies',1,%s,%s,%s,%s,%s,'User',%s,"
                "'POST','/v1/me/policy-acceptances',7,'COMPLETED',1,%s,NULL,"
                "200,'PolicyRequirementStatusDto','\"v8\"','\"v8\"',%s,%s,%s)",
                (
                    request.receipt.receipt_id,
                    self.graph.actor_id,
                    identity.digest,
                    identity.key_id,
                    payload.digest,
                    payload.key_id,
                    payload.canonicalization_version,
                    self.graph.actor_id,
                    Jsonb(safe_body),
                    self.now - timedelta(minutes=2),
                    self.now + timedelta(days=30),
                    self.now - timedelta(minutes=1),
                ),
            )
        before = self._atomic_snapshot()
        observation = self._observe(self._factory(), request)
        after = self._atomic_snapshot()
        self.assertEqual(
            (observation, after),
            (SemanticObservation("SERVICE_UNAVAILABLE"), before),
            "stored response metadata drift was silently recomputed during replay",
        )

    def test_online_role_force_rls_and_pool_reset_are_closed(self) -> None:
        with self._iam_app(autocommit=True) as connection:
            identity = connection.execute(
                "SELECT current_user,session_user,rolsuper,rolbypassrls,"
                "rolinherit FROM pg_catalog.pg_roles WHERE rolname=current_user"
            ).fetchone()
            no_context = connection.execute(
                "SELECT count(*) FROM iam.users"
            ).fetchone()[0]
            forced = connection.execute(
                "SELECT count(*) FROM pg_catalog.pg_class AS relation "
                "JOIN pg_catalog.pg_namespace AS namespace "
                "ON namespace.oid=relation.relnamespace "
                "WHERE namespace.nspname IN ('iam','infra','audit') "
                "AND relation.relname IN ('users','sessions','policy_acceptances',"
                "'consent_grants','command_receipts','audit_events','outbox_events') "
                "AND relation.relrowsecurity AND relation.relforcerowsecurity"
            ).fetchone()[0]
        self.assertEqual(identity, ("iam_app", "iam_app", False, False, False))
        self.assertEqual(no_context, 0)
        self.assertEqual(forced, 7)
        self._seed_acceptance(self.creator_policy)
        source = self._source(reuse_released=True)
        accept = self._request(
            PolicyConsentPostgresOperation.ACCEPT_CURRENT_POLICIES,
            raw_idempotency_key="pool-reset-accept",
        )
        grant = self._request(
            PolicyConsentPostgresOperation.GRANT_CONSENT,
            raw_idempotency_key="pool-reset-grant",
            expected_user_version=8,
        )
        factory = self._factory(source=source)
        observations = (
            self._observe(factory, accept),
            self._observe(factory, grant),
        )
        self.assertEqual(
            (
                tuple(item.code for item in observations),
                len(set(source.backend_pids)),
                len(source.released),
                len(source.discarded),
            ),
            (("SUCCEEDED", "SUCCEEDED"), 1, 2, 0),
            "semantic RED: iam_app pool program/reset is unavailable",
        )

    def test_raw_secret_sentinels_never_cross_request_trace_receipt_audit_or_outbox(self) -> None:
        self._seed_acceptance(self.creator_policy)
        request = self._request(
            PolicyConsentPostgresOperation.GRANT_CONSENT,
            raw_idempotency_key=RAW_IDEMPOTENCY_SENTINEL,
        )
        source = self._source()
        observation = self._observe(self._factory(source=source), request)
        inspected = repr(request) + repr(observation) + "\n".join(source.trace)
        for sentinel in RAW_TRANSPORT_SENTINELS:
            with self.subTest(carrier="request-trace", sentinel=sentinel):
                self.assertNotIn(sentinel, inspected)
        self._assert_no_transport_sentinel_in_database(RAW_TRANSPORT_SENTINELS)
        self._assert_no_raw_carrier_in_iam(RAW_CARRIER_SENTINELS)
        self.assertEqual(
            observation,
            SemanticObservation("SUCCEEDED"),
            "semantic RED: secret-safe PostgreSQL command behavior is unavailable",
        )

    def _assert_no_transport_sentinel_in_database(
        self,
        sentinels: Iterable[str],
    ) -> None:
        statements = (
            "SELECT row_to_json(receipt)::text FROM infra.command_receipts AS receipt",
            "SELECT row_to_json(event)::text FROM audit.audit_events AS event",
            "SELECT row_to_json(event)::text FROM infra.outbox_events AS event",
        )
        with self._admin() as connection:
            values = tuple(
                str(row[0])
                for statement in statements
                for row in connection.execute(statement).fetchall()
            )
        joined = "\n".join(values)
        for sentinel in sentinels:
            with self.subTest(carrier="receipt-audit-outbox", sentinel=sentinel):
                self.assertNotIn(sentinel, joined)

    def _assert_no_raw_carrier_in_iam(self, sentinels: Iterable[str]) -> None:
        with self._admin() as connection:
            rows = connection.execute(
                "SELECT format('SELECT row_to_json(t)::text FROM %I.%I AS t',"
                "table_schema,table_name) FROM information_schema.tables "
                "WHERE table_schema='iam' AND table_type='BASE TABLE' "
                "ORDER BY table_name"
            ).fetchall()
            values = tuple(
                str(item[0])
                for (statement,) in rows
                for item in connection.execute(statement).fetchall()
            )
        joined = "\n".join(values)
        for sentinel in sentinels:
            with self.subTest(carrier="iam-raw", sentinel=sentinel):
                self.assertNotIn(sentinel, joined)


if __name__ == "__main__":
    unittest.main()
