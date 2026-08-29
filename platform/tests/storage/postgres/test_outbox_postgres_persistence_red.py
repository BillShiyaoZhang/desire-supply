"""Real PostgreSQL 18 semantics for durable outbox delivery and consumer inbox.

The closed migration catalog and fixtures must be valid before the reviewed
production adapters are exercised.  These tests never skip because a delivery
dependency is missing and retain the original RED filename as TDD provenance.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
from typing import Any, Dict, Optional, Sequence, Tuple
import unittest
import uuid

import psycopg

from desire_platform.identity_access.adapters.postgres.migrations import (
    IamContractSources,
    IamMigrationRunner,
    MigrationCatalog,
    PsycopgMigrationDriver,
    PsycopgMigrationSettings,
)
from desire_platform.outbox.delivery import (
    OutboxDeliveryCycleResult,
    OutboxDeliveryError,
    OutboxDeliveryErrorCode,
    OutboxDeliveryStatus,
    OutboxDeliveryWorker,
    OutboxLease,
)
from desire_platform.outbox.postgres import (
    BrokerSettlement,
    CONSUMER_INBOX_POSTGRES_STATEMENT_NAMES,
    ConsumerInboxPersistenceCode,
    ConsumerInboxPostgresUnavailable,
    OUTBOX_POSTGRES_STATEMENT_NAMES,
    OutboxPostgresPersistenceCode,
    OutboxPostgresUnavailable,
    PostgresConnectionDisposition,
    PostgresConsumerInboxSettings,
    PostgresDurableConsumerInbox,
    PostgresOutboxRepository,
    PostgresOutboxSettings,
)
from tests.storage.postgres.postgres18_harness import TemporaryPostgres18
from tests.support.outbox_delivery_builders import (
    FixedUtcClock,
    StrictBackoff,
    StrictBrokerPublisher,
    StrictEventSchemaRegistry,
    StrictShutdownSignal,
    StrictTelemetry,
)


PLATFORM_ROOT = Path(__file__).resolve().parents[3]
MIGRATION_ROOT = (
    PLATFORM_ROOT
    / "src/desire_platform/identity_access/adapters/postgres/migrations"
)


class _StrictConsumerDelivery:
    """Local vendor-neutral fake: one message may settle only once."""

    def __init__(self, message: Any) -> None:
        self._message = message
        self.settlements: list[BrokerSettlement] = []

    @property
    def message(self):
        return self._message

    def ack(self) -> None:
        if self.settlements:
            raise AssertionError("broker delivery settled twice")
        self.settlements.append(BrokerSettlement.ACK)

    def nack(self, *, requeue: bool) -> None:
        if self.settlements or requeue is not True:
            raise AssertionError("invalid broker nack")
        self.settlements.append(BrokerSettlement.NACK_REQUEUE)


class _StrictProjectionHandler:
    def __init__(self, *, fail: bool = False, secret: Optional[str] = None) -> None:
        self.fail = fail
        self.secret = secret
        self.calls: list[str] = []

    def apply(self, *, message, transaction) -> None:
        del transaction
        self.calls.append(message.event_id)
        if self.fail:
            raise RuntimeError(self.secret or "consumer-crash-before-commit")


def _cycle(worker: OutboxDeliveryWorker) -> Tuple[
    Optional[OutboxDeliveryCycleResult], Optional[OutboxDeliveryErrorCode]
]:
    try:
        return worker.deliver_once(), None
    except OutboxDeliveryError as error:
        return None, error.code


class RealPostgres18OutboxPersistenceRedTest(unittest.TestCase):
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
        driver = PsycopgMigrationDriver(
            settings=PsycopgMigrationSettings(
                conninfo=self.postgres.conninfo(
                    database=self.database,
                    user="iam_migration_runner",
                ),
                application_name="desire-outbox-postgres-red-migration",
            ),
            dbapi=psycopg,
        )
        report = IamMigrationRunner(
            driver=driver,
            runner_version="outbox-postgres-red/1",
        ).run(catalog=self.catalog, contract_sources=self.contract_sources)
        self.assertEqual(
            report.applied_versions,
            tuple(artifact.descriptor.version for artifact in self.catalog.artifacts),
        )
        self.clock = FixedUtcClock(datetime.now(timezone.utc))
        self.repository = PostgresOutboxRepository(
            settings=PostgresOutboxSettings(
                conninfo=self.postgres.conninfo(
                    database=self.database,
                    user="iam_outbox_worker",
                )
            )
        )

    def tearDown(self) -> None:
        self.postgres.drop_database(self.database)

    def _admin(self, *, autocommit: bool = False):
        return psycopg.connect(
            self.postgres.admin_conninfo(database=self.database),
            autocommit=autocommit,
        )

    def _role(self, role: str, *, autocommit: bool = False):
        return psycopg.connect(
            self.postgres.conninfo(database=self.database, user=role),
            autocommit=autocommit,
        )

    def _seed_event(self, *, attempt_count: int = 0) -> Dict[str, Any]:
        event_id = uuid.uuid4()
        aggregate_id = uuid.uuid4()
        successor_id = uuid.uuid4()
        actor_id = uuid.uuid4()
        correlation_id = uuid.uuid4()
        causation_id = uuid.uuid4()
        trace_id = uuid.uuid4()
        with self._admin() as connection:
            connection.execute(
                "INSERT INTO infra.outbox_events ("
                "event_id,event_type,schema_version,occurred_at,aggregate_type,"
                "aggregate_id,aggregate_version,actor_kind,actor_id,"
                "original_actor_id,correlation_id,causation_id,trace_id,"
                "organization_id,payload,delivery_status,attempt_count,"
                "available_at,lease_owner,lease_until,published_at,"
                "last_error_code,created_at) VALUES ("
                "%s,'PolicyBundleSuperseded',1,transaction_timestamp(),"
                "'PolicyBundle',%s,1,'SYSTEM',%s,NULL,%s,%s,%s,NULL,"
                "%s::jsonb,'PENDING',%s,transaction_timestamp(),NULL,NULL,NULL,"
                "NULL,transaction_timestamp())",
                (
                    event_id,
                    aggregate_id,
                    actor_id,
                    correlation_id,
                    causation_id,
                    trace_id,
                    psycopg.types.json.Jsonb(
                        {
                            "policy_bundle_id": str(aggregate_id),
                            "status": "SUPERSEDED",
                            "superseded_by_policy_bundle_id": str(successor_id),
                        }
                    ),
                    attempt_count,
                ),
            )
        return {
            "event_id": event_id,
            "aggregate_id": aggregate_id,
            "successor_id": successor_id,
        }

    def _snapshot(self, event_id: uuid.UUID) -> Tuple[Any, ...]:
        with self._admin() as connection:
            return tuple(
                connection.execute(
                    "SELECT delivery_status,attempt_count,lease_owner,"
                    "lease_until,published_at,last_error_code "
                    "FROM infra.outbox_events WHERE event_id=%s",
                    (event_id,),
                ).fetchone()
            )

    def _worker(
        self,
        publisher: StrictBrokerPublisher,
        *,
        repository: Optional[PostgresOutboxRepository] = None,
        worker_id: str = "outbox-worker-pg18-a",
        max_attempts: int = 8,
    ) -> OutboxDeliveryWorker:
        return OutboxDeliveryWorker(
            repository=repository or self.repository,
            schema_registry=StrictEventSchemaRegistry(),
            publisher=publisher,
            clock=self.clock,
            backoff=StrictBackoff(),
            telemetry=StrictTelemetry(),
            shutdown=StrictShutdownSignal(),
            worker_id=worker_id,
            max_attempts=max_attempts,
        )

    def _publisher(self, modes: Sequence[str]) -> StrictBrokerPublisher:
        return StrictBrokerPublisher(clock=self.clock, modes=modes)

    def _claim(
        self,
        repository: PostgresOutboxRepository,
        *,
        worker_id: str,
        lease_duration: timedelta = timedelta(seconds=30),
    ) -> Tuple[Tuple[OutboxLease, ...], Optional[OutboxPostgresPersistenceCode]]:
        try:
            leases = repository.claim_batch(
                worker_id=worker_id,
                batch_size=100,
                lease_duration=lease_duration,
                max_attempts=8,
            )
            return tuple(leases), None
        except OutboxPostgresUnavailable as error:
            return (), error.persistence_code

    def _inbox_count(self) -> int:
        try:
            with self._admin() as connection:
                return int(
                    connection.execute(
                        "SELECT count(*) FROM infra.consumer_inbox_events"
                    ).fetchone()[0]
                )
        except psycopg.Error:
            return -1

    def _validated_message(self, facts: Dict[str, Any]):
        from desire_platform.outbox.delivery import OutboxEventEnvelope

        envelope = OutboxEventEnvelope(
            event_id=str(facts["event_id"]),
            event_type="PolicyBundleSuperseded",
            schema_version=1,
            occurred_at=self.clock.now(),
            aggregate_type="PolicyBundle",
            aggregate_id=str(facts["aggregate_id"]),
            aggregate_version=1,
            actor_kind="SYSTEM",
            actor_id=str(uuid.uuid4()),
            original_actor_id=None,
            correlation_id=str(uuid.uuid4()),
            causation_id=str(uuid.uuid4()),
            trace_id=str(uuid.uuid4()),
            organization_id=None,
            payload={
                "policy_bundle_id": str(facts["aggregate_id"]),
                "status": "SUPERSEDED",
                "superseded_by_policy_bundle_id": str(facts["successor_id"]),
            },
        )
        return StrictEventSchemaRegistry().validate(envelope)

    def test_contract_is_closed_importable_and_postgres_adapters_are_ready(self) -> None:
        self.repository.check_readiness()
        inbox = PostgresDurableConsumerInbox(
            settings=PostgresConsumerInboxSettings(
                conninfo=self.postgres.conninfo(
                    database=self.database,
                    user="iam_projection_consumer",
                ),
                consumer_name="iam-policy-projection-v1",
            )
        )
        inbox.check_readiness()

        self.assertEqual(
            (
                OUTBOX_POSTGRES_STATEMENT_NAMES,
                CONSUMER_INBOX_POSTGRES_STATEMENT_NAMES,
                self._inbox_count(),
                set(item.value for item in PostgresConnectionDisposition),
            ),
            (
                (
                    "dead_letter_exhausted_outbox_v1",
                    "claim_outbox_batch_v1",
                    "mark_outbox_published_v1",
                    "reschedule_outbox_v1",
                    "dead_letter_outbox_v1",
                    "release_unstarted_outbox_lease_v1",
                ),
                (
                    "claim_consumer_inbox_v1",
                    "read_consumer_inbox_duplicate_v1",
                ),
                0,
                {
                    "REUSE_AFTER_RESET",
                    "DISCARD",
                    "OUTCOME_UNKNOWN_DISCARD",
                },
            ),
        )

    def test_two_real_connections_claim_disjoint_batches(self) -> None:
        first = self._seed_event()
        second = self._seed_event()
        repo_b = PostgresOutboxRepository(
            settings=PostgresOutboxSettings(
                conninfo=self.postgres.conninfo(
                    database=self.database,
                    user="iam_outbox_worker",
                )
            )
        )
        leases_a, error_a = self._claim(
            self.repository, worker_id="outbox-worker-pg18-a"
        )
        leases_b, error_b = self._claim(repo_b, worker_id="outbox-worker-pg18-b")
        ids_a = {lease.envelope.event_id for lease in leases_a}
        ids_b = {lease.envelope.event_id for lease in leases_b}

        self.assertEqual(
            (error_a, error_b, ids_a & ids_b, ids_a | ids_b),
            (
                None,
                None,
                set(),
                {str(first["event_id"]), str(second["event_id"])},
            ),
        )

    def test_expired_lease_reclaims_and_stale_fence_cannot_publish(self) -> None:
        facts = self._seed_event()
        old_leases, claim_error = self._claim(
            self.repository,
            worker_id="outbox-worker-pg18-old",
            lease_duration=timedelta(seconds=1),
        )
        stale_mark = None
        new_attempt = None
        if old_leases:
            old = old_leases[0]
            with self._admin() as connection:
                connection.execute(
                    "UPDATE infra.outbox_events SET lease_until=transaction_timestamp() "
                    "WHERE event_id=%s",
                    (facts["event_id"],),
                )
            new_leases, _new_error = self._claim(
                self.repository, worker_id="outbox-worker-pg18-new"
            )
            new_attempt = new_leases[0].attempt_count if new_leases else None
            stale_mark = self.repository.mark_published(lease=old)

        self.assertEqual(
            (claim_error, len(old_leases), new_attempt, stale_mark),
            (None, 1, 2, False),
        )

    def test_broker_failure_before_accept_is_durably_rescheduled(self) -> None:
        facts = self._seed_event()
        publisher = self._publisher((StrictBrokerPublisher.BEFORE_ACK,))
        result, error = _cycle(self._worker(publisher))

        self.assertEqual(
            (error, result, self._snapshot(facts["event_id"]), len(publisher.calls)),
            (
                None,
                OutboxDeliveryCycleResult(
                    1,
                    0,
                    1,
                    0,
                    0,
                    (OutboxDeliveryErrorCode.BROKER_UNAVAILABLE,),
                ),
                (
                    "PENDING",
                    1,
                    None,
                    None,
                    None,
                    "BROKER_UNAVAILABLE",
                ),
                1,
            ),
        )

    def test_broker_ack_unknown_restarts_with_same_event_id(self) -> None:
        facts = self._seed_event()
        publisher = self._publisher(
            (StrictBrokerPublisher.AFTER_ACK, StrictBrokerPublisher.SUCCESS)
        )
        first, first_error = _cycle(self._worker(publisher))
        self.clock.advance(timedelta(seconds=2))
        with self._admin() as connection:
            database_now, retry_available_at = connection.execute(
                "SELECT transaction_timestamp(),available_at "
                "FROM infra.outbox_events "
                "WHERE event_id=%s AND delivery_status='PENDING'",
                (facts["event_id"],),
            ).fetchone()
            self.assertGreater(retry_available_at, database_now)
            connection.execute(
                "UPDATE infra.outbox_events "
                "SET available_at=transaction_timestamp() "
                "WHERE event_id=%s AND delivery_status='PENDING'",
                (facts["event_id"],),
            )
        second, second_error = _cycle(self._worker(publisher))

        self.assertEqual(
            (
                first_error,
                None if first is None else first.rescheduled_count,
                second_error,
                None if second is None else second.published_count,
                publisher.accepted_event_ids,
                self._snapshot(facts["event_id"])[0:2],
            ),
            (
                None,
                1,
                None,
                1,
                [str(facts["event_id"]), str(facts["event_id"])],
                ("PUBLISHED", 2),
            ),
        )

    def test_restart_recovers_expired_lease_without_process_memory(self) -> None:
        facts = self._seed_event()
        old, old_error = self._claim(
            self.repository,
            worker_id="outbox-worker-before-restart",
            lease_duration=timedelta(seconds=1),
        )
        if old:
            with self._admin() as connection:
                connection.execute(
                    "UPDATE infra.outbox_events SET lease_until=transaction_timestamp() "
                    "WHERE event_id=%s",
                    (facts["event_id"],),
                )
        restarted = PostgresOutboxRepository(
            settings=PostgresOutboxSettings(
                conninfo=self.postgres.conninfo(
                    database=self.database,
                    user="iam_outbox_worker",
                )
            )
        )
        recovered, recovered_error = self._claim(
            restarted, worker_id="outbox-worker-after-restart"
        )

        self.assertEqual(
            (
                old_error,
                len(old),
                recovered_error,
                [lease.envelope.event_id for lease in recovered],
                [lease.lease_reclaimed for lease in recovered],
            ),
            (None, 1, None, [str(facts["event_id"])], [True]),
        )

    def test_attempt_limit_dead_letters_without_redrive(self) -> None:
        facts = self._seed_event(attempt_count=7)
        publisher = self._publisher((StrictBrokerPublisher.BEFORE_ACK,))
        first, first_error = _cycle(self._worker(publisher, max_attempts=8))
        second, second_error = _cycle(self._worker(publisher, max_attempts=8))

        self.assertEqual(
            (
                first_error,
                None if first is None else first.dead_lettered_count,
                second_error,
                None if second is None else second.claimed_count,
                self._snapshot(facts["event_id"]),
                len(publisher.calls),
            ),
            (
                None,
                1,
                None,
                0,
                (
                    "DEAD",
                    8,
                    None,
                    None,
                    None,
                    "DELIVERY_ATTEMPTS_EXHAUSTED",
                ),
                1,
            ),
        )

    def test_duplicate_consumer_delivery_commits_one_inbox_and_one_effect(self) -> None:
        facts = self._seed_event()
        message = self._validated_message(facts)
        handler = _StrictProjectionHandler()
        inbox = PostgresDurableConsumerInbox(
            settings=PostgresConsumerInboxSettings(
                conninfo=self.postgres.conninfo(
                    database=self.database,
                    user="iam_projection_consumer",
                ),
                consumer_name="iam-policy-projection-v1",
            )
        )
        settlements = []
        errors = []
        for _attempt in range(2):
            delivery = _StrictConsumerDelivery(message)
            try:
                result = inbox.process(delivery=delivery, handler=handler)
                settlements.append(result.settlement)
            except ConsumerInboxPostgresUnavailable as error:
                errors.append(error.code)

        self.assertEqual(
            (errors, settlements, handler.calls, self._inbox_count()),
            ([], [BrokerSettlement.ACK, BrokerSettlement.ACK], [message.event_id], 1),
        )

    def test_consumer_crash_rolls_back_inbox_and_redelivery_applies(self) -> None:
        facts = self._seed_event()
        message = self._validated_message(facts)
        inbox = PostgresDurableConsumerInbox(
            settings=PostgresConsumerInboxSettings(
                conninfo=self.postgres.conninfo(
                    database=self.database,
                    user="iam_projection_consumer",
                ),
                consumer_name="iam-policy-projection-v1",
            )
        )
        crash_delivery = _StrictConsumerDelivery(message)
        crash_handler = _StrictProjectionHandler(fail=True)
        crash_code = None
        try:
            inbox.process(delivery=crash_delivery, handler=crash_handler)
        except ConsumerInboxPostgresUnavailable as error:
            crash_code = error.code
        except RuntimeError:
            crash_code = None
        count_after_crash = self._inbox_count()
        retry_delivery = _StrictConsumerDelivery(message)
        retry_handler = _StrictProjectionHandler()
        retry_settlement = None
        try:
            retry_settlement = inbox.process(
                delivery=retry_delivery,
                handler=retry_handler,
            ).settlement
        except ConsumerInboxPostgresUnavailable:
            pass

        self.assertEqual(
            (
                crash_code,
                count_after_crash,
                crash_delivery.settlements,
                retry_settlement,
                retry_handler.calls,
                self._inbox_count(),
            ),
            (None, 0, [BrokerSettlement.NACK_REQUEUE], BrokerSettlement.ACK, [message.event_id], 1),
        )

    def test_worker_role_has_operational_scope_but_no_owner_bypass(self) -> None:
        facts = self._seed_event()
        with self._role("iam_outbox_worker") as connection:
            role_facts = connection.execute(
                "SELECT rolsuper,rolbypassrls,rolinherit FROM pg_catalog.pg_roles "
                "WHERE rolname=current_user"
            ).fetchone()
            connection.execute(
                "SELECT pg_catalog.set_config('app.scope_kind','OUTBOX_DELIVERY',true)"
            )
            connection.execute(
                "SELECT pg_catalog.set_config('app.operation','CLAIM',true)"
            )
            connection.execute(
                "SELECT pg_catalog.set_config('app.outbox_worker_id',%s,true)",
                ("outbox-worker-security",),
            )
            connection.execute(
                "SELECT pg_catalog.set_config('app.outbox_claim_token',%s,true)",
                (str(uuid.uuid4()),),
            )
            try:
                visible = connection.execute(
                    "SELECT count(*) FROM infra.outbox_events WHERE event_id=%s",
                    (facts["event_id"],),
                ).fetchone()[0]
            except psycopg.Error as error:
                visible = -1
                outbox_state = error.sqlstate
                connection.rollback()
            else:
                outbox_state = None

        denied_states = []
        for statement in (
            "SELECT count(*) FROM iam.users",
            "SELECT count(*) FROM audit.audit_events",
            "SELECT count(*) FROM infra.command_receipts",
        ):
            with self._role("iam_outbox_worker") as connection:
                try:
                    connection.execute(statement).fetchone()
                except psycopg.Error as error:
                    denied_states.append(error.sqlstate)

        self.assertEqual(
            (tuple(role_facts), visible, outbox_state, denied_states),
            ((False, False, False), 1, None, ["42501", "42501", "42501"]),
        )

    def test_secret_sentinel_never_reaches_row_exception_or_settings_repr(self) -> None:
        secret = "sentinel-db-password-provider-contact-token"
        facts = self._seed_event()
        private_settings = PostgresOutboxSettings(
            conninfo="postgresql://worker:%s@localhost/private" % secret
        )
        publisher = StrictBrokerPublisher(
            clock=self.clock,
            modes=(StrictBrokerPublisher.BEFORE_ACK,),
            provider_detail=secret,
        )
        result, error = _cycle(
            self._worker(publisher, repository=self.repository)
        )
        observable = repr(
            (
                private_settings,
                result,
                error,
                self._snapshot(facts["event_id"]),
                publisher.calls,
            )
        )

        self.assertEqual(
            (
                error,
                None if result is None else result.rescheduled_count,
                len(publisher.calls),
                secret in observable,
            ),
            (None, 1, 1, False),
        )

    def test_message_hash_is_stable_for_consumer_collision_detection(self) -> None:
        facts = self._seed_event()
        message = self._validated_message(facts)
        first = hashlib.sha256(message.canonical_bytes).digest()
        second = hashlib.sha256(message.canonical_bytes).digest()
        self.assertEqual((len(first), first, second), (32, second, first))


if __name__ == "__main__":
    unittest.main()
