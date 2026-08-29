from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timezone
import hashlib
from pathlib import Path
import threading
import unittest
from uuid import UUID

import psycopg

from desire_platform.demand.adapters.postgres import (
    DemandPostgresDatabaseError,
    DemandPostgresOperation,
    PsycopgDemandUnitOfWorkFactory,
)
from desire_platform.demand.adapters.postgres.migrations import (
    DemandContractSources,
    DemandMigrationCatalog,
    DemandMigrationRunner,
    DemandMigrationSettings,
    PsycopgDemandMigrationDriver,
)
from desire_platform.identity_access.adapters.postgres.editor_principal import (
    EditorPrincipalResolutionRequest,
    PsycopgEditorPrincipalResolver,
)
from desire_platform.identity_access.adapters.postgres.migrations import (
    IamContractSources,
    IamMigrationRunner,
    MigrationCatalog,
    PsycopgMigrationDriver,
    PsycopgMigrationSettings,
)
from desire_platform.internal_pilot.contract_validation import (
    DemandPostgresContractValidator,
)
from desire_platform.internal_pilot.editor import EditorPrincipal
import desire_platform.internal_pilot.editor.review_queue as review_queue_module
from desire_platform.internal_pilot.editor.review_queue import (
    DemandReviewClaimRequest,
    DemandReviewQueueError,
    PsycopgDemandReviewQueue,
)
from tests.storage.postgres.postgres18_harness import TemporaryPostgres18
from tests.support.demand_postgres_builders import (
    ASSIGNMENT_ID,
    DEMAND_ID,
    DEMAND_VERSION_ID,
    ORGANIZATION_ID,
    REVIEW_ID,
    REVIEWER_DUTY_GRANT_ID,
    REVIEWER_SESSION_ID,
    REVIEWER_USER_ID,
    SUBMISSION_ID,
    RecordingSchemaValidator,
    TrackingDemandConnectionSource,
    postgres_command,
    seed_demand_operation_graph,
    seed_exact_demand_owner_iam_authority,
)


PLATFORM_ROOT = Path(__file__).resolve().parents[3]
IAM_ROOT = PLATFORM_ROOT / "src/desire_platform/identity_access/adapters/postgres/migrations"
DEMAND_ROOT = PLATFORM_ROOT / "src/desire_platform/demand/adapters/postgres/migrations"


def _id(value: int) -> UUID:
    return UUID(f"{value:08x}-0000-4000-8000-000000000025")


class RealPostgres18DemandReviewQueueTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.postgres = TemporaryPostgres18().start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.postgres.stop()

    def setUp(self) -> None:
        self.database = self.postgres.create_database()
        self.sources: list[TrackingDemandConnectionSource] = []
        self._migrate()
        with self._admin(autocommit=False) as connection:
            seed_exact_demand_owner_iam_authority(
                connection,
                now=datetime.now(timezone.utc).replace(microsecond=0),
            )
            seed_demand_operation_graph(connection, DemandPostgresOperation.SUBMIT)
        owner = self._source("demand_self")
        PsycopgDemandUnitOfWorkFactory(
            connections=owner,
            event_validator=RecordingSchemaValidator(),
            response_validator=RecordingSchemaValidator(),
        ).execute_submit(postgres_command(DemandPostgresOperation.SUBMIT))
        resolver = PsycopgEditorPrincipalResolver(connections=self._source("iam_app"))
        workspace = resolver.resolve(
            EditorPrincipalResolutionRequest(
                actor_user_id=REVIEWER_USER_ID,
                session_id=REVIEWER_SESSION_ID,
                requested_workspace_id=f"platform:{REVIEWER_USER_ID}",
            )
        )
        self.principal = EditorPrincipal(
            user_id=str(workspace.user_id),
            session_id=str(workspace.session_id),
            organization_id=None,
            role_codes=workspace.platform_duty_codes,
            workspace_id=workspace.workspace_id,
            workspace_kind=workspace.workspace_kind.value,
            membership_id=None,
            organization_role_codes=workspace.organization_role_codes,
            user_role_codes=workspace.user_role_codes,
            platform_duty_codes=workspace.platform_duty_codes,
            principal_marker_sha256=workspace.principal_marker,
        )

    def tearDown(self) -> None:
        for source in self.sources:
            source.close()
        self.postgres.drop_database(self.database)

    def test_readiness_accepts_the_current_demand_schema_contract(self) -> None:
        queue = self._queue()

        self.assertIsNone(queue.check_readiness(timeout_ms=1_000))

    def test_list_claim_replay_occ_audit_and_outbox_are_one_pg_transaction(self) -> None:
        queue = self._queue()
        listed = queue.list_available(principal=self.principal)
        self.assertEqual(
            tuple((item.demand_id, item.demand_revision) for item in listed),
            ((str(DEMAND_ID), 2),),
        )
        request = self._claim_request(variant=1)

        claimed = queue.claim(request)
        replayed = queue.claim(request)
        unavailable_after_claim = queue.list_available(principal=self.principal)

        self.assertEqual(
            (
                claimed.assignment_id,
                claimed.demand_revision,
                claimed.status,
                claimed.replayed,
                replayed.assignment_id,
                replayed.replayed,
                unavailable_after_claim,
            ),
            (str(ASSIGNMENT_ID), 2, "ACTIVE", False, str(ASSIGNMENT_ID), True, ()),
        )
        with self._admin() as connection:
            facts = connection.execute(
                "SELECT "
                "(SELECT count(*) FROM demand.demand_review_assignments "
                " WHERE id=%s AND duty_grant_id=%s AND duty_grant_version=1 "
                " AND status='ACTIVE'),"
                "(SELECT count(*) FROM demand.review_claim_receipts "
                " WHERE receipt_id=%s AND status='COMPLETED'),"
                "(SELECT count(*) FROM audit.audit_events "
                " WHERE action_code='CLAIM_DEMAND_REVIEW'),"
                "(SELECT count(*) FROM infra.outbox_events "
                " WHERE event_type='DemandReviewClaimed')",
                (ASSIGNMENT_ID, REVIEWER_DUTY_GRANT_ID, request.receipt_id),
            ).fetchone()
        self.assertEqual(facts, (1, 1, 1, 1))

        with self.assertRaises(DemandReviewQueueError) as stale:
            queue.claim(self._claim_request(variant=2, expected_revision=1))
        self.assertEqual(stale.exception.code, "PRECONDITION_FAILED")

    def test_completed_review_history_is_self_scoped_terminal_and_safe(self) -> None:
        queue = self._queue()
        queue.claim(self._claim_request(variant=1))
        PsycopgDemandUnitOfWorkFactory(
            connections=self._source("demand_review"),
            event_validator=RecordingSchemaValidator(),
            response_validator=RecordingSchemaValidator(),
        ).execute_verify(
            postgres_command(DemandPostgresOperation.VERIFY, expected_version=2)
        )

        history = queue.list_history(principal=self.principal, maximum_items=25)

        self.assertEqual(len(history), 1)
        item = history[0]
        self.assertEqual(
            (
                item.review_id,
                item.demand_id,
                item.demand_version_id,
                item.decision,
                item.reason_codes,
                item.required_field_codes,
                item.budget_health_code,
                item.risk_code,
            ),
            (
                str(REVIEW_ID),
                str(DEMAND_ID),
                str(DEMAND_VERSION_ID),
                "VERIFIED",
                (),
                (),
                "HEALTHY",
                "STANDARD",
            ),
        )
        self.assertIsNotNone(item.reviewed_at)
        self.assertEqual(
            set(item.__dict__),
            {
                "review_id",
                "demand_id",
                "demand_version_id",
                "decision",
                "reason_codes",
                "required_field_codes",
                "budget_health_code",
                "risk_code",
                "reviewed_at",
            },
        )

    def test_conflict_release_excludes_list_resolve_and_direct_reclaim(self) -> None:
        queue = self._queue()
        self._claim_then_release(queue=queue, reason_code="CONFLICT_DECLARED")

        self.assertEqual(queue.list_available(principal=self.principal), ())
        self.assertIsNone(self._resolve_queue_target_direct())

        direct_request = self._claim_request(variant=5, expected_revision=3)
        error = self._direct_claim_error(direct_request)
        self.assertIsInstance(error, psycopg.errors.CheckViolation)
        self.assertEqual(
            error.diag.constraint_name,
            "review_claim_conflict_declared",
        )
        self.assertEqual(
            review_queue_module._database_code(error),
            "RESOURCE_NOT_FOUND",
        )
        with self._admin() as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT "
                    "(SELECT count(*) FROM demand.demand_review_assignments "
                    " WHERE demand_id=%s AND status='ACTIVE'),"
                    "(SELECT count(*) FROM demand.review_claim_receipts "
                    " WHERE receipt_id=%s),"
                    "(SELECT count(*) FROM audit.audit_events "
                    " WHERE event_id=%s),"
                    "(SELECT count(*) FROM infra.outbox_events "
                    " WHERE event_id=%s)",
                    (
                        DEMAND_ID,
                        direct_request.receipt_id,
                        direct_request.audit_event_id,
                        direct_request.outbox_event_id,
                    ),
                ).fetchone(),
                (0, 0, 0, 0),
                "a direct conflict reclaim must roll its pending receipt back",
            )

    def test_workload_release_remains_listed_resolvable_and_reclaimable(self) -> None:
        queue = self._queue()
        self._claim_then_release(queue=queue, reason_code="WORKLOAD_RELEASE")

        listed = queue.list_available(principal=self.principal)
        resolved = self._resolve_queue_target_direct()
        reclaimed = queue.claim(
            self._claim_request(variant=6, expected_revision=3)
        )

        self.assertEqual(
            tuple((item.demand_id, item.demand_revision) for item in listed),
            ((str(DEMAND_ID), 3),),
        )
        self.assertEqual(
            resolved,
            (ORGANIZATION_ID, 3, DEMAND_VERSION_ID, SUBMISSION_ID),
        )
        self.assertEqual(
            (
                reclaimed.assignment_id,
                reclaimed.demand_id,
                reclaimed.demand_revision,
                reclaimed.status,
                reclaimed.replayed,
            ),
            (
                str(_id(0x42000004)),
                str(DEMAND_ID),
                3,
                "ACTIVE",
                False,
            ),
        )

    def test_two_different_claims_serialize_to_one_assignment(self) -> None:
        barrier = threading.Barrier(2)

        def claim(variant: int):
            queue = self._queue()
            barrier.wait(timeout=10)
            try:
                return queue.claim(self._claim_request(variant=variant)).assignment_id
            except DemandReviewQueueError as error:
                return error.code
            finally:
                queue.close()

        with ThreadPoolExecutor(max_workers=2) as executor:
            outcomes = tuple(executor.map(claim, (3, 4)))

        self.assertEqual(
            sorted(
                "ASSIGNMENT" if value in {str(ASSIGNMENT_ID), str(_id(0x42000004))} else value
                for value in outcomes
            ),
            ["ASSIGNMENT", "REVIEW_ALREADY_CLAIMED"],
        )
        with self._admin() as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT "
                    "(SELECT count(*) FROM demand.demand_review_assignments "
                    " WHERE demand_id=%s AND status='ACTIVE'),"
                    "(SELECT count(*) FROM demand.review_claim_receipts),"
                    "(SELECT count(*) FROM audit.audit_events "
                    " WHERE action_code='CLAIM_DEMAND_REVIEW'),"
                    "(SELECT count(*) FROM infra.outbox_events "
                    " WHERE event_type='DemandReviewClaimed')",
                    (DEMAND_ID,),
                ).fetchone(),
                (1, 1, 1, 1),
            )

    def test_revoked_reviewer_duty_blocks_verify_without_partial_writes(self) -> None:
        queue = self._queue()
        queue.claim(self._claim_request(variant=1))
        with self._admin(autocommit=True) as connection:
            connection.execute(
                "UPDATE iam.platform_duty_grants SET revoked_at=transaction_timestamp(),"
                "revocation_reason_code='ACCESS_REVIEW',aggregate_version=2,"
                "updated_at=transaction_timestamp() WHERE id=%s",
                (REVIEWER_DUTY_GRANT_ID,),
            )
            before = connection.execute(
                "SELECT "
                "(SELECT count(*) FROM demand.demand_reviews),"
                "(SELECT count(*) FROM demand.command_receipts),"
                "(SELECT count(*) FROM audit.audit_events),"
                "(SELECT count(*) FROM infra.outbox_events)"
            ).fetchone()
        reviewer = self._source("demand_review")
        with self.assertRaises(DemandPostgresDatabaseError) as denied:
            PsycopgDemandUnitOfWorkFactory(
                connections=reviewer,
                event_validator=RecordingSchemaValidator(),
                response_validator=RecordingSchemaValidator(),
            ).execute_verify(
                postgres_command(DemandPostgresOperation.VERIFY, expected_version=2)
            )
        self.assertEqual(denied.exception.code, "RESOURCE_NOT_FOUND")
        with self._admin() as connection:
            after = connection.execute(
                "SELECT "
                "(SELECT count(*) FROM demand.demand_reviews),"
                "(SELECT count(*) FROM demand.command_receipts),"
                "(SELECT count(*) FROM audit.audit_events),"
                "(SELECT count(*) FROM infra.outbox_events)"
            ).fetchone()
        self.assertEqual(after, before)

    def _queue(self) -> PsycopgDemandReviewQueue:
        return PsycopgDemandReviewQueue(
            connections=self._source("demand_review"),
            event_validator=DemandPostgresContractValidator(),
        )

    def _claim_then_release(
        self,
        *,
        queue: PsycopgDemandReviewQueue,
        reason_code: str,
    ) -> None:
        queue.claim(self._claim_request(variant=1))
        release = replace(
            postgres_command(
                DemandPostgresOperation.RELEASE_REVIEW_ASSIGNMENT,
                expected_version=2,
            ),
            release_reason_code=reason_code,
        )
        result = PsycopgDemandUnitOfWorkFactory(
            connections=self._source("demand_review"),
            event_validator=RecordingSchemaValidator(),
            response_validator=RecordingSchemaValidator(),
        ).execute_release_review_assignment(release)
        self.assertEqual(
            (result.status, result.aggregate_version, result.replayed),
            ("SUBMITTED", 3, False),
        )

    def _resolve_queue_target_direct(self):
        with psycopg.connect(
            self.postgres.conninfo(database=self.database, user="demand_review"),
            autocommit=True,
        ) as connection:
            connection.execute(
                "BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY"
            )
            self._install_direct_context(
                connection,
                operation="RESOLVE_REVIEW_QUEUE_TARGET",
            )
            row = connection.execute(
                "SELECT organization_id,demand_revision,demand_version_id,"
                "submission_id FROM demand_api.resolve_review_queue_target_v1("
                "%s,%s,%s,%s)",
                (
                    REVIEWER_USER_ID,
                    REVIEWER_SESSION_ID,
                    DEMAND_ID,
                    self.principal.principal_marker_sha256,
                ),
            ).fetchone()
            connection.execute("ROLLBACK")
            return row

    def _direct_claim_error(
        self,
        request: DemandReviewClaimRequest,
    ) -> psycopg.Error:
        with psycopg.connect(
            self.postgres.conninfo(database=self.database, user="demand_review"),
            autocommit=True,
        ) as connection:
            connection.execute("BEGIN TRANSACTION ISOLATION LEVEL READ COMMITTED")
            self._install_direct_context(
                connection,
                operation="CLAIM_REVIEW",
                organization_id=ORGANIZATION_ID,
            )
            try:
                connection.execute(
                    "SELECT assignment_id,demand_id,demand_revision,"
                    "assignment_status,assignment_expires_at,"
                    "response_entity_tag,replayed FROM "
                    "demand_api.claim_demand_review_v1("
                    + ",".join(["%s"] * 17)
                    + ")",
                    (
                        REVIEWER_USER_ID,
                        REVIEWER_SESSION_ID,
                        ORGANIZATION_ID,
                        DEMAND_ID,
                        request.expected_demand_revision,
                        self.principal.principal_marker_sha256,
                        request.assignment_id,
                        request.receipt_id,
                        request.idempotency_key_digest_key_id,
                        request.idempotency_key_digest,
                        request.payload_hash_key_id,
                        request.payload_hash,
                        request.audit_event_id,
                        request.outbox_event_id,
                        request.correlation_id,
                        request.causation_id,
                        request.trace_id,
                    ),
                ).fetchone()
            except psycopg.Error as error:
                connection.execute("ROLLBACK")
                return error
            connection.execute("ROLLBACK")
        raise AssertionError("direct conflict reclaim unexpectedly succeeded")

    def _install_direct_context(
        self,
        connection,
        *,
        operation: str,
        organization_id=None,
    ) -> None:
        for name, value in (
            ("app.scope_kind", "DEMAND_REVIEW"),
            ("app.operation", operation),
            ("app.actor_id", str(REVIEWER_USER_ID)),
            ("app.session_id", str(REVIEWER_SESSION_ID)),
            (
                "app.organization_id",
                "" if organization_id is None else str(organization_id),
            ),
            ("app.demand_id", str(DEMAND_ID)),
        ):
            connection.execute(
                "SELECT pg_catalog.set_config(%s,%s,true)",
                (name, value),
            )

    def _claim_request(
        self,
        *,
        variant: int,
        expected_revision: int = 2,
    ) -> DemandReviewClaimRequest:
        assignment_id = ASSIGNMENT_ID if variant in {1, 2, 3} else _id(0x42000004)
        return DemandReviewClaimRequest(
            principal=self.principal,
            demand_id=DEMAND_ID,
            expected_demand_revision=expected_revision,
            assignment_id=assignment_id,
            receipt_id=_id(0x70000000 + variant),
            idempotency_key_digest_key_id="demand-idempotency-2026-01",
            idempotency_key_digest=hashlib.sha256(
                f"review-claim-idempotency-{variant}".encode()
            ).digest(),
            payload_hash_key_id="demand-payload-2026-01",
            payload_hash=hashlib.sha256(
                f"review-claim-payload-{variant}".encode()
            ).digest(),
            audit_event_id=_id(0x71000000 + variant),
            outbox_event_id=_id(0x72000000 + variant),
            correlation_id=_id(0x73000000 + variant),
            causation_id=_id(0x74000000 + variant),
            trace_id=_id(0x75000000 + variant),
        )

    def _source(self, role: str) -> TrackingDemandConnectionSource:
        source = TrackingDemandConnectionSource(
            self.postgres.conninfo(database=self.database, user=role)
        )
        self.sources.append(source)
        return source

    def _admin(self, *, autocommit: bool = True):
        return psycopg.connect(
            self.postgres.admin_conninfo(database=self.database),
            autocommit=autocommit,
        )

    def _migrate(self) -> None:
        iam_catalog = MigrationCatalog.load(IAM_ROOT)
        IamMigrationRunner(
            driver=PsycopgMigrationDriver(
                settings=PsycopgMigrationSettings(
                    conninfo=self.postgres.conninfo(
                        database=self.database,
                        user="iam_migration_runner",
                    )
                ),
                dbapi=psycopg,
            ),
            runner_version="review-queue-pg18-test/1",
        ).run(
            catalog=iam_catalog,
            contract_sources=IamContractSources(
                api_contract_bytes=(PLATFORM_ROOT / "contracts/api/iam-v1.openapi.yaml").read_bytes(),
                event_contract_bytes=(PLATFORM_ROOT / "contracts/events/iam-v1.schema.json").read_bytes(),
            ),
        )
        demand_catalog = DemandMigrationCatalog.load(DEMAND_ROOT)
        DemandMigrationRunner(
            driver=PsycopgDemandMigrationDriver(
                settings=DemandMigrationSettings(
                    conninfo=self.postgres.conninfo(
                        database=self.database,
                        user="demand_migration_runner",
                    )
                ),
                dbapi=psycopg,
            ),
            runner_version="review-queue-pg18-test/1",
        ).run(
            catalog=demand_catalog,
            contract_sources=DemandContractSources(
                api_contract_bytes=(PLATFORM_ROOT / "contracts/api/demand-v1.openapi.yaml").read_bytes(),
                event_contract_bytes=(PLATFORM_ROOT / "contracts/events/demand-v1.schema.json").read_bytes(),
                content_contract_bytes=(PLATFORM_ROOT / "contracts/domain/demand-content-v1.schema.json").read_bytes(),
            ),
        )


if __name__ == "__main__":
    unittest.main()
