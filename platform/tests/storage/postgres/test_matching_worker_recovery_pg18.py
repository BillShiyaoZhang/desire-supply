"""Real PG18 behavior gates for targetless Matching worker recovery."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
import unittest
from uuid import uuid4

import psycopg

from desire_platform.identity_access.adapters.postgres.migrations import (
    IamContractSources,
    IamMigrationRunner,
    MigrationCatalog,
    PsycopgMigrationDriver,
    PsycopgMigrationSettings,
)
from desire_platform.matching.adapters.postgres.migrations import (
    MatchingContractSources,
    MatchingMigrationCatalog,
    MatchingMigrationRunner,
    MatchingMigrationSettings,
    PsycopgMatchingMigrationDriver,
)
from tests.storage.postgres.postgres18_harness import TemporaryPostgres18
from tests.support.matching_postgres_dependencies import (
    install_matching_runtime_dependencies,
)


PLATFORM_ROOT = Path(__file__).resolve().parents[3]
IAM_ROOT = (
    PLATFORM_ROOT
    / "src/desire_platform/identity_access/adapters/postgres/migrations"
)
MATCHING_ROOT = (
    PLATFORM_ROOT / "src/desire_platform/matching/adapters/postgres/migrations"
)
WORKLOAD_ID = uuid4()
RULE_ID = uuid4()
MARKER = bytes.fromhex("ab" * 32)
OTHER_MARKER = bytes.fromhex("cd" * 32)
HASH = bytes.fromhex("11" * 32)
OLD_LEASE = bytes.fromhex("22" * 32)


class MatchingWorkerRecoveryPostgres18Test(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.postgres = TemporaryPostgres18().start()
        cls.database = cls.postgres.create_database()
        IamMigrationRunner(
            driver=PsycopgMigrationDriver(
                settings=PsycopgMigrationSettings(
                    conninfo=cls.postgres.conninfo(
                        database=cls.database,
                        user="iam_migration_runner",
                    ),
                    application_name="matching-worker-recovery-iam",
                ),
                dbapi=psycopg,
            ),
            runner_version="matching-worker-recovery-iam/1",
        ).run(
            catalog=MigrationCatalog.load(IAM_ROOT),
            contract_sources=IamContractSources(
                api_contract_bytes=(
                    PLATFORM_ROOT / "contracts/api/iam-v1.openapi.yaml"
                ).read_bytes(),
                event_contract_bytes=(
                    PLATFORM_ROOT / "contracts/events/iam-v1.schema.json"
                ).read_bytes(),
            ),
        )
        install_matching_runtime_dependencies(
            postgres=cls.postgres,
            database=cls.database,
            platform_root=PLATFORM_ROOT,
        )
        MatchingMigrationRunner(
            driver=PsycopgMatchingMigrationDriver(
                settings=MatchingMigrationSettings(
                    conninfo=cls.postgres.conninfo(
                        database=cls.database,
                        user="matching_migration_runner",
                    ),
                    application_name="matching-worker-recovery-v2",
                ),
                dbapi=psycopg,
            ),
            runner_version="matching-worker-recovery-v2/1",
        ).run(
            catalog=MatchingMigrationCatalog.load(MATCHING_ROOT),
            contract_sources=MatchingContractSources(
                api_contract_bytes=(
                    PLATFORM_ROOT / "contracts/api/matching-v1.openapi.yaml"
                ).read_bytes(),
                event_contract_bytes=(
                    PLATFORM_ROOT / "contracts/events/matching-v1.schema.json"
                ).read_bytes(),
                rule_contract_bytes=(
                    PLATFORM_ROOT
                    / "contracts/domain/matching-rule-release-v1.schema.json"
                ).read_bytes(),
                input_manifest_contract_bytes=(
                    PLATFORM_ROOT
                    / "contracts/domain/match-input-manifest-v1.schema.json"
                ).read_bytes(),
                run_input_contract_bytes=(
                    PLATFORM_ROOT
                    / "contracts/domain/match-run-input-v1.schema.json"
                ).read_bytes(),
                candidate_contract_bytes=(
                    PLATFORM_ROOT
                    / "contracts/domain/match-candidate-result-v1.schema.json"
                ).read_bytes(),
                disclosure_contract_bytes=(
                    PLATFORM_ROOT
                    / "contracts/domain/invitation-disclosure-v1.schema.json"
                ).read_bytes(),
            ),
        )
    @classmethod
    def tearDownClass(cls) -> None:
        try:
            cls.postgres.drop_database(cls.database)
        finally:
            cls.postgres.stop()

    @classmethod
    def _admin(cls, *, autocommit: bool = False):
        return psycopg.connect(
            cls.postgres.admin_conninfo(database=cls.database),
            autocommit=autocommit,
        )

    def setUp(self) -> None:
        now = datetime.now(timezone.utc)
        with self._admin() as connection:
            connection.execute("TRUNCATE matching.rule_bundles CASCADE")
            connection.execute(
                "INSERT INTO matching.rule_bundles ("
                "id,semantic_version,status,selector_digest,jurisdiction_code,"
                "locale,demand_type_code,taxonomy_family_code,engine_identifier,"
                "engine_major,engine_artifact_sha256,taxonomy_bundle_id,"
                "budget_rule_version,matching_rule_version,reason_code_version,"
                "explanation_template_version,canonical_manifest_sha256,"
                "signature_key_id,review_approval_id,review_approval_version,"
                "effective_at,effective_until,published_by_workload_id,"
                "published_authority_marker_sha256,created_at,updated_at) "
                "VALUES (%s,'1.0.0','ACTIVE',%s,'CN','zh-CN','STANDARD',"
                "'GENERAL','deterministic-matcher-v1',1,%s,%s,'budget-v1',"
                "'matching-v1','reason-v1','explanation-v1',%s,'test-key',"
                "%s,1,%s,%s,%s,%s,%s,%s)",
                (
                    RULE_ID,
                    HASH,
                    HASH,
                    uuid4(),
                    HASH,
                    uuid4(),
                    now - timedelta(days=1),
                    now + timedelta(days=1),
                    WORKLOAD_ID,
                    MARKER,
                    now,
                    now,
                ),
            )

    def _seed_graph(
        self,
        connection,
        *,
        organization_id,
        run_no: int = 1,
        run_status: str = "QUEUED",
        job_status: str = "AVAILABLE",
        marker: bytes = MARKER,
        fence: int = 0,
        attempt_count: int = 0,
        eligible_at: datetime,
    ) -> dict[str, object]:
        now = datetime.now(timezone.utc)
        attempt_id = uuid4()
        run_id = uuid4()
        selection_id = uuid4()
        job_id = uuid4()
        demand_id = uuid4()
        connection.execute("SET CONSTRAINTS ALL DEFERRED")
        connection.execute(
            "INSERT INTO matching.matching_attempts ("
            "id,organization_id,demand_id,demand_version_id,"
            "demand_content_sha256,demand_aggregate_version,matching_request_id,"
            "matching_request_version,funding_id,composite_rule_requirement_id,"
            "matching_rule_bundle_id,selector_digest,source_event_id,attempt_no,"
            "status,aggregate_version,current_match_run_id,selection_id,"
            "input_baseline_sha256,system_workload_id,"
            "system_authority_marker_sha256,created_at,updated_at,terminal_at) "
            "VALUES (%s,%s,%s,%s,%s,1,%s,1,%s,%s,%s,%s,%s,1,'OPEN',1,%s,"
            "NULL,%s,%s,%s,%s,%s,NULL)",
            (
                attempt_id,
                organization_id,
                demand_id,
                uuid4(),
                HASH,
                uuid4(),
                uuid4(),
                uuid4(),
                RULE_ID,
                HASH,
                uuid4(),
                run_id,
                HASH,
                WORKLOAD_ID,
                MARKER,
                now,
                now,
            ),
        )
        running = run_status == "RUNNING"
        connection.execute(
            "INSERT INTO matching.match_runs ("
            "id,organization_id,attempt_id,demand_id,run_no,status,"
            "aggregate_version,matching_rule_bundle_id,input_manifest_sha256,"
            "input_set_sha256,ordered_result_sha256,candidate_count,"
            "eligible_count,excluded_count,worker_id,lease_token_digest_key_id,"
            "lease_token_digest,fencing_generation,lease_until,supersedes_run_id,"
            "superseded_by_run_id,failure_code,created_at,updated_at) VALUES ("
            "%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,NULL,NULL,NULL,NULL,%s,%s,%s,%s,"
            "%s,NULL,NULL,NULL,%s,%s)",
            (
                run_id,
                organization_id,
                attempt_id,
                demand_id,
                run_no,
                run_status,
                2 if running else 1,
                RULE_ID,
                HASH if running else None,
                HASH if running else None,
                WORKLOAD_ID if running else None,
                "old-lease-v1" if running else None,
                OLD_LEASE if running else None,
                fence if running else 0,
                eligible_at if running else None,
                now,
                now,
            ),
        )
        connection.execute(
            "INSERT INTO matching.selections ("
            "id,organization_id,attempt_id,match_run_id,status,aggregate_version,"
            "current_invitation_set_sha256,chosen_invitation_id,"
            "chosen_invitation_status,selection_basis_code,reason_code,"
            "decision_actor_id,coordinator_workload_id,"
            "coordinator_authority_marker_sha256,created_at,updated_at) VALUES ("
            "%s,%s,%s,%s,'OPEN',1,%s,NULL,NULL,NULL,NULL,NULL,%s,%s,%s,%s)",
            (
                selection_id,
                organization_id,
                attempt_id,
                run_id,
                HASH,
                WORKLOAD_ID,
                MARKER,
                now,
                now,
            ),
        )
        connection.execute(
            "UPDATE matching.matching_attempts SET selection_id=%s WHERE id=%s",
            (selection_id, attempt_id),
        )
        leased = job_status == "LEASED"
        connection.execute(
            "INSERT INTO matching.match_jobs ("
            "id,organization_id,attempt_id,match_run_id,job_kind,status,"
            "workload_id,authority_marker_sha256,lease_token_digest_key_id,"
            "lease_token_digest,fencing_generation,available_at,lease_until,"
            "attempt_count,created_at,completed_at) VALUES ("
            "%s,%s,%s,%s,'RUN_MATCH',%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,NULL)",
            (
                job_id,
                organization_id,
                attempt_id,
                run_id,
                job_status,
                WORKLOAD_ID,
                marker,
                "old-lease-v1" if leased else None,
                OLD_LEASE if leased else None,
                fence,
                eligible_at,
                eligible_at if leased else None,
                attempt_count,
                now,
            ),
        )
        return {
            "organization_id": organization_id,
            "attempt_id": attempt_id,
            "run_id": run_id,
            "selection_id": selection_id,
            "job_id": job_id,
        }

    def _claim(self, *, identity: bytes, lease: bytes = HASH):
        ids = [uuid4() for _ in range(5)]
        with psycopg.connect(
            self.postgres.conninfo(
                database=self.database,
                user="matching_worker",
            )
        ) as connection:
            for key, value in (
                ("app.scope_kind", "MATCHING_WORKER"),
                ("app.operation", "CLAIM_MATCH_JOB"),
                ("app.workload_id", str(WORKLOAD_ID)),
                ("app.authority_marker_sha256", MARKER.hex()),
                ("app.command_id", str(ids[1])),
                ("app.lease_token_digest_key_id", "lease-v1"),
                ("app.lease_token_digest", lease.hex()),
            ):
                connection.execute("SELECT set_config(%s,%s,true)", (key, value))
            return connection.execute(
                "SELECT safe_projection,replayed FROM "
                "matching_api.claim_match_job_v1("
                "%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                (
                    WORKLOAD_ID,
                    MARKER,
                    "lease-v1",
                    lease,
                    60,
                    ids[0],
                    ids[1],
                    "identity-v1",
                    identity,
                    "payload-v1",
                    identity,
                    ids[2],
                    ids[3],
                    ids[4],
                    uuid4(),
                ),
            ).fetchone()

    def test_targetless_claim_orders_globally_and_recovers_queued_lease(self) -> None:
        now = datetime.now(timezone.utc)
        with self._admin() as connection:
            self._seed_graph(
                connection,
                organization_id=uuid4(),
                marker=OTHER_MARKER,
                eligible_at=now - timedelta(minutes=30),
            )
            expected = self._seed_graph(
                connection,
                organization_id=uuid4(),
                eligible_at=now - timedelta(minutes=20),
            )
            self._seed_graph(
                connection,
                organization_id=uuid4(),
                eligible_at=now - timedelta(minutes=10),
            )

        claimed = self._claim(identity=bytes.fromhex("31" * 32))
        self.assertIsNotNone(claimed)
        projection, replayed = claimed
        self.assertFalse(replayed)
        self.assertEqual(projection["job_id"], str(expected["job_id"]))
        self.assertEqual(
            projection["organization_id"], str(expected["organization_id"])
        )
        replay_projection, replayed = self._claim(
            identity=bytes.fromhex("31" * 32)
        )
        self.assertTrue(replayed)
        self.assertEqual(replay_projection, projection)

        with psycopg.connect(
            self.postgres.conninfo(
                database=self.database,
                user="matching_worker",
            )
        ) as connection:
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                connection.execute("SELECT id FROM matching.match_jobs")

        with self._admin() as connection:
            connection.execute("TRUNCATE matching.rule_bundles CASCADE")
        self.setUp()
        with self._admin() as connection:
            queued = self._seed_graph(
                connection,
                organization_id=uuid4(),
                job_status="LEASED",
                fence=4,
                attempt_count=2,
                eligible_at=now - timedelta(minutes=1),
            )
        recovered, replayed = self._claim(identity=bytes.fromhex("32" * 32))
        self.assertFalse(replayed)
        self.assertEqual(recovered["job_id"], str(queued["job_id"]))
        self.assertEqual(recovered["fencing_generation"], 5)
        self.assertEqual(recovered["attempt_count"], 3)
        self.assertEqual(recovered["recovery_status"], "QUEUED_LEASE_RECOVERED")

    def test_running_lease_retries_are_bounded_and_review_required_is_durable(
        self,
    ) -> None:
        expired = datetime.now(timezone.utc) - timedelta(minutes=1)
        with self._admin() as connection:
            initial = self._seed_graph(
                connection,
                organization_id=uuid4(),
                run_status="RUNNING",
                job_status="LEASED",
                fence=1,
                attempt_count=1,
                eligible_at=expired,
            )

        first, _ = self._claim(identity=bytes.fromhex("41" * 32))
        self.assertEqual(first["recovery_status"], "RUNNING_LEASE_RETRY_LEASED")
        self.assertEqual(first["run_attempt"], 2)
        self.assertNotEqual(first["match_run_id"], str(initial["run_id"]))

        def expire_current(projection) -> None:
            with self._admin() as connection:
                connection.execute(
                    "UPDATE matching.match_runs SET status='RUNNING',"
                    "aggregate_version=2,input_manifest_sha256=%s,"
                    "input_set_sha256=%s,worker_id=%s,"
                    "lease_token_digest_key_id='lease-v1',"
                    "lease_token_digest=%s,fencing_generation=1,"
                    "lease_until=%s,updated_at=transaction_timestamp() "
                    "WHERE id=%s",
                    (
                        HASH,
                        HASH,
                        WORKLOAD_ID,
                        HASH,
                        expired,
                        projection["match_run_id"],
                    ),
                )
                connection.execute(
                    "UPDATE matching.match_jobs SET lease_until=%s WHERE id=%s",
                    (expired, projection["job_id"]),
                )

        expire_current(first)
        first, _ = self._claim(identity=bytes.fromhex("42" * 32))
        self.assertEqual(first["run_attempt"], 3)
        self.assertEqual(first["recovery_status"], "RUNNING_LEASE_RETRY_LEASED")
        expire_current(first)
        first, _ = self._claim(identity=bytes.fromhex("43" * 32))

        self.assertEqual(first["status"], "FAILED")
        self.assertEqual(first["run_attempt"], 3)
        self.assertEqual(first["recovery_status"], "REVIEW_REQUIRED")
        with self._admin() as connection:
            run_count = connection.execute(
                "SELECT count(*) FROM matching.match_runs WHERE attempt_id=%s",
                (initial["attempt_id"],),
            ).fetchone()[0]
            receipt_status = connection.execute(
                "SELECT result_status FROM matching.command_receipts "
                "WHERE identity_digest=%s",
                (bytes.fromhex("43" * 32),),
            ).fetchone()[0]
            self.assertEqual(run_count, 3)
            self.assertEqual(receipt_status, "REVIEW_REQUIRED")


if __name__ == "__main__":
    unittest.main()
