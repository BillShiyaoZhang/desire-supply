"""Real PostgreSQL 18 semantic RED for Taxonomy fixed programs and RLS.

The latest IAM catalog is migrated dynamically on a real server.  Only the
exact reviewed Taxonomy behavior sentinel becomes a semantic observation;
migration, driver, fixture, SQL, ImportError, and programming defects remain
test errors.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError, dataclass, replace
from datetime import timedelta
from pathlib import Path
from typing import Any, Callable
import unittest
from unittest import mock

import psycopg

from desire_platform.identity_access.adapters.postgres.migrations import (
    IamContractSources,
    IamMigrationRunner,
    MigrationCatalog,
    PsycopgMigrationDriver,
    PsycopgMigrationSettings,
)
from desire_platform.taxonomy.adapters.postgres import (
    TAXONOMY_POSTGRES_BEHAVIOR_NOT_AVAILABLE,
    TAXONOMY_POSTGRES_PUBLISH_WRITE_CHECKPOINTS,
    TAXONOMY_POSTGRES_RETIRE_WRITE_CHECKPOINTS,
    TAXONOMY_POSTGRES_STATEMENT_PROFILES,
    PsycopgTaxonomyUnitOfWorkFactory,
    TaxonomyPostgresBehaviorNotAvailable,
    TaxonomyPostgresCommitOutcomeUnknownError,
    TaxonomyPostgresDatabaseError,
    TaxonomyPostgresOperation,
    TaxonomyPostgresSettings,
)
from desire_platform.taxonomy.adapters.postgres.migrations import (
    PsycopgTaxonomyMigrationRunner,
    TaxonomyContractSources,
    TaxonomyMigrationCatalog,
)
from tests.storage.postgres.postgres18_harness import TemporaryPostgres18
from tests.support.taxonomy_postgres_builders import (
    BUNDLE_ID,
    RAW_SECRET_SENTINELS,
    RaiseAtTaxonomyCheckpoint,
    UTC_NOW,
    TrackingTaxonomyConnectionSource,
    consumer_capture_request,
    exact_read_request,
    factory,
    inbox_request,
    publish_request,
    reset_taxonomy_database,
    retire_request,
    seed_consumer_authorization,
    seed_workload_authorizations,
    taxonomy_database_snapshot,
)


PLATFORM_ROOT = Path(__file__).resolve().parents[3]
IAM_MIGRATION_ROOT = (
    PLATFORM_ROOT
    / "src/desire_platform/identity_access/adapters/postgres/migrations"
)
TAXONOMY_MIGRATION_ROOT = (
    PLATFORM_ROOT / "src/desire_platform/taxonomy/adapters/postgres/migrations"
)


@dataclass(frozen=True)
class SemanticObservation:
    code: str
    replayed: bool = False


class RealPostgres18TaxonomySemanticRedTest(unittest.TestCase):
    """TEST-DB-TAXONOMY-CATALOG/RLS/UOW/CONSUMER-001."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.postgres = TemporaryPostgres18().start()
        cls.database = cls.postgres.create_database()
        cls.iam_catalog = MigrationCatalog.load(IAM_MIGRATION_ROOT)
        cls.iam_report = IamMigrationRunner(
            driver=PsycopgMigrationDriver(
                settings=PsycopgMigrationSettings(
                    conninfo=cls.postgres.conninfo(
                        database=cls.database,
                        user="iam_migration_runner",
                    ),
                    application_name="desire-taxonomy-pg-red",
                ),
                dbapi=psycopg,
            ),
            runner_version="taxonomy-pg-red/1",
        ).run(
            catalog=cls.iam_catalog,
            contract_sources=IamContractSources(
                api_contract_bytes=(
                    PLATFORM_ROOT / "contracts/api/iam-v1.openapi.yaml"
                ).read_bytes(),
                event_contract_bytes=(
                    PLATFORM_ROOT / "contracts/events/iam-v1.schema.json"
                ).read_bytes(),
            ),
        )
        expected_versions = tuple(
            artifact.descriptor.version
            for artifact in cls.iam_catalog.artifacts
        )
        if cls.iam_report.applied_versions != expected_versions:
            raise AssertionError("dynamic IAM catalog was not applied exactly")

        cls.taxonomy_catalog = TaxonomyMigrationCatalog.load(
            TAXONOMY_MIGRATION_ROOT
        )
        cls.taxonomy_report = PsycopgTaxonomyMigrationRunner(
            conninfo=cls.postgres.conninfo(
                database=cls.database,
                user="taxonomy_migration_runner",
            ),
            dbapi=psycopg,
            runner_version="taxonomy-pg-green/1",
        ).run(
            catalog=cls.taxonomy_catalog,
            contract_sources=TaxonomyContractSources(
                api_contract_bytes=(
                    PLATFORM_ROOT / "contracts/api/taxonomy-v1.openapi.yaml"
                ).read_bytes(),
                event_contract_bytes=(
                    PLATFORM_ROOT / "contracts/events/taxonomy-v1.schema.json"
                ).read_bytes(),
                release_contract_bytes=(
                    PLATFORM_ROOT
                    / "contracts/domain/taxonomy-release-v1.schema.json"
                ).read_bytes(),
            ),
        )

        with cls._admin_class() as connection:
            server_major, compatibility, taxonomy_schema = connection.execute(
                "SELECT "
                "current_setting('server_version_num')::integer / 10000,"
                "(SELECT ROW(current_schema_version,schema_head_version)::text "
                " FROM infra.iam_schema_compatibility),"
                "pg_catalog.to_regnamespace('taxonomy')::text"
            ).fetchone()
            ledger_versions = tuple(
                row[0]
                for row in connection.execute(
                    "SELECT version FROM infra.schema_migrations "
                    "WHERE component='iam' ORDER BY version"
                ).fetchall()
            )
        expected_head = expected_versions[-1]
        if server_major != 18:
            raise AssertionError("Taxonomy RED did not start PostgreSQL 18")
        if compatibility != f"({expected_head},{expected_head})":
            raise AssertionError("IAM compatibility is not at dynamic head")
        if ledger_versions != expected_versions:
            raise AssertionError("IAM ledger differs from dynamic catalog")
        if taxonomy_schema != "taxonomy":
            raise AssertionError("independent Taxonomy schema was not migrated")
        expected_taxonomy_versions = tuple(
            artifact.descriptor.version
            for artifact in cls.taxonomy_catalog.artifacts
        )
        if cls.taxonomy_report.applied_versions != expected_taxonomy_versions:
            raise AssertionError("Taxonomy catalog was not applied exactly")

    @classmethod
    def tearDownClass(cls) -> None:
        cls.postgres.drop_database(cls.database)
        cls.postgres.stop()

    @classmethod
    def _admin_class(cls, *, autocommit: bool = True):
        return psycopg.connect(
            cls.postgres.admin_conninfo(database=cls.database),
            autocommit=autocommit,
        )

    def setUp(self) -> None:
        self.sources: list[TrackingTaxonomyConnectionSource] = []
        with self._admin_class() as connection:
            reset_taxonomy_database(connection)
            seed_workload_authorizations(connection)

    def tearDown(self) -> None:
        for source in self.sources:
            source.close()

    def _source(
        self,
        *,
        role: str = "taxonomy_publisher",
        lose_first_commit_ack: bool = False,
        server_processed_commit: bool = True,
    ) -> TrackingTaxonomyConnectionSource:
        source = TrackingTaxonomyConnectionSource(
            self.postgres.conninfo(database=self.database, user=role),
            lose_first_commit_ack=lose_first_commit_ack,
            server_processed_commit=server_processed_commit,
        )
        self.sources.append(source)
        return source

    def _reset(self) -> None:
        with self._admin_class() as connection:
            reset_taxonomy_database(connection)
            seed_workload_authorizations(connection)

    def _seed_published(self) -> None:
        observation, result = self._semantic(
            lambda: factory(self._source()).publish(publish_request())
        )
        self.assertEqual(
            (observation.code, getattr(result, "aggregate_version", None)),
            ("ACTIVE", 1),
        )

    def _semantic(
        self, callback: Callable[[], Any]
    ) -> tuple[SemanticObservation, Any]:
        try:
            result = callback()
            return SemanticObservation(
                getattr(result, "target_status", "VALUE"),
                bool(getattr(result, "replayed", False)),
            ), result
        except TaxonomyPostgresBehaviorNotAvailable as error:
            self.assertEqual(
                str(error), TAXONOMY_POSTGRES_BEHAVIOR_NOT_AVAILABLE
            )
            return SemanticObservation("sentinel"), None
        except TaxonomyPostgresDatabaseError as error:
            return SemanticObservation(error.code), None
        except TaxonomyPostgresCommitOutcomeUnknownError as error:
            return SemanticObservation(error.code), None

    def test_default_deny_seam_is_immutable_fixed_and_zero_checkout(self) -> None:
        settings = TaxonomyPostgresSettings()
        source = self._source()
        unit_of_work = factory(source)
        request = publish_request()
        observation, _result = self._semantic(
            lambda: unit_of_work.publish(request)
        )
        self.assertEqual(observation.code, "ACTIVE")
        self.assertEqual(
            (source.checkout_count, source.release_count, source.discard_count),
            (1, 1, 0),
        )
        self.assertEqual(
            tuple(TAXONOMY_POSTGRES_STATEMENT_PROFILES),
            tuple(TaxonomyPostgresOperation),
        )
        self.assertEqual(
            tuple(
                profile.statement_budget
                for profile in TAXONOMY_POSTGRES_STATEMENT_PROFILES.values()
            ),
            (8, 6, 1, 1, 1, 2, 2),
        )
        self.assertTrue(
            all(
                len(profile.query_shape_sha256) == 64
                for profile in TAXONOMY_POSTGRES_STATEMENT_PROFILES.values()
            )
        )
        self.assertEqual(
            (
                len(TAXONOMY_POSTGRES_PUBLISH_WRITE_CHECKPOINTS),
                len(TAXONOMY_POSTGRES_RETIRE_WRITE_CHECKPOINTS),
            ),
            (13, 7),
        )
        self.assertFalse(hasattr(unit_of_work, "execute"))
        self.assertFalse(hasattr(unit_of_work, "query"))
        serialized = repr((settings, request)).lower()
        for secret in RAW_SECRET_SENTINELS:
            self.assertNotIn(secret.lower(), serialized)
        with self.assertRaises(FrozenInstanceError):
            request.expected_current_bundle_id = BUNDLE_ID  # type: ignore[misc]

    def test_independent_catalog_roles_schema_and_force_rls(self) -> None:
        with self._admin_class() as connection:
            namespace, api_namespace = connection.execute(
                "SELECT pg_catalog.to_regnamespace('taxonomy')::text,"
                "pg_catalog.to_regnamespace('taxonomy_api')::text"
            ).fetchone()
            role_rows = tuple(
                row[0]
                for row in connection.execute(
                    "SELECT rolname FROM pg_catalog.pg_roles "
                    "WHERE rolname = ANY(%s) ORDER BY rolname",
                    (
                        [
                            "taxonomy_schema_owner",
                            "taxonomy_migration_runner",
                            "taxonomy_publisher",
                            "taxonomy_admin",
                            "taxonomy_reader",
                            "taxonomy_consumer",
                        ],
                    ),
                ).fetchall()
            )
            protected = tuple(
                connection.execute(
                    "SELECT c.relname,c.relrowsecurity,c.relforcerowsecurity "
                    "FROM pg_catalog.pg_class c "
                    "JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace "
                    "WHERE n.nspname='taxonomy' AND c.relkind='r' "
                    "ORDER BY c.relname"
                ).fetchall()
            )
        expectations = (
            (
                "catalog",
                self.taxonomy_report.applied_versions,
                tuple(
                    artifact.descriptor.version
                    for artifact in self.taxonomy_catalog.artifacts
                ),
            ),
            ("schema", namespace, "taxonomy"),
            ("api_schema", api_namespace, "taxonomy_api"),
            (
                "roles",
                role_rows,
                (
                    "taxonomy_admin",
                    "taxonomy_consumer",
                    "taxonomy_migration_runner",
                    "taxonomy_publisher",
                    "taxonomy_reader",
                    "taxonomy_schema_owner",
                ),
            ),
            (
                "force_rls",
                bool(protected)
                and all(row[1:] == (True, True) for row in protected),
                True,
            ),
        )
        for name, actual, expected in expectations:
            with self.subTest(fact=name):
                self.assertEqual(actual, expected)

    def test_publish_persists_complete_release_current_audit_outbox_receipt(self) -> None:
        source = self._source()
        observation, result = self._semantic(
            lambda: factory(source).publish(publish_request())
        )
        with self._admin_class() as connection:
            snapshot = taxonomy_database_snapshot(connection)
        self.assertEqual(
            (
                observation.code,
                getattr(result, "aggregate_version", None),
                snapshot.get("schema_present"),
            ),
            ("ACTIVE", 1, True),
        )

    def test_publish_binds_exact_artifacts_signature_trust_and_two_approvals(self) -> None:
        base = publish_request()
        variants = (
            ("valid", base, "ACTIVE"),
            (
                "expired_signature",
                replace(
                    base,
                    signature=replace(
                        base.signature,
                        verified_at=base.signature.verified_at - timedelta(minutes=2),
                        valid_until=base.signature.verified_at - timedelta(minutes=1),
                    ),
                ),
                "SIGNATURE_INVALID",
            ),
            (
                "revoked_trust",
                replace(base, trust=replace(base.trust, trust_status="REVOKED")),
                "SIGNATURE_INVALID",
            ),
            (
                "revoked_approval",
                replace(
                    base,
                    approvals=(
                        replace(base.approvals[0], approval_status="REVOKED"),
                        base.approvals[1],
                    ),
                ),
                "REVIEW_APPROVAL_REQUIRED",
            ),
        )
        for name, request, expected in variants:
            with self.subTest(case=name):
                self._reset()
                observation, _result = self._semantic(
                    lambda request=request: factory(self._source()).publish(
                        request
                    )
                )
                self.assertEqual(observation.code, expected)

    def test_publish_fixture_remains_valid_after_delayed_test_collection(self) -> None:
        with mock.patch(
            "tests.support.taxonomy_postgres_builders.UTC_NOW",
            UTC_NOW - timedelta(hours=2),
        ):
            self._reset()
            self._seed_published()

    def test_release_graph_is_immutable_after_publish(self) -> None:
        observation, _result = self._semantic(
            lambda: factory(self._source()).publish(publish_request())
        )
        immutable = False
        if observation.code == "ACTIVE":
            with self._admin_class() as connection:
                before = taxonomy_database_snapshot(connection)
            with self._admin_class(autocommit=False) as connection:
                try:
                    connection.execute(
                        "UPDATE taxonomy.nodes SET definition_code="
                        "'DEFINITION.DOMAIN.CHANGED' "
                        "WHERE bundle_id=%s AND code='DOMAIN.ENERGY'",
                        (BUNDLE_ID,),
                    )
                    connection.commit()
                except psycopg.DatabaseError as error:
                    connection.rollback()
                    if error.sqlstate != "23514":
                        raise
                    with self._admin_class() as verified:
                        immutable = (
                            taxonomy_database_snapshot(verified) == before
                        )
        self.assertEqual((observation.code, immutable), ("ACTIVE", True))

    def test_exact_reader_and_force_rls_close_global_or_cross_bundle_reads(self) -> None:
        self._seed_published()
        cases = (
            (
                "bundle",
                lambda uow: uow.read_exact_bundle(
                    exact_read_request(TaxonomyPostgresOperation.READ_BUNDLE)
                ),
                "VALUE",
            ),
            (
                "node",
                lambda uow: uow.read_exact_node(
                    exact_read_request(TaxonomyPostgresOperation.READ_NODE)
                ),
                "VALUE",
            ),
            (
                "edge",
                lambda uow: uow.read_exact_edge_pair(
                    exact_read_request(
                        TaxonomyPostgresOperation.READ_EDGE_PAIR
                    )
                ),
                "VALUE",
            ),
            (
                "cross_bundle",
                lambda uow: uow.read_exact_bundle(
                    replace(
                        exact_read_request(
                            TaxonomyPostgresOperation.READ_BUNDLE
                        ),
                        bundle_id="taxonomy_bundle_9999999",
                        scope=replace(
                            exact_read_request(
                                TaxonomyPostgresOperation.READ_BUNDLE
                            ).scope,
                            bundle_id="taxonomy_bundle_9999999",
                        ),
                    )
                ),
                "RESOURCE_NOT_FOUND",
            ),
        )
        for name, callback, expected in cases:
            with self.subTest(case=name):
                unit_of_work = factory(
                    self._source(role="taxonomy_reader")
                )
                observation, _result = self._semantic(
                    lambda callback=callback, uow=unit_of_work: callback(uow)
                )
                self.assertEqual(observation.code, expected)

    def test_two_connection_selector_and_receipt_claim_concurrency(self) -> None:
        def invoke(raw_key: str) -> SemanticObservation:
            source = self._source()
            observation, _result = self._semantic(
                lambda: factory(source).publish(
                    publish_request(raw_key=raw_key)
                )
            )
            return observation

        with ThreadPoolExecutor(max_workers=2) as pool:
            same = tuple(
                pool.map(
                    lambda _index: invoke("raw-taxonomy-concurrent-same-001"),
                    range(2),
                )
            )
        with self.subTest(case="same_key"):
            self.assertEqual(
                sorted((item.code, item.replayed) for item in same),
                [("ACTIVE", False), ("ACTIVE", True)],
            )
        self._reset()
        with ThreadPoolExecutor(max_workers=2) as pool:
            different = tuple(
                pool.map(
                    invoke,
                    (
                        "raw-taxonomy-concurrent-a-001",
                        "raw-taxonomy-concurrent-b-001",
                    ),
                )
            )
        with self.subTest(case="different_key"):
            self.assertEqual(
                sorted(item.code for item in different),
                ["ACTIVE", "PRECONDITION_FAILED"],
            )

    def test_receipt_replay_conflict_and_retained_keys(self) -> None:
        source = self._source()
        unit_of_work = factory(source)
        request = publish_request()
        first, _ = self._semantic(lambda: unit_of_work.publish(request))
        replay, _ = self._semantic(lambda: unit_of_work.publish(request))
        cases = [
            (
                "replay",
                (first.code, replay.code, replay.replayed),
                ("ACTIVE", "ACTIVE", True),
            )
        ]
        changed = replace(
            request,
            receipt=replace(
                request.receipt,
                payload_digest=b"\x99" * 32,
            ),
        )
        conflict, _ = self._semantic(lambda: unit_of_work.publish(changed))
        cases.append(
            ("payload_conflict", conflict.code, "IDEMPOTENCY_KEY_REUSED")
        )
        retained = replace(
            request,
            receipt=replace(
                request.receipt,
                identity_key_id="taxonomy_identity_key_v1",
                payload_hash_key_id="taxonomy_payload_key_v1",
            ),
        )
        retained_observation, _ = self._semantic(
            lambda: unit_of_work.publish(retained)
        )
        cases.append(
            (
                "retained_keys",
                (retained_observation.code, retained_observation.replayed),
                ("ACTIVE", True),
            )
        )
        for name, actual, expected in cases:
            with self.subTest(case=name):
                self.assertEqual(actual, expected)

    def test_all_publish_and_retire_checkpoints_rollback_every_relation(self) -> None:
        for operation, checkpoints, request_factory, method_name in (
            (
                "publish",
                TAXONOMY_POSTGRES_PUBLISH_WRITE_CHECKPOINTS,
                publish_request,
                "publish",
            ),
            (
                "retire",
                TAXONOMY_POSTGRES_RETIRE_WRITE_CHECKPOINTS,
                retire_request,
                "retire",
            ),
        ):
            for checkpoint in checkpoints:
                with self.subTest(operation=operation, checkpoint=checkpoint.value):
                    self._reset()
                    if operation == "retire":
                        self._seed_published()
                    with self._admin_class() as connection:
                        before = taxonomy_database_snapshot(connection)
                    source = self._source(
                        role=(
                            "taxonomy_publisher"
                            if operation == "publish"
                            else "taxonomy_admin"
                        )
                    )
                    fault = RaiseAtTaxonomyCheckpoint(checkpoint)
                    unit_of_work = factory(source, fault=fault)
                    observation, _result = self._semantic(
                        lambda uow=unit_of_work, request=request_factory(), name=method_name: getattr(
                            uow, name
                        )(request)
                    )
                    with self._admin_class() as connection:
                        after = taxonomy_database_snapshot(connection)
                    self.assertEqual(
                        (observation.code, after == before),
                        ("SERVICE_UNAVAILABLE", True),
                    )

    def test_commit_sent_discards_and_new_connection_recovers(self) -> None:
        cases = (
            ("unknown", True, False, "COMMAND_OUTCOME_UNKNOWN"),
            ("durable_recovery", True, True, "ACTIVE"),
            ("not_durable_retry", False, True, "ACTIVE"),
        )
        for name, server_processed, recover, expected_code in cases:
            with self.subTest(case=name):
                self._reset()
                source = self._source(
                    lose_first_commit_ack=True,
                    server_processed_commit=server_processed,
                )
                first, _result = self._semantic(
                    lambda: factory(source).publish(publish_request())
                )
                self.assertEqual(first.code, "COMMAND_OUTCOME_UNKNOWN")
                observation = first
                if recover:
                    observation, _result = self._semantic(
                        lambda: factory(source).publish(publish_request())
                    )
                self.assertEqual(
                    (observation.code, source.discard_count),
                    (expected_code, 1),
                )

    def test_consumer_inbox_exact_capture_unsupported_major_and_match_privacy(self) -> None:
        cases = (
            (
                "inbox",
                lambda uow: uow.claim_consumer_inbox(inbox_request()),
                "COMPLETED",
            ),
            (
                "exact_capture",
                lambda uow: uow.capture_consumer_release(
                    consumer_capture_request()
                ),
                "VALUE",
            ),
            (
                "unsupported_major",
                lambda uow: uow.capture_consumer_release(
                    consumer_capture_request(supported_majors=(2,))
                ),
                "TAXONOMY_COMPATIBILITY_REJECTED",
            ),
            (
                "matching_closed_projection",
                lambda uow: uow.capture_consumer_release(
                    consumer_capture_request(consumer_code="MATCHING")
                ),
                "VALUE",
            ),
        )
        for name, callback, expected in cases:
            with self.subTest(case=name):
                self._reset()
                self._seed_published()
                with self._admin_class() as connection:
                    seed_consumer_authorization(
                        connection,
                        consumer_code=(
                            "MATCHING" if name != "exact_capture" else "MATCHING"
                        ),
                    )
                observation, result = self._semantic(
                    lambda callback=callback: callback(
                        factory(self._source(role="taxonomy_consumer"))
                    )
                )
                if result is not None:
                    serialized = repr(result).lower()
                    for secret in RAW_SECRET_SENTINELS:
                        self.assertNotIn(secret.lower(), serialized)
                self.assertEqual(observation.code, expected)

    def test_pool_role_and_secret_boundaries(self) -> None:
        cases = []
        self._seed_published()
        source = self._source(role="taxonomy_reader")
        observation, _ = self._semantic(
            lambda: factory(source).read_exact_bundle(
                exact_read_request(TaxonomyPostgresOperation.READ_BUNDLE)
            )
        )
        cases.append(
            (
                "scope_reset",
                (observation.code, source.release_count),
                ("VALUE", 1),
            )
        )
        self._reset()
        wrong_role = self._source(role="taxonomy_reader")
        wrong, _ = self._semantic(
            lambda: factory(wrong_role).publish(publish_request())
        )
        cases.append(
            (
                "wrong_role_discard",
                (wrong.code, wrong_role.discard_count),
                ("SERVICE_UNAVAILABLE", 1),
            )
        )
        self._reset()
        publish_source = self._source()
        published, _ = self._semantic(
            lambda: factory(publish_source).publish(publish_request())
        )
        with self._admin_class() as connection:
            serialized = repr(taxonomy_database_snapshot(connection)).lower()
        secret_free = all(
            secret.lower() not in serialized for secret in RAW_SECRET_SENTINELS
        )
        cases.append(
            (
                "database_secret_sentinel",
                (published.code, secret_free),
                ("ACTIVE", True),
            )
        )
        for name, actual, expected in cases:
            with self.subTest(case=name):
                self.assertEqual(actual, expected)
if __name__ == "__main__":
    unittest.main()
