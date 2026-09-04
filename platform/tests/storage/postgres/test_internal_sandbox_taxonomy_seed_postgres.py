"""Real PostgreSQL 18 proof for the reviewed INTERNAL_SANDBOX seed program."""

from __future__ import annotations

from pathlib import Path
from typing import Any
import unittest

import psycopg

from desire_platform.creator_profile.adapters.postgres.migrations import (
    ProfileContractSources,
    ProfileMigrationCatalog,
    PsycopgCreatorProfileMigrationRunner,
)
from desire_platform.demand.adapters.postgres.migrations import (
    DemandContractSources,
    DemandMigrationCatalog,
    DemandMigrationRunner,
    DemandMigrationSettings,
    PsycopgDemandMigrationDriver,
)
from desire_platform.deployment.migrations import DeploymentMigrationSettings
from desire_platform.deployment.synthetic_taxonomy_seed import (
    apply_internal_sandbox_taxonomy_seed,
)
from desire_platform.identity_access.adapters.postgres.migrations import (
    IamContractSources,
    IamMigrationRunner,
    MigrationCatalog,
    PsycopgMigrationDriver,
    PsycopgMigrationSettings,
)
from desire_platform.internal_pilot.synthetic_seed import (
    load_internal_sandbox_synthetic_seed,
)
from desire_platform.internal_pilot.synthetic_seed_postgres import (
    InternalSandboxSeedRuntimeMaterial,
    InternalSandboxSyntheticSeedPostgresError,
    PostgresInternalSandboxTaxonomySeedOrchestrator,
    PsycopgInternalSandboxProfileTaxonomyProjector,
    PsycopgInternalSandboxTaxonomyProvisioner,
)
from desire_platform.matching.adapters.postgres.migrations import (
    MatchingContractSources,
    MatchingMigrationCatalog,
    MatchingMigrationRunner,
    MatchingMigrationSettings,
    PsycopgMatchingMigrationDriver,
)
from desire_platform.trust_safety.adapters.postgres.migrations import (
    PsycopgTrustMigrationDriver,
    TrustContractSources,
    TrustMigrationCatalog,
    TrustMigrationRunner,
    TrustMigrationSettings,
)
from desire_platform.taxonomy.adapters.postgres.migrations import (
    PsycopgTaxonomyMigrationRunner,
    TaxonomyContractSources,
    TaxonomyMigrationCatalog,
)
from tests.storage.postgres.postgres18_harness import TemporaryPostgres18
from tests.support.creator_profile_postgres_builders import (
    TrackingProfileConnectionSource,
)
from tests.support.taxonomy_postgres_builders import (
    TrackingTaxonomyConnectionSource,
    factory,
)


PLATFORM_ROOT = Path(__file__).resolve().parents[3]
IAM_MIGRATION_ROOT = (
    PLATFORM_ROOT
    / "src/desire_platform/identity_access/adapters/postgres/migrations"
)
PROFILE_MIGRATION_ROOT = (
    PLATFORM_ROOT
    / "src/desire_platform/creator_profile/adapters/postgres/migrations"
)
DEMAND_MIGRATION_ROOT = (
    PLATFORM_ROOT / "src/desire_platform/demand/adapters/postgres/migrations"
)
MATCHING_MIGRATION_ROOT = (
    PLATFORM_ROOT / "src/desire_platform/matching/adapters/postgres/migrations"
)
TRUST_MIGRATION_ROOT = (
    PLATFORM_ROOT
    / "src/desire_platform/trust_safety/adapters/postgres/migrations"
)
TAXONOMY_MIGRATION_ROOT = (
    PLATFORM_ROOT / "src/desire_platform/taxonomy/adapters/postgres/migrations"
)
WORKLOAD_CREDENTIAL = "internal-sandbox-taxonomy-workload-credential-test-v1"
RECEIPT_HMAC_KEY = bytes(range(1, 33))


class _RaiseBeforeCommit:
    def __init__(self, stage: str) -> None:
        self.stage = stage

    def before_commit(self, stage: str) -> None:
        if stage == self.stage:
            raise RuntimeError("synthetic rollback gate")


class InternalSandboxTaxonomySeedPostgresTest(unittest.TestCase):
    """Seed authority/projection stays exact, replayable, and offline-only."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.postgres = TemporaryPostgres18().start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.postgres.stop()

    def setUp(self) -> None:
        self.database = self.postgres.create_database()
        self.sources: list[Any] = []
        self._migrate()
        self.plan = load_internal_sandbox_synthetic_seed()
        self.runtime = InternalSandboxSeedRuntimeMaterial(
            deployment_mode="INTERNAL_SANDBOX",
            workload_credential_id=WORKLOAD_CREDENTIAL,
            receipt_hmac_key=RECEIPT_HMAC_KEY,
        )

    def tearDown(self) -> None:
        for source in self.sources:
            source.close()
        self.postgres.drop_database(self.database)

    def _migrate(self) -> None:
        iam_catalog = MigrationCatalog.load(IAM_MIGRATION_ROOT)
        iam_report = IamMigrationRunner(
            driver=PsycopgMigrationDriver(
                settings=PsycopgMigrationSettings(
                    conninfo=self.postgres.conninfo(
                        database=self.database,
                        user="iam_migration_runner",
                    ),
                    application_name="internal-sandbox-seed-pg-test",
                ),
                dbapi=psycopg,
            ),
            runner_version="internal-sandbox-seed-pg-test/1",
        ).run(
            catalog=iam_catalog,
            contract_sources=IamContractSources(
                api_contract_bytes=(
                    PLATFORM_ROOT / "contracts/api/iam-v1.openapi.yaml"
                ).read_bytes(),
                event_contract_bytes=(
                    PLATFORM_ROOT / "contracts/events/iam-v1.schema.json"
                ).read_bytes(),
            ),
        )
        self.assertEqual(
            iam_report.applied_versions,
            tuple(item.descriptor.version for item in iam_catalog.artifacts),
        )

        taxonomy_catalog = TaxonomyMigrationCatalog.load(
            TAXONOMY_MIGRATION_ROOT
        )
        taxonomy_report = PsycopgTaxonomyMigrationRunner(
            conninfo=self.postgres.conninfo(
                database=self.database,
                user="taxonomy_migration_runner",
            ),
            dbapi=psycopg,
            runner_version="internal-sandbox-seed-pg-test/1",
        ).run(
            catalog=taxonomy_catalog,
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
        self.assertEqual(
            taxonomy_report.applied_versions,
            tuple(
                item.descriptor.version
                for item in taxonomy_catalog.artifacts
            ),
        )

        profile_catalog = ProfileMigrationCatalog.load(PROFILE_MIGRATION_ROOT)
        profile_report = PsycopgCreatorProfileMigrationRunner(
            conninfo=self.postgres.conninfo(
                database=self.database,
                user="profile_migration_runner",
            ),
            dbapi=psycopg,
            runner_version="internal-sandbox-seed-pg-test/1",
        ).run(
            catalog=profile_catalog,
            contract_sources=ProfileContractSources(
                api_contract_bytes=(
                    PLATFORM_ROOT / "contracts/api/profile-v1.openapi.yaml"
                ).read_bytes(),
                event_contract_bytes=(
                    PLATFORM_ROOT / "contracts/events/profile-v1.schema.json"
                ).read_bytes(),
                domain_contract_bytes=(
                    PLATFORM_ROOT
                    / "contracts/domain/profile-version-v1.schema.json"
                ).read_bytes(),
            ),
        )
        self.assertEqual(
            profile_report.applied_versions,
            tuple(item.descriptor.version for item in profile_catalog.artifacts),
        )

        demand_catalog = DemandMigrationCatalog.load(DEMAND_MIGRATION_ROOT)
        demand_report = DemandMigrationRunner(
            driver=PsycopgDemandMigrationDriver(
                settings=DemandMigrationSettings(
                    conninfo=self.postgres.conninfo(
                        database=self.database,
                        user="demand_migration_runner",
                    ),
                    application_name="internal-sandbox-seed-pg-test",
                ),
                dbapi=psycopg,
            ),
            runner_version="internal-sandbox-seed-pg-test/1",
        ).run(
            catalog=demand_catalog,
            contract_sources=DemandContractSources(
                api_contract_bytes=(
                    PLATFORM_ROOT / "contracts/api/demand-v1.openapi.yaml"
                ).read_bytes(),
                event_contract_bytes=(
                    PLATFORM_ROOT / "contracts/events/demand-v1.schema.json"
                ).read_bytes(),
                content_contract_bytes=(
                    PLATFORM_ROOT
                    / "contracts/domain/demand-content-v1.schema.json"
                ).read_bytes(),
            ),
        )
        self.assertEqual(
            demand_report.applied_versions,
            tuple(item.descriptor.version for item in demand_catalog.artifacts),
        )

        with psycopg.connect(
            self.postgres.admin_conninfo(database="postgres"),
            autocommit=True,
        ) as connection:
            connection.execute(
                f'GRANT CREATE ON DATABASE "{self.database}" '
                "TO trust_schema_owner"
            )
            connection.execute(
                "GRANT trust_schema_owner TO trust_migration_runner "
                "WITH INHERIT FALSE, SET TRUE"
            )
            connection.execute(
                "GRANT schema_owner TO trust_migration_runner "
                "WITH INHERIT FALSE, SET TRUE"
            )
        trust_catalog = TrustMigrationCatalog.load(TRUST_MIGRATION_ROOT)
        trust_report = TrustMigrationRunner(
            driver=PsycopgTrustMigrationDriver(
                settings=TrustMigrationSettings(
                    conninfo=self.postgres.conninfo(
                        database=self.database,
                        user="trust_migration_runner",
                    ),
                    application_name="internal-sandbox-seed-pg-test",
                ),
                dbapi=psycopg,
            ),
            runner_version="internal-sandbox-seed-pg-test/1",
        ).run(
            catalog=trust_catalog,
            contract_sources=TrustContractSources(
                api_contract_bytes=(
                    PLATFORM_ROOT / "contracts/api/trust-v1.openapi.yaml"
                ).read_bytes(),
                event_contract_bytes=(
                    PLATFORM_ROOT / "contracts/events/trust-v1.schema.json"
                ).read_bytes(),
                report_contract_bytes=(
                    PLATFORM_ROOT
                    / "contracts/domain/trust-report-v1.schema.json"
                ).read_bytes(),
                triage_contract_bytes=(
                    PLATFORM_ROOT
                    / "contracts/domain/trust-triage-v1.schema.json"
                ).read_bytes(),
                appeal_api_contract_bytes=(
                    PLATFORM_ROOT / "contracts/api/appeal-v1.openapi.yaml"
                ).read_bytes(),
                appeal_event_contract_bytes=(
                    PLATFORM_ROOT
                    / "contracts/events/appeal-v1.schema.json"
                ).read_bytes(),
                appeal_application_contract_bytes=(
                    PLATFORM_ROOT
                    / "contracts/domain/appeal-application-v1.schema.json"
                ).read_bytes(),
                appeal_review_contract_bytes=(
                    PLATFORM_ROOT
                    / "contracts/domain/appeal-review-v1.schema.json"
                ).read_bytes(),
            ),
        )
        self.assertEqual(
            trust_report.applied_versions,
            tuple(item.descriptor.version for item in trust_catalog.artifacts),
        )

        matching_catalog = MatchingMigrationCatalog.load(MATCHING_MIGRATION_ROOT)
        matching_report = MatchingMigrationRunner(
            driver=PsycopgMatchingMigrationDriver(
                settings=MatchingMigrationSettings(
                    conninfo=self.postgres.conninfo(
                        database=self.database,
                        user="matching_migration_runner",
                    ),
                    application_name="internal-sandbox-seed-pg-test",
                ),
                dbapi=psycopg,
            ),
            runner_version="internal-sandbox-seed-pg-test/1",
        ).run(
            catalog=matching_catalog,
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
        self.assertEqual(
            matching_report.applied_versions,
            tuple(item.descriptor.version for item in matching_catalog.artifacts),
        )

    def _source(self, role: str) -> TrackingTaxonomyConnectionSource:
        source = TrackingTaxonomyConnectionSource(
            self.postgres.conninfo(database=self.database, user=role)
        )
        self.sources.append(source)
        return source

    def _profile_source(self) -> TrackingProfileConnectionSource:
        source = TrackingProfileConnectionSource(
            self.postgres.conninfo(
                database=self.database,
                user="profile_migration_runner",
            )
        )
        self.sources.append(source)
        return source

    def _orchestrator(
        self,
        *,
        provision_fault: Any = None,
        projection_fault: Any = None,
    ) -> PostgresInternalSandboxTaxonomySeedOrchestrator:
        return PostgresInternalSandboxTaxonomySeedOrchestrator(
            provisioner=PsycopgInternalSandboxTaxonomyProvisioner(
                connections=self._source("taxonomy_migration_runner"),
                fault_injector=provision_fault,
            )
            if provision_fault is not None
            else PsycopgInternalSandboxTaxonomyProvisioner(
                connections=self._source("taxonomy_migration_runner")
            ),
            publisher=factory(self._source("taxonomy_publisher")),
            consumer=factory(self._source("taxonomy_consumer")),
            profile_projector=PsycopgInternalSandboxProfileTaxonomyProjector(
                connections=self._profile_source(),
                fault_injector=projection_fault,
            )
            if projection_fault is not None
            else PsycopgInternalSandboxProfileTaxonomyProjector(
                connections=self._profile_source()
            ),
        )

    def _admin(self):
        return psycopg.connect(
            self.postgres.admin_conninfo(database=self.database),
            autocommit=True,
        )

    def test_formal_publish_capture_apply_is_exact_and_idempotent(self) -> None:
        orchestrator = self._orchestrator()

        with psycopg.connect(
            self.postgres.conninfo(
                database=self.database,
                user="profile_app",
            ),
            autocommit=True,
        ) as profile_app:
            self.assertEqual(
                profile_app.execute(
                    "SELECT profile_api."
                    "internal_sandbox_taxonomy_seed_ready_v1()"
                ).fetchone(),
                (False,),
            )

        first = orchestrator.run(plan=self.plan, runtime=self.runtime)
        second = orchestrator.run(plan=self.plan, runtime=self.runtime)

        with psycopg.connect(
            self.postgres.conninfo(
                database=self.database,
                user="profile_app",
            ),
            autocommit=True,
        ) as profile_app:
            self.assertEqual(
                profile_app.execute(
                    "SELECT profile_api."
                    "internal_sandbox_taxonomy_seed_ready_v1()"
                ).fetchone(),
                (True,),
            )

        self.assertEqual(
            (
                first.workload_authority_created,
                first.publication_replayed,
                first.consumer_authority_created,
                first.consumer_inbox_replayed,
                first.profile_marker_created,
            ),
            (True, False, True, False, True),
        )
        self.assertEqual(
            (
                second.workload_authority_created,
                second.publication_replayed,
                second.consumer_authority_created,
                second.consumer_inbox_replayed,
                second.profile_marker_created,
            ),
            (False, True, False, True, False),
        )
        with self._admin() as connection:
            facts = connection.execute(
                "SELECT "
                "(SELECT count(*) FROM taxonomy.workload_authorizations),"
                "(SELECT count(*) FROM taxonomy.consumer_authorizations),"
                "(SELECT count(*) FROM taxonomy.bundles "
                " WHERE status='ACTIVE'),"
                "(SELECT count(*) FROM taxonomy.command_receipts "
                " WHERE operation='PublishTaxonomyBundle' "
                " AND status='COMPLETED'),"
                "(SELECT count(*) FROM taxonomy.outbox_events "
                " WHERE event_type='TaxonomyBundlePublished'),"
                "(SELECT count(*) FROM taxonomy.consumer_inbox "
                " WHERE status='COMPLETED'),"
                "(SELECT count(*) FROM profile.taxonomy_bundle_markers "
                " WHERE status='ACTIVE'),"
                "(SELECT count(*) FROM profile.taxonomy_projection_inbox "
                " WHERE status='COMPLETED'),"
                "(SELECT count(*) FROM profile.creator_profiles)"
            ).fetchone()
        self.assertEqual(facts, (1, 1, 1, 1, 1, 1, 1, 1, 0))

    def test_drift_is_rejected_without_creating_a_second_projection(self) -> None:
        orchestrator = self._orchestrator()
        orchestrator.run(plan=self.plan, runtime=self.runtime)
        with self._admin() as connection:
            connection.execute(
                "UPDATE profile.taxonomy_bundle_markers "
                "SET bundle_sha256=%s WHERE id=%s",
                (b"d" * 32, self.plan.taxonomy_bundle_id),
            )

        with self.assertRaises(InternalSandboxSyntheticSeedPostgresError):
            orchestrator.run(plan=self.plan, runtime=self.runtime)

        with self._admin() as connection:
            facts = connection.execute(
                "SELECT "
                "(SELECT count(*) FROM profile.taxonomy_bundle_markers),"
                "(SELECT count(*) FROM profile.taxonomy_projection_inbox),"
                "(SELECT count(*) FROM taxonomy.bundles),"
                "(SELECT count(*) FROM taxonomy.command_receipts)"
            ).fetchone()
        self.assertEqual(facts, (1, 1, 1, 1))

    def test_non_seed_roles_cannot_call_provision_or_projection_programs(self) -> None:
        checks = (
            (
                "taxonomy_publisher",
                "taxonomy_api.provision_internal_sandbox_workload_v1("
                "text,bytea,text,text,bytea,bytea,timestamptz)",
            ),
            (
                "profile_app",
                "profile_api.project_internal_sandbox_taxonomy_marker_v1("
                "text,bytea,text,bytea,uuid,bytea,bigint,timestamptz)",
            ),
            (
                "profile_matcher",
                "profile_api.internal_sandbox_taxonomy_seed_ready_v1()",
            ),
            (
                "profile_migration_runner",
                "profile_api.internal_sandbox_taxonomy_seed_ready_v1()",
            ),
        )
        with self._admin() as connection:
            actual = tuple(
                connection.execute(
                    "SELECT pg_catalog.has_function_privilege(%s,%s,'EXECUTE')",
                    (role, signature),
                ).fetchone()[0]
                for role, signature in checks
            )
        self.assertEqual(actual, (False, False, False, False))

    def test_fault_before_commit_rolls_back_authority_and_projection(self) -> None:
        with self.assertRaises(InternalSandboxSyntheticSeedPostgresError):
            self._orchestrator(
                provision_fault=_RaiseBeforeCommit("PROVISION_WORKLOAD")
            ).run(plan=self.plan, runtime=self.runtime)
        with self._admin() as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT count(*) FROM taxonomy.workload_authorizations"
                ).fetchone(),
                (0,),
            )

        with self.assertRaises(InternalSandboxSyntheticSeedPostgresError):
            self._orchestrator(
                projection_fault=_RaiseBeforeCommit(
                    "PROJECT_PROFILE_TAXONOMY"
                )
            ).run(plan=self.plan, runtime=self.runtime)
        with self._admin() as connection:
            profile_facts = connection.execute(
                "SELECT "
                "(SELECT count(*) FROM profile.taxonomy_bundle_markers),"
                "(SELECT count(*) FROM profile.taxonomy_projection_inbox)"
            ).fetchone()
        self.assertEqual(profile_facts, (0, 0))

    def test_deployment_program_revokes_all_temporary_role_credentials(self) -> None:
        password_counter = iter(range(4))
        result = apply_internal_sandbox_taxonomy_seed(
            settings=DeploymentMigrationSettings(
                host=self.postgres.host,
                port=self.postgres.port,
                database=self.database,
                admin_user=self.postgres.admin_user,
                admin_password=self.postgres.admin_password,
            ),
            runtime=self.runtime,
            plan=self.plan,
            password_factory=lambda: (
                "temporary-seed-role-password-material-%02d"
                % next(password_counter)
            ),
        )

        self.assertEqual(result.taxonomy_bundle_id, self.plan.taxonomy_bundle_id)
        with self._admin() as connection:
            credentials = tuple(
                connection.execute(
                    "SELECT rolpassword,rolvaliduntil::text "
                    "FROM pg_catalog.pg_authid "
                    "WHERE rolname=ANY(%s) ORDER BY rolname",
                    (
                        [
                            "taxonomy_migration_runner",
                            "taxonomy_publisher",
                            "taxonomy_consumer",
                            "profile_migration_runner",
                        ],
                    ),
                ).fetchall()
            )
        self.assertEqual(credentials, ((None, "infinity"),) * 4)


if __name__ == "__main__":
    unittest.main()
