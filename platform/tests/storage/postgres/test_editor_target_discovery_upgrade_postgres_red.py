"""PostgreSQL 18 upgrade/RLS proof for editor target discovery v2."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
from typing import Any
from uuid import UUID
import unittest

import psycopg

from desire_platform.creator_profile.adapters.postgres.migrations import (
    ProfileContractSources,
    ProfileMigrationCatalog,
    ProfileMigrationRunnerError,
    PsycopgCreatorProfileMigrationRunner,
)
from desire_platform.demand.adapters.postgres import DemandPostgresOperation
from desire_platform.demand.adapters.postgres.migrations import (
    DemandContractSources,
    DemandMigrationCatalog,
    DemandMigrationRunner,
    DemandMigrationRunnerError,
    DemandMigrationSettings,
    PsycopgDemandMigrationDriver,
)
from desire_platform.identity_access.adapters.postgres.migrations import (
    IamContractSources,
    IamMigrationRunner,
    MigrationCatalog,
    PsycopgMigrationDriver,
    PsycopgMigrationSettings,
)
from tests.storage.postgres.postgres18_harness import TemporaryPostgres18
from tests.support.creator_profile_postgres_builders import (
    ACTOR_USER_ID as PROFILE_ACTOR_ID,
    PROFILE_ID,
    SESSION_ID as PROFILE_SESSION_ID,
    seed_exact_creator_iam_authority,
)
from tests.support.demand_postgres_builders import (
    ACTOR_USER_ID as DEMAND_ACTOR_ID,
    ASSIGNMENT_ID,
    DEMAND_ID,
    ORGANIZATION_ID,
    REVIEWER_SESSION_ID,
    REVIEWER_USER_ID,
    seed_demand_operation_graph,
    seed_exact_demand_owner_iam_authority,
)


PLATFORM_ROOT = Path(__file__).resolve().parents[3]
IAM_ROOT = (
    PLATFORM_ROOT
    / "src/desire_platform/identity_access/adapters/postgres/migrations"
)
PROFILE_ROOT = (
    PLATFORM_ROOT
    / "src/desire_platform/creator_profile/adapters/postgres/migrations"
)
DEMAND_ROOT = (
    PLATFORM_ROOT
    / "src/desire_platform/demand/adapters/postgres/migrations"
)


class RealPostgres18EditorTargetDiscoveryUpgradeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.postgres = TemporaryPostgres18().start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.postgres.stop()

    def setUp(self) -> None:
        self.database = self.postgres.create_database()
        self._migrate_iam()

    def tearDown(self) -> None:
        self.postgres.drop_database(self.database)

    def _admin(self, *, autocommit: bool = True):
        return psycopg.connect(
            self.postgres.admin_conninfo(database=self.database),
            autocommit=autocommit,
        )

    def _migrate_iam(self) -> None:
        catalog = MigrationCatalog.load(IAM_ROOT)
        report = IamMigrationRunner(
            driver=PsycopgMigrationDriver(
                settings=PsycopgMigrationSettings(
                    conninfo=self.postgres.conninfo(
                        database=self.database,
                        user="iam_migration_runner",
                    ),
                    application_name="editor-target-upgrade-iam",
                ),
                dbapi=psycopg,
            ),
            runner_version="editor-target-upgrade/1",
        ).run(
            catalog=catalog,
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
            report.applied_versions,
            tuple(item.descriptor.version for item in catalog.artifacts),
        )

    @staticmethod
    def _set_local(connection: Any, values: tuple[tuple[str, str], ...]) -> None:
        for name, value in values:
            connection.execute(
                "SELECT pg_catalog.set_config(%s,%s,true)",
                (name, value),
            )

    def _principal_marker(
        self,
        *,
        actor_id: UUID,
        session_id: UUID,
        workspace_id: str,
    ) -> bytes:
        with psycopg.connect(
            self.postgres.conninfo(database=self.database, user="iam_app"),
            autocommit=True,
        ) as connection:
            connection.execute(
                "BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY"
            )
            self._set_local(
                connection,
                (
                    ("app.scope_kind", "EDITOR_PRINCIPAL"),
                    ("app.actor_user_id", str(actor_id)),
                    ("app.session_id", str(session_id)),
                ),
            )
            row = connection.execute(
                "SELECT principal_marker_sha256 "
                "FROM iam_api.resolve_editor_principal_v1(%s,%s) "
                "WHERE workspace_id=%s",
                (actor_id, session_id, workspace_id),
            ).fetchone()
            connection.execute("COMMIT")
        self.assertIsNotNone(row)
        marker = bytes(row[0])
        self.assertEqual(len(marker), 32)
        return marker

    def _install_profile_v1(self, catalog: ProfileMigrationCatalog) -> None:
        artifact = catalog.artifacts[0]
        sources = self._profile_sources()
        with psycopg.connect(
            self.postgres.conninfo(
                database=self.database,
                user="profile_migration_runner",
            ),
            autocommit=True,
        ) as connection:
            connection.execute("SET ROLE profile_schema_owner")
            connection.execute("BEGIN")
            connection.execute(artifact.sql_bytes.decode("utf-8"))
            connection.execute(
                "INSERT INTO profile.schema_migrations ("
                "component,version,phase,name,checksum_sha256,manifest_sha256,"
                "runner_version,applied_at) VALUES ("
                "'profile',1,'expand','creator_profile_v1',%s,%s,"
                "'reviewed-profile-v1/1',transaction_timestamp())",
                (
                    artifact.descriptor.checksum_sha256,
                    artifact.descriptor.prefix_manifest_sha256,
                ),
            )
            connection.execute(
                "INSERT INTO profile.schema_contracts ("
                "singleton_key,schema_head_version,min_app_compatible_version,"
                "max_app_compatible_version,api_contract_sha256,"
                "event_contract_sha256,domain_contract_sha256,"
                "migration_manifest_sha256,generated_at) VALUES ("
                "true,1,1,1,%s,%s,%s,%s,transaction_timestamp())",
                (
                    hashlib.sha256(sources.api_contract_bytes).digest(),
                    hashlib.sha256(sources.event_contract_bytes).digest(),
                    hashlib.sha256(sources.domain_contract_bytes).digest(),
                    artifact.descriptor.prefix_manifest_sha256,
                ),
            )
            connection.execute("COMMIT")
            connection.execute("RESET ROLE")

    def _install_demand_v1(self, catalog: DemandMigrationCatalog) -> None:
        artifact = catalog.artifacts[0]
        sources = self._demand_sources()
        with psycopg.connect(
            self.postgres.conninfo(
                database=self.database,
                user="demand_migration_runner",
            ),
            autocommit=True,
        ) as connection:
            connection.execute("SET ROLE demand_schema_owner")
            connection.execute("BEGIN")
            connection.execute(artifact.sql_bytes.decode("utf-8"))
            connection.execute(
                "INSERT INTO demand_meta.schema_migrations ("
                "component,version,phase,name,checksum_sha256,manifest_sha256,"
                "runner_version,applied_at) VALUES ("
                "'demand',1,'expand','demand_v1',%s,%s,"
                "'reviewed-demand-v1/1',transaction_timestamp())",
                (
                    artifact.descriptor.checksum_sha256,
                    artifact.descriptor.prefix_manifest_sha256,
                ),
            )
            connection.execute(
                "INSERT INTO demand_meta.schema_contracts ("
                "singleton_key,schema_head_version,min_app_compatible_version,"
                "max_app_compatible_version,required_iam_schema_version,"
                "api_contract_sha256,event_contract_sha256,"
                "content_contract_sha256,migration_manifest_sha256,"
                "generated_at) VALUES ("
                "true,1,1,1,16,%s,%s,%s,%s,transaction_timestamp())",
                (
                    hashlib.sha256(sources.api_contract_bytes).digest(),
                    hashlib.sha256(sources.event_contract_bytes).digest(),
                    hashlib.sha256(sources.content_contract_bytes).digest(),
                    artifact.descriptor.prefix_manifest_sha256,
                ),
            )
            connection.execute("COMMIT")
            connection.execute("RESET ROLE")

    @staticmethod
    def _profile_sources() -> ProfileContractSources:
        return ProfileContractSources(
            api_contract_bytes=(
                PLATFORM_ROOT / "contracts/api/profile-v1.openapi.yaml"
            ).read_bytes(),
            event_contract_bytes=(
                PLATFORM_ROOT / "contracts/events/profile-v1.schema.json"
            ).read_bytes(),
            domain_contract_bytes=(
                PLATFORM_ROOT / "contracts/domain/profile-version-v1.schema.json"
            ).read_bytes(),
        )

    @staticmethod
    def _demand_sources() -> DemandContractSources:
        return DemandContractSources(
            api_contract_bytes=(
                PLATFORM_ROOT / "contracts/api/demand-v1.openapi.yaml"
            ).read_bytes(),
            event_contract_bytes=(
                PLATFORM_ROOT / "contracts/events/demand-v1.schema.json"
            ).read_bytes(),
            content_contract_bytes=(
                PLATFORM_ROOT / "contracts/domain/demand-content-v1.schema.json"
            ).read_bytes(),
        )

    def test_profile_v1_to_v2_rerun_discovery_rls_and_drift_rejection(self) -> None:
        now = datetime.now(timezone.utc)
        with self._admin(autocommit=False) as connection:
            seed_exact_creator_iam_authority(connection, now=now)
        catalog = ProfileMigrationCatalog.load(PROFILE_ROOT)
        self._install_profile_v1(catalog)
        runner = PsycopgCreatorProfileMigrationRunner(
            conninfo=self.postgres.conninfo(
                database=self.database,
                user="profile_migration_runner",
            ),
            dbapi=psycopg,
            runner_version="editor-profile-v2/1",
        )
        upgraded = runner.run(
            catalog=catalog,
            contract_sources=self._profile_sources(),
        )
        self.assertEqual(
            (upgraded.applied_versions, upgraded.skipped_versions),
            (
                tuple(
                    artifact.descriptor.version
                    for artifact in catalog.artifacts[1:]
                ),
                (1,),
            ),
        )
        rerun = runner.run(
            catalog=catalog,
            contract_sources=self._profile_sources(),
        )
        self.assertEqual(
            (rerun.applied_versions, rerun.skipped_versions),
            (
                (),
                tuple(
                    artifact.descriptor.version
                    for artifact in catalog.artifacts
                ),
            ),
        )

        with self._admin(autocommit=False) as connection:
            connection.execute(
                "INSERT INTO profile.creator_profiles ("
                "id,owner_user_id,status,aggregate_version,"
                "current_draft_version_id,current_published_version_id,"
                "created_at,updated_at) VALUES ("
                "%s,%s,'DRAFT',1,NULL,NULL,%s,%s)",
                (PROFILE_ID, PROFILE_ACTOR_ID, now, now),
            )
        marker = self._principal_marker(
            actor_id=PROFILE_ACTOR_ID,
            session_id=PROFILE_SESSION_ID,
            workspace_id=f"personal:{PROFILE_ACTOR_ID}",
        )
        with psycopg.connect(
            self.postgres.conninfo(database=self.database, user="profile_app"),
            autocommit=True,
        ) as connection:
            connection.execute("BEGIN READ ONLY")
            self._set_local(
                connection,
                (
                    ("app.scope_kind", "PROFILE_SELF"),
                    ("app.actor_user_id", str(PROFILE_ACTOR_ID)),
                    ("app.session_id", str(PROFILE_SESSION_ID)),
                    ("app.operation", "LIST_PROFILE_TARGETS"),
                ),
            )
            discovered = tuple(
                row[0]
                for row in connection.execute(
                    "SELECT profile_id FROM "
                    "profile_api.list_owned_profile_targets_v1(%s,%s,%s)",
                    (PROFILE_ACTOR_ID, PROFILE_SESSION_ID, marker),
                ).fetchall()
            )
            direct = tuple(
                connection.execute(
                    "SELECT id FROM profile.creator_profiles"
                ).fetchall()
            )
            rejected = tuple(
                connection.execute(
                    "SELECT profile_id FROM "
                    "profile_api.list_owned_profile_targets_v1(%s,%s,%s)",
                    (PROFILE_ACTOR_ID, PROFILE_SESSION_ID, b"x" * 32),
                ).fetchall()
            )
            compatibility = connection.execute(
                "SELECT current_schema_version,schema_head_version "
                "FROM profile.schema_compatibility"
            ).fetchone()
            connection.execute("COMMIT")
        self.assertEqual(discovered, (PROFILE_ID,))
        self.assertEqual(direct, ())
        self.assertEqual(rejected, ())
        profile_head = catalog.artifacts[-1].descriptor.version
        self.assertEqual(compatibility, (profile_head, profile_head))

        with self._admin(autocommit=False) as connection:
            ledgers = tuple(
                connection.execute(
                    "SELECT version,manifest_sha256 "
                    "FROM profile.schema_migrations ORDER BY version"
                ).fetchall()
            )
            connection.execute(
                "UPDATE profile.schema_migrations SET manifest_sha256=%s "
                "WHERE version=1",
                (b"z" * 32,),
            )
        self.assertEqual(
            ledgers,
            tuple(
                (
                    artifact.descriptor.version,
                    artifact.descriptor.prefix_manifest_sha256,
                )
                for artifact in catalog.artifacts
            ),
        )
        with self.assertRaises(ProfileMigrationRunnerError) as drift:
            runner.run(
                catalog=catalog,
                contract_sources=self._profile_sources(),
            )
        self.assertEqual(drift.exception.code, "PROFILE_MIGRATION_LEDGER_DRIFT")

    def test_demand_v1_to_v2_owner_and_platform_reviewer_discovery(self) -> None:
        now = datetime.now(timezone.utc)
        with self._admin(autocommit=False) as connection:
            seed_exact_demand_owner_iam_authority(connection, now=now)
        catalog = DemandMigrationCatalog.load(DEMAND_ROOT)
        self._install_demand_v1(catalog)
        runner = DemandMigrationRunner(
            driver=PsycopgDemandMigrationDriver(
                settings=DemandMigrationSettings(
                    conninfo=self.postgres.conninfo(
                        database=self.database,
                        user="demand_migration_runner",
                    ),
                    application_name="editor-demand-v2",
                ),
                dbapi=psycopg,
            ),
            runner_version="editor-demand-v2/1",
        )
        upgraded = runner.run(
            catalog=catalog,
            contract_sources=self._demand_sources(),
        )
        self.assertEqual(
            (upgraded.applied_versions, upgraded.skipped_versions),
            (
                tuple(
                    artifact.descriptor.version
                    for artifact in catalog.artifacts[1:]
                ),
                (1,),
            ),
        )
        rerun = runner.run(
            catalog=catalog,
            contract_sources=self._demand_sources(),
        )
        self.assertEqual(
            (rerun.applied_versions, rerun.skipped_versions),
            (
                (),
                tuple(
                    artifact.descriptor.version
                    for artifact in catalog.artifacts
                ),
            ),
        )

        with self._admin(autocommit=False) as connection:
            seed_demand_operation_graph(
                connection,
                DemandPostgresOperation.REQUEST_CHANGES,
            )
        owner_marker = self._principal_marker(
            actor_id=DEMAND_ACTOR_ID,
            session_id=UUID("20000000-0000-4000-8000-000000000001"),
            workspace_id=f"org:{ORGANIZATION_ID}",
        )
        reviewer_marker = self._principal_marker(
            actor_id=REVIEWER_USER_ID,
            session_id=REVIEWER_SESSION_ID,
            workspace_id=f"platform:{REVIEWER_USER_ID}",
        )

        with psycopg.connect(
            self.postgres.conninfo(database=self.database, user="demand_self"),
            autocommit=True,
        ) as connection:
            connection.execute("BEGIN READ ONLY")
            self._set_local(
                connection,
                (
                    ("app.scope_kind", "DEMAND_OWNER"),
                    ("app.actor_id", str(DEMAND_ACTOR_ID)),
                    ("app.session_id", "20000000-0000-4000-8000-000000000001"),
                    ("app.organization_id", str(ORGANIZATION_ID)),
                    ("app.operation", "LIST_DEMAND_TARGETS"),
                ),
            )
            owned = tuple(
                row[0]
                for row in connection.execute(
                    "SELECT demand_id FROM "
                    "demand_api.list_owned_demand_targets_v1(%s,%s,%s,%s)",
                    (
                        DEMAND_ACTOR_ID,
                        UUID("20000000-0000-4000-8000-000000000001"),
                        ORGANIZATION_ID,
                        owner_marker,
                    ),
                ).fetchall()
            )
            direct_owned = tuple(
                connection.execute("SELECT id FROM demand.demands").fetchall()
            )
            connection.execute("COMMIT")

        with psycopg.connect(
            self.postgres.conninfo(database=self.database, user="demand_review"),
            autocommit=True,
        ) as connection:
            connection.execute("BEGIN READ ONLY")
            self._set_local(
                connection,
                (
                    ("app.scope_kind", "DEMAND_REVIEW"),
                    ("app.actor_id", str(REVIEWER_USER_ID)),
                    ("app.session_id", str(REVIEWER_SESSION_ID)),
                    ("app.operation", "LIST_REVIEW_TARGETS"),
                ),
            )
            reviews = tuple(
                connection.execute(
                    "SELECT organization_id,demand_id,assignment_id FROM "
                    "demand_api.list_reviewer_demand_targets_v1(%s,%s,%s)",
                    (REVIEWER_USER_ID, REVIEWER_SESSION_ID, reviewer_marker),
                ).fetchall()
            )
            direct_reviews = tuple(
                connection.execute(
                    "SELECT id FROM demand.demand_review_assignments"
                ).fetchall()
            )
            rejected = tuple(
                connection.execute(
                    "SELECT demand_id FROM "
                    "demand_api.list_reviewer_demand_targets_v1(%s,%s,%s)",
                    (REVIEWER_USER_ID, REVIEWER_SESSION_ID, b"x" * 32),
                ).fetchall()
            )
            connection.execute("COMMIT")
        self.assertEqual(owned, (DEMAND_ID,))
        self.assertEqual(direct_owned, ())
        self.assertEqual(reviews, ((ORGANIZATION_ID, DEMAND_ID, ASSIGNMENT_ID),))
        self.assertEqual(direct_reviews, ())
        self.assertEqual(rejected, ())

        with self._admin(autocommit=False) as connection:
            ledgers = tuple(
                connection.execute(
                    "SELECT version,manifest_sha256 "
                    "FROM demand_meta.schema_migrations ORDER BY version"
                ).fetchall()
            )
            connection.execute(
                "UPDATE demand_meta.schema_migrations SET manifest_sha256=%s "
                "WHERE version=1",
                (b"z" * 32,),
            )
        self.assertEqual(
            ledgers,
            tuple(
                (
                    artifact.descriptor.version,
                    artifact.descriptor.prefix_manifest_sha256,
                )
                for artifact in catalog.artifacts
            ),
        )
        with self.assertRaises(DemandMigrationRunnerError) as drift:
            runner.run(
                catalog=catalog,
                contract_sources=self._demand_sources(),
            )
        self.assertEqual(drift.exception.code, "DEMAND_MIGRATION_LEDGER_DRIFT")


if __name__ == "__main__":
    unittest.main()
