"""PostgreSQL 18 proof for the reviewed independent Trust catalog runner."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import unittest
from unittest import mock

import psycopg

import desire_platform.demand.adapters.postgres.migrations.runner as demand_runner_module

from desire_platform.demand.adapters.postgres.migrations import (
    DEMAND_SCHEMA_HEAD_VERSION,
    DemandContractSources,
    DemandMigrationCatalog,
    DemandMigrationRunner,
    DemandMigrationSettings,
    PsycopgDemandMigrationDriver,
)
from desire_platform.identity_access.adapters.postgres.migrations import (
    IAM_SCHEMA_HEAD_VERSION,
    IamContractSources,
    IamMigrationRunner,
    MigrationCatalog,
    PsycopgMigrationDriver,
    PsycopgMigrationSettings,
)
from desire_platform.trust_safety.adapters.postgres.migrations import (
    PsycopgTrustMigrationDriver,
    TRUST_EVENT_CONTRACT_SHA256,
    TRUST_REPORT_CONTRACT_SHA256,
    TRUST_REQUIRED_DEMAND_CONTRACT_SHA256,
    TRUST_REQUIRED_DEMAND_SCHEMA_VERSION,
    TRUST_REQUIRED_IAM_CONTRACT_SHA256,
    TRUST_REQUIRED_IAM_SCHEMA_VERSION,
    TRUST_REVIEWED_COMBINED_CONTRACT_SHA256,
    TRUST_REVIEWED_MANIFEST_SHA256,
    TRUST_SCHEMA_HEAD_VERSION,
    TRUST_TRIAGE_CONTRACT_SHA256,
    TrustContractSources,
    TrustMigrationCatalog,
    TrustMigrationRunner,
    TrustMigrationSettings,
)
from desire_platform.trust_safety.adapters.postgres.migrations.runner import (
    TRUST_API_CONTRACT_SHA256,
    TRUST_APPEAL_API_CONTRACT_SHA256,
    TRUST_APPEAL_APPLICATION_CONTRACT_SHA256,
    TRUST_APPEAL_EVENT_CONTRACT_SHA256,
    TRUST_APPEAL_REVIEW_CONTRACT_SHA256,
)
from tests.storage.postgres.postgres18_harness import TemporaryPostgres18


PLATFORM_ROOT = Path(__file__).resolve().parents[3]
IAM_ROOT = (
    PLATFORM_ROOT
    / "src/desire_platform/identity_access/adapters/postgres/migrations"
)
DEMAND_ROOT = PLATFORM_ROOT / "src/desire_platform/demand/adapters/postgres/migrations"
TRUST_ROOT = (
    PLATFORM_ROOT
    / "src/desire_platform/trust_safety/adapters/postgres/migrations"
)
_TRUST6_REQUIRED_IAM_CONTRACT_SHA256 = bytes.fromhex(
    "8be48226b6fb409f442c6331dffcebc69435d401a75aa423614a9b7e60eb86a4"
)
_TRUST6_REQUIRED_DEMAND_CONTRACT_SHA256 = bytes.fromhex(
    "2ce5929295d30a91b55d9d907e0031707461498d3380e9e9e2e449eec06f9328"
)
_TRUST8_API_CONTRACT_SHA256 = bytes.fromhex(
    "f23f8283ce8334cf48e1c912379451f00efe21382a281c5f5156260ae3a618ed"
)
_FROZEN_APPEAL_API_CONTRACT_SHA256 = bytes.fromhex(
    "2a0bda244ae3c59921376732a1edd51cdce7c73ffad857223f387c94741c6522"
)


class TrustMigrationRunnerPostgres18Test(unittest.TestCase):
    _PROBE_SQL = (
        "SELECT * FROM trust_api.assert_appeal_runtime_policy_v1("
        "%s,%s::text[],%s,%s::text[],%s,%s,%s::text[])"
    )
    _INITIAL_POLICY = (
        "trust-idempotency-2026-01",
        ["trust-idempotency-2026-01"],
        "trust-payload-2026-01",
        ["trust-payload-2026-01"],
        "appeal-command-json-v1",
        "trust-sealed-note-v1",
        ["trust-sealed-note-v1"],
    )

    @classmethod
    def setUpClass(cls) -> None:
        cls.postgres = TemporaryPostgres18().start()
        cls.database = cls.postgres.create_database()
        try:
            with psycopg.connect(
                cls.postgres.admin_conninfo(database="postgres"),
                autocommit=True,
            ) as connection:
                connection.execute(
                    f'GRANT CREATE ON DATABASE "{cls.database}" '
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
            cls._apply_dependencies()
        except BaseException:
            cls.postgres.drop_database(cls.database)
            cls.postgres.stop()
            raise

    @classmethod
    def tearDownClass(cls) -> None:
        cls.postgres.drop_database(cls.database)
        cls.postgres.stop()

    @classmethod
    def _apply_dependencies(cls) -> None:
        cls._apply_dependencies_to(cls.database)

    @classmethod
    def _apply_dependencies_to(cls, database: str) -> None:
        cls._apply_iam_to(database)
        cls._demand_runner(database).run(
            catalog=DemandMigrationCatalog.load(DEMAND_ROOT),
            contract_sources=cls._demand_contracts(),
        )

    @classmethod
    def _apply_iam_to(cls, database: str) -> None:
        IamMigrationRunner(
            driver=PsycopgMigrationDriver(
                settings=PsycopgMigrationSettings(
                    conninfo=cls.postgres.conninfo(
                        database=database,
                        user="iam_migration_runner",
                    ),
                    application_name="trust-runner-iam36",
                ),
                dbapi=psycopg,
            ),
            runner_version="trust-runner-pg18/1",
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

    @classmethod
    def _demand_runner(cls, database: str) -> DemandMigrationRunner:
        return DemandMigrationRunner(
            driver=PsycopgDemandMigrationDriver(
                settings=DemandMigrationSettings(
                    conninfo=cls.postgres.conninfo(
                        database=database,
                        user="demand_migration_runner",
                    ),
                    application_name="trust-runner-demand8",
                ),
                dbapi=psycopg,
            ),
            runner_version="trust-runner-pg18/1",
        )

    @staticmethod
    def _demand_contracts() -> DemandContractSources:
        return DemandContractSources(
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
        )

    @staticmethod
    def _prefix_catalog(catalog, length: int):
        entries = json.loads(catalog.manifest_bytes.decode("ascii"))
        manifest_bytes = (
            json.dumps(
                entries[:length],
                ensure_ascii=True,
                separators=(",", ":"),
            ).encode("ascii")
            + b"\n"
        )
        manifest_sha256 = hashlib.sha256(manifest_bytes).digest()
        assert manifest_sha256 == (
            catalog.artifacts[length - 1].descriptor.prefix_manifest_sha256
        )
        return type(catalog)(
            artifacts=catalog.artifacts[:length],
            manifest_bytes=manifest_bytes,
            manifest_sha256=manifest_sha256,
        )

    @classmethod
    def _prepare_exact_trust4_database(cls, database: str):
        cls._apply_iam_to(database)
        demand_catalog = DemandMigrationCatalog.load(DEMAND_ROOT)
        demand8_catalog = cls._prefix_catalog(demand_catalog, 8)
        demand8_manifest = demand8_catalog.manifest_sha256
        with (
            mock.patch.object(
                demand_runner_module,
                "DEMAND_SCHEMA_HEAD_VERSION",
                8,
            ),
            mock.patch.object(
                demand_runner_module,
                "DEMAND_REVIEWED_MANIFEST_SHA256",
                demand8_manifest,
            ),
        ):
            report = cls._demand_runner(database).run(
                catalog=demand8_catalog,
                contract_sources=cls._demand_contracts(),
            )
        assert report.applied_versions == tuple(range(1, 9))

        trust_catalog = TrustMigrationCatalog.load(TRUST_ROOT)
        trust4_catalog = cls._prefix_catalog(trust_catalog, 4)
        old_demand_dependency = bytes.fromhex(
            "7d67863b0ce45bf19011d7ed1975fb5a73068f257c13083274689b2c8aa160f3"
        )
        with psycopg.connect(
            cls.postgres.conninfo(
                database=database,
                user="trust_migration_runner",
            ),
            autocommit=True,
        ) as connection:
            connection.execute("SET ROLE trust_schema_owner")
            for artifact in trust4_catalog.artifacts:
                descriptor = artifact.descriptor
                connection.execute("BEGIN")
                connection.execute(artifact.sql_bytes.decode("utf-8"))
                connection.execute(
                    "INSERT INTO trust_meta.schema_migrations ("
                    "component,version,phase,name,checksum_sha256,"
                    "manifest_sha256,runner_version,applied_at) VALUES ("
                    "'trust',%s,%s,%s,%s,%s,'trust4-exact-fixture',"
                    "transaction_timestamp())",
                    (
                        descriptor.version,
                        descriptor.phase.value,
                        descriptor.name,
                        descriptor.checksum_sha256,
                        descriptor.prefix_manifest_sha256,
                    ),
                )
                connection.execute("COMMIT")
            connection.execute(
                "INSERT INTO trust_meta.schema_contracts ("
                "singleton_key,schema_head_version,min_app_compatible_version,"
                "max_app_compatible_version,required_iam_schema_version,"
                "required_demand_schema_version,"
                "required_iam_contract_sha256,"
                "required_demand_contract_sha256,api_contract_sha256,"
                "event_contract_sha256,report_contract_sha256,"
                "triage_contract_sha256,appeal_api_contract_sha256,"
                "appeal_event_contract_sha256,"
                "appeal_application_contract_sha256,"
                "appeal_review_contract_sha256,combined_contract_sha256,"
                "migration_manifest_sha256,generated_at) VALUES ("
                "true,4,4,4,36,8,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,"
                "transaction_timestamp())",
                (
                    _TRUST6_REQUIRED_IAM_CONTRACT_SHA256,
                    old_demand_dependency,
                    bytes.fromhex(
                        "14572f7768f31e9ced0b6ede09eb6eea"
                        "1da3d2d4abd1c6d80cc4229c28e158bd"
                    ),
                    TRUST_EVENT_CONTRACT_SHA256,
                    TRUST_REPORT_CONTRACT_SHA256,
                    TRUST_TRIAGE_CONTRACT_SHA256,
                    bytes.fromhex(
                        "e85d905e407679665e7bea0008253bc4"
                        "ec2bd941c4442964016caeb4ce62ffa7"
                    ),
                    TRUST_APPEAL_EVENT_CONTRACT_SHA256,
                    TRUST_APPEAL_APPLICATION_CONTRACT_SHA256,
                    TRUST_APPEAL_REVIEW_CONTRACT_SHA256,
                    bytes.fromhex(
                        "9829628dfb25415cb5b8880af131011a"
                        "b61730839d05a836c4d2b5601521ae08"
                    ),
                    trust4_catalog.manifest_sha256,
                ),
            )
        return demand_catalog, trust_catalog

    @classmethod
    def _prepare_exact_trust5_database(cls, database: str):
        cls._apply_dependencies_to(database)
        trust_catalog = TrustMigrationCatalog.load(TRUST_ROOT)
        with psycopg.connect(
            cls.postgres.conninfo(
                database=database,
                user="trust_migration_runner",
            ),
            autocommit=True,
        ) as connection:
            connection.execute("SET ROLE trust_schema_owner")
            for artifact in trust_catalog.artifacts[:5]:
                descriptor = artifact.descriptor
                connection.execute("BEGIN")
                connection.execute(artifact.sql_bytes.decode("utf-8"))
                connection.execute(
                    "INSERT INTO trust_meta.schema_migrations ("
                    "component,version,phase,name,checksum_sha256,"
                    "manifest_sha256,runner_version,applied_at) VALUES ("
                    "'trust',%s,%s,%s,%s,%s,'trust5-exact-fixture',"
                    "transaction_timestamp())",
                    (
                        descriptor.version,
                        descriptor.phase.value,
                        descriptor.name,
                        descriptor.checksum_sha256,
                        descriptor.prefix_manifest_sha256,
                    ),
                )
                connection.execute("COMMIT")
            connection.execute(
                "INSERT INTO trust_meta.schema_contracts ("
                "singleton_key,schema_head_version,min_app_compatible_version,"
                "max_app_compatible_version,required_iam_schema_version,"
                "required_demand_schema_version,"
                "required_iam_contract_sha256,"
                "required_demand_contract_sha256,api_contract_sha256,"
                "event_contract_sha256,report_contract_sha256,"
                "triage_contract_sha256,appeal_api_contract_sha256,"
                "appeal_event_contract_sha256,"
                "appeal_application_contract_sha256,"
                "appeal_review_contract_sha256,combined_contract_sha256,"
                "migration_manifest_sha256,generated_at) VALUES ("
                "true,5,5,5,36,9,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,"
                "transaction_timestamp())",
                (
                    _TRUST6_REQUIRED_IAM_CONTRACT_SHA256,
                    _TRUST6_REQUIRED_DEMAND_CONTRACT_SHA256,
                    bytes.fromhex(
                        "14572f7768f31e9ced0b6ede09eb6eea"
                        "1da3d2d4abd1c6d80cc4229c28e158bd"
                    ),
                    TRUST_EVENT_CONTRACT_SHA256,
                    TRUST_REPORT_CONTRACT_SHA256,
                    TRUST_TRIAGE_CONTRACT_SHA256,
                    bytes.fromhex(
                        "e85d905e407679665e7bea0008253bc4"
                        "ec2bd941c4442964016caeb4ce62ffa7"
                    ),
                    TRUST_APPEAL_EVENT_CONTRACT_SHA256,
                    TRUST_APPEAL_APPLICATION_CONTRACT_SHA256,
                    TRUST_APPEAL_REVIEW_CONTRACT_SHA256,
                    bytes.fromhex(
                        "85ba3eba8e44d325eb581bc1b1153c4e"
                        "085e58ba66f300591e1bf83c14322865"
                    ),
                    trust_catalog.artifacts[4].descriptor.prefix_manifest_sha256,
                ),
            )
        return trust_catalog

    @classmethod
    def _prepare_exact_trust6_database(cls, database: str):
        cls._apply_dependencies_to(database)
        trust_catalog = TrustMigrationCatalog.load(TRUST_ROOT)
        with psycopg.connect(
            cls.postgres.conninfo(
                database=database,
                user="trust_migration_runner",
            ),
            autocommit=True,
        ) as connection:
            connection.execute("SET ROLE trust_schema_owner")
            for artifact in trust_catalog.artifacts[:6]:
                descriptor = artifact.descriptor
                connection.execute("BEGIN")
                connection.execute(artifact.sql_bytes.decode("utf-8"))
                connection.execute(
                    "INSERT INTO trust_meta.schema_migrations ("
                    "component,version,phase,name,checksum_sha256,"
                    "manifest_sha256,runner_version,applied_at) VALUES ("
                    "'trust',%s,%s,%s,%s,%s,'trust6-exact-fixture',"
                    "transaction_timestamp())",
                    (
                        descriptor.version,
                        descriptor.phase.value,
                        descriptor.name,
                        descriptor.checksum_sha256,
                        descriptor.prefix_manifest_sha256,
                    ),
                )
                connection.execute("COMMIT")
            connection.execute(
                "INSERT INTO trust_meta.schema_contracts ("
                "singleton_key,schema_head_version,min_app_compatible_version,"
                "max_app_compatible_version,required_iam_schema_version,"
                "required_demand_schema_version,"
                "required_iam_contract_sha256,"
                "required_demand_contract_sha256,api_contract_sha256,"
                "event_contract_sha256,report_contract_sha256,"
                "triage_contract_sha256,appeal_api_contract_sha256,"
                "appeal_event_contract_sha256,"
                "appeal_application_contract_sha256,"
                "appeal_review_contract_sha256,combined_contract_sha256,"
                "migration_manifest_sha256,generated_at) VALUES ("
                "true,6,6,6,36,9,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,"
                "transaction_timestamp())",
                (
                    _TRUST6_REQUIRED_IAM_CONTRACT_SHA256,
                    _TRUST6_REQUIRED_DEMAND_CONTRACT_SHA256,
                    _TRUST8_API_CONTRACT_SHA256,
                    TRUST_EVENT_CONTRACT_SHA256,
                    TRUST_REPORT_CONTRACT_SHA256,
                    TRUST_TRIAGE_CONTRACT_SHA256,
                    _FROZEN_APPEAL_API_CONTRACT_SHA256,
                    TRUST_APPEAL_EVENT_CONTRACT_SHA256,
                    TRUST_APPEAL_APPLICATION_CONTRACT_SHA256,
                    TRUST_APPEAL_REVIEW_CONTRACT_SHA256,
                    bytes.fromhex(
                        "d797f6be98536fbc3ac6f372415418cc"
                        "7c0f48a2007c5a8af4094afa315bdd44"
                    ),
                    trust_catalog.artifacts[5].descriptor.prefix_manifest_sha256,
                ),
            )
        return trust_catalog

    @classmethod
    def _prepare_exact_trust7_database(cls, database: str):
        cls._apply_dependencies_to(database)
        trust_catalog = TrustMigrationCatalog.load(TRUST_ROOT)
        trust7_manifest = bytes.fromhex(
            "27a51c55bddfcb2a4f1bd16a3160abbb"
            "3a417425f14077f4886c3c41c22d5124"
        )
        assert (
            trust_catalog.artifacts[6].descriptor.prefix_manifest_sha256
            == trust7_manifest
        )
        with psycopg.connect(
            cls.postgres.conninfo(
                database=database,
                user="trust_migration_runner",
            ),
            autocommit=True,
        ) as connection:
            connection.execute("SET ROLE trust_schema_owner")
            for artifact in trust_catalog.artifacts[:7]:
                descriptor = artifact.descriptor
                connection.execute("BEGIN")
                connection.execute(artifact.sql_bytes.decode("utf-8"))
                connection.execute(
                    "INSERT INTO trust_meta.schema_migrations ("
                    "component,version,phase,name,checksum_sha256,"
                    "manifest_sha256,runner_version,applied_at) VALUES ("
                    "'trust',%s,%s,%s,%s,%s,'trust7-exact-fixture',"
                    "transaction_timestamp())",
                    (
                        descriptor.version,
                        descriptor.phase.value,
                        descriptor.name,
                        descriptor.checksum_sha256,
                        descriptor.prefix_manifest_sha256,
                    ),
                )
                connection.execute("COMMIT")
            connection.execute(
                "INSERT INTO trust_meta.schema_contracts ("
                "singleton_key,schema_head_version,min_app_compatible_version,"
                "max_app_compatible_version,required_iam_schema_version,"
                "required_demand_schema_version,"
                "required_iam_contract_sha256,"
                "required_demand_contract_sha256,api_contract_sha256,"
                "event_contract_sha256,report_contract_sha256,"
                "triage_contract_sha256,appeal_api_contract_sha256,"
                "appeal_event_contract_sha256,"
                "appeal_application_contract_sha256,"
                "appeal_review_contract_sha256,combined_contract_sha256,"
                "migration_manifest_sha256,generated_at) VALUES ("
                "true,7,7,7,37,10,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,"
                "transaction_timestamp())",
                (
                    bytes.fromhex(
                        "595d5232153063b0b71a88b3776c737d"
                        "1fcd5ecaef4a4b832c5e40434929c486"
                    ),
                    bytes.fromhex(
                        "27ec6b585a9340cbd7119d7a9b46d609"
                        "8a3881f88ae1be9e00df3713c0107113"
                    ),
                    _TRUST8_API_CONTRACT_SHA256,
                    TRUST_EVENT_CONTRACT_SHA256,
                    TRUST_REPORT_CONTRACT_SHA256,
                    TRUST_TRIAGE_CONTRACT_SHA256,
                    _FROZEN_APPEAL_API_CONTRACT_SHA256,
                    TRUST_APPEAL_EVENT_CONTRACT_SHA256,
                    TRUST_APPEAL_APPLICATION_CONTRACT_SHA256,
                    TRUST_APPEAL_REVIEW_CONTRACT_SHA256,
                    bytes.fromhex(
                        "ab857f25969d17afe63886afe136cda1"
                        "0814e538517c54c180503b82f5785c1b"
                    ),
                    trust7_manifest,
                ),
            )
        return trust_catalog

    @staticmethod
    def _business_surface(connection):
        return (
            connection.execute(
                "SELECT namespace.nspname,relation.relname,relation.relkind,"
                "owner_role.rolname,COALESCE(relation.relacl::text,'') "
                "FROM pg_catalog.pg_class AS relation "
                "JOIN pg_catalog.pg_namespace AS namespace "
                "ON namespace.oid=relation.relnamespace "
                "JOIN pg_catalog.pg_roles AS owner_role "
                "ON owner_role.oid=relation.relowner "
                "WHERE namespace.nspname IN ('trust','trust_api') "
                "ORDER BY 1,2,3"
            ).fetchall(),
            connection.execute(
                "SELECT namespace.nspname,procedure.oid::regprocedure::text,"
                "owner_role.rolname,procedure.prosecdef,procedure.provolatile,"
                "procedure.proparallel,procedure.proconfig,"
                "COALESCE(procedure.proacl::text,''),"
                "pg_catalog.pg_get_functiondef(procedure.oid) "
                "FROM pg_catalog.pg_proc AS procedure "
                "JOIN pg_catalog.pg_namespace AS namespace "
                "ON namespace.oid=procedure.pronamespace "
                "JOIN pg_catalog.pg_roles AS owner_role "
                "ON owner_role.oid=procedure.proowner "
                "WHERE namespace.nspname IN ('trust','trust_api') "
                "ORDER BY 1,2"
            ).fetchall(),
            connection.execute(
                "SELECT schemaname,tablename,policyname,roles,cmd,qual,"
                "with_check FROM pg_catalog.pg_policies "
                "WHERE schemaname='trust' ORDER BY 1,2,3"
            ).fetchall(),
            connection.execute(
                "SELECT namespace.nspname,owner_role.rolname,"
                "COALESCE(namespace.nspacl::text,'') "
                "FROM pg_catalog.pg_namespace AS namespace "
                "JOIN pg_catalog.pg_roles AS owner_role "
                "ON owner_role.oid=namespace.nspowner "
                "WHERE namespace.nspname IN ('trust','trust_api','trust_meta') "
                "ORDER BY 1"
            ).fetchall(),
            connection.execute(
                "SELECT owner_role.rolname,COALESCE(relation.relacl::text,'') "
                "FROM pg_catalog.pg_class AS relation "
                "JOIN pg_catalog.pg_roles AS owner_role "
                "ON owner_role.oid=relation.relowner "
                "WHERE relation.oid='trust_meta.schema_contracts'::regclass"
            ).fetchall(),
        )

    @staticmethod
    def _assert_discovery_business_additions_are_exact(
        before,
        after,
    ) -> None:
        markers = (
            "trust_api.list_own_reports_v1(",
            "trust_api.list_my_completed_case_assignments_v1(",
            "trust_api.list_my_completed_appeal_reviews_v1(",
            "trust_api.read_my_completed_appeal_review_v1(",
        )
        added_functions = [
            row for row in after[1] if row[1].startswith(markers)
        ]
        retained_functions = [
            row for row in after[1] if not row[1].startswith(markers)
        ]
        added_policy_names = {
            "rls_trust_my_completed_case_assignments_select_v1",
            "rls_trust_my_completed_case_outcomes_select_v1",
            "rls_trust_my_completed_case_roots_select_v1",
            "rls_trust_my_completed_appeal_applications_select_v1",
            "rls_trust_my_completed_appeal_assignments_select_v1",
            "rls_trust_my_completed_appeal_decisions_select_v1",
            "rls_trust_my_completed_appeal_review_drafts_select_v1",
            "rls_trust_my_completed_appeal_roots_select_v1",
        }
        added_policies = [
            row for row in after[2] if row[2] in added_policy_names
        ]
        retained_policies = [
            row for row in after[2] if row[2] not in added_policy_names
        ]
        assert after[0] == before[0]
        assert after[3:] == before[3:]
        assert retained_functions == before[1]
        assert retained_policies == before[2]
        assert len(added_functions) == 4
        assert {row[1].split("(", 1)[0] for row in added_functions} == {
            "trust_api.list_own_reports_v1",
            "trust_api.list_my_completed_case_assignments_v1",
            "trust_api.list_my_completed_appeal_reviews_v1",
            "trust_api.read_my_completed_appeal_review_v1",
        }
        for added in added_functions:
            assert added[0] == "trust_api"
            assert added[2:6] == (
                "trust_schema_owner",
                True,
                "v",
                "u",
            )
            assert added[6] == ["search_path=pg_catalog, trust"]
            assert "SECURITY DEFINER" in added[8]
        own_reports = next(
            row
            for row in added_functions
            if row[1].startswith("trust_api.list_own_reports_v1(")
        )
        completed_assignments = next(
            row
            for row in added_functions
            if row[1].startswith(
                "trust_api.list_my_completed_case_assignments_v1("
            )
        )
        assert "trust_self=X/trust_schema_owner" in own_reports[7]
        assert "trust_officer=X/trust_schema_owner" in completed_assignments[7]
        completed_appeal_functions = [
            row
            for row in added_functions
            if "_my_completed_appeal_review" in row[1]
        ]
        assert len(completed_appeal_functions) == 2
        assert all(
            "trust_appeal=X/trust_schema_owner" in row[7]
            for row in completed_appeal_functions
        )
        assert {row[2] for row in added_policies} == added_policy_names
        assert all(row[3] == ["trust_schema_owner"] for row in added_policies)
        assert all(row[4] == "SELECT" for row in added_policies)

    @classmethod
    def _runner(cls, database: str | None = None) -> TrustMigrationRunner:
        return TrustMigrationRunner(
            driver=PsycopgTrustMigrationDriver(
                settings=TrustMigrationSettings(
                    conninfo=cls.postgres.conninfo(
                        database=cls.database if database is None else database,
                        user="trust_migration_runner",
                    ),
                    application_name="trust-runner-trust1",
                ),
                dbapi=psycopg,
            ),
            runner_version="trust-runner-pg18/1",
        )

    @staticmethod
    def _contracts() -> TrustContractSources:
        return TrustContractSources(
            api_contract_bytes=(
                PLATFORM_ROOT / "contracts/api/trust-v1.openapi.yaml"
            ).read_bytes(),
            event_contract_bytes=(
                PLATFORM_ROOT / "contracts/events/trust-v1.schema.json"
            ).read_bytes(),
            report_contract_bytes=(
                PLATFORM_ROOT / "contracts/domain/trust-report-v1.schema.json"
            ).read_bytes(),
            triage_contract_bytes=(
                PLATFORM_ROOT / "contracts/domain/trust-triage-v1.schema.json"
            ).read_bytes(),
            appeal_api_contract_bytes=(
                PLATFORM_ROOT / "contracts/api/appeal-v1.openapi.yaml"
            ).read_bytes(),
            appeal_event_contract_bytes=(
                PLATFORM_ROOT / "contracts/events/appeal-v1.schema.json"
            ).read_bytes(),
            appeal_application_contract_bytes=(
                PLATFORM_ROOT
                / "contracts/domain/appeal-application-v1.schema.json"
            ).read_bytes(),
            appeal_review_contract_bytes=(
                PLATFORM_ROOT / "contracts/domain/appeal-review-v1.schema.json"
            ).read_bytes(),
        )

    @classmethod
    def _rotate_runtime_policy(
        cls,
        *,
        database: str,
        policy: tuple,
    ) -> None:
        with psycopg.connect(
            cls.postgres.conninfo(
                database=database,
                user="trust_migration_runner",
            ),
            autocommit=True,
        ) as connection:
            connection.execute("BEGIN")
            connection.execute("SET LOCAL ROLE trust_schema_owner")
            connection.execute(
                "SELECT pg_catalog.set_config("
                "'app.appeal_scope_kind','APPEAL_KEY_ROTATION',true)"
            )
            connection.execute(
                "UPDATE trust.appeal_receipt_key_policy SET "
                "active_idempotency_key_id=%s,"
                "retained_idempotency_key_ids=%s::text[],"
                "active_payload_key_id=%s,"
                "retained_payload_key_ids=%s::text[],"
                "updated_at=transaction_timestamp() WHERE singleton_key",
                policy[:4],
            )
            connection.execute(
                "UPDATE trust.sealed_text_key_policy SET "
                "active_encryption_key_id=%s,"
                "retained_encryption_key_ids=%s::text[],"
                "updated_at=transaction_timestamp() WHERE singleton_key",
                policy[5:7],
            )
            connection.execute("COMMIT")

    def test_reviewed_runner_applies_and_replays_exact_catalog(self) -> None:
        catalog = TrustMigrationCatalog.load(TRUST_ROOT)
        first = self._runner().run(
            catalog=catalog,
            contract_sources=self._contracts(),
        )
        replay = self._runner().run(
            catalog=catalog,
            contract_sources=self._contracts(),
        )
        self.assertEqual(
            first.applied_versions,
            tuple(range(1, TRUST_SCHEMA_HEAD_VERSION + 1)),
        )
        self.assertEqual(first.skipped_versions, ())
        self.assertEqual(replay.applied_versions, ())
        self.assertEqual(
            replay.skipped_versions,
            tuple(range(1, TRUST_SCHEMA_HEAD_VERSION + 1)),
        )
        with psycopg.connect(
            self.postgres.admin_conninfo(database=self.database),
            autocommit=True,
        ) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT component,current_schema_version,"
                    "schema_head_version,min_app_compatible_version,"
                    "max_app_compatible_version,required_iam_schema_version,"
                    "required_demand_schema_version,combined_contract_sha256,"
                    "migration_manifest_sha256 "
                    "FROM trust.schema_compatibility"
                ).fetchone(),
                (
                    "trust",
                    TRUST_SCHEMA_HEAD_VERSION,
                    TRUST_SCHEMA_HEAD_VERSION,
                    TRUST_SCHEMA_HEAD_VERSION,
                    TRUST_SCHEMA_HEAD_VERSION,
                    TRUST_REQUIRED_IAM_SCHEMA_VERSION,
                    TRUST_REQUIRED_DEMAND_SCHEMA_VERSION,
                    TRUST_REVIEWED_COMBINED_CONTRACT_SHA256,
                    TRUST_REVIEWED_MANIFEST_SHA256,
                ),
            )

    def test_runtime_policy_probe_is_exact_private_and_fail_closed(self) -> None:
        for role in ("trust_self", "trust_appeal"):
            with psycopg.connect(
                self.postgres.conninfo(database=self.database, user=role),
                autocommit=True,
            ) as connection:
                self.assertEqual(
                    connection.execute(
                        self._PROBE_SQL,
                        self._INITIAL_POLICY,
                    ).fetchall(),
                    [(True,)],
                )
                drift_cases = (
                    (
                        "other-idempotency-key",
                        ["other-idempotency-key"],
                        *self._INITIAL_POLICY[2:],
                    ),
                    (
                        self._INITIAL_POLICY[0],
                        ["retained-idempotency-key", self._INITIAL_POLICY[0]],
                        *self._INITIAL_POLICY[2:],
                    ),
                    (
                        *self._INITIAL_POLICY[:4],
                        "appeal-command-json-v2",
                        *self._INITIAL_POLICY[5:],
                    ),
                    (
                        *self._INITIAL_POLICY[:5],
                        "other-sealed-key",
                        ["other-sealed-key"],
                    ),
                )
                for values in drift_cases:
                    self.assertEqual(
                        connection.execute(self._PROBE_SQL, values).fetchall(),
                        [],
                    )

        with psycopg.connect(
            self.postgres.conninfo(database=self.database, user="trust_self"),
            autocommit=True,
        ) as connection:
            connection.execute("BEGIN READ ONLY")
            self.assertEqual(
                connection.execute(
                    self._PROBE_SQL,
                    self._INITIAL_POLICY,
                ).fetchall(),
                [(True,)],
            )
            self.assertEqual(
                connection.execute(
                    "SELECT current_setting('app.appeal_scope_kind',true),"
                    "current_setting('app.trust_scope_kind',true),"
                    "NULLIF(current_setting('app.actor_id',true),'') IS NULL,"
                    "NULLIF(current_setting('app.organization_id',true),'') "
                    "IS NULL,NULLIF(current_setting('app.appeal_id',true),'') "
                    "IS NULL"
                ).fetchone(),
                (
                    "APPEAL_RUNTIME_READINESS",
                    "TRUST_RUNTIME_READINESS",
                    True,
                    True,
                    True,
                ),
            )
            connection.execute("COMMIT")
            self.assertEqual(
                connection.execute(
                    "SELECT NULLIF(current_setting("
                    "'app.appeal_scope_kind',true),'') IS NULL,"
                    "NULLIF(current_setting('app.trust_scope_kind',true),'') "
                    "IS NULL"
                ).fetchone(),
                (True, True),
            )

        rotated_policy = (
            "trust-idempotency-2026-02",
            ["trust-idempotency-2026-02", "trust-idempotency-2026-01"],
            "trust-payload-2026-02",
            ["trust-payload-2026-02", "trust-payload-2026-01"],
            "appeal-command-json-v1",
            "trust-sealed-note-v2",
            ["trust-sealed-note-v2", "trust-sealed-note-v1"],
        )
        self._rotate_runtime_policy(
            database=self.database,
            policy=rotated_policy,
        )
        try:
            with psycopg.connect(
                self.postgres.conninfo(
                    database=self.database,
                    user="trust_appeal",
                ),
                autocommit=True,
            ) as connection:
                self.assertEqual(
                    connection.execute(
                        self._PROBE_SQL,
                        self._INITIAL_POLICY,
                    ).fetchall(),
                    [],
                )
                self.assertEqual(
                    connection.execute(
                        self._PROBE_SQL,
                        rotated_policy,
                    ).fetchall(),
                    [(True,)],
                )
        finally:
            self._rotate_runtime_policy(
                database=self.database,
                policy=self._INITIAL_POLICY,
            )

        with psycopg.connect(
            self.postgres.admin_conninfo(database=self.database),
            autocommit=True,
        ) as connection:
            properties = connection.execute(
                "SELECT proc.prosecdef,proc.provolatile,proc.proparallel,"
                "proc.pronargs,proc.proretset,proc.proconfig "
                "FROM pg_catalog.pg_proc AS proc "
                "JOIN pg_catalog.pg_namespace AS namespace "
                "ON namespace.oid=proc.pronamespace "
                "WHERE namespace.nspname='trust_api' "
                "AND proc.proname='assert_appeal_runtime_policy_v1'"
            ).fetchone()
            self.assertEqual(
                properties,
                (True, "s", "r", 7, True, ["search_path=pg_catalog, trust"]),
            )
            grantees = connection.execute(
                "SELECT COALESCE(role.rolname,'PUBLIC') "
                "FROM pg_catalog.pg_proc AS proc "
                "JOIN pg_catalog.pg_namespace AS namespace "
                "ON namespace.oid=proc.pronamespace "
                "CROSS JOIN LATERAL pg_catalog.aclexplode(proc.proacl) AS acl "
                "LEFT JOIN pg_catalog.pg_roles AS role ON role.oid=acl.grantee "
                "WHERE namespace.nspname='trust_api' "
                "AND proc.proname='assert_appeal_runtime_policy_v1' "
                "AND acl.privilege_type='EXECUTE' ORDER BY 1"
            ).fetchall()
            self.assertEqual(
                grantees,
                [("trust_appeal",), ("trust_schema_owner",), ("trust_self",)],
            )

        for role in ("trust_officer", "trust_decision"):
            with psycopg.connect(
                self.postgres.conninfo(database=self.database, user=role),
                autocommit=True,
            ) as connection:
                with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                    connection.execute(self._PROBE_SQL, self._INITIAL_POLICY)

    def test_exact_trust0002_database_upgrades_through_current_head_and_replays(
        self,
    ) -> None:
        database = self.postgres.create_database()
        try:
            with psycopg.connect(
                self.postgres.admin_conninfo(database="postgres"),
                autocommit=True,
            ) as connection:
                connection.execute(
                    f'GRANT CREATE ON DATABASE "{database}" '
                    "TO trust_schema_owner"
                )
            self._apply_dependencies_to(database)
            catalog = TrustMigrationCatalog.load(TRUST_ROOT)
            with psycopg.connect(
                self.postgres.conninfo(
                    database=database,
                    user="trust_migration_runner",
                ),
                autocommit=True,
            ) as connection:
                connection.execute("SET ROLE trust_schema_owner")
                for artifact in catalog.artifacts[:2]:
                    descriptor = artifact.descriptor
                    connection.execute("BEGIN")
                    connection.execute(artifact.sql_bytes.decode("utf-8"))
                    connection.execute(
                        "INSERT INTO trust_meta.schema_migrations ("
                        "component,version,phase,name,checksum_sha256,"
                        "manifest_sha256,runner_version,applied_at) VALUES ("
                        "'trust',%s,%s,%s,%s,%s,'trust-runner-v2-proof',"
                        "transaction_timestamp())",
                        (
                            descriptor.version,
                            descriptor.phase.value,
                            descriptor.name,
                            descriptor.checksum_sha256,
                            descriptor.prefix_manifest_sha256,
                        ),
                    )
                    connection.execute("COMMIT")
                connection.execute(
                    "INSERT INTO trust_meta.schema_contracts ("
                    "singleton_key,schema_head_version,"
                    "min_app_compatible_version,max_app_compatible_version,"
                    "required_iam_schema_version,required_demand_schema_version,"
                    "required_iam_contract_sha256,"
                    "required_demand_contract_sha256,api_contract_sha256,"
                    "event_contract_sha256,report_contract_sha256,"
                    "triage_contract_sha256,appeal_api_contract_sha256,"
                    "appeal_event_contract_sha256,"
                    "appeal_application_contract_sha256,"
                    "appeal_review_contract_sha256,combined_contract_sha256,"
                    "migration_manifest_sha256,generated_at) VALUES ("
                    "true,2,2,2,36,8,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,"
                    "transaction_timestamp())",
                    (
                        _TRUST6_REQUIRED_IAM_CONTRACT_SHA256,
                        bytes.fromhex(
                            "7d67863b0ce45bf19011d7ed1975fb5a"
                            "73068f257c13083274689b2c8aa160f3"
                        ),
                        bytes.fromhex(
                            "14572f7768f31e9ced0b6ede09eb6eea"
                            "1da3d2d4abd1c6d80cc4229c28e158bd"
                        ),
                        TRUST_EVENT_CONTRACT_SHA256,
                        TRUST_REPORT_CONTRACT_SHA256,
                        TRUST_TRIAGE_CONTRACT_SHA256,
                        bytes.fromhex(
                            "e85d905e407679665e7bea0008253bc4"
                            "ec2bd941c4442964016caeb4ce62ffa7"
                        ),
                        TRUST_APPEAL_EVENT_CONTRACT_SHA256,
                        TRUST_APPEAL_APPLICATION_CONTRACT_SHA256,
                        TRUST_APPEAL_REVIEW_CONTRACT_SHA256,
                        bytes.fromhex(
                            "cb8092a39b9b4b2a4bce904ccfb40802"
                            "f12270a1fe41d9aa88daa564dc1a4a0f"
                        ),
                        catalog.artifacts[1].descriptor.prefix_manifest_sha256,
                    ),
                )

            upgraded = self._runner(database).run(
                catalog=catalog,
                contract_sources=self._contracts(),
            )
            replay = self._runner(database).run(
                catalog=catalog,
                contract_sources=self._contracts(),
            )
            self.assertEqual(
                upgraded.applied_versions,
                tuple(range(3, TRUST_SCHEMA_HEAD_VERSION + 1)),
            )
            self.assertEqual(upgraded.skipped_versions, (1, 2))
            self.assertEqual(replay.applied_versions, ())
            self.assertEqual(
                replay.skipped_versions,
                tuple(range(1, TRUST_SCHEMA_HEAD_VERSION + 1)),
            )
            with psycopg.connect(
                self.postgres.conninfo(database=database, user="trust_self"),
                autocommit=True,
            ) as connection:
                self.assertEqual(
                    connection.execute(
                        self._PROBE_SQL,
                        self._INITIAL_POLICY,
                    ).fetchall(),
                    [(True,)],
                )
        finally:
            self.postgres.drop_database(database)

    def test_exact_demand8_trust4_upgrade_to_current_heads_and_replay(
        self,
    ) -> None:
        database = self.postgres.create_database()
        try:
            with psycopg.connect(
                self.postgres.admin_conninfo(database="postgres"),
                autocommit=True,
            ) as connection:
                connection.execute(
                    f'GRANT CREATE ON DATABASE "{database}" '
                    "TO trust_schema_owner"
                )
            demand_catalog, trust_catalog = self._prepare_exact_trust4_database(
                database
            )
            with psycopg.connect(
                self.postgres.admin_conninfo(database=database),
                autocommit=True,
            ) as connection:
                self.assertEqual(
                    connection.execute(
                        "SELECT schema_head_version,"
                        "required_demand_schema_version,"
                        "required_demand_contract_sha256,"
                        "migration_manifest_sha256 "
                        "FROM trust_meta.schema_contracts WHERE singleton_key"
                    ).fetchone(),
                    (
                        4,
                        8,
                        bytes.fromhex(
                            "7d67863b0ce45bf19011d7ed1975fb5a"
                            "73068f257c13083274689b2c8aa160f3"
                        ),
                        trust_catalog.artifacts[
                            3
                        ].descriptor.prefix_manifest_sha256,
                    ),
                )

            demand_upgrade = self._demand_runner(database).run(
                catalog=demand_catalog,
                contract_sources=self._demand_contracts(),
            )
            trust_upgrade = self._runner(database).run(
                catalog=trust_catalog,
                contract_sources=self._contracts(),
            )
            replay = self._runner(database).run(
                catalog=trust_catalog,
                contract_sources=self._contracts(),
            )

            self.assertEqual(
                demand_upgrade.applied_versions,
                tuple(range(9, DEMAND_SCHEMA_HEAD_VERSION + 1)),
            )
            self.assertEqual(
                demand_upgrade.skipped_versions,
                tuple(range(1, 9)),
            )
            self.assertEqual(
                trust_upgrade.applied_versions,
                tuple(range(5, TRUST_SCHEMA_HEAD_VERSION + 1)),
            )
            self.assertEqual(trust_upgrade.skipped_versions, (1, 2, 3, 4))
            self.assertEqual(replay.applied_versions, ())
            self.assertEqual(
                replay.skipped_versions,
                tuple(range(1, TRUST_SCHEMA_HEAD_VERSION + 1)),
            )
        finally:
            self.postgres.drop_database(database)

    def test_exact_trust5_database_upgrades_through_current_head_and_replays(
        self,
    ) -> None:
        database = self.postgres.create_database()
        try:
            with psycopg.connect(
                self.postgres.admin_conninfo(database="postgres"),
                autocommit=True,
            ) as connection:
                connection.execute(
                    f'GRANT CREATE ON DATABASE "{database}" '
                    "TO trust_schema_owner"
                )
            catalog = self._prepare_exact_trust5_database(database)

            upgraded = self._runner(database).run(
                catalog=catalog,
                contract_sources=self._contracts(),
            )
            replay = self._runner(database).run(
                catalog=catalog,
                contract_sources=self._contracts(),
            )

            self.assertEqual(
                upgraded.applied_versions,
                tuple(range(6, TRUST_SCHEMA_HEAD_VERSION + 1)),
            )
            self.assertEqual(upgraded.skipped_versions, (1, 2, 3, 4, 5))
            self.assertEqual(replay.applied_versions, ())
            self.assertEqual(
                replay.skipped_versions,
                tuple(range(1, TRUST_SCHEMA_HEAD_VERSION + 1)),
            )
            with psycopg.connect(
                self.postgres.admin_conninfo(database=database),
                autocommit=True,
            ) as connection:
                self.assertEqual(
                    connection.execute(
                        "SELECT current_schema_version,schema_head_version,"
                        "min_app_compatible_version,max_app_compatible_version,"
                        "combined_contract_sha256,migration_manifest_sha256 "
                        "FROM trust.schema_compatibility"
                    ).fetchone(),
                    (
                        TRUST_SCHEMA_HEAD_VERSION,
                        TRUST_SCHEMA_HEAD_VERSION,
                        TRUST_SCHEMA_HEAD_VERSION,
                        TRUST_SCHEMA_HEAD_VERSION,
                        TRUST_REVIEWED_COMBINED_CONTRACT_SHA256,
                        TRUST_REVIEWED_MANIFEST_SHA256,
                    ),
                )
                self.assertEqual(
                    connection.execute(
                        "SELECT to_regprocedure(%s) IS NOT NULL,"
                        "to_regprocedure(%s) IS NOT NULL,"
                        "to_regprocedure(%s) IS NOT NULL",
                        (
                            "trust_api.list_my_active_case_assignments_v1("
                            "uuid,uuid,integer)",
                            "trust_api.list_my_active_appeal_assignments_v1("
                            "uuid,uuid,integer)",
                            "trust_api.list_my_completed_case_assignments_v1("
                            "uuid,uuid,integer)",
                        ),
                    ).fetchone(),
                    (True, True, True),
                )
                self.assertEqual(
                    connection.execute(
                        "SELECT policyname FROM pg_catalog.pg_policies "
                        "WHERE schemaname='trust' AND policyname LIKE "
                        "'rls_trust_my_%_v1' ORDER BY policyname"
                    ).fetchall(),
                    [
                        ("rls_trust_my_appeal_assignment_releases_select_v1",),
                        ("rls_trust_my_appeal_assignments_select_v1",),
                        ("rls_trust_my_appeal_roots_select_v1",),
                        ("rls_trust_my_case_assignment_releases_select_v1",),
                        ("rls_trust_my_case_assignments_select_v1",),
                        ("rls_trust_my_case_holds_select_v1",),
                        ("rls_trust_my_case_roots_select_v1",),
                        (
                            "rls_trust_my_completed_appeal_"
                            "applications_select_v1",
                        ),
                        (
                            "rls_trust_my_completed_appeal_"
                            "assignments_select_v1",
                        ),
                        (
                            "rls_trust_my_completed_appeal_"
                            "decisions_select_v1",
                        ),
                        (
                            "rls_trust_my_completed_appeal_"
                            "review_drafts_select_v1",
                        ),
                        (
                            "rls_trust_my_completed_appeal_"
                            "roots_select_v1",
                        ),
                        ("rls_trust_my_completed_case_assignments_select_v1",),
                        ("rls_trust_my_completed_case_outcomes_select_v1",),
                        ("rls_trust_my_completed_case_roots_select_v1",),
                    ],
                )
        finally:
            self.postgres.drop_database(database)

    def test_exact_trust21_database_repins_to_iam46_and_replays(self) -> None:
        database = self.postgres.create_database()
        try:
            with psycopg.connect(
                self.postgres.admin_conninfo(database="postgres"),
                autocommit=True,
            ) as connection:
                connection.execute(
                    f'GRANT CREATE ON DATABASE "{database}" '
                    "TO trust_schema_owner"
                )
            self._apply_dependencies_to(database)
            catalog = TrustMigrationCatalog.load(TRUST_ROOT)
            with psycopg.connect(
                self.postgres.conninfo(
                    database=database,
                    user="trust_migration_runner",
                ),
                autocommit=True,
            ) as connection:
                connection.execute("SET ROLE trust_schema_owner")
                for artifact in catalog.artifacts[:21]:
                    descriptor = artifact.descriptor
                    connection.execute("BEGIN")
                    connection.execute(artifact.sql_bytes.decode("utf-8"))
                    connection.execute(
                        "INSERT INTO trust_meta.schema_migrations ("
                        "component,version,phase,name,checksum_sha256,"
                        "manifest_sha256,runner_version,applied_at) VALUES ("
                        "'trust',%s,%s,%s,%s,%s,'trust21-upgrade-proof',"
                        "transaction_timestamp())",
                        (
                            descriptor.version,
                            descriptor.phase.value,
                            descriptor.name,
                            descriptor.checksum_sha256,
                            descriptor.prefix_manifest_sha256,
                        ),
                    )
                    if descriptor.version == 21:
                        connection.execute(
                            "INSERT INTO trust_meta.schema_contracts ("
                            "singleton_key,schema_head_version,"
                            "min_app_compatible_version,max_app_compatible_version,"
                            "required_iam_schema_version,"
                            "required_demand_schema_version,"
                            "required_iam_contract_sha256,"
                            "required_demand_contract_sha256,api_contract_sha256,"
                            "event_contract_sha256,report_contract_sha256,"
                            "triage_contract_sha256,appeal_api_contract_sha256,"
                            "appeal_event_contract_sha256,"
                            "appeal_application_contract_sha256,"
                            "appeal_review_contract_sha256,combined_contract_sha256,"
                            "migration_manifest_sha256,generated_at) VALUES ("
                            "true,21,21,21,45,15,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,"
                            "%s,%s,transaction_timestamp())",
                            (
                                bytes.fromhex(
                                    "3a1619b3d21567534df7f1331c6c39bb"
                                    "09c049be67deebf7988ff3b841e384fa"
                                ),
                                TRUST_REQUIRED_DEMAND_CONTRACT_SHA256,
                                TRUST_API_CONTRACT_SHA256,
                                TRUST_EVENT_CONTRACT_SHA256,
                                TRUST_REPORT_CONTRACT_SHA256,
                                TRUST_TRIAGE_CONTRACT_SHA256,
                                TRUST_APPEAL_API_CONTRACT_SHA256,
                                TRUST_APPEAL_EVENT_CONTRACT_SHA256,
                                TRUST_APPEAL_APPLICATION_CONTRACT_SHA256,
                                TRUST_APPEAL_REVIEW_CONTRACT_SHA256,
                                bytes.fromhex(
                                    "e5aeb13a1550a43f230db4b04e6559a3"
                                    "0897803716205cb9e9ab41868152e572"
                                ),
                                descriptor.prefix_manifest_sha256,
                            ),
                        )
                    connection.execute("COMMIT")

            upgraded = self._runner(database).run(
                catalog=catalog,
                contract_sources=self._contracts(),
            )
            replay = self._runner(database).run(
                catalog=catalog,
                contract_sources=self._contracts(),
            )

            self.assertEqual(upgraded.applied_versions, (22,))
            self.assertEqual(replay.applied_versions, ())
            with psycopg.connect(
                self.postgres.admin_conninfo(database=database),
                autocommit=True,
            ) as connection:
                contract = connection.execute(
                    "SELECT schema_head_version,required_iam_schema_version,"
                    "required_iam_contract_sha256,migration_manifest_sha256 "
                    "FROM trust_meta.schema_contracts WHERE singleton_key"
                ).fetchone()
            self.assertEqual(
                contract,
                (
                    22,
                    46,
                    TRUST_REQUIRED_IAM_CONTRACT_SHA256,
                    TRUST_REVIEWED_MANIFEST_SHA256,
                ),
            )
        finally:
            self.postgres.drop_database(database)

    def test_exact_trust6_to_9_trust7_ledger_failure_rolls_back_then_recovers(
        self,
    ) -> None:
        database = self.postgres.create_database()
        try:
            with psycopg.connect(
                self.postgres.admin_conninfo(database="postgres"),
                autocommit=True,
            ) as connection:
                connection.execute(
                    f'GRANT CREATE ON DATABASE "{database}" '
                    "TO trust_schema_owner"
                )
            catalog = self._prepare_exact_trust6_database(database)
            with psycopg.connect(
                self.postgres.admin_conninfo(database=database),
                autocommit=True,
            ) as connection:
                before_contract = connection.execute(
                    "SELECT * FROM trust_meta.schema_contracts"
                ).fetchall()
                before_constraints = connection.execute(
                    "SELECT conname,pg_get_constraintdef(oid,true) "
                    "FROM pg_catalog.pg_constraint "
                    "WHERE conrelid='trust_meta.schema_contracts'::regclass "
                    "AND conname IN ("
                    "'ck_trust_schema_contract_versions',"
                    "'ck_trust_schema_contract_hashes') ORDER BY conname"
                ).fetchall()
                before_business_surface = self._business_surface(connection)
                connection.execute(
                    "CREATE FUNCTION trust_meta.reject_trust7_ledger_v1() "
                    "RETURNS trigger LANGUAGE plpgsql AS $$BEGIN "
                    "IF NEW.version = 7 THEN RAISE EXCEPTION "
                    "'TRUST7_TEST_LEDGER_REJECTED'; END IF; RETURN NEW; END$$"
                )
                connection.execute(
                    "CREATE TRIGGER reject_trust7_ledger "
                    "BEFORE INSERT ON trust_meta.schema_migrations "
                    "FOR EACH ROW EXECUTE FUNCTION "
                    "trust_meta.reject_trust7_ledger_v1()"
                )

            with self.assertRaises(psycopg.errors.RaiseException):
                self._runner(database).run(
                    catalog=catalog,
                    contract_sources=self._contracts(),
                )

            with psycopg.connect(
                self.postgres.admin_conninfo(database=database),
                autocommit=True,
            ) as connection:
                self.assertEqual(
                    connection.execute(
                        "SELECT version FROM trust_meta.schema_migrations "
                        "WHERE component='trust' ORDER BY version"
                    ).fetchall(),
                    [(1,), (2,), (3,), (4,), (5,), (6,)],
                )
                self.assertEqual(
                    connection.execute(
                        "SELECT * FROM trust_meta.schema_contracts"
                    ).fetchall(),
                    before_contract,
                )
                self.assertEqual(
                    connection.execute(
                        "SELECT conname,pg_get_constraintdef(oid,true) "
                        "FROM pg_catalog.pg_constraint "
                        "WHERE conrelid="
                        "'trust_meta.schema_contracts'::regclass "
                        "AND conname IN ("
                        "'ck_trust_schema_contract_versions',"
                        "'ck_trust_schema_contract_hashes') ORDER BY conname"
                    ).fetchall(),
                    before_constraints,
                )
                self.assertEqual(
                    self._business_surface(connection),
                    before_business_surface,
                )
                self.assertEqual(
                    connection.execute(
                        "SELECT current_schema_version,schema_head_version,"
                        "required_iam_schema_version,"
                        "required_demand_schema_version "
                        "FROM trust.schema_compatibility"
                    ).fetchone(),
                    (6, 6, 36, 9),
                )
                self.assertEqual(
                    connection.execute(
                        "SELECT current_schema_version FROM "
                        "infra.iam_schema_compatibility"
                    ).fetchone(),
                    (IAM_SCHEMA_HEAD_VERSION,),
                )
                self.assertEqual(
                    connection.execute(
                        "SELECT current_schema_version FROM "
                        "demand.schema_compatibility"
                    ).fetchone(),
                    (DEMAND_SCHEMA_HEAD_VERSION,),
                )
                connection.execute(
                    "DROP TRIGGER reject_trust7_ledger "
                    "ON trust_meta.schema_migrations"
                )
                connection.execute(
                    "DROP FUNCTION trust_meta.reject_trust7_ledger_v1()"
                )

            recovered = self._runner(database).run(
                catalog=catalog,
                contract_sources=self._contracts(),
            )
            replay = self._runner(database).run(
                catalog=catalog,
                contract_sources=self._contracts(),
            )
            self.assertEqual(
                recovered.applied_versions,
                tuple(range(7, TRUST_SCHEMA_HEAD_VERSION + 1)),
            )
            self.assertEqual(recovered.skipped_versions, (1, 2, 3, 4, 5, 6))
            self.assertEqual(replay.applied_versions, ())
            self.assertEqual(
                replay.skipped_versions,
                tuple(range(1, TRUST_SCHEMA_HEAD_VERSION + 1)),
            )

            with psycopg.connect(
                self.postgres.admin_conninfo(database=database),
                autocommit=True,
            ) as connection:
                self.assertEqual(
                    connection.execute(
                        "SELECT current_schema_version,schema_head_version,"
                        "required_iam_schema_version,"
                        "required_demand_schema_version,"
                        "required_iam_contract_sha256,"
                        "required_demand_contract_sha256,"
                        "combined_contract_sha256,migration_manifest_sha256 "
                        "FROM trust.schema_compatibility"
                    ).fetchone(),
                    (
                        TRUST_SCHEMA_HEAD_VERSION,
                        TRUST_SCHEMA_HEAD_VERSION,
                        TRUST_REQUIRED_IAM_SCHEMA_VERSION,
                        TRUST_REQUIRED_DEMAND_SCHEMA_VERSION,
                        TRUST_REQUIRED_IAM_CONTRACT_SHA256,
                        TRUST_REQUIRED_DEMAND_CONTRACT_SHA256,
                        TRUST_REVIEWED_COMBINED_CONTRACT_SHA256,
                        TRUST_REVIEWED_MANIFEST_SHA256,
                    ),
                )
                self._assert_discovery_business_additions_are_exact(
                    before_business_surface,
                    self._business_surface(connection),
                )
        finally:
            self.postgres.drop_database(database)

    def test_exact_trust7_to_8_ledger_failure_rolls_back_then_head_recovers(
        self,
    ) -> None:
        database = self.postgres.create_database()
        try:
            with psycopg.connect(
                self.postgres.admin_conninfo(database="postgres"),
                autocommit=True,
            ) as connection:
                connection.execute(
                    f'GRANT CREATE ON DATABASE "{database}" '
                    "TO trust_schema_owner"
                )
            catalog = self._prepare_exact_trust7_database(database)
            with psycopg.connect(
                self.postgres.admin_conninfo(database=database),
                autocommit=True,
            ) as connection:
                before_contract = connection.execute(
                    "SELECT * FROM trust_meta.schema_contracts"
                ).fetchall()
                before_constraints = connection.execute(
                    "SELECT conname,pg_get_constraintdef(oid,true) "
                    "FROM pg_catalog.pg_constraint "
                    "WHERE conrelid='trust_meta.schema_contracts'::regclass "
                    "AND conname IN ("
                    "'ck_trust_schema_contract_versions',"
                    "'ck_trust_schema_contract_hashes') ORDER BY conname"
                ).fetchall()
                before_business_surface = self._business_surface(connection)
                self.assertEqual(
                    connection.execute(
                        "SELECT current_schema_version,schema_head_version,"
                        "required_iam_schema_version,"
                        "required_demand_schema_version,"
                        "required_iam_contract_sha256,"
                        "required_demand_contract_sha256,"
                        "combined_contract_sha256,migration_manifest_sha256 "
                        "FROM trust.schema_compatibility"
                    ).fetchone(),
                    (
                        7,
                        7,
                        37,
                        10,
                        bytes.fromhex(
                            "595d5232153063b0b71a88b3776c737d"
                            "1fcd5ecaef4a4b832c5e40434929c486"
                        ),
                        bytes.fromhex(
                            "27ec6b585a9340cbd7119d7a9b46d609"
                            "8a3881f88ae1be9e00df3713c0107113"
                        ),
                        bytes.fromhex(
                            "ab857f25969d17afe63886afe136cda1"
                            "0814e538517c54c180503b82f5785c1b"
                        ),
                        bytes.fromhex(
                            "27a51c55bddfcb2a4f1bd16a3160abbb"
                            "3a417425f14077f4886c3c41c22d5124"
                        ),
                    ),
                )
                connection.execute(
                    "CREATE FUNCTION trust_meta.reject_trust8_ledger_v1() "
                    "RETURNS trigger LANGUAGE plpgsql AS $$BEGIN "
                    "IF NEW.version = 8 THEN RAISE EXCEPTION "
                    "'TRUST8_TEST_LEDGER_REJECTED'; END IF; RETURN NEW; END$$"
                )
                connection.execute(
                    "CREATE TRIGGER reject_trust8_ledger "
                    "BEFORE INSERT ON trust_meta.schema_migrations "
                    "FOR EACH ROW EXECUTE FUNCTION "
                    "trust_meta.reject_trust8_ledger_v1()"
                )

            with self.assertRaises(psycopg.errors.RaiseException):
                self._runner(database).run(
                    catalog=catalog,
                    contract_sources=self._contracts(),
                )

            with psycopg.connect(
                self.postgres.admin_conninfo(database=database),
                autocommit=True,
            ) as connection:
                self.assertEqual(
                    connection.execute(
                        "SELECT version FROM trust_meta.schema_migrations "
                        "WHERE component='trust' ORDER BY version"
                    ).fetchall(),
                    [(1,), (2,), (3,), (4,), (5,), (6,), (7,)],
                )
                self.assertEqual(
                    connection.execute(
                        "SELECT * FROM trust_meta.schema_contracts"
                    ).fetchall(),
                    before_contract,
                )
                self.assertEqual(
                    connection.execute(
                        "SELECT conname,pg_get_constraintdef(oid,true) "
                        "FROM pg_catalog.pg_constraint "
                        "WHERE conrelid="
                        "'trust_meta.schema_contracts'::regclass "
                        "AND conname IN ("
                        "'ck_trust_schema_contract_versions',"
                        "'ck_trust_schema_contract_hashes') ORDER BY conname"
                    ).fetchall(),
                    before_constraints,
                )
                self.assertEqual(
                    self._business_surface(connection),
                    before_business_surface,
                )
                connection.execute(
                    "DROP TRIGGER reject_trust8_ledger "
                    "ON trust_meta.schema_migrations"
                )
                connection.execute(
                    "DROP FUNCTION trust_meta.reject_trust8_ledger_v1()"
                )

            recovered = self._runner(database).run(
                catalog=catalog,
                contract_sources=self._contracts(),
            )
            replay = self._runner(database).run(
                catalog=catalog,
                contract_sources=self._contracts(),
            )
            self.assertEqual(
                recovered.applied_versions,
                tuple(range(8, TRUST_SCHEMA_HEAD_VERSION + 1)),
            )
            self.assertEqual(
                recovered.skipped_versions,
                (1, 2, 3, 4, 5, 6, 7),
            )
            self.assertEqual(replay.applied_versions, ())
            self.assertEqual(
                replay.skipped_versions,
                tuple(range(1, TRUST_SCHEMA_HEAD_VERSION + 1)),
            )
            with psycopg.connect(
                self.postgres.admin_conninfo(database=database),
                autocommit=True,
            ) as connection:
                self.assertEqual(
                    connection.execute(
                        "SELECT current_schema_version,schema_head_version,"
                        "required_iam_schema_version,"
                        "required_demand_schema_version,"
                        "required_iam_contract_sha256,"
                        "required_demand_contract_sha256,"
                        "combined_contract_sha256,migration_manifest_sha256 "
                        "FROM trust.schema_compatibility"
                    ).fetchone(),
                    (
                        TRUST_SCHEMA_HEAD_VERSION,
                        TRUST_SCHEMA_HEAD_VERSION,
                        TRUST_REQUIRED_IAM_SCHEMA_VERSION,
                        TRUST_REQUIRED_DEMAND_SCHEMA_VERSION,
                        TRUST_REQUIRED_IAM_CONTRACT_SHA256,
                        TRUST_REQUIRED_DEMAND_CONTRACT_SHA256,
                        TRUST_REVIEWED_COMBINED_CONTRACT_SHA256,
                        TRUST_REVIEWED_MANIFEST_SHA256,
                    ),
                )
                self._assert_discovery_business_additions_are_exact(
                    before_business_surface,
                    self._business_surface(connection),
                )
        finally:
            self.postgres.drop_database(database)

    def test_trust6_failure_rolls_back_metadata_and_objects_atomically(
        self,
    ) -> None:
        database = self.postgres.create_database()
        try:
            with psycopg.connect(
                self.postgres.admin_conninfo(database="postgres"),
                autocommit=True,
            ) as connection:
                connection.execute(
                    f'GRANT CREATE ON DATABASE "{database}" '
                    "TO trust_schema_owner"
                )
            catalog = self._prepare_exact_trust5_database(database)
            with psycopg.connect(
                self.postgres.admin_conninfo(database=database),
                autocommit=True,
            ) as connection:
                before_contract = connection.execute(
                    "SELECT * FROM trust_meta.schema_contracts"
                ).fetchall()
                before_constraints = connection.execute(
                    "SELECT conname,pg_get_constraintdef(oid,true) "
                    "FROM pg_catalog.pg_constraint "
                    "WHERE conrelid='trust_meta.schema_contracts'::regclass "
                    "AND conname IN ("
                    "'ck_trust_schema_contract_versions',"
                    "'ck_trust_schema_contract_hashes') ORDER BY conname"
                ).fetchall()
                connection.execute(
                    "CREATE FUNCTION trust_meta.reject_trust6_ledger_v1() "
                    "RETURNS trigger LANGUAGE plpgsql AS $$BEGIN "
                    "IF NEW.version = 6 THEN RAISE EXCEPTION "
                    "'TRUST6_TEST_LEDGER_REJECTED'; END IF; RETURN NEW; END$$"
                )
                connection.execute(
                    "CREATE TRIGGER reject_trust6_ledger "
                    "BEFORE INSERT ON trust_meta.schema_migrations "
                    "FOR EACH ROW EXECUTE FUNCTION "
                    "trust_meta.reject_trust6_ledger_v1()"
                )

            with self.assertRaises(psycopg.errors.RaiseException):
                self._runner(database).run(
                    catalog=catalog,
                    contract_sources=self._contracts(),
                )

            with psycopg.connect(
                self.postgres.admin_conninfo(database=database),
                autocommit=True,
            ) as connection:
                self.assertEqual(
                    connection.execute(
                        "SELECT version FROM trust_meta.schema_migrations "
                        "WHERE component='trust' ORDER BY version"
                    ).fetchall(),
                    [(1,), (2,), (3,), (4,), (5,)],
                )
                self.assertEqual(
                    connection.execute(
                        "SELECT * FROM trust_meta.schema_contracts"
                    ).fetchall(),
                    before_contract,
                )
                self.assertEqual(
                    connection.execute(
                        "SELECT conname,pg_get_constraintdef(oid,true) "
                        "FROM pg_catalog.pg_constraint "
                        "WHERE conrelid="
                        "'trust_meta.schema_contracts'::regclass "
                        "AND conname IN ("
                        "'ck_trust_schema_contract_versions',"
                        "'ck_trust_schema_contract_hashes') ORDER BY conname"
                    ).fetchall(),
                    before_constraints,
                )
                self.assertEqual(
                    connection.execute(
                        "SELECT to_regprocedure(%s),to_regprocedure(%s)",
                        (
                            "trust_api.list_my_active_case_assignments_v1("
                            "uuid,uuid,integer)",
                            "trust_api.list_my_active_appeal_assignments_v1("
                            "uuid,uuid,integer)",
                        ),
                    ).fetchone(),
                    (None, None),
                )
                self.assertEqual(
                    connection.execute(
                        "SELECT policyname FROM pg_catalog.pg_policies "
                        "WHERE schemaname='trust' AND policyname LIKE "
                        "'rls_trust_my_%_v1'"
                    ).fetchall(),
                    [],
                )
        finally:
            self.postgres.drop_database(database)

    def test_trust5_failure_rolls_back_metadata_and_ledger_atomically(
        self,
    ) -> None:
        database = self.postgres.create_database()
        try:
            with psycopg.connect(
                self.postgres.admin_conninfo(database="postgres"),
                autocommit=True,
            ) as connection:
                connection.execute(
                    f'GRANT CREATE ON DATABASE "{database}" '
                    "TO trust_schema_owner"
                )
            demand_catalog, trust_catalog = self._prepare_exact_trust4_database(
                database
            )
            self._demand_runner(database).run(
                catalog=demand_catalog,
                contract_sources=self._demand_contracts(),
            )
            with psycopg.connect(
                self.postgres.admin_conninfo(database=database),
                autocommit=True,
            ) as connection:
                before_contract = connection.execute(
                    "SELECT * FROM trust_meta.schema_contracts"
                ).fetchall()
                before_constraints = connection.execute(
                    "SELECT conname,pg_get_constraintdef(oid,true) "
                    "FROM pg_catalog.pg_constraint "
                    "WHERE conrelid='trust_meta.schema_contracts'::regclass "
                    "AND conname IN ("
                    "'ck_trust_schema_contract_versions',"
                    "'ck_trust_schema_contract_hashes') ORDER BY conname"
                ).fetchall()
                connection.execute(
                    "CREATE FUNCTION trust_meta.reject_trust5_ledger_v1() "
                    "RETURNS trigger LANGUAGE plpgsql AS $$BEGIN "
                    "IF NEW.version = 5 THEN RAISE EXCEPTION "
                    "'TRUST5_TEST_LEDGER_REJECTED'; END IF; RETURN NEW; END$$"
                )
                connection.execute(
                    "CREATE TRIGGER reject_trust5_ledger "
                    "BEFORE INSERT ON trust_meta.schema_migrations "
                    "FOR EACH ROW EXECUTE FUNCTION "
                    "trust_meta.reject_trust5_ledger_v1()"
                )

            with self.assertRaises(psycopg.errors.RaiseException):
                self._runner(database).run(
                    catalog=trust_catalog,
                    contract_sources=self._contracts(),
                )

            with psycopg.connect(
                self.postgres.admin_conninfo(database=database),
                autocommit=True,
            ) as connection:
                self.assertEqual(
                    connection.execute(
                        "SELECT version FROM trust_meta.schema_migrations "
                        "WHERE component='trust' ORDER BY version"
                    ).fetchall(),
                    [(1,), (2,), (3,), (4,)],
                )
                self.assertEqual(
                    connection.execute(
                        "SELECT * FROM trust_meta.schema_contracts"
                    ).fetchall(),
                    before_contract,
                )
                self.assertEqual(
                    connection.execute(
                        "SELECT conname,pg_get_constraintdef(oid,true) "
                        "FROM pg_catalog.pg_constraint "
                        "WHERE conrelid="
                        "'trust_meta.schema_contracts'::regclass "
                        "AND conname IN ("
                        "'ck_trust_schema_contract_versions',"
                        "'ck_trust_schema_contract_hashes') ORDER BY conname"
                    ).fetchall(),
                    before_constraints,
                )
        finally:
            self.postgres.drop_database(database)


if __name__ == "__main__":
    unittest.main()
