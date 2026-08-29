"""Non-skippable PostgreSQL 18 migration and adapter integration evidence."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import threading
import unittest

import psycopg

from desire_platform.identity_access.adapters.postgres.migrations import (
    IAM_MAX_APP_COMPATIBLE_VERSION,
    IAM_MIGRATION_LOCK,
    IAM_MIGRATION_SCHEMA_ROLE,
    IAM_MIGRATION_SESSION_ROLE,
    IAM_MIN_APP_COMPATIBLE_VERSION,
    IAM_POSTGRES_MAJOR,
    IAM_SCHEMA_HEAD_VERSION,
    IamContractParameters,
    IamContractSources,
    IamMigrationRunner,
    MigrationCatalog,
    MigrationLedgerRecord,
    MigrationRunnerError,
    PsycopgMigrationDriver,
    PsycopgMigrationSettings,
)
from tests.storage.postgres.postgres18_harness import TemporaryPostgres18


PLATFORM_ROOT = Path(__file__).resolve().parents[3]
MIGRATION_ROOT = (
    PLATFORM_ROOT
    / "src/desire_platform/identity_access/adapters/postgres/migrations"
)
RLS_RELATIONS = (
    ("iam", "policy_selectors"),
    ("iam", "policy_documents"),
    ("iam", "policy_bundles"),
    ("iam", "policy_bundle_documents"),
    ("iam", "consent_offers"),
    ("iam", "consent_offer_data_categories"),
    ("iam", "users"),
    ("iam", "external_identities"),
    ("iam", "contact_points"),
    ("iam", "organizations"),
    ("iam", "access_invitations"),
    ("iam", "memberships"),
    ("iam", "user_role_grants"),
    ("iam", "membership_role_grants"),
    ("iam", "platform_duty_grants"),
    ("iam", "auth_transactions"),
    ("iam", "session_families"),
    ("iam", "sessions"),
    ("iam", "session_security_events"),
    ("iam", "policy_acceptances"),
    ("iam", "consent_grants"),
    ("iam", "consent_grant_data_categories"),
    ("iam", "consent_withdrawals"),
    ("infra", "command_receipts"),
    ("infra", "iam_receipt_key_policy"),
    ("audit", "audit_events"),
    ("infra", "outbox_events"),
    ("infra", "consumer_principals"),
    ("infra", "consumer_inbox_events"),
    ("infra", "iam_sandbox_bootstrap_state"),
    ("infra", "iam_sandbox_bootstrap_accounts"),
    ("infra", "iam_sandbox_bootstrap_runs"),
    ("infra", "iam_sandbox_bootstrap_manifest_bridges"),
)


class RealPostgres18MigrationIntegrationTest(unittest.TestCase):
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

    def tearDown(self) -> None:
        self.postgres.drop_database(self.database)

    def test_clean_catalog_head_and_exact_rerun_are_real_postgres_green(self) -> None:
        first = self._run(self.catalog)
        self.assertEqual(
            first.applied_versions,
            tuple(artifact.descriptor.version for artifact in self.catalog.artifacts),
        )
        self.assertEqual(first.recovered_versions, ())
        self.assertEqual(first.skipped_versions, ())

        with self._connect_admin() as connection:
            ledger = connection.execute(
                "SELECT component, version, phase, name, checksum_sha256 "
                "FROM infra.schema_migrations ORDER BY version"
            ).fetchall()
            compatibility = connection.execute(
                "SELECT component, current_schema_version, schema_head_version, "
                "min_app_compatible_version, max_app_compatible_version, "
                "combined_contract_sha256 "
                "FROM infra.iam_schema_compatibility"
            ).fetchone()
            contract = connection.execute(
                "SELECT api_contract_sha256, event_contract_sha256, "
                "migration_manifest_sha256, combined_contract_sha256 "
                "FROM infra.iam_schema_contracts WHERE component = 'iam'"
            ).fetchone()
            rls_rows = connection.execute(
                "SELECT n.nspname, c.relname "
                "FROM pg_catalog.pg_class AS c "
                "JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace "
                "WHERE c.relrowsecurity AND c.relforcerowsecurity"
            ).fetchall()
            duty_constraint = connection.execute(
                "SELECT pg_catalog.pg_get_constraintdef(oid) "
                "FROM pg_catalog.pg_constraint "
                "WHERE conname = 'ck_platform_duty_code'"
            ).fetchone()
            duty_policies = connection.execute(
                "SELECT policyname FROM pg_catalog.pg_policies "
                "WHERE schemaname='iam' AND tablename='platform_duty_grants' "
                "ORDER BY policyname"
            ).fetchall()
            duty_indexes = connection.execute(
                "SELECT indexname FROM pg_catalog.pg_indexes "
                "WHERE schemaname='iam' AND tablename='platform_duty_grants' "
                "ORDER BY indexname"
            ).fetchall()

        self.assertEqual(
            ledger,
            [
                (
                    artifact.descriptor.component,
                    artifact.descriptor.version,
                    artifact.descriptor.phase.value,
                    artifact.descriptor.name,
                    artifact.descriptor.checksum_sha256,
                )
                for artifact in self.catalog.artifacts
            ],
        )
        self.assertIsNotNone(compatibility)
        self.assertEqual(
            compatibility[:5],
            (
                "iam",
                IAM_SCHEMA_HEAD_VERSION,
                IAM_MIN_APP_COMPATIBLE_VERSION,
                IAM_MAX_APP_COMPATIBLE_VERSION,
                IAM_SCHEMA_HEAD_VERSION,
            ),
        )
        api_hash = hashlib.sha256(
            self.contract_sources.api_contract_bytes
        ).digest()
        event_hash = hashlib.sha256(
            self.contract_sources.event_contract_bytes
        ).digest()
        combined_hash = hashlib.sha256(
            b"iam-v1-contract"
            + b"\x00"
            + api_hash
            + event_hash
            + self.catalog.manifest_sha256
        ).digest()
        self.assertEqual(
            contract,
            (api_hash, event_hash, self.catalog.manifest_sha256, combined_hash),
        )
        self.assertEqual(compatibility[5], combined_hash)
        self.assertEqual(set(rls_rows), set(RLS_RELATIONS))
        self.assertIsNotNone(duty_constraint)
        for duty_code in (
            "ACCESS_ADMIN",
            "OPERATIONS_REVIEWER",
            "FINANCE_OPERATOR",
            "TRUST_OFFICER",
            "APPEAL_REVIEWER",
        ):
            self.assertIn(duty_code, duty_constraint[0])
        self.assertTrue(
            {
                ("rls_authority_marker_reviewer_duty_definer",),
                ("rls_editor_principal_platform_duty_definer",),
                ("rls_finance_funding_iam_duty_definer",),
                ("rls_platform_admin_duty_definer",),
                ("rls_platform_duty_self_select",),
                ("rls_platform_duty_system",),
                ("rls_sandbox_bootstrap_platform_duty_grants",),
            }.issubset(set(duty_policies)),
        )
        self.assertIn(("ux_platform_duty_grant_active",), duty_indexes)

        second = self._run(self.catalog)
        self.assertEqual(second.applied_versions, ())
        self.assertEqual(second.recovered_versions, ())
        self.assertEqual(
            second.skipped_versions,
            tuple(artifact.descriptor.version for artifact in self.catalog.artifacts),
        )

    def test_two_real_runners_serialize_and_second_observes_exact_ledger(self) -> None:
        barrier = threading.Barrier(2)

        def run_after_barrier():
            barrier.wait(timeout=10)
            return self._run(self.catalog)

        with ThreadPoolExecutor(max_workers=2) as executor:
            reports = tuple(executor.map(lambda _index: run_after_barrier(), range(2)))

        applied = [report for report in reports if report.applied_versions]
        skipped = [report for report in reports if report.skipped_versions]
        self.assertEqual(len(applied), 1)
        expected_versions = tuple(
            artifact.descriptor.version for artifact in self.catalog.artifacts
        )
        self.assertEqual(applied[0].applied_versions, expected_versions)
        self.assertEqual(len(skipped), 1)
        self.assertEqual(skipped[0].skipped_versions, expected_versions)
        with self._connect_admin() as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT count(*), count(DISTINCT version) "
                    "FROM infra.schema_migrations WHERE component = 'iam'"
                ).fetchone(),
                (len(self.catalog.artifacts), len(self.catalog.artifacts)),
            )

    def test_iam36_prefix_upgrades_through_current_head_then_exactly_replays(
        self,
    ) -> None:
        old_manifest_hash, _old_combined_hash = self._install_iam36_prefix()

        upgrade = self._run(self.catalog)
        self.assertEqual(
            upgrade.applied_versions,
            tuple(range(37, IAM_SCHEMA_HEAD_VERSION + 1)),
        )
        self.assertEqual(upgrade.recovered_versions, ())
        self.assertEqual(upgrade.skipped_versions, tuple(range(37)))

        replay = self._run(self.catalog)
        self.assertEqual(replay.applied_versions, ())
        self.assertEqual(replay.recovered_versions, ())
        self.assertEqual(
            replay.skipped_versions,
            tuple(range(IAM_SCHEMA_HEAD_VERSION + 1)),
        )

        with self._connect_admin() as connection:
            ledgers = connection.execute(
                "SELECT version,phase,name,checksum_sha256 "
                "FROM infra.schema_migrations "
                "WHERE component='iam' AND version IN (37,38) "
                "ORDER BY version"
            ).fetchall()
            contract = connection.execute(
                "SELECT schema_head_version,migration_manifest_sha256 "
                "FROM infra.iam_schema_contracts WHERE component='iam'"
            ).fetchone()
        self.assertEqual(
            ledgers,
            [
                (
                    artifact.descriptor.version,
                    artifact.descriptor.phase.value,
                    artifact.descriptor.name,
                    artifact.descriptor.checksum_sha256,
                )
                for artifact in self.catalog.artifacts[37:39]
            ],
        )
        self.assertEqual(
            tuple(row[2] for row in ledgers),
            (
                "finance_funding_review_authority_v2",
                "owned_session_revocation",
            ),
        )
        self.assertEqual(
            contract,
            (IAM_SCHEMA_HEAD_VERSION, self.catalog.manifest_sha256),
        )
        self.assertNotEqual(old_manifest_hash, self.catalog.manifest_sha256)

    def test_iam37_failure_rolls_back_context_contract_and_ledger(self) -> None:
        old_manifest_hash, old_combined_hash = self._install_iam36_prefix()
        with self._connect_admin(autocommit=True) as connection:
            connection.execute(
                "CREATE FUNCTION public.desire_fail_iam37_function_ddl() "
                "RETURNS event_trigger LANGUAGE plpgsql AS $$ "
                "DECLARE ddl_command record; BEGIN FOR ddl_command IN "
                "SELECT * FROM pg_catalog.pg_event_trigger_ddl_commands() LOOP "
                "IF ddl_command.command_tag='CREATE FUNCTION' AND "
                "ddl_command.schema_name IN ('iam','iam_api') THEN "
                "RAISE EXCEPTION 'injected IAM37 failure' USING ERRCODE='P0001'; "
                "END IF; END LOOP; END $$"
            )
            connection.execute(
                "CREATE EVENT TRIGGER desire_fail_iam37_function_ddl "
                "ON ddl_command_end EXECUTE FUNCTION "
                "public.desire_fail_iam37_function_ddl()"
            )

        with self.assertRaises(psycopg.errors.RaiseException):
            self._run(self.catalog)

        with self._connect_admin() as connection:
            ledger = connection.execute(
                "SELECT count(*),max(version) FROM infra.schema_migrations "
                "WHERE component='iam'"
            ).fetchone()
            context = connection.execute(
                "SELECT pg_catalog.pg_get_functiondef("
                "'iam.finance_funding_authority_context_v1()'::regprocedure)"
            ).fetchone()[0]
            v2 = connection.execute(
                "SELECT pg_catalog.to_regprocedure("
                "'iam_api.lock_finance_funding_authority_v2("
                "uuid,uuid,uuid,uuid,uuid,uuid,text,bytea)')"
            ).fetchone()[0]
            contract = connection.execute(
                "SELECT schema_head_version,min_app_compatible_version,"
                "max_app_compatible_version,migration_manifest_sha256,"
                "combined_contract_sha256 FROM infra.iam_schema_contracts "
                "WHERE component='iam'"
            ).fetchone()

        self.assertEqual(ledger, (37, 36))
        self.assertIn("CONFIRM_FUNDING_REVIEW", context)
        self.assertNotIn("RELEASE_FUNDING_REVIEW_ASSIGNMENT", context)
        self.assertNotIn("SUBMIT_FUNDING_REVIEW_FINDING", context)
        self.assertIsNone(v2)
        self.assertEqual(
            contract,
            (36, 36, 36, old_manifest_hash, old_combined_hash),
        )

    def test_real_sql_failure_rolls_back_entire_file_and_ledger_row(self) -> None:
        with self._connect_admin(autocommit=True) as connection:
            connection.execute(
                "CREATE FUNCTION public.desire_fail_iam_schema_migrations() "
                "RETURNS event_trigger LANGUAGE plpgsql AS $$ "
                "DECLARE ddl_command record; "
                "BEGIN "
                "FOR ddl_command IN "
                "SELECT * FROM pg_catalog.pg_event_trigger_ddl_commands() LOOP "
                "IF ddl_command.object_identity = 'infra.schema_migrations' THEN "
                "RAISE EXCEPTION 'injected migration failure' USING ERRCODE = 'P0001'; "
                "END IF; "
                "END LOOP; "
                "END $$"
            )
            connection.execute(
                "CREATE EVENT TRIGGER desire_fail_iam_schema_migrations "
                "ON ddl_command_end EXECUTE FUNCTION "
                "public.desire_fail_iam_schema_migrations()"
            )

        with self.assertRaises(psycopg.errors.RaiseException):
            self._run(self.catalog)

        with self._connect_admin() as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT pg_catalog.to_regnamespace('iam'), "
                    "pg_catalog.to_regnamespace('infra'), "
                    "pg_catalog.to_regnamespace('audit'), "
                    "pg_catalog.to_regnamespace('iam_api')"
                ).fetchone(),
                (None, None, None, None),
            )
            self.assertIsNone(
                connection.execute(
                    "SELECT pg_catalog.to_regclass('infra.schema_migrations')"
                ).fetchone()[0]
            )

    def test_real_ledger_checksum_drift_fails_before_new_ddl_or_receipt(self) -> None:
        self._run(self.catalog)
        with self._connect_admin(autocommit=True) as connection:
            connection.execute(
                "UPDATE infra.schema_migrations SET checksum_sha256 = %s "
                "WHERE component = 'iam' AND version = 3",
                (b"!" * 32,),
            )

        with self.assertRaises(MigrationRunnerError) as raised:
            self._run(self.catalog)
        self.assertEqual(raised.exception.code, "MIGRATION_LEDGER_DRIFT")
        with self._connect_admin() as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT count(*) FROM infra.schema_migrations"
                ).fetchone()[0],
                len(self.catalog.artifacts),
            )
            self.assertEqual(
                connection.execute(
                    "SELECT count(*) FROM infra.iam_schema_contracts"
                ).fetchone()[0],
                1,
            )

    def _run(self, catalog: MigrationCatalog):
        return IamMigrationRunner(
            driver=self._migration_driver(),
            runner_version="real-pg18-test/1",
        ).run(catalog=catalog, contract_sources=self.contract_sources)

    def _migration_driver(self) -> PsycopgMigrationDriver:
        return PsycopgMigrationDriver(
            settings=PsycopgMigrationSettings(
                conninfo=self.postgres.conninfo(
                    database=self.database,
                    user="iam_migration_runner",
                ),
                application_name="desire-iam-real-pg18-test",
            ),
            dbapi=psycopg,
        )

    def _install_iam36_prefix(self) -> tuple[bytes, bytes]:
        entries = json.loads(self.catalog.manifest_bytes)
        self.assertGreater(IAM_SCHEMA_HEAD_VERSION, 38)
        self.assertEqual(
            tuple(entry["version"] for entry in entries[:39]),
            tuple(range(39)),
        )
        self.assertEqual(entries[37]["name"], "finance_funding_review_authority_v2")
        self.assertEqual(entries[38]["name"], "owned_session_revocation")
        old_manifest_bytes = (
            json.dumps(entries[:37], ensure_ascii=True, separators=(",", ":"))
            .encode("ascii")
            + b"\n"
        )
        old_manifest_hash = hashlib.sha256(old_manifest_bytes).digest()
        api_hash = hashlib.sha256(
            self.contract_sources.api_contract_bytes
        ).digest()
        event_hash = hashlib.sha256(
            self.contract_sources.event_contract_bytes
        ).digest()
        old_combined_hash = hashlib.sha256(
            b"iam-v1-contract"
            + b"\x00"
            + api_hash
            + event_hash
            + old_manifest_hash
        ).digest()
        contract_parameters = IamContractParameters(
            component="iam",
            schema_head_version=36,
            min_app_compatible_version=36,
            max_app_compatible_version=36,
            api_contract_sha256=api_hash,
            event_contract_sha256=event_hash,
            migration_manifest_sha256=old_manifest_hash,
            combined_contract_sha256=old_combined_hash,
        )

        session = self._migration_driver().connect(
            session_role=IAM_MIGRATION_SESSION_ROLE
        )
        locked = False
        transaction_active = False
        try:
            session.acquire_advisory_lock(*IAM_MIGRATION_LOCK)
            locked = True
            session.prepare_runner(
                schema_role=IAM_MIGRATION_SCHEMA_ROLE,
                postgres_major=IAM_POSTGRES_MAJOR,
            )
            state = session.inspect_database()
            self.assertFalse(state.ledger_exists)
            self.assertFalse(state.has_unledgered_iam_objects)
            self.assertEqual(state.applied_migrations, ())

            for artifact in self.catalog.artifacts[:37]:
                descriptor = artifact.descriptor
                session.begin_migration(descriptor)
                transaction_active = True
                session.set_local_timeouts()
                session.execute_artifact(artifact)
                session.assert_artifact(descriptor)
                if descriptor.version == 36:
                    session.insert_contract_row(contract_parameters)
                session.insert_ledger_row(
                    MigrationLedgerRecord.from_descriptor(descriptor),
                    runner_version="real-pg18-iam36-prefix-test/1",
                )
                session.commit_migration()
                transaction_active = False
        finally:
            if transaction_active:
                session.rollback_migration()
            if locked:
                session.release_advisory_lock(*IAM_MIGRATION_LOCK)
            session.close(discard=False)
        return old_manifest_hash, old_combined_hash

    def _connect_admin(self, *, autocommit: bool = False):
        return psycopg.connect(
            self.postgres.admin_conninfo(database=self.database),
            autocommit=autocommit,
        )
if __name__ == "__main__":
    unittest.main()
