"""Contract-first tests for the reviewed deployment migration composition."""

from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from desire_platform.deployment import migrations
from desire_platform.deployment import __main__ as deployment_main
from desire_platform.deployment.migrations import (
    DATABASE_ROLE_SPECS,
    MIGRATION_MEMBERSHIPS,
    DeploymentMigrationConfigurationError,
    DeploymentMigrationError,
    DeploymentMigrationSettings,
    load_settings,
)


EXPECTED_ROLES = {
    "schema_owner": False,
    "iam_migration_runner": True,
    "iam_app": True,
    "iam_session_authenticator": True,
    "iam_onboarding": True,
    "iam_sandbox_bootstrap": True,
    "iam_system": True,
    "iam_self_summary_reader": False,
    "iam_outbox_worker": True,
    "iam_projection_consumer": True,
    "iam_key_policy_operator": False,
    "audit_reader": False,
    "break_glass": False,
    "profile_schema_owner": False,
    "profile_migration_runner": True,
    "profile_app": True,
    "profile_matcher": True,
    "demand_schema_owner": False,
    "demand_migration_runner": True,
    "demand_self": True,
    "demand_review": True,
    "demand_finance": True,
    "demand_matching": True,
    "demand_system": True,
    "matching_schema_owner": False,
    "matching_migration_runner": True,
    "matching_creator": True,
    "matching_selector": True,
    "matching_assignment": True,
    "matching_review": True,
    "matching_worker": True,
    "matching_coordinator": True,
    "trust_schema_owner": False,
    "trust_migration_runner": True,
    "trust_self": True,
    "trust_officer": True,
    "trust_appeal": True,
    "trust_decision": True,
    "taxonomy_schema_owner": False,
    "taxonomy_migration_runner": True,
    "taxonomy_publisher": True,
    "taxonomy_admin": True,
    "taxonomy_reader": True,
    "taxonomy_consumer": True,
}


def iam42_public_name_preflight(
    *,
    relation_state: str = "ABSENT",
    inspected: int = 0,
    invalid: int = 0,
    length: int = 0,
    non_nfc: int = 0,
    edge_whitespace: int = 0,
    forbidden_codepoint: int = 0,
) -> migrations.Iam42PublicNamePreflightReport:
    return migrations.Iam42PublicNamePreflightReport(
        predicate_version=migrations.IAM42_PUBLIC_NAME_PREDICATE_VERSION,
        relation_state=relation_state,
        inspected_organization_count=inspected,
        invalid_organization_count=invalid,
        length_violation_count=length,
        non_nfc_count=non_nfc,
        edge_whitespace_count=edge_whitespace,
        forbidden_codepoint_count=forbidden_codepoint,
        status="BLOCKED" if invalid else "PASSED",
    )


class DeploymentMigrationSettingsTest(unittest.TestCase):
    def test_role_and_membership_contract_is_closed(self) -> None:
        self.assertEqual(dict(DATABASE_ROLE_SPECS), EXPECTED_ROLES)
        self.assertEqual(
            MIGRATION_MEMBERSHIPS,
            (
                ("schema_owner", "iam_migration_runner"),
                ("iam_self_summary_reader", "schema_owner"),
                ("profile_schema_owner", "profile_migration_runner"),
                ("demand_schema_owner", "demand_migration_runner"),
                ("schema_owner", "demand_migration_runner"),
                ("matching_schema_owner", "matching_migration_runner"),
                ("schema_owner", "matching_migration_runner"),
                ("profile_schema_owner", "matching_migration_runner"),
                ("demand_schema_owner", "matching_migration_runner"),
                ("trust_schema_owner", "matching_migration_runner"),
                ("trust_schema_owner", "trust_migration_runner"),
                ("schema_owner", "trust_migration_runner"),
                ("taxonomy_schema_owner", "taxonomy_migration_runner"),
            ),
        )
        self.assertEqual(
            migrations._MIGRATION_ROLES,
            (
                "iam_migration_runner",
                "profile_migration_runner",
                "demand_migration_runner",
                "matching_migration_runner",
                "trust_migration_runner",
                "taxonomy_migration_runner",
            ),
        )
        self.assertEqual(
            migrations._SCHEMA_CREATE_ROLES,
            (
                "profile_schema_owner",
                "demand_schema_owner",
                "matching_schema_owner",
                "trust_schema_owner",
                "taxonomy_schema_owner",
            ),
        )
        self.assertEqual(
            tuple(migrations.DeploymentMigrationReport.__dataclass_fields__),
            (
                "iam",
                "profile",
                "demand",
                "matching",
                "trust",
                "taxonomy",
                "iam42_public_name_preflight",
            ),
        )

    def test_iam42_public_name_preflight_report_is_closed_and_aggregate_only(self) -> None:
        report = iam42_public_name_preflight(
            relation_state="PRESENT", inspected=3
        )
        self.assertEqual(report.status, "PASSED")
        self.assertNotIn("public_name", repr(report).lower())
        invalid = (
            {**report.__dict__, "status": "BLOCKED"},
            {**report.__dict__, "invalid_organization_count": 1},
            {**report.__dict__, "relation_state": "ABSENT", "inspected_organization_count": 1},
        )
        for values in invalid:
            with self.subTest(values=values), self.assertRaises(ValueError):
                migrations.Iam42PublicNamePreflightReport(**values)

    def test_environment_loader_is_internal_sandbox_and_secret_file_only(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            secret = Path(directory) / "database-password"
            secret.write_text("a-database-password-with-32-bytes-minimum\n", encoding="utf-8")
            settings = load_settings(
                {
                    "DESIRE_DEPLOYMENT_MODE": "INTERNAL_SANDBOX",
                    "DESIRE_EXTERNAL_PARTICIPANTS_ENABLED": "false",
                    "DESIRE_DATABASE_HOST": "db",
                    "DESIRE_DATABASE_NAME": "desire",
                    "DESIRE_DATABASE_ADMIN_USER": "postgres",
                    "DESIRE_DATABASE_PASSWORD_FILE": str(secret),
                },
                allowed_secret_root=Path(directory),
            )
        self.assertIsInstance(settings, DeploymentMigrationSettings)
        self.assertEqual(settings.host, "db")
        self.assertNotIn(settings.admin_password, repr(settings))

    def test_loader_rejects_open_mode_inline_password_and_untrusted_locator(self) -> None:
        baseline = {
            "DESIRE_DEPLOYMENT_MODE": "INTERNAL_SANDBOX",
            "DESIRE_EXTERNAL_PARTICIPANTS_ENABLED": "false",
            "DESIRE_DATABASE_HOST": "db",
            "DESIRE_DATABASE_NAME": "desire",
            "DESIRE_DATABASE_ADMIN_USER": "postgres",
            "DESIRE_DATABASE_PASSWORD_FILE": "/run/secrets/db_superuser_password",
        }
        cases = (
            {**baseline, "DESIRE_DEPLOYMENT_MODE": "PRODUCTION"},
            {**baseline, "DESIRE_EXTERNAL_PARTICIPANTS_ENABLED": "true"},
            {**baseline, "DESIRE_DATABASE_HOST": "attacker.example"},
            {**baseline, "DESIRE_DATABASE_NAME": "desire;DROP"},
            {**baseline, "DESIRE_DATABASE_PASSWORD": "inline-forbidden"},
            {**baseline, "DESIRE_DATABASE_PASSWORD_FILE": "/tmp/password"},
        )
        for environment in cases:
            with self.subTest(environment=environment):
                with self.assertRaises(DeploymentMigrationConfigurationError):
                    load_settings(environment)

    def test_secret_shape_is_closed(self) -> None:
        baseline = {
            "DESIRE_DEPLOYMENT_MODE": "INTERNAL_SANDBOX",
            "DESIRE_EXTERNAL_PARTICIPANTS_ENABLED": "false",
            "DESIRE_DATABASE_HOST": "db",
            "DESIRE_DATABASE_NAME": "desire",
            "DESIRE_DATABASE_ADMIN_USER": "postgres",
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for index, value in enumerate((b"short", b"a" * 5000, b"a" * 30 + b"\x00")):
                secret = root / f"secret-{index}"
                secret.write_bytes(value)
                with self.subTest(index=index):
                    with self.assertRaises(DeploymentMigrationConfigurationError):
                        load_settings(
                            {**baseline, "DESIRE_DATABASE_PASSWORD_FILE": str(secret)},
                            allowed_secret_root=root,
                    )


class Iam42PublicNameDeploymentPreflightTest(unittest.TestCase):
    @staticmethod
    def _cursor(*, rows=None, row=None):
        cursor = Mock()
        cursor.fetchall.return_value = [] if rows is None else rows
        cursor.fetchone.return_value = row
        return cursor

    def test_absent_relation_is_a_zero_count_fresh_database_pass(self) -> None:
        connection = Mock()
        connection.execute.side_effect = (
            self._cursor(),
            self._cursor(),
            self._cursor(rows=[]),
            self._cursor(),
        )

        report = migrations._preflight_iam42_public_names(connection)

        self.assertEqual(report, iam42_public_name_preflight())
        self.assertEqual(
            [call.args[0] for call in connection.execute.call_args_list],
            [
                migrations._IAM42_PUBLIC_NAME_PREFLIGHT_BEGIN_SQL,
                migrations._IAM42_PUBLIC_NAME_PREFLIGHT_TIMEOUT_SQL,
                migrations._IAM42_PUBLIC_NAME_RELATION_SQL,
                "COMMIT",
            ],
        )

    def test_present_relation_returns_only_aggregate_pass_evidence(self) -> None:
        connection = Mock()
        connection.execute.side_effect = (
            self._cursor(),
            self._cursor(),
            self._cursor(rows=[("r",)]),
            self._cursor(row=(7, 0, 0, 0, 0, 0)),
            self._cursor(),
        )

        report = migrations._preflight_iam42_public_names(connection)

        self.assertEqual(
            report,
            iam42_public_name_preflight(
                relation_state="PRESENT", inspected=7
            ),
        )
        self.assertEqual(
            connection.execute.call_args_list[3].args,
            (migrations._IAM42_PUBLIC_NAME_PREFLIGHT_SQL,),
        )

    def test_invalid_rows_block_before_migration_with_reason_counts_only(self) -> None:
        connection = Mock()
        connection.execute.side_effect = (
            self._cursor(),
            self._cursor(),
            self._cursor(rows=[("r",)]),
            self._cursor(row=(6, 4, 1, 1, 2, 1)),
            self._cursor(),
        )

        with self.assertRaises(
            migrations.DeploymentIam42PublicNamePreflightError
        ) as raised:
            migrations._preflight_iam42_public_names(connection)

        self.assertEqual(
            raised.exception.report,
            iam42_public_name_preflight(
                relation_state="PRESENT",
                inspected=6,
                invalid=4,
                length=1,
                non_nfc=1,
                edge_whitespace=2,
                forbidden_codepoint=1,
            ),
        )
        self.assertEqual(
            str(raised.exception),
            "DEPLOYMENT_IAM42_PUBLIC_NAME_PREFLIGHT_BLOCKED",
        )

    def test_relation_or_aggregate_drift_is_unavailable_and_fail_closed(self) -> None:
        cases = (
            (
                self._cursor(),
                self._cursor(),
                self._cursor(rows=[("v",)]),
                self._cursor(),
            ),
            (
                self._cursor(),
                self._cursor(),
                self._cursor(rows=[("r",)]),
                self._cursor(row=(1, 0, 0)),
                self._cursor(),
            ),
        )
        for side_effect in cases:
            connection = Mock()
            connection.execute.side_effect = side_effect
            with self.subTest(side_effect=side_effect), self.assertRaises(
                migrations.DeploymentMigrationError
            ) as raised:
                migrations._preflight_iam42_public_names(connection)
            self.assertEqual(
                raised.exception.code,
                "DEPLOYMENT_IAM42_PUBLIC_NAME_PREFLIGHT_UNAVAILABLE",
            )
            self.assertEqual(connection.execute.call_args_list[-1].args, ("ROLLBACK",))

    def test_sql_predicate_keeps_every_iam42_unicode_boundary_marker(self) -> None:
        sql_text = migrations._IAM42_PUBLIC_NAME_PREFLIGHT_SQL
        migration = (
            Path(__file__).resolve().parents[2]
            / "src/desire_platform/identity_access/adapters/postgres/migrations/"
            "0042_expand__organization_public_name_management.sql"
        ).read_text(encoding="utf-8")
        for marker in (
            "IS NFC NORMALIZED",
            r"U&'\0020\00A0\1680\2000",
            "codepoint.value BETWEEN 0 AND 31",
            "codepoint.value BETWEEN 917536 AND 917631",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, sql_text)
                self.assertIn(marker, migration)
        self.assertIn("statement_timeout='30s'", migrations._IAM42_PUBLIC_NAME_PREFLIGHT_TIMEOUT_SQL)
        self.assertIn("READ ONLY", migrations._IAM42_PUBLIC_NAME_PREFLIGHT_BEGIN_SQL)


class DeploymentMigrationLifecycleTest(unittest.TestCase):
    def setUp(self) -> None:
        self.settings = DeploymentMigrationSettings(
            host="db",
            database="desire",
            admin_user="postgres",
            admin_password="a-database-password-with-32-bytes-minimum",
        )
        self.connection = Mock()
        self.connection.__enter__ = Mock(return_value=self.connection)
        self.connection.__exit__ = Mock(return_value=False)

    def test_partial_password_install_is_always_cleared(self) -> None:
        with (
            patch.object(migrations, "_admin_connection", return_value=self.connection),
            patch.object(migrations, "_assert_admin_preflight"),
            patch.object(migrations, "_acquire_provisioning_lock"),
            patch.object(
                migrations,
                "_preflight_iam42_public_names",
                return_value=iam42_public_name_preflight(),
            ),
            patch.object(migrations, "_ensure_roles"),
            patch.object(migrations, "_ensure_memberships"),
            patch.object(migrations, "_ensure_database_privileges"),
            patch.object(
                migrations,
                "_install_temporary_passwords",
                side_effect=RuntimeError("simulated partial install"),
            ),
            patch.object(migrations, "_clear_temporary_passwords") as clear,
            patch.object(migrations, "_release_provisioning_lock"),
        ):
            with self.assertRaisesRegex(RuntimeError, "partial install"):
                migrations.apply_reviewed_migrations(self.settings, dbapi=Mock())
        clear.assert_called_once_with(self.connection)

    def test_blocked_iam42_preflight_runs_before_every_provisioning_write(self) -> None:
        blocked = iam42_public_name_preflight(
            relation_state="PRESENT",
            inspected=2,
            invalid=1,
            edge_whitespace=1,
        )
        provisioning_steps = (
            "_ensure_roles",
            "_ensure_memberships",
            "_ensure_database_privileges",
            "_install_temporary_passwords",
            "_apply_catalogs",
            "_verify_catalogs",
            "_clear_temporary_passwords",
        )
        with (
            patch.object(migrations, "_admin_connection", return_value=self.connection),
            patch.object(migrations, "_assert_admin_preflight"),
            patch.object(migrations, "_acquire_provisioning_lock"),
            patch.object(
                migrations,
                "_preflight_iam42_public_names",
                side_effect=migrations.DeploymentIam42PublicNamePreflightError(
                    blocked
                ),
            ),
            patch.object(migrations, "_release_provisioning_lock") as release,
            patch.object(migrations, provisioning_steps[0]) as ensure_roles,
            patch.object(migrations, provisioning_steps[1]) as ensure_memberships,
            patch.object(migrations, provisioning_steps[2]) as ensure_privileges,
            patch.object(migrations, provisioning_steps[3]) as install_passwords,
            patch.object(migrations, provisioning_steps[4]) as apply_catalogs,
            patch.object(migrations, provisioning_steps[5]) as verify_catalogs,
            patch.object(migrations, provisioning_steps[6]) as clear_passwords,
        ):
            with self.assertRaises(
                migrations.DeploymentIam42PublicNamePreflightError
            ):
                migrations.apply_reviewed_migrations(self.settings, dbapi=Mock())

        release.assert_called_once_with(self.connection)
        for mocked_step in (
            ensure_roles,
            ensure_memberships,
            ensure_privileges,
            install_passwords,
            apply_catalogs,
            verify_catalogs,
            clear_passwords,
        ):
            mocked_step.assert_not_called()

    def test_membership_drift_query_covers_every_provisioned_role(self) -> None:
        class Cursor:
            def fetchall(cursor_self):
                return [
                    (granted, member, False, False, True)
                    for granted, member in MIGRATION_MEMBERSHIPS
                ]

        connection = Mock()
        connection.execute.return_value = Cursor()
        migrations._ensure_memberships(connection)
        query, parameters = connection.execute.call_args_list[0].args
        all_roles = set(EXPECTED_ROLES)
        self.assertIn(" OR ", query)
        self.assertEqual(set(parameters[0]), all_roles)
        self.assertEqual(set(parameters[1]), all_roles)

    def test_one_global_lock_wraps_provisioning_catalogs_and_verification(self) -> None:
        report = Mock()
        events = []

        def record(name: str):
            return lambda *_args, **_kwargs: events.append(name)

        with (
            patch.object(migrations, "_admin_connection", return_value=self.connection) as connect,
            patch.object(migrations, "_assert_admin_preflight", side_effect=record("preflight")),
            patch.object(migrations, "_acquire_provisioning_lock", create=True, side_effect=record("lock")) as acquire,
            patch.object(
                migrations,
                "_preflight_iam42_public_names",
                return_value=iam42_public_name_preflight(),
                side_effect=lambda *_args: (
                    events.append("iam42-public-name-preflight")
                    or iam42_public_name_preflight()
                ),
            ),
            patch.object(migrations, "_ensure_roles", side_effect=record("roles")),
            patch.object(migrations, "_ensure_memberships", side_effect=record("memberships")),
            patch.object(migrations, "_ensure_database_privileges", side_effect=record("privileges")),
            patch.object(
                migrations,
                "_install_temporary_passwords",
                return_value={role: "x" * 48 for role in migrations._MIGRATION_ROLES},
                side_effect=lambda *_args: (
                    events.append("passwords")
                    or {role: "x" * 48 for role in migrations._MIGRATION_ROLES}
                ),
            ),
            patch.object(
                migrations,
                "_apply_catalogs",
                return_value=report,
                side_effect=lambda *_args, **_kwargs: (
                    events.append("catalogs") or report
                ),
            ),
            patch.object(migrations, "_verify_catalogs", side_effect=record("verify")),
            patch.object(migrations, "_clear_temporary_passwords", side_effect=record("clear")),
            patch.object(migrations, "_release_provisioning_lock", create=True, side_effect=record("unlock")) as release,
        ):
            self.assertIs(
                migrations.apply_reviewed_migrations(self.settings, dbapi=Mock()),
                report,
            )

        connect.assert_called_once()
        acquire.assert_called_once_with(self.connection)
        release.assert_called_once_with(self.connection)
        self.assertEqual(
            events,
            [
                "preflight",
                "lock",
                "iam42-public-name-preflight",
                "roles",
                "memberships",
                "privileges",
                "passwords",
                "catalogs",
                "verify",
                "clear",
                "unlock",
            ],
        )

    def test_post_apply_verification_requires_the_trust_dependency_contract(self) -> None:
        expected_rows = iter(
            (
                (
                    "trust",
                    migrations.TRUST_SCHEMA_HEAD_VERSION,
                    migrations.TRUST_SCHEMA_HEAD_VERSION,
                    migrations.TRUST_SCHEMA_HEAD_VERSION,
                    migrations.TRUST_SCHEMA_HEAD_VERSION,
                    migrations.TRUST_REQUIRED_IAM_SCHEMA_VERSION,
                    migrations.TRUST_REQUIRED_DEMAND_SCHEMA_VERSION,
                ),
                (migrations.IAM_SCHEMA_HEAD_VERSION,) * 4,
                (migrations.PROFILE_SCHEMA_HEAD_VERSION,) * 4,
                (migrations.DEMAND_SCHEMA_HEAD_VERSION,) * 4
                + (migrations.DEMAND_REQUIRED_IAM_SCHEMA_VERSION,),
                (migrations.MATCHING_SCHEMA_HEAD_VERSION,) * 4
                + (migrations.MATCHING_REQUIRED_IAM_SCHEMA_VERSION,),
                (migrations.TAXONOMY_SCHEMA_HEAD_VERSION,) * 4,
            )
        )

        class Cursor:
            def __init__(self, row):
                self._row = row

            def fetchone(self):
                return self._row

        connection = Mock()
        connection.execute.side_effect = lambda _query: Cursor(next(expected_rows))
        migrations._verify_catalogs(connection)
        queries = tuple(call.args[0] for call in connection.execute.call_args_list)
        self.assertEqual(len(queries), 6)
        self.assertIn("FROM trust.schema_compatibility", queries[0])

    def test_matching_catalog_receives_all_frozen_contract_resources(self) -> None:
        catalog_report = Mock(applied_versions=(), skipped_versions=(1,))
        passwords = {
            role: "x" * 48 for role in migrations._MIGRATION_ROLES
        }
        runner_names = (
            "IamMigrationRunner",
            "PsycopgCreatorProfileMigrationRunner",
            "DemandMigrationRunner",
            "MatchingMigrationRunner",
            "TrustMigrationRunner",
            "PsycopgTaxonomyMigrationRunner",
        )
        runner_patches = [patch.object(migrations, name) for name in runner_names]
        started = [item.start() for item in runner_patches]
        self.addCleanup(lambda: [item.stop() for item in runner_patches])
        for runner in started:
            runner.return_value.run.return_value = catalog_report

        with patch.object(
            migrations,
            "_contract_bytes",
            side_effect=lambda relative_path: relative_path.encode("ascii"),
        ):
            migrations._apply_catalogs(
                self.settings,
                passwords,
                Mock(),
                iam42_public_name_preflight=iam42_public_name_preflight(),
            )

        sources = started[3].return_value.run.call_args.kwargs[
            "contract_sources"
        ]
        self.assertEqual(
            (
                sources.api_contract_bytes,
                sources.event_contract_bytes,
                sources.rule_contract_bytes,
                sources.input_manifest_contract_bytes,
                sources.run_input_contract_bytes,
                sources.candidate_contract_bytes,
                sources.disclosure_contract_bytes,
            ),
            (
                b"api/matching-v1.openapi.yaml",
                b"events/matching-v1.schema.json",
                b"domain/matching-rule-release-v1.schema.json",
                b"domain/match-input-manifest-v1.schema.json",
                b"domain/match-run-input-v1.schema.json",
                b"domain/match-candidate-result-v1.schema.json",
                b"domain/invitation-disclosure-v1.schema.json",
            ),
        )

    def test_trust_catalog_receives_all_frozen_appeal_contract_resources(self) -> None:
        catalog_report = Mock(applied_versions=(), skipped_versions=(1, 2, 3, 4))
        passwords = {
            role: "x" * 48 for role in migrations._MIGRATION_ROLES
        }
        runner_names = (
            "IamMigrationRunner",
            "PsycopgCreatorProfileMigrationRunner",
            "DemandMigrationRunner",
            "MatchingMigrationRunner",
            "TrustMigrationRunner",
            "PsycopgTaxonomyMigrationRunner",
        )
        runner_patches = [patch.object(migrations, name) for name in runner_names]
        started = [item.start() for item in runner_patches]
        self.addCleanup(lambda: [item.stop() for item in runner_patches])
        for runner in started:
            runner.return_value.run.return_value = catalog_report

        with patch.object(
            migrations,
            "_contract_bytes",
            side_effect=lambda relative_path: relative_path.encode("ascii"),
        ):
            migrations._apply_catalogs(
                self.settings,
                passwords,
                Mock(),
                iam42_public_name_preflight=iam42_public_name_preflight(),
            )

        trust_sources = started[4].return_value.run.call_args.kwargs[
            "contract_sources"
        ]
        self.assertEqual(
            (
                trust_sources.appeal_api_contract_bytes,
                trust_sources.appeal_event_contract_bytes,
                trust_sources.appeal_application_contract_bytes,
                trust_sources.appeal_review_contract_bytes,
            ),
            (
                b"api/appeal-v1.openapi.yaml",
                b"events/appeal-v1.schema.json",
                b"domain/appeal-application-v1.schema.json",
                b"domain/appeal-review-v1.schema.json",
            ),
        )

    def test_trust_failure_never_invokes_dependent_matching_or_taxonomy(self) -> None:
        passwords = {
            role: "x" * 48 for role in migrations._MIGRATION_ROLES
        }
        events = []
        runner_names = (
            "IamMigrationRunner",
            "PsycopgCreatorProfileMigrationRunner",
            "DemandMigrationRunner",
            "MatchingMigrationRunner",
            "TrustMigrationRunner",
            "PsycopgTaxonomyMigrationRunner",
        )
        runner_patches = [patch.object(migrations, name) for name in runner_names]
        started = [item.start() for item in runner_patches]
        self.addCleanup(lambda: [item.stop() for item in runner_patches])
        for name, runner in zip(("iam", "profile", "demand"), started[:3]):
            runner.return_value.run.side_effect = (
                lambda *args, _name=name, **kwargs: events.append(_name)
                or Mock(applied_versions=(), skipped_versions=())
            )
        started[3].return_value.run.side_effect = lambda *args, **kwargs: (
            events.append("matching")
            or Mock(applied_versions=(), skipped_versions=())
        )
        started[4].return_value.run.side_effect = lambda *args, **kwargs: (
            events.append("trust")
            or (_ for _ in ()).throw(RuntimeError("injected trust ledger failure"))
        )
        started[5].return_value.run.side_effect = lambda *args, **kwargs: (
            events.append("taxonomy")
            or Mock(applied_versions=(), skipped_versions=())
        )

        with (
            patch.object(
                migrations,
                "_contract_bytes",
                side_effect=lambda relative_path: relative_path.encode("ascii"),
            ),
            self.assertRaisesRegex(RuntimeError, "trust ledger failure"),
        ):
            migrations._apply_catalogs(
                self.settings,
                passwords,
                Mock(),
                iam42_public_name_preflight=iam42_public_name_preflight(),
            )

        self.assertEqual(events, ["iam", "profile", "demand", "trust"])
        started[3].assert_not_called()
        started[5].assert_not_called()

    def test_cli_trust_failure_is_exit78_with_empty_stdout_and_no_ready(self) -> None:
        stdout = StringIO()
        stderr = StringIO()
        with (
            patch.object(deployment_main, "load_settings", return_value=self.settings),
            patch.object(
                deployment_main,
                "apply_reviewed_migrations",
                side_effect=RuntimeError("injected trust runner failure"),
            ),
            redirect_stdout(stdout),
            redirect_stderr(stderr),
        ):
            self.assertEqual(deployment_main.main(), 78)

        self.assertEqual(stdout.getvalue(), "")
        self.assertNotIn("SCHEMA_READY", stdout.getvalue())
        self.assertNotIn("catalogs", stdout.getvalue())
        self.assertEqual(
            json.loads(stderr.getvalue()),
            {"code": "DEPLOYMENT_MIGRATION_FAILED", "status": "BLOCKED"},
        )

    def test_cli_reports_only_the_stable_deployment_error_code(self) -> None:
        stderr = StringIO()
        with (
            patch.object(deployment_main, "load_settings", return_value=self.settings),
            patch.object(
                deployment_main,
                "apply_reviewed_migrations",
                side_effect=DeploymentMigrationError(
                    "DEPLOYMENT_MIGRATION_ALREADY_RUNNING"
                ),
            ),
            redirect_stderr(stderr),
        ):
            self.assertEqual(deployment_main.main(), 78)
        self.assertEqual(
            json.loads(stderr.getvalue()),
            {
                "code": "DEPLOYMENT_MIGRATION_ALREADY_RUNNING",
                "status": "BLOCKED",
            },
        )

    def test_cli_reports_all_six_reviewed_catalogs(self) -> None:
        stdout = StringIO()
        catalog = migrations.CatalogMigrationReport(
            applied_versions=(1,), skipped_versions=()
        )
        report = migrations.DeploymentMigrationReport(
            iam=catalog,
            profile=catalog,
            demand=catalog,
            matching=catalog,
            trust=catalog,
            taxonomy=catalog,
            iam42_public_name_preflight=iam42_public_name_preflight(),
        )
        with (
            patch.object(deployment_main, "load_settings", return_value=self.settings),
            patch.object(
                deployment_main, "apply_reviewed_migrations", return_value=report
            ),
            redirect_stdout(stdout),
        ):
            self.assertEqual(deployment_main.main(), 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(
            tuple(sorted(payload["catalogs"])),
            ("demand", "iam", "matching", "profile", "taxonomy", "trust"),
        )
        self.assertEqual(
            payload["preflights"],
            {
                "iam42_organization_public_name": {
                    "edge_whitespace_count": 0,
                    "forbidden_codepoint_count": 0,
                    "inspected_organization_count": 0,
                    "invalid_organization_count": 0,
                    "length_violation_count": 0,
                    "non_nfc_count": 0,
                    "predicate_version": "iam42-organization-public-name-v1",
                    "relation_state": "ABSENT",
                    "status": "PASSED",
                }
            },
        )
        self.assertEqual(payload["status"], "SCHEMA_READY")

    def test_cli_reports_blocked_preflight_with_aggregate_counts_only(self) -> None:
        stderr = StringIO()
        blocked = iam42_public_name_preflight(
            relation_state="PRESENT",
            inspected=5,
            invalid=2,
            non_nfc=1,
            edge_whitespace=1,
        )
        with (
            patch.object(deployment_main, "load_settings", return_value=self.settings),
            patch.object(
                deployment_main,
                "apply_reviewed_migrations",
                side_effect=migrations.DeploymentIam42PublicNamePreflightError(
                    blocked
                ),
            ),
            redirect_stderr(stderr),
        ):
            self.assertEqual(deployment_main.main(), 78)
        self.assertEqual(
            json.loads(stderr.getvalue()),
            {
                "code": "DEPLOYMENT_IAM42_PUBLIC_NAME_PREFLIGHT_BLOCKED",
                "preflights": {
                    "iam42_organization_public_name": {
                        "edge_whitespace_count": 1,
                        "forbidden_codepoint_count": 0,
                        "inspected_organization_count": 5,
                        "invalid_organization_count": 2,
                        "length_violation_count": 0,
                        "non_nfc_count": 1,
                        "predicate_version": "iam42-organization-public-name-v1",
                        "relation_state": "PRESENT",
                        "status": "BLOCKED",
                    }
                },
                "status": "BLOCKED",
            },
        )


if __name__ == "__main__":
    unittest.main()
