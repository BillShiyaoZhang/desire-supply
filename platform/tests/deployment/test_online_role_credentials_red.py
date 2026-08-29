"""Real PostgreSQL evidence for all internal-sandbox online credentials."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile
import unittest

import psycopg

from desire_platform.deployment.migrations import (
    DeploymentMigrationSettings,
    apply_reviewed_migrations,
)
from desire_platform.deployment.online_credentials import (
    ONLINE_ROLE_CREDENTIAL_SPECS,
    OnlineRoleCredentialAction,
    OnlineRoleCredentialError,
    reconcile_online_role_credentials,
    revoke_online_role_credentials,
)
from desire_platform.internal_pilot.secrets import FileSecretManifestEntry
from desire_platform.runtime.config import (
    ArtifactRequirement,
    DatabaseProfile,
    ProcessConfiguration,
    RuntimeBudgets,
    RuntimeConfiguration,
    RuntimeIdentity,
)
from tests.storage.postgres.postgres18_harness import TemporaryPostgres18


NOW = datetime(2026, 8, 12, 6, 0, tzinfo=timezone.utc)


class _FailingPgconn:
    def __init__(self, pgconn) -> None:
        self._pgconn = pgconn
        self._changes = 0

    def change_password(self, user, password) -> None:
        self._changes += 1
        if self._changes == 3:
            raise RuntimeError("simulated password change failure")
        self._pgconn.change_password(user, password)

    def __getattr__(self, name):
        return getattr(self._pgconn, name)


class _FailingConnection:
    def __init__(self, connection) -> None:
        self._connection = connection
        self.pgconn = _FailingPgconn(connection.pgconn)

    @property
    def info(self):
        return self._connection.info

    def execute(self, statement, parameters=None):
        return self._connection.execute(statement, parameters)

    def __enter__(self):
        self._connection.__enter__()
        return self

    def __exit__(self, *arguments):
        return self._connection.__exit__(*arguments)


class _FailingDbApi:
    def __init__(self) -> None:
        self._wrapped = False

    def connect(self, *arguments, **keywords):
        connection = psycopg.connect(*arguments, **keywords)
        if (
            not self._wrapped
            and keywords.get("application_name")
            == "desire-deployment-provisioner"
        ):
            self._wrapped = True
            return _FailingConnection(connection)
        return connection


def _runtime_configuration(version: str = "v1") -> RuntimeConfiguration:
    capabilities = tuple(spec.capability_id for spec in ONLINE_ROLE_CREDENTIAL_SPECS)
    return RuntimeConfiguration(
        schema_name="desire-runtime-config-v1",
        identity=RuntimeIdentity(
            environment_id="internal-sandbox",
            deployment_id="local-credential-test",
            release_id="test-release",
            region="local",
            instance_id="credential-test-1",
        ),
        process=ProcessConfiguration(
            kind="migration",
            capability_ids=capabilities,
        ),
        artifacts=(ArtifactRequirement(artifact_id="platform", sha256="a" * 64),),
        database_profiles=tuple(
            DatabaseProfile(
                capability_id=spec.capability_id,
                online_role=spec.online_role,
                credential_ref=(
                    "secret://sandbox-db/%s#%s"
                    % (spec.online_role.replace("_", "-"), version)
                ),
                application_name="desire-%s" % spec.online_role.replace("_", "-"),
                max_pool_size=2,
                checkout_timeout_ms=2_000,
                statement_timeout_ms=10_000,
                lock_timeout_ms=2_000,
                idle_in_transaction_timeout_ms=15_000,
            )
            for spec in ONLINE_ROLE_CREDENTIAL_SPECS
        ),
        key_requirements=(),
        budgets=RuntimeBudgets(
            startup_timeout_ms=30_000,
            readiness_timeout_ms=10_000,
            shutdown_timeout_ms=30_000,
        ),
    )


class OnlineRoleCredentialPostgresTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.postgres = TemporaryPostgres18(
            enable_tcp_password_auth=True,
        ).start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.postgres.stop()

    def setUp(self) -> None:
        self.database = self.postgres.create_database()
        self.settings = DeploymentMigrationSettings(
            host=self.postgres.host,
            port=self.postgres.port,
            database=self.database,
            admin_user=self.postgres.admin_user,
            admin_password=self.postgres.admin_password,
        )
        apply_reviewed_migrations(self.settings)
        self.runtime = _runtime_configuration()
        self.temporary_secrets = tempfile.TemporaryDirectory(
            prefix="desire-online-role-secrets-",
        )
        self.secret_root = Path(self.temporary_secrets.name)
        entries = []
        passwords = {}
        for index, (spec, profile) in enumerate(
            zip(ONLINE_ROLE_CREDENTIAL_SPECS, self.runtime.database_profiles),
            start=1,
        ):
            password = "online-%02d-%s-credential-material-2026" % (
                index,
                spec.online_role,
            )
            file_name = "%s-v1" % spec.online_role
            (self.secret_root / file_name).write_text(password, encoding="utf-8")
            entries.append(
                FileSecretManifestEntry(
                    kind="DATABASE_CREDENTIAL",
                    file_name=file_name,
                    credential_ref=profile.credential_ref,
                    purpose="DATABASE_CREDENTIAL:%s" % spec.capability_id,
                    key_id="v1",
                    not_before=NOW - timedelta(minutes=1),
                    not_after=NOW + timedelta(days=30),
                    status="ACTIVE",
                )
            )
            passwords[spec.online_role] = password
        self.entries = tuple(entries)
        self.passwords = passwords

    def tearDown(self) -> None:
        self.temporary_secrets.cleanup()
        self.postgres.drop_database(self.database)

    def test_reconcile_is_distinct_scram_login_and_revoke_is_fail_closed(self) -> None:
        report = reconcile_online_role_credentials(
            settings=self.settings,
            runtime_config=self.runtime,
            manifest_entries=self.entries,
            secret_root=self.secret_root,
            now=NOW,
        )

        self.assertEqual(report.action, OnlineRoleCredentialAction.RECONCILE)
        self.assertEqual(
            report.online_roles,
            tuple(spec.online_role for spec in ONLINE_ROLE_CREDENTIAL_SPECS),
        )
        with psycopg.connect(
            self.postgres.admin_conninfo(database=self.database),
            autocommit=True,
        ) as connection:
            password_rows = connection.execute(
                "SELECT rolname,rolpassword FROM pg_catalog.pg_authid "
                "WHERE rolname = ANY(%s) ORDER BY rolname",
                ([spec.online_role for spec in ONLINE_ROLE_CREDENTIAL_SPECS],),
            ).fetchall()
            migration_passwords = connection.execute(
                "SELECT count(*) FROM pg_catalog.pg_authid "
                "WHERE rolname = ANY(%s) AND rolpassword IS NOT NULL",
                (
                    [
                        "iam_migration_runner",
                        "profile_migration_runner",
                        "demand_migration_runner",
                        "trust_migration_runner",
                        "taxonomy_migration_runner",
                    ],
                ),
            ).fetchone()
        self.assertEqual(len(password_rows), len(ONLINE_ROLE_CREDENTIAL_SPECS))
        self.assertTrue(
            all(value.startswith("SCRAM-SHA-256$") for _role, value in password_rows)
        )
        self.assertEqual(
            len({value for _role, value in password_rows}),
            len(ONLINE_ROLE_CREDENTIAL_SPECS),
        )
        self.assertEqual(migration_passwords, (0,))

        repeated = reconcile_online_role_credentials(
            settings=self.settings,
            runtime_config=self.runtime,
            manifest_entries=self.entries,
            secret_root=self.secret_root,
            now=NOW,
        )
        self.assertEqual(repeated.action, OnlineRoleCredentialAction.RECONCILE)
        with psycopg.connect(
            self.postgres.admin_conninfo(database=self.database),
            autocommit=True,
        ) as connection:
            repeated_password_rows = connection.execute(
                "SELECT rolname,rolpassword FROM pg_catalog.pg_authid "
                "WHERE rolname = ANY(%s) ORDER BY rolname",
                ([spec.online_role for spec in ONLINE_ROLE_CREDENTIAL_SPECS],),
            ).fetchall()
        self.assertEqual(repeated_password_rows, [row[:2] for row in password_rows])

        for spec in ONLINE_ROLE_CREDENTIAL_SPECS:
            with self.subTest(role=spec.online_role):
                with psycopg.connect(
                    self.postgres.tcp_conninfo(
                        database=self.database,
                        user=spec.online_role,
                        password=self.passwords[spec.online_role],
                    ),
                    autocommit=True,
                ) as connection:
                    self.assertEqual(
                        connection.execute(
                            "SELECT session_user,current_user"
                        ).fetchone(),
                        (spec.online_role, spec.online_role),
                    )
                with self.assertRaises(psycopg.OperationalError):
                    psycopg.connect(
                        self.postgres.tcp_conninfo(
                            database=self.database,
                            user=spec.online_role,
                            password="wrong-online-role-password-2026",
                        ),
                        connect_timeout=2,
                    )

        revoked = revoke_online_role_credentials(settings=self.settings)
        self.assertEqual(revoked.action, OnlineRoleCredentialAction.REVOKE)
        for spec in ONLINE_ROLE_CREDENTIAL_SPECS:
            with self.subTest(revoked_role=spec.online_role):
                with self.assertRaises(psycopg.OperationalError):
                    psycopg.connect(
                        self.postgres.tcp_conninfo(
                            database=self.database,
                            user=spec.online_role,
                            password=self.passwords[spec.online_role],
                        ),
                        connect_timeout=2,
                    )

    def test_rotation_changes_all_credentials_and_drains_old_sessions(self) -> None:
        reconcile_online_role_credentials(
            settings=self.settings,
            runtime_config=self.runtime,
            manifest_entries=self.entries,
            secret_root=self.secret_root,
            now=NOW,
        )
        old_connection = psycopg.connect(
            self.postgres.tcp_conninfo(
                database=self.database,
                user="iam_app",
                password=self.passwords["iam_app"],
            ),
            autocommit=True,
        )
        runtime_v2 = _runtime_configuration("v2")
        entries_v2 = []
        passwords_v2 = {}
        for index, (spec, profile) in enumerate(
            zip(ONLINE_ROLE_CREDENTIAL_SPECS, runtime_v2.database_profiles),
            start=1,
        ):
            password = "rotated-%02d-%s-credential-material-2026" % (
                index,
                spec.online_role,
            )
            file_name = "%s-v2" % spec.online_role
            (self.secret_root / file_name).write_text(password, encoding="utf-8")
            entries_v2.append(
                FileSecretManifestEntry(
                    kind="DATABASE_CREDENTIAL",
                    file_name=file_name,
                    credential_ref=profile.credential_ref,
                    purpose="DATABASE_CREDENTIAL:%s" % spec.capability_id,
                    key_id="v2",
                    not_before=NOW - timedelta(minutes=1),
                    not_after=NOW + timedelta(days=60),
                    status="ACTIVE",
                )
            )
            passwords_v2[spec.online_role] = password

        reconcile_online_role_credentials(
            settings=self.settings,
            runtime_config=runtime_v2,
            manifest_entries=tuple(entries_v2),
            secret_root=self.secret_root,
            now=NOW,
        )

        with self.assertRaises(psycopg.Error):
            old_connection.execute("SELECT 1")
        old_connection.close()
        for spec in ONLINE_ROLE_CREDENTIAL_SPECS:
            with self.subTest(role=spec.online_role):
                with self.assertRaises(psycopg.OperationalError):
                    psycopg.connect(
                        self.postgres.tcp_conninfo(
                            database=self.database,
                            user=spec.online_role,
                            password=self.passwords[spec.online_role],
                        ),
                        connect_timeout=2,
                    )
                with psycopg.connect(
                    self.postgres.tcp_conninfo(
                        database=self.database,
                        user=spec.online_role,
                        password=passwords_v2[spec.online_role],
                    ),
                    autocommit=True,
                ) as connection:
                    self.assertEqual(
                        connection.execute("SELECT current_user").fetchone(),
                        (spec.online_role,),
                    )

    def test_partial_rotation_failure_rolls_back_every_role(self) -> None:
        with psycopg.connect(
            self.postgres.admin_conninfo(database=self.database),
            autocommit=True,
        ) as connection:
            before = connection.execute(
                "SELECT rolname,rolpassword,rolvaliduntil "
                "FROM pg_catalog.pg_authid WHERE rolname = ANY(%s) "
                "ORDER BY rolname",
                ([spec.online_role for spec in ONLINE_ROLE_CREDENTIAL_SPECS],),
            ).fetchall()

        with self.assertRaises(OnlineRoleCredentialError) as raised:
            reconcile_online_role_credentials(
                settings=self.settings,
                runtime_config=self.runtime,
                manifest_entries=self.entries,
                secret_root=self.secret_root,
                now=NOW,
                dbapi=_FailingDbApi(),
            )
        self.assertEqual(
            raised.exception.code,
            "DEPLOYMENT_ONLINE_CREDENTIAL_RECONCILE_FAILED",
        )

        with psycopg.connect(
            self.postgres.admin_conninfo(database=self.database),
            autocommit=True,
        ) as connection:
            after = connection.execute(
                "SELECT rolname,rolpassword,rolvaliduntil "
                "FROM pg_catalog.pg_authid WHERE rolname = ANY(%s) "
                "ORDER BY rolname",
                ([spec.online_role for spec in ONLINE_ROLE_CREDENTIAL_SPECS],),
            ).fetchall()
        self.assertEqual(after, before)

if __name__ == "__main__":
    unittest.main()
