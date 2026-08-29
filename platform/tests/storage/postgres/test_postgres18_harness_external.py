"""Focused ownership tests for the external PostgreSQL 18 harness path."""

from __future__ import annotations

import os
import re
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from psycopg.conninfo import conninfo_to_dict

from tests.storage.postgres.postgres18_harness import TemporaryPostgres18


EXTERNAL_ROOT_DSN = (
    "postgresql://external_root:root-only-secret@database.internal:6543/postgres"
    "?sslmode=require&application_name=external-root-provisioner"
)


class _Result:
    def __init__(self, rows=()) -> None:
        self._rows = list(rows)

    def fetchall(self):
        return list(self._rows)

    def fetchone(self):
        return self._rows[0] if self._rows else None


class _Transaction:
    def __init__(self, connection: "_Connection") -> None:
        self.connection = connection
        self.role_snapshot = None
        self.role_fact_snapshot = None
        self.role_credential_snapshot = None
        self.database_snapshot = None

    def __enter__(self):
        self.role_snapshot = dict(self.connection.server.roles)
        self.role_fact_snapshot = dict(self.connection.server.role_facts)
        self.role_credential_snapshot = dict(
            self.connection.server.role_credentials
        )
        self.database_snapshot = dict(self.connection.server.databases)
        return self

    def __exit__(self, exception_type, _exception, _traceback) -> None:
        if exception_type is not None:
            self.connection.server.roles.clear()
            self.connection.server.roles.update(self.role_snapshot)
            self.connection.server.role_facts.clear()
            self.connection.server.role_facts.update(self.role_fact_snapshot)
            self.connection.server.role_credentials.clear()
            self.connection.server.role_credentials.update(
                self.role_credential_snapshot
            )
            self.connection.server.databases.clear()
            self.connection.server.databases.update(self.database_snapshot)
            return None
        if self.connection.server.fail_after_transaction_commit:
            self.connection.server.fail_after_transaction_commit = False
            if self.connection.server.fail_cleanup_connections_after_commit:
                self.connection.server.reject_connections = True
            raise RuntimeError(
                "injected external transaction commit acknowledgement failure"
            )
        return None


class _Connection:
    def __init__(
        self,
        server: "_Server",
        conninfo: str,
        *,
        autocommit: bool,
    ) -> None:
        self.server = server
        self.conninfo = conninfo
        self.autocommit = autocommit
        self._role_snapshot = None
        self._role_fact_snapshot = None
        self._role_credential_snapshot = None
        self._database_snapshot = None
        self.closed = False
        self.info = SimpleNamespace(
            server_version=server.server_version,
            host="database.internal",
            port=6543,
        )

    def __enter__(self):
        if not self.autocommit:
            self._role_snapshot = dict(self.server.roles)
            self._role_fact_snapshot = dict(self.server.role_facts)
            self._role_credential_snapshot = dict(
                self.server.role_credentials
            )
            self._database_snapshot = dict(self.server.databases)
        return self

    def __exit__(self, exception_type, _exception, _traceback) -> None:
        if not self.autocommit and exception_type is not None:
            self.server.roles.clear()
            self.server.roles.update(self._role_snapshot)
            self.server.role_facts.clear()
            self.server.role_facts.update(self._role_fact_snapshot)
            self.server.role_credentials.clear()
            self.server.role_credentials.update(
                self._role_credential_snapshot
            )
            self.server.databases.clear()
            self.server.databases.update(self._database_snapshot)
        if (
            not self.autocommit
            and exception_type is None
            and self.server.fail_after_transaction_commit
        ):
            self.server.fail_after_transaction_commit = False
            raise RuntimeError(
                "injected external transaction commit acknowledgement failure"
            )
        self.close()
        return None

    def transaction(self):
        return _Transaction(self)

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        if self.server.lock_owner is self:
            self.server.lock_owner = None

    def execute(self, statement, parameters=None):
        rendered = repr(statement)
        self.server.statements.append((self.conninfo, rendered, parameters))
        if (
            self.server.fail_held_cleanup_once
            and self.server.lock_owner is self
            and (
                "FROM pg_catalog.pg_database" in rendered
                or "shobj_description" in rendered
            )
        ):
            self.server.fail_held_cleanup_once = False
            if self.server.reject_after_held_cleanup_failure:
                self.server.reject_connections = True
            raise RuntimeError("injected held cleanup connection failure")
        if "pg_try_advisory_lock" in rendered:
            acquired = self.server.lock_owner in (None, self)
            if acquired:
                self.server.lock_owner = self
            return _Result(((acquired,),))
        if "pg_advisory_lock" in rendered and "xact" not in rendered:
            if self.server.lock_owner not in (None, self):
                raise RuntimeError("injected external advisory lock contention")
            self.server.lock_owner = self
            return _Result(((True,),))
        if "pg_advisory_unlock" in rendered:
            released = self.server.lock_owner is self
            if released:
                self.server.lock_owner = None
            return _Result(((released,),))
        if "SELECT rolname FROM pg_catalog.pg_roles" in rendered:
            requested = set(parameters[0])
            return _Result(
                (role_name,)
                for role_name in sorted(self.server.roles)
                if role_name in requested
            )
        if "rolcanlogin" in rendered and "FROM pg_catalog.pg_roles" in rendered:
            requested = set(parameters[0])
            return _Result(
                (role_name,) + self.server.role_facts[role_name]
                for role_name in sorted(self.server.role_facts)
                if role_name in requested
            )
        if "FROM pg_catalog.pg_database" in rendered:
            return _Result(
                (database, facts[0], facts[1])
                for database, facts in sorted(self.server.databases.items())
                if database.startswith("desire_iam_")
                or (
                    isinstance(facts[1], str)
                    and facts[1].startswith("desire-pg18-harness:")
                )
            )
        if "shobj_description" in rendered:
            requested = set(parameters[0])
            if len(parameters) == 1:
                return _Result(
                    (role_name, self.server.roles[role_name])
                    for role_name in sorted(self.server.roles)
                    if role_name in requested
                )
            marker = parameters[1]
            return _Result(
                (role_name,)
                for role_name in sorted(self.server.roles)
                if role_name in requested and self.server.roles[role_name] == marker
            )
        identifiers = re.findall(r"Identifier\('([^']+)'\)", rendered)
        literals = re.findall(r"Literal\('([^']+)'\)", rendered)
        if "CREATE ROLE" in rendered:
            role_name = identifiers[0]
            self.server.roles[role_name] = None
            self.server.role_facts[role_name] = (
                "SQL('LOGIN')" in rendered,
                False,
                "SQL('SUPERUSER')" in rendered,
                "SQL('CREATEDB')" in rendered,
                "SQL('CREATEROLE')" in rendered,
                "SQL('BYPASSRLS')" in rendered,
                "SQL('REPLICATION')" in rendered,
            )
            self.server.role_credentials[role_name] = (None, None)
            if self.server.fail_after_role_create == role_name:
                self.server.fail_after_role_create = None
                raise RuntimeError(
                    "injected external role create acknowledgement failure"
                )
        if "COMMENT ON ROLE" in rendered:
            self.server.roles[identifiers[0]] = literals[0]
        if "ALTER ROLE" in rendered and "PASSWORD" in rendered:
            role_name = identifiers[0]
            password = None if "PASSWORD NULL" in rendered else literals[0]
            valid_until = self.server.role_credentials[role_name][1]
            if "VALID UNTIL" in rendered:
                valid_until = (
                    "infinity" if "infinity" in rendered else literals[-1]
                )
            self.server.role_credentials[role_name] = (
                password,
                valid_until,
            )
            if self.server.fail_after_role_password_reset == role_name:
                self.server.fail_after_role_password_reset = None
                raise RuntimeError(
                    "injected runtime role password reset failure"
                )
        if "DROP ROLE" in rendered:
            role_name = identifiers[0]
            self.server.roles.pop(role_name, None)
            self.server.role_facts.pop(role_name, None)
            self.server.role_credentials.pop(role_name, None)
        if "CREATE DATABASE" in rendered:
            database = identifiers[0]
            self.server.databases[database] = ("schema_owner", None)
            if self.server.fail_after_database_create:
                self.server.fail_after_database_create = False
                raise RuntimeError(
                    "injected external database create acknowledgement failure"
                )
        if "COMMENT ON DATABASE" in rendered:
            database = identifiers[0]
            if self.server.fail_before_database_comment:
                self.server.fail_before_database_comment = False
                raise RuntimeError(
                    "injected external database comment pre-apply failure"
                )
            owner, _comment = self.server.databases[database]
            self.server.databases[database] = (owner, literals[0])
            if self.server.fail_after_database_comment:
                self.server.fail_after_database_comment = False
                raise RuntimeError(
                    "injected external database comment acknowledgement failure"
                )
        if "DROP DATABASE" in rendered:
            self.server.databases.pop(identifiers[0], None)
        if self.server.fail_database_grant and "GRANT CREATE ON DATABASE" in rendered:
            raise RuntimeError("injected external database grant failure")
        return _Result()


class _Server:
    def __init__(
        self,
        *,
        occupied_roles=(),
        occupied_databases=(),
        fail_after_role_create=None,
        fail_after_transaction_commit=False,
        fail_after_database_create=False,
        fail_before_database_comment=False,
        fail_after_database_comment=False,
        fail_database_grant=False,
        fail_connect=False,
        fail_cleanup_connections_after_commit=False,
        server_version=180004,
    ) -> None:
        self.roles = {row[0]: None for row in occupied_roles}
        self.role_facts = {
            row[0]: (False, False, False, False, False, False, False)
            for row in occupied_roles
        }
        self.role_credentials = {
            row[0]: (None, None) for row in occupied_roles
        }
        self.databases = (
            dict(occupied_databases)
            if isinstance(occupied_databases, dict)
            else {
                database: ("unrelated_owner", None)
                for database in occupied_databases
            }
        )
        self.fail_after_role_create = fail_after_role_create
        self.fail_after_role_password_reset = None
        self.fail_after_transaction_commit = fail_after_transaction_commit
        self.fail_after_database_create = fail_after_database_create
        self.fail_before_database_comment = fail_before_database_comment
        self.fail_after_database_comment = fail_after_database_comment
        self.fail_database_grant = fail_database_grant
        self.fail_connect = fail_connect
        self.fail_cleanup_connections_after_commit = (
            fail_cleanup_connections_after_commit
        )
        self.reject_connections = False
        self.server_version = server_version
        self.lock_owner = None
        self.fail_held_cleanup_once = False
        self.reject_after_held_cleanup_failure = False
        self.connect_attempts = 0
        self.connections: list[str] = []
        self.connection_objects: list[_Connection] = []
        self.statements: list[tuple[str, str, object]] = []

    def connect(self, conninfo: str, **kwargs):
        self.connect_attempts += 1
        if self.fail_connect or self.reject_connections:
            raise RuntimeError("injected external root connection failure")
        self.connections.append(conninfo)
        connection = _Connection(
            self,
            conninfo,
            autocommit=bool(kwargs.get("autocommit", False)),
        )
        self.connection_objects.append(connection)
        return connection


class TemporaryPostgres18ExternalTest(unittest.TestCase):
    def test_connect_and_preflight_failures_do_not_attempt_cleanup(self) -> None:
        cases = (
            (
                _Server(fail_connect=True),
                RuntimeError,
                "injected external root connection failure",
            ),
            (
                _Server(server_version=170004),
                AssertionError,
                "real PostgreSQL integration requires major 18",
            ),
        )
        for server, error_type, message in cases:
            with self.subTest(message=message), patch.dict(
                os.environ,
                {"DESIRE_IAM_TEST_POSTGRES_EPHEMERAL": "1"},
                clear=False,
            ), patch(
                "tests.storage.postgres.postgres18_harness.psycopg.connect",
                side_effect=server.connect,
            ):
                with self.assertRaisesRegex(error_type, message):
                    TemporaryPostgres18(
                        external_admin_conninfo=EXTERNAL_ROOT_DSN,
                    ).start()
            self.assertEqual(server.connect_attempts, 1)

    def test_external_root_dsn_is_redacted_for_explicit_and_environment_input(self) -> None:
        explicit = TemporaryPostgres18(external_admin_conninfo=EXTERNAL_ROOT_DSN)
        explicit_repr = repr(explicit)
        self.assertNotIn(EXTERNAL_ROOT_DSN, explicit_repr)
        self.assertNotIn("root-only-secret", explicit_repr)

        environment_dsn = (
            "postgresql://environment_root:environment-secret@db:5432/postgres"
        )
        with patch.dict(
            os.environ,
            {"DESIRE_IAM_TEST_POSTGRES_DSN": environment_dsn},
            clear=False,
        ):
            from_environment = TemporaryPostgres18()
        environment_repr = repr(from_environment)
        self.assertNotIn(environment_dsn, environment_repr)
        self.assertNotIn("environment-secret", environment_repr)

    def test_dedicated_admin_routes_runtime_and_cleanup_preserves_root_dsn(self) -> None:
        server = _Server()
        with patch.dict(
            os.environ,
            {"DESIRE_IAM_TEST_POSTGRES_EPHEMERAL": "1"},
            clear=False,
        ), patch(
            "tests.storage.postgres.postgres18_harness.psycopg.connect",
            side_effect=server.connect,
        ):
            postgres = TemporaryPostgres18(
                external_admin_conninfo=EXTERNAL_ROOT_DSN,
                enable_tcp_password_auth=True,
            ).start()

            self.assertEqual(postgres.host, "database.internal")
            self.assertEqual(postgres.port, 6543)
            self.assertEqual(postgres.admin_user, "desire_test_superuser")
            self.assertGreaterEqual(len(postgres.admin_password), 24)

            admin = conninfo_to_dict(postgres.admin_conninfo(database="example"))
            self.assertEqual(admin["host"], "database.internal")
            self.assertEqual(admin["port"], "6543")
            self.assertEqual(admin["dbname"], "example")
            self.assertEqual(admin["user"], "desire_test_superuser")
            self.assertEqual(admin["password"], postgres.admin_password)
            self.assertEqual(admin["sslmode"], "require")

            online = conninfo_to_dict(
                postgres.tcp_conninfo(
                    database="example",
                    user="iam_app",
                    password="online-role-secret",
                )
            )
            self.assertEqual(online["host"], "database.internal")
            self.assertEqual(online["port"], "6543")
            self.assertEqual(online["dbname"], "example")
            self.assertEqual(online["user"], "iam_app")
            self.assertEqual(online["password"], "online-role-secret")
            self.assertEqual(online["sslmode"], "require")

            role_markers = set(server.roles.values())
            self.assertNotIn(None, role_markers)
            self.assertEqual(len(role_markers), 1)

            rendered_statements = [
                statement
                for _conninfo, statement, _parameters in server.statements
            ]
            transaction_lock_index = next(
                index
                for index, statement in enumerate(rendered_statements)
                if "pg_try_advisory_lock" in statement
            )
            first_role_index = next(
                index
                for index, statement in enumerate(rendered_statements)
                if "CREATE ROLE" in statement
            )
            self.assertLess(transaction_lock_index, first_role_index)
            root_lock_connection = server.lock_owner
            self.assertIsNotNone(root_lock_connection)
            self.assertFalse(root_lock_connection.closed)

            database = postgres.create_database()
            database_owner, database_marker = server.databases[database]
            self.assertEqual(database_owner, "schema_owner")
            self.assertEqual(database_marker, next(iter(role_markers)))
            database_statements = [
                statement
                for _conninfo, statement, _parameters in server.statements
                if database in statement
            ]
            create_index = next(
                index
                for index, statement in enumerate(database_statements)
                if "CREATE DATABASE" in statement
            )
            comment_index = next(
                index
                for index, statement in enumerate(database_statements)
                if "COMMENT ON DATABASE" in statement
            )
            grant_index = next(
                index
                for index, statement in enumerate(database_statements)
                if "GRANT CREATE ON DATABASE" in statement
            )
            self.assertLess(create_index, comment_index)
            self.assertLess(comment_index, grant_index)
            postgres.stop()
            self.assertIsNone(server.lock_owner)
            self.assertTrue(root_lock_connection.closed)

        connection_users = [
            conninfo_to_dict(value)["user"] for value in server.connections
        ]
        self.assertEqual(connection_users[0], "external_root")
        self.assertIn("desire_test_superuser", connection_users)
        cleanup_root = conninfo_to_dict(server.connections[0])
        self.assertEqual(cleanup_root["password"], "root-only-secret")
        self.assertEqual(cleanup_root["application_name"], "external-root-provisioner")

        occupied_parameters = next(
            parameters
            for _conninfo, statement, parameters in server.statements
            if "pg_roles" in statement and parameters
        )
        self.assertIn("desire_test_superuser", occupied_parameters[0])
        self.assertTrue(
            any(
                "DROP ROLE IF EXISTS" in statement
                and "desire_test_superuser" in statement
                for _conninfo, statement, _parameters in server.statements
            )
        )
        database_cleanup = next(
            (conninfo, statement)
            for conninfo, statement, _parameters in server.statements
            if "DROP DATABASE" in statement and database in statement
        )
        self.assertEqual(
            conninfo_to_dict(database_cleanup[0])["user"],
            "external_root",
        )

    def test_create_database_restores_login_passwords_with_finite_expiry(
        self,
    ) -> None:
        server = _Server()
        with patch.dict(
            os.environ,
            {"DESIRE_IAM_TEST_POSTGRES_EPHEMERAL": "1"},
            clear=False,
        ), patch(
            "tests.storage.postgres.postgres18_harness.psycopg.connect",
            side_effect=server.connect,
        ):
            postgres = TemporaryPostgres18(
                external_admin_conninfo=EXTERNAL_ROOT_DSN,
            ).start()
            login_roles = tuple(
                role_name
                for role_name, facts in server.role_facts.items()
                if role_name != postgres.admin_user and facts[0]
            )
            nonlogin_roles = tuple(
                role_name
                for role_name, facts in server.role_facts.items()
                if role_name != postgres.admin_user and not facts[0]
            )
            self.assertTrue(login_roles)
            self.assertTrue(nonlogin_roles)
            for role_name in login_roles:
                server.role_credentials[role_name] = (None, "epoch")
            credentials_before = dict(server.role_credentials)
            statement_count = len(server.statements)

            database = postgres.create_database()

            runtime_password = conninfo_to_dict(
                postgres.conninfo(
                    database=database,
                    user="iam_migration_runner",
                )
            )["password"]
            self.assertEqual(
                {
                    role_name: server.role_credentials[role_name]
                    for role_name in login_roles
                },
                {
                    role_name: (
                        runtime_password,
                        "9999-01-01 00:00:00+00",
                    )
                    for role_name in login_roles
                },
            )
            self.assertEqual(
                {
                    role_name: server.role_credentials[role_name]
                    for role_name in nonlogin_roles
                },
                {
                    role_name: credentials_before[role_name]
                    for role_name in nonlogin_roles
                },
            )
            self.assertEqual(
                server.role_credentials[postgres.admin_user],
                credentials_before[postgres.admin_user],
            )
            statements = [
                statement
                for _conninfo, statement, _parameters in server.statements[
                    statement_count:
                ]
            ]
            ownership_index = next(
                index
                for index, statement in enumerate(statements)
                if "shobj_description" in statement
            )
            shape_index = next(
                index
                for index, statement in enumerate(statements)
                if "rolcanlogin" in statement
            )
            reset_indexes = tuple(
                index
                for index, statement in enumerate(statements)
                if "ALTER ROLE" in statement and "PASSWORD" in statement
            )
            create_index = next(
                index
                for index, statement in enumerate(statements)
                if "CREATE DATABASE" in statement
            )
            self.assertEqual(len(reset_indexes), len(login_roles))
            self.assertLess(ownership_index, reset_indexes[0])
            self.assertLess(shape_index, reset_indexes[0])
            self.assertTrue(all(index < create_index for index in reset_indexes))
            self.assertTrue(
                all(
                    "VALID UNTIL" in statements[index]
                    and "9999-01-01 00:00:00+00" in statements[index]
                    and "infinity" not in statements[index]
                    for index in reset_indexes
                )
            )
            postgres.stop()

    def test_create_database_rejects_role_ownership_and_shape_drift_first(self) -> None:
        cases = (
            (
                "ownership",
                "external PostgreSQL harness role ownership is unsafe",
            ),
            (
                "shape",
                "PostgreSQL harness runtime role contract is unsafe",
            ),
        )
        for drift, message in cases:
            server = _Server()
            with self.subTest(drift=drift), patch.dict(
                os.environ,
                {"DESIRE_IAM_TEST_POSTGRES_EPHEMERAL": "1"},
                clear=False,
            ), patch(
                "tests.storage.postgres.postgres18_harness.psycopg.connect",
                side_effect=server.connect,
            ):
                postgres = TemporaryPostgres18(
                    external_admin_conninfo=EXTERNAL_ROOT_DSN,
                ).start()
                original_marker = server.roles["iam_app"]
                original_facts = server.role_facts["iam_app"]
                if drift == "ownership":
                    server.roles["iam_app"] = (
                        "desire-pg18-harness:" + "f" * 64
                    )
                else:
                    server.role_facts["iam_app"] = (
                        True,
                        True,
                        False,
                        False,
                        False,
                        False,
                        False,
                    )
                credentials_before = dict(server.role_credentials)
                statement_count = len(server.statements)

                with self.assertRaisesRegex(AssertionError, message):
                    postgres.create_database()

                self.assertEqual(server.role_credentials, credentials_before)
                self.assertEqual(postgres._database_counter, 0)
                self.assertEqual(postgres._databases, set())
                self.assertEqual(server.databases, {})
                statements = [
                    statement
                    for _conninfo, statement, _parameters in server.statements[
                        statement_count:
                    ]
                ]
                self.assertFalse(
                    any(
                        "ALTER ROLE" in statement
                        or "CREATE DATABASE" in statement
                        for statement in statements
                    )
                )
                server.roles["iam_app"] = original_marker
                server.role_facts["iam_app"] = original_facts
                postgres.stop()

    def test_create_database_password_reset_failure_rolls_back_before_allocation(
        self,
    ) -> None:
        server = _Server()
        with patch.dict(
            os.environ,
            {"DESIRE_IAM_TEST_POSTGRES_EPHEMERAL": "1"},
            clear=False,
        ), patch(
            "tests.storage.postgres.postgres18_harness.psycopg.connect",
            side_effect=server.connect,
        ):
            postgres = TemporaryPostgres18(
                external_admin_conninfo=EXTERNAL_ROOT_DSN,
            ).start()
            login_roles = tuple(
                role_name
                for role_name, facts in server.role_facts.items()
                if role_name != postgres.admin_user and facts[0]
            )
            for role_name in login_roles:
                server.role_credentials[role_name] = (None, "epoch")
            credentials_before = dict(server.role_credentials)
            server.fail_after_role_password_reset = login_roles[1]
            statement_count = len(server.statements)

            with self.assertRaisesRegex(
                RuntimeError,
                "injected runtime role password reset failure",
            ):
                postgres.create_database()

            self.assertEqual(server.role_credentials, credentials_before)
            self.assertEqual(postgres._database_counter, 0)
            self.assertEqual(postgres._databases, set())
            self.assertEqual(server.databases, {})
            statements = [
                statement
                for _conninfo, statement, _parameters in server.statements[
                    statement_count:
                ]
            ]
            self.assertTrue(
                any("ALTER ROLE" in statement for statement in statements)
            )
            self.assertFalse(
                any("CREATE DATABASE" in statement for statement in statements)
            )
            postgres.stop()

    def test_preexisting_dedicated_admin_is_rejected_and_never_dropped(self) -> None:
        server = _Server(occupied_roles=(("desire_test_superuser",),))
        with patch.dict(
            os.environ,
            {"DESIRE_IAM_TEST_POSTGRES_EPHEMERAL": "1"},
            clear=False,
        ), patch(
            "tests.storage.postgres.postgres18_harness.psycopg.connect",
            side_effect=server.connect,
        ):
            with self.assertRaisesRegex(
                AssertionError,
                "external PostgreSQL harness role ownership is unsafe",
            ):
                TemporaryPostgres18(
                    external_admin_conninfo=EXTERNAL_ROOT_DSN,
                ).start()

        self.assertEqual(
            {conninfo_to_dict(value)["user"] for value in server.connections},
            {"external_root"},
        )
        self.assertFalse(
            any(
                "DROP ROLE" in statement
                for _conninfo, statement, _parameters in server.statements
            )
        )

    def test_admin_create_apply_then_raise_rolls_back_without_blind_drop(self) -> None:
        server = _Server(fail_after_role_create="desire_test_superuser")
        with patch.dict(
            os.environ,
            {"DESIRE_IAM_TEST_POSTGRES_EPHEMERAL": "1"},
            clear=False,
        ), patch(
            "tests.storage.postgres.postgres18_harness.psycopg.connect",
            side_effect=server.connect,
        ):
            with self.assertRaisesRegex(
                RuntimeError,
                "injected external role create acknowledgement failure",
            ):
                TemporaryPostgres18(
                    external_admin_conninfo=EXTERNAL_ROOT_DSN,
                ).start()

        self.assertEqual(server.roles, {})

    def test_ordinary_role_create_apply_then_raise_rolls_back_every_role(self) -> None:
        server = _Server(fail_after_role_create="iam_app")
        with patch.dict(
            os.environ,
            {"DESIRE_IAM_TEST_POSTGRES_EPHEMERAL": "1"},
            clear=False,
        ), patch(
            "tests.storage.postgres.postgres18_harness.psycopg.connect",
            side_effect=server.connect,
        ):
            with self.assertRaisesRegex(
                RuntimeError,
                "injected external role create acknowledgement failure",
            ):
                TemporaryPostgres18(
                    external_admin_conninfo=EXTERNAL_ROOT_DSN,
                ).start()

        self.assertEqual(server.roles, {})

    def test_commit_acknowledgement_failure_discovers_and_drops_exact_marker(self) -> None:
        server = _Server(
            occupied_roles=(("unrelated_role",),),
            fail_after_transaction_commit=True,
        )
        with patch.dict(
            os.environ,
            {"DESIRE_IAM_TEST_POSTGRES_EPHEMERAL": "1"},
            clear=False,
        ), patch(
            "tests.storage.postgres.postgres18_harness.psycopg.connect",
            side_effect=server.connect,
        ):
            with self.assertRaisesRegex(
                RuntimeError,
                "injected external transaction commit acknowledgement failure",
            ):
                TemporaryPostgres18(
                    external_admin_conninfo=EXTERNAL_ROOT_DSN,
                ).start()

        self.assertEqual(server.roles, {"unrelated_role": None})

    def test_concurrent_harness_rejects_collision_without_dropping_first_owner(self) -> None:
        server = _Server()
        with patch.dict(
            os.environ,
            {"DESIRE_IAM_TEST_POSTGRES_EPHEMERAL": "1"},
            clear=False,
        ), patch(
            "tests.storage.postgres.postgres18_harness.psycopg.connect",
            side_effect=server.connect,
        ):
            first = TemporaryPostgres18(
                external_admin_conninfo=EXTERNAL_ROOT_DSN,
            ).start()
            active_lock = server.lock_owner
            self.assertIsNotNone(active_lock)
            first_roles = dict(server.roles)
            statement_count = len(server.statements)
            with self.assertRaisesRegex(
                AssertionError,
                "external PostgreSQL harness is already active",
            ):
                TemporaryPostgres18(
                    external_admin_conninfo=EXTERNAL_ROOT_DSN,
                ).start()
            self.assertEqual(server.roles, first_roles)
            second_statements = server.statements[statement_count:]
            self.assertFalse(
                any(
                    "pg_roles" in statement or "DROP ROLE" in statement
                    for _conninfo, statement, _parameters in second_statements
                )
            )
            self.assertIs(server.lock_owner, active_lock)
            self.assertFalse(active_lock.closed)
            self.assertTrue(server.connection_objects[-1].closed)
            first.stop()

        self.assertEqual(server.roles, {})

    def test_stale_partial_marker_is_recovered_without_touching_unrelated_role(self) -> None:
        stale_marker = "desire-pg18-harness:" + "a" * 64
        server = _Server()
        server.roles.update(
            {
                "schema_owner": stale_marker,
                "iam_app": stale_marker,
                "unrelated_role": None,
            }
        )
        stale_database = "desire_iam_00000001_" + "a" * 32
        server.databases.update(
            {
                stale_database: ("schema_owner", None),
                "unrelated_database": ("unrelated_owner", "unrelated-comment"),
                "desireXiamYwildcard": (
                    "unrelated_owner",
                    "desireXpg18Yharness:" + "c" * 64,
                ),
            }
        )
        with patch.dict(
            os.environ,
            {"DESIRE_IAM_TEST_POSTGRES_EPHEMERAL": "1"},
            clear=False,
        ), patch(
            "tests.storage.postgres.postgres18_harness.psycopg.connect",
            side_effect=server.connect,
        ):
            postgres = TemporaryPostgres18(
                external_admin_conninfo=EXTERNAL_ROOT_DSN,
            ).start()
            active_markers = {
                marker
                for role_name, marker in server.roles.items()
                if role_name != "unrelated_role"
            }
            self.assertEqual(len(active_markers), 1)
            self.assertNotEqual(active_markers, {stale_marker})
            self.assertEqual(server.roles["unrelated_role"], None)
            self.assertNotIn(stale_database, server.databases)
            self.assertIn("unrelated_database", server.databases)
            self.assertIn("desireXiamYwildcard", server.databases)
            database_queries = [
                statement
                for _conninfo, statement, _parameters in server.statements
                if "FROM pg_catalog.pg_database" in statement
            ]
            self.assertTrue(database_queries)
            self.assertTrue(
                all(" LIKE " not in statement for statement in database_queries)
            )
            postgres.stop()

        self.assertEqual(server.roles, {"unrelated_role": None})
        self.assertEqual(
            server.databases,
            {
                "unrelated_database": ("unrelated_owner", "unrelated-comment"),
                "desireXiamYwildcard": (
                    "unrelated_owner",
                    "desireXpg18Yharness:" + "c" * 64,
                ),
            },
        )

    def test_unsafe_fixed_role_markers_fail_closed_and_are_preserved(self) -> None:
        valid_a = "desire-pg18-harness:" + "a" * 64
        valid_b = "desire-pg18-harness:" + "b" * 64
        cases = (
            {"schema_owner": None},
            {"schema_owner": "desire-pg18-harness:not-hex"},
            {"schema_owner": valid_a, "iam_app": valid_b},
        )
        for fixed_roles in cases:
            server = _Server()
            server.roles.update(fixed_roles)
            server.roles["unrelated_role"] = "unrelated-comment"
            before = dict(server.roles)
            with self.subTest(fixed_roles=fixed_roles), patch.dict(
                os.environ,
                {"DESIRE_IAM_TEST_POSTGRES_EPHEMERAL": "1"},
                clear=False,
            ), patch(
                "tests.storage.postgres.postgres18_harness.psycopg.connect",
                side_effect=server.connect,
            ):
                with self.assertRaisesRegex(
                    AssertionError,
                    "external PostgreSQL harness role ownership is unsafe",
                ):
                    TemporaryPostgres18(
                        external_admin_conninfo=EXTERNAL_ROOT_DSN,
                    ).start()
            self.assertEqual(server.roles, before)
            self.assertIsNone(server.lock_owner)

    def test_commit_ack_loss_cleanup_outage_releases_lock_for_next_recovery(self) -> None:
        server = _Server(
            occupied_roles=(("unrelated_role",),),
            fail_after_transaction_commit=True,
            fail_cleanup_connections_after_commit=True,
        )
        with patch.dict(
            os.environ,
            {"DESIRE_IAM_TEST_POSTGRES_EPHEMERAL": "1"},
            clear=False,
        ), patch(
            "tests.storage.postgres.postgres18_harness.psycopg.connect",
            side_effect=server.connect,
        ):
            with self.assertRaisesRegex(
                RuntimeError,
                "injected external transaction commit acknowledgement failure",
            ):
                TemporaryPostgres18(
                    external_admin_conninfo=EXTERNAL_ROOT_DSN,
                ).start()
            self.assertIsNone(server.lock_owner)
            self.assertTrue(server.connection_objects[0].closed)
            stale_markers = {
                marker
                for role_name, marker in server.roles.items()
                if role_name != "unrelated_role"
            }
            self.assertEqual(len(stale_markers), 1)

            server.reject_connections = False
            recovered = TemporaryPostgres18(
                external_admin_conninfo=EXTERNAL_ROOT_DSN,
            ).start()
            recovered_markers = {
                marker
                for role_name, marker in server.roles.items()
                if role_name != "unrelated_role"
            }
            self.assertEqual(len(recovered_markers), 1)
            self.assertNotEqual(recovered_markers, stale_markers)
            self.assertEqual(server.roles["unrelated_role"], None)
            recovered.stop()

        self.assertEqual(server.roles, {"unrelated_role": None})
        self.assertIsNone(server.lock_owner)

    def test_database_evidence_mismatch_fails_closed_and_preserves_everything(self) -> None:
        stale_marker = "desire-pg18-harness:" + "a" * 64
        other_marker = "desire-pg18-harness:" + "b" * 64
        exact_name = "desire_iam_00000001_" + "a" * 32
        cases = (
            {exact_name: ("other_owner", stale_marker)},
            {exact_name: ("schema_owner", other_marker)},
            {"desire_iam_malformed": ("schema_owner", stale_marker)},
            {
                "desire_iam_00000001_" + "b" * 32: (
                    "schema_owner",
                    stale_marker,
                )
            },
        )
        for database_evidence in cases:
            server = _Server()
            server.roles.update(
                {
                    "schema_owner": stale_marker,
                    "unrelated_role": None,
                }
            )
            server.databases.update(database_evidence)
            server.databases["unrelated_database"] = (
                "unrelated_owner",
                "unrelated-comment",
            )
            roles_before = dict(server.roles)
            databases_before = dict(server.databases)
            with self.subTest(database_evidence=database_evidence), patch.dict(
                os.environ,
                {"DESIRE_IAM_TEST_POSTGRES_EPHEMERAL": "1"},
                clear=False,
            ), patch(
                "tests.storage.postgres.postgres18_harness.psycopg.connect",
                side_effect=server.connect,
            ):
                with self.assertRaisesRegex(
                    AssertionError,
                    "external PostgreSQL harness database ownership is unsafe",
                ):
                    TemporaryPostgres18(
                        external_admin_conninfo=EXTERNAL_ROOT_DSN,
                    ).start()
            self.assertEqual(server.roles, roles_before)
            self.assertEqual(server.databases, databases_before)
            self.assertIsNone(server.lock_owner)

    def test_stop_discovers_owned_admin_without_started_flag(self) -> None:
        server = _Server()
        postgres = TemporaryPostgres18(external_admin_conninfo=EXTERNAL_ROOT_DSN)
        server.roles["desire_test_superuser"] = postgres._ownership_marker
        postgres._external_provisioning_attempted = True

        with patch(
            "tests.storage.postgres.postgres18_harness.psycopg.connect",
            side_effect=server.connect,
        ):
            postgres.stop()

        self.assertNotIn("desire_test_superuser", server.roles)
        drops = [
            (conninfo, statement)
            for conninfo, statement, _parameters in server.statements
            if "DROP ROLE IF EXISTS" in statement
        ]
        self.assertEqual(len(drops), 1)
        self.assertEqual(conninfo_to_dict(drops[0][0])["user"], "external_root")
        self.assertIn("desire_test_superuser", drops[0][1])

    def test_failed_database_grant_still_tracks_database_for_root_cleanup(self) -> None:
        server = _Server(fail_database_grant=True)
        with patch.dict(
            os.environ,
            {"DESIRE_IAM_TEST_POSTGRES_EPHEMERAL": "1"},
            clear=False,
        ), patch(
            "tests.storage.postgres.postgres18_harness.psycopg.connect",
            side_effect=server.connect,
        ):
            postgres = TemporaryPostgres18(
                external_admin_conninfo=EXTERNAL_ROOT_DSN,
            ).start()
            with self.assertRaisesRegex(
                RuntimeError,
                "injected external database grant failure",
            ):
                postgres.create_database()
            postgres.stop()

        database_drops = [
            (conninfo, statement)
            for conninfo, statement, _parameters in server.statements
            if "DROP DATABASE" in statement
        ]
        self.assertEqual(len(database_drops), 1)
        self.assertEqual(
            conninfo_to_dict(database_drops[0][0])["user"],
            "external_root",
        )

    def test_broken_held_cleanup_connection_releases_then_uses_fresh_try_lock(self) -> None:
        server = _Server()
        with patch.dict(
            os.environ,
            {"DESIRE_IAM_TEST_POSTGRES_EPHEMERAL": "1"},
            clear=False,
        ), patch(
            "tests.storage.postgres.postgres18_harness.psycopg.connect",
            side_effect=server.connect,
        ):
            postgres = TemporaryPostgres18(
                external_admin_conninfo=EXTERNAL_ROOT_DSN,
            ).start()
            held_connection = server.lock_owner
            server.fail_held_cleanup_once = True
            postgres.stop()

        self.assertTrue(held_connection.closed)
        self.assertIsNone(server.lock_owner)
        self.assertEqual(server.roles, {})
        try_lock_calls = [
            statement
            for _conninfo, statement, _parameters in server.statements
            if "pg_try_advisory_lock" in statement
        ]
        self.assertEqual(len(try_lock_calls), 2)

    def test_database_create_apply_then_raise_cleans_only_prejournaled_name(self) -> None:
        server = _Server(
            occupied_databases=("unrelated_database",),
            fail_after_database_create=True,
        )
        with patch.dict(
            os.environ,
            {"DESIRE_IAM_TEST_POSTGRES_EPHEMERAL": "1"},
            clear=False,
        ), patch(
            "tests.storage.postgres.postgres18_harness.psycopg.connect",
            side_effect=server.connect,
        ):
            postgres = TemporaryPostgres18(
                external_admin_conninfo=EXTERNAL_ROOT_DSN,
            ).start()
            with self.assertRaisesRegex(
                RuntimeError,
                "injected external database create acknowledgement failure",
            ):
                postgres.create_database()
            postgres.stop()

        self.assertEqual(
            server.databases,
            {"unrelated_database": ("unrelated_owner", None)},
        )
        create_statement = next(
            statement
            for _conninfo, statement, _parameters in server.statements
            if "CREATE DATABASE" in statement
        )
        created_name = re.findall(r"Identifier\('([^']+)'\)", create_statement)[0]
        self.assertRegex(
            created_name,
            r"^desire_iam_[0-9a-f]{8}_[0-9a-f]{32}$",
        )

    def test_database_comment_apply_then_raise_is_durably_cleaned(self) -> None:
        server = _Server(fail_after_database_comment=True)
        with patch.dict(
            os.environ,
            {"DESIRE_IAM_TEST_POSTGRES_EPHEMERAL": "1"},
            clear=False,
        ), patch(
            "tests.storage.postgres.postgres18_harness.psycopg.connect",
            side_effect=server.connect,
        ):
            postgres = TemporaryPostgres18(
                external_admin_conninfo=EXTERNAL_ROOT_DSN,
            ).start()
            with self.assertRaisesRegex(
                RuntimeError,
                "injected external database comment acknowledgement failure",
            ):
                postgres.create_database()
            self.assertEqual(len(server.databases), 1)
            self.assertEqual(
                next(iter(server.databases.values()))[1],
                postgres._ownership_marker,
            )
            postgres.stop()

        self.assertEqual(server.databases, {})

    def test_database_and_roles_recover_after_object_loss_and_cleanup_outage(self) -> None:
        server = _Server(
            occupied_databases={
                "unrelated_database": (
                    "unrelated_owner",
                    "unrelated-comment",
                )
            }
        )
        with patch.dict(
            os.environ,
            {"DESIRE_IAM_TEST_POSTGRES_EPHEMERAL": "1"},
            clear=False,
        ), patch(
            "tests.storage.postgres.postgres18_harness.psycopg.connect",
            side_effect=server.connect,
        ):
            failed = TemporaryPostgres18(
                external_admin_conninfo=EXTERNAL_ROOT_DSN,
            ).start()
            stale_database = failed.create_database()
            stale_marker = failed._ownership_marker
            server.fail_held_cleanup_once = True
            server.reject_after_held_cleanup_failure = True
            with self.assertRaisesRegex(
                RuntimeError,
                "injected external root connection failure",
            ):
                failed.stop()
            self.assertIsNone(server.lock_owner)
            self.assertEqual(
                server.databases[stale_database],
                ("schema_owner", stale_marker),
            )
            del failed

            server.reject_connections = False
            statement_count = len(server.statements)
            recovered = TemporaryPostgres18(
                external_admin_conninfo=EXTERNAL_ROOT_DSN,
            ).start()
            self.assertNotIn(stale_database, server.databases)
            recovery_statements = server.statements[statement_count:]
            database_drop_index = next(
                index
                for index, (_conninfo, statement, _parameters) in enumerate(
                    recovery_statements
                )
                if "DROP DATABASE" in statement
            )
            role_drop_index = next(
                index
                for index, (_conninfo, statement, _parameters) in enumerate(
                    recovery_statements
                )
                if "DROP ROLE" in statement
            )
            self.assertLess(database_drop_index, role_drop_index)
            self.assertEqual(
                server.databases,
                {
                    "unrelated_database": (
                        "unrelated_owner",
                        "unrelated-comment",
                    )
                },
            )
            recovered.stop()

        self.assertEqual(
            server.databases,
            {
                "unrelated_database": (
                    "unrelated_owner",
                    "unrelated-comment",
                )
            },
        )


if __name__ == "__main__":
    unittest.main()
