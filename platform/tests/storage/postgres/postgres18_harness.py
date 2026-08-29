"""One-process PostgreSQL 18 harness for non-skippable integration tests."""

from __future__ import annotations

from dataclasses import dataclass, field
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import subprocess
import tempfile
from typing import Optional

import psycopg
from psycopg import sql
from psycopg.conninfo import make_conninfo


_POSTGRES_PORT = 55418
_ADMIN_ROLE = "desire_test_superuser"
_ROLE_SPECS = (
    ("schema_owner", False),
    ("iam_migration_runner", True),
    ("iam_app", True),
    ("iam_session_authenticator", True),
    ("iam_onboarding", True),
    ("iam_sandbox_bootstrap", True),
    ("iam_system", True),
    ("iam_self_summary_reader", False),
    ("iam_outbox_worker", True),
    ("iam_projection_consumer", True),
    ("iam_key_policy_operator", False),
    ("audit_reader", False),
    ("break_glass", False),
    ("profile_schema_owner", False),
    ("profile_migration_runner", True),
    ("profile_app", True),
    ("profile_matcher", True),
    ("demand_schema_owner", False),
    ("demand_migration_runner", True),
    ("demand_self", True),
    ("demand_review", True),
    ("demand_finance", True),
    ("demand_matching", True),
    ("demand_system", True),
    ("matching_schema_owner", False),
    ("matching_migration_runner", True),
    ("matching_creator", True),
    ("matching_selector", True),
    ("matching_assignment", True),
    ("matching_review", True),
    ("matching_worker", True),
    ("matching_coordinator", True),
    ("trust_schema_owner", False),
    ("trust_migration_runner", True),
    ("trust_self", True),
    ("trust_officer", True),
    ("trust_appeal", True),
    ("trust_decision", True),
    ("taxonomy_schema_owner", False),
    ("taxonomy_migration_runner", True),
    ("taxonomy_publisher", True),
    ("taxonomy_admin", True),
    ("taxonomy_reader", True),
    ("taxonomy_consumer", True),
)
_HARNESS_ROLE_NAMES = (_ADMIN_ROLE,) + tuple(
    role_name for role_name, _can_login in _ROLE_SPECS
)
_EXTERNAL_ROLE_LOCK_KEY = (0x44534952, 0x50473138)  # "DSIR" / "PG18"
_OWNERSHIP_MARKER_PREFIX = "desire-pg18-harness:"
_OWNERSHIP_MARKER_PATTERN = re.compile(
    r"^desire-pg18-harness:[0-9a-f]{64}$"
)
_DATABASE_NAME_PREFIX = "desire_iam_"
_DATABASE_NAME_PATTERN = re.compile(
    r"^desire_iam_([0-9a-f]{8})_([0-9a-f]{32})$"
)
_MAX_DATABASE_COUNTER = 0xFFFFFFFF
_RUNTIME_ROLE_VALID_UNTIL = "9999-01-01 00:00:00+00"


@dataclass
class TemporaryPostgres18:
    """Own a PG18 cluster that has no TCP listener or persistent service."""

    binary_directory: Optional[Path] = None
    external_admin_conninfo: Optional[str] = field(default=None, repr=False)
    enable_tcp_password_auth: bool = False

    def __post_init__(self) -> None:
        self._temporary_directory: Optional[tempfile.TemporaryDirectory[str]] = None
        self.root: Optional[Path] = None
        self.data_directory: Optional[Path] = None
        self.socket_directory: Optional[Path] = None
        self.log_path: Optional[Path] = None
        self._started = False
        self._owns_server = False
        self._roles_provisioned = False
        self._provisioned_roles: list[str] = []
        self._external_admin_role_provisioned = False
        self._external_provisioning_attempted = False
        self._external_lock_connection = None
        self._database_counter = 0
        self._databases: set[str] = set()
        self._runtime_password = secrets.token_urlsafe(32)
        self._admin_password = secrets.token_urlsafe(32)
        self._ownership_marker = (
            _OWNERSHIP_MARKER_PREFIX + secrets.token_hex(32)
        )
        self._external_host: Optional[str] = None
        if self.external_admin_conninfo is None:
            self.external_admin_conninfo = os.environ.get(
                "DESIRE_IAM_TEST_POSTGRES_DSN"
            )
        self._external_root_conninfo = self.external_admin_conninfo
        self._port = (
            _available_loopback_port()
            if self.enable_tcp_password_auth and not self._external_root_conninfo
            else _POSTGRES_PORT
        )

    def start(self) -> "TemporaryPostgres18":
        if self._temporary_directory is not None:
            raise AssertionError("temporary PostgreSQL harness was started twice")
        if self._started:
            raise AssertionError("temporary PostgreSQL harness was started twice")
        if self._external_root_conninfo:
            if os.environ.get("DESIRE_IAM_TEST_POSTGRES_EPHEMERAL") != "1":
                raise AssertionError(
                    "external PostgreSQL integration requires "
                    "DESIRE_IAM_TEST_POSTGRES_EPHEMERAL=1"
                )
            root_connection = None
            try:
                root_connection = psycopg.connect(
                    self._root_conninfo(database="postgres"),
                    autocommit=True,
                )
                server_version = root_connection.info.server_version
                self._external_host = root_connection.info.host
                self._port = int(root_connection.info.port)
                if server_version // 10_000 != 18:
                    raise AssertionError(
                        "real PostgreSQL integration requires major 18, got %s"
                        % server_version
                    )
                acquired = root_connection.execute(
                    "SELECT pg_catalog.pg_try_advisory_lock(%s,%s)",
                    _EXTERNAL_ROLE_LOCK_KEY,
                ).fetchone()
                if acquired != (True,):
                    raise AssertionError(
                        "external PostgreSQL harness is already active"
                    )
                self._external_lock_connection = root_connection

                occupied_roles = self._external_role_ownership_rows(
                    root_connection
                )
                if occupied_roles:
                    markers = {row[1] for row in occupied_roles}
                    if (
                        len(markers) != 1
                        or any(
                            not isinstance(marker, str)
                            or _OWNERSHIP_MARKER_PATTERN.fullmatch(marker) is None
                            for marker in markers
                        )
                    ):
                        raise AssertionError(
                            "external PostgreSQL harness role ownership is unsafe"
                        )
                    stale_marker = next(iter(markers))
                    stale_databases = (
                        self._attributable_external_databases(
                            root_connection,
                            marker=stale_marker,
                        )
                    )
                    self._drop_external_databases(
                        root_connection,
                        stale_databases,
                    )
                    self._drop_external_roles(
                        root_connection,
                        {row[0] for row in occupied_roles},
                    )
                elif self._external_database_ownership_rows(root_connection):
                    raise AssertionError(
                        "external PostgreSQL harness database ownership is unsafe"
                    )
                if self._external_database_ownership_rows(root_connection):
                    raise AssertionError(
                        "external PostgreSQL harness database ownership is unsafe"
                    )
                if self._external_role_ownership_rows(root_connection):
                    raise AssertionError(
                        "external PostgreSQL harness role ownership is unsafe"
                    )

                with root_connection.transaction():
                    self._external_provisioning_attempted = True
                    root_connection.execute(
                        sql.SQL(
                            "CREATE ROLE {} LOGIN NOINHERIT SUPERUSER CREATEDB "
                            "CREATEROLE BYPASSRLS NOREPLICATION PASSWORD {}"
                        ).format(
                            sql.Identifier(_ADMIN_ROLE),
                            sql.Literal(self._admin_password),
                        )
                    )
                    root_connection.execute(
                        sql.SQL("COMMENT ON ROLE {} IS {}").format(
                            sql.Identifier(_ADMIN_ROLE),
                            sql.Literal(self._ownership_marker),
                        )
                    )
                    self._provision_role_specs(
                        root_connection,
                        ownership_marker=self._ownership_marker,
                    )
                self._external_admin_role_provisioned = True
                self._provisioned_roles = [
                    role_name for role_name, _can_login in _ROLE_SPECS
                ]
                self._roles_provisioned = True
                self._started = True
                return self
            except BaseException:
                self._release_external_lock_connection(
                    fallback_connection=root_connection,
                    suppress_errors=True,
                )
                if self._external_provisioning_attempted:
                    try:
                        self.stop()
                    except BaseException:
                        pass
                raise

        binaries = self.binary_directory or _find_postgres18_binaries()
        self.binary_directory = binaries
        self._temporary_directory = tempfile.TemporaryDirectory(
            prefix="desire-pg18-integration-",
            dir="/private/tmp",
        )
        self.root = Path(self._temporary_directory.name)
        self.data_directory = self.root / "data"
        self.socket_directory = self.root / "socket"
        self.log_path = self.root / "postgres.log"
        self.socket_directory.mkdir(mode=0o700)

        try:
            self._run(
                "initdb",
                "-D",
                str(self.data_directory),
                "--auth-local=trust",
                (
                    "--auth-host=scram-sha-256"
                    if self.enable_tcp_password_auth
                    else "--auth-host=reject"
                ),
                "--encoding=UTF8",
                "--locale=C",
                "--username=" + _ADMIN_ROLE,
            )
            server_options = " ".join(
                (
                    "-k",
                    str(self.socket_directory),
                    "-p",
                    str(self._port),
                    "-c",
                    (
                        "listen_addresses='127.0.0.1'"
                        if self.enable_tcp_password_auth
                        else "listen_addresses=''"
                    ),
                    "-c",
                    "unix_socket_permissions=0700",
                )
            )
            self._run(
                "pg_ctl",
                "-D",
                str(self.data_directory),
                "-l",
                str(self.log_path),
                "-o",
                server_options,
                "-w",
                "start",
            )
            self._started = True
            self._owns_server = True
            with psycopg.connect(
                self.admin_conninfo(database="postgres"),
                autocommit=True,
            ) as connection:
                server_version = connection.info.server_version
            if server_version // 10_000 != 18:
                raise AssertionError(
                    "real PostgreSQL integration requires major 18, got %s"
                    % server_version
                )
            with psycopg.connect(
                self.admin_conninfo(database="postgres"),
                autocommit=True,
            ) as connection:
                connection.execute(
                    sql.SQL("ALTER ROLE {} PASSWORD {}").format(
                        sql.Identifier(_ADMIN_ROLE),
                        sql.Literal(self._admin_password),
                    )
                )
            self._provision_roles()
        except BaseException:
            self.stop()
            raise
        return self

    def stop(self) -> None:
        cleanup_error: Optional[BaseException] = None
        has_external_resources = bool(
            self._external_root_conninfo
            and (
                self._started
                or self._databases
                or self._provisioned_roles
                or self._external_admin_role_provisioned
                or self._external_provisioning_attempted
                or self._external_lock_connection is not None
            )
        )
        if has_external_resources:
            cleanup_errors: list[BaseException] = []
            owned_roles: set[str] = set()
            had_held_connection = self._external_lock_connection is not None
            for cleanup_attempt in range(2 if had_held_connection else 1):
                attempt_errors: list[BaseException] = []
                cleanup_connection = self._external_lock_connection
                try:
                    if cleanup_connection is None:
                        cleanup_connection = psycopg.connect(
                            self._root_conninfo(database="postgres"),
                            autocommit=True,
                        )
                        acquired = cleanup_connection.execute(
                            "SELECT pg_catalog.pg_try_advisory_lock(%s,%s)",
                            _EXTERNAL_ROLE_LOCK_KEY,
                        ).fetchone()
                        if acquired != (True,):
                            raise AssertionError(
                                "external PostgreSQL harness cleanup lock unavailable"
                            )
                        self._external_lock_connection = cleanup_connection
                    owned_roles, operation_errors = (
                        self._cleanup_external_resources_on_connection(
                            cleanup_connection
                        )
                    )
                    attempt_errors.extend(operation_errors)
                except BaseException as error:
                    attempt_errors.append(error)
                finally:
                    try:
                        self._release_external_lock_connection(
                            fallback_connection=cleanup_connection,
                        )
                    except BaseException as error:
                        attempt_errors.append(error)
                if not attempt_errors:
                    cleanup_errors = []
                    break
                cleanup_errors = attempt_errors
                if cleanup_attempt == 0 and had_held_connection:
                    continue
                break
            self._provisioned_roles = [
                role_name
                for role_name, _can_login in _ROLE_SPECS
                if role_name in owned_roles
            ]
            self._roles_provisioned = bool(self._provisioned_roles)
            self._external_admin_role_provisioned = _ADMIN_ROLE in owned_roles
            if not cleanup_errors and not self._databases and not owned_roles:
                self._external_provisioning_attempted = False
            if cleanup_errors:
                cleanup_error = cleanup_errors[0]
        if self._started and self._owns_server and self.data_directory is not None:
            try:
                self._run(
                    "pg_ctl",
                    "-D",
                    str(self.data_directory),
                    "-m",
                    "fast",
                    "-w",
                    "stop",
                )
            except BaseException as error:
                cleanup_error = error
            finally:
                self._started = False
                self._owns_server = False
        else:
            self._started = False
        if self._temporary_directory is not None:
            self._temporary_directory.cleanup()
            self._temporary_directory = None
        if cleanup_error is not None:
            raise cleanup_error

    def create_database(self) -> str:
        self._require_started()
        with psycopg.connect(
            self.admin_conninfo(database="postgres"),
            autocommit=True,
        ) as connection:
            self._reset_runtime_role_credentials(connection)
            self._database_counter += 1
            if self._database_counter > _MAX_DATABASE_COUNTER:
                raise AssertionError(
                    "temporary PostgreSQL database counter exhausted"
                )
            name = "desire_iam_%08x_%s" % (
                self._database_counter,
                self._database_marker_suffix(self._ownership_marker),
            )
            self._databases.add(name)
            connection.execute(
                sql.SQL("CREATE DATABASE {} OWNER schema_owner TEMPLATE template0").format(
                    sql.Identifier(name)
                )
            )
            connection.execute(
                sql.SQL("COMMENT ON DATABASE {} IS {}").format(
                    sql.Identifier(name),
                    sql.Literal(self._ownership_marker),
                )
            )
            connection.execute(
                sql.SQL("GRANT CREATE ON DATABASE {} TO profile_schema_owner").format(
                    sql.Identifier(name)
                )
            )
            connection.execute(
                sql.SQL("GRANT CREATE ON DATABASE {} TO demand_schema_owner").format(
                    sql.Identifier(name)
                )
            )
            connection.execute(
                sql.SQL("GRANT CREATE ON DATABASE {} TO matching_schema_owner").format(
                    sql.Identifier(name)
                )
            )
            connection.execute(
                sql.SQL("GRANT CREATE ON DATABASE {} TO trust_schema_owner").format(
                    sql.Identifier(name)
                )
            )
            connection.execute(
                sql.SQL("GRANT CREATE ON DATABASE {} TO taxonomy_schema_owner").format(
                    sql.Identifier(name)
                )
            )
        return name

    def _reset_runtime_role_credentials(self, connection) -> None:
        with connection.transaction():
            if self._external_root_conninfo:
                ownership_rows = tuple(
                    self._external_role_ownership_rows(connection)
                )
                expected_ownership = tuple(
                    (role_name, self._ownership_marker)
                    for role_name in sorted(_HARNESS_ROLE_NAMES)
                )
                if ownership_rows != expected_ownership:
                    raise AssertionError(
                        "external PostgreSQL harness role ownership is unsafe"
                    )

            role_names = [role_name for role_name, _can_login in _ROLE_SPECS]
            rows = connection.execute(
                "SELECT rolname,rolcanlogin,rolinherit,rolsuper,rolcreatedb,"
                "rolcreaterole,rolbypassrls,rolreplication "
                "FROM pg_catalog.pg_roles WHERE rolname=ANY(%s) "
                "ORDER BY rolname",
                (role_names,),
            ).fetchall()
            expected_rows = tuple(
                sorted(
                    (
                        role_name,
                        can_login,
                        False,
                        False,
                        False,
                        False,
                        False,
                        False,
                    )
                    for role_name, can_login in _ROLE_SPECS
                )
            )
            if tuple(rows) != expected_rows:
                raise AssertionError(
                    "PostgreSQL harness runtime role contract is unsafe"
                )

            for role_name, can_login in _ROLE_SPECS:
                if not can_login:
                    continue
                connection.execute(
                    sql.SQL(
                        "ALTER ROLE {} PASSWORD {} VALID UNTIL {}"
                    ).format(
                        sql.Identifier(role_name),
                        sql.Literal(self._runtime_password),
                        sql.Literal(_RUNTIME_ROLE_VALID_UNTIL),
                    )
                )

    def drop_database(self, name: str) -> None:
        self._require_started()
        with psycopg.connect(
            self.admin_conninfo(database="postgres"),
            autocommit=True,
        ) as connection:
            connection.execute(
                sql.SQL("DROP DATABASE {} WITH (FORCE)").format(sql.Identifier(name))
            )
        self._databases.discard(name)

    def conninfo(self, *, database: str, user: str) -> str:
        if self._external_root_conninfo:
            return make_conninfo(
                self._external_root_conninfo,
                dbname=database,
                user=user,
                password=self._runtime_password,
                connect_timeout=5,
            )
        if self.socket_directory is None:
            raise AssertionError("temporary PostgreSQL harness is not initialized")
        return make_conninfo(
            host=str(self.socket_directory),
            port=self._port,
            dbname=database,
            user=user,
            connect_timeout=5,
        )

    def admin_conninfo(self, *, database: str) -> str:
        if self._external_root_conninfo:
            return make_conninfo(
                self._external_root_conninfo,
                dbname=database,
                user=_ADMIN_ROLE,
                password=self._admin_password,
                connect_timeout=5,
            )
        if self.socket_directory is None:
            raise AssertionError("temporary PostgreSQL harness is not initialized")
        return make_conninfo(
            host=str(self.socket_directory),
            port=self._port,
            dbname=database,
            user=_ADMIN_ROLE,
            connect_timeout=5,
        )

    @property
    def port(self) -> int:
        return self._port

    @property
    def host(self) -> str:
        if self._external_root_conninfo:
            if self._external_host is None:
                raise AssertionError("temporary PostgreSQL harness is not initialized")
            return self._external_host
        if self.enable_tcp_password_auth:
            return "127.0.0.1"
        if self.socket_directory is None:
            raise AssertionError("temporary PostgreSQL harness is not initialized")
        return str(self.socket_directory)

    @property
    def admin_user(self) -> str:
        return _ADMIN_ROLE

    @property
    def admin_password(self) -> str:
        return self._admin_password

    def tcp_conninfo(self, *, database: str, user: str, password: str) -> str:
        if not self.enable_tcp_password_auth:
            raise AssertionError("temporary PostgreSQL TCP password auth is disabled")
        if self._external_root_conninfo:
            return make_conninfo(
                self._external_root_conninfo,
                dbname=database,
                user=user,
                password=password,
                connect_timeout=5,
            )
        return make_conninfo(
            host="127.0.0.1",
            port=self._port,
            dbname=database,
            user=user,
            password=password,
            sslmode="disable",
            connect_timeout=5,
        )

    def _provision_roles(self) -> None:
        with psycopg.connect(
            self.admin_conninfo(database="postgres"),
            autocommit=True,
        ) as connection:
            self._provision_role_specs(connection)
        self._roles_provisioned = True

    def _provision_role_specs(
        self,
        connection,
        *,
        ownership_marker: Optional[str] = None,
    ) -> None:
        for role_name, can_login in _ROLE_SPECS:
            login_clause = sql.SQL("LOGIN") if can_login else sql.SQL("NOLOGIN")
            connection.execute(
                sql.SQL(
                    "CREATE ROLE {} {} NOINHERIT NOSUPERUSER NOCREATEDB "
                    "NOCREATEROLE NOBYPASSRLS"
                ).format(sql.Identifier(role_name), login_clause)
            )
            if ownership_marker is not None:
                connection.execute(
                    sql.SQL("COMMENT ON ROLE {} IS {}").format(
                        sql.Identifier(role_name),
                        sql.Literal(ownership_marker),
                    )
                )
            if can_login:
                connection.execute(
                    sql.SQL("ALTER ROLE {} PASSWORD {}").format(
                        sql.Identifier(role_name),
                        sql.Literal(self._runtime_password),
                    )
                )
        connection.execute(
            "GRANT schema_owner TO iam_migration_runner "
            "WITH INHERIT FALSE, SET TRUE"
        )
        connection.execute(
            "GRANT iam_self_summary_reader TO schema_owner "
            "WITH INHERIT FALSE, SET TRUE"
        )
        connection.execute(
            "GRANT profile_schema_owner TO profile_migration_runner "
            "WITH INHERIT FALSE, SET TRUE"
        )
        connection.execute(
            "GRANT demand_schema_owner TO demand_migration_runner "
            "WITH INHERIT FALSE, SET TRUE"
        )
        connection.execute(
            "GRANT schema_owner TO demand_migration_runner "
            "WITH INHERIT FALSE, SET TRUE"
        )
        connection.execute(
            "GRANT matching_schema_owner TO matching_migration_runner "
            "WITH INHERIT FALSE, SET TRUE"
        )
        connection.execute(
            "GRANT schema_owner TO matching_migration_runner "
            "WITH INHERIT FALSE, SET TRUE"
        )
        connection.execute(
            "GRANT profile_schema_owner TO matching_migration_runner "
            "WITH INHERIT FALSE, SET TRUE"
        )
        connection.execute(
            "GRANT demand_schema_owner TO matching_migration_runner "
            "WITH INHERIT FALSE, SET TRUE"
        )
        connection.execute(
            "GRANT trust_schema_owner TO matching_migration_runner "
            "WITH INHERIT FALSE, SET TRUE"
        )
        connection.execute(
            "GRANT trust_schema_owner TO trust_migration_runner "
            "WITH INHERIT FALSE, SET TRUE"
        )
        connection.execute(
            "GRANT schema_owner TO trust_migration_runner "
            "WITH INHERIT FALSE, SET TRUE"
        )
        connection.execute(
            "GRANT taxonomy_schema_owner TO taxonomy_migration_runner "
            "WITH INHERIT FALSE, SET TRUE"
        )

    def _cleanup_external_resources_on_connection(self, connection):
        cleanup_errors: list[BaseException] = []
        try:
            owned_databases = self._attributable_external_databases(
                connection,
                marker=self._ownership_marker,
            )
        except BaseException as error:
            cleanup_errors.append(error)
            return set(), cleanup_errors
        for database in sorted(owned_databases):
            try:
                connection.execute(
                    sql.SQL(
                        "DROP DATABASE IF EXISTS {} WITH (FORCE)"
                    ).format(sql.Identifier(database))
                )
                self._databases.discard(database)
            except BaseException as error:
                cleanup_errors.append(error)
        if cleanup_errors:
            return set(), cleanup_errors
        self._databases.clear()
        try:
            owned_roles = {
                role_name
                for role_name, marker in self._external_role_ownership_rows(
                    connection
                )
                if marker == self._ownership_marker
            }
        except BaseException as error:
            cleanup_errors.append(error)
            return set(), cleanup_errors
        for role_name, _can_login in reversed(_ROLE_SPECS):
            if role_name not in owned_roles:
                continue
            try:
                connection.execute(
                    sql.SQL("DROP ROLE IF EXISTS {}").format(
                        sql.Identifier(role_name)
                    )
                )
                owned_roles.discard(role_name)
            except BaseException as error:
                cleanup_errors.append(error)
        if _ADMIN_ROLE in owned_roles:
            try:
                connection.execute(
                    sql.SQL("DROP ROLE IF EXISTS {}").format(
                        sql.Identifier(_ADMIN_ROLE)
                    )
                )
                owned_roles.discard(_ADMIN_ROLE)
            except BaseException as error:
                cleanup_errors.append(error)
        return owned_roles, cleanup_errors

    @staticmethod
    def _external_role_ownership_rows(connection):
        return connection.execute(
            "SELECT exact_role.rolname,"
            "pg_catalog.shobj_description(exact_role.oid,'pg_authid') "
            "FROM pg_catalog.pg_roles AS exact_role "
            "WHERE exact_role.rolname=ANY(%s) "
            "ORDER BY exact_role.rolname",
            (list(_HARNESS_ROLE_NAMES),),
        ).fetchall()

    @staticmethod
    def _external_database_ownership_rows(connection):
        return connection.execute(
            "SELECT exact_database.datname,owner.rolname,"
            "pg_catalog.shobj_description(exact_database.oid,'pg_database') "
            "FROM pg_catalog.pg_database AS exact_database "
            "JOIN pg_catalog.pg_roles AS owner "
            "ON owner.oid=exact_database.datdba "
            "WHERE pg_catalog.left(exact_database.datname,"
            "pg_catalog.length(%s))=%s "
            "OR pg_catalog.left(pg_catalog.shobj_description("
            "exact_database.oid,'pg_database'),"
            "pg_catalog.length(%s))=%s "
            "ORDER BY exact_database.datname",
            (
                _DATABASE_NAME_PREFIX,
                _DATABASE_NAME_PREFIX,
                _OWNERSHIP_MARKER_PREFIX,
                _OWNERSHIP_MARKER_PREFIX,
            ),
        ).fetchall()

    @staticmethod
    def _database_marker_suffix(marker: str) -> str:
        if _OWNERSHIP_MARKER_PATTERN.fullmatch(marker) is None:
            raise AssertionError(
                "external PostgreSQL harness ownership marker is invalid"
            )
        return marker[len(_OWNERSHIP_MARKER_PREFIX) :][:32]

    @classmethod
    def _attributable_external_databases(
        cls,
        connection,
        *,
        marker: str,
    ) -> set[str]:
        marker_suffix = cls._database_marker_suffix(marker)
        attributable: set[str] = set()
        for database, owner, comment in cls._external_database_ownership_rows(
            connection
        ):
            name_match = _DATABASE_NAME_PATTERN.fullmatch(database)
            if (
                name_match is None
                or int(name_match.group(1), 16) == 0
                or name_match.group(2) != marker_suffix
                or owner != "schema_owner"
                or comment not in (None, marker)
            ):
                raise AssertionError(
                    "external PostgreSQL harness database ownership is unsafe"
                )
            attributable.add(database)
        return attributable

    @staticmethod
    def _drop_external_databases(connection, database_names: set[str]) -> None:
        for database in sorted(database_names):
            connection.execute(
                sql.SQL("DROP DATABASE IF EXISTS {} WITH (FORCE)").format(
                    sql.Identifier(database)
                )
            )

    @staticmethod
    def _drop_external_roles(connection, role_names: set[str]) -> None:
        for role_name, _can_login in reversed(_ROLE_SPECS):
            if role_name in role_names:
                connection.execute(
                    sql.SQL("DROP ROLE IF EXISTS {}").format(
                        sql.Identifier(role_name)
                    )
                )
        if _ADMIN_ROLE in role_names:
            connection.execute(
                sql.SQL("DROP ROLE IF EXISTS {}").format(
                    sql.Identifier(_ADMIN_ROLE)
                )
            )

    def _release_external_lock_connection(
        self,
        *,
        fallback_connection=None,
        suppress_errors: bool = False,
    ) -> None:
        connection = self._external_lock_connection
        lock_was_held = connection is not None
        if connection is None:
            connection = fallback_connection
        self._external_lock_connection = None
        if connection is None:
            return
        release_error: Optional[BaseException] = None
        if lock_was_held:
            try:
                released = connection.execute(
                    "SELECT pg_catalog.pg_advisory_unlock(%s,%s)",
                    _EXTERNAL_ROLE_LOCK_KEY,
                ).fetchone()
                if released != (True,):
                    release_error = AssertionError(
                        "external PostgreSQL harness advisory lock was lost"
                    )
            except BaseException as error:
                release_error = error
        try:
            connection.close()
        except BaseException as error:
            if release_error is None:
                release_error = error
        if release_error is not None and not suppress_errors:
            raise release_error

    def _root_conninfo(self, *, database: str) -> str:
        if self._external_root_conninfo is None:
            raise AssertionError("external PostgreSQL root connection is unavailable")
        return make_conninfo(
            self._external_root_conninfo,
            dbname=database,
            connect_timeout=5,
        )

    def _run(self, program: str, *arguments: str) -> None:
        if self.binary_directory is None:
            raise AssertionError("PostgreSQL binary directory is unavailable")
        executable = self.binary_directory / program
        completed = subprocess.run(
            (str(executable),) + arguments,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
            timeout=60,
        )
        if completed.returncode != 0:
            server_log = ""
            if self.log_path is not None and self.log_path.is_file():
                server_log = self.log_path.read_text(encoding="utf-8", errors="replace")
            raise AssertionError(
                "%s failed with exit %d:\n%s\n%s"
                % (program, completed.returncode, completed.stdout, server_log)
            )

    def _require_started(self) -> None:
        if not self._started:
            raise AssertionError("temporary PostgreSQL harness is not running")


def _find_postgres18_binaries() -> Path:
    configured = os.environ.get("DESIRE_POSTGRES18_BIN")
    candidates = []
    if configured:
        candidates.append(Path(configured))
    candidates.append(Path("/opt/homebrew/opt/postgresql@18/bin"))
    discovered = shutil.which("postgres")
    if discovered:
        candidates.append(Path(discovered).resolve().parent)

    for candidate in candidates:
        required = ("postgres", "initdb", "pg_ctl")
        if all((candidate / name).is_file() for name in required):
            completed = subprocess.run(
                (str(candidate / "postgres"), "--version"),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                check=False,
                timeout=5,
            )
            if completed.returncode == 0 and "PostgreSQL) 18." in completed.stdout:
                return candidate
    raise AssertionError(
        "INTEGRATION_DEPENDENCY_NOT_AVAILABLE: PostgreSQL 18 binaries; "
        "set DESIRE_POSTGRES18_BIN to the directory containing postgres/initdb/pg_ctl"
    )


def _available_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])
