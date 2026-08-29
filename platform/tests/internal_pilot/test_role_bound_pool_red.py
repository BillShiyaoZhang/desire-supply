from __future__ import annotations

import threading
import time
import unittest
from dataclasses import dataclass, replace

from desire_platform.internal_pilot.postgres_pool import (
    PostgresEndpointSettings,
    PsycopgRoleBoundPoolFactory,
    RoleBoundPoolError,
)
from desire_platform.runtime.config import DatabaseProfile


RAW_PASSWORD = b"synthetic-database-password-never-log"


def profile() -> DatabaseProfile:
    return DatabaseProfile(
        capability_id="IAM_SESSION",
        online_role="iam_session_authenticator",
        credential_ref="secret://sandbox-db/iam-session#v1",
        application_name="desire-api-iam-session",
        max_pool_size=2,
        checkout_timeout_ms=75,
        statement_timeout_ms=2_000,
        lock_timeout_ms=500,
        idle_in_transaction_timeout_ms=5_000,
    )


@dataclass
class Secret:
    material: bytearray

    def __repr__(self) -> str:
        return "Secret(material=<redacted>)"


class Info:
    transaction_status = 0


class Result:
    def __init__(self, row):
        self.row = row

    def fetchone(self):
        return self.row


class Connection:
    def __init__(
        self,
        *,
        expected_profile: DatabaseProfile,
        endpoint: PostgresEndpointSettings,
        role: str | None = None,
        major: int = 18,
    ) -> None:
        self.expected_profile = expected_profile
        self.endpoint = endpoint
        self.role = role or expected_profile.online_role
        self.major = major
        self.info = Info()
        self.autocommit = True
        self.closed = False
        self.commands: list[tuple[str, object]] = []

    def execute(self, statement, parameters=None):
        self.commands.append((statement, parameters))
        if statement.startswith("SELECT session_user,current_user"):
            return Result(
                (
                    self.role,
                    self.role,
                    self.endpoint.database,
                    self.major,
                    self.expected_profile.application_name,
                    "off",
                    *(None for _setting in range(13)),
                )
            )
        if statement == "SELECT 1":
            return Result((1,))
        return Result(None)

    def close(self):
        self.closed = True


class DbApi:
    def __init__(self, *, role: str | None = None, major: int = 18) -> None:
        self.role = role
        self.major = major
        self.calls: list[dict[str, object]] = []
        self.connections: list[Connection] = []
        self.expected_profile: DatabaseProfile | None = None
        self.endpoint: PostgresEndpointSettings | None = None

    def connect(self, **kwargs):
        self.calls.append(kwargs)
        connection = Connection(
            expected_profile=self.expected_profile,
            endpoint=self.endpoint,
            role=self.role,
            major=self.major,
        )
        self.connections.append(connection)
        return connection


def build_pool(*, dbapi: DbApi | None = None):
    selected_dbapi = dbapi or DbApi()
    endpoint = PostgresEndpointSettings(
        host="db",
        port=5432,
        database="desire",
        transport_security="TRUSTED_CONTAINER_NETWORK",
    )
    selected_dbapi.expected_profile = profile()
    selected_dbapi.endpoint = endpoint
    factory = PsycopgRoleBoundPoolFactory(endpoint=endpoint, dbapi=selected_dbapi)
    secret = Secret(bytearray(RAW_PASSWORD))
    return factory.create(profile(), secret), selected_dbapi, secret


class RoleBoundPsycopgPoolTests(unittest.TestCase):
    def test_factory_accepts_exact_trust_online_roles_and_rejects_owner_roles(self) -> None:
        endpoint = PostgresEndpointSettings(
            host="db",
            port=5432,
            database="desire",
            transport_security="TRUSTED_CONTAINER_NETWORK",
        )
        factory = PsycopgRoleBoundPoolFactory(endpoint=endpoint, dbapi=DbApi())
        for role in (
            "trust_self",
            "trust_officer",
            "trust_appeal",
            "trust_decision",
        ):
            with self.subTest(role=role):
                selected = replace(
                    profile(),
                    capability_id=role.upper(),
                    online_role=role,
                    credential_ref=f"secret://sandbox-db/{role.replace('_', '-')}#v1",
                    application_name=f"desire-{role.replace('_', '-')}",
                )
                pool = factory.create(selected, Secret(bytearray(RAW_PASSWORD)))
                self.assertIs(pool._profile, selected)
                pool.close()

        for role in ("trust_owner", "trust_migration_runner"):
            with self.subTest(rejected_role=role), self.assertRaises(TypeError):
                factory.create(
                    replace(profile(), online_role=role),
                    Secret(bytearray(RAW_PASSWORD)),
                )

    def test_connects_with_exact_role_and_secret_without_retaining_a_dsn(self) -> None:
        pool, dbapi, _ = build_pool()
        try:
            connection = pool.checkout()
            pool.release(connection)

            self.assertEqual(len(dbapi.calls), 1)
            call = dbapi.calls[0]
            self.assertEqual(call["user"], "iam_session_authenticator")
            self.assertEqual(call["password"], RAW_PASSWORD.decode("ascii"))
            self.assertEqual(call["host"], "db")
            self.assertEqual(call["sslmode"], "disable")
            self.assertNotIn(RAW_PASSWORD.decode("ascii"), repr(pool))
            self.assertNotIn("secret://", repr(pool))
            statements = [item[0] for item in connection.commands]
            self.assertIn("RESET ROLE", statements)
            self.assertIn("RESET ALL", statements)
            self.assertIn("CLOSE ALL", statements)
            self.assertIn("DISCARD TEMP", statements)
        finally:
            pool.close()

    def test_wrong_role_or_postgres_major_fails_closed_and_discards(self) -> None:
        for dbapi in (DbApi(role="postgres"), DbApi(major=17)):
            with self.subTest(role=dbapi.role, major=dbapi.major):
                pool, selected, _ = build_pool(dbapi=dbapi)
                with self.assertRaises(RoleBoundPoolError) as raised:
                    pool.checkout()
                self.assertEqual(raised.exception.code, "DATABASE_UNAVAILABLE")
                self.assertTrue(selected.connections[-1].closed)
                self.assertNotIn(RAW_PASSWORD.decode("ascii"), repr(raised.exception))
                pool.close()

    def test_pool_is_bounded_times_out_and_reuses_only_reset_connections(self) -> None:
        pool, dbapi, _ = build_pool()
        first = pool.checkout()
        second = pool.checkout()
        started = time.monotonic()
        with self.assertRaises(RoleBoundPoolError) as raised:
            pool.checkout()
        self.assertEqual(raised.exception.code, "DATABASE_POOL_EXHAUSTED")
        self.assertGreaterEqual(time.monotonic() - started, 0.05)

        pool.release(first)
        reused = pool.checkout()
        self.assertIs(reused, first)
        self.assertEqual(len(dbapi.connections), 2)
        pool.release(reused)
        pool.release(second)
        pool.close()
        self.assertTrue(all(connection.closed for connection in dbapi.connections))

    def test_readiness_is_exact_and_close_prevents_new_checkout(self) -> None:
        pool, dbapi, _ = build_pool()
        self.assertIsNone(pool.check_readiness(timeout_ms=50))
        self.assertIn("SELECT 1", [item[0] for item in dbapi.connections[0].commands])
        pool.close()
        pool.close()
        with self.assertRaises(RoleBoundPoolError) as raised:
            pool.checkout()
        self.assertEqual(raised.exception.code, "DATABASE_POOL_CLOSED")

    def test_invalid_endpoint_and_destroyed_or_malformed_credential_are_rejected(self) -> None:
        with self.assertRaises(ValueError):
            PostgresEndpointSettings(
                host="https://db",
                port=5432,
                database="desire",
                transport_security="TRUSTED_CONTAINER_NETWORK",
            )
        with self.assertRaises(ValueError):
            PostgresEndpointSettings(
                host="db.example.test",
                port=5432,
                database="desire",
                transport_security="TRUSTED_CONTAINER_NETWORK",
            )

        endpoint = PostgresEndpointSettings(
            host="db.example.test",
            port=5432,
            database="desire",
            transport_security="TLS_REQUIRED",
        )
        factory = PsycopgRoleBoundPoolFactory(endpoint=endpoint, dbapi=DbApi())
        for material in (bytearray(), bytearray(b"x" * 23), bytearray(b"x\n" * 20)):
            with self.subTest(size=len(material)):
                with self.assertRaises(TypeError):
                    factory.create(profile(), Secret(material))


if __name__ == "__main__":
    unittest.main()
