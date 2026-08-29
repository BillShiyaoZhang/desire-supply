"""Real PostgreSQL 18 acceptance for Accept receipt-principal replay.

The replay preflight deliberately authenticates an ordinary ``LOGIN`` session
before the receipt table is touched.  All identifiers and digests in this test
are synthetic; no bearer material or other recoverable secret is constructed.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
from typing import Any, Callable
import unittest
from uuid import UUID

import psycopg

from desire_platform.identity_access.adapters.postgres.migrations import (
    IAM_SCHEMA_HEAD_VERSION,
    IamContractSources,
    IamMigrationRunner,
    MigrationCatalog,
    PsycopgMigrationDriver,
    PsycopgMigrationSettings,
)
from desire_platform.identity_access.adapters.postgres.organization_admin_accept import (
    PsycopgOrganizationAcceptScopeResolver,
)
from desire_platform.identity_access.domain.errors import IamError
from tests.storage.postgres.postgres18_harness import TemporaryPostgres18


ROOT = Path(__file__).resolve().parents[3]
MIGRATIONS = (
    ROOT / "src/desire_platform/identity_access/adapters/postgres/migrations"
)
FUNCTION_SIGNATURE = "iam_api.resolve_accept_receipt_principal_v1(uuid,uuid)"


def _id(value: int) -> UUID:
    return UUID(int=value)


def _digest(label: str) -> bytes:
    return hashlib.sha256(label.encode("ascii")).digest()


class _TrackingConnection:
    def __init__(self, raw: Any, statements: list[str]) -> None:
        self._raw = raw
        self._statements = statements

    @property
    def autocommit(self) -> bool:
        return bool(self._raw.autocommit)

    @property
    def info(self) -> Any:
        return self._raw.info

    def execute(self, query: str, params: Any = None) -> Any:
        self._statements.append(query)
        return self._raw.execute(query, params)

    def close(self) -> None:
        self._raw.close()


class _TrackingConnections:
    def __init__(self, conninfo: str) -> None:
        self._conninfo = conninfo
        self.statements: list[str] = []

    def checkout(self) -> _TrackingConnection:
        raw = psycopg.connect(self._conninfo, autocommit=True)
        return _TrackingConnection(raw, self.statements)

    @staticmethod
    def release(connection: _TrackingConnection) -> None:
        connection.close()

    @staticmethod
    def discard(connection: _TrackingConnection) -> None:
        connection.close()


class AcceptReceiptPrincipalPostgres18RedTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.postgres = TemporaryPostgres18().start()
        cls.database = cls.postgres.create_database()
        try:
            catalog = MigrationCatalog.load(MIGRATIONS)
            if IAM_SCHEMA_HEAD_VERSION < 36:
                raise AssertionError("Accept receipt principal requires IAM head 34")
            report = IamMigrationRunner(
                driver=PsycopgMigrationDriver(
                    settings=PsycopgMigrationSettings(
                        conninfo=cls.postgres.conninfo(
                            database=cls.database,
                            user="iam_migration_runner",
                        ),
                        application_name="accept-receipt-principal-pg18",
                    ),
                    dbapi=psycopg,
                ),
                runner_version="accept-receipt-principal-pg18/1",
            ).run(
                catalog=catalog,
                contract_sources=IamContractSources(
                    api_contract_bytes=(
                        ROOT / "contracts/api/iam-v1.openapi.yaml"
                    ).read_bytes(),
                    event_contract_bytes=(
                        ROOT / "contracts/events/iam-v1.schema.json"
                    ).read_bytes(),
                ),
            )
            if report.applied_versions != tuple(
                range(IAM_SCHEMA_HEAD_VERSION + 1)
            ):
                raise AssertionError("fresh IAM migration did not apply exact v0-v34")
        except BaseException:
            cls.postgres.drop_database(cls.database)
            cls.postgres.stop()
            raise

    @classmethod
    def tearDownClass(cls) -> None:
        cls.postgres.drop_database(cls.database)
        cls.postgres.stop()

    @classmethod
    def _admin(cls):
        return psycopg.connect(
            cls.postgres.admin_conninfo(database=cls.database),
            autocommit=False,
        )

    @classmethod
    def _runtime_conninfo(cls, role: str) -> str:
        return cls.postgres.conninfo(database=cls.database, user=role)

    def _seed_active_login(self, ordinal: int) -> tuple[UUID, UUID, UUID]:
        user_id = _id(10_000 + ordinal * 10)
        family_id = _id(10_001 + ordinal * 10)
        session_id = _id(10_002 + ordinal * 10)
        now = datetime.now(timezone.utc).replace(microsecond=0)
        created = now - timedelta(hours=4)
        with self._admin() as connection:
            connection.execute(
                "INSERT INTO iam.users "
                "(id,status,display_handle,aggregate_version,created_at,updated_at) "
                "VALUES (%s,'ACTIVE',%s,1,%s,%s)",
                (user_id, f"receipt_principal_{ordinal}", created, created),
            )
            connection.execute(
                "INSERT INTO iam.session_families ("
                "id,user_id,status,current_generation,revoked_at,"
                "revocation_reason_code,aggregate_version,created_at,updated_at) "
                "VALUES (%s,%s,'ACTIVE',1,NULL,NULL,1,%s,%s)",
                (family_id, user_id, created, created),
            )
            connection.execute(
                "INSERT INTO iam.sessions ("
                "id,user_id,family_id,generation,predecessor_session_id,"
                "handle_digest,handle_digest_key_id,csrf_salt,csrf_key_id,"
                "csrf_digest,verified_contact_point_id,verified_at,"
                "verified_for_invitation_id,auth_transaction_id,auth_time,"
                "acr_code,amr_codes,created_at,last_activity_at,idle_expires_at,"
                "absolute_expires_at,updated_at,device_label,status,"
                "rotation_reason,revoked_at,revocation_reason_code,"
                "aggregate_version) VALUES ("
                "%s,%s,%s,1,NULL,%s,'test-session-digest-v1',%s,"
                "'test-csrf-digest-v1',%s,NULL,NULL,NULL,NULL,%s,"
                "'urn:desire:acr:baseline',ARRAY['pwd']::text[],%s,%s,%s,%s,"
                "%s,'Browser','ACTIVE','LOGIN',NULL,NULL,1)",
                (
                    session_id,
                    user_id,
                    family_id,
                    _digest(f"session-{ordinal}"),
                    _digest(f"csrf-salt-{ordinal}"),
                    _digest(f"csrf-{ordinal}"),
                    created - timedelta(minutes=1),
                    created,
                    now - timedelta(minutes=1),
                    now + timedelta(hours=1),
                    now + timedelta(days=1),
                    now - timedelta(minutes=1),
                ),
            )
        return user_id, family_id, session_id

    def _direct_resolve(self, actor_id: UUID, session_id: UUID) -> dict[str, Any]:
        invitation_id = _id(99_001)
        with psycopg.connect(
            self._runtime_conninfo("iam_onboarding"), autocommit=True
        ) as connection:
            identity = connection.execute(
                "SELECT current_user,session_user"
            ).fetchone()
            self.assertEqual(identity, ("iam_onboarding", "iam_onboarding"))
            connection.execute("BEGIN ISOLATION LEVEL READ COMMITTED READ ONLY")
            for name, value in (
                ("app.scope_kind", "AUTH_PROTOCOL"),
                ("app.operation", "ACCEPT"),
                ("app.actor_user_id", str(actor_id)),
                ("app.target_user_id", str(actor_id)),
                ("app.session_id", str(session_id)),
                ("app.target_invitation_id", str(invitation_id)),
                ("app.command_name", "AcceptAccessInvitation"),
                ("app.command_version", "1"),
            ):
                configured = connection.execute(
                    "SELECT pg_catalog.set_config(%s,%s,true)", (name, value)
                ).fetchone()
                self.assertEqual(configured, (value,))
            row = connection.execute(
                "SELECT iam_api.resolve_accept_receipt_principal_v1(%s,%s)",
                (actor_id, session_id),
            ).fetchone()
            connection.execute("COMMIT")
        self.assertIsNotNone(row)
        self.assertIsInstance(row[0], dict)
        return row[0]

    def _bridge_receipt_replay(
        self, actor_id: UUID, session_id: UUID
    ) -> tuple[Any, list[str]]:
        connections = _TrackingConnections(self._runtime_conninfo("iam_onboarding"))
        resolver = PsycopgOrganizationAcceptScopeResolver(connections=connections)
        try:
            outcome: Any = resolver.resolve_receipt_replay(
                actor_user_id=actor_id,
                session_id=session_id,
                invitation_id=_id(99_001),
                expected_version=1,
                idempotency_candidates=(
                    ("iam-receipt-idempotency-hmac-2026-01", b"i" * 32),
                ),
                payload_hash_candidates=(
                    ("iam-receipt-payload-hmac-2026-01", b"p" * 32),
                ),
            )
        except BaseException as error:
            outcome = error
        return outcome, connections.statements

    def _mutate_without_lifecycle_triggers(
        self, statement: str, params: tuple[Any, ...]
    ) -> None:
        with self._admin() as connection:
            connection.execute("SET LOCAL session_replication_role = 'replica'")
            connection.execute(statement, params)

    def test_01_active_ordinary_login_resolves_then_reaches_receipt_rls(self) -> None:
        actor_id, family_id, session_id = self._seed_active_login(1)
        self.assertEqual(
            self._direct_resolve(actor_id, session_id),
            {
                "decision_code": "AUTHORIZED",
                "actor_user_id": str(actor_id),
                "session_id": str(session_id),
                "session_family_id": str(family_id),
            },
        )

        outcome, statements = self._bridge_receipt_replay(actor_id, session_id)
        self.assertIsNone(outcome)
        self.assertTrue(
            any(FUNCTION_SIGNATURE.split("(")[0] in item for item in statements)
        )
        self.assertTrue(
            any("FROM infra.command_receipts" in item for item in statements),
            "ACTIVE principal must proceed to the receipt RLS query",
        )

    def test_02_invalid_principals_fail_before_any_receipt_read(self) -> None:
        now = datetime.now(timezone.utc).replace(microsecond=0)
        cases: list[
            tuple[str, UUID, UUID, Callable[[], None] | None]
        ] = []

        suspended = self._seed_active_login(2)
        cases.append(
            (
                "user-suspended",
                suspended[0],
                suspended[2],
                lambda: self._mutate_without_lifecycle_triggers(
                    "UPDATE iam.users SET status='SUSPENDED',aggregate_version=2,"
                    "updated_at=%s WHERE id=%s",
                    (now, suspended[0]),
                ),
            )
        )
        revoked_session = self._seed_active_login(3)
        cases.append(
            (
                "session-revoked",
                revoked_session[0],
                revoked_session[2],
                lambda: self._mutate_without_lifecycle_triggers(
                    "UPDATE iam.sessions SET status='REVOKED',revoked_at=%s,"
                    "revocation_reason_code='TEST_REVOKED',aggregate_version=2,"
                    "updated_at=%s WHERE id=%s",
                    (now, now, revoked_session[2]),
                ),
            )
        )
        idle_expired = self._seed_active_login(4)
        cases.append(
            (
                "session-idle-expired",
                idle_expired[0],
                idle_expired[2],
                lambda: self._mutate_without_lifecycle_triggers(
                    "UPDATE iam.sessions SET last_activity_at=%s,idle_expires_at=%s,"
                    "aggregate_version=2,updated_at=%s WHERE id=%s",
                    (
                        now - timedelta(hours=2),
                        now - timedelta(hours=1),
                        now,
                        idle_expired[2],
                    ),
                ),
            )
        )
        absolute_expired = self._seed_active_login(5)
        cases.append(
            (
                "session-absolute-expired",
                absolute_expired[0],
                absolute_expired[2],
                lambda: self._mutate_without_lifecycle_triggers(
                    "UPDATE iam.sessions SET last_activity_at=%s,idle_expires_at=%s,"
                    "absolute_expires_at=%s,aggregate_version=2,updated_at=%s "
                    "WHERE id=%s",
                    (
                        now - timedelta(hours=3),
                        now - timedelta(hours=2),
                        now - timedelta(hours=1),
                        now,
                        absolute_expired[2],
                    ),
                ),
            )
        )
        revoked_family = self._seed_active_login(6)
        cases.append(
            (
                "family-revoked",
                revoked_family[0],
                revoked_family[2],
                lambda: self._mutate_without_lifecycle_triggers(
                    "UPDATE iam.session_families SET status='REVOKED',revoked_at=%s,"
                    "revocation_reason_code='TEST_REVOKED',aggregate_version=2,"
                    "updated_at=%s WHERE id=%s",
                    (now, now, revoked_family[1]),
                ),
            )
        )
        generation_mismatch = self._seed_active_login(7)
        cases.append(
            (
                "family-generation-mismatch",
                generation_mismatch[0],
                generation_mismatch[2],
                lambda: self._mutate_without_lifecycle_triggers(
                    "UPDATE iam.session_families SET current_generation=2,"
                    "aggregate_version=2,updated_at=%s WHERE id=%s",
                    (now, generation_mismatch[1]),
                ),
            )
        )
        active_for_missing_session = self._seed_active_login(8)
        cases.extend(
            (
                (
                    "missing-user",
                    _id(88_001),
                    _id(88_002),
                    None,
                ),
                (
                    "missing-session",
                    active_for_missing_session[0],
                    _id(88_003),
                    None,
                ),
            )
        )

        for label, actor_id, session_id, mutate in cases:
            with self.subTest(label=label):
                if mutate is not None:
                    mutate()
                self.assertEqual(
                    self._direct_resolve(actor_id, session_id),
                    {"decision_code": "AUTHENTICATION_REQUIRED"},
                )
                outcome, statements = self._bridge_receipt_replay(
                    actor_id, session_id
                )
                self.assertIsInstance(outcome, IamError)
                self.assertEqual(outcome.code, "AUTHENTICATION_REQUIRED")
                self.assertTrue(
                    any(
                        FUNCTION_SIGNATURE.split("(")[0] in item
                        for item in statements
                    )
                )
                self.assertFalse(
                    any("FROM infra.command_receipts" in item for item in statements),
                    "invalid principal must fail before the receipt RLS query",
                )

    def test_03_function_execute_is_closed_to_onboarding_only(self) -> None:
        with self._admin() as connection:
            row = connection.execute(
                "SELECT p.oid,"
                "ARRAY(SELECT CASE WHEN acl.grantee=0 THEN 'PUBLIC' "
                "ELSE pg_catalog.pg_get_userbyid(acl.grantee) END "
                "FROM pg_catalog.aclexplode(COALESCE("
                "p.proacl,pg_catalog.acldefault('f',p.proowner))) AS acl "
                "WHERE acl.privilege_type='EXECUTE' AND acl.grantee<>p.proowner "
                "ORDER BY 1),"
                "pg_catalog.has_function_privilege('iam_onboarding',p.oid,'EXECUTE'),"
                "pg_catalog.has_function_privilege('iam_app',p.oid,'EXECUTE'),"
                "pg_catalog.has_function_privilege("
                "'iam_session_authenticator',p.oid,'EXECUTE') "
                "FROM pg_catalog.pg_proc AS p "
                "WHERE p.oid=pg_catalog.to_regprocedure("
                "'iam_api.resolve_accept_receipt_principal_v1(uuid,uuid)')"
            ).fetchone()
        self.assertIsNotNone(row, "Accept receipt principal helper is not installed")
        self.assertEqual(row[1], ["iam_onboarding"])
        self.assertEqual(row[2:], (True, False, False))

        for role in ("iam_app", "iam_session_authenticator"):
            with self.subTest(role=role):
                with psycopg.connect(
                    self._runtime_conninfo(role), autocommit=True
                ) as connection:
                    with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                        connection.execute(
                            "SELECT iam_api.resolve_accept_receipt_principal_v1(%s,%s)",
                            (_id(77_001), _id(77_002)),
                        ).fetchone()


if __name__ == "__main__":
    unittest.main()
