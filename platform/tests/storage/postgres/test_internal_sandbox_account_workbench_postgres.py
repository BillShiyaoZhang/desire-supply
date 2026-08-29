from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
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
from desire_platform.identity_access.domain.errors import IamError
from desire_platform.internal_pilot.account_admin import (
    PsycopgInternalSandboxAccountAdminRepository,
)
from tests.storage.postgres.postgres18_harness import TemporaryPostgres18


ROOT = Path(__file__).resolve().parents[3]
MIGRATIONS = (
    ROOT / "src/desire_platform/identity_access/adapters/postgres/migrations"
)


def _id(value: int) -> UUID:
    return UUID(int=value)


class _Connections:
    def __init__(self, conninfo: str) -> None:
        self.conninfo = conninfo

    def checkout(self):
        return psycopg.connect(self.conninfo, autocommit=True)

    @staticmethod
    def release(connection) -> None:
        connection.close()

    @staticmethod
    def discard(connection) -> None:
        connection.close()


class InternalSandboxAccountWorkbenchPostgresTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.postgres = TemporaryPostgres18().start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.postgres.stop()

    def setUp(self) -> None:
        self.database = self.postgres.create_database()
        catalog = MigrationCatalog.load(MIGRATIONS)
        report = IamMigrationRunner(
            driver=PsycopgMigrationDriver(
                settings=PsycopgMigrationSettings(
                    conninfo=self.postgres.conninfo(
                        database=self.database,
                        user="iam_migration_runner",
                    ),
                    application_name="sandbox-account-workbench-pg18",
                ),
                dbapi=psycopg,
            ),
            runner_version="sandbox-account-workbench-pg18/1",
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
        self.assertEqual(report.applied_versions[-1], IAM_SCHEMA_HEAD_VERSION)
        replay = IamMigrationRunner(
            driver=PsycopgMigrationDriver(
                settings=PsycopgMigrationSettings(
                    conninfo=self.postgres.conninfo(
                        database=self.database,
                        user="iam_migration_runner",
                    ),
                    application_name="sandbox-account-workbench-pg18-replay",
                ),
                dbapi=psycopg,
            ),
            runner_version="sandbox-account-workbench-pg18/1",
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
        self.assertEqual(replay.applied_versions, ())
        self.assertEqual(
            replay.skipped_versions,
            tuple(range(IAM_SCHEMA_HEAD_VERSION + 1)),
        )
        self.now = datetime.now(timezone.utc)
        self.bootstrap_id = _id(200)
        self.actor_id = _id(201)
        self.target_id = _id(202)
        self.actor_session_id = _id(203)
        self._seed()
        self.repository = PsycopgInternalSandboxAccountAdminRepository(
            connections=_Connections(
                self.postgres.conninfo(database=self.database, user="iam_app")
            )
        )

    def tearDown(self) -> None:
        self.postgres.drop_database(self.database)

    def _admin(self):
        return psycopg.connect(
            self.postgres.admin_conninfo(database=self.database),
        )

    def _seed(self) -> None:
        created = self.now - timedelta(days=1)
        session_created = self.now - timedelta(minutes=5)
        with self._admin() as connection:
            connection.execute(
                "INSERT INTO iam.users "
                "(id,status,display_handle,aggregate_version,created_at,updated_at) "
                "VALUES (%s,'ACTIVE','sandbox_access_admin_01',2,%s,%s),"
                "(%s,'SUSPENDED','sandbox_operator_01',4,%s,%s)",
                (
                    self.actor_id,
                    created,
                    created,
                    self.target_id,
                    created,
                    created,
                ),
            )
            connection.execute(
                "INSERT INTO infra.iam_sandbox_bootstrap_state ("
                "bootstrap_id,manifest_sha256,revision,issuer,account_count,"
                "status,created_at,updated_at) VALUES ("
                "%s,%s,1,'https://id.example.test',2,'ACTIVE',%s,%s)",
                (self.bootstrap_id, b"m" * 32, created, created),
            )
            for offset, code, user_id in (
                (0, "access_admin_01", self.actor_id),
                (20, "operations_reviewer_01", self.target_id),
            ):
                connection.execute(
                    "INSERT INTO infra.iam_sandbox_bootstrap_accounts ("
                    "bootstrap_id,account_code,user_id,current_external_identity_id,"
                    "current_subject_digest,current_subject_digest_key_id,"
                    "invitation_contact_point_id,current_contact_point_id,"
                    "current_recipient_binding_digest,"
                    "current_recipient_binding_digest_key_id,activation_event_id,"
                    "revocation_event_id,authority_shape_sha256,manifest_revision,"
                    "updated_at) VALUES ("
                    "%s,%s,%s,%s,%s,'subject-key-v1',%s,%s,%s,"
                    "'recipient-key-v1',%s,%s,%s,1,%s)",
                    (
                        self.bootstrap_id,
                        code,
                        user_id,
                        _id(300 + offset),
                        bytes([1 + offset]) * 32,
                        _id(301 + offset),
                        _id(302 + offset),
                        bytes([2 + offset]) * 32,
                        _id(303 + offset),
                        _id(304 + offset),
                        bytes([3 + offset]) * 32,
                        created,
                    ),
                )
            connection.execute(
                "INSERT INTO iam.platform_duty_grants ("
                "id,user_id,duty_code,granted_by_kind,granted_by_id,granted_at,"
                "expires_at,revoked_at,revocation_reason_code,aggregate_version,"
                "created_at,updated_at) VALUES "
                "(%s,%s,'ACCESS_ADMIN','SYSTEM',%s,%s,NULL,NULL,NULL,1,%s,%s),"
                "(%s,%s,'OPERATIONS_REVIEWER','SYSTEM',%s,%s,NULL,NULL,NULL,1,%s,%s)",
                (
                    _id(400),
                    self.actor_id,
                    _id(401),
                    created,
                    created,
                    created,
                    _id(402),
                    self.target_id,
                    _id(403),
                    created,
                    created,
                    created,
                ),
            )
            actor_family_id = _id(500)
            target_family_id = _id(501)
            connection.execute(
                "INSERT INTO iam.session_families ("
                "id,user_id,status,current_generation,revoked_at,"
                "revocation_reason_code,aggregate_version,created_at,updated_at) "
                "VALUES (%s,%s,'ACTIVE',1,NULL,NULL,1,%s,%s),"
                "(%s,%s,'ACTIVE',1,NULL,NULL,1,%s,%s)",
                (
                    actor_family_id,
                    self.actor_id,
                    session_created,
                    session_created,
                    target_family_id,
                    self.target_id,
                    session_created,
                    session_created,
                ),
            )
            session_sql = (
                "INSERT INTO iam.sessions ("
                "id,user_id,family_id,generation,predecessor_session_id,"
                "handle_digest,handle_digest_key_id,csrf_salt,csrf_key_id,"
                "csrf_digest,verified_contact_point_id,verified_at,"
                "verified_for_invitation_id,auth_transaction_id,auth_time,"
                "acr_code,amr_codes,created_at,last_activity_at,idle_expires_at,"
                "absolute_expires_at,updated_at,device_label,status,"
                "rotation_reason,revoked_at,revocation_reason_code,"
                "aggregate_version) VALUES ("
                "%s,%s,%s,1,NULL,%s,'session-hmac-v1',%s,'csrf-hmac-v1',%s,"
                "NULL,NULL,NULL,NULL,%s,'urn:desire:acr:mfa',"
                "ARRAY['otp']::text[],%s,%s,%s,%s,%s,'Browser','ACTIVE',"
                "'LOGIN',NULL,NULL,1)"
            )
            for session_id, user_id, family_id, byte_value in (
                (self.actor_session_id, self.actor_id, actor_family_id, 10),
                (_id(204), self.target_id, target_family_id, 20),
            ):
                connection.execute(
                    session_sql,
                    (
                        session_id,
                        user_id,
                        family_id,
                        bytes([byte_value]) * 32,
                        bytes([byte_value + 1]) * 32,
                        bytes([byte_value + 2]) * 32,
                        self.now - timedelta(minutes=6),
                        session_created,
                        self.now - timedelta(minutes=1),
                        self.now + timedelta(minutes=30),
                        self.now + timedelta(days=1),
                        self.now - timedelta(minutes=1),
                    ),
                )

    def test_list_detail_and_authority_revocation_are_database_closed(self) -> None:
        collection = self.repository.list_accounts(
            actor_user_id=str(self.actor_id),
            session_id=str(self.actor_session_id),
        )
        self.assertEqual(
            tuple(item.account_code for item in collection.accounts),
            ("access_admin_01", "operations_reviewer_01"),
        )
        self.assertEqual(collection.accounts[0].role_codes, ("ACCESS_ADMIN",))
        self.assertTrue(collection.accounts[0].is_self)
        self.assertEqual(collection.accounts[1].active_session_count, 1)

        detail = self.repository.get_account(
            actor_user_id=str(self.actor_id),
            session_id=str(self.actor_session_id),
            target_user_id=str(self.target_id),
        )
        self.assertEqual(detail.entity_tag, '"v4"')
        self.assertEqual(detail.role_codes, ("OPERATIONS_REVIEWER",))
        self.assertFalse(detail.is_self)
        for forbidden in ("issuer", "subject", "contact", "digest"):
            self.assertNotIn(forbidden, repr(collection).lower())

        with self.assertRaises(IamError) as missing:
            self.repository.get_account(
                actor_user_id=str(self.actor_id),
                session_id=str(self.actor_session_id),
                target_user_id=str(_id(999)),
            )
        self.assertEqual(missing.exception.code, "RESOURCE_NOT_FOUND")

        with self._admin() as connection:
            connection.execute(
                "UPDATE iam.platform_duty_grants SET revoked_at=%s,"
                "revocation_reason_code='ACCESS_REVIEW',updated_at=%s,"
                "aggregate_version=aggregate_version+1 WHERE user_id=%s "
                "AND duty_code='ACCESS_ADMIN'",
                (self.now, self.now, self.actor_id),
            )
        with self.assertRaises(IamError) as denied:
            self.repository.list_accounts(
                actor_user_id=str(self.actor_id),
                session_id=str(self.actor_session_id),
            )
        self.assertEqual(denied.exception.code, "SERVICE_UNAVAILABLE")


if __name__ == "__main__":
    unittest.main()
