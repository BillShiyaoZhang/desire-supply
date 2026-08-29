"""TEST-PG-IAM-PLATFORM-ADMIN-001: PostgreSQL command boundary is closed."""

from __future__ import annotations

from dataclasses import FrozenInstanceError, fields
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
import unittest
from uuid import UUID

import psycopg

from desire_platform.identity_access.adapters.postgres.migrations import (
    IamContractSources,
    IamMigrationRunner,
    MigrationCatalog,
    PsycopgMigrationDriver,
    PsycopgMigrationSettings,
)
from desire_platform.identity_access.domain.errors import IamError

from desire_platform.identity_access.adapters.postgres.platform_user_lifecycle import (
    PLATFORM_USER_POSTGRES_WRITE_CHECKPOINTS,
    PlatformUserPostgresDatabaseRequest,
    PlatformUserPostgresExecutionScope,
    PlatformUserPostgresGeneratedIds,
    PlatformUserPostgresOperation,
    PlatformUserPostgresReceiptMaterial,
    PlatformUserPostgresSettings,
    PlatformUserPostgresWriteCheckpoint,
    PsycopgPlatformUserLifecycleUnitOfWorkFactory,
)
from tests.storage.postgres.postgres18_harness import TemporaryPostgres18
from tests.support.iam_authority_lifecycle_builders import ClosedSchemaValidator


ROOT = Path(__file__).resolve().parents[3]
MIGRATION_ROOT = (
    ROOT / "src/desire_platform/identity_access/adapters/postgres/migrations"
)


def _uuid(value: int) -> UUID:
    return UUID(int=value)


def _request(
    operation: PlatformUserPostgresOperation = PlatformUserPostgresOperation.SUSPEND_USER,
) -> PlatformUserPostgresDatabaseRequest:
    scope = PlatformUserPostgresExecutionScope(
        actor_user_id=_uuid(1),
        current_session_id=_uuid(2),
        target_user_id=_uuid(3),
        command_id=_uuid(4),
        correlation_id=_uuid(5),
        causation_id=_uuid(4),
        trace_id=_uuid(7),
        original_actor_id=None,
    )
    receipt = PlatformUserPostgresReceiptMaterial(
        receipt_id=scope.command_id,
        idempotency_key_digest=b"i" * 32,
        idempotency_key_digest_key_id="iam-receipt-idempotency-hmac-2026-01",
        payload_hash=b"p" * 32,
        payload_hash_key_id="iam-receipt-payload-hmac-2026-01",
        canonicalization_version="restricted-canonical-json-v1",
        retain_until=datetime.now(timezone.utc) + timedelta(days=30),
    )
    return PlatformUserPostgresDatabaseRequest(
        operation=operation,
        scope=scope,
        receipt=receipt,
        expected_user_version=7,
        reason_code="SAFETY_REVIEW",
        generated_ids=PlatformUserPostgresGeneratedIds(
            audit_event_id=_uuid(8),
            main_outbox_event_id=_uuid(9),
            session_event_namespace=_uuid(10),
        ),
    )


class PlatformUserPostgresUnitOfWorkRedTest(unittest.TestCase):
    def test_public_request_is_frozen_digest_only_and_operation_closed(self) -> None:
        request = _request()
        self.assertEqual(
            tuple(item.value for item in PlatformUserPostgresOperation),
            (
                "SuspendUser",
                "ResumeUser",
                "RevokeAllSessions",
                "GrantPlatformDuty",
                "RevokePlatformDuty",
            ),
        )
        with self.assertRaises(FrozenInstanceError):
            request.reason_code = "CHANGED"  # type: ignore[misc]
        public_names = {
            field.name
            for value in (request, request.scope, request.receipt, request.generated_ids)
            for field in fields(value)
        }
        self.assertNotIn("idempotency_key", public_names)
        self.assertNotIn("password", public_names)
        self.assertNotIn("reason_note", public_names)
        self.assertNotIn("raw_session_handle", public_names)
        self.assertNotIn("external_identity", public_names)

    def test_settings_and_checkpoint_vocabulary_are_closed(self) -> None:
        self.assertEqual(PlatformUserPostgresSettings().runtime_role, "iam_app")
        with self.assertRaises(ValueError):
            PlatformUserPostgresSettings(runtime_role="schema_owner")
        self.assertEqual(
            PLATFORM_USER_POSTGRES_WRITE_CHECKPOINTS,
            tuple(PlatformUserPostgresWriteCheckpoint),
        )
        self.assertEqual(
            tuple(item.value for item in PlatformUserPostgresWriteCheckpoint),
            (
                "command_receipt.claim",
                "session_family.revoke",
                "session.revoke",
                "platform_duty.mutate",
                "user.version-cas",
                "audit_event.insert",
                "outbox_event.insert",
                "command_receipt.complete",
            ),
        )

    def test_factory_exposes_only_the_reviewed_programs(self) -> None:
        public_execute = {
            name
            for name in dir(PsycopgPlatformUserLifecycleUnitOfWorkFactory)
            if name.startswith("execute_")
        }
        self.assertEqual(
            public_execute,
            {
                "execute_suspend_user",
                "execute_resume_user",
                "execute_revoke_all_sessions",
                "execute_grant_platform_duty",
                "execute_revoke_platform_duty",
            },
        )

    def test_forward_duty_migration_is_closed_and_does_not_open_role_grants(self) -> None:
        sql = (
            ROOT
            / "src/desire_platform/identity_access/adapters/postgres/migrations"
            / "0030_expand__internal_sandbox_platform_duty_admin.sql"
        ).read_text(encoding="utf-8")
        for fragment in (
            "INTERNAL_SANDBOX_PLATFORM_DUTY_ADMIN",
            "lock_internal_sandbox_platform_duty_admin_v1",
            "SELF_MANAGEMENT",
            "LAST_ACTIVE_ACCESS_ADMIN",
            "ck_command_receipt_sandbox_platform_duty_admin",
            "rls_sandbox_duty_admin_receipt",
            "trg_sandbox_platform_duty_grant_transition",
            "read_internal_sandbox_account_workbench_v2",
            "BETWEEN 0 AND 8",
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, sql)
        self.assertNotIn("INSERT INTO iam.user_role_grants", sql)
        self.assertNotIn("INSERT INTO iam.membership_role_grants", sql)

    def test_migration_installs_narrow_rls_lock_and_transition_capability(self) -> None:
        sql = (
            ROOT
            / "src/desire_platform/identity_access/adapters/postgres/migrations"
            / "0018_expand__platform_user_lifecycle_uow.sql"
        ).read_text(encoding="utf-8")
        for fragment in (
            "PLATFORM_USER_ADMIN",
            "iam_api.platform_user_admin_context_authorized_v1",
            "iam_api.lock_platform_user_admin_v1",
            "ck_command_receipt_platform_user_admin_response",
            "rls_platform_admin_receipt",
            "rls_platform_admin_user_update",
            "rls_platform_admin_family_update",
            "rls_platform_admin_session_update",
            "trg_platform_admin_user_transition",
            "GRANT EXECUTE ON FUNCTION iam_api.lock_platform_user_admin_v1",
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, sql)
        self.assertNotIn("password", sql.lower())

    def test_forward_hardening_migration_closes_all_account_admin_gaps(self) -> None:
        sql = (
            ROOT
            / "src/desire_platform/identity_access/adapters/postgres/migrations"
            / "0032_expand__internal_sandbox_account_admin_hardening.sql"
        ).read_text(encoding="utf-8")
        for fragment in (
            "validate_internal_sandbox_platform_user_admin_target_v2",
            "internal_sandbox_platform_user_admin_authorized_v2",
            "lock_internal_sandbox_platform_user_admin_v2",
            "probe_platform_user_admin_command_receipt_v1",
            "lock_internal_sandbox_platform_duty_admin_v2",
            "EXPIRED_SUPERSEDED",
            "REVOKE EXECUTE ON FUNCTION iam_api.lock_platform_user_admin_v1",
            "REVOKE EXECUTE ON FUNCTION",
            "iam_api.lock_internal_sandbox_platform_duty_admin_v1",
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, sql)
        self.assertNotIn("DISABLE ROW LEVEL SECURITY", sql)
        self.assertNotIn("BYPASSRLS", sql)

    def test_request_rejects_self_management_and_receipt_misbinding(self) -> None:
        request = _request()
        with self.assertRaises(ValueError):
            PlatformUserPostgresExecutionScope(
                actor_user_id=request.scope.actor_user_id,
                current_session_id=request.scope.current_session_id,
                target_user_id=request.scope.actor_user_id,
                command_id=request.scope.command_id,
                correlation_id=request.scope.correlation_id,
                causation_id=request.scope.causation_id,
                trace_id=request.scope.trace_id,
                original_actor_id=None,
            )
        with self.assertRaises(ValueError):
            PlatformUserPostgresDatabaseRequest(
                operation=request.operation,
                scope=request.scope,
                receipt=PlatformUserPostgresReceiptMaterial(
                    receipt_id=_uuid(99),
                    idempotency_key_digest=b"i" * 32,
                    idempotency_key_digest_key_id=request.receipt.idempotency_key_digest_key_id,
                    payload_hash=b"p" * 32,
                    payload_hash_key_id=request.receipt.payload_hash_key_id,
                    canonicalization_version="restricted-canonical-json-v1",
                    retain_until=request.receipt.retain_until,
                ),
                expected_user_version=7,
                reason_code="SAFETY_REVIEW",
                generated_ids=request.generated_ids,
            )


class _ConnectionSource:
    def __init__(self, conninfo: str) -> None:
        self.conninfo = conninfo

    def checkout(self) -> Any:
        return psycopg.connect(self.conninfo, autocommit=True)

    def release(self, connection: Any) -> None:
        connection.close()

    def discard(self, connection: Any) -> None:
        connection.close()


class RealPostgres18PlatformUserLifecycleTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.postgres = TemporaryPostgres18().start()
        cls.catalog = MigrationCatalog.load(MIGRATION_ROOT)
        cls.contract_sources = IamContractSources(
            api_contract_bytes=(ROOT / "contracts/api/iam-v1.openapi.yaml").read_bytes(),
            event_contract_bytes=(ROOT / "contracts/events/iam-v1.schema.json").read_bytes(),
        )

    @classmethod
    def tearDownClass(cls) -> None:
        cls.postgres.stop()

    def setUp(self) -> None:
        self.database = self.postgres.create_database()
        driver = PsycopgMigrationDriver(
            settings=PsycopgMigrationSettings(
                conninfo=self.postgres.conninfo(
                    database=self.database,
                    user="iam_migration_runner",
                ),
                application_name="desire-platform-user-uow-red",
            ),
            dbapi=psycopg,
        )
        report = IamMigrationRunner(
            driver=driver,
            runner_version="platform-user-uow-red/1",
        ).run(catalog=self.catalog, contract_sources=self.contract_sources)
        self.assertEqual(
            report.applied_versions,
            tuple(item.descriptor.version for item in self.catalog.artifacts),
        )
        self.now = datetime.now(timezone.utc)
        self.actor_id = _uuid(101)
        self.actor_session_id = _uuid(102)
        self.target_id = _uuid(103)
        self.target_session_id = _uuid(104)
        self.target_family_id = _uuid(105)
        self.second_target_id = _uuid(141)
        self._seed_graph()

    def tearDown(self) -> None:
        self.postgres.drop_database(self.database)

    def _admin(self):
        return psycopg.connect(
            self.postgres.admin_conninfo(database=self.database),
        )

    def _seed_graph(self) -> None:
        actor_family_id = _uuid(106)
        bootstrap_id = _uuid(130)
        created = self.now - timedelta(days=1)
        session_created = self.now - timedelta(minutes=4)
        with self._admin() as connection:
            connection.execute(
                "INSERT INTO iam.users "
                "(id,status,display_handle,aggregate_version,created_at,updated_at) "
                "VALUES (%s,'ACTIVE','access_admin_pg',3,%s,%s),"
                "(%s,'ACTIVE','target_user_pg',7,%s,%s),"
                "(%s,'ACTIVE','second_target_pg',5,%s,%s)",
                (
                    self.actor_id,
                    created,
                    created,
                    self.target_id,
                    created,
                    created,
                    self.second_target_id,
                    created,
                    created,
                ),
            )
            connection.execute(
                "INSERT INTO infra.iam_sandbox_bootstrap_state ("
                "bootstrap_id,manifest_sha256,revision,issuer,account_count,status,"
                "created_at,updated_at) VALUES (%s,%s,1,%s,3,'ACTIVE',%s,%s)",
                (bootstrap_id, b"m" * 32, "https://synthetic.invalid", created, created),
            )
            account_sql = (
                "INSERT INTO infra.iam_sandbox_bootstrap_accounts ("
                "bootstrap_id,account_code,user_id,current_external_identity_id,"
                "current_subject_digest,current_subject_digest_key_id,"
                "invitation_contact_point_id,current_contact_point_id,"
                "current_recipient_binding_digest,"
                "current_recipient_binding_digest_key_id,activation_event_id,"
                "revocation_event_id,authority_shape_sha256,manifest_revision,"
                "updated_at) VALUES ("
                "%s,%s,%s,%s,%s,'synthetic-subject-v1',%s,%s,%s,"
                "'synthetic-recipient-v1',%s,%s,%s,1,%s)"
            )
            connection.execute(
                account_sql,
                (
                    bootstrap_id,
                    "access_admin",
                    self.actor_id,
                    _uuid(131),
                    b"a" * 32,
                    _uuid(132),
                    _uuid(133),
                    b"b" * 32,
                    _uuid(134),
                    _uuid(135),
                    b"c" * 32,
                    created,
                ),
            )
            connection.execute(
                account_sql,
                (
                    bootstrap_id,
                    "second_target",
                    self.second_target_id,
                    _uuid(142),
                    b"g" * 32,
                    _uuid(143),
                    _uuid(144),
                    b"h" * 32,
                    _uuid(145),
                    _uuid(146),
                    b"i" * 32,
                    created,
                ),
            )
            connection.execute(
                account_sql,
                (
                    bootstrap_id,
                    "target_user",
                    self.target_id,
                    _uuid(136),
                    b"d" * 32,
                    _uuid(137),
                    _uuid(138),
                    b"e" * 32,
                    _uuid(139),
                    _uuid(140),
                    b"f" * 32,
                    created,
                ),
            )
            connection.execute(
                "INSERT INTO iam.platform_duty_grants ("
                "id,user_id,duty_code,granted_by_kind,granted_by_id,granted_at,"
                "expires_at,revoked_at,revocation_reason_code,aggregate_version,"
                "created_at,updated_at) VALUES ("
                "%s,%s,'ACCESS_ADMIN','SYSTEM',%s,%s,NULL,NULL,NULL,1,%s,%s)",
                (_uuid(107), self.actor_id, _uuid(108), created, created, created),
            )
            connection.execute(
                "INSERT INTO iam.session_families ("
                "id,user_id,status,current_generation,revoked_at,"
                "revocation_reason_code,aggregate_version,created_at,updated_at) "
                "VALUES (%s,%s,'ACTIVE',1,NULL,NULL,1,%s,%s),"
                "(%s,%s,'ACTIVE',1,NULL,NULL,2,%s,%s)",
                (
                    actor_family_id,
                    self.actor_id,
                    session_created,
                    session_created,
                    self.target_family_id,
                    self.target_id,
                    session_created,
                    session_created,
                ),
            )
            session_sql = (
                "INSERT INTO iam.sessions ("
                "id,user_id,family_id,generation,predecessor_session_id,handle_digest,"
                "handle_digest_key_id,csrf_salt,csrf_key_id,csrf_digest,"
                "verified_contact_point_id,verified_at,verified_for_invitation_id,"
                "auth_transaction_id,auth_time,acr_code,amr_codes,created_at,"
                "last_activity_at,idle_expires_at,absolute_expires_at,updated_at,"
                "device_label,status,rotation_reason,revoked_at,"
                "revocation_reason_code,aggregate_version) VALUES ("
                "%s,%s,%s,1,NULL,%s,'session-hmac-v1',%s,'csrf-hmac-v1',%s,"
                "NULL,NULL,NULL,NULL,%s,'urn:desire:acr:mfa',"
                "ARRAY['otp','pwd']::text[],%s,%s,%s,%s,%s,'Browser','ACTIVE',"
                "'LOGIN',NULL,NULL,%s)"
            )
            connection.execute(
                session_sql,
                (
                    self.actor_session_id,
                    self.actor_id,
                    actor_family_id,
                    b"a" * 32,
                    b"b" * 32,
                    b"c" * 32,
                    self.now - timedelta(minutes=5),
                    session_created,
                    self.now - timedelta(minutes=1),
                    self.now + timedelta(minutes=30),
                    self.now + timedelta(days=1),
                    self.now - timedelta(minutes=1),
                    1,
                ),
            )
            connection.execute(
                session_sql,
                (
                    self.target_session_id,
                    self.target_id,
                    self.target_family_id,
                    b"d" * 32,
                    b"e" * 32,
                    b"f" * 32,
                    self.now - timedelta(minutes=20),
                    session_created,
                    self.now - timedelta(minutes=1),
                    self.now + timedelta(minutes=30),
                    self.now + timedelta(days=1),
                    self.now - timedelta(minutes=1),
                    4,
                ),
            )

    def _request(self) -> PlatformUserPostgresDatabaseRequest:
        command_id = _uuid(110)
        return PlatformUserPostgresDatabaseRequest(
            operation=PlatformUserPostgresOperation.SUSPEND_USER,
            scope=PlatformUserPostgresExecutionScope(
                actor_user_id=self.actor_id,
                current_session_id=self.actor_session_id,
                target_user_id=self.target_id,
                command_id=command_id,
                correlation_id=_uuid(111),
                causation_id=command_id,
                trace_id=_uuid(112),
                original_actor_id=None,
            ),
            receipt=PlatformUserPostgresReceiptMaterial(
                receipt_id=command_id,
                idempotency_key_digest=b"i" * 32,
                idempotency_key_digest_key_id="iam-receipt-idempotency-hmac-2026-01",
                payload_hash=b"p" * 32,
                payload_hash_key_id="iam-receipt-payload-hmac-2026-01",
                canonicalization_version="restricted-canonical-json-v1",
                retain_until=self.now + timedelta(days=30),
            ),
            expected_user_version=7,
            reason_code="SAFETY_REVIEW",
            generated_ids=PlatformUserPostgresGeneratedIds(
                audit_event_id=_uuid(113),
                main_outbox_event_id=_uuid(114),
                session_event_namespace=_uuid(115),
            ),
        )

    def _duty_request(
        self,
        *,
        operation: PlatformUserPostgresOperation,
        command_id: UUID,
        expected_version: int,
        grant_id: UUID | None,
        digest_byte: bytes,
        target_user_id: UUID | None = None,
        duty_code: str = "FINANCE_OPERATOR",
        payload_byte: bytes | None = None,
    ) -> PlatformUserPostgresDatabaseRequest:
        target = target_user_id or self.target_id
        payload = payload_byte or bytes([digest_byte[0] + 1])
        return PlatformUserPostgresDatabaseRequest(
            operation=operation,
            scope=PlatformUserPostgresExecutionScope(
                actor_user_id=self.actor_id,
                current_session_id=self.actor_session_id,
                target_user_id=target,
                command_id=command_id,
                correlation_id=_uuid(command_id.int + 1),
                causation_id=command_id,
                trace_id=_uuid(command_id.int + 2),
                original_actor_id=None,
            ),
            receipt=PlatformUserPostgresReceiptMaterial(
                receipt_id=command_id,
                idempotency_key_digest=digest_byte * 32,
                idempotency_key_digest_key_id=(
                    "iam-receipt-idempotency-hmac-2026-01"
                ),
                payload_hash=payload * 32,
                payload_hash_key_id="iam-receipt-payload-hmac-2026-01",
                canonicalization_version="restricted-canonical-json-v1",
                retain_until=self.now + timedelta(days=30),
            ),
            expected_user_version=expected_version,
            reason_code="ACCESS_REVIEW",
            generated_ids=PlatformUserPostgresGeneratedIds(
                audit_event_id=_uuid(command_id.int + 3),
                main_outbox_event_id=_uuid(command_id.int + 4),
                session_event_namespace=_uuid(command_id.int + 5),
                platform_duty_grant_id=grant_id,
            ),
            duty_code=duty_code,
        )

    def _lifecycle_request(
        self,
        *,
        operation: PlatformUserPostgresOperation,
        target_user_id: UUID,
        command_id: UUID,
        expected_version: int,
        digest_byte: bytes,
    ) -> PlatformUserPostgresDatabaseRequest:
        return PlatformUserPostgresDatabaseRequest(
            operation=operation,
            scope=PlatformUserPostgresExecutionScope(
                actor_user_id=self.actor_id,
                current_session_id=self.actor_session_id,
                target_user_id=target_user_id,
                command_id=command_id,
                correlation_id=_uuid(command_id.int + 1),
                causation_id=command_id,
                trace_id=_uuid(command_id.int + 2),
                original_actor_id=None,
            ),
            receipt=PlatformUserPostgresReceiptMaterial(
                receipt_id=command_id,
                idempotency_key_digest=digest_byte * 32,
                idempotency_key_digest_key_id=(
                    "iam-receipt-idempotency-hmac-2026-01"
                ),
                payload_hash=bytes([digest_byte[0] + 1]) * 32,
                payload_hash_key_id="iam-receipt-payload-hmac-2026-01",
                canonicalization_version="restricted-canonical-json-v1",
                retain_until=self.now + timedelta(days=30),
            ),
            expected_user_version=expected_version,
            reason_code="ACCESS_REVIEW",
            generated_ids=PlatformUserPostgresGeneratedIds(
                audit_event_id=_uuid(command_id.int + 3),
                main_outbox_event_id=_uuid(command_id.int + 4),
                session_event_namespace=_uuid(command_id.int + 5),
            ),
        )

    def _factory(self) -> PsycopgPlatformUserLifecycleUnitOfWorkFactory:
        return PsycopgPlatformUserLifecycleUnitOfWorkFactory(
            connections=_ConnectionSource(
                self.postgres.conninfo(database=self.database, user="iam_app")
            ),
            event_validator=ClosedSchemaValidator.for_events(),
            response_validator=ClosedSchemaValidator.for_openapi(),
        )

    def test_suspend_commits_receipt_audit_outbox_and_exact_replay(self) -> None:
        factory = PsycopgPlatformUserLifecycleUnitOfWorkFactory(
            connections=_ConnectionSource(
                self.postgres.conninfo(database=self.database, user="iam_app")
            ),
            event_validator=ClosedSchemaValidator.for_events(),
            response_validator=ClosedSchemaValidator.for_openapi(),
        )
        request = self._request()
        result = factory.execute_suspend_user(request)
        self.assertFalse(result.replayed)
        self.assertEqual(result.safe_response["status"], "SUSPENDED")
        self.assertEqual(result.safe_response["revoked_session_count"], 1)
        self.assertEqual(result.safe_response["revoked_session_family_count"], 1)
        replay = factory.execute_suspend_user(request)
        self.assertTrue(replay.replayed)
        self.assertEqual(replay.safe_response, result.safe_response)
        with self._admin() as connection:
            facts = connection.execute(
                "SELECT "
                "(SELECT status FROM iam.users WHERE id=%s),"
                "(SELECT status FROM iam.session_families WHERE id=%s),"
                "(SELECT status FROM iam.sessions WHERE id=%s),"
                "(SELECT status FROM infra.command_receipts WHERE id=%s),"
                "(SELECT count(*) FROM audit.audit_events WHERE command_id=%s),"
                "(SELECT count(*) FROM infra.outbox_events WHERE causation_id=%s)",
                (
                    self.target_id,
                    self.target_family_id,
                    self.target_session_id,
                    request.scope.command_id,
                    request.scope.command_id,
                    request.scope.command_id,
                ),
            ).fetchone()
        self.assertEqual(facts, ("SUSPENDED", "REVOKED", "REVOKED", "COMPLETED", 1, 2))

    def test_grant_and_revoke_platform_duty_commit_exact_ledgers_and_replay(self) -> None:
        factory = PsycopgPlatformUserLifecycleUnitOfWorkFactory(
            connections=_ConnectionSource(
                self.postgres.conninfo(database=self.database, user="iam_app")
            ),
            event_validator=ClosedSchemaValidator.for_events(),
            response_validator=ClosedSchemaValidator.for_openapi(),
        )
        grant_id = _uuid(150)
        grant = self._duty_request(
            operation=PlatformUserPostgresOperation.GRANT_PLATFORM_DUTY,
            command_id=_uuid(151),
            expected_version=7,
            grant_id=grant_id,
            digest_byte=b"g",
        )
        granted = factory.execute_grant_platform_duty(grant)
        self.assertFalse(granted.replayed)
        self.assertEqual(granted.response_entity_tag, '"v8"')
        self.assertTrue(factory.execute_grant_platform_duty(grant).replayed)

        revoke = self._duty_request(
            operation=PlatformUserPostgresOperation.REVOKE_PLATFORM_DUTY,
            command_id=_uuid(160),
            expected_version=8,
            grant_id=None,
            digest_byte=b"r",
        )
        revoked = factory.execute_revoke_platform_duty(revoke)
        self.assertFalse(revoked.replayed)
        self.assertEqual(revoked.response_entity_tag, '"v9"')
        self.assertTrue(factory.execute_revoke_platform_duty(revoke).replayed)
        late_grant_replay = factory.execute_grant_platform_duty(grant)
        self.assertTrue(late_grant_replay.replayed)
        self.assertEqual(late_grant_replay.safe_response, granted.safe_response)

        with self._admin() as connection:
            facts = connection.execute(
                "SELECT "
                "(SELECT aggregate_version FROM iam.users WHERE id=%s),"
                "(SELECT revoked_at IS NOT NULL FROM iam.platform_duty_grants "
                " WHERE id=%s),"
                "(SELECT aggregate_version FROM iam.platform_duty_grants WHERE id=%s),"
                "(SELECT count(*) FROM infra.command_receipts WHERE id IN (%s,%s)),"
                "(SELECT count(*) FROM audit.audit_events "
                " WHERE command_id IN (%s,%s)),"
                "(SELECT count(*) FROM infra.outbox_events "
                " WHERE causation_id IN (%s,%s))",
                (
                    self.target_id,
                    grant_id,
                    grant_id,
                    grant.scope.command_id,
                    revoke.scope.command_id,
                    grant.scope.command_id,
                    revoke.scope.command_id,
                    grant.scope.command_id,
                    revoke.scope.command_id,
                ),
            ).fetchone()
        self.assertEqual(facts, (9, True, 2, 2, 2, 2))

    def test_command_scope_idempotency_conflicts_are_409_across_duty_and_target(self) -> None:
        factory = self._factory()
        first = self._duty_request(
            operation=PlatformUserPostgresOperation.GRANT_PLATFORM_DUTY,
            command_id=_uuid(250),
            expected_version=7,
            grant_id=_uuid(251),
            digest_byte=b"k",
            payload_byte=b"l",
        )
        granted = factory.execute_grant_platform_duty(first)
        self.assertFalse(granted.replayed)

        different_duty = self._duty_request(
            operation=PlatformUserPostgresOperation.GRANT_PLATFORM_DUTY,
            command_id=_uuid(260),
            expected_version=8,
            grant_id=_uuid(261),
            digest_byte=b"k",
            payload_byte=b"m",
            duty_code="OPERATIONS_REVIEWER",
        )
        with self.assertRaises(IamError) as duty_conflict:
            factory.execute_grant_platform_duty(different_duty)
        self.assertEqual(duty_conflict.exception.code, "IDEMPOTENCY_KEY_REUSED")

        different_target = self._duty_request(
            operation=PlatformUserPostgresOperation.GRANT_PLATFORM_DUTY,
            command_id=_uuid(270),
            expected_version=5,
            grant_id=_uuid(271),
            digest_byte=b"k",
            payload_byte=b"n",
            target_user_id=self.second_target_id,
        )
        with self.assertRaises(IamError) as target_conflict:
            factory.execute_grant_platform_duty(different_target)
        self.assertEqual(target_conflict.exception.code, "IDEMPOTENCY_KEY_REUSED")

        with self._admin() as connection:
            facts = connection.execute(
                "SELECT "
                "(SELECT aggregate_version FROM iam.users WHERE id=%s),"
                "(SELECT aggregate_version FROM iam.users WHERE id=%s),"
                "(SELECT count(*) FROM iam.platform_duty_grants "
                " WHERE user_id=%s AND revoked_at IS NULL),"
                "(SELECT count(*) FROM iam.platform_duty_grants "
                " WHERE user_id=%s AND revoked_at IS NULL),"
                "(SELECT count(*) FROM infra.command_receipts "
                " WHERE principal_id=%s AND command_name='GrantPlatformDuty' "
                " AND idempotency_key_digest=%s),"
                "(SELECT count(*) FROM audit.audit_events "
                " WHERE command_id IN (%s,%s,%s)),"
                "(SELECT count(*) FROM infra.outbox_events "
                " WHERE causation_id IN (%s,%s,%s))",
                (
                    self.target_id,
                    self.second_target_id,
                    self.target_id,
                    self.second_target_id,
                    self.actor_id,
                    b"k" * 32,
                    first.scope.command_id,
                    different_duty.scope.command_id,
                    different_target.scope.command_id,
                    first.scope.command_id,
                    different_duty.scope.command_id,
                    different_target.scope.command_id,
                ),
            ).fetchone()
        self.assertEqual(facts, (8, 5, 1, 0, 1, 1, 1))

    def test_expired_unrevoked_duty_is_superseded_before_atomic_regrant(self) -> None:
        expired_grant_id = _uuid(280)
        new_grant_id = _uuid(281)
        with self._admin() as connection:
            connection.execute(
                "INSERT INTO iam.platform_duty_grants ("
                "id,user_id,duty_code,granted_by_kind,granted_by_id,granted_at,"
                "expires_at,revoked_at,revocation_reason_code,aggregate_version,"
                "created_at,updated_at) VALUES ("
                "%s,%s,'FINANCE_OPERATOR','SYSTEM',%s,%s,%s,NULL,NULL,4,%s,%s)",
                (
                    expired_grant_id,
                    self.target_id,
                    _uuid(282),
                    self.now - timedelta(days=2),
                    self.now - timedelta(hours=1),
                    self.now - timedelta(days=2),
                    self.now - timedelta(days=2),
                ),
            )

        request = self._duty_request(
            operation=PlatformUserPostgresOperation.GRANT_PLATFORM_DUTY,
            command_id=_uuid(290),
            expected_version=7,
            grant_id=new_grant_id,
            digest_byte=b"x",
        )
        result = self._factory().execute_grant_platform_duty(request)
        self.assertFalse(result.replayed)
        self.assertEqual(result.response_entity_tag, '"v8"')

        with self._admin() as connection:
            facts = connection.execute(
                "SELECT "
                "(SELECT revoked_at IS NOT NULL FROM iam.platform_duty_grants "
                " WHERE id=%s),"
                "(SELECT revocation_reason_code FROM iam.platform_duty_grants "
                " WHERE id=%s),"
                "(SELECT aggregate_version FROM iam.platform_duty_grants "
                " WHERE id=%s),"
                "(SELECT revoked_at IS NULL FROM iam.platform_duty_grants WHERE id=%s),"
                "(SELECT aggregate_version FROM iam.platform_duty_grants WHERE id=%s),"
                "(SELECT count(*) FROM iam.platform_duty_grants "
                " WHERE user_id=%s AND duty_code='FINANCE_OPERATOR' "
                " AND revoked_at IS NULL),"
                "(SELECT aggregate_version FROM iam.users WHERE id=%s),"
                "(SELECT count(*) FROM infra.command_receipts WHERE id=%s),"
                "(SELECT count(*) FROM audit.audit_events WHERE command_id=%s),"
                "(SELECT count(*) FROM infra.outbox_events WHERE causation_id=%s)",
                (
                    expired_grant_id,
                    expired_grant_id,
                    expired_grant_id,
                    new_grant_id,
                    new_grant_id,
                    self.target_id,
                    self.target_id,
                    request.scope.command_id,
                    request.scope.command_id,
                    request.scope.command_id,
                ),
            ).fetchone()
        self.assertEqual(
            facts,
            (True, "EXPIRED_SUPERSEDED", 5, True, 1, 1, 8, 1, 1, 1),
        )

    def test_future_unrevoked_duty_fails_closed_before_receipt_claim_commits(self) -> None:
        future_grant_id = _uuid(295)
        with self._admin() as connection:
            connection.execute(
                "INSERT INTO iam.platform_duty_grants ("
                "id,user_id,duty_code,granted_by_kind,granted_by_id,granted_at,"
                "expires_at,revoked_at,revocation_reason_code,aggregate_version,"
                "created_at,updated_at) VALUES ("
                "%s,%s,'FINANCE_OPERATOR','SYSTEM',%s,%s,%s,NULL,NULL,2,%s,%s)",
                (
                    future_grant_id,
                    self.target_id,
                    _uuid(296),
                    self.now + timedelta(days=1),
                    self.now + timedelta(days=2),
                    self.now,
                    self.now,
                ),
            )

        request = self._duty_request(
            operation=PlatformUserPostgresOperation.GRANT_PLATFORM_DUTY,
            command_id=_uuid(297),
            expected_version=7,
            grant_id=_uuid(298),
            digest_byte=b"z",
        )
        with self.assertRaises(IamError) as rejected:
            self._factory().execute_grant_platform_duty(request)
        self.assertEqual(rejected.exception.code, "INVALID_STATE_TRANSITION")

        with self._admin() as connection:
            facts = connection.execute(
                "SELECT "
                "(SELECT revoked_at IS NULL FROM iam.platform_duty_grants "
                " WHERE id=%s),"
                "(SELECT aggregate_version FROM iam.platform_duty_grants "
                " WHERE id=%s),"
                "(SELECT aggregate_version FROM iam.users WHERE id=%s),"
                "(SELECT count(*) FROM infra.command_receipts WHERE id=%s),"
                "(SELECT count(*) FROM audit.audit_events WHERE command_id=%s),"
                "(SELECT count(*) FROM infra.outbox_events WHERE causation_id=%s)",
                (
                    future_grant_id,
                    future_grant_id,
                    self.target_id,
                    request.scope.command_id,
                    request.scope.command_id,
                    request.scope.command_id,
                ),
            ).fetchone()
        self.assertEqual(facts, (True, 2, 7, 0, 0, 0))

    def test_nonbootstrap_targets_are_rejected_for_all_three_lifecycle_writes(self) -> None:
        cases = (
            (PlatformUserPostgresOperation.SUSPEND_USER, _uuid(301), "ACTIVE", 11, _uuid(310), b"s"),
            (PlatformUserPostgresOperation.RESUME_USER, _uuid(302), "SUSPENDED", 12, _uuid(320), b"t"),
            (
                PlatformUserPostgresOperation.REVOKE_ALL_SESSIONS,
                _uuid(303),
                "ACTIVE",
                13,
                _uuid(330),
                b"u",
            ),
        )
        created = self.now - timedelta(days=1)
        with self._admin() as connection:
            for _, user_id, status, version, _, _ in cases:
                connection.execute(
                    "INSERT INTO iam.users ("
                    "id,status,display_handle,aggregate_version,created_at,updated_at) "
                    "VALUES (%s,%s,%s,%s,%s,%s)",
                    (
                        user_id,
                        status,
                        "nonbootstrap_%s" % user_id.int,
                        version,
                        created,
                        created,
                    ),
                )

        factory = self._factory()
        executors = {
            PlatformUserPostgresOperation.SUSPEND_USER: factory.execute_suspend_user,
            PlatformUserPostgresOperation.RESUME_USER: factory.execute_resume_user,
            PlatformUserPostgresOperation.REVOKE_ALL_SESSIONS: (
                factory.execute_revoke_all_sessions
            ),
        }
        for operation, target, _, version, command_id, digest_byte in cases:
            request = self._lifecycle_request(
                operation=operation,
                target_user_id=target,
                command_id=command_id,
                expected_version=version,
                digest_byte=digest_byte,
            )
            with self.subTest(operation=operation.value):
                with self.assertRaises(IamError) as rejected:
                    executors[operation](request)
                self.assertEqual(rejected.exception.code, "RESOURCE_NOT_FOUND")

        with self._admin() as connection:
            users = connection.execute(
                "SELECT id,status,aggregate_version FROM iam.users "
                "WHERE id IN (%s,%s,%s) ORDER BY id",
                tuple(item[1] for item in cases),
            ).fetchall()
            ledgers = connection.execute(
                "SELECT "
                "(SELECT count(*) FROM infra.command_receipts "
                " WHERE id IN (%s,%s,%s)),"
                "(SELECT count(*) FROM audit.audit_events "
                " WHERE command_id IN (%s,%s,%s)),"
                "(SELECT count(*) FROM infra.outbox_events "
                " WHERE causation_id IN (%s,%s,%s))",
                tuple(item[4] for item in cases) * 3,
            ).fetchone()
        self.assertEqual(
            users,
            [(item[1], item[2], item[3]) for item in cases],
        )
        self.assertEqual(ledgers, (0, 0, 0))

    def test_workbench_v2_keeps_roleless_synthetic_target_visible(self) -> None:
        with psycopg.connect(
            self.postgres.conninfo(database=self.database, user="iam_app"),
            autocommit=True,
        ) as connection:
            connection.execute("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY")
            for name, value in (
                ("app.scope_kind", "INTERNAL_SANDBOX_ACCOUNT_ADMIN_READ"),
                ("app.operation", "LIST_ACCOUNTS"),
                ("app.actor_user_id", str(self.actor_id)),
                ("app.session_id", str(self.actor_session_id)),
                ("app.target_user_id", ""),
                ("app.organization_id", ""),
            ):
                connection.execute(
                    "SELECT pg_catalog.set_config(%s,%s,true)",
                    (name, value),
                )
            document = connection.execute(
                "SELECT iam_api.read_internal_sandbox_account_workbench_v2("
                "%s,%s,NULL)",
                (self.actor_id, self.actor_session_id),
            ).fetchone()[0]
            connection.execute("COMMIT")
        self.assertEqual(len(document["accounts"]), 3)
        target = next(
            account
            for account in document["accounts"]
            if account["user_id"] == str(self.target_id)
        )
        self.assertEqual(target["role_codes"], [])


if __name__ == "__main__":
    unittest.main()
