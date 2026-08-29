"""PostgreSQL 18 behavior proof for IAM38 owned-Session revocation."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
import unittest
from uuid import UUID, uuid4

import psycopg

from desire_platform.identity_access.adapters.postgres.current_session_logout import (
    OWNED_SESSION_REVOCATION_FUNCTION_SIGNATURE,
    CurrentSessionLogoutPostgresGeneratedIds,
    CurrentSessionLogoutPostgresReceiptMaterial,
    OwnedSessionRevocationPostgresDatabaseRequest,
    OwnedSessionRevocationPostgresExecutionScope,
    PsycopgOwnedSessionRevocationUnitOfWorkFactory,
)
from desire_platform.identity_access.adapters.postgres.migrations import (
    IamContractSources,
    IamMigrationRunner,
    MigrationCatalog,
    PsycopgMigrationDriver,
    PsycopgMigrationSettings,
)
from desire_platform.identity_access.domain.errors import IamError
from tests.storage.postgres.postgres18_harness import TemporaryPostgres18


PLATFORM_ROOT = Path(__file__).resolve().parents[3]
MIGRATION_ROOT = (
    PLATFORM_ROOT
    / "src/desire_platform/identity_access/adapters/postgres/migrations"
)
IDEMPOTENCY_KEY_ID = "iam-receipt-idempotency-hmac-2026-01"
PAYLOAD_KEY_ID = "iam-receipt-payload-hmac-2026-01"
CANONICALIZATION = "restricted-canonical-json-v1"


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


class Iam38OwnedSessionRevocationPostgresTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.postgres = TemporaryPostgres18(enable_tcp_password_auth=True).start()
        cls.addClassCleanup(cls.postgres.stop)
        cls.catalog = MigrationCatalog.load(MIGRATION_ROOT)
        cls.contract_sources = IamContractSources(
            api_contract_bytes=(
                PLATFORM_ROOT / "contracts/api/iam-v1.openapi.yaml"
            ).read_bytes(),
            event_contract_bytes=(
                PLATFORM_ROOT / "contracts/events/iam-v1.schema.json"
            ).read_bytes(),
        )

    def setUp(self) -> None:
        self.database = self.postgres.create_database()
        IamMigrationRunner(
            driver=PsycopgMigrationDriver(
                settings=PsycopgMigrationSettings(
                    conninfo=self.postgres.conninfo(
                        database=self.database,
                        user="iam_migration_runner",
                    ),
                    application_name="desire-iam38-owned-session-test",
                ),
                dbapi=psycopg,
            ),
            runner_version="iam38-owned-session-test/1",
        ).run(catalog=self.catalog, contract_sources=self.contract_sources)

    def tearDown(self) -> None:
        self.postgres.drop_database(self.database)

    def _seed_session(
        self,
        *,
        user_id: UUID,
        session_id: UUID,
        family_id: UUID,
        handle: str,
        expired: bool = False,
    ) -> None:
        now = datetime.now(timezone.utc)
        created_at = now - (timedelta(hours=3) if expired else timedelta(minutes=5))
        last_activity_at = now - (
            timedelta(hours=2) if expired else timedelta(minutes=1)
        )
        idle_expires_at = now - timedelta(hours=1) if expired else now + timedelta(hours=1)
        absolute_expires_at = now + timedelta(hours=2)
        with psycopg.connect(
            self.postgres.admin_conninfo(database=self.database),
            autocommit=True,
        ) as connection:
            connection.execute(
                "INSERT INTO iam.users(id,status,display_handle,aggregate_version,"
                "created_at,updated_at) VALUES (%s,'ACTIVE',%s,1,%s,%s) "
                "ON CONFLICT (id) DO NOTHING",
                (user_id, handle, created_at, created_at),
            )
            connection.execute(
                "INSERT INTO iam.session_families(id,user_id,status,"
                "current_generation,revoked_at,revocation_reason_code,"
                "aggregate_version,created_at,updated_at) VALUES "
                "(%s,%s,'ACTIVE',1,NULL,NULL,1,%s,%s)",
                (family_id, user_id, created_at, created_at),
            )
            connection.execute(
                "INSERT INTO iam.sessions("
                "id,user_id,family_id,generation,predecessor_session_id,"
                "handle_digest,handle_digest_key_id,csrf_salt,csrf_key_id,"
                "csrf_digest,verified_contact_point_id,verified_at,"
                "verified_for_invitation_id,auth_transaction_id,auth_time,"
                "acr_code,amr_codes,created_at,last_activity_at,idle_expires_at,"
                "absolute_expires_at,updated_at,device_label,status,"
                "rotation_reason,revoked_at,revocation_reason_code,"
                "aggregate_version) VALUES ("
                "%s,%s,%s,1,NULL,%s,'session-handle-v1',%s,'session-csrf-v1',"
                "%s,NULL,NULL,NULL,NULL,%s,'urn:desire:acr:mfa',ARRAY['otp'],"
                "%s,%s,%s,%s,%s,'Browser','ACTIVE','LOGIN',NULL,NULL,1)",
                (
                    session_id,
                    user_id,
                    family_id,
                    hashlib.sha256(b"handle:" + session_id.bytes).digest(),
                    hashlib.sha256(b"salt:" + session_id.bytes).digest(),
                    hashlib.sha256(b"csrf:" + session_id.bytes).digest(),
                    created_at - timedelta(minutes=1),
                    created_at,
                    last_activity_at,
                    idle_expires_at,
                    absolute_expires_at,
                    created_at,
                ),
            )

    def _request(
        self,
        *,
        actor_user_id: UUID,
        current_session_id: UUID,
        target_session_id: UUID,
        idempotency_digest: bytes,
        payload_hash: bytes,
    ) -> OwnedSessionRevocationPostgresDatabaseRequest:
        command_id = uuid4()
        return OwnedSessionRevocationPostgresDatabaseRequest(
            scope=OwnedSessionRevocationPostgresExecutionScope(
                actor_user_id=actor_user_id,
                current_session_id=current_session_id,
                target_session_id=target_session_id,
                command_id=command_id,
                correlation_id=uuid4(),
                causation_id=command_id,
                trace_id=uuid4(),
                original_actor_id=None,
            ),
            receipt=CurrentSessionLogoutPostgresReceiptMaterial(
                receipt_id=command_id,
                idempotency_key_digest=idempotency_digest,
                idempotency_key_digest_key_id=IDEMPOTENCY_KEY_ID,
                payload_hash=payload_hash,
                payload_hash_key_id=PAYLOAD_KEY_ID,
                canonicalization_version=CANONICALIZATION,
                retain_until=datetime.now(timezone.utc) + timedelta(days=30),
            ),
            generated_ids=CurrentSessionLogoutPostgresGeneratedIds(
                audit_event_id=uuid4(),
                outbox_event_id=uuid4(),
            ),
        )

    def _revoke(self, **values):
        return PsycopgOwnedSessionRevocationUnitOfWorkFactory(
            connections=_Connections(
                self.postgres.conninfo(database=self.database, user="iam_app")
            )
        ).execute(self._request(**values))

    def _write_counts(self, *, actor_user_id: UUID, target_session_id: UUID):
        with psycopg.connect(
            self.postgres.admin_conninfo(database=self.database)
        ) as connection:
            return connection.execute(
                "SELECT "
                "(SELECT count(*) FROM infra.command_receipts "
                " WHERE command_name='RevokeSession' AND principal_id=%s "
                " AND target_id=%s),"
                "(SELECT count(*) FROM audit.audit_events "
                " WHERE action_code='RevokeSession' AND actor_id=%s "
                " AND target_id=%s),"
                "(SELECT count(*) FROM infra.outbox_events "
                " WHERE event_type='SessionRevoked' AND actor_id=%s "
                " AND aggregate_id=%s)",
                (
                    actor_user_id,
                    target_session_id,
                    actor_user_id,
                    target_session_id,
                    actor_user_id,
                    target_session_id,
                ),
            ).fetchone()

    def _legacy_logout(
        self,
        *,
        actor_user_id: UUID,
        session_id: UUID,
        idempotency_digest: bytes,
        payload_hash: bytes,
    ):
        command_id = uuid4()
        with psycopg.connect(
            self.postgres.conninfo(database=self.database, user="iam_app")
        ) as connection:
            for name, value in (
                ("app.scope_kind", "SELF"),
                ("app.operation", "REVOKE_CURRENT_SESSION"),
                ("app.actor_user_id", str(actor_user_id)),
                ("app.session_id", str(session_id)),
                ("app.target_session_id", str(session_id)),
                ("app.command_id", str(command_id)),
            ):
                connection.execute("SELECT set_config(%s,%s,true)", (name, value))
            return connection.execute(
                "SELECT iam_api.revoke_current_session_v1("
                "%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                (
                    actor_user_id,
                    session_id,
                    command_id,
                    uuid4(),
                    command_id,
                    uuid4(),
                    idempotency_digest,
                    IDEMPOTENCY_KEY_ID,
                    payload_hash,
                    PAYLOAD_KEY_ID,
                    CANONICALIZATION,
                    datetime.now(timezone.utc) + timedelta(days=30),
                    uuid4(),
                    uuid4(),
                ),
            ).fetchone()[0]

    def test_other_owned_replay_terminal_expiry_and_foreign_zero_write(self) -> None:
        actor_id = uuid4()
        current_id, current_family = uuid4(), uuid4()
        target_id, target_family = uuid4(), uuid4()
        expiring_id, expiring_family = uuid4(), uuid4()
        foreign_actor = uuid4()
        foreign_id, foreign_family = uuid4(), uuid4()
        self._seed_session(
            user_id=actor_id,
            session_id=current_id,
            family_id=current_family,
            handle="actor-current",
        )
        self._seed_session(
            user_id=actor_id,
            session_id=target_id,
            family_id=target_family,
            handle="actor-target",
        )
        self._seed_session(
            user_id=actor_id,
            session_id=expiring_id,
            family_id=expiring_family,
            handle="actor-expired",
            expired=True,
        )
        self._seed_session(
            user_id=foreign_actor,
            session_id=foreign_id,
            family_id=foreign_family,
            handle="foreign-target",
        )
        payload_hash = hashlib.sha256(b"closed-revoke-session-payload").digest()

        with self.assertRaises(IamError) as foreign:
            self._revoke(
                actor_user_id=actor_id,
                current_session_id=current_id,
                target_session_id=foreign_id,
                idempotency_digest=hashlib.sha256(b"foreign-key").digest(),
                payload_hash=payload_hash,
            )
        self.assertEqual(foreign.exception.code, "RESOURCE_NOT_FOUND")
        self.assertEqual(
            self._write_counts(
                actor_user_id=actor_id,
                target_session_id=foreign_id,
            ),
            (0, 0, 0),
        )

        idempotency_digest = hashlib.sha256(b"other-session-key").digest()
        fresh = self._revoke(
            actor_user_id=actor_id,
            current_session_id=current_id,
            target_session_id=target_id,
            idempotency_digest=idempotency_digest,
            payload_hash=payload_hash,
        )
        self.assertFalse(fresh.replayed)
        self.assertFalse(fresh.clear_current_session_cookie)
        with psycopg.connect(
            self.postgres.admin_conninfo(database=self.database)
        ) as connection:
            facts = connection.execute(
                "SELECT "
                "(SELECT status FROM iam.sessions WHERE id=%s),"
                "(SELECT status FROM iam.sessions WHERE id=%s),"
                "(SELECT status FROM iam.session_families WHERE id=%s),"
                "(SELECT status FROM iam.session_families WHERE id=%s)",
                (current_id, target_id, current_family, target_family),
            ).fetchone()
        self.assertEqual(facts, ("ACTIVE", "REVOKED", "ACTIVE", "ACTIVE"))
        self.assertEqual(
            self._write_counts(actor_user_id=actor_id, target_session_id=target_id),
            (1, 1, 1),
        )

        replayed = self._revoke(
            actor_user_id=actor_id,
            current_session_id=current_id,
            target_session_id=target_id,
            idempotency_digest=idempotency_digest,
            payload_hash=payload_hash,
        )
        self.assertTrue(replayed.replayed)
        self.assertFalse(replayed.clear_current_session_cookie)
        self.assertEqual(
            self._write_counts(actor_user_id=actor_id, target_session_id=target_id),
            (1, 1, 1),
        )

        terminal = self._revoke(
            actor_user_id=actor_id,
            current_session_id=current_id,
            target_session_id=target_id,
            idempotency_digest=hashlib.sha256(b"terminal-new-key").digest(),
            payload_hash=payload_hash,
        )
        self.assertFalse(terminal.replayed)
        self.assertEqual(
            self._write_counts(actor_user_id=actor_id, target_session_id=target_id),
            (2, 2, 1),
        )

        expired = self._revoke(
            actor_user_id=actor_id,
            current_session_id=current_id,
            target_session_id=expiring_id,
            idempotency_digest=hashlib.sha256(b"expired-target-key").digest(),
            payload_hash=payload_hash,
        )
        self.assertEqual(expired.session_status, "EXPIRED")
        self.assertFalse(expired.clear_current_session_cookie)
        self.assertEqual(
            self._write_counts(actor_user_id=actor_id, target_session_id=expiring_id),
            (1, 1, 0),
        )

    def test_current_cookie_and_iam36_completed_receipt_upgrade_recovery(self) -> None:
        payload_hash = hashlib.sha256(b"upgrade-stable-payload").digest()
        current_actor = uuid4()
        current_id, current_family = uuid4(), uuid4()
        self._seed_session(
            user_id=current_actor,
            session_id=current_id,
            family_id=current_family,
            handle="current-cookie",
        )
        current = self._revoke(
            actor_user_id=current_actor,
            current_session_id=current_id,
            target_session_id=current_id,
            idempotency_digest=hashlib.sha256(b"current-target-key").digest(),
            payload_hash=payload_hash,
        )
        self.assertTrue(current.clear_current_session_cookie)
        self.assertEqual(current.current_session_id, current_id)
        self.assertEqual(current.session_id, current_id)
        with psycopg.connect(
            self.postgres.admin_conninfo(database=self.database)
        ) as connection:
            current_facts = connection.execute(
                "SELECT "
                "(SELECT status FROM iam.sessions WHERE id=%s),"
                "(SELECT status FROM iam.session_families WHERE id=%s),"
                "(SELECT count(*) FROM iam.sessions "
                " WHERE family_id=%s AND status='ACTIVE')",
                (current_id, current_family, current_family),
            ).fetchone()
        self.assertEqual(current_facts, ("REVOKED", "ACTIVE", 0))

        upgrade_actor = uuid4()
        legacy_id, legacy_family = uuid4(), uuid4()
        fallback_id, fallback_family = uuid4(), uuid4()
        alternate_id, alternate_family = uuid4(), uuid4()
        self._seed_session(
            user_id=upgrade_actor,
            session_id=legacy_id,
            family_id=legacy_family,
            handle="legacy-current",
        )
        self._seed_session(
            user_id=upgrade_actor,
            session_id=fallback_id,
            family_id=fallback_family,
            handle="upgrade-fallback",
        )
        self._seed_session(
            user_id=upgrade_actor,
            session_id=alternate_id,
            family_id=alternate_family,
            handle="upgrade-alternate",
        )
        legacy_digest = hashlib.sha256(b"iam36-commit-unknown-key").digest()
        legacy = self._legacy_logout(
            actor_user_id=upgrade_actor,
            session_id=legacy_id,
            idempotency_digest=legacy_digest,
            payload_hash=payload_hash,
        )
        self.assertEqual(legacy["outcome"], "REVOKED")
        self.assertTrue(legacy["clear_current_session_cookie"])

        recovered = self._revoke(
            actor_user_id=upgrade_actor,
            current_session_id=legacy_id,
            target_session_id=legacy_id,
            idempotency_digest=legacy_digest,
            payload_hash=payload_hash,
        )
        self.assertTrue(recovered.replayed)
        self.assertTrue(recovered.clear_current_session_cookie)
        with psycopg.connect(
            self.postgres.admin_conninfo(database=self.database)
        ) as connection:
            writes = connection.execute(
                "SELECT "
                "(SELECT count(*) FROM infra.command_receipts "
                " WHERE principal_id=%s AND command_name='RevokeCurrentSession'),"
                "(SELECT count(*) FROM infra.command_receipts "
                " WHERE principal_id=%s AND command_name='RevokeSession'),"
                "(SELECT count(*) FROM audit.audit_events "
                " WHERE actor_id=%s AND target_id=%s),"
                "(SELECT count(*) FROM infra.outbox_events "
                " WHERE actor_id=%s AND aggregate_id=%s)",
                (
                    upgrade_actor,
                    upgrade_actor,
                    upgrade_actor,
                    legacy_id,
                    upgrade_actor,
                    legacy_id,
                ),
            ).fetchone()
        self.assertEqual(writes, (1, 0, 1, 1))

        with self.assertRaises(IamError) as changed_payload:
            self._revoke(
                actor_user_id=upgrade_actor,
                current_session_id=legacy_id,
                target_session_id=legacy_id,
                idempotency_digest=legacy_digest,
                payload_hash=hashlib.sha256(b"changed-payload").digest(),
            )
        self.assertEqual(changed_payload.exception.code, "IDEMPOTENCY_KEY_REUSED")

        with self.assertRaises(IamError) as changed_target:
            self._revoke(
                actor_user_id=upgrade_actor,
                current_session_id=fallback_id,
                target_session_id=alternate_id,
                idempotency_digest=legacy_digest,
                payload_hash=payload_hash,
            )
        self.assertEqual(changed_target.exception.code, "IDEMPOTENCY_KEY_REUSED")
        self.assertEqual(
            self._write_counts(
                actor_user_id=upgrade_actor,
                target_session_id=alternate_id,
            ),
            (0, 0, 0),
        )

    def test_fixed_program_acl_security_and_rls_are_closed(self) -> None:
        rls_actor = uuid4()
        rls_session, rls_family = uuid4(), uuid4()
        self._seed_session(
            user_id=rls_actor,
            session_id=rls_session,
            family_id=rls_family,
            handle="rls-hidden-session",
        )
        with psycopg.connect(
            self.postgres.admin_conninfo(database=self.database)
        ) as connection:
            function_facts = connection.execute(
                "SELECT p.prosecdef,p.provolatile,p.proparallel,"
                "pg_get_userbyid(p.proowner),"
                "has_function_privilege('iam_app',%s,'EXECUTE'),"
                "has_function_privilege('iam_session_authenticator',%s,'EXECUTE'),"
                "has_function_privilege('public',%s,'EXECUTE') "
                "FROM pg_proc AS p WHERE p.oid=to_regprocedure(%s)",
                (OWNED_SESSION_REVOCATION_FUNCTION_SIGNATURE,) * 4,
            ).fetchone()
            session_rls = connection.execute(
                "SELECT c.relrowsecurity,c.relforcerowsecurity "
                "FROM pg_class AS c JOIN pg_namespace AS n ON n.oid=c.relnamespace "
                "WHERE n.nspname='iam' AND c.relname='sessions'"
            ).fetchone()
            policy_names = {
                row[0]
                for row in connection.execute(
                    "SELECT polname FROM pg_policy WHERE polname LIKE "
                    "'rls_owned_session_revocation_%'"
                ).fetchall()
            }
        self.assertEqual(
            function_facts,
            (True, "v", "u", "schema_owner", True, False, False),
        )
        self.assertEqual(session_rls, (True, True))
        self.assertTrue(
            {
                "rls_owned_session_revocation_session_select_v1",
                "rls_owned_session_revocation_session_update_v1",
                "rls_owned_session_revocation_audit_v1",
                "rls_owned_session_revocation_outbox_v1",
            }.issubset(policy_names)
        )
        with psycopg.connect(
            self.postgres.conninfo(database=self.database, user="iam_app")
        ) as connection:
            self.assertEqual(
                connection.execute("SELECT count(*) FROM iam.sessions").fetchone(),
                (0,),
            )


if __name__ == "__main__":
    unittest.main()
