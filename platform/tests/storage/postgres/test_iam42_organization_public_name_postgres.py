"""PostgreSQL 18 evidence for the IAM42 database boundary."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
import unittest
from uuid import UUID, uuid4
import threading

import psycopg

from desire_platform.deployment.identity_bootstrap import (
    IdentityBootstrapOutcome,
    apply_internal_sandbox_identity_bootstrap,
    parse_internal_sandbox_identity_manifest,
    verify_internal_sandbox_identity_bootstrap,
)
from desire_platform.deployment.migrations import DeploymentMigrationSettings
from desire_platform.identity_access.adapters.postgres.migrations import (
    IamContractSources,
    IamMigrationRunner,
    MigrationCatalog,
    PsycopgMigrationDriver,
    PsycopgMigrationSettings,
)
from tests.storage.postgres.postgres18_harness import TemporaryPostgres18
from tests.support.identity_bootstrap_builders import (
    canonical_manifest,
    identity_bootstrap_document,
)


PLATFORM_ROOT = Path(__file__).resolve().parents[3]
MIGRATION_ROOT = (
    PLATFORM_ROOT
    / "src/desire_platform/identity_access/adapters/postgres/migrations"
)
IAM42 = MIGRATION_ROOT / "0042_expand__organization_public_name_management.sql"
_IDEMPOTENCY_KEY_ID = "iam-receipt-idempotency-hmac-2026-01"
_PAYLOAD_KEY_ID = "iam-receipt-payload-hmac-2026-01"
_SYSTEM_ACTOR_ID = UUID("11111111-1111-4111-8111-111111111111")
_MIGRATION_ROLES = (
    "iam_migration_runner",
    "profile_migration_runner",
    "demand_migration_runner",
    "trust_migration_runner",
    "taxonomy_migration_runner",
)
_V3_TYPES = (
    "text", "uuid", "uuid", "uuid", "uuid", "uuid", "uuid", "uuid",
    "uuid", "uuid", "bigint", "bytea", "text", "bytea", "text",
    "timestamptz", "uuid", "uuid", "uuid", "uuid", "bytea", "text",
    "text", "timestamptz", "bytea", "text", "text", "text", "text",
    "text", "uuid", "bigint", "uuid", "text", "timestamptz",
    "timestamptz", "bytea", "text[]", "bytea[]", "text[]", "bytea[]",
    "text", "text", "uuid", "bigint", "uuid", "text", "timestamptz",
    "timestamptz", "bytea", "text",
)
_V3_SQL = (
    "SELECT iam_api.execute_organization_admin_v3("
    + ",".join(f"%s::{item}" for item in _V3_TYPES)
    + ")"
)


def _digest(label: str) -> bytes:
    return hashlib.sha256(label.encode("ascii")).digest()


@dataclass(frozen=True)
class _AuthoritySeed:
    now: datetime
    organization_id: UUID
    actor_user_id: UUID
    actor_session_id: UUID
    target_membership_id: UUID


class Iam42OrganizationPublicNamePostgresTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.postgres = TemporaryPostgres18(
            enable_tcp_password_auth=True
        ).start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.postgres.stop()

    def setUp(self) -> None:
        self.database = self.postgres.create_database()
        IamMigrationRunner(
            driver=PsycopgMigrationDriver(
                settings=PsycopgMigrationSettings(
                    conninfo=self.postgres.conninfo(
                        database=self.database,
                        user="iam_migration_runner",
                    ),
                    application_name="iam42-public-name-pg18",
                ),
                dbapi=psycopg,
            ),
            runner_version="iam42-public-name-pg18/1",
        ).run(
            catalog=MigrationCatalog.load(MIGRATION_ROOT),
            contract_sources=IamContractSources(
                api_contract_bytes=(
                    PLATFORM_ROOT / "contracts/api/iam-v1.openapi.yaml"
                ).read_bytes(),
                event_contract_bytes=(
                    PLATFORM_ROOT / "contracts/events/iam-v1.schema.json"
                ).read_bytes(),
            ),
        )
        with self._admin() as connection:
            installed = connection.execute(
                "SELECT to_regprocedure("
                "'iam_api.execute_organization_admin_v3(text,uuid,uuid,uuid,"
                "uuid,uuid,uuid,uuid,uuid,uuid,bigint,bytea,text,bytea,text,"
                "timestamptz,uuid,uuid,uuid,uuid,bytea,text,text,timestamptz,"
                "bytea,text,text,text,text,text,uuid,bigint,uuid,text,"
                "timestamptz,timestamptz,bytea,text[],bytea[],text[],bytea[],"
                "text,text,uuid,bigint,uuid,text,timestamptz,timestamptz,"
                "bytea,text)')"
            ).fetchone()
            if installed == (None,):
                connection.execute(IAM42.read_text(encoding="utf-8"))

    def tearDown(self) -> None:
        self.postgres.drop_database(self.database)

    def _admin(self):
        return psycopg.connect(
            self.postgres.admin_conninfo(database=self.database),
            autocommit=True,
        )

    def _clear_migration_role_passwords(self) -> None:
        with self._admin() as connection:
            for role in _MIGRATION_ROLES:
                connection.execute("ALTER ROLE " + role + " PASSWORD NULL")

    def _restore_migration_role_passwords(self) -> None:
        runtime_password = self.postgres._runtime_password
        with psycopg.connect(
            self.postgres.admin_conninfo(database="postgres"),
            autocommit=True,
        ) as connection:
            for role in _MIGRATION_ROLES:
                connection.pgconn.change_password(
                    role.encode("ascii"), runtime_password.encode("utf-8")
                )

    def _seed_active_org_admin(self) -> _AuthoritySeed:
        now = datetime.now(timezone.utc).replace(microsecond=0)
        created = now - timedelta(days=2)
        session_created = now - timedelta(minutes=2)
        organization_id = uuid4()
        actor_user_id = uuid4()
        family_id = uuid4()
        session_id = uuid4()
        membership_id = uuid4()
        invitation_id = uuid4()
        target_user_id = uuid4()
        target_membership_id = uuid4()
        target_invitation_id = uuid4()
        with self._admin() as connection:
            connection.execute("BEGIN")
            connection.execute("SET LOCAL session_replication_role = 'replica'")
            connection.execute(
                "INSERT INTO iam.organizations("
                "id,organization_type,public_name,jurisdiction,status,"
                "client_reference_namespace,client_reference,aggregate_version,"
                "created_at,updated_at) VALUES("
                "%s,'BUSINESS','Original Public Name','CN','ACTIVE',"
                "'iam42-pg18',%s,1,%s,%s)",
                (organization_id, str(organization_id), created, created),
            )
            connection.execute(
                "INSERT INTO iam.users("
                "id,status,display_handle,aggregate_version,created_at,updated_at) "
                "VALUES(%s,'ACTIVE',%s,1,%s,%s)",
                (actor_user_id, "iam42_admin_" + actor_user_id.hex[:12], created, now),
            )
            connection.execute(
                "INSERT INTO iam.users("
                "id,status,display_handle,aggregate_version,created_at,updated_at) "
                "VALUES(%s,'ACTIVE',%s,1,%s,%s)",
                (target_user_id, "iam42_target_" + target_user_id.hex[:12], created, now),
            )
            connection.execute(
                "INSERT INTO iam.memberships("
                "id,organization_id,user_id,status,source_invitation_id,"
                "aggregate_version,created_at,updated_at) "
                "VALUES(%s,%s,%s,'ACTIVE',%s,1,%s,%s)",
                (
                    membership_id,
                    organization_id,
                    actor_user_id,
                    invitation_id,
                    created,
                    now,
                ),
            )
            connection.execute(
                "INSERT INTO iam.membership_role_grants("
                "id,organization_id,membership_id,user_id,role_code,"
                "source_invitation_id,policy_selector_digest,granted_by_kind,"
                "granted_by_id,granted_at,revoked_at,revocation_reason_code,"
                "aggregate_version) VALUES("
                "%s,%s,%s,%s,'ORG_ADMIN',%s,%s,'SYSTEM',%s,%s,NULL,NULL,1)",
                (
                    uuid4(),
                    organization_id,
                    membership_id,
                    actor_user_id,
                    invitation_id,
                    _digest("iam42-selector"),
                    uuid4(),
                    created,
                ),
            )
            connection.execute(
                "INSERT INTO iam.memberships("
                "id,organization_id,user_id,status,source_invitation_id,"
                "aggregate_version,created_at,updated_at) "
                "VALUES(%s,%s,%s,'ACTIVE',%s,1,%s,%s)",
                (
                    target_membership_id,
                    organization_id,
                    target_user_id,
                    target_invitation_id,
                    created,
                    now,
                ),
            )
            connection.execute(
                "INSERT INTO iam.membership_role_grants("
                "id,organization_id,membership_id,user_id,role_code,"
                "source_invitation_id,policy_selector_digest,granted_by_kind,"
                "granted_by_id,granted_at,revoked_at,revocation_reason_code,"
                "aggregate_version) VALUES("
                "%s,%s,%s,%s,'DEMAND_OWNER',%s,%s,'SYSTEM',%s,%s,NULL,NULL,1)",
                (
                    uuid4(),
                    organization_id,
                    target_membership_id,
                    target_user_id,
                    target_invitation_id,
                    _digest("iam42-target-selector"),
                    uuid4(),
                    created,
                ),
            )
            connection.execute(
                "INSERT INTO iam.session_families("
                "id,user_id,status,current_generation,revoked_at,"
                "revocation_reason_code,aggregate_version,created_at,updated_at) "
                "VALUES(%s,%s,'ACTIVE',1,NULL,NULL,1,%s,%s)",
                (family_id, actor_user_id, created, now),
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
                "aggregate_version) VALUES("
                "%s,%s,%s,1,NULL,%s,'iam42-session-handle-v1',%s,"
                "'iam42-session-csrf-v1',%s,NULL,NULL,NULL,NULL,%s,"
                "'urn:desire:acr:mfa',ARRAY['otp']::text[],%s,%s,%s,%s,%s,"
                "'Browser','ACTIVE','LOGIN',NULL,NULL,1)",
                (
                    session_id,
                    actor_user_id,
                    family_id,
                    _digest("iam42-session-handle"),
                    _digest("iam42-csrf-salt"),
                    _digest("iam42-csrf"),
                    session_created - timedelta(seconds=1),
                    session_created,
                    now - timedelta(seconds=10),
                    now + timedelta(minutes=30),
                    now + timedelta(hours=8),
                    now,
                ),
            )
            connection.execute("COMMIT")
        return _AuthoritySeed(
            now,
            organization_id,
            actor_user_id,
            session_id,
            target_membership_id,
        )

    def _call_v3(
        self,
        seed: _AuthoritySeed,
        *,
        operation: str = "UpdateOrganizationPublicName",
        target_id: UUID | None = None,
        command_id: UUID | None = None,
        expected_version: int = 1,
        identity_digest: bytes | None = None,
        payload_digest: bytes | None = None,
        public_name: str | None = "Corrected Public Name",
        reason_code: str = "PUBLIC_NAME_CORRECTION",
    ):
        command_id = command_id or uuid4()
        target_id = target_id or seed.organization_id
        identity_digest = identity_digest or _digest("iam42-id-" + command_id.hex)
        payload_digest = payload_digest or _digest("iam42-payload-" + command_id.hex)
        audit_id = uuid4()
        outbox_id = uuid4()
        parameters = (
            operation,
            seed.actor_user_id,
            seed.actor_session_id,
            seed.organization_id,
            target_id,
            command_id,
            uuid4(),
            command_id,
            uuid4(),
            None,
            expected_version,
            identity_digest,
            _IDEMPOTENCY_KEY_ID,
            payload_digest,
            _PAYLOAD_KEY_ID,
            seed.now + timedelta(days=31),
            audit_id,
            outbox_id,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            reason_code,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            [_IDEMPOTENCY_KEY_ID],
            [identity_digest],
            [_PAYLOAD_KEY_ID],
            [payload_digest],
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            public_name,
        )
        self.assertEqual(len(parameters), 51)
        with psycopg.connect(
            self.postgres.conninfo(database=self.database, user="iam_app")
        ) as connection:
            for name, value in (
                ("app.scope_kind", "ORGANIZATION_ADMIN"),
                ("app.operation", operation),
                ("app.actor_user_id", str(seed.actor_user_id)),
                ("app.session_id", str(seed.actor_session_id)),
                ("app.organization_id", str(seed.organization_id)),
                ("app.target_id", str(target_id)),
                ("app.command_id", str(command_id)),
                ("app.expected_version", str(expected_version)),
            ):
                connection.execute(
                    "SELECT set_config(%s,%s,true)", (name, value)
                )
            result = connection.execute(_V3_SQL, parameters).fetchone()[0]
        return result

    def test_db_canonicalizer_matches_closed_application_examples(self) -> None:
        with self._admin() as connection:
            rows = connection.execute(
                "SELECT iam.organization_public_name_is_canonical_v1(value) "
                "FROM unnest(%s::text[]) AS candidate(value)",
                ([
                    "Canonical Organization",
                    "Caf\u00e9",
                    "\u4f8b\u793e",
                    " leading",
                    "trailing ",
                    "e\u0301",
                    "zero\u200bwidth",
                    "arabic\u0890format",
                    "egyptian\U0001343fformat",
                    "line\nbreak",
                    "",
                ],),
            ).fetchall()
        self.assertEqual(
            rows,
            [
                (True,),
                (True,),
                (True,),
                (False,),
                (False,),
                (False,),
                (False,),
                (False,),
                (False,),
                (False,),
                (False,),
            ],
        )

    def test_only_v3_and_bootstrap_v6_are_runtime_callable(self) -> None:
        organization_v2 = (
            "iam_api.execute_organization_admin_v2("
            "text,uuid,uuid,uuid,uuid,uuid,uuid,uuid,uuid,uuid,bigint,bytea,"
            "text,bytea,text,timestamptz,uuid,uuid,uuid,uuid,bytea,text,text,"
            "timestamptz,bytea,text,text,text,text,text,uuid,bigint,uuid,text,"
            "timestamptz,timestamptz,bytea,text[],bytea[],text[],bytea[],text,"
            "text,uuid,bigint,uuid,text,timestamptz,timestamptz,bytea)"
        )
        organization_v3 = organization_v2.replace(
            "execute_organization_admin_v2", "execute_organization_admin_v3"
        )[:-1] + ",text)"
        bootstrap_v5 = (
            "iam_api.manage_internal_sandbox_identity_bootstrap_v5("
            "text,bytea,bytea,uuid,uuid,uuid,uuid,uuid,uuid,uuid)"
        )
        bootstrap_v6 = bootstrap_v5.replace(
            "identity_bootstrap_v5", "identity_bootstrap_v6"
        )
        with self._admin() as connection:
            privileges = connection.execute(
                "SELECT has_function_privilege('iam_app',%s,'EXECUTE'),"
                "has_function_privilege('iam_app',%s,'EXECUTE'),"
                "has_function_privilege('iam_sandbox_bootstrap',%s,'EXECUTE'),"
                "has_function_privilege('iam_sandbox_bootstrap',%s,'EXECUTE')",
                (organization_v2, organization_v3, bootstrap_v5, bootstrap_v6),
            ).fetchone()
            index = connection.execute(
                "SELECT indexdef FROM pg_indexes WHERE schemaname='infra' "
                "AND indexname='uq_org_admin_raw_idempotency_key_v1'"
            ).fetchone()
        self.assertEqual(privileges, (False, True, False, True))
        self.assertIsNotNone(index)
        self.assertIn("UpdateOrganizationPublicName", index[0])

    def test_authority_update_replay_occ_and_cross_operation_receipt(self) -> None:
        seed = self._seed_active_org_admin()
        command_id = uuid4()
        identity_digest = _digest("iam42-shared-raw-key")
        payload_digest = _digest("iam42-update-payload")

        first = self._call_v3(
            seed,
            command_id=command_id,
            identity_digest=identity_digest,
            payload_digest=payload_digest,
        )
        self.assertEqual(first["decision_code"], "AUTHORIZED")
        self.assertFalse(first["replayed"])
        self.assertEqual(first["safe_response"]["aggregate_version"], 2)
        self.assertEqual(first["safe_response"]["public_name"], "Corrected Public Name")
        self.assertEqual(
            first["outbox_event"]["payload"],
            {"organization_id": str(seed.organization_id)},
        )

        replay = self._call_v3(
            seed,
            command_id=command_id,
            identity_digest=identity_digest,
            payload_digest=payload_digest,
        )
        self.assertEqual(replay["decision_code"], "AUTHORIZED")
        self.assertTrue(replay["replayed"])
        self.assertEqual(replay["safe_response"], first["safe_response"])

        same_name = self._call_v3(
            seed,
            expected_version=2,
            public_name="Corrected Public Name",
        )
        self.assertEqual(
            same_name,
            {"decision_code": "INVALID_STATE_TRANSITION"},
        )
        stale = self._call_v3(
            seed,
            expected_version=1,
            public_name="Another Public Name",
        )
        self.assertEqual(
            stale,
            {
                "decision_code": "PRECONDITION_FAILED",
                "current_entity_tag": '"v2"',
            },
        )
        cross_operation = self._call_v3(
            seed,
            operation="SuspendMembership",
            target_id=seed.organization_id,
            expected_version=1,
            identity_digest=identity_digest,
            payload_digest=_digest("iam42-cross-operation-payload"),
            public_name=None,
            reason_code="ACCESS_REVIEW",
        )
        self.assertEqual(
            cross_operation,
            {"decision_code": "IDEMPOTENCY_KEY_REUSED"},
        )

        with self._admin() as connection:
            organization = connection.execute(
                "SELECT public_name,aggregate_version FROM iam.organizations "
                "WHERE id=%s",
                (seed.organization_id,),
            ).fetchone()
            receipt = connection.execute(
                "SELECT safe_response_body,reconstruction_metadata,"
                "payload_hash::text,idempotency_key_digest::text "
                "FROM infra.command_receipts WHERE id=%s",
                (command_id,),
            ).fetchone()
            audit_text = connection.execute(
                "SELECT row_to_json(event)::text FROM audit.audit_events AS event "
                "WHERE command_id=%s",
                (command_id,),
            ).fetchone()[0]
            outbox = connection.execute(
                "SELECT payload,row_to_json(event)::text "
                "FROM infra.outbox_events AS event WHERE causation_id=%s",
                (command_id,),
            ).fetchone()
            counts = connection.execute(
                "SELECT "
                "(SELECT count(*) FROM infra.command_receipts WHERE id=%s),"
                "(SELECT count(*) FROM audit.audit_events WHERE command_id=%s),"
                "(SELECT count(*) FROM infra.outbox_events WHERE causation_id=%s)",
                (command_id, command_id, command_id),
            ).fetchone()
        self.assertEqual(organization, ("Corrected Public Name", 2))
        self.assertEqual(counts, (1, 1, 1))
        self.assertEqual(receipt[0]["public_name"], "Corrected Public Name")
        self.assertIsNone(receipt[1])
        self.assertNotIn("Original Public Name", str(receipt))
        self.assertNotIn("Original Public Name", audit_text)
        self.assertNotIn("Corrected Public Name", audit_text)
        self.assertEqual(outbox[0], {"organization_id": str(seed.organization_id)})
        self.assertNotIn("Original Public Name", outbox[1])
        self.assertNotIn("Corrected Public Name", outbox[1])

    def test_concurrent_six_command_raw_key_has_one_atomic_winner(self) -> None:
        seed = self._seed_active_org_admin()
        shared_digest = _digest("iam42-concurrent-shared-raw-key")
        barrier = threading.Barrier(2)

        def update_name():
            barrier.wait(timeout=10)
            return self._call_v3(
                seed,
                identity_digest=shared_digest,
                payload_digest=_digest("iam42-concurrent-update"),
            )

        def suspend_member():
            barrier.wait(timeout=10)
            return self._call_v3(
                seed,
                operation="SuspendMembership",
                target_id=seed.target_membership_id,
                identity_digest=shared_digest,
                payload_digest=_digest("iam42-concurrent-suspend"),
                public_name=None,
                reason_code="ACCESS_REVIEW",
            )

        with ThreadPoolExecutor(max_workers=2) as executor:
            results = tuple(
                future.result(timeout=20)
                for future in (
                    executor.submit(update_name),
                    executor.submit(suspend_member),
                )
            )
        self.assertEqual(
            sorted(result["decision_code"] for result in results),
            ["AUTHORIZED", "IDEMPOTENCY_KEY_REUSED"],
        )
        with self._admin() as connection:
            counts = connection.execute(
                "SELECT "
                "(SELECT count(*) FROM infra.command_receipts "
                " WHERE idempotency_key_digest=%s),"
                "(SELECT count(*) FROM audit.audit_events "
                " WHERE command_id IN (SELECT id FROM infra.command_receipts "
                " WHERE idempotency_key_digest=%s)),"
                "(SELECT count(*) FROM infra.outbox_events "
                " WHERE causation_id IN (SELECT id FROM infra.command_receipts "
                " WHERE idempotency_key_digest=%s))",
                (shared_digest, shared_digest, shared_digest),
            ).fetchone()
        self.assertEqual(counts, (1, 1, 1))

    def test_bootstrap_v6_replay_and_verify_never_overwrite_custom_names(self) -> None:
        self.addCleanup(self._restore_migration_role_passwords)
        self._clear_migration_role_passwords()
        document = identity_bootstrap_document()
        raw_manifest, manifest_digest = canonical_manifest(document)
        manifest = parse_internal_sandbox_identity_manifest(
            raw_manifest,
            expected_sha256=manifest_digest,
            expected_issuer="https://id.example.test",
        )
        settings = DeploymentMigrationSettings(
            host=self.postgres.host,
            port=self.postgres.port,
            database=self.database,
            admin_user=self.postgres.admin_user,
            admin_password=self.postgres.admin_password,
        )
        first = apply_internal_sandbox_identity_bootstrap(
            settings=settings,
            manifest=manifest,
            system_actor_id=_SYSTEM_ACTOR_ID,
            now=datetime(2026, 8, 12, 8, 0, tzinfo=timezone.utc),
            password_factory=lambda: (
                "iam42-bootstrap-apply-password-material-v1"
            ),
        )
        self.assertEqual(first.outcome, IdentityBootstrapOutcome.APPLIED)
        expected = {}
        with self._admin() as connection:
            organizations = connection.execute(
                "SELECT id,aggregate_version FROM iam.organizations ORDER BY id"
            ).fetchall()
            self.assertEqual(len(organizations), 2)
            for position, (organization_id, aggregate_version) in enumerate(
                organizations, start=1
            ):
                custom_name = f"Legally Corrected Organization {position}"
                connection.execute(
                    "UPDATE iam.organizations SET public_name=%s,"
                    "aggregate_version=aggregate_version+1,"
                    "updated_at=transaction_timestamp() WHERE id=%s",
                    (custom_name, organization_id),
                )
                expected[organization_id] = (custom_name, aggregate_version + 1)

        replay = apply_internal_sandbox_identity_bootstrap(
            settings=settings,
            manifest=manifest,
            system_actor_id=_SYSTEM_ACTOR_ID,
            now=datetime(2026, 8, 12, 8, 1, tzinfo=timezone.utc),
            password_factory=lambda: (
                "iam42-bootstrap-replay-password-material-v1"
            ),
        )
        self.assertEqual(replay.outcome, IdentityBootstrapOutcome.REPLAYED)
        verified = verify_internal_sandbox_identity_bootstrap(
            settings=settings,
            manifest=manifest,
            system_actor_id=_SYSTEM_ACTOR_ID,
            now=datetime(2026, 8, 12, 8, 2, tzinfo=timezone.utc),
            password_factory=lambda: (
                "iam42-bootstrap-verify-password-material-v1"
            ),
        )
        self.assertEqual(verified.outcome, IdentityBootstrapOutcome.VERIFIED)
        with self._admin() as connection:
            current = connection.execute(
                "SELECT id,public_name,aggregate_version "
                "FROM iam.organizations ORDER BY id"
            ).fetchall()
        self.assertEqual(
            current,
            [
                (organization_id, *expected[organization_id])
                for organization_id, _aggregate_version in organizations
            ],
        )


if __name__ == "__main__":
    unittest.main()
