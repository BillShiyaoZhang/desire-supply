"""PostgreSQL 18 evidence for the exact-resource IAM37 Finance lock."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
from pathlib import Path
import unittest
from uuid import UUID

import psycopg

from desire_platform.identity_access.adapters.postgres.editor_principal import (
    EditorPrincipalResolutionRequest,
    PsycopgEditorPrincipalResolver,
)
from desire_platform.identity_access.adapters.postgres.migrations import (
    IamContractSources,
    IamMigrationRunner,
    MigrationCatalog,
    PsycopgMigrationDriver,
    PsycopgMigrationSettings,
)
from tests.storage.postgres.postgres18_harness import TemporaryPostgres18
from tests.storage.postgres.test_finance_funding_postgres import (
    FINANCE_DUTY_GRANT_IDS,
    FINANCE_FAMILY_IDS,
    FINANCE_SESSION_IDS,
    FINANCE_USER_IDS,
    _Connections,
    _seed_finance_operator,
)
from tests.support.demand_postgres_builders import (
    DEMAND_ID,
    ORGANIZATION_ID,
    seed_exact_demand_owner_iam_authority,
)


PLATFORM_ROOT = Path(__file__).resolve().parents[3]
IAM_ROOT = (
    PLATFORM_ROOT
    / "src/desire_platform/identity_access/adapters/postgres/migrations"
)
FUNDING_REVIEW_ID = UUID("fa000001-0000-4000-8000-000000000001")
OTHER_FUNDING_REVIEW_ID = UUID("fa000001-0000-4000-8000-000000000002")
ASSIGNMENT_ID = UUID("fb000001-0000-4000-8000-000000000001")
OTHER_ASSIGNMENT_ID = UUID("fb000001-0000-4000-8000-000000000002")
CONFLICT_INVITATION_ID = UUID("fc000001-0000-4000-8000-000000000001")
CONFLICT_MEMBERSHIP_ID = UUID("fd000001-0000-4000-8000-000000000001")
ROTATED_SESSION_ID = UUID("fe000001-0000-4000-8000-000000000001")
V2_SIGNATURE = (
    "iam_api.lock_finance_funding_authority_v2("
    "uuid,uuid,uuid,uuid,uuid,uuid,text,bytea)"
)


class RealPostgres18Iam37FinanceFundingAuthorityTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.postgres = TemporaryPostgres18().start()
        cls.database = cls.postgres.create_database()
        try:
            cls._migrate()
            now = datetime.now(timezone.utc).replace(microsecond=0)
            with cls._admin(autocommit=False) as connection:
                seed_exact_demand_owner_iam_authority(connection, now=now)
                for ordinal in range(2):
                    _seed_finance_operator(connection, ordinal=ordinal, now=now)
                cls._create_demand_owner_adapter(connection)
            cls.principal_markers = tuple(
                cls._resolve_principal_marker(ordinal) for ordinal in range(2)
            )
        except BaseException:
            cls.postgres.drop_database(cls.database)
            cls.postgres.stop()
            raise

    @classmethod
    def tearDownClass(cls) -> None:
        cls.postgres.drop_database(cls.database)
        cls.postgres.stop()

    def test_v2_is_nested_only_and_binds_operation_review_and_assignment(self) -> None:
        with self._admin() as admin:
            allowed = admin.execute(
                "SELECT has_function_privilege(%s, %s, 'EXECUTE')",
                ("demand_finance", V2_SIGNATURE),
            ).fetchone()
            self.assertEqual(allowed, (False,))

        release = self._lock(
            operation="RELEASE_FUNDING_REVIEW_ASSIGNMENT",
            funding_review_id=FUNDING_REVIEW_ID,
            assignment_id=ASSIGNMENT_ID,
        )
        finding = self._lock(
            operation="SUBMIT_FUNDING_REVIEW_FINDING",
            funding_review_id=FUNDING_REVIEW_ID,
            assignment_id=ASSIGNMENT_ID,
        )
        other_review = self._lock(
            operation="SUBMIT_FUNDING_REVIEW_FINDING",
            funding_review_id=OTHER_FUNDING_REVIEW_ID,
            assignment_id=ASSIGNMENT_ID,
        )
        other_assignment = self._lock(
            operation="SUBMIT_FUNDING_REVIEW_FINDING",
            funding_review_id=FUNDING_REVIEW_ID,
            assignment_id=OTHER_ASSIGNMENT_ID,
        )

        for row in (release, finding, other_review, other_assignment):
            self.assertIsNotNone(row)
            self.assertEqual(row[0], FINANCE_DUTY_GRANT_IDS[0])
            self.assertEqual(row[1], 1)
            self.assertIsNone(row[2])
            self.assertEqual(len(row[3]), hashlib.sha256().digest_size)
        self.assertEqual(
            len({release[3], finding[3], other_review[3], other_assignment[3]}),
            4,
        )

        self.assertIsNone(
            self._lock(
                operation="CONFIRM_FUNDING_REVIEW",
                funding_review_id=FUNDING_REVIEW_ID,
                assignment_id=ASSIGNMENT_ID,
            )
        )
        self.assertIsNone(
            self._lock(
                operation="SUBMIT_FUNDING_REVIEW_FINDING",
                funding_review_id=FUNDING_REVIEW_ID,
                assignment_id=ASSIGNMENT_ID,
                context_funding_review_id=OTHER_FUNDING_REVIEW_ID,
            )
        )
        self.assertIsNone(
            self._lock(
                operation="SUBMIT_FUNDING_REVIEW_FINDING",
                funding_review_id=FUNDING_REVIEW_ID,
                assignment_id=ASSIGNMENT_ID,
                candidate_session_id=FINANCE_SESSION_IDS[1],
            )
        )

        with self._admin(autocommit=False) as admin:
            admin.execute(
                "UPDATE iam.platform_duty_grants SET "
                "revoked_at=transaction_timestamp(),"
                "revocation_reason_code='IAM37_TEST_NO_ACTIVE_DUTY',"
                "updated_at=transaction_timestamp() WHERE id=%s",
                (FINANCE_DUTY_GRANT_IDS[0],),
            )
        no_duty_marker = self._finance_principal_marker(0)
        self.assertIsNotNone(no_duty_marker)
        self.assertIsNone(
            self._lock(
                operation="SUBMIT_FUNDING_REVIEW_FINDING",
                funding_review_id=FUNDING_REVIEW_ID,
                assignment_id=ASSIGNMENT_ID,
                principal_marker=no_duty_marker,
            )
        )
        with self._admin(autocommit=False) as admin:
            admin.execute(
                "UPDATE iam.platform_duty_grants SET revoked_at=NULL,"
                "revocation_reason_code=NULL,updated_at=transaction_timestamp() "
                "WHERE id=%s",
                (FINANCE_DUTY_GRANT_IDS[0],),
            )

        with self._admin(autocommit=False) as admin:
            admin.execute(
                "UPDATE iam.platform_duty_grants SET "
                "expires_at=transaction_timestamp()-interval '1 second',"
                "updated_at=transaction_timestamp() WHERE id=%s",
                (FINANCE_DUTY_GRANT_IDS[0],),
            )
        expired_duty_marker = self._finance_principal_marker(0)
        self.assertIsNotNone(expired_duty_marker)
        self.assertIsNone(
            self._lock(
                operation="SUBMIT_FUNDING_REVIEW_FINDING",
                funding_review_id=FUNDING_REVIEW_ID,
                assignment_id=ASSIGNMENT_ID,
                principal_marker=expired_duty_marker,
            )
        )
        with self._admin(autocommit=False) as admin:
            admin.execute(
                "UPDATE iam.platform_duty_grants SET expires_at=NULL,"
                "updated_at=transaction_timestamp() WHERE id=%s",
                (FINANCE_DUTY_GRANT_IDS[0],),
            )

        self._seed_conflicting_membership()
        try:
            conflict_marker = self._finance_principal_marker(0)
            self.assertIsNotNone(conflict_marker)
            self.assertIsNone(
                self._lock(
                    operation="SUBMIT_FUNDING_REVIEW_FINDING",
                    funding_review_id=FUNDING_REVIEW_ID,
                    assignment_id=ASSIGNMENT_ID,
                    principal_marker=conflict_marker,
                )
            )
        finally:
            with self._admin(autocommit=False) as admin:
                admin.execute(
                    "DELETE FROM iam.memberships WHERE id=%s",
                    (CONFLICT_MEMBERSHIP_ID,),
                )
                admin.execute(
                    "DELETE FROM iam.access_invitations WHERE id=%s",
                    (CONFLICT_INVITATION_ID,),
                )

        with self._admin(autocommit=False) as admin:
            admin.execute(
                "UPDATE iam.sessions SET status='REVOKED',"
                "revoked_at=transaction_timestamp(),"
                "revocation_reason_code='IAM37_TEST_SESSION_REVOKED',"
                "aggregate_version=aggregate_version+1,"
                "updated_at=transaction_timestamp() WHERE id=%s",
                (FINANCE_SESSION_IDS[0],),
            )
            admin.execute(
                "INSERT INTO iam.sessions("
                "id,user_id,family_id,generation,predecessor_session_id,"
                "handle_digest,handle_digest_key_id,csrf_salt,csrf_key_id,"
                "csrf_digest,verified_contact_point_id,verified_at,"
                "verified_for_invitation_id,auth_transaction_id,auth_time,"
                "acr_code,amr_codes,created_at,last_activity_at,"
                "idle_expires_at,absolute_expires_at,updated_at,device_label,"
                "status,rotation_reason,revoked_at,revocation_reason_code,"
                "aggregate_version) SELECT %s,user_id,family_id,2,id,%s,"
                "handle_digest_key_id,%s,csrf_key_id,%s,NULL,NULL,NULL,"
                "auth_transaction_id,auth_time,acr_code,amr_codes,"
                "transaction_timestamp(),transaction_timestamp(),"
                "transaction_timestamp()+interval '1 day',"
                "absolute_expires_at,transaction_timestamp(),device_label,"
                "'ACTIVE','STEP_UP',NULL,NULL,1 FROM iam.sessions WHERE id=%s",
                (
                    ROTATED_SESSION_ID,
                    hashlib.sha256(b"iam37-rotated-session-handle").digest(),
                    hashlib.sha256(b"iam37-rotated-session-csrf-salt").digest(),
                    hashlib.sha256(b"iam37-rotated-session-csrf").digest(),
                    FINANCE_SESSION_IDS[0],
                ),
            )
            admin.execute(
                "UPDATE iam.session_families SET current_generation=2,"
                "aggregate_version=aggregate_version+1,"
                "updated_at=transaction_timestamp() WHERE id=%s",
                (FINANCE_FAMILY_IDS[0],),
            )
        self.assertIsNone(
            self._lock(
                operation="SUBMIT_FUNDING_REVIEW_FINDING",
                funding_review_id=FUNDING_REVIEW_ID,
                assignment_id=ASSIGNMENT_ID,
            )
        )

        with self._admin(autocommit=False) as admin:
            admin.execute(
                "UPDATE iam.sessions SET status='REVOKED',"
                "revoked_at=transaction_timestamp(),"
                "revocation_reason_code='IAM37_TEST_FAMILY_REVOKED',"
                "aggregate_version=aggregate_version+1,"
                "updated_at=transaction_timestamp() WHERE id=%s",
                (FINANCE_SESSION_IDS[1],),
            )
            admin.execute(
                "UPDATE iam.session_families SET status='REVOKED',"
                "revoked_at=transaction_timestamp(),"
                "revocation_reason_code='IAM37_TEST_FAMILY_REVOKED',"
                "aggregate_version=aggregate_version+1,"
                "updated_at=transaction_timestamp() WHERE id=%s",
                (FINANCE_FAMILY_IDS[1],),
            )
        self.assertIsNone(
            self._lock(
                operation="SUBMIT_FUNDING_REVIEW_FINDING",
                funding_review_id=FUNDING_REVIEW_ID,
                assignment_id=ASSIGNMENT_ID,
                ordinal=1,
            )
        )

    def _lock(
        self,
        *,
        operation: str,
        funding_review_id: UUID,
        assignment_id: UUID,
        context_funding_review_id: UUID | None = None,
        candidate_session_id: UUID | None = None,
        principal_marker: bytes | None = None,
        ordinal: int = 0,
    ):
        actor_user_id = FINANCE_USER_IDS[ordinal]
        session_id = candidate_session_id or FINANCE_SESSION_IDS[ordinal]
        settings = {
            "app.scope_kind": "FINANCE_FUNDING",
            "app.actor_id": str(actor_user_id),
            "app.session_id": str(session_id),
            "app.organization_id": str(ORGANIZATION_ID),
            "app.demand_id": str(DEMAND_ID),
            "app.funding_review_id": str(
                context_funding_review_id or funding_review_id
            ),
            "app.assignment_id": str(assignment_id),
            "app.operation": operation,
        }
        with psycopg.connect(
            self.postgres.conninfo(database=self.database, user="demand_finance"),
            autocommit=False,
        ) as connection:
            for name, value in settings.items():
                connection.execute("SELECT set_config(%s, %s, true)", (name, value))
            return connection.execute(
                "SELECT * FROM public.test_lock_finance_funding_authority_v2("
                "%s,%s,%s,%s,%s,%s,%s,%s)",
                (
                    actor_user_id,
                    session_id,
                    ORGANIZATION_ID,
                    DEMAND_ID,
                    funding_review_id,
                    assignment_id,
                    operation,
                    principal_marker or self.principal_markers[ordinal],
                ),
            ).fetchone()

    @classmethod
    def _resolve_principal_marker(cls, ordinal: int) -> bytes:
        resolver = PsycopgEditorPrincipalResolver(
            connections=_Connections(
                cls.postgres.conninfo(database=cls.database, user="iam_app")
            )
        )
        workspace = resolver.resolve(
            EditorPrincipalResolutionRequest(
                actor_user_id=FINANCE_USER_IDS[ordinal],
                session_id=FINANCE_SESSION_IDS[ordinal],
                requested_workspace_id=f"platform:{FINANCE_USER_IDS[ordinal]}",
            )
        )
        return workspace.principal_marker

    @classmethod
    def _finance_principal_marker(cls, ordinal: int) -> bytes | None:
        actor_user_id = FINANCE_USER_IDS[ordinal]
        session_id = FINANCE_SESSION_IDS[ordinal]
        with psycopg.connect(
            cls.postgres.conninfo(database=cls.database, user="demand_finance"),
            autocommit=False,
        ) as connection:
            for name, value in (
                ("app.scope_kind", "FINANCE_FUNDING"),
                ("app.operation", "LIST_FUNDING_REVIEWS"),
                ("app.actor_id", str(actor_user_id)),
                ("app.session_id", str(session_id)),
            ):
                connection.execute("SELECT set_config(%s, %s, true)", (name, value))
            row = connection.execute(
                "SELECT public.test_finance_funding_principal_marker_v1(%s,%s)",
                (actor_user_id, session_id),
            ).fetchone()
        return None if row is None else row[0]

    @classmethod
    def _seed_conflicting_membership(cls) -> None:
        now = datetime.now(timezone.utc).replace(microsecond=0)
        with cls._admin(autocommit=False) as admin:
            admin.execute(
                "INSERT INTO iam.access_invitations("
                "id,purpose,organization_id,target_scope,target_role,"
                "is_initial_admin,recipient_contact_id,masked_recipient_label,"
                "policy_selector_digest,issued_policy_bundle_id,status,"
                "expires_at,issuer_kind,issuer_user_id,token_nonce,token_key_id,"
                "accepted_by_user_id,terminal_at,terminal_reason_code,"
                "aggregate_version,created_at,updated_at) "
                "SELECT %s,'ORGANIZATION_MEMBERSHIP',organization_id,"
                "'ORGANIZATION','DEMAND_OWNER',false,recipient_contact_id,"
                "'f***@example.invalid',policy_selector_digest,"
                "issued_policy_bundle_id,'ACCEPTED',%s,'SYSTEM',NULL,%s,"
                "'invitation-token-v1',%s,%s,NULL,1,%s,%s "
                "FROM iam.access_invitations WHERE organization_id=%s LIMIT 1",
                (
                    CONFLICT_INVITATION_ID,
                    now.replace(year=now.year + 1),
                    hashlib.sha256(b"iam37-conflict-invitation").digest(),
                    FINANCE_USER_IDS[0],
                    now,
                    now,
                    now,
                    ORGANIZATION_ID,
                ),
            )
            admin.execute(
                "INSERT INTO iam.memberships("
                "id,organization_id,user_id,status,source_invitation_id,"
                "aggregate_version,created_at,updated_at) "
                "VALUES (%s,%s,%s,'ACTIVE',%s,1,%s,%s)",
                (
                    CONFLICT_MEMBERSHIP_ID,
                    ORGANIZATION_ID,
                    FINANCE_USER_IDS[0],
                    CONFLICT_INVITATION_ID,
                    now,
                    now,
                ),
            )

    @classmethod
    def _admin(cls, *, autocommit: bool = True):
        return psycopg.connect(
            cls.postgres.admin_conninfo(database=cls.database),
            autocommit=autocommit,
        )

    @classmethod
    def _migrate(cls) -> None:
        IamMigrationRunner(
            driver=PsycopgMigrationDriver(
                settings=PsycopgMigrationSettings(
                    conninfo=cls.postgres.conninfo(
                        database=cls.database,
                        user="iam_migration_runner",
                    )
                ),
                dbapi=psycopg,
            ),
            runner_version="iam37-finance-funding-pg18-test/1",
        ).run(
            catalog=MigrationCatalog.load(IAM_ROOT),
            contract_sources=IamContractSources(
                api_contract_bytes=(
                    PLATFORM_ROOT / "contracts/api/iam-v1.openapi.yaml"
                ).read_bytes(),
                event_contract_bytes=(
                    PLATFORM_ROOT / "contracts/events/iam-v1.schema.json"
                ).read_bytes(),
            ),
        )

    @classmethod
    def _create_demand_owner_adapter(cls, connection) -> None:
        connection.execute(
            "CREATE FUNCTION public.test_lock_finance_funding_authority_v2("
            "candidate_actor_user_id uuid,candidate_session_id uuid,"
            "candidate_organization_id uuid,candidate_demand_id uuid,"
            "candidate_funding_review_id uuid,candidate_assignment_id uuid,"
            "candidate_operation text,expected_principal_marker_sha256 bytea) "
            "RETURNS TABLE(duty_grant_id uuid,duty_grant_version bigint,"
            "duty_expires_at timestamptz,authority_marker_sha256 bytea) "
            "LANGUAGE sql SECURITY DEFINER VOLATILE PARALLEL UNSAFE "
            "SET search_path=pg_catalog,iam_api AS $function$ "
            "SELECT * FROM iam_api.lock_finance_funding_authority_v2("
            "candidate_actor_user_id,candidate_session_id,"
            "candidate_organization_id,candidate_demand_id,"
            "candidate_funding_review_id,candidate_assignment_id,"
            "candidate_operation,expected_principal_marker_sha256) "
            "$function$"
        )
        connection.execute(
            "ALTER FUNCTION public.test_lock_finance_funding_authority_v2("
            "uuid,uuid,uuid,uuid,uuid,uuid,text,bytea) "
            "OWNER TO demand_schema_owner"
        )
        connection.execute(
            "REVOKE ALL ON FUNCTION "
            "public.test_lock_finance_funding_authority_v2("
            "uuid,uuid,uuid,uuid,uuid,uuid,text,bytea) FROM PUBLIC"
        )
        connection.execute(
            "GRANT EXECUTE ON FUNCTION "
            "public.test_lock_finance_funding_authority_v2("
            "uuid,uuid,uuid,uuid,uuid,uuid,text,bytea) TO demand_finance"
        )
        connection.execute(
            "CREATE FUNCTION public.test_finance_funding_principal_marker_v1("
            "exact_actor_user_id uuid,exact_session_id uuid) RETURNS bytea "
            "LANGUAGE sql SECURITY DEFINER STABLE PARALLEL UNSAFE "
            "SET search_path=pg_catalog,iam_api AS $function$ "
            "SELECT iam_api.finance_funding_principal_marker_v1("
            "exact_actor_user_id,exact_session_id) $function$"
        )
        connection.execute(
            "ALTER FUNCTION public.test_finance_funding_principal_marker_v1("
            "uuid,uuid) OWNER TO schema_owner"
        )
        connection.execute(
            "REVOKE ALL ON FUNCTION "
            "public.test_finance_funding_principal_marker_v1(uuid,uuid) "
            "FROM PUBLIC"
        )
        connection.execute(
            "GRANT EXECUTE ON FUNCTION "
            "public.test_finance_funding_principal_marker_v1(uuid,uuid) "
            "TO demand_finance"
        )


if __name__ == "__main__":
    unittest.main()
