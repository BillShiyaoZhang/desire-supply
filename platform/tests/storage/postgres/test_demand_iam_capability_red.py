"""Direct-SQL TDD gate for the IAM capabilities consumed by Demand."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
import unittest
import uuid

import psycopg

from desire_platform.identity_access.adapters.postgres.migrations import (
    IamContractSources,
    IamMigrationRunner,
    MigrationCatalog,
    PsycopgMigrationDriver,
    PsycopgMigrationSettings,
)
from tests.storage.postgres.postgres18_harness import TemporaryPostgres18
from tests.support.demand_postgres_builders import (
    ACTOR_USER_ID,
    ASSIGNMENT_ID,
    DEMAND_ID,
    ORGANIZATION_ID,
    OTHER_DEMAND_ID,
    OTHER_ORGANIZATION_ID,
    REVIEWER_SESSION_ID,
    REVIEWER_USER_ID,
    SESSION_ID,
    seed_exact_demand_owner_iam_authority,
)


PLATFORM_ROOT = Path(__file__).resolve().parents[3]
IAM_MIGRATION_ROOT = (
    PLATFORM_ROOT
    / "src/desire_platform/identity_access/adapters/postgres/migrations"
)
OWNER_SIGNATURE = (
    "iam_api.lock_demand_owner_authority_v1"
    "(uuid,uuid,uuid,text,uuid,bytea)"
)
REVIEWER_SIGNATURE = (
    "iam_api.lock_demand_reviewer_authority_v2"
    "(uuid,uuid,uuid,uuid,uuid,text,bytea)"
)
OWNER_OPERATIONS = ("CREATE", "CREATE_VERSION", "SUBMIT", "CANCEL_OWNER")
REVIEWER_OPERATIONS = (
    "REQUEST_CHANGES",
    "VERIFY",
    "REQUEST_MATCHING",
    "CANCEL_REVIEW",
)


class DemandIamCapabilityDirectSqlTest(unittest.TestCase):
    """TEST-DB-DEMAND-IAM-CAPABILITY-001."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.postgres = TemporaryPostgres18().start()
        cls.catalog = MigrationCatalog.load(IAM_MIGRATION_ROOT)
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
        report = IamMigrationRunner(
            driver=PsycopgMigrationDriver(
                settings=PsycopgMigrationSettings(
                    conninfo=self.postgres.conninfo(
                        database=self.database,
                        user="iam_migration_runner",
                    ),
                    application_name="desire-demand-iam-capability",
                ),
                dbapi=psycopg,
            ),
            runner_version="demand-iam-capability/1",
        ).run(catalog=self.catalog, contract_sources=self.contract_sources)
        expected = tuple(
            artifact.descriptor.version for artifact in self.catalog.artifacts
        )
        if report.applied_versions != expected:
            raise AssertionError("Demand IAM test did not apply the exact catalog")
        with self._admin(autocommit=False) as connection:
            self.authority = seed_exact_demand_owner_iam_authority(
                connection,
                now=datetime.now(timezone.utc),
            )

    def tearDown(self) -> None:
        self.postgres.drop_database(self.database)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.postgres.stop()

    def _admin(self, *, autocommit: bool = True):
        return psycopg.connect(
            self.postgres.admin_conninfo(database=self.database),
            autocommit=autocommit,
        )

    def _require_capability(self, signature: str) -> None:
        with self._admin() as connection:
            actual = connection.execute(
                "SELECT pg_catalog.to_regprocedure(%s)::text",
                (signature,),
            ).fetchone()[0]
        self.assertEqual(
            actual,
            signature,
            "semantic RED: exact Demand IAM capability is absent",
        )

    def _owner_marker(
        self,
        *,
        operation: str,
        demand_id: uuid.UUID = DEMAND_ID,
    ) -> bytes:
        with self._admin() as connection:
            row = connection.execute(
                "SELECT family.id,family.aggregate_version,"
                "active_session.id,active_session.aggregate_version,"
                "active_session.generation,actor.id,actor.aggregate_version,"
                "organization.id,organization.aggregate_version,"
                "membership.id,membership.aggregate_version,"
                "role_grant.id,role_grant.aggregate_version,"
                "role_grant.source_invitation_id,source_invitation.aggregate_version,"
                "pg_catalog.encode(role_grant.policy_selector_digest,'hex'),"
                "selector.aggregate_version,selector.current_bundle_id,"
                "current_bundle.aggregate_version "
                "FROM iam.session_families AS family "
                "JOIN iam.sessions AS active_session ON active_session.family_id=family.id "
                "JOIN iam.users AS actor ON actor.id=active_session.user_id "
                "JOIN iam.organizations AS organization ON organization.id=%s "
                "JOIN iam.memberships AS membership "
                " ON membership.organization_id=organization.id AND membership.user_id=actor.id "
                "JOIN iam.membership_role_grants AS role_grant "
                " ON role_grant.organization_id=organization.id "
                "AND role_grant.membership_id=membership.id AND role_grant.user_id=actor.id "
                "JOIN iam.access_invitations AS source_invitation "
                " ON source_invitation.id=role_grant.source_invitation_id "
                "JOIN iam.policy_selectors AS selector "
                " ON selector.selector_digest=role_grant.policy_selector_digest "
                "JOIN iam.policy_bundles AS current_bundle "
                " ON current_bundle.id=selector.current_bundle_id "
                "WHERE active_session.id=%s AND actor.id=%s",
                (ORGANIZATION_ID, SESSION_ID, ACTOR_USER_ID),
            ).fetchone()
        if row is None:
            raise AssertionError("Demand owner marker fixture is incomplete")
        material = "|".join(
            (
                "iam-demand-owner-authority-v1",
                operation,
                str(demand_id),
                str(row[0]),
                str(row[1]),
                str(row[2]),
                str(row[3]),
                str(row[4]),
                str(row[5]),
                str(row[6]),
                str(row[7]),
                str(row[8]),
                str(row[9]),
                str(row[10]),
                str(row[11]),
                str(row[12]),
                str(row[13]),
                str(row[14]),
                row[15],
                str(row[16]),
                str(row[17]),
                str(row[18]),
            )
        )
        return hashlib.sha256(material.encode("utf-8")).digest()

    def _reviewer_marker(
        self,
        *,
        operation: str,
        organization_id: uuid.UUID = ORGANIZATION_ID,
        demand_id: uuid.UUID = DEMAND_ID,
        assignment_id: uuid.UUID = ASSIGNMENT_ID,
    ) -> bytes:
        with psycopg.connect(
            self.postgres.conninfo(database=self.database, user="demand_review"),
            autocommit=False,
        ) as connection:
            for name, value in (
                ("app.scope_kind", "DEMAND_REVIEW"),
                ("app.actor_id", str(REVIEWER_USER_ID)),
                ("app.session_id", str(REVIEWER_SESSION_ID)),
                ("app.organization_id", str(organization_id)),
                ("app.operation", operation),
                ("app.demand_id", str(demand_id)),
                ("app.assignment_id", str(assignment_id)),
            ):
                connection.execute(
                    "SELECT pg_catalog.set_config(%s,%s,true)",
                    (name, value),
                )
            row = connection.execute(
                "SELECT authority_marker_sha256 FROM "
                "iam_api.resolve_demand_reviewer_authority_marker_v2("
                "%s,%s,%s,%s,%s,%s)",
                (
                    REVIEWER_USER_ID,
                    REVIEWER_SESSION_ID,
                    organization_id,
                    operation,
                    demand_id,
                    assignment_id,
                ),
            ).fetchone()
        if row is None:
            raise AssertionError("Demand reviewer marker fixture is incomplete")
        return row[0]

    def _owner_row(
        self,
        *,
        operation: str = "CREATE",
        demand_id: uuid.UUID | None = DEMAND_ID,
        expected_marker: bytes | None = None,
        actor_id: uuid.UUID = ACTOR_USER_ID,
        session_id: uuid.UUID = SESSION_ID,
        organization_id: uuid.UUID = ORGANIZATION_ID,
        guc_actor_id: uuid.UUID | None = None,
        guc_organization_id: uuid.UUID | None = None,
    ):
        marker = expected_marker
        if marker is None and demand_id is not None:
            marker = self._owner_marker(operation=operation, demand_id=demand_id)
        with psycopg.connect(
            self.postgres.conninfo(database=self.database, user="demand_self"),
            autocommit=False,
        ) as connection:
            for name, value in (
                ("app.scope_kind", "DEMAND_OWNER"),
                ("app.actor_id", str(guc_actor_id or actor_id)),
                ("app.session_id", str(session_id)),
                ("app.organization_id", str(guc_organization_id or organization_id)),
                ("app.operation", operation),
                ("app.demand_id", "" if demand_id is None else str(demand_id)),
            ):
                connection.execute(
                    "SELECT pg_catalog.set_config(%s,%s,true)",
                    (name, value),
                )
            return connection.execute(
                "SELECT actor_user_id,session_id,session_family_id,organization_id,"
                "membership_id,membership_role_grant_id,"
                "membership_role_grant_version,policy_selector_digest,"
                "current_bundle_id,authority_marker_sha256 "
                "FROM iam_api.lock_demand_owner_authority_v1(%s,%s,%s,%s,%s,%s)",
                (
                    actor_id,
                    session_id,
                    organization_id,
                    operation,
                    demand_id,
                    marker,
                ),
            ).fetchone()

    def _reviewer_row(
        self,
        *,
        operation: str = "VERIFY",
        organization_id: uuid.UUID = ORGANIZATION_ID,
        demand_id: uuid.UUID = DEMAND_ID,
        assignment_id: uuid.UUID = ASSIGNMENT_ID,
        expected_marker: bytes | None = None,
        actor_id: uuid.UUID = REVIEWER_USER_ID,
        session_id: uuid.UUID = REVIEWER_SESSION_ID,
        guc_actor_id: uuid.UUID | None = None,
        guc_assignment_id: uuid.UUID | None = None,
    ):
        marker = expected_marker or self._reviewer_marker(
            operation=operation,
            organization_id=organization_id,
            demand_id=demand_id,
            assignment_id=assignment_id,
        )
        with psycopg.connect(
            self.postgres.conninfo(database=self.database, user="demand_review"),
            autocommit=False,
        ) as connection:
            for name, value in (
                ("app.scope_kind", "DEMAND_REVIEW"),
                ("app.actor_id", str(guc_actor_id or actor_id)),
                ("app.session_id", str(session_id)),
                ("app.organization_id", str(organization_id)),
                ("app.operation", operation),
                ("app.demand_id", str(demand_id)),
                ("app.assignment_id", str(guc_assignment_id or assignment_id)),
            ):
                connection.execute(
                    "SELECT pg_catalog.set_config(%s,%s,true)",
                    (name, value),
                )
            return connection.execute(
                "SELECT actor_user_id,session_id,session_family_id,"
                "session_family_version,session_version,session_generation,"
                "user_version,duty_grant_id,duty_grant_version,duty_expires_at,"
                "authority_marker_sha256 FROM "
                "iam_api.lock_demand_reviewer_authority_v2("
                "%s,%s,%s,%s,%s,%s,%s)",
                (
                    actor_id,
                    session_id,
                    organization_id,
                    demand_id,
                    assignment_id,
                    operation,
                    marker,
                ),
            ).fetchone()

    def _replace_current_bundle(
        self,
        *,
        reuse_document: bool,
        legal_effect: str = "CONTRACT_ACCEPTANCE",
        accept_new_document: bool = False,
    ) -> uuid.UUID:
        now = datetime.now(timezone.utc)
        bundle_id = uuid.uuid4()
        document_id = (
            self.authority.required_document_id if reuse_document else uuid.uuid4()
        )
        document_hash = (
            self.authority.required_document_sha256
            if reuse_document
            else hashlib.sha256(document_id.bytes).digest()
        )
        with self._admin(autocommit=False) as connection:
            connection.execute("SET CONSTRAINTS ALL DEFERRED")
            if not reuse_document:
                connection.execute(
                    "INSERT INTO iam.policy_documents ("
                    "id,kind,locale,semantic_version,canonical_body,content_sha256,"
                    "legal_effect,jurisdiction,status,effective_at,"
                    "superseded_by_document_id,publication_command_id,created_at,updated_at"
                    ") VALUES (%s,'TERMS','zh-CN',%s,'Demand replacement terms',%s,"
                    "%s,'CN','ACTIVE',%s,NULL,%s,%s,%s)",
                    (
                        document_id,
                        "2.0." + str(document_id.int % 100000),
                        document_hash,
                        legal_effect,
                        now - timedelta(minutes=1),
                        uuid.uuid4(),
                        now - timedelta(minutes=2),
                        now - timedelta(minutes=1),
                    ),
                )
            connection.execute(
                "INSERT INTO iam.policy_bundles ("
                "id,selector_digest,status,effective_at,effective_until,"
                "superseded_by_bundle_id,release_manifest_sha256,release_signature,"
                "release_signing_key_id,publication_command_id,aggregate_version,"
                "created_at,updated_at) VALUES ("
                "%s,%s,'DRAFT',NULL,NULL,NULL,%s,%s,'demand-capability-v1',"
                "%s,1,%s,%s)",
                (
                    bundle_id,
                    self.authority.policy_selector_digest,
                    hashlib.sha256(bundle_id.bytes).digest(),
                    b"reviewed-demand-capability-signature",
                    uuid.uuid4(),
                    now - timedelta(minutes=2),
                    now - timedelta(minutes=2),
                ),
            )
            connection.execute(
                "INSERT INTO iam.policy_bundle_documents "
                "(bundle_id,document_id,position,required) VALUES (%s,%s,1,true)",
                (bundle_id, document_id),
            )
            connection.execute(
                "UPDATE iam.policy_bundles SET status='SUPERSEDED',"
                "effective_until=%s,superseded_by_bundle_id=%s,"
                "aggregate_version=aggregate_version+1,updated_at=%s WHERE id=%s",
                (now, bundle_id, now, self.authority.policy_bundle_id),
            )
            connection.execute(
                "UPDATE iam.policy_bundles SET status='ACTIVE',effective_at=%s,"
                "aggregate_version=2,updated_at=%s WHERE id=%s",
                (now, now, bundle_id),
            )
            connection.execute(
                "UPDATE iam.policy_selectors SET current_bundle_id=%s,"
                "aggregate_version=aggregate_version+1,updated_at=%s "
                "WHERE selector_digest=%s",
                (bundle_id, now, self.authority.policy_selector_digest),
            )
            if accept_new_document:
                connection.execute(
                    "INSERT INTO iam.policy_acceptances ("
                    "id,user_id,document_id,content_sha256,bundle_id,accepted_at,"
                    "session_id,auth_transaction_id,auth_time,acr_code,amr_codes,"
                    "source_action,command_id,correlation_id,aggregate_version,created_at"
                    ") SELECT %s,%s,%s,%s,%s,%s,%s,auth_transaction_id,auth_time,"
                    "acr_code,amr_codes,'POLICY_ACCEPT',%s,%s,1,%s "
                    "FROM iam.sessions WHERE id=%s",
                    (
                        uuid.uuid4(),
                        ACTOR_USER_ID,
                        document_id,
                        document_hash,
                        bundle_id,
                        now,
                        SESSION_ID,
                        uuid.uuid4(),
                        uuid.uuid4(),
                        now,
                        SESSION_ID,
                    ),
                )
        return bundle_id

    def test_owner_function_contract_acl_and_no_dynamic_sql_are_closed(self) -> None:
        self._require_capability(OWNER_SIGNATURE)
        with self._admin() as connection:
            row = connection.execute(
                "SELECT procedure.prosecdef,procedure.provolatile,"
                "procedure.proparallel,procedure.proconfig,procedure.prosrc,"
                "pg_catalog.pg_get_function_result(procedure.oid),"
                "pg_catalog.has_function_privilege('demand_self',procedure.oid,'EXECUTE'),"
                "pg_catalog.has_function_privilege('demand_review',procedure.oid,'EXECUTE'),"
                "NOT EXISTS (SELECT 1 FROM pg_catalog.aclexplode(procedure.proacl) acl "
                " WHERE acl.grantee=0 AND acl.privilege_type='EXECUTE') "
                "FROM pg_catalog.pg_proc AS procedure "
                "WHERE procedure.oid=pg_catalog.to_regprocedure(%s)",
                (OWNER_SIGNATURE,),
            ).fetchone()
        self.assertEqual(row[:4], (True, "v", "u", ["search_path=pg_catalog, iam, iam_api"]))
        self.assertNotIn("EXECUTE", row[4].upper())
        self.assertEqual(
            row[5],
            "TABLE(actor_user_id uuid, session_id uuid, session_family_id uuid, "
            "organization_id uuid, membership_id uuid, membership_role_grant_id uuid, "
            "membership_role_grant_version bigint, policy_selector_digest bytea, "
            "current_bundle_id uuid, authority_marker_sha256 bytea)",
        )
        self.assertEqual(row[6:], (True, False, True))

    def test_owner_happy_path_returns_exact_row_for_all_four_operations(self) -> None:
        self._require_capability(OWNER_SIGNATURE)
        for operation in OWNER_OPERATIONS:
            marker = self._owner_marker(operation=operation)
            with self.subTest(operation=operation):
                row = self._owner_row(
                    operation=operation,
                    expected_marker=marker,
                )
                self.assertIsNotNone(row)
                self.assertEqual(row[0], ACTOR_USER_ID)
                self.assertEqual(row[1], SESSION_ID)
                self.assertEqual(row[3], ORGANIZATION_ID)
                self.assertEqual(row[4], self.authority.membership_id)
                self.assertEqual(row[5], self.authority.membership_role_grant_id)
                self.assertEqual(row[7], self.authority.policy_selector_digest)
                self.assertEqual(row[8], self.authority.policy_bundle_id)
                self.assertEqual(row[9], marker)

    def test_owner_cross_scope_bad_operation_null_target_and_marker_are_zero_row(self) -> None:
        self._require_capability(OWNER_SIGNATURE)
        exact = self._owner_marker(operation="CREATE")
        cases = (
            {"actor_id": uuid.uuid4(), "expected_marker": b"f" * 32},
            {"organization_id": OTHER_ORGANIZATION_ID, "expected_marker": b"f" * 32},
            {"operation": "VERIFY", "expected_marker": b"f" * 32},
            {"demand_id": None, "expected_marker": b"f" * 32},
            {"expected_marker": b"f" * 32},
            {"expected_marker": exact, "guc_actor_id": uuid.uuid4()},
            {"expected_marker": exact, "guc_organization_id": OTHER_ORGANIZATION_ID},
        )
        for values in cases:
            with self.subTest(values=tuple(sorted(values))):
                self.assertIsNone(self._owner_row(**values))

    def test_owner_inactive_membership_is_zero_row(self) -> None:
        self._require_capability(OWNER_SIGNATURE)
        with self._admin(autocommit=False) as connection:
            connection.execute(
                "UPDATE iam.memberships SET status='SUSPENDED',"
                "aggregate_version=aggregate_version+1,updated_at=transaction_timestamp() "
                "WHERE id=%s",
                (self.authority.membership_id,),
            )
        marker = self._owner_marker(operation="CREATE")
        self.assertIsNone(self._owner_row(expected_marker=marker))

    def test_owner_revoked_demand_owner_grant_is_zero_row(self) -> None:
        self._require_capability(OWNER_SIGNATURE)
        with self._admin(autocommit=False) as connection:
            connection.execute(
                "UPDATE iam.membership_role_grants SET revoked_at=transaction_timestamp(),"
                "revocation_reason_code='TEST_REVOKED',"
                "aggregate_version=aggregate_version+1 WHERE id=%s",
                (self.authority.membership_role_grant_id,),
            )
        marker = self._owner_marker(operation="CREATE")
        self.assertIsNone(self._owner_row(expected_marker=marker))

    def test_owner_expired_session_window_is_zero_row(self) -> None:
        self._require_capability(OWNER_SIGNATURE)
        with self._admin(autocommit=False) as connection:
            connection.execute(
                "UPDATE iam.sessions SET idle_expires_at=transaction_timestamp(),"
                "updated_at=transaction_timestamp(),aggregate_version=aggregate_version+1 "
                "WHERE id=%s",
                (SESSION_ID,),
            )
        marker = self._owner_marker(operation="CREATE")
        self.assertIsNone(self._owner_row(expected_marker=marker))

    def test_owner_old_source_acceptance_satisfies_current_required_document(self) -> None:
        self._require_capability(OWNER_SIGNATURE)
        current_bundle = self._replace_current_bundle(reuse_document=True)
        marker = self._owner_marker(operation="CREATE")
        row = self._owner_row(expected_marker=marker)
        self.assertIsNotNone(row)
        self.assertEqual(row[8:], (current_bundle, marker))

    def test_owner_wrong_current_legal_effect_is_zero_row(self) -> None:
        self._require_capability(OWNER_SIGNATURE)
        self._replace_current_bundle(
            reuse_document=False,
            legal_effect="CONSENT_TEXT",
            accept_new_document=True,
        )
        marker = self._owner_marker(operation="CREATE")
        self.assertIsNone(self._owner_row(expected_marker=marker))

    def test_owner_missing_exact_current_document_hash_acceptance_is_zero_row(self) -> None:
        self._require_capability(OWNER_SIGNATURE)
        self._replace_current_bundle(reuse_document=False)
        marker = self._owner_marker(operation="CREATE")
        self.assertIsNone(self._owner_row(expected_marker=marker))

    def test_reviewer_function_contract_acl_and_no_dynamic_sql_are_closed(self) -> None:
        self._require_capability(REVIEWER_SIGNATURE)
        with self._admin() as connection:
            row = connection.execute(
                "SELECT procedure.prosecdef,procedure.provolatile,"
                "procedure.proparallel,procedure.proconfig,procedure.prosrc,"
                "pg_catalog.pg_get_function_result(procedure.oid),"
                "pg_catalog.has_function_privilege('demand_review',procedure.oid,'EXECUTE'),"
                "pg_catalog.has_function_privilege('demand_self',procedure.oid,'EXECUTE'),"
                "NOT EXISTS (SELECT 1 FROM pg_catalog.aclexplode(procedure.proacl) acl "
                " WHERE acl.grantee=0 AND acl.privilege_type='EXECUTE') "
                "FROM pg_catalog.pg_proc AS procedure "
                "WHERE procedure.oid=pg_catalog.to_regprocedure(%s)",
                (REVIEWER_SIGNATURE,),
            ).fetchone()
        self.assertEqual(row[:4], (True, "v", "u", ["search_path=pg_catalog, iam, iam_api"]))
        self.assertNotIn("EXECUTE", row[4].upper())
        self.assertEqual(
            row[5],
            "TABLE(actor_user_id uuid, session_id uuid, session_family_id uuid, "
            "session_family_version bigint, session_version bigint, "
            "session_generation bigint, user_version bigint, "
            "duty_grant_id uuid, duty_grant_version bigint, "
            "duty_expires_at timestamp with time zone, "
            "authority_marker_sha256 bytea)",
        )
        self.assertEqual(row[6:], (True, False, True))

    def test_reviewer_happy_all_operations_does_not_use_org_membership_as_authority(self) -> None:
        self._require_capability(REVIEWER_SIGNATURE)
        with self._admin(autocommit=False) as connection:
            connection.execute(
                "UPDATE iam.memberships SET status='SUSPENDED',"
                "aggregate_version=aggregate_version+1,updated_at=transaction_timestamp() "
                "WHERE id=%s",
                (self.authority.membership_id,),
            )
        for operation in REVIEWER_OPERATIONS:
            marker = self._reviewer_marker(operation=operation)
            with self.subTest(operation=operation):
                row = self._reviewer_row(
                    operation=operation,
                    expected_marker=marker,
                )
                self.assertIsNotNone(row)
                self.assertEqual(row[0], REVIEWER_USER_ID)
                self.assertEqual(row[1], REVIEWER_SESSION_ID)
                self.assertEqual(row[10], marker)

    def test_reviewer_cross_actor_target_guc_and_marker_are_zero_row(self) -> None:
        self._require_capability(REVIEWER_SIGNATURE)
        exact = self._reviewer_marker(operation="VERIFY")
        cases = (
            {"actor_id": uuid.uuid4(), "expected_marker": b"f" * 32},
            {"organization_id": OTHER_ORGANIZATION_ID, "expected_marker": b"f" * 32},
            {"demand_id": OTHER_DEMAND_ID, "expected_marker": b"f" * 32},
            {"assignment_id": uuid.uuid4(), "expected_marker": b"f" * 32},
            {"operation": "CREATE", "expected_marker": b"f" * 32},
            {"expected_marker": b"f" * 32},
            {"expected_marker": exact, "guc_actor_id": uuid.uuid4()},
            {"expected_marker": exact, "guc_assignment_id": uuid.uuid4()},
        )
        for values in cases:
            with self.subTest(values=tuple(sorted(values))):
                self.assertIsNone(self._reviewer_row(**values))

    def test_reviewer_expired_session_window_is_zero_row(self) -> None:
        self._require_capability(REVIEWER_SIGNATURE)
        with self._admin(autocommit=False) as connection:
            connection.execute(
                "UPDATE iam.sessions SET idle_expires_at=transaction_timestamp(),"
                "updated_at=transaction_timestamp(),aggregate_version=aggregate_version+1 "
                "WHERE id=%s",
                (REVIEWER_SESSION_ID,),
            )
        self.assertIsNone(self._reviewer_row(expected_marker=b"f" * 32))

    def test_reviewer_suspended_user_status_is_zero_row(self) -> None:
        self._require_capability(REVIEWER_SIGNATURE)
        with self._admin(autocommit=False) as connection:
            connection.execute(
                "UPDATE iam.users SET status='SUSPENDED',"
                "updated_at=transaction_timestamp(),aggregate_version=aggregate_version+1 "
                "WHERE id=%s",
                (REVIEWER_USER_ID,),
            )
        self.assertIsNone(self._reviewer_row(expected_marker=b"f" * 32))

    def test_online_roles_have_no_direct_iam_table_select(self) -> None:
        self._require_capability(OWNER_SIGNATURE)
        self._require_capability(REVIEWER_SIGNATURE)
        for role in ("demand_self", "demand_review"):
            with self.subTest(role=role), psycopg.connect(
                self.postgres.conninfo(database=self.database, user=role),
                autocommit=False,
            ) as connection:
                with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                    connection.execute("SELECT id FROM iam.users LIMIT 1").fetchone()

    def test_demand_migration_runner_can_read_only_iam_compatibility(self) -> None:
        self._require_capability(OWNER_SIGNATURE)
        with psycopg.connect(
            self.postgres.conninfo(
                database=self.database,
                user="demand_migration_runner",
            ),
            autocommit=False,
        ) as connection:
            try:
                compatibility = connection.execute(
                    "SELECT current_schema_version,schema_head_version,"
                    "min_app_compatible_version,max_app_compatible_version,"
                    "to_regprocedure(%s) IS NOT NULL,"
                    "to_regprocedure(%s) IS NOT NULL "
                    "FROM infra.iam_schema_compatibility",
                    (OWNER_SIGNATURE, REVIEWER_SIGNATURE),
                ).fetchone()
            except psycopg.errors.InsufficientPrivilege:
                connection.rollback()
                compatibility = None
            self.assertEqual(
                compatibility,
                (self.catalog.artifacts[-1].descriptor.version,) * 4
                + (True, True),
                "semantic RED: Demand runner cannot verify IAM head/signatures",
            )
            self.assertFalse(
                connection.execute(
                    "SELECT has_function_privilege(current_user,%s,'EXECUTE') "
                    "OR has_function_privilege(current_user,%s,'EXECUTE')",
                    (OWNER_SIGNATURE, REVIEWER_SIGNATURE),
                ).fetchone()[0]
            )
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                connection.execute("SELECT id FROM iam.users LIMIT 1").fetchone()


if __name__ == "__main__":
    unittest.main()
