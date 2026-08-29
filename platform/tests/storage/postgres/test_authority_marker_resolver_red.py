"""TEST-PG-IAM-AUTHORITY-MARKER-001: closed marker-only resolution."""

from __future__ import annotations

from dataclasses import FrozenInstanceError, fields
from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
import unittest
from uuid import UUID, uuid4

import psycopg

from desire_platform.identity_access.adapters.postgres.authority_markers import (
    DemandOwnerAuthorityMarkerRequest,
    DemandReviewerAuthorityMarkerRequest,
    ProfileSelfAuthorityMarkerRequest,
    PsycopgAuthorityMarkerResolver,
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
from tests.support.demand_postgres_builders import (
    ACTOR_USER_ID,
    ORGANIZATION_ID,
    REVIEWER_SESSION_FAMILY_ID,
    REVIEWER_SESSION_ID,
    REVIEWER_USER_ID,
    SESSION_ID,
    seed_exact_demand_owner_iam_authority,
)


ROOT = Path(__file__).resolve().parents[3]
MIGRATION_ROOT = (
    ROOT / "src/desire_platform/identity_access/adapters/postgres/migrations"
)
MIGRATION = MIGRATION_ROOT / "0021_expand__authority_marker_resolver.sql"
PROFILE_ID = UUID("71000000-0000-4000-8000-000000000001")
DEMAND_ID = UUID("72000000-0000-4000-8000-000000000001")
ASSIGNMENT_ID = UUID("73000000-0000-4000-8000-000000000001")
REVIEWER_MEMBERSHIP_ID = UUID("74000000-0000-4000-8000-000000000001")


class AuthorityMarkerContractRedTest(unittest.TestCase):
    def test_requests_are_frozen_closed_and_contain_no_marker_or_secret(self) -> None:
        requests = (
            ProfileSelfAuthorityMarkerRequest(
                actor_user_id=ACTOR_USER_ID,
                session_id=SESSION_ID,
                operation="CREATE_PROFILE",
                profile_id=PROFILE_ID,
            ),
            DemandOwnerAuthorityMarkerRequest(
                actor_user_id=ACTOR_USER_ID,
                session_id=SESSION_ID,
                organization_id=ORGANIZATION_ID,
                operation="CREATE",
                demand_id=DEMAND_ID,
            ),
            DemandReviewerAuthorityMarkerRequest(
                actor_user_id=REVIEWER_USER_ID,
                session_id=REVIEWER_SESSION_ID,
                organization_id=ORGANIZATION_ID,
                operation="VERIFY",
                demand_id=DEMAND_ID,
                assignment_id=ASSIGNMENT_ID,
            ),
        )
        with self.assertRaises(FrozenInstanceError):
            requests[0].operation = "PUBLISH_PROFILE"  # type: ignore[misc]
        names = {field.name for request in requests for field in fields(request)}
        self.assertFalse(
            names
            & {
                "authority_marker",
                "marker_sha256",
                "raw_session_handle",
                "password",
                "role_code",
            }
        )
        self.assertEqual(
            {
                name
                for name in dir(PsycopgAuthorityMarkerResolver)
                if not name.startswith("_")
            },
            {
                "resolve_profile_self",
                "resolve_demand_owner",
                "resolve_demand_reviewer",
            },
        )

    def test_requests_reject_zero_ids_and_operations_outside_closed_sets(self) -> None:
        zero = UUID(int=0)
        cases = (
            lambda: ProfileSelfAuthorityMarkerRequest(
                actor_user_id=zero,
                session_id=SESSION_ID,
                operation="CREATE_PROFILE",
                profile_id=PROFILE_ID,
            ),
            lambda: ProfileSelfAuthorityMarkerRequest(
                actor_user_id=ACTOR_USER_ID,
                session_id=SESSION_ID,
                operation="DROP TABLE iam.users",
                profile_id=PROFILE_ID,
            ),
            lambda: DemandOwnerAuthorityMarkerRequest(
                actor_user_id=ACTOR_USER_ID,
                session_id=SESSION_ID,
                organization_id=ORGANIZATION_ID,
                operation="VERIFY",
                demand_id=DEMAND_ID,
            ),
            lambda: DemandReviewerAuthorityMarkerRequest(
                actor_user_id=REVIEWER_USER_ID,
                session_id=REVIEWER_SESSION_ID,
                organization_id=ORGANIZATION_ID,
                operation="CREATE",
                demand_id=DEMAND_ID,
                assignment_id=ASSIGNMENT_ID,
            ),
        )
        for case in cases:
            with self.subTest(case=case), self.assertRaises(ValueError):
                case()

    def test_migration_is_marker_only_and_never_queries_target_tables(self) -> None:
        sql = MIGRATION.read_text(encoding="utf-8")
        required = (
            "iam_api.resolve_profile_self_authority_marker_v1",
            "iam_api.resolve_demand_owner_authority_marker_v1",
            "iam_api.resolve_demand_reviewer_authority_marker_v1",
            "profile_app",
            "demand_self",
            "demand_review",
            "SECURITY DEFINER",
            "OWNER TO schema_owner",
            "SET search_path = pg_catalog, iam",
            "REVOKE ALL ON FUNCTION",
            "sha256",
            "OPERATIONS_REVIEWER",
            "DEMAND_OWNER",
            "CREATOR",
        )
        for fragment in required:
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, sql)
        lowered = sql.lower()
        for forbidden in (
            "profile.creator_profiles",
            "profile.profile_versions",
            "demand.demands",
            "demand.demand_review_assignments",
            "execute format",
            "grant select on iam.",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, lowered)


class _Connections:
    def __init__(self, conninfo: str) -> None:
        self._conninfo = conninfo

    def checkout(self):
        return psycopg.connect(self._conninfo, autocommit=True)

    def release(self, connection) -> None:
        connection.close()

    def discard(self, connection) -> None:
        connection.close()


class AuthorityMarkerRealPostgresTest(unittest.TestCase):
    """TEST-PG-IAM-AUTHORITY-MARKER-002: real PostgreSQL 18 + FORCE RLS."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.postgres = TemporaryPostgres18().start()
        cls.catalog = MigrationCatalog.load(MIGRATION_ROOT)
        cls.contract_sources = IamContractSources(
            api_contract_bytes=(ROOT / "contracts/api/iam-v1.openapi.yaml").read_bytes(),
            event_contract_bytes=(
                ROOT / "contracts/events/iam-v1.schema.json"
            ).read_bytes(),
        )

    @classmethod
    def tearDownClass(cls) -> None:
        cls.postgres.stop()

    def setUp(self) -> None:
        self.database = self.postgres.create_database()
        report = IamMigrationRunner(
            driver=PsycopgMigrationDriver(
                settings=PsycopgMigrationSettings(
                    conninfo=self.postgres.conninfo(
                        database=self.database,
                        user="iam_migration_runner",
                    ),
                    application_name="desire-authority-marker-test",
                ),
                dbapi=psycopg,
            ),
            runner_version="authority-marker-test/1",
        ).run(catalog=self.catalog, contract_sources=self.contract_sources)
        self.assertEqual(
            report.applied_versions,
            tuple(item.descriptor.version for item in self.catalog.artifacts),
        )
        self.now = datetime.now(timezone.utc).replace(microsecond=0)
        with self._admin(autocommit=False) as connection:
            authority = seed_exact_demand_owner_iam_authority(
                connection,
                now=self.now,
            )
            self.owner_authority = authority
            self.creator_grant_id = self._seed_creator_role(connection)
        self.resolver = PsycopgAuthorityMarkerResolver(
            profile_connections=_Connections(
                self.postgres.conninfo(database=self.database, user="profile_app")
            ),
            demand_owner_connections=_Connections(
                self.postgres.conninfo(database=self.database, user="demand_self")
            ),
            demand_reviewer_connections=_Connections(
                self.postgres.conninfo(database=self.database, user="demand_review")
            ),
        )

    def tearDown(self) -> None:
        self.postgres.drop_database(self.database)

    def _admin(self, *, autocommit: bool = True):
        return psycopg.connect(
            self.postgres.admin_conninfo(database=self.database),
            autocommit=autocommit,
        )

    def _profile(self, *, operation: str = "CREATE_PROFILE", profile_id=PROFILE_ID):
        return ProfileSelfAuthorityMarkerRequest(
            actor_user_id=ACTOR_USER_ID,
            session_id=SESSION_ID,
            operation=operation,
            profile_id=profile_id,
        )

    def _owner(self, *, operation: str = "CREATE", demand_id=DEMAND_ID):
        return DemandOwnerAuthorityMarkerRequest(
            actor_user_id=ACTOR_USER_ID,
            session_id=SESSION_ID,
            organization_id=ORGANIZATION_ID,
            operation=operation,
            demand_id=demand_id,
        )

    def _reviewer(
        self,
        *,
        operation: str = "VERIFY",
        demand_id=DEMAND_ID,
        assignment_id=ASSIGNMENT_ID,
    ):
        return DemandReviewerAuthorityMarkerRequest(
            actor_user_id=REVIEWER_USER_ID,
            session_id=REVIEWER_SESSION_ID,
            organization_id=ORGANIZATION_ID,
            operation=operation,
            demand_id=demand_id,
            assignment_id=assignment_id,
        )

    def test_three_role_bound_apis_return_only_domain_separated_bytes(self) -> None:
        markers = (
            self.resolver.resolve_profile_self(self._profile()),
            self.resolver.resolve_demand_owner(self._owner()),
            self.resolver.resolve_demand_reviewer(self._reviewer()),
        )
        self.assertTrue(all(type(marker) is bytes for marker in markers))
        self.assertTrue(all(len(marker) == 32 for marker in markers))
        self.assertEqual(len(set(markers)), 3)

        changed = (
            self.resolver.resolve_profile_self(
                self._profile(operation="PUBLISH_PROFILE")
            ),
            self.resolver.resolve_profile_self(self._profile(profile_id=uuid4())),
            self.resolver.resolve_demand_owner(
                self._owner(operation="CREATE_VERSION")
            ),
            self.resolver.resolve_demand_owner(self._owner(demand_id=uuid4())),
            self.resolver.resolve_demand_reviewer(
                self._reviewer(operation="REQUEST_CHANGES")
            ),
            self.resolver.resolve_demand_reviewer(
                self._reviewer(assignment_id=uuid4())
            ),
        )
        # Profile v1's canonical lock marker intentionally represents the
        # account/policy graph only; operation and target are validated as
        # separate lock inputs. Demand v1 binds its operation/target IDs into
        # the canonical marker material.
        self.assertEqual(changed[0:2], (markers[0], markers[0]))
        self.assertEqual(
            len(set(markers + changed[2:])),
            len(markers + changed[2:]),
        )

    def test_resolved_markers_are_accepted_by_the_canonical_lock_programs(self) -> None:
        profile_marker = self.resolver.resolve_profile_self(self._profile())
        owner_marker = self.resolver.resolve_demand_owner(self._owner())
        reviewer_marker = self.resolver.resolve_demand_reviewer(self._reviewer())

        profile = self._lock_profile(self._profile(), profile_marker)
        owner = self._lock_owner(self._owner(), owner_marker)
        reviewer = self._lock_reviewer(self._reviewer(), reviewer_marker)

        self.assertIsNotNone(profile)
        self.assertEqual(profile[3:], (profile_marker, True))
        self.assertIsNotNone(owner)
        self.assertEqual(owner[-1], owner_marker)
        self.assertIsNotNone(reviewer)
        self.assertEqual(reviewer[-1], reviewer_marker)

    def test_canonical_marker_rejects_revocation_policy_drift_and_assignment_mismatch(self) -> None:
        stale_profile = self.resolver.resolve_profile_self(self._profile())
        stale_owner = self.resolver.resolve_demand_owner(self._owner())
        stale_reviewer = self.resolver.resolve_demand_reviewer(self._reviewer())

        with self._admin(autocommit=False) as connection:
            connection.execute(
                "UPDATE iam.user_role_grants SET revoked_at=%s,"
                "revocation_reason_code='TEST_REVOKED',aggregate_version=2 "
                "WHERE id=%s",
                (self.now, self.creator_grant_id),
            )
            connection.execute(
                "UPDATE iam.policy_bundles SET aggregate_version=aggregate_version+1,"
                "updated_at=%s WHERE id=%s",
                (self.now, self.owner_authority.policy_bundle_id),
            )

        self.assertIsNone(self._lock_profile(self._profile(), stale_profile))
        self.assertIsNone(self._lock_owner(self._owner(), stale_owner))
        self.assertIsNone(
            self._lock_reviewer(
                self._reviewer(assignment_id=uuid4()),
                stale_reviewer,
            )
        )

    def test_reviewer_marker_is_session_and_assignment_bound_not_membership_bound(self) -> None:
        with self._admin() as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT count(*) FROM iam.memberships WHERE user_id=%s",
                    (REVIEWER_USER_ID,),
                ).fetchone()[0],
                0,
            )
        marker = self.resolver.resolve_demand_reviewer(self._reviewer())
        self.assertEqual(self._lock_reviewer(self._reviewer(), marker)[-1], marker)

    def test_arbitrary_nonzero_object_ids_are_bound_not_looked_up(self) -> None:
        self.assertEqual(
            len(self.resolver.resolve_profile_self(self._profile(profile_id=uuid4()))),
            32,
        )
        self.assertEqual(
            len(self.resolver.resolve_demand_owner(self._owner(demand_id=uuid4()))),
            32,
        )
        self.assertEqual(
            len(
                self.resolver.resolve_demand_reviewer(
                    self._reviewer(demand_id=uuid4(), assignment_id=uuid4())
                )
            ),
            32,
        )
        with self._admin() as connection:
            self.assertIsNone(connection.execute("SELECT to_regnamespace('profile')").fetchone()[0])
            self.assertIsNone(connection.execute("SELECT to_regnamespace('demand')").fetchone()[0])

    def test_force_rls_definers_have_exact_owner_path_acl_and_no_table_grants(self) -> None:
        signatures = (
            (
                "profile_app",
                "iam_api.resolve_profile_self_authority_marker_v1(uuid,uuid,text,uuid)",
            ),
            (
                "demand_self",
                "iam_api.resolve_demand_owner_authority_marker_v1(uuid,uuid,uuid,text,uuid)",
            ),
            (
                "demand_review",
                "iam_api.resolve_demand_reviewer_authority_marker_v2(uuid,uuid,uuid,text,uuid,uuid)",
            ),
        )
        procedure_names = (
            "resolve_profile_self_authority_marker_v1",
            "resolve_demand_owner_authority_marker_v1",
            "resolve_demand_reviewer_authority_marker_v2",
        )
        with self._admin() as connection:
            procedures = connection.execute(
                "SELECT p.proname,r.rolname,p.prosecdef,p.provolatile,p.proparallel,"
                "p.proconfig FROM pg_catalog.pg_proc p "
                "JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace "
                "JOIN pg_catalog.pg_roles r ON r.oid=p.proowner "
                "WHERE n.nspname='iam_api' AND p.proname=ANY(%s) "
                "ORDER BY p.proname",
                (list(procedure_names),),
            ).fetchall()
            self.assertEqual(len(procedures), 3)
            self.assertTrue(
                all(
                    row[1:] == (
                        "schema_owner",
                        True,
                        "s",
                        "u",
                        ["search_path=pg_catalog, iam"],
                    )
                    for row in procedures
                )
            )
            for role, signature in signatures:
                self.assertTrue(
                    connection.execute(
                        "SELECT pg_catalog.has_function_privilege(%s,%s,'EXECUTE')",
                        (role, signature),
                    ).fetchone()[0]
                )
                for other, _other_signature in signatures:
                    if other != role:
                        self.assertFalse(
                            connection.execute(
                                "SELECT pg_catalog.has_function_privilege(%s,%s,'EXECUTE')",
                                (other, signature),
                            ).fetchone()[0]
                        )
            for role in ("profile_app", "demand_self", "demand_review"):
                for relation in (
                    "iam.users",
                    "iam.sessions",
                    "iam.memberships",
                    "iam.user_role_grants",
                    "iam.membership_role_grants",
                    "iam.platform_duty_grants",
                ):
                    self.assertFalse(
                        connection.execute(
                            "SELECT pg_catalog.has_table_privilege(%s,%s,'SELECT')",
                            (role, relation),
                        ).fetchone()[0]
                    )

    def test_inactive_authority_graphs_return_only_resource_not_found(self) -> None:
        cases = (
            (
                "creator-role",
                "UPDATE iam.user_role_grants SET revoked_at=%s,"
                "revocation_reason_code='TEST_REVOKED',aggregate_version=2 "
                "WHERE id=%s",
                (self.now, self.creator_grant_id),
                self.resolver.resolve_profile_self,
                self._profile(),
            ),
        )
        for label, statement, parameters, method, request in cases:
            with self.subTest(graph=label):
                with self._admin(autocommit=False) as connection:
                    connection.execute(statement, parameters)
                    connection.commit()
                with self.assertRaises(IamError) as raised:
                    method(request)
                self.assertEqual(raised.exception.code, "RESOURCE_NOT_FOUND")

        with self._admin(autocommit=False) as connection:
            connection.execute(
                "UPDATE iam.memberships SET status='SUSPENDED',aggregate_version=2,"
                "updated_at=%s WHERE organization_id=%s AND user_id=%s",
                (self.now, ORGANIZATION_ID, ACTOR_USER_ID),
            )
        with self.assertRaises(IamError) as raised:
            self.resolver.resolve_demand_owner(self._owner())
        self.assertEqual(raised.exception.code, "RESOURCE_NOT_FOUND")

    def test_session_deadline_generation_and_exact_guc_are_revalidated(self) -> None:
        with self._admin(autocommit=False) as connection:
            connection.execute(
                "UPDATE iam.sessions SET status='EXPIRED',revoked_at=%s,"
                "revocation_reason_code='TEST_EXPIRED',aggregate_version=2,"
                "updated_at=%s WHERE id=%s",
                (self.now, self.now, REVIEWER_SESSION_ID),
            )
            connection.execute(
                "UPDATE iam.session_families SET status='REVOKED',revoked_at=%s,"
                "revocation_reason_code='TEST_REVOKED',aggregate_version=2,"
                "updated_at=%s WHERE id=%s",
                (self.now, self.now, REVIEWER_SESSION_FAMILY_ID),
            )
        with self.assertRaises(IamError) as raised:
            self.resolver.resolve_demand_reviewer(self._reviewer())
        self.assertEqual(raised.exception.code, "RESOURCE_NOT_FOUND")

        with psycopg.connect(
            self.postgres.conninfo(database=self.database, user="demand_self"),
            autocommit=False,
        ) as connection:
            for name, value in (
                ("app.scope_kind", "DEMAND_REVIEW"),
                ("app.actor_id", str(REVIEWER_USER_ID)),
                ("app.session_id", str(REVIEWER_SESSION_ID)),
                ("app.organization_id", str(ORGANIZATION_ID)),
                ("app.operation", "VERIFY"),
                ("app.demand_id", str(DEMAND_ID)),
                ("app.assignment_id", str(ASSIGNMENT_ID)),
            ):
                connection.execute(
                    "SELECT pg_catalog.set_config(%s,%s,true)",
                    (name, value),
                )
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                connection.execute(
                    "SELECT * FROM iam_api.resolve_demand_reviewer_authority_marker_v1("
                    "%s,%s,%s,%s,%s,%s)",
                    (
                        REVIEWER_USER_ID,
                        REVIEWER_SESSION_ID,
                        ORGANIZATION_ID,
                        "VERIFY",
                        DEMAND_ID,
                        ASSIGNMENT_ID,
                    ),
                ).fetchall()

    def _install_context(self, connection, values) -> None:
        for name, value in values:
            connection.execute(
                "SELECT pg_catalog.set_config(%s,%s,true)",
                (name, str(value)),
            )

    def _lock_profile(self, request, marker: bytes):
        with psycopg.connect(
            self.postgres.conninfo(database=self.database, user="profile_app"),
            autocommit=False,
        ) as connection:
            self._install_context(
                connection,
                (
                    ("app.scope_kind", "PROFILE_SELF"),
                    ("app.actor_user_id", request.actor_user_id),
                    ("app.session_id", request.session_id),
                    ("app.operation", request.operation),
                    ("app.profile_id", request.profile_id),
                ),
            )
            return connection.execute(
                "SELECT * FROM iam_api.lock_creator_profile_self_v1(%s,%s,%s,%s)",
                (
                    request.actor_user_id,
                    request.session_id,
                    request.operation,
                    marker,
                ),
            ).fetchone()

    def _lock_owner(self, request, marker: bytes):
        with psycopg.connect(
            self.postgres.conninfo(database=self.database, user="demand_self"),
            autocommit=False,
        ) as connection:
            self._install_context(
                connection,
                (
                    ("app.scope_kind", "DEMAND_OWNER"),
                    ("app.actor_id", request.actor_user_id),
                    ("app.session_id", request.session_id),
                    ("app.organization_id", request.organization_id),
                    ("app.operation", request.operation),
                    ("app.demand_id", request.demand_id),
                ),
            )
            return connection.execute(
                "SELECT * FROM iam_api.lock_demand_owner_authority_v1("
                "%s,%s,%s,%s,%s,%s)",
                (
                    request.actor_user_id,
                    request.session_id,
                    request.organization_id,
                    request.operation,
                    request.demand_id,
                    marker,
                ),
            ).fetchone()

    def _lock_reviewer(self, request, marker: bytes):
        with psycopg.connect(
            self.postgres.conninfo(database=self.database, user="demand_review"),
            autocommit=False,
        ) as connection:
            self._install_context(
                connection,
                (
                    ("app.scope_kind", "DEMAND_REVIEW"),
                    ("app.actor_id", request.actor_user_id),
                    ("app.session_id", request.session_id),
                    ("app.organization_id", request.organization_id),
                    ("app.operation", request.operation),
                    ("app.demand_id", request.demand_id),
                    ("app.assignment_id", request.assignment_id),
                ),
            )
            return connection.execute(
                "SELECT * FROM iam_api.lock_demand_reviewer_authority_v2("
                "%s,%s,%s,%s,%s,%s,%s)",
                (
                    request.actor_user_id,
                    request.session_id,
                    request.organization_id,
                    request.demand_id,
                    request.assignment_id,
                    request.operation,
                    marker,
                ),
            ).fetchone()

    def _seed_creator_role(self, connection) -> UUID:
        selector_digest = hashlib.sha256(b"authority-marker-creator-selector").digest()
        bundle_id = uuid4()
        document_id = uuid4()
        publication_command_id = uuid4()
        invitation_id = uuid4()
        creator_grant_id = uuid4()
        contact_id = connection.execute(
            "SELECT id FROM iam.contact_points WHERE user_id=%s ORDER BY id LIMIT 1",
            (ACTOR_USER_ID,),
        ).fetchone()[0]
        created_at = self.now - timedelta(days=10)
        accepted_at = self.now - timedelta(days=9)
        connection.execute(
            "INSERT INTO iam.policy_selectors (selector_digest,"
            "canonicalization_version,access_purpose,scope_type,target_role,"
            "jurisdiction,locale,current_bundle_id,aggregate_version,created_at,"
            "updated_at) VALUES (%s,'policy-selector-json-v1',"
            "'CREATOR_ENROLLMENT','USER_ROLE','CREATOR','CN','zh-CN',NULL,1,%s,%s)",
            (selector_digest, created_at, created_at),
        )
        connection.execute(
            "INSERT INTO iam.policy_documents (id,kind,locale,semantic_version,"
            "canonical_body,content_sha256,legal_effect,jurisdiction,status,"
            "effective_at,superseded_by_document_id,publication_command_id,"
            "created_at,updated_at) VALUES (%s,'TERMS','zh-CN','1.0.0',%s,%s,"
            "'CONTRACT_ACCEPTANCE','CN','ACTIVE',%s,NULL,%s,%s,%s)",
            (
                document_id,
                "Reviewed authority marker Creator terms.",
                hashlib.sha256(b"authority-marker-creator-terms").digest(),
                accepted_at,
                publication_command_id,
                created_at,
                accepted_at,
            ),
        )
        connection.execute(
            "INSERT INTO iam.policy_bundles (id,selector_digest,status,effective_at,"
            "effective_until,superseded_by_bundle_id,release_manifest_sha256,"
            "release_signature,release_signing_key_id,publication_command_id,"
            "aggregate_version,created_at,updated_at) VALUES "
            "(%s,%s,'DRAFT',NULL,NULL,NULL,%s,%s,'authority-marker-test-v1',"
            "%s,1,%s,%s)",
            (
                bundle_id,
                selector_digest,
                hashlib.sha256(bundle_id.bytes).digest(),
                b"reviewed-authority-marker-signature",
                uuid4(),
                created_at,
                created_at,
            ),
        )
        connection.execute(
            "INSERT INTO iam.policy_bundle_documents "
            "(bundle_id,document_id,position,required) VALUES (%s,%s,1,true)",
            (bundle_id, document_id),
        )
        connection.execute(
            "INSERT INTO iam.access_invitations (id,purpose,organization_id,"
            "target_scope,target_role,is_initial_admin,recipient_contact_id,"
            "masked_recipient_label,policy_selector_digest,issued_policy_bundle_id,"
            "status,expires_at,issuer_kind,issuer_user_id,token_nonce,token_key_id,"
            "accepted_by_user_id,terminal_at,terminal_reason_code,aggregate_version,"
            "created_at,updated_at) VALUES (%s,'CREATOR_ENROLLMENT',NULL,'USER',"
            "'CREATOR',false,%s,'a***@example.invalid',%s,%s,'ACCEPTED',%s,"
            "'SYSTEM',NULL,%s,'authority-marker-token-v1',%s,%s,NULL,2,%s,%s)",
            (
                invitation_id,
                contact_id,
                selector_digest,
                bundle_id,
                self.now + timedelta(days=30),
                hashlib.sha256(invitation_id.bytes).digest(),
                ACTOR_USER_ID,
                accepted_at,
                created_at,
                accepted_at,
            ),
        )
        connection.execute(
            "INSERT INTO iam.user_role_grants (id,user_id,role_code,"
            "source_invitation_id,policy_selector_digest,granted_by_kind,"
            "granted_by_id,granted_at,revoked_at,revocation_reason_code,"
            "aggregate_version) VALUES (%s,%s,'CREATOR',%s,%s,'SYSTEM',%s,%s,"
            "NULL,NULL,1)",
            (
                creator_grant_id,
                ACTOR_USER_ID,
                invitation_id,
                selector_digest,
                uuid4(),
                accepted_at,
            ),
        )
        connection.execute(
            "UPDATE iam.policy_bundles SET status='ACTIVE',effective_at=%s,"
            "aggregate_version=2,updated_at=%s WHERE id=%s",
            (created_at, accepted_at, bundle_id),
        )
        connection.execute(
            "UPDATE iam.policy_selectors SET current_bundle_id=%s,"
            "aggregate_version=2,updated_at=%s WHERE selector_digest=%s",
            (bundle_id, accepted_at, selector_digest),
        )
        session = connection.execute(
            "SELECT auth_transaction_id,auth_time,acr_code,amr_codes "
            "FROM iam.sessions WHERE id=%s",
            (SESSION_ID,),
        ).fetchone()
        policy_accepted_at = self.now - timedelta(minutes=30)
        connection.execute(
            "INSERT INTO iam.policy_acceptances (id,user_id,document_id,"
            "content_sha256,bundle_id,accepted_at,session_id,auth_transaction_id,"
            "auth_time,acr_code,amr_codes,source_action,command_id,correlation_id,"
            "aggregate_version,created_at) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,"
            "%s,%s,'POLICY_ACCEPT',%s,%s,1,%s)",
            (
                uuid4(),
                ACTOR_USER_ID,
                document_id,
                hashlib.sha256(b"authority-marker-creator-terms").digest(),
                bundle_id,
                policy_accepted_at,
                SESSION_ID,
                session[0],
                session[1],
                session[2],
                session[3],
                uuid4(),
                uuid4(),
                policy_accepted_at,
            ),
        )
        return creator_grant_id

if __name__ == "__main__":
    unittest.main()
