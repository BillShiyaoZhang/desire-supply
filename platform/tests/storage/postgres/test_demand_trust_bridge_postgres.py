"""Real PostgreSQL 18 acceptance for the Demand-to-Trust bridge."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
import unittest
from uuid import UUID

import psycopg
from psycopg.types.json import Jsonb

from desire_platform.demand.adapters.postgres import DemandPostgresOperation
from desire_platform.demand.adapters.postgres.migrations import (
    DEMAND_REQUIRED_IAM_SCHEMA_VERSION,
    DEMAND_SCHEMA_HEAD_VERSION,
    DemandContractSources,
    DemandMigrationCatalog,
    DemandMigrationRunner,
    DemandMigrationSettings,
    PsycopgDemandMigrationDriver,
)
from desire_platform.identity_access.adapters.postgres.migrations import (
    IamContractSources,
    IamMigrationRunner,
    MigrationCatalog,
    PsycopgMigrationDriver,
    PsycopgMigrationSettings,
)
from desire_platform.trust_safety.adapters.postgres import (
    PsycopgDemandTrustTarget,
)
from desire_platform.trust_safety.ports.commands import (
    TrustOfficerAuthority,
    TrustReporterAuthority,
    TrustTargetUnavailableError,
)
from tests.storage.postgres.postgres18_harness import TemporaryPostgres18
from tests.support.demand_postgres_builders import (
    ACTOR_USER_ID,
    ASSIGNMENT_ID,
    DEMAND_ID,
    DEMAND_VERSION_ID,
    MEMBERSHIP_ID,
    MEMBERSHIP_ROLE_GRANT_ID,
    ORGANIZATION_ID,
    SESSION_ID,
    SUBMISSION_ID,
    TrackingDemandConnectionSource,
    reset_demand_postgres_state,
    seed_demand_operation_graph,
    seed_exact_demand_owner_iam_authority,
)


PLATFORM_ROOT = Path(__file__).resolve().parents[3]
IAM_ROOT = (
    PLATFORM_ROOT
    / "src/desire_platform/identity_access/adapters/postgres/migrations"
)
DEMAND_ROOT = PLATFORM_ROOT / "src/desire_platform/demand/adapters/postgres/migrations"

OFFICER_USER_ID = UUID("a1000000-0000-4000-8000-000000000001")
OFFICER_SESSION_ID = UUID("a2000000-0000-4000-8000-000000000001")
OFFICER_FAMILY_ID = UUID("a3000000-0000-4000-8000-000000000001")
OFFICER_AUTH_TRANSACTION_ID = UUID("a4000000-0000-4000-8000-000000000001")
OFFICER_DUTY_GRANT_ID = UUID("a5000000-0000-4000-8000-000000000001")
OTHER_ORGANIZATION_ID = UUID("b1000000-0000-4000-8000-000000000001")
FOREIGN_DEMAND_ID = UUID("b2000000-0000-4000-8000-000000000001")
FOREIGN_VERSION_ID = UUID("b3000000-0000-4000-8000-000000000001")
OTHER_OWNER_DEMAND_ID = UUID("b2000000-0000-4000-8000-000000000002")
OTHER_OWNER_VERSION_ID = UUID("b3000000-0000-4000-8000-000000000002")
STALE_VERSION_ID = UUID("b3000000-0000-4000-8000-000000000003")
OFFICER_PRIOR_ASSIGNMENT_ID = UUID("b4000000-0000-4000-8000-000000000001")


def _digest(label: str) -> bytes:
    return hashlib.sha256(label.encode("utf-8")).digest()


def _seed_trust_officer(connection, *, now: datetime) -> None:
    created_at = now - timedelta(days=2)
    auth_time = now - timedelta(hours=2)
    session_created_at = now - timedelta(hours=1)
    connection.execute(
        "INSERT INTO iam.users ("
        "id,status,display_handle,aggregate_version,created_at,updated_at) "
        "VALUES (%s,'ACTIVE','demand8_trust_officer',1,%s,%s)",
        (OFFICER_USER_ID, created_at, created_at),
    )
    connection.execute(
        "INSERT INTO iam.auth_transactions ("
        "id,status,purpose,attempt,protocol_version,browser_binding_digest,"
        "browser_binding_key_id,initiating_session_id,initiating_user_id,"
        "expected_user_id,invitation_id,invitation_version,"
        "expected_contact_point_id,state_digest,state_digest_key_id,"
        "nonce_digest,nonce_digest_key_id,pkce_verifier_ciphertext,"
        "pkce_encryption_key_id,pkce_encryption_algorithm,redirect_uri,"
        "provider_error_class,deadline,succeeded_at,created_at,updated_at) "
        "VALUES (%s,'SUCCEEDED','LOGIN',1,1,%s,'browser-hmac-v1',"
        "NULL,NULL,NULL,NULL,NULL,NULL,%s,'state-hmac-v1',%s,'nonce-hmac-v1',"
        "%s,'pkce-aead-v1','AES_256_GCM_V1',"
        "'https://app.example.test/v1/auth/oidc/callback',NULL,%s,%s,%s,%s)",
        (
            OFFICER_AUTH_TRANSACTION_ID,
            _digest("demand8-officer-browser"),
            _digest("demand8-officer-state"),
            _digest("demand8-officer-nonce"),
            b"reviewed-demand8-officer-pkce",
            now + timedelta(days=1),
            auth_time,
            created_at,
            auth_time,
        ),
    )
    connection.execute(
        "INSERT INTO iam.session_families ("
        "id,user_id,status,current_generation,revoked_at,"
        "revocation_reason_code,aggregate_version,created_at,updated_at) "
        "VALUES (%s,%s,'ACTIVE',1,NULL,NULL,1,%s,%s)",
        (
            OFFICER_FAMILY_ID,
            OFFICER_USER_ID,
            session_created_at,
            session_created_at,
        ),
    )
    connection.execute(
        "INSERT INTO iam.sessions ("
        "id,user_id,family_id,generation,predecessor_session_id,handle_digest,"
        "handle_digest_key_id,csrf_salt,csrf_key_id,csrf_digest,"
        "verified_contact_point_id,verified_at,verified_for_invitation_id,"
        "auth_transaction_id,auth_time,acr_code,amr_codes,created_at,"
        "last_activity_at,idle_expires_at,absolute_expires_at,updated_at,"
        "device_label,status,rotation_reason,revoked_at,"
        "revocation_reason_code,aggregate_version) VALUES ("
        "%s,%s,%s,1,NULL,%s,'session-hmac-v1',%s,'csrf-hmac-v1',%s,"
        "NULL,NULL,NULL,%s,%s,'urn:desire:acr:mfa',ARRAY['otp']::text[],"
        "%s,%s,%s,%s,%s,'Browser','ACTIVE','LOGIN',NULL,NULL,1)",
        (
            OFFICER_SESSION_ID,
            OFFICER_USER_ID,
            OFFICER_FAMILY_ID,
            _digest("demand8-officer-session"),
            _digest("demand8-officer-csrf-salt"),
            _digest("demand8-officer-csrf"),
            OFFICER_AUTH_TRANSACTION_ID,
            auth_time,
            session_created_at,
            now - timedelta(seconds=1),
            now + timedelta(days=1),
            now + timedelta(days=30),
            now - timedelta(seconds=1),
        ),
    )
    connection.execute(
        "INSERT INTO iam.platform_duty_grants ("
        "id,user_id,duty_code,granted_by_kind,granted_by_id,granted_at,"
        "expires_at,revoked_at,revocation_reason_code,aggregate_version,"
        "created_at,updated_at) VALUES ("
        "%s,%s,'TRUST_OFFICER','SYSTEM',%s,%s,NULL,NULL,NULL,1,%s,%s)",
        (
            OFFICER_DUTY_GRANT_ID,
            OFFICER_USER_ID,
            ACTOR_USER_ID,
            created_at,
            created_at,
            created_at,
        ),
    )


class RealPostgres18DemandTrustBridgeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.postgres = TemporaryPostgres18().start()
        cls.database = cls.postgres.create_database()
        try:
            cls._migrate()
            now = datetime.now(timezone.utc).replace(microsecond=0)
            with cls._admin(autocommit=False) as connection:
                cls.owner = seed_exact_demand_owner_iam_authority(
                    connection,
                    now=now,
                )
                _seed_trust_officer(connection, now=now)
            cls.reporter_marker = cls._reporter_marker()
            cls.officer_markers = {
                operation: cls._officer_marker(operation)
                for operation in ("CLAIM_CASE", "CLAIM_HOLD_RELEASE")
            }
        except BaseException:
            cls.postgres.drop_database(cls.database)
            cls.postgres.stop()
            raise

    @classmethod
    def tearDownClass(cls) -> None:
        cls.postgres.drop_database(cls.database)
        cls.postgres.stop()

    def setUp(self) -> None:
        self.sources: list[TrackingDemandConnectionSource] = []
        with self._admin(autocommit=False) as connection:
            reset_demand_postgres_state(connection)
            seed_demand_operation_graph(
                connection,
                DemandPostgresOperation.REQUEST_CHANGES,
            )

    def tearDown(self) -> None:
        for source in self.sources:
            source.close()

    @classmethod
    def _migrate(cls) -> None:
        iam_catalog = MigrationCatalog.load(IAM_ROOT)
        iam_report = IamMigrationRunner(
            driver=PsycopgMigrationDriver(
                settings=PsycopgMigrationSettings(
                    conninfo=cls.postgres.conninfo(
                        database=cls.database,
                        user="iam_migration_runner",
                    ),
                    application_name="demand8-trust-iam",
                ),
                dbapi=psycopg,
            ),
            runner_version="demand8-trust/1",
        ).run(
            catalog=iam_catalog,
            contract_sources=IamContractSources(
                api_contract_bytes=(
                    PLATFORM_ROOT / "contracts/api/iam-v1.openapi.yaml"
                ).read_bytes(),
                event_contract_bytes=(
                    PLATFORM_ROOT / "contracts/events/iam-v1.schema.json"
                ).read_bytes(),
            ),
        )
        demand_catalog = DemandMigrationCatalog.load(DEMAND_ROOT)
        demand_report = DemandMigrationRunner(
            driver=PsycopgDemandMigrationDriver(
                settings=DemandMigrationSettings(
                    conninfo=cls.postgres.conninfo(
                        database=cls.database,
                        user="demand_migration_runner",
                    ),
                    application_name="demand8-trust-demand",
                ),
                dbapi=psycopg,
            ),
            runner_version="demand8-trust/1",
        ).run(
            catalog=demand_catalog,
            contract_sources=DemandContractSources(
                api_contract_bytes=(
                    PLATFORM_ROOT / "contracts/api/demand-v1.openapi.yaml"
                ).read_bytes(),
                event_contract_bytes=(
                    PLATFORM_ROOT / "contracts/events/demand-v1.schema.json"
                ).read_bytes(),
                content_contract_bytes=(
                    PLATFORM_ROOT
                    / "contracts/domain/demand-content-v1.schema.json"
                ).read_bytes(),
            ),
        )
        assert iam_report.applied_versions == tuple(
            item.descriptor.version for item in iam_catalog.artifacts
        )
        assert demand_report.applied_versions == tuple(
            item.descriptor.version for item in demand_catalog.artifacts
        )

    @classmethod
    def _admin(cls, *, autocommit: bool = True):
        return psycopg.connect(
            cls.postgres.admin_conninfo(database=cls.database),
            autocommit=autocommit,
        )

    @classmethod
    def _reporter_marker(cls) -> bytes:
        with cls._admin() as connection:
            row = connection.execute(
                "SELECT family.id,family.aggregate_version,"
                "family.current_generation,active_session.aggregate_version,"
                "actor.aggregate_version,organization.aggregate_version,"
                "membership.aggregate_version,owner_grant.policy_selector_digest,"
                "selector.aggregate_version,current_bundle.id,"
                "current_bundle.aggregate_version "
                "FROM iam.users AS actor "
                "JOIN iam.sessions AS active_session ON active_session.id=%s "
                "AND active_session.user_id=actor.id "
                "JOIN iam.session_families AS family "
                "ON family.id=active_session.family_id "
                "JOIN iam.organizations AS organization ON organization.id=%s "
                "JOIN iam.memberships AS membership ON membership.id=%s "
                "JOIN iam.membership_role_grants AS owner_grant "
                "ON owner_grant.id=%s "
                "JOIN iam.policy_selectors AS selector "
                "ON selector.selector_digest=owner_grant.policy_selector_digest "
                "JOIN iam.policy_bundles AS current_bundle "
                "ON current_bundle.id=selector.current_bundle_id "
                "WHERE actor.id=%s",
                (
                    SESSION_ID,
                    ORGANIZATION_ID,
                    MEMBERSHIP_ID,
                    MEMBERSHIP_ROLE_GRANT_ID,
                    ACTOR_USER_ID,
                ),
            ).fetchone()
        material = "\x1f".join(
            (
                "desire:iam:trust-reporter-authority:v1",
                "SUBMIT_REPORT",
                str(ACTOR_USER_ID),
                str(SESSION_ID),
                str(ORGANIZATION_ID),
                str(row[0]),
                str(row[1]),
                str(row[2]),
                str(row[3]),
                str(row[4]),
                str(row[5]),
                str(MEMBERSHIP_ID),
                str(row[6]),
                str(MEMBERSHIP_ROLE_GRANT_ID),
                "1",
                row[7].hex(),
                str(row[8]),
                str(row[9]),
                str(row[10]),
                "true",
            )
        )
        return hashlib.sha256(material.encode("utf-8")).digest()

    @classmethod
    def _officer_marker(cls, operation: str) -> bytes:
        material = "\x1f".join(
            (
                "desire:iam:trust-officer-authority:v1",
                operation,
                str(OFFICER_USER_ID),
                str(OFFICER_SESSION_ID),
                str(OFFICER_FAMILY_ID),
                "1",
                "1",
                "1",
                "1",
                "1",
                str(OFFICER_DUTY_GRANT_ID),
                "1",
                "none",
            )
        )
        return hashlib.sha256(material.encode("utf-8")).digest()

    def _source(self, role: str) -> TrackingDemandConnectionSource:
        source = TrackingDemandConnectionSource(
            self.postgres.conninfo(database=self.database, user=role)
        )
        self.sources.append(source)
        return source

    def _adapter(self) -> PsycopgDemandTrustTarget:
        return PsycopgDemandTrustTarget(
            reporter_connections=self._source("trust_self"),
            officer_connections=self._source("trust_officer"),
        )

    @classmethod
    def _reporter(cls) -> TrustReporterAuthority:
        return TrustReporterAuthority(
            actor_user_id=str(ACTOR_USER_ID),
            session_id=str(SESSION_ID),
            organization_id=str(ORGANIZATION_ID),
            user_status="ACTIVE",
            session_status="ACTIVE",
            session_family_status="ACTIVE",
            organization_status="ACTIVE",
            membership_id=str(MEMBERSHIP_ID),
            membership_status="ACTIVE",
            membership_role_grant_id=str(MEMBERSHIP_ROLE_GRANT_ID),
            membership_role_grant_version=1,
            role_code="DEMAND_OWNER",
            policy_requirements_satisfied=True,
            authority_marker_sha256=cls.reporter_marker.hex(),
        )

    @classmethod
    def _officer(cls, operation: str = "CLAIM_CASE") -> TrustOfficerAuthority:
        return TrustOfficerAuthority(
            actor_user_id=str(OFFICER_USER_ID),
            session_id=str(OFFICER_SESSION_ID),
            user_status="ACTIVE",
            session_status="ACTIVE",
            session_family_status="ACTIVE",
            duty_grant_id=str(OFFICER_DUTY_GRANT_ID),
            duty_grant_version=1,
            duty_code="TRUST_OFFICER",
            authority_marker_sha256=cls.officer_markers[operation].hex(),
        )

    def test_owner_report_target_is_exact_current_immutable_version(self) -> None:
        target = self._adapter().resolve_report_target(
            reporter_authority=self._reporter(),
            demand_id=str(DEMAND_ID),
            demand_version_id=str(DEMAND_VERSION_ID),
        )
        with self._admin() as connection:
            expected = connection.execute(
                "SELECT root.organization_id,root.current_version_id,"
                "version_row.version_no,root.aggregate_version,root.status,"
                "version_row.content_sha256,root.creator_user_id,root.expires_at "
                "FROM demand.demands AS root "
                "JOIN demand.demand_versions AS version_row "
                "ON version_row.id=root.current_version_id "
                "WHERE root.id=%s",
                (DEMAND_ID,),
            ).fetchone()
        self.assertEqual(
            (
                target.organization_id,
                target.demand_version_id,
                target.demand_version_no,
                target.demand_aggregate_version,
                target.demand_status,
                target.content_sha256,
                target.owner_user_id,
                target.reportable_until,
            ),
            (
                str(expected[0]),
                str(expected[1]),
                expected[2],
                expected[3],
                expected[4],
                expected[5].hex(),
                str(expected[6]),
                expected[7],
            ),
        )
        self.assertEqual(len(bytes.fromhex(target.reporter_party_marker_sha256)), 32)
        self.assertEqual(len(bytes.fromhex(target.target_marker_sha256)), 32)

    def test_missing_cross_org_non_owner_and_terminal_are_one_404_shape(self) -> None:
        with self._admin(autocommit=False) as connection:
            self._insert_other_target(
                connection,
                organization_id=OTHER_ORGANIZATION_ID,
                demand_id=FOREIGN_DEMAND_ID,
                version_id=FOREIGN_VERSION_ID,
                creator_user_id=ACTOR_USER_ID,
                label="cross-org",
            )
            self._insert_other_target(
                connection,
                organization_id=ORGANIZATION_ID,
                demand_id=OTHER_OWNER_DEMAND_ID,
                version_id=OTHER_OWNER_VERSION_ID,
                creator_user_id=OFFICER_USER_ID,
                label="other-owner",
            )
        hidden_coordinates = (
            (
                UUID("b2000000-0000-4000-8000-000000000099"),
                STALE_VERSION_ID,
            ),
            (FOREIGN_DEMAND_ID, FOREIGN_VERSION_ID),
            (OTHER_OWNER_DEMAND_ID, OTHER_OWNER_VERSION_ID),
            (DEMAND_ID, STALE_VERSION_ID),
        )
        hidden = tuple(
            self._adapter().resolve_report_target(
                reporter_authority=self._reporter(),
                demand_id=str(demand_id),
                demand_version_id=str(version_id),
            )
            for demand_id, version_id in hidden_coordinates
        )
        self.assertEqual(
            tuple(item.demand_status for item in hidden),
            ("TARGET_NOT_FOUND",) * 4,
        )
        self.assertEqual(
            tuple(item.reportable_until for item in hidden),
            (datetime(1970, 1, 1, tzinfo=timezone.utc),) * 4,
        )

        with self._admin(autocommit=False) as connection:
            now = datetime.now(timezone.utc)
            connection.execute(
                "UPDATE demand.demands SET status='CANCELLED',"
                "aggregate_version=aggregate_version+1,terminal_at=%s,"
                "terminal_reason_code='OWNER_WITHDREW',updated_at=%s "
                "WHERE id=%s",
                (now, now, DEMAND_ID),
            )
        terminal = self._adapter().resolve_report_target(
            reporter_authority=self._reporter(),
            demand_id=str(DEMAND_ID),
            demand_version_id=str(DEMAND_VERSION_ID),
        )
        self.assertEqual(terminal.demand_status, "TARGET_NOT_FOUND")

    def test_officer_conflict_is_boolean_and_stale_version_fails_closed(self) -> None:
        conflict = self._adapter().check_officer_conflict(
            officer_authority=self._officer(),
            operation="CLAIM_CASE",
            organization_id=str(ORGANIZATION_ID),
            demand_id=str(DEMAND_ID),
            demand_version_id=str(DEMAND_VERSION_ID),
        )
        self.assertTrue(conflict.conflict_free)
        self.assertEqual(
            conflict.valid_until - conflict.evaluated_at,
            timedelta(minutes=5),
        )

        with self._admin(autocommit=False) as connection:
            now = datetime.now(timezone.utc)
            connection.execute(
                "INSERT INTO demand.demand_review_assignments ("
                "id,organization_id,demand_id,submission_id,demand_version_id,"
                "reviewer_user_id,duty_grant_id,duty_grant_version,purpose_code,"
                "conflict_attestation_sha256,authority_marker_sha256,status,"
                "expires_at,aggregate_version,created_at,completed_at) VALUES ("
                "%s,%s,%s,%s,%s,%s,%s,1,'DEMAND_REVIEW',%s,%s,'COMPLETED',"
                "%s,1,%s,%s)",
                (
                    OFFICER_PRIOR_ASSIGNMENT_ID,
                    ORGANIZATION_ID,
                    DEMAND_ID,
                    SUBMISSION_ID,
                    DEMAND_VERSION_ID,
                    OFFICER_USER_ID,
                    OFFICER_DUTY_GRANT_ID,
                    _digest("demand8-officer-prior-conflict"),
                    _digest("demand8-officer-prior-authority"),
                    now + timedelta(days=1),
                    now - timedelta(minutes=2),
                    now - timedelta(minutes=1),
                ),
            )
        conflicted = self._adapter().check_officer_conflict(
            officer_authority=self._officer(),
            operation="CLAIM_CASE",
            organization_id=str(ORGANIZATION_ID),
            demand_id=str(DEMAND_ID),
            demand_version_id=str(DEMAND_VERSION_ID),
        )
        self.assertFalse(conflicted.conflict_free)
        self.assertNotEqual(
            conflict.conflict_attestation_sha256,
            conflicted.conflict_attestation_sha256,
        )

        with self.assertRaises(TrustTargetUnavailableError):
            self._adapter().check_officer_conflict(
                officer_authority=self._officer(),
                operation="CLAIM_CASE",
                organization_id=str(ORGANIZATION_ID),
                demand_id=str(DEMAND_ID),
                demand_version_id=str(STALE_VERSION_ID),
            )

    def test_hold_release_conflict_requires_its_independent_authority_marker(
        self,
    ) -> None:
        conflict = self._adapter().check_officer_conflict(
            officer_authority=self._officer("CLAIM_HOLD_RELEASE"),
            operation="CLAIM_HOLD_RELEASE",
            organization_id=str(ORGANIZATION_ID),
            demand_id=str(DEMAND_ID),
            demand_version_id=str(DEMAND_VERSION_ID),
        )
        self.assertTrue(conflict.conflict_free)

        with self.assertRaises(TrustTargetUnavailableError):
            self._adapter().check_officer_conflict(
                officer_authority=self._officer("CLAIM_CASE"),
                operation="CLAIM_HOLD_RELEASE",
                organization_id=str(ORGANIZATION_ID),
                demand_id=str(DEMAND_ID),
                demand_version_id=str(DEMAND_VERSION_ID),
            )

    def test_wrong_marker_and_base_table_acl_fail_closed(self) -> None:
        wrong = replace(
            self._reporter(),
            authority_marker_sha256="ff" * 32,
        )
        with self.assertRaises(TrustTargetUnavailableError):
            self._adapter().resolve_report_target(
                reporter_authority=wrong,
                demand_id=str(DEMAND_ID),
                demand_version_id=str(DEMAND_VERSION_ID),
            )

        for role, forbidden_function in (
            (
                "trust_self",
                "demand_api.resolve_trust_officer_conflict_v1("
                "uuid,uuid,text,uuid,bigint,uuid,uuid,uuid,bytea)",
            ),
            (
                "trust_officer",
                "demand_api.resolve_trust_report_target_v1("
                "uuid,uuid,uuid,uuid,uuid,bigint,uuid,uuid,bytea)",
            ),
        ):
            with self.subTest(role=role):
                with psycopg.connect(
                    self.postgres.conninfo(database=self.database, user=role),
                    autocommit=True,
                ) as connection:
                    compatibility = connection.execute(
                        "SELECT schema_head_version "
                        "FROM demand.schema_compatibility"
                    ).fetchone()
                    self.assertEqual(
                        compatibility,
                        (DEMAND_SCHEMA_HEAD_VERSION,),
                    )
                    with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                        connection.execute("SELECT id FROM demand.demands")
                    executable = connection.execute(
                        "SELECT pg_catalog.has_function_privilege("
                        "current_user,%s,'EXECUTE')",
                        (forbidden_function,),
                    ).fetchone()[0]
                    self.assertFalse(executable)

    def test_trust_runner_reads_one_pinned_demand_dependency_digest(self) -> None:
        api_digest = hashlib.sha256(
            (PLATFORM_ROOT / "contracts/api/demand-v1.openapi.yaml").read_bytes()
        ).digest()
        event_digest = hashlib.sha256(
            (PLATFORM_ROOT / "contracts/events/demand-v1.schema.json").read_bytes()
        ).digest()
        content_digest = hashlib.sha256(
            (
                PLATFORM_ROOT
                / "contracts/domain/demand-content-v1.schema.json"
            ).read_bytes()
        ).digest()
        manifest_digest = hashlib.sha256(
            (DEMAND_ROOT / "manifest.json").read_bytes()
        ).digest()
        dependency_digest = hashlib.sha256(
            "\x1f".join(
                (
                    "desire:demand:trust-schema-dependency:v1",
                    str(DEMAND_SCHEMA_HEAD_VERSION),
                    str(DEMAND_SCHEMA_HEAD_VERSION),
                    str(DEMAND_SCHEMA_HEAD_VERSION),
                    str(DEMAND_REQUIRED_IAM_SCHEMA_VERSION),
                    api_digest.hex(),
                    event_digest.hex(),
                    content_digest.hex(),
                    manifest_digest.hex(),
                )
            ).encode("utf-8")
        ).digest()
        with psycopg.connect(
            self.postgres.conninfo(
                database=self.database,
                user="trust_migration_runner",
            ),
            autocommit=True,
        ) as connection:
            row = connection.execute(
                "SELECT component,current_schema_version,schema_head_version,"
                "min_app_compatible_version,max_app_compatible_version,"
                "required_iam_schema_version,api_contract_sha256,"
                "event_contract_sha256,content_contract_sha256,"
                "migration_manifest_sha256,dependency_sha256 "
                "FROM demand.trust_schema_dependency_v1"
            ).fetchone()
            self.assertEqual(
                row,
                (
                    "demand",
                    DEMAND_SCHEMA_HEAD_VERSION,
                    DEMAND_SCHEMA_HEAD_VERSION,
                    DEMAND_SCHEMA_HEAD_VERSION,
                    DEMAND_SCHEMA_HEAD_VERSION,
                    DEMAND_REQUIRED_IAM_SCHEMA_VERSION,
                    api_digest,
                    event_digest,
                    content_digest,
                    manifest_digest,
                    dependency_digest,
                ),
            )
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                connection.execute("SELECT id FROM demand.demands")

    @staticmethod
    def _insert_other_target(
        connection,
        *,
        organization_id: UUID,
        demand_id: UUID,
        version_id: UUID,
        creator_user_id: UUID,
        label: str,
    ) -> None:
        now = datetime.now(timezone.utc)
        connection.execute("SET CONSTRAINTS ALL DEFERRED")
        connection.execute(
            "INSERT INTO demand.demands ("
            "id,organization_id,creator_user_id,client_reference_digest_key_id,"
            "client_reference_digest,status,aggregate_version,current_version_id,"
            "expires_at,created_at,updated_at) VALUES ("
            "%s,%s,%s,'demand8-test',%s,'SUBMITTED',1,%s,%s,%s,%s)",
            (
                demand_id,
                organization_id,
                creator_user_id,
                _digest("demand8-client-" + label),
                version_id,
                now + timedelta(days=10),
                now - timedelta(days=1),
                now,
            ),
        )
        source = connection.execute(
            "SELECT taxonomy_bundle_id,canonical_version_bytes,content,"
            "content_sha256 FROM demand.demand_versions WHERE id=%s",
            (DEMAND_VERSION_ID,),
        ).fetchone()
        connection.execute(
            "INSERT INTO demand.demand_versions ("
            "id,organization_id,demand_id,version_no,based_on_demand_version_id,"
            "demand_schema_version,canonicalization_version,taxonomy_bundle_id,"
            "canonical_version_bytes,content,content_sha256,created_by_user_id,"
            "created_at) VALUES ("
            "%s,%s,%s,1,NULL,1,'demand-content-json-v1',%s,%s,%s,%s,%s,%s)",
            (
                version_id,
                organization_id,
                demand_id,
                source[0],
                source[1],
                Jsonb(source[2]),
                source[3],
                creator_user_id,
                now - timedelta(days=1),
            ),
        )


if __name__ == "__main__":
    unittest.main()
