"""PostgreSQL 18 evidence for IAM44 Candidate Selector opt-in authority."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
import unittest
from uuid import UUID, uuid4

import psycopg

from desire_platform.identity_access.adapters.postgres.migrations import (
    IamContractSources,
    IamMigrationRunner,
    MigrationCatalog,
    PsycopgMigrationDriver,
    PsycopgMigrationSettings,
)
from tests.storage.postgres.postgres18_harness import TemporaryPostgres18


PLATFORM_ROOT = Path(__file__).resolve().parents[3]
MIGRATION_ROOT = (
    PLATFORM_ROOT
    / "src/desire_platform/identity_access/adapters/postgres/migrations"
)
RESOLVER_SQL = (
    "SELECT * FROM iam_api.resolve_candidate_selector_opt_in_marker_v1("
    "%s::uuid,%s::uuid,%s::uuid,%s::uuid,%s::uuid,%s::uuid)"
)


def _digest(label: str) -> bytes:
    return hashlib.sha256(label.encode("ascii")).digest()


@dataclass(frozen=True)
class _Seed:
    now: datetime
    actor_user_id: UUID
    family_id: UUID
    session_id: UUID
    organization_id: UUID
    other_organization_id: UUID
    membership_id: UUID


class Iam44CandidateSelectorOptInPostgres18Test(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.postgres = TemporaryPostgres18().start()
        cls.database = cls.postgres.create_database()
        IamMigrationRunner(
            driver=PsycopgMigrationDriver(
                settings=PsycopgMigrationSettings(
                    conninfo=cls.postgres.conninfo(
                        database=cls.database,
                        user="iam_migration_runner",
                    ),
                    application_name="iam44-candidate-selector-pg18",
                ),
                dbapi=psycopg,
            ),
            runner_version="iam44-candidate-selector-pg18/1",
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

    @classmethod
    def tearDownClass(cls) -> None:
        try:
            cls.postgres.drop_database(cls.database)
        finally:
            cls.postgres.stop()

    @classmethod
    def _connect(cls, role: str, *, autocommit: bool = False):
        return psycopg.connect(
            cls.postgres.conninfo(database=cls.database, user=role),
            autocommit=autocommit,
        )

    @classmethod
    def _admin(cls, *, autocommit: bool = False):
        return psycopg.connect(
            cls.postgres.admin_conninfo(database=cls.database),
            autocommit=autocommit,
        )

    def _seed(
        self,
        *,
        auth_age: timedelta = timedelta(minutes=5),
        idle_offset: timedelta = timedelta(hours=1),
        session_status: str = "ACTIVE",
        membership_status: str = "ACTIVE",
        organization_status: str = "ACTIVE",
    ) -> _Seed:
        now = datetime.now(timezone.utc).replace(microsecond=0)
        auth_time = now - auth_age
        session_created = auth_time + timedelta(minutes=1)
        last_activity = min(now - timedelta(minutes=1), session_created)
        idle_expires = now + idle_offset
        if idle_expires <= last_activity:
            last_activity = idle_expires - timedelta(minutes=1)
        created = min(session_created, last_activity) - timedelta(days=1)
        actor_user_id = uuid4()
        family_id = uuid4()
        session_id = uuid4()
        organization_id = uuid4()
        other_organization_id = uuid4()
        membership_id = uuid4()
        source_invitation_id = uuid4()
        owner_bundle_id = uuid4()
        owner_selector_digest = _digest(
            "iam44-membership-selector-" + actor_user_id.hex
        )
        creator_invitation_id = uuid4()
        creator_bundle_id = uuid4()
        creator_selector_digest = _digest(
            "iam44-user-selector-" + actor_user_id.hex
        )
        creator_jurisdiction = "I" + actor_user_id.hex[:15].upper()

        revoked_at = now if session_status == "REVOKED" else None
        revocation_reason = "TEST_REVOCATION" if revoked_at else None
        with self._admin() as connection:
            connection.execute("SET LOCAL session_replication_role = 'replica'")
            connection.execute(
                "INSERT INTO iam.users("
                "id,status,display_handle,aggregate_version,created_at,updated_at) "
                "VALUES(%s,'ACTIVE',%s,11,%s,%s)",
                (
                    actor_user_id,
                    "iam44_actor_" + actor_user_id.hex[:12],
                    created,
                    now,
                ),
            )
            for candidate_id, candidate_status, label in (
                (organization_id, organization_status, "target"),
                (other_organization_id, "ACTIVE", "other"),
            ):
                connection.execute(
                    "INSERT INTO iam.organizations("
                    "id,organization_type,public_name,jurisdiction,status,"
                    "client_reference_namespace,client_reference,"
                    "aggregate_version,created_at,updated_at) VALUES("
                    "%s,'BUSINESS',%s,'CN',%s,'iam44-pg18',%s,13,%s,%s)",
                    (
                        candidate_id,
                        "IAM44 " + label,
                        candidate_status,
                        str(candidate_id),
                        created,
                        now,
                    ),
                )
            connection.execute(
                "INSERT INTO iam.memberships("
                "id,organization_id,user_id,status,source_invitation_id,"
                "aggregate_version,created_at,updated_at) "
                "VALUES(%s,%s,%s,%s,%s,17,%s,%s)",
                (
                    membership_id,
                    organization_id,
                    actor_user_id,
                    membership_status,
                    source_invitation_id,
                    created,
                    now - timedelta(minutes=1),
                ),
            )
            connection.execute(
                "INSERT INTO iam.membership_role_grants("
                "id,organization_id,membership_id,user_id,role_code,"
                "source_invitation_id,policy_selector_digest,granted_by_kind,"
                "granted_by_id,granted_at,revoked_at,revocation_reason_code,"
                "aggregate_version) VALUES("
                "%s,%s,%s,%s,'DEMAND_OWNER',%s,%s,'SYSTEM',%s,%s,NULL,NULL,19)",
                (
                    uuid4(),
                    organization_id,
                    membership_id,
                    actor_user_id,
                    source_invitation_id,
                    owner_selector_digest,
                    uuid4(),
                    created,
                ),
            )
            connection.execute(
                "INSERT INTO iam.policy_selectors("
                "selector_digest,canonicalization_version,access_purpose,"
                "scope_type,target_role,jurisdiction,locale,current_bundle_id,"
                "aggregate_version,created_at,updated_at) VALUES("
                "%s,'policy-selector-json-v1','ORGANIZATION_MEMBERSHIP',"
                "'ORGANIZATION_ROLE','DEMAND_OWNER',%s,'en',%s,33,%s,%s)",
                (
                    owner_selector_digest,
                    creator_jurisdiction,
                    owner_bundle_id,
                    created,
                    now,
                ),
            )
            connection.execute(
                "INSERT INTO iam.policy_bundles("
                "id,selector_digest,status,effective_at,effective_until,"
                "superseded_by_bundle_id,release_manifest_sha256,"
                "release_signature,release_signing_key_id,"
                "publication_command_id,aggregate_version,created_at,updated_at) "
                "VALUES(%s,%s,'ACTIVE',%s,NULL,NULL,%s,%s,'iam44-signing-v1',"
                "%s,35,%s,%s)",
                (
                    owner_bundle_id,
                    owner_selector_digest,
                    created,
                    _digest("iam44-owner-manifest-" + actor_user_id.hex),
                    b"iam44-owner-test-signature",
                    uuid4(),
                    created,
                    now,
                ),
            )
            connection.execute(
                "INSERT INTO iam.access_invitations("
                "id,purpose,organization_id,target_scope,target_role,"
                "is_initial_admin,recipient_contact_id,masked_recipient_label,"
                "policy_selector_digest,issued_policy_bundle_id,status,"
                "expires_at,issuer_kind,issuer_user_id,token_nonce,token_key_id,"
                "accepted_by_user_id,terminal_at,terminal_reason_code,"
                "aggregate_version,created_at,updated_at) VALUES("
                "%s,'ORGANIZATION_MEMBERSHIP',%s,'ORGANIZATION','DEMAND_OWNER',"
                "false,%s,'m***@example.test',%s,%s,'ACCEPTED',%s,'SYSTEM',"
                "NULL,%s,'iam44-token-v1',%s,%s,NULL,36,%s,%s)",
                (
                    source_invitation_id,
                    organization_id,
                    uuid4(),
                    owner_selector_digest,
                    owner_bundle_id,
                    now + timedelta(days=30),
                    _digest("iam44-owner-token-" + actor_user_id.hex),
                    actor_user_id,
                    now - timedelta(minutes=1),
                    created,
                    now,
                ),
            )
            connection.execute(
                "INSERT INTO iam.policy_selectors("
                "selector_digest,canonicalization_version,access_purpose,"
                "scope_type,target_role,jurisdiction,locale,current_bundle_id,"
                "aggregate_version,created_at,updated_at) VALUES("
                "%s,'policy-selector-json-v1','CREATOR_ENROLLMENT','USER_ROLE',"
                "'CREATOR',%s,'en',%s,37,%s,%s)",
                (
                    creator_selector_digest,
                    creator_jurisdiction,
                    creator_bundle_id,
                    created,
                    now,
                ),
            )
            connection.execute(
                "INSERT INTO iam.policy_bundles("
                "id,selector_digest,status,effective_at,effective_until,"
                "superseded_by_bundle_id,release_manifest_sha256,"
                "release_signature,release_signing_key_id,"
                "publication_command_id,aggregate_version,created_at,updated_at) "
                "VALUES(%s,%s,'ACTIVE',%s,NULL,NULL,%s,%s,'iam44-signing-v1',"
                "%s,41,%s,%s)",
                (
                    creator_bundle_id,
                    creator_selector_digest,
                    created,
                    _digest("iam44-manifest-" + actor_user_id.hex),
                    b"iam44-test-signature",
                    uuid4(),
                    created,
                    now,
                ),
            )
            connection.execute(
                "INSERT INTO iam.access_invitations("
                "id,purpose,organization_id,target_scope,target_role,"
                "is_initial_admin,recipient_contact_id,masked_recipient_label,"
                "policy_selector_digest,issued_policy_bundle_id,status,"
                "expires_at,issuer_kind,issuer_user_id,token_nonce,token_key_id,"
                "accepted_by_user_id,terminal_at,terminal_reason_code,"
                "aggregate_version,created_at,updated_at) VALUES("
                "%s,'CREATOR_ENROLLMENT',NULL,'USER','CREATOR',false,%s,"
                "'c***@example.test',%s,%s,'ACCEPTED',%s,'SYSTEM',NULL,%s,"
                "'iam44-token-v1',%s,%s,NULL,43,%s,%s)",
                (
                    creator_invitation_id,
                    uuid4(),
                    creator_selector_digest,
                    creator_bundle_id,
                    now + timedelta(days=30),
                    _digest("iam44-token-" + actor_user_id.hex),
                    actor_user_id,
                    now - timedelta(minutes=1),
                    created,
                    now,
                ),
            )
            connection.execute(
                "INSERT INTO iam.user_role_grants("
                "id,user_id,role_code,source_invitation_id,"
                "policy_selector_digest,granted_by_kind,granted_by_id,"
                "granted_at,revoked_at,revocation_reason_code,aggregate_version) "
                "VALUES(%s,%s,'CREATOR',%s,%s,'SYSTEM',%s,%s,NULL,NULL,23)",
                (
                    uuid4(),
                    actor_user_id,
                    creator_invitation_id,
                    creator_selector_digest,
                    uuid4(),
                    created,
                ),
            )
            connection.execute(
                "INSERT INTO iam.session_families("
                "id,user_id,status,current_generation,revoked_at,"
                "revocation_reason_code,aggregate_version,created_at,updated_at) "
                "VALUES(%s,%s,'ACTIVE',3,NULL,NULL,29,%s,%s)",
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
                "%s,%s,%s,3,NULL,%s,'iam44-handle-v1',%s,'iam44-csrf-v1',%s,"
                "NULL,NULL,NULL,NULL,%s,'urn:pwd',ARRAY['pwd'],%s,%s,%s,%s,%s,"
                "'Browser',%s,'LOGIN',%s,%s,31)",
                (
                    session_id,
                    actor_user_id,
                    family_id,
                    _digest("iam44-handle-" + session_id.hex),
                    _digest("iam44-csrf-salt-" + session_id.hex),
                    _digest("iam44-csrf-" + session_id.hex),
                    auth_time,
                    session_created,
                    last_activity,
                    idle_expires,
                    now + timedelta(hours=8),
                    max(session_created, last_activity),
                    session_status,
                    revoked_at,
                    revocation_reason,
                ),
            )

        return _Seed(
            now=now,
            actor_user_id=actor_user_id,
            family_id=family_id,
            session_id=session_id,
            organization_id=organization_id,
            other_organization_id=other_organization_id,
            membership_id=membership_id,
        )

    @staticmethod
    def _set_local(connection, name: str, value: object) -> None:
        text_value = str(value)
        assert connection.execute(
            "SELECT pg_catalog.set_config(%s,%s,true)",
            (name, text_value),
        ).fetchone() == (text_value,)

    def _configure_opt_in(
        self,
        connection,
        *,
        seed: _Seed,
        selection_id: UUID,
        demand_id: UUID,
        command_id: UUID,
        actor_user_id: UUID | None = None,
        session_id: UUID | None = None,
        organization_id: UUID | None = None,
        scope_kind: str = "MATCHING_ASSIGNMENT",
        operation: str = "OPT_IN_CANDIDATE_SELECTOR",
    ) -> tuple[UUID, UUID, UUID]:
        actor = actor_user_id or seed.actor_user_id
        session = session_id or seed.session_id
        organization = organization_id or seed.organization_id
        values = (
            ("app.scope_kind", scope_kind),
            ("app.operation", operation),
            ("app.actor_user_id", actor),
            ("app.session_id", session),
            ("app.organization_id", organization),
            ("app.selection_id", selection_id),
            ("app.demand_id", demand_id),
            ("app.command_id", command_id),
        )
        for name, value in values:
            self._set_local(connection, name, value)
        return actor, session, organization

    @staticmethod
    def _resolve(
        connection,
        *,
        actor_user_id: UUID,
        session_id: UUID,
        organization_id: UUID,
        selection_id: UUID,
        demand_id: UUID,
        command_id: UUID,
    ):
        return connection.execute(
            RESOLVER_SQL,
            (
                actor_user_id,
                session_id,
                organization_id,
                selection_id,
                demand_id,
                command_id,
            ),
        ).fetchall()

    def _editor_marker(self, seed: _Seed) -> bytes:
        with self._connect("iam_app") as connection:
            self._set_local(connection, "app.scope_kind", "EDITOR_PRINCIPAL")
            self._set_local(connection, "app.actor_user_id", seed.actor_user_id)
            self._set_local(connection, "app.session_id", seed.session_id)
            row = connection.execute(
                "SELECT principal_marker_sha256 "
                "FROM iam_api.resolve_editor_principal_v1(%s,%s) "
                "WHERE organization_id=%s",
                (
                    seed.actor_user_id,
                    seed.session_id,
                    seed.organization_id,
                ),
            ).fetchone()
            self.assertIsNotNone(row)
            return bytes(row[0])

    def test_happy_path_is_deterministic_and_editor_marker_compatible(self) -> None:
        seed = self._seed()
        selection_id = uuid4()
        demand_id = uuid4()
        command_id = uuid4()
        expected_editor_marker = self._editor_marker(seed)

        with self._connect("matching_assignment") as connection:
            actor, session, organization = self._configure_opt_in(
                connection,
                seed=seed,
                selection_id=selection_id,
                demand_id=demand_id,
                command_id=command_id,
            )
            first = self._resolve(
                connection,
                actor_user_id=actor,
                session_id=session,
                organization_id=organization,
                selection_id=selection_id,
                demand_id=demand_id,
                command_id=command_id,
            )
            second = self._resolve(
                connection,
                actor_user_id=actor,
                session_id=session,
                organization_id=organization,
                selection_id=selection_id,
                demand_id=demand_id,
                command_id=command_id,
            )

        self.assertEqual(first, second)
        self.assertEqual(len(first), 1)
        row = first[0]
        self.assertEqual(row[:6], (
            seed.actor_user_id,
            seed.session_id,
            seed.organization_id,
            selection_id,
            demand_id,
            "CANDIDATE_SELECTOR",
        ))
        self.assertEqual(bytes(row[6]), expected_editor_marker)
        self.assertEqual(len(bytes(row[6])), 32)
        self.assertEqual(len(bytes(row[7])), 32)
        self.assertGreater(row[8], seed.now)
        self.assertLessEqual(row[8], seed.now + timedelta(minutes=26))

    def test_exact_tuple_changes_only_the_opt_in_evidence(self) -> None:
        seed = self._seed()
        demand_id = uuid4()
        first_selection_id = uuid4()
        first_command_id = uuid4()
        second_selection_id = uuid4()
        second_command_id = uuid4()

        with self._connect("matching_assignment") as connection:
            actor, session, organization = self._configure_opt_in(
                connection,
                seed=seed,
                selection_id=first_selection_id,
                demand_id=demand_id,
                command_id=first_command_id,
            )
            first = self._resolve(
                connection,
                actor_user_id=actor,
                session_id=session,
                organization_id=organization,
                selection_id=first_selection_id,
                demand_id=demand_id,
                command_id=first_command_id,
            )[0]
            self._configure_opt_in(
                connection,
                seed=seed,
                selection_id=second_selection_id,
                demand_id=demand_id,
                command_id=second_command_id,
            )
            second = self._resolve(
                connection,
                actor_user_id=actor,
                session_id=session,
                organization_id=organization,
                selection_id=second_selection_id,
                demand_id=demand_id,
                command_id=second_command_id,
            )[0]

        self.assertEqual(bytes(first[6]), bytes(second[6]))
        self.assertNotEqual(bytes(first[7]), bytes(second[7]))
        self.assertEqual(first[8], second[8])

    def test_wrong_guc_session_member_and_organization_fail_closed(self) -> None:
        seed = self._seed()
        selection_id = uuid4()
        demand_id = uuid4()
        command_id = uuid4()

        with self._connect("matching_assignment") as connection:
            actor, session, organization = self._configure_opt_in(
                connection,
                seed=seed,
                selection_id=selection_id,
                demand_id=demand_id,
                command_id=command_id,
                scope_kind="WRONG_SCOPE",
            )
            self.assertEqual(self._resolve(
                connection,
                actor_user_id=actor,
                session_id=session,
                organization_id=organization,
                selection_id=selection_id,
                demand_id=demand_id,
                command_id=command_id,
            ), [])

        wrong_session = uuid4()
        with self._connect("matching_assignment") as connection:
            actor, session, organization = self._configure_opt_in(
                connection,
                seed=seed,
                selection_id=selection_id,
                demand_id=demand_id,
                command_id=command_id,
                session_id=wrong_session,
            )
            self.assertEqual(self._resolve(
                connection,
                actor_user_id=actor,
                session_id=session,
                organization_id=organization,
                selection_id=selection_id,
                demand_id=demand_id,
                command_id=command_id,
            ), [])

        with self._connect("matching_assignment") as connection:
            actor, session, organization = self._configure_opt_in(
                connection,
                seed=seed,
                selection_id=selection_id,
                demand_id=demand_id,
                command_id=command_id,
                organization_id=seed.other_organization_id,
            )
            self.assertEqual(self._resolve(
                connection,
                actor_user_id=actor,
                session_id=session,
                organization_id=organization,
                selection_id=selection_id,
                demand_id=demand_id,
                command_id=command_id,
            ), [])

        with self._admin() as connection:
            connection.execute("SET LOCAL session_replication_role = 'replica'")
            connection.execute(
                "UPDATE iam.memberships SET status='SUSPENDED',"
                "aggregate_version=aggregate_version+1,updated_at=%s "
                "WHERE id=%s",
                (datetime.now(timezone.utc), seed.membership_id),
            )
        with self._connect("matching_assignment") as connection:
            actor, session, organization = self._configure_opt_in(
                connection,
                seed=seed,
                selection_id=selection_id,
                demand_id=demand_id,
                command_id=command_id,
            )
            self.assertEqual(self._resolve(
                connection,
                actor_user_id=actor,
                session_id=session,
                organization_id=organization,
                selection_id=selection_id,
                demand_id=demand_id,
                command_id=command_id,
            ), [])

    def test_expired_revoked_and_stale_authentication_fail_closed(self) -> None:
        seeds = (
            self._seed(idle_offset=timedelta(minutes=-1)),
            self._seed(session_status="REVOKED"),
            self._seed(auth_age=timedelta(minutes=31)),
        )
        for seed in seeds:
            with self.subTest(seed=seed.session_id):
                selection_id = uuid4()
                demand_id = uuid4()
                command_id = uuid4()
                with self._connect("matching_assignment") as connection:
                    actor, session, organization = self._configure_opt_in(
                        connection,
                        seed=seed,
                        selection_id=selection_id,
                        demand_id=demand_id,
                        command_id=command_id,
                    )
                    self.assertEqual(self._resolve(
                        connection,
                        actor_user_id=actor,
                        session_id=session,
                        organization_id=organization,
                        selection_id=selection_id,
                        demand_id=demand_id,
                        command_id=command_id,
                    ), [])

    def test_wrong_role_and_direct_table_access_are_denied(self) -> None:
        seed = self._seed()
        selection_id = uuid4()
        demand_id = uuid4()
        command_id = uuid4()

        with self._connect("matching_selector") as connection:
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                connection.execute(
                    RESOLVER_SQL,
                    (
                        seed.actor_user_id,
                        seed.session_id,
                        seed.organization_id,
                        selection_id,
                        demand_id,
                        command_id,
                    ),
                ).fetchall()

        with self._connect("matching_assignment") as connection:
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                connection.execute("SELECT id FROM iam.users").fetchall()

    def test_existing_editor_profile_and_demand_markers_remain_callable(self) -> None:
        seed = self._seed()
        editor_marker = self._editor_marker(seed)
        self.assertEqual(len(editor_marker), 32)

        profile_id = uuid4()
        with self._connect("profile_app") as connection:
            for name, value in (
                ("app.scope_kind", "PROFILE_SELF"),
                ("app.actor_user_id", seed.actor_user_id),
                ("app.session_id", seed.session_id),
                ("app.operation", "CREATE_PROFILE"),
                ("app.profile_id", profile_id),
            ):
                self._set_local(connection, name, value)
            profile_marker = connection.execute(
                "SELECT authority_marker_sha256 FROM "
                "iam_api.resolve_profile_self_authority_marker_v1("
                "%s,%s,'CREATE_PROFILE',%s)",
                (seed.actor_user_id, seed.session_id, profile_id),
            ).fetchone()
            self.assertIsNotNone(profile_marker)
            self.assertEqual(len(bytes(profile_marker[0])), 32)

        demand_id = uuid4()
        with self._connect("demand_self") as connection:
            for name, value in (
                ("app.scope_kind", "DEMAND_OWNER"),
                ("app.actor_id", seed.actor_user_id),
                ("app.session_id", seed.session_id),
                ("app.organization_id", seed.organization_id),
                ("app.operation", "CREATE"),
                ("app.demand_id", demand_id),
            ):
                self._set_local(connection, name, value)
            demand_marker = connection.execute(
                "SELECT authority_marker_sha256 FROM "
                "iam_api.resolve_demand_owner_authority_marker_v1("
                "%s,%s,%s,'CREATE',%s)",
                (
                    seed.actor_user_id,
                    seed.session_id,
                    seed.organization_id,
                    demand_id,
                ),
            ).fetchone()
            self.assertIsNotNone(demand_marker)
            self.assertEqual(len(bytes(demand_marker[0])), 32)


if __name__ == "__main__":
    unittest.main()
