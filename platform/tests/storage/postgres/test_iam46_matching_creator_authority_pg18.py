"""PostgreSQL 18 evidence for both IAM46 authority seams."""

from __future__ import annotations

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
from tests.storage.postgres import (
    test_iam44_candidate_selector_opt_in_authority_pg18 as iam44_fixture,
)
from tests.storage.postgres.test_iam44_candidate_selector_opt_in_authority_pg18 import (
    _Seed,
)


PLATFORM_ROOT = Path(__file__).resolve().parents[3]
MIGRATION_ROOT = (
    PLATFORM_ROOT
    / "src/desire_platform/identity_access/adapters/postgres/migrations"
)
CREATOR_RESOLVER_SQL = (
    "SELECT * FROM iam_api.resolve_matching_creator_authority_marker_v1("
    "%s::uuid,%s::uuid,%s::text,%s::uuid,%s::uuid)"
)
MATCHING_WRAPPER_SQL = (
    "SELECT * FROM iam46_matching_test.resolve_creator_authority_v1("
    "%s::uuid,%s::uuid,%s::text,%s::uuid,%s::uuid)"
)
PROFILE_RESOLVER_SQL = (
    "SELECT * FROM iam46_profile_test.resolve_creator_eligibility_v1("
    "%s::uuid,%s::uuid,%s::uuid,%s::bytea,%s::bytea)"
)


def _digest(label: str) -> bytes:
    return hashlib.sha256(label.encode("ascii")).digest()


class Iam46MatchingCreatorAuthorityPostgres18Test(unittest.TestCase):
    _seed = iam44_fixture.Iam44CandidateSelectorOptInPostgres18Test._seed
    _set_local = staticmethod(
        iam44_fixture.Iam44CandidateSelectorOptInPostgres18Test._set_local
    )
    _editor_marker = (
        iam44_fixture.Iam44CandidateSelectorOptInPostgres18Test._editor_marker
    )

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
                    application_name="iam46-matching-creator-pg18",
                ),
                dbapi=psycopg,
            ),
            runner_version="iam46-matching-creator-pg18/1",
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
        cls._install_matching_nested_call()
        cls._install_profile_nested_call()

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

    @classmethod
    def _install_profile_nested_call(cls) -> None:
        with cls._admin() as connection:
            connection.execute(
                "CREATE SCHEMA iam46_profile_test "
                "AUTHORIZATION profile_schema_owner"
            )
            connection.execute("SET LOCAL ROLE profile_schema_owner")
            connection.execute(
                "CREATE FUNCTION "
                "iam46_profile_test.resolve_creator_eligibility_v1("
                "exact_candidate_user_id uuid,exact_match_run_id uuid,"
                "exact_workload_id uuid,exact_authorization_digest bytea,"
                "exact_demand_match_context_sha256 bytea) RETURNS TABLE("
                "candidate_user_id uuid,eligible boolean,"
                "creator_user_version bigint,creator_grant_id uuid,"
                "creator_grant_version bigint,source_invitation_id uuid,"
                "source_invitation_version bigint,policy_selector_digest bytea,"
                "policy_selector_version bigint,policy_bundle_id uuid,"
                "policy_bundle_version bigint,"
                "required_policy_acceptance_set_sha256 bytea,"
                "eligibility_evidence_sha256 bytea,valid_until timestamptz) "
                "LANGUAGE sql SECURITY DEFINER VOLATILE PARALLEL UNSAFE "
                "SET search_path=pg_catalog,iam_api AS $wrapper$ "
                "SELECT * FROM "
                "iam_api.resolve_profile_match_creator_eligibility_v1("
                "exact_candidate_user_id,exact_match_run_id,exact_workload_id,"
                "exact_authorization_digest,"
                "exact_demand_match_context_sha256) $wrapper$"
            )
            connection.execute(
                "REVOKE ALL ON FUNCTION "
                "iam46_profile_test.resolve_creator_eligibility_v1("
                "uuid,uuid,uuid,bytea,bytea) FROM PUBLIC,profile_matcher"
            )
            connection.execute(
                "GRANT USAGE ON SCHEMA iam46_profile_test TO profile_matcher"
            )
            connection.execute(
                "GRANT EXECUTE ON FUNCTION "
                "iam46_profile_test.resolve_creator_eligibility_v1("
                "uuid,uuid,uuid,bytea,bytea) TO profile_matcher"
            )
            connection.execute("RESET ROLE")

    @classmethod
    def _install_matching_nested_call(cls) -> None:
        with cls._admin() as connection:
            connection.execute(
                "CREATE SCHEMA iam46_matching_test "
                "AUTHORIZATION matching_schema_owner"
            )
            connection.execute("SET LOCAL ROLE matching_schema_owner")
            connection.execute(
                "CREATE FUNCTION "
                "iam46_matching_test.resolve_creator_authority_v1("
                "exact_actor_user_id uuid,exact_session_id uuid,"
                "exact_operation_code text,exact_invitation_id uuid,"
                "exact_command_id uuid) RETURNS TABLE("
                "actor_user_id uuid,session_id uuid,operation_code varchar,"
                "role_code varchar,authority_marker_sha256 bytea,"
                "evidence_sha256 bytea,valid_until timestamptz) "
                "LANGUAGE sql SECURITY DEFINER STABLE PARALLEL UNSAFE "
                "SET search_path=pg_catalog,iam_api AS $wrapper$ "
                "SELECT * FROM "
                "iam_api.resolve_matching_creator_authority_marker_v1("
                "exact_actor_user_id,exact_session_id,exact_operation_code,"
                "exact_invitation_id,exact_command_id) $wrapper$"
            )
            connection.execute(
                "REVOKE ALL ON FUNCTION "
                "iam46_matching_test.resolve_creator_authority_v1("
                "uuid,uuid,text,uuid,uuid) FROM PUBLIC,matching_creator"
            )
            connection.execute(
                "GRANT USAGE ON SCHEMA iam46_matching_test TO matching_creator"
            )
            connection.execute(
                "GRANT EXECUTE ON FUNCTION "
                "iam46_matching_test.resolve_creator_authority_v1("
                "uuid,uuid,text,uuid,uuid) TO matching_creator"
            )
            connection.execute("RESET ROLE")

    def _configure_creator(
        self,
        connection,
        *,
        seed: _Seed,
        operation: str,
        invitation_id: UUID | None,
        command_id: UUID | None,
        scope_kind: str = "MATCHING_CREATOR",
        actor_user_id: UUID | None = None,
        session_id: UUID | None = None,
    ) -> tuple[UUID, UUID]:
        actor = actor_user_id or seed.actor_user_id
        session = session_id or seed.session_id
        for name, value in (
            ("app.scope_kind", scope_kind),
            ("app.operation", operation),
            ("app.actor_user_id", actor),
            ("app.session_id", session),
            ("app.invitation_id", invitation_id or ""),
            ("app.command_id", command_id or ""),
        ):
            self._set_local(connection, name, value)
        return actor, session

    @staticmethod
    def _resolve_creator(
        connection,
        *,
        actor_user_id: UUID,
        session_id: UUID,
        operation: str,
        invitation_id: UUID | None,
        command_id: UUID | None,
    ):
        return connection.execute(
            CREATOR_RESOLVER_SQL,
            (
                actor_user_id,
                session_id,
                operation,
                invitation_id,
                command_id,
            ),
        ).fetchall()

    def _configured_creator_resolve(
        self,
        seed: _Seed,
        *,
        operation: str = "READ_MATCHING_INVITATION",
        invitation_id: UUID | None = None,
        command_id: UUID | None = None,
        scope_kind: str = "MATCHING_CREATOR",
    ):
        if invitation_id is None and operation != "LIST_MATCHING_INVITATIONS":
            invitation_id = uuid4()
        if command_id is None and operation in (
            "ACCEPT_MATCHING_INVITATION",
            "DECLINE_MATCHING_INVITATION",
            "WITHDRAW_MATCHING_INVITATION",
        ):
            command_id = uuid4()
        with self._connect("matching_creator") as connection:
            actor, session = self._configure_creator(
                connection,
                seed=seed,
                operation=operation,
                invitation_id=invitation_id,
                command_id=command_id,
                scope_kind=scope_kind,
            )
            return self._resolve_creator(
                connection,
                actor_user_id=actor,
                session_id=session,
                operation=operation,
                invitation_id=invitation_id,
                command_id=command_id,
            )

    def _configure_profile(
        self,
        connection,
        *,
        match_run_id: UUID,
        workload_id: UUID,
        authorization_digest: bytes,
        demand_context_digest: bytes,
        scope_kind: str = "PROFILE_MATCH_DERIVATION",
        operation: str = "CAPTURE_DERIVED_MATCH_INPUTS",
    ) -> None:
        for name, value in (
            ("app.scope_kind", scope_kind),
            ("app.operation", operation),
            ("app.match_run_id", match_run_id),
            ("app.workload_id", workload_id),
            ("app.authorization_digest", authorization_digest.hex()),
            (
                "app.demand_match_context_sha256",
                demand_context_digest.hex(),
            ),
        ):
            self._set_local(connection, name, value)

    @staticmethod
    def _resolve_profile(
        connection,
        *,
        candidate_user_id: UUID,
        match_run_id: UUID,
        workload_id: UUID,
        authorization_digest: bytes,
        demand_context_digest: bytes,
    ):
        return connection.execute(
            PROFILE_RESOLVER_SQL,
            (
                candidate_user_id,
                match_run_id,
                workload_id,
                authorization_digest,
                demand_context_digest,
            ),
        ).fetchall()

    def _creator_facts(self, candidate_user_id: UUID):
        with self._admin() as connection:
            return connection.execute(
                "SELECT actor.aggregate_version,grant_row.id,"
                "grant_row.aggregate_version,grant_row.source_invitation_id,"
                "invitation.aggregate_version,grant_row.policy_selector_digest,"
                "selector.aggregate_version,bundle.id,bundle.aggregate_version "
                "FROM iam.users AS actor "
                "JOIN iam.user_role_grants AS grant_row "
                "ON grant_row.user_id=actor.id AND grant_row.role_code='CREATOR' "
                "JOIN iam.access_invitations AS invitation "
                "ON invitation.id=grant_row.source_invitation_id "
                "JOIN iam.policy_selectors AS selector "
                "ON selector.selector_digest=grant_row.policy_selector_digest "
                "JOIN iam.policy_bundles AS bundle "
                "ON bundle.id=selector.current_bundle_id "
                "WHERE actor.id=%s",
                (candidate_user_id,),
            ).fetchone()

    def test_every_creator_operation_shape_is_deterministic_and_marker_compatible(
        self,
    ) -> None:
        seed = self._seed()
        expected_marker = self._editor_marker(seed)
        matrix = (
            ("LIST_MATCHING_INVITATIONS", None, None),
            ("READ_MATCHING_INVITATION", uuid4(), None),
            ("ACCEPT_MATCHING_INVITATION", uuid4(), uuid4()),
            ("DECLINE_MATCHING_INVITATION", uuid4(), uuid4()),
            ("WITHDRAW_MATCHING_INVITATION", uuid4(), uuid4()),
        )

        for operation, invitation_id, command_id in matrix:
            with self.subTest(operation=operation), self._connect(
                "matching_creator"
            ) as connection:
                actor, session = self._configure_creator(
                    connection,
                    seed=seed,
                    operation=operation,
                    invitation_id=invitation_id,
                    command_id=command_id,
                )
                arguments = {
                    "actor_user_id": actor,
                    "session_id": session,
                    "operation": operation,
                    "invitation_id": invitation_id,
                    "command_id": command_id,
                }
                first = self._resolve_creator(connection, **arguments)
                second = self._resolve_creator(connection, **arguments)

                self.assertEqual(first, second)
                self.assertEqual(len(first), 1)
                row = first[0]
                self.assertEqual(
                    row[:4],
                    (seed.actor_user_id, seed.session_id, operation, "CREATOR"),
                )
                self.assertEqual(bytes(row[4]), expected_marker)
                self.assertEqual(len(bytes(row[5])), 32)
                self.assertGreater(row[6], seed.now)
                self.assertLessEqual(
                    row[6], seed.now + timedelta(minutes=5, seconds=10)
                )

    def test_creator_evidence_binds_operation_invitation_and_command_only(self) -> None:
        seed = self._seed()
        first_invitation = uuid4()
        second_invitation = uuid4()
        first_command = uuid4()
        second_command = uuid4()
        with self._connect("matching_creator") as connection:
            actor, session = self._configure_creator(
                connection,
                seed=seed,
                operation="ACCEPT_MATCHING_INVITATION",
                invitation_id=first_invitation,
                command_id=first_command,
            )
            first = self._resolve_creator(
                connection,
                actor_user_id=actor,
                session_id=session,
                operation="ACCEPT_MATCHING_INVITATION",
                invitation_id=first_invitation,
                command_id=first_command,
            )[0]
            self._configure_creator(
                connection,
                seed=seed,
                operation="DECLINE_MATCHING_INVITATION",
                invitation_id=second_invitation,
                command_id=second_command,
            )
            second = self._resolve_creator(
                connection,
                actor_user_id=actor,
                session_id=session,
                operation="DECLINE_MATCHING_INVITATION",
                invitation_id=second_invitation,
                command_id=second_command,
            )[0]

        self.assertEqual(bytes(first[4]), bytes(second[4]))
        self.assertNotEqual(bytes(first[5]), bytes(second[5]))
        self.assertEqual(first[6], second[6])

    def test_creator_argument_matrix_and_every_local_guc_mismatch_fail_closed(
        self,
    ) -> None:
        seed = self._seed()
        invitation_id = uuid4()
        command_id = uuid4()
        invalid_shapes = (
            ("LIST_MATCHING_INVITATIONS", invitation_id, None),
            ("LIST_MATCHING_INVITATIONS", None, command_id),
            ("READ_MATCHING_INVITATION", None, None),
            ("READ_MATCHING_INVITATION", invitation_id, command_id),
            ("ACCEPT_MATCHING_INVITATION", None, command_id),
            ("DECLINE_MATCHING_INVITATION", invitation_id, None),
            ("WITHDRAW_MATCHING_INVITATION", None, None),
            ("BROWSER_SELECTED_OPERATION", invitation_id, command_id),
        )
        for operation, exact_invitation, exact_command in invalid_shapes:
            with self.subTest(shape=operation), self._connect(
                "matching_creator"
            ) as connection:
                self._configure_creator(
                    connection,
                    seed=seed,
                    operation=operation,
                    invitation_id=exact_invitation,
                    command_id=exact_command,
                )
                self.assertEqual(
                    self._resolve_creator(
                        connection,
                        actor_user_id=seed.actor_user_id,
                        session_id=seed.session_id,
                        operation=operation,
                        invitation_id=exact_invitation,
                        command_id=exact_command,
                    ),
                    [],
                )

        mismatches = {
            "app.scope_kind": "WRONG_SCOPE",
            "app.operation": "DECLINE_MATCHING_INVITATION",
            "app.actor_user_id": str(uuid4()),
            "app.session_id": str(uuid4()),
            "app.invitation_id": str(uuid4()),
            "app.command_id": str(uuid4()),
        }
        for setting, wrong_value in mismatches.items():
            with self.subTest(setting=setting), self._connect(
                "matching_creator"
            ) as connection:
                self._configure_creator(
                    connection,
                    seed=seed,
                    operation="ACCEPT_MATCHING_INVITATION",
                    invitation_id=invitation_id,
                    command_id=command_id,
                )
                self._set_local(connection, setting, wrong_value)
                self.assertEqual(
                    self._resolve_creator(
                        connection,
                        actor_user_id=seed.actor_user_id,
                        session_id=seed.session_id,
                        operation="ACCEPT_MATCHING_INVITATION",
                        invitation_id=invitation_id,
                        command_id=command_id,
                    ),
                    [],
                )

        for operation, unwanted_setting in (
            ("LIST_MATCHING_INVITATIONS", "app.invitation_id"),
            ("LIST_MATCHING_INVITATIONS", "app.command_id"),
            ("READ_MATCHING_INVITATION", "app.command_id"),
        ):
            with self.subTest(
                operation=operation, unwanted=unwanted_setting
            ), self._connect("matching_creator") as connection:
                exact_invitation = (
                    None if operation == "LIST_MATCHING_INVITATIONS" else uuid4()
                )
                self._configure_creator(
                    connection,
                    seed=seed,
                    operation=operation,
                    invitation_id=exact_invitation,
                    command_id=None,
                )
                self._set_local(connection, unwanted_setting, uuid4())
                self.assertEqual(
                    self._resolve_creator(
                        connection,
                        actor_user_id=seed.actor_user_id,
                        session_id=seed.session_id,
                        operation=operation,
                        invitation_id=exact_invitation,
                        command_id=None,
                    ),
                    [],
                )

    def test_inactive_expired_and_revoked_creator_authority_fail_closed(self) -> None:
        expired_session = self._seed(idle_offset=timedelta(minutes=-1))
        self.assertEqual(self._configured_creator_resolve(expired_session), [])

        revoked_session = self._seed(session_status="REVOKED")
        self.assertEqual(self._configured_creator_resolve(revoked_session), [])

        suspended_user = self._seed()
        with self._admin() as connection:
            connection.execute("SET LOCAL session_replication_role='replica'")
            connection.execute(
                "UPDATE iam.users SET status='SUSPENDED',"
                "aggregate_version=aggregate_version+1,updated_at=%s WHERE id=%s",
                (datetime.now(timezone.utc), suspended_user.actor_user_id),
            )
        self.assertEqual(self._configured_creator_resolve(suspended_user), [])

        revoked_grant = self._seed()
        with self._admin() as connection:
            connection.execute("SET LOCAL session_replication_role='replica'")
            connection.execute(
                "UPDATE iam.user_role_grants SET revoked_at=%s,"
                "revocation_reason_code='TEST_REVOCATION',"
                "aggregate_version=aggregate_version+1 WHERE user_id=%s "
                "AND role_code='CREATOR'",
                (datetime.now(timezone.utc), revoked_grant.actor_user_id),
            )
        self.assertEqual(self._configured_creator_resolve(revoked_grant), [])

        inactive_bundle = self._seed()
        with self._admin() as connection:
            connection.execute("SET LOCAL session_replication_role='replica'")
            connection.execute(
                "UPDATE iam.policy_bundles AS bundle SET status='RETIRED',"
                "effective_until=%s,aggregate_version=bundle.aggregate_version+1,"
                "updated_at=%s FROM iam.policy_selectors AS selector,"
                "iam.user_role_grants AS grant_row "
                "WHERE grant_row.user_id=%s "
                "AND selector.selector_digest=grant_row.policy_selector_digest "
                "AND bundle.id=selector.current_bundle_id",
                (
                    datetime.now(timezone.utc),
                    datetime.now(timezone.utc),
                    inactive_bundle.actor_user_id,
                ),
            )
        self.assertEqual(self._configured_creator_resolve(inactive_bundle), [])

    def test_creator_impersonation_wrong_roles_and_direct_table_access_are_denied(
        self,
    ) -> None:
        seed = self._seed()
        invitation_id = uuid4()
        with self._connect("matching_creator") as connection:
            self._configure_creator(
                connection,
                seed=seed,
                operation="READ_MATCHING_INVITATION",
                invitation_id=invitation_id,
                command_id=None,
                actor_user_id=uuid4(),
            )
            self.assertEqual(
                self._resolve_creator(
                    connection,
                    actor_user_id=seed.actor_user_id,
                    session_id=seed.session_id,
                    operation="READ_MATCHING_INVITATION",
                    invitation_id=invitation_id,
                    command_id=None,
                ),
                [],
            )
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                connection.execute("SET ROLE schema_owner")

        with self._connect("matching_selector") as connection:
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                connection.execute(
                    CREATOR_RESOLVER_SQL,
                    (
                        seed.actor_user_id,
                        seed.session_id,
                        "READ_MATCHING_INVITATION",
                        invitation_id,
                        None,
                    ),
                ).fetchall()

        with self._connect("matching_creator") as connection:
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                connection.execute("SELECT id FROM iam.users").fetchall()

    def test_matching_owner_nested_call_works_but_direct_session_fails_closed(
        self,
    ) -> None:
        seed = self._seed()
        invitation_id = uuid4()
        with self._connect("matching_creator") as connection:
            self._configure_creator(
                connection,
                seed=seed,
                operation="READ_MATCHING_INVITATION",
                invitation_id=invitation_id,
                command_id=None,
            )
            nested = connection.execute(
                MATCHING_WRAPPER_SQL,
                (
                    seed.actor_user_id,
                    seed.session_id,
                    "READ_MATCHING_INVITATION",
                    invitation_id,
                    None,
                ),
            ).fetchall()
        self.assertEqual(len(nested), 1)
        self.assertEqual(nested[0][0:4], (
            seed.actor_user_id,
            seed.session_id,
            "READ_MATCHING_INVITATION",
            "CREATOR",
        ))

        with self._admin() as connection:
            connection.execute("SET SESSION AUTHORIZATION matching_schema_owner")
            for name, value in (
                ("app.scope_kind", "MATCHING_CREATOR"),
                ("app.operation", "READ_MATCHING_INVITATION"),
                ("app.actor_user_id", seed.actor_user_id),
                ("app.session_id", seed.session_id),
                ("app.invitation_id", invitation_id),
                ("app.command_id", ""),
            ):
                self._set_local(connection, name, value)
            direct = self._resolve_creator(
                connection,
                actor_user_id=seed.actor_user_id,
                session_id=seed.session_id,
                operation="READ_MATCHING_INVITATION",
                invitation_id=invitation_id,
                command_id=None,
            )
            connection.execute("RESET SESSION AUTHORIZATION")
        self.assertEqual(direct, [])

    def test_profile_nested_call_returns_exact_versioned_eligible_row(self) -> None:
        seed = self._seed()
        expected = self._creator_facts(seed.actor_user_id)
        self.assertIsNotNone(expected)
        match_run_id = uuid4()
        workload_id = uuid4()
        authorization_digest = _digest("iam46-profile-authorization")
        demand_context = _digest("iam46-demand-context")

        with self._connect("profile_matcher") as connection:
            connection.execute(
                "BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ"
            )
            self._configure_profile(
                connection,
                match_run_id=match_run_id,
                workload_id=workload_id,
                authorization_digest=authorization_digest,
                demand_context_digest=demand_context,
            )
            arguments = {
                "candidate_user_id": seed.actor_user_id,
                "match_run_id": match_run_id,
                "workload_id": workload_id,
                "authorization_digest": authorization_digest,
                "demand_context_digest": demand_context,
            }
            first = self._resolve_profile(connection, **arguments)
            second = self._resolve_profile(connection, **arguments)

        self.assertEqual(first, second)
        self.assertEqual(len(first), 1)
        row = first[0]
        self.assertEqual(row[0:2], (seed.actor_user_id, True))
        self.assertEqual(
            row[2:11],
            (
                expected[0],
                expected[1],
                expected[2],
                expected[3],
                expected[4],
                bytes(expected[5]),
                expected[6],
                expected[7],
                expected[8],
            ),
        )
        self.assertEqual(len(bytes(row[11])), 32)
        self.assertEqual(len(bytes(row[12])), 32)
        self.assertGreater(row[13], seed.now)
        self.assertLessEqual(
            row[13], seed.now + timedelta(minutes=15, seconds=10)
        )

    def test_profile_target_context_is_bound_and_ineligible_is_one_safe_row(
        self,
    ) -> None:
        seed = self._seed()
        first_run, second_run = uuid4(), uuid4()
        first_workload, second_workload = uuid4(), uuid4()
        first_auth = _digest("iam46-first-auth")
        second_auth = _digest("iam46-second-auth")
        first_context = _digest("iam46-first-context")
        second_context = _digest("iam46-second-context")

        with self._connect("profile_matcher") as connection:
            connection.execute(
                "BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ"
            )
            self._configure_profile(
                connection,
                match_run_id=first_run,
                workload_id=first_workload,
                authorization_digest=first_auth,
                demand_context_digest=first_context,
            )
            first = self._resolve_profile(
                connection,
                candidate_user_id=seed.actor_user_id,
                match_run_id=first_run,
                workload_id=first_workload,
                authorization_digest=first_auth,
                demand_context_digest=first_context,
            )[0]
            self._configure_profile(
                connection,
                match_run_id=second_run,
                workload_id=second_workload,
                authorization_digest=second_auth,
                demand_context_digest=second_context,
            )
            second = self._resolve_profile(
                connection,
                candidate_user_id=seed.actor_user_id,
                match_run_id=second_run,
                workload_id=second_workload,
                authorization_digest=second_auth,
                demand_context_digest=second_context,
            )[0]
            missing = self._resolve_profile(
                connection,
                candidate_user_id=uuid4(),
                match_run_id=second_run,
                workload_id=second_workload,
                authorization_digest=second_auth,
                demand_context_digest=second_context,
            )

        self.assertNotEqual(bytes(first[11]), bytes(second[11]))
        self.assertNotEqual(bytes(first[12]), bytes(second[12]))
        self.assertEqual(len(missing), 1)
        self.assertFalse(missing[0][1])
        self.assertTrue(all(value is None for value in missing[0][2:]))

    def test_profile_every_outer_guc_mismatch_and_direct_call_fail_closed(
        self,
    ) -> None:
        seed = self._seed()
        match_run_id = uuid4()
        workload_id = uuid4()
        authorization_digest = _digest("iam46-profile-guc-auth")
        demand_context = _digest("iam46-profile-guc-context")
        mismatches = {
            "app.scope_kind": "WRONG_SCOPE",
            "app.operation": "WRONG_OPERATION",
            "app.match_run_id": str(uuid4()),
            "app.workload_id": str(uuid4()),
            "app.authorization_digest": _digest("wrong-auth").hex(),
            "app.demand_match_context_sha256": _digest(
                "wrong-context"
            ).hex(),
        }
        for setting, wrong_value in mismatches.items():
            with self.subTest(setting=setting), self._connect(
                "profile_matcher"
            ) as connection:
                self._configure_profile(
                    connection,
                    match_run_id=match_run_id,
                    workload_id=workload_id,
                    authorization_digest=authorization_digest,
                    demand_context_digest=demand_context,
                )
                self._set_local(connection, setting, wrong_value)
                self.assertEqual(
                    self._resolve_profile(
                        connection,
                        candidate_user_id=seed.actor_user_id,
                        match_run_id=match_run_id,
                        workload_id=workload_id,
                        authorization_digest=authorization_digest,
                        demand_context_digest=demand_context,
                    ),
                    [],
                )

        with self._connect("profile_matcher") as connection:
            self._configure_profile(
                connection,
                match_run_id=match_run_id,
                workload_id=workload_id,
                authorization_digest=authorization_digest,
                demand_context_digest=demand_context,
            )
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                connection.execute(
                    "SELECT * FROM "
                    "iam_api.resolve_profile_match_creator_eligibility_v1("
                    "%s,%s,%s,%s,%s)",
                    (
                        seed.actor_user_id,
                        match_run_id,
                        workload_id,
                        authorization_digest,
                        demand_context,
                    ),
                ).fetchall()
            connection.rollback()
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                connection.execute("SET ROLE profile_schema_owner")

        with self._connect("profile_matcher") as connection:
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                connection.execute("SELECT id FROM iam.users").fetchall()

    def test_profile_version_drift_changes_evidence_and_revocation_is_immediate(
        self,
    ) -> None:
        seed = self._seed()
        match_run_id = uuid4()
        workload_id = uuid4()
        authorization_digest = _digest("iam46-version-auth")
        demand_context = _digest("iam46-version-context")

        def resolve_once():
            with self._connect("profile_matcher") as connection:
                self._configure_profile(
                    connection,
                    match_run_id=match_run_id,
                    workload_id=workload_id,
                    authorization_digest=authorization_digest,
                    demand_context_digest=demand_context,
                )
                return self._resolve_profile(
                    connection,
                    candidate_user_id=seed.actor_user_id,
                    match_run_id=match_run_id,
                    workload_id=workload_id,
                    authorization_digest=authorization_digest,
                    demand_context_digest=demand_context,
                )[0]

        first = resolve_once()
        with self._admin() as connection:
            connection.execute("SET LOCAL session_replication_role='replica'")
            connection.execute(
                "UPDATE iam.users SET aggregate_version=aggregate_version+1,"
                "updated_at=%s WHERE id=%s",
                (datetime.now(timezone.utc), seed.actor_user_id),
            )
        second = resolve_once()
        self.assertEqual(second[2], first[2] + 1)
        self.assertNotEqual(bytes(second[12]), bytes(first[12]))

        with self._admin() as connection:
            connection.execute("SET LOCAL session_replication_role='replica'")
            connection.execute(
                "UPDATE iam.user_role_grants SET revoked_at=%s,"
                "revocation_reason_code='TEST_REVOCATION',"
                "aggregate_version=aggregate_version+1 WHERE user_id=%s "
                "AND role_code='CREATOR'",
                (datetime.now(timezone.utc), seed.actor_user_id),
            )
        revoked = resolve_once()
        self.assertEqual(revoked[0:2], (seed.actor_user_id, False))
        self.assertTrue(all(value is None for value in revoked[2:]))

    def test_execute_acls_are_exact_for_both_resolvers(self) -> None:
        with self._admin() as connection:
            creator_acl = connection.execute(
                "SELECT has_function_privilege('matching_creator',%s,'EXECUTE'),"
                "has_function_privilege('schema_owner',%s,'EXECUTE'),"
                "has_function_privilege('matching_schema_owner',%s,'EXECUTE'),"
                "has_function_privilege('public',%s,'EXECUTE')",
                (
                    "iam_api.resolve_matching_creator_authority_marker_v1("
                    "uuid,uuid,text,uuid,uuid)",
                ) * 4,
            ).fetchone()
            profile_acl = connection.execute(
                "SELECT has_function_privilege('profile_schema_owner',%s,'EXECUTE'),"
                "has_function_privilege('schema_owner',%s,'EXECUTE'),"
                "has_function_privilege('profile_matcher',%s,'EXECUTE'),"
                "has_function_privilege('public',%s,'EXECUTE')",
                (
                    "iam_api.resolve_profile_match_creator_eligibility_v1("
                    "uuid,uuid,uuid,bytea,bytea)",
                ) * 4,
            ).fetchone()

        self.assertEqual(creator_acl, (True, True, True, False))
        self.assertEqual(profile_acl, (True, True, False, False))


if __name__ == "__main__":
    unittest.main()
