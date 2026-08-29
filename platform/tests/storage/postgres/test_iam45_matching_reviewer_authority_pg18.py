"""PostgreSQL 18 evidence for IAM45 Matching reviewer authority."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
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
from tests.storage.postgres.test_iam44_candidate_selector_opt_in_authority_pg18 import _Seed


PLATFORM_ROOT = Path(__file__).resolve().parents[3]
MIGRATION_ROOT = (
    PLATFORM_ROOT
    / "src/desire_platform/identity_access/adapters/postgres/migrations"
)
RESOLVER_SQL = (
    "SELECT * FROM iam_api.resolve_matching_reviewer_authority_marker_v1("
    "%s::uuid,%s::uuid,%s::uuid,%s::uuid,%s::uuid,%s::text,%s::uuid)"
)


class Iam45MatchingReviewerAuthorityPostgres18Test(unittest.TestCase):
    # Reuse the exact IAM44 identity/policy graph fixture.  Its primary
    # organization is an ACTIVE member workspace; its other organization is
    # ACTIVE with no actor membership, which is the valid review target.
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
                    application_name="iam45-matching-review-pg18",
                ),
                dbapi=psycopg,
            ),
            runner_version="iam45-matching-review-pg18/1",
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

    def _grant_reviewer_duty(
        self,
        seed: _Seed,
        *,
        expires_offset: timedelta | None = timedelta(minutes=20),
        revoked: bool = False,
    ) -> tuple[UUID, datetime | None]:
        duty_id = uuid4()
        granted_at = seed.now - timedelta(days=1)
        expires_at = (
            None if expires_offset is None else seed.now + expires_offset
        )
        revoked_at = seed.now if revoked else None
        with self._admin() as connection:
            connection.execute("SET LOCAL session_replication_role = 'replica'")
            connection.execute(
                "INSERT INTO iam.platform_duty_grants("
                "id,user_id,duty_code,granted_by_kind,granted_by_id,"
                "granted_at,expires_at,revoked_at,revocation_reason_code,"
                "aggregate_version,created_at,updated_at) VALUES("
                "%s,%s,'OPERATIONS_REVIEWER','SYSTEM',%s,%s,%s,%s,%s,47,%s,%s)",
                (
                    duty_id,
                    seed.actor_user_id,
                    uuid4(),
                    granted_at,
                    expires_at,
                    revoked_at,
                    "TEST_REVOCATION" if revoked else None,
                    granted_at - timedelta(minutes=1),
                    seed.now,
                ),
            )
        return duty_id, expires_at

    def _configure_review(
        self,
        connection,
        *,
        seed: _Seed,
        attempt_id: UUID,
        match_run_id: UUID,
        purpose_code: str,
        command_id: UUID,
        actor_user_id: UUID | None = None,
        session_id: UUID | None = None,
        organization_id: UUID | None = None,
        scope_kind: str = "MATCHING_REVIEW",
        operation: str = "CLAIM_MATCHING_REVIEW",
    ) -> tuple[UUID, UUID, UUID]:
        actor = actor_user_id or seed.actor_user_id
        session = session_id or seed.session_id
        organization = organization_id or seed.other_organization_id
        for name, value in (
            ("app.scope_kind", scope_kind),
            ("app.operation", operation),
            ("app.actor_user_id", actor),
            ("app.session_id", session),
            ("app.organization_id", organization),
            ("app.attempt_id", attempt_id),
            ("app.match_run_id", match_run_id),
            ("app.purpose_code", purpose_code),
            ("app.command_id", command_id),
        ):
            self._set_local(connection, name, value)
        return actor, session, organization

    @staticmethod
    def _resolve(
        connection,
        *,
        actor_user_id: UUID,
        session_id: UUID,
        organization_id: UUID,
        attempt_id: UUID,
        match_run_id: UUID,
        purpose_code: str,
        command_id: UUID,
    ):
        return connection.execute(
            RESOLVER_SQL,
            (
                actor_user_id,
                session_id,
                organization_id,
                attempt_id,
                match_run_id,
                purpose_code,
                command_id,
            ),
        ).fetchall()

    def _configured_resolve(
        self,
        seed: _Seed,
        *,
        purpose_code: str = "ATTEMPT_REVIEW",
        organization_id: UUID | None = None,
        scope_kind: str = "MATCHING_REVIEW",
    ):
        attempt_id = uuid4()
        match_run_id = uuid4()
        command_id = uuid4()
        with self._connect("matching_review") as connection:
            actor, session, organization = self._configure_review(
                connection,
                seed=seed,
                attempt_id=attempt_id,
                match_run_id=match_run_id,
                purpose_code=purpose_code,
                command_id=command_id,
                organization_id=organization_id,
                scope_kind=scope_kind,
            )
            return self._resolve(
                connection,
                actor_user_id=actor,
                session_id=session,
                organization_id=organization,
                attempt_id=attempt_id,
                match_run_id=match_run_id,
                purpose_code=purpose_code,
                command_id=command_id,
            )

    def test_valid_resolve_is_deterministic_and_editor_marker_compatible(self) -> None:
        seed = self._seed()
        duty_id, duty_expires_at = self._grant_reviewer_duty(seed)
        expected_editor_marker = self._editor_marker(seed)
        attempt_id = uuid4()
        match_run_id = uuid4()
        command_id = uuid4()

        with self._connect("matching_review") as connection:
            actor, session, organization = self._configure_review(
                connection,
                seed=seed,
                attempt_id=attempt_id,
                match_run_id=match_run_id,
                purpose_code="ATTEMPT_REVIEW",
                command_id=command_id,
            )
            first = self._resolve(
                connection,
                actor_user_id=actor,
                session_id=session,
                organization_id=organization,
                attempt_id=attempt_id,
                match_run_id=match_run_id,
                purpose_code="ATTEMPT_REVIEW",
                command_id=command_id,
            )
            second = self._resolve(
                connection,
                actor_user_id=actor,
                session_id=session,
                organization_id=organization,
                attempt_id=attempt_id,
                match_run_id=match_run_id,
                purpose_code="ATTEMPT_REVIEW",
                command_id=command_id,
            )

        self.assertEqual(first, second)
        self.assertEqual(len(first), 1)
        row = first[0]
        self.assertEqual(
            row[:10],
            (
                seed.actor_user_id,
                seed.session_id,
                seed.other_organization_id,
                attempt_id,
                match_run_id,
                "ATTEMPT_REVIEW",
                "MATCHING_REVIEWER",
                "OPERATIONS_REVIEWER",
                duty_id,
                47,
            ),
        )
        self.assertEqual(bytes(row[10]), expected_editor_marker)
        self.assertEqual(len(bytes(row[10])), 32)
        self.assertEqual(len(bytes(row[11])), 32)
        self.assertGreater(row[12], seed.now)
        self.assertLessEqual(row[12], seed.now + timedelta(minutes=5, seconds=5))
        self.assertLessEqual(row[12], duty_expires_at)

    def test_no_duty_revoked_duty_and_expired_duty_fail_closed(self) -> None:
        no_duty = self._seed()
        self.assertEqual(self._configured_resolve(no_duty), [])

        revoked = self._seed()
        self._grant_reviewer_duty(revoked, revoked=True)
        self.assertEqual(self._configured_resolve(revoked), [])

        expired = self._seed()
        self._grant_reviewer_duty(
            expired,
            expires_offset=timedelta(minutes=-1),
        )
        self.assertEqual(self._configured_resolve(expired), [])

    def test_inactive_or_expired_identity_session_and_org_fail_closed(self) -> None:
        stale_auth = self._seed(auth_age=timedelta(minutes=31))
        self._grant_reviewer_duty(stale_auth)
        self.assertEqual(self._configured_resolve(stale_auth), [])

        expired_session = self._seed(idle_offset=timedelta(minutes=-1))
        self._grant_reviewer_duty(expired_session)
        self.assertEqual(self._configured_resolve(expired_session), [])

        suspended_user = self._seed()
        self._grant_reviewer_duty(suspended_user)
        with self._admin() as connection:
            connection.execute("SET LOCAL session_replication_role = 'replica'")
            connection.execute(
                "UPDATE iam.users SET status='SUSPENDED',"
                "aggregate_version=aggregate_version+1,updated_at=%s WHERE id=%s",
                (datetime.now(timezone.utc), suspended_user.actor_user_id),
            )
        self.assertEqual(self._configured_resolve(suspended_user), [])

        inactive_org = self._seed()
        self._grant_reviewer_duty(inactive_org)
        with self._admin() as connection:
            connection.execute("SET LOCAL session_replication_role = 'replica'")
            connection.execute(
                "UPDATE iam.organizations SET status='SUSPENDED',"
                "aggregate_version=aggregate_version+1,updated_at=%s WHERE id=%s",
                (
                    datetime.now(timezone.utc),
                    inactive_org.other_organization_id,
                ),
            )
        self.assertEqual(self._configured_resolve(inactive_org), [])

    def test_active_target_membership_is_an_explicit_conflict(self) -> None:
        seed = self._seed()
        self._grant_reviewer_duty(seed)

        self.assertEqual(
            self._configured_resolve(
                seed,
                organization_id=seed.organization_id,
            ),
            [],
        )

    def test_cross_tuple_and_wrong_purpose_fail_and_exact_evidence_changes(self) -> None:
        seed = self._seed()
        self._grant_reviewer_duty(seed)
        first_attempt = uuid4()
        first_run = uuid4()
        first_command = uuid4()
        second_attempt = uuid4()
        second_run = uuid4()
        second_command = uuid4()

        with self._connect("matching_review") as connection:
            actor, session, organization = self._configure_review(
                connection,
                seed=seed,
                attempt_id=first_attempt,
                match_run_id=first_run,
                purpose_code="MATCH_RETRY",
                command_id=first_command,
            )
            first = self._resolve(
                connection,
                actor_user_id=actor,
                session_id=session,
                organization_id=organization,
                attempt_id=first_attempt,
                match_run_id=first_run,
                purpose_code="MATCH_RETRY",
                command_id=first_command,
            )[0]
            self.assertEqual(
                self._resolve(
                    connection,
                    actor_user_id=actor,
                    session_id=session,
                    organization_id=organization,
                    attempt_id=second_attempt,
                    match_run_id=first_run,
                    purpose_code="MATCH_RETRY",
                    command_id=first_command,
                ),
                [],
            )
            self._configure_review(
                connection,
                seed=seed,
                attempt_id=second_attempt,
                match_run_id=second_run,
                purpose_code="INVITATION_REVIEW",
                command_id=second_command,
            )
            second = self._resolve(
                connection,
                actor_user_id=actor,
                session_id=session,
                organization_id=organization,
                attempt_id=second_attempt,
                match_run_id=second_run,
                purpose_code="INVITATION_REVIEW",
                command_id=second_command,
            )[0]

        self.assertEqual(bytes(first[10]), bytes(second[10]))
        self.assertNotEqual(bytes(first[11]), bytes(second[11]))
        self.assertEqual(first[12], second[12])
        self.assertEqual(
            self._configured_resolve(seed, purpose_code="BROWSER_CHOSEN"),
            [],
        )

    def test_valid_until_is_capped_by_duty_and_recent_auth_windows(self) -> None:
        duty_bound = self._seed()
        _duty_id, duty_expiry = self._grant_reviewer_duty(
            duty_bound,
            expires_offset=timedelta(minutes=2),
        )
        duty_row = self._configured_resolve(duty_bound)[0]
        self.assertLessEqual(duty_row[12], duty_expiry)
        self.assertGreater(duty_row[12], duty_bound.now)

        auth_bound = self._seed(auth_age=timedelta(minutes=29))
        self._grant_reviewer_duty(auth_bound)
        auth_row = self._configured_resolve(auth_bound)[0]
        self.assertGreater(auth_row[12], auth_bound.now)
        self.assertLessEqual(
            auth_row[12],
            auth_bound.now + timedelta(minutes=1, seconds=1),
        )

    def test_committed_duty_revocation_and_membership_conflict_fail_next_read(
        self,
    ) -> None:
        duty_seed = self._seed()
        duty_id, _expiry = self._grant_reviewer_duty(duty_seed)
        attempt_id = uuid4()
        match_run_id = uuid4()
        command_id = uuid4()
        with self._connect("matching_review") as connection:
            actor, session, organization = self._configure_review(
                connection,
                seed=duty_seed,
                attempt_id=attempt_id,
                match_run_id=match_run_id,
                purpose_code="ATTEMPT_REVIEW",
                command_id=command_id,
            )
            arguments = {
                "actor_user_id": actor,
                "session_id": session,
                "organization_id": organization,
                "attempt_id": attempt_id,
                "match_run_id": match_run_id,
                "purpose_code": "ATTEMPT_REVIEW",
                "command_id": command_id,
            }
            self.assertEqual(len(self._resolve(connection, **arguments)), 1)
            with self._admin() as admin:
                admin.execute("SET LOCAL session_replication_role = 'replica'")
                admin.execute(
                    "UPDATE iam.platform_duty_grants SET revoked_at=%s,"
                    "revocation_reason_code='TEST_CONCURRENT_REVOCATION',"
                    "aggregate_version=aggregate_version+1,updated_at=%s "
                    "WHERE id=%s",
                    (duty_seed.now, duty_seed.now, duty_id),
                )
            self.assertEqual(self._resolve(connection, **arguments), [])

        membership_seed = self._seed()
        self._grant_reviewer_duty(membership_seed)
        attempt_id = uuid4()
        match_run_id = uuid4()
        command_id = uuid4()
        with self._connect("matching_review") as connection:
            actor, session, organization = self._configure_review(
                connection,
                seed=membership_seed,
                attempt_id=attempt_id,
                match_run_id=match_run_id,
                purpose_code="INVITATION_REVIEW",
                command_id=command_id,
            )
            arguments = {
                "actor_user_id": actor,
                "session_id": session,
                "organization_id": organization,
                "attempt_id": attempt_id,
                "match_run_id": match_run_id,
                "purpose_code": "INVITATION_REVIEW",
                "command_id": command_id,
            }
            self.assertEqual(len(self._resolve(connection, **arguments)), 1)
            with self._admin() as admin:
                admin.execute("SET LOCAL session_replication_role = 'replica'")
                admin.execute(
                    "INSERT INTO iam.memberships("
                    "id,organization_id,user_id,status,source_invitation_id,"
                    "aggregate_version,created_at,updated_at) "
                    "VALUES(%s,%s,%s,'ACTIVE',%s,53,%s,%s)",
                    (
                        uuid4(),
                        membership_seed.other_organization_id,
                        membership_seed.actor_user_id,
                        uuid4(),
                        membership_seed.now - timedelta(days=1),
                        membership_seed.now,
                    ),
                )
            self.assertEqual(self._resolve(connection, **arguments), [])

    def test_wrong_scope_role_and_direct_table_access_are_denied(self) -> None:
        seed = self._seed()
        self._grant_reviewer_duty(seed)
        self.assertEqual(
            self._configured_resolve(seed, scope_kind="WRONG_SCOPE"),
            [],
        )

        with self._connect("matching_assignment") as connection:
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                connection.execute(
                    RESOLVER_SQL,
                    (
                        seed.actor_user_id,
                        seed.session_id,
                        seed.other_organization_id,
                        uuid4(),
                        uuid4(),
                        "ATTEMPT_REVIEW",
                        uuid4(),
                    ),
                ).fetchall()

        with self._connect("matching_review") as connection:
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                connection.execute(
                    "SELECT id FROM iam.platform_duty_grants"
                ).fetchall()

    def test_all_prior_editor_marker_contexts_remain_callable(self) -> None:
        seed = self._seed()
        self._grant_reviewer_duty(seed)
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

        with self._connect("demand_review") as connection:
            for name, value in (
                ("app.scope_kind", "DEMAND_REVIEW"),
                ("app.actor_id", seed.actor_user_id),
                ("app.session_id", seed.session_id),
                ("app.organization_id", seed.other_organization_id),
                ("app.operation", "VERIFY"),
                ("app.demand_id", demand_id),
                ("app.assignment_id", uuid4()),
            ):
                self._set_local(connection, name, value)
            assignment_id = UUID(
                connection.execute(
                    "SELECT current_setting('app.assignment_id')"
                ).fetchone()[0]
            )
            demand_review_marker = connection.execute(
                "SELECT authority_marker_sha256 FROM "
                "iam_api.resolve_demand_reviewer_authority_marker_v2("
                "%s,%s,%s,'VERIFY',%s,%s)",
                (
                    seed.actor_user_id,
                    seed.session_id,
                    seed.other_organization_id,
                    demand_id,
                    assignment_id,
                ),
            ).fetchone()
            self.assertIsNotNone(demand_review_marker)

        selection_id = uuid4()
        selector_demand_id = uuid4()
        selector_command_id = uuid4()
        with self._connect("matching_assignment") as connection:
            for name, value in (
                ("app.scope_kind", "MATCHING_ASSIGNMENT"),
                ("app.operation", "OPT_IN_CANDIDATE_SELECTOR"),
                ("app.actor_user_id", seed.actor_user_id),
                ("app.session_id", seed.session_id),
                ("app.organization_id", seed.organization_id),
                ("app.selection_id", selection_id),
                ("app.demand_id", selector_demand_id),
                ("app.command_id", selector_command_id),
            ):
                self._set_local(connection, name, value)
            iam44 = connection.execute(
                "SELECT authority_marker_sha256,evidence_sha256 FROM "
                "iam_api.resolve_candidate_selector_opt_in_marker_v1("
                "%s,%s,%s,%s,%s,%s)",
                (
                    seed.actor_user_id,
                    seed.session_id,
                    seed.organization_id,
                    selection_id,
                    selector_demand_id,
                    selector_command_id,
                ),
            ).fetchone()
            self.assertIsNotNone(iam44)
            self.assertEqual(bytes(iam44[0]), editor_marker)
            self.assertEqual(len(bytes(iam44[1])), 32)


if __name__ == "__main__":
    unittest.main()
