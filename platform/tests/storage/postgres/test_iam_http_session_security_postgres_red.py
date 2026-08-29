"""Semantic RED for production IAM HTTP Session security on PostgreSQL 18.

The current IAM catalog is always loaded dynamically and applied through the
production runner.  Test helpers turn only closed adapter outcomes into values;
an import, migration, fixture, SQL leak, or PostgreSQL dependency failure is not
accepted as RED evidence.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import timezone
from pathlib import Path
import threading
from typing import Any, Optional
import unittest
import uuid

import psycopg

from desire_platform.http.contracts import AuthenticatedHttpActor
from desire_platform.http.iam_security import (
    PsycopgIamSessionSecurity,
    SessionSecuritySettings,
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
from tests.support.iam_session_security_postgres_builders import (
    ACTIVE_CSRF_KEY_ID,
    ACTIVE_HANDLE_KEY_ID,
    DeterministicSessionSecurityIdSource,
    DeterministicSessionSecurityKeyring,
    OLD_HANDLE_KEY_ID,
    RAW_ACTIVE_HANDLE,
    RAW_REPLAYED_HANDLE,
    RAW_UNKNOWN_HANDLE,
    RAW_WRONG_CSRF_TOKEN,
    SessionSecurityPostgresFixture,
    TrackingSessionSecurityConnectionSource,
    reset_session_security_database,
    seed_session_security_graph,
)


PLATFORM_ROOT = Path(__file__).resolve().parents[3]
MIGRATION_ROOT = (
    PLATFORM_ROOT
    / "src/desire_platform/identity_access/adapters/postgres/migrations"
)
SYSTEM_SESSION_SECURITY_ACTOR_ID = uuid.UUID(
    "00000000-0000-5000-8000-000000000017"
)

COOKIE_V1_COLUMNS = (
    "session_id",
    "user_id",
    "family_id",
    "generation",
    "session_status",
    "handle_digest_key_id",
    "handle_digest",
    "csrf_salt",
    "csrf_key_id",
    "csrf_digest",
    "auth_time",
    "acr_code",
    "amr_codes",
    "idle_expires_at",
    "absolute_expires_at",
    "verified_contact_point_id",
    "verified_at",
    "verified_for_invitation_id",
    "auth_transaction_id",
    "device_label",
    "session_aggregate_version",
    "family_status",
    "current_generation",
    "family_aggregate_version",
)
COOKIE_V2_COLUMNS = COOKIE_V1_COLUMNS + ("user_status",)


def _authentication_outcome(
    component: PsycopgIamSessionSecurity,
    *,
    raw_handle: Optional[str],
    trace_id: str,
) -> tuple[Optional[AuthenticatedHttpActor], Optional[str]]:
    try:
        return (
            component.authenticate(
                raw_session_handle=raw_handle,
                trace_id=trace_id,
            ),
            None,
        )
    except IamError as error:
        return (None, error.code)


def _csrf_outcome(
    component: PsycopgIamSessionSecurity,
    *,
    raw_handle: str,
    raw_token: Optional[str],
    actor: AuthenticatedHttpActor,
    operation_id: str = "grantConsent",
) -> Optional[str]:
    try:
        component.require_valid(
            raw_session_handle=raw_handle,
            raw_csrf_token=raw_token,
            actor=actor,
            operation_id=operation_id,
        )
    except IamError as error:
        return error.code
    return None


class RealPostgres18IamHttpSessionSecurityRedTest(unittest.TestCase):
    """TEST-HTTP-IAM-SESSION-003: exact retained-key Session security."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.postgres = TemporaryPostgres18().start()
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
        cls.database = cls.postgres.create_database()
        report = cls._run_migrations()
        expected = tuple(
            artifact.descriptor.version for artifact in cls.catalog.artifacts
        )
        if report.applied_versions != expected:
            raise AssertionError("IAM catalog was not applied exactly")

    @classmethod
    def tearDownClass(cls) -> None:
        try:
            cls.postgres.drop_database(cls.database)
        finally:
            cls.postgres.stop()

    @classmethod
    def _run_migrations(cls):
        driver = PsycopgMigrationDriver(
            settings=PsycopgMigrationSettings(
                conninfo=cls.postgres.conninfo(
                    database=cls.database,
                    user="iam_migration_runner",
                ),
                application_name="desire-iam-http-session-pg18-red",
            ),
            dbapi=psycopg,
        )
        return IamMigrationRunner(
            driver=driver,
            runner_version="iam-http-session-pg18-red/1",
        ).run(catalog=cls.catalog, contract_sources=cls.contract_sources)

    def setUp(self) -> None:
        self.sources: list[TrackingSessionSecurityConnectionSource] = []
        self.keyring = DeterministicSessionSecurityKeyring()
        self.fixture = self._reset_and_seed()

    def tearDown(self) -> None:
        for source in self.sources:
            source.close()

    def _admin(self, *, autocommit: bool = False):
        return psycopg.connect(
            self.postgres.admin_conninfo(database=self.database),
            options="-c timezone=UTC",
            autocommit=autocommit,
        )

    def _runtime(self, *, autocommit: bool = True):
        return psycopg.connect(
            self.postgres.conninfo(
                database=self.database,
                user="iam_session_authenticator",
            ),
            autocommit=autocommit,
        )

    def _reset_and_seed(
        self,
        *,
        active_handle_key_id: str = ACTIVE_HANDLE_KEY_ID,
    ) -> SessionSecurityPostgresFixture:
        with self._admin() as connection:
            reset_session_security_database(connection)
            fixture = seed_session_security_graph(
                connection,
                self.keyring,
                active_handle_key_id=active_handle_key_id,
            )
        return fixture

    def _source(self, **options: Any) -> TrackingSessionSecurityConnectionSource:
        source = TrackingSessionSecurityConnectionSource(
            self.postgres.conninfo(
                database=self.database,
                user="iam_session_authenticator",
            ),
            **options,
        )
        self.sources.append(source)
        return source

    def _component(
        self,
        *,
        source: Optional[TrackingSessionSecurityConnectionSource] = None,
        keyring: Optional[DeterministicSessionSecurityKeyring] = None,
        id_label: str = "session-security",
    ) -> tuple[
        PsycopgIamSessionSecurity,
        TrackingSessionSecurityConnectionSource,
        DeterministicSessionSecurityIdSource,
    ]:
        selected_source = source or self._source()
        ids = DeterministicSessionSecurityIdSource(id_label)
        component = PsycopgIamSessionSecurity(
            connections=selected_source,
            keyring=keyring or self.keyring,
            id_source=ids,
            settings=SessionSecuritySettings(),
        )
        return component, selected_source, ids

    def _expected_actor(self) -> AuthenticatedHttpActor:
        with self._admin() as connection:
            row = connection.execute(
                "SELECT user_id,id,auth_time,acr_code,amr_codes "
                "FROM iam.sessions WHERE id=%s",
                (self.fixture.current_session_id,),
            ).fetchone()
        trace = str(self.fixture.trace_id)
        return AuthenticatedHttpActor(
            actor_user_id=str(row[0]),
            session_id=str(row[1]),
            correlation_id=trace,
            causation_id=trace,
            trace_id=trace,
            original_actor_id=None,
            auth_time=row[2].astimezone(timezone.utc),
            acr_code=row[3],
            amr_codes=tuple(row[4]),
        )

    def test_catalog_publishes_closed_v2_view_and_replay_marker_capability(self) -> None:
        """The head must expose v2+User and the exact append-only replay ledger."""

        with self._admin() as connection:
            view_oid = connection.execute(
                "SELECT pg_catalog.to_regclass("
                "'iam_api.resolve_cookie_session_v2')::pg_catalog.oid"
            ).fetchone()[0]
            marker_oid = connection.execute(
                "SELECT pg_catalog.to_regclass("
                "'iam.session_security_events')::pg_catalog.oid"
            ).fetchone()[0]
            replay_function_acl = connection.execute(
                "SELECT "
                "pg_catalog.has_function_privilege("
                "'iam_session_authenticator',"
                "'iam_api.revoke_replayed_session_family_v1("
                "uuid,uuid,uuid,uuid,uuid,uuid)','EXECUTE'),"
                "pg_catalog.has_function_privilege("
                "'iam_app','iam_api.revoke_replayed_session_family_v1("
                "uuid,uuid,uuid,uuid,uuid,uuid)','EXECUTE'),"
                "pg_catalog.has_function_privilege("
                "'public','iam_api.revoke_replayed_session_family_v1("
                "uuid,uuid,uuid,uuid,uuid,uuid)','EXECUTE'),"
                "pg_catalog.has_function_privilege("
                "'public','iam.reject_session_security_event_mutation()',"
                "'EXECUTE')"
            ).fetchone()
            view_columns = tuple(
                row[0]
                for row in connection.execute(
                    "SELECT column_name FROM information_schema.columns "
                    "WHERE table_schema='iam_api' "
                    "AND table_name='resolve_cookie_session_v2' "
                    "ORDER BY ordinal_position"
                ).fetchall()
            )
            marker_columns = tuple(
                row[0]
                for row in connection.execute(
                    "SELECT column_name FROM information_schema.columns "
                    "WHERE table_schema='iam' "
                    "AND table_name='session_security_events' "
                    "ORDER BY ordinal_position"
                ).fetchall()
            )
            view_facts = None
            if view_oid is not None:
                view_facts = connection.execute(
                    "SELECT owner.rolname,relation.reloptions,"
                    "pg_catalog.has_table_privilege("
                    "'iam_session_authenticator',relation.oid,'SELECT'),"
                    "pg_catalog.has_table_privilege('public',relation.oid,'SELECT') "
                    "FROM pg_catalog.pg_class AS relation "
                    "JOIN pg_catalog.pg_roles AS owner ON owner.oid=relation.relowner "
                    "WHERE relation.oid=%s",
                    (view_oid,),
                ).fetchone()
            marker_facts = None
            marker_constraints: tuple[str, ...] = ()
            marker_triggers: tuple[str, ...] = ()
            if marker_oid is not None:
                marker_facts = connection.execute(
                    "SELECT owner.rolname,relation.relrowsecurity,"
                    "relation.relforcerowsecurity,"
                    "pg_catalog.has_table_privilege("
                    "'iam_session_authenticator',relation.oid,'SELECT'),"
                    "pg_catalog.has_table_privilege("
                    "'iam_session_authenticator',relation.oid,'INSERT'),"
                    "pg_catalog.has_table_privilege('public',relation.oid,'SELECT'),"
                    "pg_catalog.has_table_privilege('public',relation.oid,'INSERT') "
                    "FROM pg_catalog.pg_class AS relation "
                    "JOIN pg_catalog.pg_roles AS owner ON owner.oid=relation.relowner "
                    "WHERE relation.oid=%s",
                    (marker_oid,),
                ).fetchone()
                marker_constraints = tuple(
                    row[0]
                    for row in connection.execute(
                        "SELECT conname FROM pg_catalog.pg_constraint "
                        "WHERE conrelid=%s ORDER BY conname",
                        (marker_oid,),
                    ).fetchall()
                )
                marker_triggers = tuple(
                    row[0]
                    for row in connection.execute(
                        "SELECT tgname FROM pg_catalog.pg_trigger "
                        "WHERE tgrelid=%s AND NOT tgisinternal ORDER BY tgname",
                        (marker_oid,),
                    ).fetchall()
                )

        checks = {
            "v2 relation": view_oid is not None,
            "v2 exact columns": view_columns == COOKIE_V2_COLUMNS,
            "v2 owner and options": view_facts is not None
            and view_facts[0] == "schema_owner"
            and set(view_facts[1] or ())
            == {"security_barrier=true", "security_invoker=true"},
            "v2 role only": view_facts is not None
            and view_facts[2:] == (True, False),
            "marker relation": marker_oid is not None,
            "marker exact columns": marker_columns
            == (
                "security_event_id",
                "event_type",
                "session_family_id",
                "replayed_session_id",
                "user_id",
                "occurred_at",
            ),
            "marker owner force RLS and ACL": marker_facts is not None
            and marker_facts
            == ("schema_owner", True, True, True, True, False, False),
            "marker primary unique and exact FK": marker_oid is not None
            and len(marker_constraints) >= 4,
            "marker append-only trigger": any(
                "append" in name for name in marker_triggers
            ),
            "fixed program and trigger ACL": replay_function_acl
            == (True, False, False, False),
        }
        for label, condition in checks.items():
            with self.subTest(capability=label):
                self.assertTrue(
                    condition,
                    "semantic RED: IAM Session v2/replay capability is unavailable",
                )

        component, _source, _ids = self._component()
        try:
            component.check_readiness(timeout_ms=1_000)
            readiness = None
        except RuntimeError as error:
            readiness = str(error)
        self.assertIsNone(
            readiness,
            "semantic RED: production Session security readiness is unavailable",
        )

    def test_active_current_session_uses_every_retained_candidate_and_row_actor(self) -> None:
        component, source, _ids = self._component()
        actor, code = _authentication_outcome(
            component,
            raw_handle=self.fixture.raw_active_handle,
            trace_id=str(self.fixture.trace_id),
        )
        candidate_keys = tuple(
            key_id
            for purpose, key_id in self.keyring.calls
            if purpose == "session-handle"
        )
        checks = (
            ("closed code", code is None),
            ("row actor", actor == self._expected_actor()),
            (
                "all retained candidates",
                candidate_keys == (ACTIVE_HANDLE_KEY_ID, OLD_HANDLE_KEY_ID),
            ),
            (
                "v2 query per candidate",
                sum("resolve_cookie_session_v2" in item for item in source.trace)
                == 2,
            ),
            (
                "legacy v1 never called",
                not any(
                    "resolve_cookie_session_v1" in item for item in source.trace
                ),
            ),
            (
                "safe pool disposition",
                (len(source.released), len(source.discarded)) == (1, 0),
            ),
        )
        for label, condition in checks:
            with self.subTest(check=label):
                self.assertTrue(
                    condition,
                    "semantic RED: ACTIVE exact retained-key Session is unavailable",
                )

    def test_active_session_under_old_retained_handle_key_authenticates(self) -> None:
        self.fixture = self._reset_and_seed(active_handle_key_id=OLD_HANDLE_KEY_ID)
        component, source, _ids = self._component()
        actor, code = _authentication_outcome(
            component,
            raw_handle=self.fixture.raw_active_handle,
            trace_id=str(self.fixture.trace_id),
        )
        checks = {
            "closed code": code is None,
            "row actor": actor == self._expected_actor(),
            "retained order": tuple(
                key_id
                for purpose, key_id in self.keyring.calls
                if purpose == "session-handle"
            )
            == (ACTIVE_HANDLE_KEY_ID, OLD_HANDLE_KEY_ID),
            "pool disposition": len(source.discarded) == 0,
        }
        for label, condition in checks.items():
            with self.subTest(check=label):
                self.assertTrue(
                    condition,
                    "semantic RED: old retained Session handle is unavailable",
                )

    def test_missing_retained_handle_key_is_503_before_database_checkout(self) -> None:
        self.keyring.remove_key_material(OLD_HANDLE_KEY_ID)
        component, source, _ids = self._component()
        actor, code = _authentication_outcome(
            component,
            raw_handle=self.fixture.raw_active_handle,
            trace_id=str(self.fixture.trace_id),
        )
        self.assertIsNone(actor)
        self.assertEqual(code, "SERVICE_UNAVAILABLE")
        self.assertEqual(
            len(source.checked_out),
            0,
            "missing configured retained material must fail before SQL",
        )
        self.assertNotIn(self.fixture.raw_active_handle, repr(component))

    def test_absent_invalid_and_unknown_handles_share_closed_outcomes(self) -> None:
        component, source, _ids = self._component()
        absent_actor, absent_code = _authentication_outcome(
            component,
            raw_handle=None,
            trace_id=str(self.fixture.trace_id),
        )
        with self.subTest(carrier="absent"):
            self.assertEqual((absent_actor, absent_code), (None, None))
        invalid_handles = (
            "",
            "short",
            "A" * 42,
            "A" * 43 + "=",
            "A" * 42 + "$",
            "界" * 43,
            "A" * 129,
        )
        for raw_handle in invalid_handles:
            with self.subTest(raw_handle_length=len(raw_handle)):
                actor, code = _authentication_outcome(
                    component,
                    raw_handle=raw_handle,
                    trace_id=str(self.fixture.trace_id),
                )
                self.assertEqual((actor, code), (None, "AUTHENTICATION_REQUIRED"))
        with self.subTest(carrier="invalid database boundary"):
            self.assertEqual(
                len(source.checked_out),
                0,
                "absent/invalid carriers reached the database",
            )

        unknown_actor, unknown_code = _authentication_outcome(
            component,
            raw_handle=RAW_UNKNOWN_HANDLE,
            trace_id=str(self.fixture.trace_id),
        )
        with self.subTest(carrier="unknown"):
            self.assertEqual(
                (unknown_actor, unknown_code),
                (None, "AUTHENTICATION_REQUIRED"),
            )
        with self.subTest(carrier="unknown database boundary"):
            self.assertEqual(len(source.checked_out), 1)

    def test_expired_equal_suspended_and_generation_drift_never_create_actor(self) -> None:
        mutations = (
            ("deadline equality", self._expire_at_database_now),
            ("materialized expired", self._materialize_expired_session),
            ("suspended user", self._suspend_user),
            ("generation drift", self._corrupt_generation),
        )
        for label, mutation in mutations:
            with self.subTest(state=label):
                self.fixture = self._reset_and_seed()
                mutation()
                component, _source, _ids = self._component(
                    id_label="expired-" + label
                )
                actor, code = _authentication_outcome(
                    component,
                    raw_handle=self.fixture.raw_active_handle,
                    trace_id=str(self.fixture.trace_id),
                )
                self.assertIsNone(actor)
                self.assertEqual(code, "SESSION_EXPIRED")

    def test_csrf_re_resolves_and_verifies_row_derived_and_request_digests(self) -> None:
        actor = self._expected_actor()
        component, source, _ids = self._component()
        code = _csrf_outcome(
            component,
            raw_handle=self.fixture.raw_active_handle,
            raw_token=self.fixture.active_csrf_token,
            actor=actor,
        )
        csrf_digest_calls = tuple(
            item for item in self.keyring.calls if item[0] == "csrf-digest"
        )
        checks = {
            "closed code": code is None,
            "independent all-key resolve": sum(
                "resolve_cookie_session_v2" in item for item in source.trace
            )
            == 2,
            "row and request digest": csrf_digest_calls
            == (
                ("csrf-digest", ACTIVE_CSRF_KEY_ID),
                ("csrf-digest", ACTIVE_CSRF_KEY_ID),
            ),
        }
        for label, condition in checks.items():
            with self.subTest(check=label):
                self.assertTrue(
                    condition,
                    "semantic RED: persisted CSRF verification is unavailable",
                )

    def test_csrf_rejects_request_actor_operation_key_and_row_corruption(self) -> None:
        cases = (
            (
                "missing request token",
                None,
                None,
                "grantConsent",
                "INVALID_REQUEST",
                2,
            ),
            (
                "mismatched request token",
                RAW_WRONG_CSRF_TOKEN,
                None,
                "grantConsent",
                "INVALID_REQUEST",
                2,
            ),
            (
                "wrong actor",
                self.fixture.active_csrf_token,
                "actor",
                "grantConsent",
                "SERVICE_UNAVAILABLE",
                2,
            ),
            (
                "unknown operation",
                self.fixture.active_csrf_token,
                None,
                "unknownUnsafeOperation",
                "SERVICE_UNAVAILABLE",
                0,
            ),
        )
        for label, token, actor_mode, operation, expected, expected_queries in cases:
            actor = self._expected_actor()
            if actor_mode == "actor":
                actor = replace(
                    actor,
                    actor_user_id="50000000-0000-4000-8000-000000000001",
                )
            component, source, _ids = self._component(id_label="csrf-" + label)
            code = _csrf_outcome(
                component,
                raw_handle=self.fixture.raw_active_handle,
                raw_token=token,
                actor=actor,
                operation_id=operation,
            )
            query_count = sum(
                "resolve_cookie_session_v2" in item for item in source.trace
            )
            with self.subTest(case=label, check="closed code"):
                self.assertEqual(
                    code,
                    expected,
                )
            with self.subTest(case=label, check="authority re-resolution"):
                self.assertEqual(
                    query_count,
                    expected_queries,
                    "CSRF request/actor checks ran before authority re-resolution",
                )

        self.fixture = self._reset_and_seed()
        self.keyring.remove_key_material(ACTIVE_CSRF_KEY_ID)
        component, _source, _ids = self._component(id_label="csrf-missing-key")
        self.assertEqual(
            _csrf_outcome(
                component,
                raw_handle=self.fixture.raw_active_handle,
                raw_token=self.fixture.active_csrf_token,
                actor=self._expected_actor(),
            ),
            "SERVICE_UNAVAILABLE",
        )

        self.keyring = DeterministicSessionSecurityKeyring()
        self.fixture = self._reset_and_seed()
        self._corrupt_csrf_digest()
        component, _source, _ids = self._component(id_label="csrf-corrupt-row")
        self.assertEqual(
            _csrf_outcome(
                component,
                raw_handle=self.fixture.raw_active_handle,
                raw_token=self.fixture.active_csrf_token,
                actor=self._expected_actor(),
            ),
            "SERVICE_UNAVAILABLE",
        )

    def test_revoked_old_handle_atomically_revokes_exact_family_with_events(self) -> None:
        component, _source, _ids = self._component(id_label="replay-first")
        actor, code = _authentication_outcome(
            component,
            raw_handle=self.fixture.raw_replayed_handle,
            trace_id=str(self.fixture.trace_id),
        )
        with self.subTest(check="closed replay outcome"):
            self.assertEqual((actor, code), (None, "AUTHENTICATION_REQUIRED"))
        snapshot = self._replay_snapshot()
        self._assert_single_replay_transition(snapshot)

    def test_concurrent_replay_has_exactly_one_monotonic_event_set(self) -> None:
        barrier = threading.Barrier(2, timeout=15)
        left_source = self._source(replay_barrier=barrier)
        right_source = self._source(replay_barrier=barrier)
        left, _source, _ids = self._component(
            source=left_source,
            id_label="replay-left",
        )
        right, _source, _ids = self._component(
            source=right_source,
            id_label="replay-right",
        )

        def invoke(component: PsycopgIamSessionSecurity):
            return _authentication_outcome(
                component,
                raw_handle=self.fixture.raw_replayed_handle,
                trace_id=str(self.fixture.trace_id),
            )

        with ThreadPoolExecutor(max_workers=2) as executor:
            outcomes = tuple(executor.map(invoke, (left, right)))
        with self.subTest(check="both replay outcomes"):
            self.assertEqual(
                outcomes,
                ((None, "AUTHENTICATION_REQUIRED"),) * 2,
            )
        self._assert_single_replay_transition(self._replay_snapshot())

    def test_replay_commit_ack_loss_discards_then_converges_on_new_connection(self) -> None:
        source = self._source(lose_replay_commit_ack=True)
        component, _source, _ids = self._component(
            source=source,
            id_label="replay-commit-unknown",
        )
        actor, code = _authentication_outcome(
            component,
            raw_handle=self.fixture.raw_replayed_handle,
            trace_id=str(self.fixture.trace_id),
        )
        checks = {
            "closed replay outcome": (actor, code)
            == (None, "AUTHENTICATION_REQUIRED"),
            "one lost acknowledgement": source.commit_ack_losses == 1,
            "tainted connection discarded": len(source.discarded) == 1,
            "fresh convergence backend": len(set(source.backend_pids)) >= 2,
        }
        for label, condition in checks.items():
            with self.subTest(check=label):
                self.assertTrue(
                    condition,
                    "semantic RED: COMMIT_SENT replay convergence is unavailable",
                )
        self._assert_single_replay_transition(self._replay_snapshot())

    def test_runtime_role_acl_rls_and_direct_business_access_are_closed(self) -> None:
        with self._admin() as connection:
            role = connection.execute(
                "SELECT rolname,rolsuper,rolbypassrls,rolinherit "
                "FROM pg_catalog.pg_roles "
                "WHERE rolname='iam_session_authenticator'"
            ).fetchone()
            view_oid = connection.execute(
                "SELECT pg_catalog.to_regclass("
                "'iam_api.resolve_cookie_session_v2')::pg_catalog.oid"
            ).fetchone()[0]
            v1_oid = connection.execute(
                "SELECT pg_catalog.to_regclass("
                "'iam_api.resolve_cookie_session_v1')::pg_catalog.oid"
            ).fetchone()[0]
            v2_select = (
                connection.execute(
                    "SELECT pg_catalog.has_table_privilege("
                    "'iam_session_authenticator',%s,'SELECT')",
                    (view_oid,),
                ).fetchone()[0]
                if view_oid is not None
                else False
            )
            v1_select = connection.execute(
                "SELECT pg_catalog.has_table_privilege("
                "'iam_session_authenticator',%s,'SELECT')",
                (v1_oid,),
            ).fetchone()[0]
        with self.subTest(check="role attributes"):
            self.assertEqual(
                role,
                ("iam_session_authenticator", False, False, False),
            )
        with self.subTest(check="v2 SELECT"):
            self.assertTrue(v2_select)
        with self.subTest(check="v1 compatibility retained"):
            self.assertTrue(
                v1_select,
                "forward migration revoked the previously published v1 view",
            )

        direct_statements = (
            "SELECT id FROM iam.users",
            "SELECT id FROM iam.session_families",
            "SELECT id FROM iam.sessions",
        )
        for statement in direct_statements:
            with self.subTest(statement=statement):
                with self._runtime() as connection:
                    try:
                        rows: Any = connection.execute(statement).fetchall()
                    except psycopg.Error as error:
                        rows = error.sqlstate
                self.assertIn(rows, ([], "42501"))

        with self._runtime() as connection:
            connection.execute(
                "SELECT pg_catalog.set_config('app.scope_kind',"
                "'SESSION_AUTHENTICATE',false)"
            )
            connection.execute(
                "SELECT pg_catalog.set_config('app.operation',"
                "'REVOKE_REPLAYED_FAMILY',false)"
            )
            connection.execute(
                "SELECT pg_catalog.set_config('app.actor_user_id',%s,false)",
                (str(self.fixture.user_id),),
            )
            connection.execute(
                "SELECT pg_catalog.set_config('app.session_family_id',%s,false)",
                (str(self.fixture.other_family_id),),
            )
            connection.execute(
                "SELECT pg_catalog.set_config('app.session_id',%s,false)",
                (str(self.fixture.replayed_session_id),),
            )
            connection.execute(
                "SELECT pg_catalog.set_config("
                "'app.session_handle_digest_key_id','forged-key',false)"
            )
            connection.execute(
                "SELECT pg_catalog.set_config("
                "'app.session_handle_digest',repeat('00',32),false)"
            )
            forged_family_rows = connection.execute(
                "SELECT id FROM iam.session_families"
            ).fetchall()
            forged_session_rows = connection.execute(
                "SELECT id FROM iam.sessions"
            ).fetchall()
        with self.subTest(check="forged replay scope"):
            self.assertEqual((forged_family_rows, forged_session_rows), ([], []))

        marker_outcome = self._attempt_arbitrary_marker_insert()
        with self.subTest(check="arbitrary marker append"):
            self.assertEqual(
                marker_outcome,
                "42501",
                "arbitrary GUCs or direct SQL could append a replay marker",
            )

    def test_pool_reset_close_ownership_and_secret_sentinel_are_closed(self) -> None:
        source = self._source(reuse_released=True)
        poisoned_pid = source.prime_reusable_connection()
        component, _source, _ids = self._component(source=source)
        outcomes = (
            _authentication_outcome(
                component,
                raw_handle=self.fixture.raw_active_handle,
                trace_id=str(self.fixture.trace_id),
            ),
            _authentication_outcome(
                component,
                raw_handle=self.fixture.raw_active_handle,
                trace_id=str(self.fixture.trace_id),
            ),
        )
        with self.subTest(check="same-pool successful outcomes"):
            self.assertEqual(
                outcomes,
                ((self._expected_actor(), None),) * 2,
            )
        with self.subTest(check="same backend reused"):
            self.assertEqual(set(source.backend_pids), {poisoned_pid})
        reusable = source._reusable_raw
        session_state = None
        if reusable is not None and not reusable.closed:
            session_state = source.reusable_session_state()
        with self.subTest(check="reusable connection survived"):
            self.assertIsNotNone(session_state)
        if session_state is not None:
            timezone_name, scope, operation, digest, transaction_state = session_state
            with self.subTest(check="UTC restored"):
                self.assertIn(timezone_name, ("UTC", "Etc/UTC"))
            with self.subTest(check="scope reset"):
                self.assertEqual(
                    (scope, operation, digest, transaction_state),
                    ("", "", "", "IDLE"),
                    "released Session security connection retained request scope",
                )

        inspected = "\n".join(
            (
                repr(component),
                repr(self.keyring),
                repr(outcomes),
                *source.trace,
                self._database_security_text(),
            )
        )
        for secret in (
            RAW_ACTIVE_HANDLE,
            RAW_REPLAYED_HANDLE,
            self.fixture.active_csrf_token,
            RAW_WRONG_CSRF_TOKEN,
            "pool-poison-secret",
        ):
            with self.subTest(secret=secret[:12]):
                self.assertNotIn(secret, inspected)

        component.close()
        reusable = source._reusable_raw
        with self.subTest(check="component does not own shared pool"):
            self.assertTrue(reusable is not None and not reusable.closed)
        actor, code = _authentication_outcome(
            component,
            raw_handle=self.fixture.raw_active_handle,
            trace_id=str(self.fixture.trace_id),
        )
        with self.subTest(check="closed component fails closed"):
            self.assertEqual((actor, code), (None, "SERVICE_UNAVAILABLE"))

    def _expire_at_database_now(self) -> None:
        with self._admin() as connection:
            connection.execute(
                "UPDATE iam.sessions SET "
                "last_activity_at=transaction_timestamp()-interval '1 second',"
                "idle_expires_at=transaction_timestamp(),"
                "updated_at=transaction_timestamp(),"
                "aggregate_version=aggregate_version+1 WHERE id=%s",
                (self.fixture.current_session_id,),
            )

    def _materialize_expired_session(self) -> None:
        with self._admin() as connection:
            connection.execute(
                "UPDATE iam.sessions SET status='EXPIRED',"
                "revoked_at=transaction_timestamp(),"
                "revocation_reason_code='SESSION_EXPIRED',"
                "updated_at=transaction_timestamp(),"
                "aggregate_version=aggregate_version+1 WHERE id=%s",
                (self.fixture.current_session_id,),
            )
            connection.execute(
                "UPDATE iam.session_families SET status='REVOKED',"
                "revoked_at=transaction_timestamp(),"
                "revocation_reason_code='SESSION_EXPIRED',"
                "updated_at=transaction_timestamp(),"
                "aggregate_version=aggregate_version+1 WHERE id=%s",
                (self.fixture.family_id,),
            )

    def _suspend_user(self) -> None:
        with self._admin() as connection:
            connection.execute(
                "UPDATE iam.users SET status='SUSPENDED',"
                "updated_at=transaction_timestamp(),"
                "aggregate_version=aggregate_version+1 WHERE id=%s",
                (self.fixture.user_id,),
            )

    def _corrupt_generation(self) -> None:
        with self._admin() as connection:
            connection.execute(
                "ALTER TABLE iam.session_families DISABLE TRIGGER ALL"
            )
            connection.execute(
                "UPDATE iam.session_families SET current_generation=3,"
                "updated_at=transaction_timestamp(),"
                "aggregate_version=aggregate_version+1 WHERE id=%s",
                (self.fixture.family_id,),
            )
            connection.execute(
                "ALTER TABLE iam.session_families ENABLE TRIGGER ALL"
            )

    def _corrupt_csrf_digest(self) -> None:
        with self._admin() as connection:
            connection.execute("ALTER TABLE iam.sessions DISABLE TRIGGER ALL")
            connection.execute(
                "UPDATE iam.sessions SET csrf_digest=decode(repeat('7f',32),'hex') "
                "WHERE id=%s",
                (self.fixture.current_session_id,),
            )
            connection.execute("ALTER TABLE iam.sessions ENABLE TRIGGER ALL")

    def _replay_snapshot(self) -> dict[str, Any]:
        with self._admin() as connection:
            family = connection.execute(
                "SELECT status,current_generation,revocation_reason_code,"
                "aggregate_version FROM iam.session_families WHERE id=%s",
                (self.fixture.family_id,),
            ).fetchone()
            other_family = connection.execute(
                "SELECT status,current_generation,revocation_reason_code,"
                "aggregate_version FROM iam.session_families WHERE id=%s",
                (self.fixture.other_family_id,),
            ).fetchone()
            sessions = tuple(
                connection.execute(
                    "SELECT id,status,revocation_reason_code,aggregate_version "
                    "FROM iam.sessions ORDER BY id"
                ).fetchall()
            )
            marker_exists = connection.execute(
                "SELECT pg_catalog.to_regclass('iam.session_security_events')"
            ).fetchone()[0]
            markers: tuple[Any, ...] = ()
            if marker_exists is not None:
                markers = tuple(
                    connection.execute(
                        "SELECT security_event_id,event_type,session_family_id,"
                        "replayed_session_id,user_id,occurred_at "
                        "FROM iam.session_security_events ORDER BY security_event_id"
                    ).fetchall()
                )
            audit = tuple(
                connection.execute(
                    "SELECT event_id,actor_kind,actor_id,action_code,target_kind,"
                    "target_id,before_status,after_status,before_version,"
                    "after_version,reason_code,result_code,command_id,"
                    "correlation_id,causation_id,trace_id,safe_attributes "
                    "FROM audit.audit_events "
                    "WHERE action_code='RevokeReplayedSessionFamily' "
                    "ORDER BY event_id"
                ).fetchall()
            )
            outbox = tuple(
                connection.execute(
                    "SELECT event_id,event_type,aggregate_type,aggregate_id,"
                    "aggregate_version,actor_kind,actor_id,correlation_id,"
                    "causation_id,trace_id,organization_id,payload,"
                    "delivery_status,attempt_count FROM infra.outbox_events "
                    "WHERE event_type='SessionRevoked' ORDER BY event_id"
                ).fetchall()
            )
        return {
            "family": family,
            "other_family": other_family,
            "sessions": sessions,
            "markers": markers,
            "audit": audit,
            "outbox": outbox,
        }

    def _assert_single_replay_transition(self, snapshot: dict[str, Any]) -> None:
        self.assertEqual(
            snapshot["family"],
            ("REVOKED", 2, "REPLAYED_SESSION_HANDLE", 2),
        )
        self.assertEqual(snapshot["other_family"], ("ACTIVE", 1, None, 1))
        sessions = {row[0]: row[1:] for row in snapshot["sessions"]}
        self.assertEqual(
            sessions[self.fixture.replayed_session_id],
            ("REVOKED", "TEST_PREDECESSOR_ROTATED", 1),
        )
        self.assertEqual(
            sessions[self.fixture.current_session_id],
            ("REVOKED", "REPLAYED_SESSION_HANDLE", 2),
        )
        self.assertEqual(
            sessions[self.fixture.other_session_id],
            ("ACTIVE", None, 1),
        )

        self.assertEqual(len(snapshot["markers"]), 1)
        marker = snapshot["markers"][0]
        self.assertEqual(
            marker[1:5],
            (
                "REPLAYED_SESSION_HANDLE",
                self.fixture.family_id,
                self.fixture.replayed_session_id,
                self.fixture.user_id,
            ),
        )
        self.assertEqual(marker[5].utcoffset().total_seconds(), 0)

        self.assertEqual(len(snapshot["audit"]), 1)
        audit = snapshot["audit"][0]
        self.assertEqual(
            audit[1:13],
            (
                "SYSTEM",
                SYSTEM_SESSION_SECURITY_ACTOR_ID,
                "RevokeReplayedSessionFamily",
                "SessionFamily",
                self.fixture.family_id,
                "ACTIVE",
                "REVOKED",
                1,
                2,
                "REPLAYED_SESSION_HANDLE",
                "SUCCEEDED",
                marker[0],
            ),
        )
        self.assertEqual(
            audit[13:16],
            (self.fixture.trace_id, marker[0], self.fixture.trace_id),
        )
        self.assertEqual(audit[16], {})

        self.assertEqual(len(snapshot["outbox"]), 1)
        outbox = snapshot["outbox"][0]
        self.assertEqual(
            outbox[1:11],
            (
                "SessionRevoked",
                "Session",
                self.fixture.current_session_id,
                2,
                "SYSTEM",
                SYSTEM_SESSION_SECURITY_ACTOR_ID,
                self.fixture.trace_id,
                marker[0],
                self.fixture.trace_id,
                None,
            ),
        )
        self.assertEqual(
            outbox[11],
            {
                "session_id": str(self.fixture.current_session_id),
                "session_family_id": str(self.fixture.family_id),
                "user_id": str(self.fixture.user_id),
                "status": "REVOKED",
            },
        )
        self.assertEqual(outbox[12:], ("PENDING", 0))

    def _attempt_arbitrary_marker_insert(self) -> str:
        with self._runtime() as connection:
            relation = connection.execute(
                "SELECT pg_catalog.to_regclass('iam.session_security_events')"
            ).fetchone()[0]
            if relation is None:
                return "CAPABILITY_MISSING"
            try:
                connection.execute(
                    "INSERT INTO iam.session_security_events ("
                    "security_event_id,event_type,session_family_id,"
                    "replayed_session_id,user_id,occurred_at) VALUES ("
                    "%s,'REPLAYED_SESSION_HANDLE',%s,%s,%s,"
                    "transaction_timestamp())",
                    (
                        uuid.uuid4(),
                        self.fixture.other_family_id,
                        self.fixture.replayed_session_id,
                        self.fixture.user_id,
                    ),
                )
                return "INSERTED"
            except psycopg.Error as error:
                return error.sqlstate or "DATABASE_ERROR"

    def _database_security_text(self) -> str:
        statements = (
            "SELECT row_to_json(item)::text FROM iam.sessions AS item",
            "SELECT row_to_json(item)::text FROM iam.session_families AS item",
            "SELECT row_to_json(item)::text FROM audit.audit_events AS item",
            "SELECT row_to_json(item)::text FROM infra.outbox_events AS item",
        )
        with self._admin() as connection:
            values = [
                row[0]
                for statement in statements
                for row in connection.execute(statement).fetchall()
            ]
            marker_exists = connection.execute(
                "SELECT pg_catalog.to_regclass('iam.session_security_events')"
            ).fetchone()[0]
            if marker_exists is not None:
                values.extend(
                    row[0]
                    for row in connection.execute(
                        "SELECT row_to_json(item)::text "
                        "FROM iam.session_security_events AS item"
                    ).fetchall()
                )
        return "\n".join(values)


if __name__ == "__main__":
    unittest.main()
