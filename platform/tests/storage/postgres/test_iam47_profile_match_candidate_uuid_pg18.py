"""Real matcher-session RLS evidence for IAM47 canonical candidate UUIDs."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import re
import unittest
from uuid import uuid4

import psycopg
from psycopg import sql

from tests.storage.postgres import (
    test_creator_profile_postgres_red as profile,
    test_iam44_candidate_selector_opt_in_authority_pg18 as iam44,
    test_iam46_matching_creator_authority_pg18 as iam46,
)
from tests.support.creator_profile_postgres_builders import (
    seed_exact_creator_iam_authority,
)


class Iam47ProfileMatchCandidateUuidPostgres18Test(unittest.TestCase):
    _seed_eligible_creator_clones = (
        profile.RealPostgres18CreatorProfileSemanticRedTest._seed_eligible_creator_clones
    )
    _v4_id = staticmethod(profile.RealPostgres18CreatorProfileSemanticRedTest._v4_id)
    _admin = classmethod(iam44.Iam44CandidateSelectorOptInPostgres18Test._admin.__func__)
    _admin_class = _admin
    _connect = classmethod(
        iam46.Iam46MatchingCreatorAuthorityPostgres18Test._connect.__func__
    )
    _set_local = staticmethod(iam44.Iam44CandidateSelectorOptInPostgres18Test._set_local)
    _configure_profile = (
        iam46.Iam46MatchingCreatorAuthorityPostgres18Test._configure_profile
    )
    tearDownClass = classmethod(
        iam44.Iam44CandidateSelectorOptInPostgres18Test.tearDownClass.__func__
    )

    @classmethod
    def setUpClass(cls) -> None:
        iam44.Iam44CandidateSelectorOptInPostgres18Test.setUpClass.__func__(cls)
        with cls._admin() as connection:
            cls.iam_authority = seed_exact_creator_iam_authority(
                connection, now=datetime.now(timezone.utc)
            )
        # These isolated probes preserve the real profile_matcher session and
        # schema_owner definer identity. They deliberately do not set candidate
        # context, so malformed input reaches the actual SELECT/row-mark RLS.
        # No IAM relation privilege or production-function ACL is changed.
        with cls._admin() as connection:
            connection.execute("CREATE SCHEMA iam47_test AUTHORIZATION schema_owner")
            connection.execute("SET LOCAL ROLE schema_owner")
            relations = {
                "user": ("users", "id = exact_user"),
                "grant": (
                    "user_role_grants",
                    "user_id = exact_user AND role_code = 'CREATOR'",
                ),
                "invitation": (
                    "access_invitations", "accepted_by_user_id = exact_user"
                ),
                "selector": ("policy_selectors", "selector_digest = exact_selector"),
                "acceptance": ("policy_acceptances", "user_id = exact_user"),
            }
            for kind, (table, predicate) in relations.items():
                for locking in (False, True):
                    function = kind + ("_lock" if locking else "_read")
                    query = (
                        f"SELECT count(*) FROM (SELECT 1 FROM iam.{table} "
                        f"WHERE {predicate}"
                        + (" FOR KEY SHARE" if locking else "")
                        + ") AS visible_rows"
                    )
                    connection.execute(
                        sql.SQL(
                            "CREATE FUNCTION iam47_test.{}("
                            "exact_user uuid, exact_selector bytea) "
                            "RETURNS bigint LANGUAGE sql SECURITY DEFINER VOLATILE "
                            "SET search_path=pg_catalog,iam AS {}"
                        ).format(sql.Identifier(function), sql.Literal(query))
                    )
                    connection.execute(
                        sql.SQL(
                            "REVOKE ALL ON FUNCTION "
                            "iam47_test.{}(uuid,bytea) FROM PUBLIC"
                        ).format(sql.Identifier(function))
                    )
                    connection.execute(
                        sql.SQL(
                            "GRANT EXECUTE ON FUNCTION "
                            "iam47_test.{}(uuid,bytea) TO profile_matcher"
                        ).format(sql.Identifier(function))
                    )
            connection.execute("GRANT USAGE ON SCHEMA iam47_test TO profile_matcher")

    def _candidate_user(self):
        return self._seed_eligible_creator_clones(
            label="iam47-probe-" + str(uuid4()), count=1
        )[0]

    def _replace_candidate_policies(self, *, legacy: bool) -> None:
        root = Path(__file__).resolve().parents[3] / (
            "src/desire_platform/identity_access/adapters/postgres/migrations"
        )
        filename = (
            "0046_expand__matching_creator_authority.sql" if legacy
            else "0047_expand__profile_match_candidate_uuid_predicates.sql"
        )
        statements = re.findall(
            r"(?:CREATE|ALTER) POLICY "
            r"(rls_profile_match_derivation_"
            r"(?:user|grant|invitation|selector|acceptance)_(?:definer|lock)_v1)"
            r"\nON (iam\.\w+)\n(?:FOR (?:SELECT|UPDATE) TO schema_owner\n)?USING \((.*?)\n\);",
            (root / filename).read_text(), re.DOTALL,
        )
        self.assertEqual(len(statements), 10)
        with self._admin() as connection:
            for name, table, body in statements:
                connection.execute(sql.SQL("ALTER POLICY {} ON {} USING ({})").format(
                    sql.Identifier(name), sql.Identifier(*table.split(".")), sql.SQL(body)
                ))

    def _probe_candidate(self, candidate, actor_user_id, selector):
        observed = {}
        with self._connect("profile_matcher") as connection:
            self._configure_profile(
                connection, match_run_id=uuid4(), workload_id=uuid4(),
                authorization_digest=b"a" * 32, demand_context_digest=b"b" * 32,
            )
            if candidate is not None:
                self._set_local(connection, "app.iam_profile_candidate_user_id", candidate)
            for kind in ("user", "grant", "invitation", "selector", "acceptance"):
                for command in ("read", "lock"):
                    try:
                        with connection.transaction():
                            observed[kind, command] = connection.execute(
                                sql.SQL("SELECT iam47_test.{}(%s,%s)").format(
                                    sql.Identifier(kind + "_" + command)
                                ), (actor_user_id, selector),
                            ).fetchone()[0]
                    except psycopg.errors.InvalidTextRepresentation as error:
                        # Legacy IAM15 also reads this GUC with an unguarded
                        # UUID cast. PostgreSQL may evaluate that other RLS
                        # branch while planning an artificial direct probe.
                        # Compare its exact rejection before/after IAM47;
                        # production resolvers always install typed UUIDs.
                        observed[kind, command] = error.sqlstate
        return observed

    def test_select_and_row_mark_policies_preserve_every_candidate_boundary(self) -> None:
        actor_user_id = self._candidate_user()
        with self._admin() as connection:
            selector = bytes(connection.execute(
                "SELECT policy_selector_digest FROM iam.user_role_grants "
                "WHERE user_id=%s AND role_code='CREATOR'", (actor_user_id,),
            ).fetchone()[0])
        canonical = str(actor_user_id)
        self.assertNotEqual(canonical.upper(), canonical)
        candidates = (
            None, "", canonical, str(uuid4()), canonical.upper(),
            canonical.replace("-", ""), "{" + canonical + "}",
            " " + canonical, canonical + " ", canonical + "\n",
            "g" + canonical[1:], canonical + "0",
            "00000000-0000-0000-0000-000000000000",
        )
        self._replace_candidate_policies(legacy=True)
        try:
            before = {
                candidate: self._probe_candidate(candidate, actor_user_id, selector)
                for candidate in candidates
            }
        finally:
            self._replace_candidate_policies(legacy=False)
        for candidate in candidates:
            with self.subTest(candidate=candidate):
                after = self._probe_candidate(candidate, actor_user_id, selector)
                self.assertEqual(after, before[candidate])
                for count_or_state in after.values():
                    if candidate == canonical:
                        self.assertEqual(count_or_state, 1)
                    else:
                        self.assertIn(count_or_state, (0, "22P02"))

    def test_new_case_expression_rejects_malformed_values_without_cast_errors(self) -> None:
        root = Path(__file__).resolve().parents[3] / (
            "src/desire_platform/identity_access/adapters/postgres/migrations"
        )
        migration = (root / "0047_expand__profile_match_candidate_uuid_predicates.sql").read_text()
        expression = re.search(r"AND id = (CASE.*?\n    END)", migration, re.DOTALL).group(1)
        canonical = "abcdef01-2345-0000-0000-123456789abc"
        with self._connect("profile_matcher") as connection:
            for candidate in (
                "", canonical, canonical.upper(), canonical.replace("-", ""),
                "{" + canonical + "}", " " + canonical, canonical + " ",
                canonical + "\n", "g" + canonical[1:], canonical + "0",
                "00000000-0000-0000-0000-000000000000",
            ):
                with self.subTest(candidate=candidate):
                    self._set_local(connection, "app.iam_profile_candidate_user_id", candidate)
                    actual = connection.execute(sql.SQL("SELECT " + expression)).fetchone()[0]
                    expected = candidate if candidate in (
                        canonical, "00000000-0000-0000-0000-000000000000"
                    ) else None
                    self.assertEqual(str(actual) if actual is not None else None, expected)

    def test_closed_outer_context_and_direct_relation_denial_are_preserved(self) -> None:
        actor_user_id = self._candidate_user()
        with self._connect("profile_matcher") as connection:
            self._set_local(connection, "app.iam_profile_candidate_user_id", actor_user_id)
            self.assertEqual(connection.execute(
                "SELECT iam47_test.user_read(%s,NULL)", (actor_user_id,),
            ).fetchone()[0], 0)
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                connection.execute("SELECT id FROM iam.users")
