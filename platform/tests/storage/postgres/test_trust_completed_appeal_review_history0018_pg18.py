"""PostgreSQL 18 semantic proof for actor-bound Appeal review history."""

from __future__ import annotations

import json
import unittest
from uuid import UUID

import psycopg

from desire_platform.trust_safety.adapters.postgres.migrations import (
    TrustMigrationCatalog,
)
from tests.storage.postgres import test_trust_migration_runner_pg18 as runner_proof


def _uuid(value: int) -> UUID:
    return UUID(f"a6180000-0000-4000-8000-{value:012d}")


REVIEWER_ONE = _uuid(1)
REVIEWER_ONE_SESSION = _uuid(2)
REVIEWER_ONE_DUTY = _uuid(3)
REVIEWER_TWO = _uuid(4)
REVIEWER_TWO_SESSION = _uuid(5)
REVIEWER_TWO_DUTY = _uuid(6)
WRONG_SESSION = _uuid(7)

REVIEWER_ONE_OLD = _uuid(100)
REVIEWER_ONE_TIE_LOW = _uuid(101)
REVIEWER_ONE_TIE_HIGH = _uuid(102)
REVIEWER_ONE_EDITOR_MISMATCH = _uuid(103)
REVIEWER_ONE_DECIDER_MISMATCH = _uuid(104)
REVIEWER_TWO_ONLY = _uuid(200)


class TrustCompletedAppealReviewHistoryPostgres18Test(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        base = runner_proof.TrustMigrationRunnerPostgres18Test
        base.setUpClass()
        cls._base = base
        cls.postgres = base.postgres
        cls.database = base.database
        try:
            base._runner().run(
                catalog=TrustMigrationCatalog.load(runner_proof.TRUST_ROOT),
                contract_sources=base._contracts(),
            )
            cls._install_authority_stub()
            cls._seed_completed_reviews()
        except BaseException:
            base.tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls) -> None:
        cls._base.tearDownClass()

    @classmethod
    def _admin(cls):
        return psycopg.connect(
            cls.postgres.admin_conninfo(database=cls.database),
            autocommit=True,
        )

    @classmethod
    def _runtime(cls, role: str = "trust_appeal"):
        return psycopg.connect(
            cls.postgres.conninfo(database=cls.database, user=role),
            autocommit=True,
        )

    @classmethod
    def _install_authority_stub(cls) -> None:
        with cls._admin() as connection:
            connection.execute("SET ROLE schema_owner")
            connection.execute(
                f"""
                CREATE OR REPLACE FUNCTION
                iam_api.resolve_appeal_reviewer_authority_v1(
                    exact_actor_user_id uuid,
                    exact_session_id uuid,
                    exact_operation text
                ) RETURNS TABLE(
                    actor_user_id uuid,
                    session_id uuid,
                    user_status text,
                    session_status text,
                    session_family_status text,
                    duty_grant_id uuid,
                    duty_grant_version bigint,
                    duty_expires_at timestamptz,
                    duty_code text,
                    authority_marker_sha256 bytea
                ) LANGUAGE plpgsql SECURITY DEFINER VOLATILE PARALLEL UNSAFE
                SET search_path=pg_catalog AS $function$
                DECLARE
                    selected_duty uuid;
                BEGIN
                    IF session_user <> 'trust_appeal'
                       OR exact_operation <> 'READ_ASSIGNED_APPEAL'
                       OR current_setting(
                            'app.test_appeal_duty_revoked', true
                       ) = 'on'
                       OR NULLIF(current_setting('app.scope_kind', true), '')
                            IS DISTINCT FROM 'TRUST_APPEAL'
                       OR NULLIF(current_setting('app.operation', true), '')
                            IS DISTINCT FROM exact_operation
                       OR NULLIF(current_setting('app.actor_id', true), '')
                            IS DISTINCT FROM exact_actor_user_id::text
                       OR NULLIF(current_setting('app.session_id', true), '')
                            IS DISTINCT FROM exact_session_id::text
                    THEN
                        RETURN;
                    END IF;

                    IF exact_actor_user_id = '{REVIEWER_ONE}'::uuid
                       AND exact_session_id = '{REVIEWER_ONE_SESSION}'::uuid
                    THEN
                        selected_duty := '{REVIEWER_ONE_DUTY}'::uuid;
                    ELSIF exact_actor_user_id = '{REVIEWER_TWO}'::uuid
                       AND exact_session_id = '{REVIEWER_TWO_SESSION}'::uuid
                    THEN
                        selected_duty := '{REVIEWER_TWO_DUTY}'::uuid;
                    ELSE
                        RETURN;
                    END IF;

                    RETURN QUERY SELECT
                        exact_actor_user_id,
                        exact_session_id,
                        'ACTIVE',
                        'ACTIVE',
                        'ACTIVE',
                        selected_duty,
                        1::bigint,
                        CASE
                            WHEN current_setting(
                                'app.test_appeal_duty_expired', true
                            ) = 'on'
                            THEN transaction_timestamp() - interval '1 second'
                            ELSE transaction_timestamp() + interval '1 day'
                        END,
                        'APPEAL_REVIEWER',
                        sha256(convert_to(
                            exact_operation || exact_actor_user_id::text,
                            'UTF8'
                        ));
                END
                $function$
                """
            )
            connection.execute(
                "GRANT EXECUTE ON FUNCTION "
                "iam_api.resolve_appeal_reviewer_authority_v1("
                "uuid,uuid,text) TO trust_schema_owner"
            )

    @classmethod
    def _insert_completed_review(
        cls,
        connection,
        *,
        appeal_id: UUID,
        reviewer: UUID,
        duty: UUID,
        decided_at: str,
        decision_code: str,
        review_edited_by: UUID | None = None,
        decision_decided_by: UUID | None = None,
    ) -> None:
        assignment_id = _uuid(appeal_id.int % 10_000 + 1_000)
        decision_id = _uuid(appeal_id.int % 10_000 + 2_000)
        source_outcome_id = _uuid(appeal_id.int % 10_000 + 3_000)
        source_case_id = _uuid(appeal_id.int % 10_000 + 4_000)
        applicant = _uuid(appeal_id.int % 10_000 + 5_000)
        accepted = decision_code in {"MODIFY", "VACATE_AND_REMAND"}
        assessment_code = "ACCEPTED" if accepted else "REJECTED"
        finding_code = (
            "PROCEDURE_MATERIAL_ERROR"
            if accepted
            else "APPEAL_NOT_SUBSTANTIATED"
        )
        remedy_code = {
            "MODIFY": "NARROW_CORRECTIVE_MEASURE",
            "VACATE_AND_REMAND": "RETURN_TO_TRUST_REVIEW",
        }.get(decision_code, "NO_CHANGE")
        assessments = json.dumps(
            [
                {
                    "accepted_evidence_reference_ids": [],
                    "assessment_code": assessment_code,
                    "finding_codes": [finding_code],
                    "ground": "PROCEDURAL_ERROR",
                }
            ],
            separators=(",", ":"),
        )

        connection.execute(
            "INSERT INTO trust.appeals (appeal_id,"
            "source_outcome_version_id,source_case_id,organization_id,"
            "demand_id,demand_version_id,applicant_user_id,"
            "applicant_membership_id,applicant_role_grant_id,"
            "applicant_role_grant_version,"
            "applicant_authority_marker_sha256,"
            "applicant_party_marker_sha256,source_outcome_code,"
            "source_reason_codes,source_action_codes,"
            "source_evidence_packet_version_id,"
            "source_evidence_packet_sha256,source_policy_version,"
            "source_decided_at,source_appeal_deadline,source_content_sha256,"
            "source_deciding_officer_user_id,source_appeal_eligible,"
            "source_appeal_eligibility_code,status,aggregate_version,"
            "current_application_draft_version,submitted_application_version,"
            "current_assignment_id,current_review_draft_version,"
            "decision_version_id,opened_at,updated_at) VALUES ("
            "%s,%s,%s,%s,%s,%s,%s,%s,%s,1,"
            "decode(repeat('11',32),'hex'),decode(repeat('12',32),'hex'),"
            "'PROTECTION_MAINTAINED',"
            "ARRAY['PRECAUTIONARY_ACTION_REQUIRED']::text[],"
            "ARRAY['SUBMIT_DEMAND']::text[],%s,"
            "decode(repeat('13',32),'hex'),'trust-case-outcome-v1',"
            "'2026-01-01T00:00:00Z'::timestamptz,"
            "'2026-02-01T00:00:00Z'::timestamptz,"
            "decode(repeat('14',32),'hex'),%s,true,'ELIGIBLE','DECIDED',4,"
            "1,1,%s,1,%s,'2026-01-02T00:00:00Z'::timestamptz,"
            "%s::timestamptz)",
            (
                appeal_id,
                source_outcome_id,
                source_case_id,
                _uuid(9001),
                _uuid(9002),
                _uuid(9003),
                applicant,
                _uuid(appeal_id.int % 10_000 + 5_100),
                _uuid(appeal_id.int % 10_000 + 5_200),
                _uuid(appeal_id.int % 10_000 + 5_300),
                _uuid(9004),
                assignment_id,
                decision_id,
                decided_at,
            ),
        )
        connection.execute(
            "INSERT INTO trust.appeal_review_assignments (assignment_id,"
            "appeal_id,reviewer_user_id,duty_grant_id,duty_grant_version,"
            "authority_marker_sha256,conflict_attestation_sha256,"
            "conflict_evaluated_at,conflict_valid_until,assigned_at,expires_at) "
            "VALUES (%s,%s,%s,%s,1,decode(repeat('21',32),'hex'),"
            "decode(repeat('22',32),'hex'),"
            "'2026-01-02T00:00:00Z'::timestamptz,"
            "'2026-12-31T00:00:00Z'::timestamptz,"
            "'2026-01-03T00:00:00Z'::timestamptz,"
            "'2026-12-01T00:00:00Z'::timestamptz)",
            (assignment_id, appeal_id, reviewer, duty),
        )
        connection.execute(
            "INSERT INTO trust.appeal_application_versions (appeal_id,"
            "application_version,source_draft_version,grounds,"
            "requested_outcome,sealed_statement_reference,"
            "sealed_statement_sha256,sealed_statement_purpose_code,"
            "new_evidence_reference_ids,submitted_by_user_id,submitted_at) "
            "VALUES (%s,1,1,ARRAY['PROCEDURAL_ERROR']::text[],"
            "'REMOVE_MEASURE',%s,decode(repeat('31',32),'hex'),"
            "'APPEAL_STATEMENT',ARRAY[]::uuid[],%s,"
            "'2026-01-04T00:00:00Z'::timestamptz)",
            (appeal_id, f"appeal-statement://{appeal_id}", applicant),
        )
        connection.execute(
            "INSERT INTO trust.appeal_review_drafts (appeal_id,assignment_id,"
            "draft_version,assessments,reason_codes,remedy_delta_codes,"
            "sealed_review_note_reference,sealed_review_note_sha256,"
            "sealed_review_note_purpose_code,edited_by_user_id,edited_at) "
            "VALUES (%s,%s,1,%s::jsonb,"
            "ARRAY['PROCEDURAL_REVIEW_COMPLETE']::text[],"
            "ARRAY[%s]::text[],%s,decode(repeat('32',32),'hex'),"
            "'APPEAL_REVIEW_NOTE',%s,%s::timestamptz)",
            (
                appeal_id,
                assignment_id,
                assessments,
                remedy_code,
                f"appeal-review-note://{appeal_id}",
                review_edited_by or reviewer,
                decided_at,
            ),
        )
        connection.execute(
            "INSERT INTO trust.appeal_decision_versions (decision_version_id,"
            "appeal_id,decision_version,source_outcome_version_id,"
            "source_outcome_sha256,source_application_version,"
            "source_assignment_id,source_review_draft_version,decision_code,"
            "assessments,reason_codes,remedy_delta_codes,policy_version,"
            "policy_marker_sha256,decided_by_user_id,decided_at,"
            "decision_sha256) VALUES (%s,%s,1,%s,"
            "decode(repeat('14',32),'hex'),1,%s,1,%s,%s::jsonb,"
            "ARRAY['PROCEDURAL_REVIEW_COMPLETE']::text[],"
            "ARRAY[%s]::text[],'appeal-decision-v1',"
            "decode(repeat('41',32),'hex'),%s,%s::timestamptz,"
            "decode(repeat('42',32),'hex'))",
            (
                decision_id,
                appeal_id,
                source_outcome_id,
                assignment_id,
                decision_code,
                assessments,
                remedy_code,
                decision_decided_by or reviewer,
                decided_at,
            ),
        )

    @classmethod
    def _seed_completed_reviews(cls) -> None:
        with cls._admin() as connection:
            connection.execute("SET session_replication_role=replica")
            cls._insert_completed_review(
                connection,
                appeal_id=REVIEWER_ONE_OLD,
                reviewer=REVIEWER_ONE,
                duty=REVIEWER_ONE_DUTY,
                decided_at="2026-01-10T00:00:00Z",
                decision_code="AFFIRM",
            )
            cls._insert_completed_review(
                connection,
                appeal_id=REVIEWER_ONE_TIE_LOW,
                reviewer=REVIEWER_ONE,
                duty=REVIEWER_ONE_DUTY,
                decided_at="2026-01-20T00:00:00Z",
                decision_code="MODIFY",
            )
            cls._insert_completed_review(
                connection,
                appeal_id=REVIEWER_ONE_TIE_HIGH,
                reviewer=REVIEWER_ONE,
                duty=REVIEWER_ONE_DUTY,
                decided_at="2026-01-20T00:00:00Z",
                decision_code="VACATE_AND_REMAND",
            )
            cls._insert_completed_review(
                connection,
                appeal_id=REVIEWER_TWO_ONLY,
                reviewer=REVIEWER_TWO,
                duty=REVIEWER_TWO_DUTY,
                decided_at="2026-01-30T00:00:00Z",
                decision_code="DISMISS",
            )
            cls._insert_completed_review(
                connection,
                appeal_id=REVIEWER_ONE_EDITOR_MISMATCH,
                reviewer=REVIEWER_ONE,
                duty=REVIEWER_ONE_DUTY,
                decided_at="2026-01-31T00:00:00Z",
                decision_code="AFFIRM",
                review_edited_by=REVIEWER_TWO,
            )
            cls._insert_completed_review(
                connection,
                appeal_id=REVIEWER_ONE_DECIDER_MISMATCH,
                reviewer=REVIEWER_ONE,
                duty=REVIEWER_ONE_DUTY,
                decided_at="2026-02-01T00:00:00Z",
                decision_code="AFFIRM",
                decision_decided_by=REVIEWER_TWO,
            )
            connection.execute("SET session_replication_role=origin")

    @staticmethod
    def _call(connection, function: str, *arguments):
        placeholders = ",".join(["%s"] * len(arguments))
        return connection.execute(
            f"SELECT projection FROM trust_api.{function}({placeholders})",
            arguments,
        ).fetchall()

    def test_two_reviewers_are_isolated_and_ties_are_stable(self) -> None:
        with self._runtime() as connection:
            reviewer_one = self._call(
                connection,
                "list_my_completed_appeal_reviews_v1",
                REVIEWER_ONE,
                REVIEWER_ONE_SESSION,
                2,
            )
            self.assertEqual(len(reviewer_one), 1)
            projection = reviewer_one[0][0]
            self.assertEqual(set(projection), {"entity_tag", "has_more", "items"})
            self.assertRegex(
                projection["entity_tag"],
                r'^"appeal-[1-9][0-9]*-[0-9a-f]{24}"$',
            )
            self.assertTrue(projection["has_more"])
            self.assertEqual(
                [item["appeal_id"] for item in projection["items"]],
                [str(REVIEWER_ONE_TIE_HIGH), str(REVIEWER_ONE_TIE_LOW)],
            )
            self.assertTrue(
                all(
                    set(item) == {"appeal_id", "decided_at", "decision_code"}
                    for item in projection["items"]
                )
            )

            reviewer_two = self._call(
                connection,
                "list_my_completed_appeal_reviews_v1",
                REVIEWER_TWO,
                REVIEWER_TWO_SESSION,
                100,
            )[0][0]
            self.assertFalse(reviewer_two["has_more"])
            self.assertEqual(
                [item["appeal_id"] for item in reviewer_two["items"]],
                [str(REVIEWER_TWO_ONLY)],
            )

            self.assertEqual(
                self._call(
                    connection,
                    "read_my_completed_appeal_review_v1",
                    REVIEWER_ONE,
                    REVIEWER_ONE_SESSION,
                    REVIEWER_TWO_ONLY,
                ),
                [],
            )

            for mismatch_case, appeal_id in (
                ("editor-assignment-mismatch", REVIEWER_ONE_EDITOR_MISMATCH),
                (
                    "decider-assignment-mismatch",
                    REVIEWER_ONE_DECIDER_MISMATCH,
                ),
            ):
                for actor, session in (
                    (REVIEWER_ONE, REVIEWER_ONE_SESSION),
                    (REVIEWER_TWO, REVIEWER_TWO_SESSION),
                ):
                    with self.subTest(actor=actor, case=mismatch_case):
                        self.assertEqual(
                            self._call(
                                connection,
                                "read_my_completed_appeal_review_v1",
                                actor,
                                session,
                                appeal_id,
                            ),
                            [],
                        )

            self.assertEqual(
                self._call(
                    connection,
                    "read_my_completed_appeal_review_v1",
                    REVIEWER_TWO,
                    REVIEWER_TWO_SESSION,
                    REVIEWER_ONE_TIE_HIGH,
                ),
                [],
            )

    def test_terminal_detail_is_exact_party_safe_and_note_backed(self) -> None:
        with self._runtime() as connection:
            rows = self._call(
                connection,
                "read_my_completed_appeal_review_v1",
                REVIEWER_ONE,
                REVIEWER_ONE_SESSION,
                REVIEWER_ONE_TIE_HIGH,
            )
            self.assertEqual(len(rows), 1)
            projection = rows[0][0]
            self.assertEqual(
                set(projection),
                {
                    "appeal_id",
                    "application",
                    "decision",
                    "entity_tag",
                    "review_note_recorded",
                    "status",
                },
            )
            self.assertEqual(projection["appeal_id"], str(REVIEWER_ONE_TIE_HIGH))
            self.assertEqual(projection["status"], "DECIDED")
            self.assertTrue(projection["review_note_recorded"])
            self.assertRegex(
                projection["entity_tag"],
                r'^"appeal-[1-9][0-9]*-[0-9a-f]{24}"$',
            )
            self.assertEqual(
                set(projection["application"]),
                {
                    "grounds",
                    "new_evidence_reference_ids",
                    "requested_outcome",
                    "statement_recorded",
                    "submitted_at",
                },
            )
            self.assertEqual(
                set(projection["decision"]),
                {
                    "assessments",
                    "decided_at",
                    "decision_code",
                    "decision_sha256",
                    "decision_version_id",
                    "policy_version",
                    "reason_codes",
                    "remedy_delta_codes",
                },
            )
            self.assertEqual(
                projection["decision"]["assessments"],
                [
                    {
                        "accepted_evidence_reference_ids": [],
                        "assessment_code": "ACCEPTED",
                        "finding_codes": ["PROCEDURE_MATERIAL_ERROR"],
                        "ground": "PROCEDURAL_ERROR",
                    }
                ],
            )
            serialized = json.dumps(projection, sort_keys=True)
            for forbidden in (
                "aggregate_version",
                "applicant",
                "reviewer",
                "duty_grant",
                "organization",
                "assignment_id",
                "sealed_",
                "restricted_text",
                "source_case",
                "source_outcome",
            ):
                self.assertNotIn(forbidden, serialized)

    def test_wrong_session_revoked_or_expired_duty_and_limits_fail_closed(
        self,
    ) -> None:
        with self._runtime() as connection:
            self.assertEqual(
                self._call(
                    connection,
                    "list_my_completed_appeal_reviews_v1",
                    REVIEWER_ONE,
                    WRONG_SESSION,
                    100,
                ),
                [],
            )
            self.assertEqual(
                self._call(
                    connection,
                    "read_my_completed_appeal_review_v1",
                    REVIEWER_ONE,
                    WRONG_SESSION,
                    REVIEWER_ONE_TIE_HIGH,
                ),
                [],
            )

            connection.execute("SET app.test_appeal_duty_revoked='off'")
            connection.execute("SET app.test_appeal_duty_expired='on'")
            self.assertEqual(
                self._call(
                    connection,
                    "list_my_completed_appeal_reviews_v1",
                    REVIEWER_ONE,
                    REVIEWER_ONE_SESSION,
                    100,
                ),
                [],
            )
            self.assertEqual(
                self._call(
                    connection,
                    "read_my_completed_appeal_review_v1",
                    REVIEWER_ONE,
                    REVIEWER_ONE_SESSION,
                    REVIEWER_ONE_TIE_HIGH,
                ),
                [],
            )
            for invalid_limit in (None, 0, 101):
                self.assertEqual(
                    self._call(
                        connection,
                        "list_my_completed_appeal_reviews_v1",
                        REVIEWER_ONE,
                        REVIEWER_ONE_SESSION,
                        invalid_limit,
                    ),
                    [],
                )

            connection.execute("SET app.test_appeal_duty_expired='off'")
            connection.execute("SET app.test_appeal_duty_revoked='on'")
            self.assertEqual(
                self._call(
                    connection,
                    "list_my_completed_appeal_reviews_v1",
                    REVIEWER_ONE,
                    REVIEWER_ONE_SESSION,
                    100,
                ),
                [],
            )
            self.assertEqual(
                self._call(
                    connection,
                    "read_my_completed_appeal_review_v1",
                    REVIEWER_ONE,
                    REVIEWER_ONE_SESSION,
                    REVIEWER_ONE_TIE_HIGH,
                ),
                [],
            )

    def test_runtime_role_cannot_read_backing_tables_directly(self) -> None:
        with self._runtime() as connection:
            for relation in (
                "appeals",
                "appeal_review_assignments",
                "appeal_application_versions",
                "appeal_review_drafts",
                "appeal_decision_versions",
            ):
                with self.subTest(relation=relation):
                    with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                        connection.execute(
                            f"SELECT * FROM trust.{relation} LIMIT 1"
                        ).fetchall()


if __name__ == "__main__":
    unittest.main()
