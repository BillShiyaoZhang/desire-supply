"""PostgreSQL 18 security and lifecycle proof for Trust0006 discovery."""

from __future__ import annotations

import unittest
from uuid import UUID

import psycopg

from desire_platform.utc import parse_offset_timestamp
from desire_platform.trust_safety.adapters.postgres.migrations import (
    TrustMigrationCatalog,
)
from tests.storage.postgres import test_trust_migration_runner_pg18 as runner_proof


def _uuid(value: int) -> UUID:
    return UUID(f"a6000000-0000-4000-8000-{value:012d}")


OFFICER = _uuid(1)
OFFICER_SESSION = _uuid(2)
OFFICER_ROTATED_SESSION = _uuid(3)
OFFICER_DUTY = _uuid(4)
OTHER_OFFICER = _uuid(5)
OTHER_DUTY = _uuid(6)
APPEAL_REVIEWER = _uuid(7)
APPEAL_SESSION = _uuid(8)
APPEAL_ROTATED_SESSION = _uuid(9)
APPEAL_DUTY = _uuid(10)
ORGANIZATION = _uuid(11)
DEMAND = _uuid(12)
DEMAND_VERSION = _uuid(13)

ACTIVE_CASE = _uuid(100)
ACTIVE_CASE_ASSIGNMENT = _uuid(101)
ACTIVE_HOLD_CASE = _uuid(110)
ACTIVE_HOLD_CASE_ASSIGNMENT = _uuid(111)
ACTIVE_HOLD = _uuid(112)
ACTIVE_HOLD_ASSIGNMENT = _uuid(113)
ACTIVE_HOLD_TRIAGE_ASSIGNMENT = _uuid(114)
OTHER_CASE = _uuid(120)
OTHER_CASE_ASSIGNMENT = _uuid(121)
EXPIRED_CASE = _uuid(130)
EXPIRED_CASE_ASSIGNMENT = _uuid(131)
RELEASED_CASE = _uuid(140)
RELEASED_CASE_ASSIGNMENT = _uuid(141)
TERMINAL_CASE = _uuid(150)
TERMINAL_CASE_ASSIGNMENT = _uuid(151)
OLD_DUTY_CASE = _uuid(160)
OLD_DUTY_CASE_ASSIGNMENT = _uuid(161)
HOLD_ONLY_CASE = _uuid(170)
HOLD_ONLY_CASE_ASSIGNMENT = _uuid(171)
HOLD_ONLY_HOLD_ONE = _uuid(172)
HOLD_ONLY_HOLD_ONE_ASSIGNMENT = _uuid(173)
HOLD_ONLY_HOLD_TWO = _uuid(174)
HOLD_ONLY_HOLD_TWO_ASSIGNMENT = _uuid(175)
HOLD_ONLY_UNASSIGNED_HOLD = _uuid(176)

ACTIVE_APPEAL = _uuid(200)
ACTIVE_APPEAL_ASSIGNMENT = _uuid(201)
OTHER_APPEAL = _uuid(210)
OTHER_APPEAL_ASSIGNMENT = _uuid(211)
EXPIRED_APPEAL = _uuid(220)
EXPIRED_APPEAL_ASSIGNMENT = _uuid(221)
RELEASED_APPEAL = _uuid(230)
RELEASED_APPEAL_ASSIGNMENT = _uuid(231)
TERMINAL_APPEAL = _uuid(240)
TERMINAL_APPEAL_ASSIGNMENT = _uuid(241)
OLD_DUTY_APPEAL = _uuid(250)
OLD_DUTY_APPEAL_ASSIGNMENT = _uuid(251)


class TrustAssignmentDiscoveryPostgres18Test(unittest.TestCase):
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
            cls._install_authority_stubs()
            cls._seed_assignment_states()
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
    def _runtime(cls, role: str):
        return psycopg.connect(
            cls.postgres.conninfo(database=cls.database, user=role),
            autocommit=True,
        )

    @classmethod
    def _install_authority_stubs(cls) -> None:
        with cls._admin() as connection:
            connection.execute("SET ROLE schema_owner")
            connection.execute(
                f"""
                CREATE OR REPLACE FUNCTION
                iam_api.resolve_trust_officer_authority_v1(
                    exact_actor_user_id uuid, exact_session_id uuid,
                    exact_operation text
                ) RETURNS TABLE(
                    actor_user_id uuid,session_id uuid,user_status text,
                    session_status text,session_family_status text,
                    duty_grant_id uuid,duty_grant_version bigint,
                    duty_expires_at timestamptz,duty_code text,
                    authority_marker_sha256 bytea
                ) LANGUAGE plpgsql SECURITY DEFINER STABLE PARALLEL UNSAFE
                SET search_path=pg_catalog AS $function$
                DECLARE selected_duty_version bigint := CASE
                    WHEN current_setting('app.test_current_duty_v2',true)='on'
                    THEN 2 ELSE 1 END;
                BEGIN
                    IF session_user<>'trust_officer'
                       OR current_user<>'schema_owner'
                       OR exact_actor_user_id<>'{OFFICER}'::uuid
                       OR exact_session_id NOT IN (
                            '{OFFICER_SESSION}'::uuid,
                            '{OFFICER_ROTATED_SESSION}'::uuid
                       )
                       OR exact_operation<>'READ_ASSIGNED_CASE'
                       OR current_setting('app.test_authority_disabled',true)='on'
                       OR NULLIF(current_setting('app.scope_kind',true),'')
                            IS DISTINCT FROM 'TRUST_OFFICER'
                       OR NULLIF(current_setting('app.operation',true),'')
                            IS DISTINCT FROM exact_operation
                       OR NULLIF(current_setting('app.actor_id',true),'')
                            IS DISTINCT FROM exact_actor_user_id::text
                       OR NULLIF(current_setting('app.session_id',true),'')
                            IS DISTINCT FROM exact_session_id::text
                    THEN RETURN; END IF;
                    RETURN QUERY SELECT exact_actor_user_id,exact_session_id,
                        'ACTIVE',
                        'ACTIVE','ACTIVE','{OFFICER_DUTY}'::uuid,
                        selected_duty_version,
                        transaction_timestamp()+interval '1 day',
                        'TRUST_OFFICER',sha256(convert_to(
                            exact_operation||exact_actor_user_id::text||
                            selected_duty_version::text,'UTF8'));
                END
                $function$
                """
            )
            connection.execute(
                f"""
                CREATE OR REPLACE FUNCTION
                iam_api.resolve_appeal_reviewer_authority_v1(
                    exact_actor_user_id uuid, exact_session_id uuid,
                    exact_operation text
                ) RETURNS TABLE(
                    actor_user_id uuid,session_id uuid,user_status text,
                    session_status text,session_family_status text,
                    duty_grant_id uuid,duty_grant_version bigint,
                    duty_expires_at timestamptz,duty_code text,
                    authority_marker_sha256 bytea
                ) LANGUAGE plpgsql SECURITY DEFINER STABLE PARALLEL UNSAFE
                SET search_path=pg_catalog AS $function$
                DECLARE selected_duty_version bigint := CASE
                    WHEN current_setting('app.test_current_duty_v2',true)='on'
                    THEN 2 ELSE 1 END;
                BEGIN
                    IF session_user<>'trust_appeal'
                       OR current_user<>'schema_owner'
                       OR exact_actor_user_id<>'{APPEAL_REVIEWER}'::uuid
                       OR exact_session_id NOT IN (
                            '{APPEAL_SESSION}'::uuid,
                            '{APPEAL_ROTATED_SESSION}'::uuid
                       )
                       OR exact_operation<>'READ_ASSIGNED_APPEAL'
                       OR current_setting('app.test_authority_disabled',true)='on'
                       OR NULLIF(current_setting('app.scope_kind',true),'')
                            IS DISTINCT FROM 'TRUST_APPEAL'
                       OR NULLIF(current_setting('app.operation',true),'')
                            IS DISTINCT FROM exact_operation
                       OR NULLIF(current_setting('app.actor_id',true),'')
                            IS DISTINCT FROM exact_actor_user_id::text
                       OR NULLIF(current_setting('app.session_id',true),'')
                            IS DISTINCT FROM exact_session_id::text
                    THEN RETURN; END IF;
                    RETURN QUERY SELECT exact_actor_user_id,exact_session_id,
                        'ACTIVE',
                        'ACTIVE','ACTIVE','{APPEAL_DUTY}'::uuid,
                        selected_duty_version,
                        transaction_timestamp()+interval '1 day',
                        'APPEAL_REVIEWER',sha256(convert_to(
                            exact_operation||exact_actor_user_id::text||
                            selected_duty_version::text,'UTF8'));
                END
                $function$
                """
            )

    @classmethod
    def _insert_case(
        cls,
        connection,
        *,
        case_id: UUID,
        assignment_id: UUID,
        officer: UUID,
        status: str = "TRIAGING",
        expires: str = "1 day",
        duty: UUID = OFFICER_DUTY,
        duty_version: int = 1,
        outcome_id: UUID | None = None,
    ) -> None:
        report_id = _uuid(case_id.int % 10_000 + 5_000)
        connection.execute(
            "INSERT INTO trust.reports (report_id,case_id,organization_id,"
            "demand_id,demand_version_id,demand_version_no,"
            "demand_aggregate_version,demand_status,demand_content_sha256,"
            "demand_owner_user_id,reportable_until,reporter_user_id,"
            "reporter_membership_id,reporter_role_grant_id,"
            "reporter_role_grant_version,reporter_authority_marker_sha256,"
            "reporter_party_marker_sha256,target_marker_sha256,category,"
            "incident_started_at,incident_ended_at,impact_codes,"
            "evidence_reference_ids,requested_protection_codes,created_at) "
            "VALUES (%s,%s,%s,%s,%s,1,1,'SUBMITTED',"
            "decode(repeat('71',32),'hex'),%s,"
            "transaction_timestamp()+interval '10 days',%s,%s,%s,1,"
            "decode(repeat('72',32),'hex'),"
            "decode(repeat('73',32),'hex'),"
            "decode(repeat('74',32),'hex'),'HARASSMENT',"
            "transaction_timestamp()-interval '2 days',NULL,"
            "ARRAY['PARTICIPANT_SAFETY_RISK']::text[],"
            "ARRAY[%s]::uuid[],ARRAY['PAUSE_MATCHING']::text[],"
            "transaction_timestamp()-interval '1 day')",
            (
                report_id,
                case_id,
                ORGANIZATION,
                DEMAND,
                DEMAND_VERSION,
                _uuid(19),
                _uuid(20),
                _uuid(21),
                _uuid(22),
                _uuid(case_id.int % 10_000 + 9_000),
            ),
        )
        connection.execute(
            "INSERT INTO trust.cases (case_id,report_id,organization_id,"
            "demand_id,demand_version_id,reporter_user_id,status,"
            "aggregate_version,assigned_officer_user_id,assignment_id,"
            "assignment_expires_at,current_triage_draft_version,"
            "current_triage_version,outcome_version_id,opened_at,updated_at) "
            "VALUES (%s,%s,%s,%s,%s,%s,%s,2,%s,%s,"
            f"transaction_timestamp()+interval '{expires}',NULL,NULL,%s,"
            "transaction_timestamp()-interval '2 days',"
            "transaction_timestamp())",
            (
                case_id,
                report_id,
                ORGANIZATION,
                DEMAND,
                DEMAND_VERSION,
                _uuid(20),
                status,
                officer,
                assignment_id,
                outcome_id,
            ),
        )
        connection.execute(
            "INSERT INTO trust.case_assignments (assignment_id,organization_id,"
            "case_id,assignment_purpose_code,hold_id,officer_user_id,"
            "excluded_officer_user_id,duty_grant_id,duty_grant_version,"
            "authority_marker_sha256,conflict_attestation_sha256,"
            "conflict_evaluated_at,conflict_valid_until,assigned_at,expires_at) "
            "VALUES (%s,%s,%s,'CASE_TRIAGE',NULL,%s,NULL,%s,%s,"
            "decode(repeat('11',32),'hex'),decode(repeat('22',32),'hex'),"
            "transaction_timestamp()-interval '2 days',"
            "transaction_timestamp()+interval '2 days',"
            "transaction_timestamp()-interval '1 day',"
            f"transaction_timestamp()+interval '{expires}')",
            (assignment_id, ORGANIZATION, case_id, officer, duty, duty_version),
        )

    @classmethod
    def _insert_appeal(
        cls,
        connection,
        *,
        appeal_id: UUID,
        assignment_id: UUID,
        reviewer: UUID,
        status: str = "IN_REVIEW",
        expires: str = "1 day",
        duty: UUID = APPEAL_DUTY,
        duty_version: int = 1,
    ) -> None:
        is_terminal = status == "DECIDED"
        connection.execute(
            "INSERT INTO trust.appeals (appeal_id,source_outcome_version_id,"
            "source_case_id,organization_id,demand_id,demand_version_id,"
            "applicant_user_id,applicant_membership_id,"
            "applicant_role_grant_id,applicant_role_grant_version,"
            "applicant_authority_marker_sha256,applicant_party_marker_sha256,"
            "source_outcome_code,source_reason_codes,source_action_codes,"
            "source_evidence_packet_version_id,source_evidence_packet_sha256,"
            "source_policy_version,source_decided_at,source_appeal_deadline,"
            "source_content_sha256,source_deciding_officer_user_id,"
            "source_appeal_eligible,source_appeal_eligibility_code,status,"
            "aggregate_version,current_application_draft_version,"
            "submitted_application_version,current_assignment_id,"
            "current_review_draft_version,decision_version_id,opened_at,updated_at) "
            "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,1,"
            "decode(repeat('31',32),'hex'),decode(repeat('32',32),'hex'),"
            "'PROTECTION_MAINTAINED',"
            "ARRAY['PRECAUTIONARY_ACTION_REQUIRED']::text[],"
            "ARRAY['SUBMIT_DEMAND']::text[],%s,"
            "decode(repeat('33',32),'hex'),'trust-case-outcome-v1',"
            "transaction_timestamp()-interval '3 days',"
            "transaction_timestamp()+interval '3 days',"
            "decode(repeat('34',32),'hex'),%s,true,'ELIGIBLE',%s,3,1,1,%s,"
            "%s,%s,transaction_timestamp()-interval '2 days',"
            "transaction_timestamp())",
            (
                appeal_id,
                _uuid(appeal_id.int % 10_000 + 6_000),
                _uuid(appeal_id.int % 10_000 + 7_000),
                ORGANIZATION,
                DEMAND,
                DEMAND_VERSION,
                _uuid(30),
                _uuid(31),
                _uuid(32),
                _uuid(appeal_id.int % 10_000 + 8_000),
                OTHER_OFFICER,
                status,
                assignment_id,
                1 if is_terminal else None,
                _uuid(appeal_id.int % 10_000 + 9_000)
                if is_terminal
                else None,
            ),
        )
        connection.execute(
            "INSERT INTO trust.appeal_review_assignments (assignment_id,"
            "appeal_id,reviewer_user_id,duty_grant_id,duty_grant_version,"
            "authority_marker_sha256,conflict_attestation_sha256,"
            "conflict_evaluated_at,conflict_valid_until,assigned_at,expires_at) "
            "VALUES (%s,%s,%s,%s,%s,decode(repeat('41',32),'hex'),"
            "decode(repeat('42',32),'hex'),"
            "transaction_timestamp()-interval '2 days',"
            "transaction_timestamp()+interval '2 days',"
            "transaction_timestamp()-interval '1 day',"
            f"transaction_timestamp()+interval '{expires}')",
            (assignment_id, appeal_id, reviewer, duty, duty_version),
        )

    @classmethod
    def _insert_hold_release_assignment(
        cls,
        connection,
        *,
        case_id: UUID,
        issue_assignment_id: UUID,
        hold_id: UUID,
        release_assignment_id: UUID,
        action_code: str,
        reason_code: str,
        effective_ago: str,
        hold_expires: str,
        assignment_expires: str,
    ) -> None:
        connection.execute(
            "INSERT INTO trust.safety_holds (hold_id,organization_id,"
            "case_id,demand_id,demand_version_id,triage_version,"
            "action_codes,reason_code,status,policy_version,"
            "issued_by_user_id,issue_assignment_id,effective_at,expires_at,"
            "aggregate_version,requires_independent_release,"
            "release_assignment_id,released_at,released_by_user_id,"
            "release_reason_code) VALUES (%s,%s,%s,%s,%s,1,"
            f"ARRAY['{action_code}']::text[],%s,'ACTIVE',"
            "'trust-demand-hold-v1',%s,%s,"
            f"transaction_timestamp()-interval '{effective_ago}',"
            f"transaction_timestamp()+interval '{hold_expires}',"
            "1,true,%s,NULL,NULL,NULL)",
            (
                hold_id,
                ORGANIZATION,
                case_id,
                DEMAND,
                DEMAND_VERSION,
                reason_code,
                OTHER_OFFICER,
                issue_assignment_id,
                release_assignment_id,
            ),
        )
        connection.execute(
            "INSERT INTO trust.case_assignments (assignment_id,"
            "organization_id,case_id,assignment_purpose_code,hold_id,"
            "officer_user_id,excluded_officer_user_id,duty_grant_id,"
            "duty_grant_version,authority_marker_sha256,"
            "conflict_attestation_sha256,conflict_evaluated_at,"
            "conflict_valid_until,assigned_at,expires_at) VALUES ("
            "%s,%s,%s,'HOLD_RELEASE',%s,%s,%s,%s,1,"
            "decode(repeat('61',32),'hex'),decode(repeat('62',32),'hex'),"
            "transaction_timestamp()-interval '2 hours',"
            "transaction_timestamp()+interval '1 day',"
            "transaction_timestamp()-interval '1 hour',"
            f"transaction_timestamp()+interval '{assignment_expires}')",
            (
                release_assignment_id,
                ORGANIZATION,
                case_id,
                hold_id,
                OFFICER,
                OTHER_OFFICER,
                OFFICER_DUTY,
            ),
        )

    @classmethod
    def _seed_assignment_states(cls) -> None:
        with cls._admin() as connection:
            connection.execute("SET session_replication_role=replica")
            cls._insert_case(
                connection,
                case_id=ACTIVE_CASE,
                assignment_id=ACTIVE_CASE_ASSIGNMENT,
                officer=OFFICER,
            )
            cls._insert_case(
                connection,
                case_id=OTHER_CASE,
                assignment_id=OTHER_CASE_ASSIGNMENT,
                officer=OTHER_OFFICER,
                duty=OTHER_DUTY,
            )
            cls._insert_case(
                connection,
                case_id=EXPIRED_CASE,
                assignment_id=EXPIRED_CASE_ASSIGNMENT,
                officer=OFFICER,
                expires="-1 hour",
            )
            cls._insert_case(
                connection,
                case_id=RELEASED_CASE,
                assignment_id=RELEASED_CASE_ASSIGNMENT,
                officer=OFFICER,
            )
            cls._insert_case(
                connection,
                case_id=TERMINAL_CASE,
                assignment_id=TERMINAL_CASE_ASSIGNMENT,
                officer=OFFICER,
                status="DECIDED",
                outcome_id=_uuid(152),
            )
            cls._insert_case(
                connection,
                case_id=OLD_DUTY_CASE,
                assignment_id=OLD_DUTY_CASE_ASSIGNMENT,
                officer=OFFICER,
                duty_version=2,
            )
            cls._insert_case(
                connection,
                case_id=ACTIVE_HOLD_CASE,
                assignment_id=ACTIVE_HOLD_CASE_ASSIGNMENT,
                officer=OTHER_OFFICER,
                duty=OTHER_DUTY,
                status="IN_REVIEW",
            )
            connection.execute(
                "INSERT INTO trust.case_assignments (assignment_id,"
                "organization_id,case_id,assignment_purpose_code,hold_id,"
                "officer_user_id,excluded_officer_user_id,duty_grant_id,"
                "duty_grant_version,authority_marker_sha256,"
                "conflict_attestation_sha256,conflict_evaluated_at,"
                "conflict_valid_until,assigned_at,expires_at) VALUES ("
                "%s,%s,%s,'CASE_TRIAGE',NULL,%s,NULL,%s,1,"
                "decode(repeat('53',32),'hex'),decode(repeat('54',32),'hex'),"
                "transaction_timestamp()-interval '2 hours',"
                "transaction_timestamp()+interval '1 day',"
                "transaction_timestamp()-interval '1 hour',"
                "transaction_timestamp()+interval '1 day')",
                (
                    ACTIVE_HOLD_TRIAGE_ASSIGNMENT,
                    ORGANIZATION,
                    ACTIVE_HOLD_CASE,
                    OFFICER,
                    OFFICER_DUTY,
                ),
            )
            cls._insert_case(
                connection,
                case_id=HOLD_ONLY_CASE,
                assignment_id=HOLD_ONLY_CASE_ASSIGNMENT,
                officer=OTHER_OFFICER,
                duty=OTHER_DUTY,
                status="IN_REVIEW",
            )
            cls._insert_hold_release_assignment(
                connection,
                case_id=HOLD_ONLY_CASE,
                issue_assignment_id=HOLD_ONLY_CASE_ASSIGNMENT,
                hold_id=HOLD_ONLY_HOLD_ONE,
                release_assignment_id=HOLD_ONLY_HOLD_ONE_ASSIGNMENT,
                action_code="SUBMIT_DEMAND",
                reason_code="PARTICIPANT_SAFETY_RISK",
                effective_ago="45 minutes",
                hold_expires="2 days",
                assignment_expires="8 hours",
            )
            cls._insert_hold_release_assignment(
                connection,
                case_id=HOLD_ONLY_CASE,
                issue_assignment_id=HOLD_ONLY_CASE_ASSIGNMENT,
                hold_id=HOLD_ONLY_HOLD_TWO,
                release_assignment_id=HOLD_ONLY_HOLD_TWO_ASSIGNMENT,
                action_code="VERIFY_DEMAND",
                reason_code="RETALIATION_RISK",
                effective_ago="30 minutes",
                hold_expires="3 days",
                assignment_expires="10 hours",
            )
            connection.execute(
                "INSERT INTO trust.safety_holds (hold_id,organization_id,"
                "case_id,demand_id,demand_version_id,triage_version,"
                "action_codes,reason_code,status,policy_version,"
                "issued_by_user_id,issue_assignment_id,effective_at,"
                "expires_at,aggregate_version,requires_independent_release,"
                "release_assignment_id,released_at,released_by_user_id,"
                "release_reason_code) VALUES (%s,%s,%s,%s,%s,1,"
                "ARRAY['REQUEST_MATCHING']::text[],"
                "'PARTICIPANT_SAFETY_RISK','ACTIVE',"
                "'trust-demand-hold-v1',%s,%s,"
                "transaction_timestamp()-interval '5 minutes',"
                "transaction_timestamp()+interval '4 days',1,true,"
                "NULL,NULL,NULL,NULL)",
                (
                    HOLD_ONLY_UNASSIGNED_HOLD,
                    ORGANIZATION,
                    HOLD_ONLY_CASE,
                    DEMAND,
                    DEMAND_VERSION,
                    OTHER_OFFICER,
                    HOLD_ONLY_CASE_ASSIGNMENT,
                ),
            )
            connection.execute(
                "UPDATE trust.cases SET assigned_officer_user_id=%s,"
                "assignment_id=%s,assignment_expires_at="
                "transaction_timestamp()+interval '1 day' WHERE case_id=%s",
                (
                    OFFICER,
                    ACTIVE_HOLD_TRIAGE_ASSIGNMENT,
                    ACTIVE_HOLD_CASE,
                ),
            )
            connection.execute(
                "INSERT INTO trust.safety_holds (hold_id,organization_id,"
                "case_id,demand_id,demand_version_id,triage_version,"
                "action_codes,reason_code,status,policy_version,"
                "issued_by_user_id,issue_assignment_id,effective_at,expires_at,"
                "aggregate_version,requires_independent_release,"
                "release_assignment_id,released_at,released_by_user_id,"
                "release_reason_code) VALUES (%s,%s,%s,%s,%s,1,"
                "ARRAY['SUBMIT_DEMAND']::text[],'PARTICIPANT_SAFETY_RISK',"
                "'ACTIVE','trust-demand-hold-v1',%s,%s,"
                "transaction_timestamp()-interval '1 hour',"
                "transaction_timestamp()+interval '1 day',1,true,%s,"
                "NULL,NULL,NULL)",
                (
                    ACTIVE_HOLD,
                    ORGANIZATION,
                    ACTIVE_HOLD_CASE,
                    DEMAND,
                    DEMAND_VERSION,
                    OTHER_OFFICER,
                    ACTIVE_HOLD_CASE_ASSIGNMENT,
                    ACTIVE_HOLD_ASSIGNMENT,
                ),
            )
            connection.execute(
                "INSERT INTO trust.case_assignments (assignment_id,"
                "organization_id,case_id,assignment_purpose_code,hold_id,"
                "officer_user_id,excluded_officer_user_id,duty_grant_id,"
                "duty_grant_version,authority_marker_sha256,"
                "conflict_attestation_sha256,conflict_evaluated_at,"
                "conflict_valid_until,assigned_at,expires_at) VALUES ("
                "%s,%s,%s,'HOLD_RELEASE',%s,%s,%s,%s,1,"
                "decode(repeat('51',32),'hex'),decode(repeat('52',32),'hex'),"
                "transaction_timestamp()-interval '2 hours',"
                "transaction_timestamp()+interval '1 day',"
                "transaction_timestamp()-interval '1 hour',"
                "transaction_timestamp()+interval '12 hours')",
                (
                    ACTIVE_HOLD_ASSIGNMENT,
                    ORGANIZATION,
                    ACTIVE_HOLD_CASE,
                    ACTIVE_HOLD,
                    OFFICER,
                    OTHER_OFFICER,
                    OFFICER_DUTY,
                ),
            )
            connection.execute(
                "INSERT INTO trust.case_assignment_releases (assignment_id,"
                "organization_id,case_id,released_by_user_id,reason_code,"
                "released_at) VALUES (%s,%s,%s,%s,'WORKLOAD_RELEASE',"
                "transaction_timestamp())",
                (
                    RELEASED_CASE_ASSIGNMENT,
                    ORGANIZATION,
                    RELEASED_CASE,
                    OFFICER,
                ),
            )

            cls._insert_appeal(
                connection,
                appeal_id=ACTIVE_APPEAL,
                assignment_id=ACTIVE_APPEAL_ASSIGNMENT,
                reviewer=APPEAL_REVIEWER,
            )
            cls._insert_appeal(
                connection,
                appeal_id=OTHER_APPEAL,
                assignment_id=OTHER_APPEAL_ASSIGNMENT,
                reviewer=OTHER_OFFICER,
                duty=OTHER_DUTY,
            )
            cls._insert_appeal(
                connection,
                appeal_id=EXPIRED_APPEAL,
                assignment_id=EXPIRED_APPEAL_ASSIGNMENT,
                reviewer=APPEAL_REVIEWER,
                expires="-1 hour",
            )
            cls._insert_appeal(
                connection,
                appeal_id=RELEASED_APPEAL,
                assignment_id=RELEASED_APPEAL_ASSIGNMENT,
                reviewer=APPEAL_REVIEWER,
            )
            cls._insert_appeal(
                connection,
                appeal_id=TERMINAL_APPEAL,
                assignment_id=TERMINAL_APPEAL_ASSIGNMENT,
                reviewer=APPEAL_REVIEWER,
                status="DECIDED",
            )
            cls._insert_appeal(
                connection,
                appeal_id=OLD_DUTY_APPEAL,
                assignment_id=OLD_DUTY_APPEAL_ASSIGNMENT,
                reviewer=APPEAL_REVIEWER,
                duty_version=2,
            )
            connection.execute(
                "INSERT INTO trust.appeal_assignment_releases (assignment_id,"
                "appeal_id,released_by_user_id,reason_code,released_at) "
                "VALUES (%s,%s,%s,'WORKLOAD_RELEASE',transaction_timestamp())",
                (
                    RELEASED_APPEAL_ASSIGNMENT,
                    RELEASED_APPEAL,
                    APPEAL_REVIEWER,
                ),
            )
            connection.execute("SET session_replication_role=origin")

    @staticmethod
    def _call(connection, function: str, actor: UUID, session: UUID, limit):
        return connection.execute(
            f"SELECT projection FROM trust_api.{function}(%s,%s,%s)",
            (actor, session, limit),
        ).fetchall()

    def test_functions_and_relations_are_private_force_rls(self) -> None:
        with self._admin() as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT proc.proname,owner_role.rolname,proc.prosecdef,"
                    "proc.provolatile,proc.proparallel,proc.proconfig "
                    "FROM pg_catalog.pg_proc AS proc "
                    "JOIN pg_catalog.pg_namespace AS namespace "
                    "ON namespace.oid=proc.pronamespace "
                    "JOIN pg_catalog.pg_roles AS owner_role "
                    "ON owner_role.oid=proc.proowner "
                    "WHERE namespace.nspname='trust_api' AND proc.proname IN ("
                    "'list_my_active_case_assignments_v1',"
                    "'read_my_active_case_triage_assignment_v1',"
                    "'read_my_active_hold_release_assignment_v1',"
                    "'list_my_active_appeal_assignments_v1') ORDER BY 1"
                ).fetchall(),
                [
                    (
                        "list_my_active_appeal_assignments_v1",
                        "trust_schema_owner",
                        True,
                        "v",
                        "u",
                        ["search_path=pg_catalog, trust"],
                    ),
                    (
                        "list_my_active_case_assignments_v1",
                        "trust_schema_owner",
                        True,
                        "v",
                        "u",
                        ["search_path=pg_catalog, trust"],
                    ),
                    (
                        "read_my_active_case_triage_assignment_v1",
                        "trust_schema_owner",
                        True,
                        "v",
                        "u",
                        ["search_path=pg_catalog, trust"],
                    ),
                    (
                        "read_my_active_hold_release_assignment_v1",
                        "trust_schema_owner",
                        True,
                        "v",
                        "u",
                        ["search_path=pg_catalog, trust"],
                    ),
                ],
            )
            self.assertTrue(
                all(
                    row[1:]
                    == ("trust_schema_owner", True, True)
                    for row in connection.execute(
                        "SELECT relation.relname,owner_role.rolname,"
                        "relation.relrowsecurity,relation.relforcerowsecurity "
                        "FROM pg_catalog.pg_class AS relation "
                        "JOIN pg_catalog.pg_namespace AS namespace "
                        "ON namespace.oid=relation.relnamespace "
                        "JOIN pg_catalog.pg_roles AS owner_role "
                        "ON owner_role.oid=relation.relowner "
                        "WHERE namespace.nspname='trust' AND relation.relname "
                        "IN ('cases','case_assignments',"
                        "'case_assignment_releases','safety_holds','appeals',"
                        "'appeal_review_assignments',"
                        "'appeal_assignment_releases')"
                    ).fetchall()
                )
            )
            self.assertEqual(
                connection.execute(
                    "SELECT "
                    "has_function_privilege('trust_officer',%s,'EXECUTE'),"
                    "has_function_privilege('trust_appeal',%s,'EXECUTE'),"
                    "has_function_privilege('trust_officer',%s,'EXECUTE'),"
                    "has_function_privilege('trust_appeal',%s,'EXECUTE'),"
                    "has_function_privilege('trust_officer',%s,'EXECUTE')",
                    (
                        "trust_api."
                        "read_my_active_case_triage_assignment_v1("
                        "uuid,uuid,uuid)",
                        "trust_api."
                        "read_my_active_case_triage_assignment_v1("
                        "uuid,uuid,uuid)",
                        "trust_api."
                        "read_my_active_hold_release_assignment_v1("
                        "uuid,uuid,uuid)",
                        "trust_api."
                        "read_my_active_hold_release_assignment_v1("
                        "uuid,uuid,uuid)",
                        "trust_api.read_assigned_case_v1(uuid,uuid,uuid)",
                    ),
                ).fetchone(),
                (True, False, True, False, False),
            )

        for role, forbidden_function, target in (
            ("trust_appeal", "list_my_active_case_assignments_v1", 10),
            ("trust_officer", "list_my_active_appeal_assignments_v1", 10),
            ("trust_self", "list_my_active_case_assignments_v1", 10),
            (
                "trust_appeal",
                "read_my_active_case_triage_assignment_v1",
                ACTIVE_CASE,
            ),
            (
                "trust_self",
                "read_my_active_hold_release_assignment_v1",
                HOLD_ONLY_HOLD_ONE,
            ),
        ):
            with self._runtime(role) as connection:
                with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                    self._call(
                        connection,
                        forbidden_function,
                        OFFICER,
                        OFFICER_SESSION,
                        target,
                    )
                with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                    connection.execute("SELECT * FROM trust.case_assignments")

        with self._runtime("trust_officer") as connection:
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                self._call(
                    connection,
                    "read_assigned_case_v1",
                    OFFICER,
                    OFFICER_SESSION,
                    HOLD_ONLY_CASE,
                )

    def test_active_assignment_wrappers_are_exact_and_hold_bound(self) -> None:
        with self._runtime("trust_officer") as connection:
            triage = self._call(
                connection,
                "read_my_active_case_triage_assignment_v1",
                OFFICER,
                OFFICER_SESSION,
                ACTIVE_CASE,
            )
            self.assertEqual(len(triage), 1)
            self.assertEqual(triage[0][0]["case_id"], str(ACTIVE_CASE))
            terminal_triage = self._call(
                connection,
                "read_my_active_case_triage_assignment_v1",
                OFFICER,
                OFFICER_SESSION,
                TERMINAL_CASE,
            )
            self.assertEqual(len(terminal_triage), 1)
            self.assertEqual(
                (
                    terminal_triage[0][0]["case_id"],
                    terminal_triage[0][0]["status"],
                ),
                (str(TERMINAL_CASE), "DECIDED"),
            )
            self.assertEqual(
                self._call(
                    connection,
                    "read_my_active_case_triage_assignment_v1",
                    OFFICER,
                    OFFICER_SESSION,
                    HOLD_ONLY_CASE,
                ),
                [],
            )
            for inactive_case_id in (
                OTHER_CASE,
                EXPIRED_CASE,
                RELEASED_CASE,
                OLD_DUTY_CASE,
            ):
                self.assertEqual(
                    self._call(
                        connection,
                        "read_my_active_case_triage_assignment_v1",
                        OFFICER,
                        OFFICER_SESSION,
                        inactive_case_id,
                    ),
                    [],
                )
            self.assertEqual(
                self._call(
                    connection,
                    "read_my_active_case_triage_assignment_v1",
                    OTHER_OFFICER,
                    OFFICER_SESSION,
                    ACTIVE_CASE,
                ),
                [],
            )
            self.assertEqual(
                self._call(
                    connection,
                    "read_my_active_case_triage_assignment_v1",
                    OFFICER,
                    _uuid(997),
                    ACTIVE_CASE,
                ),
                [],
            )

            hold_one = self._call(
                connection,
                "read_my_active_hold_release_assignment_v1",
                OFFICER,
                OFFICER_SESSION,
                HOLD_ONLY_HOLD_ONE,
            )
            hold_two = self._call(
                connection,
                "read_my_active_hold_release_assignment_v1",
                OFFICER,
                OFFICER_SESSION,
                HOLD_ONLY_HOLD_TWO,
            )
            self.assertEqual(len(hold_one), 1)
            self.assertEqual(len(hold_two), 1)
            exact_keys = {
                "action_codes",
                "assignment_expires_at",
                "case_id",
                "case_status",
                "effective_at",
                "entity_tag",
                "expires_at",
                "hold_id",
                "hold_status",
                "reason_code",
            }
            self.assertEqual(set(hold_one[0][0]), exact_keys)
            self.assertEqual(set(hold_two[0][0]), exact_keys)
            self.assertEqual(
                (
                    hold_one[0][0]["hold_id"],
                    hold_one[0][0]["case_id"],
                    hold_one[0][0]["case_status"],
                    hold_one[0][0]["hold_status"],
                    hold_one[0][0]["reason_code"],
                    hold_one[0][0]["action_codes"],
                ),
                (
                    str(HOLD_ONLY_HOLD_ONE),
                    str(HOLD_ONLY_CASE),
                    "IN_REVIEW",
                    "ACTIVE",
                    "PARTICIPANT_SAFETY_RISK",
                    ["SUBMIT_DEMAND"],
                ),
            )
            self.assertEqual(
                (
                    hold_two[0][0]["hold_id"],
                    hold_two[0][0]["case_id"],
                    hold_two[0][0]["case_status"],
                    hold_two[0][0]["hold_status"],
                    hold_two[0][0]["reason_code"],
                    hold_two[0][0]["action_codes"],
                ),
                (
                    str(HOLD_ONLY_HOLD_TWO),
                    str(HOLD_ONLY_CASE),
                    "IN_REVIEW",
                    "ACTIVE",
                    "RETALIATION_RISK",
                    ["VERIFY_DEMAND"],
                ),
            )
            self.assertNotEqual(
                hold_one[0][0]["entity_tag"],
                hold_two[0][0]["entity_tag"],
            )
            for projection in (hold_one[0][0], hold_two[0][0]):
                self.assertRegex(
                    projection["entity_tag"],
                    r'^"trust-[1-9][0-9]*-[0-9a-f]{24}"$',
                )
                self.assertLess(
                    parse_offset_timestamp(projection["effective_at"]),
                    parse_offset_timestamp(projection["expires_at"]),
                )
                self.assertLessEqual(
                    parse_offset_timestamp(
                        projection["assignment_expires_at"]
                    ),
                    parse_offset_timestamp(projection["expires_at"]),
                )
                self.assertIn(
                    projection["reason_code"],
                    {
                        "PARTICIPANT_SAFETY_RISK",
                        "RETALIATION_RISK",
                    },
                )
                self.assertEqual(
                    projection["action_codes"],
                    sorted(set(projection["action_codes"])),
                )
                self.assertTrue(
                    set(projection["action_codes"])
                    <= {
                        "REQUEST_MATCHING",
                        "SUBMIT_DEMAND",
                        "VERIFY_DEMAND",
                    }
                )
            self.assertEqual(
                self._call(
                    connection,
                    "read_my_active_hold_release_assignment_v1",
                    OFFICER,
                    OFFICER_SESSION,
                    HOLD_ONLY_UNASSIGNED_HOLD,
                ),
                [],
            )
            self.assertEqual(
                self._call(
                    connection,
                    "read_my_active_hold_release_assignment_v1",
                    OTHER_OFFICER,
                    OFFICER_SESSION,
                    HOLD_ONLY_HOLD_ONE,
                ),
                [],
            )
            self.assertEqual(
                self._call(
                    connection,
                    "read_my_active_case_triage_assignment_v1",
                    OFFICER,
                    OFFICER_SESSION,
                    UUID(int=0),
                ),
                [],
            )
            self.assertEqual(
                self._call(
                    connection,
                    "read_my_active_hold_release_assignment_v1",
                    OFFICER,
                    OFFICER_SESSION,
                    UUID(int=0),
                ),
                [],
            )
            connection.execute("SET app.test_current_duty_v2='on'")
            self.assertEqual(
                self._call(
                    connection,
                    "read_my_active_case_triage_assignment_v1",
                    OFFICER,
                    OFFICER_SESSION,
                    ACTIVE_CASE,
                ),
                [],
            )
            self.assertEqual(
                self._call(
                    connection,
                    "read_my_active_hold_release_assignment_v1",
                    OFFICER,
                    OFFICER_SESSION,
                    HOLD_ONLY_HOLD_ONE,
                ),
                [],
            )
            connection.execute("RESET app.test_current_duty_v2")

    def test_current_assignments_are_minimal_and_fail_closed(self) -> None:
        with self._runtime("trust_officer") as connection:
            rows = self._call(
                connection,
                "list_my_active_case_assignments_v1",
                OFFICER,
                OFFICER_SESSION,
                100,
            )
            self.assertEqual(len(rows), 1)
            projection = rows[0][0]
            self.assertEqual(set(projection), {"entity_tag", "items"})
            self.assertRegex(
                projection["entity_tag"],
                r'^"trust-[1-9][0-9]*-[0-9a-f]{24}"$',
            )
            assignment_targets = [
                (
                    item["case_id"],
                    item["assignment_purpose"],
                    item["hold_id"],
                )
                for item in projection["items"]
            ]
            self.assertEqual(
                len(assignment_targets),
                len(set(assignment_targets)),
            )
            self.assertEqual(
                set(assignment_targets),
                {
                    (str(ACTIVE_HOLD_CASE), "HOLD_RELEASE", str(ACTIVE_HOLD)),
                    (str(ACTIVE_HOLD_CASE), "CASE_TRIAGE", None),
                    (str(ACTIVE_CASE), "CASE_TRIAGE", None),
                    (str(HOLD_ONLY_CASE), "HOLD_RELEASE", str(HOLD_ONLY_HOLD_ONE)),
                    (str(HOLD_ONLY_CASE), "HOLD_RELEASE", str(HOLD_ONLY_HOLD_TWO)),
                },
            )
            self.assertEqual(
                sum(
                    case_id == str(ACTIVE_HOLD_CASE)
                    for case_id, _purpose, _hold_id in assignment_targets
                ),
                2,
            )
            self.assertTrue(
                all(
                    set(item)
                    == {
                        "case_id",
                        "assignment_purpose",
                        "assignment_expires_at",
                        "hold_id",
                    }
                    for item in projection["items"]
                )
            )
            self.assertEqual(
                len(
                    self._call(
                        connection,
                        "list_my_active_case_assignments_v1",
                        OFFICER,
                        OFFICER_ROTATED_SESSION,
                        1,
                    )[0][0]["items"]
                ),
                1,
            )
            for invalid_limit in (None, 0, 101):
                self.assertEqual(
                    self._call(
                        connection,
                        "list_my_active_case_assignments_v1",
                        OFFICER,
                        OFFICER_SESSION,
                        invalid_limit,
                    ),
                    [],
                )
            self.assertEqual(
                self._call(
                    connection,
                    "list_my_active_case_assignments_v1",
                    _uuid(999),
                    OFFICER_SESSION,
                    100,
                ),
                [],
            )
            self.assertEqual(
                self._call(
                    connection,
                    "list_my_active_case_assignments_v1",
                    OFFICER,
                    _uuid(998),
                    100,
                ),
                [],
            )
            connection.execute("SET app.test_authority_disabled='on'")
            self.assertEqual(
                self._call(
                    connection,
                    "list_my_active_case_assignments_v1",
                    OFFICER,
                    OFFICER_SESSION,
                    100,
                ),
                [],
            )
            connection.execute("RESET app.test_authority_disabled")
            connection.execute("SET app.test_current_duty_v2='on'")
            duty_v2 = self._call(
                connection,
                "list_my_active_case_assignments_v1",
                OFFICER,
                OFFICER_SESSION,
                100,
            )[0][0]["items"]
            self.assertEqual(
                [(item["case_id"], item["assignment_purpose"]) for item in duty_v2],
                [(str(OLD_DUTY_CASE), "CASE_TRIAGE")],
            )
            connection.execute("RESET app.test_current_duty_v2")

        with self._runtime("trust_appeal") as connection:
            rows = self._call(
                connection,
                "list_my_active_appeal_assignments_v1",
                APPEAL_REVIEWER,
                APPEAL_SESSION,
                100,
            )
            self.assertEqual(len(rows), 1)
            projection = rows[0][0]
            self.assertEqual(set(projection), {"entity_tag", "items"})
            self.assertRegex(
                projection["entity_tag"],
                r'^"appeal-[1-9][0-9]*-[0-9a-f]{24}"$',
            )
            self.assertEqual(
                projection["items"],
                [
                    {
                        "appeal_id": str(ACTIVE_APPEAL),
                        "assignment_expires_at": projection["items"][0][
                            "assignment_expires_at"
                        ],
                    }
                ],
            )
            self.assertEqual(
                set(projection["items"][0]),
                {"appeal_id", "assignment_expires_at"},
            )
            self.assertEqual(
                len(
                    self._call(
                        connection,
                        "list_my_active_appeal_assignments_v1",
                        APPEAL_REVIEWER,
                        APPEAL_ROTATED_SESSION,
                        1,
                    )[0][0]["items"]
                ),
                1,
            )
            for invalid_limit in (None, 0, 101):
                self.assertEqual(
                    self._call(
                        connection,
                        "list_my_active_appeal_assignments_v1",
                        APPEAL_REVIEWER,
                        APPEAL_SESSION,
                        invalid_limit,
                    ),
                    [],
                )
            self.assertEqual(
                self._call(
                    connection,
                    "list_my_active_appeal_assignments_v1",
                    _uuid(996),
                    APPEAL_SESSION,
                    100,
                ),
                [],
            )
            self.assertEqual(
                self._call(
                    connection,
                    "list_my_active_appeal_assignments_v1",
                    APPEAL_REVIEWER,
                    _uuid(995),
                    100,
                ),
                [],
            )
            connection.execute("SET app.test_authority_disabled='on'")
            self.assertEqual(
                self._call(
                    connection,
                    "list_my_active_appeal_assignments_v1",
                    APPEAL_REVIEWER,
                    APPEAL_SESSION,
                    100,
                ),
                [],
            )
            connection.execute("RESET app.test_authority_disabled")
            connection.execute("SET app.test_current_duty_v2='on'")
            self.assertEqual(
                self._call(
                    connection,
                    "list_my_active_appeal_assignments_v1",
                    APPEAL_REVIEWER,
                    APPEAL_SESSION,
                    100,
                )[0][0]["items"],
                [
                    {
                        "appeal_id": str(OLD_DUTY_APPEAL),
                        "assignment_expires_at": self._call(
                            connection,
                            "list_my_active_appeal_assignments_v1",
                            APPEAL_REVIEWER,
                            APPEAL_SESSION,
                            100,
                        )[0][0]["items"][0]["assignment_expires_at"],
                    }
                ],
            )
            connection.execute("RESET app.test_current_duty_v2")

        with self._admin() as connection:
            connection.execute("SET session_replication_role=replica")
            connection.execute(
                "INSERT INTO trust.case_assignment_releases (assignment_id,"
                "organization_id,case_id,released_by_user_id,reason_code,"
                "released_at) VALUES (%s,%s,%s,%s,'WORKLOAD_RELEASE',"
                "transaction_timestamp())",
                (
                    HOLD_ONLY_HOLD_ONE_ASSIGNMENT,
                    ORGANIZATION,
                    HOLD_ONLY_CASE,
                    OFFICER,
                ),
            )
            connection.execute(
                "UPDATE trust.case_assignments SET expires_at="
                "transaction_timestamp()-interval '1 minute' "
                "WHERE assignment_id=%s",
                (HOLD_ONLY_HOLD_TWO_ASSIGNMENT,),
            )
            connection.execute("SET session_replication_role=origin")

        with self._runtime("trust_officer") as connection:
            for inactive_hold_id in (
                HOLD_ONLY_HOLD_ONE,
                HOLD_ONLY_HOLD_TWO,
            ):
                self.assertEqual(
                    self._call(
                        connection,
                        "read_my_active_hold_release_assignment_v1",
                        OFFICER,
                        OFFICER_SESSION,
                        inactive_hold_id,
                    ),
                    [],
                )

        with self._admin() as connection:
            connection.execute("SET session_replication_role=replica")
            connection.execute(
                "UPDATE trust.cases SET status='DECIDED',aggregate_version=3,"
                "outcome_version_id=%s,updated_at=transaction_timestamp() "
                "WHERE case_id=%s",
                (_uuid(170), ACTIVE_CASE),
            )
            connection.execute(
                "UPDATE trust.cases SET status='DECIDED',aggregate_version=3,"
                "outcome_version_id=%s,updated_at=transaction_timestamp() "
                "WHERE case_id=%s",
                (_uuid(171), ACTIVE_HOLD_CASE),
            )
            connection.execute(
                "UPDATE trust.appeals SET status='DECIDED',aggregate_version=4,"
                "current_review_draft_version=1,decision_version_id=%s,"
                "updated_at=transaction_timestamp() WHERE appeal_id=%s",
                (_uuid(270), ACTIVE_APPEAL),
            )
            connection.execute(
                "UPDATE trust.cases SET status='DECIDED',aggregate_version=3,"
                "outcome_version_id=%s,updated_at=transaction_timestamp() "
                "WHERE case_id=%s",
                (_uuid(177), HOLD_ONLY_CASE),
            )
            connection.execute("SET session_replication_role=origin")

        with self._runtime("trust_officer") as connection:
            decided_triage = self._call(
                connection,
                "read_my_active_case_triage_assignment_v1",
                OFFICER,
                OFFICER_SESSION,
                ACTIVE_CASE,
            )
            self.assertEqual(len(decided_triage), 1)
            self.assertEqual(
                (
                    decided_triage[0][0]["case_id"],
                    decided_triage[0][0]["status"],
                ),
                (str(ACTIVE_CASE), "DECIDED"),
            )
            empty = self._call(
                connection,
                "list_my_active_case_assignments_v1",
                OFFICER,
                OFFICER_SESSION,
                100,
            )
            self.assertEqual(len(empty), 1)
            self.assertEqual(empty[0][0]["items"], [])
        with self._runtime("trust_appeal") as connection:
            empty = self._call(
                connection,
                "list_my_active_appeal_assignments_v1",
                APPEAL_REVIEWER,
                APPEAL_SESSION,
                100,
            )
            self.assertEqual(len(empty), 1)
            self.assertEqual(empty[0][0]["items"], [])


if __name__ == "__main__":
    unittest.main()
