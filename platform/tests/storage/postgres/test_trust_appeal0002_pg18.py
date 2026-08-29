"""PostgreSQL 18 lifecycle proof for the fixed Appeal0002 programs."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import unittest
from uuid import UUID

import psycopg

from desire_platform.trust_safety.adapters.postgres.appeal_production import (
    PsycopgAppealSealedTextProvider,
)
from tests.storage.postgres import test_trust_postgres_commands_pg18 as trust_base
from tests.storage.postgres.test_trust_postgres_commands_pg18 import (
    ACTOR_OFFICER_ONE,
    ACTOR_REPORTER,
    DEMAND,
    DEMAND_VERSION,
    ORGANIZATION,
    SESSION_REPORTER,
    SESSION_REPORTER_ROTATED,
    _uuid,
)


PLATFORM_ROOT = Path(__file__).resolve().parents[3]
APPEAL_MIGRATION = (
    PLATFORM_ROOT
    / "src/desire_platform/trust_safety/adapters/postgres/migrations"
    / "0002_expand__appeal_review_v1.sql"
)

SOURCE_CASE = _uuid(21)
SOURCE_OUTCOME = _uuid(26)
REVIEWER_ONE = _uuid(60)
REVIEWER_ONE_SESSION = _uuid(61)
REVIEWER_ONE_ROTATED_SESSION = _uuid(62)
REVIEWER_ONE_DUTY = _uuid(63)
REVIEWER_TWO = _uuid(64)
REVIEWER_TWO_SESSION = _uuid(65)
REVIEWER_TWO_DUTY = _uuid(66)
DECIDING_OFFICER_REVIEW_SESSION = _uuid(67)
DECIDING_OFFICER_REVIEW_DUTY = _uuid(68)


def _digest(label: str) -> bytes:
    return hashlib.sha256(label.encode("utf-8")).digest()


def _call(connection: psycopg.Connection, function: str, arguments: list):
    return connection.execute(
        f"SELECT safe_response,replayed FROM trust_api.{function}("
        + ",".join(["%s"] * len(arguments))
        + ")",
        arguments,
    ).fetchone()


class AppealPostgres18LifecycleTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        trust_base.TrustPostgresCommandsTest.setUpClass()
        try:
            # Produce one real, frozen Trust outcome before applying Appeal0002.
            trust_base.TrustPostgresCommandsTest(
                methodName=(
                    "test_fixed_programs_replay_rollback_occ_and_independent_release"
                )
            ).test_fixed_programs_replay_rollback_occ_and_independent_release()
            cls.postgres = trust_base.TrustPostgresCommandsTest.postgres
            cls.database = trust_base.TrustPostgresCommandsTest.database
            cls._install_appeal_authority_stubs()
            with psycopg.connect(
                cls.postgres.conninfo(
                    database=cls.database,
                    user="trust_migration_runner",
                ),
                autocommit=False,
            ) as connection:
                connection.execute("SET ROLE trust_schema_owner")
                connection.execute(APPEAL_MIGRATION.read_text(encoding="utf-8"))
                connection.commit()
        except BaseException:
            trust_base.TrustPostgresCommandsTest.tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls) -> None:
        trust_base.TrustPostgresCommandsTest.tearDownClass()

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
    def _install_appeal_authority_stubs(cls) -> None:
        with cls._admin() as connection:
            connection.execute("SET ROLE schema_owner")
            connection.execute(
                """
                CREATE OR REPLACE FUNCTION
                iam_api.resolve_trust_reporter_authority_v1(
                    exact_actor uuid, exact_session uuid, exact_org uuid,
                    exact_operation text
                ) RETURNS TABLE(
                    actor_user_id uuid,session_id uuid,organization_id uuid,
                    user_status text,session_status text,
                    session_family_status text,organization_status text,
                    membership_id uuid,membership_status text,
                    membership_role_grant_id uuid,
                    membership_role_grant_version bigint,role_code text,
                    policy_requirements_satisfied boolean,
                    authority_marker_sha256 bytea
                ) LANGUAGE plpgsql SECURITY DEFINER
                SET search_path=pg_catalog AS $function$
                BEGIN
                    IF current_setting('app.test_authority_disabled',true)='on'
                       OR session_user<>'trust_self'
                       OR exact_actor<>'90000000-0000-4000-8000-000000000001'
                       OR exact_session NOT IN (
                            '90000000-0000-4000-8000-000000000004'::uuid,
                            '90000000-0000-4000-8000-000000000014'::uuid
                       )
                       OR exact_org<>'90000000-0000-4000-8000-000000000007'
                       OR exact_operation NOT IN (
                            'SUBMIT_REPORT','READ_OWN_REPORT','OPEN_APPEAL',
                            'READ_OWN_APPEAL','SAVE_APPEAL_DRAFT','SUBMIT_APPEAL'
                       ) THEN RETURN; END IF;
                    RETURN QUERY SELECT exact_actor,exact_session,exact_org,
                        'ACTIVE','ACTIVE','ACTIVE','ACTIVE',
                        '90000000-0000-4000-8000-000000000010'::uuid,'ACTIVE',
                        '90000000-0000-4000-8000-000000000011'::uuid,1::bigint,
                        'DEMAND_OWNER',true,sha256(convert_to(
                            exact_operation||exact_actor::text,'UTF8'));
                END $function$
                """
            )
            connection.execute(
                """
                CREATE FUNCTION iam_api.resolve_appeal_reviewer_authority_v1(
                    exact_actor uuid, exact_session uuid, exact_operation text
                ) RETURNS TABLE(
                    actor_user_id uuid,session_id uuid,user_status text,
                    session_status text,session_family_status text,
                    duty_grant_id uuid,duty_grant_version bigint,
                    duty_expires_at timestamptz,duty_code text,
                    authority_marker_sha256 bytea
                ) LANGUAGE plpgsql SECURITY DEFINER
                SET search_path=pg_catalog AS $function$
                DECLARE exact_duty uuid;
                BEGIN
                    IF current_setting('app.test_authority_disabled',true)='on'
                       OR session_user<>'trust_appeal'
                       OR exact_operation NOT IN (
                            'LIST_APPEAL_QUEUE','READ_ASSIGNED_APPEAL',
                            'CLAIM_APPEAL','RELEASE_APPEAL_ASSIGNMENT',
                            'SAVE_APPEAL_REVIEW_DRAFT','DECIDE_APPEAL'
                       ) THEN RETURN; END IF;
                    IF exact_actor =
                        '90000000-0000-4000-8000-000000000060'::uuid
                       AND exact_session IN (
                        '90000000-0000-4000-8000-000000000061'::uuid,
                        '90000000-0000-4000-8000-000000000062'::uuid
                       ) THEN
                        exact_duty :=
                            '90000000-0000-4000-8000-000000000063'::uuid;
                    ELSIF exact_actor =
                        '90000000-0000-4000-8000-000000000064'::uuid
                       AND exact_session =
                        '90000000-0000-4000-8000-000000000065'::uuid THEN
                        exact_duty :=
                            '90000000-0000-4000-8000-000000000066'::uuid;
                    ELSIF exact_actor =
                        '90000000-0000-4000-8000-000000000002'::uuid
                       AND exact_session =
                        '90000000-0000-4000-8000-000000000067'::uuid THEN
                        exact_duty :=
                            '90000000-0000-4000-8000-000000000068'::uuid;
                    ELSE RETURN; END IF;
                    RETURN QUERY SELECT exact_actor,exact_session,'ACTIVE',
                        'ACTIVE','ACTIVE',exact_duty,1::bigint,
                        transaction_timestamp()+interval '1 day',
                        'APPEAL_REVIEWER',sha256(convert_to(
                            exact_operation||exact_actor::text,'UTF8'));
                END $function$
                """
            )
            connection.execute(
                "GRANT EXECUTE ON FUNCTION "
                "iam_api.resolve_appeal_reviewer_authority_v1(uuid,uuid,text) "
                "TO trust_schema_owner"
            )
            connection.execute("RESET ROLE")
            connection.execute("SET ROLE demand_schema_owner")
            connection.execute(
                """
                CREATE FUNCTION demand_api.resolve_appeal_applicant_party_v1(
                    exact_actor uuid, exact_session uuid, exact_org uuid,
                    exact_membership uuid, exact_grant uuid,
                    exact_grant_version bigint, exact_demand uuid,
                    exact_demand_version uuid, exact_marker bytea
                ) RETURNS TABLE(applicant_party_marker_sha256 bytea)
                LANGUAGE sql SECURITY DEFINER
                SET search_path=pg_catalog AS $function$
                    SELECT sha256(convert_to(
                        'appeal-party|'||exact_actor::text||'|'||
                        exact_demand_version::text,'UTF8'))
                    WHERE session_user='trust_self'
                      AND exact_actor=
                        '90000000-0000-4000-8000-000000000001'::uuid
                      AND exact_session IN (
                        '90000000-0000-4000-8000-000000000004'::uuid,
                        '90000000-0000-4000-8000-000000000014'::uuid
                      )
                      AND exact_org=
                        '90000000-0000-4000-8000-000000000007'::uuid
                      AND exact_membership=
                        '90000000-0000-4000-8000-000000000010'::uuid
                      AND exact_grant=
                        '90000000-0000-4000-8000-000000000011'::uuid
                      AND exact_grant_version=1
                      AND exact_demand=
                        '90000000-0000-4000-8000-000000000008'::uuid
                      AND exact_demand_version=
                        '90000000-0000-4000-8000-000000000009'::uuid
                      AND octet_length(exact_marker)=32
                $function$
                """
            )
            connection.execute(
                "GRANT EXECUTE ON FUNCTION "
                "demand_api.resolve_appeal_applicant_party_v1("
                "uuid,uuid,uuid,uuid,uuid,bigint,uuid,uuid,bytea) "
                "TO trust_schema_owner"
            )

    @classmethod
    def _receipt(cls, seed: int) -> tuple[list, UUID, UUID, UUID]:
        with cls._admin() as connection:
            policy = connection.execute(
                "SELECT retained_idempotency_key_ids,retained_payload_key_ids "
                "FROM trust.appeal_receipt_key_policy WHERE singleton_key"
            ).fetchone()
        idempotency = [_digest(f"appeal-idempotency-{seed}-{key}") for key in policy[0]]
        payload = [_digest(f"appeal-payload-{seed}-{key}") for key in policy[1]]
        receipt_id = _uuid(1000 + seed)
        audit_id = _uuid(2000 + seed)
        outbox_id = _uuid(3000 + seed)
        return (
            [receipt_id, audit_id, outbox_id, policy[0], idempotency, policy[1], payload],
            receipt_id,
            audit_id,
            outbox_id,
        )

    @classmethod
    def _seal(
        cls,
        *,
        actor: UUID,
        session: UUID,
        organization: UUID | None,
        appeal_id: UUID,
        purpose: str,
        receipt_material: list,
        seed: int,
    ) -> tuple[str, bytes]:
        with cls._admin() as connection:
            encryption_keys = connection.execute(
                "SELECT retained_encryption_key_ids "
                "FROM trust.sealed_text_key_policy WHERE singleton_key"
            ).fetchone()[0]
        references = [
            f"sealed://trust/appeal-{seed}-{index}"
            for index, _ in enumerate(encryption_keys, start=1)
        ]
        plaintext_hmacs = [
            _digest(f"appeal-plaintext-{seed}-{key}") for key in encryption_keys
        ]
        key_id = encryption_keys[0]
        nonce = bytes([seed % 251 + 1]) * 12
        ciphertext = bytes([seed % 249 + 2]) * 64
        aad = hashlib.sha256(
            PsycopgAppealSealedTextProvider.associated_data(
                reference=references[0],
                appeal_id=appeal_id,
                actor_user_id=actor,
                purpose_code=purpose,
                plaintext_hmac_sha256=plaintext_hmacs[0],
                key_id=key_id,
            )
        ).digest()
        envelope = PsycopgAppealSealedTextProvider.envelope_digest(
            key_id=key_id,
            nonce=nonce,
            ciphertext=ciphertext,
            aad_sha256=aad,
        )
        arguments = [
            actor,
            session,
            organization,
            appeal_id,
            purpose,
            encryption_keys,
            references,
            plaintext_hmacs,
            envelope,
            key_id,
            nonce,
            ciphertext,
            aad,
            receipt_material[3],
            receipt_material[4],
            "APPEAL_RESTRICTED_TEXT",
            datetime.now(timezone.utc) + timedelta(days=365),
            None,
            None,
        ]
        role = "trust_self" if organization is not None else "trust_appeal"
        with cls._runtime(role) as connection:
            row = connection.execute(
                "SELECT * FROM trust_api.store_appeal_restricted_text_v1("
                + ",".join(["%s"] * len(arguments))
                + ")",
                arguments,
            ).fetchone()
            replay = connection.execute(
                "SELECT * FROM trust_api.store_appeal_restricted_text_v1("
                + ",".join(["%s"] * len(arguments))
                + ")",
                arguments,
            ).fetchone()
        assert row[4] is False
        assert replay[4] is True
        assert row[0] == references[0]
        assert row[1] == envelope
        return references[0], envelope

    def test_seven_writes_four_reads_replay_privacy_and_assignment_rules(self) -> None:
        appeal_id = _uuid(70)
        assignment_one = _uuid(71)
        assignment_two = _uuid(72)
        assignment_three = _uuid(73)
        decision_id = _uuid(74)

        open_material, *_ = self._receipt(70)
        open_args = [
            ACTOR_REPORTER,
            SESSION_REPORTER,
            ORGANIZATION,
            _uuid(4001),
            _uuid(4002),
            _uuid(4003),
            *open_material[:3],
            appeal_id,
            SOURCE_OUTCOME,
            *open_material[3:],
        ]
        with self._runtime("trust_self") as connection:
            opened = _call(connection, "open_appeal_v1", open_args)
            self.assertFalse(opened[1])
            self.assertEqual(opened[0]["appeal_status"], "DRAFT")
            replay_args = open_args.copy()
            replay_args[1] = SESSION_REPORTER_ROTATED
            replay_args[6:9] = [_uuid(4011), _uuid(4012), _uuid(4013)]
            replay_args[9] = _uuid(75)
            replay = _call(connection, "open_appeal_v1", replay_args)
            self.assertTrue(replay[1])
            self.assertEqual(replay[0], opened[0])
            by_source = connection.execute(
                "SELECT projection FROM "
                "trust_api.find_own_appeal_by_source_v1(%s,%s,%s,%s)",
                (ACTOR_REPORTER, SESSION_REPORTER_ROTATED, ORGANIZATION, SOURCE_OUTCOME),
            ).fetchone()[0]
            own = connection.execute(
                "SELECT projection FROM trust_api.read_own_appeal_v1(%s,%s,%s,%s)",
                (ACTOR_REPORTER, SESSION_REPORTER_ROTATED, ORGANIZATION, appeal_id),
            ).fetchone()[0]
            self.assertEqual(by_source, own)
            self.assertEqual(own["source"]["outcome_version_id"], str(SOURCE_OUTCOME))
            self.assertIsNone(
                connection.execute(
                    "SELECT projection FROM "
                    "trust_api.read_own_appeal_v1(%s,%s,%s,%s)",
                    (ACTOR_REPORTER, SESSION_REPORTER_ROTATED, _uuid(999), appeal_id),
                ).fetchone()
            )

            changed_payload_args = open_args.copy()
            changed_payload_args[1] = SESSION_REPORTER_ROTATED
            changed_payload_args[6:9] = [_uuid(4014), _uuid(4015), _uuid(4016)]
            changed_payload_args[14] = [_digest("changed-open-payload")]
            with self.assertRaises(psycopg.errors.UniqueViolation) as error:
                _call(connection, "open_appeal_v1", changed_payload_args)
            self.assertEqual(error.exception.diag.message_primary, "IDEMPOTENCY_KEY_REUSED")

        duplicate_material, *_ = self._receipt(71)
        duplicate_args = open_args.copy()
        duplicate_args[6:9] = duplicate_material[:3]
        duplicate_args[9] = _uuid(76)
        duplicate_args[11:] = duplicate_material[3:]
        with self._runtime("trust_self") as connection:
            with self.assertRaises(psycopg.errors.UniqueViolation) as error:
                _call(connection, "open_appeal_v1", duplicate_args)
            self.assertEqual(error.exception.diag.message_primary, "APPEAL_ALREADY_EXISTS")

        save_material, *_ = self._receipt(72)
        statement_reference, statement_sha256 = self._seal(
            actor=ACTOR_REPORTER,
            session=SESSION_REPORTER_ROTATED,
            organization=ORGANIZATION,
            appeal_id=appeal_id,
            purpose="APPEAL_STATEMENT",
            receipt_material=save_material,
            seed=72,
        )
        save_args = [
            ACTOR_REPORTER,
            SESSION_REPORTER_ROTATED,
            ORGANIZATION,
            _uuid(4021),
            _uuid(4022),
            _uuid(4023),
            *save_material[:3],
            appeal_id,
            1,
            *save_material[3:],
            statement_reference,
            statement_sha256,
            ["PROCEDURAL_ERROR"],
            "VACATE_AND_REMAND",
            [],
        ]
        with self._runtime("trust_self") as connection:
            saved = _call(connection, "save_appeal_draft_v1", save_args)
            self.assertEqual(saved[0]["aggregate_version"], 2)
            self.assertEqual(saved[0]["application_draft_version"], 1)

        submit_material, *_ = self._receipt(73)
        submit_args = [
            ACTOR_REPORTER,
            SESSION_REPORTER_ROTATED,
            ORGANIZATION,
            _uuid(4031),
            _uuid(4032),
            _uuid(4033),
            *submit_material[:3],
            appeal_id,
            2,
            1,
            *submit_material[3:],
        ]
        with self._runtime("trust_self") as connection:
            submitted = _call(connection, "submit_appeal_v1", submit_args)
            self.assertEqual(submitted[0]["appeal_status"], "SUBMITTED")
            self.assertEqual(submitted[0]["aggregate_version"], 3)

        with self._runtime("trust_appeal") as connection:
            rejected_null_limit = connection.execute(
                "SELECT projection FROM trust_api.list_appeal_queue_v1(%s,%s,%s)",
                (REVIEWER_ONE, REVIEWER_ONE_SESSION, None),
            ).fetchall()
            self.assertEqual(rejected_null_limit, [])
            queued = connection.execute(
                "SELECT projection FROM trust_api.list_appeal_queue_v1(%s,%s,%s)",
                (REVIEWER_ONE, REVIEWER_ONE_SESSION, 100),
            ).fetchall()
            self.assertEqual(
                [item["appeal_id"] for item in queued[0][0]["items"]],
                [str(appeal_id)],
            )

        conflict_material, *_ = self._receipt(74)
        conflict_args = [
            ACTOR_OFFICER_ONE,
            DECIDING_OFFICER_REVIEW_SESSION,
            _uuid(4041),
            _uuid(4042),
            _uuid(4043),
            *conflict_material[:3],
            _uuid(77),
            appeal_id,
            3,
            *conflict_material[3:],
        ]
        with self._runtime("trust_appeal") as connection:
            with self.assertRaises(psycopg.errors.InsufficientPrivilege) as error:
                _call(connection, "claim_appeal_v1", conflict_args)
            self.assertEqual(error.exception.diag.message_primary, "CONFLICT_OF_INTEREST")

        claim_one_material, *_ = self._receipt(75)
        claim_one_args = [
            REVIEWER_ONE,
            REVIEWER_ONE_SESSION,
            _uuid(4051),
            _uuid(4052),
            _uuid(4053),
            *claim_one_material[:3],
            assignment_one,
            appeal_id,
            3,
            *claim_one_material[3:],
        ]
        with self._runtime("trust_appeal") as connection:
            claimed = _call(connection, "claim_appeal_v1", claim_one_args)
            self.assertEqual(claimed[0]["appeal_status"], "IN_REVIEW")
            self.assertEqual(claimed[0]["aggregate_version"], 4)
            assigned = connection.execute(
                "SELECT projection FROM trust_api.read_assigned_appeal_v1(%s,%s,%s)",
                (REVIEWER_ONE, REVIEWER_ONE_SESSION, appeal_id),
            ).fetchone()[0]
            self.assertEqual(assigned["appeal"]["appeal_id"], str(appeal_id))
            self.assertNotIn("assignment_id", json.dumps(assigned))

        wrong_release_material, *_ = self._receipt(76)
        wrong_release_args = [
            REVIEWER_TWO,
            REVIEWER_TWO_SESSION,
            _uuid(4061),
            _uuid(4062),
            _uuid(4063),
            *wrong_release_material[:3],
            appeal_id,
            4,
            "WORKLOAD_RELEASE",
            *wrong_release_material[3:],
        ]
        with self._runtime("trust_appeal") as connection:
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                _call(connection, "release_appeal_assignment_v1", wrong_release_args)

        release_one_material, *_ = self._receipt(77)
        release_one_args = [
            REVIEWER_ONE,
            REVIEWER_ONE_SESSION,
            _uuid(4071),
            _uuid(4072),
            _uuid(4073),
            *release_one_material[:3],
            appeal_id,
            4,
            "WORKLOAD_RELEASE",
            *release_one_material[3:],
        ]
        with self._runtime("trust_appeal") as connection:
            released = _call(connection, "release_appeal_assignment_v1", release_one_args)
            self.assertEqual(released[0]["aggregate_version"], 5)
            self.assertEqual(released[0]["appeal_status"], "SUBMITTED")

        claim_two_material, *_ = self._receipt(78)
        claim_two_args = claim_one_args.copy()
        claim_two_args[0] = REVIEWER_ONE
        claim_two_args[1] = REVIEWER_ONE_ROTATED_SESSION
        claim_two_args[2:5] = [_uuid(4081), _uuid(4082), _uuid(4083)]
        claim_two_args[5:8] = claim_two_material[:3]
        claim_two_args[8] = assignment_two
        claim_two_args[10] = 5
        claim_two_args[11:] = claim_two_material[3:]
        with self._runtime("trust_appeal") as connection:
            second_claim = _call(connection, "claim_appeal_v1", claim_two_args)
            self.assertEqual(second_claim[0]["aggregate_version"], 6)

        with self._admin() as connection:
            now = datetime.now(timezone.utc)
            connection.execute("SET session_replication_role=replica")
            connection.execute(
                "UPDATE trust.appeal_review_assignments "
                "SET conflict_evaluated_at=%s,assigned_at=%s,expires_at=%s "
                "WHERE assignment_id=%s",
                (
                    now - timedelta(minutes=3),
                    now - timedelta(minutes=2),
                    now - timedelta(minutes=1),
                    assignment_two,
                ),
            )
            connection.execute("SET session_replication_role=origin")

        expiry_release_material, *_ = self._receipt(79)
        expiry_release_args = [
            REVIEWER_TWO,
            REVIEWER_TWO_SESSION,
            _uuid(4091),
            _uuid(4092),
            _uuid(4093),
            *expiry_release_material[:3],
            appeal_id,
            6,
            "ASSIGNMENT_EXPIRED",
            *expiry_release_material[3:],
        ]
        with self._runtime("trust_appeal") as connection:
            expired_release = _call(
                connection, "release_appeal_assignment_v1", expiry_release_args
            )
            self.assertEqual(expired_release[0]["aggregate_version"], 7)

        claim_three_material, *_ = self._receipt(80)
        claim_three_args = claim_one_args.copy()
        claim_three_args[1] = REVIEWER_ONE_ROTATED_SESSION
        claim_three_args[2:5] = [_uuid(4101), _uuid(4102), _uuid(4103)]
        claim_three_args[5:8] = claim_three_material[:3]
        claim_three_args[8] = assignment_three
        claim_three_args[10] = 7
        claim_three_args[11:] = claim_three_material[3:]
        with self._runtime("trust_appeal") as connection:
            third_claim = _call(connection, "claim_appeal_v1", claim_three_args)
            self.assertEqual(third_claim[0]["aggregate_version"], 8)

        review_material, *_ = self._receipt(81)
        review_reference, review_sha256 = self._seal(
            actor=REVIEWER_ONE,
            session=REVIEWER_ONE_ROTATED_SESSION,
            organization=None,
            appeal_id=appeal_id,
            purpose="APPEAL_REVIEW_NOTE",
            receipt_material=review_material,
            seed=81,
        )
        assessments = [
            {
                "ground": "PROCEDURAL_ERROR",
                "assessment_code": "ACCEPTED",
                "finding_codes": ["PROCEDURE_MATERIAL_ERROR"],
                "accepted_evidence_reference_ids": [],
            }
        ]
        review_args = [
            REVIEWER_ONE,
            REVIEWER_ONE_ROTATED_SESSION,
            _uuid(4111),
            _uuid(4112),
            _uuid(4113),
            *review_material[:3],
            appeal_id,
            8,
            *review_material[3:],
            review_reference,
            review_sha256,
            json.dumps(assessments),
            ["PROCEDURAL_REVIEW_COMPLETE", "REMAND_REQUIRED"],
            ["RETURN_TO_TRUST_REVIEW"],
        ]
        with self._runtime("trust_appeal") as connection:
            reviewed = _call(connection, "save_appeal_review_draft_v1", review_args)
            self.assertEqual(reviewed[0]["aggregate_version"], 9)
            self.assertEqual(reviewed[0]["review_draft_version"], 1)
            review_projection = connection.execute(
                "SELECT projection FROM trust_api.read_assigned_appeal_v1(%s,%s,%s)",
                (REVIEWER_ONE, REVIEWER_ONE_ROTATED_SESSION, appeal_id),
            ).fetchone()[0]
            self.assertTrue(review_projection["review_draft"]["review_note_recorded"])
            self.assertNotIn("sealed_", json.dumps(review_projection))

        decide_material, *_ = self._receipt(82)
        decide_args = [
            REVIEWER_ONE,
            REVIEWER_ONE_ROTATED_SESSION,
            _uuid(4121),
            _uuid(4122),
            _uuid(4123),
            *decide_material[:3],
            decision_id,
            appeal_id,
            9,
            1,
            "VACATE_AND_REMAND",
            *decide_material[3:],
        ]
        with self._runtime("trust_appeal") as connection:
            decided = _call(connection, "decide_appeal_v1", decide_args)
            self.assertEqual(decided[0]["appeal_status"], "DECIDED")
            self.assertEqual(decided[0]["aggregate_version"], 10)

        # Old commands replay from retained receipts after all business state changed.
        save_replay_args = save_args.copy()
        save_replay_args[1] = SESSION_REPORTER
        save_replay_args[3:9] = [
            _uuid(4201), _uuid(4202), _uuid(4203),
            _uuid(4204), _uuid(4205), _uuid(4206),
        ]
        release_replay_args = release_one_args.copy()
        release_replay_args[1] = REVIEWER_ONE_ROTATED_SESSION
        release_replay_args[2:8] = [
            _uuid(4211), _uuid(4212), _uuid(4213),
            _uuid(4214), _uuid(4215), _uuid(4216),
        ]
        submit_replay_args = submit_args.copy()
        submit_replay_args[1] = SESSION_REPORTER
        submit_replay_args[3:9] = [
            _uuid(4221), _uuid(4222), _uuid(4223),
            _uuid(4224), _uuid(4225), _uuid(4226),
        ]
        claim_replay_args = claim_one_args.copy()
        claim_replay_args[1] = REVIEWER_ONE_ROTATED_SESSION
        claim_replay_args[2:8] = [
            _uuid(4231), _uuid(4232), _uuid(4233),
            _uuid(4234), _uuid(4235), _uuid(4236),
        ]
        review_replay_args = review_args.copy()
        review_replay_args[1] = REVIEWER_ONE_SESSION
        review_replay_args[2:8] = [
            _uuid(4241), _uuid(4242), _uuid(4243),
            _uuid(4244), _uuid(4245), _uuid(4246),
        ]
        decide_replay_args = decide_args.copy()
        decide_replay_args[1] = REVIEWER_ONE_SESSION
        decide_replay_args[2:8] = [
            _uuid(4251), _uuid(4252), _uuid(4253),
            _uuid(4254), _uuid(4255), _uuid(4256),
        ]
        with self._runtime("trust_self") as connection:
            save_replay = _call(connection, "save_appeal_draft_v1", save_replay_args)
            submit_replay = _call(connection, "submit_appeal_v1", submit_replay_args)
            self.assertEqual(save_replay, (saved[0], True))
            self.assertEqual(submit_replay, (submitted[0], True))
            final_own = connection.execute(
                "SELECT projection FROM trust_api.read_own_appeal_v1(%s,%s,%s,%s)",
                (ACTOR_REPORTER, SESSION_REPORTER, ORGANIZATION, appeal_id),
            ).fetchone()[0]
        with self._runtime("trust_appeal") as connection:
            self.assertEqual(
                _call(connection, "claim_appeal_v1", claim_replay_args),
                (claimed[0], True),
            )
            self.assertEqual(
                _call(connection, "release_appeal_assignment_v1", release_replay_args),
                (released[0], True),
            )
            self.assertEqual(
                _call(connection, "save_appeal_review_draft_v1", review_replay_args),
                (reviewed[0], True),
            )
            self.assertEqual(
                _call(connection, "decide_appeal_v1", decide_replay_args),
                (decided[0], True),
            )

        new_idempotency_key_id = "trust-idempotency-2026-02"
        new_payload_key_id = "trust-payload-2026-02"
        with psycopg.connect(
            self.postgres.conninfo(
                database=self.database,
                user="trust_migration_runner",
            ),
            autocommit=False,
        ) as connection:
            connection.execute("SET ROLE trust_schema_owner")
            connection.execute(
                "SELECT set_config('app.appeal_scope_kind',"
                "'APPEAL_KEY_ROTATION',true)"
            )
            connection.execute(
                "UPDATE trust.appeal_receipt_key_policy SET "
                "active_idempotency_key_id=%s,active_payload_key_id=%s,"
                "retained_idempotency_key_ids=ARRAY[%s,%s]::text[],"
                "retained_payload_key_ids=ARRAY[%s,%s]::text[],"
                "updated_at=transaction_timestamp() WHERE singleton_key",
                (
                    new_idempotency_key_id,
                    new_payload_key_id,
                    new_idempotency_key_id,
                    open_material[3][0],
                    new_payload_key_id,
                    open_material[5][0],
                ),
            )
            connection.commit()

        retained_replay_args = open_args.copy()
        retained_replay_args[1] = SESSION_REPORTER_ROTATED
        retained_replay_args[6:9] = [_uuid(4261), _uuid(4262), _uuid(4263)]
        retained_replay_args[9] = _uuid(78)
        retained_replay_args[11] = [new_idempotency_key_id, open_material[3][0]]
        retained_replay_args[12] = [
            _digest("rotated-open-idempotency"),
            open_material[4][0],
        ]
        retained_replay_args[13] = [new_payload_key_id, open_material[5][0]]
        retained_replay_args[14] = [
            _digest("rotated-open-payload"),
            open_material[6][0],
        ]
        with self._runtime("trust_self") as connection:
            self.assertEqual(
                _call(connection, "open_appeal_v1", retained_replay_args),
                (opened[0], True),
            )

        with psycopg.connect(
            self.postgres.conninfo(
                database=self.database,
                user="trust_migration_runner",
            ),
            autocommit=False,
        ) as connection:
            connection.execute("SET ROLE trust_schema_owner")
            connection.execute(
                "SELECT set_config('app.appeal_scope_kind',"
                "'APPEAL_KEY_ROTATION',true)"
            )
            with self.assertRaises(psycopg.errors.CheckViolation) as error:
                connection.execute(
                    "UPDATE trust.appeal_receipt_key_policy SET "
                    "retained_idempotency_key_ids=ARRAY[%s]::text[],"
                    "retained_payload_key_ids=ARRAY[%s]::text[],"
                    "updated_at=transaction_timestamp() WHERE singleton_key",
                    (new_idempotency_key_id, new_payload_key_id),
                )
            self.assertEqual(
                error.exception.diag.message_primary,
                "APPEAL_RECEIPT_KEY_STILL_RETAINED",
            )
            connection.rollback()

        serialized = json.dumps(final_own, sort_keys=True)
        self.assertTrue(final_own["application"]["statement_recorded"])
        self.assertEqual(
            final_own["decision"]["assessments"][0]["ground"],
            "PROCEDURAL_ERROR",
        )
        for forbidden in (
            "sealed_", "assignment_id", "duty_grant", "reviewer_user_id",
            statement_reference, review_reference,
        ):
            self.assertNotIn(forbidden, serialized)

        with self._admin() as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT count(*) FROM trust.appeal_command_receipts "
                    "WHERE target_appeal_id=%s",
                    (appeal_id,),
                ).fetchone()[0],
                10,
            )
            self.assertEqual(
                connection.execute(
                    "SELECT count(*) FROM infra.outbox_events "
                    "WHERE aggregate_type='Appeal' AND aggregate_id=%s",
                    (appeal_id,),
                ).fetchone()[0],
                10,
            )
            leak_count = connection.execute(
                "SELECT count(*) FROM infra.outbox_events "
                "WHERE aggregate_type='Appeal' AND payload::text LIKE %s",
                ("%sealed://trust/%",),
            ).fetchone()[0]
            self.assertEqual(leak_count, 0)

        with self._runtime("trust_self") as connection:
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                connection.execute("SELECT count(*) FROM trust.appeals").fetchone()
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                connection.execute(
                    "SELECT * FROM trust_api.list_appeal_queue_v1(%s,%s,%s)",
                    (REVIEWER_ONE, REVIEWER_ONE_SESSION, 100),
                ).fetchall()


if __name__ == "__main__":
    unittest.main()
