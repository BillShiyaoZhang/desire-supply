"""PostgreSQL 18 semantics for Trust writes and owned report discovery."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
import unittest
from uuid import UUID

import psycopg
from psycopg.types.json import Jsonb

from tests.storage.postgres.postgres18_harness import TemporaryPostgres18


PLATFORM_ROOT = Path(__file__).resolve().parents[3]
TRUST_MIGRATIONS = (
    PLATFORM_ROOT
    / "src/desire_platform/trust_safety/adapters/postgres/migrations"
)
TRUST_OWNED_REPORT_DISCOVERY = (
    PLATFORM_ROOT
    / "src/desire_platform/trust_safety/adapters/postgres/migrations"
    / "0009_expand__owned_report_discovery.sql"
)
TRUST_MIGRATIONS = (
    TRUST_MIGRATIONS / "0001_expand__demand_safety_case_v1.sql",
    TRUST_MIGRATIONS / "0004_expand__claim_receipt_http_status_v2.sql",
)


def _uuid(number: int) -> UUID:
    return UUID(f"90000000-0000-4000-8000-{number:012d}")


ACTOR_REPORTER = _uuid(1)
ACTOR_OFFICER_ONE = _uuid(2)
ACTOR_OFFICER_TWO = _uuid(3)
SESSION_REPORTER = _uuid(4)
SESSION_OFFICER_ONE = _uuid(5)
SESSION_OFFICER_TWO = _uuid(6)
ORGANIZATION = _uuid(7)
DEMAND = _uuid(8)
DEMAND_VERSION = _uuid(9)
MEMBERSHIP = _uuid(10)
MEMBERSHIP_GRANT = _uuid(11)
DUTY_ONE = _uuid(12)
DUTY_TWO = _uuid(13)
SESSION_REPORTER_ROTATED = _uuid(14)
SESSION_OFFICER_TWO_ROTATED = _uuid(15)
SESSION_OFFICER_ONE_ROTATED = _uuid(16)

IDEMPOTENCY_KEY_IDS = [
    "trust-idempotency-2026-01",
]
PAYLOAD_KEY_IDS = [
    "trust-payload-2026-01",
]


def _digests(seed: int) -> tuple[list[bytes], list[bytes]]:
    return (
        [bytes([seed]) * 32],
        [bytes([seed + 1]) * 32],
    )


def _call(connection: psycopg.Connection, function_name: str, arguments: list):
    placeholders = ",".join(["%s"] * len(arguments))
    return connection.execute(
        f"SELECT safe_response,replayed FROM trust_api.{function_name}("
        f"{placeholders})",
        arguments,
    ).fetchone()


def _insert_completed_claim_receipt(
    connection: psycopg.Connection,
    *,
    receipt_id: UUID,
    actor_id: UUID,
    case_id: UUID,
    safe_response: dict,
    idempotency_digest: bytes,
    payload_hash: bytes,
    response_http_status: int,
) -> None:
    completed_at = safe_response["completed_at"]
    connection.execute(
        "INSERT INTO trust.command_receipts("
        "receipt_id,principal_kind,principal_id,organization_id,"
        "command_domain,command_name,command_version,"
        "idempotency_key_digest_key_id,idempotency_key_digest,"
        "payload_hash_key_id,canonicalization_version,payload_hash,"
        "http_method,canonical_path,if_match_version,status,"
        "response_http_status,response_schema_name,response_schema_version,"
        "response_entity_tag,safe_response,target_case_id,target_version,"
        "result_status,event_types,retain_until,created_at,completed_at) "
        "VALUES(%s,'USER',%s,NULL,'TRUST_SAFETY','CLAIM_CASE',1,"
        "%s,%s,%s,'trust-command-json-v1',%s,'POST',"
        "'/v1/app/trust/queue/{case_id}/claim',1,'COMPLETED',"
        "%s,'TrustCommandResult',1,"
        "trust.entity_tag_v1('SafetyCase',%s,2,'TRIAGING',%s::timestamptz),"
        "%s,%s,2,'TRIAGING',ARRAY['TrustCaseClaimed']::text[],"
        "%s::timestamptz + interval '90 days',"
        "%s::timestamptz - interval '1 millisecond',%s::timestamptz)",
        (
            receipt_id,
            actor_id,
            IDEMPOTENCY_KEY_IDS[0],
            idempotency_digest,
            PAYLOAD_KEY_IDS[0],
            payload_hash,
            response_http_status,
            case_id,
            completed_at,
            Jsonb(safe_response),
            case_id,
            completed_at,
            completed_at,
            completed_at,
        ),
    )


def _sealed_aad(
    reference: str,
    case_id: UUID,
    actor_id: UUID,
    plaintext_hmac_sha256: bytes,
    key_id: str,
) -> bytes:
    material = "\x1f".join(
        (
            "desire:trust:restricted-text-aad:v1",
            reference,
            str(case_id),
            str(actor_id),
            "TRIAGE_NOTE",
            plaintext_hmac_sha256.hex(),
            key_id,
        )
    ).encode("utf-8")
    return hashlib.sha256(material).digest()


def _sealed_envelope(
    key_id: str,
    nonce: bytes,
    ciphertext: bytes,
    aad_sha256: bytes,
) -> bytes:
    material = "\x1f".join(
        (
            "desire:trust:restricted-text-envelope:v1",
            key_id,
            nonce.hex(),
            ciphertext.hex(),
            aad_sha256.hex(),
        )
    ).encode("utf-8")
    return hashlib.sha256(material).digest()


def _utc_text(value: datetime) -> str:
    return (
        value.astimezone(timezone.utc)
        .strftime("%Y-%m-%dT%H:%M:%S.%f")
        .rstrip("0")
        .rstrip(".")
        + "Z"
    )


def _outcome_source_digest(canonical_source_document: str) -> bytes:
    return hashlib.sha256(
        "\x1f".join(
            (
                "desire:trust:outcome-source:v1",
                canonical_source_document,
            )
        ).encode("utf-8")
    ).digest()


def _outcome_packet_digest(
    packet_id: UUID,
    source_digest: bytes,
    outcome_code: str,
    reason_codes: list[str],
    action_codes: list[str],
    appeal_deadline: datetime,
    evaluated_at: datetime,
    valid_until: datetime,
) -> bytes:
    return hashlib.sha256(
        "\x1f".join(
            (
                "desire:trust:outcome-evidence-packet:v1",
                "trust-evidence-redaction-v1",
                str(packet_id),
                source_digest.hex(),
                outcome_code,
                "\x1e".join(reason_codes),
                "\x1e".join(action_codes),
                "ELIGIBLE",
                _utc_text(appeal_deadline),
                "trust-case-outcome-v1",
                "PARTY_SAFE_V1",
                _utc_text(evaluated_at),
                _utc_text(valid_until),
            )
        ).encode("utf-8")
    ).digest()


class TrustPostgresCommandsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.postgres = TemporaryPostgres18().start()
        cls.database = cls.postgres.create_database()
        with psycopg.connect(
            cls.postgres.admin_conninfo(database="postgres"),
            autocommit=True,
        ) as connection:
            connection.execute(
                f'GRANT CREATE ON DATABASE "{cls.database}" '
                "TO trust_schema_owner"
            )
            connection.execute(
                "GRANT trust_schema_owner TO trust_migration_runner "
                "WITH INHERIT FALSE, SET TRUE"
            )
            connection.execute(
                "GRANT schema_owner TO trust_migration_runner "
                "WITH INHERIT FALSE, SET TRUE"
            )
        cls._install_dependencies()
        with psycopg.connect(
            cls.postgres.conninfo(
                database=cls.database,
                user="trust_migration_runner",
            ),
            autocommit=False,
        ) as connection:
            connection.execute("SET ROLE trust_schema_owner")
            connection.execute(TRUST_MIGRATIONS[0].read_text(encoding="utf-8"))
            cls.reader_before_0004 = connection.execute(
                "SELECT pg_get_functiondef("
                "'trust_api.read_completed_command_receipt_v1("
                "uuid,uuid,uuid,text,uuid,bigint,text[],bytea[],text[],bytea[])'"
                "::regprocedure)"
            ).fetchone()[0]
            connection.execute(TRUST_MIGRATIONS[1].read_text(encoding="utf-8"))
            cls.reader_after_0004 = connection.execute(
                "SELECT pg_get_functiondef("
                "'trust_api.read_completed_command_receipt_v1("
                "uuid,uuid,uuid,text,uuid,bigint,text[],bytea[],text[],bytea[])'"
                "::regprocedure)"
            ).fetchone()[0]
            discovery = TRUST_OWNED_REPORT_DISCOVERY.read_text(encoding="utf-8")
            discovery_start = discovery.index(
                "CREATE FUNCTION trust_api.list_own_reports_v1("
            )
            discovery_end = discovery.index(
                ") TO trust_self;", discovery_start
            ) + len(") TO trust_self;")
            connection.execute(discovery[discovery_start:discovery_end])
            connection.commit()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.postgres.stop()

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
    def _install_dependencies(cls) -> None:
        with cls._admin() as connection:
            connection.execute("SET ROLE schema_owner")
            connection.execute("CREATE SCHEMA audit AUTHORIZATION schema_owner")
            connection.execute("CREATE SCHEMA infra AUTHORIZATION schema_owner")
            connection.execute("CREATE SCHEMA iam_api AUTHORIZATION schema_owner")
            connection.execute(
                "CREATE TABLE audit.audit_events ("
                "event_id uuid PRIMARY KEY,occurred_at timestamptz NOT NULL,"
                "actor_kind text NOT NULL,actor_id uuid NOT NULL,"
                "original_actor_id uuid NULL,action_code varchar(96) NOT NULL,"
                "target_kind varchar(64) NOT NULL,target_id uuid NOT NULL,"
                "organization_id uuid NULL,before_status varchar(64) NULL,"
                "after_status varchar(64) NULL,before_version bigint NULL,"
                "after_version bigint NULL,role_code varchar(128) NULL,"
                "purpose_code varchar(128) NULL,reason_code varchar(128) NULL,"
                "auth_strength_code varchar(128) NULL,result_code varchar(64) NOT NULL,"
                "command_id uuid NOT NULL,correlation_id uuid NOT NULL,"
                "causation_id uuid NOT NULL,trace_id uuid NOT NULL,"
                "safe_attributes jsonb NOT NULL)"
            )
            connection.execute(
                "CREATE TABLE infra.outbox_events ("
                "event_id uuid PRIMARY KEY,event_type varchar(96) NOT NULL,"
                "schema_version integer NOT NULL,occurred_at timestamptz NOT NULL,"
                "aggregate_type varchar(64) NOT NULL,aggregate_id uuid NOT NULL,"
                "aggregate_version bigint NOT NULL,actor_kind text NOT NULL,"
                "actor_id uuid NOT NULL,original_actor_id uuid NULL,"
                "correlation_id uuid NOT NULL,causation_id uuid NOT NULL,"
                "trace_id uuid NOT NULL,organization_id uuid NULL,"
                "payload jsonb NOT NULL,delivery_status text NOT NULL,"
                "attempt_count integer NOT NULL,available_at timestamptz NOT NULL,"
                "lease_owner varchar(128) NULL,lease_until timestamptz NULL,"
                "published_at timestamptz NULL,last_error_code varchar(64) NULL,"
                "created_at timestamptz NOT NULL,"
                "UNIQUE(causation_id,event_type,aggregate_type,aggregate_id))"
            )
            connection.execute(
                "ALTER TABLE audit.audit_events ENABLE ROW LEVEL SECURITY"
            )
            connection.execute(
                "ALTER TABLE audit.audit_events FORCE ROW LEVEL SECURITY"
            )
            connection.execute(
                "ALTER TABLE infra.outbox_events ENABLE ROW LEVEL SECURITY"
            )
            connection.execute(
                "ALTER TABLE infra.outbox_events FORCE ROW LEVEL SECURITY"
            )
            connection.execute(
                """
                CREATE FUNCTION iam_api.resolve_trust_reporter_authority_v1(
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
                            'SUBMIT_REPORT','READ_OWN_REPORT'
                       ) THEN RETURN; END IF;
                    RETURN QUERY SELECT exact_actor,exact_session,exact_org,
                        'ACTIVE','ACTIVE','ACTIVE','ACTIVE',
                        '90000000-0000-4000-8000-000000000010'::uuid,'ACTIVE',
                        '90000000-0000-4000-8000-000000000011'::uuid,1::bigint,
                        'DEMAND_OWNER',true,decode(repeat('a1',32),'hex');
                END $function$
                """
            )
            connection.execute(
                """
                CREATE FUNCTION iam_api.resolve_trust_officer_authority_v1(
                    exact_actor uuid, exact_session uuid, exact_operation text
                ) RETURNS TABLE(
                    actor_user_id uuid,session_id uuid,user_status text,
                    session_status text,session_family_status text,
                    duty_grant_id uuid,duty_grant_version bigint,
                    duty_expires_at timestamptz,duty_code text,
                    authority_marker_sha256 bytea
                ) LANGUAGE plpgsql SECURITY DEFINER
                SET search_path=pg_catalog AS $function$
                DECLARE duty uuid; expected_session uuid;
                BEGIN
                    IF current_setting('app.test_authority_disabled',true)='on'
                       OR session_user<>'trust_officer' THEN RETURN; END IF;
                    IF exact_actor =
                        '90000000-0000-4000-8000-000000000002'::uuid THEN
                        duty := '90000000-0000-4000-8000-000000000012'::uuid;
                        IF exact_session NOT IN (
                            '90000000-0000-4000-8000-000000000005'::uuid,
                            '90000000-0000-4000-8000-000000000016'::uuid
                        ) THEN RETURN; END IF;
                        expected_session := exact_session;
                    ELSIF exact_actor =
                        '90000000-0000-4000-8000-000000000003'::uuid THEN
                        duty := '90000000-0000-4000-8000-000000000013'::uuid;
                        IF exact_session NOT IN (
                            '90000000-0000-4000-8000-000000000006'::uuid,
                            '90000000-0000-4000-8000-000000000015'::uuid
                        ) THEN RETURN; END IF;
                        expected_session := exact_session;
                    ELSE
                        RETURN;
                    END IF;
                    IF exact_session <> expected_session THEN RETURN; END IF;
                    RETURN QUERY SELECT exact_actor,exact_session,'ACTIVE',
                        'ACTIVE','ACTIVE',duty,1::bigint,
                        transaction_timestamp()+interval '1 day',
                        'TRUST_OFFICER',sha256(convert_to(
                            exact_operation||exact_actor::text,'UTF8'));
                END $function$
                """
            )
            connection.execute(
                "GRANT USAGE ON SCHEMA iam_api TO trust_schema_owner"
            )
            connection.execute(
                "GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA iam_api "
                "TO trust_schema_owner"
            )
            connection.execute("RESET ROLE")
            connection.execute("SET ROLE demand_schema_owner")
            connection.execute(
                "CREATE SCHEMA demand_api AUTHORIZATION demand_schema_owner"
            )
            connection.execute(
                """
                CREATE FUNCTION demand_api.resolve_trust_report_target_v1(
                    exact_actor uuid,exact_session uuid,exact_org uuid,
                    exact_membership uuid,exact_grant uuid,
                    exact_grant_version bigint,exact_demand uuid,
                    exact_demand_version uuid,exact_marker bytea
                ) RETURNS TABLE(
                    organization_id uuid,demand_id uuid,demand_version_id uuid,
                    demand_version_no integer,demand_aggregate_version bigint,
                    demand_status text,content_sha256 bytea,owner_user_id uuid,
                    reportable_until timestamptz,
                    reporter_party_marker_sha256 bytea,
                    target_marker_sha256 bytea
                ) LANGUAGE sql SECURITY DEFINER
                SET search_path=pg_catalog AS $function$
                    SELECT exact_org,exact_demand,exact_demand_version,1,3::bigint,
                        'SUBMITTED',decode(repeat('b1',32),'hex'),exact_actor,
                        transaction_timestamp()+interval '1 day',
                        decode(repeat('b2',32),'hex'),decode(repeat('b3',32),'hex')
                    WHERE session_user='trust_self'
                      AND exact_membership=
                        '90000000-0000-4000-8000-000000000010'::uuid
                      AND exact_grant=
                        '90000000-0000-4000-8000-000000000011'::uuid
                      AND exact_grant_version=1
                      AND octet_length(exact_marker)=32
                $function$
                """
            )
            connection.execute(
                """
                CREATE FUNCTION demand_api.resolve_trust_officer_conflict_v1(
                    exact_actor uuid,exact_session uuid,exact_operation text,
                    exact_duty uuid,exact_duty_version bigint,exact_org uuid,
                    exact_demand uuid,exact_demand_version uuid,
                    exact_marker bytea
                ) RETURNS TABLE(
                    officer_user_id uuid,organization_id uuid,demand_id uuid,
                    demand_version_id uuid,conflict_free boolean,
                    conflict_attestation_sha256 bytea,
                    evaluated_at timestamptz,valid_until timestamptz
                ) LANGUAGE sql SECURITY DEFINER
                SET search_path=pg_catalog AS $function$
                    SELECT exact_actor,exact_org,exact_demand,exact_demand_version,
                        true,sha256(convert_to(
                            exact_operation||exact_actor::text,'UTF8')),
                        transaction_timestamp(),
                        transaction_timestamp()+interval '5 minutes'
                    WHERE session_user='trust_officer'
                      AND exact_operation IN ('CLAIM_CASE','CLAIM_HOLD_RELEASE')
                      AND exact_duty_version=1
                      AND octet_length(exact_marker)=32
                $function$
                """
            )
            connection.execute(
                "GRANT USAGE ON SCHEMA demand_api TO trust_schema_owner"
            )
            connection.execute(
                "GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA demand_api "
                "TO trust_schema_owner"
            )

    @staticmethod
    def _context(seed: int) -> list[UUID]:
        return [_uuid(seed), _uuid(seed + 1), _uuid(seed + 2)]

    @staticmethod
    def _receipt(seed: int) -> tuple[list, UUID, UUID, UUID]:
        idempotency, payload = _digests(seed)
        receipt_id, audit_id, outbox_id = _uuid(seed + 100), _uuid(
            seed + 200
        ), _uuid(seed + 300)
        return (
            [
                receipt_id,
                audit_id,
                outbox_id,
                IDEMPOTENCY_KEY_IDS,
                idempotency,
                PAYLOAD_KEY_IDS,
                payload,
            ],
            receipt_id,
            audit_id,
            outbox_id,
        )

    @staticmethod
    def _insert_discovery_report(
        connection: psycopg.Connection,
        *,
        seed: int,
        reporter_user_id: UUID,
        organization_id: UUID,
        created_at: datetime,
        decided: bool,
    ) -> tuple[UUID, UUID | None]:
        report_id = _uuid(seed)
        case_id = _uuid(seed + 100)
        demand_id = _uuid(seed + 200)
        demand_version_id = _uuid(seed + 300)
        outcome_id = _uuid(seed + 400) if decided else None
        assignment_id = _uuid(seed + 500) if decided else None
        decided_at = created_at + timedelta(minutes=2)
        connection.execute("SET CONSTRAINTS ALL DEFERRED")
        connection.execute(
            "INSERT INTO trust.reports("
            "report_id,case_id,organization_id,demand_id,demand_version_id,"
            "demand_version_no,demand_aggregate_version,demand_status,"
            "demand_content_sha256,demand_owner_user_id,reportable_until,"
            "reporter_user_id,reporter_membership_id,reporter_role_grant_id,"
            "reporter_role_grant_version,reporter_authority_marker_sha256,"
            "reporter_party_marker_sha256,target_marker_sha256,category,"
            "incident_started_at,incident_ended_at,impact_codes,"
            "evidence_reference_ids,requested_protection_codes,created_at) "
            "VALUES(%s,%s,%s,%s,%s,1,1,'SUBMITTED',%s,%s,%s,%s,%s,%s,1,"
            "%s,%s,%s,'WORKFLOW_INTEGRITY',%s,NULL,%s,%s,%s,%s)",
            (
                report_id,
                case_id,
                organization_id,
                demand_id,
                demand_version_id,
                b"d" * 32,
                reporter_user_id,
                created_at + timedelta(days=30),
                reporter_user_id,
                _uuid(seed + 600),
                _uuid(seed + 700),
                b"a" * 32,
                b"p" * 32,
                b"t" * 32,
                created_at - timedelta(minutes=5),
                ["WORKFLOW_INTEGRITY_RISK"],
                [_uuid(seed + 800)],
                ["PAUSE_SUBMISSION"],
                created_at,
            ),
        )
        connection.execute(
            "INSERT INTO trust.cases("
            "case_id,report_id,organization_id,demand_id,demand_version_id,"
            "reporter_user_id,status,aggregate_version,"
            "assigned_officer_user_id,assignment_id,assignment_expires_at,"
            "current_triage_draft_version,current_triage_version,"
            "outcome_version_id,opened_at,updated_at) "
            "VALUES(%s,%s,%s,%s,%s,%s,%s,%s,NULL,NULL,NULL,NULL,NULL,%s,%s,%s)",
            (
                case_id,
                report_id,
                organization_id,
                demand_id,
                demand_version_id,
                reporter_user_id,
                "DECIDED" if decided else "OPEN",
                2 if decided else 1,
                outcome_id,
                created_at,
                decided_at if decided else created_at,
            ),
        )
        if decided:
            connection.execute(
                "INSERT INTO trust.case_assignments("
                "assignment_id,organization_id,case_id,"
                "assignment_purpose_code,hold_id,officer_user_id,"
                "excluded_officer_user_id,duty_grant_id,duty_grant_version,"
                "authority_marker_sha256,conflict_attestation_sha256,"
                "conflict_evaluated_at,conflict_valid_until,assigned_at,expires_at) "
                "VALUES(%s,%s,%s,'CASE_TRIAGE',NULL,%s,NULL,%s,1,%s,%s,%s,%s,%s,%s)",
                (
                    assignment_id,
                    organization_id,
                    case_id,
                    ACTOR_OFFICER_ONE,
                    _uuid(seed + 900),
                    b"m" * 32,
                    b"c" * 32,
                    created_at,
                    created_at + timedelta(days=1),
                    created_at + timedelta(minutes=1),
                    created_at + timedelta(hours=12),
                ),
            )
            connection.execute(
                "INSERT INTO trust.case_outcome_versions("
                "outcome_version_id,organization_id,case_id,outcome_version,"
                "outcome_code,reason_codes,action_codes,"
                "evidence_packet_version_id,evidence_packet_digest,source_digest,"
                "redaction_profile_code,appeal_eligible,"
                "appeal_eligibility_code,appeal_deadline,policy_version,"
                "decided_by_user_id,decision_assignment_id,decided_at,"
                "content_sha256) "
                "VALUES(%s,%s,%s,1,'NO_ACTION',%s,%s,%s,%s,%s,"
                "'PARTY_SAFE_V1',true,'ELIGIBLE',%s,"
                "'trust-case-outcome-v1',%s,%s,%s,%s)",
                (
                    outcome_id,
                    organization_id,
                    case_id,
                    ["NO_POLICY_BREACH"],
                    [],
                    _uuid(seed + 1000),
                    b"e" * 32,
                    b"s" * 32,
                    decided_at + timedelta(days=7),
                    ACTOR_OFFICER_ONE,
                    assignment_id,
                    decided_at,
                    b"h" * 32,
                ),
            )
        return report_id, outcome_id

    def test_claim_receipt_status_surface_has_closed_acl(self) -> None:
        reader = (
            "trust_api.read_completed_command_receipt_v1("
            "uuid,uuid,uuid,text,uuid,bigint,text[],bytea[],text[],bytea[])"
        )
        normalizer = "trust.normalize_claim_receipt_http_status_v2()"
        with self._admin() as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT "
                    "has_function_privilege('trust_self',%s,'EXECUTE'),"
                    "has_function_privilege('trust_officer',%s,'EXECUTE'),"
                    "has_function_privilege('trust_appeal',%s,'EXECUTE'),"
                    "has_function_privilege('trust_decision',%s,'EXECUTE'),"
                    "has_function_privilege('trust_self',%s,'EXECUTE'),"
                    "has_function_privilege('trust_officer',%s,'EXECUTE'),"
                    "has_function_privilege('trust_decision',%s,'EXECUTE')",
                    (
                        reader,
                        reader,
                        reader,
                        reader,
                        normalizer,
                        normalizer,
                        normalizer,
                    ),
                ).fetchone(),
                (True, True, False, False, False, False, False),
            )

    def test_trust0004_reader_upgrade_has_only_two_reviewed_body_differences(
        self,
    ) -> None:
        migration = TRUST_MIGRATIONS[1].read_text(encoding="utf-8")

        def literal(tag: str) -> str:
            marker = f"${tag}$"
            start = migration.index(marker) + len(marker)
            return migration[start : migration.index(marker, start)]

        old_case = literal("reader_old_status_case")
        new_case = literal("reader_new_status_case")
        old_guard = literal("reader_old_status_guard")
        new_guard = literal("reader_new_status_guard")
        self.assertEqual(self.reader_before_0004.count(old_case), 1)
        self.assertEqual(self.reader_before_0004.count(old_guard), 1)
        self.assertEqual(
            self.reader_after_0004,
            self.reader_before_0004.replace(old_case, new_case).replace(
                old_guard,
                new_guard,
            ),
        )
        self.assertEqual(
            hashlib.sha256(self.reader_before_0004.encode("utf-8")).hexdigest(),
            "46dd40efb9b41922a4febf4a089364de82704c56899781c537f95f918c225264",
        )

    def test_trust0004_rejects_unreviewed_full_reader_drift(self) -> None:
        migration = TRUST_MIGRATIONS[1].read_text(encoding="utf-8")
        replacement_start = migration.index("DO $replace_reader$")
        replacement_end = migration.index(
            "\n$replace_reader$;",
            replacement_start,
        ) + len("\n$replace_reader$;")
        replacement = migration[replacement_start:replacement_end]
        drifted = self.reader_before_0004.replace(
            "DECLARE\n",
            "DECLARE\n    -- unreviewed-drift-marker\n",
            1,
        )
        self.assertNotEqual(drifted, self.reader_before_0004)
        with psycopg.connect(
            self.postgres.conninfo(
                database=self.database,
                user="trust_migration_runner",
            ),
            autocommit=False,
        ) as connection:
            connection.execute("SET ROLE trust_schema_owner")
            connection.execute(drifted)
            with self.assertRaises(
                psycopg.errors.ObjectNotInPrerequisiteState
            ) as error:
                connection.execute(replacement)
            self.assertEqual(
                error.exception.diag.message_primary,
                "TRUST_RECEIPT_READER_BASELINE_MISMATCH",
            )
            connection.rollback()

    def test_trust0004_rejects_unreviewed_reader_acl_drift(self) -> None:
        migration = TRUST_MIGRATIONS[1].read_text(encoding="utf-8")
        reader = (
            "trust_api.read_completed_command_receipt_v1("
            "uuid,uuid,uuid,text,uuid,bigint,text[],bytea[],text[],bytea[])"
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
                "GRANT EXECUTE ON FUNCTION " + reader + " TO trust_appeal"
            )
            with self.assertRaises(
                psycopg.errors.ObjectNotInPrerequisiteState
            ) as error:
                connection.execute(migration)
            self.assertEqual(
                error.exception.diag.message_primary,
                "TRUST_RECEIPT_READER_ACL_BASELINE_MISMATCH",
            )
            connection.rollback()

    def test_trust0004_rejects_superuser_forged_duplicate_acl_item(self) -> None:
        migration = TRUST_MIGRATIONS[1].read_text(encoding="utf-8")
        reader = (
            "trust_api.read_completed_command_receipt_v1("
            "uuid,uuid,uuid,text,uuid,bigint,text[],bytea[],text[],bytea[])"
        )
        with psycopg.connect(
            self.postgres.admin_conninfo(database=self.database),
            autocommit=False,
        ) as connection:
            connection.execute(
                "UPDATE pg_proc SET proacl=array_append(proacl,proacl[1]) "
                "WHERE oid=%s::regprocedure",
                (reader,),
            )
            connection.execute(
                "SET SESSION AUTHORIZATION trust_migration_runner"
            )
            connection.execute("SET ROLE trust_schema_owner")
            with self.assertRaises(
                psycopg.errors.ObjectNotInPrerequisiteState
            ) as error:
                connection.execute(migration)
            self.assertEqual(
                error.exception.diag.message_primary,
                "TRUST_RECEIPT_READER_ACL_BASELINE_MISMATCH",
            )
            connection.rollback()

    def test_fixed_programs_replay_rollback_occ_and_independent_release(self) -> None:
        report_id, case_id = _uuid(20), _uuid(21)
        hold_id = _uuid(22)
        first_assignment = _uuid(23)
        second_assignment = _uuid(24)
        release_assignment = _uuid(25)
        outcome_id = _uuid(26)
        evidence_packet_id = _uuid(27)
        now = datetime.now(timezone.utc)

        submit_receipt, _, submit_audit_id, _ = self._receipt(30)
        submit_args = [
            ACTOR_REPORTER,
            SESSION_REPORTER,
            ORGANIZATION,
            *self._context(400),
            *submit_receipt[:3],
            report_id,
            case_id,
            *submit_receipt[3:],
            DEMAND,
            DEMAND_VERSION,
            "WORKFLOW_INTEGRITY",
            now - timedelta(minutes=5),
            None,
            ["WORKFLOW_INTEGRITY_RISK"],
            [_uuid(28)],
            ["PAUSE_SUBMISSION"],
        ]
        with self._runtime("trust_self") as connection:
            first = _call(connection, "submit_report_v1", submit_args)
            self.assertFalse(first[1])
            self.assertEqual(first[0]["case_status"], "OPEN")
            replay_args = submit_args.copy()
            replay_args[1] = SESSION_REPORTER_ROTATED
            replay_args[6:11] = [
                _uuid(901),
                _uuid(902),
                _uuid(903),
                _uuid(904),
                _uuid(905),
            ]
            replay = _call(connection, "submit_report_v1", replay_args)
            self.assertTrue(replay[1])
            self.assertEqual(replay[0], first[0])
            reused = replay_args.copy()
            reused[14] = [bytes.fromhex("fe" * 32)]
            with self.assertRaises(psycopg.errors.UniqueViolation) as error:
                _call(connection, "submit_report_v1", reused)
            self.assertEqual(str(error.exception.diag.message_primary),
                             "IDEMPOTENCY_KEY_REUSED")
            connection.execute("SET app.test_authority_disabled='on'")
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                _call(connection, "submit_report_v1", replay_args)

        failed_claim_receipt, failed_receipt_id, _, _ = self._receipt(40)
        failed_claim_args = [
            ACTOR_OFFICER_ONE,
            SESSION_OFFICER_ONE,
            *self._context(410),
            failed_receipt_id,
            submit_audit_id,
            failed_claim_receipt[2],
            first_assignment,
            *failed_claim_receipt[3:],
            case_id,
            1,
        ]
        with self._runtime("trust_officer") as connection:
            with self.assertRaises(psycopg.errors.UniqueViolation):
                _call(connection, "claim_case_v1", failed_claim_args)
        with self._admin() as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT status,aggregate_version FROM trust.cases "
                    "WHERE case_id=%s",
                    (case_id,),
                ).fetchone(),
                ("OPEN", 1),
            )
            self.assertEqual(
                connection.execute(
                    "SELECT count(*) FROM trust.command_receipts "
                    "WHERE receipt_id=%s",
                    (failed_receipt_id,),
                ).fetchone()[0],
                0,
            )

        claim_receipt, *_ = self._receipt(41)
        claim_args = [
            ACTOR_OFFICER_ONE,
            SESSION_OFFICER_ONE,
            *self._context(420),
            *claim_receipt[:3],
            first_assignment,
            *claim_receipt[3:],
            case_id,
            1,
        ]
        with self._runtime("trust_officer") as connection:
            claimed = _call(connection, "claim_case_v1", claim_args)
            self.assertEqual(claimed[0]["aggregate_version"], 2)
            claim_probe_args = [
                ACTOR_OFFICER_ONE,
                SESSION_OFFICER_ONE_ROTATED,
                None,
                "CLAIM_CASE",
                case_id,
                1,
                *claim_receipt[3:],
            ]
            self.assertEqual(
                connection.execute(
                    "SELECT safe_response,replayed FROM "
                    "trust_api.read_completed_command_receipt_v1("
                    + ",".join(["%s"] * len(claim_probe_args))
                    + ")",
                    claim_probe_args,
                ).fetchone(),
                (claimed[0], True),
            )
            stale_receipt, *_ = self._receipt(42)
            stale_args = claim_args.copy()
            stale_args[5:8] = stale_receipt[:3]
            stale_args[9:13] = stale_receipt[3:]
            stale_args[-1] = 1
            with self.assertRaises(psycopg.errors.SerializationFailure) as error:
                _call(connection, "claim_case_v1", stale_args)
            self.assertEqual(str(error.exception.diag.message_primary),
                             "PRECONDITION_FAILED")

        with self._admin() as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT response_http_status FROM trust.command_receipts "
                    "WHERE receipt_id=%s",
                    (claim_receipt[0],),
                ).fetchone(),
                (201,),
            )
            legacy_idempotency, legacy_payload = _digests(60)
            _insert_completed_claim_receipt(
                connection,
                receipt_id=_uuid(160),
                actor_id=ACTOR_OFFICER_ONE,
                case_id=case_id,
                safe_response=claimed[0],
                idempotency_digest=legacy_idempotency[0],
                payload_hash=legacy_payload[0],
                response_http_status=200,
            )
            corrupt_idempotency, corrupt_payload = _digests(61)
            _insert_completed_claim_receipt(
                connection,
                receipt_id=_uuid(161),
                actor_id=ACTOR_OFFICER_ONE,
                case_id=case_id,
                safe_response=claimed[0],
                idempotency_digest=corrupt_idempotency[0],
                payload_hash=corrupt_payload[0],
                response_http_status=202,
            )
        with self._runtime("trust_officer") as connection:
            legacy_probe = claim_probe_args.copy()
            legacy_probe[6:] = [
                IDEMPOTENCY_KEY_IDS,
                legacy_idempotency,
                PAYLOAD_KEY_IDS,
                legacy_payload,
            ]
            self.assertEqual(
                connection.execute(
                    "SELECT safe_response,replayed FROM "
                    "trust_api.read_completed_command_receipt_v1("
                    + ",".join(["%s"] * len(legacy_probe))
                    + ")",
                    legacy_probe,
                ).fetchone(),
                (claimed[0], True),
            )
            corrupt_probe = claim_probe_args.copy()
            corrupt_probe[6:] = [
                IDEMPOTENCY_KEY_IDS,
                corrupt_idempotency,
                PAYLOAD_KEY_IDS,
                corrupt_payload,
            ]
            with self.assertRaises(psycopg.errors.StatementCompletionUnknown):
                connection.execute(
                    "SELECT safe_response,replayed FROM "
                    "trust_api.read_completed_command_receipt_v1("
                    + ",".join(["%s"] * len(corrupt_probe))
                    + ")",
                    corrupt_probe,
                ).fetchone()

        release_receipt, *_ = self._receipt(43)
        release_args = [
            ACTOR_OFFICER_ONE,
            SESSION_OFFICER_ONE,
            *self._context(430),
            *release_receipt[:3],
            *release_receipt[3:],
            case_id,
            2,
            "WORKLOAD_RELEASE",
        ]
        with self._runtime("trust_officer") as connection:
            released = _call(
                connection, "release_case_assignment_v1", release_args
            )
            self.assertEqual(released[0]["aggregate_version"], 3)

        second_claim_receipt, *_ = self._receipt(44)
        second_claim_args = [
            ACTOR_OFFICER_ONE,
            SESSION_OFFICER_ONE,
            *self._context(440),
            *second_claim_receipt[:3],
            second_assignment,
            *second_claim_receipt[3:],
            case_id,
            3,
        ]
        with self._runtime("trust_officer") as connection:
            second_claim = _call(
                connection, "claim_case_v1", second_claim_args
            )
            self.assertEqual(second_claim[0]["aggregate_version"], 4)

        save_receipt, *_ = self._receipt(45)
        sealed_reference = "sealed://trust/case-note-0001"
        sealed_hidden_hmac = bytes.fromhex("c1" * 32)
        sealed_key_id = "trust-sealed-note-v1"
        sealed_nonce = bytes.fromhex("c2" * 12)
        sealed_ciphertext = bytes.fromhex("c3" * 64)
        sealed_aad = _sealed_aad(
            sealed_reference,
            case_id,
            ACTOR_OFFICER_ONE,
            sealed_hidden_hmac,
            sealed_key_id,
        )
        sealed_digest = _sealed_envelope(
            sealed_key_id,
            sealed_nonce,
            sealed_ciphertext,
            sealed_aad,
        )
        sealed_args = [
            ACTOR_OFFICER_ONE,
            SESSION_OFFICER_ONE,
            case_id,
            "TRIAGE_NOTE",
            [sealed_key_id],
            [sealed_reference],
            [sealed_hidden_hmac],
            sealed_digest,
            sealed_key_id,
            sealed_nonce,
            sealed_ciphertext,
            sealed_aad,
            save_receipt[3],
            save_receipt[4],
            "TRUST_CASE_NOTE",
            now + timedelta(days=365),
        ]
        with self._runtime("trust_officer") as connection:
            stored = connection.execute(
                "SELECT * FROM trust_api.store_restricted_text_blob_v1("
                + ",".join(["%s"] * len(sealed_args))
                + ")",
                sealed_args,
            ).fetchone()
            self.assertEqual(stored[0], sealed_reference)
            self.assertEqual(stored[1], sealed_digest)
            self.assertFalse(stored[4])
            reused_blob = connection.execute(
                "SELECT * FROM trust_api.store_restricted_text_blob_v1("
                + ",".join(["%s"] * len(sealed_args))
                + ")",
                sealed_args,
            ).fetchone()
            self.assertTrue(reused_blob[4])
            changed_blob_args = sealed_args.copy()
            changed_blob_args[6] = [bytes.fromhex("cf" * 32)]
            with self.assertRaises(psycopg.errors.UniqueViolation):
                connection.execute(
                    "SELECT * FROM trust_api.store_restricted_text_blob_v1("
                    + ",".join(["%s"] * len(changed_blob_args))
                    + ")",
                    changed_blob_args,
                ).fetchone()
        with self._admin() as connection:
            connection.execute(
                "UPDATE trust.sealed_text_key_policy SET "
                "active_encryption_key_id='trust-sealed-note-v2',"
                "retained_encryption_key_ids=ARRAY["
                "'trust-sealed-note-v2','trust-sealed-note-v1']::text[],"
                "updated_at=transaction_timestamp() WHERE singleton_key"
            )
        with self._runtime("trust_officer") as connection:
            with self.assertRaises(psycopg.errors.ObjectNotInPrerequisiteState):
                connection.execute(
                    "SELECT * FROM trust_api.store_restricted_text_blob_v1("
                    + ",".join(["%s"] * len(sealed_args))
                    + ")",
                    sealed_args,
                ).fetchone()
            rotated_reference = "sealed://trust/case-note-0002"
            rotated_key_id = "trust-sealed-note-v2"
            rotated_args = sealed_args.copy()
            rotated_args[4] = [rotated_key_id, sealed_key_id]
            rotated_args[5] = [rotated_reference, sealed_reference]
            rotated_hidden_hmac = bytes.fromhex("d1" * 32)
            rotated_args[6] = [rotated_hidden_hmac, sealed_hidden_hmac]
            rotated_args[8] = rotated_key_id
            rotated_args[9] = bytes.fromhex("d2" * 12)
            rotated_args[10] = bytes.fromhex("d3" * 64)
            rotated_args[11] = _sealed_aad(
                rotated_reference,
                case_id,
                ACTOR_OFFICER_ONE,
                rotated_hidden_hmac,
                rotated_key_id,
            )
            rotated_args[7] = _sealed_envelope(
                rotated_key_id,
                rotated_args[9],
                rotated_args[10],
                rotated_args[11],
            )
            retained_replay = connection.execute(
                "SELECT * FROM trust_api.store_restricted_text_blob_v1("
                + ",".join(["%s"] * len(rotated_args))
                + ")",
                rotated_args,
            ).fetchone()
            self.assertEqual(retained_replay[0], sealed_reference)
            self.assertEqual(retained_replay[1], sealed_digest)
            self.assertTrue(retained_replay[4])
            unknown_args = rotated_args.copy()
            unknown_args[4] = ["trust-sealed-note-unknown", *rotated_args[4]]
            unknown_args[5] = [
                "sealed://trust/case-note-unknown",
                *rotated_args[5],
            ]
            unknown_args[6] = [bytes.fromhex("ef" * 32), *rotated_args[6]]
            unknown_args[8] = "trust-sealed-note-unknown"
            with self.assertRaises(psycopg.errors.ObjectNotInPrerequisiteState):
                connection.execute(
                    "SELECT * FROM trust_api.store_restricted_text_blob_v1("
                    + ",".join(["%s"] * len(unknown_args))
                    + ")",
                    unknown_args,
                ).fetchone()
        with self._admin() as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT count(*) FROM trust.restricted_text_blobs "
                    "WHERE case_id=%s",
                    (case_id,),
                ).fetchone()[0],
                1,
            )
        save_args = [
            ACTOR_OFFICER_ONE,
            SESSION_OFFICER_ONE,
            *self._context(450),
            *save_receipt[:3],
            *save_receipt[3:],
            case_id,
            4,
            "P1",
            "PLATFORM_INTERNAL",
            "HIGH",
            ["WORKFLOW_INTEGRITY_GAP"],
            ["CHECK_DEMAND_VERSION"],
            ["SUBMIT_DEMAND"],
            120,
            sealed_reference,
            sealed_digest,
        ]
        with self._runtime("trust_officer") as connection:
            saved = _call(connection, "save_triage_draft_v1", save_args)
            self.assertEqual(saved[0]["triage_draft_version"], 1)
            probe_args = [
                ACTOR_OFFICER_ONE,
                SESSION_OFFICER_ONE,
                None,
                "SAVE_TRIAGE_DRAFT",
                case_id,
                4,
                *save_receipt[3:],
            ]
            probe = connection.execute(
                "SELECT safe_response,replayed "
                "FROM trust_api.read_completed_command_receipt_v1("
                + ",".join(["%s"] * len(probe_args))
                + ")",
                probe_args,
            ).fetchone()
            self.assertEqual(probe, (saved[0], True))
            changed_probe_args = probe_args.copy()
            changed_probe_args[-1] = [bytes.fromhex("ce" * 32)]
            with self.assertRaises(psycopg.errors.UniqueViolation) as error:
                connection.execute(
                    "SELECT safe_response,replayed "
                    "FROM trust_api.read_completed_command_receipt_v1("
                    + ",".join(["%s"] * len(changed_probe_args))
                    + ")",
                    changed_probe_args,
                ).fetchone()
            self.assertEqual(
                error.exception.diag.message_primary,
                "IDEMPOTENCY_KEY_REUSED",
            )
            fresh_probe_args = probe_args.copy()
            fresh_probe_args[7] = [bytes.fromhex("cd" * 32)]
            self.assertIsNone(
                connection.execute(
                    "SELECT safe_response,replayed "
                    "FROM trust_api.read_completed_command_receipt_v1("
                    + ",".join(["%s"] * len(fresh_probe_args))
                    + ")",
                    fresh_probe_args,
                ).fetchone()
            )

        publish_receipt, *_ = self._receipt(46)
        publish_args = [
            ACTOR_OFFICER_ONE,
            SESSION_OFFICER_ONE,
            *self._context(460),
            *publish_receipt[:3],
            *publish_receipt[3:],
            case_id,
            5,
            1,
        ]
        with self._runtime("trust_officer") as connection:
            published = _call(connection, "publish_triage_v1", publish_args)
            self.assertEqual(published[0]["aggregate_version"], 6)

        hold_receipt, *_ = self._receipt(47)
        hold_args = [
            ACTOR_OFFICER_ONE,
            SESSION_OFFICER_ONE,
            *self._context(470),
            *hold_receipt[:3],
            hold_id,
            *hold_receipt[3:],
            case_id,
            6,
            ["SUBMIT_DEMAND"],
            "PARTICIPANT_SAFETY_RISK",
            60,
        ]
        with self._runtime("trust_officer") as connection:
            placed = _call(connection, "place_hold_v1", hold_args)
            self.assertEqual(placed[0]["hold_version"], 1)

        hold_claim_receipt, *_ = self._receipt(48)
        hold_claim_args = [
            ACTOR_OFFICER_TWO,
            SESSION_OFFICER_TWO,
            *self._context(480),
            *hold_claim_receipt[:3],
            release_assignment,
            *hold_claim_receipt[3:],
            hold_id,
            1,
        ]
        with self._runtime("trust_officer") as connection:
            hold_claimed = _call(
                connection, "claim_hold_release_v1", hold_claim_args
            )
            self.assertEqual(hold_claimed[0]["hold_version"], 2)
            hold_claim_probe = [
                ACTOR_OFFICER_TWO,
                SESSION_OFFICER_TWO_ROTATED,
                None,
                "CLAIM_HOLD_RELEASE",
                hold_id,
                1,
                *hold_claim_receipt[3:],
            ]
            self.assertEqual(
                connection.execute(
                    "SELECT safe_response,replayed FROM "
                    "trust_api.read_completed_command_receipt_v1("
                    + ",".join(["%s"] * len(hold_claim_probe))
                    + ")",
                    hold_claim_probe,
                ).fetchone(),
                (hold_claimed[0], True),
            )
            independent_projection = connection.execute(
                "SELECT projection FROM trust_api.read_assigned_case_v1("
                "%s,%s,%s)",
                (ACTOR_OFFICER_TWO, SESSION_OFFICER_TWO, case_id),
            ).fetchone()
            self.assertIsNotNone(independent_projection)
            self.assertEqual(
                independent_projection[0]["case_id"],
                str(case_id),
            )
            self.assertEqual(
                independent_projection[0]["active_hold"]["hold_id"],
                str(hold_id),
            )
            self.assertIsNone(
                connection.execute(
                    "SELECT projection "
                    "FROM trust_api.read_assigned_case_v1(%s,%s,%s)",
                    (_uuid(90), _uuid(91), case_id),
                ).fetchone()
            )

        with self._admin() as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT response_http_status FROM trust.command_receipts "
                    "WHERE receipt_id=%s",
                    (hold_claim_receipt[0],),
                ).fetchone(),
                (201,),
            )

        with self._admin() as connection:
            assignment_window = connection.execute(
                "SELECT assigned_at,expires_at FROM trust.case_assignments "
                "WHERE assignment_id=%s",
                (release_assignment,),
            ).fetchone()
            connection.execute("SET session_replication_role=replica")
            connection.execute(
                "UPDATE trust.case_assignments SET expires_at=%s "
                "WHERE assignment_id=%s",
                (
                    assignment_window[0] + timedelta(microseconds=1),
                    release_assignment,
                ),
            )
            connection.execute("SET session_replication_role=origin")
        with self._runtime("trust_officer") as connection:
            self.assertIsNone(
                connection.execute(
                    "SELECT projection "
                    "FROM trust_api.read_assigned_case_v1(%s,%s,%s)",
                    (ACTOR_OFFICER_TWO, SESSION_OFFICER_TWO, case_id),
                ).fetchone()
            )
        with self._admin() as connection:
            connection.execute("SET session_replication_role=replica")
            connection.execute(
                "UPDATE trust.case_assignments SET expires_at=%s "
                "WHERE assignment_id=%s",
                (assignment_window[1], release_assignment),
            )
            connection.execute("SET session_replication_role=origin")

        wrong_release_receipt, *_ = self._receipt(49)
        wrong_release_args = [
            ACTOR_OFFICER_ONE,
            SESSION_OFFICER_ONE,
            *self._context(490),
            *wrong_release_receipt[:3],
            *wrong_release_receipt[3:],
            hold_id,
            2,
            "RISK_MITIGATED",
        ]
        with self._runtime("trust_officer") as connection:
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                _call(connection, "release_hold_v1", wrong_release_args)

        hold_release_receipt, *_ = self._receipt(50)
        hold_release_args = [
            ACTOR_OFFICER_TWO,
            SESSION_OFFICER_TWO,
            *self._context(500),
            *hold_release_receipt[:3],
            *hold_release_receipt[3:],
            hold_id,
            2,
            "RISK_MITIGATED",
        ]
        with self._runtime("trust_officer") as connection:
            hold_released = _call(
                connection, "release_hold_v1", hold_release_args
            )
            self.assertEqual(hold_released[0]["hold_version"], 3)
            self.assertEqual(hold_released[0]["aggregate_version"], 8)
            replay_args = hold_release_args.copy()
            replay_args[2:8] = [
                _uuid(911),
                _uuid(912),
                _uuid(913),
                _uuid(914),
                _uuid(915),
                _uuid(916),
            ]
            replay_args[1] = SESSION_OFFICER_TWO_ROTATED
            replayed_release = _call(
                connection, "release_hold_v1", replay_args
            )
            self.assertTrue(replayed_release[1])
            self.assertEqual(replayed_release[0], hold_released[0])
            connection.execute("SET app.test_authority_disabled='on'")
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                _call(connection, "release_hold_v1", replay_args)

        with self._admin() as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT count(*) FROM trust.case_assignment_releases "
                    "WHERE assignment_id=%s "
                    "AND reason_code='HOLD_RELEASE_COMPLETED'",
                    (release_assignment,),
                ).fetchone()[0],
                1,
            )
            self.assertEqual(
                connection.execute(
                    "SELECT status,aggregate_version,release_assignment_id "
                    "FROM trust.safety_holds WHERE hold_id=%s",
                    (hold_id,),
                ).fetchone(),
                ("RELEASED", 3, release_assignment),
            )
            self.assertEqual(
                connection.execute(
                    "SELECT count(*) FROM trust.command_receipts "
                    "WHERE command_name='RELEASE_HOLD'",
                ).fetchone()[0],
                1,
            )
            self.assertEqual(
                connection.execute(
                    "SELECT count(*) FROM infra.outbox_events "
                    "WHERE event_type='SafetyHoldReleased'",
                ).fetchone()[0],
                1,
            )

        with self._runtime("trust_officer") as connection:
            self.assertIsNone(
                connection.execute(
                    "SELECT projection "
                    "FROM trust_api.read_assigned_case_v1(%s,%s,%s)",
                    (
                        ACTOR_OFFICER_TWO,
                        SESSION_OFFICER_TWO_ROTATED,
                        case_id,
                    ),
                ).fetchone()
            )

        with self._runtime("trust_officer") as connection:
            source_document, evidence_evaluated_at, evidence_valid_until = (
                connection.execute(
                    "SELECT * FROM "
                    "trust_api.read_outcome_evidence_source_v1("
                    "%s,%s,%s,%s,%s,%s,%s)",
                    (
                        ACTOR_OFFICER_ONE,
                        SESSION_OFFICER_ONE,
                        case_id,
                        8,
                        "NO_ACTION",
                        ["NO_POLICY_BREACH"],
                        [],
                    ),
                ).fetchone()
            )
        source_digest = _outcome_source_digest(source_document)
        appeal_deadline = evidence_evaluated_at + timedelta(days=7)
        packet_digest = _outcome_packet_digest(
            evidence_packet_id,
            source_digest,
            "NO_ACTION",
            ["NO_POLICY_BREACH"],
            [],
            appeal_deadline,
            evidence_evaluated_at,
            evidence_valid_until,
        )
        outcome_receipt, *_ = self._receipt(51)
        outcome_args = [
            ACTOR_OFFICER_ONE,
            SESSION_OFFICER_ONE,
            *self._context(510),
            *outcome_receipt[:3],
            outcome_id,
            *outcome_receipt[3:],
            case_id,
            8,
            "NO_ACTION",
            ["NO_POLICY_BREACH"],
            [],
            case_id,
            8,
            1,
            "NO_ACTION",
            ["NO_POLICY_BREACH"],
            [],
            evidence_packet_id,
            packet_digest,
            source_digest,
            True,
            "ELIGIBLE",
            appeal_deadline,
            "trust-case-outcome-v1",
            "PARTY_SAFE_V1",
            evidence_evaluated_at,
            evidence_valid_until,
        ]
        with self._runtime("trust_officer") as connection:
            tampered = outcome_args.copy()
            tampered[25] = bytes.fromhex("d1" * 32)
            with self.assertRaises(psycopg.errors.ObjectNotInPrerequisiteState):
                _call(connection, "publish_outcome_v1", tampered)
            outcome = _call(connection, "publish_outcome_v1", outcome_args)
            self.assertEqual(outcome[0]["case_status"], "DECIDED")
            self.assertEqual(outcome[0]["aggregate_version"], 9)

        with self._runtime("trust_self") as connection:
            owner_projection = connection.execute(
                "SELECT projection FROM trust_api.read_own_report_v1("
                "%s,%s,%s,%s)",
                (
                    ACTOR_REPORTER,
                    SESSION_REPORTER_ROTATED,
                    ORGANIZATION,
                    report_id,
                ),
            ).fetchone()[0]
            self.assertEqual(
                owner_projection["outcome"]["outcome_version_id"],
                str(outcome_id),
            )
            self.assertEqual(
                owner_projection["outcome"]["appeal_eligibility_code"],
                "ELIGIBLE",
            )
            self.assertNotIn("decided_by_user_id", owner_projection["outcome"])

        with self._runtime("trust_self") as connection:
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                _call(connection, "claim_case_v1", claim_args)

        with self._admin() as connection:
            connection.execute(
                "UPDATE trust.receipt_key_policy SET "
                "active_idempotency_key_id='trust-idempotency-2026-02',"
                "active_payload_key_id='trust-payload-2026-02',"
                "retained_idempotency_key_ids=ARRAY["
                "'trust-idempotency-2026-02',"
                "'trust-idempotency-2026-01']::text[],"
                "retained_payload_key_ids=ARRAY["
                "'trust-payload-2026-02',"
                "'trust-payload-2026-01']::text[],"
                "updated_at=transaction_timestamp() WHERE singleton_key"
            )
        rotated_submit_args = submit_args.copy()
        rotated_submit_args[1] = SESSION_REPORTER_ROTATED
        rotated_submit_args[6:11] = [
            _uuid(921),
            _uuid(922),
            _uuid(923),
            _uuid(924),
            _uuid(925),
        ]
        rotated_submit_args[11] = [
            "trust-idempotency-2026-02",
            "trust-idempotency-2026-01",
        ]
        rotated_submit_args[12] = [bytes.fromhex("a8" * 32), bytes([30]) * 32]
        rotated_submit_args[13] = [
            "trust-payload-2026-02",
            "trust-payload-2026-01",
        ]
        rotated_submit_args[14] = [bytes.fromhex("a9" * 32), bytes([31]) * 32]
        with self._runtime("trust_self") as connection:
            late_replay = _call(
                connection,
                "submit_report_v1",
                rotated_submit_args,
            )
            self.assertTrue(late_replay[1])
            self.assertEqual(late_replay[0], first[0])

        with self._admin() as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT status,aggregate_version,outcome_version_id "
                    "FROM trust.cases WHERE case_id=%s",
                    (case_id,),
                ).fetchone(),
                ("DECIDED", 9, outcome_id),
            )
            self.assertEqual(
                connection.execute(
                    "SELECT count(*),count(DISTINCT event_type) "
                    "FROM infra.outbox_events WHERE aggregate_id=%s",
                    (case_id,),
                ).fetchone(),
                (10, 9),
            )
            forbidden = connection.execute(
                "SELECT count(*) FROM infra.outbox_events "
                "WHERE payload ?| ARRAY["
                "'reporter_user_id','demand_owner_user_id','session_id',"
                "'sealed_note_reference','sealed_note_sha256']::text[]"
            ).fetchone()[0]
            self.assertEqual(forbidden, 0)
            sealed_row = connection.execute(
                "SELECT encryption_nonce,ciphertext,aad_sha256,count(*) "
                "FROM trust.restricted_text_blobs "
                "WHERE sealed_note_reference=%s "
                "GROUP BY encryption_nonce,ciphertext,aad_sha256",
                (sealed_reference,),
            ).fetchone()
            self.assertEqual(len(sealed_row[0]), 12)
            self.assertEqual(sealed_row[1], sealed_ciphertext)
            self.assertNotEqual(sealed_row[1], b"restricted triage note")
            self.assertEqual(sealed_row[2], sealed_aad)
            self.assertEqual(sealed_row[3], 1)

    def test_owned_report_discovery_is_authorized_minimal_and_keyset_stable(
        self,
    ) -> None:
        top_created_at = datetime(2030, 1, 4, tzinfo=timezone.utc)
        older_created_at = datetime(2030, 1, 3, tzinfo=timezone.utc)
        oldest_created_at = datetime(2030, 1, 2, tzinfo=timezone.utc)
        other_reporter = _uuid(2800)
        other_organization = _uuid(2801)

        with psycopg.connect(
            self.postgres.admin_conninfo(database=self.database),
            autocommit=False,
        ) as connection:
            first_report_id, first_outcome_id = self._insert_discovery_report(
                connection,
                seed=2000,
                reporter_user_id=ACTOR_REPORTER,
                organization_id=ORGANIZATION,
                created_at=top_created_at,
                decided=True,
            )
            second_report_id, _ = self._insert_discovery_report(
                connection,
                seed=2100,
                reporter_user_id=ACTOR_REPORTER,
                organization_id=ORGANIZATION,
                created_at=top_created_at,
                decided=False,
            )
            third_report_id, _ = self._insert_discovery_report(
                connection,
                seed=2200,
                reporter_user_id=ACTOR_REPORTER,
                organization_id=ORGANIZATION,
                created_at=older_created_at,
                decided=False,
            )
            fourth_report_id, _ = self._insert_discovery_report(
                connection,
                seed=2300,
                reporter_user_id=ACTOR_REPORTER,
                organization_id=ORGANIZATION,
                created_at=oldest_created_at,
                decided=False,
            )
            other_reporter_id, _ = self._insert_discovery_report(
                connection,
                seed=2400,
                reporter_user_id=other_reporter,
                organization_id=ORGANIZATION,
                created_at=datetime(2032, 1, 1, tzinfo=timezone.utc),
                decided=False,
            )
            self._insert_discovery_report(
                connection,
                seed=2500,
                reporter_user_id=ACTOR_REPORTER,
                organization_id=other_organization,
                created_at=datetime(2032, 1, 2, tzinfo=timezone.utc),
                decided=False,
            )
            connection.commit()

        statement = (
            "SELECT projection,next_created_at,next_report_id "
            "FROM trust_api.list_own_reports_v1(%s,%s,%s,%s,%s,%s)"
        )
        with self._runtime("trust_self") as connection:
            page_one = connection.execute(
                statement,
                (
                    ACTOR_REPORTER,
                    SESSION_REPORTER,
                    ORGANIZATION,
                    2,
                    None,
                    None,
                ),
            ).fetchone()

        self.assertIsNotNone(page_one)
        page_one_projection, next_created_at, next_report_id = page_one
        self.assertEqual(
            [item["report_id"] for item in page_one_projection["items"]],
            [str(first_report_id), str(second_report_id)],
        )
        self.assertEqual(next_created_at, top_created_at)
        self.assertEqual(next_report_id, second_report_id)
        self.assertEqual(
            set(page_one_projection),
            {"entity_tag", "items"},
        )
        for item in page_one_projection["items"]:
            self.assertEqual(
                set(item),
                {
                    "category",
                    "demand_id",
                    "outcome",
                    "report_id",
                    "status",
                    "submitted_at",
                },
            )
        outcome = page_one_projection["items"][0]["outcome"]
        self.assertEqual(
            set(outcome),
            {
                "appeal_deadline",
                "appeal_eligibility_code",
                "decided_at",
                "outcome_code",
                "outcome_version_id",
            },
        )
        self.assertEqual(outcome["outcome_version_id"], str(first_outcome_id))
        self.assertIsNone(page_one_projection["items"][1]["outcome"])

        with psycopg.connect(
            self.postgres.admin_conninfo(database=self.database),
            autocommit=False,
        ) as connection:
            inserted_report_id, _ = self._insert_discovery_report(
                connection,
                seed=2600,
                reporter_user_id=ACTOR_REPORTER,
                organization_id=ORGANIZATION,
                created_at=datetime(2031, 1, 1, tzinfo=timezone.utc),
                decided=False,
            )
            connection.commit()

        page_two_arguments = (
            ACTOR_REPORTER,
            SESSION_REPORTER_ROTATED,
            ORGANIZATION,
            2,
            next_created_at,
            next_report_id,
        )
        with self._runtime("trust_self") as connection:
            page_two = connection.execute(
                statement,
                page_two_arguments,
            ).fetchone()
            page_two_replay = connection.execute(
                statement,
                page_two_arguments,
            ).fetchone()
            refreshed_page_one = connection.execute(
                statement,
                (
                    ACTOR_REPORTER,
                    SESSION_REPORTER,
                    ORGANIZATION,
                    2,
                    None,
                    None,
                ),
            ).fetchone()
            hidden_actor = connection.execute(
                statement,
                (
                    other_reporter,
                    SESSION_REPORTER,
                    ORGANIZATION,
                    2,
                    None,
                    None,
                ),
            ).fetchone()
            hidden_organization = connection.execute(
                statement,
                (
                    ACTOR_REPORTER,
                    SESSION_REPORTER,
                    other_organization,
                    2,
                    None,
                    None,
                ),
            ).fetchone()
            foreign_cursor = connection.execute(
                statement,
                (
                    ACTOR_REPORTER,
                    SESSION_REPORTER,
                    ORGANIZATION,
                    2,
                    datetime(2032, 1, 1, tzinfo=timezone.utc),
                    other_reporter_id,
                ),
            ).fetchone()

        self.assertEqual(page_two, page_two_replay)
        self.assertEqual(
            [item["report_id"] for item in page_two[0]["items"]],
            [str(third_report_id), str(fourth_report_id)],
        )
        self.assertNotIn(
            str(inserted_report_id),
            {item["report_id"] for item in page_two[0]["items"]},
        )
        self.assertEqual(
            refreshed_page_one[0]["items"][0]["report_id"],
            str(inserted_report_id),
        )
        self.assertIsNone(hidden_actor)
        self.assertIsNone(hidden_organization)
        self.assertIsNone(foreign_cursor)

        with self._admin() as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT relname,relrowsecurity,relforcerowsecurity "
                    "FROM pg_class WHERE oid IN ("
                    "'trust.reports'::regclass,'trust.cases'::regclass,"
                    "'trust.case_outcome_versions'::regclass) "
                    "ORDER BY relname"
                ).fetchall(),
                [
                    ("case_outcome_versions", True, True),
                    ("cases", True, True),
                    ("reports", True, True),
                ],
            )
            self.assertFalse(
                connection.execute(
                    "SELECT has_table_privilege("
                    "'trust_self','trust.reports','SELECT')"
                ).fetchone()[0]
            )
            self.assertEqual(
                connection.execute(
                    "SELECT "
                    "has_function_privilege('trust_self',"
                    "'trust_api.list_own_reports_v1(uuid,uuid,uuid,integer,"
                    "timestamptz,uuid)','EXECUTE'),"
                    "has_function_privilege('trust_officer',"
                    "'trust_api.list_own_reports_v1(uuid,uuid,uuid,integer,"
                    "timestamptz,uuid)','EXECUTE')"
                ).fetchone(),
                (True, False),
            )

        with self._runtime("trust_self") as connection:
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                connection.execute("SELECT report_id FROM trust.reports")


if __name__ == "__main__":
    unittest.main()
