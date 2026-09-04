"""Real PostgreSQL 18 evidence for the synthetic Finance funding workbench.

The test deliberately seeds two independent platform-only Finance Operators.
It exercises the production PostgreSQL service seam and proves that two
assignment-bound confirmations, not a representation of real money, are what
advance one verified Demand to ``FUNDED``.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
from threading import Barrier
import unittest
from uuid import UUID

import psycopg

from desire_platform.demand.adapters.postgres import DemandPostgresOperation
from desire_platform.demand.adapters.postgres.migrations import (
    DEMAND_REQUIRED_IAM_SCHEMA_VERSION,
    DEMAND_SCHEMA_HEAD_VERSION,
    DemandContractSources,
    DemandMigrationCatalog,
    DemandMigrationRunner,
    DemandMigrationRunnerError,
    DemandMigrationSettings,
    PsycopgDemandMigrationDriver,
)
from desire_platform.identity_access.adapters.postgres.editor_principal import (
    EditorPrincipalResolutionRequest,
    PsycopgEditorPrincipalResolver,
)
from desire_platform.identity_access.adapters.postgres.migrations import (
    IamContractSources,
    IamMigrationRunner,
    MigrationCatalog,
    PsycopgMigrationDriver,
    PsycopgMigrationSettings,
)
from desire_platform.internal_pilot.editor import (
    EditorPrincipal,
    EditorServiceError,
)
from desire_platform.internal_pilot.finance_funding import (
    FINANCE_FUNDING_ATTESTATION_CODES,
    FINANCE_FUNDING_EVIDENCE_KIND,
    FINANCE_FUNDING_LEGAL_EFFECT,
    FinanceFundingKeys,
    PsycopgFinanceFundingService,
)
from tests.storage.postgres.postgres18_harness import TemporaryPostgres18
from tests.support.demand_postgres_builders import (
    ACTOR_USER_ID,
    DEMAND_ID,
    DEMAND_VERSION_ID,
    ORGANIZATION_ID,
    SESSION_ID as DEMAND_OWNER_SESSION_ID,
    TrackingDemandConnectionSource,
    owner_authority_marker,
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

FINANCE_USER_IDS = (
    UUID("f621329e-0c6c-5a7b-aeb5-b561b7621b73"),
    UUID("b9e9d8b1-132f-548e-8a25-af90d7db85eb"),
)
FINANCE_SESSION_IDS = (
    UUID("f1000001-0000-4000-8000-000000000001"),
    UUID("f1000002-0000-4000-8000-000000000001"),
)
FINANCE_FAMILY_IDS = (
    UUID("f2000001-0000-4000-8000-000000000001"),
    UUID("f2000002-0000-4000-8000-000000000001"),
)
FINANCE_AUTH_TRANSACTION_IDS = (
    UUID("f3000001-0000-4000-8000-000000000001"),
    UUID("f3000002-0000-4000-8000-000000000001"),
)
FINANCE_DUTY_GRANT_IDS = (
    UUID("f4000001-0000-4000-8000-000000000001"),
    UUID("f4000002-0000-4000-8000-000000000001"),
)


def _digest(label: str) -> bytes:
    return hashlib.sha256(label.encode("utf-8")).digest()


class _Connections:
    def __init__(self, conninfo: str) -> None:
        self._conninfo = conninfo

    def checkout(self):
        return psycopg.connect(self._conninfo, autocommit=True)

    @staticmethod
    def release(connection) -> None:
        connection.close()

    @staticmethod
    def discard(connection) -> None:
        connection.close()


def _seed_finance_operator(
    connection,
    *,
    ordinal: int,
    now: datetime,
) -> None:
    """Seed one active session and exactly one FINANCE_OPERATOR duty."""

    user_id = FINANCE_USER_IDS[ordinal]
    session_id = FINANCE_SESSION_IDS[ordinal]
    family_id = FINANCE_FAMILY_IDS[ordinal]
    auth_transaction_id = FINANCE_AUTH_TRANSACTION_IDS[ordinal]
    duty_grant_id = FINANCE_DUTY_GRANT_IDS[ordinal]
    label = f"finance-operator-{ordinal + 1}"
    created_at = now - timedelta(days=2)
    auth_time = now - timedelta(hours=2)
    session_created_at = now - timedelta(hours=1)

    connection.execute(
        "INSERT INTO iam.users ("
        "id,status,display_handle,aggregate_version,created_at,updated_at) "
        "VALUES (%s,'ACTIVE',%s,1,%s,%s)",
        (user_id, f"sandbox_finance_operator_0{ordinal + 1}", created_at, created_at),
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
            auth_transaction_id,
            _digest(label + "-browser"),
            _digest(label + "-state"),
            _digest(label + "-nonce"),
            b"reviewed-finance-pg-pkce-" + bytes((ordinal,)),
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
        (family_id, user_id, session_created_at, session_created_at),
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
            session_id,
            user_id,
            family_id,
            _digest(label + "-session"),
            _digest(label + "-csrf-salt"),
            _digest(label + "-csrf"),
            auth_transaction_id,
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
        "%s,%s,'FINANCE_OPERATOR','SYSTEM',%s,%s,NULL,NULL,NULL,1,%s,%s)",
        (duty_grant_id, user_id, ACTOR_USER_ID, created_at, created_at, created_at),
    )


class RealPostgres18FinanceFundingTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.postgres = TemporaryPostgres18().start()
        cls.database = cls.postgres.create_database()
        try:
            cls._migrate()
            now = datetime.now(timezone.utc).replace(microsecond=0)
            with cls._admin(autocommit=False) as connection:
                seed_exact_demand_owner_iam_authority(connection, now=now)
                for ordinal in range(2):
                    _seed_finance_operator(connection, ordinal=ordinal, now=now)
            cls.principals = tuple(cls._principal(ordinal) for ordinal in range(2))
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
                DemandPostgresOperation.APPLY_FUNDING_SECURED,
            )

    def tearDown(self) -> None:
        for source in self.sources:
            source.close()

    def test_two_operator_replay_occ_and_four_eyes_fund_one_demand(self) -> None:
        operator_one, operator_two = self.principals
        self.assertEqual(
            tuple(
                (
                    principal.user_id,
                    principal.workspace_id,
                    principal.role_codes,
                    principal.organization_id,
                )
                for principal in self.principals
            ),
            tuple(
                (
                    str(user_id),
                    f"platform:{user_id}",
                    ("FINANCE_OPERATOR",),
                    None,
                )
                for user_id in FINANCE_USER_IDS
            ),
        )
        self.assertNotEqual(operator_one.session_id, operator_two.session_id)
        self.assertNotEqual(
            operator_one.principal_marker_sha256,
            operator_two.principal_marker_sha256,
        )
        service = self._service()
        service.check_readiness(timeout_ms=1_000)

        available = service.list_funding_reviews(principal=operator_one)
        self.assertEqual(len(available), 1)
        initial = available[0]
        self.assertEqual(
            (
                initial.demand_id,
                initial.demand_version_id,
                initial.demand_revision,
                initial.review_status,
                initial.funding_review_id,
                initial.confirmation_count,
                initial.assigned_to_me,
                initial.etag,
            ),
            (
                str(DEMAND_ID),
                str(DEMAND_VERSION_ID),
                1,
                "AVAILABLE",
                None,
                0,
                False,
                '"demand-1-finance-queue"',
            ),
        )

        first_claim = service.claim_funding_review(
            principal=operator_one,
            demand_id=str(DEMAND_ID),
            if_match=initial.etag,
            idempotency_key="finance-operator-01-claim-v1",
        )
        first_claim_replay = service.claim_funding_review(
            principal=operator_one,
            demand_id=str(DEMAND_ID),
            if_match=initial.etag,
            idempotency_key="finance-operator-01-claim-v1",
        )
        self.assertEqual(
            (
                first_claim.status,
                first_claim.revision,
                first_claim.confirmation_count,
                first_claim.can_confirm,
                first_claim.replayed,
                first_claim_replay.funding_review_id,
                first_claim_replay.assignment_id,
                first_claim_replay.replayed,
            ),
            (
                "PENDING",
                1,
                0,
                True,
                False,
                first_claim.funding_review_id,
                first_claim.assignment_id,
                True,
            ),
        )
        self.assertEqual(
            (
                len(first_claim.target_content_sha256),
                first_claim.planned_budget_currency,
                first_claim.planned_budget_minimum_amount_minor,
                first_claim.planned_budget_maximum_amount_minor,
                first_claim.planned_budget_direct_cost_amount_minor,
                first_claim.sandbox_funds_amount_minor,
                first_claim.provider_code,
                first_claim.payment_operation_code,
            ),
            (64, "CNY", 100_000, 200_000, 20_000, 0, "NONE", "NONE"),
        )
        with self._admin() as connection:
            immutable_version_evidence = connection.execute(
                "SELECT encode(content_sha256,'hex'),"
                "content#>>'{budget,currency}',"
                "(content#>>'{budget,minimum_amount_minor}')::bigint,"
                "(content#>>'{budget,maximum_amount_minor}')::bigint,"
                "(content#>>'{budget,direct_cost_amount_minor}')::bigint "
                "FROM demand.demand_versions WHERE id=%s",
                (UUID(first_claim.demand_version_id),),
            ).fetchone()
        self.assertEqual(
            immutable_version_evidence,
            (
                first_claim.target_content_sha256,
                first_claim.planned_budget_currency,
                first_claim.planned_budget_minimum_amount_minor,
                first_claim.planned_budget_maximum_amount_minor,
                first_claim.planned_budget_direct_cost_amount_minor,
            ),
        )

        with self.assertRaises(EditorServiceError) as stale_demand:
            service.claim_funding_review(
                principal=operator_two,
                demand_id=str(DEMAND_ID),
                if_match=initial.etag,
                idempotency_key="finance-operator-02-stale-demand-v1",
            )
        self.assertEqual(
            (stale_demand.exception.status, stale_demand.exception.code),
            (412, "PRECONDITION_FAILED"),
        )

        first_confirmation = service.confirm_funding_review(
            principal=operator_one,
            funding_review_id=first_claim.funding_review_id,
            if_match=first_claim.etag,
            attestation_codes=FINANCE_FUNDING_ATTESTATION_CODES,
            idempotency_key="finance-operator-01-confirm-v1",
        )
        first_confirmation_replay = service.confirm_funding_review(
            principal=operator_one,
            funding_review_id=first_claim.funding_review_id,
            if_match=first_claim.etag,
            attestation_codes=FINANCE_FUNDING_ATTESTATION_CODES,
            idempotency_key="finance-operator-01-confirm-v1",
        )
        self.assertEqual(
            (
                first_confirmation.status,
                first_confirmation.revision,
                first_confirmation.confirmation_count,
                first_confirmation.can_confirm,
                first_confirmation.replayed,
                first_confirmation_replay.replayed,
            ),
            ("PENDING", 2, 1, False, False, True),
        )

        second_queue = service.list_funding_reviews(principal=operator_two)
        self.assertEqual(len(second_queue), 1)
        pending = second_queue[0]
        self.assertEqual(
            (
                pending.funding_review_id,
                pending.review_status,
                pending.review_revision,
                pending.confirmation_count,
                pending.assigned_to_me,
                pending.etag,
            ),
            (
                first_claim.funding_review_id,
                "PENDING",
                2,
                1,
                False,
                '"funding-review-2"',
            ),
        )
        with self.assertRaises(EditorServiceError) as unassigned_detail:
            service.get_funding_review(
                principal=operator_two,
                funding_review_id=first_claim.funding_review_id,
            )
        self.assertEqual(
            (unassigned_detail.exception.status, unassigned_detail.exception.code),
            (404, "RESOURCE_NOT_FOUND"),
        )

        with self.assertRaises(EditorServiceError) as stale_review:
            service.claim_funding_review(
                principal=operator_two,
                demand_id=str(DEMAND_ID),
                if_match=first_claim.etag,
                idempotency_key="finance-operator-02-stale-review-v1",
            )
        self.assertEqual(
            (stale_review.exception.status, stale_review.exception.code),
            (412, "PRECONDITION_FAILED"),
        )

        second_claim = service.claim_funding_review(
            principal=operator_two,
            demand_id=str(DEMAND_ID),
            if_match=pending.etag,
            idempotency_key="finance-operator-02-claim-v1",
        )
        second_claim_replay = service.claim_funding_review(
            principal=operator_two,
            demand_id=str(DEMAND_ID),
            if_match=pending.etag,
            idempotency_key="finance-operator-02-claim-v1",
        )
        self.assertEqual(
            (
                second_claim.funding_review_id,
                second_claim.status,
                second_claim.revision,
                second_claim.confirmation_count,
                second_claim.can_confirm,
                second_claim.replayed,
                second_claim_replay.assignment_id,
                second_claim_replay.confirmation_count,
                second_claim_replay.replayed,
            ),
            (
                first_claim.funding_review_id,
                "PENDING",
                3,
                1,
                True,
                False,
                second_claim.assignment_id,
                1,
                True,
            ),
        )
        self.assertNotEqual(first_claim.assignment_id, second_claim.assignment_id)

        operator_one_detail = service.get_funding_review(
            principal=operator_one,
            funding_review_id=first_claim.funding_review_id,
        )
        operator_two_detail = service.get_funding_review(
            principal=operator_two,
            funding_review_id=first_claim.funding_review_id,
        )
        self.assertEqual(
            (
                operator_one_detail.can_confirm,
                operator_two_detail.can_confirm,
                operator_one_detail.confirmation_count,
                operator_two_detail.confirmation_count,
            ),
            (False, True, 1, 1),
        )

        funded = service.confirm_funding_review(
            principal=operator_two,
            funding_review_id=first_claim.funding_review_id,
            if_match=second_claim.etag,
            attestation_codes=FINANCE_FUNDING_ATTESTATION_CODES,
            idempotency_key="finance-operator-02-confirm-v1",
        )
        funded_replay = service.confirm_funding_review(
            principal=operator_two,
            funding_review_id=first_claim.funding_review_id,
            if_match=second_claim.etag,
            attestation_codes=FINANCE_FUNDING_ATTESTATION_CODES,
            idempotency_key="finance-operator-02-confirm-v1",
        )
        self.assertEqual(
            (
                funded.status,
                funded.revision,
                funded.confirmation_count,
                funded.can_confirm,
                funded.replayed,
                funded_replay.status,
                funded_replay.revision,
                funded_replay.replayed,
            ),
            ("SECURED", 4, 2, False, False, "SECURED", 4, True),
        )
        with self._admin() as connection:
            ledger_before_late_replay = connection.execute(
                "SELECT "
                "(SELECT count(*) FROM demand.manual_funding_receipts),"
                "(SELECT count(*) FROM demand.manual_funding_review_assignments),"
                "(SELECT count(*) FROM demand.manual_funding_confirmations),"
                "(SELECT count(*) FROM audit.audit_events),"
                "(SELECT count(*) FROM infra.outbox_events),"
                "(SELECT aggregate_version FROM demand.demands WHERE id=%s)",
                (DEMAND_ID,),
            ).fetchone()
        late_first_claim_replay = service.claim_funding_review(
            principal=operator_one,
            demand_id=str(DEMAND_ID),
            if_match=initial.etag,
            idempotency_key="finance-operator-01-claim-v1",
        )
        self.assertEqual(
            late_first_claim_replay,
            replace(first_claim, replayed=True),
        )
        with self._admin() as connection:
            ledger_after_late_replay = connection.execute(
                "SELECT "
                "(SELECT count(*) FROM demand.manual_funding_receipts),"
                "(SELECT count(*) FROM demand.manual_funding_review_assignments),"
                "(SELECT count(*) FROM demand.manual_funding_confirmations),"
                "(SELECT count(*) FROM audit.audit_events),"
                "(SELECT count(*) FROM infra.outbox_events),"
                "(SELECT aggregate_version FROM demand.demands WHERE id=%s)",
                (DEMAND_ID,),
            ).fetchone()
        self.assertEqual(ledger_after_late_replay, ledger_before_late_replay)
        self.assertEqual(service.list_funding_reviews(principal=operator_one), ())
        self.assertEqual(service.list_funding_reviews(principal=operator_two), ())

        with self._admin() as connection:
            root = connection.execute(
                "SELECT status,aggregate_version,current_funding_marker_id "
                "FROM demand.demands WHERE id=%s",
                (DEMAND_ID,),
            ).fetchone()
            ledger = connection.execute(
                "SELECT review.status,review.aggregate_version,"
                "review.evidence_kind,review.sandbox_funds_amount_minor,"
                "review.legal_effect,review.required_confirmations,"
                "marker.status,marker.funding_id=review.funding_id,"
                "marker.verification_reference_sha256="
                "review.evidence_reference_sha256 "
                "FROM demand.manual_funding_review_cases AS review "
                "JOIN demand.demand_funding_markers AS marker "
                "ON marker.id=(SELECT current_funding_marker_id "
                "FROM demand.demands WHERE id=review.demand_id) "
                "WHERE review.id=%s",
                (UUID(first_claim.funding_review_id),),
            ).fetchone()
            assignments = connection.execute(
                "SELECT count(*),count(DISTINCT actor_user_id),"
                "count(*) FILTER (WHERE status='COMPLETED'),"
                "bool_and(octet_length(authority_marker_sha256)=32) "
                "FROM demand.manual_funding_review_assignments "
                "WHERE funding_review_id=%s",
                (UUID(first_claim.funding_review_id),),
            ).fetchone()
            confirmations = connection.execute(
                "SELECT count(*),count(DISTINCT actor_user_id),"
                "bool_and(attestation_codes=%s),"
                "bool_and(confirmation.target_sha256=review.target_sha256),"
                "bool_and(confirmation.evidence_reference_sha256="
                "review.evidence_reference_sha256) "
                "FROM demand.manual_funding_confirmations AS confirmation "
                "JOIN demand.manual_funding_review_cases AS review "
                "ON review.id=confirmation.funding_review_id "
                "WHERE confirmation.funding_review_id=%s",
                (
                    list(FINANCE_FUNDING_ATTESTATION_CODES),
                    UUID(first_claim.funding_review_id),
                ),
            ).fetchone()
            receipts = dict(
                connection.execute(
                    "SELECT command_name,count(*) FROM demand.manual_funding_receipts "
                    "GROUP BY command_name"
                ).fetchall()
            )
            receipt_progress = dict(
                connection.execute(
                    "SELECT result_event_type,"
                    "(safe_response_body->>'confirmation_count')::integer "
                    "FROM demand.manual_funding_receipts"
                ).fetchall()
            )
            audit = dict(
                connection.execute(
                    "SELECT action_code,count(*) FROM audit.audit_events "
                    "GROUP BY action_code"
                ).fetchall()
            )
            outbox = dict(
                connection.execute(
                    "SELECT event_type,count(*) FROM infra.outbox_events "
                    "GROUP BY event_type"
                ).fetchall()
            )
            outbox_progress = dict(
                connection.execute(
                    "SELECT event_type,COALESCE("
                    "(payload->>'confirmation_count')::integer,-1) "
                    "FROM infra.outbox_events"
                ).fetchall()
            )

        self.assertEqual(root[:2], ("FUNDED", 5))
        self.assertIsNotNone(root[2])
        self.assertEqual(
            ledger,
            (
                "SECURED",
                4,
                FINANCE_FUNDING_EVIDENCE_KIND,
                0,
                FINANCE_FUNDING_LEGAL_EFFECT,
                2,
                "SECURED",
                True,
                True,
            ),
        )
        self.assertEqual(assignments, (2, 2, 2, True))
        self.assertEqual(confirmations, (2, 2, True, True, True))
        self.assertEqual(
            receipts,
            {"ClaimManualFundingReview": 2, "ConfirmManualFundingReview": 2},
        )
        self.assertEqual(
            receipt_progress,
            {
                "DemandFundingRequested": 0,
                "DemandFundingEvidenceConfirmed": 1,
                "DemandFundingReviewClaimed": 1,
                "DemandFunded": 2,
            },
        )
        self.assertEqual(
            audit,
            {
                "START_MANUAL_FUNDING_REVIEW": 1,
                "JOIN_MANUAL_FUNDING_REVIEW": 1,
                "CONFIRM_MANUAL_FUNDING_EVIDENCE": 2,
            },
        )
        self.assertEqual(
            outbox,
            {
                "DemandFundingRequested": 1,
                "DemandFundingEvidenceConfirmed": 1,
                "DemandFundingReviewClaimed": 1,
                "DemandFunded": 1,
            },
        )
        self.assertEqual(
            outbox_progress,
            {
                "DemandFundingRequested": -1,
                "DemandFundingEvidenceConfirmed": 1,
                "DemandFundingReviewClaimed": 1,
                "DemandFunded": -1,
            },
        )

    def test_terminal_history_is_actor_owned_and_keyset_paginated(self) -> None:
        operator_one, operator_two = self.principals
        service = self._service()

        initial = service.list_funding_reviews(principal=operator_one)[0]
        first_cycle_one = service.claim_funding_review(
            principal=operator_one,
            demand_id=str(DEMAND_ID),
            if_match=initial.etag,
            idempotency_key="demand12-history-finding-claim-one",
        )
        first_cycle_queue = service.list_funding_reviews(
            principal=operator_two
        )[0]
        first_cycle_two = service.claim_funding_review(
            principal=operator_two,
            demand_id=str(DEMAND_ID),
            if_match=first_cycle_queue.etag,
            idempotency_key="demand12-history-finding-claim-two",
        )
        finding = service.submit_funding_review_finding(
            principal=operator_one,
            funding_review_id=first_cycle_one.funding_review_id,
            if_match=first_cycle_two.etag,
            disposition="DISCREPANCY",
            reason_codes=("TARGET_CONTENT_MISMATCH",),
            required_field_codes=("SCOPE",),
            idempotency_key="demand12-history-finding",
        )
        self.assertEqual(
            (finding.status, finding.assignment_status),
            ("DISCREPANCY", "COMPLETED"),
        )

        finding_owner_history = service.list_funding_review_history(
            principal=operator_one,
            cursor=None,
            limit=100,
        )
        finding_peer_history = service.list_funding_review_history(
            principal=operator_two,
            cursor=None,
            limit=100,
        )
        self.assertEqual(
            tuple(
                (item.funding_review_id, item.status)
                for item in finding_owner_history.items
            ),
            ((first_cycle_one.funding_review_id, "DISCREPANCY"),),
        )
        self.assertEqual(
            (
                finding_owner_history.has_more,
                finding_owner_history.next_cursor,
                finding_peer_history.items,
                finding_peer_history.has_more,
                finding_peer_history.next_cursor,
            ),
            (False, None, (), False, None),
        )

        second_cycle_queue = service.list_funding_reviews(
            principal=operator_two
        )[0]
        second_cycle_two = service.claim_funding_review(
            principal=operator_two,
            demand_id=str(DEMAND_ID),
            if_match=second_cycle_queue.etag,
            idempotency_key="demand12-history-secured-claim-two",
        )
        second_cycle_pending = service.list_funding_reviews(
            principal=operator_one
        )[0]
        second_cycle_one = service.claim_funding_review(
            principal=operator_one,
            demand_id=str(DEMAND_ID),
            if_match=second_cycle_pending.etag,
            idempotency_key="demand12-history-secured-claim-one",
        )
        first_confirmation = service.confirm_funding_review(
            principal=operator_one,
            funding_review_id=second_cycle_one.funding_review_id,
            if_match=second_cycle_one.etag,
            attestation_codes=FINANCE_FUNDING_ATTESTATION_CODES,
            idempotency_key="demand12-history-secured-confirm-one",
        )
        second_cycle_two_current = service.get_funding_review(
            principal=operator_two,
            funding_review_id=second_cycle_two.funding_review_id,
        )
        secured = service.confirm_funding_review(
            principal=operator_two,
            funding_review_id=second_cycle_two.funding_review_id,
            if_match=second_cycle_two_current.etag,
            attestation_codes=FINANCE_FUNDING_ATTESTATION_CODES,
            idempotency_key="demand12-history-secured-confirm-two",
        )
        self.assertEqual(
            (
                first_confirmation.status,
                first_confirmation.confirmation_count,
                secured.status,
                secured.confirmation_count,
            ),
            ("PENDING", 1, "SECURED", 2),
        )

        complete_one = service.list_funding_review_history(
            principal=operator_one,
            cursor=None,
            limit=100,
        )
        complete_two = service.list_funding_review_history(
            principal=operator_two,
            cursor=None,
            limit=100,
        )
        self.assertEqual(
            tuple(item.status for item in complete_one.items),
            ("SECURED", "DISCREPANCY"),
        )
        self.assertEqual(
            tuple(
                (item.funding_review_id, item.status)
                for item in complete_two.items
            ),
            ((second_cycle_two.funding_review_id, "SECURED"),),
        )

        first_page = service.list_funding_review_history(
            principal=operator_one,
            cursor=None,
            limit=1,
        )
        self.assertEqual(
            (
                tuple(item.status for item in first_page.items),
                first_page.has_more,
                first_page.next_cursor is not None,
            ),
            (("SECURED",), True, True),
        )
        with self.assertRaises(EditorServiceError) as actor_bound:
            service.list_funding_review_history(
                principal=operator_two,
                cursor=first_page.next_cursor,
                limit=1,
            )
        self.assertEqual(
            (
                actor_bound.exception.status,
                actor_bound.exception.code,
                actor_bound.exception.path,
            ),
            (422, "INVALID_CURSOR", "/query/cursor"),
        )

        second_page = service.list_funding_review_history(
            principal=operator_one,
            cursor=first_page.next_cursor,
            limit=1,
        )
        self.assertEqual(
            (
                tuple(item.status for item in second_page.items),
                second_page.has_more,
                second_page.next_cursor,
            ),
            (("DISCREPANCY",), False, None),
        )
        self.assertEqual(first_page.items + second_page.items, complete_one.items)

    def test_wrong_role_tampered_marker_and_direct_table_access_fail_closed(self) -> None:
        operator = self.principals[0]
        source = self._source("demand_finance")
        service = PsycopgFinanceFundingService(
            connections=source,
            keys=self._keys(),
        )

        wrong_role = replace(
            operator,
            role_codes=("OPERATIONS_REVIEWER",),
            platform_duty_codes=("OPERATIONS_REVIEWER",),
        )
        with self.assertRaises(EditorServiceError) as rejected_role:
            service.list_funding_reviews(principal=wrong_role)
        self.assertEqual(
            (rejected_role.exception.status, rejected_role.exception.code),
            (404, "RESOURCE_NOT_FOUND"),
        )
        self.assertEqual(source.checked_out, [])

        initial = service.list_funding_reviews(principal=operator)[0]
        with self._admin() as connection:
            before = connection.execute(
                "SELECT "
                "(SELECT count(*) FROM demand.manual_funding_review_cases),"
                "(SELECT count(*) FROM demand.manual_funding_review_assignments),"
                "(SELECT count(*) FROM demand.manual_funding_receipts),"
                "(SELECT count(*) FROM audit.audit_events),"
                "(SELECT count(*) FROM infra.outbox_events)"
            ).fetchone()
        tampered = replace(operator, principal_marker_sha256=b"x" * 32)
        with self.assertRaises(EditorServiceError) as rejected_marker:
            service.claim_funding_review(
                principal=tampered,
                demand_id=str(DEMAND_ID),
                if_match=initial.etag,
                idempotency_key="tampered-finance-principal-marker-v1",
            )
        self.assertEqual(
            (rejected_marker.exception.status, rejected_marker.exception.code),
            (404, "RESOURCE_NOT_FOUND"),
        )
        with self._admin() as connection:
            after = connection.execute(
                "SELECT "
                "(SELECT count(*) FROM demand.manual_funding_review_cases),"
                "(SELECT count(*) FROM demand.manual_funding_review_assignments),"
                "(SELECT count(*) FROM demand.manual_funding_receipts),"
                "(SELECT count(*) FROM audit.audit_events),"
                "(SELECT count(*) FROM infra.outbox_events)"
            ).fetchone()
        self.assertEqual(after, before)

        with psycopg.connect(
            self.postgres.conninfo(database=self.database, user="demand_finance"),
            autocommit=True,
        ) as finance_connection:
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                finance_connection.execute(
                    "SELECT count(*) FROM demand.manual_funding_confirmations"
                )
        with psycopg.connect(
            self.postgres.conninfo(database=self.database, user="demand_review"),
            autocommit=True,
        ) as reviewer_connection:
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                reviewer_connection.execute(
                    "SELECT * FROM demand_api.list_manual_funding_reviews_v1("
                    "%s,%s,%s,100)",
                    (
                        FINANCE_USER_IDS[0],
                        FINANCE_SESSION_IDS[0],
                        operator.principal_marker_sha256,
                    ),
                )

    def test_release_replay_reclaim_and_receipt_collision_are_history_safe(self) -> None:
        operator = self.principals[0]
        service = self._service()
        initial = service.list_funding_reviews(principal=operator)[0]
        claim_key = "demand10-release-claim-operator-01"
        claimed = service.claim_funding_review(
            principal=operator,
            demand_id=str(DEMAND_ID),
            if_match=initial.etag,
            idempotency_key=claim_key,
        )
        released = service.release_funding_review_assignment(
            principal=operator,
            funding_review_id=claimed.funding_review_id,
            if_match=claimed.etag,
            reason_code="WORKLOAD_RELEASE",
            idempotency_key="demand10-release-operator-01",
        )
        released_replay = service.release_funding_review_assignment(
            principal=operator,
            funding_review_id=claimed.funding_review_id,
            if_match=claimed.etag,
            reason_code="WORKLOAD_RELEASE",
            idempotency_key="demand10-release-operator-01",
        )
        self.assertEqual(
            (
                released.status,
                released.assignment_status,
                released.confirmation_by_me,
                released.available_actions,
                released.can_confirm,
                released.revision,
                released_replay.replayed,
            ),
            ("PENDING", "RELEASED", False, (), False, 2, True),
        )

        historical_claim = service.claim_funding_review(
            principal=operator,
            demand_id=str(DEMAND_ID),
            if_match=initial.etag,
            idempotency_key=claim_key,
        )
        self.assertEqual(historical_claim, replace(claimed, replayed=True))

        pending = service.list_funding_reviews(principal=operator)[0]
        self.assertFalse(pending.assigned_to_me)
        reclaimed = service.claim_funding_review(
            principal=operator,
            demand_id=str(DEMAND_ID),
            if_match=pending.etag,
            idempotency_key="demand10-reclaim-operator-01",
        )
        self.assertNotEqual(reclaimed.assignment_id, claimed.assignment_id)
        self.assertEqual(
            (
                reclaimed.assignment_status,
                reclaimed.confirmation_by_me,
                reclaimed.available_actions,
                reclaimed.can_confirm,
                reclaimed.revision,
            ),
            (
                "ACTIVE",
                False,
                ("CONFIRM", "RELEASE_ASSIGNMENT", "SUBMIT_FINDING"),
                True,
                3,
            ),
        )

        original_command_id = service._command_id
        claim_receipt_id = original_command_id(
            operator, "CLAIM_MANUAL_FUNDING_REVIEW", claim_key
        )
        service._command_id = lambda *_args, **_kwargs: claim_receipt_id
        try:
            with self.assertRaises(EditorServiceError) as collision:
                service.release_funding_review_assignment(
                    principal=operator,
                    funding_review_id=reclaimed.funding_review_id,
                    if_match=reclaimed.etag,
                    reason_code="CONFLICT_DECLARED",
                    idempotency_key="demand10-colliding-receipt-id",
                )
            self.assertEqual(
                (collision.exception.status, collision.exception.code),
                (409, "IDEMPOTENCY_KEY_REUSED"),
            )
            with self.assertRaises(EditorServiceError) as hidden:
                service.release_funding_review_assignment(
                    principal=replace(
                        operator, principal_marker_sha256=b"x" * 32
                    ),
                    funding_review_id=reclaimed.funding_review_id,
                    if_match=reclaimed.etag,
                    reason_code="CONFLICT_DECLARED",
                    idempotency_key="demand10-colliding-receipt-id",
                )
            self.assertEqual(
                (hidden.exception.status, hidden.exception.code),
                (404, "RESOURCE_NOT_FOUND"),
            )
        finally:
            service._command_id = original_command_id

        old_release_replay = service.release_funding_review_assignment(
            principal=operator,
            funding_review_id=claimed.funding_review_id,
            if_match=claimed.etag,
            reason_code="WORKLOAD_RELEASE",
            idempotency_key="demand10-release-operator-01",
        )
        self.assertEqual(old_release_replay, replace(released, replayed=True))
        with self._admin() as connection:
            assignment_rows = connection.execute(
                "SELECT id,status FROM demand.manual_funding_review_assignments "
                "WHERE funding_review_id=%s ORDER BY created_at,id",
                (UUID(claimed.funding_review_id),),
            ).fetchall()
            release_fact = connection.execute(
                "SELECT reason_code,actor_user_id,assignment_id "
                "FROM demand.manual_funding_assignment_releases "
                "WHERE funding_review_id=%s",
                (UUID(claimed.funding_review_id),),
            ).fetchone()
        self.assertEqual(
            tuple(status for _assignment_id, status in assignment_rows),
            ("RELEASED", "ACTIVE"),
        )
        self.assertEqual(
            release_fact,
            ("WORKLOAD_RELEASE", FINANCE_USER_IDS[0], UUID(claimed.assignment_id)),
        )

    def test_rejected_finding_revokes_peer_and_is_owner_actionable(self) -> None:
        operator_one, operator_two = self.principals
        service = self._service()
        initial = service.list_funding_reviews(principal=operator_one)[0]
        first = service.claim_funding_review(
            principal=operator_one,
            demand_id=str(DEMAND_ID),
            if_match=initial.etag,
            idempotency_key="demand10-rejected-first-claim",
        )
        pending = service.list_funding_reviews(principal=operator_two)[0]
        second = service.claim_funding_review(
            principal=operator_two,
            demand_id=str(DEMAND_ID),
            if_match=pending.etag,
            idempotency_key="demand10-rejected-second-claim",
        )
        with self._admin() as connection:
            review_context_before = connection.execute(
                "SELECT current_review_id FROM demand.demands WHERE id=%s",
                (DEMAND_ID,),
            ).fetchone()[0]

        rejected = service.submit_funding_review_finding(
            principal=operator_one,
            funding_review_id=first.funding_review_id,
            if_match=second.etag,
            disposition="REJECTED",
            reason_codes=("BUDGET_PLAN_UNACCEPTABLE",),
            required_field_codes=("BUDGET", "SCOPE"),
            idempotency_key="demand10-rejected-finding",
        )
        rejected_replay = service.submit_funding_review_finding(
            principal=operator_one,
            funding_review_id=first.funding_review_id,
            if_match=second.etag,
            disposition="REJECTED",
            reason_codes=("BUDGET_PLAN_UNACCEPTABLE",),
            required_field_codes=("BUDGET", "SCOPE"),
            idempotency_key="demand10-rejected-finding",
        )
        self.assertEqual(
            (
                rejected.status,
                rejected.assignment_status,
                rejected.available_actions,
                rejected.can_confirm,
                rejected.revision,
                rejected_replay.replayed,
            ),
            ("REJECTED", "COMPLETED", (), False, 3, True),
        )
        second_claim_replay = service.claim_funding_review(
            principal=operator_two,
            demand_id=str(DEMAND_ID),
            if_match=pending.etag,
            idempotency_key="demand10-rejected-second-claim",
        )
        self.assertEqual(second_claim_replay, replace(second, replayed=True))

        with self._admin() as connection:
            root = connection.execute(
                "SELECT status,verified_version_id,current_review_id "
                "FROM demand.demands WHERE id=%s",
                (DEMAND_ID,),
            ).fetchone()
            assignments = connection.execute(
                "SELECT actor_user_id,status FROM "
                "demand.manual_funding_review_assignments "
                "WHERE funding_review_id=%s ORDER BY actor_user_id",
                (UUID(first.funding_review_id),),
            ).fetchall()
            finding = connection.execute(
                "SELECT disposition,reason_codes,required_field_codes "
                "FROM demand.manual_funding_findings WHERE funding_review_id=%s",
                (UUID(first.funding_review_id),),
            ).fetchone()
        self.assertEqual(root, ("NEEDS_CHANGES", None, review_context_before))
        self.assertEqual(
            dict(assignments),
            {
                FINANCE_USER_IDS[0]: "COMPLETED",
                FINANCE_USER_IDS[1]: "REVOKED",
            },
        )
        self.assertEqual(
            finding,
            (
                "REJECTED",
                ["BUDGET_PLAN_UNACCEPTABLE"],
                ["BUDGET", "SCOPE"],
            ),
        )
        finance_owner_rows = tuple(
            row for row in self._owner_findings() if row[3] == "REJECTED"
        )
        self.assertEqual(len(finance_owner_rows), 1)
        self.assertEqual(
            finance_owner_rows[0][1:6],
            (
                DEMAND_VERSION_ID,
                None,
                "REJECTED",
                ["BUDGET_PLAN_UNACCEPTABLE"],
                ["BUDGET", "SCOPE"],
            ),
        )

    def test_discrepancy_closes_one_cycle_and_allows_a_new_history_row(self) -> None:
        operator_one, operator_two = self.principals
        service = self._service()
        initial = service.list_funding_reviews(principal=operator_one)[0]
        first = service.claim_funding_review(
            principal=operator_one,
            demand_id=str(DEMAND_ID),
            if_match=initial.etag,
            idempotency_key="demand10-discrepancy-first-claim",
        )
        discrepancy = service.submit_funding_review_finding(
            principal=operator_one,
            funding_review_id=first.funding_review_id,
            if_match=first.etag,
            disposition="DISCREPANCY",
            reason_codes=("TARGET_CONTENT_MISMATCH",),
            required_field_codes=("SCOPE",),
            idempotency_key="demand10-discrepancy-finding",
        )
        self.assertEqual(
            (discrepancy.status, discrepancy.assignment_status),
            ("DISCREPANCY", "COMPLETED"),
        )
        available = service.list_funding_reviews(principal=operator_two)[0]
        self.assertEqual(
            (available.review_status, available.funding_review_id),
            ("AVAILABLE", None),
        )
        second_cycle = service.claim_funding_review(
            principal=operator_two,
            demand_id=str(DEMAND_ID),
            if_match=available.etag,
            idempotency_key="demand10-discrepancy-new-cycle",
        )
        self.assertNotEqual(second_cycle.funding_review_id, first.funding_review_id)
        with self._admin() as connection:
            cases = connection.execute(
                "SELECT status,count(*) FROM demand.manual_funding_review_cases "
                "WHERE demand_id=%s GROUP BY status ORDER BY status",
                (DEMAND_ID,),
            ).fetchall()
            root = connection.execute(
                "SELECT status,current_version_id=verified_version_id "
                "FROM demand.demands WHERE id=%s",
                (DEMAND_ID,),
            ).fetchone()
        self.assertEqual(cases, [("DISCREPANCY", 1), ("PENDING", 1)])
        self.assertEqual(root, ("FUNDING_PENDING", True))

    def test_legacy_case_expiry_does_not_block_assignment_reaping_or_root_deadline(self) -> None:
        operator_one, operator_two = self.principals
        service = self._service()
        initial = service.list_funding_reviews(principal=operator_one)[0]
        first = service.claim_funding_review(
            principal=operator_one,
            demand_id=str(DEMAND_ID),
            if_match=initial.etag,
            idempotency_key="demand10-expiry-first-claim",
        )
        with self._admin(autocommit=False) as connection:
            connection.execute("SET LOCAL session_replication_role='replica'")
            connection.execute(
                "UPDATE demand.manual_funding_review_cases SET "
                "expires_at=created_at+interval '1 microsecond' WHERE id=%s",
                (UUID(first.funding_review_id),),
            )
            connection.execute(
                "UPDATE demand.manual_funding_review_assignments SET "
                "expires_at=created_at+interval '1 microsecond' WHERE id=%s",
                (UUID(first.assignment_id),),
            )

        pending = service.list_funding_reviews(principal=operator_two)[0]
        self.assertEqual(
            (pending.funding_review_id, pending.review_status, pending.expires_at),
            (first.funding_review_id, "PENDING", initial.expires_at),
        )
        second = service.claim_funding_review(
            principal=operator_two,
            demand_id=str(DEMAND_ID),
            if_match=pending.etag,
            idempotency_key="demand10-expiry-second-claim",
        )
        expired_replay = service.claim_funding_review(
            principal=operator_one,
            demand_id=str(DEMAND_ID),
            if_match=initial.etag,
            idempotency_key="demand10-expiry-first-claim",
        )
        self.assertEqual(expired_replay, replace(first, replayed=True))
        with self._admin() as connection:
            statuses = dict(
                connection.execute(
                    "SELECT actor_user_id,status FROM "
                    "demand.manual_funding_review_assignments "
                    "WHERE funding_review_id=%s",
                    (UUID(first.funding_review_id),),
                ).fetchall()
            )
            cleanup = connection.execute(
                "SELECT safe_attributes->>'expired_assignment_count',"
                "safe_attributes->>'stale_own_assignment_revoked' "
                "FROM audit.audit_events WHERE actor_id=%s "
                "AND action_code='JOIN_MANUAL_FUNDING_REVIEW'",
                (FINANCE_USER_IDS[1],),
            ).fetchone()
        self.assertEqual(
            statuses,
            {
                FINANCE_USER_IDS[0]: "EXPIRED",
                FINANCE_USER_IDS[1]: "ACTIVE",
            },
        )
        self.assertEqual(cleanup, ("1", "false"))
        self.assertLessEqual(second.assignment_expires_at, initial.expires_at)

        with self._admin(autocommit=False) as connection:
            connection.execute("SET LOCAL session_replication_role='replica'")
            connection.execute(
                "UPDATE demand.demands SET "
                "expires_at=created_at+interval '1 microsecond' WHERE id=%s",
                (DEMAND_ID,),
            )
        self.assertEqual(service.list_funding_reviews(principal=operator_one), ())
        with self.assertRaises(EditorServiceError) as deadline:
            service.claim_funding_review(
                principal=operator_one,
                demand_id=str(DEMAND_ID),
                if_match=second.etag,
                idempotency_key="demand10-root-deadline-claim",
            )
        self.assertEqual(
            (deadline.exception.status, deadline.exception.code),
            (409, "STATE_CONFLICT"),
        )

    def test_current_duty_regrant_revokes_stale_own_assignment_and_replays_claim(self) -> None:
        operator = self.principals[0]
        service = self._service()
        initial = service.list_funding_reviews(principal=operator)[0]
        claim_key = "demand10-duty-regrant-first-claim"
        claimed = service.claim_funding_review(
            principal=operator,
            demand_id=str(DEMAND_ID),
            if_match=initial.etag,
            idempotency_key=claim_key,
        )
        replacement_id = UUID("f4000001-0000-4000-8000-000000000101")
        try:
            self._replace_finance_duty(ordinal=0, replacement_id=replacement_id)
            refreshed = self._principal(0)
            pending = service.list_funding_reviews(principal=refreshed)[0]
            self.assertFalse(pending.assigned_to_me)
            with self.assertRaises(EditorServiceError) as hidden_old:
                service.get_funding_review(
                    principal=refreshed,
                    funding_review_id=claimed.funding_review_id,
                )
            self.assertEqual(
                (hidden_old.exception.status, hidden_old.exception.code),
                (404, "RESOURCE_NOT_FOUND"),
            )
            reclaimed = service.claim_funding_review(
                principal=refreshed,
                demand_id=str(DEMAND_ID),
                if_match=pending.etag,
                idempotency_key="demand10-duty-regrant-reclaim",
            )
            self.assertNotEqual(reclaimed.assignment_id, claimed.assignment_id)
            original_replay = service.claim_funding_review(
                principal=refreshed,
                demand_id=str(DEMAND_ID),
                if_match=initial.etag,
                idempotency_key=claim_key,
            )
            self.assertEqual(original_replay, replace(claimed, replayed=True))
            with self._admin() as connection:
                assignments = connection.execute(
                    "SELECT duty_grant_id,status FROM "
                    "demand.manual_funding_review_assignments "
                    "WHERE funding_review_id=%s ORDER BY created_at,id",
                    (UUID(claimed.funding_review_id),),
                ).fetchall()
                cleanup = connection.execute(
                    "SELECT safe_attributes->>'expired_assignment_count',"
                    "safe_attributes->>'stale_own_assignment_revoked' "
                    "FROM audit.audit_events WHERE actor_id=%s "
                    "AND action_code='JOIN_MANUAL_FUNDING_REVIEW'",
                    (FINANCE_USER_IDS[0],),
                ).fetchone()
            self.assertEqual(
                assignments,
                [
                    (FINANCE_DUTY_GRANT_IDS[0], "REVOKED"),
                    (replacement_id, "ACTIVE"),
                ],
            )
            self.assertEqual(cleanup, ("0", "true"))
        finally:
            self._restore_finance_duty(
                ordinal=0, replacement_id=replacement_id
            )

    def test_confirm_receipt_replays_after_current_duty_regrant(self) -> None:
        operator = self.principals[0]
        service = self._service()
        initial = service.list_funding_reviews(principal=operator)[0]
        claimed = service.claim_funding_review(
            principal=operator,
            demand_id=str(DEMAND_ID),
            if_match=initial.etag,
            idempotency_key="demand10-confirm-regrant-claim",
        )
        confirm_key = "demand10-confirm-before-regrant"
        confirmed = service.confirm_funding_review(
            principal=operator,
            funding_review_id=claimed.funding_review_id,
            if_match=claimed.etag,
            attestation_codes=FINANCE_FUNDING_ATTESTATION_CODES,
            idempotency_key=confirm_key,
        )
        with self._admin() as connection:
            before = connection.execute(
                "SELECT (SELECT count(*) FROM demand.manual_funding_receipts),"
                "(SELECT count(*) FROM demand.manual_funding_confirmations),"
                "(SELECT count(*) FROM audit.audit_events),"
                "(SELECT count(*) FROM infra.outbox_events),"
                "(SELECT aggregate_version FROM demand.demands WHERE id=%s)",
                (DEMAND_ID,),
            ).fetchone()
        replacement_id = UUID("f4000001-0000-4000-8000-000000000102")
        try:
            self._replace_finance_duty(ordinal=0, replacement_id=replacement_id)
            refreshed = self._principal(0)
            replay = service.confirm_funding_review(
                principal=refreshed,
                funding_review_id=claimed.funding_review_id,
                if_match=claimed.etag,
                attestation_codes=FINANCE_FUNDING_ATTESTATION_CODES,
                idempotency_key=confirm_key,
            )
            self.assertEqual(replay, replace(confirmed, replayed=True))
            with self._admin() as connection:
                after = connection.execute(
                    "SELECT (SELECT count(*) FROM demand.manual_funding_receipts),"
                    "(SELECT count(*) FROM demand.manual_funding_confirmations),"
                    "(SELECT count(*) FROM audit.audit_events),"
                    "(SELECT count(*) FROM infra.outbox_events),"
                    "(SELECT aggregate_version FROM demand.demands WHERE id=%s)",
                    (DEMAND_ID,),
                ).fetchone()
            self.assertEqual(after, before)
        finally:
            self._restore_finance_duty(
                ordinal=0, replacement_id=replacement_id
            )

    def test_evidence_rejects_non_integer_or_unsafe_amounts_and_corrupt_claim_marker(self) -> None:
        operator = self.principals[0]
        service = self._service()
        initial = service.list_funding_reviews(principal=operator)[0]
        claimed = service.claim_funding_review(
            principal=operator,
            demand_id=str(DEMAND_ID),
            if_match=initial.etag,
            idempotency_key="demand10-evidence-claim",
        )
        with self._admin() as connection:
            original_content = connection.execute(
                "SELECT content::text FROM demand.demand_versions WHERE id=%s",
                (DEMAND_VERSION_ID,),
            ).fetchone()[0]
        for malformed in ('"100"', "100.5", "-1", "9007199254740992"):
            with self.subTest(malformed=malformed):
                with self._admin(autocommit=False) as connection:
                    connection.execute("SET LOCAL session_replication_role='replica'")
                    connection.execute(
                        "UPDATE demand.demand_versions SET content=jsonb_set("
                        "content,'{budget,minimum_amount_minor}',%s::jsonb,false) "
                        "WHERE id=%s",
                        (malformed, DEMAND_VERSION_ID),
                    )
                with self.assertRaises(EditorServiceError) as rejected:
                    service.get_funding_review(
                        principal=operator,
                        funding_review_id=claimed.funding_review_id,
                    )
                self.assertEqual(
                    (rejected.exception.status, rejected.exception.code),
                    (404, "RESOURCE_NOT_FOUND"),
                )
                with self._admin(autocommit=False) as connection:
                    connection.execute("SET LOCAL session_replication_role='replica'")
                    connection.execute(
                        "UPDATE demand.demand_versions SET content=%s::jsonb "
                        "WHERE id=%s",
                        (original_content, DEMAND_VERSION_ID),
                    )

        with self._admin(autocommit=False) as connection:
            connection.execute("SET LOCAL session_replication_role='replica'")
            connection.execute(
                "UPDATE demand.manual_funding_review_assignments SET "
                "authority_marker_sha256=sha256(convert_to('corrupt','UTF8')) "
                "WHERE id=%s",
                (UUID(claimed.assignment_id),),
            )
        with psycopg.connect(
            self.postgres.conninfo(database=self.database, user="demand_finance"),
            autocommit=False,
        ) as connection:
            for name, value in (
                ("app.scope_kind", "FINANCE_FUNDING"),
                ("app.operation", "CLAIM_FUNDING_REVIEW"),
                ("app.actor_id", operator.user_id),
                ("app.session_id", operator.session_id),
                ("app.organization_id", str(ORGANIZATION_ID)),
                ("app.demand_id", str(DEMAND_ID)),
                ("app.funding_review_id", claimed.funding_review_id),
                ("app.assignment_id", claimed.assignment_id),
            ):
                connection.execute(
                    "SELECT pg_catalog.set_config(%s,%s,true)", (name, value)
                )
            evidence = connection.execute(
                "SELECT * FROM demand_api.read_manual_funding_evidence_v2("
                "%s,%s,%s,%s)",
                (
                    UUID(operator.user_id),
                    UUID(operator.session_id),
                    UUID(claimed.funding_review_id),
                    operator.principal_marker_sha256,
                ),
            ).fetchone()
        self.assertIsNone(evidence)

    def test_concurrent_claims_serialize_and_never_overbook_two_slots(self) -> None:
        operator_one, operator_two = self.principals
        setup_service = self._service()
        initial = setup_service.list_funding_reviews(principal=operator_one)[0]
        claimed = setup_service.claim_funding_review(
            principal=operator_one,
            demand_id=str(DEMAND_ID),
            if_match=initial.etag,
            idempotency_key="demand10-concurrent-setup-claim",
        )
        released = setup_service.release_funding_review_assignment(
            principal=operator_one,
            funding_review_id=claimed.funding_review_id,
            if_match=claimed.etag,
            reason_code="WORKLOAD_RELEASE",
            idempotency_key="demand10-concurrent-setup-release",
        )
        barrier = Barrier(2)

        def race(principal: EditorPrincipal, key: str):
            service = self._service()
            barrier.wait(timeout=5)
            try:
                return service.claim_funding_review(
                    principal=principal,
                    demand_id=str(DEMAND_ID),
                    if_match=released.etag,
                    idempotency_key=key,
                )
            except EditorServiceError as error:
                return error

        with ThreadPoolExecutor(max_workers=2) as executor:
            results = tuple(
                executor.map(
                    lambda values: race(*values),
                    (
                        (operator_one, "demand10-concurrent-operator-one"),
                        (operator_two, "demand10-concurrent-operator-two"),
                    ),
                )
            )
        successes = tuple(
            result for result in results if not isinstance(result, EditorServiceError)
        )
        failures = tuple(
            result for result in results if isinstance(result, EditorServiceError)
        )
        self.assertEqual(len(successes), 1)
        self.assertEqual(
            tuple((error.status, error.code) for error in failures),
            ((412, "PRECONDITION_FAILED"),),
        )
        with self._admin() as connection:
            slots = connection.execute(
                "SELECT count(*) FILTER (WHERE status IN ('ACTIVE','COMPLETED')) ,"
                "count(DISTINCT actor_user_id) FILTER ("
                "WHERE status IN ('ACTIVE','COMPLETED')) FROM "
                "demand.manual_funding_review_assignments "
                "WHERE funding_review_id=%s",
                (UUID(claimed.funding_review_id),),
            ).fetchone()
        self.assertEqual(slots, (1, 1))
        self.assertLessEqual(slots[0], 2)

    def test_exact_demand9_to_current_rolls_back_then_applies_and_replays(
        self,
    ) -> None:
        database = self.postgres.create_database()
        try:
            iam_catalog = MigrationCatalog.load(IAM_ROOT)
            iam_report = IamMigrationRunner(
                driver=PsycopgMigrationDriver(
                    settings=PsycopgMigrationSettings(
                        conninfo=self.postgres.conninfo(
                            database=database,
                            user="iam_migration_runner",
                        ),
                        application_name="demand10-upgrade-iam",
                    ),
                    dbapi=psycopg,
                ),
                runner_version="demand10-upgrade-pg18/1",
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
            self.assertEqual(
                iam_report.applied_versions,
                tuple(
                    artifact.descriptor.version
                    for artifact in iam_catalog.artifacts
                ),
            )

            catalog = DemandMigrationCatalog.load(DEMAND_ROOT)
            sources = DemandContractSources(
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
            )
            prefix = catalog.artifacts[:9]
            with psycopg.connect(
                self.postgres.conninfo(
                    database=database,
                    user="demand_migration_runner",
                ),
                autocommit=True,
            ) as connection:
                connection.execute("SET ROLE demand_schema_owner")
                for artifact in prefix:
                    descriptor = artifact.descriptor
                    connection.execute("BEGIN")
                    connection.execute(artifact.sql_bytes.decode("utf-8"))
                    connection.execute(
                        "INSERT INTO demand_meta.schema_migrations ("
                        "component,version,phase,name,checksum_sha256,"
                        "manifest_sha256,runner_version,applied_at) VALUES ("
                        "'demand',%s,%s,%s,%s,%s,"
                        "'reviewed-demand9-boundary/1',"
                        "transaction_timestamp())",
                        (
                            descriptor.version,
                            descriptor.phase.value,
                            descriptor.name,
                            descriptor.checksum_sha256,
                            descriptor.prefix_manifest_sha256,
                        ),
                    )
                    if descriptor.version == 9:
                        connection.execute(
                            "INSERT INTO demand_meta.schema_contracts ("
                            "singleton_key,schema_head_version,"
                            "min_app_compatible_version,"
                            "max_app_compatible_version,"
                            "required_iam_schema_version,"
                            "api_contract_sha256,event_contract_sha256,"
                            "content_contract_sha256,"
                            "migration_manifest_sha256,generated_at) VALUES ("
                            "true,9,9,9,36,%s,%s,%s,%s,"
                            "transaction_timestamp())",
                            (
                                hashlib.sha256(
                                    sources.api_contract_bytes
                                ).digest(),
                                hashlib.sha256(
                                    sources.event_contract_bytes
                                ).digest(),
                                hashlib.sha256(
                                    sources.content_contract_bytes
                                ).digest(),
                                descriptor.prefix_manifest_sha256,
                            ),
                        )
                    connection.execute("COMMIT")
                connection.execute(
                    "CREATE TABLE demand.manual_funding_assignment_releases ("
                    "rollback_blocker boolean NOT NULL)"
                )
                connection.execute("RESET ROLE")

            runner = DemandMigrationRunner(
                driver=PsycopgDemandMigrationDriver(
                    settings=DemandMigrationSettings(
                        conninfo=self.postgres.conninfo(
                            database=database,
                            user="demand_migration_runner",
                        ),
                        application_name="demand10-exact-upgrade",
                    ),
                    dbapi=psycopg,
                ),
                runner_version="demand10-upgrade-pg18/1",
            )
            with self.assertRaises(psycopg.errors.DuplicateTable):
                runner.run(catalog=catalog, contract_sources=sources)

            with psycopg.connect(
                self.postgres.admin_conninfo(database=database),
                autocommit=True,
            ) as connection:
                rolled_back = connection.execute(
                    "SELECT "
                    "(SELECT max(version) FROM demand_meta.schema_migrations),"
                    "(SELECT schema_head_version FROM "
                    "demand_meta.schema_contracts WHERE singleton_key),"
                    "pg_catalog.to_regprocedure("
                    "'demand.text_array_is_sorted_unique_v1(text[])'),"
                    "pg_catalog.pg_get_constraintdef(oid) "
                    "FROM pg_catalog.pg_constraint WHERE conname="
                    "'ck_manual_funding_assignment_shape'"
                ).fetchone()
                self.assertEqual(rolled_back[:3], (9, 9, None))
                self.assertNotIn("RELEASED", rolled_back[3])
                connection.execute("SET ROLE demand_schema_owner")
                connection.execute(
                    "DROP TABLE demand.manual_funding_assignment_releases"
                )
                connection.execute("RESET ROLE")

            upgraded = runner.run(catalog=catalog, contract_sources=sources)
            replayed = runner.run(catalog=catalog, contract_sources=sources)
            self.assertEqual(
                (upgraded.applied_versions, upgraded.skipped_versions),
                (
                    tuple(range(10, DEMAND_SCHEMA_HEAD_VERSION + 1)),
                    tuple(range(1, 10)),
                ),
            )
            self.assertEqual(
                (replayed.applied_versions, replayed.skipped_versions),
                ((), tuple(range(1, DEMAND_SCHEMA_HEAD_VERSION + 1))),
            )
            with psycopg.connect(
                self.postgres.admin_conninfo(database=database),
                autocommit=True,
            ) as connection:
                compatibility = connection.execute(
                    "SELECT current_schema_version,schema_head_version,"
                    "min_app_compatible_version,max_app_compatible_version,"
                    "required_iam_schema_version,migration_manifest_sha256 "
                    "FROM demand.schema_compatibility"
                ).fetchone()
                dependency_sha256 = connection.execute(
                    "SELECT encode(dependency_sha256,'hex') FROM "
                    "demand.trust_schema_dependency_v1"
                ).fetchone()[0]
            self.assertEqual(
                compatibility,
                (
                    DEMAND_SCHEMA_HEAD_VERSION,
                    DEMAND_SCHEMA_HEAD_VERSION,
                    DEMAND_SCHEMA_HEAD_VERSION,
                    DEMAND_SCHEMA_HEAD_VERSION,
                    DEMAND_REQUIRED_IAM_SCHEMA_VERSION,
                    catalog.manifest_sha256,
                ),
            )
            self.assertEqual(
                dependency_sha256,
                "ea6887891134ffa2f451fed35d469ae1c5195c54649e228f587622d95696dddf",
            )
        finally:
            self.postgres.drop_database(database)

    def _owner_findings(self) -> tuple[tuple, ...]:
        operation = DemandPostgresOperation.CREATE_VERSION
        operation_code = "CREATE_VERSION"
        marker = owner_authority_marker(operation)
        with psycopg.connect(
            self.postgres.conninfo(database=self.database, user="demand_self"),
            autocommit=False,
        ) as connection:
            for name, value in (
                ("app.scope_kind", "DEMAND_OWNER"),
                ("app.operation", operation_code),
                ("app.actor_id", str(ACTOR_USER_ID)),
                ("app.session_id", str(DEMAND_OWNER_SESSION_ID)),
                ("app.organization_id", str(ORGANIZATION_ID)),
                ("app.demand_id", str(DEMAND_ID)),
            ):
                connection.execute(
                    "SELECT pg_catalog.set_config(%s,%s,true)", (name, value)
                )
            return tuple(
                connection.execute(
                    "SELECT finding_id,demand_version_id,assignment_id,decision,"
                    "reason_codes,required_field_codes,reviewed_at FROM "
                    "demand_api.read_demand_owner_findings_v2("
                    "%s,%s,%s,%s,%s,%s)",
                    (
                        ACTOR_USER_ID,
                        DEMAND_OWNER_SESSION_ID,
                        ORGANIZATION_ID,
                        DEMAND_ID,
                        operation_code,
                        marker,
                    ),
                ).fetchall()
            )

    def _replace_finance_duty(self, *, ordinal: int, replacement_id: UUID) -> None:
        now = datetime.now(timezone.utc).replace(microsecond=0)
        with self._admin(autocommit=False) as connection:
            connection.execute(
                "UPDATE iam.platform_duty_grants SET "
                "revoked_at=%s,revocation_reason_code='DEMAND10_TEST_REGRANT',"
                "aggregate_version=aggregate_version+1,updated_at=%s WHERE id=%s",
                (now, now, FINANCE_DUTY_GRANT_IDS[ordinal]),
            )
            connection.execute(
                "INSERT INTO iam.platform_duty_grants("
                "id,user_id,duty_code,granted_by_kind,granted_by_id,granted_at,"
                "expires_at,revoked_at,revocation_reason_code,aggregate_version,"
                "created_at,updated_at) VALUES ("
                "%s,%s,'FINANCE_OPERATOR','SYSTEM',%s,%s,NULL,NULL,NULL,1,%s,%s)",
                (
                    replacement_id,
                    FINANCE_USER_IDS[ordinal],
                    ACTOR_USER_ID,
                    now,
                    now,
                    now,
                ),
            )

    def _restore_finance_duty(self, *, ordinal: int, replacement_id: UUID) -> None:
        with self._admin(autocommit=False) as connection:
            reset_demand_postgres_state(connection)
            connection.execute(
                "DELETE FROM iam.platform_duty_grants WHERE id=%s",
                (replacement_id,),
            )
            connection.execute(
                "UPDATE iam.platform_duty_grants SET revoked_at=NULL,"
                "revocation_reason_code=NULL,aggregate_version=1,"
                "updated_at=created_at WHERE id=%s",
                (FINANCE_DUTY_GRANT_IDS[ordinal],),
            )

    def _source(self, role: str) -> TrackingDemandConnectionSource:
        source = TrackingDemandConnectionSource(
            self.postgres.conninfo(database=self.database, user=role)
        )
        self.sources.append(source)
        return source

    def _service(self) -> PsycopgFinanceFundingService:
        return PsycopgFinanceFundingService(
            connections=self._source("demand_finance"),
            keys=self._keys(),
        )

    @staticmethod
    def _keys() -> FinanceFundingKeys:
        return FinanceFundingKeys(
            id_key=b"finance-pg-id-key-material-2026!",
            idempotency_key=b"finance-pg-idempotency-key-2026!",
            payload_key=b"finance-pg-payload-key-material-2026!",
        )

    @classmethod
    def _principal(cls, ordinal: int) -> EditorPrincipal:
        user_id = FINANCE_USER_IDS[ordinal]
        session_id = FINANCE_SESSION_IDS[ordinal]
        resolver = PsycopgEditorPrincipalResolver(
            connections=_Connections(
                cls.postgres.conninfo(database=cls.database, user="iam_app")
            )
        )
        workspace = resolver.resolve(
            EditorPrincipalResolutionRequest(
                actor_user_id=user_id,
                session_id=session_id,
                requested_workspace_id=f"platform:{user_id}",
            )
        )
        return EditorPrincipal(
            user_id=str(workspace.user_id),
            session_id=str(workspace.session_id),
            organization_id=None,
            role_codes=workspace.platform_duty_codes,
            workspace_id=workspace.workspace_id,
            workspace_kind=workspace.workspace_kind.value,
            membership_id=None,
            organization_role_codes=workspace.organization_role_codes,
            user_role_codes=workspace.user_role_codes,
            platform_duty_codes=workspace.platform_duty_codes,
            principal_marker_sha256=workspace.principal_marker,
        )

    @classmethod
    def _admin(cls, *, autocommit: bool = True):
        return psycopg.connect(
            cls.postgres.admin_conninfo(database=cls.database),
            autocommit=autocommit,
        )

    @classmethod
    def _migrate(cls) -> None:
        IamMigrationRunner(
            driver=PsycopgMigrationDriver(
                settings=PsycopgMigrationSettings(
                    conninfo=cls.postgres.conninfo(
                        database=cls.database,
                        user="iam_migration_runner",
                    )
                ),
                dbapi=psycopg,
            ),
            runner_version="finance-funding-pg18-test/1",
        ).run(
            catalog=MigrationCatalog.load(IAM_ROOT),
            contract_sources=IamContractSources(
                api_contract_bytes=(
                    PLATFORM_ROOT / "contracts/api/iam-v1.openapi.yaml"
                ).read_bytes(),
                event_contract_bytes=(
                    PLATFORM_ROOT / "contracts/events/iam-v1.schema.json"
                ).read_bytes(),
            ),
        )
        demand_runner = DemandMigrationRunner(
            driver=PsycopgDemandMigrationDriver(
                settings=DemandMigrationSettings(
                    conninfo=cls.postgres.conninfo(
                        database=cls.database,
                        user="demand_migration_runner",
                    )
                ),
                dbapi=psycopg,
            ),
            runner_version="finance-funding-pg18-test/1",
        )
        demand_catalog = DemandMigrationCatalog.load(DEMAND_ROOT)
        demand_contracts = DemandContractSources(
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
        )
        first = demand_runner.run(
            catalog=demand_catalog, contract_sources=demand_contracts
        )
        replay = demand_runner.run(
            catalog=demand_catalog, contract_sources=demand_contracts
        )
        expected = tuple(
            artifact.descriptor.version for artifact in demand_catalog.artifacts
        )
        if (
            first.applied_versions != expected
            or first.skipped_versions != ()
            or replay.applied_versions != ()
            or replay.skipped_versions != expected
        ):
            raise AssertionError("Demand migration apply/replay evidence drifted")


if __name__ == "__main__":
    unittest.main()
