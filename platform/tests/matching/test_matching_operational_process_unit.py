"""Closed, zero-I/O behavior gates for the Matching v3 process loop."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from decimal import Decimal
import hashlib
from uuid import UUID

from desire_platform.creator_profile.adapters.postgres import (
    CreatorProfilePostgresDerivedMatchCaptureResult,
)
from desire_platform.demand.adapters.postgres import (
    DemandPostgresMatchCaptureResult,
)
from desire_platform.matching.adapters.postgres import (
    MATCHING_OPERATIONAL_AUTHORITY_MARKER_SHA256,
    MATCHING_OPERATIONAL_WORKLOAD_ID,
    MatchingCoordinatorProcess,
    MatchingOperationalKeyRing,
    MatchingPostgresRejectedError,
    MatchingSelectionCompletionClaim,
    MatchingSelectionCompletionResult,
    MatchingTrustEvidence,
    MatchingWorkerJobClaim,
    MatchingWorkerProcess,
    MatchingWorkerRunResult,
    MatchingWorkloadContext,
    PsycopgMatchingCoordinatorRuntime,
    PsycopgMatchingWorkerRuntime,
)
from desire_platform.matching.adapters.postgres.operational_runtime import (
    _operational_material,
    _operational_uuid,
    _score_text,
)
from desire_platform.matching.engine_v1 import load_default_rule_release_v1
from tests.support.demand_postgres_builders import match_input_snapshot


def uid(value: int) -> UUID:
    return UUID(f"a{value:07x}-0000-4000-8000-000000000001")


def key_ring(prefix: str) -> MatchingOperationalKeyRing:
    return MatchingOperationalKeyRing(
        identity_key_id=f"{prefix}-identity-v1",
        identity_key=bytearray(hashlib.sha256(f"{prefix}-identity".encode()).digest()),
        payload_hash_key_id=f"{prefix}-payload-v1",
        payload_hash_key=bytearray(hashlib.sha256(f"{prefix}-payload".encode()).digest()),
        lease_digest_key_id=f"{prefix}-lease-v1",
        lease_digest_key=bytearray(hashlib.sha256(f"{prefix}-lease".encode()).digest()),
    )


class _NoDelivery:
    @staticmethod
    def claim_matching_requested_delivery(**_kwargs):
        return None

    @staticmethod
    def complete_matching_requested_delivery(**_kwargs):
        raise AssertionError("no delivery was claimed")


class _DemandCapture:
    def __init__(self, result: DemandPostgresMatchCaptureResult) -> None:
        self.result = result
        self.requests = []

    def capture_match_inputs(self, request):
        self.requests.append(request)
        return self.result


class _ProfileCapture:
    def __init__(self, result: CreatorProfilePostgresDerivedMatchCaptureResult) -> None:
        self.result = result
        self.requests = []

    def capture_derived_match_inputs(self, request):
        self.requests.append(request)
        return self.result


class _WorkerRuntime(PsycopgMatchingWorkerRuntime):
    def __init__(self, claim: MatchingWorkerJobClaim) -> None:
        self.claim = claim
        self.claim_requests = []
        self.start_requests = []
        self.complete_requests = []
        self.fail_requests = []
        self.rule = load_default_rule_release_v1()
        self.start_error = None

    def claim_job(self, request):
        self.claim_requests.append(request)
        return self.claim

    def read_rule_bundle(self, **_kwargs):
        return self.rule

    def start_run(self, request):
        self.start_requests.append(request)
        if self.start_error is not None:
            error, self.start_error = self.start_error, None
            raise error
        return MatchingWorkerRunResult(
            projection={"status": "RUNNING"}, replayed=False
        )

    def complete_run(self, request):
        self.complete_requests.append(request)
        return MatchingWorkerRunResult(
            projection={"status": "COMPLETED"}, replayed=False
        )

    def fail_run(self, request):
        self.fail_requests.append(request)
        status = "QUEUED" if request.retry_run_id is not None else "FAILED"
        return MatchingWorkerRunResult(
            projection={"status": status}, replayed=False
        )


class _CoordinatorRuntime(PsycopgMatchingCoordinatorRuntime):
    def __init__(self, claim: MatchingSelectionCompletionClaim) -> None:
        self.claim = claim
        self.claim_requests = []
        self.complete_requests = []
        self.fail_requests = []
        self.complete_error = None

    def claim_completion(self, request):
        self.claim_requests.append(request)
        return self.claim

    def complete_claimed_selection(self, request):
        self.complete_requests.append(request)
        if self.complete_error is not None:
            error, self.complete_error = self.complete_error, None
            raise error
        return MatchingSelectionCompletionResult(
            projection={"status": "CLOSED_NO_SELECTION"}, replayed=False
        )

    def fail_completion(self, request):
        self.fail_requests.append(request)
        return MatchingSelectionCompletionResult(
            projection={"status": "AVAILABLE"}, replayed=False
        )


def _worker_process(
    runtime: _WorkerRuntime,
    *,
    now: datetime,
) -> MatchingWorkerProcess:
    snapshot = match_input_snapshot(captured_at=now)
    demand_capture = DemandPostgresMatchCaptureResult(
        match_run_id=runtime.claim.match_run_id,
        captured_at=now,
        requested_matching_request_ids=(snapshot.matching_request_id,),
        snapshots=(snapshot,),
        statement_count=2,
    )
    allowlist = hashlib.sha256(
        b"profile-derived-match-allowlist-v1|0|"
    ).digest()
    profile_capture = CreatorProfilePostgresDerivedMatchCaptureResult(
        match_run_id=runtime.claim.match_run_id,
        workload_id=MATCHING_OPERATIONAL_WORKLOAD_ID,
        capture_contract_version=2,
        status="COMPLETED",
        captured_at=now,
        candidate_count=0,
        allowlist_sha256=allowlist,
        authorization_valid_until=now + timedelta(minutes=5),
        replayed=False,
        snapshots=(),
        statement_count=1,
    )
    identifiers = iter(uid(value) for value in range(800, 820))
    return MatchingWorkerProcess(
        runtime=runtime,
        demand_delivery=_NoDelivery(),
        demand_capture=_DemandCapture(demand_capture),
        profile_capture=_ProfileCapture(profile_capture),
        context=MatchingWorkloadContext(
            workload_id=MATCHING_OPERATIONAL_WORKLOAD_ID,
            authority_marker_sha256=(
                MATCHING_OPERATIONAL_AUTHORITY_MARKER_SHA256
            ),
        ),
        coordinator_context=MatchingWorkloadContext(
            workload_id=uid(700),
            authority_marker_sha256=b"c" * 32,
        ),
        keys=key_ring("worker"),
        default_rule=runtime.rule,
        clock=lambda: now,
        id_source=lambda: next(identifiers),
    )


def test_key_material_is_stable_and_carrier_backed() -> None:
    keys = key_ring("worker")
    material_one = _operational_material(
        keys=keys,
        operation="COMPLETE_MATCH_RUN",
        stable_key=str(uid(1)),
        payload={"score": "88.00"},
        outbox_count=1,
    )
    material_two = _operational_material(
        keys=keys,
        operation="COMPLETE_MATCH_RUN",
        stable_key=str(uid(1)),
        payload={"score": "88.00"},
        outbox_count=1,
    )
    assert material_one == material_two
    assert isinstance(keys.identity_key, bytearray)
    keys.identity_key[:] = b"\x00" * len(keys.identity_key)
    assert keys.identity_key == bytearray(32)


def test_run_identifiers_and_numeric_score_text_are_canonical() -> None:
    source_event_id = str(uid(50))
    run_id = _operational_uuid("match-run", source_event_id)
    assert run_id == _operational_uuid("match-run", source_event_id)
    assert run_id != _operational_uuid("match-job", source_event_id)
    assert _score_text(Decimal("88")) == "88.00"
    assert _score_text("0.10") == "0.10"


def test_worker_completes_zero_candidate_run_with_durable_system_close() -> None:
    now = datetime.now(timezone.utc).replace(microsecond=0)
    snapshot = match_input_snapshot(captured_at=now)
    claim = MatchingWorkerJobClaim(
        organization_id=snapshot.organization_id,
        job_id=uid(101),
        attempt_id=uid(102),
        match_run_id=uid(103),
        demand_id=snapshot.demand_id,
        demand_version_id=snapshot.demand_version_id,
        matching_request_id=snapshot.matching_request_id,
        matching_rule_bundle_id=snapshot.matching_rule_bundle_id,
        selector_digest=snapshot.matching_selector_digest,
        source_authorization_digest=(
            MATCHING_OPERATIONAL_AUTHORITY_MARKER_SHA256
        ),
        status="LEASED",
        run_status="QUEUED",
        fencing_generation=1,
        lease_until=now + timedelta(minutes=1),
        attempt_count=1,
        run_attempt=1,
        recovery_status="CLAIMED",
        failure_code=None,
        replayed=False,
    )
    runtime = _WorkerRuntime(claim)
    tick = _worker_process(runtime, now=now).run_once()
    assert (tick.status, tick.worked) == ("MATCH_COMPLETED", True)
    assert len(runtime.start_requests) == 1
    assert len(runtime.complete_requests) == 1
    completed = runtime.complete_requests[0]
    assert completed.result.candidate_documents == ()
    assert all(
        value is not None
        for value in (
            completed.system_close_intent_id,
            completed.system_close_audit_event_id,
            completed.selection_close_intent_event_id,
            completed.attempt_close_event_id,
        )
    )
    start = runtime.start_requests[0]
    assert start.payload.candidate_count == 0
    assert start.payload.source_capture["profile"]["capture_contract_version"] == 2


def test_third_worker_run_failure_is_terminal_without_retry_identifiers() -> None:
    now = datetime.now(timezone.utc).replace(microsecond=0)
    snapshot = match_input_snapshot(captured_at=now)
    claim = MatchingWorkerJobClaim(
        organization_id=snapshot.organization_id,
        job_id=uid(201),
        attempt_id=uid(202),
        match_run_id=uid(203),
        demand_id=snapshot.demand_id,
        demand_version_id=snapshot.demand_version_id,
        matching_request_id=snapshot.matching_request_id,
        matching_rule_bundle_id=snapshot.matching_rule_bundle_id,
        selector_digest=snapshot.matching_selector_digest,
        source_authorization_digest=(
            MATCHING_OPERATIONAL_AUTHORITY_MARKER_SHA256
        ),
        status="LEASED",
        run_status="RUNNING",
        fencing_generation=7,
        lease_until=now + timedelta(minutes=1),
        attempt_count=1,
        run_attempt=3,
        recovery_status="RUNNING_LEASE_RETRY_LEASED",
        failure_code=None,
        replayed=False,
    )
    runtime = _WorkerRuntime(claim)
    process = _worker_process(runtime, now=now)
    tick = process._fail_started_run(
        claim=claim,
        lease_digest=b"l" * 32,
        failure_code="MATCH_ENGINE_REJECTED",
    )
    assert tick.status == "MATCH_REVIEW_REQUIRED"
    failed = runtime.fail_requests[0]
    assert failed.retry_run_id is None
    assert failed.retry_job_id is None
    assert failed.retry_available_at is None


def test_worker_rotates_claim_only_after_conclusive_lease_loss() -> None:
    now = datetime.now(timezone.utc).replace(microsecond=0)
    snapshot = match_input_snapshot(captured_at=now)
    claim = MatchingWorkerJobClaim(
        organization_id=snapshot.organization_id,
        job_id=uid(251),
        attempt_id=uid(252),
        match_run_id=uid(253),
        demand_id=snapshot.demand_id,
        demand_version_id=snapshot.demand_version_id,
        matching_request_id=snapshot.matching_request_id,
        matching_rule_bundle_id=snapshot.matching_rule_bundle_id,
        selector_digest=snapshot.matching_selector_digest,
        source_authorization_digest=MATCHING_OPERATIONAL_AUTHORITY_MARKER_SHA256,
        status="LEASED",
        run_status="QUEUED",
        fencing_generation=1,
        lease_until=now + timedelta(minutes=1),
        attempt_count=1,
        run_attempt=1,
        recovery_status="CLAIMED",
        failure_code=None,
        replayed=False,
    )
    runtime = _WorkerRuntime(claim)
    runtime.start_error = MatchingPostgresRejectedError("LEASE_LOST")
    process = _worker_process(runtime, now=now)

    first = process.run_once()
    second = process.run_once()

    assert (first.status, first.worked) == ("MATCH_LEASE_LOST", True)
    assert second.status == "MATCH_COMPLETED"
    assert len(runtime.claim_requests) == 2
    assert (
        runtime.claim_requests[0].material.identity_digest
        != runtime.claim_requests[1].material.identity_digest
    )


def test_coordinator_system_close_uses_immutable_original_actor_without_trust() -> None:
    now = datetime.now(timezone.utc).replace(microsecond=0)
    original_actor = uid(301)
    claim = MatchingSelectionCompletionClaim(
        completion_job_id=uid(302),
        organization_id=uid(303),
        selection_id=uid(304),
        attempt_id=uid(305),
        match_run_id=uid(306),
        intent_receipt_id=uid(307),
        intent_kind="SYSTEM_CLOSE",
        status="LEASED",
        fencing_generation=2,
        attempt_count=1,
        lease_until=now + timedelta(minutes=1),
        failure_code=None,
        original_actor_user_id=original_actor,
        demand_id=uid(308),
        prospective_demand_version=2,
        demand_version_id=uid(309),
        demand_content_sha256=b"d" * 32,
        replayed=False,
    )
    runtime = _CoordinatorRuntime(claim)
    identifiers = iter(uid(value) for value in range(900, 910))
    process = MatchingCoordinatorProcess(
        runtime=runtime,
        context=MatchingWorkloadContext(
            workload_id=uid(310),
            authority_marker_sha256=b"m" * 32,
        ),
        keys=key_ring("coordinator"),
        trust_evidence=None,
        clock=lambda: now,
        id_source=lambda: next(identifiers),
    )
    tick = process.run_once()
    assert (tick.status, tick.worked) == ("SELECTION_COMPLETED", True)
    completed = runtime.complete_requests[0]
    assert completed.claim.original_actor_user_id == original_actor
    assert completed.trust is None
    assert len(completed.material.outbox_event_ids) == 2


def test_coordinator_rotates_claim_after_lease_expires_after_trust() -> None:
    now = datetime.now(timezone.utc).replace(microsecond=0)
    claim = MatchingSelectionCompletionClaim(
        completion_job_id=uid(351),
        organization_id=uid(352),
        selection_id=uid(353),
        attempt_id=uid(354),
        match_run_id=uid(355),
        intent_receipt_id=uid(356),
        intent_kind="CHOOSE",
        status="LEASED",
        fencing_generation=2,
        attempt_count=1,
        lease_until=now + timedelta(minutes=1),
        failure_code=None,
        original_actor_user_id=uid(357),
        demand_id=uid(358),
        prospective_demand_version=2,
        demand_version_id=uid(359),
        demand_content_sha256=b"d" * 32,
        replayed=False,
    )
    runtime = _CoordinatorRuntime(claim)
    runtime.complete_error = MatchingPostgresRejectedError("LEASE_LOST")
    identifiers = iter(uid(value) for value in range(950, 970))
    process = MatchingCoordinatorProcess(
        runtime=runtime,
        context=MatchingWorkloadContext(
            workload_id=uid(360),
            authority_marker_sha256=b"m" * 32,
        ),
        keys=key_ring("coordinator"),
        trust_evidence=lambda _claim, evaluated_at: MatchingTrustEvidence(
            evidence_id=uid(361),
            evidence_sha256=b"t" * 32,
            evaluated_at=evaluated_at,
            valid_until=evaluated_at + timedelta(seconds=15),
        ),
        clock=lambda: now,
        id_source=lambda: next(identifiers),
    )

    first = process.run_once()
    second = process.run_once()

    assert (first.status, first.worked) == ("SELECTION_LEASE_LOST", True)
    assert second.status == "SELECTION_COMPLETED"
    assert runtime.complete_requests[0].trust is not None
    assert len(runtime.claim_requests) == 2
    assert (
        runtime.claim_requests[0].material.identity_digest
        != runtime.claim_requests[1].material.identity_digest
    )
