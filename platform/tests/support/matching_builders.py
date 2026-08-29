"""Independent secret-safe builders for Matching semantic RED tests."""

from __future__ import annotations

from contextlib import AbstractContextManager
from copy import deepcopy
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from decimal import Decimal
import hashlib
import hmac
import json
from typing import Any, Mapping, Optional

from desire_platform.matching.application import (
    ChooseCreatorCommand,
    CloseSelectionWithoutChoiceCommand,
    CompleteMatchRunCommand,
    CreateInvitationCommand,
    CreateMatchingAttemptCommand,
    MatchingActorContext,
    MatchingActorKind,
    MatchingRequestedSourceEvent,
    PublishInvitationCommand,
    RespondInvitationCommand,
    RetryMatchRunCommand,
    StartMatchRunCommand,
    WithdrawAcceptedInvitationCommand,
)
from desire_platform.matching.domain import (
    AttemptDemandBinding,
    CandidateEligibility,
    CandidateSelectorAssignment,
    CandidateSelectorAssignmentStatus,
    CandidateSelectorRoleCode,
    ComponentScore,
    EvidenceFact,
    Invitation,
    InvitationResponse,
    InvitationResponseKind,
    InvitationStatus,
    MatchCandidate,
    MatchRun,
    MatchRunStatus,
    MatchingAttempt,
    MatchingAttemptStatus,
    Selection,
    SelectionStatus,
    InvitationDisclosureSnapshot,
    MatchInputManifest,
    MatchRunInput,
    deterministic_rank_and_hash,
    match_input_set_sha256,
    selection_invitation_set_sha256,
)
from desire_platform.matching.ports import (
    CapturedMatchInputs,
    DemandMatchingFacts,
    MatchingCommitOutcomeUnknownError,
    MatchingCandidateSelectorAuthority,
    MatchingCreatorAuthority,
    MatchingHoldDecision,
    MatchingPrincipalAuthority,
    MatchingProfileFacts,
    MatchingReviewerAuthority,
    MatchingSafetyHoldResult,
    MatchingSafeResponseInvalidError,
    MatchingStorageUnavailableError,
    MatchingSystemAuthority,
)


NOW = datetime(2035, 1, 1, tzinfo=timezone.utc)
SHA = "a" * 64
SHA_B = "b" * 64


def disclosure_bytes(
    invitation_id: str = "business_invitation_0001",
    expires_at: datetime = NOW + timedelta(days=7),
) -> bytes:
    value = {
        "schema_version": 1,
        "canonicalization_version": "invitation-disclosure-json-v1",
        "invitation_id": invitation_id,
        "attempt_id": "matching_attempt_0000001",
        "demand_id": "demand_object_000000001",
        "demand_version_id": "demand_version_00000001",
        "profile_id": "creator_profile_0000001",
        "profile_version_id": "profile_version_0000001",
        "organization_preview": {
            "organization_id": "organization_0000000001",
            "display_label": "Community Energy Lab",
        },
        "opportunity": {
            "title": "Energy analysis",
            "problem_summary": "Reduce energy waste.",
            "deliverable_summaries": ["Validated plan."],
            "acceptance_summaries": ["Measurable baseline."],
        },
        "offer": {
            "currency": "CNY",
            "minimum_amount_minor": 100000,
            "maximum_amount_minor": 200000,
            "schedule_code": "SCHEDULE.FLEXIBLE",
            "duration_weeks": 6,
        },
        "constraints": {
            "region_codes": ["REGION.CN"],
            "language_codes": ["LANGUAGE.ZH"],
            "data_sensitivity_code": "INTERNAL",
            "ai_use_code": "OPTIONAL",
        },
        "expires_at": expires_at.isoformat().replace("+00:00", "Z"),
        "demand_content_sha256": SHA,
        "profile_content_sha256": SHA,
    }
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


DISCLOSURE_BYTES = disclosure_bytes()
DISCLOSURE_SHA = hashlib.sha256(DISCLOSURE_BYTES).hexdigest()

MATCHING_CHECKPOINTS = (
    "receipt_claim", "root_lock", "candidate_or_response", "snapshot",
    "invitation", "selection", "attempt", "source_inbox", "audit",
    "outbox_events", "safe_response", "receipt_complete", "commit",
)


def attempt(**changes: object) -> MatchingAttempt:
    value = MatchingAttempt(
        attempt_id="matching_attempt_0000001",
        organization_id="organization_0000000001",
        demand_id="demand_object_000000001",
        demand_version_id="demand_version_00000001",
        matching_request_id="matching_request_000001",
        funding_id="funding_object_00000001",
        attempt_no=1,
        status=MatchingAttemptStatus.OPEN,
        aggregate_version=1,
        current_match_run_id="matching_run_0000000001",
        selection_id=None,
        input_baseline_sha256=SHA,
        created_at=NOW,
        updated_at=NOW,
    )
    return replace(value, **changes)


def run(**changes: object) -> MatchRun:
    value = MatchRun(
        run_id="matching_run_0000000001",
        attempt_id="matching_attempt_0000001",
        run_no=1,
        status=MatchRunStatus.QUEUED,
        aggregate_version=1,
        matching_rule_bundle_id="matching_bundle_00000001",
        input_manifest=None,
        input_set_sha256=None,
        ordered_result_sha256=None,
        candidate_count=None,
        eligible_count=None,
        excluded_count=None,
        worker_id=None,
        lease_token=None,
        fencing_generation=0,
        lease_until=None,
        supersedes_run_id=None,
        superseded_by_run_id=None,
        failure_code=None,
        created_at=NOW,
        updated_at=NOW,
    )
    return replace(value, **changes)


def candidate(*, creator_user_id: str = "creator_user_000000001", score: str = "80.00", eligible: bool = True, **changes: object) -> MatchCandidate:
    components = tuple(
        ComponentScore(code=code, ordinal=index, score=Decimal(score))
        for index, code in enumerate(("interest", "capability", "availability", "compensation", "collaboration", "evidence_trust"), 1)
    )
    value = MatchCandidate(
        attempt_id="matching_attempt_0000001",
        run_id="matching_run_0000000001",
        creator_user_id=creator_user_id,
        profile_id="creator_profile_0000001",
        profile_version_id="profile_version_0000001",
        profile_content_sha256=SHA,
        eligibility=CandidateEligibility.ELIGIBLE if eligible else CandidateEligibility.EXCLUDED,
        exclusion_reason_codes=() if eligible else ("BELOW_PRIVATE_FLOOR",),
        components=components if eligible else (),
        total_score=Decimal(score) if eligible else None,
        rank=1 if eligible else None,
        evidence_facts=(EvidenceFact(code="WITHIN_BUDGET", kind="BOOLEAN", value=eligible, source_version_digest=SHA_B),),
        candidate_result_sha256=SHA_B,
    )
    return replace(value, **changes)


def invitation(**changes: object) -> Invitation:
    value = Invitation(
        invitation_id="business_invitation_0001",
        attempt_id="matching_attempt_0000001",
        match_run_id="matching_run_0000000001",
        creator_user_id="creator_user_000000001",
        profile_id="creator_profile_0000001",
        profile_version_id="profile_version_0000001",
        profile_content_sha256=SHA,
        demand_id="demand_object_000000001",
        demand_version_id="demand_version_00000001",
        funding_id="funding_object_00000001",
        matching_rule_bundle_id="matching_bundle_00000001",
        disclosure_snapshot_id="disclosure_snapshot_00001",
        snapshot_sha256=SHA_B,
        status=InvitationStatus.SENT,
        aggregate_version=2,
        expires_at=NOW + timedelta(days=7),
        created_at=NOW,
        sent_at=NOW,
        responded_at=None,
        updated_at=NOW,
    )
    return replace(value, **changes)


def selection(**changes: object) -> Selection:
    value = Selection(
        selection_id="matching_selection_00001",
        attempt_id="matching_attempt_0000001",
        status=SelectionStatus.OPEN,
        aggregate_version=1,
        current_invitation_set_sha256=SHA,
        chosen_invitation_id=None,
        selection_basis_code=None,
        reason_code=None,
        decision_actor_id=None,
        created_at=NOW,
        updated_at=NOW,
    )
    return replace(value, **changes)


def actor(*, kind: MatchingActorKind = MatchingActorKind.SYSTEM) -> MatchingActorContext:
    return MatchingActorContext(
        actor_kind=kind,
        actor_id="system_actor_0000000001" if kind is MatchingActorKind.SYSTEM else "actor_user_00000000001",
        session_id=None if kind is MatchingActorKind.SYSTEM else "session_secret_0000001",
        organization_id="organization_0000000001",
        correlation_id="correlation_00000000001",
        causation_id="causation_000000000001",
        trace_id="trace_identifier_0000001",
        original_actor_id=None,
        workload_credential_id="workload_secret_000001" if kind is MatchingActorKind.SYSTEM else None,
    )


def creator_actor() -> MatchingActorContext:
    return replace(
        actor(kind=MatchingActorKind.USER),
        actor_id="creator_user_000000001",
    )


def source_event() -> MatchingRequestedSourceEvent:
    return MatchingRequestedSourceEvent(
        event_id="source_event_0000000001", event_type="MatchingRequested",
        schema_version=1, aggregate_type="Demand", aggregate_id="demand_object_000000001",
        aggregate_version=7, organization_id="organization_0000000001",
        demand_id="demand_object_000000001", demand_version_id="demand_version_00000001",
        funding_id="funding_object_00000001", matching_request_id="matching_request_000001",
        composite_rule_requirement_id="rule_requirement_000001", occurred_at=NOW,
    )


def command_for(handler_type: type) -> object:
    name = handler_type.__name__
    if name == "CreateMatchingAttemptHandler":
        return CreateMatchingAttemptCommand(source_event())
    if name == "StartMatchRunHandler":
        return StartMatchRunCommand("matching_run_0000000001", "worker_00000000000001", "lease_secret_000001", 1)
    if name == "CompleteMatchRunHandler":
        return CompleteMatchRunCommand("matching_run_0000000001", "worker_00000000000001", "lease_secret_000001", 1, SHA, (candidate(),))
    if name == "RetryMatchRunHandler":
        return RetryMatchRunCommand("matching_attempt_0000001", "matching_run_0000000001", 2, SHA, "assignment_0000000001", "raw-key-retry-0001")
    if name == "CreateInvitationHandler":
        return CreateInvitationCommand("matching_run_0000000001", "creator_user_000000001", NOW + timedelta(days=7), 3, "assignment_0000000001", "raw-key-invite-0001")
    if name == "PublishInvitationHandler":
        return PublishInvitationCommand("business_invitation_0001", DISCLOSURE_SHA, 1, "assignment_0000000001", "raw-key-publish-001")
    if name == "RespondInvitationHandler":
        return RespondInvitationCommand("business_invitation_0001", DISCLOSURE_SHA, 2, True, None, None, "raw-key-response-01")
    if name == "ChooseCreatorHandler":
        accepted_invitation = replace(
            invitation(snapshot_sha256=DISCLOSURE_SHA),
            status=InvitationStatus.ACCEPTED,
            aggregate_version=3,
            responded_at=NOW,
        )
        current_set_sha256 = selection_invitation_set_sha256(
            attempt_id=accepted_invitation.attempt_id,
            run_id=accepted_invitation.match_run_id,
            invitations=(accepted_invitation,),
        )
        return ChooseCreatorCommand(
            "matching_selection_00001",
            "business_invitation_0001",
            "ALGORITHM_TOP",
            current_set_sha256,
            1,
            "selector_assignment_00001",
            1,
            "raw-key-choose-0001",
        )
    if name == "CloseSelectionWithoutChoiceHandler":
        terminal_invitation = replace(
            invitation(snapshot_sha256=DISCLOSURE_SHA),
            status=InvitationStatus.DECLINED,
            aggregate_version=3,
            responded_at=NOW,
        )
        current_set_sha256 = selection_invitation_set_sha256(
            attempt_id=terminal_invitation.attempt_id,
            run_id=terminal_invitation.match_run_id,
            invitations=(terminal_invitation,),
        )
        return CloseSelectionWithoutChoiceCommand(
            "matching_selection_00001",
            "NO_MUTUAL_FIT",
            current_set_sha256,
            1,
            "selector_assignment_00001",
            1,
            "raw-key-close-00001",
        )
    if name == "WithdrawAcceptedInvitationHandler":
        return WithdrawAcceptedInvitationCommand(
            "business_invitation_0001",
            DISCLOSURE_SHA,
            3,
            "CREATOR_UNAVAILABLE",
            "private withdrawal explanation",
            "raw-key-withdraw-001",
        )
    raise AssertionError(name)


class FixedClock:
    def now(self) -> datetime:
        return NOW


class DeterministicKeyring:
    identity_key_id = "matching-receipt-identity-v1"
    payload_hash_key_id = "matching-receipt-payload-v1"

    def __init__(self) -> None:
        self.calls: list[tuple[str, bytes]] = []

    def keyed_digest(self, key_id: str, value: bytes) -> str:
        self.calls.append((key_id, bytes(value)))
        return hmac.new(
            f"test-only:{key_id}".encode(), value, hashlib.sha256
        ).hexdigest()


class IdSource:
    def __init__(self) -> None:
        self.counters: dict[str, int] = {}

    def peek_id(self, kind: str) -> str:
        number = self.counters.get(kind, 0) + 1
        return f"matching_{kind}_{number:08d}"

    def next_id(self, kind: str) -> str:
        value = self.peek_id(kind)
        self.counters[kind] = self.counters.get(kind, 0) + 1
        return value


class RecordingValidator:
    def __init__(self) -> None:
        self.calls: list[Any] = []

    def validate(self, *args: Any, **kwargs: Any) -> None:
        value = args[0] if args else kwargs
        self.calls.append(deepcopy(value))
        serialized = repr(value).lower()
        for secret in (
            "raw-key", "lease_secret", "session_secret", "workload_secret",
            "private_floor_amount", "no longer available",
        ):
            if secret in serialized:
                raise AssertionError(f"private sentinel escaped: {secret}")


class MatchingEventValidator(RecordingValidator):
    def validate(self, event: Any) -> None:
        super().validate(event)
        from pathlib import Path
        from tests.contract.test_demand_contracts import _load, _validate

        path = (
            Path(__file__).resolve().parents[2]
            / "contracts/events/matching-v1.schema.json"
        )
        document = _load(path)
        _validate(document, path, document, event)


class MatchingSafeResponseValidator(RecordingValidator):
    def validate(self, *, operation: str, response: Any) -> None:
        try:
            super().validate(operation=operation, response=response)
        except AssertionError as error:
            raise MatchingSafeResponseInvalidError(str(error)) from error
        if not isinstance(response, Mapping) or set(response) != {
            "schema_version",
            "response_schema",
            "http_status",
            "etag",
            "body",
        }:
            raise MatchingSafeResponseInvalidError(
                "matching safe response is not closed"
            )
        body = response.get("body")
        if (
            response.get("schema_version") != 1
            or response.get("response_schema") != "MatchingCommandResult"
            or response.get("http_status")
            != (201 if operation == "CREATE_INVITATION" else 200)
            or not isinstance(response.get("etag"), str)
            or not isinstance(body, Mapping)
            or set(body)
            != {
                "target_id",
                "target_status",
                "aggregate_version",
                "updated_at",
                "event_types",
            }
            or not isinstance(body["target_id"], str)
            or not isinstance(body["target_status"], str)
            or not isinstance(body["aggregate_version"], int)
            or isinstance(body["aggregate_version"], bool)
            or body["aggregate_version"] < 1
            or response["etag"] != f'"v{body["aggregate_version"]}"'
            or not isinstance(body["updated_at"], str)
            or not isinstance(body["event_types"], list)
            or not all(isinstance(value, str) for value in body["event_types"])
        ):
            raise MatchingSafeResponseInvalidError(
                "matching safe response has invalid primitive shape"
            )


class SourceEventValidator(RecordingValidator):
    pass


class SystemAuthorityPort:
    def authorize(self, **query: Any) -> MatchingSystemAuthority:
        actor = query["actor"]
        return MatchingSystemAuthority(
            workload_principal_id=actor.actor_id,
            workload_credential_id=actor.workload_credential_id or "missing",
            operation=query["operation"],
            organization_id=actor.organization_id,
            attempt_id=query["attempt_id"],
            match_run_id=query["match_run_id"],
            source_event_id=query["source_event_id"],
            job_id=(
                f"job:{query['match_run_id']}"
                if query["match_run_id"] is not None
                else f"source:{query['source_event_id']}"
            ),
            valid_until=NOW + timedelta(minutes=5),
            authority_marker_sha256="1" * 64,
        )


class PrincipalAuthorityPort:
    def __init__(self) -> None:
        self.calls: list[MatchingActorContext] = []
        self.user_status = "ACTIVE"
        self.session_status = "ACTIVE"
        self.session_family_status = "ACTIVE"
        self.workload_credential_status = "ACTIVE"

    def authenticate(
        self, *, actor: MatchingActorContext
    ) -> MatchingPrincipalAuthority:
        self.calls.append(deepcopy(actor))
        return MatchingPrincipalAuthority(
            actor_kind=actor.actor_kind,
            actor_id=actor.actor_id,
            session_id=actor.session_id,
            user_status=(
                self.user_status
                if actor.actor_kind is MatchingActorKind.USER
                else None
            ),
            session_status=(
                self.session_status
                if actor.actor_kind is MatchingActorKind.USER
                else None
            ),
            session_family_status=(
                self.session_family_status
                if actor.actor_kind is MatchingActorKind.USER
                else None
            ),
            workload_credential_id=actor.workload_credential_id,
            workload_credential_status=(
                self.workload_credential_status
                if actor.actor_kind is MatchingActorKind.SYSTEM
                else None
            ),
            valid_until=NOW + timedelta(minutes=5),
            principal_marker_sha256="0" * 64,
        )


class ReviewerAuthorityPort:
    def __init__(self, *, attempt_id: str = "matching_attempt_0000001", run_id: Optional[str] = "matching_run_0000000001") -> None:
        self.attempt_id = attempt_id
        self.run_id = run_id
        self.calls: list[dict[str, Any]] = []

    def authorize(self, **query: Any) -> MatchingReviewerAuthority:
        self.calls.append(deepcopy(query))
        actor = query["actor"]
        return MatchingReviewerAuthority(
            actor_user_id=actor.actor_id,
            session_id=actor.session_id or "missing",
            organization_id=actor.organization_id,
            assignment_id=query["assignment_id"],
            assignment_status="ACTIVE",
            assignment_version=1,
            assignment_expires_at=NOW + timedelta(minutes=5),
            assignment_attempt_id=self.attempt_id,
            assignment_run_id=self.run_id,
            assignment_purpose="INVITATION_REVIEW",
            duty_grant_id="matching_duty_grant_0001",
            duty_grant_version=1,
            duty_code="OPERATIONS_REVIEWER",
            conflict_attestation_sha256="2" * 64,
            authority_marker_sha256="3" * 64,
        )


class CreatorAuthorityPort:
    def authorize(self, **query: Any) -> MatchingCreatorAuthority:
        actor = query["actor"]
        return MatchingCreatorAuthority(
            actor_user_id=actor.actor_id,
            session_id=actor.session_id or "missing",
            user_status="ACTIVE",
            session_status="ACTIVE",
            session_family_status="ACTIVE",
            creator_grant_id="creator_grant_000000001",
            creator_grant_version=1,
            creator_grant_status="ACTIVE",
            invitation_id=query["invitation_id"],
            profile_id="creator_profile_0000001",
            profile_version_id="profile_version_0000001",
            authority_marker_sha256="4" * 64,
        )


class CandidateSelectorAuthorityPort:
    def __init__(self) -> None:
        selector = actor(kind=MatchingActorKind.USER)
        self.calls: list[dict[str, Any]] = []
        self.result = MatchingCandidateSelectorAuthority(
            actor_user_id=selector.actor_id,
            session_id=selector.session_id or "missing",
            assignment=CandidateSelectorAssignment(
                assignment_id="selector_assignment_00001",
                aggregate_version=1,
                status=CandidateSelectorAssignmentStatus.ACTIVE,
                role_code=CandidateSelectorRoleCode.CANDIDATE_SELECTOR,
                assigned_user_id=selector.actor_id,
                organization_id=selector.organization_id,
                demand_id="demand_object_000000001",
                selection_id="matching_selection_00001",
                assigned_at=NOW - timedelta(minutes=5),
                expires_at=NOW + timedelta(minutes=5),
            ),
            authority_marker_sha256="5" * 64,
        )

    def authorize(self, **query: Any) -> MatchingCandidateSelectorAuthority:
        self.calls.append(deepcopy(query))
        return self.result


class DemandFactsPort:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []
        self.demand_aggregate_version = 7

    def read_exact(self, **query: Any) -> DemandMatchingFacts:
        self.calls.append(deepcopy(query))
        return DemandMatchingFacts(
            organization_id=query["organization_id"],
            demand_id=query["demand_id"],
            demand_aggregate_version=self.demand_aggregate_version,
            demand_version_id=query["demand_version_id"],
            demand_content_sha256=SHA,
            funding_id=query["funding_id"],
            funding_status="SECURED",
            matching_request_id=query["matching_request_id"],
            matching_request_version=7,
            matching_request_status="OPEN",
            composite_rule_requirement_id="rule_requirement_000001",
            selector_digest=SHA,
            matching_rule_bundle_id="matching_bundle_00000001",
            discovery_facts=(("domain_code", "DOMAIN.ENERGY"),),
        )


class CaptureInputsPort:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def capture(self, **query: Any) -> CapturedMatchInputs:
        self.calls.append(deepcopy(query))
        manifest = MatchInputManifest(
            attempt_id="matching_attempt_0000001",
            run_id=query["run_id"],
            organization_id="organization_0000000001",
            demand_id="demand_object_000000001",
            demand_version_id="demand_version_00000001",
            demand_content_sha256=SHA,
            funding_id="funding_object_00000001",
            matching_request_id="matching_request_000001",
            matching_request_version=7,
            matching_rule_bundle_id="matching_bundle_00000001",
            selector_digest=SHA,
            rule_manifest_sha256=SHA_B,
            ordered_candidate_identities=(),
            captured_at=NOW,
            candidate_count=0,
            input_set_sha256=SHA,
        )
        run_input = MatchRunInput(
            attempt_id=manifest.attempt_id,
            run_id=manifest.run_id,
            demand_id=manifest.demand_id,
            demand_version_id=manifest.demand_version_id,
            matching_rule_bundle_id=manifest.matching_rule_bundle_id,
            input_set_sha256=manifest.input_set_sha256,
            demand_facts=(("domain_code", "DOMAIN.ENERGY"),),
            profile_facts=(),
        )
        input_set_sha256 = match_input_set_sha256(
            manifest=manifest,
            run_input=run_input,
        )
        manifest = replace(manifest, input_set_sha256=input_set_sha256)
        run_input = replace(run_input, input_set_sha256=input_set_sha256)
        return CapturedMatchInputs(
            manifest=manifest,
            run_input=run_input,
            candidate_allowlist_sha256=SHA_B,
            captured_at=NOW,
        )


class ProfileFactsPort:
    def read_exact(self, **query: Any) -> MatchingProfileFacts:
        return MatchingProfileFacts(
            creator_user_id=query["creator_user_id"],
            user_status="ACTIVE",
            creator_grant_status="ACTIVE",
            profile_id=query["profile_id"],
            profile_status="ACTIVE",
            current_profile_version_id=query["profile_version_id"],
            current_profile_content_sha256=SHA,
            current_evidence_version_digest=SHA_B,
        )


class SafetyHoldPort:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []
        self.overrides: dict[str, Any] = {}

    def evaluate(self, **binding: Any) -> MatchingSafetyHoldResult:
        self.calls.append(deepcopy(binding))
        values = dict(binding)
        values.update(self.overrides)
        return MatchingSafetyHoldResult(
            decision=values.pop("decision", MatchingHoldDecision.ALLOW),
            evaluated_at=NOW - timedelta(seconds=1),
            valid_until=NOW + timedelta(minutes=5),
            **values,
        )


class DisclosureBuilder:
    def build(self, **facts: Any) -> InvitationDisclosureSnapshot:
        invitation_id = facts["invitation_id"]
        attempt_value = facts["attempt"]
        candidate_value = facts["candidate"]
        canonical_bytes = disclosure_bytes(invitation_id, facts["expires_at"])
        return InvitationDisclosureSnapshot(
            snapshot_id="disclosure_snapshot_new1",
            invitation_id=invitation_id,
            attempt_id=attempt_value.attempt_id,
            demand_id=attempt_value.demand_id,
            demand_version_id=attempt_value.demand_version_id,
            profile_id=candidate_value.profile_id,
            profile_version_id=candidate_value.profile_version_id,
            demand_content_sha256=SHA,
            profile_content_sha256=candidate_value.profile_content_sha256,
            snapshot_sha256=hashlib.sha256(canonical_bytes).hexdigest(),
            canonical_bytes=canonical_bytes,
        )


class SnapshotStore:
    def __init__(self, seed: Optional[Mapping[str, Mapping[str, Any]]] = None) -> None:
        self.data: dict[str, dict[str, Any]] = deepcopy(seed or {})

    def snapshot(self) -> dict[str, dict[str, Any]]:
        return deepcopy(self.data)


class MemoryUnitOfWork(AbstractContextManager["MemoryUnitOfWork"]):
    def __init__(self, factory: "MemoryUnitOfWorkFactory") -> None:
        self.factory = factory
        self.working = deepcopy(factory.store.data)
        self.calls: list[Any] = []

    def __enter__(self) -> "MemoryUnitOfWork":
        self.factory.instances.append(self)
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        return None

    def checkpoint(self, name: str) -> None:
        self.calls.append(("checkpoint", (name,), {}))
        if self.factory.fail_checkpoint == name:
            raise MatchingStorageUnavailableError(name)

    def lock(self, resource: str, keys: Any) -> None:
        self.calls.append(("lock", (resource, tuple(keys)), {}))
        for collection, key, replacement in self.factory.locked_replacements:
            self.working.setdefault(collection, {})[key] = deepcopy(replacement)

    def get(self, collection: str, key: str) -> Any:
        return deepcopy(self.working.get(collection, {}).get(key))

    def values(self, collection: str) -> tuple[Any, ...]:
        return tuple(deepcopy(tuple(self.working.get(collection, {}).values())))

    def put(self, collection: str, key: str, value: Any) -> None:
        self.working.setdefault(collection, {})[key] = deepcopy(value)

    def commit(self) -> None:
        if self.factory.commit_unknown:
            if self.factory.commit_unknown_durable:
                self.factory.store.data = deepcopy(self.working)
            raise MatchingCommitOutcomeUnknownError("matching commit ack lost")
        self.factory.store.data = deepcopy(self.working)


class MemoryUnitOfWorkFactory:
    def __init__(self, seed: Optional[Mapping[str, Mapping[str, Any]]] = None) -> None:
        self.store = SnapshotStore(seed)
        self.instances: list[MemoryUnitOfWork] = []
        self.fail_checkpoint: Optional[str] = None
        self.commit_unknown = False
        self.commit_unknown_durable = False
        self.locked_replacements: list[tuple[str, str, Any]] = []

    @property
    def calls(self) -> list[Any]:
        return self.instances[-1].calls if self.instances else []

    def begin(self) -> MemoryUnitOfWork:
        return MemoryUnitOfWork(self)

    def replace_after_lock(
        self, collection: str, key: str, replacement: Any
    ) -> None:
        self.locked_replacements.append((collection, key, deepcopy(replacement)))


class RecoveryReader:
    def __init__(self, factory: MemoryUnitOfWorkFactory) -> None:
        self.factory = factory

    def read_receipt(self, identity: str) -> Any:
        return deepcopy(self.factory.store.data.get("receipts", {}).get(identity))

    def read_target(self, target_id: str) -> Any:
        for collection in ("attempts", "runs", "invitations", "selections"):
            value = self.factory.store.data.get(collection, {}).get(target_id)
            if value is not None:
                return deepcopy(value)
        return None

    def read_fact(self, collection: str, identifier: str) -> Any:
        return deepcopy(
            self.factory.store.data.get(collection, {}).get(identifier)
        )


def _snapshot() -> InvitationDisclosureSnapshot:
    return InvitationDisclosureSnapshot(
        snapshot_id="disclosure_snapshot_00001",
        invitation_id="business_invitation_0001",
        attempt_id="matching_attempt_0000001",
        demand_id="demand_object_000000001",
        demand_version_id="demand_version_00000001",
        profile_id="creator_profile_0000001",
        profile_version_id="profile_version_0000001",
        demand_content_sha256=SHA,
        profile_content_sha256=SHA,
        snapshot_sha256=DISCLOSURE_SHA,
        canonical_bytes=DISCLOSURE_BYTES,
    )


def seed_for(handler_type: type, command: Any) -> dict[str, dict[str, Any]]:
    name = handler_type.__name__
    base_attempt = attempt()
    if name == "CreateMatchingAttemptHandler":
        return {}
    if name == "StartMatchRunHandler":
        return {"attempts": {base_attempt.attempt_id: base_attempt}, "runs": {run().run_id: run()}}
    if name == "CompleteMatchRunHandler":
        running = run(
            status=MatchRunStatus.RUNNING,
            aggregate_version=2,
            input_set_sha256=SHA,
            worker_id=command.worker_id,
            lease_token=command.lease_token,
            fencing_generation=command.fencing_generation,
            lease_until=NOW + timedelta(minutes=5),
        )
        return {"attempts": {base_attempt.attempt_id: base_attempt}, "runs": {running.run_id: running}}
    if name == "RetryMatchRunHandler":
        failed = run(status=MatchRunStatus.FAILED, aggregate_version=2, failure_code="ENGINE_FAILURE")
        retriable = attempt(aggregate_version=2)
        return {"attempts": {retriable.attempt_id: retriable}, "runs": {failed.run_id: failed}}
    completed = run(status=MatchRunStatus.COMPLETED, aggregate_version=3, input_set_sha256=SHA, ordered_result_sha256=SHA_B, candidate_count=1, eligible_count=1, excluded_count=0)
    base_candidate = candidate()
    common: dict[str, dict[str, Any]] = {
        "attempts": {base_attempt.attempt_id: base_attempt},
        "runs": {completed.run_id: completed},
        "candidates": {f"{completed.run_id}:{base_candidate.creator_user_id}": base_candidate},
    }
    if name == "CreateInvitationHandler":
        return common
    seeded_invitation = invitation(snapshot_sha256=DISCLOSURE_SHA)
    common["invitations"] = {seeded_invitation.invitation_id: seeded_invitation}
    common["snapshots"] = {_snapshot().snapshot_id: _snapshot()}
    if name == "PublishInvitationHandler":
        common["invitations"] = {seeded_invitation.invitation_id: replace(seeded_invitation, status=InvitationStatus.CREATED, aggregate_version=1, sent_at=None)}
        return common
    open_selection = selection()
    common["selections"] = {open_selection.selection_id: open_selection}
    common["attempts"] = {base_attempt.attempt_id: replace(base_attempt, selection_id=open_selection.selection_id)}
    if name == "RespondInvitationHandler":
        return common
    if name == "WithdrawAcceptedInvitationHandler":
        accepted_invitation = replace(
            seeded_invitation,
            status=InvitationStatus.ACCEPTED,
            aggregate_version=3,
            responded_at=NOW,
        )
        accepted_response = InvitationResponse(
            response_id="response_object_0000001",
            invitation_id=accepted_invitation.invitation_id,
            creator_user_id=accepted_invitation.creator_user_id,
            response_kind=InvitationResponseKind.ACCEPTED,
            snapshot_sha256=accepted_invitation.snapshot_sha256,
            reason_code=None,
            restricted_note=None,
            responded_at=NOW,
        )
        current_set_sha256 = selection_invitation_set_sha256(
            attempt_id=base_attempt.attempt_id,
            run_id=completed.run_id,
            invitations=(accepted_invitation,),
        )
        common["invitations"] = {
            accepted_invitation.invitation_id: accepted_invitation
        }
        common["responses"] = {
            accepted_response.response_id: accepted_response
        }
        common["selections"] = {
            open_selection.selection_id: replace(
                open_selection,
                current_invitation_set_sha256=current_set_sha256,
            )
        }
        return common
    if name in {"ChooseCreatorHandler", "CloseSelectionWithoutChoiceHandler"}:
        if name == "CloseSelectionWithoutChoiceHandler":
            terminal_invitation = replace(
                seeded_invitation,
                status=InvitationStatus.DECLINED,
                aggregate_version=3,
                responded_at=NOW,
            )
            current_set_sha256 = selection_invitation_set_sha256(
                attempt_id=base_attempt.attempt_id,
                run_id=completed.run_id,
                invitations=(terminal_invitation,),
            )
            common["invitations"] = {
                terminal_invitation.invitation_id: terminal_invitation
            }
            common["selections"] = {
                open_selection.selection_id: replace(
                    open_selection,
                    current_invitation_set_sha256=current_set_sha256,
                )
            }
            return common
        profile_input = (
            ("creator_user_id", base_candidate.creator_user_id),
            ("profile_id", base_candidate.profile_id),
            ("profile_version_id", base_candidate.profile_version_id),
            ("profile_content_sha256", base_candidate.profile_content_sha256),
            ("evidence_version_digest", SHA_B),
        )
        manifest = MatchInputManifest(
            attempt_id=base_attempt.attempt_id,
            run_id=completed.run_id,
            organization_id=base_attempt.organization_id,
            demand_id=base_attempt.demand_id,
            demand_version_id=base_attempt.demand_version_id,
            demand_content_sha256=SHA,
            funding_id=base_attempt.funding_id,
            matching_request_id=base_attempt.matching_request_id,
            matching_request_version=7,
            matching_rule_bundle_id=completed.matching_rule_bundle_id,
            selector_digest=SHA,
            rule_manifest_sha256=SHA_B,
            ordered_candidate_identities=(
                (
                    base_candidate.creator_user_id,
                    base_candidate.profile_id,
                    base_candidate.profile_version_id,
                    base_candidate.profile_content_sha256,
                    SHA_B,
                ),
            ),
            captured_at=NOW,
            candidate_count=1,
            input_set_sha256=SHA,
        )
        run_input = MatchRunInput(
            attempt_id=base_attempt.attempt_id,
            run_id=completed.run_id,
            demand_id=base_attempt.demand_id,
            demand_version_id=base_attempt.demand_version_id,
            matching_rule_bundle_id=completed.matching_rule_bundle_id,
            input_set_sha256=SHA,
            demand_facts=(("domain_code", "DOMAIN.ENERGY"),),
            profile_facts=(profile_input,),
        )
        input_set_sha256 = match_input_set_sha256(
            manifest=manifest,
            run_input=run_input,
        )
        manifest = replace(manifest, input_set_sha256=input_set_sha256)
        normalized_candidates, ordered_result_sha256 = deterministic_rank_and_hash(
            candidates=(base_candidate,),
            matching_rule_bundle_id=completed.matching_rule_bundle_id,
            input_set_sha256=input_set_sha256,
        )
        chosen_candidate = normalized_candidates[0]
        completed = replace(
            completed,
            input_manifest=manifest,
            input_set_sha256=input_set_sha256,
            ordered_result_sha256=ordered_result_sha256,
        )
        common["runs"] = {completed.run_id: completed}
        common["candidates"] = {
            f"{completed.run_id}:{chosen_candidate.creator_user_id}": chosen_candidate
        }
        common["attempt_bindings"] = {
            base_attempt.attempt_id: AttemptDemandBinding(
                attempt_id=base_attempt.attempt_id,
                source_event_id="source_event_0000000001",
                organization_id=base_attempt.organization_id,
                demand_id=base_attempt.demand_id,
                demand_aggregate_version=7,
                demand_version_id=base_attempt.demand_version_id,
                funding_id=base_attempt.funding_id,
                matching_request_id=base_attempt.matching_request_id,
                matching_request_version=7,
                composite_rule_requirement_id="rule_requirement_000001",
                matching_rule_bundle_id=completed.matching_rule_bundle_id,
                selector_digest=SHA,
                created_at=NOW,
            )
        }
        accepted_invitation = replace(
            seeded_invitation,
            status=InvitationStatus.ACCEPTED,
            aggregate_version=3,
            responded_at=NOW,
        )
        current_set_sha256 = selection_invitation_set_sha256(
            attempt_id=base_attempt.attempt_id,
            run_id=completed.run_id,
            invitations=(accepted_invitation,),
        )
        common["invitations"] = {
            accepted_invitation.invitation_id: accepted_invitation
        }
        common["selections"] = {
            open_selection.selection_id: replace(
                open_selection,
                current_invitation_set_sha256=current_set_sha256,
            )
        }
        return common
    raise AssertionError(name)


@dataclass
class MatchingHarness:
    dependencies: dict[str, Any]
    uow_factory: MemoryUnitOfWorkFactory
    source_event_validator: SourceEventValidator
    capture_match_inputs: CaptureInputsPort
    reviewer_authority: ReviewerAuthorityPort
    safety_hold: SafetyHoldPort
    principal_authority: PrincipalAuthorityPort


def build_application_harness(handler_type: type, command: Any) -> MatchingHarness:
    factory = MemoryUnitOfWorkFactory(seed_for(handler_type, command))
    source_validator = SourceEventValidator()
    capture = CaptureInputsPort()
    reviewer = ReviewerAuthorityPort()
    hold = SafetyHoldPort()
    principal = PrincipalAuthorityPort()
    dependencies = {
        "clock": FixedClock(),
        "principal_authority": principal,
        "system_authority": SystemAuthorityPort(),
        "reviewer_authority": reviewer,
        "creator_authority": CreatorAuthorityPort(),
        "candidate_selector_authority": CandidateSelectorAuthorityPort(),
        "source_event_validator": source_validator,
        "demand_facts": DemandFactsPort(),
        "capture_match_inputs": capture,
        "profile_facts": ProfileFactsPort(),
        "safety_hold": hold,
        "disclosure_builder": DisclosureBuilder(),
        "uow_factory": factory,
        "recovery_reader": RecoveryReader(factory),
        "id_source": IdSource(),
        "receipt_keyring": DeterministicKeyring(),
        "event_validator": MatchingEventValidator(),
        "safe_response_validator": MatchingSafeResponseValidator(),
    }
    return MatchingHarness(
        dependencies=dependencies,
        uow_factory=factory,
        source_event_validator=source_validator,
        capture_match_inputs=capture,
        reviewer_authority=reviewer,
        safety_hold=hold,
        principal_authority=principal,
    )
