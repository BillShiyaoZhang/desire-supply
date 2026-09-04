"""Closed-surface tests for the production Matching PostgreSQL HTTP bridge."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
from types import SimpleNamespace
from uuid import UUID

import pytest

from desire_platform.internal_pilot.runtime_adapters import SecureRuntimeSources
from desire_platform.internal_pilot.matching_postgres import (
    MATCHING_POSTGRES_OPERATIONAL_SUPPORT,
    MatchingPostgresActorContext,
    MatchingPostgresHttpKeys,
    MatchingPostgresOperationalHttpService,
    PostgresCreateMatchingInvitationHandler,
    PostgresChooseCreatorHandler,
    PostgresInvalidateMatchingAttemptHandler,
    PostgresPublishMatchingInvitationHandler,
    PostgresRespondInvitationHandler,
    PsycopgMatchingHttpProjectionAdapter,
    PsycopgMatchingReviewerAssignmentResolver,
    build_matching_postgres_http_bindings,
)
from desire_platform.matching.adapters.postgres import (
    CandidateSelectionCommandResult,
    MatchingCandidateSelectorClaimResult,
    MatchingAttemptPage,
    MatchingAttemptView,
    MatchingPreparedInvitationDisclosure,
    MatchingPostgresCommitOutcomeUnknownError,
    MatchingPostgresRejectedError,
    MatchingReviewActions,
    MatchingReviewAssignmentSummary,
    MatchingReviewAssignmentView,
    MatchingReviewAttemptView,
    MatchingReviewCandidateView,
    MatchingReviewComponentScoreView,
    MatchingReviewInvitationView,
    MatchingReviewerAssignmentResolution,
    MatchingReviewRunView,
    MatchingSelectionView,
    PsycopgMatchingAssignmentRuntime,
    PsycopgMatchingReviewRuntime,
    PsycopgMatchingRuntime,
    RecipientInvitationCommandResult,
    RecipientInvitationPage,
    RecipientInvitationView,
    SelectionCandidateView,
)
from desire_platform.matching.application import (
    ChooseCreatorCommand,
    CreateInvitationCommand,
    InvalidateAttemptCommand,
    MatchingActorKind,
    MatchingApplicationError,
    MatchingCommandResult,
    PublishInvitationCommand,
    RespondInvitationCommand,
    RespondInvitationHandler,
)
from desire_platform.matching.http import (
    MatchingHttpActor,
    MatchingHttpApplicationDispatcher,
    MatchingHttpPresenterBindings,
    MatchingHttpRequest,
)
from desire_platform.matching.domain import InvitationDisclosureSnapshot


NOW = datetime(2026, 8, 26, 8, 30, tzinfo=timezone.utc)
USER_ID = "10000000-0000-4000-8000-000000000001"
OTHER_USER_ID = "10000000-0000-4000-8000-000000000002"
SESSION_ID = "11000000-0000-4000-8000-000000000001"
ORG_ID = "20000000-0000-4000-8000-000000000001"
DEMAND_ID = "30000000-0000-4000-8000-000000000001"
DEMAND_VERSION_ID = "31000000-0000-4000-8000-000000000001"
ATTEMPT_ID = "40000000-0000-4000-8000-000000000001"
RUN_ID = "41000000-0000-4000-8000-000000000001"
INVITATION_ID = "50000000-0000-4000-8000-000000000001"
SELECTION_ID = "60000000-0000-4000-8000-000000000001"
ASSIGNMENT_ID = "61000000-0000-4000-8000-000000000001"
PROFILE_ID = "70000000-0000-4000-8000-000000000001"
PROFILE_VERSION_ID = "71000000-0000-4000-8000-000000000001"
CORRELATION_ID = "80000000-0000-4000-8000-000000000001"
CAUSATION_ID = "81000000-0000-4000-8000-000000000001"
TRACE_ID = "82000000-0000-4000-8000-000000000001"
MARKER = b"m" * 32


def _disclosure() -> tuple[dict[str, object], str]:
    value: dict[str, object] = {
        "schema_version": 1,
        "canonicalization_version": "invitation-disclosure-json-v1",
        "invitation_id": INVITATION_ID,
        "attempt_id": ATTEMPT_ID,
        "demand_id": DEMAND_ID,
        "demand_version_id": DEMAND_VERSION_ID,
        "profile_id": PROFILE_ID,
        "profile_version_id": PROFILE_VERSION_ID,
        "organization_preview": {
            "organization_id": ORG_ID,
            "display_label": "Synthetic Studio",
        },
        "opportunity": {
            "title": "Research brief",
            "problem_summary": "Validate one bounded pilot opportunity.",
            "deliverable_summaries": ["One evidence-backed brief"],
            "acceptance_summaries": ["Reviewed by the demand owner"],
        },
        "offer": {
            "currency": "CNY",
            "minimum_amount_minor": 100_000,
            "maximum_amount_minor": 200_000,
            "schedule_code": "FIXED_PRICE",
            "duration_weeks": 4,
        },
        "constraints": {
            "region_codes": ["CN"],
            "language_codes": ["ZH"],
            "data_sensitivity_code": "INTERNAL",
            "ai_use_code": "OPTIONAL",
        },
        "expires_at": "2026-09-02T08:30:00Z",
        "demand_content_sha256": "d" * 64,
        "profile_content_sha256": "e" * 64,
    }
    digest = hashlib.sha256(
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()
    value["snapshot_sha256"] = digest
    return value, digest


def invitation(
    *, status: str = "SENT", version: int = 1
) -> RecipientInvitationView:
    disclosure, digest = _disclosure()
    return RecipientInvitationView(
        invitation_id=UUID(INVITATION_ID),
        status=status,
        aggregate_version=version,
        updated_at=NOW,
        expires_at=NOW + timedelta(days=7),
        snapshot_sha256=digest,
        response_status=None if status == "SENT" else status,
        disclosure=disclosure,
    )


def selection(
    *, status: str = "OPEN", version: int = 3
) -> MatchingSelectionView:
    candidate = SelectionCandidateView(
        invitation_id=UUID(INVITATION_ID),
        creator_display_handle="studio-one",
        profile_id=UUID(PROFILE_ID),
        profile_version_id=UUID(PROFILE_VERSION_ID),
        accepted_at=NOW,
        capability_summary="Research and synthesis",
    )
    return MatchingSelectionView(
        selection_id=UUID(SELECTION_ID),
        attempt_id=UUID(ATTEMPT_ID),
        candidate_selector_assignment_id=UUID(ASSIGNMENT_ID),
        candidate_selector_assignment_version=4,
        status=status,
        aggregate_version=version,
        updated_at=NOW,
        current_invitation_set_sha256="a" * 64,
        chosen_invitation_id=(
            UUID(INVITATION_ID) if status == "SELECTED" else None
        ),
        accepted_invitations=(candidate,),
    )


def attempt() -> MatchingAttemptView:
    return MatchingAttemptView(
        attempt_id=UUID(ATTEMPT_ID),
        demand_id=UUID(DEMAND_ID),
        attempt_no=1,
        status="OPEN",
        aggregate_version=2,
        updated_at=NOW,
    )


def personal_actor(*, user_id: str = USER_ID) -> MatchingHttpActor:
    return MatchingHttpActor(
        actor_user_id=user_id,
        session_id=SESSION_ID,
        correlation_id=CORRELATION_ID,
        causation_id=CAUSATION_ID,
        trace_id=TRACE_ID,
        original_actor_id=None,
        workspace_id=f"personal:{user_id}",
        workspace_kind="PERSONAL",
        organization_id=None,
        role_codes=("CREATOR",),
        authority_marker_sha256=MARKER,
    )


def selector_actor(*, user_id: str = USER_ID) -> MatchingHttpActor:
    return MatchingHttpActor(
        actor_user_id=user_id,
        session_id=SESSION_ID,
        correlation_id=CORRELATION_ID,
        causation_id=CAUSATION_ID,
        trace_id=TRACE_ID,
        original_actor_id=None,
        workspace_id=f"org:{ORG_ID}",
        workspace_kind="ORGANIZATION",
        organization_id=ORG_ID,
        role_codes=("DEMAND_OWNER",),
        authority_marker_sha256=MARKER,
    )


def platform_actor() -> MatchingHttpActor:
    return MatchingHttpActor(
        actor_user_id=USER_ID,
        session_id=SESSION_ID,
        correlation_id=CORRELATION_ID,
        causation_id=CAUSATION_ID,
        trace_id=TRACE_ID,
        original_actor_id=None,
        workspace_id=f"platform:{USER_ID}",
        workspace_kind="PLATFORM",
        organization_id=None,
        role_codes=("OPERATIONS_REVIEWER",),
        authority_marker_sha256=MARKER,
    )


def keys() -> MatchingPostgresHttpKeys:
    return MatchingPostgresHttpKeys(
        idempotency_key_id="matching-idempotency-v1",
        idempotency_key=bytearray(b"i" * 32),
        payload_hash_key_id="matching-payload-v1",
        payload_hash_key=bytearray(b"p" * 32),
        read_cursor_key_id="matching-read-cursor-v1",
        read_cursor_key=bytearray(b"c" * 32),
    )


class Ids:
    def __init__(self) -> None:
        self.value = 100

    def new_id(self, purpose: str) -> UUID:
        assert purpose.startswith("matching_")
        self.value += 1
        return UUID(int=self.value)


class Runtime(PsycopgMatchingRuntime):
    def __init__(self) -> None:
        self.calls: list[tuple[str, object]] = []
        self.invitation = invitation()
        self.selection = selection()
        self.unknown = False

    def read_creator_invitation(self, *, context, invitation_id):
        self.calls.append(("read_creator", (context, invitation_id)))
        return self.invitation

    def list_creator_invitations(self, **facts):
        self.calls.append(("list_creator", facts))
        if facts["cursor_updated_at"] is None:
            return RecipientInvitationPage(
                (self.invitation,), NOW, UUID(INVITATION_ID)
            )
        return RecipientInvitationPage((self.invitation,), None, None)

    def list_selector_attempts(self, **facts):
        self.calls.append(("list_selector", facts))
        if facts["cursor_updated_at"] is None:
            return MatchingAttemptPage((attempt(),), NOW, UUID(ATTEMPT_ID))
        return MatchingAttemptPage((attempt(),), None, None)

    def read_selection_by_attempt(self, **facts):
        self.calls.append(("selection_by_attempt", facts))
        return self.selection

    def read_selection_by_id(self, **facts):
        self.calls.append(("selection_by_id", facts))
        return self.selection

    def accept_invitation(self, request):
        self.calls.append(("accept", request))
        if self.unknown:
            raise MatchingPostgresCommitOutcomeUnknownError()
        self.invitation = invitation(status="ACCEPTED", version=2)
        return RecipientInvitationCommandResult(self.invitation, False)

    def decline_invitation(self, request):
        self.calls.append(("decline", request))
        return RecipientInvitationCommandResult(self.invitation, False)

    def withdraw_invitation(self, request):
        self.calls.append(("withdraw", request))
        return RecipientInvitationCommandResult(self.invitation, False)

    def choose_creator(self, request):
        self.calls.append(("choose", request))
        return CandidateSelectionCommandResult(self.selection, False)

    def close_selection(self, request):
        self.calls.append(("close", request))
        return CandidateSelectionCommandResult(self.selection, False)


def review_summary(
    *, status: str = "ACTIVE", version: int = 1
) -> MatchingReviewAssignmentSummary:
    return MatchingReviewAssignmentSummary(
        assignment_id=UUID(ASSIGNMENT_ID),
        organization_id=UUID(ORG_ID),
        attempt_id=UUID(ATTEMPT_ID),
        match_run_id=UUID(RUN_ID),
        purpose_code="INVITATION_REVIEW",
        role_code="MATCHING_REVIEWER",
        status=status,
        aggregate_version=version,
        expires_at=NOW + timedelta(hours=1),
    )


def review_workspace() -> MatchingReviewAssignmentView:
    components = tuple(
        MatchingReviewComponentScoreView(
            code=f"COMPONENT_{ordinal}", ordinal=ordinal, score="1.000000"
        )
        for ordinal in range(1, 7)
    )
    return MatchingReviewAssignmentView(
        assignment=review_summary(),
        attempt=MatchingReviewAttemptView(
            attempt_no=1,
            status="OPEN",
            aggregate_version=2,
            updated_at=NOW,
            demand_id=UUID(DEMAND_ID),
            demand_version_id=UUID(DEMAND_VERSION_ID),
            demand_aggregate_version=3,
            demand_content_sha256=b"d" * 32,
            input_baseline_sha256=b"b" * 32,
        ),
        run=MatchingReviewRunView(
            status="COMPLETED",
            aggregate_version=4,
            ordered_result_sha256=b"r" * 32,
            candidate_count=1,
            eligible_count=1,
            excluded_count=0,
            failure_code=None,
        ),
        eligible_candidates=(
            MatchingReviewCandidateView(
                creator_user_id=UUID(OTHER_USER_ID),
                creator_display_handle="creator_0123456789abcdef",
                profile_id=UUID(PROFILE_ID),
                profile_version_id=UUID(PROFILE_VERSION_ID),
                profile_content_sha256=b"p" * 32,
                evidence_version_digest=b"e" * 32,
                total_score="6.000000",
                rank=1,
                component_scores=components,
                candidate_result_sha256=b"c" * 32,
            ),
        ),
        invitations=(
            MatchingReviewInvitationView(
                invitation_id=UUID(INVITATION_ID),
                creator_user_id=UUID(OTHER_USER_ID),
                status="CREATED",
                aggregate_version=1,
                snapshot_sha256=b"s" * 32,
                expires_at=NOW + timedelta(days=7),
                updated_at=NOW,
            ),
        ),
        actions=MatchingReviewActions(True, True, True),
    )


class ReviewRuntime(PsycopgMatchingReviewRuntime):
    def __init__(self) -> None:
        self.calls: list[tuple[str, object]] = []
        self.workspace = review_workspace()
        self.create_replay = None

    def resolve_assignment(self, *, context, operation, target_id):
        self.calls.append(("resolve", (context, operation, target_id)))
        expected = {
            "CREATE_INVITATION": UUID(RUN_ID),
            "PUBLISH_INVITATION": UUID(INVITATION_ID),
            "INVALIDATE_ATTEMPT": UUID(ATTEMPT_ID),
        }
        if expected.get(operation) != target_id:
            return None
        return MatchingReviewerAssignmentResolution(
            assignment_id=UUID(ASSIGNMENT_ID),
            organization_id=UUID(ORG_ID),
            attempt_id=UUID(ATTEMPT_ID),
            match_run_id=UUID(RUN_ID),
            purpose_code="INVITATION_REVIEW",
            assignment_version=1,
            expires_at=NOW + timedelta(hours=1),
        )

    def read_assignment(self, context):
        self.calls.append(("read", context))
        return self.workspace

    def claim_assignment(self, request):
        self.calls.append(("claim", request))
        return review_summary()

    def release_assignment(self, request):
        self.calls.append(("release", request))
        return review_summary(status="REVOKED", version=2)

    def replay_create_invitation(self, request):
        self.calls.append(("probe_create", request))
        return self.create_replay

    def prepare_invitation(self, request):
        self.calls.append(("prepare", request))
        document, _digest = _disclosure()
        document.pop("snapshot_sha256")
        document["invitation_id"] = str(request.invitation_id)
        canonical = json.dumps(
            document,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        snapshot = InvitationDisclosureSnapshot(
            snapshot_id=str(request.snapshot_id),
            invitation_id=str(request.invitation_id),
            attempt_id=ATTEMPT_ID,
            demand_id=DEMAND_ID,
            demand_version_id=DEMAND_VERSION_ID,
            profile_id=PROFILE_ID,
            profile_version_id=PROFILE_VERSION_ID,
            demand_content_sha256="d" * 64,
            profile_content_sha256="e" * 64,
            snapshot_sha256=hashlib.sha256(canonical).hexdigest(),
            canonical_bytes=canonical,
        )
        return MatchingPreparedInvitationDisclosure(
            snapshot=snapshot, document=document
        )

    def create_invitation(self, request):
        self.calls.append(("create", request))
        return MatchingCommandResult(
            str(request.invitation_id), "CREATED", 1, NOW, False,
            ("InvitationCreated",),
        )

    def publish_invitation(self, request):
        self.calls.append(("publish", request))
        return MatchingCommandResult(
            str(request.invitation_id), "SENT", 2, NOW, False,
            ("InvitationSent", "SelectionInvitationSetChanged"),
        )

    def invalidate_attempt(self, request):
        self.calls.append(("invalidate", request))
        return MatchingCommandResult(
            str(request.attempt_id), "INVALIDATED", 3, NOW, False,
            ("InvitationRevoked", "SelectionCancelled", "MatchingAttemptInvalidated"),
        )


class AssignmentRuntime(PsycopgMatchingAssignmentRuntime):
    def __init__(self) -> None:
        self.calls: list[object] = []

    def claim_candidate_selector(self, request):
        self.calls.append(request)
        return MatchingCandidateSelectorClaimResult(
            assignment_id=request.assignment_id,
            assignment_version=1,
            selection_id=UUID(SELECTION_ID),
            attempt_id=UUID(ATTEMPT_ID),
            demand_id=request.demand_id,
            status="ACTIVE",
            expires_at=NOW + timedelta(hours=1),
            selection_status="OPEN",
            selection_version=1,
            current_invitation_set_sha256=b"a" * 32,
            replayed=False,
        )


class AllowDemandHold:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def evaluate_for_matching(self, **facts):
        self.calls.append(facts)
        return SimpleNamespace(
            decision="ALLOW",
            evidence_sha256=b"t" * 32,
            evaluated_at=NOW,
            valid_until=NOW + timedelta(minutes=5),
        )


class CompatibleKeyring:
    def __init__(self, value: MatchingPostgresHttpKeys) -> None:
        self.identity_key_id = value.idempotency_key_id
        self.payload_hash_key_id = value.payload_hash_key_id
        self.value = value

    def keyed_digest(self, key_id: str, raw: bytes) -> str:
        purpose = (
            "IDEMPOTENCY"
            if key_id == self.identity_key_id
            else "PAYLOAD_HASH"
        )
        return self.value.digest(purpose=purpose, value=raw).hex()


def command_actor() -> MatchingPostgresActorContext:
    return MatchingPostgresActorContext(
        actor_kind=MatchingActorKind.USER,
        actor_id=USER_ID,
        session_id=SESSION_ID,
        organization_id=ORG_ID,
        correlation_id=CORRELATION_ID,
        causation_id=CAUSATION_ID,
        trace_id=TRACE_ID,
        original_actor_id=None,
        workload_credential_id=None,
        authority_marker_sha256=MARKER,
    )


def test_factory_enables_only_reviewed_public_programs() -> None:
    runtime = Runtime()
    bindings = build_matching_postgres_http_bindings(
        runtime=runtime, keys=keys(), id_source=Ids()
    )
    assert isinstance(bindings, MatchingHttpPresenterBindings)
    assert isinstance(bindings.respond_invitation, PostgresRespondInvitationHandler)
    assert isinstance(bindings.choose_creator, PostgresChooseCreatorHandler)
    assert isinstance(bindings.projections, PsycopgMatchingHttpProjectionAdapter)
    assert bindings.create_invitation is None
    assert bindings.publish_invitation is None
    assert bindings.invalidate_attempt is None
    assert bindings.reviewer_assignments is None
    assert MATCHING_POSTGRES_OPERATIONAL_SUPPORT == {
        "creator_http": "AVAILABLE",
        "candidate_selector_http": "AVAILABLE",
        "candidate_selector_assignment_http": "AVAILABLE",
        "operations_http": "AVAILABLE",
        "attempt_run_worker": "UNAVAILABLE_NO_FIXED_DATABASE_PROGRAM",
    }


def test_creator_command_actor_organization_comes_only_from_safe_projection() -> None:
    runtime = Runtime()
    bindings = build_matching_postgres_http_bindings(
        runtime=runtime, keys=keys(), id_source=Ids()
    )
    actor = bindings.command_actors.resolve_actor(
        actor=personal_actor(),
        operation_id="acceptMatchingInvitation",
        path_parameters={"invitation_id": INVITATION_ID},
    )
    assert isinstance(actor, MatchingPostgresActorContext)
    assert actor.organization_id == ORG_ID
    assert actor.authority_marker_sha256 == MARKER
    assert runtime.calls[0][0] == "read_creator"


def test_recipient_and_selector_projections_use_actor_bound_signed_cursors() -> None:
    runtime = Runtime()
    adapter = PsycopgMatchingHttpProjectionAdapter(runtime=runtime, keys=keys())
    first = adapter.list_recipient_invitations(
        actor=personal_actor(), limit=25, cursor=None
    ).as_json()
    assert first["items"][0]["invitation_id"] == INVITATION_ID
    assert isinstance(first["next_cursor"], str)
    second = adapter.list_recipient_invitations(
        actor=personal_actor(), limit=25, cursor=first["next_cursor"]
    ).as_json()
    assert second["next_cursor"] is None
    with pytest.raises(MatchingApplicationError) as wrong_creator:
        adapter.list_recipient_invitations(
            actor=personal_actor(user_id=OTHER_USER_ID),
            limit=25,
            cursor=first["next_cursor"],
        )
    assert wrong_creator.value.code == "INVALID_REQUEST"

    attempts = adapter.list_demand_attempts(
        actor=selector_actor(),
        organization_id=ORG_ID,
        demand_id=DEMAND_ID,
        limit=10,
        cursor=None,
    ).as_json()
    assert attempts["items"][0]["attempt_id"] == ATTEMPT_ID
    projection = adapter.read_selection_for_attempt(
        actor=selector_actor(),
        organization_id=ORG_ID,
        attempt_id=ATTEMPT_ID,
    )
    assert projection.as_json()["candidate_selector_assignment_id"] == ASSIGNMENT_ID


def test_postgres_handler_uses_application_canonical_receipt_and_safe_dtos() -> None:
    runtime = Runtime()
    keyring = keys()
    handler = PostgresRespondInvitationHandler(
        runtime=runtime, keys=keyring, id_source=Ids()
    )
    actor = command_actor()
    _value, snapshot_sha256 = _disclosure()
    command = RespondInvitationCommand(
        invitation_id=INVITATION_ID,
        snapshot_sha256=snapshot_sha256,
        expected_invitation_version=1,
        accept=True,
        reason_code=None,
        note=None,
        idempotency_key="accept-key-0000000001",
    )
    expected_receipt = RespondInvitationHandler(
        receipt_keyring=CompatibleKeyring(keyring)
    )._receipt_binding(actor=actor, command=command)
    result = handler.handle(actor=actor, command=command)
    assert result.target_status == "ACCEPTED"
    assert result.event_types == (
        "InvitationAccepted",
        "SelectionInvitationSetChanged",
    )
    request = next(value for name, value in runtime.calls if name == "accept")
    assert request.material.identity_digest.hex() == expected_receipt["identity"]
    assert request.material.payload_hash.hex() == expected_receipt["payload_hash"]
    assert command.idempotency_key not in repr(request)


def test_selector_handler_carries_exact_assignment_and_never_infers_role_authority() -> None:
    runtime = Runtime()
    bindings = build_matching_postgres_http_bindings(
        runtime=runtime, keys=keys(), id_source=Ids()
    )
    actor = bindings.command_actors.resolve_actor(
        actor=selector_actor(),
        operation_id="chooseMatchingCreator",
        path_parameters={
            "organization_id": ORG_ID,
            "selection_id": SELECTION_ID,
        },
    )
    command = ChooseCreatorCommand(
        selection_id=SELECTION_ID,
        invitation_id=INVITATION_ID,
        selection_basis_code="CAPABILITY_FIT",
        current_invitation_set_sha256="a" * 64,
        expected_selection_version=3,
        assignment_id=ASSIGNMENT_ID,
        expected_assignment_version=4,
        idempotency_key="choose-key-0000000001",
    )
    result = bindings.choose_creator.handle(actor=actor, command=command)
    assert result.target_status == "OPEN"
    request = next(value for name, value in runtime.calls if name == "choose")
    assert str(request.selector.assignment_id) == ASSIGNMENT_ID
    assert request.selector.assignment_version == 4
    assert request.selector.authority_marker_sha256 == MARKER


def test_unknown_commit_is_not_retried_or_reported_as_success() -> None:
    runtime = Runtime()
    runtime.unknown = True
    handler = PostgresRespondInvitationHandler(
        runtime=runtime, keys=keys(), id_source=Ids()
    )
    _value, snapshot_sha256 = _disclosure()
    with pytest.raises(MatchingApplicationError) as raised:
        handler.handle(
            actor=command_actor(),
            command=RespondInvitationCommand(
                invitation_id=INVITATION_ID,
                snapshot_sha256=snapshot_sha256,
                expected_invitation_version=1,
                accept=True,
                reason_code=None,
                note=None,
                idempotency_key="accept-key-0000000001",
            ),
        )
    assert raised.value.code == "COMMAND_OUTCOME_UNKNOWN"
    assert [name for name, _value in runtime.calls].count("accept") == 1


def test_operational_service_claims_only_from_authenticated_workspace_facts() -> None:
    assignment_runtime = AssignmentRuntime()
    review_runtime = ReviewRuntime()
    service = MatchingPostgresOperationalHttpService(
        assignment_runtime=assignment_runtime,
        review_runtime=review_runtime,
        keys=keys(),
        id_source=SecureRuntimeSources(),
    )
    selector_response = service.handle(
        request=MatchingHttpRequest(
            method="POST",
            path="/v1/matching/candidate-selector-assignments/claim",
            headers={"idempotency-key": "selector-claim-key-0001"},
            json_body={"demand_id": DEMAND_ID},
        ),
        actor=selector_actor(),
    )
    assert selector_response.status == 201
    assert selector_response.headers["etag"] == '"v1"'
    assert selector_response.json_body == {
        "candidate_selector_assignment_id": str(
            assignment_runtime.calls[0].assignment_id
        ),
        "candidate_selector_assignment_version": 1,
        "selection_id": SELECTION_ID,
        "attempt_id": ATTEMPT_ID,
        "demand_id": DEMAND_ID,
        "status": "ACTIVE",
        "expires_at": "2026-08-26T09:30:00Z",
        "selection_status": "OPEN",
        "selection_version": 1,
        "current_invitation_set_sha256": (b"a" * 32).hex(),
    }
    claim = assignment_runtime.calls[0]
    assert str(claim.context.actor_user_id) == USER_ID
    assert str(claim.context.session_id) == SESSION_ID
    assert str(claim.context.organization_id) == ORG_ID
    assert claim.context.principal_marker_sha256 == MARKER
    assert len(claim.material.outbox_event_ids) == 1
    assert "selector-claim-key" not in repr(claim)

    hidden = service.handle(
        request=MatchingHttpRequest(
            method="POST",
            path="/v1/matching/candidate-selector-assignments/claim",
            headers={"idempotency-key": "selector-claim-key-0002"},
            json_body={"demand_id": DEMAND_ID, "organization_id": ORG_ID},
        ),
        actor=selector_actor(),
    )
    assert hidden.status == 400
    assert hidden.json_body["code"] == "INVALID_REQUEST"
    assert len(assignment_runtime.calls) == 1


def test_review_claim_read_and_release_are_current_assignment_only() -> None:
    assignment_runtime = AssignmentRuntime()
    review_runtime = ReviewRuntime()
    service = MatchingPostgresOperationalHttpService(
        assignment_runtime=assignment_runtime,
        review_runtime=review_runtime,
        keys=keys(),
        id_source=SecureRuntimeSources(),
    )
    claim = service.handle(
        request=MatchingHttpRequest(
            method="POST",
            path="/v1/app/matching-review/queue/claim",
            headers={"idempotency-key": "review-claim-key-000001"},
            json_body={},
        ),
        actor=platform_actor(),
    )
    assert claim.status == 201
    assert claim.json_body["assignment_id"] == ASSIGNMENT_ID
    assert set(claim.json_body) == {
        "assignment_id", "organization_id", "attempt_id", "match_run_id",
        "purpose_code", "role_code", "status", "aggregate_version", "expires_at",
    }
    claimed_request = next(value for name, value in review_runtime.calls if name == "claim")
    assert str(claimed_request.context.actor_user_id) == USER_ID
    assert claimed_request.context.principal_marker_sha256 == MARKER

    read = service.handle(
        request=MatchingHttpRequest(
            method="GET",
            path="/v1/app/matching-review/assignment",
            headers={},
            json_body={},
        ),
        actor=platform_actor(),
    )
    assert read.status == 200
    assert read.json_body["run"]["candidate_count"] == 1
    assert read.json_body["eligible_candidates"][0]["total_score"] == "6.000000"
    assert "private_note" not in json.dumps(read.json_body)

    release = service.handle(
        request=MatchingHttpRequest(
            method="POST",
            path="/v1/app/matching-review/assignment/release",
            headers={
                "idempotency-key": "review-release-key-0001",
                "if-match": '"v1"',
            },
            json_body={},
        ),
        actor=platform_actor(),
    )
    assert release.status == 200
    assert release.json_body["status"] == "REVOKED"
    released_request = next(
        value for name, value in review_runtime.calls if name == "release"
    )
    assert released_request.expected_assignment_version == 1
    assert len(released_request.material.outbox_event_ids) == 1

    wrong_role = service.handle(
        request=MatchingHttpRequest(
            method="POST",
            path="/v1/app/matching-review/queue/claim",
            headers={"idempotency-key": "review-claim-key-000002"},
            json_body={},
        ),
        actor=selector_actor(),
    )
    assert wrong_role.status == 404
    assert wrong_role.json_body["code"] == "RESOURCE_NOT_FOUND"


def test_operational_service_preserves_only_controlled_database_failures() -> None:
    class RejectingReviewRuntime(ReviewRuntime):
        def __init__(self, error: Exception) -> None:
            super().__init__()
            self.error = error

        def claim_assignment(self, request):
            self.calls.append(("claim", request))
            raise self.error

    request = MatchingHttpRequest(
        method="POST",
        path="/v1/app/matching-review/queue/claim",
        headers={"idempotency-key": "review-claim-errors-0001"},
        json_body={},
    )
    controlled = MatchingPostgresOperationalHttpService(
        assignment_runtime=AssignmentRuntime(),
        review_runtime=RejectingReviewRuntime(
            MatchingPostgresRejectedError("PRECONDITION_FAILED")
        ),
        keys=keys(),
        id_source=Ids(),
    ).handle(request=request, actor=platform_actor())
    assert (controlled.status, controlled.json_body["code"]) == (
        412,
        "PRECONDITION_FAILED",
    )

    unknown = MatchingPostgresOperationalHttpService(
        assignment_runtime=AssignmentRuntime(),
        review_runtime=RejectingReviewRuntime(
            MatchingPostgresCommitOutcomeUnknownError()
        ),
        keys=keys(),
        id_source=Ids(),
    ).handle(request=request, actor=platform_actor())
    assert (unknown.status, unknown.json_body["code"]) == (
        503,
        "COMMAND_OUTCOME_UNKNOWN",
    )

    hidden_internal_code = MatchingPostgresOperationalHttpService(
        assignment_runtime=AssignmentRuntime(),
        review_runtime=RejectingReviewRuntime(
            MatchingPostgresRejectedError("INTERNAL_TABLE_DETAIL")
        ),
        keys=keys(),
        id_source=Ids(),
    ).handle(request=request, actor=platform_actor())
    assert (hidden_internal_code.status, hidden_internal_code.json_body["code"]) == (
        503,
        "SERVICE_UNAVAILABLE",
    )


def test_reviewer_commands_resolve_current_assignment_and_bind_trust_evidence() -> None:
    review_runtime = ReviewRuntime()
    hold = AllowDemandHold()
    bindings = build_matching_postgres_http_bindings(
        runtime=Runtime(),
        review_runtime=review_runtime,
        demand_hold=hold,
        keys=keys(),
        id_source=SecureRuntimeSources(),
    )
    assert isinstance(
        bindings.create_invitation, PostgresCreateMatchingInvitationHandler
    )
    assert isinstance(
        bindings.publish_invitation, PostgresPublishMatchingInvitationHandler
    )
    assert isinstance(
        bindings.invalidate_attempt, PostgresInvalidateMatchingAttemptHandler
    )
    assert isinstance(
        bindings.reviewer_assignments, PsycopgMatchingReviewerAssignmentResolver
    )
    actor = bindings.command_actors.resolve_actor(
        actor=platform_actor(),
        operation_id="createMatchingInvitation",
        path_parameters={"match_run_id": RUN_ID},
    )
    assert actor.organization_id == ORG_ID

    create_result = bindings.create_invitation.handle(
        actor=actor,
        command=CreateInvitationCommand(
            match_run_id=RUN_ID,
            creator_user_id=OTHER_USER_ID,
            expires_at=NOW + timedelta(days=7),
            expected_run_version=4,
            assignment_id=ASSIGNMENT_ID,
            idempotency_key="create-review-key-0001",
        ),
    )
    assert create_result.target_status == "CREATED"
    prepared = next(value for name, value in review_runtime.calls if name == "prepare")
    probed = next(value for name, value in review_runtime.calls if name == "probe_create")
    created = next(value for name, value in review_runtime.calls if name == "create")
    assert probed.material is created.material
    assert [name for name, _ in review_runtime.calls].index("probe_create") < [name for name, _ in review_runtime.calls].index("prepare")
    assert prepared.snapshot_id == created.snapshot_id
    assert prepared.invitation_id == created.invitation_id
    assert created.assignment_id == UUID(ASSIGNMENT_ID)
    assert created.expected_assignment_version == 1
    assert len(created.material.outbox_event_ids) == 1
    assert created.trust.evidence_sha256 == b"t" * 32

    publish_result = bindings.publish_invitation.handle(
        actor=actor,
        command=PublishInvitationCommand(
            invitation_id=INVITATION_ID,
            snapshot_sha256=(b"s" * 32).hex(),
            expected_invitation_version=1,
            assignment_id=ASSIGNMENT_ID,
            idempotency_key="publish-review-key-001",
        ),
    )
    assert publish_result.target_status == "SENT"
    published = next(value for name, value in review_runtime.calls if name == "publish")
    assert published.organization_id == UUID(ORG_ID)
    assert published.expected_snapshot_sha256 == b"s" * 32
    assert len(published.material.outbox_event_ids) == 2

    invalidated_result = bindings.invalidate_attempt.handle(
        actor=actor,
        command=InvalidateAttemptCommand(
            attempt_id=ATTEMPT_ID,
            reason_code="REVIEW_INVALIDATED",
            input_baseline_sha256=(b"b" * 32).hex(),
            expected_attempt_version=2,
            assignment_id=ASSIGNMENT_ID,
            idempotency_key="invalidate-review-key-1",
        ),
    )
    assert invalidated_result.target_status == "INVALIDATED"
    invalidated = next(
        value for name, value in review_runtime.calls if name == "invalidate"
    )
    assert len(invalidated.material.outbox_event_ids) == 3
    assert invalidated.expected_input_baseline_sha256 == b"b" * 32
    assert len(hold.calls) == 2
    assert hold.calls[0]["organization_id"] == ORG_ID
    assert hold.calls[0]["demand_id"] == DEMAND_ID

    with pytest.raises(MatchingApplicationError) as hidden:
        bindings.create_invitation.handle(
            actor=actor,
            command=CreateInvitationCommand(
                match_run_id=RUN_ID,
                creator_user_id=OTHER_USER_ID,
                expires_at=NOW + timedelta(days=7),
                expected_run_version=4,
                assignment_id=str(UUID(int=999)),
                idempotency_key="create-review-key-0002",
            ),
        )
    assert hidden.value.code == "RESOURCE_NOT_FOUND"


def test_completed_create_replay_retains_authority_but_skips_preparation_and_hold() -> None:
    review_runtime = ReviewRuntime()
    review_runtime.create_replay = MatchingCommandResult(
        INVITATION_ID, "CREATED", 1, NOW, True, ("InvitationCreated",),
    )
    hold = AllowDemandHold()
    bindings = build_matching_postgres_http_bindings(
        runtime=Runtime(), review_runtime=review_runtime, demand_hold=hold,
        keys=keys(), id_source=SecureRuntimeSources(),
    )
    actor = bindings.command_actors.resolve_actor(
        actor=platform_actor(), operation_id="createMatchingInvitation",
        path_parameters={"match_run_id": RUN_ID},
    )
    command = CreateInvitationCommand(
        match_run_id=RUN_ID, creator_user_id=OTHER_USER_ID,
        expires_at=NOW + timedelta(days=7), expected_run_version=4,
        assignment_id=ASSIGNMENT_ID, idempotency_key="create-review-key-0001",
    )
    review_runtime.calls.clear()
    result = bindings.create_invitation.handle(actor=actor, command=command)
    assert result is review_runtime.create_replay
    assert [name for name, _ in review_runtime.calls] == ["resolve", "read", "probe_create"]
    assert hold.calls == []
    review_runtime.calls.clear()
    with pytest.raises(MatchingApplicationError) as denied:
        bindings.create_invitation.handle(
            actor=actor, command=replace(command, assignment_id=str(UUID(int=999))),
        )
    assert denied.value.code == "RESOURCE_NOT_FOUND"
    assert "probe_create" not in [name for name, _ in review_runtime.calls]


@pytest.mark.parametrize("committed_elsewhere", [False, True])
def test_create_preflight_race_reads_exact_receipt_without_retrying_write(committed_elsewhere) -> None:
    class RacingReviewRuntime(ReviewRuntime):
        def prepare_invitation(self, request):
            self.calls.append(("prepare", request))
            if committed_elsewhere:
                self.create_replay = MatchingCommandResult(
                    INVITATION_ID, "CREATED", 1, NOW, True, ("InvitationCreated",),
                )
            raise MatchingPostgresRejectedError("INVITATION_ALREADY_EXISTS")

    runtime = RacingReviewRuntime()
    hold = AllowDemandHold()
    bindings = build_matching_postgres_http_bindings(
        runtime=Runtime(), review_runtime=runtime, demand_hold=hold,
        keys=keys(), id_source=SecureRuntimeSources(),
    )
    actor = bindings.command_actors.resolve_actor(
        actor=platform_actor(), operation_id="createMatchingInvitation",
        path_parameters={"match_run_id": RUN_ID},
    )
    command = CreateInvitationCommand(
        match_run_id=RUN_ID, creator_user_id=OTHER_USER_ID,
        expires_at=NOW + timedelta(days=7), expected_run_version=4,
        assignment_id=ASSIGNMENT_ID, idempotency_key="create-review-key-0001",
    )
    runtime.calls.clear()
    if committed_elsewhere:
        assert bindings.create_invitation.handle(actor=actor, command=command) is runtime.create_replay
    else:
        with pytest.raises(MatchingApplicationError) as rejected:
            bindings.create_invitation.handle(actor=actor, command=command)
        assert rejected.value.code == "INVITATION_ALREADY_EXISTS"
    assert [name for name, _ in runtime.calls] == ["resolve", "read", "probe_create", "prepare", "resolve", "read", "probe_create"]
    probes = [request for name, request in runtime.calls if name == "probe_create"]
    assert probes[0] is probes[1]
    assert hold.calls == []


def test_operations_routes_are_explicitly_service_unavailable() -> None:
    bindings = build_matching_postgres_http_bindings(
        runtime=Runtime(), keys=keys(), id_source=Ids()
    )
    response = MatchingHttpApplicationDispatcher(bindings=bindings).handle(
        request=MatchingHttpRequest(
            method="POST",
            path=f"/v1/operations/match-runs/{RUN_ID}/invitations",
            headers={
                "idempotency-key": "create-key-0000000001",
                "if-match": '"v1"',
            },
            json_body={
                "match_run_id": RUN_ID,
                "creator_user_id": USER_ID,
                "expires_at": "2026-09-02T08:30:00Z",
            },
        ),
        actor=platform_actor(),
    )
    assert response.status == 503
    assert response.json_body["code"] == "SERVICE_UNAVAILABLE"


def test_key_material_is_purpose_separated_and_redacted() -> None:
    value = keys()
    assert "iiii" not in repr(value)
    assert value.digest(purpose="IDEMPOTENCY", value=b"same") != value.digest(
        purpose="PAYLOAD_HASH", value=b"same"
    )
    with pytest.raises(ValueError):
        MatchingPostgresHttpKeys(
            idempotency_key_id="same-key",
            idempotency_key=bytearray(b"x" * 32),
            payload_hash_key_id="same-key",
            payload_hash_key=bytearray(b"y" * 32),
            read_cursor_key_id="cursor-key",
            read_cursor_key=bytearray(b"z" * 32),
        )
