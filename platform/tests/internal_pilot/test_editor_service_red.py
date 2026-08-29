from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from desire_platform.demand.domain import (
    DemandReviewAssignment,
    ReviewAssignmentStatus,
)
from desire_platform.internal_pilot.editor import (
    EditorPrincipal,
    EditorService,
    EditorServiceError,
    MemoryEditorRepository,
)
from tests.support.creator_profile_builders import (
    freeze_json as freeze_profile_json,
    valid_content_mapping as _profile_content,
)
from tests.support.demand_builders import (
    freeze_json as freeze_demand_json,
    valid_content_mapping as _demand_content,
)


NOW = datetime(2026, 8, 12, 8, 0, tzinfo=timezone.utc)
OWNER = EditorPrincipal(
    user_id="user_owner_internal_0001",
    session_id="session_owner_internal_01",
    organization_id="organization_internal_01",
    role_codes=("DEMAND_OWNER",),
)
CREATOR = EditorPrincipal(
    user_id="user_creator_internal_01",
    session_id="session_creator_internal_1",
    organization_id="organization_internal_01",
    role_codes=("CREATOR",),
)
REVIEWER = EditorPrincipal(
    user_id="user_reviewer_internal_1",
    session_id="session_reviewer_internal_1",
    organization_id="organization_review_ops_1",
    role_codes=("OPERATIONS_REVIEWER",),
)


class FixedClock:
    def now(self) -> datetime:
        return NOW


class Ids:
    def __init__(self) -> None:
        self.count = 0

    def new(self, kind: str) -> str:
        self.count += 1
        return f"{kind}_{self.count:016d}"


def profile_content() -> dict:
    content = _profile_content()
    content["interests"][0].update(
        {
            "problem_code": "PROBLEM.OPERATIONS",
            "domain_code": "DOMAIN.SOFTWARE",
            "task_code": "TASK.ANALYSIS",
        }
    )
    content["skills"][0]["skill_code"] = "SKILL.SYSTEMS_ANALYSIS"
    content["boundaries"]["prohibited_domains"] = []
    content["boundaries"]["prohibited_tasks"] = []
    content["location"]["region_code"] = "CN"
    content["ai"]["prohibited_case_codes"] = []
    return content


def demand_content() -> dict:
    content = _demand_content()
    content["problem"].update(
        {
            "domain_code": "DOMAIN.SOFTWARE",
            "problem_type_codes": ["PROBLEM.OPERATIONS"],
            "target_user_category_codes": ["SYNTHETIC_USER"],
        }
    )
    content["skills"]["must_have"][0]["skill_code"] = (
        "SKILL.SYSTEMS_ANALYSIS"
    )
    content["skills"]["nice_to_have"] = []
    content["matching"].update(
        {
            "problem_codes": ["PROBLEM.OPERATIONS"],
            "domain_codes": ["DOMAIN.SOFTWARE"],
            "task_codes": ["TASK.ANALYSIS"],
        }
    )
    content["risk"]["dependency_codes"] = []
    content["collaboration"]["languages"] = ["zh-CN"]
    content["location"].update(
        {
            "demand_region_code": "CN",
            "allowed_creator_region_codes": ["CN"],
        }
    )
    return content


@pytest.fixture
def repo() -> MemoryEditorRepository:
    return MemoryEditorRepository()


@pytest.fixture
def service(repo: MemoryEditorRepository) -> EditorService:
    return EditorService(
        repository=repo,
        clock=FixedClock(),
        id_source=Ids(),
        client_reference_key=b"test-only-client-reference-key-32b",
    )


def test_profile_drafts_publish_and_owner_scope_are_domain_backed(
    service: EditorService,
) -> None:
    created = service.create_profile(
        principal=CREATOR,
        idempotency_key="profile-create-idempotency-001",
    )
    original_etag = created.etag
    draft = service.save_profile_draft(
        principal=CREATOR,
        profile_id=created.object_id,
        if_match=original_etag,
        base_version_id=None,
        taxonomy_bundle_id="taxonomy_bundle_internal_01",
        content=profile_content(),
        idempotency_key="profile-save-idempotency-0001",
    )

    assert draft.revision == 2
    assert draft.etag != original_etag
    assert draft.current_version.status == "DRAFT"
    published = service.publish_profile(
        principal=CREATOR,
        profile_id=created.object_id,
        draft_version_id=draft.current_version.version_id,
        if_match=draft.etag,
        idempotency_key="profile-publish-idempotency-1",
    )
    assert published.status == "ACTIVE"
    assert published.current_version.status == "PUBLISHED"
    assert published.current_version.content == profile_content()

    stranger = EditorPrincipal(
        user_id="user_creator_internal_02",
        session_id="session_creator_internal_2",
        organization_id=CREATOR.organization_id,
        role_codes=("CREATOR",),
    )
    assert service.list_profiles(principal=stranger) == ()
    with pytest.raises(EditorServiceError) as hidden:
        service.get_profile(principal=stranger, profile_id=created.object_id)
    assert (hidden.value.status, hidden.value.code) == (404, "RESOURCE_NOT_FOUND")


def test_resource_contract_exposes_server_capabilities_and_editable_paths(
    service: EditorService,
) -> None:
    profile = service.create_profile(
        principal=CREATOR,
        idempotency_key="profile-create-idempotency-002",
    )
    assert profile.resource_type == "CREATOR_PROFILE"
    assert profile.capabilities == ("SAVE_DRAFT", "ARCHIVE")
    assert "/skills" in profile.editable_paths

    demand = service.create_demand(
        principal=OWNER,
        taxonomy_bundle_id="taxonomy_bundle_internal_01",
        content=demand_content(),
        client_reference="capability-surface-case",
        expires_at=NOW + timedelta(days=60),
        idempotency_key="demand-create-idempotency-006",
    )
    assert demand.resource_type == "DEMAND"
    assert demand.capabilities == ("SAVE_DRAFT", "SUBMIT", "CANCEL")
    assert "/problem" in demand.editable_paths


def test_demand_owner_cancel_is_conditional_authorized_terminal_and_replay_safe(
    service: EditorService,
) -> None:
    created = service.create_demand(
        principal=OWNER,
        taxonomy_bundle_id="taxonomy_bundle_internal_01",
        content=demand_content(),
        client_reference="owner-cancel-case",
        expires_at=NOW + timedelta(days=60),
        idempotency_key="demand-cancel-create-0001",
    )
    assert created.capabilities == ("SAVE_DRAFT", "SUBMIT", "CANCEL")

    cancelled = service.cancel_demand(
        principal=OWNER,
        demand_id=created.object_id,
        if_match=created.etag,
        reason_code="REQUIREMENTS_CHANGED",
        idempotency_key="demand-cancel-command-0001",
    )
    assert (cancelled.status, cancelled.revision, cancelled.capabilities) == (
        "CANCELLED",
        created.revision + 1,
        (),
    )

    replay = service.cancel_demand(
        principal=OWNER,
        demand_id=created.object_id,
        if_match=created.etag,
        reason_code="REQUIREMENTS_CHANGED",
        idempotency_key="demand-cancel-command-0001",
    )
    assert replay == cancelled

    with pytest.raises(EditorServiceError) as changed_replay:
        service.cancel_demand(
            principal=OWNER,
            demand_id=created.object_id,
            if_match=created.etag,
            reason_code="OWNER_WITHDREW",
            idempotency_key="demand-cancel-command-0001",
        )
    assert (changed_replay.value.status, changed_replay.value.code) == (
        409,
        "IDEMPOTENCY_CONFLICT",
    )

    with pytest.raises(EditorServiceError) as terminal:
        service.cancel_demand(
            principal=OWNER,
            demand_id=created.object_id,
            if_match=cancelled.etag,
            reason_code="OWNER_WITHDREW",
            idempotency_key="demand-cancel-command-0002",
        )
    assert (terminal.value.status, terminal.value.code) == (
        409,
        "INVALID_STATE_TRANSITION",
    )

    stranger = EditorPrincipal(
        user_id="user_owner_internal_0002",
        session_id="session_owner_internal_02",
        organization_id=OWNER.organization_id,
        role_codes=("DEMAND_OWNER",),
    )
    with pytest.raises(EditorServiceError) as hidden:
        service.cancel_demand(
            principal=stranger,
            demand_id=created.object_id,
            if_match=cancelled.etag,
            reason_code="OWNER_WITHDREW",
            idempotency_key="demand-cancel-command-0003",
        )
    assert (hidden.value.status, hidden.value.code) == (
        404,
        "RESOURCE_NOT_FOUND",
    )


def test_demand_owner_cancel_rejects_stale_etag_and_closed_reason_code(
    service: EditorService,
) -> None:
    created = service.create_demand(
        principal=OWNER,
        taxonomy_bundle_id="taxonomy_bundle_internal_01",
        content=demand_content(),
        client_reference="owner-cancel-stale-case",
        expires_at=NOW + timedelta(days=60),
        idempotency_key="demand-cancel-create-0002",
    )
    submitted = service.submit_demand(
        principal=OWNER,
        demand_id=created.object_id,
        if_match=created.etag,
        idempotency_key="demand-cancel-submit-0001",
    )
    assert submitted.capabilities == ("CANCEL",)

    with pytest.raises(EditorServiceError) as stale:
        service.cancel_demand(
            principal=OWNER,
            demand_id=created.object_id,
            if_match=created.etag,
            reason_code="OWNER_WITHDREW",
            idempotency_key="demand-cancel-command-0004",
        )
    assert (stale.value.status, stale.value.code, stale.value.etag) == (
        412,
        "PRECONDITION_FAILED",
        submitted.etag,
    )

    with pytest.raises(EditorServiceError) as scheduler_only:
        service.cancel_demand(
            principal=OWNER,
            demand_id=created.object_id,
            if_match=submitted.etag,
            reason_code="DEADLINE_REACHED",
            idempotency_key="demand-cancel-command-0005",
        )
    assert (
        scheduler_only.value.status,
        scheduler_only.value.code,
        scheduler_only.value.path,
    ) == (422, "INVALID_REASON_CODE", "/reason_code")


def test_profile_lifecycle_is_state_bound_replay_safe_and_terminal(
    service: EditorService,
) -> None:
    created = service.create_profile(
        principal=CREATOR,
        idempotency_key="profile-lifecycle-create-001",
    )
    assert created.capabilities == ("SAVE_DRAFT", "ARCHIVE")
    draft = service.save_profile_draft(
        principal=CREATOR,
        profile_id=created.object_id,
        if_match=created.etag,
        base_version_id=None,
        taxonomy_bundle_id="taxonomy_bundle_internal_01",
        content=profile_content(),
        idempotency_key="profile-lifecycle-save-0001",
    )
    active = service.publish_profile(
        principal=CREATOR,
        profile_id=created.object_id,
        draft_version_id=draft.current_version.version_id,
        if_match=draft.etag,
        idempotency_key="profile-lifecycle-publish-1",
    )
    assert active.capabilities == ("SAVE_DRAFT", "PAUSE", "ARCHIVE")

    paused = service.pause_profile(
        principal=CREATOR,
        profile_id=created.object_id,
        if_match=active.etag,
        reason_code="TEMPORARY_UNAVAILABILITY",
        idempotency_key="profile-lifecycle-pause-001",
    )
    assert (paused.status, paused.capabilities, paused.editable_paths) == (
        "PAUSED",
        ("RESUME", "ARCHIVE"),
        (),
    )
    assert paused.current_version.status == "PUBLISHED"
    assert service.pause_profile(
        principal=CREATOR,
        profile_id=created.object_id,
        if_match=active.etag,
        reason_code="TEMPORARY_UNAVAILABILITY",
        idempotency_key="profile-lifecycle-pause-001",
    ) == paused
    with pytest.raises(EditorServiceError) as changed_replay:
        service.pause_profile(
            principal=CREATOR,
            profile_id=created.object_id,
            if_match=active.etag,
            reason_code="OWNER_REQUEST",
            idempotency_key="profile-lifecycle-pause-001",
        )
    assert (changed_replay.value.status, changed_replay.value.code) == (
        409,
        "IDEMPOTENCY_CONFLICT",
    )
    with pytest.raises(EditorServiceError) as paused_save:
        service.save_profile_draft(
            principal=CREATOR,
            profile_id=created.object_id,
            if_match=paused.etag,
            base_version_id=paused.current_version.version_id,
            taxonomy_bundle_id="taxonomy_bundle_internal_01",
            content=profile_content(),
            idempotency_key="profile-lifecycle-paused-save",
        )
    assert (paused_save.value.status, paused_save.value.code) == (
        409,
        "INVALID_STATE_TRANSITION",
    )
    with pytest.raises(EditorServiceError) as stale:
        service.resume_profile(
            principal=CREATOR,
            profile_id=created.object_id,
            if_match=active.etag,
            idempotency_key="profile-lifecycle-stale-001",
        )
    assert (stale.value.status, stale.value.code, stale.value.etag) == (
        412,
        "PRECONDITION_FAILED",
        paused.etag,
    )

    resumed = service.resume_profile(
        principal=CREATOR,
        profile_id=created.object_id,
        if_match=paused.etag,
        idempotency_key="profile-lifecycle-resume-01",
    )
    assert (resumed.status, resumed.capabilities) == (
        "ACTIVE",
        ("SAVE_DRAFT", "PAUSE", "ARCHIVE"),
    )
    archived = service.archive_profile(
        principal=CREATOR,
        profile_id=created.object_id,
        if_match=resumed.etag,
        reason_code="ACCOUNT_CLOSURE",
        idempotency_key="profile-lifecycle-archive-1",
    )
    assert (archived.status, archived.capabilities, archived.current_version) == (
        "ARCHIVED",
        (),
        None,
    )
    assert archived.versions[-1].status == "RETIRED"
    assert service.archive_profile(
        principal=CREATOR,
        profile_id=created.object_id,
        if_match=resumed.etag,
        reason_code="ACCOUNT_CLOSURE",
        idempotency_key="profile-lifecycle-archive-1",
    ) == archived

    draft_creator = EditorPrincipal(
        user_id="user_creator_internal_03",
        session_id="session_creator_internal_3",
        organization_id=CREATOR.organization_id,
        role_codes=("CREATOR",),
    )
    draft_only = service.create_profile(
        principal=draft_creator,
        idempotency_key="profile-lifecycle-create-002",
    )
    draft_only = service.save_profile_draft(
        principal=draft_creator,
        profile_id=draft_only.object_id,
        if_match=draft_only.etag,
        base_version_id=None,
        taxonomy_bundle_id="taxonomy_bundle_internal_01",
        content=profile_content(),
        idempotency_key="profile-lifecycle-save-0002",
    )
    archived_draft = service.archive_profile(
        principal=draft_creator,
        profile_id=draft_only.object_id,
        if_match=draft_only.etag,
        reason_code="OWNER_REQUEST",
        idempotency_key="profile-lifecycle-archive-2",
    )
    assert archived_draft.versions[-1].status == "DISCARDED"

    with pytest.raises(EditorServiceError) as invalid_reason:
        service.archive_profile(
            principal=CREATOR,
            profile_id=created.object_id,
            if_match=archived.etag,
            reason_code="FREE_TEXT",
            idempotency_key="profile-lifecycle-invalid-1",
        )
    assert (invalid_reason.value.status, invalid_reason.value.code) == (
        422,
        "INVALID_REASON_CODE",
    )


def test_paused_profile_projects_published_version_and_resume_restores_draft(
    service: EditorService,
) -> None:
    created = service.create_profile(
        principal=CREATOR,
        idempotency_key="profile-paused-projection-create-001",
    )
    first_draft = service.save_profile_draft(
        principal=CREATOR,
        profile_id=created.object_id,
        if_match=created.etag,
        base_version_id=None,
        taxonomy_bundle_id="taxonomy_bundle_internal_01",
        content=profile_content(),
        idempotency_key="profile-paused-projection-save-001",
    )
    published = service.publish_profile(
        principal=CREATOR,
        profile_id=created.object_id,
        draft_version_id=first_draft.current_version.version_id,
        if_match=first_draft.etag,
        idempotency_key="profile-paused-projection-publish-001",
    )
    published_version_id = published.current_version.version_id

    revised_content = deepcopy(profile_content())
    revised_content["skills"][0]["proficiency"] = 4
    active_with_draft = service.save_profile_draft(
        principal=CREATOR,
        profile_id=created.object_id,
        if_match=published.etag,
        base_version_id=published_version_id,
        taxonomy_bundle_id="taxonomy_bundle_internal_01",
        content=revised_content,
        idempotency_key="profile-paused-projection-save-002",
    )
    draft_version_id = active_with_draft.current_version.version_id
    assert active_with_draft.current_version.status == "DRAFT"

    paused = service.pause_profile(
        principal=CREATOR,
        profile_id=created.object_id,
        if_match=active_with_draft.etag,
        reason_code="TEMPORARY_UNAVAILABILITY",
        idempotency_key="profile-paused-projection-pause-001",
    )
    assert (paused.current_version.version_id, paused.current_version.status) == (
        published_version_id,
        "PUBLISHED",
    )
    assert tuple(
        (version.version_id, version.status) for version in paused.versions
    ) == (
        (published_version_id, "PUBLISHED"),
        (draft_version_id, "DRAFT"),
    )

    resumed = service.resume_profile(
        principal=CREATOR,
        profile_id=created.object_id,
        if_match=paused.etag,
        idempotency_key="profile-paused-projection-resume-001",
    )
    assert (resumed.current_version.version_id, resumed.current_version.status) == (
        draft_version_id,
        "DRAFT",
    )
    assert resumed.current_version.content == revised_content
    assert tuple(
        (version.version_id, version.status) for version in resumed.versions
    ) == (
        (published_version_id, "PUBLISHED"),
        (draft_version_id, "DRAFT"),
    )


def test_demand_edit_is_new_immutable_version_and_submit_pins_that_version(
    service: EditorService,
) -> None:
    initial = demand_content()
    created = service.create_demand(
        principal=OWNER,
        taxonomy_bundle_id="taxonomy_bundle_internal_01",
        content=initial,
        client_reference="internal-pilot-case-1",
        expires_at=NOW + timedelta(days=60),
        idempotency_key="demand-create-idempotency-001",
    )
    first_version = created.current_version
    changed = deepcopy(initial)
    changed["problem"]["background"] = "A revised, concrete problem statement."
    edited = service.save_demand_draft(
        principal=OWNER,
        demand_id=created.object_id,
        if_match=created.etag,
        base_version_id=first_version.version_id,
        taxonomy_bundle_id="taxonomy_bundle_internal_01",
        content=changed,
        idempotency_key="demand-save-idempotency-0001",
    )

    assert edited.revision == 2
    assert edited.current_version.version_id != first_version.version_id
    assert edited.versions[0].content == initial
    assert edited.versions[1].content == changed
    submitted = service.submit_demand(
        principal=OWNER,
        demand_id=created.object_id,
        if_match=edited.etag,
        idempotency_key="demand-submit-idempotency-01",
    )
    assert submitted.status == "SUBMITTED"
    assert submitted.submissions[0].version_id == edited.current_version.version_id
    assert submitted.submissions[0].content_sha256 == edited.current_version.content_sha256
    assert submitted.versions[1].content == changed


def test_stale_write_returns_three_way_material_and_receipt_replays_first_write(
    service: EditorService,
) -> None:
    initial = demand_content()
    created = service.create_demand(
        principal=OWNER,
        taxonomy_bundle_id="taxonomy_bundle_internal_01",
        content=initial,
        client_reference="internal-pilot-case-2",
        expires_at=NOW + timedelta(days=60),
        idempotency_key="demand-create-idempotency-002",
    )
    yours = deepcopy(initial)
    yours["problem"]["background"] = "First accepted edit."
    first = service.save_demand_draft(
        principal=OWNER,
        demand_id=created.object_id,
        if_match=created.etag,
        base_version_id=created.current_version.version_id,
        taxonomy_bundle_id="taxonomy_bundle_internal_01",
        content=yours,
        idempotency_key="demand-save-idempotency-0002",
    )
    replay = service.save_demand_draft(
        principal=OWNER,
        demand_id=created.object_id,
        if_match=created.etag,
        base_version_id=created.current_version.version_id,
        taxonomy_bundle_id="taxonomy_bundle_internal_01",
        content=yours,
        idempotency_key="demand-save-idempotency-0002",
    )
    assert replay == first

    stale_yours = deepcopy(initial)
    stale_yours["problem"]["background"] = "Competing stale edit."
    with pytest.raises(EditorServiceError) as conflict:
        service.save_demand_draft(
            principal=OWNER,
            demand_id=created.object_id,
            if_match=created.etag,
            base_version_id=created.current_version.version_id,
            taxonomy_bundle_id="taxonomy_bundle_internal_01",
            content=stale_yours,
            idempotency_key="demand-save-idempotency-0003",
        )
    error = conflict.value
    assert (error.status, error.code) == (412, "PRECONDITION_FAILED")
    assert error.details["current"]["content"] == yours
    assert error.details["base"]["content"] == initial
    assert error.details["yours"]["content"] == stale_yours


def test_validation_is_422_with_field_path_and_idempotency_payload_is_closed(
    service: EditorService,
) -> None:
    invalid = demand_content()
    invalid["budget"]["currency"] = "yuan"
    with pytest.raises(EditorServiceError) as rejected:
        service.create_demand(
            principal=OWNER,
            taxonomy_bundle_id="taxonomy_bundle_internal_01",
            content=invalid,
            client_reference="internal-pilot-case-3",
            expires_at=NOW + timedelta(days=60),
            idempotency_key="demand-create-idempotency-003",
        )
    assert (rejected.value.status, rejected.value.code) == (
        422,
        "EDITOR_CHOICE_UNAVAILABLE",
    )
    assert rejected.value.path == "/content/budget/currency"

    valid = demand_content()
    service.create_demand(
        principal=OWNER,
        taxonomy_bundle_id="taxonomy_bundle_internal_01",
        content=valid,
        client_reference="internal-pilot-case-4",
        expires_at=NOW + timedelta(days=60),
        idempotency_key="demand-create-idempotency-004",
    )
    with pytest.raises(EditorServiceError) as changed_replay:
        service.create_demand(
            principal=OWNER,
            taxonomy_bundle_id="taxonomy_bundle_internal_01",
            content=valid,
            client_reference="changed-reference",
            expires_at=NOW + timedelta(days=60),
            idempotency_key="demand-create-idempotency-004",
        )
    assert (changed_replay.value.status, changed_replay.value.code) == (
        409,
        "IDEMPOTENCY_CONFLICT",
    )


def test_choice_membership_blocks_direct_save_and_existing_legacy_versions(
    service: EditorService,
    repo: MemoryEditorRepository,
) -> None:
    profile = service.create_profile(
        principal=CREATOR,
        idempotency_key="choice-profile-create-0001",
    )
    legacy_profile = profile_content()
    legacy_profile["interests"][0]["domain_code"] = "GENERAL"
    with pytest.raises(EditorServiceError) as profile_save:
        service.save_profile_draft(
            principal=CREATOR,
            profile_id=profile.object_id,
            if_match=profile.etag,
            base_version_id=None,
            taxonomy_bundle_id="taxonomy_bundle_internal_01",
            content=legacy_profile,
            idempotency_key="choice-profile-save-0001",
        )
    assert (
        profile_save.value.status,
        profile_save.value.code,
        profile_save.value.path,
    ) == (
        422,
        "EDITOR_CHOICE_UNAVAILABLE",
        "/content/interests/0/domain_code",
    )

    approved_draft = service.save_profile_draft(
        principal=CREATOR,
        profile_id=profile.object_id,
        if_match=profile.etag,
        base_version_id=None,
        taxonomy_bundle_id="taxonomy_bundle_internal_01",
        content=profile_content(),
        idempotency_key="choice-profile-save-0002",
    )
    draft_id = approved_draft.current_version.version_id
    stored_profile = repo.profile_versions[draft_id]
    repo.profile_versions[draft_id] = replace(
        stored_profile,
        content=freeze_profile_json(legacy_profile),
    )
    with pytest.raises(EditorServiceError) as profile_publish:
        service.publish_profile(
            principal=CREATOR,
            profile_id=profile.object_id,
            draft_version_id=draft_id,
            if_match=approved_draft.etag,
            idempotency_key="choice-profile-publish-0001",
        )
    assert (
        profile_publish.value.status,
        profile_publish.value.code,
        profile_publish.value.path,
    ) == (
        422,
        "EDITOR_CHOICE_UNAVAILABLE",
        "/content/interests/0/domain_code",
    )

    demand = service.create_demand(
        principal=OWNER,
        taxonomy_bundle_id="taxonomy_bundle_internal_01",
        content=demand_content(),
        client_reference="choice-membership-old-draft",
        expires_at=NOW + timedelta(days=60),
        idempotency_key="choice-demand-create-0001",
    )
    legacy_demand = demand_content()
    legacy_demand["problem"]["target_user_category_codes"] = [
        "TARGET_USER.SMALL_TEAM"
    ]
    with pytest.raises(EditorServiceError) as demand_save:
        service.save_demand_draft(
            principal=OWNER,
            demand_id=demand.object_id,
            if_match=demand.etag,
            base_version_id=demand.current_version.version_id,
            taxonomy_bundle_id="taxonomy_bundle_internal_01",
            content=legacy_demand,
            idempotency_key="choice-demand-save-0001",
        )
    assert (
        demand_save.value.status,
        demand_save.value.code,
        demand_save.value.path,
    ) == (
        422,
        "EDITOR_CHOICE_UNAVAILABLE",
        "/content/problem/target_user_category_codes/0",
    )

    current_id = demand.current_version.version_id
    stored_demand = repo.demand_versions[current_id]
    repo.demand_versions[current_id] = replace(
        stored_demand,
        content=freeze_demand_json(legacy_demand),
    )
    with pytest.raises(EditorServiceError) as demand_submit:
        service.submit_demand(
            principal=OWNER,
            demand_id=demand.object_id,
            if_match=demand.etag,
            idempotency_key="choice-demand-submit-0001",
        )
    assert (
        demand_submit.value.status,
        demand_submit.value.code,
        demand_submit.value.path,
    ) == (
        422,
        "EDITOR_CHOICE_UNAVAILABLE",
        "/content/problem/target_user_category_codes/0",
    )


def test_completed_memory_replay_precedes_new_choice_membership_rules(
    service: EditorService,
    repo: MemoryEditorRepository,
) -> None:
    created = service.create_demand(
        principal=OWNER,
        taxonomy_bundle_id="taxonomy_bundle_internal_01",
        content=demand_content(),
        client_reference="choice-replay-safe",
        expires_at=NOW + timedelta(days=60),
        idempotency_key="choice-replay-create-0001",
    )
    submitted = service.submit_demand(
        principal=OWNER,
        demand_id=created.object_id,
        if_match=created.etag,
        idempotency_key="choice-replay-submit-0001",
    )
    version_id = created.current_version.version_id
    legacy = demand_content()
    legacy["risk"]["dependency_codes"] = ["DEPENDENCY.GENERAL"]
    repo.demand_versions[version_id] = replace(
        repo.demand_versions[version_id],
        content=freeze_demand_json(legacy),
    )

    replay = service.submit_demand(
        principal=OWNER,
        demand_id=created.object_id,
        if_match=created.etag,
        idempotency_key="choice-replay-submit-0001",
    )

    assert replay == submitted


def test_reviewer_sees_only_authoritative_assignment_and_records_findings(
    service: EditorService,
    repo: MemoryEditorRepository,
) -> None:
    created = service.create_demand(
        principal=OWNER,
        taxonomy_bundle_id="taxonomy_bundle_internal_01",
        content=demand_content(),
        client_reference="internal-pilot-case-5",
        expires_at=NOW + timedelta(days=60),
        idempotency_key="demand-create-idempotency-005",
    )
    submitted = service.submit_demand(
        principal=OWNER,
        demand_id=created.object_id,
        if_match=created.etag,
        idempotency_key="demand-submit-idempotency-02",
    )
    assignment = DemandReviewAssignment(
        assignment_id="review_assignment_internal_1",
        organization_id=OWNER.organization_id,
        demand_id=created.object_id,
        reviewer_user_id=REVIEWER.user_id,
        duty_grant_id="review_duty_grant_internal1",
        duty_grant_version=1,
        issued_by_user_id="user_ops_admin_internal_1",
        purpose="DEMAND_REVIEW",
        status=ReviewAssignmentStatus.ACTIVE,
        conflict_attestation_sha256="a" * 64,
        assigned_at=NOW - timedelta(minutes=1),
        expires_at=NOW + timedelta(days=7),
        aggregate_version=1,
    )
    # There is deliberately no public API for granting review authority.  The
    # account/IAM composition will persist this authoritative assignment.
    repo.add_review_assignment(assignment)

    visible = service.list_demands(principal=REVIEWER)
    assert tuple(item.object_id for item in visible) == (created.object_id,)
    assert visible[0].review_assignment is not None
    assert visible[0].review_assignment.assignment_id == assignment.assignment_id
    assert visible[0].review_assignment.expires_at == assignment.expires_at
    reviewed = service.request_demand_changes(
        principal=REVIEWER,
        assignment_id=assignment.assignment_id,
        demand_id=created.object_id,
        if_match=submitted.etag,
        reason_codes=("SCOPE_UNCLEAR",),
        required_field_codes=("/scope/deliverables",),
        idempotency_key="review-findings-idempotency-01",
    )
    assert reviewed.status == "NEEDS_CHANGES"
    assert reviewed.findings[0].result == "NEEDS_CHANGES"
    assert reviewed.findings[0].required_field_paths == ("/scope/deliverables",)
    assert reviewed.review_assignment is None

    impostor = EditorPrincipal(
        user_id="user_reviewer_internal_2",
        session_id="session_reviewer_internal_2",
        organization_id=REVIEWER.organization_id,
        role_codes=("OPERATIONS_REVIEWER",),
    )
    with pytest.raises(EditorServiceError) as hidden:
        service.request_demand_changes(
            principal=impostor,
            assignment_id=assignment.assignment_id,
            demand_id=created.object_id,
            if_match=submitted.etag,
            reason_codes=("SCOPE_UNCLEAR",),
            required_field_codes=("/scope/deliverables",),
            idempotency_key="review-findings-idempotency-02",
        )
    assert (hidden.value.status, hidden.value.code) == (404, "RESOURCE_NOT_FOUND")
