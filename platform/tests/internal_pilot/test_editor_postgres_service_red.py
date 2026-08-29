"""Application TDD for HTTP DTO to canonical PostgreSQL command conversion."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import json
from uuid import UUID

import pytest

from desire_platform.creator_profile.adapters.postgres import (
    CreatorProfilePostgresCommitOutcomeUnknownError,
    CreatorProfilePostgresHoldEvidence,
    CreatorProfilePostgresOperation,
)
from desire_platform.demand.adapters.postgres import (
    DemandPostgresCommitOutcomeUnknownError,
    DemandPostgresContentPolicyEvidence,
    DemandPostgresDatabaseError,
    DemandPostgresHoldEvidence,
    DemandPostgresOperation,
    DemandPostgresRuleRequirement,
)
from desire_platform.internal_pilot.editor import (
    DemandCompletedVerifyReplayError,
    DemandCompletedVerifyReplayResult,
    DemandReadAuthority,
    EditorConfigurationDto,
    EditorFindingDto,
    EditorHttpApi,
    EditorPostgresKeys,
    EditorPsycopgConnectionSettings,
    EditorPrincipal,
    EditorResourceDto,
    EditorServiceError,
    HttpRequest,
    PostgresEditorService,
    ProfileCompletedLifecycleReplayError,
    ProfileCompletedLifecycleReplayResult,
    ProfileReadAuthority,
    EditorTaxonomyBundleDto,
    EditorVersionDto,
    build_internal_sandbox_editor_choices,
)
from desire_platform.internal_pilot.editor.postgres import _PROFILE_EDITABLE_PATHS
from tests.internal_pilot.test_editor_service_red import (
    demand_content,
    profile_content,
)


NOW = datetime(2026, 8, 12, 12, 0, tzinfo=timezone.utc)
ACTOR = "10000000-0000-4000-8000-000000000001"
SESSION = "20000000-0000-4000-8000-000000000001"
ORG = "81000000-0000-4000-8000-000000000001"
MARKER = hashlib.sha256(b"editor-authority").digest()
ASSIGNMENT = UUID("82000000-0000-4000-8000-000000000001")
ORG_A = "81000000-0000-4000-8000-00000000000a"
ORG_B = "81000000-0000-4000-8000-00000000000b"
MEMBERSHIP_A = "83000000-0000-4000-8000-00000000000a"
MEMBERSHIP_B = "83000000-0000-4000-8000-00000000000b"


class _Clock:
    @staticmethod
    def now() -> datetime:
        return NOW


class _Authorities:
    def __init__(self) -> None:
        self.profiles = []

    def profile(self, *, principal, operation, profile_id):
        del principal
        if profile_id not in self.profiles:
            self.profiles.append(profile_id)
        return ProfileReadAuthority(MARKER, operation)

    def profile_targets(self, *, principal):
        del principal
        return tuple((item, ProfileReadAuthority(MARKER)) for item in self.profiles)

    def demand(self, **kwargs):
        raise AssertionError(kwargs)

    def demand_targets(self, *, principal):
        del principal
        return ()


class _Evidence:
    def __init__(self) -> None:
        self.configuration_calls = []

    def editor_configuration(self, *, principal, evaluated_at):
        self.configuration_calls.append((principal, evaluated_at))
        return EditorConfigurationDto(
            schema_version="editor-configuration-v2",
            deployment_mode="INTERNAL_SANDBOX",
            taxonomy_bundle=EditorTaxonomyBundleDto(
                bundle_id="50000000-0000-4000-8000-000000000001",
                status="CURRENT_APPROVED",
                effective_at=NOW - timedelta(days=1),
                effective_until=NOW + timedelta(days=1),
            ),
            editor_choices=build_internal_sandbox_editor_choices(
                bundle_id="50000000-0000-4000-8000-000000000001"
            ),
        )

    def profile_hold(
        self,
        *,
        principal,
        action,
        profile_id,
        profile_version_no,
        taxonomy_bundle_id,
        prospective_aggregate_version,
        content_sha256,
        content,
        evaluated_at,
    ):
        assert action in {
            "PublishCreatorProfileVersion",
            "ResumeCreatorProfile",
        }
        assert isinstance(content, dict)
        assert profile_version_no >= 1
        assert isinstance(taxonomy_bundle_id, UUID)
        return CreatorProfilePostgresHoldEvidence(
            profile_id=profile_id,
            prospective_aggregate_version=prospective_aggregate_version,
            content_sha256=content_sha256,
            actor_user_id=UUID(principal.user_id),
            policy_version="creator-profile-hold-v1",
            evaluated_at=evaluated_at,
            valid_until=evaluated_at + timedelta(minutes=5),
        )


class _Repository:
    def __init__(self) -> None:
        self.commands = []
        self.resources = {}

    def execute_profile(self, command):
        self.commands.append(command)
        existing = self.resources.get(str(command.scope.profile_id))
        if existing is not None and any(
            prior.scope.command_id == command.scope.command_id
            for prior in self.commands[:-1]
        ):
            return object()
        revision = 1 if existing is None else existing.revision + 1
        self.resources[str(command.scope.profile_id)] = EditorResourceDto(
            resource_type="CREATOR_PROFILE",
            object_id=str(command.scope.profile_id),
            status="DRAFT",
            revision=revision,
            etag=f'"profile-{revision}"',
            capabilities=("SAVE_DRAFT",),
            editable_paths=(),
            current_version=None,
            versions=(),
        )
        return object()

    def get_profile(self, *, principal, profile_id, authority):
        del principal
        assert authority.expected_authority_marker_sha256 == MARKER
        return self.resources[profile_id]

    def list_profiles(self, *, principal, targets):
        return tuple(
            self.get_profile(
                principal=principal, profile_id=profile_id, authority=authority
            )
            for profile_id, authority in targets
        )


class _DemandAuthorizationProbe:
    def __init__(self) -> None:
        self.create_calls = []
        self.list_calls = []

    def demand(self, **facts):
        self.create_calls.append(facts)
        return DemandReadAuthority(DemandPostgresOperation.CREATE, MARKER)

    def demand_targets(self, *, principal):
        self.list_calls.append(principal)
        return ()


class _DemandRepositoryProbe:
    def __init__(self) -> None:
        self.list_calls = []
        self.commands = []

    def list_demands(self, *, principal, targets):
        self.list_calls.append((principal, targets))
        return ()

    def execute_demand(self, command):
        self.commands.append(command)

    def get_demand(self, *, principal, demand_id, authority):
        del principal, authority
        return EditorResourceDto(
            resource_type="DEMAND",
            object_id=demand_id,
            status="DRAFT",
            revision=1,
            etag='"demand-1"',
            capabilities=("SAVE_DRAFT",),
            editable_paths=(),
            current_version=None,
            versions=(),
        )


def _keys() -> EditorPostgresKeys:
    return EditorPostgresKeys(
        id_key=b"i" * 32,
        profile_idempotency_key=b"a" * 32,
        profile_payload_key=b"b" * 32,
        demand_idempotency_key=b"c" * 32,
        demand_payload_key=b"d" * 32,
        demand_client_reference_key=b"e" * 32,
    )


def _profile_etag(profile_id: str, revision: int) -> str:
    digest = hashlib.sha256(
        f"CREATOR_PROFILE:{profile_id}:{revision}".encode("utf-8")
    ).hexdigest()[:24]
    return f'"creator_profile-{revision}-{digest}"'


def _profile_version(*, status: str = "PUBLISHED") -> EditorVersionDto:
    return EditorVersionDto(
        version_id="40000000-0000-4000-8000-000000000081",
        version_no=1,
        based_on_version_id=None,
        status=status,
        content={"identity": {"headline": "Profile lifecycle replay"}},
        content_sha256=hashlib.sha256(b"profile-version").hexdigest(),
        taxonomy_bundle_id="50000000-0000-4000-8000-000000000081",
        created_at=NOW - timedelta(days=1),
    )


def _profile_resource(
    *,
    profile_id: str,
    status: str,
    revision: int,
) -> EditorResourceDto:
    published = _profile_version()
    archived = status == "ARCHIVED"
    if archived:
        capabilities = ()
        editable_paths = ()
    elif status == "PAUSED":
        capabilities = ("RESUME", "ARCHIVE")
        editable_paths = ()
    else:
        capabilities = ("SAVE_DRAFT", "PAUSE", "ARCHIVE")
        editable_paths = _PROFILE_EDITABLE_PATHS
    return EditorResourceDto(
        resource_type="CREATOR_PROFILE",
        object_id=profile_id,
        status=status,
        revision=revision,
        etag=_profile_etag(profile_id, revision),
        capabilities=capabilities,
        editable_paths=editable_paths,
        current_version=None if archived else published,
        versions=(
            (replace(published, status="RETIRED"),)
            if archived
            else (published,)
        ),
    )


def _invoke_profile_lifecycle(
    service: PostgresEditorService,
    *,
    operation: CreatorProfilePostgresOperation,
    principal: EditorPrincipal,
    profile_id: str,
    if_match: str,
    idempotency_key: str,
) -> EditorResourceDto:
    common = {
        "principal": principal,
        "profile_id": profile_id,
        "if_match": if_match,
        "idempotency_key": idempotency_key,
    }
    if operation is CreatorProfilePostgresOperation.PAUSE:
        return service.pause_profile(reason_code="OWNER_REQUEST", **common)
    if operation is CreatorProfilePostgresOperation.RESUME:
        return service.resume_profile(**common)
    if operation is CreatorProfilePostgresOperation.ARCHIVE:
        return service.archive_profile(reason_code="OWNER_REQUEST", **common)
    raise AssertionError("test lifecycle operation is closed")


def test_same_editor_http_api_builds_exact_durable_create_command_and_list() -> None:
    repository = _Repository()
    service = PostgresEditorService(
        repository=repository,
        authorities=_Authorities(),
        evidence=_Evidence(),
        keys=_keys(),
        clock=_Clock(),
    )
    api = EditorHttpApi(service=service)
    principal = EditorPrincipal(
        user_id=ACTOR,
        session_id=SESSION,
        organization_id=ORG,
        role_codes=("CREATOR",),
    )
    request = HttpRequest(
        method="POST",
        path="/v1/app/profiles",
        headers={"Idempotency-Key": "profile-create-0001"},
        json={},
    )

    first = api.handle(request=request, principal=principal)
    replay = api.handle(request=request, principal=principal)
    listed = api.handle(
        request=HttpRequest(
            method="GET", path="/v1/app/profiles", headers={}, json=None
        ),
        principal=principal,
    )

    assert first.status == replay.status == 201
    assert first.json == replay.json
    assert len(listed.json["data"]) == 1
    assert len(repository.commands) == 2
    command = repository.commands[0]
    assert command.operation is CreatorProfilePostgresOperation.CREATE
    assert command.scope.actor_user_id == UUID(ACTOR)
    assert command.scope.session_id == UUID(SESSION)
    assert command.scope.expected_authority_marker_sha256 == MARKER
    assert command.receipt.idempotency_key_digest != b"profile-create-0001"
    assert command.receipt.payload_hash != hashlib.sha256(b"{}").digest()
    assert repository.commands[1] == command


def test_postgres_service_projects_current_configuration_only_for_edit_roles() -> None:
    evidence = _Evidence()
    service = PostgresEditorService(
        repository=_Repository(),
        authorities=_Authorities(),
        evidence=evidence,
        keys=_keys(),
        clock=_Clock(),
    )
    creator = EditorPrincipal(
        user_id=ACTOR,
        session_id=SESSION,
        organization_id=None,
        role_codes=("CREATOR",),
    )

    configuration = service.get_configuration(principal=creator)

    assert configuration.taxonomy_bundle.bundle_id == (
        "50000000-0000-4000-8000-000000000001"
    )
    assert len(configuration.editor_choices.fields) == 23
    assert evidence.configuration_calls == [(creator, NOW)]

    reviewer = EditorPrincipal(
        user_id=ACTOR,
        session_id=SESSION,
        organization_id=None,
        role_codes=("OPERATIONS_REVIEWER",),
    )
    with pytest.raises(EditorServiceError) as hidden:
        service.get_configuration(principal=reviewer)
    assert (hidden.value.status, hidden.value.code) == (404, "RESOURCE_NOT_FOUND")
    assert evidence.configuration_calls == [(creator, NOW)]


def test_selected_organization_never_inherits_another_organizations_owner_role() -> None:
    authorities = _DemandAuthorizationProbe()
    repository = _DemandRepositoryProbe()
    service = PostgresEditorService(
        repository=repository,
        authorities=authorities,
        evidence=_Evidence(),
        keys=_keys(),
        clock=_Clock(),
    )
    common = {
        "user_id": ACTOR,
        "session_id": SESSION,
        "user_role_codes": (),
        "platform_duty_codes": (),
        "principal_marker_sha256": MARKER,
        "workspace_kind": "ORGANIZATION",
    }
    org_a = EditorPrincipal(
        **common,
        organization_id=ORG_A,
        membership_id=MEMBERSHIP_A,
        workspace_id=f"org:{ORG_A}",
        organization_role_codes=("ORG_ADMIN",),
        role_codes=("ORG_ADMIN",),
    )
    org_b = EditorPrincipal(
        **common,
        organization_id=ORG_B,
        membership_id=MEMBERSHIP_B,
        workspace_id=f"org:{ORG_B}",
        organization_role_codes=("DEMAND_OWNER",),
        role_codes=("DEMAND_OWNER",),
    )

    for operation in (
        lambda: service.list_demands(principal=org_a),
        lambda: service.create_demand(
            principal=org_a,
            taxonomy_bundle_id="84000000-0000-4000-8000-000000000001",
            content={},
            client_reference="org-a-must-not-create",
            expires_at=NOW + timedelta(days=1),
            idempotency_key="org-a-create-0001",
        ),
    ):
        with pytest.raises(EditorServiceError) as denied:
            operation()
        assert (denied.value.status, denied.value.code) == (
            404,
            "RESOURCE_NOT_FOUND",
        )
    assert authorities.create_calls == []
    assert authorities.list_calls == []

    assert service.list_demands(principal=org_b) == ()
    assert authorities.list_calls == [org_b]
    created = service.create_demand(
        principal=org_b,
        taxonomy_bundle_id="84000000-0000-4000-8000-000000000001",
        content={},
        client_reference="org-b-owner-create",
        expires_at=NOW + timedelta(days=1),
        idempotency_key="org-b-create-0001",
    )
    assert created.resource_type == "DEMAND"
    assert len(authorities.create_calls) == 1
    assert authorities.create_calls[0]["principal"] is org_b
    assert len(repository.commands) == 1


def test_postgres_fake_fallback_blocks_profile_save_and_existing_draft_publish() -> None:
    profile_id = "30000000-0000-4000-8000-000000000071"
    taxonomy_id = "50000000-0000-4000-8000-000000000001"
    creator = EditorPrincipal(
        user_id=ACTOR,
        session_id=SESSION,
        organization_id=None,
        role_codes=("CREATOR",),
    )
    repository = _Repository()
    current = EditorResourceDto(
        resource_type="CREATOR_PROFILE",
        object_id=profile_id,
        status="DRAFT",
        revision=1,
        etag='"profile-choice-1"',
        capabilities=("SAVE_DRAFT", "ARCHIVE"),
        editable_paths=_PROFILE_EDITABLE_PATHS,
        current_version=None,
        versions=(),
    )
    repository.resources[profile_id] = current
    service = PostgresEditorService(
        repository=repository,
        authorities=_Authorities(),
        evidence=_Evidence(),
        keys=_keys(),
        clock=_Clock(),
    )
    legacy = profile_content()
    legacy["interests"][0]["domain_code"] = "GENERAL"

    with pytest.raises(EditorServiceError) as save_rejected:
        service.save_profile_draft(
            principal=creator,
            profile_id=profile_id,
            if_match=current.etag,
            base_version_id=None,
            taxonomy_bundle_id=taxonomy_id,
            content=legacy,
            idempotency_key="pg-choice-profile-save-0001",
        )
    assert (
        save_rejected.value.status,
        save_rejected.value.code,
        save_rejected.value.path,
    ) == (
        422,
        "EDITOR_CHOICE_UNAVAILABLE",
        "/content/interests/0/domain_code",
    )
    assert repository.commands == []

    service.save_profile_draft(
        principal=creator,
        profile_id=profile_id,
        if_match=current.etag,
        base_version_id=None,
        taxonomy_bundle_id=taxonomy_id,
        content=profile_content(),
        idempotency_key="pg-choice-profile-save-approved-0001",
    )
    assert repository.commands[-1].operation is (
        CreatorProfilePostgresOperation.SAVE_DRAFT
    )
    repository.commands.clear()

    draft = EditorVersionDto(
        version_id="40000000-0000-4000-8000-000000000071",
        version_no=1,
        based_on_version_id=None,
        status="DRAFT",
        content=legacy,
        content_sha256=hashlib.sha256(b"legacy-profile").hexdigest(),
        taxonomy_bundle_id=taxonomy_id,
        created_at=NOW - timedelta(minutes=5),
    )
    repository.resources[profile_id] = replace(
        current,
        capabilities=("SAVE_DRAFT", "PUBLISH", "ARCHIVE"),
        current_version=draft,
        versions=(draft,),
    )
    with pytest.raises(EditorServiceError) as publish_rejected:
        service.publish_profile(
            principal=creator,
            profile_id=profile_id,
            draft_version_id=draft.version_id,
            if_match=current.etag,
            idempotency_key="pg-choice-profile-publish-0001",
        )
    assert (
        publish_rejected.value.status,
        publish_rejected.value.code,
        publish_rejected.value.path,
    ) == (
        422,
        "EDITOR_CHOICE_UNAVAILABLE",
        "/content/interests/0/domain_code",
    )
    assert repository.commands == []

    approved_draft = replace(draft, content=profile_content())
    repository.resources[profile_id] = replace(
        current,
        capabilities=("SAVE_DRAFT", "PUBLISH", "ARCHIVE"),
        current_version=approved_draft,
        versions=(approved_draft,),
    )
    service.publish_profile(
        principal=creator,
        profile_id=profile_id,
        draft_version_id=approved_draft.version_id,
        if_match=current.etag,
        idempotency_key="pg-choice-profile-publish-approved-0001",
    )
    assert repository.commands[-1].operation is (
        CreatorProfilePostgresOperation.PUBLISH
    )


def test_postgres_fake_fallback_blocks_demand_save_and_existing_draft_submit() -> None:
    demand_id = "30000000-0000-4000-8000-000000000072"
    version_id = "40000000-0000-4000-8000-000000000072"
    taxonomy_id = "50000000-0000-4000-8000-000000000001"
    owner = EditorPrincipal(
        user_id=ACTOR,
        session_id=SESSION,
        organization_id=ORG,
        role_codes=("DEMAND_OWNER",),
    )

    class Authorities(_Authorities):
        @staticmethod
        def demand(*, principal, operation, demand_id, assignment_id=None):
            del principal, demand_id, assignment_id
            return DemandReadAuthority(operation, MARKER)

    class Repository:
        def __init__(self, resource):
            self.resource = resource
            self.commands = []

        def get_demand(self, **_facts):
            return self.resource

        def execute_demand(self, command):
            self.commands.append(command)

    class Evidence(_Evidence):
        @staticmethod
        def demand_content_policy(**facts):
            return DemandPostgresContentPolicyEvidence(
                demand_id=facts["demand_id"],
                demand_version_id=facts["demand_version_id"],
                content_sha256=facts["content_sha256"],
                decision="ALLOW",
                policy_version="demand-content-policy-v1",
                result_sha256=hashlib.sha256(b"policy").digest(),
                evaluated_at=NOW - timedelta(seconds=1),
                valid_until=NOW + timedelta(minutes=5),
            )

        @staticmethod
        def demand_hold(**facts):
            return DemandPostgresHoldEvidence(
                actor_id=UUID(ACTOR),
                organization_id=UUID(ORG),
                demand_id=facts["demand_id"],
                prospective_aggregate_version=facts[
                    "prospective_aggregate_version"
                ],
                demand_version_id=facts["demand_version_id"],
                content_sha256=facts["content_sha256"],
                action="SUBMIT_DEMAND",
                decision="ALLOW",
                policy_version="demand-safety-hold-v1",
                evaluated_at=NOW - timedelta(seconds=1),
                valid_until=NOW + timedelta(minutes=5),
            )

        @staticmethod
        def demand_rules(**_facts):
            return DemandPostgresRuleRequirement(
                taxonomy_bundle_id=UUID(taxonomy_id),
                budget_rule_bundle_id=UUID(
                    "51000000-0000-4000-8000-000000000001"
                ),
                risk_rule_bundle_id=UUID(
                    "52000000-0000-4000-8000-000000000001"
                ),
                matching_rule_bundle_id=UUID(
                    "53000000-0000-4000-8000-000000000001"
                ),
                reason_code_bundle_id=UUID(
                    "54000000-0000-4000-8000-000000000001"
                ),
                composite_rule_requirement_id=UUID(
                    "55000000-0000-4000-8000-000000000001"
                ),
                requirement_sha256=hashlib.sha256(b"rules").digest(),
                effective_at=NOW - timedelta(days=1),
                effective_until=NOW + timedelta(days=1),
            )

    approved = demand_content()
    version = EditorVersionDto(
        version_id=version_id,
        version_no=1,
        based_on_version_id=None,
        status="COMMITTED",
        content=approved,
        content_sha256=hashlib.sha256(b"approved-demand").hexdigest(),
        taxonomy_bundle_id=taxonomy_id,
        created_at=NOW - timedelta(minutes=5),
    )
    current = EditorResourceDto(
        resource_type="DEMAND",
        object_id=demand_id,
        status="DRAFT",
        revision=1,
        etag='"demand-choice-1"',
        capabilities=("SAVE_DRAFT", "SUBMIT"),
        editable_paths=(),
        current_version=version,
        versions=(version,),
    )
    repository = Repository(current)
    service = PostgresEditorService(
        repository=repository,
        authorities=Authorities(),
        evidence=Evidence(),
        keys=_keys(),
        clock=_Clock(),
    )
    legacy_create = demand_content()
    legacy_create["matching"]["task_codes"] = ["VALIDATION"]
    with pytest.raises(EditorServiceError) as create_rejected:
        service.create_demand(
            principal=owner,
            taxonomy_bundle_id=taxonomy_id,
            content=legacy_create,
            client_reference="pg-choice-legacy-create",
            expires_at=NOW + timedelta(days=1),
            idempotency_key="pg-choice-demand-create-0001",
        )
    assert (
        create_rejected.value.status,
        create_rejected.value.code,
        create_rejected.value.path,
    ) == (
        422,
        "EDITOR_CHOICE_UNAVAILABLE",
        "/content/matching/task_codes/0",
    )
    assert repository.commands == []

    service.create_demand(
        principal=owner,
        taxonomy_bundle_id=taxonomy_id,
        content=demand_content(),
        client_reference="pg-choice-approved-create",
        expires_at=NOW + timedelta(days=1),
        idempotency_key="pg-choice-demand-create-approved-0001",
    )
    assert repository.commands[-1].operation is DemandPostgresOperation.CREATE
    repository.commands.clear()

    legacy_save = demand_content()
    legacy_save["skills"]["must_have"][0]["skill_code"] = (
        "GENERAL_RESEARCH"
    )
    with pytest.raises(EditorServiceError) as save_rejected:
        service.save_demand_draft(
            principal=owner,
            demand_id=demand_id,
            if_match=current.etag,
            base_version_id=version_id,
            taxonomy_bundle_id=taxonomy_id,
            content=legacy_save,
            idempotency_key="pg-choice-demand-save-0001",
        )
    assert (
        save_rejected.value.status,
        save_rejected.value.code,
        save_rejected.value.path,
    ) == (
        422,
        "EDITOR_CHOICE_UNAVAILABLE",
        "/content/skills/must_have/0/skill_code",
    )
    assert repository.commands == []

    service.save_demand_draft(
        principal=owner,
        demand_id=demand_id,
        if_match=current.etag,
        base_version_id=version_id,
        taxonomy_bundle_id=taxonomy_id,
        content=demand_content(),
        idempotency_key="pg-choice-demand-save-approved-0001",
    )
    assert repository.commands[-1].operation is (
        DemandPostgresOperation.CREATE_VERSION
    )
    repository.commands.clear()

    legacy_submit = demand_content()
    legacy_submit["risk"]["dependency_codes"] = ["DEPENDENCY.GENERAL"]
    legacy_version = replace(version, content=legacy_submit)
    repository.resource = replace(
        current,
        current_version=legacy_version,
        versions=(legacy_version,),
    )
    with pytest.raises(EditorServiceError) as submit_rejected:
        service.submit_demand(
            principal=owner,
            demand_id=demand_id,
            if_match=current.etag,
            idempotency_key="pg-choice-demand-submit-0001",
        )
    assert (
        submit_rejected.value.status,
        submit_rejected.value.code,
        submit_rejected.value.path,
    ) == (
        422,
        "EDITOR_CHOICE_UNAVAILABLE",
        "/content/risk/dependency_codes/0",
    )
    assert repository.commands == []

    repository.resource = current
    service.submit_demand(
        principal=owner,
        demand_id=demand_id,
        if_match=current.etag,
        idempotency_key="pg-choice-demand-submit-approved-0001",
    )
    assert repository.commands[-1].operation is DemandPostgresOperation.SUBMIT


def test_postgres_demand_owner_cancel_uses_closed_uow_authority_occ_and_receipt() -> None:
    demand_id = "30000000-0000-4000-8000-000000000073"
    owner = EditorPrincipal(
        user_id=ACTOR,
        session_id=SESSION,
        organization_id=ORG,
        role_codes=("DEMAND_OWNER",),
    )

    def etag(revision: int) -> str:
        digest = hashlib.sha256(
            f"DEMAND:{demand_id}:{revision}".encode("utf-8")
        ).hexdigest()[:24]
        return f'"demand-{revision}-{digest}"'

    class Authorities(_Authorities):
        def __init__(self) -> None:
            super().__init__()
            self.demand_calls = []

        def demand(
            self, *, principal, operation, demand_id, assignment_id=None
        ):
            self.demand_calls.append(
                (principal, operation, demand_id, assignment_id)
            )
            return DemandReadAuthority(operation, MARKER)

    class Repository:
        def __init__(self) -> None:
            self.commands = []
            self.completed = set()
            self.resource = EditorResourceDto(
                resource_type="DEMAND",
                object_id=demand_id,
                status="FUNDED",
                revision=1,
                etag=etag(1),
                capabilities=("CANCEL",),
                editable_paths=(),
                current_version=None,
                versions=(),
            )

        def get_demand(self, **_facts):
            return self.resource

        def execute_demand(self, command):
            self.commands.append(command)
            if command.scope.command_id in self.completed:
                return object()
            if command.expected_aggregate_version != self.resource.revision:
                raise DemandPostgresDatabaseError("PRECONDITION_FAILED")
            self.completed.add(command.scope.command_id)
            self.resource = replace(
                self.resource,
                status="CANCELLED",
                revision=2,
                etag=etag(2),
                capabilities=(),
            )
            return object()

    authorities = Authorities()
    repository = Repository()
    service = PostgresEditorService(
        repository=repository,
        authorities=authorities,
        evidence=_Evidence(),
        keys=_keys(),
        clock=_Clock(),
    )

    cancelled = service.cancel_demand(
        principal=owner,
        demand_id=demand_id,
        if_match=etag(1),
        reason_code="FUNDING_UNAVAILABLE",
        idempotency_key="pg-demand-cancel-command-0001",
    )
    assert (cancelled.status, cancelled.etag, cancelled.capabilities) == (
        "CANCELLED",
        etag(2),
        (),
    )
    command = repository.commands[-1]
    assert (
        command.operation,
        command.cancel_reason_code,
        command.expected_aggregate_version,
        command.receipt.command_name,
        command.receipt.canonical_path,
        command.scope.expected_authority_marker_sha256,
    ) == (
        DemandPostgresOperation.CANCEL_OWNER,
        "FUNDING_UNAVAILABLE",
        1,
        "CancelDemand",
        f"/v1/organizations/{ORG}/demands/{demand_id}/cancel",
        MARKER,
    )
    assert authorities.demand_calls[-1][1] is (
        DemandPostgresOperation.CANCEL_OWNER
    )

    replay = service.cancel_demand(
        principal=owner,
        demand_id=demand_id,
        if_match=etag(1),
        reason_code="FUNDING_UNAVAILABLE",
        idempotency_key="pg-demand-cancel-command-0001",
    )
    assert replay == cancelled
    assert repository.commands[-1].scope.command_id == command.scope.command_id

    with pytest.raises(EditorServiceError) as stale:
        service.cancel_demand(
            principal=owner,
            demand_id=demand_id,
            if_match=etag(1),
            reason_code="OWNER_WITHDREW",
            idempotency_key="pg-demand-cancel-command-0002",
        )
    assert (stale.value.status, stale.value.code, stale.value.etag) == (
        412,
        "PRECONDITION_FAILED",
        etag(2),
    )

    reviewer = replace(owner, role_codes=("OPERATIONS_REVIEWER",))
    calls_before = len(authorities.demand_calls)
    with pytest.raises(EditorServiceError) as unauthorized:
        service.cancel_demand(
            principal=reviewer,
            demand_id=demand_id,
            if_match=etag(2),
            reason_code="OWNER_WITHDREW",
            idempotency_key="pg-demand-cancel-command-0003",
        )
    assert (unauthorized.value.status, unauthorized.value.code) == (
        404,
        "RESOURCE_NOT_FOUND",
    )
    assert len(authorities.demand_calls) == calls_before


def test_runtime_secrets_are_not_rendered_and_connection_role_is_closed() -> None:
    keys = _keys()
    settings = EditorPsycopgConnectionSettings(
        conninfo="postgresql://profile_app:raw-password@db/pilot",
        expected_role="profile_app",
    )

    rendered = repr(keys) + repr(settings)
    for secret in (
        b"i" * 32,
        b"a" * 32,
        b"b" * 32,
        b"c" * 32,
        b"d" * 32,
        b"e" * 32,
    ):
        assert repr(secret) not in rendered
    assert "raw-password" not in rendered


def test_editor_keys_retain_zeroizable_runtime_carriers_without_copying() -> None:
    carriers = tuple(bytearray(bytes((index,)) * 32) for index in range(1, 7))
    keys = EditorPostgresKeys(
        id_key=carriers[0],
        profile_idempotency_key=carriers[1],
        profile_payload_key=carriers[2],
        demand_idempotency_key=carriers[3],
        demand_payload_key=carriers[4],
        demand_client_reference_key=carriers[5],
    )

    assert keys.id_key is carriers[0]
    for carrier in carriers:
        carrier[:] = b"\0" * len(carrier)
    assert all(set(value) == {0} for value in carriers)
    assert all(
        set(value) == {0}
        for value in (
            keys.id_key,
            keys.profile_idempotency_key,
            keys.profile_payload_key,
            keys.demand_idempotency_key,
            keys.demand_payload_key,
            keys.demand_client_reference_key,
        )
    )


def test_demand_read_authority_separates_owner_and_reviewer_organization() -> None:
    owner = DemandReadAuthority(DemandPostgresOperation.CREATE, MARKER)
    assert owner.assignment_id is None
    assert owner.organization_id is None

    reviewer = DemandReadAuthority(
        DemandPostgresOperation.REQUEST_CHANGES,
        MARKER,
        ASSIGNMENT,
        UUID(ORG),
    )
    assert reviewer.assignment_id == ASSIGNMENT
    assert reviewer.organization_id == UUID(ORG)

    with pytest.raises(ValueError, match="requires an organization"):
        DemandReadAuthority(
            DemandPostgresOperation.REQUEST_CHANGES,
            MARKER,
            ASSIGNMENT,
        )
    with pytest.raises(ValueError, match="cannot carry"):
        DemandReadAuthority(
            DemandPostgresOperation.CREATE,
            MARKER,
            organization_id=UUID(ORG),
        )


def test_profile_read_authority_binds_the_exact_user_operation() -> None:
    legacy = ProfileReadAuthority(MARKER)
    assert legacy.operation is CreatorProfilePostgresOperation.SAVE_DRAFT
    published = ProfileReadAuthority(
        MARKER,
        CreatorProfilePostgresOperation.PUBLISH,
    )
    assert published.operation is CreatorProfilePostgresOperation.PUBLISH
    with pytest.raises(ValueError, match="not user-bound"):
        ProfileReadAuthority(
            MARKER,
            CreatorProfilePostgresOperation.CAPTURE_MATCH_INPUTS,
        )


@pytest.mark.parametrize(
    ("operation", "terminal_status"),
    (
        (CreatorProfilePostgresOperation.PAUSE, "PAUSED"),
        (CreatorProfilePostgresOperation.RESUME, "ACTIVE"),
        (CreatorProfilePostgresOperation.ARCHIVE, "ARCHIVED"),
    ),
)
def test_completed_profile_lifecycle_receipt_precedes_state_hold_and_uow(
    operation: CreatorProfilePostgresOperation,
    terminal_status: str,
) -> None:
    profile_id = "30000000-0000-4000-8000-000000000081"
    principal = EditorPrincipal(
        user_id=ACTOR,
        session_id=SESSION,
        organization_id=None,
        role_codes=("CREATOR",),
    )
    final = _profile_resource(
        profile_id=profile_id,
        status=terminal_status,
        revision=3,
    )

    class Probe:
        def __init__(self):
            self.calls = []

        def read_completed(self, request):
            self.calls.append(request)
            return ProfileCompletedLifecycleReplayResult(
                profile_id=UUID(profile_id),
                operation=operation,
                aggregate_version=3,
                status=terminal_status,
            )

    class Repository:
        def __init__(self):
            self.reads = []

        def get_profile(self, **facts):
            self.reads.append(facts)
            return final

        @staticmethod
        def execute_profile(_command):
            raise AssertionError("completed Profile replay must not write")

    class Evidence(_Evidence):
        @staticmethod
        def profile_hold(**facts):
            raise AssertionError(f"completed Profile replay evaluated hold: {facts}")

    probe = Probe()
    repository = Repository()
    service = PostgresEditorService(
        repository=repository,
        authorities=_Authorities(),
        evidence=Evidence(),
        keys=_keys(),
        clock=_Clock(),
        completed_profile_lifecycle_receipts=probe,
    )

    result = _invoke_profile_lifecycle(
        service,
        operation=operation,
        principal=principal,
        profile_id=profile_id,
        if_match=_profile_etag(profile_id, 2),
        idempotency_key=f"{operation.name.lower()}-completed-replay-0001",
    )

    assert result is final
    assert len(probe.calls) == 1
    request = probe.calls[0]
    assert request.operation is operation
    assert request.expected_version == 2
    assert request.expected_authority_marker_sha256 == MARKER
    assert json.loads(request.canonical_payload) == {
        "operation": operation.value,
        "payload": {
            "profile_id": profile_id,
            "if_match": _profile_etag(profile_id, 2),
            **(
                {"reason_code": "OWNER_REQUEST"}
                if operation
                in {
                    CreatorProfilePostgresOperation.PAUSE,
                    CreatorProfilePostgresOperation.ARCHIVE,
                }
                else {}
            ),
        },
    }
    # The only read is the terminal projection after the receipt HIT. There is
    # no preflight state read, hold evaluation, or UoW execution.
    assert len(repository.reads) == 1
    assert repository.reads[0]["authority"].operation is operation


def test_completed_resume_receipt_accepts_preserved_draft_as_current() -> None:
    profile_id = "30000000-0000-4000-8000-000000000086"
    principal = EditorPrincipal(
        user_id=ACTOR,
        session_id=SESSION,
        organization_id=None,
        role_codes=("CREATOR",),
    )
    published = _profile_version()
    draft = replace(
        published,
        version_id="40000000-0000-4000-8000-000000000086",
        version_no=2,
        based_on_version_id=published.version_id,
        status="DRAFT",
        content={"identity": {"headline": "preserved draft"}},
    )
    final = replace(
        _profile_resource(
            profile_id=profile_id,
            status="ACTIVE",
            revision=3,
        ),
        current_version=draft,
        versions=(published, draft),
        capabilities=("SAVE_DRAFT", "PUBLISH", "PAUSE", "ARCHIVE"),
    )
    replay = ProfileCompletedLifecycleReplayResult(
        profile_id=UUID(profile_id),
        operation=CreatorProfilePostgresOperation.RESUME,
        aggregate_version=3,
        status="ACTIVE",
    )

    class Probe:
        @staticmethod
        def read_completed(_request):
            return replay

    class Repository:
        @staticmethod
        def get_profile(**_facts):
            return final

        @staticmethod
        def execute_profile(_command):
            raise AssertionError("completed Resume replay must not write")

    class Evidence(_Evidence):
        @staticmethod
        def profile_hold(**facts):
            raise AssertionError(f"completed Resume replay evaluated hold: {facts}")

    service = PostgresEditorService(
        repository=Repository(),
        authorities=_Authorities(),
        evidence=Evidence(),
        keys=_keys(),
        clock=_Clock(),
        completed_profile_lifecycle_receipts=Probe(),
    )

    result = service.resume_profile(
        principal=principal,
        profile_id=profile_id,
        if_match=_profile_etag(profile_id, 2),
        idempotency_key="resume-profile-preserved-draft-0001",
    )

    assert result is final
    assert result.current_version is draft
    assert {version.status for version in result.versions} == {
        "DRAFT",
        "PUBLISHED",
    }


def test_completed_archive_receipt_accepts_superseded_history() -> None:
    profile_id = "30000000-0000-4000-8000-000000000087"
    principal = EditorPrincipal(
        user_id=ACTOR,
        session_id=SESSION,
        organization_id=None,
        role_codes=("CREATOR",),
    )
    published = _profile_version()
    superseded = replace(
        published,
        version_id="40000000-0000-4000-8000-000000000087",
        status="SUPERSEDED",
    )
    retired = replace(
        published,
        version_id="40000000-0000-4000-8000-000000000088",
        version_no=2,
        based_on_version_id=superseded.version_id,
        status="RETIRED",
    )
    final = replace(
        _profile_resource(
            profile_id=profile_id,
            status="ARCHIVED",
            revision=3,
        ),
        versions=(superseded, retired),
    )
    replay = ProfileCompletedLifecycleReplayResult(
        profile_id=UUID(profile_id),
        operation=CreatorProfilePostgresOperation.ARCHIVE,
        aggregate_version=3,
        status="ARCHIVED",
    )

    class Probe:
        @staticmethod
        def read_completed(_request):
            return replay

    class Repository:
        @staticmethod
        def get_profile(**_facts):
            return final

        @staticmethod
        def execute_profile(_command):
            raise AssertionError("completed Archive replay must not write")

    service = PostgresEditorService(
        repository=Repository(),
        authorities=_Authorities(),
        evidence=_Evidence(),
        keys=_keys(),
        clock=_Clock(),
        completed_profile_lifecycle_receipts=Probe(),
    )

    result = service.archive_profile(
        principal=principal,
        profile_id=profile_id,
        if_match=_profile_etag(profile_id, 2),
        reason_code="OWNER_REQUEST",
        idempotency_key="archive-profile-superseded-history-0001",
    )

    assert result is final
    assert tuple(version.status for version in result.versions) == (
        "SUPERSEDED",
        "RETIRED",
    )


@pytest.mark.parametrize("illegal_status", ("DRAFT", "PUBLISHED"))
def test_completed_archive_receipt_rejects_active_version_history(
    illegal_status: str,
) -> None:
    profile_id = "30000000-0000-4000-8000-000000000089"
    principal = EditorPrincipal(
        user_id=ACTOR,
        session_id=SESSION,
        organization_id=None,
        role_codes=("CREATOR",),
    )
    final = replace(
        _profile_resource(
            profile_id=profile_id,
            status="ARCHIVED",
            revision=3,
        ),
        versions=(replace(_profile_version(), status=illegal_status),),
    )
    replay = ProfileCompletedLifecycleReplayResult(
        profile_id=UUID(profile_id),
        operation=CreatorProfilePostgresOperation.ARCHIVE,
        aggregate_version=3,
        status="ARCHIVED",
    )

    class Probe:
        @staticmethod
        def read_completed(_request):
            return replay

    class Repository:
        @staticmethod
        def get_profile(**_facts):
            return final

        @staticmethod
        def execute_profile(_command):
            raise AssertionError("invalid Archive projection must not write")

    service = PostgresEditorService(
        repository=Repository(),
        authorities=_Authorities(),
        evidence=_Evidence(),
        keys=_keys(),
        clock=_Clock(),
        completed_profile_lifecycle_receipts=Probe(),
    )

    with pytest.raises(EditorServiceError) as unavailable:
        service.archive_profile(
            principal=principal,
            profile_id=profile_id,
            if_match=_profile_etag(profile_id, 2),
            reason_code="OWNER_REQUEST",
            idempotency_key=(
                f"archive-profile-illegal-{illegal_status.lower()}-0001"
            ),
        )
    assert (unavailable.value.status, unavailable.value.code) == (
        503,
        "SERVICE_UNAVAILABLE",
    )


def test_profile_lifecycle_changed_payload_is_409_before_occ_or_hold() -> None:
    profile_id = "30000000-0000-4000-8000-000000000082"
    principal = EditorPrincipal(
        user_id=ACTOR,
        session_id=SESSION,
        organization_id=None,
        role_codes=("CREATOR",),
    )

    class Probe:
        def __init__(self):
            self.calls = []

        def read_completed(self, request):
            self.calls.append(request)
            raise ProfileCompletedLifecycleReplayError("IDEMPOTENCY_KEY_REUSED")

    class Repository:
        @staticmethod
        def get_profile(**facts):
            raise AssertionError(f"payload conflict read Profile state: {facts}")

        @staticmethod
        def execute_profile(command):
            raise AssertionError(f"payload conflict wrote Profile: {command}")

    class Evidence(_Evidence):
        @staticmethod
        def profile_hold(**facts):
            raise AssertionError(f"payload conflict evaluated hold: {facts}")

    probe = Probe()
    service = PostgresEditorService(
        repository=Repository(),
        authorities=_Authorities(),
        evidence=Evidence(),
        keys=_keys(),
        clock=_Clock(),
        completed_profile_lifecycle_receipts=probe,
    )

    with pytest.raises(EditorServiceError) as conflict:
        service.resume_profile(
            principal=principal,
            profile_id=profile_id,
            if_match='"malformed-changed-if-match"',
            idempotency_key="resume-profile-conflict-0001",
        )
    assert (conflict.value.status, conflict.value.code) == (
        409,
        "IDEMPOTENCY_KEY_REUSED",
    )
    assert len(probe.calls) == 1
    assert probe.calls[0].expected_version == 1


def test_profile_pause_commit_unknown_recovers_completed_receipt() -> None:
    profile_id = "30000000-0000-4000-8000-000000000083"
    principal = EditorPrincipal(
        user_id=ACTOR,
        session_id=SESSION,
        organization_id=None,
        role_codes=("CREATOR",),
    )
    active = _profile_resource(
        profile_id=profile_id,
        status="ACTIVE",
        revision=2,
    )
    final = _profile_resource(
        profile_id=profile_id,
        status="PAUSED",
        revision=3,
    )
    replay = ProfileCompletedLifecycleReplayResult(
        profile_id=UUID(profile_id),
        operation=CreatorProfilePostgresOperation.PAUSE,
        aggregate_version=3,
        status="PAUSED",
    )

    class Probe:
        def __init__(self):
            self.results = [None, replay]
            self.calls = 0

        def read_completed(self, _request):
            self.calls += 1
            return self.results.pop(0)

    class Repository:
        def __init__(self):
            self.results = [active, final]
            self.writes = 0

        def get_profile(self, **_facts):
            return self.results.pop(0)

        def execute_profile(self, _command):
            self.writes += 1
            raise CreatorProfilePostgresCommitOutcomeUnknownError()

    probe = Probe()
    repository = Repository()
    service = PostgresEditorService(
        repository=repository,
        authorities=_Authorities(),
        evidence=_Evidence(),
        keys=_keys(),
        clock=_Clock(),
        completed_profile_lifecycle_receipts=probe,
    )

    result = service.pause_profile(
        principal=principal,
        profile_id=profile_id,
        if_match=active.etag,
        reason_code="OWNER_REQUEST",
        idempotency_key="pause-profile-commit-unknown-0001",
    )

    assert result is final
    assert probe.calls == 2
    assert repository.writes == 1


def test_completed_profile_lifecycle_projection_drift_fails_closed() -> None:
    profile_id = "30000000-0000-4000-8000-000000000084"
    principal = EditorPrincipal(
        user_id=ACTOR,
        session_id=SESSION,
        organization_id=None,
        role_codes=("CREATOR",),
    )
    replay = ProfileCompletedLifecycleReplayResult(
        profile_id=UUID(profile_id),
        operation=CreatorProfilePostgresOperation.PAUSE,
        aggregate_version=3,
        status="PAUSED",
    )
    drifted = replace(
        _profile_resource(
            profile_id=profile_id,
            status="PAUSED",
            revision=3,
        ),
        etag='"creator_profile-3-drifted"',
    )

    class Probe:
        @staticmethod
        def read_completed(_request):
            return replay

    class Repository:
        @staticmethod
        def get_profile(**_facts):
            return drifted

        @staticmethod
        def execute_profile(_command):
            raise AssertionError("drifted replay must not write")

    service = PostgresEditorService(
        repository=Repository(),
        authorities=_Authorities(),
        evidence=_Evidence(),
        keys=_keys(),
        clock=_Clock(),
        completed_profile_lifecycle_receipts=Probe(),
    )
    with pytest.raises(EditorServiceError) as unavailable:
        service.pause_profile(
            principal=principal,
            profile_id=profile_id,
            if_match=_profile_etag(profile_id, 2),
            reason_code="OWNER_REQUEST",
            idempotency_key="pause-profile-drifted-replay-0001",
        )
    assert (unavailable.value.status, unavailable.value.code) == (
        503,
        "SERVICE_UNAVAILABLE",
    )


@pytest.mark.parametrize(
    "drift",
    (
        "PAUSE_CAPABILITIES",
        "RESUME_CAPABILITIES",
        "RESUME_EDITABLE_PATHS",
        "CURRENT_VERSION_VALUE",
    ),
)
def test_completed_profile_lifecycle_capability_and_current_drift_fails_closed(
    drift: str,
) -> None:
    profile_id = "30000000-0000-4000-8000-000000000090"
    principal = EditorPrincipal(
        user_id=ACTOR,
        session_id=SESSION,
        organization_id=None,
        role_codes=("CREATOR",),
    )
    operation = (
        CreatorProfilePostgresOperation.RESUME
        if drift.startswith("RESUME")
        else CreatorProfilePostgresOperation.PAUSE
    )
    status = "ACTIVE" if operation is CreatorProfilePostgresOperation.RESUME else "PAUSED"
    final = _profile_resource(
        profile_id=profile_id,
        status=status,
        revision=3,
    )
    if drift == "PAUSE_CAPABILITIES":
        final = replace(final, capabilities=("ARCHIVE",))
    elif drift == "RESUME_CAPABILITIES":
        final = replace(
            final,
            capabilities=("SAVE_DRAFT", "PUBLISH", "PAUSE", "ARCHIVE"),
        )
    elif drift == "RESUME_EDITABLE_PATHS":
        final = replace(final, editable_paths=())
    else:
        assert final.current_version is not None
        final = replace(
            final,
            current_version=replace(
                final.current_version,
                content={"identity": {"headline": "drifted current value"}},
            ),
        )
    replay = ProfileCompletedLifecycleReplayResult(
        profile_id=UUID(profile_id),
        operation=operation,
        aggregate_version=3,
        status=status,
    )

    class Probe:
        @staticmethod
        def read_completed(_request):
            return replay

    class Repository:
        @staticmethod
        def get_profile(**_facts):
            return final

        @staticmethod
        def execute_profile(_command):
            raise AssertionError("drifted lifecycle replay must not write")

    service = PostgresEditorService(
        repository=Repository(),
        authorities=_Authorities(),
        evidence=_Evidence(),
        keys=_keys(),
        clock=_Clock(),
        completed_profile_lifecycle_receipts=Probe(),
    )

    with pytest.raises(EditorServiceError) as unavailable:
        _invoke_profile_lifecycle(
            service,
            operation=operation,
            principal=principal,
            profile_id=profile_id,
            if_match=_profile_etag(profile_id, 2),
            idempotency_key=f"profile-lifecycle-drift-{drift.lower()}-0001",
        )
    assert (unavailable.value.status, unavailable.value.code) == (
        503,
        "SERVICE_UNAVAILABLE",
    )


@pytest.mark.parametrize(
    "operation",
    (
        CreatorProfilePostgresOperation.PAUSE,
        CreatorProfilePostgresOperation.ARCHIVE,
    ),
)
def test_profile_pause_and_archive_miss_never_evaluate_hold(
    operation: CreatorProfilePostgresOperation,
) -> None:
    profile_id = "30000000-0000-4000-8000-000000000085"
    principal = EditorPrincipal(
        user_id=ACTOR,
        session_id=SESSION,
        organization_id=None,
        role_codes=("CREATOR",),
    )
    current = _profile_resource(
        profile_id=profile_id,
        status="ACTIVE",
        revision=2,
    )
    final_status = (
        "PAUSED"
        if operation is CreatorProfilePostgresOperation.PAUSE
        else "ARCHIVED"
    )
    final = _profile_resource(
        profile_id=profile_id,
        status=final_status,
        revision=3,
    )

    class Probe:
        @staticmethod
        def read_completed(_request):
            return None

    class Repository:
        def __init__(self):
            self.results = [current, final]
            self.commands = []

        def get_profile(self, **_facts):
            return self.results.pop(0)

        def execute_profile(self, command):
            self.commands.append(command)

    class Evidence(_Evidence):
        @staticmethod
        def profile_hold(**facts):
            raise AssertionError(f"{operation.name} evaluated hold: {facts}")

    repository = Repository()
    service = PostgresEditorService(
        repository=repository,
        authorities=_Authorities(),
        evidence=Evidence(),
        keys=_keys(),
        clock=_Clock(),
        completed_profile_lifecycle_receipts=Probe(),
    )

    result = _invoke_profile_lifecycle(
        service,
        operation=operation,
        principal=principal,
        profile_id=profile_id,
        if_match=current.etag,
        idempotency_key=f"{operation.name.lower()}-profile-miss-0001",
    )

    assert result is final
    assert len(repository.commands) == 1
    assert repository.commands[0].operation is operation
    assert repository.commands[0].reason_code == "OWNER_REQUEST"


def test_verify_builds_exact_assignment_bound_command_and_server_evidence_digest() -> None:
    demand_id = "30000000-0000-4000-8000-000000000001"
    version_id = "40000000-0000-4000-8000-000000000001"
    taxonomy_id = "50000000-0000-4000-8000-000000000001"
    content = {"problem": {"background": "synthetic"}}
    content_hash = hashlib.sha256(b"reviewed-demand-content").digest()
    current = EditorResourceDto(
        resource_type="DEMAND",
        object_id=demand_id,
        status="SUBMITTED",
        revision=2,
        etag='"demand-2"',
        capabilities=("VERIFY",),
        editable_paths=(),
        current_version=EditorVersionDto(
            version_id=version_id,
            version_no=1,
            based_on_version_id=None,
            status="SUBMITTED",
            content=content,
            content_sha256=content_hash.hex(),
            taxonomy_bundle_id=taxonomy_id,
            created_at=NOW - timedelta(days=1),
        ),
        versions=(),
    )

    class Authorities(_Authorities):
        def demand(self, **facts):
            assert facts == {
                "principal": reviewer,
                "operation": DemandPostgresOperation.VERIFY,
                "demand_id": demand_id,
                "assignment_id": str(ASSIGNMENT),
            }
            return DemandReadAuthority(
                DemandPostgresOperation.VERIFY,
                MARKER,
                ASSIGNMENT,
                UUID(ORG),
            )

    class Repository(_Repository):
        def __init__(self):
            super().__init__()
            self.commands = []

        def get_demand(self, **_facts):
            return current

        def execute_demand(self, command):
            self.commands.append(command)

    class Evidence(_Evidence):
        def __init__(self):
            super().__init__()
            self.demand_calls = []

        def demand_content_policy(self, **facts):
            self.demand_calls.append(("policy", facts))
            return DemandPostgresContentPolicyEvidence(
                demand_id=UUID(demand_id),
                demand_version_id=UUID(version_id),
                content_sha256=content_hash,
                decision="ALLOW",
                policy_version="demand-content-policy-v1",
                result_sha256=hashlib.sha256(b"policy").digest(),
                evaluated_at=NOW - timedelta(seconds=1),
                valid_until=NOW + timedelta(minutes=5),
            )

        def demand_hold(self, **facts):
            self.demand_calls.append(("hold", facts))
            return DemandPostgresHoldEvidence(
                actor_id=UUID(ACTOR),
                organization_id=UUID(ORG),
                demand_id=UUID(demand_id),
                prospective_aggregate_version=3,
                demand_version_id=UUID(version_id),
                content_sha256=content_hash,
                action="VERIFY_DEMAND",
                decision="ALLOW",
                policy_version="demand-safety-hold-v1",
                evaluated_at=NOW - timedelta(seconds=1),
                valid_until=NOW + timedelta(minutes=5),
            )

        def demand_rules(self, **facts):
            self.demand_calls.append(("rules", facts))
            return DemandPostgresRuleRequirement(
                taxonomy_bundle_id=UUID(taxonomy_id),
                budget_rule_bundle_id=UUID("51000000-0000-4000-8000-000000000001"),
                risk_rule_bundle_id=UUID("52000000-0000-4000-8000-000000000001"),
                matching_rule_bundle_id=UUID("53000000-0000-4000-8000-000000000001"),
                reason_code_bundle_id=UUID("54000000-0000-4000-8000-000000000001"),
                composite_rule_requirement_id=UUID("55000000-0000-4000-8000-000000000001"),
                requirement_sha256=hashlib.sha256(b"rules").digest(),
                effective_at=NOW - timedelta(days=1),
                effective_until=NOW + timedelta(days=1),
            )

    reviewer = EditorPrincipal(
        user_id=ACTOR,
        session_id=SESSION,
        organization_id=None,
        role_codes=("OPERATIONS_REVIEWER",),
        workspace_id=f"platform:{ACTOR}",
        workspace_kind="PLATFORM",
        membership_id=None,
        organization_role_codes=(),
        user_role_codes=(),
        platform_duty_codes=("OPERATIONS_REVIEWER",),
        principal_marker_sha256=MARKER,
    )
    repository = Repository()
    evidence = Evidence()
    service = PostgresEditorService(
        repository=repository,
        authorities=Authorities(),
        evidence=evidence,
        keys=_keys(),
        clock=_Clock(),
    )

    service.verify_demand(
        principal=reviewer,
        demand_id=demand_id,
        assignment_id=str(ASSIGNMENT),
        if_match='"demand-2"',
        budget_health_code="HEALTHY",
        risk_code="STANDARD",
        evidence_codes=("SCOPE_COMPLETE", "ACCEPTANCE_TESTABLE"),
        idempotency_key="verify-demand-review-0001",
    )

    command = repository.commands[0]
    expected_digest = hashlib.sha256(
        json.dumps(
            {"evidence_codes": ("ACCEPTANCE_TESTABLE", "SCOPE_COMPLETE")},
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    ).digest()
    assert command.operation is DemandPostgresOperation.VERIFY
    assert command.scope.organization_id == UUID(ORG)
    assert command.assignment_id == ASSIGNMENT
    assert command.evidence_summary_sha256 == expected_digest
    assert command.receipt.canonical_path.endswith(f"/{ASSIGNMENT}/verify")
    assert all(call[1]["organization_id"] == UUID(ORG) for call in evidence.demand_calls)


def test_completed_verify_receipt_precedes_active_target_discovery() -> None:
    demand_id = "30000000-0000-4000-8000-000000000009"
    version_id = "40000000-0000-4000-8000-000000000009"
    revision = 3
    terminal_digest = hashlib.sha256(
        f"DEMAND:{demand_id}:{revision}".encode("utf-8")
    ).hexdigest()[:24]
    digest = hashlib.sha256(
        f"DEMAND:{demand_id}:2".encode("utf-8")
    ).hexdigest()[:24]
    if_match = f'"demand-2-{digest}"'
    reviewer = EditorPrincipal(
        user_id=ACTOR,
        session_id=SESSION,
        organization_id=None,
        role_codes=("OPERATIONS_REVIEWER",),
    )
    final = EditorResourceDto(
        resource_type="DEMAND",
        object_id=demand_id,
        status="VERIFIED",
        revision=revision,
        etag=f'"demand-{revision}-{terminal_digest}"',
        capabilities=(),
        editable_paths=(),
        current_version=EditorVersionDto(
            version_id=version_id,
            version_no=1,
            based_on_version_id=None,
            status="COMMITTED",
            content={},
            content_sha256=hashlib.sha256(b"version").hexdigest(),
            taxonomy_bundle_id="50000000-0000-4000-8000-000000000009",
            created_at=NOW,
        ),
        versions=(),
        findings=(
            EditorFindingDto(
                finding_id="60000000-0000-4000-8000-000000000009",
                version_id=version_id,
                assignment_id=str(ASSIGNMENT),
                result="VERIFIED",
                reason_codes=(),
                required_field_paths=(),
                reviewed_at=NOW,
            ),
        ),
    )

    class Probe:
        def __init__(self):
            self.calls = []

        def read_completed(self, request):
            self.calls.append(request)
            return DemandCompletedVerifyReplayResult(
                organization_id=UUID(ORG),
                authority_marker_sha256=MARKER,
                aggregate_version=revision,
                demand_version_id=UUID(version_id),
            )

    class Repository:
        def __init__(self):
            self.reads = []

        def get_demand(self, **facts):
            self.reads.append(facts)
            return final

        def execute_demand(self, _command):
            raise AssertionError("completed replay must not write")

    class Authorities(_Authorities):
        def demand(self, **facts):
            raise AssertionError(f"ACTIVE discovery ran for replay: {facts}")

    class Evidence(_Evidence):
        def __getattr__(self, name):
            raise AssertionError(f"evidence ran for replay: {name}")

    probe = Probe()
    repository = Repository()
    service = PostgresEditorService(
        repository=repository,
        authorities=Authorities(),
        evidence=Evidence(),
        keys=_keys(),
        clock=_Clock(),
        completed_verify_receipts=probe,
    )

    result = service.verify_demand(
        principal=reviewer,
        demand_id=demand_id,
        assignment_id=str(ASSIGNMENT),
        if_match=if_match,
        budget_health_code="HEALTHY",
        risk_code="STANDARD",
        evidence_codes=("SCOPE_COMPLETE",),
        idempotency_key="verify-completed-replay-0001",
    )

    assert result is final
    assert len(probe.calls) == 1
    assert probe.calls[0].expected_version == 2
    assert len(repository.reads) == 1
    assert repository.reads[0]["authority"].organization_id == UUID(ORG)

    final = replace(final, etag='"demand-3-drifted"')
    with pytest.raises(EditorServiceError) as drifted:
        service.verify_demand(
            principal=reviewer,
            demand_id=demand_id,
            assignment_id=str(ASSIGNMENT),
            if_match=if_match,
            budget_health_code="HEALTHY",
            risk_code="STANDARD",
            evidence_codes=("SCOPE_COMPLETE",),
            idempotency_key="verify-completed-replay-0001",
        )
    assert (drifted.value.status, drifted.value.code) == (
        503,
        "SERVICE_UNAVAILABLE",
    )


def test_verify_miss_then_concurrent_completion_reprobes_after_discovery_404() -> None:
    demand_id = "30000000-0000-4000-8000-000000000009"
    version_id = "40000000-0000-4000-8000-000000000009"
    revision = 3
    terminal_digest = hashlib.sha256(
        f"DEMAND:{demand_id}:{revision}".encode("utf-8")
    ).hexdigest()[:24]
    reviewer = EditorPrincipal(
        user_id=ACTOR,
        session_id=SESSION,
        organization_id=None,
        role_codes=("OPERATIONS_REVIEWER",),
    )
    replay = DemandCompletedVerifyReplayResult(
        organization_id=UUID(ORG),
        authority_marker_sha256=MARKER,
        aggregate_version=revision,
        demand_version_id=UUID(version_id),
    )

    class Probe:
        def __init__(self):
            self.results = [None, replay]
            self.calls = 0

        def read_completed(self, _request):
            self.calls += 1
            return self.results.pop(0)

    class Authorities(_Authorities):
        def demand(self, **_facts):
            raise EditorServiceError(status=404, code="RESOURCE_NOT_FOUND")

    class Repository:
        def get_demand(self, **_facts):
            return EditorResourceDto(
                resource_type="DEMAND",
                object_id=demand_id,
                status="VERIFIED",
                revision=revision,
                etag=f'"demand-{revision}-{terminal_digest}"',
                capabilities=(),
                editable_paths=(),
                current_version=EditorVersionDto(
                    version_id=version_id,
                    version_no=1,
                    based_on_version_id=None,
                    status="COMMITTED",
                    content={},
                    content_sha256=hashlib.sha256(b"version").hexdigest(),
                    taxonomy_bundle_id="50000000-0000-4000-8000-000000000009",
                    created_at=NOW,
                ),
                versions=(),
                findings=(
                    EditorFindingDto(
                        finding_id="60000000-0000-4000-8000-000000000009",
                        version_id=version_id,
                        assignment_id=str(ASSIGNMENT),
                        result="VERIFIED",
                        reason_codes=(),
                        required_field_paths=(),
                        reviewed_at=NOW,
                    ),
                ),
            )

        def execute_demand(self, _command):
            raise AssertionError("concurrent recovery must not write")

    probe = Probe()
    service = PostgresEditorService(
        repository=Repository(),
        authorities=Authorities(),
        evidence=_Evidence(),
        keys=_keys(),
        clock=_Clock(),
        completed_verify_receipts=probe,
    )

    result = service.verify_demand(
        principal=reviewer,
        demand_id=demand_id,
        assignment_id=str(ASSIGNMENT),
        if_match='"stale"',
        budget_health_code="HEALTHY",
        risk_code="STANDARD",
        evidence_codes=("SCOPE_COMPLETE",),
        idempotency_key="verify-concurrent-replay-0001",
    )

    assert result.status == "VERIFIED"
    assert probe.calls == 2


def test_verify_miss_then_concurrent_completion_reprobes_after_precondition_412() -> None:
    demand_id = "30000000-0000-4000-8000-000000000009"
    version_id = "40000000-0000-4000-8000-000000000009"
    replay_revision = 3
    terminal_digest = hashlib.sha256(
        f"DEMAND:{demand_id}:{replay_revision}".encode("utf-8")
    ).hexdigest()[:24]
    active_digest = hashlib.sha256(
        f"DEMAND:{demand_id}:2".encode("utf-8")
    ).hexdigest()[:24]
    reviewer = EditorPrincipal(
        user_id=ACTOR,
        session_id=SESSION,
        organization_id=None,
        role_codes=("OPERATIONS_REVIEWER",),
    )
    replay = DemandCompletedVerifyReplayResult(
        organization_id=UUID(ORG),
        authority_marker_sha256=MARKER,
        aggregate_version=replay_revision,
        demand_version_id=UUID(version_id),
    )
    version = EditorVersionDto(
        version_id=version_id,
        version_no=1,
        based_on_version_id=None,
        status="COMMITTED",
        content={},
        content_sha256=hashlib.sha256(b"version").hexdigest(),
        taxonomy_bundle_id="50000000-0000-4000-8000-000000000009",
        created_at=NOW,
    )
    active = EditorResourceDto(
        resource_type="DEMAND",
        object_id=demand_id,
        status="SUBMITTED",
        revision=2,
        etag=f'"demand-2-{active_digest}"',
        capabilities=("VERIFY",),
        editable_paths=(),
        current_version=version,
        versions=(),
    )
    terminal = replace(
        active,
        status="VERIFIED",
        revision=replay_revision,
        etag=f'"demand-{replay_revision}-{terminal_digest}"',
        capabilities=(),
        findings=(
            EditorFindingDto(
                finding_id="60000000-0000-4000-8000-000000000009",
                version_id=version_id,
                assignment_id=str(ASSIGNMENT),
                result="VERIFIED",
                reason_codes=(),
                required_field_paths=(),
                reviewed_at=NOW,
            ),
        ),
    )

    class Probe:
        def __init__(self):
            self.results = [None, replay]

        def read_completed(self, _request):
            return self.results.pop(0)

    class Authorities(_Authorities):
        def demand(self, **_facts):
            return DemandReadAuthority(
                DemandPostgresOperation.VERIFY,
                MARKER,
                ASSIGNMENT,
                UUID(ORG),
            )

    class Repository:
        def __init__(self):
            self.results = [active, terminal]

        def get_demand(self, **_facts):
            return self.results.pop(0)

        def execute_demand(self, _command):
            raise AssertionError("precondition recovery must not write")

    service = PostgresEditorService(
        repository=Repository(),
        authorities=Authorities(),
        evidence=_Evidence(),
        keys=_keys(),
        clock=_Clock(),
        completed_verify_receipts=Probe(),
    )
    result = service.verify_demand(
        principal=reviewer,
        demand_id=demand_id,
        assignment_id=str(ASSIGNMENT),
        if_match='"invalid"',
        budget_health_code="HEALTHY",
        risk_code="STANDARD",
        evidence_codes=("SCOPE_COMPLETE",),
        idempotency_key="verify-concurrent-precondition-0001",
    )
    assert result is terminal

    class MissProbe:
        def __init__(self):
            self.calls = 0

        def read_completed(self, _request):
            self.calls += 1
            return None

    class ActiveRepository:
        @staticmethod
        def get_demand(**_facts):
            return active

        @staticmethod
        def execute_demand(_command):
            raise AssertionError("invalid If-Match must not write")

    miss_probe = MissProbe()
    miss_service = PostgresEditorService(
        repository=ActiveRepository(),
        authorities=Authorities(),
        evidence=_Evidence(),
        keys=_keys(),
        clock=_Clock(),
        completed_verify_receipts=miss_probe,
    )
    with pytest.raises(EditorServiceError) as stale:
        miss_service.verify_demand(
            principal=reviewer,
            demand_id=demand_id,
            assignment_id=str(ASSIGNMENT),
            if_match='"invalid"',
            budget_health_code="HEALTHY",
            risk_code="STANDARD",
            evidence_codes=("SCOPE_COMPLETE",),
            idempotency_key="verify-new-invalid-key-0001",
        )
    assert (stale.value.status, stale.value.code) == (
        412,
        "PRECONDITION_FAILED",
    )
    assert miss_probe.calls == 2

    class CommitUnknownProbe:
        def __init__(self):
            self.results = [None, replay]
            self.calls = 0

        def read_completed(self, _request):
            self.calls += 1
            return self.results.pop(0)

    class CommitUnknownRepository:
        def __init__(self):
            self.results = [active, terminal]
            self.writes = 0

        def get_demand(self, **_facts):
            return self.results.pop(0)

        def execute_demand(self, _command):
            self.writes += 1
            raise DemandPostgresCommitOutcomeUnknownError()

    class CommitEvidence:
        @staticmethod
        def demand_content_policy(**_facts):
            return DemandPostgresContentPolicyEvidence(
                demand_id=UUID(demand_id),
                demand_version_id=UUID(version_id),
                content_sha256=bytes.fromhex(version.content_sha256),
                decision="ALLOW",
                policy_version="demand-content-policy-v1",
                result_sha256=hashlib.sha256(b"policy").digest(),
                evaluated_at=NOW - timedelta(seconds=1),
                valid_until=NOW + timedelta(minutes=5),
            )

        @staticmethod
        def demand_hold(**_facts):
            return DemandPostgresHoldEvidence(
                actor_id=UUID(ACTOR),
                organization_id=UUID(ORG),
                demand_id=UUID(demand_id),
                prospective_aggregate_version=3,
                demand_version_id=UUID(version_id),
                content_sha256=bytes.fromhex(version.content_sha256),
                action="VERIFY_DEMAND",
                decision="ALLOW",
                policy_version="demand-safety-hold-v1",
                evaluated_at=NOW - timedelta(seconds=1),
                valid_until=NOW + timedelta(minutes=5),
            )

        @staticmethod
        def demand_rules(**_facts):
            return DemandPostgresRuleRequirement(
                taxonomy_bundle_id=UUID(version.taxonomy_bundle_id),
                budget_rule_bundle_id=UUID(
                    "51000000-0000-4000-8000-000000000001"
                ),
                risk_rule_bundle_id=UUID(
                    "52000000-0000-4000-8000-000000000001"
                ),
                matching_rule_bundle_id=UUID(
                    "53000000-0000-4000-8000-000000000001"
                ),
                reason_code_bundle_id=UUID(
                    "54000000-0000-4000-8000-000000000001"
                ),
                composite_rule_requirement_id=UUID(
                    "55000000-0000-4000-8000-000000000001"
                ),
                requirement_sha256=hashlib.sha256(b"rules").digest(),
                effective_at=NOW - timedelta(days=1),
                effective_until=NOW + timedelta(days=1),
            )

    commit_probe = CommitUnknownProbe()
    commit_repository = CommitUnknownRepository()
    commit_service = PostgresEditorService(
        repository=commit_repository,
        authorities=Authorities(),
        evidence=CommitEvidence(),
        keys=_keys(),
        clock=_Clock(),
        completed_verify_receipts=commit_probe,
    )
    assert commit_service.verify_demand(
        principal=reviewer,
        demand_id=demand_id,
        assignment_id=str(ASSIGNMENT),
        if_match=active.etag,
        budget_health_code="HEALTHY",
        risk_code="STANDARD",
        evidence_codes=("SCOPE_COMPLETE",),
        idempotency_key="verify-commit-unknown-0001",
    ) is terminal
    assert commit_probe.calls == 2
    assert commit_repository.writes == 1


def test_verify_new_key_completed_assignment_preserves_original_404() -> None:
    class Probe:
        def __init__(self):
            self.calls = 0

        def read_completed(self, _request):
            self.calls += 1
            return None

    class Authorities(_Authorities):
        def demand(self, **_facts):
            raise EditorServiceError(status=404, code="RESOURCE_NOT_FOUND")

    probe = Probe()
    service = PostgresEditorService(
        repository=_DemandRepositoryProbe(),
        authorities=Authorities(),
        evidence=_Evidence(),
        keys=_keys(),
        clock=_Clock(),
        completed_verify_receipts=probe,
    )
    reviewer = EditorPrincipal(
        user_id=ACTOR,
        session_id=SESSION,
        organization_id=None,
        role_codes=("OPERATIONS_REVIEWER",),
    )
    with pytest.raises(EditorServiceError) as missing:
        service.verify_demand(
            principal=reviewer,
            demand_id="30000000-0000-4000-8000-000000000009",
            assignment_id=str(ASSIGNMENT),
            if_match='"invalid"',
            budget_health_code="HEALTHY",
            risk_code="STANDARD",
            evidence_codes=("SCOPE_COMPLETE",),
            idempotency_key="verify-new-completed-key-0001",
        )
    assert (missing.value.status, missing.value.code) == (
        404,
        "RESOURCE_NOT_FOUND",
    )
    assert probe.calls == 2


def test_completed_verify_receipt_payload_conflict_is_not_a_miss() -> None:
    class Probe:
        @staticmethod
        def read_completed(_request):
            raise DemandCompletedVerifyReplayError("IDEMPOTENCY_KEY_REUSED")

    reviewer = EditorPrincipal(
        user_id=ACTOR,
        session_id=SESSION,
        organization_id=None,
        role_codes=("OPERATIONS_REVIEWER",),
    )
    service = PostgresEditorService(
        repository=_DemandRepositoryProbe(),
        authorities=_Authorities(),
        evidence=_Evidence(),
        keys=_keys(),
        clock=_Clock(),
        completed_verify_receipts=Probe(),
    )

    with pytest.raises(EditorServiceError) as conflict:
        service.verify_demand(
            principal=reviewer,
            demand_id="30000000-0000-4000-8000-000000000009",
            assignment_id=str(ASSIGNMENT),
            if_match='"stale"',
            budget_health_code="HEALTHY",
            risk_code="STANDARD",
            evidence_codes=("SCOPE_COMPLETE",),
            idempotency_key="verify-conflict-replay-0001",
        )
    assert (conflict.value.status, conflict.value.code) == (
        409,
        "IDEMPOTENCY_KEY_REUSED",
    )
