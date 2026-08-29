"""TDD for session-bound editor target discovery and object authority."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from types import SimpleNamespace
from uuid import UUID

import pytest

from desire_platform.creator_profile.adapters.postgres import (
    CreatorProfilePostgresOperation,
)
from desire_platform.demand.adapters.postgres import DemandPostgresOperation
from desire_platform.identity_access.adapters.postgres.authority_markers import (
    DemandOwnerAuthorityMarkerRequest,
    DemandReviewerAuthorityMarkerRequest,
    ProfileSelfAuthorityMarkerRequest,
)
from desire_platform.internal_pilot.editor import (
    EditorPrincipal,
    EditorServiceError,
    PostgresEditorAuthorityProvider,
)


USER = "10000000-0000-4000-8000-000000000001"
SESSION = "20000000-0000-4000-8000-000000000001"
ORG = "30000000-0000-4000-8000-000000000001"
MEMBERSHIP = "40000000-0000-4000-8000-000000000001"
PROFILE = "50000000-0000-4000-8000-000000000001"
DEMAND = "60000000-0000-4000-8000-000000000001"
ASSIGNMENT = "70000000-0000-4000-8000-000000000001"
PRINCIPAL_MARKER = hashlib.sha256(b"principal").digest()
PROFILE_MARKER = hashlib.sha256(b"profile").digest()
OWNER_MARKER = hashlib.sha256(b"owner").digest()
REVIEWER_MARKER = hashlib.sha256(b"reviewer").digest()


@dataclass
class _Info:
    transaction_status: int = 0


class _Result:
    def __init__(self, *, one=None, all_rows=()):
        self._one = one
        self._all = tuple(all_rows)

    def fetchone(self):
        return self._one

    def fetchall(self):
        return self._all


class _Connection:
    def __init__(self, role, rows):
        self.role = role
        self.rows = tuple(rows)
        self.info = _Info()
        self.commands = []

    def execute(self, statement, parameters=None):
        self.commands.append((statement, parameters))
        if statement.startswith("SELECT current_user,session_user"):
            return _Result(one=(self.role, self.role, 180004))
        if "list_owned_profile_targets_v1" in statement:
            return _Result(all_rows=self.rows)
        if "list_owned_demand_targets_v1" in statement:
            return _Result(all_rows=self.rows)
        if "list_reviewer_demand_targets_v1" in statement:
            return _Result(all_rows=self.rows)
        if "to_regprocedure" in statement:
            return _Result(one=(True, True))
        if statement.startswith("SELECT pg_catalog.set_config"):
            return _Result(one=(parameters[1],))
        return _Result()


class _Connections:
    def __init__(self, role, rows):
        self.role = role
        self.rows = rows
        self.released = []
        self.discarded = []

    def checkout(self):
        return _Connection(self.role, self.rows)

    def release(self, connection):
        self.released.append(connection)

    def discard(self, connection):
        self.discarded.append(connection)


class _Markers:
    def __init__(self, profile, owner, reviewer):
        self._profile_connections = profile
        self._demand_owner_connections = owner
        self._demand_reviewer_connections = reviewer
        self.requests = []

    def resolve_profile_self(self, request):
        assert isinstance(request, ProfileSelfAuthorityMarkerRequest)
        self.requests.append(request)
        return PROFILE_MARKER

    def resolve_demand_owner(self, request):
        assert isinstance(request, DemandOwnerAuthorityMarkerRequest)
        self.requests.append(request)
        return OWNER_MARKER

    def resolve_demand_reviewer(self, request):
        assert isinstance(request, DemandReviewerAuthorityMarkerRequest)
        self.requests.append(request)
        return REVIEWER_MARKER


def _principal(kind):
    facts = {
        "user_id": USER,
        "session_id": SESSION,
        "principal_marker_sha256": PRINCIPAL_MARKER,
    }
    if kind == "PERSONAL":
        return EditorPrincipal(
            **facts,
            organization_id=None,
            role_codes=("CREATOR",),
            workspace_id=f"personal:{USER}",
            workspace_kind=kind,
            user_role_codes=("CREATOR",),
        )
    if kind == "ORGANIZATION":
        return EditorPrincipal(
            **facts,
            organization_id=ORG,
            role_codes=("DEMAND_OWNER",),
            workspace_id=f"org:{ORG}",
            workspace_kind=kind,
            membership_id=MEMBERSHIP,
            organization_role_codes=("DEMAND_OWNER",),
        )
    return EditorPrincipal(
        **facts,
        organization_id=None,
        role_codes=("OPERATIONS_REVIEWER",),
        workspace_id=f"platform:{USER}",
        workspace_kind="PLATFORM",
        platform_duty_codes=("OPERATIONS_REVIEWER",),
    )


def _provider(*, profile_rows=((UUID(PROFILE),),), owner_rows=((UUID(DEMAND),),), reviewer_rows=((UUID(ORG), UUID(DEMAND), UUID(ASSIGNMENT)),)):
    profile = _Connections("profile_app", profile_rows)
    owner = _Connections("demand_self", owner_rows)
    reviewer = _Connections("demand_review", reviewer_rows)
    markers = _Markers(profile, owner, reviewer)
    return (
        PostgresEditorAuthorityProvider(
            marker_resolver=markers,
            profile_connections=profile,
            demand_owner_connections=owner,
            demand_reviewer_connections=reviewer,
        ),
        markers,
        (profile, owner, reviewer),
    )


def test_personal_and_organization_discovery_bind_principal_then_object_markers():
    provider, markers, sources = _provider()

    profiles = provider.profile_targets(principal=_principal("PERSONAL"))
    demands = provider.demand_targets(principal=_principal("ORGANIZATION"))

    assert profiles[0][0] == PROFILE
    assert profiles[0][1].expected_authority_marker_sha256 == PROFILE_MARKER
    assert demands[0][0] == DEMAND
    assert demands[0][1].expected_authority_marker_sha256 == OWNER_MARKER
    assert demands[0][1].organization_id is None
    assert [request.operation for request in markers.requests] == [
        "SAVE_PROFILE_DRAFT",
        "CREATE_VERSION",
    ]
    profile_call = next(
        item
        for item in sources[0].released[0].commands
        if "list_owned_profile_targets_v1" in item[0]
    )
    assert profile_call[1] == (UUID(USER), UUID(SESSION), PRINCIPAL_MARKER)


def test_platform_reviewer_discovers_assignment_org_without_org_workspace():
    provider, markers, _sources = _provider()

    targets = provider.demand_targets(principal=_principal("PLATFORM"))
    direct = provider.demand(
        principal=_principal("PLATFORM"),
        operation=DemandPostgresOperation.REQUEST_CHANGES,
        demand_id=DEMAND,
        assignment_id=ASSIGNMENT,
    )

    for authority in (targets[0][1], direct):
        assert authority.organization_id == UUID(ORG)
        assert authority.assignment_id == UUID(ASSIGNMENT)
        assert authority.expected_authority_marker_sha256 == REVIEWER_MARKER
    reviewer_requests = [
        item for item in markers.requests
        if isinstance(item, DemandReviewerAuthorityMarkerRequest)
    ]
    assert all(item.organization_id == UUID(ORG) for item in reviewer_requests)


def test_workspace_cannot_activate_another_layer_and_ambiguous_assignment_is_hidden():
    provider, _markers, _sources = _provider(
        reviewer_rows=(
            (UUID(ORG), UUID(DEMAND), UUID(ASSIGNMENT)),
            (UUID(ORG), UUID(DEMAND), UUID("70000000-0000-4000-8000-000000000002")),
        )
    )

    with pytest.raises(EditorServiceError) as wrong_workspace:
        provider.profile_targets(principal=_principal("ORGANIZATION"))
    assert (wrong_workspace.value.status, wrong_workspace.value.code) == (
        404,
        "RESOURCE_NOT_FOUND",
    )
    with pytest.raises(EditorServiceError) as ambiguous:
        provider.demand(
            principal=_principal("PLATFORM"),
            operation=DemandPostgresOperation.REQUEST_CHANGES,
            demand_id=DEMAND,
        )
    assert (ambiguous.value.status, ambiguous.value.code) == (
        404,
        "RESOURCE_NOT_FOUND",
    )


def test_exact_operation_mapping_and_managed_readiness_are_closed():
    provider, markers, sources = _provider()

    profile = provider.profile(
        principal=_principal("PERSONAL"),
        operation=CreatorProfilePostgresOperation.PUBLISH,
        profile_id=PROFILE,
    )
    owner = provider.demand(
        principal=_principal("ORGANIZATION"),
        operation=DemandPostgresOperation.SUBMIT,
        demand_id=DEMAND,
    )
    assert profile.expected_authority_marker_sha256 == PROFILE_MARKER
    assert owner.expected_authority_marker_sha256 == OWNER_MARKER
    assert [item.operation for item in markers.requests] == [
        "PUBLISH_PROFILE",
        "SUBMIT",
    ]
    assert provider.check_readiness(timeout_ms=500) is None
    assert all(source.released for source in sources)
    provider.close()
    with pytest.raises(RuntimeError, match="EDITOR_AUTHORITY_NOT_READY"):
        provider.check_readiness(timeout_ms=500)


def test_malformed_or_oversized_discovery_never_becomes_an_authority():
    malformed, _markers, sources = _provider(profile_rows=(("not-a-uuid",),))
    with pytest.raises(EditorServiceError) as raised:
        malformed.profile_targets(principal=_principal("PERSONAL"))
    assert (raised.value.status, raised.value.code) == (503, "SERVICE_UNAVAILABLE")
    # The database transaction itself was well-formed, so the source can be
    # safely reset/released before the closed row parser rejects its payload.
    assert sources[0].released

    oversized, _markers, _sources = _provider(
        owner_rows=tuple((UUID(int=index + 1),) for index in range(1_001))
    )
    with pytest.raises(EditorServiceError) as too_many:
        oversized.demand_targets(principal=_principal("ORGANIZATION"))
    assert (too_many.value.status, too_many.value.code) == (
        503,
        "SERVICE_UNAVAILABLE",
    )
