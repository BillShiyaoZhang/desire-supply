from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
from uuid import UUID

import pytest

from desire_platform.demand.adapters.postgres import DemandPostgresOperation
from desire_platform.internal_pilot.editor import (
    DemandCompletedReleaseReplayResult,
    DemandReadAuthority,
    EditorHttpApi,
    EditorPostgresKeys,
    EditorPrincipal,
    EditorResourceDto,
    EditorReviewAssignmentDto,
    EditorServiceError,
    EditorVersionDto,
    HttpRequest,
    PostgresEditorService,
)


NOW = datetime(2026, 8, 26, 8, 0, tzinfo=timezone.utc)
ACTOR = "10000000-0000-4000-8000-000000000013"
SESSION = "20000000-0000-4000-8000-000000000013"
ORGANIZATION = UUID("30000000-0000-4000-8000-000000000013")
DEMAND = "40000000-0000-4000-8000-000000000013"
VERSION = "50000000-0000-4000-8000-000000000013"
ASSIGNMENT = UUID("60000000-0000-4000-8000-000000000013")
MARKER = hashlib.sha256(b"demand-release-authority").digest()


def _etag(revision: int) -> str:
    digest = hashlib.sha256(
        f"DEMAND:{DEMAND}:{revision}".encode("utf-8")
    ).hexdigest()[:24]
    return f'"demand-{revision}-{digest}"'


def _principal() -> EditorPrincipal:
    return EditorPrincipal(
        user_id=ACTOR,
        session_id=SESSION,
        organization_id=None,
        role_codes=("OPERATIONS_REVIEWER",),
        workspace_id=f"platform:{ACTOR}",
        workspace_kind="PLATFORM",
        platform_duty_codes=("OPERATIONS_REVIEWER",),
        principal_marker_sha256=MARKER,
    )


def _version() -> EditorVersionDto:
    return EditorVersionDto(
        version_id=VERSION,
        version_no=1,
        based_on_version_id=None,
        status="SUBMITTED",
        content={"problem": {"background": "synthetic"}},
        content_sha256=hashlib.sha256(b"release-version").hexdigest(),
        taxonomy_bundle_id="70000000-0000-4000-8000-000000000013",
        created_at=NOW - timedelta(days=1),
    )


def _resource(*, revision: int, assigned: bool) -> EditorResourceDto:
    return EditorResourceDto(
        resource_type="DEMAND",
        object_id=DEMAND,
        status="SUBMITTED",
        revision=revision,
        etag=_etag(revision),
        capabilities=("RECORD_FINDINGS",) if assigned else (),
        editable_paths=(),
        current_version=_version(),
        versions=(_version(),),
        review_assignment=(
            EditorReviewAssignmentDto(
                assignment_id=str(ASSIGNMENT),
                status="ACTIVE",
                expires_at=NOW + timedelta(minutes=30),
            )
            if assigned
            else None
        ),
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


class _Clock:
    @staticmethod
    def now() -> datetime:
        return NOW


class _Evidence:
    pass


def test_release_builds_exact_assignment_bound_idempotent_command() -> None:
    principal = _principal()
    before = _resource(revision=2, assigned=True)
    after = _resource(revision=3, assigned=False)

    class Authorities:
        def demand(self, **facts):
            assert facts == {
                "principal": principal,
                "operation": DemandPostgresOperation.RELEASE_REVIEW_ASSIGNMENT,
                "demand_id": DEMAND,
                "assignment_id": str(ASSIGNMENT),
            }
            return DemandReadAuthority(
                DemandPostgresOperation.RELEASE_REVIEW_ASSIGNMENT,
                MARKER,
                ASSIGNMENT,
                ORGANIZATION,
            )

    class Repository:
        def __init__(self) -> None:
            self.results = [before, after]
            self.commands = []

        def get_demand(self, **_facts):
            return self.results.pop(0)

        def execute_demand(self, command):
            self.commands.append(command)

    repository = Repository()
    service = PostgresEditorService(
        repository=repository,
        authorities=Authorities(),
        evidence=_Evidence(),
        keys=_keys(),
        clock=_Clock(),
    )
    result = service.release_demand_review_assignment(
        principal=principal,
        demand_id=DEMAND,
        assignment_id=str(ASSIGNMENT),
        if_match=before.etag,
        reason_code="WORKLOAD_RELEASE",
        idempotency_key="release-demand-review-001",
    )

    assert result is after
    assert len(repository.commands) == 1
    command = repository.commands[0]
    assert command.operation is DemandPostgresOperation.RELEASE_REVIEW_ASSIGNMENT
    assert command.assignment_id == ASSIGNMENT
    assert command.demand_version_id == UUID(VERSION)
    assert command.release_reason_code == "WORKLOAD_RELEASE"
    assert command.receipt.command_name == "ReleaseDemandReviewAssignment"
    assert command.receipt.canonical_path == (
        f"/v1/operations/demand-review-assignments/{ASSIGNMENT}/release"
    )
    assert command.receipt.if_match_version == 2


def test_completed_release_replay_precedes_active_assignment_discovery() -> None:
    final = _resource(revision=3, assigned=False)

    class Probe:
        def __init__(self) -> None:
            self.calls = []

        def read_completed_release(self, request):
            self.calls.append(request)
            return DemandCompletedReleaseReplayResult(
                organization_id=ORGANIZATION,
                authority_marker_sha256=MARKER,
                aggregate_version=3,
                demand_version_id=UUID(VERSION),
            )

    class Authorities:
        def demand(self, **facts):
            raise AssertionError(f"ACTIVE assignment discovery ran: {facts}")

    class Repository:
        def get_demand(self, **facts):
            authority = facts["authority"]
            assert authority.operation is (
                DemandPostgresOperation.RELEASE_REVIEW_ASSIGNMENT
            )
            assert authority.assignment_id == ASSIGNMENT
            return final

        def execute_demand(self, _command):
            raise AssertionError("completed release replay must not write")

    probe = Probe()
    service = PostgresEditorService(
        repository=Repository(),
        authorities=Authorities(),
        evidence=_Evidence(),
        keys=_keys(),
        clock=_Clock(),
        completed_verify_receipts=probe,
    )
    result = service.release_demand_review_assignment(
        principal=_principal(),
        demand_id=DEMAND,
        assignment_id=str(ASSIGNMENT),
        if_match=_etag(2),
        reason_code="CONFLICT_DECLARED",
        idempotency_key="release-demand-review-replay-001",
    )

    assert result is final
    assert len(probe.calls) == 1
    assert probe.calls[0].expected_version == 2
    assert b"CONFLICT_DECLARED" in probe.calls[0].canonical_payload


def test_release_rejects_open_reason_set_before_authority_discovery() -> None:
    class Authorities:
        def demand(self, **facts):
            raise AssertionError(f"invalid reason reached authority: {facts}")

    service = PostgresEditorService(
        repository=object(),
        authorities=Authorities(),
        evidence=_Evidence(),
        keys=_keys(),
        clock=_Clock(),
    )
    with pytest.raises(EditorServiceError) as rejected:
        service.release_demand_review_assignment(
            principal=_principal(),
            demand_id=DEMAND,
            assignment_id=str(ASSIGNMENT),
            if_match=_etag(2),
            reason_code="FREE_TEXT",
            idempotency_key="release-demand-review-invalid-001",
        )
    assert (rejected.value.status, rejected.value.code, rejected.value.path) == (
        422,
        "INVALID_REASON_CODE",
        "/reason_code",
    )


def test_http_release_route_accepts_only_reason_body_and_forwards_headers() -> None:
    final = _resource(revision=3, assigned=False)

    class Service:
        def __init__(self) -> None:
            self.calls = []

        def release_demand_review_assignment(self, **facts):
            self.calls.append(facts)
            return final

    service = Service()
    api = EditorHttpApi(service=service)
    request = HttpRequest(
        method="POST",
        path=(
            f"/v1/app/demands/{DEMAND}/review-assignments/"
            f"{ASSIGNMENT}/release"
        ),
        headers={
            "If-Match": _etag(2),
            "Idempotency-Key": "release-demand-review-http-001",
        },
        json={"reason_code": "WORKLOAD_RELEASE"},
    )
    response = api.handle(request=request, principal=_principal())
    assert response.status == 200
    assert response.headers["ETag"] == final.etag
    assert response.json["data"]["review_assignment"] is None
    assert service.calls == [
        {
            "principal": _principal(),
            "demand_id": DEMAND,
            "assignment_id": str(ASSIGNMENT),
            "if_match": _etag(2),
            "reason_code": "WORKLOAD_RELEASE",
            "idempotency_key": "release-demand-review-http-001",
        }
    ]

    unknown = api.handle(
        request=HttpRequest(
            method="POST",
            path=request.path,
            headers=request.headers,
            json={"reason_code": "WORKLOAD_RELEASE", "actor_id": ACTOR},
        ),
        principal=_principal(),
    )
    assert (unknown.status, unknown.json["error"]["code"]) == (
        422,
        "UNKNOWN_FIELD",
    )
