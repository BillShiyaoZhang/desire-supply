from __future__ import annotations

from datetime import datetime, timedelta, timezone

from desire_platform.internal_pilot.editor import (
    EditorConfigurationDto,
    EditorHttpApi,
    EditorPrincipal,
    EditorService,
    EditorTaxonomyBundleDto,
    HttpRequest,
    MemoryEditorRepository,
    build_internal_sandbox_editor_choices,
)
from tests.internal_pilot.test_editor_service_red import (
    FixedClock,
    Ids,
    demand_content as valid_content_mapping,
    profile_content as valid_profile_content,
)


NOW = datetime(2026, 8, 12, 8, 0, tzinfo=timezone.utc)
OWNER = EditorPrincipal(
    user_id="user_owner_internal_0001",
    session_id="session_owner_internal_01",
    organization_id="organization_internal_01",
    role_codes=("DEMAND_OWNER",),
)


def api() -> EditorHttpApi:
    service = EditorService(
        repository=MemoryEditorRepository(),
        clock=FixedClock(),
        id_source=Ids(),
        client_reference_key=b"test-only-client-reference-key-32b",
    )
    return EditorHttpApi(service=service)


def test_http_actor_org_and_roles_are_injected_not_accepted_from_json() -> None:
    http = api()
    response = http.handle(
        request=HttpRequest(
            method="POST",
            path="/v1/app/demands",
            headers={"Idempotency-Key": "demand-http-idempotency-001"},
            json={
                "taxonomy_bundle_id": "taxonomy_bundle_internal_01",
                "content": valid_content_mapping(),
                "client_reference": "http-pilot-case-1",
                "expires_at": (NOW + timedelta(days=60)).isoformat(),
                "organization_id": "organization_attacker_01",
                "actor_id": "user_attacker_internal_01",
                "roles": ["OPERATIONS_ADMIN"],
            },
        ),
        principal=OWNER,
    )
    assert response.status == 422
    assert response.json["error"]["code"] == "UNKNOWN_FIELD"
    assert response.json["error"]["path"] == "/actor_id"


def test_http_configuration_route_has_one_closed_server_selected_taxonomy() -> None:
    configuration = EditorConfigurationDto(
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

    class _ConfigurationService:
        def get_configuration(self, *, principal):
            assert principal is OWNER
            return configuration

    http = EditorHttpApi(service=_ConfigurationService())
    response = http.handle(
        request=HttpRequest(
            method="GET",
            path="/v1/app/configuration",
            headers={},
            json=None,
        ),
        principal=OWNER,
    )

    assert response.status == 200
    assert response.json == {
        "data": {
            "schema_version": "editor-configuration-v2",
            "deployment_mode": "INTERNAL_SANDBOX",
            "taxonomy_bundle": {
                "bundle_id": "50000000-0000-4000-8000-000000000001",
                "status": "CURRENT_APPROVED",
                "effective_at": "2026-08-11T08:00:00+00:00",
                "effective_until": "2026-08-13T08:00:00+00:00",
            },
            "editor_choices": {
                "schema_version": "editor-choices-v1",
                "locale": "zh-CN",
                "fields": [
                    {
                        "resource_type": field.resource_type,
                        "path_template": field.path_template,
                        "value_contract": field.value_contract,
                        "intended_node_kind": field.intended_node_kind,
                        "status": field.status,
                        "reason_code": field.reason_code,
                        "options": [
                            {
                                "value": option.value,
                                "label": option.label,
                                "source": option.source,
                            }
                            for option in field.options
                        ],
                    }
                    for field in configuration.editor_choices.fields
                ],
            },
        }
    }


def test_http_etag_contract_and_three_way_412() -> None:
    http = api()
    created = http.handle(
        request=HttpRequest(
            method="POST",
            path="/v1/app/demands",
            headers={"Idempotency-Key": "demand-http-idempotency-002"},
            json={
                "taxonomy_bundle_id": "taxonomy_bundle_internal_01",
                "content": valid_content_mapping(),
                "client_reference": "http-pilot-case-2",
                "expires_at": (NOW + timedelta(days=60)).isoformat(),
            },
        ),
        principal=OWNER,
    )
    assert created.status == 201
    demand_id = created.json["data"]["object_id"]
    first_etag = created.headers["ETag"]
    first_version = created.json["data"]["current_version"]["version_id"]
    changed = valid_content_mapping()
    changed["problem"]["background"] = "Accepted HTTP edit."
    accepted = http.handle(
        request=HttpRequest(
            method="PUT",
            path=f"/v1/app/demands/{demand_id}/draft",
            headers={
                "If-Match": first_etag,
                "Idempotency-Key": "demand-http-idempotency-003",
            },
            json={
                "base_version_id": first_version,
                "taxonomy_bundle_id": "taxonomy_bundle_internal_01",
                "content": changed,
            },
        ),
        principal=OWNER,
    )
    assert accepted.status == 200
    assert accepted.headers["ETag"] != first_etag

    stale = valid_content_mapping()
    stale["problem"]["background"] = "Stale HTTP edit."
    conflict = http.handle(
        request=HttpRequest(
            method="PUT",
            path=f"/v1/app/demands/{demand_id}/draft",
            headers={
                "If-Match": first_etag,
                "Idempotency-Key": "demand-http-idempotency-004",
            },
            json={
                "base_version_id": first_version,
                "taxonomy_bundle_id": "taxonomy_bundle_internal_01",
                "content": stale,
            },
        ),
        principal=OWNER,
    )
    assert conflict.status == 412
    assert set(conflict.json["error"]["details"]) == {"current", "base", "yours"}
    assert conflict.headers["ETag"] == accepted.headers["ETag"]


def test_http_requires_conditional_and_idempotency_headers_with_paths() -> None:
    http = api()
    created = http.handle(
        request=HttpRequest(
            method="POST",
            path="/v1/app/demands",
            headers={"Idempotency-Key": "demand-http-idempotency-005"},
            json={
                "taxonomy_bundle_id": "taxonomy_bundle_internal_01",
                "content": valid_content_mapping(),
                "client_reference": "http-pilot-case-3",
                "expires_at": (NOW + timedelta(days=60)).isoformat(),
            },
        ),
        principal=OWNER,
    )
    demand_id = created.json["data"]["object_id"]
    missing = http.handle(
        request=HttpRequest(
            method="POST",
            path=f"/v1/app/demands/{demand_id}/submit",
            headers={},
            json={},
        ),
        principal=OWNER,
    )
    assert missing.status == 428
    assert missing.json["error"]["path"] == "/headers/If-Match"


def test_http_demand_owner_cancel_route_is_exact_closed_and_replay_safe() -> None:
    http = api()
    created = http.handle(
        request=HttpRequest(
            method="POST",
            path="/v1/app/demands",
            headers={"Idempotency-Key": "demand-http-cancel-create-1"},
            json={
                "taxonomy_bundle_id": "taxonomy_bundle_internal_01",
                "content": valid_content_mapping(),
                "client_reference": "http-owner-cancel",
                "expires_at": (NOW + timedelta(days=60)).isoformat(),
            },
        ),
        principal=OWNER,
    )
    demand_id = created.json["data"]["object_id"]
    headers = {
        "If-Match": created.headers["ETag"],
        "Idempotency-Key": "demand-http-cancel-command-1",
    }
    cancelled = http.handle(
        request=HttpRequest(
            method="POST",
            path=f"/v1/app/demands/{demand_id}/cancel",
            headers=headers,
            json={"reason_code": "OWNER_WITHDREW"},
        ),
        principal=OWNER,
    )
    assert cancelled.status == 200
    assert cancelled.json["data"]["status"] == "CANCELLED"
    assert cancelled.json["data"]["capabilities"] == []

    replay = http.handle(
        request=HttpRequest(
            method="POST",
            path=f"/v1/app/demands/{demand_id}/cancel",
            headers=headers,
            json={"reason_code": "OWNER_WITHDREW"},
        ),
        principal=OWNER,
    )
    assert replay == cancelled

    for body, expected_code, expected_path in (
        (
            {"reason_code": "DEADLINE_REACHED"},
            "INVALID_REASON_CODE",
            "/reason_code",
        ),
        (
            {"reason_code": "OWNER_WITHDREW", "actor_id": "attacker"},
            "UNKNOWN_FIELD",
            "/actor_id",
        ),
    ):
        rejected = http.handle(
            request=HttpRequest(
                method="POST",
                path=f"/v1/app/demands/{demand_id}/cancel",
                headers={
                    "If-Match": cancelled.headers["ETag"],
                    "Idempotency-Key": "demand-http-cancel-invalid-1",
                },
                json=body,
            ),
            principal=OWNER,
        )
        assert (
            rejected.status,
            rejected.json["error"]["code"],
            rejected.json["error"]["path"],
        ) == (422, expected_code, expected_path)

    wrong_method = http.handle(
        request=HttpRequest(
            method="PUT",
            path=f"/v1/app/demands/{demand_id}/cancel",
            headers=headers,
            json={"reason_code": "OWNER_WITHDREW"},
        ),
        principal=OWNER,
    )
    assert (wrong_method.status, wrong_method.json["error"]["code"]) == (
        404,
        "RESOURCE_NOT_FOUND",
    )


def test_http_profile_list_detail_draft_publish_routes() -> None:
    http = api()
    creator = EditorPrincipal(
        user_id="user_creator_internal_01",
        session_id="session_creator_internal_1",
        organization_id="organization_internal_01",
        role_codes=("CREATOR",),
    )
    created = http.handle(
        request=HttpRequest(
            method="POST",
            path="/v1/app/profiles",
            headers={"Idempotency-Key": "profile-http-idempotency-001"},
            json={},
        ),
        principal=creator,
    )
    assert created.status == 201
    profile_id = created.json["data"]["object_id"]
    detail = http.handle(
        request=HttpRequest(
            method="GET", path=f"/v1/app/profiles/{profile_id}", headers={}, json={}
        ),
        principal=creator,
    )
    assert detail.json["data"]["resource_type"] == "CREATOR_PROFILE"
    listed = http.handle(
        request=HttpRequest(
            method="GET", path="/v1/app/profiles", headers={}, json={}
        ),
        principal=creator,
    )
    assert listed.json["data"][0]["object_id"] == profile_id


def test_http_profile_lifecycle_routes_are_closed_conditional_and_replay_safe() -> None:
    http = api()
    creator = EditorPrincipal(
        user_id="user_creator_internal_01",
        session_id="session_creator_internal_1",
        organization_id="organization_internal_01",
        role_codes=("CREATOR",),
    )
    created = http.handle(
        request=HttpRequest(
            method="POST",
            path="/v1/app/profiles",
            headers={"Idempotency-Key": "profile-http-lifecycle-create-1"},
            json={},
        ),
        principal=creator,
    )
    profile_id = created.json["data"]["object_id"]
    drafted = http.handle(
        request=HttpRequest(
            method="PUT",
            path=f"/v1/app/profiles/{profile_id}/draft",
            headers={
                "If-Match": created.headers["ETag"],
                "Idempotency-Key": "profile-http-lifecycle-draft-01",
            },
            json={
                "base_version_id": None,
                "taxonomy_bundle_id": "taxonomy_bundle_internal_01",
                "content": valid_profile_content(),
            },
        ),
        principal=creator,
    )
    published = http.handle(
        request=HttpRequest(
            method="POST",
            path=f"/v1/app/profiles/{profile_id}/publish",
            headers={
                "If-Match": drafted.headers["ETag"],
                "Idempotency-Key": "profile-http-lifecycle-publish-1",
            },
            json={
                "draft_version_id": drafted.json["data"]["current_version"][
                    "version_id"
                ]
            },
        ),
        principal=creator,
    )
    paused = http.handle(
        request=HttpRequest(
            method="POST",
            path=f"/v1/app/profiles/{profile_id}/pause",
            headers={
                "If-Match": published.headers["ETag"],
                "Idempotency-Key": "profile-http-lifecycle-pause-01",
            },
            json={"reason_code": "TEMPORARY_UNAVAILABILITY"},
        ),
        principal=creator,
    )
    assert paused.status == 200
    assert paused.json["data"]["capabilities"] == ["RESUME", "ARCHIVE"]
    assert paused.headers["ETag"] == paused.json["data"]["etag"]
    assert paused.headers["Cache-Control"] == "no-store"

    missing_precondition = http.handle(
        request=HttpRequest(
            method="POST",
            path=f"/v1/app/profiles/{profile_id}/resume",
            headers={"Idempotency-Key": "profile-http-lifecycle-resume-1"},
            json={},
        ),
        principal=creator,
    )
    assert (missing_precondition.status, missing_precondition.json["error"]["path"]) == (
        428,
        "/headers/If-Match",
    )
    for body in (
        {"reason_code": "FREE_TEXT"},
        {"reason_code": "OWNER_REQUEST", "actor_id": "forged"},
    ):
        rejected = http.handle(
            request=HttpRequest(
                method="POST",
                path=f"/v1/app/profiles/{profile_id}/pause",
                headers={
                    "If-Match": paused.headers["ETag"],
                    "Idempotency-Key": "profile-http-lifecycle-invalid-1",
                },
                json=body,
            ),
            principal=creator,
        )
        assert rejected.status == 422

    resumed = http.handle(
        request=HttpRequest(
            method="POST",
            path=f"/v1/app/profiles/{profile_id}/resume",
            headers={
                "If-Match": paused.headers["ETag"],
                "Idempotency-Key": "profile-http-lifecycle-resume-2",
            },
            json={},
        ),
        principal=creator,
    )
    assert resumed.json["data"]["status"] == "ACTIVE"
    stale = http.handle(
        request=HttpRequest(
            method="POST",
            path=f"/v1/app/profiles/{profile_id}/archive",
            headers={
                "If-Match": paused.headers["ETag"],
                "Idempotency-Key": "profile-http-lifecycle-stale-01",
            },
            json={"reason_code": "OWNER_REQUEST"},
        ),
        principal=creator,
    )
    assert (stale.status, stale.json["error"]["code"]) == (
        412,
        "PRECONDITION_FAILED",
    )
    assert stale.headers["ETag"] == resumed.headers["ETag"]

    archive_request = HttpRequest(
        method="POST",
        path=f"/v1/app/profiles/{profile_id}/archive",
        headers={
            "If-Match": resumed.headers["ETag"],
            "Idempotency-Key": "profile-http-lifecycle-archive-1",
        },
        json={"reason_code": "ACCOUNT_CLOSURE"},
    )
    archived = http.handle(request=archive_request, principal=creator)
    replay = http.handle(request=archive_request, principal=creator)
    assert archived.json == replay.json
    assert archived.json["data"]["status"] == "ARCHIVED"
    assert archived.json["data"]["current_version"] is None


def test_http_findings_route_rejects_body_authority_fields() -> None:
    http = api()
    reviewer = EditorPrincipal(
        user_id="user_reviewer_internal_1",
        session_id="session_reviewer_internal_1",
        organization_id="organization_review_ops_1",
        role_codes=("OPERATIONS_REVIEWER",),
    )
    response = http.handle(
        request=HttpRequest(
            method="POST",
            path=(
                "/v1/app/demands/demand_target_internal_1/"
                "review-assignments/review_assignment_internal_1/findings"
            ),
            headers={
                "If-Match": '"demand-1-stale"',
                "Idempotency-Key": "findings-http-idempotency-001",
            },
            json={
                "reason_codes": ["SCOPE_UNCLEAR"],
                "required_field_paths": ["/scope/deliverables"],
                "demand_id": "demand_body_override_01",
            },
        ),
        principal=reviewer,
    )
    assert response.status == 422
    assert response.json["error"]["code"] == "UNKNOWN_FIELD"
    assert response.json["error"]["path"] == "/demand_id"


def test_http_findings_accepts_only_reviewed_reason_codes() -> None:
    http = api()
    reviewer = EditorPrincipal(
        user_id="user_reviewer_internal_1",
        session_id="session_reviewer_internal_1",
        organization_id="organization_review_ops_1",
        role_codes=("OPERATIONS_REVIEWER",),
    )
    response = http.handle(
        request=HttpRequest(
            method="POST",
            path=(
                "/v1/app/demands/demand_target_internal_1/"
                "review-assignments/review_assignment_internal_1/findings"
            ),
            headers={
                "If-Match": '"demand-1-stale"',
                "Idempotency-Key": "findings-http-idempotency-002",
            },
            json={
                "reason_codes": ["MISSING_EVIDENCE"],
                "required_field_paths": ["/scope/deliverables"],
            },
        ),
        principal=reviewer,
    )
    assert response.status == 422
    assert response.json["error"] == {
        "code": "INVALID_REASON_CODE",
        "path": "/reason_codes/0",
    }
