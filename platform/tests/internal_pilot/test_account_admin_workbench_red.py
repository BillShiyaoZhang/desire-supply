"""INTERNAL_SANDBOX ACCESS_ADMIN account-workbench contract tests."""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

import pytest

from desire_platform.identity_access.adapters.postgres.platform_user_lifecycle import (
    PlatformUserPostgresDatabaseResult,
    PlatformUserPostgresOperation,
    PsycopgPlatformUserLifecycleUnitOfWorkFactory,
)
from desire_platform.identity_access.domain.errors import IamError

from desire_platform.internal_pilot.account_admin import (
    ACCOUNT_ADMIN_REASON_CODES,
    InternalSandboxAccountAdminCollectionDto,
    InternalSandboxAccountAdminCommandDto,
    InternalSandboxAccountAdminDto,
    PlatformUserAdminKeys,
    PostgresInternalSandboxAccountAdminService,
    PsycopgInternalSandboxAccountAdminRepository,
)
from desire_platform.internal_pilot.editor import (
    EditorHttpApi,
    EditorPrincipal,
    EditorServiceError,
    HttpRequest,
)


NOW = datetime(2026, 8, 15, 8, 0, tzinfo=timezone.utc)
ACTOR_ID = "10000000-0000-4000-8000-000000000001"
TARGET_ID = "10000000-0000-4000-8000-000000000002"
SESSION_ID = "20000000-0000-4000-8000-000000000001"


def _principal(*, role_codes=("ACCESS_ADMIN",)) -> EditorPrincipal:
    return EditorPrincipal(
        user_id=ACTOR_ID,
        session_id=SESSION_ID,
        organization_id=None,
        role_codes=role_codes,
        workspace_id=f"platform:{ACTOR_ID}",
        workspace_kind="PLATFORM",
        membership_id=None,
        organization_role_codes=(),
        user_role_codes=(),
        platform_duty_codes=role_codes,
        principal_marker_sha256=b"m" * 32,
    )


def _account(*, user_id: str = TARGET_ID) -> InternalSandboxAccountAdminDto:
    return InternalSandboxAccountAdminDto(
        account_code="creator" if user_id == TARGET_ID else "access_admin",
        user_id=user_id,
        display_handle="sandbox_creator" if user_id == TARGET_ID else "sandbox_access_admin",
        status="ACTIVE",
        aggregate_version=3,
        entity_tag='"v3"',
        role_codes=("CREATOR",) if user_id == TARGET_ID else ("ACCESS_ADMIN",),
        active_session_count=1,
        created_at=NOW,
        updated_at=NOW,
        is_self=user_id == ACTOR_ID,
    )


class _EditorService:
    pass


class _AccountAdminService:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, object]]] = []

    def list_accounts(self, *, principal: EditorPrincipal):
        self.calls.append(("list", {"principal": principal}))
        return InternalSandboxAccountAdminCollectionDto(
            schema_version="internal-sandbox-account-admin-v1",
            evaluated_at=NOW,
            accounts=(_account(user_id=ACTOR_ID), _account()),
        )

    def get_account(self, *, principal: EditorPrincipal, user_id: str):
        self.calls.append(("detail", {"principal": principal, "user_id": user_id}))
        return _account(user_id=user_id)

    def manage_account(self, **facts):
        self.calls.append(("manage", facts))
        return InternalSandboxAccountAdminCommandDto(
            user_id=facts["user_id"],
            display_handle="sandbox_creator",
            status="SUSPENDED" if facts["action"] == "SUSPEND" else "ACTIVE",
            aggregate_version=4,
            entity_tag='"v4"',
            revoked_session_count=1,
            revoked_session_family_count=1,
            replayed=False,
        )

    def manage_platform_duty(self, **facts):
        self.calls.append(("manage-duty", facts))
        return InternalSandboxAccountAdminCommandDto(
            user_id=facts["user_id"],
            display_handle="sandbox_creator",
            status="ACTIVE",
            aggregate_version=4,
            entity_tag='"v4"',
            revoked_session_count=0,
            revoked_session_family_count=0,
            replayed=False,
        )


def _api():
    service = _AccountAdminService()
    return EditorHttpApi(
        service=_EditorService(),
        account_admin_service=service,
    ), service


def test_list_and_detail_are_closed_internal_sandbox_projections() -> None:
    api, service = _api()

    listed = api.handle(
        request=HttpRequest(
            method="GET", path="/v1/app/admin/accounts", headers={}, json={}
        ),
        principal=_principal(),
    )
    detail = api.handle(
        request=HttpRequest(
            method="GET",
            path=f"/v1/app/admin/accounts/{TARGET_ID}",
            headers={},
            json={},
        ),
        principal=_principal(),
    )

    assert listed.status == 200
    assert listed.headers["Cache-Control"] == "no-store"
    assert listed.json["data"]["schema_version"] == "internal-sandbox-account-admin-v1"
    assert len(listed.json["data"]["accounts"]) == 2
    assert set(listed.json["data"]["accounts"][0]) == {
        "account_code",
        "user_id",
        "display_handle",
        "status",
        "aggregate_version",
        "entity_tag",
        "role_codes",
        "active_session_count",
        "created_at",
        "updated_at",
        "is_self",
    }
    rendered = repr(listed.json).lower()
    for forbidden in ("issuer", "subject", "contact", "digest", "organization_id"):
        assert forbidden not in rendered
    assert detail.status == 200
    assert detail.headers["ETag"] == '"v3"'
    assert detail.json["data"]["user_id"] == TARGET_ID
    assert [call[0] for call in service.calls] == ["list", "detail"]


def test_writes_bind_closed_body_etag_csrf_and_idempotency_without_authority_input() -> None:
    api, service = _api()
    request = HttpRequest(
        method="POST",
        path=f"/v1/app/admin/accounts/{TARGET_ID}/suspend",
        headers={
            "If-Match": '"v3"',
            "Idempotency-Key": "account-admin-suspend-0001",
        },
        json={"reason_code": "SAFETY_REVIEW"},
    )

    response = api.handle(request=request, principal=_principal())

    assert response.status == 200
    assert response.headers["ETag"] == '"v4"'
    assert response.json["data"]["status"] == "SUSPENDED"
    assert service.calls[-1] == (
        "manage",
        {
            "principal": _principal(),
            "user_id": TARGET_ID,
            "action": "SUSPEND",
            "if_match": '"v3"',
            "idempotency_key": "account-admin-suspend-0001",
            "reason_code": "SAFETY_REVIEW",
        },
    )
    assert ACCOUNT_ADMIN_REASON_CODES == (
        "ACCESS_REVIEW",
        "SAFETY_REVIEW",
        "SESSION_HYGIENE",
    )

    for body in (
        {"reason_code": "SAFETY_REVIEW", "actor_id": ACTOR_ID},
        {"reason_code": "SAFETY_REVIEW", "organization_id": ACTOR_ID},
        {"reason_code": "SAFETY_REVIEW", "role_codes": ["ACCESS_ADMIN"]},
        {"reason_code": "NOT_REVIEWED"},
    ):
        denied = api.handle(
            request=HttpRequest(
                method="POST",
                path=f"/v1/app/admin/accounts/{TARGET_ID}/suspend",
                headers=request.headers,
                json=body,
            ),
            principal=_principal(),
        )
        assert denied.status == 422
    assert len([call for call in service.calls if call[0] == "manage"]) == 1


def test_all_three_actions_require_if_match_and_idempotency_headers() -> None:
    api, service = _api()
    for suffix, action in (
        ("suspend", "SUSPEND"),
        ("resume", "RESUME"),
        ("revoke-all-sessions", "REVOKE_ALL_SESSIONS"),
    ):
        missing_version = api.handle(
            request=HttpRequest(
                method="POST",
                path=f"/v1/app/admin/accounts/{TARGET_ID}/{suffix}",
                headers={"Idempotency-Key": f"account-{suffix}-00000001"},
                json={"reason_code": "SAFETY_REVIEW"},
            ),
            principal=_principal(),
        )
        assert missing_version.status == 428
        assert missing_version.json["error"]["path"] == "/headers/If-Match"

        missing_key = api.handle(
            request=HttpRequest(
                method="POST",
                path=f"/v1/app/admin/accounts/{TARGET_ID}/{suffix}",
                headers={"If-Match": '"v3"'},
                json={"reason_code": "SAFETY_REVIEW"},
            ),
            principal=_principal(),
        )
        assert missing_key.status == 428
        assert missing_key.json["error"]["path"] == "/headers/Idempotency-Key"

        accepted = api.handle(
            request=HttpRequest(
                method="POST",
                path=f"/v1/app/admin/accounts/{TARGET_ID}/{suffix}",
                headers={
                    "If-Match": '"v3"',
                    "Idempotency-Key": f"account-{suffix}-00000001",
                },
                json={"reason_code": "SAFETY_REVIEW"},
            ),
            principal=_principal(),
        )
        assert accepted.status == 200
        assert service.calls[-1][1]["action"] == action


def test_platform_duty_writes_use_closed_path_and_never_accept_client_authority() -> None:
    api, service = _api()
    request = HttpRequest(
        method="POST",
        path=(
            f"/v1/app/admin/accounts/{TARGET_ID}/platform-duties/"
            "FINANCE_OPERATOR/grant"
        ),
        headers={
            "If-Match": '"v3"',
            "Idempotency-Key": "account-duty-grant-000001",
        },
        json={"reason_code": "ACCESS_REVIEW"},
    )

    response = api.handle(request=request, principal=_principal())

    assert response.status == 200
    assert response.headers["ETag"] == '"v4"'
    assert service.calls[-1] == (
        "manage-duty",
        {
            "principal": _principal(),
            "user_id": TARGET_ID,
            "duty_code": "FINANCE_OPERATOR",
            "action": "GRANT",
            "if_match": '"v3"',
            "idempotency_key": "account-duty-grant-000001",
            "reason_code": "ACCESS_REVIEW",
        },
    )

    for path, body in (
        (request.path, {"reason_code": "ACCESS_REVIEW", "actor_id": ACTOR_ID}),
        (request.path, {"reason_code": "ACCESS_REVIEW", "role_codes": []}),
        (
            f"/v1/app/admin/accounts/{TARGET_ID}/platform-duties/CREATOR/grant",
            {"reason_code": "ACCESS_REVIEW"},
        ),
    ):
        denied = api.handle(
            request=HttpRequest(
                method="POST", path=path, headers=request.headers, json=body
            ),
            principal=_principal(),
        )
        assert denied.status in {404, 422}
    assert len([call for call in service.calls if call[0] == "manage-duty"]) == 1


def test_non_access_admin_has_no_account_workbench_authority() -> None:
    api, service = _api()

    response = api.handle(
        request=HttpRequest(
            method="GET", path="/v1/app/admin/accounts", headers={}, json={}
        ),
        principal=_principal(role_codes=("OPERATIONS_REVIEWER",)),
    )

    assert response.status == 404
    assert service.calls == []


class _Connections:
    def checkout(self):
        raise AssertionError("not used by this service contract test")

    def release(self, connection):
        raise AssertionError(connection)

    def discard(self, connection):
        raise AssertionError(connection)


class _Validator:
    def validate(self, value, schema_name=None):
        del value, schema_name


class _Clock:
    def now(self):
        return NOW


class _Ids:
    def __init__(self) -> None:
        self.value = 500
        self.purposes: list[str] = []

    def new_id(self, purpose: str) -> UUID:
        self.value += 1
        self.purposes.append(purpose)
        return UUID(int=self.value)


def test_production_service_builds_exact_existing_iam_uow_request_and_redacts_keys() -> None:
    connections = _Connections()
    repository = PsycopgInternalSandboxAccountAdminRepository(
        connections=connections
    )
    scoped_reads = []

    def read_synthetic_target(**facts):
        scoped_reads.append(facts)
        return _account()

    repository.get_account = read_synthetic_target  # type: ignore[method-assign]
    validator = _Validator()
    lifecycle = PsycopgPlatformUserLifecycleUnitOfWorkFactory(
        connections=connections,
        event_validator=validator,
        response_validator=validator,
    )
    captured = []

    def execute(request):
        captured.append(request)
        return PlatformUserPostgresDatabaseResult(
            operation=PlatformUserPostgresOperation.SUSPEND_USER,
            replayed=False,
            safe_response={
                "user_id": TARGET_ID,
                "display_handle": "sandbox_creator",
                "status": "SUSPENDED",
                "aggregate_version": 4,
                "entity_tag": '"v4"',
                "revoked_session_count": 1,
                "revoked_session_family_count": 1,
            },
            response_entity_tag='"v4"',
        )

    lifecycle.execute_suspend_user = execute  # type: ignore[method-assign]
    keys = PlatformUserAdminKeys(
        idempotency_key=b"i" * 32,
        payload_hash_key=b"p" * 32,
    )
    ids = _Ids()
    service = PostgresInternalSandboxAccountAdminService(
        repository=repository,
        lifecycle=lifecycle,
        keys=keys,
        clock=_Clock(),
        id_source=ids,
    )

    result = service.manage_account(
        principal=_principal(),
        user_id=TARGET_ID,
        action="SUSPEND",
        if_match='"v3"',
        idempotency_key="account-admin-suspend-0001",
        reason_code="SAFETY_REVIEW",
    )

    assert result.status == "SUSPENDED"
    assert scoped_reads == [{
        "actor_user_id": ACTOR_ID,
        "session_id": SESSION_ID,
        "target_user_id": TARGET_ID,
    }]
    request = captured[0]
    assert request.operation is PlatformUserPostgresOperation.SUSPEND_USER
    assert str(request.scope.actor_user_id) == ACTOR_ID
    assert str(request.scope.current_session_id) == SESSION_ID
    assert str(request.scope.target_user_id) == TARGET_ID
    assert request.scope.causation_id == request.scope.command_id
    assert request.expected_user_version == 3
    assert request.receipt.idempotency_key_digest_key_id == (
        "iam-receipt-idempotency-hmac-2026-01"
    )
    assert request.receipt.payload_hash_key_id == (
        "iam-receipt-payload-hmac-2026-01"
    )
    assert request.receipt.idempotency_key_digest != request.receipt.payload_hash
    assert request.receipt.retain_until > NOW
    assert "account-admin-suspend-0001" not in repr(request)
    assert "iiii" not in repr(keys)
    assert ids.purposes == [
        "platform_user_command",
        "platform_user_correlation",
        "platform_user_trace",
        "platform_user_audit",
        "platform_user_outbox",
        "platform_user_session_event_namespace",
    ]

    with pytest.raises(ValueError):
        PlatformUserAdminKeys(
            idempotency_key=b"x" * 32,
            payload_hash_key=b"x" * 32,
        )


def test_production_service_maps_idempotency_payload_conflict_to_409() -> None:
    connections = _Connections()
    repository = PsycopgInternalSandboxAccountAdminRepository(
        connections=connections
    )
    repository.get_account = lambda **_facts: _account()  # type: ignore[method-assign]
    validator = _Validator()
    lifecycle = PsycopgPlatformUserLifecycleUnitOfWorkFactory(
        connections=connections,
        event_validator=validator,
        response_validator=validator,
    )

    def reject(_request):
        raise IamError("IDEMPOTENCY_KEY_REUSED")

    lifecycle.execute_suspend_user = reject  # type: ignore[method-assign]
    service = PostgresInternalSandboxAccountAdminService(
        repository=repository,
        lifecycle=lifecycle,
        keys=PlatformUserAdminKeys(
            idempotency_key=b"i" * 32,
            payload_hash_key=b"p" * 32,
        ),
        clock=_Clock(),
        id_source=_Ids(),
    )

    with pytest.raises(EditorServiceError) as raised:
        service.manage_account(
            principal=_principal(),
            user_id=TARGET_ID,
            action="SUSPEND",
            if_match='"v3"',
            idempotency_key="account-admin-suspend-0001",
            reason_code="SAFETY_REVIEW",
        )

    assert raised.value.status == 409
    assert raised.value.code == "IDEMPOTENCY_KEY_REUSED"


def test_account_lifecycle_write_requires_scoped_synthetic_target_read() -> None:
    connections = _Connections()
    repository = PsycopgInternalSandboxAccountAdminRepository(
        connections=connections
    )

    def unknown_target(**_facts):
        raise IamError("RESOURCE_NOT_FOUND")

    repository.get_account = unknown_target  # type: ignore[method-assign]
    validator = _Validator()
    lifecycle = PsycopgPlatformUserLifecycleUnitOfWorkFactory(
        connections=connections,
        event_validator=validator,
        response_validator=validator,
    )
    lifecycle.execute_suspend_user = (  # type: ignore[method-assign]
        lambda _request: pytest.fail("non-synthetic target reached lifecycle UoW")
    )
    ids = _Ids()
    service = PostgresInternalSandboxAccountAdminService(
        repository=repository,
        lifecycle=lifecycle,
        keys=PlatformUserAdminKeys(
            idempotency_key=b"i" * 32,
            payload_hash_key=b"p" * 32,
        ),
        clock=_Clock(),
        id_source=ids,
    )

    with pytest.raises(EditorServiceError) as raised:
        service.manage_account(
            principal=_principal(),
            user_id=TARGET_ID,
            action="SUSPEND",
            if_match='"v3"',
            idempotency_key="account-admin-suspend-0001",
            reason_code="SAFETY_REVIEW",
        )

    assert raised.value.status == 404
    assert raised.value.code == "RESOURCE_NOT_FOUND"
    assert ids.purposes == []


def test_production_service_builds_platform_duty_uow_without_client_authority() -> None:
    connections = _Connections()
    repository = PsycopgInternalSandboxAccountAdminRepository(
        connections=connections
    )
    validator = _Validator()
    lifecycle = PsycopgPlatformUserLifecycleUnitOfWorkFactory(
        connections=connections,
        event_validator=validator,
        response_validator=validator,
    )
    captured = []

    def execute(request):
        captured.append(request)
        return PlatformUserPostgresDatabaseResult(
            operation=PlatformUserPostgresOperation.GRANT_PLATFORM_DUTY,
            replayed=False,
            safe_response={
                "user_id": TARGET_ID,
                "display_handle": "sandbox_creator",
                "status": "ACTIVE",
                "aggregate_version": 4,
                "entity_tag": '"v4"',
                "revoked_session_count": 0,
                "revoked_session_family_count": 0,
            },
            response_entity_tag='"v4"',
        )

    lifecycle.execute_grant_platform_duty = execute  # type: ignore[method-assign]
    ids = _Ids()
    service = PostgresInternalSandboxAccountAdminService(
        repository=repository,
        lifecycle=lifecycle,
        keys=PlatformUserAdminKeys(
            idempotency_key=b"i" * 32,
            payload_hash_key=b"p" * 32,
        ),
        clock=_Clock(),
        id_source=ids,
    )

    result = service.manage_platform_duty(
        principal=_principal(),
        user_id=TARGET_ID,
        duty_code="FINANCE_OPERATOR",
        action="GRANT",
        if_match='"v3"',
        idempotency_key="account-duty-grant-000001",
        reason_code="ACCESS_REVIEW",
    )

    assert result.entity_tag == '"v4"'
    request = captured[0]
    assert request.operation is PlatformUserPostgresOperation.GRANT_PLATFORM_DUTY
    assert request.duty_code == "FINANCE_OPERATOR"
    assert request.generated_ids.platform_duty_grant_id is not None
    assert request.scope.actor_user_id != request.scope.target_user_id
    assert "FINANCE_OPERATOR" not in repr(request.receipt)
    assert ids.purposes == [
        "platform_duty_command",
        "platform_duty_correlation",
        "platform_duty_trace",
        "platform_duty_audit",
        "platform_duty_outbox",
        "platform_duty_session_event_namespace",
        "platform_duty_grant",
    ]

    with pytest.raises(EditorServiceError) as self_target:
        service.manage_platform_duty(
            principal=_principal(),
            user_id=ACTOR_ID,
            duty_code="FINANCE_OPERATOR",
            action="GRANT",
            if_match='"v3"',
            idempotency_key="account-duty-grant-000002",
            reason_code="ACCESS_REVIEW",
        )
    assert self_target.value.code == "SELF_MANAGEMENT_FORBIDDEN"
