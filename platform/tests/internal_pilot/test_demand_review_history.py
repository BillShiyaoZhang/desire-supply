from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import UUID

import pytest

from desire_platform.internal_pilot.editor import (
    DemandReviewQueueError,
    EditorHttpApi,
    EditorPostgresKeys,
    EditorPrincipal,
    EditorReviewHistoryItemDto,
    EditorServiceError,
    HttpRequest,
    PostgresEditorService,
    PsycopgDemandReviewQueue,
)
from desire_platform.demand.adapters.postgres.migrations import (
    DEMAND_REQUIRED_IAM_SCHEMA_VERSION,
    DEMAND_SCHEMA_HEAD_VERSION,
)


NOW = datetime(2026, 8, 25, 12, 0, tzinfo=timezone.utc)


def _id(number: int) -> str:
    return str(UUID(int=number))


def _principal(number: int = 1, *roles: str) -> EditorPrincipal:
    user_id = _id(number)
    duties = tuple(sorted(roles or ("OPERATIONS_REVIEWER",)))
    return EditorPrincipal(
        user_id=user_id,
        session_id=_id(number + 100),
        organization_id=None,
        role_codes=duties,
        workspace_id=f"platform:{user_id}",
        workspace_kind="PLATFORM",
        membership_id=None,
        organization_role_codes=(),
        user_role_codes=(),
        platform_duty_codes=duties,
        principal_marker_sha256=bytes([number]) * 32,
    )


def _item(number: int, *, decision: str, reviewed_at: datetime):
    verified = decision == "VERIFIED"
    return EditorReviewHistoryItemDto(
        review_id=_id(number),
        demand_id=_id(number + 1_000),
        demand_version_id=_id(number + 2_000),
        decision=decision,
        reason_codes=() if verified else ("SCOPE_UNCLEAR",),
        required_field_codes=() if verified else ("SCOPE",),
        budget_health_code="HEALTHY" if verified else None,
        risk_code="STANDARD" if verified else None,
        reviewed_at=reviewed_at,
    )


ITEMS = (
    _item(30, decision="VERIFIED", reviewed_at=NOW),
    _item(20, decision="NEEDS_CHANGES", reviewed_at=NOW),
    _item(10, decision="VERIFIED", reviewed_at=NOW - timedelta(minutes=1)),
)


class _Queue:
    def __init__(self) -> None:
        self.calls = []

    def list_history(
        self,
        *,
        principal,
        maximum_items,
        cursor_reviewed_at,
        cursor_review_id,
    ):
        self.calls.append(
            (
                principal,
                maximum_items,
                cursor_reviewed_at,
                cursor_review_id,
            )
        )
        if cursor_review_id is None:
            return ITEMS[: maximum_items + 1]
        boundary = next(
            index
            for index, item in enumerate(ITEMS)
            if item.review_id == str(cursor_review_id)
            and item.reviewed_at == cursor_reviewed_at
        )
        return ITEMS[boundary + 1 : boundary + maximum_items + 2]


class _Clock:
    @staticmethod
    def now() -> datetime:
        return NOW


def _keys() -> EditorPostgresKeys:
    return EditorPostgresKeys(
        id_key=b"i" * 32,
        profile_idempotency_key=b"p" * 32,
        profile_payload_key=b"q" * 32,
        demand_idempotency_key=b"d" * 32,
        demand_payload_key=b"h" * 32,
        demand_client_reference_key=b"r" * 32,
    )


def _service(queue: _Queue) -> PostgresEditorService:
    return PostgresEditorService(
        repository=object(),
        authorities=object(),
        evidence=object(),
        keys=_keys(),
        clock=_Clock(),
        review_queue=queue,
    )


def test_service_returns_stable_pages_and_actor_bound_cursor() -> None:
    queue = _Queue()
    service = _service(queue)
    actor = _principal()

    first = service.list_review_history(
        principal=actor,
        cursor=None,
        limit=2,
    )
    assert first.items == ITEMS[:2]
    assert first.has_more is True
    assert first.next_cursor is not None
    assert set(first.next_cursor).issubset(
        set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-")
    )

    second = service.list_review_history(
        principal=actor,
        cursor=first.next_cursor,
        limit=2,
    )
    assert second.items == ITEMS[2:]
    assert second.has_more is False
    assert second.next_cursor is None
    assert queue.calls[-1][2:] == (ITEMS[1].reviewed_at, UUID(ITEMS[1].review_id))

    with pytest.raises(EditorServiceError) as tampered:
        service.list_review_history(
            principal=actor,
            cursor=first.next_cursor[:-1] + ("A" if first.next_cursor[-1] != "A" else "B"),
            limit=2,
        )
    assert (tampered.value.status, tampered.value.code, tampered.value.path) == (
        422,
        "INVALID_CURSOR",
        "/query/cursor",
    )

    with pytest.raises(EditorServiceError) as cross_actor:
        service.list_review_history(
            principal=_principal(2),
            cursor=first.next_cursor,
            limit=2,
        )
    assert cross_actor.value.code == "INVALID_CURSOR"


def test_http_projection_is_exactly_the_safe_terminal_dto() -> None:
    queue = _Queue()
    api = EditorHttpApi(service=_service(queue))
    response = api.handle(
        request=HttpRequest(
            method="GET",
            path="/v1/app/review-history",
            headers={},
            json={},
            query={"limit": "1"},
        ),
        principal=_principal(),
    )

    assert response.status == 200
    assert response.json["data"]["schema_version"] == "demand-review-history-v1"
    item = response.json["data"]["items"][0]
    assert set(item) == {
        "review_id",
        "demand_id",
        "demand_version_id",
        "decision",
        "reason_codes",
        "required_field_codes",
        "budget_health_code",
        "risk_code",
        "reviewed_at",
    }
    for forbidden in (
        "content",
        "organization_id",
        "owner_user_id",
        "reviewer_user_id",
        "duty_grant_id",
        "authority",
        "payload_hash",
        "note",
    ):
        assert forbidden not in item


def test_history_is_reviewer_only_and_query_contract_is_closed() -> None:
    queue = _Queue()
    api = EditorHttpApi(service=_service(queue))
    non_reviewer = api.handle(
        request=HttpRequest(
            method="GET",
            path="/v1/app/review-history",
            headers={},
            json={},
        ),
        principal=_principal(3, "ACCESS_ADMIN"),
    )
    assert non_reviewer.status == 404
    assert non_reviewer.json == {"error": {"code": "RESOURCE_NOT_FOUND"}}
    assert queue.calls == []

    for query in (
        {"limit": "0"},
        {"limit": "101"},
        {"owner_user_id": _id(99)},
        {"cursor": "not-a-signed-cursor"},
    ):
        response = api.handle(
            request=HttpRequest(
                method="GET",
                path="/v1/app/review-history",
                headers={},
                json={},
                query=query,
            ),
            principal=_principal(),
        )
        assert response.status == 422
        assert response.json["error"]["code"] == "INVALID_REQUEST"
        assert response.json["error"]["path"] == "/query"


def test_dto_rejects_non_terminal_or_cross_shape_fields() -> None:
    with pytest.raises(ValueError):
        _item(40, decision="PENDING", reviewed_at=NOW)
    with pytest.raises(ValueError):
        EditorReviewHistoryItemDto(
            review_id=_id(40),
            demand_id=_id(41),
            demand_version_id=_id(42),
            decision="NEEDS_CHANGES",
            reason_codes=("SCOPE_UNCLEAR",),
            required_field_codes=("SCOPE",),
            budget_health_code="HEALTHY",
            risk_code=None,
            reviewed_at=NOW,
        )


class _Connection:
    def __init__(self, rows) -> None:
        self.rows = rows
        self.fetchone_value = None
        self.executed = []

    def execute(self, sql, params=None):
        self.executed.append((sql, params))
        if "session_user,current_user" in sql:
            self.fetchone_value = ("demand_review", "demand_review", 18)
        elif "FROM demand.schema_compatibility" in sql:
            self.fetchone_value = (
                "demand",
                DEMAND_SCHEMA_HEAD_VERSION,
                DEMAND_SCHEMA_HEAD_VERSION,
                DEMAND_SCHEMA_HEAD_VERSION,
                DEMAND_SCHEMA_HEAD_VERSION,
                DEMAND_REQUIRED_IAM_SCHEMA_VERSION,
            )
        elif "pg_catalog.set_config" in sql:
            self.fetchone_value = (params[1],)
        else:
            self.fetchone_value = None
        return self

    def fetchone(self):
        return self.fetchone_value

    def fetchall(self):
        return self.rows


class _Connections:
    def __init__(self, rows) -> None:
        self.connection = _Connection(rows)
        self.released = []
        self.discarded = []

    def checkout(self):
        return self.connection

    def release(self, connection):
        self.released.append(connection)

    def discard(self, connection):
        self.discarded.append(connection)


class _Validator:
    @staticmethod
    def validate(value, *, schema_name):
        del value, schema_name


def test_postgres_adapter_calls_the_allowlisted_safe_nine_column_program() -> None:
    row = (
        UUID(ITEMS[0].review_id),
        UUID(ITEMS[0].demand_id),
        UUID(ITEMS[0].demand_version_id),
        ITEMS[0].decision,
        [],
        [],
        ITEMS[0].budget_health_code,
        ITEMS[0].risk_code,
        ITEMS[0].reviewed_at,
    )
    connections = _Connections([row])
    queue = PsycopgDemandReviewQueue(
        connections=connections,
        event_validator=_Validator(),
    )

    result = queue.list_history(
        principal=_principal(),
        maximum_items=25,
    )

    assert result == (ITEMS[0],)
    history_call = next(
        call
        for call in connections.connection.executed
        if "list_own_demand_review_history_v1" in call[0]
    )
    assert history_call[1] == (
        UUID(_principal().user_id),
        UUID(_principal().session_id),
        _principal().principal_marker_sha256,
        25,
        None,
        None,
    )
    assert history_call[0].startswith(
        "SELECT review_id,demand_id,demand_version_id,decision,"
        "reason_codes,required_field_codes,budget_health_code,"
        "risk_code,reviewed_at FROM "
    )
    assert connections.released == [connections.connection]
    assert connections.discarded == []

    malformed = _Connections([row + ("unsafe",)])
    malformed_queue = PsycopgDemandReviewQueue(
        connections=malformed,
        event_validator=_Validator(),
    )
    with pytest.raises(DemandReviewQueueError) as rejected:
        malformed_queue.list_history(
            principal=_principal(),
            maximum_items=25,
        )
    assert rejected.value.code == "SERVICE_UNAVAILABLE"
    assert malformed.discarded == [malformed.connection]
