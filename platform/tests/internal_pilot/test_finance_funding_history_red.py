"""Closed contracts for Finance Operator terminal-review discovery."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from desire_platform.internal_pilot.editor.contracts import (
    EditorPrincipal,
    EditorServiceError,
)
from desire_platform.internal_pilot.editor.http import (
    EditorHttpApi,
    HttpRequest,
)
from desire_platform.internal_pilot.finance_funding import (
    FinanceFundingHistoryItemDto,
    FinanceFundingHistoryPageDto,
    FinanceFundingKeys,
    PsycopgFinanceFundingService,
)


ACTOR = "10000000-0000-4000-8000-000000000001"
OTHER_ACTOR = "10000000-0000-4000-8000-000000000002"
SESSION = "20000000-0000-4000-8000-000000000001"
REVIEW_1 = "30000000-0000-4000-8000-000000000003"
REVIEW_2 = "30000000-0000-4000-8000-000000000002"
DEMAND_1 = "40000000-0000-4000-8000-000000000003"
DEMAND_2 = "40000000-0000-4000-8000-000000000002"
VERSION_1 = "50000000-0000-4000-8000-000000000003"
VERSION_2 = "50000000-0000-4000-8000-000000000002"
NOW = datetime(2026, 8, 26, 12, 0, tzinfo=timezone.utc)


def _principal(user_id: str = ACTOR) -> EditorPrincipal:
    return EditorPrincipal(
        user_id=user_id,
        session_id=SESSION,
        organization_id=None,
        role_codes=("FINANCE_OPERATOR",),
        workspace_id=f"platform:{user_id}",
        workspace_kind="PLATFORM",
        membership_id=None,
        principal_marker_sha256=b"m" * 32,
        platform_duty_codes=("FINANCE_OPERATOR",),
    )


def _row(
    review_id: str,
    demand_id: str,
    version_id: str,
    status: str,
    completed_at: datetime,
):
    return (review_id, demand_id, version_id, status, completed_at)


class _HistoryCursor:
    def __init__(self, rows):
        self._rows = rows

    def fetchall(self):
        return self._rows


class _HistoryConnection:
    def __init__(self, rows) -> None:
        self.rows = rows
        self.calls = []

    def execute(self, query, parameters):
        self.calls.append((query, parameters))
        return _HistoryCursor(self.rows)


class _UnusedPool:
    def checkout(self):
        raise AssertionError("direct history service does not checkout")

    def release(self, connection):
        raise AssertionError(connection)

    def discard(self, connection):
        raise AssertionError(connection)


class _DirectHistoryService(PsycopgFinanceFundingService):
    def __init__(self, rows) -> None:
        super().__init__(
            connections=_UnusedPool(),
            keys=FinanceFundingKeys(
                id_key=b"i" * 32,
                idempotency_key=b"d" * 32,
                payload_key=b"p" * 32,
            ),
        )
        self.connection = _HistoryConnection(rows)
        self.operations = []

    def _read(self, *, principal, operation, projector, funding_review_id=None):
        self.operations.append((principal, operation, funding_review_id))
        return projector(self.connection)


def test_history_page_is_actor_bound_sorted_and_keyset_paginated() -> None:
    rows = (
        _row(REVIEW_1, DEMAND_1, VERSION_1, "SECURED", NOW),
        _row(
            REVIEW_2,
            DEMAND_2,
            VERSION_2,
            "REJECTED",
            NOW - timedelta(minutes=1),
        ),
    )
    service = _DirectHistoryService(rows)

    first = service.list_funding_review_history(
        principal=_principal(), cursor=None, limit=1
    )

    assert first.schema_version == "finance-funding-review-history-v1"
    assert first.items == (
        FinanceFundingHistoryItemDto(
            funding_review_id=REVIEW_1,
            demand_id=DEMAND_1,
            demand_version_id=VERSION_1,
            status="SECURED",
            completed_at=NOW,
        ),
    )
    assert first.has_more is True
    assert first.next_cursor is not None
    assert service.operations[-1][1] == "LIST_FUNDING_REVIEWS"

    service.connection.rows = ()
    second = service.list_funding_review_history(
        principal=_principal(), cursor=first.next_cursor, limit=1
    )
    assert second == FinanceFundingHistoryPageDto(
        schema_version="finance-funding-review-history-v1",
        items=(),
        next_cursor=None,
        has_more=False,
    )
    parameters = service.connection.calls[-1][1]
    assert parameters[4] == NOW
    assert str(parameters[5]) == REVIEW_1

    for principal, cursor in (
        (_principal(), first.next_cursor[:-1] + "A"),
        (_principal(OTHER_ACTOR), first.next_cursor),
    ):
        with pytest.raises(EditorServiceError) as raised:
            service.list_funding_review_history(
                principal=principal,
                cursor=cursor,
                limit=1,
            )
        assert raised.value.status == 422
        assert raised.value.code == "INVALID_CURSOR"


def test_history_dtos_reject_leak_fields_duplicates_and_unsorted_rows() -> None:
    item = FinanceFundingHistoryItemDto(
        funding_review_id=REVIEW_1,
        demand_id=DEMAND_1,
        demand_version_id=VERSION_1,
        status="SECURED",
        completed_at=NOW,
    )
    with pytest.raises(TypeError):
        FinanceFundingHistoryItemDto(
            **{**item.__dict__, "organization_id": OTHER_ACTOR}
        )
    with pytest.raises(ValueError):
        FinanceFundingHistoryPageDto(
            schema_version="finance-funding-review-history-v1",
            items=(item, item),
            next_cursor=None,
            has_more=False,
        )
    older = FinanceFundingHistoryItemDto(
        funding_review_id=REVIEW_2,
        demand_id=DEMAND_2,
        demand_version_id=VERSION_2,
        status="DISCREPANCY",
        completed_at=NOW - timedelta(minutes=1),
    )
    with pytest.raises(ValueError):
        FinanceFundingHistoryPageDto(
            schema_version="finance-funding-review-history-v1",
            items=(older, item),
            next_cursor=None,
            has_more=False,
        )


class _HttpFinanceProbe:
    def list_funding_review_history(self, *, principal, cursor, limit):
        assert principal == _principal()
        assert cursor is None
        assert limit == 25
        return FinanceFundingHistoryPageDto(
            schema_version="finance-funding-review-history-v1",
            items=(),
            next_cursor=None,
            has_more=False,
        )

    def list_funding_reviews(self, **values):
        raise AssertionError(values)

    def claim_funding_review(self, **values):
        raise AssertionError(values)

    def get_funding_review(self, **values):
        raise AssertionError(values)

    def confirm_funding_review(self, **values):
        raise AssertionError(values)

    def release_funding_review_assignment(self, **values):
        raise AssertionError(values)

    def submit_funding_review_finding(self, **values):
        raise AssertionError(values)


def test_http_history_route_is_read_only_and_query_closed() -> None:
    api = EditorHttpApi(service=object(), finance_service=_HttpFinanceProbe())
    response = api.handle(
        request=HttpRequest(
            method="GET",
            path="/v1/app/finance/funding-review-history",
            headers={},
            json={},
            query={},
        ),
        principal=_principal(),
    )
    assert response.status == 200
    assert response.headers["Cache-Control"] == "no-store"
    assert response.json == {
        "data": {
            "schema_version": "finance-funding-review-history-v1",
            "items": [],
            "next_cursor": None,
            "has_more": False,
        }
    }

    invalid = api.handle(
        request=HttpRequest(
            method="GET",
            path="/v1/app/finance/funding-review-history",
            headers={},
            json={},
            query={"actor_user_id": ACTOR},
        ),
        principal=_principal(),
    )
    assert invalid.status == 422
    assert invalid.json == {
        "error": {"code": "INVALID_REQUEST", "path": "/query"}
    }
