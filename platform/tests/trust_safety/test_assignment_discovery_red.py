from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace
from uuid import UUID

import pytest

from desire_platform.trust_safety.appeal_http import (
    AppealHttpApplicationDispatcher,
    AppealHttpRequest,
)
from desire_platform.trust_safety.application import TrustActorContext
from desire_platform.trust_safety.http import (
    TrustHttpApplicationDispatcher,
    TrustHttpProjection,
    TrustHttpRequest,
)
from desire_platform.trust_safety.ports import (
    AppealActiveAssignmentItem,
    AppealActiveAssignmentsProjection,
)


def _id(number: int) -> str:
    return str(UUID(int=number))


USER_ID = _id(1)
SESSION_ID = _id(2)
CASE_ID = _id(3)
APPEAL_ID = _id(4)
TRACE_ID = _id(5)
HOLD_ID = _id(6)
SECOND_HOLD_ID = _id(7)
TRUST_ETAG = '"trust-3-0123456789abcdef01234567"'
APPEAL_ETAG = '"appeal-4-0123456789abcdef01234567"'
EXPIRES_AT = datetime(2026, 8, 19, 12, 0, tzinfo=timezone.utc)


def _actor() -> TrustActorContext:
    return TrustActorContext(
        actor_user_id=USER_ID,
        session_id=SESSION_ID,
        organization_id=None,
        correlation_id=TRACE_ID,
        causation_id=TRACE_ID,
        trace_id=TRACE_ID,
        original_actor_user_id=None,
    )


def _trust_projection(*, items=None) -> TrustHttpProjection:
    return TrustHttpProjection(
        "MY_ACTIVE_CASE_ASSIGNMENTS",
        {
            "entity_tag": TRUST_ETAG,
            "items": [
                {
                    "assignment_expires_at": "2026-08-19T12:00:00Z",
                    "assignment_purpose": "CASE_TRIAGE",
                    "case_id": CASE_ID,
                    "hold_id": None,
                }
            ]
            if items is None
            else items,
        },
        TRUST_ETAG,
    )


class _TrustProjections:
    def __init__(self, *, items=None) -> None:
        self.calls = []
        self.items = items

    def list_my_active_case_assignments(self, *, actor, limit):
        self.calls.append((actor, limit))
        return _trust_projection(items=self.items)

    def read_assigned_hold_release(self, *, actor, hold_id):
        self.calls.append((actor, hold_id))
        return TrustHttpProjection(
            "ASSIGNED_HOLD_RELEASE",
            {
                "action_codes": ["REQUEST_MATCHING"],
                "assignment_expires_at": "2026-08-19T12:00:00Z",
                "case_id": CASE_ID,
                "case_status": "IN_REVIEW",
                "effective_at": "2026-08-19T10:00:00Z",
                "entity_tag": TRUST_ETAG,
                "expires_at": "2026-08-19T13:00:00Z",
                "hold_id": HOLD_ID,
                "hold_status": "ACTIVE",
                "reason_code": "RETALIATION_RISK",
            },
            TRUST_ETAG,
        )


class _AppealProjections:
    def __init__(self, *, items=None) -> None:
        self.calls = []
        self.items = items

    def list_my_active_appeal_assignments(self, *, actor, limit):
        self.calls.append((actor, limit))
        return AppealActiveAssignmentsProjection(
            items=(
                AppealActiveAssignmentItem(
                    appeal_id=APPEAL_ID,
                    assignment_expires_at=EXPIRES_AT,
                ),
            )
            if self.items is None
            else self.items,
            entity_tag=APPEAL_ETAG,
        )


def test_closed_assignment_projection_types_accept_items_and_zero_rows_only() -> None:
    assert _trust_projection().as_json()["items"][0]["case_id"] == CASE_ID
    paired = _trust_projection(
        items=[
            {
                "assignment_expires_at": "2026-08-19T12:00:00Z",
                "assignment_purpose": "CASE_TRIAGE",
                "case_id": CASE_ID,
                "hold_id": None,
            },
            {
                "assignment_expires_at": "2026-08-19T12:00:00Z",
                "assignment_purpose": "HOLD_RELEASE",
                "case_id": CASE_ID,
                "hold_id": HOLD_ID,
            },
            {
                "assignment_expires_at": "2026-08-19T13:00:00Z",
                "assignment_purpose": "HOLD_RELEASE",
                "case_id": CASE_ID,
                "hold_id": SECOND_HOLD_ID,
            },
        ]
    )
    assert [item["assignment_purpose"] for item in paired.as_json()["items"]] == [
        "CASE_TRIAGE",
        "HOLD_RELEASE",
        "HOLD_RELEASE",
    ]
    with pytest.raises(ValueError, match="TRUST_HTTP_PROJECTION_INVALID"):
        _trust_projection(items=[paired.as_json()["items"][0]] * 2)
    for unsafe in (
        {
            **paired.as_json()["items"][0],
            "hold_id": HOLD_ID,
        },
        {
            **paired.as_json()["items"][1],
            "hold_id": None,
        },
    ):
        with pytest.raises(ValueError, match="TRUST_HTTP_PROJECTION_INVALID"):
            _trust_projection(items=[unsafe])
    hold_projection = _TrustProjections().read_assigned_hold_release(
        actor=_actor(), hold_id=HOLD_ID
    ).as_json()
    for unsafe_hold in (
        {**hold_projection, "effective_at": hold_projection["expires_at"]},
        {
            **hold_projection,
            "assignment_expires_at": "2026-08-19T13:00:00.000001Z",
        },
        {**hold_projection, "expires_at": "2026-08-19T21:00:00+08:00"},
    ):
        with pytest.raises(ValueError, match="TRUST_HTTP_PROJECTION_INVALID"):
            TrustHttpProjection(
                "ASSIGNED_HOLD_RELEASE", unsafe_hold, TRUST_ETAG
            )
    assert _trust_projection(items=[]).as_json()["items"] == []
    assert AppealActiveAssignmentsProjection(
        items=(), entity_tag=APPEAL_ETAG
    ).items == ()
    with pytest.raises(ValueError, match="TRUST_HTTP_PROJECTION_INVALID"):
        TrustHttpProjection(
            "MY_ACTIVE_CASE_ASSIGNMENTS",
            {
                "entity_tag": TRUST_ETAG,
                "items": [
                    {
                        "assignment_expires_at": "2026-08-19T12:00:00Z",
                        "assignment_id": CASE_ID,
                        "assignment_purpose": "CASE_TRIAGE",
                        "case_id": CASE_ID,
                        "hold_id": None,
                    }
                ],
            },
            TRUST_ETAG,
        )
    completed = TrustHttpProjection(
        "MY_COMPLETED_CASE_ASSIGNMENTS",
        {
            "entity_tag": TRUST_ETAG,
            "has_more": False,
            "items": [
                {
                    "case_id": CASE_ID,
                    "decided_at": "2026-08-19T12:00:00Z",
                    "outcome_code": "PROTECTION_MAINTAINED",
                }
            ],
        },
        TRUST_ETAG,
    )
    assert set(completed.as_json()["items"][0]) == {
        "case_id",
        "decided_at",
        "outcome_code",
    }
    with pytest.raises(ValueError, match="APPEAL_READ_PROJECTION_INVALID"):
        AppealActiveAssignmentItem(
            appeal_id=APPEAL_ID,
            assignment_expires_at=EXPIRES_AT.replace(tzinfo=None),
        )


def test_dispatchers_route_assignment_discovery_with_bounded_server_limit() -> None:
    trust_port = _TrustProjections()
    trust = object.__new__(TrustHttpApplicationDispatcher)
    trust._bindings = SimpleNamespace(projections=trust_port)
    trust_response = trust.handle(
        request=TrustHttpRequest(
            method="GET",
            path="/v1/app/trust/assignments",
            headers={},
            json={},
        ),
        actor=_actor(),
    )
    assert (trust_response.status, trust_response.headers["etag"]) == (
        200,
        TRUST_ETAG,
    )
    assert trust_port.calls == [(_actor(), 100)]

    hold_response = trust.handle(
        request=TrustHttpRequest(
            method="GET",
            path=f"/v1/app/trust/assigned-holds/{HOLD_ID}",
            headers={},
            json={},
        ),
        actor=_actor(),
    )
    assert (hold_response.status, hold_response.headers["etag"]) == (
        200,
        TRUST_ETAG,
    )
    assert set(hold_response.json["data"]) == {
        "action_codes",
        "assignment_expires_at",
        "case_id",
        "case_status",
        "effective_at",
        "entity_tag",
        "expires_at",
        "hold_id",
        "hold_status",
        "reason_code",
    }
    assert trust_port.calls[-1] == (_actor(), HOLD_ID)

    appeal_port = _AppealProjections()
    appeal = object.__new__(AppealHttpApplicationDispatcher)
    appeal._bindings = SimpleNamespace(projections=appeal_port)
    appeal_response = appeal.handle(
        request=AppealHttpRequest(
            method="GET",
            path="/v1/app/appeal-review/assignments",
            headers={},
            query={},
            json={},
        ),
        actor=_actor(),
    )
    assert (appeal_response.status, appeal_response.headers["etag"]) == (
        200,
        APPEAL_ETAG,
    )
    assert appeal_port.calls == [(_actor(), 100)]

    empty_trust_port = _TrustProjections(items=[])
    trust._bindings = SimpleNamespace(projections=empty_trust_port)
    empty_trust = trust.handle(
        request=TrustHttpRequest(
            method="GET",
            path="/v1/app/trust/assignments",
            headers={},
            json={},
        ),
        actor=_actor(),
    )
    assert empty_trust.status == 200
    assert empty_trust.json == {
        "data": {"entity_tag": TRUST_ETAG, "items": []}
    }

    empty_appeal_port = _AppealProjections(items=())
    appeal._bindings = SimpleNamespace(projections=empty_appeal_port)
    empty_appeal = appeal.handle(
        request=AppealHttpRequest(
            method="GET",
            path="/v1/app/appeal-review/assignments",
            headers={},
            query={},
            json={},
        ),
        actor=_actor(),
    )
    assert empty_appeal.status == 200
    assert empty_appeal.json == {
        "data": {"entity_tag": APPEAL_ETAG, "items": []}
    }
