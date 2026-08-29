from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import json

import pytest

from desire_platform.http.contracts import AuthenticatedHttpActor
from desire_platform.identity_access.domain.errors import IamError
from desire_platform.internal_pilot.editor import EditorPrincipal
from desire_platform.internal_pilot.runtime import InternalSandboxApiMux
from desire_platform.internal_pilot.trust_http import TrustAsgiApplication
from desire_platform.trust_safety.http import (
    TrustHttpApplicationDispatcher,
    TrustHttpResponse,
)


USER_ID = "10000000-0000-4000-8000-000000000001"
SESSION_ID = "20000000-0000-4000-8000-000000000001"
ORG_ID = "30000000-0000-4000-8000-000000000001"
TRACE_ID = "90000000-0000-4000-8000-000000000001"
REPORT_ID = "50000000-0000-4000-8000-000000000001"
RAW_HANDLE = "trust-session-handle-abcdefghijklmnopqrstuvwxyz-012345"
RAW_CSRF = "trust-csrf-token-abcdefghijklmnopqrstuvwxyz-0123456789"
NOW = datetime(2026, 8, 18, 8, 0, tzinfo=timezone.utc)


def async_test(function):
    def run():
        return asyncio.run(function())

    return run


class SessionSecurity:
    def __init__(self) -> None:
        self.auth_calls = []
        self.csrf_calls = []
        self.actor = AuthenticatedHttpActor(
            actor_user_id=USER_ID,
            session_id=SESSION_ID,
            correlation_id=TRACE_ID,
            causation_id=TRACE_ID,
            trace_id=TRACE_ID,
            original_actor_id=None,
            auth_time=NOW,
            acr_code="urn:desire:acr:mfa",
            amr_codes=("pwd", "otp"),
        )

    def authenticate(self, *, raw_session_handle, trace_id):
        self.auth_calls.append((raw_session_handle, trace_id))
        if raw_session_handle != RAW_HANDLE:
            raise IamError("AUTHENTICATION_REQUIRED")
        return self.actor

    def require_valid(self, **facts):
        self.csrf_calls.append(facts)
        if facts["raw_csrf_token"] != RAW_CSRF:
            raise IamError("INVALID_REQUEST")


class PrincipalResolver:
    def __init__(self) -> None:
        self.calls = []

    def resolve(self, *, actor, requested_workspace_id):
        self.calls.append((actor, requested_workspace_id))
        if requested_workspace_id == f"org:{ORG_ID}":
            return EditorPrincipal(
                user_id=USER_ID,
                session_id=SESSION_ID,
                organization_id=ORG_ID,
                role_codes=("DEMAND_OWNER",),
                workspace_id=f"org:{ORG_ID}",
                workspace_kind="ORGANIZATION",
                membership_id="40000000-0000-4000-8000-000000000001",
                organization_role_codes=("DEMAND_OWNER",),
                principal_marker_sha256=b"a" * 32,
            )
        if requested_workspace_id == f"platform:{USER_ID}":
            return EditorPrincipal(
                user_id=USER_ID,
                session_id=SESSION_ID,
                organization_id=None,
                role_codes=("TRUST_OFFICER",),
                workspace_id=f"platform:{USER_ID}",
                workspace_kind="PLATFORM",
                platform_duty_codes=("TRUST_OFFICER",),
                principal_marker_sha256=b"b" * 32,
            )
        raise IamError("ACCESS_DENIED")


class Dispatcher(TrustHttpApplicationDispatcher):
    def __init__(self) -> None:
        self.calls = []

    def handle(self, *, request, actor):
        self.calls.append((request, actor))
        if request.method == "POST":
            return TrustHttpResponse(
                status=201,
                headers={"content-type": "application/json"},
                json={"data": {"case_id": "40000000-0000-4000-8000-000000000001"}},
            )
        return TrustHttpResponse(
            status=200,
            headers={
                "content-type": "application/json",
                "etag": '"trust-1-0123456789abcdef01234567"',
            },
            json={"data": {"report_id": REPORT_ID}},
        )


def application():
    dispatcher = Dispatcher()
    security = SessionSecurity()
    resolver = PrincipalResolver()
    app = TrustAsgiApplication(
        dispatcher=dispatcher,
        session_security=security,
        principal_resolver=resolver,
        allowed_origins=("https://pilot.example.test",),
        trace_id_source=lambda: TRACE_ID,
    )
    return app, dispatcher, security, resolver


async def invoke(app, *, method="GET", path=None, query=b"", headers=(), body=b""):
    path = path or f"/v1/app/trust/reports/{REPORT_ID}"
    messages = [{"type": "http.request", "body": body, "more_body": False}]
    sent = []

    async def receive():
        return messages.pop(0)

    async def send(message):
        sent.append(message)

    await app(
        {
            "type": "http",
            "method": method,
            "scheme": "https",
            "path": path,
            "raw_path": path.encode("ascii"),
            "query_string": query,
            "headers": list(headers),
        },
        receive,
        send,
    )
    return (
        sent[0]["status"],
        dict(sent[0]["headers"]),
        json.loads(sent[1]["body"] or b"{}"),
    )


@async_test
async def test_reporter_and_officer_paths_require_the_exact_selected_workspace():
    app, dispatcher, _, resolver = application()
    cookie = (b"cookie", ("__Host-ds_session=" + RAW_HANDLE).encode())

    status, headers, body = await invoke(
        app,
        headers=(cookie, (b"x-workspace-id", f"org:{ORG_ID}".encode())),
    )
    assert (status, body["data"]["report_id"]) == (200, REPORT_ID)
    assert headers[b"cache-control"] == b"no-store"
    assert headers[b"etag"].startswith(b'"trust-')
    assert dispatcher.calls[0][1].organization_id == ORG_ID

    officer, _, _ = await invoke(
        app,
        path="/v1/app/trust/queue",
        headers=(cookie, (b"x-workspace-id", f"platform:{USER_ID}".encode())),
    )
    assignments, assignment_headers, _ = await invoke(
        app,
        path="/v1/app/trust/assignments",
        headers=(cookie, (b"x-workspace-id", f"platform:{USER_ID}".encode())),
    )
    history, history_headers, _ = await invoke(
        app,
        path="/v1/app/trust/history",
        headers=(cookie, (b"x-workspace-id", f"platform:{USER_ID}".encode())),
    )
    assigned_hold, assigned_hold_headers, _ = await invoke(
        app,
        path=f"/v1/app/trust/assigned-holds/{REPORT_ID}",
        headers=(cookie, (b"x-workspace-id", f"platform:{USER_ID}".encode())),
    )
    assert (officer, assignments, history, assigned_hold) == (200, 200, 200, 200)
    assert assignment_headers[b"cache-control"] == b"no-store"
    assert assignment_headers[b"etag"].startswith(b'"trust-')
    assert history_headers[b"cache-control"] == b"no-store"
    assert history_headers[b"etag"].startswith(b'"trust-')
    assert assigned_hold_headers[b"cache-control"] == b"no-store"
    assert assigned_hold_headers[b"etag"].startswith(b'"trust-')
    assert dispatcher.calls[1][1].organization_id is None
    assert [call[1] for call in resolver.calls] == [
        f"org:{ORG_ID}",
        f"platform:{USER_ID}",
        f"platform:{USER_ID}",
        f"platform:{USER_ID}",
        f"platform:{USER_ID}",
    ]


@async_test
async def test_owned_report_query_is_closed_and_forwarded_only_after_reporter_authority():
    app, dispatcher, _, _ = application()
    cookie = (b"cookie", ("__Host-ds_session=" + RAW_HANDLE).encode())
    cursor = "a" * 64 + "." + "b" * 43
    reporter_headers = (
        cookie,
        (b"x-workspace-id", f"org:{ORG_ID}".encode()),
    )

    status, headers, _ = await invoke(
        app,
        path="/v1/app/trust/reports",
        query=f"limit=1&cursor={cursor}".encode(),
        headers=reporter_headers,
    )

    assert status == 200
    assert headers[b"cache-control"] == b"no-store"
    request, actor = dispatcher.calls[-1]
    assert request.query == {"limit": ("1",), "cursor": (cursor,)}
    assert actor.organization_id == ORG_ID

    for raw in (
        b"limit=01",
        b"limit=1&limit=2",
        b"cursor=unsigned",
        b"actor_user_id=forged",
        b"limit=1%26actor=forged",
    ):
        before = len(dispatcher.calls)
        rejected, _, body = await invoke(
            app,
            path="/v1/app/trust/reports",
            query=raw,
            headers=reporter_headers,
        )
        assert (rejected, body["error"]["code"]) == (400, "INVALID_REQUEST")
        assert len(dispatcher.calls) == before

    before = len(dispatcher.calls)
    hidden, _, body = await invoke(
        app,
        path="/v1/app/trust/reports",
        query=b"actor_user_id=forged",
        headers=(cookie, (b"x-workspace-id", f"platform:{USER_ID}".encode())),
    )
    assert (hidden, body) == (404, {"error": {"code": "RESOURCE_NOT_FOUND"}})
    assert len(dispatcher.calls) == before


@async_test
async def test_authentication_workspace_and_cross_role_fail_closed_before_dispatch():
    app, dispatcher, _, _ = application()
    cookie = (b"cookie", ("__Host-ds_session=" + RAW_HANDLE).encode())
    cases = (
        ((), 401, "AUTHENTICATION_REQUIRED"),
        ((cookie,), 400, "INVALID_REQUEST"),
        (
            (cookie, (b"x-workspace-id", f"platform:{USER_ID}".encode())),
            404,
            "RESOURCE_NOT_FOUND",
        ),
    )
    for headers, wanted_status, wanted_code in cases:
        status, _, body = await invoke(app, headers=headers)
        assert (status, body["error"]["code"]) == (wanted_status, wanted_code)
    status, _, body = await invoke(
        app,
        path="/v1/app/trust/assignments",
        headers=(cookie, (b"x-workspace-id", f"org:{ORG_ID}".encode())),
    )
    assert (status, body["error"]["code"]) == (404, "RESOURCE_NOT_FOUND")
    status, _, body = await invoke(
        app,
        path="/v1/app/trust/history",
        headers=(cookie, (b"x-workspace-id", f"org:{ORG_ID}".encode())),
    )
    assert (status, body["error"]["code"]) == (404, "RESOURCE_NOT_FOUND")
    status, headers, body = await invoke(
        app,
        path=f"/v1/app/trust/assigned-holds/{REPORT_ID}",
        headers=(cookie, (b"x-workspace-id", f"org:{ORG_ID}".encode())),
    )
    assert (status, body) == (404, {"error": {"code": "RESOURCE_NOT_FOUND"}})
    assert b"etag" not in headers
    status, headers, body = await invoke(
        app,
        path=f"/v1/app/trust/assigned-holds/{REPORT_ID}",
        query=b"unexpected=1",
        headers=(cookie, (b"x-workspace-id", f"platform:{USER_ID}".encode())),
    )
    assert (status, body) == (404, {"error": {"code": "RESOURCE_NOT_FOUND"}})
    assert b"etag" not in headers
    assert not dispatcher.calls


@async_test
async def test_write_requires_exact_origin_csrf_json_idempotency_and_workspace():
    app, dispatcher, security, _ = application()
    body = json.dumps(
        {
            "category": "WORKFLOW_INTEGRITY",
            "demand_id": "70000000-0000-4000-8000-000000000001",
            "demand_version_id": "80000000-0000-4000-8000-000000000001",
            "evidence_reference_ids": [REPORT_ID],
            "impact_codes": ["WORKFLOW_INTEGRITY_RISK"],
            "incident_ended_at": None,
            "incident_started_at": "2026-08-18T07:00:00Z",
            "requested_protection_codes": ["PAUSE_SUBMISSION"],
        }
    ).encode()
    common = (
        (b"cookie", ("__Host-ds_session=" + RAW_HANDLE).encode()),
        (b"x-workspace-id", f"org:{ORG_ID}".encode()),
        (b"origin", b"https://pilot.example.test"),
        (b"x-csrf-token", RAW_CSRF.encode()),
        (b"idempotency-key", b"trust-http-idempotency-0001"),
        (b"content-type", b"application/json"),
    )
    status, headers, _ = await invoke(
        app,
        method="POST",
        path="/v1/app/trust/reports",
        headers=common,
        body=body,
    )
    assert status == 201
    assert headers[b"cache-control"] == b"no-store"
    assert b"etag" not in headers
    assert len(security.csrf_calls) == 1
    assert len(dispatcher.calls) == 1

    for omitted in (b"origin", b"x-csrf-token"):
        denied, _, payload = await invoke(
            app,
            method="POST",
            path="/v1/app/trust/reports",
            headers=tuple(item for item in common if item[0] != omitted),
            body=body,
        )
        assert denied == 403
        assert payload["error"]["code"] in {"CSRF_REQUIRED", "CSRF_INVALID"}
    assert len(dispatcher.calls) == 1


@async_test
async def test_transport_never_reflects_restricted_note_or_accepts_path_aliases():
    app, dispatcher, _, _ = application()
    common = (
        (b"cookie", ("__Host-ds_session=" + RAW_HANDLE).encode()),
        (b"x-workspace-id", f"platform:{USER_ID}".encode()),
        (b"origin", b"https://pilot.example.test"),
        (b"x-csrf-token", RAW_CSRF.encode()),
        (b"idempotency-key", b"trust-http-idempotency-0001"),
        (b"if-match", b'"trust-1-0123456789abcdef01234567"'),
        (b"content-type", b"application/json"),
    )
    secret = "restricted narrative must not reflect"
    status, _, payload = await invoke(
        app,
        method="PUT",
        path="/v1/app/trust/cases/../triage-draft",
        headers=common,
        body=json.dumps({"restricted_note": secret}).encode(),
    )
    assert status in {400, 404}
    assert secret not in json.dumps(payload)
    assert not dispatcher.calls


class AsgiDelegate:
    def __init__(self, status):
        self.status = status
        self.calls = 0

    async def __call__(self, scope, receive, send):
        self.calls += 1
        await send({"type": "http.response.start", "status": self.status, "headers": []})
        await send({"type": "http.response.body", "body": b"{}", "more_body": False})


@async_test
async def test_mux_routes_trust_before_editor_and_missing_binding_is_503():
    iam, editor, trust = AsgiDelegate(201), AsgiDelegate(202), AsgiDelegate(203)
    mux = InternalSandboxApiMux(
        iam_application=iam,
        editor_application=editor,
        trust_application=trust,
    )
    status, _, _ = await invoke(mux, path="/v1/app/trust/queue")
    assert status == 203
    assert (iam.calls, editor.calls, trust.calls) == (0, 0, 1)

    closed = InternalSandboxApiMux(
        iam_application=iam,
        editor_application=editor,
    )
    status, headers, body = await invoke(closed, path="/v1/app/trust/queue")
    assert (status, body["error"]["code"]) == (503, "SERVICE_UNAVAILABLE")
    assert headers[b"cache-control"] == b"no-store"
    assert editor.calls == 0
