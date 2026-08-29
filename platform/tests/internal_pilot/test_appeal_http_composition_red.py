from __future__ import annotations

import asyncio
from dataclasses import MISSING, fields
from datetime import datetime, timezone
import json

from desire_platform.http.contracts import AuthenticatedHttpActor
from desire_platform.identity_access.domain.errors import IamError
from desire_platform.internal_pilot.api_composition import (
    InternalSandboxApiDependencies,
)
from desire_platform.internal_pilot.appeal_http import AppealAsgiApplication
from desire_platform.internal_pilot.editor import EditorPrincipal
from desire_platform.internal_pilot.runtime import InternalSandboxApiMux
from desire_platform.trust_safety.appeal_http import (
    AppealHttpApplicationDispatcher,
    AppealHttpResponse,
)


USER_ID = "10000000-0000-4000-8000-000000000001"
SESSION_ID = "20000000-0000-4000-8000-000000000001"
ORG_ID = "30000000-0000-4000-8000-000000000001"
TRACE_ID = "90000000-0000-4000-8000-000000000001"
APPEAL_ID = "50000000-0000-4000-8000-000000000001"
OUTCOME_ID = "60000000-0000-4000-8000-000000000001"
RAW_HANDLE = "appeal-session-handle-abcdefghijklmnopqrstuvwxyz-01234"
RAW_CSRF = "appeal-csrf-token-abcdefghijklmnopqrstuvwxyz-0123456789"
ETAG = '"appeal-3-0123456789abcdef01234567"'
NOW = datetime(2026, 8, 19, 8, 0, tzinfo=timezone.utc)


def async_test(function):
    def run():
        return asyncio.run(function())

    return run


class SessionSecurity:
    def __init__(self):
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
        if raw_session_handle != RAW_HANDLE:
            raise IamError("AUTHENTICATION_REQUIRED")
        return self.actor

    def require_valid(self, **facts):
        self.csrf_calls.append(facts)
        if facts["raw_csrf_token"] != RAW_CSRF:
            raise IamError("INVALID_REQUEST")


class PrincipalResolver:
    def resolve(self, *, actor, requested_workspace_id):
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
                role_codes=("APPEAL_REVIEWER",),
                workspace_id=f"platform:{USER_ID}",
                workspace_kind="PLATFORM",
                platform_duty_codes=("APPEAL_REVIEWER",),
                principal_marker_sha256=b"b" * 32,
            )
        raise IamError("ACCESS_DENIED")


class Dispatcher(AppealHttpApplicationDispatcher):
    def __init__(self):
        self.calls = []

    def handle(self, *, request, actor):
        self.calls.append((request, actor))
        return AppealHttpResponse(
            status=201 if request.method == "POST" else 200,
            headers={
                "content-type": "application/json",
                **({"etag": ETAG} if request.method == "GET" else {}),
            },
            json={"data": {"appeal_id": APPEAL_ID}},
        )


def application():
    dispatcher = Dispatcher()
    security = SessionSecurity()
    app = AppealAsgiApplication(
        dispatcher=dispatcher,
        session_security=security,
        principal_resolver=PrincipalResolver(),
        allowed_origins=("https://pilot.example.test",),
        trace_id_source=lambda: TRACE_ID,
    )
    return app, dispatcher, security


async def invoke(app, *, method="GET", path=None, query=b"", headers=(), body=b""):
    path = path or f"/v1/app/appeals/{APPEAL_ID}"
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
async def test_applicant_and_reviewer_require_exact_workspace_and_session():
    app, dispatcher, _ = application()
    cookie = (b"cookie", ("__Host-ds_session=" + RAW_HANDLE).encode())
    applicant = await invoke(
        app,
        path="/v1/app/appeals",
        query=f"source_outcome_version_id={OUTCOME_ID}".encode(),
        headers=(cookie, (b"x-workspace-id", f"org:{ORG_ID}".encode())),
    )
    reviewer = await invoke(
        app,
        path="/v1/app/appeal-review/queue",
        headers=(cookie, (b"x-workspace-id", f"platform:{USER_ID}".encode())),
    )
    assignments = await invoke(
        app,
        path="/v1/app/appeal-review/assignments",
        headers=(cookie, (b"x-workspace-id", f"platform:{USER_ID}".encode())),
    )
    history = await invoke(
        app,
        path="/v1/app/appeal-review/history",
        headers=(cookie, (b"x-workspace-id", f"platform:{USER_ID}".encode())),
    )
    detail = await invoke(
        app,
        path=f"/v1/app/appeal-review/history/{APPEAL_ID}",
        headers=(cookie, (b"x-workspace-id", f"platform:{USER_ID}".encode())),
    )
    assert (
        applicant[0],
        reviewer[0],
        assignments[0],
        history[0],
        detail[0],
    ) == (200, 200, 200, 200, 200)
    assert all(
        response[1][b"cache-control"] == b"no-store"
        for response in (applicant, reviewer, assignments, history, detail)
    )
    assert history[1][b"etag"] == detail[1][b"etag"] == ETAG.encode()
    assert dispatcher.calls[0][0].query == {
        "source_outcome_version_id": (OUTCOME_ID,)
    }
    assert dispatcher.calls[0][1].organization_id == ORG_ID
    assert dispatcher.calls[1][1].organization_id is None
    assert dispatcher.calls[2][1].organization_id is None
    assert dispatcher.calls[3][0].query == {}
    assert dispatcher.calls[3][0].json == {}
    assert dispatcher.calls[3][1].organization_id is None
    assert dispatcher.calls[4][0].query == {}
    assert dispatcher.calls[4][0].json == {}
    assert dispatcher.calls[4][1].organization_id is None


@async_test
async def test_write_requires_origin_csrf_json_and_never_reflects_raw_statement():
    app, dispatcher, security = application()
    secret = "private applicant narrative"
    body = json.dumps({"source_outcome_version_id": OUTCOME_ID}).encode()
    common = (
        (b"cookie", ("__Host-ds_session=" + RAW_HANDLE).encode()),
        (b"x-workspace-id", f"org:{ORG_ID}".encode()),
        (b"origin", b"https://pilot.example.test"),
        (b"x-csrf-token", RAW_CSRF.encode()),
        (b"idempotency-key", b"appeal-http-idempotency-0001"),
        (b"content-type", b"application/json"),
    )
    status, headers, _ = await invoke(
        app, method="POST", path="/v1/app/appeals", headers=common, body=body
    )
    assert status == 201
    assert headers[b"cache-control"] == b"no-store"
    assert b"etag" not in headers
    assert len(security.csrf_calls) == 1

    denied, _, payload = await invoke(
        app,
        method="PUT",
        path=f"/v1/app/appeals/{APPEAL_ID}/draft",
        headers=tuple(item for item in common if item[0] != b"origin"),
        body=json.dumps({"applicant_statement": secret}).encode(),
    )
    assert (denied, payload["error"]["code"]) == (403, "CSRF_INVALID")
    assert secret not in json.dumps(payload)
    assert len(dispatcher.calls) == 1


@async_test
async def test_cross_role_query_alias_and_path_alias_fail_before_dispatch():
    app, dispatcher, _ = application()
    cookie = (b"cookie", ("__Host-ds_session=" + RAW_HANDLE).encode())
    cases = (
        (f"/v1/app/appeals/{APPEAL_ID}", b"", f"platform:{USER_ID}", 404),
        ("/v1/app/appeal-review/assignments", b"", f"org:{ORG_ID}", 404),
        ("/v1/app/appeals", b"unexpected=1", f"org:{ORG_ID}", 400),
        ("/v1/app/appeals/../draft", b"", f"org:{ORG_ID}", 400),
    )
    for path, query, workspace, expected in cases:
        status, _, _ = await invoke(
            app,
            path=path,
            query=query,
            headers=(cookie, (b"x-workspace-id", workspace.encode())),
        )
        assert status == expected
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
async def test_mux_routes_both_appeal_namespaces_and_missing_binding_is_503():
    iam, editor, trust, appeal = (
        AsgiDelegate(201),
        AsgiDelegate(202),
        AsgiDelegate(203),
        AsgiDelegate(204),
    )
    mux = InternalSandboxApiMux(
        iam_application=iam,
        editor_application=editor,
        trust_application=trust,
        appeal_application=appeal,
    )
    for path in ("/v1/app/appeals", "/v1/app/appeal-review/queue"):
        status, _, _ = await invoke(mux, path=path)
        assert status == 204
    assert (iam.calls, editor.calls, trust.calls, appeal.calls) == (0, 0, 0, 2)

    closed = InternalSandboxApiMux(
        iam_application=iam,
        editor_application=editor,
        trust_application=trust,
    )
    status, headers, payload = await invoke(closed, path="/v1/app/appeals")
    assert (status, payload["error"]["code"]) == (503, "SERVICE_UNAVAILABLE")
    assert headers[b"cache-control"] == b"no-store"


def test_api_composition_requires_closed_appeal_bindings():
    declared = {
        field.name: field for field in fields(InternalSandboxApiDependencies)
    }
    assert declared["appeal_http_bindings"].default is MISSING
    assert declared["trust_http_bindings"].default is None
