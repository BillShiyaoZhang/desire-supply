from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import unittest

from desire_platform.http.contracts import AuthenticatedHttpActor
from desire_platform.identity_access.domain.errors import IamError
from desire_platform.internal_pilot.editor import (
    EditorConfigurationDto,
    EditorHttpApi,
    EditorPrincipal,
    EditorService,
    EditorWorkspaceSummary,
    EditorTaxonomyBundleDto,
    MemoryEditorRepository,
    build_internal_sandbox_editor_choices,
)
from desire_platform.internal_pilot.editor.asgi import EditorAsgiApplication


NOW = datetime(2026, 8, 12, 8, 0, tzinfo=timezone.utc)
RAW_HANDLE = "editor-session-handle-abcdefghijklmnopqrstuvwxyz-012345"
RAW_CSRF = "editor-csrf-token-abcdefghijklmnopqrstuvwxyz-0123456789"
CONFIGURATION = EditorConfigurationDto(
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


class FixedClock:
    def now(self):
        return NOW


class Ids:
    def __init__(self):
        self.count = 0

    def new(self, kind):
        self.count += 1
        return f"{kind}_{self.count:016d}"


class SessionSecurity:
    def __init__(self):
        self.actor = AuthenticatedHttpActor(
            actor_user_id="user_creator_internal_01",
            session_id="session_creator_internal_1",
            correlation_id="trace-editor-asgi-01",
            causation_id="trace-editor-asgi-01",
            trace_id="trace-editor-asgi-01",
            original_actor_id=None,
            auth_time=NOW,
            acr_code="urn:desire:acr:mfa",
            amr_codes=("pwd", "otp"),
        )
        self.auth_calls = []
        self.csrf_calls = []

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
    def __init__(self):
        self.calls = []
        self.list_calls = []

    def resolve(self, *, actor, requested_workspace_id):
        self.calls.append((actor, requested_workspace_id))
        return EditorPrincipal(
            user_id=actor.actor_user_id,
            session_id=actor.session_id,
            organization_id="organization_internal_01",
            role_codes=("CREATOR",),
        )

    def list_workspaces(self, *, actor):
        self.list_calls.append(actor)
        return (
            EditorWorkspaceSummary(
                workspace_id="personal:10000000-0000-4000-8000-000000000001",
                workspace_kind="PERSONAL",
                role_codes=("CREATOR",),
            ),
            EditorWorkspaceSummary(
                workspace_id="platform:10000000-0000-4000-8000-000000000001",
                workspace_kind="PLATFORM",
                role_codes=("OPERATIONS_REVIEWER",),
            ),
        )


def application():
    security = SessionSecurity()
    resolver = PrincipalResolver()
    service = EditorService(
        repository=MemoryEditorRepository(),
        clock=FixedClock(),
        id_source=Ids(),
        client_reference_key=b"test-only-client-reference-key-32b",
        configuration=CONFIGURATION,
    )
    app = EditorAsgiApplication(
        api=EditorHttpApi(service=service),
        session_security=security,
        principal_resolver=resolver,
        allowed_origins=("https://pilot.example.test",),
        trace_id_source=lambda: "trace-editor-asgi-01",
    )
    return app, security, resolver


async def invoke(app, *, method="GET", path="/v1/app/profiles", headers=(), body=b""):
    messages = [
        {"type": "http.request", "body": body, "more_body": False},
    ]
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
            "query_string": b"",
            "headers": list(headers),
        },
        receive,
        send,
    )
    status = sent[0]["status"]
    response_headers = dict(sent[0]["headers"])
    payload = json.loads(sent[1]["body"] or b"{}")
    return status, response_headers, payload


class EditorAsgiRedTest(unittest.IsolatedAsyncioTestCase):
    def test_internal_bff_origin_requires_exact_internal_sandbox_profile(self):
        service = EditorService(
            repository=MemoryEditorRepository(),
            clock=FixedClock(),
            id_source=Ids(),
            client_reference_key=b"test-only-client-reference-key-32b",
        )
        common = {
            "api": EditorHttpApi(service=service),
            "session_security": SessionSecurity(),
            "principal_resolver": PrincipalResolver(),
            "trace_id_source": lambda: "trace-editor-asgi-01",
        }
        with self.assertRaises(TypeError):
            EditorAsgiApplication(
                **common,
                allowed_origins=("http://api:8000",),
            )
        EditorAsgiApplication(
            **common,
            allowed_origins=("http://api:8000",),
            allow_internal_bff_http=True,
            deployment_mode="INTERNAL_SANDBOX",
        )
        with self.assertRaises(TypeError):
            EditorAsgiApplication(
                **common,
                allowed_origins=("http://api:8000",),
                allow_internal_bff_http=True,
                deployment_mode="CONTROLLED_PILOT",
            )

    async def test_get_requires_authoritative_cookie_and_injects_principal(self):
        app, security, resolver = application()
        status, headers, body = await invoke(
            app,
            headers=((b"cookie", ("__Host-ds_session=" + RAW_HANDLE).encode()),),
        )
        self.assertEqual((status, body), (200, {"data": []}))
        self.assertEqual(headers[b"cache-control"], b"no-store")
        self.assertEqual(security.auth_calls[0][0], RAW_HANDLE)
        self.assertIsNone(resolver.calls[0][1])

        denied, _, denied_body = await invoke(app)
        self.assertEqual((denied, denied_body["error"]["code"]), (401, "AUTHENTICATION_REQUIRED"))

    async def test_configuration_requires_session_and_selected_workspace(self):
        app, security, resolver = application()
        workspace_id = "personal:10000000-0000-4000-8000-000000000001"
        cookie = ("__Host-ds_session=" + RAW_HANDLE).encode()

        status, headers, body = await invoke(
            app,
            path="/v1/app/configuration",
            headers=(
                (b"cookie", cookie),
                (b"x-workspace-id", workspace_id.encode("ascii")),
            ),
        )

        self.assertEqual(status, 200)
        self.assertEqual(headers[b"cache-control"], b"no-store")
        self.assertEqual(
            body["data"]["taxonomy_bundle"]["bundle_id"],
            "50000000-0000-4000-8000-000000000001",
        )
        self.assertEqual(security.auth_calls[0][0], RAW_HANDLE)
        self.assertEqual(resolver.calls[0][1], workspace_id)

        denied, _, denied_body = await invoke(
            app,
            path="/v1/app/configuration",
            headers=((b"x-workspace-id", workspace_id.encode("ascii")),),
        )
        self.assertEqual(
            (denied, denied_body["error"]["code"]),
            (401, "AUTHENTICATION_REQUIRED"),
        )

    async def test_write_requires_exact_origin_csrf_json_and_no_actor_override(self):
        app, security, _ = application()
        common = (
            (b"cookie", ("__Host-ds_session=" + RAW_HANDLE).encode()),
            (b"origin", b"https://pilot.example.test"),
            (b"x-csrf-token", RAW_CSRF.encode()),
            (b"idempotency-key", b"profile-asgi-idempotency-001"),
            (b"content-type", b"application/json"),
        )
        status, headers, body = await invoke(
            app,
            method="POST",
            headers=common,
            body=b"{}",
        )
        self.assertEqual(status, 201)
        self.assertEqual(body["data"]["resource_type"], "CREATOR_PROFILE")
        self.assertEqual(len(security.csrf_calls), 1)
        self.assertIn(b"etag", headers)

        for changed in (
            tuple(item for item in common if item[0] != b"origin"),
            tuple(
                (name, b"https://evil.example.test") if name == b"origin" else (name, value)
                for name, value in common
            ),
            tuple(item for item in common if item[0] != b"x-csrf-token"),
        ):
            with self.subTest(changed=changed):
                denied, _, payload = await invoke(
                    app,
                    method="POST",
                    headers=changed,
                    body=b"{}",
                )
                self.assertIn(denied, (400, 403))
                self.assertNotEqual(payload.get("data", {}).get("status"), "ACTIVE")

    async def test_malformed_oversize_duplicate_cookie_and_unknown_path_fail_closed(self):
        app, _, _ = application()
        cookie = ("__Host-ds_session=" + RAW_HANDLE).encode()
        cases = (
            ("duplicate-cookie", dict(headers=((b"cookie", cookie), (b"cookie", cookie)))),
            ("path-alias", dict(headers=((b"cookie", cookie),), path="/v1/app/../profiles")),
            (
                "oversize",
            dict(
                method="POST",
                headers=(
                    (b"cookie", cookie),
                    (b"origin", b"https://pilot.example.test"),
                    (b"x-csrf-token", RAW_CSRF.encode()),
                    (b"content-type", b"application/json"),
                ),
                body=b"x" * 1_048_577,
            ),
            ),
        )
        for label, candidate in cases:
            with self.subTest(label=label):
                status, _, payload = await invoke(app, **candidate)
                self.assertIn(status, (400, 404, 413))
                self.assertIn("error", payload)

    async def test_workspace_header_is_only_forwarded_as_an_opaque_locator(self):
        app, _, resolver = application()
        cookie = ("__Host-ds_session=" + RAW_HANDLE).encode()
        workspace_id = "org:01234567-89ab-4def-8abc-0123456789ab"

        status, _, _ = await invoke(
            app,
            headers=(
                (b"cookie", cookie),
                (b"x-workspace-id", workspace_id.encode("ascii")),
            ),
        )

        self.assertEqual(status, 200)
        self.assertEqual(resolver.calls[-1][1], workspace_id)
        duplicate, _, payload = await invoke(
            app,
            headers=(
                (b"cookie", cookie),
                (b"x-workspace-id", workspace_id.encode("ascii")),
                (b"x-workspace-id", workspace_id.encode("ascii")),
            ),
        )
        self.assertEqual((duplicate, payload["error"]["code"]), (400, "INVALID_REQUEST"))

    async def test_workspace_discovery_is_authenticated_closed_and_marker_free(self):
        app, _, resolver = application()
        cookie = ("__Host-ds_session=" + RAW_HANDLE).encode()

        status, headers, payload = await invoke(
            app,
            path="/v1/app/workspaces",
            headers=((b"cookie", cookie),),
        )

        self.assertEqual(status, 200)
        self.assertEqual(headers[b"cache-control"], b"no-store")
        self.assertEqual(
            payload,
            {
                "data": {
                    "workspaces": [
                        {
                            "workspace_id": "personal:10000000-0000-4000-8000-000000000001",
                            "workspace_kind": "PERSONAL",
                            "role_codes": ["CREATOR"],
                        },
                        {
                            "workspace_id": "platform:10000000-0000-4000-8000-000000000001",
                            "workspace_kind": "PLATFORM",
                            "role_codes": ["OPERATIONS_REVIEWER"],
                        },
                    ],
                    "selection_required": True,
                }
            },
        )
        self.assertEqual(len(resolver.list_calls), 1)
        self.assertEqual(resolver.calls, [])
        self.assertNotIn("marker", json.dumps(payload))
        self.assertNotIn("membership", json.dumps(payload))

        rejected, _, body = await invoke(
            app,
            path="/v1/app/workspaces",
            headers=(
                (b"cookie", cookie),
                (b"x-workspace-id", b"personal:10000000-0000-4000-8000-000000000001"),
            ),
        )
        self.assertEqual((rejected, body["error"]["code"]), (400, "INVALID_REQUEST"))


if __name__ == "__main__":
    unittest.main()
