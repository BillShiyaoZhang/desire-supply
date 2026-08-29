from __future__ import annotations

import asyncio
import json
import unittest
from dataclasses import dataclass
from typing import Any
from uuid import UUID

from desire_platform.http.contracts import AuthenticatedHttpActor
from desire_platform.identity_access.adapters.postgres.editor_principal import (
    ResolvedEditorWorkspace,
    WorkspaceKind,
)
from desire_platform.internal_pilot.editor.contracts import EditorPrincipal
from desire_platform.internal_pilot.editor.contracts import EditorWorkspaceSummary
from desire_platform.internal_pilot.runtime import (
    EditorPrincipalBridge,
    InternalSandboxApiApplication,
    InternalSandboxApiMux,
    InternalBffTransportApplication,
    InternalSandboxRuntime,
)


USER_ID = UUID("10000000-0000-4000-8000-000000000001")
SESSION_ID = UUID("20000000-0000-4000-8000-000000000002")
ORG_ID = UUID("30000000-0000-4000-8000-000000000003")
MEMBERSHIP_ID = UUID("40000000-0000-4000-8000-000000000004")


class RecordingApplication:
    def __init__(self, label: str) -> None:
        self.label = label
        self.paths: list[str] = []

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        self.paths.append(scope.get("path", ""))
        body = self.label.encode("ascii")
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"content-length", str(len(body)).encode("ascii"))],
            }
        )
        await send({"type": "http.response.body", "body": body})


async def request(application: Any, path: str) -> tuple[int, dict[bytes, bytes], bytes]:
    sent: list[dict[str, Any]] = []

    async def receive() -> dict[str, Any]:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: dict[str, Any]) -> None:
        sent.append(message)

    await application(
        {
            "type": "http",
            "method": "GET",
            "scheme": "https",
            "path": path,
            "raw_path": path.encode("ascii"),
            "query_string": b"",
            "headers": [],
        },
        receive,
        send,
    )
    start = next(item for item in sent if item["type"] == "http.response.start")
    body = b"".join(
        item.get("body", b"")
        for item in sent
        if item["type"] == "http.response.body"
    )
    return start["status"], dict(start["headers"]), body


class InternalSandboxApiMuxTests(unittest.IsolatedAsyncioTestCase):
    async def test_routes_only_exact_product_and_iam_namespaces(self) -> None:
        iam = RecordingApplication("iam")
        editor = RecordingApplication("editor")
        mux = InternalSandboxApiMux(iam_application=iam, editor_application=editor)

        self.assertEqual((await request(mux, "/v1/app/profiles"))[2], b"editor")
        self.assertEqual((await request(mux, "/v1/auth/session"))[2], b"iam")
        self.assertEqual((await request(mux, "/v1/me"))[2], b"iam")
        status, headers, body = await request(mux, "/v1/local/personas")

        self.assertEqual(status, 404)
        self.assertEqual(json.loads(body), {"error": {"code": "RESOURCE_NOT_FOUND"}})
        self.assertEqual(headers[b"cache-control"], b"no-store")
        self.assertEqual(iam.paths, ["/v1/auth/session", "/v1/me"])
        self.assertEqual(editor.paths, ["/v1/app/profiles"])

    async def test_internal_bff_transport_is_an_exact_envelope_not_general_http(self) -> None:
        delegate = RecordingApplication("accepted")
        application = InternalBffTransportApplication(
            application=delegate,
            deployment_mode="INTERNAL_SANDBOX",
            enabled=True,
        )

        async def invoke(*, scheme="http", headers=()):
            sent = []

            async def receive():
                return {"type": "http.request", "body": b"", "more_body": False}

            async def send(message):
                sent.append(message)

            await application(
                {
                    "type": "http",
                    "method": "GET",
                    "scheme": scheme,
                    "path": "/v1/me",
                    "raw_path": b"/v1/me",
                    "query_string": b"",
                    "headers": list(headers),
                },
                receive,
                send,
            )
            return sent

        exact = await invoke(
            headers=(
                (b"host", b"api:8000"),
                (b"origin", b"http://api:8000"),
            )
        )
        self.assertEqual(exact[0]["status"], 200)
        self.assertEqual(delegate.paths, ["/v1/me"])

        invalid = (
            ((b"host", b"api:8000"),),
            (
                (b"host", b"api:8000"),
                (b"origin", b"http://api:8000"),
                (b"forwarded", b"proto=https"),
            ),
            (
                (b"host", b"api:8000"),
                (b"origin", b"http://api:8000"),
                (b"x-forwarded-proto", b"https"),
            ),
            (
                (b"host", b"127.0.0.1:8000"),
                (b"origin", b"http://api:8000"),
            ),
        )
        for headers in invalid:
            with self.subTest(headers=headers):
                messages = await invoke(headers=headers)
                self.assertEqual(messages[0]["status"], 400)
        https = await invoke(
            scheme="https",
            headers=(
                (b"host", b"api:8000"),
                (b"origin", b"http://api:8000"),
            ),
        )
        self.assertEqual(https[0]["status"], 400)

        with self.assertRaises(ValueError):
            InternalBffTransportApplication(
                application=delegate,
                deployment_mode="CONTROLLED_PILOT",
                enabled=True,
            )
        with self.assertRaises(ValueError):
            InternalBffTransportApplication(
                application=delegate,
                deployment_mode="INTERNAL_SANDBOX",
                enabled=False,
            )


class Resolver:
    def __init__(self, resolved: ResolvedEditorWorkspace) -> None:
        self.resolved = resolved
        self.requests: list[Any] = []

    def resolve(self, request: Any) -> ResolvedEditorWorkspace:
        self.requests.append(request)
        return self.resolved

    def list_workspaces(self, request: Any) -> tuple[ResolvedEditorWorkspace, ...]:
        self.requests.append(request)
        return (self.resolved,)


class EditorPrincipalWorkspaceActivationTests(unittest.TestCase):
    def test_retains_layered_graph_but_activates_only_selected_workspace_layer(self) -> None:
        layered = {
            "organization_role_codes": ("DEMAND_OWNER",),
            "user_role_codes": ("CREATOR",),
            "platform_duty_codes": ("OPERATIONS_REVIEWER",),
            "principal_marker_sha256": b"m" * 32,
        }
        organization = EditorPrincipal(
            user_id=str(USER_ID),
            session_id=str(SESSION_ID),
            organization_id=str(ORG_ID),
            membership_id=str(MEMBERSHIP_ID),
            workspace_id=f"org:{ORG_ID}",
            workspace_kind="ORGANIZATION",
            role_codes=("DEMAND_OWNER",),
            **layered,
        )
        personal = EditorPrincipal(
            user_id=str(USER_ID),
            session_id=str(SESSION_ID),
            organization_id=None,
            membership_id=None,
            workspace_id=f"personal:{USER_ID}",
            workspace_kind="PERSONAL",
            role_codes=("CREATOR",),
            **layered,
        )
        platform = EditorPrincipal(
            user_id=str(USER_ID),
            session_id=str(SESSION_ID),
            organization_id=None,
            membership_id=None,
            workspace_id=f"platform:{USER_ID}",
            workspace_kind="PLATFORM",
            role_codes=("OPERATIONS_REVIEWER",),
            **layered,
        )

        self.assertEqual(organization.role_codes, ("DEMAND_OWNER",))
        self.assertEqual(personal.role_codes, ("CREATOR",))
        self.assertEqual(platform.role_codes, ("OPERATIONS_REVIEWER",))
        self.assertEqual(platform.organization_role_codes, ("DEMAND_OWNER",))

        with self.assertRaises(ValueError):
            EditorPrincipal(
                user_id=str(USER_ID),
                session_id=str(SESSION_ID),
                organization_id=str(ORG_ID),
                membership_id=str(MEMBERSHIP_ID),
                workspace_id=f"org:{ORG_ID}",
                workspace_kind="ORGANIZATION",
                role_codes=("CREATOR", "DEMAND_OWNER", "OPERATIONS_REVIEWER"),
                **layered,
            )


class EditorPrincipalBridgeTests(unittest.TestCase):
    def test_maps_only_database_resolved_authority_and_preserves_workspace_request(self) -> None:
        resolved = ResolvedEditorWorkspace(
            workspace_id=f"org:{ORG_ID}",
            workspace_kind=WorkspaceKind.ORGANIZATION,
            user_id=USER_ID,
            session_id=SESSION_ID,
            organization_id=ORG_ID,
            membership_id=MEMBERSHIP_ID,
            organization_role_codes=("DEMAND_OWNER",),
            user_role_codes=("CREATOR",),
            platform_duty_codes=("OPERATIONS_REVIEWER",),
            principal_marker=b"p" * 32,
        )
        resolver = Resolver(resolved)
        bridge = EditorPrincipalBridge(resolver=resolver)
        actor = AuthenticatedHttpActor(
            actor_user_id=str(USER_ID),
            session_id=str(SESSION_ID),
            correlation_id=str(UUID("50000000-0000-4000-8000-000000000005")),
            causation_id=str(UUID("50000000-0000-4000-8000-000000000005")),
            trace_id=str(UUID("50000000-0000-4000-8000-000000000005")),
            original_actor_id=None,
            auth_time=__import__("datetime").datetime.now(__import__("datetime").timezone.utc),
            acr_code="urn:desire:acr:mfa",
            amr_codes=("pwd", "otp"),
        )

        principal = bridge.resolve(
            actor=actor,
            requested_workspace_id=f"org:{ORG_ID}",
        )

        self.assertEqual(resolver.requests[0].actor_user_id, USER_ID)
        self.assertEqual(resolver.requests[0].session_id, SESSION_ID)
        self.assertEqual(
            resolver.requests[0].requested_workspace_id,
            f"org:{ORG_ID}",
        )
        self.assertEqual(principal.organization_id, str(ORG_ID))
        self.assertEqual(principal.role_codes, ("DEMAND_OWNER",))
        self.assertEqual(principal.user_role_codes, ("CREATOR",))
        self.assertEqual(
            principal.platform_duty_codes,
            ("OPERATIONS_REVIEWER",),
        )
        self.assertNotIn((b"p" * 32).hex(), repr(principal))

    def test_lists_only_safe_selected_layer_workspace_summaries(self) -> None:
        resolved = ResolvedEditorWorkspace(
            workspace_id=f"platform:{USER_ID}",
            workspace_kind=WorkspaceKind.PLATFORM,
            user_id=USER_ID,
            session_id=SESSION_ID,
            organization_id=None,
            membership_id=None,
            organization_role_codes=(),
            user_role_codes=("CREATOR",),
            platform_duty_codes=("OPERATIONS_REVIEWER",),
            principal_marker=b"s" * 32,
        )
        resolver = Resolver(resolved)
        bridge = EditorPrincipalBridge(resolver=resolver)
        actor = AuthenticatedHttpActor(
            actor_user_id=str(USER_ID),
            session_id=str(SESSION_ID),
            correlation_id=str(UUID("50000000-0000-4000-8000-000000000005")),
            causation_id=str(UUID("50000000-0000-4000-8000-000000000005")),
            trace_id=str(UUID("50000000-0000-4000-8000-000000000005")),
            original_actor_id=None,
            auth_time=__import__("datetime").datetime.now(__import__("datetime").timezone.utc),
            acr_code="urn:desire:acr:mfa",
            amr_codes=("pwd", "otp"),
        )

        summaries = bridge.list_workspaces(actor=actor)

        self.assertEqual(
            summaries,
            (
                EditorWorkspaceSummary(
                    workspace_id=f"platform:{USER_ID}",
                    workspace_kind="PLATFORM",
                    role_codes=("OPERATIONS_REVIEWER",),
                ),
            ),
        )
        self.assertEqual(resolver.requests[0].actor_user_id, USER_ID)
        self.assertEqual(resolver.requests[0].session_id, SESSION_ID)
        self.assertNotIn((b"s" * 32).hex(), repr(summaries))


class ManagedResource:
    def __init__(self, label: str, events: list[str], *, fail_ready: bool = False) -> None:
        self.label = label
        self.events = events
        self.fail_ready = fail_ready

    def check_readiness(self, timeout_ms: int) -> None:
        self.events.append(f"ready:{self.label}:{timeout_ms}")
        if self.fail_ready:
            raise RuntimeError("secret readiness detail")

    def close(self) -> None:
        self.events.append(f"close:{self.label}")


class InternalSandboxRuntimeTests(unittest.IsolatedAsyncioTestCase):
    async def test_health_is_bounded_fail_closed_and_displays_gate_boundary(self) -> None:
        events: list[str] = []
        mux = InternalSandboxApiMux(
            iam_application=RecordingApplication("iam"),
            editor_application=RecordingApplication("editor"),
        )
        dependency = ManagedResource("database", events)
        runtime = InternalSandboxRuntime(
            application=mux,
            managed_resources=(dependency,),
            readiness_timeout_ms=125,
        )

        status, headers, body = await request(runtime.application, "/health/live")
        self.assertEqual(status, 200)
        self.assertEqual(
            json.loads(body),
            {
                "deployment_mode": "INTERNAL_SANDBOX",
                "external_participants": "DISABLED",
                "g1": "NO-GO",
                "g2": "NO-GO",
                "status": "LIVE",
            },
        )
        self.assertEqual(headers[b"cache-control"], b"no-store")

        status, _, body = await request(runtime.application, "/health/ready")
        self.assertEqual((status, json.loads(body)["status"]), (200, "READY"))
        dependency.fail_ready = True
        status, _, body = await request(runtime.application, "/health/ready")
        self.assertEqual((status, json.loads(body)["status"]), (503, "NOT_READY"))
        self.assertNotIn(b"secret readiness detail", body)

        runtime.close()
        self.assertEqual(events[-1], "close:database")
        self.assertEqual((await request(runtime.application, "/health/live"))[0], 503)

    async def test_lifespan_builds_once_and_closes_once(self) -> None:
        events: list[str] = []

        def build() -> InternalSandboxRuntime:
            events.append("build")
            return InternalSandboxRuntime(
                application=InternalSandboxApiMux(
                    iam_application=RecordingApplication("iam"),
                    editor_application=RecordingApplication("editor"),
                ),
                managed_resources=(ManagedResource("db", events),),
                readiness_timeout_ms=100,
            )

        application = InternalSandboxApiApplication(builder=build)
        incoming = asyncio.Queue()
        sent: list[dict[str, Any]] = []
        await incoming.put({"type": "lifespan.startup"})
        await incoming.put({"type": "lifespan.shutdown"})

        async def receive() -> dict[str, Any]:
            return await incoming.get()

        async def send(message: dict[str, Any]) -> None:
            sent.append(message)

        await application({"type": "lifespan"}, receive, send)

        self.assertEqual(
            [item["type"] for item in sent],
            ["lifespan.startup.complete", "lifespan.shutdown.complete"],
        )
        self.assertEqual(events, ["build", "ready:db:100", "close:db"])

    async def test_lifespan_failure_is_stable_and_cleans_partial_runtime(self) -> None:
        events: list[str] = []

        def build() -> InternalSandboxRuntime:
            return InternalSandboxRuntime(
                application=InternalSandboxApiMux(
                    iam_application=RecordingApplication("iam"),
                    editor_application=RecordingApplication("editor"),
                ),
                managed_resources=(
                    ManagedResource("database", events, fail_ready=True),
                ),
                readiness_timeout_ms=100,
            )

        application = InternalSandboxApiApplication(builder=build)
        incoming = asyncio.Queue()
        sent: list[dict[str, Any]] = []
        await incoming.put({"type": "lifespan.startup"})

        async def receive() -> dict[str, Any]:
            return await incoming.get()

        async def send(message: dict[str, Any]) -> None:
            sent.append(message)

        await application({"type": "lifespan"}, receive, send)

        self.assertEqual(
            sent,
            [
                {
                    "type": "lifespan.startup.failed",
                    "message": "INTERNAL_SANDBOX_STARTUP_FAILED",
                }
            ],
        )
        self.assertEqual(
            events,
            ["ready:database:100", "close:database"],
        )


if __name__ == "__main__":
    unittest.main()
