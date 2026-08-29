"""Closed ASGI composition boundary for the INTERNAL_SANDBOX pilot.

This module deliberately contains no ambient configuration reads, global
connection pools, Memory fallbacks, or allow-all providers.  A deployment
composition supplies both authenticated applications and every managed
dependency explicitly, then exposes this boundary through an ASGI server.
"""

from __future__ import annotations

import asyncio
import json
import threading
from enum import Enum
from typing import Any, Callable, Mapping, Optional, Sequence, Tuple
from uuid import UUID

from desire_platform.http.contracts import AuthenticatedHttpActor
from desire_platform.identity_access.adapters.postgres.editor_principal import (
    EditorPrincipalResolutionRequest,
    EditorWorkspaceListRequest,
    ResolvedEditorWorkspace,
)
from desire_platform.identity_access.domain.errors import IamError
from desire_platform.matching.http import is_matching_public_path

from .editor.contracts import EditorPrincipal, EditorWorkspaceSummary
from .matching_http import is_matching_operational_path


_IAM_PATH_PREFIXES = (
    "/v1/auth/",
    "/v1/access-invitations/",
    "/v1/policy-bundles/",
    "/v1/me/",
    "/v1/organizations/",
    "/v1/memberships/",
    "/v1/platform/users/",
)
_IAM_EXACT_PATHS = frozenset(("/v1/me",))
_HEALTH_PATHS = frozenset(("/health/live", "/health/ready"))
_HEALTH_METHODS = frozenset(("GET", "HEAD"))
_FORWARDED_HEADERS = frozenset(
    (
        b"forwarded",
        b"x-forwarded-for",
        b"x-forwarded-host",
        b"x-forwarded-port",
        b"x-forwarded-proto",
    )
)
_INTERNAL_BFF_HOST = b"api:8000"
_INTERNAL_BFF_ORIGIN = b"http://api:8000"


class InternalSandboxRuntimeState(str, Enum):
    READY = "READY"
    FAILED = "FAILED"
    CLOSED = "CLOSED"


def _callable(value: Any) -> bool:
    return callable(value)


def _managed(value: Any) -> bool:
    return callable(getattr(value, "check_readiness", None)) and callable(
        getattr(value, "close", None)
    )


def _json_response(
    *,
    status_code: int,
    body: Mapping[str, Any],
    method: str = "GET",
    extra_headers: Tuple[Tuple[bytes, bytes], ...] = (),
) -> Tuple[int, Tuple[Tuple[bytes, bytes], ...], bytes]:
    encoded = json.dumps(
        body,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    headers = (
        (b"content-type", b"application/json"),
        (b"cache-control", b"no-store"),
        (b"content-length", str(len(encoded)).encode("ascii")),
    ) + extra_headers
    return status_code, headers, b"" if method == "HEAD" else encoded


async def _send_response(
    send: Any,
    response: Tuple[int, Tuple[Tuple[bytes, bytes], ...], bytes],
) -> None:
    status, headers, body = response
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": list(headers),
        }
    )
    await send(
        {
            "type": "http.response.body",
            "body": body,
            "more_body": False,
        }
    )


class InternalSandboxApiMux:
    """Dispatch only the reviewed IAM, editor, Trust, Appeal, and Matching namespaces."""

    def __init__(
        self,
        *,
        iam_application: Any,
        editor_application: Any,
        trust_application: Any = None,
        appeal_application: Any = None,
        matching_application: Any = None,
    ) -> None:
        if not _callable(iam_application) or not _callable(editor_application):
            raise TypeError("internal sandbox applications are unavailable")
        if trust_application is not None and not _callable(trust_application):
            raise TypeError("internal sandbox Trust application is unavailable")
        if appeal_application is not None and not _callable(appeal_application):
            raise TypeError("internal sandbox Appeal application is unavailable")
        if matching_application is not None and not _callable(matching_application):
            raise TypeError("internal sandbox Matching application is unavailable")
        self._iam_application = iam_application
        self._editor_application = editor_application
        self._trust_application = trust_application
        self._appeal_application = appeal_application
        self._matching_application = matching_application

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope.get("type") != "http":
            if scope.get("type") == "websocket":
                await send({"type": "websocket.close", "code": 1008})
                return
            raise RuntimeError("internal sandbox mux accepts only HTTP scopes")
        path = scope.get("path")
        if is_matching_public_path(path) or is_matching_operational_path(path):
            if self._matching_application is not None:
                await self._matching_application(scope, receive, send)
                return
            method = scope.get("method")
            await _send_response(
                send,
                _json_response(
                    status_code=503,
                    body={
                        "code": "SERVICE_UNAVAILABLE",
                        "message": "Service is temporarily unavailable.",
                        "trace_id": "trace-unavailable",
                    },
                    method=method if isinstance(method, str) else "GET",
                ),
            )
            return
        if isinstance(path, str) and (
            path == "/v1/app/appeals"
            or path.startswith("/v1/app/appeals/")
            or path == "/v1/app/appeal-review"
            or path.startswith("/v1/app/appeal-review/")
        ):
            if self._appeal_application is not None:
                await self._appeal_application(scope, receive, send)
                return
            method = scope.get("method")
            await _send_response(
                send,
                _json_response(
                    status_code=503,
                    body={"error": {"code": "SERVICE_UNAVAILABLE"}},
                    method=method if isinstance(method, str) else "GET",
                ),
            )
            return
        if isinstance(path, str) and (
            path == "/v1/app/trust" or path.startswith("/v1/app/trust/")
        ):
            if self._trust_application is not None:
                await self._trust_application(scope, receive, send)
                return
            method = scope.get("method")
            await _send_response(
                send,
                _json_response(
                    status_code=503,
                    body={"error": {"code": "SERVICE_UNAVAILABLE"}},
                    method=method if isinstance(method, str) else "GET",
                ),
            )
            return
        if isinstance(path, str) and (
            path == "/v1/app" or path.startswith("/v1/app/")
        ):
            await self._editor_application(scope, receive, send)
            return
        if isinstance(path, str) and (
            path in _IAM_EXACT_PATHS
            or any(path.startswith(prefix) for prefix in _IAM_PATH_PREFIXES)
        ):
            await self._iam_application(scope, receive, send)
            return
        method = scope.get("method")
        await _send_response(
            send,
            _json_response(
                status_code=404,
                body={"error": {"code": "RESOURCE_NOT_FOUND"}},
                method=method if isinstance(method, str) else "GET",
            ),
        )


class InternalBffTransportApplication:
    """Verify the one Docker BFF hop before asserting a secure app scope.

    This is not a general ``allow HTTP`` switch.  It is available only in the
    INTERNAL_SANDBOX deployment and accepts the immutable Compose service
    authority.  The API service must remain un-published on an internal
    network; the deployment verifier owns that independent invariant.
    """

    def __init__(
        self,
        *,
        application: Any,
        deployment_mode: str,
        enabled: bool = False,
    ) -> None:
        if not _callable(application):
            raise TypeError("internal BFF delegate is unavailable")
        if enabled is not True or deployment_mode != "INTERNAL_SANDBOX":
            raise ValueError("internal BFF transport is not enabled for this deployment")
        self._application = application

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope.get("type") != "http" or scope.get("scheme") != "http":
            await _send_response(
                send,
                _json_response(
                    status_code=400,
                    body={"error": {"code": "INVALID_INTERNAL_BFF_TRANSPORT"}},
                    method=scope.get("method", "GET"),
                ),
            )
            return
        raw_headers = scope.get("headers")
        if not isinstance(raw_headers, (tuple, list)) or len(raw_headers) > 100:
            await self._reject(scope, send)
            return
        host_values: list[bytes] = []
        origin_values: list[bytes] = []
        for item in raw_headers:
            if (
                not isinstance(item, (tuple, list))
                or len(item) != 2
                or not isinstance(item[0], bytes)
                or not isinstance(item[1], bytes)
            ):
                await self._reject(scope, send)
                return
            name = bytes(item[0]).lower()
            value = bytes(item[1])
            if name in _FORWARDED_HEADERS or name.startswith(b"x-forwarded-"):
                await self._reject(scope, send)
                return
            if name == b"host":
                host_values.append(value)
            elif name == b"origin":
                origin_values.append(value)
        if host_values != [_INTERNAL_BFF_HOST] or origin_values != [
            _INTERNAL_BFF_ORIGIN
        ]:
            await self._reject(scope, send)
            return
        verified_scope = dict(scope)
        verified_scope["scheme"] = "https"
        extensions = dict(scope.get("extensions", {}))
        extensions["desire.internal_bff_transport"] = {"version": 1}
        verified_scope["extensions"] = extensions
        await self._application(verified_scope, receive, send)

    @staticmethod
    async def _reject(scope: Mapping[str, Any], send: Any) -> None:
        await _send_response(
            send,
            _json_response(
                status_code=400,
                body={"error": {"code": "INVALID_INTERNAL_BFF_TRANSPORT"}},
                method=scope.get("method", "GET"),
            ),
        )


class EditorPrincipalBridge:
    """Map an authenticated actor through the exact PostgreSQL workspace resolver."""

    def __init__(self, *, resolver: Any) -> None:
        if not callable(getattr(resolver, "resolve", None)) or not callable(
            getattr(resolver, "list_workspaces", None)
        ):
            raise TypeError("editor principal resolver is unavailable")
        self._resolver = resolver

    def resolve(
        self,
        *,
        actor: AuthenticatedHttpActor,
        requested_workspace_id: Optional[str],
    ) -> EditorPrincipal:
        if not isinstance(actor, AuthenticatedHttpActor):
            raise IamError("SERVICE_UNAVAILABLE")
        actor_user_id = _canonical_uuid(actor.actor_user_id)
        session_id = _canonical_uuid(actor.session_id)
        try:
            resolved = self._resolver.resolve(
                EditorPrincipalResolutionRequest(
                    actor_user_id=actor_user_id,
                    session_id=session_id,
                    requested_workspace_id=requested_workspace_id,
                )
            )
        except IamError:
            raise
        except Exception:
            raise IamError("SERVICE_UNAVAILABLE") from None
        if not isinstance(resolved, ResolvedEditorWorkspace):
            raise IamError("SERVICE_UNAVAILABLE")
        if resolved.user_id != actor_user_id or resolved.session_id != session_id:
            raise IamError("SERVICE_UNAVAILABLE")
        # Activate only the selected workspace layer.  The other tuples are
        # retained for typed diagnostics/gradual service migration and remain
        # cryptographically covered by the database marker; they are never an
        # authorization union.
        effective_roles = {
            "ORGANIZATION": resolved.organization_role_codes,
            "PERSONAL": resolved.user_role_codes,
            "PLATFORM": resolved.platform_duty_codes,
        }.get(resolved.workspace_kind.value)
        if effective_roles is None:
            raise IamError("SERVICE_UNAVAILABLE")
        role_codes = tuple(sorted(set(effective_roles)))
        return EditorPrincipal(
            user_id=str(resolved.user_id),
            session_id=str(resolved.session_id),
            organization_id=(
                None
                if resolved.organization_id is None
                else str(resolved.organization_id)
            ),
            role_codes=role_codes,
            workspace_id=resolved.workspace_id,
            workspace_kind=resolved.workspace_kind.value,
            membership_id=(
                None if resolved.membership_id is None else str(resolved.membership_id)
            ),
            organization_role_codes=resolved.organization_role_codes,
            user_role_codes=resolved.user_role_codes,
            platform_duty_codes=resolved.platform_duty_codes,
            principal_marker_sha256=bytes(resolved.principal_marker),
        )

    def list_workspaces(
        self,
        *,
        actor: AuthenticatedHttpActor,
    ) -> Tuple[EditorWorkspaceSummary, ...]:
        if not isinstance(actor, AuthenticatedHttpActor):
            raise IamError("SERVICE_UNAVAILABLE")
        actor_user_id = _canonical_uuid(actor.actor_user_id)
        session_id = _canonical_uuid(actor.session_id)
        try:
            resolved = self._resolver.list_workspaces(
                EditorWorkspaceListRequest(
                    actor_user_id=actor_user_id,
                    session_id=session_id,
                )
            )
        except IamError:
            raise
        except Exception:
            raise IamError("SERVICE_UNAVAILABLE") from None
        if not isinstance(resolved, tuple):
            raise IamError("SERVICE_UNAVAILABLE")
        summaries = []
        for workspace in resolved:
            if (
                not isinstance(workspace, ResolvedEditorWorkspace)
                or workspace.user_id != actor_user_id
                or workspace.session_id != session_id
            ):
                raise IamError("SERVICE_UNAVAILABLE")
            effective_roles = {
                "ORGANIZATION": workspace.organization_role_codes,
                "PERSONAL": workspace.user_role_codes,
                "PLATFORM": workspace.platform_duty_codes,
            }.get(workspace.workspace_kind.value)
            if effective_roles is None:
                raise IamError("SERVICE_UNAVAILABLE")
            try:
                summaries.append(
                    EditorWorkspaceSummary(
                        workspace_id=workspace.workspace_id,
                        workspace_kind=workspace.workspace_kind.value,
                        role_codes=tuple(sorted(set(effective_roles))),
                    )
                )
            except ValueError:
                raise IamError("SERVICE_UNAVAILABLE") from None
        identifiers = tuple(summary.workspace_id for summary in summaries)
        if identifiers != tuple(sorted(set(identifiers))):
            raise IamError("SERVICE_UNAVAILABLE")
        return tuple(summaries)


def _canonical_uuid(value: Any) -> UUID:
    if not isinstance(value, str):
        raise IamError("SERVICE_UNAVAILABLE")
    try:
        parsed = UUID(value)
    except (ValueError, AttributeError):
        raise IamError("SERVICE_UNAVAILABLE") from None
    if str(parsed) != value or parsed.int == 0:
        raise IamError("SERVICE_UNAVAILABLE")
    return parsed


class InternalSandboxRuntime:
    """Own the composed boundary and its explicitly managed dependencies."""

    def __init__(
        self,
        *,
        application: Any,
        managed_resources: Sequence[Any],
        readiness_timeout_ms: int,
    ) -> None:
        resources = tuple(managed_resources)
        if not _callable(application):
            raise TypeError("internal sandbox application is unavailable")
        if (
            type(readiness_timeout_ms) is not int
            or not 50 <= readiness_timeout_ms <= 30_000
            or any(not _managed(resource) for resource in resources)
            or len({id(resource) for resource in resources}) != len(resources)
        ):
            raise TypeError("internal sandbox runtime contract is unavailable")
        self._delegate = application
        self._resources = resources
        self._readiness_timeout_ms = readiness_timeout_ms
        self._state = InternalSandboxRuntimeState.READY
        self._close_failures: list[str] = []
        self._lock = threading.RLock()
        self._application = _InternalSandboxHealthBoundary(self)

    @property
    def application(self) -> Any:
        return self._application

    @property
    def state(self) -> InternalSandboxRuntimeState:
        with self._lock:
            return self._state

    @property
    def close_failures(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(self._close_failures)

    def check_readiness(self, timeout_ms: Optional[int] = None) -> bool:
        budget = self._readiness_timeout_ms if timeout_ms is None else timeout_ms
        if type(budget) is not int or not 1 <= budget <= 30_000:
            raise TypeError("readiness timeout is unavailable")
        with self._lock:
            if self._state is InternalSandboxRuntimeState.CLOSED:
                return False
            try:
                for resource in self._resources:
                    result = resource.check_readiness(timeout_ms=budget)
                    if result is not None:
                        raise TypeError("readiness result is not closed")
            except BaseException:
                self._state = InternalSandboxRuntimeState.FAILED
                return False
            self._state = InternalSandboxRuntimeState.READY
            return True

    def close(self) -> None:
        with self._lock:
            if self._state is InternalSandboxRuntimeState.CLOSED:
                return
            self._state = InternalSandboxRuntimeState.CLOSED
            for index, resource in reversed(tuple(enumerate(self._resources))):
                try:
                    resource.close()
                except BaseException:
                    self._close_failures.append(f"RESOURCE_CLOSE_FAILED:{index}")

    def __repr__(self) -> str:
        return (
            "InternalSandboxRuntime("
            f"state={self.state.value!r}, resources=<redacted>)"
        )


class _InternalSandboxHealthBoundary:
    def __init__(self, runtime: InternalSandboxRuntime) -> None:
        self._runtime = runtime

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        path = scope.get("path")
        if scope.get("type") == "http" and path in _HEALTH_PATHS:
            method = scope.get("method")
            if method not in _HEALTH_METHODS:
                await _send_response(
                    send,
                    _json_response(
                        status_code=405,
                        body={"status": "METHOD_NOT_ALLOWED"},
                        extra_headers=((b"allow", b"GET, HEAD"),),
                    ),
                )
                return
            if path == "/health/live":
                live = self._runtime.state is not InternalSandboxRuntimeState.CLOSED
                status = "LIVE" if live else "NOT_LIVE"
            else:
                live = self._runtime.check_readiness()
                status = "READY" if live else "NOT_READY"
            await _send_response(
                send,
                _json_response(
                    status_code=200 if live else 503,
                    body={
                        "deployment_mode": "INTERNAL_SANDBOX",
                        "external_participants": "DISABLED",
                        "g1": "NO-GO",
                        "g2": "NO-GO",
                        "status": status,
                    },
                    method=method,
                ),
            )
            return
        if self._runtime.state is not InternalSandboxRuntimeState.READY:
            await _send_response(
                send,
                _json_response(
                    status_code=503,
                    body={"error": {"code": "SERVICE_UNAVAILABLE"}},
                    method=scope.get("method", "GET"),
                ),
            )
            return
        await self._runtime._delegate(scope, receive, send)


class InternalSandboxApiApplication:
    """ASGI lifespan owner that constructs and closes the runtime exactly once."""

    def __init__(self, *, builder: Callable[[], InternalSandboxRuntime]) -> None:
        if not callable(builder):
            raise TypeError("internal sandbox builder is unavailable")
        self._builder = builder
        self._runtime: Optional[InternalSandboxRuntime] = None
        self._starting = False

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope.get("type") == "lifespan":
            await self._lifespan(receive, send)
            return
        runtime = self._runtime
        if runtime is None:
            await _send_response(
                send,
                _json_response(
                    status_code=503,
                    body={"error": {"code": "SERVICE_UNAVAILABLE"}},
                    method=scope.get("method", "GET"),
                ),
            )
            return
        await runtime.application(scope, receive, send)

    async def _lifespan(self, receive: Any, send: Any) -> None:
        while True:
            message = await receive()
            message_type = message.get("type") if isinstance(message, dict) else None
            if message_type == "lifespan.startup":
                if self._runtime is not None or self._starting:
                    await send(
                        {
                            "type": "lifespan.startup.failed",
                            "message": "INTERNAL_SANDBOX_STARTUP_FAILED",
                        }
                    )
                    return
                self._starting = True
                candidate: Optional[InternalSandboxRuntime] = None
                try:
                    candidate = await asyncio.to_thread(self._builder)
                    if not isinstance(candidate, InternalSandboxRuntime):
                        raise TypeError("builder returned an open runtime")
                    if not await asyncio.to_thread(candidate.check_readiness):
                        raise RuntimeError("runtime is not ready")
                    self._runtime = candidate
                except BaseException:
                    if candidate is not None:
                        await asyncio.to_thread(candidate.close)
                    await send(
                        {
                            "type": "lifespan.startup.failed",
                            "message": "INTERNAL_SANDBOX_STARTUP_FAILED",
                        }
                    )
                    return
                finally:
                    self._starting = False
                await send({"type": "lifespan.startup.complete"})
                continue
            if message_type == "lifespan.shutdown":
                runtime = self._runtime
                self._runtime = None
                if runtime is not None:
                    await asyncio.to_thread(runtime.close)
                await send({"type": "lifespan.shutdown.complete"})
                return
            await send(
                {
                    "type": "lifespan.startup.failed",
                    "message": "INTERNAL_SANDBOX_LIFESPAN_INVALID",
                }
            )
            return


__all__ = [
    "EditorPrincipalBridge",
    "InternalSandboxApiApplication",
    "InternalSandboxApiMux",
    "InternalBffTransportApplication",
    "InternalSandboxRuntime",
    "InternalSandboxRuntimeState",
]
