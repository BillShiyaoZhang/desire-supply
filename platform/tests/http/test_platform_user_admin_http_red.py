"""TEST-HTTP-IAM-PLATFORM-ADMIN-001: closed platform user administration API."""

from __future__ import annotations

from dataclasses import fields
from pathlib import Path
import unittest

import yaml

from desire_platform.http import (
    IAM_HTTP_ROUTES,
    HttpAuthenticationMode,
    HttpCsrfMode,
    IamHttpApplicationDispatcher,
    IamHttpInvocation,
    IamHttpOperation,
    IamHttpPresenterBindings,
)
from desire_platform.identity_access.domain.authority_lifecycle import (
    LifecycleActorContext,
    ResumeUserCommand,
    RevokeAllSessionsCommand,
    SuspendUserCommand,
)
from tests.support.iam_presenter_builders import (
    ACTOR,
    IDEMPOTENCY_KEY,
    RAW_SESSION_HANDLE,
    RecordingHandler,
    freeze_json,
    result_for,
)


PLATFORM_ROOT = Path(__file__).resolve().parents[2]
OPERATIONS = {
    "suspendUser": ("/v1/platform/users/{user_id}/suspend", SuspendUserCommand),
    "resumeUser": ("/v1/platform/users/{user_id}/resume", ResumeUserCommand),
    "revokeAllUserSessions": (
        "/v1/platform/users/{user_id}/revoke-all-sessions",
        RevokeAllSessionsCommand,
    ),
}


def _invocation(operation_id: str) -> IamHttpInvocation:
    path_template = OPERATIONS[operation_id][0]
    target = "user_platform_target_012345"
    return IamHttpInvocation(
        operation_id=operation_id,
        canonical_path=path_template.replace("{user_id}", target),
        path_parameters=(("user_id", target),),
        query_parameters=(),
        json_body=freeze_json(
            {
                "reason_code": "SAFETY_REVIEW",
                "reason_note": "Closed platform-administration reason.",
            }
        ),
        actor=ACTOR,
        idempotency_key=IDEMPOTENCY_KEY,
        expected_version=7,
        trace_id=ACTOR.trace_id,
        raw_session_handle=RAW_SESSION_HANDLE,
        raw_oidc_browser_cookie=None,
    )


class PlatformUserAdminHttpRedTest(unittest.TestCase):
    def test_route_registry_is_closed_at_25_and_uses_existing_session_security(self) -> None:
        self.assertEqual(len(IAM_HTTP_ROUTES), 25)
        self.assertEqual(len(tuple(IamHttpOperation)), 25)
        by_operation = {route.operation.value: route for route in IAM_HTTP_ROUTES}
        self.assertEqual(set(OPERATIONS), set(by_operation) & set(OPERATIONS))
        for operation_id, (path, _) in OPERATIONS.items():
            with self.subTest(operation_id=operation_id):
                route = by_operation[operation_id]
                self.assertEqual(route.method, "POST")
                self.assertEqual(route.path_template, path)
                self.assertIs(route.authentication, HttpAuthenticationMode.REQUIRED_SESSION)
                self.assertIs(route.csrf, HttpCsrfMode.SESSION_REQUIRED)
                self.assertEqual(route.body_limit_bytes, 4096)

    def test_openapi_freezes_all_three_commands_and_no_password_surface(self) -> None:
        document = yaml.safe_load(
            (PLATFORM_ROOT / "contracts/api/iam-v1.openapi.yaml").read_text(encoding="utf-8")
        )
        rendered = yaml.safe_dump(document, sort_keys=True)
        self.assertNotIn("password", rendered.lower())
        for operation_id, (path, _) in OPERATIONS.items():
            with self.subTest(operation_id=operation_id):
                operation = document["paths"][path]["post"]
                self.assertEqual(operation["operationId"], operation_id)
                self.assertEqual(operation["security"], [{"cookieAuth": []}])
                parameter_names = {
                    item["$ref"].rsplit("/", 1)[-1]
                    for item in operation["parameters"]
                }
                self.assertEqual(
                    parameter_names,
                    {"UserId", "IdempotencyKey", "IfMatch", "CsrfToken"},
                )
                self.assertEqual(
                    operation["requestBody"]["$ref"],
                    "#/components/requestBodies/RequiredReason",
                )
                self.assertEqual(
                    operation["responses"]["200"]["$ref"],
                    "#/components/responses/PlatformUserUpdated",
                )

    def test_presenter_registry_is_closed_and_translates_exact_commands(self) -> None:
        handlers = {
            operation_id: RecordingHandler(result_for(operation_id))
            for operation_id in OPERATIONS
        }
        bindings = IamHttpPresenterBindings(
            suspend_user=handlers["suspendUser"],
            resume_user=handlers["resumeUser"],
            revoke_all_user_sessions=handlers["revokeAllUserSessions"],
        )
        self.assertEqual(len(fields(bindings)), 25)
        dispatcher = IamHttpApplicationDispatcher(bindings=bindings)
        for operation_id, (_, command_type) in OPERATIONS.items():
            with self.subTest(operation_id=operation_id):
                result = dispatcher.dispatch(_invocation(operation_id))
                self.assertEqual(result.status_code, 200)
                args, kwargs = handlers[operation_id].calls[0]
                self.assertEqual(args, ())
                self.assertIsInstance(kwargs["actor"], LifecycleActorContext)
                command = kwargs["command"]
                self.assertIsInstance(command, command_type)
                self.assertEqual(command.user_id, "user_platform_target_012345")
                self.assertEqual(command.expected_version, 7)
                self.assertEqual(command.idempotency_key, IDEMPOTENCY_KEY)
                self.assertEqual(command.reason.reason_code, "SAFETY_REVIEW")


if __name__ == "__main__":
    unittest.main()
