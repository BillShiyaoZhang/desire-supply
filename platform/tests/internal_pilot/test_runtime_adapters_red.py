from __future__ import annotations

import ast
import inspect
import io
import json
import textwrap
import unittest
from datetime import datetime, timezone

from desire_platform.http import iam_security
from desire_platform.http.contracts import (
    AuthenticatedHttpActor,
    HttpTelemetryEvent,
    RateLimitExceeded,
)
from desire_platform.identity_access.adapters.postgres import (
    oidc_bundle,
    organization_admin_accept,
    organization_admin_handlers,
    organization_public_name,
)
from desire_platform.internal_pilot import (
    account_admin,
    current_session_logout,
    matching_postgres,
    policy_acceptance,
    production_plan,
    runtime_adapters,
)
from desire_platform.trust_safety.adapters.postgres import (
    appeal_production,
    outcome_evidence as trust_outcome_evidence,
    production as trust_production,
)
from desire_platform.internal_pilot.runtime_adapters import (
    InternalSandboxRateLimitSettings,
    InternalSandboxRateLimiter,
    JsonLineHttpTelemetry,
    SecureRuntimeSources,
)


class Monotonic:
    def __init__(self) -> None:
        self.value = 100.0

    def monotonic(self) -> float:
        return self.value


class RuntimeAdapterTests(unittest.TestCase):
    def test_secure_source_purposes_cover_exact_production_id_injections(self) -> None:
        injected_targets = _production_id_source_targets()
        self.assertEqual(
            injected_targets,
            {
                "PostgresAcceptCurrentPoliciesHandler",
                "PostgresAcceptOrganizationAccessInvitationHandler",
                "PostgresInternalSandboxAccountAdminService",
                "PostgresIssueOrganizationAccessInvitationHandler",
                "PostgresUpdateOrganizationPublicNameHandler",
                "PostgresResumeMembershipHandler",
                "PostgresRevokeAccessInvitationHandler",
                "PostgresRevokeOwnedSessionHandler",
                "PostgresRevokeMembershipHandler",
                "PostgresSuspendMembershipHandler",
                "PsycopgTrustOutcomeEvidenceProvider",
                "PsycopgIamSessionSecurity",
                "MatchingPostgresOperationalHttpService",
                "build_appeal_postgres_command_handlers",
                "build_matching_postgres_http_bindings",
                "build_postgres_iam_authentication_bundle",
                "build_trust_postgres_command_handlers",
            },
        )
        required = _literal_id_purposes(
            iam_security.PsycopgIamSessionSecurity,
            oidc_bundle.PostgresBeginOidcAuthorizationHandler,
            oidc_bundle.PostgresCompleteOidcAuthenticationHandler,
            organization_admin_accept.PostgresAcceptOrganizationAccessInvitationHandler,
            organization_admin_handlers.PostgresIssueOrganizationAccessInvitationHandler,
            organization_admin_handlers._PostgresOrganizationLifecycleHandler,
            organization_admin_handlers.PostgresResumeMembershipHandler,
            organization_public_name.PostgresUpdateOrganizationPublicNameHandler,
            organization_admin_handlers._request,
            account_admin.PostgresInternalSandboxAccountAdminService,
            policy_acceptance.PostgresAcceptCurrentPoliciesHandler,
            current_session_logout.PostgresRevokeCurrentSessionHandler,
            matching_postgres._PostgresMatchingCommandHandler,
            matching_postgres._PostgresMatchingReviewCommandHandler,
            matching_postgres.PostgresCreateMatchingInvitationHandler,
            matching_postgres.MatchingPostgresOperationalHttpService,
            matching_postgres._operational_material,
            appeal_production._PostgresAppealCommandHandler,
            trust_production._PostgresTrustCommandHandler,
            trust_outcome_evidence.PsycopgTrustOutcomeEvidenceProvider,
        ) | frozenset(
            f"matching_operational_outbox_event_{ordinal}" for ordinal in range(102)
        )

        self.assertEqual(runtime_adapters._ID_PURPOSES, required)
        sources = SecureRuntimeSources()
        for purpose in sorted(required):
            self.assertNotEqual(sources.new_id(purpose).int, 0)

    def test_secure_sources_reject_non_injected_or_deterministic_ids(self) -> None:
        sources = SecureRuntimeSources()

        # These names belong to memory-only domain handlers, application handlers
        # not wired by production_plan, or the Postgres editor's keyed-ID scheme.
        for purpose in (
            "creator_profile",
            "demand",
            "demand_review",
            "demand_submission",
            "demand_version",
            "funding_marker",
            "matching_request",
            "profile",
            "profile_version",
            "review",
            "submission",
            "user_role_grant",
            "consent_withdrawal",
            "matching_unknown",
            "matching_operational_outbox_event_-1",
            "matching_operational_outbox_event_102",
        ):
            with self.subTest(purpose=purpose), self.assertRaises(ValueError):
                sources.new_id(purpose)

    def test_rate_limiter_is_bounded_per_actor_operation_and_recovers_by_window(self) -> None:
        clock = Monotonic()
        limiter = InternalSandboxRateLimiter(
            settings=InternalSandboxRateLimitSettings(
                window_seconds=60,
                authenticated_limit=2,
                anonymous_limit=1,
                maximum_buckets=8,
            ),
            clock=clock,
        )
        actor = AuthenticatedHttpActor(
            actor_user_id="10000000-0000-4000-8000-000000000001",
            session_id="20000000-0000-4000-8000-000000000002",
            correlation_id="30000000-0000-4000-8000-000000000003",
            causation_id="30000000-0000-4000-8000-000000000003",
            trace_id="30000000-0000-4000-8000-000000000003",
            original_actor_id=None,
            auth_time=datetime.now(timezone.utc),
            acr_code="urn:desire:acr:mfa",
            amr_codes=("otp",),
        )

        limiter.require_allowed(operation_id="getMe", actor=actor)
        limiter.require_allowed(operation_id="getMe", actor=actor)
        with self.assertRaises(RateLimitExceeded) as raised:
            limiter.require_allowed(operation_id="getMe", actor=actor)
        self.assertEqual(raised.exception.retry_after_seconds, 60)

        limiter.require_allowed(operation_id="getSessionBootstrap", actor=actor)
        limiter.require_allowed(operation_id="beginOidcAuthorization", actor=None)
        with self.assertRaises(RateLimitExceeded):
            limiter.require_allowed(operation_id="beginOidcAuthorization", actor=None)

        clock.value += 61
        limiter.require_allowed(operation_id="getMe", actor=actor)
        self.assertIsNone(limiter.check_readiness(timeout_ms=50))
        limiter.close()
        with self.assertRaises(RuntimeError):
            limiter.check_readiness(timeout_ms=50)

    def test_rate_limiter_rejects_unknown_operation_and_bucket_exhaustion(self) -> None:
        clock = Monotonic()
        limiter = InternalSandboxRateLimiter(
            settings=InternalSandboxRateLimitSettings(
                window_seconds=60,
                authenticated_limit=2,
                anonymous_limit=1,
                maximum_buckets=1,
            ),
            clock=clock,
        )
        limiter.require_allowed(operation_id="beginOidcAuthorization", actor=None)
        with self.assertRaises(RateLimitExceeded):
            limiter.require_allowed(operation_id="getPolicyBundle", actor=None)
        with self.assertRaises(RuntimeError):
            limiter.require_allowed(operation_id="unknown", actor=None)

    def test_telemetry_emits_only_closed_first_party_observation(self) -> None:
        stream = io.StringIO()
        telemetry = JsonLineHttpTelemetry(stream=stream)
        event = HttpTelemetryEvent(
            trace_id="30000000-0000-4000-8000-000000000003",
            operation_id="getMe",
            method="GET",
            route_template="/v1/me",
            status_code=200,
            error_code=None,
            request_size_bucket="0",
            duration_bucket="not_measured",
            authenticated=True,
            replayed=False,
        )
        telemetry.record(event)

        payload = json.loads(stream.getvalue())
        self.assertEqual(payload["event_type"], "IAM_HTTP_OBSERVATION_V1")
        self.assertEqual(payload["operation_id"], "getMe")
        self.assertNotIn("cookie", payload)
        self.assertIsNone(telemetry.check_readiness(timeout_ms=50))
        telemetry.close()
        with self.assertRaises(RuntimeError):
            telemetry.record(event)

    def test_secure_sources_return_utc_uuid_and_exact_random_bytes(self) -> None:
        sources = SecureRuntimeSources()
        self.assertEqual(sources.now().utcoffset().total_seconds(), 0)
        self.assertGreaterEqual(sources.monotonic(), 0)
        self.assertEqual(str(__import__("uuid").UUID(sources.new_trace_id())), sources.new_trace_id.__self__.last_trace_id)
        generated = sources.new_id("auth_transaction")
        self.assertEqual(str(__import__("uuid").UUID(str(generated))), str(generated))
        for purpose in (
            "session-replay-security-event",
            "session-replay-audit-event",
            "session-replay-outbox-event",
        ):
            replay_id = sources.new_id(purpose)
            self.assertIsInstance(replay_id, __import__("uuid").UUID)
            self.assertNotEqual(replay_id.int, 0)
        self.assertEqual(len(sources.token_bytes("oidc-state", 32)), 32)
        with self.assertRaises(ValueError):
            sources.new_id("unknown-purpose")
        with self.assertRaises(ValueError):
            sources.token_bytes("unknown-purpose", 32)

    def test_secure_sources_allow_successor_session_for_step_up_callbacks(self) -> None:
        sources = SecureRuntimeSources()

        successor_session_id = sources.new_id("successor_session")

        self.assertIsInstance(successor_session_id, __import__("uuid").UUID)
        self.assertNotEqual(successor_session_id.int, 0)


def _production_id_source_targets() -> set[str]:
    tree = ast.parse(
        textwrap.dedent(
            inspect.getsource(production_plan.build_internal_sandbox_server_plan)
        )
    )
    targets: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if not any(
            keyword.arg == "id_source"
            and isinstance(keyword.value, ast.Name)
            and keyword.value.id == "sources"
            for keyword in node.keywords
        ):
            continue
        if isinstance(node.func, ast.Name):
            targets.add(node.func.id)
        elif isinstance(node.func, ast.Attribute):
            targets.add(node.func.attr)
    return targets


def _literal_id_purposes(*owners: object) -> frozenset[str]:
    purposes: set[str] = set()
    helper_argument = {
        "_new": 1,
        "_new_id": 1,
        "_new_operational_id": 1,
        "_new_uuid": 1,
        "_required_generated_uuid": 1,
    }
    for owner in owners:
        tree = ast.parse(textwrap.dedent(inspect.getsource(owner)))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            argument_index: int | None = None
            if isinstance(node.func, ast.Attribute) and node.func.attr in {
                "new_id",
                "_new_id",
            }:
                argument_index = 0
            elif isinstance(node.func, ast.Name):
                argument_index = helper_argument.get(node.func.id)
            if argument_index is None or len(node.args) <= argument_index:
                continue
            argument = node.args[argument_index]
            if isinstance(argument, ast.Constant) and isinstance(argument.value, str):
                purposes.add(argument.value)
    return frozenset(purposes)


if __name__ == "__main__":
    unittest.main()
