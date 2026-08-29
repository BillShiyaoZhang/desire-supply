"""Exact RED→GREEN boundary for PostgreSQL ResumeMembership SafetyHold."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import unittest
from uuid import UUID

from desire_platform.identity_access.adapters.postgres.organization_admin import (
    OrganizationAdminPostgresCommitOutcomeUnknownError,
    OrganizationAdminPostgresDatabaseResult,
    OrganizationAdminPostgresOperation,
    OrganizationAdminPostgresResumeResolution,
    OrganizationAdminPostgresSafetyDecisionStaleError,
    PsycopgOrganizationAdminUnitOfWorkFactory,
)
from desire_platform.identity_access.adapters.postgres.organization_admin_handlers import (
    OrganizationAdminKeys,
    PostgresResumeMembershipHandler,
)
from desire_platform.identity_access.domain.authority_lifecycle import (
    LifecycleActorContext,
    LifecycleReason,
    ResumeMembershipCommand,
)
from desire_platform.identity_access.domain.errors import IamError
from desire_platform.identity_access.ports.safety_hold import (
    HoldDecision,
    SafetyHoldDecisionResult,
    SafetyHoldUnavailableError,
)


NOW = datetime(2026, 8, 16, 8, 0, tzinfo=timezone.utc)
POLICY = "iam-membership-resume-hold-v1"


def _id(value: int) -> UUID:
    return UUID(int=value)


class OrganizationAdminResumeSafetyRedTest(unittest.TestCase):
    def test_receipt_miss_requires_exact_allow_and_binds_private_snapshot(self) -> None:
        fixture = _fixture()
        result = fixture.handler.handle(actor=fixture.actor, command=fixture.command)
        self.assertFalse(result.replayed)
        self.assertEqual(len(fixture.hold.calls), 1)
        self.assertEqual(len(fixture.requests), 1)
        request = fixture.requests[0]
        evidence = request.resume_hold
        self.assertEqual(evidence.target_id, _id(3))
        self.assertEqual(evidence.target_version, 2)
        self.assertEqual(evidence.organization_id, _id(4))
        self.assertEqual(evidence.snapshot_digest, b"s" * 32)
        self.assertNotIn((b"s" * 32).hex(), repr(request))
        self.assertNotIn("resume_hold", result.safe_response)
        self.assertNotIn("snapshot", result.safe_response)

    def test_exact_completed_receipt_replay_never_calls_hold(self) -> None:
        fixture = _fixture(replayed=True)
        result = fixture.handler.handle(actor=fixture.actor, command=fixture.command)
        self.assertTrue(result.replayed)
        self.assertEqual(fixture.hold.calls, [])
        self.assertEqual(len(fixture.requests), 1)
        self.assertIsNone(fixture.requests[0].resume_hold)

    def test_initial_if_match_mismatch_fails_before_hold_and_uow(self) -> None:
        fixture = _fixture(target_version=3)
        with self.assertRaises(IamError) as caught:
            fixture.handler.handle(actor=fixture.actor, command=fixture.command)
        self.assertEqual(caught.exception.code, "PRECONDITION_FAILED")
        self.assertEqual(fixture.hold.calls, [])
        self.assertEqual(fixture.requests, [])

    def test_block_unavailable_mismatch_and_deadline_are_zero_write(self) -> None:
        base = _allow()
        cases = (
            ("block", replace(base, decision=HoldDecision.BLOCK), "SAFETY_HOLD_BLOCKED"),
            ("unavailable", HoldDecision.UNAVAILABLE, "SAFETY_DECISION_UNAVAILABLE"),
            (
                "wrong-block-binding",
                replace(base, decision=HoldDecision.BLOCK, target_id=str(_id(99))),
                "SAFETY_DECISION_UNAVAILABLE",
            ),
            (
                "wrong-version",
                replace(base, target_version=3),
                "SAFETY_DECISION_UNAVAILABLE",
            ),
            (
                "expired-equal",
                replace(base, valid_until=NOW),
                "SAFETY_DECISION_UNAVAILABLE",
            ),
            (
                "future-evaluation",
                replace(base, evaluated_at=NOW + timedelta(microseconds=1)),
                "SAFETY_DECISION_UNAVAILABLE",
            ),
            ("provider-error", SafetyHoldUnavailableError("down"), "SAFETY_DECISION_UNAVAILABLE"),
        )
        for label, outcome, expected in cases:
            with self.subTest(case=label):
                fixture = _fixture(hold_outcome=outcome)
                with self.assertRaises(IamError) as caught:
                    fixture.handler.handle(actor=fixture.actor, command=fixture.command)
                self.assertEqual(caught.exception.code, expected)
                self.assertEqual(fixture.requests, [])

    def test_locked_dependency_drift_re_resolves_and_never_reuses_old_allow(self) -> None:
        first = _resolution(snapshot=b"a" * 32)
        second = _resolution(snapshot=b"b" * 32)
        fixture = _fixture(
            resolutions=(first, second),
            outcomes=(OrganizationAdminPostgresSafetyDecisionStaleError(), _result()),
        )
        result = fixture.handler.handle(actor=fixture.actor, command=fixture.command)
        self.assertFalse(result.replayed)
        self.assertEqual(len(fixture.hold.calls), 2)
        self.assertEqual(len(fixture.requests), 2)
        self.assertEqual(fixture.requests[0].resume_hold.snapshot_digest, b"a" * 32)
        self.assertEqual(fixture.requests[1].resume_hold.snapshot_digest, b"b" * 32)

    def test_target_version_drift_after_allow_rolls_back_then_returns_412(self) -> None:
        fixture = _fixture(
            resolutions=(_resolution(), _resolution(target_version=3)),
            outcomes=(OrganizationAdminPostgresSafetyDecisionStaleError(),),
        )
        with self.assertRaises(IamError) as caught:
            fixture.handler.handle(actor=fixture.actor, command=fixture.command)
        self.assertEqual(caught.exception.code, "PRECONDITION_FAILED")
        self.assertEqual(len(fixture.hold.calls), 1)
        self.assertEqual(len(fixture.requests), 1)

    def test_commit_unknown_recovers_via_replay_without_second_hold(self) -> None:
        fixture = _fixture(
            resolutions=(_resolution(), _resolution(replayed=True)),
            outcomes=(OrganizationAdminPostgresCommitOutcomeUnknownError(), _result(replayed=True)),
        )
        with self.assertRaises(IamError) as caught:
            fixture.handler.handle(actor=fixture.actor, command=fixture.command)
        self.assertEqual(caught.exception.code, "COMMAND_OUTCOME_UNKNOWN")
        replay = fixture.handler.handle(actor=fixture.actor, command=fixture.command)
        self.assertTrue(replay.replayed)
        self.assertEqual(len(fixture.hold.calls), 1)
        self.assertIsNone(fixture.requests[1].resume_hold)


class _Connections:
    def checkout(self):
        raise AssertionError("unit handler must not checkout a real connection")

    def release(self, _connection):
        raise AssertionError

    def discard(self, _connection):
        raise AssertionError


class _Validator:
    def validate(self, _value, _schema_name=None):
        return None


class _Resolver:
    def __init__(self, resolutions):
        self.resolutions = list(resolutions)
        self.calls = []

    def resolve(self, **_query):
        raise AssertionError("ResumeMembership must use the receipt-aware resolver")

    def resolve_resume(self, **query):
        self.calls.append(query)
        return self.resolutions.pop(0)


class _Hold:
    def __init__(self, outcome):
        self.outcome = outcome
        self.calls = []

    def evaluate(self, **query):
        self.calls.append(query)
        outcome = self.outcome
        if isinstance(outcome, BaseException):
            raise outcome
        if outcome is HoldDecision.UNAVAILABLE:
            return replace(_allow(), decision=HoldDecision.UNAVAILABLE)
        return outcome


class _Clock:
    def now(self):
        return NOW


class _Ids:
    def __init__(self):
        self.value = 100

    def new_id(self, _purpose):
        self.value += 1
        return _id(self.value)


class _Fixture:
    pass


def _resolution(
    *, target_version=2, snapshot=b"s" * 32, replayed=False
) -> OrganizationAdminPostgresResumeResolution:
    return OrganizationAdminPostgresResumeResolution(
        organization_id=_id(4),
        target_version=target_version,
        snapshot_digest=snapshot,
        replayed=replayed,
    )


def _allow() -> SafetyHoldDecisionResult:
    return SafetyHoldDecisionResult(
        decision=HoldDecision.ALLOW,
        action="ResumeMembership",
        target_type="Membership",
        target_id=str(_id(3)),
        target_version=2,
        organization_id=str(_id(4)),
        policy_version=POLICY,
        evaluated_at=NOW - timedelta(seconds=1),
        valid_until=NOW + timedelta(minutes=1),
    )


def _result(*, replayed=False) -> OrganizationAdminPostgresDatabaseResult:
    return OrganizationAdminPostgresDatabaseResult(
        operation=OrganizationAdminPostgresOperation.RESUME_MEMBERSHIP,
        replayed=replayed,
        safe_response={
            "membership_id": str(_id(3)),
            "organization_id": str(_id(4)),
            "status": "ACTIVE",
            "aggregate_version": 3,
            "entity_tag": '"v3"',
        },
        response_entity_tag='"v3"',
    )


def _fixture(
    *,
    replayed=False,
    target_version=2,
    resolutions=None,
    outcomes=None,
    hold_outcome=None,
):
    fixture = _Fixture()
    fixture.actor = LifecycleActorContext(
        actor_user_id=str(_id(1)),
        current_session_id=str(_id(2)),
        original_actor_id=None,
        correlation_id=str(_id(5)),
        causation_id=str(_id(6)),
        trace_id=str(_id(7)),
    )
    fixture.command = ResumeMembershipCommand(
        membership_id=str(_id(3)),
        expected_version=2,
        idempotency_key="resume-membership-idem-0001",
        reason=LifecycleReason(reason_code="REVIEW_CLEARED"),
    )
    fixture.resolver = _Resolver(
        resolutions
        if resolutions is not None
        else (_resolution(target_version=target_version, replayed=replayed),)
    )
    fixture.hold = _Hold(hold_outcome if hold_outcome is not None else _allow())
    fixture.requests = []
    scripted = list(outcomes if outcomes is not None else (_result(replayed=replayed),))
    uow = PsycopgOrganizationAdminUnitOfWorkFactory(
        connections=_Connections(),
        event_validator=_Validator(),
        response_validator=_Validator(),
    )

    def execute(request):
        fixture.requests.append(request)
        outcome = scripted.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    uow.execute_resume_membership = execute
    fixture.handler = PostgresResumeMembershipHandler(
        uow_factory=uow,
        target_resolver=fixture.resolver,
        safety_hold=fixture.hold,
        safety_hold_policy_version=POLICY,
        keys=OrganizationAdminKeys(
            idempotency_key=b"i" * 32,
            payload_hash_key=b"p" * 32,
            invitation_token_keys=(("invitation-token-v1", b"t" * 32),),
            active_invitation_token_key_id="invitation-token-v1",
        ),
        clock=_Clock(),
        id_source=_Ids(),
    )
    return fixture


if __name__ == "__main__":
    unittest.main()
