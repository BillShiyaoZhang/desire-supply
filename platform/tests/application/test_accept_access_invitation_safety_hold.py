"""TEST-APP-HOLD-IAM-001 rich SafetyHoldDecisionResult regression tests.

The pure authorization policy already covers the three closed decision values.
These application tests specify the stronger port boundary: a decision is usable
only when every returned binding and its exclusive validity window match the
server-derived query.  Provider evaluation also stays outside the unit of work.
"""

from __future__ import annotations

from dataclasses import dataclass, fields, is_dataclass, replace
from datetime import timedelta
import unittest

from desire_platform.identity_access.adapters.memory import MemoryUnitOfWorkFactory
from desire_platform.identity_access.application.access_invitations import (
    AcceptAccessInvitationHandler,
)
from desire_platform.identity_access.domain.errors import IamError
from desire_platform.identity_access.ports import safety_hold as safety_hold_port
from desire_platform.identity_access.ports.safety_hold import HoldDecision
from tests.support.iam_application_builders import (
    HOLD_POLICY_VERSION,
    creator_acceptance_fixture,
)


@dataclass(frozen=True)
class _FallbackSafetyHoldDecisionResult:
    """Keeps failures behavioral until the production result type is introduced."""

    decision: HoldDecision
    action: str
    target_type: str
    target_id: str
    target_version: int
    organization_id: str | None
    policy_version: str
    evaluated_at: object
    valid_until: object


class _FallbackSafetyHoldUnavailableError(Exception):
    pass


SafetyHoldDecisionResult = getattr(
    safety_hold_port,
    "SafetyHoldDecisionResult",
    _FallbackSafetyHoldDecisionResult,
)
SafetyHoldUnavailableError = getattr(
    safety_hold_port,
    "SafetyHoldUnavailableError",
    _FallbackSafetyHoldUnavailableError,
)


class _ScriptedSafetyHold:
    """Test adapter returning exact results/exceptions in declared call order."""

    def __init__(self, *outcomes, transaction_is_active=None) -> None:
        self._outcomes = list(outcomes)
        self._transaction_is_active = transaction_is_active or (lambda: False)
        self.calls: list[dict] = []

    def evaluate(self, **query):
        if self._transaction_is_active():
            raise AssertionError("SafetyHold provider was called inside an active UoW")
        self.calls.append(dict(query))
        if not self._outcomes:
            raise AssertionError("unexpected SafetyHold evaluation")
        outcome = self._outcomes.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome


class _TrackingUnitOfWork:
    def __init__(self, owner, inner) -> None:
        self._owner = owner
        self._inner = inner

    @property
    def tables(self):
        return self._inner.tables

    def __enter__(self):
        if self._owner.transaction_active:
            raise AssertionError("nested IAM unit of work")
        self._owner.transaction_active = True
        self._inner.__enter__()
        return self

    def __exit__(self, exception_type, exception, traceback):
        try:
            return self._inner.__exit__(exception_type, exception, traceback)
        finally:
            self._owner.transaction_active = False

    def put(self, *args, **kwargs):
        return self._inner.put(*args, **kwargs)

    def commit(self):
        return self._inner.commit()


class _VersionDriftUnitOfWorkFactory:
    """Makes the locked transaction see v4 after the outside query saw v3."""

    def __init__(self, fixture) -> None:
        self.store = fixture.store
        self._invitation_id = fixture.ids.invitation_id
        self._inner = MemoryUnitOfWorkFactory(
            store=fixture.store,
            fault_injector=fixture.fault_injector,
        )
        self.transaction_active = False
        self._drifted = False

    def begin(self):
        if not self._drifted:
            current = self.store.snapshot()["invitations"][self._invitation_id]
            self.store.seed(
                invitations={
                    self._invitation_id: replace(
                        current,
                        aggregate_version=current.aggregate_version + 1,
                    )
                }
            )
            self._drifted = True
        return _TrackingUnitOfWork(self, self._inner.begin())


class AcceptAccessInvitationSafetyHoldTest(unittest.TestCase):
    """A rich hold result is an exact, short-lived authorization capability."""

    def assert_iam_error(self, expected_code, operation) -> None:
        with self.assertRaises(IamError) as raised:
            operation()
        self.assertEqual(raised.exception.code, expected_code)

    def test_port_exports_an_immutable_rich_result_and_narrow_unavailable_error(self):
        self.assertIsNot(
            SafetyHoldDecisionResult,
            _FallbackSafetyHoldDecisionResult,
            "safety_hold port must export SafetyHoldDecisionResult",
        )
        self.assertIsNot(
            SafetyHoldUnavailableError,
            _FallbackSafetyHoldUnavailableError,
            "safety_hold port must export SafetyHoldUnavailableError",
        )
        result = self._decision(creator_acceptance_fixture())
        self.assertTrue(is_dataclass(result))
        self.assertTrue(
            {
                "decision",
                "action",
                "target_type",
                "target_id",
                "target_version",
                "organization_id",
                "policy_version",
                "evaluated_at",
                "valid_until",
            }.issubset({field.name for field in fields(result)})
        )
        with self.assertRaises((AttributeError, TypeError)):
            result.target_version += 1

    def test_query_contains_every_exact_server_derived_binding(self):
        fixture = creator_acceptance_fixture()
        provider = _ScriptedSafetyHold(
            self._decision(fixture, decision=HoldDecision.UNAVAILABLE)
        )
        fixture.handler = self._handler(fixture, provider)

        self.assert_iam_error(
            "SAFETY_DECISION_UNAVAILABLE",
            lambda: fixture.handler.handle(actor=fixture.actor, command=fixture.command),
        )

        self.assertEqual(
            provider.calls,
            [
                {
                    "actor_id": fixture.ids.user_id,
                    "action": "AcceptAccessInvitation",
                    "target_type": "AccessInvitation",
                    "target_id": fixture.ids.invitation_id,
                    "target_version": fixture.invitation.aggregate_version,
                    "organization_id": None,
                    "policy_version": HOLD_POLICY_VERSION,
                }
            ],
        )

    def test_exact_unexpired_rich_allow_is_accepted(self):
        fixture = creator_acceptance_fixture()
        provider = _ScriptedSafetyHold(self._decision(fixture))
        fixture.handler = self._handler(fixture, provider)

        result = fixture.handler.handle(actor=fixture.actor, command=fixture.command)

        self.assertFalse(result.replayed)
        self.assertGreater(fixture.fault_injector.write_count, 0)
        self.assertEqual(len(provider.calls), 1)

    def test_every_mismatched_result_binding_fails_closed_without_a_write(self):
        changes = {
            "action": "IssueAccessInvitation",
            "target_type": "Membership",
            "target_id": "access_invitation_other_999",
            "target_version": 4,
            "organization_id": "organization_other_999",
            "policy_version": "safety-hold-stale-v0",
        }
        for field_name, wrong_value in changes.items():
            with self.subTest(field=field_name):
                fixture = creator_acceptance_fixture()
                provider = _ScriptedSafetyHold(
                    self._decision(fixture, **{field_name: wrong_value})
                )
                fixture.handler = self._handler(fixture, provider)
                before = fixture.store.snapshot()

                self.assert_iam_error(
                    "SAFETY_DECISION_UNAVAILABLE",
                    lambda: fixture.handler.handle(
                        actor=fixture.actor,
                        command=fixture.command,
                    ),
                )

                self.assertEqual(fixture.store.snapshot(), before)
                self.assertEqual(fixture.fault_injector.write_count, 0)

    def test_future_or_expired_result_fails_closed_at_exclusive_deadline(self):
        for label, time_changes in (
            (
                "future-evaluation",
                {"evaluated_at_delta": timedelta(microseconds=1)},
            ),
            (
                "deadline-equality",
                {"valid_until_delta": timedelta(0)},
            ),
            (
                "expired",
                {"valid_until_delta": -timedelta(microseconds=1)},
            ),
        ):
            with self.subTest(case=label):
                fixture = creator_acceptance_fixture()
                provider = _ScriptedSafetyHold(
                    self._decision(fixture, **time_changes)
                )
                fixture.handler = self._handler(fixture, provider)
                before = fixture.store.snapshot()

                self.assert_iam_error(
                    "SAFETY_DECISION_UNAVAILABLE",
                    lambda: fixture.handler.handle(
                        actor=fixture.actor,
                        command=fixture.command,
                    ),
                )

                self.assertEqual(fixture.store.snapshot(), before)
                self.assertEqual(fixture.fault_injector.write_count, 0)

    def test_rich_block_is_403_but_rich_unavailable_is_503_with_zero_writes(self):
        for decision, expected_code in (
            (HoldDecision.BLOCK, "SAFETY_HOLD_BLOCKED"),
            (HoldDecision.UNAVAILABLE, "SAFETY_DECISION_UNAVAILABLE"),
        ):
            with self.subTest(decision=decision):
                fixture = creator_acceptance_fixture()
                provider = _ScriptedSafetyHold(
                    self._decision(fixture, decision=decision)
                )
                fixture.handler = self._handler(fixture, provider)
                before = fixture.store.snapshot()

                self.assert_iam_error(
                    expected_code,
                    lambda: fixture.handler.handle(
                        actor=fixture.actor,
                        command=fixture.command,
                    ),
                )

                self.assertEqual(fixture.store.snapshot(), before)
                self.assertEqual(fixture.fault_injector.write_count, 0)

    def test_only_the_port_unavailable_error_is_mapped_to_503(self):
        fixture = creator_acceptance_fixture()
        provider = _ScriptedSafetyHold(
            SafetyHoldUnavailableError("synthetic provider outage")
        )
        fixture.handler = self._handler(fixture, provider)
        before = fixture.store.snapshot()

        self.assert_iam_error(
            "SAFETY_DECISION_UNAVAILABLE",
            lambda: fixture.handler.handle(actor=fixture.actor, command=fixture.command),
        )
        self.assertEqual(fixture.store.snapshot(), before)
        self.assertEqual(fixture.fault_injector.write_count, 0)

        programming_fixture = creator_acceptance_fixture()
        programming_provider = _ScriptedSafetyHold(
            RuntimeError("synthetic provider adapter bug")
        )
        programming_fixture.handler = self._handler(
            programming_fixture,
            programming_provider,
        )
        programming_before = programming_fixture.store.snapshot()
        with self.assertRaisesRegex(RuntimeError, "adapter bug"):
            programming_fixture.handler.handle(
                actor=programming_fixture.actor,
                command=programming_fixture.command,
            )
        self.assertEqual(programming_fixture.store.snapshot(), programming_before)
        self.assertEqual(programming_fixture.fault_injector.write_count, 0)

    def test_locked_version_drift_re_evaluates_outside_uow_then_returns_412(self):
        fixture = creator_acceptance_fixture()
        factory = _VersionDriftUnitOfWorkFactory(fixture)
        provider = _ScriptedSafetyHold(
            self._decision(fixture, target_version=3),
            self._decision(fixture, target_version=4),
            transaction_is_active=lambda: factory.transaction_active,
        )
        fixture.handler = self._handler(fixture, provider, uow_factory=factory)
        expected_after_drift = fixture.store.snapshot()
        expected_after_drift["invitations"][fixture.ids.invitation_id] = replace(
            fixture.invitation,
            aggregate_version=4,
        )

        self.assert_iam_error(
            "PRECONDITION_FAILED",
            lambda: fixture.handler.handle(actor=fixture.actor, command=fixture.command),
        )

        self.assertEqual(
            [call["target_version"] for call in provider.calls],
            [3, 4],
        )
        self.assertFalse(factory.transaction_active)
        self.assertEqual(fixture.store.snapshot(), expected_after_drift)
        self.assertEqual(fixture.fault_injector.write_count, 0)

    def _handler(self, fixture, provider, *, uow_factory=None):
        return AcceptAccessInvitationHandler(
            uow_factory=(
                uow_factory
                or MemoryUnitOfWorkFactory(
                    store=fixture.store,
                    fault_injector=fixture.fault_injector,
                )
            ),
            safety_hold=provider,
            safety_hold_policy_version=HOLD_POLICY_VERSION,
            clock=fixture.clock,
            id_source=fixture.id_source,
            secret_source=fixture.secret_source,
            keyring=fixture.keyring,
        )

    def _decision(
        self,
        fixture,
        *,
        decision=HoldDecision.ALLOW,
        action="AcceptAccessInvitation",
        target_type="AccessInvitation",
        target_id=None,
        target_version=None,
        organization_id=None,
        policy_version=HOLD_POLICY_VERSION,
        evaluated_at_delta=timedelta(0),
        valid_until_delta=timedelta(seconds=30),
    ):
        return SafetyHoldDecisionResult(
            decision=decision,
            action=action,
            target_type=target_type,
            target_id=target_id or fixture.ids.invitation_id,
            target_version=(
                fixture.invitation.aggregate_version
                if target_version is None
                else target_version
            ),
            organization_id=organization_id,
            policy_version=policy_version,
            evaluated_at=fixture.clock.now() + evaluated_at_delta,
            valid_until=fixture.clock.now() + valid_until_delta,
        )


if __name__ == "__main__":
    unittest.main()
