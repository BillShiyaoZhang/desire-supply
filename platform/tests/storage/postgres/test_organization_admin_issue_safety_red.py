"""Exact receipt-first SafetyHold protocol for PG organization invitations."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import unittest
from uuid import UUID

from desire_platform.identity_access.adapters.postgres.organization_admin import (
    OrganizationAdminPostgresCommitOutcomeUnknownError,
    OrganizationAdminPostgresDatabaseResult,
    OrganizationAdminPostgresIssueResolution,
    OrganizationAdminPostgresOperation,
    OrganizationAdminPostgresSafetyDecisionStaleError,
    PsycopgOrganizationAdminUnitOfWorkFactory,
)
from desire_platform.identity_access.adapters.postgres.organization_admin_handlers import (
    HmacOrganizationInvitationTokenCodec,
    OrganizationAdminKeys,
    PostgresIssueOrganizationAccessInvitationHandler,
)
from desire_platform.identity_access.application.issue_access_invitations import (
    InvitationIssuerContext,
    IssueAccessInvitationCommand,
    IssuerKind,
    RecipientContactType,
    RecipientInput,
)
from desire_platform.identity_access.domain.errors import IamError
from desire_platform.identity_access.domain.invitations import TargetRole
from desire_platform.identity_access.ports.recipient_binding import RecipientBindingTuple
from desire_platform.identity_access.ports.safety_hold import (
    HoldDecision,
    SafetyHoldDecisionResult,
    SafetyHoldUnavailableError,
)


NOW = datetime(2026, 8, 16, 8, 0, tzinfo=timezone.utc)
POLICY = "iam-organization-invitation-issue-hold-v1"


def _id(value: int) -> UUID:
    return UUID(int=value)


class OrganizationAdminIssueSafetyRedTest(unittest.TestCase):
    def test_fresh_issue_persists_exact_private_allow_evidence(self) -> None:
        fixture = _fixture()
        result = fixture.handler.handle(actor=fixture.actor, command=fixture.command)
        self.assertFalse(result.replayed)
        self.assertEqual(len(fixture.hold.calls), 1)
        evidence = fixture.requests[0].issue_hold
        self.assertEqual(evidence.snapshot_digest, b"s" * 32)
        self.assertEqual(evidence.target_type, "AccessInvitation")
        self.assertEqual(evidence.target_id, _id(101))
        self.assertEqual(evidence.target_version, 1)
        self.assertEqual(fixture.hold.calls[0]["target_id"], str(_id(101)))
        self.assertNotIn("issue_hold", result.invitation)
        self.assertNotIn((b"s" * 32).hex(), repr(fixture.requests[0]))

    def test_completed_receipt_replay_never_calls_hold(self) -> None:
        fixture = _fixture(replayed=True, outcome=_result(replayed=True))
        result = fixture.handler.handle(actor=fixture.actor, command=fixture.command)
        self.assertTrue(result.replayed)
        self.assertEqual(fixture.hold.calls, [])
        self.assertEqual(fixture.requests, [])

    def test_completed_replay_precedes_all_id_and_entropy_sources(self) -> None:
        fixture = _fixture(
            replayed=True,
            id_source=_FailIds(),
            secret_source=_FailSecrets(),
        )

        result = fixture.handler.handle(actor=fixture.actor, command=fixture.command)

        self.assertTrue(result.replayed)
        self.assertEqual(fixture.hold.calls, [])
        self.assertEqual(fixture.requests, [])

    def test_block_unavailable_wrong_binding_and_expired_are_zero_write(self) -> None:
        allow = _allow()
        cases = (
            (replace(allow, decision=HoldDecision.BLOCK), "SAFETY_HOLD_BLOCKED"),
            (replace(allow, target_id=str(_id(99))), "SAFETY_DECISION_UNAVAILABLE"),
            (replace(allow, valid_until=NOW), "SAFETY_DECISION_UNAVAILABLE"),
            (SafetyHoldUnavailableError("down"), "SAFETY_DECISION_UNAVAILABLE"),
        )
        for hold_outcome, code in cases:
            with self.subTest(code=code, outcome=type(hold_outcome).__name__):
                fixture = _fixture(hold_outcome=hold_outcome)
                with self.assertRaises(IamError) as caught:
                    fixture.handler.handle(actor=fixture.actor, command=fixture.command)
                self.assertEqual(caught.exception.code, code)
                self.assertEqual(fixture.requests, [])

    def test_if_match_mismatch_fails_before_hold_and_write(self) -> None:
        fixture = _fixture(target_version=2)
        with self.assertRaises(IamError) as caught:
            fixture.handler.handle(actor=fixture.actor, command=fixture.command)
        self.assertEqual(caught.exception.code, "PRECONDITION_FAILED")
        self.assertEqual(fixture.hold.calls, [])
        self.assertEqual(fixture.requests, [])

    def test_locked_snapshot_drift_re_resolves_and_re_evaluates(self) -> None:
        fixture = _fixture(
            resolutions=(
                _resolution(snapshot=b"a" * 32),
                _resolution(snapshot=b"b" * 32),
            ),
            outcomes=(OrganizationAdminPostgresSafetyDecisionStaleError(), _result()),
        )
        fixture.handler.handle(actor=fixture.actor, command=fixture.command)
        self.assertEqual(len(fixture.hold.calls), 2)
        self.assertEqual(fixture.requests[0].issue_hold.snapshot_digest, b"a" * 32)
        self.assertEqual(fixture.requests[1].issue_hold.snapshot_digest, b"b" * 32)

    def test_commit_unknown_then_receipt_replay_does_not_call_hold_twice(self) -> None:
        fixture = _fixture(
            resolutions=(_resolution(), _resolution(replayed=True)),
            outcomes=(
                OrganizationAdminPostgresCommitOutcomeUnknownError(),
                _result(replayed=True),
            ),
        )
        with self.assertRaises(IamError) as caught:
            fixture.handler.handle(actor=fixture.actor, command=fixture.command)
        self.assertEqual(caught.exception.code, "COMMAND_OUTCOME_UNKNOWN")
        replay = fixture.handler.handle(actor=fixture.actor, command=fixture.command)
        self.assertTrue(replay.replayed)
        self.assertEqual(len(fixture.hold.calls), 1)
        self.assertEqual(len(fixture.requests), 1)

    def test_recipient_binding_rotation_retains_old_issue_payload_candidate(self) -> None:
        old = _fixture(binding=_Binding(key_id="recipient-binding-v1", byte=b"o"))
        old.handler.handle(actor=old.actor, command=old.command)
        rotated = _fixture(
            replayed=True,
            outcome=_result(replayed=True),
            binding=_Binding(
                key_id="recipient-binding-v2",
                byte=b"n",
                retained=(("recipient-binding-v1", b"o"),),
            ),
        )

        replay = rotated.handler.handle(actor=rotated.actor, command=rotated.command)

        self.assertTrue(replay.replayed)
        self.assertEqual(rotated.hold.calls, [])
        old_payload = old.resolver.calls[0]["payload_hash_candidates"][0][1]
        self.assertIn(
            old_payload,
            tuple(
                digest
                for _key_id, digest in rotated.resolver.calls[0][
                    "payload_hash_candidates"
                ]
            ),
        )


class _Connections:
    def checkout(self):
        raise AssertionError("unit handler must not checkout PostgreSQL")

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

    def resolve_issue(self, **query):
        self.calls.append(query)
        return self.resolutions.pop(0)


class _Hold:
    def __init__(self, outcome):
        self.outcome = outcome
        self.calls = []

    def evaluate(self, **query):
        self.calls.append(query)
        if isinstance(self.outcome, BaseException):
            raise self.outcome
        return self.outcome


class _Clock:
    def now(self):
        return NOW


class _Ids:
    def __init__(self):
        self.value = 100

    def new_id(self, _purpose):
        self.value += 1
        return _id(self.value)


class _Secrets:
    def token_bytes(self, purpose, length):
        self.last = (purpose, length)
        return b"n" * length


class _FailIds:
    def new_id(self, _purpose):
        raise AssertionError("receipt replay must precede ID allocation")


class _FailSecrets:
    def token_bytes(self, _purpose, _length):
        raise AssertionError("receipt replay must precede secret generation")


class _Binding:
    def __init__(
        self,
        *,
        key_id="recipient-binding-v1",
        byte=b"r",
        retained=(),
    ):
        self.key_id = key_id
        self.byte = byte
        self.retained = retained

    def bind_verified(self, *, contact_type, verified_locator):
        return self.bind_verified_candidates(
            contact_type=contact_type, verified_locator=verified_locator
        )[0]

    def bind_verified_candidates(self, *, contact_type, verified_locator):
        self.last = (contact_type, verified_locator)
        return tuple(
            RecipientBindingTuple(
                contact_type="EMAIL",
                binding_digest=(byte * 32).hex(),
                digest_key_id=key_id,
            )
            for key_id, byte in ((self.key_id, self.byte),) + self.retained
        )


class _Fixture:
    pass


def _resolution(*, target_version=1, snapshot=b"s" * 32, replayed=False):
    replay = _result(replayed=True) if replayed else None
    return OrganizationAdminPostgresIssueResolution(
        organization_id=_id(3),
        target_version=target_version,
        snapshot_digest=snapshot,
        replayed=replayed,
        safe_response=(replay.safe_response if replay else None),
        response_entity_tag=(replay.response_entity_tag if replay else None),
        capability_reconstruction=(
            replay.capability_reconstruction if replay else None
        ),
    )


def _allow():
    return SafetyHoldDecisionResult(
        decision=HoldDecision.ALLOW,
        action="IssueAccessInvitation",
        target_type="AccessInvitation",
        target_id=str(_id(101)),
        target_version=1,
        organization_id=str(_id(3)),
        policy_version=POLICY,
        evaluated_at=NOW - timedelta(seconds=1),
        valid_until=NOW + timedelta(minutes=1),
    )


def _result(*, replayed=False):
    response = {
        "invitation_id": str(_id(101)),
        "purpose": "ORGANIZATION_MEMBERSHIP",
        "organization_id": str(_id(3)),
        "target_role": "DEMAND_OWNER",
        "masked_recipient_label": "p***@example.test",
        "is_initial_admin": False,
        "status": "ISSUED",
        "expires_at": "2026-08-23T08:00:00Z",
        "created_at": "2026-08-16T08:00:00Z",
        "required_policy_bundle_id": str(_id(90)),
        "aggregate_version": 1,
        "entity_tag": '"v1"',
    }
    return OrganizationAdminPostgresDatabaseResult(
        operation=OrganizationAdminPostgresOperation.ISSUE_ACCESS_INVITATION,
        replayed=replayed,
        safe_response=response,
        response_entity_tag='"v1"',
        capability_reconstruction={
            "nonce": (b"n" * 32).hex(),
            "token_key_id": "invitation-token-v1",
            "token_format_version": "access-invitation-token-v1",
            "expires_at": response["expires_at"],
        },
    )


def _fixture(
    *,
    replayed=False,
    target_version=1,
    resolutions=None,
    outcome=None,
    outcomes=None,
    hold_outcome=None,
    binding=None,
    id_source=None,
    secret_source=None,
):
    fixture = _Fixture()
    keys = OrganizationAdminKeys(
        idempotency_key=b"i" * 32,
        payload_hash_key=b"p" * 32,
        invitation_token_keys=(("invitation-token-v1", b"t" * 32),),
        active_invitation_token_key_id="invitation-token-v1",
    )
    resolver = _Resolver(
        resolutions
        or (_resolution(target_version=target_version, replayed=replayed),)
    )
    hold = _Hold(hold_outcome if hold_outcome is not None else _allow())
    requests = []
    pending = list(outcomes or (outcome or _result(replayed=replayed),))
    uow = PsycopgOrganizationAdminUnitOfWorkFactory(
        connections=_Connections(),
        event_validator=_Validator(),
        response_validator=_Validator(),
    )

    def execute(request):
        requests.append(request)
        result = pending.pop(0)
        if isinstance(result, BaseException):
            raise result
        return result

    uow.execute_issue_access_invitation = execute
    fixture.handler = PostgresIssueOrganizationAccessInvitationHandler(
        uow_factory=uow,
        target_resolver=resolver,
        safety_hold=hold,
        safety_hold_policy_version=POLICY,
        recipient_binding=binding or _Binding(),
        token_codec=HmacOrganizationInvitationTokenCodec(keys=keys),
        keys=keys,
        clock=_Clock(),
        id_source=id_source or _Ids(),
        secret_source=secret_source or _Secrets(),
    )
    fixture.actor = InvitationIssuerContext(
        actor_kind=IssuerKind.USER,
        actor_id=str(_id(1)),
        session_id=str(_id(2)),
        original_actor_id=None,
        correlation_id=str(_id(5)),
        causation_id=str(_id(6)),
        trace_id=str(_id(7)),
        auth_time=NOW - timedelta(minutes=1),
        acr_code="urn:desire:acr:synthetic-internal-sandbox:mfa",
        amr_codes=("mfa", "synthetic"),
    )
    fixture.command = IssueAccessInvitationCommand(
        organization_id=str(_id(3)),
        expected_organization_version=1,
        recipient=RecipientInput(
            type=RecipientContactType.EMAIL, value="person@example.test"
        ),
        target_role=TargetRole.DEMAND_OWNER,
        expires_at=NOW + timedelta(days=7),
        idempotency_key="org-admin-issue-safety-0001",
    )
    fixture.hold = hold
    fixture.resolver = resolver
    fixture.requests = requests
    return fixture


if __name__ == "__main__":
    unittest.main()
