"""RED→GREEN contract for the fixed STEP_UP-to-Accept PostgreSQL bridge."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import fields
from datetime import datetime, timedelta, timezone
import hashlib
from types import SimpleNamespace
import unittest
from uuid import UUID

from psycopg.pq import TransactionStatus

from desire_platform.identity_access.adapters.postgres.accept_access_invitation import (
    AcceptAccessInvitationDatabaseRequest,
    AcceptAccessInvitationDatabaseResult,
    PsycopgAcceptAccessInvitationUnitOfWorkFactory,
)
from desire_platform.identity_access.adapters.postgres.organization_admin_accept import (
    InternalSandboxInvitationSafetyHold,
    OrganizationAcceptKeyring,
    OrganizationAcceptResolvedScope,
    PostgresAcceptOrganizationAccessInvitationHandler,
    PsycopgOrganizationAcceptScopeResolver,
)
from desire_platform.identity_access.adapters.postgres.organization_admin_handlers import (
    OrganizationAdminKeys,
)
from desire_platform.identity_access.application.access_invitations import (
    AcceptAccessInvitationCommand,
    ActorContext,
)
from desire_platform.identity_access.domain.policies import PolicyAcceptance
from desire_platform.identity_access.domain.errors import IamError
from desire_platform.identity_access.ports.safety_hold import (
    HoldDecision,
    SafetyHoldDecisionResult,
    SafetyHoldUnavailableError,
)


NOW = datetime(2026, 8, 16, 8, 0, tzinfo=timezone.utc)


def _id(value: int) -> UUID:
    return UUID(int=value)


class OrganizationAdminAcceptBridgeRedTest(unittest.TestCase):
    def test_accept_command_and_pg_request_never_carry_invitation_token(self) -> None:
        names = {
            item.name
            for owner in (AcceptAccessInvitationCommand, AcceptAccessInvitationDatabaseRequest)
            for item in fields(owner)
        }
        self.assertNotIn("access_invitation_token", names)
        self.assertNotIn("raw_session_handle", names)
        self.assertNotIn("csrf_token", names)
        self.assertNotIn("recipient", names)

    def test_fresh_accept_rotates_once_and_replay_returns_no_secret_rotation(self) -> None:
        scope = OrganizationAcceptResolvedScope(
            actor_user_id=_id(1),
            session_id=_id(2),
            session_family_id=_id(3),
            auth_transaction_id=_id(4),
            invitation_id=_id(5),
            organization_id=_id(6),
            policy_selector_digest=b"s" * 32,
            policy_bundle_id=_id(7),
            current_generation=2,
            user_status="ACTIVE",
            target_role="DEMAND_OWNER",
            invitation_status="ISSUED",
            missing_policy_document_ids=(_id(8),),
            missing_consent_offer_ids=(),
        )
        resolver = PsycopgOrganizationAcceptScopeResolver(connections=object())
        resolver.resolve = lambda **_query: scope
        receipt_queries = []
        replay_body = _replay_body(scope)
        receipt_outcomes = [None, replay_body]

        def resolve_receipt_replay(**query):
            receipt_queries.append(query)
            return receipt_outcomes.pop(0)

        resolver.resolve_receipt_replay = resolve_receipt_replay
        uow = PsycopgAcceptAccessInvitationUnitOfWorkFactory(
            connections=object(),
            event_validator=_Validator(),
            response_validator=_Validator(),
        )
        requests = []
        outcomes = [
            AcceptAccessInvitationDatabaseResult(
                replayed=False,
                safe_response=replay_body,
                successor_session_id=_id(100),
            ),
        ]

        def execute(request):
            requests.append(request)
            result = outcomes.pop(0)
            if not result.replayed:
                result = AcceptAccessInvitationDatabaseResult(
                    replayed=False,
                    safe_response=result.safe_response,
                    successor_session_id=request.successor.session_id,
                )
            return result

        uow.execute = execute
        sources = _Sources()
        receipt_keys = OrganizationAdminKeys(
            idempotency_key=b"i" * 32,
            payload_hash_key=b"p" * 32,
            invitation_token_keys=(("invitation-token-v1", b"t" * 32),),
            active_invitation_token_key_id="invitation-token-v1",
        )
        safety_hold = InternalSandboxInvitationSafetyHold(
            deployment_mode="INTERNAL_SANDBOX",
            clock=sources,
        )
        hold_calls = []
        evaluate_hold = safety_hold.evaluate

        def evaluate(**query):
            hold_calls.append(query)
            return evaluate_hold(**query)

        safety_hold.evaluate = evaluate
        handler = PostgresAcceptOrganizationAccessInvitationHandler(
            scope_resolver=resolver,
            uow_factory=uow,
            safety_hold=safety_hold,
            keyring=OrganizationAcceptKeyring(
                receipt_keys=receipt_keys,
                session_keyring=_SessionKeyring(),
            ),
            clock=sources,
            id_source=sources,
            secret_source=sources,
        )
        actor = ActorContext(
            actor_id=str(scope.actor_user_id),
            session_id=str(scope.session_id),
            original_actor_id=None,
            correlation_id=str(_id(20)),
            causation_id=str(_id(21)),
            trace_id=str(_id(22)),
        )
        command = AcceptAccessInvitationCommand(
            invitation_id=str(scope.invitation_id),
            expected_version=1,
            idempotency_key="accept-replay-key-0001",
            policy_bundle_id=str(scope.policy_bundle_id),
            policy_acceptances=(
                PolicyAcceptance(
                    document_id=str(_id(8)),
                    content_sha256=(b"d" * 32).hex(),
                    affirmed=True,
                ),
            ),
            consent_grants=(),
        )
        fresh = handler.handle(actor=actor, command=command)
        replay = handler.handle(actor=actor, command=command)
        self.assertFalse(fresh.replayed)
        self.assertIsNotNone(fresh.session_rotation)
        self.assertTrue(replay.replayed)
        self.assertIsNone(replay.session_rotation)
        self.assertEqual(replay.safe_response, fresh.safe_response)
        self.assertEqual(len(hold_calls), 1)
        self.assertEqual(len(requests), 1)
        self.assertEqual(
            receipt_queries[0]["idempotency_candidates"],
            receipt_queries[1]["idempotency_candidates"],
        )
        self.assertEqual(
            receipt_queries[0]["payload_hash_candidates"],
            receipt_queries[1]["payload_hash_candidates"],
        )
        self.assertEqual(len(requests[0].generated_ids.outbox_event_ids), 5)
        self.assertNotIn("accept-replay-key-0001", repr(requests[0]))
        self.assertNotIn("bff-session", repr(requests[0]))

    def test_blocked_accept_uses_the_registered_forbidden_error_and_never_writes(self) -> None:
        fixture = _bridge_fixture()
        fixture["hold"].evaluate = lambda **query: SafetyHoldDecisionResult(
            decision=HoldDecision.BLOCK,
            action=query["action"],
            target_type=query["target_type"],
            target_id=query["target_id"],
            target_version=query["target_version"],
            organization_id=query["organization_id"],
            policy_version=query["policy_version"],
            evaluated_at=NOW,
            valid_until=NOW + timedelta(minutes=1),
        )

        with self.assertRaises(IamError) as captured:
            fixture["handler"].handle(
                actor=fixture["actor"], command=fixture["command"]
            )

        self.assertEqual(captured.exception.code, "SAFETY_HOLD_BLOCKED")
        self.assertEqual(fixture["uow_calls"], [])

    def test_pending_enrollment_allocates_the_user_activation_event_id(self) -> None:
        fixture = _bridge_fixture(user_status="PENDING_ENROLLMENT")

        result = fixture["handler"].handle(
            actor=fixture["actor"], command=fixture["command"]
        )

        self.assertFalse(result.replayed)
        self.assertEqual(len(fixture["uow_calls"]), 1)
        self.assertEqual(
            len(fixture["uow_calls"][0].generated_ids.outbox_event_ids),
            5,
        )

    def test_allow_with_wrong_hold_policy_version_fails_closed_before_uow(self) -> None:
        fixture = _bridge_fixture()
        fixture["hold"].evaluate = lambda **query: SafetyHoldDecisionResult(
            decision=HoldDecision.ALLOW,
            action=query["action"],
            target_type=query["target_type"],
            target_id=query["target_id"],
            target_version=query["target_version"],
            organization_id=query["organization_id"],
            policy_version="stale-invitation-hold-policy-v0",
            evaluated_at=NOW,
            valid_until=NOW + timedelta(minutes=1),
        )

        with self.assertRaises(IamError) as captured:
            fixture["handler"].handle(
                actor=fixture["actor"], command=fixture["command"]
            )

        self.assertEqual(captured.exception.code, "SAFETY_DECISION_UNAVAILABLE")
        self.assertEqual(fixture["uow_calls"], [])

    def test_unavailable_misbound_or_invalid_time_hold_never_reaches_uow(self) -> None:
        overrides = (
            {"decision": HoldDecision.UNAVAILABLE},
            {"action": "IssueAccessInvitation"},
            {"target_type": "Organization"},
            {"target_id": str(_id(97))},
            {"target_version": 9},
            {"organization_id": str(_id(96))},
            {"evaluated_at": NOW + timedelta(seconds=1)},
            {
                "evaluated_at": NOW - timedelta(minutes=1),
                "valid_until": NOW,
            },
        )
        for override in overrides:
            with self.subTest(override=override):
                fixture = _bridge_fixture()
                facts = {
                    "decision": HoldDecision.ALLOW,
                    "action": "AcceptAccessInvitation",
                    "target_type": "AccessInvitation",
                    "target_id": str(fixture["scope"].invitation_id),
                    "target_version": fixture["command"].expected_version,
                    "organization_id": str(fixture["scope"].organization_id),
                    "policy_version": fixture["hold"].policy_version,
                    "evaluated_at": NOW,
                    "valid_until": NOW + timedelta(minutes=1),
                }
                facts.update(override)
                fixture["hold"].evaluate = (
                    lambda _facts=facts, **_query: SafetyHoldDecisionResult(**_facts)
                )

                with self.assertRaises(IamError) as captured:
                    fixture["handler"].handle(
                        actor=fixture["actor"], command=fixture["command"]
                    )

                self.assertEqual(
                    captured.exception.code, "SAFETY_DECISION_UNAVAILABLE"
                )
                self.assertEqual(fixture["uow_calls"], [])

    def test_defined_hold_provider_unavailable_is_mapped_and_zero_write(self) -> None:
        fixture = _bridge_fixture()
        fixture["hold"].evaluate = lambda **_query: (_ for _ in ()).throw(
            SafetyHoldUnavailableError("provider unavailable")
        )

        with self.assertRaises(IamError) as captured:
            fixture["handler"].handle(
                actor=fixture["actor"], command=fixture["command"]
            )

        self.assertEqual(captured.exception.code, "SAFETY_DECISION_UNAVAILABLE")
        self.assertEqual(fixture["uow_calls"], [])

    def test_completed_receipt_replays_for_an_ordinary_current_login_session(self) -> None:
        invitation_id = _id(5)
        actor_user_id = _id(1)
        payload_digest = b"p" * 32
        replay_body = {"invitation": {"invitation_id": str(invitation_id)}}
        receipt_row = (
            "AccessInvitation",
            invitation_id,
            "POST",
            f"/v1/access-invitations/{invitation_id}/accept",
            1,
            payload_digest,
            "payload-old",
            "restricted-canonical-json-v1",
            "COMPLETED",
            1,
            None,
            None,
            None,
            None,
            replay_body,
            None,
            NOW + timedelta(days=1),
        )
        connection = _ReceiptConnection(
            receipt_rows={"idempotency-old": [receipt_row]},
            key_policy=(
                "idempotency-active",
                "payload-active",
                "restricted-canonical-json-v1",
                ("idempotency-active", "idempotency-old"),
                ("payload-active", "payload-old"),
            ),
        )
        connections = _ReceiptConnections(connection)
        resolver = PsycopgOrganizationAcceptScopeResolver(connections=connections)

        replay = resolver.resolve_receipt_replay(
            actor_user_id=actor_user_id,
            session_id=_id(2),
            invitation_id=invitation_id,
            expected_version=1,
            idempotency_candidates=(
                ("idempotency-active", b"a" * 32),
                ("idempotency-old", b"b" * 32),
            ),
            payload_hash_candidates=(
                ("payload-active", b"q" * 32),
                ("payload-old", payload_digest),
            ),
        )

        self.assertEqual(replay, replay_body)
        self.assertEqual(connections.released, [connection])
        self.assertEqual(connections.discarded, [])
        self.assertFalse(
            any("SELECT rotation_reason" in sql for sql, _params in connection.calls)
        )

    def test_inactive_receipt_principal_is_rejected_before_receipt_lookup(self) -> None:
        connection = _ReceiptConnection(
            receipt_rows={},
            principal_result={"decision_code": "AUTHENTICATION_REQUIRED"},
            key_policy=(
                "idempotency-active",
                "payload-active",
                "restricted-canonical-json-v1",
                ("idempotency-active",),
                ("payload-active",),
            ),
        )
        resolver = PsycopgOrganizationAcceptScopeResolver(
            connections=_ReceiptConnections(connection)
        )

        with self.assertRaises(IamError) as captured:
            resolver.resolve_receipt_replay(
                actor_user_id=_id(1),
                session_id=_id(2),
                invitation_id=_id(5),
                expected_version=1,
                idempotency_candidates=(("idempotency-active", b"a" * 32),),
                payload_hash_candidates=(("payload-active", b"b" * 32),),
            )

        self.assertEqual(captured.exception.code, "AUTHENTICATION_REQUIRED")
        self.assertFalse(
            any(
                sql.startswith(
                    "SELECT target_kind,target_id,http_method,canonical_path"
                )
                for sql, _params in connection.calls
            )
        )

    def test_receipt_replay_precedes_bundle_resolution_and_safety_hold(self) -> None:
        fixture = _bridge_fixture()
        fixture["resolver"].resolve_receipt_replay = (
            lambda **_query: _replay_body(fixture["scope"])
        )
        fixture["resolver"].resolve = lambda **_query: (_ for _ in ()).throw(
            IamError("POLICY_BUNDLE_CHANGED")
        )
        fixture["hold"].evaluate = lambda **_query: (_ for _ in ()).throw(
            SafetyHoldUnavailableError("hold unavailable")
        )

        result = fixture["handler"].handle(
            actor=fixture["actor"], command=fixture["command"]
        )

        self.assertTrue(result.replayed)
        self.assertIsNone(result.session_rotation)
        self.assertEqual(fixture["uow_calls"], [])

    def test_contract_valid_receipt_is_still_bound_to_actor_bundle_and_version(self) -> None:
        mutations = (
            lambda body: body["me"].__setitem__("user_id", str(_id(99))),
            lambda body: body["invitation"].__setitem__(
                "required_policy_bundle_id", str(_id(98))
            ),
            lambda body: body["invitation"].__setitem__("aggregate_version", 7),
            lambda body: body["me"].__setitem__("policy_requirements", []),
            lambda body: body["me"]["policy_requirements"][0].__setitem__(
                "scope_id", str(_id(97))
            ),
            lambda body: body["me"]["policy_requirements"][0].__setitem__(
                "required_policy_bundle_id", str(_id(96))
            ),
            lambda body: body["me"]["policy_requirements"][0].__setitem__(
                "role", "ORG_ADMIN"
            ),
            lambda body: body["me"]["memberships"][0].__setitem__(
                "roles", ["ORG_ADMIN"]
            ),
            lambda body: body["me"]["policy_requirements"].append(
                {
                    **body["me"]["policy_requirements"][0],
                    "selector_digest": "a" * 64,
                }
            ),
        )
        for mutate in mutations:
            with self.subTest(mutation=mutate.__code__.co_firstlineno):
                fixture = _bridge_fixture()
                body = deepcopy(_replay_body(fixture["scope"]))
                mutate(body)
                fixture["uow"].response_validator = _ClosedReceiptValidator()
                fixture["resolver"].resolve_receipt_replay = lambda **_query: body

                with self.assertRaises(IamError) as captured:
                    fixture["handler"].handle(
                        actor=fixture["actor"], command=fixture["command"]
                    )

                self.assertEqual(captured.exception.code, "SERVICE_UNAVAILABLE")
                self.assertEqual(fixture["uow_calls"], [])

    def test_fresh_or_uow_race_response_without_exact_authority_fails_closed(self) -> None:
        mutations = (
            lambda body: body["me"].__setitem__("status", "PENDING_ENROLLMENT"),
            lambda body: body["me"].__setitem__("memberships", []),
            lambda body: body["me"].__setitem__("policy_requirements", []),
            lambda body: body["me"]["policy_requirements"][0].__setitem__(
                "selector_digest", "a" * 64
            ),
            lambda body: body["me"]["policy_requirements"][0].__setitem__(
                "scope_id", str(_id(95))
            ),
        )
        for replayed in (False, True):
            for mutate in mutations:
                with self.subTest(
                    replayed=replayed,
                    mutation=mutate.__code__.co_firstlineno,
                ):
                    fixture = _bridge_fixture()
                    body = deepcopy(_replay_body(fixture["scope"]))
                    mutate(body)
                    fixture["uow"].response_validator = _ClosedReceiptValidator()

                    def execute(request, *, _body=body, _replayed=replayed):
                        fixture["uow_calls"].append(request)
                        return AcceptAccessInvitationDatabaseResult(
                            replayed=_replayed,
                            safe_response=_body,
                            successor_session_id=(
                                None if _replayed else request.successor.session_id
                            ),
                        )

                    fixture["uow"].execute = execute
                    with self.assertRaises(IamError) as captured:
                        fixture["handler"].handle(
                            actor=fixture["actor"], command=fixture["command"]
                        )

                    self.assertEqual(captured.exception.code, "SERVICE_UNAVAILABLE")
                    self.assertEqual(len(fixture["uow_calls"]), 1)

    def test_receipt_with_unknown_secret_field_is_never_reflected(self) -> None:
        fixture = _bridge_fixture()
        body = _replay_body(fixture["scope"])
        body["secret_sentinel"] = "raw-session-secret-never-reflect"
        fixture["uow"].response_validator = _ClosedReceiptValidator()
        fixture["resolver"].resolve_receipt_replay = lambda **_query: body

        with self.assertRaises(IamError) as captured:
            fixture["handler"].handle(
                actor=fixture["actor"], command=fixture["command"]
            )

        self.assertEqual(captured.exception.code, "SERVICE_UNAVAILABLE")
        self.assertNotIn("raw-session-secret-never-reflect", str(captured.exception))

    def test_retained_receipt_candidates_keep_active_first_for_both_domains(self) -> None:
        fixture = _bridge_fixture()
        receipt_keys = OrganizationAdminKeys(
            idempotency_key=b"a" * 32,
            payload_hash_key=b"b" * 32,
            invitation_token_keys=(("invitation-active", b"c" * 32),),
            active_invitation_token_key_id="invitation-active",
            idempotency_key_id="idempotency-active",
            payload_hash_key_id="payload-active",
            idempotency_keyring=(
                ("idempotency-active", b"a" * 32),
                ("idempotency-retained", b"d" * 32),
            ),
            payload_hash_keyring=(
                ("payload-active", b"b" * 32),
                ("payload-retained", b"e" * 32),
            ),
        )
        keyring = OrganizationAcceptKeyring(
            receipt_keys=receipt_keys,
            session_keyring=_SessionKeyring(),
        )

        identities, payloads = keyring.receipt_candidates(
            raw_idempotency_key=fixture["command"].idempotency_key,
            command=fixture["command"],
        )

        self.assertEqual(
            tuple(key_id for key_id, _digest in identities),
            ("idempotency-active", "idempotency-retained"),
        )
        self.assertEqual(
            tuple(key_id for key_id, _digest in payloads),
            ("payload-active", "payload-retained"),
        )
        self.assertTrue(all(len(digest) == 32 for _key_id, digest in identities + payloads))

    def test_receipts_under_two_retained_identity_keys_are_ambiguous(self) -> None:
        invitation_id = _id(5)
        payload_digest = b"p" * 32
        replay_body = {"invitation": {"invitation_id": str(invitation_id)}}

        def row(payload_key_id):
            return (
                "AccessInvitation",
                invitation_id,
                "POST",
                f"/v1/access-invitations/{invitation_id}/accept",
                1,
                payload_digest,
                payload_key_id,
                "restricted-canonical-json-v1",
                "COMPLETED",
                1,
                None,
                None,
                None,
                None,
                replay_body,
                None,
                NOW + timedelta(days=1),
            )

        connection = _ReceiptConnection(
            receipt_rows={
                "idempotency-active": [row("payload-active")],
                "idempotency-retained": [row("payload-retained")],
            },
            key_policy=(
                "idempotency-active",
                "payload-active",
                "restricted-canonical-json-v1",
                ("idempotency-active", "idempotency-retained"),
                ("payload-active", "payload-retained"),
            ),
        )
        resolver = PsycopgOrganizationAcceptScopeResolver(
            connections=_ReceiptConnections(connection)
        )

        with self.assertRaises(IamError) as captured:
            resolver.resolve_receipt_replay(
                actor_user_id=_id(1),
                session_id=_id(2),
                invitation_id=invitation_id,
                expected_version=1,
                idempotency_candidates=(
                    ("idempotency-active", b"a" * 32),
                    ("idempotency-retained", b"b" * 32),
                ),
                payload_hash_candidates=(
                    ("payload-active", payload_digest),
                    ("payload-retained", payload_digest),
                ),
            )

        self.assertEqual(captured.exception.code, "SERVICE_UNAVAILABLE")

    def test_receipt_miss_requires_exact_retained_set_and_database_active_keys(
        self,
    ) -> None:
        cases = (
            (
                (
                    "idempotency-db-active",
                    "payload-db-active",
                    "restricted-canonical-json-v1",
                    ("idempotency-db-active",),
                    ("payload-db-active",),
                ),
                (("idempotency-runtime-only", b"a" * 32),),
                (("payload-runtime-only", b"b" * 32),),
            ),
            (
                (
                    "idempotency-retained",
                    "payload-retained",
                    "restricted-canonical-json-v1",
                    ("idempotency-active", "idempotency-retained"),
                    ("payload-active", "payload-retained"),
                ),
                (
                    ("idempotency-active", b"a" * 32),
                    ("idempotency-retained", b"b" * 32),
                ),
                (
                    ("payload-active", b"c" * 32),
                    ("payload-retained", b"d" * 32),
                ),
            ),
        )
        for key_policy, identities, payloads in cases:
            with self.subTest(active_idempotency=key_policy[0]):
                resolver = PsycopgOrganizationAcceptScopeResolver(
                    connections=_ReceiptConnections(
                        _ReceiptConnection(
                            receipt_rows={}, key_policy=key_policy
                        )
                    )
                )
                with self.assertRaises(IamError) as captured:
                    resolver.resolve_receipt_replay(
                        actor_user_id=_id(1),
                        session_id=_id(2),
                        invitation_id=_id(5),
                        expected_version=1,
                        idempotency_candidates=identities,
                        payload_hash_candidates=payloads,
                    )
                self.assertEqual(
                    captured.exception.code, "SERVICE_UNAVAILABLE"
                )


def _bridge_fixture(*, user_status="ACTIVE"):
    scope = OrganizationAcceptResolvedScope(
        actor_user_id=_id(1),
        session_id=_id(2),
        session_family_id=_id(3),
        auth_transaction_id=_id(4),
        invitation_id=_id(5),
        organization_id=_id(6),
        policy_selector_digest=b"s" * 32,
        policy_bundle_id=_id(7),
        current_generation=2,
        user_status=user_status,
        target_role="DEMAND_OWNER",
        invitation_status="ISSUED",
        missing_policy_document_ids=(_id(8),),
        missing_consent_offer_ids=(),
    )
    resolver = PsycopgOrganizationAcceptScopeResolver(connections=object())
    resolver.resolve_receipt_replay = lambda **_query: None
    resolver.resolve = lambda **_query: scope
    uow = PsycopgAcceptAccessInvitationUnitOfWorkFactory(
        connections=object(),
        event_validator=_Validator(),
        response_validator=_Validator(),
    )
    uow_calls = []

    def execute(request):
        uow_calls.append(request)
        return AcceptAccessInvitationDatabaseResult(
            replayed=False,
            safe_response=_replay_body(scope),
            successor_session_id=request.successor.session_id,
        )

    uow.execute = execute
    sources = _Sources()
    receipt_keys = OrganizationAdminKeys(
        idempotency_key=b"i" * 32,
        payload_hash_key=b"p" * 32,
        invitation_token_keys=(("invitation-token-v1", b"t" * 32),),
        active_invitation_token_key_id="invitation-token-v1",
    )
    hold = InternalSandboxInvitationSafetyHold(
        deployment_mode="INTERNAL_SANDBOX",
        clock=sources,
    )
    handler = PostgresAcceptOrganizationAccessInvitationHandler(
        scope_resolver=resolver,
        uow_factory=uow,
        safety_hold=hold,
        keyring=OrganizationAcceptKeyring(
            receipt_keys=receipt_keys,
            session_keyring=_SessionKeyring(),
        ),
        clock=sources,
        id_source=sources,
        secret_source=sources,
    )
    actor = ActorContext(
        actor_id=str(scope.actor_user_id),
        session_id=str(scope.session_id),
        original_actor_id=None,
        correlation_id=str(_id(20)),
        causation_id=str(_id(21)),
        trace_id=str(_id(22)),
    )
    command = AcceptAccessInvitationCommand(
        invitation_id=str(scope.invitation_id),
        expected_version=1,
        idempotency_key="accept-replay-key-0001",
        policy_bundle_id=str(scope.policy_bundle_id),
        policy_acceptances=(
            PolicyAcceptance(
                document_id=str(_id(8)),
                content_sha256=(b"d" * 32).hex(),
                affirmed=True,
            ),
        ),
        consent_grants=(),
    )
    return {
        "actor": actor,
        "command": command,
        "handler": handler,
        "hold": hold,
        "resolver": resolver,
        "scope": scope,
        "uow": uow,
        "uow_calls": uow_calls,
    }


def _replay_body(scope):
    invitation_version = 2
    user_version = 3
    return {
        "invitation": {
            "invitation_id": str(scope.invitation_id),
            "purpose": "ORGANIZATION_MEMBERSHIP",
            "organization_id": str(scope.organization_id),
            "target_role": scope.target_role,
            "masked_recipient_label": "a***@example.test",
            "is_initial_admin": False,
            "status": "ACCEPTED",
            "expires_at": "2026-08-17T08:00:00Z",
            "created_at": "2026-08-16T07:00:00Z",
            "required_policy_bundle_id": str(scope.policy_bundle_id),
            "aggregate_version": invitation_version,
            "entity_tag": f'"v{invitation_version}"',
        },
        "me": {
            "user_id": str(scope.actor_user_id),
            "status": "ACTIVE",
            "display_handle": "sandbox_user",
            "user_roles": [],
            "memberships": [
                {
                    "membership_id": str(_id(9)),
                    "organization": {
                        "organization_id": str(scope.organization_id),
                        "public_name": "Synthetic Organization",
                        "type": "BUSINESS",
                        "status": "ACTIVE",
                        "aggregate_version": 1,
                        "entity_tag": '"v1"',
                    },
                    "status": "ACTIVE",
                    "roles": [scope.target_role],
                    "aggregate_version": 1,
                    "entity_tag": '"v1"',
                }
            ],
            "policy_requirements": [
                {
                    "selector_digest": scope.policy_selector_digest.hex(),
                    "purpose": "ORGANIZATION_MEMBERSHIP",
                    "role": scope.target_role,
                    "scope_type": "ORGANIZATION_ROLE",
                    "scope_id": str(scope.organization_id),
                    "satisfied": True,
                    "required_policy_bundle_id": str(scope.policy_bundle_id),
                    "missing_document_ids": [],
                }
            ],
            "aggregate_version": user_version,
            "entity_tag": f'"v{user_version}"',
        },
        "activated_scope": "ORGANIZATION_MEMBERSHIP",
    }


class _ReceiptCursor:
    def __init__(self, *, one=None, rows=()):
        self._one = one
        self._rows = list(rows)

    def fetchone(self):
        return self._one

    def fetchall(self):
        return list(self._rows)


class _ReceiptConnection:
    autocommit = True

    def __init__(self, *, receipt_rows, key_policy, principal_result=None):
        self.info = SimpleNamespace(transaction_status=TransactionStatus.IDLE)
        self.receipt_rows = receipt_rows
        self.key_policy = key_policy
        self.principal_result = principal_result or {
            "decision_code": "AUTHORIZED",
            "actor_user_id": str(_id(1)),
            "session_id": str(_id(2)),
            "session_family_id": str(_id(3)),
        }
        self.settings = {}
        self.calls = []

    def execute(self, sql, params=None):
        self.calls.append((sql, params))
        if sql.startswith(
            "SELECT current_user,session_user,current_setting('server_version_num')"
        ):
            return _ReceiptCursor(one=("iam_onboarding", "iam_onboarding", 180000))
        if sql.startswith("BEGIN"):
            self.info.transaction_status = TransactionStatus.INTRANS
            return _ReceiptCursor()
        if sql in {"COMMIT", "ROLLBACK"}:
            self.info.transaction_status = TransactionStatus.IDLE
            return _ReceiptCursor()
        if sql.startswith("SET LOCAL") or sql == "DISCARD TEMP":
            return _ReceiptCursor()
        if sql == "RESET ALL":
            self.settings.clear()
            return _ReceiptCursor()
        if sql.startswith("SELECT pg_catalog.set_config"):
            name, value = params
            self.settings[name] = value
            return _ReceiptCursor(one=(value,))
        if sql.startswith("SELECT iam_api.resolve_accept_receipt_principal_v1"):
            return _ReceiptCursor(rows=[(self.principal_result,)])
        if sql.startswith("SELECT active_idempotency_key_id"):
            return _ReceiptCursor(one=self.key_policy)
        if sql == "SELECT transaction_timestamp()":
            return _ReceiptCursor(one=(NOW,))
        if sql.startswith("SELECT rotation_reason,verified_for_invitation_id"):
            return _ReceiptCursor(one=None)
        if sql.startswith("SELECT target_kind,target_id,http_method,canonical_path"):
            key_id = self.settings["app.idempotency_key_digest_key_id"]
            return _ReceiptCursor(rows=self.receipt_rows.get(key_id, ()))
        if sql.startswith(
            "SELECT current_user,session_user,current_setting('app.scope_kind'"
        ):
            return _ReceiptCursor(one=("iam_onboarding", "iam_onboarding", None))
        raise AssertionError(f"unexpected Accept receipt SQL: {sql}")


class _ReceiptConnections:
    def __init__(self, connection):
        self.connection = connection
        self.released = []
        self.discarded = []

    def checkout(self):
        return self.connection

    def release(self, connection):
        self.released.append(connection)

    def discard(self, connection):
        self.discarded.append(connection)


class _Validator:
    def validate(self, _value, _schema_name=None):
        return None


class _ClosedReceiptValidator:
    def validate(self, value, schema_name=None):
        if schema_name != "AccessInvitationAcceptanceDto":
            raise ValueError("unexpected response schema")
        if set(value) != {"invitation", "me", "activated_scope"}:
            raise ValueError("receipt response is not closed")


class _SessionKeyring:
    session_handle_digest_key_id = "session-handle-v1"
    csrf_key_id = "csrf-v1"

    def keyed_digest_hex(self, *, key_id, canonical_bytes):
        if key_id not in {self.session_handle_digest_key_id, self.csrf_key_id}:
            raise LookupError(key_id)
        return hashlib.sha256(key_id.encode("ascii") + canonical_bytes).hexdigest()


class _Sources:
    def __init__(self):
        self._next = 99
        self._secret = 0

    def now(self):
        return NOW

    def new_id(self, _purpose):
        self._next += 1
        return _id(self._next)

    def token_bytes(self, _purpose, length):
        self._secret += 1
        return bytes((self._secret,)) * length


if __name__ == "__main__":
    unittest.main()
