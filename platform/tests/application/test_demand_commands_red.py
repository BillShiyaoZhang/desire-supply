"""First application semantic RED for the complete Demand command boundary."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from typing import Any, Callable, Mapping
import unittest

from desire_platform.demand.application import (
    DemandApplicationBehaviorNotAvailable,
    DemandApplicationError,
    DEMAND_APPLICATION_BEHAVIOR_NOT_AVAILABLE,
)
from desire_platform.demand.application.handlers import demand_command_payload_hash
from desire_platform.demand.domain import DemandStatus
from tests.support.demand_builders import (
    ASSIGNMENT_ID,
    DEMAND_ID,
    DEMAND_WRITE_CHECKPOINTS,
    DeterministicReceiptKeyring,
    FUNDING_EVENT_ID,
    FUNDING_ID,
    IDEMPOTENCY_KEY,
    ORGANIZATION_ID,
    OTHER_ORGANIZATION_ID,
    RAW_PRIVATE_SENTINELS,
    REVIEWER_USER_ID,
    UTC_NOW,
    VERSION_ID,
    build_harness,
    commands,
    demand,
    demand_version,
    freeze_json,
    funding_marker,
    matching_request,
    owner_actor,
    review_assignment,
    reviewer_actor,
    submission,
    system_actor,
    valid_content_mapping,
)


def _capture(call: Callable[[], Any]) -> tuple[Any, str | None]:
    try:
        return call(), None
    except DemandApplicationError as error:
        return None, error.code
    except DemandApplicationBehaviorNotAvailable as error:
        if str(error) != DEMAND_APPLICATION_BEHAVIOR_NOT_AVAILABLE:
            raise
        return None, DEMAND_APPLICATION_BEHAVIOR_NOT_AVAILABLE


def _seed_for(name: str) -> Mapping[str, Mapping[str, Any]]:
    root = demand()
    seed: dict[str, dict[str, Any]] = {
        "demands": {DEMAND_ID: root},
        "demand_versions": {VERSION_ID: demand_version()},
        "submissions": {},
        "review_assignments": {},
        "reviews": {},
        "funding_markers": {},
        "matching_requests": {},
        "receipts": {},
        "source_inbox": {},
        "audits": {},
        "outbox": {},
    }
    if name == "create":
        seed["demands"].clear()
        seed["demand_versions"].clear()
    if name in {"changes", "verify"}:
        seed["demands"][DEMAND_ID] = demand(
            status=DemandStatus.SUBMITTED, aggregate_version=2
        )
        seed["submissions"]["demand_submission_00001"] = submission()
        seed["review_assignments"][ASSIGNMENT_ID] = review_assignment()
    if name == "funding":
        seed["demands"][DEMAND_ID] = demand(
            status=DemandStatus.FUNDING_PENDING,
            aggregate_version=4,
            verified_version_id=VERSION_ID,
        )
    if name == "matching":
        seed["demands"][DEMAND_ID] = demand(
            status=DemandStatus.FUNDED,
            aggregate_version=5,
            verified_version_id=VERSION_ID,
            current_funding_id=FUNDING_ID,
        )
        seed["funding_markers"]["funding_marker_0000001"] = funding_marker()
        seed["review_assignments"][ASSIGNMENT_ID] = review_assignment()
    if name == "expire":
        seed["demands"][DEMAND_ID] = replace(root, expires_at=UTC_NOW)
    return seed


def _actor_for(name: str):
    if name in {"changes", "verify", "matching"}:
        return reviewer_actor()
    if name in {"funding", "expire"}:
        return system_actor()
    return owner_actor()


class DemandApplicationSemanticRedTest(unittest.TestCase):
    """TEST-APP-DEMAND-* first-round Memory-orchestration specification."""

    def _assert_success(
        self,
        name: str,
        *,
        expected_status: DemandStatus,
        expected_events: tuple[str, ...],
    ) -> None:
        harness = build_harness(_seed_for(name))
        result, code = _capture(
            lambda: harness.handlers[name].handle(
                actor=_actor_for(name), command=commands()[name]
            )
        )
        self.assertEqual(
            {
                "code": code,
                "status": getattr(getattr(result, "demand", None), "status", None),
                "event_types": getattr(result, "event_types", None),
                "replayed": getattr(result, "replayed", None),
            },
            {
                "code": None,
                "status": expected_status,
                "event_types": expected_events,
                "replayed": False,
            },
        )

    def test_create_writes_root_version_receipt_audit_and_two_events_atomically(self) -> None:
        self._assert_success(
            "create",
            expected_status=DemandStatus.DRAFT,
            expected_events=("DemandCreated", "DemandVersionCreated"),
        )

    def test_create_version_appends_current_version_and_invalidates_old_eligibility(self) -> None:
        self._assert_success(
            "version",
            expected_status=DemandStatus.DRAFT,
            expected_events=("DemandVersionCreated",),
        )

    def test_submit_binds_complete_content_policy_hold_and_exact_current_version(self) -> None:
        self._assert_success(
            "submit",
            expected_status=DemandStatus.SUBMITTED,
            expected_events=("DemandSubmitted",),
        )

    def test_request_changes_appends_structured_review_without_hold_gate(self) -> None:
        self._assert_success(
            "changes",
            expected_status=DemandStatus.NEEDS_CHANGES,
            expected_events=("DemandChangesRequested",),
        )

    def test_verify_appends_exact_review_and_sets_verified_version(self) -> None:
        self._assert_success(
            "verify",
            expected_status=DemandStatus.VERIFIED,
            expected_events=("DemandVerified",),
        )

    def test_funding_source_event_is_authenticated_deduplicated_and_exactly_bound(self) -> None:
        self._assert_success(
            "funding",
            expected_status=DemandStatus.FUNDED,
            expected_events=("DemandFunded",),
        )

    def test_request_matching_freezes_funding_and_composite_rule_requirement(self) -> None:
        self._assert_success(
            "matching",
            expected_status=DemandStatus.MATCHING,
            expected_events=("MatchingRequested",),
        )

    def test_system_can_request_matching_without_reusing_completed_review_assignment(self) -> None:
        harness = build_harness(_seed_for("matching"))
        command = replace(commands()["matching"], assignment_id=None)

        result, code = _capture(
            lambda: harness.handlers["matching"].handle(
                actor=system_actor(), command=command
            )
        )

        self.assertEqual(code, None)
        self.assertEqual(result.demand.status, DemandStatus.MATCHING)
        self.assertEqual(result.event_types, ("MatchingRequested",))
        self.assertEqual(len(harness.system_authority.calls), 1)
        self.assertEqual(harness.review_authority.calls, [])
        self.assertEqual(
            harness.system_authority.calls[0]["operation"],
            "REQUEST_MATCHING",
        )
        self.assertIsNone(
            harness.system_authority.calls[0]["source_event_id"]
        )

    def test_system_request_matching_rejects_a_user_review_assignment_shape(self) -> None:
        harness = build_harness(_seed_for("matching"))
        before = harness.uow_factory.store.snapshot()

        _result, code = _capture(
            lambda: harness.handlers["matching"].handle(
                actor=system_actor(), command=commands()["matching"]
            )
        )

        self.assertEqual(code, "INVALID_REQUEST")
        self.assertEqual(harness.system_authority.calls, [])
        self.assertEqual(harness.review_authority.calls, [])
        self.assertEqual(harness.uow_factory.store.snapshot(), before)

    def test_cancel_is_terminal_and_never_claims_refund_completed(self) -> None:
        self._assert_success(
            "cancel",
            expected_status=DemandStatus.CANCELLED,
            expected_events=("DemandCancelled",),
        )

    def test_expire_uses_server_deadline_scheduler_identity_and_is_terminal(self) -> None:
        self._assert_success(
            "expire",
            expected_status=DemandStatus.EXPIRED,
            expected_events=("DemandExpired",),
        )

    def test_owner_authority_is_exact_actor_session_organization_and_membership_grant(self) -> None:
        cases = []
        for mutation in (
            {"organization_id": OTHER_ORGANIZATION_ID},
            {"membership_status": "SUSPENDED"},
            {"role_code": "ORG_ADMIN"},
            {"policy_requirements_satisfied": False},
        ):
            harness = build_harness()
            harness.owner_authority.result = replace(
                harness.owner_authority.result, **mutation
            )
            before = harness.uow_factory.store.snapshot()
            _result, code = _capture(
                lambda harness=harness: harness.handlers["create"].handle(
                    actor=owner_actor(), command=commands()["create"]
                )
            )
            cases.append((code, harness.uow_factory.store.snapshot() == before))
        self.assertEqual(cases, [("RESOURCE_NOT_FOUND", True)] * 4)

    def test_review_requires_exact_assignment_platform_duty_and_separation(self) -> None:
        mutations = (
            {"assignment_status": "EXPIRED"},
            {"duty_code": "FINANCE_OPERATOR"},
            {"reviewer_is_creator": True},
            {"reviewer_is_owning_organization_member": True},
            {"demand_id": "demand_target_wrong_001"},
        )
        observations = []
        for mutation in mutations:
            harness = build_harness(_seed_for("verify"))
            harness.review_authority.result = replace(
                harness.review_authority.result, **mutation
            )
            before = harness.uow_factory.store.snapshot()
            _result, code = _capture(
                lambda harness=harness: harness.handlers["verify"].handle(
                    actor=reviewer_actor(), command=commands()["verify"]
                )
            )
            observations.append((code, harness.uow_factory.store.snapshot() == before))
        self.assertEqual(
            observations,
            [
                ("RESOURCE_NOT_FOUND", True),
                ("RESOURCE_NOT_FOUND", True),
                ("REVIEW_CONFLICT", True),
                ("REVIEW_CONFLICT", True),
                ("RESOURCE_NOT_FOUND", True),
            ],
        )

    def test_content_policy_hold_and_rule_drift_fail_closed_with_zero_writes(self) -> None:
        observations = []
        mutations = (
            ("content", {"content_sha256": "7" * 64}, "SERVICE_UNAVAILABLE"),
            ("hold", {"prospective_aggregate_version": 999}, "SERVICE_UNAVAILABLE"),
            ("rules", {"taxonomy_bundle_id": "taxonomy_bundle_changed_01"}, "TAXONOMY_BUNDLE_CHANGED"),
        )
        for target, mutation, expected in mutations:
            harness = build_harness(_seed_for("submit"))
            if target == "content":
                harness.content_policy.overrides.update(mutation)
            elif target == "hold":
                harness.safety_hold.overrides.update(mutation)
            else:
                harness.rule_catalog.result = replace(
                    harness.rule_catalog.result, **mutation
                )
            before = harness.uow_factory.store.snapshot()
            _result, code = _capture(
                lambda harness=harness: harness.handlers["submit"].handle(
                    actor=owner_actor(), command=commands()["submit"]
                )
            )
            observations.append(
                (code, expected, harness.uow_factory.store.snapshot() == before)
            )
        self.assertEqual(
            [(code, unchanged) for code, _expected, unchanged in observations],
            [(expected, True) for _code, expected, _unchanged in observations],
        )

    def test_completed_receipt_replays_before_policy_and_different_payload_conflicts(self) -> None:
        actor = owner_actor()
        original_command = commands()["create"]
        keyring = DeterministicReceiptKeyring()
        receipt = {
            "principal_kind": "USER",
            "principal_id": "user_demand_owner_00001",
            "organization_id": ORGANIZATION_ID,
            "command_name": "CreateDemand",
            "command_version": 1,
            "key_digest_key_id": "demand-idempotency-2026-01",
            "key_digest": keyring.keyed_digest(
                keyring.idempotency_key_digest_key_id,
                IDEMPOTENCY_KEY.encode("utf-8"),
            ),
            "payload_hash_key_id": "demand-payload-2026-01",
            "payload_hash": demand_command_payload_hash(
                actor=actor,
                command=original_command,
                receipt_keyring=keyring,
            ),
            "target_id": DEMAND_ID,
            "target_version": 1,
            "status": "COMPLETED",
            "safe_response": {
                "demand_id": DEMAND_ID,
                "organization_id": ORGANIZATION_ID,
                "demand_version_id": VERSION_ID,
                "status": "DRAFT",
                "aggregate_version": 1,
                "etag": '"v1"',
                "replayed": False,
            },
        }
        seed = dict(_seed_for("version"))
        seed["receipts"] = {"receipt": receipt}
        harness = build_harness(seed)
        replay, replay_code = _capture(
            lambda: harness.handlers["create"].handle(
                actor=actor, command=original_command
            )
        )
        changed = commands()["create"]
        changed_mapping = valid_content_mapping()
        changed_mapping["problem"]["background"] = "Different private content."
        changed = replace(changed, content=freeze_json(changed_mapping))
        _conflict, conflict_code = _capture(
            lambda: harness.handlers["create"].handle(
                actor=owner_actor(), command=changed
            )
        )
        corrupt_receipt = deepcopy(receipt)
        corrupt_receipt["safe_response"]["provider_secret"] = "must-not-replay"
        corrupt_seed = dict(_seed_for("version"))
        corrupt_seed["receipts"] = {"receipt": corrupt_receipt}
        corrupt = build_harness(corrupt_seed)
        _corrupt, corrupt_code = _capture(
            lambda: corrupt.handlers["create"].handle(
                actor=actor, command=original_command
            )
        )
        self.assertEqual(
            {
                "replay_code": replay_code,
                "replayed": getattr(replay, "replayed", None),
                "content_policy_calls": len(harness.content_policy.calls),
                "hold_calls": len(harness.safety_hold.calls),
                "conflict_code": conflict_code,
                "corrupt_code": corrupt_code,
            },
            {
                "replay_code": None,
                "replayed": True,
                "content_policy_calls": 0,
                "hold_calls": 0,
                "conflict_code": "IDEMPOTENCY_KEY_REUSED",
                "corrupt_code": "SERVICE_UNAVAILABLE",
            },
        )

    def test_every_stable_write_checkpoint_rolls_back_all_business_and_infrastructure_facts(self) -> None:
        checkpoint_command = {
            "receipt.claim": "create",
            "demand_version.insert": "create",
            "demand_root.insert_or_update": "create",
            "submission.insert": "submit",
            "review.insert": "verify",
            "review_assignment.update": "verify",
            "source_inbox.claim": "funding",
            "funding_marker.insert": "funding",
            "matching_request.insert": "matching",
            "audit.insert": "create",
            "outbox.insert": "create",
            "source_inbox.complete": "funding",
            "receipt.complete": "create",
        }
        observations = []
        for checkpoint in DEMAND_WRITE_CHECKPOINTS:
            name = checkpoint_command[checkpoint]
            harness = build_harness(_seed_for(name))
            harness.uow_factory.fail_checkpoint = checkpoint
            before = harness.uow_factory.store.snapshot()
            _result, code = _capture(
                lambda harness=harness, name=name: harness.handlers[name].handle(
                    actor=_actor_for(name), command=commands()[name]
                )
            )
            observations.append(
                (
                    checkpoint,
                    code,
                    harness.uow_factory.store.snapshot() == before,
                )
            )
        self.assertEqual(
            observations,
            [(checkpoint, "SERVICE_UNAVAILABLE", True) for checkpoint in DEMAND_WRITE_CHECKPOINTS],
        )

    def test_commit_unknown_recovers_only_complete_bound_receipt_and_discards_ambiguity(self) -> None:
        durable = build_harness()
        durable.uow_factory.commit_unknown = True
        durable.uow_factory.commit_unknown_durable = True
        durable_result, durable_code = _capture(
            lambda: durable.handlers["create"].handle(
                actor=owner_actor(), command=commands()["create"]
            )
        )
        ambiguous = build_harness()
        ambiguous.uow_factory.commit_unknown = True
        ambiguous.uow_factory.commit_unknown_durable = False
        ambiguous.uow_factory.store.data["receipts"] = {
            "receipt": {"status": "IN_PROGRESS", "target_id": DEMAND_ID}
        }
        _unknown, ambiguous_code = _capture(
            lambda: ambiguous.handlers["create"].handle(
                actor=owner_actor(), command=commands()["create"]
            )
        )
        self.assertEqual(
            {
                "durable_code": durable_code,
                "durable_status": getattr(
                    getattr(durable_result, "demand", None), "status", None
                ),
                "durable_replayed": getattr(durable_result, "replayed", None),
                "ambiguous_code": ambiguous_code,
            },
            {
                "durable_code": None,
                "durable_status": DemandStatus.DRAFT,
                "durable_replayed": True,
                "ambiguous_code": "SERVICE_UNAVAILABLE",
            },
        )

    def test_raw_content_references_keys_sessions_notes_and_provider_evidence_never_escape(self) -> None:
        harness = build_harness()
        result, code = _capture(
            lambda: harness.handlers["create"].handle(
                actor=owner_actor(), command=commands()["create"]
            )
        )
        observable = repr(
            (
                owner_actor(),
                commands()["create"],
                result,
                harness.uow_factory.store.snapshot(),
                harness.event_validator.calls,
                harness.safe_response_validator.calls,
            )
        )
        self.assertEqual(
            {
                "code": code,
                "sentinels_visible": [
                    secret for secret in RAW_PRIVATE_SENTINELS if secret in observable
                ],
                "event_validated": bool(harness.event_validator.calls),
                "safe_response_validated": bool(harness.safe_response_validator.calls),
            },
            {
                "code": None,
                "sentinels_visible": [],
                "event_validated": True,
                "safe_response_validated": True,
            },
        )


if __name__ == "__main__":
    unittest.main()
