"""First semantic RED for Creator Profile command orchestration."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import FrozenInstanceError, replace
import json
from typing import Any, Callable, Mapping
import unittest

from desire_platform.creator_profile.application import (
    CreatorProfileApplicationBehaviorNotAvailable,
    CreatorProfileApplicationError,
    PROFILE_APPLICATION_BEHAVIOR_NOT_AVAILABLE,
)
from desire_platform.creator_profile.domain import CreatorProfileStatus
from desire_platform.creator_profile.ports.commands import (
    CreatorProfileAuthorityUnavailableError,
    CreatorProfileHoldDecision,
    CreatorProfileSafetyHoldUnavailableError,
)
from tests.support.creator_profile_builders import (
    CREATOR_GRANT_ID,
    IDEMPOTENCY_KEY,
    OTHER_USER_ID,
    POLICY_BUNDLE_ID,
    PROFILE_ID,
    RAW_PRIVATE_SENTINELS,
    SESSION_ID,
    TAXONOMY_ID,
    USER_ID,
    VERSION_ID,
    application_fixture,
    replace_authority,
)


def _capture(call: Callable[[], Any]) -> tuple[Any, str | None]:
    try:
        return call(), None
    except CreatorProfileApplicationError as error:
        return None, error.code
    except CreatorProfileApplicationBehaviorNotAvailable as error:
        if str(error) != PROFILE_APPLICATION_BEHAVIOR_NOT_AVAILABLE:
            return None, "UNEXPECTED_APPLICATION_SENTINEL"
        return None, PROFILE_APPLICATION_BEHAVIOR_NOT_AVAILABLE
    except Exception as error:
        return None, "UNEXPECTED:" + type(error).__name__


def _invoke(fixture, operation: str):
    return _capture(
        lambda: fixture.handlers[operation].handle(
            actor=fixture.actor,
            command=fixture.commands[operation],
        )
    )


def _recursive_strings(value: Any) -> list[str]:
    if isinstance(value, Mapping):
        result = [str(key) for key in value]
        for child in value.values():
            result.extend(_recursive_strings(child))
        return result
    if isinstance(value, (list, tuple, set)):
        result = []
        for child in value:
            result.extend(_recursive_strings(child))
        return result
    return [str(value)]


class CreatorProfileApplicationSemanticRedTest(unittest.TestCase):
    """TEST-APP-PROFILE-001/HOLD-001/RECEIPT-001."""

    def test_commands_and_actor_are_frozen_and_secret_safe(self) -> None:
        fixture = application_fixture("save")
        rendered = repr((fixture.actor, tuple(fixture.commands.values())))
        self.assertNotIn(SESSION_ID, rendered)
        self.assertNotIn(IDEMPOTENCY_KEY, rendered)
        self.assertNotIn("minimum_project_amount_minor", rendered)
        for sentinel in RAW_PRIVATE_SENTINELS:
            with self.subTest(sentinel=sentinel[:12]):
                self.assertNotIn(sentinel, rendered)
        with self.assertRaises(FrozenInstanceError):
            fixture.actor.actor_user_id = OTHER_USER_ID  # type: ignore[misc]
        with self.assertRaises(FrozenInstanceError):
            fixture.commands["save"].expected_version = 99  # type: ignore[misc]

    def test_six_command_happy_paths_have_exact_state_event_and_single_commit(self) -> None:
        expected = {
            "create": (CreatorProfileStatus.DRAFT, ("CreatorProfileCreated",), 1),
            "save": (CreatorProfileStatus.ACTIVE, (), 3),
            "publish": (CreatorProfileStatus.ACTIVE, ("CreatorProfilePublished",), 3),
            "pause": (CreatorProfileStatus.PAUSED, ("CreatorProfilePaused",), 3),
            "resume": (CreatorProfileStatus.ACTIVE, ("CreatorProfileResumed",), 3),
            "archive": (CreatorProfileStatus.ARCHIVED, ("CreatorProfileArchived",), 3),
        }
        observed = {}
        for operation, (status, events, aggregate_version) in expected.items():
            fixture = application_fixture(operation)
            result, code = _invoke(fixture, operation)
            observed[operation] = (
                code,
                getattr(getattr(result, "profile", None), "status", None),
                getattr(result, "event_types", None),
                getattr(getattr(result, "profile", None), "aggregate_version", None),
                getattr(result, "replayed", None),
                fixture.uow_factory.commit_count,
            )
        self.assertEqual(
            observed,
            {
                operation: (None, status, events, version, False, 1)
                for operation, (status, events, version) in expected.items()
            },
        )

    def test_exact_iam_authority_failures_are_classified_before_hold_or_write(self) -> None:
        cases = (
            ("suspended-user", {"user_status": "SUSPENDED"}, "AUTHENTICATION_REQUIRED"),
            ("revoked-session", {"session_status": "REVOKED"}, "SESSION_EXPIRED"),
            ("revoked-family", {"session_family_status": "REVOKED"}, "SESSION_EXPIRED"),
            ("missing-creator-grant", {"creator_grant_id": ""}, "RESOURCE_NOT_FOUND"),
            ("other-authority-user", {"actor_user_id": OTHER_USER_ID}, "RESOURCE_NOT_FOUND"),
            ("policy-missing", {"policy_requirements_satisfied": False}, "POLICY_ACCEPTANCE_REQUIRED"),
        )
        observed = []
        for name, changes, expected_code in cases:
            fixture = application_fixture("publish")
            replace_authority(fixture, **changes)
            before = fixture.store.snapshot()
            _result, code = _invoke(fixture, "publish")
            observed.append(
                (
                    name,
                    code,
                    fixture.store.snapshot() == before,
                    len(fixture.hold.calls),
                    fixture.uow_factory.begin_count,
                    expected_code,
                )
            )
        self.assertEqual(
            [(name, code, unchanged, holds, begins) for name, code, unchanged, holds, begins, _ in observed],
            [(name, expected, True, 0, 0) for name, _code, _unchanged, _holds, _begins, expected in observed],
        )

    def test_unknown_cross_owner_stale_etag_and_state_do_not_leak_relationships(self) -> None:
        missing = application_fixture("pause")
        missing.store.tables["creator_profiles"].clear()
        _missing_result, missing_code = _invoke(missing, "pause")

        cross_owner = application_fixture("pause")
        root = cross_owner.store.tables["creator_profiles"][PROFILE_ID]
        cross_owner.store.tables["creator_profiles"][PROFILE_ID] = replace(
            root,
            owner_user_id=OTHER_USER_ID,
        )
        _cross_result, cross_code = _invoke(cross_owner, "pause")

        stale = application_fixture("pause")
        stale.commands = {
            **stale.commands,
            "pause": replace(stale.commands["pause"], expected_version=1),
        }
        _stale_result, stale_code = _invoke(stale, "pause")

        invalid_state = application_fixture("pause")
        archived = replace(
            invalid_state.store.tables["creator_profiles"][PROFILE_ID],
            status=CreatorProfileStatus.ARCHIVED,
            current_published_version_id=None,
        )
        invalid_state.store.tables["creator_profiles"][PROFILE_ID] = archived
        _state_result, state_code = _invoke(invalid_state, "pause")

        self.assertEqual(
            (missing_code, cross_code, stale_code, state_code),
            (
                "RESOURCE_NOT_FOUND",
                "RESOURCE_NOT_FOUND",
                "PRECONDITION_FAILED",
                "INVALID_STATE_TRANSITION",
            ),
        )

    def test_publish_resume_hold_is_exact_while_private_or_downgrade_commands_skip_it(self) -> None:
        visibility_increasing = {}
        for operation in ("publish", "resume"):
            fixture = application_fixture(operation)
            result, code = _invoke(fixture, operation)
            call = fixture.hold.calls[0] if fixture.hold.calls else {}
            visibility_increasing[operation] = {
                "code": code,
                "result": result,
                "calls": len(fixture.hold.calls),
                "profile_id": call.get("profile_id"),
                "prospective": call.get("prospective_aggregate_version"),
                "actor": call.get("actor_user_id"),
                "policy": call.get("policy_version"),
            }

        downgrade_holds = {}
        for operation in ("save", "pause", "archive"):
            fixture = application_fixture(operation)
            _result, code = _invoke(fixture, operation)
            downgrade_holds[operation] = (code, len(fixture.hold.calls))

        blocked = application_fixture("publish")
        blocked.hold.decision = CreatorProfileHoldDecision.BLOCK
        blocked_before = blocked.store.snapshot()
        _blocked_result, blocked_code = _invoke(blocked, "publish")

        unavailable = application_fixture("resume")
        unavailable.hold.error = CreatorProfileSafetyHoldUnavailableError(
            "scripted unavailable"
        )
        _unavailable_result, unavailable_code = _invoke(unavailable, "resume")

        drift = application_fixture("publish")
        drift.hold.overrides["content_sha256"] = "f" * 64
        _drift_result, drift_code = _invoke(drift, "publish")

        self.assertEqual(
            {
                "visibility": visibility_increasing,
                "downgrade": downgrade_holds,
                "blocked_code": blocked_code,
                "blocked_unchanged": blocked.store.snapshot() == blocked_before,
                "unavailable_code": unavailable_code,
                "drift_code": drift_code,
            },
            {
                "visibility": {
                    "publish": {
                        "code": None,
                        "result": visibility_increasing["publish"]["result"],
                        "calls": 1,
                        "profile_id": PROFILE_ID,
                        "prospective": 3,
                        "actor": USER_ID,
                        "policy": "creator-profile-hold-v1",
                    },
                    "resume": {
                        "code": None,
                        "result": visibility_increasing["resume"]["result"],
                        "calls": 1,
                        "profile_id": PROFILE_ID,
                        "prospective": 3,
                        "actor": USER_ID,
                        "policy": "creator-profile-hold-v1",
                    },
                },
                "downgrade": {operation: (None, 0) for operation in ("save", "pause", "archive")},
                "blocked_code": "SAFETY_HOLD_BLOCKED",
                "blocked_unchanged": True,
                "unavailable_code": "SERVICE_UNAVAILABLE",
                "drift_code": "SERVICE_UNAVAILABLE",
            },
        )

    def test_lock_order_rechecks_authority_profile_versions_taxonomy_evidence_then_receipt(self) -> None:
        fixture = application_fixture("publish")
        _result, code = _invoke(fixture, "publish")
        resources = [resource for resource, _keys in fixture.uow_factory.lock_calls]
        self.assertEqual(
            {
                "code": code,
                "authority_calls": [operation for _actor, operation in fixture.authority.calls],
                "resources": resources,
            },
            {
                "code": None,
                "authority_calls": ["PublishCreatorProfileVersion"],
                "resources": [
                    "iam.authority_marker",
                    "profile.creator_profile",
                    "profile.current_draft",
                    "profile.current_published",
                    "profile.taxonomy_bundle",
                    "profile.capability_evidence",
                    "profile.command_receipt",
                ],
            },
        )

    def test_receipt_exact_replay_and_same_key_changed_payload_conflict(self) -> None:
        fixture = application_fixture("save")
        first, first_code = _invoke(fixture, "save")
        replay, replay_code = _invoke(fixture, "save")
        changed = replace(
            fixture.commands["save"],
            taxonomy_bundle_id="taxonomy_bundle_other_01",
        )
        _conflict, conflict_code = _capture(
            lambda: fixture.handlers["save"].handle(
                actor=fixture.actor,
                command=changed,
            )
        )
        self.assertEqual(
            {
                "first_code": first_code,
                "first_replayed": getattr(first, "replayed", None),
                "replay_code": replay_code,
                "replayed": getattr(replay, "replayed", None),
                "same_profile": getattr(getattr(replay, "profile", None), "profile_id", None),
                "conflict_code": conflict_code,
                "outbox_count": len(fixture.store.snapshot().get("outbox_events", {})),
            },
            {
                "first_code": None,
                "first_replayed": False,
                "replay_code": None,
                "replayed": True,
                "same_profile": PROFILE_ID,
                "conflict_code": "IDEMPOTENCY_KEY_REUSED",
                "outbox_count": 0,
            },
        )

    def test_every_publish_write_checkpoint_rolls_back_root_version_receipt_audit_outbox(self) -> None:
        checkpoints = (
            "receipt.pending",
            "profile_version.published",
            "profile.root",
            "audit.profile_published",
            "outbox.profile_published",
            "receipt.completed",
        )
        observed = []
        for checkpoint in checkpoints:
            fixture = application_fixture("publish")
            fixture.uow_factory.fail_checkpoint = checkpoint
            before = fixture.store.snapshot()
            _result, code = _invoke(fixture, "publish")
            observed.append(
                (
                    checkpoint,
                    code,
                    fixture.store.snapshot() == before,
                    fixture.uow_factory.commit_count,
                )
            )
        self.assertEqual(
            observed,
            [(checkpoint, "SERVICE_UNAVAILABLE", True, 0) for checkpoint in checkpoints],
        )

    def test_commit_unknown_recovers_only_exact_completed_receipt_and_never_duplicates_event(self) -> None:
        persisted = application_fixture("publish")
        persisted.uow_factory.commit_unknown = True
        persisted.uow_factory.commit_unknown_persists = True
        persisted_result, persisted_code = _invoke(persisted, "publish")

        missing = application_fixture("publish")
        missing.uow_factory.commit_unknown = True
        missing.uow_factory.commit_unknown_persists = False
        _missing_result, missing_code = _invoke(missing, "publish")

        self.assertEqual(
            {
                "persisted_code": persisted_code,
                "persisted_replayed": getattr(persisted_result, "replayed", None),
                "persisted_events": len(persisted.store.snapshot().get("outbox_events", {})),
                "missing_code": missing_code,
                "missing_events": len(missing.store.snapshot().get("outbox_events", {})),
            },
            {
                "persisted_code": None,
                "persisted_replayed": True,
                "persisted_events": 1,
                "missing_code": "SERVICE_UNAVAILABLE",
                "missing_events": 0,
            },
        )

    def test_receipt_audit_outbox_result_and_errors_never_copy_private_content_or_raw_key(self) -> None:
        fixture = application_fixture("save")
        result, code = _invoke(fixture, "save")
        snapshot = fixture.store.snapshot()
        diagnostic_surface = {
            "receipt": snapshot.get("command_receipts", {}),
            "audit": snapshot.get("audit_events", {}),
            "outbox": snapshot.get("outbox_events", {}),
            "result_repr": repr(result),
            "code": code,
        }
        rendered = "\n".join(_recursive_strings(diagnostic_surface))
        forbidden_names = (
            "minimum_project_amount_minor",
            "direct_cost_amount_minor",
            "prohibited_domains",
            "organization_conflict_0001",
            "evidence_locator",
            "legacy_source_ref",
        )
        self.assertEqual(code, None)
        for forbidden in (*RAW_PRIVATE_SENTINELS, *forbidden_names):
            with self.subTest(forbidden=forbidden[:16]):
                self.assertNotIn(forbidden, rendered)


if __name__ == "__main__":
    unittest.main()
