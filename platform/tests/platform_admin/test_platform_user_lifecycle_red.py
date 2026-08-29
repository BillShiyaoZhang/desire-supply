from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import unittest

from desire_platform.identity_access.adapters.memory import (
    FaultInjector,
    InMemoryIamStore,
    MemoryUnitOfWorkFactory,
)
from desire_platform.identity_access.application.platform_user_lifecycle import (
    ResumeUserHandler,
    RevokeAllSessionsHandler,
    SuspendUserHandler,
)
from desire_platform.identity_access.domain.authority_lifecycle import (
    LifecycleActorContext,
    LifecycleReason,
    ResumeUserCommand,
    RevokeAllSessionsCommand,
    SuspendUserCommand,
)
from desire_platform.identity_access.domain.errors import IamError
from tests.support.iam_authority_lifecycle_builders import ClosedSchemaValidator


NOW = datetime(2026, 8, 12, 9, 0, tzinfo=timezone.utc)
ACTOR_ID = "user_access_admin_001"
ACTOR_SESSION_ID = "session_access_admin_01"
ACTOR_FAMILY_ID = "family_access_admin_001"
TARGET_ID = "user_platform_target_01"
TARGET_SESSION_IDS = ("session_target_user_001", "session_target_user_002")
TARGET_FAMILY_IDS = ("family_target_user_0001", "family_target_user_0002")
IDEMPOTENCY_KEY = "idem_platform_user_0001"


class FixedClock:
    def now(self) -> datetime:
        return NOW


class FixedIds:
    def __init__(self) -> None:
        self.counter = 0

    def new_id(self, kind: str) -> str:
        self.counter += 1
        return "%s_%08d" % (kind, self.counter)


class Keyring:
    idempotency_key_digest_key_id = "platform-idempotency-key-0001"
    payload_hash_key_id = "platform-payload-key-0000001"
    session_handle_digest_key_id = "platform-session-key-0000001"
    csrf_key_id = "platform-csrf-key-0000000001"

    def __init__(self) -> None:
        self.keys = {
            self.idempotency_key_digest_key_id: b"i" * 32,
            self.payload_hash_key_id: b"p" * 32,
            self.session_handle_digest_key_id: b"s" * 32,
            self.csrf_key_id: b"c" * 32,
        }

    def get_key(self, key_id: str) -> bytes:
        return self.keys[key_id]

    def keyed_digest_hex(self, *, key_id: str, canonical_bytes: bytes) -> str:
        return hmac.new(self.get_key(key_id), canonical_bytes, hashlib.sha256).hexdigest()


def _session(
    session_id: str,
    family_id: str,
    user_id: str,
    *,
    generation: int = 1,
) -> dict:
    return {
        "session_id": session_id,
        "session_family_id": family_id,
        "user_id": user_id,
        "generation": generation,
        "status": "ACTIVE",
        "auth_time": NOW - timedelta(minutes=1),
        "acr_code": "urn:example:acr:mfa",
        "amr_codes": ["oidc", "webauthn"],
        "idle_expires_at": NOW + timedelta(hours=1),
        "absolute_expires_at": NOW + timedelta(days=1),
        "handle_digest_key_id": "platform-session-key-0000001",
        "csrf_key_id": "platform-csrf-key-0000000001",
        "aggregate_version": 1,
    }


def _family(family_id: str, user_id: str) -> dict:
    return {
        "session_family_id": family_id,
        "user_id": user_id,
        "status": "ACTIVE",
        "current_generation": 1,
        "revoked_at": None,
        "revocation_reason_code": None,
        "aggregate_version": 1,
    }


def _seed() -> dict:
    return {
        "users": {
            ACTOR_ID: {
                "user_id": ACTOR_ID,
                "status": "ACTIVE",
                "display_handle": "access-admin",
                "aggregate_version": 1,
                "created_at": NOW - timedelta(days=10),
                "updated_at": NOW - timedelta(days=10),
            },
            TARGET_ID: {
                "user_id": TARGET_ID,
                "status": "ACTIVE",
                "display_handle": "pilot-operator",
                "aggregate_version": 1,
                "created_at": NOW - timedelta(days=5),
                "updated_at": NOW - timedelta(days=5),
            },
        },
        "platform_duty_grants": {
            "duty_grant_access_admin_01": {
                "platform_duty_grant_id": "duty_grant_access_admin_01",
                "user_id": ACTOR_ID,
                "duty_code": "ACCESS_ADMIN",
                "granted_at": NOW - timedelta(days=2),
                "expires_at": NOW + timedelta(days=30),
                "revoked_at": None,
                "aggregate_version": 1,
            },
            "duty_grant_operator_0001": {
                "platform_duty_grant_id": "duty_grant_operator_0001",
                "user_id": TARGET_ID,
                "duty_code": "OPERATIONS_REVIEWER",
                "granted_at": NOW - timedelta(days=2),
                "expires_at": NOW + timedelta(days=30),
                "revoked_at": None,
                "aggregate_version": 1,
            },
        },
        "session_families": {
            ACTOR_FAMILY_ID: _family(ACTOR_FAMILY_ID, ACTOR_ID),
            **{
                family_id: _family(family_id, TARGET_ID)
                for family_id in TARGET_FAMILY_IDS
            },
        },
        "sessions": {
            ACTOR_SESSION_ID: _session(ACTOR_SESSION_ID, ACTOR_FAMILY_ID, ACTOR_ID),
            **{
                session_id: _session(session_id, family_id, TARGET_ID)
                for session_id, family_id in zip(TARGET_SESSION_IDS, TARGET_FAMILY_IDS)
            },
        },
        "command_receipts": {},
        "audit_events": {},
        "outbox_events": {},
    }


def _actor() -> LifecycleActorContext:
    return LifecycleActorContext(
        actor_user_id=ACTOR_ID,
        current_session_id=ACTOR_SESSION_ID,
        original_actor_id=None,
        correlation_id="correlation_platform_001",
        causation_id="causation_platform_0001",
        trace_id="trace_platform_admin_001",
    )


class Fixture:
    def __init__(self, handler_type, command, *, seed=None, fault=None) -> None:
        self.store = InMemoryIamStore()
        self.store.seed(**(seed or _seed()))
        self.factory = MemoryUnitOfWorkFactory(
            store=self.store,
            fault_injector=fault or FaultInjector(),
        )
        self.handler = handler_type(
            uow_factory=self.factory,
            clock=FixedClock(),
            id_source=FixedIds(),
            keyring=Keyring(),
            event_validator=ClosedSchemaValidator.for_events(),
            safe_response_validator=ClosedSchemaValidator.for_openapi(),
        )
        self.command = command

    def invoke(self):
        return self.handler.handle(actor=_actor(), command=self.command)


def _reason() -> LifecycleReason:
    return LifecycleReason(
        reason_code="SECURITY_REVIEW",
        reason_note="restricted operator note; never persist plaintext",
    )


def _suspend(target_id=TARGET_ID, version=1, key=IDEMPOTENCY_KEY):
    return SuspendUserCommand(
        user_id=target_id,
        expected_version=version,
        idempotency_key=key,
        reason=_reason(),
    )


def _resume(version=2):
    return ResumeUserCommand(
        user_id=TARGET_ID,
        expected_version=version,
        idempotency_key="idem_platform_resume_0001",
        reason=_reason(),
    )


def _revoke_all(version=1):
    return RevokeAllSessionsCommand(
        user_id=TARGET_ID,
        expected_version=version,
        idempotency_key="idem_platform_revoke_sessions_01",
        reason=_reason(),
    )


class PlatformUserLifecycleRedTest(unittest.TestCase):
    def test_suspend_user_revokes_every_active_family_and_session_atomically(self) -> None:
        fixture = Fixture(SuspendUserHandler, _suspend())

        result = fixture.invoke()

        self.assertFalse(result.replayed)
        self.assertEqual(result.http_status, 200)
        self.assertEqual(result.safe_response["status"], "SUSPENDED")
        self.assertEqual(result.safe_response["aggregate_version"], 2)
        self.assertEqual(result.safe_response["revoked_session_count"], 2)
        self.assertEqual(result.safe_response["revoked_session_family_count"], 2)
        after = fixture.store.snapshot()
        self.assertEqual(after["users"][TARGET_ID]["status"], "SUSPENDED")
        self.assertEqual(after["users"][TARGET_ID]["aggregate_version"], 2)
        self.assertTrue(
            all(after["sessions"][item]["status"] == "REVOKED" for item in TARGET_SESSION_IDS)
        )
        self.assertTrue(
            all(after["session_families"][item]["status"] == "REVOKED" for item in TARGET_FAMILY_IDS)
        )
        self.assertEqual(len(after["command_receipts"]), 1)
        self.assertEqual(len(after["audit_events"]), 1)
        self.assertEqual(
            sorted(event["event_type"] for event in after["outbox_events"].values()),
            ["SessionRevoked", "SessionRevoked", "UserSuspended"],
        )
        self.assertNotIn("restricted operator note", repr(after))

    def test_receipt_replay_is_exact_and_writes_nothing_new(self) -> None:
        fixture = Fixture(SuspendUserHandler, _suspend())
        first = fixture.invoke()
        after_first = fixture.store.snapshot()
        writes_after_first = fixture.factory.fault_injector.write_count

        second = fixture.invoke()

        self.assertTrue(second.replayed)
        self.assertEqual(second.safe_response, first.safe_response)
        self.assertEqual(fixture.store.snapshot(), after_first)
        self.assertEqual(fixture.factory.fault_injector.write_count, writes_after_first)

    def test_same_receipt_key_with_changed_payload_is_rejected(self) -> None:
        fixture = Fixture(SuspendUserHandler, _suspend())
        fixture.invoke()
        fixture.command = _suspend(version=2)
        with self.assertRaises(IamError) as raised:
            fixture.invoke()
        self.assertEqual(raised.exception.code, "IDEMPOTENCY_KEY_REUSED")

    def test_access_admin_and_recent_mfa_are_both_required(self) -> None:
        cases = []
        no_duty = _seed()
        no_duty["platform_duty_grants"] = {}
        cases.append(("no access admin", no_duty, "RESOURCE_NOT_FOUND"))
        stale_mfa = _seed()
        stale_mfa["sessions"][ACTOR_SESSION_ID]["auth_time"] = NOW - timedelta(minutes=10)
        cases.append(("stale mfa", stale_mfa, "MFA_STEP_UP_REQUIRED"))
        weak_mfa = _seed()
        weak_mfa["sessions"][ACTOR_SESSION_ID]["acr_code"] = "urn:example:acr:password"
        weak_mfa["sessions"][ACTOR_SESSION_ID]["amr_codes"] = ["pwd"]
        cases.append(("weak mfa", weak_mfa, "MFA_STEP_UP_REQUIRED"))
        corrupt_duty = _seed()
        corrupt_duty["platform_duty_grants"]["duty_grant_access_admin_01"][
            "granted_at"
        ] = NOW.replace(tzinfo=None)
        cases.append(("corrupt duty timestamp", corrupt_duty, "SERVICE_UNAVAILABLE"))

        for label, seed, expected in cases:
            with self.subTest(label=label):
                fixture = Fixture(SuspendUserHandler, _suspend(), seed=seed)
                before = fixture.store.snapshot()
                with self.assertRaises(IamError) as raised:
                    fixture.invoke()
                self.assertEqual(raised.exception.code, expected)
                self.assertEqual(fixture.store.snapshot(), before)

    def test_platform_admin_cannot_manage_its_own_user(self) -> None:
        fixture = Fixture(SuspendUserHandler, _suspend(target_id=ACTOR_ID))
        before = fixture.store.snapshot()
        with self.assertRaises(IamError) as raised:
            fixture.invoke()
        self.assertEqual(raised.exception.code, "SELF_MANAGEMENT_FORBIDDEN")
        self.assertEqual(fixture.store.snapshot(), before)

    def test_suspending_a_second_access_admin_preserves_one_active_admin(self) -> None:
        seed = _seed()
        seed["platform_duty_grants"]["duty_grant_operator_0001"][
            "duty_code"
        ] = "ACCESS_ADMIN"
        fixture = Fixture(SuspendUserHandler, _suspend(), seed=seed)

        fixture.invoke()

        after = fixture.store.snapshot()
        active_admin_users = {
            grant["user_id"]
            for grant in after["platform_duty_grants"].values()
            if grant["duty_code"] == "ACCESS_ADMIN"
            and grant["revoked_at"] is None
            and after["users"][grant["user_id"]]["status"] == "ACTIVE"
        }
        self.assertEqual(active_admin_users, {ACTOR_ID})

    def test_stale_user_version_or_wrong_state_is_closed(self) -> None:
        stale = Fixture(SuspendUserHandler, _suspend(version=2))
        with self.assertRaises(IamError) as raised:
            stale.invoke()
        self.assertEqual(raised.exception.code, "PRECONDITION_FAILED")

        seed = _seed()
        seed["users"][TARGET_ID]["status"] = "SUSPENDED"
        invalid_state = Fixture(SuspendUserHandler, _suspend(), seed=seed)
        with self.assertRaises(IamError) as raised:
            invalid_state.invoke()
        self.assertEqual(raised.exception.code, "INVALID_STATE_TRANSITION")

    def test_resume_changes_only_user_state_and_never_resurrects_sessions(self) -> None:
        suspend = Fixture(SuspendUserHandler, _suspend())
        suspend.invoke()
        fixture = Fixture(
            ResumeUserHandler,
            _resume(),
            seed=suspend.store.snapshot(),
        )

        result = fixture.invoke()

        self.assertEqual(result.safe_response["status"], "ACTIVE")
        self.assertEqual(result.safe_response["aggregate_version"], 3)
        self.assertEqual(result.safe_response["revoked_session_count"], 0)
        after = fixture.store.snapshot()
        self.assertTrue(
            all(after["sessions"][item]["status"] == "REVOKED" for item in TARGET_SESSION_IDS)
        )
        self.assertEqual(
            [event["event_type"] for event in after["outbox_events"].values()].count("UserResumed"),
            1,
        )

    def test_resume_converges_any_drifted_active_sessions_instead_of_reviving_them(self) -> None:
        seed = _seed()
        seed["users"][TARGET_ID].update(
            {"status": "SUSPENDED", "aggregate_version": 2}
        )
        fixture = Fixture(ResumeUserHandler, _resume(), seed=seed)

        result = fixture.invoke()

        self.assertEqual(result.safe_response["status"], "ACTIVE")
        self.assertEqual(result.safe_response["revoked_session_count"], 2)
        after = fixture.store.snapshot()
        self.assertTrue(
            all(after["sessions"][item]["status"] == "REVOKED" for item in TARGET_SESSION_IDS)
        )
        self.assertTrue(
            all(
                after["session_families"][item]["status"] == "REVOKED"
                for item in TARGET_FAMILY_IDS
            )
        )

    def test_revoke_all_sessions_keeps_user_active_but_advances_its_version(self) -> None:
        fixture = Fixture(RevokeAllSessionsHandler, _revoke_all())

        result = fixture.invoke()

        self.assertEqual(result.safe_response["status"], "ACTIVE")
        self.assertEqual(result.safe_response["aggregate_version"], 2)
        self.assertEqual(result.safe_response["revoked_session_count"], 2)
        after = fixture.store.snapshot()
        self.assertEqual(after["users"][TARGET_ID]["status"], "ACTIVE")
        self.assertEqual(
            sorted(event["event_type"] for event in after["outbox_events"].values()),
            ["SessionRevoked", "SessionRevoked", "SessionsRevoked"],
        )

    def test_memory_uow_supports_lock_get_values_and_full_rollback(self) -> None:
        fault = FaultInjector(fail_on_checkpoint="platform_user.audit")
        fixture = Fixture(SuspendUserHandler, _suspend(), fault=fault)
        before = fixture.store.snapshot()

        with self.assertRaises(RuntimeError):
            fixture.invoke()
        self.assertEqual(fixture.store.snapshot(), before)
        self.assertTrue(fixture.factory.lock_calls)
        self.assertIn(
            ("users", tuple(sorted((ACTOR_ID, TARGET_ID)))),
            fixture.factory.lock_calls,
            "actor/target User locks must share one deterministic order to avoid cross-admin deadlocks",
        )
        with fixture.factory.begin() as uow:
            self.assertEqual(uow.get("users", TARGET_ID)["status"], "ACTIVE")
            self.assertEqual(len(uow.values("users")), 2)

    def test_every_suspend_write_checkpoint_rolls_back_the_whole_command(self) -> None:
        probe = Fixture(SuspendUserHandler, _suspend())
        probe.invoke()
        write_count = probe.factory.fault_injector.write_count
        self.assertGreater(write_count, 0)
        self.assertEqual(
            len(probe.factory.fault_injector.checkpoint_names),
            len(set(probe.factory.fault_injector.checkpoint_names)),
        )

        for ordinal in range(1, write_count + 1):
            with self.subTest(write_ordinal=ordinal, total=write_count):
                fixture = Fixture(
                    SuspendUserHandler,
                    _suspend(),
                    fault=FaultInjector(fail_on_write=ordinal),
                )
                before = fixture.store.snapshot()
                with self.assertRaises(RuntimeError):
                    fixture.invoke()
                self.assertEqual(fixture.store.snapshot(), before)


if __name__ == "__main__":
    unittest.main()
