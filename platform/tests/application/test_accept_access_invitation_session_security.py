"""Session lifetime, auth-context, and key-availability TDD for invitation accept.

These application tests use the formal Session fields from DES-SESSION-001 and
the PostgreSQL implementation design.  They intentionally keep transport cookie
validation outside this handler while requiring persisted Session facts and
versioned key dependencies to fail closed before the safety hold or any write.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
import unittest

from desire_platform.identity_access.domain.errors import IamError
from tests.support.iam_application_builders import (
    RECEIPT_HASH_KEY_ID,
    creator_acceptance_fixture,
)


class AcceptAccessInvitationSessionSecurityTest(unittest.TestCase):
    def test_naive_or_non_utc_server_clock_fails_closed_before_hold_and_writes(
        self,
    ) -> None:
        """Application timestamps are emitted only from an aware UTC clock."""

        for label, current in (
            ("naive", datetime(2026, 8, 7, 10, 30)),
            (
                "non-zero-offset",
                datetime(
                    2026,
                    8,
                    7,
                    18,
                    30,
                    tzinfo=timezone(timedelta(hours=8)),
                ),
            ),
        ):
            with self.subTest(server_clock=label):
                fixture = creator_acceptance_fixture()
                fixture.handler._clock = _StaticClock(current)
                self._assert_rejected_before_hold_and_writes(
                    fixture,
                    expected_code="SERVICE_UNAVAILABLE",
                )

    def test_invalid_or_expired_current_session_fails_before_hold_and_writes(
        self,
    ) -> None:
        """Missing/malformed persisted time is unavailable; expiry is a 401."""

        cases = (
            (
                "missing_idle_expires_at",
                lambda session, fixture: session.pop("idle_expires_at"),
                "SERVICE_UNAVAILABLE",
            ),
            (
                "naive_idle_expires_at",
                lambda session, fixture: session.__setitem__(
                    "idle_expires_at",
                    (fixture.clock.now() + timedelta(hours=1)).replace(tzinfo=None),
                ),
                "SERVICE_UNAVAILABLE",
            ),
            (
                "non_utc_offset_absolute_expires_at",
                lambda session, fixture: session.__setitem__(
                    "absolute_expires_at",
                    (fixture.clock.now() + timedelta(hours=1)).astimezone(
                        timezone(timedelta(hours=8))
                    ),
                ),
                "SERVICE_UNAVAILABLE",
            ),
            (
                "expired_before_now",
                lambda session, fixture: session.__setitem__(
                    "idle_expires_at",
                    fixture.clock.now() - timedelta(microseconds=1),
                ),
                "SESSION_EXPIRED",
            ),
            (
                "expires_at_boundary",
                lambda session, fixture: session.__setitem__(
                    "idle_expires_at", fixture.clock.now()
                ),
                "SESSION_EXPIRED",
            ),
        )

        for name, mutate, expected_code in cases:
            with self.subTest(session_deadline=name):
                fixture = creator_acceptance_fixture()
                session = dict(
                    fixture.store.snapshot()["sessions"][fixture.ids.session_id]
                )
                mutate(session, fixture)
                fixture.store.seed(sessions={fixture.ids.session_id: session})
                self._assert_rejected_before_hold_and_writes(
                    fixture,
                    expected_code=expected_code,
                )

    def test_successor_preserves_formal_auth_context_and_utc_lifetimes(self) -> None:
        """Rotation changes secrets/binding, not authentication strength/evidence."""

        fixture = creator_acceptance_fixture()
        before = fixture.store.snapshot()
        predecessor = before["sessions"][fixture.ids.session_id]

        fixture.handler.handle(actor=fixture.actor, command=fixture.command)
        snapshot = fixture.store.snapshot()
        successor = snapshot["sessions"][fixture.ids.successor_session_id]

        for field in ("auth_time", "acr_code", "amr_codes"):
            self.assertIn(field, successor, "successor omitted %s" % field)
            if field in successor:
                self.assertEqual(successor[field], predecessor[field])

        self.assertEqual(
            successor.get("absolute_expires_at"),
            predecessor["absolute_expires_at"],
        )
        self.assertEqual(
            successor.get("idle_expires_at"),
            min(
                fixture.clock.now() + timedelta(minutes=30),
                predecessor["absolute_expires_at"],
            ),
        )
        for field in ("created_at", "last_activity_at", "updated_at"):
            self.assertEqual(successor.get(field), fixture.clock.now())

        lifetime_fields = (
            "created_at",
            "last_activity_at",
            "idle_expires_at",
            "absolute_expires_at",
            "updated_at",
        )
        for field in lifetime_fields:
            self.assertIn(field, successor, "successor omitted %s" % field)
            if field in successor:
                self._assert_utc_datetime("successor.%s" % field, successor[field])

        audit = next(iter(snapshot["audit_events"].values()))
        self.assertEqual(
            audit.get("auth_strength_code"),
            predecessor["acr_code"],
            "audit must retain the exact server-verified authentication strength",
        )

        for path, value in self._walk_values(snapshot):
            if isinstance(value, datetime):
                self._assert_utc_datetime(path, value)
        for event_id, event in snapshot["outbox_events"].items():
            self.assertTrue(
                event["occurred_at"].endswith("Z"),
                "outbox_events.%s.occurred_at is not canonical UTC" % event_id,
            )

    def test_missing_known_key_material_fails_closed_before_hold_and_writes(
        self,
    ) -> None:
        """A configured key version without material is a stable service failure."""

        fixture = creator_acceptance_fixture()
        fixture.keyring.remove_key_material(RECEIPT_HASH_KEY_ID)

        self._assert_rejected_before_hold_and_writes(
            fixture,
            expected_code="SERVICE_UNAVAILABLE",
        )

    def test_unknown_active_key_id_fails_closed_before_hold_and_writes(self) -> None:
        """Rotation must preflight an unknown active key ID before authority work."""

        fixture = creator_acceptance_fixture()
        fixture.keyring.session_handle_digest_key_id = (
            "iam-session-handle-hmac-unknown-2099-99"
        )

        self._assert_rejected_before_hold_and_writes(
            fixture,
            expected_code="SERVICE_UNAVAILABLE",
        )

    def _assert_rejected_before_hold_and_writes(
        self,
        fixture,
        *,
        expected_code: str,
    ) -> None:
        before = fixture.store.snapshot()
        writes_before = fixture.fault_injector.write_count
        hold_calls_before = len(fixture.hold.calls)
        caught = None
        try:
            fixture.handler.handle(actor=fixture.actor, command=fixture.command)
        except Exception as error:  # noqa: BLE001 - assertion records exact type/code
            caught = error

        problems = []
        if not isinstance(caught, IamError):
            problems.append(
                "expected stable IamError %s, got %s"
                % (expected_code, type(caught).__name__ if caught else "success")
            )
        elif caught.code != expected_code:
            problems.append(
                "expected %s, got %s" % (expected_code, caught.code)
            )
        if fixture.store.snapshot() != before:
            problems.append("rejected command changed persisted facts")
        if fixture.fault_injector.write_count != writes_before:
            problems.append("invalid dependency/session reached an instrumented write")
        if len(fixture.hold.calls) != hold_calls_before:
            problems.append("invalid dependency/session reached the safety hold")
        if problems:
            self.fail("; ".join(problems))

    def _assert_utc_datetime(self, path: str, value) -> None:
        self.assertIsInstance(value, datetime, "%s is not datetime" % path)
        if isinstance(value, datetime):
            self.assertIsNotNone(value.tzinfo, "%s is naive" % path)
            self.assertEqual(
                value.utcoffset(),
                timedelta(0),
                "%s does not use UTC" % path,
            )

    def _walk_values(self, value, path: str = "snapshot"):
        if isinstance(value, Mapping):
            for key, item in value.items():
                yield from self._walk_values(item, "%s.%s" % (path, key))
            return
        if isinstance(value, (list, tuple)):
            for index, item in enumerate(value):
                yield from self._walk_values(item, "%s[%d]" % (path, index))
            return
        yield path, value


class _StaticClock:
    def __init__(self, current: datetime) -> None:
        self._current = current

    def now(self) -> datetime:
        return self._current


if __name__ == "__main__":
    unittest.main()
