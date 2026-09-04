from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
from datetime import timedelta
import unittest
from uuid import UUID

from desire_platform.http.contracts import AuthenticatedHttpActor
from desire_platform.http.iam_security import (
    PsycopgIamSessionSecurity,
    SessionSecuritySettings,
)
from desire_platform.identity_access.domain.errors import IamError
from desire_platform.identity_access.security.cryptography import (
    KeyUnavailableError,
)

from tests.support.iam_http_session_security_builders import (
    ACTIVE_CSRF_KEY,
    ACTIVE_HANDLE,
    ACTIVE_HANDLE_KEY,
    FAMILY_ID,
    FixedSessionSecurityIdSource,
    FixedSessionSecurityKeyring,
    NOW,
    OLD_HANDLE_KEY,
    OLD_KEY_HANDLE,
    SESSION_ID,
    ScriptedSessionConnectionSource,
    TRACE_ID,
    UNKNOWN_HANDLE,
    USER_ID,
    seed_row,
    session_row,
)


def _auth_outcome(component: PsycopgIamSessionSecurity, raw: str | None):
    try:
        return component.authenticate(raw_session_handle=raw, trace_id=TRACE_ID)
    except IamError as error:
        return error.code


def _csrf_outcome(
    component: PsycopgIamSessionSecurity,
    *,
    raw_handle: str,
    raw_token: str | None,
    actor: AuthenticatedHttpActor,
    operation_id: str = "grantConsent",
):
    try:
        component.require_valid(
            raw_session_handle=raw_handle,
            raw_csrf_token=raw_token,
            actor=actor,
            operation_id=operation_id,
        )
    except IamError as error:
        return error.code
    return None


class _ProductionStyleUuidIdSource:
    """Matches SecureRuntimeSources' UUID-valued new_id boundary."""

    def __init__(self) -> None:
        self.purposes: list[str] = []

    def new_id(self, purpose: str) -> UUID:
        self.purposes.append(purpose)
        return UUID(int=len(self.purposes))


class IamHttpSessionSecurityUnitRedTests(unittest.TestCase):
    def _fixture(self):
        source = ScriptedSessionConnectionSource()
        keyring = FixedSessionSecurityKeyring()
        ids = FixedSessionSecurityIdSource()
        component = PsycopgIamSessionSecurity(
            connections=source,
            keyring=keyring,
            id_source=ids,
        )
        return source, keyring, ids, component

    def test_active_exact_cookie_builds_only_persisted_actor_facts(self) -> None:
        source, keyring, _ids, component = self._fixture()
        row = session_row(keyring)
        seed_row(source, row)
        actor = _auth_outcome(component, ACTIVE_HANDLE)
        self.assertIsInstance(actor, AuthenticatedHttpActor)
        self.assertEqual(actor.actor_user_id, USER_ID)
        self.assertEqual(actor.session_id, SESSION_ID)
        self.assertEqual(actor.original_actor_id, None)
        self.assertEqual(actor.auth_time, NOW - timedelta(minutes=5))
        self.assertEqual(actor.acr_code, "urn:desire:acr:mfa")
        self.assertEqual(actor.amr_codes, ("pwd", "otp"))
        self.assertEqual(
            (actor.correlation_id, actor.causation_id, actor.trace_id),
            (TRACE_ID, TRACE_ID, TRACE_ID),
        )
        self.assertEqual(source.checkout_count, 1)
        self.assertEqual(len(source.released), 1)
        self.assertEqual(source.discarded, [])
        install_keys = [
            params[-2]
            for statement, params in source.executions
            if "install_session_authenticate_context_v2" in statement
        ]
        self.assertEqual(install_keys, [OLD_HANDLE_KEY, ACTIVE_HANDLE_KEY])
        self.assertNotIn(ACTIVE_HANDLE, repr(source.executions))

    def test_pending_enrollment_cookie_authenticates_for_closed_enrollment_flow(
        self,
    ) -> None:
        source, keyring, _ids, component = self._fixture()
        row = session_row(keyring, user_status="PENDING_ENROLLMENT")
        seed_row(source, row)

        actor = _auth_outcome(component, ACTIVE_HANDLE)

        self.assertIsInstance(actor, AuthenticatedHttpActor)
        self.assertEqual(actor.actor_user_id, USER_ID)
        self.assertEqual(actor.session_id, SESSION_ID)
        self.assertIsNone(
            _csrf_outcome(
                component,
                raw_handle=ACTIVE_HANDLE,
                raw_token=row["csrf_token"],
                actor=actor,
            )
        )

    def test_old_retained_handle_key_resolves_without_active_key_fallback(self) -> None:
        source, keyring, _ids, component = self._fixture()
        row = session_row(
            keyring,
            raw_handle=OLD_KEY_HANDLE,
            handle_key_id=OLD_HANDLE_KEY,
            csrf_key_id=ACTIVE_CSRF_KEY,
        )
        seed_row(source, row)
        actor = _auth_outcome(component, OLD_KEY_HANDLE)
        self.assertIsInstance(actor, AuthenticatedHttpActor)
        install_keys = [
            params[-2]
            for statement, params in source.executions
            if "install_session_authenticate_context_v2" in statement
        ]
        self.assertEqual(install_keys, [OLD_HANDLE_KEY, ACTIVE_HANDLE_KEY])

    def test_invalid_unknown_and_missing_key_fail_before_authority(self) -> None:
        source, keyring, _ids, component = self._fixture()
        self.assertIsNone(_auth_outcome(component, None))
        for raw in ("short", "!" * 43):
            with self.subTest(raw=raw):
                self.assertEqual(_auth_outcome(component, raw), "AUTHENTICATION_REQUIRED")
        self.assertEqual(source.checkout_count, 0)

        self.assertEqual(
            _auth_outcome(component, UNKNOWN_HANDLE),
            "AUTHENTICATION_REQUIRED",
        )
        self.assertEqual(source.checkout_count, 1)

        source2, keyring2, _ids2, component2 = self._fixture()
        del keyring2.material[OLD_HANDLE_KEY]
        self.assertEqual(
            _auth_outcome(component2, ACTIVE_HANDLE),
            "SERVICE_UNAVAILABLE",
        )
        self.assertEqual(source2.checkout_count, 0)

    def test_terminal_deadline_and_authority_matrix_is_closed(self) -> None:
        cases = (
            ({"session_status": "EXPIRED"}, "SESSION_EXPIRED"),
            ({"family_status": "REVOKED"}, "SESSION_EXPIRED"),
            ({"user_status": "SUSPENDED"}, "SESSION_EXPIRED"),
            ({"generation": 1, "current_generation": 2}, "SESSION_EXPIRED"),
            ({"idle_expires_at": NOW}, "SESSION_EXPIRED"),
            ({"absolute_expires_at": NOW}, "SESSION_EXPIRED"),
            ({"session_status": "UNKNOWN"}, "SERVICE_UNAVAILABLE"),
            ({"user_status": "UNKNOWN"}, "SERVICE_UNAVAILABLE"),
        )
        for changes, expected in cases:
            with self.subTest(changes=changes):
                source, keyring, _ids, component = self._fixture()
                seed_row(source, session_row(keyring, **changes))
                self.assertEqual(_auth_outcome(component, ACTIVE_HANDLE), expected)

    def test_revoked_current_generation_is_unauthenticated_without_replay_write(self) -> None:
        for family_status in ("ACTIVE", "REVOKED"):
            with self.subTest(family_status=family_status):
                source, keyring, ids, component = self._fixture()
                row = session_row(keyring)
                seed_row(source, row)
                actor = _auth_outcome(component, ACTIVE_HANDLE)
                self.assertIsInstance(actor, AuthenticatedHttpActor)
                source.rows_by_digest.clear()
                seed_row(source, session_row(
                    keyring, session_status="REVOKED", family_status=family_status,
                ))
                self.assertEqual(_auth_outcome(component, ACTIVE_HANDLE), "AUTHENTICATION_REQUIRED")
                self.assertEqual(_csrf_outcome(
                    component, raw_handle=ACTIVE_HANDLE, raw_token=row["csrf_token"], actor=actor,
                ), "AUTHENTICATION_REQUIRED")
                self.assertEqual(source.replay_calls, 0)
                self.assertEqual(ids.counter, 0)

    def test_revoked_generation_or_family_corruption_is_unavailable(self) -> None:
        for changes in ({"generation": 3}, {"family_status": "UNKNOWN"}):
            with self.subTest(changes=changes):
                source, keyring, ids, component = self._fixture()
                seed_row(source, session_row(keyring, session_status="REVOKED", **changes))
                self.assertEqual(_auth_outcome(component, ACTIVE_HANDLE), "SERVICE_UNAVAILABLE")
                self.assertEqual(source.replay_calls, 0)
                self.assertEqual(ids.counter, 0)

    def test_revoked_handle_runs_closed_replay_program_then_requires_auth(self) -> None:
        source, keyring, ids, component = self._fixture()
        seed_row(source, session_row(keyring, session_status="REVOKED", generation=1))
        self.assertEqual(
            _auth_outcome(component, ACTIVE_HANDLE),
            "AUTHENTICATION_REQUIRED",
        )
        self.assertEqual(ids.counter, 3)
        self.assertEqual(source.replay_calls, 1)
        self.assertEqual(source.checkout_count, 2)
        self.assertTrue(
            any(
                "revoke_replayed_session_family_v1" in statement
                for statement, _params in source.executions
            )
        )
        self.assertNotIn(ACTIVE_HANDLE, repr(source.executions))

    def test_revoked_handle_accepts_production_style_uuid_generated_ids(self) -> None:
        source = ScriptedSessionConnectionSource()
        keyring = FixedSessionSecurityKeyring()
        ids = _ProductionStyleUuidIdSource()
        component = PsycopgIamSessionSecurity(
            connections=source,
            keyring=keyring,
            id_source=ids,
        )
        seed_row(source, session_row(keyring, session_status="REVOKED", generation=1))

        self.assertEqual(
            _auth_outcome(component, ACTIVE_HANDLE),
            "AUTHENTICATION_REQUIRED",
        )
        self.assertEqual(
            ids.purposes,
            [
                "session-replay-security-event",
                "session-replay-audit-event",
                "session-replay-outbox-event",
            ],
        )
        replay_params = next(
            params
            for statement, params in source.executions
            if "revoke_replayed_session_family_v1" in statement
        )
        self.assertEqual(
            replay_params[:3],
            tuple(str(UUID(int=value)) for value in (1, 2, 3)),
        )

    def test_replay_commit_ack_loss_discards_and_reuses_exact_ids(self) -> None:
        source, keyring, ids, component = self._fixture()
        source.lose_replay_commit_ack = True
        seed_row(source, session_row(keyring, session_status="REVOKED", generation=1))
        self.assertEqual(
            _auth_outcome(component, ACTIVE_HANDLE),
            "AUTHENTICATION_REQUIRED",
        )
        self.assertEqual(ids.counter, 3)
        self.assertEqual(source.commit_ack_losses, 1)
        self.assertEqual(source.replay_calls, 2)
        self.assertEqual(len(source.discarded), 1)
        calls = [
            params
            for statement, params in source.executions
            if "revoke_replayed_session_family_v1" in statement
        ]
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[0], calls[1])

    def test_duplicate_rows_or_multiple_retained_key_matches_are_corrupt(self) -> None:
        source, keyring, _ids, component = self._fixture()
        row = session_row(keyring)
        seed_row(source, row)
        seed_row(source, row)
        self.assertEqual(
            _auth_outcome(component, ACTIVE_HANDLE),
            "SERVICE_UNAVAILABLE",
        )
        self.assertEqual(len(source.discarded), 1)

        source2, keyring2, _ids2, component2 = self._fixture()
        active = session_row(keyring2)
        old = session_row(
            keyring2,
            raw_handle=ACTIVE_HANDLE,
            handle_key_id=OLD_HANDLE_KEY,
            session_id="55555555-5555-4555-8555-555555555555",
        )
        seed_row(source2, active)
        seed_row(source2, old)
        self.assertEqual(
            _auth_outcome(component2, ACTIVE_HANDLE),
            "SERVICE_UNAVAILABLE",
        )

    def test_csrf_re_resolves_and_checks_actor_derived_and_request_digests(self) -> None:
        source, keyring, _ids, component = self._fixture()
        row = session_row(keyring)
        seed_row(source, row)
        actor = _auth_outcome(component, ACTIVE_HANDLE)
        self.assertIsInstance(actor, AuthenticatedHttpActor)
        self.assertIsNone(
            _csrf_outcome(
                component,
                raw_handle=ACTIVE_HANDLE,
                raw_token=row["csrf_token"],
                actor=actor,
            )
        )
        self.assertEqual(source.checkout_count, 2)
        self.assertEqual(
            _csrf_outcome(
                component,
                raw_handle=ACTIVE_HANDLE,
                raw_token="Z" * 43,
                actor=actor,
            ),
            "INVALID_REQUEST",
        )
        forged = replace(actor, session_id="66666666-6666-4666-8666-666666666666")
        self.assertEqual(
            _csrf_outcome(
                component,
                raw_handle=ACTIVE_HANDLE,
                raw_token=row["csrf_token"],
                actor=forged,
            ),
            "SERVICE_UNAVAILABLE",
        )

    def test_explicit_product_operation_can_reuse_the_exact_session_csrf_proof(self) -> None:
        source = ScriptedSessionConnectionSource()
        keyring = FixedSessionSecurityKeyring()
        component = PsycopgIamSessionSecurity(
            connections=source,
            keyring=keyring,
            id_source=FixedSessionSecurityIdSource(),
            settings=SessionSecuritySettings(
                additional_csrf_operation_ids=("internalPilotEditorWrite",),
            ),
        )
        row = session_row(keyring)
        seed_row(source, row)
        actor = _auth_outcome(component, ACTIVE_HANDLE)
        self.assertIsInstance(actor, AuthenticatedHttpActor)
        self.assertIsNone(
            _csrf_outcome(
                component,
                raw_handle=ACTIVE_HANDLE,
                raw_token=row["csrf_token"],
                actor=actor,
                operation_id="internalPilotEditorWrite",
            )
        )

        default_source = ScriptedSessionConnectionSource()
        default_keyring = FixedSessionSecurityKeyring()
        default_component = PsycopgIamSessionSecurity(
            connections=default_source,
            keyring=default_keyring,
            id_source=FixedSessionSecurityIdSource(),
        )
        default_row = session_row(default_keyring)
        seed_row(default_source, default_row)
        default_actor = _auth_outcome(default_component, ACTIVE_HANDLE)
        self.assertIsInstance(default_actor, AuthenticatedHttpActor)
        self.assertEqual(
            _csrf_outcome(
                default_component,
                raw_handle=ACTIVE_HANDLE,
                raw_token=default_row["csrf_token"],
                actor=default_actor,
                operation_id="internalPilotEditorWrite",
            ),
            "SERVICE_UNAVAILABLE",
        )
        self.assertEqual(
            _csrf_outcome(
                component,
                raw_handle=ACTIVE_HANDLE,
                raw_token=row["csrf_token"],
                actor=actor,
                operation_id="getMe",
            ),
            "SERVICE_UNAVAILABLE",
        )

    def test_corrupt_persisted_csrf_or_missing_exact_key_is_unavailable(self) -> None:
        source, keyring, _ids, component = self._fixture()
        row = session_row(keyring, csrf_digest_override=b"x" * 32)
        seed_row(source, row)
        actor = _auth_outcome(component, ACTIVE_HANDLE)
        self.assertIsInstance(actor, AuthenticatedHttpActor)
        self.assertEqual(
            _csrf_outcome(
                component,
                raw_handle=ACTIVE_HANDLE,
                raw_token="Z" * 43,
                actor=actor,
            ),
            "SERVICE_UNAVAILABLE",
        )

        source2, keyring2, _ids2, component2 = self._fixture()
        row2 = session_row(keyring2)
        seed_row(source2, row2)
        actor2 = _auth_outcome(component2, ACTIVE_HANDLE)
        del keyring2.material[ACTIVE_CSRF_KEY]
        self.assertEqual(
            _csrf_outcome(
                component2,
                raw_handle=ACTIVE_HANDLE,
                raw_token=row2["csrf_token"],
                actor=actor2,
            ),
            "SERVICE_UNAVAILABLE",
        )

    def test_readiness_identity_reset_close_and_settings_contract(self) -> None:
        source, _keyring, _ids, component = self._fixture()
        try:
            readiness = component.check_readiness(timeout_ms=100)
        except RuntimeError as error:
            readiness = str(error)
        self.assertIsNone(readiness)
        self.assertEqual(source.checkout_count, 1)
        self.assertEqual(len(source.released), 1)
        reset_statements = [statement for statement, _ in source.executions]
        readiness_statements = [
            statement
            for statement in reset_statements
            if "iam.session_security_readiness_v2" in statement
        ]
        self.assertEqual(len(readiness_statements), 1)
        self.assertEqual(
            readiness_statements[0].count(
                "uuid,uuid,uuid,uuid,uuid,uuid)"
            ),
            2,
        )
        self.assertNotIn(
            "uuid,uuid,uuid,uuid,uuid,uuid) "
            "'uuid,uuid,uuid,uuid,uuid,uuid)'",
            readiness_statements[0],
        )
        self.assertIn("RESET ROLE", reset_statements)
        self.assertIn("RESET ALL", reset_statements)
        self.assertEqual(reset_statements.count("SET TIME ZONE 'UTC'"), 2)
        self.assertEqual(reset_statements.count("SET LOCAL TIME ZONE 'UTC'"), 1)
        self.assertIn("DISCARD TEMP", reset_statements)
        component.close()
        self.assertEqual(
            _auth_outcome(component, ACTIVE_HANDLE),
            "SERVICE_UNAVAILABLE",
        )

        settings = SessionSecuritySettings()
        with self.assertRaises(FrozenInstanceError):
            settings.runtime_role = "schema_owner"  # type: ignore[misc]
        self.assertNotIn(ACTIVE_HANDLE, repr(component))
        self.assertNotIn("csrf", repr(component).lower())

    def test_non_utc_transaction_fact_fails_closed(self) -> None:
        source, keyring, _ids, component = self._fixture()
        source.timezone_name = "Asia/Shanghai"
        seed_row(source, session_row(keyring))

        self.assertEqual(
            _auth_outcome(component, ACTIVE_HANDLE),
            "SERVICE_UNAVAILABLE",
        )
        self.assertEqual(len(source.discarded), 1)
        self.assertIn(
            "SET LOCAL TIME ZONE 'UTC'",
            [statement for statement, _parameters in source.executions],
        )

        readiness_source, _keyring, _ids, readiness_component = self._fixture()
        readiness_source.timezone_name = "Etc/UTC"
        with self.assertRaisesRegex(
            RuntimeError,
            "IAM_HTTP_SESSION_SECURITY_UNAVAILABLE",
        ):
            readiness_component.check_readiness(timeout_ms=100)
        self.assertEqual(len(readiness_source.discarded), 1)


if __name__ == "__main__":
    unittest.main()
