"""Second semantic RED for authoritative Issue security and recovery facts."""

from __future__ import annotations

from dataclasses import replace
from datetime import timedelta
import json
from pathlib import Path
from typing import Any, Callable, Mapping
import unittest

import yaml

from desire_platform.identity_access.domain.errors import IamError
from desire_platform.identity_access.domain.invitations import TargetRole
from desire_platform.identity_access.ports.safety_hold import HoldDecision
from tests.application.test_accept_access_invitation_security import (
    _ContractAssertion,
)
from tests.support.iam_issue_security_builders import (
    ACTIVE_TOKEN_KEY_ID,
    MEMBERSHIP_ID,
    ROLE_GRANT_ID,
    ROTATED_TOKEN_KEY_ID,
    SESSION_FAMILY_ID,
    SESSION_ID,
    TOKEN_FORMAT_VERSION,
    USER_ID,
    expected_user_lock_order,
    invitation_row,
    receipt_row,
    replace_invitation,
    secure_system_issue_fixture,
    secure_user_issue_fixture,
    update_row,
    valid_system_operation_credential,
    with_transport_auth,
)
from tests.support.iam_policy_issue_builders import UTC_NOW


PLATFORM_ROOT = Path(__file__).resolve().parents[2]
EVENT_SCHEMA_PATH = PLATFORM_ROOT / "contracts" / "events" / "iam-v1.schema.json"
OPENAPI_PATH = PLATFORM_ROOT / "contracts" / "api" / "iam-v1.openapi.yaml"


class IssueAccessInvitationSecuritySemanticRedTest(unittest.TestCase):
    """Freeze the remaining Issue authority, hold, and replay protocol."""

    def test_user_happy_path_locks_every_authority_source_in_fixed_order(
        self,
    ) -> None:
        fixture = secure_user_issue_fixture()
        result, code = self._invoke(fixture)
        snapshot = fixture.store.snapshot()
        invitation = next(iter(snapshot.get("invitations", {}).values()), None)
        audit = next(iter(snapshot.get("audit_events", {}).values()), {})

        self.assertEqual(
            {
                "code": code,
                "replayed": getattr(result, "replayed", None),
                "locks": fixture.uow_factory.lock_calls,
                "issuer_kind": getattr(invitation, "issuer_kind", None),
                "issuer_id": getattr(invitation, "issuer_id", None),
                "audit_auth_strength": audit.get("auth_strength_code"),
                "commits": fixture.uow_factory.commit_count,
            },
            {
                "code": None,
                "replayed": False,
                "locks": expected_user_lock_order(fixture),
                "issuer_kind": "USER",
                "issuer_id": USER_ID,
                "audit_auth_strength": "urn:desire:acr:mfa",
                "commits": 1,
            },
        )

    def test_user_authority_comes_from_persisted_session_not_context_copy(
        self,
    ) -> None:
        fixture = secure_user_issue_fixture()
        fixture.actor = with_transport_auth(
            fixture.actor,
            auth_time=UTC_NOW - timedelta(days=1),
            acr_code="urn:transport:evidence-only",
            amr_codes=("transport-only",),
        )
        result, code = self._invoke(fixture)
        audit = next(
            iter(fixture.store.snapshot().get("audit_events", {}).values()),
            {},
        )
        self.assertEqual(
            {
                "code": code,
                "replayed": getattr(result, "replayed", None),
                "hold_calls": len(fixture.hold.calls),
                "audit_auth_strength": audit.get("auth_strength_code"),
            },
            {
                "code": None,
                "replayed": False,
                "hold_calls": 1,
                "audit_auth_strength": "urn:desire:acr:mfa",
            },
        )

    def test_invalid_persisted_user_session_or_org_authority_is_zero_hold_write(
        self,
    ) -> None:
        cases: tuple[
            tuple[str, Callable[[Any], None], str], ...
        ] = (
            (
                "missing-user",
                lambda fixture: fixture.store._tables["users"].pop(USER_ID),
                "AUTHENTICATION_REQUIRED",
            ),
            (
                "suspended-user",
                lambda fixture: update_row(
                    fixture,
                    "users",
                    USER_ID,
                    status="SUSPENDED",
                ),
                "AUTHENTICATION_REQUIRED",
            ),
            (
                "missing-family",
                lambda fixture: fixture.store._tables[
                    "session_families"
                ].pop(SESSION_FAMILY_ID),
                "AUTHENTICATION_REQUIRED",
            ),
            (
                "revoked-family",
                lambda fixture: update_row(
                    fixture,
                    "session_families",
                    SESSION_FAMILY_ID,
                    status="REVOKED",
                    revoked_at=UTC_NOW,
                ),
                "SESSION_EXPIRED",
            ),
            (
                "missing-session",
                lambda fixture: fixture.store._tables["sessions"].pop(
                    SESSION_ID
                ),
                "AUTHENTICATION_REQUIRED",
            ),
            (
                "other-user-session",
                lambda fixture: update_row(
                    fixture,
                    "sessions",
                    SESSION_ID,
                    user_id="user_other_issuer_0002",
                ),
                "AUTHENTICATION_REQUIRED",
            ),
            (
                "revoked-session",
                lambda fixture: update_row(
                    fixture,
                    "sessions",
                    SESSION_ID,
                    status="REVOKED",
                ),
                "SESSION_EXPIRED",
            ),
            (
                "expired-session",
                lambda fixture: update_row(
                    fixture,
                    "sessions",
                    SESSION_ID,
                    idle_expires_at=UTC_NOW,
                ),
                "SESSION_EXPIRED",
            ),
            (
                "non-mfa-session",
                lambda fixture: update_row(
                    fixture,
                    "sessions",
                    SESSION_ID,
                    acr_code="urn:desire:acr:password",
                    amr_codes=("pwd",),
                ),
                "MFA_STEP_UP_REQUIRED",
            ),
            (
                "stale-session-auth",
                lambda fixture: update_row(
                    fixture,
                    "sessions",
                    SESSION_ID,
                    auth_time=UTC_NOW - timedelta(minutes=10),
                ),
                "MFA_STEP_UP_REQUIRED",
            ),
            (
                "suspended-membership",
                lambda fixture: update_row(
                    fixture,
                    "memberships",
                    MEMBERSHIP_ID,
                    status="SUSPENDED",
                ),
                "RESOURCE_NOT_FOUND",
            ),
            (
                "revoked-admin-grant",
                lambda fixture: update_row(
                    fixture,
                    "membership_role_grants",
                    ROLE_GRANT_ID,
                    revoked_at=UTC_NOW,
                ),
                "RESOURCE_NOT_FOUND",
            ),
        )
        for name, mutate, expected_code in cases:
            with self.subTest(case=name):
                fixture = secure_user_issue_fixture()
                mutate(fixture)
                before = fixture.store.snapshot()
                _result, code = self._invoke(fixture)
                self.assertEqual(
                    {
                        "code": code,
                        "unchanged": fixture.store.snapshot() == before,
                        "hold_calls": len(fixture.hold.calls),
                        "uow_begins": fixture.uow_factory.begin_count,
                        "writes": fixture.uow_factory.write_calls,
                        "commits": fixture.uow_factory.commit_count,
                    },
                    {
                        "code": expected_code,
                        "unchanged": True,
                        "hold_calls": 0,
                        "uow_begins": 0,
                        "writes": [],
                        "commits": 0,
                    },
                )

    def test_system_issuer_requires_same_active_allowlisted_operation_credential(
        self,
    ) -> None:
        valid = valid_system_operation_credential()
        cases = (
            ("missing", None),
            ("wrong-system", replace(valid, system_id="system_other_0002")),
            ("wrong-operation", replace(valid, operation="PublishPolicyBundle")),
            (
                "wrong-purpose",
                replace(valid, allowed_purposes=("ORGANIZATION_MEMBERSHIP",)),
            ),
            ("revoked", replace(valid, status="REVOKED")),
            (
                "not-yet-valid",
                replace(valid, valid_from=UTC_NOW + timedelta(seconds=1)),
            ),
            ("expired", replace(valid, valid_until=UTC_NOW)),
        )
        for name, credential in cases:
            with self.subTest(case=name):
                fixture = secure_system_issue_fixture(credential=credential)
                before = fixture.store.snapshot()
                _result, code = self._invoke(fixture)
                self.assertEqual(
                    {
                        "code": code,
                        "unchanged": fixture.store.snapshot() == before,
                        "hold_calls": len(fixture.hold.calls),
                        "uow_begins": fixture.uow_factory.begin_count,
                        "writes": fixture.uow_factory.write_calls,
                    },
                    {
                        "code": "AUTHENTICATION_REQUIRED",
                        "unchanged": True,
                        "hold_calls": 0,
                        "uow_begins": 0,
                        "writes": [],
                    },
                )

    def test_hold_allow_binds_preallocated_final_invitation_before_any_uow(
        self,
    ) -> None:
        fixture = secure_user_issue_fixture()
        result, code = self._invoke(fixture)
        call = fixture.hold.calls[0] if fixture.hold.calls else None
        invitation = next(
            iter(fixture.store.snapshot().get("invitations", {}).values()),
            None,
        )
        self.assertEqual(
            {
                "code": code,
                "target_type": getattr(call, "target_type", None),
                "target_id": getattr(call, "target_id", None),
                "target_version": getattr(call, "target_version", None),
                "organization_id": getattr(call, "organization_id", None),
                "persisted_id": getattr(invitation, "invitation_id", None),
                "timeline_prefix": fixture.timeline[:3],
                "replayed": getattr(result, "replayed", None),
            },
            {
                "code": None,
                "target_type": "AccessInvitation",
                "target_id": "access_invitation_issue_001",
                "target_version": 1,
                "organization_id": fixture.command.organization_id,
                "persisted_id": "access_invitation_issue_001",
                "timeline_prefix": [
                    "id:access_invitation",
                    "hold.evaluate",
                    "uow.begin",
                ],
                "replayed": False,
            },
        )

    def test_negative_or_invalid_hold_is_zero_write_but_still_uses_final_id(
        self,
    ) -> None:
        cases = (
            (
                "block",
                lambda: secure_user_issue_fixture(
                    hold_decision=HoldDecision.BLOCK
                ),
                "SAFETY_HOLD_BLOCKED",
            ),
            (
                "unavailable-decision",
                lambda: secure_user_issue_fixture(
                    hold_decision=HoldDecision.UNAVAILABLE
                ),
                "SAFETY_DECISION_UNAVAILABLE",
            ),
            (
                "provider-unavailable",
                lambda: secure_user_issue_fixture(
                    hold_unavailable_error=True
                ),
                "SAFETY_DECISION_UNAVAILABLE",
            ),
            (
                "wrong-target",
                lambda: secure_user_issue_fixture(
                    hold_overrides={
                        "target_id": "access_invitation_other_0002"
                    }
                ),
                "SAFETY_DECISION_UNAVAILABLE",
            ),
            (
                "expired-result",
                lambda: secure_user_issue_fixture(
                    hold_overrides={"valid_until": UTC_NOW}
                ),
                "SAFETY_DECISION_UNAVAILABLE",
            ),
        )
        for name, factory, expected_code in cases:
            with self.subTest(case=name):
                fixture = factory()
                before = fixture.store.snapshot()
                _result, code = self._invoke(fixture)
                call = fixture.hold.calls[0] if fixture.hold.calls else None
                self.assertEqual(
                    {
                        "code": code,
                        "target_type": getattr(call, "target_type", None),
                        "target_id": getattr(call, "target_id", None),
                        "target_version": getattr(call, "target_version", None),
                        "timeline": fixture.timeline,
                        "unchanged": fixture.store.snapshot() == before,
                        "writes": fixture.uow_factory.write_calls,
                        "commits": fixture.uow_factory.commit_count,
                    },
                    {
                        "code": expected_code,
                        "target_type": "AccessInvitation",
                        "target_id": "access_invitation_issue_001",
                        "target_version": 1,
                        "timeline": [
                            "id:access_invitation",
                            "hold.evaluate",
                        ],
                        "unchanged": True,
                        "writes": [],
                        "commits": 0,
                    },
                )

    def test_receipt_replay_uses_exact_retained_token_key_and_format(self) -> None:
        fixture = secure_user_issue_fixture()
        first, first_code = self._invoke(fixture)
        receipt = receipt_row(fixture)
        metadata = receipt.get("reconstruction_metadata", {})
        hold_count = len(fixture.hold.calls)
        write_count = len(fixture.uow_factory.write_calls)
        before = fixture.store.snapshot()
        first_codec_call = (
            fixture.token_codec.calls[0]
            if fixture.token_codec.calls
            else {}
        )

        fixture.token_codec.rotate()
        replay, replay_code = self._invoke(fixture)
        replay_codec_call = (
            fixture.token_codec.calls[-1]
            if len(fixture.token_codec.calls) > 1
            else {}
        )

        self.assertEqual(
            {
                "first_code": first_code,
                "first_explicit_key": first_codec_call.get("explicit_key_id"),
                "first_explicit_format": first_codec_call.get(
                    "explicit_format_version"
                ),
                "metadata": metadata,
                "replay_code": replay_code,
                "replayed": getattr(replay, "replayed", None),
                "same_token": (
                    getattr(replay, "access_invitation_token", None)
                    == getattr(first, "access_invitation_token", None)
                ),
                "replay_key": replay_codec_call.get("token_key_id"),
                "replay_format": replay_codec_call.get(
                    "token_format_version"
                ),
                "codec_calls": len(fixture.token_codec.calls),
                "unchanged": fixture.store.snapshot() == before,
                "new_hold_calls": len(fixture.hold.calls) - hold_count,
                "new_writes": len(fixture.uow_factory.write_calls)
                - write_count,
            },
            {
                "first_code": None,
                "first_explicit_key": True,
                "first_explicit_format": True,
                "metadata": {
                    "kind": "AccessInvitationCapability",
                    "version": 1,
                    "invitation_id": "access_invitation_issue_001",
                    "invitation_version": 1,
                    "token_format_version": TOKEN_FORMAT_VERSION,
                    "token_key_id": ACTIVE_TOKEN_KEY_ID,
                },
                "replay_code": None,
                "replayed": True,
                "same_token": True,
                "replay_key": ACTIVE_TOKEN_KEY_ID,
                "replay_format": TOKEN_FORMAT_VERSION,
                "codec_calls": 2,
                "unchanged": True,
                "new_hold_calls": 0,
                "new_writes": 0,
            },
        )

    def test_missing_retained_token_key_is_stable_service_unavailable(self) -> None:
        fixture = secure_user_issue_fixture()
        _first, first_code = self._invoke(fixture)
        fixture.token_codec.drop_key(ACTIVE_TOKEN_KEY_ID)
        hold_count = len(fixture.hold.calls)
        write_count = len(fixture.uow_factory.write_calls)
        before = fixture.store.snapshot()
        _replay, replay_code = self._invoke(fixture)
        self.assertEqual(
            {
                "first_code": first_code,
                "replay_code": replay_code,
                "unchanged": fixture.store.snapshot() == before,
                "new_hold_calls": len(fixture.hold.calls) - hold_count,
                "new_writes": len(fixture.uow_factory.write_calls)
                - write_count,
            },
            {
                "first_code": None,
                "replay_code": "SERVICE_UNAVAILABLE",
                "unchanged": True,
                "new_hold_calls": 0,
                "new_writes": 0,
            },
        )

    def test_receipt_and_creation_binding_swaps_all_fail_closed(self) -> None:
        cases: tuple[tuple[str, Callable[[Any], None]], ...] = (
            (
                "receipt-target",
                lambda fixture: receipt_row(fixture).update(
                    {
                        "target_type": "AccessInvitation",
                        "target_id": "access_invitation_other_0002",
                        "target_version": 1,
                    }
                ),
            ),
            (
                "metadata-kind",
                lambda fixture: receipt_row(fixture)[
                    "reconstruction_metadata"
                ].update({"kind": "WrongCapabilityKind"}),
            ),
            (
                "metadata-version",
                lambda fixture: receipt_row(fixture)[
                    "reconstruction_metadata"
                ].update({"invitation_version": 2}),
            ),
            (
                "safe-dto-role",
                lambda fixture: receipt_row(fixture)["response_body"][
                    "invitation"
                ].update({"target_role": "ORG_ADMIN"}),
            ),
            (
                "safe-dto-expiry",
                lambda fixture: receipt_row(fixture)["response_body"][
                    "invitation"
                ].update({"expires_at": "2026-08-16T09:00:00Z"}),
            ),
            (
                "safe-dto-version",
                lambda fixture: receipt_row(fixture)["response_body"][
                    "invitation"
                ].update({"aggregate_version": 2, "entity_tag": '"v2"'}),
            ),
            (
                "invitation-issuer",
                lambda fixture: replace_invitation(
                    fixture,
                    issuer_id="user_other_issuer_0002",
                ),
            ),
            (
                "invitation-organization",
                lambda fixture: replace_invitation(
                    fixture,
                    organization_id="organization_other_target_002",
                ),
            ),
            (
                "invitation-role",
                lambda fixture: replace_invitation(
                    fixture,
                    target_role=TargetRole.ORG_ADMIN,
                ),
            ),
            (
                "invitation-contact",
                lambda fixture: replace_invitation(
                    fixture,
                    recipient_contact_id="contact_point_issue_other_002",
                ),
            ),
            (
                "invitation-expiry",
                lambda fixture: replace_invitation(
                    fixture,
                    expires_at=fixture.command.expires_at + timedelta(days=1),
                ),
            ),
            (
                "invitation-token-key",
                lambda fixture: replace_invitation(
                    fixture,
                    token_key_id=ROTATED_TOKEN_KEY_ID,
                ),
            ),
            (
                "contact-binding",
                lambda fixture: self._swap_contact_binding(fixture),
            ),
        )
        for name, mutate in cases:
            with self.subTest(case=name):
                fixture = secure_user_issue_fixture()
                _first, first_code = self._invoke(fixture)
                mutate(fixture)
                before = fixture.store.snapshot()
                hold_count = len(fixture.hold.calls)
                write_count = len(fixture.uow_factory.write_calls)
                commit_count = fixture.uow_factory.commit_count
                _replay, replay_code = self._invoke(fixture)
                self.assertEqual(
                    {
                        "first_code": first_code,
                        "replay_code": replay_code,
                        "unchanged": fixture.store.snapshot() == before,
                        "new_hold_calls": len(fixture.hold.calls)
                        - hold_count,
                        "new_writes": len(fixture.uow_factory.write_calls)
                        - write_count,
                        "new_commits": fixture.uow_factory.commit_count
                        - commit_count,
                    },
                    {
                        "first_code": None,
                        "replay_code": "SERVICE_UNAVAILABLE",
                        "unchanged": True,
                        "new_hold_calls": 0,
                        "new_writes": 0,
                        "new_commits": 0,
                    },
                )

    def test_issue_dto_event_and_recursive_secret_sentinels_are_closed(self) -> None:
        fixture = secure_user_issue_fixture()
        result, code = self._invoke(fixture)
        snapshot = fixture.store.snapshot()
        receipt = next(iter(snapshot["command_receipts"].values()))
        audit = next(iter(snapshot["audit_events"].values()))
        event = next(iter(snapshot["outbox_events"].values()))
        contact = next(iter(snapshot["contact_points"].values()))
        invitation = next(iter(snapshot["invitations"].values()))

        with OPENAPI_PATH.open("r", encoding="utf-8") as stream:
            openapi = yaml.safe_load(stream)
        with EVENT_SCHEMA_PATH.open("r", encoding="utf-8") as stream:
            events = json.load(stream)
        validator = _ContractAssertion(self, openapi)
        validator.assert_valid(
            result.invitation,
            openapi["components"]["schemas"]["AccessInvitationAdminDto"],
            "issue.invitation",
        )
        validator.assert_valid(
            receipt["response_body"]["invitation"],
            openapi["components"]["schemas"]["AccessInvitationAdminDto"],
            "receipt.invitation",
        )
        _ContractAssertion(self, events).assert_valid(
            event,
            {"$ref": "#/$defs/OrganizationAccessInvitationIssuedEvent"},
            "issue.event",
        )

        secret_values = (
            fixture.command.recipient.value,
            fixture.command.recipient.value.strip().casefold(),
            fixture.command.idempotency_key,
            result.access_invitation_token,
            result.join_fragment_url,
            invitation.nonce,
            contact["locator_ciphertext"],
            contact["binding_digest"],
        )
        for artifact_name, artifact in (
            ("dto", result.invitation),
            ("receipt", receipt),
            ("audit", audit),
            ("event", event),
        ):
            rendered = repr(artifact)
            for secret in secret_values:
                with self.subTest(artifact=artifact_name, secret=secret[:12]):
                    self.assertNotIn(secret, rendered)

        forbidden_event_keys = {
            key
            for key in self._recursive_keys(event)
            if any(
                fragment in key.casefold()
                for fragment in (
                    "recipient",
                    "contact",
                    "token",
                    "nonce",
                    "digest",
                    "issuer",
                    "session",
                    "mfa",
                    "receipt",
                    "mask",
                )
            )
        }
        self.assertEqual(forbidden_event_keys, set())
        self.assertNotIn(
            invitation.masked_recipient_label,
            repr(event),
        )
        self.assertEqual(code, None)

    @staticmethod
    def _invoke(fixture):
        try:
            return (
                fixture.handler.handle(
                    actor=fixture.actor,
                    command=fixture.command,
                ),
                None,
            )
        except IamError as error:
            return None, error.code
        except Exception as error:  # semantic RED, never a unittest error
            return None, "UNMAPPED_%s" % type(error).__name__

    @staticmethod
    def _swap_contact_binding(fixture) -> None:
        invitation = invitation_row(fixture)
        update_row(
            fixture,
            "contact_points",
            invitation.recipient_contact_id,
            binding_digest="f" * 64,
        )

    @classmethod
    def _recursive_keys(cls, value: Any) -> set[str]:
        if isinstance(value, Mapping):
            result = {str(key) for key in value}
            for child in value.values():
                result.update(cls._recursive_keys(child))
            return result
        if isinstance(value, (list, tuple)):
            result: set[str] = set()
            for child in value:
                result.update(cls._recursive_keys(child))
            return result
        return set()


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
