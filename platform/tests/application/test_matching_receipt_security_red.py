"""Second-round receipt, replay, audit and privacy security gates."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
import json
import unittest

from desire_platform.matching.application import (
    MatchingApplicationError,
    RespondInvitationHandler,
)
from desire_platform.matching.ports import MatchingAuthorityUnavailableError
from tests.support.matching_builders import (
    build_application_harness,
    command_for,
    creator_actor,
)


_RECEIPT_KEYS = {
    "command_version",
    "canonicalization_version",
    "identity_key_id",
    "payload_hash_key_id",
    "principal_kind",
    "principal_id",
    "organization_id",
    "operation",
    "identity",
    "payload_hash",
    "status",
    "safe_response",
    "recovery_facts",
}


class _UnavailableBusinessAuthority:
    def authorize(self, **query):
        raise MatchingAuthorityUnavailableError("business authority unavailable")


def _only_receipt(harness):
    receipts = harness.uow_factory.store.snapshot().get("receipts", {})
    if len(receipts) != 1:
        raise AssertionError(f"expected one receipt, got {len(receipts)}")
    return next(iter(receipts.items()))


def _replay_code(harness, command, *, call_actor=None):
    try:
        result = RespondInvitationHandler(**harness.dependencies).handle(
            actor=call_actor or creator_actor(), command=command
        )
    except MatchingApplicationError as error:
        return error.code, None
    return None, result


class MatchingReceiptSecurityRedTests(unittest.TestCase):
    def _completed(self):
        command = command_for(RespondInvitationHandler)
        harness = build_application_harness(RespondInvitationHandler, command)
        result = RespondInvitationHandler(**harness.dependencies).handle(
            actor=creator_actor(), command=command
        )
        self.assertFalse(result.replayed)
        return harness, command

    def test_receipt_persists_closed_versioned_key_metadata(self) -> None:
        harness, _ = self._completed()
        _, receipt = _only_receipt(harness)
        self.assertEqual(set(receipt), _RECEIPT_KEYS)
        self.assertEqual(
            {
                "command_version": receipt["command_version"],
                "canonicalization_version": receipt["canonicalization_version"],
                "identity_key_id": receipt["identity_key_id"],
                "payload_hash_key_id": receipt["payload_hash_key_id"],
                "principal_kind": receipt["principal_kind"],
            },
            {
                "command_version": 1,
                "canonicalization_version": "matching-command-json-v1",
                "identity_key_id": "matching-receipt-identity-v1",
                "payload_hash_key_id": "matching-receipt-payload-v1",
                "principal_kind": "USER",
            },
        )
        serialized = repr(receipt).lower()
        self.assertNotIn("raw-key", serialized)
        self.assertNotIn("session_secret", serialized)

    def test_payload_hmac_surface_binds_transport_target_if_match_and_schema(self) -> None:
        harness, _ = self._completed()
        keyring = harness.dependencies["receipt_keyring"]
        self.assertEqual(len(keyring.calls), 2)
        payload_surface = json.loads(keyring.calls[1][1])
        self.assertEqual(
            set(payload_surface),
            {
                "method",
                "canonical_path",
                "organization_id",
                "target",
                "if_match",
                "command_schema_version",
                "body",
            },
        )
        self.assertEqual(
            {
                "method": payload_surface["method"],
                "canonical_path": payload_surface["canonical_path"],
                "target": payload_surface["target"],
                "if_match": payload_surface["if_match"],
                "command_schema_version": payload_surface[
                    "command_schema_version"
                ],
            },
            {
                "method": "POST",
                "canonical_path": (
                    "/v1/me/matching-invitations/"
                    "business_invitation_0001/accept"
                ),
                "target": {
                    "kind": "Invitation",
                    "id": "business_invitation_0001",
                    "parent_kind": None,
                    "parent_id": None,
                },
                "if_match": 2,
                "command_schema_version": 1,
            },
        )

    def test_corrupt_receipt_is_503_and_only_payload_conflict_is_409(self) -> None:
        corruption_codes = []
        for field, value in (
            ("extra", "not-allowed"),
            ("command_version", 2),
            ("canonicalization_version", "unknown"),
            ("identity_key_id", "unknown"),
            ("payload_hash_key_id", "unknown"),
            ("identity", "f" * 64),
        ):
            harness, command = self._completed()
            receipt_id, receipt = _only_receipt(harness)
            damaged = deepcopy(receipt)
            damaged[field] = value
            harness.uow_factory.store.data["receipts"][receipt_id] = damaged
            corruption_codes.append(_replay_code(harness, command)[0])

        harness, command = self._completed()
        different = replace(command, reason_code="RECIPIENT_CHANGED_MIND")
        conflict_code, _ = _replay_code(harness, different)
        self.assertEqual(
            {"corruption_codes": corruption_codes, "conflict": conflict_code},
            {
                "corruption_codes": ["SERVICE_UNAVAILABLE"] * 6,
                "conflict": "IDEMPOTENCY_KEY_REUSED",
            },
        )

    def test_replay_new_active_session_skips_completed_business_authority(self) -> None:
        harness, command = self._completed()
        harness.dependencies["creator_authority"] = _UnavailableBusinessAuthority()
        harness.dependencies["profile_facts"] = _UnavailableBusinessAuthority()
        harness.dependencies["safety_hold"] = _UnavailableBusinessAuthority()
        new_session_actor = replace(
            creator_actor(), session_id="session_secret_0000002"
        )
        code, result = _replay_code(
            harness, command, call_actor=new_session_actor
        )
        self.assertEqual(
            {
                "code": code,
                "replayed": result.replayed if result is not None else None,
                "principal_preflights": len(harness.principal_authority.calls),
            },
            {"code": None, "replayed": True, "principal_preflights": 2},
        )

    def test_replay_still_requires_current_active_principal_and_session(self) -> None:
        harness, command = self._completed()
        harness.principal_authority.session_status = "EXPIRED"
        code, _ = _replay_code(
            harness,
            command,
            call_actor=replace(
                creator_actor(), session_id="session_secret_0000002"
            ),
        )
        self.assertEqual(code, "SESSION_EXPIRED")

    def test_audit_is_closed_and_carries_full_correlation_result_facts(self) -> None:
        harness, _ = self._completed()
        audits = harness.uow_factory.store.snapshot()["audits"]
        self.assertEqual(len(audits), 1)
        audit = next(iter(audits.values()))
        self.assertEqual(
            set(audit),
            {
                "schema_version",
                "operation",
                "command_version",
                "actor_kind",
                "actor_id",
                "original_actor_id",
                "organization_id",
                "target_id",
                "target_status",
                "aggregate_version",
                "result_code",
                "event_types",
                "occurred_at",
                "correlation_id",
                "causation_id",
                "trace_id",
            },
        )
        self.assertEqual(
            {
                "schema_version": audit["schema_version"],
                "actor_kind": audit["actor_kind"],
                "result_code": audit["result_code"],
                "aggregate_version": audit["aggregate_version"],
                "event_types": audit["event_types"],
            },
            {
                "schema_version": 1,
                "actor_kind": "USER",
                "result_code": "SUCCESS",
                "aggregate_version": 3,
                "event_types": [
                    "InvitationAccepted",
                    "SelectionInvitationSetChanged",
                ],
            },
        )
        self.assertNotIn("session_secret", repr(audit).lower())
        self.assertNotIn("raw-key", repr(audit).lower())

    def test_safe_response_closes_schema_http_status_etag_and_replay_binding(self) -> None:
        harness, command = self._completed()
        receipt_id, receipt = _only_receipt(harness)
        safe = receipt["safe_response"]
        self.assertEqual(
            set(safe),
            {
                "schema_version",
                "response_schema",
                "http_status",
                "etag",
                "body",
            },
        )
        self.assertEqual(
            {
                "schema_version": safe["schema_version"],
                "response_schema": safe["response_schema"],
                "http_status": safe["http_status"],
                "etag": safe["etag"],
                "body_version": safe["body"]["aggregate_version"],
            },
            {
                "schema_version": 1,
                "response_schema": "MatchingCommandResult",
                "http_status": 200,
                "etag": '"v3"',
                "body_version": 3,
            },
        )
        corruption_codes = []
        for mutation in (
            lambda value: value.update(response_schema="UnknownResponse"),
            lambda value: value.update(http_status=201),
            lambda value: value.update(etag='"999"'),
            lambda value: value["body"].update(target_id="other_target"),
            lambda value: value["body"].update(aggregate_version=999),
            lambda value: value.update(secret="not-allowed"),
        ):
            current_harness, current_command = self._completed()
            current_id, current_receipt = _only_receipt(current_harness)
            damaged = deepcopy(current_receipt)
            mutation(damaged["safe_response"])
            current_harness.uow_factory.store.data["receipts"][
                current_id
            ] = damaged
            corruption_codes.append(
                _replay_code(current_harness, current_command)[0]
            )
        self.assertEqual(corruption_codes, ["SERVICE_UNAVAILABLE"] * 6)


if __name__ == "__main__":
    unittest.main()
