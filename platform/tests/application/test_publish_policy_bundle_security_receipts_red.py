"""Third semantic RED for Publish caller, trust, approval, and receipts."""

from __future__ import annotations

from dataclasses import FrozenInstanceError, fields, replace
from datetime import timedelta
import json
import unittest

from desire_platform.identity_access.application.policy_publication import (
    PolicyLegalApprovalAttestation,
    PolicyLegalApprovalDecision,
    PolicyPublisherAuthorizationAttestation,
    PolicyPublisherOperation,
    PolicyPublisherPrincipalKind,
    PolicyReleaseKeyUsage,
    PolicyReleaseTrustStatus,
    PolicyReleaseVerificationAttestation,
    PublishPolicyBundleHandler,
)
from desire_platform.identity_access.domain.errors import IamError
from tests.support.iam_policy_publish_security_builders import (
    ACTIVE_IDENTITY_KEY_ID,
    ACTIVE_PAYLOAD_KEY_ID,
    OLD_IDENTITY_KEY_ID,
    OLD_PAYLOAD_KEY_ID,
    PUBLISH_PATH,
    PUBLISH_RECEIPT_CANONICALIZATION,
    PUBLISH_RECEIPT_FIELDS,
    StrictPolicyPublishReceiptCodec,
    completed_publish_receipt,
    local_manifest_sha256,
    secure_publication_fixture,
)


class PublishPolicyBundleSecurityReceiptRedTest(unittest.TestCase):
    def test_security_attestations_are_closed_and_immutable(self) -> None:
        fixture = secure_publication_fixture(rich_release_verifier=True)
        workload = fixture.workload_authorizer.attestation
        release = fixture.release_verifier.attestation
        approval = fixture.legal_approval.attestation

        self.assertEqual(
            [field.name for field in fields(PolicyPublisherAuthorizationAttestation)],
            [
                "credential_id",
                "principal_kind",
                "system_id",
                "operation",
                "command_id",
                "selector_digest",
                "policy_bundle_id",
                "credential_status",
                "authenticated_at",
                "valid_until",
            ],
        )
        self.assertEqual(
            [field.name for field in fields(PolicyReleaseVerificationAttestation)],
            [
                "canonical_manifest",
                "manifest_sha256",
                "signature_algorithm",
                "signature_key_id",
                "key_usage",
                "allowed_manifest_schema_versions",
                "allowed_access_purposes",
                "allowed_scope_types",
                "allowed_target_roles",
                "allowed_jurisdictions",
                "trust_status",
                "trust_valid_from",
                "trust_valid_until",
                "verified_at",
            ],
        )
        self.assertEqual(
            [field.name for field in fields(PolicyLegalApprovalAttestation)],
            [
                "credential_id",
                "manifest_sha256",
                "signature_key_id",
                "decision",
                "approver_id",
                "valid_from",
                "valid_until",
                "revoked_at",
            ],
        )
        for value, attribute in (
            (workload, "operation"),
            (release, "key_usage"),
            (approval, "decision"),
        ):
            with self.subTest(contract=type(value).__name__):
                with self.assertRaises(FrozenInstanceError):
                    setattr(value, attribute, "TAMPERED")

    def test_operation_scoped_system_workload_authorization_is_pre_uow(
        self,
    ) -> None:
        cases = []

        valid = secure_publication_fixture()
        cases.append(("valid", valid, None, 1))

        non_system = secure_publication_fixture()
        non_system.actor = replace(
            non_system.actor,
            principal_kind=PolicyPublisherPrincipalKind.USER,
        )
        cases.append(
            ("non-system", non_system, "AUTHENTICATION_REQUIRED", 0)
        )

        wrong_operation = secure_publication_fixture()
        wrong_operation.workload_authorizer.attestation = replace(
            wrong_operation.workload_authorizer.attestation,
            operation="OTHER_SYSTEM_TASK",
        )
        cases.append(
            (
                "wrong-operation",
                wrong_operation,
                "AUTHENTICATION_REQUIRED",
                0,
            )
        )

        expired = secure_publication_fixture()
        expired.workload_authorizer.attestation = replace(
            expired.workload_authorizer.attestation,
            valid_until=expired.clock.now(),
        )
        cases.append(
            ("expired-exclusive", expired, "AUTHENTICATION_REQUIRED", 0)
        )

        unavailable = secure_publication_fixture()
        unavailable.workload_authorizer.unavailable = True
        cases.append(
            ("dependency-unavailable", unavailable, "SERVICE_UNAVAILABLE", 0)
        )

        for name, fixture, expected_code, expected_begins in cases:
            with self.subTest(case=name):
                before = fixture.store.snapshot()
                _result, code = self._invoke(fixture)
                expected_unchanged = expected_code is not None
                self.assertEqual(
                    {
                        "code": code,
                        "authorizer_calls": len(
                            fixture.workload_authorizer.calls
                        ),
                        "begins": fixture.uow_factory.begin_count,
                        "writes": (
                            []
                            if not expected_unchanged
                            else fixture.uow_factory.write_calls
                        ),
                        "unchanged": fixture.store.snapshot() == before,
                    },
                    {
                        "code": expected_code,
                        "authorizer_calls": 1,
                        "begins": expected_begins,
                        "writes": [],
                        "unchanged": expected_unchanged,
                    },
                )

    def test_rich_release_attestation_binds_trust_record_and_scope(self) -> None:
        cases = []

        valid = secure_publication_fixture(rich_release_verifier=True)
        cases.append(("valid", valid, None, 1, 1))

        mutations = {
            "manifest-digest-binding": {"manifest_sha256": "f" * 64},
            "algorithm-binding": {
                "signature_algorithm": "Ed448"
            },
            "key-binding": {"signature_key_id": "unknown_policy_key_009"},
            "key-usage": {"key_usage": "OTHER_USE"},
            "manifest-schema-scope": {
                "allowed_manifest_schema_versions": ("other-schema-v9",)
            },
            "purpose-scope": {"allowed_access_purposes": ()},
            "selector-scope": {"allowed_scope_types": ()},
            "role-scope": {"allowed_target_roles": ()},
            "jurisdiction-scope": {"allowed_jurisdictions": ("CN",)},
            "trust-revoked": {"trust_status": PolicyReleaseTrustStatus.REVOKED},
            "trust-not-yet-valid": {
                "trust_valid_from": valid.clock.now() + timedelta(seconds=1)
            },
            "trust-expired": {"trust_valid_until": valid.clock.now()},
            "verification-from-future": {
                "verified_at": valid.clock.now() + timedelta(seconds=1)
            },
        }
        for name, changes in mutations.items():
            fixture = secure_publication_fixture(rich_release_verifier=True)
            fixture.release_verifier.attestation = replace(
                fixture.release_verifier.attestation,
                **changes,
            )
            cases.append((name, fixture, "POLICY_RELEASE_INVALID", 0, 0))

        unavailable = secure_publication_fixture(rich_release_verifier=True)
        unavailable.release_verifier.unavailable = True
        cases.append(
            ("provider-unavailable", unavailable, "SERVICE_UNAVAILABLE", 0, 0)
        )

        for name, fixture, expected_code, expected_begins, approval_calls in cases:
            with self.subTest(case=name):
                before = fixture.store.snapshot()
                _result, code = self._invoke(fixture)
                self.assertEqual(
                    {
                        "code": code,
                        "verifier_calls": len(fixture.release_verifier.calls),
                        "approval_calls": len(fixture.legal_approval.calls),
                        "begins": fixture.uow_factory.begin_count,
                        "writes": fixture.uow_factory.write_calls,
                        "unchanged": fixture.store.snapshot() == before,
                    },
                    {
                        "code": expected_code,
                        "verifier_calls": 1,
                        "approval_calls": approval_calls,
                        "begins": expected_begins,
                        "writes": [] if expected_code is not None else fixture.uow_factory.write_calls,
                        "unchanged": expected_code is not None,
                    },
                )

    def test_legal_approval_is_exact_fail_closed_and_audit_minimal(self) -> None:
        cases = []

        valid = secure_publication_fixture()
        cases.append(("valid", valid, None, 1))

        missing = secure_publication_fixture()
        missing.legal_approval.attestation = None
        cases.append(("missing", missing, "POLICY_RELEASE_INVALID", 0))

        mutations = {
            "manifest-binding": {"manifest_sha256": "f" * 64},
            "key-binding": {"signature_key_id": "wrong_signing_key_009"},
            "decision": {"decision": PolicyLegalApprovalDecision.REJECTED},
            "not-yet-valid": {
                "valid_from": valid.clock.now() + timedelta(seconds=1)
            },
            "expired": {"valid_until": valid.clock.now()},
            "revoked": {"revoked_at": valid.clock.now() - timedelta(seconds=1)},
        }
        for name, changes in mutations.items():
            fixture = secure_publication_fixture()
            fixture.legal_approval.attestation = replace(
                fixture.legal_approval.attestation,
                **changes,
            )
            cases.append((name, fixture, "POLICY_RELEASE_INVALID", 0))

        unavailable = secure_publication_fixture()
        unavailable.legal_approval.unavailable = True
        cases.append(
            ("provider-unavailable", unavailable, "SERVICE_UNAVAILABLE", 0)
        )

        for name, fixture, expected_code, expected_begins in cases:
            with self.subTest(case=name):
                before = fixture.store.snapshot()
                _result, code = self._invoke(fixture)
                snapshot = fixture.store.snapshot()
                self.assertEqual(
                    {
                        "code": code,
                        "approval_calls": len(fixture.legal_approval.calls),
                        "begins": fixture.uow_factory.begin_count,
                        "writes": (
                            fixture.uow_factory.write_calls
                            if expected_code is not None
                            else []
                        ),
                        "unchanged": snapshot == before,
                    },
                    {
                        "code": expected_code,
                        "approval_calls": 1,
                        "begins": expected_begins,
                        "writes": [],
                        "unchanged": expected_code is not None,
                    },
                )
                if expected_code is None:
                    audit = next(iter(snapshot["audit_events"].values()))
                    self.assertEqual(
                        {
                            "approval_credential_id": audit.get(
                                "approval_credential_id"
                            ),
                            "approval_approver_id": audit.get(
                                "approval_approver_id"
                            ),
                            "approved_manifest_sha256": audit.get(
                                "approved_manifest_sha256"
                            ),
                        },
                        {
                            "approval_credential_id": (
                                fixture.legal_approval.attestation.credential_id
                            ),
                            "approval_approver_id": (
                                fixture.legal_approval.attestation.approver_id
                            ),
                            "approved_manifest_sha256": local_manifest_sha256(
                                fixture.command
                            ),
                        },
                    )
                    serialized_audit = json.dumps(audit, default=str)
                    self.assertNotIn(
                        fixture.legal_approval.approval_body_sentinel,
                        serialized_audit,
                    )
                    self.assertNotIn(
                        fixture.command.release.signature,
                        serialized_audit,
                    )

    def test_publish_receipt_has_keyed_closed_in_progress_and_completed_shape(
        self,
    ) -> None:
        fixture = secure_publication_fixture()
        _result, code = self._invoke(fixture)
        snapshot = fixture.store.snapshot()
        receipt = next(iter(snapshot["command_receipts"].values()))
        captured_receipts = [
            value
            for table, _key, _checkpoint, value
            in fixture.uow_factory.captured_writes
            if table == "command_receipts"
        ]
        pending = captured_receipts[0]
        completed = captured_receipts[-1]
        expected_identity = fixture.receipt_codec.identity_digest(
            fixture.command.command_id
        )
        expected_payload = fixture.receipt_codec.payload_hash(
            fixture.command,
            locally_computed_manifest_sha256=local_manifest_sha256(
                fixture.command
            ),
        )
        serialized = json.dumps(receipt, default=str)

        self.assertEqual(
            {
                "code": code,
                "identity_key": receipt.get(
                    "idempotency_key_digest_key_id"
                ),
                "payload_key": receipt.get("payload_hash_key_id"),
                "keys_are_separate": (
                    receipt.get("idempotency_key_digest_key_id")
                    != receipt.get("payload_hash_key_id")
                ),
                "identity_digest": receipt.get("idempotency_key_digest"),
                "payload_hash": receipt.get("payload_hash"),
                "payload_is_not_manifest_hash": (
                    receipt.get("payload_hash")
                    != fixture.command.release.manifest_sha256
                ),
                "canonicalization": receipt.get(
                    "canonicalization_version"
                ),
                "profile": (
                    receipt.get("http_method"),
                    receipt.get("canonical_path"),
                    receipt.get("target_kind"),
                    receipt.get("target_id"),
                    receipt.get("if_match_version"),
                ),
                "pending_status": pending.get("status"),
                "pending_fields": set(pending),
                "completed_status": completed.get("status"),
                "completed_fields": set(completed),
                "stored_fields": set(receipt),
                "raw_command_is_not_digest": (
                    fixture.command.command_id
                    != receipt.get("idempotency_key_digest")
                ),
                "secret_free": all(
                    secret not in serialized
                    for secret in (
                        fixture.command.release.signature,
                        fixture.legal_approval.approval_body_sentinel,
                        *(
                            document.canonical_body
                            for document in fixture.command.release.manifest.documents
                        ),
                    )
                ),
            },
            {
                "code": None,
                "identity_key": ACTIVE_IDENTITY_KEY_ID,
                "payload_key": ACTIVE_PAYLOAD_KEY_ID,
                "keys_are_separate": True,
                "identity_digest": expected_identity,
                "payload_hash": expected_payload,
                "payload_is_not_manifest_hash": True,
                "canonicalization": PUBLISH_RECEIPT_CANONICALIZATION,
                "profile": (
                    "INTERNAL",
                    PUBLISH_PATH,
                    "PolicyBundle",
                    fixture.command.release.manifest.policy_bundle_id,
                    None,
                ),
                "pending_status": "IN_PROGRESS",
                "pending_fields": PUBLISH_RECEIPT_FIELDS,
                "completed_status": "COMPLETED",
                "completed_fields": PUBLISH_RECEIPT_FIELDS,
                "stored_fields": PUBLISH_RECEIPT_FIELDS,
                "raw_command_is_not_digest": True,
                "secret_free": True,
            },
        )

    def test_same_manifest_changed_signature_reuses_identity_but_conflicts_payload(
        self,
    ) -> None:
        fixture = secure_publication_fixture()
        original_payload_hash = fixture.receipt_codec.payload_hash(
            fixture.command,
            locally_computed_manifest_sha256=local_manifest_sha256(
                fixture.command
            ),
        )
        first_result, first_code = self._invoke(fixture)
        before_retry = fixture.store.snapshot()
        original_verifier_calls = len(fixture.release_verifier.calls)
        fixture.command = replace(
            fixture.command,
            release=replace(
                fixture.command.release,
                signature="changed-signature-envelope-with-same-manifest",
            ),
        )
        changed_payload_hash = fixture.receipt_codec.payload_hash(
            fixture.command,
            locally_computed_manifest_sha256=local_manifest_sha256(
                fixture.command
            ),
        )
        retry_result, retry_code = self._invoke(fixture)

        self.assertEqual(
            {
                "first_code": first_code,
                "first_replayed": getattr(first_result, "replayed", None),
                "retry_code": retry_code,
                "retry_result": retry_result,
                "same_identity": fixture.receipt_codec.identity_digest(
                    fixture.command.command_id
                ),
                "payload_changed": (
                    original_payload_hash != changed_payload_hash
                ),
                "unchanged": fixture.store.snapshot() == before_retry,
                "commits": fixture.uow_factory.commit_count,
                "verifier_calls": len(fixture.release_verifier.calls),
            },
            {
                "first_code": None,
                "first_replayed": False,
                "retry_code": "IDEMPOTENCY_KEY_REUSED",
                "retry_result": None,
                "same_identity": fixture.receipt_codec.identity_digest(
                    fixture.command.command_id
                ),
                "payload_changed": True,
                "unchanged": True,
                "commits": 1,
                "verifier_calls": original_verifier_calls,
            },
        )

    def test_old_retained_receipt_replays_and_missing_old_key_fails_closed(
        self,
    ) -> None:
        for case in ("retained", "missing-key"):
            with self.subTest(case=case):
                fixture = secure_publication_fixture()
                seeding_codec = StrictPolicyPublishReceiptCodec()
                receipt = completed_publish_receipt(
                    fixture,
                    codec=seeding_codec,
                    identity_key_id=OLD_IDENTITY_KEY_ID,
                    payload_key_id=OLD_PAYLOAD_KEY_ID,
                )
                fixture.store.seed(
                    command_receipts={
                        fixture.command.command_id: receipt,
                    }
                )
                if case == "retained":
                    restart_codec = StrictPolicyPublishReceiptCodec()
                    expected_code = None
                    expected_replayed = True
                else:
                    restart_codec = StrictPolicyPublishReceiptCodec(
                        identity_keys={
                            ACTIVE_IDENTITY_KEY_ID: (
                                seeding_codec.identity_keys[
                                    ACTIVE_IDENTITY_KEY_ID
                                ]
                            )
                        },
                        payload_keys={
                            ACTIVE_PAYLOAD_KEY_ID: (
                                seeding_codec.payload_keys[
                                    ACTIVE_PAYLOAD_KEY_ID
                                ]
                            )
                        },
                    )
                    expected_code = "SERVICE_UNAVAILABLE"
                    expected_replayed = None
                fixture.receipt_codec = restart_codec
                fixture.handler = PublishPolicyBundleHandler(
                    uow_factory=fixture.uow_factory,
                    release_verifier=fixture.release_verifier,
                    clock=fixture.clock,
                    workload_authorizer=fixture.workload_authorizer,
                    legal_approval_port=fixture.legal_approval,
                    receipt_codec=restart_codec,
                )
                before = fixture.store.snapshot()
                result, code = self._invoke(fixture)

                self.assertEqual(
                    {
                        "code": code,
                        "replayed": getattr(result, "replayed", None),
                        "unchanged": fixture.store.snapshot() == before,
                        "begins": fixture.uow_factory.begin_count,
                        "verifier_calls": len(fixture.release_verifier.calls),
                        "approval_calls": len(fixture.legal_approval.calls),
                        "authorizer_calls": len(
                            fixture.workload_authorizer.calls
                        ),
                        "receipt_key_calls": (
                            len(restart_codec.identity_calls),
                            len(restart_codec.payload_calls),
                        ),
                    },
                    {
                        "code": expected_code,
                        "replayed": expected_replayed,
                        "unchanged": True,
                        "begins": 0,
                        "verifier_calls": 0,
                        "approval_calls": 0,
                        "authorizer_calls": 1,
                        "receipt_key_calls": (
                            2 if case == "retained" else 1,
                            1 if case == "retained" else 0,
                        ),
                    },
                )

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


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
