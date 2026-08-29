"""Robust Taxonomy publish, retire and consumer application semantic RED."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import FrozenInstanceError, replace
import unittest

from desire_platform.taxonomy.application import (
    ApplyTaxonomyBundleToConsumerHandler,
    PublishTaxonomyBundleHandler,
    RetireTaxonomyBundleHandler,
    TAXONOMY_APPLICATION_BEHAVIOR_NOT_AVAILABLE,
    TaxonomyApplicationBehaviorNotAvailable,
    TaxonomyApplicationError,
)
from desire_platform.taxonomy.domain import TaxonomyBundleStatus
from desire_platform.taxonomy.ports import (
    TaxonomyApprovalEvidence,
    TaxonomyArtifactUnavailableError,
    TaxonomyConsumerRelease,
)
from tests.support.taxonomy_builders import (
    BUNDLE_ID,
    NOW,
    PUBLISH_CHECKPOINTS,
    RETIRE_CHECKPOINTS,
    SUCCESSOR_ID,
    actor,
    build_harness,
    consumer_command,
    publish_command,
    release_candidate,
    retire_command,
    validated_release,
)


class _Unavailable:
    def __getattr__(self, name):
        def unavailable(*args, **kwargs):
            raise TaxonomyArtifactUnavailableError("must be skipped on replay")
        return unavailable


class _DuplicateApprovalReader:
    def read_exact(self, **query):
        first = TaxonomyApprovalEvidence(
            query["domain_approval_id"],
            "DOMAIN_STEWARD",
            "same_taxonomy_reviewer",
            "APPROVED",
            query["release_manifest_sha256"],
            "2" * 64,
            NOW,
        )
        return first, replace(
            first,
            approval_id=query["safety_data_approval_id"],
            duty_code="SAFETY_DATA_STEWARD",
        )


class TaxonomyApplicationSemanticRedTests(unittest.TestCase):
    def _call_semantic(self, handler_type, command, harness=None):
        harness = harness or build_harness(handler_type, command)
        harness.assert_ready(handler_type, command)
        try:
            result = handler_type(**harness.dependencies).handle(
                actor=actor(), command=command
            )
            return ("value", result), harness
        except TaxonomyApplicationBehaviorNotAvailable as error:
            self.assertEqual(
                str(error), TAXONOMY_APPLICATION_BEHAVIOR_NOT_AVAILABLE
            )
            return ("sentinel", None), harness
        except TaxonomyApplicationError as error:
            return ("error", error.code), harness

    def test_publish_requires_exact_system_workload_and_operation_attestation(self) -> None:
        outcome, harness = self._call_semantic(
            PublishTaxonomyBundleHandler, publish_command()
        )
        self.assertEqual(
            {
                "kind": outcome[0],
                "status": outcome[1].target_status if outcome[0] == "value" else None,
                "authority_calls": len(harness.authority.calls),
            },
            {"kind": "value", "status": "ACTIVE", "authority_calls": 1},
        )

    def test_publish_reads_exact_artifact_bytes_and_binds_signature_trust(self) -> None:
        outcome, harness = self._call_semantic(
            PublishTaxonomyBundleHandler, publish_command()
        )
        self.assertEqual(
            {
                "kind": outcome[0],
                "artifact_reads": len(harness.artifacts.calls),
                "signature_checks": len(harness.signature.calls),
                "trust_checks": len(harness.trust.calls),
                "locked_rechecks": len(harness.locked_evidence.calls),
            },
            {
                "kind": "value",
                "artifact_reads": 1,
                "signature_checks": 1,
                "trust_checks": 1,
                "locked_rechecks": 1,
            },
        )

    def test_publish_requires_two_independent_exact_review_duties(self) -> None:
        command = publish_command()
        harness = build_harness(PublishTaxonomyBundleHandler, command)
        harness.dependencies["approval_reader"] = _DuplicateApprovalReader()
        outcome, _ = self._call_semantic(
            PublishTaxonomyBundleHandler, command, harness
        )
        self.assertEqual(outcome, ("error", "REVIEW_APPROVAL_REQUIRED"))

    def test_completed_receipt_replays_and_skips_artifact_signature_approval_domain(self) -> None:
        command = publish_command()
        first, harness = self._call_semantic(PublishTaxonomyBundleHandler, command)
        harness.dependencies.update(
            artifact_reader=_Unavailable(),
            signature_verifier=_Unavailable(),
            approval_reader=_Unavailable(),
            domain_validator=_Unavailable(),
        )
        second, _ = self._call_semantic(
            PublishTaxonomyBundleHandler, command, harness
        )
        self.assertEqual(
            (
                first[1].replayed if first[0] == "value" else first[0],
                second[1].replayed if second[0] == "value" else second[0],
            ),
            (False, True),
        )

    def test_receipt_same_identity_different_payload_conflicts(self) -> None:
        command = publish_command()
        first, harness = self._call_semantic(PublishTaxonomyBundleHandler, command)
        different = replace(
            command, trust_record_id="taxonomy_trust_record_002"
        )
        second, _ = self._call_semantic(
            PublishTaxonomyBundleHandler, different, harness
        )
        self.assertEqual(
            (first[0], second),
            ("value", ("error", "IDEMPOTENCY_KEY_REUSED")),
        )

    def test_receipt_replay_accepts_retained_identity_and_payload_keys(self) -> None:
        command = publish_command()
        first, harness = self._call_semantic(PublishTaxonomyBundleHandler, command)
        keyring = harness.dependencies["receipt_keyring"]
        keyring.active_identity_key_id = "taxonomy-identity-key-v3"
        keyring.active_payload_key_id = "taxonomy-payload-key-v3"
        keyring.retained_identity_key_ids = (
            "taxonomy-identity-key-v2",
            "taxonomy-identity-key-v1",
        )
        keyring.retained_payload_key_ids = (
            "taxonomy-payload-key-v2",
            "taxonomy-payload-key-v1",
        )
        second, _ = self._call_semantic(
            PublishTaxonomyBundleHandler, command, harness
        )
        self.assertEqual(
            (
                first[0],
                second[1].replayed if second[0] == "value" else second[0],
            ),
            ("value", True),
        )

    def test_selector_current_race_fails_closed_and_rolls_back(self) -> None:
        command = publish_command()
        harness = build_harness(PublishTaxonomyBundleHandler, command)
        harness.uow_factory.current_race = True
        before = harness.uow_factory.store.snapshot()
        outcome, _ = self._call_semantic(
            PublishTaxonomyBundleHandler, command, harness
        )
        self.assertEqual(
            (outcome, harness.uow_factory.store.snapshot() == before),
            (("error", "PRECONDITION_FAILED"), True),
        )

    def test_all_thirteen_publish_checkpoints_rollback_every_fact(self) -> None:
        observed = []
        for checkpoint in PUBLISH_CHECKPOINTS:
            command = publish_command()
            harness = build_harness(PublishTaxonomyBundleHandler, command)
            harness.uow_factory.fail_checkpoint = checkpoint
            before = harness.uow_factory.store.snapshot()
            outcome, _ = self._call_semantic(
                PublishTaxonomyBundleHandler, command, harness
            )
            observed.append(
                (outcome, harness.uow_factory.store.snapshot() == before)
            )
        self.assertEqual(
            observed,
            [(('error', 'SERVICE_UNAVAILABLE'), True)] * 13,
        )

    def test_commit_unknown_recovers_only_a_durable_full_chain(self) -> None:
        outcomes = []
        for durable in (True, False):
            command = publish_command()
            harness = build_harness(PublishTaxonomyBundleHandler, command)
            harness.uow_factory.commit_unknown = True
            harness.uow_factory.commit_unknown_durable = durable
            outcome, _ = self._call_semantic(
                PublishTaxonomyBundleHandler, command, harness
            )
            outcomes.append(
                outcome[1].replayed if outcome[0] == "value" else outcome
            )
        self.assertEqual(
            outcomes,
            [True, ("error", "SERVICE_UNAVAILABLE")],
        )

    def test_retire_is_terminal_and_clears_current_atomically(self) -> None:
        command = retire_command()
        first, harness = self._call_semantic(RetireTaxonomyBundleHandler, command)
        second_command = replace(
            command,
            expected_bundle_version=2,
            idempotency_key="raw-taxonomy-retire-key-002",
        )
        second, _ = self._call_semantic(
            RetireTaxonomyBundleHandler, second_command, harness
        )
        snapshot = harness.uow_factory.store.snapshot()
        self.assertEqual(
            {
                "first": first[1].target_status if first[0] == "value" else first,
                "second": second,
                "current": snapshot.get("current", {}).get("selector"),
            },
            {
                "first": TaxonomyBundleStatus.RETIRED.value,
                "second": ("error", "INVALID_STATE_TRANSITION"),
                "current": None,
            },
        )

    def test_all_seven_retire_checkpoints_rollback_every_fact(self) -> None:
        observed = []
        for checkpoint in RETIRE_CHECKPOINTS:
            command = retire_command()
            harness = build_harness(RetireTaxonomyBundleHandler, command)
            harness.uow_factory.fail_checkpoint = checkpoint
            before = harness.uow_factory.store.snapshot()
            outcome, _ = self._call_semantic(
                RetireTaxonomyBundleHandler, command, harness
            )
            observed.append(
                (outcome, harness.uow_factory.store.snapshot() == before)
            )
        self.assertEqual(
            observed,
            [(('error', 'SERVICE_UNAVAILABLE'), True)] * 7,
        )

    def test_consumer_claims_exact_source_event_inbox_once(self) -> None:
        command = consumer_command()
        first, harness = self._call_semantic(
            ApplyTaxonomyBundleToConsumerHandler, command
        )
        second, _ = self._call_semantic(
            ApplyTaxonomyBundleToConsumerHandler, command, harness
        )
        snapshot = harness.uow_factory.store.snapshot()
        self.assertEqual(
            {
                "first": first[0],
                "second_replayed": second[1].replayed if second[0] == "value" else None,
                "inbox": len(snapshot.get("consumer_inbox", {})),
                "markers": len(snapshot.get("consumer_markers", {})),
                "source_validations": len(harness.source_validator.calls),
            },
            {
                "first": "value",
                "second_replayed": True,
                "inbox": 1,
                "markers": 1,
                "source_validations": 2,
            },
        )

    def test_consumer_uses_exact_catalog_artifact_not_event_as_body(self) -> None:
        command = consumer_command()
        outcome, harness = self._call_semantic(
            ApplyTaxonomyBundleToConsumerHandler, command
        )
        self.assertEqual(
            {
                "kind": outcome[0],
                "catalog_reads": len(harness.consumer_catalog.calls),
                "marker_status": outcome[1].target_status if outcome[0] == "value" else None,
            },
            {"kind": "value", "catalog_reads": 1, "marker_status": "ACTIVE"},
        )

    def test_consumer_rejects_unsupported_major_partial_or_hash_drift(self) -> None:
        unsupported = replace(
            consumer_command(), supported_semantic_majors=(2,)
        )
        unsupported_outcome, _ = self._call_semantic(
            ApplyTaxonomyBundleToConsumerHandler, unsupported
        )

        command = consumer_command()
        partial_harness = build_harness(
            ApplyTaxonomyBundleToConsumerHandler, command
        )
        candidate = release_candidate()
        partial = replace(candidate, labels=candidate.labels[:1])
        partial_harness.consumer_catalog.override = TaxonomyConsumerRelease(
            replace(validated_release(candidate), candidate=partial), 1, "ACTIVE"
        )
        before = partial_harness.uow_factory.store.snapshot()
        partial_outcome, _ = self._call_semantic(
            ApplyTaxonomyBundleToConsumerHandler, command, partial_harness
        )
        self.assertEqual(
            {
                "unsupported": unsupported_outcome,
                "partial": partial_outcome,
                "partial_rollback": partial_harness.uow_factory.store.snapshot() == before,
            },
            {
                "unsupported": ("error", "TAXONOMY_COMPATIBILITY_REJECTED"),
                "partial": ("error", "SERVICE_UNAVAILABLE"),
                "partial_rollback": True,
            },
        )

    def test_event_audit_receipt_and_errors_are_closed_and_secret_free(self) -> None:
        outcome, harness = self._call_semantic(
            PublishTaxonomyBundleHandler, publish_command()
        )
        snapshot = harness.uow_factory.store.snapshot()
        serialized = repr(
            {
                "receipts": snapshot.get("receipts", {}),
                "audits": snapshot.get("audits", {}),
                "outbox": snapshot.get("outbox", {}),
            }
        ).lower()
        self.assertEqual(
            {
                "kind": outcome[0],
                "audits": len(snapshot.get("audits", {})),
                "outbox": len(snapshot.get("outbox", {})),
                "has_signature": "signature_envelope" in serialized,
                "has_approval": "taxonomy_domain_approval" in serialized,
                "has_raw_key": "raw-taxonomy" in serialized,
                "has_workload_secret": "workload_secret" in serialized,
            },
            {
                "kind": "value",
                "audits": 1,
                "outbox": 1,
                "has_signature": False,
                "has_approval": False,
                "has_raw_key": False,
                "has_workload_secret": False,
            },
        )

    def test_application_commands_are_deeply_immutable_and_secret_safe(self) -> None:
        command = publish_command()
        with self.assertRaises(FrozenInstanceError):
            command.release_manifest_sha256 = "f" * 64  # type: ignore[misc]
        self.assertNotIn("raw-taxonomy", repr(command))
        self.assertNotIn("workload_secret", repr(actor()))


if __name__ == "__main__":
    unittest.main()
