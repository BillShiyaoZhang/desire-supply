"""TEST-APP-POLICY-001 semantic RED for the sole ACTIVE publication path."""

from __future__ import annotations

from dataclasses import FrozenInstanceError, fields, replace
from datetime import timedelta
import unittest

from desire_platform.identity_access.application.policy_publication import (
    PolicyReleaseManifest,
    PolicySelectorFacts,
    PublishPolicyBundleCommand,
    SignedPolicyRelease,
)
from desire_platform.identity_access.domain.errors import IamError
from desire_platform.identity_access.domain.policies import PolicyBundleStatus
from tests.support.iam_policy_issue_builders import (
    UTC_NOW,
    initial_publication_fixture,
    policy_selector_digest,
    replacement_publication_fixture,
    sign_policy_release,
)


class PublishPolicyBundleSemanticRedTest(unittest.TestCase):
    def test_command_and_signed_manifest_are_closed_and_immutable(self) -> None:
        """Status, current pointer, versions and actor facts are not commands."""

        fixture = initial_publication_fixture()
        self.assertEqual(
            [field.name for field in fields(PublishPolicyBundleCommand)],
            ["command_id", "release"],
        )
        self.assertEqual(
            [field.name for field in fields(SignedPolicyRelease)],
            [
                "manifest",
                "manifest_sha256",
                "signature_algorithm",
                "signature_key_id",
                "signature",
            ],
        )
        self.assertEqual(
            [field.name for field in fields(PolicySelectorFacts)],
            [
                "canonicalization_version",
                "access_purpose",
                "scope_type",
                "target_role",
                "jurisdiction",
                "locale",
            ],
        )
        manifest_fields = {
            field.name for field in fields(PolicyReleaseManifest)
        }
        self.assertFalse(
            manifest_fields
            & {
                "status",
                "current_bundle_id",
                "aggregate_version",
                "created_at",
                "published_at",
                "actor_id",
            }
        )
        with self.assertRaises(FrozenInstanceError):
            fixture.command.release.manifest.selector.locale = "zh-CN"

    def test_initial_release_atomically_activates_exact_selector_and_evidence(
        self,
    ) -> None:
        """The first signed release creates one current ACTIVE bundle path."""

        fixture = initial_publication_fixture()
        result, code = self._invoke(fixture)
        snapshot = fixture.store.snapshot()
        selector = snapshot.get("policy_selectors", {}).get(
            fixture.selector_digest, {}
        )
        bundle = snapshot.get("policy_bundles", {}).get(
            fixture.command.release.manifest.policy_bundle_id
        )
        document = snapshot.get("policy_documents", {}).get(
            fixture.command.release.manifest.documents[0].document_id
        )
        events = self._event_types(snapshot)

        self.assertEqual(
            {
                "code": code,
                "result_replayed": getattr(result, "replayed", None),
                "result_bundle": getattr(result, "policy_bundle_id", None),
                "selector_current": selector.get("current_bundle_id"),
                "selector_version": selector.get("aggregate_version"),
                "selector_facts": self._selector_facts(selector),
                "bundle_status": self._status(bundle),
                "bundle_selector": getattr(bundle, "selector_digest", None),
                "manifest_sha256": getattr(
                    bundle, "release_manifest_sha256", None
                ),
                "signature_key_id": getattr(
                    bundle, "release_signature_key_id", None
                ),
                "document_hash": getattr(document, "content_sha256", None),
                "receipt_count": len(snapshot.get("command_receipts", {})),
                "audit_count": len(snapshot.get("audit_events", {})),
                "events": events,
                "verifier_calls": len(fixture.verifier.calls),
                "locks": fixture.uow_factory.lock_calls,
                "commits": fixture.uow_factory.commit_count,
            },
            {
                "code": None,
                "result_replayed": False,
                "result_bundle": (
                    fixture.command.release.manifest.policy_bundle_id
                ),
                "selector_current": (
                    fixture.command.release.manifest.policy_bundle_id
                ),
                "selector_version": 1,
                "selector_facts": {
                    "canonicalization_version": "policy-selector-json-v1",
                    "access_purpose": "CREATOR_ENROLLMENT",
                    "scope_type": "USER_ROLE",
                    "target_role": "CREATOR",
                    "jurisdiction": "GLOBAL",
                    "locale": "en",
                },
                "bundle_status": "ACTIVE",
                "bundle_selector": fixture.selector_digest,
                "manifest_sha256": fixture.command.release.manifest_sha256,
                "signature_key_id": fixture.command.release.signature_key_id,
                "document_hash": (
                    fixture.command.release.manifest.documents[0].content_sha256
                ),
                "receipt_count": 1,
                "audit_count": 1,
                "events": ["PolicyBundlePublished"],
                "verifier_calls": 1,
                "locks": [("policy_selectors", fixture.selector_digest)],
                "commits": 1,
            },
        )

    def test_replacement_closes_old_window_and_advances_pointer_atomically(
        self,
    ) -> None:
        """Exactly one old current is superseded by the signed successor."""

        fixture = replacement_publication_fixture()
        result, code = self._invoke(fixture)
        snapshot = fixture.store.snapshot()
        manifest = fixture.command.release.manifest
        selector = snapshot.get("policy_selectors", {}).get(
            fixture.selector_digest, {}
        )
        old_bundle = snapshot.get("policy_bundles", {}).get(
            manifest.supersedes_policy_bundle_id
        )
        new_bundle = snapshot.get("policy_bundles", {}).get(
            manifest.policy_bundle_id
        )

        self.assertEqual(
            {
                "code": code,
                "result_bundle": getattr(result, "policy_bundle_id", None),
                "selector_current": selector.get("current_bundle_id"),
                "selector_version": selector.get("aggregate_version"),
                "old_status": self._status(old_bundle),
                "old_until": getattr(old_bundle, "effective_until", None),
                "old_superseded_by": getattr(
                    old_bundle,
                    "superseded_by_bundle_id",
                    None,
                ),
                "new_status": self._status(new_bundle),
                "new_effective_at": getattr(new_bundle, "effective_at", None),
                "events": self._event_types(snapshot),
                "commits": fixture.uow_factory.commit_count,
            },
            {
                "code": None,
                "result_bundle": manifest.policy_bundle_id,
                "selector_current": manifest.policy_bundle_id,
                "selector_version": 2,
                "old_status": "SUPERSEDED",
                "old_until": manifest.effective_at,
                "old_superseded_by": manifest.policy_bundle_id,
                "new_status": "ACTIVE",
                "new_effective_at": manifest.effective_at,
                "events": [
                    "PolicyBundlePublished",
                    "PolicyBundleSuperseded",
                ],
                "commits": 1,
            },
        )

    def test_checksum_signature_document_and_selector_tampering_are_zero_write(
        self,
    ) -> None:
        """Every signed artifact mismatch is rejected before a transaction."""

        cases = []
        base = initial_publication_fixture().command.release
        cases.append(
            (
                "manifest-checksum",
                replace(base, manifest_sha256="0" * 64),
            )
        )
        cases.append(("signature", replace(base, signature="not-a-signature")))
        tampered_document = replace(
            base.manifest.documents[0],
            canonical_body="Body changed after signing.",
        )
        cases.append(
            (
                "document-body",
                replace(
                    base,
                    manifest=replace(
                        base.manifest,
                        documents=(tampered_document,),
                    ),
                ),
            )
        )
        wrong_document_hash = replace(
            base.manifest.documents[0],
            content_sha256="0" * 64,
        )
        cases.append(
            (
                "document-content-hash",
                sign_policy_release(
                    replace(
                        base.manifest,
                        documents=(wrong_document_hash,),
                    )
                ),
            )
        )
        wrong_selector_manifest = replace(
            base.manifest,
            selector_digest="f" * 64,
        )
        cases.append(
            (
                "selector-digest",
                sign_policy_release(wrong_selector_manifest),
            )
        )

        for name, release in cases:
            with self.subTest(case=name):
                fixture = initial_publication_fixture()
                fixture.command = replace(fixture.command, release=release)
                before = fixture.store.snapshot()
                _result, code = self._invoke(fixture)
                self.assertEqual(
                    {
                        "code": code,
                        "unchanged": fixture.store.snapshot() == before,
                        "begins": fixture.uow_factory.begin_count,
                        "writes": fixture.uow_factory.write_calls,
                        "computed_selector": policy_selector_digest(
                            release.manifest.selector
                        ),
                        "claimed_selector": release.manifest.selector_digest,
                    },
                    {
                        "code": "POLICY_RELEASE_INVALID",
                        "unchanged": True,
                        "begins": 0,
                        "writes": [],
                        "computed_selector": (
                            release.manifest.selector_digest
                            if name != "selector-digest"
                            else base.manifest.selector_digest
                        ),
                        "claimed_selector": release.manifest.selector_digest,
                    },
                )

    def test_stale_replacement_or_commit_conflict_cannot_create_two_currents(
        self,
    ) -> None:
        """The selector lock/current check maps both races to a stable 412."""

        for case in ("stale-supersedes", "commit-conflict"):
            with self.subTest(case=case):
                fixture = replacement_publication_fixture()
                if case == "stale-supersedes":
                    bundles = fixture.store._tables["policy_bundles"]
                    old_bundle_id = (
                        fixture.command.release.manifest
                        .supersedes_policy_bundle_id
                    )
                    old_bundle = bundles[old_bundle_id]
                    bundles[old_bundle_id] = replace(
                        old_bundle,
                        status=PolicyBundleStatus.SUPERSEDED,
                        effective_until=UTC_NOW,
                    )
                    competing = replace(
                        old_bundle,
                        policy_bundle_id=(
                            "policy_bundle_competing_winner_003"
                        ),
                        status=PolicyBundleStatus.ACTIVE,
                        effective_at=UTC_NOW,
                        effective_until=None,
                    )
                    bundles[competing.policy_bundle_id] = competing
                    selector = fixture.store._tables["policy_selectors"][
                        fixture.selector_digest
                    ]
                    selector["current_bundle_id"] = competing.policy_bundle_id
                    selector["aggregate_version"] = 2
                else:
                    fixture.uow_factory.conflict_on_commit = True
                before = fixture.store.snapshot()
                _result, code = self._invoke(fixture)
                after = fixture.store.snapshot()
                active_for_selector = [
                    bundle
                    for bundle in after.get("policy_bundles", {}).values()
                    if getattr(bundle, "selector_digest", None)
                    == fixture.selector_digest
                    and self._status(bundle) == "ACTIVE"
                    and getattr(bundle, "effective_at", UTC_NOW) <= UTC_NOW
                    and (
                        getattr(bundle, "effective_until", None) is None
                        or UTC_NOW
                        < getattr(bundle, "effective_until", UTC_NOW)
                    )
                ]
                self.assertEqual(
                    {
                        "code": code,
                        "unchanged": after == before,
                        "new_bundle_present": (
                            fixture.command.release.manifest.policy_bundle_id
                            in after.get("policy_bundles", {})
                        ),
                        "active_count": len(active_for_selector),
                    },
                    {
                        "code": "PRECONDITION_FAILED",
                        "unchanged": True,
                        "new_bundle_present": False,
                        "active_count": 1,
                    },
                )

    def test_completed_command_replays_exact_release_but_rejects_changed_payload(
        self,
    ) -> None:
        """Internal command_id is exact-payload idempotency, not a bypass."""

        fixture = initial_publication_fixture()
        receipt_key = (
            "SYSTEM",
            fixture.actor.system_id,
            "PublishPolicyBundle",
            1,
            fixture.command.command_id,
        )
        fixture.store.seed(
            command_receipts={
                receipt_key: {
                    "principal_kind": "SYSTEM",
                    "principal_id": fixture.actor.system_id,
                    "command_name": "PublishPolicyBundle",
                    "command_version": 1,
                    "command_id": fixture.command.command_id,
                    "payload_hash": fixture.command.release.manifest_sha256,
                    "status": "COMPLETED",
                    "response_body": {
                        "policy_bundle_id": (
                            fixture.command.release.manifest.policy_bundle_id
                        ),
                        "selector_digest": fixture.selector_digest,
                        "aggregate_version": 1,
                    },
                }
            }
        )
        before = fixture.store.snapshot()
        replay_result, replay_code = self._invoke(fixture)

        changed_manifest = replace(
            fixture.command.release.manifest,
            effective_until=UTC_NOW + timedelta(days=90),
        )
        fixture.command = replace(
            fixture.command,
            release=sign_policy_release(changed_manifest),
        )
        _changed_result, changed_code = self._invoke(fixture)

        self.assertEqual(
            {
                "replay_code": replay_code,
                "replayed": getattr(replay_result, "replayed", None),
                "bundle": getattr(replay_result, "policy_bundle_id", None),
                "changed_code": changed_code,
                "unchanged": fixture.store.snapshot() == before,
                "verifier_calls": len(fixture.verifier.calls),
                "begins": fixture.uow_factory.begin_count,
            },
            {
                "replay_code": None,
                "replayed": True,
                "bundle": fixture.command.release.manifest.policy_bundle_id,
                "changed_code": "IDEMPOTENCY_KEY_REUSED",
                "unchanged": True,
                "verifier_calls": 0,
                "begins": 0,
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

    @staticmethod
    def _status(bundle) -> object:
        status = getattr(bundle, "status", None)
        return getattr(status, "value", status)

    @staticmethod
    def _selector_facts(selector) -> dict[str, object]:
        return {
            name: selector.get(name)
            for name in (
                "canonicalization_version",
                "access_purpose",
                "scope_type",
                "target_role",
                "jurisdiction",
                "locale",
            )
        }

    @staticmethod
    def _event_types(snapshot) -> list[str]:
        return sorted(
            event.get("event_type")
            for event in snapshot.get("outbox_events", {}).values()
            if isinstance(event, dict) and event.get("event_type") is not None
        )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
