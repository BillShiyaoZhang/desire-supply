"""Second semantic RED for complete signed policy release validation.

The first publication slice proves atomic selector replacement.  This matrix
closes the next artifact boundary: a signature covers every ordered
ConsentOffer fact, while a trusted signature still cannot authorize an invalid
manifest or conceal a false independently canonicalized offer digest.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import timedelta, timezone
from enum import Enum
import json
import unittest

from desire_platform.identity_access.application.policy_publication import (
    PolicySelectorScopeType,
)
from desire_platform.identity_access.domain.errors import IamError
from desire_platform.identity_access.domain.invitations import TargetRole
from desire_platform.identity_access.domain.policies import (
    PolicyLegalEffect,
)
from tests.support.iam_policy_issue_builders import (
    UTC_NOW,
    canonical_consent_offer_bytes,
    canonical_consent_offer_sha256,
    canonical_release_manifest_bytes,
    initial_publication_fixture,
    policy_selector_digest,
    publication_with_consent_offer_fixture,
    replacement_publication_fixture,
    sign_policy_release,
)


class _TamperedPurpose(str, Enum):
    AI_ASSISTED_PROCESSING = "AI_ASSISTED_PROCESSING"


class _TamperedScope(str, Enum):
    ORGANIZATION = "ORGANIZATION"


class PublishPolicyBundleReleaseValidationRedTest(unittest.TestCase):
    def test_independent_offer_hash_covers_exact_ordered_server_facts(
        self,
    ) -> None:
        """The offer hash is independent of, then embedded in, the manifest."""

        fixture = publication_with_consent_offer_fixture()
        manifest = fixture.command.release.manifest
        offer = manifest.consent_offers[0]
        offer_payload = json.loads(canonical_consent_offer_bytes(offer))
        release_payload = json.loads(canonical_release_manifest_bytes(manifest))

        self.assertEqual(
            canonical_consent_offer_sha256(offer),
            "abe043f79fa66004fe910428d1a2ac029c3ba1ede9c6136568b9d9ccf3b23f81",
        )
        self.assertEqual(
            offer.canonical_offer_sha256,
            canonical_consent_offer_sha256(offer),
        )
        self.assertEqual(
            release_payload["consent_offers"],
            [
                {
                    **offer_payload,
                    "canonical_offer_sha256": (
                        offer.canonical_offer_sha256
                    ),
                }
            ],
        )
        self.assertEqual(
            list(offer_payload["data_categories"]),
            ["PROFILE", "MATCHING", "RESEARCH"],
        )
        self.assertNotEqual(
            canonical_consent_offer_sha256(
                replace(
                    offer,
                    data_categories=tuple(reversed(offer.data_categories)),
                )
            ),
            offer.canonical_offer_sha256,
        )

    def test_every_offer_field_order_and_reference_tamper_is_pre_uow_invalid(
        self,
    ) -> None:
        """An old signature cannot survive any changed authorization fact."""

        base_fixture = publication_with_consent_offer_fixture()
        base_offer = base_fixture.command.release.manifest.consent_offers[0]
        terms = base_fixture.command.release.manifest.documents[0]
        tampered_offers = {
            "canonicalization-version": replace(
                base_offer,
                canonicalization_version="consent-offer-json-v2",
            ),
            "offer-id": replace(
                base_offer,
                consent_offer_id="consent_offer_pilot_research_0002",
            ),
            "offer-version": replace(base_offer, aggregate_version=2),
            "bundle-reference": replace(
                base_offer,
                policy_bundle_id="policy_bundle_unbound_offer_0002",
            ),
            "purpose": replace(
                base_offer,
                purpose=_TamperedPurpose.AI_ASSISTED_PROCESSING,
            ),
            "scope-type": replace(
                base_offer,
                scope_type=_TamperedScope.ORGANIZATION,
            ),
            "scope-derivation": replace(
                base_offer,
                scope_derivation="ORGANIZATION_FROM_COMMAND",
            ),
            "category-order": replace(
                base_offer,
                data_categories=tuple(reversed(base_offer.data_categories)),
            ),
            "recipient-reference": replace(
                base_offer,
                recipient_reference="research_controller_other_v1",
            ),
            "recipient-label": replace(
                base_offer,
                recipient_label="Another Research Controller",
            ),
            "supporting-document-reference": replace(
                base_offer,
                supporting_document_id=terms.document_id,
            ),
            "supporting-document-hash": replace(
                base_offer,
                supporting_document_sha256=terms.content_sha256,
            ),
            "expiry-rule": replace(
                base_offer,
                expiry_rule="FIXED_NOT_AFTER",
            ),
            "expiry-days": replace(base_offer, expiry_days=None),
            "not-after": replace(
                base_offer,
                not_after=base_offer.not_after + timedelta(days=1),
            ),
            "optional": replace(base_offer, optional=False),
            "claimed-canonical-hash": replace(
                base_offer,
                canonical_offer_sha256="f" * 64,
            ),
        }

        for name, tampered_offer in tampered_offers.items():
            with self.subTest(case=name):
                fixture = publication_with_consent_offer_fixture()
                before = fixture.store.snapshot()
                old_release = fixture.command.release
                fixture.command = replace(
                    fixture.command,
                    release=replace(
                        old_release,
                        manifest=replace(
                            old_release.manifest,
                            consent_offers=(tampered_offer,),
                        ),
                    ),
                )
                _result, code = self._invoke(fixture)
                self.assertEqual(
                    {
                        "code": code,
                        "unchanged": fixture.store.snapshot() == before,
                        "begins": fixture.uow_factory.begin_count,
                        "writes": fixture.uow_factory.write_calls,
                    },
                    {
                        "code": "POLICY_RELEASE_INVALID",
                        "unchanged": True,
                        "begins": 0,
                        "writes": [],
                    },
                )

    def test_re_signed_false_offer_hash_is_independently_rejected_pre_uow(
        self,
    ) -> None:
        """A valid manifest signature cannot make a self-reported hash true."""

        fixture = publication_with_consent_offer_fixture()
        manifest = fixture.command.release.manifest
        offer = manifest.consent_offers[0]
        false_hash_offer = replace(
            offer,
            canonical_offer_sha256="f" * 64,
        )
        self.assertNotEqual(
            false_hash_offer.canonical_offer_sha256,
            canonical_consent_offer_sha256(false_hash_offer),
        )
        fixture.command = replace(
            fixture.command,
            release=sign_policy_release(
                replace(manifest, consent_offers=(false_hash_offer,))
            ),
        )

        self._assert_rejected_without_writes(
            fixture,
            expected_code="POLICY_RELEASE_INVALID",
            expected_begins=0,
        )

    def test_validly_re_signed_illegal_manifest_matrix_is_pre_uow_invalid(
        self,
    ) -> None:
        """Signer authority never bypasses closed manifest domain rules."""

        cases = []

        fixture = initial_publication_fixture()
        manifest = fixture.command.release.manifest
        invalid_selector = replace(
            manifest.selector,
            scope_type=PolicySelectorScopeType.ORGANIZATION_ROLE,
            target_role=TargetRole.ORG_ADMIN,
        )
        cases.append(
            (
                "selector-shape",
                fixture,
                replace(
                    manifest,
                    selector=invalid_selector,
                    selector_digest=policy_selector_digest(invalid_selector),
                ),
            )
        )

        fixture = initial_publication_fixture()
        manifest = fixture.command.release.manifest
        cases.append(
            (
                "duplicate-document-id",
                fixture,
                replace(manifest, documents=(manifest.documents[0],) * 2),
            )
        )

        fixture = initial_publication_fixture()
        manifest = fixture.command.release.manifest
        duplicate_version = replace(
            manifest.documents[0],
            document_id="policy_document_terms_same_version_0002",
        )
        cases.append(
            (
                "duplicate-document-version",
                fixture,
                replace(
                    manifest,
                    documents=manifest.documents + (duplicate_version,),
                ),
            )
        )

        fixture = initial_publication_fixture()
        manifest = fixture.command.release.manifest
        cases.append(
            (
                "unknown-required-document",
                fixture,
                replace(
                    manifest,
                    required_document_ids=(
                        "policy_document_not_in_bundle_0009",
                    ),
                ),
            )
        )

        fixture = publication_with_consent_offer_fixture()
        manifest = fixture.command.release.manifest
        invalid_consent_document = replace(
            manifest.documents[1],
            legal_effect=PolicyLegalEffect.CONTRACT_ACCEPTANCE,
        )
        cases.append(
            (
                "offer-supporting-document-legal-effect",
                fixture,
                replace(
                    manifest,
                    documents=(manifest.documents[0], invalid_consent_document),
                ),
            )
        )

        fixture = initial_publication_fixture()
        manifest = fixture.command.release.manifest
        cases.extend(
            (
                (
                    "future-effective-at",
                    fixture,
                    replace(manifest, effective_at=UTC_NOW + timedelta(seconds=1)),
                ),
                (
                    "naive-effective-at",
                    initial_publication_fixture(),
                    replace(manifest, effective_at=UTC_NOW.replace(tzinfo=None)),
                ),
                (
                    "non-utc-effective-at",
                    initial_publication_fixture(),
                    replace(
                        manifest,
                        effective_at=UTC_NOW.astimezone(
                            timezone(timedelta(hours=8))
                        ),
                    ),
                ),
                (
                    "active-effective-until",
                    initial_publication_fixture(),
                    replace(
                        manifest,
                        effective_until=UTC_NOW + timedelta(days=1),
                    ),
                ),
            )
        )

        for name, case_fixture, invalid_manifest in cases:
            with self.subTest(case=name):
                case_fixture.command = replace(
                    case_fixture.command,
                    release=sign_policy_release(invalid_manifest),
                )
                self._assert_rejected_without_writes(
                    case_fixture,
                    expected_code="POLICY_RELEASE_INVALID",
                    expected_begins=0,
                )

    def test_signed_predecessor_staleness_and_corrupt_current_are_distinct(
        self,
    ) -> None:
        """Caller staleness is 412; impossible persisted current is 503."""

        stale = replacement_publication_fixture()
        stale_manifest = replace(
            stale.command.release.manifest,
            supersedes_policy_bundle_id="policy_bundle_stale_predecessor_009",
        )
        stale.command = replace(
            stale.command,
            release=sign_policy_release(stale_manifest),
        )
        self._assert_rejected_without_writes(
            stale,
            expected_code="PRECONDITION_FAILED",
            expected_begins=1,
        )

        corrupt = replacement_publication_fixture()
        selector = corrupt.store._tables["policy_selectors"][
            corrupt.selector_digest
        ]
        selector["current_bundle_id"] = "policy_bundle_missing_current_009"
        self._assert_rejected_without_writes(
            corrupt,
            expected_code="POLICY_CONFIGURATION_UNAVAILABLE",
            expected_begins=1,
        )

    def _assert_rejected_without_writes(
        self,
        fixture,
        *,
        expected_code: str,
        expected_begins: int,
    ) -> None:
        before = fixture.store.snapshot()
        _result, code = self._invoke(fixture)
        self.assertEqual(
            {
                "code": code,
                "unchanged": fixture.store.snapshot() == before,
                "begins": fixture.uow_factory.begin_count,
                "writes": fixture.uow_factory.write_calls,
                "verifier_calls": len(fixture.verifier.calls),
            },
            {
                "code": expected_code,
                "unchanged": True,
                "begins": expected_begins,
                "writes": [],
                "verifier_calls": 1,
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
