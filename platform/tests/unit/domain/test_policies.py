"""TEST-UNIT-CONSENT-001/003 semantic RED tests for policies and offers."""

from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta, timezone
import unittest

from desire_platform.identity_access.domain.errors import IamError
from desire_platform.identity_access.domain.policies import (
    ConsentOffer,
    ConsentOfferChoice,
    ConsentPurpose,
    ConsentScopeType,
    DataCategory,
    PolicyAcceptance,
    PolicyBundle,
    PolicyBundleStatus,
    PolicyDocument,
    PolicyLegalEffect,
)


class FixedUtcClock:
    """Deterministic server UTC clock used by policy tests."""

    def __init__(self, current: datetime):
        if current.tzinfo is None or current.utcoffset() != timedelta(0):
            raise ValueError("FixedUtcClock requires an aware UTC datetime")
        self._current = current

    def now(self) -> datetime:
        return self._current


class PolicyAndConsentTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.clock = FixedUtcClock(
            datetime(2026, 8, 7, 10, 0, tzinfo=timezone.utc)
        )
        self.terms = PolicyDocument(
            document_id="policy_terms_v1",
            content_sha256="a" * 64,
            legal_effect=PolicyLegalEffect.CONTRACT_ACCEPTANCE,
        )
        self.privacy_notice = PolicyDocument(
            document_id="policy_privacy_v1",
            content_sha256="b" * 64,
            legal_effect=PolicyLegalEffect.NOTICE_ACKNOWLEDGEMENT,
        )
        self.research_consent = PolicyDocument(
            document_id="policy_research_consent_v1",
            content_sha256="c" * 64,
            legal_effect=PolicyLegalEffect.CONSENT_TEXT,
        )
        self.pilot_end = datetime(2026, 12, 31, 23, 59, tzinfo=timezone.utc)
        self.research_offer = ConsentOffer.pilot_research(
            consent_offer_id="consent_offer_research_v1",
            aggregate_version=1,
            supporting_document_id=self.research_consent.document_id,
            supporting_document_sha256=self.research_consent.content_sha256,
            recipient_reference="research_controller_v1",
            pilot_ends_at=self.pilot_end,
        )
        self.bundle = PolicyBundle(
            policy_bundle_id="policy_bundle_creator_v1",
            selector_digest="d" * 64,
            status=PolicyBundleStatus.ACTIVE,
            effective_at=self.clock.now() - timedelta(days=1),
            effective_until=None,
            documents=(self.terms, self.privacy_notice, self.research_consent),
            required_document_ids=(
                self.terms.document_id,
                self.privacy_notice.document_id,
            ),
            consent_offers=(self.research_offer,),
        )

    def assert_iam_error(self, expected_code, operation) -> None:
        with self.assertRaises(IamError) as raised:
            operation()
        self.assertEqual(raised.exception.code, expected_code)

    def exact_policy_acceptances(self):
        return (
            PolicyAcceptance(
                document_id=self.terms.document_id,
                content_sha256=self.terms.content_sha256,
                affirmed=True,
            ),
            PolicyAcceptance(
                document_id=self.privacy_notice.document_id,
                content_sha256=self.privacy_notice.content_sha256,
                affirmed=True,
            ),
        )

    def evaluate(self, *, policy_acceptances=None, consent_choices=(), bundle_id=None):
        return self.bundle.evaluate(
            now=self.clock.now(),
            presented_bundle_id=bundle_id or self.bundle.policy_bundle_id,
            policy_acceptances=(
                self.exact_policy_acceptances()
                if policy_acceptances is None
                else policy_acceptances
            ),
            consent_choices=consent_choices,
        )

    def test_req_consent_001_requires_exact_bundle_document_hash_and_affirmation(self):
        """Required documents are accepted only as one exact affirmative set."""

        evaluation = self.evaluate()
        self.assertEqual(
            {
                (acceptance.document_id, acceptance.content_sha256)
                for acceptance in evaluation.policy_acceptances
            },
            {
                (self.terms.document_id, self.terms.content_sha256),
                (
                    self.privacy_notice.document_id,
                    self.privacy_notice.content_sha256,
                ),
            },
        )

        self.assert_iam_error(
            "POLICY_BUNDLE_CHANGED",
            lambda: self.evaluate(bundle_id="policy_bundle_superseding_v2"),
        )
        self.assert_iam_error(
            "POLICY_ACCEPTANCE_REQUIRED",
            lambda: self.evaluate(
                policy_acceptances=(self.exact_policy_acceptances()[0],)
            ),
        )
        self.assert_iam_error(
            "POLICY_ACCEPTANCE_REQUIRED",
            lambda: self.evaluate(
                policy_acceptances=(
                    self.exact_policy_acceptances()[0],
                    PolicyAcceptance(
                        document_id=self.privacy_notice.document_id,
                        content_sha256=self.privacy_notice.content_sha256,
                        affirmed=False,
                    ),
                )
            ),
        )

        for bad_acceptance in (
            PolicyAcceptance(
                document_id="policy_other",
                content_sha256=self.privacy_notice.content_sha256,
                affirmed=True,
            ),
            PolicyAcceptance(
                document_id=self.privacy_notice.document_id,
                content_sha256="d" * 64,
                affirmed=True,
            ),
        ):
            with self.subTest(bad_acceptance=bad_acceptance):
                self.assert_iam_error(
                    "POLICY_DOCUMENT_MISMATCH",
                    lambda bad_acceptance=bad_acceptance: self.evaluate(
                        policy_acceptances=(
                            self.exact_policy_acceptances()[0],
                            bad_acceptance,
                        )
                    ),
                )

    def test_req_consent_001_pilot_research_is_derived_only_from_exact_offer_choice(self):
        """A choice confirms an offer; it cannot author purpose or authorization fields."""

        choice = ConsentOfferChoice(
            consent_offer_id=self.research_offer.consent_offer_id,
            document_id=self.research_consent.document_id,
            content_sha256=self.research_consent.content_sha256,
            affirmed=True,
        )
        evaluation = self.evaluate(consent_choices=(choice,))

        self.assertEqual(len(evaluation.consent_authorizations), 1)
        authorization = evaluation.consent_authorizations[0]
        self.assertEqual(
            authorization.consent_offer_id,
            self.research_offer.consent_offer_id,
        )
        self.assertEqual(authorization.consent_offer_version, 1)
        self.assertEqual(authorization.policy_bundle_id, self.bundle.policy_bundle_id)
        self.assertEqual(authorization.purpose, ConsentPurpose.PILOT_RESEARCH)
        self.assertEqual(
            authorization.scope_type,
            ConsentScopeType.PLATFORM_PARTICIPATION,
        )
        self.assertIsNone(authorization.scope_id)
        self.assertEqual(
            authorization.data_categories,
            (
                DataCategory.PROFILE,
                DataCategory.MATCHING,
                DataCategory.RESEARCH,
            ),
        )
        self.assertEqual(
            authorization.recipient_reference,
            "research_controller_v1",
        )
        self.assertEqual(
            authorization.supporting_policy_document_id,
            self.research_consent.document_id,
        )
        self.assertEqual(
            authorization.supporting_document_sha256,
            self.research_consent.content_sha256,
        )
        self.assertEqual(authorization.expires_at, self.pilot_end)

        with self.assertRaises(TypeError):
            ConsentOfferChoice(
                consent_offer_id=self.research_offer.consent_offer_id,
                document_id=self.research_consent.document_id,
                content_sha256=self.research_consent.content_sha256,
                affirmed=True,
                purpose=ConsentPurpose.PILOT_RESEARCH,
            )

    def test_req_consent_001_missing_or_false_optional_choice_grants_nothing(self):
        """Optional consent omission or false never becomes an affirmative grant."""

        omitted = self.evaluate(consent_choices=())
        declined = self.evaluate(
            consent_choices=(
                ConsentOfferChoice(
                    consent_offer_id=self.research_offer.consent_offer_id,
                    document_id=self.research_consent.document_id,
                    content_sha256=self.research_consent.content_sha256,
                    affirmed=False,
                ),
            )
        )

        self.assertEqual(omitted.consent_authorizations, ())
        self.assertEqual(declined.consent_authorizations, ())

    def test_req_consent_001_offer_document_and_hash_cannot_be_substituted(self):
        """An offer choice cannot select another offer or supporting document."""

        invalid_choices = (
            ConsentOfferChoice(
                consent_offer_id="consent_offer_other",
                document_id=self.research_consent.document_id,
                content_sha256=self.research_consent.content_sha256,
                affirmed=True,
            ),
            ConsentOfferChoice(
                consent_offer_id=self.research_offer.consent_offer_id,
                document_id=self.terms.document_id,
                content_sha256=self.research_consent.content_sha256,
                affirmed=True,
            ),
            ConsentOfferChoice(
                consent_offer_id=self.research_offer.consent_offer_id,
                document_id=self.research_consent.document_id,
                content_sha256="e" * 64,
                affirmed=True,
            ),
        )

        for choice in invalid_choices:
            with self.subTest(choice=choice):
                self.assert_iam_error(
                    "CONSENT_OFFER_MISMATCH",
                    lambda choice=choice: self.evaluate(consent_choices=(choice,)),
                )

    def test_req_consent_001_offer_expiry_is_the_earlier_server_derived_deadline(self):
        """Clients cannot select expiry; the offer caps it at 365 days or pilot end."""

        later_offer = ConsentOffer.pilot_research(
            consent_offer_id="consent_offer_research_long_pilot",
            aggregate_version=1,
            supporting_document_id=self.research_consent.document_id,
            supporting_document_sha256=self.research_consent.content_sha256,
            recipient_reference="research_controller_v1",
            pilot_ends_at=self.clock.now() + timedelta(days=800),
        )
        bundle = PolicyBundle(
            policy_bundle_id="policy_bundle_long_pilot",
            selector_digest="d" * 64,
            status=PolicyBundleStatus.ACTIVE,
            effective_at=self.clock.now() - timedelta(days=1),
            effective_until=None,
            documents=(self.terms, self.privacy_notice, self.research_consent),
            required_document_ids=(
                self.terms.document_id,
                self.privacy_notice.document_id,
            ),
            consent_offers=(later_offer,),
        )
        evaluation = bundle.evaluate(
            now=self.clock.now(),
            presented_bundle_id=bundle.policy_bundle_id,
            policy_acceptances=self.exact_policy_acceptances(),
            consent_choices=(
                ConsentOfferChoice(
                    consent_offer_id=later_offer.consent_offer_id,
                    document_id=self.research_consent.document_id,
                    content_sha256=self.research_consent.content_sha256,
                    affirmed=True,
                ),
            ),
        )

        self.assertEqual(
            evaluation.consent_authorizations[0].expires_at,
            self.clock.now() + timedelta(days=365),
        )
        with self.assertRaises((FrozenInstanceError, AttributeError)):
            later_offer.pilot_ends_at = self.clock.now()


if __name__ == "__main__":
    unittest.main()
