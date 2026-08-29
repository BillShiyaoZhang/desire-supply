"""Focused executable specification for deterministic-matcher-v1."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from datetime import date
from fractions import Fraction
import hashlib
import json
from pathlib import Path
import unittest
from unittest.mock import patch

import desire_platform.matching.engine_v1 as engine
from desire_platform.matching.domain.model import CandidateEligibility
from desire_platform.matching.engine_v1 import (
    COMPONENT_CODES,
    HARD_FILTER_CODES,
    DeterministicMatcherV1Error,
    component_scores_v1,
    demand_postgres_snapshot_to_input_v1,
    evaluate_candidate_hard_filters_v1,
    evaluate_match_run_v1,
    load_default_rule_release_v1,
    load_rule_release_v1,
    normalize_match_run_input_v1,
)
from tests.support.demand_postgres_builders import match_input_snapshot


RESOURCE_ROOT = (
    Path(__file__).resolve().parents[2]
    / "src/desire_platform/matching/resources"
)
ENGINE_SPEC = RESOURCE_ROOT / "deterministic-matcher-v1.engine.json"
GOLDENS = RESOURCE_ROOT / "deterministic-matcher-v1.golden.json"
DEFAULT_RULE = RESOURCE_ROOT / "internal-sandbox-matching-rule-release-v1.json"

ENGINE_ARTIFACT_SHA256 = (
    "f00ca4864a86a90bec51e9f93e61da75c86016213942d416c604fcfe5fe6c79e"
)
GOLDEN_RESOURCE_SHA256 = (
    "ae44d64cc44e86a79cb81314c168b4c5e637fbd6b882f2d2e4151cebe13a323f"
)
DEFAULT_MANIFEST_SHA256 = (
    "7955850bf01a142cb555a82f5da8ad519beaf3e93277aad2c791e791e35838d2"
)


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _json_resource(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _base_input() -> dict:
    vectors = _json_resource(GOLDENS)["vectors"]
    value = deepcopy(vectors[0]["run_input"])
    value["demand"]["budget_override_code"] = None
    value["profiles"][0]["within_offered_budget"] = True
    return value


def _rule_variant(mutate) -> object:
    document = _json_resource(DEFAULT_RULE)
    mutate(document)
    return load_rule_release_v1(_canonical(document), verify_golden_vectors=False)


class DeterministicMatcherV1ArtifactTests(unittest.TestCase):
    def test_default_release_loads_and_verifies_real_artifact_and_goldens(self) -> None:
        rule = load_default_rule_release_v1()
        self.assertEqual(
            (
                rule.bundle_id,
                rule.selector_digest,
                rule.taxonomy_bundle_id,
                rule.engine_identifier,
                rule.engine_major,
                rule.engine_artifact_sha256,
                rule.canonical_manifest_sha256,
                rule.invitation_limit,
                tuple(item.weight_bps for item in rule.components),
            ),
            (
                "53000000-0000-4000-8000-000000000001",
                "3bd2f51daac99e67e0da34eb15134ab3cc3a786c994899c5246fe33689179ead",
                "50000000-0000-4000-8000-000000000001",
                "deterministic-matcher-v1",
                1,
                ENGINE_ARTIFACT_SHA256,
                DEFAULT_MANIFEST_SHA256,
                10,
                (3000, 2500, 1500, 1500, 1000, 500),
            ),
        )
        self.assertEqual(
            hashlib.sha256(ENGINE_SPEC.read_bytes().rstrip(b"\n")).hexdigest(),
            ENGINE_ARTIFACT_SHA256,
        )
        self.assertEqual(
            hashlib.sha256(GOLDENS.read_bytes().rstrip(b"\n")).hexdigest(),
            GOLDEN_RESOURCE_SHA256,
        )
        self.assertEqual(
            hashlib.sha256(DEFAULT_RULE.read_bytes().rstrip(b"\n")).hexdigest(),
            DEFAULT_MANIFEST_SHA256,
        )

    def test_rule_loader_rejects_noncanonical_extra_order_code_weight_and_digest(self) -> None:
        valid = _json_resource(DEFAULT_RULE)
        cases = []

        extra = deepcopy(valid)
        extra["signature"] = "forbidden"
        cases.append((extra, "MATCH_RULE_RELEASE_INVALID"))

        wrong_order = deepcopy(valid)
        wrong_order["hard_filters"][0], wrong_order["hard_filters"][1] = (
            wrong_order["hard_filters"][1],
            wrong_order["hard_filters"][0],
        )
        cases.append((wrong_order, "MATCH_RULE_RELEASE_INVALID"))

        wrong_code = deepcopy(valid)
        wrong_code["components"][0]["code"] = "availability"
        cases.append((wrong_code, "MATCH_RULE_RELEASE_INVALID"))

        wrong_weight = deepcopy(valid)
        wrong_weight["components"][0]["weight_bps"] = 2999
        cases.append((wrong_weight, "MATCH_RULE_RELEASE_INVALID"))

        bool_weight = deepcopy(valid)
        bool_weight["components"][0]["weight_bps"] = True
        cases.append((bool_weight, "MATCH_RULE_RELEASE_INVALID"))

        for value, expected in cases:
            with self.subTest(expected=expected, mutation=list(value)):
                with self.assertRaises(DeterministicMatcherV1Error) as observed:
                    load_rule_release_v1(
                        _canonical(value), verify_golden_vectors=False
                    )
                self.assertEqual(observed.exception.code, expected)

        with self.assertRaises(DeterministicMatcherV1Error) as observed:
            load_rule_release_v1(
                json.dumps(valid, indent=2).encode("utf-8"),
                verify_golden_vectors=False,
            )
        self.assertEqual(
            observed.exception.code, "MATCH_RULE_RELEASE_CANONICAL_MISMATCH"
        )

        with self.assertRaises(DeterministicMatcherV1Error) as observed:
            load_rule_release_v1(
                _canonical(valid),
                expected_manifest_sha256="0" * 64,
                verify_golden_vectors=False,
            )
        self.assertEqual(
            observed.exception.code, "MATCH_RULE_RELEASE_DIGEST_MISMATCH"
        )

    def test_unknown_engine_major_and_artifact_corruption_fail_closed(self) -> None:
        base = _json_resource(DEFAULT_RULE)
        mutations = (
            ("engine_identifier", "future-matcher-v2", "MATCH_RULE_RELEASE_INVALID"),
            ("engine_major", 2, "MATCH_RULE_RELEASE_INVALID"),
            ("engine_artifact_sha256", "0" * 64, "MATCH_ENGINE_ARTIFACT_MISMATCH"),
        )
        for member, value, expected in mutations:
            broken = deepcopy(base)
            broken[member] = value
            with self.subTest(member=member):
                with self.assertRaises(DeterministicMatcherV1Error) as observed:
                    load_rule_release_v1(
                        _canonical(broken), verify_golden_vectors=False
                    )
                self.assertEqual(observed.exception.code, expected)

        spec = _json_resource(ENGINE_SPEC)
        spec["arithmetic"]["rounding_mode"] = "ROUND_HALF_UP"
        with self.assertRaises(DeterministicMatcherV1Error) as observed:
            load_rule_release_v1(
                DEFAULT_RULE.read_bytes().rstrip(b"\n"),
                engine_spec_bytes=_canonical(spec),
                golden_vectors_bytes=GOLDENS.read_bytes().rstrip(b"\n"),
                verify_golden_vectors=False,
            )
        self.assertEqual(observed.exception.code, "MATCH_ENGINE_ARTIFACT_INVALID")

    def test_golden_vector_input_and_result_corruption_are_rejected(self) -> None:
        broken_input = _json_resource(GOLDENS)
        broken_input["vectors"][0]["run_input"]["demand"][
            "required_weekly_hours"
        ] = 11
        with self.assertRaises(DeterministicMatcherV1Error) as observed:
            load_rule_release_v1(
                DEFAULT_RULE.read_bytes().rstrip(b"\n"),
                golden_vectors_bytes=_canonical(broken_input),
            )
        self.assertEqual(observed.exception.code, "MATCH_ENGINE_ARTIFACT_INVALID")

        broken_result = _json_resource(DEFAULT_RULE)
        broken_result["golden_vectors"][0]["expected_result_sha256"] = "0" * 64
        with self.assertRaises(DeterministicMatcherV1Error) as observed:
            load_rule_release_v1(_canonical(broken_result))
        self.assertEqual(observed.exception.code, "MATCH_GOLDEN_VECTOR_INVALID")


class DeterministicMatcherV1InputTests(unittest.TestCase):
    def test_closed_input_rejects_extra_malformed_bool_order_and_digest_drift(self) -> None:
        valid = _base_input()
        cases = []
        extra = deepcopy(valid)
        extra["profiles"][0]["contact"] = "private@example.invalid"
        cases.append(extra)
        bool_level = deepcopy(valid)
        bool_level["profiles"][0]["interest_intensity"] = True
        cases.append(bool_level)
        unordered = deepcopy(valid)
        unordered["demand"]["required_language_codes"].reverse()
        cases.append(unordered)
        duplicate = deepcopy(valid)
        duplicate["profiles"].append(deepcopy(duplicate["profiles"][0]))
        cases.append(duplicate)
        inactive = deepcopy(valid)
        inactive["profiles"][0]["status"] = "INACTIVE"
        cases.append(inactive)
        for value in cases:
            with self.subTest(value=value):
                with self.assertRaises(DeterministicMatcherV1Error) as observed:
                    normalize_match_run_input_v1(value)
                self.assertEqual(observed.exception.code, "MATCH_RUN_INPUT_INVALID")

        with self.assertRaises(DeterministicMatcherV1Error) as observed:
            normalize_match_run_input_v1(
                json.dumps(valid, indent=1).encode("utf-8")
            )
        self.assertEqual(
            observed.exception.code, "MATCH_RUN_INPUT_CANONICAL_MISMATCH"
        )

        with self.assertRaises(DeterministicMatcherV1Error) as observed:
            normalize_match_run_input_v1(
                valid, expected_input_set_sha256="0" * 64
            )
        self.assertEqual(
            observed.exception.code, "MATCH_RUN_INPUT_DIGEST_MISMATCH"
        )

        normalized = normalize_match_run_input_v1(valid)
        with self.assertRaises(DeterministicMatcherV1Error) as observed:
            normalize_match_run_input_v1(
                valid, expected_canonical_sha256="0" * 64
            )
        self.assertNotEqual(normalized.canonical_input_sha256, "0" * 64)
        self.assertEqual(
            observed.exception.code, "MATCH_RUN_INPUT_DIGEST_MISMATCH"
        )

    def test_candidate_order_is_normalized_and_zero_candidates_are_valid(self) -> None:
        rule = load_default_rule_release_v1()
        tie = deepcopy(_json_resource(GOLDENS)["vectors"][2]["run_input"])
        first = evaluate_match_run_v1(tie, rule)
        tie["profiles"].reverse()
        second = evaluate_match_run_v1(tie, rule)
        self.assertEqual(first.canonical_result_bytes, second.canonical_result_bytes)
        self.assertEqual(
            tuple(item.creator_user_id for item in first.candidates),
            (
                "72000000-0000-4000-8000-000000000003",
                "72000000-0000-4000-8000-000000000004",
            ),
        )
        self.assertEqual(tuple(item.rank for item in first.candidates), (1, 2))

        empty = _base_input()
        empty["profiles"] = []
        result = evaluate_match_run_v1(empty, rule)
        self.assertEqual(result.candidates, ())
        self.assertEqual(result.candidate_documents, ())
        self.assertEqual(result.result_document["candidates"], [])
        self.assertRegex(result.ordered_result_sha256, r"^[a-f0-9]{64}$")

    def test_demand_postgres_snapshot_has_a_strict_worker_ready_mapping(self) -> None:
        snapshot = match_input_snapshot()
        mapped = demand_postgres_snapshot_to_input_v1(snapshot)
        self.assertEqual(
            (
                mapped["currency"],
                mapped["required_weekly_hours"],
                mapped["budget_override_code"],
            ),
            (snapshot.currency, snapshot.required_weekly_hours, None),
        )
        self.assertEqual(
            set(mapped),
            {
                "problem_type_codes",
                "domain_codes",
                "task_codes",
                "must_have_skills",
                "nice_to_have_skills",
                "start_date",
                "due_date",
                "required_weekly_hours",
                "required_duration_weeks",
                "currency",
                "minimum_amount_minor",
                "maximum_amount_minor",
                "allowed_region_codes",
                "required_language_codes",
                "required_work_mode_code",
                "data_sensitivity_code",
                "ai_use_code",
                "budget_override_code",
            },
        )
        with self.assertRaises(DeterministicMatcherV1Error) as observed:
            demand_postgres_snapshot_to_input_v1(object())
        self.assertEqual(
            observed.exception.code, "MATCH_INPUT_NORMALIZATION_UNAVAILABLE"
        )


class DeterministicMatcherV1FilterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.rule = load_default_rule_release_v1()
        cls.normalized = normalize_match_run_input_v1(_base_input())

    def test_all_fifteen_filters_execute_and_preserve_manifest_order(self) -> None:
        demand = replace(
            self.normalized.demand,
            ai_use_code="REQUIRED",
            budget_override_code=None,
        )
        profile = replace(
            self.normalized.profiles[0],
            status="INACTIVE",
            prohibited_domain_codes=("DOMAIN.ENERGY",),
            prohibited_task_codes=("TASK.ANALYZE",),
            skills=(),
            available_from=date(2035, 3, 1),
            available_weekly_hours=0,
            available_duration_weeks=0,
            currency="USD",
            within_offered_budget=False,
            allowed_data_sensitivity_codes=(),
            ai_use_code="PROHIBITED",
            language_codes=("LANGUAGE.FR",),
            work_mode_code="WORK_MODE.ONSITE",
            region_code="REGION.US",
            location_eligible=False,
            conflict_of_interest=True,
        )
        self.assertEqual(
            evaluate_candidate_hard_filters_v1(
                demand=demand, profile=profile, rule=self.rule
            ),
            HARD_FILTER_CODES,
        )

    def test_each_filter_has_an_independent_trigger(self) -> None:
        demand = self.normalized.demand
        profile = self.normalized.profiles[0]
        cases = {
            "CREATOR_INACTIVE": (demand, replace(profile, status="INACTIVE")),
            "BOUNDARY_DOMAIN": (
                demand,
                replace(profile, prohibited_domain_codes=("DOMAIN.ENERGY",)),
            ),
            "BOUNDARY_TASK": (
                demand,
                replace(profile, prohibited_task_codes=("TASK.ANALYZE",)),
            ),
            "MISSING_MUST_HAVE_SKILL": (demand, replace(profile, skills=())),
            "DATE_CONFLICT": (
                demand,
                replace(profile, available_from=date(2035, 3, 1)),
            ),
            "CAPACITY_CONFLICT": (
                demand,
                replace(profile, available_weekly_hours=9),
            ),
            "DURATION_CONFLICT": (
                demand,
                replace(profile, available_duration_weeks=5),
            ),
            "CURRENCY_MISMATCH": (demand, replace(profile, currency="USD")),
            "BELOW_PRIVATE_FLOOR": (
                demand,
                replace(profile, within_offered_budget=False),
            ),
            "DATA_POLICY_CONFLICT": (
                demand,
                replace(profile, allowed_data_sensitivity_codes=()),
            ),
            "AI_POLICY_CONFLICT": (
                replace(demand, ai_use_code="REQUIRED"),
                replace(profile, ai_use_code="PROHIBITED"),
            ),
            "LANGUAGE_MISMATCH": (
                demand,
                replace(profile, language_codes=("LANGUAGE.FR",)),
            ),
            "WORK_MODE_CONFLICT": (
                demand,
                replace(profile, work_mode_code="WORK_MODE.ONSITE"),
            ),
            "LOCATION_RESTRICTION": (
                demand,
                replace(profile, location_eligible=False),
            ),
            "CONFLICT_OF_INTEREST": (
                demand,
                replace(profile, conflict_of_interest=True),
            ),
        }
        self.assertEqual(tuple(cases), HARD_FILTER_CODES)
        for expected, (candidate_demand, candidate_profile) in cases.items():
            with self.subTest(expected=expected):
                self.assertEqual(
                    evaluate_candidate_hard_filters_v1(
                        demand=candidate_demand,
                        profile=candidate_profile,
                        rule=self.rule,
                    ),
                    (expected,),
                )

    def test_disabled_filter_is_skipped_without_changing_ordinal_surface(self) -> None:
        rule = _rule_variant(
            lambda value: value["hard_filters"][1].update(enabled=False)
        )
        value = _base_input()
        value["profiles"][0]["prohibited_domain_codes"] = ["DOMAIN.ENERGY"]
        result = evaluate_match_run_v1(value, rule)
        self.assertEqual(result.candidates[0].eligibility, CandidateEligibility.ELIGIBLE)
        self.assertEqual(
            tuple((item.code, item.ordinal) for item in rule.hard_filters),
            tuple(zip(HARD_FILTER_CODES, range(1, 16))),
        )

    def test_approved_exception_is_the_only_private_floor_bypass(self) -> None:
        rule = self.rule
        value = _base_input()
        value["profiles"][0]["within_offered_budget"] = False
        excluded = evaluate_match_run_v1(value, rule)
        self.assertEqual(
            excluded.candidates[0].exclusion_reason_codes,
            ("BELOW_PRIVATE_FLOOR",),
        )

        value["demand"]["budget_override_code"] = "APPROVED_EXCEPTION"
        allowed = evaluate_match_run_v1(value, rule)
        self.assertEqual(allowed.candidates[0].eligibility, CandidateEligibility.ELIGIBLE)
        self.assertEqual(
            dict(
                (item.code, item.score)
                for item in allowed.candidates[0].components
            )["compensation"],
            engine.Decimal("60.00"),
        )

        value["profiles"][0]["currency"] = "USD"
        still_excluded = evaluate_match_run_v1(value, rule)
        self.assertEqual(
            still_excluded.candidates[0].exclusion_reason_codes,
            ("CURRENCY_MISMATCH",),
        )


class DeterministicMatcherV1ScoringTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.rule = load_default_rule_release_v1()
        cls.normalized = normalize_match_run_input_v1(_base_input())

    def test_exact_rational_formulas_produce_six_real_components(self) -> None:
        components, total = component_scores_v1(
            demand=self.normalized.demand,
            profile=self.normalized.profiles[0],
            rule=self.rule,
        )
        self.assertEqual(tuple(item.code for item in components), COMPONENT_CODES)
        self.assertEqual(
            tuple(item.score for item in components),
            tuple(
                engine.Decimal(value)
                for value in (
                    "100.00",
                    "92.50",
                    "91.67",
                    "100.00",
                    "100.00",
                    "87.50",
                )
            ),
        )
        self.assertEqual(total, engine.Decimal("96.25"))

    def test_interest_capability_and_evidence_trust_materially_vary(self) -> None:
        demand = self.normalized.demand
        strong = self.normalized.profiles[0]
        weak_interest = replace(strong, interest_intensity=0)
        weak_evidence_skill = replace(
            strong.skills[0], evidence_trust_level=0, evidence_bucket="NONE"
        )
        weak_evidence = replace(strong, skills=(weak_evidence_skill,))
        strong_scores = dict(
            (item.code, item.score)
            for item in component_scores_v1(
                demand=demand, profile=strong, rule=self.rule
            )[0]
        )
        interest_scores = dict(
            (item.code, item.score)
            for item in component_scores_v1(
                demand=demand, profile=weak_interest, rule=self.rule
            )[0]
        )
        evidence_scores = dict(
            (item.code, item.score)
            for item in component_scores_v1(
                demand=demand, profile=weak_evidence, rule=self.rule
            )[0]
        )
        self.assertEqual(interest_scores["interest"], engine.Decimal("60.00"))
        self.assertLess(evidence_scores["capability"], strong_scores["capability"])
        self.assertLess(
            evidence_scores["evidence_trust"],
            strong_scores["evidence_trust"],
        )

    def test_availability_boundaries_and_half_even_rounding_are_exact(self) -> None:
        profile = replace(
            self.normalized.profiles[0],
            available_weekly_hours=self.normalized.demand.required_weekly_hours,
            available_duration_weeks=self.normalized.demand.required_duration_weeks,
        )
        scores = dict(
            (item.code, item.score)
            for item in component_scores_v1(
                demand=self.normalized.demand,
                profile=profile,
                rule=self.rule,
            )[0]
        )
        self.assertEqual(scores["availability"], engine.Decimal("62.50"))
        self.assertEqual(engine._round_fraction_score(Fraction(1, 200)), engine.Decimal("0.00"))
        self.assertEqual(engine._round_fraction_score(Fraction(3, 200)), engine.Decimal("0.02"))
        self.assertEqual(engine._round_fraction_score(Fraction(5, 200)), engine.Decimal("0.02"))
        self.assertEqual(engine._round_fraction_score(Fraction(7, 200)), engine.Decimal("0.04"))

        zero_required = replace(
            self.normalized.demand,
            required_weekly_hours=0,
            required_duration_weeks=0,
            due_date=self.normalized.demand.start_date,
        )
        zero_scores = dict(
            (item.code, item.score)
            for item in component_scores_v1(
                demand=zero_required,
                profile=replace(
                    self.normalized.profiles[0],
                    available_from=zero_required.start_date,
                ),
                rule=self.rule,
            )[0]
        )
        self.assertEqual(zero_scores["availability"], engine.Decimal("100.00"))

    def test_valid_configured_basis_point_weights_drive_the_total(self) -> None:
        def interest_only(value: dict) -> None:
            for component in value["components"]:
                component["weight_bps"] = (
                    10000 if component["code"] == "interest" else 0
                )

        rule = _rule_variant(interest_only)
        components, total = component_scores_v1(
            demand=self.normalized.demand,
            profile=self.normalized.profiles[0],
            rule=rule,
        )
        self.assertEqual(sum(item.weight_bps for item in rule.components), 10000)
        self.assertEqual(
            dict((item.code, item.score) for item in components)["interest"],
            engine.Decimal("100.00"),
        )
        self.assertEqual(total, engine.Decimal("100.00"))

    def test_candidate_documents_are_exact_closed_schema_and_output_is_private(self) -> None:
        value = _base_input()
        value["profiles"][0]["private_floor_evidence_digest"] = "f" * 64
        result = evaluate_match_run_v1(value, self.rule)
        candidate = result.candidate_documents[0]
        self.assertEqual(
            set(candidate),
            {
                "schema_version",
                "canonicalization_version",
                "attempt_id",
                "run_id",
                "creator_user_id",
                "profile_id",
                "profile_version_id",
                "profile_content_sha256",
                "eligibility",
                "exclusion_reason_codes",
                "components",
                "total_score",
                "rank",
                "evidence_facts",
                "candidate_result_sha256",
            },
        )
        self.assertNotIn("evidence_version_digest", candidate)
        self.assertEqual(
            result.candidate_evidence_bindings[0].evidence_version_digest,
            value["profiles"][0]["evidence_version_digest"],
        )
        serialized = result.canonical_result_bytes.decode("utf-8")
        for banned in (
            "contact",
            "protected_attribute",
            "private_floor_amount",
            "precise_location",
            "conflict_object",
            "provider_locator",
            "review_note",
        ):
            with self.subTest(banned=banned):
                self.assertNotIn(banned, serialized.lower())
        self.assertEqual(
            hashlib.sha256(result.canonical_result_bytes).hexdigest(),
            result.engine_result_sha256,
        )

    def test_loaded_rule_and_input_cannot_be_tampered_via_replace(self) -> None:
        replaced_rule = replace(
            self.rule,
            invitation_limit=99,
        )
        with self.assertRaises(DeterministicMatcherV1Error) as observed:
            evaluate_match_run_v1(self.normalized, replaced_rule)
        self.assertEqual(observed.exception.code, "MATCH_RULE_RELEASE_INVALID")

        replaced_input = replace(
            self.normalized,
            input_set_sha256="0" * 64,
        )
        with self.assertRaises(DeterministicMatcherV1Error) as observed:
            evaluate_match_run_v1(replaced_input, self.rule)
        self.assertEqual(observed.exception.code, "MATCH_RUN_INPUT_DIGEST_MISMATCH")

    def test_evaluation_is_pure_and_performs_no_resource_io(self) -> None:
        with patch.object(
            engine,
            "_resource_bytes",
            side_effect=AssertionError("evaluator attempted resource I/O"),
        ):
            result = evaluate_match_run_v1(self.normalized, self.rule)
        self.assertEqual(result.candidates[0].total_score, engine.Decimal("96.25"))


if __name__ == "__main__":
    unittest.main()
