"""Deterministic, privacy-bounded Matching engine v1.

The engine is deliberately pure.  It accepts the closed ``match-run-input-v1``
value surface and a reviewed ``matching-rule-release-v1`` manifest, performs no
I/O, and returns immutable domain candidates plus canonical persistence
documents.  PostgreSQL capture, leases, fencing, and completion remain outside
this module.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from decimal import Decimal
from fractions import Fraction
import hashlib
from importlib import resources
import json
import re
from typing import Any, Mapping, Optional, Sequence, Tuple, Union

from desire_platform.matching.domain.model import (
    CandidateEligibility,
    ComponentScore,
    EvidenceFact,
    MatchCandidate,
    canonical_candidate_result_bytes,
    deterministic_rank_and_hash,
)


ENGINE_IDENTIFIER = "deterministic-matcher-v1"
ENGINE_MAJOR = 1
ENGINE_SPEC_RESOURCE = "deterministic-matcher-v1.engine.json"
GOLDEN_VECTORS_RESOURCE = "deterministic-matcher-v1.golden.json"
DEFAULT_RULE_RESOURCE = "internal-sandbox-matching-rule-release-v1.json"

HARD_FILTER_CODES = (
    "CREATOR_INACTIVE",
    "BOUNDARY_DOMAIN",
    "BOUNDARY_TASK",
    "MISSING_MUST_HAVE_SKILL",
    "DATE_CONFLICT",
    "CAPACITY_CONFLICT",
    "DURATION_CONFLICT",
    "CURRENCY_MISMATCH",
    "BELOW_PRIVATE_FLOOR",
    "DATA_POLICY_CONFLICT",
    "AI_POLICY_CONFLICT",
    "LANGUAGE_MISMATCH",
    "WORK_MODE_CONFLICT",
    "LOCATION_RESTRICTION",
    "CONFLICT_OF_INTEREST",
)

COMPONENT_CODES = (
    "interest",
    "capability",
    "availability",
    "compensation",
    "collaboration",
    "evidence_trust",
)

_RULE_ROOT_KEYS = frozenset(
    {
        "schema_version",
        "canonicalization_version",
        "bundle_id",
        "semantic_version",
        "selector_digest",
        "jurisdiction_code",
        "locale",
        "demand_type_code",
        "taxonomy_family_code",
        "engine_identifier",
        "engine_major",
        "engine_artifact_sha256",
        "taxonomy_bundle_id",
        "budget_rule_version",
        "matching_rule_version",
        "reason_code_version",
        "explanation_template_version",
        "hard_filters",
        "components",
        "invitation_limit",
        "golden_vectors",
        "effective_at",
        "effective_until",
    }
)

_RUN_INPUT_ROOT_KEYS = frozenset(
    {
        "schema_version",
        "canonicalization_version",
        "attempt_id",
        "run_id",
        "demand_id",
        "demand_version_id",
        "matching_rule_bundle_id",
        "input_set_sha256",
        "demand",
        "profiles",
    }
)

_DEMAND_KEYS = frozenset(
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
    }
)

_PROFILE_KEYS = frozenset(
    {
        "creator_user_id",
        "profile_id",
        "profile_version_id",
        "profile_content_sha256",
        "evidence_version_digest",
        "status",
        "interest_problem_type_codes",
        "interest_domain_codes",
        "interest_task_codes",
        "interest_intensity",
        "prohibited_domain_codes",
        "prohibited_task_codes",
        "skills",
        "available_from",
        "available_weekly_hours",
        "available_duration_weeks",
        "currency",
        "within_offered_budget",
        "private_floor_evidence_digest",
        "allowed_data_sensitivity_codes",
        "ai_use_code",
        "language_codes",
        "work_mode_code",
        "region_code",
        "location_eligible",
        "conflict_of_interest",
    }
)

_OPAQUE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{15,127}\Z")
_SHA256 = re.compile(r"[a-f0-9]{64}\Z")
_CODE = re.compile(r"[A-Z][A-Z0-9_.:-]{1,63}\Z")
_SEMVER = re.compile(
    r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\Z"
)
_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}\Z")
_LOCALE = re.compile(r"[a-z]{2}(?:-[A-Z]{2})?\Z")
_CURRENCY = re.compile(r"[A-Z]{3}\Z")

_ZERO = Fraction(0, 1)
_ONE = Fraction(1, 1)
_HUNDRED = Fraction(100, 1)


class DeterministicMatcherV1Error(ValueError):
    """Stable, payload-free rejection from the v1 engine boundary."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class HardFilterRuleV1:
    code: str
    ordinal: int
    enabled: bool


@dataclass(frozen=True)
class ComponentRuleV1:
    code: str
    ordinal: int
    weight_bps: int


@dataclass(frozen=True)
class GoldenVectorReferenceV1:
    vector_id: str
    input_sha256: str
    expected_result_sha256: str


@dataclass(frozen=True)
class LoadedMatchingRuleReleaseV1:
    bundle_id: str
    semantic_version: str
    selector_digest: str = field(repr=False)
    jurisdiction_code: str
    locale: str
    demand_type_code: str
    taxonomy_family_code: str
    engine_identifier: str
    engine_major: int
    engine_artifact_sha256: str = field(repr=False)
    taxonomy_bundle_id: str
    budget_rule_version: str
    matching_rule_version: str
    reason_code_version: str
    explanation_template_version: str
    hard_filters: Tuple[HardFilterRuleV1, ...]
    components: Tuple[ComponentRuleV1, ...]
    invitation_limit: int
    golden_vectors: Tuple[GoldenVectorReferenceV1, ...] = field(repr=False)
    effective_at: datetime
    effective_until: Optional[datetime]
    canonical_manifest_sha256: str = field(repr=False)
    canonical_manifest_bytes: bytes = field(repr=False)


@dataclass(frozen=True)
class MatchSkillRequirementV1:
    skill_code: str
    minimum_level: int


@dataclass(frozen=True)
class MatchSkillFactV1:
    skill_code: str
    proficiency_level: int
    evidence_trust_level: int
    evidence_bucket: str


@dataclass(frozen=True)
class DemandMatchInputV1:
    problem_type_codes: Tuple[str, ...]
    domain_codes: Tuple[str, ...]
    task_codes: Tuple[str, ...]
    must_have_skills: Tuple[MatchSkillRequirementV1, ...]
    nice_to_have_skills: Tuple[MatchSkillRequirementV1, ...]
    start_date: date
    due_date: date
    required_weekly_hours: int
    required_duration_weeks: int
    currency: str
    minimum_amount_minor: int = field(repr=False)
    maximum_amount_minor: int = field(repr=False)
    allowed_region_codes: Tuple[str, ...] = field(repr=False)
    required_language_codes: Tuple[str, ...]
    required_work_mode_code: str
    data_sensitivity_code: str = field(repr=False)
    ai_use_code: str
    budget_override_code: Optional[str] = field(repr=False)


@dataclass(frozen=True)
class ProfileMatchInputV1:
    creator_user_id: str
    profile_id: str
    profile_version_id: str
    profile_content_sha256: str = field(repr=False)
    evidence_version_digest: str = field(repr=False)
    status: str
    interest_problem_type_codes: Tuple[str, ...]
    interest_domain_codes: Tuple[str, ...]
    interest_task_codes: Tuple[str, ...]
    interest_intensity: int
    prohibited_domain_codes: Tuple[str, ...] = field(repr=False)
    prohibited_task_codes: Tuple[str, ...] = field(repr=False)
    skills: Tuple[MatchSkillFactV1, ...]
    available_from: date
    available_weekly_hours: int
    available_duration_weeks: int
    currency: str
    within_offered_budget: bool = field(repr=False)
    private_floor_evidence_digest: str = field(repr=False)
    allowed_data_sensitivity_codes: Tuple[str, ...] = field(repr=False)
    ai_use_code: str
    language_codes: Tuple[str, ...]
    work_mode_code: str
    region_code: str = field(repr=False)
    location_eligible: bool = field(repr=False)
    conflict_of_interest: bool = field(repr=False)


@dataclass(frozen=True)
class MatchRunInputV1:
    attempt_id: str
    run_id: str
    demand_id: str
    demand_version_id: str
    matching_rule_bundle_id: str
    input_set_sha256: str = field(repr=False)
    demand: DemandMatchInputV1 = field(repr=False)
    profiles: Tuple[ProfileMatchInputV1, ...] = field(repr=False)
    canonical_input_bytes: bytes = field(repr=False)
    canonical_input_sha256: str = field(repr=False)


@dataclass(frozen=True)
class CandidateEvidenceBindingV1:
    """Internal persistence binding; deliberately absent from candidate JSON."""

    creator_user_id: str
    profile_id: str
    profile_version_id: str
    profile_content_sha256: str = field(repr=False)
    evidence_version_digest: str = field(repr=False)


@dataclass(frozen=True)
class DeterministicMatchResultV1:
    candidates: Tuple[MatchCandidate, ...]
    candidate_documents: Tuple[Mapping[str, Any], ...]
    candidate_evidence_bindings: Tuple[CandidateEvidenceBindingV1, ...] = field(
        repr=False
    )
    ordered_result_sha256: str = field(repr=False)
    canonical_result_bytes: bytes = field(repr=False)
    result_document: Mapping[str, Any]
    engine_result_sha256: str = field(repr=False)


def load_default_rule_release_v1() -> LoadedMatchingRuleReleaseV1:
    """Load and startup-verify the deployable internal-sandbox release."""

    return load_rule_release_v1(_resource_bytes(DEFAULT_RULE_RESOURCE))


def load_rule_release_v1(
    manifest: Union[bytes, bytearray, Mapping[str, Any]],
    *,
    expected_manifest_sha256: Optional[str] = None,
    engine_spec_bytes: Optional[bytes] = None,
    golden_vectors_bytes: Optional[bytes] = None,
    verify_golden_vectors: bool = True,
) -> LoadedMatchingRuleReleaseV1:
    """Validate a reviewed rule manifest and its exact engine artifact.

    Byte input must already be the canonical UTF-8 JSON representation.  A
    mapping is useful for a JSONB-backed worker and is canonicalized here.  The
    optional expected digest binds that mapping to the independently persisted
    manifest digest.
    """

    document, canonical = _document_and_canonical_bytes(
        manifest,
        canonical_error="MATCH_RULE_RELEASE_CANONICAL_MISMATCH",
        invalid_error="MATCH_RULE_RELEASE_INVALID",
        maximum_bytes=256 * 1024,
    )
    digest = hashlib.sha256(canonical).hexdigest()
    if expected_manifest_sha256 is not None:
        _require_sha256(expected_manifest_sha256, "MATCH_RULE_RELEASE_INVALID")
        if digest != expected_manifest_sha256:
            _fail("MATCH_RULE_RELEASE_DIGEST_MISMATCH")

    spec_raw = engine_spec_bytes or _resource_bytes(ENGINE_SPEC_RESOURCE)
    vectors_raw = golden_vectors_bytes or _resource_bytes(GOLDEN_VECTORS_RESOURCE)
    artifact_sha256, vector_document = _load_engine_artifact(
        spec_raw,
        vectors_raw,
    )
    rule = _parse_rule_release(document, canonical, digest, artifact_sha256)
    if verify_golden_vectors:
        _verify_golden_vectors(rule, vector_document)
    return rule


def normalize_match_run_input_v1(
    value: Union[bytes, bytearray, Mapping[str, Any]],
    *,
    expected_input_set_sha256: Optional[str] = None,
    expected_canonical_sha256: Optional[str] = None,
) -> MatchRunInputV1:
    """Validate and normalize the private worker input without performing I/O.

    Code sets and skill lists are required to arrive in canonical UTF-8 order.
    Candidate order alone is normalized by creator ID so scheduling or capture
    iteration order cannot affect scoring or ranking.
    """

    document, _ = _document_and_canonical_bytes(
        value,
        canonical_error="MATCH_RUN_INPUT_CANONICAL_MISMATCH",
        invalid_error="MATCH_RUN_INPUT_INVALID",
        maximum_bytes=4 * 1024 * 1024,
    )
    parsed = _parse_run_input(document)
    normalized_document = _run_input_document(parsed)
    canonical = _jcs_bytes(normalized_document, "MATCH_RUN_INPUT_INVALID")
    digest = hashlib.sha256(canonical).hexdigest()
    normalized = MatchRunInputV1(
        attempt_id=parsed.attempt_id,
        run_id=parsed.run_id,
        demand_id=parsed.demand_id,
        demand_version_id=parsed.demand_version_id,
        matching_rule_bundle_id=parsed.matching_rule_bundle_id,
        input_set_sha256=parsed.input_set_sha256,
        demand=parsed.demand,
        profiles=parsed.profiles,
        canonical_input_bytes=canonical,
        canonical_input_sha256=digest,
    )
    if expected_input_set_sha256 is not None:
        _require_sha256(expected_input_set_sha256, "MATCH_RUN_INPUT_INVALID")
        if normalized.input_set_sha256 != expected_input_set_sha256:
            _fail("MATCH_RUN_INPUT_DIGEST_MISMATCH")
    if expected_canonical_sha256 is not None:
        _require_sha256(expected_canonical_sha256, "MATCH_RUN_INPUT_INVALID")
        if digest != expected_canonical_sha256:
            _fail("MATCH_RUN_INPUT_DIGEST_MISMATCH")
    return normalized


def demand_postgres_snapshot_to_input_v1(snapshot: object) -> Mapping[str, Any]:
    """Map the closed Demand PostgreSQL capture DTO to engine demand facts.

    Profile normalization is intentionally a separate pure mapping seam: the
    Profile context, not this engine, owns private-floor, location, conflict,
    and evidence derivation.
    """

    try:
        from desire_platform.demand.adapters.postgres.uow import (
            DemandPostgresMatchInputSnapshot,
        )

        if not isinstance(snapshot, DemandPostgresMatchInputSnapshot):
            _fail("MATCH_INPUT_NORMALIZATION_UNAVAILABLE")
        value = {
            "problem_type_codes": list(snapshot.problem_type_codes),
            "domain_codes": list(snapshot.domain_codes),
            "task_codes": list(snapshot.task_codes),
            "must_have_skills": [
                {
                    "skill_code": item.skill_code,
                    "minimum_level": item.minimum_level,
                }
                for item in snapshot.must_have_skills
            ],
            "nice_to_have_skills": [
                {
                    "skill_code": item.skill_code,
                    "minimum_level": item.minimum_level,
                }
                for item in snapshot.nice_to_have_skills
            ],
            "start_date": snapshot.start_date.isoformat(),
            "due_date": snapshot.due_date.isoformat(),
            "required_weekly_hours": snapshot.required_weekly_hours,
            "required_duration_weeks": snapshot.required_duration_weeks,
            "currency": snapshot.currency,
            "minimum_amount_minor": snapshot.minimum_amount_minor,
            "maximum_amount_minor": snapshot.maximum_amount_minor,
            "allowed_region_codes": list(snapshot.allowed_region_codes),
            "required_language_codes": list(snapshot.required_language_codes),
            "required_work_mode_code": snapshot.required_work_mode_code,
            "data_sensitivity_code": snapshot.data_sensitivity_code,
            "ai_use_code": snapshot.ai_use_code,
            "budget_override_code": snapshot.budget_override_code,
        }
        _parse_demand_input(value)
        return value
    except DeterministicMatcherV1Error:
        raise
    except Exception:
        _fail("MATCH_INPUT_NORMALIZATION_UNAVAILABLE")


def compose_match_run_input_v1(
    *,
    attempt_id: str,
    run_id: str,
    demand_id: str,
    demand_version_id: str,
    matching_rule_bundle_id: str,
    input_set_sha256: str,
    demand: Union[DemandMatchInputV1, Mapping[str, Any]],
    profiles: Sequence[Union[ProfileMatchInputV1, Mapping[str, Any]]],
) -> MatchRunInputV1:
    """Worker seam for already-derived, closed Demand/Profile capture facts."""

    demand_document = (
        _demand_document(demand)
        if isinstance(demand, DemandMatchInputV1)
        else _plain_json(demand, "MATCH_RUN_INPUT_INVALID")
    )
    profile_documents = [
        _profile_document(item)
        if isinstance(item, ProfileMatchInputV1)
        else _plain_json(item, "MATCH_RUN_INPUT_INVALID")
        for item in profiles
    ]
    return normalize_match_run_input_v1(
        {
            "schema_version": 1,
            "canonicalization_version": "match-run-input-json-v1",
            "attempt_id": attempt_id,
            "run_id": run_id,
            "demand_id": demand_id,
            "demand_version_id": demand_version_id,
            "matching_rule_bundle_id": matching_rule_bundle_id,
            "input_set_sha256": input_set_sha256,
            "demand": demand_document,
            "profiles": profile_documents,
        },
        expected_input_set_sha256=input_set_sha256,
    )


def evaluate_match_run_v1(
    run_input: Union[MatchRunInputV1, bytes, bytearray, Mapping[str, Any]],
    rule: LoadedMatchingRuleReleaseV1,
) -> DeterministicMatchResultV1:
    """Evaluate all candidates, rank eligible results, and hash closed output."""

    _revalidate_loaded_rule(rule)
    normalized = (
        _revalidate_normalized_input(run_input)
        if isinstance(run_input, MatchRunInputV1)
        else normalize_match_run_input_v1(run_input)
    )
    if normalized.matching_rule_bundle_id != rule.bundle_id:
        _fail("MATCH_RULE_RELEASE_MISMATCH")

    unranked = tuple(
        _evaluate_candidate(normalized, profile, rule)
        for profile in normalized.profiles
    )
    try:
        candidates, ordered_result_sha256 = deterministic_rank_and_hash(
            candidates=unranked,
            matching_rule_bundle_id=rule.bundle_id,
            input_set_sha256=normalized.input_set_sha256,
        )
    except Exception:
        _fail("MATCH_RESULT_INVALID")

    profiles = {item.creator_user_id: item for item in normalized.profiles}
    candidate_documents = tuple(
        _candidate_document(item) for item in candidates
    )
    bindings = tuple(
        CandidateEvidenceBindingV1(
            creator_user_id=item.creator_user_id,
            profile_id=item.profile_id,
            profile_version_id=item.profile_version_id,
            profile_content_sha256=item.profile_content_sha256,
            evidence_version_digest=profiles[item.creator_user_id].evidence_version_digest,
        )
        for item in candidates
    )
    result_document = {
        "schema_version": 1,
        "canonicalization_version": "deterministic-match-result-json-v1",
        "attempt_id": normalized.attempt_id,
        "run_id": normalized.run_id,
        "matching_rule_bundle_id": rule.bundle_id,
        "input_set_sha256": normalized.input_set_sha256,
        "engine_identifier": rule.engine_identifier,
        "engine_artifact_sha256": rule.engine_artifact_sha256,
        "ordered_result_sha256": ordered_result_sha256,
        "candidates": list(candidate_documents),
    }
    canonical = _jcs_bytes(result_document, "MATCH_RESULT_INVALID")
    return DeterministicMatchResultV1(
        candidates=candidates,
        candidate_documents=candidate_documents,
        candidate_evidence_bindings=bindings,
        ordered_result_sha256=ordered_result_sha256,
        canonical_result_bytes=canonical,
        result_document=result_document,
        engine_result_sha256=hashlib.sha256(canonical).hexdigest(),
    )


def evaluate_candidate_hard_filters_v1(
    *,
    demand: DemandMatchInputV1,
    profile: ProfileMatchInputV1,
    rule: LoadedMatchingRuleReleaseV1,
) -> Tuple[str, ...]:
    """Return every enabled failure in manifest ordinal order, without short-circuit."""

    if (
        not isinstance(demand, DemandMatchInputV1)
        or not isinstance(profile, ProfileMatchInputV1)
        or not isinstance(rule, LoadedMatchingRuleReleaseV1)
    ):
        _fail("MATCH_RUN_INPUT_INVALID")
    failed = _hard_filter_failures(demand, profile)
    return tuple(
        item.code
        for item in rule.hard_filters
        if item.enabled and failed[item.code]
    )


def component_scores_v1(
    *,
    demand: DemandMatchInputV1,
    profile: ProfileMatchInputV1,
    rule: LoadedMatchingRuleReleaseV1,
) -> Tuple[Tuple[ComponentScore, ...], Decimal]:
    """Compute six rounded components and the exact-weighted rounded total."""

    raw = _component_fractions(demand, profile)
    components = tuple(
        ComponentScore(
            code=item.code,
            ordinal=item.ordinal,
            score=_round_fraction_score(raw[item.code]),
        )
        for item in rule.components
    )
    weighted_total = sum(
        (raw[item.code] * item.weight_bps for item in rule.components),
        _ZERO,
    ) / 10000
    return components, _round_fraction_score(weighted_total)


def _evaluate_candidate(
    run_input: MatchRunInputV1,
    profile: ProfileMatchInputV1,
    rule: LoadedMatchingRuleReleaseV1,
) -> MatchCandidate:
    reasons = evaluate_candidate_hard_filters_v1(
        demand=run_input.demand,
        profile=profile,
        rule=rule,
    )
    evidence = _evidence_facts(run_input, profile, reasons)
    if reasons:
        return MatchCandidate(
            attempt_id=run_input.attempt_id,
            run_id=run_input.run_id,
            creator_user_id=profile.creator_user_id,
            profile_id=profile.profile_id,
            profile_version_id=profile.profile_version_id,
            profile_content_sha256=profile.profile_content_sha256,
            eligibility=CandidateEligibility.EXCLUDED,
            exclusion_reason_codes=reasons,
            components=(),
            total_score=None,
            rank=None,
            evidence_facts=evidence,
            candidate_result_sha256="",
        )
    components, total = component_scores_v1(
        demand=run_input.demand,
        profile=profile,
        rule=rule,
    )
    return MatchCandidate(
        attempt_id=run_input.attempt_id,
        run_id=run_input.run_id,
        creator_user_id=profile.creator_user_id,
        profile_id=profile.profile_id,
        profile_version_id=profile.profile_version_id,
        profile_content_sha256=profile.profile_content_sha256,
        eligibility=CandidateEligibility.ELIGIBLE,
        exclusion_reason_codes=(),
        components=components,
        total_score=total,
        rank=1,
        evidence_facts=evidence,
        candidate_result_sha256="",
    )


def _hard_filter_failures(
    demand: DemandMatchInputV1,
    profile: ProfileMatchInputV1,
) -> Mapping[str, bool]:
    skill_map = {item.skill_code: item for item in profile.skills}
    missing_skill = any(
        requirement.skill_code not in skill_map
        or skill_map[requirement.skill_code].proficiency_level
        < requirement.minimum_level
        for requirement in demand.must_have_skills
    )
    ai_conflict = (
        demand.ai_use_code == "REQUIRED" and profile.ai_use_code == "PROHIBITED"
    ) or (
        demand.ai_use_code == "PROHIBITED" and profile.ai_use_code == "REQUIRED"
    )
    required_languages = frozenset(demand.required_language_codes)
    profile_languages = frozenset(profile.language_codes)
    location_conflict = not profile.location_eligible or (
        bool(demand.allowed_region_codes)
        and profile.region_code not in demand.allowed_region_codes
    )
    return {
        "CREATOR_INACTIVE": profile.status != "ACTIVE",
        "BOUNDARY_DOMAIN": bool(
            frozenset(demand.domain_codes).intersection(
                profile.prohibited_domain_codes
            )
        ),
        "BOUNDARY_TASK": bool(
            frozenset(demand.task_codes).intersection(profile.prohibited_task_codes)
        ),
        "MISSING_MUST_HAVE_SKILL": missing_skill,
        "DATE_CONFLICT": profile.available_from > demand.due_date,
        "CAPACITY_CONFLICT": (
            profile.available_weekly_hours < demand.required_weekly_hours
        ),
        "DURATION_CONFLICT": (
            profile.available_duration_weeks < demand.required_duration_weeks
        ),
        "CURRENCY_MISMATCH": profile.currency != demand.currency,
        "BELOW_PRIVATE_FLOOR": (
            not profile.within_offered_budget
            and demand.budget_override_code != "APPROVED_EXCEPTION"
        ),
        "DATA_POLICY_CONFLICT": (
            demand.data_sensitivity_code
            not in profile.allowed_data_sensitivity_codes
        ),
        "AI_POLICY_CONFLICT": ai_conflict,
        "LANGUAGE_MISMATCH": bool(required_languages)
        and not required_languages.intersection(profile_languages),
        "WORK_MODE_CONFLICT": (
            profile.work_mode_code != demand.required_work_mode_code
        ),
        "LOCATION_RESTRICTION": location_conflict,
        "CONFLICT_OF_INTEREST": profile.conflict_of_interest,
    }


def _component_fractions(
    demand: DemandMatchInputV1,
    profile: ProfileMatchInputV1,
) -> Mapping[str, Fraction]:
    skill_map = {item.skill_code: item for item in profile.skills}

    def coverage(wanted: Tuple[str, ...], offered: Tuple[str, ...]) -> Fraction:
        if not wanted:
            return Fraction(1, 2)
        return Fraction(len(frozenset(wanted).intersection(offered)), len(wanted))

    interest_base = sum(
        (
            coverage(demand.problem_type_codes, profile.interest_problem_type_codes),
            coverage(demand.domain_codes, profile.interest_domain_codes),
            coverage(demand.task_codes, profile.interest_task_codes),
        ),
        _ZERO,
    ) / 3
    interest = (
        _HUNDRED
        * interest_base
        * Fraction(6 + profile.interest_intensity, 10)
    )

    def skill_quality(requirement: MatchSkillRequirementV1) -> Fraction:
        fact = skill_map.get(requirement.skill_code)
        if fact is None:
            return _ZERO
        return Fraction(
            fact.proficiency_level * (28 + 3 * fact.evidence_trust_level),
            160,
        )

    def requirement_average(
        requirements: Tuple[MatchSkillRequirementV1, ...],
    ) -> Fraction:
        if not requirements:
            return _ONE
        return sum((skill_quality(item) for item in requirements), _ZERO) / len(
            requirements
        )

    must_capability = requirement_average(demand.must_have_skills)
    nice_capability = (
        requirement_average(demand.nice_to_have_skills)
        if demand.nice_to_have_skills
        else must_capability
    )
    capability = _HUNDRED * (
        Fraction(17, 20) * must_capability
        + Fraction(3, 20) * nice_capability
    )

    capacity = _bounded_surplus_ratio(
        profile.available_weekly_hours,
        demand.required_weekly_hours,
    )
    duration = _bounded_surplus_ratio(
        profile.available_duration_weeks,
        demand.required_duration_weeks,
    )
    if profile.available_from <= demand.start_date:
        start_fit = _ONE
    else:
        window = max((demand.due_date - demand.start_date).days, 1)
        remaining = max((demand.due_date - profile.available_from).days, 0)
        start_fit = min(_ONE, Fraction(remaining, window))
    availability = _HUNDRED * (
        Fraction(1, 2) * capacity
        + Fraction(1, 4) * duration
        + Fraction(1, 4) * start_fit
    )

    compensation = (
        _HUNDRED
        if profile.within_offered_budget
        else Fraction(60, 1)
        if demand.budget_override_code == "APPROVED_EXCEPTION"
        else _ZERO
    )

    required_languages = frozenset(demand.required_language_codes)
    if not required_languages:
        language_fit = _ONE
    else:
        language_fit = Fraction(
            len(required_languages.intersection(profile.language_codes)),
            len(required_languages),
        )
    work_mode_fit = (
        _ONE
        if profile.work_mode_code == demand.required_work_mode_code
        else _ZERO
    )
    if not demand.allowed_region_codes:
        location_fit = _ONE if profile.location_eligible else _ZERO
    elif profile.region_code in demand.allowed_region_codes:
        location_fit = _ONE if profile.location_eligible else _ZERO
    else:
        location_fit = Fraction(3, 4) if profile.location_eligible else _ZERO
    if profile.ai_use_code == demand.ai_use_code:
        ai_fit = _ONE
    elif (
        profile.ai_use_code == "OPTIONAL" or demand.ai_use_code == "OPTIONAL"
    ):
        ai_fit = Fraction(3, 4)
    else:
        ai_fit = _ZERO
    collaboration = _HUNDRED * (
        language_fit + work_mode_fit + location_fit + ai_fit
    ) / 4

    relevant_codes = {
        item.skill_code
        for item in (*demand.must_have_skills, *demand.nice_to_have_skills)
    }
    relevant_skills = tuple(
        item
        for item in profile.skills
        if not relevant_codes or item.skill_code in relevant_codes
    )
    if not relevant_skills:
        evidence_trust = _ZERO
    else:
        bucket_level = {
            "NONE": 0,
            "SELF_ASSERTED": 1,
            "DOCUMENTED": 3,
            "VERIFIED": 4,
        }
        evidence_trust = _HUNDRED * sum(
            (
                Fraction(
                    item.evidence_trust_level
                    + bucket_level[item.evidence_bucket],
                    8,
                )
                for item in relevant_skills
            ),
            _ZERO,
        ) / len(relevant_skills)

    return {
        "interest": min(_HUNDRED, max(_ZERO, interest)),
        "capability": min(_HUNDRED, max(_ZERO, capability)),
        "availability": min(_HUNDRED, max(_ZERO, availability)),
        "compensation": min(_HUNDRED, max(_ZERO, compensation)),
        "collaboration": min(_HUNDRED, max(_ZERO, collaboration)),
        "evidence_trust": min(_HUNDRED, max(_ZERO, evidence_trust)),
    }


def _bounded_surplus_ratio(available: int, required: int) -> Fraction:
    if required <= 0:
        return _ONE
    return min(_ONE, Fraction(available, required * 2))


def _evidence_facts(
    run_input: MatchRunInputV1,
    profile: ProfileMatchInputV1,
    reasons: Tuple[str, ...],
) -> Tuple[EvidenceFact, ...]:
    raw = _component_fractions(run_input.demand, profile)
    return (
        EvidenceFact(
            code="ELIGIBILITY",
            kind="CODE",
            value="EXCLUDED" if reasons else "ELIGIBLE",
            source_version_digest=run_input.input_set_sha256,
        ),
        EvidenceFact(
            code="FILTER_RESULT",
            kind="BUCKET",
            value=(
                "NO_FAILURE"
                if not reasons
                else "ONE_FAILURE"
                if len(reasons) == 1
                else "MULTIPLE_FAILURES"
            ),
            source_version_digest=run_input.input_set_sha256,
        ),
        EvidenceFact(
            code="WITHIN_OFFERED_BUDGET",
            kind="BOOLEAN",
            value=profile.within_offered_budget,
            source_version_digest=profile.private_floor_evidence_digest,
        ),
        EvidenceFact(
            code="BUDGET_OVERRIDE",
            kind="CODE",
            value=run_input.demand.budget_override_code or "NONE",
            source_version_digest=run_input.input_set_sha256,
        ),
        *tuple(
            EvidenceFact(
                code=f"{code.upper()}_FIT",
                kind="BUCKET",
                value=_score_bucket(raw[code]),
                source_version_digest=run_input.input_set_sha256,
            )
            for code in COMPONENT_CODES
        ),
    )


def _score_bucket(value: Fraction) -> str:
    if value == 0:
        return "NONE"
    if value < 50:
        return "LOW"
    if value < 75:
        return "MEDIUM"
    if value < 100:
        return "HIGH"
    return "COMPLETE"


def _round_fraction_score(value: Fraction) -> Decimal:
    if value < 0 or value > 100:
        _fail("MATCH_RESULT_INVALID")
    scaled = value * 100
    quotient, remainder = divmod(scaled.numerator, scaled.denominator)
    twice = remainder * 2
    if twice > scaled.denominator or (
        twice == scaled.denominator and quotient % 2 == 1
    ):
        quotient += 1
    return (Decimal(quotient) / Decimal(100)).quantize(Decimal("0.00"))


def _parse_rule_release(
    value: Any,
    canonical: bytes,
    canonical_sha256: str,
    artifact_sha256: str,
) -> LoadedMatchingRuleReleaseV1:
    error = "MATCH_RULE_RELEASE_INVALID"
    root = _require_mapping(value, error)
    _require_exact_keys(root, _RULE_ROOT_KEYS, error)
    _require_exact_int(root["schema_version"], 1, error)
    _require_exact_string(
        root["canonicalization_version"],
        "matching-rule-release-json-v1",
        error,
    )
    bundle_id = _require_opaque_id(root["bundle_id"], error)
    semantic_version = _require_pattern(root["semantic_version"], _SEMVER, error)
    selector_digest = _require_sha256(root["selector_digest"], error)
    jurisdiction_code = _require_code(root["jurisdiction_code"], error)
    locale = _require_pattern(root["locale"], _LOCALE, error)
    demand_type_code = _require_code(root["demand_type_code"], error)
    taxonomy_family_code = _require_code(root["taxonomy_family_code"], error)
    _require_exact_string(root["engine_identifier"], ENGINE_IDENTIFIER, error)
    _require_exact_int(root["engine_major"], ENGINE_MAJOR, error)
    claimed_artifact = _require_sha256(root["engine_artifact_sha256"], error)
    if claimed_artifact != artifact_sha256:
        _fail("MATCH_ENGINE_ARTIFACT_MISMATCH")
    taxonomy_bundle_id = _require_opaque_id(root["taxonomy_bundle_id"], error)
    budget_version = _require_pattern(root["budget_rule_version"], _VERSION, error)
    matching_version = _require_pattern(root["matching_rule_version"], _VERSION, error)
    reason_version = _require_pattern(root["reason_code_version"], _VERSION, error)
    explanation_version = _require_pattern(
        root["explanation_template_version"], _VERSION, error
    )

    hard_rows = _require_list(root["hard_filters"], error)
    if len(hard_rows) != len(HARD_FILTER_CODES):
        _fail(error)
    hard_filters = []
    for ordinal, (row_value, expected_code) in enumerate(
        zip(hard_rows, HARD_FILTER_CODES), 1
    ):
        row = _require_mapping(row_value, error)
        _require_exact_keys(row, frozenset({"code", "ordinal", "enabled"}), error)
        _require_exact_string(row["code"], expected_code, error)
        _require_exact_int(row["ordinal"], ordinal, error)
        if type(row["enabled"]) is not bool:
            _fail(error)
        hard_filters.append(
            HardFilterRuleV1(expected_code, ordinal, row["enabled"])
        )

    component_rows = _require_list(root["components"], error)
    if len(component_rows) != len(COMPONENT_CODES):
        _fail(error)
    components = []
    for ordinal, (row_value, expected_code) in enumerate(
        zip(component_rows, COMPONENT_CODES), 1
    ):
        row = _require_mapping(row_value, error)
        _require_exact_keys(
            row, frozenset({"code", "ordinal", "weight_bps"}), error
        )
        _require_exact_string(row["code"], expected_code, error)
        _require_exact_int(row["ordinal"], ordinal, error)
        weight = _require_bounded_int(row["weight_bps"], 0, 10000, error)
        components.append(ComponentRuleV1(expected_code, ordinal, weight))
    if sum(item.weight_bps for item in components) != 10000:
        _fail(error)

    invitation_limit = _require_bounded_int(root["invitation_limit"], 1, 100, error)
    golden_rows = _require_list(root["golden_vectors"], error)
    if not 3 <= len(golden_rows) <= 100:
        _fail(error)
    golden_vectors = []
    for row_value in golden_rows:
        row = _require_mapping(row_value, error)
        _require_exact_keys(
            row,
            frozenset(
                {"vector_id", "input_sha256", "expected_result_sha256"}
            ),
            error,
        )
        golden_vectors.append(
            GoldenVectorReferenceV1(
                vector_id=_require_opaque_id(row["vector_id"], error),
                input_sha256=_require_sha256(row["input_sha256"], error),
                expected_result_sha256=_require_sha256(
                    row["expected_result_sha256"], error
                ),
            )
        )
    vector_ids = tuple(item.vector_id for item in golden_vectors)
    if (
        len(set(vector_ids)) != len(vector_ids)
        or vector_ids != tuple(sorted(vector_ids, key=lambda item: item.encode("utf-8")))
    ):
        _fail(error)

    effective_at = _require_timestamp(root["effective_at"], error)
    effective_until = (
        None
        if root["effective_until"] is None
        else _require_timestamp(root["effective_until"], error)
    )
    if effective_until is not None and effective_until <= effective_at:
        _fail(error)

    return LoadedMatchingRuleReleaseV1(
        bundle_id=bundle_id,
        semantic_version=semantic_version,
        selector_digest=selector_digest,
        jurisdiction_code=jurisdiction_code,
        locale=locale,
        demand_type_code=demand_type_code,
        taxonomy_family_code=taxonomy_family_code,
        engine_identifier=ENGINE_IDENTIFIER,
        engine_major=ENGINE_MAJOR,
        engine_artifact_sha256=artifact_sha256,
        taxonomy_bundle_id=taxonomy_bundle_id,
        budget_rule_version=budget_version,
        matching_rule_version=matching_version,
        reason_code_version=reason_version,
        explanation_template_version=explanation_version,
        hard_filters=tuple(hard_filters),
        components=tuple(components),
        invitation_limit=invitation_limit,
        golden_vectors=tuple(golden_vectors),
        effective_at=effective_at,
        effective_until=effective_until,
        canonical_manifest_sha256=canonical_sha256,
        canonical_manifest_bytes=canonical,
    )


def _parse_run_input(value: Any) -> MatchRunInputV1:
    error = "MATCH_RUN_INPUT_INVALID"
    root = _require_mapping(value, error)
    _require_exact_keys(root, _RUN_INPUT_ROOT_KEYS, error)
    _require_exact_int(root["schema_version"], 1, error)
    _require_exact_string(
        root["canonicalization_version"], "match-run-input-json-v1", error
    )
    profiles = tuple(
        _parse_profile_input(item)
        for item in _require_list(root["profiles"], error)
    )
    if len(profiles) > 10000:
        _fail(error)
    creator_ids = tuple(item.creator_user_id for item in profiles)
    if len(set(creator_ids)) != len(creator_ids):
        _fail(error)
    profiles = tuple(
        sorted(profiles, key=lambda item: item.creator_user_id.encode("utf-8"))
    )
    demand = _parse_demand_input(root["demand"])
    canonical = b"{}"
    return MatchRunInputV1(
        attempt_id=_require_opaque_id(root["attempt_id"], error),
        run_id=_require_opaque_id(root["run_id"], error),
        demand_id=_require_opaque_id(root["demand_id"], error),
        demand_version_id=_require_opaque_id(root["demand_version_id"], error),
        matching_rule_bundle_id=_require_opaque_id(
            root["matching_rule_bundle_id"], error
        ),
        input_set_sha256=_require_sha256(root["input_set_sha256"], error),
        demand=demand,
        profiles=profiles,
        canonical_input_bytes=canonical,
        canonical_input_sha256=hashlib.sha256(canonical).hexdigest(),
    )


def _parse_demand_input(value: Any) -> DemandMatchInputV1:
    error = "MATCH_RUN_INPUT_INVALID"
    row = _require_mapping(value, error)
    _require_exact_keys(row, _DEMAND_KEYS, error)
    must = _parse_requirements(row["must_have_skills"], error)
    nice = _parse_requirements(row["nice_to_have_skills"], error)
    if {item.skill_code for item in must}.intersection(
        item.skill_code for item in nice
    ):
        _fail(error)
    start = _require_date(row["start_date"], error)
    due = _require_date(row["due_date"], error)
    if due < start:
        _fail(error)
    minimum = _require_bounded_int(
        row["minimum_amount_minor"], 0, 9007199254740991, error
    )
    maximum = _require_bounded_int(
        row["maximum_amount_minor"], 0, 9007199254740991, error
    )
    if minimum > maximum:
        _fail(error)
    override = row["budget_override_code"]
    if override not in {None, "APPROVED_EXCEPTION"}:
        _fail(error)
    sensitivity = row["data_sensitivity_code"]
    if sensitivity not in {"PUBLIC", "INTERNAL", "HIGH", "RESTRICTED"}:
        _fail(error)
    ai_use = row["ai_use_code"]
    if ai_use not in {"PROHIBITED", "OPTIONAL", "REQUIRED"}:
        _fail(error)
    return DemandMatchInputV1(
        problem_type_codes=_require_code_tuple(row["problem_type_codes"], 100, error),
        domain_codes=_require_code_tuple(row["domain_codes"], 100, error),
        task_codes=_require_code_tuple(row["task_codes"], 100, error),
        must_have_skills=must,
        nice_to_have_skills=nice,
        start_date=start,
        due_date=due,
        required_weekly_hours=_require_bounded_int(
            row["required_weekly_hours"], 0, 168, error
        ),
        required_duration_weeks=_require_bounded_int(
            row["required_duration_weeks"], 0, 520, error
        ),
        currency=_require_pattern(row["currency"], _CURRENCY, error),
        minimum_amount_minor=minimum,
        maximum_amount_minor=maximum,
        allowed_region_codes=_require_code_tuple(
            row["allowed_region_codes"], 100, error
        ),
        required_language_codes=_require_code_tuple(
            row["required_language_codes"], 100, error
        ),
        required_work_mode_code=_require_code(
            row["required_work_mode_code"], error
        ),
        data_sensitivity_code=sensitivity,
        ai_use_code=ai_use,
        budget_override_code=override,
    )


def _parse_profile_input(value: Any) -> ProfileMatchInputV1:
    error = "MATCH_RUN_INPUT_INVALID"
    row = _require_mapping(value, error)
    _require_exact_keys(row, _PROFILE_KEYS, error)
    status = row["status"]
    # The public v1 input contract captures only ACTIVE profiles.  The engine
    # still evaluates CREATOR_INACTIVE defensively on its typed filter surface.
    if status != "ACTIVE":
        _fail(error)
    ai_use = row["ai_use_code"]
    if ai_use not in {"PROHIBITED", "OPTIONAL", "REQUIRED"}:
        _fail(error)
    return ProfileMatchInputV1(
        creator_user_id=_require_opaque_id(row["creator_user_id"], error),
        profile_id=_require_opaque_id(row["profile_id"], error),
        profile_version_id=_require_opaque_id(row["profile_version_id"], error),
        profile_content_sha256=_require_sha256(
            row["profile_content_sha256"], error
        ),
        evidence_version_digest=_require_sha256(
            row["evidence_version_digest"], error
        ),
        status=status,
        interest_problem_type_codes=_require_code_tuple(
            row["interest_problem_type_codes"], 100, error
        ),
        interest_domain_codes=_require_code_tuple(
            row["interest_domain_codes"], 100, error
        ),
        interest_task_codes=_require_code_tuple(
            row["interest_task_codes"], 100, error
        ),
        interest_intensity=_require_bounded_int(
            row["interest_intensity"], 0, 4, error
        ),
        prohibited_domain_codes=_require_code_tuple(
            row["prohibited_domain_codes"], 100, error
        ),
        prohibited_task_codes=_require_code_tuple(
            row["prohibited_task_codes"], 100, error
        ),
        skills=_parse_skill_facts(row["skills"], error),
        available_from=_require_date(row["available_from"], error),
        available_weekly_hours=_require_bounded_int(
            row["available_weekly_hours"], 0, 168, error
        ),
        available_duration_weeks=_require_bounded_int(
            row["available_duration_weeks"], 0, 520, error
        ),
        currency=_require_pattern(row["currency"], _CURRENCY, error),
        within_offered_budget=_require_bool(row["within_offered_budget"], error),
        private_floor_evidence_digest=_require_sha256(
            row["private_floor_evidence_digest"], error
        ),
        allowed_data_sensitivity_codes=_require_closed_code_tuple(
            row["allowed_data_sensitivity_codes"],
            ("HIGH", "INTERNAL", "PUBLIC", "RESTRICTED"),
            error,
        ),
        ai_use_code=ai_use,
        language_codes=_require_code_tuple(row["language_codes"], 100, error),
        work_mode_code=_require_code(row["work_mode_code"], error),
        region_code=_require_code(row["region_code"], error),
        location_eligible=_require_bool(row["location_eligible"], error),
        conflict_of_interest=_require_bool(row["conflict_of_interest"], error),
    )


def _parse_requirements(value: Any, error: str) -> Tuple[MatchSkillRequirementV1, ...]:
    rows = _require_list(value, error)
    if len(rows) > 100:
        _fail(error)
    result = []
    for row_value in rows:
        row = _require_mapping(row_value, error)
        _require_exact_keys(row, frozenset({"skill_code", "minimum_level"}), error)
        result.append(
            MatchSkillRequirementV1(
                _require_code(row["skill_code"], error),
                _require_bounded_int(row["minimum_level"], 0, 4, error),
            )
        )
    codes = tuple(item.skill_code for item in result)
    _require_ordered_unique(codes, error)
    return tuple(result)


def _parse_skill_facts(value: Any, error: str) -> Tuple[MatchSkillFactV1, ...]:
    rows = _require_list(value, error)
    if len(rows) > 200:
        _fail(error)
    result = []
    for row_value in rows:
        row = _require_mapping(row_value, error)
        _require_exact_keys(
            row,
            frozenset(
                {
                    "skill_code",
                    "proficiency_level",
                    "evidence_trust_level",
                    "evidence_bucket",
                }
            ),
            error,
        )
        bucket = row["evidence_bucket"]
        if bucket not in {"NONE", "SELF_ASSERTED", "DOCUMENTED", "VERIFIED"}:
            _fail(error)
        result.append(
            MatchSkillFactV1(
                skill_code=_require_code(row["skill_code"], error),
                proficiency_level=_require_bounded_int(
                    row["proficiency_level"], 0, 4, error
                ),
                evidence_trust_level=_require_bounded_int(
                    row["evidence_trust_level"], 0, 4, error
                ),
                evidence_bucket=bucket,
            )
        )
    codes = tuple(item.skill_code for item in result)
    _require_ordered_unique(codes, error)
    return tuple(result)


def _run_input_document(value: MatchRunInputV1) -> Mapping[str, Any]:
    return {
        "schema_version": 1,
        "canonicalization_version": "match-run-input-json-v1",
        "attempt_id": value.attempt_id,
        "run_id": value.run_id,
        "demand_id": value.demand_id,
        "demand_version_id": value.demand_version_id,
        "matching_rule_bundle_id": value.matching_rule_bundle_id,
        "input_set_sha256": value.input_set_sha256,
        "demand": _demand_document(value.demand),
        "profiles": [_profile_document(item) for item in value.profiles],
    }


def _demand_document(value: DemandMatchInputV1) -> Mapping[str, Any]:
    return {
        "problem_type_codes": list(value.problem_type_codes),
        "domain_codes": list(value.domain_codes),
        "task_codes": list(value.task_codes),
        "must_have_skills": [
            {"skill_code": item.skill_code, "minimum_level": item.minimum_level}
            for item in value.must_have_skills
        ],
        "nice_to_have_skills": [
            {"skill_code": item.skill_code, "minimum_level": item.minimum_level}
            for item in value.nice_to_have_skills
        ],
        "start_date": value.start_date.isoformat(),
        "due_date": value.due_date.isoformat(),
        "required_weekly_hours": value.required_weekly_hours,
        "required_duration_weeks": value.required_duration_weeks,
        "currency": value.currency,
        "minimum_amount_minor": value.minimum_amount_minor,
        "maximum_amount_minor": value.maximum_amount_minor,
        "allowed_region_codes": list(value.allowed_region_codes),
        "required_language_codes": list(value.required_language_codes),
        "required_work_mode_code": value.required_work_mode_code,
        "data_sensitivity_code": value.data_sensitivity_code,
        "ai_use_code": value.ai_use_code,
        "budget_override_code": value.budget_override_code,
    }


def _profile_document(value: ProfileMatchInputV1) -> Mapping[str, Any]:
    return {
        "creator_user_id": value.creator_user_id,
        "profile_id": value.profile_id,
        "profile_version_id": value.profile_version_id,
        "profile_content_sha256": value.profile_content_sha256,
        "evidence_version_digest": value.evidence_version_digest,
        "status": value.status,
        "interest_problem_type_codes": list(value.interest_problem_type_codes),
        "interest_domain_codes": list(value.interest_domain_codes),
        "interest_task_codes": list(value.interest_task_codes),
        "interest_intensity": value.interest_intensity,
        "prohibited_domain_codes": list(value.prohibited_domain_codes),
        "prohibited_task_codes": list(value.prohibited_task_codes),
        "skills": [
            {
                "skill_code": item.skill_code,
                "proficiency_level": item.proficiency_level,
                "evidence_trust_level": item.evidence_trust_level,
                "evidence_bucket": item.evidence_bucket,
            }
            for item in value.skills
        ],
        "available_from": value.available_from.isoformat(),
        "available_weekly_hours": value.available_weekly_hours,
        "available_duration_weeks": value.available_duration_weeks,
        "currency": value.currency,
        "within_offered_budget": value.within_offered_budget,
        "private_floor_evidence_digest": value.private_floor_evidence_digest,
        "allowed_data_sensitivity_codes": list(
            value.allowed_data_sensitivity_codes
        ),
        "ai_use_code": value.ai_use_code,
        "language_codes": list(value.language_codes),
        "work_mode_code": value.work_mode_code,
        "region_code": value.region_code,
        "location_eligible": value.location_eligible,
        "conflict_of_interest": value.conflict_of_interest,
    }


def _revalidate_normalized_input(value: MatchRunInputV1) -> MatchRunInputV1:
    try:
        return normalize_match_run_input_v1(
            _run_input_document(value),
            expected_input_set_sha256=value.input_set_sha256,
            expected_canonical_sha256=value.canonical_input_sha256,
        )
    except DeterministicMatcherV1Error:
        raise
    except Exception:
        _fail("MATCH_RUN_INPUT_INVALID")


def _revalidate_loaded_rule(value: LoadedMatchingRuleReleaseV1) -> None:
    if not isinstance(value, LoadedMatchingRuleReleaseV1):
        _fail("MATCH_RULE_RELEASE_INVALID")
    document, canonical = _document_and_canonical_bytes(
        value.canonical_manifest_bytes,
        canonical_error="MATCH_RULE_RELEASE_CANONICAL_MISMATCH",
        invalid_error="MATCH_RULE_RELEASE_INVALID",
        maximum_bytes=256 * 1024,
    )
    digest = hashlib.sha256(canonical).hexdigest()
    if digest != value.canonical_manifest_sha256:
        _fail("MATCH_RULE_RELEASE_DIGEST_MISMATCH")
    reloaded = _parse_rule_release(
        document,
        canonical,
        digest,
        value.engine_artifact_sha256,
    )
    if reloaded != value:
        _fail("MATCH_RULE_RELEASE_INVALID")


def _candidate_document(candidate: MatchCandidate) -> Mapping[str, Any]:
    try:
        document = json.loads(canonical_candidate_result_bytes(candidate))
    except Exception:
        _fail("MATCH_RESULT_INVALID")
    document["candidate_result_sha256"] = candidate.candidate_result_sha256
    # This exact key set intentionally excludes evidence_version_digest.  The
    # persistence adapter binds that value from the immutable input identity.
    expected = {
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
    }
    if set(document) != expected:
        _fail("MATCH_RESULT_INVALID")
    return document


def _load_engine_artifact(
    spec_raw: bytes,
    vectors_raw: bytes,
) -> Tuple[str, Mapping[str, Any]]:
    spec, canonical_spec = _document_and_canonical_bytes(
        spec_raw,
        canonical_error="MATCH_ENGINE_ARTIFACT_INVALID",
        invalid_error="MATCH_ENGINE_ARTIFACT_INVALID",
        maximum_bytes=256 * 1024,
    )
    vectors, canonical_vectors = _document_and_canonical_bytes(
        vectors_raw,
        canonical_error="MATCH_ENGINE_ARTIFACT_INVALID",
        invalid_error="MATCH_ENGINE_ARTIFACT_INVALID",
        maximum_bytes=4 * 1024 * 1024,
    )
    _validate_engine_spec(spec, hashlib.sha256(canonical_vectors).hexdigest())
    _validate_golden_vector_document(vectors)
    return hashlib.sha256(canonical_spec).hexdigest(), vectors


def _validate_engine_spec(value: Any, vectors_sha256: str) -> None:
    error = "MATCH_ENGINE_ARTIFACT_INVALID"
    root = _require_mapping(value, error)
    keys = frozenset(
        {
            "schema_version",
            "canonicalization_version",
            "engine_identifier",
            "engine_major",
            "input_contract",
            "candidate_contract",
            "result_contract",
            "arithmetic",
            "hard_filters",
            "components",
            "weighted_total_formula",
            "rank_order",
            "evidence_fact_kinds",
            "privacy_exclusions",
            "golden_vectors_resource",
            "golden_vectors_resource_sha256",
        }
    )
    _require_exact_keys(root, keys, error)
    _require_exact_int(root["schema_version"], 1, error)
    _require_exact_string(
        root["canonicalization_version"],
        "deterministic-matcher-engine-artifact-json-v1",
        error,
    )
    _require_exact_string(root["engine_identifier"], ENGINE_IDENTIFIER, error)
    _require_exact_int(root["engine_major"], ENGINE_MAJOR, error)
    _require_exact_string(root["input_contract"], "match-run-input-v1", error)
    _require_exact_string(
        root["candidate_contract"], "match-candidate-result-v1", error
    )
    _require_exact_string(
        root["result_contract"], "deterministic-match-result-v1", error
    )
    arithmetic = _require_mapping(root["arithmetic"], error)
    _require_exact_keys(
        arithmetic,
        frozenset({"number_system", "intermediate_rounding", "rounding_mode", "score_scale"}),
        error,
    )
    _require_exact_string(arithmetic["number_system"], "INTEGER_RATIONAL", error)
    _require_exact_string(arithmetic["intermediate_rounding"], "NONE", error)
    _require_exact_string(arithmetic["rounding_mode"], "ROUND_HALF_EVEN", error)
    _require_exact_int(arithmetic["score_scale"], 2, error)

    hard_rows = _require_list(root["hard_filters"], error)
    if tuple(row.get("code") for row in hard_rows if isinstance(row, Mapping)) != HARD_FILTER_CODES:
        _fail(error)
    if tuple(
        row.get("ordinal")
        for row in hard_rows
        if isinstance(row, Mapping)
    ) != tuple(range(1, 16)):
        _fail(error)
    expected_predicates = (
        "status != ACTIVE",
        "demand.domain_codes intersects profile.prohibited_domain_codes",
        "demand.task_codes intersects profile.prohibited_task_codes",
        "a must-have skill is absent or proficiency_level < minimum_level",
        "available_from > due_date",
        "available_weekly_hours < required_weekly_hours",
        "available_duration_weeks < required_duration_weeks",
        "profile.currency != demand.currency",
        "not within_offered_budget and budget_override_code != APPROVED_EXCEPTION",
        "data_sensitivity_code not in allowed_data_sensitivity_codes",
        "REQUIRED conflicts with PROHIBITED in either direction",
        "required languages are nonempty and have no intersection",
        "profile.work_mode_code != demand.required_work_mode_code",
        "not location_eligible or region is outside a nonempty allowed set",
        "conflict_of_interest",
    )
    for row_value, code, ordinal, predicate in zip(
        hard_rows, HARD_FILTER_CODES, range(1, 16), expected_predicates
    ):
        row = _require_mapping(row_value, error)
        _require_exact_keys(row, frozenset({"code", "ordinal", "predicate"}), error)
        _require_exact_string(row["code"], code, error)
        _require_exact_int(row["ordinal"], ordinal, error)
        _require_exact_string(row["predicate"], predicate, error)

    component_rows = _require_list(root["components"], error)
    formulas = (
        "100 * ((problem_overlap + domain_overlap + task_overlap) / 3) * ((6 + interest_intensity) / 10); each overlap = 1/2 when the demand code set is empty, otherwise intersection_count / demand_count",
        "100 * (17/20 * must_mean + 3/20 * nice_mean); skill_quality = proficiency_level * (28 + 3 * evidence_trust_level) / 160; a missing skill has quality 0; empty must_mean = 1; empty nice_mean = must_mean",
        "100 * (1/2 * capacity_fit + 1/4 * duration_fit + 1/4 * start_fit); capacity/duration fit = 1 when required is 0, otherwise min(available/(2*required),1); start_fit = 1 when available_from <= start_date, otherwise max((due_date-available_from).days,0) / max((due_date-start_date).days,1)",
        "100 when within_offered_budget; 60 only for APPROVED_EXCEPTION; otherwise 0",
        "100 * (language_fit + work_mode_fit + location_fit + ai_fit) / 4; language_fit = 1 when no language is required, otherwise shared_required_count/required_count; work_mode_fit = 1 for exact match else 0; location_fit = 1 for eligible exact/no-restriction region, 3/4 for eligible outside region, else 0; ai_fit = 1 exact, 3/4 when either side is OPTIONAL, else 0",
        "100 * mean((evidence_trust_level + evidence_bucket_level)/8) over demanded skills present in the profile; when no skills are demanded use all profile skills; an empty selected skill set scores 0; bucket levels NONE=0 SELF_ASSERTED=1 DOCUMENTED=3 VERIFIED=4",
    )
    if len(component_rows) != 6:
        _fail(error)
    for row_value, code, ordinal, formula in zip(
        component_rows, COMPONENT_CODES, range(1, 7), formulas
    ):
        row = _require_mapping(row_value, error)
        _require_exact_keys(row, frozenset({"code", "ordinal", "formula"}), error)
        _require_exact_string(row["code"], code, error)
        _require_exact_int(row["ordinal"], ordinal, error)
        _require_exact_string(row["formula"], formula, error)

    _require_exact_string(
        root["weighted_total_formula"],
        "sum(unrounded_component_score * weight_bps / 10000), then ROUND_HALF_EVEN to 2 decimals",
        error,
    )
    rank_order = _require_list(root["rank_order"], error)
    if rank_order != ["total_score DESC", "creator_user_id UTF-8 ASC"]:
        _fail(error)
    if _require_list(root["evidence_fact_kinds"], error) != [
        "BOOLEAN",
        "CODE",
        "BUCKET",
    ]:
        _fail(error)
    if _require_list(root["privacy_exclusions"], error) != [
        "CONTACT",
        "PROTECTED_ATTRIBUTE",
        "PROSE",
        "PRIVATE_FLOOR_VALUE",
        "PRECISE_LOCATION",
        "CONFLICT_OBJECT",
        "EVIDENCE_LOCATOR",
    ]:
        _fail(error)
    _require_exact_string(
        root["golden_vectors_resource"], GOLDEN_VECTORS_RESOURCE, error
    )
    if _require_sha256(root["golden_vectors_resource_sha256"], error) != vectors_sha256:
        _fail(error)


def _validate_golden_vector_document(value: Any) -> None:
    error = "MATCH_ENGINE_ARTIFACT_INVALID"
    root = _require_mapping(value, error)
    _require_exact_keys(
        root,
        frozenset(
            {
                "schema_version",
                "canonicalization_version",
                "engine_identifier",
                "engine_major",
                "vectors",
            }
        ),
        error,
    )
    _require_exact_int(root["schema_version"], 1, error)
    _require_exact_string(
        root["canonicalization_version"],
        "deterministic-matcher-golden-vectors-json-v1",
        error,
    )
    _require_exact_string(root["engine_identifier"], ENGINE_IDENTIFIER, error)
    _require_exact_int(root["engine_major"], ENGINE_MAJOR, error)
    rows = _require_list(root["vectors"], error)
    if len(rows) < 3:
        _fail(error)
    ids = []
    coverage = set()
    for row_value in rows:
        row = _require_mapping(row_value, error)
        _require_exact_keys(
            row, frozenset({"vector_id", "coverage", "run_input"}), error
        )
        ids.append(_require_opaque_id(row["vector_id"], error))
        if row["coverage"] not in {"excluded", "same-score-tie", "budget-override"}:
            _fail(error)
        coverage.add(row["coverage"])
        normalize_match_run_input_v1(row["run_input"])
    if tuple(ids) != tuple(sorted(ids, key=lambda item: item.encode("utf-8"))):
        _fail(error)
    if len(set(ids)) != len(ids) or coverage != {
        "excluded",
        "same-score-tie",
        "budget-override",
    }:
        _fail(error)


def _verify_golden_vectors(
    rule: LoadedMatchingRuleReleaseV1,
    document: Mapping[str, Any],
) -> None:
    rows = _require_list(document["vectors"], "MATCH_GOLDEN_VECTOR_INVALID")
    references = {item.vector_id: item for item in rule.golden_vectors}
    if set(references) != {row["vector_id"] for row in rows}:
        _fail("MATCH_GOLDEN_VECTOR_INVALID")
    for row in rows:
        reference = references[row["vector_id"]]
        input_bytes = _jcs_bytes(row["run_input"], "MATCH_GOLDEN_VECTOR_INVALID")
        if hashlib.sha256(input_bytes).hexdigest() != reference.input_sha256:
            _fail("MATCH_GOLDEN_VECTOR_INVALID")
        normalized = normalize_match_run_input_v1(row["run_input"])
        result = evaluate_match_run_v1(normalized, rule)
        if result.engine_result_sha256 != reference.expected_result_sha256:
            _fail("MATCH_GOLDEN_VECTOR_INVALID")


def _document_and_canonical_bytes(
    value: Union[bytes, bytearray, Mapping[str, Any]],
    *,
    canonical_error: str,
    invalid_error: str,
    maximum_bytes: int,
) -> Tuple[Mapping[str, Any], bytes]:
    if isinstance(value, (bytes, bytearray)):
        raw = bytes(value)
        if not raw or len(raw) > maximum_bytes:
            _fail(invalid_error)
        try:
            document = json.loads(
                raw.decode("utf-8"),
                object_pairs_hook=_reject_duplicate_pairs,
                parse_float=lambda _: _fail(invalid_error),
                parse_constant=lambda _: _fail(invalid_error),
            )
        except DeterministicMatcherV1Error:
            raise
        except Exception:
            _fail(invalid_error)
        canonical = _jcs_bytes(document, invalid_error)
        if raw != canonical:
            _fail(canonical_error)
        return _require_mapping(document, invalid_error), canonical
    document = _plain_json(value, invalid_error)
    canonical = _jcs_bytes(document, invalid_error)
    if len(canonical) > maximum_bytes:
        _fail(invalid_error)
    return _require_mapping(document, invalid_error), canonical


def _reject_duplicate_pairs(pairs: Sequence[Tuple[str, Any]]) -> Mapping[str, Any]:
    result = {}
    for key, value in pairs:
        if key in result:
            _fail("MATCH_JSON_DUPLICATE_KEY")
        result[key] = value
    return result


def _plain_json(value: Any, error: str) -> Any:
    if isinstance(value, Mapping):
        result = {}
        for key, child in value.items():
            if type(key) is not str or key in result:
                _fail(error)
            result[key] = _plain_json(child, error)
        return result
    if isinstance(value, (list, tuple)):
        return [_plain_json(child, error) for child in value]
    if value is None or type(value) in {bool, int, str}:
        return value
    _fail(error)


def _jcs_bytes(value: Any, error: str) -> bytes:
    try:
        return json.dumps(
            _plain_json(value, error),
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except DeterministicMatcherV1Error:
        raise
    except Exception:
        _fail(error)


def _resource_bytes(name: str) -> bytes:
    try:
        raw = resources.files("desire_platform.matching.resources").joinpath(name).read_bytes()
        # Source-controlled text resources carry one POSIX line terminator;
        # the reviewed artifact is the sole canonical JSON value before it.
        return raw[:-1] if raw.endswith(b"\n") else raw
    except Exception:
        _fail("MATCH_ENGINE_ARTIFACT_INVALID")


def _require_mapping(value: Any, error: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        _fail(error)
    return value


def _require_list(value: Any, error: str) -> list[Any]:
    if type(value) is not list:
        _fail(error)
    return value


def _require_exact_keys(
    value: Mapping[str, Any], expected: frozenset[str], error: str
) -> None:
    if frozenset(value) != expected:
        _fail(error)


def _require_exact_int(value: Any, expected: int, error: str) -> int:
    if type(value) is not int or value != expected:
        _fail(error)
    return value


def _require_bounded_int(value: Any, minimum: int, maximum: int, error: str) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        _fail(error)
    return value


def _require_bool(value: Any, error: str) -> bool:
    if type(value) is not bool:
        _fail(error)
    return value


def _require_exact_string(value: Any, expected: str, error: str) -> str:
    if type(value) is not str or value != expected:
        _fail(error)
    return value


def _require_pattern(value: Any, pattern: re.Pattern[str], error: str) -> str:
    if type(value) is not str or pattern.fullmatch(value) is None:
        _fail(error)
    return value


def _require_opaque_id(value: Any, error: str) -> str:
    return _require_pattern(value, _OPAQUE_ID, error)


def _require_sha256(value: Any, error: str) -> str:
    return _require_pattern(value, _SHA256, error)


def _require_code(value: Any, error: str) -> str:
    return _require_pattern(value, _CODE, error)


def _require_date(value: Any, error: str) -> date:
    if type(value) is not str:
        _fail(error)
    try:
        result = date.fromisoformat(value)
    except ValueError:
        _fail(error)
    if result.isoformat() != value:
        _fail(error)
    return result


def _require_timestamp(value: Any, error: str) -> datetime:
    if type(value) is not str or not value.endswith("Z"):
        _fail(error)
    try:
        result = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        _fail(error)
    if result.tzinfo is None or result.utcoffset() != timedelta(0):
        _fail(error)
    return result.astimezone(timezone.utc)


def _require_code_tuple(value: Any, maximum: int, error: str) -> Tuple[str, ...]:
    rows = _require_list(value, error)
    if len(rows) > maximum:
        _fail(error)
    result = tuple(_require_code(item, error) for item in rows)
    _require_ordered_unique(result, error)
    return result


def _require_closed_code_tuple(
    value: Any,
    allowed_order: Tuple[str, ...],
    error: str,
) -> Tuple[str, ...]:
    result = _require_code_tuple(value, len(allowed_order), error)
    if any(item not in allowed_order for item in result):
        _fail(error)
    return result


def _require_ordered_unique(values: Tuple[str, ...], error: str) -> None:
    if len(set(values)) != len(values) or values != tuple(
        sorted(values, key=lambda item: item.encode("utf-8"))
    ):
        _fail(error)


def _fail(code: str) -> Any:
    raise DeterministicMatcherV1Error(code)


__all__ = [
    "COMPONENT_CODES",
    "DEFAULT_RULE_RESOURCE",
    "DeterministicMatchResultV1",
    "DeterministicMatcherV1Error",
    "DemandMatchInputV1",
    "ENGINE_IDENTIFIER",
    "ENGINE_MAJOR",
    "ENGINE_SPEC_RESOURCE",
    "GOLDEN_VECTORS_RESOURCE",
    "HARD_FILTER_CODES",
    "LoadedMatchingRuleReleaseV1",
    "MatchRunInputV1",
    "ProfileMatchInputV1",
    "component_scores_v1",
    "compose_match_run_input_v1",
    "demand_postgres_snapshot_to_input_v1",
    "evaluate_candidate_hard_filters_v1",
    "evaluate_match_run_v1",
    "load_default_rule_release_v1",
    "load_rule_release_v1",
    "normalize_match_run_input_v1",
]
