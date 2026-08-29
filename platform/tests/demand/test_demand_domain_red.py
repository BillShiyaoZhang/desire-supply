"""First semantic RED for Demand content, immutable facts, and lifecycle."""

from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
from datetime import timedelta
import hashlib
import json
from typing import Any, Callable
import unittest

from desire_platform.demand.domain import (
    CancelReasonCode,
    Demand,
    DemandDomainBehaviorNotAvailable,
    DemandDomainError,
    DemandFinanceFundingFinding,
    DemandStatus,
    FinanceFundingFindingDisposition,
    ReviewResult,
    DEMAND_DOMAIN_BEHAVIOR_NOT_AVAILABLE,
    canonical_demand_version_bytes,
    demand_version_content_sha256,
    require_demand_version_immutable,
    validate_demand,
    validate_demand_content,
    validate_demand_version,
)
from tests.support.demand_builders import (
    ASSIGNMENT_ID,
    DEMAND_ID,
    FUNDING_ID,
    ORGANIZATION_ID,
    OWNER_USER_ID,
    REVIEW_ID,
    REVIEWER_USER_ID,
    SECOND_VERSION_ID,
    TAXONOMY_ID,
    UTC_NOW,
    VALID_CONTENT_SHA256,
    VERSION_ID,
    demand,
    demand_version,
    freeze_json,
    funding_marker,
    matching_request,
    review,
    review_assignment,
    submission,
    thaw_json,
    valid_content,
    valid_content_mapping,
)


def _capture(call: Callable[[], Any]) -> tuple[Any, str | None]:
    try:
        return call(), None
    except DemandDomainError as error:
        return None, error.code
    except DemandDomainBehaviorNotAvailable as error:
        if str(error) != DEMAND_DOMAIN_BEHAVIOR_NOT_AVAILABLE:
            raise
        return None, DEMAND_DOMAIN_BEHAVIOR_NOT_AVAILABLE


class DemandDomainSemanticRedTest(unittest.TestCase):
    """TEST-UNIT-DEMAND-001 and TEST-PROP-DEMAND-001."""

    def test_immutable_facts_hide_content_and_sensitive_evidence(self) -> None:
        root = demand()
        version = demand_version()
        marker = funding_marker()
        rendered = repr((root, version, marker, version.content))
        self.assertNotIn("Reduce energy waste", rendered)
        self.assertNotIn("provider-evidence", rendered)
        self.assertNotIn(root.client_reference_digest, rendered)
        with self.assertRaises(FrozenInstanceError):
            root.status = DemandStatus.SUBMITTED  # type: ignore[misc]
        with self.assertRaises(FrozenInstanceError):
            version.content = valid_content()  # type: ignore[misc]

    def test_finance_rejected_fact_justifies_owner_needs_changes(self) -> None:
        root = demand(
            status=DemandStatus.NEEDS_CHANGES,
            aggregate_version=5,
            verified_version_id=None,
        )
        rejected = DemandFinanceFundingFinding(
            finding_id="finance_finding_00001",
            organization_id=ORGANIZATION_ID,
            demand_id=DEMAND_ID,
            demand_version_id=VERSION_ID,
            funding_review_id="funding_review_00001",
            disposition=FinanceFundingFindingDisposition.REJECTED,
            reason_codes=("BUDGET_PLAN_UNACCEPTABLE",),
            required_field_codes=("BUDGET",),
            created_at=UTC_NOW,
        )
        validate_demand(
            root,
            versions=(demand_version(),),
            submissions=(submission(),),
            reviews=(review(result=ReviewResult.VERIFIED),),
            funding_markers=(),
            matching_requests=(),
            finance_findings=(rejected,),
        )
        for invalid in (
            replace(
                rejected,
                disposition=FinanceFundingFindingDisposition.DISCREPANCY,
                reason_codes=("TARGET_CONTENT_MISMATCH",),
            ),
            replace(rejected, demand_version_id=SECOND_VERSION_ID),
        ):
            with self.assertRaises(DemandDomainError):
                validate_demand(
                    root,
                    versions=(demand_version(),),
                    submissions=(submission(),),
                    reviews=(review(result=ReviewResult.VERIFIED),),
                    funding_markers=(),
                    matching_requests=(),
                    finance_findings=(invalid,),
                )

    def test_content_is_closed_nfc_control_and_utf8_byte_bounded(self) -> None:
        mappings: list[tuple[str, dict[str, Any], str | None]] = [
            ("valid", valid_content_mapping(), None),
        ]
        unknown = valid_content_mapping()
        unknown["provider_payload"] = "private"
        mappings.append(("unknown", unknown, "DEMAND_VALIDATION_FAILED"))
        nested_unknown = valid_content_mapping()
        nested_unknown["scope"]["deliverables"][0]["contact"] = "private"
        mappings.append(("nested-unknown", nested_unknown, "DEMAND_VALIDATION_FAILED"))
        non_nfc = valid_content_mapping()
        non_nfc["problem"]["background"] = "Cafe\u0301"
        mappings.append(("non-nfc", non_nfc, "DEMAND_VALIDATION_FAILED"))
        control = valid_content_mapping()
        control["problem"]["background"] = "unsafe\u0007text"
        mappings.append(("control", control, "DEMAND_VALIDATION_FAILED"))
        byte_overflow = valid_content_mapping()
        byte_overflow["problem"]["background"] = "界" * 4001
        mappings.append(("utf8-byte-overflow", byte_overflow, "DEMAND_VALIDATION_FAILED"))

        observed = []
        for name, mapping, expected in mappings:
            _value, code = _capture(
                lambda mapping=mapping: validate_demand_content(
                    freeze_json(mapping), for_submission=False
                )
            )
            observed.append((name, code, expected))
        self.assertEqual(
            [(name, code) for name, code, _expected in observed],
            [(name, expected) for name, _code, expected in observed],
        )

    def test_bool_amount_percent_and_cross_field_numeric_rules_are_rejected(self) -> None:
        invalid: list[dict[str, Any]] = []
        for field in (
            "minimum_amount_minor",
            "maximum_amount_minor",
            "direct_cost_amount_minor",
        ):
            mapping = valid_content_mapping()
            mapping["budget"][field] = True
            invalid.append(mapping)
        bool_percent = valid_content_mapping()
        bool_percent["milestone_plan"]["items"][0]["percent"] = True
        invalid.append(bool_percent)
        reversed_range = valid_content_mapping()
        reversed_range["budget"].update(
            {"minimum_amount_minor": 300000, "maximum_amount_minor": 200000}
        )
        invalid.append(reversed_range)
        negative_direct = valid_content_mapping()
        negative_direct["budget"]["direct_cost_amount_minor"] = -1
        invalid.append(negative_direct)
        wrong_percent = valid_content_mapping()
        wrong_percent["milestone_plan"]["items"][1]["percent"] = 59
        invalid.append(wrong_percent)

        codes = [
            _capture(
                lambda mapping=mapping: validate_demand_content(
                    freeze_json(mapping), for_submission=False
                )
            )[1]
            for mapping in invalid
        ]
        self.assertEqual(codes, ["DEMAND_VALIDATION_FAILED"] * len(invalid))

    def test_calendar_dates_ranges_and_ai_data_policy_are_cross_validated(self) -> None:
        cases: list[dict[str, Any]] = []
        invalid_calendar = valid_content_mapping()
        invalid_calendar["schedule"]["start_date"] = "2026-02-30"
        cases.append(invalid_calendar)
        reversed_dates = valid_content_mapping()
        reversed_dates["schedule"].update(
            {"start_date": "2026-11-01", "due_date": "2026-10-31"}
        )
        cases.append(reversed_dates)
        ai_required_denied = valid_content_mapping()
        ai_required_denied["ai"].update({"required": True, "allowed": False})
        cases.append(ai_required_denied)
        ai_without_policy = valid_content_mapping()
        ai_without_policy["ai"]["data_model_policy"] = None
        cases.append(ai_without_policy)
        restricted_without_plan = valid_content_mapping()
        restricted_without_plan["risk"].update(
            {"data_sensitivity": "RESTRICTED", "data_handling_plan": None}
        )
        cases.append(restricted_without_plan)

        self.assertEqual(
            [
                _capture(
                    lambda mapping=mapping: validate_demand_content(
                        freeze_json(mapping), for_submission=False
                    )
                )[1]
                for mapping in cases
            ],
            ["DEMAND_VALIDATION_FAILED"] * len(cases),
        )

    def test_submission_completeness_skill_overlap_and_matching_domain_are_enforced(self) -> None:
        partial = {"problem": valid_content_mapping()["problem"]}
        overlapping = valid_content_mapping()
        overlapping["skills"]["nice_to_have"] = list(
            overlapping["skills"]["must_have"]
        )
        wrong_domain = valid_content_mapping()
        wrong_domain["matching"]["domain_codes"] = ["DOMAIN.HEALTH"]
        false_declaration = valid_content_mapping()
        false_declaration["declarations"]["data_rights"] = False
        observations = []
        for mapping in (partial, overlapping, wrong_domain, false_declaration):
            observations.append(
                _capture(
                    lambda mapping=mapping: validate_demand_content(
                        freeze_json(mapping), for_submission=True
                    )
                )[1]
            )
        self.assertEqual(observations, ["DEMAND_VALIDATION_FAILED"] * 4)

    def test_jcs_bytes_and_sha_bind_demand_version_taxonomy_and_content(self) -> None:
        content = valid_content()
        mapping = thaw_json(content)
        reordered = freeze_json(dict(reversed(tuple(mapping.items()))))
        canonical, canonical_code = _capture(
            lambda: canonical_demand_version_bytes(
                demand_id=DEMAND_ID,
                version_no=1,
                taxonomy_bundle_id=TAXONOMY_ID,
                content=content,
            )
        )
        reordered_bytes, reorder_code = _capture(
            lambda: canonical_demand_version_bytes(
                demand_id=DEMAND_ID,
                version_no=1,
                taxonomy_bundle_id=TAXONOMY_ID,
                content=reordered,
            )
        )
        digest, digest_code = _capture(
            lambda: demand_version_content_sha256(
                demand_id=DEMAND_ID,
                version_no=1,
                taxonomy_bundle_id=TAXONOMY_ID,
                content=content,
            )
        )
        expected_bytes = json.dumps(
            {
                "canonicalization_version": "demand-content-json-v1",
                "content": mapping,
                "demand_id": DEMAND_ID,
                "demand_schema_version": 1,
                "taxonomy_bundle_id": TAXONOMY_ID,
                "version_no": 1,
            },
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        self.assertEqual(
            {
                "canonical_code": canonical_code,
                "canonical": canonical,
                "reorder_code": reorder_code,
                "order_independent": reordered_bytes == canonical,
                "digest_code": digest_code,
                "digest": digest,
            },
            {
                "canonical_code": None,
                "canonical": expected_bytes,
                "reorder_code": None,
                "order_independent": True,
                "digest_code": None,
                "digest": hashlib.sha256(expected_bytes).hexdigest(),
            },
        )

    def test_create_and_each_save_append_exact_monotonic_version(self) -> None:
        created, create_code = _capture(
            lambda: Demand.create(
                demand_id=DEMAND_ID,
                demand_version_id=VERSION_ID,
                organization_id=ORGANIZATION_ID,
                created_by_user_id=OWNER_USER_ID,
                taxonomy_bundle_id=TAXONOMY_ID,
                content=valid_content(),
                client_reference_digest_key_id="demand-client-ref-2026-01",
                client_reference_digest="a" * 64,
                expires_at=UTC_NOW + timedelta(days=60),
                now=UTC_NOW,
            )
        )
        current = demand(aggregate_version=1)
        appended, append_code = _capture(
            lambda: current.create_version(
                demand_version_id=SECOND_VERSION_ID,
                based_on_demand_version_id=VERSION_ID,
                taxonomy_bundle_id=TAXONOMY_ID,
                content=valid_content(),
                actor_user_id=OWNER_USER_ID,
                existing_versions=(demand_version(),),
                now=UTC_NOW,
            )
        )
        created_root = created[0] if isinstance(created, tuple) else None
        created_version = created[1] if isinstance(created, tuple) else None
        appended_root = appended[0] if isinstance(appended, tuple) else None
        appended_version = appended[1] if isinstance(appended, tuple) else None
        self.assertEqual(
            {
                "create_code": create_code,
                "create_status": getattr(created_root, "status", None),
                "create_aggregate_version": getattr(created_root, "aggregate_version", None),
                "create_version_no": getattr(created_version, "version_no", None),
                "append_code": append_code,
                "append_aggregate_version": getattr(appended_root, "aggregate_version", None),
                "append_version_no": getattr(appended_version, "version_no", None),
                "append_base": getattr(appended_version, "based_on_demand_version_id", None),
            },
            {
                "create_code": None,
                "create_status": DemandStatus.DRAFT,
                "create_aggregate_version": 1,
                "create_version_no": 1,
                "append_code": None,
                "append_aggregate_version": 2,
                "append_version_no": 2,
                "append_base": VERSION_ID,
            },
        )

    def test_version_is_append_only_and_hash_is_recomputed_on_validation(self) -> None:
        before = demand_version()
        content_changed = valid_content_mapping()
        content_changed["problem"]["background"] = "Silently rewritten history."
        after = replace(before, content=freeze_json(content_changed))
        _valid, valid_code = _capture(
            lambda: validate_demand_version(
                before,
                demand=demand(),
                prior_versions=(),
                for_submission=False,
            )
        )
        _immutable, immutable_code = _capture(
            lambda: require_demand_version_immutable(before=before, after=after)
        )
        self.assertEqual(
            (valid_code, immutable_code),
            (None, "INVALID_STATE_TRANSITION"),
        )

    def test_submission_binds_exact_current_version_hash_and_is_unique(self) -> None:
        submitted, submit_code = _capture(
            lambda: demand().submit(
                submission_id="demand_submission_00002",
                actor_user_id=OWNER_USER_ID,
                current_version=demand_version(),
                prior_submissions=(),
                content_policy_version="demand-content-policy-v1",
                content_policy_result_sha256="c" * 64,
                now=UTC_NOW,
            )
        )
        _duplicate, duplicate_code = _capture(
            lambda: demand().submit(
                submission_id="demand_submission_00002",
                actor_user_id=OWNER_USER_ID,
                current_version=demand_version(),
                prior_submissions=(submission(),),
                content_policy_version="demand-content-policy-v1",
                content_policy_result_sha256="c" * 64,
                now=UTC_NOW,
            )
        )
        submitted_root = submitted[0] if isinstance(submitted, tuple) else None
        submitted_fact = submitted[1] if isinstance(submitted, tuple) else None
        self.assertEqual(
            {
                "submit_code": submit_code,
                "status": getattr(submitted_root, "status", None),
                "version": getattr(submitted_root, "aggregate_version", None),
                "fact_version": getattr(submitted_fact, "demand_version_id", None),
                "fact_hash": getattr(submitted_fact, "content_sha256", None),
                "duplicate_code": duplicate_code,
            },
            {
                "submit_code": None,
                "status": DemandStatus.SUBMITTED,
                "version": 2,
                "fact_version": VERSION_ID,
                "fact_hash": VALID_CONTENT_SHA256,
                "duplicate_code": "INVALID_STATE_TRANSITION",
            },
        )

    def test_review_requires_exact_submission_assignment_reviewer_and_result_shape(self) -> None:
        submitted_root = demand(status=DemandStatus.SUBMITTED, aggregate_version=2)
        changes, changes_code = _capture(
            lambda: submitted_root.request_changes(
                review_id=REVIEW_ID,
                assignment_id=ASSIGNMENT_ID,
                current_version=demand_version(),
                submission=submission(),
                assignment=review_assignment(),
                reviewer_user_id=REVIEWER_USER_ID,
                reason_codes=("SCOPE_UNCLEAR",),
                required_field_codes=("SCOPE",),
                now=UTC_NOW,
            )
        )
        verified, verified_code = _capture(
            lambda: submitted_root.verify(
                review_id=REVIEW_ID,
                assignment_id=ASSIGNMENT_ID,
                current_version=demand_version(),
                submission=submission(),
                assignment=review_assignment(),
                reviewer_user_id=REVIEWER_USER_ID,
                budget_health_code="HEALTHY",
                risk_code="STANDARD",
                evidence_summary_sha256="e" * 64,
                now=UTC_NOW,
            )
        )
        wrong_assignment = replace(review_assignment(), assignment_id="wrong_assignment_00001")
        _wrong, wrong_code = _capture(
            lambda: submitted_root.verify(
                review_id=REVIEW_ID,
                assignment_id=ASSIGNMENT_ID,
                current_version=demand_version(),
                submission=submission(),
                assignment=wrong_assignment,
                reviewer_user_id=REVIEWER_USER_ID,
                budget_health_code="HEALTHY",
                risk_code="STANDARD",
                evidence_summary_sha256="e" * 64,
                now=UTC_NOW,
            )
        )
        changes_fact = changes[1] if isinstance(changes, tuple) else None
        verified_fact = verified[1] if isinstance(verified, tuple) else None
        self.assertEqual(
            {
                "changes_code": changes_code,
                "changes_result": getattr(changes_fact, "result", None),
                "verify_code": verified_code,
                "verify_result": getattr(verified_fact, "result", None),
                "wrong_code": wrong_code,
            },
            {
                "changes_code": None,
                "changes_result": ReviewResult.NEEDS_CHANGES,
                "verify_code": None,
                "verify_result": ReviewResult.VERIFIED,
                "wrong_code": "REVIEW_CONFLICT",
            },
        )

    def test_root_pointer_shape_and_terminal_states_cannot_reopen(self) -> None:
        _valid, valid_code = _capture(
            lambda: validate_demand(
                demand(),
                versions=(demand_version(),),
                submissions=(),
                reviews=(),
                funding_markers=(),
                matching_requests=(),
            )
        )
        corrupt = demand(
            status=DemandStatus.MATCHING,
            aggregate_version=6,
            verified_version_id=VERSION_ID,
            current_funding_id=FUNDING_ID,
            current_matching_request_id=None,
        )
        _corrupt, corrupt_code = _capture(
            lambda: validate_demand(
                corrupt,
                versions=(demand_version(),),
                submissions=(submission(),),
                reviews=(review(),),
                funding_markers=(funding_marker(),),
                matching_requests=(),
            )
        )
        terminal_codes = []
        for terminal in (
            demand(
                status=DemandStatus.MATCHED,
                aggregate_version=7,
                verified_version_id=VERSION_ID,
                current_funding_id=FUNDING_ID,
            ),
            demand(
                status=DemandStatus.CANCELLED,
                aggregate_version=2,
                cancelled_at=UTC_NOW,
                reason_code=CancelReasonCode.OWNER_WITHDREW,
            ),
            demand(
                status=DemandStatus.EXPIRED,
                aggregate_version=2,
                expired_at=UTC_NOW,
                reason_code=CancelReasonCode.DEADLINE_REACHED,
            ),
        ):
            _value, code = _capture(
                lambda terminal=terminal: terminal.create_version(
                    demand_version_id=SECOND_VERSION_ID,
                    based_on_demand_version_id=VERSION_ID,
                    taxonomy_bundle_id=TAXONOMY_ID,
                    content=valid_content(),
                    actor_user_id=OWNER_USER_ID,
                    existing_versions=(demand_version(),),
                    now=UTC_NOW + timedelta(seconds=1),
                )
            )
            terminal_codes.append(code)
        self.assertEqual(
            (valid_code, corrupt_code, terminal_codes),
            (None, "INVALID_STATE_TRANSITION", ["INVALID_STATE_TRANSITION"] * 3),
        )


if __name__ == "__main__":
    unittest.main()
