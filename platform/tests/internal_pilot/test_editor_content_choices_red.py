"""Write-bound enforcement for the reviewed editor choice catalog."""

from __future__ import annotations

from copy import deepcopy

import pytest

from desire_platform.internal_pilot.editor import (
    EditorServiceError,
    normalize_editor_choice_path,
    validate_editor_choice_membership,
)
from tests.internal_pilot.test_editor_service_red import (
    demand_content,
    profile_content,
)


def test_array_indexes_normalize_to_the_exact_choice_binding() -> None:
    assert normalize_editor_choice_path(
        "/skills/12/must_have/0/skill_code"
    ) == "/skills/*/must_have/*/skill_code"
    assert normalize_editor_choice_path("/problem/domain_code") == (
        "/problem/domain_code"
    )
    with pytest.raises(ValueError, match="content path is invalid"):
        normalize_editor_choice_path("problem/domain_code")


def test_approved_creator_and_demand_values_pass_the_shared_validator() -> None:
    validate_editor_choice_membership(
        resource_type="CREATOR_PROFILE", content=profile_content()
    )
    validate_editor_choice_membership(
        resource_type="DEMAND", content=demand_content()
    )


def test_missing_optional_fields_and_empty_unavailable_arrays_are_accepted() -> None:
    validate_editor_choice_membership(
        resource_type="CREATOR_PROFILE",
        content={"ai": {"prohibited_case_codes": []}},
    )
    validate_editor_choice_membership(
        resource_type="DEMAND",
        content={"risk": {"dependency_codes": []}},
    )
    validate_editor_choice_membership(
        resource_type="CREATOR_PROFILE", content={}
    )
    validate_editor_choice_membership(resource_type="DEMAND", content={})


@pytest.mark.parametrize(
    ("resource_type", "content_factory", "mutate", "path"),
    (
        (
            "CREATOR_PROFILE",
            profile_content,
            lambda value: value["interests"][0].__setitem__(
                "domain_code", "GENERAL"
            ),
            "/content/interests/0/domain_code",
        ),
        (
            "DEMAND",
            demand_content,
            lambda value: value["problem"].__setitem__(
                "problem_type_codes", ["EXPLORATION"]
            ),
            "/content/problem/problem_type_codes/0",
        ),
        (
            "DEMAND",
            demand_content,
            lambda value: value["problem"].__setitem__(
                "target_user_category_codes", ["TARGET_USER.SMALL_TEAM"]
            ),
            "/content/problem/target_user_category_codes/0",
        ),
        (
            "CREATOR_PROFILE",
            profile_content,
            lambda value: value["ai"].__setitem__(
                "prohibited_case_codes", ["AI.GENERAL"]
            ),
            "/content/ai/prohibited_case_codes/0",
        ),
        (
            "DEMAND",
            demand_content,
            lambda value: value["risk"].__setitem__(
                "dependency_codes", ["DEPENDENCY.GENERAL"]
            ),
            "/content/risk/dependency_codes/0",
        ),
    ),
)
def test_legacy_policy_and_unavailable_values_fail_with_the_concrete_path(
    resource_type,
    content_factory,
    mutate,
    path,
) -> None:
    content = deepcopy(content_factory())
    mutate(content)

    with pytest.raises(EditorServiceError) as rejected:
        validate_editor_choice_membership(
            resource_type=resource_type,
            content=content,
        )

    assert (
        rejected.value.status,
        rejected.value.code,
        rejected.value.path,
    ) == (422, "EDITOR_CHOICE_UNAVAILABLE", path)


def test_non_string_value_at_a_choice_leaf_is_a_stable_422() -> None:
    content = demand_content()
    content["location"]["allowed_creator_region_codes"] = [{"code": "CN"}]

    with pytest.raises(EditorServiceError) as rejected:
        validate_editor_choice_membership(resource_type="DEMAND", content=content)

    assert (
        rejected.value.status,
        rejected.value.code,
        rejected.value.path,
    ) == (
        422,
        "EDITOR_CHOICE_UNAVAILABLE",
        "/content/location/allowed_creator_region_codes/0",
    )


@pytest.mark.parametrize(
    ("mutate", "path"),
    (
        (
            lambda value: value["problem"].__setitem__(
                "domain_code", "GENERAL"
            ),
            "/content/problem/domain_code",
        ),
        (
            lambda value: value["problem"].__setitem__(
                "problem_type_codes", ["EXPLORATION"]
            ),
            "/content/problem/problem_type_codes/0",
        ),
        (
            lambda value: value["skills"]["must_have"][0].__setitem__(
                "skill_code", "GENERAL_RESEARCH"
            ),
            "/content/skills/must_have/0/skill_code",
        ),
        (
            lambda value: value["matching"].__setitem__(
                "task_codes", ["VALIDATION"]
            ),
            "/content/matching/task_codes/0",
        ),
    ),
)
def test_each_legacy_web_default_is_rejected_while_target_stays_synthetic(
    mutate,
    path,
) -> None:
    content = demand_content()
    assert content["problem"]["target_user_category_codes"] == [
        "SYNTHETIC_USER"
    ]
    mutate(content)

    with pytest.raises(EditorServiceError) as rejected:
        validate_editor_choice_membership(resource_type="DEMAND", content=content)

    assert (
        rejected.value.status,
        rejected.value.code,
        rejected.value.path,
    ) == (422, "EDITOR_CHOICE_UNAVAILABLE", path)
