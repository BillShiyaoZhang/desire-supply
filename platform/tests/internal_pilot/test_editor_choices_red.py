"""Closed contracts for INTERNAL_SANDBOX editor code choices."""

from __future__ import annotations

from dataclasses import replace

import pytest

from desire_platform.internal_pilot.editor import (
    EditorChoiceOptionDto,
    build_internal_sandbox_editor_choices,
)


BUNDLE_ID = "50000000-0000-4000-8000-000000000001"


def choices():
    return build_internal_sandbox_editor_choices(bundle_id=BUNDLE_ID)


def test_editor_choices_are_the_exact_sorted_twenty_three_field_catalog() -> None:
    catalog = choices()
    expected = {
        ("CREATOR_PROFILE", "/ai/prohibited_case_codes/*"): (
            "TAXONOMY_CODE", None, "UNAVAILABLE", (),
        ),
        ("CREATOR_PROFILE", "/boundaries/prohibited_domains/*/code"): (
            "TAXONOMY_CODE", "DOMAIN", "AVAILABLE", ("DOMAIN.SOFTWARE",),
        ),
        ("CREATOR_PROFILE", "/boundaries/prohibited_tasks/*/code"): (
            "TAXONOMY_CODE", "TASK", "AVAILABLE", ("TASK.ANALYSIS",),
        ),
        ("CREATOR_PROFILE", "/collaboration/languages/*/language_code"): (
            "LANGUAGE_TAG", None, "AVAILABLE", ("zh-CN",),
        ),
        ("CREATOR_PROFILE", "/compensation/currency"): (
            "CURRENCY_CODE", None, "AVAILABLE", ("CNY",),
        ),
        ("CREATOR_PROFILE", "/interests/*/domain_code"): (
            "TAXONOMY_CODE", "DOMAIN", "AVAILABLE", ("DOMAIN.SOFTWARE",),
        ),
        ("CREATOR_PROFILE", "/interests/*/problem_code"): (
            "TAXONOMY_CODE", "PROBLEM_TYPE", "AVAILABLE", ("PROBLEM.OPERATIONS",),
        ),
        ("CREATOR_PROFILE", "/interests/*/task_code"): (
            "TAXONOMY_CODE", "TASK", "AVAILABLE", ("TASK.ANALYSIS",),
        ),
        ("CREATOR_PROFILE", "/location/region_code"): (
            "REGION_CODE", None, "AVAILABLE", ("CN",),
        ),
        ("CREATOR_PROFILE", "/skills/*/skill_code"): (
            "TAXONOMY_CODE", "SKILL", "AVAILABLE", ("SKILL.SYSTEMS_ANALYSIS",),
        ),
        ("DEMAND", "/budget/currency"): (
            "CURRENCY_CODE", None, "AVAILABLE", ("CNY",),
        ),
        ("DEMAND", "/collaboration/languages/*"): (
            "LANGUAGE_TAG", None, "AVAILABLE", ("zh-CN",),
        ),
        ("DEMAND", "/location/allowed_creator_region_codes/*"): (
            "REGION_CODE", None, "AVAILABLE", ("CN",),
        ),
        ("DEMAND", "/location/demand_region_code"): (
            "REGION_CODE", None, "AVAILABLE", ("CN",),
        ),
        ("DEMAND", "/matching/domain_codes/*"): (
            "TAXONOMY_CODE", "DOMAIN", "AVAILABLE", ("DOMAIN.SOFTWARE",),
        ),
        ("DEMAND", "/matching/problem_codes/*"): (
            "TAXONOMY_CODE", "PROBLEM_TYPE", "AVAILABLE", ("PROBLEM.OPERATIONS",),
        ),
        ("DEMAND", "/matching/task_codes/*"): (
            "TAXONOMY_CODE", "TASK", "AVAILABLE", ("TASK.ANALYSIS",),
        ),
        ("DEMAND", "/problem/domain_code"): (
            "TAXONOMY_CODE", "DOMAIN", "AVAILABLE", ("DOMAIN.SOFTWARE",),
        ),
        ("DEMAND", "/problem/problem_type_codes/*"): (
            "TAXONOMY_CODE", "PROBLEM_TYPE", "AVAILABLE", ("PROBLEM.OPERATIONS",),
        ),
        ("DEMAND", "/problem/target_user_category_codes/*"): (
            "TAXONOMY_CODE", "TARGET_USER_CATEGORY", "AVAILABLE", ("SYNTHETIC_USER",),
        ),
        ("DEMAND", "/risk/dependency_codes/*"): (
            "TAXONOMY_CODE", None, "UNAVAILABLE", (),
        ),
        ("DEMAND", "/skills/must_have/*/skill_code"): (
            "TAXONOMY_CODE", "SKILL", "AVAILABLE", ("SKILL.SYSTEMS_ANALYSIS",),
        ),
        ("DEMAND", "/skills/nice_to_have/*/skill_code"): (
            "TAXONOMY_CODE", "SKILL", "AVAILABLE", ("SKILL.SYSTEMS_ANALYSIS",),
        ),
    }
    identities = tuple(
        (field.resource_type, field.path_template) for field in catalog.fields
    )

    assert (catalog.schema_version, catalog.locale) == (
        "editor-choices-v1",
        "zh-CN",
    )
    assert identities == tuple(sorted(expected))
    for field in catalog.fields:
        identity = (field.resource_type, field.path_template)
        value_contract, node_kind, status, values = expected[identity]
        assert (
            field.value_contract,
            field.intended_node_kind,
            field.status,
            tuple(option.value for option in field.options),
        ) == (value_contract, node_kind, status, values)
        assert field.reason_code == (
            None if status == "AVAILABLE" else "NO_REVIEWED_CHOICE_SET"
        )


def test_taxonomy_labels_and_non_taxonomy_sources_are_not_conflated() -> None:
    catalog = choices()
    fields = {
        (field.resource_type, field.path_template): field
        for field in catalog.fields
    }
    assert fields[("CREATOR_PROFILE", "/interests/*/domain_code")].options == (
        EditorChoiceOptionDto(
            value="DOMAIN.SOFTWARE",
            label="软件",
            source="TAXONOMY_BUNDLE_NODE",
        ),
    )
    assert fields[("CREATOR_PROFILE", "/interests/*/problem_code")].options[0].label == "运营改进"
    assert fields[("CREATOR_PROFILE", "/interests/*/task_code")].options[0].label == "分析"
    assert fields[("CREATOR_PROFILE", "/skills/*/skill_code")].options[0].label == "系统分析"
    assert fields[("DEMAND", "/problem/target_user_category_codes/*")].options == (
        EditorChoiceOptionDto(
            value="SYNTHETIC_USER",
            label="合成用户",
            source="INTERNAL_SANDBOX_POLICY",
        ),
    )
    assert "TARGET_USER.SMALL_TEAM" not in {
        option.value
        for option in fields[
            ("DEMAND", "/problem/target_user_category_codes/*")
        ].options
    }
    assert "DATA_SENSITIVITY.INTERNAL" not in {
        option.value for field in catalog.fields for option in field.options
    }
    assert fields[("DEMAND", "/budget/currency")].options[0].source == (
        "INTERNAL_SANDBOX_POLICY"
    )
    assert fields[("DEMAND", "/location/demand_region_code")].options[0].source == (
        "INTERNAL_SANDBOX_PRESET"
    )


def test_choice_catalog_fails_closed_for_an_unreviewed_bundle() -> None:
    with pytest.raises(ValueError, match="taxonomy bundle is unavailable"):
        build_internal_sandbox_editor_choices(
            bundle_id="50000000-0000-4000-8000-000000000002"
        )


@pytest.mark.parametrize(
    "mutate",
    (
        lambda catalog: replace(catalog, fields=catalog.fields[:-1]),
        lambda catalog: replace(catalog, fields=tuple(reversed(catalog.fields))),
        lambda catalog: replace(
            catalog,
            fields=catalog.fields
            + (replace(catalog.fields[-1], path_template="/skills/other/*"),),
        ),
        lambda catalog: replace(
            catalog,
            fields=catalog.fields[:-1] + (catalog.fields[0],),
        ),
    ),
)
def test_choice_catalog_rejects_missing_extra_unsorted_or_duplicate_bindings(
    mutate,
) -> None:
    with pytest.raises(ValueError, match="editor choices are invalid"):
        mutate(choices())


@pytest.mark.parametrize(
    ("identity", "mutate_field"),
    (
        (
            ("CREATOR_PROFILE", "/interests/*/domain_code"),
            lambda field: replace(field, intended_node_kind="TASK"),
        ),
        (
            ("CREATOR_PROFILE", "/compensation/currency"),
            lambda field: replace(field, value_contract="CONTENT_ENUM"),
        ),
        (
            ("CREATOR_PROFILE", "/interests/*/domain_code"),
            lambda field: replace(
                field,
                status="UNAVAILABLE",
                reason_code="NO_REVIEWED_CHOICE_SET",
                options=(),
            ),
        ),
        (
            ("CREATOR_PROFILE", "/interests/*/domain_code"),
            lambda field: replace(
                field,
                options=(
                    replace(
                        field.options[0], source="INTERNAL_SANDBOX_POLICY"
                    ),
                ),
            ),
        ),
        (
            ("DEMAND", "/problem/target_user_category_codes/*"),
            lambda field: replace(
                field,
                options=(replace(field.options[0], label="其他用户"),),
            ),
        ),
        (
            ("DEMAND", "/location/demand_region_code"),
            lambda field: replace(
                field,
                options=(
                    replace(field.options[0], value="US", label="美国"),
                ),
            ),
        ),
        (
            ("DEMAND", "/risk/dependency_codes/*"),
            lambda field: replace(field, intended_node_kind="RISK"),
        ),
    ),
)
def test_choice_catalog_rejects_wrong_semantics_for_a_known_binding(
    identity,
    mutate_field,
) -> None:
    catalog = choices()
    fields = list(catalog.fields)
    index = next(
        index
        for index, field in enumerate(fields)
        if (field.resource_type, field.path_template) == identity
    )
    fields[index] = mutate_field(fields[index])

    with pytest.raises(ValueError, match="editor choices are invalid"):
        replace(catalog, fields=tuple(fields))


def test_choice_field_rejects_unsorted_duplicate_excess_or_wrong_source_options() -> None:
    catalog = choices()
    field = next(
        item
        for item in catalog.fields
        if item.path_template == "/interests/*/domain_code"
    )
    original = field.options[0]
    extra = EditorChoiceOptionDto(
        value="DOMAIN.ZZZ",
        label="占位",
        source="TAXONOMY_BUNDLE_NODE",
    )
    mutations = (
        (extra, original),
        (original, original),
        tuple(
            EditorChoiceOptionDto(
                value=f"DOMAIN.VALUE_{index:02d}",
                label=f"选项 {index:02d}",
                source="TAXONOMY_BUNDLE_NODE",
            )
            for index in range(17)
        ),
        (
            replace(original, source="INTERNAL_SANDBOX_PRESET"),
        ),
    )
    for options in mutations:
        with pytest.raises(ValueError, match="editor choice field is invalid"):
            replace(field, options=options)


@pytest.mark.parametrize(
    "mutation",
    (
        {"label": " 软件"},
        {"label": "软件\n"},
        {"source": "BROWSER_DEFAULT"},
    ),
)
def test_choice_option_rejects_untrimmed_control_or_unknown_provenance(
    mutation,
) -> None:
    values = {
        "value": "DOMAIN.SOFTWARE",
        "label": "软件",
        "source": "TAXONOMY_BUNDLE_NODE",
    }
    values.update(mutation)
    with pytest.raises(ValueError, match="editor choice option is invalid"):
        EditorChoiceOptionDto(**values)
