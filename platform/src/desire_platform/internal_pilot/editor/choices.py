"""Reviewed editor choices for the code-native internal sandbox release."""

from __future__ import annotations

from functools import lru_cache
from typing import Dict, Iterable, Optional, Tuple

from ...taxonomy.domain import TaxonomyNodeKind, TaxonomyNodeStatus
from ..synthetic_taxonomy import (
    INTERNAL_SANDBOX_TAXONOMY_BUNDLE_ID,
    build_internal_sandbox_taxonomy_release,
)
from .contracts import (
    EditorChoiceFieldDto,
    EditorChoiceOptionDto,
    EditorChoicesDto,
)


_LOCALE = "zh-CN"


def _option(value: str, label: str, source: str) -> EditorChoiceOptionDto:
    return EditorChoiceOptionDto(value=value, label=label, source=source)


def _available(
    resource_type: str,
    path_template: str,
    value_contract: str,
    intended_node_kind: Optional[str],
    options: Iterable[EditorChoiceOptionDto],
) -> EditorChoiceFieldDto:
    return EditorChoiceFieldDto(
        resource_type=resource_type,
        path_template=path_template,
        value_contract=value_contract,
        intended_node_kind=intended_node_kind,
        status="AVAILABLE",
        reason_code=None,
        options=tuple(
            sorted(options, key=lambda option: option.value.encode("utf-8"))
        ),
    )


def _unavailable(
    resource_type: str,
    path_template: str,
) -> EditorChoiceFieldDto:
    return EditorChoiceFieldDto(
        resource_type=resource_type,
        path_template=path_template,
        value_contract="TAXONOMY_CODE",
        intended_node_kind=None,
        status="UNAVAILABLE",
        reason_code="NO_REVIEWED_CHOICE_SET",
        options=(),
    )


def _taxonomy_options() -> Dict[str, Tuple[EditorChoiceOptionDto, ...]]:
    release = build_internal_sandbox_taxonomy_release().candidate
    if (
        release.manifest.bundle_id != INTERNAL_SANDBOX_TAXONOMY_BUNDLE_ID
        or release.nodes.bundle_id != INTERNAL_SANDBOX_TAXONOMY_BUNDLE_ID
    ):
        raise ValueError("internal sandbox taxonomy release is unavailable")
    selected_labels = tuple(
        labels for labels in release.labels if labels.locale == _LOCALE
    )
    if (
        len(selected_labels) != 1
        or selected_labels[0].bundle_id
        != INTERNAL_SANDBOX_TAXONOMY_BUNDLE_ID
    ):
        raise ValueError("internal sandbox taxonomy labels are unavailable")
    labels_by_code = {
        label.code: label.short_label for label in selected_labels[0].labels
    }
    if len(labels_by_code) != len(selected_labels[0].labels):
        raise ValueError("internal sandbox taxonomy labels are unavailable")
    result: Dict[str, list[EditorChoiceOptionDto]] = {}
    for node in release.nodes.nodes:
        if node.status is not TaxonomyNodeStatus.ACTIVE:
            continue
        label = labels_by_code.get(node.code)
        if label is None:
            raise ValueError("internal sandbox taxonomy labels are unavailable")
        result.setdefault(node.kind.value, []).append(
            _option(node.code, label, "TAXONOMY_BUNDLE_NODE")
        )
    required_kinds = (
        TaxonomyNodeKind.DOMAIN.value,
        TaxonomyNodeKind.PROBLEM_TYPE.value,
        TaxonomyNodeKind.TASK.value,
        TaxonomyNodeKind.SKILL.value,
    )
    if any(not result.get(kind) for kind in required_kinds):
        raise ValueError("internal sandbox taxonomy choices are unavailable")
    return {
        kind: tuple(
            sorted(options, key=lambda option: option.value.encode("utf-8"))
        )
        for kind, options in result.items()
    }


@lru_cache(maxsize=1)
def build_internal_sandbox_editor_choices(*, bundle_id: str) -> EditorChoicesDto:
    """Build the exact bounded UI catalog for the reviewed synthetic bundle."""

    if bundle_id != INTERNAL_SANDBOX_TAXONOMY_BUNDLE_ID:
        raise ValueError("internal sandbox taxonomy bundle is unavailable")
    taxonomy = _taxonomy_options()

    def node_field(
        resource_type: str, path_template: str, node_kind: str
    ) -> EditorChoiceFieldDto:
        return _available(
            resource_type,
            path_template,
            "TAXONOMY_CODE",
            node_kind,
            taxonomy[node_kind],
        )

    fields = (
        _unavailable("CREATOR_PROFILE", "/ai/prohibited_case_codes/*"),
        node_field(
            "CREATOR_PROFILE",
            "/boundaries/prohibited_domains/*/code",
            "DOMAIN",
        ),
        node_field(
            "CREATOR_PROFILE",
            "/boundaries/prohibited_tasks/*/code",
            "TASK",
        ),
        _available(
            "CREATOR_PROFILE",
            "/collaboration/languages/*/language_code",
            "LANGUAGE_TAG",
            None,
            (_option("zh-CN", "中文（简体）", "INTERNAL_SANDBOX_PRESET"),),
        ),
        _available(
            "CREATOR_PROFILE",
            "/compensation/currency",
            "CURRENCY_CODE",
            None,
            (_option("CNY", "人民币", "INTERNAL_SANDBOX_POLICY"),),
        ),
        node_field(
            "CREATOR_PROFILE", "/interests/*/domain_code", "DOMAIN"
        ),
        node_field(
            "CREATOR_PROFILE",
            "/interests/*/problem_code",
            "PROBLEM_TYPE",
        ),
        node_field(
            "CREATOR_PROFILE", "/interests/*/task_code", "TASK"
        ),
        _available(
            "CREATOR_PROFILE",
            "/location/region_code",
            "REGION_CODE",
            None,
            (_option("CN", "中国", "INTERNAL_SANDBOX_PRESET"),),
        ),
        node_field("CREATOR_PROFILE", "/skills/*/skill_code", "SKILL"),
        _available(
            "DEMAND",
            "/budget/currency",
            "CURRENCY_CODE",
            None,
            (_option("CNY", "人民币", "INTERNAL_SANDBOX_POLICY"),),
        ),
        _available(
            "DEMAND",
            "/collaboration/languages/*",
            "LANGUAGE_TAG",
            None,
            (_option("zh-CN", "中文（简体）", "INTERNAL_SANDBOX_PRESET"),),
        ),
        _available(
            "DEMAND",
            "/location/allowed_creator_region_codes/*",
            "REGION_CODE",
            None,
            (_option("CN", "中国", "INTERNAL_SANDBOX_PRESET"),),
        ),
        _available(
            "DEMAND",
            "/location/demand_region_code",
            "REGION_CODE",
            None,
            (_option("CN", "中国", "INTERNAL_SANDBOX_PRESET"),),
        ),
        node_field("DEMAND", "/matching/domain_codes/*", "DOMAIN"),
        node_field(
            "DEMAND", "/matching/problem_codes/*", "PROBLEM_TYPE"
        ),
        node_field("DEMAND", "/matching/task_codes/*", "TASK"),
        node_field("DEMAND", "/problem/domain_code", "DOMAIN"),
        node_field(
            "DEMAND", "/problem/problem_type_codes/*", "PROBLEM_TYPE"
        ),
        _available(
            "DEMAND",
            "/problem/target_user_category_codes/*",
            "TAXONOMY_CODE",
            "TARGET_USER_CATEGORY",
            (
                _option(
                    "SYNTHETIC_USER",
                    "合成用户",
                    "INTERNAL_SANDBOX_POLICY",
                ),
            ),
        ),
        _unavailable("DEMAND", "/risk/dependency_codes/*"),
        node_field("DEMAND", "/skills/must_have/*/skill_code", "SKILL"),
        node_field("DEMAND", "/skills/nice_to_have/*/skill_code", "SKILL"),
    )
    return EditorChoicesDto(
        schema_version="editor-choices-v1",
        locale=_LOCALE,
        fields=tuple(
            sorted(
                fields,
                key=lambda field: (
                    field.resource_type.encode("utf-8"),
                    field.path_template.encode("utf-8"),
                ),
            )
        ),
    )


__all__ = ["build_internal_sandbox_editor_choices"]
