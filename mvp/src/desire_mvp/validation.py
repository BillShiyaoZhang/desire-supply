from datetime import date
import math
import re
from typing import Any, Dict, Iterable, List, Optional, Sequence, Type

from .config import ConfigBundle
from .models import Issue, ValidationResult
from .schema import (
    SchemaVersionError,
    is_controlled_reference,
    unknown_schema_fields,
    validate_schema_version,
)


DEMAND_STATUSES = frozenset(
    {
        "draft",
        "clarifying",
        "verified",
        "funded",
        "matching",
        "agreed",
        "cancelled",
    }
)
CREATOR_STATUSES = frozenset({"active", "paused", "inactive"})
OUTCOME_STATUSES = frozenset({"completed", "exited", "failed"})
DATA_SENSITIVITY_LEVELS = frozenset({"public", "low", "medium", "high", "restricted"})
_MISSING = object()
_DATE_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{1,127}$")
_CONTACT_DIGIT_RUN_PATTERN = re.compile(r"\d{7,}")
_OPERATOR_HOUR_CATEGORIES = {
    "recruiting",
    "interview",
    "matching",
    "coordination",
    "dispute",
}
_SAFETY_EVENT_SEVERITIES = frozenset(("low", "medium", "high", "critical"))


def _value(record: Dict[str, Any], path: str, default: Any = None) -> Any:
    current: Any = record
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            return default
        current = current[part]
    return current


def _present(value: Any) -> bool:
    return value is not None and value != "" and value != [] and value != {}


def _require(
    issues: List[Issue], record: Dict[str, Any], fields: Iterable[str], entity_label: str
) -> None:
    for field in fields:
        if not _present(_value(record, field)):
            issues.append(Issue("BLOCKER", "MISSING_REQUIRED", "{}缺少必填字段 {}".format(entity_label, field), field))


def _require_present(
    issues: List[Issue], record: Dict[str, Any], fields: Iterable[str], entity_label: str
) -> None:
    for field in fields:
        if _value(record, field, _MISSING) is _MISSING:
            issues.append(
                Issue(
                    "BLOCKER",
                    "MISSING_REQUIRED",
                    "{}缺少必填字段 {}".format(entity_label, field),
                    field,
                )
            )


def _parse_date(value: Any) -> Optional[date]:
    if not isinstance(value, str) or _DATE_PATTERN.fullmatch(value) is None:
        return None
    try:
        return date.fromisoformat(value)
    except ValueError:
        return None


def _is_finite_number(value: Any) -> bool:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        return False
    try:
        return math.isfinite(float(value))
    except (OverflowError, TypeError, ValueError):
        return False


def _type_name(expected: Sequence[Type[Any]]) -> str:
    return " 或 ".join(item.__name__ for item in expected)


def _expect_type(
    issues: List[Issue],
    record: Dict[str, Any],
    path: str,
    expected: Sequence[Type[Any]],
) -> bool:
    value = _value(record, path, _MISSING)
    if value is _MISSING:
        return False
    valid = isinstance(value, tuple(expected))
    if (int in expected or float in expected) and isinstance(value, bool):
        valid = False
    if not valid:
        issues.append(
            Issue(
                "BLOCKER",
                "INVALID_TYPE",
                "{} 必须是 {}".format(path, _type_name(expected)),
                path,
            )
        )
    return valid


def _expect_string_list(
    issues: List[Issue], record: Dict[str, Any], path: str
) -> Optional[List[str]]:
    if not _expect_type(issues, record, path, (list,)):
        return None
    value = _value(record, path)
    if any(not isinstance(item, str) or not item for item in value):
        issues.append(
            Issue("BLOCKER", "INVALID_TYPE", "{} 必须是非空字符串数组".format(path), path)
        )
        return None
    return value


def _expect_number(
    issues: List[Issue], record: Dict[str, Any], path: str
) -> Optional[float]:
    value = _value(record, path, _MISSING)
    if value is _MISSING:
        return None
    if not _is_finite_number(value):
        issues.append(Issue("BLOCKER", "INVALID_TYPE", "{} 必须是有限数字".format(path), path))
        return None
    return float(value)


def _expect_string(
    issues: List[Issue],
    record: Dict[str, Any],
    path: str,
    *,
    allow_none: bool = False,
) -> None:
    value = _value(record, path, _MISSING)
    if value is _MISSING or (allow_none and value is None):
        return
    if not isinstance(value, str) or not value:
        issues.append(Issue("BLOCKER", "INVALID_TYPE", "{} 必须是非空字符串".format(path), path))


def _expect_bool(issues: List[Issue], record: Dict[str, Any], path: str) -> None:
    value = _value(record, path, _MISSING)
    if value is not _MISSING and not isinstance(value, bool):
        issues.append(Issue("BLOCKER", "INVALID_TYPE", "{} 必须是布尔值".format(path), path))


def _expect_list_items(
    issues: List[Issue],
    record: Dict[str, Any],
    path: str,
    expected: Type[Any],
    label: str,
) -> None:
    value = _value(record, path, _MISSING)
    if value is _MISSING:
        return
    if not isinstance(value, list):
        return
    if any(not isinstance(item, expected) for item in value):
        issues.append(
            Issue("BLOCKER", "INVALID_TYPE", "{} 必须是 {} 数组".format(path, label), path)
        )


def _expect_bool_list(issues: List[Issue], record: Dict[str, Any], path: str) -> None:
    _expect_list_items(issues, record, path, bool, "布尔值")


def _check_unique_items(issues: List[Issue], record: Dict[str, Any], path: str) -> None:
    value = _value(record, path, _MISSING)
    if not isinstance(value, list):
        return
    for index, item in enumerate(value):
        if any(item == earlier for earlier in value[:index]):
            issues.append(
                Issue(
                    "BLOCKER",
                    "DUPLICATE_ITEMS",
                    "{} 不允许重复项".format(path),
                    path,
                )
            )
            return


def is_public_identifier(value: Any) -> bool:
    """Return whether a value is safe to use as a public entity identifier."""
    return (
        isinstance(value, str)
        and _IDENTIFIER_PATTERN.fullmatch(value) is not None
        and any(character in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz" for character in value)
        and _CONTACT_DIGIT_RUN_PATTERN.search(value) is None
    )


def _safe_result_identifier(value: Any) -> str:
    """Return identifiers only after the public-identifier contract accepts them."""

    return value if is_public_identifier(value) else "<redacted>"


def _check_identifier(issues: List[Issue], value: Any, path: str) -> None:
    if not is_public_identifier(value):
        issues.append(
            Issue("BLOCKER", "INVALID_IDENTIFIER", "{} 必须是不含联系信息的标识符".format(path), path)
        )


def _check_external_reference(
    issues: List[Issue], value: Any, path: str, *, allow_empty: bool = False
) -> None:
    if allow_empty and (value is _MISSING or value == ""):
        return
    if not is_controlled_reference(value):
        issues.append(
            Issue(
                "BLOCKER",
                "INVALID_EXTERNAL_REFERENCE",
                "{} 必须是受控外部引用".format(path),
                path,
            )
        )


def _check_enum(
    issues: List[Issue], record: Dict[str, Any], path: str, allowed: Iterable[str]
) -> None:
    value = _value(record, path, _MISSING)
    if value is _MISSING:
        return
    if not isinstance(value, str) or value not in set(allowed):
        issues.append(
            Issue("BLOCKER", "UNKNOWN_ENUM", "{} 不是允许的枚举值".format(path), path)
        )


def _check_schema_version(issues: List[Issue], record: Dict[str, Any]) -> bool:
    try:
        validate_schema_version(record)
        return True
    except SchemaVersionError:
        issues.append(
            Issue(
                "BLOCKER",
                "UNSUPPORTED_SCHEMA_VERSION",
                "schema_version 必须是当前支持的显式整数版本",
                "schema_version",
            )
        )
        return False


def _check_unknown_fields(
    issues: List[Issue], record_type: str, record: Dict[str, Any]
) -> None:
    for path in unknown_schema_fields(record_type, record):
        issues.append(
            Issue(
                "BLOCKER",
                "UNKNOWN_FIELD",
                "{} 不是 {} v1 的允许字段".format(path, record_type),
                path,
            )
        )


def _check_enum_list(
    issues: List[Issue], record: Dict[str, Any], path: str, allowed: Iterable[str]
) -> None:
    values = _expect_string_list(issues, record, path)
    if values is None:
        return
    allowed_values = set(allowed)
    if any(value not in allowed_values for value in values):
        issues.append(
            Issue("BLOCKER", "UNKNOWN_ENUM", "{} 包含未知枚举值".format(path), path)
        )


def _check_taxonomy(
    issues: List[Issue],
    record: Dict[str, Any],
    path: str,
    allowed: Iterable[str],
    *,
    is_list: bool = True,
) -> None:
    allowed_values = set(allowed)
    if is_list:
        values = _expect_string_list(issues, record, path)
        if values is None:
            return
    else:
        value = _value(record, path, _MISSING)
        if value is _MISSING:
            return
        if not isinstance(value, str):
            issues.append(
                Issue("BLOCKER", "INVALID_TYPE", "{} 必须是字符串".format(path), path)
            )
            return
        values = [value]
    if any(value not in allowed_values for value in values):
        issues.append(
            Issue("BLOCKER", "UNKNOWN_TAXONOMY", "{} 包含受控词表之外的值".format(path), path)
        )


def validate_demand(demand: Dict[str, Any], rules: ConfigBundle) -> ValidationResult:
    issues: List[Issue] = []
    if _check_schema_version(issues, demand):
        _check_unknown_fields(issues, "demand", demand)
    demand_id = _safe_result_identifier(demand.get("id"))
    _require(
        issues,
        demand,
        (
            "id",
            "pilot_id",
            "status",
            "consent_version",
            "problem.domain",
            "problem.background",
            "problem.desired_outcome",
            "problem.target_users",
            "scope.deliverables",
            "scope.out_of_scope",
            "acceptance.criteria",
            "acceptance.owner",
            "acceptance.response_days",
            "skills.must_have",
            "skills.level",
            "matching",
            "schedule.start_date",
            "schedule.due_date",
            "schedule.estimated_days",
            "schedule.weekly_hours",
            "schedule.duration_weeks",
            "budget.maximum",
            "budget.minimum",
            "budget.direct_cost",
            "budget.currency",
            "payment.plan",
            "risk.uncertainty",
            "risk.urgency",
            "risk.external_dependencies",
            "risk.data_sensitivity",
            "ai.allowed",
            "ai.required",
            "collaboration",
            "collaboration.languages",
            "collaboration.preferred_work_mode",
            "collaboration.feedback_frequency",
            "collaboration.team_preference",
            "location.region",
        ),
        "需求",
    )
    _require_present(
        issues,
        demand,
        (
            "skills.nice_to_have",
            "matching.problem_types",
            "matching.domains",
            "matching.tasks",
            "location.allowed_creator_regions",
        ),
        "需求",
    )
    for path in (
        "problem",
        "scope",
        "acceptance",
        "skills",
        "matching",
        "schedule",
        "budget",
        "payment",
        "risk",
        "ai",
        "collaboration",
        "location",
    ):
        _expect_type(issues, demand, path, (dict,))
    for path in (
        "problem.target_users",
        "scope.deliverables",
        "scope.out_of_scope",
        "acceptance.criteria",
        "skills.must_have",
        "skills.nice_to_have",
        "matching.problem_types",
        "matching.domains",
        "matching.tasks",
        "collaboration.languages",
        "location.allowed_creator_regions",
    ):
        _expect_string_list(issues, demand, path)
        _check_unique_items(issues, demand, path)
    _expect_type(issues, demand, "payment.plan", (list,))
    for path in (
        "schedule.estimated_days",
        "schedule.weekly_hours",
        "schedule.duration_weeks",
        "acceptance.response_days",
        "budget.minimum",
        "budget.maximum",
        "budget.direct_cost",
    ):
        _expect_number(issues, demand, path)
    for path in (
        "id",
        "pilot_id",
        "status",
        "consent_version",
        "client_org_id",
        "problem.background",
        "problem.domain",
        "problem.desired_outcome",
        "acceptance.owner",
        "schedule.start_date",
        "schedule.due_date",
        "budget.currency",
        "risk.uncertainty",
        "risk.urgency",
        "risk.external_dependencies",
        "risk.data_sensitivity",
        "risk.data_handling_plan",
        "ai.data_model_policy",
        "collaboration.preferred_work_mode",
        "collaboration.feedback_frequency",
        "collaboration.team_preference",
        "location.region",
    ):
        _expect_string(issues, demand, path)
    for path in ("decision_authority_confirmed", "funding_commitment", "ai.allowed", "ai.required"):
        _expect_bool(issues, demand, path)
    for path in ("id", "pilot_id", "client_org_id"):
        _check_identifier(issues, _value(demand, path), path)
    _check_external_reference(
        issues,
        _value(demand, "funding_evidence_ref", _MISSING),
        "funding_evidence_ref",
        allow_empty=True,
    )

    _check_enum(issues, demand, "status", DEMAND_STATUSES)
    _check_enum(issues, demand, "risk.data_sensitivity", DATA_SENSITIVITY_LEVELS)
    taxonomy = rules.taxonomy
    _check_taxonomy(issues, demand, "problem.domain", taxonomy.get("domains", []), is_list=False)
    _check_taxonomy(issues, demand, "matching.domains", taxonomy.get("domains", []))
    _check_taxonomy(
        issues, demand, "matching.problem_types", taxonomy.get("problem_types", [])
    )
    _check_taxonomy(issues, demand, "matching.tasks", taxonomy.get("tasks", []))
    _check_taxonomy(issues, demand, "skills.must_have", taxonomy.get("skills", []))
    _check_taxonomy(issues, demand, "skills.nice_to_have", taxonomy.get("skills", []))
    _check_enum(issues, demand, "skills.level", rules.budget.get("skill_multipliers", {}))
    for category in ("uncertainty", "urgency", "external_dependencies"):
        _check_enum(
            issues,
            demand,
            "risk.{}".format(category),
            rules.budget.get("risk_rates", {}).get(category, {}),
        )
    _check_enum(issues, demand, "budget.currency", {rules.budget.get("currency")})
    _check_enum(
        issues,
        demand,
        "location.region",
        set(rules.budget.get("regional_daily_baselines", {})) - {"default"},
    )

    payment_plan = _value(demand, "payment.plan")
    if isinstance(payment_plan, list):
        percentages = []
        for index, item in enumerate(payment_plan):
            field = "payment.plan.{}".format(index)
            if not isinstance(item, dict):
                issues.append(Issue("BLOCKER", "INVALID_TYPE", "付款计划项必须是对象", field))
                continue
            if not isinstance(item.get("milestone"), str) or not item.get("milestone"):
                issues.append(Issue("BLOCKER", "INVALID_TYPE", "付款计划 milestone 必须是非空字符串", field + ".milestone"))
            percent = item.get("percent")
            if not _is_finite_number(percent):
                issues.append(Issue("BLOCKER", "INVALID_TYPE", "付款计划 percent 必须是有限数字", field + ".percent"))
            elif not 0 < percent <= 100:
                issues.append(Issue("BLOCKER", "INVALID_NUMBER", "付款计划 percent 必须在 0 到 100 之间", field + ".percent"))
            else:
                percentages.append(float(percent))
        if len(percentages) == len(payment_plan) and not math.isclose(
            sum(percentages), 100.0, rel_tol=0.0, abs_tol=1e-9
        ):
            issues.append(Issue("BLOCKER", "INVALID_PERCENT_TOTAL", "付款计划比例合计必须为 100", "payment.plan"))
    if demand.get("decision_authority_confirmed") is not True:
        issues.append(Issue("BLOCKER", "DECISION_AUTHORITY_UNVERIFIED", "决策权尚未确认", "decision_authority_confirmed"))
    if demand.get("funding_commitment") is not True:
        issues.append(Issue("BLOCKER", "FUNDING_UNCOMMITTED", "资金承诺尚未验证", "funding_commitment"))

    must_have = _value(demand, "skills.must_have", [])
    if isinstance(must_have, list) and len(must_have) > 5:
        issues.append(Issue("WARNING", "TOO_MANY_MUST_HAVE_SKILLS", "必需技能超过 5 个，需求可能需要拆分", "skills.must_have"))
    if isinstance(must_have, list) and not must_have:
        issues.append(Issue("BLOCKER", "NO_MUST_HAVE_SKILLS", "至少需要一个必需技能", "skills.must_have"))

    start = _parse_date(_value(demand, "schedule.start_date"))
    due = _parse_date(_value(demand, "schedule.due_date"))
    if _present(_value(demand, "schedule.start_date")) and start is None:
        issues.append(Issue("BLOCKER", "INVALID_DATE", "开始日期必须是 YYYY-MM-DD", "schedule.start_date"))
    if _present(_value(demand, "schedule.due_date")) and due is None:
        issues.append(Issue("BLOCKER", "INVALID_DATE", "截止日期必须是 YYYY-MM-DD", "schedule.due_date"))
    if start and due and due < start:
        issues.append(Issue("BLOCKER", "INVALID_DATE_RANGE", "截止日期早于开始日期", "schedule.due_date"))

    estimated_days = _value(demand, "schedule.estimated_days")
    if _is_finite_number(estimated_days) and estimated_days <= 0:
        issues.append(Issue("BLOCKER", "INVALID_ESTIMATE", "预计投入天数必须大于 0", "schedule.estimated_days"))
    budget_max = _value(demand, "budget.maximum")
    if _is_finite_number(budget_max) and budget_max <= 0:
        issues.append(Issue("BLOCKER", "INVALID_BUDGET", "预算上限必须大于 0", "budget.maximum"))
    budget_min = _value(demand, "budget.minimum", 0)
    if _is_finite_number(budget_min) and _is_finite_number(budget_max) and budget_min > budget_max:
        issues.append(Issue("BLOCKER", "INVALID_BUDGET_RANGE", "预算下限高于预算上限", "budget.minimum"))
    for field in (
        "schedule.weekly_hours",
        "schedule.duration_weeks",
        "budget.minimum",
        "budget.direct_cost",
    ):
        value = _value(demand, field)
        if _is_finite_number(value) and value < 0:
            issues.append(Issue("BLOCKER", "INVALID_NUMBER", "{} 必须是非负数".format(field), field))
    response_days = _value(demand, "acceptance.response_days")
    if _is_finite_number(response_days) and response_days <= 0:
        issues.append(Issue("BLOCKER", "INVALID_NUMBER", "验收响应天数必须大于 0", "acceptance.response_days"))

    if _value(demand, "risk.data_sensitivity") in ("high", "restricted") and not _present(
        _value(demand, "risk.data_handling_plan")
    ):
        issues.append(Issue("BLOCKER", "MISSING_DATA_PLAN", "高敏感数据需要处理方案", "risk.data_handling_plan"))
    if _value(demand, "ai.allowed") is True and _value(demand, "risk.data_sensitivity") in ("high", "restricted"):
        if not _present(_value(demand, "ai.data_model_policy")):
            issues.append(Issue("BLOCKER", "MISSING_AI_DATA_POLICY", "敏感数据场景需要说明数据能否发送给模型", "ai.data_model_policy"))
    if not _present(_value(demand, "funding_evidence_ref")):
        issues.append(Issue("QUESTION", "FUNDING_EVIDENCE_REFERENCE", "记录资金承诺证据的位置（不要把付款资料放进仓库）", "funding_evidence_ref"))
    return ValidationResult("demand", demand_id, issues)


def validate_creator(creator: Dict[str, Any], rules: ConfigBundle) -> ValidationResult:
    issues: List[Issue] = []
    if _check_schema_version(issues, creator):
        _check_unknown_fields(issues, "creator", creator)
    creator_id = _safe_result_identifier(creator.get("id"))
    _require(
        issues,
        creator,
        (
            "id",
            "status",
            "consent_version",
            "interests.problem_types",
            "interests.domains",
            "interests.tasks",
            "interests.intensity",
            "skills",
            "availability.available_from",
            "availability.weekly_hours",
            "availability.duration_weeks",
            "availability.timezone",
            "collaboration.languages",
            "collaboration.work_mode",
            "collaboration.feedback_frequency",
            "collaboration.team_preference",
            "compensation.minimum_project",
            "compensation.direct_cost",
            "compensation.currency",
            "ai.allowed",
            "ai.requires_ai",
            "ai.human_review",
            "location.region",
        ),
        "创作者",
    )
    _require_present(issues, creator, ("conflicts",), "创作者")
    for path in (
        "interests",
        "availability",
        "collaboration",
        "compensation",
        "boundaries",
        "location",
        "ai",
    ):
        _expect_type(issues, creator, path, (dict,))
    _expect_type(issues, creator, "skills", (list,))
    for path in (
        "interests.problem_types",
        "interests.domains",
        "interests.tasks",
        "collaboration.languages",
        "boundaries.prohibited_domains",
        "boundaries.prohibited_tasks",
        "boundaries.allowed_data_sensitivity",
        "conflicts",
        "ai.prohibited_cases",
    ):
        _expect_string_list(issues, creator, path)
        _check_unique_items(issues, creator, path)
    for path in (
        "interests.intensity",
        "availability.weekly_hours",
        "availability.duration_weeks",
        "compensation.minimum_project",
        "compensation.direct_cost",
    ):
        _expect_number(issues, creator, path)
    for path in (
        "id",
        "status",
        "consent_version",
        "availability.available_from",
        "availability.timezone",
        "collaboration.work_mode",
        "collaboration.feedback_frequency",
        "collaboration.team_preference",
        "compensation.currency",
        "location.region",
        "ai.human_review",
    ):
        _expect_string(issues, creator, path)
    for path in ("ai.allowed", "ai.requires_ai"):
        _expect_bool(issues, creator, path)
    _check_identifier(issues, creator.get("id"), "id")
    conflicts = creator.get("conflicts")
    if isinstance(conflicts, list):
        for index, conflict_id in enumerate(conflicts):
            _check_identifier(issues, conflict_id, "conflicts.{}".format(index))

    _check_enum(issues, creator, "status", CREATOR_STATUSES)
    _check_enum_list(
        issues,
        creator,
        "boundaries.allowed_data_sensitivity",
        DATA_SENSITIVITY_LEVELS,
    )
    taxonomy = rules.taxonomy
    _check_taxonomy(
        issues, creator, "interests.problem_types", taxonomy.get("problem_types", [])
    )
    _check_taxonomy(issues, creator, "interests.domains", taxonomy.get("domains", []))
    _check_taxonomy(issues, creator, "interests.tasks", taxonomy.get("tasks", []))
    _check_enum(
        issues, creator, "compensation.currency", {rules.budget.get("currency")}
    )
    boundaries = creator.get("boundaries")
    if not isinstance(boundaries, dict):
        issues.append(Issue("BLOCKER", "MISSING_REQUIRED", "创作者缺少必填字段 boundaries", "boundaries"))
    else:
        for key in ("prohibited_domains", "prohibited_tasks", "allowed_data_sensitivity"):
            if key not in boundaries or not isinstance(boundaries[key], list):
                issues.append(
                    Issue(
                        "BLOCKER",
                        "MISSING_REQUIRED",
                        "创作者缺少列表字段 boundaries.{}".format(key),
                        "boundaries.{}".format(key),
                    )
                )
    intensity = _value(creator, "interests.intensity")
    if _present(intensity) and (not isinstance(intensity, (int, float)) or not 0 <= intensity <= 4):
        issues.append(Issue("BLOCKER", "INVALID_INTEREST_INTENSITY", "兴趣强度必须在 0～4 之间", "interests.intensity"))
    available_from = _parse_date(_value(creator, "availability.available_from"))
    if _present(_value(creator, "availability.available_from")) and available_from is None:
        issues.append(Issue("BLOCKER", "INVALID_DATE", "可开始日期必须是 YYYY-MM-DD", "availability.available_from"))
    for field in (
        "availability.weekly_hours",
        "availability.duration_weeks",
        "compensation.minimum_project",
        "compensation.direct_cost",
    ):
        value = _value(creator, field)
        if _is_finite_number(value) and value < 0:
            issues.append(Issue("BLOCKER", "INVALID_NUMBER", "{} 必须是非负数".format(field), field))

    skills = creator.get("skills", [])
    if isinstance(skills, list):
        if not skills:
            issues.append(Issue("BLOCKER", "NO_SKILLS", "至少需要一项带证据的技能", "skills"))
        for index, skill in enumerate(skills):
            if not isinstance(skill, dict) or not skill.get("tag"):
                issues.append(Issue("BLOCKER", "INVALID_SKILL", "技能记录缺少 tag", "skills.{}".format(index)))
                continue
            proficiency = skill.get("proficiency")
            trust = skill.get("evidence_trust")
            for field in ("tag", "evidence_type", "evidence_ref"):
                value = skill.get(field)
                if _present(value) and (not isinstance(value, str) or not value):
                    issues.append(
                        Issue(
                            "BLOCKER",
                            "INVALID_TYPE",
                            "技能 {} 必须是非空字符串".format(field),
                            "skills.{}.{}".format(index, field),
                        )
                    )
            _check_external_reference(
                issues,
                skill.get("evidence_ref", _MISSING),
                "skills.{}.evidence_ref".format(index),
            )
            if not _is_finite_number(proficiency):
                issues.append(Issue("BLOCKER", "INVALID_TYPE", "技能熟练度必须是有限数字", "skills.{}.proficiency".format(index)))
            elif not 0 <= proficiency <= 4:
                issues.append(Issue("BLOCKER", "INVALID_PROFICIENCY", "技能熟练度必须在 0～4 之间", "skills.{}.proficiency".format(index)))
            if not _is_finite_number(trust):
                issues.append(Issue("BLOCKER", "INVALID_TYPE", "证据可信度必须是有限数字", "skills.{}.evidence_trust".format(index)))
            elif not 0 <= trust <= 4:
                issues.append(Issue("BLOCKER", "INVALID_EVIDENCE_TRUST", "证据可信度必须在 0～4 之间", "skills.{}.evidence_trust".format(index)))
            tag = skill.get("tag")
            if isinstance(tag, str) and tag not in set(rules.taxonomy.get("skills", [])):
                issues.append(Issue("BLOCKER", "UNKNOWN_TAXONOMY", "技能标签不在受控词表中", "skills.{}.tag".format(index)))
            if not skill.get("evidence_type") or not skill.get("evidence_ref"):
                issues.append(
                    Issue(
                        "BLOCKER",
                        "MISSING_SKILL_EVIDENCE",
                        "技能记录缺少证据类型或引用",
                        "skills.{}".format(index),
                    )
                )
        skill_tags = [skill.get("tag") for skill in skills if isinstance(skill, dict) and isinstance(skill.get("tag"), str)]
        if len(skill_tags) != len(set(skill_tags)):
            issues.append(Issue("BLOCKER", "DUPLICATE_SKILL", "技能标签不能重复", "skills"))
    if creator.get("status") != "active":
        issues.append(Issue("WARNING", "CREATOR_NOT_ACTIVE", "创作者当前不是 active 状态，不会进入匹配", "status"))
    if not _present(_value(creator, "ai.prohibited_cases")):
        issues.append(Issue("QUESTION", "AI_PROHIBITED_CASES", "确认哪些情形不能使用 AI", "ai.prohibited_cases"))
    return ValidationResult("creator", creator_id, issues)


def validate_outcome(outcome: Dict[str, Any], rules: ConfigBundle) -> ValidationResult:
    issues: List[Issue] = []
    if _check_schema_version(issues, outcome):
        _check_unknown_fields(issues, "outcome", outcome)
    project_id = _safe_result_identifier(outcome.get("project_id"))
    required_keys = (
        "project_id",
        "pilot_id",
        "demand_id",
        "creator_ids",
        "status",
        "signed",
        "real_payment",
        "milestones",
        "scope_changes",
        "dispute",
        "demand_clarity_improved",
        "creator_preference_confirmed",
        "willing_to_use_again",
        "service_fee_accepted",
        "operator_hours",
        "failure_primary",
        "failure_secondary",
        "safety_events",
    )
    for key in required_keys:
        if key not in outcome:
            issues.append(Issue("BLOCKER", "MISSING_REQUIRED", "结果记录缺少 {}".format(key), key))
    _check_enum(issues, outcome, "status", OUTCOME_STATUSES)
    for path in (
        "creator_ids",
        "milestones",
        "creator_preference_confirmed",
        "failure_secondary",
        "safety_events",
    ):
        _expect_type(issues, outcome, path, (list,))
    for path in (
        "signed",
        "real_payment",
        "dispute",
        "demand_clarity_improved",
        "service_fee_accepted",
    ):
        _expect_bool(issues, outcome, path)
    _expect_type(issues, outcome, "operator_hours", (dict,))
    _expect_type(issues, outcome, "willing_to_use_again", (dict,))
    for path in (
        "project_id",
        "pilot_id",
        "demand_id",
        "status",
        "planned_start",
        "actual_start",
        "planned_finish",
        "actual_finish",
    ):
        _expect_string(issues, outcome, path)
    _expect_string(issues, outcome, "failure_primary", allow_none=True)
    for path in ("planned_start", "actual_start", "planned_finish", "actual_finish"):
        value = _value(outcome, path, _MISSING)
        if value is not _MISSING and _parse_date(value) is None:
            issues.append(Issue("BLOCKER", "INVALID_DATE", "{} 必须是 YYYY-MM-DD".format(path), path))
    _expect_number(issues, outcome, "scope_changes")
    _expect_list_items(issues, outcome, "creator_ids", str, "字符串")
    _expect_list_items(issues, outcome, "failure_secondary", str, "字符串")
    _check_unique_items(issues, outcome, "creator_ids")
    _check_unique_items(issues, outcome, "failure_secondary")
    _expect_list_items(issues, outcome, "safety_events", dict, "对象")
    _expect_bool_list(issues, outcome, "creator_preference_confirmed")
    for field in ("project_id", "pilot_id", "demand_id"):
        _check_identifier(issues, outcome.get(field), field)
    creator_ids = outcome.get("creator_ids")
    if isinstance(creator_ids, list):
        for index, creator_id in enumerate(creator_ids):
            _check_identifier(issues, creator_id, "creator_ids.{}".format(index))
    willingness_value = outcome.get("willing_to_use_again")
    if isinstance(willingness_value, dict):
        if "demand" in willingness_value and not isinstance(willingness_value.get("demand"), bool):
            issues.append(
                Issue(
                    "BLOCKER",
                    "INVALID_TYPE",
                    "willing_to_use_again.demand 必须是布尔值",
                    "willing_to_use_again.demand",
                )
            )
    preferences = outcome.get("creator_preference_confirmed")
    willingness_creators = (
        willingness_value.get("creators") if isinstance(willingness_value, dict) else None
    )
    if isinstance(creator_ids, list):
        if isinstance(preferences, list) and len(preferences) != len(creator_ids):
            issues.append(Issue("BLOCKER", "CARDINALITY_MISMATCH", "创作者偏好反馈数量必须与 creator_ids 一致", "creator_preference_confirmed"))
        if isinstance(willingness_creators, list) and len(willingness_creators) != len(creator_ids):
            issues.append(Issue("BLOCKER", "CARDINALITY_MISMATCH", "再次合作反馈数量必须与 creator_ids 一致", "willing_to_use_again.creators"))
    if isinstance(willingness_creators, list) and any(
        not isinstance(item, bool) for item in willingness_creators
    ):
        issues.append(
            Issue(
                "BLOCKER",
                "INVALID_TYPE",
                "willing_to_use_again.creators 必须是布尔值数组",
                "willing_to_use_again.creators",
            )
        )
    failure_codes = rules.reason_codes.get("project_failure", {})
    failure_primary = outcome.get("failure_primary")
    if isinstance(failure_primary, str) and failure_primary:
        if failure_primary not in failure_codes:
            issues.append(Issue("BLOCKER", "UNKNOWN_ENUM", "failure_primary 不是有效原因代码", "failure_primary"))
    secondary = outcome.get("failure_secondary")
    if isinstance(secondary, list) and any(
        isinstance(code, str) and code not in failure_codes for code in secondary
    ):
            issues.append(Issue("BLOCKER", "UNKNOWN_ENUM", "failure_secondary 包含无效原因代码", "failure_secondary"))
    outcome_status = outcome.get("status")
    if not isinstance(outcome_status, str) or outcome_status not in OUTCOME_STATUSES:
        issues.append(Issue("BLOCKER", "INVALID_OUTCOME_STATUS", "结果状态必须是 completed/exited/failed", "status"))
    if not isinstance(outcome.get("creator_ids"), list) or not outcome.get("creator_ids"):
        issues.append(Issue("BLOCKER", "INVALID_CREATORS", "结果至少需要一个 creator id", "creator_ids"))
    if outcome.get("status") == "completed" and outcome.get("real_payment") is not True:
        issues.append(Issue("BLOCKER", "COMPLETED_WITHOUT_PAYMENT", "首轮付费项目不能在无真实付款时标记 completed", "real_payment"))
    if outcome.get("status") == "completed" and (
        _present(outcome.get("failure_primary")) or _present(outcome.get("failure_secondary"))
    ):
        issues.append(Issue("BLOCKER", "CONTRADICTORY_OUTCOME", "完成状态不能同时记录失败原因", "failure_primary"))
    if outcome.get("status") in ("exited", "failed") and not outcome.get("failure_primary"):
        issues.append(Issue("BLOCKER", "MISSING_FAILURE_REASON", "退出或失败必须记录首要原因", "failure_primary"))
    milestones = outcome.get("milestones")
    if not isinstance(milestones, list):
        issues.append(Issue("BLOCKER", "INVALID_MILESTONES", "milestones 必须是列表", "milestones"))
    else:
        for index, milestone in enumerate(milestones):
            if not isinstance(milestone, dict) or not all(
                key in milestone for key in ("id", "amount", "accepted", "paid", "paid_on_terms")
            ):
                issues.append(Issue("BLOCKER", "INVALID_MILESTONE", "里程碑缺少结果字段", "milestones.{}".format(index)))
                continue
            if not isinstance(milestone.get("id"), str) or not milestone.get("id"):
                issues.append(Issue("BLOCKER", "INVALID_TYPE", "里程碑 id 必须是非空字符串", "milestones.{}.id".format(index)))
            else:
                _check_identifier(issues, milestone.get("id"), "milestones.{}.id".format(index))
            if not _is_finite_number(milestone.get("amount")):
                issues.append(Issue("BLOCKER", "INVALID_TYPE", "里程碑 amount 必须是有限数字", "milestones.{}.amount".format(index)))
            elif milestone.get("amount") < 0:
                issues.append(Issue("BLOCKER", "INVALID_NUMBER", "里程碑 amount 必须是非负数", "milestones.{}.amount".format(index)))
            for field in ("accepted", "paid", "paid_on_terms"):
                if not isinstance(milestone.get(field), bool):
                    issues.append(Issue("BLOCKER", "INVALID_TYPE", "里程碑 {} 必须是布尔值".format(field), "milestones.{}.{}".format(index, field)))
    hours = outcome.get("operator_hours")
    if not isinstance(hours, dict):
        issues.append(Issue("BLOCKER", "INVALID_OPERATOR_HOURS", "operator_hours 必须是对象", "operator_hours"))
    else:
        unknown_categories = sorted(set(hours) - _OPERATOR_HOUR_CATEGORIES)
        if unknown_categories:
            issues.append(Issue("BLOCKER", "UNKNOWN_ENUM", "operator_hours 包含未知分类", "operator_hours"))
            issues.append(Issue("BLOCKER", "INVALID_TYPE", "operator_hours 包含无效条目", "operator_hours"))
        for category in _OPERATOR_HOUR_CATEGORIES:
            if category not in hours:
                continue
            value = hours[category]
            if not _is_finite_number(value):
                issues.append(Issue("BLOCKER", "INVALID_TYPE", "人工耗时必须是有限数字", "operator_hours.{}".format(category)))
            elif value < 0:
                issues.append(Issue("BLOCKER", "INVALID_OPERATOR_HOURS", "无效的人工耗时 {}".format(category), "operator_hours.{}".format(category)))
        for category in _OPERATOR_HOUR_CATEGORIES:
            if not _is_finite_number(hours.get(category)):
                if category not in hours:
                    issues.append(Issue("BLOCKER", "INVALID_OPERATOR_HOURS", "缺少人工耗时 {}".format(category), "operator_hours.{}".format(category)))
    willingness = outcome.get("willing_to_use_again")
    if not isinstance(willingness, dict) or not isinstance(willingness.get("demand"), bool) or not isinstance(willingness.get("creators"), list):
        issues.append(Issue("BLOCKER", "INVALID_WILLINGNESS", "再次合作意愿必须包含 demand 布尔值和 creators 列表", "willing_to_use_again"))
    if not isinstance(outcome.get("safety_events"), list):
        issues.append(Issue("BLOCKER", "INVALID_SAFETY_EVENTS", "safety_events 必须是列表", "safety_events"))
    else:
        for index, event in enumerate(outcome["safety_events"]):
            event_path = "safety_events.{}".format(index)
            if not isinstance(event, dict):
                continue
            for field in ("event_ref", "severity"):
                if field not in event:
                    issues.append(
                        Issue(
                            "BLOCKER",
                            "MISSING_REQUIRED",
                            "安全事件缺少必填字段",
                            "{}.{}".format(event_path, field),
                        )
                    )
            _check_external_reference(
                issues,
                event.get("event_ref", _MISSING),
                "{}.event_ref".format(event_path),
            )
            severity = event.get("severity", _MISSING)
            if severity is not _MISSING and (
                not isinstance(severity, str) or severity not in _SAFETY_EVENT_SEVERITIES
            ):
                issues.append(
                    Issue(
                        "BLOCKER",
                        "UNKNOWN_ENUM",
                        "安全事件 severity 不是允许值",
                        "{}.severity".format(event_path),
                    )
                )
    scope_changes = outcome.get("scope_changes")
    if _is_finite_number(scope_changes):
        if not isinstance(scope_changes, int) or isinstance(scope_changes, bool):
            issues.append(Issue("BLOCKER", "INVALID_TYPE", "scope_changes 必须是整数", "scope_changes"))
        elif scope_changes < 0:
            issues.append(Issue("BLOCKER", "INVALID_NUMBER", "scope_changes 必须是非负数", "scope_changes"))
    for start_field, finish_field in (
        ("planned_start", "planned_finish"),
        ("actual_start", "actual_finish"),
    ):
        start = _parse_date(outcome.get(start_field))
        finish = _parse_date(outcome.get(finish_field))
        if start and finish and finish < start:
            issues.append(Issue("BLOCKER", "INVALID_DATE_RANGE", "{} 不能早于 {}".format(finish_field, start_field), finish_field))
    return ValidationResult("outcome", project_id, issues)
