from datetime import date
from typing import Any, Dict, Iterable, List, Optional

from .models import Issue, ValidationResult


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


def _parse_date(value: Any) -> Optional[date]:
    if not isinstance(value, str):
        return None
    try:
        return date.fromisoformat(value)
    except ValueError:
        return None


def validate_demand(demand: Dict[str, Any], rules: Dict[str, Any] = None) -> ValidationResult:
    issues: List[Issue] = []
    demand_id = str(demand.get("id", "<unknown>"))
    _require(
        issues,
        demand,
        (
            "id",
            "pilot_id",
            "status",
            "consent_version",
            "problem.background",
            "problem.desired_outcome",
            "problem.target_users",
            "scope.deliverables",
            "scope.out_of_scope",
            "acceptance.criteria",
            "acceptance.owner",
            "acceptance.response_days",
            "skills.must_have",
            "schedule.start_date",
            "schedule.due_date",
            "schedule.estimated_days",
            "budget.maximum",
            "budget.currency",
            "payment.plan",
            "risk.uncertainty",
            "risk.urgency",
            "risk.external_dependencies",
            "risk.data_sensitivity",
            "ai.allowed",
        ),
        "需求",
    )
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
    if _present(estimated_days) and (not isinstance(estimated_days, (int, float)) or estimated_days <= 0):
        issues.append(Issue("BLOCKER", "INVALID_ESTIMATE", "预计投入天数必须大于 0", "schedule.estimated_days"))
    budget_max = _value(demand, "budget.maximum")
    if _present(budget_max) and (not isinstance(budget_max, (int, float)) or budget_max <= 0):
        issues.append(Issue("BLOCKER", "INVALID_BUDGET", "预算上限必须大于 0", "budget.maximum"))
    budget_min = _value(demand, "budget.minimum", 0)
    if isinstance(budget_min, (int, float)) and isinstance(budget_max, (int, float)) and budget_min > budget_max:
        issues.append(Issue("BLOCKER", "INVALID_BUDGET_RANGE", "预算下限高于预算上限", "budget.minimum"))

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


def validate_creator(creator: Dict[str, Any], rules: Dict[str, Any] = None) -> ValidationResult:
    issues: List[Issue] = []
    creator_id = str(creator.get("id", "<unknown>"))
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
            "compensation.minimum_project",
            "compensation.currency",
            "ai.allowed",
            "ai.human_review",
        ),
        "创作者",
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
    for field in ("availability.weekly_hours", "availability.duration_weeks", "compensation.minimum_project"):
        value = _value(creator, field)
        if _present(value) and (not isinstance(value, (int, float)) or value < 0):
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
            if not isinstance(proficiency, (int, float)) or not 0 <= proficiency <= 4:
                issues.append(Issue("BLOCKER", "INVALID_PROFICIENCY", "技能熟练度必须在 0～4 之间", "skills.{}.proficiency".format(index)))
            if not isinstance(trust, (int, float)) or not 0 <= trust <= 4:
                issues.append(Issue("BLOCKER", "INVALID_EVIDENCE_TRUST", "证据可信度必须在 0～4 之间", "skills.{}.evidence_trust".format(index)))
            if not skill.get("evidence_type") or not skill.get("evidence_ref"):
                issues.append(Issue("BLOCKER", "MISSING_SKILL_EVIDENCE", "技能 {} 缺少证据类型或引用".format(skill.get("tag", index)), "skills.{}".format(index)))
    if creator.get("status") != "active":
        issues.append(Issue("WARNING", "CREATOR_NOT_ACTIVE", "创作者当前不是 active 状态，不会进入匹配", "status"))
    if not _present(_value(creator, "ai.prohibited_cases")):
        issues.append(Issue("QUESTION", "AI_PROHIBITED_CASES", "确认哪些情形不能使用 AI", "ai.prohibited_cases"))
    return ValidationResult("creator", creator_id, issues)


def validate_outcome(outcome: Dict[str, Any], rules: Dict[str, Any] = None) -> ValidationResult:
    issues: List[Issue] = []
    project_id = str(outcome.get("project_id", "<unknown>"))
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
    if outcome.get("status") not in ("completed", "exited", "failed"):
        issues.append(Issue("BLOCKER", "INVALID_OUTCOME_STATUS", "结果状态必须是 completed/exited/failed", "status"))
    if not isinstance(outcome.get("creator_ids"), list) or not outcome.get("creator_ids"):
        issues.append(Issue("BLOCKER", "INVALID_CREATORS", "结果至少需要一个 creator id", "creator_ids"))
    if outcome.get("status") == "completed" and outcome.get("real_payment") is not True:
        issues.append(Issue("BLOCKER", "COMPLETED_WITHOUT_PAYMENT", "首轮付费项目不能在无真实付款时标记 completed", "real_payment"))
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
    hours = outcome.get("operator_hours")
    if not isinstance(hours, dict):
        issues.append(Issue("BLOCKER", "INVALID_OPERATOR_HOURS", "operator_hours 必须是对象", "operator_hours"))
    else:
        for category in ("recruiting", "interview", "matching", "coordination", "dispute"):
            if not isinstance(hours.get(category), (int, float)) or hours.get(category, -1) < 0:
                issues.append(Issue("BLOCKER", "INVALID_OPERATOR_HOURS", "缺少或无效的人工耗时 {}".format(category), "operator_hours.{}".format(category)))
    willingness = outcome.get("willing_to_use_again")
    if not isinstance(willingness, dict) or not isinstance(willingness.get("demand"), bool) or not isinstance(willingness.get("creators"), list):
        issues.append(Issue("BLOCKER", "INVALID_WILLINGNESS", "再次合作意愿必须包含 demand 布尔值和 creators 列表", "willing_to_use_again"))
    if not isinstance(outcome.get("safety_events"), list):
        issues.append(Issue("BLOCKER", "INVALID_SAFETY_EVENTS", "safety_events 必须是列表", "safety_events"))
    return ValidationResult("outcome", project_id, issues)
