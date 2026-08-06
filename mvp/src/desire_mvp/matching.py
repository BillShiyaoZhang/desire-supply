from datetime import date
from typing import Any, Dict, Iterable, List, Sequence, Set, Tuple

from .models import EligibilityResult, MatchScore


def _strings(value: Any) -> List[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if item is not None and str(item)]


def _set(value: Any) -> Set[str]:
    return set(_strings(value))


def _date(value: Any) -> date:
    try:
        return date.fromisoformat(str(value))
    except (TypeError, ValueError):
        return date.max


def _skill_map(creator: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    skills = creator.get("skills", [])
    return {
        str(skill.get("tag")): skill
        for skill in skills
        if isinstance(skill, dict) and skill.get("tag")
    }


def _reason(code: str, message: str) -> Dict[str, str]:
    return {"code": code, "message": message}


def filter_candidate(
    demand: Dict[str, Any], creator: Dict[str, Any], rules: Dict[str, Any]
) -> EligibilityResult:
    reasons: List[Dict[str, str]] = []
    if creator.get("status") != "active":
        reasons.append(_reason("CREATOR_INACTIVE", "创作者当前不可参与匹配"))

    demand_domain = str(demand.get("problem", {}).get("domain", ""))
    demand_tasks = _set(demand.get("matching", {}).get("tasks", []))
    boundaries = creator.get("boundaries", {})
    if demand_domain and demand_domain in _set(boundaries.get("prohibited_domains")):
        reasons.append(_reason("BOUNDARY_DOMAIN", "需求领域触及创作者明确边界"))
    blocked_tasks = demand_tasks & _set(boundaries.get("prohibited_tasks"))
    if blocked_tasks:
        reasons.append(_reason("BOUNDARY_TASK", "任务触及创作者明确边界: {}".format(", ".join(sorted(blocked_tasks)))))

    creator_skills = _skill_map(creator)
    missing_skills = []
    for tag in _strings(demand.get("skills", {}).get("must_have")):
        skill = creator_skills.get(tag)
        if not skill or float(skill.get("proficiency", 0)) <= 0 or float(skill.get("evidence_trust", 0)) <= 0:
            missing_skills.append(tag)
    if missing_skills:
        reasons.append(_reason("MISSING_MUST_HAVE_SKILL", "缺少有证据的必需技能: {}".format(", ".join(sorted(missing_skills)))))

    schedule = demand.get("schedule", {})
    availability = creator.get("availability", {})
    if _date(availability.get("available_from")) > _date(schedule.get("due_date")):
        reasons.append(_reason("DATE_CONFLICT", "可开始日期晚于项目截止日期"))
    required_hours = float(schedule.get("weekly_hours", 0) or 0)
    available_hours = float(availability.get("weekly_hours", 0) or 0)
    if required_hours and available_hours < required_hours:
        reasons.append(_reason("CAPACITY_CONFLICT", "每周可用容量不足"))
    required_weeks = float(schedule.get("duration_weeks", 0) or 0)
    available_weeks = float(availability.get("duration_weeks", 0) or 0)
    if required_weeks and available_weeks < required_weeks:
        reasons.append(_reason("DURATION_CONFLICT", "可持续参与时间不足"))

    budget = demand.get("budget", {})
    compensation = creator.get("compensation", {})
    if budget.get("currency") != compensation.get("currency"):
        reasons.append(_reason("CURRENCY_MISMATCH", "项目币种与创作者报酬边界币种不一致"))
    elif float(budget.get("maximum", 0) or 0) < float(compensation.get("minimum_project", 0) or 0):
        reasons.append(_reason("BELOW_PRIVATE_FLOOR", "预算未满足创作者的私密报酬边界"))

    risk = demand.get("risk", {})
    data_level = str(risk.get("data_sensitivity", "low"))
    allowed_data = _set(boundaries.get("allowed_data_sensitivity", ["public", "low", "medium", "high", "restricted"]))
    if data_level not in allowed_data:
        reasons.append(_reason("DATA_POLICY_CONFLICT", "数据敏感度与创作者边界不兼容"))
    demand_ai = demand.get("ai", {})
    creator_ai = creator.get("ai", {})
    if demand_ai.get("required") is True and creator_ai.get("allowed") is not True:
        reasons.append(_reason("AI_POLICY_CONFLICT", "需求要求使用 AI，但创作者不接受"))
    if demand_ai.get("allowed") is False and creator_ai.get("requires_ai") is True:
        reasons.append(_reason("AI_POLICY_CONFLICT", "需求禁止使用 AI，但创作者工作方式依赖 AI"))

    required_languages = _set(demand.get("collaboration", {}).get("languages"))
    creator_languages = _set(creator.get("collaboration", {}).get("languages"))
    if required_languages and not (required_languages & creator_languages):
        reasons.append(_reason("LANGUAGE_MISMATCH", "双方没有满足要求的共同工作语言"))
    required_mode = demand.get("collaboration", {}).get("required_work_mode")
    if required_mode and required_mode != creator.get("collaboration", {}).get("work_mode"):
        reasons.append(_reason("WORK_MODE_CONFLICT", "必要协作方式不兼容"))

    allowed_regions = _set(demand.get("location", {}).get("allowed_creator_regions"))
    creator_region = str(creator.get("location", {}).get("region", ""))
    if allowed_regions and creator_region not in allowed_regions:
        reasons.append(_reason("LOCATION_RESTRICTION", "创作者所在地不满足要求"))
    client_org = str(demand.get("client_org_id", ""))
    if client_org and client_org in _set(creator.get("conflicts", [])):
        reasons.append(_reason("CONFLICT_OF_INTEREST", "存在尚未解决的利益冲突"))

    return EligibilityResult(not reasons, reasons)


def _overlap_score(target: Iterable[str], offered: Iterable[str]) -> Tuple[float, List[str]]:
    target_set = set(target)
    offered_set = set(offered)
    if not target_set:
        return 50.0, []
    overlap = sorted(target_set & offered_set)
    return 100.0 * len(overlap) / len(target_set), overlap


def _interest_score(demand: Dict[str, Any], creator: Dict[str, Any]) -> Tuple[float, Dict[str, Any]]:
    matching = demand.get("matching", {})
    interests = creator.get("interests", {})
    targets: Sequence[Tuple[str, List[str], List[str]]] = (
        ("problem_types", _strings(matching.get("problem_types")), _strings(interests.get("problem_types"))),
        ("domains", _strings(matching.get("domains", [demand.get("problem", {}).get("domain")])), _strings(interests.get("domains"))),
        ("tasks", _strings(matching.get("tasks")), _strings(interests.get("tasks"))),
    )
    scores: List[float] = []
    overlaps: Dict[str, List[str]] = {}
    for name, wanted, offered in targets:
        score, overlap = _overlap_score(wanted, offered)
        scores.append(score)
        overlaps[name] = overlap
    base = sum(scores) / len(scores)
    intensity = min(max(float(interests.get("intensity", 0) or 0), 0.0), 4.0)
    adjusted = base * (0.6 + 0.1 * intensity)
    return min(100.0, adjusted), {"overlap": overlaps, "interest_intensity": intensity}


def _capability_score(demand: Dict[str, Any], creator: Dict[str, Any]) -> Tuple[float, Dict[str, Any]]:
    skills = _skill_map(creator)
    must = _strings(demand.get("skills", {}).get("must_have"))
    nice = _strings(demand.get("skills", {}).get("nice_to_have"))

    def score(tags: List[str]) -> float:
        if not tags:
            return 100.0
        values = []
        for tag in tags:
            item = skills.get(tag, {})
            proficiency = min(max(float(item.get("proficiency", 0) or 0), 0.0), 4.0)
            trust = min(max(float(item.get("evidence_trust", 0) or 0), 0.0), 4.0)
            values.append((proficiency / 4.0) * (0.7 + 0.3 * trust / 4.0) * 100.0)
        return sum(values) / len(values)

    must_score = score(must)
    nice_score = score(nice) if nice else must_score
    return 0.85 * must_score + 0.15 * nice_score, {
        "must_have_covered": [tag for tag in must if tag in skills],
        "nice_to_have_covered": [tag for tag in nice if tag in skills],
    }


def _availability_score(demand: Dict[str, Any], creator: Dict[str, Any]) -> Tuple[float, Dict[str, Any]]:
    schedule = demand.get("schedule", {})
    availability = creator.get("availability", {})
    required = float(schedule.get("weekly_hours", 0) or 0)
    available = float(availability.get("weekly_hours", 0) or 0)
    capacity_score = 100.0 if required <= 0 else min(100.0, 100.0 * available / required)
    start = _date(schedule.get("start_date"))
    available_from = _date(availability.get("available_from"))
    if available_from <= start:
        start_score = 100.0
    else:
        due = _date(schedule.get("due_date"))
        window = max((due - start).days, 1)
        delay = max((available_from - start).days, 0)
        start_score = max(0.0, 100.0 * (1 - delay / window))
    return 0.7 * capacity_score + 0.3 * start_score, {
        "weekly_hours_required": required,
        "weekly_hours_available": available,
        "available_from": availability.get("available_from"),
    }


def _compensation_score(demand: Dict[str, Any], creator: Dict[str, Any]) -> Tuple[float, Dict[str, Any]]:
    budget = demand.get("budget", {})
    floor = float(creator.get("compensation", {}).get("minimum_project", 0) or 0)
    minimum = float(budget.get("minimum", 0) or 0)
    maximum = float(budget.get("maximum", 0) or 0)
    if minimum >= floor:
        score = 100.0
    elif maximum >= floor and maximum > minimum:
        score = 80.0 + 20.0 * (maximum - floor) / (maximum - minimum)
    else:
        score = 0.0
    return min(100.0, score), {"within_budget": maximum >= floor}


def _collaboration_score(demand: Dict[str, Any], creator: Dict[str, Any]) -> Tuple[float, Dict[str, Any]]:
    wanted = demand.get("collaboration", {})
    offered = creator.get("collaboration", {})
    parts: List[float] = []
    languages = _set(wanted.get("languages"))
    shared = sorted(languages & _set(offered.get("languages")))
    parts.append(100.0 if not languages or shared else 0.0)
    for demand_key, creator_key in (
        ("preferred_work_mode", "work_mode"),
        ("feedback_frequency", "feedback_frequency"),
        ("team_preference", "team_preference"),
    ):
        target = wanted.get(demand_key)
        actual = offered.get(creator_key)
        parts.append(100.0 if not target or target == actual else 40.0)
    return sum(parts) / len(parts), {"shared_languages": shared}


def _evidence_score(creator: Dict[str, Any]) -> Tuple[float, Dict[str, Any]]:
    trusts = [
        min(max(float(skill.get("evidence_trust", 0) or 0), 0.0), 4.0)
        for skill in creator.get("skills", [])
        if isinstance(skill, dict)
    ]
    average = sum(trusts) / len(trusts) if trusts else 0.0
    return average / 4.0 * 100.0, {"evidence_items": len(trusts)}


def score_candidate(demand: Dict[str, Any], creator: Dict[str, Any], config: Dict[str, Any]) -> MatchScore:
    calculations = {
        "interest": _interest_score(demand, creator),
        "capability": _capability_score(demand, creator),
        "availability": _availability_score(demand, creator),
        "compensation": _compensation_score(demand, creator),
        "collaboration": _collaboration_score(demand, creator),
        "evidence_trust": _evidence_score(creator),
    }
    components = {name: round(value[0], 2) for name, value in calculations.items()}
    weights = config.get("weights", {})
    total = sum(components[name] * float(weights.get(name, 0)) for name in components)
    return MatchScore(
        creator_id=str(creator.get("id")),
        total=round(total, 2),
        components=components,
        evidence={name: value[1] for name, value in calculations.items()},
    )


def rank_candidates(
    demand: Dict[str, Any], creators: Iterable[Dict[str, Any]], config: Dict[str, Any]
) -> Tuple[List[MatchScore], List[Dict[str, Any]]]:
    scores: List[MatchScore] = []
    excluded: List[Dict[str, Any]] = []
    for creator in sorted(creators, key=lambda item: str(item.get("id", ""))):
        eligibility = filter_candidate(demand, creator, config)
        if eligibility.eligible:
            scores.append(score_candidate(demand, creator, config))
        else:
            excluded.append({"creator_id": str(creator.get("id")), "reasons": eligibility.reasons})
    scores.sort(key=lambda item: (-item.total, item.creator_id))
    return scores, excluded
