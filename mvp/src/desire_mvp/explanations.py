from typing import Any, Dict, List

from .models import MatchBrief, MatchScore


def explain_candidate(
    demand: Dict[str, Any], creator: Dict[str, Any], result: MatchScore
) -> MatchBrief:
    """生成可对外分享的说明；不得读取 compensation 中的私密金额。"""
    reasons: List[str] = []
    unknowns: List[str] = []
    risks: List[str] = []
    questions: List[str] = []

    overlap = result.evidence.get("interest", {}).get("overlap", {})
    interest_terms = []
    for key in ("problem_types", "domains", "tasks"):
        interest_terms.extend(overlap.get(key, []))
    if interest_terms:
        reasons.append("主动兴趣与需求重合：{}".format("、".join(dict.fromkeys(interest_terms))))

    capability = result.evidence.get("capability", {})
    must = capability.get("must_have_covered", [])
    if must:
        reasons.append("有可验证的必需技能证据：{}".format("、".join(must)))
    nice = capability.get("nice_to_have_covered", [])
    if nice:
        reasons.append("同时覆盖可选技能：{}".format("、".join(nice)))
    if result.evidence.get("compensation", {}).get("within_budget"):
        reasons.append("时间容量与报酬范围满足当前约束")

    demand_domain = demand.get("problem", {}).get("domain")
    creator_domains = creator.get("interests", {}).get("domains", [])
    if demand_domain and demand_domain not in creator_domains:
        unknowns.append("尚未确认该具体领域的直接经验")
    shared_languages = result.evidence.get("collaboration", {}).get("shared_languages", [])
    if not shared_languages:
        unknowns.append("需要确认日常工作语言")
    if result.components.get("collaboration", 0) < 80:
        unknowns.append("双方偏好的协作或反馈节奏并不完全一致")

    availability = result.evidence.get("availability", {})
    required = float(availability.get("weekly_hours_required", 0) or 0)
    available = float(availability.get("weekly_hours_available", 0) or 0)
    if required and available <= required * 1.2:
        risks.append("交付所需投入接近其当前每周可用容量")
    if result.components.get("evidence_trust", 0) < 75:
        risks.append("部分能力证据仍需在短沟通中核实")
    if demand.get("risk", {}).get("uncertainty") in ("high", "very_high"):
        risks.append("需求不确定性较高，应优先确认首个可验收里程碑")

    desired = demand.get("problem", {}).get("desired_outcome", "预期结果")
    questions.append("你会如何在第一阶段验证“{}”？".format(desired))
    if demand.get("risk", {}).get("data_sensitivity") not in (None, "public", "low"):
        questions.append("哪些数据可以不进入模型或第三方服务？")
    questions.append("开始工作前，还需要需求方提供哪些输入或决策？")

    if not reasons:
        reasons.append("满足全部硬性条件，并在透明加权规则中进入候选名单")
    if not unknowns:
        unknowns.append("需通过短沟通确认对问题理解和首个里程碑")
    if not risks:
        risks.append("暂未发现结构化高风险；仍需核实访谈中的非结构化信号")

    return MatchBrief(
        demand_id=str(demand.get("id")),
        creator_id=str(creator.get("id")),
        reasons=reasons,
        unknowns=unknowns,
        risks=risks,
        questions=questions,
    )


def brief_to_markdown(brief: MatchBrief) -> str:
    sections = [
        ("推荐理由", brief.reasons),
        ("需要确认", brief.unknowns),
        ("风险", brief.risks),
        ("建议沟通问题", brief.questions),
    ]
    lines = ["# 候选匹配说明", "", "需求：`{}`  ".format(brief.demand_id), "候选：`{}`".format(brief.creator_id)]
    for heading, items in sections:
        lines.extend(["", "## {}".format(heading), ""])
        lines.extend("- {}".format(item) for item in items)
    lines.extend(["", "> 此说明仅用于双方短沟通，不代表录用承诺，也不包含候选人的私密报酬边界。", ""])
    return "\n".join(lines)
