import csv
import io
from collections import Counter, defaultdict
from typing import Any, Dict, Iterable, List, Tuple

from .repository import Repository


def _latest_by(records: Iterable[Dict[str, Any]], key: str) -> Dict[str, Dict[str, Any]]:
    result: Dict[str, Dict[str, Any]] = {}
    for record in records:
        result[str(record[key])] = record
    return result


def _ratio(numerator: int, denominator: int) -> float:
    return round(numerator / denominator, 4) if denominator else 0.0


def _hhi(values: Dict[str, float]) -> float:
    total = sum(values.values())
    if total <= 0:
        return 0.0
    return round(sum((value / total) ** 2 for value in values.values()), 4)


def build_pilot_report(repository: Repository, pilot_id: str) -> Dict[str, Any]:
    demands = repository.list_entities("demand", pilot_id)
    recommendations = repository.recommendations_for_pilot(pilot_id)
    decisions = repository.decisions_for_pilot(pilot_id)
    outcomes = repository.outcomes_for_pilot(pilot_id)
    latest_recommendations = _latest_by(recommendations, "demand_id")
    latest_decisions = _latest_by(decisions, "demand_id")

    committed = sum(1 for demand in demands if demand.get("funding_commitment") is True)
    signed = sum(1 for outcome in outcomes if outcome.get("signed") is True)
    paid_stage = sum(1 for outcome in outcomes if outcome.get("real_payment") is True)
    completed = sum(1 for outcome in outcomes if outcome.get("status") == "completed")

    top3_hits = 0
    selected_count = 0
    override_reasons: Counter = Counter()
    candidate_responses: Counter = Counter()
    for demand_id, decision in latest_decisions.items():
        for response in decision.get("participant_responses", []):
            candidate_responses[str(response.get("code", "UNKNOWN"))] += 1
        if not decision.get("selected_creator_id"):
            continue
        selected_count += 1
        recommendation = latest_recommendations.get(demand_id, {})
        top3 = [item.get("creator_id") for item in recommendation.get("result", {}).get("ranked", [])[:3]]
        if decision["selected_creator_id"] in top3:
            top3_hits += 1
        expected_invites = top3[: len(decision.get("invited_creator_ids", []))]
        if decision.get("invited_creator_ids") != expected_invites:
            override_reasons[decision.get("reason_code", "UNKNOWN")] += 1

    budget_status = Counter(
        recommendation.get("budget", {}).get("status", "UNKNOWN")
        for recommendation in latest_recommendations.values()
    )
    milestones = [
        milestone
        for outcome in outcomes
        for milestone in outcome.get("milestones", [])
        if isinstance(milestone, dict)
    ]
    accepted_milestones = [item for item in milestones if item.get("accepted") is True]
    paid_on_terms = [item for item in accepted_milestones if item.get("paid_on_terms") is True]
    scope_changes = sum(int(outcome.get("scope_changes", 0) or 0) for outcome in outcomes)
    disputes = sum(1 for outcome in outcomes if outcome.get("dispute") is True)
    clarity_improved = sum(1 for outcome in outcomes if outcome.get("demand_clarity_improved") is True)

    willingness_responses: List[bool] = []
    preference_responses: List[bool] = []
    service_fee_responses: List[bool] = []
    for outcome in outcomes:
        feedback = outcome.get("willing_to_use_again", {})
        if isinstance(feedback.get("demand"), bool):
            willingness_responses.append(feedback["demand"])
        for value in feedback.get("creators", []):
            if isinstance(value, bool):
                willingness_responses.append(value)
        for value in outcome.get("creator_preference_confirmed", []):
            if isinstance(value, bool):
                preference_responses.append(value)
        if isinstance(outcome.get("service_fee_accepted"), bool):
            service_fee_responses.append(outcome["service_fee_accepted"])
    willing = sum(1 for value in willingness_responses if value)

    hours: Dict[str, float] = defaultdict(float)
    income: Dict[str, float] = defaultdict(float)
    opportunities: Dict[str, float] = defaultdict(float)
    failures: Counter = Counter()
    safety_events = 0
    for outcome in outcomes:
        for category, value in outcome.get("operator_hours", {}).items():
            if isinstance(value, (int, float)):
                hours[category] += float(value)
        paid_amount = sum(
            float(item.get("amount", 0) or 0)
            for item in outcome.get("milestones", [])
            if item.get("paid") is True
        )
        creator_ids = outcome.get("creator_ids", [])
        if creator_ids:
            share = paid_amount / len(creator_ids)
            for creator_id in creator_ids:
                income[str(creator_id)] += share
                opportunities[str(creator_id)] += 1
        if outcome.get("failure_primary"):
            failures[str(outcome["failure_primary"])] += 1
        safety_events += len(outcome.get("safety_events", []))

    metrics = {
        "funnel": {
            "interviewed_demands": len(demands),
            "funding_committed": committed,
            "matched": len(latest_recommendations),
            "selected": selected_count,
            "signed": signed,
            "paid_stage": paid_stage,
            "completed": completed,
        },
        "matching": {
            "top3_hits": top3_hits,
            "selected_count": selected_count,
            "top3_hit_rate": _ratio(top3_hits, selected_count),
            "override_count": sum(override_reasons.values()),
            "override_reasons": dict(sorted(override_reasons.items())),
            "candidate_response_reasons": dict(sorted(candidate_responses.items())),
        },
        "budget_status": dict(sorted(budget_status.items())),
        "delivery": {
            "milestones": len(milestones),
            "accepted_milestones": len(accepted_milestones),
            "paid_on_terms": len(paid_on_terms),
            "paid_on_terms_rate": _ratio(len(paid_on_terms), len(accepted_milestones)),
            "scope_changes": scope_changes,
            "disputes": disputes,
            "clarity_improved_projects": clarity_improved,
        },
        "experience": {
            "willing_again_positive": willing,
            "willing_again_responses": len(willingness_responses),
            "willing_again_rate": _ratio(willing, len(willingness_responses)),
            "creator_preference_confirmed": sum(1 for value in preference_responses if value),
            "creator_preference_responses": len(preference_responses),
            "service_fee_accepted": sum(1 for value in service_fee_responses if value),
            "service_fee_responses": len(service_fee_responses),
        },
        "operator_hours": dict(sorted((key, round(value, 2)) for key, value in hours.items())),
        "concentration": {
            "opportunity_hhi": _hhi(opportunities),
            "income_hhi": _hhi(income),
            "income_by_creator": dict(sorted((key, round(value, 2)) for key, value in income.items())),
        },
        "failure_reasons": dict(sorted(failures.items())),
        "safety_events": safety_events,
    }
    hypotheses = [
        {"id": "H1", "signal": "真实付款项目", "value": paid_stage, "status": "supported" if paid_stage >= 3 else "unknown"},
        {"id": "H2", "signal": "创作者认为匹配符合真实偏好", "value": metrics["experience"]["creator_preference_confirmed"], "status": "supported" if metrics["experience"]["creator_preference_confirmed"] >= 4 else "unknown"},
        {"id": "H3", "signal": "少量候选形成选择", "value": selected_count, "status": "supported" if selected_count >= 3 else "unknown"},
        {"id": "H4", "signal": "需求变清晰的项目", "value": clarity_improved, "status": "supported" if clarity_improved >= 4 else "unknown"},
        {"id": "H5", "signal": "前三名命中率", "value": metrics["matching"]["top3_hit_rate"], "status": "supported" if top3_hits >= 4 else "unknown"},
        {"id": "H6", "signal": "愿意再次使用比例/服务费接受数", "value": "{:.0%}/{}".format(metrics["experience"]["willing_again_rate"], metrics["experience"]["service_fee_accepted"]), "status": "supported" if metrics["experience"]["willing_again_rate"] >= 0.8 and metrics["experience"]["service_fee_accepted"] >= 3 else "unknown"},
    ]
    return {"pilot_id": pilot_id, "metrics": metrics, "hypotheses": hypotheses}


def report_to_markdown(report: Dict[str, Any]) -> str:
    metrics = report["metrics"]
    funnel = metrics["funnel"]
    lines = [
        "# 愿作 MVP 批次报告：{}".format(report["pilot_id"]),
        "",
        "> 这是小样本方向性报告，不作统计推断。所有数字只基于已录入的匿名化记录。",
        "",
        "## 漏斗",
        "",
        "| 访谈需求 | 资金承诺 | 已匹配 | 已选择 | 已签约 | 真实付款 | 已完成 |",
        "| ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
        "| {interviewed_demands} | {funding_committed} | {matched} | {selected} | {signed} | {paid_stage} | {completed} |".format(**funnel),
        "",
        "## 核心指标",
        "",
        "- 算法前三名命中：{top3_hits}/{selected_count}（{top3_hit_rate:.0%}）".format(**metrics["matching"]),
        "- 已验收里程碑按约付款：{paid_on_terms}/{accepted_milestones}（{paid_on_terms_rate:.0%}）".format(**metrics["delivery"]),
        "- 愿意再次使用/合作：{willing_again_positive}/{willing_again_responses}（{willing_again_rate:.0%}）".format(**metrics["experience"]),
        "- 范围变更：{}；争议：{}；安全/隐私事件：{}".format(metrics["delivery"]["scope_changes"], metrics["delivery"]["disputes"], metrics["safety_events"]),
        "- 预算健康分布：{}".format(", ".join("{}={}".format(k, v) for k, v in metrics["budget_status"].items()) or "无"),
        "",
        "## 假设信号",
        "",
        "| 假设 | 信号 | 当前值 | 判断 |",
        "| --- | --- | ---: | --- |",
    ]
    for item in report["hypotheses"]:
        lines.append("| {id} | {signal} | {value} | {status} |".format(**item))
    lines.extend(["", "## 人工投入", ""])
    if metrics["operator_hours"]:
        lines.extend("- {}：{} 小时".format(key, value) for key, value in metrics["operator_hours"].items())
    else:
        lines.append("- 尚未录入")
    lines.extend(["", "## 覆盖与失败原因", ""])
    lines.append("- 人工覆盖：{}".format(metrics["matching"]["override_reasons"] or "无"))
    lines.append("- 邀请反馈：{}".format(metrics["matching"]["candidate_response_reasons"] or "无"))
    lines.append("- 项目失败：{}".format(metrics["failure_reasons"] or "无"))
    lines.extend([
        "",
        "## 批次决策（人工填写）",
        "",
        "- [ ] 继续人工验证",
        "- [ ] 只产品化一个已反复出现的瓶颈",
        "- [ ] 调整方向后再验证",
        "- [ ] 停止",
        "",
        "决策依据：",
        "",
    ])
    return "\n".join(lines)


def report_to_csv(report: Dict[str, Any]) -> str:
    rows: List[Tuple[str, str, Any]] = []

    def flatten(prefix: str, value: Any) -> None:
        if isinstance(value, dict):
            for key in sorted(value):
                flatten("{}.{}".format(prefix, key) if prefix else key, value[key])
        else:
            rows.append((report["pilot_id"], prefix, value))

    flatten("metrics", report["metrics"])
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(("pilot_id", "metric", "value"))
    writer.writerows(rows)
    return output.getvalue()
