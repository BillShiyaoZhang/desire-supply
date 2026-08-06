from typing import Any, Dict

from .models import BudgetAssessment


def _number(value: Any, default: float = 0.0) -> float:
    if isinstance(value, (int, float)):
        return float(value)
    return default


def assess_budget(demand: Dict[str, Any], budget_config: Dict[str, Any]) -> BudgetAssessment:
    budget = demand.get("budget", {})
    schedule = demand.get("schedule", {})
    risk = demand.get("risk", {})
    region = demand.get("location", {}).get("region", budget_config.get("default_region", "CN"))
    skill_level = demand.get("skills", {}).get("level", "standard")
    domain = demand.get("problem", {}).get("domain")

    regional_baseline = budget_config.get("regional_daily_baselines", {}).get(
        region, budget_config.get("regional_daily_baselines", {}).get("default", 0)
    )
    skill_multiplier = budget_config.get("skill_multipliers", {}).get(skill_level, 1.0)
    estimated_days = _number(schedule.get("estimated_days"))
    labor_baseline = estimated_days * _number(regional_baseline) * _number(skill_multiplier, 1.0)
    historical_median = _number(budget_config.get("historical_domain_medians", {}).get(domain))
    direct_cost = _number(budget.get("direct_cost"))

    risk_rates = budget_config.get("risk_rates", {})
    risk_buffer = sum(
        _number(risk_rates.get(category, {}).get(risk.get(category), 0.0))
        for category in ("uncertainty", "urgency", "external_dependencies")
    )
    risk_cap = _number(budget_config.get("risk_buffer_cap", 0.5), 0.5)
    risk_buffer = min(risk_buffer, risk_cap)
    base = max(labor_baseline, historical_median) + direct_cost
    recommended = round(base * (1 + risk_buffer), 2)
    maximum = round(_number(budget.get("maximum")), 2)
    ratio = round(maximum / recommended, 4) if recommended > 0 else 0.0
    thresholds = budget_config.get("health_thresholds", {})
    green = _number(thresholds.get("green", 1.0), 1.0)
    yellow = _number(thresholds.get("yellow", 0.8), 0.8)
    status = "GREEN" if ratio >= green else "YELLOW" if ratio >= yellow else "RED"

    return BudgetAssessment(
        demand_id=str(demand.get("id", "<unknown>")),
        currency=str(budget.get("currency", budget_config.get("currency", "CNY"))),
        labor_baseline=round(labor_baseline, 2),
        direct_cost=round(direct_cost, 2),
        risk_buffer_rate=round(risk_buffer, 4),
        recommended_minimum=recommended,
        budget_maximum=maximum,
        health_ratio=ratio,
        status=status,
        config_version=str(budget_config.get("version", "unknown")),
        assumptions={
            "region": region,
            "regional_daily_baseline": regional_baseline,
            "estimated_days": estimated_days,
            "skill_level": skill_level,
            "skill_multiplier": skill_multiplier,
            "historical_domain_median": historical_median or None,
            "risk_inputs": {
                category: risk.get(category) for category in ("uncertainty", "urgency", "external_dependencies")
            },
        },
    )
