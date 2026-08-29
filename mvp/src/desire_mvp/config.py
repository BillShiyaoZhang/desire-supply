import json
import math
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, Optional

from .matching import HARD_FILTER_CODES, MATCH_COMPONENTS


class ConfigError(ValueError):
    pass


_KEBAB_CASE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
_UPPER_SNAKE_CASE = re.compile(r"^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)*$")
_REQUIRED_REASON_CODES = {
    "decision_override": {
        "ALGORITHM_TOP",
        "MISSING_CONTEXT",
        "BAD_TAXONOMY",
        "WEIGHT_PROBLEM",
        "TRUST_SIGNAL",
        "PARTICIPANT_CHOICE",
        "CONFLICT",
        "NO_MATCH",
        "OTHER",
    },
    "candidate_response": {
        "ACCEPT",
        "NOT_INTERESTED",
        "CAPACITY",
        "COMPENSATION",
        "SCOPE_UNCLEAR",
        "BOUNDARY",
        "OTHER",
    },
    "project_failure": {
        "NO_FUNDING",
        "NO_MATCH",
        "SCOPE",
        "DEPENDENCY",
        "CAPACITY",
        "PAYMENT",
        "QUALITY",
        "COMMUNICATION",
        "SAFETY",
        "OTHER",
    },
}
_REQUIRED_RISK_LEVELS = {"low", "medium", "high", "very_high"}
_LEGACY_HARD_FILTER_OMISSIONS = {
    "matching-v1": {"CREATOR_INACTIVE", "CURRENCY_MISMATCH"},
}


@dataclass(frozen=True)
class ConfigBundle:
    manifest: Dict[str, Any]
    taxonomy: Dict[str, Any]
    matching: Dict[str, Any]
    budget: Dict[str, Any]
    reason_codes: Dict[str, Any]

    @property
    def rule_version(self) -> str:
        parts = (
            self.taxonomy.get("version"),
            self.matching.get("version"),
            self.budget.get("version"),
            self.reason_codes.get("version"),
        )
        return "+".join(str(part) for part in parts)


def default_config_dir() -> Path:
    return Path(__file__).resolve().parents[2] / "config"


def _read_json_compatible_yaml(path: Path) -> Dict[str, Any]:
    """读取 JSON 语法的 YAML。

    JSON 是 YAML 1.2 的子集。首轮采用该格式可保留 .yaml 的可迁移性，
    同时让本地工具保持零第三方运行时依赖。
    """
    try:
        with path.open("r", encoding="utf-8") as handle:
            value = json.load(handle)
    except FileNotFoundError as exc:
        raise ConfigError("缺少配置文件: {}".format(path)) from exc
    except json.JSONDecodeError as exc:
        raise ConfigError("配置不是有效的 JSON-compatible YAML: {} ({})".format(path, exc)) from exc
    if not isinstance(value, dict):
        raise ConfigError("配置根节点必须是对象: {}".format(path))
    return value


def _is_finite_number(value: Any) -> bool:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        return False
    try:
        return math.isfinite(float(value))
    except (OverflowError, TypeError, ValueError):
        return False


def _require_non_empty_string(value: Any, path: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ConfigError("{} 必须是非空字符串".format(path))
    return value


def _require_number(value: Any, path: str, minimum: float = 0.0) -> float:
    if not _is_finite_number(value) or float(value) < minimum:
        raise ConfigError("{} 必须是大于等于 {} 的有限数字".format(path, minimum))
    return float(value)


def _require_string_list(
    value: Any, path: str, *, pattern: Optional[re.Pattern] = None
) -> Iterable[str]:
    if not isinstance(value, list) or not value:
        raise ConfigError("{} 必须是非空字符串数组".format(path))
    if any(not isinstance(item, str) or not item for item in value):
        raise ConfigError("{} 必须是非空字符串数组".format(path))
    if len(set(value)) != len(value):
        raise ConfigError("{} 不能包含重复值".format(path))
    if pattern is not None:
        invalid = [item for item in value if pattern.fullmatch(item) is None]
        if invalid:
            raise ConfigError("{} 包含无效标识: {}".format(path, ", ".join(invalid)))
    return value


def _validate_taxonomy(taxonomy: Dict[str, Any]) -> None:
    for field in ("domains", "problem_types", "tasks", "skills"):
        _require_string_list(taxonomy.get(field), "taxonomy.{}".format(field), pattern=_KEBAB_CASE)


def _validate_matching(matching: Dict[str, Any]) -> None:
    weights = matching.get("weights")
    if not isinstance(weights, dict):
        raise ConfigError("matching.weights 必须是对象")
    actual_components = set(weights)
    if actual_components != MATCH_COMPONENTS:
        missing = sorted(MATCH_COMPONENTS - actual_components)
        extra = sorted(actual_components - MATCH_COMPONENTS)
        raise ConfigError(
            "matching.weights 分项不一致: missing={}, extra={}".format(missing, extra)
        )
    numeric_weights = [
        _require_number(weights[name], "matching.weights.{}".format(name))
        for name in sorted(MATCH_COMPONENTS)
    ]
    if not math.isclose(sum(numeric_weights), 1.0, rel_tol=0.0, abs_tol=1e-9):
        raise ConfigError("matching.weights 总和必须等于 1.0")

    order = matching.get("hard_filter_order")
    _require_string_list(order, "matching.hard_filter_order", pattern=_UPPER_SNAKE_CASE)
    expected_codes = HARD_FILTER_CODES - _LEGACY_HARD_FILTER_OMISSIONS.get(
        matching.get("version"), set()
    )
    actual_codes = set(order)
    if actual_codes != expected_codes:
        missing = sorted(expected_codes - actual_codes)
        extra = sorted(actual_codes - expected_codes)
        raise ConfigError(
            "matching.hard_filter_order 与引擎不一致: missing={}, extra={}".format(
                missing, extra
            )
        )


def _validate_number_map(value: Any, path: str) -> None:
    if not isinstance(value, dict) or not value:
        raise ConfigError("{} 必须是非空对象".format(path))
    for key, number in value.items():
        _require_non_empty_string(key, "{} key".format(path))
        _require_number(number, "{}.{}".format(path, key))


def _validate_budget(budget: Dict[str, Any]) -> None:
    _require_non_empty_string(budget.get("currency"), "budget.currency")
    default_region = _require_non_empty_string(budget.get("default_region"), "budget.default_region")
    baselines = budget.get("regional_daily_baselines")
    _validate_number_map(baselines, "budget.regional_daily_baselines")
    if "default" not in baselines or default_region not in baselines:
        raise ConfigError("budget.regional_daily_baselines 必须包含 default 和默认地区")
    _validate_number_map(budget.get("skill_multipliers"), "budget.skill_multipliers")
    historical_medians = budget.get("historical_domain_medians")
    if not isinstance(historical_medians, dict):
        raise ConfigError("budget.historical_domain_medians 必须是对象")
    for domain, median in historical_medians.items():
        _require_non_empty_string(domain, "budget.historical_domain_medians key")
        _require_number(median, "budget.historical_domain_medians.{}".format(domain))
    provenance = budget.get("provenance")
    if not isinstance(provenance, dict):
        raise ConfigError("budget.provenance 必须是对象")
    for field in ("status", "review_after", "instruction"):
        _require_non_empty_string(provenance.get(field), "budget.provenance.{}".format(field))

    risk_rates = budget.get("risk_rates")
    if not isinstance(risk_rates, dict):
        raise ConfigError("budget.risk_rates 必须是对象")
    for category in ("uncertainty", "urgency", "external_dependencies"):
        values = risk_rates.get(category)
        _validate_number_map(values, "budget.risk_rates.{}".format(category))
        missing_levels = sorted(_REQUIRED_RISK_LEVELS - set(values))
        if missing_levels:
            raise ConfigError(
                "budget.risk_rates.{} 缺少风险等级: {}".format(category, missing_levels)
            )
    _require_number(budget.get("risk_buffer_cap"), "budget.risk_buffer_cap")

    thresholds = budget.get("health_thresholds")
    if not isinstance(thresholds, dict):
        raise ConfigError("budget.health_thresholds 必须是对象")
    yellow = _require_number(thresholds.get("yellow"), "budget.health_thresholds.yellow")
    green = _require_number(thresholds.get("green"), "budget.health_thresholds.green")
    if yellow <= 0 or green <= yellow:
        raise ConfigError("budget 健康阈值必须满足 0 < yellow < green")


def _validate_reason_codes(reason_codes: Dict[str, Any]) -> None:
    for group, required in _REQUIRED_REASON_CODES.items():
        values = reason_codes.get(group)
        if not isinstance(values, dict) or not values:
            raise ConfigError("reason_codes.{} 必须是非空对象".format(group))
        invalid = [
            code
            for code, description in values.items()
            if not isinstance(code, str)
            or _UPPER_SNAKE_CASE.fullmatch(code) is None
            or not isinstance(description, str)
            or not description.strip()
        ]
        if invalid:
            raise ConfigError(
                "reason_codes.{} 包含无效代码或说明: {}".format(group, invalid)
            )
        missing = sorted(required - set(values))
        if missing:
            raise ConfigError("reason_codes.{} 缺少: {}".format(group, missing))


def _validate_bundle(bundle: ConfigBundle) -> None:
    _require_non_empty_string(bundle.manifest.get("active_ruleset"), "manifest.active_ruleset")
    for name, config in (
        ("taxonomy", bundle.taxonomy),
        ("matching", bundle.matching),
        ("budget", bundle.budget),
        ("reason_codes", bundle.reason_codes),
    ):
        _require_non_empty_string(config.get("version"), "{}.version".format(name))
    _validate_taxonomy(bundle.taxonomy)
    _validate_matching(bundle.matching)
    _validate_budget(bundle.budget)
    _validate_reason_codes(bundle.reason_codes)


def load_config(config_dir: Optional[Path] = None) -> ConfigBundle:
    root = Path(config_dir or default_config_dir())
    manifest = _read_json_compatible_yaml(root / "manifest.json")
    files = manifest.get("files", {})
    required = ("taxonomy", "matching", "budget", "reason_codes")
    if not isinstance(files, dict):
        raise ConfigError("manifest.files 必须是对象")
    missing = [name for name in required if not files.get(name)]
    if missing:
        raise ConfigError("manifest 缺少配置引用: {}".format(", ".join(missing)))
    invalid_files = [
        name for name in required if not isinstance(files.get(name), str) or not files[name]
    ]
    if invalid_files:
        raise ConfigError("manifest 配置引用必须是非空字符串: {}".format(invalid_files))
    bundle = ConfigBundle(
        manifest=manifest,
        taxonomy=_read_json_compatible_yaml(root / files["taxonomy"]),
        matching=_read_json_compatible_yaml(root / files["matching"]),
        budget=_read_json_compatible_yaml(root / files["budget"]),
        reason_codes=_read_json_compatible_yaml(root / files["reason_codes"]),
    )
    expected = manifest.get("versions", {})
    if not isinstance(expected, dict):
        raise ConfigError("manifest.versions 必须是对象")
    for name in required:
        actual = getattr(bundle, name).get("version")
        if expected.get(name) != actual:
            raise ConfigError(
                "{} 版本不一致: manifest={}, file={}".format(name, expected.get(name), actual)
            )
    _validate_bundle(bundle)
    return bundle
