import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional


class ConfigError(ValueError):
    pass


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


def load_config(config_dir: Optional[Path] = None) -> ConfigBundle:
    root = Path(config_dir or default_config_dir())
    manifest = _read_json_compatible_yaml(root / "manifest.json")
    files = manifest.get("files", {})
    required = ("taxonomy", "matching", "budget", "reason_codes")
    missing = [name for name in required if not files.get(name)]
    if missing:
        raise ConfigError("manifest 缺少配置引用: {}".format(", ".join(missing)))
    bundle = ConfigBundle(
        manifest=manifest,
        taxonomy=_read_json_compatible_yaml(root / files["taxonomy"]),
        matching=_read_json_compatible_yaml(root / files["matching"]),
        budget=_read_json_compatible_yaml(root / files["budget"]),
        reason_codes=_read_json_compatible_yaml(root / files["reason_codes"]),
    )
    expected = manifest.get("versions", {})
    for name in required:
        actual = getattr(bundle, name).get("version")
        if expected.get(name) != actual:
            raise ConfigError(
                "{} 版本不一致: manifest={}, file={}".format(name, expected.get(name), actual)
            )
    return bundle
