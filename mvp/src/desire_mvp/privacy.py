import json
from typing import Any, Iterable, List, Tuple


PROHIBITED_IDENTITY_KEYS = {
    "name",
    "real_name",
    "full_name",
    "email",
    "phone",
    "telephone",
    "wechat",
    "id_number",
    "identity_number",
    "address",
}

PRIVATE_CREATOR_KEYS = {
    "minimum_project",
    "minimum_day_rate",
    "private_floor",
    "internal_risk_label",
}


def find_prohibited_identity_fields(value: Any, path: str = "") -> List[str]:
    found: List[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = "{}.{}".format(path, key) if path else str(key)
            if str(key).lower() in PROHIBITED_IDENTITY_KEYS:
                found.append(child_path)
            found.extend(find_prohibited_identity_fields(child, child_path))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            found.extend(find_prohibited_identity_fields(child, "{}[{}]".format(path, index)))
    return found


def private_values(creator: dict) -> Iterable[Tuple[str, str]]:
    compensation = creator.get("compensation", {})
    for key in PRIVATE_CREATOR_KEYS:
        if key in compensation and compensation[key] is not None:
            yield "compensation.{}".format(key), str(compensation[key])
    for key in PRIVATE_CREATOR_KEYS:
        if key in creator and creator[key] is not None:
            yield key, str(creator[key])


def assert_external_output_safe(value: Any, creators: Iterable[dict]) -> None:
    serialized = json.dumps(value, ensure_ascii=False, sort_keys=True)
    leaks = []
    for path, private_value in (item for creator in creators for item in private_values(creator)):
        if private_value and private_value in serialized:
            leaks.append(path)
    if leaks:
        raise ValueError("对外输出疑似包含私密字段值: {}".format(", ".join(sorted(set(leaks)))))
