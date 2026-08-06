from typing import Any, Dict, List, Optional


class DecisionError(ValueError):
    pass


def validate_decision(
    recommendation: Dict[str, Any],
    selected_creator_id: Optional[str],
    invited_creator_ids: List[str],
    participant_responses: List[Dict[str, Any]],
    reason_code: str,
    reason_note: Optional[str],
    reason_config: Dict[str, Any],
) -> None:
    codes = reason_config.get("decision_override", {})
    if reason_code not in codes:
        raise DecisionError("未知决定原因代码: {}".format(reason_code))
    if reason_code == "OTHER" and not reason_note:
        raise DecisionError("OTHER 必须补充文字说明")
    candidates = {
        item["creator_id"] for item in recommendation.get("result", {}).get("ranked", [])
    }
    unknown_invited = sorted(set(invited_creator_ids) - candidates)
    if unknown_invited:
        raise DecisionError("被邀请者不在合格候选中: {}".format(", ".join(unknown_invited)))
    if selected_creator_id and selected_creator_id not in candidates:
        raise DecisionError("最终选择不在合格候选中；请先修正输入并重新匹配")
    if selected_creator_id and selected_creator_id not in invited_creator_ids:
        raise DecisionError("最终选择必须包含在 invited 列表中")
    response_codes = reason_config.get("candidate_response", {})
    seen = set()
    for response in participant_responses:
        creator_id = str(response.get("creator_id", ""))
        code = response.get("code")
        if creator_id not in invited_creator_ids:
            raise DecisionError("候选反馈来自未邀请者: {}".format(creator_id))
        if creator_id in seen:
            raise DecisionError("候选反馈重复: {}".format(creator_id))
        if code not in response_codes:
            raise DecisionError("未知候选反馈代码: {}".format(code))
        if code == "OTHER" and not response.get("note"):
            raise DecisionError("候选反馈 OTHER 必须补充 note")
        seen.add(creator_id)


def is_override(recommendation: Dict[str, Any], invited_creator_ids: List[str], top: int = 3) -> bool:
    recommended = [
        item["creator_id"] for item in recommendation.get("result", {}).get("ranked", [])[:top]
    ]
    return set(invited_creator_ids) != set(recommended[: len(invited_creator_ids)])
