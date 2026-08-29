"""Closed durable trigger shared by Matching and CompleteSelection.

This module intentionally contains facts only.  It has no dependency on the
Matching application handlers or on the cross-context transaction primitive,
so the producer and consumer can persist/read the exact same immutable shape.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field, is_dataclass
from datetime import datetime
import hashlib
import json
from typing import Any, Mapping


@dataclass(frozen=True)
class ChooseReceiptFact:
    receipt_id: str
    command_id: str
    operation: str
    status: str
    actor_id: str
    organization_id: str
    correlation_id: str
    selection_id: str
    attempt_id: str
    invitation_id: str
    run_id: str
    expected_selection_version: int
    expected_attempt_version: int
    expected_demand_version: int
    demand_id: str
    demand_version_id: str
    matching_request_id: str
    matching_request_version: int
    funding_id: str
    matching_rule_bundle_id: str
    candidate_selector_assignment_id: str
    candidate_selector_assignment_version: int
    candidate_selector_authority_marker_sha256: str = field(repr=False)
    rule_manifest_sha256: str = field(repr=False)
    input_set_sha256: str = field(repr=False)
    ordered_result_sha256: str = field(repr=False)
    candidate_result_sha256: str = field(repr=False)
    selection_intent_sha256: str = field(repr=False)
    payload_sha256: str = field(repr=False)


@dataclass(frozen=True)
class SelectionHoldBinding:
    selection_id: str
    selection_version: int
    current_invitation_set_sha256: str
    attempt_id: str
    attempt_version: int
    invitation_id: str
    invitation_version: int
    run_id: str
    run_version: int
    demand_id: str
    demand_version: int
    demand_version_id: str
    matching_request_id: str
    matching_request_version: int
    funding_id: str
    matching_rule_bundle_id: str
    candidate_selector_assignment_id: str
    candidate_selector_assignment_version: int
    candidate_selector_authority_marker_sha256: str = field(repr=False)
    rule_manifest_sha256: str
    input_set_sha256: str
    ordered_result_sha256: str
    candidate_result_sha256: str


@dataclass(frozen=True)
class SelectionIntentFact:
    selection_id: str
    receipt_id: str
    choose_command_id: str
    event_type: str
    status: str
    actor_id: str
    organization_id: str
    attempt_id: str
    invitation_id: str
    run_id: str
    selection_basis_code: str
    hold_decision: str
    hold_valid_until: datetime
    hold_binding: SelectionHoldBinding


@dataclass(frozen=True)
class PendingCompleteSelectionTrigger:
    """The exact receipt/intent pair durably committed by ChooseCreator."""

    completion_command_id: str
    status: str
    recorded_at: datetime
    receipt: ChooseReceiptFact
    intent: SelectionIntentFact


def _canonical_bytes(value: Any) -> bytes:
    def normalize(item: Any) -> Any:
        if is_dataclass(item):
            return normalize(asdict(item))
        if isinstance(item, datetime):
            return item.isoformat().replace("+00:00", "Z")
        if isinstance(item, tuple):
            return [normalize(child) for child in item]
        if isinstance(item, Mapping):
            return {
                str(key): normalize(child)
                for key, child in sorted(
                    item.items(), key=lambda pair: str(pair[0])
                )
            }
        return item

    return json.dumps(
        normalize(value),
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def selection_intent_sha256(intent: SelectionIntentFact) -> str:
    """Return the closed marker a Choose receipt binds for its intent."""

    if not isinstance(intent, SelectionIntentFact):
        raise TypeError("selection intent fact is required")
    return hashlib.sha256(_canonical_bytes(intent)).hexdigest()


def pending_complete_selection_trigger_sha256(
    trigger: PendingCompleteSelectionTrigger,
) -> str:
    """Bind every closed producer fact, including the receipt payload marker."""

    if not isinstance(trigger, PendingCompleteSelectionTrigger):
        raise TypeError("pending complete selection trigger is required")
    return hashlib.sha256(_canonical_bytes(trigger)).hexdigest()


__all__ = [
    "ChooseReceiptFact",
    "PendingCompleteSelectionTrigger",
    "SelectionHoldBinding",
    "SelectionIntentFact",
    "pending_complete_selection_trigger_sha256",
    "selection_intent_sha256",
]
