"""Public payload-schema version and closed-field boundary.

The migration layer may accept an unversioned legacy payload so that it can be
converted deliberately.  Normal application reads and writes must use this
module instead: there is exactly one current, explicit payload version and the
boundary never guesses or coerces it.
"""

from dataclasses import dataclass
from datetime import date
import math
import re
from typing import Any, Dict, Mapping, Tuple

from .migration_support import CURRENT_PAYLOAD_SCHEMA_VERSION


class SchemaVersionError(ValueError):
    """Stable, payload-safe failure raised for unsupported schema versions."""

    def __init__(self) -> None:
        self.code = "UNSUPPORTED_SCHEMA_VERSION"
        super().__init__(self.code)


class SchemaContractError(ValueError):
    """Stable failure for a versioned payload outside its static contract."""

    def __init__(self) -> None:
        self.code = "INVALID_PAYLOAD_SCHEMA"
        super().__init__(self.code)


@dataclass(frozen=True)
class SchemaContractViolation:
    code: str
    path: str


def validate_schema_version(record: Mapping[str, Any]) -> int:
    """Return the current explicit payload version or raise a stable error.

    ``bool`` is intentionally rejected even though it is an ``int`` subclass
    in Python.  Strings and legacy/missing versions are not coerced.  Keeping
    this function side-effect free lets import preflight and Repository writes
    share the exact same contract.
    """

    version = record.get("schema_version") if isinstance(record, Mapping) else None
    if (
        not isinstance(version, int)
        or isinstance(version, bool)
        or version != CURRENT_PAYLOAD_SCHEMA_VERSION
    ):
        raise SchemaVersionError()
    return CURRENT_PAYLOAD_SCHEMA_VERSION


# ``None`` is a scalar/open leaf, a dict is a closed JSON object, and a
# one-element tuple describes every item in a JSON array.  Keeping this small
# structural mirror in the runtime makes ``additionalProperties: false`` from
# the published schemas enforceable without adding a networked dependency.
_DEMAND_SHAPE: Dict[str, Any] = {
    "schema_version": None,
    "id": None,
    "pilot_id": None,
    "status": None,
    "consent_version": None,
    "client_org_id": None,
    "decision_authority_confirmed": None,
    "funding_commitment": None,
    "funding_evidence_ref": None,
    "problem": {
        "background": None,
        "domain": None,
        "target_users": (None,),
        "desired_outcome": None,
    },
    "scope": {"deliverables": (None,), "out_of_scope": (None,)},
    "acceptance": {"criteria": (None,), "owner": None, "response_days": None},
    "skills": {"must_have": (None,), "nice_to_have": (None,), "level": None},
    "matching": {"problem_types": (None,), "domains": (None,), "tasks": (None,)},
    "schedule": {
        "start_date": None,
        "due_date": None,
        "estimated_days": None,
        "weekly_hours": None,
        "duration_weeks": None,
    },
    "budget": {
        "minimum": None,
        "maximum": None,
        "currency": None,
        "direct_cost": None,
    },
    "payment": {
        "plan": (
            {"milestone": None, "percent": None},
        )
    },
    "risk": {
        "uncertainty": None,
        "urgency": None,
        "external_dependencies": None,
        "data_sensitivity": None,
        "data_handling_plan": None,
    },
    "ai": {"allowed": None, "required": None, "data_model_policy": None},
    "collaboration": {
        "languages": (None,),
        "preferred_work_mode": None,
        "feedback_frequency": None,
        "team_preference": None,
    },
    "location": {"region": None, "allowed_creator_regions": (None,)},
}

_CREATOR_SHAPE: Dict[str, Any] = {
    "schema_version": None,
    "id": None,
    "status": None,
    "consent_version": None,
    "interests": {
        "problem_types": (None,),
        "domains": (None,),
        "tasks": (None,),
        "intensity": None,
    },
    "skills": (
        {
            "tag": None,
            "proficiency": None,
            "evidence_type": None,
            "evidence_trust": None,
            "evidence_ref": None,
        },
    ),
    "availability": {
        "available_from": None,
        "weekly_hours": None,
        "duration_weeks": None,
        "timezone": None,
    },
    "collaboration": {
        "languages": (None,),
        "work_mode": None,
        "feedback_frequency": None,
        "team_preference": None,
    },
    "compensation": {"minimum_project": None, "currency": None, "direct_cost": None},
    "boundaries": {
        "prohibited_domains": (None,),
        "prohibited_tasks": (None,),
        "allowed_data_sensitivity": (None,),
    },
    "location": {"region": None},
    "conflicts": (None,),
    "ai": {
        "allowed": None,
        "requires_ai": None,
        "human_review": None,
        "prohibited_cases": (None,),
    },
}

_OUTCOME_SHAPE: Dict[str, Any] = {
    "schema_version": None,
    "project_id": None,
    "pilot_id": None,
    "demand_id": None,
    "creator_ids": (None,),
    "status": None,
    "signed": None,
    "real_payment": None,
    "planned_start": None,
    "actual_start": None,
    "planned_finish": None,
    "actual_finish": None,
    "milestones": (
        {
            "id": None,
            "amount": None,
            "accepted": None,
            "paid": None,
            "paid_on_terms": None,
        },
    ),
    "scope_changes": None,
    "dispute": None,
    "demand_clarity_improved": None,
    "creator_preference_confirmed": (None,),
    "willing_to_use_again": {"demand": None, "creators": (None,)},
    "service_fee_accepted": None,
    "operator_hours": {
        "recruiting": None,
        "interview": None,
        "matching": None,
        "coordination": None,
        "dispute": None,
    },
    "failure_primary": None,
    "failure_secondary": (None,),
    "safety_events": ({"event_ref": None, "severity": None},),
}

_PAYLOAD_SHAPES = {
    "demand": _DEMAND_SHAPE,
    "creator": _CREATOR_SHAPE,
    "outcome": _OUTCOME_SHAPE,
}

_REQUIRED_PATHS = {
    "demand": (
        "schema_version", "id", "pilot_id", "status", "consent_version",
        "client_org_id", "decision_authority_confirmed", "funding_commitment",
        "problem", "problem.background", "problem.domain", "problem.target_users",
        "problem.desired_outcome", "scope", "scope.deliverables", "scope.out_of_scope",
        "acceptance", "acceptance.criteria", "acceptance.owner",
        "acceptance.response_days", "skills", "skills.must_have",
        "skills.nice_to_have", "skills.level", "matching",
        "matching.problem_types", "matching.domains", "matching.tasks", "schedule",
        "schedule.start_date", "schedule.due_date", "schedule.estimated_days",
        "schedule.weekly_hours", "schedule.duration_weeks", "budget", "budget.minimum",
        "budget.maximum", "budget.currency", "budget.direct_cost", "payment",
        "payment.plan", "risk", "risk.uncertainty", "risk.urgency",
        "risk.external_dependencies", "risk.data_sensitivity", "ai", "ai.allowed",
        "ai.required", "collaboration", "collaboration.languages",
        "collaboration.preferred_work_mode", "collaboration.feedback_frequency",
        "collaboration.team_preference", "location", "location.region",
        "location.allowed_creator_regions",
    ),
    "creator": (
        "schema_version", "id", "status", "consent_version", "interests",
        "interests.problem_types", "interests.domains", "interests.tasks",
        "interests.intensity", "skills", "availability", "availability.available_from",
        "availability.weekly_hours", "availability.duration_weeks", "availability.timezone",
        "collaboration", "collaboration.languages", "collaboration.work_mode",
        "collaboration.feedback_frequency", "collaboration.team_preference", "compensation",
        "compensation.minimum_project", "compensation.currency", "compensation.direct_cost",
        "boundaries", "boundaries.prohibited_domains", "boundaries.prohibited_tasks",
        "boundaries.allowed_data_sensitivity", "location", "location.region", "conflicts",
        "ai", "ai.allowed", "ai.requires_ai", "ai.human_review",
    ),
    "outcome": (
        "schema_version", "project_id", "pilot_id", "demand_id", "creator_ids",
        "status", "signed", "real_payment", "milestones", "scope_changes", "dispute",
        "demand_clarity_improved", "creator_preference_confirmed", "willing_to_use_again",
        "willing_to_use_again.demand", "willing_to_use_again.creators",
        "service_fee_accepted", "operator_hours", "operator_hours.recruiting",
        "operator_hours.interview", "operator_hours.matching", "operator_hours.coordination",
        "operator_hours.dispute", "failure_primary", "failure_secondary", "safety_events",
    ),
}

_REQUIRED_ARRAY_ITEM_FIELDS = {
    ("demand", "payment.plan"): ("milestone", "percent"),
    ("creator", "skills"): (
        "tag", "proficiency", "evidence_type", "evidence_trust", "evidence_ref"
    ),
    ("outcome", "milestones"): ("id", "amount", "accepted", "paid", "paid_on_terms"),
    ("outcome", "safety_events"): ("event_ref", "severity"),
}

_UNIQUE_ARRAY_PATHS = {
    "demand": (
        "problem.target_users", "scope.deliverables", "scope.out_of_scope",
        "acceptance.criteria", "skills.must_have", "skills.nice_to_have",
        "matching.problem_types", "matching.domains", "matching.tasks",
        "collaboration.languages", "location.allowed_creator_regions",
    ),
    "creator": (
        "interests.problem_types", "interests.domains", "interests.tasks",
        "collaboration.languages", "boundaries.prohibited_domains",
        "boundaries.prohibited_tasks", "boundaries.allowed_data_sensitivity",
        "conflicts", "ai.prohibited_cases",
    ),
    "outcome": ("creator_ids", "failure_secondary"),
}

_STRING_PATHS = {
    "demand": (
        "consent_version", "problem.background",
        "problem.domain", "problem.desired_outcome", "acceptance.owner", "skills.level",
        "budget.currency", "risk.uncertainty", "risk.urgency",
        "risk.external_dependencies", "risk.data_handling_plan", "ai.data_model_policy",
        "collaboration.preferred_work_mode", "collaboration.feedback_frequency",
        "collaboration.team_preference", "location.region", "payment.plan[].milestone",
    ),
    "creator": (
        "consent_version", "availability.timezone", "collaboration.work_mode",
        "collaboration.feedback_frequency", "collaboration.team_preference",
        "compensation.currency", "ai.human_review", "skills[].tag",
        "skills[].evidence_type", "skills[].evidence_ref", "location.region",
    ),
    "outcome": (),
}

_IDENTIFIER_PATHS = {
    "demand": ("id", "pilot_id", "client_org_id"),
    "creator": ("id", "conflicts[]"),
    "outcome": ("project_id", "pilot_id", "demand_id", "creator_ids[]", "milestones[].id"),
}

_REFERENCE_PATHS = {
    "demand": ("funding_evidence_ref",),
    "creator": ("skills[].evidence_ref",),
    "outcome": ("safety_events[].event_ref",),
}

_DATE_PATHS = {
    "demand": ("schedule.start_date", "schedule.due_date"),
    "creator": ("availability.available_from",),
    "outcome": ("planned_start", "actual_start", "planned_finish", "actual_finish"),
}

_BOOLEAN_PATHS = {
    "demand": ("decision_authority_confirmed", "funding_commitment", "ai.allowed", "ai.required"),
    "creator": ("ai.allowed", "ai.requires_ai"),
    "outcome": (
        "signed", "real_payment", "dispute", "demand_clarity_improved",
        "service_fee_accepted", "milestones[].accepted", "milestones[].paid",
        "milestones[].paid_on_terms", "creator_preference_confirmed[]",
        "willing_to_use_again.demand", "willing_to_use_again.creators[]",
    ),
}

# path -> (minimum, minimum_is_exclusive, maximum, integer_only)
_NUMBER_RULES = {
    "demand": {
        "acceptance.response_days": (0.0, True, None, False),
        "schedule.estimated_days": (0.0, True, None, False),
        "schedule.weekly_hours": (0.0, False, None, False),
        "schedule.duration_weeks": (0.0, False, None, False),
        "budget.minimum": (0.0, False, None, False),
        "budget.maximum": (0.0, True, None, False),
        "budget.direct_cost": (0.0, False, None, False),
        "payment.plan[].percent": (0.0, True, 100.0, False),
    },
    "creator": {
        "interests.intensity": (0.0, False, 4.0, False),
        "availability.weekly_hours": (0.0, False, None, False),
        "availability.duration_weeks": (0.0, False, None, False),
        "compensation.minimum_project": (0.0, False, None, False),
        "compensation.direct_cost": (0.0, False, None, False),
        "skills[].proficiency": (0.0, False, 4.0, False),
        "skills[].evidence_trust": (0.0, False, 4.0, False),
    },
    "outcome": {
        "scope_changes": (0.0, False, None, True),
        "operator_hours.recruiting": (0.0, False, None, False),
        "operator_hours.interview": (0.0, False, None, False),
        "operator_hours.matching": (0.0, False, None, False),
        "operator_hours.coordination": (0.0, False, None, False),
        "operator_hours.dispute": (0.0, False, None, False),
        "milestones[].amount": (0.0, False, None, False),
    },
}

_ENUM_RULES = {
    "demand": {
        "status": frozenset(("draft", "clarifying", "verified", "funded", "matching", "agreed", "cancelled")),
        "risk.data_sensitivity": frozenset(("public", "low", "medium", "high", "restricted")),
    },
    "creator": {
        "status": frozenset(("active", "paused", "inactive")),
        "boundaries.allowed_data_sensitivity[]": frozenset(("public", "low", "medium", "high", "restricted")),
    },
    "outcome": {
        "status": frozenset(("completed", "exited", "failed")),
        "safety_events[].severity": frozenset(("low", "medium", "high", "critical")),
    },
}

_STRING_ARRAY_PATHS = {
    "demand": (
        "problem.target_users", "scope.deliverables", "scope.out_of_scope",
        "acceptance.criteria", "skills.must_have", "skills.nice_to_have",
        "matching.problem_types", "matching.domains", "matching.tasks",
        "collaboration.languages", "location.allowed_creator_regions",
    ),
    "creator": (
        "interests.problem_types", "interests.domains", "interests.tasks",
        "collaboration.languages", "boundaries.prohibited_domains",
        "boundaries.prohibited_tasks", "boundaries.allowed_data_sensitivity",
        "ai.prohibited_cases",
    ),
    "outcome": ("failure_secondary",),
}

_MIN_ITEMS = {
    "demand": (
        "problem.target_users", "scope.deliverables", "acceptance.criteria",
        "skills.must_have", "payment.plan", "collaboration.languages",
    ),
    "creator": ("skills", "collaboration.languages"),
    "outcome": ("creator_ids",),
}

_IDENTIFIER_PATTERN = re.compile(
    r"^(?=.*[A-Za-z])(?!.*[0-9]{7})[A-Za-z0-9][A-Za-z0-9_-]{1,127}$"
)
_CONTROLLED_REFERENCE_PATTERN = re.compile(
    r"^(?!.*[0-9]{7})(?:external://)?[A-Za-z][A-Za-z0-9_-]{1,127}$"
)

_MISSING = object()


def _display_field_name(value: Any) -> str:
    """Never reflect an unknown user-controlled key into an error path."""

    return "<unknown-field>"


def is_controlled_reference(value: Any) -> bool:
    """Return whether a reference names controlled storage without embedding a URL."""

    return (
        isinstance(value, str)
        and _CONTROLLED_REFERENCE_PATTERN.fullmatch(value) is not None
    )


def _unknown_fields(value: Any, shape: Any, path: str) -> Tuple[str, ...]:
    if isinstance(shape, dict):
        if not isinstance(value, Mapping):
            return ()
        found = []
        for key in sorted(value, key=lambda item: str(item)):
            if key not in shape:
                rendered_key = _display_field_name(key)
                field_path = "{}.{}".format(path, rendered_key) if path else rendered_key
                found.append(field_path)
            else:
                # Known names come from the trusted, hard-coded contract rather
                # than from a user-controlled error label.
                field_path = "{}.{}".format(path, key) if path else key
                found.extend(_unknown_fields(value[key], shape[key], field_path))
        return tuple(found)
    if isinstance(shape, tuple) and len(shape) == 1 and isinstance(value, list):
        found = []
        for index, item in enumerate(value):
            field_path = "{}[{}]".format(path, index)
            found.extend(_unknown_fields(item, shape[0], field_path))
        return tuple(found)
    return ()


def unknown_schema_fields(record_type: str, record: Mapping[str, Any]) -> Tuple[str, ...]:
    """Return deterministic, payload-safe paths not admitted by the v1 schema."""

    try:
        shape = _PAYLOAD_SHAPES[record_type]
    except KeyError as exc:  # internal programming error, not a payload error
        raise ValueError("unknown record type") from exc
    return _unknown_fields(record, shape, "")


def _path_value(record: Mapping[str, Any], path: str) -> Any:
    current: Any = record
    for part in path.split("."):
        if not isinstance(current, Mapping) or part not in current:
            return _MISSING
        current = current[part]
    return current


def _container_violations(
    value: Any, shape: Any, path: str
) -> Tuple[SchemaContractViolation, ...]:
    if isinstance(shape, dict):
        if not isinstance(value, Mapping):
            return (SchemaContractViolation("INVALID_TYPE", path or "<root>"),)
        found = []
        for key, child_shape in shape.items():
            if key in value:
                child_path = "{}.{}".format(path, key) if path else key
                found.extend(_container_violations(value[key], child_shape, child_path))
        return tuple(found)
    if isinstance(shape, tuple) and len(shape) == 1:
        if not isinstance(value, list):
            return (SchemaContractViolation("INVALID_TYPE", path),)
        found = []
        for index, item in enumerate(value):
            found.extend(
                _container_violations(item, shape[0], "{}[{}]".format(path, index))
            )
        return tuple(found)
    return ()


def _path_values(record: Mapping[str, Any], path: str) -> Tuple[Tuple[str, Any], ...]:
    current = (("", record),)
    for token in path.split("."):
        is_array = token.endswith("[]")
        key = token[:-2] if is_array else token
        following = []
        for parent_path, parent in current:
            if not isinstance(parent, Mapping) or key not in parent:
                continue
            value = parent[key]
            value_path = "{}.{}".format(parent_path, key) if parent_path else key
            if is_array:
                if isinstance(value, list):
                    following.extend(
                        ("{}[{}]".format(value_path, index), item)
                        for index, item in enumerate(value)
                    )
            else:
                following.append((value_path, value))
        current = tuple(following)
    return tuple(current)


def _valid_date(value: Any) -> bool:
    if not isinstance(value, str) or re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", value) is None:
        return False
    try:
        date.fromisoformat(value)
        return True
    except ValueError:
        return False


def _scalar_contract_violations(
    record_type: str, record: Mapping[str, Any]
) -> Tuple[SchemaContractViolation, ...]:
    found = []
    for path in _STRING_PATHS[record_type]:
        for concrete_path, value in _path_values(record, path):
            if not isinstance(value, str) or not value:
                found.append(SchemaContractViolation("INVALID_TYPE", concrete_path))
    for path in _IDENTIFIER_PATHS[record_type]:
        for concrete_path, value in _path_values(record, path):
            if not isinstance(value, str) or _IDENTIFIER_PATTERN.fullmatch(value) is None:
                found.append(SchemaContractViolation("INVALID_IDENTIFIER", concrete_path))
    for path in _REFERENCE_PATHS[record_type]:
        for concrete_path, value in _path_values(record, path):
            if record_type == "demand" and path == "funding_evidence_ref" and value == "":
                continue
            if not is_controlled_reference(value):
                found.append(
                    SchemaContractViolation("INVALID_EXTERNAL_REFERENCE", concrete_path)
                )
    for path in _DATE_PATHS[record_type]:
        for concrete_path, value in _path_values(record, path):
            if not _valid_date(value):
                found.append(SchemaContractViolation("INVALID_DATE", concrete_path))
    for path in _BOOLEAN_PATHS[record_type]:
        for concrete_path, value in _path_values(record, path):
            if not isinstance(value, bool):
                found.append(SchemaContractViolation("INVALID_TYPE", concrete_path))
    for path, (minimum, exclusive, maximum, integer_only) in _NUMBER_RULES[
        record_type
    ].items():
        for concrete_path, value in _path_values(record, path):
            is_number = isinstance(value, (int, float)) and not isinstance(value, bool)
            if integer_only:
                is_number = isinstance(value, int) and not isinstance(value, bool)
            if not is_number:
                found.append(SchemaContractViolation("INVALID_TYPE", concrete_path))
                continue
            try:
                numeric = float(value)
            except (OverflowError, TypeError, ValueError):
                found.append(SchemaContractViolation("INVALID_TYPE", concrete_path))
                continue
            if not math.isfinite(numeric):
                found.append(SchemaContractViolation("INVALID_TYPE", concrete_path))
            elif (exclusive and numeric <= minimum) or (not exclusive and numeric < minimum):
                found.append(SchemaContractViolation("INVALID_NUMBER", concrete_path))
            elif maximum is not None and numeric > maximum:
                found.append(SchemaContractViolation("INVALID_NUMBER", concrete_path))
    for path, allowed in _ENUM_RULES[record_type].items():
        for concrete_path, value in _path_values(record, path):
            if not isinstance(value, str) or value not in allowed:
                found.append(SchemaContractViolation("UNKNOWN_ENUM", concrete_path))
    for path in _STRING_ARRAY_PATHS[record_type]:
        value = _path_value(record, path)
        if isinstance(value, list) and any(
            not isinstance(item, str) or not item for item in value
        ):
            found.append(SchemaContractViolation("INVALID_TYPE", path))
    for path in _MIN_ITEMS[record_type]:
        value = _path_value(record, path)
        if isinstance(value, list) and not value:
            found.append(SchemaContractViolation("MIN_ITEMS", path))

    failure_primary = _path_value(record, "failure_primary")
    if record_type == "outcome" and failure_primary is not _MISSING and not (
        failure_primary is None or isinstance(failure_primary, str)
    ):
        found.append(SchemaContractViolation("INVALID_TYPE", "failure_primary"))
    if record_type == "outcome":
        for path in ("creator_preference_confirmed", "willing_to_use_again.creators"):
            value = _path_value(record, path)
            if isinstance(value, list) and any(not isinstance(item, bool) for item in value):
                found.append(SchemaContractViolation("INVALID_TYPE", path))
        safety_events = _path_value(record, "safety_events")
        if isinstance(safety_events, list) and any(
            not isinstance(item, Mapping) for item in safety_events
        ):
            found.append(SchemaContractViolation("INVALID_TYPE", "safety_events"))

    if record_type == "demand":
        sensitivity = _path_value(record, "risk.data_sensitivity")
        if sensitivity in ("high", "restricted"):
            if _path_value(record, "risk.data_handling_plan") in (_MISSING, ""):
                found.append(
                    SchemaContractViolation("MISSING_REQUIRED", "risk.data_handling_plan")
                )
            if _path_value(record, "ai.allowed") is True and _path_value(
                record, "ai.data_model_policy"
            ) in (_MISSING, ""):
                found.append(
                    SchemaContractViolation("MISSING_REQUIRED", "ai.data_model_policy")
                )
    return tuple(found)


def _fixed_invariant_violations(
    record_type: str, record: Mapping[str, Any]
) -> Tuple[SchemaContractViolation, ...]:
    """Check immutable cross-field rules that do not depend on runtime config."""

    found = []
    if record_type == "demand":
        payment_plan = _path_value(record, "payment.plan")
        if isinstance(payment_plan, list):
            percentages = [
                item.get("percent")
                for item in payment_plan
                if isinstance(item, Mapping)
            ]
            if (
                len(percentages) == len(payment_plan)
                and all(
                    isinstance(value, (int, float))
                    and not isinstance(value, bool)
                    and math.isfinite(float(value))
                    for value in percentages
                )
                and not math.isclose(
                    sum(float(value) for value in percentages),
                    100.0,
                    rel_tol=0.0,
                    abs_tol=1e-9,
                )
            ):
                found.append(
                    SchemaContractViolation("INVALID_PERCENT_TOTAL", "payment.plan")
                )
        start = _path_value(record, "schedule.start_date")
        due = _path_value(record, "schedule.due_date")
        if _valid_date(start) and _valid_date(due) and date.fromisoformat(due) < date.fromisoformat(start):
            found.append(
                SchemaContractViolation("INVALID_DATE_RANGE", "schedule.due_date")
            )
        minimum = _path_value(record, "budget.minimum")
        maximum = _path_value(record, "budget.maximum")
        if (
            isinstance(minimum, (int, float))
            and not isinstance(minimum, bool)
            and isinstance(maximum, (int, float))
            and not isinstance(maximum, bool)
            and math.isfinite(float(minimum))
            and math.isfinite(float(maximum))
            and float(minimum) > float(maximum)
        ):
            found.append(
                SchemaContractViolation("INVALID_BUDGET_RANGE", "budget.minimum")
            )
    elif record_type == "creator":
        skills = _path_value(record, "skills")
        if isinstance(skills, list):
            tags = [
                item.get("tag")
                for item in skills
                if isinstance(item, Mapping) and isinstance(item.get("tag"), str)
            ]
            if len(tags) != len(set(tags)):
                found.append(SchemaContractViolation("DUPLICATE_SKILL", "skills"))
    elif record_type == "outcome":
        status = _path_value(record, "status")
        primary = _path_value(record, "failure_primary")
        secondary = _path_value(record, "failure_secondary")
        if status == "completed" and _path_value(record, "real_payment") is not True:
            found.append(
                SchemaContractViolation("COMPLETED_WITHOUT_PAYMENT", "real_payment")
            )
        if status == "completed" and (
            primary not in (_MISSING, None, "")
            or (isinstance(secondary, list) and bool(secondary))
        ):
            found.append(
                SchemaContractViolation("CONTRADICTORY_OUTCOME", "failure_primary")
            )
        if status in ("exited", "failed") and primary in (_MISSING, None, ""):
            found.append(
                SchemaContractViolation("MISSING_FAILURE_REASON", "failure_primary")
            )
        creator_ids = _path_value(record, "creator_ids")
        if isinstance(creator_ids, list):
            for path in (
                "creator_preference_confirmed",
                "willing_to_use_again.creators",
            ):
                values = _path_value(record, path)
                if isinstance(values, list) and len(values) != len(creator_ids):
                    found.append(
                        SchemaContractViolation("CARDINALITY_MISMATCH", path)
                    )
        for start_path, finish_path in (
            ("planned_start", "planned_finish"),
            ("actual_start", "actual_finish"),
        ):
            start = _path_value(record, start_path)
            finish = _path_value(record, finish_path)
            if (
                _valid_date(start)
                and _valid_date(finish)
                and date.fromisoformat(finish) < date.fromisoformat(start)
            ):
                found.append(
                    SchemaContractViolation("INVALID_DATE_RANGE", finish_path)
                )
    return tuple(found)


def schema_contract_violations(
    record_type: str, record: Mapping[str, Any]
) -> Tuple[SchemaContractViolation, ...]:
    """Validate static v1 structure without taxonomy, I/O, or mutable config."""

    try:
        shape = _PAYLOAD_SHAPES[record_type]
        required_paths = _REQUIRED_PATHS[record_type]
        unique_paths = _UNIQUE_ARRAY_PATHS[record_type]
    except KeyError as exc:
        raise ValueError("unknown record type") from exc
    if not isinstance(record, Mapping):
        return (SchemaContractViolation("INVALID_TYPE", "<root>"),)

    found = []
    try:
        validate_schema_version(record)
    except SchemaVersionError:
        found.append(
            SchemaContractViolation("UNSUPPORTED_SCHEMA_VERSION", "schema_version")
        )
    found.extend(
        SchemaContractViolation("UNKNOWN_FIELD", path)
        for path in unknown_schema_fields(record_type, record)
    )
    found.extend(
        SchemaContractViolation("MISSING_REQUIRED", path)
        for path in required_paths
        if _path_value(record, path) is _MISSING
    )
    for (item_record_type, list_path), required_fields in _REQUIRED_ARRAY_ITEM_FIELDS.items():
        if item_record_type != record_type:
            continue
        values = _path_value(record, list_path)
        if not isinstance(values, list):
            continue
        for index, item in enumerate(values):
            if not isinstance(item, Mapping):
                continue
            found.extend(
                SchemaContractViolation(
                    "MISSING_REQUIRED", "{}[{}].{}".format(list_path, index, field)
                )
                for field in required_fields
                if field not in item
            )
    for path in unique_paths:
        values = _path_value(record, path)
        if isinstance(values, list) and any(
            any(item == earlier for earlier in values[:index])
            for index, item in enumerate(values)
        ):
            found.append(SchemaContractViolation("DUPLICATE_ITEMS", path))
    found.extend(_container_violations(record, shape, ""))
    found.extend(_scalar_contract_violations(record_type, record))
    found.extend(_fixed_invariant_violations(record_type, record))
    return tuple(found)


def validate_payload_contract(record_type: str, record: Mapping[str, Any]) -> None:
    """Raise a payload-safe error unless the record satisfies static v1 structure."""

    if schema_contract_violations(record_type, record):
        raise SchemaContractError()
