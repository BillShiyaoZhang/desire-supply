"""Closed DTOs for the authenticated internal-pilot editor boundary."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import re
from typing import Any, Mapping, Optional, Tuple
import unicodedata
from uuid import UUID


JsonObject = Mapping[str, Any]
_WORKSPACE_ID = re.compile(
    r"^(?P<kind>org|personal|platform):"
    r"(?P<identifier>[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
    r"[0-9a-f]{4}-[0-9a-f]{12})$"
)
_EDITOR_CHOICE_PATH = re.compile(r"/(?:[a-z][a-z0-9_]*|\*)(?:/(?:[a-z][a-z0-9_]*|\*))*")
_TAXONOMY_CODE = re.compile(r"[A-Z][A-Z0-9_.:-]{1,63}")
_REGION_CODE = re.compile(r"[A-Z0-9][A-Z0-9-]{1,31}")
_LANGUAGE_TAG = re.compile(r"[A-Za-z]{2,3}(?:-[A-Za-z0-9]{2,8})*")
_CURRENCY_CODE = re.compile(r"[A-Z]{3}")
_CONTENT_ENUM = re.compile(r"[A-Z][A-Z0-9_]{1,63}")
_EDITOR_CHOICE_RESOURCE_TYPES = frozenset(("CREATOR_PROFILE", "DEMAND"))
_EDITOR_CHOICE_VALUE_CONTRACTS = frozenset(
    (
        "TAXONOMY_CODE",
        "REGION_CODE",
        "LANGUAGE_TAG",
        "CURRENCY_CODE",
        "CONTENT_ENUM",
    )
)
_EDITOR_CHOICE_NODE_KINDS = frozenset(
    (
        "DOMAIN",
        "PROBLEM_TYPE",
        "TASK",
        "SKILL",
        "SKILL_LEVEL",
        "TARGET_USER_CATEGORY",
        "WORK_MODE",
        "FEEDBACK_CADENCE",
        "TEAM_PREFERENCE",
        "REGION",
        "LANGUAGE",
        "DATA_SENSITIVITY",
        "AI_USE",
        "RISK",
        "DELIVERY_KIND",
        "REVIEW_REASON",
    )
)
_EDITOR_CHOICE_SOURCES = frozenset(
    (
        "TAXONOMY_BUNDLE_NODE",
        "INTERNAL_SANDBOX_POLICY",
        "INTERNAL_SANDBOX_PRESET",
    )
)
_DEMAND_REVIEW_REASON_CODES = frozenset(
    (
        "ACCEPTANCE_UNCLEAR",
        "BUDGET_UNHEALTHY",
        "CONTENT_INCOMPLETE",
        "DATA_PLAN_REQUIRED",
        "RISK_UNRESOLVED",
        "SCOPE_UNCLEAR",
    )
)
_DEMAND_REVIEW_FIELD_CODES = frozenset(
    (
        "ACCEPTANCE",
        "AI",
        "BUDGET",
        "COLLABORATION",
        "DECLARATIONS",
        "LOCATION",
        "MATCHING",
        "MILESTONE_PLAN",
        "PROBLEM",
        "RISK",
        "SCHEDULE",
        "SCOPE",
        "SKILLS",
    )
)
_DEMAND_REVIEW_BUDGET_CODES = frozenset(("APPROVED_EXCEPTION", "HEALTHY"))
_DEMAND_REVIEW_RISK_CODES = frozenset(("ELEVATED_APPROVED", "STANDARD"))
_DEMAND_REVIEW_HISTORY_CURSOR = re.compile(
    r"[A-Za-z0-9_-]{64,1024}\.[A-Za-z0-9_-]{43}\Z"
)
_EDITOR_CHOICE_SOURCE_CONTRACTS = {
    "TAXONOMY_BUNDLE_NODE": frozenset(("TAXONOMY_CODE",)),
    "INTERNAL_SANDBOX_POLICY": frozenset(
        ("TAXONOMY_CODE", "CURRENCY_CODE", "CONTENT_ENUM")
    ),
    "INTERNAL_SANDBOX_PRESET": frozenset(("REGION_CODE", "LANGUAGE_TAG")),
}
_EDITOR_CHOICE_VALUE_PATTERNS = {
    "TAXONOMY_CODE": _TAXONOMY_CODE,
    "REGION_CODE": _REGION_CODE,
    "LANGUAGE_TAG": _LANGUAGE_TAG,
    "CURRENCY_CODE": _CURRENCY_CODE,
    "CONTENT_ENUM": _CONTENT_ENUM,
}
# Each identity is bound to:
# (value contract, intended node kind, status, reason, sole allowed source,
#  exact fixed options).  ``None`` for fixed options means the option values
# and labels come from the exact code-native taxonomy bundle; their provenance
# is still closed here.  Policy and preset values are deliberately fixed.
_EDITOR_CHOICES_V1_BINDINGS = {
    ("CREATOR_PROFILE", "/ai/prohibited_case_codes/*"): (
        "TAXONOMY_CODE", None, "UNAVAILABLE", "NO_REVIEWED_CHOICE_SET", None, (),
    ),
    ("CREATOR_PROFILE", "/boundaries/prohibited_domains/*/code"): (
        "TAXONOMY_CODE", "DOMAIN", "AVAILABLE", None,
        "TAXONOMY_BUNDLE_NODE", None,
    ),
    ("CREATOR_PROFILE", "/boundaries/prohibited_tasks/*/code"): (
        "TAXONOMY_CODE", "TASK", "AVAILABLE", None,
        "TAXONOMY_BUNDLE_NODE", None,
    ),
    ("CREATOR_PROFILE", "/collaboration/languages/*/language_code"): (
        "LANGUAGE_TAG", None, "AVAILABLE", None, "INTERNAL_SANDBOX_PRESET",
        (("zh-CN", "中文（简体）", "INTERNAL_SANDBOX_PRESET"),),
    ),
    ("CREATOR_PROFILE", "/compensation/currency"): (
        "CURRENCY_CODE", None, "AVAILABLE", None, "INTERNAL_SANDBOX_POLICY",
        (("CNY", "人民币", "INTERNAL_SANDBOX_POLICY"),),
    ),
    ("CREATOR_PROFILE", "/interests/*/domain_code"): (
        "TAXONOMY_CODE", "DOMAIN", "AVAILABLE", None,
        "TAXONOMY_BUNDLE_NODE", None,
    ),
    ("CREATOR_PROFILE", "/interests/*/problem_code"): (
        "TAXONOMY_CODE", "PROBLEM_TYPE", "AVAILABLE", None,
        "TAXONOMY_BUNDLE_NODE", None,
    ),
    ("CREATOR_PROFILE", "/interests/*/task_code"): (
        "TAXONOMY_CODE", "TASK", "AVAILABLE", None,
        "TAXONOMY_BUNDLE_NODE", None,
    ),
    ("CREATOR_PROFILE", "/location/region_code"): (
        "REGION_CODE", None, "AVAILABLE", None, "INTERNAL_SANDBOX_PRESET",
        (("CN", "中国", "INTERNAL_SANDBOX_PRESET"),),
    ),
    ("CREATOR_PROFILE", "/skills/*/skill_code"): (
        "TAXONOMY_CODE", "SKILL", "AVAILABLE", None,
        "TAXONOMY_BUNDLE_NODE", None,
    ),
    ("DEMAND", "/budget/currency"): (
        "CURRENCY_CODE", None, "AVAILABLE", None, "INTERNAL_SANDBOX_POLICY",
        (("CNY", "人民币", "INTERNAL_SANDBOX_POLICY"),),
    ),
    ("DEMAND", "/collaboration/languages/*"): (
        "LANGUAGE_TAG", None, "AVAILABLE", None, "INTERNAL_SANDBOX_PRESET",
        (("zh-CN", "中文（简体）", "INTERNAL_SANDBOX_PRESET"),),
    ),
    ("DEMAND", "/location/allowed_creator_region_codes/*"): (
        "REGION_CODE", None, "AVAILABLE", None, "INTERNAL_SANDBOX_PRESET",
        (("CN", "中国", "INTERNAL_SANDBOX_PRESET"),),
    ),
    ("DEMAND", "/location/demand_region_code"): (
        "REGION_CODE", None, "AVAILABLE", None, "INTERNAL_SANDBOX_PRESET",
        (("CN", "中国", "INTERNAL_SANDBOX_PRESET"),),
    ),
    ("DEMAND", "/matching/domain_codes/*"): (
        "TAXONOMY_CODE", "DOMAIN", "AVAILABLE", None,
        "TAXONOMY_BUNDLE_NODE", None,
    ),
    ("DEMAND", "/matching/problem_codes/*"): (
        "TAXONOMY_CODE", "PROBLEM_TYPE", "AVAILABLE", None,
        "TAXONOMY_BUNDLE_NODE", None,
    ),
    ("DEMAND", "/matching/task_codes/*"): (
        "TAXONOMY_CODE", "TASK", "AVAILABLE", None,
        "TAXONOMY_BUNDLE_NODE", None,
    ),
    ("DEMAND", "/problem/domain_code"): (
        "TAXONOMY_CODE", "DOMAIN", "AVAILABLE", None,
        "TAXONOMY_BUNDLE_NODE", None,
    ),
    ("DEMAND", "/problem/problem_type_codes/*"): (
        "TAXONOMY_CODE", "PROBLEM_TYPE", "AVAILABLE", None,
        "TAXONOMY_BUNDLE_NODE", None,
    ),
    ("DEMAND", "/problem/target_user_category_codes/*"): (
        "TAXONOMY_CODE", "TARGET_USER_CATEGORY", "AVAILABLE", None,
        "INTERNAL_SANDBOX_POLICY",
        (("SYNTHETIC_USER", "合成用户", "INTERNAL_SANDBOX_POLICY"),),
    ),
    ("DEMAND", "/risk/dependency_codes/*"): (
        "TAXONOMY_CODE", None, "UNAVAILABLE", "NO_REVIEWED_CHOICE_SET", None, (),
    ),
    ("DEMAND", "/skills/must_have/*/skill_code"): (
        "TAXONOMY_CODE", "SKILL", "AVAILABLE", None,
        "TAXONOMY_BUNDLE_NODE", None,
    ),
    ("DEMAND", "/skills/nice_to_have/*/skill_code"): (
        "TAXONOMY_CODE", "SKILL", "AVAILABLE", None,
        "TAXONOMY_BUNDLE_NODE", None,
    ),
}


@dataclass(frozen=True)
class EditorPrincipal:
    """Authoritative identity facts injected by the authentication boundary."""

    user_id: str
    session_id: str = field(repr=False)
    organization_id: Optional[str]
    role_codes: Tuple[str, ...]
    workspace_id: Optional[str] = None
    workspace_kind: Optional[str] = None
    membership_id: Optional[str] = None
    organization_role_codes: Tuple[str, ...] = ()
    user_role_codes: Tuple[str, ...] = ()
    platform_duty_codes: Tuple[str, ...] = ()
    principal_marker_sha256: bytes = field(default=b"", repr=False)

    def __post_init__(self) -> None:
        layered = (
            self.organization_role_codes,
            self.user_role_codes,
            self.platform_duty_codes,
        )
        if (
            not isinstance(self.role_codes, tuple)
            or any(not isinstance(values, tuple) for values in layered)
            or any(
                not isinstance(code, str) or not code
                for values in (self.role_codes,) + layered
                for code in values
            )
        ):
            raise ValueError("editor role facts are invalid")
        if self.workspace_id is None:
            # Compatibility shape for the existing Memory service tests only.
            if (
                self.workspace_kind is not None
                or self.membership_id is not None
                or any(layered)
                or self.principal_marker_sha256
            ):
                raise ValueError("legacy editor principal contains workspace facts")
            return
        match = _WORKSPACE_ID.fullmatch(self.workspace_id)
        # These are selected-workspace facts, not a cross-tenant catalog of
        # everything the User can do.  In particular, organization roles are
        # scoped to this exact organization/membership candidate.  The opaque
        # principal marker separately binds the complete IAM authority graph.
        effective_role_codes = {
            "ORGANIZATION": self.organization_role_codes,
            "PERSONAL": self.user_role_codes,
            "PLATFORM": self.platform_duty_codes,
        }.get(self.workspace_kind)
        if (
            match is None
            or effective_role_codes is None
            or not isinstance(self.principal_marker_sha256, bytes)
            or len(self.principal_marker_sha256) != 32
            or self.role_codes != tuple(sorted(set(effective_role_codes)))
        ):
            raise ValueError("editor workspace authority facts are invalid")
        try:
            user_id = UUID(self.user_id)
            workspace_identifier = UUID(match.group("identifier"))
            organization_id = (
                None if self.organization_id is None else UUID(self.organization_id)
            )
            membership_id = (
                None if self.membership_id is None else UUID(self.membership_id)
            )
        except (ValueError, AttributeError):
            raise ValueError("editor workspace identity facts are invalid") from None
        if self.workspace_kind == "ORGANIZATION":
            if (
                match.group("kind") != "org"
                or organization_id != workspace_identifier
                or membership_id is None
                or not self.organization_role_codes
            ):
                raise ValueError("organization workspace facts are invalid")
        elif self.workspace_kind == "PERSONAL" and (
            match.group("kind") != "personal"
            or workspace_identifier != user_id
            or self.organization_id is not None
            or self.membership_id is not None
            or "CREATOR" not in self.user_role_codes
        ):
            raise ValueError("personal workspace facts are invalid")
        elif self.workspace_kind == "PLATFORM" and (
            match.group("kind") != "platform"
            or workspace_identifier != user_id
            or self.organization_id is not None
            or self.membership_id is not None
            or not self.platform_duty_codes
        ):
            raise ValueError("platform workspace facts are invalid")


@dataclass(frozen=True)
class EditorWorkspaceSummary:
    """Browser-safe selected-layer facts for choosing an editor workspace."""

    workspace_id: str
    workspace_kind: str
    role_codes: Tuple[str, ...]

    def __post_init__(self) -> None:
        match = _WORKSPACE_ID.fullmatch(self.workspace_id)
        allowed = {
            "ORGANIZATION": frozenset(("ORG_ADMIN", "DEMAND_OWNER")),
            "PERSONAL": frozenset(("CREATOR",)),
            "PLATFORM": frozenset(
                (
                    "ACCESS_ADMIN",
                    "OPERATIONS_REVIEWER",
                    "FINANCE_OPERATOR",
                    "TRUST_OFFICER",
                    "APPEAL_REVIEWER",
                )
            ),
        }.get(self.workspace_kind)
        prefix = {
            "ORGANIZATION": "org",
            "PERSONAL": "personal",
            "PLATFORM": "platform",
        }.get(self.workspace_kind)
        if (
            match is None
            or allowed is None
            or prefix is None
            or match.group("kind") != prefix
            or not isinstance(self.role_codes, tuple)
            or tuple(sorted(set(self.role_codes))) != self.role_codes
            or not self.role_codes
            or not set(self.role_codes).issubset(allowed)
        ):
            raise ValueError("editor workspace summary is invalid")


@dataclass(frozen=True)
class EditorVersionDto:
    version_id: str
    version_no: int
    based_on_version_id: Optional[str]
    status: str
    content: JsonObject = field(repr=False)
    content_sha256: str
    taxonomy_bundle_id: str
    created_at: datetime


@dataclass(frozen=True)
class EditorSubmissionDto:
    submission_id: str
    version_id: str
    submission_no: int
    content_sha256: str
    submitted_at: datetime


@dataclass(frozen=True)
class EditorFindingDto:
    finding_id: str
    version_id: str
    assignment_id: Optional[str]
    result: str
    reason_codes: Tuple[str, ...]
    required_field_paths: Tuple[str, ...]
    reviewed_at: datetime


@dataclass(frozen=True)
class EditorReviewAssignmentDto:
    assignment_id: str
    status: str
    expires_at: datetime


@dataclass(frozen=True)
class EditorReviewQueueItemDto:
    """Minimal pre-claim projection; tenant and content facts stay hidden."""

    demand_id: str
    demand_revision: int
    demand_version_no: int
    submitted_at: datetime
    demand_expires_at: datetime
    etag: str

    def __post_init__(self) -> None:
        try:
            demand_id = UUID(self.demand_id)
            submitted_at = _aware_utc(self.submitted_at)
            demand_expires_at = _aware_utc(self.demand_expires_at)
        except (AttributeError, TypeError, ValueError):
            raise ValueError("editor review queue item is invalid") from None
        if (
            demand_id.int == 0
            or str(demand_id) != self.demand_id
            or isinstance(self.demand_revision, bool)
            or not isinstance(self.demand_revision, int)
            or self.demand_revision < 1
            or isinstance(self.demand_version_no, bool)
            or not isinstance(self.demand_version_no, int)
            or self.demand_version_no < 1
            or submitted_at >= demand_expires_at
            or self.etag
            != f'"demand-{self.demand_revision}-review-queue"'
        ):
            raise ValueError("editor review queue item is invalid")


@dataclass(frozen=True)
class EditorReviewClaimDto:
    assignment_id: str
    demand_id: str
    demand_revision: int
    status: str
    expires_at: datetime
    etag: str
    replayed: bool

    def __post_init__(self) -> None:
        try:
            assignment_id = UUID(self.assignment_id)
            demand_id = UUID(self.demand_id)
            _aware_utc(self.expires_at)
        except (AttributeError, TypeError, ValueError):
            raise ValueError("editor review claim is invalid") from None
        if (
            assignment_id.int == 0
            or demand_id.int == 0
            or str(assignment_id) != self.assignment_id
            or str(demand_id) != self.demand_id
            or isinstance(self.demand_revision, bool)
            or not isinstance(self.demand_revision, int)
            or self.demand_revision < 1
            or self.status != "ACTIVE"
            or self.etag
            != f'"demand-{self.demand_revision}-review-queue"'
            or not isinstance(self.replayed, bool)
        ):
            raise ValueError("editor review claim is invalid")


@dataclass(frozen=True)
class EditorReviewHistoryItemDto:
    """Reviewer-owned terminal fact without tenant or authority metadata."""

    review_id: str
    demand_id: str
    demand_version_id: str
    decision: str
    reason_codes: Tuple[str, ...]
    required_field_codes: Tuple[str, ...]
    budget_health_code: Optional[str]
    risk_code: Optional[str]
    reviewed_at: datetime

    def __post_init__(self) -> None:
        try:
            identifiers = tuple(
                UUID(value)
                for value in (
                    self.review_id,
                    self.demand_id,
                    self.demand_version_id,
                )
            )
            reviewed_at = _aware_utc(self.reviewed_at)
        except (AttributeError, TypeError, ValueError):
            raise ValueError("editor review history item is invalid") from None
        if (
            any(identifier.int == 0 for identifier in identifiers)
            or tuple(str(identifier) for identifier in identifiers)
            != (self.review_id, self.demand_id, self.demand_version_id)
            or not isinstance(self.reason_codes, tuple)
            or not isinstance(self.required_field_codes, tuple)
            or len(set(self.reason_codes)) != len(self.reason_codes)
            or len(set(self.required_field_codes))
            != len(self.required_field_codes)
            or any(
                code not in _DEMAND_REVIEW_REASON_CODES
                for code in self.reason_codes
            )
            or any(
                code not in _DEMAND_REVIEW_FIELD_CODES
                for code in self.required_field_codes
            )
            or reviewed_at != self.reviewed_at.astimezone(timezone.utc)
        ):
            raise ValueError("editor review history item is invalid")
        if self.decision == "NEEDS_CHANGES":
            valid_shape = (
                1 <= len(self.reason_codes) <= 20
                and 1 <= len(self.required_field_codes) <= 50
                and self.budget_health_code is None
                and self.risk_code is None
            )
        elif self.decision == "VERIFIED":
            valid_shape = (
                not self.reason_codes
                and not self.required_field_codes
                and self.budget_health_code in _DEMAND_REVIEW_BUDGET_CODES
                and self.risk_code in _DEMAND_REVIEW_RISK_CODES
            )
        else:
            valid_shape = False
        if not valid_shape:
            raise ValueError("editor review history item is invalid")


@dataclass(frozen=True)
class EditorReviewHistoryPageDto:
    """Stable keyset page of the current reviewer's terminal decisions."""

    schema_version: str
    items: Tuple[EditorReviewHistoryItemDto, ...]
    next_cursor: Optional[str]
    has_more: bool

    def __post_init__(self) -> None:
        if (
            self.schema_version != "demand-review-history-v1"
            or not isinstance(self.items, tuple)
            or len(self.items) > 100
            or any(
                not isinstance(item, EditorReviewHistoryItemDto)
                for item in self.items
            )
            or len({item.review_id for item in self.items}) != len(self.items)
            or type(self.has_more) is not bool
            or (self.next_cursor is None) is not (not self.has_more)
            or (
                self.next_cursor is not None
                and _DEMAND_REVIEW_HISTORY_CURSOR.fullmatch(self.next_cursor)
                is None
            )
        ):
            raise ValueError("editor review history page is invalid")
        coordinates = tuple(
            (_aware_utc(item.reviewed_at), UUID(item.review_id).int)
            for item in self.items
        )
        if any(left <= right for left, right in zip(coordinates, coordinates[1:])):
            raise ValueError("editor review history page is invalid")


@dataclass(frozen=True)
class EditorChoiceOptionDto:
    """One display value with explicit, non-inferred provenance."""

    value: str
    label: str
    source: str

    def __post_init__(self) -> None:
        if (
            not isinstance(self.value, str)
            or not isinstance(self.label, str)
            or not isinstance(self.source, str)
            or not 1 <= len(self.label) <= 120
            or self.label.strip() != self.label
            or unicodedata.normalize("NFC", self.value) != self.value
            or unicodedata.normalize("NFC", self.label) != self.label
            or any(unicodedata.category(character) == "Cc" for character in self.label)
            or self.source not in _EDITOR_CHOICE_SOURCES
        ):
            raise ValueError("editor choice option is invalid")


@dataclass(frozen=True)
class EditorChoiceFieldDto:
    """A closed selector for one normalized editor field path."""

    resource_type: str
    path_template: str
    value_contract: str
    intended_node_kind: Optional[str]
    status: str
    reason_code: Optional[str]
    options: Tuple[EditorChoiceOptionDto, ...]

    def __post_init__(self) -> None:
        if (
            not isinstance(self.resource_type, str)
            or self.resource_type not in _EDITOR_CHOICE_RESOURCE_TYPES
            or not isinstance(self.path_template, str)
            or not 1 <= len(self.path_template) <= 256
            or _EDITOR_CHOICE_PATH.fullmatch(self.path_template) is None
            or not isinstance(self.value_contract, str)
            or self.value_contract not in _EDITOR_CHOICE_VALUE_CONTRACTS
            or (
                self.intended_node_kind is not None
                and (
                    not isinstance(self.intended_node_kind, str)
                    or self.intended_node_kind not in _EDITOR_CHOICE_NODE_KINDS
                )
            )
            or not isinstance(self.status, str)
            or (
                self.reason_code is not None
                and not isinstance(self.reason_code, str)
            )
            or not isinstance(self.options, tuple)
            or any(
                not isinstance(option, EditorChoiceOptionDto)
                for option in self.options
            )
        ):
            raise ValueError("editor choice field is invalid")
        if self.value_contract == "TAXONOMY_CODE":
            if self.status == "AVAILABLE" and self.intended_node_kind is None:
                raise ValueError("editor choice field is invalid")
        elif self.intended_node_kind is not None:
            raise ValueError("editor choice field is invalid")
        if self.status == "AVAILABLE":
            if self.reason_code is not None or not 1 <= len(self.options) <= 16:
                raise ValueError("editor choice field is invalid")
        elif self.status == "UNAVAILABLE":
            if (
                self.reason_code != "NO_REVIEWED_CHOICE_SET"
                or self.options
            ):
                raise ValueError("editor choice field is invalid")
        else:
            raise ValueError("editor choice field is invalid")
        option_values = tuple(option.value for option in self.options)
        if (
            len(set(option_values)) != len(option_values)
            or option_values
            != tuple(sorted(option_values, key=lambda value: value.encode("utf-8")))
        ):
            raise ValueError("editor choice field is invalid")
        value_pattern = _EDITOR_CHOICE_VALUE_PATTERNS[self.value_contract]
        for option in self.options:
            if (
                value_pattern.fullmatch(option.value) is None
                or self.value_contract
                not in _EDITOR_CHOICE_SOURCE_CONTRACTS[option.source]
                or (
                    option.source == "TAXONOMY_BUNDLE_NODE"
                    and self.intended_node_kind is None
                )
            ):
                raise ValueError("editor choice field is invalid")


@dataclass(frozen=True)
class EditorChoicesDto:
    """Bounded code and preset choices for the authenticated editor."""

    schema_version: str
    locale: str
    fields: Tuple[EditorChoiceFieldDto, ...]

    def __post_init__(self) -> None:
        if (
            self.schema_version != "editor-choices-v1"
            or self.locale != "zh-CN"
            or not isinstance(self.fields, tuple)
            or not 1 <= len(self.fields) <= 32
            or any(
                not isinstance(choice, EditorChoiceFieldDto)
                for choice in self.fields
            )
        ):
            raise ValueError("editor choices are invalid")
        identities = tuple(
            (choice.resource_type, choice.path_template) for choice in self.fields
        )
        if (
            len(set(identities)) != len(identities)
            or frozenset(identities) != frozenset(_EDITOR_CHOICES_V1_BINDINGS)
            or identities
            != tuple(
                sorted(
                    identities,
                    key=lambda value: (
                        value[0].encode("utf-8"),
                        value[1].encode("utf-8"),
                    ),
                )
            )
        ):
            raise ValueError("editor choices are invalid")
        for choice in self.fields:
            identity = (choice.resource_type, choice.path_template)
            (
                expected_contract,
                expected_kind,
                expected_status,
                expected_reason,
                expected_source,
                fixed_options,
            ) = _EDITOR_CHOICES_V1_BINDINGS[identity]
            if (
                (
                    choice.value_contract,
                    choice.intended_node_kind,
                    choice.status,
                    choice.reason_code,
                )
                != (
                    expected_contract,
                    expected_kind,
                    expected_status,
                    expected_reason,
                )
                or any(
                    option.source != expected_source for option in choice.options
                )
                or (
                    fixed_options is not None
                    and tuple(
                        (option.value, option.label, option.source)
                        for option in choice.options
                    )
                    != fixed_options
                )
            ):
                raise ValueError("editor choices are invalid")


@dataclass(frozen=True)
class EditorTaxonomyBundleDto:
    """One currently approved taxonomy selected by the managed rule catalog."""

    bundle_id: str
    status: str
    effective_at: datetime
    effective_until: Optional[datetime]

    def __post_init__(self) -> None:
        try:
            bundle_id = UUID(self.bundle_id)
        except (AttributeError, TypeError, ValueError):
            raise ValueError("editor taxonomy bundle identifier is invalid") from None
        effective_at = _aware_utc(self.effective_at)
        effective_until = (
            None
            if self.effective_until is None
            else _aware_utc(self.effective_until)
        )
        if (
            bundle_id.int == 0
            or str(bundle_id) != self.bundle_id
            or self.status != "CURRENT_APPROVED"
            or (
                effective_until is not None
                and effective_until <= effective_at
            )
        ):
            raise ValueError("editor taxonomy bundle configuration is invalid")


@dataclass(frozen=True)
class EditorConfigurationDto:
    """Closed browser configuration; it carries no writable authority facts."""

    schema_version: str
    deployment_mode: str
    taxonomy_bundle: EditorTaxonomyBundleDto
    editor_choices: EditorChoicesDto

    def __post_init__(self) -> None:
        if (
            self.schema_version != "editor-configuration-v2"
            or self.deployment_mode != "INTERNAL_SANDBOX"
            or not isinstance(self.taxonomy_bundle, EditorTaxonomyBundleDto)
            or not isinstance(self.editor_choices, EditorChoicesDto)
        ):
            raise ValueError("editor configuration is invalid")


@dataclass(frozen=True)
class EditorResourceDto:
    resource_type: str
    object_id: str
    status: str
    revision: int
    etag: str
    capabilities: Tuple[str, ...]
    editable_paths: Tuple[str, ...]
    current_version: Optional[EditorVersionDto]
    versions: Tuple[EditorVersionDto, ...]
    submissions: Tuple[EditorSubmissionDto, ...] = ()
    findings: Tuple[EditorFindingDto, ...] = ()
    review_assignment: Optional[EditorReviewAssignmentDto] = None


class EditorServiceError(RuntimeError):
    """A closed error safe to serialize at the editor transport boundary."""

    def __init__(
        self,
        *,
        status: int,
        code: str,
        path: Optional[str] = None,
        details: Optional[Mapping[str, Any]] = None,
        etag: Optional[str] = None,
    ) -> None:
        self.status = status
        self.code = code
        self.path = path
        self.details = details or {}
        self.etag = etag
        super().__init__(code)


def _aware_utc(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ValueError("editor configuration timestamp is not aware")
    try:
        if value.utcoffset() is None:
            raise ValueError("editor configuration timestamp is not aware")
        return value.astimezone(timezone.utc)
    except (OverflowError, ValueError):
        raise ValueError("editor configuration timestamp is invalid") from None
