"""Creator Profile immutable facts, validation, and aggregate transitions.

The module deliberately has no storage, HTTP, IAM, or clock dependency.  It
accepts server-issued facts, validates the closed v1 content shape, and returns
new immutable values for an application transaction to persist atomically.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import date, datetime, timedelta
from enum import Enum
import hashlib
import hmac
import json
import re
from typing import Any, Iterable, Mapping, Optional, Tuple, Union
import unicodedata
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


# Kept as a compatibility marker for callers compiled against the RED surface.
# Implemented behavior never raises this sentinel.
PROFILE_DOMAIN_BEHAVIOR_NOT_AVAILABLE = "PROFILE_DOMAIN_BEHAVIOR_NOT_AVAILABLE"


class ProfileDomainBehaviorNotAvailable(RuntimeError):
    """Legacy RED sentinel; retained for a stable import surface."""


class CreatorProfileDomainError(ValueError):
    """A closed, transport-independent Creator Profile domain rejection."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class CreatorProfileStatus(str, Enum):
    DRAFT = "DRAFT"
    ACTIVE = "ACTIVE"
    PAUSED = "PAUSED"
    ARCHIVED = "ARCHIVED"


class ProfileVersionStatus(str, Enum):
    DRAFT = "DRAFT"
    PUBLISHED = "PUBLISHED"
    SUPERSEDED = "SUPERSEDED"
    DISCARDED = "DISCARDED"
    RETIRED = "RETIRED"


class ProfileVisibility(str, Enum):
    PRIVATE = "PRIVATE"
    MATCH_ONLY = "MATCH_ONLY"
    PUBLIC = "PUBLIC"


class ProfileSourceKind(str, Enum):
    SELF_ASSERTED = "SELF_ASSERTED"
    VERIFIED_EVIDENCE = "VERIFIED_EVIDENCE"
    LEGACY_UNVERIFIED = "LEGACY_UNVERIFIED"


class CapabilityEvidenceStatus(str, Enum):
    SELF_ASSERTED = "SELF_ASSERTED"
    PENDING_VERIFICATION = "PENDING_VERIFICATION"
    VERIFIED = "VERIFIED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"
    WITHDRAWN = "WITHDRAWN"


class PauseReasonCode(str, Enum):
    OWNER_REQUEST = "OWNER_REQUEST"
    TEMPORARY_UNAVAILABILITY = "TEMPORARY_UNAVAILABILITY"
    SAFETY_REVIEW = "SAFETY_REVIEW"


class ArchiveReasonCode(str, Enum):
    OWNER_REQUEST = "OWNER_REQUEST"
    ACCOUNT_CLOSURE = "ACCOUNT_CLOSURE"
    SAFETY_REVIEW = "SAFETY_REVIEW"


FrozenScalar = Union[None, bool, int, str]
FrozenJson = Union[FrozenScalar, "ProfileContent", Tuple["FrozenJson", ...]]


@dataclass(frozen=True)
class ProfileContent:
    """Insertion-order-preserving, deeply immutable JSON object."""

    members: Tuple[Tuple[str, FrozenJson], ...] = field(repr=False)


@dataclass(frozen=True)
class CapabilityEvidence:
    evidence_id: str
    owner_user_id: str
    evidence_kind: str
    controlled_object_ref: str = field(repr=False)
    claimed_skill_codes: Tuple[str, ...]
    status: CapabilityEvidenceStatus
    verification_provider_code: Optional[str]
    verification_provider_version: Optional[str]
    verified_at: Optional[datetime]
    expires_at: Optional[datetime]
    aggregate_version: int


@dataclass(frozen=True)
class ProfileVersion:
    profile_version_id: str
    profile_id: str
    version_no: int
    status: ProfileVersionStatus
    based_on_profile_version_id: Optional[str]
    profile_schema_version: int
    canonicalization_version: str
    taxonomy_bundle_id: str
    content: ProfileContent = field(repr=False)
    content_sha256: str
    created_by_user_id: str
    asserted_at: datetime
    confirmed_by_user_id: Optional[str]
    confirmed_at: Optional[datetime]
    confirmed_evidence_versions: Tuple[Tuple[str, int, str], ...] = field(
        repr=False
    )


@dataclass(frozen=True)
class CreatorProfile:
    profile_id: str
    owner_user_id: str
    status: CreatorProfileStatus
    aggregate_version: int
    current_draft_version_id: Optional[str]
    current_published_version_id: Optional[str]
    paused_at: Optional[datetime]
    pause_reason_code: Optional[PauseReasonCode]
    archived_at: Optional[datetime]
    archive_reason_code: Optional[ArchiveReasonCode]
    created_at: datetime
    updated_at: datetime

    @classmethod
    def create(
        cls,
        *,
        profile_id: str,
        owner_user_id: str,
        now: datetime,
    ) -> "CreatorProfile":
        _require_opaque_id(profile_id)
        _require_opaque_id(owner_user_id)
        _require_utc(now)
        profile = cls(
            profile_id=profile_id,
            owner_user_id=owner_user_id,
            status=CreatorProfileStatus.DRAFT,
            aggregate_version=1,
            current_draft_version_id=None,
            current_published_version_id=None,
            paused_at=None,
            pause_reason_code=None,
            archived_at=None,
            archive_reason_code=None,
            created_at=now,
            updated_at=now,
        )
        validate_creator_profile(profile, versions=())
        return profile

    def save_draft(
        self,
        *,
        profile_version_id: str,
        taxonomy_bundle_id: str,
        based_on_profile_version_id: Optional[str],
        content: ProfileContent,
        actor_user_id: str,
        now: datetime,
        existing_versions: Tuple[ProfileVersion, ...],
    ) -> tuple["CreatorProfile", ProfileVersion]:
        if self.status is CreatorProfileStatus.ARCHIVED:
            _reject_state()
        if actor_user_id != self.owner_user_id:
            _reject_state()
        _require_opaque_id(profile_version_id)
        _require_opaque_id(taxonomy_bundle_id)
        _require_utc(now)
        _require_unique_version_chain(self, existing_versions)
        if any(item.profile_version_id == profile_version_id for item in existing_versions):
            _reject_state()

        expected_base = (
            self.current_draft_version_id or self.current_published_version_id
        )
        if based_on_profile_version_id != expected_base:
            _reject_state()
        if based_on_profile_version_id is not None:
            base = next(
                (
                    item
                    for item in existing_versions
                    if item.profile_version_id == based_on_profile_version_id
                ),
                None,
            )
            if base is None or base.profile_id != self.profile_id:
                _reject_state()

        version_no = 1 + max(
            (item.version_no for item in existing_versions), default=0
        )
        digest = profile_version_content_sha256(
            profile_id=self.profile_id,
            version_no=version_no,
            taxonomy_bundle_id=taxonomy_bundle_id,
            content=content,
        )
        version = ProfileVersion(
            profile_version_id=profile_version_id,
            profile_id=self.profile_id,
            version_no=version_no,
            status=ProfileVersionStatus.DRAFT,
            based_on_profile_version_id=based_on_profile_version_id,
            profile_schema_version=1,
            canonicalization_version="profile-version-json-v1",
            taxonomy_bundle_id=taxonomy_bundle_id,
            content=content,
            content_sha256=digest,
            created_by_user_id=actor_user_id,
            asserted_at=now,
            confirmed_by_user_id=None,
            confirmed_at=None,
            confirmed_evidence_versions=(),
        )
        validate_profile_version(
            version,
            profile=self,
            prior_versions=existing_versions,
            server_now=now,
            for_publish=False,
        )
        root = replace(
            self,
            aggregate_version=self.aggregate_version + 1,
            current_draft_version_id=profile_version_id,
            updated_at=now,
        )
        return root, version

    def publish(
        self,
        *,
        profile_version: ProfileVersion,
        actor_user_id: str,
        now: datetime,
        existing_versions: Tuple[ProfileVersion, ...],
        confirmed_evidence_versions: Tuple[Tuple[str, int, str], ...] = (),
    ) -> tuple["CreatorProfile", ProfileVersion]:
        if self.status not in (
            CreatorProfileStatus.DRAFT,
            CreatorProfileStatus.ACTIVE,
        ):
            _reject_state()
        if actor_user_id != self.owner_user_id:
            _reject_state()
        if (
            self.current_draft_version_id is None
            or profile_version.profile_version_id != self.current_draft_version_id
            or profile_version.status is not ProfileVersionStatus.DRAFT
        ):
            _reject_state()
        _require_utc(now)
        validate_profile_version(
            profile_version,
            profile=self,
            prior_versions=tuple(
                item
                for item in existing_versions
                if item.profile_version_id != profile_version.profile_version_id
            ),
            server_now=now,
            for_publish=True,
        )
        published = replace(
            profile_version,
            status=ProfileVersionStatus.PUBLISHED,
            confirmed_by_user_id=actor_user_id,
            confirmed_at=now,
            confirmed_evidence_versions=confirmed_evidence_versions,
        )
        root = replace(
            self,
            status=CreatorProfileStatus.ACTIVE,
            aggregate_version=self.aggregate_version + 1,
            current_draft_version_id=None,
            current_published_version_id=profile_version.profile_version_id,
            paused_at=None,
            pause_reason_code=None,
            updated_at=now,
        )
        return root, published

    def pause(
        self,
        *,
        reason_code: PauseReasonCode,
        now: datetime,
    ) -> "CreatorProfile":
        if self.status is not CreatorProfileStatus.ACTIVE:
            _reject_state()
        if not isinstance(reason_code, PauseReasonCode):
            _reject_validation()
        _require_utc(now)
        return replace(
            self,
            status=CreatorProfileStatus.PAUSED,
            aggregate_version=self.aggregate_version + 1,
            paused_at=now,
            pause_reason_code=reason_code,
            updated_at=now,
        )

    def resume(self, *, now: datetime) -> "CreatorProfile":
        if (
            self.status is not CreatorProfileStatus.PAUSED
            or self.current_published_version_id is None
        ):
            _reject_state()
        _require_utc(now)
        return replace(
            self,
            status=CreatorProfileStatus.ACTIVE,
            aggregate_version=self.aggregate_version + 1,
            paused_at=None,
            pause_reason_code=None,
            updated_at=now,
        )

    def archive(
        self,
        *,
        reason_code: ArchiveReasonCode,
        now: datetime,
    ) -> "CreatorProfile":
        if self.status is CreatorProfileStatus.ARCHIVED:
            _reject_state()
        if not isinstance(reason_code, ArchiveReasonCode):
            _reject_validation()
        _require_utc(now)
        return replace(
            self,
            status=CreatorProfileStatus.ARCHIVED,
            aggregate_version=self.aggregate_version + 1,
            current_draft_version_id=None,
            current_published_version_id=None,
            paused_at=None,
            pause_reason_code=None,
            archived_at=now,
            archive_reason_code=reason_code,
            updated_at=now,
        )


def validate_creator_profile(
    profile: CreatorProfile,
    *,
    versions: Tuple[ProfileVersion, ...],
) -> None:
    try:
        _require_opaque_id(profile.profile_id)
        _require_opaque_id(profile.owner_user_id)
        _require_positive_int(profile.aggregate_version, maximum=2_147_483_647)
        _require_utc(profile.created_at)
        _require_utc(profile.updated_at)
        if profile.updated_at < profile.created_at:
            _reject_state()
        _require_unique_version_chain(profile, versions)
        by_id = {item.profile_version_id: item for item in versions}
        draft_versions = tuple(
            item for item in versions if item.status is ProfileVersionStatus.DRAFT
        )
        published_versions = tuple(
            item
            for item in versions
            if item.status is ProfileVersionStatus.PUBLISHED
        )
        if len(draft_versions) > 1 or len(published_versions) > 1:
            _reject_state()
        if draft_versions and (
            profile.current_draft_version_id
            != draft_versions[0].profile_version_id
        ):
            _reject_state()
        if published_versions and (
            profile.current_published_version_id
            != published_versions[0].profile_version_id
        ):
            _reject_state()

        if profile.current_draft_version_id is not None:
            _require_opaque_id(profile.current_draft_version_id)
            draft = by_id.get(profile.current_draft_version_id)
            if draft is None or draft.status is not ProfileVersionStatus.DRAFT:
                _reject_state()
        if profile.current_published_version_id is not None:
            _require_opaque_id(profile.current_published_version_id)
            published = by_id.get(profile.current_published_version_id)
            if published is None or published.status is not ProfileVersionStatus.PUBLISHED:
                _reject_state()
        if profile.current_draft_version_id == profile.current_published_version_id and (
            profile.current_draft_version_id is not None
        ):
            _reject_state()

        if profile.status is CreatorProfileStatus.DRAFT:
            if (
                profile.current_published_version_id is not None
                or profile.paused_at is not None
                or profile.pause_reason_code is not None
                or profile.archived_at is not None
                or profile.archive_reason_code is not None
            ):
                _reject_state()
        elif profile.status is CreatorProfileStatus.ACTIVE:
            if (
                profile.current_published_version_id is None
                or profile.paused_at is not None
                or profile.pause_reason_code is not None
                or profile.archived_at is not None
                or profile.archive_reason_code is not None
            ):
                _reject_state()
        elif profile.status is CreatorProfileStatus.PAUSED:
            if (
                profile.current_published_version_id is None
                or profile.paused_at is None
                or profile.pause_reason_code is None
                or profile.archived_at is not None
                or profile.archive_reason_code is not None
            ):
                _reject_state()
            if not isinstance(profile.pause_reason_code, PauseReasonCode):
                _reject_state()
            _require_utc(profile.paused_at)
        elif profile.status is CreatorProfileStatus.ARCHIVED:
            if (
                profile.current_draft_version_id is not None
                or profile.current_published_version_id is not None
                or profile.paused_at is not None
                or profile.pause_reason_code is not None
                or profile.archived_at is None
                or profile.archive_reason_code is None
            ):
                _reject_state()
            if not isinstance(profile.archive_reason_code, ArchiveReasonCode):
                _reject_state()
            _require_utc(profile.archived_at)
        else:
            _reject_state()
    except CreatorProfileDomainError:
        raise
    except Exception:
        _reject_state()


def validate_profile_version(
    version: ProfileVersion,
    *,
    profile: CreatorProfile,
    prior_versions: Tuple[ProfileVersion, ...],
    server_now: datetime,
    for_publish: bool,
) -> None:
    try:
        _require_utc(server_now)
        _require_opaque_id(version.profile_version_id)
        if version.profile_id != profile.profile_id:
            _reject_validation()
        _require_positive_int(version.version_no, maximum=2_147_483_647)
        if version.profile_schema_version != 1:
            _reject_validation()
        if version.canonicalization_version != "profile-version-json-v1":
            _reject_validation()
        _require_opaque_id(version.taxonomy_bundle_id)
        _require_opaque_id(version.created_by_user_id)
        if version.created_by_user_id != profile.owner_user_id:
            _reject_validation()
        _require_utc(version.asserted_at)
        if version.asserted_at < profile.created_at or version.asserted_at > server_now:
            _reject_validation()
        if not re.fullmatch(r"[a-f0-9]{64}", version.content_sha256):
            _reject_validation()

        _require_unique_version_chain(profile, prior_versions)
        if any(
            item.profile_version_id == version.profile_version_id
            or item.version_no == version.version_no
            for item in prior_versions
        ):
            _reject_validation()
        if prior_versions and version.version_no <= max(
            item.version_no for item in prior_versions
        ):
            _reject_validation()
        if version.based_on_profile_version_id is not None:
            base = next(
                (
                    item
                    for item in prior_versions
                    if item.profile_version_id == version.based_on_profile_version_id
                ),
                None,
            )
            if base is None or base.version_no >= version.version_no:
                _reject_validation()
        elif version.version_no != 1:
            _reject_validation()

        mapping = _profile_content_mapping(version.content)
        _validate_content_mapping(mapping, for_publish=for_publish)
        expected_digest = profile_version_content_sha256(
            profile_id=version.profile_id,
            version_no=version.version_no,
            taxonomy_bundle_id=version.taxonomy_bundle_id,
            content=version.content,
        )
        if not hmac.compare_digest(expected_digest, version.content_sha256):
            _reject_validation()

        if version.status is ProfileVersionStatus.DRAFT:
            if (
                version.confirmed_by_user_id is not None
                or version.confirmed_at is not None
                or version.confirmed_evidence_versions
            ):
                _reject_validation()
        elif version.status in (
            ProfileVersionStatus.PUBLISHED,
            ProfileVersionStatus.SUPERSEDED,
            ProfileVersionStatus.RETIRED,
        ):
            if version.confirmed_by_user_id is None or version.confirmed_at is None:
                _reject_validation()
            _require_opaque_id(version.confirmed_by_user_id)
            if version.confirmed_by_user_id != profile.owner_user_id:
                _reject_validation()
            _require_utc(version.confirmed_at)
            if version.confirmed_at < version.asserted_at or version.confirmed_at > server_now:
                _reject_validation()
        elif version.status is ProfileVersionStatus.DISCARDED:
            if (
                version.confirmed_by_user_id is not None
                or version.confirmed_at is not None
                or version.confirmed_evidence_versions
            ):
                _reject_validation()
        else:
            _reject_validation()
        evidence_ids = _content_evidence_ids(mapping)
        confirmed_ids: list[str] = []
        for item in version.confirmed_evidence_versions:
            if not isinstance(item, tuple) or len(item) != 3:
                _reject_validation()
            evidence_id, evidence_version, safe_state = item
            _require_opaque_id(evidence_id)
            _require_positive_int(evidence_version, maximum=2_147_483_647)
            if (
                not isinstance(safe_state, str)
                or not safe_state
                or len(safe_state) > 128
            ):
                _reject_validation()
            confirmed_ids.append(evidence_id)
        _require_unique_sorted(confirmed_ids)
        if version.status in (
            ProfileVersionStatus.PUBLISHED,
            ProfileVersionStatus.SUPERSEDED,
            ProfileVersionStatus.RETIRED,
        ) and set(confirmed_ids) != evidence_ids:
            _reject_validation()
    except CreatorProfileDomainError:
        raise
    except Exception:
        _reject_validation()


def canonical_profile_version_bytes(
    *,
    profile_id: str,
    version_no: int,
    taxonomy_bundle_id: str,
    content: ProfileContent,
) -> bytes:
    try:
        _require_opaque_id(profile_id)
        _require_positive_int(version_no, maximum=2_147_483_647)
        _require_opaque_id(taxonomy_bundle_id)
        mapping = _profile_content_mapping(content)
        # v1 excludes floats and limits all member names to the ASCII contract.
        # For that closed subset these JSON settings are the RFC 8785 encoding.
        return json.dumps(
            {
                "canonicalization_version": "profile-version-json-v1",
                "content": mapping,
                "profile_id": profile_id,
                "profile_schema_version": 1,
                "taxonomy_bundle_id": taxonomy_bundle_id,
                "version_no": version_no,
            },
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except CreatorProfileDomainError:
        raise
    except Exception:
        _reject_validation()


def freeze_profile_content(
    value: Mapping[str, Any],
    *,
    for_publish: bool,
) -> ProfileContent:
    """Validate a closed v1 content object and return a deep immutable value."""

    try:
        frozen = _freeze_json_value(value)
        if not isinstance(frozen, ProfileContent):
            _reject_validation()
        mapping = _profile_content_mapping(frozen)
        _validate_content_mapping(mapping, for_publish=for_publish)
        return frozen
    except CreatorProfileDomainError:
        raise
    except Exception:
        _reject_validation()


def profile_version_content_sha256(
    *,
    profile_id: str,
    version_no: int,
    taxonomy_bundle_id: str,
    content: ProfileContent,
) -> str:
    return hashlib.sha256(
        canonical_profile_version_bytes(
            profile_id=profile_id,
            version_no=version_no,
            taxonomy_bundle_id=taxonomy_bundle_id,
            content=content,
        )
    ).hexdigest()


def is_profile_field_effective(
    *,
    expires_at: Optional[datetime],
    server_now: datetime,
) -> bool:
    _require_utc(server_now)
    if expires_at is None:
        return True
    _require_utc(expires_at)
    return expires_at > server_now


def require_profile_version_immutable(
    *,
    before: ProfileVersion,
    after: ProfileVersion,
) -> None:
    immutable_before = replace(before, status=ProfileVersionStatus.PUBLISHED)
    immutable_after = replace(after, status=ProfileVersionStatus.PUBLISHED)
    allowed_statuses = {
        ProfileVersionStatus.PUBLISHED: {
            ProfileVersionStatus.PUBLISHED,
            ProfileVersionStatus.SUPERSEDED,
            ProfileVersionStatus.RETIRED,
        },
        ProfileVersionStatus.SUPERSEDED: {ProfileVersionStatus.SUPERSEDED},
        ProfileVersionStatus.RETIRED: {ProfileVersionStatus.RETIRED},
    }
    if (
        before.status not in allowed_statuses
        or after.status not in allowed_statuses[before.status]
        or immutable_before != immutable_after
    ):
        _reject_state()


_OPAQUE_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{15,127}")
_TAXONOMY_CODE_RE = re.compile(r"[A-Z][A-Z0-9_.:-]{1,63}")
_REGION_RE = re.compile(r"[A-Z0-9][A-Z0-9_-]{1,31}")
_LANGUAGE_RE = re.compile(r"[A-Za-z]{2,3}(?:-[A-Za-z0-9]{2,8})*")


def _reject_validation() -> None:
    raise CreatorProfileDomainError("PROFILE_VALIDATION_FAILED")


def _reject_state() -> None:
    raise CreatorProfileDomainError("INVALID_STATE_TRANSITION")


def _require_utc(value: datetime) -> None:
    if (
        value.tzinfo is None
        or value.utcoffset() is None
        or value.utcoffset() != timedelta(0)
    ):
        _reject_validation()


def _require_opaque_id(value: Any) -> None:
    if not isinstance(value, str) or _OPAQUE_ID_RE.fullmatch(value) is None:
        _reject_validation()


def _require_nfc_string(value: Any) -> str:
    if not isinstance(value, str) or unicodedata.normalize("NFC", value) != value:
        _reject_validation()
    return value


def _require_int(value: Any, *, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        _reject_validation()
    if value < minimum or value > maximum:
        _reject_validation()
    return value


def _require_positive_int(value: Any, *, maximum: int) -> int:
    return _require_int(value, minimum=1, maximum=maximum)


def _require_code(value: Any) -> str:
    value = _require_nfc_string(value)
    if _TAXONOMY_CODE_RE.fullmatch(value) is None:
        _reject_validation()
    return value


def _profile_content_mapping(content: ProfileContent) -> dict[str, Any]:
    if not isinstance(content, ProfileContent):
        _reject_validation()
    return _thaw_object(content)


def _thaw_object(value: ProfileContent) -> dict[str, Any]:
    if not isinstance(value.members, tuple):
        _reject_validation()
    result: dict[str, Any] = {}
    for member in value.members:
        if (
            not isinstance(member, tuple)
            or len(member) != 2
            or not isinstance(member[0], str)
            or member[0] in result
        ):
            _reject_validation()
        key = _require_nfc_string(member[0])
        result[key] = _thaw_value(member[1])
    return result


def _thaw_value(value: FrozenJson) -> Any:
    if isinstance(value, ProfileContent):
        return _thaw_object(value)
    if isinstance(value, tuple):
        return [_thaw_value(child) for child in value]
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, str):
        return _require_nfc_string(value)
    _reject_validation()


def _freeze_json_value(value: Any) -> FrozenJson:
    if isinstance(value, Mapping):
        members = []
        for key, child in value.items():
            if not isinstance(key, str):
                _reject_validation()
            members.append((_require_nfc_string(key), _freeze_json_value(child)))
        return ProfileContent(tuple(members))
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_json_value(child) for child in value)
    if value is None or isinstance(value, (bool, int, str)):
        if isinstance(value, str):
            return _require_nfc_string(value)
        return value
    _reject_validation()


def _require_object(
    value: Any,
    *,
    keys: Iterable[str],
) -> dict[str, Any]:
    expected = set(keys)
    if not isinstance(value, dict) or set(value) != expected:
        _reject_validation()
    return value


def _require_array(value: Any, *, maximum: int) -> list[Any]:
    if not isinstance(value, list) or len(value) > maximum:
        _reject_validation()
    return value


def _require_enum(value: Any, allowed: set[str]) -> str:
    if not isinstance(value, str) or value not in allowed:
        _reject_validation()
    return value


def _require_unique_sorted(values: list[str]) -> None:
    if len(values) != len(set(values)) or values != sorted(values):
        _reject_validation()


def _validate_source_metadata(
    item: dict[str, Any],
    *,
    visibilities: set[str],
) -> None:
    _require_enum(item["visibility"], visibilities)
    source = _require_enum(
        item["source_kind"],
        {"SELF_ASSERTED", "VERIFIED_EVIDENCE", "LEGACY_UNVERIFIED"},
    )
    evidence = _require_array(item["evidence_ids"], maximum=20)
    evidence_ids = []
    for evidence_id in evidence:
        _require_opaque_id(evidence_id)
        evidence_ids.append(evidence_id)
    _require_unique_sorted(evidence_ids)
    if (source == "VERIFIED_EVIDENCE") != bool(evidence_ids):
        _reject_validation()


def _validate_item(
    value: Any,
    *,
    business_keys: Iterable[str],
    visibilities: set[str],
) -> dict[str, Any]:
    keys = tuple(business_keys) + ("visibility", "source_kind", "evidence_ids")
    item = _require_object(value, keys=keys)
    _validate_source_metadata(item, visibilities=visibilities)
    return item


def _validate_content_mapping(content: dict[str, Any], *, for_publish: bool) -> None:
    _require_object(
        content,
        keys=(
            "interests",
            "skills",
            "availability",
            "collaboration",
            "compensation",
            "boundaries",
            "location",
            "conflicts",
            "ai",
        ),
    )

    interest_keys: list[tuple[str, str, str]] = []
    interest_tasks: set[str] = set()
    interest_domains: set[str] = set()
    interests = _require_array(content["interests"], maximum=50)
    for raw in interests:
        item = _validate_item(
            raw,
            business_keys=("problem_code", "domain_code", "task_code", "strength"),
            visibilities={"PRIVATE", "MATCH_ONLY"},
        )
        problem = _require_code(item["problem_code"])
        domain = _require_code(item["domain_code"])
        task = _require_code(item["task_code"])
        _require_int(item["strength"], minimum=0, maximum=4)
        interest_keys.append((problem, domain, task))
        interest_domains.add(domain)
        interest_tasks.add(task)
    if len(interest_keys) != len(set(interest_keys)) or interest_keys != sorted(interest_keys):
        _reject_validation()

    skill_codes: list[str] = []
    skills = _require_array(content["skills"], maximum=100)
    for raw in skills:
        item = _validate_item(
            raw,
            business_keys=("skill_code", "proficiency"),
            visibilities={"PRIVATE", "MATCH_ONLY", "PUBLIC"},
        )
        skill_codes.append(_require_code(item["skill_code"]))
        _require_int(item["proficiency"], minimum=0, maximum=4)
    _require_unique_sorted(skill_codes)

    availability = content["availability"]
    if availability is not None:
        item = _validate_item(
            availability,
            business_keys=("available_from", "weekly_hours", "duration_weeks", "timezone"),
            visibilities={"PRIVATE", "MATCH_ONLY"},
        )
        available_from = _require_nfc_string(item["available_from"])
        if not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", available_from):
            _reject_validation()
        try:
            date.fromisoformat(available_from)
        except ValueError:
            _reject_validation()
        _require_int(item["weekly_hours"], minimum=1, maximum=80)
        _require_int(item["duration_weeks"], minimum=1, maximum=104)
        timezone_name = _require_nfc_string(item["timezone"])
        if not 3 <= len(timezone_name) <= 64:
            _reject_validation()
        try:
            ZoneInfo(timezone_name)
        except (ZoneInfoNotFoundError, ValueError):
            _reject_validation()

    collaboration = _require_object(
        content["collaboration"],
        keys=("languages", "work_modes", "feedback_cadence", "team_preference"),
    )
    language_codes: list[str] = []
    for raw in _require_array(collaboration["languages"], maximum=20):
        item = _validate_item(
            raw,
            business_keys=("language_code",),
            visibilities={"PRIVATE", "MATCH_ONLY", "PUBLIC"},
        )
        code = _require_nfc_string(item["language_code"])
        if _LANGUAGE_RE.fullmatch(code) is None:
            _reject_validation()
        language_codes.append(code)
    _require_unique_sorted(language_codes)
    work_modes: list[str] = []
    for raw in _require_array(collaboration["work_modes"], maximum=3):
        item = _validate_item(
            raw,
            business_keys=("work_mode",),
            visibilities={"PRIVATE", "MATCH_ONLY", "PUBLIC"},
        )
        work_modes.append(_require_enum(item["work_mode"], {"REMOTE", "HYBRID", "ONSITE"}))
    _require_unique_sorted(work_modes)
    if collaboration["feedback_cadence"] is not None:
        item = _validate_item(
            collaboration["feedback_cadence"],
            business_keys=("feedback_cadence",),
            visibilities={"PRIVATE", "MATCH_ONLY", "PUBLIC"},
        )
        _require_enum(item["feedback_cadence"], {"ASYNC", "DAILY", "TWICE_WEEKLY", "WEEKLY"})
    if collaboration["team_preference"] is not None:
        item = _validate_item(
            collaboration["team_preference"],
            business_keys=("team_preference",),
            visibilities={"PRIVATE", "MATCH_ONLY", "PUBLIC"},
        )
        _require_enum(item["team_preference"], {"SOLO", "PAIR", "SMALL_TEAM", "ANY"})

    compensation = content["compensation"]
    if compensation is not None:
        item = _validate_item(
            compensation,
            business_keys=("minimum_project_amount_minor", "currency", "direct_cost_amount_minor"),
            visibilities={"PRIVATE"},
        )
        _require_int(item["minimum_project_amount_minor"], minimum=0, maximum=9_007_199_254_740_991)
        _require_int(item["direct_cost_amount_minor"], minimum=0, maximum=9_007_199_254_740_991)
        currency = _require_nfc_string(item["currency"])
        if re.fullmatch(r"[A-Z]{3}", currency) is None:
            _reject_validation()

    prohibited_domains: list[str] = []
    prohibited_tasks: list[str] = []
    boundaries = content["boundaries"]
    if boundaries is not None:
        boundary = _require_object(
            boundaries,
            keys=("prohibited_domains", "prohibited_tasks", "allowed_data_sensitivity"),
        )
        for raw in _require_array(boundary["prohibited_domains"], maximum=100):
            item = _validate_item(raw, business_keys=("code",), visibilities={"PRIVATE"})
            prohibited_domains.append(_require_code(item["code"]))
        _require_unique_sorted(prohibited_domains)
        for raw in _require_array(boundary["prohibited_tasks"], maximum=100):
            item = _validate_item(raw, business_keys=("code",), visibilities={"PRIVATE"})
            prohibited_tasks.append(_require_code(item["code"]))
        _require_unique_sorted(prohibited_tasks)
        sensitivity = _validate_item(
            boundary["allowed_data_sensitivity"],
            business_keys=("data_sensitivity",),
            visibilities={"PRIVATE"},
        )
        _require_enum(sensitivity["data_sensitivity"], {"PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"})

    location = content["location"]
    if location is not None:
        item = _validate_item(
            location,
            business_keys=("region_code",),
            visibilities={"PRIVATE", "MATCH_ONLY", "PUBLIC"},
        )
        region = _require_nfc_string(item["region_code"])
        if _REGION_RE.fullmatch(region) is None:
            _reject_validation()

    conflict_ids: list[str] = []
    for raw in _require_array(content["conflicts"], maximum=100):
        item = _validate_item(raw, business_keys=("organization_id",), visibilities={"PRIVATE"})
        _require_opaque_id(item["organization_id"])
        conflict_ids.append(item["organization_id"])
    _require_unique_sorted(conflict_ids)

    ai = content["ai"]
    if ai is not None:
        item = _validate_item(
            ai,
            business_keys=("allowed", "requires_ai", "human_review_code", "prohibited_case_codes"),
            visibilities={"PRIVATE", "MATCH_ONLY"},
        )
        if not isinstance(item["allowed"], bool) or not isinstance(item["requires_ai"], bool):
            _reject_validation()
        if item["requires_ai"] and not item["allowed"]:
            _reject_validation()
        _require_enum(item["human_review_code"], {"NONE", "AS_NEEDED", "REQUIRED"})
        prohibited_cases = [
            _require_code(value)
            for value in _require_array(item["prohibited_case_codes"], maximum=50)
        ]
        _require_unique_sorted(prohibited_cases)

    if interest_tasks.intersection(prohibited_tasks) or interest_domains.intersection(prohibited_domains):
        _reject_validation()
    if for_publish and (
        not interests or not skills or availability is None or boundaries is None
    ):
        _reject_validation()


def _content_evidence_ids(content: Mapping[str, Any]) -> set[str]:
    found: set[str] = set()

    def visit(value: Any) -> None:
        if isinstance(value, Mapping):
            evidence_ids = value.get("evidence_ids")
            if isinstance(evidence_ids, list):
                found.update(
                    item for item in evidence_ids if isinstance(item, str)
                )
            for child in value.values():
                visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)

    visit(content)
    return found


def _require_unique_version_chain(
    profile: CreatorProfile,
    versions: Tuple[ProfileVersion, ...],
) -> None:
    ids: set[str] = set()
    numbers: set[int] = set()
    for version in versions:
        if (
            not isinstance(version, ProfileVersion)
            or version.profile_id != profile.profile_id
            or version.profile_version_id in ids
            or version.version_no in numbers
        ):
            _reject_state()
        try:
            _require_opaque_id(version.profile_version_id)
            _require_positive_int(version.version_no, maximum=2_147_483_647)
            if not isinstance(version.status, ProfileVersionStatus):
                _reject_state()
            if version.based_on_profile_version_id is not None:
                _require_opaque_id(version.based_on_profile_version_id)
        except CreatorProfileDomainError:
            _reject_state()
        ids.add(version.profile_version_id)
        numbers.add(version.version_no)
    ordered = sorted(versions, key=lambda item: item.version_no)
    if [item.version_no for item in ordered] != list(range(1, len(ordered) + 1)):
        _reject_state()
    for index, version in enumerate(ordered):
        expected_base = None if index == 0 else ordered[index - 1].profile_version_id
        if version.based_on_profile_version_id != expected_base:
            _reject_state()
