"""Independent deterministic fixtures for Creator Profile Memory semantics.

The fakes expose every authority, hold, lock, write checkpoint, receipt, and
commit observation needed by the planned application implementation.  They do
not import or seed IAM aggregates and therefore cannot manufacture CREATOR
authority from a Profile fixture.
"""

from __future__ import annotations

from contextlib import AbstractContextManager
from copy import deepcopy
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
from typing import Any, Mapping, Optional

from desire_platform.creator_profile.application import (
    ArchiveCreatorProfileCommand,
    ArchiveCreatorProfileHandler,
    CreateCreatorProfileCommand,
    CreateCreatorProfileHandler,
    CreatorProfileActorContext,
    PauseCreatorProfileCommand,
    PauseCreatorProfileHandler,
    PublishCreatorProfileVersionCommand,
    PublishCreatorProfileVersionHandler,
    ResumeCreatorProfileCommand,
    ResumeCreatorProfileHandler,
    SaveCreatorProfileDraftCommand,
    SaveCreatorProfileDraftHandler,
)
from desire_platform.creator_profile.domain import (
    ArchiveReasonCode,
    CreatorProfile,
    CreatorProfileStatus,
    PauseReasonCode,
    ProfileContent,
    ProfileVersion,
    ProfileVersionStatus,
    profile_version_content_sha256,
)
from desire_platform.creator_profile.ports.commands import (
    CreatorProfileAuthority,
    CreatorProfileCommitOutcomeUnknownError,
    CreatorProfileHoldDecision,
    CreatorProfileSafetyHoldResult,
    CreatorProfileStorageUnavailableError,
)


UTC_NOW = datetime(2026, 8, 8, 10, 0, tzinfo=timezone.utc)
USER_ID = "user_creator_00000001"
OTHER_USER_ID = "user_creator_other_0001"
SESSION_ID = "session_creator_000001"
PROFILE_ID = "profile_creator_0000001"
VERSION_ID = "profile_version_000001"
SECOND_VERSION_ID = "profile_version_000002"
TAXONOMY_ID = "taxonomy_bundle_000001"
CREATOR_GRANT_ID = "creator_grant_0000001"
POLICY_BUNDLE_ID = "policy_bundle_creator_01"
IDEMPOTENCY_KEY = "profile-command-key-00000001"
RAW_PRIVATE_SENTINELS = (
    "s3://private-evidence/creator/raw-object",
    "provider-token-private-0001",
    "creator@example.invalid",
    "legacy-private-profile-ref-0001",
    "profile-command-key-00000001",
)


def freeze_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        return ProfileContent(
            tuple((str(key), freeze_json(child)) for key, child in value.items())
        )
    if isinstance(value, list):
        return tuple(freeze_json(child) for child in value)
    if value is None or isinstance(value, (bool, int, str)):
        return value
    raise TypeError("test profile JSON contains an unsupported value")


def thaw_json(value: Any) -> Any:
    if isinstance(value, ProfileContent):
        return {key: thaw_json(child) for key, child in value.members}
    if isinstance(value, tuple):
        return [thaw_json(child) for child in value]
    return value


def valid_content_mapping() -> dict[str, Any]:
    metadata = {
        "visibility": "MATCH_ONLY",
        "source_kind": "SELF_ASSERTED",
        "evidence_ids": [],
    }
    private = {**metadata, "visibility": "PRIVATE"}
    return {
        "interests": [
            {
                "problem_code": "PROBLEM.CLIMATE",
                "domain_code": "DOMAIN.ENERGY",
                "task_code": "TASK.RESEARCH",
                "strength": 4,
                **metadata,
            }
        ],
        "skills": [
            {"skill_code": "SKILL.RESEARCH", "proficiency": 3, **metadata}
        ],
        "availability": {
            "available_from": "2026-08-09",
            "weekly_hours": 20,
            "duration_weeks": 12,
            "timezone": "Asia/Shanghai",
            **metadata,
        },
        "collaboration": {
            "languages": [{"language_code": "zh-CN", **metadata}],
            "work_modes": [{"work_mode": "REMOTE", **metadata}],
            "feedback_cadence": {"feedback_cadence": "WEEKLY", **metadata},
            "team_preference": {"team_preference": "SMALL_TEAM", **metadata},
        },
        "compensation": {
            "minimum_project_amount_minor": 100000,
            "currency": "CNY",
            "direct_cost_amount_minor": 20000,
            **private,
        },
        "boundaries": {
            "prohibited_domains": [{"code": "DOMAIN.GAMBLING", **private}],
            "prohibited_tasks": [{"code": "TASK.SURVEILLANCE", **private}],
            "allowed_data_sensitivity": {
                "data_sensitivity": "CONFIDENTIAL",
                **private,
            },
        },
        "location": {
            "region_code": "CN-SH",
            "visibility": "PUBLIC",
            "source_kind": "SELF_ASSERTED",
            "evidence_ids": [],
        },
        "conflicts": [
            {"organization_id": "organization_conflict_0001", **private}
        ],
        "ai": {
            "allowed": True,
            "requires_ai": False,
            "human_review_code": "REQUIRED",
            "prohibited_case_codes": ["AI.BIOMETRIC_SURVEILLANCE"],
            **metadata,
        },
    }


def valid_content() -> ProfileContent:
    return freeze_json(valid_content_mapping())


def creator_profile(
    *,
    status: CreatorProfileStatus = CreatorProfileStatus.DRAFT,
    aggregate_version: int = 1,
    current_draft_version_id: Optional[str] = None,
    current_published_version_id: Optional[str] = None,
    paused_at: Optional[datetime] = None,
    pause_reason_code: Optional[PauseReasonCode] = None,
    archived_at: Optional[datetime] = None,
    archive_reason_code: Optional[ArchiveReasonCode] = None,
    owner_user_id: str = USER_ID,
) -> CreatorProfile:
    return CreatorProfile(
        profile_id=PROFILE_ID,
        owner_user_id=owner_user_id,
        status=status,
        aggregate_version=aggregate_version,
        current_draft_version_id=current_draft_version_id,
        current_published_version_id=current_published_version_id,
        paused_at=paused_at,
        pause_reason_code=pause_reason_code,
        archived_at=archived_at,
        archive_reason_code=archive_reason_code,
        created_at=UTC_NOW - timedelta(days=1),
        updated_at=UTC_NOW,
    )


def profile_version(
    *,
    profile_version_id: str = VERSION_ID,
    version_no: int = 1,
    status: ProfileVersionStatus = ProfileVersionStatus.DRAFT,
    based_on_profile_version_id: Optional[str] = None,
    content: Optional[ProfileContent] = None,
    content_sha256: Optional[str] = None,
    confirmed: bool = False,
) -> ProfileVersion:
    content_value = content or valid_content()
    digest = content_sha256 or profile_version_content_sha256(
        profile_id=PROFILE_ID,
        version_no=version_no,
        taxonomy_bundle_id=TAXONOMY_ID,
        content=content_value,
    )
    return ProfileVersion(
        profile_version_id=profile_version_id,
        profile_id=PROFILE_ID,
        version_no=version_no,
        status=status,
        based_on_profile_version_id=based_on_profile_version_id,
        profile_schema_version=1,
        canonicalization_version="profile-version-json-v1",
        taxonomy_bundle_id=TAXONOMY_ID,
        content=content_value,
        content_sha256=digest,
        created_by_user_id=USER_ID,
        asserted_at=UTC_NOW - timedelta(minutes=5),
        confirmed_by_user_id=USER_ID if confirmed else None,
        confirmed_at=UTC_NOW if confirmed else None,
        confirmed_evidence_versions=(),
    )


def actor_context(*, actor_user_id: str = USER_ID) -> CreatorProfileActorContext:
    return CreatorProfileActorContext(
        actor_user_id=actor_user_id,
        session_id=SESSION_ID,
        correlation_id="correlation_profile_001",
        causation_id="causation_profile_0001",
        trace_id="trace_profile_00000001",
        original_actor_id=None,
    )


def valid_authority() -> CreatorProfileAuthority:
    return CreatorProfileAuthority(
        actor_user_id=USER_ID,
        session_id=SESSION_ID,
        user_status="ACTIVE",
        session_status="ACTIVE",
        session_family_status="ACTIVE",
        creator_grant_id=CREATOR_GRANT_ID,
        creator_grant_version=1,
        policy_selector_digest="b" * 64,
        policy_bundle_id=POLICY_BUNDLE_ID,
        policy_requirements_satisfied=True,
        authority_marker_sha256="c" * 64,
    )


class FixedClock:
    def __init__(self, now: datetime = UTC_NOW) -> None:
        self.value = now
        self.calls = 0

    def now(self) -> datetime:
        self.calls += 1
        return self.value


class ScriptedIdSource:
    def __init__(self) -> None:
        self.values = {
            "creator_profile": [PROFILE_ID],
            "profile_version": [SECOND_VERSION_ID],
            "command_receipt": ["profile_receipt_000001"],
            "audit_event": ["profile_audit_0000001"],
            "outbox_event": ["profile_event_0000001"],
        }
        self.calls: list[str] = []

    def new_id(self, kind: str) -> str:
        self.calls.append(kind)
        values = self.values.get(kind, [])
        if not values:
            raise AssertionError(f"unregistered ID kind: {kind}")
        return values.pop(0)


class DeterministicReceiptKeyring:
    idempotency_key_digest_key_id = "profile-idempotency-key-2026-01"
    payload_hash_key_id = "profile-payload-key-2026-01"

    def keyed_digest(self, key_id: str, value: bytes) -> str:
        key = ("test-key:" + key_id).encode("utf-8")
        return hmac.new(key, value, hashlib.sha256).hexdigest()


class RecordingValidator:
    def __init__(self) -> None:
        self.calls: list[tuple[str, Mapping[str, Any]]] = []

    def validate(self, value: Mapping[str, Any], schema_name: str) -> None:
        self.calls.append((schema_name, deepcopy(dict(value))))


class ScriptedAuthority:
    def __init__(self, result: Optional[CreatorProfileAuthority] = None) -> None:
        self.result = result or valid_authority()
        self.error: Optional[Exception] = None
        self.calls: list[tuple[CreatorProfileActorContext, str]] = []

    def authorize(
        self,
        *,
        actor: CreatorProfileActorContext,
        operation: str,
    ) -> CreatorProfileAuthority:
        self.calls.append((actor, operation))
        if self.error is not None:
            raise self.error
        return self.result


class ScriptedSafetyHold:
    def __init__(self) -> None:
        self.decision = CreatorProfileHoldDecision.ALLOW
        self.error: Optional[Exception] = None
        self.overrides: dict[str, Any] = {}
        self.calls: list[dict[str, Any]] = []

    def evaluate(self, **query: Any) -> CreatorProfileSafetyHoldResult:
        self.calls.append(deepcopy(query))
        if self.error is not None:
            raise self.error
        values = {
            "decision": self.decision,
            "profile_id": query["profile_id"],
            "prospective_aggregate_version": query[
                "prospective_aggregate_version"
            ],
            "content_sha256": query["content_sha256"],
            "actor_user_id": query["actor_user_id"],
            "policy_version": query["policy_version"],
            "evaluated_at": UTC_NOW,
            "valid_until": UTC_NOW + timedelta(seconds=30),
        }
        values.update(self.overrides)
        return CreatorProfileSafetyHoldResult(**values)


class InMemoryReadStore:
    def __init__(self, tables: Optional[Mapping[str, Mapping[str, Any]]] = None) -> None:
        self.tables = deepcopy(dict(tables or {}))

    def snapshot(self) -> Mapping[str, Mapping[str, Any]]:
        return deepcopy(self.tables)


class RecordingUnitOfWork:
    def __init__(self, factory: "RecordingUnitOfWorkFactory") -> None:
        self.factory = factory
        self.tables = deepcopy(factory.store.tables)

    def lock(self, resource: str, keys: list[str] | tuple[str, ...]) -> None:
        self.factory.lock_calls.append((resource, tuple(keys)))

    def get(self, collection: str, key: str) -> Any:
        return self.tables.get(collection, {}).get(key)

    def values(self, collection: str) -> tuple[Any, ...]:
        return tuple(self.tables.get(collection, {}).values())

    def put(
        self,
        collection: str,
        key: str,
        value: Any,
        *,
        checkpoint: str,
    ) -> None:
        self.factory.write_calls.append((collection, key, checkpoint))
        if checkpoint == self.factory.fail_checkpoint:
            raise CreatorProfileStorageUnavailableError("scripted write failure")
        self.tables.setdefault(collection, {})[key] = deepcopy(value)

    def commit(self) -> None:
        self.factory.commit_count += 1
        if self.factory.commit_unknown:
            if self.factory.commit_unknown_persists:
                self.factory.store.tables = deepcopy(self.tables)
            raise CreatorProfileCommitOutcomeUnknownError(
                "scripted unknown outcome"
            )
        self.factory.store.tables = deepcopy(self.tables)


class _UowContext(AbstractContextManager[RecordingUnitOfWork]):
    def __init__(self, factory: "RecordingUnitOfWorkFactory") -> None:
        self.factory = factory
        self.uow = RecordingUnitOfWork(factory)

    def __enter__(self) -> RecordingUnitOfWork:
        return self.uow

    def __exit__(self, exc_type, exc, traceback) -> None:
        if exc_type is not None:
            self.factory.rollback_count += 1
        return None


class RecordingUnitOfWorkFactory:
    def __init__(self, store: InMemoryReadStore) -> None:
        self.store = store
        self.begin_count = 0
        self.commit_count = 0
        self.rollback_count = 0
        self.lock_calls: list[tuple[str, tuple[str, ...]]] = []
        self.write_calls: list[tuple[str, str, str]] = []
        self.fail_checkpoint: Optional[str] = None
        self.commit_unknown = False
        self.commit_unknown_persists = False

    def begin(self) -> _UowContext:
        self.begin_count += 1
        return _UowContext(self)


@dataclass
class ProfileApplicationFixture:
    actor: CreatorProfileActorContext
    authority: ScriptedAuthority
    hold: ScriptedSafetyHold
    store: InMemoryReadStore
    uow_factory: RecordingUnitOfWorkFactory
    clock: FixedClock
    id_source: ScriptedIdSource
    keyring: DeterministicReceiptKeyring
    event_validator: RecordingValidator
    response_validator: RecordingValidator
    handlers: Mapping[str, Any]
    commands: Mapping[str, Any]


def application_fixture(
    operation: str = "pause",
) -> ProfileApplicationFixture:
    published = profile_version(
        status=ProfileVersionStatus.PUBLISHED,
        confirmed=True,
    )
    if operation == "create":
        root = None
        versions: dict[str, ProfileVersion] = {}
    elif operation == "publish":
        root = creator_profile(
            status=CreatorProfileStatus.DRAFT,
            aggregate_version=2,
            current_draft_version_id=VERSION_ID,
        )
        versions = {VERSION_ID: profile_version()}
    elif operation == "resume":
        root = creator_profile(
            status=CreatorProfileStatus.PAUSED,
            aggregate_version=2,
            current_published_version_id=VERSION_ID,
            paused_at=UTC_NOW - timedelta(minutes=1),
            pause_reason_code=PauseReasonCode.OWNER_REQUEST,
        )
        versions = {VERSION_ID: published}
    else:
        root = creator_profile(
            status=CreatorProfileStatus.ACTIVE,
            aggregate_version=2,
            current_published_version_id=VERSION_ID,
        )
        versions = {VERSION_ID: published}
    store = InMemoryReadStore(
        {
            "creator_profiles": ({PROFILE_ID: root} if root is not None else {}),
            "profile_versions": versions,
            "capability_evidence": {},
            "taxonomy_bundles": {
                TAXONOMY_ID: {
                    "taxonomy_bundle_id": TAXONOMY_ID,
                    "status": "ACTIVE",
                    "content_sha256": "d" * 64,
                }
            },
            "command_receipts": {},
            "audit_events": {},
            "outbox_events": {},
        }
    )
    authority = ScriptedAuthority()
    hold = ScriptedSafetyHold()
    uow_factory = RecordingUnitOfWorkFactory(store)
    clock = FixedClock()
    id_source = ScriptedIdSource()
    keyring = DeterministicReceiptKeyring()
    event_validator = RecordingValidator()
    response_validator = RecordingValidator()
    dependencies = {
        "authority": authority,
        "uow_factory": uow_factory,
        "clock": clock,
        "id_source": id_source,
        "receipt_keyring": keyring,
        "event_validator": event_validator,
        "safe_response_validator": response_validator,
        "safety_hold": hold,
        "safety_hold_policy_version": "creator-profile-hold-v1",
    }
    handlers = {
        "create": CreateCreatorProfileHandler(**dependencies),
        "save": SaveCreatorProfileDraftHandler(**dependencies),
        "publish": PublishCreatorProfileVersionHandler(**dependencies),
        "pause": PauseCreatorProfileHandler(**dependencies),
        "resume": ResumeCreatorProfileHandler(**dependencies),
        "archive": ArchiveCreatorProfileHandler(**dependencies),
    }
    commands = {
        "create": CreateCreatorProfileCommand(idempotency_key=IDEMPOTENCY_KEY),
        "save": SaveCreatorProfileDraftCommand(
            profile_id=PROFILE_ID,
            expected_version=2,
            taxonomy_bundle_id=TAXONOMY_ID,
            based_on_profile_version_id=VERSION_ID,
            content=valid_content(),
            idempotency_key=IDEMPOTENCY_KEY,
        ),
        "publish": PublishCreatorProfileVersionCommand(
            profile_id=PROFILE_ID,
            profile_version_id=VERSION_ID,
            expected_version=2,
            confirmed=True,
            idempotency_key=IDEMPOTENCY_KEY,
        ),
        "pause": PauseCreatorProfileCommand(
            profile_id=PROFILE_ID,
            expected_version=2,
            reason_code=PauseReasonCode.OWNER_REQUEST,
            idempotency_key=IDEMPOTENCY_KEY,
        ),
        "resume": ResumeCreatorProfileCommand(
            profile_id=PROFILE_ID,
            expected_version=2,
            idempotency_key=IDEMPOTENCY_KEY,
        ),
        "archive": ArchiveCreatorProfileCommand(
            profile_id=PROFILE_ID,
            expected_version=2,
            reason_code=ArchiveReasonCode.OWNER_REQUEST,
            idempotency_key=IDEMPOTENCY_KEY,
        ),
    }
    return ProfileApplicationFixture(
        actor=actor_context(),
        authority=authority,
        hold=hold,
        store=store,
        uow_factory=uow_factory,
        clock=clock,
        id_source=id_source,
        keyring=keyring,
        event_validator=event_validator,
        response_validator=response_validator,
        handlers=handlers,
        commands=commands,
    )


def replace_authority(
    fixture: ProfileApplicationFixture,
    **changes: Any,
) -> None:
    fixture.authority.result = replace(fixture.authority.result, **changes)
