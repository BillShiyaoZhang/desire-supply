"""Independent strict fixtures for IAM authority-lifecycle semantic RED tests."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import re
from typing import Any, Mapping, Optional, Sequence

import yaml

from desire_platform.identity_access.application.authority_lifecycle import (
    ResumeMembershipHandler,
    RevokeAccessInvitationHandler,
    RevokeMembershipHandler,
    RevokeReplayedSessionFamilyHandler,
    RevokeSessionHandler,
    SuspendMembershipHandler,
    WithdrawConsentGrantHandler,
)
from desire_platform.identity_access.domain.authority_lifecycle import (
    LifecycleActorContext,
    LifecycleReason,
    ResumeMembershipCommand,
    RevokeAccessInvitationCommand,
    RevokeMembershipCommand,
    RevokeReplayedSessionFamilyCommand,
    RevokeSessionCommand,
    SuspendMembershipCommand,
    WithdrawConsentGrantCommand,
)
from desire_platform.identity_access.domain.errors import IamError
from desire_platform.identity_access.ports.authority_lifecycle import (
    LifecycleCommitOutcomeUnknownError,
    LifecycleStorageUnavailableError,
)
from desire_platform.identity_access.ports.safety_hold import (
    HoldDecision,
    SafetyHoldDecisionResult,
)


PLATFORM_ROOT = Path(__file__).resolve().parents[2]
EVENT_SCHEMA_PATH = PLATFORM_ROOT / "contracts" / "events" / "iam-v1.schema.json"
OPENAPI_PATH = PLATFORM_ROOT / "contracts" / "api" / "iam-v1.openapi.yaml"

NOW = datetime(2026, 8, 8, 9, 0, tzinfo=timezone.utc)
ACTOR_USER_ID = "user_admin_000001"
ACTOR_FAMILY_ID = "family_admin_00001"
ACTOR_SESSION_ID = "session_admin_0001"
ORGANIZATION_ID = "organization_0001"
ACTOR_MEMBERSHIP_ID = "membership_admin_01"
ACTOR_ROLE_GRANT_ID = "role_grant_admin_1"
TARGET_MEMBERSHIP_ID = "membership_target_1"
TARGET_ROLE_GRANT_ID = "role_grant_target1"
SECOND_ADMIN_MEMBERSHIP_ID = "membership_admin_02"
SECOND_ADMIN_ROLE_GRANT_ID = "role_grant_admin_2"
INVITATION_ID = "invitation_target1"
CONSENT_GRANT_ID = "consent_grant_0001"
TARGET_SESSION_ID = "session_target_0001"
TARGET_FAMILY_ID = "family_target_0001"
REPLAYED_SESSION_ID = "session_replayed_01"
POLICY_BUNDLE_ID = "policy_bundle_0001"
SELECTOR_DIGEST = "a" * 64
IDEMPOTENCY_KEY = "idem_authority_00000001"
REASON_NOTE_SENTINEL = "private-reason-note-sentinel@example.test"
RAW_SESSION_SENTINEL = "raw-session-handle-secret-sentinel"
CONTACT_SENTINEL = "recipient-secret-sentinel@example.test"
TRACE_ID = "trace_authority_001"
HOLD_POLICY_VERSION = "safety-hold-v1"


class FixedClock:
    def __init__(self, current: datetime = NOW) -> None:
        self.current = current

    def now(self) -> datetime:
        return self.current


class FixedIdSource:
    def __init__(self) -> None:
        self.counter = 0
        self.calls: list[str] = []

    def new_id(self, kind: str) -> str:
        self.counter += 1
        self.calls.append(kind)
        return f"{kind}_{self.counter:08d}"


class StrictLifecycleKeyring:
    idempotency_key_digest_key_id = "lifecycle-idempotency-key-0001"
    payload_hash_key_id = "lifecycle-payload-key-000001"
    session_handle_digest_key_id = "session-handle-key-00000001"
    csrf_key_id = "session-csrf-key-0000000001"

    def __init__(self) -> None:
        self.material = {
            self.idempotency_key_digest_key_id: b"i" * 32,
            self.payload_hash_key_id: b"p" * 32,
            self.session_handle_digest_key_id: b"s" * 32,
            self.csrf_key_id: b"c" * 32,
        }

    def get_key(self, key_id: str) -> bytes:
        try:
            return self.material[key_id]
        except KeyError as error:
            raise KeyError("synthetic lifecycle key unavailable") from error


class ConfigurableSafetyHold:
    def __init__(
        self,
        *,
        decision: HoldDecision = HoldDecision.ALLOW,
        overrides: Optional[Mapping[str, Any]] = None,
    ) -> None:
        self.decision = decision
        self.overrides = dict(overrides or {})
        self.calls: list[dict[str, Any]] = []
        self.after_evaluate = None

    def evaluate(self, **query: Any) -> SafetyHoldDecisionResult:
        self.calls.append(dict(query))
        values = {
            "decision": self.decision,
            "action": query["action"],
            "target_type": query["target_type"],
            "target_id": query["target_id"],
            "target_version": query["target_version"],
            "organization_id": query.get("organization_id"),
            "policy_version": query["policy_version"],
            "evaluated_at": NOW - timedelta(seconds=1),
            "valid_until": NOW + timedelta(minutes=1),
        }
        values.update(self.overrides)
        result = SafetyHoldDecisionResult(**values)
        if self.after_evaluate is not None:
            self.after_evaluate(len(self.calls), dict(query))
        return result


class StrictLifecycleStore:
    def __init__(self, tables: Mapping[str, Mapping[str, Any]]) -> None:
        self._tables = deepcopy(dict(tables))

    def snapshot(self) -> dict[str, dict[str, Any]]:
        return deepcopy(self._tables)

    def replace_fact(self, table: str, key: str, **changes: Any) -> None:
        fact = deepcopy(self._tables[table][key])
        fact.update(changes)
        self._tables[table][key] = fact


class StrictLifecycleUnitOfWorkFactory:
    def __init__(
        self,
        *,
        store: StrictLifecycleStore,
        fail_on_checkpoint: Optional[str] = None,
        commit_mode: str = "normal",
    ) -> None:
        self.store = store
        self.fail_on_checkpoint = fail_on_checkpoint
        self.commit_mode = commit_mode
        self.begin_count = 0
        self.lock_calls: list[tuple[str, tuple[str, ...]]] = []
        self.write_checkpoints: list[str] = []
        self.commit_count = 0

    def begin(self) -> "StrictLifecycleUnitOfWork":
        self.begin_count += 1
        return StrictLifecycleUnitOfWork(self)


class StrictLifecycleUnitOfWork:
    def __init__(self, factory: StrictLifecycleUnitOfWorkFactory) -> None:
        self.factory = factory
        self.tables = factory.store.snapshot()
        self.committed = False

    def __enter__(self) -> "StrictLifecycleUnitOfWork":
        return self

    def __exit__(self, exception_type, exception, traceback) -> bool:
        return False

    def lock(self, table: str, keys: Sequence[str]) -> None:
        normalized = tuple(keys)
        if tuple(sorted(normalized)) != normalized and len(normalized) > 1:
            raise AssertionError("same-level lifecycle locks must be sorted")
        self.factory.lock_calls.append((table, normalized))

    def get(self, table: str, key: str) -> Any:
        return self.tables.get(table, {}).get(key)

    def values(self, table: str) -> Sequence[Any]:
        return tuple(self.tables.get(table, {}).values())

    def put(self, table: str, key: str, value: Any, *, checkpoint: str) -> None:
        self.factory.write_checkpoints.append(checkpoint)
        if checkpoint == self.factory.fail_on_checkpoint:
            raise LifecycleStorageUnavailableError("synthetic lifecycle storage fault")
        self.tables.setdefault(table, {})[key] = deepcopy(value)

    def commit(self) -> None:
        self.factory.commit_count += 1
        if self.factory.commit_mode == "unavailable":
            raise LifecycleStorageUnavailableError("synthetic commit was not sent")
        if self.factory.commit_mode == "unknown_not_landed":
            raise LifecycleCommitOutcomeUnknownError("synthetic unknown commit")
        self.factory.store._tables = deepcopy(self.tables)
        self.committed = True
        if self.factory.commit_mode == "unknown_landed":
            raise LifecycleCommitOutcomeUnknownError("synthetic landed unknown commit")


class ClosedSchemaValidator:
    """Small validator for the JSON-Schema/OpenAPI vocabulary used by this slice."""

    def __init__(self, document: Mapping[str, Any], definitions_key: str) -> None:
        self.document = document
        self.definitions_key = definitions_key
        self.calls: list[tuple[Optional[str], Any]] = []

    @classmethod
    def for_events(cls) -> "ClosedSchemaValidator":
        return cls(json.loads(EVENT_SCHEMA_PATH.read_text()), "$defs")

    @classmethod
    def for_openapi(cls) -> "ClosedSchemaValidator":
        return cls(yaml.safe_load(OPENAPI_PATH.read_text()), "schemas")

    def validate(self, value: Any, schema_name: Optional[str] = None) -> None:
        self.calls.append((schema_name, deepcopy(value)))
        if schema_name is None:
            schema = self.document
        elif self.definitions_key == "$defs":
            schema = self.document["$defs"][schema_name]
        else:
            schema = self.document["components"]["schemas"][schema_name]
        self._assert_valid(value, schema, path="$")

    def _resolve(self, reference: str) -> Mapping[str, Any]:
        node: Any = self.document
        for part in reference.removeprefix("#/").split("/"):
            node = node[part]
        return node

    def _assert_valid(self, value: Any, schema: Mapping[str, Any], *, path: str) -> None:
        if "$ref" in schema:
            self._assert_valid(value, self._resolve(schema["$ref"]), path=path)
        for index, child in enumerate(schema.get("allOf", ())):
            self._assert_valid(value, child, path=f"{path}.allOf[{index}]")
        if "oneOf" in schema:
            matches = 0
            for child in schema["oneOf"]:
                try:
                    self._assert_valid(value, child, path=path)
                except AssertionError:
                    pass
                else:
                    matches += 1
            if matches != 1:
                raise AssertionError(f"{path}: expected one oneOf match, got {matches}")
        if "const" in schema and value != schema["const"]:
            raise AssertionError(f"{path}: expected const {schema['const']!r}")
        if "enum" in schema and value not in schema["enum"]:
            raise AssertionError(f"{path}: value outside enum")
        expected_type = schema.get("type")
        if expected_type == "object" and not isinstance(value, dict):
            raise AssertionError(f"{path}: expected object")
        if expected_type == "array" and not isinstance(value, list):
            raise AssertionError(f"{path}: expected array")
        if expected_type == "string" and not isinstance(value, str):
            raise AssertionError(f"{path}: expected string")
        if expected_type == "integer" and (not isinstance(value, int) or isinstance(value, bool)):
            raise AssertionError(f"{path}: expected integer")
        if expected_type == "boolean" and not isinstance(value, bool):
            raise AssertionError(f"{path}: expected boolean")
        if expected_type == "null" and value is not None:
            raise AssertionError(f"{path}: expected null")
        if isinstance(value, dict):
            required = set(schema.get("required", ()))
            if not required.issubset(value):
                raise AssertionError(f"{path}: missing {sorted(required - set(value))}")
            properties = schema.get("properties", {})
            if schema.get("additionalProperties") is False and not set(value).issubset(properties):
                raise AssertionError(f"{path}: additional properties")
            for name, child in properties.items():
                if name in value:
                    self._assert_valid(value[name], child, path=f"{path}.{name}")
        if isinstance(value, list):
            if len(value) < schema.get("minItems", 0):
                raise AssertionError(f"{path}: too few items")
            if "maxItems" in schema and len(value) > schema["maxItems"]:
                raise AssertionError(f"{path}: too many items")
            if schema.get("uniqueItems"):
                encoded = [json.dumps(item, sort_keys=True) for item in value]
                if len(encoded) != len(set(encoded)):
                    raise AssertionError(f"{path}: duplicate items")
            for index, item in enumerate(value):
                self._assert_valid(item, schema.get("items", {}), path=f"{path}[{index}]")
        if isinstance(value, str):
            if len(value) < schema.get("minLength", 0):
                raise AssertionError(f"{path}: too short")
            if "maxLength" in schema and len(value) > schema["maxLength"]:
                raise AssertionError(f"{path}: too long")
            if "pattern" in schema and re.search(schema["pattern"], value) is None:
                raise AssertionError(f"{path}: pattern mismatch")


@dataclass
class LifecycleFixture:
    store: StrictLifecycleStore
    uow_factory: StrictLifecycleUnitOfWorkFactory
    handler: Any
    actor: LifecycleActorContext
    command: Any
    hold: ConfigurableSafetyHold
    event_validator: ClosedSchemaValidator
    response_validator: ClosedSchemaValidator


@dataclass(frozen=True)
class LifecycleObservation:
    error_code: Optional[str]
    escaped_exception: Optional[str]
    result: Any
    before: Mapping[str, Mapping[str, Any]]
    after: Mapping[str, Mapping[str, Any]]


def invoke_fixture(fixture: LifecycleFixture) -> LifecycleObservation:
    before = fixture.store.snapshot()
    try:
        if isinstance(fixture.command, RevokeReplayedSessionFamilyCommand):
            result = fixture.handler.handle(command=fixture.command)
        else:
            result = fixture.handler.handle(actor=fixture.actor, command=fixture.command)
    except IamError as error:
        return LifecycleObservation(
            error_code=error.code,
            escaped_exception=None,
            result=None,
            before=before,
            after=fixture.store.snapshot(),
        )
    except Exception as error:  # semantic tests report a value, never a fixture ERROR
        return LifecycleObservation(
            error_code=None,
            escaped_exception=type(error).__name__,
            result=None,
            before=before,
            after=fixture.store.snapshot(),
        )
    return LifecycleObservation(
        error_code=None,
        escaped_exception=None,
        result=result,
        before=before,
        after=fixture.store.snapshot(),
    )


def _base_tables() -> dict[str, dict[str, Any]]:
    return {
        "users": {
            ACTOR_USER_ID: {
                "user_id": ACTOR_USER_ID,
                "status": "ACTIVE",
                "aggregate_version": 3,
            },
            "user_target_00001": {
                "user_id": "user_target_00001",
                "status": "ACTIVE",
                "aggregate_version": 2,
            },
        },
        "organizations": {
            ORGANIZATION_ID: {
                "organization_id": ORGANIZATION_ID,
                "public_name": "Synthetic Organization",
                "status": "ACTIVE",
                "aggregate_version": 4,
            },
            "organization_other1": {
                "organization_id": "organization_other1",
                "public_name": "Other Synthetic Organization",
                "status": "ACTIVE",
                "aggregate_version": 2,
            },
        },
        "session_families": {
            ACTOR_FAMILY_ID: {
                "session_family_id": ACTOR_FAMILY_ID,
                "user_id": ACTOR_USER_ID,
                "status": "ACTIVE",
                "current_generation": 2,
                "aggregate_version": 2,
            },
            TARGET_FAMILY_ID: {
                "session_family_id": TARGET_FAMILY_ID,
                "user_id": ACTOR_USER_ID,
                "status": "ACTIVE",
                "current_generation": 1,
                "aggregate_version": 1,
            },
        },
        "sessions": {
            ACTOR_SESSION_ID: _session_fact(
                ACTOR_SESSION_ID,
                ACTOR_FAMILY_ID,
                generation=2,
                is_current=True,
            ),
            TARGET_SESSION_ID: _session_fact(
                TARGET_SESSION_ID,
                TARGET_FAMILY_ID,
                generation=1,
                is_current=False,
            ),
        },
        "memberships": {
            ACTOR_MEMBERSHIP_ID: _membership_fact(
                ACTOR_MEMBERSHIP_ID,
                ACTOR_USER_ID,
                "ACTIVE",
                display_handle="admin_actor",
            ),
            TARGET_MEMBERSHIP_ID: _membership_fact(
                TARGET_MEMBERSHIP_ID,
                "user_target_00001",
                "ACTIVE",
                display_handle="target_member",
            ),
            SECOND_ADMIN_MEMBERSHIP_ID: _membership_fact(
                SECOND_ADMIN_MEMBERSHIP_ID,
                "user_second_admin1",
                "ACTIVE",
                display_handle="second_admin",
            ),
        },
        "membership_role_grants": {
            ACTOR_ROLE_GRANT_ID: _role_fact(
                ACTOR_ROLE_GRANT_ID,
                ACTOR_MEMBERSHIP_ID,
                ACTOR_USER_ID,
                "ORG_ADMIN",
            ),
            TARGET_ROLE_GRANT_ID: _role_fact(
                TARGET_ROLE_GRANT_ID,
                TARGET_MEMBERSHIP_ID,
                "user_target_00001",
                "DEMAND_OWNER",
            ),
            SECOND_ADMIN_ROLE_GRANT_ID: _role_fact(
                SECOND_ADMIN_ROLE_GRANT_ID,
                SECOND_ADMIN_MEMBERSHIP_ID,
                "user_second_admin1",
                "ORG_ADMIN",
            ),
        },
        "invitations": {
            INVITATION_ID: {
                "invitation_id": INVITATION_ID,
                "purpose": "ORGANIZATION_MEMBERSHIP",
                "organization_id": ORGANIZATION_ID,
                "target_scope": "ORGANIZATION",
                "target_role": "DEMAND_OWNER",
                "is_initial_admin": False,
                "recipient_contact_id": "contact_target_0001",
                "masked_recipient_label": "t***@example.test",
                "policy_selector_digest": SELECTOR_DIGEST,
                "issued_policy_bundle_id": POLICY_BUNDLE_ID,
                "required_policy_bundle_id": POLICY_BUNDLE_ID,
                "status": "ISSUED",
                "expires_at": NOW + timedelta(days=2),
                "created_at": NOW - timedelta(days=1),
                "issuer_kind": "USER",
                "issuer_user_id": "user_other_admin01",
                "aggregate_version": 1,
            }
        },
        "policy_selectors": {
            SELECTOR_DIGEST: {
                "selector_digest": SELECTOR_DIGEST,
                "current_bundle_id": POLICY_BUNDLE_ID,
                "aggregate_version": 2,
            }
        },
        "policy_bundles": {
            POLICY_BUNDLE_ID: {
                "policy_bundle_id": POLICY_BUNDLE_ID,
                "selector_digest": SELECTOR_DIGEST,
                "status": "ACTIVE",
                "effective_at": NOW - timedelta(days=1),
                "effective_until": None,
            }
        },
        "consent_grants": {
            CONSENT_GRANT_ID: {
                "consent_grant_id": CONSENT_GRANT_ID,
                "user_id": ACTOR_USER_ID,
                "consent_offer_id": "consent_offer_0001",
                "consent_offer_version": 1,
                "policy_bundle_id": POLICY_BUNDLE_ID,
                "purpose": "PILOT_RESEARCH",
                "scope_type": "PLATFORM_PARTICIPATION",
                "scope_id": None,
                "data_categories": ["PROFILE", "MATCHING", "RESEARCH"],
                "recipient_ref": "internal-controller-reference",
                "recipient_label": "Synthetic Research Controller",
                "document_id": "policy_document_01",
                "content_sha256": "b" * 64,
                "granted_at": NOW - timedelta(days=10),
                "expires_at": NOW + timedelta(days=100),
                "status": "ACTIVE",
                "aggregate_version": 1,
            }
        },
        "consent_withdrawals": {},
        "command_receipts": {},
        "audit_events": {},
        "outbox_events": {},
        "security_events": {},
    }


def _session_fact(
    session_id: str,
    family_id: str,
    *,
    generation: int,
    is_current: bool,
) -> dict[str, Any]:
    return {
        "session_id": session_id,
        "session_family_id": family_id,
        "user_id": ACTOR_USER_ID,
        "generation": generation,
        "status": "ACTIVE",
        "auth_time": NOW - timedelta(minutes=2),
        "acr_code": "urn:synthetic:acr:mfa",
        "amr_codes": ("pwd", "otp"),
        "created_at": NOW - timedelta(minutes=5),
        "last_activity_at": NOW - timedelta(seconds=10),
        "idle_expires_at": NOW + timedelta(minutes=25),
        "absolute_expires_at": NOW + timedelta(hours=11),
        "handle_digest_key_id": StrictLifecycleKeyring.session_handle_digest_key_id,
        "csrf_key_id": StrictLifecycleKeyring.csrf_key_id,
        "device_label": "Browser",
        "is_current": is_current,
        "aggregate_version": generation,
    }


def _membership_fact(
    membership_id: str,
    user_id: str,
    status: str,
    *,
    display_handle: str,
) -> dict[str, Any]:
    return {
        "membership_id": membership_id,
        "organization_id": ORGANIZATION_ID,
        "user_id": user_id,
        "display_handle": display_handle,
        "status": status,
        "aggregate_version": 2,
    }


def _role_fact(
    grant_id: str,
    membership_id: str,
    user_id: str,
    role_code: str,
) -> dict[str, Any]:
    return {
        "membership_role_grant_id": grant_id,
        "organization_id": ORGANIZATION_ID,
        "membership_id": membership_id,
        "user_id": user_id,
        "role_code": role_code,
        "revoked_at": None,
        "aggregate_version": 1,
    }


def _actor() -> LifecycleActorContext:
    return LifecycleActorContext(
        actor_user_id=ACTOR_USER_ID,
        current_session_id=ACTOR_SESSION_ID,
        original_actor_id=None,
        correlation_id="correlation_auth_01",
        causation_id="causation_auth_001",
        trace_id=TRACE_ID,
    )


def _fixture(
    handler_type: Any,
    command: Any,
    *,
    tables: Optional[Mapping[str, Mapping[str, Any]]] = None,
    hold: Optional[ConfigurableSafetyHold] = None,
    fail_on_checkpoint: Optional[str] = None,
    commit_mode: str = "normal",
) -> LifecycleFixture:
    store = StrictLifecycleStore(tables or _base_tables())
    uow_factory = StrictLifecycleUnitOfWorkFactory(
        store=store,
        fail_on_checkpoint=fail_on_checkpoint,
        commit_mode=commit_mode,
    )
    configured_hold = hold or ConfigurableSafetyHold()
    event_validator = ClosedSchemaValidator.for_events()
    response_validator = ClosedSchemaValidator.for_openapi()
    handler = handler_type(
        uow_factory=uow_factory,
        clock=FixedClock(),
        id_source=FixedIdSource(),
        keyring=StrictLifecycleKeyring(),
        event_validator=event_validator,
        safe_response_validator=response_validator,
        safety_hold=configured_hold,
        safety_hold_policy_version=HOLD_POLICY_VERSION,
    )
    return LifecycleFixture(
        store=store,
        uow_factory=uow_factory,
        handler=handler,
        actor=_actor(),
        command=command,
        hold=configured_hold,
        event_validator=event_validator,
        response_validator=response_validator,
    )


def invitation_revoke_fixture(**kwargs: Any) -> LifecycleFixture:
    return _fixture(
        RevokeAccessInvitationHandler,
        RevokeAccessInvitationCommand(
            invitation_id=INVITATION_ID,
            expected_version=1,
            idempotency_key=IDEMPOTENCY_KEY,
            reason=LifecycleReason("INVITATION_CANCELLED", REASON_NOTE_SENTINEL),
        ),
        **kwargs,
    )


def consent_withdraw_fixture(**kwargs: Any) -> LifecycleFixture:
    return _fixture(
        WithdrawConsentGrantHandler,
        WithdrawConsentGrantCommand(
            consent_grant_id=CONSENT_GRANT_ID,
            expected_version=1,
            idempotency_key=IDEMPOTENCY_KEY,
            reason=LifecycleReason("USER_WITHDREW_CONSENT", REASON_NOTE_SENTINEL),
        ),
        **kwargs,
    )


def session_revoke_fixture(*, current: bool = False, **kwargs: Any) -> LifecycleFixture:
    return _fixture(
        RevokeSessionHandler,
        RevokeSessionCommand(
            session_id=ACTOR_SESSION_ID if current else TARGET_SESSION_ID,
            idempotency_key=IDEMPOTENCY_KEY,
        ),
        **kwargs,
    )


def replayed_family_fixture(**kwargs: Any) -> LifecycleFixture:
    tables = _base_tables()
    tables["session_families"][TARGET_FAMILY_ID]["current_generation"] = 2
    tables["sessions"][TARGET_SESSION_ID]["generation"] = 2
    tables["sessions"][TARGET_SESSION_ID]["aggregate_version"] = 2
    tables["sessions"][REPLAYED_SESSION_ID] = {
        **_session_fact(REPLAYED_SESSION_ID, TARGET_FAMILY_ID, generation=1, is_current=False),
        "status": "REVOKED",
        "aggregate_version": 2,
    }
    return _fixture(
        RevokeReplayedSessionFamilyHandler,
        RevokeReplayedSessionFamilyCommand(
            security_event_id="security_event_0001",
            replayed_session_id=REPLAYED_SESSION_ID,
            session_family_id=TARGET_FAMILY_ID,
            user_id=ACTOR_USER_ID,
        ),
        tables=tables,
        **kwargs,
    )


def membership_fixture(action: str, **kwargs: Any) -> LifecycleFixture:
    tables = _base_tables()
    if action == "resume":
        tables["memberships"][TARGET_MEMBERSHIP_ID]["status"] = "SUSPENDED"
        handler_type = ResumeMembershipHandler
        command_type = ResumeMembershipCommand
    elif action == "suspend":
        handler_type = SuspendMembershipHandler
        command_type = SuspendMembershipCommand
    elif action == "revoke":
        handler_type = RevokeMembershipHandler
        command_type = RevokeMembershipCommand
    else:
        raise ValueError("unknown membership action")
    return _fixture(
        handler_type,
        command_type(
            membership_id=TARGET_MEMBERSHIP_ID,
            expected_version=2,
            idempotency_key=IDEMPOTENCY_KEY,
            reason=LifecycleReason("MEMBERSHIP_LIFECYCLE", REASON_NOTE_SENTINEL),
        ),
        tables=tables,
        **kwargs,
    )


def invitation_admin_dto(status: str = "REVOKED", version: int = 2) -> dict[str, Any]:
    return {
        "invitation_id": INVITATION_ID,
        "purpose": "ORGANIZATION_MEMBERSHIP",
        "organization_id": ORGANIZATION_ID,
        "target_role": "DEMAND_OWNER",
        "masked_recipient_label": "t***@example.test",
        "is_initial_admin": False,
        "status": status,
        "expires_at": "2026-08-10T09:00:00Z",
        "created_at": "2026-08-07T09:00:00Z",
        "required_policy_bundle_id": POLICY_BUNDLE_ID,
        "aggregate_version": version,
        "entity_tag": f'"v{version}"',
    }


def consent_grant_dto(status: str = "WITHDRAWN", version: int = 2) -> dict[str, Any]:
    return {
        "consent_grant_id": CONSENT_GRANT_ID,
        "consent_offer_id": "consent_offer_0001",
        "purpose": "PILOT_RESEARCH",
        "scope_type": "PLATFORM_PARTICIPATION",
        "scope_id": None,
        "data_categories": ["PROFILE", "MATCHING", "RESEARCH"],
        "recipient_label": "Synthetic Research Controller",
        "document_id": "policy_document_01",
        "content_sha256": "b" * 64,
        "granted_at": "2026-07-29T09:00:00Z",
        "expires_at": "2026-11-16T09:00:00Z",
        "status": status,
        "aggregate_version": version,
        "entity_tag": f'"v{version}"',
    }


def membership_admin_dto(status: str, roles: Sequence[str], version: int = 3) -> dict[str, Any]:
    return {
        "membership_id": TARGET_MEMBERSHIP_ID,
        "organization_id": ORGANIZATION_ID,
        "user_id": "user_target_00001",
        "display_handle": "target_member",
        "status": status,
        "roles": list(roles),
        "aggregate_version": version,
        "entity_tag": f'"v{version}"',
    }


def recursive_contains(value: Any, sentinel: str) -> bool:
    if isinstance(value, Mapping):
        return any(
            recursive_contains(key, sentinel) or recursive_contains(item, sentinel)
            for key, item in value.items()
        )
    if isinstance(value, (list, tuple, set)):
        return any(recursive_contains(item, sentinel) for item in value)
    if isinstance(value, bytes):
        return sentinel.encode() in value
    return sentinel in str(value)


def write_count(snapshot: Mapping[str, Mapping[str, Any]]) -> int:
    return sum(
        len(snapshot.get(table, {}))
        for table in ("command_receipts", "audit_events", "outbox_events", "consent_withdrawals")
    )


__all__ = [name for name in globals() if name.isupper() or name.endswith("_fixture")]
