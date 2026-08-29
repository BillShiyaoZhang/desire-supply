"""PostgreSQL composition repository for the internal-pilot editor.

The editor does not own another copy of Profile or Demand state.  Every write
is delegated to the existing role-bound canonical PostgreSQL unit of work,
which is responsible for its root/version graph, OCC, receipt, audit and
outbox transaction.  Read projection support is defined below without an
``internal_pilot`` business table or a second migration ledger.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import hmac
from typing import Any, Callable, Mapping, Optional, Tuple, Union
from uuid import UUID

import psycopg

from ...creator_profile.adapters.postgres import (
    CreatorProfilePostgresCommand,
    CreatorProfilePostgresOperation,
)
from ...creator_profile.adapters.postgres.migrations import (
    PROFILE_SCHEMA_HEAD_VERSION,
)
from ...demand.adapters.postgres import (
    DemandPostgresCommand,
    DemandPostgresOperation,
)
from ...demand.domain import DemandStatus
from ...demand.adapters.postgres.migrations import DEMAND_SCHEMA_HEAD_VERSION
from .contracts import (
    EditorFindingDto,
    EditorReviewAssignmentDto,
    EditorPrincipal,
    EditorResourceDto,
    EditorServiceError,
    EditorSubmissionDto,
    EditorVersionDto,
)


_PROFILE_EXECUTOR = {
    CreatorProfilePostgresOperation.CREATE: "execute_create",
    CreatorProfilePostgresOperation.SAVE_DRAFT: "execute_save_draft",
    CreatorProfilePostgresOperation.PUBLISH: "execute_publish",
    CreatorProfilePostgresOperation.PAUSE: "execute_pause",
    CreatorProfilePostgresOperation.RESUME: "execute_resume",
    CreatorProfilePostgresOperation.ARCHIVE: "execute_archive",
}

_PROFILE_AUTHORITY_OPERATION = {
    CreatorProfilePostgresOperation.CREATE: "CREATE_PROFILE",
    CreatorProfilePostgresOperation.SAVE_DRAFT: "SAVE_PROFILE_DRAFT",
    CreatorProfilePostgresOperation.PUBLISH: "PUBLISH_PROFILE",
    CreatorProfilePostgresOperation.PAUSE: "PAUSE_PROFILE",
    CreatorProfilePostgresOperation.RESUME: "RESUME_PROFILE",
    CreatorProfilePostgresOperation.ARCHIVE: "ARCHIVE_PROFILE",
}

_PROFILE_LIFECYCLE_OPERATIONS = frozenset(
    (
        CreatorProfilePostgresOperation.PAUSE,
        CreatorProfilePostgresOperation.RESUME,
        CreatorProfilePostgresOperation.ARCHIVE,
    )
)

_PROFILE_LIFECYCLE_STATUS = {
    CreatorProfilePostgresOperation.PAUSE: "PAUSED",
    CreatorProfilePostgresOperation.RESUME: "ACTIVE",
    CreatorProfilePostgresOperation.ARCHIVE: "ARCHIVED",
}

_DEMAND_EXECUTOR = {
    DemandPostgresOperation.CREATE: "execute_create",
    DemandPostgresOperation.CREATE_VERSION: "execute_create_version",
    DemandPostgresOperation.SUBMIT: "execute_submit",
    DemandPostgresOperation.REQUEST_CHANGES: "execute_request_changes",
    DemandPostgresOperation.VERIFY: "execute_verify",
    DemandPostgresOperation.RELEASE_REVIEW_ASSIGNMENT: (
        "execute_release_review_assignment"
    ),
    DemandPostgresOperation.APPLY_FUNDING_SECURED: "execute_apply_funding_secured",
    DemandPostgresOperation.REQUEST_MATCHING: "execute_request_matching",
    DemandPostgresOperation.CANCEL_OWNER: "execute_cancel_owner",
    DemandPostgresOperation.CANCEL_REVIEW: "execute_cancel_review",
    DemandPostgresOperation.EXPIRE: "execute_expire",
}

_DEMAND_AUTHORITY_OPERATION = {
    DemandPostgresOperation.CREATE: "CREATE",
    DemandPostgresOperation.CREATE_VERSION: "CREATE_VERSION",
    DemandPostgresOperation.SUBMIT: "SUBMIT",
    DemandPostgresOperation.REQUEST_CHANGES: "REQUEST_CHANGES",
    DemandPostgresOperation.VERIFY: "VERIFY",
    DemandPostgresOperation.RELEASE_REVIEW_ASSIGNMENT: (
        "RELEASE_REVIEW_ASSIGNMENT"
    ),
    DemandPostgresOperation.REQUEST_MATCHING: "REQUEST_MATCHING",
    DemandPostgresOperation.CANCEL_OWNER: "CANCEL_OWNER",
    DemandPostgresOperation.CANCEL_REVIEW: "CANCEL_REVIEW",
}

_DEMAND_OWNER_READ_OPERATIONS = frozenset(
    {
        DemandPostgresOperation.CREATE,
        DemandPostgresOperation.CREATE_VERSION,
        DemandPostgresOperation.SUBMIT,
        DemandPostgresOperation.CANCEL_OWNER,
    }
)
_DEMAND_REVIEW_READ_OPERATIONS = frozenset(
    {
        DemandPostgresOperation.REQUEST_CHANGES,
        DemandPostgresOperation.VERIFY,
        DemandPostgresOperation.RELEASE_REVIEW_ASSIGNMENT,
        DemandPostgresOperation.REQUEST_MATCHING,
        DemandPostgresOperation.CANCEL_REVIEW,
    }
)

_DEMAND_FIELD_PATH_BY_CODE = {
    "ACCEPTANCE": "/acceptance",
    "AI": "/ai",
    "BUDGET": "/budget",
    "COLLABORATION": "/collaboration",
    "DECLARATIONS": "/declarations",
    "LOCATION": "/location",
    "MATCHING": "/matching",
    "MILESTONE_PLAN": "/milestone_plan",
    "PROBLEM": "/problem",
    "RISK": "/risk",
    "SCHEDULE": "/schedule",
    "SCOPE": "/scope",
    "SKILLS": "/skills",
}
_DEMAND_REVIEW_REASON_CODES = frozenset(
    {
        "CONTENT_INCOMPLETE",
        "SCOPE_UNCLEAR",
        "ACCEPTANCE_UNCLEAR",
        "BUDGET_UNHEALTHY",
        "RISK_UNRESOLVED",
        "DATA_PLAN_REQUIRED",
    }
)
_FINANCE_DISCREPANCY_REASON_CODES = frozenset(
    {"EVIDENCE_REFERENCE_MISMATCH", "TARGET_CONTENT_MISMATCH"}
)
_FINANCE_REJECTED_REASON_CODES = frozenset(
    {
        "BUDGET_PLAN_UNACCEPTABLE",
        "DECLARATION_CONFLICT",
        "SYNTHETIC_SCOPE_VIOLATION",
    }
)

_PROFILE_EDITABLE_PATHS = (
    "/interests",
    "/skills",
    "/availability",
    "/collaboration",
    "/compensation",
    "/boundaries",
    "/location",
    "/conflicts",
    "/ai",
)
_DEMAND_EDITABLE_PATHS = (
    "/problem",
    "/scope",
    "/acceptance",
    "/skills",
    "/matching",
    "/schedule",
    "/budget",
    "/milestone_plan",
    "/risk",
    "/ai",
    "/collaboration",
    "/location",
    "/declarations",
)


class EditorPostgresConfigurationError(RuntimeError):
    """The role-bound pool, PostgreSQL major, or schema head is untrusted."""


class DemandCompletedVerifyReplayError(RuntimeError):
    """A completed VerifyDemand receipt cannot be safely replayed."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class DemandCompletedReleaseReplayError(RuntimeError):
    """A completed Demand assignment-release receipt cannot be replayed."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class DemandCompletedVerifyReplayProbeRequest:
    actor_user_id: UUID
    session_id: UUID
    command_id: UUID
    demand_id: UUID
    assignment_id: UUID
    expected_version: int
    idempotency_key: str = field(repr=False)
    canonical_payload: bytes = field(repr=False)

    def __post_init__(self) -> None:
        identities = (
            self.actor_user_id,
            self.session_id,
            self.command_id,
            self.demand_id,
            self.assignment_id,
        )
        if any(not isinstance(value, UUID) or value.int == 0 for value in identities):
            raise ValueError("Demand Verify replay identity is invalid")
        if (
            isinstance(self.expected_version, bool)
            or not isinstance(self.expected_version, int)
            or self.expected_version < 1
            or not isinstance(self.idempotency_key, str)
            or not self.idempotency_key
            or not isinstance(self.canonical_payload, bytes)
            or not self.canonical_payload
        ):
            raise ValueError("Demand Verify replay material is invalid")


@dataclass(frozen=True)
class DemandCompletedVerifyReplayResult:
    organization_id: UUID
    authority_marker_sha256: bytes = field(repr=False)
    aggregate_version: int
    demand_version_id: UUID

    def __post_init__(self) -> None:
        if (
            not isinstance(self.organization_id, UUID)
            or self.organization_id.int == 0
            or not isinstance(self.demand_version_id, UUID)
            or self.demand_version_id.int == 0
            or not isinstance(self.authority_marker_sha256, bytes)
            or len(self.authority_marker_sha256) != 32
            or isinstance(self.aggregate_version, bool)
            or not isinstance(self.aggregate_version, int)
            or self.aggregate_version < 1
        ):
            raise ValueError("Demand Verify replay result is invalid")


@dataclass(frozen=True)
class DemandCompletedReleaseReplayProbeRequest:
    actor_user_id: UUID
    session_id: UUID
    command_id: UUID
    demand_id: UUID
    assignment_id: UUID
    expected_version: int
    idempotency_key: str = field(repr=False)
    canonical_payload: bytes = field(repr=False)

    def __post_init__(self) -> None:
        identities = (
            self.actor_user_id,
            self.session_id,
            self.command_id,
            self.demand_id,
            self.assignment_id,
        )
        if any(not isinstance(value, UUID) or value.int == 0 for value in identities):
            raise ValueError("Demand release replay identity is invalid")
        if (
            isinstance(self.expected_version, bool)
            or not isinstance(self.expected_version, int)
            or self.expected_version < 1
            or not isinstance(self.idempotency_key, str)
            or not self.idempotency_key
            or not isinstance(self.canonical_payload, bytes)
            or not self.canonical_payload
        ):
            raise ValueError("Demand release replay material is invalid")


@dataclass(frozen=True)
class DemandCompletedReleaseReplayResult:
    organization_id: UUID
    authority_marker_sha256: bytes = field(repr=False)
    aggregate_version: int
    demand_version_id: UUID

    def __post_init__(self) -> None:
        if (
            not isinstance(self.organization_id, UUID)
            or self.organization_id.int == 0
            or not isinstance(self.demand_version_id, UUID)
            or self.demand_version_id.int == 0
            or not isinstance(self.authority_marker_sha256, bytes)
            or len(self.authority_marker_sha256) != 32
            or isinstance(self.aggregate_version, bool)
            or not isinstance(self.aggregate_version, int)
            or self.aggregate_version < 2
        ):
            raise ValueError("Demand release replay result is invalid")


class ProfileCompletedLifecycleReplayError(RuntimeError):
    """A completed Profile lifecycle receipt cannot be safely replayed."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class ProfileCompletedLifecycleReplayProbeRequest:
    actor_user_id: UUID
    session_id: UUID
    command_id: UUID
    profile_id: UUID
    operation: CreatorProfilePostgresOperation
    expected_version: int
    expected_authority_marker_sha256: bytes = field(repr=False)
    idempotency_key: str = field(repr=False)
    canonical_payload: bytes = field(repr=False)

    def __post_init__(self) -> None:
        identities = (
            self.actor_user_id,
            self.session_id,
            self.command_id,
            self.profile_id,
        )
        if any(not isinstance(value, UUID) or value.int == 0 for value in identities):
            raise ValueError("Profile lifecycle replay identity is invalid")
        if self.operation not in _PROFILE_LIFECYCLE_OPERATIONS:
            raise ValueError("Profile lifecycle replay operation is invalid")
        if (
            isinstance(self.expected_version, bool)
            or not isinstance(self.expected_version, int)
            or self.expected_version < 1
            or not isinstance(self.expected_authority_marker_sha256, bytes)
            or len(self.expected_authority_marker_sha256) != 32
            or not isinstance(self.idempotency_key, str)
            or not self.idempotency_key
            or not isinstance(self.canonical_payload, bytes)
            or not self.canonical_payload
        ):
            raise ValueError("Profile lifecycle replay material is invalid")


@dataclass(frozen=True)
class ProfileCompletedLifecycleReplayResult:
    profile_id: UUID
    operation: CreatorProfilePostgresOperation
    aggregate_version: int
    status: str

    def __post_init__(self) -> None:
        if (
            not isinstance(self.profile_id, UUID)
            or self.profile_id.int == 0
            or self.operation not in _PROFILE_LIFECYCLE_OPERATIONS
            or isinstance(self.aggregate_version, bool)
            or not isinstance(self.aggregate_version, int)
            or self.aggregate_version < 2
            or self.status != _PROFILE_LIFECYCLE_STATUS[self.operation]
        ):
            raise ValueError("Profile lifecycle replay result is invalid")


@dataclass(frozen=True)
class EditorPsycopgConnectionSettings:
    conninfo: str = field(repr=False)
    expected_role: str
    application_name: str = "desire-internal-pilot-editor"
    connect_timeout_seconds: int = 5

    def __post_init__(self) -> None:
        if not self.conninfo:
            raise ValueError("editor PostgreSQL conninfo is required")
        if self.expected_role not in {
            "profile_app",
            "demand_self",
            "demand_review",
            "demand_finance",
            "demand_system",
        }:
            raise ValueError("editor PostgreSQL role is not reviewed")
        if not self.application_name or len(self.application_name) > 96:
            raise ValueError("editor PostgreSQL application name is invalid")
        if not 1 <= self.connect_timeout_seconds <= 30:
            raise ValueError("editor PostgreSQL connect timeout is invalid")


class PsycopgEditorConnectionSource:
    """Runnable role-bound psycopg source; a pool can implement the same port."""

    def __init__(
        self,
        *,
        settings: EditorPsycopgConnectionSettings,
        dbapi: Any = psycopg,
    ) -> None:
        if not isinstance(settings, EditorPsycopgConnectionSettings):
            raise ValueError("editor PostgreSQL connection settings are required")
        self._settings = settings
        self._dbapi = dbapi

    def checkout(self) -> Any:
        connection = self._dbapi.connect(
            self._settings.conninfo,
            autocommit=True,
            application_name=self._settings.application_name,
            connect_timeout=self._settings.connect_timeout_seconds,
        )
        row = connection.execute(
            "SELECT session_user,current_user,"
            "current_setting('server_version_num')::integer/10000"
        ).fetchone()
        if row != (
            self._settings.expected_role,
            self._settings.expected_role,
            18,
        ):
            connection.close()
            raise EditorPostgresConfigurationError(
                "editor PostgreSQL connection role or server is untrusted"
            )
        return connection

    @staticmethod
    def release(connection: Any) -> None:
        connection.close()

    @staticmethod
    def discard(connection: Any) -> None:
        connection.close()


class PsycopgDemandCompletedVerifyReceiptProbe:
    """Receipt-only recovery before ACTIVE reviewer-target discovery."""

    def __init__(
        self,
        *,
        connections: Any,
        idempotency_keys: Tuple[Tuple[str, Union[bytes, bytearray]], ...],
        payload_hash_keys: Tuple[Tuple[str, Union[bytes, bytearray]], ...],
    ) -> None:
        if not all(
            callable(getattr(connections, name, None))
            for name in ("checkout", "release", "discard")
        ):
            raise TypeError("Demand Verify replay pool is unavailable")
        _require_replay_keys(idempotency_keys)
        _require_replay_keys(payload_hash_keys)
        if set(key_id for key_id, _ in idempotency_keys) & set(
            key_id for key_id, _ in payload_hash_keys
        ):
            raise ValueError("Demand Verify replay key purposes overlap")
        if len(
            {
                bytes(material)
                for _key_id, material in idempotency_keys + payload_hash_keys
            }
        ) != len(idempotency_keys) + len(payload_hash_keys):
            raise ValueError("Demand Verify replay key materials overlap")
        self._connections = connections
        self._idempotency_keys = idempotency_keys
        self._payload_hash_keys = payload_hash_keys
        self._closed = False

    def read_completed(
        self,
        request: DemandCompletedVerifyReplayProbeRequest,
    ) -> Optional[DemandCompletedVerifyReplayResult]:
        if not isinstance(request, DemandCompletedVerifyReplayProbeRequest):
            raise TypeError("Demand Verify replay request is unavailable")
        if self._closed:
            raise DemandCompletedVerifyReplayError("SERVICE_UNAVAILABLE")
        identity_ids, identity_digests = _replay_candidates(
            self._idempotency_keys,
            request.idempotency_key.encode("utf-8"),
        )
        payload_ids, payload_hashes = _replay_candidates(
            self._payload_hash_keys,
            request.canonical_payload,
        )

        def read(connection: Any) -> Optional[DemandCompletedVerifyReplayResult]:
            _set_local(
                connection,
                {
                    "TimeZone": "UTC",
                    "lock_timeout": "2000ms",
                    "statement_timeout": "10000ms",
                    "idle_in_transaction_session_timeout": "15000ms",
                    "app.scope_kind": "DEMAND_VERIFY_REPLAY",
                    "app.operation": "VERIFY",
                    "app.actor_id": str(request.actor_user_id),
                    "app.session_id": str(request.session_id),
                    "app.organization_id": "",
                    "app.demand_id": str(request.demand_id),
                    "app.assignment_id": str(request.assignment_id),
                    "app.command_id": str(request.command_id),
                },
            )
            rows = connection.execute(
                "SELECT organization_id,authority_marker_sha256,"
                "aggregate_version,demand_version_id FROM "
                "demand_api.read_completed_verify_receipt_v1("
                + ",".join(["%s"] * 10)
                + ")",
                (
                    request.actor_user_id,
                    request.session_id,
                    request.command_id,
                    request.demand_id,
                    request.assignment_id,
                    request.expected_version,
                    list(identity_ids),
                    list(identity_digests),
                    list(payload_ids),
                    list(payload_hashes),
                ),
            ).fetchmany(2)
            if not isinstance(rows, list) or len(rows) > 1:
                raise EditorPostgresConfigurationError(
                    "Demand Verify replay result cardinality drifted"
                )
            if not rows:
                return None
            row = rows[0]
            if not isinstance(row, tuple) or len(row) != 4:
                raise EditorPostgresConfigurationError(
                    "Demand Verify replay result shape drifted"
                )
            try:
                return DemandCompletedVerifyReplayResult(
                    organization_id=row[0],
                    authority_marker_sha256=bytes(row[1]),
                    aggregate_version=int(row[2]),
                    demand_version_id=row[3],
                )
            except (TypeError, ValueError):
                raise EditorPostgresConfigurationError(
                    "Demand Verify replay result is corrupt"
                ) from None

        try:
            return _run_projection(
                source=self._connections,
                expected_role="demand_review",
                expected_component="demand",
                work=read,
            )
        except psycopg.Error as error:
            sqlstate = getattr(error, "sqlstate", None)
            message = str(getattr(getattr(error, "diag", None), "message_primary", ""))
            if sqlstate == "23505" and message == "IDEMPOTENCY_KEY_REUSED":
                raise DemandCompletedVerifyReplayError(
                    "IDEMPOTENCY_KEY_REUSED"
                ) from None
            if sqlstate == "42501" and message == "ACCESS_DENIED":
                raise DemandCompletedVerifyReplayError("RESOURCE_NOT_FOUND") from None
            if sqlstate == "40003" and message == "COMMAND_OUTCOME_UNKNOWN":
                raise DemandCompletedVerifyReplayError(
                    "COMMAND_OUTCOME_UNKNOWN"
                ) from None
            raise DemandCompletedVerifyReplayError("SERVICE_UNAVAILABLE") from None
        except DemandCompletedVerifyReplayError:
            raise
        except BaseException:
            raise DemandCompletedVerifyReplayError("SERVICE_UNAVAILABLE") from None

    def read_completed_release(
        self,
        request: DemandCompletedReleaseReplayProbeRequest,
    ) -> Optional[DemandCompletedReleaseReplayResult]:
        """Recover an exact completed release before ACTIVE target discovery."""

        if not isinstance(request, DemandCompletedReleaseReplayProbeRequest):
            raise TypeError("Demand release replay request is unavailable")
        if self._closed:
            raise DemandCompletedReleaseReplayError("SERVICE_UNAVAILABLE")
        identity_ids, identity_digests = _replay_candidates(
            self._idempotency_keys,
            request.idempotency_key.encode("utf-8"),
        )
        payload_ids, payload_hashes = _replay_candidates(
            self._payload_hash_keys,
            request.canonical_payload,
        )

        def read(connection: Any) -> Optional[DemandCompletedReleaseReplayResult]:
            _set_local(
                connection,
                {
                    "TimeZone": "UTC",
                    "lock_timeout": "2000ms",
                    "statement_timeout": "10000ms",
                    "idle_in_transaction_session_timeout": "15000ms",
                    "app.scope_kind": "DEMAND_REVIEW_RELEASE_REPLAY",
                    "app.operation": "RELEASE_REVIEW_ASSIGNMENT",
                    "app.actor_id": str(request.actor_user_id),
                    "app.session_id": str(request.session_id),
                    "app.organization_id": "",
                    "app.demand_id": str(request.demand_id),
                    "app.assignment_id": str(request.assignment_id),
                    "app.command_id": str(request.command_id),
                },
            )
            rows = connection.execute(
                "SELECT organization_id,authority_marker_sha256,"
                "aggregate_version,demand_version_id FROM "
                "demand_api.read_completed_review_assignment_release_receipt_v1("
                + ",".join(["%s"] * 10)
                + ")",
                (
                    request.actor_user_id,
                    request.session_id,
                    request.command_id,
                    request.demand_id,
                    request.assignment_id,
                    request.expected_version,
                    list(identity_ids),
                    list(identity_digests),
                    list(payload_ids),
                    list(payload_hashes),
                ),
            ).fetchmany(2)
            if not isinstance(rows, list) or len(rows) > 1:
                raise EditorPostgresConfigurationError(
                    "Demand release replay result cardinality drifted"
                )
            if not rows:
                return None
            row = rows[0]
            if not isinstance(row, tuple) or len(row) != 4:
                raise EditorPostgresConfigurationError(
                    "Demand release replay result shape drifted"
                )
            try:
                return DemandCompletedReleaseReplayResult(
                    organization_id=row[0],
                    authority_marker_sha256=bytes(row[1]),
                    aggregate_version=int(row[2]),
                    demand_version_id=row[3],
                )
            except (TypeError, ValueError):
                raise EditorPostgresConfigurationError(
                    "Demand release replay result is corrupt"
                ) from None

        try:
            return _run_projection(
                source=self._connections,
                expected_role="demand_review",
                expected_component="demand",
                work=read,
            )
        except psycopg.Error as error:
            sqlstate = getattr(error, "sqlstate", None)
            message = str(
                getattr(getattr(error, "diag", None), "message_primary", "")
            )
            if sqlstate == "23505" and message == "IDEMPOTENCY_KEY_REUSED":
                raise DemandCompletedReleaseReplayError(
                    "IDEMPOTENCY_KEY_REUSED"
                ) from None
            if sqlstate == "42501" and message == "ACCESS_DENIED":
                raise DemandCompletedReleaseReplayError(
                    "RESOURCE_NOT_FOUND"
                ) from None
            if sqlstate == "40003" and message == "COMMAND_OUTCOME_UNKNOWN":
                raise DemandCompletedReleaseReplayError(
                    "COMMAND_OUTCOME_UNKNOWN"
                ) from None
            raise DemandCompletedReleaseReplayError(
                "SERVICE_UNAVAILABLE"
            ) from None
        except DemandCompletedReleaseReplayError:
            raise
        except BaseException:
            raise DemandCompletedReleaseReplayError(
                "SERVICE_UNAVAILABLE"
            ) from None

    def close(self) -> None:
        self._closed = True

    def check_readiness(self, *, timeout_ms: int) -> None:
        if (
            self._closed
            or type(timeout_ms) is not int
            or not 1 <= timeout_ms <= 30_000
        ):
            raise RuntimeError("DEMAND_VERIFY_REPLAY_NOT_READY")

    def __repr__(self) -> str:
        return (
            "PsycopgDemandCompletedVerifyReceiptProbe("
            f"idempotency_retained={len(self._idempotency_keys)}, "
            f"payload_retained={len(self._payload_hash_keys)}, "
            f"closed={self._closed}, material=<redacted>)"
        )


class PsycopgProfileCompletedLifecycleReceiptProbe:
    """Authority-bound receipt recovery before Profile state discovery."""

    def __init__(
        self,
        *,
        connections: Any,
        idempotency_keys: Tuple[Tuple[str, Union[bytes, bytearray]], ...],
        payload_hash_keys: Tuple[Tuple[str, Union[bytes, bytearray]], ...],
    ) -> None:
        if not all(
            callable(getattr(connections, name, None))
            for name in ("checkout", "release", "discard")
        ):
            raise TypeError("Profile lifecycle replay pool is unavailable")
        _require_replay_keys(idempotency_keys)
        _require_replay_keys(payload_hash_keys)
        if set(key_id for key_id, _ in idempotency_keys) & set(
            key_id for key_id, _ in payload_hash_keys
        ):
            raise ValueError("Profile lifecycle replay key purposes overlap")
        if len(
            {
                bytes(material)
                for _key_id, material in idempotency_keys + payload_hash_keys
            }
        ) != len(idempotency_keys) + len(payload_hash_keys):
            raise ValueError("Profile lifecycle replay key materials overlap")
        self._connections = connections
        self._idempotency_keys = idempotency_keys
        self._payload_hash_keys = payload_hash_keys
        self._closed = False

    def read_completed(
        self,
        request: ProfileCompletedLifecycleReplayProbeRequest,
    ) -> Optional[ProfileCompletedLifecycleReplayResult]:
        if not isinstance(request, ProfileCompletedLifecycleReplayProbeRequest):
            raise TypeError("Profile lifecycle replay request is unavailable")
        if self._closed:
            raise ProfileCompletedLifecycleReplayError("SERVICE_UNAVAILABLE")
        identity_ids, identity_digests = _replay_candidates(
            self._idempotency_keys,
            request.idempotency_key.encode("utf-8"),
        )
        payload_ids, payload_hashes = _replay_candidates(
            self._payload_hash_keys,
            request.canonical_payload,
        )
        payload_candidates = dict(zip(payload_ids, payload_hashes))
        operation = _PROFILE_AUTHORITY_OPERATION[request.operation]

        def read(
            connection: Any,
        ) -> Optional[ProfileCompletedLifecycleReplayResult]:
            _set_local(
                connection,
                {
                    "TimeZone": "UTC",
                    "lock_timeout": "2000ms",
                    "statement_timeout": "10000ms",
                    "idle_in_transaction_session_timeout": "15000ms",
                    "app.scope_kind": "PROFILE_SELF",
                    "app.operation": operation,
                    "app.actor_user_id": str(request.actor_user_id),
                    "app.session_id": str(request.session_id),
                    "app.profile_id": str(request.profile_id),
                    "app.command_id": str(request.command_id),
                    "app.command_name": request.operation.value,
                    "app.command_version": "1",
                    "app.expected_aggregate_version": str(
                        request.expected_version
                    ),
                },
            )
            authority = connection.execute(
                "SELECT user_id,creator_grant_id,current_bundle_id,"
                "authority_marker_sha256,marker_matches FROM "
                "iam_api.lock_creator_profile_self_v1(%s,%s,%s,%s)",
                (
                    request.actor_user_id,
                    request.session_id,
                    operation,
                    request.expected_authority_marker_sha256,
                ),
            ).fetchone()
            if authority is None:
                raise ProfileCompletedLifecycleReplayError("RESOURCE_NOT_FOUND")
            if (
                not isinstance(authority, tuple)
                or len(authority) != 5
                or authority[0] != request.actor_user_id
                or not isinstance(authority[1], UUID)
                or authority[1].int == 0
                or not isinstance(authority[2], UUID)
                or authority[2].int == 0
                or authority[4] is not True
            ):
                raise ProfileCompletedLifecycleReplayError("SERVICE_UNAVAILABLE")
            try:
                marker = bytes(authority[3])
            except (TypeError, ValueError):
                raise ProfileCompletedLifecycleReplayError(
                    "SERVICE_UNAVAILABLE"
                ) from None
            if len(marker) != 32 or not hmac.compare_digest(
                marker,
                request.expected_authority_marker_sha256,
            ):
                raise ProfileCompletedLifecycleReplayError("SERVICE_UNAVAILABLE")

            matches = []
            for key_id, digest in zip(identity_ids, identity_digests):
                _set_local(
                    connection,
                    {
                        "app.idempotency_key_digest_key_id": key_id,
                        "app.idempotency_key_digest": digest.hex(),
                    },
                )
                rows = connection.execute(
                    "SELECT id,principal_kind,principal_id,command_name,"
                    "command_version,idempotency_key_digest_key_id,"
                    "idempotency_key_digest,payload_hash_key_id,"
                    "canonicalization_version,payload_hash,target_profile_id,"
                    "expected_aggregate_version,status,safe_response_body,"
                    "response_schema_version,completed_aggregate_version,"
                    "created_at,retain_until,completed_at,"
                    "transaction_timestamp() FROM profile.command_receipts "
                    "WHERE principal_kind='USER' AND principal_id=%s "
                    "AND command_name=%s AND command_version=1 "
                    "AND idempotency_key_digest_key_id=%s "
                    "AND idempotency_key_digest=%s ORDER BY id LIMIT 2",
                    (
                        request.actor_user_id,
                        request.operation.value,
                        key_id,
                        digest,
                    ),
                ).fetchmany(2)
                if not isinstance(rows, list) or len(rows) > 1:
                    raise ProfileCompletedLifecycleReplayError(
                        "SERVICE_UNAVAILABLE"
                    )
                if rows:
                    matches.append((rows[0], key_id, digest))
            if not matches:
                return None
            if len(matches) != 1:
                raise ProfileCompletedLifecycleReplayError("SERVICE_UNAVAILABLE")

            row, identity_key_id, identity_digest = matches[0]
            if not isinstance(row, tuple) or len(row) != 20:
                raise ProfileCompletedLifecycleReplayError("SERVICE_UNAVAILABLE")
            try:
                stored_identity_digest = bytes(row[6])
                stored_payload_hash = bytes(row[9])
            except (TypeError, ValueError):
                raise ProfileCompletedLifecycleReplayError(
                    "SERVICE_UNAVAILABLE"
                ) from None
            stored_payload_key_id = row[7]
            expected_payload_hash = payload_candidates.get(stored_payload_key_id)
            if expected_payload_hash is None:
                raise ProfileCompletedLifecycleReplayError("SERVICE_UNAVAILABLE")
            if len(stored_payload_hash) != 32:
                raise ProfileCompletedLifecycleReplayError("SERVICE_UNAVAILABLE")
            if not hmac.compare_digest(stored_payload_hash, expected_payload_hash):
                raise ProfileCompletedLifecycleReplayError(
                    "IDEMPOTENCY_KEY_REUSED"
                )

            expected_status = _PROFILE_LIFECYCLE_STATUS[request.operation]
            if (
                not isinstance(row[0], UUID)
                or row[0].int == 0
                or row[0] != request.command_id
                or row[1] != "USER"
                or row[2] != request.actor_user_id
                or row[3] != request.operation.value
                or type(row[4]) is not int
                or row[4] != 1
                or row[5] != identity_key_id
                or len(stored_identity_digest) != 32
                or not hmac.compare_digest(
                    stored_identity_digest,
                    identity_digest,
                )
                or row[8] != "profile-command-json-v1"
                or row[10] != request.profile_id
                or type(row[11]) is not int
                or row[11] != request.expected_version
            ):
                raise ProfileCompletedLifecycleReplayError("SERVICE_UNAVAILABLE")
            try:
                created_at = _utc(row[16])
                retain_until = _utc(row[17])
                database_now = _utc(row[19])
            except (TypeError, ValueError, EditorPostgresConfigurationError):
                raise ProfileCompletedLifecycleReplayError(
                    "SERVICE_UNAVAILABLE"
                ) from None
            if not created_at <= database_now < retain_until:
                raise ProfileCompletedLifecycleReplayError("SERVICE_UNAVAILABLE")
            if row[12] == "IN_PROGRESS":
                if any(row[index] is not None for index in (13, 14, 15, 18)):
                    raise ProfileCompletedLifecycleReplayError(
                        "SERVICE_UNAVAILABLE"
                    )
                raise ProfileCompletedLifecycleReplayError(
                    "COMMAND_OUTCOME_UNKNOWN"
                )
            if row[12] != "COMPLETED":
                raise ProfileCompletedLifecycleReplayError("SERVICE_UNAVAILABLE")
            safe_response = row[13]
            if (
                type(safe_response) is not dict
                or set(safe_response) != {
                    "profile_id",
                    "aggregate_version",
                    "status",
                }
                or safe_response["profile_id"] != str(request.profile_id)
                or type(safe_response["aggregate_version"]) is not int
                or safe_response["aggregate_version"]
                != request.expected_version + 1
                or safe_response["status"] != expected_status
                or type(row[14]) is not int
                or row[14] != 1
                or type(row[15]) is not int
                or row[15] != request.expected_version + 1
            ):
                raise ProfileCompletedLifecycleReplayError("SERVICE_UNAVAILABLE")
            try:
                completed_at = _utc(row[18])
            except (TypeError, ValueError, EditorPostgresConfigurationError):
                raise ProfileCompletedLifecycleReplayError(
                    "SERVICE_UNAVAILABLE"
                ) from None
            if not created_at <= completed_at <= database_now:
                raise ProfileCompletedLifecycleReplayError("SERVICE_UNAVAILABLE")
            try:
                return ProfileCompletedLifecycleReplayResult(
                    profile_id=request.profile_id,
                    operation=request.operation,
                    aggregate_version=request.expected_version + 1,
                    status=expected_status,
                )
            except ValueError:
                raise ProfileCompletedLifecycleReplayError(
                    "SERVICE_UNAVAILABLE"
                ) from None

        try:
            return _run_projection(
                source=self._connections,
                expected_role="profile_app",
                expected_component="profile",
                work=read,
            )
        except psycopg.Error as error:
            sqlstate = getattr(error, "sqlstate", None)
            message = str(getattr(getattr(error, "diag", None), "message_primary", ""))
            if sqlstate == "23505" and message == "IDEMPOTENCY_KEY_REUSED":
                raise ProfileCompletedLifecycleReplayError(
                    "IDEMPOTENCY_KEY_REUSED"
                ) from None
            if sqlstate == "42501" and message == "ACCESS_DENIED":
                raise ProfileCompletedLifecycleReplayError(
                    "RESOURCE_NOT_FOUND"
                ) from None
            if sqlstate == "40003" and message == "COMMAND_OUTCOME_UNKNOWN":
                raise ProfileCompletedLifecycleReplayError(
                    "COMMAND_OUTCOME_UNKNOWN"
                ) from None
            raise ProfileCompletedLifecycleReplayError(
                "SERVICE_UNAVAILABLE"
            ) from None
        except ProfileCompletedLifecycleReplayError:
            raise
        except BaseException:
            raise ProfileCompletedLifecycleReplayError(
                "SERVICE_UNAVAILABLE"
            ) from None

    def close(self) -> None:
        self._closed = True

    def check_readiness(self, *, timeout_ms: int) -> None:
        if (
            self._closed
            or type(timeout_ms) is not int
            or not 1 <= timeout_ms <= 30_000
        ):
            raise RuntimeError("PROFILE_LIFECYCLE_REPLAY_NOT_READY")

    def __repr__(self) -> str:
        return (
            "PsycopgProfileCompletedLifecycleReceiptProbe("
            f"idempotency_retained={len(self._idempotency_keys)}, "
            f"payload_retained={len(self._payload_hash_keys)}, "
            f"closed={self._closed}, material=<redacted>)"
        )


@dataclass(frozen=True)
class ProfileReadAuthority:
    """Trusted IAM capability evidence captured by the authentication layer."""

    expected_authority_marker_sha256: bytes = field(repr=False)
    operation: CreatorProfilePostgresOperation = (
        CreatorProfilePostgresOperation.SAVE_DRAFT
    )

    def __post_init__(self) -> None:
        _require_digest(self.expected_authority_marker_sha256)
        if self.operation not in _PROFILE_AUTHORITY_OPERATION:
            raise ValueError("Profile read authority operation is not user-bound")


@dataclass(frozen=True)
class DemandReadAuthority:
    """One exact owner or reviewer capability used to authorize a projection."""

    operation: DemandPostgresOperation
    expected_authority_marker_sha256: bytes = field(repr=False)
    assignment_id: Optional[UUID] = None
    organization_id: Optional[UUID] = None

    def __post_init__(self) -> None:
        if self.operation not in (
            _DEMAND_OWNER_READ_OPERATIONS | _DEMAND_REVIEW_READ_OPERATIONS
        ):
            raise ValueError("Demand read authority operation is not user-bound")
        _require_digest(self.expected_authority_marker_sha256)
        if self.operation in _DEMAND_REVIEW_READ_OPERATIONS:
            if not isinstance(self.assignment_id, UUID) or self.assignment_id.int == 0:
                raise ValueError("Demand reviewer read requires an assignment")
            if (
                not isinstance(self.organization_id, UUID)
                or self.organization_id.int == 0
            ):
                raise ValueError("Demand reviewer read requires an organization")
        elif self.assignment_id is not None or self.organization_id is not None:
            raise ValueError(
                "Demand owner read cannot carry an assignment or organization"
            )


class PsycopgEditorRepository:
    """Closed dispatch over canonical Profile and Demand fixed UoWs.

    Demand factories are keyed by operation because each fixed program checks
    out one exact least-privilege role (owner, reviewer, finance or system).
    """

    def __init__(
        self,
        *,
        profile_uow: Any,
        demand_uows: Mapping[DemandPostgresOperation, Any],
        profile_reads: Any = None,
        demand_owner_reads: Any = None,
        demand_review_reads: Any = None,
    ) -> None:
        self._profile_uow = profile_uow
        self._demand_uows = dict(demand_uows)
        self._profile_reads = profile_reads
        self._demand_owner_reads = demand_owner_reads
        self._demand_review_reads = demand_review_reads

    def execute_profile(self, command: CreatorProfilePostgresCommand) -> Any:
        operation = getattr(command, "operation", None)
        if operation not in _PROFILE_EXECUTOR:
            raise ValueError("closed Creator Profile command is required")
        executor = getattr(self._profile_uow, _PROFILE_EXECUTOR[operation], None)
        if executor is None:
            raise EditorPostgresConfigurationError(
                "Creator Profile fixed program is not configured"
            )
        return executor(command)

    def execute_profile_validated(
        self,
        command: CreatorProfilePostgresCommand,
        before_mutation: Any,
    ) -> Any:
        operation = getattr(command, "operation", None)
        if operation not in {
            CreatorProfilePostgresOperation.SAVE_DRAFT,
            CreatorProfilePostgresOperation.PUBLISH,
        } or not callable(before_mutation):
            raise ValueError("validated Creator Profile command is invalid")
        executor = getattr(self._profile_uow, _PROFILE_EXECUTOR[operation], None)
        if executor is None:
            raise EditorPostgresConfigurationError(
                "Creator Profile fixed program is not configured"
            )
        return executor(command, before_mutation=before_mutation)

    def execute_demand(self, command: DemandPostgresCommand) -> Any:
        operation = getattr(command, "operation", None)
        if operation not in _DEMAND_EXECUTOR:
            raise ValueError("closed Demand command is required")
        uow = self._demand_uows.get(operation)
        if uow is None:
            raise EditorPostgresConfigurationError(
                "Demand fixed program is not configured"
            )
        executor = getattr(uow, _DEMAND_EXECUTOR[operation], None)
        if executor is None:
            raise EditorPostgresConfigurationError(
                "Demand fixed program is not configured"
            )
        return executor(command)

    def execute_demand_validated(
        self,
        command: DemandPostgresCommand,
        before_mutation: Any,
    ) -> Any:
        operation = getattr(command, "operation", None)
        if operation not in {
            DemandPostgresOperation.CREATE,
            DemandPostgresOperation.CREATE_VERSION,
            DemandPostgresOperation.SUBMIT,
        } or not callable(before_mutation):
            raise ValueError("validated Demand command is invalid")
        uow = self._demand_uows.get(operation)
        if uow is None:
            raise EditorPostgresConfigurationError(
                "Demand fixed program is not configured"
            )
        executor = getattr(uow, _DEMAND_EXECUTOR[operation], None)
        if executor is None:
            raise EditorPostgresConfigurationError(
                "Demand fixed program is not configured"
            )
        return executor(command, before_mutation=before_mutation)

    def get_profile(
        self,
        *,
        principal: EditorPrincipal,
        profile_id: str,
        authority: ProfileReadAuthority,
    ) -> EditorResourceDto:
        """Project one canonical Profile after exact IAM capability locking."""

        if self._profile_reads is None:
            raise EditorPostgresConfigurationError(
                "Creator Profile read pool is not configured"
            )
        actor_id = _uuid(principal.user_id)
        session_id = _uuid(principal.session_id)
        target_id = _uuid(profile_id)
        operation = _PROFILE_AUTHORITY_OPERATION[authority.operation]

        def read(connection: Any) -> EditorResourceDto:
            _set_local(
                connection,
                {
                    "TimeZone": "UTC",
                    "lock_timeout": "2000ms",
                    "statement_timeout": "10000ms",
                    "idle_in_transaction_session_timeout": "15000ms",
                    "app.scope_kind": "PROFILE_SELF",
                    "app.operation": operation,
                    "app.actor_user_id": str(actor_id),
                    "app.session_id": str(session_id),
                    "app.profile_id": str(target_id),
                },
            )
            capability = connection.execute(
                "SELECT authority_marker_sha256,marker_matches "
                "FROM iam_api.lock_creator_profile_self_v1(%s,%s,%s,%s)",
                (
                    actor_id,
                    session_id,
                    operation,
                    authority.expected_authority_marker_sha256,
                ),
            ).fetchone()
            if (
                capability is None
                or capability[1] is not True
                or not hmac.compare_digest(
                    bytes(capability[0]),
                    authority.expected_authority_marker_sha256,
                )
            ):
                _not_found()
            root = connection.execute(
                "SELECT id,owner_user_id,status,aggregate_version,"
                "current_draft_version_id,current_published_version_id "
                "FROM profile.creator_profiles WHERE id=%s",
                (target_id,),
            ).fetchone()
            if root is None or root[1] != actor_id:
                _not_found()
            version_rows = connection.execute(
                "SELECT id,version_no,based_on_profile_version_id,status,"
                "content,content_sha256,taxonomy_bundle_id,created_at "
                "FROM profile.profile_versions WHERE profile_id=%s "
                "ORDER BY version_no,id",
                (target_id,),
            ).fetchall()
            versions = tuple(_profile_version(row) for row in version_rows)
            current_id = (
                root[5]
                if root[2] == "PAUSED"
                else root[4] or root[5]
            )
            current = next(
                (item for item in versions if item.version_id == str(current_id)),
                None,
            )
            capabilities = []
            if root[2] != "ARCHIVED":
                if root[2] in {"DRAFT", "ACTIVE"}:
                    capabilities.append("SAVE_DRAFT")
                if (
                    root[2] in {"DRAFT", "ACTIVE"}
                    and current is not None
                    and current.status == "DRAFT"
                ):
                    capabilities.append("PUBLISH")
                if root[2] == "ACTIVE":
                    capabilities.append("PAUSE")
                if root[2] == "PAUSED":
                    capabilities.append("RESUME")
                capabilities.append("ARCHIVE")
            return EditorResourceDto(
                resource_type="CREATOR_PROFILE",
                object_id=str(root[0]),
                status=root[2],
                revision=int(root[3]),
                etag=_etag("CREATOR_PROFILE", str(root[0]), int(root[3])),
                capabilities=tuple(capabilities),
                editable_paths=(
                    _PROFILE_EDITABLE_PATHS if "SAVE_DRAFT" in capabilities else ()
                ),
                current_version=current,
                versions=versions,
            )

        return _run_projection(
            source=self._profile_reads,
            expected_role="profile_app",
            expected_component="profile",
            work=read,
        )

    def list_profiles(
        self,
        *,
        principal: EditorPrincipal,
        targets: Tuple[Tuple[str, ProfileReadAuthority], ...],
    ) -> Tuple[EditorResourceDto, ...]:
        """Reauthorize every candidate; a stale discovery row reveals nothing."""

        visible = []
        for profile_id, authority in targets:
            try:
                visible.append(
                    self.get_profile(
                        principal=principal,
                        profile_id=profile_id,
                        authority=authority,
                    )
                )
            except EditorServiceError as error:
                if error.code != "RESOURCE_NOT_FOUND":
                    raise
        return tuple(sorted(visible, key=lambda item: item.object_id))

    def get_demand(
        self,
        *,
        principal: EditorPrincipal,
        demand_id: str,
        authority: DemandReadAuthority,
    ) -> EditorResourceDto:
        """Project one canonical Demand under exact actor/org/target RLS."""

        actor_id = _uuid(principal.user_id)
        session_id = _uuid(principal.session_id)
        target_id = _uuid(demand_id)
        is_owner = authority.operation in _DEMAND_OWNER_READ_OPERATIONS
        if is_owner:
            organization_id = _uuid(principal.organization_id)
        else:
            assert authority.organization_id is not None
            organization_id = authority.organization_id
        source = self._demand_owner_reads if is_owner else self._demand_review_reads
        if source is None:
            raise EditorPostgresConfigurationError("Demand read pool is not configured")
        expected_role = "demand_self" if is_owner else "demand_review"
        scope_kind = "DEMAND_OWNER" if is_owner else "DEMAND_REVIEW"
        operation = _DEMAND_AUTHORITY_OPERATION[authority.operation]

        def read(connection: Any) -> EditorResourceDto:
            _set_local(
                connection,
                {
                    "TimeZone": "UTC",
                    "lock_timeout": "2000ms",
                    "statement_timeout": "10000ms",
                    "idle_in_transaction_session_timeout": "15000ms",
                    "app.scope_kind": scope_kind,
                    "app.operation": operation,
                    "app.actor_id": str(actor_id),
                    "app.session_id": str(session_id),
                    "app.organization_id": str(organization_id),
                    "app.demand_id": str(target_id),
                    "app.assignment_id": (
                        "" if authority.assignment_id is None else str(authority.assignment_id)
                    ),
                },
            )
            if is_owner:
                capability = connection.execute(
                    "SELECT 1 FROM iam_api.lock_demand_owner_authority_v1("
                    "%s,%s,%s,%s,%s,%s)",
                    (
                        actor_id,
                        session_id,
                        organization_id,
                        operation,
                        target_id,
                        authority.expected_authority_marker_sha256,
                    ),
                ).fetchone()
                if capability != (1,):
                    _not_found()
            else:
                capability = connection.execute(
                    "SELECT duty_grant_id,duty_grant_version FROM "
                    "iam_api.lock_demand_reviewer_authority_v2("
                    "%s,%s,%s,%s,%s,%s,%s)",
                    (
                        actor_id,
                        session_id,
                        organization_id,
                        target_id,
                        authority.assignment_id,
                        operation,
                        authority.expected_authority_marker_sha256,
                    ),
                ).fetchone()
                if (
                    capability is None
                    or len(capability) != 2
                    or not isinstance(capability[0], UUID)
                    or isinstance(capability[1], bool)
                    or not isinstance(capability[1], int)
                    or capability[1] < 1
                ):
                    _not_found()
            root = connection.execute(
                "SELECT id,organization_id,creator_user_id,status,aggregate_version,"
                "current_version_id FROM demand.demands "
                "WHERE organization_id=%s AND id=%s",
                (organization_id, target_id),
            ).fetchone()
            if root is None:
                _not_found()
            version_rows = connection.execute(
                "SELECT id,version_no,based_on_demand_version_id,content,"
                "content_sha256,taxonomy_bundle_id,created_at "
                "FROM demand.demand_versions "
                "WHERE organization_id=%s AND demand_id=%s ORDER BY version_no,id",
                (organization_id, target_id),
            ).fetchall()
            versions = tuple(_demand_version(row) for row in version_rows)
            current = next(
                (item for item in versions if item.version_id == str(root[5])),
                None,
            )
            submission_rows = connection.execute(
                "SELECT id,demand_version_id,content_sha256,submitted_at "
                "FROM demand.demand_submissions "
                "WHERE organization_id=%s AND demand_id=%s ORDER BY submitted_at,id",
                (organization_id, target_id),
            ).fetchall()
            submissions = tuple(
                EditorSubmissionDto(
                    submission_id=str(row[0]),
                    version_id=str(row[1]),
                    submission_no=index,
                    content_sha256=bytes(row[2]).hex(),
                    submitted_at=_utc(row[3]),
                )
                for index, row in enumerate(submission_rows, start=1)
            )
            findings: Tuple[EditorFindingDto, ...] = ()
            assignment_active = False
            review_assignment = None
            if is_owner:
                review_rows = tuple(
                    connection.execute(
                        "SELECT finding_id,demand_version_id,assignment_id,"
                        "decision,reason_codes,required_field_codes,reviewed_at "
                        "FROM demand_api.read_demand_owner_findings_v2("
                        "%s,%s,%s,%s,%s,%s)",
                        (
                            actor_id,
                            session_id,
                            organization_id,
                            target_id,
                            operation,
                            authority.expected_authority_marker_sha256,
                        ),
                    ).fetchall()
                )
                findings = _owner_demand_findings(review_rows)
            else:
                assignment_row = connection.execute(
                    "SELECT id,status,expires_at,duty_grant_id,duty_grant_version "
                    "FROM demand.demand_review_assignments "
                    "WHERE organization_id=%s AND demand_id=%s AND id=%s "
                    "AND reviewer_user_id=%s AND status='ACTIVE' "
                    "AND transaction_timestamp()<expires_at",
                    (
                        organization_id,
                        target_id,
                        authority.assignment_id,
                        actor_id,
                    ),
                ).fetchone()
                assignment_active = bool(
                    assignment_row is not None
                    and assignment_row[3] == capability[0]
                    and assignment_row[4] == capability[1]
                )
                if assignment_active:
                    review_assignment = EditorReviewAssignmentDto(
                        assignment_id=str(assignment_row[0]),
                        status=str(assignment_row[1]),
                        expires_at=_utc(assignment_row[2]),
                    )
                review_rows = connection.execute(
                    "SELECT id,demand_version_id,assignment_id,decision,"
                    "reason_codes,required_field_codes,reviewed_at "
                    "FROM demand.demand_reviews "
                    "WHERE organization_id=%s AND demand_id=%s "
                    "ORDER BY reviewed_at,id",
                    (organization_id, target_id),
                ).fetchall()
                findings = tuple(_demand_finding(row) for row in review_rows)
            capabilities = []
            if is_owner and root[3] in {"DRAFT", "NEEDS_CHANGES", "NO_MATCH"}:
                capabilities.extend(("SAVE_DRAFT", "SUBMIT"))
            if is_owner and root[3] not in {
                DemandStatus.MATCHED.value,
                DemandStatus.CANCELLED.value,
                DemandStatus.EXPIRED.value,
            }:
                capabilities.append("CANCEL")
            if not is_owner and assignment_active:
                capabilities.append("RECORD_FINDINGS")
            return EditorResourceDto(
                resource_type="DEMAND",
                object_id=str(root[0]),
                status=root[3],
                revision=int(root[4]),
                etag=_etag("DEMAND", str(root[0]), int(root[4])),
                capabilities=tuple(capabilities),
                editable_paths=(
                    _DEMAND_EDITABLE_PATHS if "SAVE_DRAFT" in capabilities else ()
                ),
                current_version=current,
                versions=versions,
                submissions=submissions,
                findings=findings,
                review_assignment=review_assignment,
            )

        return _run_projection(
            source=source,
            expected_role=expected_role,
            expected_component="demand",
            work=read,
        )

    def list_demands(
        self,
        *,
        principal: EditorPrincipal,
        targets: Tuple[Tuple[str, DemandReadAuthority], ...],
    ) -> Tuple[EditorResourceDto, ...]:
        """Project an injected allowlist through exact target RLS one by one."""

        visible = []
        for demand_id, authority in targets:
            try:
                visible.append(
                    self.get_demand(
                        principal=principal,
                        demand_id=demand_id,
                        authority=authority,
                    )
                )
            except EditorServiceError as error:
                if error.code != "RESOURCE_NOT_FOUND":
                    raise
        return tuple(sorted(visible, key=lambda item: item.object_id))

def _run_projection(
    *,
    source: Any,
    expected_role: str,
    expected_component: str,
    work: Callable[[Any], EditorResourceDto],
) -> EditorResourceDto:
    connection = source.checkout()
    transaction_open = False
    try:
        connection.execute("RESET ROLE")
        connection.execute("RESET ALL")
        connection.execute("DISCARD TEMP")
        row = connection.execute(
            "SELECT session_user,current_user,"
            "current_setting('server_version_num')::integer/10000"
        ).fetchone()
        if row != (expected_role, expected_role, 18):
            raise EditorPostgresConfigurationError(
                "editor PostgreSQL role or server is untrusted"
            )
        if expected_component == "demand":
            compatibility = connection.execute(
                "SELECT component,current_schema_version,schema_head_version,"
                "min_app_compatible_version,max_app_compatible_version "
                "FROM demand.schema_compatibility"
            ).fetchone()
            if compatibility != (
                "demand",
                DEMAND_SCHEMA_HEAD_VERSION,
                DEMAND_SCHEMA_HEAD_VERSION,
                DEMAND_SCHEMA_HEAD_VERSION,
                DEMAND_SCHEMA_HEAD_VERSION,
            ):
                raise EditorPostgresConfigurationError(
                    "editor PostgreSQL schema head is incompatible"
                )
        else:
            compatibility = connection.execute(
                "SELECT component,current_schema_version,schema_head_version,"
                "min_app_compatible_version,max_app_compatible_version "
                "FROM profile.schema_compatibility"
            ).fetchone()
            if compatibility != (
                "profile",
                PROFILE_SCHEMA_HEAD_VERSION,
                PROFILE_SCHEMA_HEAD_VERSION,
                PROFILE_SCHEMA_HEAD_VERSION,
                PROFILE_SCHEMA_HEAD_VERSION,
            ):
                raise EditorPostgresConfigurationError(
                    "editor PostgreSQL schema head is incompatible"
                )
        connection.execute("BEGIN ISOLATION LEVEL READ COMMITTED")
        transaction_open = True
        result = work(connection)
        connection.execute("COMMIT")
        transaction_open = False
        _reset_projection_connection(connection)
        source.release(connection)
        return result
    except BaseException:
        if transaction_open:
            try:
                connection.execute("ROLLBACK")
            except BaseException:
                pass
        try:
            _reset_projection_connection(connection)
        except BaseException:
            source.discard(connection)
        else:
            source.release(connection)
        raise


def _reset_projection_connection(connection: Any) -> None:
    connection.execute("RESET ROLE")
    connection.execute("RESET ALL")
    connection.execute("DISCARD TEMP")
    row = connection.execute(
        "SELECT NULLIF(current_setting('app.scope_kind',true),''),"
        "NULLIF(current_setting('app.actor_id',true),''),"
        "NULLIF(current_setting('app.actor_user_id',true),''),"
        "NULLIF(current_setting('app.organization_id',true),''),"
        "NULLIF(current_setting('app.demand_id',true),''),"
        "NULLIF(current_setting('app.profile_id',true),'')"
    ).fetchone()
    if row != (None, None, None, None, None, None):
        raise EditorPostgresConfigurationError(
            "editor PostgreSQL connection reset failed"
        )


def _set_local(connection: Any, values: Mapping[str, str]) -> None:
    for name, value in values.items():
        connection.execute(
            "SELECT pg_catalog.set_config(%s,%s,true)",
            (name, value),
        )


def _profile_version(row: Tuple[Any, ...]) -> EditorVersionDto:
    stored = dict(row[4])
    content = stored.get("content", stored)
    if not isinstance(content, Mapping):
        raise EditorPostgresConfigurationError("Profile content projection is corrupt")
    return EditorVersionDto(
        version_id=str(row[0]),
        version_no=int(row[1]),
        based_on_version_id=None if row[2] is None else str(row[2]),
        status=row[3],
        content=dict(content),
        content_sha256=bytes(row[5]).hex(),
        taxonomy_bundle_id=str(row[6]),
        created_at=_utc(row[7]),
    )


def _demand_version(row: Tuple[Any, ...]) -> EditorVersionDto:
    return EditorVersionDto(
        version_id=str(row[0]),
        version_no=int(row[1]),
        based_on_version_id=None if row[2] is None else str(row[2]),
        status="COMMITTED",
        content=dict(row[3]),
        content_sha256=bytes(row[4]).hex(),
        taxonomy_bundle_id=str(row[5]),
        created_at=_utc(row[6]),
    )


def _demand_finding(row: Tuple[Any, ...]) -> EditorFindingDto:
    try:
        required_field_paths = tuple(
            _DEMAND_FIELD_PATH_BY_CODE[code] for code in row[5]
        )
    except (KeyError, TypeError):
        raise EditorPostgresConfigurationError(
            "Demand finding field-code projection is invalid"
        ) from None
    return EditorFindingDto(
        finding_id=str(row[0]),
        version_id=str(row[1]),
        assignment_id=None if row[2] is None else str(row[2]),
        result=row[3],
        reason_codes=tuple(row[4]),
        required_field_paths=required_field_paths,
        reviewed_at=_utc(row[6]),
    )


def _owner_demand_findings(
    rows: Tuple[Tuple[Any, ...], ...],
) -> Tuple[EditorFindingDto, ...]:
    findings = []
    ordering = []
    seen = set()
    for row in rows:
        if not isinstance(row, tuple) or len(row) != 7:
            raise EditorPostgresConfigurationError(
                "owner Demand findings projection is invalid"
            )
        identifiers = row[:2]
        if any(
            not isinstance(value, UUID) or value.int == 0
            for value in identifiers
        ):
            raise EditorPostgresConfigurationError(
                "owner Demand findings projection is invalid"
            )
        finding_id = identifiers[0]
        if finding_id in seen:
            raise EditorPostgresConfigurationError(
                "owner Demand findings projection is invalid"
            )
        seen.add(finding_id)
        decision = row[3]
        reason_codes = row[4]
        required_field_codes = row[5]
        allowed_reasons = {
            "NEEDS_CHANGES": _DEMAND_REVIEW_REASON_CODES,
            "VERIFIED": frozenset(),
            "DISCREPANCY": _FINANCE_DISCREPANCY_REASON_CODES,
            "REJECTED": _FINANCE_REJECTED_REASON_CODES,
        }.get(decision, frozenset())
        if (
            decision not in {
                "NEEDS_CHANGES", "VERIFIED", "DISCREPANCY", "REJECTED"
            }
            or (
                decision in {"NEEDS_CHANGES", "VERIFIED"}
                and not isinstance(row[2], UUID)
            )
            or (
                decision in {"DISCREPANCY", "REJECTED"}
                and row[2] is not None
            )
            or not isinstance(reason_codes, list)
            or not isinstance(required_field_codes, list)
            or any(
                not isinstance(value, str) or not value
                for values in (reason_codes, required_field_codes)
                for value in values
            )
            or len(reason_codes) != len(set(reason_codes))
            or len(required_field_codes) != len(set(required_field_codes))
            or (
                decision in {"DISCREPANCY", "REJECTED"}
                and tuple(reason_codes) != tuple(sorted(reason_codes))
            )
            or (
                decision in {"DISCREPANCY", "REJECTED"}
                and tuple(required_field_codes)
                    != tuple(sorted(required_field_codes))
            )
            or any(code not in allowed_reasons for code in reason_codes)
            or any(
                code not in _DEMAND_FIELD_PATH_BY_CODE
                for code in required_field_codes
            )
            or (
                decision in {"NEEDS_CHANGES", "DISCREPANCY", "REJECTED"}
                and (not reason_codes or not required_field_codes)
            )
            or (
                decision == "VERIFIED"
                and (reason_codes or required_field_codes)
            )
        ):
            raise EditorPostgresConfigurationError(
                "owner Demand findings projection is invalid"
            )
        reviewed_at = _utc(row[6])
        ordering.append((reviewed_at, finding_id))
        findings.append(_demand_finding(row))
    if ordering != sorted(ordering):
        raise EditorPostgresConfigurationError(
            "owner Demand findings projection is invalid"
        )
    return tuple(findings)


def _etag(resource_type: str, object_id: str, revision: int) -> str:
    digest = hashlib.sha256(
        f"{resource_type}:{object_id}:{revision}".encode("utf-8")
    ).hexdigest()[:24]
    return f'"{resource_type.lower()}-{revision}-{digest}"'


def _require_replay_keys(
    values: Tuple[Tuple[str, Union[bytes, bytearray]], ...],
) -> None:
    if (
        not isinstance(values, tuple)
        or not 1 <= len(values) <= 4
        or any(
            not isinstance(item, tuple)
            or len(item) != 2
            or not isinstance(item[0], str)
            or not item[0]
            or len(item[0]) > 128
            or not isinstance(item[1], (bytes, bytearray))
            or len(item[1]) < 32
            or not any(item[1])
            for item in values
        )
        or len({item[0] for item in values}) != len(values)
    ):
        raise ValueError("Demand Verify replay keys are invalid")


def _replay_candidates(
    keys: Tuple[Tuple[str, Union[bytes, bytearray]], ...],
    material: bytes,
) -> Tuple[Tuple[str, ...], Tuple[bytes, ...]]:
    return (
        tuple(key_id for key_id, _key in keys),
        tuple(hmac.new(key, material, hashlib.sha256).digest() for _key_id, key in keys),
    )


def _utc(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise EditorPostgresConfigurationError("database datetime is not aware")
    return value.astimezone(timezone.utc)


def _uuid(value: str) -> UUID:
    try:
        parsed = UUID(value)
    except (AttributeError, TypeError, ValueError) as error:
        raise ValueError("canonical editor identifiers must be UUIDs") from error
    if parsed.int == 0:
        raise ValueError("canonical editor identifiers cannot be zero UUIDs")
    return parsed


def _require_digest(value: bytes) -> None:
    if not isinstance(value, bytes) or len(value) != 32:
        raise ValueError("authority marker must be a SHA-256 digest")


def _not_found() -> None:
    raise EditorServiceError(status=404, code="RESOURCE_NOT_FOUND")
