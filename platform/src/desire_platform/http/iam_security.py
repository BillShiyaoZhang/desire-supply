"""Production HTTP security adapters for the IAM transport boundary.

The module is intentionally framework-neutral.  Database-backed Session and
rate-limit components are added behind the closed values defined here; no
adapter may fall back to a process-local identity or allow-all policy.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
import hmac
import ipaddress
import re
from typing import Any, Mapping, Optional, Protocol, Sequence, Tuple
import unicodedata
from urllib.parse import urlsplit
import uuid

from desire_platform.identity_access.domain.errors import IamError
from desire_platform.identity_access.security.cryptography import (
    KeyUnavailableError,
    canonical_json_bytes,
    csrf_digest,
    derive_csrf_token,
    session_handle_digest_for_key,
)

from .contracts import AuthenticatedHttpActor
from .iam import IAM_HTTP_ROUTES, HttpCsrfMode


_DOMAIN_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_KNOWN_OPERATION_IDS = frozenset(route.operation.value for route in IAM_HTTP_ROUTES)
_CSRF_OPERATION_IDS = frozenset(
    route.operation.value
    for route in IAM_HTTP_ROUTES
    if route.csrf
    in {HttpCsrfMode.SESSION_IF_AUTHENTICATED, HttpCsrfMode.SESSION_REQUIRED}
)
_SESSION_HANDLE = re.compile(r"^[A-Za-z0-9_-]{43,128}$")
_CSRF_TOKEN = re.compile(r"^[A-Za-z0-9_-]{32,512}$")
_LOWER_HEX_32 = re.compile(r"^[a-f0-9]{64}$")
_APPLICATION_OPERATION_ID = re.compile(r"^[A-Za-z][A-Za-z0-9]{0,127}$")
_SESSION_SECURITY_SYSTEM_ACTOR_ID = "00000000-0000-5000-8000-000000000017"
_REPLAY_RESULT_OUTCOMES = frozenset(
    {"REVOKED", "ALREADY_REVOKED", "ALREADY_TERMINAL"}
)
IAM_HTTP_SESSION_SECURITY_BEHAVIOR_NOT_AVAILABLE = (
    "IAM_HTTP_SESSION_SECURITY_BEHAVIOR_NOT_AVAILABLE"
)

_COOKIE_COLUMNS = (
    "session_id",
    "user_id",
    "family_id",
    "generation",
    "session_status",
    "handle_digest_key_id",
    "handle_digest",
    "csrf_salt",
    "csrf_key_id",
    "csrf_digest",
    "auth_time",
    "acr_code",
    "amr_codes",
    "idle_expires_at",
    "absolute_expires_at",
    "verified_contact_point_id",
    "verified_at",
    "verified_for_invitation_id",
    "auth_transaction_id",
    "device_label",
    "session_aggregate_version",
    "family_status",
    "current_generation",
    "family_aggregate_version",
    "user_status",
    "resolved_at",
)
_REPLAY_RESULT_COLUMNS = (
    "outcome",
    "revoked_session_id",
    "family_version",
    "session_version",
)


class SessionSecurityConnectionSource(Protocol):
    def checkout(self) -> Any: ...

    def release(self, connection: Any) -> None: ...

    def discard(self, connection: Any) -> None: ...


class SessionSecurityKeyring(Protocol):
    session_handle_digest_key_id: str
    retained_session_handle_digest_key_ids: Tuple[str, ...]
    csrf_key_id: str
    retained_csrf_key_ids: Tuple[str, ...]

    def keyed_digest_hex(self, *, key_id: str, canonical_bytes: bytes) -> str: ...


class SessionSecurityIdSource(Protocol):
    def new_id(self, purpose: str) -> str | uuid.UUID: ...


@dataclass(frozen=True, repr=False)
class _ResolvedSession:
    session_id: str
    user_id: str
    family_id: str
    generation: int
    session_status: str
    handle_digest_key_id: str
    handle_digest: bytes = field(repr=False)
    csrf_salt: bytes = field(repr=False)
    csrf_key_id: str = field(repr=False)
    csrf_digest: bytes = field(repr=False)
    auth_time: datetime
    acr_code: str
    amr_codes: Tuple[str, ...]
    idle_expires_at: datetime
    absolute_expires_at: datetime
    session_aggregate_version: int
    family_status: str
    current_generation: int
    family_aggregate_version: int
    user_status: str
    resolved_at: datetime


@dataclass(frozen=True)
class ExactOriginPolicySettings:
    allowed_origins: Tuple[str, ...]
    allow_synthetic_loopback_http: bool = False
    allow_internal_bff_http: bool = False
    deployment_mode: Optional[str] = None

    def __post_init__(self) -> None:
        if (
            not isinstance(self.allowed_origins, tuple)
            or not 1 <= len(self.allowed_origins) <= 32
            or len(set(self.allowed_origins)) != len(self.allowed_origins)
        ):
            raise ValueError("Origin allowlist must be a unique non-empty tuple")
        if not isinstance(self.allow_synthetic_loopback_http, bool):
            raise TypeError("synthetic loopback flag must be boolean")
        if not isinstance(self.allow_internal_bff_http, bool):
            raise TypeError("internal BFF flag must be boolean")
        if self.allow_synthetic_loopback_http and self.allow_internal_bff_http:
            raise ValueError("HTTP origin profiles cannot be combined")
        if self.allow_internal_bff_http:
            if (
                self.deployment_mode != "INTERNAL_SANDBOX"
                or self.allowed_origins != ("http://api:8000",)
            ):
                raise ValueError("internal BFF origin profile is invalid")
        elif self.deployment_mode is not None:
            raise ValueError("deployment mode is unused without internal BFF")
        for origin in self.allowed_origins:
            _require_canonical_origin(
                origin,
                allow_synthetic_loopback_http=self.allow_synthetic_loopback_http,
                allow_internal_bff_http=self.allow_internal_bff_http,
            )


@dataclass(frozen=True)
class SessionSecuritySettings:
    runtime_role: str = "iam_session_authenticator"
    lock_timeout_ms: int = 500
    statement_timeout_ms: int = 2_000
    idle_in_transaction_timeout_ms: int = 5_000
    maximum_retained_handle_keys: int = 8
    maximum_replay_resolution_attempts: int = 3
    additional_csrf_operation_ids: Tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.runtime_role != "iam_session_authenticator":
            raise ValueError("Session security role must be iam_session_authenticator")
        if not 1 <= self.lock_timeout_ms <= 1_000:
            raise ValueError("Session security lock timeout is outside bounds")
        if not 1 <= self.statement_timeout_ms <= 5_000:
            raise ValueError("Session security statement timeout is outside bounds")
        if not 1 <= self.idle_in_transaction_timeout_ms <= 10_000:
            raise ValueError(
                "Session security idle-in-transaction timeout is outside bounds"
            )
        if not 1 <= self.maximum_retained_handle_keys <= 8:
            raise ValueError("Session handle retained-key count is outside bounds")
        if not 1 <= self.maximum_replay_resolution_attempts <= 3:
            raise ValueError("Session replay resolution attempts are outside bounds")
        operations = self.additional_csrf_operation_ids
        if (
            not isinstance(operations, tuple)
            or len(operations) > 64
            or len(set(operations)) != len(operations)
            or any(
                not isinstance(operation, str)
                or _APPLICATION_OPERATION_ID.fullmatch(operation) is None
                or operation in _KNOWN_OPERATION_IDS
                for operation in operations
            )
        ):
            raise ValueError("Additional CSRF operation IDs are not closed")


class ExactOriginPolicy:
    def __init__(self, settings: ExactOriginPolicySettings) -> None:
        if not isinstance(settings, ExactOriginPolicySettings):
            raise TypeError("Exact Origin policy settings are required")
        self._settings = settings
        self._allowed = frozenset(settings.allowed_origins)
        self._closed = False

    def require_allowed(self, *, origin: str | None, operation_id: str) -> None:
        if self._closed or operation_id not in _KNOWN_OPERATION_IDS:
            raise IamError("SERVICE_UNAVAILABLE")
        if not isinstance(origin, str) or origin not in self._allowed:
            raise IamError("INVALID_REQUEST")

    def check_readiness(self, *, timeout_ms: int) -> None:
        if self._closed:
            raise RuntimeError("IAM_HTTP_ORIGIN_POLICY_CLOSED")
        if type(timeout_ms) is not int or not 1 <= timeout_ms <= 30_000:
            raise ValueError("Origin readiness timeout is outside bounds")
        return None

    def close(self) -> None:
        self._closed = True

    def __repr__(self) -> str:
        return (
            "ExactOriginPolicy("
            f"origin_count={len(self._allowed)}, closed={self._closed})"
        )


class PsycopgIamSessionSecurity:
    """Fixed PostgreSQL Session lookup and deterministic CSRF verification."""

    def __init__(
        self,
        *,
        connections: SessionSecurityConnectionSource,
        keyring: SessionSecurityKeyring,
        id_source: SessionSecurityIdSource,
        settings: SessionSecuritySettings = SessionSecuritySettings(),
    ) -> None:
        if not isinstance(settings, SessionSecuritySettings):
            raise TypeError("Session security settings are required")
        if not all(
            callable(getattr(connections, name, None))
            for name in ("checkout", "release", "discard")
        ):
            raise TypeError("Session security connection source is unavailable")
        if not callable(getattr(keyring, "keyed_digest_hex", None)):
            raise TypeError("Session security keyring is unavailable")
        if not callable(getattr(id_source, "new_id", None)):
            raise TypeError("Session security ID source is unavailable")
        self._connections = connections
        self._keyring = keyring
        self._id_source = id_source
        self._settings = settings
        self._csrf_operation_ids = _CSRF_OPERATION_IDS | frozenset(
            settings.additional_csrf_operation_ids
        )
        self._closed = False

    def authenticate(
        self,
        *,
        raw_session_handle: Optional[str],
        trace_id: str,
    ) -> Optional[AuthenticatedHttpActor]:
        if self._closed:
            raise IamError("SERVICE_UNAVAILABLE")
        if raw_session_handle is None:
            return None
        if (
            not isinstance(raw_session_handle, str)
            or _SESSION_HANDLE.fullmatch(raw_session_handle) is None
        ):
            raise IamError("AUTHENTICATION_REQUIRED")
        trace = _uuid_text(trace_id)
        if trace is None:
            raise IamError("SERVICE_UNAVAILABLE")
        row = self._resolve_unique(raw_session_handle)
        if row is None:
            raise IamError("AUTHENTICATION_REQUIRED")
        if row.session_status == "REVOKED":
            self._converge_replayed_session(row, trace_id=trace)
            raise IamError("AUTHENTICATION_REQUIRED")
        return _active_actor(row, trace_id=trace)

    def require_valid(
        self,
        *,
        raw_session_handle: str,
        raw_csrf_token: Optional[str],
        actor: AuthenticatedHttpActor,
        operation_id: str,
    ) -> None:
        if self._closed or operation_id not in self._csrf_operation_ids:
            raise IamError("SERVICE_UNAVAILABLE")
        if not isinstance(actor, AuthenticatedHttpActor):
            raise IamError("SERVICE_UNAVAILABLE")
        if (
            not isinstance(raw_session_handle, str)
            or _SESSION_HANDLE.fullmatch(raw_session_handle) is None
        ):
            raise IamError("INVALID_REQUEST")
        row = self._resolve_unique(raw_session_handle)
        if row is None:
            raise IamError("AUTHENTICATION_REQUIRED")
        if row.session_status == "REVOKED":
            self._converge_replayed_session(row, trace_id=actor.trace_id)
            raise IamError("AUTHENTICATION_REQUIRED")
        current_actor = _active_actor(row, trace_id=actor.trace_id)
        if current_actor != actor:
            raise IamError("SERVICE_UNAVAILABLE")
        if (
            not isinstance(raw_csrf_token, str)
            or _CSRF_TOKEN.fullmatch(raw_csrf_token) is None
        ):
            raise IamError("INVALID_REQUEST")
        retained_csrf_keys = _key_id_tuple(
            getattr(self._keyring, "retained_csrf_key_ids", None),
            active_key_id=getattr(self._keyring, "csrf_key_id", None),
            maximum=self._settings.maximum_retained_handle_keys,
        )
        if row.csrf_key_id not in retained_csrf_keys:
            raise IamError("SERVICE_UNAVAILABLE")
        try:
            derived_token = derive_csrf_token(
                self._keyring,
                raw_session_handle=raw_session_handle,
                csrf_salt=row.csrf_salt,
                session_id=row.session_id,
                generation=row.generation,
                key_id=row.csrf_key_id,
            )
            derived_digest = _digest_bytes(
                csrf_digest(
                    self._keyring,
                    csrf_token=derived_token,
                    key_id=row.csrf_key_id,
                )
            )
            request_digest = _digest_bytes(
                csrf_digest(
                    self._keyring,
                    csrf_token=raw_csrf_token,
                    key_id=row.csrf_key_id,
                )
            )
        except (KeyUnavailableError, LookupError, TypeError, ValueError):
            raise IamError("SERVICE_UNAVAILABLE") from None
        if not hmac.compare_digest(derived_digest, row.csrf_digest):
            raise IamError("SERVICE_UNAVAILABLE")
        if not hmac.compare_digest(request_digest, row.csrf_digest):
            raise IamError("INVALID_REQUEST")
        return None

    def check_readiness(self, *, timeout_ms: int) -> None:
        if self._closed:
            raise RuntimeError("IAM_HTTP_SESSION_SECURITY_CLOSED")
        if type(timeout_ms) is not int or not 1 <= timeout_ms <= 30_000:
            raise ValueError("Session security readiness timeout is outside bounds")
        handle_keys = self._handle_key_ids()
        csrf_keys = _key_id_tuple(
            getattr(self._keyring, "retained_csrf_key_ids", None),
            active_key_id=getattr(self._keyring, "csrf_key_id", None),
            maximum=self._settings.maximum_retained_handle_keys,
        )
        try:
            for purpose, key_ids in (
                ("SESSION_HANDLE", handle_keys),
                ("CSRF", csrf_keys),
            ):
                for key_id in key_ids:
                    digest = self._keyring.keyed_digest_hex(
                        key_id=key_id,
                        canonical_bytes=canonical_json_bytes(
                            {
                                "key_id": key_id,
                                "purpose": f"IAM_HTTP_{purpose}_READINESS",
                            }
                        ),
                    )
                    _digest_bytes(digest)
        except (KeyUnavailableError, LookupError, TypeError, ValueError):
            raise RuntimeError("IAM_HTTP_SESSION_SECURITY_KEY_UNAVAILABLE") from None

        connection = self._connections.checkout()
        transaction_started = False
        try:
            _require_autocommit(connection)
            _reset_connection(connection)
            connection.execute("BEGIN TRANSACTION ISOLATION LEVEL READ COMMITTED READ ONLY")
            transaction_started = True
            _set_utc_transaction_timezone(connection)
            cursor = connection.execute(
                """
                /* iam.session_security_readiness_v2 */
                SELECT
                    session_user,
                    current_user,
                    current_setting('server_version_num')::integer,
                    current_setting('TimeZone'),
                    pg_catalog.to_regclass(
                        'iam_api.resolve_cookie_session_v2'
                    ) IS NOT NULL
                    AND pg_catalog.to_regclass(
                        'iam.session_security_events'
                    ) IS NOT NULL
                    AND pg_catalog.to_regprocedure(
                        'iam_api.revoke_replayed_session_family_v1('
                        'uuid,uuid,uuid,uuid,uuid,uuid)'
                    ) IS NOT NULL
                    AND pg_catalog.has_table_privilege(
                        session_user,
                        'iam_api.resolve_cookie_session_v2',
                        'SELECT'
                    )
                    AND pg_catalog.has_table_privilege(
                        session_user,
                        'iam.session_security_events',
                        'SELECT,INSERT'
                    )
                    AND pg_catalog.has_function_privilege(
                        session_user,
                        'iam_api.revoke_replayed_session_family_v1('
                        'uuid,uuid,uuid,uuid,uuid,uuid)',
                        'EXECUTE'
                    ) AS capability_ready
                """
            )
            row = cursor.fetchone()
            if (
                row is None
                or len(row) != 5
                or row[0] != self._settings.runtime_role
                or row[1] != self._settings.runtime_role
                or type(row[2]) is not int
                or row[2] < 180000
                or row[3] != "UTC"
                or row[4] is not True
            ):
                raise RuntimeError("Session security readiness facts are invalid")
            connection.execute("COMMIT")
            transaction_started = False
            _reset_connection(connection)
            self._connections.release(connection)
            return None
        except Exception:
            _abort_and_discard(
                self._connections,
                connection,
                transaction_started=transaction_started,
            )
            raise RuntimeError("IAM_HTTP_SESSION_SECURITY_UNAVAILABLE") from None

    def close(self) -> None:
        self._closed = True

    def __repr__(self) -> str:
        return f"PsycopgIamSessionSecurity(closed={self._closed})"

    def _handle_key_ids(self) -> Tuple[str, ...]:
        return _key_id_tuple(
            getattr(self._keyring, "retained_session_handle_digest_key_ids", None),
            active_key_id=getattr(
                self._keyring,
                "session_handle_digest_key_id",
                None,
            ),
            maximum=self._settings.maximum_retained_handle_keys,
        )

    def _candidate_digests(
        self,
        raw_session_handle: str,
    ) -> Tuple[Tuple[str, str], ...]:
        result = []
        try:
            for key_id in self._handle_key_ids():
                digest = session_handle_digest_for_key(
                    self._keyring,
                    raw_session_handle=raw_session_handle,
                    key_id=key_id,
                )
                _digest_bytes(digest)
                result.append((key_id, digest))
        except (KeyUnavailableError, LookupError, TypeError, ValueError):
            raise IamError("SERVICE_UNAVAILABLE") from None
        return tuple(result)

    def _resolve_unique(self, raw_session_handle: str) -> Optional[_ResolvedSession]:
        candidates = self._candidate_digests(raw_session_handle)
        connection = self._connections.checkout()
        transaction_started = False
        matches: list[_ResolvedSession] = []
        try:
            _require_autocommit(connection)
            _reset_connection(connection)
            for key_id, digest in candidates:
                connection.execute(
                    "BEGIN TRANSACTION ISOLATION LEVEL READ COMMITTED READ ONLY"
                )
                transaction_started = True
                transaction_time = _install_session_context(
                    connection,
                    key_id=key_id,
                    digest=digest,
                    settings=self._settings,
                )
                cursor = connection.execute(
                    """
                    /* iam.resolve_cookie_session_v2 */
                    SELECT
                        session_id,
                        user_id,
                        family_id,
                        generation,
                        session_status,
                        handle_digest_key_id,
                        handle_digest,
                        csrf_salt,
                        csrf_key_id,
                        csrf_digest,
                        auth_time,
                        acr_code,
                        amr_codes,
                        idle_expires_at,
                        absolute_expires_at,
                        verified_contact_point_id,
                        verified_at,
                        verified_for_invitation_id,
                        auth_transaction_id,
                        device_label,
                        session_aggregate_version,
                        family_status,
                        current_generation,
                        family_aggregate_version,
                        user_status,
                        transaction_timestamp() AS resolved_at
                    FROM iam_api.resolve_cookie_session_v2
                    """
                )
                rows = _mapping_rows(cursor, expected_columns=_COOKIE_COLUMNS)
                if len(rows) > 1:
                    raise RuntimeError("Session digest resolved more than one row")
                if rows:
                    resolved = _resolved_session(
                        rows[0],
                        expected_key_id=key_id,
                        expected_digest=digest,
                    )
                    if resolved.resolved_at != transaction_time:
                        raise RuntimeError("Session transaction time drifted")
                    matches.append(resolved)
                connection.execute("COMMIT")
                transaction_started = False
            if len(matches) > 1:
                raise RuntimeError("Session handle matched multiple retained keys")
            _reset_connection(connection)
            self._connections.release(connection)
        except IamError:
            _abort_and_discard(
                self._connections,
                connection,
                transaction_started=transaction_started,
            )
            raise
        except Exception:
            _abort_and_discard(
                self._connections,
                connection,
                transaction_started=transaction_started,
            )
            raise IamError("SERVICE_UNAVAILABLE") from None
        return None if not matches else matches[0]

    def _converge_replayed_session(
        self,
        row: _ResolvedSession,
        *,
        trace_id: str,
    ) -> None:
        trace = _nonzero_uuid_text(trace_id)
        if trace is None:
            raise IamError("SERVICE_UNAVAILABLE")
        if (
            row.family_status not in {"ACTIVE", "REVOKED"}
            or row.generation > row.current_generation
        ):
            raise IamError("SERVICE_UNAVAILABLE")
        if row.generation == row.current_generation:
            # Explicit logout/revocation can terminate the current Session
            # while its family remains ACTIVE. There is no successor handle
            # to revoke; callers still reject this credential immediately.
            # The replay program is reserved for revoked older generations.
            return None
        try:
            security_event_id = _required_generated_uuid(
                self._id_source,
                "session-replay-security-event",
            )
            audit_event_id = _required_generated_uuid(
                self._id_source,
                "session-replay-audit-event",
            )
            outbox_event_id = _required_generated_uuid(
                self._id_source,
                "session-replay-outbox-event",
            )
        except (TypeError, ValueError):
            raise IamError("SERVICE_UNAVAILABLE") from None
        if len({security_event_id, audit_event_id, outbox_event_id}) != 3:
            raise IamError("SERVICE_UNAVAILABLE")

        for attempt in range(self._settings.maximum_replay_resolution_attempts):
            connection = self._connections.checkout()
            transaction_started = False
            commit_sent = False
            try:
                _require_autocommit(connection)
                _reset_connection(connection)
                connection.execute(
                    "BEGIN TRANSACTION ISOLATION LEVEL READ COMMITTED READ WRITE"
                )
                transaction_started = True
                _install_replay_context(
                    connection,
                    row=row,
                    security_event_id=security_event_id,
                    audit_event_id=audit_event_id,
                    outbox_event_id=outbox_event_id,
                    trace_id=trace,
                    settings=self._settings,
                )
                cursor = connection.execute(
                    """
                    /* IAM REVOKE_REPLAYED_FAMILY fixed program v1 */
                    SELECT
                        outcome,
                        revoked_session_id,
                        family_version,
                        session_version
                    FROM iam_api.revoke_replayed_session_family_v1(
                        %s::uuid,
                        %s::uuid,
                        %s::uuid,
                        %s::uuid,
                        %s::uuid,
                        %s::uuid
                    )
                    """,
                    (
                        security_event_id,
                        audit_event_id,
                        outbox_event_id,
                        _SESSION_SECURITY_SYSTEM_ACTOR_ID,
                        trace,
                        trace,
                    ),
                )
                result_rows = _mapping_rows(
                    cursor,
                    expected_columns=_REPLAY_RESULT_COLUMNS,
                )
                result = result_rows[0] if len(result_rows) == 1 else None
                if (
                    result is None
                    or result["outcome"] not in _REPLAY_RESULT_OUTCOMES
                    or (
                        _row_uuid_text(result["revoked_session_id"])
                        == row.session_id
                        and result["outcome"] == "REVOKED"
                    )
                    or _positive_int(result["family_version"])
                    < row.family_aggregate_version
                    or _positive_int(result["session_version"]) < 1
                ):
                    raise RuntimeError("Session replay result is invalid")
                commit_sent = True
                connection.execute("COMMIT")
                transaction_started = False
                _reset_connection(connection)
                self._connections.release(connection)
                return None
            except Exception as error:
                _abort_and_discard(
                    self._connections,
                    connection,
                    transaction_started=transaction_started,
                )
                retryable = _is_retryable_transaction_error(error) or (
                    commit_sent and _is_commit_outcome_unknown(error)
                )
                if (
                    not retryable
                    or attempt + 1
                    >= self._settings.maximum_replay_resolution_attempts
                ):
                    raise IamError("SERVICE_UNAVAILABLE") from None
        raise IamError("SERVICE_UNAVAILABLE")


def _key_id_tuple(
    value: object,
    *,
    active_key_id: object,
    maximum: int,
) -> Tuple[str, ...]:
    if (
        not isinstance(value, tuple)
        or not 1 <= len(value) <= maximum
        or len(set(value)) != len(value)
        or any(not isinstance(item, str) or not item for item in value)
        or not isinstance(active_key_id, str)
        or not active_key_id
        or active_key_id not in value
    ):
        raise IamError("SERVICE_UNAVAILABLE")
    return value


def _digest_bytes(value: object) -> bytes:
    if not isinstance(value, str) or _LOWER_HEX_32.fullmatch(value) is None:
        raise ValueError("digest is not a lowercase SHA-256 value")
    return bytes.fromhex(value)


def _uuid_text(value: object) -> Optional[str]:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError):
        return None
    canonical = str(parsed)
    return canonical if canonical == value else None


def _nonzero_uuid_text(value: object) -> Optional[str]:
    canonical = _uuid_text(value)
    if canonical is None or uuid.UUID(canonical).int == 0:
        return None
    return canonical


def _generated_uuid_text(value: object) -> Optional[str]:
    if isinstance(value, uuid.UUID):
        return str(value) if value.int != 0 else None
    return _nonzero_uuid_text(value)


def _required_generated_uuid(
    source: SessionSecurityIdSource,
    purpose: str,
) -> str:
    value = source.new_id(purpose)
    canonical = _generated_uuid_text(value)
    if canonical is None:
        raise ValueError("Session security ID source returned an invalid UUID")
    return canonical


def _row_uuid_text(value: object) -> str:
    try:
        parsed = uuid.UUID(str(value))
    except (ValueError, AttributeError):
        raise RuntimeError("Session row UUID is invalid") from None
    return str(parsed)


def _utc(value: object) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise RuntimeError("Session timestamp is not UTC aware")
    try:
        offset = value.utcoffset()
    except BaseException:
        raise RuntimeError("Session timestamp is not UTC aware") from None
    if offset != timedelta(0):
        raise RuntimeError("Session timestamp is not UTC")
    return value


def _positive_int(value: object) -> int:
    if type(value) is not int or value < 1:
        raise RuntimeError("Session aggregate fact is invalid")
    return value


def _secret_bytes(value: object) -> bytes:
    if isinstance(value, bytes):
        result = value
    elif isinstance(value, bytearray):
        result = bytes(value)
    elif isinstance(value, memoryview):
        result = value.tobytes()
    else:
        raise RuntimeError("Session secret evidence is invalid")
    if len(result) != 32:
        raise RuntimeError("Session secret evidence length is invalid")
    return result


def _required_text(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise RuntimeError("Session text fact is invalid")
    return value


def _amr_codes(value: object) -> Tuple[str, ...]:
    if not isinstance(value, (tuple, list)):
        raise RuntimeError("Session AMR facts are invalid")
    result = tuple(value)
    if (
        not result
        or len(set(result)) != len(result)
        or any(not isinstance(code, str) or not code for code in result)
    ):
        raise RuntimeError("Session AMR facts are invalid")
    return result


def _resolved_session(
    row: Mapping[str, Any],
    *,
    expected_key_id: str,
    expected_digest: str,
) -> _ResolvedSession:
    if set(row) != set(_COOKIE_COLUMNS):
        raise RuntimeError("Session row fields are not closed")
    persisted_key_id = _required_text(row["handle_digest_key_id"])
    persisted_digest = _secret_bytes(row["handle_digest"])
    if (
        persisted_key_id != expected_key_id
        or not hmac.compare_digest(persisted_digest, _digest_bytes(expected_digest))
    ):
        raise RuntimeError("Session digest binding is corrupt")
    return _ResolvedSession(
        session_id=_row_uuid_text(row["session_id"]),
        user_id=_row_uuid_text(row["user_id"]),
        family_id=_row_uuid_text(row["family_id"]),
        generation=_positive_int(row["generation"]),
        session_status=_required_text(row["session_status"]),
        handle_digest_key_id=persisted_key_id,
        handle_digest=persisted_digest,
        csrf_salt=_secret_bytes(row["csrf_salt"]),
        csrf_key_id=_required_text(row["csrf_key_id"]),
        csrf_digest=_secret_bytes(row["csrf_digest"]),
        auth_time=_utc(row["auth_time"]),
        acr_code=_required_text(row["acr_code"]),
        amr_codes=_amr_codes(row["amr_codes"]),
        idle_expires_at=_utc(row["idle_expires_at"]),
        absolute_expires_at=_utc(row["absolute_expires_at"]),
        session_aggregate_version=_positive_int(row["session_aggregate_version"]),
        family_status=_required_text(row["family_status"]),
        current_generation=_positive_int(row["current_generation"]),
        family_aggregate_version=_positive_int(row["family_aggregate_version"]),
        user_status=_required_text(row["user_status"]),
        resolved_at=_utc(row["resolved_at"]),
    )


def _active_actor(
    row: _ResolvedSession,
    *,
    trace_id: str,
) -> AuthenticatedHttpActor:
    if row.session_status not in {"ACTIVE", "REVOKED", "EXPIRED"}:
        raise IamError("SERVICE_UNAVAILABLE")
    if row.family_status not in {"ACTIVE", "REVOKED"}:
        raise IamError("SERVICE_UNAVAILABLE")
    if row.user_status not in {
        "PENDING_ENROLLMENT",
        "ACTIVE",
        "SUSPENDED",
        "CLOSED",
    }:
        raise IamError("SERVICE_UNAVAILABLE")
    if row.session_status == "REVOKED":
        # The caller must route this row through the IAM 0024 replay program.
        raise IamError("SERVICE_UNAVAILABLE")
    if (
        row.session_status != "ACTIVE"
        or row.family_status != "ACTIVE"
        or row.user_status not in {"PENDING_ENROLLMENT", "ACTIVE"}
        or row.generation != row.current_generation
        or row.resolved_at >= row.idle_expires_at
        or row.resolved_at >= row.absolute_expires_at
    ):
        raise IamError("SESSION_EXPIRED")
    return AuthenticatedHttpActor(
        actor_user_id=row.user_id,
        session_id=row.session_id,
        correlation_id=trace_id,
        causation_id=trace_id,
        trace_id=trace_id,
        original_actor_id=None,
        auth_time=row.auth_time,
        acr_code=row.acr_code,
        amr_codes=row.amr_codes,
    )


def _mapping_rows(
    cursor: Any,
    *,
    expected_columns: Sequence[str],
) -> list[dict[str, Any]]:
    description = getattr(cursor, "description", None)
    if description is None:
        raise RuntimeError("Session statement has no result description")
    columns = tuple(getattr(column, "name", None) for column in description)
    if columns != tuple(expected_columns):
        raise RuntimeError("Session statement columns do not match registry")
    return [dict(zip(columns, values)) for values in cursor.fetchall()]


def _require_autocommit(connection: Any) -> None:
    if getattr(connection, "autocommit", None) is not True:
        raise RuntimeError("Session security connections require autocommit")


def _reset_connection(connection: Any) -> None:
    connection.execute("RESET ROLE")
    connection.execute("RESET ALL")
    connection.execute("SET TIME ZONE 'UTC'")
    connection.execute("DISCARD TEMP")


def _set_utc_transaction_timezone(connection: Any) -> None:
    connection.execute("SET LOCAL TIME ZONE 'UTC'")


def _abort_and_discard(
    source: SessionSecurityConnectionSource,
    connection: Any,
    *,
    transaction_started: bool,
) -> None:
    try:
        if transaction_started:
            connection.execute("ROLLBACK")
        _reset_connection(connection)
    except Exception:
        pass
    source.discard(connection)


def _install_session_context(
    connection: Any,
    *,
    key_id: str,
    digest: str,
    settings: SessionSecuritySettings,
) -> datetime:
    _set_utc_transaction_timezone(connection)
    cursor = connection.execute(
        """
        /* iam.install_session_authenticate_context_v2 */
        SELECT
            session_user,
            current_user,
            current_setting('server_version_num')::integer,
            transaction_timestamp(),
            current_setting('TimeZone'),
            set_config('lock_timeout', %s, true),
            set_config('statement_timeout', %s, true),
            set_config('idle_in_transaction_session_timeout', %s, true),
            set_config('app.scope_kind', 'SESSION_AUTHENTICATE', true),
            set_config('app.operation', 'RESOLVE_COOKIE', true),
            set_config('app.session_handle_digest_key_id', %s, true),
            set_config('app.session_handle_digest', %s, true)
        """,
        (
            f"{settings.lock_timeout_ms}ms",
            f"{settings.statement_timeout_ms}ms",
            f"{settings.idle_in_transaction_timeout_ms}ms",
            key_id,
            digest,
        ),
    )
    row = cursor.fetchone()
    if (
        row is None
        or len(row) < 5
        or row[0] != settings.runtime_role
        or row[1] != settings.runtime_role
        or type(row[2]) is not int
        or row[2] < 180000
        or row[4] != "UTC"
    ):
        raise RuntimeError("Session security connection identity is invalid")
    return _utc(row[3])


def _install_replay_context(
    connection: Any,
    *,
    row: _ResolvedSession,
    security_event_id: str,
    audit_event_id: str,
    outbox_event_id: str,
    trace_id: str,
    settings: SessionSecuritySettings,
) -> datetime:
    _set_utc_transaction_timezone(connection)
    cursor = connection.execute(
        """
        /* iam.install_session_replay_context_v1 REVOKE_REPLAYED_FAMILY */
        SELECT
            session_user,
            current_user,
            current_setting('server_version_num')::integer,
            transaction_timestamp(),
            current_setting('TimeZone'),
            set_config('lock_timeout', %s, true),
            set_config('statement_timeout', %s, true),
            set_config('idle_in_transaction_session_timeout', %s, true),
            set_config('app.scope_kind', 'SESSION_AUTHENTICATE', true),
            set_config('app.operation', 'REVOKE_REPLAYED_FAMILY', true),
            set_config('app.actor_user_id', %s, true),
            set_config('app.session_id', %s, true),
            set_config('app.session_family_id', %s, true),
            set_config('app.session_handle_digest_key_id', %s, true),
            set_config('app.session_handle_digest', %s, true),
            set_config('app.command_id', %s, true),
            set_config('app.audit_event_id', %s, true),
            set_config('app.outbox_event_id', %s, true),
            set_config('app.correlation_id', %s, true),
            set_config('app.trace_id', %s, true)
        """,
        (
            f"{settings.lock_timeout_ms}ms",
            f"{settings.statement_timeout_ms}ms",
            f"{settings.idle_in_transaction_timeout_ms}ms",
            row.user_id,
            row.session_id,
            row.family_id,
            row.handle_digest_key_id,
            row.handle_digest.hex(),
            security_event_id,
            audit_event_id,
            outbox_event_id,
            trace_id,
            trace_id,
        ),
    )
    facts = cursor.fetchone()
    if (
        facts is None
        or len(facts) < 5
        or facts[0] != settings.runtime_role
        or facts[1] != settings.runtime_role
        or type(facts[2]) is not int
        or facts[2] < 180000
        or facts[4] != "UTC"
    ):
        raise RuntimeError("Session replay connection identity is invalid")
    return _utc(facts[3])


def _is_retryable_transaction_error(error: BaseException) -> bool:
    return getattr(error, "sqlstate", None) in {"40001", "40P01", "55P03"}


def _is_commit_outcome_unknown(error: BaseException) -> bool:
    return hasattr(error, "sqlstate") and getattr(error, "sqlstate", False) is None


def _require_canonical_origin(
    origin: object,
    *,
    allow_synthetic_loopback_http: bool,
    allow_internal_bff_http: bool = False,
) -> None:
    if (
        not isinstance(origin, str)
        or not origin
        or len(origin) > 512
        or unicodedata.normalize("NFC", origin) != origin
    ):
        raise ValueError("Origin must be a bounded canonical string")
    try:
        origin.encode("ascii")
    except UnicodeEncodeError:
        raise ValueError("Origin must be ASCII") from None
    if "%" in origin or origin == "null" or origin == "*":
        raise ValueError("Origin aliases and wildcards are forbidden")
    try:
        parsed = urlsplit(origin)
        port = parsed.port
    except ValueError:
        raise ValueError("Origin authority is invalid") from None
    if (
        parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path
        or not parsed.netloc
        or parsed.hostname is None
    ):
        raise ValueError("Origin must contain only scheme and authority")
    scheme = parsed.scheme
    host = parsed.hostname
    if scheme != scheme.lower() or host != host.lower() or host.endswith("."):
        raise ValueError("Origin scheme and host must already be canonical")

    is_loopback = False
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        labels = host.split(".")
        if (
            len(host) > 253
            or any(not _DOMAIN_LABEL.fullmatch(label) for label in labels)
        ):
            raise ValueError("Origin host is not canonical DNS") from None
        is_loopback = host == "localhost"
        rendered_host = host
    else:
        if str(address) != host:
            raise ValueError("Origin IP literal is not canonical")
        is_loopback = address.is_loopback
        rendered_host = f"[{host}]" if address.version == 6 else host

    if scheme == "https":
        if port == 443:
            raise ValueError("Origin must omit the default HTTPS port")
    elif scheme == "http":
        if allow_internal_bff_http:
            if origin != "http://api:8000":
                raise ValueError("HTTP Origin is not the exact internal BFF")
        else:
            if not allow_synthetic_loopback_http or not is_loopback:
                raise ValueError("HTTP Origin is restricted to synthetic loopback")
            if port in (None, 80):
                raise ValueError("synthetic loopback Origin requires a non-default port")
    else:
        raise ValueError("Origin scheme must be HTTPS")

    canonical = f"{scheme}://{rendered_host}"
    if port is not None:
        canonical += f":{port}"
    if canonical != origin:
        raise ValueError("Origin must be in exact canonical form")


__all__ = [
    "ExactOriginPolicy",
    "ExactOriginPolicySettings",
    "IAM_HTTP_SESSION_SECURITY_BEHAVIOR_NOT_AVAILABLE",
    "PsycopgIamSessionSecurity",
    "SessionSecurityConnectionSource",
    "SessionSecurityIdSource",
    "SessionSecurityKeyring",
    "SessionSecuritySettings",
]
