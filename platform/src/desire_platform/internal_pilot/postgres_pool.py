"""Bounded, role-bound PostgreSQL 18 pool for the internal sandbox API.

The pool accepts a validated runtime ``DatabaseProfile`` and a destructible
credential carrier.  It never accepts a DSN, owner role, migration role, or
caller-selected SQL role.  Every checkout and check-in proves the physical
connection identity and the absence of request-local authority context.
"""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import re
import threading
import time
from typing import Any, Optional, Tuple

import psycopg
from psycopg.pq import TransactionStatus

from desire_platform.runtime.config import DatabaseProfile


_DNS_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_DATABASE = re.compile(r"^[a-z][a-z0-9_]{0,62}$")
_REVIEWED_API_ROLES = frozenset(
    (
        "iam_app",
        "iam_session_authenticator",
        "iam_onboarding",
        "profile_app",
        "demand_self",
        "demand_review",
        "demand_finance",
        "trust_self",
        "trust_officer",
        "trust_appeal",
        "trust_decision",
        "matching_creator",
        "matching_selector",
        "matching_assignment",
        "matching_review",
        "demand_matching",
        "profile_matcher",
        "matching_worker",
        "matching_coordinator",
    )
)
_TRANSPORT_SECURITY = frozenset(("TLS_REQUIRED", "TRUSTED_CONTAINER_NETWORK"))
_REQUEST_CONTEXT_SETTINGS = (
    "app.admin_workspace_id",
    "app.admin_participant_ids",
    "app.actor_user_id",
    "app.session_id",
    "app.organization_id",
    "app.membership_id",
    "app.scope_kind",
    "app.operation",
    "app.invitation_id",
    "app.selection_id",
    "app.selector_assignment_id",
    "app.authority_marker_sha256",
    "app.attempt_id",
    "app.command_id",
    "app.target_id",
)


class RoleBoundPoolError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class PostgresEndpointSettings:
    host: str
    port: int
    database: str
    transport_security: str

    def __post_init__(self) -> None:
        if (
            not isinstance(self.host, str)
            or not self.host
            or self.host != self.host.lower()
            or self.host.endswith(".")
            or not 1 <= len(self.host) <= 253
        ):
            raise ValueError("PostgreSQL host is not canonical")
        try:
            address = ipaddress.ip_address(self.host)
        except ValueError:
            if any(
                not label or _DNS_LABEL.fullmatch(label) is None
                for label in self.host.split(".")
            ):
                raise ValueError("PostgreSQL host is not canonical") from None
        else:
            if str(address) != self.host:
                raise ValueError("PostgreSQL address is not canonical")
        if type(self.port) is not int or not 1 <= self.port <= 65_535:
            raise ValueError("PostgreSQL port is invalid")
        if not isinstance(self.database, str) or _DATABASE.fullmatch(self.database) is None:
            raise ValueError("PostgreSQL database name is invalid")
        if self.transport_security not in _TRANSPORT_SECURITY:
            raise ValueError("PostgreSQL transport security is not closed")
        if self.transport_security == "TRUSTED_CONTAINER_NETWORK" and self.host != "db":
            raise ValueError("plaintext PostgreSQL is restricted to the container network")


class PsycopgRoleBoundPoolFactory:
    """Concrete factory compatible with ``RuntimeBindings.pool_factory``."""

    def __init__(
        self,
        *,
        endpoint: PostgresEndpointSettings,
        dbapi: Any = psycopg,
        allowed_roles: Tuple[str, ...] = tuple(sorted(_REVIEWED_API_ROLES)),
    ) -> None:
        if not isinstance(endpoint, PostgresEndpointSettings):
            raise TypeError("PostgreSQL endpoint settings are unavailable")
        if (
            not isinstance(allowed_roles, tuple)
            or not allowed_roles
            or len(set(allowed_roles)) != len(allowed_roles)
            or any(role not in _REVIEWED_API_ROLES for role in allowed_roles)
        ):
            raise ValueError("PostgreSQL API role allowlist is invalid")
        if not callable(getattr(dbapi, "connect", None)):
            raise TypeError("psycopg adapter is unavailable")
        self._endpoint = endpoint
        self._dbapi = dbapi
        self._allowed_roles = frozenset(allowed_roles)

    def create(self, profile: DatabaseProfile, credential: Any) -> "RoleBoundPsycopgPool":
        if not isinstance(profile, DatabaseProfile):
            raise TypeError("database profile is unavailable")
        if profile.online_role not in self._allowed_roles:
            raise TypeError("database profile role is not allowed for this API")
        _credential_material(credential)
        return RoleBoundPsycopgPool(
            endpoint=self._endpoint,
            profile=profile,
            credential=credential,
            dbapi=self._dbapi,
        )

    def __repr__(self) -> str:
        return (
            "PsycopgRoleBoundPoolFactory("
            f"host={self._endpoint.host!r}, database={self._endpoint.database!r}, "
            f"role_count={len(self._allowed_roles)})"
        )


class RoleBoundPsycopgPool:
    """Small synchronous pool implementing the repository connection-source port."""

    def __init__(
        self,
        *,
        endpoint: PostgresEndpointSettings,
        profile: DatabaseProfile,
        credential: Any,
        dbapi: Any,
    ) -> None:
        self._endpoint = endpoint
        self._profile = profile
        self._credential = credential
        self._dbapi = dbapi
        self._condition = threading.Condition(threading.RLock())
        self._idle: list[Any] = []
        self._checked_out: dict[int, Any] = {}
        self._total = 0
        self._closed = False

    def checkout(self) -> Any:
        return self._checkout(self._profile.checkout_timeout_ms)

    def _checkout(self, timeout_ms: int) -> Any:
        if type(timeout_ms) is not int or timeout_ms <= 0:
            raise TypeError("database checkout timeout is unavailable")
        deadline = time.monotonic() + timeout_ms / 1000.0
        while True:
            create = False
            connection: Any = None
            with self._condition:
                if self._closed:
                    raise RoleBoundPoolError("DATABASE_POOL_CLOSED")
                if self._idle:
                    connection = self._idle.pop()
                    self._checked_out[id(connection)] = connection
                elif self._total < self._profile.max_pool_size:
                    self._total += 1
                    create = True
                else:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise RoleBoundPoolError("DATABASE_POOL_EXHAUSTED")
                    self._condition.wait(remaining)
                    continue

            if create:
                try:
                    connection = self._connect()
                    _verify_connection(
                        connection,
                        endpoint=self._endpoint,
                        profile=self._profile,
                    )
                except BaseException:
                    if connection is not None:
                        _close_ignoring_failure(connection)
                    with self._condition:
                        self._total -= 1
                        self._condition.notify()
                    raise RoleBoundPoolError("DATABASE_UNAVAILABLE") from None
                with self._condition:
                    if self._closed:
                        self._total -= 1
                        _close_ignoring_failure(connection)
                        raise RoleBoundPoolError("DATABASE_POOL_CLOSED")
                    self._checked_out[id(connection)] = connection
                return connection

            try:
                _verify_connection(
                    connection,
                    endpoint=self._endpoint,
                    profile=self._profile,
                )
            except BaseException:
                self.discard(connection)
                raise RoleBoundPoolError("DATABASE_UNAVAILABLE") from None
            return connection

    def _connect(self) -> Any:
        password = _credential_material(self._credential).decode(
            "utf-8", errors="strict"
        )
        sslmode = (
            "verify-full"
            if self._endpoint.transport_security == "TLS_REQUIRED"
            else "disable"
        )
        return self._dbapi.connect(
            host=self._endpoint.host,
            port=self._endpoint.port,
            dbname=self._endpoint.database,
            user=self._profile.online_role,
            password=password,
            application_name=self._profile.application_name,
            connect_timeout=max(
                1,
                min(30, (self._profile.checkout_timeout_ms + 999) // 1000),
            ),
            sslmode=sslmode,
            autocommit=True,
        )

    def release(self, connection: Any) -> None:
        with self._condition:
            known = self._checked_out.pop(id(connection), None)
        if known is not connection:
            _close_ignoring_failure(connection)
            raise RoleBoundPoolError("DATABASE_CONNECTION_NOT_OWNED")
        reusable = False
        try:
            _reset_connection(connection)
            _verify_connection(
                connection,
                endpoint=self._endpoint,
                profile=self._profile,
            )
            reusable = True
        except BaseException:
            _close_ignoring_failure(connection)
        with self._condition:
            if reusable and not self._closed:
                self._idle.append(connection)
            else:
                if reusable:
                    _close_ignoring_failure(connection)
                self._total -= 1
            self._condition.notify()
        if not reusable:
            raise RoleBoundPoolError("DATABASE_CONNECTION_TAINTED")

    def discard(self, connection: Any) -> None:
        with self._condition:
            known = self._checked_out.pop(id(connection), None)
            if known is connection:
                self._total -= 1
                self._condition.notify()
        _close_ignoring_failure(connection)

    def check_readiness(self, timeout_ms: int) -> None:
        if type(timeout_ms) is not int or not 1 <= timeout_ms <= 30_000:
            raise TypeError("database readiness timeout is unavailable")
        connection = self._checkout(
            min(timeout_ms, self._profile.checkout_timeout_ms)
        )
        try:
            row = connection.execute("SELECT 1").fetchone()
            if row != (1,):
                raise RuntimeError("database readiness result is not closed")
        except BaseException:
            self.discard(connection)
            raise RoleBoundPoolError("DATABASE_UNAVAILABLE") from None
        try:
            self.release(connection)
        except RoleBoundPoolError:
            raise RoleBoundPoolError("DATABASE_UNAVAILABLE") from None
        return None

    def close(self) -> None:
        with self._condition:
            if self._closed:
                return
            self._closed = True
            connections = tuple(self._idle) + tuple(self._checked_out.values())
            self._idle.clear()
            self._checked_out.clear()
            self._total = 0
            self._condition.notify_all()
        for connection in connections:
            _close_ignoring_failure(connection)

    def __repr__(self) -> str:
        with self._condition:
            return (
                "RoleBoundPsycopgPool("
                f"role={self._profile.online_role!r}, "
                f"size={self._total}, idle={len(self._idle)}, "
                f"closed={self._closed})"
            )


def _credential_material(credential: Any) -> bytes:
    material = getattr(credential, "material", None)
    if not isinstance(material, bytearray):
        raise TypeError("database credential carrier is unavailable")
    value = bytes(material)
    if (
        not 24 <= len(value) <= 4_096
        or b"\x00" in value
        or b"\r" in value
        or b"\n" in value
        or not any(value)
    ):
        raise TypeError("database credential material is unavailable")
    try:
        value.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise TypeError("database credential material is unavailable") from None
    return value


def _verify_connection(
    connection: Any,
    *,
    endpoint: PostgresEndpointSettings,
    profile: DatabaseProfile,
) -> None:
    if (
        getattr(connection, "autocommit", None) is not True
        or connection.info.transaction_status != TransactionStatus.IDLE
    ):
        raise RuntimeError("database connection is not transaction-idle")
    row = connection.execute(
        "SELECT session_user,current_user,current_database(),"
        "current_setting('server_version_num')::integer/10000,"
        "current_setting('application_name'),"
        "current_setting('transaction_read_only'),"
        "current_setting('app.actor_user_id',true),"
        "current_setting('app.session_id',true),"
        "current_setting('app.organization_id',true),"
        "current_setting('app.membership_id',true),"
        "current_setting('app.scope_kind',true),"
        "current_setting('app.operation',true),"
        "current_setting('app.invitation_id',true),"
        "current_setting('app.selection_id',true),"
        "current_setting('app.selector_assignment_id',true),"
        "current_setting('app.authority_marker_sha256',true),"
        "current_setting('app.attempt_id',true),"
        "current_setting('app.command_id',true),"
        "current_setting('app.target_id',true)"
    ).fetchone()
    if (
        row is None
        or len(row) != 19
        or row[:6]
        != (
            profile.online_role,
            profile.online_role,
            endpoint.database,
            18,
            profile.application_name,
            "off",
        )
        or any(value not in (None, "") for value in row[6:])
    ):
        raise RuntimeError("database connection identity is unavailable")


def _reset_connection(connection: Any) -> None:
    if connection.info.transaction_status != TransactionStatus.IDLE:
        raise RuntimeError("database connection is not transaction-idle")
    connection.execute("RESET ROLE")
    connection.execute("RESET ALL")
    connection.execute("CLOSE ALL")
    connection.execute("DISCARD TEMP")


def _close_ignoring_failure(connection: Any) -> None:
    try:
        connection.close()
    except BaseException:
        pass


__all__ = [
    "PostgresEndpointSettings",
    "PsycopgRoleBoundPoolFactory",
    "RoleBoundPoolError",
    "RoleBoundPsycopgPool",
]
