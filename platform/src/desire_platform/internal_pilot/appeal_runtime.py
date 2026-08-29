"""Managed production ownership and readiness for the Appeal PostgreSQL slice."""

from __future__ import annotations

from typing import Any

from desire_platform.trust_safety.adapters.postgres._session_settings import (
    set_config_result_matches,
)
from desire_platform.trust_safety.adapters.postgres.appeal_gateway import (
    AppealPostgresConfigurationError,
    AppealPostgresGatewaySettings,
    PsycopgAppealCommandGateway,
    PsycopgAppealReadGateway,
    PsycopgAppealReceiptProbe,
    PsycopgAppealRestrictedTextStore,
    _discard,
    _prepare,
    _reset,
)
from desire_platform.trust_safety.adapters.postgres.appeal_production import (
    AppealPostgresReceiptKeyring,
    AppealSealedTextKeyring,
    PsycopgAppealHttpProjectionAdapter,
    PsycopgAppealSealedTextProvider,
)


_ROLES = ("trust_self", "trust_appeal")
_CANONICALIZATION_VERSION = "appeal-command-json-v1"


class PsycopgAppealRuntimeReadiness:
    """Assert the frozen Appeal receipt and sealed-text policy as both roles."""

    def __init__(
        self,
        *,
        applicant_connections: Any,
        reviewer_connections: Any,
        settings: AppealPostgresGatewaySettings = AppealPostgresGatewaySettings(),
    ) -> None:
        sources = (applicant_connections, reviewer_connections)
        if len({id(source) for source in sources}) != 2 or any(
            not all(
                callable(getattr(source, name, None))
                for name in ("checkout", "release", "discard")
            )
            for source in sources
        ):
            raise TypeError("Appeal runtime connection identities are unavailable")
        if not isinstance(settings, AppealPostgresGatewaySettings):
            raise TypeError("Appeal PostgreSQL gateway settings are unavailable")
        self._sources = dict(zip(_ROLES, sources))
        self._settings = settings
        self._closed = False

    def verify(
        self,
        *,
        receipt_keyring: AppealPostgresReceiptKeyring,
        sealed_text_keyring: AppealSealedTextKeyring,
    ) -> None:
        if self._closed:
            raise AppealPostgresConfigurationError()
        if not isinstance(
            receipt_keyring, AppealPostgresReceiptKeyring
        ) or not isinstance(sealed_text_keyring, AppealSealedTextKeyring):
            raise TypeError("Appeal runtime keyrings are unavailable")
        parameters = (
            receipt_keyring.idempotency_key_digest_key_ids[0],
            list(receipt_keyring.idempotency_key_digest_key_ids),
            receipt_keyring.payload_hash_key_ids[0],
            list(receipt_keyring.payload_hash_key_ids),
            _CANONICALIZATION_VERSION,
            sealed_text_keyring.active_key_id,
            list(sealed_text_keyring.retained_key_ids),
        )
        for role in _ROLES:
            self._assert_role(
                role=role,
                source=self._sources[role],
                parameters=parameters,
            )
        return None

    def close(self) -> None:
        self._closed = True

    def _assert_role(
        self, *, role: str, source: Any, parameters: tuple[Any, ...]
    ) -> None:
        connection = None
        transaction = False
        disposed = False
        try:
            connection = source.checkout()
            _prepare(connection, role)
            connection.execute("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY")
            transaction = True
            for name, value in (
                ("TimeZone", "UTC"),
                ("lock_timeout", f"{self._settings.lock_timeout_ms}ms"),
                (
                    "statement_timeout",
                    f"{self._settings.statement_timeout_ms}ms",
                ),
                (
                    "idle_in_transaction_session_timeout",
                    f"{self._settings.idle_in_transaction_timeout_ms}ms",
                ),
            ):
                row = connection.execute(
                    "SELECT pg_catalog.set_config(%s,%s,true)",
                    (name, value),
                ).fetchone()
                if not set_config_result_matches(
                    name=name,
                    requested_value=value,
                    row=row,
                ):
                    raise AppealPostgresConfigurationError()
            rows = connection.execute(
                "SELECT ready FROM "
                "trust_api.assert_appeal_runtime_policy_v1("
                + ",".join(["%s"] * 7)
                + ")",
                parameters,
            ).fetchmany(2)
            if rows != [(True,)]:
                raise AppealPostgresConfigurationError()
            connection.execute("COMMIT")
            transaction = False
            _reset(connection)
            source.release(connection)
            disposed = True
        except BaseException as error:
            if connection is not None and transaction:
                try:
                    connection.execute("ROLLBACK")
                except BaseException:
                    pass
            if connection is not None and not disposed:
                _discard(source, connection)
                disposed = True
            if isinstance(error, AppealPostgresConfigurationError):
                raise
            raise AppealPostgresConfigurationError() from None
        finally:
            if connection is not None and not disposed:
                _discard(source, connection)


class InternalSandboxAppealPostgresRuntime:
    """Own all Appeal read/write dependencies behind one managed projection."""

    def __init__(
        self,
        *,
        projections: PsycopgAppealHttpProjectionAdapter,
        command_gateway: PsycopgAppealCommandGateway,
        receipt_probe: PsycopgAppealReceiptProbe,
        receipt_keyring: AppealPostgresReceiptKeyring,
        sealed_text: PsycopgAppealSealedTextProvider,
        runtime_readiness: PsycopgAppealRuntimeReadiness,
    ) -> None:
        values = (
            (projections, PsycopgAppealHttpProjectionAdapter),
            (command_gateway, PsycopgAppealCommandGateway),
            (receipt_probe, PsycopgAppealReceiptProbe),
            (receipt_keyring, AppealPostgresReceiptKeyring),
            (sealed_text, PsycopgAppealSealedTextProvider),
            (runtime_readiness, PsycopgAppealRuntimeReadiness),
        )
        if any(not isinstance(value, expected) for value, expected in values):
            raise TypeError("managed Appeal PostgreSQL runtime is unavailable")
        if len({id(value) for value, _expected in values}) != len(values):
            raise TypeError("managed Appeal PostgreSQL resources are aliased")
        read_gateway = projections._read_gateway
        sealed_store = sealed_text._store
        if not isinstance(read_gateway, PsycopgAppealReadGateway) or not isinstance(
            sealed_store, PsycopgAppealRestrictedTextStore
        ):
            raise TypeError("managed Appeal PostgreSQL runtime is unavailable")
        self._projections = projections
        self._command_gateway = command_gateway
        self._receipt_probe = receipt_probe
        self._receipt_keyring = receipt_keyring
        self._sealed_text = sealed_text
        self._runtime_readiness = runtime_readiness
        self._closed = False

    def find_own_appeal_by_source(self, **values: Any) -> Any:
        self._require_open()
        return self._projections.find_own_appeal_by_source(**values)

    def read_own_appeal(self, **values: Any) -> Any:
        self._require_open()
        return self._projections.read_own_appeal(**values)

    def list_appeal_queue(self, **values: Any) -> Any:
        self._require_open()
        return self._projections.list_appeal_queue(**values)

    def list_my_active_appeal_assignments(self, **values: Any) -> Any:
        self._require_open()
        return self._projections.list_my_active_appeal_assignments(**values)

    def read_assigned_appeal(self, **values: Any) -> Any:
        self._require_open()
        return self._projections.read_assigned_appeal(**values)

    def list_my_completed_appeal_assignments(self, **values: Any) -> Any:
        self._require_open()
        return self._projections.list_my_completed_appeal_assignments(**values)

    def read_my_completed_appeal(self, **values: Any) -> Any:
        self._require_open()
        return self._projections.read_my_completed_appeal(**values)

    def check_readiness(self, *, timeout_ms: int) -> None:
        if (
            self._closed
            or type(timeout_ms) is not int
            or not 1 <= timeout_ms <= 30_000
            or self._runtime_readiness._settings.statement_timeout_ms > timeout_ms
        ):
            raise RuntimeError("APPEAL_RUNTIME_NOT_READY")
        try:
            result = self._runtime_readiness.verify(
                receipt_keyring=self._receipt_keyring,
                sealed_text_keyring=self._sealed_text._keyring,
            )
        except BaseException:
            raise RuntimeError("APPEAL_RUNTIME_NOT_READY") from None
        if result is not None:
            raise RuntimeError("APPEAL_RUNTIME_NOT_READY")
        return None

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        for resource in (
            self._runtime_readiness,
            self._projections,
            self._sealed_text,
            self._receipt_probe,
            self._command_gateway,
            self._receipt_keyring,
        ):
            try:
                resource.close()
            except BaseException:
                pass

    def _require_open(self) -> None:
        if self._closed:
            raise RuntimeError("APPEAL_RUNTIME_NOT_READY")

    def __repr__(self) -> str:
        return (
            "InternalSandboxAppealPostgresRuntime("
            f"closed={self._closed}, dependencies=<redacted>)"
        )


__all__ = [
    "InternalSandboxAppealPostgresRuntime",
    "PsycopgAppealRuntimeReadiness",
]
