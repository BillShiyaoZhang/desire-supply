"""Runtime-to-database key-policy readiness for Trust0001."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Tuple

from ._session_settings import set_config_result_matches
from .gateway import (
    TrustPostgresConfigurationError,
    TrustPostgresGatewaySettings,
    _discard,
    _prepare,
    _reset,
)
from .production import TrustPostgresReceiptKeyring
from .sealed_text import TrustSealedTextKeyring


_ROLES = ("trust_self", "trust_officer", "trust_appeal", "trust_decision")


@dataclass(frozen=True)
class TrustRuntimeKeyPolicyProjection:
    active_idempotency_key_id: str
    retained_idempotency_key_ids: Tuple[str, ...]
    active_payload_key_id: str
    retained_payload_key_ids: Tuple[str, ...]
    active_canonicalization_version: str
    retained_canonicalization_versions: Tuple[str, ...]
    active_sealed_text_key_id: str
    retained_sealed_text_key_ids: Tuple[str, ...]


class PsycopgTrustRuntimeReadiness:
    """Verify all four runtime identities see the same approved key policy."""

    def __init__(
        self,
        *,
        reporter_connections: Any,
        officer_connections: Any,
        appeal_connections: Any,
        decision_connections: Any,
        settings: TrustPostgresGatewaySettings = TrustPostgresGatewaySettings(),
    ) -> None:
        sources = (
            reporter_connections,
            officer_connections,
            appeal_connections,
            decision_connections,
        )
        if len({id(source) for source in sources}) != 4 or any(
            not all(
                callable(getattr(source, name, None))
                for name in ("checkout", "release", "discard")
            )
            for source in sources
        ):
            raise TypeError("Trust runtime connection identities are unavailable")
        if not isinstance(settings, TrustPostgresGatewaySettings):
            raise TypeError("Trust PostgreSQL gateway settings are unavailable")
        self._sources = dict(zip(_ROLES, sources))
        self._settings = settings
        self._closed = False

    def verify(
        self,
        *,
        receipt_keyring: TrustPostgresReceiptKeyring,
        sealed_text_keyring: TrustSealedTextKeyring,
    ) -> TrustRuntimeKeyPolicyProjection:
        if self._closed:
            raise TrustPostgresConfigurationError()
        if not isinstance(receipt_keyring, TrustPostgresReceiptKeyring) or not isinstance(
            sealed_text_keyring, TrustSealedTextKeyring
        ):
            raise TypeError("Trust runtime keyrings are unavailable")
        expected = TrustRuntimeKeyPolicyProjection(
            active_idempotency_key_id=(
                receipt_keyring.idempotency_key_digest_key_ids[0]
            ),
            retained_idempotency_key_ids=(
                receipt_keyring.idempotency_key_digest_key_ids
            ),
            active_payload_key_id=receipt_keyring.payload_hash_key_ids[0],
            retained_payload_key_ids=receipt_keyring.payload_hash_key_ids,
            active_canonicalization_version="trust-command-json-v1",
            retained_canonicalization_versions=("trust-command-json-v1",),
            active_sealed_text_key_id=sealed_text_keyring.active_key_id,
            retained_sealed_text_key_ids=sealed_text_keyring.retained_key_ids,
        )
        observed = tuple(
            self._read(role=role, source=self._sources[role]) for role in _ROLES
        )
        if any(value != expected for value in observed):
            raise TrustPostgresConfigurationError()
        return expected

    def close(self) -> None:
        self._closed = True

    def _read(self, *, role: str, source: Any) -> TrustRuntimeKeyPolicyProjection:
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
                    raise TrustPostgresConfigurationError()
            rows = connection.execute(
                "SELECT * FROM trust_api.read_runtime_key_policy_v1()"
            ).fetchmany(2)
            if not isinstance(rows, list) or len(rows) != 1:
                raise TrustPostgresConfigurationError()
            result = _projection(rows[0])
            connection.execute("COMMIT")
            transaction = False
            _reset(connection)
            source.release(connection)
            disposed = True
            return result
        except BaseException as error:
            if connection is not None and transaction:
                try:
                    connection.execute("ROLLBACK")
                except BaseException:
                    pass
            if connection is not None and not disposed:
                _discard(source, connection)
                disposed = True
            if isinstance(error, TrustPostgresConfigurationError):
                raise
            raise TrustPostgresConfigurationError() from None
        finally:
            if connection is not None and not disposed:
                _discard(source, connection)


def _projection(row: Any) -> TrustRuntimeKeyPolicyProjection:
    if not isinstance(row, tuple) or len(row) != 8:
        raise TrustPostgresConfigurationError()
    (
        active_idempotency,
        retained_idempotency,
        active_payload,
        retained_payload,
        active_canonicalization,
        retained_canonicalization,
        active_sealed,
        retained_sealed,
    ) = row
    arrays = (
        retained_idempotency,
        retained_payload,
        retained_canonicalization,
        retained_sealed,
    )
    if (
        any(not isinstance(value, str) or not value for value in (
            active_idempotency,
            active_payload,
            active_canonicalization,
            active_sealed,
        ))
        or any(
            not isinstance(values, list)
            or not 1 <= len(values) <= 4
            or len(values) != len(set(values))
            or any(not isinstance(item, str) or not item for item in values)
            for values in arrays
        )
        or retained_idempotency[0] != active_idempotency
        or retained_payload[0] != active_payload
        or retained_canonicalization[0] != active_canonicalization
        or retained_sealed[0] != active_sealed
    ):
        raise TrustPostgresConfigurationError()
    return TrustRuntimeKeyPolicyProjection(
        active_idempotency_key_id=active_idempotency,
        retained_idempotency_key_ids=tuple(retained_idempotency),
        active_payload_key_id=active_payload,
        retained_payload_key_ids=tuple(retained_payload),
        active_canonicalization_version=active_canonicalization,
        retained_canonicalization_versions=tuple(retained_canonicalization),
        active_sealed_text_key_id=active_sealed,
        retained_sealed_text_key_ids=tuple(retained_sealed),
    )


__all__ = [
    "PsycopgTrustRuntimeReadiness",
    "TrustRuntimeKeyPolicyProjection",
]
