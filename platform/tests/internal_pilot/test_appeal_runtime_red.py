from __future__ import annotations

from types import SimpleNamespace

import pytest
from psycopg.pq import TransactionStatus

from desire_platform.internal_pilot.appeal_runtime import (
    InternalSandboxAppealPostgresRuntime,
    PsycopgAppealRuntimeReadiness,
)
from desire_platform.trust_safety.adapters.postgres import (
    AppealPostgresGatewaySettings,
    AppealPostgresReceiptKey,
    AppealPostgresReceiptKeyring,
    AppealSealedTextKey,
    AppealSealedTextKeyring,
    PsycopgAppealCommandGateway,
    PsycopgAppealHttpProjectionAdapter,
    PsycopgAppealReadGateway,
    PsycopgAppealReceiptProbe,
    PsycopgAppealRestrictedTextStore,
    PsycopgAppealSealedTextProvider,
)
from desire_platform.trust_safety.adapters.postgres.migrations import (
    TRUST_REQUIRED_DEMAND_SCHEMA_VERSION,
    TRUST_REQUIRED_IAM_SCHEMA_VERSION,
    TRUST_SCHEMA_HEAD_VERSION,
)


class _Cursor:
    def __init__(self, *, row=None, rows=None) -> None:
        self._row = row
        self._rows = rows

    def fetchone(self):
        return self._row

    def fetchmany(self, count: int):
        assert count == 2
        return self._rows if self._rows is not None else []


class _Connection:
    def __init__(
        self,
        role: str,
        *,
        ready: bool = True,
        normalize_timeouts: bool = False,
    ) -> None:
        self.autocommit = True
        self.info = SimpleNamespace(transaction_status=TransactionStatus.IDLE)
        self.role = role
        self.ready = ready
        self.normalize_timeouts = normalize_timeouts
        self.policy_parameters = []

    def execute(self, statement, parameters=None):
        sql = str(statement)
        if "FROM trust.schema_compatibility" in sql:
            return _Cursor(
                row=(
                    self.role,
                    self.role,
                    18,
                    "trust",
                    TRUST_SCHEMA_HEAD_VERSION,
                    TRUST_SCHEMA_HEAD_VERSION,
                    TRUST_SCHEMA_HEAD_VERSION,
                    TRUST_SCHEMA_HEAD_VERSION,
                    TRUST_REQUIRED_IAM_SCHEMA_VERSION,
                    TRUST_REQUIRED_DEMAND_SCHEMA_VERSION,
                )
            )
        if "pg_catalog.set_config" in sql:
            value = parameters[1]
            if (
                self.normalize_timeouts
                and parameters[0]
                in {
                    "lock_timeout",
                    "statement_timeout",
                    "idle_in_transaction_session_timeout",
                }
                and value.endswith("ms")
                and int(value[:-2]) % 1_000 == 0
            ):
                value = f"{int(value[:-2]) // 1_000}s"
            return _Cursor(row=(value,))
        if "assert_appeal_runtime_policy_v1" in sql:
            self.policy_parameters.append(parameters)
            return _Cursor(rows=[(True,)] if self.ready else [])
        return _Cursor()


class _Source:
    def __init__(self, *connections: _Connection) -> None:
        self._connections = list(connections)
        self.released = []
        self.discarded = []

    def checkout(self):
        return self._connections.pop(0)

    def release(self, connection) -> None:
        self.released.append(connection)

    def discard(self, connection) -> None:
        self.discarded.append(connection)


class _ExplodingSource:
    def checkout(self):
        raise AssertionError("projection path must not run")

    def release(self, connection) -> None:
        del connection

    def discard(self, connection) -> None:
        del connection


def _receipt_keyring() -> AppealPostgresReceiptKeyring:
    return AppealPostgresReceiptKeyring(
        idempotency_keys=(
            AppealPostgresReceiptKey(
                purpose="IDEMPOTENCY",
                key_id="trust-idempotency-2026-01",
                material=bytearray(b"i" * 32),
            ),
        ),
        payload_hash_keys=(
            AppealPostgresReceiptKey(
                purpose="PAYLOAD_HASH",
                key_id="trust-payload-2026-01",
                material=bytearray(b"p" * 32),
            ),
        ),
    )


def _sealed_keyring() -> AppealSealedTextKeyring:
    return AppealSealedTextKeyring(
        keys=(
            AppealSealedTextKey(
                key_id="trust-sealed-note-v1",
                material=bytearray(b"s" * 32),
            ),
        ),
        active_key_id="trust-sealed-note-v1",
        retained_key_ids=("trust-sealed-note-v1",),
    )


def _readiness(applicant, reviewer) -> PsycopgAppealRuntimeReadiness:
    return PsycopgAppealRuntimeReadiness(
        applicant_connections=applicant,
        reviewer_connections=reviewer,
        settings=AppealPostgresGatewaySettings(
            lock_timeout_ms=500,
            statement_timeout_ms=1_000,
            idle_in_transaction_timeout_ms=1_000,
        ),
    )


def test_readiness_asserts_exact_policy_as_both_runtime_roles() -> None:
    applicant_connection = _Connection("trust_self")
    reviewer_connection = _Connection("trust_appeal")
    applicant = _Source(applicant_connection)
    reviewer = _Source(reviewer_connection)
    readiness = _readiness(applicant, reviewer)

    assert readiness.verify(
        receipt_keyring=_receipt_keyring(),
        sealed_text_keyring=_sealed_keyring(),
    ) is None

    expected = (
        "trust-idempotency-2026-01",
        ["trust-idempotency-2026-01"],
        "trust-payload-2026-01",
        ["trust-payload-2026-01"],
        "appeal-command-json-v1",
        "trust-sealed-note-v1",
        ["trust-sealed-note-v1"],
    )
    assert applicant_connection.policy_parameters == [expected]
    assert reviewer_connection.policy_parameters == [expected]
    assert applicant.released == [applicant_connection]
    assert reviewer.released == [reviewer_connection]


def test_readiness_accepts_postgres_canonical_timeout_display() -> None:
    applicant = _Source(
        _Connection("trust_self", normalize_timeouts=True)
    )
    reviewer = _Source(
        _Connection("trust_appeal", normalize_timeouts=True)
    )
    readiness = _readiness(applicant, reviewer)

    assert readiness.verify(
        receipt_keyring=_receipt_keyring(),
        sealed_text_keyring=_sealed_keyring(),
    ) is None


def test_runtime_fails_closed_on_policy_drift_and_discards_connection() -> None:
    applicant_connection = _Connection("trust_self", ready=False)
    applicant = _Source(applicant_connection)
    reviewer = _Source(_Connection("trust_appeal"))
    readiness = _readiness(applicant, reviewer)

    with pytest.raises(Exception):
        readiness.verify(
            receipt_keyring=_receipt_keyring(),
            sealed_text_keyring=_sealed_keyring(),
        )

    assert applicant.discarded == [applicant_connection]
    assert reviewer.released == []


def test_managed_runtime_checks_readiness_and_zeroizes_on_close() -> None:
    applicant = _ExplodingSource()
    reviewer = _ExplodingSource()
    receipt_keyring = _receipt_keyring()
    sealed_keyring = _sealed_keyring()
    sealed_text = PsycopgAppealSealedTextProvider(
        store=PsycopgAppealRestrictedTextStore(
            applicant_connections=applicant,
            reviewer_connections=reviewer,
        ),
        keyring=sealed_keyring,
    )
    runtime = InternalSandboxAppealPostgresRuntime(
        projections=PsycopgAppealHttpProjectionAdapter(
            read_gateway=PsycopgAppealReadGateway(
                applicant_connections=applicant,
                reviewer_connections=reviewer,
            )
        ),
        command_gateway=PsycopgAppealCommandGateway(
            applicant_connections=applicant,
            reviewer_connections=reviewer,
        ),
        receipt_probe=PsycopgAppealReceiptProbe(
            applicant_connections=applicant,
            reviewer_connections=reviewer,
        ),
        receipt_keyring=receipt_keyring,
        sealed_text=sealed_text,
        runtime_readiness=_readiness(
            _Source(_Connection("trust_self")),
            _Source(_Connection("trust_appeal")),
        ),
    )

    assert runtime.check_readiness(timeout_ms=1_000) is None
    assert "material" not in repr(runtime)
    runtime.close()
    runtime.close()

    assert all(set(item.material) == {0} for item in receipt_keyring._keys.values())
    assert all(set(item.material) == {0} for item in sealed_keyring._keys.values())
    with pytest.raises(RuntimeError, match="APPEAL_RUNTIME_NOT_READY"):
        runtime.check_readiness(timeout_ms=1_000)
