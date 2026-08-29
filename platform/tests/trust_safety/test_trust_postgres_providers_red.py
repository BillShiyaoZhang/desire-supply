"""Production-provider contracts for Trust sealed text and Demand holds."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
from types import SimpleNamespace
from uuid import UUID

from psycopg.pq import TransactionStatus

from desire_platform.demand.ports.commands import DemandHoldDecision
from desire_platform.trust_safety.adapters.postgres.demand_hold import (
    PsycopgTrustDemandSafetyHoldProvider,
    TrustDemandHoldEvidenceResult,
)
from desire_platform.trust_safety.adapters.postgres.gateway import (
    TrustPostgresReplayMaterial,
)
from desire_platform.trust_safety.adapters.postgres.migrations import (
    TRUST_REQUIRED_DEMAND_SCHEMA_VERSION,
    TRUST_REQUIRED_IAM_SCHEMA_VERSION,
    TRUST_SCHEMA_HEAD_VERSION,
)
from desire_platform.trust_safety.adapters.postgres.outcome_evidence import (
    PsycopgTrustOutcomeEvidenceProvider,
    TrustOutcomeEvidenceRequest,
)
from desire_platform.trust_safety.adapters.postgres.sealed_text import (
    PsycopgTrustRestrictedTextStore,
    PsycopgTrustSealedNoteProvider,
    TrustSealedTextKey,
    TrustSealedTextKeyring,
)


def _uuid(number: int) -> UUID:
    return UUID(f"b0000000-0000-4000-8000-{number:012d}")


class _Cursor:
    def __init__(self, row=None, rows=None) -> None:
        self._row = row
        self._rows = rows

    def fetchone(self):
        return self._row

    def fetchmany(self, count: int):
        assert count == 2
        return self._rows or []


class _Connection:
    def __init__(self, role: str, *, result=None, store_result=None) -> None:
        self.autocommit = True
        self.info = SimpleNamespace(transaction_status=TransactionStatus.IDLE)
        self.role = role
        self.result = result
        self.store_result = store_result
        self.calls: list[tuple[str, object]] = []

    def execute(self, statement, parameters=None):
        sql = str(statement)
        self.calls.append((sql, parameters))
        if "FROM trust.schema_compatibility" in sql:
            return _Cursor(
                (
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
            return _Cursor((parameters[1],))
        if "store_restricted_text_blob_v1" in sql:
            if self.store_result is not None:
                return _Cursor(self.store_result)
            params = parameters
            return _Cursor(
                (
                    params[5][0],
                    params[7],
                    "TRUST_CASE_NOTE",
                    datetime.now(timezone.utc) - timedelta(seconds=1),
                    False,
                )
            )
        if "evaluate_demand_hold_v1" in sql:
            return _Cursor(rows=[self.result])
        if "read_outcome_evidence_source_v1" in sql:
            return _Cursor(rows=[self.result])
        return _Cursor()


class _Source:
    def __init__(self, *connections: _Connection) -> None:
        self.connections = list(connections)
        self.released = []
        self.discarded = []

    def checkout(self):
        return self.connections.pop(0)

    def release(self, connection) -> None:
        self.released.append(connection)

    def discard(self, connection) -> None:
        self.discarded.append(connection)


class _Ids:
    def __init__(self, value: UUID) -> None:
        self.value = value
        self.kinds: list[str] = []

    def new_id(self, kind: str) -> str:
        self.kinds.append(kind)
        return str(self.value)


def test_sealed_note_provider_encrypts_and_store_receives_no_plaintext() -> None:
    connection = _Connection("trust_officer")
    store = PsycopgTrustRestrictedTextStore(
        officer_connections=_Source(connection),
    )
    keyring = TrustSealedTextKeyring(
        keys=(
            TrustSealedTextKey(
                key_id="trust-sealed-note-v2",
                material=bytearray(b"a" * 32),
            ),
            TrustSealedTextKey(
                key_id="trust-sealed-note-v1",
                material=bytearray(b"b" * 32),
            ),
        ),
        active_key_id="trust-sealed-note-v2",
        retained_key_ids=("trust-sealed-note-v2", "trust-sealed-note-v1"),
    )
    provider = PsycopgTrustSealedNoteProvider(
        store=store,
        keyring=keyring,
        nonce_source=lambda count: b"n" * count,
    )
    replay = TrustPostgresReplayMaterial(
        idempotency_key_digest_key_ids=("trust-idempotency-2026-01",),
        idempotency_key_digests=(b"i" * 32,),
        payload_hash_key_ids=("trust-payload-2026-01",),
        payload_hashes=(b"p" * 32,),
    )

    sealed = provider.seal(
        actor_user_id=_uuid(1),
        session_id=_uuid(2),
        case_id=_uuid(3),
        purpose="TRIAGE_NOTE",
        raw_note="highly restricted note",
        raw_idempotency_key="save-note-001",
        replay_material=replay,
        retain_until=datetime(2030, 8, 19, tzinfo=timezone.utc),
    )

    call = next(
        call for call in connection.calls if "store_restricted_text_blob_v1" in call[0]
    )
    parameters = call[1]
    assert parameters[4] == ["trust-sealed-note-v2", "trust-sealed-note-v1"]
    assert parameters[5][0] == sealed.sealed_note_reference
    raw = b"highly restricted note"
    assert parameters[9] == b"n" * 12
    assert b"highly restricted note" not in parameters[10]
    assert hashlib.sha256(raw).digest() not in parameters[6]
    assert parameters[7] != hashlib.sha256(raw).digest()
    assert "highly restricted note" not in repr(sealed)
    assert "highly restricted note" not in repr(call)
    assert keyring.decrypt(
        key_id=parameters[8],
        nonce=parameters[9],
        ciphertext=parameters[10],
        aad=provider.associated_data(
            reference=parameters[5][0],
            case_id=_uuid(3),
            actor_user_id=_uuid(1),
            purpose="TRIAGE_NOTE",
            plaintext_hmac_sha256=parameters[6][0],
            key_id=parameters[8],
        ),
    ) == "highly restricted note"


def test_sealed_note_rotation_replay_accepts_retained_old_envelope() -> None:
    old_reference = "sealed://trust/triage-note/" + "a" * 64
    old_digest = bytes.fromhex("ab" * 32)
    sealed_at = datetime.now(timezone.utc) - timedelta(minutes=1)
    connection = _Connection(
        "trust_officer",
        store_result=(
            old_reference,
            old_digest,
            "TRUST_CASE_NOTE",
            sealed_at,
            True,
        ),
    )
    keyring = TrustSealedTextKeyring(
        keys=(
            TrustSealedTextKey(
                key_id="trust-sealed-note-v2",
                material=bytearray(b"a" * 32),
            ),
            TrustSealedTextKey(
                key_id="trust-sealed-note-v1",
                material=bytearray(b"b" * 32),
            ),
        ),
        active_key_id="trust-sealed-note-v2",
        retained_key_ids=("trust-sealed-note-v2", "trust-sealed-note-v1"),
    )
    raw_key = "save-note-001"
    expected_old_reference = keyring.reference(
        key_id="trust-sealed-note-v1",
        case_id=_uuid(3),
        actor_user_id=_uuid(1),
        purpose="TRIAGE_NOTE",
        raw_idempotency_key=raw_key,
    )
    connection.store_result = (
        expected_old_reference,
        old_digest,
        "TRUST_CASE_NOTE",
        sealed_at,
        True,
    )
    provider = PsycopgTrustSealedNoteProvider(
        store=PsycopgTrustRestrictedTextStore(
            officer_connections=_Source(connection)
        ),
        keyring=keyring,
        nonce_source=lambda count: b"n" * count,
    )
    replay = TrustPostgresReplayMaterial(
        idempotency_key_digest_key_ids=("trust-idempotency-2026-01",),
        idempotency_key_digests=(b"i" * 32,),
        payload_hash_key_ids=("trust-payload-2026-01",),
        payload_hashes=(b"p" * 32,),
    )

    sealed = provider.seal(
        actor_user_id=_uuid(1),
        session_id=_uuid(2),
        case_id=_uuid(3),
        purpose="TRIAGE_NOTE",
        raw_note="same retained note",
        raw_idempotency_key=raw_key,
        replay_material=replay,
        retain_until=datetime(2030, 8, 19, tzinfo=timezone.utc),
    )

    assert sealed.sealed_note_reference == expected_old_reference
    assert sealed.sealed_note_sha256 == old_digest.hex()


def test_outcome_provider_uses_fixed_safe_source_and_db_clock() -> None:
    evaluated_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    valid_until = evaluated_at + timedelta(minutes=5)
    source = {
        "action_codes": [],
        "active_holds": [],
        "case_aggregate_version": 8,
        "case_id": str(_uuid(3)),
        "case_status": "IN_REVIEW",
        "demand_aggregate_version": 7,
        "demand_content_sha256": "c" * 64,
        "demand_id": str(_uuid(4)),
        "demand_version_id": str(_uuid(5)),
        "demand_version_no": 2,
        "organization_id": str(_uuid(6)),
        "outcome_code": "NO_ACTION",
        "reason_codes": ["NO_POLICY_BREACH"],
        "report_content_sha256": "d" * 64,
        "report_id": str(_uuid(7)),
        "triage_version": 1,
    }
    canonical = json.dumps(source, sort_keys=True)
    connection = _Connection(
        "trust_officer",
        result=(canonical, evaluated_at, valid_until),
    )
    ids = _Ids(_uuid(8))
    provider = PsycopgTrustOutcomeEvidenceProvider(
        officer_connections=_Source(connection),
        id_source=ids,
    )

    evidence = provider.prepare_for_postgres(
        TrustOutcomeEvidenceRequest(
            actor_user_id=_uuid(1),
            session_id=_uuid(2),
            case_id=_uuid(3),
            expected_case_version=8,
            outcome_code="NO_ACTION",
            reason_codes=("NO_POLICY_BREACH",),
            action_codes=(),
        )
    )

    assert ids.kinds == ["trust_evidence_packet_version"]
    assert evidence.evaluated_at == evaluated_at
    assert evidence.valid_until == valid_until
    assert evidence.appeal_eligibility_code == "ELIGIBLE"
    assert evidence.appeal_deadline == evaluated_at + timedelta(days=7)
    assert evidence.redaction_profile_code == "PARTY_SAFE_V1"
    assert "BEGIN ISOLATION LEVEL REPEATABLE READ" in {
        sql for sql, _ in connection.calls
    }
    assert not any(
        "READ ONLY" in sql
        for sql, _ in connection.calls
        if sql.startswith("BEGIN")
    )
    assert any(
        "read_outcome_evidence_source_v1" in sql for sql, _ in connection.calls
    )


def test_demand_hold_provider_strictly_maps_exact_block_result() -> None:
    now = datetime.now(timezone.utc)
    echo = (
        _uuid(1),
        _uuid(2),
        _uuid(3),
        7,
        _uuid(4),
        b"c" * 32,
        "VERIFY_DEMAND",
        "demand-safety-hold-v1",
        "BLOCK",
        b"e" * 32,
        now - timedelta(seconds=1),
        now + timedelta(seconds=10),
    )
    connection = _Connection("trust_decision", result=echo)
    provider = PsycopgTrustDemandSafetyHoldProvider(
        decision_connections=_Source(connection),
    )

    result = provider.evaluate(
        actor_id=str(_uuid(1)),
        organization_id=str(_uuid(2)),
        demand_id=str(_uuid(3)),
        prospective_aggregate_version=7,
        demand_version_id=str(_uuid(4)),
        content_sha256=(b"c" * 32).hex(),
        action="VERIFY_DEMAND",
        policy_version="demand-safety-hold-v1",
    )

    assert result.decision is DemandHoldDecision.BLOCK
    assert result.valid_until == echo[-1]
    assert any(
        "trust_api.evaluate_demand_hold_v1" in sql for sql, _ in connection.calls
    )


def test_demand_hold_provider_retains_exact_matching_completion_evidence() -> None:
    now = datetime.now(timezone.utc)
    echo = (
        _uuid(1),
        _uuid(2),
        _uuid(3),
        8,
        _uuid(4),
        b"c" * 32,
        "REQUEST_MATCHING",
        "demand-safety-hold-v1",
        "ALLOW",
        b"e" * 32,
        now - timedelta(seconds=1),
        now + timedelta(seconds=10),
    )
    connection = _Connection("trust_decision", result=echo)
    provider = PsycopgTrustDemandSafetyHoldProvider(
        decision_connections=_Source(connection),
    )

    result = provider.evaluate_for_matching(
        actor_id=str(_uuid(1)),
        organization_id=str(_uuid(2)),
        demand_id=str(_uuid(3)),
        prospective_aggregate_version=8,
        demand_version_id=str(_uuid(4)),
        content_sha256=(b"c" * 32).hex(),
        action="REQUEST_MATCHING",
        policy_version="demand-safety-hold-v1",
    )

    assert isinstance(result, TrustDemandHoldEvidenceResult)
    assert result.decision is DemandHoldDecision.ALLOW
    assert result.evidence_sha256 == b"e" * 32
    assert result.evaluated_at == echo[-2]
    assert result.valid_until == echo[-1]
    assert len(connection.calls) > 0
    assert sum(
        "trust_api.evaluate_demand_hold_v1" in sql
        for sql, _ in connection.calls
    ) == 1
