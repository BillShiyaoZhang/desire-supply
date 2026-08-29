"""Production composition contracts for the Trust PostgreSQL vertical."""

from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace
from uuid import UUID

import pytest
from psycopg.pq import TransactionStatus

from desire_platform.trust_safety.adapters.postgres.gateway import (
    PsycopgTrustCommandGateway,
    PsycopgTrustReadGateway,
    PsycopgTrustReceiptProbe,
    TrustPostgresCommitOutcomeUnknownError,
    TrustPostgresRejectedError,
)
from desire_platform.trust_safety.adapters.postgres.migrations import (
    TRUST_REQUIRED_DEMAND_SCHEMA_VERSION,
    TRUST_REQUIRED_IAM_SCHEMA_VERSION,
    TRUST_SCHEMA_HEAD_VERSION,
)
from desire_platform.trust_safety.adapters.postgres.production import (
    PsycopgTrustHttpProjectionAdapter,
    PostgresSaveTrustTriageDraftHandler,
    TrustOwnedReportCursorKey,
    TrustOwnedReportCursorKeyring,
    TrustPostgresReceiptKey,
    TrustPostgresReceiptKeyring,
    build_trust_postgres_command_handlers,
)
from desire_platform.trust_safety.adapters.postgres.outcome_evidence import (
    PsycopgTrustOutcomeEvidenceProvider,
)
from desire_platform.trust_safety.adapters.postgres.readiness import (
    PsycopgTrustRuntimeReadiness,
)
from desire_platform.trust_safety.adapters.postgres.sealed_text import (
    PsycopgTrustRestrictedTextStore,
    PsycopgTrustSealedNoteProvider,
    TrustSealedTextKey,
    TrustSealedTextKeyring,
)
from desire_platform.trust_safety.application.commands import (
    SaveTrustTriageDraftCommand,
    TrustActorContext,
    TrustCommandResult,
)
from desire_platform.trust_safety.application.handlers import TrustApplicationError
from desire_platform.trust_safety.domain import HoldAction, SafetyCaseStatus
from desire_platform.trust_safety.http import TrustHttpPresenterBindings
from desire_platform.trust_safety.ports import TrustSealedNote


def _uuid(number: int) -> UUID:
    return UUID(f"c0000000-0000-4000-8000-{number:012d}")


def _actor() -> TrustActorContext:
    return TrustActorContext(
        actor_user_id=str(_uuid(1)),
        session_id=str(_uuid(2)),
        organization_id=None,
        correlation_id=str(_uuid(3)),
        causation_id=str(_uuid(4)),
        trace_id=str(_uuid(5)),
        original_actor_user_id=None,
    )


def _command(note: str = "restricted note") -> SaveTrustTriageDraftCommand:
    return SaveTrustTriageDraftCommand(
        case_id=str(_uuid(6)),
        expected_case_version=3,
        priority_code="P1",
        jurisdiction_code="PLATFORM_INTERNAL",
        severity_code="HIGH",
        issue_codes=("WORKFLOW_INTEGRITY_GAP",),
        investigation_step_codes=("CHECK_DEMAND_VERSION",),
        proposed_hold_actions=(HoldAction.VERIFY_DEMAND,),
        proposed_hold_ttl_minutes=120,
        restricted_note=note,
        idempotency_key="save-note-idempotency-001",
    )


def _result(*, replayed: bool) -> TrustCommandResult:
    return TrustCommandResult(
        case_id=str(_uuid(6)),
        case_status=SafetyCaseStatus.TRIAGING,
        aggregate_version=4,
        report_id=None,
        assignment_id=None,
        triage_draft_version=1,
        triage_version=None,
        hold_id=None,
        hold_version=None,
        outcome_version_id=None,
        replayed=replayed,
        event_types=("TrustTriageDraftSaved",),
        completed_at=datetime.now(timezone.utc),
    )


class _Cursor:
    def __init__(self, row=None, rows=None) -> None:
        self.row = row
        self.rows = rows

    def fetchone(self):
        return self.row

    def fetchmany(self, count: int):
        assert count == 2
        return self.rows or []


class _Connection:
    def __init__(
        self,
        role: str,
        *,
        replay=None,
        runtime_policy=None,
        normalize_timeouts: bool = False,
    ) -> None:
        self.autocommit = True
        self.info = SimpleNamespace(transaction_status=TransactionStatus.IDLE)
        self.role = role
        self.replay = replay
        self.runtime_policy = runtime_policy
        self.normalize_timeouts = normalize_timeouts

    def execute(self, statement, parameters=None):
        sql = str(statement)
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
            return _Cursor((value,))
        if "read_completed_command_receipt_v1" in sql:
            return _Cursor(rows=[] if self.replay is None else [(self.replay, True)])
        if "read_runtime_key_policy_v1" in sql:
            return _Cursor(rows=[self.runtime_policy])
        return _Cursor()


class _Source:
    def __init__(self, *connections: _Connection) -> None:
        self.connections = list(connections)

    def checkout(self):
        return self.connections.pop(0)

    def release(self, connection) -> None:
        pass

    def discard(self, connection) -> None:
        pass


class _ExplodingSources:
    def checkout(self):
        raise AssertionError("fresh PostgreSQL path must not run")

    def release(self, connection) -> None:
        pass

    def discard(self, connection) -> None:
        pass


class _ExplodingRuntime:
    def new_id(self, purpose: str):
        raise AssertionError("ID source must not run on completed replay")

    def now(self):
        raise AssertionError("clock must not run on completed replay")


def _receipt_keyring() -> TrustPostgresReceiptKeyring:
    return TrustPostgresReceiptKeyring(
        idempotency_keys=(
            TrustPostgresReceiptKey(
                purpose="IDEMPOTENCY",
                key_id="trust-idempotency-2026-01",
                material=bytearray(b"i" * 32),
            ),
        ),
        payload_hash_keys=(
            TrustPostgresReceiptKey(
                purpose="PAYLOAD_HASH",
                key_id="trust-payload-2026-01",
                material=bytearray(b"p" * 32),
            ),
        ),
    )


def _cursor_keyring() -> TrustOwnedReportCursorKeyring:
    return TrustOwnedReportCursorKeyring(
        keys=(
            TrustOwnedReportCursorKey(
                purpose="TRUST_REPORT_CURSOR",
                key_id="trust-report-cursor-2026-01",
                material=bytearray(b"c" * 32),
            ),
        ),
        active_key_id="trust-report-cursor-2026-01",
        retained_key_ids=("trust-report-cursor-2026-01",),
    )


def _exploding_sealer() -> PsycopgTrustSealedNoteProvider:
    store = PsycopgTrustRestrictedTextStore(
        officer_connections=_ExplodingSources()
    )
    keyring = TrustSealedTextKeyring(
        keys=(
            TrustSealedTextKey(
                key_id="trust-sealed-note-v1",
                material=bytearray(b"s" * 32),
            ),
        ),
        active_key_id="trust-sealed-note-v1",
        retained_key_ids=("trust-sealed-note-v1",),
    )
    return PsycopgTrustSealedNoteProvider(
        store=store,
        keyring=keyring,
        nonce_source=lambda count: (_ for _ in ()).throw(
            AssertionError("nonce source must not run on completed replay")
        ),
    )


def test_completed_save_replay_precedes_ids_clock_nonce_and_store() -> None:
    safe = {
        "aggregate_version": 4,
        "assignment_id": None,
        "case_id": str(_uuid(6)),
        "case_status": "TRIAGING",
        "completed_at": "2026-08-19T09:00:00Z",
        "event_types": ["TrustTriageDraftSaved"],
        "hold_id": None,
        "hold_version": None,
        "outcome_version_id": None,
        "report_id": None,
        "triage_draft_version": 1,
        "triage_version": None,
    }
    probe = PsycopgTrustReceiptProbe(
        reporter_connections=_ExplodingSources(),
        officer_connections=_Source(_Connection("trust_officer", replay=safe)),
    )
    gateway = PsycopgTrustCommandGateway(
        reporter_connections=_ExplodingSources(),
        officer_connections=_ExplodingSources(),
    )
    handler = PostgresSaveTrustTriageDraftHandler(
        gateway=gateway,
        receipt_probe=probe,
        receipt_keyring=_receipt_keyring(),
        id_source=_ExplodingRuntime(),
        clock=_ExplodingRuntime(),
        sealed_notes=_exploding_sealer(),
    )

    result = handler.handle(actor=_actor(), command=_command())

    assert result.replayed is True
    assert result.triage_draft_version == 1


def test_fresh_save_and_commit_unknown_use_probe_not_a_second_write(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    probe = PsycopgTrustReceiptProbe(
        reporter_connections=_ExplodingSources(),
        officer_connections=_ExplodingSources(),
    )
    gateway = PsycopgTrustCommandGateway(
        reporter_connections=_ExplodingSources(),
        officer_connections=_ExplodingSources(),
    )
    sealer = _exploding_sealer()
    replay = _result(replayed=True)
    probe_results = iter((None, replay))
    probe_calls: list[object] = []
    seal_calls: list[object] = []
    write_calls: list[object] = []
    monkeypatch.setattr(
        probe,
        "read_completed",
        lambda request: (probe_calls.append(request), next(probe_results))[1],
    )
    monkeypatch.setattr(
        sealer,
        "seal",
        lambda **values: (
            seal_calls.append(values),
            TrustSealedNote(
                sealed_note_reference="sealed://trust/triage-note/" + "a" * 64,
                sealed_note_sha256="b" * 64,
                retention_class="TRUST_CASE_NOTE",
                sealed_at=datetime.now(timezone.utc),
            ),
        )[1],
    )
    monkeypatch.setattr(
        gateway,
        "save_triage_draft",
        lambda request: (
            write_calls.append(request),
            (_ for _ in ()).throw(TrustPostgresCommitOutcomeUnknownError()),
        )[1],
    )

    class _Runtime:
        value = 10

        def new_id(self, purpose: str) -> UUID:
            self.value += 1
            return _uuid(self.value)

        def now(self) -> datetime:
            return datetime.now(timezone.utc)

    runtime = _Runtime()
    handler = PostgresSaveTrustTriageDraftHandler(
        gateway=gateway,
        receipt_probe=probe,
        receipt_keyring=_receipt_keyring(),
        id_source=runtime,
        clock=runtime,
        sealed_notes=sealer,
    )

    result = handler.handle(actor=_actor(), command=_command())

    assert result is replay
    assert len(probe_calls) == 2
    assert len(seal_calls) == 1
    assert len(write_calls) == 1


def test_same_key_different_note_conflicts_before_sealing_or_ids(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    probe = PsycopgTrustReceiptProbe(
        reporter_connections=_ExplodingSources(),
        officer_connections=_ExplodingSources(),
    )
    monkeypatch.setattr(
        probe,
        "read_completed",
        lambda request: (_ for _ in ()).throw(
            TrustPostgresRejectedError("IDEMPOTENCY_KEY_REUSED")
        ),
    )
    handler = PostgresSaveTrustTriageDraftHandler(
        gateway=PsycopgTrustCommandGateway(
            reporter_connections=_ExplodingSources(),
            officer_connections=_ExplodingSources(),
        ),
        receipt_probe=probe,
        receipt_keyring=_receipt_keyring(),
        id_source=_ExplodingRuntime(),
        clock=_ExplodingRuntime(),
        sealed_notes=_exploding_sealer(),
    )

    with pytest.raises(TrustApplicationError) as error:
        handler.handle(
            actor=_actor(),
            command=_command("different low entropy phrase"),
        )

    assert error.value.code == "IDEMPOTENCY_KEY_REUSED"


def test_receipt_keys_are_hidden_and_zeroized_on_close() -> None:
    keyring = _receipt_keyring()
    before = keyring.keyed_digest(
        "trust-idempotency-2026-01", b"canonical request"
    )
    assert len(before) == 64
    assert "iiii" not in repr(keyring)

    keyring.close()

    with pytest.raises(LookupError):
        keyring.keyed_digest(
            "trust-idempotency-2026-01", b"canonical request"
        )


def test_save_handler_rejects_generic_or_memory_dependencies() -> None:
    with pytest.raises(TypeError):
        PostgresSaveTrustTriageDraftHandler(
            gateway=object(),
            receipt_probe=object(),
            receipt_keyring=_receipt_keyring(),
            id_source=_ExplodingRuntime(),
            clock=_ExplodingRuntime(),
            sealed_notes=_exploding_sealer(),
        )


def test_invalid_command_never_reaches_postgres() -> None:
    handler = PostgresSaveTrustTriageDraftHandler(
        gateway=PsycopgTrustCommandGateway(
            reporter_connections=_ExplodingSources(),
            officer_connections=_ExplodingSources(),
        ),
        receipt_probe=PsycopgTrustReceiptProbe(
            reporter_connections=_ExplodingSources(),
            officer_connections=_ExplodingSources(),
        ),
        receipt_keyring=_receipt_keyring(),
        id_source=_ExplodingRuntime(),
        clock=_ExplodingRuntime(),
        sealed_notes=_exploding_sealer(),
    )
    with pytest.raises(TrustApplicationError) as error:
        handler.handle(actor=_actor(), command=object())
    assert error.value.code == "INVALID_REQUEST"


def test_runtime_readiness_matches_all_four_roles_to_both_keyrings() -> None:
    policy = (
        "trust-idempotency-2026-01",
        ["trust-idempotency-2026-01"],
        "trust-payload-2026-01",
        ["trust-payload-2026-01"],
        "trust-command-json-v1",
        ["trust-command-json-v1"],
        "trust-sealed-note-v1",
        ["trust-sealed-note-v1"],
    )
    sealed_keyring = TrustSealedTextKeyring(
        keys=(
            TrustSealedTextKey(
                key_id="trust-sealed-note-v1",
                material=bytearray(b"s" * 32),
            ),
        ),
        active_key_id="trust-sealed-note-v1",
        retained_key_ids=("trust-sealed-note-v1",),
    )
    readiness = PsycopgTrustRuntimeReadiness(
        reporter_connections=_Source(
            _Connection("trust_self", runtime_policy=policy)
        ),
        officer_connections=_Source(
            _Connection("trust_officer", runtime_policy=policy)
        ),
        appeal_connections=_Source(
            _Connection("trust_appeal", runtime_policy=policy)
        ),
        decision_connections=_Source(
            _Connection("trust_decision", runtime_policy=policy)
        ),
    )

    projection = readiness.verify(
        receipt_keyring=_receipt_keyring(),
        sealed_text_keyring=sealed_keyring,
    )

    assert projection.retained_payload_key_ids == (
        "trust-payload-2026-01",
    )
    assert projection.retained_sealed_text_key_ids == (
        "trust-sealed-note-v1",
    )


def test_runtime_readiness_accepts_postgres_canonical_timeout_display() -> None:
    policy = (
        "trust-idempotency-2026-01",
        ["trust-idempotency-2026-01"],
        "trust-payload-2026-01",
        ["trust-payload-2026-01"],
        "trust-command-json-v1",
        ["trust-command-json-v1"],
        "trust-sealed-note-v1",
        ["trust-sealed-note-v1"],
    )
    sources = tuple(
        _Source(
            _Connection(
                role,
                runtime_policy=policy,
                normalize_timeouts=True,
            )
        )
        for role in (
            "trust_self",
            "trust_officer",
            "trust_appeal",
            "trust_decision",
        )
    )
    readiness = PsycopgTrustRuntimeReadiness(
        reporter_connections=sources[0],
        officer_connections=sources[1],
        appeal_connections=sources[2],
        decision_connections=sources[3],
    )

    projection = readiness.verify(
        receipt_keyring=_receipt_keyring(),
        sealed_text_keyring=TrustSealedTextKeyring(
            keys=(
                TrustSealedTextKey(
                    key_id="trust-sealed-note-v1",
                    material=bytearray(b"s" * 32),
                ),
            ),
            active_key_id="trust-sealed-note-v1",
            retained_key_ids=("trust-sealed-note-v1",),
        ),
    )

    assert projection.active_canonicalization_version == "trust-command-json-v1"


def test_postgres_factory_builds_exact_http_binding_and_wrong_mapping_fails() -> None:
    runtime = _ExplodingRuntime()
    gateway = PsycopgTrustCommandGateway(
        reporter_connections=_ExplodingSources(),
        officer_connections=_ExplodingSources(),
    )
    probe = PsycopgTrustReceiptProbe(
        reporter_connections=_ExplodingSources(),
        officer_connections=_ExplodingSources(),
    )
    handlers = build_trust_postgres_command_handlers(
        gateway=gateway,
        receipt_probe=probe,
        receipt_keyring=_receipt_keyring(),
        id_source=runtime,
        clock=runtime,
        sealed_notes=_exploding_sealer(),
        outcome_evidence=PsycopgTrustOutcomeEvidenceProvider(
            officer_connections=_ExplodingSources(),
            id_source=runtime,
        ),
    )
    projections = PsycopgTrustHttpProjectionAdapter(
        read_gateway=PsycopgTrustReadGateway(
            reporter_connections=_ExplodingSources(),
            officer_connections=_ExplodingSources(),
        ),
        cursor_keyring=_cursor_keyring(),
    )

    bindings = TrustHttpPresenterBindings(
        projections=projections,
        **handlers.__dict__,
    )

    assert bindings.projections is projections
    with pytest.raises(TypeError, match="command handlers"):
        TrustHttpPresenterBindings(
            projections=projections,
            **{
                **handlers.__dict__,
                "claim_case": handlers.release_assignment,
            },
        )
    generic_postgres_type = type(
        "GenericPostgresSubmitSafetyReportHandler",
        (type(handlers.submit_report),),
        {},
    )
    generic_postgres_handler = object.__new__(generic_postgres_type)
    with pytest.raises(TypeError, match="command handlers"):
        TrustHttpPresenterBindings(
            projections=projections,
            **{
                **handlers.__dict__,
                "submit_report": generic_postgres_handler,
            },
        )
