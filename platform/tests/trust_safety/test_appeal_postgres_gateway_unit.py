"""Focused non-PostgreSQL proofs for the closed Appeal production boundary."""

from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace
from uuid import UUID

import pytest
from psycopg.pq import TransactionStatus
from psycopg.types.json import Jsonb

from desire_platform.trust_safety.adapters.postgres.appeal_gateway import (
    AppealCompletedReceiptProbeRequest,
    AppealPostgresCommandContext,
    AppealPostgresCommitOutcomeUnknownError,
    AppealPostgresConfigurationError,
    AppealPostgresReceiptMaterial,
    AppealPostgresRejectedError,
    AppealPostgresReplayMaterial,
    AppealRestrictedTextStoreRequest,
    AppealReviewAssessmentPostgres,
    ClaimAppealPostgresRequest,
    DecideAppealPostgresRequest,
    OpenAppealPostgresRequest,
    PsycopgAppealCommandGateway,
    PsycopgAppealReadGateway,
    PsycopgAppealReceiptProbe,
    PsycopgAppealRestrictedTextStore,
    ReleaseAppealAssignmentPostgresRequest,
    SaveAppealDraftPostgresRequest,
    SaveAppealReviewDraftPostgresRequest,
    SubmitAppealPostgresRequest,
    _database_error,
)
from desire_platform.trust_safety.adapters.postgres.appeal_production import (
    AppealPostgresReceiptKey,
    AppealPostgresReceiptKeyring,
    AppealSealedTextKey,
    AppealSealedTextKeyring,
    PostgresReleaseAppealAssignmentHandler,
    PsycopgAppealSealedTextProvider,
)
from desire_platform.trust_safety.adapters.postgres.migrations import (
    TRUST_REQUIRED_DEMAND_SCHEMA_VERSION,
    TRUST_REQUIRED_IAM_SCHEMA_VERSION,
    TRUST_SCHEMA_HEAD_VERSION,
)
from desire_platform.trust_safety.application.appeal_commands import (
    AppealCommandResult,
    ReleaseAppealAssignmentCommand,
)
from desire_platform.trust_safety.application.commands import TrustActorContext
from desire_platform.trust_safety.domain import (
    AppealAssignmentReleaseReason,
    AppealStatus,
)
from desire_platform.trust_safety.ports import AppealSealedTextUnavailableError


def _uuid(number: int) -> UUID:
    return UUID(f"d0000000-0000-4000-8000-{number:012d}")


def _context() -> AppealPostgresCommandContext:
    return AppealPostgresCommandContext(
        actor_user_id=_uuid(1),
        session_id=_uuid(2),
        correlation_id=_uuid(3),
        causation_id=_uuid(4),
        trace_id=_uuid(5),
    )


def _receipt() -> AppealPostgresReceiptMaterial:
    return AppealPostgresReceiptMaterial(
        receipt_id=_uuid(6),
        audit_event_id=_uuid(7),
        outbox_event_id=_uuid(8),
        idempotency_key_digest_key_ids=("trust-idempotency-2026-01",),
        idempotency_key_digests=(b"i" * 32,),
        payload_hash_key_ids=("trust-payload-2026-01",),
        payload_hashes=(b"p" * 32,),
    )


def _replay_material() -> AppealPostgresReplayMaterial:
    return AppealPostgresReplayMaterial(
        idempotency_key_digest_key_ids=("trust-idempotency-2026-01",),
        idempotency_key_digests=(b"i" * 32,),
        payload_hash_key_ids=("trust-payload-2026-01",),
        payload_hashes=(b"p" * 32,),
    )


def _safe_response(*, replayed_event: str = "AppealReviewAssignmentReleased"):
    return {
        "aggregate_version": 4,
        "appeal_id": str(_uuid(20)),
        "appeal_status": "SUBMITTED",
        "application_draft_version": 1,
        "application_version": 1,
        "completed_at": "2026-08-19T09:00:00Z",
        "decision_version_id": None,
        "event_types": [replayed_event],
        "review_draft_version": None,
    }


class _Cursor:
    def __init__(self, row=None, rows=None) -> None:
        self.row = row
        self.rows = rows

    def fetchone(self):
        return self.row

    def fetchmany(self, count: int):
        assert count == 2
        if self.rows is not None:
            return self.rows
        return [] if self.row is None else [self.row]


class _Connection:
    def __init__(
        self,
        role: str,
        *,
        function_result=None,
        read_rows=None,
        fail_commit: bool = False,
        normalize_timeouts: bool = False,
    ) -> None:
        self.autocommit = True
        self.info = SimpleNamespace(transaction_status=TransactionStatus.IDLE)
        self.role = role
        self.function_result = function_result
        self.read_rows = read_rows
        self.fail_commit = fail_commit
        self.normalize_timeouts = normalize_timeouts
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
        if "trust_api.release_appeal_assignment_v1" in sql:
            return _Cursor(self.function_result)
        if "trust_api.read_completed_appeal_receipt_v1" in sql:
            return _Cursor(rows=self.read_rows)
        if (
            "trust_api.list_appeal_queue_v1" in sql
            or "trust_api.list_my_active_appeal_assignments_v1" in sql
            or "trust_api.list_my_completed_appeal_reviews_v1" in sql
            or "trust_api.read_my_completed_appeal_review_v1" in sql
        ):
            return _Cursor(rows=self.read_rows)
        if sql == "COMMIT" and self.fail_commit:
            raise ConnectionError("commit acknowledgement lost")
        return _Cursor()


class _Source:
    def __init__(self, *connections: _Connection) -> None:
        self.connections = list(connections)
        self.released: list[_Connection] = []
        self.discarded: list[_Connection] = []
        self.checkouts = 0

    def checkout(self):
        self.checkouts += 1
        return self.connections.pop(0)

    def release(self, connection) -> None:
        self.released.append(connection)

    def discard(self, connection) -> None:
        self.discarded.append(connection)


class _ExplodingSource:
    def __init__(self) -> None:
        self.checkouts = 0

    def checkout(self):
        self.checkouts += 1
        raise AssertionError("database path must not run")

    def release(self, connection) -> None:
        raise AssertionError("database path must not run")

    def discard(self, connection) -> None:
        pass


def _release_request() -> ReleaseAppealAssignmentPostgresRequest:
    return ReleaseAppealAssignmentPostgresRequest(
        context=_context(),
        receipt=_receipt(),
        appeal_id=_uuid(20),
        expected_appeal_version=3,
        reason_code="WORKLOAD_RELEASE",
    )


def test_command_gateway_has_exactly_seven_named_writes_and_close() -> None:
    public = {
        name
        for name, value in PsycopgAppealCommandGateway.__dict__.items()
        if callable(value) and not name.startswith("_")
    }
    assert public == {
        "claim_appeal",
        "close",
        "decide_appeal",
        "open_appeal",
        "release_appeal_assignment",
        "save_appeal_draft",
        "save_appeal_review_draft",
        "submit_appeal",
    }


def test_command_gateway_accepts_postgres_canonical_timeout_display() -> None:
    connection = _Connection(
        "trust_appeal",
        function_result=(_safe_response(), False),
        normalize_timeouts=True,
    )
    gateway = PsycopgAppealCommandGateway(
        applicant_connections=_Source(_Connection("trust_self")),
        reviewer_connections=_Source(connection),
    )

    result = gateway.release_appeal_assignment(_release_request())

    assert result.replayed is False


def test_all_seven_write_dtos_bind_the_frozen_abi_counts_and_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    gateway = PsycopgAppealCommandGateway(
        applicant_connections=_ExplodingSource(),
        reviewer_connections=_ExplodingSource(),
    )
    captured = []

    def capture(**values):
        captured.append(values)
        return object()

    monkeypatch.setattr(gateway, "_run", capture)
    reference = "sealed://trust/appeal-statement/" + "a" * 64
    assessment = AppealReviewAssessmentPostgres(
        ground="PROCEDURAL_ERROR",
        assessment_code="ACCEPTED",
        finding_codes=("PROCEDURE_MATERIAL_ERROR",),
        accepted_evidence_reference_ids=(),
    )
    requests = (
        (
            gateway.open_appeal,
            OpenAppealPostgresRequest(
                context=_context(),
                receipt=_receipt(),
                organization_id=_uuid(9),
                appeal_id=_uuid(20),
                source_outcome_version_id=_uuid(21),
            ),
            15,
        ),
        (
            gateway.save_appeal_draft,
            SaveAppealDraftPostgresRequest(
                context=_context(),
                receipt=_receipt(),
                organization_id=_uuid(9),
                appeal_id=_uuid(20),
                expected_appeal_version=1,
                sealed_statement_reference=reference,
                sealed_statement_sha256=b"s" * 32,
                grounds=("PROCEDURAL_ERROR",),
                requested_outcome="MODIFY_MEASURE",
                new_evidence_reference_ids=(),
            ),
            20,
        ),
        (
            gateway.submit_appeal,
            SubmitAppealPostgresRequest(
                context=_context(),
                receipt=_receipt(),
                organization_id=_uuid(9),
                appeal_id=_uuid(20),
                expected_appeal_version=2,
                expected_draft_version=1,
            ),
            16,
        ),
        (
            gateway.claim_appeal,
            ClaimAppealPostgresRequest(
                context=_context(),
                receipt=_receipt(),
                assignment_id=_uuid(22),
                appeal_id=_uuid(20),
                expected_appeal_version=3,
            ),
            15,
        ),
        (gateway.release_appeal_assignment, _release_request(), 15),
        (
            gateway.save_appeal_review_draft,
            SaveAppealReviewDraftPostgresRequest(
                context=_context(),
                receipt=_receipt(),
                appeal_id=_uuid(20),
                expected_appeal_version=4,
                sealed_review_note_reference=(
                    "sealed://trust/appeal-review-note/" + "b" * 64
                ),
                sealed_review_note_sha256=b"n" * 32,
                assessments=(assessment,),
                reason_codes=("PROCEDURAL_REVIEW_COMPLETE",),
                remedy_delta_codes=("NO_CHANGE",),
            ),
            19,
        ),
        (
            gateway.decide_appeal,
            DecideAppealPostgresRequest(
                context=_context(),
                receipt=_receipt(),
                decision_version_id=_uuid(23),
                appeal_id=_uuid(20),
                expected_appeal_version=5,
                expected_review_draft_version=1,
                decision_code="AFFIRM",
            ),
            17,
        ),
    )
    for method, request, expected_count in requests:
        method(request)
        call = captured[-1]
        assert call["count"] == expected_count
        assert len(call["parameters"]) == expected_count

    open_parameters = captured[0]["parameters"]
    assert open_parameters[:11] == (
        _uuid(1),
        _uuid(2),
        _uuid(9),
        _uuid(3),
        _uuid(4),
        _uuid(5),
        _uuid(6),
        _uuid(7),
        _uuid(8),
        _uuid(20),
        _uuid(21),
    )
    release_parameters = captured[4]["parameters"]
    assert release_parameters[8:11] == (_uuid(20), 3, "WORKLOAD_RELEASE")
    review_assessments = captured[5]["parameters"][16]
    assert isinstance(review_assessments, Jsonb)
    assert review_assessments.obj == [dict(assessment.as_json())]


def test_commit_unknown_is_surfaced_without_repeating_the_write() -> None:
    first = _Connection(
        "trust_appeal",
        function_result=(_safe_response(), False),
        fail_commit=True,
    )
    unused = _Connection(
        "trust_appeal", function_result=(_safe_response(), True)
    )
    reviewer = _Source(first, unused)
    gateway = PsycopgAppealCommandGateway(
        applicant_connections=_Source(_Connection("trust_self")),
        reviewer_connections=reviewer,
    )

    with pytest.raises(AppealPostgresCommitOutcomeUnknownError):
        gateway.release_appeal_assignment(_release_request())

    writes = [
        sql
        for sql, _ in first.calls
        if "trust_api.release_appeal_assignment_v1" in sql
    ]
    assert writes == [writes[0]]
    assert reviewer.checkouts == 1
    assert reviewer.discarded == [first]
    assert reviewer.connections == [unused]


def test_reviewer_receipt_probe_uses_none_organization_and_a_fresh_checkout() -> None:
    first = _Connection(
        "trust_appeal", read_rows=[(_safe_response(), True)]
    )
    second = _Connection(
        "trust_appeal", read_rows=[(_safe_response(), True)]
    )
    reviewer = _Source(first, second)
    probe = PsycopgAppealReceiptProbe(
        applicant_connections=_Source(_Connection("trust_self")),
        reviewer_connections=reviewer,
    )
    request = AppealCompletedReceiptProbeRequest(
        context=_context(),
        material=_replay_material(),
        operation="RELEASE_APPEAL_ASSIGNMENT",
        organization_id=None,
        target_appeal_id=_uuid(20),
        expected_appeal_version=3,
    )

    assert probe.read_completed(request).replayed is True
    assert probe.read_completed(request).replayed is True
    assert reviewer.checkouts == 2
    for connection in (first, second):
        query = next(
            parameters
            for sql, parameters in connection.calls
            if "read_completed_appeal_receipt_v1" in sql
        )
        assert query[2] is None
        configured = {
            parameters[0]: parameters[1]
            for sql, parameters in connection.calls
            if "pg_catalog.set_config" in sql
        }
        assert configured["app.organization_id"] == ""
        assert configured["app.appeal_id"] == str(_uuid(20))


def test_open_receipt_probe_has_no_candidate_target() -> None:
    request = AppealCompletedReceiptProbeRequest(
        context=_context(),
        material=_replay_material(),
        operation="OPEN_APPEAL",
        organization_id=_uuid(9),
        target_appeal_id=None,
        expected_appeal_version=None,
    )
    assert request.target_appeal_id is None
    with pytest.raises(ValueError):
        AppealCompletedReceiptProbeRequest(
            context=_context(),
            material=_replay_material(),
            operation="OPEN_APPEAL",
            organization_id=_uuid(9),
            target_appeal_id=_uuid(20),
            expected_appeal_version=None,
        )
    with pytest.raises(ValueError):
        AppealCompletedReceiptProbeRequest(
            context=_context(),
            material=_replay_material(),
            operation="SUBMIT_APPEAL",
            organization_id=_uuid(9),
            target_appeal_id=None,
            expected_appeal_version=2,
        )


def test_open_receipt_probe_supports_true_miss_then_stored_target_replay() -> None:
    open_safe = {
        "aggregate_version": 1,
        "appeal_id": str(_uuid(20)),
        "appeal_status": "DRAFT",
        "application_draft_version": None,
        "application_version": None,
        "completed_at": "2026-08-19T09:00:00Z",
        "decision_version_id": None,
        "event_types": ["AppealOpened"],
        "review_draft_version": None,
    }
    applicant = _Source(
        _Connection("trust_self", read_rows=[]),
        _Connection("trust_self", read_rows=[(open_safe, True)]),
    )
    probe = PsycopgAppealReceiptProbe(
        applicant_connections=applicant,
        reviewer_connections=_Source(_Connection("trust_appeal")),
    )
    request = AppealCompletedReceiptProbeRequest(
        context=_context(),
        material=_replay_material(),
        operation="OPEN_APPEAL",
        organization_id=_uuid(9),
        target_appeal_id=None,
        expected_appeal_version=None,
    )

    assert probe.read_completed(request) is None
    replay = probe.read_completed(request)
    assert replay is not None
    assert replay.replayed is True
    assert replay.appeal_id == str(_uuid(20))
    assert applicant.checkouts == 2
    for connection in applicant.released:
        begin_statements = [
            sql for sql, _ in connection.calls if sql.startswith("BEGIN")
        ]
        assert begin_statements == ["BEGIN ISOLATION LEVEL READ COMMITTED"]
        assert all("READ ONLY" not in sql for sql in begin_statements)


def test_extra_read_projection_key_fails_closed() -> None:
    connection = _Connection(
        "trust_appeal",
        read_rows=[
            (
                {
                    "entity_tag": '"appeal-1-0123456789abcdef01234567"',
                    "items": [],
                    "unexpected": True,
                },
            )
        ],
    )
    gateway = PsycopgAppealReadGateway(
        applicant_connections=_Source(_Connection("trust_self")),
        reviewer_connections=_Source(connection),
    )
    with pytest.raises(AppealPostgresConfigurationError):
        gateway.list_appeal_queue(
            actor_user_id=_uuid(1), session_id=_uuid(2), limit=20
        )


def test_my_active_appeal_assignments_use_frozen_abi_and_minimal_projection() -> None:
    projection = {
        "entity_tag": '"appeal-4-0123456789abcdef01234567"',
        "items": [
            {
                "appeal_id": str(_uuid(20)),
                "assignment_expires_at": "2026-08-19T13:00:00Z",
            }
        ],
    }
    connection = _Connection(
        "trust_appeal",
        read_rows=[(projection,)],
    )
    gateway = PsycopgAppealReadGateway(
        applicant_connections=_Source(_Connection("trust_self")),
        reviewer_connections=_Source(connection),
    )

    result = gateway.list_my_active_appeal_assignments(
        actor_user_id=_uuid(1), session_id=_uuid(2), limit=100
    )

    assert result.entity_tag == projection["entity_tag"]
    assert result.items[0].appeal_id == str(_uuid(20))
    calls = [
        (statement, parameters)
        for statement, parameters in connection.calls
        if "list_my_active_appeal_assignments_v1" in statement
    ]
    assert calls == [
        (
            "SELECT projection FROM "
            "trust_api.list_my_active_appeal_assignments_v1(%s,%s,%s)",
            (_uuid(1), _uuid(2), 100),
        )
    ]


def test_my_active_appeal_assignments_fail_closed_on_no_row_or_rich_item() -> None:
    missing = PsycopgAppealReadGateway(
        applicant_connections=_Source(_Connection("trust_self")),
        reviewer_connections=_Source(
            _Connection("trust_appeal", read_rows=[])
        ),
    )
    with pytest.raises(AppealPostgresRejectedError, match="APPEAL_NOT_FOUND"):
        missing.list_my_active_appeal_assignments(
            actor_user_id=_uuid(1), session_id=_uuid(2), limit=100
        )

    rich = {
        "entity_tag": '"appeal-4-0123456789abcdef01234567"',
        "items": [
            {
                "appeal_id": str(_uuid(20)),
                "assignment_expires_at": "2026-08-19T13:00:00Z",
                "assignment_id": str(_uuid(21)),
            }
        ],
    }
    unsafe = PsycopgAppealReadGateway(
        applicant_connections=_Source(_Connection("trust_self")),
        reviewer_connections=_Source(
            _Connection("trust_appeal", read_rows=[(rich,)])
        ),
    )
    with pytest.raises(AppealPostgresConfigurationError):
        unsafe.list_my_active_appeal_assignments(
            actor_user_id=_uuid(1), session_id=_uuid(2), limit=100
        )


def test_completed_appeal_history_uses_frozen_abi_and_strict_descending_order() -> None:
    projection = {
        "entity_tag": '"appeal-6-0123456789abcdef01234567"',
        "has_more": True,
        "items": [
            {
                "appeal_id": str(_uuid(21)),
                "decided_at": "2026-08-19T09:00:00Z",
                "decision_code": "AFFIRM",
            },
            {
                "appeal_id": str(_uuid(20)),
                "decided_at": "2026-08-19T09:00:00Z",
                "decision_code": "MODIFY",
            },
        ],
    }
    connection = _Connection("trust_appeal", read_rows=[(projection,)])
    gateway = PsycopgAppealReadGateway(
        applicant_connections=_Source(_Connection("trust_self")),
        reviewer_connections=_Source(connection),
    )

    result = gateway.list_my_completed_appeal_assignments(
        actor_user_id=_uuid(1), session_id=_uuid(2), limit=100
    )

    assert [item.appeal_id for item in result.items] == [
        str(_uuid(21)),
        str(_uuid(20)),
    ]
    assert result.has_more is True
    calls = [
        (statement, parameters)
        for statement, parameters in connection.calls
        if "list_my_completed_appeal_reviews_v1" in statement
    ]
    assert calls == [
        (
            "SELECT projection FROM "
            "trust_api.list_my_completed_appeal_reviews_v1(%s,%s,%s)",
            (_uuid(1), _uuid(2), 100),
        )
    ]
    configured = [
        parameters
        for statement, parameters in connection.calls
        if "pg_catalog.set_config" in statement
    ]
    assert ("app.appeal_scope_kind", "APPEAL_COMPLETED_HISTORY_READ") in configured
    assert ("app.operation", "READ_ASSIGNED_APPEAL") in configured


def test_completed_appeal_history_rejects_same_timestamp_reverse_order() -> None:
    reverse = {
        "entity_tag": '"appeal-6-0123456789abcdef01234567"',
        "has_more": False,
        "items": [
            {
                "appeal_id": str(_uuid(20)),
                "decided_at": "2026-08-19T09:00:00Z",
                "decision_code": "AFFIRM",
            },
            {
                "appeal_id": str(_uuid(21)),
                "decided_at": "2026-08-19T09:00:00Z",
                "decision_code": "MODIFY",
            },
        ],
    }
    gateway = PsycopgAppealReadGateway(
        applicant_connections=_Source(_Connection("trust_self")),
        reviewer_connections=_Source(
            _Connection("trust_appeal", read_rows=[(reverse,)])
        ),
    )

    with pytest.raises(AppealPostgresConfigurationError):
        gateway.list_my_completed_appeal_assignments(
            actor_user_id=_uuid(1), session_id=_uuid(2), limit=100
        )


def test_completed_appeal_detail_is_exact_and_party_safe() -> None:
    projection = {
        "appeal_id": str(_uuid(20)),
        "status": "DECIDED",
        "application": {
            "grounds": ["PROCEDURAL_ERROR"],
            "new_evidence_reference_ids": [],
            "requested_outcome": "MODIFY_MEASURE",
            "statement_recorded": True,
            "submitted_at": "2026-08-19T08:00:00Z",
        },
        "decision": {
            "assessments": [
                {
                    "accepted_evidence_reference_ids": [],
                    "assessment_code": "ACCEPTED",
                    "finding_codes": ["PROCEDURE_MATERIAL_ERROR"],
                    "ground": "PROCEDURAL_ERROR",
                }
            ],
            "decided_at": "2026-08-19T09:00:00Z",
            "decision_code": "MODIFY",
            "decision_sha256": "a" * 64,
            "decision_version_id": str(_uuid(30)),
            "policy_version": "appeal-decision-v1",
            "reason_codes": ["PROCEDURAL_REVIEW_COMPLETE"],
            "remedy_delta_codes": ["NARROW_CORRECTIVE_MEASURE"],
        },
        "review_note_recorded": True,
        "entity_tag": '"appeal-6-0123456789abcdef01234567"',
    }
    connection = _Connection("trust_appeal", read_rows=[(projection,)])
    gateway = PsycopgAppealReadGateway(
        applicant_connections=_Source(_Connection("trust_self")),
        reviewer_connections=_Source(connection),
    )

    result = gateway.read_my_completed_appeal(
        actor_user_id=_uuid(1),
        session_id=_uuid(2),
        appeal_id=_uuid(20),
    )

    assert result.status == "DECIDED"
    assert result.review_note_recorded is True
    assert result.application.statement_recorded is True
    assert result.decision.decision_code == "MODIFY"
    assert set(vars(result)) == {
        "appeal_id",
        "application",
        "decision",
        "entity_tag",
        "review_note_recorded",
        "status",
    }
    call = next(
        value
        for value in connection.calls
        if "read_my_completed_appeal_review_v1" in value[0]
    )
    assert call == (
        "SELECT projection FROM "
        "trust_api.read_my_completed_appeal_review_v1(%s,%s,%s)",
        (_uuid(1), _uuid(2), _uuid(20)),
    )

    unsafe = dict(projection, reviewer_user_id=str(_uuid(1)))
    closed_gateway = PsycopgAppealReadGateway(
        applicant_connections=_Source(_Connection("trust_self")),
        reviewer_connections=_Source(
            _Connection("trust_appeal", read_rows=[(unsafe,)])
        ),
    )
    with pytest.raises(AppealPostgresConfigurationError):
        closed_gateway.read_my_completed_appeal(
            actor_user_id=_uuid(1),
            session_id=_uuid(2),
            appeal_id=_uuid(20),
        )


@pytest.mark.parametrize(
    "code",
    (
        "APPEAL_APPLICATION_FROZEN",
        "APPEAL_DEADLINE_PASSED",
        "APPEAL_DRAFT_VERSION_CONFLICT",
    ),
)
def test_three_state_conflicts_are_the_only_new_public_diagnostics(code: str) -> None:
    error = RuntimeError(code)
    error.diag = SimpleNamespace(message_primary=code)
    translated = _database_error(error)
    assert isinstance(translated, AppealPostgresRejectedError)
    assert translated.code == code

    internal = RuntimeError("APPEAL_SEALED_TEXT_BINDING_CORRUPT")
    internal.diag = SimpleNamespace(
        message_primary="APPEAL_SEALED_TEXT_BINDING_CORRUPT"
    )
    internal.sqlstate = "23505"
    assert _database_error(internal) is None


def test_unknown_sealed_purpose_is_rejected_before_nonce_or_store() -> None:
    applicant, reviewer = _ExplodingSource(), _ExplodingSource()
    store = PsycopgAppealRestrictedTextStore(
        applicant_connections=applicant,
        reviewer_connections=reviewer,
    )
    keyring = AppealSealedTextKeyring(
        keys=(
            AppealSealedTextKey(
                key_id="appeal-sealed-2026-01", material=bytearray(b"s" * 32)
            ),
        ),
        active_key_id="appeal-sealed-2026-01",
        retained_key_ids=("appeal-sealed-2026-01",),
    )
    nonce_calls = []
    provider = PsycopgAppealSealedTextProvider(
        store=store,
        keyring=keyring,
        nonce_source=lambda size: (nonce_calls.append(size), b"n" * size)[1],
    )

    with pytest.raises(AppealSealedTextUnavailableError):
        provider.seal(
            actor_user_id=_uuid(1),
            session_id=_uuid(2),
            organization_id=_uuid(9),
            appeal_id=_uuid(20),
            purpose="TRIAGE_NOTE",
            raw_text="must never be encrypted for an unknown purpose",
            raw_idempotency_key="appeal-sealed-key-001",
            replay_material=_replay_material(),
            retain_until=datetime(2030, 1, 1, tzinfo=timezone.utc),
        )

    assert nonce_calls == []
    assert applicant.checkouts == reviewer.checkouts == 0


def test_applicant_sealed_request_forbids_reviewer_duty_echo() -> None:
    common = dict(
        actor_user_id=_uuid(1),
        session_id=_uuid(2),
        organization_id=_uuid(9),
        appeal_id=_uuid(20),
        purpose_code="APPEAL_STATEMENT",
        encryption_key_ids=("appeal-sealed-2026-01",),
        candidate_references=(
            "sealed://trust/appeal-statement/" + "a" * 64,
        ),
        plaintext_hmac_sha256s=(b"h" * 32,),
        envelope_sha256=b"e" * 32,
        encryption_key_id="appeal-sealed-2026-01",
        nonce=b"n" * 12,
        ciphertext=b"c" * 17,
        aad_sha256=b"a" * 32,
        replay_material=_replay_material(),
        retention_class="APPEAL_RESTRICTED_TEXT",
        retain_until=datetime(2030, 1, 1, tzinfo=timezone.utc),
    )
    with pytest.raises(ValueError):
        AppealRestrictedTextStoreRequest(
            **common,
            duty_grant_id=_uuid(30),
            duty_grant_version=1,
        )


def test_production_handler_recovers_commit_unknown_only_via_receipt_probe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    applicant_probe, reviewer_probe = _ExplodingSource(), _ExplodingSource()
    probe = PsycopgAppealReceiptProbe(
        applicant_connections=applicant_probe,
        reviewer_connections=reviewer_probe,
    )
    gateway = PsycopgAppealCommandGateway(
        applicant_connections=_ExplodingSource(),
        reviewer_connections=_ExplodingSource(),
    )
    recovered = AppealCommandResult(
        appeal_id=str(_uuid(20)),
        appeal_status=AppealStatus.SUBMITTED,
        aggregate_version=4,
        application_draft_version=1,
        application_version=1,
        review_draft_version=None,
        decision_version_id=None,
        replayed=True,
        event_types=("AppealReviewAssignmentReleased",),
        completed_at=datetime(2026, 8, 19, 9, tzinfo=timezone.utc),
    )
    probes = iter((None, recovered))
    probe_calls = []
    write_calls = []
    monkeypatch.setattr(
        probe,
        "read_completed",
        lambda request: (probe_calls.append(request), next(probes))[1],
    )
    monkeypatch.setattr(
        gateway,
        "release_appeal_assignment",
        lambda request: (
            write_calls.append(request),
            (_ for _ in ()).throw(AppealPostgresCommitOutcomeUnknownError()),
        )[1],
    )

    class _Runtime:
        value = 40

        def new_id(self, purpose: str) -> UUID:
            self.value += 1
            return _uuid(self.value)

        def now(self) -> datetime:
            raise AssertionError("release does not need the clock")

    keyring = AppealPostgresReceiptKeyring(
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
    handler = PostgresReleaseAppealAssignmentHandler(
        gateway=gateway,
        receipt_probe=probe,
        receipt_keyring=keyring,
        id_source=_Runtime(),
        clock=_Runtime(),
    )
    actor = TrustActorContext(
        actor_user_id=str(_uuid(1)),
        session_id=str(_uuid(2)),
        organization_id=None,
        correlation_id=str(_uuid(3)),
        causation_id=str(_uuid(4)),
        trace_id=str(_uuid(5)),
        original_actor_user_id=None,
    )
    command = ReleaseAppealAssignmentCommand(
        appeal_id=str(_uuid(20)),
        expected_appeal_version=3,
        reason_code=AppealAssignmentReleaseReason.WORKLOAD_RELEASE,
        idempotency_key="appeal-release-key-001",
    )

    assert handler.handle(actor=actor, command=command) is recovered
    assert len(probe_calls) == 2
    assert len(write_calls) == 1
    assert all(request.organization_id is None for request in probe_calls)


def test_raw_text_cannot_enter_command_or_store_request_repr() -> None:
    for request_type in (
        SaveAppealDraftPostgresRequest,
        SaveAppealReviewDraftPostgresRequest,
        AppealRestrictedTextStoreRequest,
    ):
        fields = request_type.__dataclass_fields__
        assert "raw_text" not in fields
        assert "applicant_statement" not in fields
        assert "reviewer_note" not in fields
