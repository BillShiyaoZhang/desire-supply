"""RED/GREEN contract for the closed Trust PostgreSQL production gateway."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from uuid import UUID

import pytest
from psycopg.pq import TransactionStatus

from desire_platform.trust_safety.adapters.postgres import (
    gateway as trust_gateway_module,
)
from desire_platform.trust_safety.adapters.postgres.gateway import (
    PublishOutcomePostgresRequest,
    PsycopgTrustCommandGateway,
    PsycopgTrustReadGateway,
    PsycopgTrustReceiptProbe,
    ReleaseCaseAssignmentPostgresRequest,
    SaveTriageDraftPostgresRequest,
    SubmitReportPostgresRequest,
    TrustCompletedReceiptProbeRequest,
    TrustOutcomePostgresEvidence,
    TrustPostgresCommandContext,
    TrustPostgresCommitOutcomeUnknownError,
    TrustPostgresConfigurationError,
    TrustPostgresRejectedError,
    TrustPostgresReceiptMaterial,
    TrustPostgresReplayMaterial,
)
from desire_platform.trust_safety.adapters.postgres.migrations import (
    TRUST_REQUIRED_DEMAND_SCHEMA_VERSION,
    TRUST_REQUIRED_IAM_SCHEMA_VERSION,
    TRUST_SCHEMA_HEAD_VERSION,
)


def _uuid(number: int) -> UUID:
    return UUID(f"a0000000-0000-4000-8000-{number:012d}")


def _safe_response() -> dict[str, object]:
    return {
        "aggregate_version": 4,
        "assignment_id": str(_uuid(20)),
        "case_id": str(_uuid(21)),
        "case_status": "OPEN",
        "completed_at": "2026-08-18T12:34:56.1234Z",
        "event_types": ["TrustCaseAssignmentReleased"],
        "hold_id": None,
        "hold_version": None,
        "outcome_version_id": None,
        "report_id": None,
        "triage_draft_version": None,
        "triage_version": None,
    }


class _Cursor:
    def __init__(self, row=None, rows=None) -> None:
        self._row = row
        self._rows = rows

    def fetchone(self):
        return self._row

    def fetchmany(self, count: int):
        assert count == 2
        if self._rows is not None:
            return self._rows
        return [] if self._row is None else [self._row]


class _Connection:
    def __init__(
        self,
        *,
        role: str,
        function_result=None,
        read_result=None,
        fail_commit: bool = False,
        normalize_timeouts: bool = False,
    ) -> None:
        self.autocommit = True
        self.info = SimpleNamespace(transaction_status=TransactionStatus.IDLE)
        self.role = role
        self.function_result = function_result
        self.read_result = read_result
        self.fail_commit = fail_commit
        self.normalize_timeouts = normalize_timeouts
        self.statements: list[str] = []
        self.executions: list[tuple[str, object]] = []

    def execute(self, statement, parameters=None):
        sql = str(statement)
        self.statements.append(sql)
        self.executions.append((sql, parameters))
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
        if "trust_api.release_case_assignment_v1" in sql:
            return _Cursor(self.function_result)
        if "trust_api.publish_outcome_v1" in sql:
            return _Cursor(self.function_result)
        if "trust_api.read_completed_command_receipt_v1" in sql:
            return _Cursor(rows=self.read_result)
        if (
            "trust_api.list_own_reports_v1" in sql
            or
            "trust_api.list_safety_case_queue_v1" in sql
            or "trust_api.list_my_active_case_assignments_v1" in sql
            or "trust_api.list_my_completed_case_assignments_v1" in sql
            or "trust_api.read_own_report_v1" in sql
            or "trust_api.read_my_active_case_triage_assignment_v1" in sql
            or "trust_api.read_my_active_hold_release_assignment_v1" in sql
        ):
            return _Cursor(rows=self.read_result)
        if sql == "COMMIT" and self.fail_commit:
            raise ConnectionError("ambiguous commit")
        return _Cursor()


class _Source:
    def __init__(self, *connections: _Connection) -> None:
        self.connections = list(connections)
        self.released: list[_Connection] = []
        self.discarded: list[_Connection] = []

    def checkout(self):
        return self.connections.pop(0)

    def release(self, connection) -> None:
        self.released.append(connection)

    def discard(self, connection) -> None:
        self.discarded.append(connection)


def _request() -> ReleaseCaseAssignmentPostgresRequest:
    return ReleaseCaseAssignmentPostgresRequest(
        context=TrustPostgresCommandContext(
            actor_user_id=_uuid(1),
            session_id=_uuid(2),
            correlation_id=_uuid(3),
            causation_id=_uuid(4),
            trace_id=_uuid(5),
        ),
        receipt=TrustPostgresReceiptMaterial(
            receipt_id=_uuid(6),
            audit_event_id=_uuid(7),
            outbox_event_id=_uuid(8),
            idempotency_key_digest_key_ids=("trust-idem-active",),
            idempotency_key_digests=(b"i" * 32,),
            payload_hash_key_ids=("trust-payload-active",),
            payload_hashes=(b"p" * 32,),
        ),
        case_id=_uuid(21),
        expected_case_version=3,
        reason_code="WORKLOAD_RELEASE",
    )


def _submit_request(
    *,
    impact_codes: tuple[str, ...] = ("WORKFLOW_INTEGRITY_RISK",),
    evidence_reference_ids: tuple[UUID, ...] = (_uuid(30),),
    requested_protection_codes: tuple[str, ...] = ("PAUSE_VERIFICATION",),
) -> SubmitReportPostgresRequest:
    base = _request()
    return SubmitReportPostgresRequest(
        context=base.context,
        receipt=base.receipt,
        organization_id=_uuid(9),
        report_id=_uuid(10),
        case_id=_uuid(11),
        demand_id=_uuid(12),
        demand_version_id=_uuid(13),
        category="WORKFLOW_INTEGRITY",
        incident_started_at=datetime(2026, 8, 18, 12, 0, tzinfo=timezone.utc),
        incident_ended_at=None,
        impact_codes=impact_codes,
        evidence_reference_ids=evidence_reference_ids,
        requested_protection_codes=requested_protection_codes,
    )


def _report_projection() -> dict[str, object]:
    return {
        "demand_id": str(_uuid(30)),
        "demand_version_id": str(_uuid(31)),
        "entity_tag": '"trust-9-0123456789abcdef01234567"',
        "outcome": None,
        "report": {
            "category": "WORKFLOW_INTEGRITY",
            "evidence_reference_ids": [str(_uuid(40))],
            "impact_codes": ["WORKFLOW_INTEGRITY_RISK"],
            "incident_ended_at": None,
            "incident_started_at": "2026-08-18T12:00:00Z",
            "requested_protection_codes": ["PAUSE_VERIFICATION"],
        },
        "report_id": str(_uuid(32)),
        "status": "OPEN",
        "submitted_at": "2026-08-18T12:00:00Z",
    }


def _owned_report_list_projection() -> dict[str, object]:
    return {
        "entity_tag": '"trust-9-0123456789abcdef01234567"',
        "items": [
            {
                "category": "WORKFLOW_INTEGRITY",
                "demand_id": str(_uuid(30)),
                "outcome": {
                    "appeal_deadline": "2026-08-25T12:00:00Z",
                    "appeal_eligibility_code": "ELIGIBLE",
                    "decided_at": "2026-08-18T12:00:00Z",
                    "outcome_code": "NO_ACTION",
                    "outcome_version_id": str(_uuid(33)),
                },
                "report_id": str(_uuid(32)),
                "status": "DECIDED",
                "submitted_at": "2026-08-18T12:00:00Z",
            }
        ],
    }


def _triage_request(
    *,
    issue_codes: tuple[str, ...] = ("WORKFLOW_INTEGRITY_GAP",),
    investigation_step_codes: tuple[str, ...] = ("CHECK_DEMAND_VERSION",),
    proposed_hold_actions: tuple[str, ...] = ("VERIFY_DEMAND",),
    proposed_hold_ttl_minutes: int = 120,
) -> SaveTriageDraftPostgresRequest:
    base = _request()
    return SaveTriageDraftPostgresRequest(
        context=base.context,
        receipt=base.receipt,
        case_id=_uuid(21),
        expected_case_version=3,
        priority_code="P1",
        jurisdiction_code="PLATFORM_INTERNAL",
        severity_code="HIGH",
        issue_codes=issue_codes,
        investigation_step_codes=investigation_step_codes,
        proposed_hold_actions=proposed_hold_actions,
        proposed_hold_ttl_minutes=proposed_hold_ttl_minutes,
        sealed_note_reference="sealed://trust/triage-note/" + "a" * 64,
        sealed_note_sha256=b"s" * 32,
    )


def _case_projection(
    *,
    issue_codes: tuple[str, ...],
    investigation_step_codes: tuple[str, ...],
    proposed_hold_actions: tuple[str, ...],
    proposed_hold_ttl_minutes: int = 120,
) -> dict[str, object]:
    return {
        "active_hold": None,
        "aggregate_version": 4,
        "case_id": str(_uuid(21)),
        "demand_id": str(_uuid(30)),
        "demand_version_id": str(_uuid(31)),
        "entity_tag": '"trust-4-0123456789abcdef01234567"',
        "outcome": None,
        "report": _report_projection()["report"],
        "report_id": str(_uuid(32)),
        "status": "TRIAGING",
        "triage_draft": {
            "content": {
                "investigation_step_codes": list(investigation_step_codes),
                "issue_codes": list(issue_codes),
                "jurisdiction_code": "PLATFORM_INTERNAL",
                "priority_code": "P1",
                "proposed_hold_actions": list(proposed_hold_actions),
                "proposed_hold_ttl_minutes": proposed_hold_ttl_minutes,
                "sealed_note_reference": "sealed://trust/triage-note/" + "a" * 64,
                "sealed_note_sha256": "b" * 64,
                "severity_code": "HIGH",
            },
            "content_sha256": "c" * 64,
            "saved_at": "2026-08-18T12:10:00Z",
            "triage_version": 1,
        },
    }


def _assigned_hold_release_projection() -> dict[str, object]:
    return {
        "action_codes": ["REQUEST_MATCHING"],
        "assignment_expires_at": "2026-08-18T13:00:00Z",
        "case_id": str(_uuid(21)),
        "case_status": "IN_REVIEW",
        "effective_at": "2026-08-18T12:00:00Z",
        "entity_tag": '"trust-4-0123456789abcdef01234567"',
        "expires_at": "2026-08-18T14:00:00Z",
        "hold_id": str(_uuid(22)),
        "hold_status": "ACTIVE",
        "reason_code": "RETALIATION_RISK",
    }


def test_submit_report_request_uses_frozen_http_sql_collection_bounds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    impact_codes = tuple(f"IMPACT_{index:02d}" for index in range(17))
    monkeypatch.setattr(
        trust_gateway_module,
        "_IMPACT_CODES",
        frozenset((*impact_codes, "WORKFLOW_INTEGRITY_RISK")),
    )
    evidence_ids = tuple(_uuid(100 + index) for index in range(33))

    accepted = _submit_request(
        impact_codes=impact_codes[:16],
        evidence_reference_ids=evidence_ids[:32],
    )

    assert len(accepted.impact_codes) == 16
    assert len(accepted.evidence_reference_ids) == 32
    with pytest.raises(ValueError, match="code list"):
        _submit_request(impact_codes=impact_codes)
    with pytest.raises(ValueError, match="identifier list"):
        _submit_request(evidence_reference_ids=evidence_ids)
    with pytest.raises(ValueError, match="identifier list"):
        _submit_request(evidence_reference_ids=())
    with pytest.raises(ValueError, match="code list"):
        _submit_request(requested_protection_codes=())


def test_triage_request_uses_frozen_http_sql_collection_bounds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    issue_codes = tuple(f"ISSUE_{index:02d}" for index in range(17))
    investigation_codes = tuple(
        f"INVESTIGATION_{index:02d}" for index in range(17)
    )
    hold_actions = tuple(f"ACTION_{index:02d}" for index in range(4))
    monkeypatch.setattr(trust_gateway_module, "_ISSUE_CODES", frozenset(issue_codes))
    monkeypatch.setattr(
        trust_gateway_module,
        "_INVESTIGATION_CODES",
        frozenset(investigation_codes),
    )
    monkeypatch.setattr(
        trust_gateway_module,
        "_HOLD_ACTIONS",
        frozenset(hold_actions),
    )

    accepted = _triage_request(
        issue_codes=issue_codes[:16],
        investigation_step_codes=investigation_codes[:16],
        proposed_hold_actions=hold_actions[:3],
        proposed_hold_ttl_minutes=10_080,
    )

    assert len(accepted.issue_codes) == 16
    assert len(accepted.investigation_step_codes) == 16
    assert len(accepted.proposed_hold_actions) == 3
    with pytest.raises(ValueError, match="code list"):
        _triage_request(
            issue_codes=issue_codes,
            investigation_step_codes=investigation_codes[:16],
            proposed_hold_actions=hold_actions[:3],
        )
    with pytest.raises(ValueError, match="code list"):
        _triage_request(
            issue_codes=issue_codes[:16],
            investigation_step_codes=investigation_codes,
            proposed_hold_actions=hold_actions[:3],
        )
    with pytest.raises(ValueError, match="code list"):
        _triage_request(
            issue_codes=issue_codes[:16],
            investigation_step_codes=investigation_codes[:16],
            proposed_hold_actions=(),
        )
    with pytest.raises(ValueError, match="code list"):
        _triage_request(
            issue_codes=issue_codes[:16],
            investigation_step_codes=investigation_codes[:16],
            proposed_hold_actions=hold_actions,
        )
    ttl_values = {
        "issue_codes": issue_codes[:1],
        "investigation_step_codes": investigation_codes[:1],
        "proposed_hold_actions": hold_actions[:1],
    }
    _triage_request(**ttl_values, proposed_hold_ttl_minutes=15)
    with pytest.raises(ValueError, match="triage draft"):
        _triage_request(**ttl_values, proposed_hold_ttl_minutes=14)
    with pytest.raises(ValueError, match="triage draft"):
        _triage_request(**ttl_values, proposed_hold_ttl_minutes=10_081)


def test_triage_projection_uses_frozen_http_sql_collection_bounds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    issue_codes = tuple(f"ISSUE_{index:02d}" for index in range(17))
    investigation_codes = tuple(
        f"INVESTIGATION_{index:02d}" for index in range(17)
    )
    hold_actions = tuple(f"ACTION_{index:02d}" for index in range(4))
    monkeypatch.setattr(trust_gateway_module, "_ISSUE_CODES", frozenset(issue_codes))
    monkeypatch.setattr(
        trust_gateway_module,
        "_INVESTIGATION_CODES",
        frozenset(investigation_codes),
    )
    monkeypatch.setattr(
        trust_gateway_module,
        "_HOLD_ACTIONS",
        frozenset(hold_actions),
    )

    def gateway_for(
        *,
        issues: tuple[str, ...] = issue_codes[:16],
        investigations: tuple[str, ...] = investigation_codes[:16],
        actions: tuple[str, ...] = hold_actions[:3],
        ttl: int = 10_080,
    ) -> PsycopgTrustReadGateway:
        return PsycopgTrustReadGateway(
            reporter_connections=_Source(_Connection(role="trust_self")),
            officer_connections=_Source(
                _Connection(
                    role="trust_officer",
                    read_result=[(
                        _case_projection(
                            issue_codes=issues,
                            investigation_step_codes=investigations,
                            proposed_hold_actions=actions,
                            proposed_hold_ttl_minutes=ttl,
                        ),
                    )],
                )
            ),
        )

    accepted = gateway_for().read_assigned_case(
        actor_user_id=_uuid(1),
        session_id=_uuid(2),
        case_id=_uuid(21),
    )

    content = accepted.projection["triage_draft"]["content"]
    assert len(content["issue_codes"]) == 16
    assert len(content["investigation_step_codes"]) == 16
    assert len(content["proposed_hold_actions"]) == 3
    for invalid in (
        {"issues": issue_codes},
        {"investigations": investigation_codes},
        {"actions": ()},
        {"actions": hold_actions},
        {"ttl": 14},
        {"ttl": 10_081},
    ):
        with pytest.raises(TrustPostgresConfigurationError):
            gateway_for(**invalid).read_assigned_case(
                actor_user_id=_uuid(1),
                session_id=_uuid(2),
                case_id=_uuid(21),
            )


def test_command_gateway_has_nine_closed_entry_points_and_no_generic_execute() -> None:
    public = {
        name
        for name, value in PsycopgTrustCommandGateway.__dict__.items()
        if callable(value) and not name.startswith("_")
    }
    assert public == {
        "claim_case",
        "claim_hold_release",
        "close",
        "place_hold",
        "publish_outcome",
        "publish_triage",
        "release_case_assignment",
        "release_hold",
        "save_triage_draft",
        "submit_report",
    }


def test_command_gateway_accepts_postgres_canonical_timeout_display() -> None:
    connection = _Connection(
        role="trust_officer",
        function_result=(_safe_response(), False),
        normalize_timeouts=True,
    )
    gateway = PsycopgTrustCommandGateway(
        reporter_connections=_Source(_Connection(role="trust_self")),
        officer_connections=_Source(connection),
    )

    result = gateway.release_case_assignment(_request())

    assert result.replayed is False


def test_publish_outcome_uses_exact_frozen_34_argument_abi() -> None:
    outcome_version_id = _uuid(40)
    case_id = _uuid(21)
    now = datetime(2026, 8, 18, 12, 34, 56, tzinfo=timezone.utc)
    response = {
        **_safe_response(),
        "aggregate_version": 8,
        "assignment_id": None,
        "case_id": str(case_id),
        "case_status": "DECIDED",
        "event_types": ["TrustCaseOutcomePublished"],
        "outcome_version_id": str(outcome_version_id),
    }
    connection = _Connection(
        role="trust_officer",
        function_result=(response, False),
    )
    gateway = PsycopgTrustCommandGateway(
        reporter_connections=_Source(_Connection(role="trust_self")),
        officer_connections=_Source(connection),
    )
    request = PublishOutcomePostgresRequest(
        context=_request().context,
        receipt=_request().receipt,
        outcome_version_id=outcome_version_id,
        case_id=case_id,
        expected_case_version=7,
        outcome_code="NO_ACTION",
        reason_codes=("NO_POLICY_BREACH",),
        action_codes=(),
        evidence=TrustOutcomePostgresEvidence(
            case_id=case_id,
            case_aggregate_version=7,
            triage_version=1,
            outcome_code="NO_ACTION",
            reason_codes=("NO_POLICY_BREACH",),
            action_codes=(),
            evidence_packet_version_id=_uuid(41),
            evidence_packet_digest=b"e" * 32,
            source_digest=b"s" * 32,
            appeal_eligible=True,
            appeal_eligibility_code="ELIGIBLE",
            appeal_deadline=datetime(2026, 9, 17, tzinfo=timezone.utc),
            policy_version="trust-case-outcome-v1",
            redaction_profile_code="PARTY_SAFE_V1",
            evaluated_at=now,
            valid_until=datetime(2026, 8, 18, 12, 39, 56, tzinfo=timezone.utc),
        ),
    )

    result = gateway.publish_outcome(request)

    statement, parameters = next(
        execution
        for execution in connection.executions
        if "trust_api.publish_outcome_v1" in execution[0]
    )
    assert statement.count("%s") == len(parameters) == 34
    assert result.outcome_version_id == str(outcome_version_id)


def test_commit_unknown_is_surfaced_without_repeating_mutating_program() -> None:
    first = _Connection(
        role="trust_officer",
        function_result=(_safe_response(), False),
        fail_commit=True,
    )
    second = _Connection(
        role="trust_officer",
        function_result=(_safe_response(), True),
    )
    officer = _Source(first, second)
    reporter = _Source(_Connection(role="trust_self"))
    gateway = PsycopgTrustCommandGateway(
        reporter_connections=reporter,
        officer_connections=officer,
    )

    with pytest.raises(TrustPostgresCommitOutcomeUnknownError):
        gateway.release_case_assignment(_request())

    assert len(officer.discarded) == 1
    assert len(officer.released) == 0
    calls = [
        sql
        for connection in (first, second)
        for sql in connection.statements
        if "trust_api.release_case_assignment_v1" in sql
    ]
    assert len(calls) == 1
    assert len(officer.connections) == 1


def test_ambiguous_commit_never_consumes_a_second_connection() -> None:
    officer = _Source(
        _Connection(
            role="trust_officer",
            function_result=(_safe_response(), False),
            fail_commit=True,
        ),
        _Connection(
            role="trust_officer",
            function_result=(_safe_response(), True),
            fail_commit=True,
        ),
    )
    gateway = PsycopgTrustCommandGateway(
        reporter_connections=_Source(_Connection(role="trust_self")),
        officer_connections=officer,
    )
    with pytest.raises(TrustPostgresCommitOutcomeUnknownError):
        gateway.release_case_assignment(_request())
    assert len(officer.connections) == 1


def test_completed_receipt_probe_returns_exact_replay_or_true_miss() -> None:
    probe_request = TrustCompletedReceiptProbeRequest(
        context=_request().context,
        material=TrustPostgresReplayMaterial(
            idempotency_key_digest_key_ids=("trust-idem-active",),
            idempotency_key_digests=(b"i" * 32,),
            payload_hash_key_ids=("trust-payload-active",),
            payload_hashes=(b"p" * 32,),
        ),
        operation="RELEASE_CASE_ASSIGNMENT",
        organization_id=None,
        target_id=_uuid(21),
        expected_version=3,
    )
    replay_connection = _Connection(
        role="trust_officer",
        read_result=[(_safe_response(), True)],
    )
    miss_connection = _Connection(role="trust_officer", read_result=[])
    probe = PsycopgTrustReceiptProbe(
        reporter_connections=_Source(_Connection(role="trust_self")),
        officer_connections=_Source(replay_connection, miss_connection),
    )

    replay = probe.read_completed(probe_request)
    miss = probe.read_completed(
        TrustCompletedReceiptProbeRequest(
            context=probe_request.context,
            material=TrustPostgresReplayMaterial(
                idempotency_key_digest_key_ids=("trust-idem-active",),
                idempotency_key_digests=(b"j" * 32,),
                payload_hash_key_ids=("trust-payload-active",),
                payload_hashes=(b"q" * 32,),
            ),
            operation="RELEASE_CASE_ASSIGNMENT",
            organization_id=None,
            target_id=_uuid(21),
            expected_version=3,
        )
    )

    assert replay is not None and replay.replayed
    assert miss is None


def test_queue_read_is_exactly_parsed_and_role_isolated() -> None:
    projection = {
        "entity_tag": '"trust-3-0123456789abcdef01234567"',
        "items": [
            {
                "case_id": str(_uuid(21)),
                "category": "WORKFLOW_INTEGRITY",
                "demand_id": str(_uuid(30)),
                "demand_version_id": str(_uuid(31)),
                "entity_tag": '"trust-3-89abcdef0123456701234567"',
                "impact_codes": ["WORKFLOW_INTEGRITY_RISK"],
                "report_id": str(_uuid(32)),
                "submitted_at": "2026-08-18T12:00:00Z",
            }
        ],
    }
    officer_connection = _Connection(
        role="trust_officer",
        read_result=[(projection,)],
    )
    gateway = PsycopgTrustReadGateway(
        reporter_connections=_Source(_Connection(role="trust_self")),
        officer_connections=_Source(officer_connection),
    )

    result = gateway.list_case_queue(
        actor_user_id=_uuid(1),
        session_id=_uuid(2),
        limit=20,
    )

    assert result.response_entity_tag == projection["entity_tag"]
    assert result.projection == projection

    assert any(
        "trust_api.list_safety_case_queue_v1" in statement
        for statement in officer_connection.statements
    )


def test_my_active_assignments_read_uses_frozen_abi_and_minimal_projection() -> None:
    projection = {
        "entity_tag": '"trust-3-0123456789abcdef01234567"',
        "items": [
            {
                "assignment_expires_at": "2026-08-18T16:00:00Z",
                "assignment_purpose": "CASE_TRIAGE",
                "case_id": str(_uuid(21)),
                "hold_id": None,
            }
        ],
    }
    connection = _Connection(
        role="trust_officer",
        read_result=[(projection,)],
    )
    gateway = PsycopgTrustReadGateway(
        reporter_connections=_Source(_Connection(role="trust_self")),
        officer_connections=_Source(connection),
    )

    result = gateway.list_my_active_case_assignments(
        actor_user_id=_uuid(1),
        session_id=_uuid(2),
        limit=100,
    )

    assert result.kind == "MY_ACTIVE_CASE_ASSIGNMENTS"
    assert result.projection == projection
    calls = [
        (statement, parameters)
        for statement, parameters in connection.executions
        if "list_my_active_case_assignments_v1" in statement
    ]
    assert calls == [
        (
            "SELECT projection FROM "
            "trust_api.list_my_active_case_assignments_v1(%s,%s,%s)",
            (_uuid(1), _uuid(2), 100),
        )
    ]


def test_my_active_assignments_allow_two_purposes_for_the_same_case() -> None:
    case_id = str(_uuid(21))
    projection = {
        "entity_tag": '"trust-3-0123456789abcdef01234567"',
        "items": [
            {
                "assignment_expires_at": "2026-08-18T16:00:00Z",
                "assignment_purpose": "CASE_TRIAGE",
                "case_id": case_id,
                "hold_id": None,
            },
            {
                "assignment_expires_at": "2026-08-18T16:00:00Z",
                "assignment_purpose": "HOLD_RELEASE",
                "case_id": case_id,
                "hold_id": str(_uuid(22)),
            },
            {
                "assignment_expires_at": "2026-08-18T17:00:00Z",
                "assignment_purpose": "HOLD_RELEASE",
                "case_id": case_id,
                "hold_id": str(_uuid(23)),
            },
        ],
    }
    gateway = PsycopgTrustReadGateway(
        reporter_connections=_Source(_Connection(role="trust_self")),
        officer_connections=_Source(
            _Connection(role="trust_officer", read_result=[(projection,)])
        ),
    )

    result = gateway.list_my_active_case_assignments(
        actor_user_id=_uuid(1), session_id=_uuid(2), limit=100
    )

    assert result.projection == projection

    duplicate_projection = {
        **projection,
        "items": [projection["items"][0], projection["items"][0]],
    }
    duplicate = PsycopgTrustReadGateway(
        reporter_connections=_Source(_Connection(role="trust_self")),
        officer_connections=_Source(
            _Connection(
                role="trust_officer", read_result=[(duplicate_projection,)]
            )
        ),
    )
    with pytest.raises(TrustPostgresConfigurationError):
        duplicate.list_my_active_case_assignments(
            actor_user_id=_uuid(1), session_id=_uuid(2), limit=100
        )


def test_my_completed_assignments_read_is_minimal_ordered_and_actor_bound() -> None:
    projection = {
        "entity_tag": '"trust-8-0123456789abcdef01234567"',
        "has_more": True,
        "items": [
            {
                "case_id": str(_uuid(22)),
                "decided_at": "2026-08-18T16:00:00Z",
                "outcome_code": "PROTECTION_MAINTAINED",
            },
            {
                "case_id": str(_uuid(21)),
                "decided_at": "2026-08-18T16:00:00Z",
                "outcome_code": "NO_ACTION",
            },
        ],
    }
    connection = _Connection(
        role="trust_officer",
        read_result=[(projection,)],
    )
    gateway = PsycopgTrustReadGateway(
        reporter_connections=_Source(_Connection(role="trust_self")),
        officer_connections=_Source(connection),
    )

    result = gateway.list_my_completed_case_assignments(
        actor_user_id=_uuid(1),
        session_id=_uuid(2),
        limit=100,
    )

    assert result.kind == "MY_COMPLETED_CASE_ASSIGNMENTS"
    assert result.projection == projection
    assert [
        (statement, parameters)
        for statement, parameters in connection.executions
        if "list_my_completed_case_assignments_v1" in statement
    ] == [
        (
            "SELECT projection FROM "
            "trust_api.list_my_completed_case_assignments_v1(%s,%s,%s)",
            (_uuid(1), _uuid(2), 100),
        )
    ]
    configured_operations = [
        parameters[1]
        for statement, parameters in connection.executions
        if "pg_catalog.set_config" in statement
        and parameters[0] == "app.operation"
    ]
    assert configured_operations == ["READ_ASSIGNED_CASE"]


@pytest.mark.parametrize(
    "mutation",
    (
        lambda value: {**value, "items": [value["items"][0]] * 2},
        lambda value: {
            **value,
            "items": [{**value["items"][0], "reporter_user_id": str(_uuid(9))}],
        },
        lambda value: {**value, "has_more": 1},
        lambda value: {
            **value,
            "items": list(reversed(value["items"])),
        },
    ),
)
def test_my_completed_assignments_projection_fails_closed_on_leaks_and_order(
    mutation,
) -> None:
    safe = {
        "entity_tag": '"trust-8-0123456789abcdef01234567"',
        "has_more": False,
        "items": [
            {
                "case_id": str(_uuid(22)),
                "decided_at": "2026-08-18T16:00:00Z",
                "outcome_code": "PROTECTION_MAINTAINED",
            },
            {
                "case_id": str(_uuid(21)),
                "decided_at": "2026-08-18T16:00:00Z",
                "outcome_code": "NO_ACTION",
            },
        ],
    }
    gateway = PsycopgTrustReadGateway(
        reporter_connections=_Source(_Connection(role="trust_self")),
        officer_connections=_Source(
            _Connection(role="trust_officer", read_result=[(mutation(safe),)])
        ),
    )

    with pytest.raises(TrustPostgresConfigurationError):
        gateway.list_my_completed_case_assignments(
            actor_user_id=_uuid(1), session_id=_uuid(2), limit=100
        )

def test_my_active_assignments_fail_closed_on_no_row_or_rich_item() -> None:
    missing = PsycopgTrustReadGateway(
        reporter_connections=_Source(_Connection(role="trust_self")),
        officer_connections=_Source(
            _Connection(role="trust_officer", read_result=[])
        ),
    )
    with pytest.raises(TrustPostgresRejectedError, match="RESOURCE_NOT_FOUND"):
        missing.list_my_active_case_assignments(
            actor_user_id=_uuid(1), session_id=_uuid(2), limit=100
        )

    rich = {
        "entity_tag": '"trust-3-0123456789abcdef01234567"',
        "items": [
            {
                "assignment_expires_at": "2026-08-18T16:00:00Z",
                "assignment_id": str(_uuid(22)),
                "assignment_purpose": "CASE_TRIAGE",
                "case_id": str(_uuid(21)),
                "hold_id": None,
            }
        ],
    }
    unsafe = PsycopgTrustReadGateway(
        reporter_connections=_Source(_Connection(role="trust_self")),
        officer_connections=_Source(
            _Connection(role="trust_officer", read_result=[(rich,)])
        ),
    )
    with pytest.raises(TrustPostgresConfigurationError):
        unsafe.list_my_active_case_assignments(
            actor_user_id=_uuid(1), session_id=_uuid(2), limit=100
        )


def test_assignment_detail_reads_use_exact_triage_and_hold_navigation_abis() -> None:
    case_projection = _case_projection(
        issue_codes=("WORKFLOW_INTEGRITY_GAP",),
        investigation_step_codes=("CHECK_DEMAND_VERSION",),
        proposed_hold_actions=("VERIFY_DEMAND",),
    )
    case_connection = _Connection(
        role="trust_officer", read_result=[(case_projection,)]
    )
    case_gateway = PsycopgTrustReadGateway(
        reporter_connections=_Source(_Connection(role="trust_self")),
        officer_connections=_Source(case_connection),
    )

    case_result = case_gateway.read_assigned_case(
        actor_user_id=_uuid(1), session_id=_uuid(2), case_id=_uuid(21)
    )

    assert case_result.kind == "CASE"
    assert [
        (statement, parameters)
        for statement, parameters in case_connection.executions
        if "read_my_active_case_triage_assignment_v1" in statement
    ] == [
        (
            "SELECT projection FROM "
            "trust_api.read_my_active_case_triage_assignment_v1(%s,%s,%s)",
            (_uuid(1), _uuid(2), _uuid(21)),
        )
    ]

    decided_projection = {**case_projection, "status": "DECIDED"}
    decided_gateway = PsycopgTrustReadGateway(
        reporter_connections=_Source(_Connection(role="trust_self")),
        officer_connections=_Source(
            _Connection(role="trust_officer", read_result=[(decided_projection,)])
        ),
    )
    assert decided_gateway.read_assigned_case(
        actor_user_id=_uuid(1), session_id=_uuid(2), case_id=_uuid(21)
    ).projection["status"] == "DECIDED"

    hold_projection = _assigned_hold_release_projection()
    hold_connection = _Connection(
        role="trust_officer", read_result=[(hold_projection,)]
    )
    hold_gateway = PsycopgTrustReadGateway(
        reporter_connections=_Source(_Connection(role="trust_self")),
        officer_connections=_Source(hold_connection),
    )

    hold_result = hold_gateway.read_assigned_hold_release(
        actor_user_id=_uuid(1), session_id=_uuid(2), hold_id=_uuid(22)
    )

    assert hold_result.kind == "ASSIGNED_HOLD_RELEASE"
    assert hold_result.projection == hold_projection
    assert (
        "SELECT pg_catalog.set_config(%s,%s,true)",
        ("app.operation", "READ_ASSIGNED_CASE"),
    ) in hold_connection.executions
    assert [
        (statement, parameters)
        for statement, parameters in hold_connection.executions
        if "read_my_active_hold_release_assignment_v1" in statement
    ] == [
        (
            "SELECT projection FROM "
            "trust_api.read_my_active_hold_release_assignment_v1(%s,%s,%s)",
            (_uuid(1), _uuid(2), _uuid(22)),
        )
    ]


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("effective_at", "2026-08-18T14:00:00Z"),
        ("assignment_expires_at", "2026-08-18T14:00:00.000001Z"),
        ("expires_at", "2026-08-18T22:00:00+08:00"),
    ),
)
def test_assigned_hold_release_read_rejects_invalid_or_non_utc_time_order(
    field: str, value: str
) -> None:
    projection = {**_assigned_hold_release_projection(), field: value}
    gateway = PsycopgTrustReadGateway(
        reporter_connections=_Source(_Connection(role="trust_self")),
        officer_connections=_Source(
            _Connection(role="trust_officer", read_result=[(projection,)])
        ),
    )

    with pytest.raises(TrustPostgresConfigurationError):
        gateway.read_assigned_hold_release(
            actor_user_id=_uuid(1), session_id=_uuid(2), hold_id=_uuid(22)
        )


def test_assigned_hold_release_read_hides_wrong_or_stale_hold_as_not_found() -> None:
    gateway = PsycopgTrustReadGateway(
        reporter_connections=_Source(_Connection(role="trust_self")),
        officer_connections=_Source(
            _Connection(role="trust_officer", read_result=[])
        ),
    )

    with pytest.raises(TrustPostgresRejectedError, match="RESOURCE_NOT_FOUND"):
        gateway.read_assigned_hold_release(
            actor_user_id=_uuid(1), session_id=_uuid(2), hold_id=_uuid(99)
        )


def test_queue_read_uses_frozen_http_sql_impact_bound(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    impact_codes = tuple(f"IMPACT_{index:02d}" for index in range(17))
    monkeypatch.setattr(
        trust_gateway_module,
        "_IMPACT_CODES",
        frozenset(impact_codes),
    )

    def projection(codes: tuple[str, ...]) -> dict[str, object]:
        return {
            "entity_tag": '"trust-3-0123456789abcdef01234567"',
            "items": [
                {
                    "case_id": str(_uuid(21)),
                    "category": "WORKFLOW_INTEGRITY",
                    "demand_id": str(_uuid(30)),
                    "demand_version_id": str(_uuid(31)),
                    "entity_tag": '"trust-3-89abcdef0123456701234567"',
                    "impact_codes": list(codes),
                    "report_id": str(_uuid(32)),
                    "submitted_at": "2026-08-18T12:00:00Z",
                }
            ],
        }

    accepted = PsycopgTrustReadGateway(
        reporter_connections=_Source(_Connection(role="trust_self")),
        officer_connections=_Source(
            _Connection(
                role="trust_officer",
                read_result=[(projection(impact_codes[:16]),)],
            )
        ),
    )
    rejected = PsycopgTrustReadGateway(
        reporter_connections=_Source(_Connection(role="trust_self")),
        officer_connections=_Source(
            _Connection(
                role="trust_officer",
                read_result=[(projection(impact_codes),)],
            )
        ),
    )

    result = accepted.list_case_queue(
        actor_user_id=_uuid(1),
        session_id=_uuid(2),
        limit=20,
    )

    assert result.projection["items"][0]["impact_codes"] == list(
        impact_codes[:16]
    )
    with pytest.raises(TrustPostgresConfigurationError):
        rejected.list_case_queue(
            actor_user_id=_uuid(1),
            session_id=_uuid(2),
            limit=20,
        )


def test_queue_read_accepts_postgres_utc_offset_timestamp() -> None:
    projection = {
        "entity_tag": '"trust-3-0123456789abcdef01234567"',
        "items": [
            {
                "case_id": str(_uuid(21)),
                "category": "WORKFLOW_INTEGRITY",
                "demand_id": str(_uuid(30)),
                "demand_version_id": str(_uuid(31)),
                "entity_tag": '"trust-3-89abcdef0123456701234567"',
                "impact_codes": ["WORKFLOW_INTEGRITY_RISK"],
                "report_id": str(_uuid(32)),
                "submitted_at": "2026-08-18T12:00:00+00:00",
            }
        ],
    }
    gateway = PsycopgTrustReadGateway(
        reporter_connections=_Source(_Connection(role="trust_self")),
        officer_connections=_Source(
            _Connection(role="trust_officer", read_result=[(projection,)])
        ),
    )

    result = gateway.list_case_queue(
        actor_user_id=_uuid(1),
        session_id=_uuid(2),
        limit=20,
    )

    assert result.projection == projection


def test_queue_read_rejects_non_utc_offset_timestamp() -> None:
    projection = {
        "entity_tag": '"trust-3-0123456789abcdef01234567"',
        "items": [
            {
                "case_id": str(_uuid(21)),
                "category": "WORKFLOW_INTEGRITY",
                "demand_id": str(_uuid(30)),
                "demand_version_id": str(_uuid(31)),
                "entity_tag": '"trust-3-89abcdef0123456701234567"',
                "impact_codes": ["WORKFLOW_INTEGRITY_RISK"],
                "report_id": str(_uuid(32)),
                "submitted_at": "2026-08-18T20:00:00+08:00",
            }
        ],
    }
    gateway = PsycopgTrustReadGateway(
        reporter_connections=_Source(_Connection(role="trust_self")),
        officer_connections=_Source(
            _Connection(role="trust_officer", read_result=[(projection,)])
        ),
    )

    with pytest.raises(TrustPostgresConfigurationError):
        gateway.list_case_queue(
            actor_user_id=_uuid(1),
            session_id=_uuid(2),
            limit=20,
        )


def test_report_projection_uses_frozen_http_sql_collection_bounds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    impact_codes = tuple(f"IMPACT_{index:02d}" for index in range(16))
    monkeypatch.setattr(
        trust_gateway_module,
        "_IMPACT_CODES",
        frozenset(impact_codes),
    )
    report = _report_projection()
    summary = report["report"]
    assert isinstance(summary, dict)
    summary["evidence_reference_ids"] = [
        str(_uuid(100 + index)) for index in range(32)
    ]
    summary["impact_codes"] = list(impact_codes)
    reporter_connection = _Connection(
        role="trust_self",
        read_result=[(report,)],
    )
    gateway = PsycopgTrustReadGateway(
        reporter_connections=_Source(reporter_connection),
        officer_connections=_Source(_Connection(role="trust_officer")),
    )

    result = gateway.read_own_report(
        actor_user_id=_uuid(1),
        session_id=_uuid(2),
        organization_id=_uuid(3),
        report_id=_uuid(32),
    )

    assert result.projection["outcome"] is None


def test_owned_report_page_uses_exact_program_shape_and_resets_before_release() -> None:
    boundary = datetime(2026, 8, 18, 12, 0, tzinfo=timezone.utc)
    projection = _owned_report_list_projection()
    connection = _Connection(
        role="trust_self",
        read_result=[(projection, boundary, _uuid(32))],
    )
    reporter = _Source(connection)
    gateway = PsycopgTrustReadGateway(
        reporter_connections=reporter,
        officer_connections=_Source(_Connection(role="trust_officer")),
    )

    result = gateway.list_own_reports(
        actor_user_id=_uuid(1),
        session_id=_uuid(2),
        organization_id=_uuid(3),
        limit=1,
        cursor_created_at=None,
        cursor_report_id=None,
    )

    assert result.projection == projection
    assert result.next_created_at == boundary
    assert result.next_report_id == _uuid(32)
    program_calls = [
        execution
        for execution in connection.executions
        if "trust_api.list_own_reports_v1" in execution[0]
    ]
    assert program_calls == [
        (
            "SELECT projection,next_created_at,next_report_id FROM "
            "trust_api.list_own_reports_v1(%s,%s,%s,%s,%s,%s)",
            (_uuid(1), _uuid(2), _uuid(3), 1, None, None),
        )
    ]
    assert "BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY" in connection.statements
    assert connection.statements[-5:] == [
        "COMMIT",
        "RESET ROLE",
        "RESET ALL",
        "CLOSE ALL",
        "DISCARD TEMP",
    ]
    assert reporter.released == [connection]
    assert reporter.discarded == []


@pytest.mark.parametrize(
    "row",
    (
        ({"entity_tag": '"trust-1-0123456789abcdef01234567"', "items": []}, None, _uuid(32)),
        ({"entity_tag": '"trust-1-0123456789abcdef01234567"', "items": [], "reporter_user_id": str(_uuid(1))}, None, None),
        (_owned_report_list_projection(), datetime(2026, 8, 18, 20, 0, tzinfo=timezone(timedelta(hours=8))), _uuid(32)),
    ),
)
def test_owned_report_page_rejects_malformed_rows_rolls_back_and_discards(row) -> None:
    connection = _Connection(role="trust_self", read_result=[row])
    reporter = _Source(connection)
    gateway = PsycopgTrustReadGateway(
        reporter_connections=reporter,
        officer_connections=_Source(_Connection(role="trust_officer")),
    )

    with pytest.raises(TrustPostgresConfigurationError):
        gateway.list_own_reports(
            actor_user_id=_uuid(1),
            session_id=_uuid(2),
            organization_id=_uuid(3),
            limit=1,
            cursor_created_at=None,
            cursor_report_id=None,
        )

    assert "ROLLBACK" in connection.statements
    assert reporter.released == []
    assert reporter.discarded == [connection]


@pytest.mark.parametrize(
    "field_name",
    ("evidence_reference_ids", "requested_protection_codes"),
)
def test_report_projection_rejects_empty_required_collection(
    field_name: str,
) -> None:
    report = _report_projection()
    summary = report["report"]
    assert isinstance(summary, dict)
    summary[field_name] = []
    gateway = PsycopgTrustReadGateway(
        reporter_connections=_Source(
            _Connection(role="trust_self", read_result=[(report,)])
        ),
        officer_connections=_Source(_Connection(role="trust_officer")),
    )

    with pytest.raises(TrustPostgresConfigurationError):
        gateway.read_own_report(
            actor_user_id=_uuid(1),
            session_id=_uuid(2),
            organization_id=_uuid(3),
            report_id=_uuid(32),
        )


def test_read_projection_extra_key_fails_closed() -> None:
    officer = _Source(
        _Connection(
            role="trust_officer",
            read_result=[(
                {
                    "entity_tag": '"trust-1-0123456789abcdef01234567"',
                    "items": [],
                    "unexpected": True,
                },
            )],
        )
    )
    gateway = PsycopgTrustReadGateway(
        reporter_connections=_Source(_Connection(role="trust_self")),
        officer_connections=officer,
    )
    with pytest.raises(TrustPostgresConfigurationError):
        gateway.list_case_queue(
            actor_user_id=_uuid(1),
            session_id=_uuid(2),
            limit=20,
        )


def test_raw_note_cannot_enter_postgres_request_shape() -> None:
    fields = ReleaseCaseAssignmentPostgresRequest.__dataclass_fields__
    assert "restricted_note" not in fields
    assert "raw_note" not in fields
