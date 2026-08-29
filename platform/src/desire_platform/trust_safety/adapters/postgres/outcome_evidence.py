"""Managed PostgreSQL evidence provider for the initial Trust outcome."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
from typing import Any, Mapping, Tuple
from uuid import UUID

from ...domain import (
    SafetyCase,
    SafetyCaseStatus,
    SafetyHold,
    SafetyHoldStatus,
    SafetyReport,
    TrustCaseOutcome,
    TrustTriageVersion,
)
from ...ports.commands import (
    TrustDecisionEvidenceUnavailableError,
    TrustInitialOutcomeEvidence,
    TrustOfficerAuthority,
)
from .gateway import (
    TrustOutcomePostgresEvidence,
    TrustPostgresConfigurationError,
    TrustPostgresGatewaySettings,
    _configure,
    _database_error,
    _discard,
    _prepare,
    _reset,
)


_OUTCOMES = frozenset(
    {
        "NO_ACTION",
        "PROTECTION_LIFTED",
        "PROTECTION_MAINTAINED",
        "PROTECTION_MODIFIED",
        "REMEDIATION_REQUIRED",
    }
)
_REASONS = frozenset(
    {
        "INSUFFICIENT_VERIFIED_EVIDENCE",
        "NO_POLICY_BREACH",
        "POLICY_REQUIREMENT_NOT_MET",
        "PRECAUTIONARY_ACTION_REQUIRED",
        "RISK_MITIGATED",
    }
)
_ACTIONS = frozenset(
    {"REQUEST_MATCHING", "SUBMIT_DEMAND", "VERIFY_DEMAND"}
)
_SOURCE_KEYS = frozenset(
    {
        "action_codes",
        "active_holds",
        "case_aggregate_version",
        "case_id",
        "case_status",
        "demand_aggregate_version",
        "demand_content_sha256",
        "demand_id",
        "demand_version_id",
        "demand_version_no",
        "organization_id",
        "outcome_code",
        "reason_codes",
        "report_content_sha256",
        "report_id",
        "triage_version",
    }
)
_HOLD_KEYS = frozenset({"action_codes", "hold_id", "hold_version", "status"})
_POLICY_VERSION = "trust-case-outcome-v1"
_REDACTION_PROFILE = "PARTY_SAFE_V1"
_REDACTION_DIGEST_DOMAIN = "trust-evidence-redaction-v1"


@dataclass(frozen=True)
class TrustOutcomeEvidenceRequest:
    actor_user_id: UUID
    session_id: UUID
    case_id: UUID
    expected_case_version: int
    outcome_code: str
    reason_codes: Tuple[str, ...]
    action_codes: Tuple[str, ...]

    def __post_init__(self) -> None:
        _require_uuid(self.actor_user_id)
        _require_uuid(self.session_id)
        _require_uuid(self.case_id)
        if type(self.expected_case_version) is not int or self.expected_case_version < 1:
            raise ValueError("Trust outcome evidence version is invalid")
        _require_code(self.outcome_code, _OUTCOMES)
        _require_codes(self.reason_codes, _REASONS, 1, 8)
        _require_codes(self.action_codes, _ACTIONS, 0, 3)
        if (
            self.outcome_code in {"NO_ACTION", "PROTECTION_LIFTED"}
            and self.action_codes
        ) or (
            self.outcome_code not in {"NO_ACTION", "PROTECTION_LIFTED"}
            and not self.action_codes
        ):
            raise ValueError("Trust outcome evidence action shape is invalid")


class PsycopgTrustOutcomeEvidenceProvider:
    """Read an authorized safe snapshot and derive one five-minute packet."""

    def __init__(
        self,
        *,
        officer_connections: Any,
        id_source: Any,
        settings: TrustPostgresGatewaySettings = TrustPostgresGatewaySettings(),
    ) -> None:
        if not all(
            callable(getattr(officer_connections, name, None))
            for name in ("checkout", "release", "discard")
        ):
            raise TypeError("Trust officer connection source is unavailable")
        if not callable(getattr(id_source, "new_id", None)):
            raise TypeError("Trust evidence identifier source is unavailable")
        if not isinstance(settings, TrustPostgresGatewaySettings):
            raise TypeError("Trust PostgreSQL gateway settings are unavailable")
        self._connections = officer_connections
        self._id_source = id_source
        self._settings = settings
        self._closed = False

    def prepare_for_postgres(
        self,
        request: TrustOutcomeEvidenceRequest,
    ) -> TrustOutcomePostgresEvidence:
        if not isinstance(request, TrustOutcomeEvidenceRequest):
            raise TypeError("Trust outcome evidence request is unavailable")
        try:
            evidence, _ = self._prepare(request)
            return evidence
        except TrustDecisionEvidenceUnavailableError:
            raise
        except Exception:
            raise TrustDecisionEvidenceUnavailableError() from None

    def prepare_initial_outcome(
        self,
        *,
        officer_authority: TrustOfficerAuthority,
        case: SafetyCase,
        report: SafetyReport,
        triage: TrustTriageVersion,
        active_holds: Tuple[SafetyHold, ...],
        outcome: TrustCaseOutcome,
        reason_codes: Tuple[str, ...],
        action_codes: Tuple[Any, ...],
        now: datetime,
    ) -> TrustInitialOutcomeEvidence:
        try:
            if (
                not isinstance(officer_authority, TrustOfficerAuthority)
                or not isinstance(case, SafetyCase)
                or not isinstance(report, SafetyReport)
                or not isinstance(triage, TrustTriageVersion)
                or type(active_holds) is not tuple
                or any(not isinstance(item, SafetyHold) for item in active_holds)
                or not isinstance(outcome, TrustCaseOutcome)
                or not isinstance(now, datetime)
                or now.tzinfo is None
                or now.utcoffset() is None
            ):
                raise ValueError
            action_values = tuple(item.value for item in action_codes)
            request = TrustOutcomeEvidenceRequest(
                actor_user_id=UUID(officer_authority.actor_user_id),
                session_id=UUID(officer_authority.session_id),
                case_id=UUID(case.case_id),
                expected_case_version=case.aggregate_version,
                outcome_code=outcome.value,
                reason_codes=reason_codes,
                action_codes=action_values,
            )
            evidence, source = self._prepare(request)
            _validate_domain_echo(
                source=source,
                case=case,
                report=report,
                triage=triage,
                active_holds=active_holds,
            )
            return TrustInitialOutcomeEvidence(
                case_id=str(evidence.case_id),
                case_aggregate_version=evidence.case_aggregate_version,
                triage_version=evidence.triage_version,
                outcome_code=evidence.outcome_code,
                reason_codes=evidence.reason_codes,
                action_codes=evidence.action_codes,
                evidence_packet_version_id=str(
                    evidence.evidence_packet_version_id
                ),
                evidence_packet_digest=evidence.evidence_packet_digest.hex(),
                source_digest=evidence.source_digest.hex(),
                appeal_eligible=evidence.appeal_eligible,
                appeal_eligibility_code=evidence.appeal_eligibility_code,
                appeal_deadline=evidence.appeal_deadline,
                policy_version=evidence.policy_version,
                redaction_profile_code=evidence.redaction_profile_code,
                evaluated_at=evidence.evaluated_at,
                valid_until=evidence.valid_until,
            )
        except TrustDecisionEvidenceUnavailableError:
            raise
        except Exception:
            raise TrustDecisionEvidenceUnavailableError() from None

    def close(self) -> None:
        self._closed = True

    def _prepare(
        self,
        request: TrustOutcomeEvidenceRequest,
    ) -> tuple[TrustOutcomePostgresEvidence, Mapping[str, Any]]:
        if self._closed:
            raise TrustPostgresConfigurationError()
        canonical, source, evaluated_at, valid_until = self._read_source(request)
        source_digest = hashlib.sha256(
            "\x1f".join(
                ("desire:trust:outcome-source:v1", canonical)
            ).encode("utf-8")
        ).digest()
        packet_id = _new_id(self._id_source, "trust_evidence_packet_version")
        appeal_deadline = evaluated_at + timedelta(days=7)
        packet_digest = outcome_packet_digest(
            evidence_packet_version_id=packet_id,
            source_digest=source_digest,
            outcome_code=request.outcome_code,
            reason_codes=request.reason_codes,
            action_codes=request.action_codes,
            appeal_deadline=appeal_deadline,
            evaluated_at=evaluated_at,
            valid_until=valid_until,
        )
        return (
            TrustOutcomePostgresEvidence(
                case_id=request.case_id,
                case_aggregate_version=request.expected_case_version,
                triage_version=source["triage_version"],
                outcome_code=request.outcome_code,
                reason_codes=request.reason_codes,
                action_codes=request.action_codes,
                evidence_packet_version_id=packet_id,
                evidence_packet_digest=packet_digest,
                source_digest=source_digest,
                appeal_eligible=True,
                appeal_eligibility_code="ELIGIBLE",
                appeal_deadline=appeal_deadline,
                policy_version=_POLICY_VERSION,
                redaction_profile_code=_REDACTION_PROFILE,
                evaluated_at=evaluated_at,
                valid_until=valid_until,
            ),
            source,
        )

    def _read_source(
        self,
        request: TrustOutcomeEvidenceRequest,
    ) -> tuple[str, Mapping[str, Any], datetime, datetime]:
        connection = None
        transaction = False
        disposed = False
        try:
            connection = self._connections.checkout()
            _prepare(connection, "trust_officer")
            # The fixed source program locks the case and active assignment so the
            # evidence snapshot cannot race the subsequent outcome write.  PostgreSQL
            # forbids those row locks in a READ ONLY transaction.
            connection.execute("BEGIN ISOLATION LEVEL REPEATABLE READ")
            transaction = True
            _configure(
                connection,
                settings=self._settings,
                scope="TRUST_OFFICER",
                operation="PUBLISH_OUTCOME",
                actor_id=request.actor_user_id,
                session_id=request.session_id,
                organization_id=None,
            )
            rows = connection.execute(
                "SELECT * FROM trust_api.read_outcome_evidence_source_v1("
                + ",".join(["%s"] * 7)
                + ")",
                (
                    request.actor_user_id,
                    request.session_id,
                    request.case_id,
                    request.expected_case_version,
                    request.outcome_code,
                    list(request.reason_codes),
                    list(request.action_codes),
                ),
            ).fetchmany(2)
            canonical, source, evaluated_at, valid_until = _parse_source(
                rows, request
            )
            connection.execute("COMMIT")
            transaction = False
            _reset(connection)
            self._connections.release(connection)
            disposed = True
            return canonical, source, evaluated_at, valid_until
        except BaseException as error:
            if connection is not None and transaction:
                try:
                    connection.execute("ROLLBACK")
                except BaseException:
                    pass
            if connection is not None and not disposed:
                _discard(self._connections, connection)
                disposed = True
            if isinstance(error, (TrustPostgresConfigurationError, ValueError)):
                raise
            translated = _database_error(error)
            if translated is not None:
                raise translated from None
            raise TrustPostgresConfigurationError() from None
        finally:
            if connection is not None and not disposed:
                _discard(self._connections, connection)


def outcome_packet_digest(
    *,
    evidence_packet_version_id: UUID,
    source_digest: bytes,
    outcome_code: str,
    reason_codes: Tuple[str, ...],
    action_codes: Tuple[str, ...],
    appeal_deadline: datetime,
    evaluated_at: datetime,
    valid_until: datetime,
) -> bytes:
    _require_uuid(evidence_packet_version_id)
    if not isinstance(source_digest, bytes) or len(source_digest) != 32:
        raise ValueError("Trust outcome source digest is invalid")
    return hashlib.sha256(
        "\x1f".join(
            (
                "desire:trust:outcome-evidence-packet:v1",
                _REDACTION_DIGEST_DOMAIN,
                str(evidence_packet_version_id),
                source_digest.hex(),
                outcome_code,
                "\x1e".join(reason_codes),
                "\x1e".join(action_codes),
                "ELIGIBLE",
                _utc_text(appeal_deadline),
                _POLICY_VERSION,
                _REDACTION_PROFILE,
                _utc_text(evaluated_at),
                _utc_text(valid_until),
            )
        ).encode("utf-8")
    ).digest()


def _parse_source(
    rows: Any,
    request: TrustOutcomeEvidenceRequest,
) -> tuple[str, Mapping[str, Any], datetime, datetime]:
    if not isinstance(rows, list) or len(rows) != 1:
        raise TrustPostgresConfigurationError()
    row = rows[0]
    if not isinstance(row, tuple) or len(row) != 3:
        raise TrustPostgresConfigurationError()
    canonical, evaluated_at, valid_until = row
    if not isinstance(canonical, str):
        raise TrustPostgresConfigurationError()
    try:
        source = json.loads(canonical)
    except (TypeError, ValueError):
        raise TrustPostgresConfigurationError() from None
    if not isinstance(source, dict) or set(source) != _SOURCE_KEYS:
        raise TrustPostgresConfigurationError()
    if (
        _uuid_text(source["case_id"]) != str(request.case_id)
        or source["case_aggregate_version"] != request.expected_case_version
        or source["case_status"] != "IN_REVIEW"
        or source["outcome_code"] != request.outcome_code
        or source["reason_codes"] != list(request.reason_codes)
        or source["action_codes"] != list(request.action_codes)
    ):
        raise TrustPostgresConfigurationError()
    for key in (
        "organization_id",
        "demand_id",
        "demand_version_id",
        "report_id",
    ):
        if _uuid_text(source[key]) is None:
            raise TrustPostgresConfigurationError()
    for key in (
        "case_aggregate_version",
        "demand_aggregate_version",
        "demand_version_no",
        "triage_version",
    ):
        if type(source[key]) is not int or source[key] < 1:
            raise TrustPostgresConfigurationError()
    for key in (
        "demand_content_sha256",
        "report_content_sha256",
    ):
        if not _hex_digest(source[key]):
            raise TrustPostgresConfigurationError()
    holds = source["active_holds"]
    if not isinstance(holds, list) or len(holds) > 100:
        raise TrustPostgresConfigurationError()
    hold_ids: list[str] = []
    for hold in holds:
        if not isinstance(hold, dict) or set(hold) != _HOLD_KEYS:
            raise TrustPostgresConfigurationError()
        hold_id = _uuid_text(hold["hold_id"])
        if (
            hold_id is None
            or type(hold["hold_version"]) is not int
            or hold["hold_version"] < 1
            or hold["status"] != "ACTIVE"
        ):
            raise TrustPostgresConfigurationError()
        _require_json_codes(hold["action_codes"], _ACTIONS, 1, 3)
        hold_ids.append(hold_id)
    if hold_ids != sorted(hold_ids) or len(hold_ids) != len(set(hold_ids)):
        raise TrustPostgresConfigurationError()
    evaluated = _utc(evaluated_at)
    valid = _utc(valid_until)
    validation_now = datetime.now(timezone.utc)
    if (
        valid - evaluated != timedelta(minutes=5)
        or valid <= validation_now
        or evaluated > validation_now + timedelta(seconds=5)
    ):
        raise TrustPostgresConfigurationError()
    return canonical, source, evaluated, valid


def _validate_domain_echo(
    *,
    source: Mapping[str, Any],
    case: SafetyCase,
    report: SafetyReport,
    triage: TrustTriageVersion,
    active_holds: Tuple[SafetyHold, ...],
) -> None:
    if (
        source["case_id"] != case.case_id
        or source["case_aggregate_version"] != case.aggregate_version
        or case.status is not SafetyCaseStatus.IN_REVIEW
        or source["case_status"] != case.status.value
        or source["organization_id"] != case.organization_id
        or source["demand_id"] != case.demand_id
        or source["demand_version_id"] != case.demand_version_id
        or source["report_id"] != report.report_id
        or source["demand_version_no"] != report.demand_version_no
        or source["demand_aggregate_version"] != report.demand_aggregate_version
        or source["demand_content_sha256"] != report.demand_content_sha256
        or source["report_content_sha256"] != _report_safe_digest(report)
        or source["triage_version"] != triage.version
    ):
        raise TrustPostgresConfigurationError()
    expected_holds = [
        {
            "action_codes": [item.value for item in hold.action_codes],
            "hold_id": hold.hold_id,
            "hold_version": hold.aggregate_version,
            "status": hold.status.value,
        }
        for hold in sorted(active_holds, key=lambda item: item.hold_id)
        if hold.status is SafetyHoldStatus.ACTIVE
    ]
    if source["active_holds"] != expected_holds:
        raise TrustPostgresConfigurationError()


def _report_safe_digest(report: SafetyReport) -> str:
    return hashlib.sha256(
        "\x1f".join(
            (
                "desire:trust:outcome-report-safe-content:v1",
                report.report_id,
                report.organization_id,
                report.demand_id,
                report.demand_version_id,
                str(report.demand_version_no),
                str(report.demand_aggregate_version),
                report.demand_status,
                report.demand_content_sha256,
                report.category.value,
                _utc_text(report.incident_started_at),
                "null"
                if report.incident_ended_at is None
                else _utc_text(report.incident_ended_at),
                "\x1e".join(report.impact_codes),
                "\x1e".join(report.evidence_reference_ids),
                "\x1e".join(report.requested_protection_codes),
                _utc_text(report.created_at),
            )
        ).encode("utf-8")
    ).hexdigest()


def _new_id(source: Any, kind: str) -> UUID:
    value = source.new_id(kind)
    if isinstance(value, UUID):
        result = value
    elif isinstance(value, str):
        try:
            result = UUID(value)
        except ValueError:
            raise ValueError("Trust evidence identifier is invalid") from None
    else:
        raise ValueError("Trust evidence identifier is invalid")
    _require_uuid(result)
    return result


def _require_uuid(value: Any) -> None:
    if not isinstance(value, UUID) or value.int == 0:
        raise ValueError("Trust outcome evidence identifier is invalid")


def _uuid_text(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = UUID(value)
    except ValueError:
        return None
    return value if parsed.int != 0 and str(parsed) == value else None


def _require_code(value: Any, allowed: frozenset[str]) -> None:
    if not isinstance(value, str) or value not in allowed:
        raise ValueError("Trust outcome evidence code is invalid")


def _require_codes(
    values: Any,
    allowed: frozenset[str],
    minimum: int,
    maximum: int,
) -> None:
    if (
        type(values) is not tuple
        or not minimum <= len(values) <= maximum
        or values != tuple(sorted(values))
        or len(values) != len(set(values))
        or any(not isinstance(item, str) or item not in allowed for item in values)
    ):
        raise ValueError("Trust outcome evidence code list is invalid")


def _require_json_codes(
    values: Any,
    allowed: frozenset[str],
    minimum: int,
    maximum: int,
) -> None:
    if not isinstance(values, list):
        raise TrustPostgresConfigurationError()
    try:
        _require_codes(tuple(values), allowed, minimum, maximum)
    except ValueError:
        raise TrustPostgresConfigurationError() from None


def _hex_digest(value: Any) -> bool:
    if not isinstance(value, str) or len(value) != 64 or value != value.lower():
        return False
    try:
        return len(bytes.fromhex(value)) == 32
    except ValueError:
        return False


def _utc(value: Any) -> datetime:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() is None
    ):
        raise TrustPostgresConfigurationError()
    return value.astimezone(timezone.utc)


def _utc_text(value: datetime) -> str:
    current = _utc(value)
    return (
        current.strftime("%Y-%m-%dT%H:%M:%S.%f")
        .rstrip("0")
        .rstrip(".")
        + "Z"
    )


__all__ = [
    "PsycopgTrustOutcomeEvidenceProvider",
    "TrustOutcomeEvidenceRequest",
    "outcome_packet_digest",
]
