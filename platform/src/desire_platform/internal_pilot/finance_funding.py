"""Synthetic-only Finance Operator funding-review contracts and PostgreSQL seam.

The browser surface represented here cannot assert that money exists.  It can
only record two independent, assignment-bound attestations over one immutable
INTERNAL_SANDBOX zero-funds evidence reference.  The PostgreSQL adapter is
defined later in this module so production composition has no Memory fallback.
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import hmac
import json
import re
from typing import Any, Mapping, Optional, Tuple, Union
from uuid import UUID

import psycopg

from ..demand.adapters.postgres.migrations import (
    DEMAND_REQUIRED_IAM_SCHEMA_VERSION,
    DEMAND_SCHEMA_HEAD_VERSION,
)
from ..identity_access.domain.platform_duties import PLATFORM_DUTY_CODES
from .editor.contracts import EditorPrincipal, EditorServiceError


FINANCE_FUNDING_ATTESTATION_CODES = (
    "SYNTHETIC_ONLY",
    "ZERO_REAL_FUNDS",
    "NO_PROVIDER_OR_PAYMENT",
    "TARGET_AND_EVIDENCE_MATCH",
)
FINANCE_FUNDING_ACTIONS = (
    "CONFIRM",
    "RELEASE_ASSIGNMENT",
    "SUBMIT_FINDING",
)
FINANCE_FUNDING_RELEASE_REASON_CODES = (
    "CONFLICT_DECLARED",
    "WORKLOAD_RELEASE",
)
FINANCE_FUNDING_FINDING_FIELD_CODES = (
    "BUDGET",
    "DECLARATIONS",
    "RISK",
    "SCOPE",
)
FINANCE_FUNDING_FINDING_REASON_CODES = {
    "DISCREPANCY": (
        "EVIDENCE_REFERENCE_MISMATCH",
        "TARGET_CONTENT_MISMATCH",
    ),
    "REJECTED": (
        "BUDGET_PLAN_UNACCEPTABLE",
        "DECLARATION_CONFLICT",
        "SYNTHETIC_SCOPE_VIOLATION",
    ),
}
FINANCE_FUNDING_EVIDENCE_KIND = "INTERNAL_SANDBOX_ZERO_FUNDS_V1"
FINANCE_FUNDING_LEGAL_EFFECT = "NO_REAL_FUNDS_OR_PAYMENT"

_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_KEY_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_FINANCE_FUNDING_HISTORY_CURSOR = re.compile(
    r"[A-Za-z0-9_-]{64,1024}\.[A-Za-z0-9_-]{43}\Z"
)
_FINANCE_FUNDING_HISTORY_CURSOR_DOMAIN = (
    b"desire:finance-funding-review-history-cursor:v1\x00"
)


@dataclass(frozen=True)
class FinanceFundingQueueItemDto:
    """Minimal pre-assignment projection; organization and Demand body stay hidden."""

    demand_id: str
    demand_version_id: str
    demand_revision: int
    funding_review_id: Optional[str]
    review_status: str
    review_revision: Optional[int]
    assigned_to_me: bool
    confirmation_count: int
    required_confirmations: int
    expires_at: datetime
    etag: str

    def __post_init__(self) -> None:
        demand_id = _uuid(self.demand_id)
        _uuid(self.demand_version_id)
        review_id = (
            None
            if self.funding_review_id is None
            else _uuid(self.funding_review_id)
        )
        _utc(self.expires_at)
        if (
            type(self.demand_revision) is not int
            or self.demand_revision < 1
            or type(self.confirmation_count) is not int
            or self.confirmation_count not in (0, 1)
            or self.required_confirmations != 2
            or self.review_status not in {"AVAILABLE", "PENDING"}
            or type(self.assigned_to_me) is not bool
            or (
                self.review_status == "AVAILABLE"
                and (
                    review_id is not None
                    or self.review_revision is not None
                    or self.assigned_to_me
                )
            )
            or (
                self.review_status == "PENDING"
                and (
                    review_id is None
                    or type(self.review_revision) is not int
                    or self.review_revision < 1
                )
            )
        ):
            raise ValueError("Finance funding queue item is invalid")
        expected_etag = (
            f'"demand-{self.demand_revision}-finance-queue"'
            if review_id is None
            else f'"funding-review-{self.review_revision}"'
        )
        if self.etag != expected_etag or demand_id.int == 0:
            raise ValueError("Finance funding queue item is invalid")


@dataclass(frozen=True)
class FinanceFundingReviewDto:
    """One assignment-scoped, zero-funds manual-review projection."""

    funding_review_id: str
    demand_id: str
    demand_version_id: str
    status: str
    revision: int
    assignment_id: str
    assignment_expires_at: datetime
    target_sha256: str
    target_content_sha256: str
    planned_budget_currency: str
    planned_budget_minimum_amount_minor: int
    planned_budget_maximum_amount_minor: int
    planned_budget_direct_cost_amount_minor: int
    evidence_kind: str
    evidence_reference_sha256: str
    sandbox_funds_amount_minor: int
    provider_code: str
    payment_operation_code: str
    synthetic: bool
    legal_effect: str
    confirmation_count: int
    required_confirmations: int
    assignment_status: str
    confirmation_by_me: bool
    available_actions: Tuple[str, ...]
    can_confirm: bool
    etag: str
    replayed: bool

    def __post_init__(self) -> None:
        identifiers = (
            _uuid(self.funding_review_id),
            _uuid(self.demand_id),
            _uuid(self.demand_version_id),
            _uuid(self.assignment_id),
        )
        _utc(self.assignment_expires_at)
        expected_actions = (
            FINANCE_FUNDING_ACTIONS
            if (
                self.status == "PENDING"
                and self.assignment_status == "ACTIVE"
                and self.confirmation_by_me is False
            )
            else ()
        )
        if (
            any(value.int == 0 for value in identifiers)
            or self.status not in {
                "PENDING", "SECURED", "DISCREPANCY", "REJECTED"
            }
            or type(self.confirmation_count) is not int
            or self.confirmation_count not in (0, 1, 2)
            or self.required_confirmations != 2
            or type(self.revision) is not int
            or self.revision < 1
            or (self.status == "SECURED") != (self.confirmation_count == 2)
            or (
                self.status in {"DISCREPANCY", "REJECTED"}
                and self.confirmation_count == 2
            )
            or _SHA256.fullmatch(self.target_content_sha256) is None
            or self.planned_budget_currency != "CNY"
            or any(
                type(value) is not int
                or value < 0
                or value > 9_007_199_254_740_991
                for value in (
                    self.planned_budget_minimum_amount_minor,
                    self.planned_budget_maximum_amount_minor,
                    self.planned_budget_direct_cost_amount_minor,
                )
            )
            or self.planned_budget_minimum_amount_minor
            > self.planned_budget_maximum_amount_minor
            or self.evidence_kind != FINANCE_FUNDING_EVIDENCE_KIND
            or _SHA256.fullmatch(self.target_sha256) is None
            or _SHA256.fullmatch(self.evidence_reference_sha256) is None
            or type(self.sandbox_funds_amount_minor) is not int
            or self.sandbox_funds_amount_minor != 0
            or self.provider_code != "NONE"
            or self.payment_operation_code != "NONE"
            or self.synthetic is not True
            or self.legal_effect != FINANCE_FUNDING_LEGAL_EFFECT
            or type(self.can_confirm) is not bool
            or (self.status == "SECURED" and self.can_confirm)
            or self.assignment_status not in {
                "ACTIVE", "COMPLETED", "RELEASED", "EXPIRED", "REVOKED"
            }
            or type(self.confirmation_by_me) is not bool
            or not isinstance(self.available_actions, tuple)
            or self.available_actions != expected_actions
            or self.can_confirm != ("CONFIRM" in self.available_actions)
            or (
                self.confirmation_by_me
                and self.assignment_status != "COMPLETED"
            )
            or self.etag != f'"funding-review-{self.revision}"'
            or type(self.replayed) is not bool
        ):
            raise ValueError("Finance funding review is invalid")


@dataclass(frozen=True)
class FinanceFundingHistoryItemDto:
    """Current-operator terminal review fact without tenant or peer metadata."""

    funding_review_id: str
    demand_id: str
    demand_version_id: str
    status: str
    completed_at: datetime

    def __post_init__(self) -> None:
        try:
            identifiers = tuple(
                _uuid(value)
                for value in (
                    self.funding_review_id,
                    self.demand_id,
                    self.demand_version_id,
                )
            )
            completed_at = _utc(self.completed_at)
        except (TypeError, ValueError):
            raise ValueError("Finance funding history item is invalid") from None
        if (
            any(identifier.int == 0 for identifier in identifiers)
            or self.status not in {"SECURED", "DISCREPANCY", "REJECTED"}
            or completed_at != self.completed_at.astimezone(timezone.utc)
        ):
            raise ValueError("Finance funding history item is invalid")


@dataclass(frozen=True)
class FinanceFundingHistoryPageDto:
    """Stable actor-bound keyset page of terminal funding reviews."""

    schema_version: str
    items: Tuple[FinanceFundingHistoryItemDto, ...]
    next_cursor: Optional[str]
    has_more: bool

    def __post_init__(self) -> None:
        if (
            self.schema_version != "finance-funding-review-history-v1"
            or not isinstance(self.items, tuple)
            or len(self.items) > 100
            or any(
                not isinstance(item, FinanceFundingHistoryItemDto)
                for item in self.items
            )
            or len({item.funding_review_id for item in self.items})
            != len(self.items)
            or type(self.has_more) is not bool
            or (self.next_cursor is None) is not (not self.has_more)
            or (
                self.next_cursor is not None
                and _FINANCE_FUNDING_HISTORY_CURSOR.fullmatch(
                    self.next_cursor
                ) is None
            )
        ):
            raise ValueError("Finance funding history page is invalid")
        coordinates = tuple(
            (_utc(item.completed_at), UUID(item.funding_review_id).int)
            for item in self.items
        )
        if any(
            left <= right for left, right in zip(coordinates, coordinates[1:])
        ):
            raise ValueError("Finance funding history page is invalid")


class FinanceFundingDomainError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class FinanceFundingReviewState:
    """Pure four-eyes state used to keep the PostgreSQL transition honest."""

    funding_review_id: str
    demand_id: str
    demand_version_id: str
    status: str
    revision: int
    assigned_user_ids: Tuple[str, ...]
    confirmed_user_ids: Tuple[str, ...]

    def __post_init__(self) -> None:
        _uuid(self.funding_review_id)
        _uuid(self.demand_id)
        _uuid(self.demand_version_id)
        assigned = tuple(_uuid(value) for value in self.assigned_user_ids)
        confirmed = tuple(_uuid(value) for value in self.confirmed_user_ids)
        if (
            self.status not in {
                "PENDING", "SECURED", "DISCREPANCY", "REJECTED"
            }
            or type(self.revision) is not int
            or self.revision < 1
            or not 0 <= len(assigned) <= 2
            or len(set(assigned)) != len(assigned)
            or len(set(confirmed)) != len(confirmed)
            or not set(confirmed).issubset(assigned)
            or (self.status == "SECURED") != (len(confirmed) == 2)
            or (
                self.status in {"DISCREPANCY", "REJECTED"}
                and len(confirmed) == 2
            )
        ):
            raise ValueError("Finance funding review state is invalid")

    @classmethod
    def start(
        cls,
        *,
        funding_review_id: str,
        demand_id: str,
        demand_version_id: str,
        actor_user_id: str,
    ) -> "FinanceFundingReviewState":
        return cls(
            funding_review_id=funding_review_id,
            demand_id=demand_id,
            demand_version_id=demand_version_id,
            status="PENDING",
            revision=1,
            assigned_user_ids=(actor_user_id,),
            confirmed_user_ids=(),
        )

    def assign(self, *, actor_user_id: str) -> "FinanceFundingReviewState":
        _uuid(actor_user_id)
        if self.status != "PENDING":
            raise FinanceFundingDomainError("STATE_CONFLICT")
        if actor_user_id in self.assigned_user_ids:
            raise FinanceFundingDomainError("FUNDING_REVIEW_ALREADY_ASSIGNED")
        if actor_user_id in self.confirmed_user_ids:
            raise FinanceFundingDomainError("FUNDING_CONFIRMATION_DUPLICATE")
        if len(self.assigned_user_ids) >= 2:
            raise FinanceFundingDomainError("FUNDING_REVIEW_FULL")
        return FinanceFundingReviewState(
            funding_review_id=self.funding_review_id,
            demand_id=self.demand_id,
            demand_version_id=self.demand_version_id,
            status=self.status,
            revision=self.revision + 1,
            assigned_user_ids=self.assigned_user_ids + (actor_user_id,),
            confirmed_user_ids=self.confirmed_user_ids,
        )

    def release(self, *, actor_user_id: str) -> "FinanceFundingReviewState":
        """Release one unconfirmed active seat without erasing its DB history."""

        _uuid(actor_user_id)
        if self.status != "PENDING":
            raise FinanceFundingDomainError("STATE_CONFLICT")
        if actor_user_id not in self.assigned_user_ids:
            raise FinanceFundingDomainError("ASSIGNMENT_REQUIRED")
        if actor_user_id in self.confirmed_user_ids:
            raise FinanceFundingDomainError("FUNDING_CONFIRMATION_DUPLICATE")
        return FinanceFundingReviewState(
            funding_review_id=self.funding_review_id,
            demand_id=self.demand_id,
            demand_version_id=self.demand_version_id,
            status=self.status,
            revision=self.revision + 1,
            assigned_user_ids=tuple(
                value for value in self.assigned_user_ids
                if value != actor_user_id
            ),
            confirmed_user_ids=self.confirmed_user_ids,
        )

    def submit_finding(
        self,
        *,
        actor_user_id: str,
        disposition: str,
        reason_codes: Tuple[str, ...],
        required_field_codes: Tuple[str, ...],
    ) -> "FinanceFundingReviewState":
        _uuid(actor_user_id)
        _finding_codes(
            disposition=disposition,
            reason_codes=reason_codes,
            required_field_codes=required_field_codes,
        )
        if self.status != "PENDING":
            raise FinanceFundingDomainError("STATE_CONFLICT")
        if actor_user_id not in self.assigned_user_ids:
            raise FinanceFundingDomainError("ASSIGNMENT_REQUIRED")
        if actor_user_id in self.confirmed_user_ids:
            raise FinanceFundingDomainError("FUNDING_CONFIRMATION_DUPLICATE")
        return FinanceFundingReviewState(
            funding_review_id=self.funding_review_id,
            demand_id=self.demand_id,
            demand_version_id=self.demand_version_id,
            status=disposition,
            revision=self.revision + 1,
            assigned_user_ids=self.assigned_user_ids,
            confirmed_user_ids=self.confirmed_user_ids,
        )

    def confirm(
        self,
        *,
        actor_user_id: str,
        attestation_codes: Tuple[str, ...],
    ) -> "FinanceFundingReviewState":
        _uuid(actor_user_id)
        if attestation_codes != FINANCE_FUNDING_ATTESTATION_CODES:
            raise FinanceFundingDomainError("INVALID_ATTESTATION_CODES")
        if self.status != "PENDING":
            raise FinanceFundingDomainError("STATE_CONFLICT")
        if actor_user_id not in self.assigned_user_ids:
            raise FinanceFundingDomainError("ASSIGNMENT_REQUIRED")
        if actor_user_id in self.confirmed_user_ids:
            raise FinanceFundingDomainError("FUNDING_CONFIRMATION_DUPLICATE")
        confirmed = self.confirmed_user_ids + (actor_user_id,)
        return FinanceFundingReviewState(
            funding_review_id=self.funding_review_id,
            demand_id=self.demand_id,
            demand_version_id=self.demand_version_id,
            status="SECURED" if len(confirmed) == 2 else "PENDING",
            revision=self.revision + 1,
            assigned_user_ids=self.assigned_user_ids,
            confirmed_user_ids=confirmed,
        )


class FinanceFundingPostgresError(RuntimeError):
    """Closed failure from the Finance funding fixed PostgreSQL boundary."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class FinanceFundingCommitOutcomeUnknownError(FinanceFundingPostgresError):
    def __init__(self) -> None:
        super().__init__("COMMAND_OUTCOME_UNKNOWN")


@dataclass(frozen=True)
class FinanceFundingKeys:
    """Purpose-separated keys reused from the reviewed Demand key policy."""

    id_key: Union[bytes, bytearray] = field(repr=False)
    idempotency_key: Union[bytes, bytearray] = field(repr=False)
    payload_key: Union[bytes, bytearray] = field(repr=False)
    idempotency_key_id: str = "demand-idempotency-2026-01"
    payload_key_id: str = "demand-payload-2026-01"

    def __post_init__(self) -> None:
        values = (self.id_key, self.idempotency_key, self.payload_key)
        if (
            any(
                not isinstance(value, (bytes, bytearray))
                or len(value) < 32
                or not any(value)
                for value in values
            )
            or len({bytes(value) for value in values}) != 3
            or _KEY_ID.fullmatch(self.idempotency_key_id) is None
            or _KEY_ID.fullmatch(self.payload_key_id) is None
            or self.idempotency_key_id == self.payload_key_id
        ):
            raise ValueError("Finance funding keys are invalid")


class PsycopgFinanceFundingService:
    """List/detail/write service over the role-bound ``demand_finance`` pool."""

    def __init__(self, *, connections: Any, keys: FinanceFundingKeys) -> None:
        if not all(
            callable(getattr(connections, name, None))
            for name in ("checkout", "release", "discard")
        ):
            raise TypeError("Finance funding PostgreSQL pool is unavailable")
        if not isinstance(keys, FinanceFundingKeys):
            raise TypeError("Finance funding keys are unavailable")
        self._connections = connections
        self._keys = keys
        self._closed = False

    def list_funding_reviews(
        self, *, principal: EditorPrincipal
    ) -> Tuple[FinanceFundingQueueItemDto, ...]:
        _finance_principal(principal)

        def project(connection: Any) -> Tuple[FinanceFundingQueueItemDto, ...]:
            rows = tuple(
                connection.execute(
                    "SELECT demand_id,demand_version_id,demand_revision,"
                    "funding_review_id,review_status,confirmation_count,"
                    "review_revision,assigned_to_me,expires_at FROM "
                    "demand_api.list_manual_funding_reviews_v2(%s,%s,%s,%s)",
                    (
                        UUID(principal.user_id),
                        UUID(principal.session_id),
                        principal.principal_marker_sha256,
                        100,
                    ),
                ).fetchall()
            )
            if len(rows) > 100 or any(len(row) != 9 for row in rows):
                raise FinanceFundingPostgresError("SERVICE_UNAVAILABLE")
            return tuple(_queue_item(row) for row in rows)

        return self._read(
            principal=principal,
            operation="LIST_FUNDING_REVIEWS",
            projector=project,
        )

    def list_funding_review_history(
        self,
        *,
        principal: EditorPrincipal,
        cursor: Optional[str],
        limit: int,
    ) -> FinanceFundingHistoryPageDto:
        _finance_principal(principal)
        if type(limit) is not int or not 1 <= limit <= 100:
            raise EditorServiceError(
                status=422,
                code="INVALID_PAGE_LIMIT",
                path="/query/limit",
            )
        cursor_completed_at: Optional[datetime] = None
        cursor_review_id: Optional[UUID] = None
        if cursor is not None:
            try:
                cursor_completed_at, cursor_review_id = (
                    _decode_finance_funding_history_cursor(
                        cursor=cursor,
                        actor_user_id=principal.user_id,
                        key=self._keys.payload_key,
                    )
                )
            except (TypeError, ValueError):
                raise EditorServiceError(
                    status=422,
                    code="INVALID_CURSOR",
                    path="/query/cursor",
                ) from None

        def project(connection: Any) -> FinanceFundingHistoryPageDto:
            rows = tuple(
                connection.execute(
                    "SELECT funding_review_id,demand_id,demand_version_id,"
                    "status,completed_at FROM "
                    "demand_api.list_manual_funding_review_history_v1("
                    "%s,%s,%s,%s,%s,%s)",
                    (
                        UUID(principal.user_id),
                        UUID(principal.session_id),
                        principal.principal_marker_sha256,
                        limit,
                        cursor_completed_at,
                        cursor_review_id,
                    ),
                ).fetchall()
            )
            if len(rows) > limit + 1 or any(len(row) != 5 for row in rows):
                raise FinanceFundingPostgresError("SERVICE_UNAVAILABLE")
            history = tuple(
                FinanceFundingHistoryItemDto(
                    funding_review_id=str(row[0]),
                    demand_id=str(row[1]),
                    demand_version_id=str(row[2]),
                    status=str(row[3]),
                    completed_at=_utc(row[4]),
                )
                for row in rows
            )
            coordinates = tuple(
                (item.completed_at, UUID(item.funding_review_id).int)
                for item in history
            )
            if (
                len({item.funding_review_id for item in history})
                != len(history)
                or any(
                    left <= right
                    for left, right in zip(coordinates, coordinates[1:])
                )
            ):
                raise FinanceFundingPostgresError("SERVICE_UNAVAILABLE")
            has_more = len(history) > limit
            items = history[:limit]
            next_cursor = (
                _encode_finance_funding_history_cursor(
                    item=items[-1],
                    actor_user_id=principal.user_id,
                    key=self._keys.payload_key,
                )
                if has_more and items
                else None
            )
            return FinanceFundingHistoryPageDto(
                schema_version="finance-funding-review-history-v1",
                items=items,
                next_cursor=next_cursor,
                has_more=has_more,
            )

        # IAM31 names the current-duty read capability LIST_FUNDING_REVIEWS.
        # Demand12 narrows app.operation after that authority check succeeds.
        return self._read(
            principal=principal,
            operation="LIST_FUNDING_REVIEWS",
            projector=project,
        )

    def get_funding_review(
        self, *, principal: EditorPrincipal, funding_review_id: str
    ) -> FinanceFundingReviewDto:
        _finance_principal(principal)
        review_id = _uuid(funding_review_id)

        def project(connection: Any) -> FinanceFundingReviewDto:
            row = connection.execute(
                "SELECT funding_review_id,demand_id,demand_version_id,status,"
                "review_revision,assignment_id,assignment_expires_at,"
                "target_sha256,evidence_reference_sha256,confirmation_count,"
                "assignment_status,confirmation_by_me,available_actions,"
                "can_confirm FROM demand_api.get_manual_funding_review_v2("
                "%s,%s,%s,%s)",
                (
                    UUID(principal.user_id),
                    UUID(principal.session_id),
                    review_id,
                    principal.principal_marker_sha256,
                ),
            ).fetchone()
            if row is None:
                raise FinanceFundingPostgresError("RESOURCE_NOT_FOUND")
            projected_review_id, assignment_id = _review_projection_ids(row)
            _bind_review_projection(
                connection,
                funding_review_id=projected_review_id,
                assignment_id=assignment_id,
            )
            evidence = _funding_evidence(
                connection,
                principal=principal,
                funding_review_id=projected_review_id,
            )
            return _review(row, evidence=evidence, replayed=False)

        return self._read(
            principal=principal,
            operation="GET_FUNDING_REVIEW",
            funding_review_id=review_id,
            projector=project,
        )

    def claim_funding_review(
        self,
        *,
        principal: EditorPrincipal,
        demand_id: str,
        if_match: str,
        idempotency_key: str,
    ) -> FinanceFundingReviewDto:
        _finance_principal(principal)
        target_id = _uuid(demand_id)
        expected_demand_revision, expected_review_revision = _queue_etag(if_match)
        payload = {
            "demand_id": demand_id,
            "if_match": if_match,
        }
        command_id = self._command_id(
            principal, "CLAIM_MANUAL_FUNDING_REVIEW", idempotency_key
        )
        return self._write(
            principal=principal,
            operation="CLAIM_FUNDING_REVIEW",
            demand_id=target_id,
            sql=(
                "SELECT funding_review_id,demand_id,demand_version_id,status,"
                "review_revision,assignment_id,assignment_expires_at,"
                "target_sha256,evidence_reference_sha256,confirmation_count,"
                "assignment_status,confirmation_by_me,available_actions,"
                "can_confirm,replayed FROM "
                "demand_api.claim_manual_funding_review_v2("
                + ",".join(("%s",) * 22)
                + ")"
            ),
            parameters=(
                UUID(principal.user_id),
                UUID(principal.session_id),
                target_id,
                expected_demand_revision,
                expected_review_revision,
                principal.principal_marker_sha256,
                self._scoped_id(command_id, "funding-review"),
                self._scoped_id(command_id, "funding"),
                self._scoped_id(command_id, "finance-assignment"),
                command_id,
                self._keys.idempotency_key_id,
                _hmac(self._keys.idempotency_key, idempotency_key.encode("utf-8")),
                self._keys.payload_key_id,
                _hmac(
                    self._keys.payload_key,
                    _canonical_payload("ClaimManualFundingReview", payload),
                ),
                self._scoped_id(command_id, "audit"),
                self._scoped_id(command_id, "outbox"),
                self._scoped_id(command_id, "correlation"),
                self._scoped_id(command_id, "causation"),
                self._scoped_id(command_id, "trace"),
                FINANCE_FUNDING_EVIDENCE_KIND,
                FINANCE_FUNDING_LEGAL_EFFECT,
                0,
            ),
        )

    def confirm_funding_review(
        self,
        *,
        principal: EditorPrincipal,
        funding_review_id: str,
        if_match: str,
        attestation_codes: Tuple[str, ...],
        idempotency_key: str,
    ) -> FinanceFundingReviewDto:
        _finance_principal(principal)
        review_id = _uuid(funding_review_id)
        expected_review_revision = _review_etag(if_match)
        if attestation_codes != FINANCE_FUNDING_ATTESTATION_CODES:
            raise EditorServiceError(
                status=422,
                code="INVALID_ATTESTATION_CODES",
                path="/attestation_codes",
            )
        payload = {
            "attestation_codes": list(attestation_codes),
            "funding_review_id": funding_review_id,
            "if_match": if_match,
        }
        command_id = self._command_id(
            principal, "CONFIRM_MANUAL_FUNDING_REVIEW", idempotency_key
        )
        return self._write(
            principal=principal,
            operation="CONFIRM_FUNDING_REVIEW",
            funding_review_id=review_id,
            sql=(
                "SELECT funding_review_id,demand_id,demand_version_id,status,"
                "review_revision,assignment_id,assignment_expires_at,"
                "target_sha256,evidence_reference_sha256,confirmation_count,"
                "assignment_status,confirmation_by_me,available_actions,"
                "can_confirm,replayed FROM "
                "demand_api.confirm_manual_funding_review_v2("
                + ",".join(("%s",) * 18)
                + ")"
            ),
            parameters=(
                UUID(principal.user_id),
                UUID(principal.session_id),
                review_id,
                expected_review_revision,
                principal.principal_marker_sha256,
                list(attestation_codes),
                self._scoped_id(command_id, "finance-confirmation"),
                self._scoped_id(command_id, "funding-marker"),
                command_id,
                self._keys.idempotency_key_id,
                _hmac(self._keys.idempotency_key, idempotency_key.encode("utf-8")),
                self._keys.payload_key_id,
                _hmac(
                    self._keys.payload_key,
                    _canonical_payload("ConfirmManualFundingReview", payload),
                ),
                self._scoped_id(command_id, "audit"),
                self._scoped_id(command_id, "outbox"),
                self._scoped_id(command_id, "correlation"),
                self._scoped_id(command_id, "causation"),
                self._scoped_id(command_id, "trace"),
            ),
        )

    def release_funding_review_assignment(
        self,
        *,
        principal: EditorPrincipal,
        funding_review_id: str,
        if_match: str,
        reason_code: str,
        idempotency_key: str,
    ) -> FinanceFundingReviewDto:
        _finance_principal(principal)
        review_id = _uuid(funding_review_id)
        expected_review_revision = _review_etag(if_match)
        if reason_code not in FINANCE_FUNDING_RELEASE_REASON_CODES:
            raise EditorServiceError(
                status=422, code="INVALID_REASON_CODE", path="/reason_code"
            )
        payload = {
            "funding_review_id": funding_review_id,
            "if_match": if_match,
            "reason_code": reason_code,
        }
        command_id = self._command_id(
            principal,
            "RELEASE_MANUAL_FUNDING_REVIEW_ASSIGNMENT",
            idempotency_key,
        )
        return self._write(
            principal=principal,
            operation="RELEASE_FUNDING_REVIEW_ASSIGNMENT",
            funding_review_id=review_id,
            sql=(
                "SELECT funding_review_id,demand_id,demand_version_id,status,"
                "review_revision,assignment_id,assignment_expires_at,"
                "target_sha256,evidence_reference_sha256,confirmation_count,"
                "assignment_status,confirmation_by_me,available_actions,"
                "can_confirm,replayed FROM "
                "demand_api.release_manual_funding_review_assignment_v1("
                + ",".join(("%s",) * 17)
                + ")"
            ),
            parameters=(
                UUID(principal.user_id),
                UUID(principal.session_id),
                review_id,
                expected_review_revision,
                principal.principal_marker_sha256,
                reason_code,
                self._scoped_id(command_id, "finance-assignment-release"),
                command_id,
                self._keys.idempotency_key_id,
                _hmac(self._keys.idempotency_key, idempotency_key.encode("utf-8")),
                self._keys.payload_key_id,
                _hmac(
                    self._keys.payload_key,
                    _canonical_payload(
                        "ReleaseManualFundingReviewAssignment", payload
                    ),
                ),
                self._scoped_id(command_id, "audit"),
                self._scoped_id(command_id, "outbox"),
                self._scoped_id(command_id, "correlation"),
                self._scoped_id(command_id, "causation"),
                self._scoped_id(command_id, "trace"),
            ),
        )

    def submit_funding_review_finding(
        self,
        *,
        principal: EditorPrincipal,
        funding_review_id: str,
        if_match: str,
        disposition: str,
        reason_codes: Tuple[str, ...],
        required_field_codes: Tuple[str, ...],
        idempotency_key: str,
    ) -> FinanceFundingReviewDto:
        _finance_principal(principal)
        review_id = _uuid(funding_review_id)
        expected_review_revision = _review_etag(if_match)
        try:
            _finding_codes(
                disposition=disposition,
                reason_codes=reason_codes,
                required_field_codes=required_field_codes,
            )
        except FinanceFundingDomainError as error:
            paths = {
                "INVALID_FINDING_DISPOSITION": "/disposition",
                "INVALID_FINDING_REASON_CODES": "/reason_codes",
                "INVALID_FINDING_FIELD_CODES": "/required_field_codes",
            }
            raise EditorServiceError(
                status=422, code=error.code, path=paths[error.code]
            ) from None
        payload = {
            "disposition": disposition,
            "funding_review_id": funding_review_id,
            "if_match": if_match,
            "reason_codes": list(reason_codes),
            "required_field_codes": list(required_field_codes),
        }
        command_id = self._command_id(
            principal,
            "SUBMIT_MANUAL_FUNDING_REVIEW_FINDING",
            idempotency_key,
        )
        return self._write(
            principal=principal,
            operation="SUBMIT_FUNDING_REVIEW_FINDING",
            funding_review_id=review_id,
            sql=(
                "SELECT funding_review_id,demand_id,demand_version_id,status,"
                "review_revision,assignment_id,assignment_expires_at,"
                "target_sha256,evidence_reference_sha256,confirmation_count,"
                "assignment_status,confirmation_by_me,available_actions,"
                "can_confirm,replayed FROM "
                "demand_api.submit_manual_funding_review_finding_v1("
                + ",".join(("%s",) * 19)
                + ")"
            ),
            parameters=(
                UUID(principal.user_id),
                UUID(principal.session_id),
                review_id,
                expected_review_revision,
                principal.principal_marker_sha256,
                disposition,
                list(reason_codes),
                list(required_field_codes),
                self._scoped_id(command_id, "finance-finding"),
                command_id,
                self._keys.idempotency_key_id,
                _hmac(self._keys.idempotency_key, idempotency_key.encode("utf-8")),
                self._keys.payload_key_id,
                _hmac(
                    self._keys.payload_key,
                    _canonical_payload(
                        "SubmitManualFundingReviewFinding", payload
                    ),
                ),
                self._scoped_id(command_id, "audit"),
                self._scoped_id(command_id, "outbox"),
                self._scoped_id(command_id, "correlation"),
                self._scoped_id(command_id, "causation"),
                self._scoped_id(command_id, "trace"),
            ),
        )

    def check_readiness(self, *, timeout_ms: int) -> None:
        if self._closed or type(timeout_ms) is not int or not 1 <= timeout_ms <= 30_000:
            raise RuntimeError("FINANCE_FUNDING_NOT_READY")
        connection: Any = None
        try:
            connection = self._connections.checkout()
            _prepare(connection)
            row = connection.execute(
                "SELECT "
                "pg_catalog.to_regprocedure('demand_api.list_manual_funding_reviews_v2(uuid,uuid,bytea,integer)') IS NOT NULL,"
                "pg_catalog.to_regprocedure('demand_api.list_manual_funding_review_history_v1(uuid,uuid,bytea,integer,timestamptz,uuid)') IS NOT NULL,"
                "pg_catalog.to_regprocedure('demand_api.get_manual_funding_review_v2(uuid,uuid,uuid,bytea)') IS NOT NULL,"
                "pg_catalog.to_regprocedure('demand_api.claim_manual_funding_review_v2(uuid,uuid,uuid,bigint,bigint,bytea,uuid,uuid,uuid,uuid,text,bytea,text,bytea,uuid,uuid,uuid,uuid,uuid,text,text,bigint)') IS NOT NULL,"
                "pg_catalog.to_regprocedure('demand_api.confirm_manual_funding_review_v2(uuid,uuid,uuid,bigint,bytea,text[],uuid,uuid,uuid,text,bytea,text,bytea,uuid,uuid,uuid,uuid,uuid)') IS NOT NULL,"
                "pg_catalog.to_regprocedure('demand_api.release_manual_funding_review_assignment_v1(uuid,uuid,uuid,bigint,bytea,text,uuid,uuid,text,bytea,text,bytea,uuid,uuid,uuid,uuid,uuid)') IS NOT NULL,"
                "pg_catalog.to_regprocedure('demand_api.submit_manual_funding_review_finding_v1(uuid,uuid,uuid,bigint,bytea,text,text[],text[],uuid,uuid,text,bytea,text,bytea,uuid,uuid,uuid,uuid,uuid)') IS NOT NULL,"
                "pg_catalog.to_regprocedure('demand_api.read_manual_funding_evidence_v2(uuid,uuid,uuid,bytea)') IS NOT NULL"
            ).fetchone()
            if row != (True, True, True, True, True, True, True, True):
                raise RuntimeError
            _reset(connection)
            self._connections.release(connection)
            connection = None
        except BaseException:
            if connection is not None:
                _discard(self._connections, connection)
            raise RuntimeError("FINANCE_FUNDING_NOT_READY") from None

    def close(self) -> None:
        self._closed = True

    def _read(
        self,
        *,
        principal: EditorPrincipal,
        operation: str,
        projector: Any,
        funding_review_id: Optional[UUID] = None,
    ) -> Any:
        if self._closed:
            raise EditorServiceError(status=503, code="SERVICE_UNAVAILABLE")
        connection: Any = None
        transaction = False
        released = False
        try:
            connection = self._connections.checkout()
            _prepare(connection)
            connection.execute(
                "BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY"
            )
            transaction = True
            _context(
                connection,
                principal=principal,
                operation=operation,
                funding_review_id=funding_review_id,
            )
            result = projector(connection)
            connection.execute("COMMIT")
            transaction = False
            _reset(connection)
            self._connections.release(connection)
            released = True
            return result
        except FinanceFundingPostgresError as error:
            if transaction:
                _rollback(connection)
            _discard(self._connections, connection)
            released = True
            _surface(error.code)
        except BaseException:
            if transaction:
                _rollback(connection)
            _discard(self._connections, connection)
            released = True
            raise EditorServiceError(status=503, code="SERVICE_UNAVAILABLE") from None
        finally:
            if connection is not None and not released:
                _discard(self._connections, connection)

    def _write(
        self,
        *,
        principal: EditorPrincipal,
        operation: str,
        sql: str,
        parameters: tuple[Any, ...],
        demand_id: Optional[UUID] = None,
        funding_review_id: Optional[UUID] = None,
    ) -> FinanceFundingReviewDto:
        if self._closed:
            raise EditorServiceError(status=503, code="SERVICE_UNAVAILABLE")
        connection: Any = None
        transaction = False
        commit_sent = False
        released = False
        try:
            connection = self._connections.checkout()
            _prepare(connection)
            connection.execute("BEGIN TRANSACTION ISOLATION LEVEL READ COMMITTED")
            transaction = True
            _context(
                connection,
                principal=principal,
                operation=operation,
                demand_id=demand_id,
                funding_review_id=funding_review_id,
            )
            row = connection.execute(sql, parameters).fetchone()
            if row is None:
                raise FinanceFundingPostgresError("RESOURCE_NOT_FOUND")
            review_id, assignment_id = _review_projection_ids(row[:14])
            _bind_review_projection(
                connection,
                funding_review_id=review_id,
                assignment_id=assignment_id,
            )
            evidence = _funding_evidence(
                connection,
                principal=principal,
                funding_review_id=review_id,
            )
            result = _review(row[:14], evidence=evidence, replayed=row[14])
            commit_sent = True
            connection.execute("COMMIT")
            transaction = False
            _reset(connection)
            self._connections.release(connection)
            released = True
            return result
        except psycopg.Error as error:
            if commit_sent:
                _discard(self._connections, connection)
                released = True
                raise EditorServiceError(
                    status=503, code="COMMAND_OUTCOME_UNKNOWN"
                ) from None
            if transaction:
                _rollback(connection)
            _discard(self._connections, connection)
            released = True
            _surface(_database_code(error))
        except FinanceFundingPostgresError as error:
            if transaction:
                _rollback(connection)
            _discard(self._connections, connection)
            released = True
            _surface(error.code)
        except EditorServiceError:
            if transaction:
                _rollback(connection)
            _discard(self._connections, connection)
            released = True
            raise
        except BaseException:
            if transaction:
                _rollback(connection)
            _discard(self._connections, connection)
            released = True
            raise EditorServiceError(status=503, code="SERVICE_UNAVAILABLE") from None
        finally:
            if connection is not None and not released:
                _discard(self._connections, connection)

    def _command_id(
        self, principal: EditorPrincipal, operation: str, idempotency_key: str
    ) -> UUID:
        if (
            not isinstance(idempotency_key, str)
            or not 8 <= len(idempotency_key.encode("utf-8")) <= 255
            or idempotency_key != idempotency_key.strip()
        ):
            raise EditorServiceError(
                status=422,
                code="INVALID_IDEMPOTENCY_KEY",
                path="/headers/Idempotency-Key",
            )
        return _derived_uuid(
            self._keys.id_key,
            "finance-command",
            principal.user_id,
            principal.session_id,
            operation,
            idempotency_key,
        )

    def _scoped_id(self, command_id: UUID, purpose: str) -> UUID:
        return _derived_uuid(self._keys.id_key, purpose, str(command_id))


def _prepare(connection: Any) -> None:
    _reset(connection)
    identity = connection.execute(
        "SELECT session_user,current_user,"
        "current_setting('server_version_num')::integer/10000"
    ).fetchone()
    compatibility = connection.execute(
        "SELECT component,current_schema_version,schema_head_version,"
        "min_app_compatible_version,max_app_compatible_version,"
        "required_iam_schema_version FROM demand.schema_compatibility"
    ).fetchone()
    if identity != ("demand_finance", "demand_finance", 18) or compatibility != (
        "demand",
        DEMAND_SCHEMA_HEAD_VERSION,
        DEMAND_SCHEMA_HEAD_VERSION,
        DEMAND_SCHEMA_HEAD_VERSION,
        DEMAND_SCHEMA_HEAD_VERSION,
        DEMAND_REQUIRED_IAM_SCHEMA_VERSION,
    ):
        raise FinanceFundingPostgresError("SERVICE_UNAVAILABLE")


def _context(
    connection: Any,
    *,
    principal: EditorPrincipal,
    operation: str,
    demand_id: Optional[UUID] = None,
    funding_review_id: Optional[UUID] = None,
) -> None:
    for name, value in (
        ("TimeZone", "UTC"),
        ("lock_timeout", "2s"),
        ("statement_timeout", "10s"),
        ("idle_in_transaction_session_timeout", "15s"),
        ("app.scope_kind", "FINANCE_FUNDING"),
        ("app.operation", operation),
        ("app.actor_id", principal.user_id),
        ("app.session_id", principal.session_id),
        ("app.organization_id", ""),
        ("app.demand_id", "" if demand_id is None else str(demand_id)),
        (
            "app.funding_review_id",
            "" if funding_review_id is None else str(funding_review_id),
        ),
        ("app.assignment_id", ""),
    ):
        installed = connection.execute(
            "SELECT pg_catalog.set_config(%s,%s,true)", (name, value)
        ).fetchone()
        if installed != (value,):
            raise FinanceFundingPostgresError("SERVICE_UNAVAILABLE")


def _reset(connection: Any) -> None:
    connection.execute("RESET ROLE")
    connection.execute("RESET ALL")
    connection.execute("DISCARD TEMP")


def _rollback(connection: Any) -> None:
    try:
        connection.execute("ROLLBACK")
    except BaseException:
        pass


def _discard(source: Any, connection: Any) -> None:
    if connection is not None:
        try:
            source.discard(connection)
        except BaseException:
            pass


def _finance_principal(principal: EditorPrincipal) -> None:
    """Require Finance inside one exact, closed multi-duty platform layer."""

    duties = (
        principal.platform_duty_codes
        if isinstance(principal, EditorPrincipal)
        else ()
    )
    if (
        not isinstance(principal, EditorPrincipal)
        or principal.workspace_kind != "PLATFORM"
        or principal.workspace_id != f"platform:{principal.user_id}"
        or principal.organization_id is not None
        or principal.membership_id is not None
        or duties != tuple(sorted(set(duties)))
        or not set(duties).issubset(PLATFORM_DUTY_CODES)
        or principal.role_codes != duties
        or "FINANCE_OPERATOR" not in duties
        or len(principal.principal_marker_sha256) != 32
    ):
        raise EditorServiceError(status=404, code="RESOURCE_NOT_FOUND")


def _queue_item(row: tuple[Any, ...]) -> FinanceFundingQueueItemDto:
    review_id = None if row[3] is None else str(row[3])
    review_status = str(row[4])
    demand_revision = int(row[2])
    confirmations = int(row[5])
    review_revision = None if row[6] is None else int(row[6])
    if review_status == "AVAILABLE":
        if review_id is not None or review_revision is not None:
            raise FinanceFundingPostgresError("SERVICE_UNAVAILABLE")
        etag = f'"demand-{demand_revision}-finance-queue"'
    elif review_status == "PENDING":
        if review_id is None or review_revision is None:
            raise FinanceFundingPostgresError("SERVICE_UNAVAILABLE")
        etag = f'"funding-review-{review_revision}"'
    else:
        raise FinanceFundingPostgresError("SERVICE_UNAVAILABLE")
    try:
        return FinanceFundingQueueItemDto(
            demand_id=str(row[0]),
            demand_version_id=str(row[1]),
            demand_revision=demand_revision,
            funding_review_id=review_id,
            review_status=review_status,
            review_revision=review_revision,
            assigned_to_me=row[7],
            confirmation_count=confirmations,
            required_confirmations=2,
            expires_at=_utc(row[8]),
            etag=etag,
        )
    except (TypeError, ValueError):
        raise FinanceFundingPostgresError("SERVICE_UNAVAILABLE") from None


def _review_projection_ids(row: tuple[Any, ...]) -> tuple[UUID, UUID]:
    if len(row) != 14:
        raise FinanceFundingPostgresError("SERVICE_UNAVAILABLE")
    try:
        review_id = _uuid(str(row[0]))
        assignment_id = _uuid(str(row[5]))
    except (TypeError, ValueError):
        raise FinanceFundingPostgresError("SERVICE_UNAVAILABLE") from None
    return review_id, assignment_id


def _bind_review_projection(
    connection: Any, *, funding_review_id: UUID, assignment_id: UUID
) -> None:
    for name, value in (
        ("app.funding_review_id", str(funding_review_id)),
        ("app.assignment_id", str(assignment_id)),
    ):
        installed = connection.execute(
            "SELECT pg_catalog.set_config(%s,%s,true)", (name, value)
        ).fetchone()
        if installed != (value,):
            raise FinanceFundingPostgresError("SERVICE_UNAVAILABLE")


def _funding_evidence(
    connection: Any,
    *,
    principal: EditorPrincipal,
    funding_review_id: UUID,
) -> tuple[Any, ...]:
    row = connection.execute(
        "SELECT target_content_sha256,planned_budget_currency,"
        "planned_budget_minimum_amount_minor,"
        "planned_budget_maximum_amount_minor,"
        "planned_budget_direct_cost_amount_minor,sandbox_funds_amount_minor,"
        "provider_code,payment_operation_code,evidence_kind,legal_effect "
        "FROM demand_api.read_manual_funding_evidence_v2(%s,%s,%s,%s)",
        (
            UUID(principal.user_id),
            UUID(principal.session_id),
            funding_review_id,
            principal.principal_marker_sha256,
        ),
    ).fetchone()
    if row is None:
        raise FinanceFundingPostgresError("RESOURCE_NOT_FOUND")
    if len(row) != 10:
        raise FinanceFundingPostgresError("SERVICE_UNAVAILABLE")
    return row


def _review(
    row: tuple[Any, ...], *, evidence: tuple[Any, ...], replayed: bool
) -> FinanceFundingReviewDto:
    if len(row) != 14 or len(evidence) != 10:
        raise FinanceFundingPostgresError("SERVICE_UNAVAILABLE")
    try:
        target_digest = bytes(row[7]).hex()
        evidence_digest = bytes(row[8]).hex()
        content_digest = bytes(evidence[0]).hex()
        return FinanceFundingReviewDto(
            funding_review_id=str(row[0]),
            demand_id=str(row[1]),
            demand_version_id=str(row[2]),
            status=str(row[3]),
            revision=int(row[4]),
            assignment_id=str(row[5]),
            assignment_expires_at=_utc(row[6]),
            target_sha256=target_digest,
            target_content_sha256=content_digest,
            planned_budget_currency=str(evidence[1]),
            planned_budget_minimum_amount_minor=int(evidence[2]),
            planned_budget_maximum_amount_minor=int(evidence[3]),
            planned_budget_direct_cost_amount_minor=int(evidence[4]),
            evidence_kind=str(evidence[8]),
            evidence_reference_sha256=evidence_digest,
            sandbox_funds_amount_minor=int(evidence[5]),
            provider_code=str(evidence[6]),
            payment_operation_code=str(evidence[7]),
            synthetic=True,
            legal_effect=str(evidence[9]),
            confirmation_count=int(row[9]),
            required_confirmations=2,
            assignment_status=str(row[10]),
            confirmation_by_me=row[11],
            available_actions=tuple(row[12]),
            can_confirm=row[13],
            etag=f'"funding-review-{int(row[4])}"',
            replayed=replayed,
        )
    except (AttributeError, TypeError, ValueError):
        raise FinanceFundingPostgresError("SERVICE_UNAVAILABLE") from None


def _queue_etag(value: str) -> tuple[Optional[int], Optional[int]]:
    if not isinstance(value, str):
        raise EditorServiceError(
            status=422, code="INVALID_ETAG", path="/headers/If-Match"
        )
    demand = re.fullmatch(r'"demand-([1-9][0-9]*)-finance-queue"', value)
    if demand is not None:
        return int(demand.group(1)), None
    review = re.fullmatch(r'"funding-review-([1-9][0-9]*)"', value)
    if review is not None:
        return None, int(review.group(1))
    raise EditorServiceError(
        status=422, code="INVALID_ETAG", path="/headers/If-Match"
    )


def _review_etag(value: str) -> int:
    parsed = re.fullmatch(
        r'"funding-review-([1-9][0-9]*)"', value if isinstance(value, str) else ""
    )
    if parsed is None:
        raise EditorServiceError(
            status=422, code="INVALID_ETAG", path="/headers/If-Match"
        )
    return int(parsed.group(1))


def _closed_codes(
    values: Tuple[str, ...], *, allowed: Tuple[str, ...], code: str
) -> Tuple[str, ...]:
    if (
        not isinstance(values, tuple)
        or not values
        or len(values) != len(set(values))
        or tuple(sorted(values)) != values
        or any(value not in allowed for value in values)
    ):
        raise FinanceFundingDomainError(code)
    return values


def _finding_codes(
    *,
    disposition: str,
    reason_codes: Tuple[str, ...],
    required_field_codes: Tuple[str, ...],
) -> None:
    allowed_reasons = FINANCE_FUNDING_FINDING_REASON_CODES.get(disposition)
    if allowed_reasons is None:
        raise FinanceFundingDomainError("INVALID_FINDING_DISPOSITION")
    _closed_codes(
        reason_codes,
        allowed=allowed_reasons,
        code="INVALID_FINDING_REASON_CODES",
    )
    _closed_codes(
        required_field_codes,
        allowed=FINANCE_FUNDING_FINDING_FIELD_CODES,
        code="INVALID_FINDING_FIELD_CODES",
    )


def _canonical_payload(operation: str, payload: Mapping[str, Any]) -> bytes:
    return json.dumps(
        {"operation": operation, "payload": payload},
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def _hmac(key: Union[bytes, bytearray], value: bytes) -> bytes:
    return hmac.new(bytes(key), value, hashlib.sha256).digest()


def _derived_uuid(
    key: Union[bytes, bytearray], purpose: str, *parts: str
) -> UUID:
    material = b"\x00".join(
        (b"finance-funding-v1", purpose.encode("ascii"))
        + tuple(part.encode("ascii") for part in parts)
    )
    digest = bytearray(_hmac(key, material)[:16])
    digest[6] = (digest[6] & 0x0F) | 0x40
    digest[8] = (digest[8] & 0x3F) | 0x80
    result = UUID(bytes=bytes(digest))
    if result.int == 0:
        raise EditorServiceError(status=503, code="SERVICE_UNAVAILABLE")
    return result


def _database_code(error: psycopg.Error) -> str:
    constraint = getattr(getattr(error, "diag", None), "constraint_name", None)
    mapping = {
        "finance_funding_precondition_failed": "PRECONDITION_FAILED",
        "finance_funding_idempotency_reused": "IDEMPOTENCY_KEY_REUSED",
        "finance_funding_already_assigned": "FUNDING_REVIEW_ALREADY_ASSIGNED",
        "finance_funding_confirmation_duplicate": "FUNDING_CONFIRMATION_DUPLICATE",
        "finance_funding_state_conflict": "STATE_CONFLICT",
        "finance_funding_assignment_expired": "ASSIGNMENT_EXPIRED",
        "finance_funding_assignment_not_releasable": (
            "ASSIGNMENT_NOT_RELEASABLE"
        ),
        "finance_funding_finding_not_submittable": (
            "FINDING_NOT_SUBMITTABLE"
        ),
        "finance_funding_key_policy_unavailable": "SERVICE_UNAVAILABLE",
    }
    return mapping.get(constraint, "SERVICE_UNAVAILABLE")


def _surface(code: str) -> None:
    if code == "RESOURCE_NOT_FOUND":
        raise EditorServiceError(status=404, code=code)
    if code == "PRECONDITION_FAILED":
        raise EditorServiceError(status=412, code=code)
    if code in {
        "IDEMPOTENCY_KEY_REUSED",
        "FUNDING_REVIEW_ALREADY_ASSIGNED",
        "FUNDING_CONFIRMATION_DUPLICATE",
        "STATE_CONFLICT",
        "ASSIGNMENT_EXPIRED",
        "ASSIGNMENT_NOT_RELEASABLE",
        "FINDING_NOT_SUBMITTABLE",
    }:
        raise EditorServiceError(status=409, code=code)
    raise EditorServiceError(status=503, code="SERVICE_UNAVAILABLE")


def _encode_finance_funding_history_cursor(
    *,
    item: FinanceFundingHistoryItemDto,
    actor_user_id: str,
    key: Union[bytes, bytearray],
) -> str:
    actor = _uuid(actor_user_id)
    payload = json.dumps(
        {
            "completed_at": _cursor_timestamp(item.completed_at),
            "funding_review_id": item.funding_review_id,
            "version": 1,
        },
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    signature = _hmac(
        key,
        _FINANCE_FUNDING_HISTORY_CURSOR_DOMAIN
        + actor.bytes
        + b"\x00"
        + payload,
    )
    return f"{_base64url(payload)}.{_base64url(signature)}"


def _decode_finance_funding_history_cursor(
    *,
    cursor: str,
    actor_user_id: str,
    key: Union[bytes, bytearray],
) -> Tuple[datetime, UUID]:
    if (
        not isinstance(cursor, str)
        or _FINANCE_FUNDING_HISTORY_CURSOR.fullmatch(cursor) is None
    ):
        raise ValueError("Finance funding history cursor is invalid")
    encoded_payload, encoded_signature = cursor.split(".")
    payload = _unbase64url(encoded_payload)
    signature = _unbase64url(encoded_signature)
    actor = _uuid(actor_user_id)
    expected_signature = _hmac(
        key,
        _FINANCE_FUNDING_HISTORY_CURSOR_DOMAIN
        + actor.bytes
        + b"\x00"
        + payload,
    )
    if len(signature) != 32 or not hmac.compare_digest(
        signature, expected_signature
    ):
        raise ValueError("Finance funding history cursor is invalid")
    try:
        value = json.loads(payload.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ValueError("Finance funding history cursor is invalid") from None
    if (
        not isinstance(value, dict)
        or tuple(sorted(value))
        != ("completed_at", "funding_review_id", "version")
        or value.get("version") != 1
        or isinstance(value.get("version"), bool)
    ):
        raise ValueError("Finance funding history cursor is invalid")
    canonical = json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    if not hmac.compare_digest(payload, canonical):
        raise ValueError("Finance funding history cursor is invalid")
    review_id = _uuid(value.get("funding_review_id"))
    timestamp = value.get("completed_at")
    if not isinstance(timestamp, str) or not timestamp.endswith("Z"):
        raise ValueError("Finance funding history cursor is invalid")
    try:
        completed_at = datetime.fromisoformat(timestamp[:-1] + "+00:00")
    except ValueError:
        raise ValueError("Finance funding history cursor is invalid") from None
    if _cursor_timestamp(completed_at) != timestamp:
        raise ValueError("Finance funding history cursor is invalid")
    return completed_at, review_id


def _cursor_timestamp(value: datetime) -> str:
    return _utc(value).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def _base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _unbase64url(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    try:
        return base64.b64decode(
            value + padding,
            altchars=b"-_",
            validate=True,
        )
    except (ValueError, binascii.Error):
        raise ValueError("Finance funding history cursor is invalid") from None


def _uuid(value: str) -> UUID:
    try:
        parsed = UUID(value)
    except (AttributeError, TypeError, ValueError):
        raise ValueError("Finance funding identifier is invalid") from None
    if parsed.int == 0 or str(parsed) != value:
        raise ValueError("Finance funding identifier is invalid")
    return parsed


def _utc(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ValueError("Finance funding timestamp is invalid")
    try:
        offset = value.utcoffset()
    except (OverflowError, ValueError):
        raise ValueError("Finance funding timestamp is invalid") from None
    if offset is None or value.astimezone(timezone.utc) != value:
        raise ValueError("Finance funding timestamp is invalid")
    return value


__all__ = [
    "FINANCE_FUNDING_ACTIONS",
    "FINANCE_FUNDING_ATTESTATION_CODES",
    "FINANCE_FUNDING_EVIDENCE_KIND",
    "FINANCE_FUNDING_FINDING_FIELD_CODES",
    "FINANCE_FUNDING_FINDING_REASON_CODES",
    "FINANCE_FUNDING_LEGAL_EFFECT",
    "FINANCE_FUNDING_RELEASE_REASON_CODES",
    "FinanceFundingCommitOutcomeUnknownError",
    "FinanceFundingDomainError",
    "FinanceFundingHistoryItemDto",
    "FinanceFundingHistoryPageDto",
    "FinanceFundingKeys",
    "FinanceFundingPostgresError",
    "FinanceFundingQueueItemDto",
    "FinanceFundingReviewState",
    "FinanceFundingReviewDto",
    "PsycopgFinanceFundingService",
]
