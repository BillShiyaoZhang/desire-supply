"""Framework-neutral HTTP contract for the internal-pilot editor."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field, is_dataclass
from datetime import datetime
import re
from typing import Any, Dict, Mapping, Optional, Tuple

from ..account_admin import (
    ACCOUNT_ADMIN_PLATFORM_DUTY_CODES,
    ACCOUNT_ADMIN_REASON_CODES,
)
from ..finance_funding import (
    FINANCE_FUNDING_ATTESTATION_CODES,
    FINANCE_FUNDING_FINDING_FIELD_CODES,
    FINANCE_FUNDING_FINDING_REASON_CODES,
    FINANCE_FUNDING_RELEASE_REASON_CODES,
    _finance_principal,
)
from ...demand.domain import CancelReasonCode
from .contracts import (
    EditorPrincipal,
    EditorResourceDto,
    EditorReviewClaimDto,
    EditorServiceError,
)


_REVIEW_REASON_CODES = frozenset((
    "CONTENT_INCOMPLETE",
    "SCOPE_UNCLEAR",
    "ACCEPTANCE_UNCLEAR",
    "BUDGET_UNHEALTHY",
    "RISK_UNRESOLVED",
    "DATA_PLAN_REQUIRED",
))
_VERIFY_BUDGET_HEALTH_CODES = frozenset(("HEALTHY", "APPROVED_EXCEPTION"))
_VERIFY_RISK_CODES = frozenset(("STANDARD", "ELEVATED_APPROVED"))
_VERIFY_EVIDENCE_CODES = frozenset((
    "SCOPE_COMPLETE",
    "ACCEPTANCE_TESTABLE",
    "BUDGET_COHERENT",
    "RISK_HANDLED",
    "DECLARATIONS_CONFIRMED",
))
_REVIEW_ASSIGNMENT_RELEASE_REASON_CODES = frozenset(
    ("CONFLICT_DECLARED", "WORKLOAD_RELEASE")
)
_PROFILE_PAUSE_REASON_CODES = frozenset((
    "OWNER_REQUEST",
    "TEMPORARY_UNAVAILABILITY",
    "SAFETY_REVIEW",
))
_PROFILE_ARCHIVE_REASON_CODES = frozenset((
    "OWNER_REQUEST",
    "ACCOUNT_CLOSURE",
    "SAFETY_REVIEW",
))
_DEMAND_OWNER_CANCEL_REASON_CODES = frozenset(
    code.value
    for code in CancelReasonCode
    if code is not CancelReasonCode.DEADLINE_REACHED
)


@dataclass(frozen=True)
class HttpRequest:
    method: str
    path: str
    headers: Mapping[str, str]
    json: Any
    query: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class HttpResponse:
    status: int
    headers: Mapping[str, str]
    json: Mapping[str, Any]


class EditorHttpApi:
    """Exact route adapter; authentication creates ``principal`` upstream."""

    def __init__(
        self,
        *,
        service: Any,
        account_admin_service: Any = None,
        finance_service: Any = None,
        task_service: Any = None,
        admin_demand_service: Any = None,
    ) -> None:
        self._service = service
        self._account_admin_service = account_admin_service
        self._finance_service = finance_service
        self._task_service = task_service
        self._admin_demand_service = admin_demand_service

    def handle(
        self, *, request: HttpRequest, principal: EditorPrincipal
    ) -> HttpResponse:
        try:
            return self._dispatch(request=request, principal=principal)
        except EditorServiceError as error:
            body: Dict[str, Any] = {"code": error.code}
            if error.path is not None:
                body["path"] = error.path
            if error.details:
                body["details"] = error.details
            headers = {"Content-Type": "application/json"}
            if error.etag is not None:
                headers["ETag"] = error.etag
            return HttpResponse(
                status=error.status, headers=headers, json={"error": body}
            )
        except (TypeError, ValueError):
            return HttpResponse(
                status=422,
                headers={"Content-Type": "application/json"},
                json={"error": {"code": "INVALID_REQUEST", "path": "/body"}},
            )

    def _dispatch(
        self, *, request: HttpRequest, principal: EditorPrincipal
    ) -> HttpResponse:
        method = request.method.upper()
        path = request.path.rstrip("/") or "/"
        admin_match = re.fullmatch(r"/v1/app/admin/demands/([^/]+)/timeline", path)
        if method == "GET" and (path == "/v1/app/admin/demands" or admin_match):
            _closed_body(request.json, ())
            query = _review_history_query(request.query)
            if self._admin_demand_service is None:
                raise EditorServiceError(status=404, code="RESOURCE_NOT_FOUND")
            arguments = dict(principal=principal, limit=int(query.get("limit", "100" if admin_match else "25")), cursor=query.get("cursor"))
            if admin_match:
                return _ok(self._admin_demand_service.get_timeline(demand_id=admin_match.group(1), **arguments))
            return _ok(self._admin_demand_service.list_demands(**arguments))
        if method == "GET" and path == "/v1/app/tasks":
            _closed_body(request.json, ())
            return _ok(self._tasks().list_tasks(principal=principal))
        if (
            method == "GET"
            and path == "/v1/app/finance/funding-review-history"
        ):
            _closed_body(request.json, ())
            query = _review_history_query(request.query)
            finance = self._finance(principal)
            history = getattr(finance, "list_funding_review_history", None)
            if not callable(history):
                raise EditorServiceError(status=404, code="RESOURCE_NOT_FOUND")
            return _ok(
                history(
                    principal=principal,
                    cursor=query.get("cursor"),
                    limit=int(query.get("limit", "25")),
                )
            )
        if method == "GET" and path == "/v1/app/finance/funding-reviews":
            _closed_body(request.json, ())
            finance = self._finance(principal)
            return _ok(finance.list_funding_reviews(principal=principal))
        match = re.fullmatch(
            r"/v1/app/finance/funding-reviews/([^/]+)/claim", path
        )
        if method == "POST" and match:
            _closed_body(request.json, ())
            finance = self._finance(principal)
            return _ok(
                finance.claim_funding_review(
                    principal=principal,
                    demand_id=match.group(1),
                    if_match=_if_match(request.headers),
                    idempotency_key=_idempotency(request.headers),
                )
            )
        match = re.fullmatch(
            r"/v1/app/finance/funding-reviews/([^/]+)/confirm", path
        )
        if method == "POST" and match:
            body = _closed_body(request.json, ("attestation_codes",))
            attestation_codes = _string_tuple(body, "attestation_codes")
            if attestation_codes != FINANCE_FUNDING_ATTESTATION_CODES:
                raise EditorServiceError(
                    status=422,
                    code="INVALID_ATTESTATION_CODES",
                    path="/attestation_codes",
                )
            finance = self._finance(principal)
            return _ok(
                finance.confirm_funding_review(
                    principal=principal,
                    funding_review_id=match.group(1),
                    if_match=_if_match(request.headers),
                    attestation_codes=attestation_codes,
                    idempotency_key=_idempotency(request.headers),
                )
            )
        match = re.fullmatch(
            r"/v1/app/finance/funding-reviews/([^/]+)/assignment/release",
            path,
        )
        if method == "POST" and match:
            body = _closed_body(request.json, ("reason_code",))
            reason_code = _string(body, "reason_code")
            if reason_code not in FINANCE_FUNDING_RELEASE_REASON_CODES:
                raise EditorServiceError(
                    status=422,
                    code="INVALID_REASON_CODE",
                    path="/reason_code",
                )
            finance = self._finance(principal)
            return _ok(
                finance.release_funding_review_assignment(
                    principal=principal,
                    funding_review_id=match.group(1),
                    if_match=_if_match(request.headers),
                    reason_code=reason_code,
                    idempotency_key=_idempotency(request.headers),
                )
            )
        match = re.fullmatch(
            r"/v1/app/finance/funding-reviews/([^/]+)/findings", path
        )
        if method == "POST" and match:
            body = _closed_body(
                request.json,
                ("disposition", "reason_codes", "required_field_codes"),
            )
            disposition = _string(body, "disposition")
            reason_codes = _string_tuple(body, "reason_codes")
            required_field_codes = _string_tuple(
                body, "required_field_codes"
            )
            allowed_reasons = FINANCE_FUNDING_FINDING_REASON_CODES.get(
                disposition
            )
            if allowed_reasons is None:
                raise EditorServiceError(
                    status=422,
                    code="INVALID_FINDING_DISPOSITION",
                    path="/disposition",
                )
            if (
                not reason_codes
                or tuple(sorted(reason_codes)) != reason_codes
                or len(set(reason_codes)) != len(reason_codes)
                or any(code not in allowed_reasons for code in reason_codes)
            ):
                raise EditorServiceError(
                    status=422,
                    code="INVALID_FINDING_REASON_CODES",
                    path="/reason_codes",
                )
            if (
                not required_field_codes
                or tuple(sorted(required_field_codes))
                    != required_field_codes
                or len(set(required_field_codes))
                    != len(required_field_codes)
                or any(
                    code not in FINANCE_FUNDING_FINDING_FIELD_CODES
                    for code in required_field_codes
                )
            ):
                raise EditorServiceError(
                    status=422,
                    code="INVALID_FINDING_FIELD_CODES",
                    path="/required_field_codes",
                )
            finance = self._finance(principal)
            return _ok(
                finance.submit_funding_review_finding(
                    principal=principal,
                    funding_review_id=match.group(1),
                    if_match=_if_match(request.headers),
                    disposition=disposition,
                    reason_codes=reason_codes,
                    required_field_codes=required_field_codes,
                    idempotency_key=_idempotency(request.headers),
                )
            )
        match = re.fullmatch(r"/v1/app/finance/funding-reviews/([^/]+)", path)
        if method == "GET" and match:
            _closed_body(request.json, ())
            finance = self._finance(principal)
            return _ok(
                finance.get_funding_review(
                    principal=principal,
                    funding_review_id=match.group(1),
                )
            )
        if method == "GET" and path == "/v1/app/admin/accounts":
            _closed_body(request.json, ())
            account_admin = self._account_admin(principal)
            return _ok(account_admin.list_accounts(principal=principal))
        match = re.fullmatch(r"/v1/app/admin/accounts/([^/]+)", path)
        if method == "GET" and match:
            _closed_body(request.json, ())
            account_admin = self._account_admin(principal)
            return _ok(
                account_admin.get_account(
                    principal=principal,
                    user_id=match.group(1),
                )
            )
        match = re.fullmatch(
            r"/v1/app/admin/accounts/([^/]+)/(suspend|resume|revoke-all-sessions)",
            path,
        )
        if method == "POST" and match:
            body = _closed_body(request.json, ("reason_code",))
            reason_code = _string(body, "reason_code")
            if reason_code not in ACCOUNT_ADMIN_REASON_CODES:
                raise EditorServiceError(
                    status=422,
                    code="INVALID_REASON_CODE",
                    path="/reason_code",
                )
            if_match = _if_match(request.headers)
            idempotency_key = _idempotency(request.headers)
            account_admin = self._account_admin(principal)
            action = {
                "suspend": "SUSPEND",
                "resume": "RESUME",
                "revoke-all-sessions": "REVOKE_ALL_SESSIONS",
            }[match.group(2)]
            return _ok(
                account_admin.manage_account(
                    principal=principal,
                    user_id=match.group(1),
                    action=action,
                    if_match=if_match,
                    idempotency_key=idempotency_key,
                    reason_code=reason_code,
                )
            )
        match = re.fullmatch(
            r"/v1/app/admin/accounts/([^/]+)/platform-duties/([^/]+)/(grant|revoke)",
            path,
        )
        if method == "POST" and match:
            if match.group(2) not in ACCOUNT_ADMIN_PLATFORM_DUTY_CODES:
                raise EditorServiceError(status=404, code="RESOURCE_NOT_FOUND")
            body = _closed_body(request.json, ("reason_code",))
            reason_code = _string(body, "reason_code")
            if reason_code not in ACCOUNT_ADMIN_REASON_CODES:
                raise EditorServiceError(
                    status=422,
                    code="INVALID_REASON_CODE",
                    path="/reason_code",
                )
            account_admin = self._account_admin(principal)
            return _ok(
                account_admin.manage_platform_duty(
                    principal=principal,
                    user_id=match.group(1),
                    duty_code=match.group(2),
                    action=match.group(3).upper(),
                    if_match=_if_match(request.headers),
                    idempotency_key=_idempotency(request.headers),
                    reason_code=reason_code,
                )
            )
        if method == "GET" and path == "/v1/app/configuration":
            return _ok(self._service.get_configuration(principal=principal))
        if method == "GET" and path == "/v1/app/review-queue":
            return _ok(self._service.list_review_queue(principal=principal))
        if method == "GET" and path == "/v1/app/review-history":
            _closed_body(request.json, ())
            query = _review_history_query(request.query)
            return _ok(
                self._service.list_review_history(
                    principal=principal,
                    cursor=query.get("cursor"),
                    limit=int(query.get("limit", "25")),
                )
            )
        match = re.fullmatch(r"/v1/app/review-queue/([^/]+)/claim", path)
        if method == "POST" and match:
            body = _closed_body(request.json, ())
            del body
            return _ok(
                self._service.claim_demand_review(
                    principal=principal,
                    demand_id=match.group(1),
                    if_match=_if_match(request.headers),
                    idempotency_key=_idempotency(request.headers),
                )
            )
        if method == "GET" and path == "/v1/app/profiles":
            return _ok(self._service.list_profiles(principal=principal))
        if method == "POST" and path == "/v1/app/profiles":
            body = _closed_body(request.json, ())
            del body
            result = self._service.create_profile(
                principal=principal,
                idempotency_key=_idempotency(request.headers),
            )
            return _ok(result, status=201)
        if method == "GET" and path == "/v1/app/demands":
            return _ok(self._service.list_demands(principal=principal))
        if method == "POST" and path == "/v1/app/demands":
            body = _closed_body(
                request.json,
                ("taxonomy_bundle_id", "content", "client_reference", "expires_at"),
            )
            result = self._service.create_demand(
                principal=principal,
                taxonomy_bundle_id=_string(body, "taxonomy_bundle_id"),
                content=_object(body, "content"),
                client_reference=_string(body, "client_reference"),
                expires_at=_datetime(body, "expires_at"),
                idempotency_key=_idempotency(request.headers),
            )
            return _ok(result, status=201)

        match = re.fullmatch(r"/v1/app/profiles/([^/]+)", path)
        if method == "GET" and match:
            return _ok(
                self._service.get_profile(
                    principal=principal, profile_id=match.group(1)
                )
            )
        match = re.fullmatch(r"/v1/app/profiles/([^/]+)/draft", path)
        if method == "PUT" and match:
            body = _closed_body(
                request.json, ("base_version_id", "taxonomy_bundle_id", "content")
            )
            result = self._service.save_profile_draft(
                principal=principal,
                profile_id=match.group(1),
                if_match=_if_match(request.headers),
                base_version_id=_nullable_string(body, "base_version_id"),
                taxonomy_bundle_id=_string(body, "taxonomy_bundle_id"),
                content=_object(body, "content"),
                idempotency_key=_idempotency(request.headers),
            )
            return _ok(result)
        match = re.fullmatch(r"/v1/app/profiles/([^/]+)/publish", path)
        if method == "POST" and match:
            body = _closed_body(request.json, ("draft_version_id",))
            result = self._service.publish_profile(
                principal=principal,
                profile_id=match.group(1),
                draft_version_id=_string(body, "draft_version_id"),
                if_match=_if_match(request.headers),
                idempotency_key=_idempotency(request.headers),
            )
            return _ok(result)
        match = re.fullmatch(
            r"/v1/app/profiles/([^/]+)/(pause|resume|archive)", path
        )
        if method == "POST" and match:
            action = match.group(2)
            if action == "resume":
                _closed_body(request.json, ())
                result = self._service.resume_profile(
                    principal=principal,
                    profile_id=match.group(1),
                    if_match=_if_match(request.headers),
                    idempotency_key=_idempotency(request.headers),
                )
            else:
                body = _closed_body(request.json, ("reason_code",))
                reason_code = _string(body, "reason_code")
                allowed = (
                    _PROFILE_PAUSE_REASON_CODES
                    if action == "pause"
                    else _PROFILE_ARCHIVE_REASON_CODES
                )
                if reason_code not in allowed:
                    raise EditorServiceError(
                        status=422,
                        code="INVALID_REASON_CODE",
                        path="/reason_code",
                    )
                lifecycle = (
                    self._service.pause_profile
                    if action == "pause"
                    else self._service.archive_profile
                )
                result = lifecycle(
                    principal=principal,
                    profile_id=match.group(1),
                    if_match=_if_match(request.headers),
                    reason_code=reason_code,
                    idempotency_key=_idempotency(request.headers),
                )
            return _ok(result)

        match = re.fullmatch(r"/v1/app/demands/([^/]+)", path)
        if method == "GET" and match:
            return _ok(
                self._service.get_demand(
                    principal=principal, demand_id=match.group(1)
                )
            )
        match = re.fullmatch(r"/v1/app/demands/([^/]+)/draft", path)
        if method == "PUT" and match:
            body = _closed_body(
                request.json, ("base_version_id", "taxonomy_bundle_id", "content")
            )
            result = self._service.save_demand_draft(
                principal=principal,
                demand_id=match.group(1),
                if_match=_if_match(request.headers),
                base_version_id=_string(body, "base_version_id"),
                taxonomy_bundle_id=_string(body, "taxonomy_bundle_id"),
                content=_object(body, "content"),
                idempotency_key=_idempotency(request.headers),
            )
            return _ok(result)
        match = re.fullmatch(r"/v1/app/demands/([^/]+)/submit", path)
        if method == "POST" and match:
            body = _closed_body(request.json, ())
            del body
            return _ok(
                self._service.submit_demand(
                    principal=principal,
                    demand_id=match.group(1),
                    if_match=_if_match(request.headers),
                    idempotency_key=_idempotency(request.headers),
                )
            )
        match = re.fullmatch(r"/v1/app/demands/([^/]+)/cancel", path)
        if method == "POST" and match:
            body = _closed_body(request.json, ("reason_code",))
            reason_code = _string(body, "reason_code")
            if reason_code not in _DEMAND_OWNER_CANCEL_REASON_CODES:
                raise EditorServiceError(
                    status=422,
                    code="INVALID_REASON_CODE",
                    path="/reason_code",
                )
            return _ok(
                self._service.cancel_demand(
                    principal=principal,
                    demand_id=match.group(1),
                    if_match=_if_match(request.headers),
                    reason_code=reason_code,
                    idempotency_key=_idempotency(request.headers),
                )
            )
        match = re.fullmatch(
            r"/v1/app/demands/([^/]+)/review-assignments/([^/]+)/findings", path
        )
        if method == "POST" and match:
            body = _closed_body(
                request.json, ("reason_codes", "required_field_paths")
            )
            reason_codes = _string_tuple(body, "reason_codes")
            invalid_reason = next(
                (index for index, value in enumerate(reason_codes) if value not in _REVIEW_REASON_CODES),
                None,
            )
            if invalid_reason is not None:
                raise EditorServiceError(
                    status=422,
                    code="INVALID_REASON_CODE",
                    path=f"/reason_codes/{invalid_reason}",
                )
            return _ok(
                self._service.request_demand_changes(
                    principal=principal,
                    demand_id=match.group(1),
                    assignment_id=match.group(2),
                    if_match=_if_match(request.headers),
                    reason_codes=reason_codes,
                    required_field_paths=_string_tuple(
                        body, "required_field_paths"
                    ),
                    idempotency_key=_idempotency(request.headers),
                )
            )
        match = re.fullmatch(
            r"/v1/app/demands/([^/]+)/review-assignments/([^/]+)/verify", path
        )
        release_match = re.fullmatch(
            r"/v1/app/demands/([^/]+)/review-assignments/([^/]+)/release",
            path,
        )
        if method == "POST" and release_match:
            body = _closed_body(request.json, ("reason_code",))
            reason_code = _string(body, "reason_code")
            if reason_code not in _REVIEW_ASSIGNMENT_RELEASE_REASON_CODES:
                raise EditorServiceError(
                    status=422,
                    code="INVALID_REASON_CODE",
                    path="/reason_code",
                )
            return _ok(
                self._service.release_demand_review_assignment(
                    principal=principal,
                    demand_id=release_match.group(1),
                    assignment_id=release_match.group(2),
                    if_match=_if_match(request.headers),
                    reason_code=reason_code,
                    idempotency_key=_idempotency(request.headers),
                )
            )
        if method == "POST" and match:
            body = _closed_body(
                request.json,
                ("budget_health_code", "risk_code", "evidence_codes"),
            )
            budget_health_code = _string(body, "budget_health_code")
            if budget_health_code not in _VERIFY_BUDGET_HEALTH_CODES:
                raise EditorServiceError(
                    status=422,
                    code="INVALID_BUDGET_HEALTH_CODE",
                    path="/budget_health_code",
                )
            risk_code = _string(body, "risk_code")
            if risk_code not in _VERIFY_RISK_CODES:
                raise EditorServiceError(
                    status=422, code="INVALID_RISK_CODE", path="/risk_code"
                )
            evidence_codes = _string_tuple(body, "evidence_codes")
            if not evidence_codes:
                raise EditorServiceError(
                    status=422,
                    code="INVALID_EVIDENCE_CODE",
                    path="/evidence_codes",
                )
            seen = set()
            for index, value in enumerate(evidence_codes):
                if value not in _VERIFY_EVIDENCE_CODES or value in seen:
                    raise EditorServiceError(
                        status=422,
                        code="INVALID_EVIDENCE_CODE",
                        path=f"/evidence_codes/{index}",
                    )
                seen.add(value)
            return _ok(
                self._service.verify_demand(
                    principal=principal,
                    demand_id=match.group(1),
                    assignment_id=match.group(2),
                    if_match=_if_match(request.headers),
                    budget_health_code=budget_health_code,
                    risk_code=risk_code,
                    evidence_codes=evidence_codes,
                    idempotency_key=_idempotency(request.headers),
                )
            )
        raise EditorServiceError(status=404, code="RESOURCE_NOT_FOUND")

    def _account_admin(self, principal: EditorPrincipal) -> Any:
        if (
            not isinstance(principal, EditorPrincipal)
            or principal.workspace_kind != "PLATFORM"
            or "ACCESS_ADMIN" not in principal.role_codes
            or principal.role_codes
            != tuple(sorted(set(principal.platform_duty_codes)))
            or self._account_admin_service is None
            or not all(
                callable(getattr(self._account_admin_service, name, None))
                for name in (
                    "list_accounts",
                    "get_account",
                    "manage_account",
                    "manage_platform_duty",
                )
            )
        ):
            raise EditorServiceError(status=404, code="RESOURCE_NOT_FOUND")
        return self._account_admin_service

    def _finance(self, principal: EditorPrincipal) -> Any:
        methods = (
            "list_funding_reviews",
            "claim_funding_review",
            "get_funding_review",
            "confirm_funding_review",
            "release_funding_review_assignment",
            "submit_funding_review_finding",
        )
        _finance_principal(principal)
        if (
            self._finance_service is None
            or any(
                not callable(getattr(self._finance_service, name, None))
                for name in methods
            )
        ):
            raise EditorServiceError(status=404, code="RESOURCE_NOT_FOUND")
        return self._finance_service

    def _tasks(self) -> Any:
        if self._task_service is None or not callable(
            getattr(self._task_service, "list_tasks", None)
        ):
            raise EditorServiceError(status=503, code="SERVICE_UNAVAILABLE")
        return self._task_service


def _ok(value: Any, *, status: int = 200) -> HttpResponse:
    headers = {"Content-Type": "application/json", "Cache-Control": "no-store"}
    if isinstance(value, (EditorResourceDto, EditorReviewClaimDto)):
        headers["ETag"] = value.etag
    else:
        entity_tag = getattr(value, "etag", None)
        if entity_tag is None:
            entity_tag = getattr(value, "entity_tag", None)
        if isinstance(entity_tag, str):
            headers["ETag"] = entity_tag
    return HttpResponse(
        status=status,
        headers=headers,
        json={"data": _serialize(value)},
    )


def _serialize(value: Any) -> Any:
    if is_dataclass(value):
        return _serialize(asdict(value))
    if isinstance(value, Mapping):
        return {str(key): _serialize(child) for key, child in value.items()}
    if isinstance(value, (tuple, list)):
        return [_serialize(child) for child in value]
    if isinstance(value, datetime):
        return value.isoformat()
    return value


def _closed_body(value: Any, fields: Tuple[str, ...]) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise EditorServiceError(status=422, code="INVALID_BODY", path="/body")
    unknown = sorted(set(value).difference(fields))
    if unknown:
        raise EditorServiceError(
            status=422, code="UNKNOWN_FIELD", path=f"/{unknown[0]}"
        )
    missing = [field for field in fields if field not in value]
    if missing:
        raise EditorServiceError(
            status=422, code="REQUIRED_FIELD", path=f"/{missing[0]}"
        )
    return value


def _review_history_query(value: Any) -> Mapping[str, str]:
    if not isinstance(value, Mapping) or any(
        not isinstance(key, str) or not isinstance(item, str)
        for key, item in value.items()
    ):
        raise EditorServiceError(
            status=422,
            code="INVALID_REQUEST",
            path="/query",
        )
    if set(value).difference(("cursor", "limit")):
        raise EditorServiceError(
            status=422,
            code="INVALID_REQUEST",
            path="/query",
        )
    cursor = value.get("cursor")
    limit = value.get("limit")
    if (
        cursor is not None
        and re.fullmatch(r"[A-Za-z0-9_-]{64,1024}\.[A-Za-z0-9_-]{43}", cursor)
        is None
    ) or (
        limit is not None
        and re.fullmatch(r"(?:[1-9]|[1-9][0-9]|100)", limit) is None
    ):
        raise EditorServiceError(
            status=422,
            code="INVALID_REQUEST",
            path="/query",
        )
    return value


def _header(headers: Mapping[str, str], name: str) -> Optional[str]:
    expected = name.casefold()
    return next(
        (value for key, value in headers.items() if key.casefold() == expected), None
    )


def _idempotency(headers: Mapping[str, str]) -> str:
    value = _header(headers, "Idempotency-Key")
    if value is None:
        raise EditorServiceError(
            status=428,
            code="PRECONDITION_REQUIRED",
            path="/headers/Idempotency-Key",
        )
    return value


def _if_match(headers: Mapping[str, str]) -> str:
    value = _header(headers, "If-Match")
    if value is None:
        raise EditorServiceError(
            status=428, code="PRECONDITION_REQUIRED", path="/headers/If-Match"
        )
    return value


def _string(body: Mapping[str, Any], name: str) -> str:
    value = body[name]
    if not isinstance(value, str) or not value:
        raise EditorServiceError(status=422, code="INVALID_FIELD", path=f"/{name}")
    return value


def _nullable_string(body: Mapping[str, Any], name: str) -> Optional[str]:
    value = body[name]
    if value is None:
        return None
    return _string(body, name)


def _object(body: Mapping[str, Any], name: str) -> Mapping[str, Any]:
    value = body[name]
    if not isinstance(value, Mapping):
        raise EditorServiceError(status=422, code="INVALID_FIELD", path=f"/{name}")
    return value


def _datetime(body: Mapping[str, Any], name: str) -> datetime:
    raw = _string(body, name)
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as error:
        raise EditorServiceError(
            status=422, code="INVALID_FIELD", path=f"/{name}"
        ) from error


def _string_tuple(body: Mapping[str, Any], name: str) -> Tuple[str, ...]:
    value = body[name]
    if not isinstance(value, list) or any(
        not isinstance(item, str) or not item for item in value
    ):
        raise EditorServiceError(status=422, code="INVALID_FIELD", path=f"/{name}")
    return tuple(value)
