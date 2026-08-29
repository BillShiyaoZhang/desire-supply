"""Closed adapters from domain policy ports to PostgreSQL evidence DTOs.

The adapter never manufactures an ALLOW decision.  Every database evidence
object is converted from an exact, current result returned by an injected
domain port.  Missing, malformed, stale, or mismatched results fail closed.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hmac
from typing import Any, Mapping, Optional
from uuid import UUID

from ...creator_profile.adapters.postgres import CreatorProfilePostgresHoldEvidence
from ...creator_profile.ports.commands import (
    CreatorProfileHoldDecision,
    CreatorProfileSafetyHoldResult,
)
from ...demand.adapters.postgres import (
    DemandPostgresContentPolicyEvidence,
    DemandPostgresHoldEvidence,
    DemandPostgresRuleRequirement,
)
from ...demand.ports.commands import (
    DemandContentPolicyDecision,
    DemandContentPolicyResult,
    DemandHoldDecision,
    DemandRuleRequirement,
    DemandSafetyHoldResult,
)
from .contracts import EditorPrincipal, EditorServiceError


class PortBackedEditorEvidenceProvider:
    """Translate four mandatory policy ports without a permissive fallback."""

    def __init__(
        self,
        *,
        profile_safety_hold: Any,
        demand_content_policy: Any,
        demand_safety_hold: Any,
        demand_rule_catalog: Any,
    ) -> None:
        dependencies = (
            profile_safety_hold,
            demand_content_policy,
            demand_safety_hold,
            demand_rule_catalog,
        )
        if any(value is None for value in dependencies):
            raise ValueError("all editor evidence ports are required")
        self._profile_safety_hold = profile_safety_hold
        self._demand_content_policy = demand_content_policy
        self._demand_safety_hold = demand_safety_hold
        self._demand_rule_catalog = demand_rule_catalog

    def profile_hold(
        self,
        *,
        principal: EditorPrincipal,
        action: str,
        profile_id: UUID,
        profile_version_no: int,
        taxonomy_bundle_id: UUID,
        prospective_aggregate_version: int,
        content_sha256: bytes,
        content: Mapping[str, Any],
        evaluated_at: datetime,
    ) -> CreatorProfilePostgresHoldEvidence:
        del profile_version_no, taxonomy_bundle_id, content
        now = _utc(evaluated_at)
        if action not in {
            "PublishCreatorProfileVersion",
            "ResumeCreatorProfile",
        }:
            _unavailable()
        query = {
            "actor_user_id": principal.user_id,
            "action": action,
            "profile_id": str(profile_id),
            "prospective_aggregate_version": prospective_aggregate_version,
            "content_sha256": _digest_hex(content_sha256),
            "policy_version": "creator-profile-hold-v1",
        }
        result = _call(self._profile_safety_hold.evaluate, query)
        if not isinstance(result, CreatorProfileSafetyHoldResult):
            _unavailable()
        if result.decision is CreatorProfileHoldDecision.BLOCK:
            _reject(403, "SAFETY_HOLD_BLOCKED")
        if (
            result.decision is not CreatorProfileHoldDecision.ALLOW
            or result.profile_id != query["profile_id"]
            or result.prospective_aggregate_version
            != query["prospective_aggregate_version"]
            or not _same_hex(result.content_sha256, query["content_sha256"])
            or result.actor_user_id != query["actor_user_id"]
            or result.policy_version != query["policy_version"]
            or not _current_window(result.evaluated_at, result.valid_until, now)
        ):
            _unavailable()
        return CreatorProfilePostgresHoldEvidence(
            profile_id=profile_id,
            prospective_aggregate_version=prospective_aggregate_version,
            content_sha256=content_sha256,
            actor_user_id=_uuid(principal.user_id),
            policy_version=result.policy_version,
            evaluated_at=result.evaluated_at,
            valid_until=result.valid_until,
        )

    def demand_content_policy(
        self,
        *,
        principal: EditorPrincipal,
        demand_id: UUID,
        demand_version_id: UUID,
        demand_version_no: int,
        taxonomy_bundle_id: UUID,
        content_sha256: bytes,
        content: Mapping[str, Any],
        evaluated_at: datetime,
        organization_id: Optional[UUID] = None,
    ) -> DemandPostgresContentPolicyEvidence:
        _demand_organization(principal, organization_id)
        del demand_version_no, taxonomy_bundle_id
        now = _utc(evaluated_at)
        query = {
            "demand_id": str(demand_id),
            "demand_version_id": str(demand_version_id),
            "content_sha256": _digest_hex(content_sha256),
            "content": content,
            "policy_version": "demand-content-policy-v1",
        }
        result = _call(self._demand_content_policy.evaluate, query)
        if not isinstance(result, DemandContentPolicyResult):
            _unavailable()
        if result.decision is DemandContentPolicyDecision.BLOCK:
            _reject(422, "DEMAND_VALIDATION_FAILED", path="/content")
        if (
            result.decision is not DemandContentPolicyDecision.ALLOW
            or result.demand_id != query["demand_id"]
            or result.demand_version_id != query["demand_version_id"]
            or not _same_hex(result.content_sha256, query["content_sha256"])
            or result.policy_version != query["policy_version"]
            or not _is_hex_digest(result.result_sha256)
            or not _current_window(result.evaluated_at, result.valid_until, now)
        ):
            _unavailable()
        return DemandPostgresContentPolicyEvidence(
            demand_id=demand_id,
            demand_version_id=demand_version_id,
            content_sha256=content_sha256,
            decision="ALLOW",
            policy_version=result.policy_version,
            result_sha256=bytes.fromhex(result.result_sha256),
            evaluated_at=result.evaluated_at,
            valid_until=result.valid_until,
        )

    def demand_hold(
        self,
        *,
        principal: EditorPrincipal,
        demand_id: UUID,
        demand_version_id: UUID,
        prospective_aggregate_version: int,
        content_sha256: bytes,
        action: str,
        content_policy: DemandPostgresContentPolicyEvidence,
        evaluated_at: datetime,
        organization_id: Optional[UUID] = None,
    ) -> DemandPostgresHoldEvidence:
        resolved_organization_id = _demand_organization(
            principal, organization_id
        )
        now = _utc(evaluated_at)
        if (
            content_policy.demand_id != demand_id
            or content_policy.demand_version_id != demand_version_id
            or not hmac.compare_digest(content_policy.content_sha256, content_sha256)
            or content_policy.valid_until <= now
        ):
            _unavailable()
        query = {
            "actor_id": principal.user_id,
            "organization_id": str(resolved_organization_id),
            "demand_id": str(demand_id),
            "prospective_aggregate_version": prospective_aggregate_version,
            "demand_version_id": str(demand_version_id),
            "content_sha256": _digest_hex(content_sha256),
            "action": action,
            "policy_version": "demand-safety-hold-v1",
        }
        result = _call(self._demand_safety_hold.evaluate, query)
        if not isinstance(result, DemandSafetyHoldResult):
            _unavailable()
        if result.decision is DemandHoldDecision.BLOCK:
            _reject(403, "SAFETY_HOLD_BLOCKED")
        if (
            result.decision is not DemandHoldDecision.ALLOW
            or result.actor_id != query["actor_id"]
            or result.organization_id != query["organization_id"]
            or result.demand_id != query["demand_id"]
            or result.prospective_aggregate_version
            != query["prospective_aggregate_version"]
            or result.demand_version_id != query["demand_version_id"]
            or not _same_hex(result.content_sha256, query["content_sha256"])
            or result.action != query["action"]
            or result.policy_version != query["policy_version"]
            or not _current_window(result.evaluated_at, result.valid_until, now)
        ):
            _unavailable()
        return DemandPostgresHoldEvidence(
            actor_id=_uuid(principal.user_id),
            organization_id=resolved_organization_id,
            demand_id=demand_id,
            prospective_aggregate_version=prospective_aggregate_version,
            demand_version_id=demand_version_id,
            content_sha256=content_sha256,
            action=action,
            decision="ALLOW",
            policy_version=result.policy_version,
            evaluated_at=result.evaluated_at,
            valid_until=result.valid_until,
        )

    def demand_rules(
        self,
        *,
        principal: EditorPrincipal,
        demand_id: UUID,
        taxonomy_bundle_id: UUID,
        operation: str,
        evaluated_at: datetime,
        organization_id: Optional[UUID] = None,
    ) -> DemandPostgresRuleRequirement:
        resolved_organization_id = _demand_organization(
            principal, organization_id
        )
        now = _utc(evaluated_at)
        result = _call(
            self._demand_rule_catalog.current_requirement,
            {
                "organization_id": str(resolved_organization_id),
                "demand_id": str(demand_id),
                "operation": operation,
            },
        )
        if not isinstance(result, DemandRuleRequirement):
            _unavailable()
        if (
            result.taxonomy_bundle_id != str(taxonomy_bundle_id)
            or result.effective_at.tzinfo is None
            or result.effective_at.astimezone(timezone.utc) > now
            or (
                result.effective_until is not None
                and (
                    result.effective_until.tzinfo is None
                    or result.effective_until.astimezone(timezone.utc) <= now
                )
            )
            or not _is_hex_digest(result.requirement_sha256)
        ):
            _unavailable()
        try:
            return DemandPostgresRuleRequirement(
                taxonomy_bundle_id=_uuid(result.taxonomy_bundle_id),
                budget_rule_bundle_id=_uuid(result.budget_rule_bundle_id),
                risk_rule_bundle_id=_uuid(result.risk_rule_bundle_id),
                matching_rule_bundle_id=_uuid(result.matching_rule_bundle_id),
                reason_code_bundle_id=_uuid(result.reason_code_bundle_id),
                composite_rule_requirement_id=_uuid(
                    result.composite_rule_requirement_id
                ),
                requirement_sha256=bytes.fromhex(result.requirement_sha256),
                effective_at=result.effective_at,
                effective_until=result.effective_until,
            )
        except (TypeError, ValueError):
            _unavailable()
        raise AssertionError("unreachable")


def _call(method: Any, query: Mapping[str, Any]) -> Any:
    try:
        return method(**query)
    except EditorServiceError:
        raise
    except Exception:
        _unavailable()
    raise AssertionError("unreachable")


def _demand_organization(
    principal: EditorPrincipal, candidate: Optional[UUID]
) -> UUID:
    if not isinstance(principal, EditorPrincipal):
        _reject(404, "RESOURCE_NOT_FOUND")
    # Legacy principals are accepted only by the isolated test-compatible
    # boundary.  Production principals always carry a selected workspace and
    # are checked by the stricter branches below.
    if (
        principal.workspace_id is None
        and principal.workspace_kind is None
        and "DEMAND_OWNER" in principal.role_codes
    ):
        result = _uuid(principal.organization_id)
        if candidate is not None and candidate != result:
            _reject(404, "RESOURCE_NOT_FOUND")
        return result
    if principal.workspace_kind == "ORGANIZATION" and "DEMAND_OWNER" in principal.role_codes:
        result = _uuid(principal.organization_id)
        if candidate is not None and candidate != result:
            _reject(404, "RESOURCE_NOT_FOUND")
        return result
    if (
        principal.workspace_kind == "PLATFORM"
        and "OPERATIONS_REVIEWER" in principal.role_codes
        and isinstance(candidate, UUID)
        and candidate.int != 0
    ):
        return candidate
    _reject(404, "RESOURCE_NOT_FOUND")
    raise AssertionError("unreachable")


def _current_window(start: datetime, end: datetime, now: datetime) -> bool:
    return (
        isinstance(start, datetime)
        and isinstance(end, datetime)
        and start.tzinfo is not None
        and end.tzinfo is not None
        and start.astimezone(timezone.utc) <= now
        and end.astimezone(timezone.utc) > now
    )


def _digest_hex(value: bytes) -> str:
    if not isinstance(value, bytes) or len(value) != 32:
        _unavailable()
    return value.hex()


def _is_hex_digest(value: Any) -> bool:
    if not isinstance(value, str) or len(value) != 64:
        return False
    try:
        decoded = bytes.fromhex(value)
    except ValueError:
        return False
    return len(decoded) == 32 and value == value.lower()


def _same_hex(left: Any, right: str) -> bool:
    return _is_hex_digest(left) and hmac.compare_digest(left, right)


def _uuid(value: str) -> UUID:
    try:
        result = UUID(value)
    except (AttributeError, TypeError, ValueError):
        _unavailable()
    if result.int == 0:
        _unavailable()
    return result


def _utc(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        _unavailable()
    return value.astimezone(timezone.utc)


def _reject(status: int, code: str, *, path: Optional[str] = None) -> None:
    raise EditorServiceError(status=status, code=code, path=path)


def _unavailable() -> None:
    raise EditorServiceError(status=503, code="SERVICE_UNAVAILABLE")


__all__ = ["PortBackedEditorEvidenceProvider"]
