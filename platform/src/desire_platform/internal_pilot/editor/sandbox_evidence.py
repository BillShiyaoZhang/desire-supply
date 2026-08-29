"""Executable policy boundary for the synthetic-only internal sandbox.

This is deliberately not a general-purpose trust or safety engine.  It can
only produce the narrow evidence accepted by the current Profile/Demand
PostgreSQL UoWs, and only after proving that the submitted material stays
inside the documented synthetic-data envelope.  CONTROLLED_PILOT and PUBLIC
must replace this component with independently reviewed policy services.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import re
import threading
from typing import Any, Mapping, Optional
from uuid import UUID

from ...creator_profile.adapters.postgres import CreatorProfilePostgresHoldEvidence
from ...creator_profile.domain import (
    CreatorProfileDomainError,
    canonical_profile_version_bytes,
    freeze_profile_content,
)
from ...demand.adapters.postgres import (
    DemandPostgresContentPolicyEvidence,
    DemandPostgresHoldEvidence,
    DemandPostgresRuleRequirement,
)
from ...demand.domain import (
    DemandContent,
    DemandDomainError,
    canonical_demand_version_bytes,
    validate_demand_content,
)
from ...demand.ports.commands import (
    DemandHoldDecision,
    DemandRuleRequirement,
    DemandSafetyHoldResult,
)
from .contracts import (
    EditorConfigurationDto,
    EditorPrincipal,
    EditorServiceError,
    EditorTaxonomyBundleDto,
)
from .choices import build_internal_sandbox_editor_choices


_PROFILE_POLICY_VERSION = "creator-profile-hold-v1"
_CONTENT_POLICY_VERSION = "demand-content-policy-v1"
_HOLD_POLICY_VERSION = "demand-safety-hold-v1"
_POLICY_RESULT_DOMAIN = b"desire:internal-sandbox:content-policy:v1\0"
_HOLD_TTL = timedelta(minutes=2)
_MAXIMUM_SYNTHETIC_AMOUNT_MINOR = 680_000
_REAL_LOCATOR = re.compile(
    r"(?:https?://|www\.|[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Za-z0-9.-]+\.[A-Za-z]{2,}|(?:\+?86[- ]?)?1[3-9][0-9]{9})",
    re.IGNORECASE,
)
_CLOSED_DEMAND_OPERATIONS = frozenset(("SUBMIT_DEMAND", "VERIFY_DEMAND"))


class InternalSandboxEditorEvidenceProvider:
    """Managed synthetic-data policy provider; no permissive fallback."""

    def __init__(
        self,
        *,
        deployment_mode: str,
        demand_rule_catalog: Any,
        demand_safety_hold: Any = None,
        validation_clock: Any = None,
    ) -> None:
        if deployment_mode != "INTERNAL_SANDBOX":
            raise ValueError("evidence provider is restricted to INTERNAL_SANDBOX")
        if not all(
            callable(getattr(demand_rule_catalog, name, None))
            for name in ("current_requirement", "check_readiness", "close")
        ):
            raise TypeError("managed Demand rule catalog is unavailable")
        if (demand_safety_hold is None) != (validation_clock is None):
            raise ValueError(
                "Trust Demand hold and its validation clock are both required"
            )
        if demand_safety_hold is not None and (
            not callable(getattr(demand_safety_hold, "evaluate", None))
            or not callable(getattr(demand_safety_hold, "close", None))
            or not callable(getattr(validation_clock, "now", None))
        ):
            raise TypeError("managed Trust Demand hold is unavailable")
        self._demand_rule_catalog = demand_rule_catalog
        self._demand_safety_hold = demand_safety_hold
        self._validation_clock = validation_clock
        self._closed = False
        self._content_facts: dict[int, tuple[Any, ...]] = {}
        self._lock = threading.RLock()

    def editor_configuration(
        self,
        *,
        principal: EditorPrincipal,
        evaluated_at: datetime,
    ) -> EditorConfigurationDto:
        """Project the active taxonomy from the managed PostgreSQL rule catalog."""

        self._require_open()
        _require_configuration_workspace(principal)
        now = _configuration_utc(evaluated_at)
        # The catalog's policy is a singleton, but its fixed read program still
        # requires canonical scope context.  Use only authenticated principal
        # identifiers; no browser-selected or fabricated resource identifier is
        # admitted before the first Profile/Demand exists.
        organization_id = principal.organization_id or principal.user_id
        try:
            result = self._demand_rule_catalog.current_requirement(
                organization_id=organization_id,
                demand_id=principal.user_id,
                operation="SUBMIT_DEMAND",
            )
        except BaseException:
            _configuration_unavailable()
        if not isinstance(result, DemandRuleRequirement):
            _configuration_unavailable()
        try:
            taxonomy_bundle_id = UUID(result.taxonomy_bundle_id)
            effective_at = _configuration_utc(result.effective_at)
            effective_until = (
                None
                if result.effective_until is None
                else _configuration_utc(result.effective_until)
            )
            digest = bytes.fromhex(result.requirement_sha256)
            if (
                len(digest) != 32
                or result.requirement_sha256 != digest.hex()
                or taxonomy_bundle_id.int == 0
                or str(taxonomy_bundle_id) != result.taxonomy_bundle_id
                or effective_at > now
                or (effective_until is not None and effective_until <= now)
            ):
                _configuration_unavailable()
            try:
                editor_choices = build_internal_sandbox_editor_choices(
                    bundle_id=str(taxonomy_bundle_id)
                )
            except BaseException:
                _configuration_unavailable()
            return EditorConfigurationDto(
                schema_version="editor-configuration-v2",
                deployment_mode="INTERNAL_SANDBOX",
                taxonomy_bundle=EditorTaxonomyBundleDto(
                    bundle_id=str(taxonomy_bundle_id),
                    status="CURRENT_APPROVED",
                    effective_at=effective_at,
                    effective_until=effective_until,
                ),
                editor_choices=editor_choices,
            )
        except (AttributeError, TypeError, ValueError):
            _configuration_unavailable()
        raise AssertionError("unreachable")

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
        self._require_open()
        _require_workspace(principal, "PERSONAL", "CREATOR")
        if action not in {
            "PublishCreatorProfileVersion",
            "ResumeCreatorProfile",
        }:
            _unavailable()
        now = _utc(evaluated_at)
        try:
            frozen = freeze_profile_content(content, for_publish=True)
            expected = hashlib.sha256(
                canonical_profile_version_bytes(
                    profile_id=str(profile_id),
                    version_no=profile_version_no,
                    taxonomy_bundle_id=str(taxonomy_bundle_id),
                    content=frozen,
                )
            ).digest()
        except (CreatorProfileDomainError, TypeError, ValueError):
            _reject_synthetic()
        if not _same_digest(expected, content_sha256):
            _unavailable()
        if not _profile_is_synthetic(content):
            _reject_synthetic()
        return CreatorProfilePostgresHoldEvidence(
            profile_id=profile_id,
            prospective_aggregate_version=prospective_aggregate_version,
            content_sha256=content_sha256,
            actor_user_id=_uuid(principal.user_id),
            policy_version=_PROFILE_POLICY_VERSION,
            evaluated_at=now,
            valid_until=now + _HOLD_TTL,
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
        self._require_open()
        resolved_organization_id = _demand_evidence_organization(
            principal, organization_id
        )
        now = _utc(evaluated_at)
        try:
            frozen = _freeze_demand_content(content)
            validate_demand_content(frozen, for_submission=True)
            expected = hashlib.sha256(
                canonical_demand_version_bytes(
                    demand_id=str(demand_id),
                    version_no=demand_version_no,
                    taxonomy_bundle_id=str(taxonomy_bundle_id),
                    content=frozen,
                )
            ).digest()
        except (DemandDomainError, TypeError, ValueError):
            _reject_synthetic()
        if not _same_digest(expected, content_sha256):
            _unavailable()
        if not _demand_is_synthetic(content):
            _reject_synthetic()
        surface = {
            "content_sha256": content_sha256.hex(),
            "demand_id": str(demand_id),
            "demand_version_id": str(demand_version_id),
            "policy_version": _CONTENT_POLICY_VERSION,
            "taxonomy_bundle_id": str(taxonomy_bundle_id),
        }
        result = hashlib.sha256(
            _POLICY_RESULT_DOMAIN
            + json.dumps(
                surface,
                ensure_ascii=False,
                allow_nan=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        ).digest()
        evidence = DemandPostgresContentPolicyEvidence(
            demand_id=demand_id,
            demand_version_id=demand_version_id,
            content_sha256=content_sha256,
            decision="ALLOW",
            policy_version=_CONTENT_POLICY_VERSION,
            result_sha256=result,
            evaluated_at=now,
            valid_until=now + _HOLD_TTL,
        )
        with self._lock:
            if self._closed or len(self._content_facts) >= 10_000:
                _unavailable()
            self._content_facts[id(evidence)] = (
                evidence,
                principal.user_id,
                str(resolved_organization_id),
                demand_id,
                demand_version_id,
                content_sha256,
            )
        return evidence

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
        self._require_open()
        resolved_organization_id = _demand_evidence_organization(
            principal, organization_id
        )
        now = _utc(evaluated_at)
        if action not in _CLOSED_DEMAND_OPERATIONS:
            _unavailable()
        with self._lock:
            remembered = self._content_facts.pop(id(content_policy), None)
        if (
            remembered
            != (
                content_policy,
                principal.user_id,
                str(resolved_organization_id),
                demand_id,
                demand_version_id,
                content_sha256,
            )
            or content_policy.valid_until <= now
            or not _same_digest(content_policy.content_sha256, content_sha256)
        ):
            raise EditorServiceError(
                status=503, code="EVIDENCE_CHAIN_UNAVAILABLE"
            )
        if self._demand_safety_hold is None:
            return DemandPostgresHoldEvidence(
                actor_id=_uuid(principal.user_id),
                organization_id=resolved_organization_id,
                demand_id=demand_id,
                prospective_aggregate_version=prospective_aggregate_version,
                demand_version_id=demand_version_id,
                content_sha256=content_sha256,
                action=action,
                decision="ALLOW",
                policy_version=_HOLD_POLICY_VERSION,
                evaluated_at=now,
                valid_until=content_policy.valid_until,
            )
        query = {
            "actor_id": principal.user_id,
            "organization_id": str(resolved_organization_id),
            "demand_id": str(demand_id),
            "prospective_aggregate_version": prospective_aggregate_version,
            "demand_version_id": str(demand_version_id),
            "content_sha256": content_sha256.hex(),
            "action": action,
            "policy_version": _HOLD_POLICY_VERSION,
        }
        try:
            result = self._demand_safety_hold.evaluate(**query)
            validation_now = _utc(self._validation_clock.now())
            evaluated = _utc(result.evaluated_at)
            valid_until = _utc(result.valid_until)
        except BaseException:
            _unavailable()
        if (
            not isinstance(result, DemandSafetyHoldResult)
            or (
                result.decision is not DemandHoldDecision.ALLOW
                and result.decision is not DemandHoldDecision.BLOCK
            )
            or result.actor_id != query["actor_id"]
            or result.organization_id != query["organization_id"]
            or result.demand_id != query["demand_id"]
            or result.prospective_aggregate_version
            != query["prospective_aggregate_version"]
            or result.demand_version_id != query["demand_version_id"]
            or not isinstance(result.content_sha256, str)
            or not hmac.compare_digest(
                result.content_sha256,
                query["content_sha256"],
            )
            or result.action != query["action"]
            or result.policy_version != query["policy_version"]
            or evaluated > validation_now
            or valid_until <= validation_now
            or valid_until <= evaluated
            or valid_until - evaluated > timedelta(seconds=15)
            or content_policy.valid_until <= validation_now
        ):
            _unavailable()
        if result.decision is DemandHoldDecision.BLOCK:
            raise EditorServiceError(status=403, code="SAFETY_HOLD_BLOCKED")
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
            evaluated_at=evaluated,
            valid_until=valid_until,
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
        self._require_open()
        resolved_organization_id = _demand_evidence_organization(
            principal, organization_id
        )
        now = _utc(evaluated_at)
        if operation not in _CLOSED_DEMAND_OPERATIONS:
            _unavailable()
        try:
            result = self._demand_rule_catalog.current_requirement(
                organization_id=str(resolved_organization_id),
                demand_id=str(demand_id),
                operation=operation,
            )
        except BaseException:
            raise EditorServiceError(
                status=503, code="RULE_REQUIREMENT_UNAVAILABLE"
            ) from None
        if not isinstance(result, DemandRuleRequirement):
            _rule_unavailable()
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
        ):
            _rule_unavailable()
        try:
            digest = bytes.fromhex(result.requirement_sha256)
            if len(digest) != 32 or result.requirement_sha256 != digest.hex():
                _rule_unavailable()
            return DemandPostgresRuleRequirement(
                taxonomy_bundle_id=taxonomy_bundle_id,
                budget_rule_bundle_id=_uuid(result.budget_rule_bundle_id),
                risk_rule_bundle_id=_uuid(result.risk_rule_bundle_id),
                matching_rule_bundle_id=_uuid(result.matching_rule_bundle_id),
                reason_code_bundle_id=_uuid(result.reason_code_bundle_id),
                composite_rule_requirement_id=_uuid(
                    result.composite_rule_requirement_id
                ),
                requirement_sha256=digest,
                effective_at=result.effective_at,
                effective_until=result.effective_until,
            )
        except (TypeError, ValueError):
            _rule_unavailable()
        raise AssertionError("unreachable")

    def check_readiness(self, *, timeout_ms: int) -> None:
        if (
            self._closed
            or type(timeout_ms) is not int
            or not 1 <= timeout_ms <= 30_000
        ):
            raise RuntimeError("EDITOR_EVIDENCE_NOT_READY")
        with self._lock:
            now = datetime.now(timezone.utc)
            stale = tuple(
                identity
                for identity, fact in self._content_facts.items()
                if isinstance(fact[0], DemandPostgresContentPolicyEvidence)
                and fact[0].valid_until <= now
            )
            for identity in stale:
                self._content_facts.pop(identity, None)
        try:
            result = self._demand_rule_catalog.check_readiness(
                timeout_ms=timeout_ms
            )
        except BaseException:
            raise RuntimeError("EDITOR_EVIDENCE_NOT_READY") from None
        if result is not None:
            raise RuntimeError("EDITOR_EVIDENCE_NOT_READY")

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            self._content_facts.clear()
        try:
            self._demand_rule_catalog.close()
        finally:
            if self._demand_safety_hold is not None:
                self._demand_safety_hold.close()

    def _require_open(self) -> None:
        with self._lock:
            if self._closed:
                _unavailable()

    def __repr__(self) -> str:
        with self._lock:
            return (
                "InternalSandboxEditorEvidenceProvider("
                f"closed={self._closed}, pending_content_facts="
                f"{len(self._content_facts)}, trust_hold="
                f"{self._demand_safety_hold is not None}, policy=<redacted>)"
            )


def _profile_is_synthetic(content: Mapping[str, Any]) -> bool:
    if _contains_real_locator(content):
        return False
    for value in _walk_mappings(content):
        if "source_kind" in value and (
            value.get("source_kind") != "SELF_ASSERTED"
            or value.get("evidence_ids") != []
        ):
            return False
    compensation = content.get("compensation")
    if compensation is not None and (
        not isinstance(compensation, Mapping)
        or compensation.get("currency") != "CNY"
        or any(
            type(compensation.get(name)) is not int
            or compensation[name] < 0
            or compensation[name] > _MAXIMUM_SYNTHETIC_AMOUNT_MINOR
            for name in (
                "minimum_project_amount_minor",
                "direct_cost_amount_minor",
            )
        )
    ):
        return False
    boundaries = content.get("boundaries")
    if boundaries is not None and (
        not isinstance(boundaries, Mapping)
        or not isinstance(boundaries.get("allowed_data_sensitivity"), Mapping)
        or boundaries["allowed_data_sensitivity"].get("data_sensitivity")
        not in {"PUBLIC", "INTERNAL"}
    ):
        return False
    location = content.get("location")
    if location is not None and (
        not isinstance(location, Mapping)
        or not str(location.get("region_code", "")).startswith("CN")
    ):
        return False
    ai = content.get("ai")
    return (
        isinstance(ai, Mapping)
        and ai.get("allowed") is False
        and ai.get("requires_ai") is False
    )


def _demand_is_synthetic(content: Mapping[str, Any]) -> bool:
    if _contains_real_locator(content):
        return False
    try:
        problem = content["problem"]
        scope = content["scope"]
        budget = content["budget"]
        risk = content["risk"]
        ai = content["ai"]
        location = content["location"]
        if not all(
            isinstance(value, Mapping)
            for value in (problem, scope, budget, risk, ai, location)
        ):
            return False
        amounts = tuple(
            budget[name]
            for name in (
                "minimum_amount_minor",
                "maximum_amount_minor",
                "direct_cost_amount_minor",
            )
        )
        return (
            str(problem["background"]).startswith("INTERNAL_SANDBOX ")
            and problem["target_user_category_codes"] == ["SYNTHETIC_USER"]
            and "真实用户与真实交易" in scope["out_of_scope"]
            and budget["currency"] == "CNY"
            and all(
                type(amount) is int
                and 0 <= amount <= _MAXIMUM_SYNTHETIC_AMOUNT_MINOR
                for amount in amounts
            )
            and risk["data_sensitivity"] in {"PUBLIC", "INTERNAL"}
            and ai["allowed"] is False
            and ai["required"] is False
            and str(location["demand_region_code"]).startswith("CN")
            and all(
                str(region).startswith("CN")
                for region in location["allowed_creator_region_codes"]
            )
        )
    except (KeyError, TypeError, ValueError):
        return False


def _freeze_demand_content(value: Mapping[str, Any]) -> DemandContent:
    def freeze(child: Any) -> Any:
        if isinstance(child, Mapping):
            return DemandContent(
                tuple((str(key), freeze(item)) for key, item in child.items())
            )
        if isinstance(child, (list, tuple)):
            return tuple(freeze(item) for item in child)
        if child is None or isinstance(child, (bool, int, str)):
            return child
        raise TypeError("Demand content is not closed JSON")

    result = freeze(value)
    if not isinstance(result, DemandContent):
        raise TypeError("Demand content is not an object")
    return result


def _walk_mappings(value: Any):
    if isinstance(value, Mapping):
        yield value
        for child in value.values():
            yield from _walk_mappings(child)
    elif isinstance(value, (list, tuple)):
        for child in value:
            yield from _walk_mappings(child)


def _contains_real_locator(value: Any) -> bool:
    return any(
        _REAL_LOCATOR.search(child) is not None
        for child in _walk_strings(value)
    )


def _walk_strings(value: Any):
    if isinstance(value, Mapping):
        for child in value.values():
            yield from _walk_strings(child)
    elif isinstance(value, (list, tuple)):
        for child in value:
            yield from _walk_strings(child)
    elif isinstance(value, str):
        yield value


def _require_workspace(
    principal: EditorPrincipal, kind: str, role: str
) -> None:
    if (
        not isinstance(principal, EditorPrincipal)
        or principal.workspace_kind != kind
        or role not in principal.role_codes
        or len(principal.principal_marker_sha256) != 32
    ):
        raise EditorServiceError(status=404, code="RESOURCE_NOT_FOUND")


def _require_configuration_workspace(principal: EditorPrincipal) -> None:
    if not isinstance(principal, EditorPrincipal):
        raise EditorServiceError(status=404, code="RESOURCE_NOT_FOUND")
    allowed = (
        principal.workspace_kind == "PERSONAL"
        and "CREATOR" in principal.role_codes
        or principal.workspace_kind == "ORGANIZATION"
        and "DEMAND_OWNER" in principal.role_codes
    )
    if not allowed or len(principal.principal_marker_sha256) != 32:
        raise EditorServiceError(status=404, code="RESOURCE_NOT_FOUND")


def _demand_evidence_organization(
    principal: EditorPrincipal, candidate: Optional[UUID]
) -> UUID:
    _require_workspace(
        principal,
        principal.workspace_kind or "",
        (
            "DEMAND_OWNER"
            if principal.workspace_kind == "ORGANIZATION"
            else "OPERATIONS_REVIEWER"
        ),
    )
    if principal.workspace_kind == "ORGANIZATION":
        organization_id = _uuid(principal.organization_id)
        if candidate is not None and candidate != organization_id:
            raise EditorServiceError(status=404, code="RESOURCE_NOT_FOUND")
        return organization_id
    if principal.workspace_kind == "PLATFORM" and isinstance(candidate, UUID):
        if candidate.int != 0:
            return candidate
    raise EditorServiceError(status=404, code="RESOURCE_NOT_FOUND")


def _same_digest(left: bytes, right: bytes) -> bool:
    return (
        isinstance(left, bytes)
        and isinstance(right, bytes)
        and len(left) == len(right) == 32
        and hmac.compare_digest(left, right)
    )


def _uuid(value: Any) -> UUID:
    try:
        result = value if isinstance(value, UUID) else UUID(value)
    except (AttributeError, TypeError, ValueError):
        _unavailable()
    if result.int == 0:
        _unavailable()
    return result


def _utc(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        _unavailable()
    return value.astimezone(timezone.utc)


def _configuration_utc(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        _configuration_unavailable()
    try:
        if value.utcoffset() is None:
            _configuration_unavailable()
        return value.astimezone(timezone.utc)
    except (OverflowError, ValueError):
        _configuration_unavailable()
    raise AssertionError("unreachable")


def _reject_synthetic() -> None:
    raise EditorServiceError(
        status=422,
        code="SYNTHETIC_DATA_REQUIRED",
        path="/content",
    )


def _rule_unavailable() -> None:
    raise EditorServiceError(status=503, code="RULE_REQUIREMENT_UNAVAILABLE")


def _configuration_unavailable() -> None:
    raise EditorServiceError(
        status=503, code="EDITOR_CONFIGURATION_UNAVAILABLE"
    )


def _unavailable() -> None:
    raise EditorServiceError(status=503, code="SERVICE_UNAVAILABLE")


__all__ = ["InternalSandboxEditorEvidenceProvider"]
