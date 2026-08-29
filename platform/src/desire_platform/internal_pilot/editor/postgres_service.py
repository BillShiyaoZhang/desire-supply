"""HTTP-compatible editor service backed only by canonical PostgreSQL UoWs.

This adapter converts authenticated editor DTO calls into the closed Profile
and Demand database commands.  IAM authority markers and policy/safety
evidence are injected by trusted composition ports; raw browser role strings
never become database authority.  No Memory repository is consulted.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import re
from typing import Any, Callable, Mapping, Optional, Protocol, Tuple, Union
from uuid import UUID

from ...creator_profile.adapters.postgres import (
    CreatorProfilePostgresCommand,
    CreatorProfilePostgresCommitOutcomeUnknownError,
    CreatorProfilePostgresConfigurationError,
    CreatorProfilePostgresDatabaseError,
    CreatorProfilePostgresExecutionScope,
    CreatorProfilePostgresHoldEvidence,
    CreatorProfilePostgresOperation,
    CreatorProfilePostgresReceiptMaterial,
)
from ...creator_profile.domain import (
    CreatorProfileDomainError,
    canonical_profile_version_bytes,
    freeze_profile_content,
)
from ...demand.adapters.postgres import (
    DemandPostgresCommand,
    DemandPostgresCommitOutcomeUnknownError,
    DemandPostgresConfigurationError,
    DemandPostgresContentPolicyEvidence,
    DemandPostgresDatabaseError,
    DemandPostgresExecutionScope,
    DemandPostgresHoldEvidence,
    DemandPostgresOperation,
    DemandPostgresReceiptMaterial,
    DemandPostgresRuleRequirement,
)
from ...demand.domain import (
    CancelReasonCode,
    DemandContent,
    DemandDomainError,
    canonical_demand_version_bytes,
)
from .contracts import (
    EditorConfigurationDto,
    EditorPrincipal,
    EditorReviewClaimDto,
    EditorReviewHistoryItemDto,
    EditorReviewHistoryPageDto,
    EditorReviewQueueItemDto,
    EditorResourceDto,
    EditorServiceError,
)
from .content_choices import (
    internal_sandbox_editor_choices,
    validate_editor_choice_membership,
)
from .postgres import (
    DemandCompletedReleaseReplayError,
    DemandCompletedReleaseReplayProbeRequest,
    DemandCompletedReleaseReplayResult,
    DemandCompletedVerifyReplayError,
    DemandCompletedVerifyReplayProbeRequest,
    DemandCompletedVerifyReplayResult,
    DemandReadAuthority,
    EditorPostgresConfigurationError,
    ProfileCompletedLifecycleReplayError,
    ProfileCompletedLifecycleReplayProbeRequest,
    ProfileCompletedLifecycleReplayResult,
    ProfileReadAuthority,
    PsycopgEditorRepository,
    _PROFILE_EDITABLE_PATHS,
)
from .review_queue import (
    DemandReviewClaimRequest,
    DemandReviewQueueCommitOutcomeUnknownError,
    DemandReviewQueueError,
)


class EditorPostgresAuthorityProvider(Protocol):
    """Trusted, session-bound authority and target discovery projection."""

    def profile(
        self,
        *,
        principal: EditorPrincipal,
        operation: CreatorProfilePostgresOperation,
        profile_id: str,
    ) -> ProfileReadAuthority: ...

    def demand(
        self,
        *,
        principal: EditorPrincipal,
        operation: DemandPostgresOperation,
        demand_id: str,
        assignment_id: Optional[str] = None,
    ) -> DemandReadAuthority: ...

    def profile_targets(
        self, *, principal: EditorPrincipal
    ) -> Tuple[Tuple[str, ProfileReadAuthority], ...]: ...

    def demand_targets(
        self, *, principal: EditorPrincipal
    ) -> Tuple[Tuple[str, DemandReadAuthority], ...]: ...


class EditorPostgresEvidenceProvider(Protocol):
    """Policy engines produce exact, short-lived evidence for fixed UoWs."""

    def editor_configuration(
        self,
        *,
        principal: EditorPrincipal,
        evaluated_at: datetime,
    ) -> EditorConfigurationDto: ...

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
    ) -> CreatorProfilePostgresHoldEvidence: ...

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
    ) -> DemandPostgresContentPolicyEvidence: ...

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
    ) -> DemandPostgresHoldEvidence: ...

    def demand_rules(
        self,
        *,
        principal: EditorPrincipal,
        demand_id: UUID,
        taxonomy_bundle_id: UUID,
        operation: str,
        evaluated_at: datetime,
        organization_id: Optional[UUID] = None,
    ) -> DemandPostgresRuleRequirement: ...


class EditorFieldCodeResolver(Protocol):
    def demand_field_code(self, json_pointer: str) -> str: ...


class EditorDemandCompletedVerifyReceiptProbe(Protocol):
    def read_completed(
        self,
        request: DemandCompletedVerifyReplayProbeRequest,
    ) -> Optional[DemandCompletedVerifyReplayResult]: ...

    def read_completed_release(
        self,
        request: DemandCompletedReleaseReplayProbeRequest,
    ) -> Optional[DemandCompletedReleaseReplayResult]: ...


class EditorProfileCompletedLifecycleReceiptProbe(Protocol):
    def read_completed(
        self,
        request: ProfileCompletedLifecycleReplayProbeRequest,
    ) -> Optional[ProfileCompletedLifecycleReplayResult]: ...


@dataclass(frozen=True)
class EditorPostgresKeys:
    id_key: Union[bytes, bytearray] = field(repr=False)
    profile_idempotency_key: Union[bytes, bytearray] = field(repr=False)
    profile_payload_key: Union[bytes, bytearray] = field(repr=False)
    demand_idempotency_key: Union[bytes, bytearray] = field(repr=False)
    demand_payload_key: Union[bytes, bytearray] = field(repr=False)
    demand_client_reference_key: Union[bytes, bytearray] = field(repr=False)
    profile_idempotency_key_id: str = "profile-idempotency-2026-01"
    profile_payload_key_id: str = "profile-payload-2026-01"
    demand_idempotency_key_id: str = "demand-idempotency-2026-01"
    demand_payload_key_id: str = "demand-payload-2026-01"
    demand_client_reference_key_id: str = "demand-client-ref-2026-01"

    def __post_init__(self) -> None:
        secrets = (
            self.id_key,
            self.profile_idempotency_key,
            self.profile_payload_key,
            self.demand_idempotency_key,
            self.demand_payload_key,
            self.demand_client_reference_key,
        )
        if any(
            not isinstance(value, (bytes, bytearray))
            or len(value) < 32
            or not any(value)
            for value in secrets
        ):
            raise ValueError("editor PostgreSQL keys must contain at least 256 bits")
        if len({bytes(value) for value in secrets}) != len(secrets):
            raise ValueError("editor PostgreSQL key purposes must be separated")
        key_ids = (
            self.profile_idempotency_key_id,
            self.profile_payload_key_id,
            self.demand_idempotency_key_id,
            self.demand_payload_key_id,
            self.demand_client_reference_key_id,
        )
        if any(not _KEY_ID.fullmatch(value) for value in key_ids):
            raise ValueError("editor PostgreSQL key ID is invalid")
        if self.profile_idempotency_key_id == self.profile_payload_key_id:
            raise ValueError("Profile receipt key purposes must differ")
        if self.demand_idempotency_key_id == self.demand_payload_key_id:
            raise ValueError("Demand receipt key purposes must differ")


class DefaultEditorFieldCodeResolver:
    """Closed v1 mapping from editable JSON Pointers to review field codes."""

    _CODES = {
        "/problem": "PROBLEM",
        "/scope": "SCOPE",
        "/acceptance": "ACCEPTANCE",
        "/skills": "SKILLS",
        "/matching": "MATCHING",
        "/schedule": "SCHEDULE",
        "/budget": "BUDGET",
        "/milestone_plan": "MILESTONE_PLAN",
        "/risk": "RISK",
        "/ai": "AI",
        "/collaboration": "COLLABORATION",
        "/location": "LOCATION",
        "/declarations": "DECLARATIONS",
    }

    def demand_field_code(self, json_pointer: str) -> str:
        try:
            return self._CODES[json_pointer]
        except KeyError as error:
            raise EditorServiceError(
                status=422,
                code="INVALID_FIELD_PATH",
                path="/required_field_paths",
            ) from error


class PostgresEditorService:
    """Same callable surface as :class:`EditorService`, without Memory state."""

    def __init__(
        self,
        *,
        repository: PsycopgEditorRepository,
        authorities: EditorPostgresAuthorityProvider,
        evidence: EditorPostgresEvidenceProvider,
        keys: EditorPostgresKeys,
        clock: Any,
        field_codes: Optional[EditorFieldCodeResolver] = None,
        review_queue: Optional[Any] = None,
        completed_verify_receipts: Optional[
            EditorDemandCompletedVerifyReceiptProbe
        ] = None,
        completed_profile_lifecycle_receipts: Optional[
            EditorProfileCompletedLifecycleReceiptProbe
        ] = None,
    ) -> None:
        self._repo = repository
        self._authorities = authorities
        self._evidence = evidence
        self._keys = keys
        self._clock = clock
        self._field_codes = field_codes or DefaultEditorFieldCodeResolver()
        self._review_queue = review_queue
        self._completed_verify_receipts = completed_verify_receipts
        self._completed_profile_lifecycle_receipts = (
            completed_profile_lifecycle_receipts
        )
        self._editor_choices = internal_sandbox_editor_choices()

    def get_configuration(
        self, *, principal: EditorPrincipal
    ) -> EditorConfigurationDto:
        if not ({"CREATOR", "DEMAND_OWNER"} & set(principal.role_codes)):
            self._not_found()
        return self._evidence.editor_configuration(
            principal=principal,
            evaluated_at=self._now(),
        )

    def create_profile(
        self, *, principal: EditorPrincipal, idempotency_key: str
    ) -> EditorResourceDto:
        self._require_role(principal, "CREATOR")
        payload: Mapping[str, Any] = {}
        command_id = self._command_id(principal, "CREATE_PROFILE", idempotency_key)
        profile_id = self._scoped_id(command_id, "profile")
        authority = self._authorities.profile(
            principal=principal,
            operation=CreatorProfilePostgresOperation.CREATE,
            profile_id=str(profile_id),
        )
        command = self._profile_command(
            principal=principal,
            operation=CreatorProfilePostgresOperation.CREATE,
            profile_id=profile_id,
            command_id=command_id,
            idempotency_key=idempotency_key,
            payload=payload,
            authority=authority,
            expected_version=None,
        )
        self._execute_profile(command)
        return self._repo.get_profile(
            principal=principal, profile_id=str(profile_id), authority=authority
        )

    def list_profiles(
        self, *, principal: EditorPrincipal
    ) -> Tuple[EditorResourceDto, ...]:
        self._require_role(principal, "CREATOR")
        return self._repo.list_profiles(
            principal=principal,
            targets=self._authorities.profile_targets(principal=principal),
        )

    def get_profile(
        self, *, principal: EditorPrincipal, profile_id: str
    ) -> EditorResourceDto:
        self._require_role(principal, "CREATOR")
        authority = self._authorities.profile(
            principal=principal,
            operation=CreatorProfilePostgresOperation.SAVE_DRAFT,
            profile_id=profile_id,
        )
        return self._repo.get_profile(
            principal=principal, profile_id=profile_id, authority=authority
        )

    def save_profile_draft(
        self,
        *,
        principal: EditorPrincipal,
        profile_id: str,
        if_match: str,
        base_version_id: Optional[str],
        taxonomy_bundle_id: str,
        content: Mapping[str, Any],
        idempotency_key: str,
    ) -> EditorResourceDto:
        self._require_role(principal, "CREATOR")
        authority = self._authorities.profile(
            principal=principal,
            operation=CreatorProfilePostgresOperation.SAVE_DRAFT,
            profile_id=profile_id,
        )
        current = self._repo.get_profile(
            principal=principal, profile_id=profile_id, authority=authority
        )
        if current.status not in {"DRAFT", "ACTIVE"}:
            raise EditorServiceError(
                status=409,
                code="INVALID_STATE_TRANSITION",
                path="/status",
            )
        self._require_etag(
            current=current,
            if_match=if_match,
            base_version_id=base_version_id,
            yours=content,
        )
        try:
            frozen = freeze_profile_content(content, for_publish=False)
            next_version_no = max(
                (item.version_no for item in current.versions), default=0
            ) + 1
            canonical = canonical_profile_version_bytes(
                profile_id=profile_id,
                version_no=next_version_no,
                taxonomy_bundle_id=taxonomy_bundle_id,
                content=frozen,
            )
        except (CreatorProfileDomainError, TypeError, ValueError) as error:
            raise EditorServiceError(
                status=422, code="PROFILE_VALIDATION_FAILED", path="/content"
            ) from error
        payload = {
            "profile_id": profile_id,
            "if_match": if_match,
            "base_version_id": base_version_id,
            "taxonomy_bundle_id": taxonomy_bundle_id,
            "content": content,
        }
        command_id = self._command_id(principal, "SAVE_PROFILE", idempotency_key)
        command = self._profile_command(
            principal=principal,
            operation=CreatorProfilePostgresOperation.SAVE_DRAFT,
            profile_id=_uuid(profile_id),
            command_id=command_id,
            idempotency_key=idempotency_key,
            payload=payload,
            authority=authority,
            expected_version=current.revision,
            profile_version_id=self._scoped_id(command_id, "profile-version"),
            based_on_profile_version_id=(
                None if base_version_id is None else _uuid(base_version_id)
            ),
            taxonomy_bundle_id=_uuid(taxonomy_bundle_id),
            canonical_profile_version_bytes=canonical,
            content_sha256=hashlib.sha256(canonical).digest(),
        )
        self._execute_profile(
            command,
            current=current,
            membership_validation=lambda: self._validate_editor_choices(
                "CREATOR_PROFILE", content
            ),
        )
        return self._repo.get_profile(
            principal=principal, profile_id=profile_id, authority=authority
        )

    def publish_profile(
        self,
        *,
        principal: EditorPrincipal,
        profile_id: str,
        draft_version_id: str,
        if_match: str,
        idempotency_key: str,
    ) -> EditorResourceDto:
        self._require_role(principal, "CREATOR")
        authority = self._authorities.profile(
            principal=principal,
            operation=CreatorProfilePostgresOperation.PUBLISH,
            profile_id=profile_id,
        )
        current = self._repo.get_profile(
            principal=principal, profile_id=profile_id, authority=authority
        )
        draft = next(
            (
                item
                for item in current.versions
                if item.version_id == draft_version_id and item.status == "DRAFT"
            ),
            None,
        )
        if draft is None or current.current_version is None:
            self._not_found()
        self._require_etag(
            current=current,
            if_match=if_match,
            base_version_id=draft_version_id,
            yours=draft.content,
        )
        now = self._now()
        hold = self._evidence.profile_hold(
            principal=principal,
            action="PublishCreatorProfileVersion",
            profile_id=_uuid(profile_id),
            profile_version_no=draft.version_no,
            taxonomy_bundle_id=_uuid(draft.taxonomy_bundle_id),
            prospective_aggregate_version=current.revision + 1,
            content_sha256=bytes.fromhex(draft.content_sha256),
            content=draft.content,
            evaluated_at=now,
        )
        payload = {
            "profile_id": profile_id,
            "draft_version_id": draft_version_id,
            "if_match": if_match,
        }
        command_id = self._command_id(principal, "PUBLISH_PROFILE", idempotency_key)
        command = self._profile_command(
            principal=principal,
            operation=CreatorProfilePostgresOperation.PUBLISH,
            profile_id=_uuid(profile_id),
            command_id=command_id,
            idempotency_key=idempotency_key,
            payload=payload,
            authority=authority,
            expected_version=current.revision,
            profile_version_id=_uuid(draft_version_id),
            confirmed=True,
            hold=hold,
        )
        self._execute_profile(
            command,
            current=current,
            membership_validation=lambda: self._validate_editor_choices(
                "CREATOR_PROFILE", draft.content
            ),
        )
        return self._repo.get_profile(
            principal=principal, profile_id=profile_id, authority=authority
        )

    def pause_profile(
        self,
        *,
        principal: EditorPrincipal,
        profile_id: str,
        if_match: str,
        reason_code: str,
        idempotency_key: str,
    ) -> EditorResourceDto:
        self._require_role(principal, "CREATOR")
        if reason_code not in {
            "OWNER_REQUEST",
            "TEMPORARY_UNAVAILABILITY",
            "SAFETY_REVIEW",
        }:
            raise EditorServiceError(
                status=422, code="INVALID_REASON_CODE", path="/reason_code"
            )
        payload = {
            "profile_id": profile_id,
            "if_match": if_match,
            "reason_code": reason_code,
        }
        command_id = self._command_id(
            principal, "PAUSE_PROFILE", idempotency_key
        )
        authority = self._authorities.profile(
            principal=principal,
            operation=CreatorProfilePostgresOperation.PAUSE,
            profile_id=profile_id,
        )
        replay_request = self._profile_lifecycle_replay_request(
            principal=principal,
            profile_id=profile_id,
            operation=CreatorProfilePostgresOperation.PAUSE,
            command_id=command_id,
            idempotency_key=idempotency_key,
            if_match=if_match,
            payload=payload,
            authority=authority,
        )
        replay = self._read_completed_profile_lifecycle(replay_request)
        if replay is not None:
            return self._project_completed_profile_lifecycle(
                principal=principal,
                profile_id=profile_id,
                authority=authority,
                replay=replay,
            )
        current = self._repo.get_profile(
            principal=principal, profile_id=profile_id, authority=authority
        )
        expected_revision = _profile_etag_revision(
            profile_id=profile_id,
            value=if_match,
            current_etag=current.etag,
        )
        command = self._profile_command(
            principal=principal,
            operation=CreatorProfilePostgresOperation.PAUSE,
            profile_id=_uuid(profile_id),
            command_id=command_id,
            idempotency_key=idempotency_key,
            payload=payload,
            authority=authority,
            expected_version=expected_revision,
            reason_code=reason_code,
        )
        try:
            self._execute_profile(command, current=current)
        except EditorServiceError as error:
            recovered = self._recover_completed_profile_lifecycle(
                error=error,
                principal=principal,
                profile_id=profile_id,
                authority=authority,
                request=replay_request,
            )
            if recovered is not None:
                return recovered
            raise
        return self._repo.get_profile(
            principal=principal, profile_id=profile_id, authority=authority
        )

    def resume_profile(
        self,
        *,
        principal: EditorPrincipal,
        profile_id: str,
        if_match: str,
        idempotency_key: str,
    ) -> EditorResourceDto:
        self._require_role(principal, "CREATOR")
        payload = {"profile_id": profile_id, "if_match": if_match}
        command_id = self._command_id(
            principal, "RESUME_PROFILE", idempotency_key
        )
        authority = self._authorities.profile(
            principal=principal,
            operation=CreatorProfilePostgresOperation.RESUME,
            profile_id=profile_id,
        )
        replay_request = self._profile_lifecycle_replay_request(
            principal=principal,
            profile_id=profile_id,
            operation=CreatorProfilePostgresOperation.RESUME,
            command_id=command_id,
            idempotency_key=idempotency_key,
            if_match=if_match,
            payload=payload,
            authority=authority,
        )
        replay = self._read_completed_profile_lifecycle(replay_request)
        if replay is not None:
            return self._project_completed_profile_lifecycle(
                principal=principal,
                profile_id=profile_id,
                authority=authority,
                replay=replay,
            )
        current = self._repo.get_profile(
            principal=principal, profile_id=profile_id, authority=authority
        )
        expected_revision = _profile_etag_revision(
            profile_id=profile_id,
            value=if_match,
            current_etag=current.etag,
        )
        published = next(
            (item for item in current.versions if item.status == "PUBLISHED"),
            None,
        )
        if published is None:
            raise EditorServiceError(
                status=409, code="INVALID_STATE_TRANSITION"
            )
        hold = self._evidence.profile_hold(
            principal=principal,
            action="ResumeCreatorProfile",
            profile_id=_uuid(profile_id),
            profile_version_no=published.version_no,
            taxonomy_bundle_id=_uuid(published.taxonomy_bundle_id),
            prospective_aggregate_version=expected_revision + 1,
            content_sha256=bytes.fromhex(published.content_sha256),
            content=published.content,
            evaluated_at=self._now(),
        )
        command = self._profile_command(
            principal=principal,
            operation=CreatorProfilePostgresOperation.RESUME,
            profile_id=_uuid(profile_id),
            command_id=command_id,
            idempotency_key=idempotency_key,
            payload=payload,
            authority=authority,
            expected_version=expected_revision,
            hold=hold,
        )
        try:
            self._execute_profile(command, current=current)
        except EditorServiceError as error:
            recovered = self._recover_completed_profile_lifecycle(
                error=error,
                principal=principal,
                profile_id=profile_id,
                authority=authority,
                request=replay_request,
            )
            if recovered is not None:
                return recovered
            raise
        return self._repo.get_profile(
            principal=principal, profile_id=profile_id, authority=authority
        )

    def archive_profile(
        self,
        *,
        principal: EditorPrincipal,
        profile_id: str,
        if_match: str,
        reason_code: str,
        idempotency_key: str,
    ) -> EditorResourceDto:
        self._require_role(principal, "CREATOR")
        if reason_code not in {
            "OWNER_REQUEST",
            "ACCOUNT_CLOSURE",
            "SAFETY_REVIEW",
        }:
            raise EditorServiceError(
                status=422, code="INVALID_REASON_CODE", path="/reason_code"
            )
        payload = {
            "profile_id": profile_id,
            "if_match": if_match,
            "reason_code": reason_code,
        }
        command_id = self._command_id(
            principal, "ARCHIVE_PROFILE", idempotency_key
        )
        authority = self._authorities.profile(
            principal=principal,
            operation=CreatorProfilePostgresOperation.ARCHIVE,
            profile_id=profile_id,
        )
        replay_request = self._profile_lifecycle_replay_request(
            principal=principal,
            profile_id=profile_id,
            operation=CreatorProfilePostgresOperation.ARCHIVE,
            command_id=command_id,
            idempotency_key=idempotency_key,
            if_match=if_match,
            payload=payload,
            authority=authority,
        )
        replay = self._read_completed_profile_lifecycle(replay_request)
        if replay is not None:
            return self._project_completed_profile_lifecycle(
                principal=principal,
                profile_id=profile_id,
                authority=authority,
                replay=replay,
            )
        current = self._repo.get_profile(
            principal=principal, profile_id=profile_id, authority=authority
        )
        expected_revision = _profile_etag_revision(
            profile_id=profile_id,
            value=if_match,
            current_etag=current.etag,
        )
        command = self._profile_command(
            principal=principal,
            operation=CreatorProfilePostgresOperation.ARCHIVE,
            profile_id=_uuid(profile_id),
            command_id=command_id,
            idempotency_key=idempotency_key,
            payload=payload,
            authority=authority,
            expected_version=expected_revision,
            reason_code=reason_code,
        )
        try:
            self._execute_profile(command, current=current)
        except EditorServiceError as error:
            recovered = self._recover_completed_profile_lifecycle(
                error=error,
                principal=principal,
                profile_id=profile_id,
                authority=authority,
                request=replay_request,
            )
            if recovered is not None:
                return recovered
            raise
        return self._repo.get_profile(
            principal=principal, profile_id=profile_id, authority=authority
        )

    def create_demand(
        self,
        *,
        principal: EditorPrincipal,
        taxonomy_bundle_id: str,
        content: Mapping[str, Any],
        client_reference: str,
        expires_at: datetime,
        idempotency_key: str,
    ) -> EditorResourceDto:
        self._require_role(principal, "DEMAND_OWNER")
        if _utc(expires_at) <= self._now():
            raise EditorServiceError(
                status=422, code="INVALID_DATETIME", path="/expires_at"
            )
        payload = {
            "taxonomy_bundle_id": taxonomy_bundle_id,
            "content": content,
            "client_reference": client_reference,
            "expires_at": _utc(expires_at),
        }
        command_id = self._command_id(principal, "CREATE_DEMAND", idempotency_key)
        demand_id = self._scoped_id(command_id, "demand")
        version_id = self._scoped_id(command_id, "demand-version")
        authority = self._authorities.demand(
            principal=principal,
            operation=DemandPostgresOperation.CREATE,
            demand_id=str(demand_id),
        )
        frozen = _freeze_demand_content(content)
        canonical = canonical_demand_version_bytes(
            demand_id=str(demand_id),
            version_no=1,
            taxonomy_bundle_id=taxonomy_bundle_id,
            content=frozen,
        )
        command = self._demand_command(
            principal=principal,
            operation=DemandPostgresOperation.CREATE,
            demand_id=demand_id,
            command_id=command_id,
            idempotency_key=idempotency_key,
            payload=payload,
            authority=authority,
            expected_version=None,
            demand_version_id=version_id,
            taxonomy_bundle_id=_uuid(taxonomy_bundle_id),
            canonical_demand_version_bytes=canonical,
            content_sha256=hashlib.sha256(canonical).digest(),
            client_reference_digest_key_id=self._keys.demand_client_reference_key_id,
            client_reference_digest=_hmac(
                self._keys.demand_client_reference_key,
                client_reference.encode("utf-8"),
            ),
        )
        self._execute_demand(
            command,
            membership_validation=lambda: self._validate_editor_choices(
                "DEMAND", content
            ),
        )
        return self._repo.get_demand(
            principal=principal, demand_id=str(demand_id), authority=authority
        )

    def list_demands(
        self, *, principal: EditorPrincipal
    ) -> Tuple[EditorResourceDto, ...]:
        if not ({"DEMAND_OWNER", "OPERATIONS_REVIEWER"} & set(principal.role_codes)):
            self._not_found()
        return self._repo.list_demands(
            principal=principal,
            targets=self._authorities.demand_targets(principal=principal),
        )

    def list_review_queue(
        self, *, principal: EditorPrincipal
    ) -> Tuple[EditorReviewQueueItemDto, ...]:
        self._require_role(principal, "OPERATIONS_REVIEWER")
        if self._review_queue is None:
            raise EditorServiceError(status=503, code="SERVICE_UNAVAILABLE")
        try:
            return self._review_queue.list_available(principal=principal)
        except DemandReviewQueueError as error:
            self._review_queue_error(error.code)
        raise AssertionError("unreachable")

    def list_review_history(
        self,
        *,
        principal: EditorPrincipal,
        cursor: Optional[str],
        limit: int,
    ) -> EditorReviewHistoryPageDto:
        self._require_role(principal, "OPERATIONS_REVIEWER")
        if self._review_queue is None:
            raise EditorServiceError(status=503, code="SERVICE_UNAVAILABLE")
        if type(limit) is not int or not 1 <= limit <= 100:
            raise EditorServiceError(
                status=422,
                code="INVALID_PAGE_LIMIT",
                path="/query/limit",
            )
        cursor_reviewed_at: Optional[datetime] = None
        cursor_review_id: Optional[UUID] = None
        if cursor is not None:
            try:
                cursor_reviewed_at, cursor_review_id = _decode_review_history_cursor(
                    cursor=cursor,
                    actor_user_id=principal.user_id,
                    key=self._keys.demand_payload_key,
                )
            except (TypeError, ValueError):
                raise EditorServiceError(
                    status=422,
                    code="INVALID_CURSOR",
                    path="/query/cursor",
                ) from None
        try:
            rows = self._review_queue.list_history(
                principal=principal,
                maximum_items=limit,
                cursor_reviewed_at=cursor_reviewed_at,
                cursor_review_id=cursor_review_id,
            )
        except DemandReviewQueueError as error:
            self._review_queue_error(error.code)
        if not isinstance(rows, tuple) or len(rows) > limit + 1 or any(
            not isinstance(item, EditorReviewHistoryItemDto) for item in rows
        ):
            raise EditorServiceError(status=503, code="SERVICE_UNAVAILABLE")
        has_more = len(rows) > limit
        items = rows[:limit]
        next_cursor = (
            _encode_review_history_cursor(
                item=items[-1],
                actor_user_id=principal.user_id,
                key=self._keys.demand_payload_key,
            )
            if has_more and items
            else None
        )
        return EditorReviewHistoryPageDto(
            schema_version="demand-review-history-v1",
            items=items,
            next_cursor=next_cursor,
            has_more=has_more,
        )

    def claim_demand_review(
        self,
        *,
        principal: EditorPrincipal,
        demand_id: str,
        if_match: str,
        idempotency_key: str,
    ) -> EditorReviewClaimDto:
        self._require_role(principal, "OPERATIONS_REVIEWER")
        if self._review_queue is None:
            raise EditorServiceError(status=503, code="SERVICE_UNAVAILABLE")
        target_id = _uuid(demand_id)
        expected_revision = _review_queue_revision(if_match)
        command_id = self._command_id(
            principal, "CLAIM_DEMAND_REVIEW", idempotency_key
        )
        payload = {
            "demand_id": demand_id,
            "if_match": if_match,
        }
        request = DemandReviewClaimRequest(
            principal=principal,
            demand_id=target_id,
            expected_demand_revision=expected_revision,
            assignment_id=self._scoped_id(command_id, "review-assignment"),
            receipt_id=command_id,
            idempotency_key_digest_key_id=self._keys.demand_idempotency_key_id,
            idempotency_key_digest=_hmac(
                self._keys.demand_idempotency_key,
                idempotency_key.encode("utf-8"),
            ),
            payload_hash_key_id=self._keys.demand_payload_key_id,
            payload_hash=_hmac(
                self._keys.demand_payload_key,
                _canonical_payload("CLAIM_DEMAND_REVIEW", payload),
            ),
            audit_event_id=self._scoped_id(command_id, "audit"),
            outbox_event_id=self._scoped_id(command_id, "outbox"),
            correlation_id=self._scoped_id(command_id, "correlation"),
            causation_id=self._scoped_id(command_id, "causation"),
            trace_id=self._scoped_id(command_id, "trace"),
        )
        try:
            return self._review_queue.claim(request)
        except DemandReviewQueueCommitOutcomeUnknownError as error:
            raise EditorServiceError(
                status=503, code="COMMAND_OUTCOME_UNKNOWN"
            ) from error
        except DemandReviewQueueError as error:
            self._review_queue_error(error.code, etag=if_match)
        raise AssertionError("unreachable")

    def get_demand(
        self, *, principal: EditorPrincipal, demand_id: str
    ) -> EditorResourceDto:
        operation = (
            DemandPostgresOperation.CREATE_VERSION
            if "DEMAND_OWNER" in principal.role_codes
            else DemandPostgresOperation.REQUEST_CHANGES
        )
        authority = self._authorities.demand(
            principal=principal, operation=operation, demand_id=demand_id
        )
        return self._repo.get_demand(
            principal=principal, demand_id=demand_id, authority=authority
        )

    def save_demand_draft(
        self,
        *,
        principal: EditorPrincipal,
        demand_id: str,
        if_match: str,
        base_version_id: str,
        taxonomy_bundle_id: str,
        content: Mapping[str, Any],
        idempotency_key: str,
    ) -> EditorResourceDto:
        self._require_role(principal, "DEMAND_OWNER")
        authority = self._authorities.demand(
            principal=principal,
            operation=DemandPostgresOperation.CREATE_VERSION,
            demand_id=demand_id,
        )
        current = self._repo.get_demand(
            principal=principal, demand_id=demand_id, authority=authority
        )
        self._require_etag(
            current=current,
            if_match=if_match,
            base_version_id=base_version_id,
            yours=content,
        )
        if current.current_version is None or current.current_version.version_id != base_version_id:
            raise EditorServiceError(
                status=412,
                code="PRECONDITION_FAILED",
                path="/base_version_id",
                etag=current.etag,
            )
        frozen = _freeze_demand_content(content)
        next_version_no = max(
            (item.version_no for item in current.versions), default=0
        ) + 1
        canonical = canonical_demand_version_bytes(
            demand_id=demand_id,
            version_no=next_version_no,
            taxonomy_bundle_id=taxonomy_bundle_id,
            content=frozen,
        )
        payload = {
            "demand_id": demand_id,
            "if_match": if_match,
            "base_version_id": base_version_id,
            "taxonomy_bundle_id": taxonomy_bundle_id,
            "content": content,
        }
        command_id = self._command_id(principal, "SAVE_DEMAND", idempotency_key)
        command = self._demand_command(
            principal=principal,
            operation=DemandPostgresOperation.CREATE_VERSION,
            demand_id=_uuid(demand_id),
            command_id=command_id,
            idempotency_key=idempotency_key,
            payload=payload,
            authority=authority,
            expected_version=current.revision,
            demand_version_id=self._scoped_id(command_id, "demand-version"),
            based_on_demand_version_id=_uuid(base_version_id),
            taxonomy_bundle_id=_uuid(taxonomy_bundle_id),
            canonical_demand_version_bytes=canonical,
            content_sha256=hashlib.sha256(canonical).digest(),
        )
        self._execute_demand(
            command,
            current=current,
            membership_validation=lambda: self._validate_editor_choices(
                "DEMAND", content
            ),
        )
        return self._repo.get_demand(
            principal=principal, demand_id=demand_id, authority=authority
        )

    def submit_demand(
        self,
        *,
        principal: EditorPrincipal,
        demand_id: str,
        if_match: str,
        idempotency_key: str,
    ) -> EditorResourceDto:
        self._require_role(principal, "DEMAND_OWNER")
        authority = self._authorities.demand(
            principal=principal,
            operation=DemandPostgresOperation.SUBMIT,
            demand_id=demand_id,
        )
        current = self._repo.get_demand(
            principal=principal, demand_id=demand_id, authority=authority
        )
        if current.current_version is None:
            self._not_found()
        self._require_etag(
            current=current,
            if_match=if_match,
            base_version_id=current.current_version.version_id,
            yours=current.current_version.content,
        )
        now = self._now()
        target = _uuid(demand_id)
        version_id = _uuid(current.current_version.version_id)
        content_hash = bytes.fromhex(current.current_version.content_sha256)
        policy = self._evidence.demand_content_policy(
            principal=principal,
            demand_id=target,
            demand_version_id=version_id,
            demand_version_no=current.current_version.version_no,
            taxonomy_bundle_id=_uuid(
                current.current_version.taxonomy_bundle_id
            ),
            content_sha256=content_hash,
            content=current.current_version.content,
            evaluated_at=now,
            organization_id=authority.organization_id,
        )
        hold = self._evidence.demand_hold(
            principal=principal,
            demand_id=target,
            demand_version_id=version_id,
            prospective_aggregate_version=current.revision + 1,
            content_sha256=content_hash,
            action="SUBMIT_DEMAND",
            content_policy=policy,
            evaluated_at=now,
            organization_id=authority.organization_id,
        )
        rules = self._evidence.demand_rules(
            principal=principal,
            demand_id=target,
            taxonomy_bundle_id=_uuid(
                current.current_version.taxonomy_bundle_id
            ),
            operation="SUBMIT_DEMAND",
            evaluated_at=now,
        )
        payload = {"demand_id": demand_id, "if_match": if_match}
        command_id = self._command_id(principal, "SUBMIT_DEMAND", idempotency_key)
        command = self._demand_command(
            principal=principal,
            operation=DemandPostgresOperation.SUBMIT,
            demand_id=target,
            command_id=command_id,
            idempotency_key=idempotency_key,
            payload=payload,
            authority=authority,
            expected_version=current.revision,
            demand_version_id=version_id,
            submission_id=self._scoped_id(command_id, "demand-submission"),
            content_policy=policy,
            hold=hold,
            rule_requirement=rules,
        )
        self._execute_demand(
            command,
            current=current,
            membership_validation=lambda: self._validate_editor_choices(
                "DEMAND", current.current_version.content
            ),
        )
        return self._repo.get_demand(
            principal=principal, demand_id=demand_id, authority=authority
        )

    def cancel_demand(
        self,
        *,
        principal: EditorPrincipal,
        demand_id: str,
        if_match: str,
        reason_code: str,
        idempotency_key: str,
    ) -> EditorResourceDto:
        self._require_role(principal, "DEMAND_OWNER")
        try:
            reason = CancelReasonCode(reason_code)
        except (TypeError, ValueError):
            raise EditorServiceError(
                status=422, code="INVALID_REASON_CODE", path="/reason_code"
            ) from None
        if reason is CancelReasonCode.DEADLINE_REACHED:
            raise EditorServiceError(
                status=422, code="INVALID_REASON_CODE", path="/reason_code"
            )
        payload = {
            "demand_id": demand_id,
            "if_match": if_match,
            "reason_code": reason.value,
        }
        command_id = self._command_id(
            principal, "CANCEL_DEMAND", idempotency_key
        )
        authority = self._authorities.demand(
            principal=principal,
            operation=DemandPostgresOperation.CANCEL_OWNER,
            demand_id=demand_id,
        )
        current = self._repo.get_demand(
            principal=principal, demand_id=demand_id, authority=authority
        )
        expected_revision = _validated_demand_etag_revision(
            demand_id=demand_id,
            value=if_match,
            current_etag=current.etag,
        )
        command = self._demand_command(
            principal=principal,
            operation=DemandPostgresOperation.CANCEL_OWNER,
            demand_id=_uuid(demand_id),
            command_id=command_id,
            idempotency_key=idempotency_key,
            payload=payload,
            authority=authority,
            expected_version=expected_revision,
            cancel_reason_code=reason.value,
        )
        self._execute_demand(command, current=current)
        return self._repo.get_demand(
            principal=principal, demand_id=demand_id, authority=authority
        )

    def request_demand_changes(
        self,
        *,
        principal: EditorPrincipal,
        assignment_id: str,
        demand_id: str,
        if_match: str,
        reason_codes: Tuple[str, ...],
        required_field_codes: Tuple[str, ...] = (),
        required_field_paths: Tuple[str, ...] = (),
        idempotency_key: str,
    ) -> EditorResourceDto:
        self._require_role(principal, "OPERATIONS_REVIEWER")
        fields = required_field_paths or required_field_codes
        if not fields:
            raise EditorServiceError(
                status=422,
                code="INVALID_FIELD_PATH",
                path="/required_field_paths",
            )
        field_codes = tuple(
            self._field_codes.demand_field_code(value) for value in fields
        )
        authority = self._authorities.demand(
            principal=principal,
            operation=DemandPostgresOperation.REQUEST_CHANGES,
            demand_id=demand_id,
            assignment_id=assignment_id,
        )
        if authority.assignment_id != _uuid(assignment_id):
            self._not_found()
        current = self._repo.get_demand(
            principal=principal, demand_id=demand_id, authority=authority
        )
        if current.current_version is None:
            self._not_found()
        self._require_etag(
            current=current,
            if_match=if_match,
            base_version_id=current.current_version.version_id,
            yours=current.current_version.content,
        )
        payload = {
            "assignment_id": assignment_id,
            "demand_id": demand_id,
            "if_match": if_match,
            "reason_codes": reason_codes,
            "required_field_codes": field_codes,
        }
        command_id = self._command_id(principal, "REVIEW_FINDINGS", idempotency_key)
        command = self._demand_command(
            principal=principal,
            operation=DemandPostgresOperation.REQUEST_CHANGES,
            demand_id=_uuid(demand_id),
            command_id=command_id,
            idempotency_key=idempotency_key,
            payload=payload,
            authority=authority,
            expected_version=current.revision,
            demand_version_id=_uuid(current.current_version.version_id),
            assignment_id=_uuid(assignment_id),
            review_id=self._scoped_id(command_id, "demand-review"),
            reason_codes=tuple(reason_codes),
            required_field_codes=field_codes,
        )
        self._execute_demand(command, current=current)
        return self._repo.get_demand(
            principal=principal, demand_id=demand_id, authority=authority
        )

    def release_demand_review_assignment(
        self,
        *,
        principal: EditorPrincipal,
        assignment_id: str,
        demand_id: str,
        if_match: str,
        reason_code: str,
        idempotency_key: str,
    ) -> EditorResourceDto:
        """Return an active Demand review lease to the shared queue."""

        self._require_role(principal, "OPERATIONS_REVIEWER")
        if reason_code not in _REVIEW_ASSIGNMENT_RELEASE_REASON_CODES:
            raise EditorServiceError(
                status=422,
                code="INVALID_REASON_CODE",
                path="/reason_code",
            )
        target = _uuid(demand_id)
        assignment = _uuid(assignment_id)
        payload = {
            "assignment_id": assignment_id,
            "demand_id": demand_id,
            "if_match": if_match,
            "reason_code": reason_code,
        }
        command_id = self._command_id(
            principal,
            "RELEASE_DEMAND_REVIEW_ASSIGNMENT",
            idempotency_key,
        )
        replay_request = DemandCompletedReleaseReplayProbeRequest(
            actor_user_id=_uuid(principal.user_id),
            session_id=_uuid(principal.session_id),
            command_id=command_id,
            demand_id=target,
            assignment_id=assignment,
            expected_version=_demand_etag_revision(demand_id, if_match),
            idempotency_key=idempotency_key,
            canonical_payload=_canonical_payload(
                DemandPostgresOperation.RELEASE_REVIEW_ASSIGNMENT.value,
                payload,
            ),
        )
        replay = self._read_completed_release(replay_request)
        if replay is not None:
            return self._project_completed_release(
                principal=principal,
                demand_id=demand_id,
                assignment_id=assignment,
                replay=replay,
            )

        try:
            authority = self._authorities.demand(
                principal=principal,
                operation=DemandPostgresOperation.RELEASE_REVIEW_ASSIGNMENT,
                demand_id=demand_id,
                assignment_id=assignment_id,
            )
            if authority.assignment_id != assignment:
                self._not_found()
            current = self._repo.get_demand(
                principal=principal,
                demand_id=demand_id,
                authority=authority,
            )
            if (
                current.current_version is None
                or current.review_assignment is None
                or current.review_assignment.assignment_id != assignment_id
            ):
                self._not_found()
            expected_revision = _validated_demand_etag_revision(
                demand_id=demand_id,
                value=if_match,
                current_etag=current.etag,
            )
        except EditorServiceError as error:
            recovered = self._recover_completed_release(
                error=error,
                principal=principal,
                demand_id=demand_id,
                assignment_id=assignment,
                request=replay_request,
                statuses=frozenset((404, 412)),
            )
            if recovered is not None:
                return recovered
            raise

        command = self._demand_command(
            principal=principal,
            operation=DemandPostgresOperation.RELEASE_REVIEW_ASSIGNMENT,
            demand_id=target,
            command_id=command_id,
            idempotency_key=idempotency_key,
            payload=payload,
            authority=authority,
            expected_version=expected_revision,
            demand_version_id=_uuid(current.current_version.version_id),
            assignment_id=assignment,
            release_reason_code=reason_code,
        )
        try:
            self._execute_demand(command, current=current)
        except EditorServiceError as error:
            recovered = self._recover_completed_release(
                error=error,
                principal=principal,
                demand_id=demand_id,
                assignment_id=assignment,
                request=replay_request,
                statuses=frozenset((404, 412, 503)),
            )
            if recovered is not None:
                return recovered
            raise
        return self._repo.get_demand(
            principal=principal,
            demand_id=demand_id,
            authority=authority,
        )

    def verify_demand(
        self,
        *,
        principal: EditorPrincipal,
        assignment_id: str,
        demand_id: str,
        if_match: str,
        budget_health_code: str,
        risk_code: str,
        evidence_codes: Tuple[str, ...],
        idempotency_key: str,
    ) -> EditorResourceDto:
        self._require_role(principal, "OPERATIONS_REVIEWER")
        if budget_health_code not in _VERIFY_BUDGET_HEALTH_CODES:
            raise EditorServiceError(
                status=422,
                code="INVALID_BUDGET_HEALTH_CODE",
                path="/budget_health_code",
            )
        if risk_code not in _VERIFY_RISK_CODES:
            raise EditorServiceError(
                status=422, code="INVALID_RISK_CODE", path="/risk_code"
            )
        if (
            not isinstance(evidence_codes, tuple)
            or not evidence_codes
            or len(set(evidence_codes)) != len(evidence_codes)
            or not set(evidence_codes).issubset(_VERIFY_EVIDENCE_CODES)
        ):
            raise EditorServiceError(
                status=422,
                code="INVALID_EVIDENCE_CODE",
                path="/evidence_codes",
            )
        target = _uuid(demand_id)
        assignment = _uuid(assignment_id)
        canonical_evidence = tuple(
            sorted(evidence_codes, key=lambda value: value.encode("utf-8"))
        )
        payload = {
            "assignment_id": assignment_id,
            "budget_health_code": budget_health_code,
            "demand_id": demand_id,
            "evidence_codes": canonical_evidence,
            "if_match": if_match,
            "risk_code": risk_code,
        }
        command_id = self._command_id(
            principal, "VERIFY_DEMAND", idempotency_key
        )
        replay_request = DemandCompletedVerifyReplayProbeRequest(
            actor_user_id=_uuid(principal.user_id),
            session_id=_uuid(principal.session_id),
            command_id=command_id,
            demand_id=target,
            assignment_id=assignment,
            expected_version=_demand_etag_revision(demand_id, if_match),
            idempotency_key=idempotency_key,
            canonical_payload=_canonical_payload(
                DemandPostgresOperation.VERIFY.value,
                payload,
            ),
        )
        replay = self._read_completed_verify(replay_request)
        if replay is not None:
            return self._project_completed_verify(
                principal=principal,
                demand_id=demand_id,
                assignment_id=assignment,
                replay=replay,
            )

        try:
            authority = self._authorities.demand(
                principal=principal,
                operation=DemandPostgresOperation.VERIFY,
                demand_id=demand_id,
                assignment_id=assignment_id,
            )
            if authority.assignment_id != assignment:
                self._not_found()
            current = self._repo.get_demand(
                principal=principal, demand_id=demand_id, authority=authority
            )
            if current.current_version is None:
                self._not_found()
            self._require_etag(
                current=current,
                if_match=if_match,
                base_version_id=current.current_version.version_id,
                yours=current.current_version.content,
            )
        except EditorServiceError as error:
            recovered = self._recover_completed_verify(
                error=error,
                principal=principal,
                demand_id=demand_id,
                assignment_id=assignment,
                request=replay_request,
                statuses=frozenset((404, 412)),
            )
            if recovered is not None:
                return recovered
            raise

        now = self._now()
        version_id = _uuid(current.current_version.version_id)
        content_hash = bytes.fromhex(current.current_version.content_sha256)
        taxonomy_bundle_id = _uuid(current.current_version.taxonomy_bundle_id)
        policy = self._evidence.demand_content_policy(
            principal=principal,
            demand_id=target,
            demand_version_id=version_id,
            demand_version_no=current.current_version.version_no,
            taxonomy_bundle_id=taxonomy_bundle_id,
            content_sha256=content_hash,
            content=current.current_version.content,
            evaluated_at=now,
            organization_id=authority.organization_id,
        )
        hold = self._evidence.demand_hold(
            principal=principal,
            demand_id=target,
            demand_version_id=version_id,
            prospective_aggregate_version=current.revision + 1,
            content_sha256=content_hash,
            action="VERIFY_DEMAND",
            content_policy=policy,
            evaluated_at=now,
            organization_id=authority.organization_id,
        )
        rules = self._evidence.demand_rules(
            principal=principal,
            demand_id=target,
            taxonomy_bundle_id=taxonomy_bundle_id,
            operation="VERIFY_DEMAND",
            evaluated_at=now,
            organization_id=authority.organization_id,
        )
        command = self._demand_command(
            principal=principal,
            operation=DemandPostgresOperation.VERIFY,
            demand_id=target,
            command_id=command_id,
            idempotency_key=idempotency_key,
            payload=payload,
            authority=authority,
            expected_version=current.revision,
            demand_version_id=version_id,
            assignment_id=assignment,
            review_id=self._scoped_id(command_id, "demand-review"),
            budget_health_code=budget_health_code,
            risk_code=risk_code,
            evidence_summary_sha256=hashlib.sha256(
                json.dumps(
                    {"evidence_codes": canonical_evidence},
                    ensure_ascii=True,
                    separators=(",", ":"),
                    sort_keys=True,
                ).encode("ascii")
            ).digest(),
            hold=hold,
            rule_requirement=rules,
        )
        try:
            self._execute_demand(command, current=current)
        except EditorServiceError as error:
            recovered = self._recover_completed_verify(
                error=error,
                principal=principal,
                demand_id=demand_id,
                assignment_id=assignment,
                request=replay_request,
                statuses=frozenset((404, 412, 503)),
            )
            if recovered is not None:
                return recovered
            raise
        return self._repo.get_demand(
            principal=principal, demand_id=demand_id, authority=authority
        )

    def _profile_lifecycle_replay_request(
        self,
        *,
        principal: EditorPrincipal,
        profile_id: str,
        operation: CreatorProfilePostgresOperation,
        command_id: UUID,
        idempotency_key: str,
        if_match: str,
        payload: Mapping[str, Any],
        authority: ProfileReadAuthority,
    ) -> ProfileCompletedLifecycleReplayProbeRequest:
        if authority.operation is not operation:
            raise EditorServiceError(status=503, code="SERVICE_UNAVAILABLE")
        return ProfileCompletedLifecycleReplayProbeRequest(
            actor_user_id=_uuid(principal.user_id),
            session_id=_uuid(principal.session_id),
            command_id=command_id,
            profile_id=_uuid(profile_id),
            operation=operation,
            expected_version=_profile_replay_etag_revision(profile_id, if_match),
            expected_authority_marker_sha256=(
                authority.expected_authority_marker_sha256
            ),
            idempotency_key=idempotency_key,
            canonical_payload=_canonical_payload(operation.value, payload),
        )

    def _read_completed_profile_lifecycle(
        self,
        request: ProfileCompletedLifecycleReplayProbeRequest,
    ) -> Optional[ProfileCompletedLifecycleReplayResult]:
        if self._completed_profile_lifecycle_receipts is None:
            return None
        try:
            return self._completed_profile_lifecycle_receipts.read_completed(request)
        except ProfileCompletedLifecycleReplayError as error:
            if error.code == "IDEMPOTENCY_KEY_REUSED":
                raise EditorServiceError(
                    status=409, code="IDEMPOTENCY_KEY_REUSED"
                ) from None
            if error.code == "RESOURCE_NOT_FOUND":
                self._not_found()
            if error.code == "COMMAND_OUTCOME_UNKNOWN":
                raise EditorServiceError(
                    status=503, code="COMMAND_OUTCOME_UNKNOWN"
                ) from None
            raise EditorServiceError(status=503, code="SERVICE_UNAVAILABLE") from None

    def _recover_completed_profile_lifecycle(
        self,
        *,
        error: EditorServiceError,
        principal: EditorPrincipal,
        profile_id: str,
        authority: ProfileReadAuthority,
        request: ProfileCompletedLifecycleReplayProbeRequest,
    ) -> Optional[EditorResourceDto]:
        if error.status != 503 or error.code != "COMMAND_OUTCOME_UNKNOWN":
            return None
        replay = self._read_completed_profile_lifecycle(request)
        if replay is None:
            return None
        return self._project_completed_profile_lifecycle(
            principal=principal,
            profile_id=profile_id,
            authority=authority,
            replay=replay,
        )

    def _project_completed_profile_lifecycle(
        self,
        *,
        principal: EditorPrincipal,
        profile_id: str,
        authority: ProfileReadAuthority,
        replay: ProfileCompletedLifecycleReplayResult,
    ) -> EditorResourceDto:
        if (
            replay.operation is not authority.operation
            or str(replay.profile_id) != profile_id
        ):
            raise EditorServiceError(status=503, code="SERVICE_UNAVAILABLE")
        try:
            current = self._repo.get_profile(
                principal=principal,
                profile_id=profile_id,
                authority=authority,
            )
        except Exception:
            raise EditorServiceError(
                status=503, code="SERVICE_UNAVAILABLE"
            ) from None
        if not isinstance(current, EditorResourceDto):
            raise EditorServiceError(status=503, code="SERVICE_UNAVAILABLE")
        current_version_matches = (
            ()
            if current.current_version is None
            else tuple(
                version
                for version in current.versions
                if version.version_id == current.current_version.version_id
            )
        )
        current_version_is_exact = (
            current.current_version is not None
            and len(current_version_matches) == 1
            and current_version_matches[0] == current.current_version
        )
        if replay.operation is CreatorProfilePostgresOperation.ARCHIVE:
            lifecycle_projection_valid = (
                current.current_version is None
                and not current.capabilities
                and not current.editable_paths
                and all(
                    version.status in _ARCHIVED_PROFILE_VERSION_STATUSES
                    for version in current.versions
                )
            )
        elif replay.operation is CreatorProfilePostgresOperation.PAUSE:
            lifecycle_projection_valid = (
                current_version_is_exact
                and current.current_version.status == "PUBLISHED"
                and current.capabilities == ("RESUME", "ARCHIVE")
                and not current.editable_paths
            )
        else:
            expected_capabilities = (
                ("SAVE_DRAFT", "PUBLISH", "PAUSE", "ARCHIVE")
                if current.current_version is not None
                and current.current_version.status == "DRAFT"
                else ("SAVE_DRAFT", "PAUSE", "ARCHIVE")
            )
            lifecycle_projection_valid = (
                current_version_is_exact
                and current.current_version.status in {"DRAFT", "PUBLISHED"}
                and any(
                    version.status == "PUBLISHED"
                    for version in current.versions
                )
                and current.capabilities == expected_capabilities
                and current.editable_paths == _PROFILE_EDITABLE_PATHS
            )
        if (
            current.resource_type != "CREATOR_PROFILE"
            or current.object_id != profile_id
            or current.status != replay.status
            or current.revision != replay.aggregate_version
            or current.etag
            != _editor_profile_etag(profile_id, replay.aggregate_version)
            or not lifecycle_projection_valid
        ):
            raise EditorServiceError(status=503, code="SERVICE_UNAVAILABLE")
        return current

    def _read_completed_verify(
        self,
        request: DemandCompletedVerifyReplayProbeRequest,
    ) -> Optional[DemandCompletedVerifyReplayResult]:
        if self._completed_verify_receipts is None:
            return None
        try:
            return self._completed_verify_receipts.read_completed(request)
        except DemandCompletedVerifyReplayError as error:
            if error.code == "IDEMPOTENCY_KEY_REUSED":
                raise EditorServiceError(
                    status=409, code="IDEMPOTENCY_KEY_REUSED"
                ) from None
            if error.code == "RESOURCE_NOT_FOUND":
                self._not_found()
            if error.code == "COMMAND_OUTCOME_UNKNOWN":
                raise EditorServiceError(
                    status=503, code="COMMAND_OUTCOME_UNKNOWN"
                ) from None
            raise EditorServiceError(status=503, code="SERVICE_UNAVAILABLE") from None

    def _recover_completed_verify(
        self,
        *,
        error: EditorServiceError,
        principal: EditorPrincipal,
        demand_id: str,
        assignment_id: UUID,
        request: DemandCompletedVerifyReplayProbeRequest,
        statuses: frozenset[int],
    ) -> Optional[EditorResourceDto]:
        if error.status not in statuses or (
            error.status == 503 and error.code != "COMMAND_OUTCOME_UNKNOWN"
        ):
            return None
        replay = self._read_completed_verify(request)
        if replay is None:
            return None
        return self._project_completed_verify(
            principal=principal,
            demand_id=demand_id,
            assignment_id=assignment_id,
            replay=replay,
        )

    def _project_completed_verify(
        self,
        *,
        principal: EditorPrincipal,
        demand_id: str,
        assignment_id: UUID,
        replay: DemandCompletedVerifyReplayResult,
    ) -> EditorResourceDto:
        authority = DemandReadAuthority(
            DemandPostgresOperation.VERIFY,
            replay.authority_marker_sha256,
            assignment_id,
            replay.organization_id,
        )
        current = self._repo.get_demand(
            principal=principal,
            demand_id=demand_id,
            authority=authority,
        )
        matching_findings = tuple(
            finding
            for finding in current.findings
            if finding.assignment_id == str(assignment_id)
        )
        if (
            current.resource_type != "DEMAND"
            or current.object_id != demand_id
            or current.status != "VERIFIED"
            or current.revision != replay.aggregate_version
            or current.etag
            != _editor_demand_etag(demand_id, replay.aggregate_version)
            or current.current_version is None
            or current.current_version.version_id != str(replay.demand_version_id)
            or current.review_assignment is not None
            or current.capabilities
            or len(matching_findings) != 1
            or matching_findings[0].result != "VERIFIED"
            or matching_findings[0].version_id != str(replay.demand_version_id)
        ):
            raise EditorServiceError(status=503, code="SERVICE_UNAVAILABLE")
        return current

    def _read_completed_release(
        self,
        request: DemandCompletedReleaseReplayProbeRequest,
    ) -> Optional[DemandCompletedReleaseReplayResult]:
        if self._completed_verify_receipts is None:
            return None
        try:
            return self._completed_verify_receipts.read_completed_release(request)
        except DemandCompletedReleaseReplayError as error:
            if error.code == "IDEMPOTENCY_KEY_REUSED":
                raise EditorServiceError(
                    status=409,
                    code="IDEMPOTENCY_KEY_REUSED",
                ) from None
            if error.code == "RESOURCE_NOT_FOUND":
                self._not_found()
            if error.code == "COMMAND_OUTCOME_UNKNOWN":
                raise EditorServiceError(
                    status=503,
                    code="COMMAND_OUTCOME_UNKNOWN",
                ) from None
            raise EditorServiceError(
                status=503,
                code="SERVICE_UNAVAILABLE",
            ) from None

    def _recover_completed_release(
        self,
        *,
        error: EditorServiceError,
        principal: EditorPrincipal,
        demand_id: str,
        assignment_id: UUID,
        request: DemandCompletedReleaseReplayProbeRequest,
        statuses: frozenset[int],
    ) -> Optional[EditorResourceDto]:
        if error.status not in statuses or (
            error.status == 503 and error.code != "COMMAND_OUTCOME_UNKNOWN"
        ):
            return None
        replay = self._read_completed_release(request)
        if replay is None:
            return None
        return self._project_completed_release(
            principal=principal,
            demand_id=demand_id,
            assignment_id=assignment_id,
            replay=replay,
        )

    def _project_completed_release(
        self,
        *,
        principal: EditorPrincipal,
        demand_id: str,
        assignment_id: UUID,
        replay: DemandCompletedReleaseReplayResult,
    ) -> EditorResourceDto:
        authority = DemandReadAuthority(
            DemandPostgresOperation.RELEASE_REVIEW_ASSIGNMENT,
            replay.authority_marker_sha256,
            assignment_id,
            replay.organization_id,
        )
        current = self._repo.get_demand(
            principal=principal,
            demand_id=demand_id,
            authority=authority,
        )
        if (
            current.resource_type != "DEMAND"
            or current.object_id != demand_id
            or current.status != "SUBMITTED"
            or current.revision != replay.aggregate_version
            or current.etag
            != _editor_demand_etag(demand_id, replay.aggregate_version)
            or current.current_version is None
            or current.current_version.version_id
            != str(replay.demand_version_id)
            or current.review_assignment is not None
            or current.capabilities
        ):
            raise EditorServiceError(status=503, code="SERVICE_UNAVAILABLE")
        return current

    def _profile_command(
        self,
        *,
        principal: EditorPrincipal,
        operation: CreatorProfilePostgresOperation,
        profile_id: UUID,
        command_id: UUID,
        idempotency_key: str,
        payload: Mapping[str, Any],
        authority: ProfileReadAuthority,
        expected_version: Optional[int],
        profile_version_id: Optional[UUID] = None,
        based_on_profile_version_id: Optional[UUID] = None,
        taxonomy_bundle_id: Optional[UUID] = None,
        canonical_profile_version_bytes: Optional[bytes] = None,
        content_sha256: Optional[bytes] = None,
        confirmed: Optional[bool] = None,
        reason_code: Optional[str] = None,
        hold: Optional[CreatorProfilePostgresHoldEvidence] = None,
    ) -> CreatorProfilePostgresCommand:
        actor_id = _uuid(principal.user_id)
        now = self._now()
        event_required = operation is not CreatorProfilePostgresOperation.SAVE_DRAFT
        scope = CreatorProfilePostgresExecutionScope(
            actor_user_id=actor_id,
            session_id=_uuid(principal.session_id),
            profile_id=profile_id,
            command_id=command_id,
            audit_event_id=self._scoped_id(command_id, "audit"),
            outbox_event_id=(
                self._scoped_id(command_id, "outbox") if event_required else None
            ),
            correlation_id=self._scoped_id(command_id, "correlation"),
            causation_id=self._scoped_id(command_id, "causation"),
            trace_id=self._scoped_id(command_id, "trace"),
            original_actor_id=None,
            expected_authority_marker_sha256=(
                authority.expected_authority_marker_sha256
            ),
        )
        receipt = CreatorProfilePostgresReceiptMaterial(
            receipt_id=command_id,
            principal_id=actor_id,
            idempotency_key_digest_key_id=self._keys.profile_idempotency_key_id,
            idempotency_key_digest=_hmac(
                self._keys.profile_idempotency_key,
                idempotency_key.encode("utf-8"),
            ),
            payload_hash_key_id=self._keys.profile_payload_key_id,
            canonicalization_version="profile-command-json-v1",
            payload_hash=_hmac(
                self._keys.profile_payload_key,
                _canonical_payload(operation.value, payload),
            ),
            retain_until=now + timedelta(days=7),
        )
        return CreatorProfilePostgresCommand(
            operation=operation,
            scope=scope,
            receipt=receipt,
            expected_aggregate_version=expected_version,
            profile_version_id=profile_version_id,
            based_on_profile_version_id=based_on_profile_version_id,
            taxonomy_bundle_id=taxonomy_bundle_id,
            canonical_profile_version_bytes=canonical_profile_version_bytes,
            content_sha256=content_sha256,
            confirmed=confirmed,
            reason_code=reason_code,
            hold=hold,
        )

    def _demand_command(
        self,
        *,
        principal: EditorPrincipal,
        operation: DemandPostgresOperation,
        demand_id: UUID,
        command_id: UUID,
        idempotency_key: str,
        payload: Mapping[str, Any],
        authority: DemandReadAuthority,
        expected_version: Optional[int],
        demand_version_id: Optional[UUID] = None,
        based_on_demand_version_id: Optional[UUID] = None,
        taxonomy_bundle_id: Optional[UUID] = None,
        canonical_demand_version_bytes: Optional[bytes] = None,
        content_sha256: Optional[bytes] = None,
        client_reference_digest_key_id: Optional[str] = None,
        client_reference_digest: Optional[bytes] = None,
        submission_id: Optional[UUID] = None,
        assignment_id: Optional[UUID] = None,
        review_id: Optional[UUID] = None,
        reason_codes: Tuple[str, ...] = (),
        required_field_codes: Tuple[str, ...] = (),
        budget_health_code: Optional[str] = None,
        risk_code: Optional[str] = None,
        evidence_summary_sha256: Optional[bytes] = None,
        cancel_reason_code: Optional[str] = None,
        release_reason_code: Optional[str] = None,
        content_policy: Optional[DemandPostgresContentPolicyEvidence] = None,
        hold: Optional[DemandPostgresHoldEvidence] = None,
        rule_requirement: Optional[DemandPostgresRuleRequirement] = None,
    ) -> DemandPostgresCommand:
        actor_id = _uuid(principal.user_id)
        if authority.operation is not operation:
            raise ValueError("Demand command authority operation mismatch")
        if authority.organization_id is not None:
            organization_id = authority.organization_id
        else:
            organization_id = _uuid(principal.organization_id)
        outbox_count = 2 if operation is DemandPostgresOperation.CREATE else 1
        scope = DemandPostgresExecutionScope(
            actor_kind="USER",
            actor_id=actor_id,
            session_id=_uuid(principal.session_id),
            organization_id=organization_id,
            demand_id=demand_id,
            command_id=command_id,
            audit_event_id=self._scoped_id(command_id, "audit"),
            outbox_event_ids=tuple(
                self._scoped_id(command_id, f"outbox-{index}")
                for index in range(outbox_count)
            ),
            correlation_id=self._scoped_id(command_id, "correlation"),
            causation_id=self._scoped_id(command_id, "causation"),
            trace_id=self._scoped_id(command_id, "trace"),
            original_actor_id=None,
            expected_authority_marker_sha256=(
                authority.expected_authority_marker_sha256
            ),
        )
        receipt = DemandPostgresReceiptMaterial(
            receipt_id=command_id,
            principal_kind="USER",
            principal_id=actor_id,
            organization_id=organization_id,
            command_name=_DEMAND_COMMAND_NAME[operation],
            command_version=1,
            idempotency_key_digest_key_id=self._keys.demand_idempotency_key_id,
            idempotency_key_digest=_hmac(
                self._keys.demand_idempotency_key,
                idempotency_key.encode("utf-8"),
            ),
            payload_hash_key_id=self._keys.demand_payload_key_id,
            canonicalization_version="demand-command-json-v1",
            payload_hash=_hmac(
                self._keys.demand_payload_key,
                _canonical_payload(operation.value, payload),
            ),
            http_method="POST",
            canonical_path=_demand_path(
                operation=operation,
                organization_id=organization_id,
                demand_id=demand_id,
                assignment_id=assignment_id,
            ),
            if_match_version=(
                None if operation is DemandPostgresOperation.CREATE else expected_version
            ),
            retain_until=self._now() + timedelta(days=7),
        )
        return DemandPostgresCommand(
            operation=operation,
            scope=scope,
            receipt=receipt,
            expected_aggregate_version=expected_version,
            demand_version_id=demand_version_id,
            based_on_demand_version_id=based_on_demand_version_id,
            taxonomy_bundle_id=taxonomy_bundle_id,
            canonical_demand_version_bytes=canonical_demand_version_bytes,
            content_sha256=content_sha256,
            client_reference_digest_key_id=client_reference_digest_key_id,
            client_reference_digest=client_reference_digest,
            submission_id=submission_id,
            assignment_id=assignment_id,
            review_id=review_id,
            reason_codes=reason_codes,
            required_field_codes=required_field_codes,
            budget_health_code=budget_health_code,
            risk_code=risk_code,
            evidence_summary_sha256=evidence_summary_sha256,
            cancel_reason_code=cancel_reason_code,
            release_reason_code=release_reason_code,
            content_policy=content_policy,
            hold=hold,
            rule_requirement=rule_requirement,
        )

    def _execute_profile(
        self,
        command: CreatorProfilePostgresCommand,
        *,
        current: Optional[EditorResourceDto] = None,
        membership_validation: Optional[Callable[[], None]] = None,
    ) -> None:
        try:
            validated = getattr(
                self._repo, "execute_profile_validated", None
            )
            if membership_validation is not None and callable(validated):
                validated(command, membership_validation)
            else:
                if membership_validation is not None:
                    membership_validation()
                self._repo.execute_profile(command)
        except CreatorProfilePostgresDatabaseError as error:
            self._database_error(error.code, current=current)
        except CreatorProfilePostgresCommitOutcomeUnknownError as error:
            raise EditorServiceError(
                status=503, code="COMMAND_OUTCOME_UNKNOWN"
            ) from error
        except (CreatorProfilePostgresConfigurationError, EditorPostgresConfigurationError) as error:
            raise EditorServiceError(status=503, code="SERVICE_UNAVAILABLE") from error

    def _execute_demand(
        self,
        command: DemandPostgresCommand,
        *,
        current: Optional[EditorResourceDto] = None,
        membership_validation: Optional[Callable[[], None]] = None,
    ) -> None:
        try:
            validated = getattr(
                self._repo, "execute_demand_validated", None
            )
            if membership_validation is not None and callable(validated):
                validated(command, membership_validation)
            else:
                if membership_validation is not None:
                    membership_validation()
                self._repo.execute_demand(command)
        except DemandPostgresDatabaseError as error:
            self._database_error(error.code, current=current)
        except DemandPostgresCommitOutcomeUnknownError as error:
            raise EditorServiceError(
                status=503, code="COMMAND_OUTCOME_UNKNOWN"
            ) from error
        except (DemandPostgresConfigurationError, EditorPostgresConfigurationError) as error:
            raise EditorServiceError(status=503, code="SERVICE_UNAVAILABLE") from error

    def _validate_editor_choices(
        self, resource_type: str, content: Mapping[str, Any]
    ) -> None:
        validate_editor_choice_membership(
            resource_type=resource_type,
            content=content,
            choices=self._editor_choices,
        )

    @staticmethod
    def _database_error(
        code: str, *, current: Optional[EditorResourceDto]
    ) -> None:
        if code == "RESOURCE_NOT_FOUND":
            PostgresEditorService._not_found()
        if code == "PRECONDITION_FAILED":
            raise EditorServiceError(
                status=412,
                code=code,
                etag=None if current is None else current.etag,
            )
        if code in {
            "IDEMPOTENCY_KEY_REUSED",
            "PROFILE_ALREADY_EXISTS",
            "DEMAND_ALREADY_EXISTS",
            "INVALID_STATE_TRANSITION",
        }:
            raise EditorServiceError(status=409, code=code)
        if "VALIDATION" in code:
            raise EditorServiceError(status=422, code=code, path="/content")
        raise EditorServiceError(status=503, code="SERVICE_UNAVAILABLE")

    @staticmethod
    def _review_queue_error(code: str, *, etag: Optional[str] = None) -> None:
        if code == "RESOURCE_NOT_FOUND":
            PostgresEditorService._not_found()
        if code == "PRECONDITION_FAILED":
            raise EditorServiceError(status=412, code=code, etag=etag)
        if code in {"IDEMPOTENCY_KEY_REUSED", "REVIEW_ALREADY_CLAIMED"}:
            raise EditorServiceError(status=409, code=code)
        if code == "COMMAND_OUTCOME_UNKNOWN":
            raise EditorServiceError(status=503, code=code)
        raise EditorServiceError(status=503, code="SERVICE_UNAVAILABLE")

    @staticmethod
    def _require_etag(
        *,
        current: EditorResourceDto,
        if_match: str,
        base_version_id: Optional[str],
        yours: Mapping[str, Any],
    ) -> None:
        if hmac.compare_digest(current.etag, if_match):
            return
        base = next(
            (
                {"version_id": item.version_id, "content": item.content}
                for item in current.versions
                if item.version_id == base_version_id
            ),
            {"version_id": base_version_id, "content": {}},
        )
        latest = (
            {
                "version_id": current.current_version.version_id,
                "content": current.current_version.content,
            }
            if current.current_version is not None
            else {"version_id": None, "content": {}}
        )
        raise EditorServiceError(
            status=412,
            code="PRECONDITION_FAILED",
            details={
                "current": latest,
                "base": base,
                "yours": {"version_id": base_version_id, "content": dict(yours)},
            },
            etag=current.etag,
        )

    def _command_id(
        self,
        principal: EditorPrincipal,
        operation: str,
        idempotency_key: str,
    ) -> UUID:
        _require_idempotency_key(idempotency_key)
        return _keyed_uuid(
            self._keys.id_key,
            "command",
            principal.user_id,
            operation,
            idempotency_key,
        )

    def _scoped_id(self, command_id: UUID, label: str) -> UUID:
        return _keyed_uuid(self._keys.id_key, str(command_id), label)

    def _now(self) -> datetime:
        return _utc(self._clock.now())

    @staticmethod
    def _require_role(principal: EditorPrincipal, role: str) -> None:
        if role not in principal.role_codes:
            PostgresEditorService._not_found()

    @staticmethod
    def _not_found() -> None:
        raise EditorServiceError(status=404, code="RESOURCE_NOT_FOUND")


_KEY_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_PROFILE_ETAG = re.compile(
    r'"creator_profile-([1-9][0-9]*)-([0-9a-f]{24})"\Z'
)
_DEMAND_ETAG = re.compile(r'"demand-([1-9][0-9]*)-([0-9a-f]{24})"\Z')

_DEMAND_COMMAND_NAME = {
    DemandPostgresOperation.CREATE: "CreateDemand",
    DemandPostgresOperation.CREATE_VERSION: "CreateDemandVersion",
    DemandPostgresOperation.SUBMIT: "SubmitDemand",
    DemandPostgresOperation.REQUEST_CHANGES: "RequestDemandChanges",
    DemandPostgresOperation.VERIFY: "VerifyDemand",
    DemandPostgresOperation.RELEASE_REVIEW_ASSIGNMENT: (
        "ReleaseDemandReviewAssignment"
    ),
    DemandPostgresOperation.CANCEL_OWNER: "CancelDemand",
}

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
_ARCHIVED_PROFILE_VERSION_STATUSES = frozenset(
    ("DISCARDED", "SUPERSEDED", "RETIRED")
)
_REVIEW_HISTORY_CURSOR = re.compile(
    r"[A-Za-z0-9_-]{64,1024}\.[A-Za-z0-9_-]{43}\Z"
)
_REVIEW_HISTORY_CURSOR_DOMAIN = b"desire:demand-review-history-cursor:v1\x00"


def _demand_path(
    *,
    operation: DemandPostgresOperation,
    organization_id: UUID,
    demand_id: UUID,
    assignment_id: Optional[UUID],
) -> str:
    if operation is DemandPostgresOperation.CREATE:
        return f"/v1/organizations/{organization_id}/demands"
    if operation is DemandPostgresOperation.CREATE_VERSION:
        return f"/v1/organizations/{organization_id}/demands/{demand_id}/versions"
    if operation is DemandPostgresOperation.SUBMIT:
        return f"/v1/organizations/{organization_id}/demands/{demand_id}/submit"
    if operation is DemandPostgresOperation.REQUEST_CHANGES:
        return (
            "/v1/operations/demand-review-assignments/"
            f"{assignment_id}/request-changes"
        )
    if operation is DemandPostgresOperation.VERIFY:
        return f"/v1/operations/demand-review-assignments/{assignment_id}/verify"
    if operation is DemandPostgresOperation.RELEASE_REVIEW_ASSIGNMENT:
        return f"/v1/operations/demand-review-assignments/{assignment_id}/release"
    if operation is DemandPostgresOperation.CANCEL_OWNER:
        return f"/v1/organizations/{organization_id}/demands/{demand_id}/cancel"
    raise ValueError("editor Demand operation has no receipt path")


def _validated_demand_etag_revision(
    *, demand_id: str, value: str, current_etag: str
) -> int:
    match = _DEMAND_ETAG.fullmatch(value) if isinstance(value, str) else None
    if match is not None:
        revision = int(match.group(1))
        expected = hashlib.sha256(
            f"DEMAND:{demand_id}:{revision}".encode("utf-8")
        ).hexdigest()[:24]
        if hmac.compare_digest(expected, match.group(2)):
            return revision
    raise EditorServiceError(
        status=412,
        code="PRECONDITION_FAILED",
        etag=current_etag,
    )


def _canonical_payload(operation: str, payload: Mapping[str, Any]) -> bytes:
    return json.dumps(
        {"operation": operation, "payload": payload},
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
        default=_json_default,
    ).encode("utf-8")


def _demand_etag_revision(demand_id: str, value: str) -> int:
    match = _DEMAND_ETAG.fullmatch(value) if isinstance(value, str) else None
    if match is not None:
        revision = int(match.group(1))
        expected = hashlib.sha256(
            f"DEMAND:{demand_id}:{revision}".encode("utf-8")
        ).hexdigest()[:24]
        if hmac.compare_digest(expected, match.group(2)):
            return revision
    # A mismatched replay is still probed so an existing same-key receipt is
    # handled as a payload conflict.  A true MISS follows the legacy OCC path.
    return 1


def _profile_etag_revision(
    *, profile_id: str, value: str, current_etag: str
) -> int:
    revision = _valid_profile_etag_revision(profile_id, value)
    if revision is not None:
        return revision
    raise EditorServiceError(
        status=412,
        code="PRECONDITION_FAILED",
        etag=current_etag,
    )


def _profile_replay_etag_revision(profile_id: str, value: str) -> int:
    revision = _valid_profile_etag_revision(profile_id, value)
    # A malformed changed payload must still reach a same-key receipt and be
    # classified as a 409. A true MISS follows the normal OCC parser below.
    return 1 if revision is None else revision


def _valid_profile_etag_revision(profile_id: str, value: str) -> Optional[int]:
    match = _PROFILE_ETAG.fullmatch(value) if isinstance(value, str) else None
    if match is not None:
        revision = int(match.group(1))
        expected = hashlib.sha256(
            f"CREATOR_PROFILE:{profile_id}:{revision}".encode("utf-8")
        ).hexdigest()[:24]
        if hmac.compare_digest(expected, match.group(2)):
            return revision
    return None


def _editor_profile_etag(profile_id: str, revision: int) -> str:
    digest = hashlib.sha256(
        f"CREATOR_PROFILE:{profile_id}:{revision}".encode("utf-8")
    ).hexdigest()[:24]
    return f'"creator_profile-{revision}-{digest}"'


def _editor_demand_etag(demand_id: str, revision: int) -> str:
    digest = hashlib.sha256(
        f"DEMAND:{demand_id}:{revision}".encode("utf-8")
    ).hexdigest()[:24]
    return f'"demand-{revision}-{digest}"'


def _json_default(value: Any) -> str:
    if isinstance(value, datetime):
        return _utc(value).isoformat()
    raise TypeError("unsupported editor receipt value")


def _hmac(key: Union[bytes, bytearray], material: bytes) -> bytes:
    return hmac.new(key, material, hashlib.sha256).digest()


def _keyed_uuid(key: Union[bytes, bytearray], *parts: str) -> UUID:
    material = "\x1f".join(parts).encode("utf-8")
    raw = bytearray(_hmac(key, material)[:16])
    raw[6] = (raw[6] & 0x0F) | 0x40
    raw[8] = (raw[8] & 0x3F) | 0x80
    return UUID(bytes=bytes(raw))


def _require_idempotency_key(value: str) -> None:
    if (
        not isinstance(value, str)
        or not 8 <= len(value) <= 200
        or any(ord(character) < 0x21 or ord(character) > 0x7E for character in value)
    ):
        raise EditorServiceError(
            status=422,
            code="INVALID_IDEMPOTENCY_KEY",
            path="/headers/Idempotency-Key",
        )


def _review_queue_revision(value: str) -> int:
    if not isinstance(value, str):
        raise EditorServiceError(status=412, code="PRECONDITION_FAILED")
    match = re.fullmatch(r'"demand-([1-9][0-9]*)-review-queue"', value)
    if match is None:
        raise EditorServiceError(status=412, code="PRECONDITION_FAILED")
    revision = int(match.group(1))
    if revision > 2_147_483_647:
        raise EditorServiceError(status=412, code="PRECONDITION_FAILED")
    return revision


def _encode_review_history_cursor(
    *,
    item: EditorReviewHistoryItemDto,
    actor_user_id: str,
    key: Union[bytes, bytearray],
) -> str:
    actor = _cursor_uuid(actor_user_id)
    payload = json.dumps(
        {
            "review_id": item.review_id,
            "reviewed_at": _cursor_timestamp(item.reviewed_at),
            "version": 1,
        },
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    signature = _hmac(
        key,
        _REVIEW_HISTORY_CURSOR_DOMAIN + actor.bytes + b"\x00" + payload,
    )
    return f"{_base64url(payload)}.{_base64url(signature)}"


def _decode_review_history_cursor(
    *,
    cursor: str,
    actor_user_id: str,
    key: Union[bytes, bytearray],
) -> Tuple[datetime, UUID]:
    if not isinstance(cursor, str) or _REVIEW_HISTORY_CURSOR.fullmatch(cursor) is None:
        raise ValueError("Demand review history cursor is invalid")
    encoded_payload, encoded_signature = cursor.split(".")
    payload = _unbase64url(encoded_payload)
    signature = _unbase64url(encoded_signature)
    actor = _cursor_uuid(actor_user_id)
    if len(signature) != 32 or not hmac.compare_digest(
        signature,
        _hmac(
            key,
            _REVIEW_HISTORY_CURSOR_DOMAIN + actor.bytes + b"\x00" + payload,
        ),
    ):
        raise ValueError("Demand review history cursor is invalid")
    try:
        value = json.loads(payload.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ValueError("Demand review history cursor is invalid") from None
    if (
        not isinstance(value, dict)
        or tuple(sorted(value)) != ("review_id", "reviewed_at", "version")
        or value.get("version") != 1
        or isinstance(value.get("version"), bool)
    ):
        raise ValueError("Demand review history cursor is invalid")
    canonical = json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    if not hmac.compare_digest(payload, canonical):
        raise ValueError("Demand review history cursor is invalid")
    review_id = _cursor_uuid(value.get("review_id"))
    timestamp = value.get("reviewed_at")
    if not isinstance(timestamp, str) or not timestamp.endswith("Z"):
        raise ValueError("Demand review history cursor is invalid")
    try:
        reviewed_at = datetime.fromisoformat(timestamp[:-1] + "+00:00")
    except ValueError:
        raise ValueError("Demand review history cursor is invalid") from None
    if _cursor_timestamp(reviewed_at) != timestamp:
        raise ValueError("Demand review history cursor is invalid")
    return reviewed_at, review_id


def _cursor_timestamp(value: datetime) -> str:
    return _utc(value).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _cursor_uuid(value: Any) -> UUID:
    try:
        result = UUID(value)
    except (AttributeError, TypeError, ValueError):
        raise ValueError("Demand review history cursor is invalid") from None
    if result.int == 0 or str(result) != value:
        raise ValueError("Demand review history cursor is invalid")
    return result


def _base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _unbase64url(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    try:
        decoded = base64.b64decode(
            value + padding,
            altchars=b"-_",
            validate=True,
        )
    except (ValueError, TypeError):
        raise ValueError("Demand review history cursor is invalid") from None
    if _base64url(decoded) != value:
        raise ValueError("Demand review history cursor is invalid")
    return decoded


def _uuid(value: str) -> UUID:
    try:
        parsed = UUID(value)
    except (AttributeError, TypeError, ValueError) as error:
        raise EditorServiceError(status=404, code="RESOURCE_NOT_FOUND") from error
    if parsed.int == 0:
        raise EditorServiceError(status=404, code="RESOURCE_NOT_FOUND")
    return parsed


def _utc(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise EditorServiceError(status=422, code="INVALID_DATETIME")
    return value.astimezone(timezone.utc)


def _freeze_demand_content(value: Mapping[str, Any]) -> DemandContent:
    try:
        frozen = _freeze_demand_json(value)
    except (TypeError, ValueError) as error:
        raise EditorServiceError(
            status=422, code="DEMAND_VALIDATION_FAILED", path="/content"
        ) from error
    if not isinstance(frozen, DemandContent):
        raise EditorServiceError(
            status=422, code="DEMAND_VALIDATION_FAILED", path="/content"
        )
    return frozen


def _freeze_demand_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        return DemandContent(
            tuple(
                (str(key), _freeze_demand_json(child))
                for key, child in value.items()
            )
        )
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_demand_json(child) for child in value)
    if value is None or isinstance(value, (bool, int, str)):
        return value
    raise TypeError("Demand content is not JSON")
