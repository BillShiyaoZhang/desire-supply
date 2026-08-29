"""Profile and Demand editable-workspace composition over existing domains."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import hmac
import json
from typing import Any, Mapping, Optional, Sequence, Tuple

from ...creator_profile.domain import (
    ArchiveReasonCode,
    CreatorProfile,
    CreatorProfileDomainError,
    CreatorProfileStatus,
    PauseReasonCode,
    ProfileContent,
    ProfileVersion,
    ProfileVersionStatus,
    freeze_profile_content,
)
from ...demand.domain import (
    CancelReasonCode,
    Demand,
    DemandContent,
    DemandDomainError,
    DemandReviewAssignment,
    DemandStatus,
    ReviewAssignmentStatus,
)
from .contracts import (
    EditorConfigurationDto,
    EditorFindingDto,
    EditorPrincipal,
    EditorReviewAssignmentDto,
    EditorResourceDto,
    EditorServiceError,
    EditorSubmissionDto,
    EditorVersionDto,
)
from .content_choices import (
    internal_sandbox_editor_choices,
    validate_editor_choice_membership,
)


_PROFILE_EDITABLE_PATHS = (
    "/interests",
    "/skills",
    "/availability",
    "/collaboration",
    "/compensation",
    "/boundaries",
    "/location",
    "/conflicts",
    "/ai",
)
_DEMAND_EDITABLE_PATHS = (
    "/problem",
    "/scope",
    "/acceptance",
    "/skills",
    "/matching",
    "/schedule",
    "/budget",
    "/milestone_plan",
    "/risk",
    "/ai",
    "/collaboration",
    "/location",
    "/declarations",
)


class EditorService:
    """Closed application API for an authenticated internal pilot.

    The repository lock makes each Memory write and its receipt atomic within
    one process.  Production composition must replace it with PostgreSQL row
    locks, transactions, RLS, audit and durable receipts.
    """

    def __init__(
        self,
        *,
        repository: Any,
        clock: Any,
        id_source: Any,
        client_reference_key: bytes,
        configuration: Optional[EditorConfigurationDto] = None,
    ) -> None:
        if not isinstance(client_reference_key, bytes) or len(client_reference_key) < 16:
            raise ValueError("client_reference_key must contain at least 16 bytes")
        self._repo = repository
        self._clock = clock
        self._ids = id_source
        self._client_reference_key = client_reference_key
        if configuration is not None and not isinstance(
            configuration, EditorConfigurationDto
        ):
            raise TypeError("editor configuration is invalid")
        self._configuration = configuration
        self._editor_choices = (
            configuration.editor_choices
            if configuration is not None
            else internal_sandbox_editor_choices()
        )

    def get_configuration(
        self, *, principal: EditorPrincipal
    ) -> EditorConfigurationDto:
        if not ({"CREATOR", "DEMAND_OWNER"} & set(principal.role_codes)):
            self._not_found()
        if self._configuration is None:
            raise EditorServiceError(
                status=503, code="EDITOR_CONFIGURATION_UNAVAILABLE"
            )
        return self._configuration

    def create_profile(
        self, *, principal: EditorPrincipal, idempotency_key: str
    ) -> EditorResourceDto:
        self._require_role(principal, "CREATOR")
        payload = {}
        replay = self._replay(
            principal, "CREATE_PROFILE", idempotency_key, payload
        )
        if replay is not None:
            return replay
        with self._repo.lock:
            replay = self._replay(
                principal, "CREATE_PROFILE", idempotency_key, payload
            )
            if replay is not None:
                return replay
            owned = [
                item
                for item in self._repo.profiles.values()
                if item.owner_user_id == principal.user_id
            ]
            if owned:
                raise EditorServiceError(status=409, code="PROFILE_ALREADY_EXISTS")
            root = CreatorProfile.create(
                profile_id=self._new_id("profile"),
                owner_user_id=principal.user_id,
                now=self._now(),
            )
            self._repo.profiles[root.profile_id] = root
            result = self._profile_dto(principal, root)
            self._save_receipt(
                principal, "CREATE_PROFILE", idempotency_key, payload, result
            )
            return result

    def list_profiles(
        self, *, principal: EditorPrincipal
    ) -> Tuple[EditorResourceDto, ...]:
        self._require_role(principal, "CREATOR")
        return tuple(
            self._profile_dto(principal, item)
            for item in sorted(
                self._repo.profiles.values(), key=lambda value: value.profile_id
            )
            if item.owner_user_id == principal.user_id
        )

    def get_profile(
        self, *, principal: EditorPrincipal, profile_id: str
    ) -> EditorResourceDto:
        self._require_role(principal, "CREATOR")
        root = self._repo.profiles.get(profile_id)
        if root is None or root.owner_user_id != principal.user_id:
            self._not_found()
        return self._profile_dto(principal, root)

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
        payload = {
            "profile_id": profile_id,
            "if_match": if_match,
            "base_version_id": base_version_id,
            "taxonomy_bundle_id": taxonomy_bundle_id,
            "content": content,
        }
        replay = self._replay(principal, "SAVE_PROFILE", idempotency_key, payload)
        if replay is not None:
            return replay
        with self._repo.lock:
            replay = self._replay(
                principal, "SAVE_PROFILE", idempotency_key, payload
            )
            if replay is not None:
                return replay
            root = self._owned_profile(principal, profile_id)
            if root.status not in {
                CreatorProfileStatus.DRAFT,
                CreatorProfileStatus.ACTIVE,
            }:
                raise EditorServiceError(
                    status=409,
                    code="INVALID_STATE_TRANSITION",
                    path="/status",
                )
            self._require_etag(
                current=self._profile_dto(principal, root),
                if_match=if_match,
                base_version_id=base_version_id,
                yours=content,
                versions=self._repo.profile_versions_for(profile_id),
            )
            self._validate_editor_choices("CREATOR_PROFILE", content)
            try:
                frozen = freeze_profile_content(content, for_publish=False)
                updated, version = root.save_draft(
                    profile_version_id=self._new_id("profile_version"),
                    taxonomy_bundle_id=taxonomy_bundle_id,
                    based_on_profile_version_id=base_version_id,
                    content=frozen,
                    actor_user_id=principal.user_id,
                    now=self._now(),
                    existing_versions=self._repo.profile_versions_for(profile_id),
                )
            except CreatorProfileDomainError as error:
                self._domain_error(error.code, path="/content")
            self._repo.profile_versions[version.profile_version_id] = version
            self._repo.profiles[profile_id] = updated
            result = self._profile_dto(principal, updated)
            self._save_receipt(
                principal, "SAVE_PROFILE", idempotency_key, payload, result
            )
            return result

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
        payload = {
            "profile_id": profile_id,
            "draft_version_id": draft_version_id,
            "if_match": if_match,
        }
        replay = self._replay(
            principal, "PUBLISH_PROFILE", idempotency_key, payload
        )
        if replay is not None:
            return replay
        with self._repo.lock:
            replay = self._replay(
                principal, "PUBLISH_PROFILE", idempotency_key, payload
            )
            if replay is not None:
                return replay
            root = self._owned_profile(principal, profile_id)
            current = self._profile_dto(principal, root)
            self._require_etag(
                current=current,
                if_match=if_match,
                base_version_id=draft_version_id,
                yours=(current.current_version.content if current.current_version else {}),
                versions=self._repo.profile_versions_for(profile_id),
            )
            version = self._repo.profile_versions.get(draft_version_id)
            if version is None or version.profile_id != profile_id:
                self._not_found()
            self._validate_editor_choices(
                "CREATOR_PROFILE", _thaw_json(version.content)
            )
            try:
                updated, published = root.publish(
                    profile_version=version,
                    actor_user_id=principal.user_id,
                    now=self._now(),
                    existing_versions=self._repo.profile_versions_for(profile_id),
                )
            except CreatorProfileDomainError as error:
                self._domain_error(error.code, path="/draft_version_id")
            old_published_id = root.current_published_version_id
            if old_published_id is not None and old_published_id != draft_version_id:
                old = self._repo.profile_versions.get(old_published_id)
                if old is not None:
                    self._repo.profile_versions[old_published_id] = replace(
                        old, status=ProfileVersionStatus.SUPERSEDED
                    )
            self._repo.profile_versions[draft_version_id] = published
            self._repo.profiles[profile_id] = updated
            result = self._profile_dto(principal, updated)
            self._save_receipt(
                principal, "PUBLISH_PROFILE", idempotency_key, payload, result
            )
            return result

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
        try:
            reason = PauseReasonCode(reason_code)
        except (TypeError, ValueError):
            raise EditorServiceError(
                status=422, code="INVALID_REASON_CODE", path="/reason_code"
            ) from None
        payload = {
            "profile_id": profile_id,
            "if_match": if_match,
            "reason_code": reason.value,
        }
        replay = self._replay(
            principal, "PAUSE_PROFILE", idempotency_key, payload
        )
        if replay is not None:
            return replay
        with self._repo.lock:
            replay = self._replay(
                principal, "PAUSE_PROFILE", idempotency_key, payload
            )
            if replay is not None:
                return replay
            root = self._owned_profile(principal, profile_id)
            current = self._profile_dto(principal, root)
            self._require_lifecycle_etag(current=current, if_match=if_match)
            try:
                updated = root.pause(reason_code=reason, now=self._now())
            except CreatorProfileDomainError as error:
                self._domain_error(error.code, path="/status")
            self._repo.profiles[profile_id] = updated
            result = self._profile_dto(principal, updated)
            self._save_receipt(
                principal, "PAUSE_PROFILE", idempotency_key, payload, result
            )
            return result

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
        replay = self._replay(
            principal, "RESUME_PROFILE", idempotency_key, payload
        )
        if replay is not None:
            return replay
        with self._repo.lock:
            replay = self._replay(
                principal, "RESUME_PROFILE", idempotency_key, payload
            )
            if replay is not None:
                return replay
            root = self._owned_profile(principal, profile_id)
            current = self._profile_dto(principal, root)
            self._require_lifecycle_etag(current=current, if_match=if_match)
            try:
                updated = root.resume(now=self._now())
            except CreatorProfileDomainError as error:
                self._domain_error(error.code, path="/status")
            self._repo.profiles[profile_id] = updated
            result = self._profile_dto(principal, updated)
            self._save_receipt(
                principal, "RESUME_PROFILE", idempotency_key, payload, result
            )
            return result

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
        try:
            reason = ArchiveReasonCode(reason_code)
        except (TypeError, ValueError):
            raise EditorServiceError(
                status=422, code="INVALID_REASON_CODE", path="/reason_code"
            ) from None
        payload = {
            "profile_id": profile_id,
            "if_match": if_match,
            "reason_code": reason.value,
        }
        replay = self._replay(
            principal, "ARCHIVE_PROFILE", idempotency_key, payload
        )
        if replay is not None:
            return replay
        with self._repo.lock:
            replay = self._replay(
                principal, "ARCHIVE_PROFILE", idempotency_key, payload
            )
            if replay is not None:
                return replay
            root = self._owned_profile(principal, profile_id)
            current = self._profile_dto(principal, root)
            self._require_lifecycle_etag(current=current, if_match=if_match)
            try:
                updated = root.archive(reason_code=reason, now=self._now())
            except CreatorProfileDomainError as error:
                self._domain_error(error.code, path="/status")
            if root.current_draft_version_id is not None:
                draft = self._repo.profile_versions.get(
                    root.current_draft_version_id
                )
                if draft is not None:
                    self._repo.profile_versions[draft.profile_version_id] = replace(
                        draft, status=ProfileVersionStatus.DISCARDED
                    )
            if root.current_published_version_id is not None:
                published = self._repo.profile_versions.get(
                    root.current_published_version_id
                )
                if published is not None:
                    self._repo.profile_versions[
                        published.profile_version_id
                    ] = replace(published, status=ProfileVersionStatus.RETIRED)
            self._repo.profiles[profile_id] = updated
            result = self._profile_dto(principal, updated)
            self._save_receipt(
                principal, "ARCHIVE_PROFILE", idempotency_key, payload, result
            )
            return result

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
        payload = {
            "taxonomy_bundle_id": taxonomy_bundle_id,
            "content": content,
            "client_reference": client_reference,
            "expires_at": expires_at,
        }
        replay = self._replay(principal, "CREATE_DEMAND", idempotency_key, payload)
        if replay is not None:
            return replay
        with self._repo.lock:
            replay = self._replay(
                principal, "CREATE_DEMAND", idempotency_key, payload
            )
            if replay is not None:
                return replay
            self._validate_editor_choices("DEMAND", content)
            try:
                root, version = Demand.create(
                    demand_id=self._new_id("demand"),
                    demand_version_id=self._new_id("demand_version"),
                    organization_id=principal.organization_id,
                    created_by_user_id=principal.user_id,
                    taxonomy_bundle_id=taxonomy_bundle_id,
                    content=_freeze_demand_content(content),
                    client_reference_digest_key_id="internal-pilot-v1",
                    client_reference_digest=hmac.new(
                        self._client_reference_key,
                        client_reference.encode("utf-8"),
                        hashlib.sha256,
                    ).hexdigest(),
                    expires_at=_utc_datetime(expires_at),
                    now=self._now(),
                )
            except DemandDomainError as error:
                self._domain_error(error.code, path="/content")
            self._repo.demands[root.demand_id] = root
            self._repo.demand_versions[version.demand_version_id] = version
            result = self._demand_dto(principal, root)
            self._save_receipt(
                principal, "CREATE_DEMAND", idempotency_key, payload, result
            )
            return result

    def list_demands(
        self, *, principal: EditorPrincipal
    ) -> Tuple[EditorResourceDto, ...]:
        roots = tuple(
            sorted(self._repo.demands.values(), key=lambda value: value.demand_id)
        )
        if "DEMAND_OWNER" in principal.role_codes:
            visible = tuple(
                item
                for item in roots
                if item.organization_id == principal.organization_id
                and item.created_by_user_id == principal.user_id
            )
        elif "OPERATIONS_REVIEWER" in principal.role_codes:
            allowed = {
                item.demand_id
                for item in self._repo.assignments_for_reviewer(principal.user_id)
                if item.status is ReviewAssignmentStatus.ACTIVE
                and item.expires_at > self._now()
            }
            visible = tuple(item for item in roots if item.demand_id in allowed)
        else:
            self._not_found()
        return tuple(self._demand_dto(principal, item) for item in visible)

    def get_demand(
        self, *, principal: EditorPrincipal, demand_id: str
    ) -> EditorResourceDto:
        root = self._visible_demand(principal, demand_id)
        return self._demand_dto(principal, root)

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
        payload = {
            "demand_id": demand_id,
            "if_match": if_match,
            "base_version_id": base_version_id,
            "taxonomy_bundle_id": taxonomy_bundle_id,
            "content": content,
        }
        replay = self._replay(principal, "SAVE_DEMAND", idempotency_key, payload)
        if replay is not None:
            return replay
        with self._repo.lock:
            replay = self._replay(
                principal, "SAVE_DEMAND", idempotency_key, payload
            )
            if replay is not None:
                return replay
            root = self._owned_demand(principal, demand_id)
            self._require_etag(
                current=self._demand_dto(principal, root),
                if_match=if_match,
                base_version_id=base_version_id,
                yours=content,
                versions=self._repo.demand_versions_for(demand_id),
            )
            self._validate_editor_choices("DEMAND", content)
            try:
                updated, version = root.create_version(
                    demand_version_id=self._new_id("demand_version"),
                    based_on_demand_version_id=base_version_id,
                    taxonomy_bundle_id=taxonomy_bundle_id,
                    content=_freeze_demand_content(content),
                    actor_user_id=principal.user_id,
                    now=self._now(),
                    existing_versions=self._repo.demand_versions_for(demand_id),
                )
            except DemandDomainError as error:
                path = "/base_version_id" if error.code == "PRECONDITION_FAILED" else "/content"
                self._domain_error(error.code, path=path)
            self._repo.demand_versions[version.demand_version_id] = version
            self._repo.demands[demand_id] = updated
            result = self._demand_dto(principal, updated)
            self._save_receipt(
                principal, "SAVE_DEMAND", idempotency_key, payload, result
            )
            return result

    def submit_demand(
        self,
        *,
        principal: EditorPrincipal,
        demand_id: str,
        if_match: str,
        idempotency_key: str,
    ) -> EditorResourceDto:
        self._require_role(principal, "DEMAND_OWNER")
        payload = {"demand_id": demand_id, "if_match": if_match}
        replay = self._replay(principal, "SUBMIT_DEMAND", idempotency_key, payload)
        if replay is not None:
            return replay
        with self._repo.lock:
            replay = self._replay(
                principal, "SUBMIT_DEMAND", idempotency_key, payload
            )
            if replay is not None:
                return replay
            root = self._owned_demand(principal, demand_id)
            current = self._demand_dto(principal, root)
            self._require_etag(
                current=current,
                if_match=if_match,
                base_version_id=root.current_version_id,
                yours=current.current_version.content if current.current_version else {},
                versions=self._repo.demand_versions_for(demand_id),
            )
            version = self._repo.demand_versions[root.current_version_id]
            self._validate_editor_choices(
                "DEMAND", _thaw_json(version.content)
            )
            try:
                updated, submission = root.submit(
                    current_version=version,
                    prior_submissions=self._repo.submissions_for(demand_id),
                    submission_id=self._new_id("demand_submission"),
                    actor_user_id=principal.user_id,
                    now=self._now(),
                    content_policy_version="internal-pilot-content-policy-v1",
                    content_policy_result_sha256=hashlib.sha256(
                        b"internal-pilot-allow"
                    ).hexdigest(),
                )
            except DemandDomainError as error:
                self._domain_error(error.code, path="/content")
            self._repo.demands[demand_id] = updated
            self._repo.demand_submissions[submission.submission_id] = submission
            result = self._demand_dto(principal, updated)
            self._save_receipt(
                principal, "SUBMIT_DEMAND", idempotency_key, payload, result
            )
            return result

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
        # Replay remains conditional on current server-derived ownership; a
        # receipt alone is never sufficient authority to disclose the result.
        self._owned_demand(principal, demand_id)
        replay = self._replay(
            principal, "CANCEL_DEMAND", idempotency_key, payload
        )
        if replay is not None:
            return replay
        with self._repo.lock:
            replay = self._replay(
                principal, "CANCEL_DEMAND", idempotency_key, payload
            )
            if replay is not None:
                return replay
            root = self._owned_demand(principal, demand_id)
            current = self._demand_dto(principal, root)
            self._require_lifecycle_etag(current=current, if_match=if_match)
            try:
                updated = root.cancel(now=self._now(), reason_code=reason)
            except DemandDomainError as error:
                self._domain_error(error.code, path="/status")
            self._repo.demands[demand_id] = updated
            result = self._demand_dto(principal, updated)
            self._save_receipt(
                principal, "CANCEL_DEMAND", idempotency_key, payload, result
            )
            return result

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
        payload = {
            "assignment_id": assignment_id,
            "demand_id": demand_id,
            "if_match": if_match,
            "reason_codes": reason_codes,
            "required_field_paths": fields,
        }
        replay = self._replay(principal, "REVIEW_FINDINGS", idempotency_key, payload)
        if replay is not None:
            return replay
        with self._repo.lock:
            replay = self._replay(
                principal, "REVIEW_FINDINGS", idempotency_key, payload
            )
            if replay is not None:
                return replay
            assignment = self._authoritative_assignment(
                principal, demand_id, assignment_id
            )
            root = self._repo.demands.get(demand_id)
            if root is None:
                self._not_found()
            current = self._demand_dto(principal, root)
            self._require_etag(
                current=current,
                if_match=if_match,
                base_version_id=root.current_version_id,
                yours=current.current_version.content if current.current_version else {},
                versions=self._repo.demand_versions_for(demand_id),
            )
            if any(not _valid_json_pointer(value) for value in fields):
                raise EditorServiceError(
                    status=422,
                    code="INVALID_FIELD_PATH",
                    path="/required_field_paths",
                )
            version = self._repo.demand_versions[root.current_version_id]
            submissions = self._repo.submissions_for(demand_id)
            if not submissions:
                self._not_found()
            try:
                updated, review = root.request_changes(
                    current_version=version,
                    submission=submissions[-1],
                    assignment=assignment,
                    assignment_id=assignment_id,
                    reviewer_user_id=principal.user_id,
                    review_id=self._new_id("demand_review"),
                    reason_codes=reason_codes,
                    required_field_codes=fields,
                    now=self._now(),
                )
            except DemandDomainError as error:
                self._domain_error(error.code, path="/required_field_paths")
            self._repo.demands[demand_id] = updated
            self._repo.demand_reviews[review.review_id] = review
            self._repo.review_assignments[assignment_id] = replace(
                assignment,
                status=ReviewAssignmentStatus.COMPLETED,
                aggregate_version=assignment.aggregate_version + 1,
            )
            result = self._demand_dto(principal, updated)
            self._save_receipt(
                principal, "REVIEW_FINDINGS", idempotency_key, payload, result
            )
            return result

    def _profile_dto(
        self, principal: EditorPrincipal, root: CreatorProfile
    ) -> EditorResourceDto:
        versions = tuple(
            _profile_version_dto(item)
            for item in self._repo.profile_versions_for(root.profile_id)
        )
        current_id = (
            root.current_published_version_id
            if root.status is CreatorProfileStatus.PAUSED
            else root.current_draft_version_id or root.current_published_version_id
        )
        current = next(
            (item for item in versions if item.version_id == current_id), None
        )
        capabilities = []
        if root.owner_user_id == principal.user_id and root.status.value != "ARCHIVED":
            if root.status in {
                CreatorProfileStatus.DRAFT,
                CreatorProfileStatus.ACTIVE,
            }:
                capabilities.append("SAVE_DRAFT")
            if (
                root.status in {
                    CreatorProfileStatus.DRAFT,
                    CreatorProfileStatus.ACTIVE,
                }
                and current is not None
                and current.status == "DRAFT"
            ):
                capabilities.append("PUBLISH")
            if root.status is CreatorProfileStatus.ACTIVE:
                capabilities.append("PAUSE")
            if root.status is CreatorProfileStatus.PAUSED:
                capabilities.append("RESUME")
            capabilities.append("ARCHIVE")
        return EditorResourceDto(
            resource_type="CREATOR_PROFILE",
            object_id=root.profile_id,
            status=root.status.value,
            revision=root.aggregate_version,
            etag=_etag("CREATOR_PROFILE", root.profile_id, root.aggregate_version),
            capabilities=tuple(capabilities),
            editable_paths=_PROFILE_EDITABLE_PATHS if "SAVE_DRAFT" in capabilities else (),
            current_version=current,
            versions=versions,
        )

    def _demand_dto(
        self, principal: EditorPrincipal, root: Demand
    ) -> EditorResourceDto:
        versions = tuple(
            _demand_version_dto(item)
            for item in self._repo.demand_versions_for(root.demand_id)
        )
        current = next(
            (item for item in versions if item.version_id == root.current_version_id),
            None,
        )
        submissions = tuple(
            EditorSubmissionDto(
                submission_id=item.submission_id,
                version_id=item.demand_version_id,
                submission_no=item.submission_no,
                content_sha256=item.content_sha256,
                submitted_at=item.submitted_at,
            )
            for item in self._repo.submissions_for(root.demand_id)
        )
        findings = tuple(
            EditorFindingDto(
                finding_id=item.review_id,
                version_id=item.demand_version_id,
                assignment_id=item.assignment_id,
                result=item.result.value,
                reason_codes=item.reason_codes,
                required_field_paths=item.required_field_codes,
                reviewed_at=item.reviewed_at,
            )
            for item in self._repo.reviews_for(root.demand_id)
        )
        capabilities = []
        is_owner = (
            root.created_by_user_id == principal.user_id
            and root.organization_id == principal.organization_id
            and "DEMAND_OWNER" in principal.role_codes
        )
        if is_owner and root.status in {DemandStatus.DRAFT, DemandStatus.NEEDS_CHANGES}:
            capabilities.extend(("SAVE_DRAFT", "SUBMIT"))
        if is_owner and root.status not in {
            DemandStatus.MATCHED,
            DemandStatus.CANCELLED,
            DemandStatus.EXPIRED,
        }:
            capabilities.append("CANCEL")
        assignment = next((
            item
            for item in self._repo.assignments_for_reviewer(principal.user_id)
            if item.demand_id == root.demand_id
            and item.status is ReviewAssignmentStatus.ACTIVE
            and item.expires_at > self._now()
        ), None)
        if "OPERATIONS_REVIEWER" in principal.role_codes and assignment is not None:
            capabilities.append("RECORD_FINDINGS")
        return EditorResourceDto(
            resource_type="DEMAND",
            object_id=root.demand_id,
            status=root.status.value,
            revision=root.aggregate_version,
            etag=_etag("DEMAND", root.demand_id, root.aggregate_version),
            capabilities=tuple(capabilities),
            editable_paths=_DEMAND_EDITABLE_PATHS if "SAVE_DRAFT" in capabilities else (),
            current_version=current,
            versions=versions,
            submissions=submissions,
            findings=findings,
            review_assignment=(
                EditorReviewAssignmentDto(
                    assignment_id=assignment.assignment_id,
                    status=assignment.status.value,
                    expires_at=assignment.expires_at,
                )
                if assignment is not None else None
            ),
        )

    def _owned_profile(
        self, principal: EditorPrincipal, profile_id: str
    ) -> CreatorProfile:
        root = self._repo.profiles.get(profile_id)
        if root is None or root.owner_user_id != principal.user_id:
            self._not_found()
        return root

    def _owned_demand(self, principal: EditorPrincipal, demand_id: str) -> Demand:
        root = self._repo.demands.get(demand_id)
        if (
            root is None
            or root.organization_id != principal.organization_id
            or root.created_by_user_id != principal.user_id
        ):
            self._not_found()
        return root

    def _visible_demand(self, principal: EditorPrincipal, demand_id: str) -> Demand:
        root = self._repo.demands.get(demand_id)
        if root is None:
            self._not_found()
        if "DEMAND_OWNER" in principal.role_codes:
            return self._owned_demand(principal, demand_id)
        if "OPERATIONS_REVIEWER" in principal.role_codes:
            self._authoritative_assignment(principal, demand_id, None)
            return root
        self._not_found()

    def _authoritative_assignment(
        self,
        principal: EditorPrincipal,
        demand_id: str,
        assignment_id: Optional[str],
    ) -> DemandReviewAssignment:
        candidates = self._repo.assignments_for_reviewer(principal.user_id)
        for item in candidates:
            if (
                item.demand_id == demand_id
                and (assignment_id is None or item.assignment_id == assignment_id)
                and item.status is ReviewAssignmentStatus.ACTIVE
                and item.expires_at > self._now()
            ):
                return item
        self._not_found()

    def _require_etag(
        self,
        *,
        current: EditorResourceDto,
        if_match: str,
        base_version_id: Optional[str],
        yours: Mapping[str, Any],
        versions: Sequence[Any],
    ) -> None:
        if hmac.compare_digest(current.etag, if_match):
            return
        base = next(
            (
                _version_conflict_surface(item)
                for item in versions
                if _version_id(item) == base_version_id
            ),
            None,
        )
        current_surface = (
            _dto_version_surface(current.current_version)
            if current.current_version is not None
            else {"version_id": None, "content": {}}
        )
        raise EditorServiceError(
            status=412,
            code="PRECONDITION_FAILED",
            details={
                "current": current_surface,
                "base": base or {"version_id": base_version_id, "content": {}},
                "yours": {"version_id": base_version_id, "content": _plain_json(yours)},
            },
            etag=current.etag,
        )

    @staticmethod
    def _require_lifecycle_etag(
        *, current: EditorResourceDto, if_match: str
    ) -> None:
        if not isinstance(if_match, str) or not hmac.compare_digest(
            current.etag, if_match
        ):
            raise EditorServiceError(
                status=412,
                code="PRECONDITION_FAILED",
                etag=current.etag,
            )

    def _replay(
        self,
        principal: EditorPrincipal,
        operation: str,
        idempotency_key: str,
        payload: Mapping[str, Any],
    ) -> Optional[EditorResourceDto]:
        _require_idempotency_key(idempotency_key)
        digest = _payload_sha256(payload)
        prior = self._repo.receipt(
            actor_user_id=principal.user_id, operation=operation, key=idempotency_key
        )
        if prior is None:
            return None
        if not hmac.compare_digest(prior[0], digest):
            raise EditorServiceError(status=409, code="IDEMPOTENCY_CONFLICT")
        return prior[1]

    def _save_receipt(
        self,
        principal: EditorPrincipal,
        operation: str,
        idempotency_key: str,
        payload: Mapping[str, Any],
        result: EditorResourceDto,
    ) -> None:
        self._repo.save_receipt(
            actor_user_id=principal.user_id,
            operation=operation,
            key=idempotency_key,
            payload_sha256=_payload_sha256(payload),
            result=result,
        )

    @staticmethod
    def _require_role(principal: EditorPrincipal, role: str) -> None:
        if role not in principal.role_codes:
            EditorService._not_found()

    @staticmethod
    def _not_found() -> None:
        raise EditorServiceError(status=404, code="RESOURCE_NOT_FOUND")

    @staticmethod
    def _domain_error(code: str, *, path: str) -> None:
        status = 422 if "VALIDATION" in code else 409
        raise EditorServiceError(status=status, code=code, path=path)

    def _now(self) -> datetime:
        return _utc_datetime(self._clock.now())

    def _validate_editor_choices(
        self, resource_type: str, content: Mapping[str, Any]
    ) -> None:
        validate_editor_choice_membership(
            resource_type=resource_type,
            content=content,
            choices=self._editor_choices,
        )

    def _new_id(self, kind: str) -> str:
        value = self._ids.new(kind)
        if not isinstance(value, str):
            raise RuntimeError("id source returned a non-string")
        return value


def _profile_version_dto(version: ProfileVersion) -> EditorVersionDto:
    return EditorVersionDto(
        version_id=version.profile_version_id,
        version_no=version.version_no,
        based_on_version_id=version.based_on_profile_version_id,
        status=version.status.value,
        content=_thaw_json(version.content),
        content_sha256=version.content_sha256,
        taxonomy_bundle_id=version.taxonomy_bundle_id,
        created_at=version.asserted_at,
    )


def _demand_version_dto(version: Any) -> EditorVersionDto:
    return EditorVersionDto(
        version_id=version.demand_version_id,
        version_no=version.version_no,
        based_on_version_id=version.based_on_demand_version_id,
        status="COMMITTED",
        content=_thaw_json(version.content),
        content_sha256=version.content_sha256,
        taxonomy_bundle_id=version.taxonomy_bundle_id,
        created_at=version.created_at,
    )


def _etag(resource_type: str, object_id: str, revision: int) -> str:
    digest = hashlib.sha256(
        f"{resource_type}:{object_id}:{revision}".encode("utf-8")
    ).hexdigest()[:24]
    return f'"{resource_type.lower()}-{revision}-{digest}"'


def _payload_sha256(payload: Mapping[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(
            payload,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
            default=_json_default,
        ).encode("utf-8")
    ).hexdigest()


def _json_default(value: Any) -> str:
    if isinstance(value, datetime):
        return _utc_datetime(value).isoformat()
    raise TypeError("unsupported receipt value")


def _freeze_demand_content(value: Mapping[str, Any]) -> DemandContent:
    frozen = _freeze_json(value, DemandContent)
    if not isinstance(frozen, DemandContent):
        raise DemandDomainError("DEMAND_VALIDATION_FAILED")
    return frozen


def _freeze_json(value: Any, object_type: Any) -> Any:
    if isinstance(value, Mapping):
        return object_type(
            tuple((str(key), _freeze_json(child, object_type)) for key, child in value.items())
        )
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_json(child, object_type) for child in value)
    if value is None or isinstance(value, (bool, int, str)):
        return value
    raise DemandDomainError("DEMAND_VALIDATION_FAILED")


def _thaw_json(value: Any) -> Any:
    if isinstance(value, (ProfileContent, DemandContent)):
        return {key: _thaw_json(child) for key, child in value.members}
    if isinstance(value, tuple):
        return [_thaw_json(child) for child in value]
    return value


def _plain_json(value: Mapping[str, Any]) -> Mapping[str, Any]:
    return json.loads(json.dumps(value, ensure_ascii=False, allow_nan=False))


def _version_id(value: Any) -> Optional[str]:
    return getattr(value, "profile_version_id", None) or getattr(
        value, "demand_version_id", None
    )


def _version_conflict_surface(value: Any) -> Mapping[str, Any]:
    return {"version_id": _version_id(value), "content": _thaw_json(value.content)}


def _dto_version_surface(value: EditorVersionDto) -> Mapping[str, Any]:
    return {"version_id": value.version_id, "content": value.content}


def _require_idempotency_key(value: str) -> None:
    if not isinstance(value, str) or not 8 <= len(value) <= 200:
        raise EditorServiceError(
            status=422, code="INVALID_IDEMPOTENCY_KEY", path="/headers/Idempotency-Key"
        )


def _utc_datetime(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise EditorServiceError(status=422, code="INVALID_DATETIME")
    return value.astimezone(timezone.utc)


def _valid_json_pointer(value: str) -> bool:
    return (
        isinstance(value, str)
        and value.startswith("/")
        and len(value) <= 256
        and "//" not in value
    )
