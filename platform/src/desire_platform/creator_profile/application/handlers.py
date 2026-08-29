"""Creator Profile Memory command orchestration.

The handlers use only closed ports.  IAM authority is checked before any
Profile read that could disclose ownership; visibility-increasing SafetyHold
calls run outside the unit of work; all durable facts, receipt, audit, and
outbox entries are committed together.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta
from enum import Enum
import hmac
import json
from typing import Any, Mapping, Optional, Tuple

from ..domain.model import (
    CreatorProfile,
    CreatorProfileDomainError,
    CreatorProfileStatus,
    ProfileContent,
    ProfileVersion,
    ProfileVersionStatus,
    is_profile_field_effective,
    profile_version_content_sha256,
    require_profile_version_immutable,
)
from ..ports.commands import (
    CreatorProfileAuthority,
    CreatorProfileAuthorityUnavailableError,
    CreatorProfileCommitOutcomeUnknownError,
    CreatorProfileHoldDecision,
    CreatorProfileSafetyHoldResult,
    CreatorProfileSafetyHoldUnavailableError,
    CreatorProfileStorageUnavailableError,
)
from .commands import (
    ArchiveCreatorProfileCommand,
    CreateCreatorProfileCommand,
    CreatorProfileActorContext,
    CreatorProfileCommandResult,
    PauseCreatorProfileCommand,
    PublishCreatorProfileVersionCommand,
    ResumeCreatorProfileCommand,
    SaveCreatorProfileDraftCommand,
)


# Retained only as a stable import for code compiled during the preceding RED.
PROFILE_APPLICATION_BEHAVIOR_NOT_AVAILABLE = (
    "PROFILE_APPLICATION_BEHAVIOR_NOT_AVAILABLE"
)


class CreatorProfileApplicationBehaviorNotAvailable(RuntimeError):
    """Legacy RED sentinel; implemented handlers never raise it."""


class CreatorProfileApplicationError(RuntimeError):
    """Closed application error safe to map at a later HTTP boundary."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class _HoldTargetDrift(RuntimeError):
    """The locked root/version no longer matches the external hold decision."""


_OPERATION_NAMES = {
    "create": "CreateCreatorProfile",
    "save": "SaveCreatorProfileDraft",
    "publish": "PublishCreatorProfileVersion",
    "pause": "PauseCreatorProfile",
    "resume": "ResumeCreatorProfile",
    "archive": "ArchiveCreatorProfile",
}

_CANONICAL_PATHS = {
    "create": "/v1/me/creator-profile",
    "save": "/v1/me/creator-profile/drafts",
    "publish": "/v1/me/creator-profile/drafts/{profile_version_id}/publish",
    "pause": "/v1/me/creator-profile/pause",
    "resume": "/v1/me/creator-profile/resume",
    "archive": "/v1/me/creator-profile/archive",
}

_EVENT_TYPES = {
    "create": "CreatorProfileCreated",
    "publish": "CreatorProfilePublished",
    "pause": "CreatorProfilePaused",
    "resume": "CreatorProfileResumed",
    "archive": "CreatorProfileArchived",
}

_AUDIT_ACTIONS = {
    "create": "creator_profile.created",
    "save": "creator_profile.draft_saved",
    "publish": "creator_profile.published",
    "pause": "creator_profile.paused",
    "resume": "creator_profile.resumed",
    "archive": "creator_profile.archived",
}


class _CreatorProfileHandler:
    operation: str

    def __init__(
        self,
        *,
        authority: Any,
        uow_factory: Any,
        clock: Any,
        id_source: Any,
        receipt_keyring: Any,
        event_validator: Any,
        safe_response_validator: Any,
        safety_hold: Any = None,
        safety_hold_policy_version: str = "creator-profile-hold-v1",
    ) -> None:
        self._authority = authority
        self._uow_factory = uow_factory
        self._clock = clock
        self._id_source = id_source
        self._receipt_keyring = receipt_keyring
        self._event_validator = event_validator
        self._safe_response_validator = safe_response_validator
        self._safety_hold = safety_hold
        self._safety_hold_policy_version = safety_hold_policy_version

    def _handle(
        self,
        *,
        actor: CreatorProfileActorContext,
        command: Any,
    ) -> CreatorProfileCommandResult:
        now = self._now()
        authority = self._authorize(actor)
        identity = self._receipt_identity(
            actor_user_id=actor.actor_user_id,
            idempotency_key=command.idempotency_key,
        )

        snapshot = self._safe_snapshot()
        prior_receipt = _find_identity_receipt(
            snapshot.get("command_receipts", {}), identity
        )
        target_profile_id = _command_profile_id(command)
        if prior_receipt is not None:
            if self.operation == "create":
                target_profile_id = prior_receipt.get("target_profile_id")
            payload_hash = self._payload_hash(
                command=command,
                target_profile_id=target_profile_id,
            )
            return self._replay_or_conflict(
                receipt=prior_receipt,
                payload_hash=payload_hash,
                snapshot=snapshot,
            )

        if self.operation == "create":
            target_profile_id = self._new_id("creator_profile")
        if not isinstance(target_profile_id, str):
            _fail("INVALID_REQUEST")
        payload_hash = self._payload_hash(
            command=command,
            target_profile_id=target_profile_id,
        )

        hold_result: Optional[CreatorProfileSafetyHoldResult] = None
        if self.operation in ("publish", "resume"):
            hold_result = self._evaluate_hold(
                actor=actor,
                command=command,
                snapshot=snapshot,
                now=now,
            )

        receipt_id = self._new_id("command_receipt")
        new_version_id = (
            self._new_id("profile_version") if self.operation == "save" else None
        )
        audit_id = self._new_id("audit_event")
        outbox_id = (
            self._new_id("outbox_event")
            if self.operation in _EVENT_TYPES
            else None
        )

        try:
            for attempt in range(2):
                try:
                    with self._uow_factory.begin() as uow:
                        self._lock_all(
                            uow=uow,
                            authority=authority,
                            actor=actor,
                            command=command,
                            identity=identity,
                            snapshot=snapshot,
                        )
                        raced_receipt = _find_identity_receipt(
                            {
                                str(index): value
                                for index, value in enumerate(
                                    uow.values("command_receipts")
                                )
                            },
                            identity,
                        )
                        if raced_receipt is not None:
                            return self._replay_or_conflict(
                                receipt=raced_receipt,
                                payload_hash=payload_hash,
                                snapshot=self._safe_snapshot(),
                            )

                        result, pending, completed, event = self._execute_locked(
                            uow=uow,
                            actor=actor,
                            command=command,
                            authority=authority,
                            identity=identity,
                            payload_hash=payload_hash,
                            target_profile_id=target_profile_id,
                            receipt_id=receipt_id,
                            new_version_id=new_version_id,
                            audit_id=audit_id,
                            outbox_id=outbox_id,
                            hold_result=hold_result,
                            now=now,
                        )
                        # pending is returned for explicit traceability; it was
                        # written before the first business mutation.
                        del pending, completed, event
                        uow.commit()
                        return result
                except _HoldTargetDrift:
                    if self.operation not in ("publish", "resume") or attempt:
                        _fail("SERVICE_UNAVAILABLE")
                    # Leave the failed UoW first, then obtain a fresh exact IAM
                    # projection and target snapshot before another external
                    # hold call.  No business write from the first attempt can
                    # escape its transaction.
                    authority = self._authorize(actor)
                    snapshot = self._safe_snapshot()
                    now = self._now()
                    hold_result = self._evaluate_hold(
                        actor=actor,
                        command=command,
                        snapshot=snapshot,
                        now=now,
                    )
                    continue
            _fail("SERVICE_UNAVAILABLE")
        except CreatorProfileCommitOutcomeUnknownError:
            recovered = self._recover_commit_unknown(
                identity=identity,
                payload_hash=payload_hash,
            )
            if recovered is not None:
                return recovered
            _fail("SERVICE_UNAVAILABLE")
        except CreatorProfileApplicationError:
            raise
        except CreatorProfileDomainError as error:
            _fail(error.code)
        except CreatorProfileStorageUnavailableError:
            _fail("SERVICE_UNAVAILABLE")
        except Exception:
            # Port/storage/validator exceptions are deliberately collapsed to
            # the closed wire set; raw dependency details never escape.
            _fail("SERVICE_UNAVAILABLE")

    def _authorize(
        self,
        actor: CreatorProfileActorContext,
    ) -> CreatorProfileAuthority:
        try:
            authority = self._authority.authorize(
                actor=actor,
                operation=_OPERATION_NAMES[self.operation],
            )
        except CreatorProfileAuthorityUnavailableError:
            _fail("SERVICE_UNAVAILABLE")
        except Exception:
            _fail("SERVICE_UNAVAILABLE")
        if not isinstance(authority, CreatorProfileAuthority):
            _fail("SERVICE_UNAVAILABLE")
        if authority.user_status != "ACTIVE":
            _fail("AUTHENTICATION_REQUIRED")
        if (
            authority.session_status != "ACTIVE"
            or authority.session_family_status != "ACTIVE"
            or authority.session_id != actor.session_id
        ):
            _fail("SESSION_EXPIRED")
        if (
            authority.actor_user_id != actor.actor_user_id
            or not authority.creator_grant_id
        ):
            _fail("RESOURCE_NOT_FOUND")
        if not authority.policy_requirements_satisfied:
            _fail("POLICY_ACCEPTANCE_REQUIRED")
        if not all(
            isinstance(value, str) and value
            for value in (
                authority.policy_selector_digest,
                authority.policy_bundle_id,
                authority.authority_marker_sha256,
            )
        ):
            _fail("POLICY_CONFIGURATION_UNAVAILABLE")
        return authority

    def _now(self) -> datetime:
        try:
            value = self._clock.now()
        except Exception:
            _fail("SERVICE_UNAVAILABLE")
        if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
            _fail("SERVICE_UNAVAILABLE")
        if value.utcoffset() != timedelta(0):
            _fail("SERVICE_UNAVAILABLE")
        return value

    def _new_id(self, kind: str) -> str:
        try:
            value = self._id_source.new_id(kind)
        except Exception:
            _fail("SERVICE_UNAVAILABLE")
        if not isinstance(value, str) or not value:
            _fail("SERVICE_UNAVAILABLE")
        return value

    def _safe_snapshot(self) -> Mapping[str, Mapping[str, Any]]:
        try:
            snapshot = self._uow_factory.store.snapshot()
        except Exception:
            _fail("SERVICE_UNAVAILABLE")
        if not isinstance(snapshot, Mapping):
            _fail("SERVICE_UNAVAILABLE")
        return snapshot

    def _receipt_identity(
        self,
        *,
        actor_user_id: str,
        idempotency_key: str,
    ) -> Mapping[str, Any]:
        if not isinstance(idempotency_key, str) or not idempotency_key:
            _fail("INVALID_REQUEST")
        identity_key_id = getattr(
            self._receipt_keyring, "idempotency_key_digest_key_id", None
        )
        if not isinstance(identity_key_id, str) or not identity_key_id:
            _fail("SERVICE_UNAVAILABLE")
        try:
            digest = self._receipt_keyring.keyed_digest(
                identity_key_id,
                idempotency_key.encode("utf-8"),
            )
        except Exception:
            _fail("SERVICE_UNAVAILABLE")
        if not isinstance(digest, str) or len(digest) != 64:
            _fail("SERVICE_UNAVAILABLE")
        return {
            "principal_kind": "USER",
            "principal_id": actor_user_id,
            "command_name": _OPERATION_NAMES[self.operation],
            "command_version": 1,
            "idempotency_key_digest_key_id": identity_key_id,
            "idempotency_key_digest": digest,
        }

    def _payload_hash(self, *, command: Any, target_profile_id: str) -> str:
        payload_key_id = getattr(self._receipt_keyring, "payload_hash_key_id", None)
        if not isinstance(payload_key_id, str) or not payload_key_id:
            _fail("SERVICE_UNAVAILABLE")
        material = {
            "method": "POST",
            "canonical_path": _canonical_path(self.operation, command),
            "target_profile_id": target_profile_id,
            "if_match": getattr(command, "expected_version", None),
            "command_schema_version": 1,
            "body": _command_body(self.operation, command),
        }
        try:
            encoded = json.dumps(
                material,
                ensure_ascii=False,
                allow_nan=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
            digest = self._receipt_keyring.keyed_digest(payload_key_id, encoded)
        except Exception:
            _fail("INVALID_REQUEST")
        if not isinstance(digest, str) or len(digest) != 64:
            _fail("SERVICE_UNAVAILABLE")
        return digest

    def _evaluate_hold(
        self,
        *,
        actor: CreatorProfileActorContext,
        command: Any,
        snapshot: Mapping[str, Mapping[str, Any]],
        now: datetime,
    ) -> CreatorProfileSafetyHoldResult:
        profile, version = _preflight_hold_target(
            operation=self.operation,
            command=command,
            actor=actor,
            snapshot=snapshot,
        )
        _require_profile_version_hash(version)
        if self._safety_hold is None or not self._safety_hold_policy_version:
            _fail("SERVICE_UNAVAILABLE")
        query = {
            "actor_user_id": actor.actor_user_id,
            "action": _OPERATION_NAMES[self.operation],
            "profile_id": profile.profile_id,
            "prospective_aggregate_version": profile.aggregate_version + 1,
            "content_sha256": version.content_sha256,
            "policy_version": self._safety_hold_policy_version,
        }
        try:
            result = self._safety_hold.evaluate(**query)
        except CreatorProfileSafetyHoldUnavailableError:
            _fail("SERVICE_UNAVAILABLE")
        except Exception:
            _fail("SERVICE_UNAVAILABLE")
        if not isinstance(result, CreatorProfileSafetyHoldResult):
            _fail("SERVICE_UNAVAILABLE")
        if result.decision is CreatorProfileHoldDecision.BLOCK:
            _fail("SAFETY_HOLD_BLOCKED")
        if (
            result.decision is not CreatorProfileHoldDecision.ALLOW
            or result.profile_id != query["profile_id"]
            or result.prospective_aggregate_version
            != query["prospective_aggregate_version"]
            or not hmac.compare_digest(
                result.content_sha256, query["content_sha256"]
            )
            or result.actor_user_id != query["actor_user_id"]
            or result.policy_version != query["policy_version"]
            or result.evaluated_at > now
            or result.valid_until <= now
        ):
            _fail("SERVICE_UNAVAILABLE")
        return result

    def _lock_all(
        self,
        *,
        uow: Any,
        authority: CreatorProfileAuthority,
        actor: CreatorProfileActorContext,
        command: Any,
        identity: Mapping[str, Any],
        snapshot: Mapping[str, Mapping[str, Any]],
    ) -> None:
        profile_id = _command_profile_id(command)
        profile = snapshot.get("creator_profiles", {}).get(profile_id)
        draft_id = (
            profile.current_draft_version_id
            if isinstance(profile, CreatorProfile)
            else None
        )
        published_id = (
            profile.current_published_version_id
            if isinstance(profile, CreatorProfile)
            else None
        )
        taxonomy_id = None
        try:
            uow.lock(
                "iam.authority_marker", (authority.authority_marker_sha256,)
            )
            uow.lock(
                "profile.creator_profile", ((profile_id or actor.actor_user_id),)
            )
            # Once the root lock is held, derive every later lock key from the
            # UoW snapshot instead of trusting the earlier hold snapshot.
            locked_profile = (
                uow.get("creator_profiles", profile_id)
                if profile_id is not None
                else None
            )
            if isinstance(locked_profile, CreatorProfile):
                profile = locked_profile
                draft_id = profile.current_draft_version_id
                published_id = profile.current_published_version_id
            uow.lock("profile.current_draft", ((draft_id,) if draft_id else ()))
            uow.lock(
                "profile.current_published",
                ((published_id,) if published_id else ()),
            )
            if self.operation == "publish":
                version = uow.get("profile_versions", command.profile_version_id)
            elif self.operation == "save":
                taxonomy_id = command.taxonomy_bundle_id
                version = None
            elif published_id:
                version = uow.get("profile_versions", published_id)
            else:
                version = None
            if self.operation != "save":
                taxonomy_id = (
                    version.taxonomy_bundle_id
                    if isinstance(version, ProfileVersion)
                    else None
                )
            evidence_ids = (
                _content_evidence_ids(version.content)
                if isinstance(version, ProfileVersion)
                else ()
            )
            uow.lock(
                "profile.taxonomy_bundle", ((taxonomy_id,) if taxonomy_id else ())
            )
            uow.lock(
                "profile.capability_evidence", tuple(sorted(evidence_ids))
            )
            uow.lock(
                "profile.command_receipt",
                (identity["idempotency_key_digest"],),
            )
        except Exception:
            _fail("SERVICE_UNAVAILABLE")

    def _execute_locked(
        self,
        *,
        uow: Any,
        actor: CreatorProfileActorContext,
        command: Any,
        authority: CreatorProfileAuthority,
        identity: Mapping[str, Any],
        payload_hash: str,
        target_profile_id: str,
        receipt_id: str,
        new_version_id: Optional[str],
        audit_id: str,
        outbox_id: Optional[str],
        hold_result: Optional[CreatorProfileSafetyHoldResult],
        now: datetime,
    ) -> tuple[CreatorProfileCommandResult, Mapping[str, Any], Mapping[str, Any], Optional[Mapping[str, Any]]]:
        del authority
        profile, affected_versions = self._apply_domain(
            uow=uow,
            actor=actor,
            command=command,
            target_profile_id=target_profile_id,
            new_version_id=new_version_id,
            hold_result=hold_result,
            now=now,
        )
        event_types = (
            (_EVENT_TYPES[self.operation],)
            if self.operation in _EVENT_TYPES
            else ()
        )
        if (
            uow.get("command_receipts", receipt_id) is not None
            or uow.get("audit_events", audit_id) is not None
            or (
                outbox_id is not None
                and uow.get("outbox_events", outbox_id) is not None
            )
        ):
            _fail("SERVICE_UNAVAILABLE")
        pending = {
            "receipt_id": receipt_id,
            **identity,
            "canonicalization_version": "profile-command-json-v1",
            "payload_hash_key_id": self._receipt_keyring.payload_hash_key_id,
            "payload_hash": payload_hash,
            "target_profile_id": profile.profile_id,
            "status": "IN_PROGRESS",
        }

        # _apply_domain computes immutable facts but intentionally does not
        # write them.  The first durable statement is always receipt.pending.
        uow.put(
            "command_receipts",
            receipt_id,
            pending,
            checkpoint="receipt.pending",
        )
        self._write_business_facts(
            uow=uow,
            command=command,
            profile=profile,
            affected_versions=affected_versions,
        )

        audit = {
            "audit_event_id": audit_id,
            "action": _AUDIT_ACTIONS[self.operation],
            "profile_id": profile.profile_id,
            "aggregate_version": profile.aggregate_version,
            "actor_user_id": actor.actor_user_id,
            "occurred_at": _timestamp(now),
            "trace_id": actor.trace_id,
        }
        uow.put(
            "audit_events",
            audit_id,
            audit,
            checkpoint="audit." + _checkpoint_suffix(self.operation),
        )

        event: Optional[Mapping[str, Any]] = None
        if outbox_id is not None:
            event = _event_envelope(
                event_id=outbox_id,
                event_type=_EVENT_TYPES[self.operation],
                profile=profile,
                affected_versions=affected_versions,
                actor=actor,
                occurred_at=now,
            )
            self._validate_event(event)
            uow.put(
                "outbox_events",
                outbox_id,
                event,
                checkpoint="outbox." + _checkpoint_suffix(self.operation),
            )

        safe_response = _safe_response(
            profile=profile,
            affected_versions=affected_versions,
            event_types=event_types,
            completed_at=now,
        )
        self._validate_response(safe_response)
        completed = {
            **pending,
            "status": "COMPLETED",
            "target_aggregate_version": profile.aggregate_version,
            "affected_version_ids": tuple(
                item.profile_version_id for item in affected_versions
            ),
            "event_types": event_types,
            "completed_at": _timestamp(now),
            "safe_response": safe_response,
        }
        uow.put(
            "command_receipts",
            receipt_id,
            completed,
            checkpoint="receipt.completed",
        )
        result = CreatorProfileCommandResult(
            profile=profile,
            affected_versions=affected_versions,
            replayed=False,
            event_types=event_types,
            completed_at=now,
        )
        return result, pending, completed, event

    def _apply_domain(
        self,
        *,
        uow: Any,
        actor: CreatorProfileActorContext,
        command: Any,
        target_profile_id: str,
        new_version_id: Optional[str],
        hold_result: Optional[CreatorProfileSafetyHoldResult],
        now: datetime,
    ) -> tuple[CreatorProfile, Tuple[ProfileVersion, ...]]:
        profiles = tuple(uow.values("creator_profiles"))
        if self.operation == "create":
            collided = uow.get("creator_profiles", target_profile_id)
            if collided is not None:
                if (
                    isinstance(collided, CreatorProfile)
                    and collided.owner_user_id == actor.actor_user_id
                ):
                    _fail("PROFILE_ALREADY_EXISTS")
                _fail("SERVICE_UNAVAILABLE")
            if any(
                isinstance(item, CreatorProfile)
                and item.owner_user_id == actor.actor_user_id
                for item in profiles
            ):
                _fail("PROFILE_ALREADY_EXISTS")
            return (
                CreatorProfile.create(
                    profile_id=target_profile_id,
                    owner_user_id=actor.actor_user_id,
                    now=now,
                ),
                (),
            )

        profile = uow.get("creator_profiles", command.profile_id)
        if (
            not isinstance(profile, CreatorProfile)
            or profile.owner_user_id != actor.actor_user_id
        ):
            _fail("RESOURCE_NOT_FOUND")
        if profile.aggregate_version != command.expected_version:
            _fail("PRECONDITION_FAILED")
        versions = tuple(
            item
            for item in uow.values("profile_versions")
            if isinstance(item, ProfileVersion) and item.profile_id == profile.profile_id
        )

        if self.operation == "save":
            taxonomy = uow.get("taxonomy_bundles", command.taxonomy_bundle_id)
            if not isinstance(taxonomy, Mapping) or taxonomy.get("status") != "ACTIVE":
                _fail("TAXONOMY_BUNDLE_CHANGED")
            if new_version_id is None:
                _fail("SERVICE_UNAVAILABLE")
            if uow.get("profile_versions", new_version_id) is not None:
                _fail("SERVICE_UNAVAILABLE")
            old_draft = (
                uow.get("profile_versions", profile.current_draft_version_id)
                if profile.current_draft_version_id
                else None
            )
            root, draft = profile.save_draft(
                profile_version_id=new_version_id,
                taxonomy_bundle_id=command.taxonomy_bundle_id,
                based_on_profile_version_id=command.based_on_profile_version_id,
                content=command.content,
                actor_user_id=actor.actor_user_id,
                now=now,
                existing_versions=versions,
            )
            affected: list[ProfileVersion] = []
            if isinstance(old_draft, ProfileVersion):
                affected.append(replace(old_draft, status=ProfileVersionStatus.DISCARDED))
            affected.append(draft)
            return root, tuple(affected)

        if self.operation == "publish":
            if command.confirmed is not True:
                _fail("PROFILE_VALIDATION_FAILED")
            draft = uow.get("profile_versions", command.profile_version_id)
            if not isinstance(draft, ProfileVersion):
                _fail("RESOURCE_NOT_FOUND")
            if profile.current_draft_version_id != draft.profile_version_id:
                _fail("INVALID_STATE_TRANSITION")
            _require_profile_version_hash(draft)
            taxonomy = uow.get("taxonomy_bundles", draft.taxonomy_bundle_id)
            if not isinstance(taxonomy, Mapping) or taxonomy.get("status") != "ACTIVE":
                _fail("TAXONOMY_BUNDLE_CHANGED")
            evidence_snapshot = _require_evidence_for_publish(
                uow=uow,
                version=draft,
                owner_user_id=actor.actor_user_id,
                now=now,
            )
            _require_current_hold(
                hold_result,
                profile=profile,
                version=draft,
                actor_user_id=actor.actor_user_id,
                now=now,
                policy_version=self._safety_hold_policy_version,
            )
            old_published = (
                uow.get("profile_versions", profile.current_published_version_id)
                if profile.current_published_version_id
                else None
            )
            root, published = profile.publish(
                profile_version=draft,
                actor_user_id=actor.actor_user_id,
                now=now,
                existing_versions=versions,
                confirmed_evidence_versions=evidence_snapshot,
            )
            affected = []
            if isinstance(old_published, ProfileVersion):
                superseded = replace(
                    old_published, status=ProfileVersionStatus.SUPERSEDED
                )
                require_profile_version_immutable(
                    before=old_published,
                    after=superseded,
                )
                affected.append(superseded)
            affected.append(published)
            return root, tuple(affected)

        if self.operation == "pause":
            return profile.pause(reason_code=command.reason_code, now=now), ()

        if self.operation == "resume":
            published = uow.get(
                "profile_versions", profile.current_published_version_id
            )
            if not isinstance(published, ProfileVersion):
                _fail("INVALID_STATE_TRANSITION")
            _require_profile_version_hash(published)
            _require_current_hold(
                hold_result,
                profile=profile,
                version=published,
                actor_user_id=actor.actor_user_id,
                now=now,
                policy_version=self._safety_hold_policy_version,
            )
            return profile.resume(now=now), ()

        if self.operation == "archive":
            affected = []
            if profile.current_draft_version_id:
                draft = uow.get(
                    "profile_versions", profile.current_draft_version_id
                )
                if isinstance(draft, ProfileVersion):
                    affected.append(
                        replace(draft, status=ProfileVersionStatus.DISCARDED)
                    )
            if profile.current_published_version_id:
                published = uow.get(
                    "profile_versions", profile.current_published_version_id
                )
                if isinstance(published, ProfileVersion):
                    retired = replace(
                        published, status=ProfileVersionStatus.RETIRED
                    )
                    require_profile_version_immutable(
                        before=published,
                        after=retired,
                    )
                    affected.append(retired)
            return (
                profile.archive(reason_code=command.reason_code, now=now),
                tuple(affected),
            )
        _fail("INVALID_REQUEST")

    def _write_business_facts(
        self,
        *,
        uow: Any,
        command: Any,
        profile: CreatorProfile,
        affected_versions: Tuple[ProfileVersion, ...],
    ) -> None:
        if self.operation == "save":
            for version in affected_versions:
                checkpoint = (
                    "profile_version.draft"
                    if version.status is ProfileVersionStatus.DRAFT
                    else "profile_version.discarded"
                )
                uow.put(
                    "profile_versions",
                    version.profile_version_id,
                    version,
                    checkpoint=checkpoint,
                )
        elif self.operation == "publish":
            for version in affected_versions:
                checkpoint = (
                    "profile_version.published"
                    if version.status is ProfileVersionStatus.PUBLISHED
                    else "profile_version.superseded"
                )
                uow.put(
                    "profile_versions",
                    version.profile_version_id,
                    version,
                    checkpoint=checkpoint,
                )
        elif self.operation == "archive":
            for version in affected_versions:
                uow.put(
                    "profile_versions",
                    version.profile_version_id,
                    version,
                    checkpoint=(
                        "profile_version.retired"
                        if version.status is ProfileVersionStatus.RETIRED
                        else "profile_version.discarded"
                    ),
                )
        uow.put(
            "creator_profiles",
            profile.profile_id,
            profile,
            checkpoint="profile.root",
        )

    def _validate_event(self, event: Mapping[str, Any]) -> None:
        try:
            self._event_validator.validate(event, "profile-v1.schema.json")
        except Exception:
            _fail("SERVICE_UNAVAILABLE")

    def _validate_response(self, response: Mapping[str, Any]) -> None:
        try:
            self._safe_response_validator.validate(
                response, "profile-command-response-v1"
            )
        except Exception:
            _fail("SERVICE_UNAVAILABLE")

    def _replay_or_conflict(
        self,
        *,
        receipt: Mapping[str, Any],
        payload_hash: str,
        snapshot: Mapping[str, Mapping[str, Any]],
    ) -> CreatorProfileCommandResult:
        stored_hash = receipt.get("payload_hash")
        if not isinstance(stored_hash, str) or not hmac.compare_digest(
            stored_hash, payload_hash
        ):
            _fail("IDEMPOTENCY_KEY_REUSED")
        if receipt.get("status") != "COMPLETED":
            _fail("SERVICE_UNAVAILABLE")
        safe_response = receipt.get("safe_response")
        if not isinstance(safe_response, Mapping):
            _fail("SERVICE_UNAVAILABLE")
        self._validate_response(safe_response)
        return _result_from_receipt(receipt=receipt, snapshot=snapshot)

    def _recover_commit_unknown(
        self,
        *,
        identity: Mapping[str, Any],
        payload_hash: str,
    ) -> Optional[CreatorProfileCommandResult]:
        snapshot = self._safe_snapshot()
        receipt = _find_identity_receipt(
            snapshot.get("command_receipts", {}), identity
        )
        if receipt is None:
            return None
        return self._replay_or_conflict(
            receipt=receipt,
            payload_hash=payload_hash,
            snapshot=snapshot,
        )


class CreateCreatorProfileHandler(_CreatorProfileHandler):
    operation = "create"

    def handle(
        self,
        *,
        actor: CreatorProfileActorContext,
        command: CreateCreatorProfileCommand,
    ) -> CreatorProfileCommandResult:
        return self._handle(actor=actor, command=command)


class SaveCreatorProfileDraftHandler(_CreatorProfileHandler):
    operation = "save"

    def handle(
        self,
        *,
        actor: CreatorProfileActorContext,
        command: SaveCreatorProfileDraftCommand,
    ) -> CreatorProfileCommandResult:
        return self._handle(actor=actor, command=command)


class PublishCreatorProfileVersionHandler(_CreatorProfileHandler):
    operation = "publish"

    def handle(
        self,
        *,
        actor: CreatorProfileActorContext,
        command: PublishCreatorProfileVersionCommand,
    ) -> CreatorProfileCommandResult:
        return self._handle(actor=actor, command=command)


class PauseCreatorProfileHandler(_CreatorProfileHandler):
    operation = "pause"

    def handle(
        self,
        *,
        actor: CreatorProfileActorContext,
        command: PauseCreatorProfileCommand,
    ) -> CreatorProfileCommandResult:
        return self._handle(actor=actor, command=command)


class ResumeCreatorProfileHandler(_CreatorProfileHandler):
    operation = "resume"

    def handle(
        self,
        *,
        actor: CreatorProfileActorContext,
        command: ResumeCreatorProfileCommand,
    ) -> CreatorProfileCommandResult:
        return self._handle(actor=actor, command=command)


class ArchiveCreatorProfileHandler(_CreatorProfileHandler):
    operation = "archive"

    def handle(
        self,
        *,
        actor: CreatorProfileActorContext,
        command: ArchiveCreatorProfileCommand,
    ) -> CreatorProfileCommandResult:
        return self._handle(actor=actor, command=command)


def _fail(code: str) -> None:
    raise CreatorProfileApplicationError(code)


def _command_profile_id(command: Any) -> Optional[str]:
    value = getattr(command, "profile_id", None)
    return value if isinstance(value, str) else None


def _command_body(operation: str, command: Any) -> Mapping[str, Any]:
    if operation in ("create", "resume"):
        return {}
    if operation == "save":
        return {
            "taxonomy_bundle_id": command.taxonomy_bundle_id,
            "based_on_profile_version_id": command.based_on_profile_version_id,
            "content": _content_mapping(command.content),
        }
    if operation == "publish":
        return {"confirmed": command.confirmed}
    if operation in ("pause", "archive"):
        reason = command.reason_code
        return {"reason_code": reason.value if isinstance(reason, Enum) else reason}
    _fail("INVALID_REQUEST")


def _canonical_path(operation: str, command: Any) -> str:
    path = _CANONICAL_PATHS[operation]
    if operation == "publish":
        version_id = getattr(command, "profile_version_id", None)
        if not isinstance(version_id, str) or not version_id:
            _fail("INVALID_REQUEST")
        return path.replace("{profile_version_id}", version_id)
    return path


def _content_mapping(content: ProfileContent) -> Mapping[str, Any]:
    if not isinstance(content, ProfileContent):
        _fail("INVALID_REQUEST")
    result: dict[str, Any] = {}
    for member in content.members:
        if not isinstance(member, tuple) or len(member) != 2 or member[0] in result:
            _fail("INVALID_REQUEST")
        result[member[0]] = _content_value(member[1])
    return result


def _content_value(value: Any) -> Any:
    if isinstance(value, ProfileContent):
        return _content_mapping(value)
    if isinstance(value, tuple):
        return [_content_value(child) for child in value]
    if value is None or isinstance(value, (bool, int, str)):
        return value
    _fail("INVALID_REQUEST")


def _content_evidence_ids(content: ProfileContent) -> Tuple[str, ...]:
    found: set[str] = set()

    def visit(value: Any) -> None:
        if isinstance(value, ProfileContent):
            mapping = dict(value.members)
            evidence = mapping.get("evidence_ids")
            if isinstance(evidence, tuple):
                for item in evidence:
                    if isinstance(item, str):
                        found.add(item)
            for child in mapping.values():
                visit(child)
        elif isinstance(value, tuple):
            for child in value:
                visit(child)

    visit(content)
    return tuple(sorted(found))


def _find_identity_receipt(
    receipts: Mapping[str, Any],
    identity: Mapping[str, Any],
) -> Optional[Mapping[str, Any]]:
    matches = []
    for receipt in receipts.values():
        if not isinstance(receipt, Mapping):
            continue
        if all(receipt.get(key) == value for key, value in identity.items()):
            matches.append(receipt)
    if len(matches) > 1:
        _fail("SERVICE_UNAVAILABLE")
    return matches[0] if matches else None


def _preflight_hold_target(
    *,
    operation: str,
    command: Any,
    actor: CreatorProfileActorContext,
    snapshot: Mapping[str, Mapping[str, Any]],
) -> tuple[CreatorProfile, ProfileVersion]:
    profile = snapshot.get("creator_profiles", {}).get(command.profile_id)
    if not isinstance(profile, CreatorProfile) or profile.owner_user_id != actor.actor_user_id:
        _fail("RESOURCE_NOT_FOUND")
    if profile.aggregate_version != command.expected_version:
        _fail("PRECONDITION_FAILED")
    if operation == "publish":
        if profile.status not in (CreatorProfileStatus.DRAFT, CreatorProfileStatus.ACTIVE):
            _fail("INVALID_STATE_TRANSITION")
        if profile.current_draft_version_id != command.profile_version_id:
            _fail("INVALID_STATE_TRANSITION")
        version_id = command.profile_version_id
    else:
        if profile.status is not CreatorProfileStatus.PAUSED:
            _fail("INVALID_STATE_TRANSITION")
        version_id = profile.current_published_version_id
    version = snapshot.get("profile_versions", {}).get(version_id)
    if not isinstance(version, ProfileVersion):
        _fail("SERVICE_UNAVAILABLE")
    return profile, version


def _require_profile_version_hash(version: ProfileVersion) -> None:
    try:
        actual = profile_version_content_sha256(
            profile_id=version.profile_id,
            version_no=version.version_no,
            taxonomy_bundle_id=version.taxonomy_bundle_id,
            content=version.content,
        )
    except CreatorProfileDomainError:
        _fail("SERVICE_UNAVAILABLE")
    if not hmac.compare_digest(actual, version.content_sha256):
        _fail("SERVICE_UNAVAILABLE")


def _require_current_hold(
    hold: Optional[CreatorProfileSafetyHoldResult],
    *,
    profile: CreatorProfile,
    version: ProfileVersion,
    actor_user_id: str,
    now: datetime,
    policy_version: str,
) -> None:
    if hold is None or hold.decision is not CreatorProfileHoldDecision.ALLOW:
        _fail("SERVICE_UNAVAILABLE")
    if (
        hold.profile_id != profile.profile_id
        or hold.prospective_aggregate_version != profile.aggregate_version + 1
        or not hmac.compare_digest(hold.content_sha256, version.content_sha256)
        or hold.actor_user_id != actor_user_id
        or hold.policy_version != policy_version
        or hold.evaluated_at > now
        or hold.valid_until <= now
    ):
        raise _HoldTargetDrift()


def _require_evidence_for_publish(
    *,
    uow: Any,
    version: ProfileVersion,
    owner_user_id: str,
    now: datetime,
) -> Tuple[Tuple[str, int, str], ...]:
    snapshots = []
    for evidence_id in _content_evidence_ids(version.content):
        evidence = uow.get("capability_evidence", evidence_id)
        if (
            evidence is None
            or getattr(evidence, "owner_user_id", None) != owner_user_id
            or getattr(evidence, "status", None) is None
            or getattr(evidence.status, "value", evidence.status) != "VERIFIED"
            or not is_profile_field_effective(
                expires_at=getattr(evidence, "expires_at", None),
                server_now=now,
            )
        ):
            _fail("PROFILE_VALIDATION_FAILED")
        snapshots.append(
            (
                evidence_id,
                getattr(evidence, "aggregate_version", 0),
                "VERIFIED",
            )
        )
    return tuple(snapshots)


def _checkpoint_suffix(operation: str) -> str:
    return {
        "create": "profile_created",
        "save": "profile_draft_saved",
        "publish": "profile_published",
        "pause": "profile_paused",
        "resume": "profile_resumed",
        "archive": "profile_archived",
    }[operation]


def _timestamp(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _event_envelope(
    *,
    event_id: str,
    event_type: str,
    profile: CreatorProfile,
    affected_versions: Tuple[ProfileVersion, ...],
    actor: CreatorProfileActorContext,
    occurred_at: datetime,
) -> Mapping[str, Any]:
    if event_type == "CreatorProfilePublished":
        version = next(
            (
                item
                for item in affected_versions
                if item.status is ProfileVersionStatus.PUBLISHED
            ),
            None,
        )
        if version is None:
            _fail("SERVICE_UNAVAILABLE")
        payload: Mapping[str, Any] = {
            "profile_id": profile.profile_id,
            "profile_version_id": version.profile_version_id,
            "version_no": version.version_no,
            "content_sha256": version.content_sha256,
            "taxonomy_bundle_id": version.taxonomy_bundle_id,
            "status": profile.status.value,
        }
    else:
        payload = {
            "profile_id": profile.profile_id,
            "owner_user_id": profile.owner_user_id,
            "status": profile.status.value,
        }
    return {
        "event_id": event_id,
        "event_type": event_type,
        "schema_version": 1,
        "occurred_at": _timestamp(occurred_at),
        "aggregate_type": "CreatorProfile",
        "aggregate_id": profile.profile_id,
        "aggregate_version": profile.aggregate_version,
        "actor_kind": "USER",
        "actor_id": actor.actor_user_id,
        "original_actor_id": actor.original_actor_id,
        "correlation_id": actor.correlation_id,
        "causation_id": actor.causation_id,
        "trace_id": actor.trace_id,
        "organization_id": None,
        "payload": payload,
    }


def _safe_response(
    *,
    profile: CreatorProfile,
    affected_versions: Tuple[ProfileVersion, ...],
    event_types: Tuple[str, ...],
    completed_at: datetime,
) -> Mapping[str, Any]:
    return {
        "profile": {
            "profile_id": profile.profile_id,
            "owner_user_id": profile.owner_user_id,
            "status": profile.status.value,
            "aggregate_version": profile.aggregate_version,
            "current_draft_version_id": profile.current_draft_version_id,
            "current_published_version_id": profile.current_published_version_id,
            "paused_at": _timestamp(profile.paused_at) if profile.paused_at else None,
            "pause_reason_code": (
                profile.pause_reason_code.value if profile.pause_reason_code else None
            ),
            "archived_at": _timestamp(profile.archived_at) if profile.archived_at else None,
            "archive_reason_code": (
                profile.archive_reason_code.value if profile.archive_reason_code else None
            ),
            "created_at": _timestamp(profile.created_at),
            "updated_at": _timestamp(profile.updated_at),
        },
        "affected_version_ids": tuple(
            item.profile_version_id for item in affected_versions
        ),
        "event_types": event_types,
        "completed_at": _timestamp(completed_at),
    }


def _result_from_receipt(
    *,
    receipt: Mapping[str, Any],
    snapshot: Mapping[str, Mapping[str, Any]],
) -> CreatorProfileCommandResult:
    safe = receipt.get("safe_response")
    profile_data = safe.get("profile") if isinstance(safe, Mapping) else None
    if not isinstance(profile_data, Mapping):
        _fail("SERVICE_UNAVAILABLE")
    try:
        from ..domain.model import ArchiveReasonCode, PauseReasonCode

        profile = CreatorProfile(
            profile_id=profile_data["profile_id"],
            owner_user_id=profile_data["owner_user_id"],
            status=CreatorProfileStatus(profile_data["status"]),
            aggregate_version=profile_data["aggregate_version"],
            current_draft_version_id=profile_data["current_draft_version_id"],
            current_published_version_id=profile_data["current_published_version_id"],
            paused_at=_parse_timestamp(profile_data["paused_at"]),
            pause_reason_code=(
                PauseReasonCode(profile_data["pause_reason_code"])
                if profile_data["pause_reason_code"] is not None
                else None
            ),
            archived_at=_parse_timestamp(profile_data["archived_at"]),
            archive_reason_code=(
                ArchiveReasonCode(profile_data["archive_reason_code"])
                if profile_data["archive_reason_code"] is not None
                else None
            ),
            created_at=_parse_timestamp(profile_data["created_at"]),
            updated_at=_parse_timestamp(profile_data["updated_at"]),
        )
        affected_ids = safe.get("affected_version_ids", ())
        versions = snapshot.get("profile_versions", {})
        affected = tuple(
            versions[version_id]
            for version_id in affected_ids
            if isinstance(versions.get(version_id), ProfileVersion)
        )
        event_types = tuple(safe.get("event_types", ()))
        completed_at = _parse_timestamp(safe["completed_at"])
        if completed_at is None:
            _fail("SERVICE_UNAVAILABLE")
    except CreatorProfileApplicationError:
        raise
    except Exception:
        _fail("SERVICE_UNAVAILABLE")
    return CreatorProfileCommandResult(
        profile=profile,
        affected_versions=affected,
        replayed=True,
        event_types=event_types,
        completed_at=completed_at,
    )


def _parse_timestamp(value: Any) -> Optional[datetime]:
    if value is None:
        return None
    if not isinstance(value, str) or not value.endswith("Z"):
        _fail("SERVICE_UNAVAILABLE")
    parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    if parsed.tzinfo is None:
        _fail("SERVICE_UNAVAILABLE")
    return parsed
