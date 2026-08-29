"""First semantic RED for Creator Profile aggregate and content invariants."""

from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
from datetime import timedelta
import hashlib
import json
from typing import Any, Callable
import unittest

from desire_platform.creator_profile.domain import (
    ArchiveReasonCode,
    CreatorProfile,
    CreatorProfileDomainError,
    CreatorProfileStatus,
    PauseReasonCode,
    ProfileDomainBehaviorNotAvailable,
    ProfileVersionStatus,
    PROFILE_DOMAIN_BEHAVIOR_NOT_AVAILABLE,
    canonical_profile_version_bytes,
    is_profile_field_effective,
    profile_version_content_sha256,
    require_profile_version_immutable,
    validate_creator_profile,
    validate_profile_version,
)
from tests.support.creator_profile_builders import (
    PROFILE_ID,
    SECOND_VERSION_ID,
    TAXONOMY_ID,
    USER_ID,
    UTC_NOW,
    VERSION_ID,
    creator_profile,
    freeze_json,
    profile_version,
    thaw_json,
    valid_content,
    valid_content_mapping,
)


def _capture(call: Callable[[], Any]) -> tuple[Any, str | None]:
    try:
        return call(), None
    except CreatorProfileDomainError as error:
        return None, error.code
    except ProfileDomainBehaviorNotAvailable as error:
        if str(error) != PROFILE_DOMAIN_BEHAVIOR_NOT_AVAILABLE:
            return None, "UNEXPECTED_DOMAIN_SENTINEL"
        return None, PROFILE_DOMAIN_BEHAVIOR_NOT_AVAILABLE
    except Exception as error:
        return None, "UNEXPECTED:" + type(error).__name__


def _validate_version(version, *, profile=None, for_publish=False):
    return validate_profile_version(
        version,
        profile=profile or creator_profile(),
        prior_versions=(),
        server_now=UTC_NOW,
        for_publish=for_publish,
    )


class CreatorProfileDomainSemanticRedTest(unittest.TestCase):
    """TEST-UNIT-PROFILE-001 and TEST-PROP-PROFILE-001."""

    def test_immutable_values_hide_content_and_reject_in_place_mutation(self) -> None:
        profile = creator_profile()
        version = profile_version()
        rendered = repr((profile, version, version.content))
        self.assertNotIn("minimum_project_amount_minor", rendered)
        self.assertNotIn("organization_conflict_0001", rendered)
        with self.assertRaises(FrozenInstanceError):
            profile.status = CreatorProfileStatus.ACTIVE  # type: ignore[misc]
        with self.assertRaises(FrozenInstanceError):
            version.content = valid_content()  # type: ignore[misc]

    def test_root_status_shape_and_pointer_invariants_are_closed(self) -> None:
        cases = (
            ("draft", creator_profile(), (), None),
            (
                "active-without-published",
                creator_profile(status=CreatorProfileStatus.ACTIVE),
                (),
                "INVALID_STATE_TRANSITION",
            ),
            (
                "paused-without-shape",
                creator_profile(status=CreatorProfileStatus.PAUSED),
                (),
                "INVALID_STATE_TRANSITION",
            ),
            (
                "archived-keeps-draft",
                creator_profile(
                    status=CreatorProfileStatus.ARCHIVED,
                    current_draft_version_id=VERSION_ID,
                    archived_at=UTC_NOW,
                    archive_reason_code=ArchiveReasonCode.OWNER_REQUEST,
                ),
                (profile_version(),),
                "INVALID_STATE_TRANSITION",
            ),
        )
        observations = []
        for name, profile, versions, expected in cases:
            _value, code = _capture(
                lambda profile=profile, versions=versions: validate_creator_profile(
                    profile,
                    versions=versions,
                )
            )
            observations.append((name, code, expected))
        self.assertEqual(
            [(name, code) for name, code, _expected in observations],
            [(name, expected) for name, _code, expected in observations],
        )

    def test_create_pause_resume_archive_and_archived_terminality(self) -> None:
        created, create_code = _capture(
            lambda: CreatorProfile.create(
                profile_id=PROFILE_ID,
                owner_user_id=USER_ID,
                now=UTC_NOW,
            )
        )
        active = creator_profile(
            status=CreatorProfileStatus.ACTIVE,
            aggregate_version=3,
            current_published_version_id=VERSION_ID,
        )
        paused, pause_code = _capture(
            lambda: active.pause(
                reason_code=PauseReasonCode.OWNER_REQUEST,
                now=UTC_NOW,
            )
        )
        paused_root = creator_profile(
            status=CreatorProfileStatus.PAUSED,
            aggregate_version=4,
            current_published_version_id=VERSION_ID,
            paused_at=UTC_NOW - timedelta(minutes=1),
            pause_reason_code=PauseReasonCode.OWNER_REQUEST,
        )
        resumed, resume_code = _capture(lambda: paused_root.resume(now=UTC_NOW))
        archived, archive_code = _capture(
            lambda: active.archive(
                reason_code=ArchiveReasonCode.OWNER_REQUEST,
                now=UTC_NOW,
            )
        )
        archived_root = creator_profile(
            status=CreatorProfileStatus.ARCHIVED,
            aggregate_version=5,
            archived_at=UTC_NOW,
            archive_reason_code=ArchiveReasonCode.OWNER_REQUEST,
        )
        _illegal, illegal_code = _capture(
            lambda: archived_root.resume(now=UTC_NOW + timedelta(seconds=1))
        )
        self.assertEqual(
            {
                "create_code": create_code,
                "created_status": getattr(created, "status", None),
                "created_version": getattr(created, "aggregate_version", None),
                "pause_code": pause_code,
                "paused_status": getattr(paused, "status", None),
                "resume_code": resume_code,
                "resumed_status": getattr(resumed, "status", None),
                "archive_code": archive_code,
                "archived_status": getattr(archived, "status", None),
                "illegal_code": illegal_code,
            },
            {
                "create_code": None,
                "created_status": CreatorProfileStatus.DRAFT,
                "created_version": 1,
                "pause_code": None,
                "paused_status": CreatorProfileStatus.PAUSED,
                "resume_code": None,
                "resumed_status": CreatorProfileStatus.ACTIVE,
                "archive_code": None,
                "archived_status": CreatorProfileStatus.ARCHIVED,
                "illegal_code": "INVALID_STATE_TRANSITION",
            },
        )

    def test_each_save_appends_one_version_and_discards_exact_prior_draft(self) -> None:
        empty = creator_profile()
        first, first_code = _capture(
            lambda: empty.save_draft(
                profile_version_id=VERSION_ID,
                taxonomy_bundle_id=TAXONOMY_ID,
                based_on_profile_version_id=None,
                content=valid_content(),
                actor_user_id=USER_ID,
                now=UTC_NOW,
                existing_versions=(),
            )
        )
        root_with_draft = creator_profile(
            aggregate_version=2,
            current_draft_version_id=VERSION_ID,
        )
        prior = profile_version()
        second, second_code = _capture(
            lambda: root_with_draft.save_draft(
                profile_version_id=SECOND_VERSION_ID,
                taxonomy_bundle_id=TAXONOMY_ID,
                based_on_profile_version_id=VERSION_ID,
                content=valid_content(),
                actor_user_id=USER_ID,
                now=UTC_NOW + timedelta(seconds=1),
                existing_versions=(prior,),
            )
        )
        first_root = first[0] if isinstance(first, tuple) else None
        first_version = first[1] if isinstance(first, tuple) else None
        second_root = second[0] if isinstance(second, tuple) else None
        second_version = second[1] if isinstance(second, tuple) else None
        self.assertEqual(
            {
                "first_code": first_code,
                "first_no": getattr(first_version, "version_no", None),
                "first_pointer": getattr(first_root, "current_draft_version_id", None),
                "second_code": second_code,
                "second_no": getattr(second_version, "version_no", None),
                "second_based_on": getattr(second_version, "based_on_profile_version_id", None),
                "second_pointer": getattr(second_root, "current_draft_version_id", None),
            },
            {
                "first_code": None,
                "first_no": 1,
                "first_pointer": VERSION_ID,
                "second_code": None,
                "second_no": 2,
                "second_based_on": VERSION_ID,
                "second_pointer": SECOND_VERSION_ID,
            },
        )

    def test_profile_version_jcs_bytes_and_sha_cover_exact_canonical_root(self) -> None:
        content = valid_content()
        mapping = thaw_json(content)
        reordered = freeze_json(dict(reversed(tuple(mapping.items()))))
        canonical, canonical_code = _capture(
            lambda: canonical_profile_version_bytes(
                profile_id=PROFILE_ID,
                version_no=1,
                taxonomy_bundle_id=TAXONOMY_ID,
                content=content,
            )
        )
        reordered_bytes, reorder_code = _capture(
            lambda: canonical_profile_version_bytes(
                profile_id=PROFILE_ID,
                version_no=1,
                taxonomy_bundle_id=TAXONOMY_ID,
                content=reordered,
            )
        )
        digest, digest_code = _capture(
            lambda: profile_version_content_sha256(
                profile_id=PROFILE_ID,
                version_no=1,
                taxonomy_bundle_id=TAXONOMY_ID,
                content=content,
            )
        )
        expected_bytes = json.dumps(
            {
                "canonicalization_version": "profile-version-json-v1",
                "content": mapping,
                "profile_id": PROFILE_ID,
                "profile_schema_version": 1,
                "taxonomy_bundle_id": TAXONOMY_ID,
                "version_no": 1,
            },
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        self.assertEqual(
            {
                "canonical_code": canonical_code,
                "canonical": canonical,
                "reorder_code": reorder_code,
                "order_independent": reordered_bytes == canonical,
                "digest_code": digest_code,
                "digest": digest,
            },
            {
                "canonical_code": None,
                "canonical": expected_bytes,
                "reorder_code": None,
                "order_independent": True,
                "digest_code": None,
                "digest": hashlib.sha256(expected_bytes).hexdigest(),
            },
        )

    def test_visibility_bool_overlap_and_closed_content_fail_before_publish(self) -> None:
        invalid_mappings = []
        public_compensation = valid_content_mapping()
        public_compensation["compensation"]["visibility"] = "PUBLIC"
        invalid_mappings.append(public_compensation)
        bool_proficiency = valid_content_mapping()
        bool_proficiency["skills"][0]["proficiency"] = True
        invalid_mappings.append(bool_proficiency)
        prohibited_interest = valid_content_mapping()
        prohibited_interest["boundaries"]["prohibited_tasks"][0]["code"] = (
            prohibited_interest["interests"][0]["task_code"]
        )
        invalid_mappings.append(prohibited_interest)
        unknown_field = valid_content_mapping()
        unknown_field["skills"][0]["provider_token"] = "private"
        invalid_mappings.append(unknown_field)

        observed_codes = []
        for mapping in invalid_mappings:
            version = profile_version(content=freeze_json(mapping))
            _value, code = _capture(lambda version=version: _validate_version(version))
            observed_codes.append(code)
        self.assertEqual(
            observed_codes,
            ["PROFILE_VALIDATION_FAILED"] * len(invalid_mappings),
        )

    def test_publish_requires_complete_current_draft_and_valid_version_chain(self) -> None:
        incomplete = valid_content_mapping()
        incomplete.update(
            {
                "interests": [],
                "skills": [],
                "availability": None,
                "boundaries": None,
            }
        )
        invalid = profile_version(content=freeze_json(incomplete))
        valid = profile_version()
        _invalid_value, invalid_code = _capture(
            lambda: _validate_version(invalid, for_publish=True)
        )
        valid_value, valid_code = _capture(
            lambda: _validate_version(valid, for_publish=True)
        )
        self.assertEqual(
            {
                "invalid_code": invalid_code,
                "valid_code": valid_code,
                "valid_result": valid_value,
            },
            {
                "invalid_code": "PROFILE_VALIDATION_FAILED",
                "valid_code": None,
                "valid_result": None,
            },
        )

    def test_expiry_is_exclusive_and_equality_is_immediately_ineffective(self) -> None:
        observations = []
        for expires_at in (
            None,
            UTC_NOW + timedelta(microseconds=1),
            UTC_NOW,
            UTC_NOW - timedelta(microseconds=1),
        ):
            value, code = _capture(
                lambda expires_at=expires_at: is_profile_field_effective(
                    expires_at=expires_at,
                    server_now=UTC_NOW,
                )
            )
            observations.append((value, code))
        self.assertEqual(
            observations,
            [(True, None), (True, None), (False, None), (False, None)],
        )

    def test_published_content_and_canonical_metadata_are_immutable(self) -> None:
        before = profile_version(
            status=ProfileVersionStatus.PUBLISHED,
            confirmed=True,
        )
        same, same_code = _capture(
            lambda: require_profile_version_immutable(before=before, after=before)
        )
        changed_content = replace(before, content=freeze_json({"tampered": True}))
        _changed, changed_code = _capture(
            lambda: require_profile_version_immutable(
                before=before,
                after=changed_content,
            )
        )
        changed_taxonomy = replace(before, taxonomy_bundle_id="taxonomy_other_000001")
        _taxonomy, taxonomy_code = _capture(
            lambda: require_profile_version_immutable(
                before=before,
                after=changed_taxonomy,
            )
        )
        self.assertEqual(
            {
                "same": same,
                "same_code": same_code,
                "changed_code": changed_code,
                "taxonomy_code": taxonomy_code,
            },
            {
                "same": None,
                "same_code": None,
                "changed_code": "INVALID_STATE_TRANSITION",
                "taxonomy_code": "INVALID_STATE_TRANSITION",
            },
        )


if __name__ == "__main__":
    unittest.main()
