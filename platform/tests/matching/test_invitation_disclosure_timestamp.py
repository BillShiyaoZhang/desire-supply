"""Reject invalid signed timestamps before a disclosure can be persisted."""

from dataclasses import replace
from datetime import timedelta
import hashlib
import json
from types import SimpleNamespace
from uuid import UUID

import pytest

from desire_platform.matching.domain import MatchingDomainError, validate_invitation_disclosure
from desire_platform.matching.adapters.postgres.operational_runtime import (
    MatchingReviewContext, MatchingReviewPrepareInvitationRequest,
    PsycopgMatchingReviewRuntime,
)
from desire_platform.matching.adapters.postgres.runtime import MatchingPostgresConfigurationError
from tests.support.matching_builders import NOW, _snapshot


def signed_snapshot(expires_at):
    original = _snapshot()
    document = json.loads(original.canonical_bytes)
    document["expires_at"] = expires_at
    canonical = json.dumps(document, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    return replace(original, canonical_bytes=canonical, snapshot_sha256=hashlib.sha256(canonical).hexdigest())


@pytest.mark.parametrize("expires_at", ["2035-01-02T03:04:05Z", "2035-01-02T03:04:05.123456Z"])
def test_valid_v1_timestamp_retains_signed_bytes_and_digest(expires_at):
    snapshot = signed_snapshot(expires_at)
    before = snapshot.canonical_bytes, snapshot.snapshot_sha256
    validate_invitation_disclosure(snapshot)
    assert (snapshot.canonical_bytes, snapshot.snapshot_sha256) == before


@pytest.mark.parametrize("expires_at", [
    "2035-01-02T03:04:05+00:00", "2035-01-02T11:04:05+08:00",
    "2035-01-02T03:04:05", "2035-01-02T03:04:05z", "2035-02-30T03:04:05Z", None,
])
def test_well_hashed_but_invalid_v1_timestamp_is_rejected(expires_at):
    snapshot = signed_snapshot(expires_at)
    with pytest.raises(MatchingDomainError) as rejected:
        validate_invitation_disclosure(snapshot)
    assert rejected.value.code == "INVALID_REQUEST"


@pytest.mark.parametrize("expires_at,valid", [
    ("2035-01-02T03:04:05Z", True), ("2035-01-02T03:04:05+00:00", False),
])
def test_database_preparation_rejects_offset_before_create_can_receive_snapshot(expires_at, valid):
    document = json.loads(signed_snapshot(expires_at).canonical_bytes)
    document["invitation_id"] = str(UUID(int=7))
    calls = []
    def execute(**kwargs):
        calls.append(kwargs)
        return [(document,)]
    runtime = object.__new__(PsycopgMatchingReviewRuntime)
    runtime._gateway = SimpleNamespace(execute=execute)
    request = MatchingReviewPrepareInvitationRequest(
        context=MatchingReviewContext(UUID(int=1), UUID(int=2), b"a" * 32),
        organization_id=UUID(int=3), assignment_id=UUID(int=4), expected_assignment_version=1,
        match_run_id=UUID(int=5), expected_match_run_version=1, creator_user_id=UUID(int=6),
        invitation_id=UUID(int=7), snapshot_id=UUID(int=8), expires_at=NOW + timedelta(days=7),
    )
    if valid:
        prepared = runtime.prepare_invitation(request)
        assert json.loads(prepared.snapshot.canonical_bytes)["expires_at"] == expires_at
    else:
        with pytest.raises(MatchingPostgresConfigurationError):
            runtime.prepare_invitation(request)
    assert len(calls) == 1 and calls[0]["write"] is False
    assert calls[0]["operation"] == "PREPARE_INVITATION"
