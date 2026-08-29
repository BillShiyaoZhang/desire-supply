"""Fast closed-surface checks for the Matching PostgreSQL runtime."""

from __future__ import annotations

import ast
from dataclasses import replace
import inspect
from uuid import UUID

import pytest

from desire_platform.matching.adapters.postgres.runtime import (
    CandidateSelectionMutation,
    CandidateSelectionOperation,
    CreatorInvitationMutation,
    CreatorInvitationOperation,
    MatchingCommandContext,
    MatchingCreatorContext,
    MatchingPostgresConfigurationError,
    MatchingPostgresSettings,
    MatchingSelectorDiscoveryContext,
    MatchingSelectorContext,
    MatchingWriteMaterial,
    PsycopgMatchingRuntime,
    RecipientInvitationView,
)


def uid(value: int) -> UUID:
    return UUID(f"a{value:07x}-0000-4000-8000-000000000001")


class Source:
    def checkout(self):
        raise AssertionError("unit validation must be zero-checkout")

    def release(self, connection):
        del connection

    def discard(self, connection):
        del connection


def material(*, choose: bool = False, close: bool = False) -> MatchingWriteMaterial:
    return MatchingWriteMaterial(
        receipt_id=uid(10),
        fact_id=uid(11) if choose or not close else None,
        audit_event_id=uid(12),
        primary_outbox_event_id=uid(13),
        secondary_outbox_event_id=None if choose else uid(14),
        identity_key_id="matching-idempotency-v1",
        identity_digest=b"i" * 32,
        payload_hash_key_id="matching-payload-v1",
        payload_hash=b"p" * 32,
    )


def test_role_sources_must_be_distinct_and_settings_are_closed() -> None:
    source = Source()
    with pytest.raises(TypeError):
        PsycopgMatchingRuntime(
            creator_connections=source,
            selector_connections=source,
        )
    with pytest.raises(ValueError):
        MatchingPostgresSettings(selector_role="matching_creator")


def test_readiness_timeout_and_closed_state_fail_before_checkout() -> None:
    runtime = PsycopgMatchingRuntime(
        creator_connections=Source(),
        selector_connections=Source(),
    )
    for invalid in (True, 0, 30_001):
        with pytest.raises(ValueError):
            runtime.check_readiness(invalid)
    runtime.close()
    with pytest.raises(MatchingPostgresConfigurationError):
        runtime.check_readiness(1_000)


def test_recipient_view_declares_each_wire_field_once() -> None:
    syntax = ast.parse(inspect.getsource(RecipientInvitationView))
    declaration = syntax.body[0]
    assert isinstance(declaration, ast.ClassDef)
    names = tuple(
        node.target.id
        for node in declaration.body
        if isinstance(node, ast.AnnAssign)
        and isinstance(node.target, ast.Name)
    )
    assert names == (
        "invitation_id",
        "status",
        "aggregate_version",
        "updated_at",
        "expires_at",
        "snapshot_sha256",
        "response_status",
        "disclosure",
    )


def test_selector_discovery_context_has_no_assignment_guess() -> None:
    context = MatchingSelectorDiscoveryContext(
        actor_user_id=uid(15),
        session_id=uid(16),
        organization_id=uid(17),
        authority_marker_sha256=b"d" * 32,
    )
    assert context.organization_id == uid(17)
    assert "assignment" not in context.__dataclass_fields__
    assert (b"d" * 32).hex() not in repr(context)


def test_selector_detail_read_has_no_direct_relation_authority() -> None:
    source = inspect.getsource(PsycopgMatchingRuntime.read_selection)
    assert "read_selection_by_id" in source
    assert "candidate_selector_assignments" not in source
    assert "selection_projection_v1" not in source
    assert "authority_statement" not in inspect.signature(
        PsycopgMatchingRuntime._read
    ).parameters


def test_creator_secrets_are_redacted_and_accept_shape_is_exact() -> None:
    creator = MatchingCreatorContext(uid(1), uid(2), b"a" * 32)
    request = CreatorInvitationMutation(
        operation=CreatorInvitationOperation.DECLINE,
        creator=creator,
        command=MatchingCommandContext(uid(3), uid(4), uid(5)),
        organization_id=uid(6),
        invitation_id=uid(7),
        expected_invitation_version=2,
        expected_snapshot_sha256=b"s" * 32,
        reason_code="NOT_AVAILABLE",
        restricted_note="private scheduling detail",
        material=material(),
    )
    rendered = repr(request)
    for secret in (
        "private scheduling detail",
        (b"a" * 32).hex(),
        (b"i" * 32).hex(),
        (b"p" * 32).hex(),
    ):
        assert secret not in rendered
    with pytest.raises(ValueError):
        replace(
            request,
            operation=CreatorInvitationOperation.ACCEPT,
            reason_code="NOT_AVAILABLE",
        )


def test_selector_requires_exact_assignment_version_and_mutation_shape() -> None:
    selector = MatchingSelectorContext(
        actor_user_id=uid(20),
        session_id=uid(21),
        organization_id=uid(22),
        selection_id=uid(23),
        assignment_id=uid(24),
        assignment_version=7,
        authority_marker_sha256=b"m" * 32,
    )
    choose = CandidateSelectionMutation(
        operation=CandidateSelectionOperation.CHOOSE,
        selector=selector,
        command=MatchingCommandContext(uid(25), uid(26), uid(27)),
        expected_selection_version=4,
        expected_invitation_set_sha256=b"h" * 32,
        invitation_id=uid(28),
        selection_basis_code="CAPABILITY_FIT",
        reason_code=None,
        material=material(choose=True),
    )
    assert choose.selector.assignment_version == 7
    with pytest.raises(ValueError):
        replace(choose, invitation_id=None)
    with pytest.raises(ValueError):
        replace(
            choose,
            operation=CandidateSelectionOperation.CLOSE,
            reason_code="NO_AVAILABLE_CREATOR",
        )
