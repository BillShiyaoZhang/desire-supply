"""Closed application contracts for organization public-name correction."""

from dataclasses import FrozenInstanceError, replace
from datetime import datetime, timezone

import pytest

from desire_platform.identity_access.application.organization_profile import (
    OrganizationPublicNameActorContext,
    OrganizationPublicNameReasonCode,
    UpdateOrganizationPublicNameCommand,
    UpdateOrganizationPublicNameResult,
)


NOW = datetime(2026, 8, 26, 8, 0, tzinfo=timezone.utc)


def _command(**changes: object) -> UpdateOrganizationPublicNameCommand:
    values = {
        "organization_id": "organization_profile_012345",
        "expected_version": 7,
        "public_name": "Corrected Organization",
        "reason_code": OrganizationPublicNameReasonCode.PUBLIC_NAME_CORRECTION,
        "idempotency_key": "organization_profile_idem_012345",
    }
    values.update(changes)
    return UpdateOrganizationPublicNameCommand(**values)  # type: ignore[arg-type]


def _actor(**changes: object) -> OrganizationPublicNameActorContext:
    values = {
        "actor_user_id": "user_profile_0123456789",
        "current_session_id": "session_profile_0123456789",
        "original_actor_id": None,
        "correlation_id": "correlation_profile_0123456789",
        "causation_id": "causation_profile_0123456789",
        "trace_id": "trace_profile_0123456789",
        "auth_time": NOW,
        "acr_code": "urn:example:acr:mfa",
        "amr_codes": ("pwd", "otp"),
    }
    values.update(changes)
    return OrganizationPublicNameActorContext(**values)  # type: ignore[arg-type]


def test_public_name_command_is_frozen_closed_and_secret_safe() -> None:
    command = _command(public_name="A" * 160)
    assert tuple(OrganizationPublicNameReasonCode) == (
        OrganizationPublicNameReasonCode.PUBLIC_NAME_CORRECTION,
    )
    assert command.expected_version == 7
    assert "organization_profile_idem_012345" not in repr(command)
    with pytest.raises(FrozenInstanceError):
        command.public_name = "Changed"  # type: ignore[misc]


@pytest.mark.parametrize(
    "changes",
    (
        {"organization_id": ""},
        {"expected_version": True},
        {"expected_version": 0},
        {"public_name": ""},
        {"public_name": " Leading"},
        {"public_name": "Trailing "},
        {"public_name": "A" * 161},
        {"public_name": "Cafe\u0301"},
        {"public_name": "Line\nBreak"},
        {"public_name": "Hidden\u200dFormat"},
        {"reason_code": "PUBLIC_NAME_CORRECTION"},
        {"idempotency_key": "too-short"},
    ),
)
def test_public_name_command_rejects_noncanonical_or_open_inputs(
    changes: dict[str, object],
) -> None:
    with pytest.raises(ValueError):
        _command(**changes)


def test_actor_requires_closed_recent_authentication_facts() -> None:
    actor = _actor(original_actor_id="support_profile_0123456789")
    assert actor.auth_time == NOW
    assert actor.amr_codes == ("pwd", "otp")
    with pytest.raises(FrozenInstanceError):
        actor.acr_code = "changed"  # type: ignore[misc]
    for changes in (
        {"auth_time": NOW.replace(tzinfo=None)},
        {"amr_codes": ()},
        {"amr_codes": ("pwd", "pwd")},
        {"amr_codes": ("pwd", "")},
        {"original_actor_id": "user_profile_0123456789"},
    ):
        with pytest.raises(ValueError):
            _actor(**changes)


def test_result_is_frozen_mapping_and_hides_response_details() -> None:
    result = UpdateOrganizationPublicNameResult(
        replayed=True,
        organization={"public_name": "Corrected Organization", "entity_tag": '"v8"'},
    )
    assert result.replayed is True
    assert "Corrected Organization" not in repr(result)
    with pytest.raises(FrozenInstanceError):
        replace(result, replayed=False).replayed = True  # type: ignore[misc]
    with pytest.raises(ValueError):
        UpdateOrganizationPublicNameResult(replayed=1, organization={})  # type: ignore[arg-type]
