"""PostgreSQL-only ORG_ADMIN public-name command handler.

The public command reuses the closed organization-administration receipt and
transaction boundary, while exposing no generic statement or memory fallback.
IAM0042 routes all six ORG_ADMIN commands through the v3 database program so a
raw idempotency key cannot be reused across command names.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any, Protocol
from uuid import UUID

from ...application.organization_profile import (
    OrganizationPublicNameActorContext,
    OrganizationPublicNameReasonCode,
    UpdateOrganizationPublicNameCommand,
    UpdateOrganizationPublicNameResult,
)
from ...domain.errors import IamError
from .organization_admin import (
    OrganizationAdminPostgresCommitOutcomeUnknownError,
    OrganizationAdminPostgresConfigurationError,
    OrganizationAdminPostgresOperation,
    PsycopgOrganizationAdminUnitOfWorkFactory,
)
from .organization_admin_handlers import (
    OrganizationAdminKeys,
    _new,
    _receipt_digest_candidates,
    _request,
    _utc,
)


_MFA_WINDOW = timedelta(minutes=10)
_MFA_ACR_CODES = frozenset(
    (
        "urn:desire:acr:mfa",
        "urn:desire:acr:synthetic-internal-sandbox:mfa",
    )
)
_MFA_AMR_CODES = frozenset(("hwk", "mfa", "otp", "webauthn"))


class OrganizationPublicNameClock(Protocol):
    def now(self) -> datetime: ...


class OrganizationPublicNameIdSource(Protocol):
    def new_id(self, purpose: str) -> UUID: ...


class PsycopgOrganizationPublicNameUnitOfWorkFactory(
    PsycopgOrganizationAdminUnitOfWorkFactory
):
    """Purpose-named construction boundary for the IAM0042 v3 program."""

    def execute(self, request: Any):
        return self.execute_update_organization_public_name(request)


class PostgresUpdateOrganizationPublicNameHandler:
    def __init__(
        self,
        *,
        uow_factory: PsycopgOrganizationPublicNameUnitOfWorkFactory,
        keys: OrganizationAdminKeys,
        clock: OrganizationPublicNameClock,
        id_source: OrganizationPublicNameIdSource,
    ) -> None:
        if not isinstance(
            uow_factory, PsycopgOrganizationPublicNameUnitOfWorkFactory
        ):
            raise TypeError("organization public-name PostgreSQL UoW is unavailable")
        if not isinstance(keys, OrganizationAdminKeys):
            raise TypeError("organization public-name receipt keys are unavailable")
        if not callable(getattr(clock, "now", None)) or not callable(
            getattr(id_source, "new_id", None)
        ):
            raise TypeError("organization public-name runtime sources are unavailable")
        self._uow_factory = uow_factory
        self._keys = keys
        self._clock = clock
        self._ids = id_source

    def handle(
        self,
        *,
        actor: OrganizationPublicNameActorContext,
        command: UpdateOrganizationPublicNameCommand,
    ) -> UpdateOrganizationPublicNameResult:
        if not isinstance(actor, OrganizationPublicNameActorContext) or not isinstance(
            command, UpdateOrganizationPublicNameCommand
        ):
            raise IamError("INVALID_REQUEST")
        now = _utc(self._clock.now())
        _require_recent_mfa(actor, now)
        reason_code = command.reason_code.value
        if reason_code != OrganizationPublicNameReasonCode.PUBLIC_NAME_CORRECTION.value:
            raise IamError("INVALID_REQUEST")
        payload = {
            "public_name": command.public_name,
            "reason_code": reason_code,
        }
        receipt_candidates = _receipt_digest_candidates(
            operation=(
                OrganizationAdminPostgresOperation.UPDATE_ORGANIZATION_PUBLIC_NAME
            ),
            organization_id=command.organization_id,
            target_id=command.organization_id,
            expected_version=command.expected_version,
            idempotency_key=command.idempotency_key,
            payload=payload,
            candidate_payloads=None,
            keys=self._keys,
        )
        request = _request(
            operation=(
                OrganizationAdminPostgresOperation.UPDATE_ORGANIZATION_PUBLIC_NAME
            ),
            actor_user_id=actor.actor_user_id,
            session_id=actor.current_session_id,
            organization_id=command.organization_id,
            target_id=command.organization_id,
            command_id=_new(self._ids, "command_receipt"),
            correlation_id=actor.correlation_id,
            trace_id=actor.trace_id,
            original_actor_id=actor.original_actor_id,
            expected_version=command.expected_version,
            idempotency_key=command.idempotency_key,
            payload=payload,
            candidate_payloads=tuple(
                (key_id, payload)
                for key_id, _material in self._keys.payload_hash_keyring
            ),
            keys=self._keys,
            now=now,
            ids=self._ids,
            invitation=None,
            issue_hold=None,
            resume_hold=None,
            reason_code=reason_code,
            recipient_contact_id=None,
            public_name=command.public_name,
        )
        # The independently calculated candidates are compared so construction
        # changes cannot silently alter receipt identity between preflight and UoW.
        if (
            request.receipt.idempotency_candidates != receipt_candidates[0]
            or request.receipt.payload_hash_candidates != receipt_candidates[1]
        ):
            raise IamError("SERVICE_UNAVAILABLE")
        try:
            result = self._uow_factory.execute(request)
        except OrganizationAdminPostgresCommitOutcomeUnknownError:
            raise IamError("COMMAND_OUTCOME_UNKNOWN") from None
        except OrganizationAdminPostgresConfigurationError:
            raise IamError("SERVICE_UNAVAILABLE") from None
        try:
            return UpdateOrganizationPublicNameResult(
                replayed=result.replayed,
                organization=dict(result.safe_response),
            )
        except (TypeError, ValueError):
            raise IamError("SERVICE_UNAVAILABLE") from None


def _require_recent_mfa(
    actor: OrganizationPublicNameActorContext, now: datetime
) -> None:
    if (
        actor.acr_code not in _MFA_ACR_CODES
        or _MFA_AMR_CODES.isdisjoint(actor.amr_codes)
        or actor.auth_time > now
        or now - actor.auth_time >= _MFA_WINDOW
    ):
        raise IamError("MFA_STEP_UP_REQUIRED")


__all__ = [
    "PostgresUpdateOrganizationPublicNameHandler",
    "PsycopgOrganizationPublicNameUnitOfWorkFactory",
]
