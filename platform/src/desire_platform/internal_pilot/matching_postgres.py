"""Production-real Matching HTTP bindings over the reviewed PostgreSQL programs.

Creator, Candidate Selector, and Operations Reviewer traffic is bound only to
the fixed ``matching_api`` programs and their least-privilege PostgreSQL roles.
This module never substitutes the Memory application and never writes a mutable
Matching table directly.
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import asdict, dataclass, field, is_dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
import hashlib
import hmac
import json
import re
from types import MappingProxyType
from typing import Any, Mapping, Optional, Tuple
from uuid import UUID

from desire_platform.matching.adapters.postgres import (
    CandidateSelectionMutation,
    CandidateSelectionOperation,
    CreatorInvitationMutation,
    CreatorInvitationOperation,
    MatchingAttemptView,
    MatchingCommandContext,
    MatchingCreatorContext,
    MatchingPostgresCommitOutcomeUnknownError,
    MatchingPostgresConfigurationError,
    MatchingPostgresRejectedError,
    MatchingSelectionView,
    MatchingSelectorContext,
    MatchingSelectorDiscoveryContext,
    MatchingWriteMaterial,
    PsycopgMatchingRuntime,
    RecipientInvitationView,
)
from desire_platform.matching.adapters.postgres.operational_runtime import (
    MatchingAssignmentContext,
    MatchingCandidateSelectorClaimRequest,
    MatchingOperationalCommandMaterial,
    MatchingReviewAssignmentSummary,
    MatchingReviewAssignmentView,
    MatchingReviewClaimRequest,
    MatchingReviewContext,
    MatchingReviewCreateInvitationRequest,
    MatchingReviewInvalidateAttemptRequest,
    MatchingReviewPrepareInvitationRequest,
    MatchingReviewPublishInvitationRequest,
    MatchingReviewReleaseRequest,
    MatchingReviewerAssignmentResolution,
    MatchingTrustEvidence,
    PsycopgMatchingAssignmentRuntime,
    PsycopgMatchingReviewRuntime,
)
from desire_platform.matching.application import (
    ChooseCreatorCommand,
    ChooseCreatorHandler,
    CloseSelectionWithoutChoiceCommand,
    CloseSelectionWithoutChoiceHandler,
    CreateInvitationCommand,
    CreateInvitationHandler,
    InvalidateAttemptCommand,
    InvalidateAttemptHandler,
    MatchingActorContext,
    MatchingActorKind,
    MatchingApplicationError,
    MatchingCommandResult,
    PublishInvitationCommand,
    PublishInvitationHandler,
    RespondInvitationCommand,
    RespondInvitationHandler,
    WithdrawAcceptedInvitationCommand,
    WithdrawAcceptedInvitationHandler,
)
from desire_platform.matching.http import (
    MatchingHttpActor,
    MatchingHttpPresenterBindings,
    MatchingHttpProjection,
    MatchingHttpRequest,
    MatchingHttpResponse,
    matching_http_error,
)


_KEY_ID = re.compile(r"[a-z0-9][a-z0-9-]{2,127}\Z")
_CURSOR_TOKEN = re.compile(
    r"[A-Za-z0-9_-]{64,1536}\.[A-Za-z0-9_-]{43}\Z"
)
_CURSOR_VERSION = "matching-read-page-v1"
_CURSOR_DOMAIN = b"desire:matching:read-cursor:v1\x00"
_CANONICALIZATION_VERSION = "matching-command-json-v1"
_IDEMPOTENCY_KEY = re.compile(r"[A-Za-z0-9][A-Za-z0-9._~-]{15,127}\Z")
_PUBLIC_COMMAND_OPERATIONS = frozenset(
    {
        "acceptMatchingInvitation",
        "declineMatchingInvitation",
        "withdrawMatchingInvitationAcceptance",
        "chooseMatchingCreator",
        "closeMatchingSelection",
        "createMatchingInvitation",
        "publishMatchingInvitation",
        "invalidateMatchingAttempt",
    }
)
_REVIEW_OPERATION_MAP = MappingProxyType({
    "createMatchingInvitation": ("CREATE_INVITATION", "match_run_id"),
    "publishMatchingInvitation": ("PUBLISH_INVITATION", "invitation_id"),
    "invalidateMatchingAttempt": ("INVALIDATE_ATTEMPT", "attempt_id"),
})

# This is intentionally data, not a latent fallback switch.  Readiness and
# composition tests can assert the exact production support boundary.
MATCHING_POSTGRES_OPERATIONAL_SUPPORT = MappingProxyType({
    "creator_http": "AVAILABLE",
    "candidate_selector_http": "AVAILABLE",
    "candidate_selector_assignment_http": "AVAILABLE",
    "operations_http": "AVAILABLE",
    "attempt_run_worker": "UNAVAILABLE_NO_FIXED_DATABASE_PROGRAM",
})


class _MatchingCursorInvalid(ValueError):
    pass


class _MatchingResourceInvalid(ValueError):
    pass


@dataclass(repr=False)
class MatchingPostgresHttpKeys:
    """Borrowed purpose-separated key material owned by runtime secrets."""

    idempotency_key_id: str
    idempotency_key: bytearray = field(repr=False)
    payload_hash_key_id: str
    payload_hash_key: bytearray = field(repr=False)
    read_cursor_key_id: str
    read_cursor_key: bytearray = field(repr=False)

    def __post_init__(self) -> None:
        identifiers = (
            self.idempotency_key_id,
            self.payload_hash_key_id,
            self.read_cursor_key_id,
        )
        materials = (
            self.idempotency_key,
            self.payload_hash_key,
            self.read_cursor_key,
        )
        if (
            any(
                not isinstance(value, str) or _KEY_ID.fullmatch(value) is None
                for value in identifiers
            )
            or len(set(identifiers)) != len(identifiers)
            or any(
                not isinstance(value, bytearray)
                or not 32 <= len(value) <= 64
                or not any(value)
                for value in materials
            )
            or len({bytes(value) for value in materials}) != len(materials)
        ):
            raise ValueError("Matching HTTP keys are invalid")

    def digest(self, *, purpose: str, value: bytes) -> bytes:
        if not isinstance(value, bytes) or not value:
            raise LookupError("Matching HTTP key is unavailable")
        material = {
            "IDEMPOTENCY": self.idempotency_key,
            "PAYLOAD_HASH": self.payload_hash_key,
        }.get(purpose)
        if material is None or not any(material):
            raise LookupError("Matching HTTP key is unavailable")
        return hmac.new(bytes(material), value, hashlib.sha256).digest()

    def sign_cursor(self, value: bytes) -> bytes:
        if not isinstance(value, bytes) or not value or not any(self.read_cursor_key):
            raise LookupError("Matching cursor key is unavailable")
        return hmac.new(
            bytes(self.read_cursor_key), _CURSOR_DOMAIN + value, hashlib.sha256
        ).digest()

    def verify_cursor(self, *, value: bytes, signature: bytes) -> bool:
        if (
            not isinstance(value, bytes)
            or not value
            or not isinstance(signature, bytes)
            or len(signature) != 32
        ):
            return False
        material = (
            bytes(self.read_cursor_key)
            if any(self.read_cursor_key)
            else bytes(len(self.read_cursor_key))
        )
        expected = hmac.new(
            material, _CURSOR_DOMAIN + value, hashlib.sha256
        ).digest()
        return hmac.compare_digest(expected, signature) and any(
            self.read_cursor_key
        )

    def __repr__(self) -> str:
        return (
            "MatchingPostgresHttpKeys("
            f"idempotency_key_id={self.idempotency_key_id!r}, "
            f"payload_hash_key_id={self.payload_hash_key_id!r}, "
            f"read_cursor_key_id={self.read_cursor_key_id!r}, "
            "material=<redacted>)"
        )


@dataclass(frozen=True)
class MatchingPostgresActorContext(MatchingActorContext):
    """Command actor carrying the IAM marker used by Matching RLS."""

    authority_marker_sha256: bytes = field(default=b"", repr=False)

    def __post_init__(self) -> None:
        if (
            self.actor_kind is not MatchingActorKind.USER
            or not isinstance(self.authority_marker_sha256, bytes)
            or len(self.authority_marker_sha256) != 32
            or self.workload_credential_id is not None
        ):
            raise ValueError("Matching PostgreSQL actor is invalid")


class PsycopgMatchingCommandActorResolver:
    """Resolve command scope without trusting a client-supplied organization."""

    def __init__(
        self,
        *,
        runtime: PsycopgMatchingRuntime,
        review_runtime: Optional[PsycopgMatchingReviewRuntime] = None,
    ) -> None:
        if not isinstance(runtime, PsycopgMatchingRuntime) or (
            review_runtime is not None
            and not isinstance(review_runtime, PsycopgMatchingReviewRuntime)
        ):
            raise TypeError("Matching PostgreSQL runtime is unavailable")
        self._runtime = runtime
        self._review_runtime = review_runtime

    def resolve_actor(
        self,
        *,
        actor: MatchingHttpActor,
        operation_id: str,
        path_parameters: Mapping[str, str],
    ) -> MatchingActorContext:
        try:
            if (
                not isinstance(actor, MatchingHttpActor)
                or operation_id not in _PUBLIC_COMMAND_OPERATIONS
                or not isinstance(path_parameters, Mapping)
                or actor.original_actor_id is not None
                or len(actor.authority_marker_sha256) != 32
            ):
                raise MatchingApplicationError("RESOURCE_NOT_FOUND")
            organization_id: str
            if operation_id in _REVIEW_OPERATION_MAP:
                if (
                    self._review_runtime is None
                    or actor.workspace_kind != "PLATFORM"
                    or actor.organization_id is not None
                    or "OPERATIONS_REVIEWER" not in actor.role_codes
                ):
                    raise MatchingApplicationError("RESOURCE_NOT_FOUND")
                operation, target_name = _REVIEW_OPERATION_MAP[operation_id]
                resolution = self._review_runtime.resolve_assignment(
                    context=_review_context(actor),
                    operation=operation,
                    target_id=_resource_uuid(path_parameters.get(target_name)),
                )
                if resolution is None:
                    raise MatchingApplicationError("RESOURCE_NOT_FOUND")
                organization_id = str(resolution.organization_id)
            elif operation_id in {
                "acceptMatchingInvitation",
                "declineMatchingInvitation",
                "withdrawMatchingInvitationAcceptance",
            }:
                if actor.workspace_kind != "PERSONAL" or "CREATOR" not in actor.role_codes:
                    raise MatchingApplicationError("RESOURCE_NOT_FOUND")
                invitation_id = _resource_uuid(path_parameters.get("invitation_id"))
                invitation = self._runtime.read_creator_invitation(
                    context=_creator_context(actor),
                    invitation_id=invitation_id,
                )
                if invitation is None:
                    raise MatchingApplicationError("RESOURCE_NOT_FOUND")
                organization_id = _recipient_organization_id(invitation)
            else:
                if actor.workspace_kind != "ORGANIZATION":
                    raise MatchingApplicationError("RESOURCE_NOT_FOUND")
                organization_id = str(
                    _resource_uuid(path_parameters.get("organization_id"))
                )
                if organization_id != actor.organization_id:
                    raise MatchingApplicationError("RESOURCE_NOT_FOUND")
            return MatchingPostgresActorContext(
                actor_kind=MatchingActorKind.USER,
                actor_id=str(_resource_uuid(actor.actor_user_id)),
                session_id=str(_resource_uuid(actor.session_id)),
                organization_id=organization_id,
                correlation_id=str(_resource_uuid(actor.correlation_id)),
                causation_id=str(_resource_uuid(actor.causation_id)),
                trace_id=str(_resource_uuid(actor.trace_id)),
                original_actor_id=None,
                workload_credential_id=None,
                authority_marker_sha256=bytes(actor.authority_marker_sha256),
            )
        except MatchingApplicationError:
            raise
        except MatchingPostgresRejectedError as error:
            raise MatchingApplicationError(error.code) from None
        except MatchingPostgresConfigurationError:
            raise MatchingApplicationError("SERVICE_UNAVAILABLE") from None
        except (TypeError, ValueError, AttributeError):
            raise MatchingApplicationError("RESOURCE_NOT_FOUND") from None
        except Exception:
            raise MatchingApplicationError("SERVICE_UNAVAILABLE") from None


class PsycopgMatchingReviewerAssignmentResolver:
    """Resolve only the caller's current exact Matching Review assignment."""

    def __init__(self, *, runtime: PsycopgMatchingReviewRuntime) -> None:
        if not isinstance(runtime, PsycopgMatchingReviewRuntime):
            raise TypeError("Matching review runtime is unavailable")
        self._runtime = runtime

    def resolve_assignment_id(
        self,
        *,
        actor: MatchingHttpActor,
        operation_id: str,
        path_parameters: Mapping[str, str],
    ) -> str:
        try:
            if (
                not isinstance(actor, MatchingHttpActor)
                or operation_id not in _REVIEW_OPERATION_MAP
                or actor.workspace_kind != "PLATFORM"
                or actor.organization_id is not None
                or "OPERATIONS_REVIEWER" not in actor.role_codes
                or len(actor.authority_marker_sha256) != 32
            ):
                raise MatchingApplicationError("RESOURCE_NOT_FOUND")
            operation, target_name = _REVIEW_OPERATION_MAP[operation_id]
            value = self._runtime.resolve_assignment(
                context=_review_context(actor),
                operation=operation,
                target_id=_resource_uuid(path_parameters.get(target_name)),
            )
            if value is None:
                raise MatchingApplicationError("RESOURCE_NOT_FOUND")
            return str(value.assignment_id)
        except MatchingApplicationError:
            raise
        except MatchingPostgresRejectedError as error:
            raise MatchingApplicationError(error.code) from None
        except MatchingPostgresConfigurationError:
            raise MatchingApplicationError("SERVICE_UNAVAILABLE") from None
        except (TypeError, ValueError, AttributeError):
            raise MatchingApplicationError("RESOURCE_NOT_FOUND") from None
        except Exception:
            raise MatchingApplicationError("SERVICE_UNAVAILABLE") from None

    def __repr__(self) -> str:
        return "PsycopgMatchingReviewerAssignmentResolver(dependencies=<redacted>)"


class _PostgresMatchingCommandHandler:
    command_type: Any
    application_operation: str

    def __init__(
        self,
        *,
        runtime: PsycopgMatchingRuntime,
        keys: MatchingPostgresHttpKeys,
        id_source: Any,
    ) -> None:
        if (
            not isinstance(runtime, PsycopgMatchingRuntime)
            or not isinstance(keys, MatchingPostgresHttpKeys)
            or not callable(getattr(id_source, "new_id", None))
        ):
            raise TypeError("Matching PostgreSQL command dependencies are unavailable")
        self._runtime = runtime
        self._keys = keys
        self._id_source = id_source

    def handle(
        self, *, actor: MatchingActorContext, command: Any
    ) -> MatchingCommandResult:
        try:
            if not isinstance(actor, MatchingPostgresActorContext) or not isinstance(
                command, self.command_type
            ):
                raise MatchingApplicationError("INVALID_REQUEST")
            command_context = MatchingCommandContext(
                command_id=self._new_id("matching_command"),
                correlation_id=_request_uuid(actor.correlation_id),
                trace_id=_request_uuid(actor.trace_id),
            )
            material = self._material(actor=actor, command=command)
            return self._execute(
                actor=actor,
                command=command,
                command_context=command_context,
                material=material,
            )
        except MatchingApplicationError:
            raise
        except MatchingPostgresCommitOutcomeUnknownError:
            raise MatchingApplicationError("COMMAND_OUTCOME_UNKNOWN") from None
        except MatchingPostgresRejectedError as error:
            raise MatchingApplicationError(error.code) from None
        except MatchingPostgresConfigurationError:
            raise MatchingApplicationError("SERVICE_UNAVAILABLE") from None
        except (TypeError, ValueError, UnicodeError):
            raise MatchingApplicationError("INVALID_REQUEST") from None
        except Exception:
            raise MatchingApplicationError("SERVICE_UNAVAILABLE") from None

    def _execute(
        self,
        *,
        actor: MatchingPostgresActorContext,
        command: Any,
        command_context: MatchingCommandContext,
        material: MatchingWriteMaterial,
    ) -> MatchingCommandResult:
        raise NotImplementedError

    def _material(
        self, *, actor: MatchingPostgresActorContext, command: Any
    ) -> MatchingWriteMaterial:
        identity_bytes = json.dumps(
            {
                "canonicalization_version": _CANONICALIZATION_VERSION,
                "command_version": 1,
                "idempotency_key": command.idempotency_key,
                "operation": self.application_operation,
                "organization_id": actor.organization_id,
                "principal_id": actor.actor_id,
                "principal_kind": actor.actor_kind.value,
            },
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        payload_bytes = _canonical_command(
            actor=actor,
            command=command,
        )
        choose = isinstance(command, ChooseCreatorCommand)
        close = isinstance(command, CloseSelectionWithoutChoiceCommand)
        return MatchingWriteMaterial(
            receipt_id=self._new_id("matching_command_receipt"),
            fact_id=(
                None
                if close
                else self._new_id("matching_fact")
            ),
            audit_event_id=self._new_id("matching_audit_event"),
            primary_outbox_event_id=self._new_id("matching_outbox_event"),
            secondary_outbox_event_id=(
                None
                if choose
                else self._new_id("matching_outbox_event")
            ),
            identity_key_id=self._keys.idempotency_key_id,
            identity_digest=self._keys.digest(
                purpose="IDEMPOTENCY", value=identity_bytes
            ),
            payload_hash_key_id=self._keys.payload_hash_key_id,
            payload_hash=self._keys.digest(
                purpose="PAYLOAD_HASH", value=payload_bytes
            ),
        )

    def _new_id(self, purpose: str) -> UUID:
        value = self._id_source.new_id(purpose)
        if not isinstance(value, UUID) or value.int == 0:
            raise MatchingPostgresConfigurationError()
        return value

    def __repr__(self) -> str:
        return f"{type(self).__name__}(dependencies=<redacted>)"


class PostgresRespondInvitationHandler(
    _PostgresMatchingCommandHandler, RespondInvitationHandler
):
    command_type = RespondInvitationCommand
    application_operation = "RESPOND_INVITATION"

    def _execute(
        self,
        *,
        actor: MatchingPostgresActorContext,
        command: RespondInvitationCommand,
        command_context: MatchingCommandContext,
        material: MatchingWriteMaterial,
    ) -> MatchingCommandResult:
        operation = (
            CreatorInvitationOperation.ACCEPT
            if command.accept
            else CreatorInvitationOperation.DECLINE
        )
        request = CreatorInvitationMutation(
            operation=operation,
            creator=_creator_write_context(actor),
            command=command_context,
            organization_id=_request_uuid(actor.organization_id),
            invitation_id=_request_uuid(command.invitation_id),
            expected_invitation_version=command.expected_invitation_version,
            expected_snapshot_sha256=bytes.fromhex(command.snapshot_sha256),
            reason_code=command.reason_code,
            restricted_note=command.note,
            material=material,
        )
        result = (
            self._runtime.accept_invitation(request)
            if command.accept
            else self._runtime.decline_invitation(request)
        )
        return _invitation_result(
            result.invitation,
            replayed=result.replayed,
            event_types=(
                "InvitationAccepted" if command.accept else "InvitationDeclined",
                "SelectionInvitationSetChanged",
            ),
        )


class PostgresWithdrawAcceptedInvitationHandler(
    _PostgresMatchingCommandHandler, WithdrawAcceptedInvitationHandler
):
    command_type = WithdrawAcceptedInvitationCommand
    application_operation = "WITHDRAW_ACCEPTED_INVITATION"

    def _execute(
        self,
        *,
        actor: MatchingPostgresActorContext,
        command: WithdrawAcceptedInvitationCommand,
        command_context: MatchingCommandContext,
        material: MatchingWriteMaterial,
    ) -> MatchingCommandResult:
        result = self._runtime.withdraw_invitation(
            CreatorInvitationMutation(
                operation=CreatorInvitationOperation.WITHDRAW,
                creator=_creator_write_context(actor),
                command=command_context,
                organization_id=_request_uuid(actor.organization_id),
                invitation_id=_request_uuid(command.invitation_id),
                expected_invitation_version=command.expected_invitation_version,
                expected_snapshot_sha256=bytes.fromhex(command.snapshot_sha256),
                reason_code=command.reason_code,
                restricted_note=command.note,
                material=material,
            )
        )
        return _invitation_result(
            result.invitation,
            replayed=result.replayed,
            event_types=(
                "InvitationWithdrawn",
                "SelectionInvitationSetChanged",
            ),
        )


class PostgresChooseCreatorHandler(
    _PostgresMatchingCommandHandler, ChooseCreatorHandler
):
    command_type = ChooseCreatorCommand
    application_operation = "CHOOSE_CREATOR"

    def _execute(
        self,
        *,
        actor: MatchingPostgresActorContext,
        command: ChooseCreatorCommand,
        command_context: MatchingCommandContext,
        material: MatchingWriteMaterial,
    ) -> MatchingCommandResult:
        result = self._runtime.choose_creator(
            CandidateSelectionMutation(
                operation=CandidateSelectionOperation.CHOOSE,
                selector=_selector_write_context(actor, command),
                command=command_context,
                expected_selection_version=command.expected_selection_version,
                expected_invitation_set_sha256=bytes.fromhex(
                    command.current_invitation_set_sha256
                ),
                invitation_id=_request_uuid(command.invitation_id),
                selection_basis_code=command.selection_basis_code,
                reason_code=None,
                material=material,
            )
        )
        return _selection_result(
            result.selection,
            replayed=result.replayed,
            event_types=("SelectionIntentRecorded",),
        )


class PostgresCloseSelectionWithoutChoiceHandler(
    _PostgresMatchingCommandHandler, CloseSelectionWithoutChoiceHandler
):
    command_type = CloseSelectionWithoutChoiceCommand
    application_operation = "CLOSE_SELECTION_WITHOUT_CHOICE"

    def _execute(
        self,
        *,
        actor: MatchingPostgresActorContext,
        command: CloseSelectionWithoutChoiceCommand,
        command_context: MatchingCommandContext,
        material: MatchingWriteMaterial,
    ) -> MatchingCommandResult:
        result = self._runtime.close_selection(
            CandidateSelectionMutation(
                operation=CandidateSelectionOperation.CLOSE,
                selector=_selector_write_context(actor, command),
                command=command_context,
                expected_selection_version=command.expected_selection_version,
                expected_invitation_set_sha256=bytes.fromhex(
                    command.current_invitation_set_sha256
                ),
                invitation_id=None,
                selection_basis_code=None,
                reason_code=command.reason_code,
                material=material,
            )
        )
        return _selection_result(
            result.selection,
            replayed=result.replayed,
            event_types=("SelectionCloseIntentRecorded",),
        )


class _PostgresMatchingReviewCommandHandler:
    command_type: Any
    review_operation: str
    outbox_count: int

    def __init__(
        self,
        *,
        runtime: PsycopgMatchingReviewRuntime,
        keys: MatchingPostgresHttpKeys,
        id_source: Any,
        demand_hold: Any,
    ) -> None:
        if (
            not isinstance(runtime, PsycopgMatchingReviewRuntime)
            or not isinstance(keys, MatchingPostgresHttpKeys)
            or not callable(getattr(id_source, "new_id", None))
            or (
                self.review_operation in {"CREATE_INVITATION", "PUBLISH_INVITATION"}
                and not callable(getattr(demand_hold, "evaluate_for_matching", None))
            )
        ):
            raise TypeError("Matching review command dependencies are unavailable")
        self._runtime = runtime
        self._keys = keys
        self._id_source = id_source
        self._demand_hold = demand_hold

    def handle(
        self, *, actor: MatchingActorContext, command: Any
    ) -> MatchingCommandResult:
        try:
            if not isinstance(actor, MatchingPostgresActorContext) or not isinstance(
                command, self.command_type
            ):
                raise MatchingApplicationError("INVALID_REQUEST")
            return self._execute(actor=actor, command=command)
        except MatchingApplicationError:
            raise
        except MatchingPostgresCommitOutcomeUnknownError:
            raise MatchingApplicationError("COMMAND_OUTCOME_UNKNOWN") from None
        except MatchingPostgresRejectedError as error:
            raise MatchingApplicationError(error.code) from None
        except MatchingPostgresConfigurationError:
            raise MatchingApplicationError("SERVICE_UNAVAILABLE") from None
        except (TypeError, ValueError, AttributeError, UnicodeError):
            raise MatchingApplicationError("INVALID_REQUEST") from None
        except Exception:
            raise MatchingApplicationError("SERVICE_UNAVAILABLE") from None

    def _execute(
        self, *, actor: MatchingPostgresActorContext, command: Any
    ) -> MatchingCommandResult:
        raise NotImplementedError

    def _scope(
        self,
        *,
        actor: MatchingPostgresActorContext,
        target_id: Any,
        assignment_id: Any,
    ) -> tuple[
        MatchingReviewContext,
        MatchingReviewerAssignmentResolution,
        MatchingReviewAssignmentView,
    ]:
        context = _review_write_context(actor)
        resolution = self._runtime.resolve_assignment(
            context=context,
            operation=self.review_operation,
            target_id=_request_uuid(target_id),
        )
        workspace = self._runtime.read_assignment(context)
        if (
            resolution is None
            or workspace is None
            or resolution.assignment_id != _request_uuid(assignment_id)
            or resolution.organization_id != _request_uuid(actor.organization_id)
            or workspace.assignment.assignment_id != resolution.assignment_id
            or workspace.assignment.organization_id != resolution.organization_id
            or workspace.assignment.attempt_id != resolution.attempt_id
            or workspace.assignment.match_run_id != resolution.match_run_id
            or workspace.assignment.purpose_code != resolution.purpose_code
            or workspace.assignment.aggregate_version != resolution.assignment_version
            or workspace.assignment.expires_at != resolution.expires_at
            or workspace.assignment.status != "ACTIVE"
        ):
            raise MatchingApplicationError("RESOURCE_NOT_FOUND")
        return context, resolution, workspace

    def _material(
        self,
        *,
        actor: MatchingPostgresActorContext,
        command: Any,
        outbox_count: Optional[int] = None,
    ) -> MatchingOperationalCommandMaterial:
        return _operational_material(
            actor_id=actor.actor_id,
            organization_id=actor.organization_id,
            correlation_id=actor.correlation_id,
            trace_id=actor.trace_id,
            operation=self.review_operation,
            idempotency_key=command.idempotency_key,
            payload=_normalize_command(command),
            outbox_count=self.outbox_count if outbox_count is None else outbox_count,
            keys=self._keys,
            id_source=self._id_source,
        )

    def _trust(
        self,
        *,
        actor: MatchingPostgresActorContext,
        workspace: MatchingReviewAssignmentView,
    ) -> MatchingTrustEvidence:
        try:
            attempt = workspace.attempt
            result = self._demand_hold.evaluate_for_matching(
                actor_id=actor.actor_id,
                organization_id=actor.organization_id,
                demand_id=str(attempt.demand_id),
                prospective_aggregate_version=attempt.demand_aggregate_version,
                demand_version_id=str(attempt.demand_version_id),
                content_sha256=attempt.demand_content_sha256.hex(),
                action="REQUEST_MATCHING",
                policy_version="demand-safety-hold-v1",
            )
            decision = getattr(result.decision, "value", result.decision)
            if decision != "ALLOW":
                raise MatchingApplicationError("SAFETY_HOLD_BLOCKED")
            return MatchingTrustEvidence(
                evidence_id=_new_operational_id(
                    self._id_source, "matching_trust_hold_evidence"
                ),
                evidence_sha256=bytes(result.evidence_sha256),
                evaluated_at=result.evaluated_at,
                valid_until=result.valid_until,
            )
        except MatchingApplicationError:
            raise
        except Exception:
            raise MatchingPostgresConfigurationError() from None

    def __repr__(self) -> str:
        return f"{type(self).__name__}(dependencies=<redacted>)"


class PostgresCreateMatchingInvitationHandler(
    _PostgresMatchingReviewCommandHandler, CreateInvitationHandler
):
    command_type = CreateInvitationCommand
    review_operation = "CREATE_INVITATION"
    outbox_count = 1

    def _execute(
        self, *, actor: MatchingPostgresActorContext, command: CreateInvitationCommand
    ) -> MatchingCommandResult:
        context, resolution, workspace = self._scope(
            actor=actor,
            target_id=command.match_run_id,
            assignment_id=command.assignment_id,
        )
        invitation_id = _new_operational_id(
            self._id_source, "matching_invitation"
        )
        snapshot_id = _new_operational_id(
            self._id_source, "matching_invitation_disclosure_snapshot"
        )
        prepared = self._runtime.prepare_invitation(
            MatchingReviewPrepareInvitationRequest(
                context=context,
                organization_id=resolution.organization_id,
                assignment_id=resolution.assignment_id,
                expected_assignment_version=resolution.assignment_version,
                match_run_id=_request_uuid(command.match_run_id),
                expected_match_run_version=command.expected_run_version,
                creator_user_id=_request_uuid(command.creator_user_id),
                invitation_id=invitation_id,
                snapshot_id=snapshot_id,
                expires_at=command.expires_at,
            )
        )
        return self._runtime.create_invitation(
            MatchingReviewCreateInvitationRequest(
                context=context,
                organization_id=resolution.organization_id,
                assignment_id=resolution.assignment_id,
                expected_assignment_version=resolution.assignment_version,
                match_run_id=_request_uuid(command.match_run_id),
                expected_match_run_version=command.expected_run_version,
                creator_user_id=_request_uuid(command.creator_user_id),
                invitation_id=invitation_id,
                snapshot_id=snapshot_id,
                expires_at=command.expires_at,
                prepared=prepared,
                trust=self._trust(actor=actor, workspace=workspace),
                material=self._material(actor=actor, command=command),
            )
        )


class PostgresPublishMatchingInvitationHandler(
    _PostgresMatchingReviewCommandHandler, PublishInvitationHandler
):
    command_type = PublishInvitationCommand
    review_operation = "PUBLISH_INVITATION"
    outbox_count = 2

    def _execute(
        self, *, actor: MatchingPostgresActorContext, command: PublishInvitationCommand
    ) -> MatchingCommandResult:
        context, resolution, workspace = self._scope(
            actor=actor,
            target_id=command.invitation_id,
            assignment_id=command.assignment_id,
        )
        return self._runtime.publish_invitation(
            MatchingReviewPublishInvitationRequest(
                context=context,
                organization_id=resolution.organization_id,
                assignment_id=resolution.assignment_id,
                expected_assignment_version=resolution.assignment_version,
                invitation_id=_request_uuid(command.invitation_id),
                expected_invitation_version=command.expected_invitation_version,
                expected_snapshot_sha256=bytes.fromhex(command.snapshot_sha256),
                trust=self._trust(actor=actor, workspace=workspace),
                material=self._material(actor=actor, command=command),
            )
        )


class PostgresInvalidateMatchingAttemptHandler(
    _PostgresMatchingReviewCommandHandler, InvalidateAttemptHandler
):
    command_type = InvalidateAttemptCommand
    review_operation = "INVALIDATE_ATTEMPT"
    outbox_count = 2

    def _execute(
        self, *, actor: MatchingPostgresActorContext, command: InvalidateAttemptCommand
    ) -> MatchingCommandResult:
        if command.assignment_id is None:
            raise MatchingApplicationError("RESOURCE_NOT_FOUND")
        context, resolution, workspace = self._scope(
            actor=actor,
            target_id=command.attempt_id,
            assignment_id=command.assignment_id,
        )
        affected = sum(
            invitation.status in {"CREATED", "SENT", "ACCEPTED"}
            for invitation in workspace.invitations
        )
        return self._runtime.invalidate_attempt(
            MatchingReviewInvalidateAttemptRequest(
                context=context,
                organization_id=resolution.organization_id,
                assignment_id=resolution.assignment_id,
                expected_assignment_version=resolution.assignment_version,
                attempt_id=_request_uuid(command.attempt_id),
                expected_attempt_version=command.expected_attempt_version,
                expected_input_baseline_sha256=bytes.fromhex(
                    command.input_baseline_sha256
                ),
                reason_code=command.reason_code,
                material=self._material(
                    actor=actor, command=command, outbox_count=2 + affected
                ),
            )
        )


class PsycopgMatchingHttpProjectionAdapter:
    """Convert only recipient-safe and exact-assignment PG views to HTTP DTOs."""

    def __init__(
        self,
        *,
        runtime: PsycopgMatchingRuntime,
        keys: MatchingPostgresHttpKeys,
        review_runtime: Optional[PsycopgMatchingReviewRuntime] = None,
    ) -> None:
        if not isinstance(runtime, PsycopgMatchingRuntime) or not isinstance(
            keys, MatchingPostgresHttpKeys
        ) or (
            review_runtime is not None
            and not isinstance(review_runtime, PsycopgMatchingReviewRuntime)
        ):
            raise TypeError("Matching PostgreSQL projection dependencies are unavailable")
        self._runtime = runtime
        self._keys = keys
        self._review_runtime = review_runtime

    def list_recipient_invitations(
        self,
        *,
        actor: MatchingHttpActor,
        limit: int,
        cursor: Optional[str],
    ) -> MatchingHttpProjection:
        try:
            context = _creator_context(actor)
            cursor_time, cursor_id = _read_cursor(
                cursor,
                keys=self._keys,
                operation="listMyMatchingInvitations",
                actor_user_id=context.actor_user_id,
                organization_id=None,
                demand_id=None,
                limit=limit,
            )
            page = self._runtime.list_creator_invitations(
                context=context,
                limit=limit,
                cursor_updated_at=cursor_time,
                cursor_invitation_id=cursor_id,
            )
            next_cursor = _next_cursor(
                keys=self._keys,
                operation="listMyMatchingInvitations",
                actor_user_id=context.actor_user_id,
                organization_id=None,
                demand_id=None,
                limit=limit,
                updated_at=page.next_updated_at,
                item_id=page.next_invitation_id,
            )
            return MatchingHttpProjection(
                kind="RECIPIENT_INVITATION_LIST",
                data={
                    "items": [_recipient_data(value) for value in page.items],
                    "next_cursor": next_cursor,
                },
            )
        except Exception as error:
            _projection_error(error)
        raise AssertionError("unreachable")

    def read_recipient_invitation(
        self, *, actor: MatchingHttpActor, invitation_id: str
    ) -> MatchingHttpProjection:
        try:
            value = self._runtime.read_creator_invitation(
                context=_creator_context(actor),
                invitation_id=_resource_uuid(invitation_id),
            )
            if value is None:
                raise MatchingApplicationError("RESOURCE_NOT_FOUND")
            return MatchingHttpProjection(
                kind="RECIPIENT_INVITATION",
                data=_recipient_data(value),
                entity_tag=value.entity_tag,
            )
        except Exception as error:
            _projection_error(error)
        raise AssertionError("unreachable")

    def list_demand_attempts(
        self,
        *,
        actor: MatchingHttpActor,
        organization_id: str,
        demand_id: str,
        limit: int,
        cursor: Optional[str],
    ) -> MatchingHttpProjection:
        try:
            context = _selector_discovery_context(actor, organization_id)
            exact_demand_id = _resource_uuid(demand_id)
            cursor_time, cursor_id = _read_cursor(
                cursor,
                keys=self._keys,
                operation="listDemandMatchingAttempts",
                actor_user_id=context.actor_user_id,
                organization_id=context.organization_id,
                demand_id=exact_demand_id,
                limit=limit,
            )
            page = self._runtime.list_selector_attempts(
                context=context,
                demand_id=exact_demand_id,
                limit=limit,
                cursor_updated_at=cursor_time,
                cursor_attempt_id=cursor_id,
            )
            next_cursor = _next_cursor(
                keys=self._keys,
                operation="listDemandMatchingAttempts",
                actor_user_id=context.actor_user_id,
                organization_id=context.organization_id,
                demand_id=exact_demand_id,
                limit=limit,
                updated_at=page.next_updated_at,
                item_id=page.next_attempt_id,
            )
            return MatchingHttpProjection(
                kind="ATTEMPT_LIST",
                data={
                    "items": [_attempt_data(value) for value in page.items],
                    "next_cursor": next_cursor,
                },
            )
        except Exception as error:
            _projection_error(error)
        raise AssertionError("unreachable")

    def read_selection_for_attempt(
        self,
        *,
        actor: MatchingHttpActor,
        organization_id: str,
        attempt_id: str,
    ) -> MatchingHttpProjection:
        try:
            value = self._runtime.read_selection_by_attempt(
                context=_selector_discovery_context(actor, organization_id),
                attempt_id=_resource_uuid(attempt_id),
            )
            return _selection_projection(value)
        except Exception as error:
            _projection_error(error)
        raise AssertionError("unreachable")

    def read_selection(
        self,
        *,
        actor: MatchingHttpActor,
        organization_id: str,
        selection_id: str,
    ) -> MatchingHttpProjection:
        try:
            value = self._runtime.read_selection_by_id(
                context=_selector_discovery_context(actor, organization_id),
                selection_id=_resource_uuid(selection_id),
            )
            return _selection_projection(value)
        except Exception as error:
            _projection_error(error)
        raise AssertionError("unreachable")

    def read_reviewer_invitation(
        self, *, actor: MatchingHttpActor, invitation_id: str
    ) -> MatchingHttpProjection:
        try:
            workspace = self._review_workspace(actor)
            target = _resource_uuid(invitation_id)
            value = next(
                (
                    item
                    for item in workspace.invitations
                    if item.invitation_id == target
                ),
                None,
            )
            if value is None:
                raise MatchingApplicationError("RESOURCE_NOT_FOUND")
            return MatchingHttpProjection(
                kind="REVIEWER_INVITATION",
                data={
                    "invitation_id": str(value.invitation_id),
                    "attempt_id": str(workspace.assignment.attempt_id),
                    "match_run_id": str(workspace.assignment.match_run_id),
                    "creator_user_id": str(value.creator_user_id),
                    "status": value.status,
                    "aggregate_version": value.aggregate_version,
                    "updated_at": _utc_text(value.updated_at),
                    "expires_at": _utc_text(value.expires_at),
                    "snapshot_sha256": value.snapshot_sha256.hex(),
                },
                entity_tag=f'"v{value.aggregate_version}"',
            )
        except Exception as error:
            _projection_error(error)
        raise AssertionError("unreachable")

    def read_attempt(
        self, *, actor: MatchingHttpActor, attempt_id: str
    ) -> MatchingHttpProjection:
        try:
            workspace = self._review_workspace(actor)
            if workspace.assignment.attempt_id != _resource_uuid(attempt_id):
                raise MatchingApplicationError("RESOURCE_NOT_FOUND")
            value = workspace.attempt
            return MatchingHttpProjection(
                kind="ATTEMPT",
                data={
                    "attempt_id": str(workspace.assignment.attempt_id),
                    "demand_id": str(value.demand_id),
                    "attempt_no": value.attempt_no,
                    "status": value.status,
                    "aggregate_version": value.aggregate_version,
                    "updated_at": _utc_text(value.updated_at),
                },
                entity_tag=f'"v{value.aggregate_version}"',
            )
        except Exception as error:
            _projection_error(error)
        raise AssertionError("unreachable")

    def _review_workspace(
        self, actor: MatchingHttpActor
    ) -> MatchingReviewAssignmentView:
        if self._review_runtime is None:
            raise MatchingApplicationError("SERVICE_UNAVAILABLE")
        value = self._review_runtime.read_assignment(_review_context(actor))
        if value is None:
            raise MatchingApplicationError("RESOURCE_NOT_FOUND")
        return value

    def __repr__(self) -> str:
        return "PsycopgMatchingHttpProjectionAdapter(dependencies=<redacted>)"


def build_matching_postgres_http_bindings(
    *,
    runtime: PsycopgMatchingRuntime,
    keys: MatchingPostgresHttpKeys,
    id_source: Any,
    review_runtime: Optional[PsycopgMatchingReviewRuntime] = None,
    demand_hold: Any = None,
) -> MatchingHttpPresenterBindings:
    """Build public bindings and optionally enable the exact reviewer set."""

    common = {"runtime": runtime, "keys": keys, "id_source": id_source}
    operations_enabled = review_runtime is not None and demand_hold is not None
    if (review_runtime is None) != (demand_hold is None):
        raise TypeError("Matching review bindings are only enabled as one set")
    review_common = {
        "runtime": review_runtime,
        "keys": keys,
        "id_source": id_source,
        "demand_hold": demand_hold,
    }
    return MatchingHttpPresenterBindings(
        respond_invitation=PostgresRespondInvitationHandler(**common),
        withdraw_invitation=PostgresWithdrawAcceptedInvitationHandler(**common),
        choose_creator=PostgresChooseCreatorHandler(**common),
        close_selection=PostgresCloseSelectionWithoutChoiceHandler(**common),
        projections=PsycopgMatchingHttpProjectionAdapter(
            runtime=runtime, keys=keys, review_runtime=review_runtime
        ),
        command_actors=PsycopgMatchingCommandActorResolver(
            runtime=runtime, review_runtime=review_runtime
        ),
        create_invitation=(
            PostgresCreateMatchingInvitationHandler(**review_common)
            if operations_enabled
            else None
        ),
        publish_invitation=(
            PostgresPublishMatchingInvitationHandler(**review_common)
            if operations_enabled
            else None
        ),
        invalidate_attempt=(
            PostgresInvalidateMatchingAttemptHandler(**review_common)
            if operations_enabled
            else None
        ),
        reviewer_assignments=(
            PsycopgMatchingReviewerAssignmentResolver(runtime=review_runtime)
            if operations_enabled and review_runtime is not None
            else None
        ),
    )


class _MatchingOperationalRequestInvalid(ValueError):
    pass


class _MatchingOperationalResourceHidden(ValueError):
    pass


class MatchingPostgresOperationalHttpService:
    """Serve claim/resume/release routes without trusting browser authority."""

    def __init__(
        self,
        *,
        assignment_runtime: PsycopgMatchingAssignmentRuntime,
        review_runtime: PsycopgMatchingReviewRuntime,
        keys: MatchingPostgresHttpKeys,
        id_source: Any,
    ) -> None:
        if (
            not isinstance(assignment_runtime, PsycopgMatchingAssignmentRuntime)
            or not isinstance(review_runtime, PsycopgMatchingReviewRuntime)
            or not isinstance(keys, MatchingPostgresHttpKeys)
            or not callable(getattr(id_source, "new_id", None))
        ):
            raise TypeError("Matching operational HTTP dependencies are unavailable")
        self._assignment_runtime = assignment_runtime
        self._review_runtime = review_runtime
        self._keys = keys
        self._id_source = id_source

    def handle(
        self, *, request: MatchingHttpRequest, actor: MatchingHttpActor
    ) -> MatchingHttpResponse:
        trace_id = actor.trace_id if isinstance(actor, MatchingHttpActor) else "trace-unavailable"
        mutating = isinstance(request, MatchingHttpRequest) and request.method == "POST"
        try:
            if not isinstance(request, MatchingHttpRequest) or not isinstance(
                actor, MatchingHttpActor
            ):
                raise _MatchingOperationalRequestInvalid()
            if request.query:
                raise _MatchingOperationalRequestInvalid()
            if request.path == "/v1/matching/candidate-selector-assignments/claim":
                return self._claim_candidate_selector(request=request, actor=actor)
            if request.path == "/v1/app/matching-review/queue/claim":
                return self._claim_review(request=request, actor=actor)
            if request.path == "/v1/app/matching-review/assignment":
                return self._read_review(request=request, actor=actor)
            if request.path == "/v1/app/matching-review/assignment/release":
                return self._release_review(request=request, actor=actor)
            raise _MatchingOperationalResourceHidden()
        except _MatchingOperationalRequestInvalid:
            return matching_http_error("INVALID_REQUEST", trace_id=trace_id)
        except _MatchingOperationalResourceHidden:
            return matching_http_error("RESOURCE_NOT_FOUND", trace_id=trace_id)
        except MatchingPostgresCommitOutcomeUnknownError:
            return matching_http_error(
                "COMMAND_OUTCOME_UNKNOWN" if mutating else "SERVICE_UNAVAILABLE",
                trace_id=trace_id,
            )
        except MatchingPostgresRejectedError as error:
            return matching_http_error(error.code, trace_id=trace_id)
        except MatchingPostgresConfigurationError:
            return matching_http_error("SERVICE_UNAVAILABLE", trace_id=trace_id)
        except Exception:
            return matching_http_error(
                "COMMAND_OUTCOME_UNKNOWN" if mutating else "SERVICE_UNAVAILABLE",
                trace_id=trace_id,
            )

    def _claim_candidate_selector(
        self, *, request: MatchingHttpRequest, actor: MatchingHttpActor
    ) -> MatchingHttpResponse:
        if request.method != "POST" or "if-match" in request.headers:
            raise _MatchingOperationalRequestInvalid()
        if (
            actor.workspace_kind != "ORGANIZATION"
            or actor.organization_id is None
            or "DEMAND_OWNER" not in actor.role_codes
            or len(actor.authority_marker_sha256) != 32
        ):
            raise _MatchingOperationalResourceHidden()
        _exact_operational_body(request.json_body, ("demand_id",))
        demand_id = _operational_request_uuid(request.json_body["demand_id"])
        idempotency_key = _operational_idempotency_key(request.headers)
        context = MatchingAssignmentContext(
            actor_user_id=_operational_request_uuid(actor.actor_user_id),
            session_id=_operational_request_uuid(actor.session_id),
            organization_id=_operational_request_uuid(actor.organization_id),
            principal_marker_sha256=bytes(actor.authority_marker_sha256),
        )
        result = self._assignment_runtime.claim_candidate_selector(
            MatchingCandidateSelectorClaimRequest(
                context=context,
                demand_id=demand_id,
                assignment_id=_new_operational_id(
                    self._id_source, "matching_candidate_selector_assignment"
                ),
                material=self._material(
                    actor=actor,
                    organization_id=actor.organization_id,
                    operation="OPT_IN_CANDIDATE_SELECTOR",
                    idempotency_key=idempotency_key,
                    payload={"demand_id": str(demand_id)},
                    outbox_count=1,
                ),
            )
        )
        return MatchingHttpResponse(
            status=201,
            headers={
                "content-type": "application/json",
                "etag": f'"v{result.assignment_version}"',
            },
            json_body={
                "candidate_selector_assignment_id": str(result.assignment_id),
                "candidate_selector_assignment_version": result.assignment_version,
                "selection_id": str(result.selection_id),
                "attempt_id": str(result.attempt_id),
                "demand_id": str(result.demand_id),
                "status": result.status,
                "expires_at": _utc_text(result.expires_at),
                "selection_status": result.selection_status,
                "selection_version": result.selection_version,
                "current_invitation_set_sha256": (
                    result.current_invitation_set_sha256.hex()
                ),
            },
        )

    def _claim_review(
        self, *, request: MatchingHttpRequest, actor: MatchingHttpActor
    ) -> MatchingHttpResponse:
        if request.method != "POST" or "if-match" in request.headers:
            raise _MatchingOperationalRequestInvalid()
        _exact_operational_body(request.json_body, ())
        context = self._review_context(actor)
        idempotency_key = _operational_idempotency_key(request.headers)
        result = self._review_runtime.claim_assignment(
            MatchingReviewClaimRequest(
                context=context,
                assignment_id=_new_operational_id(
                    self._id_source, "matching_review_assignment"
                ),
                material=self._material(
                    actor=actor,
                    organization_id=None,
                    operation="CLAIM_MATCHING_REVIEW",
                    idempotency_key=idempotency_key,
                    payload={},
                    outbox_count=1,
                ),
            )
        )
        if result is None:
            raise _MatchingOperationalResourceHidden()
        return _review_summary_response(result, status=201)

    def _read_review(
        self, *, request: MatchingHttpRequest, actor: MatchingHttpActor
    ) -> MatchingHttpResponse:
        if (
            request.method != "GET"
            or request.json_body
            or "idempotency-key" in request.headers
            or "if-match" in request.headers
        ):
            raise _MatchingOperationalRequestInvalid()
        result = self._review_runtime.read_assignment(self._review_context(actor))
        if result is None:
            raise _MatchingOperationalResourceHidden()
        return MatchingHttpResponse(
            status=200,
            headers={
                "content-type": "application/json",
                "etag": f'"v{result.assignment.aggregate_version}"',
            },
            json_body=_review_workspace_data(result),
        )

    def _release_review(
        self, *, request: MatchingHttpRequest, actor: MatchingHttpActor
    ) -> MatchingHttpResponse:
        if request.method != "POST":
            raise _MatchingOperationalRequestInvalid()
        _exact_operational_body(request.json_body, ())
        expected_version = _operational_expected_version(request.headers)
        idempotency_key = _operational_idempotency_key(request.headers)
        result = self._review_runtime.release_assignment(
            MatchingReviewReleaseRequest(
                context=self._review_context(actor),
                expected_assignment_version=expected_version,
                material=self._material(
                    actor=actor,
                    organization_id=None,
                    operation="RELEASE_MATCHING_REVIEW",
                    idempotency_key=idempotency_key,
                    payload={"expected_assignment_version": expected_version},
                    outbox_count=1,
                ),
            )
        )
        return _review_summary_response(result, status=200)

    def _review_context(self, actor: MatchingHttpActor) -> MatchingReviewContext:
        try:
            return _review_context(actor)
        except (MatchingApplicationError, TypeError, ValueError, AttributeError):
            raise _MatchingOperationalResourceHidden() from None

    def _material(
        self,
        *,
        actor: MatchingHttpActor,
        organization_id: Optional[str],
        operation: str,
        idempotency_key: str,
        payload: Mapping[str, Any],
        outbox_count: int,
    ) -> MatchingOperationalCommandMaterial:
        return _operational_material(
            actor_id=actor.actor_user_id,
            organization_id=organization_id,
            correlation_id=actor.correlation_id,
            trace_id=actor.trace_id,
            operation=operation,
            idempotency_key=idempotency_key,
            payload=payload,
            outbox_count=outbox_count,
            keys=self._keys,
            id_source=self._id_source,
        )

    def __repr__(self) -> str:
        return "MatchingPostgresOperationalHttpService(dependencies=<redacted>)"


def _exact_operational_body(
    value: Mapping[str, Any], names: Tuple[str, ...]
) -> None:
    if not isinstance(value, Mapping) or set(value) != set(names):
        raise _MatchingOperationalRequestInvalid()


def _operational_request_uuid(value: Any) -> UUID:
    try:
        return _request_uuid(value)
    except (TypeError, ValueError, AttributeError):
        raise _MatchingOperationalRequestInvalid() from None


def _operational_idempotency_key(headers: Mapping[str, str]) -> str:
    value = headers.get("idempotency-key")
    if not isinstance(value, str) or _IDEMPOTENCY_KEY.fullmatch(value) is None:
        raise _MatchingOperationalRequestInvalid()
    return value


def _operational_expected_version(headers: Mapping[str, str]) -> int:
    value = headers.get("if-match")
    match = re.fullmatch(r'"v([1-9][0-9]*)"', value or "")
    if match is None:
        raise _MatchingOperationalRequestInvalid()
    version = int(match.group(1))
    if version > 2_147_483_647:
        raise _MatchingOperationalRequestInvalid()
    return version


def _review_summary_data(
    value: MatchingReviewAssignmentSummary,
) -> Mapping[str, Any]:
    return {
        "assignment_id": str(value.assignment_id),
        "organization_id": str(value.organization_id),
        "attempt_id": str(value.attempt_id),
        "match_run_id": str(value.match_run_id),
        "purpose_code": value.purpose_code,
        "role_code": value.role_code,
        "status": value.status,
        "aggregate_version": value.aggregate_version,
        "expires_at": _utc_text(value.expires_at),
    }


def _review_summary_response(
    value: MatchingReviewAssignmentSummary, *, status: int
) -> MatchingHttpResponse:
    return MatchingHttpResponse(
        status=status,
        headers={
            "content-type": "application/json",
            "etag": f'"v{value.aggregate_version}"',
        },
        json_body=_review_summary_data(value),
    )


def _review_workspace_data(
    value: MatchingReviewAssignmentView,
) -> Mapping[str, Any]:
    attempt = value.attempt
    run = value.run
    return {
        **_review_summary_data(value.assignment),
        "attempt": {
            "status": attempt.status,
            "aggregate_version": attempt.aggregate_version,
            "attempt_no": attempt.attempt_no,
            "updated_at": _utc_text(attempt.updated_at),
            "demand_id": str(attempt.demand_id),
            "demand_version_id": str(attempt.demand_version_id),
            "demand_aggregate_version": attempt.demand_aggregate_version,
            "demand_content_sha256": attempt.demand_content_sha256.hex(),
            "input_baseline_sha256": attempt.input_baseline_sha256.hex(),
        },
        "run": {
            "status": run.status,
            "aggregate_version": run.aggregate_version,
            "ordered_result_sha256": (
                None
                if run.ordered_result_sha256 is None
                else run.ordered_result_sha256.hex()
            ),
            "candidate_count": run.candidate_count,
            "eligible_count": run.eligible_count,
            "excluded_count": run.excluded_count,
            "failure_code": run.failure_code,
        },
        "eligible_candidates": [
            {
                "creator_user_id": str(candidate.creator_user_id),
                "creator_display_handle": candidate.creator_display_handle,
                "profile_id": str(candidate.profile_id),
                "profile_version_id": str(candidate.profile_version_id),
                "profile_content_sha256": candidate.profile_content_sha256.hex(),
                "evidence_version_digest": candidate.evidence_version_digest.hex(),
                "total_score": candidate.total_score,
                "rank": candidate.rank,
                "component_scores": [
                    {
                        "code": component.code,
                        "ordinal": component.ordinal,
                        "score": component.score,
                    }
                    for component in candidate.component_scores
                ],
                "candidate_result_sha256": candidate.candidate_result_sha256.hex(),
            }
            for candidate in value.eligible_candidates
        ],
        "invitations": [
            {
                "invitation_id": str(invitation.invitation_id),
                "creator_user_id": str(invitation.creator_user_id),
                "status": invitation.status,
                "aggregate_version": invitation.aggregate_version,
                "snapshot_sha256": invitation.snapshot_sha256.hex(),
                "expires_at": _utc_text(invitation.expires_at),
                "updated_at": _utc_text(invitation.updated_at),
            }
            for invitation in value.invitations
        ],
        "actions": {
            "can_create_invitation": value.actions.can_create_invitation,
            "can_publish_invitation": value.actions.can_publish_invitation,
            "can_invalidate_attempt": value.actions.can_invalidate_attempt,
        },
    }


def _creator_context(actor: MatchingHttpActor) -> MatchingCreatorContext:
    if (
        not isinstance(actor, MatchingHttpActor)
        or actor.workspace_kind != "PERSONAL"
        or actor.organization_id is not None
        or "CREATOR" not in actor.role_codes
        or len(actor.authority_marker_sha256) != 32
    ):
        raise MatchingApplicationError("RESOURCE_NOT_FOUND")
    return MatchingCreatorContext(
        actor_user_id=_resource_uuid(actor.actor_user_id),
        session_id=_resource_uuid(actor.session_id),
        authority_marker_sha256=bytes(actor.authority_marker_sha256),
    )


def _selector_discovery_context(
    actor: MatchingHttpActor, organization_id: str
) -> MatchingSelectorDiscoveryContext:
    exact_organization_id = _resource_uuid(organization_id)
    if (
        not isinstance(actor, MatchingHttpActor)
        or actor.workspace_kind != "ORGANIZATION"
        or actor.organization_id != str(exact_organization_id)
        or len(actor.authority_marker_sha256) != 32
    ):
        raise MatchingApplicationError("RESOURCE_NOT_FOUND")
    return MatchingSelectorDiscoveryContext(
        actor_user_id=_resource_uuid(actor.actor_user_id),
        session_id=_resource_uuid(actor.session_id),
        organization_id=exact_organization_id,
        authority_marker_sha256=bytes(actor.authority_marker_sha256),
    )


def _review_context(actor: MatchingHttpActor) -> MatchingReviewContext:
    if (
        not isinstance(actor, MatchingHttpActor)
        or actor.workspace_kind != "PLATFORM"
        or actor.organization_id is not None
        or "OPERATIONS_REVIEWER" not in actor.role_codes
        or len(actor.authority_marker_sha256) != 32
    ):
        raise MatchingApplicationError("RESOURCE_NOT_FOUND")
    return MatchingReviewContext(
        actor_user_id=_resource_uuid(actor.actor_user_id),
        session_id=_resource_uuid(actor.session_id),
        principal_marker_sha256=bytes(actor.authority_marker_sha256),
    )


def _creator_write_context(
    actor: MatchingPostgresActorContext,
) -> MatchingCreatorContext:
    return MatchingCreatorContext(
        actor_user_id=_request_uuid(actor.actor_id),
        session_id=_request_uuid(actor.session_id),
        authority_marker_sha256=bytes(actor.authority_marker_sha256),
    )


def _selector_write_context(
    actor: MatchingPostgresActorContext,
    command: Any,
) -> MatchingSelectorContext:
    return MatchingSelectorContext(
        actor_user_id=_request_uuid(actor.actor_id),
        session_id=_request_uuid(actor.session_id),
        organization_id=_request_uuid(actor.organization_id),
        selection_id=_request_uuid(command.selection_id),
        assignment_id=_request_uuid(command.assignment_id),
        assignment_version=command.expected_assignment_version,
        authority_marker_sha256=bytes(actor.authority_marker_sha256),
    )


def _review_write_context(
    actor: MatchingPostgresActorContext,
) -> MatchingReviewContext:
    if len(actor.authority_marker_sha256) != 32:
        raise MatchingApplicationError("RESOURCE_NOT_FOUND")
    return MatchingReviewContext(
        actor_user_id=_request_uuid(actor.actor_id),
        session_id=_request_uuid(actor.session_id),
        principal_marker_sha256=bytes(actor.authority_marker_sha256),
    )


def _recipient_organization_id(value: RecipientInvitationView) -> str:
    preview = value.disclosure.get("organization_preview")
    organization_id = preview.get("organization_id") if isinstance(preview, Mapping) else None
    return str(_resource_uuid(organization_id))


def _recipient_data(value: RecipientInvitationView) -> Mapping[str, Any]:
    return {
        "invitation_id": str(value.invitation_id),
        "status": value.status,
        "aggregate_version": value.aggregate_version,
        "updated_at": _utc_text(value.updated_at),
        "expires_at": _utc_text(value.expires_at),
        "snapshot_sha256": value.snapshot_sha256,
        "response_status": value.response_status,
        "disclosure": _json_value(value.disclosure),
    }


def _attempt_data(value: MatchingAttemptView) -> Mapping[str, Any]:
    return {
        "attempt_id": str(value.attempt_id),
        "demand_id": str(value.demand_id),
        "attempt_no": value.attempt_no,
        "status": value.status,
        "aggregate_version": value.aggregate_version,
        "updated_at": _utc_text(value.updated_at),
    }


def _selection_data(value: MatchingSelectionView) -> Mapping[str, Any]:
    return {
        "selection_id": str(value.selection_id),
        "attempt_id": str(value.attempt_id),
        "candidate_selector_assignment_id": str(
            value.candidate_selector_assignment_id
        ),
        "candidate_selector_assignment_version": (
            value.candidate_selector_assignment_version
        ),
        "status": value.status,
        "aggregate_version": value.aggregate_version,
        "updated_at": _utc_text(value.updated_at),
        "current_invitation_set_sha256": value.current_invitation_set_sha256,
        "chosen_invitation_id": (
            None
            if value.chosen_invitation_id is None
            else str(value.chosen_invitation_id)
        ),
        "accepted_invitations": [
            {
                "invitation_id": str(item.invitation_id),
                "creator_display_handle": item.creator_display_handle,
                "profile_id": str(item.profile_id),
                "profile_version_id": str(item.profile_version_id),
                "accepted_at": _utc_text(item.accepted_at),
                "capability_summary": item.capability_summary,
            }
            for item in value.accepted_invitations
        ],
    }


def _selection_projection(
    value: Optional[MatchingSelectionView],
) -> MatchingHttpProjection:
    if value is None:
        raise MatchingApplicationError("RESOURCE_NOT_FOUND")
    return MatchingHttpProjection(
        kind="SELECTION",
        data=_selection_data(value),
        entity_tag=value.entity_tag,
    )


def _invitation_result(
    value: RecipientInvitationView,
    *,
    replayed: bool,
    event_types: Tuple[str, ...],
) -> MatchingCommandResult:
    return MatchingCommandResult(
        target_id=str(value.invitation_id),
        target_status=value.status,
        aggregate_version=value.aggregate_version,
        updated_at=value.updated_at,
        replayed=replayed,
        event_types=event_types,
    )


def _selection_result(
    value: MatchingSelectionView,
    *,
    replayed: bool,
    event_types: Tuple[str, ...],
) -> MatchingCommandResult:
    return MatchingCommandResult(
        target_id=str(value.selection_id),
        target_status=value.status,
        aggregate_version=value.aggregate_version,
        updated_at=value.updated_at,
        replayed=replayed,
        event_types=event_types,
    )


def _new_operational_id(id_source: Any, purpose: str) -> UUID:
    value = id_source.new_id(purpose)
    if not isinstance(value, UUID) or value.int == 0:
        raise MatchingPostgresConfigurationError()
    return value


def _operational_material(
    *,
    actor_id: str,
    organization_id: Optional[str],
    correlation_id: str,
    trace_id: str,
    operation: str,
    idempotency_key: str,
    payload: Mapping[str, Any],
    outbox_count: int,
    keys: MatchingPostgresHttpKeys,
    id_source: Any,
) -> MatchingOperationalCommandMaterial:
    if (
        not isinstance(operation, str)
        or not operation
        or not isinstance(idempotency_key, str)
        or _IDEMPOTENCY_KEY.fullmatch(idempotency_key) is None
        or type(outbox_count) is not int
        or not 1 <= outbox_count <= 102
        or not isinstance(payload, Mapping)
    ):
        raise ValueError("Matching operational command is invalid")
    identity = json.dumps(
        {
            "canonicalization_version": _CANONICALIZATION_VERSION,
            "command_version": 1,
            "idempotency_key": idempotency_key,
            "operation": operation,
            "organization_id": organization_id,
            "principal_id": actor_id,
            "principal_kind": "USER",
        },
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    body = json.dumps(
        {
            "canonicalization_version": _CANONICALIZATION_VERSION,
            "command_version": 1,
            "operation": operation,
            "organization_id": organization_id,
            "payload": _json_value(payload),
        },
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return MatchingOperationalCommandMaterial(
        command_id=_new_operational_id(id_source, "matching_operational_command"),
        receipt_id=_new_operational_id(
            id_source, "matching_operational_command_receipt"
        ),
        identity_key_id=keys.idempotency_key_id,
        identity_digest=keys.digest(purpose="IDEMPOTENCY", value=identity),
        payload_hash_key_id=keys.payload_hash_key_id,
        payload_hash=keys.digest(purpose="PAYLOAD_HASH", value=body),
        audit_event_id=_new_operational_id(
            id_source, "matching_operational_audit_event"
        ),
        outbox_event_ids=tuple(
            _new_operational_id(
                id_source, f"matching_operational_outbox_event_{ordinal}"
            )
            for ordinal in range(outbox_count)
        ),
        correlation_id=_request_uuid(correlation_id),
        trace_id=_request_uuid(trace_id),
    )


def _canonical_command(
    *, actor: MatchingPostgresActorContext, command: Any
) -> bytes:
    normalized = _normalize_command(command)
    if isinstance(command, RespondInvitationCommand):
        suffix = "accept" if command.accept else "decline"
        path = f"/v1/me/matching-invitations/{command.invitation_id}/{suffix}"
        target_kind = "Invitation"
        target_id = command.invitation_id
        expected_version = command.expected_invitation_version
    elif isinstance(command, WithdrawAcceptedInvitationCommand):
        path = f"/v1/me/matching-invitations/{command.invitation_id}/withdraw"
        target_kind = "Invitation"
        target_id = command.invitation_id
        expected_version = command.expected_invitation_version
    elif isinstance(command, ChooseCreatorCommand):
        path = (
            f"/v1/organizations/{actor.organization_id}/selections/"
            f"{command.selection_id}/choose"
        )
        target_kind = "Selection"
        target_id = command.selection_id
        expected_version = command.expected_selection_version
    elif isinstance(command, CloseSelectionWithoutChoiceCommand):
        path = (
            f"/v1/organizations/{actor.organization_id}/selections/"
            f"{command.selection_id}/close"
        )
        target_kind = "Selection"
        target_id = command.selection_id
        expected_version = command.expected_selection_version
    else:
        raise MatchingPostgresConfigurationError()
    return json.dumps(
        {
            "body": normalized,
            "canonical_path": path,
            "command_schema_version": 1,
            "if_match": expected_version,
            "method": "POST",
            "organization_id": actor.organization_id,
            "target": {
                "id": target_id,
                "kind": target_kind,
                "parent_id": None,
                "parent_kind": None,
            },
        },
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _normalize_command(value: Any) -> Any:
    if is_dataclass(value):
        return {
            name: _normalize_command(item)
            for name, item in asdict(value).items()
            if name not in {"idempotency_key", "scheduler_command_id"}
        }
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, datetime):
        return _utc_text(value)
    if isinstance(value, tuple):
        return [_normalize_command(item) for item in value]
    if isinstance(value, dict):
        return {str(name): _normalize_command(item) for name, item in value.items()}
    return value


def _next_cursor(
    *,
    keys: MatchingPostgresHttpKeys,
    operation: str,
    actor_user_id: UUID,
    organization_id: Optional[UUID],
    demand_id: Optional[UUID],
    limit: int,
    updated_at: Optional[datetime],
    item_id: Optional[UUID],
) -> Optional[str]:
    if (updated_at is None) != (item_id is None):
        raise MatchingPostgresConfigurationError()
    if updated_at is None or item_id is None:
        return None
    document = {
        "actor_user_id": str(actor_user_id),
        "demand_id": None if demand_id is None else str(demand_id),
        "item_id": str(item_id),
        "key_id": keys.read_cursor_key_id,
        "limit": limit,
        "operation": operation,
        "organization_id": (
            None if organization_id is None else str(organization_id)
        ),
        "updated_at": _cursor_timestamp(updated_at),
        "version": _CURSOR_VERSION,
    }
    canonical = json.dumps(
        document,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    token = (
        f"{_b64(canonical)}."
        f"{_b64(keys.sign_cursor(canonical))}"
    )
    if _CURSOR_TOKEN.fullmatch(token) is None:
        raise MatchingPostgresConfigurationError()
    return token


def _decode_cursor(
    cursor: Optional[str],
    *,
    keys: MatchingPostgresHttpKeys,
    operation: str,
    actor_user_id: UUID,
    organization_id: Optional[UUID],
    demand_id: Optional[UUID],
    limit: int,
) -> Tuple[Optional[datetime], Optional[UUID]]:
    if cursor is None:
        return None, None
    if not isinstance(cursor, str) or _CURSOR_TOKEN.fullmatch(cursor) is None:
        raise ValueError("Matching cursor is invalid")
    encoded, encoded_signature = cursor.split(".", 1)
    raw = _unb64(encoded)
    signature = _unb64(encoded_signature)
    if len(raw) > 1_536:
        raise ValueError("Matching cursor is invalid")
    pairs = json.loads(
        raw.decode("ascii"),
        object_pairs_hook=lambda values: values,
        parse_float=lambda _value: _invalid_cursor(),
        parse_constant=lambda _value: _invalid_cursor(),
    )
    if not isinstance(pairs, list) or any(
        not isinstance(item, tuple) or len(item) != 2 for item in pairs
    ):
        raise ValueError("Matching cursor is invalid")
    names = [name for name, _value in pairs]
    if len(names) != len(set(names)):
        raise ValueError("Matching cursor is invalid")
    document = dict(pairs)
    if set(document) != {
        "actor_user_id",
        "demand_id",
        "item_id",
        "key_id",
        "limit",
        "operation",
        "organization_id",
        "updated_at",
        "version",
    }:
        raise ValueError("Matching cursor is invalid")
    canonical = json.dumps(
        document,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    if (
        document["actor_user_id"] != str(actor_user_id)
        or document["organization_id"]
        != (None if organization_id is None else str(organization_id))
        or document["demand_id"] != (None if demand_id is None else str(demand_id))
        or document["operation"] != operation
        or document["limit"] != limit
        or document["version"] != _CURSOR_VERSION
        or document["key_id"] != keys.read_cursor_key_id
        or _b64(canonical) != encoded
        or not keys.verify_cursor(value=canonical, signature=signature)
    ):
        raise ValueError("Matching cursor authority is invalid")
    item_id = _resource_uuid(document["item_id"])
    updated_at = datetime.fromisoformat(
        str(document["updated_at"]).replace("Z", "+00:00")
    )
    if _cursor_timestamp(updated_at) != document["updated_at"]:
        raise ValueError("Matching cursor is invalid")
    return updated_at, item_id


def _read_cursor(*args: Any, **kwargs: Any) -> Tuple[Optional[datetime], Optional[UUID]]:
    try:
        return _decode_cursor(*args, **kwargs)
    except _MatchingCursorInvalid:
        raise
    except (
        AttributeError,
        TypeError,
        ValueError,
        UnicodeError,
        binascii.Error,
        json.JSONDecodeError,
    ):
        raise _MatchingCursorInvalid("Matching cursor is invalid") from None


def _projection_error(error: Exception) -> None:
    if isinstance(error, MatchingApplicationError):
        raise error
    if isinstance(error, MatchingPostgresRejectedError):
        raise MatchingApplicationError(error.code) from None
    if isinstance(error, MatchingPostgresConfigurationError):
        raise MatchingApplicationError("SERVICE_UNAVAILABLE") from None
    if isinstance(error, _MatchingCursorInvalid):
        raise MatchingApplicationError("INVALID_REQUEST") from None
    if isinstance(error, _MatchingResourceInvalid):
        raise MatchingApplicationError("RESOURCE_NOT_FOUND") from None
    if isinstance(error, (TypeError, ValueError, AttributeError, UnicodeError)):
        raise MatchingApplicationError("SERVICE_UNAVAILABLE") from None
    raise MatchingApplicationError("SERVICE_UNAVAILABLE") from None


def _resource_uuid(value: Any) -> UUID:
    try:
        result = UUID(value) if isinstance(value, str) else value
    except (ValueError, AttributeError):
        raise _MatchingResourceInvalid(
            "Matching resource identifier is invalid"
        ) from None
    if (
        not isinstance(result, UUID)
        or result.int == 0
        or (isinstance(value, str) and str(result) != value)
    ):
        raise _MatchingResourceInvalid("Matching resource identifier is invalid")
    return result


def _request_uuid(value: Any) -> UUID:
    try:
        result = UUID(value) if isinstance(value, str) else value
    except (ValueError, AttributeError):
        raise ValueError("Matching request identifier is invalid") from None
    if not isinstance(result, UUID) or result.int == 0:
        raise ValueError("Matching request identifier is invalid")
    if isinstance(value, str) and str(result) != value:
        raise ValueError("Matching request identifier is invalid")
    return result


def _utc_text(value: datetime) -> str:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() is None
    ):
        raise ValueError("Matching timestamp is invalid")
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _cursor_timestamp(value: datetime) -> str:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() != timedelta(0)
    ):
        raise ValueError("Matching cursor timestamp is invalid")
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def _json_value(value: Any) -> Any:
    if value is None or isinstance(value, (bool, int, str)):
        return value
    if isinstance(value, (tuple, list)):
        return [_json_value(item) for item in value]
    if isinstance(value, Mapping):
        return {str(name): _json_value(item) for name, item in value.items()}
    raise MatchingPostgresConfigurationError()


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _unb64(value: str) -> bytes:
    return base64.b64decode(
        (value + "=" * (-len(value) % 4)).encode("ascii"),
        altchars=b"-_",
        validate=True,
    )


def _invalid_cursor() -> Any:
    raise ValueError("Matching cursor is invalid")


__all__ = [
    "MATCHING_POSTGRES_OPERATIONAL_SUPPORT",
    "MatchingPostgresActorContext",
    "MatchingPostgresHttpKeys",
    "MatchingPostgresOperationalHttpService",
    "PostgresCreateMatchingInvitationHandler",
    "PostgresChooseCreatorHandler",
    "PostgresCloseSelectionWithoutChoiceHandler",
    "PostgresInvalidateMatchingAttemptHandler",
    "PostgresPublishMatchingInvitationHandler",
    "PostgresRespondInvitationHandler",
    "PostgresWithdrawAcceptedInvitationHandler",
    "PsycopgMatchingCommandActorResolver",
    "PsycopgMatchingHttpProjectionAdapter",
    "PsycopgMatchingReviewerAssignmentResolver",
    "build_matching_postgres_http_bindings",
]
