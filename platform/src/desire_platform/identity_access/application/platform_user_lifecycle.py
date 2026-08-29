"""Closed ACCESS_ADMIN commands over the existing OIDC/IAM user and sessions.

This module does not create a second account or session model.  It reduces or
restores authority on the existing ``iam.users`` aggregate and converges the
existing OIDC BFF Session families in the same unit of work.
"""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta
from typing import Any, Mapping, Sequence

from .authority_lifecycle import (
    _LifecycleHandler,
    _audit,
    _event,
    _lock_receipt,
    _receipt_response,
    _reason_body,
    _require_current_session,
    _require_recent_mfa,
)
from ..domain.authority_lifecycle import (
    LifecycleActorContext,
    LifecycleCommandResult,
    ResumeUserCommand,
    RevokeAllSessionsCommand,
    SuspendUserCommand,
)
from ..domain.errors import IamError
from ..ports.authority_lifecycle import LifecycleStorageUnavailableError


class _PlatformUserLifecycleHandler(_LifecycleHandler):
    _action = ""
    _event_type = ""
    _from_statuses: frozenset[str] = frozenset()
    _to_status = ""
    _path_suffix = ""
    _revoke_sessions = False

    def _after_status(self, target: Mapping[str, Any]) -> str:
        return self._to_status

    def handle(
        self,
        *,
        actor: LifecycleActorContext,
        command: Any,
    ) -> LifecycleCommandResult:
        now = self._now()
        snapshot = self._snapshot()
        current_session = _require_current_session(snapshot, actor=actor, now=now)
        reason_body = _reason_body(self._keyring, command.reason)
        material = self._receipt_material(
            actor=actor,
            command=command,
            command_name=self._action,
            target_type="User",
            target_id=command.user_id,
            path="/v1/platform/users/%s/%s" % (command.user_id, self._path_suffix),
            expected_version=command.expected_version,
            body={"reason": reason_body},
            session=current_session,
        )
        receipt = self._receipt(snapshot, material)
        target = self._guards(
            snapshot,
            actor=actor,
            command=command,
            now=now,
            check_state=receipt is None,
            check_version=receipt is None,
        )
        if receipt is not None:
            response = _receipt_response(receipt, "PlatformUserAdminDto")
            _require_receipt_binding(response, target)
            self._validate_response(response, "PlatformUserAdminDto")
            return LifecycleCommandResult(True, 200, response)

        family_ids, session_ids = _active_session_coordinates(
            snapshot,
            user_id=target["user_id"],
        )
        receipt_id = self._id_source.new_id("command_receipt")
        pending = self._pending_receipt(material, receipt_id=receipt_id, now=now)
        try:
            with self._uow_factory.begin() as uow:
                self._lock_rows(
                    uow,
                    snapshot=snapshot,
                    actor=actor,
                    target=target,
                    material=material,
                    family_ids=family_ids,
                    session_ids=session_ids,
                    now=now,
                )
                tables = uow.tables
                locked_target = self._guards(
                    tables,
                    actor=actor,
                    command=command,
                    now=now,
                    check_state=True,
                    check_version=True,
                )
                locked_families, locked_sessions = _require_locked_session_set(
                    tables,
                    user_id=locked_target["user_id"],
                    expected_family_ids=family_ids,
                    expected_session_ids=session_ids,
                )
                response = self._write_transaction(
                    uow,
                    tables=tables,
                    actor=actor,
                    command=command,
                    target=locked_target,
                    families=locked_families,
                    sessions=locked_sessions,
                    pending=pending,
                    receipt_id=receipt_id,
                    now=now,
                )
                self._commit(uow)
        except LifecycleStorageUnavailableError as error:
            raise IamError("SERVICE_UNAVAILABLE") from error
        return LifecycleCommandResult(False, 200, response)

    def _guards(
        self,
        tables: Mapping[str, Mapping[str, Any]],
        *,
        actor: LifecycleActorContext,
        command: Any,
        now: datetime,
        check_state: bool,
        check_version: bool,
    ) -> Mapping[str, Any]:
        session = _require_current_session(tables, actor=actor, now=now)
        _require_access_admin(tables, actor_user_id=actor.actor_user_id, now=now)
        _require_recent_mfa(session, now)
        if command.user_id == actor.actor_user_id:
            raise IamError("SELF_MANAGEMENT_FORBIDDEN")
        target = tables.get("users", {}).get(command.user_id)
        if target is None or target.get("user_id") != command.user_id:
            raise IamError("RESOURCE_NOT_FOUND")
        if check_state and target.get("status") not in self._from_statuses:
            raise IamError("INVALID_STATE_TRANSITION")
        if check_version and target.get("aggregate_version") != command.expected_version:
            raise IamError("PRECONDITION_FAILED")
        if self._action == "SuspendUser":
            _require_not_last_access_admin(tables, target_user_id=command.user_id, now=now)
        return target

    def _lock_rows(
        self,
        uow: Any,
        *,
        snapshot: Mapping[str, Mapping[str, Any]],
        actor: LifecycleActorContext,
        target: Mapping[str, Any],
        material: Mapping[str, Any],
        family_ids: Sequence[str],
        session_ids: Sequence[str],
        now: datetime,
    ) -> None:
        _lock_receipt(uow, material)
        actor_session = snapshot["sessions"][actor.current_session_id]
        uow.lock("session_families", (actor_session["session_family_id"],))
        uow.lock("sessions", (actor.current_session_id,))
        uow.lock(
            "users",
            tuple(sorted({actor.actor_user_id, target["user_id"]})),
        )
        duty_ids = sorted(
            grant["platform_duty_grant_id"]
            for grant in snapshot.get("platform_duty_grants", {}).values()
            if _duty_active(grant, now)
            and grant.get("duty_code") == "ACCESS_ADMIN"
        )
        uow.lock("platform_duty_grants", tuple(duty_ids))
        uow.lock("session_families", tuple(sorted(family_ids)))
        uow.lock("sessions", tuple(sorted(session_ids)))

    def _write_transaction(
        self,
        uow: Any,
        *,
        tables: Mapping[str, Mapping[str, Any]],
        actor: LifecycleActorContext,
        command: Any,
        target: Mapping[str, Any],
        families: Sequence[Mapping[str, Any]],
        sessions: Sequence[Mapping[str, Any]],
        pending: Mapping[str, Any],
        receipt_id: str,
        now: datetime,
    ) -> Mapping[str, Any]:
        self._put(
            uow,
            "command_receipts",
            receipt_id,
            pending,
            "platform_user.receipt_in_progress",
        )
        revoked_families = []
        revoked_sessions = []
        if self._revoke_sessions:
            for index, family in enumerate(families):
                updated_family = deepcopy(family)
                updated_family.update(
                    {
                        "status": "REVOKED",
                        "revoked_at": now,
                        "revocation_reason_code": command.reason.reason_code,
                        "aggregate_version": family["aggregate_version"] + 1,
                    }
                )
                self._put(
                    uow,
                    "session_families",
                    family["session_family_id"],
                    updated_family,
                    "platform_user.family.%d" % index,
                )
                revoked_families.append(updated_family)
            for index, session in enumerate(sessions):
                updated_session = deepcopy(session)
                updated_session.update(
                    {
                        "status": "REVOKED",
                        "revoked_at": now,
                        "revocation_reason_code": command.reason.reason_code,
                        "aggregate_version": session["aggregate_version"] + 1,
                    }
                )
                self._put(
                    uow,
                    "sessions",
                    session["session_id"],
                    updated_session,
                    "platform_user.session.%d" % index,
                )
                revoked_sessions.append(updated_session)

        after_status = self._after_status(target)
        updated_user = deepcopy(target)
        updated_user.update(
            {
                "status": after_status,
                "aggregate_version": target["aggregate_version"] + 1,
                "updated_at": now,
            }
        )
        self._put(
            uow,
            "users",
            target["user_id"],
            updated_user,
            "platform_user.aggregate",
        )
        response = _platform_user_dto(
            updated_user,
            revoked_session_count=len(revoked_sessions),
            revoked_family_count=len(revoked_families),
        )
        self._validate_response(response, "PlatformUserAdminDto")
        actor_session = tables["sessions"][actor.current_session_id]
        audit_id = self._id_source.new_id("audit_event")
        self._put(
            uow,
            "audit_events",
            audit_id,
            _audit(
                audit_id=audit_id,
                actor=actor,
                action=self._action,
                target_type="User",
                target_id=target["user_id"],
                organization_id=None,
                auth_strength=actor_session["acr_code"],
                reason_code=command.reason.reason_code,
                before_status=target["status"],
                after_status=updated_user["status"],
                before_version=target["aggregate_version"],
                after_version=updated_user["aggregate_version"],
                occurred_at=now,
            ),
            "platform_user.audit",
        )
        main_event_id = self._id_source.new_id("outbox_event")
        main_payload = (
            {
                "user_id": target["user_id"],
                "scope": "ALL_ACTIVE_SESSION_FAMILIES",
            }
            if self._event_type == "SessionsRevoked"
            else {"user_id": target["user_id"], "status": updated_user["status"]}
        )
        main_event = _event(
            event_id=main_event_id,
            event_type=self._event_type,
            aggregate_type="User",
            aggregate_id=target["user_id"],
            aggregate_version=updated_user["aggregate_version"],
            actor=actor,
            organization_id=None,
            occurred_at=now,
            payload=main_payload,
        )
        self._validate_event(main_event)
        self._put(
            uow,
            "outbox_events",
            main_event_id,
            main_event,
            "platform_user.outbox.0",
        )
        for index, session in enumerate(revoked_sessions, start=1):
            event_id = self._id_source.new_id("outbox_event")
            event = _event(
                event_id=event_id,
                event_type="SessionRevoked",
                aggregate_type="Session",
                aggregate_id=session["session_id"],
                aggregate_version=session["aggregate_version"],
                actor=actor,
                organization_id=None,
                occurred_at=now,
                payload={
                    "session_id": session["session_id"],
                    "session_family_id": session["session_family_id"],
                    "user_id": session["user_id"],
                    "status": "REVOKED",
                },
            )
            self._validate_event(event)
            self._put(
                uow,
                "outbox_events",
                event_id,
                event,
                "platform_user.outbox.%d" % index,
            )
        completed = self._complete_receipt(
            pending,
            response_body=response,
            response_schema="PlatformUserAdminDto",
            now=now,
        )
        self._put(
            uow,
            "command_receipts",
            receipt_id,
            completed,
            "platform_user.receipt_completed",
        )
        return response


class SuspendUserHandler(_PlatformUserLifecycleHandler):
    _action = "SuspendUser"
    _event_type = "UserSuspended"
    _from_statuses = frozenset({"ACTIVE"})
    _to_status = "SUSPENDED"
    _path_suffix = "suspend"
    _revoke_sessions = True


class ResumeUserHandler(_PlatformUserLifecycleHandler):
    _action = "ResumeUser"
    _event_type = "UserResumed"
    _from_statuses = frozenset({"SUSPENDED"})
    _to_status = "ACTIVE"
    _path_suffix = "resume"
    # A resume never revives prior credentials.  Any legacy/drifted ACTIVE
    # family is reduced in the same transaction before the User becomes ACTIVE.
    _revoke_sessions = True


class RevokeAllSessionsHandler(_PlatformUserLifecycleHandler):
    _action = "RevokeAllSessions"
    _event_type = "SessionsRevoked"
    _from_statuses = frozenset({"ACTIVE", "SUSPENDED"})
    _to_status = "ACTIVE"
    _path_suffix = "revoke-all-sessions"
    _revoke_sessions = True

    def _after_status(self, target: Mapping[str, Any]) -> str:
        return target["status"]


def _duty_active(grant: Mapping[str, Any], now: datetime) -> bool:
    expires_at = grant.get("expires_at")
    granted_at = grant.get("granted_at")
    revoked_at = grant.get("revoked_at")
    if (
        not _is_utc(granted_at)
        or not _is_utc(now)
        or (expires_at is not None and not _is_utc(expires_at))
        or (revoked_at is not None and not _is_utc(revoked_at))
    ):
        raise IamError("SERVICE_UNAVAILABLE")
    return (
        granted_at <= now
        and revoked_at is None
        and (expires_at is None or now < expires_at)
    )


def _is_utc(value: object) -> bool:
    return (
        isinstance(value, datetime)
        and value.tzinfo is not None
        and value.utcoffset() == timedelta(0)
    )


def _require_access_admin(
    tables: Mapping[str, Mapping[str, Any]],
    *,
    actor_user_id: str,
    now: datetime,
) -> Mapping[str, Any]:
    grants = [
        grant
        for grant in tables.get("platform_duty_grants", {}).values()
        if grant.get("user_id") == actor_user_id
        and grant.get("duty_code") == "ACCESS_ADMIN"
        and _duty_active(grant, now)
    ]
    if not grants:
        raise IamError("RESOURCE_NOT_FOUND")
    if len(grants) != 1:
        raise IamError("SERVICE_UNAVAILABLE")
    return grants[0]


def _active_access_admin_users(
    tables: Mapping[str, Mapping[str, Any]], now: datetime
) -> set[str]:
    return {
        grant["user_id"]
        for grant in tables.get("platform_duty_grants", {}).values()
        if grant.get("duty_code") == "ACCESS_ADMIN"
        and _duty_active(grant, now)
        and tables.get("users", {}).get(grant.get("user_id"), {}).get("status")
        == "ACTIVE"
    }


def _require_not_last_access_admin(
    tables: Mapping[str, Mapping[str, Any]], *, target_user_id: str, now: datetime
) -> None:
    active_admins = _active_access_admin_users(tables, now)
    if target_user_id in active_admins and len(active_admins) <= 1:
        raise IamError("LAST_ACTIVE_ACCESS_ADMIN")


def _active_session_coordinates(
    tables: Mapping[str, Mapping[str, Any]], *, user_id: str
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    session_ids = tuple(
        sorted(
            session["session_id"]
            for session in tables.get("sessions", {}).values()
            if session.get("user_id") == user_id and session.get("status") == "ACTIVE"
        )
    )
    family_ids = tuple(
        sorted(
            family["session_family_id"]
            for family in tables.get("session_families", {}).values()
            if family.get("user_id") == user_id and family.get("status") == "ACTIVE"
        )
    )
    return family_ids, session_ids


def _require_locked_session_set(
    tables: Mapping[str, Mapping[str, Any]],
    *,
    user_id: str,
    expected_family_ids: Sequence[str],
    expected_session_ids: Sequence[str],
) -> tuple[list[Mapping[str, Any]], list[Mapping[str, Any]]]:
    actual_family_ids, actual_session_ids = _active_session_coordinates(
        tables, user_id=user_id
    )
    if tuple(expected_family_ids) != actual_family_ids or tuple(expected_session_ids) != actual_session_ids:
        raise IamError("PRECONDITION_FAILED")
    families = [tables["session_families"][item] for item in actual_family_ids]
    sessions = [tables["sessions"][item] for item in actual_session_ids]
    active_family_ids = {item["session_family_id"] for item in families}
    if any(session.get("session_family_id") not in active_family_ids for session in sessions):
        raise IamError("SERVICE_UNAVAILABLE")
    return families, sessions


def _platform_user_dto(
    user: Mapping[str, Any], *, revoked_session_count: int, revoked_family_count: int
) -> dict[str, Any]:
    version = user.get("aggregate_version")
    return {
        "user_id": user["user_id"],
        "display_handle": user["display_handle"],
        "status": user["status"],
        "aggregate_version": version,
        "entity_tag": '"v%d"' % version,
        "revoked_session_count": revoked_session_count,
        "revoked_session_family_count": revoked_family_count,
    }


def _require_receipt_binding(
    response: Mapping[str, Any], user: Mapping[str, Any]
) -> None:
    version = user.get("aggregate_version")
    expected = {
        "user_id": user.get("user_id"),
        "display_handle": user.get("display_handle"),
        "status": user.get("status"),
        "aggregate_version": version,
        "entity_tag": '"v%d"' % version,
    }
    if any(response.get(name) != value for name, value in expected.items()):
        raise IamError("SERVICE_UNAVAILABLE")
    for name in ("revoked_session_count", "revoked_session_family_count"):
        value = response.get(name)
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise IamError("SERVICE_UNAVAILABLE")


__all__ = ["ResumeUserHandler", "RevokeAllSessionsHandler", "SuspendUserHandler"]
