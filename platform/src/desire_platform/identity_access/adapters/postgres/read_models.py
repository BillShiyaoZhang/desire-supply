"""Default-deny PostgreSQL 18 repository for the nine IAM read models.

The implementation executes only the reviewed fixed-statement registry through
role-bound online pools.  It has no owner/migration or Memory fallback and
exposes no arbitrary SQL/filter entry point.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
from typing import Any, Callable, Mapping, Optional, Protocol, Sequence
import uuid

from ...read_model_registry import (
    READ_STATEMENT_PROFILES,
    RegisteredReadStatementProfile,
)
from ...ports.access_invitation_capability import (
    VerifiedAccessInvitationCapability,
)
from ...ports.read_models import ReadModelSnapshot, ReadPageWindow
from ...ports.read_models import ReadModelStorageUnavailableError
from . import read_model_sql


POSTGRES_READ_MODEL_BEHAVIOR_NOT_AVAILABLE = (
    "IAM_POSTGRES_READ_MODEL_BEHAVIOR_NOT_AVAILABLE"
)


class PostgresReadModelBehaviorNotAvailable(RuntimeError):
    """Compatibility-only semantic RED sentinel; production methods do not emit it."""


class PostgresReadModelConfigurationError(RuntimeError):
    """The role, server, transaction, or closed settings are unsafe."""


class ReadModelConnectionSource(Protocol):
    """A role-bound pool boundary with explicit connection disposition."""

    def checkout(self) -> Any: ...

    def release(self, connection: Any) -> None: ...

    def discard(self, connection: Any) -> None: ...


@dataclass(frozen=True)
class PostgresReadModelSettings:
    """Closed deployment settings shared by both role-bound read pools."""

    lock_timeout_ms: int = 500
    statement_timeout_ms: int = 5_000
    idle_in_transaction_timeout_ms: int = 10_000
    maximum_snapshot_bytes: int = 2 * 1024 * 1024
    maximum_policy_document_bytes: int = 200 * 1024

    def __post_init__(self) -> None:
        if not 1 <= self.lock_timeout_ms <= 1_000:
            raise ValueError("read lock timeout is outside the reviewed bounds")
        if not 1 <= self.statement_timeout_ms <= 5_000:
            raise ValueError(
                "read statement timeout is outside the reviewed bounds"
            )
        if not 1 <= self.idle_in_transaction_timeout_ms <= 10_000:
            raise ValueError(
                "read idle-in-transaction timeout is outside the reviewed bounds"
            )
        if self.maximum_snapshot_bytes != 2 * 1024 * 1024:
            raise ValueError("read snapshot byte budget must use the v1 value")
        if self.maximum_policy_document_bytes != 200 * 1024:
            raise ValueError("policy document byte budget must use the v1 value")


class PsycopgIamReadModelRepository:
    """Closed psycopg implementation of the nine fixed PostgreSQL programs."""

    def __init__(
        self,
        *,
        app_connections: ReadModelConnectionSource,
        onboarding_connections: ReadModelConnectionSource,
        settings: PostgresReadModelSettings = PostgresReadModelSettings(),
    ) -> None:
        self._app_connections = app_connections
        self._onboarding_connections = onboarding_connections
        self._settings = settings

    @staticmethod
    def profile(operation_id: str) -> RegisteredReadStatementProfile:
        try:
            return READ_STATEMENT_PROFILES[operation_id]
        except KeyError as error:
            raise ValueError("unknown IAM read-model operation") from error

    def read_session_bootstrap(
        self, *, actor_user_id: str, session_id: str
    ) -> ReadModelSnapshot:
        actor = _uuid_text(actor_user_id)
        session = _uuid_text(session_id)
        return self._run(
            "getSessionBootstrap",
            context={"actor_user_id": actor, "session_id": session},
            reader=lambda connection, _: _read_session_bootstrap(
                connection, actor, session
            ),
        )

    def read_invitation_preview(
        self, *, capability: VerifiedAccessInvitationCapability
    ) -> ReadModelSnapshot:
        if not isinstance(capability, VerifiedAccessInvitationCapability):
            raise ValueError("verified invitation capability is required")
        invitation_id = _uuid_text(capability.invitation_id)
        return self._run(
            "inspectAccessInvitation",
            context={"target_invitation_id": invitation_id},
            reader=lambda connection, _: _read_invitation_preview(
                connection, invitation_id
            ),
        )

    def read_public_policy_bundle(
        self, *, policy_bundle_id: str
    ) -> ReadModelSnapshot:
        bundle_id = _uuid_text(policy_bundle_id)
        return self._run(
            "getPolicyBundle",
            context={"policy_bundle_id": bundle_id},
            reader=lambda connection, _: _read_public_policy_bundle(
                connection, bundle_id
            ),
        )

    def read_me(
        self, *, actor_user_id: str, session_id: str
    ) -> ReadModelSnapshot:
        actor = _uuid_text(actor_user_id)
        session = _uuid_text(session_id)
        return self._run(
            "getMe",
            context={"actor_user_id": actor, "session_id": session},
            reader=lambda connection, _: _read_me(connection, actor, session),
        )

    def list_my_consent_grants(
        self,
        *,
        actor_user_id: str,
        session_id: str,
        window: ReadPageWindow,
    ) -> ReadModelSnapshot:
        actor = _uuid_text(actor_user_id)
        session = _uuid_text(session_id)
        return self._run(
            "listMyConsentGrants",
            context={"actor_user_id": actor, "session_id": session},
            reader=lambda connection, transaction_time: _read_consent_page(
                connection, actor, session, window, transaction_time
            ),
        )

    def list_my_sessions(
        self,
        *,
        actor_user_id: str,
        session_id: str,
        window: ReadPageWindow,
    ) -> ReadModelSnapshot:
        actor = _uuid_text(actor_user_id)
        session = _uuid_text(session_id)
        return self._run(
            "listMySessions",
            context={"actor_user_id": actor, "session_id": session},
            reader=lambda connection, transaction_time: _read_session_page(
                connection, actor, session, window, transaction_time
            ),
        )

    def read_organization_summary(
        self,
        *,
        actor_user_id: str,
        session_id: str,
        organization_id: str,
    ) -> ReadModelSnapshot:
        actor = _uuid_text(actor_user_id)
        session = _uuid_text(session_id)
        organization = _uuid_text(organization_id)
        return self._run(
            "getOrganizationSummary",
            context={
                "actor_user_id": actor,
                "session_id": session,
                "organization_id": organization,
            },
            reader=lambda connection, _: _read_organization_summary(
                connection, actor, session, organization
            ),
        )

    def list_organization_access_invitations(
        self,
        *,
        actor_user_id: str,
        session_id: str,
        organization_id: str,
        window: ReadPageWindow,
    ) -> ReadModelSnapshot:
        actor = _uuid_text(actor_user_id)
        session = _uuid_text(session_id)
        organization = _uuid_text(organization_id)
        return self._run(
            "listOrganizationAccessInvitations",
            context={
                "actor_user_id": actor,
                "session_id": session,
                "organization_id": organization,
            },
            reader=lambda connection, transaction_time: _read_invitation_page(
                connection,
                actor,
                session,
                organization,
                window,
                transaction_time,
            ),
        )

    def list_organization_memberships(
        self,
        *,
        actor_user_id: str,
        session_id: str,
        organization_id: str,
        window: ReadPageWindow,
    ) -> ReadModelSnapshot:
        actor = _uuid_text(actor_user_id)
        session = _uuid_text(session_id)
        organization = _uuid_text(organization_id)
        return self._run(
            "listOrganizationMemberships",
            context={
                "actor_user_id": actor,
                "session_id": session,
                "organization_id": organization,
            },
            reader=lambda connection, transaction_time: _read_membership_page(
                connection,
                actor,
                session,
                organization,
                window,
                transaction_time,
            ),
        )

    def _run(
        self,
        operation_id: str,
        *,
        context: Mapping[str, str],
        reader: Callable[[Any, datetime], Mapping[str, object]],
    ) -> ReadModelSnapshot:
        profile = self.profile(operation_id)
        source = (
            self._app_connections
            if profile.runtime_role == "iam_app"
            else self._onboarding_connections
        )
        connection = source.checkout()
        transaction_started = False
        try:
            if getattr(connection, "autocommit", None) is not True:
                raise PostgresReadModelConfigurationError(
                    "IAM read connections must use explicit autocommit control"
                )
            _reset_connection(connection)
            connection.execute(
                "BEGIN TRANSACTION ISOLATION LEVEL READ COMMITTED READ ONLY"
            )
            transaction_started = True
            transaction_time = _install_context(
                connection,
                profile=profile,
                context=context,
                settings=self._settings,
            )
            facts = reader(connection, transaction_time)
            if not isinstance(facts, Mapping):
                raise RuntimeError("fixed read program returned invalid facts")
            _enforce_snapshot_size(facts, self._settings.maximum_snapshot_bytes)
            connection.execute("COMMIT")
            transaction_started = False
            _reset_connection(connection)
            source.release(connection)
            return ReadModelSnapshot.from_mapping(
                transaction_time=transaction_time,
                statement_count=profile.statement_budget,
                facts=facts,
            )
        except PostgresReadModelConfigurationError:
            _abort_and_discard(
                source, connection, transaction_started=transaction_started
            )
            raise
        except Exception as error:
            _abort_and_discard(
                source, connection, transaction_started=transaction_started
            )
            raise ReadModelStorageUnavailableError(
                "IAM PostgreSQL read program unavailable"
            ) from error


_CONTEXT_KEYS = (
    "actor_user_id",
    "session_id",
    "organization_id",
    "target_invitation_id",
    "policy_bundle_id",
    "policy_selector_digest",
    "scope_kind",
    "operation",
    "query_shape_digest",
)


def _uuid_text(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError("IAM read identifier must be a UUID string")
    try:
        return str(uuid.UUID(value))
    except (ValueError, AttributeError) as error:
        raise ValueError("IAM read identifier must be a UUID string") from error


def _reset_connection(connection: Any) -> None:
    connection.execute("RESET ROLE")
    connection.execute("RESET ALL")
    connection.execute("DISCARD TEMP")


def _abort_and_discard(
    source: ReadModelConnectionSource,
    connection: Any,
    *,
    transaction_started: bool,
) -> None:
    try:
        if transaction_started:
            connection.execute("ROLLBACK")
        _reset_connection(connection)
    except Exception:
        pass
    source.discard(connection)


def _install_context(
    connection: Any,
    *,
    profile: RegisteredReadStatementProfile,
    context: Mapping[str, str],
    settings: PostgresReadModelSettings,
) -> datetime:
    unexpected = set(context).difference(_CONTEXT_KEYS)
    if unexpected:
        raise PostgresReadModelConfigurationError(
            "IAM read context contains an unregistered setting"
        )
    values = {
        **{name: "" for name in _CONTEXT_KEYS},
        **context,
        "scope_kind": profile.scope_kind,
        "operation": profile.scope_operation,
        "query_shape_digest": profile.query_shape_digest,
    }
    connection.execute("SET LOCAL TIME ZONE 'UTC'")
    statement = """
    /* iam.install_read_context_v1 */
    SELECT
        session_user,
        current_user,
        current_setting('server_version_num')::integer,
        transaction_timestamp(),
        set_config('lock_timeout', %s, true),
        set_config('statement_timeout', %s, true),
        set_config('idle_in_transaction_session_timeout', %s, true),
        set_config('app.actor_user_id', %s, true),
        set_config('app.session_id', %s, true),
        set_config('app.organization_id', %s, true),
        set_config('app.target_invitation_id', %s, true),
        set_config('app.policy_bundle_id', %s, true),
        set_config('app.policy_selector_digest', %s, true),
        set_config('app.scope_kind', %s, true),
        set_config('app.operation', %s, true),
        set_config('app.query_shape_digest', %s, true)
    """
    row = connection.execute(
        statement,
        (
            f"{settings.lock_timeout_ms}ms",
            f"{settings.statement_timeout_ms}ms",
            f"{settings.idle_in_transaction_timeout_ms}ms",
            *(values[name] for name in _CONTEXT_KEYS),
        ),
    ).fetchone()
    if row is None:
        raise PostgresReadModelConfigurationError(
            "IAM read connection did not report its identity"
        )
    session_role, current_role, server_version, transaction_time = row[:4]
    if session_role != profile.runtime_role or current_role != profile.runtime_role:
        raise PostgresReadModelConfigurationError(
            "IAM read connection uses the wrong online role"
        )
    if not isinstance(server_version, int) or server_version < 180000:
        raise PostgresReadModelConfigurationError(
            "IAM read repository requires PostgreSQL 18 or newer"
        )
    if not isinstance(transaction_time, datetime) or transaction_time.utcoffset() is None:
        raise PostgresReadModelConfigurationError(
            "IAM read transaction timestamp is invalid"
        )
    return transaction_time


def _rows(cursor: Any) -> list[dict[str, Any]]:
    description = cursor.description
    if description is None:
        raise RuntimeError("fixed read statement has no result description")
    names = tuple(column.name for column in description)
    return [dict(zip(names, row)) for row in cursor.fetchall()]


def _execute_rows(connection: Any, statement: str, parameters: Sequence[Any]) -> list[dict[str, Any]]:
    return _rows(connection.execute(statement, tuple(parameters)))


def _text_id(value: object) -> Optional[str]:
    if value is None:
        return None
    return str(value)


def _hex(value: object) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, str):
        return value[2:] if value.startswith("\\x") else value
    raise RuntimeError("fixed read digest projection has an invalid type")


def _authority(row: Mapping[str, Any], *, include_csrf: bool = False) -> dict[str, object]:
    user = {
        "user_id": _text_id(row.get("actor_user_id")),
        "status": row.get("actor_user_status"),
        "display_handle": row.get("actor_display_handle"),
        "aggregate_version": row.get("actor_user_version"),
    }
    session = {
        "session_id": _text_id(row.get("current_session_id")),
        "user_id": _text_id(row.get("current_session_user_id")),
        "family_id": _text_id(row.get("current_session_family_id")),
        "generation": row.get("current_session_generation"),
        "created_at": row.get("current_session_created_at"),
        "last_activity_at": row.get("current_session_last_activity_at"),
        "idle_expires_at": row.get("current_session_idle_expires_at"),
        "absolute_expires_at": row.get("current_session_absolute_expires_at"),
        "device_label": row.get("current_session_device_label"),
        "status": row.get("current_session_status"),
        "aggregate_version": row.get("current_session_version"),
    }
    if include_csrf:
        session.update(
            {
                "csrf_salt": row.get("current_session_csrf_salt"),
                "csrf_key_id": row.get("current_session_csrf_key_id"),
                "csrf_digest": row.get("current_session_csrf_digest"),
            }
        )
    family = {
        "family_id": _text_id(row.get("current_family_id")),
        "user_id": _text_id(row.get("current_family_user_id")),
        "status": row.get("current_family_status"),
        "current_generation": row.get("current_family_generation"),
        "aggregate_version": row.get("current_family_version"),
    }
    return {"user": user, "session": session, "family": family}


def _organization(row: Mapping[str, Any]) -> Optional[dict[str, object]]:
    if row.get("organization_id") is None:
        return None
    return {
        "organization_id": _text_id(row.get("organization_id")),
        "public_name": row.get("organization_public_name"),
        "organization_type": row.get("organization_type"),
        "jurisdiction": row.get("organization_jurisdiction"),
        "status": row.get("organization_status"),
        "aggregate_version": row.get("organization_version"),
    }


def _read_session_bootstrap(connection: Any, actor: str, session: str) -> Mapping[str, object]:
    rows = _execute_rows(
        connection,
        read_model_sql.READ_SESSION_BOOTSTRAP_V1,
        (actor, session),
    )
    return {} if not rows else _authority(rows[0], include_csrf=True)


def _invitation(row: Mapping[str, Any]) -> dict[str, object]:
    return {
        "invitation_id": _text_id(row.get("invitation_id")),
        "purpose": row.get("invitation_purpose"),
        "organization_id": _text_id(row.get("invitation_organization_id")),
        "target_scope": row.get("invitation_target_scope"),
        "target_role": row.get("invitation_target_role"),
        "is_initial_admin": row.get("invitation_is_initial_admin"),
        "recipient_contact_id": _text_id(row.get("invitation_recipient_contact_id")),
        "masked_recipient_label": row.get("invitation_masked_recipient_label"),
        "policy_selector_digest": _hex(row.get("invitation_selector_digest")),
        "issued_policy_bundle_id": _text_id(row.get("invitation_issued_bundle_id")),
        "status": row.get("invitation_status"),
        "expires_at": row.get("invitation_expires_at"),
        "token_nonce": row.get("invitation_token_nonce"),
        "token_key_id": row.get("invitation_token_key_id"),
        "token_format_version": row.get("invitation_token_format_version"),
        "accepted_by_user_id": _text_id(row.get("invitation_accepted_by_user_id")),
        "aggregate_version": row.get("invitation_version"),
        "created_at": row.get("invitation_created_at"),
    }


def _policy_from_join(rows: Sequence[Mapping[str, Any]]) -> Mapping[str, object]:
    if not rows or rows[0].get("selector_digest") is None:
        return {}
    first = rows[0]
    selector = {
        "selector_digest": _hex(first.get("selector_digest")),
        "canonicalization_version": first.get("selector_canonicalization_version"),
        "access_purpose": first.get("selector_access_purpose"),
        "scope_type": first.get("selector_scope_type"),
        "target_role": first.get("selector_target_role"),
        "jurisdiction": first.get("selector_jurisdiction"),
        "locale": first.get("selector_locale"),
        "current_bundle_id": _text_id(first.get("selector_current_bundle_id")),
    }
    bundle = {
        "policy_bundle_id": _text_id(first.get("bundle_id")),
        "selector_digest": _hex(first.get("bundle_selector_digest")),
        "status": first.get("bundle_status"),
        "effective_at": first.get("bundle_effective_at"),
        "effective_until": first.get("bundle_effective_until"),
        "aggregate_version": first.get("bundle_version"),
    }
    documents_by_id: dict[str, dict[str, object]] = {}
    offers_by_id: dict[str, dict[str, object]] = {}
    for row in rows:
        document_id = _text_id(row.get("document_id"))
        if document_id is not None:
            documents_by_id.setdefault(
                document_id,
                {
                    "document_id": document_id,
                    "bundle_id": _text_id(first.get("bundle_id")),
                    "position": row.get("document_position"),
                    "required": row.get("document_required"),
                    "kind": row.get("document_kind"),
                    "semantic_version": row.get("document_semantic_version"),
                    "locale": row.get("document_locale"),
                    "jurisdiction": row.get("document_jurisdiction"),
                    "canonical_body": row.get("document_canonical_body"),
                    "content_sha256": _hex(row.get("document_content_sha256")),
                    "legal_effect": row.get("document_legal_effect"),
                    "status": row.get("document_status"),
                },
            )
        offer_id = _text_id(row.get("offer_id"))
        if offer_id is not None:
            offers_by_id.setdefault(
                offer_id,
                {
                    "canonicalization_version": "consent-offer-json-v1",
                    "consent_offer_id": offer_id,
                    "consent_offer_version": row.get("offer_version"),
                    "policy_bundle_id": _text_id(first.get("bundle_id")),
                    "purpose": row.get("offer_purpose"),
                    "scope_type": row.get("offer_scope_type"),
                    "scope_derivation": row.get("offer_scope_derivation"),
                    "data_categories": list(row.get("offer_categories") or ()),
                    "recipient_ref": row.get("offer_recipient_ref"),
                    "recipient_label": row.get("offer_recipient_label"),
                    "supporting_document_id": _text_id(row.get("offer_document_id")),
                    "supporting_document_sha256": _hex(row.get("offer_document_sha256")),
                    "expiry_rule": row.get("offer_expiry_rule"),
                    "expiry_days": row.get("offer_expiry_days"),
                    "not_after": row.get("offer_not_after"),
                    "optional": row.get("offer_optional"),
                    "canonical_offer_sha256": _hex(row.get("offer_canonical_sha256")),
                },
            )
    return {
        "selector": selector,
        "bundle": bundle,
        "documents": sorted(
            documents_by_id.values(), key=lambda item: int(item["position"] or 0)
        ),
        "offers": sorted(
            offers_by_id.values(),
            key=lambda item: (str(item["purpose"]), str(item["consent_offer_id"])),
        ),
    }


def _read_invitation_preview(connection: Any, invitation_id: str) -> Mapping[str, object]:
    rows = _execute_rows(
        connection,
        read_model_sql.READ_INVITATION_PREVIEW_V1,
        (invitation_id,),
    )
    if not rows:
        return {"invitation": {}, "organization": {}, "policy": {}}
    first = rows[0]
    return {
        "invitation": _invitation(first),
        "recipient_binding": {
            "contact_point_id": _text_id(first.get("recipient_contact_id")),
            "contact_type": first.get("recipient_contact_type"),
            "binding_digest": _hex(first.get("recipient_binding_digest")),
            "binding_digest_key_id": first.get(
                "recipient_binding_digest_key_id"
            ),
        },
        "organization": _organization(first) or {},
        "policy": _policy_from_join(rows),
    }


def _read_public_policy_bundle(connection: Any, bundle_id: str) -> Mapping[str, object]:
    roots = _execute_rows(
        connection,
        read_model_sql.READ_PUBLIC_POLICY_BUNDLE_V1,
        (bundle_id,),
    )
    documents = _execute_rows(
        connection,
        read_model_sql.READ_PUBLIC_POLICY_DOCUMENTS_V1,
        (bundle_id,),
    )
    offers = _execute_rows(
        connection,
        read_model_sql.READ_PUBLIC_POLICY_OFFERS_V1,
        (bundle_id,),
    )
    if not roots:
        return {}
    root = roots[0]
    join_rows: list[dict[str, Any]] = []
    if not documents:
        documents = [{}]
    if not offers:
        offers = [{}]
    for document in documents:
        for offer in offers:
            join_rows.append(
                {
                    "selector_digest": root.get("selector_digest"),
                    "selector_canonicalization_version": root.get("canonicalization_version"),
                    "selector_access_purpose": root.get("access_purpose"),
                    "selector_scope_type": root.get("scope_type"),
                    "selector_target_role": root.get("target_role"),
                    "selector_jurisdiction": root.get("jurisdiction"),
                    "selector_locale": root.get("locale"),
                    "selector_current_bundle_id": root.get("current_bundle_id"),
                    "bundle_id": root.get("bundle_id"),
                    "bundle_selector_digest": root.get("bundle_selector_digest"),
                    "bundle_status": root.get("bundle_status"),
                    "bundle_effective_at": root.get("bundle_effective_at"),
                    "bundle_effective_until": root.get("bundle_effective_until"),
                    "bundle_version": root.get("bundle_version"),
                    "document_id": document.get("document_id"),
                    "document_position": document.get("position"),
                    "document_required": document.get("required"),
                    "document_kind": document.get("kind"),
                    "document_semantic_version": document.get("semantic_version"),
                    "document_locale": document.get("locale"),
                    "document_jurisdiction": document.get("jurisdiction"),
                    "document_canonical_body": document.get("canonical_body"),
                    "document_content_sha256": document.get("content_sha256"),
                    "document_legal_effect": document.get("legal_effect"),
                    "document_status": document.get("status"),
                    "offer_id": offer.get("offer_id"),
                    "offer_version": offer.get("offer_version"),
                    "offer_purpose": offer.get("purpose"),
                    "offer_scope_type": offer.get("scope_type"),
                    "offer_scope_derivation": offer.get("scope_derivation"),
                    "offer_recipient_ref": offer.get("recipient_ref"),
                    "offer_recipient_label": offer.get("recipient_label"),
                    "offer_document_id": offer.get("document_id"),
                    "offer_document_sha256": offer.get("document_content_sha256"),
                    "offer_expiry_rule": offer.get("expiry_rule"),
                    "offer_expiry_days": offer.get("expiry_days"),
                    "offer_not_after": offer.get("not_after"),
                    "offer_optional": offer.get("optional"),
                    "offer_canonical_sha256": offer.get("canonical_offer_sha256"),
                    "offer_categories": offer.get("categories"),
                }
            )
    return _policy_from_join(join_rows)


_JSON_TIME_FIELDS = {
    "accepted_at",
    "created_at",
    "effective_at",
    "effective_until",
    "expires_at",
    "granted_at",
    "last_activity_at",
    "not_after",
    "revoked_at",
    "updated_at",
    "withdrawn_at",
}


def _restore_json_fact(value: object, *, field_name: str = "") -> object:
    if isinstance(value, Mapping):
        return {
            str(key): _restore_json_fact(item, field_name=str(key))
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_restore_json_fact(item, field_name=field_name) for item in value]
    if isinstance(value, str) and field_name in _JSON_TIME_FIELDS:
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return value
        return parsed
    return value


def _read_me(connection: Any, actor: str, session: str) -> Mapping[str, object]:
    summary = _execute_rows(
        connection,
        read_model_sql.READ_ME_SELF_SUMMARY_V1,
        (actor, session),
    )
    graph_rows = _execute_rows(
        connection,
        read_model_sql.READ_ME_AUTHORITY_POLICY_GRAPH_V1,
        (actor, actor, actor, actor, actor, actor),
    )
    if not summary:
        return {
            "user": {},
            "session": {},
            "family": {},
            "user_role_grants": [],
            "memberships": [],
            "source_invitations": [],
            "policies": [],
            "acceptances": [],
        }
    facts: dict[str, object] = {
        **_authority(summary[0]),
        "user_role_grants": [],
        "memberships": [],
        "source_invitations": [],
        "policies": [],
        "acceptances": [],
    }
    destinations = {
        "user_role": "user_role_grants",
        "membership": "memberships",
        "source_invitation": "source_invitations",
        "policy": "policies",
        "acceptance": "acceptances",
    }
    for row in graph_rows:
        destination = destinations.get(row.get("record_kind"))
        if destination is None:
            raise RuntimeError("fixed getMe graph returned an unknown record kind")
        payload = _restore_json_fact(row.get("payload"))
        if not isinstance(payload, Mapping):
            raise RuntimeError("fixed getMe graph returned an invalid payload")
        target = facts[destination]
        if not isinstance(target, list):
            raise RuntimeError("fixed getMe graph destination is invalid")
        target.append(dict(payload))
    return facts


def _page_window(window: ReadPageWindow, transaction_time: datetime) -> tuple[datetime, Optional[datetime], Optional[str], int]:
    if not isinstance(window, ReadPageWindow):
        raise ValueError("IAM read page window is required")
    if isinstance(window.limit, bool) or not isinstance(window.limit, int):
        raise ValueError("IAM read page limit must be an integer")
    if not 1 <= window.limit <= 100:
        raise ValueError("IAM read page limit is outside the reviewed bounds")
    if (window.after_created_at is None) != (window.after_id is None):
        raise ValueError("IAM read page boundary must be a complete tuple")
    snapshot_at = window.snapshot_at or transaction_time
    if not isinstance(snapshot_at, datetime) or snapshot_at.utcoffset() is None:
        raise ValueError("IAM read page snapshot must be timezone-aware")
    if snapshot_at > transaction_time:
        raise ValueError("IAM read page snapshot cannot be in the future")
    after_created_at = window.after_created_at
    after_id: Optional[str] = None
    if after_created_at is not None:
        if after_created_at.utcoffset() is None or after_created_at > snapshot_at:
            raise ValueError("IAM read page boundary is outside its snapshot")
        after_id = _uuid_text(window.after_id)
    return snapshot_at, after_created_at, after_id, window.limit + 1


def _grant_from_row(row: Mapping[str, Any]) -> dict[str, object]:
    return {
        "consent_grant_id": _text_id(row.get("grant_id")),
        "user_id": _text_id(row.get("grant_user_id")),
        "consent_offer_id": _text_id(row.get("consent_offer_id")),
        "consent_offer_version": row.get("consent_offer_version"),
        "purpose": row.get("grant_purpose"),
        "scope_type": row.get("grant_scope_type"),
        "scope_id": _text_id(row.get("grant_scope_id")),
        "recipient_ref": row.get("grant_recipient_ref"),
        "recipient_label": row.get("grant_recipient_label"),
        "document_id": _text_id(row.get("grant_document_id")),
        "content_sha256": _hex(row.get("grant_document_sha256")),
        "granted_at": row.get("granted_at"),
        "expires_at": row.get("grant_expires_at"),
        "status": row.get("grant_status"),
        "withdrawn_at": row.get("grant_withdrawn_at"),
        "aggregate_version": row.get("grant_version"),
        "created_at": row.get("grant_created_at"),
    }


def _read_consent_page(
    connection: Any,
    actor: str,
    session: str,
    window: ReadPageWindow,
    transaction_time: datetime,
) -> Mapping[str, object]:
    snapshot_at, after_at, after_id, fetch_limit = _page_window(
        window, transaction_time
    )
    roots = _execute_rows(
        connection,
        read_model_sql.READ_MY_CONSENT_GRANTS_PAGE_V1,
        (
            snapshot_at,
            after_at,
            after_at,
            after_id,
            actor,
            session,
            fetch_limit,
        ),
    )
    grant_ids = [str(row["grant_id"]) for row in roots if row.get("grant_id")]
    children = _execute_rows(
        connection,
        read_model_sql.READ_MY_CONSENT_GRANT_CHILDREN_V1,
        (grant_ids,),
    )
    children_by_id = {str(row["grant_id"]): row for row in children}
    rows: list[dict[str, object]] = []
    for root in roots:
        if root.get("grant_id") is None:
            continue
        grant_id = str(root["grant_id"])
        child = children_by_id.get(grant_id, {})
        withdrawals: list[dict[str, object]] = []
        if child.get("withdrawal_grant_id") is not None:
            withdrawals.append(
                {
                    "consent_grant_id": _text_id(child.get("withdrawal_grant_id")),
                    "user_id": _text_id(child.get("withdrawal_user_id")),
                    "withdrawn_at": child.get("withdrawn_at"),
                    "reason_code": child.get("withdrawal_reason_code"),
                }
            )
        rows.append(
            {
                "grant": _grant_from_row(root),
                "categories": list(child.get("categories") or ()),
                "withdrawals": withdrawals,
                "sort_id": grant_id,
                "created_at": root.get("grant_created_at"),
            }
        )
    actor_facts = {} if not roots else _authority(roots[0])
    return {"actor": actor_facts, "rows": rows, "snapshot_at": snapshot_at}


def _listed_session(row: Mapping[str, Any]) -> dict[str, object]:
    return {
        "session_id": _text_id(row.get("listed_session_id")),
        "user_id": _text_id(row.get("listed_session_user_id")),
        "family_id": _text_id(row.get("listed_session_family_id")),
        "generation": row.get("listed_session_generation"),
        "created_at": row.get("listed_session_created_at"),
        "last_activity_at": row.get("listed_session_last_activity_at"),
        "idle_expires_at": row.get("listed_session_idle_expires_at"),
        "absolute_expires_at": row.get("listed_session_absolute_expires_at"),
        "device_label": row.get("listed_session_device_label"),
        "status": row.get("listed_session_status"),
        "aggregate_version": row.get("listed_session_version"),
        "sort_id": _text_id(row.get("listed_session_id")),
    }


def _read_session_page(
    connection: Any,
    actor: str,
    session: str,
    window: ReadPageWindow,
    transaction_time: datetime,
) -> Mapping[str, object]:
    snapshot_at, after_at, after_id, fetch_limit = _page_window(
        window, transaction_time
    )
    roots = _execute_rows(
        connection,
        read_model_sql.READ_MY_SESSIONS_PAGE_V1,
        (
            snapshot_at,
            after_at,
            after_at,
            after_id,
            actor,
            session,
            fetch_limit,
        ),
    )
    rows = [
        _listed_session(row)
        for row in roots
        if row.get("listed_session_id") is not None
    ]
    actor_facts = {} if not roots else _authority(roots[0])
    return {"actor": actor_facts, "rows": rows, "snapshot_at": snapshot_at}


def _organization_actor(rows: Sequence[Mapping[str, Any]]) -> dict[str, object]:
    if not rows:
        return {}
    first = rows[0]
    facts: dict[str, object] = _authority(first)
    organization = _organization(first)
    facts["organization"] = organization
    if first.get("actor_membership_id") is None:
        facts["membership"] = None
        facts["roles"] = []
        return facts
    membership_id = _text_id(first.get("actor_membership_id"))
    facts["membership"] = {
        "membership_id": membership_id,
        "organization_id": _text_id(first.get("actor_membership_organization_id")),
        "user_id": _text_id(first.get("actor_membership_user_id")),
        "status": first.get("actor_membership_status"),
        "source_invitation_id": _text_id(first.get("actor_membership_source_invitation_id")),
        "aggregate_version": first.get("actor_membership_version"),
        "created_at": first.get("actor_membership_created_at"),
    }
    roles: list[dict[str, object]] = []
    for row in rows:
        if row.get("actor_role_grant_id") is None:
            continue
        roles.append(
            {
                "role_grant_id": _text_id(row.get("actor_role_grant_id")),
                "organization_id": _text_id(first.get("actor_membership_organization_id")),
                "membership_id": membership_id,
                "user_id": _text_id(first.get("actor_membership_user_id")),
                "role_code": row.get("actor_role_code"),
                "source_invitation_id": _text_id(row.get("actor_role_source_invitation_id")),
                "policy_selector_digest": _hex(row.get("actor_role_selector_digest")),
                "revoked_at": row.get("actor_role_revoked_at"),
                "aggregate_version": row.get("actor_role_version"),
            }
        )
    facts["roles"] = roles
    return facts


def _read_organization_summary(
    connection: Any, actor: str, session: str, organization: str
) -> Mapping[str, object]:
    rows = _execute_rows(
        connection,
        read_model_sql.READ_ORGANIZATION_SUMMARY_V1,
        (organization, actor, session),
    )
    actor_facts = _organization_actor(rows)
    return {
        "actor": actor_facts,
        "organization": actor_facts.get("organization"),
    }


def _organization_page_parameters(
    organization: str,
    window: ReadPageWindow,
    transaction_time: datetime,
) -> tuple[datetime, Optional[datetime], Optional[str], int, tuple[object, ...]]:
    snapshot_at, after_at, after_id, fetch_limit = _page_window(
        window, transaction_time
    )
    parameters: tuple[object, ...] = (
        organization,
        snapshot_at,
        after_at,
        after_at,
        after_id,
        organization,
        snapshot_at,
        after_at,
        after_at,
        after_id,
        fetch_limit,
    )
    return snapshot_at, after_at, after_id, fetch_limit, parameters


def _read_invitation_page(
    connection: Any,
    actor: str,
    session: str,
    organization: str,
    window: ReadPageWindow,
    transaction_time: datetime,
) -> Mapping[str, object]:
    authority_rows = _execute_rows(
        connection,
        read_model_sql.READ_ORGANIZATION_ACTOR_AUTHORITY_V1,
        (organization, actor, session),
    )
    snapshot_at, _, _, _, parameters = _organization_page_parameters(
        organization, window, transaction_time
    )
    flat_rows = _execute_rows(
        connection,
        read_model_sql.READ_ORGANIZATION_INVITATIONS_PAGE_V1,
        parameters,
    )
    grouped: dict[str, list[dict[str, Any]]] = {}
    ordered_ids: list[str] = []
    for row in flat_rows:
        invitation_id = str(row["invitation_id"])
        if invitation_id not in grouped:
            grouped[invitation_id] = []
            ordered_ids.append(invitation_id)
        grouped[invitation_id].append(row)
    rows: list[dict[str, object]] = []
    for invitation_id in ordered_ids:
        group = grouped[invitation_id]
        first = group[0]
        rows.append(
            {
                "invitation": _invitation(first),
                "policy": _policy_from_join(group),
                "recipient_mask_verified": True,
                "sort_id": invitation_id,
                "created_at": first.get("invitation_created_at"),
            }
        )
    actor_facts = _organization_actor(authority_rows)
    return {
        "actor": actor_facts,
        "organization": actor_facts.get("organization"),
        "rows": rows,
        "snapshot_at": snapshot_at,
    }


def _read_membership_page(
    connection: Any,
    actor: str,
    session: str,
    organization: str,
    window: ReadPageWindow,
    transaction_time: datetime,
) -> Mapping[str, object]:
    authority_rows = _execute_rows(
        connection,
        read_model_sql.READ_ORGANIZATION_ACTOR_AUTHORITY_V1,
        (organization, actor, session),
    )
    snapshot_at, _, _, _, parameters = _organization_page_parameters(
        organization, window, transaction_time
    )
    flat_rows = _execute_rows(
        connection,
        read_model_sql.READ_ORGANIZATION_MEMBERSHIPS_PAGE_V1,
        parameters,
    )
    grouped: dict[str, list[dict[str, Any]]] = {}
    ordered_ids: list[str] = []
    for row in flat_rows:
        membership_id = str(row["membership_id"])
        if membership_id not in grouped:
            grouped[membership_id] = []
            ordered_ids.append(membership_id)
        grouped[membership_id].append(row)
    rows: list[dict[str, object]] = []
    for membership_id in ordered_ids:
        group = grouped[membership_id]
        first = group[0]
        role_grants: list[dict[str, object]] = []
        for row in group:
            if row.get("role_grant_id") is None:
                continue
            role_grants.append(
                {
                    "role_grant_id": _text_id(row.get("role_grant_id")),
                    "organization_id": _text_id(row.get("organization_id")),
                    "membership_id": membership_id,
                    "user_id": _text_id(row.get("user_id")),
                    "role_code": row.get("role_code"),
                    "source_invitation_id": _text_id(row.get("role_source_invitation_id")),
                    "policy_selector_digest": _hex(row.get("role_selector_digest")),
                    "revoked_at": row.get("role_revoked_at"),
                    "aggregate_version": row.get("role_version"),
                }
            )
        rows.append(
            {
                "membership": {
                    "membership_id": membership_id,
                    "organization_id": _text_id(first.get("organization_id")),
                    "user_id": _text_id(first.get("user_id")),
                    "status": first.get("membership_status"),
                    "source_invitation_id": _text_id(first.get("source_invitation_id")),
                    "aggregate_version": first.get("membership_version"),
                    "created_at": first.get("membership_created_at"),
                },
                "user": {
                    "user_id": _text_id(first.get("target_user_id")),
                    "status": first.get("target_user_status"),
                    "display_handle": first.get("target_display_handle"),
                    "aggregate_version": first.get("target_user_version"),
                },
                "role_grants": role_grants,
                "sort_id": membership_id,
                "created_at": first.get("membership_created_at"),
            }
        )
    actor_facts = _organization_actor(authority_rows)
    return {
        "actor": actor_facts,
        "organization": actor_facts.get("organization"),
        "rows": rows,
        "snapshot_at": snapshot_at,
    }


def _json_size_value(value: object) -> object:
    if isinstance(value, Mapping):
        return {str(key): _json_size_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_size_value(item) for item in value]
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat()
    if isinstance(value, bytes):
        return value.hex()
    return value


def _enforce_snapshot_size(facts: Mapping[str, object], maximum_bytes: int) -> None:
    encoded = json.dumps(
        _json_size_value(facts),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    if len(encoded) > maximum_bytes:
        raise RuntimeError("fixed IAM read snapshot exceeded its byte budget")


__all__ = [
    "POSTGRES_READ_MODEL_BEHAVIOR_NOT_AVAILABLE",
    "PostgresReadModelBehaviorNotAvailable",
    "PostgresReadModelConfigurationError",
    "PostgresReadModelSettings",
    "PsycopgIamReadModelRepository",
    "READ_STATEMENT_PROFILES",
    "ReadModelConnectionSource",
    "RegisteredReadStatementProfile",
]
