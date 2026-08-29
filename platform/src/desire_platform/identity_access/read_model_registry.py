"""Shared closed registry for the nine IAM read-model SQL programs.

The application cursor binding and every storage adapter consume these exact
profiles.  Request input can therefore never select a statement name or alter
the query-shape digest carried by a cursor.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from types import MappingProxyType
from typing import Mapping, Tuple


@dataclass(frozen=True)
class RegisteredReadStatementProfile:
    """Immutable identity for one reviewed SQL program."""

    operation_id: str
    runtime_role: str
    scope_kind: str
    scope_operation: str
    statement_names: Tuple[str, ...]
    statement_budget: int
    query_shape_digest: str
    paged: bool

    def __post_init__(self) -> None:
        if self.runtime_role not in {"iam_app", "iam_onboarding"}:
            raise ValueError("read profile uses an unreviewed runtime role")
        if self.statement_budget != len(self.statement_names):
            raise ValueError("read statement budget must equal the fixed program")
        if not self.statement_names or len(set(self.statement_names)) != len(
            self.statement_names
        ):
            raise ValueError("read statement names must be non-empty and unique")
        if (
            len(self.query_shape_digest) != 64
            or any(
                character not in "0123456789abcdef"
                for character in self.query_shape_digest
            )
        ):
            raise ValueError("read query-shape digest must be lowercase SHA-256")


def _profile(
    operation_id: str,
    *,
    runtime_role: str,
    scope_kind: str,
    scope_operation: str,
    statement_names: Tuple[str, ...],
    paged: bool = False,
) -> RegisteredReadStatementProfile:
    canonical_shape = json.dumps(
        {
            "operation_id": operation_id,
            "paged": paged,
            "projection_version": 1,
            "scope_kind": scope_kind,
            "scope_operation": scope_operation,
            "statement_names": statement_names,
        },
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return RegisteredReadStatementProfile(
        operation_id=operation_id,
        runtime_role=runtime_role,
        scope_kind=scope_kind,
        scope_operation=scope_operation,
        statement_names=statement_names,
        statement_budget=len(statement_names),
        query_shape_digest=hashlib.sha256(canonical_shape).hexdigest(),
        paged=paged,
    )


_PROFILES = (
    _profile(
        "getSessionBootstrap",
        runtime_role="iam_app",
        scope_kind="SELF",
        scope_operation="READ_SESSION_BOOTSTRAP",
        statement_names=("read_session_bootstrap_v1",),
    ),
    _profile(
        "inspectAccessInvitation",
        runtime_role="iam_onboarding",
        scope_kind="INVITATION",
        scope_operation="INSPECT",
        statement_names=("read_invitation_preview_v1",),
    ),
    _profile(
        "getPolicyBundle",
        runtime_role="iam_app",
        scope_kind="PUBLIC_POLICY_READ",
        scope_operation="READ_PUBLIC_POLICY_BUNDLE",
        statement_names=(
            "read_public_policy_bundle_v1",
            "read_public_policy_documents_v1",
            "read_public_policy_offers_v1",
        ),
    ),
    _profile(
        "getMe",
        runtime_role="iam_app",
        scope_kind="SELF",
        scope_operation="ME_READ_MODEL",
        statement_names=(
            "read_me_self_summary_v1",
            "read_me_authority_policy_graph_v1",
        ),
    ),
    _profile(
        "listMyConsentGrants",
        runtime_role="iam_app",
        scope_kind="SELF",
        scope_operation="LIST_MY_CONSENT_GRANTS",
        statement_names=(
            "read_my_consent_grants_page_v1",
            "read_my_consent_grant_children_v1",
        ),
        paged=True,
    ),
    _profile(
        "listMySessions",
        runtime_role="iam_app",
        scope_kind="SELF",
        scope_operation="LIST_MY_SESSIONS",
        statement_names=("read_my_sessions_page_v1",),
        paged=True,
    ),
    _profile(
        "getOrganizationSummary",
        runtime_role="iam_app",
        scope_kind="ORGANIZATION",
        scope_operation="READ_ORGANIZATION_SUMMARY",
        statement_names=("read_organization_summary_v1",),
    ),
    _profile(
        "listOrganizationAccessInvitations",
        runtime_role="iam_app",
        scope_kind="ORGANIZATION",
        scope_operation="LIST_ORGANIZATION_INVITATIONS",
        statement_names=(
            "read_organization_actor_authority_v1",
            "read_organization_invitations_page_v1",
        ),
        paged=True,
    ),
    _profile(
        "listOrganizationMemberships",
        runtime_role="iam_app",
        scope_kind="ORGANIZATION",
        scope_operation="LIST_ORGANIZATION_MEMBERSHIPS",
        statement_names=(
            "read_organization_actor_authority_v1",
            "read_organization_memberships_page_v1",
        ),
        paged=True,
    ),
)

READ_STATEMENT_PROFILES: Mapping[str, RegisteredReadStatementProfile] = (
    MappingProxyType({profile.operation_id: profile for profile in _PROFILES})
)
READ_STATEMENT_BUDGETS: Mapping[str, int] = MappingProxyType(
    {
        operation_id: profile.statement_budget
        for operation_id, profile in READ_STATEMENT_PROFILES.items()
    }
)
PAGED_READ_QUERY_SHAPE_DIGESTS: Mapping[str, str] = MappingProxyType(
    {
        operation_id: profile.query_shape_digest
        for operation_id, profile in READ_STATEMENT_PROFILES.items()
        if profile.paged
    }
)


__all__ = [
    "PAGED_READ_QUERY_SHAPE_DIGESTS",
    "READ_STATEMENT_BUDGETS",
    "READ_STATEMENT_PROFILES",
    "RegisteredReadStatementProfile",
]
