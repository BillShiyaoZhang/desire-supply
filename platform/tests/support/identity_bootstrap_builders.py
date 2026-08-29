"""Independent fixtures for the closed internal-sandbox identity manifest."""

from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, Optional, Tuple
from uuid import NAMESPACE_URL, uuid5


def _id(label: str) -> str:
    return str(uuid5(NAMESPACE_URL, "https://desire.test/bootstrap/" + label))


def identity_bootstrap_document(
    *,
    revision: int = 1,
    previous_manifest_sha256: Optional[str] = None,
    rotation_label: str = "v1",
) -> Dict[str, Any]:
    def account(
        code: str,
        *,
        demand_owner: bool,
        org_admin: bool = False,
        duties: Tuple[str, ...],
    ) -> Dict[str, Any]:
        return {
            "account_code": code,
            "activation_event_id": _id("%s-activation-%s" % (code, rotation_label)),
            "contact_point": {
                "id": _id("%s-contact-%s" % (code, rotation_label)),
                "recipient_binding_digest_key_id": "sandbox-recipient-%s" % rotation_label,
                "recipient_binding_digest_sha256": hashlib.sha256(
                    ("synthetic-recipient:%s:%s" % (code, rotation_label)).encode()
                ).hexdigest(),
            },
            "creator_grant": {
                "grant_id": _id("%s-creator-grant" % code),
                "invitation_id": _id("%s-creator-invitation" % code),
            },
            "demand_owner_grant": (
                {
                    "grant_id": _id("%s-demand-owner-grant" % code),
                    "invitation_id": _id("%s-demand-owner-invitation" % code),
                    "membership_id": _id("%s-membership" % code),
                    "organization_id": _id("%s-organization" % code),
                }
                if demand_owner
                else None
            ),
            "organization_grant": (
                {
                    "grant_id": _id("%s-org-admin-grant" % code),
                    "invitation_id": _id("%s-org-admin-invitation" % code),
                    "membership_id": _id("%s-org-admin-membership" % code),
                    "organization_id": _id("demand_owner_01-organization"),
                    "role_code": "ORG_ADMIN",
                }
                if org_admin
                else None
            ),
            "external_identity": {
                "id": _id("%s-identity-%s" % (code, rotation_label)),
                "subject_digest_key_id": "oidc-subject-%s" % rotation_label,
                "subject_digest_sha256": hashlib.sha256(
                    ("synthetic-subject:%s:%s" % (code, rotation_label)).encode()
                ).hexdigest(),
            },
            "platform_duty_grants": [
                {
                    "duty_code": duty,
                    "grant_id": _id("%s-duty-%s" % (code, duty.lower())),
                }
                for duty in duties
            ],
            "revocation_event_id": _id("%s-revocation-%s" % (code, rotation_label)),
            "user_id": _id("%s-user" % code),
        }

    return {
        "accounts": [
            account("access_admin_01", demand_owner=False, duties=("ACCESS_ADMIN",)),
            account(
                "appeal_reviewer_01",
                demand_owner=False,
                duties=("APPEAL_REVIEWER",),
            ),
            account("creator_01", demand_owner=False, duties=()),
            account("demand_owner_01", demand_owner=True, duties=()),
            account(
                "finance_operator_01",
                demand_owner=False,
                duties=("FINANCE_OPERATOR",),
            ),
            account(
                "finance_operator_02",
                demand_owner=False,
                duties=("FINANCE_OPERATOR",),
            ),
            account(
                "operations_reviewer_01",
                demand_owner=False,
                duties=("OPERATIONS_REVIEWER",),
            ),
            account(
                "org_admin_01",
                demand_owner=False,
                org_admin=True,
                duties=(),
            ),
            account(
                "trust_officer_01",
                demand_owner=False,
                duties=("TRUST_OFFICER",),
            ),
            account(
                "trust_officer_02",
                demand_owner=False,
                duties=("TRUST_OFFICER",),
            ),
        ],
        "bootstrap_id": _id("bootstrap"),
        "environment_id": "internal-sandbox",
        "issuer": "https://id.example.test",
        "policy": {
            "creator_bundle_id": _id("creator-policy-bundle"),
            "demand_owner_bundle_id": _id("demand-owner-policy-bundle"),
            "document_id": _id("sandbox-policy-document"),
            "org_admin_bundle_id": _id("org-admin-policy-bundle"),
        },
        "previous_manifest_sha256": previous_manifest_sha256,
        "revision": revision,
        "schema_name": "desire-internal-sandbox-identity-bootstrap-v1",
    }


def canonical_manifest(document: Dict[str, Any]) -> Tuple[bytes, str]:
    raw = json.dumps(
        document,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return raw, hashlib.sha256(raw).hexdigest()


__all__ = ("canonical_manifest", "identity_bootstrap_document")
