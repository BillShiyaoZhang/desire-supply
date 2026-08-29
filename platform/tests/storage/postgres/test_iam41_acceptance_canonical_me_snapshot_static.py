"""Static fail-closed contract for the IAM41 acceptance Me snapshot."""

from __future__ import annotations

import hashlib
from pathlib import Path
import re


PLATFORM_ROOT = Path(__file__).resolve().parents[3]
MIGRATION_ROOT = (
    PLATFORM_ROOT
    / "src/desire_platform/identity_access/adapters/postgres/migrations"
)
IAM40 = MIGRATION_ROOT / "0040_expand__invitation_enrollment_acceptance.sql"
IAM41 = MIGRATION_ROOT / "0041_expand__acceptance_canonical_me_snapshot.sql"
IAM40_SHA256 = "5bf84831502fb295279666a2df5e660f977995bf8c0e8a86f3a321808909cad7"


def _compact(value: str) -> str:
    return " ".join(value.split())


def _function_body(sql: str) -> str:
    signature = "CREATE FUNCTION iam_api.read_acceptance_me_snapshot_v2()"
    start = sql.index(signature)
    body_start = sql.index("AS $function$", start)
    return sql[body_start : sql.index("$function$;", body_start)]


def test_iam41_is_forward_only_and_preserves_the_reviewed_iam40_bytes() -> None:
    assert IAM41.is_file()
    assert hashlib.sha256(IAM40.read_bytes()).hexdigest() == IAM40_SHA256
    sql = IAM41.read_text(encoding="utf-8")
    assert "0040_expand__" not in sql
    assert not re.search(r"\b(?:ALTER|DROP)\s+TABLE\b", sql, re.IGNORECASE)
    assert "CREATE OR REPLACE" not in sql


def test_snapshot_api_is_one_closed_no_argument_jsonb_program() -> None:
    sql = IAM41.read_text(encoding="utf-8")
    compact = _compact(sql)
    assert (
        "CREATE FUNCTION iam_api.read_acceptance_me_snapshot_v2() "
        "RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER VOLATILE "
        "PARALLEL UNSAFE SET search_path = pg_catalog, iam, infra, pg_temp "
        "SET row_security = on"
    ) in compact
    assert (
        "ALTER FUNCTION iam_api.read_acceptance_me_snapshot_v2() "
        "OWNER TO iam_self_summary_reader;"
    ) in compact
    assert (
        "REVOKE ALL ON FUNCTION iam_api.read_acceptance_me_snapshot_v2() "
        "FROM PUBLIC;"
    ) in compact
    assert (
        "GRANT EXECUTE ON FUNCTION iam_api.read_acceptance_me_snapshot_v2() "
        "TO iam_onboarding;"
    ) in compact
    execute_grantees = re.findall(
        r"GRANT EXECUTE ON FUNCTION "
        r"iam_api\.read_acceptance_me_snapshot_v2\(\) TO ([a-z_]+);",
        compact,
    )
    assert execute_grantees == ["iam_onboarding"]


def test_snapshot_context_binds_the_in_progress_receipt_and_post_write_state() -> None:
    body = _function_body(IAM41.read_text(encoding="utf-8"))
    for required in (
        "session_user IS DISTINCT FROM 'iam_onboarding'",
        "current_user IS DISTINCT FROM 'iam_self_summary_reader'",
        "IS DISTINCT FROM 'AUTH_PROTOCOL'",
        "IS DISTINCT FROM 'ACCEPT'",
        "IS DISTINCT FROM 'AcceptAccessInvitation'",
        "target_user_setting IS DISTINCT FROM actor_setting",
        "receipt.id = exact_command_id",
        "receipt.principal_id = exact_actor_id",
        "receipt.target_id = exact_invitation_id",
        "receipt.status = 'IN_PROGRESS'",
        "receipt.if_match_version = invitation.aggregate_version - 1",
        "invitation.status = 'ACCEPTED'",
        "invitation.accepted_by_user_id = exact_actor_id",
        "invitation.terminal_at = transaction_timestamp()",
        "invitation.updated_at = transaction_timestamp()",
        "invitation.policy_selector_digest = exact_selector_digest",
        "exact_grant.source_invitation_id",
        "= exact_invitation_id",
        "required_membership.required",
        "acceptance.user_id = exact_actor_id",
        "RETURN NULL;",
    ):
        assert required in body
    assert "invitation.issued_policy_bundle_id = exact_bundle_id" not in body
    assert "EXECUTE " not in body
    assert "SET ROLE" not in body
    assert "set_config" not in body


def test_snapshot_owner_has_only_the_columns_needed_by_the_fixed_graph() -> None:
    sql = IAM41.read_text(encoding="utf-8")
    for relation in (
        "iam.user_role_grants",
        "iam.memberships",
        "iam.membership_role_grants",
        "iam.organizations",
        "iam.access_invitations",
        "iam.policy_acceptances",
        "iam.policy_selectors",
        "iam.policy_bundles",
        "iam.policy_bundle_documents",
        "iam.policy_documents",
        "iam.consent_offers",
        "iam.consent_offer_data_categories",
        "infra.command_receipts",
    ):
        assert re.search(
            rf"GRANT SELECT \(.+?\)\s+ON {re.escape(relation)}\s+"
            r"TO iam_self_summary_reader;",
            sql,
            re.DOTALL,
        )
    assert "GRANT SELECT ON iam." not in sql
    assert "GRANT SELECT ON infra." not in sql
    assert "GRANT ALL" not in sql


def test_snapshot_rls_is_actor_scoped_across_the_complete_authority_graph() -> None:
    sql = IAM41.read_text(encoding="utf-8")
    policy_relations = {
        "rls_accept_snapshot_receipt_v2": "infra.command_receipts",
        "rls_accept_snapshot_user_v2": "iam.users",
        "rls_accept_snapshot_user_role_v2": "iam.user_role_grants",
        "rls_accept_snapshot_membership_v2": "iam.memberships",
        "rls_accept_snapshot_membership_role_v2": "iam.membership_role_grants",
        "rls_accept_snapshot_organization_v2": "iam.organizations",
        "rls_accept_snapshot_invitation_v2": "iam.access_invitations",
        "rls_accept_snapshot_acceptance_v2": "iam.policy_acceptances",
        "rls_accept_snapshot_selector_v2": "iam.policy_selectors",
        "rls_accept_snapshot_bundle_v2": "iam.policy_bundles",
        "rls_accept_snapshot_bundle_document_v2": "iam.policy_bundle_documents",
        "rls_accept_snapshot_document_v2": "iam.policy_documents",
        "rls_accept_snapshot_offer_v2": "iam.consent_offers",
        "rls_accept_snapshot_offer_category_v2": (
            "iam.consent_offer_data_categories"
        ),
    }
    for policy, relation in policy_relations.items():
        marker = f"CREATE POLICY {policy}"
        start = sql.index(marker)
        end = sql.index(";", start)
        fragment = sql[start:end]
        assert f"ON {relation}" in fragment
        assert "FOR SELECT TO iam_self_summary_reader" in fragment
        assert "session_user = 'iam_onboarding'" in fragment
        assert "current_user = 'iam_self_summary_reader'" in fragment
        assert "'AUTH_PROTOCOL'" in fragment
        assert "'ACCEPT'" in fragment


def test_snapshot_shape_matches_the_canonical_me_projector_facts() -> None:
    body = _function_body(IAM41.read_text(encoding="utf-8"))
    for top_level_key in (
        "'user'",
        "'user_role_grants'",
        "'memberships'",
        "'source_invitations'",
        "'policies'",
        "'acceptances'",
    ):
        assert top_level_key in body
    for nested_key in (
        "'role_grant_id'",
        "'source_invitation_id'",
        "'policy_selector_digest'",
        "'organization_type'",
        "'recipient_contact_id'",
        "'issued_policy_bundle_id'",
        "'canonicalization_version'",
        "'current_bundle_id'",
        "'policy_bundle_id'",
        "'documents'",
        "'offers'",
        "'data_categories'",
        "'supporting_document_sha256'",
        "'canonical_offer_sha256'",
    ):
        assert nested_key in body
    assert body.count("jsonb_agg(payload ORDER BY payload::text)") == 5
    assert "COALESCE((" in body
    assert "'[]'::jsonb" in body
