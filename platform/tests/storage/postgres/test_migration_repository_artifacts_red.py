"""Pre-implementation REDs for the actual checked-in IAM migration artifacts."""

from __future__ import annotations

from pathlib import Path
import re
import unittest

from desire_platform.identity_access.adapters.postgres.migrations import (
    IAM_MIGRATION_LAYOUT,
    IAM_REVIEWED_MANIFEST_SHA256,
    MigrationCatalog,
    MigrationCatalogError,
)


PLATFORM_ROOT = Path(__file__).resolve().parents[3]
MIGRATION_ROOT = (
    PLATFORM_ROOT
    / "src/desire_platform/identity_access/adapters/postgres/migrations"
)

REQUIRED_SQL_MARKERS = {
    0: (b"create schema", b"infra.schema_migrations"),
    1: (b"iam.policy_selectors", b"iam.policy_bundles"),
    2: (
        b"iam.access_invitations",
        b"iam.user_role_grants",
        b"iam.membership_role_grants",
    ),
    3: (b"iam.session_families", b"iam.sessions", b"iam.consent_grants"),
    4: (
        b"infra.command_receipts",
        b"audit.audit_events",
        b"infra.outbox_events",
    ),
    5: (
        b"enable row level security",
        b"force row level security",
        b"session_authenticate",
    ),
    6: (b"iam_api.read_me_self_summary",),
    7: (b"infra.iam_schema_contracts", b"infra.iam_schema_compatibility"),
    8: (b"infra.consumer_inbox_events", b"rls_outbox_worker_update"),
    9: (b"iam.lock_accept_policy_graph_v1", b"security definer"),
    10: (b"iam.enforce_consent_grant_matches_offer", b"tg_table_name"),
    11: (b"rls_policy_acceptance_accept_reuse", b"membership.required"),
    12: (b"iam_api.read_session_bootstrap_v1", b"rls_read_organization_invitation"),
    13: (b"rls_consent_grant_accept_expire", b"transaction_timestamp()"),
    14: (
        b"iam.lock_policy_consent_self_v1",
        b"rls_policy_consent_grant_insert",
        b"response_http_status",
        b"response_schema_name",
        b"current_user_entity_tag",
    ),
    15: (
        b"iam_api.lock_creator_profile_self_v1",
        b"iam_api.is_creator_match_eligible_v1",
        b"rls_profile_audit_insert_user",
        b"rls_profile_outbox_insert_user",
    ),
    16: (
        b"iam_api.lock_demand_owner_authority_v1",
        b"iam_api.lock_demand_reviewer_session_v1",
        b"rls_demand_owner_role_grant_definer",
        b"rls_demand_reviewer_session_definer",
    ),
    17: (
        b"iam.platform_duty_grants",
        b"ux_platform_duty_grant_active",
        b"rls_platform_duty_self_select",
        b"rls_platform_duty_system",
    ),
    18: (
        b"iam_api.lock_platform_user_admin_v1",
        b"platform_user_admin",
        b"rls_platform_admin_user_update",
        b"rls_platform_admin_session_update",
    ),
    19: (
        b"iam_api.resolve_editor_principal_v1",
        b"iam_api.verify_editor_principal_marker_v1",
        b"rls_editor_principal_user_definer",
        b"rls_editor_principal_platform_duty_definer",
    ),
    20: (
        b"iam_api.read_oidc_callback_v2",
        b"iam_api.lock_oidc_identity_v2",
        b"rls_oidc_callback_transaction_definer",
        b"protocol_version = 2",
    ),
    21: (
        b"iam_api.resolve_profile_self_authority_marker_v1",
        b"iam_api.resolve_demand_owner_authority_marker_v1",
        b"iam_api.resolve_demand_reviewer_authority_marker_v1",
        b"rls_authority_marker_reviewer_duty_definer",
    ),
    22: (
        b"profile_migration_runner",
        b"infra.iam_schema_compatibility",
        b"grant usage on schema infra",
    ),
    23: (
        b"iam_sandbox_bootstrap",
        b"iam_api.manage_internal_sandbox_identity_bootstrap_v1",
        b"infra.iam_sandbox_bootstrap_state",
        b"rls_sandbox_bootstrap_users",
    ),
    24: (
        b"iam_api.resolve_cookie_session_v2",
        b"iam.session_security_events",
        b"iam_api.revoke_replayed_session_family_v1",
        b"revoke_replayed_family",
    ),
    25: (
        b"iam_api.authorize_demand_review_queue_v1",
        b"iam_api.lock_demand_review_claim_authority_v1",
        b"iam_api.resolve_demand_reviewer_authority_marker_v2",
        b"iam_api.lock_demand_reviewer_authority_v2",
    ),
    26: (
        b"iam_api.manage_internal_sandbox_identity_bootstrap_v2",
        b"iam.internal_sandbox_independent_role_graph_v2",
        b"bootstrap_role_isolation",
        b"revoke execute on function",
    ),
    27: (
        b"iam_api.read_internal_sandbox_account_workbench_v1",
        b"internal_sandbox_account_admin_read",
        b"rls_sandbox_account_workbench_users",
        b"rls_sandbox_account_workbench_sessions",
    ),
    28: (
        b"create or replace function iam.lock_policy_consent_principal_v1",
        b"locked_auth.created_at > locked_auth.succeeded_at",
        b"locked_auth.succeeded_at > locked_auth.deadline",
        b"locked_auth.succeeded_at > locked_session.created_at",
        b"locked_session.auth_time > locked_auth.succeeded_at",
        b"policy consent principal execute assertion failed",
    ),
    29: (
        b"create or replace function iam.lock_policy_consent_self_v1",
        b"source_document.legal_effect in",
        b"notice_acknowledgement",
        b"contract_acceptance",
        b"policy consent self execute assertion failed",
    ),
    30: (
        b"iam_api.lock_internal_sandbox_platform_duty_admin_v1",
        b"internal_sandbox_platform_duty_admin",
        b"rls_sandbox_duty_admin_receipt",
        b"trg_sandbox_platform_duty_grant_transition",
        b"iam_api.read_internal_sandbox_account_workbench_v2",
    ),
    31: (
        b"iam_api.manage_internal_sandbox_identity_bootstrap_v3",
        b"iam.internal_sandbox_independent_role_graph_v3",
        b"iam_api.authorize_finance_funding_queue_v1",
        b"iam_api.lock_finance_funding_authority_v1",
        b"finance_operator_01",
        b"finance_operator_02",
    ),
    32: (
        b"iam_api.validate_internal_sandbox_platform_user_admin_target_v2",
        b"iam_api.lock_internal_sandbox_platform_user_admin_v2",
        b"internal_sandbox_platform_user_admin_authorized_v2",
    ),
    33: (
        b"iam_api.manage_internal_sandbox_identity_bootstrap_v4",
        b"iam.internal_sandbox_independent_role_graph_v4",
        b"org_admin_01",
        b"resolve_demand_owner_authority_marker_v1",
    ),
    34: (
        b"iam_api.execute_organization_admin_v1",
        b"iam_api.resolve_organization_admin_resume_scope_v1",
        b"iam_api.resolve_oidc_generic_step_up_session_v1",
        b"iam_api.finalize_oidc_generic_step_up_v1",
        b"iam_api.finalize_oidc_invitation_step_up_v1",
        b"rls_oidc_exact_invitation_lock_definer_v3",
        b"iam_api.resolve_accept_receipt_principal_v1",
        b"iam_api.resolve_accept_access_invitation_scope_v1",
        b"ck_auth_transaction_purpose_shape",
        b"safety_decision_stale",
    ),
    35: (
        b"iam_api.execute_organization_admin_v2",
        b"iam_api.resolve_accept_access_invitation_scope_v2",
        b"trg_access_invitation_issued_timestamp_v1",
        b"accepted.content_sha256 = document.content_sha256",
    ),
    36: (
        b"iam_api.manage_internal_sandbox_identity_bootstrap_v5",
        b"iam_api.resolve_trust_reporter_authority_v1",
        b"iam_api.resolve_trust_officer_authority_v1",
        b"iam_api.resolve_appeal_reviewer_authority_v1",
        b"iam_api.resolve_trust_party_conflict_facts_v1",
        b"iam_api.revoke_current_session_v1",
        b"trust_officer_01",
        b"trust_officer_02",
        b"appeal_reviewer_01",
    ),
    37: (
        b"create or replace function iam.finance_funding_authority_context_v1",
        b"iam_api.lock_finance_funding_authority_v2",
        b"release_funding_review_assignment",
        b"submit_funding_review_finding",
        b"iam-finance-funding-authority-v2",
    ),
    38: (
        b"ck_command_receipt_owned_session_revocation",
        b"iam.owned_session_revocation_context_v1",
        b"iam_api.revoke_owned_session_v1",
        b"rls_owned_session_revocation_session_update_v1",
        b"clear_current_session_cookie",
        b"sessionrevoked",
    ),
    39: (
        b"iam_api.finalize_oidc_invitation_enrollment_v1",
        b"rls_oidc_enrollment_user_insert_definer_v1",
        b"rls_oidc_enrollment_identity_insert_definer_v1",
        b"pending_enrollment",
        b"verified_for_invitation_id",
    ),
    40: (
        b"iam_api.resolve_accept_receipt_principal_v1",
        b"iam_api.resolve_accept_access_invitation_scope_v1",
        b"rls_accept_scope_auth_exact_definer_v2",
        b"pending_enrollment",
        b"enrollment",
    ),
    41: (
        b"iam_api.read_acceptance_me_snapshot_v2",
        b"iam_self_summary_reader",
        b"receipt.status = 'in_progress'",
        b"invitation.terminal_at = transaction_timestamp()",
        b"target_user_setting is distinct from actor_setting",
    ),
    42: (
        b"iam.organization_public_name_is_canonical_v1",
        b"iam_api.execute_organization_admin_v3",
        b"updateorganizationpublicname",
        b"uq_org_admin_raw_idempotency_key_v1",
        b"organizationpublicnamechanged",
        b"iam_api.manage_internal_sandbox_identity_bootstrap_v6",
    ),
    43: (
        b"iam_api.resolve_demand_reviewer_authority_marker_v2",
        b"iam_api.lock_demand_reviewer_authority_v2",
        b"release_review_assignment",
        b"iam-demand-reviewer-duty-v2",
        b"iam43_demand_release_authority_drifted",
    ),
    44: (
        b"create function iam_api.resolve_candidate_selector_opt_in_marker_v1",
        b"rls_candidate_selector_opt_in_session_guard_v1",
        b"opt_in_candidate_selector",
        b"desire.iam.candidate-selector-opt-in-evidence.v1",
        b"ck_iam44_candidate_selector_opt_in_readiness",
    ),
    45: (
        b"create function iam_api.resolve_matching_reviewer_authority_marker_v1",
        b"rls_matching_review_target_organization_definer_v1",
        b"reviewer_duty.duty_code = 'operations_reviewer'",
        b"desire.iam.matching-reviewer-claim-evidence.v1",
        b"ck_iam45_matching_reviewer_readiness",
    ),
    46: (
        b"create function iam_api.resolve_matching_creator_authority_marker_v1",
        b"rls_matching_creator_session_guard_v1",
        b"desire.iam.matching-creator-authority-evidence.v1",
        b"ck_iam46_matching_creator_readiness",
        b"create function iam_api.resolve_profile_match_creator_eligibility_v1",
        b"rls_profile_match_derivation_user_lock_v1",
        b"desire.iam.profile-match-creator-eligibility-evidence.v1",
        b"ck_iam46_profile_match_creator_readiness",
    ),
    47: (
        b"alter policy rls_profile_match_derivation_selector_definer_v1",
        b"alter policy rls_profile_match_derivation_selector_lock_v1",
        b"collate \"c\"",
        b"else null::uuid",
        b"create or replace function iam_api.resolve_profile_match_creator_eligibility_v1",
        b"schema_head_version = 47",
        b"ck_iam47_profile_match_creator_readiness",
    ),
    48: (
        b"create function iam_api.admin_demand_scope_v1",
        b"create function iam_api.read_admin_demand_audit_v1",
        b"principal.workspace_id",
        b"principal.principal_marker_sha256",
        b"principal.organization_id = exact_organization_id",
        b"revoke all on function iam_api.admin_demand_participant_names_v1",
    ),
}


class IamRepositoryMigrationArtifactRedTest(unittest.TestCase):
    def test_actual_root_contains_manifest_and_exact_reviewed_sql_files(self) -> None:
        expected = ["manifest.json"] + [item[3] for item in IAM_MIGRATION_LAYOUT]
        expected_sql = sorted(item[3] for item in IAM_MIGRATION_LAYOUT)
        missing = [name for name in expected if not (MIGRATION_ROOT / name).is_file()]
        symlinked = [name for name in expected if (MIGRATION_ROOT / name).is_symlink()]
        actual_sql = sorted(path.name for path in MIGRATION_ROOT.glob("*.sql"))

        self.assertEqual(
            missing,
            [],
            "semantic RED: actual IAM migration manifest/SQL files are not checked in",
        )
        self.assertEqual(
            symlinked,
            [],
            "semantic RED: reviewed IAM migration artifacts must be regular files",
        )
        self.assertEqual(
            actual_sql,
            expected_sql,
            "semantic RED: actual IAM migration root must match the reviewed layout",
        )

    def test_actual_manifest_digest_matches_a_non_placeholder_review_pin(self) -> None:
        self.assertEqual(
            len(IAM_REVIEWED_MANIFEST_SHA256),
            32,
            "semantic RED: reviewed actual manifest digest is still default-deny",
        )
        self.assertNotEqual(IAM_REVIEWED_MANIFEST_SHA256, b"\x00" * 32)
        try:
            catalog = MigrationCatalog.load(MIGRATION_ROOT)
        except MigrationCatalogError as exc:
            self.fail(
                "semantic RED: actual migration catalog is unavailable: %s" % exc.code
            )
        self.assertEqual(
            catalog.manifest_sha256,
            IAM_REVIEWED_MANIFEST_SHA256,
            "semantic RED: checked-in manifest changed without review-pin update",
        )

    def test_actual_sql_files_contain_reviewed_schema_markers_not_placeholders(self) -> None:
        self.assertEqual(
            set(REQUIRED_SQL_MARKERS),
            {version for version, _phase, _name, _path in IAM_MIGRATION_LAYOUT},
            "every reviewed IAM migration must have substantive SQL markers",
        )
        missing = [
            relative_path
            for _version, _phase, _name, relative_path in IAM_MIGRATION_LAYOUT
            if not (MIGRATION_ROOT / relative_path).is_file()
        ]
        self.assertEqual(
            missing,
            [],
            "semantic RED: substantive SQL cannot be reviewed until files exist",
        )

        placeholder = re.compile(rb"\A\s*SELECT\s+[0-9]+\s*;\s*\Z", re.IGNORECASE)
        forbidden = (b"TODO", b"NOT_IMPLEMENTED", b"BEHAVIOR_NOT_AVAILABLE")
        for version, _phase, _name, relative_path in IAM_MIGRATION_LAYOUT:
            with self.subTest(version=version):
                sql_bytes = (MIGRATION_ROOT / relative_path).read_bytes()
                lowered = sql_bytes.lower()
                self.assertIsNone(
                    placeholder.fullmatch(sql_bytes),
                    "semantic RED: migration is still a SELECT-only placeholder",
                )
                self.assertFalse(
                    any(token.lower() in lowered for token in forbidden),
                    "semantic RED: migration contains a default-deny placeholder token",
                )
                for marker in REQUIRED_SQL_MARKERS[version]:
                    self.assertIn(
                        marker,
                        lowered,
                        "semantic RED: migration lacks reviewed schema marker %r" % marker,
                    )


if __name__ == "__main__":
    unittest.main()
