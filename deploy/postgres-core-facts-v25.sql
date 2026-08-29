BEGIN TRANSACTION READ ONLY;
SET LOCAL statement_timeout = '30s';

SELECT jsonb_build_object(
    'postgres_major', current_setting('server_version_num')::integer / 10000,
    'schema_contracts', jsonb_build_object(
        'iam', jsonb_build_object(
            'current', iam_contract.current_schema_version,
            'head', iam_contract.schema_head_version,
            'sha256', encode(iam_contract.combined_contract_sha256, 'hex')
        ),
        'profile', jsonb_build_object(
            'current', profile_contract.current_schema_version,
            'head', profile_contract.schema_head_version,
            'sha256', encode(profile_contract.migration_manifest_sha256, 'hex')
        ),
        'demand', jsonb_build_object(
            'current', demand_contract.current_schema_version,
            'head', demand_contract.schema_head_version,
            'sha256', encode(demand_contract.migration_manifest_sha256, 'hex')
        ),
        'trust', jsonb_build_object(
            'current', trust_contract.current_schema_version,
            'head', trust_contract.schema_head_version,
            'required_iam_schema_version',
                trust_contract.required_iam_schema_version,
            'required_demand_schema_version',
                trust_contract.required_demand_schema_version,
            'required_iam_contract_sha256',
                encode(trust_contract.required_iam_contract_sha256, 'hex'),
            'required_demand_contract_sha256',
                encode(trust_contract.required_demand_contract_sha256, 'hex'),
            'combined_contract_sha256',
                encode(trust_contract.combined_contract_sha256, 'hex'),
            'sha256', encode(trust_contract.migration_manifest_sha256, 'hex')
        ),
        'taxonomy', jsonb_build_object(
            'current', taxonomy_contract.current_schema_version,
            'head', taxonomy_contract.schema_head_version,
            'sha256', encode(taxonomy_contract.migration_manifest_sha256, 'hex')
        )
    ),
    'demand_receipt_keys', jsonb_build_object(
        'active_idempotency_key_id', receipt_policy.active_idempotency_key_id,
        'active_payload_key_id', receipt_policy.active_payload_key_id,
        'retained_idempotency_key_ids', receipt_policy.retained_idempotency_key_ids,
        'retained_payload_key_ids', receipt_policy.retained_payload_key_ids
    ),
    'trust_receipt_keys', jsonb_build_object(
        'active_idempotency_key_id', trust_receipt_policy.active_idempotency_key_id,
        'active_payload_key_id', trust_receipt_policy.active_payload_key_id,
        'retained_idempotency_key_ids', trust_receipt_policy.retained_idempotency_key_ids,
        'retained_payload_key_ids', trust_receipt_policy.retained_payload_key_ids
    ),
    'appeal_receipt_keys', jsonb_build_object(
        'active_idempotency_key_id', appeal_receipt_policy.active_idempotency_key_id,
        'active_payload_key_id', appeal_receipt_policy.active_payload_key_id,
        'retained_idempotency_key_ids', appeal_receipt_policy.retained_idempotency_key_ids,
        'retained_payload_key_ids', appeal_receipt_policy.retained_payload_key_ids
    ),
    'trust_sealed_text_keys', jsonb_build_object(
        'active_encryption_key_id', sealed_text_policy.active_encryption_key_id,
        'retained_encryption_key_ids', sealed_text_policy.retained_encryption_key_ids
    ),
    'iam_durable_counts', jsonb_build_object(
        'iam_organizations', (SELECT count(*) FROM iam.organizations),
        'iam_external_identities', (
            SELECT count(*) FROM iam.external_identities
        ),
        'iam_contact_points', (SELECT count(*) FROM iam.contact_points),
        'iam_auth_transactions', (
            SELECT count(*) FROM iam.auth_transactions
        ),
        'iam_session_families', (SELECT count(*) FROM iam.session_families),
        'iam_session_security_events', (
            SELECT count(*) FROM iam.session_security_events
        ),
        'iam_membership_role_grants', (
            SELECT count(*) FROM iam.membership_role_grants
        ),
        'iam_platform_duty_grants', (
            SELECT count(*) FROM iam.platform_duty_grants
        ),
        'iam_consent_grants', (SELECT count(*) FROM iam.consent_grants),
        'iam_consent_grant_data_categories', (
            SELECT count(*) FROM iam.consent_grant_data_categories
        ),
        'iam_consent_withdrawals', (
            SELECT count(*) FROM iam.consent_withdrawals
        ),
        'infra_command_receipts', (
            SELECT count(*) FROM infra.command_receipts
        ),
        'infra_iam_sandbox_bootstrap_state', (
            SELECT count(*) FROM infra.iam_sandbox_bootstrap_state
        ),
        'infra_iam_sandbox_bootstrap_accounts', (
            SELECT count(*) FROM infra.iam_sandbox_bootstrap_accounts
        ),
        'infra_iam_sandbox_bootstrap_runs', (
            SELECT count(*) FROM infra.iam_sandbox_bootstrap_runs
        ),
        'infra_iam_sandbox_bootstrap_manifest_bridges', (
            SELECT count(*) FROM infra.iam_sandbox_bootstrap_manifest_bridges
        )
    ),
    'core_counts', jsonb_build_object(
        'iam_users', (SELECT count(*) FROM iam.users),
        'iam_active_users', (
            SELECT count(*) FROM iam.users WHERE status = 'ACTIVE'
        ),
        'iam_suspended_users', (
            SELECT count(*) FROM iam.users WHERE status = 'SUSPENDED'
        ),
        'iam_sessions', (SELECT count(*) FROM iam.sessions),
        'iam_active_sessions', (
            SELECT count(*) FROM iam.sessions WHERE status = 'ACTIVE'
        ),
        'iam_user_role_grants', (SELECT count(*) FROM iam.user_role_grants),
        'iam_policy_acceptances', (SELECT count(*) FROM iam.policy_acceptances),
        'creator_profiles', (SELECT count(*) FROM profile.creator_profiles),
        'active_creator_profiles', (
            SELECT count(*) FROM profile.creator_profiles WHERE status = 'ACTIVE'
        ),
        'profile_versions', (SELECT count(*) FROM profile.profile_versions),
        'demands', (SELECT count(*) FROM demand.demands),
        'submitted_demands', (
            SELECT count(*) FROM demand.demands WHERE status = 'SUBMITTED'
        ),
        'verified_demands', (
            SELECT count(*) FROM demand.demands WHERE status = 'VERIFIED'
        ),
        'demand_versions', (SELECT count(*) FROM demand.demand_versions),
        'demand_reviews', (SELECT count(*) FROM demand.demand_reviews),
        'trust_reports', (SELECT count(*) FROM trust.reports),
        'trust_cases', (SELECT count(*) FROM trust.cases),
        'trust_active_holds', (
            SELECT count(*) FROM trust.safety_holds WHERE status = 'ACTIVE'
        ),
        'trust_outcomes', (SELECT count(*) FROM trust.case_outcome_versions),
        'trust_restricted_text_blobs', (
            SELECT count(*) FROM trust.restricted_text_blobs
        ),
        'trust_appeals', (SELECT count(*) FROM trust.appeals),
        'trust_appeal_application_drafts', (
            SELECT count(*) FROM trust.appeal_application_drafts
        ),
        'trust_appeal_application_versions', (
            SELECT count(*) FROM trust.appeal_application_versions
        ),
        'trust_appeal_review_assignments', (
            SELECT count(*) FROM trust.appeal_review_assignments
        ),
        'trust_appeal_assignment_releases', (
            SELECT count(*) FROM trust.appeal_assignment_releases
        ),
        'trust_appeal_review_drafts', (
            SELECT count(*) FROM trust.appeal_review_drafts
        ),
        'trust_appeal_decisions', (
            SELECT count(*) FROM trust.appeal_decision_versions
        ),
        'trust_appeal_command_receipts', (
            SELECT count(*) FROM trust.appeal_command_receipts
        ),
        'taxonomy_bundles', (SELECT count(*) FROM taxonomy.bundles),
        'taxonomy_current_bundles', (
            SELECT count(*) FROM taxonomy.current_bundles
        ),
        'taxonomy_nodes', (SELECT count(*) FROM taxonomy.nodes),
        'audit_events', (SELECT count(*) FROM audit.audit_events),
        'outbox_events', (SELECT count(*) FROM infra.outbox_events)
    ),
    'continuity_counts', jsonb_build_object(
        'iam_access_invitations', (
            SELECT count(*) FROM iam.access_invitations
        ),
        'iam_memberships', (SELECT count(*) FROM iam.memberships),
        'profile_command_receipts', (
            SELECT count(*) FROM profile.command_receipts
        ),
        'profile_taxonomy_projection_inbox', (
            SELECT count(*) FROM profile.taxonomy_projection_inbox
        ),
        'demand_review_assignments', (
            SELECT count(*) FROM demand.demand_review_assignments
        ),
        'demand_source_inbox', (SELECT count(*) FROM demand.source_inbox),
        'demand_command_receipts', (
            SELECT count(*) FROM demand.command_receipts
        ),
        'demand_review_claim_receipts', (
            SELECT count(*) FROM demand.review_claim_receipts
        ),
        'demand_funding_markers', (
            SELECT count(*) FROM demand.demand_funding_markers
        ),
        'demand_manual_funding_review_cases', (
            SELECT count(*) FROM demand.manual_funding_review_cases
        ),
        'demand_manual_funding_review_assignments', (
            SELECT count(*) FROM demand.manual_funding_review_assignments
        ),
        'demand_manual_funding_assignment_releases', (
            SELECT count(*) FROM demand.manual_funding_assignment_releases
        ),
        'demand_manual_funding_findings', (
            SELECT count(*) FROM demand.manual_funding_findings
        ),
        'demand_manual_funding_confirmations', (
            SELECT count(*) FROM demand.manual_funding_confirmations
        ),
        'demand_manual_funding_receipts', (
            SELECT count(*) FROM demand.manual_funding_receipts
        ),
        'trust_case_assignments', (
            SELECT count(*) FROM trust.case_assignments
        ),
        'trust_case_assignment_releases', (
            SELECT count(*) FROM trust.case_assignment_releases
        ),
        'trust_triage_drafts', (SELECT count(*) FROM trust.triage_drafts),
        'trust_triage_versions', (SELECT count(*) FROM trust.triage_versions),
        'trust_command_receipts', (
            SELECT count(*) FROM trust.command_receipts
        ),
        'taxonomy_consumer_inbox', (
            SELECT count(*) FROM taxonomy.consumer_inbox
        ),
        'infra_consumer_inbox_events', (
            SELECT count(*) FROM infra.consumer_inbox_events
        )
    )
)::text
FROM infra.iam_schema_compatibility AS iam_contract
CROSS JOIN profile.schema_compatibility AS profile_contract
CROSS JOIN demand.schema_compatibility AS demand_contract
CROSS JOIN trust.schema_compatibility AS trust_contract
CROSS JOIN taxonomy.schema_compatibility AS taxonomy_contract
CROSS JOIN demand.receipt_key_policy AS receipt_policy
CROSS JOIN trust.receipt_key_policy AS trust_receipt_policy
CROSS JOIN trust.appeal_receipt_key_policy AS appeal_receipt_policy
CROSS JOIN trust.sealed_text_key_policy AS sealed_text_policy
WHERE receipt_policy.singleton_key
  AND trust_receipt_policy.singleton_key
  AND appeal_receipt_policy.singleton_key
  AND sealed_text_policy.singleton_key;

COMMIT;
