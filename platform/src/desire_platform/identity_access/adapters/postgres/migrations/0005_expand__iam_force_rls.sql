ALTER TABLE iam.policy_selectors ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.policy_selectors FORCE ROW LEVEL SECURITY;
ALTER TABLE iam.policy_documents ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.policy_documents FORCE ROW LEVEL SECURITY;
ALTER TABLE iam.policy_bundles ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.policy_bundles FORCE ROW LEVEL SECURITY;
ALTER TABLE iam.policy_bundle_documents ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.policy_bundle_documents FORCE ROW LEVEL SECURITY;
ALTER TABLE iam.consent_offers ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.consent_offers FORCE ROW LEVEL SECURITY;
ALTER TABLE iam.consent_offer_data_categories ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.consent_offer_data_categories FORCE ROW LEVEL SECURITY;
ALTER TABLE iam.users ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.users FORCE ROW LEVEL SECURITY;
ALTER TABLE iam.external_identities ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.external_identities FORCE ROW LEVEL SECURITY;
ALTER TABLE iam.contact_points ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.contact_points FORCE ROW LEVEL SECURITY;
ALTER TABLE iam.organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.organizations FORCE ROW LEVEL SECURITY;
ALTER TABLE iam.access_invitations ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.access_invitations FORCE ROW LEVEL SECURITY;
ALTER TABLE iam.memberships ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.memberships FORCE ROW LEVEL SECURITY;
ALTER TABLE iam.user_role_grants ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.user_role_grants FORCE ROW LEVEL SECURITY;
ALTER TABLE iam.membership_role_grants ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.membership_role_grants FORCE ROW LEVEL SECURITY;
ALTER TABLE iam.auth_transactions ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.auth_transactions FORCE ROW LEVEL SECURITY;
ALTER TABLE iam.session_families ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.session_families FORCE ROW LEVEL SECURITY;
ALTER TABLE iam.sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.sessions FORCE ROW LEVEL SECURITY;
ALTER TABLE iam.policy_acceptances ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.policy_acceptances FORCE ROW LEVEL SECURITY;
ALTER TABLE iam.consent_grants ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.consent_grants FORCE ROW LEVEL SECURITY;
ALTER TABLE iam.consent_grant_data_categories ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.consent_grant_data_categories FORCE ROW LEVEL SECURITY;
ALTER TABLE iam.consent_withdrawals ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.consent_withdrawals FORCE ROW LEVEL SECURITY;
ALTER TABLE infra.command_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE infra.command_receipts FORCE ROW LEVEL SECURITY;
ALTER TABLE infra.iam_receipt_key_policy ENABLE ROW LEVEL SECURITY;
ALTER TABLE infra.iam_receipt_key_policy FORCE ROW LEVEL SECURITY;
ALTER TABLE audit.audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit.audit_events FORCE ROW LEVEL SECURITY;
ALTER TABLE infra.outbox_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE infra.outbox_events FORCE ROW LEVEL SECURITY;

REVOKE ALL ON ALL TABLES IN SCHEMA iam FROM
    iam_app,
    iam_session_authenticator,
    iam_onboarding,
    iam_system,
    iam_self_summary_reader,
    iam_outbox_worker,
    iam_key_policy_operator;
REVOKE ALL ON ALL TABLES IN SCHEMA iam_api FROM
    iam_app,
    iam_session_authenticator,
    iam_onboarding,
    iam_system;
REVOKE ALL ON ALL TABLES IN SCHEMA infra FROM
    iam_app,
    iam_session_authenticator,
    iam_onboarding,
    iam_system,
    iam_outbox_worker,
    iam_key_policy_operator;
REVOKE ALL ON ALL TABLES IN SCHEMA audit FROM
    iam_app,
    iam_session_authenticator,
    iam_onboarding,
    iam_system,
    iam_outbox_worker;

GRANT USAGE ON SCHEMA iam TO
    iam_app,
    iam_session_authenticator,
    iam_onboarding,
    iam_system,
    iam_self_summary_reader,
    iam_key_policy_operator;
GRANT USAGE ON SCHEMA iam_api TO
    iam_app,
    iam_session_authenticator,
    iam_onboarding,
    iam_system;
GRANT USAGE ON SCHEMA infra TO
    iam_app,
    iam_session_authenticator,
    iam_onboarding,
    iam_system,
    iam_outbox_worker,
    iam_key_policy_operator;
GRANT USAGE ON SCHEMA audit TO
    iam_app,
    iam_session_authenticator,
    iam_onboarding,
    iam_system;

GRANT EXECUTE ON FUNCTION iam.text_array_is_unique_nonnull(text[]) TO
    iam_app,
    iam_session_authenticator,
    iam_onboarding,
    iam_system,
    iam_key_policy_operator;
GRANT EXECUTE ON FUNCTION iam.canonical_text_array(text[]) TO
    iam_app,
    iam_onboarding,
    iam_system;
GRANT EXECUTE ON FUNCTION iam.assert_policy_selector_consistent(bytea) TO iam_system;
GRANT EXECUTE ON FUNCTION iam.assert_consent_grant_matches_offer(uuid) TO iam_onboarding;

GRANT SELECT (id, status, display_handle, aggregate_version, created_at, updated_at)
    ON iam.users TO iam_app, iam_onboarding, iam_system;
GRANT UPDATE (status, display_handle, aggregate_version, updated_at)
    ON iam.users TO iam_onboarding, iam_system;
GRANT INSERT ON iam.users TO iam_onboarding, iam_system;

GRANT SELECT (
    id,
    user_id,
    issuer,
    subject_digest,
    subject_digest_key_id,
    verified_at,
    status,
    created_at
) ON iam.external_identities TO iam_onboarding;
GRANT INSERT, UPDATE ON iam.external_identities TO iam_onboarding;

GRANT SELECT (
    id,
    user_id,
    contact_type,
    binding_digest,
    binding_digest_key_id,
    verified_at,
    created_at,
    updated_at
) ON iam.contact_points TO iam_onboarding;
GRANT UPDATE (user_id, verified_at, updated_at) ON iam.contact_points TO iam_onboarding;

GRANT SELECT (
    id,
    organization_type,
    public_name,
    jurisdiction,
    status,
    aggregate_version,
    created_at,
    updated_at
) ON iam.organizations TO iam_app, iam_onboarding, iam_system;
GRANT INSERT ON iam.organizations TO iam_system;
GRANT UPDATE (status, aggregate_version, updated_at)
    ON iam.organizations TO iam_onboarding, iam_system;

GRANT SELECT (
    id,
    purpose,
    organization_id,
    target_scope,
    target_role,
    is_initial_admin,
    recipient_contact_id,
    masked_recipient_label,
    policy_selector_digest,
    issued_policy_bundle_id,
    status,
    expires_at,
    accepted_by_user_id,
    aggregate_version,
    created_at,
    updated_at
) ON iam.access_invitations TO iam_onboarding, iam_system;
GRANT SELECT (
    id,
    purpose,
    organization_id,
    target_scope,
    target_role,
    policy_selector_digest,
    status,
    accepted_by_user_id
) ON iam.access_invitations TO iam_app;
GRANT INSERT ON iam.access_invitations TO iam_system;
GRANT UPDATE (
    status,
    accepted_by_user_id,
    terminal_at,
    terminal_reason_code,
    aggregate_version,
    updated_at
) ON iam.access_invitations TO iam_onboarding, iam_system;

GRANT SELECT (
    id,
    organization_id,
    user_id,
    status,
    source_invitation_id,
    aggregate_version,
    created_at,
    updated_at
) ON iam.memberships TO iam_app, iam_onboarding, iam_system;
GRANT INSERT ON iam.memberships TO iam_onboarding, iam_system;
GRANT UPDATE (status, aggregate_version, updated_at)
    ON iam.memberships TO iam_system;

GRANT SELECT (
    id,
    user_id,
    role_code,
    source_invitation_id,
    policy_selector_digest,
    revoked_at,
    aggregate_version
) ON iam.user_role_grants TO iam_app, iam_onboarding, iam_system;
GRANT INSERT ON iam.user_role_grants TO iam_onboarding, iam_system;
GRANT UPDATE (revoked_at, revocation_reason_code, aggregate_version)
    ON iam.user_role_grants TO iam_system;

GRANT SELECT (
    id,
    organization_id,
    membership_id,
    user_id,
    role_code,
    source_invitation_id,
    policy_selector_digest,
    revoked_at,
    aggregate_version
) ON iam.membership_role_grants TO iam_app, iam_onboarding, iam_system;
GRANT INSERT ON iam.membership_role_grants TO iam_onboarding, iam_system;
GRANT UPDATE (revoked_at, revocation_reason_code, aggregate_version)
    ON iam.membership_role_grants TO iam_system;

GRANT SELECT, INSERT, UPDATE ON iam.auth_transactions TO iam_onboarding;

GRANT SELECT (
    id,
    user_id,
    status,
    current_generation,
    aggregate_version,
    created_at,
    updated_at
) ON iam.session_families TO iam_app, iam_session_authenticator, iam_onboarding;
GRANT INSERT ON iam.session_families TO iam_onboarding;
GRANT UPDATE (
    status,
    current_generation,
    revoked_at,
    revocation_reason_code,
    aggregate_version,
    updated_at
) ON iam.session_families TO iam_session_authenticator, iam_onboarding;

GRANT SELECT (
    id,
    user_id,
    family_id,
    generation,
    predecessor_session_id,
    handle_digest,
    handle_digest_key_id,
    csrf_salt,
    csrf_key_id,
    csrf_digest,
    verified_contact_point_id,
    verified_at,
    verified_for_invitation_id,
    auth_transaction_id,
    auth_time,
    acr_code,
    amr_codes,
    created_at,
    last_activity_at,
    idle_expires_at,
    absolute_expires_at,
    updated_at,
    device_label,
    status,
    aggregate_version
) ON iam.sessions TO iam_session_authenticator, iam_onboarding;
GRANT SELECT (
    id,
    user_id,
    family_id,
    generation,
    created_at,
    last_activity_at,
    idle_expires_at,
    absolute_expires_at,
    device_label,
    status,
    aggregate_version
) ON iam.sessions TO iam_app;
GRANT INSERT ON iam.sessions TO iam_onboarding;
GRANT UPDATE (
    last_activity_at,
    idle_expires_at,
    status,
    revoked_at,
    revocation_reason_code,
    aggregate_version,
    updated_at
) ON iam.sessions TO iam_session_authenticator, iam_onboarding;

GRANT SELECT, INSERT ON iam.policy_acceptances TO iam_onboarding;
GRANT SELECT (id, user_id, document_id, content_sha256, bundle_id, accepted_at)
    ON iam.policy_acceptances TO iam_app;
GRANT SELECT, INSERT, UPDATE ON iam.consent_grants TO iam_onboarding;
GRANT SELECT (
    id,
    user_id,
    consent_offer_id,
    consent_offer_version,
    policy_bundle_id,
    purpose,
    scope_type,
    scope_id,
    recipient_label,
    document_id,
    document_content_sha256,
    granted_at,
    expires_at,
    status,
    aggregate_version,
    created_at,
    updated_at
) ON iam.consent_grants TO iam_app;
GRANT SELECT, INSERT ON iam.consent_grant_data_categories TO iam_onboarding;
GRANT SELECT ON iam.consent_grant_data_categories TO iam_app;
GRANT SELECT (
    id,
    consent_grant_id,
    user_id,
    withdrawn_at,
    reason_code,
    created_at
) ON iam.consent_withdrawals TO iam_app;

GRANT SELECT ON iam.policy_selectors TO iam_onboarding, iam_system;
GRANT SELECT (
    selector_digest,
    canonicalization_version,
    access_purpose,
    scope_type,
    target_role,
    jurisdiction,
    locale,
    current_bundle_id,
    aggregate_version
) ON iam.policy_selectors TO iam_app;
GRANT INSERT, UPDATE ON iam.policy_selectors TO iam_system;
GRANT SELECT ON iam.policy_documents TO iam_onboarding, iam_system;
GRANT SELECT (
    id,
    kind,
    locale,
    semantic_version,
    canonical_body,
    content_sha256,
    legal_effect,
    jurisdiction,
    status,
    effective_at
) ON iam.policy_documents TO iam_app;
GRANT INSERT, UPDATE ON iam.policy_documents TO iam_system;
GRANT SELECT ON iam.policy_bundles TO iam_onboarding, iam_system;
GRANT SELECT (
    id,
    selector_digest,
    status,
    effective_at,
    effective_until,
    aggregate_version
) ON iam.policy_bundles TO iam_app;
GRANT INSERT, UPDATE ON iam.policy_bundles TO iam_system;
GRANT SELECT ON iam.policy_bundle_documents TO iam_app, iam_onboarding, iam_system;
GRANT INSERT, UPDATE, DELETE ON iam.policy_bundle_documents TO iam_system;
GRANT SELECT ON iam.consent_offers TO iam_onboarding, iam_system;
GRANT SELECT (
    id,
    bundle_id,
    offer_version,
    purpose,
    scope_type,
    recipient_label,
    document_id,
    document_content_sha256,
    expiry_rule,
    not_after,
    optional,
    canonical_offer_sha256,
    created_at
) ON iam.consent_offers TO iam_app;
GRANT INSERT, UPDATE, DELETE ON iam.consent_offers TO iam_system;
GRANT SELECT ON iam.consent_offer_data_categories TO iam_app, iam_onboarding, iam_system;
GRANT INSERT, UPDATE, DELETE ON iam.consent_offer_data_categories TO iam_system;

GRANT SELECT, INSERT, UPDATE ON infra.command_receipts TO
    iam_app,
    iam_onboarding,
    iam_system;
GRANT SELECT ON infra.iam_receipt_key_policy TO
    iam_app,
    iam_session_authenticator,
    iam_onboarding,
    iam_system,
    iam_key_policy_operator;
GRANT UPDATE ON infra.iam_receipt_key_policy TO iam_key_policy_operator;
GRANT INSERT ON audit.audit_events TO
    iam_app,
    iam_session_authenticator,
    iam_onboarding,
    iam_system;
GRANT INSERT ON infra.outbox_events TO iam_app, iam_onboarding, iam_system;

CREATE POLICY rls_user_self_select ON iam.users
FOR SELECT TO iam_app
USING (
    NULLIF(current_setting('app.scope_kind', true), '') = 'SELF'
    AND id = NULLIF(current_setting('app.actor_user_id', true), '')::uuid
);

CREATE POLICY rls_user_onboarding ON iam.users
FOR ALL TO iam_onboarding
USING (
    NULLIF(current_setting('app.scope_kind', true), '') = 'AUTH_PROTOCOL'
    AND NULLIF(current_setting('app.operation', true), '') IN ('BEGIN', 'COMPLETE', 'ACCEPT')
    AND id = NULLIF(current_setting('app.target_user_id', true), '')::uuid
    AND id = NULLIF(current_setting('app.actor_user_id', true), '')::uuid
    AND (
        NULLIF(current_setting('app.operation', true), '') IN ('BEGIN', 'COMPLETE')
        OR EXISTS (
            SELECT 1
            FROM iam.access_invitations AS invitation
            WHERE invitation.id = NULLIF(
                current_setting('app.target_invitation_id', true),
                ''
            )::uuid
        )
    )
)
WITH CHECK (
    NULLIF(current_setting('app.scope_kind', true), '') = 'AUTH_PROTOCOL'
    AND NULLIF(current_setting('app.operation', true), '') IN ('BEGIN', 'COMPLETE', 'ACCEPT')
    AND id = NULLIF(current_setting('app.target_user_id', true), '')::uuid
    AND (
        NULLIF(current_setting('app.operation', true), '') IN ('BEGIN', 'COMPLETE')
        OR (
            id = NULLIF(current_setting('app.actor_user_id', true), '')::uuid
            AND EXISTS (
                SELECT 1
                FROM iam.access_invitations AS invitation
                WHERE invitation.id = NULLIF(
                    current_setting('app.target_invitation_id', true),
                    ''
                )::uuid
            )
        )
    )
);

CREATE POLICY rls_user_system ON iam.users
FOR ALL TO iam_system
USING (
    NULLIF(current_setting('app.scope_kind', true), '') = 'SYSTEM'
    AND id = NULLIF(current_setting('app.target_user_id', true), '')::uuid
    AND NULLIF(current_setting('app.command_id', true), '') IS NOT NULL
)
WITH CHECK (
    NULLIF(current_setting('app.scope_kind', true), '') = 'SYSTEM'
    AND id = NULLIF(current_setting('app.target_user_id', true), '')::uuid
    AND NULLIF(current_setting('app.command_id', true), '') IS NOT NULL
);

CREATE POLICY rls_external_identity_protocol ON iam.external_identities
FOR ALL TO iam_onboarding
USING (
    NULLIF(current_setting('app.scope_kind', true), '') = 'AUTH_PROTOCOL'
    AND user_id = NULLIF(current_setting('app.target_user_id', true), '')::uuid
)
WITH CHECK (
    NULLIF(current_setting('app.scope_kind', true), '') = 'AUTH_PROTOCOL'
    AND user_id = NULLIF(current_setting('app.target_user_id', true), '')::uuid
);

CREATE POLICY rls_contact_protocol ON iam.contact_points
FOR SELECT TO iam_onboarding
USING (
    NULLIF(current_setting('app.scope_kind', true), '') IN ('INVITATION', 'AUTH_PROTOCOL')
    AND EXISTS (
        SELECT 1
        FROM iam.access_invitations AS invitation
        WHERE invitation.id = NULLIF(current_setting('app.target_invitation_id', true), '')::uuid
          AND invitation.recipient_contact_id = contact_points.id
    )
);

CREATE POLICY rls_contact_accept_update ON iam.contact_points
FOR UPDATE TO iam_onboarding
USING (
    NULLIF(current_setting('app.scope_kind', true), '') = 'AUTH_PROTOCOL'
    AND NULLIF(current_setting('app.operation', true), '') = 'ACCEPT'
    AND EXISTS (
        SELECT 1
        FROM iam.access_invitations AS invitation
        WHERE invitation.id = NULLIF(current_setting('app.target_invitation_id', true), '')::uuid
          AND invitation.recipient_contact_id = contact_points.id
    )
)
WITH CHECK (
    user_id = NULLIF(current_setting('app.actor_user_id', true), '')::uuid
);

CREATE POLICY rls_organization_scope ON iam.organizations
FOR SELECT TO iam_app
USING (
    NULLIF(current_setting('app.scope_kind', true), '') = 'ORGANIZATION'
    AND id = NULLIF(current_setting('app.organization_id', true), '')::uuid
    AND NULLIF(current_setting('app.actor_membership_id', true), '') IS NOT NULL
    AND NULLIF(current_setting('app.actor_membership_version', true), '') IS NOT NULL
    AND NULLIF(current_setting('app.actor_organization_role', true), '') IN ('ORG_ADMIN', 'DEMAND_OWNER')
);

CREATE POLICY rls_organization_me_policy ON iam.organizations
FOR SELECT TO iam_app
USING (
    NULLIF(current_setting('app.scope_kind', true), '') = 'SELF'
    AND NULLIF(current_setting('app.operation', true), '') = 'ME_POLICY_REQUIREMENTS'
    AND EXISTS (
        SELECT 1
        FROM iam.memberships AS membership
        WHERE membership.organization_id = organizations.id
          AND membership.user_id = NULLIF(current_setting('app.actor_user_id', true), '')::uuid
          AND membership.status = 'ACTIVE'
    )
);

CREATE POLICY rls_organization_invitation_preview ON iam.organizations
FOR SELECT TO iam_onboarding
USING (
    NULLIF(current_setting('app.scope_kind', true), '') = 'INVITATION'
    AND NULLIF(current_setting('app.operation', true), '') = 'INSPECT'
    AND EXISTS (
        SELECT 1
        FROM iam.access_invitations AS invitation
        WHERE invitation.id = NULLIF(current_setting('app.target_invitation_id', true), '')::uuid
          AND invitation.organization_id = organizations.id
    )
);

CREATE POLICY rls_organization_onboarding ON iam.organizations
FOR ALL TO iam_onboarding
USING (
    NULLIF(current_setting('app.scope_kind', true), '') = 'AUTH_PROTOCOL'
    AND NULLIF(current_setting('app.operation', true), '') = 'ACCEPT'
    AND id = NULLIF(current_setting('app.organization_id', true), '')::uuid
    AND EXISTS (
        SELECT 1
        FROM iam.access_invitations AS invitation
        WHERE invitation.id = NULLIF(
            current_setting('app.target_invitation_id', true),
            ''
        )::uuid
          AND invitation.organization_id = organizations.id
    )
)
WITH CHECK (
    id = NULLIF(current_setting('app.organization_id', true), '')::uuid
    AND EXISTS (
        SELECT 1
        FROM iam.access_invitations AS invitation
        WHERE invitation.id = NULLIF(
            current_setting('app.target_invitation_id', true),
            ''
        )::uuid
          AND invitation.organization_id = organizations.id
    )
);

CREATE POLICY rls_organization_system ON iam.organizations
FOR ALL TO iam_system
USING (
    NULLIF(current_setting('app.scope_kind', true), '') = 'SYSTEM'
    AND id = NULLIF(current_setting('app.organization_id', true), '')::uuid
)
WITH CHECK (
    NULLIF(current_setting('app.scope_kind', true), '') = 'SYSTEM'
    AND id = NULLIF(current_setting('app.organization_id', true), '')::uuid
);

CREATE POLICY rls_invitation_protocol ON iam.access_invitations
FOR SELECT TO iam_onboarding
USING (
    NULLIF(current_setting('app.scope_kind', true), '') IN ('INVITATION', 'AUTH_PROTOCOL')
    AND NULLIF(current_setting('app.operation', true), '') IN ('INSPECT', 'BEGIN', 'COMPLETE', 'ACCEPT')
    AND id = NULLIF(current_setting('app.target_invitation_id', true), '')::uuid
    AND (
        NULLIF(current_setting('app.operation', true), '') <> 'ACCEPT'
        OR (
            NULLIF(current_setting('app.scope_kind', true), '') = 'AUTH_PROTOCOL'
            AND NULLIF(current_setting('app.command_id', true), '') IS NOT NULL
            AND NULLIF(current_setting('app.target_user_id', true), '')::uuid
                = NULLIF(current_setting('app.actor_user_id', true), '')::uuid
            AND status IN ('ISSUED', 'ACCEPTED')
            AND transaction_timestamp() < expires_at
            AND (
                (
                    organization_id IS NULL
                    AND NULLIF(current_setting('app.organization_id', true), '') IS NULL
                )
                OR organization_id = NULLIF(
                    current_setting('app.organization_id', true),
                    ''
                )::uuid
            )
            AND EXISTS (
                SELECT 1
                FROM iam.sessions AS verified_session
                JOIN iam.session_families AS verified_family
                  ON verified_family.id = verified_session.family_id
                 AND verified_family.user_id = verified_session.user_id
                JOIN iam.auth_transactions AS verified_transaction
                  ON verified_transaction.id = verified_session.auth_transaction_id
                WHERE verified_session.id = NULLIF(
                    current_setting('app.session_id', true),
                    ''
                )::uuid
                  AND verified_session.user_id = NULLIF(
                      current_setting('app.actor_user_id', true),
                      ''
                  )::uuid
                  AND verified_session.family_id = NULLIF(
                      current_setting('app.session_family_id', true),
                      ''
                  )::uuid
                  AND verified_session.status = 'ACTIVE'
                  AND verified_family.status = 'ACTIVE'
                  AND verified_family.current_generation = verified_session.generation
                  AND transaction_timestamp() < verified_session.idle_expires_at
                  AND transaction_timestamp() < verified_session.absolute_expires_at
                  AND verified_session.verified_for_invitation_id = access_invitations.id
                  AND verified_session.verified_contact_point_id = access_invitations.recipient_contact_id
                  AND verified_session.auth_transaction_id = NULLIF(
                      current_setting('app.auth_transaction_id', true),
                      ''
                  )::uuid
                  AND verified_transaction.status = 'SUCCEEDED'
                  AND transaction_timestamp() < verified_transaction.deadline
                  AND verified_transaction.invitation_id = access_invitations.id
                  AND verified_transaction.expected_contact_point_id
                      = access_invitations.recipient_contact_id
            )
        )
    )
);

CREATE POLICY rls_invitation_accept_update ON iam.access_invitations
FOR UPDATE TO iam_onboarding
USING (
    NULLIF(current_setting('app.scope_kind', true), '') = 'AUTH_PROTOCOL'
    AND NULLIF(current_setting('app.operation', true), '') = 'ACCEPT'
    AND id = NULLIF(current_setting('app.target_invitation_id', true), '')::uuid
    AND NULLIF(current_setting('app.command_id', true), '') IS NOT NULL
    AND status = 'ISSUED'
    AND transaction_timestamp() < expires_at
    AND NULLIF(current_setting('app.target_user_id', true), '')::uuid
        = NULLIF(current_setting('app.actor_user_id', true), '')::uuid
    AND (
        (
            organization_id IS NULL
            AND NULLIF(current_setting('app.organization_id', true), '') IS NULL
        )
        OR organization_id = NULLIF(
            current_setting('app.organization_id', true),
            ''
        )::uuid
    )
    AND EXISTS (
        SELECT 1
        FROM iam.sessions AS verified_session
        JOIN iam.session_families AS verified_family
          ON verified_family.id = verified_session.family_id
         AND verified_family.user_id = verified_session.user_id
        JOIN iam.auth_transactions AS verified_transaction
          ON verified_transaction.id = verified_session.auth_transaction_id
        WHERE verified_session.id = NULLIF(
            current_setting('app.session_id', true),
            ''
        )::uuid
          AND verified_session.user_id = NULLIF(
              current_setting('app.actor_user_id', true),
              ''
          )::uuid
          AND verified_session.family_id = NULLIF(
              current_setting('app.session_family_id', true),
              ''
          )::uuid
          AND verified_session.status = 'ACTIVE'
          AND verified_family.status = 'ACTIVE'
          AND verified_family.current_generation = verified_session.generation
          AND transaction_timestamp() < verified_session.idle_expires_at
          AND transaction_timestamp() < verified_session.absolute_expires_at
          AND verified_session.verified_for_invitation_id = access_invitations.id
          AND verified_session.verified_contact_point_id = access_invitations.recipient_contact_id
          AND verified_session.auth_transaction_id = NULLIF(
              current_setting('app.auth_transaction_id', true),
              ''
          )::uuid
          AND verified_transaction.status = 'SUCCEEDED'
          AND transaction_timestamp() < verified_transaction.deadline
          AND verified_transaction.invitation_id = access_invitations.id
          AND verified_transaction.expected_contact_point_id
              = access_invitations.recipient_contact_id
    )
)
WITH CHECK (
    id = NULLIF(current_setting('app.target_invitation_id', true), '')::uuid
    AND accepted_by_user_id = NULLIF(current_setting('app.actor_user_id', true), '')::uuid
    AND status = 'ACCEPTED'
    AND transaction_timestamp() < expires_at
    AND NULLIF(current_setting('app.target_user_id', true), '')::uuid
        = NULLIF(current_setting('app.actor_user_id', true), '')::uuid
    AND (
        (
            organization_id IS NULL
            AND NULLIF(current_setting('app.organization_id', true), '') IS NULL
        )
        OR organization_id = NULLIF(
            current_setting('app.organization_id', true),
            ''
        )::uuid
    )
    AND EXISTS (
        SELECT 1
        FROM iam.sessions AS verified_session
        JOIN iam.session_families AS verified_family
          ON verified_family.id = verified_session.family_id
         AND verified_family.user_id = verified_session.user_id
        JOIN iam.auth_transactions AS verified_transaction
          ON verified_transaction.id = verified_session.auth_transaction_id
        WHERE verified_session.id = NULLIF(
            current_setting('app.session_id', true),
            ''
        )::uuid
          AND verified_session.user_id = NULLIF(
              current_setting('app.actor_user_id', true),
              ''
          )::uuid
          AND verified_session.family_id = NULLIF(
              current_setting('app.session_family_id', true),
              ''
          )::uuid
          AND verified_session.status = 'ACTIVE'
          AND verified_family.status = 'ACTIVE'
          AND verified_family.current_generation = verified_session.generation
          AND transaction_timestamp() < verified_session.idle_expires_at
          AND transaction_timestamp() < verified_session.absolute_expires_at
          AND verified_session.verified_for_invitation_id = access_invitations.id
          AND verified_session.verified_contact_point_id = access_invitations.recipient_contact_id
          AND verified_session.auth_transaction_id = NULLIF(
              current_setting('app.auth_transaction_id', true),
              ''
          )::uuid
          AND verified_transaction.status = 'SUCCEEDED'
          AND transaction_timestamp() < verified_transaction.deadline
          AND verified_transaction.invitation_id = access_invitations.id
          AND verified_transaction.expected_contact_point_id
              = access_invitations.recipient_contact_id
    )
);

CREATE POLICY rls_invitation_self_source ON iam.access_invitations
FOR SELECT TO iam_app
USING (
    NULLIF(current_setting('app.scope_kind', true), '') = 'SELF'
    AND status = 'ACCEPTED'
    AND accepted_by_user_id = NULLIF(current_setting('app.actor_user_id', true), '')::uuid
    AND (
        EXISTS (
            SELECT 1
            FROM iam.user_role_grants AS grant_row
            WHERE grant_row.user_id = accepted_by_user_id
              AND grant_row.source_invitation_id = access_invitations.id
              AND grant_row.revoked_at IS NULL
        )
        OR EXISTS (
            SELECT 1
            FROM iam.membership_role_grants AS grant_row
            WHERE grant_row.user_id = accepted_by_user_id
              AND grant_row.source_invitation_id = access_invitations.id
              AND grant_row.revoked_at IS NULL
        )
    )
);

CREATE POLICY rls_invitation_system ON iam.access_invitations
FOR ALL TO iam_system
USING (
    NULLIF(current_setting('app.scope_kind', true), '') = 'SYSTEM'
    AND id = NULLIF(current_setting('app.target_invitation_id', true), '')::uuid
)
WITH CHECK (
    NULLIF(current_setting('app.scope_kind', true), '') = 'SYSTEM'
    AND id = NULLIF(current_setting('app.target_invitation_id', true), '')::uuid
);

CREATE POLICY rls_membership_self ON iam.memberships
FOR SELECT TO iam_app
USING (
    NULLIF(current_setting('app.scope_kind', true), '') = 'SELF'
    AND user_id = NULLIF(current_setting('app.actor_user_id', true), '')::uuid
);

CREATE POLICY rls_membership_organization ON iam.memberships
FOR SELECT TO iam_app
USING (
    NULLIF(current_setting('app.scope_kind', true), '') = 'ORGANIZATION'
    AND organization_id = NULLIF(current_setting('app.organization_id', true), '')::uuid
    AND NULLIF(current_setting('app.actor_membership_id', true), '') IS NOT NULL
    AND NULLIF(current_setting('app.actor_membership_version', true), '') IS NOT NULL
    AND NULLIF(current_setting('app.actor_organization_role', true), '') IN ('ORG_ADMIN', 'DEMAND_OWNER')
);

CREATE POLICY rls_membership_accept ON iam.memberships
FOR ALL TO iam_onboarding
USING (
    NULLIF(current_setting('app.scope_kind', true), '') = 'AUTH_PROTOCOL'
    AND NULLIF(current_setting('app.operation', true), '') = 'ACCEPT'
    AND user_id = NULLIF(current_setting('app.actor_user_id', true), '')::uuid
    AND source_invitation_id = NULLIF(current_setting('app.target_invitation_id', true), '')::uuid
)
WITH CHECK (
    user_id = NULLIF(current_setting('app.actor_user_id', true), '')::uuid
    AND source_invitation_id = NULLIF(current_setting('app.target_invitation_id', true), '')::uuid
    AND organization_id = NULLIF(current_setting('app.organization_id', true), '')::uuid
);

CREATE POLICY rls_membership_system ON iam.memberships
FOR ALL TO iam_system
USING (
    NULLIF(current_setting('app.scope_kind', true), '') = 'SYSTEM'
    AND organization_id = NULLIF(current_setting('app.organization_id', true), '')::uuid
)
WITH CHECK (
    NULLIF(current_setting('app.scope_kind', true), '') = 'SYSTEM'
    AND organization_id = NULLIF(current_setting('app.organization_id', true), '')::uuid
);

CREATE POLICY rls_user_role_self ON iam.user_role_grants
FOR SELECT TO iam_app
USING (
    NULLIF(current_setting('app.scope_kind', true), '') = 'SELF'
    AND user_id = NULLIF(current_setting('app.actor_user_id', true), '')::uuid
);

CREATE POLICY rls_user_role_accept ON iam.user_role_grants
FOR ALL TO iam_onboarding
USING (
    NULLIF(current_setting('app.scope_kind', true), '') = 'AUTH_PROTOCOL'
    AND NULLIF(current_setting('app.operation', true), '') = 'ACCEPT'
    AND user_id = NULLIF(current_setting('app.actor_user_id', true), '')::uuid
    AND source_invitation_id = NULLIF(current_setting('app.target_invitation_id', true), '')::uuid
)
WITH CHECK (
    user_id = NULLIF(current_setting('app.actor_user_id', true), '')::uuid
    AND source_invitation_id = NULLIF(current_setting('app.target_invitation_id', true), '')::uuid
);

CREATE POLICY rls_user_role_system ON iam.user_role_grants
FOR ALL TO iam_system
USING (
    NULLIF(current_setting('app.scope_kind', true), '') = 'SYSTEM'
    AND user_id = NULLIF(current_setting('app.target_user_id', true), '')::uuid
)
WITH CHECK (
    NULLIF(current_setting('app.scope_kind', true), '') = 'SYSTEM'
    AND user_id = NULLIF(current_setting('app.target_user_id', true), '')::uuid
);

CREATE POLICY rls_membership_role_self ON iam.membership_role_grants
FOR SELECT TO iam_app
USING (
    NULLIF(current_setting('app.scope_kind', true), '') = 'SELF'
    AND user_id = NULLIF(current_setting('app.actor_user_id', true), '')::uuid
);

CREATE POLICY rls_membership_role_organization ON iam.membership_role_grants
FOR SELECT TO iam_app
USING (
    NULLIF(current_setting('app.scope_kind', true), '') = 'ORGANIZATION'
    AND organization_id = NULLIF(current_setting('app.organization_id', true), '')::uuid
    AND NULLIF(current_setting('app.actor_membership_id', true), '') IS NOT NULL
    AND NULLIF(current_setting('app.actor_membership_version', true), '') IS NOT NULL
    AND NULLIF(current_setting('app.actor_organization_role', true), '') IN ('ORG_ADMIN', 'DEMAND_OWNER')
);

CREATE POLICY rls_membership_role_accept ON iam.membership_role_grants
FOR ALL TO iam_onboarding
USING (
    NULLIF(current_setting('app.scope_kind', true), '') = 'AUTH_PROTOCOL'
    AND NULLIF(current_setting('app.operation', true), '') = 'ACCEPT'
    AND user_id = NULLIF(current_setting('app.actor_user_id', true), '')::uuid
    AND source_invitation_id = NULLIF(current_setting('app.target_invitation_id', true), '')::uuid
)
WITH CHECK (
    user_id = NULLIF(current_setting('app.actor_user_id', true), '')::uuid
    AND source_invitation_id = NULLIF(current_setting('app.target_invitation_id', true), '')::uuid
    AND organization_id = NULLIF(current_setting('app.organization_id', true), '')::uuid
);

CREATE POLICY rls_membership_role_system ON iam.membership_role_grants
FOR ALL TO iam_system
USING (
    NULLIF(current_setting('app.scope_kind', true), '') = 'SYSTEM'
    AND organization_id = NULLIF(current_setting('app.organization_id', true), '')::uuid
)
WITH CHECK (
    NULLIF(current_setting('app.scope_kind', true), '') = 'SYSTEM'
    AND organization_id = NULLIF(current_setting('app.organization_id', true), '')::uuid
);

CREATE POLICY rls_auth_transaction_protocol ON iam.auth_transactions
FOR ALL TO iam_onboarding
USING (
    NULLIF(current_setting('app.scope_kind', true), '') = 'AUTH_PROTOCOL'
    AND NULLIF(current_setting('app.operation', true), '') IN ('BEGIN', 'COMPLETE', 'ACCEPT')
    AND id = NULLIF(current_setting('app.auth_transaction_id', true), '')::uuid
    AND (
        invitation_id IS NULL
        OR invitation_id = NULLIF(current_setting('app.target_invitation_id', true), '')::uuid
    )
)
WITH CHECK (
    NULLIF(current_setting('app.scope_kind', true), '') = 'AUTH_PROTOCOL'
    AND id = NULLIF(current_setting('app.auth_transaction_id', true), '')::uuid
    AND (
        invitation_id IS NULL
        OR invitation_id = NULLIF(current_setting('app.target_invitation_id', true), '')::uuid
    )
);

CREATE POLICY rls_session_authenticate_exact ON iam.sessions
FOR SELECT TO iam_session_authenticator
USING (
    NULLIF(current_setting('app.scope_kind', true), '') = 'SESSION_AUTHENTICATE'
    AND NULLIF(current_setting('app.operation', true), '') = 'RESOLVE_COOKIE'
    AND handle_digest_key_id = NULLIF(
        current_setting('app.session_handle_digest_key_id', true),
        ''
    )
    AND handle_digest = decode(
        NULLIF(current_setting('app.session_handle_digest', true), ''),
        'hex'
    )
);

CREATE POLICY rls_session_replay_validator_owner ON iam.sessions
FOR SELECT TO schema_owner
USING (
    NULLIF(current_setting('app.scope_kind', true), '') = 'SESSION_AUTHENTICATE'
    AND NULLIF(current_setting('app.operation', true), '') = 'REVOKE_REPLAYED_FAMILY'
    AND id = NULLIF(current_setting('app.session_id', true), '')::uuid
    AND user_id = NULLIF(current_setting('app.actor_user_id', true), '')::uuid
    AND status = 'REVOKED'
    AND handle_digest_key_id = NULLIF(
        current_setting('app.session_handle_digest_key_id', true),
        ''
    )
    AND handle_digest = decode(
        NULLIF(current_setting('app.session_handle_digest', true), ''),
        'hex'
    )
);

CREATE FUNCTION iam.replayed_session_matches_family(candidate_family_id uuid)
RETURNS boolean
LANGUAGE sql
STABLE
PARALLEL RESTRICTED
SECURITY DEFINER
SET search_path = pg_catalog, iam
AS $function$
    SELECT EXISTS (
        SELECT 1
        FROM iam.sessions AS replayed_session
        WHERE replayed_session.id = NULLIF(
            current_setting('app.session_id', true),
            ''
        )::uuid
          AND replayed_session.user_id = NULLIF(
              current_setting('app.actor_user_id', true),
              ''
          )::uuid
          AND replayed_session.family_id = candidate_family_id
          AND replayed_session.status = 'REVOKED'
          AND replayed_session.handle_digest_key_id = NULLIF(
              current_setting('app.session_handle_digest_key_id', true),
              ''
          )
          AND replayed_session.handle_digest = decode(
              NULLIF(current_setting('app.session_handle_digest', true), ''),
              'hex'
          )
    )
$function$;

REVOKE ALL ON FUNCTION iam.replayed_session_matches_family(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION iam.replayed_session_matches_family(uuid)
    TO iam_session_authenticator;

CREATE POLICY rls_session_authenticate_replay_select ON iam.sessions
FOR SELECT TO iam_session_authenticator
USING (
    NULLIF(current_setting('app.scope_kind', true), '') = 'SESSION_AUTHENTICATE'
    AND NULLIF(current_setting('app.operation', true), '') = 'REVOKE_REPLAYED_FAMILY'
    AND family_id = NULLIF(current_setting('app.session_family_id', true), '')::uuid
    AND user_id = NULLIF(current_setting('app.actor_user_id', true), '')::uuid
    AND iam.replayed_session_matches_family(family_id)
);

CREATE POLICY rls_session_authenticate_replay_update ON iam.sessions
FOR UPDATE TO iam_session_authenticator
USING (
    NULLIF(current_setting('app.scope_kind', true), '') = 'SESSION_AUTHENTICATE'
    AND NULLIF(current_setting('app.operation', true), '') = 'REVOKE_REPLAYED_FAMILY'
    AND family_id = NULLIF(current_setting('app.session_family_id', true), '')::uuid
    AND user_id = NULLIF(current_setting('app.actor_user_id', true), '')::uuid
    AND iam.replayed_session_matches_family(family_id)
)
WITH CHECK (
    family_id = NULLIF(current_setting('app.session_family_id', true), '')::uuid
    AND user_id = NULLIF(current_setting('app.actor_user_id', true), '')::uuid
    AND iam.replayed_session_matches_family(family_id)
    AND status IN ('REVOKED', 'EXPIRED')
);

CREATE POLICY rls_session_self ON iam.sessions
FOR SELECT TO iam_app
USING (
    NULLIF(current_setting('app.scope_kind', true), '') = 'SELF'
    AND user_id = NULLIF(current_setting('app.actor_user_id', true), '')::uuid
);

CREATE POLICY rls_session_onboarding ON iam.sessions
FOR ALL TO iam_onboarding
USING (
    NULLIF(current_setting('app.scope_kind', true), '') = 'AUTH_PROTOCOL'
    AND NULLIF(current_setting('app.operation', true), '') IN ('COMPLETE', 'ACCEPT')
    AND user_id = NULLIF(current_setting('app.actor_user_id', true), '')::uuid
    AND (
        id = NULLIF(current_setting('app.session_id', true), '')::uuid
        OR family_id = NULLIF(current_setting('app.session_family_id', true), '')::uuid
    )
)
WITH CHECK (
    NULLIF(current_setting('app.scope_kind', true), '') = 'AUTH_PROTOCOL'
    AND user_id = NULLIF(current_setting('app.actor_user_id', true), '')::uuid
    AND family_id = NULLIF(current_setting('app.session_family_id', true), '')::uuid
);

CREATE POLICY rls_family_authenticate_exact ON iam.session_families
FOR SELECT TO iam_session_authenticator
USING (
    NULLIF(current_setting('app.scope_kind', true), '') = 'SESSION_AUTHENTICATE'
    AND NULLIF(current_setting('app.operation', true), '') = 'RESOLVE_COOKIE'
    AND EXISTS (
        SELECT 1
        FROM iam.sessions AS exact_session
        WHERE exact_session.family_id = session_families.id
          AND exact_session.handle_digest_key_id = NULLIF(
              current_setting('app.session_handle_digest_key_id', true),
              ''
          )
          AND exact_session.handle_digest = decode(
              NULLIF(current_setting('app.session_handle_digest', true), ''),
              'hex'
          )
    )
);

CREATE POLICY rls_family_replay_select ON iam.session_families
FOR SELECT TO iam_session_authenticator
USING (
    NULLIF(current_setting('app.scope_kind', true), '') = 'SESSION_AUTHENTICATE'
    AND NULLIF(current_setting('app.operation', true), '') = 'REVOKE_REPLAYED_FAMILY'
    AND id = NULLIF(current_setting('app.session_family_id', true), '')::uuid
    AND user_id = NULLIF(current_setting('app.actor_user_id', true), '')::uuid
    AND EXISTS (
        SELECT 1
        FROM iam.sessions AS replayed_session
        WHERE replayed_session.id = NULLIF(current_setting('app.session_id', true), '')::uuid
          AND replayed_session.family_id = session_families.id
          AND replayed_session.status = 'REVOKED'
          AND replayed_session.handle_digest_key_id = NULLIF(
              current_setting('app.session_handle_digest_key_id', true),
              ''
          )
          AND replayed_session.handle_digest = decode(
              NULLIF(current_setting('app.session_handle_digest', true), ''),
              'hex'
          )
    )
);

CREATE POLICY rls_family_replay_update ON iam.session_families
FOR UPDATE TO iam_session_authenticator
USING (
    NULLIF(current_setting('app.scope_kind', true), '') = 'SESSION_AUTHENTICATE'
    AND NULLIF(current_setting('app.operation', true), '') = 'REVOKE_REPLAYED_FAMILY'
    AND id = NULLIF(current_setting('app.session_family_id', true), '')::uuid
    AND user_id = NULLIF(current_setting('app.actor_user_id', true), '')::uuid
    AND EXISTS (
        SELECT 1
        FROM iam.sessions AS replayed_session
        WHERE replayed_session.id = NULLIF(current_setting('app.session_id', true), '')::uuid
          AND replayed_session.family_id = session_families.id
          AND replayed_session.status = 'REVOKED'
          AND replayed_session.handle_digest_key_id = NULLIF(
              current_setting('app.session_handle_digest_key_id', true),
              ''
          )
          AND replayed_session.handle_digest = decode(
              NULLIF(current_setting('app.session_handle_digest', true), ''),
              'hex'
          )
    )
)
WITH CHECK (
    id = NULLIF(current_setting('app.session_family_id', true), '')::uuid
    AND status = 'REVOKED'
);

CREATE POLICY rls_family_self ON iam.session_families
FOR SELECT TO iam_app
USING (
    NULLIF(current_setting('app.scope_kind', true), '') = 'SELF'
    AND user_id = NULLIF(current_setting('app.actor_user_id', true), '')::uuid
);

CREATE POLICY rls_family_onboarding ON iam.session_families
FOR ALL TO iam_onboarding
USING (
    NULLIF(current_setting('app.scope_kind', true), '') = 'AUTH_PROTOCOL'
    AND NULLIF(current_setting('app.operation', true), '') IN ('COMPLETE', 'ACCEPT')
    AND id = NULLIF(current_setting('app.session_family_id', true), '')::uuid
    AND user_id = NULLIF(current_setting('app.actor_user_id', true), '')::uuid
)
WITH CHECK (
    id = NULLIF(current_setting('app.session_family_id', true), '')::uuid
    AND user_id = NULLIF(current_setting('app.actor_user_id', true), '')::uuid
);

CREATE POLICY rls_policy_acceptance_self ON iam.policy_acceptances
FOR SELECT TO iam_app
USING (
    NULLIF(current_setting('app.scope_kind', true), '') = 'SELF'
    AND user_id = NULLIF(current_setting('app.actor_user_id', true), '')::uuid
);

CREATE POLICY rls_policy_acceptance_accept ON iam.policy_acceptances
FOR ALL TO iam_onboarding
USING (
    NULLIF(current_setting('app.scope_kind', true), '') = 'AUTH_PROTOCOL'
    AND NULLIF(current_setting('app.operation', true), '') = 'ACCEPT'
    AND user_id = NULLIF(current_setting('app.actor_user_id', true), '')::uuid
    AND command_id = NULLIF(current_setting('app.command_id', true), '')::uuid
)
WITH CHECK (
    user_id = NULLIF(current_setting('app.actor_user_id', true), '')::uuid
    AND session_id = NULLIF(current_setting('app.session_id', true), '')::uuid
    AND auth_transaction_id = NULLIF(current_setting('app.auth_transaction_id', true), '')::uuid
    AND command_id = NULLIF(current_setting('app.command_id', true), '')::uuid
);

CREATE POLICY rls_consent_grant_self ON iam.consent_grants
FOR SELECT TO iam_app
USING (
    NULLIF(current_setting('app.scope_kind', true), '') = 'SELF'
    AND user_id = NULLIF(current_setting('app.actor_user_id', true), '')::uuid
);

CREATE POLICY rls_consent_grant_accept ON iam.consent_grants
FOR ALL TO iam_onboarding
USING (
    NULLIF(current_setting('app.scope_kind', true), '') = 'AUTH_PROTOCOL'
    AND NULLIF(current_setting('app.operation', true), '') = 'ACCEPT'
    AND user_id = NULLIF(current_setting('app.actor_user_id', true), '')::uuid
)
WITH CHECK (
    user_id = NULLIF(current_setting('app.actor_user_id', true), '')::uuid
    AND session_id = NULLIF(current_setting('app.session_id', true), '')::uuid
    AND auth_transaction_id = NULLIF(current_setting('app.auth_transaction_id', true), '')::uuid
    AND command_id = NULLIF(current_setting('app.command_id', true), '')::uuid
);

CREATE POLICY rls_consent_category_self ON iam.consent_grant_data_categories
FOR SELECT TO iam_app
USING (
    NULLIF(current_setting('app.scope_kind', true), '') = 'SELF'
    AND EXISTS (
        SELECT 1 FROM iam.consent_grants AS grant_row
        WHERE grant_row.id = consent_grant_data_categories.grant_id
          AND grant_row.user_id = NULLIF(current_setting('app.actor_user_id', true), '')::uuid
    )
);

CREATE POLICY rls_consent_category_accept ON iam.consent_grant_data_categories
FOR ALL TO iam_onboarding
USING (
    NULLIF(current_setting('app.scope_kind', true), '') = 'AUTH_PROTOCOL'
    AND NULLIF(current_setting('app.operation', true), '') = 'ACCEPT'
    AND EXISTS (
        SELECT 1 FROM iam.consent_grants AS grant_row
        WHERE grant_row.id = consent_grant_data_categories.grant_id
          AND grant_row.user_id = NULLIF(current_setting('app.actor_user_id', true), '')::uuid
    )
)
WITH CHECK (
    EXISTS (
        SELECT 1 FROM iam.consent_grants AS grant_row
        WHERE grant_row.id = consent_grant_data_categories.grant_id
          AND grant_row.user_id = NULLIF(current_setting('app.actor_user_id', true), '')::uuid
          AND grant_row.command_id = NULLIF(current_setting('app.command_id', true), '')::uuid
    )
);

CREATE POLICY rls_consent_withdrawal_self ON iam.consent_withdrawals
FOR SELECT TO iam_app
USING (
    NULLIF(current_setting('app.scope_kind', true), '') = 'SELF'
    AND user_id = NULLIF(current_setting('app.actor_user_id', true), '')::uuid
);

CREATE POLICY rls_policy_selector_self ON iam.policy_selectors
FOR SELECT TO iam_app
USING (
    NULLIF(current_setting('app.scope_kind', true), '') = 'SELF'
    AND NULLIF(current_setting('app.operation', true), '') = 'ME_POLICY_REQUIREMENTS'
    AND EXISTS (
        SELECT 1
        FROM iam.users AS actor
        WHERE actor.id = NULLIF(current_setting('app.actor_user_id', true), '')::uuid
          AND actor.status = 'ACTIVE'
    )
    AND (
        EXISTS (
            SELECT 1
            FROM iam.user_role_grants AS grant_row
            WHERE grant_row.user_id = NULLIF(current_setting('app.actor_user_id', true), '')::uuid
              AND grant_row.revoked_at IS NULL
              AND grant_row.policy_selector_digest = policy_selectors.selector_digest
        )
        OR EXISTS (
            SELECT 1
            FROM iam.membership_role_grants AS grant_row
            JOIN iam.memberships AS membership
              ON membership.id = grant_row.membership_id
             AND membership.organization_id = grant_row.organization_id
             AND membership.user_id = grant_row.user_id
            JOIN iam.organizations AS organization
              ON organization.id = membership.organization_id
            WHERE grant_row.user_id = NULLIF(current_setting('app.actor_user_id', true), '')::uuid
              AND grant_row.revoked_at IS NULL
              AND membership.status = 'ACTIVE'
              AND organization.status = 'ACTIVE'
              AND grant_row.policy_selector_digest = policy_selectors.selector_digest
        )
    )
);

CREATE POLICY rls_policy_selector_accept ON iam.policy_selectors
FOR SELECT TO iam_onboarding
USING (
    NULLIF(current_setting('app.scope_kind', true), '') IN ('INVITATION', 'AUTH_PROTOCOL')
    AND NULLIF(current_setting('app.operation', true), '') IN ('INSPECT', 'ACCEPT')
    AND selector_digest = decode(
        NULLIF(current_setting('app.policy_selector_digest', true), ''),
        'hex'
    )
);

CREATE POLICY rls_policy_selector_publish ON iam.policy_selectors
FOR ALL TO iam_system
USING (
    NULLIF(current_setting('app.scope_kind', true), '') = 'POLICY_PUBLISH'
    AND selector_digest = decode(
        NULLIF(current_setting('app.policy_selector_digest', true), ''),
        'hex'
    )
    AND NULLIF(current_setting('app.command_id', true), '') IS NOT NULL
)
WITH CHECK (
    NULLIF(current_setting('app.scope_kind', true), '') = 'POLICY_PUBLISH'
    AND selector_digest = decode(
        NULLIF(current_setting('app.policy_selector_digest', true), ''),
        'hex'
    )
);

CREATE POLICY rls_policy_bundle_public ON iam.policy_bundles
FOR SELECT TO iam_app
USING (
    NULLIF(current_setting('app.scope_kind', true), '') = 'PUBLIC_POLICY_READ'
    AND id = NULLIF(current_setting('app.policy_bundle_id', true), '')::uuid
    AND status = 'ACTIVE'
    AND effective_at <= transaction_timestamp()
    AND (effective_until IS NULL OR transaction_timestamp() < effective_until)
);

CREATE POLICY rls_policy_bundle_self ON iam.policy_bundles
FOR SELECT TO iam_app
USING (
    NULLIF(current_setting('app.scope_kind', true), '') = 'SELF'
    AND status = 'ACTIVE'
    AND effective_at <= transaction_timestamp()
    AND effective_until IS NULL
    AND EXISTS (
        SELECT 1 FROM iam.policy_selectors AS selector
        WHERE selector.selector_digest = policy_bundles.selector_digest
          AND selector.current_bundle_id = policy_bundles.id
    )
);

CREATE POLICY rls_policy_bundle_accept ON iam.policy_bundles
FOR SELECT TO iam_onboarding
USING (
    NULLIF(current_setting('app.scope_kind', true), '') IN ('INVITATION', 'AUTH_PROTOCOL')
    AND NULLIF(current_setting('app.operation', true), '') IN ('INSPECT', 'ACCEPT')
    AND id = NULLIF(current_setting('app.policy_bundle_id', true), '')::uuid
    AND selector_digest = decode(
        NULLIF(current_setting('app.policy_selector_digest', true), ''),
        'hex'
    )
    AND status = 'ACTIVE'
    AND effective_at <= transaction_timestamp()
    AND effective_until IS NULL
);

CREATE POLICY rls_policy_bundle_publish ON iam.policy_bundles
FOR ALL TO iam_system
USING (
    NULLIF(current_setting('app.scope_kind', true), '') = 'POLICY_PUBLISH'
    AND selector_digest = decode(
        NULLIF(current_setting('app.policy_selector_digest', true), ''),
        'hex'
    )
    AND (
        id = NULLIF(current_setting('app.policy_bundle_id', true), '')::uuid
        OR EXISTS (
            SELECT 1 FROM iam.policy_selectors AS selector
            WHERE selector.selector_digest = policy_bundles.selector_digest
              AND selector.current_bundle_id = policy_bundles.id
        )
    )
)
WITH CHECK (
    selector_digest = decode(
        NULLIF(current_setting('app.policy_selector_digest', true), ''),
        'hex'
    )
    AND (
        id <> NULLIF(current_setting('app.policy_bundle_id', true), '')::uuid
        OR publication_command_id = NULLIF(current_setting('app.command_id', true), '')::uuid
    )
);

CREATE POLICY rls_policy_document_public ON iam.policy_documents
FOR SELECT TO iam_app
USING (
    NULLIF(current_setting('app.scope_kind', true), '') = 'PUBLIC_POLICY_READ'
    AND status = 'ACTIVE'
    AND EXISTS (
        SELECT 1
        FROM iam.policy_bundle_documents AS membership
        WHERE membership.bundle_id = NULLIF(
            current_setting('app.policy_bundle_id', true),
            ''
        )::uuid
          AND membership.document_id = policy_documents.id
    )
);

CREATE POLICY rls_policy_document_self ON iam.policy_documents
FOR SELECT TO iam_app
USING (
    NULLIF(current_setting('app.scope_kind', true), '') = 'SELF'
    AND status = 'ACTIVE'
    AND EXISTS (
        SELECT 1
        FROM iam.policy_bundle_documents AS membership
        JOIN iam.policy_bundles AS bundle ON bundle.id = membership.bundle_id
        WHERE membership.document_id = policy_documents.id
          AND bundle.status = 'ACTIVE'
    )
);

CREATE POLICY rls_policy_document_accept ON iam.policy_documents
FOR SELECT TO iam_onboarding
USING (
    NULLIF(current_setting('app.scope_kind', true), '') = 'AUTH_PROTOCOL'
    AND NULLIF(current_setting('app.operation', true), '') = 'ACCEPT'
    AND status = 'ACTIVE'
    AND EXISTS (
        SELECT 1
        FROM iam.policy_bundle_documents AS membership
        WHERE membership.bundle_id = NULLIF(
            current_setting('app.policy_bundle_id', true),
            ''
        )::uuid
          AND membership.document_id = policy_documents.id
    )
);

CREATE POLICY rls_policy_document_publish ON iam.policy_documents
FOR ALL TO iam_system
USING (
    NULLIF(current_setting('app.scope_kind', true), '') = 'POLICY_PUBLISH'
    AND (
        publication_command_id = NULLIF(current_setting('app.command_id', true), '')::uuid
        OR EXISTS (
            SELECT 1
            FROM iam.policy_bundle_documents AS membership
            WHERE membership.bundle_id = NULLIF(
                current_setting('app.policy_bundle_id', true),
                ''
            )::uuid
              AND membership.document_id = policy_documents.id
        )
    )
)
WITH CHECK (
    publication_command_id = NULLIF(current_setting('app.command_id', true), '')::uuid
);

CREATE POLICY rls_bundle_document_public ON iam.policy_bundle_documents
FOR SELECT TO iam_app
USING (
    NULLIF(current_setting('app.scope_kind', true), '') = 'PUBLIC_POLICY_READ'
    AND bundle_id = NULLIF(current_setting('app.policy_bundle_id', true), '')::uuid
    AND EXISTS (
        SELECT 1
        FROM iam.policy_bundles AS exact_bundle
        WHERE exact_bundle.id = policy_bundle_documents.bundle_id
          AND exact_bundle.status = 'ACTIVE'
          AND exact_bundle.effective_at <= transaction_timestamp()
          AND (
              exact_bundle.effective_until IS NULL
              OR transaction_timestamp() < exact_bundle.effective_until
          )
    )
);

CREATE POLICY rls_bundle_document_self ON iam.policy_bundle_documents
FOR SELECT TO iam_app
USING (
    NULLIF(current_setting('app.scope_kind', true), '') = 'SELF'
    AND EXISTS (
        SELECT 1 FROM iam.policy_bundles AS bundle
        WHERE bundle.id = policy_bundle_documents.bundle_id
          AND bundle.status = 'ACTIVE'
    )
);

CREATE POLICY rls_bundle_document_accept ON iam.policy_bundle_documents
FOR SELECT TO iam_onboarding
USING (
    NULLIF(current_setting('app.scope_kind', true), '') = 'AUTH_PROTOCOL'
    AND NULLIF(current_setting('app.operation', true), '') = 'ACCEPT'
    AND bundle_id = NULLIF(current_setting('app.policy_bundle_id', true), '')::uuid
);

CREATE POLICY rls_bundle_document_publish ON iam.policy_bundle_documents
FOR ALL TO iam_system
USING (
    NULLIF(current_setting('app.scope_kind', true), '') = 'POLICY_PUBLISH'
    AND (
        bundle_id = NULLIF(current_setting('app.policy_bundle_id', true), '')::uuid
        OR EXISTS (
            SELECT 1
            FROM iam.policy_bundles AS bundle
            JOIN iam.policy_selectors AS selector
              ON selector.selector_digest = bundle.selector_digest
            WHERE bundle.id = policy_bundle_documents.bundle_id
              AND selector.selector_digest = decode(
                  NULLIF(current_setting('app.policy_selector_digest', true), ''),
                  'hex'
              )
              AND selector.current_bundle_id = bundle.id
        )
    )
)
WITH CHECK (
    bundle_id = NULLIF(current_setting('app.policy_bundle_id', true), '')::uuid
);

CREATE POLICY rls_consent_offer_public ON iam.consent_offers
FOR SELECT TO iam_app
USING (
    NULLIF(current_setting('app.scope_kind', true), '') = 'PUBLIC_POLICY_READ'
    AND bundle_id = NULLIF(current_setting('app.policy_bundle_id', true), '')::uuid
    AND EXISTS (
        SELECT 1
        FROM iam.policy_bundles AS exact_bundle
        WHERE exact_bundle.id = consent_offers.bundle_id
          AND exact_bundle.status = 'ACTIVE'
          AND exact_bundle.effective_at <= transaction_timestamp()
          AND (
              exact_bundle.effective_until IS NULL
              OR transaction_timestamp() < exact_bundle.effective_until
          )
    )
);

CREATE POLICY rls_consent_offer_self ON iam.consent_offers
FOR SELECT TO iam_app
USING (
    NULLIF(current_setting('app.scope_kind', true), '') = 'SELF'
    AND EXISTS (
        SELECT 1 FROM iam.policy_bundles AS bundle
        WHERE bundle.id = consent_offers.bundle_id
          AND bundle.status = 'ACTIVE'
    )
);

CREATE POLICY rls_consent_offer_accept ON iam.consent_offers
FOR SELECT TO iam_onboarding
USING (
    NULLIF(current_setting('app.scope_kind', true), '') = 'AUTH_PROTOCOL'
    AND NULLIF(current_setting('app.operation', true), '') = 'ACCEPT'
    AND bundle_id = NULLIF(current_setting('app.policy_bundle_id', true), '')::uuid
);

CREATE POLICY rls_consent_offer_publish ON iam.consent_offers
FOR ALL TO iam_system
USING (
    NULLIF(current_setting('app.scope_kind', true), '') = 'POLICY_PUBLISH'
    AND bundle_id = NULLIF(current_setting('app.policy_bundle_id', true), '')::uuid
)
WITH CHECK (
    bundle_id = NULLIF(current_setting('app.policy_bundle_id', true), '')::uuid
    AND publication_command_id = NULLIF(current_setting('app.command_id', true), '')::uuid
);

CREATE POLICY rls_offer_category_public ON iam.consent_offer_data_categories
FOR SELECT TO iam_app
USING (
    NULLIF(current_setting('app.scope_kind', true), '') = 'PUBLIC_POLICY_READ'
    AND EXISTS (
        SELECT 1 FROM iam.consent_offers AS offer
        WHERE offer.id = consent_offer_data_categories.offer_id
          AND offer.bundle_id = NULLIF(current_setting('app.policy_bundle_id', true), '')::uuid
    )
);

CREATE POLICY rls_offer_category_self ON iam.consent_offer_data_categories
FOR SELECT TO iam_app
USING (
    NULLIF(current_setting('app.scope_kind', true), '') = 'SELF'
    AND EXISTS (
        SELECT 1 FROM iam.consent_offers AS offer
        WHERE offer.id = consent_offer_data_categories.offer_id
    )
);

CREATE POLICY rls_offer_category_accept ON iam.consent_offer_data_categories
FOR SELECT TO iam_onboarding
USING (
    NULLIF(current_setting('app.scope_kind', true), '') = 'AUTH_PROTOCOL'
    AND NULLIF(current_setting('app.operation', true), '') = 'ACCEPT'
    AND EXISTS (
        SELECT 1 FROM iam.consent_offers AS offer
        WHERE offer.id = consent_offer_data_categories.offer_id
          AND offer.bundle_id = NULLIF(current_setting('app.policy_bundle_id', true), '')::uuid
    )
);

CREATE POLICY rls_offer_category_publish ON iam.consent_offer_data_categories
FOR ALL TO iam_system
USING (
    NULLIF(current_setting('app.scope_kind', true), '') = 'POLICY_PUBLISH'
    AND EXISTS (
        SELECT 1 FROM iam.consent_offers AS offer
        WHERE offer.id = consent_offer_data_categories.offer_id
          AND offer.bundle_id = NULLIF(current_setting('app.policy_bundle_id', true), '')::uuid
    )
)
WITH CHECK (
    EXISTS (
        SELECT 1 FROM iam.consent_offers AS offer
        WHERE offer.id = consent_offer_data_categories.offer_id
          AND offer.bundle_id = NULLIF(current_setting('app.policy_bundle_id', true), '')::uuid
    )
);

CREATE POLICY rls_receipt_self ON infra.command_receipts
FOR ALL TO iam_app
USING (
    NULLIF(current_setting('app.scope_kind', true), '') = 'SELF'
    AND principal_kind = 'USER'
    AND principal_id = NULLIF(current_setting('app.actor_user_id', true), '')::uuid
    AND command_name = NULLIF(current_setting('app.command_name', true), '')
    AND command_version = NULLIF(current_setting('app.command_version', true), '')::integer
    AND idempotency_key_digest_key_id = NULLIF(
        current_setting('app.idempotency_key_digest_key_id', true),
        ''
    )
    AND idempotency_key_digest = decode(
        NULLIF(current_setting('app.idempotency_key_digest', true), ''),
        'hex'
    )
)
WITH CHECK (
    principal_kind = 'USER'
    AND principal_id = NULLIF(current_setting('app.actor_user_id', true), '')::uuid
    AND command_name = NULLIF(current_setting('app.command_name', true), '')
    AND command_version = NULLIF(current_setting('app.command_version', true), '')::integer
    AND idempotency_key_digest_key_id = NULLIF(
        current_setting('app.idempotency_key_digest_key_id', true),
        ''
    )
    AND idempotency_key_digest = decode(
        NULLIF(current_setting('app.idempotency_key_digest', true), ''),
        'hex'
    )
);

CREATE POLICY rls_receipt_accept ON infra.command_receipts
FOR ALL TO iam_onboarding
USING (
    NULLIF(current_setting('app.scope_kind', true), '') = 'AUTH_PROTOCOL'
    AND NULLIF(current_setting('app.operation', true), '') = 'ACCEPT'
    AND principal_kind = 'USER'
    AND principal_id = NULLIF(current_setting('app.actor_user_id', true), '')::uuid
    AND command_name = NULLIF(current_setting('app.command_name', true), '')
    AND command_version = NULLIF(current_setting('app.command_version', true), '')::integer
    AND idempotency_key_digest_key_id = NULLIF(
        current_setting('app.idempotency_key_digest_key_id', true),
        ''
    )
    AND idempotency_key_digest = decode(
        NULLIF(current_setting('app.idempotency_key_digest', true), ''),
        'hex'
    )
)
WITH CHECK (
    id = NULLIF(current_setting('app.command_id', true), '')::uuid
    AND principal_kind = 'USER'
    AND principal_id = NULLIF(current_setting('app.actor_user_id', true), '')::uuid
    AND target_id = NULLIF(current_setting('app.target_invitation_id', true), '')::uuid
    AND command_name = NULLIF(current_setting('app.command_name', true), '')
    AND command_version = NULLIF(current_setting('app.command_version', true), '')::integer
);

CREATE POLICY rls_receipt_system ON infra.command_receipts
FOR ALL TO iam_system
USING (
    NULLIF(current_setting('app.scope_kind', true), '') IN ('SYSTEM', 'POLICY_PUBLISH')
    AND principal_kind = 'SYSTEM'
    AND principal_id = NULLIF(current_setting('app.actor_user_id', true), '')::uuid
    AND command_name = NULLIF(current_setting('app.command_name', true), '')
    AND command_version = NULLIF(current_setting('app.command_version', true), '')::integer
    AND idempotency_key_digest_key_id = NULLIF(
        current_setting('app.idempotency_key_digest_key_id', true),
        ''
    )
    AND idempotency_key_digest = decode(
        NULLIF(current_setting('app.idempotency_key_digest', true), ''),
        'hex'
    )
)
WITH CHECK (
    id = NULLIF(current_setting('app.command_id', true), '')::uuid
    AND principal_kind = 'SYSTEM'
    AND principal_id = NULLIF(current_setting('app.actor_user_id', true), '')::uuid
);

CREATE POLICY rls_receipt_schema_owner_maintenance ON infra.command_receipts
FOR ALL TO schema_owner
USING (true)
WITH CHECK (true);

CREATE POLICY rls_receipt_key_policy_runtime ON infra.iam_receipt_key_policy
FOR SELECT TO iam_app, iam_session_authenticator, iam_onboarding, iam_system
USING (singleton_key);

CREATE POLICY rls_receipt_key_policy_operator ON infra.iam_receipt_key_policy
FOR ALL TO iam_key_policy_operator
USING (singleton_key)
WITH CHECK (singleton_key);

CREATE POLICY rls_audit_insert_user ON audit.audit_events
FOR INSERT TO iam_app, iam_session_authenticator, iam_onboarding
WITH CHECK (
    actor_kind = 'USER'
    AND actor_id = NULLIF(current_setting('app.actor_user_id', true), '')::uuid
    AND command_id = NULLIF(current_setting('app.command_id', true), '')::uuid
    AND causation_id = command_id
    AND organization_id IS NOT DISTINCT FROM
        NULLIF(current_setting('app.organization_id', true), '')::uuid
);

CREATE POLICY rls_audit_insert_system ON audit.audit_events
FOR INSERT TO iam_system
WITH CHECK (
    actor_kind = 'SYSTEM'
    AND actor_id = NULLIF(current_setting('app.actor_user_id', true), '')::uuid
    AND command_id = NULLIF(current_setting('app.command_id', true), '')::uuid
    AND causation_id = command_id
    AND organization_id IS NOT DISTINCT FROM
        NULLIF(current_setting('app.organization_id', true), '')::uuid
);

CREATE POLICY rls_outbox_insert_user ON infra.outbox_events
FOR INSERT TO iam_app, iam_onboarding
WITH CHECK (
    actor_kind = 'USER'
    AND actor_id = NULLIF(current_setting('app.actor_user_id', true), '')::uuid
    AND causation_id = NULLIF(current_setting('app.command_id', true), '')::uuid
    AND organization_id IS NOT DISTINCT FROM
        NULLIF(current_setting('app.organization_id', true), '')::uuid
);

CREATE POLICY rls_outbox_insert_system ON infra.outbox_events
FOR INSERT TO iam_system
WITH CHECK (
    actor_kind = 'SYSTEM'
    AND actor_id = NULLIF(current_setting('app.actor_user_id', true), '')::uuid
    AND causation_id = NULLIF(current_setting('app.command_id', true), '')::uuid
    AND organization_id IS NOT DISTINCT FROM
        NULLIF(current_setting('app.organization_id', true), '')::uuid
);

CREATE VIEW iam_api.resolve_cookie_session_v1
WITH (security_barrier = true, security_invoker = true)
AS
SELECT
    session.id AS session_id,
    session.user_id,
    session.family_id,
    session.generation,
    session.status AS session_status,
    session.handle_digest_key_id,
    session.handle_digest,
    session.csrf_salt,
    session.csrf_key_id,
    session.csrf_digest,
    session.auth_time,
    session.acr_code,
    session.amr_codes,
    session.idle_expires_at,
    session.absolute_expires_at,
    session.verified_contact_point_id,
    session.verified_at,
    session.verified_for_invitation_id,
    session.auth_transaction_id,
    session.device_label,
    session.aggregate_version AS session_aggregate_version,
    family.status AS family_status,
    family.current_generation,
    family.aggregate_version AS family_aggregate_version
FROM iam.sessions AS session
JOIN iam.session_families AS family ON family.id = session.family_id;

CREATE VIEW iam_api.invitation_public_preview_v1
WITH (security_barrier = true, security_invoker = true)
AS
SELECT
    invitation.id AS invitation_id,
    invitation.purpose,
    invitation.organization_id,
    organization.public_name AS organization_public_name,
    invitation.target_role,
    invitation.is_initial_admin,
    invitation.masked_recipient_label,
    invitation.status,
    invitation.expires_at,
    selector.current_bundle_id AS required_policy_bundle_id,
    invitation.aggregate_version,
    invitation.created_at
FROM iam.access_invitations AS invitation
LEFT JOIN iam.organizations AS organization
  ON organization.id = invitation.organization_id
JOIN iam.policy_selectors AS selector
  ON selector.selector_digest = invitation.policy_selector_digest
JOIN iam.policy_bundles AS bundle
  ON bundle.id = selector.current_bundle_id
 AND bundle.selector_digest = selector.selector_digest
 AND bundle.status = 'ACTIVE'
 AND bundle.effective_at <= transaction_timestamp()
 AND bundle.effective_until IS NULL;

CREATE VIEW iam_api.public_policy_documents_v1
WITH (security_barrier = true, security_invoker = true)
AS
SELECT
    membership.bundle_id,
    membership.position,
    membership.required,
    document.id AS document_id,
    document.kind,
    document.locale,
    document.semantic_version,
    document.canonical_body,
    document.content_sha256,
    document.legal_effect,
    document.jurisdiction,
    document.effective_at
FROM iam.policy_bundle_documents AS membership
JOIN iam.policy_documents AS document ON document.id = membership.document_id
WHERE document.status = 'ACTIVE';

CREATE VIEW iam_api.public_consent_offers_v1
WITH (security_barrier = true, security_invoker = true)
AS
SELECT
    offer.bundle_id,
    offer.id AS consent_offer_id,
    offer.offer_version,
    offer.purpose,
    offer.scope_type,
    offer.recipient_label,
    offer.document_id,
    offer.document_content_sha256,
    offer.expiry_rule,
    offer.not_after,
    offer.canonical_offer_sha256,
    offer.optional
FROM iam.consent_offers AS offer;

CREATE VIEW iam_api.acceptance_me_snapshot
WITH (security_barrier = true, security_invoker = true)
AS
SELECT
    invitation.id AS invitation_id,
    invitation.purpose,
    invitation.organization_id,
    invitation.target_role,
    invitation.is_initial_admin,
    invitation.masked_recipient_label,
    invitation.status AS invitation_status,
    invitation.expires_at AS invitation_expires_at,
    invitation.aggregate_version AS invitation_aggregate_version,
    invitation.created_at AS invitation_created_at,
    selector.current_bundle_id AS required_policy_bundle_id,
    actor.id AS user_id,
    actor.status AS user_status,
    actor.display_handle,
    actor.aggregate_version AS user_aggregate_version
FROM iam.access_invitations AS invitation
JOIN iam.users AS actor
  ON actor.id = invitation.accepted_by_user_id
JOIN iam.policy_selectors AS selector
  ON selector.selector_digest = invitation.policy_selector_digest
JOIN iam.policy_bundles AS bundle
  ON bundle.id = selector.current_bundle_id
 AND bundle.status = 'ACTIVE'
 AND bundle.effective_at <= transaction_timestamp()
 AND bundle.effective_until IS NULL
WHERE NULLIF(current_setting('app.scope_kind', true), '') = 'AUTH_PROTOCOL'
  AND NULLIF(current_setting('app.operation', true), '') = 'ACCEPT'
  AND invitation.id = NULLIF(current_setting('app.target_invitation_id', true), '')::uuid
  AND actor.id = NULLIF(current_setting('app.actor_user_id', true), '')::uuid;

REVOKE ALL ON ALL TABLES IN SCHEMA iam_api FROM PUBLIC;
GRANT SELECT ON iam_api.resolve_cookie_session_v1 TO iam_session_authenticator;
GRANT SELECT ON iam_api.invitation_public_preview_v1 TO iam_onboarding;
GRANT SELECT ON iam_api.public_policy_documents_v1 TO iam_app;
GRANT SELECT ON iam_api.public_consent_offers_v1 TO iam_app;
GRANT SELECT ON iam_api.acceptance_me_snapshot TO iam_onboarding;
