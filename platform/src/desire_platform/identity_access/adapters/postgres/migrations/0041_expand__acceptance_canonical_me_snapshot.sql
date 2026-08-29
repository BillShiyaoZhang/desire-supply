-- IAM 0041: canonical post-AcceptAccessInvitation authority snapshot.
--
-- The Accept command must persist the exact response body before COMMIT.  Its
-- caller cannot switch to the iam_app read pool without losing the transaction
-- snapshot, and the historical acceptance_me_snapshot view projects only the
-- authority created by the current Invitation.  This fixed program exposes the
-- complete post-write actor graph through the existing non-login summary owner.

GRANT USAGE ON SCHEMA infra, iam_api TO iam_self_summary_reader;

GRANT SELECT (
    id,
    user_id,
    role_code,
    source_invitation_id,
    policy_selector_digest,
    revoked_at,
    aggregate_version
) ON iam.user_role_grants TO iam_self_summary_reader;
GRANT SELECT (
    source_invitation_id,
    created_at
) ON iam.memberships TO iam_self_summary_reader;
GRANT SELECT (
    id,
    source_invitation_id,
    policy_selector_digest,
    aggregate_version
) ON iam.membership_role_grants TO iam_self_summary_reader;
GRANT SELECT (jurisdiction)
    ON iam.organizations TO iam_self_summary_reader;
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
    terminal_at,
    aggregate_version,
    created_at,
    updated_at
) ON iam.access_invitations TO iam_self_summary_reader;
GRANT SELECT (
    user_id,
    document_id,
    content_sha256,
    bundle_id
) ON iam.policy_acceptances TO iam_self_summary_reader;
GRANT SELECT (
    selector_digest,
    canonicalization_version,
    access_purpose,
    scope_type,
    target_role,
    jurisdiction,
    locale,
    current_bundle_id
) ON iam.policy_selectors TO iam_self_summary_reader;
GRANT SELECT (
    id,
    selector_digest,
    status,
    effective_at,
    effective_until,
    aggregate_version
) ON iam.policy_bundles TO iam_self_summary_reader;
GRANT SELECT (bundle_id, document_id, position, required)
    ON iam.policy_bundle_documents TO iam_self_summary_reader;
GRANT SELECT (
    id,
    kind,
    semantic_version,
    locale,
    jurisdiction,
    canonical_body,
    content_sha256,
    legal_effect,
    status
) ON iam.policy_documents TO iam_self_summary_reader;
GRANT SELECT (
    id,
    bundle_id,
    offer_version,
    purpose,
    scope_type,
    scope_derivation,
    recipient_ref,
    recipient_label,
    document_id,
    document_content_sha256,
    expiry_rule,
    expiry_days,
    not_after,
    optional,
    canonical_offer_sha256
) ON iam.consent_offers TO iam_self_summary_reader;
GRANT SELECT (offer_id, category, position)
    ON iam.consent_offer_data_categories TO iam_self_summary_reader;
GRANT SELECT (
    id,
    principal_kind,
    principal_id,
    command_name,
    command_version,
    target_kind,
    target_id,
    http_method,
    canonical_path,
    if_match_version,
    status
) ON infra.command_receipts TO iam_self_summary_reader;

-- Every policy is scoped to the fixed SECURITY DEFINER owner and the original
-- iam_onboarding login.  The function validates the typed GUCs and their exact
-- persisted Receipt/Invitation binding before executing the graph statement.
CREATE POLICY rls_accept_snapshot_receipt_v2 ON infra.command_receipts
FOR SELECT TO iam_self_summary_reader
USING (
    session_user = 'iam_onboarding'
    AND current_user = 'iam_self_summary_reader'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'AUTH_PROTOCOL'
    AND NULLIF(current_setting('app.operation', true), '') = 'ACCEPT'
    AND id::text = NULLIF(current_setting('app.command_id', true), '')
    AND principal_kind = 'USER'
    AND principal_id::text
        = NULLIF(current_setting('app.actor_user_id', true), '')
    AND command_name = 'AcceptAccessInvitation'
    AND command_version = 1
    AND target_kind = 'AccessInvitation'
    AND target_id::text
        = NULLIF(current_setting('app.target_invitation_id', true), '')
    AND status = 'IN_PROGRESS'
);

CREATE POLICY rls_accept_snapshot_user_v2 ON iam.users
FOR SELECT TO iam_self_summary_reader
USING (
    session_user = 'iam_onboarding'
    AND current_user = 'iam_self_summary_reader'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'AUTH_PROTOCOL'
    AND NULLIF(current_setting('app.operation', true), '') = 'ACCEPT'
    AND id::text = NULLIF(current_setting('app.actor_user_id', true), '')
    AND status = 'ACTIVE'
);

CREATE POLICY rls_accept_snapshot_user_role_v2 ON iam.user_role_grants
FOR SELECT TO iam_self_summary_reader
USING (
    session_user = 'iam_onboarding'
    AND current_user = 'iam_self_summary_reader'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'AUTH_PROTOCOL'
    AND NULLIF(current_setting('app.operation', true), '') = 'ACCEPT'
    AND user_id::text = NULLIF(current_setting('app.actor_user_id', true), '')
);

CREATE POLICY rls_accept_snapshot_membership_v2 ON iam.memberships
FOR SELECT TO iam_self_summary_reader
USING (
    session_user = 'iam_onboarding'
    AND current_user = 'iam_self_summary_reader'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'AUTH_PROTOCOL'
    AND NULLIF(current_setting('app.operation', true), '') = 'ACCEPT'
    AND user_id::text = NULLIF(current_setting('app.actor_user_id', true), '')
);

CREATE POLICY rls_accept_snapshot_membership_role_v2
ON iam.membership_role_grants
FOR SELECT TO iam_self_summary_reader
USING (
    session_user = 'iam_onboarding'
    AND current_user = 'iam_self_summary_reader'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'AUTH_PROTOCOL'
    AND NULLIF(current_setting('app.operation', true), '') = 'ACCEPT'
    AND user_id::text = NULLIF(current_setting('app.actor_user_id', true), '')
);

CREATE POLICY rls_accept_snapshot_organization_v2 ON iam.organizations
FOR SELECT TO iam_self_summary_reader
USING (
    session_user = 'iam_onboarding'
    AND current_user = 'iam_self_summary_reader'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'AUTH_PROTOCOL'
    AND NULLIF(current_setting('app.operation', true), '') = 'ACCEPT'
    AND EXISTS (
        SELECT 1
        FROM iam.memberships AS membership
        WHERE membership.organization_id = organizations.id
          AND membership.user_id::text
              = NULLIF(current_setting('app.actor_user_id', true), '')
          AND membership.status = 'ACTIVE'
    )
);

CREATE POLICY rls_accept_snapshot_invitation_v2 ON iam.access_invitations
FOR SELECT TO iam_self_summary_reader
USING (
    session_user = 'iam_onboarding'
    AND current_user = 'iam_self_summary_reader'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'AUTH_PROTOCOL'
    AND NULLIF(current_setting('app.operation', true), '') = 'ACCEPT'
    AND status = 'ACCEPTED'
    AND accepted_by_user_id::text
        = NULLIF(current_setting('app.actor_user_id', true), '')
    AND (
        EXISTS (
            SELECT 1
            FROM iam.user_role_grants AS grant_row
            WHERE grant_row.user_id = access_invitations.accepted_by_user_id
              AND grant_row.source_invitation_id = access_invitations.id
              AND grant_row.revoked_at IS NULL
        )
        OR EXISTS (
            SELECT 1
            FROM iam.membership_role_grants AS grant_row
            WHERE grant_row.user_id = access_invitations.accepted_by_user_id
              AND grant_row.source_invitation_id = access_invitations.id
              AND grant_row.revoked_at IS NULL
        )
    )
);

CREATE POLICY rls_accept_snapshot_acceptance_v2 ON iam.policy_acceptances
FOR SELECT TO iam_self_summary_reader
USING (
    session_user = 'iam_onboarding'
    AND current_user = 'iam_self_summary_reader'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'AUTH_PROTOCOL'
    AND NULLIF(current_setting('app.operation', true), '') = 'ACCEPT'
    AND user_id::text = NULLIF(current_setting('app.actor_user_id', true), '')
);

CREATE POLICY rls_accept_snapshot_selector_v2 ON iam.policy_selectors
FOR SELECT TO iam_self_summary_reader
USING (
    session_user = 'iam_onboarding'
    AND current_user = 'iam_self_summary_reader'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'AUTH_PROTOCOL'
    AND NULLIF(current_setting('app.operation', true), '') = 'ACCEPT'
    AND (
        EXISTS (
            SELECT 1
            FROM iam.user_role_grants AS grant_row
            WHERE grant_row.user_id::text
                = NULLIF(current_setting('app.actor_user_id', true), '')
              AND grant_row.revoked_at IS NULL
              AND grant_row.policy_selector_digest
                  = policy_selectors.selector_digest
        )
        OR EXISTS (
            SELECT 1
            FROM iam.membership_role_grants AS grant_row
            JOIN iam.memberships AS membership
              ON membership.id = grant_row.membership_id
             AND membership.organization_id = grant_row.organization_id
             AND membership.user_id = grant_row.user_id
            WHERE grant_row.user_id::text
                = NULLIF(current_setting('app.actor_user_id', true), '')
              AND grant_row.revoked_at IS NULL
              AND membership.status = 'ACTIVE'
              AND grant_row.policy_selector_digest
                  = policy_selectors.selector_digest
        )
    )
);

CREATE POLICY rls_accept_snapshot_bundle_v2 ON iam.policy_bundles
FOR SELECT TO iam_self_summary_reader
USING (
    session_user = 'iam_onboarding'
    AND current_user = 'iam_self_summary_reader'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'AUTH_PROTOCOL'
    AND NULLIF(current_setting('app.operation', true), '') = 'ACCEPT'
    AND status = 'ACTIVE'
    AND effective_at <= transaction_timestamp()
    AND effective_until IS NULL
    AND EXISTS (
        SELECT 1
        FROM iam.policy_selectors AS selector
        WHERE selector.selector_digest = policy_bundles.selector_digest
          AND selector.current_bundle_id = policy_bundles.id
    )
);

CREATE POLICY rls_accept_snapshot_bundle_document_v2
ON iam.policy_bundle_documents
FOR SELECT TO iam_self_summary_reader
USING (
    session_user = 'iam_onboarding'
    AND current_user = 'iam_self_summary_reader'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'AUTH_PROTOCOL'
    AND NULLIF(current_setting('app.operation', true), '') = 'ACCEPT'
    AND EXISTS (
        SELECT 1
        FROM iam.policy_bundles AS bundle
        WHERE bundle.id = policy_bundle_documents.bundle_id
          AND bundle.status = 'ACTIVE'
          AND bundle.effective_at <= transaction_timestamp()
          AND bundle.effective_until IS NULL
    )
);

CREATE POLICY rls_accept_snapshot_document_v2 ON iam.policy_documents
FOR SELECT TO iam_self_summary_reader
USING (
    session_user = 'iam_onboarding'
    AND current_user = 'iam_self_summary_reader'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'AUTH_PROTOCOL'
    AND NULLIF(current_setting('app.operation', true), '') = 'ACCEPT'
    AND status = 'ACTIVE'
    AND EXISTS (
        SELECT 1
        FROM iam.policy_bundle_documents AS membership
        JOIN iam.policy_bundles AS bundle ON bundle.id = membership.bundle_id
        WHERE membership.document_id = policy_documents.id
          AND bundle.status = 'ACTIVE'
          AND bundle.effective_at <= transaction_timestamp()
          AND bundle.effective_until IS NULL
    )
);

CREATE POLICY rls_accept_snapshot_offer_v2 ON iam.consent_offers
FOR SELECT TO iam_self_summary_reader
USING (
    session_user = 'iam_onboarding'
    AND current_user = 'iam_self_summary_reader'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'AUTH_PROTOCOL'
    AND NULLIF(current_setting('app.operation', true), '') = 'ACCEPT'
    AND EXISTS (
        SELECT 1
        FROM iam.policy_bundles AS bundle
        WHERE bundle.id = consent_offers.bundle_id
          AND bundle.status = 'ACTIVE'
          AND bundle.effective_at <= transaction_timestamp()
          AND bundle.effective_until IS NULL
    )
);

CREATE POLICY rls_accept_snapshot_offer_category_v2
ON iam.consent_offer_data_categories
FOR SELECT TO iam_self_summary_reader
USING (
    session_user = 'iam_onboarding'
    AND current_user = 'iam_self_summary_reader'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'AUTH_PROTOCOL'
    AND NULLIF(current_setting('app.operation', true), '') = 'ACCEPT'
    AND EXISTS (
        SELECT 1
        FROM iam.consent_offers AS offer
        WHERE offer.id = consent_offer_data_categories.offer_id
    )
);

CREATE FUNCTION iam_api.read_acceptance_me_snapshot_v2()
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
PARALLEL UNSAFE
SET search_path = pg_catalog, iam, infra, pg_temp
SET row_security = on
AS $function$
DECLARE
    actor_setting text;
    target_user_setting text;
    invitation_setting text;
    command_setting text;
    organization_setting text;
    selector_setting text;
    bundle_setting text;
    exact_actor_id uuid;
    exact_invitation_id uuid;
    exact_command_id uuid;
    exact_organization_id uuid;
    exact_selector_digest bytea;
    exact_bundle_id uuid;
    context_is_bound boolean := false;
    snapshot jsonb;
BEGIN
    IF session_user IS DISTINCT FROM 'iam_onboarding'
       OR current_user IS DISTINCT FROM 'iam_self_summary_reader'
       OR NULLIF(current_setting('app.scope_kind', true), '')
            IS DISTINCT FROM 'AUTH_PROTOCOL'
       OR NULLIF(current_setting('app.operation', true), '')
            IS DISTINCT FROM 'ACCEPT'
       OR NULLIF(current_setting('app.command_name', true), '')
            IS DISTINCT FROM 'AcceptAccessInvitation'
       OR NULLIF(current_setting('app.command_version', true), '')
            IS DISTINCT FROM '1' THEN
        RETURN NULL;
    END IF;

    actor_setting := NULLIF(current_setting('app.actor_user_id', true), '');
    target_user_setting := NULLIF(
        current_setting('app.target_user_id', true), ''
    );
    invitation_setting := NULLIF(
        current_setting('app.target_invitation_id', true), ''
    );
    command_setting := NULLIF(current_setting('app.command_id', true), '');
    organization_setting := NULLIF(
        current_setting('app.organization_id', true), ''
    );
    selector_setting := NULLIF(
        current_setting('app.policy_selector_digest', true), ''
    );
    bundle_setting := NULLIF(
        current_setting('app.policy_bundle_id', true), ''
    );

    IF actor_setting IS NULL
       OR actor_setting !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
       OR target_user_setting IS DISTINCT FROM actor_setting
       OR invitation_setting IS NULL
       OR invitation_setting !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
       OR command_setting IS NULL
       OR command_setting !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
       OR bundle_setting IS NULL
       OR bundle_setting !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
       OR selector_setting IS NULL
       OR selector_setting !~ '^[0-9a-f]{64}$'
       OR (
            organization_setting IS NOT NULL
            AND organization_setting
                !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
       ) THEN
        RETURN NULL;
    END IF;

    exact_actor_id := actor_setting::uuid;
    exact_invitation_id := invitation_setting::uuid;
    exact_command_id := command_setting::uuid;
    exact_organization_id := organization_setting::uuid;
    exact_selector_digest := decode(selector_setting, 'hex');
    exact_bundle_id := bundle_setting::uuid;

    SELECT EXISTS (
        SELECT 1
        FROM infra.command_receipts AS receipt
        JOIN iam.access_invitations AS invitation
          ON invitation.id = receipt.target_id
        JOIN iam.users AS actor
          ON actor.id = receipt.principal_id
        WHERE receipt.id = exact_command_id
          AND receipt.principal_kind = 'USER'
          AND receipt.principal_id = exact_actor_id
          AND receipt.command_name = 'AcceptAccessInvitation'
          AND receipt.command_version = 1
          AND receipt.target_kind = 'AccessInvitation'
          AND receipt.target_id = exact_invitation_id
          AND receipt.http_method = 'POST'
          AND receipt.canonical_path
              = '/v1/access-invitations/'
                || exact_invitation_id::text
                || '/accept'
          AND receipt.status = 'IN_PROGRESS'
          AND receipt.if_match_version = invitation.aggregate_version - 1
          AND actor.status = 'ACTIVE'
          AND invitation.status = 'ACCEPTED'
          AND invitation.accepted_by_user_id = exact_actor_id
          AND invitation.terminal_at = transaction_timestamp()
          AND invitation.updated_at = transaction_timestamp()
          AND invitation.policy_selector_digest = exact_selector_digest
          AND EXISTS (
                SELECT 1
                FROM iam.policy_selectors AS exact_selector
                JOIN iam.policy_bundles AS exact_bundle
                  ON exact_bundle.id = exact_selector.current_bundle_id
                 AND exact_bundle.selector_digest
                     = exact_selector.selector_digest
                WHERE exact_selector.selector_digest = exact_selector_digest
                  AND exact_selector.current_bundle_id = exact_bundle_id
                  AND exact_bundle.status = 'ACTIVE'
                  AND exact_bundle.effective_at <= transaction_timestamp()
                  AND exact_bundle.effective_until IS NULL
          )
          AND (
                (
                    invitation.organization_id IS NULL
                    AND exact_organization_id IS NULL
                )
                OR invitation.organization_id = exact_organization_id
          )
          AND (
                (
                    invitation.target_scope = 'USER'
                    AND invitation.target_role = 'CREATOR'
                    AND invitation.organization_id IS NULL
                    AND (
                        SELECT count(*)
                        FROM iam.user_role_grants AS exact_grant
                        WHERE exact_grant.user_id = exact_actor_id
                          AND exact_grant.source_invitation_id
                              = exact_invitation_id
                          AND exact_grant.role_code = invitation.target_role
                          AND exact_grant.policy_selector_digest
                              = invitation.policy_selector_digest
                          AND exact_grant.revoked_at IS NULL
                    ) = 1
                    AND NOT EXISTS (
                        SELECT 1
                        FROM iam.membership_role_grants AS wrong_grant
                        WHERE wrong_grant.source_invitation_id
                            = exact_invitation_id
                    )
                )
                OR (
                    invitation.target_scope = 'ORGANIZATION'
                    AND invitation.target_role IN ('ORG_ADMIN', 'DEMAND_OWNER')
                    AND invitation.organization_id IS NOT NULL
                    AND (
                        SELECT count(*)
                        FROM iam.memberships AS exact_membership
                        JOIN iam.membership_role_grants AS exact_grant
                          ON exact_grant.membership_id = exact_membership.id
                         AND exact_grant.organization_id
                             = exact_membership.organization_id
                         AND exact_grant.user_id = exact_membership.user_id
                        WHERE exact_membership.user_id = exact_actor_id
                          AND exact_membership.organization_id
                              = invitation.organization_id
                          AND exact_membership.source_invitation_id
                              = exact_invitation_id
                          AND exact_membership.status = 'ACTIVE'
                          AND exact_grant.source_invitation_id
                              = exact_invitation_id
                          AND exact_grant.role_code = invitation.target_role
                          AND exact_grant.policy_selector_digest
                              = invitation.policy_selector_digest
                          AND exact_grant.revoked_at IS NULL
                    ) = 1
                    AND NOT EXISTS (
                        SELECT 1
                        FROM iam.user_role_grants AS wrong_grant
                        WHERE wrong_grant.source_invitation_id
                            = exact_invitation_id
                    )
                )
          )
          AND NOT EXISTS (
                SELECT 1
                FROM iam.policy_bundle_documents AS required_membership
                WHERE required_membership.bundle_id = exact_bundle_id
                  AND required_membership.required
                  AND NOT EXISTS (
                      SELECT 1
                      FROM iam.policy_documents AS required_document
                      JOIN iam.policy_acceptances AS acceptance
                        ON acceptance.document_id = required_document.id
                       AND acceptance.content_sha256
                           = required_document.content_sha256
                      WHERE required_document.id
                            = required_membership.document_id
                        AND acceptance.user_id = exact_actor_id
                  )
          )
    ) INTO context_is_bound;

    IF context_is_bound IS DISTINCT FROM true THEN
        RETURN NULL;
    END IF;

    WITH relevant_selectors AS (
        SELECT grant_row.policy_selector_digest
        FROM iam.user_role_grants AS grant_row
        WHERE grant_row.user_id = exact_actor_id
          AND grant_row.revoked_at IS NULL
        UNION
        SELECT grant_row.policy_selector_digest
        FROM iam.membership_role_grants AS grant_row
        JOIN iam.memberships AS membership
          ON membership.id = grant_row.membership_id
         AND membership.organization_id = grant_row.organization_id
         AND membership.user_id = grant_row.user_id
        WHERE grant_row.user_id = exact_actor_id
          AND grant_row.revoked_at IS NULL
          AND membership.status = 'ACTIVE'
    ),
    user_role_records AS (
        SELECT jsonb_build_object(
            'role_grant_id', grant_row.id::text,
            'user_id', grant_row.user_id::text,
            'role_code', grant_row.role_code,
            'source_invitation_id', grant_row.source_invitation_id::text,
            'policy_selector_digest',
                encode(grant_row.policy_selector_digest, 'hex'),
            'revoked_at', grant_row.revoked_at,
            'aggregate_version', grant_row.aggregate_version
        ) AS payload
        FROM iam.user_role_grants AS grant_row
        WHERE grant_row.user_id = exact_actor_id
    ),
    membership_records AS (
        SELECT jsonb_build_object(
            'membership', jsonb_build_object(
                'membership_id', membership.id::text,
                'organization_id', membership.organization_id::text,
                'user_id', membership.user_id::text,
                'status', membership.status,
                'source_invitation_id', membership.source_invitation_id::text,
                'aggregate_version', membership.aggregate_version,
                'created_at', membership.created_at
            ),
            'organization', jsonb_build_object(
                'organization_id', organization.id::text,
                'public_name', organization.public_name,
                'organization_type', organization.organization_type,
                'jurisdiction', organization.jurisdiction,
                'status', organization.status,
                'aggregate_version', organization.aggregate_version
            ),
            'role_grants', COALESCE((
                SELECT jsonb_agg(
                    jsonb_build_object(
                        'role_grant_id', role_grant.id::text,
                        'organization_id', role_grant.organization_id::text,
                        'membership_id', role_grant.membership_id::text,
                        'user_id', role_grant.user_id::text,
                        'role_code', role_grant.role_code,
                        'source_invitation_id',
                            role_grant.source_invitation_id::text,
                        'policy_selector_digest',
                            encode(role_grant.policy_selector_digest, 'hex'),
                        'revoked_at', role_grant.revoked_at,
                        'aggregate_version', role_grant.aggregate_version
                    ) ORDER BY role_grant.role_code, role_grant.id
                )
                FROM iam.membership_role_grants AS role_grant
                WHERE role_grant.membership_id = membership.id
                  AND role_grant.organization_id = membership.organization_id
                  AND role_grant.user_id = membership.user_id
            ), '[]'::jsonb)
        ) AS payload
        FROM iam.memberships AS membership
        JOIN iam.organizations AS organization
          ON organization.id = membership.organization_id
        WHERE membership.user_id = exact_actor_id
          AND membership.status = 'ACTIVE'
    ),
    source_invitation_records AS (
        SELECT jsonb_build_object(
            'invitation_id', invitation.id::text,
            'purpose', invitation.purpose,
            'organization_id', invitation.organization_id::text,
            'target_scope', invitation.target_scope,
            'target_role', invitation.target_role,
            'is_initial_admin', invitation.is_initial_admin,
            'recipient_contact_id', invitation.recipient_contact_id::text,
            'masked_recipient_label', invitation.masked_recipient_label,
            'policy_selector_digest',
                encode(invitation.policy_selector_digest, 'hex'),
            'issued_policy_bundle_id', invitation.issued_policy_bundle_id::text,
            'status', invitation.status,
            'expires_at', invitation.expires_at,
            'accepted_by_user_id', invitation.accepted_by_user_id::text,
            'aggregate_version', invitation.aggregate_version,
            'created_at', invitation.created_at
        ) AS payload
        FROM iam.access_invitations AS invitation
        WHERE invitation.accepted_by_user_id = exact_actor_id
          AND invitation.status = 'ACCEPTED'
    ),
    acceptance_records AS (
        SELECT jsonb_build_object(
            'user_id', acceptance.user_id::text,
            'document_id', acceptance.document_id::text,
            'content_sha256', encode(acceptance.content_sha256, 'hex'),
            'policy_bundle_id', acceptance.bundle_id::text
        ) AS payload
        FROM iam.policy_acceptances AS acceptance
        WHERE acceptance.user_id = exact_actor_id
    ),
    policy_records AS (
        SELECT jsonb_build_object(
            'selector', jsonb_build_object(
                'selector_digest', encode(selector.selector_digest, 'hex'),
                'canonicalization_version', selector.canonicalization_version,
                'access_purpose', selector.access_purpose,
                'scope_type', selector.scope_type,
                'target_role', selector.target_role,
                'jurisdiction', selector.jurisdiction,
                'locale', selector.locale,
                'current_bundle_id', selector.current_bundle_id::text
            ),
            'bundle', jsonb_build_object(
                'policy_bundle_id', bundle.id::text,
                'selector_digest', encode(bundle.selector_digest, 'hex'),
                'status', bundle.status,
                'effective_at', bundle.effective_at,
                'effective_until', bundle.effective_until,
                'aggregate_version', bundle.aggregate_version
            ),
            'documents', COALESCE((
                SELECT jsonb_agg(
                    jsonb_build_object(
                        'document_id', document.id::text,
                        'bundle_id', membership.bundle_id::text,
                        'position', membership.position,
                        'required', membership.required,
                        'kind', document.kind,
                        'semantic_version', document.semantic_version,
                        'locale', document.locale,
                        'jurisdiction', document.jurisdiction,
                        'canonical_body', document.canonical_body,
                        'content_sha256', encode(document.content_sha256, 'hex'),
                        'legal_effect', document.legal_effect,
                        'status', document.status
                    ) ORDER BY membership.position
                )
                FROM iam.policy_bundle_documents AS membership
                JOIN iam.policy_documents AS document
                  ON document.id = membership.document_id
                WHERE membership.bundle_id = bundle.id
                  AND document.status = 'ACTIVE'
            ), '[]'::jsonb),
            'offers', COALESCE((
                SELECT jsonb_agg(
                    jsonb_build_object(
                        'canonicalization_version', 'consent-offer-json-v1',
                        'consent_offer_id', offer.id::text,
                        'consent_offer_version', offer.offer_version,
                        'policy_bundle_id', offer.bundle_id::text,
                        'purpose', offer.purpose,
                        'scope_type', offer.scope_type,
                        'scope_derivation', offer.scope_derivation,
                        'data_categories', COALESCE((
                            SELECT jsonb_agg(
                                category.category ORDER BY category.position
                            )
                            FROM iam.consent_offer_data_categories AS category
                            WHERE category.offer_id = offer.id
                        ), '[]'::jsonb),
                        'recipient_ref', offer.recipient_ref,
                        'recipient_label', offer.recipient_label,
                        'supporting_document_id', offer.document_id::text,
                        'supporting_document_sha256',
                            encode(offer.document_content_sha256, 'hex'),
                        'expiry_rule', offer.expiry_rule,
                        'expiry_days', offer.expiry_days,
                        'not_after', offer.not_after,
                        'optional', offer.optional,
                        'canonical_offer_sha256',
                            encode(offer.canonical_offer_sha256, 'hex')
                    ) ORDER BY offer.purpose, offer.id
                )
                FROM iam.consent_offers AS offer
                WHERE offer.bundle_id = bundle.id
            ), '[]'::jsonb)
        ) AS payload
        FROM relevant_selectors AS relevant
        JOIN iam.policy_selectors AS selector
          ON selector.selector_digest = relevant.policy_selector_digest
        JOIN iam.policy_bundles AS bundle
          ON bundle.id = selector.current_bundle_id
         AND bundle.selector_digest = selector.selector_digest
         AND bundle.status = 'ACTIVE'
         AND bundle.effective_at <= transaction_timestamp()
         AND bundle.effective_until IS NULL
    )
    SELECT jsonb_build_object(
        'user', jsonb_build_object(
            'user_id', actor.id::text,
            'status', actor.status,
            'display_handle', actor.display_handle,
            'aggregate_version', actor.aggregate_version
        ),
        'user_role_grants', COALESCE((
            SELECT jsonb_agg(payload ORDER BY payload::text)
            FROM user_role_records
        ), '[]'::jsonb),
        'memberships', COALESCE((
            SELECT jsonb_agg(payload ORDER BY payload::text)
            FROM membership_records
        ), '[]'::jsonb),
        'source_invitations', COALESCE((
            SELECT jsonb_agg(payload ORDER BY payload::text)
            FROM source_invitation_records
        ), '[]'::jsonb),
        'policies', COALESCE((
            SELECT jsonb_agg(payload ORDER BY payload::text)
            FROM policy_records
        ), '[]'::jsonb),
        'acceptances', COALESCE((
            SELECT jsonb_agg(payload ORDER BY payload::text)
            FROM acceptance_records
        ), '[]'::jsonb)
    )
    INTO snapshot
    FROM iam.users AS actor
    WHERE actor.id = exact_actor_id
      AND actor.status = 'ACTIVE';

    RETURN snapshot;
END
$function$;

REVOKE ALL ON FUNCTION iam_api.read_acceptance_me_snapshot_v2() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION iam_api.read_acceptance_me_snapshot_v2()
    TO iam_onboarding;

GRANT CREATE ON SCHEMA iam_api TO iam_self_summary_reader;
ALTER FUNCTION iam_api.read_acceptance_me_snapshot_v2()
    OWNER TO iam_self_summary_reader;
REVOKE CREATE ON SCHEMA iam_api FROM iam_self_summary_reader;
