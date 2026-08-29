ALTER TABLE iam.access_invitations
    ADD COLUMN token_format_version varchar(64)
        NOT NULL DEFAULT 'access-invitation-token-v1';

ALTER TABLE iam.access_invitations
    ADD CONSTRAINT ck_invitation_token_format_version CHECK (
        token_format_version = 'access-invitation-token-v1'
    );

CREATE OR REPLACE FUNCTION iam.enforce_invitation_binding_immutable()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, iam
AS $function$
BEGIN
    IF NEW.purpose IS DISTINCT FROM OLD.purpose
       OR NEW.organization_id IS DISTINCT FROM OLD.organization_id
       OR NEW.target_scope IS DISTINCT FROM OLD.target_scope
       OR NEW.target_role IS DISTINCT FROM OLD.target_role
       OR NEW.is_initial_admin IS DISTINCT FROM OLD.is_initial_admin
       OR NEW.recipient_contact_id IS DISTINCT FROM OLD.recipient_contact_id
       OR NEW.masked_recipient_label IS DISTINCT FROM OLD.masked_recipient_label
       OR NEW.policy_selector_digest IS DISTINCT FROM OLD.policy_selector_digest
       OR NEW.issued_policy_bundle_id IS DISTINCT FROM OLD.issued_policy_bundle_id
       OR NEW.expires_at IS DISTINCT FROM OLD.expires_at
       OR NEW.issuer_kind IS DISTINCT FROM OLD.issuer_kind
       OR NEW.issuer_user_id IS DISTINCT FROM OLD.issuer_user_id
       OR NEW.token_nonce IS DISTINCT FROM OLD.token_nonce
       OR NEW.token_key_id IS DISTINCT FROM OLD.token_key_id
       OR NEW.token_format_version IS DISTINCT FROM OLD.token_format_version
       OR NEW.created_at IS DISTINCT FROM OLD.created_at
       OR OLD.status <> 'ISSUED'
       OR NEW.status NOT IN ('ACCEPTED', 'REVOKED', 'EXPIRED')
       OR NEW.aggregate_version <> OLD.aggregate_version + 1 THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'trg_invitation_binding_immutable',
            MESSAGE = 'invalid invitation mutation';
    END IF;
    RETURN NEW;
END
$function$;

GRANT SELECT (token_nonce, token_key_id, token_format_version)
    ON iam.access_invitations TO iam_onboarding;
GRANT SELECT (
    is_initial_admin,
    recipient_contact_id,
    masked_recipient_label,
    issued_policy_bundle_id,
    expires_at,
    aggregate_version,
    created_at
) ON iam.access_invitations TO iam_app;
GRANT SELECT (recipient_ref, withdrawn_at)
    ON iam.consent_grants TO iam_app;
GRANT SELECT (scope_derivation, recipient_ref, expiry_days)
    ON iam.consent_offers TO iam_app;

GRANT SELECT (
    id,
    user_id,
    status,
    current_generation,
    aggregate_version
) ON iam.session_families TO iam_self_summary_reader;
GRANT SELECT (
    csrf_salt,
    csrf_key_id,
    csrf_digest,
    generation,
    family_id,
    created_at,
    last_activity_at,
    device_label,
    aggregate_version
) ON iam.sessions TO iam_self_summary_reader;

CREATE POLICY rls_read_session_bootstrap_user_owner ON iam.users
FOR SELECT TO iam_self_summary_reader
USING (
    session_user = 'iam_app'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'SELF'
    AND NULLIF(current_setting('app.operation', true), '')
        = 'READ_SESSION_BOOTSTRAP'
    AND id = NULLIF(current_setting('app.actor_user_id', true), '')::uuid
    AND status IN ('PENDING_ENROLLMENT', 'ACTIVE')
);

CREATE POLICY rls_read_session_bootstrap_session_owner ON iam.sessions
FOR SELECT TO iam_self_summary_reader
USING (
    session_user = 'iam_app'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'SELF'
    AND NULLIF(current_setting('app.operation', true), '')
        = 'READ_SESSION_BOOTSTRAP'
    AND id = NULLIF(current_setting('app.session_id', true), '')::uuid
    AND user_id = NULLIF(current_setting('app.actor_user_id', true), '')::uuid
);

CREATE POLICY rls_read_session_bootstrap_family_owner
ON iam.session_families
FOR SELECT TO iam_self_summary_reader
USING (
    session_user = 'iam_app'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'SELF'
    AND NULLIF(current_setting('app.operation', true), '')
        = 'READ_SESSION_BOOTSTRAP'
    AND user_id = NULLIF(current_setting('app.actor_user_id', true), '')::uuid
    AND EXISTS (
        SELECT 1
        FROM iam.sessions AS exact_session
        WHERE exact_session.id
            = NULLIF(current_setting('app.session_id', true), '')::uuid
          AND exact_session.user_id = session_families.user_id
          AND exact_session.family_id = session_families.id
    )
);

CREATE VIEW iam_api.read_session_bootstrap_v1
WITH (security_barrier = true)
AS
SELECT
    actor.id AS actor_user_id,
    actor.status AS actor_user_status,
    actor.display_handle AS actor_display_handle,
    actor.aggregate_version AS actor_user_version,
    current_session.id AS current_session_id,
    current_session.user_id AS current_session_user_id,
    current_session.family_id AS current_session_family_id,
    current_session.generation AS current_session_generation,
    current_session.csrf_salt AS current_session_csrf_salt,
    current_session.csrf_key_id AS current_session_csrf_key_id,
    current_session.csrf_digest AS current_session_csrf_digest,
    current_session.created_at AS current_session_created_at,
    current_session.last_activity_at AS current_session_last_activity_at,
    current_session.idle_expires_at AS current_session_idle_expires_at,
    current_session.absolute_expires_at AS current_session_absolute_expires_at,
    current_session.device_label AS current_session_device_label,
    current_session.status AS current_session_status,
    current_session.aggregate_version AS current_session_version,
    family.id AS current_family_id,
    family.user_id AS current_family_user_id,
    family.status AS current_family_status,
    family.current_generation AS current_family_generation,
    family.aggregate_version AS current_family_version
FROM iam.users AS actor
JOIN iam.sessions AS current_session
  ON current_session.user_id = actor.id
JOIN iam.session_families AS family
  ON family.id = current_session.family_id
 AND family.user_id = actor.id
WHERE session_user = 'iam_app'
  AND NULLIF(current_setting('app.scope_kind', true), '') = 'SELF'
  AND NULLIF(current_setting('app.operation', true), '')
      = 'READ_SESSION_BOOTSTRAP'
  AND actor.id = NULLIF(
      current_setting('app.actor_user_id', true), ''
  )::uuid
  AND current_session.id = NULLIF(
      current_setting('app.session_id', true), ''
  )::uuid;

REVOKE ALL ON iam_api.read_session_bootstrap_v1 FROM PUBLIC;
GRANT SELECT ON iam_api.read_session_bootstrap_v1 TO iam_app;
GRANT CREATE ON SCHEMA iam_api TO iam_self_summary_reader;
ALTER VIEW iam_api.read_session_bootstrap_v1 OWNER TO iam_self_summary_reader;
REVOKE CREATE ON SCHEMA iam_api FROM iam_self_summary_reader;

CREATE POLICY rls_read_org_authority_user_owner ON iam.users
FOR SELECT TO iam_self_summary_reader
USING (
    session_user = 'iam_app'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'ORGANIZATION'
    AND NULLIF(current_setting('app.operation', true), '') IN (
        'READ_ORGANIZATION_SUMMARY',
        'LIST_ORGANIZATION_INVITATIONS',
        'LIST_ORGANIZATION_MEMBERSHIPS'
    )
    AND id = NULLIF(current_setting('app.actor_user_id', true), '')::uuid
    AND status = 'ACTIVE'
);

CREATE POLICY rls_read_org_authority_session_owner ON iam.sessions
FOR SELECT TO iam_self_summary_reader
USING (
    session_user = 'iam_app'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'ORGANIZATION'
    AND NULLIF(current_setting('app.operation', true), '') IN (
        'READ_ORGANIZATION_SUMMARY',
        'LIST_ORGANIZATION_INVITATIONS',
        'LIST_ORGANIZATION_MEMBERSHIPS'
    )
    AND id = NULLIF(current_setting('app.session_id', true), '')::uuid
    AND user_id = NULLIF(current_setting('app.actor_user_id', true), '')::uuid
    AND status = 'ACTIVE'
    AND transaction_timestamp() < idle_expires_at
    AND transaction_timestamp() < absolute_expires_at
);

CREATE POLICY rls_read_org_authority_family_owner ON iam.session_families
FOR SELECT TO iam_self_summary_reader
USING (
    session_user = 'iam_app'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'ORGANIZATION'
    AND NULLIF(current_setting('app.operation', true), '') IN (
        'READ_ORGANIZATION_SUMMARY',
        'LIST_ORGANIZATION_INVITATIONS',
        'LIST_ORGANIZATION_MEMBERSHIPS'
    )
    AND user_id = NULLIF(current_setting('app.actor_user_id', true), '')::uuid
    AND status = 'ACTIVE'
    AND EXISTS (
        SELECT 1
        FROM iam.sessions AS exact_session
        WHERE exact_session.id
            = NULLIF(current_setting('app.session_id', true), '')::uuid
          AND exact_session.family_id = session_families.id
          AND exact_session.generation = session_families.current_generation
    )
);

CREATE POLICY rls_read_org_authority_organization_owner ON iam.organizations
FOR SELECT TO iam_self_summary_reader
USING (
    session_user = 'iam_app'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'ORGANIZATION'
    AND id = NULLIF(current_setting('app.organization_id', true), '')::uuid
    AND status = 'ACTIVE'
);

CREATE POLICY rls_read_org_authority_membership_owner ON iam.memberships
FOR SELECT TO iam_self_summary_reader
USING (
    session_user = 'iam_app'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'ORGANIZATION'
    AND organization_id
        = NULLIF(current_setting('app.organization_id', true), '')::uuid
    AND user_id = NULLIF(current_setting('app.actor_user_id', true), '')::uuid
    AND status = 'ACTIVE'
);

CREATE POLICY rls_read_org_authority_role_owner
ON iam.membership_role_grants
FOR SELECT TO iam_self_summary_reader
USING (
    session_user = 'iam_app'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'ORGANIZATION'
    AND organization_id
        = NULLIF(current_setting('app.organization_id', true), '')::uuid
    AND user_id = NULLIF(current_setting('app.actor_user_id', true), '')::uuid
    AND revoked_at IS NULL
);

CREATE FUNCTION iam.read_model_actor_has_organization_role(
    candidate_organization_id uuid,
    require_admin boolean
)
RETURNS boolean
LANGUAGE sql
STABLE
PARALLEL RESTRICTED
SECURITY DEFINER
SET search_path = pg_catalog, iam, pg_temp
AS $function$
    SELECT
        session_user = 'iam_app'
        AND NULLIF(current_setting('app.scope_kind', true), '')
            = 'ORGANIZATION'
        AND NULLIF(current_setting('app.operation', true), '') IN (
            'READ_ORGANIZATION_SUMMARY',
            'LIST_ORGANIZATION_INVITATIONS',
            'LIST_ORGANIZATION_MEMBERSHIPS'
        )
        AND candidate_organization_id = NULLIF(
            current_setting('app.organization_id', true), ''
        )::uuid
        AND EXISTS (
            SELECT 1
            FROM iam.users AS actor
            JOIN iam.sessions AS current_session
              ON current_session.user_id = actor.id
            JOIN iam.session_families AS family
              ON family.id = current_session.family_id
             AND family.user_id = actor.id
            JOIN iam.memberships AS membership
              ON membership.organization_id = candidate_organization_id
             AND membership.user_id = actor.id
            JOIN iam.membership_role_grants AS role_grant
              ON role_grant.organization_id = membership.organization_id
             AND role_grant.membership_id = membership.id
             AND role_grant.user_id = membership.user_id
            JOIN iam.organizations AS organization
              ON organization.id = membership.organization_id
            WHERE actor.id = NULLIF(
                    current_setting('app.actor_user_id', true), ''
                  )::uuid
              AND actor.status = 'ACTIVE'
              AND current_session.id = NULLIF(
                    current_setting('app.session_id', true), ''
                  )::uuid
              AND current_session.status = 'ACTIVE'
              AND transaction_timestamp() < current_session.idle_expires_at
              AND transaction_timestamp() < current_session.absolute_expires_at
              AND family.status = 'ACTIVE'
              AND family.current_generation = current_session.generation
              AND membership.status = 'ACTIVE'
              AND organization.status = 'ACTIVE'
              AND role_grant.revoked_at IS NULL
              AND role_grant.role_code IN ('ORG_ADMIN', 'DEMAND_OWNER')
              AND (NOT require_admin OR role_grant.role_code = 'ORG_ADMIN')
        )
$function$;

REVOKE ALL ON FUNCTION iam.read_model_actor_has_organization_role(uuid, boolean)
    FROM PUBLIC;
GRANT EXECUTE ON FUNCTION
    iam.read_model_actor_has_organization_role(uuid, boolean) TO iam_app;
GRANT CREATE ON SCHEMA iam TO iam_self_summary_reader;
ALTER FUNCTION iam.read_model_actor_has_organization_role(uuid, boolean)
    OWNER TO iam_self_summary_reader;
REVOKE CREATE ON SCHEMA iam FROM iam_self_summary_reader;

DROP POLICY rls_organization_scope ON iam.organizations;
CREATE POLICY rls_organization_scope ON iam.organizations
FOR SELECT TO iam_app
USING (
    NULLIF(current_setting('app.scope_kind', true), '') = 'ORGANIZATION'
    AND id = NULLIF(current_setting('app.organization_id', true), '')::uuid
    AND iam.read_model_actor_has_organization_role(
        id,
        NULLIF(current_setting('app.operation', true), '') IN (
            'LIST_ORGANIZATION_INVITATIONS',
            'LIST_ORGANIZATION_MEMBERSHIPS'
        )
    )
);

DROP POLICY rls_membership_organization ON iam.memberships;
CREATE POLICY rls_membership_organization ON iam.memberships
FOR SELECT TO iam_app
USING (
    NULLIF(current_setting('app.scope_kind', true), '') = 'ORGANIZATION'
    AND organization_id
        = NULLIF(current_setting('app.organization_id', true), '')::uuid
    AND iam.read_model_actor_has_organization_role(
        organization_id,
        NULLIF(current_setting('app.operation', true), '') IN (
            'LIST_ORGANIZATION_INVITATIONS',
            'LIST_ORGANIZATION_MEMBERSHIPS'
        )
    )
    AND (
        user_id = NULLIF(current_setting('app.actor_user_id', true), '')::uuid
        OR NULLIF(current_setting('app.operation', true), '')
            = 'LIST_ORGANIZATION_MEMBERSHIPS'
    )
);

DROP POLICY rls_membership_role_organization ON iam.membership_role_grants;
CREATE POLICY rls_membership_role_organization ON iam.membership_role_grants
FOR SELECT TO iam_app
USING (
    NULLIF(current_setting('app.scope_kind', true), '') = 'ORGANIZATION'
    AND organization_id
        = NULLIF(current_setting('app.organization_id', true), '')::uuid
    AND iam.read_model_actor_has_organization_role(
        organization_id,
        NULLIF(current_setting('app.operation', true), '') IN (
            'LIST_ORGANIZATION_INVITATIONS',
            'LIST_ORGANIZATION_MEMBERSHIPS'
        )
    )
    AND (
        user_id = NULLIF(current_setting('app.actor_user_id', true), '')::uuid
        OR NULLIF(current_setting('app.operation', true), '')
            = 'LIST_ORGANIZATION_MEMBERSHIPS'
    )
);

CREATE POLICY rls_read_organization_actor_user ON iam.users
FOR SELECT TO iam_app
USING (
    NULLIF(current_setting('app.scope_kind', true), '') = 'ORGANIZATION'
    AND (
        id = NULLIF(current_setting('app.actor_user_id', true), '')::uuid
        OR (
            NULLIF(current_setting('app.operation', true), '')
                = 'LIST_ORGANIZATION_MEMBERSHIPS'
            AND iam.read_model_actor_has_organization_role(
                NULLIF(current_setting('app.organization_id', true), '')::uuid,
                true
            )
            AND EXISTS (
                SELECT 1
                FROM iam.memberships AS target_membership
                WHERE target_membership.organization_id = NULLIF(
                        current_setting('app.organization_id', true), ''
                      )::uuid
                  AND target_membership.user_id = users.id
            )
        )
    )
);

CREATE POLICY rls_read_organization_session ON iam.sessions
FOR SELECT TO iam_app
USING (
    NULLIF(current_setting('app.scope_kind', true), '') = 'ORGANIZATION'
    AND id = NULLIF(current_setting('app.session_id', true), '')::uuid
    AND user_id = NULLIF(current_setting('app.actor_user_id', true), '')::uuid
    AND iam.read_model_actor_has_organization_role(
        NULLIF(current_setting('app.organization_id', true), '')::uuid,
        NULLIF(current_setting('app.operation', true), '') IN (
            'LIST_ORGANIZATION_INVITATIONS',
            'LIST_ORGANIZATION_MEMBERSHIPS'
        )
    )
);

CREATE POLICY rls_read_organization_family ON iam.session_families
FOR SELECT TO iam_app
USING (
    NULLIF(current_setting('app.scope_kind', true), '') = 'ORGANIZATION'
    AND user_id = NULLIF(current_setting('app.actor_user_id', true), '')::uuid
    AND EXISTS (
        SELECT 1
        FROM iam.sessions AS exact_session
        WHERE exact_session.id
            = NULLIF(current_setting('app.session_id', true), '')::uuid
          AND exact_session.family_id = session_families.id
    )
);

CREATE POLICY rls_read_organization_invitation ON iam.access_invitations
FOR SELECT TO iam_app
USING (
    NULLIF(current_setting('app.scope_kind', true), '') = 'ORGANIZATION'
    AND NULLIF(current_setting('app.operation', true), '')
        = 'LIST_ORGANIZATION_INVITATIONS'
    AND organization_id
        = NULLIF(current_setting('app.organization_id', true), '')::uuid
    AND iam.read_model_actor_has_organization_role(organization_id, true)
);

CREATE POLICY rls_read_organization_selector ON iam.policy_selectors
FOR SELECT TO iam_app
USING (
    NULLIF(current_setting('app.scope_kind', true), '') = 'ORGANIZATION'
    AND NULLIF(current_setting('app.operation', true), '')
        = 'LIST_ORGANIZATION_INVITATIONS'
    AND iam.read_model_actor_has_organization_role(
        NULLIF(current_setting('app.organization_id', true), '')::uuid,
        true
    )
    AND EXISTS (
        SELECT 1
        FROM iam.access_invitations AS invitation
        WHERE invitation.organization_id = NULLIF(
                current_setting('app.organization_id', true), ''
              )::uuid
          AND invitation.policy_selector_digest
              = policy_selectors.selector_digest
    )
);

CREATE POLICY rls_read_organization_bundle ON iam.policy_bundles
FOR SELECT TO iam_app
USING (
    NULLIF(current_setting('app.scope_kind', true), '') = 'ORGANIZATION'
    AND NULLIF(current_setting('app.operation', true), '')
        = 'LIST_ORGANIZATION_INVITATIONS'
    AND iam.read_model_actor_has_organization_role(
        NULLIF(current_setting('app.organization_id', true), '')::uuid,
        true
    )
    AND EXISTS (
        SELECT 1
        FROM iam.access_invitations AS invitation
        WHERE invitation.organization_id = NULLIF(
                current_setting('app.organization_id', true), ''
              )::uuid
          AND invitation.issued_policy_bundle_id = policy_bundles.id
          AND invitation.policy_selector_digest
              = policy_bundles.selector_digest
    )
);

CREATE POLICY rls_read_organization_bundle_document
ON iam.policy_bundle_documents
FOR SELECT TO iam_app
USING (
    NULLIF(current_setting('app.scope_kind', true), '') = 'ORGANIZATION'
    AND NULLIF(current_setting('app.operation', true), '')
        = 'LIST_ORGANIZATION_INVITATIONS'
    AND EXISTS (
        SELECT 1
        FROM iam.access_invitations AS invitation
        WHERE invitation.organization_id = NULLIF(
                current_setting('app.organization_id', true), ''
              )::uuid
          AND invitation.issued_policy_bundle_id
              = policy_bundle_documents.bundle_id
    )
);

CREATE POLICY rls_read_organization_document ON iam.policy_documents
FOR SELECT TO iam_app
USING (
    NULLIF(current_setting('app.scope_kind', true), '') = 'ORGANIZATION'
    AND NULLIF(current_setting('app.operation', true), '')
        = 'LIST_ORGANIZATION_INVITATIONS'
    AND EXISTS (
        SELECT 1
        FROM iam.policy_bundle_documents AS membership
        WHERE membership.document_id = policy_documents.id
    )
);

CREATE POLICY rls_read_organization_offer ON iam.consent_offers
FOR SELECT TO iam_app
USING (
    NULLIF(current_setting('app.scope_kind', true), '') = 'ORGANIZATION'
    AND NULLIF(current_setting('app.operation', true), '')
        = 'LIST_ORGANIZATION_INVITATIONS'
    AND EXISTS (
        SELECT 1
        FROM iam.access_invitations AS invitation
        WHERE invitation.organization_id = NULLIF(
                current_setting('app.organization_id', true), ''
              )::uuid
          AND invitation.issued_policy_bundle_id = consent_offers.bundle_id
    )
);

CREATE POLICY rls_read_organization_offer_category
ON iam.consent_offer_data_categories
FOR SELECT TO iam_app
USING (
    NULLIF(current_setting('app.scope_kind', true), '') = 'ORGANIZATION'
    AND NULLIF(current_setting('app.operation', true), '')
        = 'LIST_ORGANIZATION_INVITATIONS'
    AND EXISTS (
        SELECT 1
        FROM iam.consent_offers AS offer
        WHERE offer.id = consent_offer_data_categories.offer_id
    )
);

CREATE POLICY rls_read_public_policy_selector ON iam.policy_selectors
FOR SELECT TO iam_app
USING (
    NULLIF(current_setting('app.scope_kind', true), '')
        = 'PUBLIC_POLICY_READ'
    AND NULLIF(current_setting('app.operation', true), '')
        = 'READ_PUBLIC_POLICY_BUNDLE'
    AND current_bundle_id = NULLIF(
        current_setting('app.policy_bundle_id', true), ''
    )::uuid
);

CREATE POLICY rls_read_me_policy_selector ON iam.policy_selectors
FOR SELECT TO iam_app
USING (
    NULLIF(current_setting('app.scope_kind', true), '') = 'SELF'
    AND NULLIF(current_setting('app.operation', true), '') = 'ME_READ_MODEL'
    AND EXISTS (
        SELECT 1
        FROM iam.user_role_grants AS user_grant
        WHERE user_grant.user_id = NULLIF(
                current_setting('app.actor_user_id', true), ''
              )::uuid
          AND user_grant.revoked_at IS NULL
          AND user_grant.policy_selector_digest
              = policy_selectors.selector_digest
        UNION ALL
        SELECT 1
        FROM iam.membership_role_grants AS membership_grant
        JOIN iam.memberships AS membership
          ON membership.id = membership_grant.membership_id
         AND membership.organization_id
             = membership_grant.organization_id
         AND membership.user_id = membership_grant.user_id
        WHERE membership_grant.user_id = NULLIF(
                current_setting('app.actor_user_id', true), ''
              )::uuid
          AND membership_grant.revoked_at IS NULL
          AND membership.status = 'ACTIVE'
          AND membership_grant.policy_selector_digest
              = policy_selectors.selector_digest
    )
);

CREATE POLICY rls_read_me_organization ON iam.organizations
FOR SELECT TO iam_app
USING (
    NULLIF(current_setting('app.scope_kind', true), '') = 'SELF'
    AND NULLIF(current_setting('app.operation', true), '') = 'ME_READ_MODEL'
    AND EXISTS (
        SELECT 1
        FROM iam.memberships AS membership
        WHERE membership.organization_id = organizations.id
          AND membership.user_id = NULLIF(
                current_setting('app.actor_user_id', true), ''
              )::uuid
          AND membership.status = 'ACTIVE'
    )
);

CREATE POLICY rls_read_invitation_selector ON iam.policy_selectors
FOR SELECT TO iam_onboarding
USING (
    NULLIF(current_setting('app.scope_kind', true), '') = 'INVITATION'
    AND NULLIF(current_setting('app.operation', true), '') = 'INSPECT'
    AND EXISTS (
        SELECT 1
        FROM iam.access_invitations AS invitation
        WHERE invitation.id = NULLIF(
                current_setting('app.target_invitation_id', true), ''
              )::uuid
          AND invitation.policy_selector_digest
              = policy_selectors.selector_digest
    )
);

CREATE POLICY rls_read_invitation_bundle ON iam.policy_bundles
FOR SELECT TO iam_onboarding
USING (
    NULLIF(current_setting('app.scope_kind', true), '') = 'INVITATION'
    AND NULLIF(current_setting('app.operation', true), '') = 'INSPECT'
    AND status = 'ACTIVE'
    AND effective_at <= transaction_timestamp()
    AND (effective_until IS NULL OR transaction_timestamp() < effective_until)
    AND EXISTS (
        SELECT 1
        FROM iam.access_invitations AS invitation
        WHERE invitation.id = NULLIF(
                current_setting('app.target_invitation_id', true), ''
              )::uuid
          AND invitation.issued_policy_bundle_id = policy_bundles.id
          AND invitation.policy_selector_digest
              = policy_bundles.selector_digest
    )
);

CREATE POLICY rls_read_invitation_bundle_document
ON iam.policy_bundle_documents
FOR SELECT TO iam_onboarding
USING (
    NULLIF(current_setting('app.scope_kind', true), '') = 'INVITATION'
    AND NULLIF(current_setting('app.operation', true), '') = 'INSPECT'
    AND EXISTS (
        SELECT 1
        FROM iam.access_invitations AS invitation
        WHERE invitation.id = NULLIF(
                current_setting('app.target_invitation_id', true), ''
              )::uuid
          AND invitation.issued_policy_bundle_id
              = policy_bundle_documents.bundle_id
    )
);

CREATE POLICY rls_read_invitation_document ON iam.policy_documents
FOR SELECT TO iam_onboarding
USING (
    NULLIF(current_setting('app.scope_kind', true), '') = 'INVITATION'
    AND NULLIF(current_setting('app.operation', true), '') = 'INSPECT'
    AND status = 'ACTIVE'
    AND EXISTS (
        SELECT 1
        FROM iam.policy_bundle_documents AS membership
        WHERE membership.document_id = policy_documents.id
    )
);

CREATE POLICY rls_read_invitation_offer ON iam.consent_offers
FOR SELECT TO iam_onboarding
USING (
    NULLIF(current_setting('app.scope_kind', true), '') = 'INVITATION'
    AND NULLIF(current_setting('app.operation', true), '') = 'INSPECT'
    AND EXISTS (
        SELECT 1
        FROM iam.access_invitations AS invitation
        WHERE invitation.id = NULLIF(
                current_setting('app.target_invitation_id', true), ''
              )::uuid
          AND invitation.issued_policy_bundle_id = consent_offers.bundle_id
    )
);

CREATE POLICY rls_read_invitation_offer_category
ON iam.consent_offer_data_categories
FOR SELECT TO iam_onboarding
USING (
    NULLIF(current_setting('app.scope_kind', true), '') = 'INVITATION'
    AND NULLIF(current_setting('app.operation', true), '') = 'INSPECT'
    AND EXISTS (
        SELECT 1
        FROM iam.consent_offers AS offer
        WHERE offer.id = consent_offer_data_categories.offer_id
    )
);

CREATE VIEW iam_api.read_invitation_preview_v1
WITH (security_barrier = true, security_invoker = true)
AS
SELECT
    invitation.id AS invitation_id,
    invitation.organization_id,
    invitation.policy_selector_digest,
    invitation.issued_policy_bundle_id,
    invitation.status,
    invitation.expires_at,
    invitation.token_nonce,
    invitation.token_key_id,
    invitation.token_format_version,
    organization.public_name AS organization_public_name,
    organization.status AS organization_status
FROM iam.access_invitations AS invitation
JOIN iam.organizations AS organization
  ON organization.id = invitation.organization_id
WHERE invitation.id = NULLIF(
    current_setting('app.target_invitation_id', true), ''
)::uuid;

CREATE VIEW iam_api.read_me_authority_policy_graph_v1
WITH (security_barrier = true, security_invoker = true)
AS
SELECT
    grant_row.id AS role_grant_id,
    grant_row.user_id,
    grant_row.role_code,
    grant_row.source_invitation_id,
    grant_row.policy_selector_digest,
    grant_row.revoked_at,
    grant_row.aggregate_version
FROM iam.user_role_grants AS grant_row
WHERE grant_row.user_id = NULLIF(
    current_setting('app.actor_user_id', true), ''
)::uuid;

CREATE VIEW iam_api.read_organization_memberships_page_v1
WITH (security_barrier = true, security_invoker = true)
AS
SELECT
    membership.id AS membership_id,
    membership.organization_id,
    membership.user_id,
    membership.status,
    membership.source_invitation_id,
    membership.aggregate_version,
    membership.created_at,
    target_user.display_handle,
    role_grant.id AS role_grant_id,
    role_grant.role_code,
    role_grant.policy_selector_digest,
    role_grant.revoked_at
FROM iam.memberships AS membership
JOIN iam.users AS target_user ON target_user.id = membership.user_id
LEFT JOIN iam.membership_role_grants AS role_grant
  ON role_grant.organization_id = membership.organization_id
 AND role_grant.membership_id = membership.id
 AND role_grant.user_id = membership.user_id
WHERE membership.organization_id = NULLIF(
    current_setting('app.organization_id', true), ''
)::uuid;

REVOKE ALL ON
    iam_api.read_invitation_preview_v1,
    iam_api.read_me_authority_policy_graph_v1,
    iam_api.read_organization_memberships_page_v1
FROM PUBLIC;
GRANT SELECT ON iam_api.read_invitation_preview_v1 TO iam_onboarding;
GRANT SELECT ON iam_api.read_me_authority_policy_graph_v1 TO iam_app;
GRANT SELECT ON iam_api.read_organization_memberships_page_v1 TO iam_app;
