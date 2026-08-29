-- Narrow Accept visibility and mutation paths for prior ConsentGrant expiry.

DROP POLICY rls_consent_grant_accept ON iam.consent_grants;

CREATE POLICY rls_consent_grant_accept
ON iam.consent_grants
FOR SELECT TO iam_onboarding
USING (
    session_user = 'iam_onboarding'
    AND current_user = 'iam_onboarding'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'AUTH_PROTOCOL'
    AND NULLIF(current_setting('app.operation', true), '') = 'ACCEPT'
    AND user_id = NULLIF(
        current_setting('app.actor_user_id', true),
        ''
    )::uuid
);

CREATE POLICY rls_consent_grant_accept_insert
ON iam.consent_grants
FOR INSERT TO iam_onboarding
WITH CHECK (
    session_user = 'iam_onboarding'
    AND current_user = 'iam_onboarding'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'AUTH_PROTOCOL'
    AND NULLIF(current_setting('app.operation', true), '') = 'ACCEPT'
    AND user_id = NULLIF(
        current_setting('app.actor_user_id', true),
        ''
    )::uuid
    AND session_id = NULLIF(
        current_setting('app.session_id', true),
        ''
    )::uuid
    AND auth_transaction_id = NULLIF(
        current_setting('app.auth_transaction_id', true),
        ''
    )::uuid
    AND command_id = NULLIF(
        current_setting('app.command_id', true),
        ''
    )::uuid
);

CREATE POLICY rls_consent_grant_accept_expire
ON iam.consent_grants
FOR UPDATE TO iam_onboarding
USING (
    session_user = 'iam_onboarding'
    AND current_user = 'iam_onboarding'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'AUTH_PROTOCOL'
    AND NULLIF(current_setting('app.operation', true), '') = 'ACCEPT'
    AND user_id = NULLIF(
        current_setting('app.actor_user_id', true),
        ''
    )::uuid
    AND status = 'ACTIVE'
    AND EXISTS (
        SELECT 1
        FROM iam.policy_selectors AS selector
        JOIN iam.policy_bundles AS current_bundle
          ON current_bundle.id = selector.current_bundle_id
         AND current_bundle.selector_digest = selector.selector_digest
         AND current_bundle.status = 'ACTIVE'
         AND current_bundle.effective_at <= transaction_timestamp()
         AND (
             current_bundle.effective_until IS NULL
             OR transaction_timestamp() < current_bundle.effective_until
         )
        JOIN iam.consent_offers AS offer
          ON offer.bundle_id = current_bundle.id
         AND offer.purpose = consent_grants.purpose
         AND offer.scope_type = consent_grants.scope_type
         AND (
             (
                 offer.scope_derivation =
                     'PLATFORM_PARTICIPATION_NULL_SCOPE'
                 AND consent_grants.scope_id IS NULL
             )
         )
        WHERE selector.selector_digest = decode(
            NULLIF(
                current_setting('app.policy_selector_digest', true),
                ''
            ),
            'hex'
        )
          AND selector.current_bundle_id = NULLIF(
              current_setting('app.policy_bundle_id', true),
              ''
          )::uuid
    )
)
WITH CHECK (
    session_user = 'iam_onboarding'
    AND current_user = 'iam_onboarding'
    AND NULLIF(current_setting('app.scope_kind', true), '') = 'AUTH_PROTOCOL'
    AND NULLIF(current_setting('app.operation', true), '') = 'ACCEPT'
    AND user_id = NULLIF(
        current_setting('app.actor_user_id', true),
        ''
    )::uuid
    AND status = 'EXPIRED'
    AND withdrawn_at IS NULL
    AND expires_at <= transaction_timestamp()
    AND EXISTS (
        SELECT 1
        FROM iam.policy_selectors AS selector
        JOIN iam.policy_bundles AS current_bundle
          ON current_bundle.id = selector.current_bundle_id
         AND current_bundle.selector_digest = selector.selector_digest
         AND current_bundle.status = 'ACTIVE'
         AND current_bundle.effective_at <= transaction_timestamp()
         AND (
             current_bundle.effective_until IS NULL
             OR transaction_timestamp() < current_bundle.effective_until
         )
        JOIN iam.consent_offers AS offer
          ON offer.bundle_id = current_bundle.id
         AND offer.purpose = consent_grants.purpose
         AND offer.scope_type = consent_grants.scope_type
         AND (
             (
                 offer.scope_derivation =
                     'PLATFORM_PARTICIPATION_NULL_SCOPE'
                 AND consent_grants.scope_id IS NULL
             )
         )
        WHERE selector.selector_digest = decode(
            NULLIF(
                current_setting('app.policy_selector_digest', true),
                ''
            ),
            'hex'
        )
          AND selector.current_bundle_id = NULLIF(
              current_setting('app.policy_bundle_id', true),
              ''
          )::uuid
    )
);
