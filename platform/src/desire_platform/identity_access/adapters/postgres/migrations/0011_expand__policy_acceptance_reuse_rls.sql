-- Narrow prior PolicyAcceptance visibility for exact Accept evidence reuse.

CREATE POLICY rls_policy_acceptance_accept_reuse
ON iam.policy_acceptances
FOR SELECT TO iam_onboarding
USING (
    NULLIF(current_setting('app.scope_kind', true), '') = 'AUTH_PROTOCOL'
    AND NULLIF(current_setting('app.operation', true), '') = 'ACCEPT'
    AND user_id = NULLIF(
        current_setting('app.actor_user_id', true),
        ''
    )::uuid
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
        JOIN iam.policy_bundle_documents AS membership
          ON membership.bundle_id = current_bundle.id
         AND membership.required
         AND membership.document_id = policy_acceptances.document_id
        JOIN iam.policy_documents AS document
          ON document.id = membership.document_id
         AND document.content_sha256 = policy_acceptances.content_sha256
         AND document.status = 'ACTIVE'
         AND document.legal_effect IN (
             'NOTICE_ACKNOWLEDGEMENT',
             'CONTRACT_ACCEPTANCE'
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
