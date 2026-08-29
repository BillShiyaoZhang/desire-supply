"""Reviewed fixed SQL text for IAM read-model projection version 1.

Every value is a static module constant.  Bind values may constrain an exact
root, page boundary, or limit; they never choose identifiers, joins, ordering,
or projection fields.
"""

READ_SESSION_BOOTSTRAP_V1 = """
/* iam.read_session_bootstrap_v1 */
SELECT *
FROM iam_api.read_session_bootstrap_v1
WHERE actor_user_id = %s::uuid
  AND current_session_id = %s::uuid
"""


READ_INVITATION_PREVIEW_V1 = """
/* iam.read_invitation_preview_v1 */
SELECT
    invitation.id AS invitation_id,
    invitation.purpose AS invitation_purpose,
    invitation.organization_id AS invitation_organization_id,
    invitation.target_scope AS invitation_target_scope,
    invitation.target_role AS invitation_target_role,
    invitation.is_initial_admin AS invitation_is_initial_admin,
    invitation.recipient_contact_id AS invitation_recipient_contact_id,
    invitation.masked_recipient_label AS invitation_masked_recipient_label,
    invitation.policy_selector_digest AS invitation_selector_digest,
    invitation.issued_policy_bundle_id AS invitation_issued_bundle_id,
    invitation.status AS invitation_status,
    invitation.expires_at AS invitation_expires_at,
    encode(invitation.token_nonce, 'hex') AS invitation_token_nonce,
    invitation.token_key_id AS invitation_token_key_id,
    invitation.token_format_version AS invitation_token_format_version,
    invitation.accepted_by_user_id AS invitation_accepted_by_user_id,
    invitation.aggregate_version AS invitation_version,
    invitation.created_at AS invitation_created_at,
    contact.id AS recipient_contact_id,
    contact.contact_type AS recipient_contact_type,
    contact.binding_digest AS recipient_binding_digest,
    contact.binding_digest_key_id AS recipient_binding_digest_key_id,
    organization.id AS organization_id,
    organization.public_name AS organization_public_name,
    organization.organization_type AS organization_type,
    organization.jurisdiction AS organization_jurisdiction,
    organization.status AS organization_status,
    organization.aggregate_version AS organization_version,
    selector.selector_digest AS selector_digest,
    selector.canonicalization_version AS selector_canonicalization_version,
    selector.access_purpose AS selector_access_purpose,
    selector.scope_type AS selector_scope_type,
    selector.target_role AS selector_target_role,
    selector.jurisdiction AS selector_jurisdiction,
    selector.locale AS selector_locale,
    selector.current_bundle_id AS selector_current_bundle_id,
    bundle.id AS bundle_id,
    bundle.selector_digest AS bundle_selector_digest,
    bundle.status AS bundle_status,
    bundle.effective_at AS bundle_effective_at,
    bundle.effective_until AS bundle_effective_until,
    bundle.aggregate_version AS bundle_version,
    membership.document_id AS document_id,
    membership.position AS document_position,
    membership.required AS document_required,
    document.kind AS document_kind,
    document.locale AS document_locale,
    document.semantic_version AS document_semantic_version,
    document.canonical_body AS document_canonical_body,
    document.content_sha256 AS document_content_sha256,
    document.legal_effect AS document_legal_effect,
    document.jurisdiction AS document_jurisdiction,
    document.status AS document_status,
    offer.id AS offer_id,
    offer.offer_version AS offer_version,
    offer.purpose AS offer_purpose,
    offer.scope_type AS offer_scope_type,
    offer.scope_derivation AS offer_scope_derivation,
    offer.recipient_ref AS offer_recipient_ref,
    offer.recipient_label AS offer_recipient_label,
    offer.document_id AS offer_document_id,
    offer.document_content_sha256 AS offer_document_sha256,
    offer.expiry_rule AS offer_expiry_rule,
    offer.expiry_days AS offer_expiry_days,
    offer.not_after AS offer_not_after,
    offer.optional AS offer_optional,
    offer.canonical_offer_sha256 AS offer_canonical_sha256,
    COALESCE(
        ARRAY(
            SELECT category.category
            FROM iam.consent_offer_data_categories AS category
            WHERE category.offer_id = offer.id
            ORDER BY category.position
        ),
        ARRAY[]::text[]
    ) AS offer_categories
FROM iam.access_invitations AS invitation
JOIN iam.contact_points AS contact
  ON contact.id = invitation.recipient_contact_id
JOIN iam.organizations AS organization
  ON organization.id = invitation.organization_id
LEFT JOIN iam.policy_selectors AS selector
  ON selector.selector_digest = invitation.policy_selector_digest
LEFT JOIN iam.policy_bundles AS bundle
  ON bundle.id = invitation.issued_policy_bundle_id
 AND bundle.selector_digest = invitation.policy_selector_digest
LEFT JOIN iam.policy_bundle_documents AS membership
  ON membership.bundle_id = bundle.id
LEFT JOIN iam.policy_documents AS document
  ON document.id = membership.document_id
LEFT JOIN iam.consent_offers AS offer
  ON offer.bundle_id = bundle.id
WHERE invitation.id = %s::uuid
ORDER BY membership.position, offer.purpose, offer.id
"""


READ_PUBLIC_POLICY_BUNDLE_V1 = """
/* iam.read_public_policy_bundle_v1 */
SELECT
    selector.selector_digest,
    selector.canonicalization_version,
    selector.access_purpose,
    selector.scope_type,
    selector.target_role,
    selector.jurisdiction,
    selector.locale,
    selector.current_bundle_id,
    bundle.id AS bundle_id,
    bundle.selector_digest AS bundle_selector_digest,
    bundle.status AS bundle_status,
    bundle.effective_at AS bundle_effective_at,
    bundle.effective_until AS bundle_effective_until,
    bundle.aggregate_version AS bundle_version
FROM iam.policy_bundles AS bundle
JOIN iam.policy_selectors AS selector
  ON selector.selector_digest = bundle.selector_digest
WHERE bundle.id = %s::uuid
"""


READ_PUBLIC_POLICY_DOCUMENTS_V1 = """
/* iam.read_public_policy_documents_v1 */
SELECT
    membership.bundle_id,
    membership.document_id AS document_id,
    membership.position,
    membership.required,
    document.kind,
    document.locale,
    document.semantic_version,
    document.canonical_body,
    document.content_sha256,
    document.legal_effect,
    document.jurisdiction,
    document.status
FROM iam.policy_bundle_documents AS membership
JOIN iam.policy_documents AS document
  ON document.id = membership.document_id
WHERE membership.bundle_id = %s::uuid
ORDER BY membership.position
"""


READ_PUBLIC_POLICY_OFFERS_V1 = """
/* iam.read_public_policy_offers_v1 */
SELECT
    offer.id AS offer_id,
    offer.bundle_id,
    offer.offer_version,
    offer.purpose,
    offer.scope_type,
    offer.scope_derivation,
    offer.recipient_ref,
    offer.recipient_label,
    offer.document_id,
    offer.document_content_sha256,
    offer.expiry_rule,
    offer.expiry_days,
    offer.not_after,
    offer.optional,
    offer.canonical_offer_sha256,
    COALESCE(
        ARRAY(
            SELECT category.category
            FROM iam.consent_offer_data_categories AS category
            WHERE category.offer_id = offer.id
            ORDER BY category.position
        ),
        ARRAY[]::text[]
    ) AS categories
FROM iam.consent_offers AS offer
WHERE offer.bundle_id = %s::uuid
ORDER BY offer.purpose, offer.id
"""


READ_ME_SELF_SUMMARY_V1 = """
/* iam.read_me_self_summary_v1 */
SELECT
    actor.id AS actor_user_id,
    actor.status AS actor_user_status,
    actor.display_handle AS actor_display_handle,
    actor.aggregate_version AS actor_user_version,
    current_session.id AS current_session_id,
    current_session.user_id AS current_session_user_id,
    current_session.family_id AS current_session_family_id,
    current_session.generation AS current_session_generation,
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
WHERE actor.id = %s::uuid
  AND current_session.id = %s::uuid
"""


READ_ME_AUTHORITY_POLICY_GRAPH_V1 = """
/* iam.read_me_authority_policy_graph_v1 */
WITH relevant_selectors AS (
    SELECT grant_row.policy_selector_digest
    FROM iam.user_role_grants AS grant_row
    WHERE grant_row.user_id = %s::uuid
      AND grant_row.revoked_at IS NULL
    UNION
    SELECT grant_row.policy_selector_digest
    FROM iam.membership_role_grants AS grant_row
    JOIN iam.memberships AS membership
      ON membership.id = grant_row.membership_id
     AND membership.organization_id = grant_row.organization_id
     AND membership.user_id = grant_row.user_id
    WHERE grant_row.user_id = %s::uuid
      AND grant_row.revoked_at IS NULL
      AND membership.status = 'ACTIVE'
), records AS (
    SELECT
        'user_role'::text AS record_kind,
        jsonb_build_object(
            'role_grant_id', grant_row.id::text,
            'user_id', grant_row.user_id::text,
            'role_code', grant_row.role_code,
            'source_invitation_id', grant_row.source_invitation_id::text,
            'policy_selector_digest', encode(grant_row.policy_selector_digest, 'hex'),
            'revoked_at', grant_row.revoked_at,
            'aggregate_version', grant_row.aggregate_version
        ) AS payload
    FROM iam.user_role_grants AS grant_row
    WHERE grant_row.user_id = %s::uuid

    UNION ALL

    SELECT
        'membership',
        jsonb_build_object(
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
                        'source_invitation_id', role_grant.source_invitation_id::text,
                        'policy_selector_digest', encode(role_grant.policy_selector_digest, 'hex'),
                        'revoked_at', role_grant.revoked_at,
                        'aggregate_version', role_grant.aggregate_version
                    ) ORDER BY role_grant.role_code, role_grant.id
                )
                FROM iam.membership_role_grants AS role_grant
                WHERE role_grant.membership_id = membership.id
                  AND role_grant.organization_id = membership.organization_id
                  AND role_grant.user_id = membership.user_id
            ), '[]'::jsonb)
        )
    FROM iam.memberships AS membership
    JOIN iam.organizations AS organization
      ON organization.id = membership.organization_id
    WHERE membership.user_id = %s::uuid

    UNION ALL

    SELECT
        'source_invitation',
        jsonb_build_object(
            'invitation_id', invitation.id::text,
            'purpose', invitation.purpose,
            'organization_id', invitation.organization_id::text,
            'target_scope', invitation.target_scope,
            'target_role', invitation.target_role,
            'is_initial_admin', invitation.is_initial_admin,
            'recipient_contact_id', invitation.recipient_contact_id::text,
            'masked_recipient_label', invitation.masked_recipient_label,
            'policy_selector_digest', encode(invitation.policy_selector_digest, 'hex'),
            'issued_policy_bundle_id', invitation.issued_policy_bundle_id::text,
            'status', invitation.status,
            'expires_at', invitation.expires_at,
            'accepted_by_user_id', invitation.accepted_by_user_id::text,
            'aggregate_version', invitation.aggregate_version,
            'created_at', invitation.created_at
        )
    FROM iam.access_invitations AS invitation
    WHERE invitation.accepted_by_user_id = %s::uuid

    UNION ALL

    SELECT
        'acceptance',
        jsonb_build_object(
            'user_id', acceptance.user_id::text,
            'document_id', acceptance.document_id::text,
            'content_sha256', encode(acceptance.content_sha256, 'hex'),
            'policy_bundle_id', acceptance.bundle_id::text
        )
    FROM iam.policy_acceptances AS acceptance
    WHERE acceptance.user_id = %s::uuid

    UNION ALL

    SELECT
        'policy',
        jsonb_build_object(
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
                            SELECT jsonb_agg(category.category ORDER BY category.position)
                            FROM iam.consent_offer_data_categories AS category
                            WHERE category.offer_id = offer.id
                        ), '[]'::jsonb),
                        'recipient_ref', offer.recipient_ref,
                        'recipient_label', offer.recipient_label,
                        'supporting_document_id', offer.document_id::text,
                        'supporting_document_sha256', encode(offer.document_content_sha256, 'hex'),
                        'expiry_rule', offer.expiry_rule,
                        'expiry_days', offer.expiry_days,
                        'not_after', offer.not_after,
                        'optional', offer.optional,
                        'canonical_offer_sha256', encode(offer.canonical_offer_sha256, 'hex')
                    ) ORDER BY offer.purpose, offer.id
                )
                FROM iam.consent_offers AS offer
                WHERE offer.bundle_id = bundle.id
            ), '[]'::jsonb)
        )
    FROM relevant_selectors AS relevant
    JOIN iam.policy_selectors AS selector
      ON selector.selector_digest = relevant.policy_selector_digest
    JOIN iam.policy_bundles AS bundle
      ON bundle.id = selector.current_bundle_id
     AND bundle.selector_digest = selector.selector_digest
)
SELECT record_kind, payload
FROM records
ORDER BY record_kind, payload::text
"""


READ_MY_CONSENT_GRANTS_PAGE_V1 = """
/* iam.read_my_consent_grants_page_v1 */
SELECT
    actor.id AS actor_user_id,
    actor.status AS actor_user_status,
    actor.display_handle AS actor_display_handle,
    actor.aggregate_version AS actor_user_version,
    current_session.id AS current_session_id,
    current_session.user_id AS current_session_user_id,
    current_session.family_id AS current_session_family_id,
    current_session.generation AS current_session_generation,
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
    family.aggregate_version AS current_family_version,
    grant_row.id AS grant_id,
    grant_row.user_id AS grant_user_id,
    grant_row.consent_offer_id,
    grant_row.consent_offer_version,
    grant_row.policy_bundle_id,
    grant_row.purpose AS grant_purpose,
    grant_row.scope_type AS grant_scope_type,
    grant_row.scope_id AS grant_scope_id,
    grant_row.recipient_ref AS grant_recipient_ref,
    grant_row.recipient_label AS grant_recipient_label,
    grant_row.document_id AS grant_document_id,
    grant_row.document_content_sha256 AS grant_document_sha256,
    grant_row.granted_at,
    grant_row.expires_at AS grant_expires_at,
    grant_row.status AS grant_status,
    grant_row.withdrawn_at AS grant_withdrawn_at,
    grant_row.aggregate_version AS grant_version,
    grant_row.created_at AS grant_created_at
FROM iam.users AS actor
JOIN iam.sessions AS current_session
  ON current_session.user_id = actor.id
JOIN iam.session_families AS family
  ON family.id = current_session.family_id
 AND family.user_id = actor.id
LEFT JOIN iam.consent_grants AS grant_row
  ON grant_row.user_id = actor.id
 AND grant_row.created_at <= %s::timestamptz
 AND (
      %s::timestamptz IS NULL
      OR (grant_row.created_at, grant_row.id) < (%s::timestamptz, %s::uuid)
 )
WHERE actor.id = %s::uuid
  AND current_session.id = %s::uuid
ORDER BY grant_row.created_at DESC NULLS LAST, grant_row.id DESC NULLS LAST
LIMIT %s
"""


READ_MY_CONSENT_GRANT_CHILDREN_V1 = """
/* iam.read_my_consent_grant_children_v1 */
SELECT
    grant_row.id AS grant_id,
    COALESCE(
        ARRAY(
            SELECT category.category
            FROM iam.consent_grant_data_categories AS category
            WHERE category.grant_id = grant_row.id
            ORDER BY category.position
        ),
        ARRAY[]::text[]
    ) AS categories,
    withdrawal.consent_grant_id AS withdrawal_grant_id,
    withdrawal.user_id AS withdrawal_user_id,
    withdrawal.withdrawn_at,
    withdrawal.reason_code AS withdrawal_reason_code
FROM iam.consent_grants AS grant_row
LEFT JOIN iam.consent_withdrawals AS withdrawal
  ON withdrawal.consent_grant_id = grant_row.id
WHERE grant_row.id = ANY(%s::uuid[])
ORDER BY grant_row.id
"""


READ_MY_SESSIONS_PAGE_V1 = """
/* iam.read_my_sessions_page_v1 */
SELECT
    actor.id AS actor_user_id,
    actor.status AS actor_user_status,
    actor.display_handle AS actor_display_handle,
    actor.aggregate_version AS actor_user_version,
    current_session.id AS current_session_id,
    current_session.user_id AS current_session_user_id,
    current_session.family_id AS current_session_family_id,
    current_session.generation AS current_session_generation,
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
    family.aggregate_version AS current_family_version,
    listed.id AS listed_session_id,
    listed.user_id AS listed_session_user_id,
    listed.family_id AS listed_session_family_id,
    listed.generation AS listed_session_generation,
    listed.created_at AS listed_session_created_at,
    listed.last_activity_at AS listed_session_last_activity_at,
    listed.idle_expires_at AS listed_session_idle_expires_at,
    listed.absolute_expires_at AS listed_session_absolute_expires_at,
    listed.device_label AS listed_session_device_label,
    listed.status AS listed_session_status,
    listed.aggregate_version AS listed_session_version
FROM iam.users AS actor
JOIN iam.sessions AS current_session
  ON current_session.user_id = actor.id
JOIN iam.session_families AS family
  ON family.id = current_session.family_id
 AND family.user_id = actor.id
LEFT JOIN iam.sessions AS listed
  ON listed.user_id = actor.id
 AND listed.created_at <= %s::timestamptz
 AND (
      %s::timestamptz IS NULL
      OR (listed.created_at, listed.id) < (%s::timestamptz, %s::uuid)
 )
WHERE actor.id = %s::uuid
  AND current_session.id = %s::uuid
ORDER BY listed.created_at DESC NULLS LAST, listed.id DESC NULLS LAST
LIMIT %s
"""


READ_ORGANIZATION_ACTOR_AUTHORITY_V1 = """
/* iam.read_organization_actor_authority_v1 */
SELECT
    actor.id AS actor_user_id,
    actor.status AS actor_user_status,
    actor.display_handle AS actor_display_handle,
    actor.aggregate_version AS actor_user_version,
    current_session.id AS current_session_id,
    current_session.user_id AS current_session_user_id,
    current_session.family_id AS current_session_family_id,
    current_session.generation AS current_session_generation,
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
    family.aggregate_version AS current_family_version,
    organization.id AS organization_id,
    organization.public_name AS organization_public_name,
    organization.organization_type,
    organization.jurisdiction AS organization_jurisdiction,
    organization.status AS organization_status,
    organization.aggregate_version AS organization_version,
    membership.id AS actor_membership_id,
    membership.organization_id AS actor_membership_organization_id,
    membership.user_id AS actor_membership_user_id,
    membership.status AS actor_membership_status,
    membership.source_invitation_id AS actor_membership_source_invitation_id,
    membership.aggregate_version AS actor_membership_version,
    membership.created_at AS actor_membership_created_at,
    role_grant.id AS actor_role_grant_id,
    role_grant.role_code AS actor_role_code,
    role_grant.source_invitation_id AS actor_role_source_invitation_id,
    role_grant.policy_selector_digest AS actor_role_selector_digest,
    role_grant.revoked_at AS actor_role_revoked_at,
    role_grant.aggregate_version AS actor_role_version
FROM iam.users AS actor
JOIN iam.sessions AS current_session
  ON current_session.user_id = actor.id
JOIN iam.session_families AS family
  ON family.id = current_session.family_id
 AND family.user_id = actor.id
LEFT JOIN iam.organizations AS organization
  ON organization.id = %s::uuid
LEFT JOIN iam.memberships AS membership
  ON membership.organization_id = organization.id
 AND membership.user_id = actor.id
LEFT JOIN iam.membership_role_grants AS role_grant
  ON role_grant.organization_id = membership.organization_id
 AND role_grant.membership_id = membership.id
 AND role_grant.user_id = membership.user_id
WHERE actor.id = %s::uuid
  AND current_session.id = %s::uuid
ORDER BY role_grant.role_code, role_grant.id
"""


READ_ORGANIZATION_SUMMARY_V1 = READ_ORGANIZATION_ACTOR_AUTHORITY_V1.replace(
    "iam.read_organization_actor_authority_v1",
    "iam.read_organization_summary_v1",
)


READ_ORGANIZATION_INVITATIONS_PAGE_V1 = """
/* iam.read_organization_invitations_page_v1 */
SELECT
    invitation.id AS invitation_id,
    invitation.purpose AS invitation_purpose,
    invitation.organization_id AS invitation_organization_id,
    invitation.target_scope AS invitation_target_scope,
    invitation.target_role AS invitation_target_role,
    invitation.is_initial_admin AS invitation_is_initial_admin,
    invitation.recipient_contact_id AS invitation_recipient_contact_id,
    invitation.masked_recipient_label AS invitation_masked_recipient_label,
    invitation.policy_selector_digest AS invitation_selector_digest,
    invitation.issued_policy_bundle_id AS invitation_issued_bundle_id,
    invitation.status AS invitation_status,
    invitation.expires_at AS invitation_expires_at,
    invitation.accepted_by_user_id AS invitation_accepted_by_user_id,
    invitation.aggregate_version AS invitation_version,
    invitation.created_at AS invitation_created_at,
    selector.selector_digest AS selector_digest,
    selector.canonicalization_version AS selector_canonicalization_version,
    selector.access_purpose AS selector_access_purpose,
    selector.scope_type AS selector_scope_type,
    selector.target_role AS selector_target_role,
    selector.jurisdiction AS selector_jurisdiction,
    selector.locale AS selector_locale,
    selector.current_bundle_id AS selector_current_bundle_id,
    bundle.id AS bundle_id,
    bundle.selector_digest AS bundle_selector_digest,
    bundle.status AS bundle_status,
    bundle.effective_at AS bundle_effective_at,
    bundle.effective_until AS bundle_effective_until,
    bundle.aggregate_version AS bundle_version,
    membership.document_id AS document_id,
    membership.position AS document_position,
    membership.required AS document_required,
    document.kind AS document_kind,
    document.locale AS document_locale,
    document.semantic_version AS document_semantic_version,
    document.canonical_body AS document_canonical_body,
    document.content_sha256 AS document_content_sha256,
    document.legal_effect AS document_legal_effect,
    document.jurisdiction AS document_jurisdiction,
    document.status AS document_status,
    offer.id AS offer_id,
    offer.offer_version AS offer_version,
    offer.purpose AS offer_purpose,
    offer.scope_type AS offer_scope_type,
    offer.scope_derivation AS offer_scope_derivation,
    offer.recipient_ref AS offer_recipient_ref,
    offer.recipient_label AS offer_recipient_label,
    offer.document_id AS offer_document_id,
    offer.document_content_sha256 AS offer_document_sha256,
    offer.expiry_rule AS offer_expiry_rule,
    offer.expiry_days AS offer_expiry_days,
    offer.not_after AS offer_not_after,
    offer.optional AS offer_optional,
    offer.canonical_offer_sha256 AS offer_canonical_sha256,
    COALESCE(
        ARRAY(
            SELECT category.category
            FROM iam.consent_offer_data_categories AS category
            WHERE category.offer_id = offer.id
            ORDER BY category.position
        ),
        ARRAY[]::text[]
    ) AS offer_categories
FROM iam.access_invitations AS invitation
LEFT JOIN iam.policy_selectors AS selector
  ON selector.selector_digest = invitation.policy_selector_digest
LEFT JOIN iam.policy_bundles AS bundle
  ON bundle.id = invitation.issued_policy_bundle_id
 AND bundle.selector_digest = invitation.policy_selector_digest
LEFT JOIN iam.policy_bundle_documents AS membership
  ON membership.bundle_id = bundle.id
LEFT JOIN iam.policy_documents AS document
  ON document.id = membership.document_id
LEFT JOIN iam.consent_offers AS offer
  ON offer.bundle_id = bundle.id
WHERE invitation.organization_id = %s::uuid
  AND invitation.created_at <= %s::timestamptz
  AND (
      %s::timestamptz IS NULL
      OR (invitation.created_at, invitation.id) < (%s::timestamptz, %s::uuid)
  )
  AND invitation.id IN (
      SELECT page_root.id
      FROM iam.access_invitations AS page_root
      WHERE page_root.organization_id = %s::uuid
        AND page_root.created_at <= %s::timestamptz
        AND (
            %s::timestamptz IS NULL
            OR (page_root.created_at, page_root.id) < (%s::timestamptz, %s::uuid)
        )
      ORDER BY page_root.created_at DESC, page_root.id DESC
      LIMIT %s
  )
ORDER BY invitation.created_at DESC, invitation.id DESC,
         membership.position, offer.purpose, offer.id
"""


READ_ORGANIZATION_MEMBERSHIPS_PAGE_V1 = """
/* iam.read_organization_memberships_page_v1 */
SELECT
    membership.id AS membership_id,
    membership.organization_id,
    membership.user_id,
    membership.status AS membership_status,
    membership.source_invitation_id,
    membership.aggregate_version AS membership_version,
    membership.created_at AS membership_created_at,
    target_user.id AS target_user_id,
    target_user.status AS target_user_status,
    target_user.display_handle AS target_display_handle,
    target_user.aggregate_version AS target_user_version,
    role_grant.id AS role_grant_id,
    role_grant.role_code,
    role_grant.source_invitation_id AS role_source_invitation_id,
    role_grant.policy_selector_digest AS role_selector_digest,
    role_grant.revoked_at AS role_revoked_at,
    role_grant.aggregate_version AS role_version
FROM iam.memberships AS membership
JOIN iam.users AS target_user
  ON target_user.id = membership.user_id
LEFT JOIN iam.membership_role_grants AS role_grant
  ON role_grant.organization_id = membership.organization_id
 AND role_grant.membership_id = membership.id
 AND role_grant.user_id = membership.user_id
WHERE membership.organization_id = %s::uuid
  AND membership.created_at <= %s::timestamptz
  AND (
      %s::timestamptz IS NULL
      OR (membership.created_at, membership.id) < (%s::timestamptz, %s::uuid)
  )
  AND membership.id IN (
      SELECT page_root.id
      FROM iam.memberships AS page_root
      WHERE page_root.organization_id = %s::uuid
        AND page_root.created_at <= %s::timestamptz
        AND (
            %s::timestamptz IS NULL
            OR (page_root.created_at, page_root.id) < (%s::timestamptz, %s::uuid)
        )
      ORDER BY page_root.created_at DESC, page_root.id DESC
      LIMIT %s
  )
ORDER BY membership.created_at DESC, membership.id DESC,
         role_grant.role_code, role_grant.id
"""


__all__ = [name for name in globals() if name.startswith("READ_")]
