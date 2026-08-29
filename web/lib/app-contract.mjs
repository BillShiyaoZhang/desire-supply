export const PROFILE_EDITABLE_PATHS = Object.freeze([
  "/interests",
  "/skills",
  "/availability",
  "/collaboration",
  "/compensation",
  "/boundaries",
  "/location",
  "/conflicts",
  "/ai",
]);

export const PROFILE_PAUSE_REASON_CODES = Object.freeze([
  "OWNER_REQUEST",
  "TEMPORARY_UNAVAILABILITY",
  "SAFETY_REVIEW",
]);

export const PROFILE_ARCHIVE_REASON_CODES = Object.freeze([
  "OWNER_REQUEST",
  "ACCOUNT_CLOSURE",
  "SAFETY_REVIEW",
]);

export const DEMAND_OWNER_CANCEL_REASON_CODES = Object.freeze([
  "OWNER_WITHDREW",
  "REQUIREMENTS_CHANGED",
  "REVIEW_CLOSED",
  "FUNDING_UNAVAILABLE",
  "SAFETY_RESTRICTION",
]);

export const DEMAND_EDITABLE_PATHS = Object.freeze([
  "/problem",
  "/scope",
  "/acceptance",
  "/skills",
  "/matching",
  "/schedule",
  "/budget",
  "/milestone_plan",
  "/risk",
  "/ai",
  "/collaboration",
  "/location",
  "/declarations",
]);

const RESOURCE_KEYS = new Set([
  "resource_type",
  "object_id",
  "status",
  "revision",
  "etag",
  "capabilities",
  "editable_paths",
  "current_version",
  "versions",
  "submissions",
  "findings",
  "review_assignment",
]);
const VERSION_KEYS = new Set([
  "version_id",
  "version_no",
  "based_on_version_id",
  "status",
  "content",
  "content_sha256",
  "taxonomy_bundle_id",
  "created_at",
]);
const CURRENT_ACCOUNT_TASK_DISCOVERY_KEYS = new Set(["schema_version", "items", "has_more"]);
const CURRENT_ACCOUNT_TASK_KEYS = new Set([
  "classification", "resource_kind", "resource_id", "source_status",
  "next_action", "resource_path", "updated_at", "due_at",
]);
export const CURRENT_ACCOUNT_TASK_CLASSIFICATIONS = Object.freeze([
  "NEEDS_ACTION", "WAITING", "COMPLETED",
]);
export const CURRENT_ACCOUNT_TASK_RESOURCE_KINDS = Object.freeze([
  "APPEAL", "APPEAL_REVIEW", "CREATOR_PROFILE", "DEMAND", "DEMAND_REVIEW",
  "FINANCE_FUNDING_REVIEW", "TRUST_CASE", "TRUST_HOLD_RELEASE", "TRUST_REPORT",
]);
export const CURRENT_ACCOUNT_TASK_NEXT_ACTIONS = Object.freeze([
  "CLAIM_APPEAL_REVIEW",
  "CLAIM_DEMAND_REVIEW",
  "CLAIM_FINANCE_REVIEW",
  "CLAIM_TRUST_CASE",
  "CLAIM_TRUST_HOLD_RELEASE",
  "CONTINUE_FINANCE_REVIEW",
  "EDIT_APPEAL",
  "EDIT_OR_SUBMIT_DEMAND",
  "REVIEW_ASSIGNED_APPEAL",
  "REVIEW_ASSIGNED_DEMAND",
  "REVIEW_ASSIGNED_TRUST_CASE",
  "REVIEW_ASSIGNED_TRUST_HOLD_RELEASE",
  "VIEW_APPEAL_HISTORY",
  "VIEW_APPEAL_REVIEW_HISTORY",
  "VIEW_CREATOR_PROFILE",
  "VIEW_DEMAND_HISTORY",
  "VIEW_DEMAND_REVIEW_HISTORY",
  "VIEW_TRUST_CASE_HISTORY",
  "VIEW_TRUST_REPORT_HISTORY",
  "WAIT_FOR_APPEAL_REVIEW",
  "WAIT_FOR_DEMAND_PROCESSING",
  "WAIT_FOR_FINANCE_CONFIRMATION",
  "WAIT_FOR_TRUST_REVIEW",
]);
const CURRENT_ACCOUNT_TASK_CLASSIFICATION_ORDER = Object.freeze({
  NEEDS_ACTION: 0,
  WAITING: 1,
  COMPLETED: 2,
});
const CURRENT_ACCOUNT_DEMAND_STATUSES = Object.freeze([
  "CANCELLED", "DRAFT", "EXPIRED", "FUNDED", "FUNDING_PENDING", "MATCHED",
  "MATCHING", "NEEDS_CHANGES", "NO_MATCH", "SUBMITTED", "VERIFIED",
]);
const CURRENT_ACCOUNT_FINANCE_STATUSES = Object.freeze([
  "PENDING", "SECURED", "DISCREPANCY", "REJECTED",
]);
const taskStates = (...values) => new Set(values);
const CURRENT_ACCOUNT_TASK_RULES = new Map([
  ["APPEAL:EDIT_APPEAL", ["APPEAL_DETAIL", taskStates("NEEDS_ACTION:DRAFT")]],
  ["APPEAL:VIEW_APPEAL_HISTORY", ["APPEAL_DETAIL", taskStates("COMPLETED:DECIDED", "COMPLETED:WITHDRAWN")]],
  ["APPEAL:WAIT_FOR_APPEAL_REVIEW", ["APPEAL_DETAIL", taskStates("WAITING:SUBMITTED", "WAITING:IN_REVIEW")]],
  ["APPEAL_REVIEW:CLAIM_APPEAL_REVIEW", ["APPEAL_REVIEW_QUEUE", taskStates("NEEDS_ACTION:AVAILABLE")]],
  ["APPEAL_REVIEW:REVIEW_ASSIGNED_APPEAL", ["APPEAL_REVIEW_DETAIL", taskStates("NEEDS_ACTION:ASSIGNED")]],
  ["APPEAL_REVIEW:VIEW_APPEAL_REVIEW_HISTORY", ["APPEAL_REVIEW_HISTORY", taskStates(
    "COMPLETED:AFFIRM", "COMPLETED:DISMISS", "COMPLETED:MODIFY", "COMPLETED:VACATE_AND_REMAND",
  )]],
  ["CREATOR_PROFILE:VIEW_CREATOR_PROFILE", ["PROFILE_DETAIL", taskStates(
    "NEEDS_ACTION:DRAFT", "WAITING:ACTIVE", "WAITING:PAUSED", "COMPLETED:ARCHIVED",
  )]],
  ["DEMAND:EDIT_OR_SUBMIT_DEMAND", ["DEMAND_DETAIL", taskStates("NEEDS_ACTION:DRAFT", "NEEDS_ACTION:NEEDS_CHANGES", "NEEDS_ACTION:NO_MATCH")]],
  ["DEMAND:VIEW_DEMAND_HISTORY", ["DEMAND_DETAIL", taskStates("COMPLETED:MATCHED", "COMPLETED:CANCELLED", "COMPLETED:EXPIRED")]],
  ["DEMAND:WAIT_FOR_DEMAND_PROCESSING", ["DEMAND_DETAIL", taskStates(
    "WAITING:SUBMITTED", "WAITING:VERIFIED", "WAITING:FUNDING_PENDING", "WAITING:FUNDED", "WAITING:MATCHING",
  )]],
  ["DEMAND_REVIEW:CLAIM_DEMAND_REVIEW", ["DEMAND_REVIEW_QUEUE", taskStates("NEEDS_ACTION:AVAILABLE")]],
  ["DEMAND_REVIEW:VIEW_DEMAND_REVIEW_HISTORY", ["DEMAND_REVIEW_HISTORY", taskStates(
    "COMPLETED:NEEDS_CHANGES", "COMPLETED:VERIFIED",
  )]],
  ["DEMAND_REVIEW:REVIEW_ASSIGNED_DEMAND", ["DEMAND_DETAIL", taskStates(
    ...CURRENT_ACCOUNT_DEMAND_STATUSES.map((status) => `NEEDS_ACTION:${status}`),
  )]],
  ["DEMAND_REVIEW:WAIT_FOR_DEMAND_PROCESSING", ["DEMAND_DETAIL", taskStates(
    ...CURRENT_ACCOUNT_DEMAND_STATUSES.map((status) => `WAITING:${status}`),
  )]],
  ["FINANCE_FUNDING_REVIEW:CLAIM_FINANCE_REVIEW", ["FINANCE_QUEUE", taskStates("NEEDS_ACTION:AVAILABLE", "NEEDS_ACTION:PENDING")]],
  ["FINANCE_FUNDING_REVIEW:CONTINUE_FINANCE_REVIEW", ["FINANCE_DETAIL", taskStates("NEEDS_ACTION:PENDING")]],
  ["FINANCE_FUNDING_REVIEW:WAIT_FOR_FINANCE_CONFIRMATION", ["FINANCE_DETAIL", taskStates(
    ...CURRENT_ACCOUNT_FINANCE_STATUSES.map((status) => `WAITING:${status}`),
  )]],
  ["TRUST_CASE:CLAIM_TRUST_CASE", ["TRUST_QUEUE", taskStates("NEEDS_ACTION:AVAILABLE")]],
  ["TRUST_CASE:REVIEW_ASSIGNED_TRUST_CASE", ["TRUST_CASE_DETAIL", taskStates("NEEDS_ACTION:ASSIGNED")]],
  ["TRUST_CASE:VIEW_TRUST_CASE_HISTORY", ["TRUST_HISTORY", taskStates(
    "COMPLETED:NO_ACTION", "COMPLETED:PROTECTION_LIFTED",
    "COMPLETED:PROTECTION_MAINTAINED", "COMPLETED:PROTECTION_MODIFIED",
    "COMPLETED:REMEDIATION_REQUIRED",
  )]],
  ["TRUST_HOLD_RELEASE:CLAIM_TRUST_HOLD_RELEASE", ["TRUST_HOLD_QUEUE", taskStates("NEEDS_ACTION:AVAILABLE")]],
  ["TRUST_HOLD_RELEASE:REVIEW_ASSIGNED_TRUST_HOLD_RELEASE", ["TRUST_ASSIGNED_HOLD", taskStates("NEEDS_ACTION:ASSIGNED")]],
  ["TRUST_REPORT:VIEW_TRUST_REPORT_HISTORY", ["TRUST_REPORT_DETAIL", taskStates("COMPLETED:DECIDED")]],
  ["TRUST_REPORT:WAIT_FOR_TRUST_REVIEW", ["TRUST_REPORT_DETAIL", taskStates("WAITING:OPEN", "WAITING:TRIAGING", "WAITING:IN_REVIEW")]],
]);
const SUBMISSION_KEYS = new Set([
  "submission_id", "version_id", "submission_no", "content_sha256", "submitted_at",
]);
const FINDING_KEYS = new Set([
  "finding_id", "version_id", "assignment_id", "result", "reason_codes", "required_field_paths", "reviewed_at",
]);
const REVIEW_ASSIGNMENT_KEYS = new Set(["assignment_id", "status", "expires_at"]);
const REVIEW_QUEUE_ITEM_KEYS = new Set([
  "demand_id", "demand_revision", "demand_version_no", "submitted_at",
  "demand_expires_at", "etag",
]);
const REVIEW_HISTORY_PAGE_KEYS = new Set([
  "schema_version", "items", "next_cursor", "has_more",
]);
const REVIEW_HISTORY_ITEM_KEYS = new Set([
  "review_id", "demand_id", "demand_version_id", "decision", "reason_codes",
  "required_field_codes", "budget_health_code", "risk_code", "reviewed_at",
]);
const REVIEW_HISTORY_CURSOR = /^[A-Za-z0-9_-]{64,1024}\.[A-Za-z0-9_-]{43}$/;
const REVIEW_CLAIM_KEYS = new Set([
  "assignment_id", "demand_id", "demand_revision", "status", "expires_at",
  "etag", "replayed",
]);
const FINANCE_FUNDING_QUEUE_ITEM_KEYS = new Set([
  "demand_id", "demand_version_id", "demand_revision", "funding_review_id",
  "review_status", "review_revision", "assigned_to_me", "confirmation_count",
  "required_confirmations", "expires_at", "etag",
]);
const FINANCE_FUNDING_HISTORY_PAGE_KEYS = new Set([
  "schema_version", "items", "next_cursor", "has_more",
]);
const FINANCE_FUNDING_HISTORY_ITEM_KEYS = new Set([
  "funding_review_id", "demand_id", "demand_version_id", "status", "completed_at",
]);
const FINANCE_FUNDING_REVIEW_KEYS = new Set([
  "funding_review_id", "demand_id", "demand_version_id", "status", "revision",
  "assignment_id", "assignment_expires_at", "target_sha256",
  "target_content_sha256", "planned_budget_currency",
  "planned_budget_minimum_amount_minor", "planned_budget_maximum_amount_minor",
  "planned_budget_direct_cost_amount_minor", "evidence_kind",
  "evidence_reference_sha256", "sandbox_funds_amount_minor", "synthetic",
  "provider_code", "payment_operation_code", "legal_effect", "confirmation_count",
  "required_confirmations", "assignment_status", "confirmation_by_me",
  "available_actions", "can_confirm", "etag", "replayed",
]);
const EDITOR_CONFIGURATION_KEYS = new Set([
  "schema_version", "deployment_mode", "taxonomy_bundle", "editor_choices",
]);
const TAXONOMY_CONFIGURATION_KEYS = new Set([
  "bundle_id", "status", "effective_at", "effective_until",
]);
const EDITOR_CHOICES_KEYS = new Set(["schema_version", "locale", "fields"]);
const EDITOR_CHOICE_FIELD_KEYS = new Set([
  "resource_type", "path_template", "value_contract", "intended_node_kind",
  "status", "reason_code", "options",
]);
const EDITOR_CHOICE_OPTION_KEYS = new Set(["value", "label", "source"]);
const EDITOR_CHOICE_RESOURCE_TYPES = new Set(["CREATOR_PROFILE", "DEMAND"]);
const EDITOR_CHOICE_VALUE_CONTRACTS = new Set([
  "TAXONOMY_CODE", "REGION_CODE", "LANGUAGE_TAG", "CURRENCY_CODE", "CONTENT_ENUM",
]);
const TAXONOMY_NODE_KINDS = new Set([
  "DOMAIN", "PROBLEM_TYPE", "TASK", "SKILL", "SKILL_LEVEL",
  "TARGET_USER_CATEGORY", "WORK_MODE", "FEEDBACK_CADENCE", "TEAM_PREFERENCE",
  "REGION", "LANGUAGE", "DATA_SENSITIVITY", "AI_USE", "RISK",
  "DELIVERY_KIND", "REVIEW_REASON",
]);
const EDITOR_CHOICE_SOURCES = new Set([
  "TAXONOMY_BUNDLE_NODE", "INTERNAL_SANDBOX_POLICY", "INTERNAL_SANDBOX_PRESET",
]);
const EDITOR_CHOICE_SOURCE_CONTRACTS = Object.freeze({
  TAXONOMY_BUNDLE_NODE: new Set(["TAXONOMY_CODE"]),
  INTERNAL_SANDBOX_POLICY: new Set(["TAXONOMY_CODE", "CURRENCY_CODE", "CONTENT_ENUM"]),
  INTERNAL_SANDBOX_PRESET: new Set(["REGION_CODE", "LANGUAGE_TAG"]),
});
const EDITOR_CHOICE_PATH = /^\/(?:[a-z][a-z0-9_]*|\*)(?:\/(?:[a-z][a-z0-9_]*|\*))*$/;
const TAXONOMY_CODE = /^[A-Z][A-Z0-9_.:-]{1,63}$/;
const REGION_CODE = /^[A-Z0-9][A-Z0-9-]{1,31}$/;
const LANGUAGE_TAG = /^[A-Za-z]{2,3}(?:-[A-Za-z0-9]{2,8})*$/;
const CURRENCY_CODE = /^[A-Z]{3}$/;
const CONTENT_ENUM = /^[A-Z][A-Z0-9_]{1,63}$/;
const EDITOR_CHOICE_BINDINGS = Object.freeze([
  ["CREATOR_PROFILE", "/ai/prohibited_case_codes/*", "TAXONOMY_CODE", null, "UNAVAILABLE", null, null],
  ["CREATOR_PROFILE", "/boundaries/prohibited_domains/*/code", "TAXONOMY_CODE", "DOMAIN", "AVAILABLE", "TAXONOMY_BUNDLE_NODE", null],
  ["CREATOR_PROFILE", "/boundaries/prohibited_tasks/*/code", "TAXONOMY_CODE", "TASK", "AVAILABLE", "TAXONOMY_BUNDLE_NODE", null],
  ["CREATOR_PROFILE", "/collaboration/languages/*/language_code", "LANGUAGE_TAG", null, "AVAILABLE", "INTERNAL_SANDBOX_PRESET", ["zh-CN"]],
  ["CREATOR_PROFILE", "/compensation/currency", "CURRENCY_CODE", null, "AVAILABLE", "INTERNAL_SANDBOX_POLICY", ["CNY"]],
  ["CREATOR_PROFILE", "/interests/*/domain_code", "TAXONOMY_CODE", "DOMAIN", "AVAILABLE", "TAXONOMY_BUNDLE_NODE", null],
  ["CREATOR_PROFILE", "/interests/*/problem_code", "TAXONOMY_CODE", "PROBLEM_TYPE", "AVAILABLE", "TAXONOMY_BUNDLE_NODE", null],
  ["CREATOR_PROFILE", "/interests/*/task_code", "TAXONOMY_CODE", "TASK", "AVAILABLE", "TAXONOMY_BUNDLE_NODE", null],
  ["CREATOR_PROFILE", "/location/region_code", "REGION_CODE", null, "AVAILABLE", "INTERNAL_SANDBOX_PRESET", ["CN"]],
  ["CREATOR_PROFILE", "/skills/*/skill_code", "TAXONOMY_CODE", "SKILL", "AVAILABLE", "TAXONOMY_BUNDLE_NODE", null],
  ["DEMAND", "/budget/currency", "CURRENCY_CODE", null, "AVAILABLE", "INTERNAL_SANDBOX_POLICY", ["CNY"]],
  ["DEMAND", "/collaboration/languages/*", "LANGUAGE_TAG", null, "AVAILABLE", "INTERNAL_SANDBOX_PRESET", ["zh-CN"]],
  ["DEMAND", "/location/allowed_creator_region_codes/*", "REGION_CODE", null, "AVAILABLE", "INTERNAL_SANDBOX_PRESET", ["CN"]],
  ["DEMAND", "/location/demand_region_code", "REGION_CODE", null, "AVAILABLE", "INTERNAL_SANDBOX_PRESET", ["CN"]],
  ["DEMAND", "/matching/domain_codes/*", "TAXONOMY_CODE", "DOMAIN", "AVAILABLE", "TAXONOMY_BUNDLE_NODE", null],
  ["DEMAND", "/matching/problem_codes/*", "TAXONOMY_CODE", "PROBLEM_TYPE", "AVAILABLE", "TAXONOMY_BUNDLE_NODE", null],
  ["DEMAND", "/matching/task_codes/*", "TAXONOMY_CODE", "TASK", "AVAILABLE", "TAXONOMY_BUNDLE_NODE", null],
  ["DEMAND", "/problem/domain_code", "TAXONOMY_CODE", "DOMAIN", "AVAILABLE", "TAXONOMY_BUNDLE_NODE", null],
  ["DEMAND", "/problem/problem_type_codes/*", "TAXONOMY_CODE", "PROBLEM_TYPE", "AVAILABLE", "TAXONOMY_BUNDLE_NODE", null],
  ["DEMAND", "/problem/target_user_category_codes/*", "TAXONOMY_CODE", "TARGET_USER_CATEGORY", "AVAILABLE", "INTERNAL_SANDBOX_POLICY", ["SYNTHETIC_USER"]],
  ["DEMAND", "/risk/dependency_codes/*", "TAXONOMY_CODE", null, "UNAVAILABLE", null, null],
  ["DEMAND", "/skills/must_have/*/skill_code", "TAXONOMY_CODE", "SKILL", "AVAILABLE", "TAXONOMY_BUNDLE_NODE", null],
  ["DEMAND", "/skills/nice_to_have/*/skill_code", "TAXONOMY_CODE", "SKILL", "AVAILABLE", "TAXONOMY_BUNDLE_NODE", null],
]);
const POLICY_REQUIREMENT_KEYS = new Set([
  "selector_digest", "purpose", "role", "scope_type", "scope_id", "satisfied",
  "required_policy_bundle_id", "missing_document_ids",
]);
const POLICY_BUNDLE_KEYS = new Set([
  "policy_bundle_id", "purpose", "jurisdiction", "locale", "documents",
  "consent_offers", "effective_at", "entity_tag",
]);
const POLICY_DOCUMENT_KEYS = new Set([
  "document_id", "kind", "semantic_version", "locale", "content_sha256",
  "legal_effect", "body",
]);
const CONSENT_OFFER_KEYS = new Set([
  "consent_offer_id", "purpose", "scope_type", "data_categories", "document_id",
  "content_sha256", "recipient_label", "expiry_rule", "not_after",
  "canonical_offer_sha256", "optional",
]);
const POLICY_PURPOSES = new Set(["CREATOR_ENROLLMENT", "ORGANIZATION_MEMBERSHIP"]);
const POLICY_ROLES = new Set(["CREATOR", "ORG_ADMIN", "DEMAND_OWNER"]);
const POLICY_KINDS = new Set(["TERMS", "PRIVACY_NOTICE", "COMMUNITY_TRANSACTION_COVENANT", "CONSENT_TEXT"]);
const POLICY_LEGAL_EFFECTS = new Set(["NOTICE_ACKNOWLEDGEMENT", "CONTRACT_ACCEPTANCE", "CONSENT_TEXT"]);
const ORGANIZATION_TYPES = new Set(["BUSINESS", "NONPROFIT", "COMMUNITY", "CREATOR_TEAM"]);
const ORGANIZATION_STATUSES = new Set(["PENDING_ADMIN", "ACTIVE", "SUSPENDED", "CLOSED"]);
const MEMBERSHIP_STATUSES = new Set(["ACTIVE", "SUSPENDED", "REVOKED"]);
const ORGANIZATION_ROLES = new Set(["ORG_ADMIN", "DEMAND_OWNER"]);
const INVITATION_STATUSES = new Set(["ISSUED", "ACCEPTED", "REVOKED", "EXPIRED"]);
const INVITATION_PURPOSES = new Set(["CREATOR_ENROLLMENT", "ORGANIZATION_MEMBERSHIP"]);
const ORGANIZATION_SUMMARY_KEYS = new Set([
  "organization_id", "public_name", "type", "status", "aggregate_version", "entity_tag",
]);
const ACCESS_INVITATION_ADMIN_KEYS = new Set([
  "invitation_id", "purpose", "organization_id", "target_role", "masked_recipient_label",
  "is_initial_admin", "status", "expires_at", "created_at", "required_policy_bundle_id",
  "aggregate_version", "entity_tag",
]);
const ACCESS_INVITATION_PREVIEW_KEYS = new Set([
  "invitation_id", "purpose", "organization", "target_role", "expires_at",
  "required_policy_bundle_id", "status", "aggregate_version", "entity_tag",
]);
const MEMBERSHIP_ADMIN_KEYS = new Set([
  "membership_id", "organization_id", "user_id", "display_handle", "status", "roles",
  "aggregate_version", "entity_tag",
]);
const CONSENT_PURPOSES = new Set(["PILOT_RESEARCH", "AI_ASSISTED_PROCESSING", "DISCLOSE_PROFILE_FIELDS_TO_PARTY"]);
const CONSENT_SCOPE_TYPES = new Set(["PLATFORM_PARTICIPATION", "ORGANIZATION", "PROJECT", "RECIPIENT_DISCLOSURE"]);
const CONSENT_DATA_CATEGORIES = new Set(["PROFILE", "MATCHING", "RESEARCH", "AI_INPUT", "CONTACT", "PROJECT"]);
export const REVIEW_REASON_CODES = Object.freeze([
  "CONTENT_INCOMPLETE", "SCOPE_UNCLEAR", "ACCEPTANCE_UNCLEAR",
  "BUDGET_UNHEALTHY", "RISK_UNRESOLVED", "DATA_PLAN_REQUIRED",
]);
export const REVIEW_ASSIGNMENT_RELEASE_REASON_CODES = Object.freeze([
  "CONFLICT_DECLARED", "WORKLOAD_RELEASE",
]);
export const VERIFY_BUDGET_HEALTH_CODES = Object.freeze([
  "HEALTHY", "APPROVED_EXCEPTION",
]);
export const VERIFY_RISK_CODES = Object.freeze([
  "STANDARD", "ELEVATED_APPROVED",
]);
export const VERIFY_EVIDENCE_CODES = Object.freeze([
  "SCOPE_COMPLETE", "ACCEPTANCE_TESTABLE", "BUDGET_COHERENT",
  "RISK_HANDLED", "DECLARATIONS_CONFIRMED",
]);
export const FINANCE_FUNDING_ATTESTATION_CODES = Object.freeze([
  "SYNTHETIC_ONLY", "ZERO_REAL_FUNDS", "NO_PROVIDER_OR_PAYMENT",
  "TARGET_AND_EVIDENCE_MATCH",
]);
export const FINANCE_FUNDING_ACTIONS = Object.freeze([
  "CONFIRM", "RELEASE_ASSIGNMENT", "SUBMIT_FINDING",
]);
export const FINANCE_FUNDING_RELEASE_REASON_CODES = Object.freeze([
  "CONFLICT_DECLARED", "WORKLOAD_RELEASE",
]);
export const FINANCE_FUNDING_FINDING_FIELD_CODES = Object.freeze([
  "BUDGET", "DECLARATIONS", "RISK", "SCOPE",
]);
export const FINANCE_FUNDING_DISCREPANCY_REASON_CODES = Object.freeze([
  "EVIDENCE_REFERENCE_MISMATCH", "TARGET_CONTENT_MISMATCH",
]);
export const FINANCE_FUNDING_REJECTED_REASON_CODES = Object.freeze([
  "BUDGET_PLAN_UNACCEPTABLE", "DECLARATION_CONFLICT", "SYNTHETIC_SCOPE_VIOLATION",
]);
export const ACCOUNT_ADMIN_REASON_CODES = Object.freeze([
  "ACCESS_REVIEW", "SAFETY_REVIEW", "SESSION_HYGIENE",
]);
export const ACCOUNT_ADMIN_PLATFORM_DUTY_CODES = Object.freeze([
  "ACCESS_ADMIN", "APPEAL_REVIEWER", "FINANCE_OPERATOR",
  "OPERATIONS_REVIEWER", "TRUST_OFFICER",
]);
export const TRUST_REPORT_CATEGORIES = Object.freeze([
  "DATA_EXPOSURE", "FRAUD_RISK", "HARASSMENT", "RETALIATION", "WORKFLOW_INTEGRITY",
]);
export const TRUST_IMPACT_CODES = Object.freeze([
  "PARTICIPANT_SAFETY_RISK", "RETALIATION_RISK", "SYNTHETIC_DATA_DISCLOSED",
  "SYNTHETIC_FINANCIAL_RISK", "WORKFLOW_INTEGRITY_RISK",
]);
export const TRUST_PROTECTION_CODES = Object.freeze([
  "PAUSE_MATCHING", "PAUSE_SUBMISSION", "PAUSE_VERIFICATION",
]);
export const TRUST_INVESTIGATION_STEP_CODES = Object.freeze([
  "CHECK_ACCESS_SCOPE", "CHECK_DEMAND_VERSION", "CHECK_POLICY_REQUIREMENTS",
  "CHECK_SYNTHETIC_EVIDENCE", "REQUEST_PARTY_CLARIFICATION",
]);
export const TRUST_ISSUE_CODES = Object.freeze([
  "DATA_HANDLING_GAP", "FRAUD_INDICATOR", "HARASSMENT_INDICATOR",
  "RETALIATION_INDICATOR", "SCOPE_DISCLOSURE_RISK", "WORKFLOW_INTEGRITY_GAP",
]);
export const TRUST_DEMAND_ACTION_CODES = Object.freeze([
  "REQUEST_MATCHING", "SUBMIT_DEMAND", "VERIFY_DEMAND",
]);
export const TRUST_HOLD_REASON_CODES = Object.freeze([
  "PARTICIPANT_SAFETY_RISK", "RETALIATION_RISK", "SYNTHETIC_DATA_EXPOSURE_RISK",
  "WORKFLOW_INTEGRITY_RISK",
]);
export const TRUST_HOLD_RELEASE_REASON_CODES = Object.freeze([
  "CASE_DECIDED", "RISK_MITIGATED", "SUPERSEDED", "TTL_CORRECTION",
]);
export const TRUST_ASSIGNMENT_RELEASE_REASON_CODES = Object.freeze([
  "ASSIGNMENT_EXPIRED", "CONFLICT_DECLARED", "WORKLOAD_RELEASE",
]);
export const TRUST_OUTCOME_CODES = Object.freeze([
  "NO_ACTION", "PROTECTION_LIFTED", "PROTECTION_MAINTAINED",
  "PROTECTION_MODIFIED", "REMEDIATION_REQUIRED",
]);
export const TRUST_OUTCOME_REASON_CODES = Object.freeze([
  "INSUFFICIENT_VERIFIED_EVIDENCE", "NO_POLICY_BREACH", "POLICY_REQUIREMENT_NOT_MET",
  "PRECAUTIONARY_ACTION_REQUIRED", "RISK_MITIGATED",
]);
export const APPEAL_GROUNDS = Object.freeze([
  "NEW_MATERIAL_EVIDENCE", "PROCEDURAL_ERROR", "RULE_MISAPPLICATION",
]);
export const APPEAL_REQUESTED_OUTCOMES = Object.freeze([
  "MODIFY_MEASURE", "REMOVE_MEASURE", "VACATE_AND_REMAND",
]);
export const APPEAL_DECISION_CODES = Object.freeze([
  "AFFIRM", "DISMISS", "MODIFY", "VACATE_AND_REMAND",
]);
export const APPEAL_ASSESSMENT_CODES = Object.freeze([
  "ACCEPTED", "PARTIALLY_ACCEPTED", "REJECTED",
]);
export const APPEAL_FINDING_CODES = Object.freeze([
  "APPEAL_NOT_SUBSTANTIATED", "NEW_EVIDENCE_MATERIAL", "PROCEDURE_MATERIAL_ERROR",
  "RULE_APPLICATION_ERROR", "RULE_APPLIED_CORRECTLY",
]);
export const APPEAL_REASON_CODES = Object.freeze([
  "APPEAL_SCOPE_INVALID", "NEW_EVIDENCE_REVIEWED", "PROCEDURAL_REVIEW_COMPLETE",
  "REMAND_REQUIRED", "SOURCE_OUTCOME_SUPPORTED", "SOURCE_OUTCOME_UNSUPPORTED",
]);
export const APPEAL_REMEDY_DELTA_CODES = Object.freeze([
  "NARROW_CORRECTIVE_MEASURE", "NO_CHANGE", "REMOVE_CORRECTIVE_MEASURE",
  "REPLACE_CORRECTIVE_MEASURE", "RETURN_TO_TRUST_REVIEW",
]);
export const APPEAL_ASSIGNMENT_RELEASE_REASON_CODES = Object.freeze([
  "ASSIGNMENT_EXPIRED", "CONFLICT_DECLARED", "WORKLOAD_RELEASE",
]);
export const ORGANIZATION_ADMIN_REASON_CODES = Object.freeze([
  "ACCESS_REVIEW", "MEMBER_REQUEST", "SECURITY_REVIEW", "INVITATION_CANCELLED",
]);
export const ORGANIZATION_PUBLIC_NAME_REASON_CODE = "PUBLIC_NAME_CORRECTION";
const REVIEW_REASON_CODE_SET = new Set(REVIEW_REASON_CODES);
const REVIEW_ASSIGNMENT_RELEASE_REASON_CODE_SET = new Set(REVIEW_ASSIGNMENT_RELEASE_REASON_CODES);
const FINANCE_FUNDING_ACTION_SET = new Set(FINANCE_FUNDING_ACTIONS);
const FINANCE_FUNDING_RELEASE_REASON_CODE_SET = new Set(FINANCE_FUNDING_RELEASE_REASON_CODES);
const FINANCE_FUNDING_FINDING_FIELD_CODE_SET = new Set(FINANCE_FUNDING_FINDING_FIELD_CODES);
const FINANCE_FUNDING_DISCREPANCY_REASON_CODE_SET = new Set(FINANCE_FUNDING_DISCREPANCY_REASON_CODES);
const FINANCE_FUNDING_REJECTED_REASON_CODE_SET = new Set(FINANCE_FUNDING_REJECTED_REASON_CODES);
const VERIFY_BUDGET_HEALTH_CODE_SET = new Set(VERIFY_BUDGET_HEALTH_CODES);
const VERIFY_RISK_CODE_SET = new Set(VERIFY_RISK_CODES);
const VERIFY_EVIDENCE_CODE_SET = new Set(VERIFY_EVIDENCE_CODES);
const ACCOUNT_ADMIN_REASON_CODE_SET = new Set(ACCOUNT_ADMIN_REASON_CODES);
const ACCOUNT_ADMIN_PLATFORM_DUTY_CODE_SET = new Set(ACCOUNT_ADMIN_PLATFORM_DUTY_CODES);
const ORGANIZATION_ADMIN_REASON_CODE_SET = new Set(ORGANIZATION_ADMIN_REASON_CODES);
const TRUST_REPORT_CATEGORY_SET = new Set(TRUST_REPORT_CATEGORIES);
const TRUST_IMPACT_CODE_SET = new Set(TRUST_IMPACT_CODES);
const TRUST_PROTECTION_CODE_SET = new Set(TRUST_PROTECTION_CODES);
const TRUST_INVESTIGATION_STEP_CODE_SET = new Set(TRUST_INVESTIGATION_STEP_CODES);
const TRUST_ISSUE_CODE_SET = new Set(TRUST_ISSUE_CODES);
const TRUST_DEMAND_ACTION_CODE_SET = new Set(TRUST_DEMAND_ACTION_CODES);
const TRUST_HOLD_REASON_CODE_SET = new Set(TRUST_HOLD_REASON_CODES);
const TRUST_HOLD_RELEASE_REASON_CODE_SET = new Set(TRUST_HOLD_RELEASE_REASON_CODES);
const TRUST_ASSIGNMENT_RELEASE_REASON_CODE_SET = new Set(TRUST_ASSIGNMENT_RELEASE_REASON_CODES);
const TRUST_OUTCOME_CODE_SET = new Set(TRUST_OUTCOME_CODES);
const TRUST_OUTCOME_REASON_CODE_SET = new Set(TRUST_OUTCOME_REASON_CODES);
const APPEAL_GROUND_SET = new Set(APPEAL_GROUNDS);
const APPEAL_REQUESTED_OUTCOME_SET = new Set(APPEAL_REQUESTED_OUTCOMES);
const APPEAL_DECISION_CODE_SET = new Set(APPEAL_DECISION_CODES);
const APPEAL_ASSESSMENT_CODE_SET = new Set(APPEAL_ASSESSMENT_CODES);
const APPEAL_FINDING_CODE_SET = new Set(APPEAL_FINDING_CODES);
const APPEAL_REASON_CODE_SET = new Set(APPEAL_REASON_CODES);
const APPEAL_REMEDY_DELTA_CODE_SET = new Set(APPEAL_REMEDY_DELTA_CODES);
const APPEAL_ASSIGNMENT_RELEASE_REASON_CODE_SET = new Set(APPEAL_ASSIGNMENT_RELEASE_REASON_CODES);
const ACCOUNT_ADMIN_ROLE_CODES = new Set([
  "ACCESS_ADMIN", "APPEAL_REVIEWER", "CREATOR", "DEMAND_OWNER",
  "FINANCE_OPERATOR", "OPERATIONS_REVIEWER", "ORG_ADMIN", "TRUST_OFFICER",
]);
const ACCOUNT_ADMIN_KEYS = new Set([
  "account_code", "user_id", "display_handle", "status", "aggregate_version",
  "entity_tag", "role_codes", "active_session_count", "created_at", "updated_at",
  "is_self",
]);
const ACCOUNT_ADMIN_COMMAND_KEYS = new Set([
  "user_id", "display_handle", "status", "aggregate_version", "entity_tag",
  "revoked_session_count", "revoked_session_family_count", "replayed",
]);
const TRUST_REPORT_SUMMARY_KEYS = new Set([
  "category", "evidence_reference_ids", "impact_codes", "incident_ended_at",
  "incident_started_at", "requested_protection_codes",
]);
const TRUST_REPORT_PROJECTION_KEYS = new Set([
  "demand_id", "demand_version_id", "entity_tag", "outcome", "report", "report_id", "status",
  "submitted_at",
]);
const TRUST_OWN_REPORT_LIST_KEYS = new Set(["entity_tag", "items", "next_cursor"]);
const TRUST_OWN_REPORT_ITEM_KEYS = new Set([
  "category", "demand_id", "outcome", "report_id", "status", "submitted_at",
]);
const TRUST_OWN_REPORT_OUTCOME_KEYS = new Set([
  "appeal_deadline", "appeal_eligibility_code", "decided_at", "outcome_code",
  "outcome_version_id",
]);
const TRUST_OWN_REPORT_CURSOR = /^[A-Za-z0-9_-]{64,1024}\.[A-Za-z0-9_-]{43}$/;
const TRUST_QUEUE_ITEM_KEYS = new Set([
  "category", "case_id", "demand_id", "demand_version_id", "entity_tag", "impact_codes",
  "report_id", "submitted_at",
]);
const TRUST_HOLD_RELEASE_QUEUE_ITEM_KEYS = new Set([
  "action_codes", "case_id", "demand_id", "demand_version_id", "entity_tag", "expires_at",
  "hold_id", "reason_code",
]);
const TRUST_ASSIGNMENT_ITEM_KEYS = new Set([
  "assignment_expires_at", "assignment_purpose", "case_id", "hold_id",
]);
const TRUST_CASE_HISTORY_ITEM_KEYS = new Set([
  "case_id", "decided_at", "outcome_code",
]);
const TRUST_ASSIGNED_HOLD_KEYS = new Set([
  "action_codes", "assignment_expires_at", "case_id", "case_status", "effective_at",
  "entity_tag", "expires_at", "hold_id", "hold_status", "reason_code",
]);
const TRUST_SAFE_TRIAGE_KEYS = new Set([
  "investigation_step_codes", "issue_codes", "jurisdiction_code", "priority_code",
  "proposed_hold_actions", "proposed_hold_ttl_minutes", "sealed_note_reference",
  "sealed_note_sha256", "severity_code",
]);
const TRUST_TRIAGE_DRAFT_KEYS = new Set([
  "content", "content_sha256", "saved_at", "triage_version",
]);
const TRUST_HOLD_KEYS = new Set([
  "action_codes", "effective_at", "entity_tag", "expires_at", "hold_id", "status",
]);
const TRUST_OUTCOME_KEYS = new Set([
  "action_codes", "appeal_deadline", "appeal_eligibility_code", "content_sha256", "decided_at",
  "evidence_packet_digest", "evidence_packet_version_id", "outcome_code", "outcome_version_id",
  "policy_version", "reason_codes", "redaction_profile_code", "source_digest",
]);
const TRUST_CASE_KEYS = new Set([
  "active_hold", "aggregate_version", "case_id", "demand_id", "demand_version_id", "entity_tag",
  "outcome", "report", "report_id", "status", "triage_draft",
]);
const TRUST_COMMAND_RESULT_KEYS = new Set([
  "aggregate_version", "case_id", "case_status", "completed_at", "event_types", "hold_id",
  "hold_version", "outcome_version_id", "replayed", "report_id", "triage_draft_version",
  "triage_version",
]);
const TRUST_COMMAND_EVENT_TYPES = new Set([
  "SafetyHoldPlaced", "SafetyHoldReleased", "TrustCaseAssignmentReleased", "TrustCaseClaimed",
  "TrustCaseOutcomePublished", "TrustHoldReleaseClaimed", "TrustReportSubmitted",
  "TrustTriageDraftSaved", "TrustTriagePublished",
]);
const APPEAL_SOURCE_KEYS = new Set([
  "action_codes", "appeal_deadline", "appeal_eligibility_code", "appeal_eligible",
  "case_id", "content_sha256", "decided_at", "demand_id", "demand_version_id",
  "evidence_packet_sha256", "evidence_packet_version_id", "outcome_code",
  "outcome_version_id", "policy_version", "reason_codes",
]);
const APPEAL_APPLICATION_DRAFT_KEYS = new Set([
  "edited_at", "grounds", "new_evidence_reference_ids", "requested_outcome",
  "statement_recorded", "version",
]);
const APPEAL_SUBMITTED_APPLICATION_KEYS = new Set([
  "grounds", "new_evidence_reference_ids", "requested_outcome", "statement_recorded",
  "submitted_at",
]);
const APPEAL_ASSESSMENT_KEYS = new Set([
  "accepted_evidence_reference_ids", "assessment_code", "finding_codes", "ground",
]);
const APPEAL_DECISION_KEYS = new Set([
  "assessments", "decided_at", "decision_code", "decision_sha256", "decision_version_id",
  "policy_version", "reason_codes", "remedy_delta_codes",
]);
const APPEAL_OWN_KEYS = new Set([
  "aggregate_version", "appeal_id", "application", "application_draft", "decision",
  "entity_tag", "source", "source_case_id", "source_outcome_version_id", "status",
]);
const APPEAL_QUEUE_ITEM_KEYS = new Set([
  "appeal_id", "entity_tag", "grounds", "requested_outcome", "source_case_id",
  "source_outcome_version_id", "submitted_at",
]);
const APPEAL_ASSIGNMENT_ITEM_KEYS = new Set([
  "appeal_id", "assignment_expires_at",
]);
const APPEAL_REVIEW_HISTORY_ITEM_KEYS = new Set([
  "appeal_id", "decided_at", "decision_code",
]);
const APPEAL_REVIEW_HISTORY_KEYS = new Set([
  "entity_tag", "has_more", "items",
]);
const APPEAL_REVIEW_TERMINAL_KEYS = new Set([
  "appeal_id", "application", "decision", "entity_tag", "review_note_recorded", "status",
]);
const APPEAL_REVIEW_DRAFT_KEYS = new Set([
  "assessments", "edited_at", "reason_codes", "remedy_delta_codes",
  "review_note_recorded", "version",
]);
const APPEAL_ASSIGNED_KEYS = new Set([
  "appeal", "application", "assignment_expires_at", "entity_tag", "review_draft", "source",
]);
const APPEAL_COMMAND_RESULT_KEYS = new Set([
  "aggregate_version", "appeal_id", "appeal_status", "application_draft_version",
  "application_version", "completed_at", "decision_version_id", "event_types", "replayed",
  "review_draft_version",
]);
const APPEAL_COMMAND_EVENT_TYPES = new Set([
  "AppealApplicationDraftSaved", "AppealDecisionPublished", "AppealOpened",
  "AppealReviewAssignmentReleased", "AppealReviewClaimed", "AppealReviewDraftSaved",
  "AppealSubmitted",
]);
const CAPABILITIES = new Set(["SAVE_DRAFT", "PUBLISH", "PAUSE", "RESUME", "ARCHIVE", "SUBMIT", "CANCEL", "RECORD_FINDINGS"]);
const PROFILE_PAUSE_REASON_CODE_SET = new Set(PROFILE_PAUSE_REASON_CODES);
const PROFILE_ARCHIVE_REASON_CODE_SET = new Set(PROFILE_ARCHIVE_REASON_CODES);
const DEMAND_OWNER_CANCEL_REASON_CODE_SET = new Set(DEMAND_OWNER_CANCEL_REASON_CODES);
const APP_ID = /^[A-Za-z0-9][A-Za-z0-9_-]{15,127}$/;
const CANONICAL_UUID = /^(?!0{8}-0{4}-0{4}-0{4}-0{12}$)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const IDEMPOTENCY_KEY = /^[A-Za-z0-9][A-Za-z0-9._~-]{15,127}$/;
const CSRF_TOKEN = /^[A-Za-z0-9_-]{32,512}$/;
const MATCHING_CSRF_TOKEN = /^[A-Za-z0-9_-]{32,256}$/;
const CAPABILITY_TOKEN = /^[A-Za-z0-9_-]{80,4096}$/;
const EMAIL_ADDRESS = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const WORKSPACE_ID = /^(org|personal|platform):([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$/;
const TRUST_ENTITY_TAG = /^"trust-[1-9][0-9]*-[a-f0-9]{24}"$/;
const APPEAL_ENTITY_TAG = /^"appeal-([1-9][0-9]*)-[a-f0-9]{24}"$/;
const APPEAL_OPEN_ROUTE = /^\/v1\/app\/appeals$/;
const APPEAL_APPLICANT_WRITE_ROUTE = /^\/v1\/app\/appeals\/((?!0{8}-0{4}-0{4}-0{4}-0{12})[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\/(draft|submit)$/;
const APPEAL_REVIEW_CLAIM_ROUTE = /^\/v1\/app\/appeal-review\/queue\/((?!0{8}-0{4}-0{4}-0{4}-0{12})[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\/claim$/;
const APPEAL_REVIEW_WRITE_ROUTE = /^\/v1\/app\/appeal-review\/appeals\/((?!0{8}-0{4}-0{4}-0{4}-0{12})[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\/(assignment\/release|review-draft|decide)$/;
const MATCHING_INVITATION_WRITE_ROUTE = /^\/v1\/me\/matching-invitations\/([A-Za-z0-9][A-Za-z0-9_-]{15,127})\/(accept|decline|withdraw)$/;
const MATCHING_SELECTION_WRITE_ROUTE = /^\/v1\/organizations\/([A-Za-z0-9][A-Za-z0-9_-]{15,127})\/selections\/([A-Za-z0-9][A-Za-z0-9_-]{15,127})\/(choose|close)$/;
const MATCHING_ASSIGNMENT_CLAIM_ROUTE = /^\/v1\/matching\/candidate-selector-assignments\/claim$/;
const MATCHING_REVIEW_CLAIM_ROUTE = /^\/v1\/app\/matching-review\/queue\/claim$/;
const MATCHING_REVIEW_RELEASE_ROUTE = /^\/v1\/app\/matching-review\/assignment\/release$/;
const MATCHING_REVIEW_CREATE_INVITATION_ROUTE = /^\/v1\/operations\/match-runs\/([A-Za-z0-9][A-Za-z0-9_-]{15,127})\/invitations$/;
const MATCHING_REVIEW_PUBLISH_INVITATION_ROUTE = /^\/v1\/operations\/matching-invitations\/([A-Za-z0-9][A-Za-z0-9_-]{15,127})\/publish$/;
const MATCHING_REVIEW_INVALIDATE_ATTEMPT_ROUTE = /^\/v1\/operations\/matching-attempts\/([A-Za-z0-9][A-Za-z0-9_-]{15,127})\/invalidate$/;
const TRUST_CASE_CLAIM_ROUTE = /^\/v1\/app\/trust\/queue\/((?!0{8}-0{4}-0{4}-0{4}-0{12})[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\/claim$/;
const TRUST_CASE_WRITE_ROUTE = /^\/v1\/app\/trust\/cases\/((?!0{8}-0{4}-0{4}-0{4}-0{12})[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\/(?:assignment\/release|triage-draft|triage-publish|holds|decisions)$/;
const TRUST_HOLD_WRITE_ROUTE = /^\/v1\/app\/trust\/(?:hold-release-queue|holds)\/((?!0{8}-0{4}-0{4}-0{4}-0{12})[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\/(?:claim|release)$/;
const REVIEW_CLAIM_ROUTE = /^\/v1\/app\/review-queue\/((?!0{8}-0{4}-0{4}-0{4}-0{12})[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\/claim$/;
const PROFILE_LIFECYCLE_ROUTE = /^\/v1\/app\/profiles\/([A-Za-z0-9][A-Za-z0-9_-]{15,127})\/(pause|resume|archive)$/;
const DEMAND_CANCEL_ROUTE = /^\/v1\/app\/demands\/([A-Za-z0-9][A-Za-z0-9_-]{15,127})\/cancel$/;
const REVIEW_FINDING_ROUTE = /^\/v1\/app\/demands\/([A-Za-z0-9][A-Za-z0-9_-]{15,127})\/review-assignments\/[A-Za-z0-9][A-Za-z0-9_-]{15,127}\/findings$/;
const REVIEW_RELEASE_ROUTE = /^\/v1\/app\/demands\/((?!0{8}-0{4}-0{4}-0{4}-0{12})[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\/review-assignments\/((?!0{8}-0{4}-0{4}-0{4}-0{12})[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\/release$/;
const REVIEW_VERIFY_ROUTE = /^\/v1\/app\/demands\/((?!0{8}-0{4}-0{4}-0{4}-0{12})[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\/review-assignments\/((?!0{8}-0{4}-0{4}-0{4}-0{12})[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\/verify$/;
const FINANCE_FUNDING_CLAIM_ROUTE = /^\/v1\/app\/finance\/funding-reviews\/((?!0{8}-0{4}-0{4}-0{4}-0{12})[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\/claim$/;
const FINANCE_FUNDING_CONFIRM_ROUTE = /^\/v1\/app\/finance\/funding-reviews\/((?!0{8}-0{4}-0{4}-0{4}-0{12})[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\/confirm$/;
const FINANCE_FUNDING_RELEASE_ROUTE = /^\/v1\/app\/finance\/funding-reviews\/((?!0{8}-0{4}-0{4}-0{4}-0{12})[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\/assignment\/release$/;
const FINANCE_FUNDING_FINDING_ROUTE = /^\/v1\/app\/finance\/funding-reviews\/((?!0{8}-0{4}-0{4}-0{4}-0{12})[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\/findings$/;
const ACCOUNT_ADMIN_ROUTE = /^\/v1\/app\/admin\/accounts\/((?!0{8}-0{4}-0{4}-0{4}-0{12})[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\/(?:suspend|resume|revoke-all-sessions)$/;
const ACCOUNT_DUTY_ROUTE = /^\/v1\/app\/admin\/accounts\/((?!0{8}-0{4}-0{4}-0{4}-0{12})[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\/platform-duties\/(ACCESS_ADMIN|APPEAL_REVIEWER|FINANCE_OPERATOR|OPERATIONS_REVIEWER|TRUST_OFFICER)\/(?:grant|revoke)$/;
const WORKSPACE_KEYS = new Set(["workspace_id", "workspace_kind", "role_codes"]);
const WORKSPACE_ROLES = Object.freeze({
  ORGANIZATION: new Set(["DEMAND_OWNER", "ORG_ADMIN"]),
  PERSONAL: new Set(["CREATOR"]),
  PLATFORM: new Set(["ACCESS_ADMIN", "APPEAL_REVIEWER", "FINANCE_OPERATOR", "OPERATIONS_REVIEWER", "TRUST_OFFICER"]),
});
const WORKSPACE_PREFIXES = Object.freeze({
  ORGANIZATION: "org",
  PERSONAL: "personal",
  PLATFORM: "platform",
});
const PENDING_MAX_AGE_MS = 24 * 60 * 60 * 1000;
const PENDING_MAX_BYTES = 256 * 1024;

function invalid(code = "INVALID_APP_CONTRACT") {
  throw new TypeError(code);
}

function object(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) invalid();
  return value;
}

function exactKeys(value, expected) {
  const keys = Object.keys(object(value));
  if (keys.length !== expected.size || keys.some((key) => !expected.has(key))) invalid();
  return value;
}

function text(value) {
  if (typeof value !== "string" || value.length === 0) invalid();
  return value;
}

function appId(value) {
  const result = text(value);
  if (!APP_ID.test(result)) invalid();
  return result;
}

function canonicalUuid(value) {
  const result = text(value);
  if (!CANONICAL_UUID.test(result)) invalid();
  return result;
}

function timestamp(value) {
  const result = text(value);
  if (!Number.isFinite(Date.parse(result))) invalid();
  return result;
}

function utcTimestamp(value) {
  const result = timestamp(value);
  if (!result.endsWith("Z") && !result.endsWith("+00:00")) invalid();
  return result;
}

function utcInstant(value) {
  const result = utcTimestamp(value);
  const match = result.match(/^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?(?:Z|\+00:00)$/);
  if (!match) invalid();
  const seconds = Date.parse(`${match[1]}Z`);
  if (!Number.isFinite(seconds) || new Date(seconds).toISOString().slice(0, 19) !== match[1]) invalid();
  return (BigInt(seconds) * 1_000_000n) + BigInt((match[2] ?? "").padEnd(9, "0") || "0");
}

function sha256(value) {
  const result = text(value);
  if (!/^[a-f0-9]{64}$/.test(result)) invalid();
  return result;
}

function stringArray(value, allowed) {
  if (!Array.isArray(value) || value.some((item) => typeof item !== "string" || !item)) invalid();
  if (new Set(value).size !== value.length) invalid();
  if (allowed && value.some((item) => !allowed.has(item))) invalid();
  return value;
}

function boundedCodes(value, allowed, minimum, maximum) {
  const result = stringArray(value, allowed);
  if (result.length < minimum || result.length > maximum) invalid();
  return result;
}

function trustEntityTag(value) {
  const result = text(value);
  if (!TRUST_ENTITY_TAG.test(result)) invalid();
  return result;
}

function appealEntityTag(value) {
  const result = text(value);
  if (!APPEAL_ENTITY_TAG.test(result)) invalid();
  return result;
}

function appealTimestamp(value) {
  const result = timestamp(value);
  if (!result.endsWith("Z")) invalid();
  return result;
}

function positiveVersionOrNull(value) {
  if (value !== null && (!Number.isSafeInteger(value) || value < 1)) invalid();
  return value;
}

function plainJson(value) {
  try {
    const encoded = JSON.stringify(value);
    if (encoded === undefined || encoded.length > PENDING_MAX_BYTES) invalid();
    return JSON.parse(encoded);
  } catch (error) {
    if (error instanceof TypeError && error.message === "INVALID_APP_CONTRACT") throw error;
    invalid();
  }
}

function parseVersion(value) {
  const result = exactKeys(value, VERSION_KEYS);
  appId(result.version_id);
  if (!Number.isInteger(result.version_no) || result.version_no < 1) invalid();
  if (result.based_on_version_id !== null) appId(result.based_on_version_id);
  text(result.status);
  object(result.content);
  sha256(result.content_sha256);
  appId(result.taxonomy_bundle_id);
  timestamp(result.created_at);
  return result;
}

function currentAccountTaskPath(pathKind, resourceId) {
  return ({
    APPEAL_DETAIL: `/v1/app/appeals/${resourceId}`,
    APPEAL_REVIEW_DETAIL: `/v1/app/appeal-review/appeals/${resourceId}`,
    APPEAL_REVIEW_HISTORY: "/v1/app/appeal-review/history",
    APPEAL_REVIEW_QUEUE: "/v1/app/appeal-review/queue",
    DEMAND_DETAIL: `/v1/app/demands/${resourceId}`,
    DEMAND_REVIEW_HISTORY: "/v1/app/review-history",
    DEMAND_REVIEW_QUEUE: "/v1/app/review-queue",
    FINANCE_DETAIL: `/v1/app/finance/funding-reviews/${resourceId}`,
    FINANCE_QUEUE: "/v1/app/finance/funding-reviews",
    PROFILE_DETAIL: `/v1/app/profiles/${resourceId}`,
    TRUST_ASSIGNED_HOLD: `/v1/app/trust/assigned-holds/${resourceId}`,
    TRUST_CASE_DETAIL: `/v1/app/trust/cases/${resourceId}`,
    TRUST_HISTORY: "/v1/app/trust/history",
    TRUST_HOLD_QUEUE: "/v1/app/trust/hold-release-queue",
    TRUST_QUEUE: "/v1/app/trust/queue",
    TRUST_REPORT_DETAIL: `/v1/app/trust/reports/${resourceId}`,
  })[pathKind] ?? invalid();
}

function parseCurrentAccountTask(value) {
  const result = exactKeys(value, CURRENT_ACCOUNT_TASK_KEYS);
  if (!CURRENT_ACCOUNT_TASK_CLASSIFICATIONS.includes(result.classification)) invalid();
  if (!CURRENT_ACCOUNT_TASK_RESOURCE_KINDS.includes(result.resource_kind)) invalid();
  canonicalUuid(result.resource_id);
  if (!CURRENT_ACCOUNT_TASK_NEXT_ACTIONS.includes(result.next_action)) invalid();
  const rule = CURRENT_ACCOUNT_TASK_RULES.get(`${result.resource_kind}:${result.next_action}`);
  if (
    !rule
    || !rule[1].has(`${result.classification}:${result.source_status}`)
    || result.resource_path !== currentAccountTaskPath(rule[0], result.resource_id)
  ) invalid();
  if (result.updated_at !== null) utcInstant(result.updated_at);
  if (result.due_at !== null) utcInstant(result.due_at);
  return result;
}

function compareCurrentAccountTasks(left, right) {
  const classification = CURRENT_ACCOUNT_TASK_CLASSIFICATION_ORDER[left.classification]
    - CURRENT_ACCOUNT_TASK_CLASSIFICATION_ORDER[right.classification];
  if (classification !== 0) return classification;
  const leftTime = left.updated_at ?? left.due_at;
  const rightTime = right.updated_at ?? right.due_at;
  if (leftTime !== null || rightTime !== null) {
    if (leftTime === null) return 1;
    if (rightTime === null) return -1;
    const leftInstant = utcInstant(leftTime);
    const rightInstant = utcInstant(rightTime);
    if (leftInstant > rightInstant) return -1;
    if (leftInstant < rightInstant) return 1;
  }
  if (left.resource_kind !== right.resource_kind) {
    return left.resource_kind < right.resource_kind ? -1 : 1;
  }
  return left.resource_id < right.resource_id ? -1 : left.resource_id > right.resource_id ? 1 : 0;
}

export function parseCurrentAccountTaskDiscovery(value) {
  const envelope = exactKeys(value, new Set(["data"]));
  const result = exactKeys(envelope.data, CURRENT_ACCOUNT_TASK_DISCOVERY_KEYS);
  if (result.schema_version !== "current-account-task-discovery-v1") invalid();
  if (!Array.isArray(result.items) || result.items.length > 2000) invalid();
  result.items.forEach(parseCurrentAccountTask);
  const identities = result.items.map((item) => `${item.resource_kind}:${item.resource_id}`);
  if (new Set(identities).size !== identities.length) invalid();
  const sorted = [...result.items].sort(compareCurrentAccountTasks);
  if (sorted.some((item, index) => item !== result.items[index])) invalid();
  if (typeof result.has_more !== "boolean") invalid();
  return result;
}

function parseSubmission(value) {
  const result = exactKeys(value, SUBMISSION_KEYS);
  appId(result.submission_id);
  appId(result.version_id);
  if (!Number.isInteger(result.submission_no) || result.submission_no < 1) invalid();
  sha256(result.content_sha256);
  timestamp(result.submitted_at);
  return result;
}

function parseFinding(value) {
  const result = exactKeys(value, FINDING_KEYS);
  appId(result.finding_id);
  appId(result.version_id);
  if (!new Set(["NEEDS_CHANGES", "VERIFIED", "DISCREPANCY", "REJECTED"]).has(result.result)) invalid();
  const financeFinding = new Set(["DISCREPANCY", "REJECTED"]).has(result.result);
  if (financeFinding) {
    if (result.assignment_id !== null) invalid();
  } else {
    appId(result.assignment_id);
  }
  const reasons = stringArray(result.reason_codes, result.result === "DISCREPANCY"
    ? FINANCE_FUNDING_DISCREPANCY_REASON_CODE_SET
    : result.result === "REJECTED"
      ? FINANCE_FUNDING_REJECTED_REASON_CODE_SET
      : REVIEW_REASON_CODE_SET);
  const financePaths = new Set(["/budget", "/declarations", "/risk", "/scope"]);
  const fields = stringArray(
    result.required_field_paths,
    financeFinding ? financePaths : new Set(DEMAND_EDITABLE_PATHS),
  );
  if (
    (result.result === "VERIFIED" && (reasons.length !== 0 || fields.length !== 0))
    || (result.result !== "VERIFIED" && (reasons.length === 0 || fields.length === 0))
  ) invalid();
  timestamp(result.reviewed_at);
  return result;
}

function parseReviewAssignment(value) {
  const result = exactKeys(value, REVIEW_ASSIGNMENT_KEYS);
  appId(result.assignment_id);
  if (result.status !== "ACTIVE") invalid();
  timestamp(result.expires_at);
  return result;
}

export function parseEditorResource(value) {
  const result = exactKeys(value, RESOURCE_KEYS);
  if (!new Set(["CREATOR_PROFILE", "DEMAND"]).has(result.resource_type)) invalid();
  appId(result.object_id);
  const statuses = result.resource_type === "CREATOR_PROFILE"
    ? new Set(["DRAFT", "ACTIVE", "PAUSED", "ARCHIVED"])
    : new Set(["DRAFT", "SUBMITTED", "NEEDS_CHANGES", "VERIFIED", "FUNDING_PENDING", "FUNDED", "MATCHING", "MATCHED", "NO_MATCH", "CANCELLED", "EXPIRED"]);
  if (!statuses.has(result.status)) invalid();
  if (!Number.isInteger(result.revision) || result.revision < 1) invalid();
  const etagType = result.resource_type.toLowerCase();
  const expectedEtag = new RegExp(`^"${etagType}-${result.revision}-[a-f0-9]{24}"$`);
  if (typeof result.etag !== "string" || !expectedEtag.test(result.etag)) invalid();
  stringArray(result.capabilities, CAPABILITIES);
  const allowedPaths = result.resource_type === "CREATOR_PROFILE"
    ? new Set(PROFILE_EDITABLE_PATHS)
    : new Set(DEMAND_EDITABLE_PATHS);
  stringArray(result.editable_paths, allowedPaths);
  if (result.current_version !== null) parseVersion(result.current_version);
  if (!Array.isArray(result.versions)) invalid();
  result.versions.forEach(parseVersion);
  if (result.current_version !== null && !result.versions.some((version) => version.version_id === result.current_version.version_id)) invalid();
  if (result.resource_type === "CREATOR_PROFILE") {
    const currentStatus = result.current_version?.status ?? null;
    const expectedCapabilities = result.status === "ARCHIVED"
      ? []
      : result.status === "PAUSED"
        ? ["RESUME", "ARCHIVE"]
        : result.status === "ACTIVE"
          ? [
            "SAVE_DRAFT",
            ...(currentStatus === "DRAFT" ? ["PUBLISH"] : []),
            "PAUSE",
            "ARCHIVE",
          ]
          : [
            "SAVE_DRAFT",
            ...(currentStatus === "DRAFT" ? ["PUBLISH"] : []),
            "ARCHIVE",
          ];
    if (
      result.capabilities.length !== expectedCapabilities.length
      || result.capabilities.some((capability, index) => capability !== expectedCapabilities[index])
      || (result.status === "DRAFT" && currentStatus !== null && currentStatus !== "DRAFT")
      || (result.status === "PAUSED" && currentStatus !== "PUBLISHED")
      || (result.status === "ARCHIVED" && result.current_version !== null)
    ) invalid("INVALID_PROFILE_LIFECYCLE_PROJECTION");
    const expectedEditablePaths = expectedCapabilities.includes("SAVE_DRAFT")
      ? PROFILE_EDITABLE_PATHS
      : [];
    if (
      result.editable_paths.length !== expectedEditablePaths.length
      || result.editable_paths.some((path, index) => path !== expectedEditablePaths[index])
    ) invalid("INVALID_PROFILE_LIFECYCLE_PROJECTION");
  }
  if (result.resource_type === "DEMAND" && result.capabilities.includes("CANCEL")) {
    const ownerEditable = new Set(["DRAFT", "NEEDS_CHANGES", "NO_MATCH"]).has(result.status);
    const expectedCapabilities = ownerEditable
      ? ["SAVE_DRAFT", "SUBMIT", "CANCEL"]
      : ["CANCEL"];
    if (
      new Set(["MATCHED", "CANCELLED", "EXPIRED"]).has(result.status)
      || result.capabilities.length !== expectedCapabilities.length
      || result.capabilities.some((capability, index) => capability !== expectedCapabilities[index])
      || result.review_assignment !== null
      || (ownerEditable && (
        result.editable_paths.length !== DEMAND_EDITABLE_PATHS.length
        || result.editable_paths.some((path, index) => path !== DEMAND_EDITABLE_PATHS[index])
      ))
      || (!ownerEditable && result.editable_paths.length !== 0)
    ) invalid("INVALID_DEMAND_CANCEL_PROJECTION");
  }
  if (!Array.isArray(result.submissions)) invalid();
  result.submissions.forEach(parseSubmission);
  if (!Array.isArray(result.findings)) invalid();
  result.findings.forEach(parseFinding);
  if (result.review_assignment !== null) parseReviewAssignment(result.review_assignment);
  if (result.capabilities.includes("RECORD_FINDINGS") !== (result.review_assignment !== null)) invalid();
  return result;
}

export function parseEditorCollection(value) {
  const envelope = exactKeys(value, new Set(["data"]));
  if (!Array.isArray(envelope.data)) invalid();
  envelope.data.forEach(parseEditorResource);
  return envelope.data;
}

function parseEditorReviewQueueItem(value) {
  const result = exactKeys(value, REVIEW_QUEUE_ITEM_KEYS);
  canonicalUuid(result.demand_id);
  if (!Number.isSafeInteger(result.demand_revision) || result.demand_revision < 1) invalid();
  if (!Number.isSafeInteger(result.demand_version_no) || result.demand_version_no < 1) invalid();
  const submittedAt = Date.parse(utcTimestamp(result.submitted_at));
  const expiresAt = Date.parse(utcTimestamp(result.demand_expires_at));
  if (submittedAt >= expiresAt) invalid();
  if (result.etag !== `"demand-${result.demand_revision}-review-queue"`) invalid();
  return result;
}

export function parseEditorReviewQueueEnvelope(value) {
  const envelope = exactKeys(value, new Set(["data"]));
  if (!Array.isArray(envelope.data) || envelope.data.length > 100) invalid();
  envelope.data.forEach(parseEditorReviewQueueItem);
  if (new Set(envelope.data.map((item) => item.demand_id)).size !== envelope.data.length) invalid();
  return envelope.data;
}

function parseEditorReviewHistoryItem(value) {
  const result = exactKeys(value, REVIEW_HISTORY_ITEM_KEYS);
  canonicalUuid(result.review_id);
  canonicalUuid(result.demand_id);
  canonicalUuid(result.demand_version_id);
  const reasons = stringArray(result.reason_codes, REVIEW_REASON_CODE_SET);
  const fields = stringArray(
    result.required_field_codes,
    new Set(DEMAND_EDITABLE_PATHS.map((path) => path.slice(1).toUpperCase())),
  );
  if (result.decision === "NEEDS_CHANGES") {
    if (
      reasons.length < 1 || reasons.length > 20
      || fields.length < 1 || fields.length > 50
      || result.budget_health_code !== null
      || result.risk_code !== null
    ) invalid();
  } else if (result.decision === "VERIFIED") {
    if (
      reasons.length !== 0
      || fields.length !== 0
      || !VERIFY_BUDGET_HEALTH_CODES.includes(result.budget_health_code)
      || !VERIFY_RISK_CODES.includes(result.risk_code)
    ) invalid();
  } else invalid();
  utcInstant(result.reviewed_at);
  return result;
}

export function parseEditorReviewHistoryEnvelope(value) {
  const envelope = exactKeys(value, new Set(["data"]));
  const result = exactKeys(envelope.data, REVIEW_HISTORY_PAGE_KEYS);
  if (
    result.schema_version !== "demand-review-history-v1"
    || !Array.isArray(result.items)
    || result.items.length > 100
    || typeof result.has_more !== "boolean"
    || (result.next_cursor === null) !== !result.has_more
    || (result.next_cursor !== null && !REVIEW_HISTORY_CURSOR.test(result.next_cursor))
  ) invalid();
  result.items.forEach(parseEditorReviewHistoryItem);
  if (new Set(result.items.map((item) => item.review_id)).size !== result.items.length) invalid();
  for (let index = 1; index < result.items.length; index += 1) {
    const left = result.items[index - 1];
    const right = result.items[index];
    const leftAt = utcInstant(left.reviewed_at);
    const rightAt = utcInstant(right.reviewed_at);
    if (leftAt < rightAt || (leftAt === rightAt && left.review_id <= right.review_id)) invalid();
  }
  return result;
}

export function parseEditorReviewClaimEnvelope(value) {
  const envelope = exactKeys(value, new Set(["data"]));
  const result = exactKeys(envelope.data, REVIEW_CLAIM_KEYS);
  canonicalUuid(result.assignment_id);
  canonicalUuid(result.demand_id);
  if (!Number.isSafeInteger(result.demand_revision) || result.demand_revision < 1) invalid();
  if (result.status !== "ACTIVE") invalid();
  utcTimestamp(result.expires_at);
  if (result.etag !== `"demand-${result.demand_revision}-review-queue"`) invalid();
  if (typeof result.replayed !== "boolean") invalid();
  return result;
}

function parseFinanceFundingQueueItem(value) {
  const result = exactKeys(value, FINANCE_FUNDING_QUEUE_ITEM_KEYS);
  canonicalUuid(result.demand_id);
  canonicalUuid(result.demand_version_id);
  if (!Number.isSafeInteger(result.demand_revision) || result.demand_revision < 1) invalid();
  if (!new Set(["AVAILABLE", "PENDING"]).has(result.review_status)) invalid();
  if (typeof result.assigned_to_me !== "boolean") invalid();
  if (!Number.isSafeInteger(result.confirmation_count) || !new Set([0, 1]).has(result.confirmation_count)) invalid();
  if (result.required_confirmations !== 2) invalid();
  utcTimestamp(result.expires_at);
  if (result.review_status === "AVAILABLE") {
    if (
      result.funding_review_id !== null
      || result.review_revision !== null
      || result.assigned_to_me
      || result.confirmation_count !== 0
      || result.etag !== `"demand-${result.demand_revision}-finance-queue"`
    ) invalid();
  } else {
    canonicalUuid(result.funding_review_id);
    if (!Number.isSafeInteger(result.review_revision) || result.review_revision < 1) invalid();
    if (result.etag !== `"funding-review-${result.review_revision}"`) invalid();
  }
  return result;
}

export function parseFinanceFundingQueueEnvelope(value) {
  const envelope = exactKeys(value, new Set(["data"]));
  if (!Array.isArray(envelope.data) || envelope.data.length > 100) invalid();
  envelope.data.forEach(parseFinanceFundingQueueItem);
  if (new Set(envelope.data.map((item) => item.demand_id)).size !== envelope.data.length) invalid();
  return envelope.data;
}

function parseFinanceFundingHistoryItem(value) {
  const result = exactKeys(value, FINANCE_FUNDING_HISTORY_ITEM_KEYS);
  canonicalUuid(result.funding_review_id);
  canonicalUuid(result.demand_id);
  canonicalUuid(result.demand_version_id);
  if (!new Set(["SECURED", "DISCREPANCY", "REJECTED"]).has(result.status)) invalid();
  utcInstant(result.completed_at);
  return result;
}

export function parseFinanceFundingHistoryEnvelope(value) {
  const envelope = exactKeys(value, new Set(["data"]));
  const result = exactKeys(envelope.data, FINANCE_FUNDING_HISTORY_PAGE_KEYS);
  if (
    result.schema_version !== "finance-funding-review-history-v1"
    || !Array.isArray(result.items)
    || result.items.length > 100
    || typeof result.has_more !== "boolean"
    || (result.next_cursor === null) !== !result.has_more
    || (result.next_cursor !== null && !REVIEW_HISTORY_CURSOR.test(result.next_cursor))
  ) invalid();
  result.items.forEach(parseFinanceFundingHistoryItem);
  if (new Set(result.items.map((item) => item.funding_review_id)).size !== result.items.length) invalid();
  for (let index = 1; index < result.items.length; index += 1) {
    const left = result.items[index - 1];
    const right = result.items[index];
    const leftAt = utcInstant(left.completed_at);
    const rightAt = utcInstant(right.completed_at);
    if (
      leftAt < rightAt
      || (leftAt === rightAt && left.funding_review_id <= right.funding_review_id)
    ) invalid();
  }
  return result;
}

export function parseFinanceFundingReviewEnvelope(value) {
  const envelope = exactKeys(value, new Set(["data"]));
  const result = exactKeys(envelope.data, FINANCE_FUNDING_REVIEW_KEYS);
  canonicalUuid(result.funding_review_id);
  canonicalUuid(result.demand_id);
  canonicalUuid(result.demand_version_id);
  canonicalUuid(result.assignment_id);
  if (!new Set(["PENDING", "SECURED", "DISCREPANCY", "REJECTED"]).has(result.status)) invalid();
  if (!Number.isSafeInteger(result.revision) || result.revision < 1) invalid();
  utcTimestamp(result.assignment_expires_at);
  sha256(result.target_sha256);
  sha256(result.target_content_sha256);
  sha256(result.evidence_reference_sha256);
  const actions = stringArray(result.available_actions, FINANCE_FUNDING_ACTION_SET);
  const expectedActions = (
    result.status === "PENDING"
    && result.assignment_status === "ACTIVE"
    && result.confirmation_by_me === false
  ) ? FINANCE_FUNDING_ACTIONS : [];
  if (
    result.planned_budget_currency !== "CNY"
    || !Number.isSafeInteger(result.planned_budget_minimum_amount_minor)
    || result.planned_budget_minimum_amount_minor < 0
    || !Number.isSafeInteger(result.planned_budget_maximum_amount_minor)
    || result.planned_budget_maximum_amount_minor < result.planned_budget_minimum_amount_minor
    || !Number.isSafeInteger(result.planned_budget_direct_cost_amount_minor)
    || result.planned_budget_direct_cost_amount_minor < 0
    || result.evidence_kind !== "INTERNAL_SANDBOX_ZERO_FUNDS_V1"
    || result.sandbox_funds_amount_minor !== 0
    || result.provider_code !== "NONE"
    || result.payment_operation_code !== "NONE"
    || result.synthetic !== true
    || result.legal_effect !== "NO_REAL_FUNDS_OR_PAYMENT"
    || !Number.isSafeInteger(result.confirmation_count)
    || !new Set([0, 1, 2]).has(result.confirmation_count)
    || result.required_confirmations !== 2
    || (result.status === "SECURED") !== (result.confirmation_count === 2)
    || (new Set(["DISCREPANCY", "REJECTED"]).has(result.status) && result.confirmation_count === 2)
    || !new Set(["ACTIVE", "COMPLETED", "RELEASED", "EXPIRED", "REVOKED"]).has(result.assignment_status)
    || typeof result.confirmation_by_me !== "boolean"
    || (result.confirmation_by_me && result.assignment_status !== "COMPLETED")
    || actions.length !== expectedActions.length
    || actions.some((action, index) => action !== expectedActions[index])
    || typeof result.can_confirm !== "boolean"
    || result.can_confirm !== actions.includes("CONFIRM")
    || result.etag !== `"funding-review-${result.revision}"`
    || typeof result.replayed !== "boolean"
  ) invalid();
  return result;
}

function parseTrustReportSummary(value) {
  const result = exactKeys(value, TRUST_REPORT_SUMMARY_KEYS);
  if (!TRUST_REPORT_CATEGORY_SET.has(result.category)) invalid();
  boundedCodes(result.evidence_reference_ids, null, 1, 32).forEach(canonicalUuid);
  boundedCodes(result.impact_codes, TRUST_IMPACT_CODE_SET, 1, 16);
  const startedAt = Date.parse(timestamp(result.incident_started_at));
  const endedAt = result.incident_ended_at === null
    ? null
    : Date.parse(timestamp(result.incident_ended_at));
  if (endedAt !== null && endedAt < startedAt) invalid();
  boundedCodes(result.requested_protection_codes, TRUST_PROTECTION_CODE_SET, 1, 3);
  return result;
}

function parseTrustReportProjection(value) {
  const result = exactKeys(value, TRUST_REPORT_PROJECTION_KEYS);
  canonicalUuid(result.demand_id);
  canonicalUuid(result.demand_version_id);
  trustEntityTag(result.entity_tag);
  if (result.outcome !== null) parseTrustOutcome(result.outcome);
  parseTrustReportSummary(result.report);
  canonicalUuid(result.report_id);
  if (!new Set(["DECIDED", "IN_REVIEW", "OPEN", "TRIAGING"]).has(result.status)) invalid();
  timestamp(result.submitted_at);
  return result;
}

export function parseTrustReportEnvelope(value) {
  const envelope = exactKeys(value, new Set(["data"]));
  return parseTrustReportProjection(envelope.data);
}

function parseTrustOwnReportOutcome(value) {
  const result = exactKeys(value, TRUST_OWN_REPORT_OUTCOME_KEYS);
  if (result.appeal_deadline !== null) utcTimestamp(result.appeal_deadline);
  if (!new Set(["ELIGIBLE", "NOT_ELIGIBLE"]).has(result.appeal_eligibility_code)) invalid();
  utcTimestamp(result.decided_at);
  if (!TRUST_OUTCOME_CODE_SET.has(result.outcome_code)) invalid();
  canonicalUuid(result.outcome_version_id);
  if ((result.appeal_eligibility_code === "ELIGIBLE") !== (result.appeal_deadline !== null)) invalid();
  return result;
}

function parseTrustOwnReportItem(value) {
  const result = exactKeys(value, TRUST_OWN_REPORT_ITEM_KEYS);
  if (!TRUST_REPORT_CATEGORY_SET.has(result.category)) invalid();
  canonicalUuid(result.demand_id);
  canonicalUuid(result.report_id);
  if (!new Set(["DECIDED", "IN_REVIEW", "OPEN", "TRIAGING"]).has(result.status)) invalid();
  utcTimestamp(result.submitted_at);
  if (result.outcome === null) {
    if (result.status === "DECIDED") invalid();
  } else {
    parseTrustOwnReportOutcome(result.outcome);
    if (result.status !== "DECIDED") invalid();
  }
  return result;
}

export function parseTrustOwnReportListEnvelope(value) {
  const envelope = exactKeys(value, new Set(["data"]));
  const projection = exactKeys(envelope.data, TRUST_OWN_REPORT_LIST_KEYS);
  trustEntityTag(projection.entity_tag);
  if (!Array.isArray(projection.items) || projection.items.length > 100) invalid();
  projection.items.forEach(parseTrustOwnReportItem);
  if (new Set(projection.items.map((item) => item.report_id)).size !== projection.items.length) invalid();
  let previous = null;
  for (const item of projection.items) {
    const instant = utcInstant(item.submitted_at);
    if (previous !== null && !(
      instant < previous.instant
      || (instant === previous.instant && item.report_id > previous.reportId)
    )) invalid();
    previous = { instant, reportId: item.report_id };
  }
  if (projection.next_cursor !== null && (
    typeof projection.next_cursor !== "string"
    || !TRUST_OWN_REPORT_CURSOR.test(projection.next_cursor)
    || projection.items.length === 0
  )) invalid();
  return projection;
}

function parseTrustQueueItem(value) {
  const result = exactKeys(value, TRUST_QUEUE_ITEM_KEYS);
  if (!TRUST_REPORT_CATEGORY_SET.has(result.category)) invalid();
  canonicalUuid(result.case_id);
  canonicalUuid(result.demand_id);
  canonicalUuid(result.demand_version_id);
  trustEntityTag(result.entity_tag);
  boundedCodes(result.impact_codes, TRUST_IMPACT_CODE_SET, 1, 16);
  canonicalUuid(result.report_id);
  timestamp(result.submitted_at);
  return result;
}

export function parseTrustQueueEnvelope(value) {
  const envelope = exactKeys(value, new Set(["data"]));
  const projection = exactKeys(envelope.data, new Set(["entity_tag", "items"]));
  trustEntityTag(projection.entity_tag);
  if (!Array.isArray(projection.items) || projection.items.length > 100) invalid();
  projection.items.forEach(parseTrustQueueItem);
  if (new Set(projection.items.map((item) => item.case_id)).size !== projection.items.length) invalid();
  return projection;
}

function parseTrustHoldReleaseQueueItem(value) {
  const result = exactKeys(value, TRUST_HOLD_RELEASE_QUEUE_ITEM_KEYS);
  boundedCodes(result.action_codes, TRUST_DEMAND_ACTION_CODE_SET, 1, 3);
  canonicalUuid(result.case_id);
  canonicalUuid(result.demand_id);
  canonicalUuid(result.demand_version_id);
  trustEntityTag(result.entity_tag);
  timestamp(result.expires_at);
  canonicalUuid(result.hold_id);
  if (!new Set(["PARTICIPANT_SAFETY_RISK", "RETALIATION_RISK"]).has(result.reason_code)) invalid();
  return result;
}

export function parseTrustHoldReleaseQueueEnvelope(value) {
  const envelope = exactKeys(value, new Set(["data"]));
  const projection = exactKeys(envelope.data, new Set(["entity_tag", "items"]));
  trustEntityTag(projection.entity_tag);
  if (!Array.isArray(projection.items) || projection.items.length > 100) invalid();
  projection.items.forEach(parseTrustHoldReleaseQueueItem);
  if (new Set(projection.items.map((item) => item.hold_id)).size !== projection.items.length) invalid();
  return projection;
}

function parseTrustAssignmentItem(value) {
  const result = exactKeys(value, TRUST_ASSIGNMENT_ITEM_KEYS);
  utcTimestamp(result.assignment_expires_at);
  if (!new Set(["CASE_TRIAGE", "HOLD_RELEASE"]).has(result.assignment_purpose)) invalid();
  canonicalUuid(result.case_id);
  if (result.assignment_purpose === "CASE_TRIAGE") {
    if (result.hold_id !== null) invalid();
  } else {
    canonicalUuid(result.hold_id);
  }
  return result;
}

export function parseTrustAssignmentListEnvelope(value) {
  const envelope = exactKeys(value, new Set(["data"]));
  const projection = exactKeys(envelope.data, new Set(["entity_tag", "items"]));
  trustEntityTag(projection.entity_tag);
  if (!Array.isArray(projection.items) || projection.items.length > 100) invalid();
  projection.items.forEach(parseTrustAssignmentItem);
  if (new Set(projection.items.map(
    (item) => JSON.stringify([item.case_id, item.assignment_purpose, item.hold_id]),
  )).size !== projection.items.length) invalid();
  return projection;
}

function parseTrustCaseHistoryItem(value) {
  const result = exactKeys(value, TRUST_CASE_HISTORY_ITEM_KEYS);
  canonicalUuid(result.case_id);
  utcTimestamp(result.decided_at);
  if (!TRUST_OUTCOME_CODE_SET.has(result.outcome_code)) invalid();
  return result;
}

export function parseTrustCaseHistoryEnvelope(value) {
  const envelope = exactKeys(value, new Set(["data"]));
  const projection = exactKeys(envelope.data, new Set(["entity_tag", "has_more", "items"]));
  trustEntityTag(projection.entity_tag);
  if (!Array.isArray(projection.items) || projection.items.length > 100) invalid();
  projection.items.forEach(parseTrustCaseHistoryItem);
  if (new Set(projection.items.map((item) => item.case_id)).size !== projection.items.length) invalid();
  let previous = null;
  for (const item of projection.items) {
    const instant = utcInstant(item.decided_at);
    if (previous !== null && !(
      instant < previous.instant
      || (instant === previous.instant && item.case_id < previous.caseId)
    )) invalid();
    previous = { instant, caseId: item.case_id };
  }
  if (typeof projection.has_more !== "boolean") invalid();
  return projection;
}

export function parseTrustAssignedHoldEnvelope(value) {
  const envelope = exactKeys(value, new Set(["data"]));
  const result = exactKeys(envelope.data, TRUST_ASSIGNED_HOLD_KEYS);
  boundedCodes(result.action_codes, TRUST_DEMAND_ACTION_CODE_SET, 1, 3);
  canonicalUuid(result.case_id);
  canonicalUuid(result.hold_id);
  if (result.case_status !== "IN_REVIEW" || result.hold_status !== "ACTIVE") invalid();
  if (!new Set(["PARTICIPANT_SAFETY_RISK", "RETALIATION_RISK"]).has(result.reason_code)) invalid();
  trustEntityTag(result.entity_tag);
  const effectiveAt = utcInstant(result.effective_at);
  const expiresAt = utcInstant(result.expires_at);
  const assignmentExpiresAt = utcInstant(result.assignment_expires_at);
  if (effectiveAt >= expiresAt || assignmentExpiresAt > expiresAt) invalid();
  return result;
}

function parseTrustSafeTriage(value) {
  const result = exactKeys(value, TRUST_SAFE_TRIAGE_KEYS);
  boundedCodes(result.investigation_step_codes, TRUST_INVESTIGATION_STEP_CODE_SET, 1, 16);
  boundedCodes(result.issue_codes, TRUST_ISSUE_CODE_SET, 1, 16);
  if (!new Set(["LEGAL_REVIEW_REQUIRED", "ORGANIZATION_POLICY", "PLATFORM_INTERNAL"]).has(result.jurisdiction_code)) invalid();
  if (!new Set(["P0", "P1", "P2", "P3"]).has(result.priority_code)) invalid();
  boundedCodes(result.proposed_hold_actions, TRUST_DEMAND_ACTION_CODE_SET, 1, 3);
  if (!Number.isSafeInteger(result.proposed_hold_ttl_minutes) || result.proposed_hold_ttl_minutes < 15 || result.proposed_hold_ttl_minutes > 10080) invalid();
  if (typeof result.sealed_note_reference !== "string" || !/^sealed:\/\/trust\/[a-z0-9][a-z0-9/_-]{4,255}$/.test(result.sealed_note_reference)) invalid();
  sha256(result.sealed_note_sha256);
  if (!new Set(["CRITICAL", "HIGH", "LOW", "MEDIUM"]).has(result.severity_code)) invalid();
  return result;
}

function parseTrustTriageDraft(value) {
  const result = exactKeys(value, TRUST_TRIAGE_DRAFT_KEYS);
  parseTrustSafeTriage(result.content);
  sha256(result.content_sha256);
  timestamp(result.saved_at);
  if (!Number.isSafeInteger(result.triage_version) || result.triage_version < 1) invalid();
  return result;
}

function parseTrustHold(value) {
  const result = exactKeys(value, TRUST_HOLD_KEYS);
  boundedCodes(result.action_codes, TRUST_DEMAND_ACTION_CODE_SET, 1, 3);
  const effectiveAt = Date.parse(timestamp(result.effective_at));
  trustEntityTag(result.entity_tag);
  const expiresAt = Date.parse(timestamp(result.expires_at));
  if (expiresAt <= effectiveAt) invalid();
  canonicalUuid(result.hold_id);
  if (!new Set(["ACTIVE", "EXPIRED", "RELEASED"]).has(result.status)) invalid();
  return result;
}

function parseTrustOutcome(value) {
  const result = exactKeys(value, TRUST_OUTCOME_KEYS);
  boundedCodes(result.action_codes, TRUST_DEMAND_ACTION_CODE_SET, 0, 3);
  if (result.appeal_deadline !== null) timestamp(result.appeal_deadline);
  if (!new Set(["ELIGIBLE", "NOT_ELIGIBLE"]).has(result.appeal_eligibility_code)) invalid();
  sha256(result.content_sha256);
  timestamp(result.decided_at);
  sha256(result.evidence_packet_digest);
  canonicalUuid(result.evidence_packet_version_id);
  if (!TRUST_OUTCOME_CODE_SET.has(result.outcome_code)) invalid();
  canonicalUuid(result.outcome_version_id);
  if (typeof result.policy_version !== "string" || !/^trust-case-outcome-v[1-9][0-9]*$/.test(result.policy_version)) invalid();
  boundedCodes(result.reason_codes, TRUST_OUTCOME_REASON_CODE_SET, 1, 8);
  if (!new Set(["OFFICER_RESTRICTED_V1", "PARTY_SAFE_V1"]).has(result.redaction_profile_code)) invalid();
  sha256(result.source_digest);
  return result;
}

function parseTrustCaseProjection(value) {
  const result = exactKeys(value, TRUST_CASE_KEYS);
  if (result.active_hold !== null) parseTrustHold(result.active_hold);
  if (!Number.isSafeInteger(result.aggregate_version) || result.aggregate_version < 1) invalid();
  canonicalUuid(result.case_id);
  canonicalUuid(result.demand_id);
  canonicalUuid(result.demand_version_id);
  trustEntityTag(result.entity_tag);
  if (result.outcome !== null) parseTrustOutcome(result.outcome);
  parseTrustReportSummary(result.report);
  canonicalUuid(result.report_id);
  if (!new Set(["DECIDED", "IN_REVIEW", "TRIAGING"]).has(result.status)) invalid();
  if (result.triage_draft !== null) parseTrustTriageDraft(result.triage_draft);
  if ((result.status === "DECIDED") !== (result.outcome !== null)) invalid();
  return result;
}

export function parseTrustCaseEnvelope(value) {
  const envelope = exactKeys(value, new Set(["data"]));
  return parseTrustCaseProjection(envelope.data);
}

export function parseTrustCommandEnvelope(value) {
  const envelope = exactKeys(value, new Set(["data"]));
  const result = exactKeys(envelope.data, TRUST_COMMAND_RESULT_KEYS);
  if (!Number.isSafeInteger(result.aggregate_version) || result.aggregate_version < 1) invalid();
  canonicalUuid(result.case_id);
  if (!new Set(["APPEAL_PENDING", "DECIDED", "DISMISSED", "IN_REVIEW", "OPEN", "RESOLVED", "TRIAGING"]).has(result.case_status)) invalid();
  timestamp(result.completed_at);
  boundedCodes(result.event_types, TRUST_COMMAND_EVENT_TYPES, 1, 1);
  if (result.hold_id !== null) canonicalUuid(result.hold_id);
  if (result.hold_version !== null && (!Number.isSafeInteger(result.hold_version) || result.hold_version < 1)) invalid();
  if (result.outcome_version_id !== null) canonicalUuid(result.outcome_version_id);
  if (typeof result.replayed !== "boolean") invalid();
  if (result.report_id !== null) canonicalUuid(result.report_id);
  if (result.triage_draft_version !== null && (!Number.isSafeInteger(result.triage_draft_version) || result.triage_draft_version < 1)) invalid();
  if (result.triage_version !== null && (!Number.isSafeInteger(result.triage_version) || result.triage_version < 1)) invalid();
  if ((result.hold_id === null) !== (result.hold_version === null)) invalid();
  return result;
}

function parseAppealSource(value) {
  const result = exactKeys(value, APPEAL_SOURCE_KEYS);
  boundedCodes(result.action_codes, TRUST_DEMAND_ACTION_CODE_SET, 0, 3);
  const deadline = Date.parse(appealTimestamp(result.appeal_deadline));
  if (result.appeal_eligibility_code !== "ELIGIBLE" || result.appeal_eligible !== true) invalid();
  canonicalUuid(result.case_id);
  sha256(result.content_sha256);
  const decidedAt = Date.parse(appealTimestamp(result.decided_at));
  if (deadline <= decidedAt) invalid();
  canonicalUuid(result.demand_id);
  canonicalUuid(result.demand_version_id);
  sha256(result.evidence_packet_sha256);
  canonicalUuid(result.evidence_packet_version_id);
  if (!TRUST_OUTCOME_CODE_SET.has(result.outcome_code)) invalid();
  canonicalUuid(result.outcome_version_id);
  if (typeof result.policy_version !== "string" || !/^[a-z][a-z0-9._-]{2,95}$/.test(result.policy_version)) invalid();
  boundedCodes(result.reason_codes, TRUST_OUTCOME_REASON_CODE_SET, 1, 32);
  const noProtectiveAction = new Set(["NO_ACTION", "PROTECTION_LIFTED"]).has(result.outcome_code);
  if (noProtectiveAction ? result.action_codes.length !== 0 : result.action_codes.length === 0) invalid();
  return result;
}

function appealApplicationFacts(grounds, evidenceIds, requestedOutcome) {
  boundedCodes(grounds, APPEAL_GROUND_SET, 1, 3);
  boundedCodes(evidenceIds, null, 0, 32).forEach(canonicalUuid);
  if (grounds.includes("NEW_MATERIAL_EVIDENCE") && evidenceIds.length === 0) invalid();
  if (!APPEAL_REQUESTED_OUTCOME_SET.has(requestedOutcome)) invalid();
}

function parseAppealApplicationDraft(value) {
  const result = exactKeys(value, APPEAL_APPLICATION_DRAFT_KEYS);
  appealTimestamp(result.edited_at);
  appealApplicationFacts(result.grounds, result.new_evidence_reference_ids, result.requested_outcome);
  if (result.statement_recorded !== true) invalid();
  if (!Number.isSafeInteger(result.version) || result.version < 1) invalid();
  return result;
}

function parseAppealSubmittedApplication(value) {
  const result = exactKeys(value, APPEAL_SUBMITTED_APPLICATION_KEYS);
  appealApplicationFacts(result.grounds, result.new_evidence_reference_ids, result.requested_outcome);
  if (result.statement_recorded !== true) invalid();
  appealTimestamp(result.submitted_at);
  return result;
}

function parseAppealAssessment(value) {
  const result = exactKeys(value, APPEAL_ASSESSMENT_KEYS);
  boundedCodes(result.accepted_evidence_reference_ids, null, 0, 32).forEach(canonicalUuid);
  if (!APPEAL_ASSESSMENT_CODE_SET.has(result.assessment_code)) invalid();
  boundedCodes(result.finding_codes, APPEAL_FINDING_CODE_SET, 1, 32);
  if (!APPEAL_GROUND_SET.has(result.ground)) invalid();
  return result;
}

function parseAppealAssessments(value) {
  if (!Array.isArray(value) || value.length < 1 || value.length > 3) invalid();
  value.forEach(parseAppealAssessment);
  const normalized = value.map((item) => stable({
    accepted_evidence_reference_ids: item.accepted_evidence_reference_ids,
    assessment_code: item.assessment_code,
    finding_codes: item.finding_codes,
    ground: item.ground,
  }));
  if (new Set(normalized).size !== normalized.length) invalid();
  if (new Set(value.map((item) => item.ground)).size !== value.length) invalid();
  return value;
}

function validateAppealAssessmentsAgainstApplication(assessments, application) {
  const expectedGrounds = application.grounds;
  if (
    assessments.length !== expectedGrounds.length
    || assessments.some((assessment) => !expectedGrounds.includes(assessment.ground))
  ) invalid();
  const evidence = new Set(application.new_evidence_reference_ids);
  if (assessments.some((assessment) => assessment.accepted_evidence_reference_ids.some((item) => !evidence.has(item)))) invalid();
}

function validateAppealDecisionShape(decisionCode, assessments, remedyDeltaCodes) {
  const anyAccepted = assessments.some((assessment) => new Set(["ACCEPTED", "PARTIALLY_ACCEPTED"]).has(assessment.assessment_code));
  const noChange = remedyDeltaCodes.length === 1 && remedyDeltaCodes[0] === "NO_CHANGE";
  if (new Set(["MODIFY", "VACATE_AND_REMAND"]).has(decisionCode)) {
    if (!anyAccepted || noChange) invalid();
  } else if (new Set(["AFFIRM", "DISMISS"]).has(decisionCode)) {
    if (anyAccepted || !noChange) invalid();
  }
}

function parseAppealDecision(value) {
  const result = exactKeys(value, APPEAL_DECISION_KEYS);
  parseAppealAssessments(result.assessments);
  appealTimestamp(result.decided_at);
  if (!APPEAL_DECISION_CODE_SET.has(result.decision_code)) invalid();
  sha256(result.decision_sha256);
  canonicalUuid(result.decision_version_id);
  if (typeof result.policy_version !== "string" || !/^[a-z][a-z0-9._-]{2,95}$/.test(result.policy_version)) invalid();
  boundedCodes(result.reason_codes, APPEAL_REASON_CODE_SET, 1, 32);
  boundedCodes(result.remedy_delta_codes, APPEAL_REMEDY_DELTA_CODE_SET, 1, 32);
  return result;
}

function parseAppealOwnProjection(value) {
  const result = exactKeys(value, APPEAL_OWN_KEYS);
  if (!Number.isSafeInteger(result.aggregate_version) || result.aggregate_version < 1) invalid();
  canonicalUuid(result.appeal_id);
  if (result.application !== null) parseAppealSubmittedApplication(result.application);
  if (result.application_draft !== null) parseAppealApplicationDraft(result.application_draft);
  if (result.decision !== null) parseAppealDecision(result.decision);
  appealEntityTag(result.entity_tag);
  const tagVersion = Number(result.entity_tag.match(APPEAL_ENTITY_TAG)?.[1]);
  if (tagVersion !== result.aggregate_version) invalid();
  parseAppealSource(result.source);
  canonicalUuid(result.source_case_id);
  canonicalUuid(result.source_outcome_version_id);
  if (
    result.source_case_id !== result.source.case_id
    || result.source_outcome_version_id !== result.source.outcome_version_id
  ) invalid();
  if (!new Set(["DECIDED", "DRAFT", "IN_REVIEW", "SUBMITTED", "WITHDRAWN"]).has(result.status)) invalid();
  if (result.status === "DRAFT" && (result.application !== null || result.decision !== null)) invalid();
  if (new Set(["SUBMITTED", "IN_REVIEW"]).has(result.status) && (result.application === null || result.decision !== null)) invalid();
  if (result.status === "DECIDED" && (result.application === null || result.decision === null)) invalid();
  if (result.status === "WITHDRAWN" && result.decision !== null) invalid();
  if (result.application !== null && result.application_draft !== null && (
    stable(result.application.grounds) !== stable(result.application_draft.grounds)
    || stable(result.application.new_evidence_reference_ids) !== stable(result.application_draft.new_evidence_reference_ids)
    || result.application.requested_outcome !== result.application_draft.requested_outcome
  )) invalid();
  if (result.decision !== null && result.application !== null) {
    validateAppealAssessmentsAgainstApplication(result.decision.assessments, result.application);
    validateAppealDecisionShape(result.decision.decision_code, result.decision.assessments, result.decision.remedy_delta_codes);
  }
  return result;
}

export function parseAppealOwnEnvelope(value) {
  const envelope = exactKeys(value, new Set(["data"]));
  return parseAppealOwnProjection(envelope.data);
}

function parseAppealQueueItem(value) {
  const result = exactKeys(value, APPEAL_QUEUE_ITEM_KEYS);
  canonicalUuid(result.appeal_id);
  appealEntityTag(result.entity_tag);
  boundedCodes(result.grounds, APPEAL_GROUND_SET, 1, 3);
  if (!APPEAL_REQUESTED_OUTCOME_SET.has(result.requested_outcome)) invalid();
  canonicalUuid(result.source_case_id);
  canonicalUuid(result.source_outcome_version_id);
  appealTimestamp(result.submitted_at);
  return result;
}

export function parseAppealQueueEnvelope(value) {
  const envelope = exactKeys(value, new Set(["data"]));
  const projection = exactKeys(envelope.data, new Set(["entity_tag", "items"]));
  appealEntityTag(projection.entity_tag);
  if (!Array.isArray(projection.items) || projection.items.length > 100) invalid();
  projection.items.forEach(parseAppealQueueItem);
  if (new Set(projection.items.map((item) => item.appeal_id)).size !== projection.items.length) invalid();
  return projection;
}

function parseAppealAssignmentItem(value) {
  const result = exactKeys(value, APPEAL_ASSIGNMENT_ITEM_KEYS);
  canonicalUuid(result.appeal_id);
  appealTimestamp(result.assignment_expires_at);
  return result;
}

export function parseAppealAssignmentListEnvelope(value) {
  const envelope = exactKeys(value, new Set(["data"]));
  const projection = exactKeys(envelope.data, new Set(["entity_tag", "items"]));
  appealEntityTag(projection.entity_tag);
  if (!Array.isArray(projection.items) || projection.items.length > 100) invalid();
  projection.items.forEach(parseAppealAssignmentItem);
  if (new Set(projection.items.map((item) => item.appeal_id)).size !== projection.items.length) invalid();
  return projection;
}

function parseAppealReviewHistoryItem(value) {
  const result = exactKeys(value, APPEAL_REVIEW_HISTORY_ITEM_KEYS);
  canonicalUuid(result.appeal_id);
  appealTimestamp(result.decided_at);
  if (!APPEAL_DECISION_CODE_SET.has(result.decision_code)) invalid();
  return result;
}

export function parseAppealReviewHistoryEnvelope(value) {
  const envelope = exactKeys(value, new Set(["data"]));
  const projection = exactKeys(envelope.data, APPEAL_REVIEW_HISTORY_KEYS);
  appealEntityTag(projection.entity_tag);
  if (
    !Array.isArray(projection.items)
    || projection.items.length > 100
    || typeof projection.has_more !== "boolean"
    || (projection.has_more && projection.items.length === 0)
  ) invalid();
  projection.items.forEach(parseAppealReviewHistoryItem);
  if (new Set(projection.items.map((item) => item.appeal_id)).size !== projection.items.length) invalid();
  for (let index = 1; index < projection.items.length; index += 1) {
    const left = projection.items[index - 1];
    const right = projection.items[index];
    const leftAt = utcInstant(left.decided_at);
    const rightAt = utcInstant(right.decided_at);
    if (
      leftAt < rightAt
      || (leftAt === rightAt && left.appeal_id <= right.appeal_id)
    ) invalid();
  }
  return projection;
}

function parseAppealReviewDraft(value) {
  const result = exactKeys(value, APPEAL_REVIEW_DRAFT_KEYS);
  parseAppealAssessments(result.assessments);
  appealTimestamp(result.edited_at);
  boundedCodes(result.reason_codes, APPEAL_REASON_CODE_SET, 1, 32);
  boundedCodes(result.remedy_delta_codes, APPEAL_REMEDY_DELTA_CODE_SET, 1, 32);
  if (result.review_note_recorded !== true) invalid();
  if (!Number.isSafeInteger(result.version) || result.version < 1) invalid();
  return result;
}

function parseAppealAssignedProjection(value) {
  const result = exactKeys(value, APPEAL_ASSIGNED_KEYS);
  const appeal = parseAppealOwnProjection(result.appeal);
  const application = parseAppealSubmittedApplication(result.application);
  appealTimestamp(result.assignment_expires_at);
  appealEntityTag(result.entity_tag);
  if (result.review_draft !== null) parseAppealReviewDraft(result.review_draft);
  const source = parseAppealSource(result.source);
  if (
    appeal.status !== "IN_REVIEW"
    || appeal.application === null
    || result.entity_tag !== appeal.entity_tag
    || stable(application) !== stable(appeal.application)
    || stable(source) !== stable(appeal.source)
  ) invalid();
  if (result.review_draft !== null) validateAppealAssessmentsAgainstApplication(result.review_draft.assessments, application);
  return result;
}

export function parseAppealAssignedEnvelope(value) {
  const envelope = exactKeys(value, new Set(["data"]));
  return parseAppealAssignedProjection(envelope.data);
}

export function parseAppealReviewTerminalEnvelope(value) {
  const envelope = exactKeys(value, new Set(["data"]));
  const result = exactKeys(envelope.data, APPEAL_REVIEW_TERMINAL_KEYS);
  canonicalUuid(result.appeal_id);
  const application = parseAppealSubmittedApplication(result.application);
  const decision = parseAppealDecision(result.decision);
  appealEntityTag(result.entity_tag);
  if (result.review_note_recorded !== true || result.status !== "DECIDED") invalid();
  if (Date.parse(decision.decided_at) < Date.parse(application.submitted_at)) invalid();
  validateAppealAssessmentsAgainstApplication(decision.assessments, application);
  validateAppealDecisionShape(decision.decision_code, decision.assessments, decision.remedy_delta_codes);
  return result;
}

export function parseAppealCommandEnvelope(value) {
  const envelope = exactKeys(value, new Set(["data"]));
  const result = exactKeys(envelope.data, APPEAL_COMMAND_RESULT_KEYS);
  if (!Number.isSafeInteger(result.aggregate_version) || result.aggregate_version < 1) invalid();
  canonicalUuid(result.appeal_id);
  if (!new Set(["DECIDED", "DRAFT", "IN_REVIEW", "SUBMITTED", "WITHDRAWN"]).has(result.appeal_status)) invalid();
  positiveVersionOrNull(result.application_draft_version);
  positiveVersionOrNull(result.application_version);
  appealTimestamp(result.completed_at);
  if (result.decision_version_id !== null) canonicalUuid(result.decision_version_id);
  boundedCodes(result.event_types, APPEAL_COMMAND_EVENT_TYPES, 1, 1);
  if (typeof result.replayed !== "boolean") invalid();
  positiveVersionOrNull(result.review_draft_version);
  return result;
}

export function parseEditorEnvelope(value) {
  const envelope = exactKeys(value, new Set(["data"]));
  return parseEditorResource(envelope.data);
}

function editorChoiceValue(valueContract, value) {
  if (typeof value !== "string") invalid();
  const pattern = {
    TAXONOMY_CODE,
    REGION_CODE,
    LANGUAGE_TAG,
    CURRENCY_CODE,
    CONTENT_ENUM,
  }[valueContract];
  if (!pattern?.test(value)) invalid();
  return value;
}

function parseEditorChoiceField(value, binding) {
  const result = exactKeys(value, EDITOR_CHOICE_FIELD_KEYS);
  if (
    !EDITOR_CHOICE_RESOURCE_TYPES.has(result.resource_type)
    || !EDITOR_CHOICE_VALUE_CONTRACTS.has(result.value_contract)
    || typeof result.path_template !== "string"
    || result.path_template.length > 256
    || !EDITOR_CHOICE_PATH.test(result.path_template)
    || (result.intended_node_kind !== null && !TAXONOMY_NODE_KINDS.has(result.intended_node_kind))
    || (result.value_contract !== "TAXONOMY_CODE" && result.intended_node_kind !== null)
    || !new Set(["AVAILABLE", "UNAVAILABLE"]).has(result.status)
    || !Array.isArray(result.options)
  ) invalid();
  if (result.status === "AVAILABLE") {
    if (
      result.reason_code !== null
      || result.options.length < 1
      || result.options.length > 16
      || (result.value_contract === "TAXONOMY_CODE" && result.intended_node_kind === null)
    ) invalid();
  } else if (
    result.reason_code !== "NO_REVIEWED_CHOICE_SET"
    || result.options.length !== 0
  ) invalid();

  let previousValue = null;
  for (const optionValue of result.options) {
    const option = exactKeys(optionValue, EDITOR_CHOICE_OPTION_KEYS);
    const optionCode = editorChoiceValue(result.value_contract, option.value);
    if (
      typeof option.label !== "string"
      || [...option.label].length < 1
      || [...option.label].length > 120
      || option.label.trim() !== option.label
      || option.value.normalize("NFC") !== option.value
      || option.label.normalize("NFC") !== option.label
      || [...option.label].some((character) => {
        const point = character.codePointAt(0);
        return point <= 0x1f || (point >= 0x7f && point <= 0x9f);
      })
      || !EDITOR_CHOICE_SOURCES.has(option.source)
      || !EDITOR_CHOICE_SOURCE_CONTRACTS[option.source]?.has(result.value_contract)
      || (option.source === "TAXONOMY_BUNDLE_NODE" && result.intended_node_kind === null)
      || (previousValue !== null && previousValue >= optionCode)
    ) invalid();
    previousValue = optionCode;
  }
  const [resourceType, pathTemplate, valueContract, intendedNodeKind, status, source, fixedValues] = binding;
  if (
    result.resource_type !== resourceType
    || result.path_template !== pathTemplate
    || result.value_contract !== valueContract
    || result.intended_node_kind !== intendedNodeKind
    || result.status !== status
    || result.options.some((option) => option.source !== source)
    || (fixedValues !== null && (
      result.options.length !== fixedValues.length
      || result.options.some((option, index) => option.value !== fixedValues[index])
    ))
  ) invalid();
  return result;
}

function parseEditorChoices(value) {
  const result = exactKeys(value, EDITOR_CHOICES_KEYS);
  if (
    result.schema_version !== "editor-choices-v1"
    || result.locale !== "zh-CN"
    || !Array.isArray(result.fields)
    || result.fields.length !== EDITOR_CHOICE_BINDINGS.length
    || result.fields.length > 32
  ) invalid();
  let previousKey = null;
  for (const [index, fieldValue] of result.fields.entries()) {
    const field = parseEditorChoiceField(fieldValue, EDITOR_CHOICE_BINDINGS[index]);
    const key = `${field.resource_type}\0${field.path_template}`;
    if (previousKey !== null && previousKey >= key) invalid();
    previousKey = key;
  }
  return result;
}

export function parseEditorConfigurationEnvelope(value) {
  const envelope = exactKeys(value, new Set(["data"]));
  const result = exactKeys(envelope.data, EDITOR_CONFIGURATION_KEYS);
  if (
    result.schema_version !== "editor-configuration-v2"
    || result.deployment_mode !== "INTERNAL_SANDBOX"
  ) invalid();
  const taxonomy = exactKeys(
    result.taxonomy_bundle,
    TAXONOMY_CONFIGURATION_KEYS,
  );
  canonicalUuid(taxonomy.bundle_id);
  if (taxonomy.status !== "CURRENT_APPROVED") invalid();
  const effectiveAt = Date.parse(timestamp(taxonomy.effective_at));
  const effectiveUntil = taxonomy.effective_until === null
    ? null
    : Date.parse(timestamp(taxonomy.effective_until));
  if (effectiveUntil !== null && effectiveUntil <= effectiveAt) invalid();
  parseEditorChoices(result.editor_choices);
  return result;
}

export function parseSessionBootstrap(value) {
  const result = exactKeys(value, new Set(["session", "user_status", "csrf_token"]));
  const session = object(result.session);
  appId(session.session_id);
  text(result.user_status);
  if (typeof result.csrf_token !== "string" || !CSRF_TOKEN.test(result.csrf_token)) invalid();
  return result;
}

function parsePolicyRequirement(value) {
  const result = exactKeys(value, POLICY_REQUIREMENT_KEYS);
  sha256(result.selector_digest);
  if (!POLICY_PURPOSES.has(result.purpose) || !POLICY_ROLES.has(result.role)) invalid();
  if (!new Set(["USER_ROLE", "ORGANIZATION_ROLE"]).has(result.scope_type)) invalid();
  if (result.scope_type === "USER_ROLE") {
    if (result.scope_id !== null || result.role !== "CREATOR" || result.purpose !== "CREATOR_ENROLLMENT") invalid();
  } else if (
    result.scope_id === null
    || !new Set(["ORG_ADMIN", "DEMAND_OWNER"]).has(result.role)
    || result.purpose !== "ORGANIZATION_MEMBERSHIP"
  ) {
    invalid();
  } else {
    appId(result.scope_id);
  }
  if (typeof result.satisfied !== "boolean") invalid();
  if (result.required_policy_bundle_id !== null) appId(result.required_policy_bundle_id);
  stringArray(result.missing_document_ids);
  if (
    result.missing_document_ids.length > 20
    || result.satisfied !== (result.missing_document_ids.length === 0)
    || (!result.satisfied && result.required_policy_bundle_id === null)
  ) invalid();
  return result;
}

export function parsePolicyRequirementStatus(value, expectedRequirement = null) {
  const result = parsePolicyRequirement(value);
  if (expectedRequirement !== null) {
    const expected = parsePolicyRequirement(expectedRequirement);
    if (
      result.selector_digest !== expected.selector_digest
      || result.purpose !== expected.purpose
      || result.role !== expected.role
      || result.scope_type !== expected.scope_type
      || result.scope_id !== expected.scope_id
      || result.required_policy_bundle_id !== expected.required_policy_bundle_id
      || result.satisfied !== true
      || result.missing_document_ids.length !== 0
    ) invalid();
  }
  return result;
}

function parsePolicyDocument(value) {
  const result = exactKeys(value, POLICY_DOCUMENT_KEYS);
  appId(result.document_id);
  if (!POLICY_KINDS.has(result.kind)) invalid();
  if (typeof result.semantic_version !== "string" || !/^[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?$/.test(result.semantic_version) || result.semantic_version.length > 64) invalid();
  if (typeof result.locale !== "string" || !/^[A-Za-z]{2,3}(?:-[A-Za-z0-9]{2,8})*$/.test(result.locale) || result.locale.length > 35) invalid();
  sha256(result.content_sha256);
  if (!POLICY_LEGAL_EFFECTS.has(result.legal_effect)) invalid();
  if (typeof result.body !== "string" || result.body.length < 1 || result.body.length > 200_000) invalid();
  return result;
}

function parseConsentOffer(value, documents) {
  const result = exactKeys(value, CONSENT_OFFER_KEYS);
  appId(result.consent_offer_id);
  if (!CONSENT_PURPOSES.has(result.purpose) || !CONSENT_SCOPE_TYPES.has(result.scope_type)) invalid();
  stringArray(result.data_categories, CONSENT_DATA_CATEGORIES);
  if (result.data_categories.length < 1 || result.data_categories.length > 20) invalid();
  appId(result.document_id);
  const document = documents.get(result.document_id);
  if (!document || document.legal_effect !== "CONSENT_TEXT") invalid();
  sha256(result.content_sha256);
  if (result.content_sha256 !== document.content_sha256) invalid();
  if (typeof result.recipient_label !== "string" || result.recipient_label.length < 1 || result.recipient_label.length > 160) invalid();
  if (!new Set(["FIXED_NOT_AFTER", "EARLIER_OF_GRANTED_AT_PLUS_365_DAYS_OR_NOT_AFTER"]).has(result.expiry_rule)) invalid();
  timestamp(result.not_after);
  sha256(result.canonical_offer_sha256);
  if (result.optional !== true) invalid();
  return result;
}

export function parsePolicyBundle(value) {
  const result = exactKeys(value, POLICY_BUNDLE_KEYS);
  appId(result.policy_bundle_id);
  if (!POLICY_PURPOSES.has(result.purpose)) invalid();
  if (typeof result.jurisdiction !== "string" || !/^[A-Z0-9_-]{2,32}$/.test(result.jurisdiction)) invalid();
  if (typeof result.locale !== "string" || result.locale.length < 2 || result.locale.length > 35) invalid();
  if (!Array.isArray(result.documents) || result.documents.length < 1 || result.documents.length > 20) invalid();
  result.documents.forEach(parsePolicyDocument);
  const documents = new Map(result.documents.map((document) => [document.document_id, document]));
  if (documents.size !== result.documents.length) invalid();
  if (!Array.isArray(result.consent_offers) || result.consent_offers.length > 20) invalid();
  result.consent_offers.forEach((offer) => parseConsentOffer(offer, documents));
  const offerIds = result.consent_offers.map((offer) => offer.consent_offer_id);
  if (new Set(offerIds).size !== offerIds.length) invalid();
  timestamp(result.effective_at);
  if (typeof result.entity_tag !== "string" || !/^"v[1-9][0-9]*"$/.test(result.entity_tag)) invalid();
  return result;
}

export async function verifyPolicyBundleDocuments(value) {
  const bundle = parsePolicyBundle(value);
  if (!globalThis.crypto?.subtle) invalid("POLICY_DOCUMENT_DIGEST_UNAVAILABLE");
  for (const document of bundle.documents) {
    const bytes = new TextEncoder().encode(document.body);
    const digest = await globalThis.crypto.subtle.digest("SHA-256", bytes);
    const actual = [...new Uint8Array(digest)].map((item) => item.toString(16).padStart(2, "0")).join("");
    if (actual !== document.content_sha256) invalid("POLICY_DOCUMENT_DIGEST_MISMATCH");
  }
  return bundle;
}

function aggregateVersion(value) {
  if (!Number.isSafeInteger(value) || value < 1) invalid();
  return value;
}

function entityTagForVersion(value, version) {
  if (value !== `"v${version}"`) invalid();
  return value;
}

function organizationPublicName(value, code = "INVALID_APP_CONTRACT") {
  if (
    typeof value !== "string"
    || value.trim() !== value
    || value.normalize("NFC") !== value
    || [...value].length < 1
    || [...value].length > 160
    || /[\p{Cc}\p{Cf}]/u.test(value)
  ) invalid(code);
  return value;
}

export function parseOrganizationSummary(value) {
  const result = exactKeys(value, ORGANIZATION_SUMMARY_KEYS);
  appId(result.organization_id);
  organizationPublicName(result.public_name);
  if (!ORGANIZATION_TYPES.has(result.type) || !ORGANIZATION_STATUSES.has(result.status)) invalid();
  aggregateVersion(result.aggregate_version);
  entityTagForVersion(result.entity_tag, result.aggregate_version);
  return result;
}

function parseAccessInvitationAdmin(value) {
  const result = exactKeys(value, ACCESS_INVITATION_ADMIN_KEYS);
  appId(result.invitation_id);
  if (!INVITATION_PURPOSES.has(result.purpose)) invalid();
  if (result.organization_id !== null) appId(result.organization_id);
  if (
    (result.purpose === "ORGANIZATION_MEMBERSHIP" && result.organization_id === null)
    || (result.purpose === "CREATOR_ENROLLMENT" && result.organization_id !== null)
  ) invalid();
  if (!POLICY_ROLES.has(result.target_role)) invalid();
  if (
    (result.purpose === "CREATOR_ENROLLMENT" && result.target_role !== "CREATOR")
    || (result.purpose === "ORGANIZATION_MEMBERSHIP" && !ORGANIZATION_ROLES.has(result.target_role))
  ) invalid();
  if (typeof result.masked_recipient_label !== "string" || result.masked_recipient_label.length < 3 || result.masked_recipient_label.length > 80) invalid();
  if (typeof result.is_initial_admin !== "boolean" || !INVITATION_STATUSES.has(result.status)) invalid();
  timestamp(result.expires_at);
  timestamp(result.created_at);
  appId(result.required_policy_bundle_id);
  aggregateVersion(result.aggregate_version);
  entityTagForVersion(result.entity_tag, result.aggregate_version);
  return result;
}

export function parseAccessInvitationPreview(value) {
  const result = exactKeys(value, ACCESS_INVITATION_PREVIEW_KEYS);
  appId(result.invitation_id);
  if (!INVITATION_PURPOSES.has(result.purpose) || result.status !== "ISSUED") invalid();
  if (result.organization === null) {
    if (result.purpose !== "CREATOR_ENROLLMENT") invalid();
  } else {
    const organization = exactKeys(result.organization, new Set(["public_name"]));
    organizationPublicName(organization.public_name);
    if (result.purpose !== "ORGANIZATION_MEMBERSHIP") invalid();
  }
  if (!POLICY_ROLES.has(result.target_role)) invalid();
  if (
    (result.purpose === "CREATOR_ENROLLMENT" && result.target_role !== "CREATOR")
    || (result.purpose === "ORGANIZATION_MEMBERSHIP" && !ORGANIZATION_ROLES.has(result.target_role))
  ) invalid();
  timestamp(result.expires_at);
  appId(result.required_policy_bundle_id);
  aggregateVersion(result.aggregate_version);
  entityTagForVersion(result.entity_tag, result.aggregate_version);
  return result;
}

function parsePageInfo(value) {
  const page = exactKeys(value, new Set(["next_cursor"]));
  if (page.next_cursor !== null && (
    typeof page.next_cursor !== "string"
    || !/^[A-Za-z0-9_-]{64,1900}\.[A-Za-z0-9_-]{43}$/.test(page.next_cursor)
  )) invalid();
  return page;
}

export function parseAccessInvitationPage(value) {
  const result = exactKeys(value, new Set(["items", "page"]));
  if (!Array.isArray(result.items) || result.items.length > 100) invalid();
  result.items.forEach(parseAccessInvitationAdmin);
  parsePageInfo(result.page);
  const ids = result.items.map((item) => item.invitation_id);
  if (new Set(ids).size !== ids.length) invalid();
  return result;
}

function parseMembershipAdmin(value) {
  const result = exactKeys(value, MEMBERSHIP_ADMIN_KEYS);
  appId(result.membership_id);
  appId(result.organization_id);
  appId(result.user_id);
  if (typeof result.display_handle !== "string" || !/^[A-Za-z0-9][A-Za-z0-9_-]{1,79}$/.test(result.display_handle)) invalid();
  if (!MEMBERSHIP_STATUSES.has(result.status)) invalid();
  stringArray(result.roles, ORGANIZATION_ROLES);
  if (result.roles.length < 1 || result.roles.length > 2 || new Set(result.roles).size !== result.roles.length) invalid();
  aggregateVersion(result.aggregate_version);
  entityTagForVersion(result.entity_tag, result.aggregate_version);
  return result;
}

export function parseMembershipPage(value) {
  const result = exactKeys(value, new Set(["items", "page"]));
  if (!Array.isArray(result.items) || result.items.length > 100) invalid();
  result.items.forEach(parseMembershipAdmin);
  parsePageInfo(result.page);
  const ids = result.items.map((item) => item.membership_id);
  if (new Set(ids).size !== ids.length) invalid();
  return result;
}

export function parseIssueOrganizationInvitationResponse(value) {
  const result = exactKeys(value, new Set(["invitation", "access_invitation_token", "join_fragment_url"]));
  const invitation = parseAccessInvitationAdmin(result.invitation);
  if (invitation.purpose !== "ORGANIZATION_MEMBERSHIP" || invitation.organization_id === null) invalid();
  if (typeof result.access_invitation_token !== "string" || !CAPABILITY_TOKEN.test(result.access_invitation_token)) invalid();
  if (result.join_fragment_url !== `/join#access_invitation_token=${result.access_invitation_token}`) invalid();
  return result;
}

export function parseAccessInvitationAcceptance(value) {
  const result = exactKeys(value, new Set(["invitation", "me", "activated_scope"]));
  const invitation = parseAccessInvitationAdmin(result.invitation);
  if (invitation.status !== "ACCEPTED") invalid();
  parseMe(result.me);
  if (!new Set(["USER_ROLE", "ORGANIZATION_MEMBERSHIP"]).has(result.activated_scope)) invalid();
  if (
    (invitation.purpose === "CREATOR_ENROLLMENT" && result.activated_scope !== "USER_ROLE")
    || (invitation.purpose === "ORGANIZATION_MEMBERSHIP" && result.activated_scope !== "ORGANIZATION_MEMBERSHIP")
  ) invalid();
  return result;
}

export function parseMe(value) {
  const result = exactKeys(value, new Set([
    "user_id", "status", "display_handle", "user_roles", "memberships", "policy_requirements", "aggregate_version", "entity_tag",
  ]));
  appId(result.user_id);
  text(result.status);
  text(result.display_handle);
  stringArray(result.user_roles, new Set(["CREATOR"]));
  if (!Array.isArray(result.memberships)) invalid();
  for (const membershipValue of result.memberships) {
    const membership = exactKeys(membershipValue, new Set([
      "membership_id", "organization", "status", "roles", "aggregate_version", "entity_tag",
    ]));
    appId(membership.membership_id);
    text(membership.status);
    stringArray(membership.roles, new Set(["ORG_ADMIN", "DEMAND_OWNER"]));
    if (!Number.isInteger(membership.aggregate_version) || membership.aggregate_version < 1) invalid();
    text(membership.entity_tag);
    const organization = exactKeys(membership.organization, new Set([
      "organization_id", "public_name", "type", "status", "aggregate_version", "entity_tag",
    ]));
    appId(organization.organization_id);
    text(organization.public_name);
    text(organization.type);
    text(organization.status);
    if (!Number.isInteger(organization.aggregate_version) || organization.aggregate_version < 1) invalid();
    text(organization.entity_tag);
  }
  if (!Array.isArray(result.policy_requirements) || result.policy_requirements.length > 100) invalid();
  result.policy_requirements.forEach(parsePolicyRequirement);
  const requirementKeys = result.policy_requirements.map((requirement) => [
    requirement.selector_digest, requirement.role, requirement.scope_type, requirement.scope_id ?? "",
  ].join("\0"));
  if (new Set(requirementKeys).size !== requirementKeys.length) invalid();
  if (!Number.isInteger(result.aggregate_version) || result.aggregate_version < 1) invalid();
  if (result.entity_tag !== `"v${result.aggregate_version}"`) invalid();
  return result;
}

export function parseWorkspaceDiscovery(value) {
  const envelope = exactKeys(value, new Set(["data"]));
  const result = exactKeys(envelope.data, new Set(["workspaces", "selection_required"]));
  if (!Array.isArray(result.workspaces) || typeof result.selection_required !== "boolean") invalid();
  const identifiers = [];
  for (const workspaceValue of result.workspaces) {
    const workspace = exactKeys(workspaceValue, WORKSPACE_KEYS);
    if (!Object.hasOwn(WORKSPACE_ROLES, workspace.workspace_kind)) invalid();
    const match = typeof workspace.workspace_id === "string" ? WORKSPACE_ID.exec(workspace.workspace_id) : null;
    if (!match || match[1] !== WORKSPACE_PREFIXES[workspace.workspace_kind] || /^0{8}-0{4}-0{4}-0{4}-0{12}$/.test(match[2])) invalid();
    stringArray(workspace.role_codes, WORKSPACE_ROLES[workspace.workspace_kind]);
    if (workspace.role_codes.length === 0 || workspace.role_codes.join("\0") !== [...workspace.role_codes].sort().join("\0")) invalid();
    identifiers.push(workspace.workspace_id);
  }
  if (new Set(identifiers).size !== identifiers.length || identifiers.join("\0") !== [...identifiers].sort().join("\0")) invalid();
  if (result.selection_required !== (result.workspaces.length > 1)) invalid();
  return result;
}

function parseAccountAdmin(value) {
  const result = exactKeys(value, ACCOUNT_ADMIN_KEYS);
  if (typeof result.account_code !== "string" || !/^[a-z][a-z0-9_]{2,31}$/.test(result.account_code)) invalid();
  canonicalUuid(result.user_id);
  if (typeof result.display_handle !== "string" || !/^[A-Za-z0-9][A-Za-z0-9_-]{1,79}$/.test(result.display_handle)) invalid();
  if (!new Set(["ACTIVE", "SUSPENDED"]).has(result.status)) invalid();
  if (!Number.isSafeInteger(result.aggregate_version) || result.aggregate_version < 1) invalid();
  if (result.entity_tag !== `"v${result.aggregate_version}"`) invalid();
  stringArray(result.role_codes, ACCOUNT_ADMIN_ROLE_CODES);
  if (
    result.role_codes.length > 8
    || result.role_codes.join("\0") !== [...result.role_codes].sort().join("\0")
  ) invalid();
  if (!Number.isSafeInteger(result.active_session_count) || result.active_session_count < 0 || result.active_session_count > 64) invalid();
  const createdAt = Date.parse(utcTimestamp(result.created_at));
  const updatedAt = Date.parse(utcTimestamp(result.updated_at));
  if (updatedAt < createdAt || typeof result.is_self !== "boolean") invalid();
  return result;
}

export function parseAccountAdminCollectionEnvelope(value) {
  const envelope = exactKeys(value, new Set(["data"]));
  const result = exactKeys(envelope.data, new Set(["schema_version", "evaluated_at", "accounts"]));
  if (result.schema_version !== "internal-sandbox-account-admin-v1") invalid();
  const evaluatedAt = Date.parse(utcTimestamp(result.evaluated_at));
  if (!Array.isArray(result.accounts) || result.accounts.length < 1 || result.accounts.length > 16) invalid();
  result.accounts.forEach(parseAccountAdmin);
  const codes = result.accounts.map((account) => account.account_code);
  const users = result.accounts.map((account) => account.user_id);
  if (
    codes.join("\0") !== [...codes].sort().join("\0")
    || new Set(codes).size !== codes.length
    || new Set(users).size !== users.length
    || result.accounts.filter((account) => account.is_self).length !== 1
    || result.accounts.some((account) => Date.parse(account.updated_at) > evaluatedAt)
  ) invalid();
  return result;
}

export function parseAccountAdminEnvelope(value) {
  const envelope = exactKeys(value, new Set(["data"]));
  return parseAccountAdmin(envelope.data);
}

export function parseAccountAdminCommandEnvelope(value) {
  const envelope = exactKeys(value, new Set(["data"]));
  const result = exactKeys(envelope.data, ACCOUNT_ADMIN_COMMAND_KEYS);
  canonicalUuid(result.user_id);
  if (typeof result.display_handle !== "string" || !/^[A-Za-z0-9][A-Za-z0-9_-]{1,79}$/.test(result.display_handle)) invalid();
  if (!new Set(["ACTIVE", "SUSPENDED"]).has(result.status)) invalid();
  if (!Number.isSafeInteger(result.aggregate_version) || result.aggregate_version < 1) invalid();
  if (result.entity_tag !== `"v${result.aggregate_version}"`) invalid();
  for (const count of [result.revoked_session_count, result.revoked_session_family_count]) {
    if (!Number.isSafeInteger(count) || count < 0) invalid();
  }
  if (typeof result.replayed !== "boolean") invalid();
  return result;
}

export function selectWorkspaceCandidate(discoveryValue, rememberedId) {
  const discovery = parseWorkspaceDiscovery({ data: discoveryValue });
  if (rememberedId !== null && typeof rememberedId !== "string") invalid();
  if (discovery.workspaces.length === 1) return discovery.workspaces[0];
  if (rememberedId === null) return null;
  return discovery.workspaces.find((workspace) => workspace.workspace_id === rememberedId) ?? null;
}

export function sectionsFromContent(resourceType, content = {}) {
  const value = object(content);
  const paths = resourceType === "CREATOR_PROFILE"
    ? PROFILE_EDITABLE_PATHS
    : resourceType === "DEMAND"
      ? DEMAND_EDITABLE_PATHS
      : invalid("UNKNOWN_EDITOR_RESOURCE");
  const today = new Date();
  const start = new Date(today.getTime() + 24 * 60 * 60 * 1000).toISOString().slice(0, 10);
  const due = new Date(today.getTime() + 31 * 24 * 60 * 60 * 1000).toISOString().slice(0, 10);
  const defaults = resourceType === "CREATOR_PROFILE" ? {
    interests: [],
    skills: [],
    availability: null,
    collaboration: { languages: [], work_modes: [], feedback_cadence: null, team_preference: null },
    compensation: null,
    boundaries: null,
    location: null,
    conflicts: [],
    ai: null,
  } : {
    problem: { background: "INTERNAL_SANDBOX 合成问题背景", domain_code: "DOMAIN.SOFTWARE", problem_type_codes: ["PROBLEM.OPERATIONS"], target_user_category_codes: ["SYNTHETIC_USER"], desired_outcomes: ["验证内部流程"] },
    scope: { deliverables: [{ item_id: "deliverable_1", description: "合成验收材料" }], out_of_scope: ["真实用户与真实交易"] },
    acceptance: { criteria: [{ criterion_id: "criterion_1", description: "内部试运行负责人确认" }], response_days: 5, owner_role_code: "DEMAND_OWNER" },
    skills: { must_have: [{ skill_code: "SKILL.SYSTEMS_ANALYSIS", minimum_level_code: "WORKING" }], nice_to_have: [] },
    matching: { problem_codes: ["PROBLEM.OPERATIONS"], domain_codes: ["DOMAIN.SOFTWARE"], task_codes: ["TASK.ANALYSIS"] },
    schedule: { start_date: start, due_date: due, estimated_days: 20, weekly_hours: 20, duration_weeks: 4 },
    budget: { minimum_amount_minor: 0, maximum_amount_minor: 0, direct_cost_amount_minor: 0, currency: "CNY" },
    milestone_plan: { items: [{ item_id: "milestone_1", label: "内部试运行里程碑", percent: 100 }] },
    risk: { uncertainty_code: "MEDIUM", urgency_code: "LOW", dependency_codes: [], data_sensitivity: "INTERNAL", data_handling_plan: null },
    ai: { allowed: false, required: false, data_model_policy: null, human_review_code: "RISK_BASED" },
    collaboration: { languages: ["zh-CN"], work_mode: "REMOTE", feedback_cadence: "ASYNC", team_preference: "ANY" },
    location: { demand_region_code: "CN", allowed_creator_region_codes: ["CN"] },
    declarations: { decision_authority: false, data_rights: false, procurement_intent: false },
  };
  return Object.fromEntries(paths.map((path) => {
    const key = path.slice(1);
    return [path, JSON.stringify(Object.hasOwn(value, key) ? value[key] : defaults[key], null, 2)];
  }));
}

export function sectionsToContent(resourceType, sections) {
  const value = object(sections);
  const paths = resourceType === "CREATOR_PROFILE"
    ? PROFILE_EDITABLE_PATHS
    : resourceType === "DEMAND"
      ? DEMAND_EDITABLE_PATHS
      : invalid("UNKNOWN_EDITOR_RESOURCE");
  if (Object.keys(value).some((path) => !paths.includes(path))) invalid("UNKNOWN_EDITOR_SECTION");
  if (paths.some((path) => !Object.hasOwn(value, path))) invalid("MISSING_EDITOR_SECTION");
  const content = {};
  for (const path of paths) {
    if (typeof value[path] !== "string") invalid("INVALID_SECTION_JSON");
    try {
      content[path.slice(1)] = JSON.parse(value[path]);
    } catch {
      invalid("INVALID_SECTION_JSON");
    }
  }
  return plainJson(content);
}

function requireWriteMaterial(resource, capability, csrfToken, idempotencyKey) {
  parseEditorResource(resource);
  if (!resource.capabilities.includes(capability)) invalid("CAPABILITY_NOT_GRANTED");
  if (typeof csrfToken !== "string" || !CSRF_TOKEN.test(csrfToken)) invalid("INVALID_CSRF_TOKEN");
  if (typeof idempotencyKey !== "string" || !IDEMPOTENCY_KEY.test(idempotencyKey)) invalid("INVALID_IDEMPOTENCY_KEY");
  return {
    "content-type": "application/json",
    "idempotency-key": idempotencyKey,
    "if-match": resource.etag,
    "x-csrf-token": csrfToken,
  };
}

function requireCreateMaterial(csrfToken, idempotencyKey) {
  if (typeof csrfToken !== "string" || !CSRF_TOKEN.test(csrfToken)) invalid("INVALID_CSRF_TOKEN");
  if (typeof idempotencyKey !== "string" || !IDEMPOTENCY_KEY.test(idempotencyKey)) invalid("INVALID_IDEMPOTENCY_KEY");
  return {
    "content-type": "application/json",
    "idempotency-key": idempotencyKey,
    "x-csrf-token": csrfToken,
  };
}

function requireTrustWriteMaterial(entityTag, csrfToken, idempotencyKey) {
  const headers = requireCreateMaterial(csrfToken, idempotencyKey);
  headers["if-match"] = trustEntityTag(entityTag);
  return headers;
}

function requireAppealWriteMaterial(entityTag, csrfToken, idempotencyKey) {
  const headers = requireCreateMaterial(csrfToken, idempotencyKey);
  headers["if-match"] = appealEntityTag(entityTag);
  return headers;
}

function trustReportBody(value) {
  const result = exactKeys(value, new Set([
    "category", "demand_id", "demand_version_id", "evidence_reference_ids", "impact_codes",
    "incident_ended_at", "incident_started_at", "requested_protection_codes",
  ]));
  canonicalUuid(result.demand_id);
  canonicalUuid(result.demand_version_id);
  parseTrustReportSummary({
    category: result.category,
    evidence_reference_ids: result.evidence_reference_ids,
    impact_codes: result.impact_codes,
    incident_ended_at: result.incident_ended_at,
    incident_started_at: result.incident_started_at,
    requested_protection_codes: result.requested_protection_codes,
  });
  return result;
}

function trustTriageBody(value) {
  const result = exactKeys(value, new Set([
    "investigation_step_codes", "issue_codes", "jurisdiction_code", "priority_code",
    "proposed_hold_actions", "proposed_hold_ttl_minutes", "restricted_note", "severity_code",
  ]));
  boundedCodes(result.investigation_step_codes, TRUST_INVESTIGATION_STEP_CODE_SET, 1, 16);
  boundedCodes(result.issue_codes, TRUST_ISSUE_CODE_SET, 1, 16);
  if (!new Set(["LEGAL_REVIEW_REQUIRED", "ORGANIZATION_POLICY", "PLATFORM_INTERNAL"]).has(result.jurisdiction_code)) invalid();
  if (!new Set(["P0", "P1", "P2", "P3"]).has(result.priority_code)) invalid();
  boundedCodes(result.proposed_hold_actions, TRUST_DEMAND_ACTION_CODE_SET, 1, 3);
  if (!Number.isSafeInteger(result.proposed_hold_ttl_minutes) || result.proposed_hold_ttl_minutes < 15 || result.proposed_hold_ttl_minutes > 10080) invalid();
  if (
    typeof result.restricted_note !== "string"
    || result.restricted_note.trim().length < 1
    || result.restricted_note.length > 4000
  ) invalid();
  if (!new Set(["CRITICAL", "HIGH", "LOW", "MEDIUM"]).has(result.severity_code)) invalid();
  return result;
}

function appealApplicationBody(value) {
  const result = exactKeys(value, new Set([
    "applicant_statement", "grounds", "new_evidence_reference_ids", "requested_outcome",
  ]));
  if (typeof result.applicant_statement !== "string" || result.applicant_statement.length < 1 || result.applicant_statement.length > 4000) invalid();
  appealApplicationFacts(result.grounds, result.new_evidence_reference_ids, result.requested_outcome);
  return result;
}

function appealReviewBody(value) {
  const result = exactKeys(value, new Set([
    "assessments", "reason_codes", "remedy_delta_codes", "reviewer_note",
  ]));
  parseAppealAssessments(result.assessments);
  boundedCodes(result.reason_codes, APPEAL_REASON_CODE_SET, 1, 32);
  boundedCodes(result.remedy_delta_codes, APPEAL_REMEDY_DELTA_CODE_SET, 1, 32);
  if (typeof result.reviewer_note !== "string" || result.reviewer_note.length < 1 || result.reviewer_note.length > 4000) invalid();
  return result;
}

function samePolicyRequirement(left, right) {
  return left.selector_digest === right.selector_digest
    && left.purpose === right.purpose
    && left.role === right.role
    && left.scope_type === right.scope_type
    && left.scope_id === right.scope_id
    && left.satisfied === right.satisfied
    && left.required_policy_bundle_id === right.required_policy_bundle_id
    && left.missing_document_ids.length === right.missing_document_ids.length
    && left.missing_document_ids.every((documentId, index) => documentId === right.missing_document_ids[index]);
}

export function createPolicyAcceptanceIntent({
  me,
  requirement,
  bundle,
  affirmedDocumentIds,
  csrfToken,
  idempotencyKey,
}) {
  const exactMe = parseMe(me);
  const exactRequirement = parsePolicyRequirement(requirement);
  const exactBundle = parsePolicyBundle(bundle);
  if (
    exactRequirement.satisfied
    || !exactMe.policy_requirements.some((candidate) => samePolicyRequirement(candidate, exactRequirement))
    || exactRequirement.required_policy_bundle_id !== exactBundle.policy_bundle_id
    || exactRequirement.purpose !== exactBundle.purpose
  ) invalid("POLICY_REQUIREMENT_NOT_AVAILABLE");
  const affirmed = stringArray(affirmedDocumentIds);
  const expectedIds = exactRequirement.missing_document_ids;
  if (
    affirmed.length !== expectedIds.length
    || affirmed.some((documentId) => !expectedIds.includes(documentId))
  ) invalid("POLICY_AFFIRMATION_REQUIRED");
  const documents = new Map(exactBundle.documents.map((document) => [document.document_id, document]));
  const policyAcceptances = expectedIds.map((documentId) => {
    const document = documents.get(documentId);
    if (!document || document.legal_effect === "CONSENT_TEXT" || document.locale !== exactBundle.locale) {
      invalid("POLICY_BUNDLE_BINDING_INVALID");
    }
    return {
      document_id: document.document_id,
      content_sha256: document.content_sha256,
      affirmed: true,
    };
  });
  const headers = requireCreateMaterial(csrfToken, idempotencyKey);
  headers["if-match"] = exactMe.entity_tag;
  return {
    method: "POST",
    path: "/v1/me/policy-acceptances",
    headers,
    body: {
      policy_requirement: {
        selector_digest: exactRequirement.selector_digest,
        scope_type: exactRequirement.scope_type,
        scope_id: exactRequirement.scope_id,
      },
      policy_bundle_id: exactBundle.policy_bundle_id,
      policy_acceptances: policyAcceptances,
    },
  };
}

export function createIssueOrganizationInvitationIntent({
  organization,
  recipientEmail,
  targetRole,
  expiresAt,
  csrfToken,
  idempotencyKey,
}) {
  const exactOrganization = parseOrganizationSummary(organization);
  if (exactOrganization.status !== "ACTIVE") invalid("ORGANIZATION_NOT_ACTIVE");
  if (
    typeof recipientEmail !== "string"
    || recipientEmail.length < 3
    || recipientEmail.length > 254
    || !EMAIL_ADDRESS.test(recipientEmail)
  ) invalid("INVALID_INVITATION_RECIPIENT");
  if (!ORGANIZATION_ROLES.has(targetRole)) invalid("INVALID_ORGANIZATION_ROLE");
  const headers = requireCreateMaterial(csrfToken, idempotencyKey);
  headers["if-match"] = exactOrganization.entity_tag;
  return {
    method: "POST",
    path: `/v1/organizations/${appId(exactOrganization.organization_id)}/access-invitations`,
    headers,
    body: {
      recipient: { type: "EMAIL", value: recipientEmail },
      target_role: targetRole,
      expires_at: utcTimestamp(expiresAt),
    },
  };
}

export function createUpdateOrganizationPublicNameIntent({
  organization,
  publicName,
  csrfToken,
  idempotencyKey,
}) {
  const exactOrganization = parseOrganizationSummary(organization);
  if (exactOrganization.status !== "ACTIVE") invalid("ORGANIZATION_NOT_ACTIVE");
  const exactPublicName = organizationPublicName(publicName, "INVALID_ORGANIZATION_PUBLIC_NAME");
  if (exactPublicName === exactOrganization.public_name) invalid("ORGANIZATION_PUBLIC_NAME_UNCHANGED");
  const headers = requireCreateMaterial(csrfToken, idempotencyKey);
  headers["if-match"] = exactOrganization.entity_tag;
  return {
    method: "POST",
    path: `/v1/organizations/${appId(exactOrganization.organization_id)}/public-name`,
    headers,
    body: {
      public_name: exactPublicName,
      reason_code: ORGANIZATION_PUBLIC_NAME_REASON_CODE,
    },
  };
}

export function createOrganizationLifecycleIntent({
  resource,
  action,
  csrfToken,
  idempotencyKey,
  reasonCode,
}) {
  let exactResource;
  let route;
  if (action === "REVOKE_INVITATION") {
    exactResource = parseAccessInvitationAdmin(resource);
    if (exactResource.status !== "ISSUED") invalid("INVITATION_ACTION_NOT_AVAILABLE");
    route = `/v1/access-invitations/${appId(exactResource.invitation_id)}/revoke`;
  } else {
    exactResource = parseMembershipAdmin(resource);
    const actions = {
      SUSPEND_MEMBERSHIP: ["ACTIVE", "suspend"],
      RESUME_MEMBERSHIP: ["SUSPENDED", "resume"],
      REVOKE_MEMBERSHIP: ["ACTIVE", "revoke"],
    };
    const choice = actions[action];
    if (!choice || exactResource.status !== choice[0]) invalid("MEMBERSHIP_ACTION_NOT_AVAILABLE");
    route = `/v1/memberships/${appId(exactResource.membership_id)}/${choice[1]}`;
  }
  if (typeof reasonCode !== "string" || !ORGANIZATION_ADMIN_REASON_CODE_SET.has(reasonCode)) invalid("INVALID_REASON_CODE");
  const headers = requireCreateMaterial(csrfToken, idempotencyKey);
  headers["if-match"] = exactResource.entity_tag;
  return {
    method: "POST",
    path: route,
    headers,
    body: { reason_code: reasonCode },
  };
}

export function createAcceptOrganizationInvitationIntent({
  invitation,
  bundle,
  affirmedDocumentIds,
  grantedConsentOfferIds,
  csrfToken,
  idempotencyKey,
}) {
  let exactInvitation;
  try {
    exactInvitation = parseAccessInvitationPreview(invitation);
  } catch {
    exactInvitation = parseAccessInvitationAdmin(invitation);
    if (exactInvitation.status !== "ISSUED") invalid("INVITATION_ACTION_NOT_AVAILABLE");
  }
  if (exactInvitation.purpose !== "ORGANIZATION_MEMBERSHIP") invalid("INVITATION_PURPOSE_NOT_SUPPORTED");
  const exactBundle = parsePolicyBundle(bundle);
  if (
    exactBundle.purpose !== exactInvitation.purpose
    || exactBundle.policy_bundle_id !== exactInvitation.required_policy_bundle_id
  ) invalid("POLICY_BUNDLE_BINDING_INVALID");
  const requiredDocuments = exactBundle.documents.filter((document) => document.legal_effect !== "CONSENT_TEXT");
  const affirmed = stringArray(affirmedDocumentIds);
  const requiredIds = requiredDocuments.map((document) => document.document_id);
  if (
    requiredIds.length === 0
    || affirmed.length !== requiredIds.length
    || affirmed.some((documentId) => !requiredIds.includes(documentId))
  ) invalid("POLICY_AFFIRMATION_REQUIRED");
  const granted = stringArray(grantedConsentOfferIds);
  const offers = new Map(exactBundle.consent_offers.map((offer) => [offer.consent_offer_id, offer]));
  if (granted.some((offerId) => !offers.has(offerId))) invalid("CONSENT_OFFER_NOT_AVAILABLE");
  const documents = new Map(exactBundle.documents.map((document) => [document.document_id, document]));
  const headers = requireCreateMaterial(csrfToken, idempotencyKey);
  headers["if-match"] = exactInvitation.entity_tag;
  return {
    method: "POST",
    path: `/v1/access-invitations/${appId(exactInvitation.invitation_id)}/accept`,
    headers,
    body: {
      policy_bundle_id: exactBundle.policy_bundle_id,
      policy_acceptances: requiredDocuments.map((document) => ({
        document_id: document.document_id,
        content_sha256: document.content_sha256,
        affirmed: true,
      })),
      consent_grants: granted.map((offerId) => {
        const offer = offers.get(offerId);
        const document = documents.get(offer.document_id);
        if (!document || document.legal_effect !== "CONSENT_TEXT") invalid("POLICY_BUNDLE_BINDING_INVALID");
        return {
          consent_offer_id: offer.consent_offer_id,
          document_id: document.document_id,
          content_sha256: document.content_sha256,
          affirmed: true,
        };
      }),
    },
  };
}

export function createProfileIntent({ csrfToken, idempotencyKey }) {
  return {
    method: "POST",
    path: "/v1/app/profiles",
    headers: requireCreateMaterial(csrfToken, idempotencyKey),
    body: {},
  };
}

export function createDemandIntent({ csrfToken, idempotencyKey, taxonomyBundleId, clientReference, expiresAt }) {
  if (typeof clientReference !== "string" || clientReference.length === 0 || clientReference.length > 200) invalid("INVALID_CLIENT_REFERENCE");
  const expiry = timestamp(expiresAt);
  return {
    method: "POST",
    path: "/v1/app/demands",
    headers: requireCreateMaterial(csrfToken, idempotencyKey),
    body: {
      taxonomy_bundle_id: appId(taxonomyBundleId),
      content: {},
      client_reference: clientReference,
      expires_at: expiry,
    },
  };
}

export function createProfileDraftIntent({ resource, csrfToken, idempotencyKey, taxonomyBundleId, content }) {
  const headers = requireWriteMaterial(resource, "SAVE_DRAFT", csrfToken, idempotencyKey);
  if (resource.resource_type !== "CREATOR_PROFILE") invalid("RESOURCE_TYPE_MISMATCH");
  return {
    method: "PUT",
    path: `/v1/app/profiles/${appId(resource.object_id)}/draft`,
    headers,
    body: {
      base_version_id: resource.current_version?.version_id ?? null,
      taxonomy_bundle_id: appId(taxonomyBundleId),
      content: plainJson(object(content)),
    },
  };
}

export function createDemandDraftIntent({ resource, csrfToken, idempotencyKey, taxonomyBundleId, content }) {
  const headers = requireWriteMaterial(resource, "SAVE_DRAFT", csrfToken, idempotencyKey);
  if (resource.resource_type !== "DEMAND" || resource.current_version === null) invalid("RESOURCE_TYPE_MISMATCH");
  return {
    method: "PUT",
    path: `/v1/app/demands/${appId(resource.object_id)}/draft`,
    headers,
    body: {
      base_version_id: resource.current_version.version_id,
      taxonomy_bundle_id: appId(taxonomyBundleId),
      content: plainJson(object(content)),
    },
  };
}

export function createResourceActionIntent({ resource, action, csrfToken, idempotencyKey }) {
  const actions = resource.resource_type === "CREATOR_PROFILE"
    ? { PUBLISH: ["profiles", "publish"] }
    : { SUBMIT: ["demands", "submit"] };
  const route = actions[action];
  if (!route) invalid("CAPABILITY_NOT_GRANTED");
  const headers = requireWriteMaterial(resource, action, csrfToken, idempotencyKey);
  return {
    method: "POST",
    path: `/v1/app/${route[0]}/${appId(resource.object_id)}/${route[1]}`,
    headers,
    body: action === "PUBLISH" ? { draft_version_id: appId(resource.current_version?.version_id) } : {},
  };
}

export function createProfileLifecycleIntent({
  resource,
  action,
  reasonCode,
  csrfToken,
  idempotencyKey,
}) {
  if (resource.resource_type !== "CREATOR_PROFILE") invalid("RESOURCE_TYPE_MISMATCH");
  const suffix = {
    PAUSE: "pause",
    RESUME: "resume",
    ARCHIVE: "archive",
  }[action];
  if (!suffix) invalid("CAPABILITY_NOT_GRANTED");
  const headers = requireWriteMaterial(resource, action, csrfToken, idempotencyKey);
  if (
    (action === "PAUSE" && !PROFILE_PAUSE_REASON_CODE_SET.has(reasonCode))
    || (action === "ARCHIVE" && !PROFILE_ARCHIVE_REASON_CODE_SET.has(reasonCode))
    || (action === "RESUME" && reasonCode !== null)
  ) invalid("INVALID_REASON_CODE");
  return {
    method: "POST",
    path: `/v1/app/profiles/${appId(resource.object_id)}/${suffix}`,
    headers,
    body: action === "RESUME" ? {} : { reason_code: reasonCode },
  };
}

export function createDemandCancelIntent({
  resource,
  reasonCode,
  csrfToken,
  idempotencyKey,
}) {
  const exactResource = parseEditorResource(resource);
  if (exactResource.resource_type !== "DEMAND") invalid("RESOURCE_TYPE_MISMATCH");
  const headers = requireWriteMaterial(
    exactResource,
    "CANCEL",
    csrfToken,
    idempotencyKey,
  );
  if (!DEMAND_OWNER_CANCEL_REASON_CODE_SET.has(reasonCode)) {
    invalid("INVALID_REASON_CODE");
  }
  return {
    method: "POST",
    path: `/v1/app/demands/${appId(exactResource.object_id)}/cancel`,
    headers,
    body: { reason_code: reasonCode },
  };
}

export function createReviewClaimIntent({ queueItem, csrfToken, idempotencyKey }) {
  const exactQueueItem = parseEditorReviewQueueItem(queueItem);
  const headers = requireCreateMaterial(csrfToken, idempotencyKey);
  headers["if-match"] = exactQueueItem.etag;
  return {
    method: "POST",
    path: `/v1/app/review-queue/${canonicalUuid(exactQueueItem.demand_id)}/claim`,
    headers,
    body: {},
  };
}

export function createFinanceFundingClaimIntent({
  queueItem,
  csrfToken,
  idempotencyKey,
}) {
  const exactQueueItem = parseFinanceFundingQueueItem(queueItem);
  const headers = requireCreateMaterial(csrfToken, idempotencyKey);
  headers["if-match"] = exactQueueItem.etag;
  return {
    method: "POST",
    path: `/v1/app/finance/funding-reviews/${canonicalUuid(exactQueueItem.demand_id)}/claim`,
    headers,
    body: {},
  };
}

export function createFinanceFundingConfirmIntent({
  review,
  attestationCodes,
  csrfToken,
  idempotencyKey,
}) {
  const exactReview = parseFinanceFundingReviewEnvelope({ data: review });
  if (!exactReview.available_actions.includes("CONFIRM")) {
    invalid("FINANCE_CONFIRMATION_NOT_AVAILABLE");
  }
  const codes = stringArray(attestationCodes, new Set(FINANCE_FUNDING_ATTESTATION_CODES));
  if (
    codes.length !== FINANCE_FUNDING_ATTESTATION_CODES.length
    || codes.some((code, index) => code !== FINANCE_FUNDING_ATTESTATION_CODES[index])
  ) invalid("FINANCE_ATTESTATION_REQUIRED");
  const headers = requireCreateMaterial(csrfToken, idempotencyKey);
  headers["if-match"] = exactReview.etag;
  return {
    method: "POST",
    path: `/v1/app/finance/funding-reviews/${canonicalUuid(exactReview.funding_review_id)}/confirm`,
    headers,
    body: { attestation_codes: [...codes] },
  };
}

export function createFinanceFundingReleaseIntent({
  review,
  reasonCode,
  csrfToken,
  idempotencyKey,
}) {
  const exactReview = parseFinanceFundingReviewEnvelope({ data: review });
  if (!exactReview.available_actions.includes("RELEASE_ASSIGNMENT")) {
    invalid("FINANCE_RELEASE_NOT_AVAILABLE");
  }
  if (!FINANCE_FUNDING_RELEASE_REASON_CODE_SET.has(reasonCode)) invalid();
  const headers = requireCreateMaterial(csrfToken, idempotencyKey);
  headers["if-match"] = exactReview.etag;
  return {
    method: "POST",
    path: `/v1/app/finance/funding-reviews/${canonicalUuid(exactReview.funding_review_id)}/assignment/release`,
    headers,
    body: { reason_code: reasonCode },
  };
}

export function createFinanceFundingFindingIntent({
  review,
  disposition,
  reasonCodes,
  requiredFieldCodes,
  csrfToken,
  idempotencyKey,
}) {
  const exactReview = parseFinanceFundingReviewEnvelope({ data: review });
  if (!exactReview.available_actions.includes("SUBMIT_FINDING")) {
    invalid("FINANCE_FINDING_NOT_AVAILABLE");
  }
  const allowedReasons = disposition === "DISCREPANCY"
    ? FINANCE_FUNDING_DISCREPANCY_REASON_CODE_SET
    : disposition === "REJECTED"
      ? FINANCE_FUNDING_REJECTED_REASON_CODE_SET
      : null;
  if (allowedReasons === null) invalid();
  const reasons = boundedCodes(reasonCodes, allowedReasons, 1, 3);
  const fields = boundedCodes(
    requiredFieldCodes,
    FINANCE_FUNDING_FINDING_FIELD_CODE_SET,
    1,
    4,
  );
  if (
    reasons.some((code, index) => index > 0 && reasons[index - 1] >= code)
    || fields.some((code, index) => index > 0 && fields[index - 1] >= code)
  ) invalid();
  const headers = requireCreateMaterial(csrfToken, idempotencyKey);
  headers["if-match"] = exactReview.etag;
  return {
    method: "POST",
    path: `/v1/app/finance/funding-reviews/${canonicalUuid(exactReview.funding_review_id)}/findings`,
    headers,
    body: {
      disposition,
      reason_codes: [...reasons],
      required_field_codes: [...fields],
    },
  };
}

export function createTrustReportIntent({
  csrfToken,
  idempotencyKey,
  demandId,
  demandVersionId,
  category,
  evidenceReferenceIds,
  impactCodes,
  incidentStartedAt,
  incidentEndedAt,
  requestedProtectionCodes,
}) {
  const body = trustReportBody({
    category,
    demand_id: demandId,
    demand_version_id: demandVersionId,
    evidence_reference_ids: evidenceReferenceIds,
    impact_codes: impactCodes,
    incident_ended_at: incidentEndedAt,
    incident_started_at: incidentStartedAt,
    requested_protection_codes: requestedProtectionCodes,
  });
  return {
    method: "POST",
    path: "/v1/app/trust/reports",
    headers: requireCreateMaterial(csrfToken, idempotencyKey),
    body: plainJson(body),
  };
}

export function createTrustCaseClaimIntent({ queueItem, csrfToken, idempotencyKey }) {
  const exact = parseTrustQueueItem(queueItem);
  return {
    method: "POST",
    path: `/v1/app/trust/queue/${canonicalUuid(exact.case_id)}/claim`,
    headers: requireTrustWriteMaterial(exact.entity_tag, csrfToken, idempotencyKey),
    body: {},
  };
}

export function createTrustAssignmentReleaseIntent({ trustCase, reasonCode, csrfToken, idempotencyKey }) {
  const exact = parseTrustCaseProjection(trustCase);
  if (!TRUST_ASSIGNMENT_RELEASE_REASON_CODE_SET.has(reasonCode)) invalid();
  return {
    method: "POST",
    path: `/v1/app/trust/cases/${canonicalUuid(exact.case_id)}/assignment/release`,
    headers: requireTrustWriteMaterial(exact.entity_tag, csrfToken, idempotencyKey),
    body: { reason_code: reasonCode },
  };
}

export function createTrustTriageDraftIntent({ trustCase, triage, csrfToken, idempotencyKey }) {
  const exact = parseTrustCaseProjection(trustCase);
  return {
    method: "PUT",
    path: `/v1/app/trust/cases/${canonicalUuid(exact.case_id)}/triage-draft`,
    headers: requireTrustWriteMaterial(exact.entity_tag, csrfToken, idempotencyKey),
    body: plainJson(trustTriageBody(triage)),
  };
}

export function createTrustTriagePublishIntent({ trustCase, csrfToken, idempotencyKey }) {
  const exact = parseTrustCaseProjection(trustCase);
  if (!exact.triage_draft) invalid("TRUST_TRIAGE_DRAFT_REQUIRED");
  return {
    method: "POST",
    path: `/v1/app/trust/cases/${canonicalUuid(exact.case_id)}/triage-publish`,
    headers: requireTrustWriteMaterial(exact.entity_tag, csrfToken, idempotencyKey),
    body: { expected_draft_version: exact.triage_draft.triage_version },
  };
}

export function createTrustHoldIntent({
  trustCase,
  actionCodes,
  reasonCode,
  ttlMinutes,
  csrfToken,
  idempotencyKey,
}) {
  const exact = parseTrustCaseProjection(trustCase);
  const actions = boundedCodes(actionCodes, TRUST_DEMAND_ACTION_CODE_SET, 1, 3);
  if (!TRUST_HOLD_REASON_CODE_SET.has(reasonCode)) invalid();
  if (!Number.isSafeInteger(ttlMinutes) || ttlMinutes < 15 || ttlMinutes > 10080) invalid();
  return {
    method: "POST",
    path: `/v1/app/trust/cases/${canonicalUuid(exact.case_id)}/holds`,
    headers: requireTrustWriteMaterial(exact.entity_tag, csrfToken, idempotencyKey),
    body: { action_codes: [...actions], reason_code: reasonCode, ttl_minutes: ttlMinutes },
  };
}

export function createTrustHoldReleaseClaimIntent({ queueItem, csrfToken, idempotencyKey }) {
  const exact = parseTrustHoldReleaseQueueItem(queueItem);
  return {
    method: "POST",
    path: `/v1/app/trust/hold-release-queue/${canonicalUuid(exact.hold_id)}/claim`,
    headers: requireTrustWriteMaterial(exact.entity_tag, csrfToken, idempotencyKey),
    body: {},
  };
}

export function createTrustHoldReleaseIntent({ trustCase, reasonCode, csrfToken, idempotencyKey }) {
  const exact = parseTrustCaseProjection(trustCase);
  if (!exact.active_hold || exact.active_hold.status !== "ACTIVE") invalid("TRUST_HOLD_NOT_ACTIVE");
  if (!TRUST_HOLD_RELEASE_REASON_CODE_SET.has(reasonCode)) invalid();
  return {
    method: "POST",
    path: `/v1/app/trust/holds/${canonicalUuid(exact.active_hold.hold_id)}/release`,
    headers: requireTrustWriteMaterial(exact.active_hold.entity_tag, csrfToken, idempotencyKey),
    body: { reason_code: reasonCode },
  };
}

export function createTrustAssignedHoldReleaseIntent({ assignedHold, reasonCode, csrfToken, idempotencyKey }) {
  const exact = parseTrustAssignedHoldEnvelope({ data: assignedHold });
  if (!TRUST_HOLD_RELEASE_REASON_CODE_SET.has(reasonCode)) invalid();
  return {
    method: "POST",
    path: `/v1/app/trust/holds/${canonicalUuid(exact.hold_id)}/release`,
    headers: requireTrustWriteMaterial(exact.entity_tag, csrfToken, idempotencyKey),
    body: { reason_code: reasonCode },
  };
}

export function createTrustOutcomeIntent({
  trustCase,
  actionCodes,
  outcomeCode,
  reasonCodes,
  csrfToken,
  idempotencyKey,
}) {
  const exact = parseTrustCaseProjection(trustCase);
  const actions = boundedCodes(actionCodes, TRUST_DEMAND_ACTION_CODE_SET, 0, 3);
  if (!TRUST_OUTCOME_CODE_SET.has(outcomeCode)) invalid();
  const reasons = boundedCodes(reasonCodes, TRUST_OUTCOME_REASON_CODE_SET, 1, 8);
  return {
    method: "POST",
    path: `/v1/app/trust/cases/${canonicalUuid(exact.case_id)}/decisions`,
    headers: requireTrustWriteMaterial(exact.entity_tag, csrfToken, idempotencyKey),
    body: { action_codes: [...actions], outcome_code: outcomeCode, reason_codes: [...reasons] },
  };
}

export function createAppealOpenIntent({ sourceOutcomeVersionId, csrfToken, idempotencyKey }) {
  return {
    method: "POST",
    path: "/v1/app/appeals",
    headers: requireCreateMaterial(csrfToken, idempotencyKey),
    body: { source_outcome_version_id: canonicalUuid(sourceOutcomeVersionId) },
  };
}

export function createAppealApplicationDraftIntent({ appeal, application, csrfToken, idempotencyKey }) {
  const exact = parseAppealOwnProjection(appeal);
  if (exact.status !== "DRAFT") invalid("APPEAL_DRAFT_NOT_EDITABLE");
  return {
    method: "PUT",
    path: `/v1/app/appeals/${canonicalUuid(exact.appeal_id)}/draft`,
    headers: requireAppealWriteMaterial(exact.entity_tag, csrfToken, idempotencyKey),
    body: plainJson(appealApplicationBody(application)),
  };
}

export function createAppealSubmitIntent({ appeal, csrfToken, idempotencyKey }) {
  const exact = parseAppealOwnProjection(appeal);
  if (exact.status !== "DRAFT" || exact.application_draft === null) invalid("APPEAL_DRAFT_REQUIRED");
  return {
    method: "POST",
    path: `/v1/app/appeals/${canonicalUuid(exact.appeal_id)}/submit`,
    headers: requireAppealWriteMaterial(exact.entity_tag, csrfToken, idempotencyKey),
    body: { expected_draft_version: exact.application_draft.version },
  };
}

export function createAppealReviewClaimIntent({ queueItem, csrfToken, idempotencyKey }) {
  const exact = parseAppealQueueItem(queueItem);
  return {
    method: "POST",
    path: `/v1/app/appeal-review/queue/${canonicalUuid(exact.appeal_id)}/claim`,
    headers: requireAppealWriteMaterial(exact.entity_tag, csrfToken, idempotencyKey),
    body: {},
  };
}

export function createAppealReviewReleaseIntent({ assignedAppeal, reasonCode, csrfToken, idempotencyKey }) {
  const exact = parseAppealAssignedProjection(assignedAppeal);
  if (!APPEAL_ASSIGNMENT_RELEASE_REASON_CODE_SET.has(reasonCode)) invalid();
  return {
    method: "POST",
    path: `/v1/app/appeal-review/appeals/${canonicalUuid(exact.appeal.appeal_id)}/assignment/release`,
    headers: requireAppealWriteMaterial(exact.entity_tag, csrfToken, idempotencyKey),
    body: { reason_code: reasonCode },
  };
}

export function createAppealReviewDraftIntent({ assignedAppeal, review, csrfToken, idempotencyKey }) {
  const exact = parseAppealAssignedProjection(assignedAppeal);
  const body = plainJson(appealReviewBody(review));
  validateAppealAssessmentsAgainstApplication(body.assessments, exact.application);
  return {
    method: "PUT",
    path: `/v1/app/appeal-review/appeals/${canonicalUuid(exact.appeal.appeal_id)}/review-draft`,
    headers: requireAppealWriteMaterial(exact.entity_tag, csrfToken, idempotencyKey),
    body,
  };
}

export function createAppealDecisionIntent({ assignedAppeal, decisionCode, csrfToken, idempotencyKey }) {
  const exact = parseAppealAssignedProjection(assignedAppeal);
  if (exact.review_draft === null) invalid("APPEAL_REVIEW_DRAFT_REQUIRED");
  if (!APPEAL_DECISION_CODE_SET.has(decisionCode)) invalid();
  validateAppealDecisionShape(decisionCode, exact.review_draft.assessments, exact.review_draft.remedy_delta_codes);
  return {
    method: "POST",
    path: `/v1/app/appeal-review/appeals/${canonicalUuid(exact.appeal.appeal_id)}/decide`,
    headers: requireAppealWriteMaterial(exact.entity_tag, csrfToken, idempotencyKey),
    body: {
      decision_code: decisionCode,
      expected_review_draft_version: exact.review_draft.version,
    },
  };
}

export function createFindingIntent({ resource, assignmentId, csrfToken, idempotencyKey, reasonCodes, requiredFieldPaths }) {
  const headers = requireWriteMaterial(resource, "RECORD_FINDINGS", csrfToken, idempotencyKey);
  if (resource.resource_type !== "DEMAND") invalid("RESOURCE_TYPE_MISMATCH");
  const reasons = stringArray(reasonCodes, REVIEW_REASON_CODE_SET);
  if (reasons.length === 0) invalid();
  if (!resource.review_assignment || resource.review_assignment.assignment_id !== assignmentId) invalid();
  const fields = stringArray(requiredFieldPaths, new Set(DEMAND_EDITABLE_PATHS));
  if (reasons.length === 0 || fields.length === 0) invalid("INVALID_FINDING");
  return {
    method: "POST",
    path: `/v1/app/demands/${appId(resource.object_id)}/review-assignments/${appId(assignmentId)}/findings`,
    headers,
    body: { reason_codes: [...reasons], required_field_paths: [...fields] },
  };
}

export function createReviewAssignmentReleaseIntent({
  resource,
  assignmentId,
  csrfToken,
  idempotencyKey,
  reasonCode,
}) {
  const headers = requireWriteMaterial(resource, "RECORD_FINDINGS", csrfToken, idempotencyKey);
  if (resource.resource_type !== "DEMAND") invalid("RESOURCE_TYPE_MISMATCH");
  const demandId = canonicalUuid(resource.object_id);
  const exactAssignmentId = canonicalUuid(assignmentId);
  if (!resource.review_assignment || resource.review_assignment.assignment_id !== exactAssignmentId) invalid();
  if (!REVIEW_ASSIGNMENT_RELEASE_REASON_CODE_SET.has(reasonCode)) invalid();
  return {
    method: "POST",
    path: `/v1/app/demands/${demandId}/review-assignments/${exactAssignmentId}/release`,
    headers,
    body: { reason_code: reasonCode },
  };
}

export function createVerifyIntent({
  resource,
  assignmentId,
  csrfToken,
  idempotencyKey,
  budgetHealthCode,
  riskCode,
  evidenceCodes,
}) {
  const headers = requireWriteMaterial(resource, "RECORD_FINDINGS", csrfToken, idempotencyKey);
  if (resource.resource_type !== "DEMAND") invalid("RESOURCE_TYPE_MISMATCH");
  const demandId = canonicalUuid(resource.object_id);
  const exactAssignmentId = canonicalUuid(assignmentId);
  if (!resource.review_assignment || resource.review_assignment.assignment_id !== exactAssignmentId) invalid();
  if (!VERIFY_BUDGET_HEALTH_CODE_SET.has(budgetHealthCode)) invalid();
  if (!VERIFY_RISK_CODE_SET.has(riskCode)) invalid();
  const evidence = stringArray(evidenceCodes, VERIFY_EVIDENCE_CODE_SET);
  if (evidence.length === 0) invalid();
  return {
    method: "POST",
    path: `/v1/app/demands/${demandId}/review-assignments/${exactAssignmentId}/verify`,
    headers,
    body: {
      budget_health_code: budgetHealthCode,
      risk_code: riskCode,
      evidence_codes: [...evidence],
    },
  };
}

export function createAccountAdminIntent({ account, action, csrfToken, idempotencyKey, reasonCode }) {
  const exactAccount = parseAccountAdmin(account);
  const actions = {
    SUSPEND: "suspend",
    RESUME: "resume",
    REVOKE_ALL_SESSIONS: "revoke-all-sessions",
  };
  const suffix = actions[action];
  if (
    !suffix
    || exactAccount.is_self
    || (action === "SUSPEND" && exactAccount.status !== "ACTIVE")
    || (action === "RESUME" && exactAccount.status !== "SUSPENDED")
    || !ACCOUNT_ADMIN_REASON_CODE_SET.has(reasonCode)
  ) invalid("ACCOUNT_ACTION_NOT_AVAILABLE");
  const headers = requireCreateMaterial(csrfToken, idempotencyKey);
  headers["if-match"] = exactAccount.entity_tag;
  return {
    method: "POST",
    path: `/v1/app/admin/accounts/${canonicalUuid(exactAccount.user_id)}/${suffix}`,
    headers,
    body: { reason_code: reasonCode },
  };
}

export function createPlatformDutyIntent({
  account,
  dutyCode,
  action,
  csrfToken,
  idempotencyKey,
  reasonCode,
}) {
  const exactAccount = parseAccountAdmin(account);
  if (
    exactAccount.is_self
    || !ACCOUNT_ADMIN_PLATFORM_DUTY_CODE_SET.has(dutyCode)
    || !new Set(["GRANT", "REVOKE"]).has(action)
    || (action === "GRANT" && exactAccount.role_codes.includes(dutyCode))
    || (action === "REVOKE" && !exactAccount.role_codes.includes(dutyCode))
    || !ACCOUNT_ADMIN_REASON_CODE_SET.has(reasonCode)
  ) invalid("ACCOUNT_ACTION_NOT_AVAILABLE");
  const headers = requireCreateMaterial(csrfToken, idempotencyKey);
  headers["if-match"] = exactAccount.entity_tag;
  return {
    method: "POST",
    path: `/v1/app/admin/accounts/${canonicalUuid(exactAccount.user_id)}/platform-duties/${dutyCode}/${action.toLowerCase()}`,
    headers,
    body: { reason_code: reasonCode },
  };
}

function stable(value) {
  if (Array.isArray(value)) return `[${value.map(stable).join(",")}]`;
  if (value && typeof value === "object") return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stable(value[key])}`).join(",")}}`;
  return JSON.stringify(value);
}

export function parseThreeWayConflict(value, currentEtag) {
  const envelope = exactKeys(value, new Set(["error"]));
  const error = exactKeys(envelope.error, new Set(["code", "details"]));
  if (error.code !== "PRECONDITION_FAILED") invalid();
  const details = exactKeys(error.details, new Set(["current", "base", "yours"]));
  for (const name of ["current", "base", "yours"]) {
    const surface = exactKeys(details[name], new Set(["version_id", "content"]));
    if (surface.version_id !== null) appId(surface.version_id);
    object(surface.content);
  }
  text(currentEtag);
  const keys = [...new Set([
    ...Object.keys(details.current.content),
    ...Object.keys(details.base.content),
    ...Object.keys(details.yours.content),
  ])].sort();
  const changedPaths = keys
    .filter((key) => stable(details.current.content[key]) !== stable(details.yours.content[key]))
    .map((key) => `/${key}`);
  return {
    current: details.current,
    base: details.base,
    yours: details.yours,
    currentEtag,
    changedPaths,
  };
}

export function bindConflictToCurrentResource(conflict, resource) {
  const exactConflict = exactKeys(conflict, new Set([
    "current", "base", "yours", "currentEtag", "changedPaths",
  ]));
  for (const name of ["current", "base", "yours"]) {
    const surface = exactKeys(exactConflict[name], new Set(["version_id", "content"]));
    if (surface.version_id !== null) appId(surface.version_id);
    object(surface.content);
  }
  text(exactConflict.currentEtag);
  stringArray(exactConflict.changedPaths);
  const current = parseEditorResource(resource);
  if (
    current.etag !== exactConflict.currentEtag
    || current.current_version?.version_id !== exactConflict.current.version_id
    || stable(current.current_version?.content ?? {}) !== stable(exactConflict.current.content)
  ) invalid("CONFLICT_REFRESH_MISMATCH");
  return current;
}

function parseWriteIntent(value) {
  const result = exactKeys(value, new Set(["method", "path", "headers", "body"]));
  if (!new Set(["POST", "PUT"]).has(result.method)) invalid();
  const appRoutes = [
    [/^\/v1\/app\/profiles$/, new Set(["POST"])],
    [/^\/v1\/app\/profiles\/[A-Za-z0-9][A-Za-z0-9_-]{15,127}\/draft$/, new Set(["PUT"])],
    [/^\/v1\/app\/profiles\/[A-Za-z0-9][A-Za-z0-9_-]{15,127}\/publish$/, new Set(["POST"])],
    [PROFILE_LIFECYCLE_ROUTE, new Set(["POST"])],
    [/^\/v1\/app\/demands$/, new Set(["POST"])],
    [/^\/v1\/app\/demands\/[A-Za-z0-9][A-Za-z0-9_-]{15,127}\/draft$/, new Set(["PUT"])],
    [/^\/v1\/app\/demands\/[A-Za-z0-9][A-Za-z0-9_-]{15,127}\/submit$/, new Set(["POST"])],
    [DEMAND_CANCEL_ROUTE, new Set(["POST"])],
    [/^\/v1\/app\/demands\/[A-Za-z0-9][A-Za-z0-9_-]{15,127}\/review-assignments\/[A-Za-z0-9][A-Za-z0-9_-]{15,127}\/findings$/, new Set(["POST"])],
    [REVIEW_CLAIM_ROUTE, new Set(["POST"])],
    [REVIEW_RELEASE_ROUTE, new Set(["POST"])],
    [REVIEW_VERIFY_ROUTE, new Set(["POST"])],
    [ACCOUNT_ADMIN_ROUTE, new Set(["POST"])],
    [ACCOUNT_DUTY_ROUTE, new Set(["POST"])],
    [FINANCE_FUNDING_CLAIM_ROUTE, new Set(["POST"])],
    [FINANCE_FUNDING_CONFIRM_ROUTE, new Set(["POST"])],
    [FINANCE_FUNDING_RELEASE_ROUTE, new Set(["POST"])],
    [FINANCE_FUNDING_FINDING_ROUTE, new Set(["POST"])],
    [/^\/v1\/app\/trust\/reports$/, new Set(["POST"])],
    [TRUST_CASE_CLAIM_ROUTE, new Set(["POST"])],
    [TRUST_CASE_WRITE_ROUTE, new Set(["POST", "PUT"])],
    [TRUST_HOLD_WRITE_ROUTE, new Set(["POST"])],
    [APPEAL_OPEN_ROUTE, new Set(["POST"])],
    [APPEAL_APPLICANT_WRITE_ROUTE, new Set(["POST", "PUT"])],
    [APPEAL_REVIEW_CLAIM_ROUTE, new Set(["POST"])],
    [APPEAL_REVIEW_WRITE_ROUTE, new Set(["POST", "PUT"])],
    [MATCHING_INVITATION_WRITE_ROUTE, new Set(["POST"])],
    [MATCHING_SELECTION_WRITE_ROUTE, new Set(["POST"])],
    [MATCHING_ASSIGNMENT_CLAIM_ROUTE, new Set(["POST"])],
    [MATCHING_REVIEW_CLAIM_ROUTE, new Set(["POST"])],
    [MATCHING_REVIEW_RELEASE_ROUTE, new Set(["POST"])],
    [MATCHING_REVIEW_CREATE_INVITATION_ROUTE, new Set(["POST"])],
    [MATCHING_REVIEW_PUBLISH_INVITATION_ROUTE, new Set(["POST"])],
    [MATCHING_REVIEW_INVALIDATE_ATTEMPT_ROUTE, new Set(["POST"])],
  ];
  if (typeof result.path !== "string" || !appRoutes.some(([pattern, methods]) => pattern.test(result.path) && methods.has(result.method))) invalid();
  const isTrustReport = result.path === "/v1/app/trust/reports";
  const isTrustWrite = isTrustReport
    || TRUST_CASE_CLAIM_ROUTE.test(result.path)
    || TRUST_CASE_WRITE_ROUTE.test(result.path)
    || TRUST_HOLD_WRITE_ROUTE.test(result.path);
  const isAppealOpen = result.path === "/v1/app/appeals";
  const appealApplicantMatch = result.path.match(APPEAL_APPLICANT_WRITE_ROUTE);
  const appealReviewClaimMatch = result.path.match(APPEAL_REVIEW_CLAIM_ROUTE);
  const appealReviewWriteMatch = result.path.match(APPEAL_REVIEW_WRITE_ROUTE);
  const isAppealWrite = isAppealOpen || appealApplicantMatch || appealReviewClaimMatch || appealReviewWriteMatch;
  const matchingInvitationMatch = result.path.match(MATCHING_INVITATION_WRITE_ROUTE);
  const matchingSelectionMatch = result.path.match(MATCHING_SELECTION_WRITE_ROUTE);
  const matchingAssignmentClaim = MATCHING_ASSIGNMENT_CLAIM_ROUTE.test(result.path);
  const matchingReviewClaim = MATCHING_REVIEW_CLAIM_ROUTE.test(result.path);
  const matchingReviewRelease = MATCHING_REVIEW_RELEASE_ROUTE.test(result.path);
  const matchingReviewCreate = result.path.match(MATCHING_REVIEW_CREATE_INVITATION_ROUTE);
  const matchingReviewPublish = result.path.match(MATCHING_REVIEW_PUBLISH_INVITATION_ROUTE);
  const matchingReviewInvalidate = result.path.match(MATCHING_REVIEW_INVALIDATE_ATTEMPT_ROUTE);
  const isMatchingWrite = matchingInvitationMatch || matchingSelectionMatch
    || matchingAssignmentClaim || matchingReviewClaim || matchingReviewRelease
    || matchingReviewCreate || matchingReviewPublish || matchingReviewInvalidate;
  const isCreate = result.path === "/v1/app/profiles" || result.path === "/v1/app/demands"
    || isTrustReport || isAppealOpen || matchingAssignmentClaim || matchingReviewClaim;
  const isAccountAdmin = result.path.startsWith("/v1/app/admin/accounts/");
  const profileLifecycleMatch = result.path.match(PROFILE_LIFECYCLE_ROUTE);
  const demandCancelMatch = result.path.match(DEMAND_CANCEL_ROUTE);
  const reviewClaimMatch = result.path.match(REVIEW_CLAIM_ROUTE);
  const reviewReleaseMatch = result.path.match(REVIEW_RELEASE_ROUTE);
  const reviewVerifyMatch = result.path.match(REVIEW_VERIFY_ROUTE);
  const financeClaimMatch = result.path.match(FINANCE_FUNDING_CLAIM_ROUTE);
  const financeConfirmMatch = result.path.match(FINANCE_FUNDING_CONFIRM_ROUTE);
  const financeReleaseMatch = result.path.match(FINANCE_FUNDING_RELEASE_ROUTE);
  const financeFindingMatch = result.path.match(FINANCE_FUNDING_FINDING_ROUTE);
  const isFinding = result.path.endsWith("/findings");
  const headers = exactKeys(result.headers, new Set(isCreate
    ? ["content-type", "idempotency-key", "x-csrf-token"]
    : ["content-type", "idempotency-key", "if-match", "x-csrf-token"]));
  if (headers["content-type"] !== "application/json") invalid();
  if (!IDEMPOTENCY_KEY.test(headers["idempotency-key"]) || !CSRF_TOKEN.test(headers["x-csrf-token"])) invalid();
  if (isMatchingWrite) {
    if (
      result.method !== "POST"
      || (!isCreate && !/^"v[1-9][0-9]*"$/.test(headers["if-match"]))
      || !MATCHING_CSRF_TOKEN.test(headers["x-csrf-token"])
    ) invalid();
    if (matchingAssignmentClaim) {
      const body = exactKeys(result.body, new Set(["demand_id"]));
      appId(body.demand_id);
    } else if (matchingReviewClaim || matchingReviewRelease) {
      exactKeys(result.body, new Set());
    } else if (matchingReviewCreate) {
      const body = exactKeys(result.body, new Set(["match_run_id", "creator_user_id", "expires_at"]));
      appId(body.match_run_id);
      appId(body.creator_user_id);
      if (body.match_run_id !== matchingReviewCreate[1]) invalid();
      utcTimestamp(body.expires_at);
    } else if (matchingReviewPublish) {
      const body = exactKeys(result.body, new Set(["snapshot_sha256"]));
      sha256(body.snapshot_sha256);
    } else if (matchingReviewInvalidate) {
      const body = exactKeys(result.body, new Set(["reason_code", "input_baseline_sha256"]));
      if (body.reason_code !== "REVIEW_INVALIDATED") invalid();
      sha256(body.input_baseline_sha256);
    } else if (matchingInvitationMatch) {
      const action = matchingInvitationMatch[2];
      if (action === "accept") {
        const body = exactKeys(result.body, new Set(["snapshot_sha256"]));
        sha256(body.snapshot_sha256);
      } else {
        const body = exactKeys(result.body, new Set(["snapshot_sha256", "reason_code", "note"]));
        sha256(body.snapshot_sha256);
        const expectedReason = action === "decline" ? "RECIPIENT_DECLINED" : "RECIPIENT_WITHDREW";
        if (body.reason_code !== expectedReason || body.note !== null) invalid();
      }
    } else if (matchingSelectionMatch?.[3] === "choose") {
      const body = exactKeys(result.body, new Set([
        "invitation_id", "selection_basis_code", "current_invitation_set_sha256",
        "candidate_selector_assignment_id", "candidate_selector_assignment_version",
      ]));
      appId(body.invitation_id);
      appId(body.candidate_selector_assignment_id);
      if (
        !Number.isSafeInteger(body.candidate_selector_assignment_version)
        || body.candidate_selector_assignment_version < 1
        || body.candidate_selector_assignment_version > 2147483647
      ) invalid();
      if (!new Set(["CAPABILITY_SUMMARY_FIT", "DELIVERY_APPROACH_FIT", "SCHEDULE_FIT"]).has(body.selection_basis_code)) invalid();
      sha256(body.current_invitation_set_sha256);
    } else if (matchingSelectionMatch?.[3] === "close") {
      const body = exactKeys(result.body, new Set([
        "reason_code", "current_invitation_set_sha256", "candidate_selector_assignment_id",
        "candidate_selector_assignment_version",
      ]));
      if (body.reason_code !== "OWNER_CLOSED") invalid();
      appId(body.candidate_selector_assignment_id);
      if (
        !Number.isSafeInteger(body.candidate_selector_assignment_version)
        || body.candidate_selector_assignment_version < 1
        || body.candidate_selector_assignment_version > 2147483647
      ) invalid();
      sha256(body.current_invitation_set_sha256);
    } else {
      invalid();
    }
  } else if (isAppealWrite) {
    if (isAppealOpen) {
      if (result.method !== "POST") invalid();
      const body = exactKeys(result.body, new Set(["source_outcome_version_id"]));
      canonicalUuid(body.source_outcome_version_id);
    } else {
      appealEntityTag(headers["if-match"]);
      if (appealReviewClaimMatch) {
        if (result.method !== "POST") invalid();
        exactKeys(result.body, new Set());
      } else if (appealApplicantMatch?.[2] === "draft") {
        if (result.method !== "PUT") invalid();
        appealApplicationBody(result.body);
      } else if (appealApplicantMatch?.[2] === "submit") {
        if (result.method !== "POST") invalid();
        const body = exactKeys(result.body, new Set(["expected_draft_version"]));
        if (!Number.isSafeInteger(body.expected_draft_version) || body.expected_draft_version < 1) invalid();
      } else if (appealReviewWriteMatch?.[2] === "assignment/release") {
        if (result.method !== "POST") invalid();
        const body = exactKeys(result.body, new Set(["reason_code"]));
        if (!APPEAL_ASSIGNMENT_RELEASE_REASON_CODE_SET.has(body.reason_code)) invalid();
      } else if (appealReviewWriteMatch?.[2] === "review-draft") {
        if (result.method !== "PUT") invalid();
        appealReviewBody(result.body);
      } else if (appealReviewWriteMatch?.[2] === "decide") {
        if (result.method !== "POST") invalid();
        const body = exactKeys(result.body, new Set(["decision_code", "expected_review_draft_version"]));
        if (!APPEAL_DECISION_CODE_SET.has(body.decision_code)) invalid();
        if (!Number.isSafeInteger(body.expected_review_draft_version) || body.expected_review_draft_version < 1) invalid();
      } else {
        invalid();
      }
    }
  } else if (isTrustWrite) {
    if ((result.path.endsWith("/triage-draft") && result.method !== "PUT")
      || (!result.path.endsWith("/triage-draft") && result.method !== "POST")) invalid();
    if (!isTrustReport) trustEntityTag(headers["if-match"]);
    if (isTrustReport) {
      trustReportBody(result.body);
    } else if (result.path.endsWith("/claim")) {
      exactKeys(result.body, new Set());
    } else if (result.path.endsWith("/triage-publish")) {
      const body = exactKeys(result.body, new Set(["expected_draft_version"]));
      if (!Number.isSafeInteger(body.expected_draft_version) || body.expected_draft_version < 1) invalid();
    } else if (result.path.endsWith("/assignment/release")) {
      const body = exactKeys(result.body, new Set(["reason_code"]));
      if (!TRUST_ASSIGNMENT_RELEASE_REASON_CODE_SET.has(body.reason_code)) invalid();
    } else if (result.path.endsWith("/triage-draft")) {
      if (result.method !== "PUT") invalid();
      trustTriageBody(result.body);
    } else if (result.path.endsWith("/holds")) {
      const body = exactKeys(result.body, new Set(["action_codes", "reason_code", "ttl_minutes"]));
      boundedCodes(body.action_codes, TRUST_DEMAND_ACTION_CODE_SET, 1, 3);
      if (!TRUST_HOLD_REASON_CODE_SET.has(body.reason_code)) invalid();
      if (!Number.isSafeInteger(body.ttl_minutes) || body.ttl_minutes < 15 || body.ttl_minutes > 10080) invalid();
    } else if (result.path.endsWith("/release")) {
      const body = exactKeys(result.body, new Set(["reason_code"]));
      if (!TRUST_HOLD_RELEASE_REASON_CODE_SET.has(body.reason_code)) invalid();
    } else if (result.path.endsWith("/decisions")) {
      const body = exactKeys(result.body, new Set(["action_codes", "outcome_code", "reason_codes"]));
      boundedCodes(body.action_codes, TRUST_DEMAND_ACTION_CODE_SET, 0, 3);
      if (!TRUST_OUTCOME_CODE_SET.has(body.outcome_code)) invalid();
      boundedCodes(body.reason_codes, TRUST_OUTCOME_REASON_CODE_SET, 1, 8);
    } else {
      invalid();
    }
  } else if (demandCancelMatch) {
    if (!/^"demand-[1-9][0-9]*-[a-f0-9]{24}"$/.test(headers["if-match"])) invalid();
    const body = exactKeys(result.body, new Set(["reason_code"]));
    if (!DEMAND_OWNER_CANCEL_REASON_CODE_SET.has(body.reason_code)) invalid();
  } else if (profileLifecycleMatch) {
    if (!/^"creator_profile-[1-9][0-9]*-[a-f0-9]{24}"$/.test(headers["if-match"])) invalid();
    if (profileLifecycleMatch[2] === "resume") {
      exactKeys(result.body, new Set());
    } else {
      const body = exactKeys(result.body, new Set(["reason_code"]));
      const allowed = profileLifecycleMatch[2] === "pause"
        ? PROFILE_PAUSE_REASON_CODE_SET
        : PROFILE_ARCHIVE_REASON_CODE_SET;
      if (!allowed.has(body.reason_code)) invalid();
    }
  } else if (reviewClaimMatch) {
    if (!/^"demand-[1-9][0-9]*-review-queue"$/.test(headers["if-match"])) invalid();
    exactKeys(result.body, new Set());
  } else if (reviewReleaseMatch) {
    if (!/^"demand-[1-9][0-9]*-[a-f0-9]{24}"$/.test(headers["if-match"])) invalid();
    const body = exactKeys(result.body, new Set(["reason_code"]));
    if (!REVIEW_ASSIGNMENT_RELEASE_REASON_CODE_SET.has(body.reason_code)) invalid();
  } else if (financeClaimMatch) {
    if (!/^"(?:demand-[1-9][0-9]*-finance-queue|funding-review-[1-9][0-9]*)"$/.test(headers["if-match"])) invalid();
    exactKeys(result.body, new Set());
  } else if (financeConfirmMatch) {
    if (!/^"funding-review-[1-9][0-9]*"$/.test(headers["if-match"])) invalid();
    const body = exactKeys(result.body, new Set(["attestation_codes"]));
    const codes = stringArray(body.attestation_codes, new Set(FINANCE_FUNDING_ATTESTATION_CODES));
    if (
      codes.length !== FINANCE_FUNDING_ATTESTATION_CODES.length
      || codes.some((code, index) => code !== FINANCE_FUNDING_ATTESTATION_CODES[index])
    ) invalid();
  } else if (financeReleaseMatch) {
    if (!/^"funding-review-[1-9][0-9]*"$/.test(headers["if-match"])) invalid();
    const body = exactKeys(result.body, new Set(["reason_code"]));
    if (!FINANCE_FUNDING_RELEASE_REASON_CODE_SET.has(body.reason_code)) invalid();
  } else if (financeFindingMatch) {
    if (!/^"funding-review-[1-9][0-9]*"$/.test(headers["if-match"])) invalid();
    const body = exactKeys(
      result.body,
      new Set(["disposition", "reason_codes", "required_field_codes"]),
    );
    const allowedReasons = body.disposition === "DISCREPANCY"
      ? FINANCE_FUNDING_DISCREPANCY_REASON_CODE_SET
      : body.disposition === "REJECTED"
        ? FINANCE_FUNDING_REJECTED_REASON_CODE_SET
        : null;
    if (allowedReasons === null) invalid();
    const reasons = boundedCodes(body.reason_codes, allowedReasons, 1, 3);
    const fields = boundedCodes(
      body.required_field_codes,
      FINANCE_FUNDING_FINDING_FIELD_CODE_SET,
      1,
      4,
    );
    if (
      reasons.some((code, index) => index > 0 && reasons[index - 1] >= code)
      || fields.some((code, index) => index > 0 && fields[index - 1] >= code)
    ) invalid();
  } else if (reviewVerifyMatch) {
    if (!/^"demand-[1-9][0-9]*-[a-f0-9]{24}"$/.test(headers["if-match"])) invalid();
    const body = exactKeys(result.body, new Set(["budget_health_code", "risk_code", "evidence_codes"]));
    if (!VERIFY_BUDGET_HEALTH_CODE_SET.has(body.budget_health_code)) invalid();
    if (!VERIFY_RISK_CODE_SET.has(body.risk_code)) invalid();
    if (stringArray(body.evidence_codes, VERIFY_EVIDENCE_CODE_SET).length === 0) invalid();
  } else if (isAccountAdmin) {
    text(headers["if-match"]);
    const body = exactKeys(result.body, new Set(["reason_code"]));
    if (!ACCOUNT_ADMIN_REASON_CODE_SET.has(body.reason_code)) invalid();
  } else if (isFinding) {
    text(headers["if-match"]);
    const body = exactKeys(result.body, new Set(["reason_codes", "required_field_paths"]));
    if (stringArray(body.reason_codes, REVIEW_REASON_CODE_SET).length === 0) invalid();
    if (stringArray(body.required_field_paths, new Set(DEMAND_EDITABLE_PATHS)).length === 0) invalid();
  } else {
    if (!isCreate) text(headers["if-match"]);
    object(result.body);
  }
  return result;
}

export function serializePendingIntent(value) {
  const encoded = JSON.stringify(value);
  if (new TextEncoder().encode(encoded).byteLength > PENDING_MAX_BYTES) invalid("PENDING_INTENT_TOO_LARGE");
  if (parsePendingIntent(encoded, Date.parse(value.saved_at)) === null) invalid("INVALID_PENDING_INTENT");
  return encoded;
}

export function parsePendingIntent(encoded, now = Date.now()) {
  if (typeof encoded !== "string" || new TextEncoder().encode(encoded).byteLength > PENDING_MAX_BYTES) return null;
  try {
    const value = exactKeys(JSON.parse(encoded), new Set(["version", "saved_at", "resource_type", "object_id", "label", "intent"]));
    if (value.version !== 1 || !new Set(["CREATOR_PROFILE", "DEMAND", "ACCOUNT_ADMIN", "REVIEW_CLAIM", "FINANCE_FUNDING", "MATCHING_INVITATION", "MATCHING_SELECTION", "MATCHING_ASSIGNMENT", "MATCHING_REVIEW", "TRUST_REPORT", "TRUST_CASE", "TRUST_HOLD", "APPEAL", "APPEAL_REVIEW"]).has(value.resource_type)) return null;
    if (new Set(["ACCOUNT_ADMIN", "REVIEW_CLAIM", "FINANCE_FUNDING", "TRUST_REPORT", "TRUST_CASE", "TRUST_HOLD", "APPEAL", "APPEAL_REVIEW"]).has(value.resource_type)) canonicalUuid(value.object_id);
    else appId(value.object_id);
    text(value.label);
    const savedAt = Date.parse(timestamp(value.saved_at));
    if (savedAt > now + 5 * 60 * 1000 || now - savedAt > PENDING_MAX_AGE_MS) return null;
    parseWriteIntent(value.intent);
    const reviewClaimMatch = value.intent.path.match(REVIEW_CLAIM_ROUTE);
    const reviewFindingMatch = value.intent.path.match(REVIEW_FINDING_ROUTE);
    const reviewReleaseMatch = value.intent.path.match(REVIEW_RELEASE_ROUTE);
    const reviewVerifyMatch = value.intent.path.match(REVIEW_VERIFY_ROUTE);
    const demandCancelMatch = value.intent.path.match(DEMAND_CANCEL_ROUTE);
    const accountAdminMatch = value.intent.path.match(ACCOUNT_ADMIN_ROUTE);
    const accountDutyMatch = value.intent.path.match(ACCOUNT_DUTY_ROUTE);
    const financeClaimMatch = value.intent.path.match(FINANCE_FUNDING_CLAIM_ROUTE);
    const financeConfirmMatch = value.intent.path.match(FINANCE_FUNDING_CONFIRM_ROUTE);
    const financeReleaseMatch = value.intent.path.match(FINANCE_FUNDING_RELEASE_ROUTE);
    const financeFindingMatch = value.intent.path.match(FINANCE_FUNDING_FINDING_ROUTE);
    const trustReport = value.intent.path === "/v1/app/trust/reports";
    const trustCaseClaim = value.intent.path.match(TRUST_CASE_CLAIM_ROUTE);
    const trustCaseWrite = value.intent.path.match(TRUST_CASE_WRITE_ROUTE);
    const trustHoldWrite = value.intent.path.match(TRUST_HOLD_WRITE_ROUTE);
    const appealOpen = value.intent.path === "/v1/app/appeals";
    const appealApplicantWrite = value.intent.path.match(APPEAL_APPLICANT_WRITE_ROUTE);
    const appealReviewClaim = value.intent.path.match(APPEAL_REVIEW_CLAIM_ROUTE);
    const appealReviewWrite = value.intent.path.match(APPEAL_REVIEW_WRITE_ROUTE);
    const matchingInvitationWrite = value.intent.path.match(MATCHING_INVITATION_WRITE_ROUTE);
    const matchingSelectionWrite = value.intent.path.match(MATCHING_SELECTION_WRITE_ROUTE);
    const matchingAssignmentClaim = MATCHING_ASSIGNMENT_CLAIM_ROUTE.test(value.intent.path);
    const matchingReviewClaim = MATCHING_REVIEW_CLAIM_ROUTE.test(value.intent.path);
    const matchingReviewRelease = MATCHING_REVIEW_RELEASE_ROUTE.test(value.intent.path);
    const matchingReviewCreate = value.intent.path.match(MATCHING_REVIEW_CREATE_INVITATION_ROUTE);
    const matchingReviewPublish = value.intent.path.match(MATCHING_REVIEW_PUBLISH_INVITATION_ROUTE);
    const matchingReviewInvalidate = value.intent.path.match(MATCHING_REVIEW_INVALIDATE_ATTEMPT_ROUTE);
    if (appealApplicantWrite?.[2] === "draft" || appealReviewWrite?.[2] === "review-draft") return null;
    if (
      (value.resource_type === "REVIEW_CLAIM" && (!reviewClaimMatch || reviewClaimMatch[1] !== value.object_id))
      || (reviewClaimMatch && value.resource_type !== "REVIEW_CLAIM")
      || (reviewFindingMatch && (value.resource_type !== "DEMAND" || reviewFindingMatch[1] !== value.object_id))
      || (reviewReleaseMatch && (value.resource_type !== "DEMAND" || reviewReleaseMatch[1] !== value.object_id))
      || (reviewVerifyMatch && (value.resource_type !== "DEMAND" || reviewVerifyMatch[1] !== value.object_id))
      || (demandCancelMatch && (value.resource_type !== "DEMAND" || demandCancelMatch[1] !== value.object_id))
      || (value.resource_type === "ACCOUNT_ADMIN" && (
        (!accountAdminMatch && !accountDutyMatch)
        || (accountAdminMatch?.[1] ?? accountDutyMatch?.[1]) !== value.object_id
      ))
      || ((accountAdminMatch || accountDutyMatch) && value.resource_type !== "ACCOUNT_ADMIN")
      || (value.resource_type === "FINANCE_FUNDING" && (
        (!financeClaimMatch && !financeConfirmMatch && !financeReleaseMatch && !financeFindingMatch)
        || (financeClaimMatch?.[1] ?? financeConfirmMatch?.[1] ?? financeReleaseMatch?.[1] ?? financeFindingMatch?.[1]) !== value.object_id
      ))
      || ((financeClaimMatch || financeConfirmMatch || financeReleaseMatch || financeFindingMatch) && value.resource_type !== "FINANCE_FUNDING")
      || (value.resource_type === "TRUST_REPORT" && (!trustReport || value.intent.body.demand_id !== value.object_id))
      || (trustReport && value.resource_type !== "TRUST_REPORT")
      || (value.resource_type === "TRUST_CASE" && (
        (!trustCaseClaim && !trustCaseWrite && !trustHoldWrite)
        || ((trustCaseClaim || trustCaseWrite) && (trustCaseClaim?.[1] ?? trustCaseWrite?.[1]) !== value.object_id)
      ))
      || ((trustCaseClaim || trustCaseWrite) && value.resource_type !== "TRUST_CASE")
      || (value.resource_type === "TRUST_HOLD" && (!trustHoldWrite || trustHoldWrite[1] !== value.object_id))
      || (trustHoldWrite && !new Set(["TRUST_CASE", "TRUST_HOLD"]).has(value.resource_type))
      || (value.resource_type === "APPEAL" && (
        (!appealOpen && !appealApplicantWrite)
        || (appealOpen && value.intent.body.source_outcome_version_id !== value.object_id)
        || (appealApplicantWrite && appealApplicantWrite[1] !== value.object_id)
      ))
      || ((appealOpen || appealApplicantWrite) && value.resource_type !== "APPEAL")
      || (value.resource_type === "APPEAL_REVIEW" && (
        (!appealReviewClaim && !appealReviewWrite)
        || (appealReviewClaim?.[1] ?? appealReviewWrite?.[1]) !== value.object_id
      ))
      || ((appealReviewClaim || appealReviewWrite) && value.resource_type !== "APPEAL_REVIEW")
      || (value.resource_type === "MATCHING_INVITATION" && (!matchingInvitationWrite || matchingInvitationWrite[1] !== value.object_id))
      || (matchingInvitationWrite && value.resource_type !== "MATCHING_INVITATION")
      || (value.resource_type === "MATCHING_SELECTION" && (!matchingSelectionWrite || matchingSelectionWrite[2] !== value.object_id))
      || (matchingSelectionWrite && value.resource_type !== "MATCHING_SELECTION")
      || (value.resource_type === "MATCHING_ASSIGNMENT" && (!matchingAssignmentClaim || value.intent.body.demand_id !== value.object_id))
      || (matchingAssignmentClaim && value.resource_type !== "MATCHING_ASSIGNMENT")
      || (value.resource_type === "MATCHING_REVIEW" && (
        !matchingReviewClaim && !matchingReviewRelease && !matchingReviewCreate
        && !matchingReviewPublish && !matchingReviewInvalidate
      ))
      || ((matchingReviewClaim || matchingReviewRelease || matchingReviewCreate
        || matchingReviewPublish || matchingReviewInvalidate)
        && value.resource_type !== "MATCHING_REVIEW")
      || (matchingReviewCreate && matchingReviewCreate[1] !== value.object_id)
      || (matchingReviewPublish && matchingReviewPublish[1] !== value.object_id)
      || (matchingReviewInvalidate && matchingReviewInvalidate[1] !== value.object_id)
    ) return null;
    return value;
  } catch {
    return null;
  }
}

function parseOrganizationAdminWriteIntent(value) {
  const result = exactKeys(value, new Set(["method", "path", "headers", "body"]));
  if (result.method !== "POST" || typeof result.path !== "string") invalid();
  const headers = exactKeys(result.headers, new Set([
    "content-type", "idempotency-key", "if-match", "x-csrf-token",
  ]));
  if (
    headers["content-type"] !== "application/json"
    || !IDEMPOTENCY_KEY.test(headers["idempotency-key"])
    || !CSRF_TOKEN.test(headers["x-csrf-token"])
    || !/^"v[1-9][0-9]*"$/.test(headers["if-match"])
  ) invalid();
  const issue = /^\/v1\/organizations\/([A-Za-z0-9][A-Za-z0-9_-]{15,127})\/access-invitations$/.exec(result.path);
  const publicName = /^\/v1\/organizations\/([A-Za-z0-9][A-Za-z0-9_-]{15,127})\/public-name$/.exec(result.path);
  const invitation = /^\/v1\/access-invitations\/([A-Za-z0-9][A-Za-z0-9_-]{15,127})\/revoke$/.exec(result.path);
  const membership = /^\/v1\/memberships\/([A-Za-z0-9][A-Za-z0-9_-]{15,127})\/(suspend|resume|revoke)$/.exec(result.path);
  if (!issue && !publicName && !invitation && !membership) invalid();
  if (issue) {
    const body = exactKeys(result.body, new Set(["recipient", "target_role", "expires_at"]));
    const recipient = exactKeys(body.recipient, new Set(["type", "value"]));
    if (
      recipient.type !== "EMAIL"
      || typeof recipient.value !== "string"
      || recipient.value.length < 3
      || recipient.value.length > 254
      || !EMAIL_ADDRESS.test(recipient.value)
      || !ORGANIZATION_ROLES.has(body.target_role)
    ) invalid();
    utcTimestamp(body.expires_at);
  } else if (publicName) {
    const body = exactKeys(result.body, new Set(["public_name", "reason_code"]));
    organizationPublicName(body.public_name);
    if (body.reason_code !== ORGANIZATION_PUBLIC_NAME_REASON_CODE) invalid();
  } else {
    const body = exactKeys(result.body, new Set(["reason_code"]));
    if (typeof body.reason_code !== "string" || !ORGANIZATION_ADMIN_REASON_CODE_SET.has(body.reason_code)) invalid();
  }
  return { result, issue, publicName, invitation, membership };
}

export function serializePendingOrganizationAdminWrite(value) {
  const encoded = JSON.stringify(value);
  if (encoded === undefined || new TextEncoder().encode(encoded).byteLength > PENDING_MAX_BYTES) {
    invalid("PENDING_ORGANIZATION_WRITE_TOO_LARGE");
  }
  if (parsePendingOrganizationAdminWrite(encoded, Date.parse(value.saved_at)) === null) {
    invalid("INVALID_APP_CONTRACT");
  }
  return encoded;
}

export function parsePendingOrganizationAdminWrite(encoded, now = Date.now()) {
  if (typeof encoded !== "string" || new TextEncoder().encode(encoded).byteLength > PENDING_MAX_BYTES) return null;
  try {
    const value = exactKeys(JSON.parse(encoded), new Set([
      "version", "saved_at", "operation", "target_id", "intent",
    ]));
    if (value.version !== 1 || !new Set([
      "ISSUE_INVITATION", "UPDATE_PUBLIC_NAME", "REVOKE_INVITATION", "SUSPEND_MEMBERSHIP",
      "RESUME_MEMBERSHIP", "REVOKE_MEMBERSHIP",
    ]).has(value.operation)) return null;
    appId(value.target_id);
    const savedAt = Date.parse(utcTimestamp(value.saved_at));
    if (!Number.isFinite(now) || savedAt > now + 5 * 60 * 1000 || now - savedAt > PENDING_MAX_AGE_MS) return null;
    const { issue, publicName, invitation, membership } = parseOrganizationAdminWriteIntent(value.intent);
    const expected = {
      ISSUE_INVITATION: [issue, null],
      UPDATE_PUBLIC_NAME: [publicName, null],
      REVOKE_INVITATION: [invitation, null],
      SUSPEND_MEMBERSHIP: [membership, "suspend"],
      RESUME_MEMBERSHIP: [membership, "resume"],
      REVOKE_MEMBERSHIP: [membership, "revoke"],
    }[value.operation];
    if (!expected[0] || expected[0][1] !== value.target_id || (expected[1] !== null && expected[0][2] !== expected[1])) return null;
    return value;
  } catch {
    return null;
  }
}

export function serializePendingInvitationContext(value) {
  const encoded = JSON.stringify(value);
  if (encoded === undefined || new TextEncoder().encode(encoded).byteLength > PENDING_MAX_BYTES) {
    invalid("PENDING_INVITATION_CONTEXT_TOO_LARGE");
  }
  if (parsePendingInvitationContext(encoded, Date.parse(value.saved_at)) === null) invalid("INVALID_APP_CONTRACT");
  return encoded;
}

export function parsePendingInvitationContext(encoded, now = Date.now()) {
  if (typeof encoded !== "string" || new TextEncoder().encode(encoded).byteLength > PENDING_MAX_BYTES) return null;
  try {
    const value = exactKeys(JSON.parse(encoded), new Set(["version", "saved_at", "invitation"]));
    if (value.version !== 1) return null;
    const savedAt = Date.parse(utcTimestamp(value.saved_at));
    if (!Number.isFinite(now) || savedAt > now + 5 * 60 * 1000 || now - savedAt > PENDING_MAX_AGE_MS) return null;
    try {
      parseAccessInvitationPreview(value.invitation);
    } catch {
      parseAccessInvitationAdmin(value.invitation);
    }
    if (value.invitation.purpose !== "ORGANIZATION_MEMBERSHIP" || value.invitation.status !== "ISSUED") return null;
    return value;
  } catch {
    return null;
  }
}

function parseInvitationAcceptanceIntent(value) {
  const result = exactKeys(value, new Set(["method", "path", "headers", "body"]));
  const match = typeof result.path === "string"
    ? /^\/v1\/access-invitations\/([A-Za-z0-9][A-Za-z0-9_-]{15,127})\/accept$/.exec(result.path)
    : null;
  if (result.method !== "POST" || !match) invalid();
  const headers = exactKeys(result.headers, new Set([
    "content-type", "idempotency-key", "if-match", "x-csrf-token",
  ]));
  if (
    headers["content-type"] !== "application/json"
    || !IDEMPOTENCY_KEY.test(headers["idempotency-key"])
    || !CSRF_TOKEN.test(headers["x-csrf-token"])
    || !/^"v[1-9][0-9]*"$/.test(headers["if-match"])
  ) invalid();
  const body = exactKeys(result.body, new Set(["policy_bundle_id", "policy_acceptances", "consent_grants"]));
  appId(body.policy_bundle_id);
  if (!Array.isArray(body.policy_acceptances) || body.policy_acceptances.length < 1 || body.policy_acceptances.length > 20) invalid();
  const acceptedIds = [];
  for (const acceptance of body.policy_acceptances) {
    const exact = exactKeys(acceptance, new Set(["document_id", "content_sha256", "affirmed"]));
    acceptedIds.push(appId(exact.document_id));
    sha256(exact.content_sha256);
    if (exact.affirmed !== true) invalid();
  }
  if (new Set(acceptedIds).size !== acceptedIds.length) invalid();
  if (!Array.isArray(body.consent_grants) || body.consent_grants.length > 20) invalid();
  const offerIds = [];
  for (const grant of body.consent_grants) {
    const exact = exactKeys(grant, new Set(["consent_offer_id", "document_id", "content_sha256", "affirmed"]));
    offerIds.push(appId(exact.consent_offer_id));
    appId(exact.document_id);
    sha256(exact.content_sha256);
    if (exact.affirmed !== true) invalid();
  }
  if (new Set(offerIds).size !== offerIds.length) invalid();
  return { result, invitationId: match[1] };
}

export function serializePendingInvitationAcceptance(value) {
  const encoded = JSON.stringify(value);
  if (encoded === undefined || new TextEncoder().encode(encoded).byteLength > PENDING_MAX_BYTES) {
    invalid("PENDING_INVITATION_ACCEPTANCE_TOO_LARGE");
  }
  if (parsePendingInvitationAcceptance(encoded, Date.parse(value.saved_at)) === null) invalid("INVALID_APP_CONTRACT");
  return encoded;
}

export function parsePendingInvitationAcceptance(encoded, now = Date.now()) {
  if (typeof encoded !== "string" || new TextEncoder().encode(encoded).byteLength > PENDING_MAX_BYTES) return null;
  try {
    const value = exactKeys(JSON.parse(encoded), new Set([
      "version", "saved_at", "invitation_id", "intent",
    ]));
    if (value.version !== 1) return null;
    appId(value.invitation_id);
    const savedAt = Date.parse(utcTimestamp(value.saved_at));
    if (!Number.isFinite(now) || savedAt > now + 5 * 60 * 1000 || now - savedAt > PENDING_MAX_AGE_MS) return null;
    const parsed = parseInvitationAcceptanceIntent(value.intent);
    if (parsed.invitationId !== value.invitation_id) return null;
    return value;
  } catch {
    return null;
  }
}
