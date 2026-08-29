export type ResourceType = "CREATOR_PROFILE" | "DEMAND";
export type CurrentAccountTaskClassification = "NEEDS_ACTION" | "WAITING" | "COMPLETED";
export type CurrentAccountTaskResourceKind =
  | "APPEAL"
  | "APPEAL_REVIEW"
  | "CREATOR_PROFILE"
  | "DEMAND"
  | "DEMAND_REVIEW"
  | "FINANCE_FUNDING_REVIEW"
  | "TRUST_CASE"
  | "TRUST_HOLD_RELEASE"
  | "TRUST_REPORT";
export type CurrentAccountTaskNextAction =
  | "CLAIM_APPEAL_REVIEW"
  | "CLAIM_DEMAND_REVIEW"
  | "CLAIM_FINANCE_REVIEW"
  | "CLAIM_TRUST_CASE"
  | "CLAIM_TRUST_HOLD_RELEASE"
  | "CONTINUE_FINANCE_REVIEW"
  | "EDIT_APPEAL"
  | "EDIT_OR_SUBMIT_DEMAND"
  | "REVIEW_ASSIGNED_APPEAL"
  | "REVIEW_ASSIGNED_DEMAND"
  | "REVIEW_ASSIGNED_TRUST_CASE"
  | "REVIEW_ASSIGNED_TRUST_HOLD_RELEASE"
  | "VIEW_APPEAL_HISTORY"
  | "VIEW_APPEAL_REVIEW_HISTORY"
  | "VIEW_CREATOR_PROFILE"
  | "VIEW_DEMAND_HISTORY"
  | "VIEW_DEMAND_REVIEW_HISTORY"
  | "VIEW_TRUST_CASE_HISTORY"
  | "VIEW_TRUST_REPORT_HISTORY"
  | "WAIT_FOR_APPEAL_REVIEW"
  | "WAIT_FOR_DEMAND_PROCESSING"
  | "WAIT_FOR_FINANCE_CONFIRMATION"
  | "WAIT_FOR_TRUST_REVIEW";
export interface CurrentAccountTask {
  classification: CurrentAccountTaskClassification;
  resource_kind: CurrentAccountTaskResourceKind;
  resource_id: string;
  source_status: string;
  next_action: CurrentAccountTaskNextAction;
  resource_path: string;
  updated_at: string | null;
  due_at: string | null;
}
export interface CurrentAccountTaskDiscovery {
  schema_version: "current-account-task-discovery-v1";
  items: CurrentAccountTask[];
  has_more: boolean;
}
export type Capability = "SAVE_DRAFT" | "PUBLISH" | "PAUSE" | "RESUME" | "ARCHIVE" | "SUBMIT" | "CANCEL" | "RECORD_FINDINGS";
export interface EditorVersion {
  version_id: string;
  version_no: number;
  based_on_version_id: string | null;
  status: string;
  content: Record<string, unknown>;
  content_sha256: string;
  taxonomy_bundle_id: string;
  created_at: string;
}
export interface EditorSubmission {
  submission_id: string;
  version_id: string;
  submission_no: number;
  content_sha256: string;
  submitted_at: string;
}
export interface EditorFinding {
  finding_id: string;
  version_id: string;
  assignment_id: string | null;
  result: "NEEDS_CHANGES" | "VERIFIED" | "DISCREPANCY" | "REJECTED";
  reason_codes: string[];
  required_field_paths: string[];
  reviewed_at: string;
}
export interface EditorReviewAssignment {
  assignment_id: string;
  status: "ACTIVE";
  expires_at: string;
}
export interface EditorReviewQueueItem {
  demand_id: string;
  demand_revision: number;
  demand_version_no: number;
  submitted_at: string;
  demand_expires_at: string;
  etag: string;
}
export interface EditorReviewClaim {
  assignment_id: string;
  demand_id: string;
  demand_revision: number;
  status: "ACTIVE";
  expires_at: string;
  etag: string;
  replayed: boolean;
}
export interface EditorReviewHistoryItem {
  review_id: string;
  demand_id: string;
  demand_version_id: string;
  decision: "NEEDS_CHANGES" | "VERIFIED";
  reason_codes: string[];
  required_field_codes: string[];
  budget_health_code: "HEALTHY" | "APPROVED_EXCEPTION" | null;
  risk_code: "STANDARD" | "ELEVATED_APPROVED" | null;
  reviewed_at: string;
}
export interface EditorReviewHistoryPage {
  schema_version: "demand-review-history-v1";
  items: EditorReviewHistoryItem[];
  next_cursor: string | null;
  has_more: boolean;
}
export interface FinanceFundingQueueItem {
  demand_id: string;
  demand_version_id: string;
  demand_revision: number;
  funding_review_id: string | null;
  review_status: "AVAILABLE" | "PENDING";
  review_revision: number | null;
  assigned_to_me: boolean;
  confirmation_count: 0 | 1;
  required_confirmations: 2;
  expires_at: string;
  etag: string;
}
export interface FinanceFundingHistoryItem {
  funding_review_id: string;
  demand_id: string;
  demand_version_id: string;
  status: "SECURED" | "DISCREPANCY" | "REJECTED";
  completed_at: string;
}
export interface FinanceFundingHistoryPage {
  schema_version: "finance-funding-review-history-v1";
  items: FinanceFundingHistoryItem[];
  next_cursor: string | null;
  has_more: boolean;
}
export interface FinanceFundingReview {
  funding_review_id: string;
  demand_id: string;
  demand_version_id: string;
  status: "PENDING" | "SECURED" | "DISCREPANCY" | "REJECTED";
  revision: number;
  assignment_id: string;
  assignment_expires_at: string;
  target_sha256: string;
  target_content_sha256: string;
  planned_budget_currency: "CNY";
  planned_budget_minimum_amount_minor: number;
  planned_budget_maximum_amount_minor: number;
  planned_budget_direct_cost_amount_minor: number;
  evidence_kind: "INTERNAL_SANDBOX_ZERO_FUNDS_V1";
  evidence_reference_sha256: string;
  sandbox_funds_amount_minor: 0;
  provider_code: "NONE";
  payment_operation_code: "NONE";
  synthetic: true;
  legal_effect: "NO_REAL_FUNDS_OR_PAYMENT";
  confirmation_count: 0 | 1 | 2;
  required_confirmations: 2;
  assignment_status: "ACTIVE" | "COMPLETED" | "RELEASED" | "EXPIRED" | "REVOKED";
  confirmation_by_me: boolean;
  available_actions: ("CONFIRM" | "RELEASE_ASSIGNMENT" | "SUBMIT_FINDING")[];
  can_confirm: boolean;
  etag: string;
  replayed: boolean;
}
export type TrustDemandActionCode = "REQUEST_MATCHING" | "SUBMIT_DEMAND" | "VERIFY_DEMAND";
export type TrustReportCategory = "DATA_EXPOSURE" | "FRAUD_RISK" | "HARASSMENT" | "RETALIATION" | "WORKFLOW_INTEGRITY";
export interface TrustReportSummary {
  category: TrustReportCategory;
  evidence_reference_ids: string[];
  impact_codes: string[];
  incident_ended_at: string | null;
  incident_started_at: string;
  requested_protection_codes: string[];
}
export interface TrustReportProjection {
  demand_id: string;
  demand_version_id: string;
  entity_tag: string;
  outcome: TrustOutcomeProjection | null;
  report: TrustReportSummary;
  report_id: string;
  status: "DECIDED" | "IN_REVIEW" | "OPEN" | "TRIAGING";
  submitted_at: string;
}
export interface TrustOwnReportOutcome {
  appeal_deadline: string | null;
  appeal_eligibility_code: "ELIGIBLE" | "NOT_ELIGIBLE";
  decided_at: string;
  outcome_code: TrustOutcomeProjection["outcome_code"];
  outcome_version_id: string;
}
export interface TrustOwnReportItem {
  category: TrustReportCategory;
  demand_id: string;
  outcome: TrustOwnReportOutcome | null;
  report_id: string;
  status: "DECIDED" | "IN_REVIEW" | "OPEN" | "TRIAGING";
  submitted_at: string;
}
export interface TrustOwnReportListProjection {
  entity_tag: string;
  items: TrustOwnReportItem[];
  next_cursor: string | null;
}
export interface TrustQueueItem {
  category: TrustReportCategory;
  case_id: string;
  demand_id: string;
  demand_version_id: string;
  entity_tag: string;
  impact_codes: string[];
  report_id: string;
  submitted_at: string;
}
export interface TrustQueueProjection { entity_tag: string; items: TrustQueueItem[] }
export interface TrustHoldReleaseQueueItem {
  action_codes: TrustDemandActionCode[];
  case_id: string;
  demand_id: string;
  demand_version_id: string;
  entity_tag: string;
  expires_at: string;
  hold_id: string;
  reason_code: "PARTICIPANT_SAFETY_RISK" | "RETALIATION_RISK";
}
export interface TrustHoldReleaseQueueProjection { entity_tag: string; items: TrustHoldReleaseQueueItem[] }
export type TrustAssignmentPurpose = "CASE_TRIAGE" | "HOLD_RELEASE";
interface TrustAssignmentItemBase {
  assignment_expires_at: string;
  case_id: string;
}
export type TrustAssignmentItem =
  | (TrustAssignmentItemBase & { assignment_purpose: "CASE_TRIAGE"; hold_id: null })
  | (TrustAssignmentItemBase & { assignment_purpose: "HOLD_RELEASE"; hold_id: string });
export interface TrustAssignmentListProjection { entity_tag: string; items: TrustAssignmentItem[] }
export interface TrustCaseHistoryItem {
  case_id: string;
  decided_at: string;
  outcome_code: "NO_ACTION" | "PROTECTION_LIFTED" | "PROTECTION_MAINTAINED" | "PROTECTION_MODIFIED" | "REMEDIATION_REQUIRED";
}
export interface TrustCaseHistoryProjection {
  entity_tag: string;
  has_more: boolean;
  items: TrustCaseHistoryItem[];
}
export interface TrustAssignedHoldProjection {
  action_codes: TrustDemandActionCode[];
  assignment_expires_at: string;
  case_id: string;
  case_status: "IN_REVIEW";
  effective_at: string;
  entity_tag: string;
  expires_at: string;
  hold_id: string;
  hold_status: "ACTIVE";
  reason_code: "PARTICIPANT_SAFETY_RISK" | "RETALIATION_RISK";
}
export interface TrustSafeTriageContent {
  investigation_step_codes: string[];
  issue_codes: string[];
  jurisdiction_code: "LEGAL_REVIEW_REQUIRED" | "ORGANIZATION_POLICY" | "PLATFORM_INTERNAL";
  priority_code: "P0" | "P1" | "P2" | "P3";
  proposed_hold_actions: TrustDemandActionCode[];
  proposed_hold_ttl_minutes: number;
  sealed_note_reference: string;
  sealed_note_sha256: string;
  severity_code: "CRITICAL" | "HIGH" | "LOW" | "MEDIUM";
}
export interface TrustTriageDraftProjection {
  content: TrustSafeTriageContent;
  content_sha256: string;
  saved_at: string;
  triage_version: number;
}
export interface TrustHoldProjection {
  action_codes: TrustDemandActionCode[];
  effective_at: string;
  entity_tag: string;
  expires_at: string;
  hold_id: string;
  status: "ACTIVE" | "EXPIRED" | "RELEASED";
}
export interface TrustOutcomeProjection {
  action_codes: TrustDemandActionCode[];
  appeal_deadline: string | null;
  appeal_eligibility_code: "ELIGIBLE" | "NOT_ELIGIBLE";
  content_sha256: string;
  decided_at: string;
  evidence_packet_digest: string;
  evidence_packet_version_id: string;
  outcome_code: "NO_ACTION" | "PROTECTION_LIFTED" | "PROTECTION_MAINTAINED" | "PROTECTION_MODIFIED" | "REMEDIATION_REQUIRED";
  outcome_version_id: string;
  policy_version: string;
  reason_codes: string[];
  redaction_profile_code: "OFFICER_RESTRICTED_V1" | "PARTY_SAFE_V1";
  source_digest: string;
}
export interface TrustCaseProjection {
  active_hold: TrustHoldProjection | null;
  aggregate_version: number;
  case_id: string;
  demand_id: string;
  demand_version_id: string;
  entity_tag: string;
  outcome: TrustOutcomeProjection | null;
  report: TrustReportSummary;
  report_id: string;
  status: "DECIDED" | "IN_REVIEW" | "TRIAGING";
  triage_draft: TrustTriageDraftProjection | null;
}
export interface TrustCommandResult {
  aggregate_version: number;
  case_id: string;
  case_status: "APPEAL_PENDING" | "DECIDED" | "DISMISSED" | "IN_REVIEW" | "OPEN" | "RESOLVED" | "TRIAGING";
  completed_at: string;
  event_types: Array<"SafetyHoldPlaced" | "SafetyHoldReleased" | "TrustCaseAssignmentReleased" | "TrustCaseClaimed" | "TrustCaseOutcomePublished" | "TrustHoldReleaseClaimed" | "TrustReportSubmitted" | "TrustTriageDraftSaved" | "TrustTriagePublished">;
  hold_id: string | null;
  hold_version: number | null;
  outcome_version_id: string | null;
  replayed: boolean;
  report_id: string | null;
  triage_draft_version: number | null;
  triage_version: number | null;
}
export type AppealGround = "NEW_MATERIAL_EVIDENCE" | "PROCEDURAL_ERROR" | "RULE_MISAPPLICATION";
export type AppealRequestedOutcome = "MODIFY_MEASURE" | "REMOVE_MEASURE" | "VACATE_AND_REMAND";
export type AppealDecisionCode = "AFFIRM" | "DISMISS" | "MODIFY" | "VACATE_AND_REMAND";
export interface AppealSourceProjection {
  action_codes: TrustDemandActionCode[];
  appeal_deadline: string;
  appeal_eligibility_code: "ELIGIBLE";
  appeal_eligible: true;
  case_id: string;
  content_sha256: string;
  decided_at: string;
  demand_id: string;
  demand_version_id: string;
  evidence_packet_sha256: string;
  evidence_packet_version_id: string;
  outcome_code: TrustOutcomeProjection["outcome_code"];
  outcome_version_id: string;
  policy_version: string;
  reason_codes: string[];
}
export interface AppealApplicationDraftProjection {
  edited_at: string;
  grounds: AppealGround[];
  new_evidence_reference_ids: string[];
  requested_outcome: AppealRequestedOutcome;
  statement_recorded: true;
  version: number;
}
export interface AppealSubmittedApplicationProjection {
  grounds: AppealGround[];
  new_evidence_reference_ids: string[];
  requested_outcome: AppealRequestedOutcome;
  statement_recorded: true;
  submitted_at: string;
}
export interface AppealAssessmentProjection {
  accepted_evidence_reference_ids: string[];
  assessment_code: "ACCEPTED" | "PARTIALLY_ACCEPTED" | "REJECTED";
  finding_codes: string[];
  ground: AppealGround;
}
export interface AppealReviewDraftProjection {
  assessments: AppealAssessmentProjection[];
  edited_at: string;
  reason_codes: string[];
  remedy_delta_codes: string[];
  review_note_recorded: true;
  version: number;
}
export interface AppealDecisionProjection {
  assessments: AppealAssessmentProjection[];
  decided_at: string;
  decision_code: AppealDecisionCode;
  decision_sha256: string;
  decision_version_id: string;
  policy_version: string;
  reason_codes: string[];
  remedy_delta_codes: string[];
}
export interface AppealOwnProjection {
  aggregate_version: number;
  appeal_id: string;
  application: AppealSubmittedApplicationProjection | null;
  application_draft: AppealApplicationDraftProjection | null;
  decision: AppealDecisionProjection | null;
  entity_tag: string;
  source: AppealSourceProjection;
  source_case_id: string;
  source_outcome_version_id: string;
  status: "DECIDED" | "DRAFT" | "IN_REVIEW" | "SUBMITTED" | "WITHDRAWN";
}
export interface AppealQueueItem {
  appeal_id: string;
  entity_tag: string;
  grounds: AppealGround[];
  requested_outcome: AppealRequestedOutcome;
  source_case_id: string;
  source_outcome_version_id: string;
  submitted_at: string;
}
export interface AppealQueueProjection { entity_tag: string; items: AppealQueueItem[] }
export interface AppealAssignmentItem {
  appeal_id: string;
  assignment_expires_at: string;
}
export interface AppealAssignmentListProjection { entity_tag: string; items: AppealAssignmentItem[] }
export interface AppealReviewHistoryItem {
  appeal_id: string;
  decided_at: string;
  decision_code: AppealDecisionCode;
}
export interface AppealReviewHistoryProjection {
  entity_tag: string;
  has_more: boolean;
  items: AppealReviewHistoryItem[];
}
export interface AppealAssignedProjection {
  appeal: AppealOwnProjection;
  application: AppealSubmittedApplicationProjection;
  assignment_expires_at: string;
  entity_tag: string;
  review_draft: AppealReviewDraftProjection | null;
  source: AppealSourceProjection;
}
export interface AppealReviewTerminalProjection {
  appeal_id: string;
  application: AppealSubmittedApplicationProjection;
  decision: AppealDecisionProjection;
  entity_tag: string;
  review_note_recorded: true;
  status: "DECIDED";
}
export interface AppealCommandResult {
  aggregate_version: number;
  appeal_id: string;
  appeal_status: AppealOwnProjection["status"];
  application_draft_version: number | null;
  application_version: number | null;
  completed_at: string;
  decision_version_id: string | null;
  event_types: Array<"AppealApplicationDraftSaved" | "AppealDecisionPublished" | "AppealOpened" | "AppealReviewAssignmentReleased" | "AppealReviewClaimed" | "AppealReviewDraftSaved" | "AppealSubmitted">;
  replayed: boolean;
  review_draft_version: number | null;
}
export interface EditorResource {
  resource_type: ResourceType;
  object_id: string;
  status: string;
  revision: number;
  etag: string;
  capabilities: Capability[];
  editable_paths: string[];
  current_version: EditorVersion | null;
  versions: EditorVersion[];
  submissions: EditorSubmission[];
  findings: EditorFinding[];
  review_assignment: EditorReviewAssignment | null;
}
export interface EditorConfiguration {
  schema_version: "editor-configuration-v2";
  deployment_mode: "INTERNAL_SANDBOX";
  taxonomy_bundle: {
    bundle_id: string;
    status: "CURRENT_APPROVED";
    effective_at: string;
    effective_until: string | null;
  };
  editor_choices: EditorChoices;
}
export type EditorChoiceValueContract = "TAXONOMY_CODE" | "REGION_CODE" | "LANGUAGE_TAG" | "CURRENCY_CODE" | "CONTENT_ENUM";
export type TaxonomyNodeKind =
  | "DOMAIN" | "PROBLEM_TYPE" | "TASK" | "SKILL" | "SKILL_LEVEL"
  | "TARGET_USER_CATEGORY" | "WORK_MODE" | "FEEDBACK_CADENCE" | "TEAM_PREFERENCE"
  | "REGION" | "LANGUAGE" | "DATA_SENSITIVITY" | "AI_USE" | "RISK"
  | "DELIVERY_KIND" | "REVIEW_REASON";
export type EditorChoiceSource = "TAXONOMY_BUNDLE_NODE" | "INTERNAL_SANDBOX_POLICY" | "INTERNAL_SANDBOX_PRESET";
export interface EditorChoiceOption {
  value: string;
  label: string;
  source: EditorChoiceSource;
}
export interface EditorChoiceField {
  resource_type: ResourceType;
  path_template: string;
  value_contract: EditorChoiceValueContract;
  intended_node_kind: TaxonomyNodeKind | null;
  status: "AVAILABLE" | "UNAVAILABLE";
  reason_code: "NO_REVIEWED_CHOICE_SET" | null;
  options: EditorChoiceOption[];
}
export interface EditorChoices {
  schema_version: "editor-choices-v1";
  locale: "zh-CN";
  fields: EditorChoiceField[];
}
export interface SessionBootstrap {
  session: { session_id: string; device_label?: string; [key: string]: unknown };
  user_status: string;
  csrf_token: string;
}
export interface MeProjection {
  user_id: string;
  status: string;
  display_handle: string;
  user_roles: string[];
  memberships: Array<{
    membership_id: string;
    organization: { organization_id: string; public_name: string; type: string; status: string; aggregate_version: number; entity_tag: string };
    status: string;
    roles: string[];
    aggregate_version: number;
    entity_tag: string;
  }>;
  policy_requirements: PolicyRequirement[];
  aggregate_version: number;
  entity_tag: string;
}
export type PolicyPurpose = "CREATOR_ENROLLMENT" | "ORGANIZATION_MEMBERSHIP";
export type PolicyRole = "CREATOR" | "ORG_ADMIN" | "DEMAND_OWNER";
export interface PolicyRequirement {
  selector_digest: string;
  purpose: PolicyPurpose;
  role: PolicyRole;
  scope_type: "USER_ROLE" | "ORGANIZATION_ROLE";
  scope_id: string | null;
  satisfied: boolean;
  required_policy_bundle_id: string | null;
  missing_document_ids: string[];
}
export interface PolicyDocument {
  document_id: string;
  kind: "TERMS" | "PRIVACY_NOTICE" | "COMMUNITY_TRANSACTION_COVENANT" | "CONSENT_TEXT";
  semantic_version: string;
  locale: string;
  content_sha256: string;
  legal_effect: "NOTICE_ACKNOWLEDGEMENT" | "CONTRACT_ACCEPTANCE" | "CONSENT_TEXT";
  body: string;
}
export interface ConsentOffer {
  consent_offer_id: string;
  purpose: "PILOT_RESEARCH" | "AI_ASSISTED_PROCESSING" | "DISCLOSE_PROFILE_FIELDS_TO_PARTY";
  scope_type: "PLATFORM_PARTICIPATION" | "ORGANIZATION" | "PROJECT" | "RECIPIENT_DISCLOSURE";
  data_categories: string[];
  document_id: string;
  content_sha256: string;
  recipient_label: string;
  expiry_rule: "FIXED_NOT_AFTER" | "EARLIER_OF_GRANTED_AT_PLUS_365_DAYS_OR_NOT_AFTER";
  not_after: string;
  canonical_offer_sha256: string;
  optional: true;
}
export interface PolicyBundle {
  policy_bundle_id: string;
  purpose: PolicyPurpose;
  jurisdiction: string;
  locale: string;
  documents: PolicyDocument[];
  consent_offers: ConsentOffer[];
  effective_at: string;
  entity_tag: string;
}
export type WorkspaceKind = "ORGANIZATION" | "PERSONAL" | "PLATFORM";
export type WorkspaceRoleCode = "ORG_ADMIN" | "DEMAND_OWNER" | "CREATOR" | "ACCESS_ADMIN" | "OPERATIONS_REVIEWER" | "FINANCE_OPERATOR" | "TRUST_OFFICER" | "APPEAL_REVIEWER";
export interface WorkspaceCandidate {
  workspace_id: string;
  workspace_kind: WorkspaceKind;
  role_codes: WorkspaceRoleCode[];
}
export interface WorkspaceDiscovery {
  workspaces: WorkspaceCandidate[];
  selection_required: boolean;
}
export interface AccountAdminProjection {
  account_code: string;
  user_id: string;
  display_handle: string;
  status: "ACTIVE" | "SUSPENDED";
  aggregate_version: number;
  entity_tag: string;
  role_codes: WorkspaceRoleCode[];
  active_session_count: number;
  created_at: string;
  updated_at: string;
  is_self: boolean;
}
export interface AccountAdminCollection {
  schema_version: "internal-sandbox-account-admin-v1";
  evaluated_at: string;
  accounts: AccountAdminProjection[];
}
export interface AccountAdminCommandResult {
  user_id: string;
  display_handle: string;
  status: "ACTIVE" | "SUSPENDED";
  aggregate_version: number;
  entity_tag: string;
  revoked_session_count: number;
  revoked_session_family_count: number;
  replayed: boolean;
}
export interface OrganizationSummary {
  organization_id: string;
  public_name: string;
  type: "BUSINESS" | "NONPROFIT" | "COMMUNITY" | "CREATOR_TEAM";
  status: "PENDING_ADMIN" | "ACTIVE" | "SUSPENDED" | "CLOSED";
  aggregate_version: number;
  entity_tag: string;
}
export interface AccessInvitationAdmin {
  invitation_id: string;
  purpose: "CREATOR_ENROLLMENT" | "ORGANIZATION_MEMBERSHIP";
  organization_id: string | null;
  target_role: "CREATOR" | "ORG_ADMIN" | "DEMAND_OWNER";
  masked_recipient_label: string;
  is_initial_admin: boolean;
  status: "ISSUED" | "ACCEPTED" | "REVOKED" | "EXPIRED";
  expires_at: string;
  created_at: string;
  required_policy_bundle_id: string;
  aggregate_version: number;
  entity_tag: string;
}
export interface AccessInvitationPreview {
  invitation_id: string;
  purpose: "CREATOR_ENROLLMENT" | "ORGANIZATION_MEMBERSHIP";
  organization: { public_name: string } | null;
  target_role: "CREATOR" | "ORG_ADMIN" | "DEMAND_OWNER";
  expires_at: string;
  required_policy_bundle_id: string;
  status: "ISSUED";
  aggregate_version: number;
  entity_tag: string;
}
export interface MembershipAdmin {
  membership_id: string;
  organization_id: string;
  user_id: string;
  display_handle: string;
  status: "ACTIVE" | "SUSPENDED" | "REVOKED";
  roles: Array<"ORG_ADMIN" | "DEMAND_OWNER">;
  aggregate_version: number;
  entity_tag: string;
}
export interface Page<T> { items: T[]; page: { next_cursor: string | null } }
export interface IssueOrganizationInvitationResponse {
  invitation: AccessInvitationAdmin;
  access_invitation_token: string;
  join_fragment_url: string;
}
export interface AccessInvitationAcceptance {
  invitation: AccessInvitationAdmin;
  me: MeProjection;
  activated_scope: "USER_ROLE" | "ORGANIZATION_MEMBERSHIP";
}
export interface WriteIntent {
  method: "POST" | "PUT";
  path: string;
  headers: Record<string, string>;
  body: Record<string, unknown>;
}
export interface ConflictSurface {
  current: { version_id: string | null; content: Record<string, unknown> };
  base: { version_id: string | null; content: Record<string, unknown> };
  yours: { version_id: string | null; content: Record<string, unknown> };
  currentEtag: string;
  changedPaths: string[];
}
export interface PendingIntent {
  version: 1;
  saved_at: string;
  resource_type: ResourceType | "ACCOUNT_ADMIN" | "REVIEW_CLAIM" | "FINANCE_FUNDING" | "MATCHING_INVITATION" | "MATCHING_SELECTION" | "MATCHING_ASSIGNMENT" | "MATCHING_REVIEW" | "TRUST_REPORT" | "TRUST_CASE" | "TRUST_HOLD" | "APPEAL" | "APPEAL_REVIEW";
  object_id: string;
  label: string;
  intent: WriteIntent;
}
export interface PendingOrganizationAdminWrite {
  version: 1;
  saved_at: string;
  operation: "ISSUE_INVITATION" | "UPDATE_PUBLIC_NAME" | "REVOKE_INVITATION" | "SUSPEND_MEMBERSHIP" | "RESUME_MEMBERSHIP" | "REVOKE_MEMBERSHIP";
  target_id: string;
  intent: WriteIntent;
}
export interface PendingInvitationContext {
  version: 1;
  saved_at: string;
  invitation: AccessInvitationPreview | AccessInvitationAdmin;
}
export interface PendingInvitationAcceptance {
  version: 1;
  saved_at: string;
  invitation_id: string;
  intent: WriteIntent;
}
export const PROFILE_EDITABLE_PATHS: readonly string[];
export const PROFILE_PAUSE_REASON_CODES: readonly ["OWNER_REQUEST", "TEMPORARY_UNAVAILABILITY", "SAFETY_REVIEW"];
export const PROFILE_ARCHIVE_REASON_CODES: readonly ["OWNER_REQUEST", "ACCOUNT_CLOSURE", "SAFETY_REVIEW"];
export const DEMAND_OWNER_CANCEL_REASON_CODES: readonly ["OWNER_WITHDREW", "REQUIREMENTS_CHANGED", "REVIEW_CLOSED", "FUNDING_UNAVAILABLE", "SAFETY_RESTRICTION"];
export const DEMAND_EDITABLE_PATHS: readonly string[];
export const REVIEW_REASON_CODES: readonly string[];
export const REVIEW_ASSIGNMENT_RELEASE_REASON_CODES: readonly ["CONFLICT_DECLARED", "WORKLOAD_RELEASE"];
export const VERIFY_BUDGET_HEALTH_CODES: readonly ["HEALTHY", "APPROVED_EXCEPTION"];
export const VERIFY_RISK_CODES: readonly ["STANDARD", "ELEVATED_APPROVED"];
export const VERIFY_EVIDENCE_CODES: readonly ["SCOPE_COMPLETE", "ACCEPTANCE_TESTABLE", "BUDGET_COHERENT", "RISK_HANDLED", "DECLARATIONS_CONFIRMED"];
export const FINANCE_FUNDING_ATTESTATION_CODES: readonly ["SYNTHETIC_ONLY", "ZERO_REAL_FUNDS", "NO_PROVIDER_OR_PAYMENT", "TARGET_AND_EVIDENCE_MATCH"];
export const FINANCE_FUNDING_ACTIONS: readonly ["CONFIRM", "RELEASE_ASSIGNMENT", "SUBMIT_FINDING"];
export const FINANCE_FUNDING_RELEASE_REASON_CODES: readonly ["CONFLICT_DECLARED", "WORKLOAD_RELEASE"];
export const FINANCE_FUNDING_FINDING_FIELD_CODES: readonly ["BUDGET", "DECLARATIONS", "RISK", "SCOPE"];
export const FINANCE_FUNDING_DISCREPANCY_REASON_CODES: readonly ["EVIDENCE_REFERENCE_MISMATCH", "TARGET_CONTENT_MISMATCH"];
export const FINANCE_FUNDING_REJECTED_REASON_CODES: readonly ["BUDGET_PLAN_UNACCEPTABLE", "DECLARATION_CONFLICT", "SYNTHETIC_SCOPE_VIOLATION"];
export const ACCOUNT_ADMIN_REASON_CODES: readonly string[];
export const ACCOUNT_ADMIN_PLATFORM_DUTY_CODES: readonly ["ACCESS_ADMIN", "APPEAL_REVIEWER", "FINANCE_OPERATOR", "OPERATIONS_REVIEWER", "TRUST_OFFICER"];
export const TRUST_REPORT_CATEGORIES: readonly ["DATA_EXPOSURE", "FRAUD_RISK", "HARASSMENT", "RETALIATION", "WORKFLOW_INTEGRITY"];
export const TRUST_IMPACT_CODES: readonly string[];
export const TRUST_PROTECTION_CODES: readonly ["PAUSE_MATCHING", "PAUSE_SUBMISSION", "PAUSE_VERIFICATION"];
export const TRUST_INVESTIGATION_STEP_CODES: readonly string[];
export const TRUST_ISSUE_CODES: readonly string[];
export const TRUST_DEMAND_ACTION_CODES: readonly ["REQUEST_MATCHING", "SUBMIT_DEMAND", "VERIFY_DEMAND"];
export const TRUST_HOLD_REASON_CODES: readonly string[];
export const TRUST_HOLD_RELEASE_REASON_CODES: readonly ["CASE_DECIDED", "RISK_MITIGATED", "SUPERSEDED", "TTL_CORRECTION"];
export const TRUST_ASSIGNMENT_RELEASE_REASON_CODES: readonly ["ASSIGNMENT_EXPIRED", "CONFLICT_DECLARED", "WORKLOAD_RELEASE"];
export const TRUST_OUTCOME_CODES: readonly ["NO_ACTION", "PROTECTION_LIFTED", "PROTECTION_MAINTAINED", "PROTECTION_MODIFIED", "REMEDIATION_REQUIRED"];
export const TRUST_OUTCOME_REASON_CODES: readonly string[];
export const APPEAL_GROUNDS: readonly ["NEW_MATERIAL_EVIDENCE", "PROCEDURAL_ERROR", "RULE_MISAPPLICATION"];
export const APPEAL_REQUESTED_OUTCOMES: readonly ["MODIFY_MEASURE", "REMOVE_MEASURE", "VACATE_AND_REMAND"];
export const APPEAL_DECISION_CODES: readonly ["AFFIRM", "DISMISS", "MODIFY", "VACATE_AND_REMAND"];
export const APPEAL_ASSESSMENT_CODES: readonly ["ACCEPTED", "PARTIALLY_ACCEPTED", "REJECTED"];
export const APPEAL_FINDING_CODES: readonly ["APPEAL_NOT_SUBSTANTIATED", "NEW_EVIDENCE_MATERIAL", "PROCEDURE_MATERIAL_ERROR", "RULE_APPLICATION_ERROR", "RULE_APPLIED_CORRECTLY"];
export const APPEAL_REASON_CODES: readonly ["APPEAL_SCOPE_INVALID", "NEW_EVIDENCE_REVIEWED", "PROCEDURAL_REVIEW_COMPLETE", "REMAND_REQUIRED", "SOURCE_OUTCOME_SUPPORTED", "SOURCE_OUTCOME_UNSUPPORTED"];
export const APPEAL_REMEDY_DELTA_CODES: readonly ["NARROW_CORRECTIVE_MEASURE", "NO_CHANGE", "REMOVE_CORRECTIVE_MEASURE", "REPLACE_CORRECTIVE_MEASURE", "RETURN_TO_TRUST_REVIEW"];
export const APPEAL_ASSIGNMENT_RELEASE_REASON_CODES: readonly ["ASSIGNMENT_EXPIRED", "CONFLICT_DECLARED", "WORKLOAD_RELEASE"];
export const ORGANIZATION_ADMIN_REASON_CODES: readonly ["ACCESS_REVIEW", "MEMBER_REQUEST", "SECURITY_REVIEW", "INVITATION_CANCELLED"];
export const ORGANIZATION_PUBLIC_NAME_REASON_CODE: "PUBLIC_NAME_CORRECTION";
export const CURRENT_ACCOUNT_TASK_CLASSIFICATIONS: readonly ["NEEDS_ACTION", "WAITING", "COMPLETED"];
export const CURRENT_ACCOUNT_TASK_RESOURCE_KINDS: readonly CurrentAccountTaskResourceKind[];
export const CURRENT_ACCOUNT_TASK_NEXT_ACTIONS: readonly CurrentAccountTaskNextAction[];
export function parseEditorResource(value: unknown): EditorResource;
export function parseEditorCollection(value: unknown): EditorResource[];
export function parseCurrentAccountTaskDiscovery(value: unknown): CurrentAccountTaskDiscovery;
export function parseEditorEnvelope(value: unknown): EditorResource;
export function parseEditorReviewQueueEnvelope(value: unknown): EditorReviewQueueItem[];
export function parseEditorReviewHistoryEnvelope(value: unknown): EditorReviewHistoryPage;
export function parseEditorReviewClaimEnvelope(value: unknown): EditorReviewClaim;
export function parseFinanceFundingQueueEnvelope(value: unknown): FinanceFundingQueueItem[];
export function parseFinanceFundingHistoryEnvelope(value: unknown): FinanceFundingHistoryPage;
export function parseFinanceFundingReviewEnvelope(value: unknown): FinanceFundingReview;
export function parseTrustReportEnvelope(value: unknown): TrustReportProjection;
export function parseTrustOwnReportListEnvelope(value: unknown): TrustOwnReportListProjection;
export function parseTrustQueueEnvelope(value: unknown): TrustQueueProjection;
export function parseTrustHoldReleaseQueueEnvelope(value: unknown): TrustHoldReleaseQueueProjection;
export function parseTrustAssignmentListEnvelope(value: unknown): TrustAssignmentListProjection;
export function parseTrustCaseHistoryEnvelope(value: unknown): TrustCaseHistoryProjection;
export function parseTrustAssignedHoldEnvelope(value: unknown): TrustAssignedHoldProjection;
export function parseTrustCaseEnvelope(value: unknown): TrustCaseProjection;
export function parseTrustCommandEnvelope(value: unknown): TrustCommandResult;
export function parseAppealOwnEnvelope(value: unknown): AppealOwnProjection;
export function parseAppealQueueEnvelope(value: unknown): AppealQueueProjection;
export function parseAppealAssignmentListEnvelope(value: unknown): AppealAssignmentListProjection;
export function parseAppealAssignedEnvelope(value: unknown): AppealAssignedProjection;
export function parseAppealReviewHistoryEnvelope(value: unknown): AppealReviewHistoryProjection;
export function parseAppealReviewTerminalEnvelope(value: unknown): AppealReviewTerminalProjection;
export function parseAppealCommandEnvelope(value: unknown): AppealCommandResult;
export function parseEditorConfigurationEnvelope(value: unknown): EditorConfiguration;
export function parseSessionBootstrap(value: unknown): SessionBootstrap;
export function parseMe(value: unknown): MeProjection;
export function parsePolicyRequirementStatus(value: unknown, expectedRequirement?: PolicyRequirement | null): PolicyRequirement;
export function parsePolicyBundle(value: unknown): PolicyBundle;
export function verifyPolicyBundleDocuments(value: unknown): Promise<PolicyBundle>;
export function parseOrganizationSummary(value: unknown): OrganizationSummary;
export function parseAccessInvitationPreview(value: unknown): AccessInvitationPreview;
export function parseAccessInvitationPage(value: unknown): Page<AccessInvitationAdmin>;
export function parseMembershipPage(value: unknown): Page<MembershipAdmin>;
export function parseIssueOrganizationInvitationResponse(value: unknown): IssueOrganizationInvitationResponse;
export function parseAccessInvitationAcceptance(value: unknown): AccessInvitationAcceptance;
export function parseWorkspaceDiscovery(value: unknown): WorkspaceDiscovery;
export function parseAccountAdminCollectionEnvelope(value: unknown): AccountAdminCollection;
export function parseAccountAdminEnvelope(value: unknown): AccountAdminProjection;
export function parseAccountAdminCommandEnvelope(value: unknown): AccountAdminCommandResult;
export function selectWorkspaceCandidate(discovery: WorkspaceDiscovery, rememberedId: string | null): WorkspaceCandidate | null;
export function sectionsFromContent(resourceType: ResourceType, content?: Record<string, unknown>): Record<string, string>;
export function sectionsToContent(resourceType: ResourceType, sections: Record<string, string>): Record<string, unknown>;
export function createProfileIntent(input: { csrfToken: string; idempotencyKey: string }): WriteIntent;
export function createPolicyAcceptanceIntent(input: { me: MeProjection; requirement: PolicyRequirement; bundle: PolicyBundle; affirmedDocumentIds: string[]; csrfToken: string; idempotencyKey: string }): WriteIntent;
export function createIssueOrganizationInvitationIntent(input: { organization: OrganizationSummary; recipientEmail: string; targetRole: "ORG_ADMIN" | "DEMAND_OWNER"; expiresAt: string; csrfToken: string; idempotencyKey: string }): WriteIntent;
export function createUpdateOrganizationPublicNameIntent(input: { organization: OrganizationSummary; publicName: string; csrfToken: string; idempotencyKey: string }): WriteIntent;
export function createOrganizationLifecycleIntent(input: { resource: AccessInvitationAdmin | MembershipAdmin; action: "REVOKE_INVITATION" | "SUSPEND_MEMBERSHIP" | "RESUME_MEMBERSHIP" | "REVOKE_MEMBERSHIP"; csrfToken: string; idempotencyKey: string; reasonCode: string }): WriteIntent;
export function createAcceptOrganizationInvitationIntent(input: { invitation: AccessInvitationPreview | AccessInvitationAdmin; bundle: PolicyBundle; affirmedDocumentIds: string[]; grantedConsentOfferIds: string[]; csrfToken: string; idempotencyKey: string }): WriteIntent;
export function createDemandIntent(input: { csrfToken: string; idempotencyKey: string; taxonomyBundleId: string; clientReference: string; expiresAt: string }): WriteIntent;
export function createProfileDraftIntent(input: { resource: EditorResource; csrfToken: string; idempotencyKey: string; taxonomyBundleId: string; content: Record<string, unknown> }): WriteIntent;
export function createProfileLifecycleIntent(input: { resource: EditorResource; action: "PAUSE" | "RESUME" | "ARCHIVE"; reasonCode: "OWNER_REQUEST" | "TEMPORARY_UNAVAILABILITY" | "ACCOUNT_CLOSURE" | "SAFETY_REVIEW" | null; csrfToken: string; idempotencyKey: string }): WriteIntent;
export function createDemandCancelIntent(input: { resource: EditorResource; reasonCode: (typeof DEMAND_OWNER_CANCEL_REASON_CODES)[number]; csrfToken: string; idempotencyKey: string }): WriteIntent;
export function createDemandDraftIntent(input: { resource: EditorResource; csrfToken: string; idempotencyKey: string; taxonomyBundleId: string; content: Record<string, unknown> }): WriteIntent;
export function createResourceActionIntent(input: { resource: EditorResource; action: "PUBLISH" | "SUBMIT"; csrfToken: string; idempotencyKey: string }): WriteIntent;
export function createReviewClaimIntent(input: { queueItem: EditorReviewQueueItem; csrfToken: string; idempotencyKey: string }): WriteIntent;
export function createFinanceFundingClaimIntent(input: { queueItem: FinanceFundingQueueItem; csrfToken: string; idempotencyKey: string }): WriteIntent;
export function createFinanceFundingConfirmIntent(input: { review: FinanceFundingReview; attestationCodes: string[]; csrfToken: string; idempotencyKey: string }): WriteIntent;
export function createFinanceFundingReleaseIntent(input: { review: FinanceFundingReview; reasonCode: "CONFLICT_DECLARED" | "WORKLOAD_RELEASE"; csrfToken: string; idempotencyKey: string }): WriteIntent;
export function createFinanceFundingFindingIntent(input: { review: FinanceFundingReview; disposition: "DISCREPANCY" | "REJECTED"; reasonCodes: string[]; requiredFieldCodes: string[]; csrfToken: string; idempotencyKey: string }): WriteIntent;
export function createTrustReportIntent(input: { csrfToken: string; idempotencyKey: string; demandId: string; demandVersionId: string; category: TrustReportCategory; evidenceReferenceIds: string[]; impactCodes: string[]; incidentStartedAt: string; incidentEndedAt: string | null; requestedProtectionCodes: string[] }): WriteIntent;
export function createTrustCaseClaimIntent(input: { queueItem: TrustQueueItem; csrfToken: string; idempotencyKey: string }): WriteIntent;
export function createTrustAssignmentReleaseIntent(input: { trustCase: TrustCaseProjection; reasonCode: string; csrfToken: string; idempotencyKey: string }): WriteIntent;
export function createTrustTriageDraftIntent(input: { trustCase: TrustCaseProjection; triage: Record<string, unknown>; csrfToken: string; idempotencyKey: string }): WriteIntent;
export function createTrustTriagePublishIntent(input: { trustCase: TrustCaseProjection; csrfToken: string; idempotencyKey: string }): WriteIntent;
export function createTrustHoldIntent(input: { trustCase: TrustCaseProjection; actionCodes: TrustDemandActionCode[]; reasonCode: string; ttlMinutes: number; csrfToken: string; idempotencyKey: string }): WriteIntent;
export function createTrustHoldReleaseClaimIntent(input: { queueItem: TrustHoldReleaseQueueItem; csrfToken: string; idempotencyKey: string }): WriteIntent;
export function createTrustHoldReleaseIntent(input: { trustCase: TrustCaseProjection; reasonCode: string; csrfToken: string; idempotencyKey: string }): WriteIntent;
export function createTrustAssignedHoldReleaseIntent(input: { assignedHold: TrustAssignedHoldProjection; reasonCode: string; csrfToken: string; idempotencyKey: string }): WriteIntent;
export function createTrustOutcomeIntent(input: { trustCase: TrustCaseProjection; actionCodes: TrustDemandActionCode[]; outcomeCode: string; reasonCodes: string[]; csrfToken: string; idempotencyKey: string }): WriteIntent;
export function createAppealOpenIntent(input: { sourceOutcomeVersionId: string; csrfToken: string; idempotencyKey: string }): WriteIntent;
export function createAppealApplicationDraftIntent(input: { appeal: AppealOwnProjection; application: { applicant_statement: string; grounds: AppealGround[]; new_evidence_reference_ids: string[]; requested_outcome: AppealRequestedOutcome }; csrfToken: string; idempotencyKey: string }): WriteIntent;
export function createAppealSubmitIntent(input: { appeal: AppealOwnProjection; csrfToken: string; idempotencyKey: string }): WriteIntent;
export function createAppealReviewClaimIntent(input: { queueItem: AppealQueueItem; csrfToken: string; idempotencyKey: string }): WriteIntent;
export function createAppealReviewReleaseIntent(input: { assignedAppeal: AppealAssignedProjection; reasonCode: string; csrfToken: string; idempotencyKey: string }): WriteIntent;
export function createAppealReviewDraftIntent(input: { assignedAppeal: AppealAssignedProjection; review: { assessments: AppealAssessmentProjection[]; reason_codes: string[]; remedy_delta_codes: string[]; reviewer_note: string }; csrfToken: string; idempotencyKey: string }): WriteIntent;
export function createAppealDecisionIntent(input: { assignedAppeal: AppealAssignedProjection; decisionCode: AppealDecisionCode; csrfToken: string; idempotencyKey: string }): WriteIntent;
export function createFindingIntent(input: { resource: EditorResource; assignmentId: string; csrfToken: string; idempotencyKey: string; reasonCodes: string[]; requiredFieldPaths: string[] }): WriteIntent;
export function createReviewAssignmentReleaseIntent(input: { resource: EditorResource; assignmentId: string; csrfToken: string; idempotencyKey: string; reasonCode: (typeof REVIEW_ASSIGNMENT_RELEASE_REASON_CODES)[number] }): WriteIntent;
export function createVerifyIntent(input: { resource: EditorResource; assignmentId: string; csrfToken: string; idempotencyKey: string; budgetHealthCode: "HEALTHY" | "APPROVED_EXCEPTION"; riskCode: "STANDARD" | "ELEVATED_APPROVED"; evidenceCodes: Array<"SCOPE_COMPLETE" | "ACCEPTANCE_TESTABLE" | "BUDGET_COHERENT" | "RISK_HANDLED" | "DECLARATIONS_CONFIRMED"> }): WriteIntent;
export function createAccountAdminIntent(input: { account: AccountAdminProjection; action: "SUSPEND" | "RESUME" | "REVOKE_ALL_SESSIONS"; csrfToken: string; idempotencyKey: string; reasonCode: string }): WriteIntent;
export function createPlatformDutyIntent(input: { account: AccountAdminProjection; dutyCode: "ACCESS_ADMIN" | "APPEAL_REVIEWER" | "FINANCE_OPERATOR" | "OPERATIONS_REVIEWER" | "TRUST_OFFICER"; action: "GRANT" | "REVOKE"; csrfToken: string; idempotencyKey: string; reasonCode: string }): WriteIntent;
export function parseThreeWayConflict(value: unknown, currentEtag: string): ConflictSurface;
export function bindConflictToCurrentResource(conflict: ConflictSurface, resource: EditorResource): EditorResource;
export function serializePendingIntent(value: PendingIntent): string;
export function parsePendingIntent(value: string, now?: number): PendingIntent | null;
export function serializePendingOrganizationAdminWrite(value: PendingOrganizationAdminWrite): string;
export function parsePendingOrganizationAdminWrite(value: string, now?: number): PendingOrganizationAdminWrite | null;
export function serializePendingInvitationContext(value: PendingInvitationContext): string;
export function parsePendingInvitationContext(value: string, now?: number): PendingInvitationContext | null;
export function serializePendingInvitationAcceptance(value: PendingInvitationAcceptance): string;
export function parsePendingInvitationAcceptance(value: string, now?: number): PendingInvitationAcceptance | null;
