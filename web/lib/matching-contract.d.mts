import type { PendingIntent, WriteIntent } from "./app-contract.mjs";

export type MatchingInvitationStatus = "SENT" | "ACCEPTED" | "DECLINED" | "WITHDRAWN" | "EXPIRED" | "REVOKED";
export type MatchingAttemptStatus = "OPEN" | "SELECTED" | "CLOSED_NO_SELECTION" | "INVALIDATED" | "CANCELLED";
export type MatchingSelectionStatus = "OPEN" | "PENDING_CHOICE" | "PENDING_CLOSE" | "SELECTED" | "CLOSED_NO_SELECTION" | "CANCELLED";

export interface MatchingInvitationSummary {
  invitation_id: string;
  status: MatchingInvitationStatus;
  aggregate_version: number;
  updated_at: string;
  expires_at: string;
  snapshot_sha256: string;
  response_status: "ACCEPTED" | "DECLINED" | "WITHDRAWN" | null;
}

export interface MatchingInvitationDisclosure {
  schema_version: 1;
  canonicalization_version: "invitation-disclosure-json-v1";
  invitation_id: string;
  attempt_id: string;
  demand_id: string;
  demand_version_id: string;
  profile_id: string;
  profile_version_id: string;
  organization_preview: { organization_id: string; display_label: string };
  opportunity: {
    title: string;
    problem_summary: string;
    deliverable_summaries: string[];
    acceptance_summaries: string[];
  };
  offer: {
    currency: string;
    minimum_amount_minor: number;
    maximum_amount_minor: number;
    schedule_code: string;
    duration_weeks: number;
  };
  constraints: {
    region_codes: string[];
    language_codes: string[];
    data_sensitivity_code: string;
    ai_use_code: string;
  };
  expires_at: string;
  demand_content_sha256: string;
  profile_content_sha256: string;
  snapshot_sha256: string;
}

export interface MatchingInvitationDetail extends MatchingInvitationSummary {
  disclosure: MatchingInvitationDisclosure;
}

export interface MatchingInvitationList {
  items: MatchingInvitationDetail[];
  next_cursor: string | null;
}

export interface MatchingAttempt {
  attempt_id: string;
  demand_id: string;
  attempt_no: number;
  status: MatchingAttemptStatus;
  aggregate_version: number;
  updated_at: string;
}

export interface MatchingAttemptList {
  items: MatchingAttempt[];
  next_cursor: string | null;
}

export interface MatchingAcceptedInvitation {
  invitation_id: string;
  creator_display_handle: string;
  profile_id: string;
  profile_version_id: string;
  accepted_at: string;
  capability_summary: string;
}

export interface MatchingSelection {
  selection_id: string;
  attempt_id: string;
  candidate_selector_assignment_id: string;
  candidate_selector_assignment_version: number;
  status: MatchingSelectionStatus;
  aggregate_version: number;
  updated_at: string;
  current_invitation_set_sha256: string;
  chosen_invitation_id: string | null;
  accepted_invitations: MatchingAcceptedInvitation[];
}

export interface MatchingCandidateSelectorAssignment {
  candidate_selector_assignment_id: string;
  candidate_selector_assignment_version: number;
  selection_id: string;
  attempt_id: string;
  demand_id: string;
  status: "ACTIVE";
  expires_at: string;
  selection_status: MatchingSelectionStatus;
  selection_version: number;
  current_invitation_set_sha256: string;
}

export interface MatchingReviewAssignment {
  assignment_id: string;
  organization_id: string;
  attempt_id: string;
  match_run_id: string;
  purpose_code: "INVITATION_REVIEW" | "ATTEMPT_REVIEW" | "MATCH_RETRY";
  role_code: "MATCHING_REVIEWER";
  status: "ACTIVE" | "REVOKED" | "EXPIRED";
  aggregate_version: number;
  expires_at: string;
}

export interface MatchingReviewWorkspace extends MatchingReviewAssignment {
  attempt: {
    status: MatchingAttemptStatus;
    aggregate_version: number;
    attempt_no: number;
    updated_at: string;
    demand_id: string;
    demand_version_id: string;
    demand_aggregate_version: number;
    demand_content_sha256: string;
    input_baseline_sha256: string;
  };
  run: {
    status: "QUEUED" | "RUNNING" | "COMPLETED" | "FAILED" | "SUPERSEDED" | "CANCELLED";
    aggregate_version: number;
    ordered_result_sha256: string | null;
    candidate_count: number | null;
    eligible_count: number | null;
    excluded_count: number | null;
    failure_code: string | null;
  };
  eligible_candidates: Array<{
    creator_user_id: string;
    creator_display_handle: string;
    profile_id: string;
    profile_version_id: string;
    profile_content_sha256: string;
    evidence_version_digest: string;
    total_score: string;
    rank: number;
    component_scores: Array<{ code: string; ordinal: number; score: string }>;
    candidate_result_sha256: string;
  }>;
  invitations: MatchingReviewInvitation[];
  actions: {
    can_create_invitation: boolean;
    can_publish_invitation: boolean;
    can_invalidate_attempt: boolean;
  };
}

export interface MatchingReviewInvitation {
  invitation_id: string;
  creator_user_id: string;
  status: "CREATED" | MatchingInvitationStatus;
  aggregate_version: number;
  snapshot_sha256: string;
  expires_at: string;
  updated_at: string;
}

export interface MatchingReviewerInvitation extends MatchingReviewInvitation {
  attempt_id: string;
  match_run_id: string;
}

export const MATCHING_DECLINE_REASON_CODES: readonly ["RECIPIENT_DECLINED"];
export const MATCHING_WITHDRAW_REASON_CODES: readonly ["RECIPIENT_WITHDREW"];
export const MATCHING_SELECTION_BASIS_CODES: readonly ["CAPABILITY_SUMMARY_FIT", "DELIVERY_APPROACH_FIT", "SCHEDULE_FIT"];
export const MATCHING_SELECTION_CLOSE_REASON_CODES: readonly ["OWNER_CLOSED"];

export function parseMatchingInvitationList(value: unknown): MatchingInvitationList;
export function parseMatchingInvitationDetail(value: unknown): MatchingInvitationDetail;
export function matchingUtcTimestampsEqual(left: string, right: string): boolean;
export function parseMatchingAttemptList(value: unknown, expectedDemandId: string): MatchingAttemptList;
export function parseMatchingSelection(value: unknown): MatchingSelection;
export function matchesMatchingSelectionAssignmentVersion(selection: MatchingSelection, submittedVersion: number): boolean;
export function parseMatchingCandidateSelectorAssignment(value: unknown, expectedDemandId: string): MatchingCandidateSelectorAssignment;
export function parseMatchingReviewAssignment(value: unknown): MatchingReviewAssignment;
export function parseMatchingReviewWorkspace(value: unknown): MatchingReviewWorkspace;
export function parseMatchingReviewerInvitation(value: unknown): MatchingReviewerInvitation;
export function parseMatchingReviewerAttempt(value: unknown): MatchingAttempt;
export function assertMatchingEntityTag(entityTag: string | null, aggregateVersion: number): string;
export function createMatchingReviewInvitationExpiry(validityHours: number, nowEpochMs?: number): string;
export function createAcceptMatchingInvitationIntent(input: { invitation: MatchingInvitationDetail; entityTag: string; csrfToken: string; idempotencyKey: string }): WriteIntent;
export function createDeclineMatchingInvitationIntent(input: { invitation: MatchingInvitationDetail; entityTag: string; reasonCode: (typeof MATCHING_DECLINE_REASON_CODES)[number]; note?: string | null; csrfToken: string; idempotencyKey: string }): WriteIntent;
export function createWithdrawMatchingInvitationIntent(input: { invitation: MatchingInvitationDetail; entityTag: string; reasonCode: (typeof MATCHING_WITHDRAW_REASON_CODES)[number]; note?: string | null; csrfToken: string; idempotencyKey: string }): WriteIntent;
export function createChooseMatchingSelectionIntent(input: { organizationId: string; selection: MatchingSelection; entityTag: string; invitationId: string; selectionBasisCode: (typeof MATCHING_SELECTION_BASIS_CODES)[number]; csrfToken: string; idempotencyKey: string }): WriteIntent;
export function createCloseMatchingSelectionIntent(input: { organizationId: string; selection: MatchingSelection; entityTag: string; reasonCode: (typeof MATCHING_SELECTION_CLOSE_REASON_CODES)[number]; csrfToken: string; idempotencyKey: string }): WriteIntent;
export function createClaimCandidateSelectorIntent(input: { demandId: string; csrfToken: string; idempotencyKey: string }): WriteIntent;
export function createClaimMatchingReviewIntent(input: { csrfToken: string; idempotencyKey: string }): WriteIntent;
export function createReleaseMatchingReviewIntent(input: { assignment: MatchingReviewAssignment; entityTag: string; csrfToken: string; idempotencyKey: string }): WriteIntent;
export function createMatchingReviewInvitationIntent(input: { workspace: MatchingReviewWorkspace; creatorUserId: string; expiresAt: string; csrfToken: string; idempotencyKey: string }): WriteIntent;
export function createPublishMatchingReviewInvitationIntent(input: { invitation: MatchingReviewInvitation; csrfToken: string; idempotencyKey: string }): WriteIntent;
export function createInvalidateMatchingReviewAttemptIntent(input: { workspace: MatchingReviewWorkspace; reasonCode: "REVIEW_INVALIDATED"; csrfToken: string; idempotencyKey: string }): WriteIntent;
export function serializeMatchingPendingIntent(value: PendingIntent): string;
