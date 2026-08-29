import { serializePendingIntent } from "./app-contract.mjs";

const OPAQUE_ID = /^[A-Za-z0-9][A-Za-z0-9_-]{15,127}$/;
const SHA256 = /^[a-f0-9]{64}$/;
const CODE = /^[A-Z][A-Z0-9_.:-]{1,63}$/;
const CURRENCY = /^[A-Z]{3}$/;
const ENTITY_TAG = /^"v([1-9][0-9]*)"$/;
const IDEMPOTENCY_KEY = /^[A-Za-z0-9][A-Za-z0-9._~-]{15,127}$/;
const CSRF_TOKEN = /^[A-Za-z0-9_-]{32,256}$/;
const PERSISTED_CSRF_PLACEHOLDER = "matching_pending_csrf_not_persisted_v1";
const INVITATION_STATUSES = new Set(["SENT", "ACCEPTED", "DECLINED", "WITHDRAWN", "EXPIRED", "REVOKED"]);
const ATTEMPT_STATUSES = new Set(["OPEN", "SELECTED", "CLOSED_NO_SELECTION", "INVALIDATED", "CANCELLED"]);
const SELECTION_STATUSES = new Set([
  "OPEN", "PENDING_CHOICE", "PENDING_CLOSE", "SELECTED", "CLOSED_NO_SELECTION", "CANCELLED",
]);
const REVIEW_PURPOSE_CODES = new Set(["INVITATION_REVIEW", "ATTEMPT_REVIEW", "MATCH_RETRY"]);
const REVIEW_ASSIGNMENT_STATUSES = new Set(["ACTIVE", "REVOKED", "EXPIRED"]);
const RUN_STATUSES = new Set([
  "QUEUED", "RUNNING", "COMPLETED", "FAILED", "SUPERSEDED", "CANCELLED",
]);
const SCORE = /^(?:0|[1-9][0-9]{0,2})(?:\.[0-9]{1,6})?$/;
const MAXIMUM_MATCHING_RESPONSE_NOTE_BYTES = 500;
const MAXIMUM_MATCHING_REVIEW_INVITATION_HOURS = 28 * 24;

export const MATCHING_DECLINE_REASON_CODES = Object.freeze(["RECIPIENT_DECLINED"]);
export const MATCHING_WITHDRAW_REASON_CODES = Object.freeze(["RECIPIENT_WITHDREW"]);
export const MATCHING_SELECTION_BASIS_CODES = Object.freeze([
  "CAPABILITY_SUMMARY_FIT",
  "DELIVERY_APPROACH_FIT",
  "SCHEDULE_FIT",
]);
export const MATCHING_SELECTION_CLOSE_REASON_CODES = Object.freeze(["OWNER_CLOSED"]);

const INVITATION_KEYS = new Set([
  "invitation_id", "status", "aggregate_version", "updated_at", "expires_at",
  "snapshot_sha256", "response_status",
]);
const INVITATION_DETAIL_KEYS = new Set([...INVITATION_KEYS, "disclosure"]);
const DISCLOSURE_KEYS = new Set([
  "schema_version", "canonicalization_version", "invitation_id", "attempt_id",
  "demand_id", "demand_version_id", "profile_id", "profile_version_id",
  "organization_preview", "opportunity", "offer", "constraints", "expires_at",
  "demand_content_sha256", "profile_content_sha256", "snapshot_sha256",
]);
const ORGANIZATION_PREVIEW_KEYS = new Set(["organization_id", "display_label"]);
const OPPORTUNITY_KEYS = new Set([
  "title", "problem_summary", "deliverable_summaries", "acceptance_summaries",
]);
const OFFER_KEYS = new Set([
  "currency", "minimum_amount_minor", "maximum_amount_minor", "schedule_code",
  "duration_weeks",
]);
const CONSTRAINT_KEYS = new Set([
  "region_codes", "language_codes", "data_sensitivity_code", "ai_use_code",
]);
const ATTEMPT_KEYS = new Set([
  "attempt_id", "demand_id", "attempt_no", "status", "aggregate_version", "updated_at",
]);
const SELECTION_KEYS = new Set([
  "selection_id", "attempt_id", "candidate_selector_assignment_id",
  "candidate_selector_assignment_version", "status", "aggregate_version", "updated_at",
  "current_invitation_set_sha256", "chosen_invitation_id", "accepted_invitations",
]);
const ACCEPTED_INVITATION_KEYS = new Set([
  "invitation_id", "creator_display_handle", "profile_id", "profile_version_id",
  "accepted_at", "capability_summary",
]);
const SELECTOR_ASSIGNMENT_KEYS = new Set([
  "candidate_selector_assignment_id", "candidate_selector_assignment_version",
  "selection_id", "attempt_id", "demand_id", "status", "expires_at",
  "selection_status", "selection_version", "current_invitation_set_sha256",
]);
const REVIEW_ASSIGNMENT_KEYS = new Set([
  "assignment_id", "organization_id", "attempt_id", "match_run_id",
  "purpose_code", "role_code", "status", "aggregate_version", "expires_at",
]);
const REVIEW_WORKSPACE_KEYS = new Set([
  ...REVIEW_ASSIGNMENT_KEYS, "attempt", "run", "eligible_candidates",
  "invitations", "actions",
]);
const REVIEW_ATTEMPT_KEYS = new Set([
  "status", "aggregate_version", "attempt_no", "updated_at", "demand_id", "demand_version_id",
  "demand_aggregate_version", "demand_content_sha256", "input_baseline_sha256",
]);
const REVIEW_RUN_KEYS = new Set([
  "status", "aggregate_version", "ordered_result_sha256", "candidate_count",
  "eligible_count", "excluded_count", "failure_code",
]);
const REVIEW_CANDIDATE_KEYS = new Set([
  "creator_user_id", "creator_display_handle", "profile_id", "profile_version_id",
  "profile_content_sha256", "evidence_version_digest", "total_score", "rank",
  "component_scores", "candidate_result_sha256",
]);
const REVIEW_COMPONENT_KEYS = new Set(["code", "ordinal", "score"]);
const REVIEW_INVITATION_KEYS = new Set([
  "invitation_id", "creator_user_id", "status", "aggregate_version",
  "snapshot_sha256", "expires_at", "updated_at",
]);
const REVIEW_ACTION_KEYS = new Set([
  "can_create_invitation", "can_publish_invitation", "can_invalidate_attempt",
]);
const REVIEWER_INVITATION_KEYS = new Set([
  "invitation_id", "attempt_id", "match_run_id", "creator_user_id", "status",
  "aggregate_version", "updated_at", "expires_at", "snapshot_sha256",
]);

function invalid(code = "INVALID_MATCHING_CONTRACT") {
  throw new TypeError(code);
}

function exactObject(value, keys, code = "INVALID_MATCHING_CONTRACT") {
  if (!value || typeof value !== "object" || Array.isArray(value)) invalid(code);
  const actual = Object.keys(value);
  if (actual.length !== keys.size || actual.some((key) => !keys.has(key))) invalid(code);
  return value;
}

function opaqueId(value) {
  if (typeof value !== "string" || !OPAQUE_ID.test(value)) invalid();
  return value;
}

function sha256(value) {
  if (typeof value !== "string" || !SHA256.test(value)) invalid();
  return value;
}

function code(value) {
  if (typeof value !== "string" || !CODE.test(value)) invalid();
  return value;
}

function responseNote(value) {
  if (value === null || value === undefined || value === "") return null;
  if (typeof value === "string" && value.trim().length === 0) return null;
  if (
    typeof value !== "string"
    || Array.from(value).length > 500
    || new TextEncoder().encode(value).byteLength > MAXIMUM_MATCHING_RESPONSE_NOTE_BYTES
    || value.normalize("NFC") !== value
    || Array.from(value).some((character) => {
      const point = character.codePointAt(0);
      return point === undefined || point < 32 || (point >= 127 && point < 160);
    })
  ) invalid("INVALID_MATCHING_RESPONSE_NOTE");
  return value;
}

export function createMatchingReviewInvitationExpiry(validityHours, nowEpochMs = Date.now()) {
  if (
    !Number.isSafeInteger(validityHours)
    || validityHours < 1
    || validityHours > MAXIMUM_MATCHING_REVIEW_INVITATION_HOURS
    || !Number.isSafeInteger(nowEpochMs)
    || nowEpochMs < 0
  ) invalid("INVALID_MATCHING_REVIEW_EXPIRY");
  const expiresAt = nowEpochMs + validityHours * 60 * 60 * 1000;
  if (!Number.isSafeInteger(expiresAt)) invalid("INVALID_MATCHING_REVIEW_EXPIRY");
  return new Date(expiresAt).toISOString();
}

function utcTimestamp(value) {
  if (
    typeof value !== "string"
    || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/.test(value)
    || !Number.isFinite(Date.parse(value))
  ) invalid();
  return value;
}

function positiveVersion(value) {
  if (!Number.isSafeInteger(value) || value < 1 || value > 2147483647) invalid();
  return value;
}

function nonNegativeInteger(value) {
  if (!Number.isSafeInteger(value) || value < 0 || value > 2147483647) invalid();
  return value;
}

function score(value) {
  if (typeof value !== "string" || !SCORE.test(value) || Number(value) > 100) invalid();
  return value;
}

function safeText(value, maximum = 500) {
  if (
    typeof value !== "string"
    || [...value].length < 1
    || [...value].length > maximum
    || value.trim() !== value
    || value.normalize("NFC") !== value
    || /[\p{Cc}\p{Cf}<>]/u.test(value)
    || /(?:https?:\/\/|www\.|mailto:|\b[^\s@]+@[^\s@]+\.[^\s@]+\b)/iu.test(value)
  ) invalid();
  return value;
}

function exactCodeArray(value, { maximum = 100 } = {}) {
  if (!Array.isArray(value) || value.length > maximum) invalid();
  value.forEach(code);
  if (new Set(value).size !== value.length) invalid();
  return value;
}

function exactSummaryArray(value) {
  if (!Array.isArray(value) || value.length > 50) invalid();
  value.forEach((item) => safeText(item));
  return value;
}

function parseInvitation(value, keys = INVITATION_KEYS) {
  const result = exactObject(value, keys);
  opaqueId(result.invitation_id);
  if (!INVITATION_STATUSES.has(result.status)) invalid();
  positiveVersion(result.aggregate_version);
  utcTimestamp(result.updated_at);
  utcTimestamp(result.expires_at);
  sha256(result.snapshot_sha256);
  if (
    (result.status === "ACCEPTED" && result.response_status !== "ACCEPTED")
    || (result.status === "DECLINED" && result.response_status !== "DECLINED")
    || (result.status === "WITHDRAWN" && result.response_status !== "WITHDRAWN")
    || (!new Set(["ACCEPTED", "DECLINED", "WITHDRAWN"]).has(result.status) && result.response_status !== null)
  ) invalid();
  return result;
}

function parseDisclosure(value) {
  const result = exactObject(value, DISCLOSURE_KEYS, "MATCHING_DISCLOSURE_UNAVAILABLE");
  if (
    result.schema_version !== 1
    || result.canonicalization_version !== "invitation-disclosure-json-v1"
  ) invalid("MATCHING_DISCLOSURE_UNAVAILABLE");
  for (const field of [
    "invitation_id", "attempt_id", "demand_id", "demand_version_id", "profile_id",
    "profile_version_id",
  ]) opaqueId(result[field]);
  const organization = exactObject(result.organization_preview, ORGANIZATION_PREVIEW_KEYS);
  opaqueId(organization.organization_id);
  safeText(organization.display_label, 120);
  const opportunity = exactObject(result.opportunity, OPPORTUNITY_KEYS);
  safeText(opportunity.title, 120);
  safeText(opportunity.problem_summary);
  exactSummaryArray(opportunity.deliverable_summaries);
  exactSummaryArray(opportunity.acceptance_summaries);
  const offer = exactObject(result.offer, OFFER_KEYS);
  if (
    typeof offer.currency !== "string"
    || !CURRENCY.test(offer.currency)
    || !Number.isSafeInteger(offer.minimum_amount_minor)
    || offer.minimum_amount_minor < 0
    || !Number.isSafeInteger(offer.maximum_amount_minor)
    || offer.maximum_amount_minor < offer.minimum_amount_minor
    || !Number.isSafeInteger(offer.duration_weeks)
    || offer.duration_weeks < 1
    || offer.duration_weeks > 520
  ) invalid();
  code(offer.schedule_code);
  const constraints = exactObject(result.constraints, CONSTRAINT_KEYS);
  exactCodeArray(constraints.region_codes);
  exactCodeArray(constraints.language_codes);
  if (!new Set(["PUBLIC", "INTERNAL", "HIGH", "RESTRICTED"]).has(constraints.data_sensitivity_code)) invalid();
  if (!new Set(["PROHIBITED", "OPTIONAL", "REQUIRED"]).has(constraints.ai_use_code)) invalid();
  utcTimestamp(result.expires_at);
  sha256(result.demand_content_sha256);
  sha256(result.profile_content_sha256);
  sha256(result.snapshot_sha256);
  return result;
}

export function parseMatchingInvitationList(value) {
  const result = exactObject(value, new Set(["items", "next_cursor"]));
  if (!Array.isArray(result.items) || result.items.length > 100) invalid();
  result.items.forEach((item) => parseMatchingInvitationDetail(item));
  const identities = result.items.map((item) => item.invitation_id);
  if (new Set(identities).size !== identities.length) invalid();
  if (result.next_cursor !== null && (
    typeof result.next_cursor !== "string"
    || [...result.next_cursor].length < 16
    || [...result.next_cursor].length > 2048
  )) invalid();
  return result;
}

export function parseMatchingInvitationDetail(value) {
  const result = parseInvitation(value, INVITATION_DETAIL_KEYS);
  const disclosure = parseDisclosure(result.disclosure);
  if (
    disclosure.invitation_id !== result.invitation_id
    || disclosure.snapshot_sha256 !== result.snapshot_sha256
    || disclosure.expires_at !== result.expires_at
  ) invalid("MATCHING_DISCLOSURE_BINDING_INVALID");
  return result;
}

function parseAttempt(value) {
  const result = exactObject(value, ATTEMPT_KEYS);
  opaqueId(result.attempt_id);
  opaqueId(result.demand_id);
  positiveVersion(result.attempt_no);
  if (!ATTEMPT_STATUSES.has(result.status)) invalid();
  positiveVersion(result.aggregate_version);
  utcTimestamp(result.updated_at);
  return result;
}

export function parseMatchingAttemptList(value, expectedDemandId) {
  opaqueId(expectedDemandId);
  const result = exactObject(value, new Set(["items", "next_cursor"]));
  if (!Array.isArray(result.items) || result.items.length > 100) invalid();
  result.items.forEach((item) => {
    parseAttempt(item);
    if (item.demand_id !== expectedDemandId) invalid("MATCHING_ATTEMPT_DEMAND_BINDING_INVALID");
  });
  const identities = result.items.map((item) => item.attempt_id);
  if (
    new Set(identities).size !== identities.length
  ) invalid();
  if (result.next_cursor !== null && (
    typeof result.next_cursor !== "string"
    || [...result.next_cursor].length < 16
    || [...result.next_cursor].length > 2048
  )) invalid();
  return result;
}

function parseAcceptedInvitation(value) {
  const result = exactObject(value, ACCEPTED_INVITATION_KEYS, "MATCHING_ACCEPTED_SET_UNAVAILABLE");
  opaqueId(result.invitation_id);
  safeText(result.creator_display_handle, 120);
  opaqueId(result.profile_id);
  opaqueId(result.profile_version_id);
  utcTimestamp(result.accepted_at);
  safeText(result.capability_summary);
  return result;
}

export function parseMatchingSelection(value) {
  const result = exactObject(value, SELECTION_KEYS, "MATCHING_ACCEPTED_SET_UNAVAILABLE");
  opaqueId(result.selection_id);
  opaqueId(result.attempt_id);
  opaqueId(result.candidate_selector_assignment_id);
  positiveVersion(result.candidate_selector_assignment_version);
  if (!SELECTION_STATUSES.has(result.status)) invalid();
  positiveVersion(result.aggregate_version);
  utcTimestamp(result.updated_at);
  sha256(result.current_invitation_set_sha256);
  if (result.chosen_invitation_id !== null) opaqueId(result.chosen_invitation_id);
  if (!Array.isArray(result.accepted_invitations) || result.accepted_invitations.length > 100) {
    invalid("MATCHING_ACCEPTED_SET_UNAVAILABLE");
  }
  result.accepted_invitations.forEach(parseAcceptedInvitation);
  const invitationIds = result.accepted_invitations.map((item) => item.invitation_id);
  if (
    new Set(invitationIds).size !== invitationIds.length
    || (result.chosen_invitation_id !== null && !invitationIds.includes(result.chosen_invitation_id))
    || (new Set(["PENDING_CHOICE", "SELECTED"]).has(result.status) && result.chosen_invitation_id === null)
    || (new Set(["PENDING_CLOSE", "CLOSED_NO_SELECTION", "CANCELLED"]).has(result.status) && result.chosen_invitation_id !== null)
  ) invalid();
  return result;
}

export function parseMatchingCandidateSelectorAssignment(value, expectedDemandId) {
  opaqueId(expectedDemandId);
  const result = exactObject(value, SELECTOR_ASSIGNMENT_KEYS);
  for (const field of [
    "candidate_selector_assignment_id", "selection_id", "attempt_id", "demand_id",
  ]) opaqueId(result[field]);
  positiveVersion(result.candidate_selector_assignment_version);
  if (result.demand_id !== expectedDemandId || result.status !== "ACTIVE") invalid();
  utcTimestamp(result.expires_at);
  if (!SELECTION_STATUSES.has(result.selection_status)) invalid();
  positiveVersion(result.selection_version);
  sha256(result.current_invitation_set_sha256);
  return result;
}

function validateReviewAssignmentFields(result) {
  for (const field of ["assignment_id", "organization_id", "attempt_id", "match_run_id"]) {
    opaqueId(result[field]);
  }
  if (!REVIEW_PURPOSE_CODES.has(result.purpose_code) || result.role_code !== "MATCHING_REVIEWER") invalid();
  if (!REVIEW_ASSIGNMENT_STATUSES.has(result.status)) invalid();
  positiveVersion(result.aggregate_version);
  utcTimestamp(result.expires_at);
  return result;
}

export function parseMatchingReviewAssignment(value) {
  return validateReviewAssignmentFields(exactObject(value, REVIEW_ASSIGNMENT_KEYS));
}

export function parseMatchingReviewWorkspace(value) {
  const result = validateReviewAssignmentFields(exactObject(value, REVIEW_WORKSPACE_KEYS));
  if (result.status !== "ACTIVE") invalid("MATCHING_REVIEW_ASSIGNMENT_INACTIVE");
  const attempt = exactObject(result.attempt, REVIEW_ATTEMPT_KEYS);
  if (!ATTEMPT_STATUSES.has(attempt.status)) invalid();
  positiveVersion(attempt.aggregate_version);
  positiveVersion(attempt.attempt_no);
  utcTimestamp(attempt.updated_at);
  for (const field of ["demand_id", "demand_version_id"]) opaqueId(attempt[field]);
  positiveVersion(attempt.demand_aggregate_version);
  sha256(attempt.demand_content_sha256);
  sha256(attempt.input_baseline_sha256);

  const run = exactObject(result.run, REVIEW_RUN_KEYS);
  if (!RUN_STATUSES.has(run.status)) invalid();
  positiveVersion(run.aggregate_version);
  const counts = [run.candidate_count, run.eligible_count, run.excluded_count];
  if (run.status === "COMPLETED" || run.status === "SUPERSEDED") {
    sha256(run.ordered_result_sha256);
    for (const value of counts) nonNegativeInteger(value);
    if (run.eligible_count + run.excluded_count !== run.candidate_count) invalid();
    if (run.failure_code !== null) invalid();
  } else if (run.status === "FAILED") {
    if (run.ordered_result_sha256 !== null || counts.some((value) => value !== null)) invalid();
    code(run.failure_code);
  } else if (
    run.ordered_result_sha256 !== null
    || counts.some((value) => value !== null)
    || run.failure_code !== null
  ) {
    invalid();
  }

  if (!Array.isArray(result.eligible_candidates) || result.eligible_candidates.length > 100) invalid();
  const ranks = new Set();
  const creatorIds = new Set();
  for (const candidateValue of result.eligible_candidates) {
    const candidate = exactObject(candidateValue, REVIEW_CANDIDATE_KEYS);
    for (const field of ["creator_user_id", "profile_id", "profile_version_id"]) opaqueId(candidate[field]);
    safeText(candidate.creator_display_handle, 120);
    for (const field of [
      "profile_content_sha256", "evidence_version_digest", "candidate_result_sha256",
    ]) sha256(candidate[field]);
    score(candidate.total_score);
    positiveVersion(candidate.rank);
    if (ranks.has(candidate.rank) || creatorIds.has(candidate.creator_user_id)) invalid();
    ranks.add(candidate.rank);
    creatorIds.add(candidate.creator_user_id);
    if (!Array.isArray(candidate.component_scores) || candidate.component_scores.length > 20) invalid();
    const componentCodes = new Set();
    for (const componentValue of candidate.component_scores) {
      const component = exactObject(componentValue, REVIEW_COMPONENT_KEYS);
      safeText(component.code, 64);
      positiveVersion(component.ordinal);
      score(component.score);
      if (componentCodes.has(component.code)) invalid();
      componentCodes.add(component.code);
    }
  }

  if (!Array.isArray(result.invitations) || result.invitations.length > 100) invalid();
  const invitationIds = new Set();
  for (const invitationValue of result.invitations) {
    const invitation = exactObject(invitationValue, REVIEW_INVITATION_KEYS);
    opaqueId(invitation.invitation_id);
    opaqueId(invitation.creator_user_id);
    if (!new Set(["CREATED", ...INVITATION_STATUSES]).has(invitation.status)) invalid();
    positiveVersion(invitation.aggregate_version);
    sha256(invitation.snapshot_sha256);
    utcTimestamp(invitation.expires_at);
    utcTimestamp(invitation.updated_at);
    if (invitationIds.has(invitation.invitation_id)) invalid();
    invitationIds.add(invitation.invitation_id);
  }
  const actions = exactObject(result.actions, REVIEW_ACTION_KEYS);
  if (Object.values(actions).some((item) => typeof item !== "boolean")) invalid();
  return result;
}

export function parseMatchingReviewerInvitation(value) {
  const result = exactObject(value, REVIEWER_INVITATION_KEYS);
  for (const field of ["invitation_id", "attempt_id", "match_run_id", "creator_user_id"]) opaqueId(result[field]);
  if (!new Set(["CREATED", ...INVITATION_STATUSES]).has(result.status)) invalid();
  positiveVersion(result.aggregate_version);
  utcTimestamp(result.updated_at);
  utcTimestamp(result.expires_at);
  sha256(result.snapshot_sha256);
  return result;
}

export function parseMatchingReviewerAttempt(value) {
  return parseAttempt(value);
}

export function assertMatchingEntityTag(entityTag, aggregateVersion) {
  const match = typeof entityTag === "string" ? entityTag.match(ENTITY_TAG) : null;
  if (!match || Number(match[1]) !== aggregateVersion) invalid("INVALID_MATCHING_ETAG");
  return entityTag;
}

function writeHeaders(entityTag, aggregateVersion, csrfToken, idempotencyKey) {
  assertMatchingEntityTag(entityTag, aggregateVersion);
  if (typeof csrfToken !== "string" || !CSRF_TOKEN.test(csrfToken)) invalid("INVALID_CSRF_TOKEN");
  if (typeof idempotencyKey !== "string" || !IDEMPOTENCY_KEY.test(idempotencyKey)) invalid("INVALID_IDEMPOTENCY_KEY");
  return {
    "content-type": "application/json",
    "idempotency-key": idempotencyKey,
    "if-match": entityTag,
    "x-csrf-token": csrfToken,
  };
}

function createHeaders(csrfToken, idempotencyKey) {
  if (typeof csrfToken !== "string" || !CSRF_TOKEN.test(csrfToken)) invalid("INVALID_CSRF_TOKEN");
  if (typeof idempotencyKey !== "string" || !IDEMPOTENCY_KEY.test(idempotencyKey)) invalid("INVALID_IDEMPOTENCY_KEY");
  return {
    "content-type": "application/json",
    "idempotency-key": idempotencyKey,
    "x-csrf-token": csrfToken,
  };
}

export function createClaimCandidateSelectorIntent({ demandId, csrfToken, idempotencyKey }) {
  opaqueId(demandId);
  return {
    method: "POST",
    path: "/v1/matching/candidate-selector-assignments/claim",
    headers: createHeaders(csrfToken, idempotencyKey),
    body: { demand_id: demandId },
  };
}

export function createClaimMatchingReviewIntent({ csrfToken, idempotencyKey }) {
  return {
    method: "POST",
    path: "/v1/app/matching-review/queue/claim",
    headers: createHeaders(csrfToken, idempotencyKey),
    body: {},
  };
}

export function createReleaseMatchingReviewIntent({ assignment, entityTag, csrfToken, idempotencyKey }) {
  const exact = parseMatchingReviewAssignment(assignment);
  if (exact.status !== "ACTIVE") invalid("MATCHING_REVIEW_ASSIGNMENT_INACTIVE");
  return {
    method: "POST",
    path: "/v1/app/matching-review/assignment/release",
    headers: writeHeaders(entityTag, exact.aggregate_version, csrfToken, idempotencyKey),
    body: {},
  };
}

export function createMatchingReviewInvitationIntent({ workspace, creatorUserId, expiresAt, csrfToken, idempotencyKey }) {
  const exact = parseMatchingReviewWorkspace(workspace);
  opaqueId(creatorUserId);
  utcTimestamp(expiresAt);
  if (!exact.actions.can_create_invitation || exact.run.status !== "COMPLETED") invalid("MATCHING_REVIEW_ACTION_UNAVAILABLE");
  if (!exact.eligible_candidates.some((item) => item.creator_user_id === creatorUserId)) invalid("MATCHING_REVIEW_CANDIDATE_UNAVAILABLE");
  return {
    method: "POST",
    path: `/v1/operations/match-runs/${exact.match_run_id}/invitations`,
    headers: writeHeaders(`"v${exact.run.aggregate_version}"`, exact.run.aggregate_version, csrfToken, idempotencyKey),
    body: { match_run_id: exact.match_run_id, creator_user_id: creatorUserId, expires_at: expiresAt },
  };
}

export function createPublishMatchingReviewInvitationIntent({ invitation, csrfToken, idempotencyKey }) {
  const exact = exactObject(invitation, REVIEW_INVITATION_KEYS);
  opaqueId(exact.invitation_id);
  opaqueId(exact.creator_user_id);
  if (exact.status !== "CREATED") invalid("MATCHING_REVIEW_ACTION_UNAVAILABLE");
  positiveVersion(exact.aggregate_version);
  sha256(exact.snapshot_sha256);
  utcTimestamp(exact.expires_at);
  utcTimestamp(exact.updated_at);
  return {
    method: "POST",
    path: `/v1/operations/matching-invitations/${exact.invitation_id}/publish`,
    headers: writeHeaders(`"v${exact.aggregate_version}"`, exact.aggregate_version, csrfToken, idempotencyKey),
    body: { snapshot_sha256: exact.snapshot_sha256 },
  };
}

export function createInvalidateMatchingReviewAttemptIntent({ workspace, reasonCode, csrfToken, idempotencyKey }) {
  const exact = parseMatchingReviewWorkspace(workspace);
  if (!exact.actions.can_invalidate_attempt) invalid("MATCHING_REVIEW_ACTION_UNAVAILABLE");
  if (reasonCode !== "REVIEW_INVALIDATED") invalid("INVALID_MATCHING_INVALIDATION_REASON");
  return {
    method: "POST",
    path: `/v1/operations/matching-attempts/${exact.attempt_id}/invalidate`,
    headers: writeHeaders(`"v${exact.attempt.aggregate_version}"`, exact.attempt.aggregate_version, csrfToken, idempotencyKey),
    body: { reason_code: reasonCode, input_baseline_sha256: exact.attempt.input_baseline_sha256 },
  };
}

export function createAcceptMatchingInvitationIntent({ invitation, entityTag, csrfToken, idempotencyKey }) {
  const exact = parseMatchingInvitationDetail(invitation);
  if (exact.status !== "SENT" || exact.response_status !== null) invalid("MATCHING_INVITATION_NOT_RESPONDABLE");
  return {
    method: "POST",
    path: `/v1/me/matching-invitations/${exact.invitation_id}/accept`,
    headers: writeHeaders(entityTag, exact.aggregate_version, csrfToken, idempotencyKey),
    body: { snapshot_sha256: exact.snapshot_sha256 },
  };
}

export function createDeclineMatchingInvitationIntent({ invitation, entityTag, reasonCode, note = null, csrfToken, idempotencyKey }) {
  const exact = parseMatchingInvitationDetail(invitation);
  if (exact.status !== "SENT" || exact.response_status !== null) invalid("MATCHING_INVITATION_NOT_RESPONDABLE");
  if (!MATCHING_DECLINE_REASON_CODES.includes(reasonCode)) invalid("INVALID_MATCHING_DECLINE_REASON");
  return {
    method: "POST",
    path: `/v1/me/matching-invitations/${exact.invitation_id}/decline`,
    headers: writeHeaders(entityTag, exact.aggregate_version, csrfToken, idempotencyKey),
    body: {
      snapshot_sha256: exact.snapshot_sha256,
      reason_code: reasonCode,
      note: responseNote(note),
    },
  };
}

export function createWithdrawMatchingInvitationIntent({ invitation, entityTag, reasonCode, note = null, csrfToken, idempotencyKey }) {
  const exact = parseMatchingInvitationDetail(invitation);
  if (exact.status !== "ACCEPTED" || exact.response_status !== "ACCEPTED") {
    invalid("MATCHING_INVITATION_NOT_WITHDRAWABLE");
  }
  if (!MATCHING_WITHDRAW_REASON_CODES.includes(reasonCode)) invalid("INVALID_MATCHING_WITHDRAW_REASON");
  return {
    method: "POST",
    path: `/v1/me/matching-invitations/${exact.invitation_id}/withdraw`,
    headers: writeHeaders(entityTag, exact.aggregate_version, csrfToken, idempotencyKey),
    body: {
      snapshot_sha256: exact.snapshot_sha256,
      reason_code: reasonCode,
      note: responseNote(note),
    },
  };
}

export function createChooseMatchingSelectionIntent({
  organizationId,
  selection,
  entityTag,
  invitationId,
  selectionBasisCode,
  csrfToken,
  idempotencyKey,
}) {
  opaqueId(organizationId);
  const exact = parseMatchingSelection(selection);
  if (exact.status !== "OPEN" || exact.chosen_invitation_id !== null) invalid("MATCHING_SELECTION_NOT_OPEN");
  if (!exact.accepted_invitations.some((item) => item.invitation_id === invitationId)) {
    invalid("MATCHING_INVITATION_NOT_ACCEPTED");
  }
  if (!MATCHING_SELECTION_BASIS_CODES.includes(selectionBasisCode)) invalid("INVALID_MATCHING_SELECTION_BASIS");
  return {
    method: "POST",
    path: `/v1/organizations/${organizationId}/selections/${exact.selection_id}/choose`,
    headers: writeHeaders(entityTag, exact.aggregate_version, csrfToken, idempotencyKey),
    body: {
      invitation_id: invitationId,
      selection_basis_code: selectionBasisCode,
      current_invitation_set_sha256: exact.current_invitation_set_sha256,
      candidate_selector_assignment_id: exact.candidate_selector_assignment_id,
      candidate_selector_assignment_version: exact.candidate_selector_assignment_version,
    },
  };
}

export function createCloseMatchingSelectionIntent({
  organizationId,
  selection,
  entityTag,
  reasonCode,
  csrfToken,
  idempotencyKey,
}) {
  opaqueId(organizationId);
  const exact = parseMatchingSelection(selection);
  if (exact.status !== "OPEN" || exact.chosen_invitation_id !== null) invalid("MATCHING_SELECTION_NOT_OPEN");
  if (!MATCHING_SELECTION_CLOSE_REASON_CODES.includes(reasonCode)) invalid("INVALID_MATCHING_CLOSE_REASON");
  return {
    method: "POST",
    path: `/v1/organizations/${organizationId}/selections/${exact.selection_id}/close`,
    headers: writeHeaders(entityTag, exact.aggregate_version, csrfToken, idempotencyKey),
    body: {
      reason_code: reasonCode,
      current_invitation_set_sha256: exact.current_invitation_set_sha256,
      candidate_selector_assignment_id: exact.candidate_selector_assignment_id,
      candidate_selector_assignment_version: exact.candidate_selector_assignment_version,
    },
  };
}

export function serializeMatchingPendingIntent(value) {
  if (
    !value
    || !new Set(["MATCHING_INVITATION", "MATCHING_SELECTION", "MATCHING_ASSIGNMENT", "MATCHING_REVIEW"]).has(value.resource_type)
    || !value.intent
    || typeof value.intent !== "object"
    || !value.intent.headers
    || typeof value.intent.headers !== "object"
  ) invalid("INVALID_MATCHING_PENDING_INTENT");
  return serializePendingIntent({
    ...value,
    intent: {
      ...value.intent,
      headers: {
        ...value.intent.headers,
        "x-csrf-token": PERSISTED_CSRF_PLACEHOLDER,
      },
    },
  });
}
