import {
  DEMAND_OWNER_CANCEL_REASON_CODES,
  PROFILE_ARCHIVE_REASON_CODES,
  PROFILE_PAUSE_REASON_CODES,
  REVIEW_ASSIGNMENT_RELEASE_REASON_CODES,
  parseEditorReviewHistoryEnvelope,
  parseFinanceFundingHistoryEnvelope,
  parseEditorEnvelope,
  parseCurrentAccountTaskDiscovery,
  parseAppealAssignmentListEnvelope,
  parseAppealAssignedEnvelope,
  parseAppealCommandEnvelope,
  parseAppealOwnEnvelope,
  parseAppealQueueEnvelope,
  parseAppealReviewHistoryEnvelope,
  parseAppealReviewTerminalEnvelope,
  parseTrustAssignmentListEnvelope,
  parseTrustAssignedHoldEnvelope,
  parseTrustCaseEnvelope,
  parseTrustCaseHistoryEnvelope,
  parseTrustCommandEnvelope,
  parseTrustHoldReleaseQueueEnvelope,
  parseTrustOwnReportListEnvelope,
  parseTrustQueueEnvelope,
  parseTrustReportEnvelope,
} from "./app-contract.mjs";
import { parseSessionPage } from "./session-contract.mjs";
import { parseAdminDemandCollection, parseAdminDemandTimeline } from "./admin-demand-contract.mjs";
import {
  assertMatchingEntityTag,
  parseMatchingCandidateSelectorAssignment,
  parseMatchingAttemptList,
  parseMatchingInvitationDetail,
  parseMatchingInvitationList,
  parseMatchingReviewAssignment,
  parseMatchingReviewWorkspace,
  parseMatchingReviewerAttempt,
  parseMatchingReviewerInvitation,
  parseMatchingSelection,
  matchesMatchingSelectionAssignmentVersion,
  matchingUtcTimestampsEqual,
} from "./matching-contract.mjs";

const LOCAL_ALLOWED_ROUTES = new Map([
  ["/v1/local/personas", new Set(["GET"])],
  ["/v1/local/session", new Set(["POST", "DELETE"])],
  ["/v1/local/bootstrap", new Set(["GET"])],
  ["/v1/local/actions", new Set(["POST"])],
  ["/v1/local/reset", new Set(["POST"])],
]);

const APP_ALLOWED_ROUTES = [
  [/^\/v1\/app\/admin\/demands$/, new Set(["GET"])],
  [/^\/v1\/app\/admin\/demands\/(?!0{8}-0{4}-0{4}-0{4}-0{12})[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\/timeline$/, new Set(["GET"])],
  [/^\/v1\/app\/workspaces$/, new Set(["GET"])],
  [/^\/v1\/app\/tasks$/, new Set(["GET"])],
  [/^\/v1\/app\/configuration$/, new Set(["GET"])],
  [/^\/v1\/app\/profiles$/, new Set(["GET", "POST"])],
  [/^\/v1\/app\/profiles\/[A-Za-z0-9][A-Za-z0-9_-]{15,127}$/, new Set(["GET"])],
  [/^\/v1\/app\/profiles\/[A-Za-z0-9][A-Za-z0-9_-]{15,127}\/draft$/, new Set(["PUT"])],
  [/^\/v1\/app\/profiles\/[A-Za-z0-9][A-Za-z0-9_-]{15,127}\/publish$/, new Set(["POST"])],
  [/^\/v1\/app\/profiles\/[A-Za-z0-9][A-Za-z0-9_-]{15,127}\/(?:pause|resume|archive)$/, new Set(["POST"])],
  [/^\/v1\/app\/demands$/, new Set(["GET", "POST"])],
  [/^\/v1\/app\/demands\/[A-Za-z0-9][A-Za-z0-9_-]{15,127}$/, new Set(["GET"])],
  [/^\/v1\/app\/demands\/[A-Za-z0-9][A-Za-z0-9_-]{15,127}\/draft$/, new Set(["PUT"])],
  [/^\/v1\/app\/demands\/[A-Za-z0-9][A-Za-z0-9_-]{15,127}\/submit$/, new Set(["POST"])],
  [/^\/v1\/app\/demands\/[A-Za-z0-9][A-Za-z0-9_-]{15,127}\/cancel$/, new Set(["POST"])],
  [/^\/v1\/app\/demands\/[A-Za-z0-9][A-Za-z0-9_-]{15,127}\/review-assignments\/[A-Za-z0-9][A-Za-z0-9_-]{15,127}\/findings$/, new Set(["POST"])],
  [/^\/v1\/app\/review-queue$/, new Set(["GET"])],
  [/^\/v1\/app\/review-history$/, new Set(["GET"])],
  [/^\/v1\/app\/review-queue\/(?!0{8}-0{4}-0{4}-0{4}-0{12})[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\/claim$/, new Set(["POST"])],
  [/^\/v1\/app\/finance\/funding-reviews$/, new Set(["GET"])],
  [/^\/v1\/app\/finance\/funding-review-history$/, new Set(["GET"])],
  [/^\/v1\/app\/finance\/funding-reviews\/(?!0{8}-0{4}-0{4}-0{4}-0{12})[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/, new Set(["GET"])],
  [/^\/v1\/app\/finance\/funding-reviews\/(?!0{8}-0{4}-0{4}-0{4}-0{12})[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\/(?:claim|confirm|findings)$/, new Set(["POST"])],
  [/^\/v1\/app\/finance\/funding-reviews\/(?!0{8}-0{4}-0{4}-0{4}-0{12})[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\/assignment\/release$/, new Set(["POST"])],
  [/^\/v1\/app\/demands\/(?!0{8}-0{4}-0{4}-0{4}-0{12})[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\/review-assignments\/(?!0{8}-0{4}-0{4}-0{4}-0{12})[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\/verify$/, new Set(["POST"])],
  [/^\/v1\/app\/demands\/(?!0{8}-0{4}-0{4}-0{4}-0{12})[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\/review-assignments\/(?!0{8}-0{4}-0{4}-0{4}-0{12})[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\/release$/, new Set(["POST"])],
  [/^\/v1\/app\/admin\/accounts$/, new Set(["GET"])],
  [/^\/v1\/app\/admin\/accounts\/(?!0{8}-0{4}-0{4}-0{4}-0{12})[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/, new Set(["GET"])],
  [/^\/v1\/app\/admin\/accounts\/(?!0{8}-0{4}-0{4}-0{4}-0{12})[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\/(?:suspend|resume|revoke-all-sessions)$/, new Set(["POST"])],
  [/^\/v1\/app\/admin\/accounts\/(?!0{8}-0{4}-0{4}-0{4}-0{12})[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\/platform-duties\/(?:ACCESS_ADMIN|APPEAL_REVIEWER|FINANCE_OPERATOR|OPERATIONS_REVIEWER|TRUST_OFFICER)\/(?:grant|revoke)$/, new Set(["POST"])],
  [/^\/v1\/app\/trust\/reports$/, new Set(["GET", "POST"])],
  [/^\/v1\/app\/trust\/reports\/(?!0{8}-0{4}-0{4}-0{4}-0{12})[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/, new Set(["GET"])],
  [/^\/v1\/app\/trust\/queue$/, new Set(["GET"])],
  [/^\/v1\/app\/trust\/history$/, new Set(["GET"])],
  [/^\/v1\/app\/trust\/assignments$/, new Set(["GET"])],
  [/^\/v1\/app\/trust\/assigned-holds\/(?!0{8}-0{4}-0{4}-0{4}-0{12})[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/, new Set(["GET"])],
  [/^\/v1\/app\/trust\/queue\/(?!0{8}-0{4}-0{4}-0{4}-0{12})[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\/claim$/, new Set(["POST"])],
  [/^\/v1\/app\/trust\/hold-release-queue$/, new Set(["GET"])],
  [/^\/v1\/app\/trust\/hold-release-queue\/(?!0{8}-0{4}-0{4}-0{4}-0{12})[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\/claim$/, new Set(["POST"])],
  [/^\/v1\/app\/trust\/cases\/(?!0{8}-0{4}-0{4}-0{4}-0{12})[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/, new Set(["GET"])],
  [/^\/v1\/app\/trust\/cases\/(?!0{8}-0{4}-0{4}-0{4}-0{12})[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\/assignment\/release$/, new Set(["POST"])],
  [/^\/v1\/app\/trust\/cases\/(?!0{8}-0{4}-0{4}-0{4}-0{12})[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\/triage-draft$/, new Set(["PUT"])],
  [/^\/v1\/app\/trust\/cases\/(?!0{8}-0{4}-0{4}-0{4}-0{12})[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\/triage-publish$/, new Set(["POST"])],
  [/^\/v1\/app\/trust\/cases\/(?!0{8}-0{4}-0{4}-0{4}-0{12})[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\/holds$/, new Set(["POST"])],
  [/^\/v1\/app\/trust\/holds\/(?!0{8}-0{4}-0{4}-0{4}-0{12})[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\/release$/, new Set(["POST"])],
  [/^\/v1\/app\/trust\/cases\/(?!0{8}-0{4}-0{4}-0{4}-0{12})[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\/decisions$/, new Set(["POST"])],
  [/^\/v1\/app\/appeals$/, new Set(["GET", "POST"])],
  [/^\/v1\/app\/appeals\/(?!0{8}-0{4}-0{4}-0{4}-0{12})[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/, new Set(["GET"])],
  [/^\/v1\/app\/appeals\/(?!0{8}-0{4}-0{4}-0{4}-0{12})[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\/draft$/, new Set(["PUT"])],
  [/^\/v1\/app\/appeals\/(?!0{8}-0{4}-0{4}-0{4}-0{12})[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\/submit$/, new Set(["POST"])],
  [/^\/v1\/app\/appeal-review\/queue$/, new Set(["GET"])],
  [/^\/v1\/app\/appeal-review\/assignments$/, new Set(["GET"])],
  [/^\/v1\/app\/appeal-review\/history$/, new Set(["GET"])],
  [/^\/v1\/app\/appeal-review\/history\/(?!0{8}-0{4}-0{4}-0{4}-0{12})[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/, new Set(["GET"])],
  [/^\/v1\/app\/appeal-review\/queue\/(?!0{8}-0{4}-0{4}-0{4}-0{12})[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\/claim$/, new Set(["POST"])],
  [/^\/v1\/app\/appeal-review\/appeals\/(?!0{8}-0{4}-0{4}-0{4}-0{12})[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/, new Set(["GET"])],
  [/^\/v1\/app\/appeal-review\/appeals\/(?!0{8}-0{4}-0{4}-0{4}-0{12})[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\/assignment\/release$/, new Set(["POST"])],
  [/^\/v1\/app\/appeal-review\/appeals\/(?!0{8}-0{4}-0{4}-0{4}-0{12})[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\/review-draft$/, new Set(["PUT"])],
  [/^\/v1\/app\/appeal-review\/appeals\/(?!0{8}-0{4}-0{4}-0{4}-0{12})[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\/decide$/, new Set(["POST"])],
];

const AUTH_ALLOWED_ROUTES = new Map([
  ["/v1/auth/session", new Set(["GET"])],
  ["/v1/auth/oidc/authorizations", new Set(["POST"])],
  ["/v1/auth/oidc/callback", new Set(["GET"])],
  ["/v1/me", new Set(["GET"])],
  ["/v1/me/sessions", new Set(["GET"])],
  ["/v1/me/policy-acceptances", new Set(["POST"])],
]);
const UUID_SEGMENT = "(?!0{8}-0{4}-0{4}-0{4}-0{12})[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}";
const UUID_VALUE = new RegExp(`^${UUID_SEGMENT}$`);
const IAM_SESSION_LIST_ROUTE = "/v1/me/sessions";
const IAM_SESSION_LOGOUT_ROUTE = new RegExp(`^/v1/me/sessions/${UUID_SEGMENT}$`);
const IAM_ORGANIZATION_SUMMARY_ROUTE = new RegExp(`^/v1/organizations/${UUID_SEGMENT}$`);
const IAM_ORGANIZATION_PUBLIC_NAME_ROUTE = new RegExp(`^/v1/organizations/${UUID_SEGMENT}/public-name$`);
const IAM_ORGANIZATION_INVITATIONS_ROUTE = new RegExp(`^/v1/organizations/${UUID_SEGMENT}/access-invitations$`);
const IAM_ORGANIZATION_MEMBERSHIPS_ROUTE = new RegExp(`^/v1/organizations/${UUID_SEGMENT}/memberships$`);
const IAM_INVITATION_ACCEPT_ROUTE = new RegExp(`^/v1/access-invitations/${UUID_SEGMENT}/accept$`);
const IAM_INVITATION_REVOKE_ROUTE = new RegExp(`^/v1/access-invitations/${UUID_SEGMENT}/revoke$`);
const IAM_MEMBERSHIP_LIFECYCLE_ROUTE = new RegExp(`^/v1/memberships/${UUID_SEGMENT}/(?:suspend|resume|revoke)$`);
const IAM_INSPECT_INVITATION_ROUTE = "/v1/access-invitations/inspect";
const OIDC_SECRET = /^[A-Za-z0-9._~-]{32,2048}$/;
const ACCESS_INVITATION_TOKEN = /^[A-Za-z0-9_-]{80,4096}$/;
const OPAQUE_ID = /^[A-Za-z0-9][A-Za-z0-9_-]{15,127}$/;
const OPAQUE_ID_SEGMENT = "[A-Za-z0-9][A-Za-z0-9_-]{15,127}";
const SHA256 = /^[a-f0-9]{64}$/;
const ENTITY_TAG = /^"v[1-9][0-9]*"$/;
const IDEMPOTENCY_KEY = /^[A-Za-z0-9][A-Za-z0-9._~-]{15,127}$/;
const CSRF_TOKEN = /^[A-Za-z0-9_-]{32,512}$/;
const MATCHING_CSRF_TOKEN = /^[A-Za-z0-9_-]{32,256}$/;
const SESSION_COOKIE = /(?:^|;\s*)__Host-ds_session=[A-Za-z0-9._~-]{32,2048}(?:;|$)/;
const SESSION_SET_COOKIE = /^__Host-ds_session=[A-Za-z0-9._~-]{32,2048}; Secure; HttpOnly; SameSite=Lax; Path=\/$/;
const SESSION_CLEAR_COOKIE = "__Host-ds_session=; Secure; HttpOnly; SameSite=Lax; Path=/; Max-Age=0";
const BOOTSTRAP_SESSION_ID_HEADER = "x-bootstrap-session-id";
const IAM_CURSOR = /^[A-Za-z0-9_-]{64,1900}\.[A-Za-z0-9_-]{43}$/;
const TRACE_ID = /^[A-Za-z0-9_-]{16,128}$/;
const EMAIL_ADDRESS = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const REASON_CODE = /^[A-Z][A-Z0-9_]{1,63}$/;
const MATCHING_INVITATION_COLLECTION_ROUTE = "/v1/me/matching-invitations";
const MATCHING_INVITATION_DETAIL_ROUTE = new RegExp(`^/v1/me/matching-invitations/(${OPAQUE_ID_SEGMENT})$`);
const MATCHING_INVITATION_WRITE_ROUTE = new RegExp(`^/v1/me/matching-invitations/(${OPAQUE_ID_SEGMENT})/(accept|decline|withdraw)$`);
const MATCHING_ATTEMPT_COLLECTION_ROUTE = new RegExp(`^/v1/organizations/(${OPAQUE_ID_SEGMENT})/demands/(${OPAQUE_ID_SEGMENT})/matching-attempts$`);
const MATCHING_SELECTION_READ_ROUTE = new RegExp(`^/v1/organizations/(${OPAQUE_ID_SEGMENT})/matching-attempts/(${OPAQUE_ID_SEGMENT})/selection$`);
const MATCHING_SELECTION_ID_READ_ROUTE = new RegExp(`^/v1/organizations/(${OPAQUE_ID_SEGMENT})/selections/(${OPAQUE_ID_SEGMENT})$`);
const MATCHING_SELECTION_CHOOSE_ROUTE = new RegExp(`^/v1/organizations/(${OPAQUE_ID_SEGMENT})/selections/(${OPAQUE_ID_SEGMENT})/choose$`);
const MATCHING_SELECTION_CLOSE_ROUTE = new RegExp(`^/v1/organizations/(${OPAQUE_ID_SEGMENT})/selections/(${OPAQUE_ID_SEGMENT})/close$`);
const MATCHING_ASSIGNMENT_CLAIM_ROUTE = "/v1/matching/candidate-selector-assignments/claim";
const MATCHING_REVIEW_CLAIM_ROUTE = "/v1/app/matching-review/queue/claim";
const MATCHING_REVIEW_ASSIGNMENT_ROUTE = "/v1/app/matching-review/assignment";
const MATCHING_REVIEW_RELEASE_ROUTE = "/v1/app/matching-review/assignment/release";
const MATCHING_REVIEW_CREATE_ROUTE = new RegExp(`^/v1/operations/match-runs/(${OPAQUE_ID_SEGMENT})/invitations$`);
const MATCHING_REVIEW_PUBLISH_ROUTE = new RegExp(`^/v1/operations/matching-invitations/(${OPAQUE_ID_SEGMENT})/publish$`);
const MATCHING_REVIEW_INVALIDATE_ROUTE = new RegExp(`^/v1/operations/matching-attempts/(${OPAQUE_ID_SEGMENT})/invalidate$`);

function isMatchingRoutePath(pathname) {
  return pathname === MATCHING_INVITATION_COLLECTION_ROUTE
    || MATCHING_INVITATION_DETAIL_ROUTE.test(pathname)
    || MATCHING_INVITATION_WRITE_ROUTE.test(pathname)
    || MATCHING_ATTEMPT_COLLECTION_ROUTE.test(pathname)
    || MATCHING_SELECTION_READ_ROUTE.test(pathname)
    || MATCHING_SELECTION_ID_READ_ROUTE.test(pathname)
    || MATCHING_SELECTION_CHOOSE_ROUTE.test(pathname)
    || MATCHING_SELECTION_CLOSE_ROUTE.test(pathname)
    || pathname === MATCHING_ASSIGNMENT_CLAIM_ROUTE
    || pathname === MATCHING_REVIEW_CLAIM_ROUTE
    || pathname === MATCHING_REVIEW_ASSIGNMENT_ROUTE
    || pathname === MATCHING_REVIEW_RELEASE_ROUTE
    || MATCHING_REVIEW_CREATE_ROUTE.test(pathname)
    || MATCHING_REVIEW_PUBLISH_ROUTE.test(pathname)
    || MATCHING_REVIEW_INVALIDATE_ROUTE.test(pathname);
}
const MATCHING_CURSOR = /^[A-Za-z0-9._~-]{16,2048}$/;
const ORGANIZATION_ADMIN_REASON_CODES = new Set([
  "ACCESS_REVIEW", "MEMBER_REQUEST", "SECURITY_REVIEW", "INVITATION_CANCELLED",
]);
const POLICY_BUNDLE_ROUTE = /^\/v1\/policy-bundles\/[A-Za-z0-9][A-Za-z0-9_-]{15,127}$/;
const REVIEW_QUEUE_ROUTE = "/v1/app/review-queue";
const REVIEW_HISTORY_ROUTE = "/v1/app/review-history";
const REVIEW_HISTORY_CURSOR = /^[A-Za-z0-9_-]{64,1024}\.[A-Za-z0-9_-]{43}$/;
const ADMIN_DEMAND_COLLECTION_ROUTE = "/v1/app/admin/demands";
const ADMIN_DEMAND_TIMELINE_ROUTE = new RegExp(`^/v1/app/admin/demands/(${UUID_SEGMENT})/timeline$`);
const TASK_DISCOVERY_ROUTE = "/v1/app/tasks";
const REVIEW_CLAIM_ROUTE = /^\/v1\/app\/review-queue\/(?!0{8}-0{4}-0{4}-0{4}-0{12})[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\/claim$/;
const REVIEW_RELEASE_ROUTE = /^\/v1\/app\/demands\/((?!0{8}-0{4}-0{4}-0{4}-0{12})[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\/review-assignments\/((?!0{8}-0{4}-0{4}-0{4}-0{12})[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\/release$/;
const REVIEW_VERIFY_ROUTE = /^\/v1\/app\/demands\/(?!0{8}-0{4}-0{4}-0{4}-0{12})[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\/review-assignments\/(?!0{8}-0{4}-0{4}-0{4}-0{12})[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\/verify$/;
const FINANCE_FUNDING_QUEUE_ROUTE = "/v1/app/finance/funding-reviews";
const FINANCE_FUNDING_HISTORY_ROUTE = "/v1/app/finance/funding-review-history";
const FINANCE_FUNDING_CLAIM_ROUTE = /^\/v1\/app\/finance\/funding-reviews\/(?!0{8}-0{4}-0{4}-0{4}-0{12})[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\/claim$/;
const FINANCE_FUNDING_CONFIRM_ROUTE = /^\/v1\/app\/finance\/funding-reviews\/(?!0{8}-0{4}-0{4}-0{4}-0{12})[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\/confirm$/;
const FINANCE_FUNDING_RELEASE_ROUTE = /^\/v1\/app\/finance\/funding-reviews\/(?!0{8}-0{4}-0{4}-0{4}-0{12})[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\/assignment\/release$/;
const FINANCE_FUNDING_FINDING_ROUTE = /^\/v1\/app\/finance\/funding-reviews\/(?!0{8}-0{4}-0{4}-0{4}-0{12})[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\/findings$/;
const REVIEW_QUEUE_ETAG = /^"demand-[1-9][0-9]*-review-queue"$/;
const DEMAND_RESOURCE_ETAG = /^"demand-[1-9][0-9]*-[a-f0-9]{24}"$/;
const PROFILE_RESOURCE_ETAG = /^"creator_profile-[1-9][0-9]*-[a-f0-9]{24}"$/;
const PROFILE_LIFECYCLE_ROUTE = /^\/v1\/app\/profiles\/[A-Za-z0-9][A-Za-z0-9_-]{15,127}\/(pause|resume|archive)$/;
const DEMAND_CANCEL_ROUTE = /^\/v1\/app\/demands\/([A-Za-z0-9][A-Za-z0-9_-]{15,127})\/cancel$/;
const PROFILE_PAUSE_REASONS = new Set(PROFILE_PAUSE_REASON_CODES);
const PROFILE_ARCHIVE_REASONS = new Set(PROFILE_ARCHIVE_REASON_CODES);
const DEMAND_OWNER_CANCEL_REASONS = new Set(DEMAND_OWNER_CANCEL_REASON_CODES);
const FINANCE_FUNDING_QUEUE_ETAG = /^(?:"demand-[1-9][0-9]*-finance-queue"|"funding-review-[1-9][0-9]*")$/;
const FINANCE_FUNDING_REVIEW_ETAG = /^"funding-review-[1-9][0-9]*"$/;
const TRUST_ENTITY_TAG = /^"trust-[1-9][0-9]*-[a-f0-9]{24}"$/;
const TRUST_REPORT_ROUTE = "/v1/app/trust/reports";
const TRUST_REPORT_CURSOR = /^[A-Za-z0-9_-]{64,1024}\.[A-Za-z0-9_-]{43}$/;
const TRUST_ASSIGNMENTS_ROUTE = "/v1/app/trust/assignments";
const TRUST_CASE_HISTORY_ROUTE = "/v1/app/trust/history";
const TRUST_ASSIGNED_HOLD_ROUTE = new RegExp(`^/v1/app/trust/assigned-holds/${UUID_SEGMENT}$`);
const TRUST_REPORT_READ_ROUTE = new RegExp(`^/v1/app/trust/reports/${UUID_SEGMENT}$`);
const TRUST_CASE_CLAIM_ROUTE = new RegExp(`^/v1/app/trust/queue/${UUID_SEGMENT}/claim$`);
const TRUST_HOLD_RELEASE_CLAIM_ROUTE = new RegExp(`^/v1/app/trust/hold-release-queue/${UUID_SEGMENT}/claim$`);
const TRUST_CASE_READ_ROUTE = new RegExp(`^/v1/app/trust/cases/${UUID_SEGMENT}$`);
const TRUST_CASE_ASSIGNMENT_RELEASE_ROUTE = new RegExp(`^/v1/app/trust/cases/${UUID_SEGMENT}/assignment/release$`);
const TRUST_TRIAGE_DRAFT_ROUTE = new RegExp(`^/v1/app/trust/cases/${UUID_SEGMENT}/triage-draft$`);
const TRUST_TRIAGE_PUBLISH_ROUTE = new RegExp(`^/v1/app/trust/cases/${UUID_SEGMENT}/triage-publish$`);
const TRUST_HOLD_PLACE_ROUTE = new RegExp(`^/v1/app/trust/cases/${UUID_SEGMENT}/holds$`);
const TRUST_HOLD_RELEASE_ROUTE = new RegExp(`^/v1/app/trust/holds/${UUID_SEGMENT}/release$`);
const TRUST_OUTCOME_ROUTE = new RegExp(`^/v1/app/trust/cases/${UUID_SEGMENT}/decisions$`);
const APPEAL_ENTITY_TAG = /^"appeal-[1-9][0-9]*-[a-f0-9]{24}"$/;
const APPEAL_COLLECTION_ROUTE = "/v1/app/appeals";
const APPEAL_OWN_READ_ROUTE = new RegExp(`^/v1/app/appeals/${UUID_SEGMENT}$`);
const APPEAL_DRAFT_ROUTE = new RegExp(`^/v1/app/appeals/${UUID_SEGMENT}/draft$`);
const APPEAL_SUBMIT_ROUTE = new RegExp(`^/v1/app/appeals/${UUID_SEGMENT}/submit$`);
const APPEAL_REVIEW_QUEUE_ROUTE = "/v1/app/appeal-review/queue";
const APPEAL_REVIEW_ASSIGNMENTS_ROUTE = "/v1/app/appeal-review/assignments";
const APPEAL_REVIEW_HISTORY_ROUTE = "/v1/app/appeal-review/history";
const APPEAL_REVIEW_HISTORY_DETAIL_ROUTE = new RegExp(`^/v1/app/appeal-review/history/${UUID_SEGMENT}$`);
const APPEAL_REVIEW_CLAIM_ROUTE = new RegExp(`^/v1/app/appeal-review/queue/${UUID_SEGMENT}/claim$`);
const APPEAL_ASSIGNED_READ_ROUTE = new RegExp(`^/v1/app/appeal-review/appeals/${UUID_SEGMENT}$`);
const APPEAL_REVIEW_RELEASE_ROUTE = new RegExp(`^/v1/app/appeal-review/appeals/${UUID_SEGMENT}/assignment/release$`);
const APPEAL_REVIEW_DRAFT_ROUTE = new RegExp(`^/v1/app/appeal-review/appeals/${UUID_SEGMENT}/review-draft$`);
const APPEAL_DECIDE_ROUTE = new RegExp(`^/v1/app/appeal-review/appeals/${UUID_SEGMENT}/decide$`);
const FINANCE_FUNDING_ATTESTATION_CODES = [
  "SYNTHETIC_ONLY", "ZERO_REAL_FUNDS", "NO_PROVIDER_OR_PAYMENT",
  "TARGET_AND_EVIDENCE_MATCH",
];
const FINANCE_FUNDING_RELEASE_REASON_CODES = new Set(["CONFLICT_DECLARED", "WORKLOAD_RELEASE"]);
const FINANCE_FUNDING_FINDING_FIELD_CODES = new Set(["BUDGET", "DECLARATIONS", "RISK", "SCOPE"]);
const FINANCE_FUNDING_DISCREPANCY_REASON_CODES = new Set([
  "EVIDENCE_REFERENCE_MISMATCH", "TARGET_CONTENT_MISMATCH",
]);
const FINANCE_FUNDING_REJECTED_REASON_CODES = new Set([
  "BUDGET_PLAN_UNACCEPTABLE", "DECLARATION_CONFLICT", "SYNTHETIC_SCOPE_VIOLATION",
]);
const VERIFY_BUDGET_HEALTH_CODES = new Set(["HEALTHY", "APPROVED_EXCEPTION"]);
const VERIFY_RISK_CODES = new Set(["STANDARD", "ELEVATED_APPROVED"]);
const VERIFY_EVIDENCE_CODES = new Set([
  "SCOPE_COMPLETE", "ACCEPTANCE_TESTABLE", "BUDGET_COHERENT",
  "RISK_HANDLED", "DECLARATIONS_CONFIRMED",
]);
const REVIEW_ASSIGNMENT_RELEASE_REASON_CODE_SET = new Set(REVIEW_ASSIGNMENT_RELEASE_REASON_CODES);
const TRUST_REPORT_CATEGORIES = new Set([
  "DATA_EXPOSURE", "FRAUD_RISK", "HARASSMENT", "RETALIATION", "WORKFLOW_INTEGRITY",
]);
const TRUST_IMPACT_CODES = new Set([
  "PARTICIPANT_SAFETY_RISK", "RETALIATION_RISK", "SYNTHETIC_DATA_DISCLOSED",
  "SYNTHETIC_FINANCIAL_RISK", "WORKFLOW_INTEGRITY_RISK",
]);
const TRUST_PROTECTION_CODES = new Set(["PAUSE_MATCHING", "PAUSE_SUBMISSION", "PAUSE_VERIFICATION"]);
const TRUST_INVESTIGATION_STEP_CODES = new Set([
  "CHECK_ACCESS_SCOPE", "CHECK_DEMAND_VERSION", "CHECK_POLICY_REQUIREMENTS",
  "CHECK_SYNTHETIC_EVIDENCE", "REQUEST_PARTY_CLARIFICATION",
]);
const TRUST_ISSUE_CODES = new Set([
  "DATA_HANDLING_GAP", "FRAUD_INDICATOR", "HARASSMENT_INDICATOR",
  "RETALIATION_INDICATOR", "SCOPE_DISCLOSURE_RISK", "WORKFLOW_INTEGRITY_GAP",
]);
const TRUST_DEMAND_ACTION_CODES = new Set(["REQUEST_MATCHING", "SUBMIT_DEMAND", "VERIFY_DEMAND"]);
const TRUST_HOLD_REASON_CODES = new Set([
  "PARTICIPANT_SAFETY_RISK", "RETALIATION_RISK", "SYNTHETIC_DATA_EXPOSURE_RISK",
  "WORKFLOW_INTEGRITY_RISK",
]);
const TRUST_HOLD_RELEASE_REASON_CODES = new Set(["CASE_DECIDED", "RISK_MITIGATED", "SUPERSEDED", "TTL_CORRECTION"]);
const TRUST_ASSIGNMENT_RELEASE_REASON_CODES = new Set(["ASSIGNMENT_EXPIRED", "CONFLICT_DECLARED", "WORKLOAD_RELEASE"]);
const TRUST_OUTCOME_CODES = new Set([
  "NO_ACTION", "PROTECTION_LIFTED", "PROTECTION_MAINTAINED", "PROTECTION_MODIFIED",
  "REMEDIATION_REQUIRED",
]);
const TRUST_OUTCOME_REASON_CODES = new Set([
  "INSUFFICIENT_VERIFIED_EVIDENCE", "NO_POLICY_BREACH", "POLICY_REQUIREMENT_NOT_MET",
  "PRECAUTIONARY_ACTION_REQUIRED", "RISK_MITIGATED",
]);
const APPEAL_GROUNDS = new Set(["NEW_MATERIAL_EVIDENCE", "PROCEDURAL_ERROR", "RULE_MISAPPLICATION"]);
const APPEAL_REQUESTED_OUTCOMES = new Set(["MODIFY_MEASURE", "REMOVE_MEASURE", "VACATE_AND_REMAND"]);
const APPEAL_DECISION_CODES = new Set(["AFFIRM", "DISMISS", "MODIFY", "VACATE_AND_REMAND"]);
const APPEAL_ASSESSMENT_CODES = new Set(["ACCEPTED", "PARTIALLY_ACCEPTED", "REJECTED"]);
const APPEAL_FINDING_CODES = new Set([
  "APPEAL_NOT_SUBSTANTIATED", "NEW_EVIDENCE_MATERIAL", "PROCEDURE_MATERIAL_ERROR",
  "RULE_APPLICATION_ERROR", "RULE_APPLIED_CORRECTLY",
]);
const APPEAL_REASON_CODES = new Set([
  "APPEAL_SCOPE_INVALID", "NEW_EVIDENCE_REVIEWED", "PROCEDURAL_REVIEW_COMPLETE",
  "REMAND_REQUIRED", "SOURCE_OUTCOME_SUPPORTED", "SOURCE_OUTCOME_UNSUPPORTED",
]);
const APPEAL_REMEDY_DELTA_CODES = new Set([
  "NARROW_CORRECTIVE_MEASURE", "NO_CHANGE", "REMOVE_CORRECTIVE_MEASURE",
  "REPLACE_CORRECTIVE_MEASURE", "RETURN_TO_TRUST_REVIEW",
]);
const APPEAL_RELEASE_REASON_CODES = new Set(["ASSIGNMENT_EXPIRED", "CONFLICT_DECLARED", "WORKLOAD_RELEASE"]);
const APPEAL_ERROR_CODES = new Set([
  "APPEAL_NOT_AVAILABLE", "APPEAL_STATE_CONFLICT", "APPEAL_VALIDATION_FAILED",
  "ASSIGNMENT_UNAVAILABLE", "AUTHENTICATION_REQUIRED", "COMMAND_IN_PROGRESS",
  "COMMAND_OUTCOME_UNKNOWN", "CONFLICT_OF_INTEREST", "CSRF_INVALID", "CSRF_REQUIRED",
  "IDEMPOTENCY_KEY_REUSED", "INVALID_IDEMPOTENCY_KEY", "INVALID_REQUEST",
  "POLICY_ACCEPTANCE_REQUIRED", "PRECONDITION_REQUIRED", "RESOURCE_NOT_FOUND",
  "SERVICE_UNAVAILABLE", "SESSION_EXPIRED", "STALE_VERSION",
]);
const TRUST_ERROR_CODES = new Set([
  "ASSIGNMENT_UNAVAILABLE", "AUTHENTICATION_REQUIRED", "COMMAND_OUTCOME_UNKNOWN",
  "CONFLICT_OF_INTEREST", "CSRF_INVALID", "CSRF_REQUIRED", "IDEMPOTENCY_KEY_REUSED",
  "INVALID_IDEMPOTENCY_KEY", "INVALID_REQUEST", "PRECONDITION_REQUIRED",
  "RESOURCE_NOT_FOUND", "SERVICE_UNAVAILABLE", "SESSION_EXPIRED", "STALE_VERSION",
  "TRUST_VALIDATION_FAILED",
]);
const CLIENT_AUTHORITY_HEADERS = new Set([
  "actor", "actor-id", "assignment", "assignment-id", "authority", "duty", "duty-code", "duty-grant-id",
  "eligibility", "eligibility-code", "organization", "organization-id", "role", "server-evidence", "user-id",
  "x-actor", "x-actor-id", "x-organization", "x-organization-id", "x-org-id",
  "x-assignment", "x-assignment-id", "x-authority", "x-duty", "x-duty-code", "x-duty-grant-id",
  "x-eligibility", "x-eligibility-code", "x-role", "x-server-evidence", "x-user-id", "x-workspace-id",
]);
const WORKSPACE_ID = /^(?:org|personal|platform):[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const OIDC_ERRORS = new Set([
  "access_denied",
  "interaction_required",
  "login_required",
  "temporarily_unavailable",
  "server_error",
]);

function hasAsciiControl(value) {
  return [...value].some((character) => {
    const code = character.charCodeAt(0);
    return code < 32 || code === 127;
  });
}

function isCanonicalOrganizationPublicName(value) {
  return typeof value === "string"
    && value.trim() === value
    && value.normalize("NFC") === value
    && [...value].length >= 1
    && [...value].length <= 160
    && !/[\p{Cc}\p{Cf}]/u.test(value);
}

const REQUEST_HEADER_ALLOWLIST = new Set([
  "accept",
  "content-type",
  "cookie",
  "if-match",
  "idempotency-key",
  "x-csrf-token",
  "x-request-id",
  "x-workspace-id",
]);

const RESPONSE_HEADER_ALLOWLIST = new Set([
  "allow",
  "cache-control",
  "content-type",
  "etag",
  "retry-after",
  "set-cookie",
  "x-trace-id",
]);
const MAXIMUM_REQUEST_BODY_BYTES = 1_048_576;

export function parseLoopbackBaseUrl(value) {
  let url;
  try { url = new URL(value); } catch { throw new TypeError("INVALID_LOOPBACK_BASE_URL"); }
  const isLoopback = ["127.0.0.1", "[::1]"].includes(url.hostname);
  // Docker service discovery is admitted as one exact, non-configurable
  // origin.  Do not broaden this to arbitrary hostnames or suffix matching:
  // the value remains an SSRF trust-boundary input on developer machines.
  const isContainerApi = value === "http://api:8000" && url.origin === value;
  if (
    url.protocol !== "http:"
    || (!isLoopback && !isContainerApi)
    || !url.port
    || url.username
    || url.password
    || url.pathname !== "/"
    || url.search
    || url.hash
  ) throw new TypeError("INVALID_LOOPBACK_BASE_URL");
  return url;
}

function assertAllowedRoute(pathname, method) {
  if (!LOCAL_ALLOWED_ROUTES.get(pathname)?.has(method.toUpperCase())) {
    throw new TypeError("LOCAL_ROUTE_NOT_ALLOWED");
  }
}

function assertAllowedAppRoute(pathname, method) {
  if (!APP_ALLOWED_ROUTES.some(([pattern, methods]) => pattern.test(pathname) && methods.has(method.toUpperCase()))) {
    throw new TypeError("APP_ROUTE_NOT_ALLOWED");
  }
}

function validateAppUrl(url, method) {
  const normalizedMethod = method.toUpperCase();
  if (normalizedMethod === "GET" && (url.pathname === ADMIN_DEMAND_COLLECTION_ROUTE || ADMIN_DEMAND_TIMELINE_ROUTE.test(url.pathname))) {
    const keys = [...url.searchParams.keys()];
    const cursor = url.searchParams.get("cursor");
    const limit = url.searchParams.get("limit");
    if (/[+%;]/.test(url.search)
      || keys.some((key) => !["cursor", "limit"].includes(key))
      || new Set(keys).size !== keys.length
      || (cursor !== null && !REVIEW_HISTORY_CURSOR.test(cursor))
      || (limit !== null && !/^(?:[1-9]|[1-9][0-9]|100)$/.test(limit))) throw new TypeError("INVALID_ADMIN_DEMAND_QUERY");
    return;
  }
  const isReviewHistory = normalizedMethod === "GET" && url.pathname === REVIEW_HISTORY_ROUTE;
  const isFinanceFundingHistory = normalizedMethod === "GET"
    && url.pathname === FINANCE_FUNDING_HISTORY_ROUTE;
  const isAppealBySource = normalizedMethod === "GET" && url.pathname === APPEAL_COLLECTION_ROUTE;
  const isTrustOwnReports = normalizedMethod === "GET" && url.pathname === TRUST_REPORT_ROUTE;
  const isTrustAssignedHold = normalizedMethod === "GET"
    && TRUST_ASSIGNED_HOLD_ROUTE.test(url.pathname);
  const isTrustAssignmentIndex = normalizedMethod === "GET"
    && url.pathname === TRUST_ASSIGNMENTS_ROUTE;
  const isAppealAssignmentIndex = normalizedMethod === "GET"
    && url.pathname === APPEAL_REVIEW_ASSIGNMENTS_ROUTE;
  const isAppealReviewHistory = normalizedMethod === "GET"
    && (url.pathname === APPEAL_REVIEW_HISTORY_ROUTE || APPEAL_REVIEW_HISTORY_DETAIL_ROUTE.test(url.pathname));
  if (isTrustAssignedHold && url.search) {
    throw new TypeError("INVALID_TRUST_ASSIGNED_HOLD_QUERY");
  }
  if (isTrustAssignmentIndex && url.search) {
    throw new TypeError("INVALID_TRUST_ASSIGNMENTS_QUERY");
  }
  if (isAppealAssignmentIndex && url.search) {
    throw new TypeError("INVALID_APPEAL_ASSIGNMENTS_QUERY");
  }
  if (isAppealReviewHistory && url.search) {
    throw new TypeError("INVALID_APPEAL_REVIEW_HISTORY_QUERY");
  }
  if (isReviewHistory) {
    const rawQuery = url.search.startsWith("?") ? url.search.slice(1) : "";
    if (/[+%;]/.test(rawQuery)) throw new TypeError("INVALID_REVIEW_HISTORY_QUERY");
    const keys = [...url.searchParams.keys()];
    if (
      keys.some((key) => !new Set(["cursor", "limit"]).has(key))
      || new Set(keys).size !== keys.length
    ) throw new TypeError("INVALID_REVIEW_HISTORY_QUERY");
    const cursor = url.searchParams.get("cursor");
    const limit = url.searchParams.get("limit");
    if (
      (cursor !== null && !REVIEW_HISTORY_CURSOR.test(cursor))
      || (limit !== null && !/^(?:[1-9]|[1-9][0-9]|100)$/.test(limit))
    ) throw new TypeError("INVALID_REVIEW_HISTORY_QUERY");
    return;
  }
  if (isFinanceFundingHistory) {
    const rawQuery = url.search.startsWith("?") ? url.search.slice(1) : "";
    if (/[+%;]/.test(rawQuery)) throw new TypeError("INVALID_FINANCE_FUNDING_HISTORY_QUERY");
    const keys = [...url.searchParams.keys()];
    if (
      keys.some((key) => !new Set(["cursor", "limit"]).has(key))
      || new Set(keys).size !== keys.length
    ) throw new TypeError("INVALID_FINANCE_FUNDING_HISTORY_QUERY");
    const cursor = url.searchParams.get("cursor");
    const limit = url.searchParams.get("limit");
    if (
      (cursor !== null && !REVIEW_HISTORY_CURSOR.test(cursor))
      || (limit !== null && !/^(?:[1-9]|[1-9][0-9]|100)$/.test(limit))
    ) throw new TypeError("INVALID_FINANCE_FUNDING_HISTORY_QUERY");
    return;
  }
  if (isTrustOwnReports) {
    const keys = [...url.searchParams.keys()];
    if (
      keys.some((key) => !new Set(["cursor", "limit"]).has(key))
      || new Set(keys).size !== keys.length
    ) throw new TypeError("INVALID_TRUST_REPORT_LIST_QUERY");
    const cursor = url.searchParams.get("cursor");
    const limit = url.searchParams.get("limit");
    if (
      (cursor !== null && !TRUST_REPORT_CURSOR.test(cursor))
      || (limit !== null && !/^(?:[1-9]|[1-9][0-9]|100)$/.test(limit))
    ) throw new TypeError("INVALID_TRUST_REPORT_LIST_QUERY");
    return;
  }
  if (!isAppealBySource) {
    if (url.search) throw new TypeError("APP_ROUTE_NOT_ALLOWED");
    return;
  }
  const keys = [...url.searchParams.keys()];
  if (
    keys.length !== 1
    || keys[0] !== "source_outcome_version_id"
    || url.searchParams.getAll("source_outcome_version_id").length !== 1
    || !UUID_VALUE.test(url.searchParams.get("source_outcome_version_id") ?? "")
  ) throw new TypeError("INVALID_APPEAL_REQUEST");
}

function assertAllowedAuthRoute(url, method) {
  const normalizedMethod = method.toUpperCase();
  const staticAllowed = AUTH_ALLOWED_ROUTES.get(url.pathname)?.has(normalizedMethod) ?? false;
  const policyBundleAllowed = normalizedMethod === "GET" && POLICY_BUNDLE_ROUTE.test(url.pathname);
  const sessionLogoutAllowed = normalizedMethod === "DELETE" && IAM_SESSION_LOGOUT_ROUTE.test(url.pathname);
  if ((!staticAllowed && !policyBundleAllowed && !sessionLogoutAllowed) || url.hash) {
    throw new TypeError("AUTH_ROUTE_NOT_ALLOWED");
  }
  if (url.pathname === IAM_SESSION_LIST_ROUTE) {
    const keys = [...url.searchParams.keys()];
    if (
      keys.some((key) => !new Set(["cursor", "limit"]).has(key))
      || new Set(keys).size !== keys.length
    ) throw new TypeError("INVALID_SESSION_LIST_REQUEST");
    const cursor = url.searchParams.get("cursor");
    const limit = url.searchParams.get("limit");
    if (
      (cursor !== null && (
        cursor.length < 108
        || cursor.length > 1944
        || !IAM_CURSOR.test(cursor)
      ))
      || (limit !== null && !/^(?:[1-9]|[1-9][0-9]|100)$/.test(limit))
    ) throw new TypeError("INVALID_SESSION_LIST_REQUEST");
    return;
  }
  if (url.pathname !== "/v1/auth/oidc/callback") {
    if (url.search) throw new TypeError("AUTH_ROUTE_NOT_ALLOWED");
    return;
  }
  const allowed = new Set(["state", "code", "error", "error_description"]);
  if ([...url.searchParams.keys()].some((key) => !allowed.has(key))) throw new TypeError("AUTH_ROUTE_NOT_ALLOWED");
  if ([...allowed].some((key) => url.searchParams.getAll(key).length > 1)) throw new TypeError("AUTH_ROUTE_NOT_ALLOWED");
  const state = url.searchParams.get("state");
  const code = url.searchParams.get("code");
  const error = url.searchParams.get("error");
  const description = url.searchParams.get("error_description");
  if (!state || !OIDC_SECRET.test(state) || Boolean(code) === Boolean(error)) throw new TypeError("AUTH_ROUTE_NOT_ALLOWED");
  if (code && !OIDC_SECRET.test(code)) throw new TypeError("AUTH_ROUTE_NOT_ALLOWED");
  if (error && !OIDC_ERRORS.has(error)) throw new TypeError("AUTH_ROUTE_NOT_ALLOWED");
  if (description !== null && (description.length > 512 || hasAsciiControl(description))) {
    throw new TypeError("AUTH_ROUTE_NOT_ALLOWED");
  }
}

function assertAllowedIamRoute(url, method) {
  const normalizedMethod = method.toUpperCase();
  const isOrganizationSummary = normalizedMethod === "GET" && IAM_ORGANIZATION_SUMMARY_ROUTE.test(url.pathname);
  const isOrganizationPublicName = normalizedMethod === "POST" && IAM_ORGANIZATION_PUBLIC_NAME_ROUTE.test(url.pathname);
  const isInvitationList = normalizedMethod === "GET" && IAM_ORGANIZATION_INVITATIONS_ROUTE.test(url.pathname);
  const isMembershipList = normalizedMethod === "GET" && IAM_ORGANIZATION_MEMBERSHIPS_ROUTE.test(url.pathname);
  const isIssue = normalizedMethod === "POST" && IAM_ORGANIZATION_INVITATIONS_ROUTE.test(url.pathname);
  const isInspect = normalizedMethod === "POST" && url.pathname === IAM_INSPECT_INVITATION_ROUTE;
  const isAccept = normalizedMethod === "POST" && IAM_INVITATION_ACCEPT_ROUTE.test(url.pathname);
  const isInvitationRevoke = normalizedMethod === "POST" && IAM_INVITATION_REVOKE_ROUTE.test(url.pathname);
  const isMembershipLifecycle = normalizedMethod === "POST" && IAM_MEMBERSHIP_LIFECYCLE_ROUTE.test(url.pathname);
  const isMatchingInvitationList = normalizedMethod === "GET" && url.pathname === MATCHING_INVITATION_COLLECTION_ROUTE;
  const isMatchingInvitationDetail = normalizedMethod === "GET" && MATCHING_INVITATION_DETAIL_ROUTE.test(url.pathname);
  const isMatchingInvitationWrite = normalizedMethod === "POST" && MATCHING_INVITATION_WRITE_ROUTE.test(url.pathname);
  const isMatchingAttemptList = normalizedMethod === "GET" && MATCHING_ATTEMPT_COLLECTION_ROUTE.test(url.pathname);
  const isMatchingSelectionRead = normalizedMethod === "GET" && (
    MATCHING_SELECTION_READ_ROUTE.test(url.pathname) || MATCHING_SELECTION_ID_READ_ROUTE.test(url.pathname)
  );
  const isMatchingSelectionChoose = normalizedMethod === "POST" && MATCHING_SELECTION_CHOOSE_ROUTE.test(url.pathname);
  const isMatchingSelectionClose = normalizedMethod === "POST" && MATCHING_SELECTION_CLOSE_ROUTE.test(url.pathname);
  const isMatchingAssignmentClaim = normalizedMethod === "POST" && url.pathname === MATCHING_ASSIGNMENT_CLAIM_ROUTE;
  const isMatchingReviewClaim = normalizedMethod === "POST" && url.pathname === MATCHING_REVIEW_CLAIM_ROUTE;
  const isMatchingReviewRead = normalizedMethod === "GET" && url.pathname === MATCHING_REVIEW_ASSIGNMENT_ROUTE;
  const isMatchingReviewRelease = normalizedMethod === "POST" && url.pathname === MATCHING_REVIEW_RELEASE_ROUTE;
  const isMatchingReviewCreate = normalizedMethod === "POST" && MATCHING_REVIEW_CREATE_ROUTE.test(url.pathname);
  const isMatchingReviewPublish = normalizedMethod === "POST" && MATCHING_REVIEW_PUBLISH_ROUTE.test(url.pathname);
  const isMatchingReviewInvalidate = normalizedMethod === "POST" && MATCHING_REVIEW_INVALIDATE_ROUTE.test(url.pathname);
  if (
    url.hash
    || (!isOrganizationSummary && !isOrganizationPublicName && !isInvitationList && !isMembershipList && !isIssue
      && !isInspect && !isAccept && !isInvitationRevoke && !isMembershipLifecycle
      && !isMatchingInvitationList && !isMatchingInvitationDetail && !isMatchingInvitationWrite
      && !isMatchingAttemptList && !isMatchingSelectionRead && !isMatchingSelectionChoose
      && !isMatchingSelectionClose && !isMatchingAssignmentClaim && !isMatchingReviewClaim
      && !isMatchingReviewRead && !isMatchingReviewRelease && !isMatchingReviewCreate
      && !isMatchingReviewPublish && !isMatchingReviewInvalidate)
  ) throw new TypeError("IAM_ROUTE_NOT_ALLOWED");
  const isMatchingList = isMatchingInvitationList || isMatchingAttemptList;
  if (!isInvitationList && !isMembershipList && !isMatchingList) {
    if (url.search) throw new TypeError("IAM_ROUTE_NOT_ALLOWED");
    return;
  }
  const keys = [...url.searchParams.keys()];
  if (
    keys.some((key) => !new Set(["cursor", "limit"]).has(key))
    || new Set(keys).size !== keys.length
  ) throw new TypeError(isMatchingList ? "INVALID_MATCHING_REQUEST" : "INVALID_IAM_REQUEST");
  const cursor = url.searchParams.get("cursor");
  const limit = url.searchParams.get("limit");
  const cursorPattern = isMatchingList ? MATCHING_CURSOR : IAM_CURSOR;
  if (cursor !== null && (cursor.length < 16 || cursor.length > 2048 || !cursorPattern.test(cursor))) {
    throw new TypeError(isMatchingList ? "INVALID_MATCHING_REQUEST" : "INVALID_IAM_REQUEST");
  }
  if (limit !== null && !/^(?:[1-9]|[1-9][0-9]|100)$/.test(limit)) {
    throw new TypeError(isMatchingList ? "INVALID_MATCHING_REQUEST" : "INVALID_IAM_REQUEST");
  }
}

function exactObject(value, keys) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const actual = Object.keys(value);
  return actual.length === keys.size && actual.every((key) => keys.has(key));
}

function validatePolicyAcceptanceBody(body) {
  if (!(body instanceof Uint8Array) || body.byteLength === 0) {
    throw new TypeError("INVALID_POLICY_ACCEPTANCE_REQUEST");
  }
  let value;
  try {
    value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(body));
  } catch {
    throw new TypeError("INVALID_POLICY_ACCEPTANCE_REQUEST");
  }
  if (!exactObject(value, new Set(["policy_requirement", "policy_bundle_id", "policy_acceptances"]))) {
    throw new TypeError("INVALID_POLICY_ACCEPTANCE_REQUEST");
  }
  const requirement = value.policy_requirement;
  if (
    !exactObject(requirement, new Set(["selector_digest", "scope_type", "scope_id"]))
    || !SHA256.test(requirement.selector_digest)
    || !new Set(["USER_ROLE", "ORGANIZATION_ROLE"]).has(requirement.scope_type)
    || (requirement.scope_type === "USER_ROLE" && requirement.scope_id !== null)
    || (requirement.scope_type === "ORGANIZATION_ROLE" && !OPAQUE_ID.test(requirement.scope_id))
    || !OPAQUE_ID.test(value.policy_bundle_id)
    || !Array.isArray(value.policy_acceptances)
    || value.policy_acceptances.length < 1
    || value.policy_acceptances.length > 20
  ) throw new TypeError("INVALID_POLICY_ACCEPTANCE_REQUEST");
  const documentIds = new Set();
  for (const acceptance of value.policy_acceptances) {
    if (
      !exactObject(acceptance, new Set(["document_id", "content_sha256", "affirmed"]))
      || !OPAQUE_ID.test(acceptance.document_id)
      || !SHA256.test(acceptance.content_sha256)
      || acceptance.affirmed !== true
      || documentIds.has(acceptance.document_id)
    ) throw new TypeError("INVALID_POLICY_ACCEPTANCE_REQUEST");
    documentIds.add(acceptance.document_id);
  }
}

function assertNoClientAuthorityHeaders(headers, allowWorkspace = false) {
  for (const name of headers.keys()) {
    const normalized = name.toLowerCase();
    if (CLIENT_AUTHORITY_HEADERS.has(normalized) && !(allowWorkspace && normalized === "x-workspace-id")) {
      throw new TypeError("AUTHORITY_HEADER_FORBIDDEN");
    }
  }
}

function parseClosedJsonBody(body) {
  if (!(body instanceof Uint8Array) || body.byteLength === 0) {
    throw new TypeError("INVALID_REVIEW_REQUEST");
  }
  try {
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(body));
  } catch {
    throw new TypeError("INVALID_REVIEW_REQUEST");
  }
}

function parseIamJsonBody(body) {
  if (!(body instanceof Uint8Array) || body.byteLength === 0) throw new TypeError("INVALID_IAM_REQUEST");
  try {
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(body));
  } catch {
    throw new TypeError("INVALID_IAM_REQUEST");
  }
}

function isUtcTimestamp(value) {
  return typeof value === "string"
    && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|\+00:00)$/.test(value)
    && Number.isFinite(Date.parse(value));
}

function validateInvitationAcceptanceBody(value) {
  if (
    !exactObject(value, new Set(["policy_bundle_id", "policy_acceptances", "consent_grants"]))
    || !OPAQUE_ID.test(value.policy_bundle_id)
    || !Array.isArray(value.policy_acceptances)
    || value.policy_acceptances.length < 1
    || value.policy_acceptances.length > 20
    || !Array.isArray(value.consent_grants)
    || value.consent_grants.length > 20
  ) throw new TypeError("INVALID_IAM_REQUEST");
  const acceptedDocuments = new Set();
  for (const acceptance of value.policy_acceptances) {
    if (
      !exactObject(acceptance, new Set(["document_id", "content_sha256", "affirmed"]))
      || !OPAQUE_ID.test(acceptance.document_id)
      || !SHA256.test(acceptance.content_sha256)
      || acceptance.affirmed !== true
      || acceptedDocuments.has(acceptance.document_id)
    ) throw new TypeError("INVALID_IAM_REQUEST");
    acceptedDocuments.add(acceptance.document_id);
  }
  const grantedOffers = new Set();
  for (const grant of value.consent_grants) {
    if (
      !exactObject(grant, new Set(["consent_offer_id", "document_id", "content_sha256", "affirmed"]))
      || !OPAQUE_ID.test(grant.consent_offer_id)
      || !OPAQUE_ID.test(grant.document_id)
      || !SHA256.test(grant.content_sha256)
      || grant.affirmed !== true
      || grantedOffers.has(grant.consent_offer_id)
    ) throw new TypeError("INVALID_IAM_REQUEST");
    grantedOffers.add(grant.consent_offer_id);
  }
}

function validateIamRequest({ pathname, method, headers, body }) {
  const matchingRoute = isMatchingRoutePath(pathname);
  if (matchingRoute) {
    validateMatchingRequest({ pathname, method, headers, body });
    return;
  }
  if (method === "GET") return;
  if (headers.get("content-type") !== "application/json") throw new TypeError("INVALID_IAM_REQUEST");
  const maximumBodyBytes = pathname === IAM_INSPECT_INVITATION_ROUTE
    || IAM_ORGANIZATION_INVITATIONS_ROUTE.test(pathname)
    ? 8192
    : IAM_INVITATION_ACCEPT_ROUTE.test(pathname)
      ? 65536
      : 4096;
  if (!(body instanceof Uint8Array)) throw new TypeError("INVALID_IAM_REQUEST");
  if (body.byteLength > maximumBodyBytes) throw new TypeError("PROXY_REQUEST_TOO_LARGE");
  const value = parseIamJsonBody(body);
  if (pathname === IAM_INSPECT_INVITATION_ROUTE) {
    if (
      !exactObject(value, new Set(["access_invitation_token"]))
      || !ACCESS_INVITATION_TOKEN.test(value.access_invitation_token)
      || headers.has("if-match")
      || headers.has("idempotency-key")
      || headers.has("x-csrf-token")
    ) throw new TypeError("INVALID_IAM_REQUEST");
    return;
  }
  if (
    !ENTITY_TAG.test(headers.get("if-match") ?? "")
    || !IDEMPOTENCY_KEY.test(headers.get("idempotency-key") ?? "")
    || !CSRF_TOKEN.test(headers.get("x-csrf-token") ?? "")
  ) throw new TypeError("INVALID_IAM_REQUEST");
  if (IAM_ORGANIZATION_INVITATIONS_ROUTE.test(pathname)) {
    const recipient = value?.recipient;
    if (
      !exactObject(value, new Set(["recipient", "target_role", "expires_at"]))
      || !exactObject(recipient, new Set(["type", "value"]))
      || recipient.type !== "EMAIL"
      || typeof recipient.value !== "string"
      || recipient.value.length < 3
      || recipient.value.length > 254
      || !EMAIL_ADDRESS.test(recipient.value)
      || !new Set(["ORG_ADMIN", "DEMAND_OWNER"]).has(value.target_role)
      || !isUtcTimestamp(value.expires_at)
    ) throw new TypeError("INVALID_IAM_REQUEST");
    return;
  }
  if (IAM_ORGANIZATION_PUBLIC_NAME_ROUTE.test(pathname)) {
    if (
      !exactObject(value, new Set(["public_name", "reason_code"]))
      || !isCanonicalOrganizationPublicName(value.public_name)
      || value.reason_code !== "PUBLIC_NAME_CORRECTION"
    ) throw new TypeError("INVALID_IAM_REQUEST");
    return;
  }
  if (IAM_INVITATION_ACCEPT_ROUTE.test(pathname)) {
    validateInvitationAcceptanceBody(value);
    return;
  }
  if (
    !exactObject(value, new Set(["reason_code"]))
    || typeof value.reason_code !== "string"
    || !REASON_CODE.test(value.reason_code)
    || !ORGANIZATION_ADMIN_REASON_CODES.has(value.reason_code)
  ) throw new TypeError("INVALID_IAM_REQUEST");
}

function validateMatchingRequest({ pathname, method, headers, body }) {
  if (method === "GET") {
    if (
      body !== undefined
      || headers.has("content-type")
      || headers.has("if-match")
      || headers.has("idempotency-key")
      || headers.has("x-csrf-token")
    ) throw new TypeError("INVALID_MATCHING_REQUEST");
    return;
  }
  const assignmentClaim = pathname === MATCHING_ASSIGNMENT_CLAIM_ROUTE;
  const reviewClaim = pathname === MATCHING_REVIEW_CLAIM_ROUTE;
  const reviewRelease = pathname === MATCHING_REVIEW_RELEASE_ROUTE;
  const reviewCreate = pathname.match(MATCHING_REVIEW_CREATE_ROUTE);
  const reviewPublish = pathname.match(MATCHING_REVIEW_PUBLISH_ROUTE);
  const reviewInvalidate = pathname.match(MATCHING_REVIEW_INVALIDATE_ROUTE);
  const targetless = assignmentClaim || reviewClaim;
  if (
    method !== "POST"
    || headers.get("content-type") !== "application/json"
    || (targetless ? headers.has("if-match") : !ENTITY_TAG.test(headers.get("if-match") ?? ""))
    || !IDEMPOTENCY_KEY.test(headers.get("idempotency-key") ?? "")
    || !MATCHING_CSRF_TOKEN.test(headers.get("x-csrf-token") ?? "")
    || !(body instanceof Uint8Array)
  ) throw new TypeError("INVALID_MATCHING_REQUEST");
  if (body.byteLength > 4096) throw new TypeError("PROXY_REQUEST_TOO_LARGE");
  const value = parseIamJsonBody(body);
  const invitation = pathname.match(MATCHING_INVITATION_WRITE_ROUTE);
  const choose = pathname.match(MATCHING_SELECTION_CHOOSE_ROUTE);
  const close = pathname.match(MATCHING_SELECTION_CLOSE_ROUTE);
  if (assignmentClaim) {
    if (!exactObject(value, new Set(["demand_id"])) || !OPAQUE_ID.test(value.demand_id)) {
      throw new TypeError("INVALID_MATCHING_REQUEST");
    }
    return;
  }
  if (reviewClaim || reviewRelease) {
    if (!exactObject(value, new Set())) throw new TypeError("INVALID_MATCHING_REQUEST");
    return;
  }
  if (reviewCreate) {
    if (
      !exactObject(value, new Set(["match_run_id", "creator_user_id", "expires_at"]))
      || value.match_run_id !== reviewCreate[1]
      || !OPAQUE_ID.test(value.creator_user_id)
      || !isUtcTimestamp(value.expires_at)
    ) throw new TypeError("INVALID_MATCHING_REQUEST");
    return;
  }
  if (reviewPublish) {
    if (!exactObject(value, new Set(["snapshot_sha256"])) || !SHA256.test(value.snapshot_sha256)) {
      throw new TypeError("INVALID_MATCHING_REQUEST");
    }
    return;
  }
  if (reviewInvalidate) {
    if (
      !exactObject(value, new Set(["reason_code", "input_baseline_sha256"]))
      || value.reason_code !== "REVIEW_INVALIDATED"
      || !SHA256.test(value.input_baseline_sha256)
    ) throw new TypeError("INVALID_MATCHING_REQUEST");
    return;
  }
  if (invitation?.[2] === "accept") {
    if (!exactObject(value, new Set(["snapshot_sha256"])) || !SHA256.test(value.snapshot_sha256)) {
      throw new TypeError("INVALID_MATCHING_REQUEST");
    }
    return;
  }
  if (invitation) {
    const expectedReason = invitation[2] === "decline" ? "RECIPIENT_DECLINED" : "RECIPIENT_WITHDREW";
    const note = value?.note;
    if (
      !exactObject(value, new Set(["snapshot_sha256", "reason_code", "note"]))
      || !SHA256.test(value.snapshot_sha256)
      || value.reason_code !== expectedReason
      || (note !== null && (
        typeof note !== "string"
        || note.length < 1
        || new TextEncoder().encode(note).byteLength > 500
        || note.normalize("NFC") !== note
        || hasAsciiControl(note)
      ))
    ) throw new TypeError("INVALID_MATCHING_REQUEST");
    return;
  }
  const assignmentFieldsValid = (candidate) => OPAQUE_ID.test(candidate?.candidate_selector_assignment_id ?? "")
    && Number.isSafeInteger(candidate?.candidate_selector_assignment_version)
    && candidate.candidate_selector_assignment_version >= 1
    && candidate.candidate_selector_assignment_version <= 2147483647;
  if (choose) {
    if (
      !exactObject(value, new Set([
        "invitation_id", "selection_basis_code", "current_invitation_set_sha256",
        "candidate_selector_assignment_id", "candidate_selector_assignment_version",
      ]))
      || !OPAQUE_ID.test(value.invitation_id)
      || !new Set(["CAPABILITY_SUMMARY_FIT", "DELIVERY_APPROACH_FIT", "SCHEDULE_FIT"]).has(value.selection_basis_code)
      || !SHA256.test(value.current_invitation_set_sha256)
      || !assignmentFieldsValid(value)
    ) throw new TypeError("INVALID_MATCHING_REQUEST");
    return;
  }
  if (close) {
    if (
      !exactObject(value, new Set([
        "reason_code", "current_invitation_set_sha256",
        "candidate_selector_assignment_id", "candidate_selector_assignment_version",
      ]))
      || value.reason_code !== "OWNER_CLOSED"
      || !SHA256.test(value.current_invitation_set_sha256)
      || !assignmentFieldsValid(value)
    ) throw new TypeError("INVALID_MATCHING_REQUEST");
    return;
  }
  throw new TypeError("INVALID_MATCHING_REQUEST");
}

function validateOidcAuthorizationBody(body, headers) {
  const value = parseIamJsonBody(body);
  if (value.return_to !== "/app") throw new TypeError("INVALID_OIDC_AUTHORIZATION_REQUEST");
  const hasInvitation = Object.hasOwn(value, "access_invitation_token");
  const hasReauthenticate = Object.hasOwn(value, "reauthenticate");
  const expected = new Set(["return_to"]);
  if (hasInvitation) expected.add("access_invitation_token");
  if (hasReauthenticate) expected.add("reauthenticate");
  if (
    !exactObject(value, expected)
    || (hasInvitation && !ACCESS_INVITATION_TOKEN.test(value.access_invitation_token))
    || (hasReauthenticate && value.reauthenticate !== true)
    || (hasInvitation && hasReauthenticate)
    || (hasReauthenticate && (!headers.get("cookie") || !CSRF_TOKEN.test(headers.get("x-csrf-token") ?? "")))
    || (hasInvitation && headers.has("x-csrf-token") && (
      !headers.get("cookie")
      || !CSRF_TOKEN.test(headers.get("x-csrf-token") ?? "")
    ))
  ) throw new TypeError("INVALID_OIDC_AUTHORIZATION_REQUEST");
  return hasInvitation && !headers.has("x-csrf-token");
}

function validateReviewAppRequest({ source, pathname, method, headers, body }) {
  const isQueue = method === "GET" && pathname === REVIEW_QUEUE_ROUTE;
  const isHistory = method === "GET" && pathname === REVIEW_HISTORY_ROUTE;
  const isClaim = method === "POST" && REVIEW_CLAIM_ROUTE.test(pathname);
  const isRelease = method === "POST" && REVIEW_RELEASE_ROUTE.test(pathname);
  const isVerify = method === "POST" && REVIEW_VERIFY_ROUTE.test(pathname);
  if (!isQueue && !isHistory && !isClaim && !isRelease && !isVerify) return;
  assertNoClientAuthorityHeaders(source.headers, true);
  if (isHistory) {
    if (
      headers.has("content-type")
      || headers.has("if-match")
      || headers.has("idempotency-key")
      || headers.has("x-csrf-token")
      || body !== undefined
    ) throw new TypeError("INVALID_REVIEW_REQUEST");
    return;
  }
  if (isQueue) return;
  if (
    headers.get("content-type") !== "application/json"
    || !IDEMPOTENCY_KEY.test(headers.get("idempotency-key") ?? "")
    || !CSRF_TOKEN.test(headers.get("x-csrf-token") ?? "")
  ) throw new TypeError("INVALID_REVIEW_REQUEST");
  const value = parseClosedJsonBody(body);
  if (isClaim) {
    if (!REVIEW_QUEUE_ETAG.test(headers.get("if-match") ?? "") || !exactObject(value, new Set())) {
      throw new TypeError("INVALID_REVIEW_REQUEST");
    }
    return;
  }
  if (isRelease) {
    if (
      !DEMAND_RESOURCE_ETAG.test(headers.get("if-match") ?? "")
      || !exactObject(value, new Set(["reason_code"]))
      || !REVIEW_ASSIGNMENT_RELEASE_REASON_CODE_SET.has(value.reason_code)
    ) throw new TypeError("INVALID_REVIEW_REQUEST");
    return;
  }
  if (
    !DEMAND_RESOURCE_ETAG.test(headers.get("if-match") ?? "")
    || !exactObject(value, new Set(["budget_health_code", "risk_code", "evidence_codes"]))
    || !VERIFY_BUDGET_HEALTH_CODES.has(value.budget_health_code)
    || !VERIFY_RISK_CODES.has(value.risk_code)
    || !Array.isArray(value.evidence_codes)
    || value.evidence_codes.length === 0
    || new Set(value.evidence_codes).size !== value.evidence_codes.length
    || value.evidence_codes.some((code) => typeof code !== "string" || !VERIFY_EVIDENCE_CODES.has(code))
  ) throw new TypeError("INVALID_REVIEW_REQUEST");
}

function validateProfileLifecycleRequest({ source, pathname, method, headers, body }) {
  const match = pathname.match(PROFILE_LIFECYCLE_ROUTE);
  if (match === null) return;
  assertNoClientAuthorityHeaders(source.headers, true);
  if (
    method !== "POST"
    || headers.get("content-type") !== "application/json"
    || !IDEMPOTENCY_KEY.test(headers.get("idempotency-key") ?? "")
    || !CSRF_TOKEN.test(headers.get("x-csrf-token") ?? "")
    || !PROFILE_RESOURCE_ETAG.test(headers.get("if-match") ?? "")
  ) throw new TypeError("INVALID_PROFILE_LIFECYCLE_REQUEST");
  let value;
  try {
    value = parseClosedJsonBody(body);
  } catch {
    throw new TypeError("INVALID_PROFILE_LIFECYCLE_REQUEST");
  }
  if (match[1] === "resume") {
    if (!exactObject(value, new Set())) {
      throw new TypeError("INVALID_PROFILE_LIFECYCLE_REQUEST");
    }
    return;
  }
  const allowed = match[1] === "pause"
    ? PROFILE_PAUSE_REASONS
    : PROFILE_ARCHIVE_REASONS;
  if (
    !exactObject(value, new Set(["reason_code"]))
    || !allowed.has(value.reason_code)
  ) throw new TypeError("INVALID_PROFILE_LIFECYCLE_REQUEST");
}

function validateDemandCancelRequest({ source, pathname, method, headers, body }) {
  if (!DEMAND_CANCEL_ROUTE.test(pathname)) return;
  assertNoClientAuthorityHeaders(source.headers, true);
  if (
    method !== "POST"
    || headers.get("content-type") !== "application/json"
    || !IDEMPOTENCY_KEY.test(headers.get("idempotency-key") ?? "")
    || !CSRF_TOKEN.test(headers.get("x-csrf-token") ?? "")
    || !DEMAND_RESOURCE_ETAG.test(headers.get("if-match") ?? "")
  ) throw new TypeError("INVALID_DEMAND_CANCEL_REQUEST");
  let value;
  try {
    value = parseClosedJsonBody(body);
  } catch {
    throw new TypeError("INVALID_DEMAND_CANCEL_REQUEST");
  }
  if (
    !exactObject(value, new Set(["reason_code"]))
    || !DEMAND_OWNER_CANCEL_REASONS.has(value.reason_code)
  ) throw new TypeError("INVALID_DEMAND_CANCEL_REQUEST");
}

function validateFinanceFundingRequest({ source, pathname, method, headers, body }) {
  const isQueue = method === "GET" && pathname === FINANCE_FUNDING_QUEUE_ROUTE;
  const isHistory = method === "GET" && pathname === FINANCE_FUNDING_HISTORY_ROUTE;
  const isDetail = method === "GET"
    && pathname.startsWith(`${FINANCE_FUNDING_QUEUE_ROUTE}/`)
    && !pathname.endsWith("/claim")
    && !pathname.endsWith("/confirm")
    && !pathname.endsWith("/findings")
    && !pathname.endsWith("/assignment/release");
  const isClaim = method === "POST" && FINANCE_FUNDING_CLAIM_ROUTE.test(pathname);
  const isConfirm = method === "POST" && FINANCE_FUNDING_CONFIRM_ROUTE.test(pathname);
  const isRelease = method === "POST" && FINANCE_FUNDING_RELEASE_ROUTE.test(pathname);
  const isFinding = method === "POST" && FINANCE_FUNDING_FINDING_ROUTE.test(pathname);
  if (!isQueue && !isHistory && !isDetail && !isClaim && !isConfirm && !isRelease && !isFinding) return;
  assertNoClientAuthorityHeaders(source.headers, true);
  if (isHistory) {
    if (
      headers.has("content-type")
      || headers.has("if-match")
      || headers.has("idempotency-key")
      || headers.has("x-csrf-token")
      || body !== undefined
    ) throw new TypeError("INVALID_FINANCE_FUNDING_REQUEST");
    return;
  }
  if (isQueue || isDetail) return;
  if (
    headers.get("content-type") !== "application/json"
    || !IDEMPOTENCY_KEY.test(headers.get("idempotency-key") ?? "")
    || !CSRF_TOKEN.test(headers.get("x-csrf-token") ?? "")
  ) throw new TypeError("INVALID_FINANCE_FUNDING_REQUEST");
  const value = parseClosedJsonBody(body);
  if (isClaim) {
    if (
      !FINANCE_FUNDING_QUEUE_ETAG.test(headers.get("if-match") ?? "")
      || !exactObject(value, new Set())
    ) throw new TypeError("INVALID_FINANCE_FUNDING_REQUEST");
    return;
  }
  if (!FINANCE_FUNDING_REVIEW_ETAG.test(headers.get("if-match") ?? "")) {
    throw new TypeError("INVALID_FINANCE_FUNDING_REQUEST");
  }
  if (isRelease) {
    if (
      !exactObject(value, new Set(["reason_code"]))
      || !FINANCE_FUNDING_RELEASE_REASON_CODES.has(value.reason_code)
    ) throw new TypeError("INVALID_FINANCE_FUNDING_REQUEST");
    return;
  }
  if (isFinding) {
    const allowedReasons = value.disposition === "DISCREPANCY"
      ? FINANCE_FUNDING_DISCREPANCY_REASON_CODES
      : value.disposition === "REJECTED"
        ? FINANCE_FUNDING_REJECTED_REASON_CODES
        : null;
    const closedSorted = (values, allowed, minimum, maximum) => (
      Array.isArray(values)
      && values.length >= minimum
      && values.length <= maximum
      && values.every((code) => typeof code === "string" && allowed.has(code))
      && values.every((code, index) => index === 0 || values[index - 1] < code)
    );
    if (
      !exactObject(value, new Set(["disposition", "reason_codes", "required_field_codes"]))
      || allowedReasons === null
      || !closedSorted(value.reason_codes, allowedReasons, 1, 3)
      || !closedSorted(value.required_field_codes, FINANCE_FUNDING_FINDING_FIELD_CODES, 1, 4)
    ) throw new TypeError("INVALID_FINANCE_FUNDING_REQUEST");
    return;
  }
  if (
    !exactObject(value, new Set(["attestation_codes"]))
    || !Array.isArray(value.attestation_codes)
    || value.attestation_codes.length !== FINANCE_FUNDING_ATTESTATION_CODES.length
    || value.attestation_codes.some((code, index) => code !== FINANCE_FUNDING_ATTESTATION_CODES[index])
  ) throw new TypeError("INVALID_FINANCE_FUNDING_REQUEST");
}

function trustCodes(value, allowed, minimum, maximum) {
  return Array.isArray(value)
    && value.length >= minimum
    && value.length <= maximum
    && new Set(value).size === value.length
    && value.every((code) => typeof code === "string" && allowed.has(code));
}

function parseTrustJsonBody(body) {
  if (!(body instanceof Uint8Array) || body.byteLength === 0 || body.byteLength > 16384) {
    throw new TypeError("INVALID_TRUST_REQUEST");
  }
  try {
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(body));
  } catch {
    throw new TypeError("INVALID_TRUST_REQUEST");
  }
}

function isTrustDateTime(value) {
  return typeof value === "string"
    && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/.test(value)
    && Number.isFinite(Date.parse(value));
}

function validateTrustRequest({ source, pathname, method, headers, body }) {
  if (!pathname.startsWith("/v1/app/trust/")) return;
  assertNoClientAuthorityHeaders(source.headers, true);
  const isRead = method === "GET" && (
    pathname === TRUST_REPORT_ROUTE
    || TRUST_REPORT_READ_ROUTE.test(pathname)
    || pathname === TRUST_ASSIGNMENTS_ROUTE
    || pathname === TRUST_CASE_HISTORY_ROUTE
    || TRUST_ASSIGNED_HOLD_ROUTE.test(pathname)
    || pathname === "/v1/app/trust/queue"
    || pathname === "/v1/app/trust/hold-release-queue"
    || TRUST_CASE_READ_ROUTE.test(pathname)
  );
  if (isRead) {
    if (headers.has("content-type") || headers.has("if-match") || headers.has("idempotency-key") || headers.has("x-csrf-token")) {
      throw new TypeError("INVALID_TRUST_REQUEST");
    }
    return;
  }
  if (
    headers.get("content-type") !== "application/json"
    || !IDEMPOTENCY_KEY.test(headers.get("idempotency-key") ?? "")
    || !CSRF_TOKEN.test(headers.get("x-csrf-token") ?? "")
  ) throw new TypeError("INVALID_TRUST_REQUEST");
  const isReport = method === "POST" && pathname === TRUST_REPORT_ROUTE;
  if (isReport ? headers.has("if-match") : !TRUST_ENTITY_TAG.test(headers.get("if-match") ?? "")) {
    throw new TypeError("INVALID_TRUST_REQUEST");
  }
  const value = parseTrustJsonBody(body);
  if (isReport) {
    if (
      !exactObject(value, new Set([
        "category", "demand_id", "demand_version_id", "evidence_reference_ids", "impact_codes",
        "incident_ended_at", "incident_started_at", "requested_protection_codes",
      ]))
      || !TRUST_REPORT_CATEGORIES.has(value.category)
      || !UUID_VALUE.test(value.demand_id)
      || !UUID_VALUE.test(value.demand_version_id)
      || !trustCodes(value.evidence_reference_ids, { has: (item) => UUID_VALUE.test(item) }, 1, 32)
      || !trustCodes(value.impact_codes, TRUST_IMPACT_CODES, 1, 16)
      || !isTrustDateTime(value.incident_started_at)
      || (value.incident_ended_at !== null && !isTrustDateTime(value.incident_ended_at))
      || (value.incident_ended_at !== null && Date.parse(value.incident_ended_at) < Date.parse(value.incident_started_at))
      || !trustCodes(value.requested_protection_codes, TRUST_PROTECTION_CODES, 1, 3)
    ) throw new TypeError("INVALID_TRUST_REQUEST");
    return;
  }
  if (TRUST_CASE_CLAIM_ROUTE.test(pathname) || TRUST_HOLD_RELEASE_CLAIM_ROUTE.test(pathname)) {
    if (!exactObject(value, new Set())) throw new TypeError("INVALID_TRUST_REQUEST");
    return;
  }
  if (TRUST_TRIAGE_PUBLISH_ROUTE.test(pathname)) {
    if (
      !exactObject(value, new Set(["expected_draft_version"]))
      || !Number.isSafeInteger(value.expected_draft_version)
      || value.expected_draft_version < 1
    ) throw new TypeError("INVALID_TRUST_REQUEST");
    return;
  }
  if (TRUST_CASE_ASSIGNMENT_RELEASE_ROUTE.test(pathname)) {
    if (!exactObject(value, new Set(["reason_code"])) || !TRUST_ASSIGNMENT_RELEASE_REASON_CODES.has(value.reason_code)) {
      throw new TypeError("INVALID_TRUST_REQUEST");
    }
    return;
  }
  if (method === "PUT" && TRUST_TRIAGE_DRAFT_ROUTE.test(pathname)) {
    if (
      !exactObject(value, new Set([
        "investigation_step_codes", "issue_codes", "jurisdiction_code", "priority_code",
        "proposed_hold_actions", "proposed_hold_ttl_minutes", "restricted_note", "severity_code",
      ]))
      || !trustCodes(value.investigation_step_codes, TRUST_INVESTIGATION_STEP_CODES, 1, 16)
      || !trustCodes(value.issue_codes, TRUST_ISSUE_CODES, 1, 16)
      || !new Set(["LEGAL_REVIEW_REQUIRED", "ORGANIZATION_POLICY", "PLATFORM_INTERNAL"]).has(value.jurisdiction_code)
      || !new Set(["P0", "P1", "P2", "P3"]).has(value.priority_code)
      || !trustCodes(value.proposed_hold_actions, TRUST_DEMAND_ACTION_CODES, 1, 3)
      || !Number.isSafeInteger(value.proposed_hold_ttl_minutes)
      || value.proposed_hold_ttl_minutes < 15
      || value.proposed_hold_ttl_minutes > 10080
      || typeof value.restricted_note !== "string"
      || value.restricted_note.trim().length < 1
      || value.restricted_note.length > 4000
      || !new Set(["CRITICAL", "HIGH", "LOW", "MEDIUM"]).has(value.severity_code)
    ) throw new TypeError("INVALID_TRUST_REQUEST");
    return;
  }
  if (TRUST_HOLD_PLACE_ROUTE.test(pathname)) {
    if (
      !exactObject(value, new Set(["action_codes", "reason_code", "ttl_minutes"]))
      || !trustCodes(value.action_codes, TRUST_DEMAND_ACTION_CODES, 1, 3)
      || !TRUST_HOLD_REASON_CODES.has(value.reason_code)
      || !Number.isSafeInteger(value.ttl_minutes)
      || value.ttl_minutes < 15
      || value.ttl_minutes > 10080
    ) throw new TypeError("INVALID_TRUST_REQUEST");
    return;
  }
  if (TRUST_HOLD_RELEASE_ROUTE.test(pathname)) {
    if (!exactObject(value, new Set(["reason_code"])) || !TRUST_HOLD_RELEASE_REASON_CODES.has(value.reason_code)) {
      throw new TypeError("INVALID_TRUST_REQUEST");
    }
    return;
  }
  if (TRUST_OUTCOME_ROUTE.test(pathname)) {
    if (
      !exactObject(value, new Set(["action_codes", "outcome_code", "reason_codes"]))
      || !trustCodes(value.action_codes, TRUST_DEMAND_ACTION_CODES, 0, 3)
      || !TRUST_OUTCOME_CODES.has(value.outcome_code)
      || !trustCodes(value.reason_codes, TRUST_OUTCOME_REASON_CODES, 1, 8)
    ) throw new TypeError("INVALID_TRUST_REQUEST");
    return;
  }
  throw new TypeError("INVALID_TRUST_REQUEST");
}

function parseAppealJsonBody(body) {
  if (!(body instanceof Uint8Array) || body.byteLength === 0 || body.byteLength > 65536) {
    throw new TypeError("INVALID_APPEAL_REQUEST");
  }
  try {
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(body));
  } catch {
    throw new TypeError("INVALID_APPEAL_REQUEST");
  }
}

function appealCodes(value, allowed, minimum, maximum) {
  return Array.isArray(value)
    && value.length >= minimum
    && value.length <= maximum
    && new Set(value).size === value.length
    && value.every((code) => typeof code === "string" && allowed.has(code));
}

function validAppealApplication(value) {
  return exactObject(value, new Set([
    "applicant_statement", "grounds", "new_evidence_reference_ids", "requested_outcome",
  ]))
    && typeof value.applicant_statement === "string"
    && value.applicant_statement.length >= 1
    && value.applicant_statement.length <= 4000
    && appealCodes(value.grounds, APPEAL_GROUNDS, 1, 3)
    && appealCodes(value.new_evidence_reference_ids, { has: (item) => UUID_VALUE.test(item) }, 0, 32)
    && (!value.grounds.includes("NEW_MATERIAL_EVIDENCE") || value.new_evidence_reference_ids.length >= 1)
    && APPEAL_REQUESTED_OUTCOMES.has(value.requested_outcome);
}

function validAppealAssessment(value) {
  return exactObject(value, new Set([
    "accepted_evidence_reference_ids", "assessment_code", "finding_codes", "ground",
  ]))
    && appealCodes(value.accepted_evidence_reference_ids, { has: (item) => UUID_VALUE.test(item) }, 0, 32)
    && APPEAL_ASSESSMENT_CODES.has(value.assessment_code)
    && appealCodes(value.finding_codes, APPEAL_FINDING_CODES, 1, 32)
    && APPEAL_GROUNDS.has(value.ground);
}

function validAppealReview(value) {
  if (
    !exactObject(value, new Set(["assessments", "reason_codes", "remedy_delta_codes", "reviewer_note"]))
    || !Array.isArray(value.assessments)
    || value.assessments.length < 1
    || value.assessments.length > 3
    || value.assessments.some((assessment) => !validAppealAssessment(assessment))
    || !appealCodes(value.reason_codes, APPEAL_REASON_CODES, 1, 32)
    || !appealCodes(value.remedy_delta_codes, APPEAL_REMEDY_DELTA_CODES, 1, 32)
    || typeof value.reviewer_note !== "string"
    || value.reviewer_note.length < 1
    || value.reviewer_note.length > 4000
  ) return false;
  const normalized = value.assessments.map((assessment) => JSON.stringify({
    accepted_evidence_reference_ids: assessment.accepted_evidence_reference_ids,
    assessment_code: assessment.assessment_code,
    finding_codes: assessment.finding_codes,
    ground: assessment.ground,
  }));
  return new Set(normalized).size === normalized.length
    && new Set(value.assessments.map((assessment) => assessment.ground)).size === value.assessments.length;
}

function validateAppealRequest({ source, pathname, method, headers, body }) {
  if (!pathname.startsWith("/v1/app/appeal")) return;
  assertNoClientAuthorityHeaders(source.headers, true);
  const isRead = method === "GET" && (
    pathname === APPEAL_COLLECTION_ROUTE
    || APPEAL_OWN_READ_ROUTE.test(pathname)
    || pathname === APPEAL_REVIEW_QUEUE_ROUTE
    || pathname === APPEAL_REVIEW_ASSIGNMENTS_ROUTE
    || pathname === APPEAL_REVIEW_HISTORY_ROUTE
    || APPEAL_REVIEW_HISTORY_DETAIL_ROUTE.test(pathname)
    || APPEAL_ASSIGNED_READ_ROUTE.test(pathname)
  );
  if (isRead) {
    if (headers.has("content-type") || headers.has("if-match") || headers.has("idempotency-key") || headers.has("x-csrf-token")) {
      throw new TypeError("INVALID_APPEAL_REQUEST");
    }
    return;
  }
  if (
    headers.get("content-type") !== "application/json"
    || !IDEMPOTENCY_KEY.test(headers.get("idempotency-key") ?? "")
    || !CSRF_TOKEN.test(headers.get("x-csrf-token") ?? "")
  ) throw new TypeError("INVALID_APPEAL_REQUEST");
  const isOpen = method === "POST" && pathname === APPEAL_COLLECTION_ROUTE;
  if (isOpen ? headers.has("if-match") : !APPEAL_ENTITY_TAG.test(headers.get("if-match") ?? "")) {
    throw new TypeError("INVALID_APPEAL_REQUEST");
  }
  const value = parseAppealJsonBody(body);
  if (isOpen) {
    if (!exactObject(value, new Set(["source_outcome_version_id"])) || !UUID_VALUE.test(value.source_outcome_version_id)) {
      throw new TypeError("INVALID_APPEAL_REQUEST");
    }
    return;
  }
  if (method === "PUT" && APPEAL_DRAFT_ROUTE.test(pathname)) {
    if (!validAppealApplication(value)) throw new TypeError("INVALID_APPEAL_REQUEST");
    return;
  }
  if (method === "POST" && APPEAL_SUBMIT_ROUTE.test(pathname)) {
    if (
      !exactObject(value, new Set(["expected_draft_version"]))
      || !Number.isSafeInteger(value.expected_draft_version)
      || value.expected_draft_version < 1
    ) throw new TypeError("INVALID_APPEAL_REQUEST");
    return;
  }
  if (method === "POST" && APPEAL_REVIEW_CLAIM_ROUTE.test(pathname)) {
    if (!exactObject(value, new Set())) throw new TypeError("INVALID_APPEAL_REQUEST");
    return;
  }
  if (method === "POST" && APPEAL_REVIEW_RELEASE_ROUTE.test(pathname)) {
    if (!exactObject(value, new Set(["reason_code"])) || !APPEAL_RELEASE_REASON_CODES.has(value.reason_code)) {
      throw new TypeError("INVALID_APPEAL_REQUEST");
    }
    return;
  }
  if (method === "PUT" && APPEAL_REVIEW_DRAFT_ROUTE.test(pathname)) {
    if (!validAppealReview(value)) throw new TypeError("INVALID_APPEAL_REQUEST");
    return;
  }
  if (method === "POST" && APPEAL_DECIDE_ROUTE.test(pathname)) {
    if (
      !exactObject(value, new Set(["decision_code", "expected_review_draft_version"]))
      || !APPEAL_DECISION_CODES.has(value.decision_code)
      || !Number.isSafeInteger(value.expected_review_draft_version)
      || value.expected_review_draft_version < 1
    ) throw new TypeError("INVALID_APPEAL_REQUEST");
    return;
  }
  throw new TypeError("INVALID_APPEAL_REQUEST");
}

function validateClosedAppRequest(facts) {
  if (facts.pathname === ADMIN_DEMAND_COLLECTION_ROUTE || ADMIN_DEMAND_TIMELINE_ROUTE.test(facts.pathname)) {
    assertNoClientAuthorityHeaders(facts.source.headers, true);
    if (facts.method !== "GET" || facts.body !== undefined
      || ["content-type", "if-match", "idempotency-key", "x-csrf-token"].some((name) => facts.headers.has(name))) {
      throw new TypeError("INVALID_ADMIN_DEMAND_REQUEST");
    }
  }
  validateProfileLifecycleRequest(facts);
  validateDemandCancelRequest(facts);
  validateReviewAppRequest(facts);
  validateFinanceFundingRequest(facts);
  validateTrustRequest(facts);
  validateAppealRequest(facts);
}

async function createProxyRequest(source, baseUrl, assertRoute, workspacePolicy = "optional", validateRequest = null, validateUrl = null) {
  const sourceUrl = new URL(source.url);
  assertRoute(sourceUrl.pathname, source.method);
  if (sourceUrl.hash) assertRoute("", source.method);
  if (validateUrl) validateUrl(sourceUrl, source.method);
  else if (sourceUrl.search) assertRoute("", source.method);
  const loopback = parseLoopbackBaseUrl(baseUrl);
  const target = new URL(`${sourceUrl.pathname}${sourceUrl.search}`, loopback);
  const headers = new Headers();
  for (const [name, value] of source.headers) {
    if (REQUEST_HEADER_ALLOWLIST.has(name.toLowerCase())) headers.set(name, value);
  }
  const workspace = headers.get("x-workspace-id");
  if (workspacePolicy === "forbidden" && workspace !== null) {
    throw new TypeError("WORKSPACE_HEADER_FORBIDDEN");
  }
  if (workspace !== null && !WORKSPACE_ID.test(workspace)) {
    throw new TypeError("INVALID_WORKSPACE_ID");
  }
  if (workspacePolicy === "required" && workspace === null) {
    throw new TypeError("WORKSPACE_REQUIRED");
  }
  // Browser-supplied Origin/Host/Forwarded headers are outside the trust
  // boundary. Reconstruct the upstream Origin from the validated platform
  // origin; Request(target) owns the upstream Host.
  headers.set("origin", loopback.origin);
  const method = source.method.toUpperCase();
  const body = method === "GET" || method === "HEAD" ? undefined : await boundedRequestBody(source);
  if (validateRequest) validateRequest({ source, pathname: sourceUrl.pathname, method, headers, body });
  return new Request(target, { method, headers, body, redirect: "manual" });
}

async function boundedRequestBody(source) {
  const declared = source.headers.get("content-length");
  if (declared !== null && (!/^\d{1,10}$/.test(declared) || Number(declared) > MAXIMUM_REQUEST_BODY_BYTES)) {
    throw new TypeError("PROXY_REQUEST_TOO_LARGE");
  }
  if (!source.body) return undefined;
  const reader = source.body.getReader();
  const chunks = [];
  let length = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    length += value.byteLength;
    if (length > MAXIMUM_REQUEST_BODY_BYTES) {
      await reader.cancel();
      throw new TypeError("PROXY_REQUEST_TOO_LARGE");
    }
    chunks.push(value);
  }
  const body = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return body;
}

export async function createLoopbackProxyRequest(source, baseUrl) {
  return createProxyRequest(source, baseUrl, assertAllowedRoute);
}

export async function createAppProxyRequest(source, baseUrl) {
  const sourceUrl = new URL(source.url);
  const workspacePolicy = sourceUrl.pathname === "/v1/app/workspaces" ? "forbidden" : "required";
  return createProxyRequest(source, baseUrl, assertAllowedAppRoute, workspacePolicy, validateClosedAppRequest, validateAppUrl);
}

export async function createAuthProxyRequest(source, baseUrl) {
  const sourceUrl = new URL(source.url);
  assertAllowedAuthRoute(sourceUrl, source.method);
  const isPolicyRoute = sourceUrl.pathname === "/v1/me/policy-acceptances"
    || POLICY_BUNDLE_ROUTE.test(sourceUrl.pathname);
  const isAuthorizationRoute = sourceUrl.pathname === "/v1/auth/oidc/authorizations";
  const isSessionLogout = source.method.toUpperCase() === "DELETE"
    && IAM_SESSION_LOGOUT_ROUTE.test(sourceUrl.pathname);
  const isSessionList = source.method.toUpperCase() === "GET"
    && sourceUrl.pathname === IAM_SESSION_LIST_ROUTE;
  if (isPolicyRoute || isAuthorizationRoute || isSessionLogout || isSessionList) {
    assertNoClientAuthorityHeaders(source.headers);
  }
  const loopback = parseLoopbackBaseUrl(baseUrl);
  const target = new URL(`${sourceUrl.pathname}${sourceUrl.search}`, loopback);
  const headers = new Headers();
  for (const [name, value] of source.headers) {
    if (REQUEST_HEADER_ALLOWLIST.has(name.toLowerCase())) headers.set(name, value);
  }
  headers.set("origin", loopback.origin);
  const method = source.method.toUpperCase();
  const body = method === "GET" || method === "HEAD" ? undefined : await boundedRequestBody(source);
  const sessionLogoutBodyIsEmpty = body === undefined
    || (body instanceof Uint8Array && body.byteLength === 0);
  const sessionLogoutContentLength = source.headers.get("content-length");
  if (isSessionList && (
    headers.has("content-type")
    || headers.has("if-match")
    || headers.has("idempotency-key")
    || headers.has("x-csrf-token")
    || body !== undefined
  )) throw new TypeError("INVALID_SESSION_LIST_REQUEST");
  if (sourceUrl.pathname === "/v1/me/policy-acceptances") {
    if (
      headers.get("content-type") !== "application/json"
      || !ENTITY_TAG.test(headers.get("if-match") ?? "")
      || !IDEMPOTENCY_KEY.test(headers.get("idempotency-key") ?? "")
      || !CSRF_TOKEN.test(headers.get("x-csrf-token") ?? "")
    ) throw new TypeError("INVALID_POLICY_ACCEPTANCE_REQUEST");
    validatePolicyAcceptanceBody(body);
  }
  if (isAuthorizationRoute) {
    if (headers.get("content-type") !== "application/json") {
      throw new TypeError("INVALID_OIDC_AUTHORIZATION_REQUEST");
    }
    const anonymousInvitation = validateOidcAuthorizationBody(body, headers);
    if (anonymousInvitation) headers.delete("cookie");
  }
  if (isSessionLogout && (
    !IDEMPOTENCY_KEY.test(headers.get("idempotency-key") ?? "")
    || !CSRF_TOKEN.test(headers.get("x-csrf-token") ?? "")
    || !SESSION_COOKIE.test(headers.get("cookie") ?? "")
    || !UUID_VALUE.test(source.headers.get(BOOTSTRAP_SESSION_ID_HEADER) ?? "")
    || headers.has("if-match")
    || headers.has("content-type")
    || !sessionLogoutBodyIsEmpty
    || (sessionLogoutContentLength !== null && sessionLogoutContentLength !== "0")
  )) throw new TypeError("INVALID_SESSION_LOGOUT_REQUEST");
  return new Request(target, {
    method,
    headers,
    body: isSessionLogout && sessionLogoutBodyIsEmpty ? null : body,
    redirect: "manual",
  });
}

export async function createIamProxyRequest(source, baseUrl) {
  const sourceUrl = new URL(source.url);
  assertAllowedIamRoute(sourceUrl, source.method);
  const matchingCreatorRoute = sourceUrl.pathname === MATCHING_INVITATION_COLLECTION_ROUTE
    || MATCHING_INVITATION_DETAIL_ROUTE.test(sourceUrl.pathname)
    || MATCHING_INVITATION_WRITE_ROUTE.test(sourceUrl.pathname);
  const matchingOrganizationId = sourceUrl.pathname.match(MATCHING_ATTEMPT_COLLECTION_ROUTE)?.[1]
    ?? sourceUrl.pathname.match(MATCHING_SELECTION_READ_ROUTE)?.[1]
    ?? sourceUrl.pathname.match(MATCHING_SELECTION_ID_READ_ROUTE)?.[1]
    ?? sourceUrl.pathname.match(MATCHING_SELECTION_CHOOSE_ROUTE)?.[1]
    ?? sourceUrl.pathname.match(MATCHING_SELECTION_CLOSE_ROUTE)?.[1]
    ?? null;
  const matchingAssignmentRoute = sourceUrl.pathname === MATCHING_ASSIGNMENT_CLAIM_ROUTE;
  const matchingReviewerRoute = sourceUrl.pathname === MATCHING_REVIEW_CLAIM_ROUTE
    || sourceUrl.pathname === MATCHING_REVIEW_ASSIGNMENT_ROUTE
    || sourceUrl.pathname === MATCHING_REVIEW_RELEASE_ROUTE
    || MATCHING_REVIEW_CREATE_ROUTE.test(sourceUrl.pathname)
    || MATCHING_REVIEW_PUBLISH_ROUTE.test(sourceUrl.pathname)
    || MATCHING_REVIEW_INVALIDATE_ROUTE.test(sourceUrl.pathname);
  const matchingRoute = matchingCreatorRoute || matchingOrganizationId !== null
    || matchingAssignmentRoute || matchingReviewerRoute;
  assertNoClientAuthorityHeaders(source.headers, matchingRoute);
  const loopback = parseLoopbackBaseUrl(baseUrl);
  const target = new URL(`${sourceUrl.pathname}${sourceUrl.search}`, loopback);
  const headers = new Headers();
  for (const [name, value] of source.headers) {
    if (REQUEST_HEADER_ALLOWLIST.has(name.toLowerCase())) headers.set(name, value);
  }
  const workspaceId = headers.get("x-workspace-id");
  if (matchingRoute) {
    if (
      !WORKSPACE_ID.test(workspaceId ?? "")
      || (matchingCreatorRoute && !workspaceId?.startsWith("personal:"))
      || (matchingOrganizationId !== null && workspaceId !== `org:${matchingOrganizationId}`)
      || (matchingAssignmentRoute && !workspaceId?.startsWith("org:"))
      || (matchingReviewerRoute && !workspaceId?.startsWith("platform:"))
    ) throw new TypeError("INVALID_MATCHING_REQUEST");
  } else {
    headers.delete("x-workspace-id");
  }
  if (sourceUrl.pathname === IAM_INSPECT_INVITATION_ROUTE) headers.delete("cookie");
  headers.set("origin", loopback.origin);
  const method = source.method.toUpperCase();
  const body = method === "GET" || method === "HEAD" ? undefined : await boundedRequestBody(source);
  validateIamRequest({ pathname: sourceUrl.pathname, method, headers, body });
  return new Request(target, { method, headers, body, redirect: "manual" });
}

function safeResponseHeaders(source) {
  const headers = new Headers({ "cache-control": "no-store" });
  for (const [name, value] of source) {
    const normalized = name.toLowerCase();
    if (normalized !== "cache-control" && RESPONSE_HEADER_ALLOWLIST.has(normalized)) headers.append(name, value);
  }
  return headers;
}

const SESSION_LIST_FIELD_ISSUE_CODES = new Set([
  "MISSING_REQUIRED",
  "UNKNOWN_FIELD",
  "INVALID_TYPE",
  "INVALID_ENUM",
  "INVALID_FORMAT",
  "TOO_LARGE",
  "CONFLICT",
]);

function parseSessionListError(value, status, traceId) {
  const allowedCodes = status === 400
    ? new Set(["INVALID_REQUEST"])
    : status === 401
      ? new Set(["AUTHENTICATION_REQUIRED", "SESSION_EXPIRED"])
      : status === 503
        ? new Set(["SERVICE_UNAVAILABLE"])
        : null;
  if (
    allowedCodes === null
    || !exactObject(value, new Set(["code", "message", "trace_id", "field_issues"]))
    || !allowedCodes.has(value.code)
    || typeof value.message !== "string"
    || value.message.length < 1
    || value.message.length > 500
    || hasAsciiControl(value.message)
    || typeof value.trace_id !== "string"
    || !TRACE_ID.test(value.trace_id)
    || value.trace_id !== traceId
    || !Array.isArray(value.field_issues)
    || value.field_issues.length > 100
  ) throw new TypeError("INVALID_SESSION_LIST_BACKEND_RESPONSE");
  for (const issue of value.field_issues) {
    if (
      !exactObject(issue, new Set(["path", "code", "message"]))
      || typeof issue.path !== "string"
      || issue.path.length < 1
      || issue.path.length > 256
      || !/^[A-Za-z0-9_[\].-]+$/.test(issue.path)
      || !SESSION_LIST_FIELD_ISSUE_CODES.has(issue.code)
      || typeof issue.message !== "string"
      || issue.message.length < 1
      || issue.message.length > 300
      || hasAsciiControl(issue.message)
    ) throw new TypeError("INVALID_SESSION_LIST_BACKEND_RESPONSE");
  }
  return value;
}

async function validateSessionListProxyResponse(source, response) {
  const sourceUrl = new URL(source.url);
  if (
    source.method.toUpperCase() !== "GET"
    || sourceUrl.pathname !== IAM_SESSION_LIST_ROUTE
  ) return null;
  const traceId = response.headers.get("x-trace-id");
  if (
    response.status >= 300 && response.status < 400
    || response.headers.get("cache-control") !== "no-store"
    || response.headers.has("set-cookie")
    || response.headers.has("etag")
    || response.headers.has("allow")
    || response.headers.has("location")
    || response.headers.has("retry-after")
    || typeof traceId !== "string"
    || !TRACE_ID.test(traceId)
    || !/^application\/json(?:\s*;|$)/i.test(
      response.headers.get("content-type") ?? "",
    )
  ) throw new TypeError("INVALID_SESSION_LIST_BACKEND_RESPONSE");
  let value;
  try {
    value = await response.json();
  } catch {
    throw new TypeError("INVALID_SESSION_LIST_BACKEND_RESPONSE");
  }
  const projection = response.status === 200
    ? parseSessionPage(value)
    : parseSessionListError(value, response.status, traceId);
  return new Response(JSON.stringify(projection), {
    status: response.status,
    statusText: response.statusText,
    headers: safeResponseHeaders(response.headers),
  });
}

async function validateAdminDemandProxyResponse(source, response) {
  const sourceUrl = new URL(source.url);
  const detail = ADMIN_DEMAND_TIMELINE_ROUTE.exec(sourceUrl.pathname);
  if (source.method.toUpperCase() !== "GET" || (sourceUrl.pathname !== ADMIN_DEMAND_COLLECTION_ROUTE && !detail)) return null;
  const traceId = response.headers.get("x-trace-id");
  if (response.headers.get("cache-control") !== "no-store"
    || ["set-cookie", "etag", "allow", "location", "retry-after"].some((name) => response.headers.has(name))
    || (traceId !== null && !TRACE_ID.test(traceId))
    || !/^application\/json(?:\s*;|$)/i.test(response.headers.get("content-type") ?? "")) throw new TypeError("INVALID_ADMIN_DEMAND_BACKEND_RESPONSE");
  const value = await response.json();
  if (response.status === 200) {
    if (detail) parseAdminDemandTimeline(value, detail[1], source.headers.get("x-workspace-id") ?? undefined);
    else parseAdminDemandCollection(value, source.headers.get("x-workspace-id") ?? undefined);
  } else {
    const allowed = new Map([
      [400, ["INVALID_JSON", "INVALID_REQUEST", "INVALID_CURSOR"]],
      [401, ["AUTHENTICATION_REQUIRED", "SESSION_EXPIRED"]],
      [403, ["ACCESS_DENIED", "CSRF_INVALID", "CSRF_REQUIRED", "ORIGIN_NOT_ALLOWED"]],
      [404, ["RESOURCE_NOT_FOUND"]],
      [409, ["WORKSPACE_REQUIRED", "TIMELINE_CHANGED"]],
      [422, ["INVALID_CURSOR", "INVALID_PAGE_LIMIT", "INVALID_REQUEST"]],
      [503, ["SERVICE_UNAVAILABLE"]],
    ]);
    const hasPath = value?.error && Object.hasOwn(value.error, "path");
    if (!exactObject(value, new Set(["error"]))
      || !exactObject(value.error, new Set(hasPath ? ["code", "path"] : ["code"]))
      || !allowed.get(response.status)?.includes(value.error.code)
      || (hasPath && (typeof value.error.path !== "string" || !/^\/query(?:\/(?:cursor|limit))?$/.test(value.error.path)))) {
      throw new TypeError("INVALID_ADMIN_DEMAND_BACKEND_RESPONSE");
    }
  }
  return new Response(JSON.stringify(value), { status: response.status, headers: safeResponseHeaders(response.headers) });
}

async function validateTaskDiscoveryProxyResponse(source, response) {
  const sourceUrl = new URL(source.url);
  if (source.method.toUpperCase() !== "GET" || sourceUrl.pathname !== TASK_DISCOVERY_ROUTE) return null;
  const traceId = response.headers.get("x-trace-id");
  if (
    response.status >= 300 && response.status < 400
    || response.headers.get("cache-control") !== "no-store"
    || response.headers.has("set-cookie")
    || response.headers.has("etag")
    || response.headers.has("allow")
    || response.headers.has("location")
    || response.headers.has("retry-after")
    || (traceId !== null && !TRACE_ID.test(traceId))
    || !/^application\/json(?:\s*;|$)/i.test(response.headers.get("content-type") ?? "")
  ) throw new TypeError("INVALID_TASK_DISCOVERY_BACKEND_RESPONSE");
  let value;
  try {
    value = await response.json();
  } catch {
    throw new TypeError("INVALID_TASK_DISCOVERY_BACKEND_RESPONSE");
  }
  if (response.status === 200) {
    parseCurrentAccountTaskDiscovery(value);
  } else {
    const allowed = new Map([
      [401, new Set(["AUTHENTICATION_REQUIRED", "SESSION_EXPIRED"])],
      [403, new Set(["ACCESS_DENIED"])],
      [404, new Set(["RESOURCE_NOT_FOUND"])],
      [409, new Set(["WORKSPACE_REQUIRED"])],
      [503, new Set(["SERVICE_UNAVAILABLE"])],
    ]);
    if (
      !exactObject(value, new Set(["error"]))
      || !exactObject(value.error, new Set(["code"]))
      || !allowed.get(response.status)?.has(value.error.code)
    ) throw new TypeError("INVALID_TASK_DISCOVERY_BACKEND_RESPONSE");
  }
  return new Response(JSON.stringify(value), {
    status: response.status,
    statusText: response.statusText,
    headers: safeResponseHeaders(response.headers),
  });
}

const MATCHING_ERROR_STATUSES = new Map([
  ["INVALID_REQUEST", new Set([400, 403])],
  ["AUTHENTICATION_REQUIRED", new Set([401])],
  ["SESSION_EXPIRED", new Set([401])],
  ["ACCESS_DENIED", new Set([403])],
  ["SAFETY_HOLD_BLOCKED", new Set([403])],
  ["POLICY_ACCEPTANCE_REQUIRED", new Set([403])],
  ["RESOURCE_NOT_FOUND", new Set([404])],
  ["INVALID_STATE_TRANSITION", new Set([409])],
  ["INVITATION_ALREADY_SELECTED", new Set([409])],
  ["SELECTOR_ASSIGNMENT_REQUIRED", new Set([409])],
  ["IDEMPOTENCY_KEY_REUSED", new Set([409])],
  ["MATCH_INPUT_CHANGED", new Set([409])],
  ["MATCH_RULE_BUNDLE_CHANGED", new Set([409])],
  ["FUNDING_FACT_CHANGED", new Set([409])],
  ["INVITATION_ALREADY_EXISTS", new Set([409])],
  ["PRECONDITION_FAILED", new Set([412])],
  ["SELECTION_NOT_READY", new Set([422])],
  ["POLICY_CONFIGURATION_UNAVAILABLE", new Set([503])],
  ["COMMAND_OUTCOME_UNKNOWN", new Set([503])],
  ["SERVICE_UNAVAILABLE", new Set([503])],
]);
const MATCHING_ERROR_CODES = new Set(MATCHING_ERROR_STATUSES.keys());

function matchingErrorContract({
  isInvitationList,
  invitationDetail,
  invitationWrite,
  attemptList,
  selectionRead,
  selectionChoose,
  selectionClose,
  assignmentClaim,
  reviewClaim,
  reviewRead,
  reviewRelease,
  reviewCreate,
  reviewPublish,
  reviewInvalidate,
}) {
  const authentication = ["AUTHENTICATION_REQUIRED", "SESSION_EXPIRED"];
  const unavailable = ["SERVICE_UNAVAILABLE"];
  const unknownWriteOutcome = ["COMMAND_OUTCOME_UNKNOWN"];
  if (isInvitationList) return {
    codes: new Set([...authentication, ...unavailable]),
    statuses: new Set([401, 503]),
  };
  if (invitationDetail || attemptList || selectionRead) return {
    codes: new Set([...authentication, "RESOURCE_NOT_FOUND", ...unavailable]),
    statuses: new Set([401, 404, 503]),
  };
  if (invitationWrite?.[2] === "decline") return {
    codes: new Set([
      "INVALID_REQUEST", ...authentication, "RESOURCE_NOT_FOUND", "INVALID_STATE_TRANSITION",
      "IDEMPOTENCY_KEY_REUSED", "PRECONDITION_FAILED", ...unknownWriteOutcome, ...unavailable,
    ]),
    statuses: new Set([400, 401, 403, 404, 409, 412, 503]),
  };
  if (invitationWrite?.[2] === "withdraw") return {
    codes: new Set([
      "INVALID_REQUEST", ...authentication, "RESOURCE_NOT_FOUND", "INVALID_STATE_TRANSITION",
      "INVITATION_ALREADY_SELECTED", "IDEMPOTENCY_KEY_REUSED", "PRECONDITION_FAILED",
      ...unknownWriteOutcome, ...unavailable,
    ]),
    statuses: new Set([400, 401, 403, 404, 409, 412, 503]),
  };
  if (invitationWrite?.[2] === "accept") return {
    codes: new Set([
      "INVALID_REQUEST", ...authentication, "ACCESS_DENIED", "SAFETY_HOLD_BLOCKED",
      "RESOURCE_NOT_FOUND", "INVALID_STATE_TRANSITION", "IDEMPOTENCY_KEY_REUSED",
      "MATCH_INPUT_CHANGED", "PRECONDITION_FAILED", "POLICY_ACCEPTANCE_REQUIRED",
      "POLICY_CONFIGURATION_UNAVAILABLE", ...unknownWriteOutcome, ...unavailable,
    ]),
    statuses: new Set([400, 401, 403, 404, 409, 412, 422, 503]),
  };
  if (selectionChoose) return {
    codes: new Set([
      "INVALID_REQUEST", ...authentication, "ACCESS_DENIED", "SAFETY_HOLD_BLOCKED",
      "RESOURCE_NOT_FOUND", "SELECTOR_ASSIGNMENT_REQUIRED", "INVALID_STATE_TRANSITION",
      "IDEMPOTENCY_KEY_REUSED", "MATCH_INPUT_CHANGED", "MATCH_RULE_BUNDLE_CHANGED",
      "FUNDING_FACT_CHANGED", "PRECONDITION_FAILED", "SELECTION_NOT_READY",
      "POLICY_ACCEPTANCE_REQUIRED", "POLICY_CONFIGURATION_UNAVAILABLE", ...unknownWriteOutcome, ...unavailable,
    ]),
    statuses: new Set([400, 401, 403, 404, 409, 412, 422, 503]),
  };
  if (selectionClose) return {
    codes: new Set([
      "INVALID_REQUEST", ...authentication, "RESOURCE_NOT_FOUND", "SELECTOR_ASSIGNMENT_REQUIRED",
      "INVALID_STATE_TRANSITION", "IDEMPOTENCY_KEY_REUSED", "PRECONDITION_FAILED",
      "SELECTION_NOT_READY", ...unknownWriteOutcome, ...unavailable,
    ]),
    statuses: new Set([400, 401, 403, 404, 409, 412, 422, 503]),
  };
  if (assignmentClaim || reviewClaim || reviewRelease || reviewCreate || reviewPublish || reviewInvalidate) return {
    codes: new Set(MATCHING_ERROR_CODES),
    statuses: new Set([400, 401, 403, 404, 409, 412, 422, 503]),
  };
  if (reviewRead) return {
    codes: new Set([...authentication, "RESOURCE_NOT_FOUND", ...unavailable]),
    statuses: new Set([401, 404, 503]),
  };
  throw new TypeError("INVALID_MATCHING_BACKEND_RESPONSE");
}

async function validateMatchingProxyResponse(source, response, forwardedRequest = null) {
  const sourceUrl = new URL(source.url);
  const pathname = sourceUrl.pathname;
  const invitationDetail = pathname.match(MATCHING_INVITATION_DETAIL_ROUTE);
  const invitationWrite = pathname.match(MATCHING_INVITATION_WRITE_ROUTE);
  const attemptList = pathname.match(MATCHING_ATTEMPT_COLLECTION_ROUTE);
  const selectionRead = pathname.match(MATCHING_SELECTION_READ_ROUTE);
  const selectionIdRead = pathname.match(MATCHING_SELECTION_ID_READ_ROUTE);
  const selectionChoose = pathname.match(MATCHING_SELECTION_CHOOSE_ROUTE);
  const selectionClose = pathname.match(MATCHING_SELECTION_CLOSE_ROUTE);
  const assignmentClaim = pathname === MATCHING_ASSIGNMENT_CLAIM_ROUTE;
  const reviewClaim = pathname === MATCHING_REVIEW_CLAIM_ROUTE;
  const reviewRead = pathname === MATCHING_REVIEW_ASSIGNMENT_ROUTE;
  const reviewRelease = pathname === MATCHING_REVIEW_RELEASE_ROUTE;
  const reviewCreate = pathname.match(MATCHING_REVIEW_CREATE_ROUTE);
  const reviewPublish = pathname.match(MATCHING_REVIEW_PUBLISH_ROUTE);
  const reviewInvalidate = pathname.match(MATCHING_REVIEW_INVALIDATE_ROUTE);
  const isInvitationList = pathname === MATCHING_INVITATION_COLLECTION_ROUTE;
  const isMatching = isInvitationList || invitationDetail || invitationWrite || attemptList
    || selectionRead || selectionIdRead || selectionChoose || selectionClose || assignmentClaim || reviewClaim
    || reviewRead || reviewRelease || reviewCreate || reviewPublish || reviewInvalidate;
  if (!isMatching) return null;
  const traceId = response.headers.get("x-trace-id");
  if (
    response.status >= 300 && response.status < 400
    || response.headers.get("cache-control") !== "no-store"
    || response.headers.has("set-cookie")
    || response.headers.has("allow")
    || response.headers.has("location")
    || response.headers.has("retry-after")
    || (traceId !== null && !TRACE_ID.test(traceId))
    || !/^application\/json(?:\s*;|$)/i.test(response.headers.get("content-type") ?? "")
  ) throw new TypeError("INVALID_MATCHING_BACKEND_RESPONSE");
  let value;
  try {
    value = await response.json();
  } catch {
    throw new TypeError("INVALID_MATCHING_BACKEND_RESPONSE");
  }
  if (response.ok) {
    let command = null;
    if (source.method.toUpperCase() === "POST") {
      try {
        command = await forwardedRequest?.json();
      } catch {
        throw new TypeError("INVALID_MATCHING_BACKEND_RESPONSE");
      }
      if (command === null) throw new TypeError("INVALID_MATCHING_BACKEND_RESPONSE");
    }
    if (assignmentClaim) {
      if (response.status !== 201 || command === null) throw new TypeError("INVALID_MATCHING_BACKEND_RESPONSE");
      const projection = parseMatchingCandidateSelectorAssignment(value, command.demand_id);
      assertMatchingEntityTag(response.headers.get("etag"), projection.candidate_selector_assignment_version);
    } else if (reviewClaim) {
      if (response.status !== 201) throw new TypeError("INVALID_MATCHING_BACKEND_RESPONSE");
      const projection = parseMatchingReviewAssignment(value);
      if (projection.status !== "ACTIVE") throw new TypeError("INVALID_MATCHING_BACKEND_RESPONSE");
      assertMatchingEntityTag(response.headers.get("etag"), projection.aggregate_version);
    } else if (reviewRead) {
      if (response.status !== 200 || command !== null) throw new TypeError("INVALID_MATCHING_BACKEND_RESPONSE");
      const projection = parseMatchingReviewWorkspace(value);
      assertMatchingEntityTag(response.headers.get("etag"), projection.aggregate_version);
    } else if (reviewRelease) {
      if (response.status !== 200) throw new TypeError("INVALID_MATCHING_BACKEND_RESPONSE");
      const projection = parseMatchingReviewAssignment(value);
      if (projection.status !== "REVOKED") throw new TypeError("INVALID_MATCHING_BACKEND_RESPONSE");
      assertMatchingEntityTag(response.headers.get("etag"), projection.aggregate_version);
    } else if (reviewCreate) {
      if (response.status !== 201 || command === null) throw new TypeError("INVALID_MATCHING_BACKEND_RESPONSE");
      const projection = parseMatchingReviewerInvitation(value);
      if (
        projection.match_run_id !== reviewCreate[1]
        || projection.creator_user_id !== command.creator_user_id
        || !matchingUtcTimestampsEqual(projection.expires_at, command.expires_at)
        || projection.status !== "CREATED"
      ) throw new TypeError("INVALID_MATCHING_BACKEND_RESPONSE");
      assertMatchingEntityTag(response.headers.get("etag"), projection.aggregate_version);
    } else if (reviewPublish) {
      if (response.status !== 200 || command === null) throw new TypeError("INVALID_MATCHING_BACKEND_RESPONSE");
      const projection = parseMatchingReviewerInvitation(value);
      if (
        projection.invitation_id !== reviewPublish[1]
        || projection.snapshot_sha256 !== command.snapshot_sha256
        || projection.status !== "SENT"
      ) throw new TypeError("INVALID_MATCHING_BACKEND_RESPONSE");
      assertMatchingEntityTag(response.headers.get("etag"), projection.aggregate_version);
    } else if (reviewInvalidate) {
      if (response.status !== 200 || command === null) throw new TypeError("INVALID_MATCHING_BACKEND_RESPONSE");
      const projection = parseMatchingReviewerAttempt(value);
      if (projection.attempt_id !== reviewInvalidate[1] || projection.status !== "INVALIDATED") {
        throw new TypeError("INVALID_MATCHING_BACKEND_RESPONSE");
      }
      assertMatchingEntityTag(response.headers.get("etag"), projection.aggregate_version);
    } else if (isInvitationList) {
      if (response.status !== 200) throw new TypeError("INVALID_MATCHING_BACKEND_RESPONSE");
      parseMatchingInvitationList(value);
      if (response.headers.has("etag")) throw new TypeError("INVALID_MATCHING_BACKEND_RESPONSE");
    } else if (invitationDetail || invitationWrite) {
      if (response.status !== 200) throw new TypeError("INVALID_MATCHING_BACKEND_RESPONSE");
      const projection = parseMatchingInvitationDetail(value);
      const expectedInvitationId = (invitationDetail ?? invitationWrite)?.[1];
      if (projection.invitation_id !== expectedInvitationId) throw new TypeError("INVALID_MATCHING_BACKEND_RESPONSE");
      if (invitationWrite && (
        projection.snapshot_sha256 !== command.snapshot_sha256
        || projection.status !== ({ accept: "ACCEPTED", decline: "DECLINED", withdraw: "WITHDRAWN" })[invitationWrite[2]]
        || projection.response_status !== projection.status
      )) throw new TypeError("INVALID_MATCHING_BACKEND_RESPONSE");
      assertMatchingEntityTag(response.headers.get("etag"), projection.aggregate_version);
    } else if (attemptList) {
      if (response.status !== 200) throw new TypeError("INVALID_MATCHING_BACKEND_RESPONSE");
      parseMatchingAttemptList(value, attemptList[2]);
      if (response.headers.has("etag")) throw new TypeError("INVALID_MATCHING_BACKEND_RESPONSE");
    } else {
      if (response.status !== 200) throw new TypeError("INVALID_MATCHING_BACKEND_RESPONSE");
      const projection = parseMatchingSelection(value);
      if (selectionRead && projection.attempt_id !== selectionRead[2]) {
        throw new TypeError("INVALID_MATCHING_BACKEND_RESPONSE");
      }
      if (selectionIdRead && projection.selection_id !== selectionIdRead[2]) {
        throw new TypeError("INVALID_MATCHING_BACKEND_RESPONSE");
      }
      if ((selectionChoose || selectionClose) && projection.selection_id !== (selectionChoose ?? selectionClose)?.[2]) {
        throw new TypeError("INVALID_MATCHING_BACKEND_RESPONSE");
      }
      if ((selectionChoose || selectionClose) && (
        projection.current_invitation_set_sha256 !== command.current_invitation_set_sha256
        || projection.candidate_selector_assignment_id !== command.candidate_selector_assignment_id
        || !matchesMatchingSelectionAssignmentVersion(projection, command.candidate_selector_assignment_version)
      )) throw new TypeError("INVALID_MATCHING_BACKEND_RESPONSE");
      if (selectionChoose && (
        projection.chosen_invitation_id !== command.invitation_id
        || !new Set(["PENDING_CHOICE", "SELECTED"]).has(projection.status)
      )) throw new TypeError("INVALID_MATCHING_BACKEND_RESPONSE");
      if (selectionClose && (
        !new Set(["PENDING_CLOSE", "CLOSED_NO_SELECTION"]).has(projection.status)
        || projection.chosen_invitation_id !== null
      )) throw new TypeError("INVALID_MATCHING_BACKEND_RESPONSE");
      assertMatchingEntityTag(response.headers.get("etag"), projection.aggregate_version);
    }
  } else {
    const contract = matchingErrorContract({
      isInvitationList, invitationDetail, invitationWrite, attemptList,
      selectionRead: selectionRead ?? selectionIdRead, selectionChoose, selectionClose, assignmentClaim, reviewClaim,
      reviewRead, reviewRelease, reviewCreate, reviewPublish, reviewInvalidate,
    });
    if (
      !contract.statuses.has(response.status)
      || !exactObject(value, new Set(["code", "message", "trace_id"]))
      || !MATCHING_ERROR_CODES.has(value.code)
      || !contract.codes.has(value.code)
      || !MATCHING_ERROR_STATUSES.get(value.code)?.has(response.status)
      || typeof value.message !== "string"
      || value.message.length < 1
      || value.message.length > 300
      || hasAsciiControl(value.message)
      || !OPAQUE_ID.test(value.trace_id ?? "")
      || (traceId !== null && value.trace_id !== traceId)
      || response.headers.has("etag")
    ) throw new TypeError("INVALID_MATCHING_BACKEND_RESPONSE");
  }
  return new Response(JSON.stringify(value), {
    status: response.status,
    statusText: response.statusText,
    headers: safeResponseHeaders(response.headers),
  });
}

async function validateReviewHistoryProxyResponse(source, response) {
  const sourceUrl = new URL(source.url);
  if (
    source.method.toUpperCase() !== "GET"
    || sourceUrl.pathname !== REVIEW_HISTORY_ROUTE
  ) return null;
  const traceId = response.headers.get("x-trace-id");
  if (
    response.status >= 300 && response.status < 400
    || response.headers.get("cache-control") !== "no-store"
    || response.headers.has("set-cookie")
    || response.headers.has("etag")
    || response.headers.has("allow")
    || response.headers.has("location")
    || response.headers.has("retry-after")
    || (traceId !== null && !TRACE_ID.test(traceId))
    || !/^application\/json(?:\s*;|$)/i.test(response.headers.get("content-type") ?? "")
  ) throw new TypeError("INVALID_REVIEW_HISTORY_BACKEND_RESPONSE");
  let value;
  try {
    value = await response.json();
  } catch {
    throw new TypeError("INVALID_REVIEW_HISTORY_BACKEND_RESPONSE");
  }
  if (response.status === 200) {
    parseEditorReviewHistoryEnvelope(value);
  } else {
    const allowed = new Map([
      [400, new Set(["INVALID_JSON", "INVALID_REQUEST"])],
      [401, new Set(["AUTHENTICATION_REQUIRED", "SESSION_EXPIRED"])],
      [403, new Set(["ACCESS_DENIED", "CSRF_INVALID", "CSRF_REQUIRED", "ORIGIN_NOT_ALLOWED"])],
      [404, new Set(["RESOURCE_NOT_FOUND"])],
      [409, new Set(["WORKSPACE_REQUIRED"])],
      [422, new Set(["INVALID_CURSOR", "INVALID_PAGE_LIMIT", "INVALID_REQUEST"])],
      [503, new Set(["SERVICE_UNAVAILABLE"])],
    ]);
    const errorKeys = value?.error && Object.hasOwn(value.error, "path")
      ? new Set(["code", "path"])
      : new Set(["code"]);
    if (
      !exactObject(value, new Set(["error"]))
      || !exactObject(value.error, errorKeys)
      || !allowed.get(response.status)?.has(value.error.code)
      || (Object.hasOwn(value.error, "path") && (
        typeof value.error.path !== "string"
        || !/^\/query\/(?:cursor|limit)$/.test(value.error.path)
      ))
    ) throw new TypeError("INVALID_REVIEW_HISTORY_BACKEND_RESPONSE");
  }
  return new Response(JSON.stringify(value), {
    status: response.status,
    statusText: response.statusText,
    headers: safeResponseHeaders(response.headers),
  });
}

async function validateFinanceFundingHistoryProxyResponse(source, response) {
  const sourceUrl = new URL(source.url);
  if (
    source.method.toUpperCase() !== "GET"
    || sourceUrl.pathname !== FINANCE_FUNDING_HISTORY_ROUTE
  ) return null;
  const traceId = response.headers.get("x-trace-id");
  if (
    response.status >= 300 && response.status < 400
    || response.headers.get("cache-control") !== "no-store"
    || response.headers.has("set-cookie")
    || response.headers.has("etag")
    || response.headers.has("allow")
    || response.headers.has("location")
    || response.headers.has("retry-after")
    || (traceId !== null && !TRACE_ID.test(traceId))
    || !/^application\/json(?:\s*;|$)/i.test(response.headers.get("content-type") ?? "")
  ) throw new TypeError("INVALID_FINANCE_FUNDING_HISTORY_BACKEND_RESPONSE");
  let value;
  try {
    value = await response.json();
  } catch {
    throw new TypeError("INVALID_FINANCE_FUNDING_HISTORY_BACKEND_RESPONSE");
  }
  if (response.status === 200) {
    parseFinanceFundingHistoryEnvelope(value);
  } else {
    const allowed = new Map([
      [400, new Set(["INVALID_JSON", "INVALID_REQUEST"])],
      [401, new Set(["AUTHENTICATION_REQUIRED", "SESSION_EXPIRED"])],
      [403, new Set(["ACCESS_DENIED", "CSRF_INVALID", "CSRF_REQUIRED", "ORIGIN_NOT_ALLOWED"])],
      [404, new Set(["RESOURCE_NOT_FOUND"])],
      [409, new Set(["WORKSPACE_REQUIRED"])],
      [422, new Set(["INVALID_CURSOR", "INVALID_PAGE_LIMIT", "INVALID_REQUEST"])],
      [503, new Set(["SERVICE_UNAVAILABLE"])],
    ]);
    const errorKeys = value?.error && Object.hasOwn(value.error, "path")
      ? new Set(["code", "path"])
      : new Set(["code"]);
    if (
      !exactObject(value, new Set(["error"]))
      || !exactObject(value.error, errorKeys)
      || !allowed.get(response.status)?.has(value.error.code)
      || (Object.hasOwn(value.error, "path") && (
        typeof value.error.path !== "string"
        || !/^\/query\/(?:cursor|limit)$/.test(value.error.path)
      ))
    ) throw new TypeError("INVALID_FINANCE_FUNDING_HISTORY_BACKEND_RESPONSE");
  }
  return new Response(JSON.stringify(value), {
    status: response.status,
    statusText: response.statusText,
    headers: safeResponseHeaders(response.headers),
  });
}

async function validateDemandCancelProxyResponse(source, response) {
  const pathname = new URL(source.url).pathname;
  const match = pathname.match(DEMAND_CANCEL_ROUTE);
  if (source.method.toUpperCase() !== "POST" || match === null) return null;
  if (
    response.status >= 300 && response.status < 400
    || response.headers.has("set-cookie")
    || !/^application\/json(?:\s*;|$)/i.test(response.headers.get("content-type") ?? "")
  ) throw new TypeError("INVALID_DEMAND_CANCEL_BACKEND_RESPONSE");
  let value;
  try {
    value = await response.json();
  } catch {
    throw new TypeError("INVALID_DEMAND_CANCEL_BACKEND_RESPONSE");
  }
  if (response.ok) {
    const resource = parseEditorEnvelope(value);
    if (
      response.status !== 200
      || response.headers.get("cache-control") !== "no-store"
      || response.headers.get("etag") !== resource.etag
      || resource.resource_type !== "DEMAND"
      || resource.object_id !== match[1]
      || resource.status !== "CANCELLED"
      || resource.capabilities.length !== 0
    ) throw new TypeError("INVALID_DEMAND_CANCEL_BACKEND_RESPONSE");
  } else {
    const allowed = new Map([
      [400, new Set(["INVALID_REQUEST"])],
      [401, new Set(["AUTHENTICATION_REQUIRED", "SESSION_EXPIRED"])],
      [403, new Set(["ACCESS_DENIED"])],
      [404, new Set(["RESOURCE_NOT_FOUND"])],
      [409, new Set(["IDEMPOTENCY_CONFLICT", "IDEMPOTENCY_KEY_REUSED", "INVALID_STATE_TRANSITION", "WORKSPACE_REQUIRED"])],
      [412, new Set(["PRECONDITION_FAILED"])],
      [413, new Set(["REQUEST_TOO_LARGE"])],
      [415, new Set(["UNSUPPORTED_MEDIA_TYPE"])],
      [422, new Set(["INVALID_BODY", "INVALID_FIELD", "INVALID_IDEMPOTENCY_KEY", "INVALID_REASON_CODE", "REQUIRED_FIELD", "UNKNOWN_FIELD"])],
      [428, new Set(["PRECONDITION_REQUIRED"])],
      [431, new Set(["REQUEST_HEADERS_TOO_LARGE"])],
      [503, new Set(["COMMAND_OUTCOME_UNKNOWN", "SERVICE_UNAVAILABLE"])],
    ]);
    const errorKeys = value?.error && Object.hasOwn(value.error, "path")
      ? new Set(["code", "path"])
      : new Set(["code"]);
    if (
      !exactObject(value, new Set(["error"]))
      || !exactObject(value.error, errorKeys)
      || !allowed.get(response.status)?.has(value.error.code)
      || (Object.hasOwn(value.error, "path") && (
        typeof value.error.path !== "string"
        || !/^\/(?:body|headers|reason_code)(?:\/[A-Za-z0-9_.~-]+)*$/.test(value.error.path)
      ))
      || (response.status === 412
        ? !DEMAND_RESOURCE_ETAG.test(response.headers.get("etag") ?? "")
        : response.headers.has("etag"))
    ) throw new TypeError("INVALID_DEMAND_CANCEL_BACKEND_RESPONSE");
  }
  return new Response(JSON.stringify(value), {
    status: response.status,
    statusText: response.statusText,
    headers: safeResponseHeaders(response.headers),
  });
}

async function validateReviewReleaseProxyResponse(source, response) {
  const pathname = new URL(source.url).pathname;
  const match = pathname.match(REVIEW_RELEASE_ROUTE);
  if (source.method.toUpperCase() !== "POST" || match === null) return null;
  if (
    response.status >= 300 && response.status < 400
    || response.headers.has("set-cookie")
    || !/^application\/json(?:\s*;|$)/i.test(response.headers.get("content-type") ?? "")
  ) throw new TypeError("INVALID_REVIEW_RELEASE_BACKEND_RESPONSE");
  let value;
  try {
    value = await response.json();
  } catch {
    throw new TypeError("INVALID_REVIEW_RELEASE_BACKEND_RESPONSE");
  }
  if (response.ok) {
    const resource = parseEditorEnvelope(value);
    if (
      response.status !== 200
      || response.headers.get("cache-control") !== "no-store"
      || response.headers.get("etag") !== resource.etag
      || resource.resource_type !== "DEMAND"
      || resource.object_id !== match[1]
      || resource.status !== "SUBMITTED"
      || resource.review_assignment !== null
      || resource.capabilities.includes("RECORD_FINDINGS")
    ) throw new TypeError("INVALID_REVIEW_RELEASE_BACKEND_RESPONSE");
  } else {
    const allowed = new Map([
      [400, new Set(["INVALID_REQUEST"])],
      [401, new Set(["AUTHENTICATION_REQUIRED", "SESSION_EXPIRED"])],
      [403, new Set(["ACCESS_DENIED"])],
      [404, new Set(["RESOURCE_NOT_FOUND"])],
      [409, new Set(["IDEMPOTENCY_CONFLICT", "IDEMPOTENCY_KEY_REUSED", "INVALID_STATE_TRANSITION", "WORKSPACE_REQUIRED"])],
      [412, new Set(["PRECONDITION_FAILED"])],
      [413, new Set(["REQUEST_TOO_LARGE"])],
      [415, new Set(["UNSUPPORTED_MEDIA_TYPE"])],
      [422, new Set(["INVALID_BODY", "INVALID_FIELD", "INVALID_IDEMPOTENCY_KEY", "INVALID_REASON_CODE", "REQUIRED_FIELD", "UNKNOWN_FIELD"])],
      [428, new Set(["PRECONDITION_REQUIRED"])],
      [431, new Set(["REQUEST_HEADERS_TOO_LARGE"])],
      [503, new Set(["COMMAND_OUTCOME_UNKNOWN", "SERVICE_UNAVAILABLE"])],
    ]);
    const errorKeys = value?.error && Object.hasOwn(value.error, "path")
      ? new Set(["code", "path"])
      : new Set(["code"]);
    if (
      !exactObject(value, new Set(["error"]))
      || !exactObject(value.error, errorKeys)
      || !allowed.get(response.status)?.has(value.error.code)
      || (Object.hasOwn(value.error, "path") && (
        typeof value.error.path !== "string"
        || !/^\/(?:body|headers|reason_code)(?:\/[A-Za-z0-9_.~-]+)*$/.test(value.error.path)
      ))
      || (response.status === 412
        ? !DEMAND_RESOURCE_ETAG.test(response.headers.get("etag") ?? "")
        : response.headers.has("etag"))
    ) throw new TypeError("INVALID_REVIEW_RELEASE_BACKEND_RESPONSE");
  }
  return new Response(JSON.stringify(value), {
    status: response.status,
    statusText: response.statusText,
    headers: safeResponseHeaders(response.headers),
  });
}

function expectedTrustSuccessStatus(pathname, method) {
  if (method === "GET") return 200;
  if (
    pathname === TRUST_REPORT_ROUTE
    || TRUST_CASE_CLAIM_ROUTE.test(pathname)
    || TRUST_HOLD_RELEASE_CLAIM_ROUTE.test(pathname)
    || TRUST_HOLD_PLACE_ROUTE.test(pathname)
    || TRUST_OUTCOME_ROUTE.test(pathname)
  ) return 201;
  return 200;
}

async function validateTrustProxyResponse(source, response) {
  const pathname = new URL(source.url).pathname;
  const method = source.method.toUpperCase();
  if (!pathname.startsWith("/v1/app/trust/")) return null;
  if (
    response.status >= 300 && response.status < 400
    || response.headers.has("set-cookie")
    || (!response.ok && response.headers.has("etag"))
    || ((pathname === TRUST_ASSIGNMENTS_ROUTE
      || pathname === TRUST_CASE_HISTORY_ROUTE
      || TRUST_ASSIGNED_HOLD_ROUTE.test(pathname)
      || (method === "GET" && pathname === TRUST_REPORT_ROUTE))
      && response.headers.get("cache-control") !== "no-store")
    || !/^application\/json(?:\s*;|$)/i.test(response.headers.get("content-type") ?? "")
  ) throw new TypeError("INVALID_TRUST_BACKEND_RESPONSE");
  let value;
  try {
    value = await response.json();
  } catch {
    throw new TypeError("INVALID_TRUST_BACKEND_RESPONSE");
  }
  if (!response.ok) {
    if (!exactObject(value, new Set(["error"]))) throw new TypeError("INVALID_TRUST_BACKEND_RESPONSE");
    const errorKeys = value.error && typeof value.error === "object" && Object.hasOwn(value.error, "path")
      ? new Set(["code", "path"])
      : new Set(["code"]);
    if (
      !exactObject(value.error, errorKeys)
      || !TRUST_ERROR_CODES.has(value.error.code)
      || (Object.hasOwn(value.error, "path") && (typeof value.error.path !== "string" || !/^\/(?:body|headers|path|query)(?:\/[A-Za-z0-9_.~-]+)*$/.test(value.error.path)))
    ) throw new TypeError("INVALID_TRUST_BACKEND_RESPONSE");
    if (method === "GET" && TRUST_ASSIGNED_HOLD_ROUTE.test(pathname)) {
      const exactCodes = new Map([
        [401, new Set(["AUTHENTICATION_REQUIRED", "SESSION_EXPIRED"])],
        [404, new Set(["RESOURCE_NOT_FOUND"])],
        [503, new Set(["COMMAND_OUTCOME_UNKNOWN", "SERVICE_UNAVAILABLE"])],
      ]);
      if (
        !exactCodes.get(response.status)?.has(value.error.code)
        || Object.hasOwn(value.error, "path")
        || response.headers.has("etag")
      ) throw new TypeError("INVALID_TRUST_BACKEND_RESPONSE");
    }
  } else if (method !== "GET") {
    if (response.status !== expectedTrustSuccessStatus(pathname, method)) {
      throw new TypeError("INVALID_TRUST_BACKEND_RESPONSE");
    }
    parseTrustCommandEnvelope(value);
    if (response.headers.has("etag")) throw new TypeError("INVALID_TRUST_BACKEND_RESPONSE");
  } else {
    if (response.status !== expectedTrustSuccessStatus(pathname, method)) {
      throw new TypeError("INVALID_TRUST_BACKEND_RESPONSE");
    }
    let projection;
    if (pathname === TRUST_REPORT_ROUTE) projection = parseTrustOwnReportListEnvelope(value);
    else if (pathname === TRUST_ASSIGNMENTS_ROUTE) projection = parseTrustAssignmentListEnvelope(value);
    else if (pathname === TRUST_CASE_HISTORY_ROUTE) projection = parseTrustCaseHistoryEnvelope(value);
    else if (TRUST_ASSIGNED_HOLD_ROUTE.test(pathname)) projection = parseTrustAssignedHoldEnvelope(value);
    else if (pathname === "/v1/app/trust/queue") projection = parseTrustQueueEnvelope(value);
    else if (pathname === "/v1/app/trust/hold-release-queue") projection = parseTrustHoldReleaseQueueEnvelope(value);
    else if (TRUST_REPORT_READ_ROUTE.test(pathname)) projection = parseTrustReportEnvelope(value);
    else if (TRUST_CASE_READ_ROUTE.test(pathname)) projection = parseTrustCaseEnvelope(value);
    else throw new TypeError("INVALID_TRUST_BACKEND_RESPONSE");
    if (response.headers.get("etag") !== projection.entity_tag) {
      throw new TypeError("INVALID_TRUST_BACKEND_RESPONSE");
    }
  }
  return new Response(JSON.stringify(value), {
    status: response.status,
    statusText: response.statusText,
    headers: safeResponseHeaders(response.headers),
  });
}

function expectedAppealSuccessStatus(pathname, method) {
  if (method === "GET") return 200;
  if (pathname === APPEAL_COLLECTION_ROUTE || APPEAL_REVIEW_CLAIM_ROUTE.test(pathname)) return 201;
  return 200;
}

function allowedAppealErrorStatuses(pathname, method) {
  if (method === "GET" && (pathname === APPEAL_COLLECTION_ROUTE || APPEAL_OWN_READ_ROUTE.test(pathname))) {
    return new Set([401, 404, 503]);
  }
  if (method === "GET" && pathname === APPEAL_REVIEW_QUEUE_ROUTE) return new Set([401, 403, 503]);
  if (method === "GET" && pathname === APPEAL_REVIEW_ASSIGNMENTS_ROUTE) return new Set([401, 403, 404, 503]);
  if (method === "GET" && pathname === APPEAL_REVIEW_HISTORY_ROUTE) return new Set([401, 403, 404, 503]);
  if (method === "GET" && APPEAL_REVIEW_HISTORY_DETAIL_ROUTE.test(pathname)) return new Set([401, 403, 404, 503]);
  if (method === "GET" && APPEAL_ASSIGNED_READ_ROUTE.test(pathname)) return new Set([401, 403, 404, 503]);
  if (method === "POST" && pathname === APPEAL_COLLECTION_ROUTE) return new Set([400, 401, 403, 404, 409, 422, 503]);
  if (method === "POST" && APPEAL_REVIEW_CLAIM_ROUTE.test(pathname)) return new Set([400, 401, 403, 404, 409, 412, 503]);
  return new Set([400, 401, 403, 404, 409, 412, 422, 503]);
}

async function validateAppealProxyResponse(source, response) {
  const pathname = new URL(source.url).pathname;
  const method = source.method.toUpperCase();
  if (!pathname.startsWith("/v1/app/appeal")) return null;
  if (
    response.status >= 300 && response.status < 400
    || response.headers.has("set-cookie")
    || response.headers.get("cache-control") !== "no-store"
    || !/^application\/json(?:\s*;|$)/i.test(response.headers.get("content-type") ?? "")
  ) throw new TypeError("INVALID_APPEAL_BACKEND_RESPONSE");
  let value;
  try {
    value = await response.json();
  } catch {
    throw new TypeError("INVALID_APPEAL_BACKEND_RESPONSE");
  }
  if (!response.ok) {
    if (!allowedAppealErrorStatuses(pathname, method).has(response.status) || !exactObject(value, new Set(["error"]))) {
      throw new TypeError("INVALID_APPEAL_BACKEND_RESPONSE");
    }
    const errorKeys = value.error && typeof value.error === "object" && Object.hasOwn(value.error, "path")
      ? new Set(["code", "path"])
      : new Set(["code"]);
    if (
      !exactObject(value.error, errorKeys)
      || !APPEAL_ERROR_CODES.has(value.error.code)
      || (Object.hasOwn(value.error, "path") && (
        typeof value.error.path !== "string"
        || value.error.path.length > 256
        || !/^\/(?:body|headers|path|query)(?:\/[A-Za-z0-9_.~-]+)*$/.test(value.error.path)
      ))
      || response.headers.has("etag")
    ) throw new TypeError("INVALID_APPEAL_BACKEND_RESPONSE");
  } else if (method !== "GET") {
    if (response.status !== expectedAppealSuccessStatus(pathname, method) || response.headers.has("etag")) {
      throw new TypeError("INVALID_APPEAL_BACKEND_RESPONSE");
    }
    parseAppealCommandEnvelope(value);
  } else {
    if (response.status !== 200) throw new TypeError("INVALID_APPEAL_BACKEND_RESPONSE");
    let projection;
    if (pathname === APPEAL_COLLECTION_ROUTE || APPEAL_OWN_READ_ROUTE.test(pathname)) {
      projection = parseAppealOwnEnvelope(value);
    } else if (pathname === APPEAL_REVIEW_QUEUE_ROUTE) {
      projection = parseAppealQueueEnvelope(value);
    } else if (pathname === APPEAL_REVIEW_ASSIGNMENTS_ROUTE) {
      projection = parseAppealAssignmentListEnvelope(value);
    } else if (pathname === APPEAL_REVIEW_HISTORY_ROUTE) {
      projection = parseAppealReviewHistoryEnvelope(value);
    } else if (APPEAL_REVIEW_HISTORY_DETAIL_ROUTE.test(pathname)) {
      projection = parseAppealReviewTerminalEnvelope(value);
    } else if (APPEAL_ASSIGNED_READ_ROUTE.test(pathname)) {
      projection = parseAppealAssignedEnvelope(value);
    } else {
      throw new TypeError("INVALID_APPEAL_BACKEND_RESPONSE");
    }
    if (response.headers.get("etag") !== projection.entity_tag) {
      throw new TypeError("INVALID_APPEAL_BACKEND_RESPONSE");
    }
  }
  return new Response(JSON.stringify(value), {
    status: response.status,
    statusText: response.statusText,
    headers: safeResponseHeaders(response.headers),
  });
}

export async function proxyLocalRequest(source, options = {}) {
  try {
    const baseUrl = typeof options.baseUrl === "string" ? options.baseUrl.trim() : options.baseUrl;
    const request = await createLoopbackProxyRequest(source, baseUrl);
    const response = await (options.fetchImpl ?? fetch)(request, { redirect: "manual", signal: AbortSignal.timeout(6000) });
    if (response.status >= 300 && response.status < 400) throw new TypeError("LOOPBACK_REDIRECT_REJECTED");
    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers: safeResponseHeaders(response.headers),
    });
  } catch (error) {
    const code = error instanceof TypeError && error.message === "LOCAL_ROUTE_NOT_ALLOWED"
      ? "LOCAL_ROUTE_NOT_ALLOWED"
      : error instanceof TypeError && error.message === "PROXY_REQUEST_TOO_LARGE"
        ? "PROXY_REQUEST_TOO_LARGE"
        : "LOCAL_BACKEND_UNAVAILABLE";
    return Response.json(
      { code, message: code === "LOCAL_ROUTE_NOT_ALLOWED" ? "该本地接口不可用。" : code === "PROXY_REQUEST_TOO_LARGE" ? "请求内容超过内部试运行限制。" : "无法连接本地平台内核。" },
      { status: code === "LOCAL_ROUTE_NOT_ALLOWED" ? 404 : code === "PROXY_REQUEST_TOO_LARGE" ? 413 : 503, headers: { "cache-control": "no-store" } },
    );
  }
}

export async function proxyAppRequest(source, options = {}) {
  try {
    const baseUrl = typeof options.baseUrl === "string" ? options.baseUrl.trim() : options.baseUrl;
    const request = await createAppProxyRequest(source, baseUrl);
    const response = await (options.fetchImpl ?? fetch)(request, { redirect: "manual", signal: AbortSignal.timeout(6000) });
    if (response.status >= 300 && response.status < 400) throw new TypeError("LOOPBACK_REDIRECT_REJECTED");
    const adminDemandResponse = await validateAdminDemandProxyResponse(source, response);
    if (adminDemandResponse) return adminDemandResponse;
    const taskResponse = await validateTaskDiscoveryProxyResponse(source, response);
    if (taskResponse) return taskResponse;
    const reviewHistoryResponse = await validateReviewHistoryProxyResponse(source, response);
    if (reviewHistoryResponse) return reviewHistoryResponse;
    const financeFundingHistoryResponse = await validateFinanceFundingHistoryProxyResponse(source, response);
    if (financeFundingHistoryResponse) return financeFundingHistoryResponse;
    const reviewReleaseResponse = await validateReviewReleaseProxyResponse(source, response);
    if (reviewReleaseResponse) return reviewReleaseResponse;
    const demandCancelResponse = await validateDemandCancelProxyResponse(source, response);
    if (demandCancelResponse) return demandCancelResponse;
    const trustResponse = await validateTrustProxyResponse(source, response);
    if (trustResponse) return trustResponse;
    const appealResponse = await validateAppealProxyResponse(source, response);
    if (appealResponse) return appealResponse;
    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers: safeResponseHeaders(response.headers),
    });
  } catch (error) {
    if (error instanceof TypeError && ["INVALID_ADMIN_DEMAND_QUERY", "INVALID_ADMIN_DEMAND_REQUEST"].includes(error.message)) {
      return Response.json({ error: { code: "INVALID_REQUEST" } }, { status: 400, headers: { "cache-control": "no-store" } });
    }
    if (error instanceof TypeError && error.message === "INVALID_TRUST_ASSIGNED_HOLD_QUERY") {
      return Response.json(
        { error: { code: "RESOURCE_NOT_FOUND" } },
        { status: 404, headers: { "cache-control": "no-store" } },
      );
    }
    if (error instanceof TypeError && error.message === "INVALID_TRUST_ASSIGNMENTS_QUERY") {
      return Response.json(
        { error: { code: "RESOURCE_NOT_FOUND" } },
        { status: 404, headers: { "cache-control": "no-store" } },
      );
    }
    if (error instanceof TypeError && error.message === "INVALID_APPEAL_ASSIGNMENTS_QUERY") {
      return Response.json(
        { error: { code: "INVALID_REQUEST", path: "/query" } },
        { status: 400, headers: { "cache-control": "no-store" } },
      );
    }
    if (error instanceof TypeError && error.message === "INVALID_APPEAL_REVIEW_HISTORY_QUERY") {
      return Response.json(
        { error: { code: "INVALID_REQUEST", path: "/query" } },
        { status: 400, headers: { "cache-control": "no-store" } },
      );
    }
    if (error instanceof TypeError && error.message === "INVALID_REVIEW_HISTORY_QUERY") {
      return Response.json(
        { error: { code: "INVALID_REQUEST", path: "/query" } },
        { status: 400, headers: { "cache-control": "no-store" } },
      );
    }
    if (error instanceof TypeError && error.message === "INVALID_FINANCE_FUNDING_HISTORY_QUERY") {
      return Response.json(
        { error: { code: "INVALID_REQUEST", path: "/query" } },
        { status: 400, headers: { "cache-control": "no-store" } },
      );
    }
    const closedClientCodes = new Set([
      "AUTHORITY_HEADER_FORBIDDEN",
      "INVALID_WORKSPACE_ID",
      "INVALID_PROFILE_LIFECYCLE_REQUEST",
      "INVALID_DEMAND_CANCEL_REQUEST",
      "INVALID_REVIEW_REQUEST",
      "INVALID_APPEAL_REQUEST",
      "INVALID_TRUST_REQUEST",
      "WORKSPACE_HEADER_FORBIDDEN",
      "WORKSPACE_REQUIRED",
    ]);
    const code = error instanceof TypeError && error.message === "APP_ROUTE_NOT_ALLOWED"
      ? "APP_ROUTE_NOT_ALLOWED"
      : error instanceof TypeError && error.message === "PROXY_REQUEST_TOO_LARGE"
        ? "PROXY_REQUEST_TOO_LARGE"
        : error instanceof TypeError && closedClientCodes.has(error.message)
          ? error.message
          : "INTERNAL_PILOT_BACKEND_UNAVAILABLE";
    const message = code === "APP_ROUTE_NOT_ALLOWED"
      ? "该内部试运行接口不可用。"
      : code === "PROXY_REQUEST_TOO_LARGE"
        ? "请求内容超过内部试运行限制。"
        : code === "WORKSPACE_REQUIRED"
          ? "必须先选择一个服务端工作区。"
        : code === "WORKSPACE_HEADER_FORBIDDEN"
            ? "工作区发现请求不能指定工作区。"
            : code === "AUTHORITY_HEADER_FORBIDDEN"
              ? "审核请求不能携带客户端声明的身份或权限。"
              : code === "INVALID_REVIEW_REQUEST"
                ? "审核请求不符合封闭契约。"
              : code === "INVALID_PROFILE_LIFECYCLE_REQUEST"
                ? "创作者档案状态请求不符合封闭契约。"
              : code === "INVALID_DEMAND_CANCEL_REQUEST"
                ? "需求取消请求不符合封闭契约。"
              : code === "INVALID_TRUST_REQUEST"
                ? "Trust 请求不符合封闭契约。"
            : code === "INVALID_WORKSPACE_ID"
              ? "工作区标识无效。"
              : "无法连接内部试运行平台。";
    const status = code === "APP_ROUTE_NOT_ALLOWED"
      ? 404
      : code === "PROXY_REQUEST_TOO_LARGE"
        ? 413
        : closedClientCodes.has(code)
          ? 400
          : 503;
    return Response.json(
      { code, message },
      { status, headers: { "cache-control": "no-store" } },
    );
  }
}

function isSafeSameOriginLocation(value) {
  return typeof value === "string"
    && value.startsWith("/")
    && !value.startsWith("//")
    && !value.includes("\\")
    && !hasAsciiControl(value);
}

export async function proxyAuthRequest(source, options = {}) {
  try {
    const sourceUrl = new URL(source.url);
    const baseUrl = typeof options.baseUrl === "string" ? options.baseUrl.trim() : options.baseUrl;
    const request = await createAuthProxyRequest(source, baseUrl);
    const response = await (options.fetchImpl ?? fetch)(request, { redirect: "manual", signal: AbortSignal.timeout(10000) });
    const isCallback = sourceUrl.pathname === "/v1/auth/oidc/callback";
    if (response.status >= 300 && response.status < 400) {
      if (!isCallback || response.status !== 303 || !isSafeSameOriginLocation(response.headers.get("location"))) {
        throw new TypeError("AUTH_REDIRECT_REJECTED");
      }
    }
    const sessionListResponse = await validateSessionListProxyResponse(
      source,
      response,
    );
    if (sessionListResponse) return sessionListResponse;
    const headers = safeResponseHeaders(response.headers);
    if (response.status === 303) headers.set("location", response.headers.get("location"));
    const isSessionLogout = source.method.toUpperCase() === "DELETE"
      && IAM_SESSION_LOGOUT_ROUTE.test(sourceUrl.pathname);
    if (isSessionLogout) {
      if (response.status === 204) {
        const targetSessionId = sourceUrl.pathname.slice(`${IAM_SESSION_LIST_ROUTE}/`.length);
        const bootstrapSessionId = source.headers.get(BOOTSTRAP_SESSION_ID_HEADER);
        const setCookie = response.headers.get("set-cookie");
        const targetsCurrentSession = targetSessionId === bootstrapSessionId;
        if (
          response.body !== null
          || (targetsCurrentSession && setCookie !== SESSION_CLEAR_COOKIE)
          || (!targetsCurrentSession && setCookie !== null)
        ) {
          throw new TypeError("SESSION_LOGOUT_RESPONSE_INVALID");
        }
      } else {
        headers.delete("set-cookie");
        if (response.ok) throw new TypeError("SESSION_LOGOUT_RESPONSE_INVALID");
      }
    }
    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers,
    });
  } catch (error) {
    const closedClientCodes = new Set([
      "AUTHORITY_HEADER_FORBIDDEN", "INVALID_POLICY_ACCEPTANCE_REQUEST", "INVALID_OIDC_AUTHORIZATION_REQUEST",
      "INVALID_SESSION_LIST_REQUEST", "INVALID_SESSION_LOGOUT_REQUEST",
    ]);
    const code = error instanceof TypeError && error.message === "AUTH_ROUTE_NOT_ALLOWED"
      ? "AUTH_ROUTE_NOT_ALLOWED"
      : error instanceof TypeError && error.message === "PROXY_REQUEST_TOO_LARGE"
        ? "PROXY_REQUEST_TOO_LARGE"
        : error instanceof TypeError && closedClientCodes.has(error.message)
          ? error.message
          : "AUTH_BACKEND_UNAVAILABLE";
    const message = code === "AUTH_ROUTE_NOT_ALLOWED"
      ? "该认证接口不可用。"
      : code === "PROXY_REQUEST_TOO_LARGE"
        ? "请求内容超过内部试运行限制。"
        : code === "AUTHORITY_HEADER_FORBIDDEN"
          ? "政策请求不能携带客户端声明的身份、组织、角色或工作区。"
          : code === "INVALID_POLICY_ACCEPTANCE_REQUEST"
            ? "政策接受请求的闭合契约无效。"
          : code === "INVALID_OIDC_AUTHORIZATION_REQUEST"
              ? "OIDC 登录或再认证请求不符合封闭契约。"
            : code === "INVALID_SESSION_LIST_REQUEST"
              ? "会话列表请求不符合封闭契约。"
            : code === "INVALID_SESSION_LOGOUT_REQUEST"
              ? "退出登录请求不符合封闭契约。"
            : "无法连接认证服务。";
    const status = code === "AUTH_ROUTE_NOT_ALLOWED"
      ? 404
      : code === "PROXY_REQUEST_TOO_LARGE"
        ? 413
        : closedClientCodes.has(code)
          ? 400
          : 503;
    return Response.json(
      { code, message },
      { status, headers: { "cache-control": "no-store" } },
    );
  }
}

export async function proxyIamRequest(source, options = {}) {
  const sourcePath = new URL(source.url).pathname;
  const matchingSource = isMatchingRoutePath(sourcePath);
  try {
    const baseUrl = typeof options.baseUrl === "string" ? options.baseUrl.trim() : options.baseUrl;
    const request = await createIamProxyRequest(source, baseUrl);
    const matchingValidationRequest = matchingSource ? request.clone() : null;
    const response = await (options.fetchImpl ?? fetch)(request, { redirect: "manual", signal: AbortSignal.timeout(10000) });
    if (response.status >= 300 && response.status < 400) throw new TypeError("IAM_REDIRECT_REJECTED");
    const matchingResponse = await validateMatchingProxyResponse(source, response, matchingValidationRequest);
    if (matchingResponse) return matchingResponse;
    const headers = safeResponseHeaders(response.headers);
    const isInvitationAccept = IAM_INVITATION_ACCEPT_ROUTE.test(sourcePath);
    const setCookies = typeof response.headers.getSetCookie === "function"
      ? response.headers.getSetCookie()
      : response.headers.has("set-cookie")
        ? [response.headers.get("set-cookie")]
        : [];
    if (isInvitationAccept && response.status === 200) {
      if (
        setCookies.length > 1
        || (setCookies.length === 1 && !SESSION_SET_COOKIE.test(setCookies[0] ?? ""))
      ) throw new TypeError("IAM_ACCEPT_SESSION_COOKIE_REJECTED");
      if (setCookies.length === 0) headers.delete("set-cookie");
      else headers.set("set-cookie", setCookies[0]);
    } else {
      headers.delete("set-cookie");
    }
    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers,
    });
  } catch (error) {
    const closedClientCodes = new Set(["AUTHORITY_HEADER_FORBIDDEN", "INVALID_IAM_REQUEST", "INVALID_MATCHING_REQUEST"]);
    const code = error instanceof TypeError && error.message === "IAM_ROUTE_NOT_ALLOWED"
      ? matchingSource ? "MATCHING_ROUTE_NOT_ALLOWED" : "IAM_ROUTE_NOT_ALLOWED"
      : error instanceof TypeError && error.message === "PROXY_REQUEST_TOO_LARGE"
        ? "PROXY_REQUEST_TOO_LARGE"
        : error instanceof TypeError && closedClientCodes.has(error.message)
          ? error.message
          : matchingSource ? "MATCHING_BACKEND_UNAVAILABLE" : "IAM_BACKEND_UNAVAILABLE";
    const message = code === "IAM_ROUTE_NOT_ALLOWED"
      ? "该组织管理接口不可用。"
      : code === "MATCHING_ROUTE_NOT_ALLOWED"
        ? "该 Matching 接口不可用。"
      : code === "PROXY_REQUEST_TOO_LARGE"
        ? "请求内容超过内部试运行限制。"
        : code === "AUTHORITY_HEADER_FORBIDDEN"
          ? matchingSource
            ? "Matching 请求不能携带客户端声明的身份、组织、角色或工作区。"
            : "组织管理请求不能携带客户端声明的身份、组织、角色或工作区。"
          : code === "INVALID_IAM_REQUEST"
            ? "组织管理请求不符合封闭契约。"
            : code === "INVALID_MATCHING_REQUEST"
              ? "Matching 请求不符合封闭契约。"
            : code === "MATCHING_BACKEND_UNAVAILABLE"
              ? "无法验证 Matching 服务响应。"
              : "无法连接组织权限服务。";
    const status = code === "IAM_ROUTE_NOT_ALLOWED" || code === "MATCHING_ROUTE_NOT_ALLOWED"
      ? 404
      : code === "PROXY_REQUEST_TOO_LARGE"
        ? 413
        : closedClientCodes.has(code)
          ? 400
          : 503;
    return Response.json({ code, message }, { status, headers: { "cache-control": "no-store" } });
  }
}
