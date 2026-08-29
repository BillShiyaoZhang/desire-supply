"use client";

import { FormEvent, type RefObject, useCallback, useEffect, useRef, useState } from "react";
import {
  type AccountAdminProjection,
  type ConflictSurface,
  type CurrentAccountTask,
  type CurrentAccountTaskDiscovery,
  type EditorConfiguration,
  type EditorReviewQueueItem,
  type EditorResource,
  type EditorVersion,
  type FinanceFundingHistoryItem,
  type FinanceFundingQueueItem,
  type FinanceFundingReview,
  type PendingIntent,
  type PendingInvitationContext,
  type PendingOrganizationAdminWrite,
  type MeProjection,
  type PolicyBundle,
  type ResourceType,
  type SessionBootstrap,
  type WorkspaceCandidate,
  type WriteIntent,
  ACCOUNT_ADMIN_REASON_CODES,
  ACCOUNT_ADMIN_PLATFORM_DUTY_CODES,
  FINANCE_FUNDING_ATTESTATION_CODES,
  FINANCE_FUNDING_DISCREPANCY_REASON_CODES,
  FINANCE_FUNDING_FINDING_FIELD_CODES,
  FINANCE_FUNDING_RELEASE_REASON_CODES,
  FINANCE_FUNDING_REJECTED_REASON_CODES,
  DEMAND_OWNER_CANCEL_REASON_CODES,
  PROFILE_ARCHIVE_REASON_CODES,
  PROFILE_PAUSE_REASON_CODES,
  REVIEW_ASSIGNMENT_RELEASE_REASON_CODES,
  REVIEW_REASON_CODES,
  VERIFY_BUDGET_HEALTH_CODES,
  VERIFY_EVIDENCE_CODES,
  VERIFY_RISK_CODES,
  createAccountAdminIntent,
  createPlatformDutyIntent,
  createDemandDraftIntent,
  createDemandCancelIntent,
  createDemandIntent,
  createFindingIntent,
  createFinanceFundingClaimIntent,
  createFinanceFundingConfirmIntent,
  createFinanceFundingFindingIntent,
  createFinanceFundingReleaseIntent,
  createProfileDraftIntent,
  createProfileIntent,
  createProfileLifecycleIntent,
  createPolicyAcceptanceIntent,
  createReviewClaimIntent,
  createReviewAssignmentReleaseIntent,
  createResourceActionIntent,
  createVerifyIntent,
  parseEditorCollection,
  parseCurrentAccountTaskDiscovery,
  parseEditorConfigurationEnvelope,
  parseEditorEnvelope,
  parseEditorReviewClaimEnvelope,
  parseEditorReviewQueueEnvelope,
  parseFinanceFundingQueueEnvelope,
  parseFinanceFundingReviewEnvelope,
  parseAccountAdminCollectionEnvelope,
  parseAccountAdminCommandEnvelope,
  parseAccountAdminEnvelope,
  parseMe,
  parsePolicyBundle,
  parsePolicyRequirementStatus,
  parsePendingIntent,
  parsePendingInvitationContext,
  parseSessionBootstrap,
  parseThreeWayConflict,
  parseWorkspaceDiscovery,
  sectionsFromContent,
  sectionsToContent,
  selectWorkspaceCandidate,
  serializePendingIntent,
  serializePendingOrganizationAdminWrite,
  verifyPolicyBundleDocuments,
  bindConflictToCurrentResource,
} from "../lib/app-contract.mjs";
import {
  PENDING_INVITATION_ACCEPTANCE_KEY,
  PENDING_INVITATION_CONTEXT_KEY,
  parseIdentityAuthorizationUrl,
} from "../lib/invitation-flow.mjs";
import { InvitationAcceptance } from "./invitation-acceptance";
import { OrganizationAdminWorkbench } from "./organization-admin-workbench";
import { SessionManager } from "./session-manager";
import {
  LEGACY_SESSION_REVOKE_PENDING_KEY,
  SESSION_REVOKE_PENDING_KEY,
} from "../lib/session-manager-state.mjs";
import { AppealWorkbench, type AppealTaskTarget } from "./appeal-workbench";
import { TrustWorkbench, type TrustCaseHistoryTaskTarget } from "./trust-workbench";
import { ReviewHistoryPanel } from "./review-history-panel";
import { FinanceFundingHistoryPanel } from "./finance-funding-history-panel";
import { MatchingWorkbench } from "./matching-workbench";
import { MatchingReviewWorkbench } from "./matching-review-workbench";
import {
  arrayItemTemplate,
  editorChoiceSourceLabel,
  fieldInputMeta,
  fieldLabel,
  hasOptionalValueTemplate,
  issueMessage,
  optionalValueTemplate,
  parseStructuredSection,
  resolveEditorChoice,
  serializeStructuredSection,
  structuredContentIssues,
  structuredSectionIssues,
} from "../lib/editor-fields.mjs";
import {
  type EditorDiffValue,
  diffEditorVersionContent,
} from "../lib/editor-version-diff.mjs";
import {
  type EditorConflictChoice,
  type EditorConflictSectionState,
  planEditorConflictMerge,
} from "../lib/editor-conflict-merge.mjs";
import {
  dateTimeLocalToIso,
  defaultDemandExpiry,
  editorResponseBindingMatches,
  expectedEditorResponseObjectId,
  persistEditorScratch as persistEditorScratchToStorage,
} from "../lib/product-workspace-state.mjs";
import {
  type AppealHandoff,
  isAppealHandoffCurrent,
} from "../lib/appeal-handoff.mjs";
import { createAtomicRefreshCoordinator } from "../lib/workbench-refresh.mjs";
import {
  resolveAppealTaskReadKind,
  resolveCurrentAccountTaskDestination,
  resolveFinanceTaskDetail,
  resolveFinanceTaskDetailAction,
  resolveRevalidatedCurrentAccountTask,
  resolveRevalidatedCurrentAccountTaskResource,
  resolveRevalidatedFinanceTaskQueueItem,
} from "../lib/current-account-task-destination.mjs";

const ENDPOINTS = {
  session: "/v1/auth/session",
  authorization: "/v1/auth/oidc/authorizations",
  me: "/v1/me",
  policyBundles: "/v1/policy-bundles",
  policyAcceptances: "/v1/me/policy-acceptances",
  workspaces: "/v1/app/workspaces",
  configuration: "/v1/app/configuration",
  tasks: "/v1/app/tasks",
  profiles: "/v1/app/profiles",
  demands: "/v1/app/demands",
  reviewQueue: "/v1/app/review-queue",
  financeFundingReviews: "/v1/app/finance/funding-reviews",
  accounts: "/v1/app/admin/accounts",
} as const;

const PENDING_KEY = "desire-pilot-pending:v1";
const MATCHING_SELECTION_RECOVERY_KEY = "desire-pilot-matching-selection-recovery:v1";
const WORKSPACE_KEY = "desire-pilot-workspace:v1";
const SCRATCH_PREFIX = "desire-pilot-scratch:v1:";
const LOGOUT_PENDING_KEY = "desire-pilot-session-logout:v1";
const PENDING_ORGANIZATION_ADMIN_KEY = "desire-pilot-org-admin-pending:v1";
const SESSION_UUID = /^(?!0{8}-0{4}-0{4}-0{4}-0{12})[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const LOGOUT_IDEMPOTENCY_KEY = /^[A-Za-z0-9][A-Za-z0-9._~-]{15,127}$/;
const LOGOUT_CSRF_TOKEN = /^[A-Za-z0-9_-]{32,512}$/;
const LOGOUT_RECOVERY_MS = 24 * 60 * 60 * 1000;

type SessionLogoutIntent = {
  version: 1;
  saved_at: string;
  session_id: string;
  csrf_token: string;
  idempotency_key: string;
};

type SessionWriteLatch = {
  resource_type: "SESSION_REVOKE";
  write_key: string;
};

function appealTaskReadKind(task: CurrentAccountTask): AppealTaskTarget["read_kind"] | null {
  return resolveAppealTaskReadKind(task) as AppealTaskTarget["read_kind"] | null;
}

function isTrustCaseHistoryTask(task: CurrentAccountTask) {
  return task.resource_kind === "TRUST_CASE"
    && task.next_action === "VIEW_TRUST_CASE_HISTORY";
}

const SECTION_LABELS: Record<string, string> = {
  "/interests": "兴趣与问题偏好",
  "/skills": "技能要求",
  "/availability": "可投入时间",
  "/collaboration": "协作方式",
  "/compensation": "报酬边界",
  "/boundaries": "工作边界",
  "/location": "地域约束",
  "/conflicts": "利益冲突",
  "/ai": "AI 使用约束",
  "/problem": "问题与目标",
  "/scope": "范围与交付物",
  "/acceptance": "验收规则",
  "/matching": "匹配条件",
  "/schedule": "计划与工期",
  "/budget": "合成预算",
  "/milestone_plan": "里程碑",
  "/risk": "风险与数据敏感度",
  "/declarations": "授权声明",
};

const STATUS_LABELS: Record<string, string> = {
  DRAFT: "草稿",
  ACTIVE: "已发布",
  PUBLISHED: "已发布",
  SUBMITTED: "已提交",
  UNDER_REVIEW: "审核中",
  NEEDS_CHANGES: "需要修改",
  VERIFIED: "已验证",
  CANCELLED: "已取消",
  PAUSED: "已暂停",
  ARCHIVED: "已归档",
  DISCARDED: "已废弃",
  RETIRED: "已退役",
};

const POLICY_LEGAL_EFFECT_LABELS: Record<string, string> = {
  NOTICE_ACKNOWLEDGEMENT: "通知知悉",
  CONTRACT_ACCEPTANCE: "合同性接受",
  CONSENT_TEXT: "可选同意文本（本步骤不授权）",
};

const WORKSPACE_KIND_LABELS: Record<WorkspaceCandidate["workspace_kind"], string> = {
  ORGANIZATION: "组织工作区",
  PERSONAL: "个人工作区",
  PLATFORM: "平台职责工作区",
};

class ApiError extends Error {
  constructor(
    public status: number,
    public code: string,
    public body: unknown,
    public etag: string | null,
    public traceId: string | null,
  ) {
    super(code);
  }
}

async function requestJson(path: string, init?: RequestInit) {
  let response: Response;
  try {
    const headers = new Headers(init?.headers);
    headers.set("accept", "application/json");
    response = await fetch(path, {
      ...init,
      cache: "no-store",
      credentials: "same-origin",
      headers,
    });
  } catch {
    throw new ApiError(0, "NETWORK_OUTCOME_UNKNOWN", null, null, null);
  }
  const value: unknown = await response.json().catch(() => null);
  if (!response.ok) {
    const top = value && typeof value === "object" ? value as Record<string, unknown> : {};
    const nested = top.error && typeof top.error === "object" ? top.error as Record<string, unknown> : {};
    const code = typeof nested.code === "string"
      ? nested.code
      : typeof top.code === "string"
        ? top.code
        : "APP_REQUEST_FAILED";
    const traceId = response.headers.get("x-trace-id")
      ?? (typeof top.trace_id === "string" ? top.trace_id : null);
    throw new ApiError(response.status, code, value, response.headers.get("etag"), traceId);
  }
  return { value, etag: response.headers.get("etag") };
}

async function requestWorkspaceJson(workspaceId: string, path: string, init?: RequestInit) {
  if (!workspaceId || path === ENDPOINTS.workspaces || !path.startsWith("/v1/app/")) {
    throw new TypeError("INVALID_WORKSPACE_REQUEST");
  }
  const headers = new Headers(init?.headers);
  headers.set("x-workspace-id", workspaceId);
  return requestJson(path, { ...init, headers });
}

function resourcePath(resource: Pick<EditorResource, "resource_type" | "object_id">) {
  const collection = resource.resource_type === "CREATOR_PROFILE" ? "profiles" : "demands";
  return `/v1/app/${collection}/${resource.object_id}`;
}

function parseEtaggedEditorResponse(
  response: { value: unknown; etag: string | null },
  expected?: { objectId?: string; assignmentId?: string },
) {
  const resource = parseEditorEnvelope(response.value);
  if (
    response.etag !== resource.etag
    || (expected?.objectId !== undefined && resource.object_id !== expected.objectId)
    || (expected?.assignmentId !== undefined && resource.review_assignment?.assignment_id !== expected.assignmentId)
  ) throw new TypeError("INVALID_EDITOR_RESPONSE_BINDING");
  return resource;
}

function isReviewDecisionPath(path: string) {
  return /^\/v1\/app\/demands\/[^/]+\/review-assignments\/[^/]+\/(?:findings|verify)$/.test(path);
}

function isReviewAssignmentReleasePath(path: string) {
  return /^\/v1\/app\/demands\/[^/]+\/review-assignments\/[^/]+\/release$/.test(path);
}

function isReviewAssignmentWritePath(path: string) {
  return isReviewDecisionPath(path) || isReviewAssignmentReleasePath(path);
}

function isProfileLifecyclePath(path: string) {
  return /^\/v1\/app\/profiles\/[^/]+\/(?:pause|resume|archive)$/.test(path);
}

function isDemandCancelPath(path: string) {
  return /^\/v1\/app\/demands\/[^/]+\/cancel$/.test(path);
}

function scratchKey(resource: Pick<EditorResource, "resource_type" | "object_id">) {
  return `${SCRATCH_PREFIX}${resource.resource_type}:${resource.object_id}`;
}

function formatTime(value: string) {
  const date = new Date(value);
  if (Number.isNaN(date.valueOf())) return value;
  return new Intl.DateTimeFormat("zh-CN", {
    dateStyle: "medium",
    timeStyle: "short",
    timeZone: "Asia/Shanghai",
  }).format(date);
}

function formatSyntheticBudgetAmount(amountMinor: number, currency: "CNY") {
  return new Intl.NumberFormat("zh-CN", {
    style: "currency",
    currency,
    currencyDisplay: "code",
  }).format(amountMinor / 100);
}

function shortId(value: string) {
  return value.length > 26 ? `${value.slice(0, 12)}…${value.slice(-8)}` : value;
}

function statusLabel(value: string) {
  return STATUS_LABELS[value] ?? value.replaceAll("_", " ");
}

function accountStatusLabel(value: AccountAdminProjection["status"]) {
  return value === "ACTIVE" ? "正常" : "已暂停";
}

function workspaceLabel(workspace: WorkspaceCandidate) {
  return WORKSPACE_KIND_LABELS[workspace.workspace_kind];
}

function newIdempotencyKey() {
  return crypto.randomUUID();
}

function serializeSessionLogoutIntent(intent: SessionLogoutIntent) {
  return JSON.stringify(intent);
}

function parseSessionLogoutIntent(encoded: string, now = Date.now()): SessionLogoutIntent | null {
  if (!encoded || encoded.length > 2048) return null;
  try {
    const value: unknown = JSON.parse(encoded);
    if (!value || typeof value !== "object" || Array.isArray(value)) return null;
    const item = value as Record<string, unknown>;
    if (
      Object.keys(item).length !== 5
      || item.version !== 1
      || typeof item.saved_at !== "string"
      || typeof item.session_id !== "string"
      || typeof item.csrf_token !== "string"
      || typeof item.idempotency_key !== "string"
      || !SESSION_UUID.test(item.session_id)
      || !LOGOUT_CSRF_TOKEN.test(item.csrf_token)
      || !LOGOUT_IDEMPOTENCY_KEY.test(item.idempotency_key)
    ) return null;
    const savedAt = Date.parse(item.saved_at);
    if (!Number.isFinite(savedAt) || savedAt > now + 5 * 60 * 1000 || now - savedAt > LOGOUT_RECOVERY_MS) return null;
    return item as SessionLogoutIntent;
  } catch {
    return null;
  }
}

function clearAuthenticatedBrowserState() {
  for (let index = sessionStorage.length - 1; index >= 0; index -= 1) {
    const key = sessionStorage.key(index);
    if (key === null) continue;
    const isScratch = key.startsWith(SCRATCH_PREFIX);
    const isOwnedState = new Set([
      PENDING_KEY,
      MATCHING_SELECTION_RECOVERY_KEY,
      WORKSPACE_KEY,
      LOGOUT_PENDING_KEY,
      PENDING_INVITATION_CONTEXT_KEY,
      PENDING_INVITATION_ACCEPTANCE_KEY,
      PENDING_ORGANIZATION_ADMIN_KEY,
      LEGACY_SESSION_REVOKE_PENDING_KEY,
      SESSION_REVOKE_PENDING_KEY,
    ]).has(key);
    if (isScratch || isOwnedState) sessionStorage.removeItem(key);
  }
}

function pendingRecord(resourceType: PendingIntent["resource_type"], objectId: string, label: string, intent: WriteIntent): PendingIntent {
  return {
    version: 1,
    saved_at: new Date().toISOString(),
    resource_type: resourceType,
    object_id: objectId,
    label,
    intent,
  };
}

function readScratch(resource: EditorResource) {
  try {
    const raw = sessionStorage.getItem(scratchKey(resource));
    if (!raw || raw.length > 256 * 1024) return null;
    const value: unknown = JSON.parse(raw);
    if (!value || typeof value !== "object") return null;
    const draft = value as Record<string, unknown>;
    if (
      draft.version !== 1
      || draft.object_id !== resource.object_id
      || draft.resource_type !== resource.resource_type
      || draft.base_revision !== resource.revision
      || typeof draft.saved_at !== "string"
      || Date.now() - Date.parse(draft.saved_at) > 24 * 60 * 60 * 1000
      || !draft.sections
      || typeof draft.sections !== "object"
    ) return null;
    const sections = Object.fromEntries(Object.entries(draft.sections).filter((entry): entry is [string, string] => typeof entry[1] === "string"));
    return { sections, savedAt: draft.saved_at };
  } catch {
    return null;
  }
}

function ErrorNotice({ error }: { error: { code: string; traceId: string | null } | null }) {
  if (!error) return null;
  return (
    <div className="error-panel" role="alert">
      <strong>请求未完成：{error.code}</strong>
      <span>平台没有把失败当作成功；请按当前页面给出的恢复方式处理。</span>
      {error.traceId && <small>追踪编号：<code>{error.traceId}</code></small>}
    </div>
  );
}

export function ProductClient() {
  const [phase, setPhase] = useState<"LOADING" | "SIGNED_OUT" | "INVITATION_ACCEPTANCE" | "POLICY_ACCEPTANCE" | "WORKSPACE_SELECTION" | "SIGNED_IN" | "UNAVAILABLE">("LOADING");
  const [session, setSession] = useState<SessionBootstrap | null>(null);
  const [me, setMe] = useState<MeProjection | null>(null);
  const [policyBundle, setPolicyBundle] = useState<PolicyBundle | null>(null);
  const [affirmedPolicyDocumentIds, setAffirmedPolicyDocumentIds] = useState<string[]>([]);
  const [policyAcceptanceIntent, setPolicyAcceptanceIntent] = useState<WriteIntent | null>(null);
  const [workspaces, setWorkspaces] = useState<WorkspaceCandidate[]>([]);
  const [selectedWorkspace, setSelectedWorkspace] = useState<WorkspaceCandidate | null>(null);
  const [configuration, setConfiguration] = useState<EditorConfiguration | null>(null);
  const [profiles, setProfiles] = useState<EditorResource[]>([]);
  const [demands, setDemands] = useState<EditorResource[]>([]);
  const [reviewQueue, setReviewQueue] = useState<EditorReviewQueueItem[]>([]);
  const [financeFundingQueue, setFinanceFundingQueue] = useState<FinanceFundingQueueItem[]>([]);
  const [profileScope, setProfileScope] = useState(false);
  const [demandScope, setDemandScope] = useState(false);
  const [reviewQueueScope, setReviewQueueScope] = useState(false);
  const [financeFundingScope, setFinanceFundingScope] = useState(false);
  const [accounts, setAccounts] = useState<AccountAdminProjection[]>([]);
  const [accountScope, setAccountScope] = useState(false);
  const [taskDiscovery, setTaskDiscovery] = useState<CurrentAccountTaskDiscovery | null>(null);
  const [taskError, setTaskError] = useState<{ code: string; traceId: string | null } | null>(null);
  const [taskBusy, setTaskBusy] = useState(false);
  const [taskRefreshCoordinator] = useState(createAtomicRefreshCoordinator);
  const [selectedAccount, setSelectedAccount] = useState<AccountAdminProjection | null>(null);
  const [selectedFinanceReview, setSelectedFinanceReview] = useState<FinanceFundingReview | null>(null);
  const [financeAttestationCodes, setFinanceAttestationCodes] = useState<string[]>([]);
  const [financeReleaseReasonCode, setFinanceReleaseReasonCode] = useState<(typeof FINANCE_FUNDING_RELEASE_REASON_CODES)[number]>("WORKLOAD_RELEASE");
  const [financeFindingDisposition, setFinanceFindingDisposition] = useState<"DISCREPANCY" | "REJECTED">("DISCREPANCY");
  const [financeFindingReasonCodes, setFinanceFindingReasonCodes] = useState<string[]>([]);
  const [financeFindingFieldCodes, setFinanceFindingFieldCodes] = useState<string[]>([]);
  const [accountReasonCode, setAccountReasonCode] = useState("ACCESS_REVIEW");
  const [selected, setSelected] = useState<EditorResource | null>(null);
  const [sections, setSections] = useState<Record<string, string>>({});
  const [dirty, setDirty] = useState(false);
  const [organizationPublicNameDirty, setOrganizationPublicNameDirty] = useState(false);
  const [recoveredScratchAt, setRecoveredScratchAt] = useState<string | null>(null);
  const [pending, setPending] = useState<PendingIntent | null>(null);
  const pendingRef = useRef<PendingIntent | { resource_type: "ORG_ADMIN"; encoded: string } | SessionWriteLatch | null>(null);
  const [pendingOwner, setPendingOwner] = useState<"PRODUCT" | "ORGANIZATION" | "TRUST" | "APPEAL" | "MATCHING" | "SESSION" | null>(null);
  const [logoutIntent, setLogoutIntent] = useState<SessionLogoutIntent | null>(null);
  const logoutIntentRef = useRef<SessionLogoutIntent | null>(null);
  const [appealHandoff, setAppealHandoff] = useState<AppealHandoff | null>(null);
  const [appealTaskTarget, setAppealTaskTarget] = useState<AppealTaskTarget | null>(null);
  const [trustCaseHistoryTaskTarget, setTrustCaseHistoryTaskTarget] = useState<TrustCaseHistoryTaskTarget | null>(null);
  const [invitationContext, setInvitationContext] = useState<PendingInvitationContext | null>(null);
  const [conflict, setConflict] = useState<ConflictSurface | null>(null);
  const [notice, setNotice] = useState("正在核对受邀账号会话和服务端权限投影。");
  const [error, setError] = useState<{ code: string; traceId: string | null } | null>(null);
  const [busy, setBusy] = useState(false);
  const [demandCreationOpen, setDemandCreationOpen] = useState(false);
  const [profilePauseReasonCode, setProfilePauseReasonCode] = useState<(typeof PROFILE_PAUSE_REASON_CODES)[number]>("OWNER_REQUEST");
  const [profileArchiveReasonCode, setProfileArchiveReasonCode] = useState<(typeof PROFILE_ARCHIVE_REASON_CODES)[number]>("OWNER_REQUEST");
  const [profileArchiveConfirmed, setProfileArchiveConfirmed] = useState(false);
  const [demandCancelReasonCode, setDemandCancelReasonCode] = useState<(typeof DEMAND_OWNER_CANCEL_REASON_CODES)[number]>("OWNER_WITHDREW");
  const [demandCancelConfirmed, setDemandCancelConfirmed] = useState(false);
  const [createReference, setCreateReference] = useState("");
  const [createExpiry, setCreateExpiry] = useState(defaultDemandExpiry);
  const [reasonCodes, setReasonCodes] = useState<string[]>(["CONTENT_INCOMPLETE"]);
  const [requiredPaths, setRequiredPaths] = useState<string[]>([]);
  const [reviewReleaseReasonCode, setReviewReleaseReasonCode] = useState<(typeof REVIEW_ASSIGNMENT_RELEASE_REASON_CODES)[number]>("WORKLOAD_RELEASE");
  const [budgetHealthCode, setBudgetHealthCode] = useState<(typeof VERIFY_BUDGET_HEALTH_CODES)[number]>("HEALTHY");
  const [riskCode, setRiskCode] = useState<(typeof VERIFY_RISK_CODES)[number]>("STANDARD");
  const [evidenceCodes, setEvidenceCodes] = useState<Array<(typeof VERIFY_EVIDENCE_CODES)[number]>>([]);
  const mainTitleRef = useRef<HTMLHeadingElement>(null);
  const resourceEditorTitleRef = useRef<HTMLHeadingElement>(null);
  const policyAcceptanceIntentRef = useRef<WriteIntent | null>(null);
  const resourceReadEpochRef = useRef(0);
  const workspaceObjectGenerationRef = useRef(0);
  const taskWorkspaceIdRef = useRef<string | null>(null);

  const prepareToLeaveSelectedEditor = useCallback(() => {
    if (conflict !== null) {
      setError({ code: "CONFLICT_RESOLUTION_REQUIRED", traceId: null });
      setNotice("请先应用逐分区合并结果，或明确放弃本次冲突编辑，再离开当前对象。");
      return false;
    }
    if (!dirty || !selected) return true;
    if (
      !selected.capabilities.includes("SAVE_DRAFT")
      || !persistEditorScratchToStorage(sessionStorage, selected, sections)
    ) {
      setError({ code: "SCRATCH_PERSIST_FAILED", traceId: null });
      setNotice("当前未提交编辑无法安全保存在此标签页；请先保存到服务端，再离开当前对象。");
      return false;
    }
    return true;
  }, [conflict, dirty, sections, selected]);

  const prepareToLeaveOrganizationAdmin = useCallback(() => {
    if (!organizationPublicNameDirty) return true;
    setError({ code: "UNSAVED_ORGANIZATION_PUBLIC_NAME", traceId: null });
    setNotice("请先在组织管理工作台更新或明确放弃公开名称草稿，再离开或重新发现工作区。");
    return false;
  }, [organizationPublicNameDirty]);

  const adoptResource = useCallback((resource: EditorResource, recoverScratch: boolean) => {
    setDemandCreationOpen(false);
    setSelectedAccount(null);
    setSelectedFinanceReview(null);
    setSelected(resource);
    setSections(sectionsFromContent(resource.resource_type, resource.current_version?.content ?? {}));
    setConflict(null);
    setDirty(false);
    setRecoveredScratchAt(null);
    setReasonCodes(["CONTENT_INCOMPLETE"]);
    setRequiredPaths([]);
    setReviewReleaseReasonCode("WORKLOAD_RELEASE");
    setBudgetHealthCode("HEALTHY");
    setRiskCode("STANDARD");
    setEvidenceCodes([]);
    setProfilePauseReasonCode("OWNER_REQUEST");
    setProfileArchiveReasonCode("OWNER_REQUEST");
    setProfileArchiveConfirmed(false);
    setDemandCancelReasonCode("OWNER_WITHDREW");
    setDemandCancelConfirmed(false);
    if (recoverScratch && resource.capabilities.includes("SAVE_DRAFT")) {
      const recovered = readScratch(resource);
      if (recovered) {
        setSections(recovered.sections);
        setDirty(true);
        setRecoveredScratchAt(recovered.savedAt);
      }
    }
  }, []);

  const clearWorkspaceObjects = useCallback(() => {
    workspaceObjectGenerationRef.current += 1;
    resourceReadEpochRef.current += 1;
    taskRefreshCoordinator.invalidate();
    taskWorkspaceIdRef.current = null;
    setAppealTaskTarget(null);
    setTrustCaseHistoryTaskTarget(null);
    setTaskDiscovery(null);
    setTaskError(null);
    setTaskBusy(false);
    setProfiles([]);
    setDemands([]);
    setReviewQueue([]);
    setFinanceFundingQueue([]);
    setConfiguration(null);
    setProfileScope(false);
    setDemandScope(false);
    setReviewQueueScope(false);
    setFinanceFundingScope(false);
    setAccounts([]);
    setAccountScope(false);
    setDemandCreationOpen(false);
    setCreateReference("");
    setCreateExpiry(defaultDemandExpiry());
    setSelectedAccount(null);
    setSelectedFinanceReview(null);
    setFinanceAttestationCodes([]);
    setFinanceReleaseReasonCode("WORKLOAD_RELEASE");
    setFinanceFindingDisposition("DISCREPANCY");
    setFinanceFindingReasonCodes([]);
    setFinanceFindingFieldCodes([]);
    setSelected(null);
    setSections({});
    setDirty(false);
    setOrganizationPublicNameDirty(false);
    setRecoveredScratchAt(null);
    setConflict(null);
    setReasonCodes(["CONTENT_INCOMPLETE"]);
    setRequiredPaths([]);
    setReviewReleaseReasonCode("WORKLOAD_RELEASE");
    setBudgetHealthCode("HEALTHY");
    setRiskCode("STANDARD");
    setEvidenceCodes([]);
    setProfilePauseReasonCode("OWNER_REQUEST");
    setProfileArchiveReasonCode("OWNER_REQUEST");
    setProfileArchiveConfirmed(false);
    setDemandCancelReasonCode("OWNER_WITHDREW");
    setDemandCancelConfirmed(false);
  }, [taskRefreshCoordinator]);

  const enterSignedOut = useCallback((message: string) => {
    clearAuthenticatedBrowserState();
    pendingRef.current = null;
    logoutIntentRef.current = null;
    policyAcceptanceIntentRef.current = null;
    setAppealHandoff(null);
    setPhase("SIGNED_OUT");
    setSession(null);
    setMe(null);
    setPolicyBundle(null);
    setAffirmedPolicyDocumentIds([]);
    setPolicyAcceptanceIntent(null);
    setWorkspaces([]);
    setSelectedWorkspace(null);
    setPendingOwner(null);
    setPending(null);
    setLogoutIntent(null);
    setInvitationContext(null);
    setBusy(false);
    setError(null);
    clearWorkspaceObjects();
    setNotice(message);
  }, [clearWorkspaceObjects]);

  const refreshReviewQueue = useCallback(async (workspaceId: string) => {
    try {
      const items = parseEditorReviewQueueEnvelope((await requestWorkspaceJson(
        workspaceId,
        ENDPOINTS.reviewQueue,
      )).value);
      setReviewQueue(items);
      setReviewQueueScope(true);
      return items;
    } catch (caught) {
      setReviewQueue([]);
      throw caught;
    }
  }, []);

  const refreshFinanceFundingQueue = useCallback(async (workspaceId: string) => {
    try {
      const items = parseFinanceFundingQueueEnvelope((await requestWorkspaceJson(
        workspaceId,
        ENDPOINTS.financeFundingReviews,
      )).value);
      setFinanceFundingQueue(items);
      setFinanceFundingScope(true);
      return items;
    } catch (caught) {
      setFinanceFundingQueue([]);
      throw caught;
    }
  }, []);

  const refreshCurrentAccountTasks = useCallback(async (workspaceId: string, announce: boolean) => {
    setTaskError(null);
    return taskRefreshCoordinator.run<CurrentAccountTaskDiscovery>({
      isValid: () => taskWorkspaceIdRef.current === workspaceId,
      load: async () => parseCurrentAccountTaskDiscovery((await requestWorkspaceJson(
        workspaceId,
        ENDPOINTS.tasks,
      )).value),
      validate: (snapshot) => {
        if (snapshot.schema_version !== "current-account-task-discovery-v1") {
          throw new TypeError("INVALID_TASK_DISCOVERY_RESPONSE");
        }
      },
      commit: setTaskDiscovery,
      onSuccess: (snapshot) => {
        setTaskError(null);
        if (announce) setNotice(`任务与历史已从当前账号投影刷新；共 ${snapshot.items.length} 项。`);
      },
      onError: (caught) => {
        const failure = caught instanceof ApiError
          ? caught
          : new ApiError(503, "INVALID_TASK_DISCOVERY_RESPONSE", null, null, null);
        setTaskError({ code: failure.code, traceId: failure.traceId });
      },
      setBusy: setTaskBusy,
    });
  }, [taskRefreshCoordinator]);

  const refreshReviewWorkspaceAfterAssignmentWrite = useCallback(async (workspaceId: string) => {
    const generation = workspaceObjectGenerationRef.current;
    taskRefreshCoordinator.invalidate();
    setTaskBusy(false);
    const demandCollection = requestWorkspaceJson(workspaceId, ENDPOINTS.demands)
      .then((response) => ({ available: true, items: parseEditorCollection(response.value) }))
      .catch((caught) => {
        if (caught instanceof ApiError && caught.status === 404) {
          return { available: false, items: [] as EditorResource[] };
        }
        throw caught;
      });
    const [demandResult, queueItems, taskSnapshot] = await Promise.all([
      demandCollection,
      requestWorkspaceJson(workspaceId, ENDPOINTS.reviewQueue)
        .then((response) => parseEditorReviewQueueEnvelope(response.value)),
      requestWorkspaceJson(workspaceId, ENDPOINTS.tasks)
        .then((response) => parseCurrentAccountTaskDiscovery(response.value)),
    ]);
    if (
      taskSnapshot.schema_version !== "current-account-task-discovery-v1"
      || workspaceObjectGenerationRef.current !== generation
      || taskWorkspaceIdRef.current !== workspaceId
    ) throw new TypeError("STALE_REVIEW_WORKSPACE_REFRESH");
    setDemands(demandResult.items);
    setDemandScope(demandResult.available);
    setReviewQueue(queueItems);
    setReviewQueueScope(true);
    setTaskDiscovery(taskSnapshot);
    setTaskError(null);
    return { demandResult, queueItems, taskSnapshot };
  }, [taskRefreshCoordinator]);

  const loadWorkspaceObjects = useCallback(async (
    workspace: WorkspaceCandidate,
    recoverBrowserState: boolean,
    refreshTasksAfterLoad = true,
  ) => {
    clearWorkspaceObjects();
    const loadGeneration = workspaceObjectGenerationRef.current;
    const needsConfiguration = workspace.role_codes.includes("CREATOR")
      || workspace.role_codes.includes("DEMAND_OWNER");
    const canReadAccounts = workspace.workspace_kind === "PLATFORM"
      && workspace.role_codes.includes("ACCESS_ADMIN");
    const canReviewDemands = workspace.workspace_kind === "PLATFORM"
      && workspace.role_codes.includes("OPERATIONS_REVIEWER");
    const canReviewFunding = workspace.workspace_kind === "PLATFORM"
      && workspace.role_codes.includes("FINANCE_OPERATOR");
    const readCollection = async (path: string) => {
      try {
        return {
          available: true,
          items: parseEditorCollection((await requestWorkspaceJson(workspace.workspace_id, path)).value),
        };
      } catch (caught) {
        if (caught instanceof ApiError && caught.status === 404) {
          return { available: false, items: [] as EditorResource[] };
        }
        throw caught;
      }
    };
    const [editorConfiguration, profileResult, demandResult, accountCollection, queueItems, financeItems] = await Promise.all([
      needsConfiguration
        ? requestWorkspaceJson(workspace.workspace_id, ENDPOINTS.configuration)
          .then((response) => parseEditorConfigurationEnvelope(response.value))
        : Promise.resolve(null),
      readCollection(ENDPOINTS.profiles),
      readCollection(ENDPOINTS.demands),
      canReadAccounts
        ? requestWorkspaceJson(workspace.workspace_id, ENDPOINTS.accounts)
          .then((response) => parseAccountAdminCollectionEnvelope(response.value))
        : Promise.resolve(null),
      canReviewDemands
        ? requestWorkspaceJson(workspace.workspace_id, ENDPOINTS.reviewQueue)
          .then((response) => parseEditorReviewQueueEnvelope(response.value))
        : Promise.resolve(null),
      canReviewFunding
        ? requestWorkspaceJson(workspace.workspace_id, ENDPOINTS.financeFundingReviews)
          .then((response) => parseFinanceFundingQueueEnvelope(response.value))
        : Promise.resolve(null),
    ]);
    if (workspaceObjectGenerationRef.current !== loadGeneration) return null;
    const first = profileResult.items[0] ?? demandResult.items[0] ?? null;
    const firstDetail = first
      ? parseEtaggedEditorResponse(await requestWorkspaceJson(
        workspace.workspace_id,
        resourcePath(first),
      ), { objectId: first.object_id })
      : null;
    if (workspaceObjectGenerationRef.current !== loadGeneration) return null;
    setConfiguration(editorConfiguration);
    setProfiles(profileResult.items);
    setDemands(demandResult.items);
    setReviewQueue(queueItems ?? []);
    setFinanceFundingQueue(financeItems ?? []);
    setProfileScope(profileResult.available);
    setDemandScope(demandResult.available);
    setReviewQueueScope(queueItems !== null);
    setFinanceFundingScope(financeItems !== null);
    setAccounts(accountCollection?.accounts ?? []);
    setAccountScope(accountCollection !== null);
    if (firstDetail) adoptResource(firstDetail, recoverBrowserState);
    if (recoverBrowserState) {
      let recoveredPending = parsePendingIntent(sessionStorage.getItem(PENDING_KEY) ?? "", Date.now());
      if (
        recoveredPending?.resource_type === "ACCOUNT_ADMIN"
        && (!accountCollection || !accountCollection.accounts.some((account) => account.user_id === recoveredPending?.object_id))
      ) recoveredPending = null;
      if (recoveredPending?.resource_type === "REVIEW_CLAIM" && !canReviewDemands) recoveredPending = null;
      if (recoveredPending?.resource_type === "FINANCE_FUNDING" && !canReviewFunding) recoveredPending = null;
      if (recoveredPending?.resource_type === "TRUST_REPORT" && !workspace.role_codes.includes("DEMAND_OWNER")) recoveredPending = null;
      if (
        (recoveredPending?.resource_type === "TRUST_CASE" || recoveredPending?.resource_type === "TRUST_HOLD")
        && !workspace.role_codes.includes("TRUST_OFFICER")
      ) recoveredPending = null;
      if (
        recoveredPending?.resource_type === "APPEAL"
        && !(workspace.workspace_kind === "ORGANIZATION" && workspace.role_codes.includes("DEMAND_OWNER"))
      ) recoveredPending = null;
      if (
        recoveredPending?.resource_type === "APPEAL_REVIEW"
        && !(workspace.workspace_kind === "PLATFORM" && workspace.role_codes.includes("APPEAL_REVIEWER"))
      ) recoveredPending = null;
      if (
        recoveredPending?.resource_type === "MATCHING_INVITATION"
        && !(workspace.workspace_kind === "PERSONAL" && workspace.role_codes.includes("CREATOR"))
      ) recoveredPending = null;
      if (
        recoveredPending?.resource_type === "MATCHING_SELECTION"
        && !(workspace.workspace_kind === "ORGANIZATION" && workspace.role_codes.includes("DEMAND_OWNER"))
      ) recoveredPending = null;
      pendingRef.current = recoveredPending;
      const recoveredTrust = recoveredPending?.resource_type === "TRUST_REPORT"
        || recoveredPending?.resource_type === "TRUST_CASE"
        || recoveredPending?.resource_type === "TRUST_HOLD";
      const recoveredAppeal = recoveredPending?.resource_type === "APPEAL"
        || recoveredPending?.resource_type === "APPEAL_REVIEW";
      const recoveredMatching = recoveredPending?.resource_type === "MATCHING_INVITATION"
        || recoveredPending?.resource_type === "MATCHING_SELECTION";
      setPendingOwner(recoveredPending ? recoveredTrust ? "TRUST" : recoveredAppeal ? "APPEAL" : recoveredMatching ? "MATCHING" : "PRODUCT" : null);
      if (recoveredPending && !recoveredTrust && !recoveredAppeal && !recoveredMatching) setPending(recoveredPending);
      else {
        setPending(null);
        if (!recoveredTrust && !recoveredAppeal && !recoveredMatching) {
          sessionStorage.removeItem(PENDING_KEY);
          sessionStorage.removeItem(MATCHING_SELECTION_RECOVERY_KEY);
        }
      }
    } else {
      if (pendingRef.current !== null) {
        throw new ApiError(409, "WRITE_OUTCOME_PENDING", null, null, null);
      }
      setPendingOwner(null);
      setPending(null);
      sessionStorage.removeItem(PENDING_KEY);
      sessionStorage.removeItem(MATCHING_SELECTION_RECOVERY_KEY);
    }
    taskWorkspaceIdRef.current = workspace.workspace_id;
    setPhase("SIGNED_IN");
    setNotice("所选工作区的对象、职责和版本号均已从服务端重新核对。");
    if (refreshTasksAfterLoad && pendingRef.current === null && logoutIntentRef.current === null) {
      void refreshCurrentAccountTasks(workspace.workspace_id, false);
    }
    return {
      demands: demandResult.items,
      financeFundingQueue: financeItems ?? [],
      generation: loadGeneration,
      profiles: profileResult.items,
    };
  }, [adoptResource, clearWorkspaceObjects, refreshCurrentAccountTasks]);

  const loadWorkspace = useCallback(async () => {
    setAppealHandoff(null);
    setPhase("LOADING");
    setError(null);
    setPolicyBundle(null);
    setAffirmedPolicyDocumentIds([]);
    policyAcceptanceIntentRef.current = null;
    setPolicyAcceptanceIntent(null);
    setSelectedWorkspace(null);
    setInvitationContext(null);
    setWorkspaces([]);
    clearWorkspaceObjects();
    try {
      const bootstrap = parseSessionBootstrap((await requestJson(ENDPOINTS.session)).value);
      setSession(bootstrap);
      const recoveredLogout = parseSessionLogoutIntent(
        sessionStorage.getItem(LOGOUT_PENDING_KEY) ?? "",
      );
      if (
        recoveredLogout
        && recoveredLogout.session_id === bootstrap.session.session_id
        && recoveredLogout.csrf_token === bootstrap.csrf_token
      ) {
        logoutIntentRef.current = recoveredLogout;
        setLogoutIntent(recoveredLogout);
      } else {
        sessionStorage.removeItem(LOGOUT_PENDING_KEY);
        logoutIntentRef.current = null;
        setLogoutIntent(null);
      }
      const identityResponse = await requestJson(ENDPOINTS.me);
      const identity = parseMe(identityResponse.value);
      setMe(identity);
      const recoveredInvitationContext = parsePendingInvitationContext(
        sessionStorage.getItem(PENDING_INVITATION_CONTEXT_KEY) ?? "",
        Date.now(),
      );
      if (recoveredInvitationContext) {
        setInvitationContext(recoveredInvitationContext);
        setPhase("INVITATION_ACCEPTANCE");
        setNotice("邀请摘要已从安全恢复对象读取；邀请能力本身未持久化。请核对完整政策后明确接受。");
        return;
      }
      sessionStorage.removeItem(PENDING_INVITATION_CONTEXT_KEY);
      sessionStorage.removeItem(PENDING_INVITATION_ACCEPTANCE_KEY);
      const unmetRequirement = identity.policy_requirements.find((requirement) => !requirement.satisfied);
      if (unmetRequirement) {
        const bundleId = unmetRequirement.required_policy_bundle_id;
        if (!bundleId) throw new TypeError("POLICY_CONFIGURATION_UNAVAILABLE");
        const bundleResponse = await requestJson(`${ENDPOINTS.policyBundles}/${encodeURIComponent(bundleId)}`);
        const bundle = await verifyPolicyBundleDocuments(parsePolicyBundle(bundleResponse.value));
        const documents = new Map(bundle.documents.map((document) => [document.document_id, document]));
        if (
          bundle.policy_bundle_id !== bundleId
          || bundle.purpose !== unmetRequirement.purpose
          || unmetRequirement.missing_document_ids.some((documentId) => {
            const document = documents.get(documentId);
            return !document || document.legal_effect === "CONSENT_TEXT" || document.locale !== bundle.locale;
          })
        ) throw new TypeError("POLICY_BUNDLE_BINDING_INVALID");
        if (bundleResponse.etag !== null && bundleResponse.etag !== bundle.entity_tag) {
          throw new TypeError("POLICY_BUNDLE_ETAG_MISMATCH");
        }
        setPolicyBundle(bundle);
        setPhase("POLICY_ACCEPTANCE");
        setNotice("该账号仍有未满足的服务端政策要求；完成明确确认前不会发现或读取任何业务工作区。");
        return;
      }
      const discoveryResponse = await requestJson(ENDPOINTS.workspaces);
      const discovery = parseWorkspaceDiscovery(discoveryResponse.value);
      setWorkspaces(discovery.workspaces);
      const rememberedId = sessionStorage.getItem(WORKSPACE_KEY);
      const workspace = selectWorkspaceCandidate(discovery, rememberedId);
      if (!workspace) {
        sessionStorage.removeItem(WORKSPACE_KEY);
        sessionStorage.removeItem(PENDING_KEY);
        sessionStorage.removeItem(MATCHING_SELECTION_RECOVERY_KEY);
        pendingRef.current = null;
        setPendingOwner(null);
        setPending(null);
        setPhase("WORKSPACE_SELECTION");
        setNotice(discovery.selection_required
          ? "此账号有多个有效职责范围；选择后才会读取任何业务对象。"
          : "此账号目前没有可用的内部试运行工作区。");
        return;
      }
      sessionStorage.setItem(WORKSPACE_KEY, workspace.workspace_id);
      setSelectedWorkspace(workspace);
      await loadWorkspaceObjects(workspace, rememberedId === workspace.workspace_id);
    } catch (caught) {
      if (caught instanceof ApiError && caught.status === 401) {
        enterSignedOut("这是受邀账号工作台；请通过配置的身份提供方登录。");
        return;
      }
      const failure = caught instanceof ApiError ? caught : new ApiError(503, "INVALID_PLATFORM_RESPONSE", null, null, null);
      setPhase("UNAVAILABLE");
      setError({ code: failure.code, traceId: failure.traceId });
      setNotice("无法建立可信工作区，页面不会使用浏览器假数据代替服务端事实。");
    }
  }, [clearWorkspaceObjects, enterSignedOut, loadWorkspaceObjects]);

  const activePolicyRequirement = me?.policy_requirements.find((requirement) => !requirement.satisfied) ?? null;

  const claimOrganizationWrite = useCallback((record: PendingOrganizationAdminWrite) => {
    const encoded = serializePendingOrganizationAdminWrite(record);
    const existing = pendingRef.current;
    if (existing === null) {
      pendingRef.current = { resource_type: "ORG_ADMIN", encoded };
      setPendingOwner("ORGANIZATION");
      return true;
    }
    return existing.resource_type === "ORG_ADMIN" && existing.encoded === encoded;
  }, []);

  const releaseOrganizationWrite = useCallback(() => {
    if (pendingRef.current?.resource_type === "ORG_ADMIN") {
      pendingRef.current = null;
      setPendingOwner(null);
    }
  }, []);

  const claimSessionWrite = useCallback((writeKey: string) => {
    if (!LOGOUT_IDEMPOTENCY_KEY.test(writeKey)) return false;
    const existing = pendingRef.current;
    if (existing === null) {
      pendingRef.current = { resource_type: "SESSION_REVOKE", write_key: writeKey };
      setPendingOwner("SESSION");
      return true;
    }
    return existing.resource_type === "SESSION_REVOKE" && existing.write_key === writeKey;
  }, []);

  const releaseSessionWrite = useCallback((writeKey: string) => {
    const existing = pendingRef.current;
    if (existing?.resource_type === "SESSION_REVOKE" && existing.write_key === writeKey) {
      pendingRef.current = null;
      setPendingOwner(null);
      setBusy(false);
    }
  }, []);

  const setSessionWriteBusy = useCallback((writeKey: string, value: boolean) => {
    const existing = pendingRef.current;
    if (existing?.resource_type === "SESSION_REVOKE" && existing.write_key === writeKey) {
      setBusy(value);
    }
  }, []);

  const claimTrustWrite = useCallback((record: PendingIntent) => {
    const isTrust = record.resource_type === "TRUST_REPORT"
      || record.resource_type === "TRUST_CASE"
      || record.resource_type === "TRUST_HOLD";
    if (!isTrust) return false;
    const existing = pendingRef.current;
    if (existing === null) {
      pendingRef.current = record;
      setPendingOwner("TRUST");
      return true;
    }
    return existing.resource_type !== "ORG_ADMIN"
      && (existing.resource_type === "TRUST_REPORT" || existing.resource_type === "TRUST_CASE" || existing.resource_type === "TRUST_HOLD")
      && serializePendingIntent(existing) === serializePendingIntent(record);
  }, []);

  const releaseTrustWrite = useCallback((record: PendingIntent) => {
    const existing = pendingRef.current;
    if (
      existing?.resource_type !== "ORG_ADMIN"
      && (existing?.resource_type === "TRUST_REPORT" || existing?.resource_type === "TRUST_CASE" || existing?.resource_type === "TRUST_HOLD")
      && serializePendingIntent(existing) === serializePendingIntent(record)
    ) {
      pendingRef.current = null;
      setPendingOwner(null);
    }
  }, []);

  const claimAppealWrite = useCallback((record: PendingIntent) => {
    const isAppeal = record.resource_type === "APPEAL" || record.resource_type === "APPEAL_REVIEW";
    if (!isAppeal) return false;
    const existing = pendingRef.current;
    if (existing === null) {
      pendingRef.current = record;
      setPendingOwner("APPEAL");
      return true;
    }
    return existing.resource_type !== "ORG_ADMIN"
      && (existing.resource_type === "APPEAL" || existing.resource_type === "APPEAL_REVIEW")
      && JSON.stringify(existing) === JSON.stringify(record);
  }, []);

  const releaseAppealWrite = useCallback((record: PendingIntent) => {
    const existing = pendingRef.current;
    if (
      existing?.resource_type !== "ORG_ADMIN"
      && (existing?.resource_type === "APPEAL" || existing?.resource_type === "APPEAL_REVIEW")
      && JSON.stringify(existing) === JSON.stringify(record)
    ) {
      pendingRef.current = null;
      setPendingOwner(null);
    }
  }, []);

  const claimMatchingWrite = useCallback((record: PendingIntent) => {
    const isMatching = record.resource_type === "MATCHING_INVITATION"
      || record.resource_type === "MATCHING_SELECTION"
      || record.resource_type === "MATCHING_ASSIGNMENT"
      || record.resource_type === "MATCHING_REVIEW";
    if (!isMatching) return false;
    const existing = pendingRef.current;
    if (existing === null) {
      pendingRef.current = record;
      setPendingOwner("MATCHING");
      return true;
    }
    return existing.resource_type !== "ORG_ADMIN"
      && (existing.resource_type === "MATCHING_INVITATION" || existing.resource_type === "MATCHING_SELECTION"
        || existing.resource_type === "MATCHING_ASSIGNMENT" || existing.resource_type === "MATCHING_REVIEW")
      && serializePendingIntent(existing) === serializePendingIntent(record);
  }, []);

  const releaseMatchingWrite = useCallback((record: PendingIntent) => {
    const existing = pendingRef.current;
    if (
      existing?.resource_type !== "ORG_ADMIN"
      && (existing?.resource_type === "MATCHING_INVITATION" || existing?.resource_type === "MATCHING_SELECTION"
        || existing?.resource_type === "MATCHING_ASSIGNMENT" || existing?.resource_type === "MATCHING_REVIEW")
      && serializePendingIntent(existing) === serializePendingIntent(record)
    ) {
      pendingRef.current = null;
      setPendingOwner(null);
    }
  }, []);

  async function acceptCurrentPolicy(event: FormEvent) {
    event.preventDefault();
    if (!session || !me || !activePolicyRequirement || !policyBundle) {
      setError({ code: "POLICY_ACCEPTANCE_UNAVAILABLE", traceId: null });
      return;
    }
    let intent = policyAcceptanceIntentRef.current;
    try {
      intent ??= createPolicyAcceptanceIntent({
        me,
        requirement: activePolicyRequirement,
        bundle: policyBundle,
        affirmedDocumentIds: affirmedPolicyDocumentIds,
        csrfToken: session.csrf_token,
        idempotencyKey: newIdempotencyKey(),
      });
    } catch (caught) {
      setError({ code: caught instanceof Error ? caught.message : "POLICY_AFFIRMATION_REQUIRED", traceId: null });
      return;
    }
    policyAcceptanceIntentRef.current = intent;
    setPolicyAcceptanceIntent(intent);
    setBusy(true);
    setError(null);
    setNotice("正在提交明确政策确认；在服务端结果明确前不会生成新的幂等请求。");
    try {
      const result = await requestJson(ENDPOINTS.policyAcceptances, {
        method: intent.method,
        headers: intent.headers,
        body: JSON.stringify(intent.body),
      });
      parsePolicyRequirementStatus(result.value, activePolicyRequirement);
      if (result.etag === null || !/^"v[1-9][0-9]*"$/.test(result.etag)) {
        throw new TypeError("INVALID_POLICY_ACCEPTANCE_RESPONSE");
      }
      policyAcceptanceIntentRef.current = null;
      setPolicyAcceptanceIntent(null);
      setNotice("政策确认已由服务端记录；正在重新读取账号要求和工作区权限。");
      await loadWorkspace();
    } catch (caught) {
      const failure = caught instanceof ApiError
        ? caught
        : new ApiError(503, caught instanceof Error ? caught.message : "INVALID_POLICY_ACCEPTANCE_RESPONSE", null, null, null);
      const outcomeUnknown = failure.status === 0 || failure.status >= 500;
      if (!outcomeUnknown) {
        policyAcceptanceIntentRef.current = null;
        setPolicyAcceptanceIntent(null);
      }
      setError({ code: failure.code, traceId: failure.traceId });
      setNotice(outcomeUnknown
        ? "政策接受结果未知；已保留完全相同的请求，下一次提交会原样复用同一幂等键。"
        : "服务端明确拒绝了政策接受请求；请重新读取当前政策要求后再确认。");
    } finally {
      setBusy(false);
    }
  }

  const switchWorkspace = useCallback(async (workspaceId: string) => {
    if (pendingRef.current) {
      setError({ code: "WRITE_OUTCOME_PENDING", traceId: null });
      setNotice("存在一笔在途写入；明确重试或放弃前不能切换工作区。");
      return;
    }
    const workspace = workspaces.find((candidate) => candidate.workspace_id === workspaceId);
    if (!workspace) {
      setError({ code: "WORKSPACE_NOT_DISCOVERED", traceId: null });
      return;
    }
    if (!prepareToLeaveOrganizationAdmin() || !prepareToLeaveSelectedEditor()) return;
    setAppealHandoff(null);
    setBusy(true);
    setError(null);
    setPhase("LOADING");
    setSelectedWorkspace(null);
    clearWorkspaceObjects();
    pendingRef.current = null;
    setPendingOwner(null);
    setPending(null);
    sessionStorage.removeItem(PENDING_KEY);
    sessionStorage.removeItem(MATCHING_SELECTION_RECOVERY_KEY);
    sessionStorage.setItem(WORKSPACE_KEY, workspace.workspace_id);
    try {
      setSelectedWorkspace(workspace);
      await loadWorkspaceObjects(workspace, false);
    } catch (caught) {
      const failure = caught instanceof ApiError ? caught : new ApiError(503, "INVALID_PLATFORM_RESPONSE", null, null, null);
      setSelectedWorkspace(null);
      setPhase("UNAVAILABLE");
      setError({ code: failure.code, traceId: failure.traceId });
      setNotice("切换后的工作区未能通过服务端核对；旧工作区对象已经清空。");
    } finally {
      setBusy(false);
    }
  }, [clearWorkspaceObjects, loadWorkspaceObjects, prepareToLeaveOrganizationAdmin, prepareToLeaveSelectedEditor, workspaces]);

  useEffect(() => {
    const timer = window.setTimeout(() => void loadWorkspace(), 0);
    return () => window.clearTimeout(timer);
  }, [loadWorkspace]);

  useEffect(() => {
    if (phase !== "LOADING") requestAnimationFrame(() => mainTitleRef.current?.focus());
  }, [phase]);

  useEffect(() => {
    if (!dirty || !selected || !selected.capabilities.includes("SAVE_DRAFT")) return;
    persistEditorScratchToStorage(sessionStorage, selected, sections);
  }, [dirty, sections, selected]);

  function refreshWorkspaceSafely() {
    if (busy || pendingRef.current !== null || logoutIntentRef.current !== null) {
      setError({ code: "WRITE_OUTCOME_PENDING", traceId: null });
      setNotice("存在一笔结果尚未明确的会话或业务写入；完成原样重试或明确放弃前不会重新发现工作区。");
      return;
    }
    if (!prepareToLeaveOrganizationAdmin() || !prepareToLeaveSelectedEditor()) return;
    void loadWorkspace();
  }

  function refreshTasksSafely() {
    if (
      !selectedWorkspace
      || busy
      || taskBusy
      || pendingRef.current !== null
      || logoutIntentRef.current !== null
    ) return;
    void refreshCurrentAccountTasks(selectedWorkspace.workspace_id, true);
  }

  async function openRevalidatedTrustCaseHistoryTask(task: CurrentAccountTask) {
    const workspace = selectedWorkspace;
    const sessionId = session?.session.session_id ?? null;
    if (
      !workspace
      || !sessionId
      || !isTrustCaseHistoryTask(task)
      || taskWorkspaceIdRef.current !== workspace.workspace_id
    ) {
      setTaskError({ code: "TASK_DESTINATION_WORKSPACE_STALE", traceId: null });
      setNotice("Trust 历史任务所属会话或工作区已经变化；请先刷新权限与对象，再从新的任务投影进入。");
      return;
    }
    if (!prepareToLeaveSelectedEditor()) return;
    let ownedGeneration = workspaceObjectGenerationRef.current;
    setTrustCaseHistoryTaskTarget(null);
    setBusy(true);
    setTaskError(null);
    setNotice("正在重新确认当前会话、工作区、TRUST_OFFICER 职责、任务类型与 exact Case ID；不会使用任务路径读取案件。");
    try {
      const [refreshedSession, workspaceDiscovery] = await Promise.all([
        requestJson(ENDPOINTS.session).then((response) => parseSessionBootstrap(response.value)),
        requestJson(ENDPOINTS.workspaces).then((response) => parseWorkspaceDiscovery(response.value)),
      ]);
      if (
        workspaceObjectGenerationRef.current !== ownedGeneration
        || taskWorkspaceIdRef.current !== workspace.workspace_id
        || pendingRef.current !== null
        || logoutIntentRef.current !== null
      ) return;
      if (refreshedSession.session.session_id !== sessionId) {
        setTaskError({ code: "TASK_DESTINATION_SESSION_STALE", traceId: null });
        setNotice("服务端返回的当前会话已变化；页面没有继续定位 Trust 历史。请刷新权限与对象后，从新会话的任务投影进入。");
        return;
      }
      setSession(refreshedSession);
      setWorkspaces(workspaceDiscovery.workspaces);
      const refreshedWorkspace = workspaceDiscovery.workspaces.find(
        (candidate) => candidate.workspace_id === workspace.workspace_id,
      );
      if (!refreshedWorkspace) {
        sessionStorage.removeItem(WORKSPACE_KEY);
        setSelectedWorkspace(null);
        clearWorkspaceObjects();
        ownedGeneration = workspaceObjectGenerationRef.current;
        setPhase("WORKSPACE_SELECTION");
        setNotice("服务端已不再返回原工作区；旧对象和 Trust 历史任务已清空。请选择仍获授权的工作区，或联系 ACCESS_ADMIN 核对职责。");
        return;
      }
      setSelectedWorkspace(refreshedWorkspace);
      sessionStorage.setItem(WORKSPACE_KEY, refreshedWorkspace.workspace_id);
      const expectedLoadGeneration = workspaceObjectGenerationRef.current + 1;
      ownedGeneration = expectedLoadGeneration;
      const snapshot = await loadWorkspaceObjects(refreshedWorkspace, false, false);
      if (!snapshot || snapshot.generation !== expectedLoadGeneration) return;
      if (
        refreshedWorkspace.workspace_kind !== "PLATFORM"
        || !refreshedWorkspace.role_codes.includes("TRUST_OFFICER")
      ) {
        setTaskError({ code: "TASK_DESTINATION_NO_LONGER_AVAILABLE", traceId: null });
        setNotice("当前工作区仍存在，但已不再包含 TRUST_OFFICER 职责；页面没有定位历史或使用任务路径读取详情。");
        return;
      }
      const taskResult = await refreshCurrentAccountTasks(refreshedWorkspace.workspace_id, false);
      if (!taskResult.ok) {
        if ("stale" in taskResult) return;
        setNotice("工作区已重读，但任务投影未能完成重核对；没有定位 Trust 历史。请使用顶部“刷新权限与对象”后重试。");
        return;
      }
      if (
        workspaceObjectGenerationRef.current !== snapshot.generation
        || taskWorkspaceIdRef.current !== refreshedWorkspace.workspace_id
        || pendingRef.current !== null
        || logoutIntentRef.current !== null
      ) return;
      const refreshedTask = resolveRevalidatedCurrentAccountTask(task, taskResult.snapshot);
      if (!refreshedTask || !isTrustCaseHistoryTask(refreshedTask)) {
        setTaskError({ code: "TASK_DESTINATION_NO_LONGER_AVAILABLE", traceId: null });
        setNotice("已重读当前工作区与任务；原 Trust Case、终态或动作已经变化。请从刷新后的任务继续。");
        return;
      }
      setTrustCaseHistoryTaskTarget({
        case_id: refreshedTask.resource_id,
        request_id: crypto.randomUUID(),
        session_id: sessionId,
        workspace_id: refreshedWorkspace.workspace_id,
      });
      setTaskError(null);
      setNotice("当前会话、工作区和 exact Trust 历史任务已重新确认；工作台将定位本人只读终态记录，不会执行写入。");
    } catch (caught) {
      if (workspaceObjectGenerationRef.current !== ownedGeneration) return;
      const failure = caught instanceof ApiError
        ? caught
        : new ApiError(503, "TASK_DESTINATION_RECHECK_FAILED", null, null, null);
      setTaskError({ code: failure.code, traceId: failure.traceId });
      setNotice("Trust 历史任务重核对失败；页面没有猜测权限、使用任务路径或发送写入。请刷新权限与对象后重试。");
    } finally {
      if (workspaceObjectGenerationRef.current === ownedGeneration) setBusy(false);
    }
  }

  async function openRevalidatedAppealCurrentAccountTask(task: CurrentAccountTask) {
    const workspace = selectedWorkspace;
    const sessionId = session?.session.session_id ?? null;
    const readKind = appealTaskReadKind(task);
    if (
      !workspace
      || !sessionId
      || !readKind
      || taskWorkspaceIdRef.current !== workspace.workspace_id
    ) {
      setTaskError({ code: "TASK_DESTINATION_WORKSPACE_STALE", traceId: null });
      setNotice("Appeal 任务所属会话或工作区已经变化；请先刷新权限与对象，再从新的任务投影进入。");
      return;
    }
    if (!prepareToLeaveSelectedEditor()) return;
    let ownedGeneration = workspaceObjectGenerationRef.current;
    setAppealTaskTarget(null);
    setBusy(true);
    setTaskError(null);
    setNotice("正在重新确认当前会话、工作区、职责、任务类型、Appeal ID 与动作；不会读取任务路径，也不会自动执行写入。");
    try {
      const [refreshedSession, workspaceDiscovery] = await Promise.all([
        requestJson(ENDPOINTS.session).then((response) => parseSessionBootstrap(response.value)),
        requestJson(ENDPOINTS.workspaces).then((response) => parseWorkspaceDiscovery(response.value)),
      ]);
      if (
        workspaceObjectGenerationRef.current !== ownedGeneration
        || taskWorkspaceIdRef.current !== workspace.workspace_id
        || pendingRef.current !== null
        || logoutIntentRef.current !== null
      ) return;
      if (refreshedSession.session.session_id !== sessionId) {
        setTaskError({ code: "TASK_DESTINATION_SESSION_STALE", traceId: null });
        setNotice("服务端返回的当前会话已变化；页面没有继续定位 Appeal。请从新会话的 fresh 任务投影重新进入。");
        return;
      }
      setSession(refreshedSession);
      setWorkspaces(workspaceDiscovery.workspaces);
      const refreshedWorkspace = workspaceDiscovery.workspaces.find(
        (candidate) => candidate.workspace_id === workspace.workspace_id,
      );
      if (!refreshedWorkspace) {
        sessionStorage.removeItem(WORKSPACE_KEY);
        setSelectedWorkspace(null);
        clearWorkspaceObjects();
        ownedGeneration = workspaceObjectGenerationRef.current;
        setPhase("WORKSPACE_SELECTION");
        setNotice("服务端已不再返回原工作区；旧对象和 Appeal 任务已清空。请选择仍获授权的工作区，或联系 ACCESS_ADMIN 核对职责。");
        return;
      }
      setSelectedWorkspace(refreshedWorkspace);
      sessionStorage.setItem(WORKSPACE_KEY, refreshedWorkspace.workspace_id);
      const expectedLoadGeneration = workspaceObjectGenerationRef.current + 1;
      ownedGeneration = expectedLoadGeneration;
      const snapshot = await loadWorkspaceObjects(refreshedWorkspace, false, false);
      if (!snapshot || snapshot.generation !== expectedLoadGeneration) return;
      const roleStillAllowsRead = readKind === "OWN"
        ? refreshedWorkspace.workspace_kind === "ORGANIZATION"
          && refreshedWorkspace.role_codes.includes("DEMAND_OWNER")
        : refreshedWorkspace.workspace_kind === "PLATFORM"
          && refreshedWorkspace.role_codes.includes("APPEAL_REVIEWER");
      if (!roleStillAllowsRead) {
        setTaskError({ code: "TASK_DESTINATION_NO_LONGER_AVAILABLE", traceId: null });
        setNotice("当前工作区仍存在，但已不再包含处理此 Appeal 的职责；旧工作区对象已清空，页面没有读取详情或发送写入。");
        return;
      }
      const taskResult = await refreshCurrentAccountTasks(refreshedWorkspace.workspace_id, false);
      if (!taskResult.ok) {
        if ("stale" in taskResult) return;
        setNotice("工作区已重读，但任务投影未能完成重核对；没有读取 Appeal。请使用顶部“刷新权限与对象”后重试。");
        return;
      }
      if (
        workspaceObjectGenerationRef.current !== snapshot.generation
        || taskWorkspaceIdRef.current !== refreshedWorkspace.workspace_id
        || pendingRef.current !== null
        || logoutIntentRef.current !== null
      ) return;
      const refreshedTask = resolveRevalidatedCurrentAccountTask(task, taskResult.snapshot);
      const refreshedReadKind = refreshedTask ? appealTaskReadKind(refreshedTask) : null;
      if (!refreshedTask || refreshedReadKind !== readKind) {
        setTaskError({ code: "TASK_DESTINATION_NO_LONGER_AVAILABLE", traceId: null });
        setNotice("已重读当前工作区与任务；原 Appeal 类型、ID 或动作已经变化。请从刷新后的任务继续。");
        return;
      }
      setAppealHandoff(null);
      setAppealTaskTarget({
        appeal_id: refreshedTask.resource_id,
        next_action: refreshedTask.next_action as AppealTaskTarget["next_action"],
        read_kind: refreshedReadKind,
        request_id: crypto.randomUUID(),
        session_id: sessionId,
        workspace_id: refreshedWorkspace.workspace_id,
      });
      setTaskError(null);
      setNotice("当前会话、工作区、职责和 exact Appeal 任务已重新确认；工作台将执行 fresh 安全读取，不会使用任务路径，也不会自动保存、提交、领取或决定。");
    } catch (caught) {
      if (workspaceObjectGenerationRef.current !== ownedGeneration) return;
      const failure = caught instanceof ApiError
        ? caught
        : new ApiError(503, "TASK_DESTINATION_RECHECK_FAILED", null, null, null);
      setTaskError({ code: failure.code, traceId: failure.traceId });
      setNotice("Appeal 任务重核对失败；页面没有猜测权限、使用任务路径或发送写入。请刷新权限与对象后重试。");
    } finally {
      if (workspaceObjectGenerationRef.current === ownedGeneration) setBusy(false);
    }
  }

  async function openRevalidatedFinanceCurrentAccountTask(task: CurrentAccountTask) {
    const workspace = selectedWorkspace;
    const sessionId = session?.session.session_id ?? null;
    const detailAction = resolveFinanceTaskDetailAction(task);
    if (
      !workspace
      || !sessionId
      || !detailAction
      || workspace.workspace_kind !== "PLATFORM"
      || !workspace.role_codes.includes("FINANCE_OPERATOR")
      || taskWorkspaceIdRef.current !== workspace.workspace_id
    ) {
      setTaskError({ code: "TASK_DESTINATION_WORKSPACE_STALE", traceId: null });
      setNotice("Finance 任务所属会话、工作区或职责已经变化；请先刷新权限与对象，再从新的任务投影进入。");
      return;
    }
    if (!prepareToLeaveSelectedEditor()) return;
    let ownedGeneration = workspaceObjectGenerationRef.current;
    setSelectedFinanceReview(null);
    setBusy(true);
    setError(null);
    setTaskError(null);
    setNotice("正在重新确认当前会话、PLATFORM 工作区、FINANCE_OPERATOR 职责、exact 资金审查任务与本人 fresh 分配；不会使用任务路径，也不会自动领取、确认或写入。");
    try {
      const [refreshedSession, workspaceDiscovery] = await Promise.all([
        requestJson(ENDPOINTS.session).then((response) => parseSessionBootstrap(response.value)),
        requestJson(ENDPOINTS.workspaces).then((response) => parseWorkspaceDiscovery(response.value)),
      ]);
      if (
        workspaceObjectGenerationRef.current !== ownedGeneration
        || taskWorkspaceIdRef.current !== workspace.workspace_id
        || pendingRef.current !== null
        || logoutIntentRef.current !== null
      ) return;
      if (refreshedSession.session.session_id !== sessionId) {
        setTaskError({ code: "TASK_DESTINATION_SESSION_STALE", traceId: null });
        setNotice("服务端返回的当前会话已变化；页面没有读取资金审查详情。请从新会话的 fresh 任务投影重新进入。");
        return;
      }
      setSession(refreshedSession);
      setWorkspaces(workspaceDiscovery.workspaces);
      const refreshedWorkspace = workspaceDiscovery.workspaces.find(
        (candidate) => candidate.workspace_id === workspace.workspace_id,
      );
      if (!refreshedWorkspace) {
        sessionStorage.removeItem(WORKSPACE_KEY);
        setSelectedWorkspace(null);
        clearWorkspaceObjects();
        ownedGeneration = workspaceObjectGenerationRef.current;
        setPhase("WORKSPACE_SELECTION");
        setNotice("服务端已不再返回原 Finance 工作区；旧对象和任务已清空。请选择仍获授权的工作区，或联系 ACCESS_ADMIN 核对职责。");
        return;
      }
      setSelectedWorkspace(refreshedWorkspace);
      sessionStorage.setItem(WORKSPACE_KEY, refreshedWorkspace.workspace_id);
      const expectedLoadGeneration = workspaceObjectGenerationRef.current + 1;
      ownedGeneration = expectedLoadGeneration;
      const snapshot = await loadWorkspaceObjects(refreshedWorkspace, false, false);
      if (!snapshot || snapshot.generation !== expectedLoadGeneration) return;
      if (
        refreshedWorkspace.workspace_kind !== "PLATFORM"
        || !refreshedWorkspace.role_codes.includes("FINANCE_OPERATOR")
      ) {
        setTaskError({ code: "TASK_DESTINATION_NO_LONGER_AVAILABLE", traceId: null });
        setNotice("当前工作区仍存在，但已不再是 PLATFORM + FINANCE_OPERATOR；旧 Finance 对象已清空，页面没有读取详情或发送写入。");
        return;
      }
      const taskResult = await refreshCurrentAccountTasks(refreshedWorkspace.workspace_id, false);
      if (!taskResult.ok) {
        if ("stale" in taskResult) return;
        setNotice("Finance 工作区已重读，但任务投影未能完成重核对；没有读取资金审查详情。请使用顶部“刷新权限与对象”后重试。");
        return;
      }
      if (
        workspaceObjectGenerationRef.current !== snapshot.generation
        || taskWorkspaceIdRef.current !== refreshedWorkspace.workspace_id
        || pendingRef.current !== null
        || logoutIntentRef.current !== null
      ) return;
      const revalidated = resolveRevalidatedFinanceTaskQueueItem(
        task,
        taskResult.snapshot,
        snapshot.financeFundingQueue,
      );
      if (!revalidated || revalidated.action !== detailAction) {
        setTaskError({ code: "TASK_FINANCE_ASSIGNMENT_NO_LONGER_AVAILABLE", traceId: null });
        setNotice("已重读 fresh 任务与资金队列，但原 exact 资金审查动作或本人分配已经变化；页面没有猜测 ID、读取详情或自动领取。");
        return;
      }
      const response = await requestWorkspaceJson(
        refreshedWorkspace.workspace_id,
        `${ENDPOINTS.financeFundingReviews}/${revalidated.task.resource_id}`,
      );
      const review = parseFinanceFundingReviewEnvelope(response.value);
      if (
        workspaceObjectGenerationRef.current !== snapshot.generation
        || taskWorkspaceIdRef.current !== refreshedWorkspace.workspace_id
        || pendingRef.current !== null
        || logoutIntentRef.current !== null
      ) return;
      const exactReview = resolveFinanceTaskDetail(
        revalidated.task,
        revalidated.queue_item,
        review,
        response.etag,
      );
      if (!exactReview) {
        setSelectedFinanceReview(null);
        setTaskError({ code: "TASK_FINANCE_DETAIL_DRIFTED", traceId: null });
        setNotice("资金审查详情与 fresh 任务/本人队列在 ID、Demand、版本、状态、ETag 或可用动作上不一致；页面已失败关闭且没有发送写入。");
        return;
      }
      setSelected(null);
      setSelectedAccount(null);
      setSelectedFinanceReview(exactReview);
      setFinanceAttestationCodes([]);
      setFinanceReleaseReasonCode("WORKLOAD_RELEASE");
      setFinanceFindingDisposition("DISCREPANCY");
      setFinanceFindingReasonCodes([]);
      setFinanceFindingFieldCodes([]);
      setTaskError(null);
      setNotice("当前会话、PLATFORM + FINANCE_OPERATOR、exact 任务、本人 fresh 分配与资金审查详情已重新确认；页面只打开详情，不会自动领取、确认或写入。");
      requestAnimationFrame(() => {
        const destination = document.getElementById("finance-funding-title");
        if (destination?.dataset.fundingReviewId !== exactReview.funding_review_id) return;
        destination.focus({ preventScroll: true });
        destination.scrollIntoView({ block: "start", behavior: "auto" });
      });
    } catch (caught) {
      if (workspaceObjectGenerationRef.current !== ownedGeneration) return;
      const failure = caught instanceof ApiError
        ? caught
        : new ApiError(503, "TASK_FINANCE_DETAIL_RECHECK_FAILED", null, null, null);
      setSelectedFinanceReview(null);
      setTaskError({ code: failure.code, traceId: failure.traceId });
      setNotice("Finance exact task handoff 重核对失败；页面没有使用任务路径、猜测分配或发送写入。请刷新权限与对象后重试。");
    } finally {
      if (workspaceObjectGenerationRef.current === ownedGeneration) setBusy(false);
    }
  }

  async function recoverMissingCurrentAccountTaskResource(task: CurrentAccountTask) {
    const workspace = selectedWorkspace;
    if (!workspace || taskWorkspaceIdRef.current !== workspace.workspace_id) {
      setTaskError({ code: "TASK_DESTINATION_WORKSPACE_STALE", traceId: null });
      setNotice("任务所属工作区已经变化；请先使用顶部“刷新权限与对象”，再从新的任务投影进入。");
      return;
    }
    if (!prepareToLeaveSelectedEditor()) return;
    let ownedGeneration = workspaceObjectGenerationRef.current;
    setBusy(true);
    setTaskError(null);
    setNotice("任务对象不在当前快照中；正在重读服务端权限、对象清单与任务投影，不会使用任务路径直接读取对象。");
    try {
      const workspaceDiscovery = parseWorkspaceDiscovery(
        (await requestJson(ENDPOINTS.workspaces)).value,
      );
      if (
        workspaceObjectGenerationRef.current !== ownedGeneration
        || taskWorkspaceIdRef.current !== workspace.workspace_id
        || pendingRef.current !== null
        || logoutIntentRef.current !== null
      ) return;
      setWorkspaces(workspaceDiscovery.workspaces);
      const refreshedWorkspace = workspaceDiscovery.workspaces.find(
        (candidate) => candidate.workspace_id === workspace.workspace_id,
      );
      if (!refreshedWorkspace) {
        sessionStorage.removeItem(WORKSPACE_KEY);
        setSelectedWorkspace(null);
        clearWorkspaceObjects();
        ownedGeneration = workspaceObjectGenerationRef.current;
        setPhase("WORKSPACE_SELECTION");
        setNotice("服务端已不再返回原工作区；旧对象和任务已清空。请选择仍获授权的工作区，或联系 ACCESS_ADMIN 核对职责。");
        return;
      }
      setSelectedWorkspace(refreshedWorkspace);
      sessionStorage.setItem(WORKSPACE_KEY, refreshedWorkspace.workspace_id);
      const expectedLoadGeneration = workspaceObjectGenerationRef.current + 1;
      ownedGeneration = expectedLoadGeneration;
      const snapshot = await loadWorkspaceObjects(refreshedWorkspace, false, false);
      if (!snapshot || snapshot.generation !== expectedLoadGeneration) return;
      const taskResult = await refreshCurrentAccountTasks(refreshedWorkspace.workspace_id, false);
      if (!taskResult.ok) {
        if ("stale" in taskResult) return;
        setNotice("对象清单已重读，但任务投影未能完成重核对；没有打开任何对象。请使用顶部“刷新权限与对象”后重试。");
        return;
      }
      if (
        workspaceObjectGenerationRef.current !== snapshot.generation
        || taskWorkspaceIdRef.current !== refreshedWorkspace.workspace_id
        || pendingRef.current !== null
        || logoutIntentRef.current !== null
      ) return;
      const resource = resolveRevalidatedCurrentAccountTaskResource(
        task,
        taskResult.snapshot,
        [...snapshot.profiles, ...snapshot.demands],
      );
      if (!resource) {
        setTaskError({ code: "TASK_DESTINATION_NO_LONGER_AVAILABLE", traceId: null });
        setNotice("已重读服务端权限、对象与任务；原动作已变化，或精确对象仍不在授权清单中。请从刷新后的任务或角色工作台继续。");
        return;
      }
      setTaskError(null);
      setNotice("任务与精确对象已在同一轮服务端重核对中重新确认；正在打开最新对象详情。");
      setBusy(false);
      await openResource(resource, true, true);
    } catch (caught) {
      if (workspaceObjectGenerationRef.current !== ownedGeneration) return;
      const failure = caught instanceof ApiError
        ? caught
        : new ApiError(503, "TASK_DESTINATION_RECHECK_FAILED", null, null, null);
      setTaskError({ code: failure.code, traceId: failure.traceId });
      setNotice("任务对象重核对失败；页面没有猜测权限或直接读取任务路径。请使用顶部“刷新权限与对象”后重试。");
    } finally {
      if (workspaceObjectGenerationRef.current === ownedGeneration) setBusy(false);
    }
  }

  function openCurrentAccountTask(task: CurrentAccountTask) {
    if (
      busy
      || taskBusy
      || pendingRef.current !== null
      || logoutIntentRef.current !== null
    ) return;
    if (isTrustCaseHistoryTask(task)) {
      void openRevalidatedTrustCaseHistoryTask(task);
      return;
    }
    setTrustCaseHistoryTaskTarget(null);
    const target = resolveCurrentAccountTaskDestination(task);
    const financeDetailAction = resolveFinanceTaskDetailAction(task);
    if (financeDetailAction) {
      void openRevalidatedFinanceCurrentAccountTask(task);
      return;
    }
    const appealReadKind = appealTaskReadKind(task);
    if (appealReadKind) {
      void openRevalidatedAppealCurrentAccountTask(task);
      return;
    }
    const resource = target.kind === "RESOURCE" && target.resource_type === "CREATOR_PROFILE"
      ? profiles.find((item) => item.object_id === task.resource_id)
      : target.kind === "RESOURCE" && target.resource_type === "DEMAND"
        ? demands.find((item) => item.object_id === task.resource_id)
        : null;
    if (resource) {
      setTaskError(null);
      void openResource(resource, true);
      return;
    }
    if (target.kind === "RESOURCE") {
      void recoverMissingCurrentAccountTaskResource(task);
      return;
    }
    const destination = document.getElementById(target.element_id);
    if (!destination) {
      setTaskError({ code: "TASK_DESTINATION_NOT_LOADED", traceId: null });
      return;
    }
    setTaskError(null);
    destination.focus({ preventScroll: true });
    destination.scrollIntoView({ block: "start", behavior: "auto" });
    setNotice("已定位到当前角色的已验证工作区；请从该工作区继续处理，不需要粘贴资源编号。");
  }

  const replaceResource = useCallback((resource: EditorResource) => {
    if (resource.resource_type === "CREATOR_PROFILE") {
      setProfiles((current) => [...current.filter((item) => item.object_id !== resource.object_id), resource]);
    } else {
      setDemands((current) => [...current.filter((item) => item.object_id !== resource.object_id), resource]);
    }
  }, []);

  const replaceAccount = useCallback((account: AccountAdminProjection) => {
    setAccounts((current) => current
      .map((item) => item.user_id === account.user_id ? account : item)
      .sort((left, right) => left.account_code.localeCompare(right.account_code)));
    setSelectedAccount((current) => current?.user_id === account.user_id ? account : current);
  }, []);

  async function openResource(
    summary: EditorResource,
    focusAfterOpen = false,
    controlledTaskRecovery = false,
  ) {
    if (
      !selectedWorkspace
      || (busy && !controlledTaskRecovery)
      || pendingRef.current !== null
      || logoutIntentRef.current !== null
    ) {
      setError({ code: "WRITE_OUTCOME_PENDING", traceId: null });
      return;
    }
    if (!prepareToLeaveSelectedEditor()) return;
    const workspaceId = selectedWorkspace.workspace_id;
    const readEpoch = resourceReadEpochRef.current + 1;
    resourceReadEpochRef.current = readEpoch;
    setBusy(true);
    setError(null);
    try {
      const resource = parseEtaggedEditorResponse(
        await requestWorkspaceJson(workspaceId, resourcePath(summary)),
        { objectId: summary.object_id },
      );
      if (
        resourceReadEpochRef.current !== readEpoch
        || pendingRef.current !== null
        || logoutIntentRef.current !== null
      ) return;
      replaceResource(resource);
      adoptResource(resource, true);
      setNotice("已读取对象详情和最新版本；可编辑范围由服务端 capabilities 决定。");
      if (focusAfterOpen) requestAnimationFrame(() => {
        if (resourceReadEpochRef.current !== readEpoch) return;
        const destination = resourceEditorTitleRef.current;
        if (destination?.dataset.resourceId !== resource.object_id) return;
        destination.focus({ preventScroll: true });
        destination.scrollIntoView({ block: "start", behavior: "auto" });
      });
    } catch (caught) {
      const failure = caught instanceof ApiError ? caught : new ApiError(503, "INVALID_PLATFORM_RESPONSE", null, null, null);
      setError({ code: failure.code, traceId: failure.traceId });
    } finally {
      setBusy(false);
    }
  }

  async function openAccount(summary: AccountAdminProjection) {
    if (!selectedWorkspace || !accountScope) return;
    if (!prepareToLeaveSelectedEditor()) return;
    const workspaceId = selectedWorkspace.workspace_id;
    setBusy(true);
    setError(null);
    try {
      const accountResponse = await requestWorkspaceJson(
        workspaceId,
        `${ENDPOINTS.accounts}/${summary.user_id}`,
      );
      const account = parseAccountAdminEnvelope(accountResponse.value);
      if (
        accountResponse.etag !== account.entity_tag
        || account.user_id !== summary.user_id
      ) throw new TypeError("INVALID_ACCOUNT_ADMIN_RESPONSE");
      replaceAccount(account);
      setDemandCreationOpen(false);
      setSelected(null);
      setSelectedFinanceReview(null);
      setSections({});
      setDirty(false);
      setRecoveredScratchAt(null);
      setConflict(null);
      setSelectedAccount(account);
      setNotice("已从 IAM 读取账号详情、当前状态、版本和有效会话计数。");
    } catch (caught) {
      const failure = caught instanceof ApiError ? caught : new ApiError(503, "INVALID_PLATFORM_RESPONSE", null, null, null);
      setError({ code: failure.code, traceId: failure.traceId });
    } finally {
      setBusy(false);
    }
  }

  async function reloadReviewQueue() {
    if (
      !selectedWorkspace
      || selectedWorkspace.workspace_kind !== "PLATFORM"
      || !selectedWorkspace.role_codes.includes("OPERATIONS_REVIEWER")
    ) return;
    setBusy(true);
    setError(null);
    try {
      const items = await refreshReviewQueue(selectedWorkspace.workspace_id);
      setNotice(`审核队列已从服务端刷新；当前有 ${items.length} 个可领取需求。整改后重提的需求必须从这里重新领取并获得新分配。`);
    } catch (caught) {
      const failure = caught instanceof ApiError ? caught : new ApiError(503, "INVALID_PLATFORM_RESPONSE", null, null, null);
      setError({ code: failure.code, traceId: failure.traceId });
      setNotice("审核队列刷新失败；页面不会保留或构造旧队列项。");
    } finally {
      setBusy(false);
    }
  }

  async function reloadFinanceFundingQueue() {
    if (
      !selectedWorkspace
      || selectedWorkspace.workspace_kind !== "PLATFORM"
      || !selectedWorkspace.role_codes.includes("FINANCE_OPERATOR")
    ) return;
    setBusy(true);
    setError(null);
    try {
      const items = await refreshFinanceFundingQueue(selectedWorkspace.workspace_id);
      setNotice(`资金确认队列已从服务端刷新；当前有 ${items.length} 个零真实资金合成案例。`);
    } catch (caught) {
      const failure = caught instanceof ApiError ? caught : new ApiError(503, "INVALID_PLATFORM_RESPONSE", null, null, null);
      setError({ code: failure.code, traceId: failure.traceId });
      setNotice("资金确认队列刷新失败；页面不会保留或构造旧队列项。");
    } finally {
      setBusy(false);
    }
  }

  async function openFinanceFundingReview(item: FinanceFundingQueueItem) {
    if (!selectedWorkspace || !item.assigned_to_me || !item.funding_review_id) return;
    if (!prepareToLeaveSelectedEditor()) return;
    setBusy(true);
    setError(null);
    try {
      const response = await requestWorkspaceJson(
        selectedWorkspace.workspace_id,
        `${ENDPOINTS.financeFundingReviews}/${item.funding_review_id}`,
      );
      const review = parseFinanceFundingReviewEnvelope(response.value);
      if (
        response.etag !== review.etag
        || review.funding_review_id !== item.funding_review_id
        || review.demand_id !== item.demand_id
      ) throw new TypeError("INVALID_FINANCE_FUNDING_RESPONSE");
      setSelected(null);
      setSelectedAccount(null);
      setSelectedFinanceReview(review);
      setFinanceAttestationCodes([]);
      setFinanceReleaseReasonCode("WORKLOAD_RELEASE");
      setFinanceFindingDisposition("DISCREPANCY");
      setFinanceFindingReasonCodes([]);
      setFinanceFindingFieldCodes([]);
      setNotice("已读取分配给当前 Finance Operator 的零资金证据摘要与最新 ETag。");
    } catch (caught) {
      const failure = caught instanceof ApiError ? caught : new ApiError(503, "INVALID_PLATFORM_RESPONSE", null, null, null);
      setError({ code: failure.code, traceId: failure.traceId });
    } finally {
      setBusy(false);
    }
  }

  async function openFinanceFundingHistoryItem(item: FinanceFundingHistoryItem) {
    if (!selectedWorkspace?.role_codes.includes("FINANCE_OPERATOR")) return;
    if (!prepareToLeaveSelectedEditor()) return;
    setBusy(true);
    setError(null);
    try {
      const response = await requestWorkspaceJson(
        selectedWorkspace.workspace_id,
        `${ENDPOINTS.financeFundingReviews}/${item.funding_review_id}`,
      );
      const review = parseFinanceFundingReviewEnvelope(response.value);
      if (
        response.etag !== review.etag
        || review.funding_review_id !== item.funding_review_id
        || review.demand_id !== item.demand_id
        || review.demand_version_id !== item.demand_version_id
        || review.status !== item.status
      ) throw new TypeError("INVALID_FINANCE_FUNDING_HISTORY_DETAIL");
      setSelected(null);
      setSelectedAccount(null);
      setSelectedFinanceReview(review);
      setFinanceAttestationCodes([]);
      setFinanceReleaseReasonCode("WORKLOAD_RELEASE");
      setFinanceFindingDisposition("DISCREPANCY");
      setFinanceFindingReasonCodes([]);
      setFinanceFindingFieldCodes([]);
      setNotice("已按历史记录重新读取本人可见的终态资金审查，并核对记录、Demand、版本、状态与 ETag。");
    } catch (caught) {
      const failure = caught instanceof ApiError
        ? caught
        : new ApiError(503, "INVALID_FINANCE_FUNDING_HISTORY_DETAIL", null, null, null);
      setError({ code: failure.code, traceId: failure.traceId });
      setNotice("终态资金审查未能通过最新详情重核对；页面没有采用历史行构造详情。");
    } finally {
      setBusy(false);
    }
  }

  function claimFinanceFundingReview(item: FinanceFundingQueueItem) {
    if (!session || !selectedWorkspace?.role_codes.includes("FINANCE_OPERATOR")) return;
    if (item.assigned_to_me) {
      void openFinanceFundingReview(item);
      return;
    }
    if (!prepareToLeaveSelectedEditor()) return;
    try {
      const intent = createFinanceFundingClaimIntent({
        queueItem: item,
        csrfToken: session.csrf_token,
        idempotencyKey: newIdempotencyKey(),
      });
      void performWrite(pendingRecord("FINANCE_FUNDING", item.demand_id, "领取资金确认", intent));
    } catch (caught) {
      setError({ code: caught instanceof Error ? caught.message : "FINANCE_FUNDING_CLAIM_NOT_AVAILABLE", traceId: null });
    }
  }

  function confirmFinanceFundingReview(event: FormEvent) {
    event.preventDefault();
    if (!session || !selectedFinanceReview) return;
    try {
      const intent = createFinanceFundingConfirmIntent({
        review: selectedFinanceReview,
        attestationCodes: financeAttestationCodes,
        csrfToken: session.csrf_token,
        idempotencyKey: newIdempotencyKey(),
      });
      void performWrite(pendingRecord(
        "FINANCE_FUNDING",
        selectedFinanceReview.funding_review_id,
        "确认零资金合成证据",
        intent,
      ));
    } catch (caught) {
      setError({ code: caught instanceof Error ? caught.message : "FINANCE_ATTESTATION_REQUIRED", traceId: null });
    }
  }

  function releaseFinanceFundingReview(event: FormEvent) {
    event.preventDefault();
    if (!session || !selectedFinanceReview) return;
    try {
      const intent = createFinanceFundingReleaseIntent({
        review: selectedFinanceReview,
        reasonCode: financeReleaseReasonCode,
        csrfToken: session.csrf_token,
        idempotencyKey: newIdempotencyKey(),
      });
      void performWrite(pendingRecord(
        "FINANCE_FUNDING",
        selectedFinanceReview.funding_review_id,
        "释放资金审查分配",
        intent,
      ));
    } catch (caught) {
      setError({ code: caught instanceof Error ? caught.message : "FINANCE_RELEASE_NOT_AVAILABLE", traceId: null });
    }
  }

  function submitFinanceFundingFinding(event: FormEvent) {
    event.preventDefault();
    if (!session || !selectedFinanceReview) return;
    try {
      const intent = createFinanceFundingFindingIntent({
        review: selectedFinanceReview,
        disposition: financeFindingDisposition,
        reasonCodes: [...financeFindingReasonCodes].sort(),
        requiredFieldCodes: [...financeFindingFieldCodes].sort(),
        csrfToken: session.csrf_token,
        idempotencyKey: newIdempotencyKey(),
      });
      void performWrite(pendingRecord(
        "FINANCE_FUNDING",
        selectedFinanceReview.funding_review_id,
        financeFindingDisposition === "REJECTED" ? "拒绝资金审查" : "提交资金审查差异",
        intent,
      ));
    } catch (caught) {
      setError({ code: caught instanceof Error ? caught.message : "FINANCE_FINDING_NOT_AVAILABLE", traceId: null });
    }
  }

  function persistPending(record: PendingIntent | null) {
    pendingRef.current = record;
    setPendingOwner(record ? "PRODUCT" : null);
    setPending(record);
    if (record) {
      sessionStorage.removeItem(MATCHING_SELECTION_RECOVERY_KEY);
      sessionStorage.setItem(PENDING_KEY, serializePendingIntent(record));
    } else {
      sessionStorage.removeItem(PENDING_KEY);
      sessionStorage.removeItem(MATCHING_SELECTION_RECOVERY_KEY);
    }
  }

  function clearReviewAssignmentSelection(objectId: string) {
    setDemands((current) => current.filter((item) => item.object_id !== objectId));
    setSelected(null);
    setSections({});
    setDirty(false);
    setRecoveredScratchAt(null);
    setConflict(null);
    setReasonCodes(["CONTENT_INCOMPLETE"]);
    setRequiredPaths([]);
    setReviewReleaseReasonCode("WORKLOAD_RELEASE");
    setBudgetHealthCode("HEALTHY");
    setRiskCode("STANDARD");
    setEvidenceCodes([]);
  }

  async function performWrite(candidateRecord: PendingIntent) {
    if (logoutIntentRef.current !== null) {
      setError({ code: "WRITE_OUTCOME_PENDING", traceId: null });
      setNotice("退出结果仍未知；只能原样重试退出或明确放弃该恢复对象，当前写入没有发送。");
      return;
    }
    const globalPending = pendingRef.current;
    if (globalPending?.resource_type === "ORG_ADMIN" || globalPending?.resource_type === "SESSION_REVOKE") {
      setError({ code: "WRITE_OUTCOME_PENDING", traceId: null });
      setNotice("已有一笔组织或会话管理写入占用单一在途门闩；当前请求没有发送，也没有覆盖它。");
      return;
    }
    const existingPending = globalPending;
    if (
      existingPending
      && serializePendingIntent(existingPending) !== serializePendingIntent(candidateRecord)
    ) {
      setError({ code: "WRITE_OUTCOME_PENDING", traceId: null });
      setNotice("已有一笔结果未知的写入；只能原样重试或明确放弃，不能用新账号操作覆盖它。");
      return;
    }
    const record = existingPending ?? candidateRecord;
    if (!selectedWorkspace) {
      setError({ code: "WORKSPACE_REQUIRED", traceId: null });
      return;
    }
    const workspaceId = selectedWorkspace.workspace_id;
    resourceReadEpochRef.current += 1;
    setBusy(true);
    setError(null);
    setConflict(null);
    if (!existingPending) persistPending(record);
    setNotice(`正在${record.label}；在结果明确前不会自动改换幂等键。`);
    let writeConfirmed = false;
    try {
      const result = await requestWorkspaceJson(workspaceId, record.intent.path, {
        method: record.intent.method,
        headers: record.intent.headers,
        body: JSON.stringify(record.intent.body),
      });
      if (record.resource_type === "REVIEW_CLAIM") {
        const claim = parseEditorReviewClaimEnvelope(result.value);
        if (result.etag !== claim.etag || claim.demand_id !== record.object_id) {
          throw new TypeError("INVALID_REVIEW_CLAIM_RESPONSE");
        }
        writeConfirmed = true;
        persistPending(null);
        const detailResponse = await requestWorkspaceJson(
          workspaceId,
          `${ENDPOINTS.demands}/${claim.demand_id}`,
        );
        const resource = parseEtaggedEditorResponse(detailResponse, {
          objectId: claim.demand_id,
          assignmentId: claim.assignment_id,
        });
        if (resource.resource_type !== "DEMAND" || !resource.capabilities.includes("RECORD_FINDINGS")) {
          throw new TypeError("INVALID_REVIEW_CLAIM_RESOURCE");
        }
        setReviewQueue((current) => current.filter((item) => item.demand_id !== claim.demand_id));
        setDemandScope(true);
        replaceResource(resource);
        adoptResource(resource, false);
        await refreshReviewQueue(workspaceId);
        setNotice(`领取审核已由服务端确认${claim.replayed ? "（同一请求重放）" : ""}。已重新读取需求与资源 ETag；当前分配为 ${shortId(claim.assignment_id)}。`);
        return;
      }
      if (record.resource_type === "FINANCE_FUNDING") {
        const review = parseFinanceFundingReviewEnvelope(result.value);
        const isClaim = record.intent.path.endsWith("/claim");
        const isRelease = record.intent.path.endsWith("/assignment/release");
        const isFinding = record.intent.path.endsWith("/findings");
        if (
          result.etag !== review.etag
          || (isClaim ? review.demand_id : review.funding_review_id) !== record.object_id
        ) throw new TypeError("INVALID_FINANCE_FUNDING_RESPONSE");
        writeConfirmed = true;
        persistPending(null);
        setSelected(null);
        setSelectedAccount(null);
        setSelectedFinanceReview(review);
        setFinanceAttestationCodes([]);
        setFinanceFindingReasonCodes([]);
        setFinanceFindingFieldCodes([]);
        await refreshFinanceFundingQueue(workspaceId);
        setNotice(isClaim
          ? `领取资金确认已由服务端确认${review.replayed ? "（同一请求重放）" : ""}。当前为 ${review.confirmation_count}/2 份独立确认。`
          : isRelease
            ? `当前未确认分配已释放${review.replayed ? "（同一请求重放）" : ""}；历史事实保留，队列席位已经重新开放。`
            : isFinding
              ? review.status === "REJECTED"
                ? "资金审查已以 REJECTED 闭合；需求已安全回到 NEEDS_CHANGES，Demand Owner 可见闭合原因与可修改字段。"
                : "资金审查已以 DISCREPANCY 闭合；需求回到 VERIFIED，Owner 历史中保留安全摘要。"
          : review.status === "SECURED"
            ? "第二名独立 Finance Operator 已完成合成零资金确认；此状态不代表真实到账、支付或托管。"
            : "当前独立确认已记录；仍需另一名 Finance Operator 独立领取并确认。"
        );
        return;
      }
      if (record.resource_type === "ACCOUNT_ADMIN") {
        const command = parseAccountAdminCommandEnvelope(result.value);
        if (result.etag !== command.entity_tag || command.user_id !== record.object_id) {
          throw new TypeError("INVALID_ACCOUNT_ADMIN_RESPONSE");
        }
        writeConfirmed = true;
        persistPending(null);
        const accountResponse = await requestWorkspaceJson(
          workspaceId,
          `${ENDPOINTS.accounts}/${command.user_id}`,
        );
        const account = parseAccountAdminEnvelope(accountResponse.value);
        if (
          accountResponse.etag !== account.entity_tag
          || account.user_id !== command.user_id
          || account.aggregate_version < command.aggregate_version
        ) throw new TypeError("INVALID_ACCOUNT_ADMIN_RESPONSE");
        replaceAccount(account);
        setSelected(null);
        setSelectedAccount(account);
        setNotice(`${record.label}已由服务端确认。账号版本为 v${account.aggregate_version}，当前有效会话 ${account.active_session_count} 个。`);
        return;
      }
      if (record.resource_type !== "CREATOR_PROFILE" && record.resource_type !== "DEMAND") {
        throw new TypeError("INVALID_EDITOR_RESPONSE_BINDING");
      }
      const resource = parseEtaggedEditorResponse(result, {
        objectId: expectedEditorResponseObjectId(record.resource_type, record.object_id),
      });
      if (!editorResponseBindingMatches(
        record.resource_type,
        record.object_id,
        resource.resource_type,
        resource.object_id,
      )) throw new TypeError("INVALID_EDITOR_RESPONSE_BINDING");
      const reviewDecision = isReviewDecisionPath(record.intent.path);
      const reviewRelease = isReviewAssignmentReleasePath(record.intent.path);
      const reviewAssignmentWrite = reviewDecision || reviewRelease;
      if (reviewDecision && resource.review_assignment !== null) {
        throw new TypeError("REVIEW_ASSIGNMENT_NOT_CLOSED");
      }
      if (reviewRelease && (resource.status !== "SUBMITTED" || resource.review_assignment !== null)) {
        throw new TypeError("INVALID_REVIEW_RELEASE_RESPONSE");
      }
      writeConfirmed = true;
      persistPending(null);
      sessionStorage.removeItem(scratchKey(resource));
      if (reviewRelease) {
        clearReviewAssignmentSelection(resource.object_id);
        await refreshReviewWorkspaceAfterAssignmentWrite(workspaceId);
        setNotice(`审核分配释放已由服务端确认。Demand 内容与 SUBMITTED 状态未改变；当前详情已清除，审核队列与任务已重新读取。对象版本为 v${resource.revision}。`);
        return;
      }
      replaceResource(resource);
      adoptResource(resource, false);
      if (record.object_id === "new_demand_internal") {
        setCreateReference("");
        setCreateExpiry(defaultDemandExpiry());
      }
      if (reviewAssignmentWrite) await refreshReviewQueue(workspaceId);
      setNotice(`${record.label}已由服务端确认。对象版本为 v${resource.revision}。`);
    } catch (caught) {
      if (writeConfirmed) {
        persistPending(null);
        const failure = caught instanceof ApiError ? caught : new ApiError(503, "INVALID_PLATFORM_RESPONSE", null, null, null);
        setError({ code: failure.code, traceId: failure.traceId });
        setNotice(`${record.label}已由服务端确认，但后续详情或队列刷新失败；请刷新权限与对象，切勿原样重试这笔已确认写入。`);
        return;
      }
      if (caught instanceof ApiError && caught.status === 412 && record.resource_type === "ACCOUNT_ADMIN") {
        persistPending(null);
        try {
          const accountResponse = await requestWorkspaceJson(
            workspaceId,
            `${ENDPOINTS.accounts}/${record.object_id}`,
          );
          const account = parseAccountAdminEnvelope(accountResponse.value);
          if (
            accountResponse.etag !== account.entity_tag
            || account.user_id !== record.object_id
          ) throw new TypeError("INVALID_ACCOUNT_ADMIN_RESPONSE");
          replaceAccount(account);
          setSelected(null);
          setSelectedFinanceReview(null);
          setSelectedAccount(account);
          setError({ code: caught.code, traceId: caught.traceId });
          setNotice("账号版本已经变化；旧请求已清除，并已 fresh GET 当前账号与 ETag。请基于重新选中的服务端事实明确发起新操作。");
        } catch (refreshCaught) {
          const failure = refreshCaught instanceof ApiError ? refreshCaught : new ApiError(503, "INVALID_PLATFORM_RESPONSE", null, null, null);
          setSelectedAccount(null);
          setError({ code: failure.code, traceId: failure.traceId });
          setNotice("账号操作的前置条件已明确失败，但 fresh GET 当前账号失败；旧请求已清除，不会误重放。请重新打开账号后再操作。");
        }
        return;
      }
      if (caught instanceof ApiError && caught.status === 412 && record.resource_type === "REVIEW_CLAIM") {
        persistPending(null);
        try {
          await refreshReviewQueue(workspaceId);
          setError({ code: caught.code, traceId: caught.traceId });
          setNotice("该队列项已变化或被其他审核员领取；已刷新审核队列，请只从新队列事实再次操作。");
        } catch (refreshCaught) {
          const failure = refreshCaught instanceof ApiError ? refreshCaught : new ApiError(503, "INVALID_PLATFORM_RESPONSE", null, null, null);
          setError({ code: failure.code, traceId: failure.traceId });
          setNotice("领取前置条件已明确失败，且队列刷新失败；旧领取请求已清除，不会误重放。");
        }
        return;
      }
      if (caught instanceof ApiError && caught.status === 412 && isReviewAssignmentWritePath(record.intent.path)) {
        persistPending(null);
        const reviewRelease = isReviewAssignmentReleasePath(record.intent.path);
        try {
          if (reviewRelease) {
            clearReviewAssignmentSelection(record.object_id);
            await refreshReviewWorkspaceAfterAssignmentWrite(workspaceId);
          } else {
            const detailResponse = await requestWorkspaceJson(workspaceId, `${ENDPOINTS.demands}/${record.object_id}`);
            const resource = parseEtaggedEditorResponse(detailResponse, { objectId: record.object_id });
            replaceResource(resource);
            adoptResource(resource, false);
            await refreshReviewQueue(workspaceId);
          }
          setError({ code: caught.code, traceId: caught.traceId });
          setNotice(reviewRelease
            ? "审核对象或分配已变化；旧释放请求已清除，并已原子重读可见需求、审核队列与任务。请基于 fresh 分配事实重新操作。"
            : "审核对象或分配已变化；已读取最新资源 ETag 与队列，旧决定请求已清除。请重新核对后生成新请求。"
          );
        } catch (refreshCaught) {
          const failure = refreshCaught instanceof ApiError ? refreshCaught : new ApiError(503, "INVALID_PLATFORM_RESPONSE", null, null, null);
          setError({ code: failure.code, traceId: failure.traceId });
          setNotice(reviewRelease
            ? "审核分配释放的前置条件已明确失败，但最新对象刷新失败；旧请求已清除，不会误重放。"
            : "审核决定的前置条件已明确失败，但最新对象刷新失败；旧请求已清除，不会误重放。"
          );
        }
        return;
      }
      if (caught instanceof ApiError && caught.status === 412 && record.resource_type === "FINANCE_FUNDING") {
        persistPending(null);
        try {
          const isClaim = record.intent.path.endsWith("/claim");
          if (!isClaim) {
            const detailResponse = await requestWorkspaceJson(
              workspaceId,
              `${ENDPOINTS.financeFundingReviews}/${record.object_id}`,
            );
            const review = parseFinanceFundingReviewEnvelope(detailResponse.value);
            if (
              detailResponse.etag !== review.etag
              || review.funding_review_id !== record.object_id
            ) throw new TypeError("INVALID_FINANCE_FUNDING_RESPONSE");
            setSelectedFinanceReview(review);
          } else {
            setSelectedFinanceReview(null);
          }
          await refreshFinanceFundingQueue(workspaceId);
          setFinanceAttestationCodes([]);
          setFinanceFindingReasonCodes([]);
          setFinanceFindingFieldCodes([]);
          setError({ code: caught.code, traceId: caught.traceId });
          setNotice(isClaim
            ? "资金确认队列项已变化；旧领取请求已清除，并已 fresh GET 队列。请只从新事实重新领取。"
            : "资金确认对象或分配版本已变化；旧请求已清除，并已 fresh GET 当前详情、ETag 与队列。请重新核对可用动作。"
          );
        } catch (refreshCaught) {
          const failure = refreshCaught instanceof ApiError ? refreshCaught : new ApiError(503, "INVALID_PLATFORM_RESPONSE", null, null, null);
          setError({ code: failure.code, traceId: failure.traceId });
          setNotice("资金确认前置条件已明确失败，但队列刷新失败；旧请求已清除，不会误重放。");
        }
        return;
      }
      if (
        caught instanceof ApiError
        && caught.status === 412
        && record.resource_type === "CREATOR_PROFILE"
        && isProfileLifecyclePath(record.intent.path)
      ) {
        persistPending(null);
        try {
          const refreshedResponse = await requestWorkspaceJson(
            workspaceId,
            `${ENDPOINTS.profiles}/${record.object_id}`,
          );
          const refreshed = parseEtaggedEditorResponse(
            refreshedResponse,
            { objectId: record.object_id },
          );
          replaceResource(refreshed);
          adoptResource(refreshed, false);
          setError({ code: caught.code, traceId: caught.traceId });
          setNotice("画像状态或版本已经变化；旧请求已清除，并已重新读取当前状态与 ETag。请基于新事实明确操作。");
        } catch (refreshCaught) {
          const failure = refreshCaught instanceof ApiError
            ? refreshCaught
            : new ApiError(503, "INVALID_PLATFORM_RESPONSE", null, null, null);
          setSelected(null);
          setSections({});
          setDirty(false);
          setError({ code: failure.code, traceId: failure.traceId });
          setNotice("画像状态请求已明确因版本变化失败，但重新读取当前画像失败；旧请求已清除，请从左侧重新打开画像。");
        }
        return;
      }
      if (
        caught instanceof ApiError
        && caught.status === 412
        && record.resource_type === "DEMAND"
        && isDemandCancelPath(record.intent.path)
      ) {
        persistPending(null);
        try {
          const refreshedResponse = await requestWorkspaceJson(
            workspaceId,
            `${ENDPOINTS.demands}/${record.object_id}`,
          );
          const refreshed = parseEtaggedEditorResponse(
            refreshedResponse,
            { objectId: record.object_id },
          );
          replaceResource(refreshed);
          adoptResource(refreshed, false);
          setError({ code: caught.code, traceId: caught.traceId });
          setNotice("需求状态或版本已经变化；旧取消请求已清除，并已重新读取当前状态与 ETag。请基于新事实重新确认。");
        } catch (refreshCaught) {
          const failure = refreshCaught instanceof ApiError
            ? refreshCaught
            : new ApiError(503, "INVALID_PLATFORM_RESPONSE", null, null, null);
          setSelected(null);
          setSections({});
          setDirty(false);
          setError({ code: failure.code, traceId: failure.traceId });
          setNotice("取消请求已明确因版本变化失败，但重新读取当前需求失败；旧请求已清除，请从左侧重新打开需求。");
        }
        return;
      }
      if (
        (record.resource_type === "CREATOR_PROFILE" || record.resource_type === "DEMAND")
        && caught instanceof ApiError
        && caught.status === 412
        && caught.etag
      ) {
        try {
          const conflictSurface = parseThreeWayConflict(caught.body, caught.etag);
          persistPending(null);
          const refreshedResponse = await requestWorkspaceJson(
            workspaceId,
            resourcePath({
              resource_type: record.resource_type,
              object_id: record.object_id,
            }),
          );
          const refreshed = bindConflictToCurrentResource(
            conflictSurface,
            parseEtaggedEditorResponse(refreshedResponse, { objectId: record.object_id }),
          );
          replaceResource(refreshed);
          adoptResource(refreshed, false);
          setConflict(conflictSurface);
          setNotice("服务端对象已变化，且最新完整版本已重新读取。页面会自动保留单边修改；双方改到不同结果的分区需要你逐项选择。");
          return;
        } catch {
          // Malformed conflict details are an unavailable platform response.
        }
      }
      const failure = caught instanceof ApiError ? caught : new ApiError(0, "WRITE_OUTCOME_UNKNOWN", null, null, null);
      const outcomeUnknown = failure.status === 0 || failure.status >= 500;
      if (!outcomeUnknown) persistPending(null);
      setError({ code: failure.code, traceId: failure.traceId });
      setNotice(outcomeUnknown
        ? "写入结果未知。已在当前标签页保留完全相同的请求，可原样重试或人工放弃。"
        : "服务端已明确拒绝该请求；请修正显示的问题后再生成新请求。");
    } finally {
      setBusy(false);
    }
  }

  function persistLogoutIntent(intent: SessionLogoutIntent | null) {
    logoutIntentRef.current = intent;
    setLogoutIntent(intent);
    if (intent) sessionStorage.setItem(LOGOUT_PENDING_KEY, serializeSessionLogoutIntent(intent));
    else sessionStorage.removeItem(LOGOUT_PENDING_KEY);
  }

  async function logoutCurrentSession() {
    if (!session) return;
    setAppealHandoff(null);
    if (!prepareToLeaveOrganizationAdmin()) return;
    if (pendingRef.current !== null || policyAcceptanceIntentRef.current !== null) {
      setError({ code: "SESSION_LOGOUT_BLOCKED_BY_PENDING_WRITE", traceId: null });
      setNotice("已有一笔结果未知的写入；请先原样重试或明确放弃，退出请求没有发送。退出成功后才会清理浏览器恢复状态。");
      return;
    }
    const existing = logoutIntentRef.current;
    if (existing && (
      existing.session_id !== session.session.session_id
      || existing.csrf_token !== session.csrf_token
    )) {
      setError({ code: "SESSION_LOGOUT_RECOVERY_MISMATCH", traceId: null });
      setNotice("保留的退出恢复对象与当前服务端会话不一致；页面没有发送请求。");
      return;
    }
    const intent = existing ?? {
      version: 1 as const,
      saved_at: new Date().toISOString(),
      session_id: session.session.session_id,
      csrf_token: session.csrf_token,
      idempotency_key: newIdempotencyKey(),
    };
    persistLogoutIntent(intent);
    setBusy(true);
    setError(null);
    setNotice(existing
      ? "正在用同一幂等键原样重试退出当前会话。"
      : "正在撤销当前服务端会话；不会撤销该账号的其他会话。"
    );
    try {
      await requestJson(
        `/v1/me/sessions/${encodeURIComponent(intent.session_id)}`,
        {
          method: "DELETE",
          headers: {
            "idempotency-key": intent.idempotency_key,
            "x-bootstrap-session-id": intent.session_id,
            "x-csrf-token": intent.csrf_token,
          },
        },
      );
      persistLogoutIntent(null);
      enterSignedOut("当前服务端会话已撤销，浏览器中的本账号恢复状态已清理。可以重新登录。 ");
    } catch (caught) {
      const failure = caught instanceof ApiError
        ? caught
        : new ApiError(503, "INVALID_LOGOUT_RESPONSE", null, null, null);
      if (failure.status === 401) {
        persistLogoutIntent(null);
        enterSignedOut("当前会话已不可用；页面已退出，你可以重新通过身份提供方登录。 ");
        return;
      }
      const outcomeUnknown = failure.status === 0 || failure.status >= 500;
      if (outcomeUnknown) persistLogoutIntent(intent);
      else persistLogoutIntent(null);
      setError({ code: failure.code, traceId: failure.traceId });
      setNotice(outcomeUnknown
        ? "退出结果未知。已保留完全相同的 Session、CSRF 与幂等键，只能原样重试或明确放弃恢复。"
        : "服务端已明确拒绝退出请求；当前会话和浏览器恢复状态均未当作已清理。"
      );
    } finally {
      setBusy(false);
    }
  }

  async function beginSignIn(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const result = await requestJson(ENDPOINTS.authorization, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ return_to: "/app" }),
      });
      if (!result.value || typeof result.value !== "object") throw new TypeError("INVALID_AUTHORIZATION_RESPONSE");
      const urlValue = (result.value as Record<string, unknown>).authorization_url;
      if (typeof urlValue !== "string") throw new TypeError("INVALID_AUTHORIZATION_RESPONSE");
      window.location.assign(parseIdentityAuthorizationUrl(urlValue));
    } catch (caught) {
      const failure = caught instanceof ApiError ? caught : new ApiError(503, "INVALID_AUTHORIZATION_RESPONSE", null, null, null);
      setError({ code: failure.code, traceId: failure.traceId });
      setBusy(false);
    }
  }

  function saveDraft() {
    if (!selected || !session || !configuration) return;
    try {
      const issues = structuredContentIssues(selected.resource_type, sections, configuration);
      if (issues.length) throw new TypeError(`EDITOR_VALIDATION:${issues[0].path}:${issues[0].code}`);
      const content = sectionsToContent(selected.resource_type, sections);
      const taxonomyBundleId = configuration.taxonomy_bundle.bundle_id;
      const intent = selected.resource_type === "CREATOR_PROFILE"
        ? createProfileDraftIntent({ resource: selected, csrfToken: session.csrf_token, idempotencyKey: newIdempotencyKey(), taxonomyBundleId, content })
        : createDemandDraftIntent({ resource: selected, csrfToken: session.csrf_token, idempotencyKey: newIdempotencyKey(), taxonomyBundleId, content });
      void performWrite(pendingRecord(selected.resource_type, selected.object_id, "保存草稿", intent));
    } catch (caught) {
      setError({ code: caught instanceof Error ? caught.message : "INVALID_EDITOR_CONTENT", traceId: null });
    }
  }

  function advanceResource(action: "PUBLISH" | "SUBMIT") {
    if (!selected || !session || !configuration) return;
    try {
      const issues = structuredContentIssues(selected.resource_type, sections, configuration);
      if (issues.length) throw new TypeError(`EDITOR_VALIDATION:${issues[0].path}:${issues[0].code}`);
      const label = action === "PUBLISH" ? "发布创作者画像" : "提交需求审核";
      const intent = createResourceActionIntent({ resource: selected, action, csrfToken: session.csrf_token, idempotencyKey: newIdempotencyKey() });
      void performWrite(pendingRecord(selected.resource_type, selected.object_id, label, intent));
    } catch (caught) {
      setError({ code: caught instanceof Error ? caught.message : "ACTION_NOT_AVAILABLE", traceId: null });
    }
  }

  function changeProfileLifecycle(action: "PAUSE" | "RESUME" | "ARCHIVE") {
    if (!selected || !session || selected.resource_type !== "CREATOR_PROFILE") return;
    if (dirty) {
      setError({ code: "UNSAVED_PROFILE_CHANGES", traceId: null });
      setNotice("请先保存或撤销当前标签页修改，再改变画像状态。");
      return;
    }
    if (action === "ARCHIVE" && !profileArchiveConfirmed) {
      setError({ code: "PROFILE_ARCHIVE_CONFIRMATION_REQUIRED", traceId: null });
      return;
    }
    try {
      const reasonCode = action === "RESUME"
        ? null
        : action === "PAUSE"
          ? profilePauseReasonCode
          : profileArchiveReasonCode;
      const intent = createProfileLifecycleIntent({
        resource: selected,
        action,
        reasonCode,
        csrfToken: session.csrf_token,
        idempotencyKey: newIdempotencyKey(),
      });
      const label = action === "PAUSE"
        ? "暂停创作者画像"
        : action === "RESUME"
          ? "恢复创作者画像"
          : "归档创作者画像";
      void performWrite(pendingRecord(
        "CREATOR_PROFILE",
        selected.object_id,
        label,
        intent,
      ));
    } catch (caught) {
      setError({ code: caught instanceof Error ? caught.message : "PROFILE_LIFECYCLE_NOT_AVAILABLE", traceId: null });
    }
  }

  function cancelDemand() {
    if (!selected || !session || selected.resource_type !== "DEMAND") return;
    if (dirty) {
      setError({ code: "UNSAVED_DEMAND_CHANGES", traceId: null });
      setNotice("请先保存或撤销当前标签页修改，再取消需求。");
      return;
    }
    if (!demandCancelConfirmed) {
      setError({ code: "DEMAND_CANCEL_CONFIRMATION_REQUIRED", traceId: null });
      return;
    }
    try {
      const intent = createDemandCancelIntent({
        resource: selected,
        reasonCode: demandCancelReasonCode,
        csrfToken: session.csrf_token,
        idempotencyKey: newIdempotencyKey(),
      });
      void performWrite(pendingRecord(
        "DEMAND",
        selected.object_id,
        "取消需求",
        intent,
      ));
    } catch (caught) {
      setError({ code: caught instanceof Error ? caught.message : "DEMAND_CANCEL_NOT_AVAILABLE", traceId: null });
    }
  }

  function createProfile() {
    if (!session || !configuration || !selectedWorkspace?.role_codes.includes("CREATOR")) return;
    try {
      const intent = createProfileIntent({ csrfToken: session.csrf_token, idempotencyKey: newIdempotencyKey() });
      void performWrite(pendingRecord("CREATOR_PROFILE", "new_profile_internal", "创建画像", intent));
    } catch (caught) {
      setError({ code: caught instanceof Error ? caught.message : "CREATE_NOT_AVAILABLE", traceId: null });
    }
  }

  function beginDemandCreation() {
    if (
      !canCreateDemand
      || busy
      || pendingRef.current !== null
      || logoutIntentRef.current !== null
    ) {
      setError({ code: "CREATE_NOT_AVAILABLE", traceId: null });
      return;
    }
    if (!prepareToLeaveSelectedEditor()) return;
    setSelected(null);
    setSelectedAccount(null);
    setSelectedFinanceReview(null);
    setSections({});
    setDirty(false);
    setRecoveredScratchAt(null);
    setConflict(null);
    setDemandCreationOpen(true);
    setError(null);
    setNotice("已进入新需求创建页；刚才对象的未提交编辑仍保留在当前标签页草稿中。");
  }

  function createDemand(event: FormEvent) {
    event.preventDefault();
    if (!session || !configuration || !selectedWorkspace?.role_codes.includes("DEMAND_OWNER")) return;
    try {
      const intent = createDemandIntent({
        csrfToken: session.csrf_token,
        idempotencyKey: newIdempotencyKey(),
        taxonomyBundleId: configuration.taxonomy_bundle.bundle_id,
        clientReference: createReference,
        expiresAt: dateTimeLocalToIso(createExpiry),
      });
      void performWrite(pendingRecord("DEMAND", "new_demand_internal", "创建合成需求", intent));
    } catch (caught) {
      setError({ code: caught instanceof Error ? caught.message : "INVALID_CREATE_INPUT", traceId: null });
    }
  }

  function recordFindings(event: FormEvent) {
    event.preventDefault();
    if (!selected || !session) return;
    try {
      const assignmentId = selected.review_assignment?.assignment_id;
      if (!assignmentId) throw new TypeError("REVIEW_ASSIGNMENT_UNAVAILABLE");
      const intent = createFindingIntent({
        resource: selected,
        assignmentId,
        csrfToken: session.csrf_token,
        idempotencyKey: newIdempotencyKey(),
        reasonCodes,
        requiredFieldPaths: requiredPaths,
      });
      void performWrite(pendingRecord("DEMAND", selected.object_id, "记录审核整改项", intent));
    } catch (caught) {
      setError({ code: caught instanceof Error ? caught.message : "INVALID_FINDING", traceId: null });
    }
  }

  function claimReview(queueItem: EditorReviewQueueItem) {
    if (!session || !selectedWorkspace?.role_codes.includes("OPERATIONS_REVIEWER")) return;
    if (!prepareToLeaveSelectedEditor()) return;
    try {
      const intent = createReviewClaimIntent({
        queueItem,
        csrfToken: session.csrf_token,
        idempotencyKey: newIdempotencyKey(),
      });
      void performWrite(pendingRecord("REVIEW_CLAIM", queueItem.demand_id, "领取审核", intent));
    } catch (caught) {
      setError({ code: caught instanceof Error ? caught.message : "REVIEW_CLAIM_NOT_AVAILABLE", traceId: null });
    }
  }

  function releaseReviewAssignment(event: FormEvent) {
    event.preventDefault();
    if (!selected || !session) return;
    try {
      const assignmentId = selected.review_assignment?.assignment_id;
      if (!assignmentId) throw new TypeError("REVIEW_ASSIGNMENT_UNAVAILABLE");
      const intent = createReviewAssignmentReleaseIntent({
        resource: selected,
        assignmentId,
        csrfToken: session.csrf_token,
        idempotencyKey: newIdempotencyKey(),
        reasonCode: reviewReleaseReasonCode,
      });
      void performWrite(pendingRecord("DEMAND", selected.object_id, "释放审核分配", intent));
    } catch (caught) {
      setError({ code: caught instanceof Error ? caught.message : "REVIEW_RELEASE_NOT_AVAILABLE", traceId: null });
    }
  }

  function verifyDemand(event: FormEvent) {
    event.preventDefault();
    if (!selected || !session) return;
    try {
      const assignmentId = selected.review_assignment?.assignment_id;
      if (!assignmentId) throw new TypeError("REVIEW_ASSIGNMENT_UNAVAILABLE");
      const intent = createVerifyIntent({
        resource: selected,
        assignmentId,
        csrfToken: session.csrf_token,
        idempotencyKey: newIdempotencyKey(),
        budgetHealthCode,
        riskCode,
        evidenceCodes,
      });
      void performWrite(pendingRecord("DEMAND", selected.object_id, "验证通过", intent));
    } catch (caught) {
      setError({ code: caught instanceof Error ? caught.message : "INVALID_VERIFICATION", traceId: null });
    }
  }

  function manageAccount(action: "SUSPEND" | "RESUME" | "REVOKE_ALL_SESSIONS") {
    if (!selectedAccount || !session || !accountScope) return;
    const labels = {
      SUSPEND: "暂停账号",
      RESUME: "恢复账号",
      REVOKE_ALL_SESSIONS: "撤销全部会话",
    } as const;
    try {
      const intent = createAccountAdminIntent({
        account: selectedAccount,
        action,
        csrfToken: session.csrf_token,
        idempotencyKey: newIdempotencyKey(),
        reasonCode: accountReasonCode,
      });
      void performWrite(pendingRecord("ACCOUNT_ADMIN", selectedAccount.user_id, labels[action], intent));
    } catch (caught) {
      setError({ code: caught instanceof Error ? caught.message : "ACCOUNT_ACTION_NOT_AVAILABLE", traceId: null });
    }
  }

  function managePlatformDuty(
    dutyCode: "ACCESS_ADMIN" | "APPEAL_REVIEWER" | "FINANCE_OPERATOR" | "OPERATIONS_REVIEWER" | "TRUST_OFFICER",
    action: "GRANT" | "REVOKE",
  ) {
    if (!selectedAccount || !session || !accountScope) return;
    try {
      const intent = createPlatformDutyIntent({
        account: selectedAccount,
        dutyCode,
        action,
        csrfToken: session.csrf_token,
        idempotencyKey: newIdempotencyKey(),
        reasonCode: accountReasonCode,
      });
      const label = `${action === "GRANT" ? "授予" : "撤销"} ${dutyCode}`;
      void performWrite(
        pendingRecord("ACCOUNT_ADMIN", selectedAccount.user_id, label, intent),
      );
    } catch (caught) {
      setError({ code: caught instanceof Error ? caught.message : "ACCOUNT_ACTION_NOT_AVAILABLE", traceId: null });
    }
  }

  function conflictStillMatchesCurrent() {
    if (!selected || !conflict) return;
    if (selected.etag !== conflict.currentEtag) {
      setError({ code: "CONFLICT_REFRESH_MISMATCH", traceId: null });
      setNotice("冲突后的服务端版本又发生变化；请重新读取对象后再处理。");
      return false;
    }
    return true;
  }

  function discardConflictEdits() {
    if (!selected || !conflict || !conflictStillMatchesCurrent()) return;
    setSections(sectionsFromContent(selected.resource_type, conflict.current.content));
    setDirty(false);
    sessionStorage.removeItem(scratchKey(selected));
    setConflict(null);
    setError(null);
    setNotice("已保留服务器当前版本，并从编辑器移除本次冲突的本地修改。");
  }

  function resolveConflict(choices: Readonly<Record<string, EditorConflictChoice>>) {
    if (!selected || !conflict || !conflictStillMatchesCurrent()) return;
    try {
      const merge = planEditorConflictMerge(
        selected.resource_type,
        conflict.base.content,
        conflict.current.content,
        conflict.yours.content,
        choices,
      );
      if (!merge.complete || merge.content === null) throw new TypeError("CONFLICT_MERGE_INCOMPLETE");
      const mergedSections = sectionsFromContent(selected.resource_type, merge.content);
      const mergedIsDirty = !diffEditorVersionContent(
        conflict.current.content,
        merge.content,
      ).equal;
      setSections(mergedSections);
      setDirty(mergedIsDirty);
      if (!mergedIsDirty) {
        sessionStorage.removeItem(scratchKey(selected));
      } else if (!persistEditorScratchToStorage(sessionStorage, selected, mergedSections)) {
        setError({ code: "SCRATCH_PERSIST_FAILED", traceId: null });
        setConflict(null);
        setNotice("合并结果已载入编辑器，但无法保存在当前标签页；请立即检查并保存到服务端。");
        return;
      }
      setConflict(null);
      setError(null);
      setNotice(mergedIsDirty
        ? "合并结果已放到最新服务端基线并保存在当前标签页；请逐项复核后显式保存。"
        : "合并结果与服务器当前版本相同；编辑器没有制造新的未保存修改。");
    } catch {
      setError({ code: "CONFLICT_MERGE_INVALID", traceId: null });
      setNotice("冲突选择无法安全形成完整内容；页面没有修改编辑器或发送写请求，请重新逐项选择。");
    }
  }

  const requestSelectedWorkspace = useCallback((path: string, init?: RequestInit) => {
    if (!selectedWorkspace) throw new TypeError("WORKSPACE_REQUIRED");
    return requestWorkspaceJson(selectedWorkspace.workspace_id, path, init);
  }, [selectedWorkspace]);

  const receiveAppealHandoff = useCallback((candidate: AppealHandoff) => {
    const workspace = selectedWorkspace;
    if (
      !session
      || !workspace
      || workspace.workspace_kind !== "ORGANIZATION"
      || !workspace.role_codes.includes("DEMAND_OWNER")
      || pendingRef.current !== null
      || logoutIntentRef.current !== null
      || !isAppealHandoffCurrent(candidate, {
        sessionId: session.session.session_id,
        workspaceId: workspace.workspace_id,
      })
    ) {
      setAppealHandoff(null);
      setAppealTaskTarget(null);
      setError({ code: "APPEAL_HANDOFF_STALE_OR_MISMATCHED", traceId: null });
      setNotice("同会话交接已拒绝：会话、Demand Owner 工作区、写入门闩或申诉期限不再匹配。");
      return;
    }
    setAppealTaskTarget(null);
    setAppealHandoff(candidate);
    setError(null);
    setNotice("已建立仅内存的同会话交接；Appeal 工作台将先 GET 查重与核对 eligibility，不会自动 POST。");
  }, [selectedWorkspace, session]);

  const clearAppealHandoff = useCallback(() => {
    setAppealHandoff(null);
  }, []);

  const canCreateProfile = Boolean(
    configuration && selectedWorkspace?.role_codes.includes("CREATOR"),
  );
  const canCreateDemand = Boolean(
    configuration && selectedWorkspace?.role_codes.includes("DEMAND_OWNER"),
  );
  const canAdminAccounts = Boolean(
    selectedWorkspace?.workspace_kind === "PLATFORM"
    && selectedWorkspace?.role_codes.includes("ACCESS_ADMIN")
    && accountScope,
  );
  const canReviewDemands = Boolean(
    selectedWorkspace?.workspace_kind === "PLATFORM"
    && selectedWorkspace?.role_codes.includes("OPERATIONS_REVIEWER")
    && reviewQueueScope,
  );
  const canReviewFunding = Boolean(
    selectedWorkspace?.workspace_kind === "PLATFORM"
    && selectedWorkspace?.role_codes.includes("FINANCE_OPERATOR")
    && financeFundingScope,
  );
  const canAdminOrganization = Boolean(
    selectedWorkspace?.workspace_kind === "ORGANIZATION"
    && selectedWorkspace?.role_codes.includes("ORG_ADMIN"),
  );
  const canUseTrust = Boolean(
    selectedWorkspace?.role_codes.includes("DEMAND_OWNER")
    || (selectedWorkspace?.workspace_kind === "PLATFORM" && selectedWorkspace?.role_codes.includes("TRUST_OFFICER")),
  );
  const canUseAppeal = Boolean(
    (selectedWorkspace?.workspace_kind === "ORGANIZATION" && selectedWorkspace?.role_codes.includes("DEMAND_OWNER"))
    || (selectedWorkspace?.workspace_kind === "PLATFORM" && selectedWorkspace?.role_codes.includes("APPEAL_REVIEWER")),
  );
  const canUseMatching = Boolean(
    (selectedWorkspace?.workspace_kind === "PERSONAL" && selectedWorkspace?.role_codes.includes("CREATOR"))
    || (selectedWorkspace?.workspace_kind === "ORGANIZATION" && selectedWorkspace?.role_codes.includes("DEMAND_OWNER")),
  );
  const canReviewMatching = Boolean(
    selectedWorkspace?.workspace_kind === "PLATFORM"
    && selectedWorkspace?.role_codes.includes("OPERATIONS_REVIEWER"),
  );

  if (phase === "LOADING") return (
    <main className="centered-screen" aria-live="polite">
      <span className="loading-mark" aria-hidden="true">愿</span>
      <p className="eyebrow">INTERNAL_SANDBOX · G1 NO-GO · G2 NO-GO</p>
      <h1 ref={mainTitleRef} tabIndex={-1}>正在建立可信工作区</h1>
      <p>{notice}</p>
      <small>账号、角色、对象与权限均由服务端返回。</small>
    </main>
  );

  if (phase === "SIGNED_OUT") return (
    <main className="login-page">
      <section className="login-intro">
        <div className="brand brand--large"><span>愿</span><strong>愿作</strong></div>
        <p className="eyebrow">INTERNAL_SANDBOX · PRE-PROVISIONED OR INVITED</p>
        <h1 ref={mainTitleRef} tabIndex={-1}>受邀账号工作台</h1>
        <p>当前仅用于 G1 内部试运行。请使用配置的 OIDC 身份提供方登录；这里不提供公开注册、密码账号、邀请令牌输入或浏览器自授角色。</p>
        <ul>
          <li>只使用虚构、合成、可删除的研究资料。</li>
          <li>G1 NO-GO：未获准开展真人研究。</li>
          <li>G2 NO-GO：不得接入真实交易、合同或资金。</li>
        </ul>
      </section>
      <form className="persona-panel auth-panel" onSubmit={beginSignIn}>
        <div>
          <p className="eyebrow">受控登录</p>
          <h2>继续到身份提供方</h2>
          <p>直接登录只接受十个已预置账号；受邀的新需求方负责人请从原邀请链接进入。其他未知身份会被服务端拒绝且不会创建账号。登录后的业务资料仍必须是可删除的合成资料。</p>
        </div>
        <button className="primary-button" disabled={busy} type="submit">{busy ? "正在建立登录…" : "通过 OIDC 登录"}</button>
        <ErrorNotice error={error} />
      </form>
    </main>
  );

  if (phase === "INVITATION_ACCEPTANCE") {
    if (!session || !invitationContext) return (
      <main className="centered-screen" aria-live="polite">
        <span className="loading-mark loading-mark--error" aria-hidden="true">!</span>
        <p className="eyebrow">INVITATION · FAIL CLOSED</p>
        <h1 ref={mainTitleRef} tabIndex={-1}>邀请恢复上下文不可用</h1>
        <p>页面没有邀请摘要与当前 Session 的闭合组合，因此不会尝试激活成员资格。</p>
        <button className="primary-button" type="button" onClick={() => void loadWorkspace()}>返回工作台</button>
      </main>
    );
    return <InvitationAcceptance
      context={invitationContext}
      session={session}
      onAccepted={async () => { await loadWorkspace(); }}
      onCancel={async () => {
        sessionStorage.removeItem(PENDING_INVITATION_CONTEXT_KEY);
        sessionStorage.removeItem(PENDING_INVITATION_ACCEPTANCE_KEY);
        setInvitationContext(null);
        await loadWorkspace();
      }}
    />;
  }

  if (phase === "POLICY_ACCEPTANCE") {
    if (!me || !session || !activePolicyRequirement || !policyBundle) return (
      <main className="centered-screen" aria-live="polite">
        <span className="loading-mark loading-mark--error" aria-hidden="true">!</span>
        <p className="eyebrow">POLICY · FAIL CLOSED</p>
        <h1 ref={mainTitleRef} tabIndex={-1}>政策要求暂不可用</h1>
        <p>页面没有完整、可验证的服务端政策包，因此不会进入工作区。</p>
        <button className="primary-button" type="button" onClick={() => void loadWorkspace()}>重新核对</button>
      </main>
    );
    const missingDocumentIds = new Set(activePolicyRequirement.missing_document_ids);
    const allAffirmed = activePolicyRequirement.missing_document_ids.every((documentId) => affirmedPolicyDocumentIds.includes(documentId));
    const remainingRequirements = me.policy_requirements.filter((requirement) => !requirement.satisfied).length;
    return (
      <>
        <div className="environment-banner">INTERNAL_SANDBOX · 预置账号政策确认 · G1 NO-GO · G2 NO-GO · 不授权真人研究、真实合同、资金或支付</div>
        <main className="policy-page" aria-live="polite">
          <header className="policy-intro">
            <div className="brand brand--large"><span>愿</span><strong>愿作</strong></div>
            <p className="eyebrow">FIRST LOGIN · SERVER REQUIRED · FAIL CLOSED</p>
            <h1 ref={mainTitleRef} tabIndex={-1}>首次登录政策确认</h1>
            <p>只有服务端标记为未满足的账号会看到此页。确认完成并重新读取 `/v1/me` 之前，页面不会请求工作区或业务对象。</p>
          </header>

          <section className="policy-authority" aria-label="服务端政策要求">
            <div><span>当前账号</span><strong>{me.display_handle}</strong></div>
            <div><span>适用职责</span><strong>{activePolicyRequirement.role}</strong></div>
            <div><span>要求用途</span><strong>{activePolicyRequirement.purpose}</strong></div>
            <div><span>待处理要求</span><strong>{remainingRequirements}</strong></div>
            <div className="policy-authority__wide"><span>要求 selector digest</span><code>{activePolicyRequirement.selector_digest}</code></div>
            <div className="policy-authority__wide"><span>政策包</span><code>{policyBundle.policy_bundle_id}</code></div>
          </section>

          <div className="live-notice" aria-live="polite"><strong>状态</strong><span>{notice}</span></div>
          <ErrorNotice error={error} />
          {policyAcceptanceIntent && <div className="unknown-panel policy-retry" role="status">
            <div>
              <p className="eyebrow">OUTCOME UNKNOWN</p>
              <h2>保留同一笔接受请求</h2>
              <p>正文、摘要、User ETag、CSRF 和幂等键均已冻结；再次提交只会原样重试。</p>
            </div>
          </div>}

          <form className="policy-form" onSubmit={acceptCurrentPolicy}>
            <section className="policy-bundle-summary">
              <div><span>管辖域</span><strong>{policyBundle.jurisdiction}</strong></div>
              <div><span>语言</span><strong>{policyBundle.locale}</strong></div>
              <div><span>生效时间</span><strong>{formatTime(policyBundle.effective_at)}</strong></div>
              <div><span>不可变版本</span><code>{policyBundle.entity_tag}</code></div>
            </section>

            <div className="policy-documents">
              {policyBundle.documents.map((document, index) => {
                const required = missingDocumentIds.has(document.document_id);
                const affirmed = affirmedPolicyDocumentIds.includes(document.document_id);
                return <article className={`policy-document${required ? " policy-document--required" : ""}`} key={document.document_id}>
                  <header>
                    <div>
                      <p className="eyebrow">政策正文 {index + 1} · {document.kind}</p>
                      <h2>{POLICY_LEGAL_EFFECT_LABELS[document.legal_effect] ?? document.legal_effect}</h2>
                    </div>
                    <span className="status">v{document.semantic_version}</span>
                  </header>
                  <dl>
                    <div><dt>法律效果</dt><dd>{POLICY_LEGAL_EFFECT_LABELS[document.legal_effect] ?? document.legal_effect}</dd></div>
                    <div><dt>文档 ID</dt><dd><code>{document.document_id}</code></dd></div>
                    <div className="policy-document__digest"><dt>内容 SHA-256</dt><dd><code>{document.content_sha256}</code></dd></div>
                  </dl>
                  <pre className="policy-body">{document.body}</pre>
                  {required ? <label className="policy-affirmation" htmlFor={`policy-affirmation-${index}`}>
                    <input
                      aria-label={`明确接受政策文档 ${document.document_id}`}
                      checked={affirmed}
                      disabled={busy || policyAcceptanceIntent !== null}
                      id={`policy-affirmation-${index}`}
                      type="checkbox"
                      onChange={(event) => setAffirmedPolicyDocumentIds((current) => event.target.checked
                        ? [...current.filter((item) => item !== document.document_id), document.document_id]
                        : current.filter((item) => item !== document.document_id))}
                    />
                    <span><strong>我已阅读并明确接受这份政策正文</strong><small>此勾选仅绑定上方文档 ID 与 SHA-256，不授权任何可选研究或数据处理同意。</small></span>
                  </label> : <p className="policy-not-required">本项不是当前 requirement 的缺失必需文档；此页不会替你授予可选同意。</p>}
                </article>;
              })}
            </div>

            <footer className="policy-actions">
              <div>
                <strong>{allAffirmed ? "所有缺失必需文档均已明确勾选" : "请逐份阅读并勾选所有缺失必需文档"}</strong>
                <small>提交将绑定当前 User {me.entity_tag}、当前会话 CSRF 和一枚独立幂等键。</small>
              </div>
              <button className="primary-button" disabled={busy || !allAffirmed} type="submit">
                {busy ? "正在确认…" : policyAcceptanceIntent ? "原样重试接受请求" : "接受并重新核对权限"}
              </button>
              {!policyAcceptanceIntent && <button className="quiet-button" disabled={busy} type="button" onClick={() => void loadWorkspace()}>重新读取政策要求</button>}
              <button className="quiet-button" disabled={busy || policyAcceptanceIntent !== null} type="button" onClick={() => void logoutCurrentSession()}>
                {logoutIntent ? "原样重试退出" : "退出登录"}
              </button>
            </footer>
          </form>
        </main>
      </>
    );
  }

  if (phase === "WORKSPACE_SELECTION") return (
    <>
      <div className="environment-banner">INTERNAL_SANDBOX · 仅限受邀内部账号与合成资料 · G1 NO-GO · G2 NO-GO · 禁止真人研究、真实合同、资金与支付</div>
      <main className="workspace-selection-page" aria-live="polite">
        <div className="brand brand--large"><span>愿</span><strong>愿作</strong></div>
        <p className="eyebrow">受控职责范围 · FAIL CLOSED</p>
        <h1 ref={mainTitleRef} tabIndex={-1}>选择工作区</h1>
        <p>{notice}</p>
        {workspaces.length > 0 ? <div className="workspace-chooser" aria-label="可用工作区">
          {workspaces.map((workspace) => <button
            className="workspace-choice"
            disabled={busy || pendingOwner !== null || logoutIntent !== null}
            key={workspace.workspace_id}
            type="button"
            onClick={() => void switchWorkspace(workspace.workspace_id)}
          >
            <span>{workspaceLabel(workspace)}</span>
            <strong>{workspace.role_codes.join(" · ")}</strong>
            <code>{workspace.workspace_id}</code>
          </button>)}
        </div> : <div className="empty-state">没有服务端返回的有效工作区；页面不会从 /v1/me 聚合角色自行构造一个。</div>}
        <ErrorNotice error={error} />
        <button className="quiet-button" disabled={busy || pendingOwner !== null || logoutIntent !== null} type="button" onClick={refreshWorkspaceSafely}>重新发现工作区</button>
        <button className="quiet-button" disabled={busy || pendingOwner !== null} type="button" onClick={() => void logoutCurrentSession()}>
          {logoutIntent ? "原样重试退出" : "退出登录"}
        </button>
        {session && me && <SessionManager
          key={`session-manager:${session.session.session_id}:${me.user_id}`}
          accountUserId={me.user_id}
          bootstrapSessionId={session.session.session_id}
          claimWrite={claimSessionWrite}
          csrfToken={session.csrf_token}
          locked={logoutIntent !== null || (pendingOwner !== null && pendingOwner !== "SESSION") || (busy && pendingOwner !== "SESSION")}
          logoutOutcomeUnknown={logoutIntent !== null}
          onGlobalBusyChange={setSessionWriteBusy}
          onLogoutCurrent={logoutCurrentSession}
          releaseWrite={releaseSessionWrite}
          request={requestJson}
        />}
      </main>
    </>
  );

  if (phase === "UNAVAILABLE") return (
    <main className="centered-screen" aria-live="polite">
      <span className="loading-mark loading-mark--error" aria-hidden="true">!</span>
      <p className="eyebrow">INTERNAL_SANDBOX · FAIL CLOSED</p>
      <h1 ref={mainTitleRef} tabIndex={-1}>工作区暂不可用</h1>
      <p>{notice}</p>
      <ErrorNotice error={error} />
      <button className="primary-button" type="button" onClick={() => void loadWorkspace()}>重新核对</button>
    </main>
  );

  const resources = [...profiles, ...demands];
  return (
    <>
      <a className="skip-link" href="#pilot-main">跳到主要内容</a>
      <div className="environment-banner">INTERNAL_SANDBOX · 仅限受邀内部账号与合成资料 · G1 NO-GO · G2 NO-GO · 禁止真人研究、真实合同、资金与支付</div>
      <header className="app-header">
        <a className="brand" href="#pilot-main"><span>愿</span><strong>愿作</strong></a>
        <div className="identity-summary">
          <span>当前服务端会话</span>
          <strong>{me?.display_handle ?? session?.user_status ?? "UNKNOWN"}</strong>
          <small><code>{session ? shortId(session.session.session_id) : "—"}</code></small>
        </div>
        <div className="header-actions">
          {workspaces.length > 1 && selectedWorkspace && <label className="workspace-switcher">
            <span>切换工作区</span>
            <select
              aria-label="切换工作区"
              disabled={busy || pendingOwner !== null || logoutIntent !== null || organizationPublicNameDirty}
              value={selectedWorkspace.workspace_id}
              onChange={(event) => void switchWorkspace(event.target.value)}
            >
              {workspaces.map((workspace) => <option key={workspace.workspace_id} value={workspace.workspace_id}>
                {workspaceLabel(workspace)} · {workspace.role_codes.join(" + ")}
              </option>)}
            </select>
          </label>}
          <button className="quiet-button" disabled={busy || pendingOwner !== null || logoutIntent !== null || organizationPublicNameDirty} type="button" onClick={refreshWorkspaceSafely}>刷新权限与对象</button>
          <button
            className="quiet-button"
            disabled={busy || pendingOwner !== null}
            title={pendingOwner !== null ? "请先处理结果未知的写入" : undefined}
            type="button"
            onClick={() => void logoutCurrentSession()}
          >{logoutIntent ? "原样重试退出" : "退出登录"}</button>
        </div>
      </header>

      <div className="pilot-layout">
        <aside className="workspace-rail" aria-label="对象工作区">
          <p className="eyebrow">服务端可见对象</p>
          <h2>{selectedWorkspace ? workspaceLabel(selectedWorkspace) : "工作区"}</h2>
          {selectedWorkspace && <div className="workspace-authority">
            <code>{shortId(selectedWorkspace.workspace_id)}</code>
            <span>{selectedWorkspace.role_codes.join(" · ")}</span>
          </div>}
          {profileScope && <ResourceGroup disabled={busy || pendingOwner !== null || logoutIntent !== null} title="创作者画像" resources={profiles} selectedId={selected?.object_id} onOpen={openResource} />}
          {demandScope && <ResourceGroup disabled={busy || pendingOwner !== null || logoutIntent !== null} title="需求与审核" resources={demands} selectedId={selected?.object_id} onOpen={openResource} />}
          {canCreateDemand && <button
            aria-pressed={demandCreationOpen}
            className="rail-create-button"
            disabled={busy || pendingOwner !== null || logoutIntent !== null}
            title={pendingOwner !== null || logoutIntent !== null ? "请先处理结果未知的写入" : undefined}
            type="button"
            onClick={beginDemandCreation}
          >＋ 新建需求</button>}
          {canReviewDemands && <ReviewQueueGroup
            busy={busy}
            items={reviewQueue}
            onClaim={claimReview}
            onRefresh={reloadReviewQueue}
          />}
          {canReviewFunding && <FinanceFundingQueueGroup
            busy={busy}
            items={financeFundingQueue}
            selectedId={selectedFinanceReview?.funding_review_id}
            onOpen={claimFinanceFundingReview}
            onRefresh={reloadFinanceFundingQueue}
          />}
          {canAdminAccounts && <AccountGroup accounts={accounts} selectedId={selectedAccount?.user_id} onOpen={openAccount} />}
          {!profileScope && !demandScope && !canReviewDemands && !canReviewFunding && !canAdminAccounts && !canAdminOrganization && !canUseTrust && !canUseAppeal && !canUseMatching && !canReviewMatching && <p className="empty-state">当前账号没有编辑器角色。请联系 ACCESS_ADMIN 核对受邀职责。</p>}
        </aside>

        <main className="pilot-main" id="pilot-main">
          <section className="pilot-overview">
            <div>
              <p className="eyebrow">独立角色账号 · 服务端权限 · 可版本化编辑</p>
              <h1 ref={mainTitleRef} tabIndex={-1}>内部试运行工作台</h1>
              <p>每次写入都绑定当前对象 ETag、Session CSRF 和独立幂等键；页面只执行服务端明确授予的 capability。</p>
            </div>
            <div className="gate-card">
              <strong>研究边界仍然关闭</strong>
              <span>本平台可用于内部操作演练，但这不等于 G1 或 G2 已通过。</span>
            </div>
          </section>

          <div className="live-notice" aria-live="polite"><strong>状态</strong><span>{notice}</span></div>
          <ErrorNotice error={error} />

          {selectedWorkspace && <CurrentAccountTaskPanel
            busy={taskBusy}
            discovery={taskDiscovery}
            error={taskError}
            locked={busy || pendingOwner !== null || logoutIntent !== null}
            onOpen={openCurrentAccountTask}
            onRefresh={refreshTasksSafely}
          />}

          {canReviewDemands && selectedWorkspace && <ReviewHistoryPanel
            key={`review-history:${selectedWorkspace.workspace_id}`}
            workspaceId={selectedWorkspace.workspace_id}
          />}

          {canReviewFunding && selectedWorkspace && <FinanceFundingHistoryPanel
            key={`finance-funding-history:${selectedWorkspace.workspace_id}`}
            busy={busy || pendingOwner !== null || logoutIntent !== null}
            workspaceId={selectedWorkspace.workspace_id}
            onOpen={openFinanceFundingHistoryItem}
          />}

          {logoutIntent && <section className="unknown-panel" aria-labelledby="logout-pending-title">
            <div>
              <p className="eyebrow">SESSION LOGOUT OUTCOME UNKNOWN</p>
              <h2 id="logout-pending-title">退出结果尚未确认</h2>
              <p>页面保留了同一当前 Session、CSRF 与幂等键。原样重试不会扩展成撤销全部会话。</p>
              <small>保存时间：{formatTime(logoutIntent.saved_at)}</small>
            </div>
            <div className="recovery-actions">
              <button className="primary-button" disabled={busy} type="button" onClick={() => void logoutCurrentSession()}>原样重试退出</button>
              <button className="quiet-button" disabled={busy} type="button" onClick={() => {
                persistLogoutIntent(null);
                setNotice("已放弃浏览器中的退出恢复对象；页面没有据此推断服务端会话状态。");
              }}>放弃退出恢复</button>
            </div>
          </section>}

          {pending && <section className="unknown-panel" aria-labelledby="pending-title">
            <div>
              <p className="eyebrow">WRITE OUTCOME UNKNOWN</p>
              <h2 id="pending-title">发现一笔未确认写入</h2>
              <p>“{pending.label}”的原请求已保留在当前标签页。重试会复用同一幂等键和完全相同的载荷。</p>
              <small>保存时间：{formatTime(pending.saved_at)}</small>
            </div>
            <div className="recovery-actions">
              <button className="primary-button" disabled={busy} type="button" onClick={() => void performWrite(pending)}>原样重试</button>
              <button className="quiet-button" disabled={busy} type="button" onClick={() => { persistPending(null); setNotice("已人工放弃浏览器中的未确认请求；服务端事实未被改写。"); }}>放弃恢复</button>
            </div>
          </section>}

          {session && me && <SessionManager
            key={`session-manager:${session.session.session_id}:${me.user_id}`}
            accountUserId={me.user_id}
            bootstrapSessionId={session.session.session_id}
            claimWrite={claimSessionWrite}
            csrfToken={session.csrf_token}
            locked={logoutIntent !== null || (pendingOwner !== null && pendingOwner !== "SESSION") || (busy && pendingOwner !== "SESSION")}
            logoutOutcomeUnknown={logoutIntent !== null}
            onGlobalBusyChange={setSessionWriteBusy}
            onLogoutCurrent={logoutCurrentSession}
            releaseWrite={releaseSessionWrite}
            request={requestJson}
          />}

          {conflict && selected && <ConflictPanel
            key={`${selected.resource_type}:${conflict.currentEtag}:${conflict.current.version_id ?? "none"}`}
            conflict={conflict}
            onDiscard={discardConflictEdits}
            onResolve={resolveConflict}
            resourceType={selected.resource_type}
          />}

          {demandCreationOpen && canCreateDemand && <section className="demand-create-panel" aria-labelledby="demand-create-title">
            <form className="starter-card demand-create-card" onSubmit={createDemand}>
              <p className="eyebrow">DEMAND OWNER</p>
              <h2 id="demand-create-title">创建合成需求</h2>
              <p>创建后会自动打开服务端返回的新需求，再通过十三个结构化分区补全、保存并提交审核。</p>
              {configuration && <ApprovedTaxonomy configuration={configuration} />}
              <label>合成案例引用<input required value={createReference} onChange={(event) => setCreateReference(event.target.value)} placeholder="synthetic-case-001" /></label>
              <label>到期时间<input required type="datetime-local" value={createExpiry} onChange={(event) => setCreateExpiry(event.target.value)} /></label>
              <div className="editor-actions">
                <button className="primary-button" disabled={busy || pendingOwner !== null || logoutIntent !== null} type="submit">创建需求</button>
                <button className="quiet-button" disabled={busy || pendingOwner !== null || logoutIntent !== null} type="button" onClick={() => setDemandCreationOpen(false)}>取消</button>
              </div>
            </form>
          </section>}

          {canAdminOrganization && session && me && selectedWorkspace && <OrganizationAdminWorkbench
            claimWrite={claimOrganizationWrite}
            me={me}
            onDirtyChange={setOrganizationPublicNameDirty}
            releaseWrite={releaseOrganizationWrite}
            session={session}
            workspace={selectedWorkspace}
            writeLocked={busy || logoutIntent !== null || (pendingOwner !== null && pendingOwner !== "ORGANIZATION")}
          />}

          {canUseTrust && session && selectedWorkspace && <TrustWorkbench
            key={`trust-workbench:${selectedWorkspace.workspace_id}`}
            caseHistoryTaskTarget={trustCaseHistoryTaskTarget}
            claimWrite={claimTrustWrite}
            demands={demands}
            demandsAvailable={demandScope}
            onBeginAppeal={receiveAppealHandoff}
            releaseWrite={releaseTrustWrite}
            request={requestSelectedWorkspace}
            session={session}
            workspace={selectedWorkspace}
            writeLocked={busy || logoutIntent !== null || (pendingOwner !== null && pendingOwner !== "TRUST")}
          />}

          {canUseAppeal && session && selectedWorkspace && <AppealWorkbench
            key={`appeal-workbench:${selectedWorkspace.workspace_id}`}
            claimWrite={claimAppealWrite}
            handoff={appealHandoff}
            onClearHandoff={clearAppealHandoff}
            releaseWrite={releaseAppealWrite}
            request={requestSelectedWorkspace}
            session={session}
            taskTarget={appealTaskTarget}
            workspace={selectedWorkspace}
            writeLocked={busy || logoutIntent !== null || (pendingOwner !== null && pendingOwner !== "APPEAL")}
          />}

          {canUseMatching && session && selectedWorkspace && <MatchingWorkbench
            key={`matching-workbench:${selectedWorkspace.workspace_id}`}
            claimWrite={claimMatchingWrite}
            demands={demands}
            demandsAvailable={demandScope}
            releaseWrite={releaseMatchingWrite}
            request={requestJson}
            session={session}
            workspace={selectedWorkspace}
            writeLocked={busy || logoutIntent !== null || (pendingOwner !== null && pendingOwner !== "MATCHING")}
          />}

          {canReviewMatching && session && selectedWorkspace && <MatchingReviewWorkbench
            key={`matching-review-workbench:${selectedWorkspace.workspace_id}`}
            claimWrite={claimMatchingWrite}
            releaseWrite={releaseMatchingWrite}
            request={requestJson}
            session={session}
            workspace={selectedWorkspace}
            writeLocked={busy || logoutIntent !== null || (pendingOwner !== null && pendingOwner !== "MATCHING")}
          />}

          {!demandCreationOpen && !selected && !selectedAccount && !selectedFinanceReview && <section className="starter-grid" aria-label="选择或创建对象">
            {canAdminOrganization && <article className="starter-card">
              <p className="eyebrow">ORG_ADMIN</p>
              <h2>组织权限管理</h2>
              <p>上方工作台直接读取 IAM 组织、成员资格和邀请投影。邀请能力只在签发成功的当前页面内存中出现一次。</p>
            </article>}
            {canReviewDemands && <article className="starter-card">
              <p className="eyebrow">OPERATIONS REVIEWER</p>
              <h2>审核队列</h2>
              <p>左侧只显示服务端返回的最小队列投影。领取成功后才会读取需求正文；整改后重提必须再次领取，旧分配不会复用。</p>
              <button className="primary-button" disabled={busy} type="button" onClick={() => void reloadReviewQueue()}>刷新审核队列</button>
            </article>}
            {canAdminAccounts && <article className="starter-card">
              <p className="eyebrow">ACCESS_ADMIN</p>
              <h2>账号管理</h2>
              <p>从左侧选择一个预置账号。页面只展示 IAM 返回的闭合投影，并在每次操作前绑定当前 ETag、会话 CSRF 和独立幂等键。</p>
            </article>}
            {canReviewFunding && <article className="starter-card">
              <p className="eyebrow">FINANCE OPERATOR · SYNTHETIC ONLY</p>
              <h2>资金确认队列</h2>
              <p>这里只记录零真实资金的合成证据确认；需要两名独立 Finance Operator 分别领取和明确确认，不代表真实到账、支付、托管或法律承诺。</p>
              <button className="primary-button" disabled={busy} type="button" onClick={() => void reloadFinanceFundingQueue()}>刷新资金确认队列</button>
            </article>}
            {canCreateProfile && profiles.length === 0 && <article className="starter-card">
              <p className="eyebrow">CREATOR</p>
              <h2>创建你的画像</h2>
              <p>先建立空画像，再通过字段、选择项和可增删条目填写九个分区。发布前服务端会执行完整校验。</p>
              <button className="primary-button" disabled={busy} type="button" onClick={createProfile}>创建画像</button>
            </article>}
            {canCreateDemand && <article className="starter-card">
              <p className="eyebrow">DEMAND OWNER</p>
              <h2>创建合成需求</h2>
              <p>从左侧“新建需求”进入独立创建页。已有需求不会遮住入口，创建完成后会自动打开服务端新对象。</p>
              <button className="primary-button" disabled={busy || pendingOwner !== null || logoutIntent !== null} type="button" onClick={beginDemandCreation}>新建需求</button>
            </article>}
            {resources.length === 0 && !canCreateProfile && !canCreateDemand && !canReviewDemands && !canReviewFunding && !canAdminAccounts && !canAdminOrganization && !canUseTrust && !canUseAppeal && !canUseMatching && !canReviewMatching && <p className="empty-state">当前账号没有可创建对象，也没有分配中的审核对象。</p>}
          </section>}

          {selectedAccount && <AccountAdminWorkbench
            account={selectedAccount}
            busy={busy || pendingOwner !== null}
            writeLocked={pending !== null || logoutIntent !== null}
            reasonCode={accountReasonCode}
            onReasonCodeChange={setAccountReasonCode}
            onAction={manageAccount}
            onDutyAction={managePlatformDuty}
          />}

          {selectedFinanceReview && <FinanceFundingWorkbench
            attestations={financeAttestationCodes}
            busy={busy}
            findingDisposition={financeFindingDisposition}
            findingFieldCodes={financeFindingFieldCodes}
            findingReasonCodes={financeFindingReasonCodes}
            releaseReasonCode={financeReleaseReasonCode}
            review={selectedFinanceReview}
            onAttestationsChange={setFinanceAttestationCodes}
            onConfirm={confirmFinanceFundingReview}
            onFindingDispositionChange={(value) => {
              setFinanceFindingDisposition(value);
              setFinanceFindingReasonCodes([]);
            }}
            onFindingFieldCodesChange={setFinanceFindingFieldCodes}
            onFindingReasonCodesChange={setFinanceFindingReasonCodes}
            onRelease={releaseFinanceFundingReview}
            onReleaseReasonCodeChange={setFinanceReleaseReasonCode}
            onSubmitFinding={submitFinanceFundingFinding}
          />}

          {selected && <ResourceEditor
            resource={selected}
            titleRef={resourceEditorTitleRef}
            sections={sections}
            configuration={configuration}
            dirty={dirty}
            recoveredScratchAt={recoveredScratchAt}
            busy={busy || pendingOwner !== null || logoutIntent !== null || conflict !== null}
            profilePauseReasonCode={profilePauseReasonCode}
            profileArchiveReasonCode={profileArchiveReasonCode}
            profileArchiveConfirmed={profileArchiveConfirmed}
            demandCancelReasonCode={demandCancelReasonCode}
            demandCancelConfirmed={demandCancelConfirmed}
            reasonCodes={reasonCodes}
            requiredPaths={requiredPaths}
            reviewReleaseReasonCode={reviewReleaseReasonCode}
            budgetHealthCode={budgetHealthCode}
            riskCode={riskCode}
            evidenceCodes={evidenceCodes}
            onSectionChange={(path, value) => { setSections((current) => ({ ...current, [path]: value })); setDirty(true); setRecoveredScratchAt(null); }}
            onSave={saveDraft}
            onAdvance={advanceResource}
            onProfileLifecycle={changeProfileLifecycle}
            onProfilePauseReasonCodeChange={setProfilePauseReasonCode}
            onProfileArchiveReasonCodeChange={(value) => {
              setProfileArchiveReasonCode(value);
              setProfileArchiveConfirmed(false);
            }}
            onProfileArchiveConfirmedChange={setProfileArchiveConfirmed}
            onDemandCancelReasonCodeChange={(value) => {
              setDemandCancelReasonCode(value);
              setDemandCancelConfirmed(false);
            }}
            onDemandCancelConfirmedChange={setDemandCancelConfirmed}
            onDemandCancel={cancelDemand}
            onReasonCodesChange={setReasonCodes}
            onRequiredPathsChange={setRequiredPaths}
            onRecordFindings={recordFindings}
            onReviewReleaseReasonCodeChange={setReviewReleaseReasonCode}
            onReleaseReviewAssignment={releaseReviewAssignment}
            onBudgetHealthCodeChange={setBudgetHealthCode}
            onRiskCodeChange={setRiskCode}
            onEvidenceCodesChange={setEvidenceCodes}
            onVerifyDemand={verifyDemand}
          />}
        </main>
      </div>
    </>
  );
}

const CURRENT_ACCOUNT_TASK_GROUPS = [
  { classification: "NEEDS_ACTION", label: "待处理" },
  { classification: "WAITING", label: "等待中" },
  { classification: "COMPLETED", label: "已完成" },
] as const;

function currentAccountTaskKindLabel(kind: CurrentAccountTask["resource_kind"]) {
  return ({
    APPEAL: "我的申诉",
    APPEAL_REVIEW: "申诉复核",
    CREATOR_PROFILE: "创作者画像",
    DEMAND: "需求",
    DEMAND_REVIEW: "需求审核",
    FINANCE_FUNDING_REVIEW: "合成资金确认",
    TRUST_CASE: "Trust 案件",
    TRUST_HOLD_RELEASE: "Trust 保护解除",
    TRUST_REPORT: "我的安全报告",
  } as Record<CurrentAccountTask["resource_kind"], string>)[kind];
}

function currentAccountTaskActionLabel(action: CurrentAccountTask["next_action"]) {
  return ({
    CLAIM_APPEAL_REVIEW: "领取申诉复核",
    CLAIM_DEMAND_REVIEW: "领取需求审核",
    CLAIM_FINANCE_REVIEW: "领取合成资金确认",
    CLAIM_TRUST_CASE: "领取 Trust 案件",
    CLAIM_TRUST_HOLD_RELEASE: "领取保护解除复核",
    CONTINUE_FINANCE_REVIEW: "继续合成资金确认",
    EDIT_APPEAL: "继续填写申诉",
    EDIT_OR_SUBMIT_DEMAND: "编辑或提交需求",
    REVIEW_ASSIGNED_APPEAL: "处理已分配申诉",
    REVIEW_ASSIGNED_DEMAND: "处理已分配需求",
    REVIEW_ASSIGNED_TRUST_CASE: "处理已分配 Trust 案件",
    REVIEW_ASSIGNED_TRUST_HOLD_RELEASE: "处理已分配保护解除复核",
    VIEW_APPEAL_HISTORY: "查看申诉历史",
    VIEW_APPEAL_REVIEW_HISTORY: "查看我的已完成申诉复核",
    VIEW_CREATOR_PROFILE: "查看画像与历史",
    VIEW_DEMAND_HISTORY: "查看需求历史",
    VIEW_DEMAND_REVIEW_HISTORY: "查看我的审核历史",
    VIEW_TRUST_CASE_HISTORY: "查看我完成的 Trust 记录",
    VIEW_TRUST_REPORT_HISTORY: "查看安全报告历史",
    WAIT_FOR_APPEAL_REVIEW: "等待申诉复核",
    WAIT_FOR_DEMAND_PROCESSING: "等待需求后续处理",
    WAIT_FOR_FINANCE_CONFIRMATION: "等待独立资金确认",
    WAIT_FOR_TRUST_REVIEW: "等待 Trust 复核",
  } as Record<CurrentAccountTask["next_action"], string>)[action];
}

function currentAccountTaskButtonLabel(task: CurrentAccountTask) {
  if (task.resource_kind === "CREATOR_PROFILE") return "打开画像";
  if (task.resource_kind === "DEMAND") return "打开需求";
  if (task.next_action === "VIEW_APPEAL_REVIEW_HISTORY") return "查看我的申诉复核历史";
  if (task.next_action === "VIEW_DEMAND_REVIEW_HISTORY") return "查看我的审核历史";
  if (task.next_action === "VIEW_TRUST_CASE_HISTORY") return "查看 Trust 完成记录";
  if (task.resource_kind === "DEMAND_REVIEW" && task.next_action !== "CLAIM_DEMAND_REVIEW") return "打开审核对象";
  if (task.resource_kind === "DEMAND_REVIEW") return "前往审核队列";
  if (task.next_action === "CONTINUE_FINANCE_REVIEW") return "打开当前资金确认";
  if (task.next_action === "WAIT_FOR_FINANCE_CONFIRMATION") return "查看当前资金确认";
  if (task.resource_kind === "FINANCE_FUNDING_REVIEW") return "前往资金确认队列";
  if (task.resource_kind === "TRUST_CASE" || task.resource_kind === "TRUST_HOLD_RELEASE" || task.resource_kind === "TRUST_REPORT") return "前往 Trust 工作台";
  return "前往申诉工作台";
}

function CurrentAccountTaskPanel({
  busy,
  discovery,
  error,
  locked,
  onOpen,
  onRefresh,
}: {
  busy: boolean;
  discovery: CurrentAccountTaskDiscovery | null;
  error: { code: string; traceId: string | null } | null;
  locked: boolean;
  onOpen: (task: CurrentAccountTask) => void;
  onRefresh: () => void;
}) {
  return <section className="current-account-tasks" aria-busy={busy} aria-labelledby="current-account-tasks-title">
    <div className="section-heading task-discovery-heading">
      <div>
        <p className="eyebrow">CURRENT ACCOUNT · SERVER DISCOVERY</p>
        <h2 id="current-account-tasks-title">我的任务与历史</h2>
        <p>仅展示当前账号、当前工作区已授权的服务端投影；入口不会执行任务写入，也不会把内部 API 路径当网页打开。</p>
      </div>
      <button className="quiet-button" disabled={busy || locked} type="button" onClick={onRefresh}>
        {busy ? "正在刷新任务…" : "刷新任务与历史"}
      </button>
    </div>

    {error && <div className="task-discovery-error" role="alert">
      <strong>任务读取未完成：{error.code}</strong>
      <span>{discovery
        ? "下方保留上一次已验证的任务快照；现有画像、需求和角色工作区均未被清空。"
        : "页面没有把读取失败伪造成“暂无任务”；现有画像、需求和角色工作区均未被清空。"}</span>
      {error.traceId && <small>追踪编号：<code>{error.traceId}</code></small>}
    </div>}
    {busy && <p className="task-discovery-progress" role="status">正在读取当前账号的任务与历史；已验证业务对象继续可见。</p>}
    {!busy && !error && discovery === null && <p className="empty-state" role="status">
      {locked ? "请先处理当前结果未知的写入，再刷新任务与历史。" : "任务投影尚未完成读取，请刷新重试。"}
    </p>}
    {discovery?.items.length === 0 && <p className="task-discovery-empty" role="status">当前账号暂无待处理、等待中或已完成的可发现记录。</p>}

    {discovery && discovery.items.length > 0 && <div className="task-discovery-groups">
      {CURRENT_ACCOUNT_TASK_GROUPS.map((group) => {
        const items = discovery.items.filter((item) => item.classification === group.classification);
        const titleId = `task-group-${group.classification.toLowerCase().replaceAll("_", "-")}`;
        return <section className={`task-discovery-group task-discovery-group--${group.classification.toLowerCase().replaceAll("_", "-")}`} aria-labelledby={titleId} key={group.classification}>
          <h3 id={titleId}>{group.label}<span>{items.length}</span></h3>
          {items.length === 0
            ? <p className="task-group-empty">本组暂无记录</p>
            : <ol>
              {items.map((task) => <li key={`${task.resource_kind}:${task.resource_id}`}>
                <article className="task-discovery-card">
                  <div className="task-discovery-card__heading">
                    <div><small>{currentAccountTaskKindLabel(task.resource_kind)}</small><strong>{currentAccountTaskActionLabel(task.next_action)}</strong></div>
                    <span className="status">{statusLabel(task.source_status)}</span>
                  </div>
                  <dl>
                    <div><dt>记录编号</dt><dd><code>{shortId(task.resource_id)}</code></dd></div>
                    {task.updated_at && <div><dt>最近更新</dt><dd><time dateTime={task.updated_at}>{formatTime(task.updated_at)}</time></dd></div>}
                    {task.due_at && <div><dt>处理期限</dt><dd><time dateTime={task.due_at}>{formatTime(task.due_at)}</time></dd></div>}
                  </dl>
                  <button className="task-discovery-action" disabled={busy || locked} type="button" onClick={() => onOpen(task)}>
                    {currentAccountTaskButtonLabel(task)}
                  </button>
                </article>
              </li>)}
            </ol>}
        </section>;
      })}
    </div>}
    {discovery?.has_more && <p className="task-discovery-more" role="status">服务端还有更多历史记录。本面板不会猜测或补齐；请进入对应角色工作台继续查看已授权分页。</p>}
  </section>;
}

function ReviewQueueGroup({
  items,
  busy,
  onClaim,
  onRefresh,
}: {
  items: EditorReviewQueueItem[];
  busy: boolean;
  onClaim: (item: EditorReviewQueueItem) => void;
  onRefresh: () => void;
}) {
  return (
    <section className="resource-group review-queue-group" aria-labelledby="review-queue-title">
      <div className="resource-group-heading">
        <h3 id="review-queue-title" tabIndex={-1}>审核队列<span>{items.length}</span></h3>
        <button className="text-button" disabled={busy} type="button" onClick={onRefresh}>刷新</button>
      </div>
      {items.length === 0 && <p>暂无可领取需求；需求方整改重提后请刷新。</p>}
      {items.map((item) => <button
        aria-label={`领取审核需求 ${item.demand_id}`}
        className="resource-link review-queue-link"
        disabled={busy}
        key={`${item.demand_id}:${item.demand_revision}`}
        type="button"
        onClick={() => onClaim(item)}
      >
        <strong>待审核需求 · v{item.demand_version_no}</strong>
        <span>提交：{formatTime(item.submitted_at)}</span>
        <span>需求到期：{formatTime(item.demand_expires_at)}</span>
        <code>{shortId(item.demand_id)} · r{item.demand_revision}</code>
        <b>领取审核</b>
      </button>)}
      <small>队列 ETag 只用于领取；审核决定使用领取后重新读取的资源 ETag。</small>
    </section>
  );
}

function FinanceFundingQueueGroup({
  items,
  busy,
  selectedId,
  onOpen,
  onRefresh,
}: {
  items: FinanceFundingQueueItem[];
  busy: boolean;
  selectedId: string | undefined;
  onOpen: (item: FinanceFundingQueueItem) => void;
  onRefresh: () => void;
}) {
  return (
    <section className="resource-group finance-funding-queue" aria-labelledby="finance-funding-queue-title">
      <div className="resource-group-heading">
        <h3 id="finance-funding-queue-title" tabIndex={-1}>资金确认队列<span>{items.length}</span></h3>
        <button className="text-button" disabled={busy} type="button" onClick={onRefresh}>刷新</button>
      </div>
      {items.length === 0 && <p>暂无已验证且等待零资金合成确认的需求。</p>}
      {items.map((item) => <button
        aria-current={item.funding_review_id === selectedId ? "page" : undefined}
        aria-label={`${item.assigned_to_me ? "打开" : "领取"}资金确认 ${item.demand_id}`}
        className="resource-link finance-funding-link"
        disabled={busy}
        key={`${item.demand_id}:${item.etag}`}
        type="button"
        onClick={() => onOpen(item)}
      >
        <strong>{item.review_status === "AVAILABLE" ? "待开始双人确认" : "双人确认进行中"}</strong>
        <span>独立确认 {item.confirmation_count}/{item.required_confirmations}</span>
        <span>截止：{formatTime(item.expires_at)}</span>
        <code>{shortId(item.demand_id)} · r{item.demand_revision}</code>
        <b>{item.assigned_to_me ? "打开当前分配" : item.review_status === "AVAILABLE" ? "领取资金确认" : "加入双人确认"}</b>
      </button>)}
      <small>队列不展示需求正文、组织或真实资金信息；领取绑定当前队列 ETag。</small>
    </section>
  );
}

function FinanceFundingWorkbench({
  review,
  attestations,
  busy,
  releaseReasonCode,
  findingDisposition,
  findingReasonCodes,
  findingFieldCodes,
  onAttestationsChange,
  onConfirm,
  onReleaseReasonCodeChange,
  onRelease,
  onFindingDispositionChange,
  onFindingReasonCodesChange,
  onFindingFieldCodesChange,
  onSubmitFinding,
}: {
  review: FinanceFundingReview;
  attestations: string[];
  busy: boolean;
  releaseReasonCode: (typeof FINANCE_FUNDING_RELEASE_REASON_CODES)[number];
  findingDisposition: "DISCREPANCY" | "REJECTED";
  findingReasonCodes: string[];
  findingFieldCodes: string[];
  onAttestationsChange: (value: string[]) => void;
  onConfirm: (event: FormEvent) => void;
  onReleaseReasonCodeChange: (value: (typeof FINANCE_FUNDING_RELEASE_REASON_CODES)[number]) => void;
  onRelease: (event: FormEvent) => void;
  onFindingDispositionChange: (value: "DISCREPANCY" | "REJECTED") => void;
  onFindingReasonCodesChange: (value: string[]) => void;
  onFindingFieldCodesChange: (value: string[]) => void;
  onSubmitFinding: (event: FormEvent) => void;
}) {
  const allAttested = FINANCE_FUNDING_ATTESTATION_CODES.every((code) => attestations.includes(code));
  const canConfirm = review.available_actions.includes("CONFIRM");
  const canRelease = review.available_actions.includes("RELEASE_ASSIGNMENT");
  const canSubmitFinding = review.available_actions.includes("SUBMIT_FINDING");
  const findingReasons = findingDisposition === "DISCREPANCY"
    ? FINANCE_FUNDING_DISCREPANCY_REASON_CODES
    : FINANCE_FUNDING_REJECTED_REASON_CODES;
  const labels: Record<string, string> = {
    SYNTHETIC_ONLY: "我确认本案例只含可删除的合成资料",
    ZERO_REAL_FUNDS: "我确认金额固定为零真实资金",
    NO_PROVIDER_OR_PAYMENT: "我确认没有支付提供方、支付操作或到账事实",
    TARGET_AND_EVIDENCE_MATCH: "我已逐项核对目标摘要与证据引用摘要",
  };
  return (
    <section className="finance-funding-workbench" aria-labelledby="finance-funding-title">
      <header className="account-header finance-funding-header">
        <div>
          <p className="eyebrow">FINANCE OPERATOR · FOUR EYES · SYNTHETIC ONLY</p>
          <h2
            data-funding-review-id={review.funding_review_id}
            id="finance-funding-title"
            tabIndex={-1}
          >零真实资金合成确认</h2>
          <p>此动作只记录两名独立 Finance Operator 对固定合成证据的确认；不创建资金、支付、托管、结算、收据或法律承诺。</p>
        </div>
        <strong className="status">{review.status === "SECURED" ? "2/2 已完成" : new Set(["DISCREPANCY", "REJECTED"]).has(review.status) ? `${review.status} 已闭合` : `${review.confirmation_count}/2 进行中`}</strong>
      </header>
      <div className="finance-zero-banner" role="status">
        <strong>实际资金：{review.sandbox_funds_amount_minor} · 零真实资金</strong>
        <span>提供方：<code>{review.provider_code}</code> · 支付操作：<code>{review.payment_operation_code}</code></span>
        <span>法律效果：<code>{review.legal_effect}</code>（固定为 <code>NO_REAL_FUNDS_OR_PAYMENT</code>）</span>
      </div>
      <section className="finance-evidence-summary" aria-labelledby="finance-evidence-summary-title">
        <div>
          <p className="eyebrow">HUMAN-READABLE TARGET · SYNTHETIC PLAN</p>
          <h3 id="finance-evidence-summary-title">本次确认所绑定的目标与证据</h3>
          <p>下面的预算来自该资金审查绑定的不可变需求版本，只是合成计划字段；它不是余额、到账、支付或可支配资金。</p>
        </div>
        <dl className="account-facts finance-evidence-facts">
          <div><dt>资金审查状态</dt><dd><code>{review.status}</code> · r{review.revision}</dd></div>
          <div><dt>不可变需求版本</dt><dd><code>{review.demand_version_id}</code></dd></div>
          <div><dt>计划币种</dt><dd><code>{review.planned_budget_currency}</code></dd></div>
          <div><dt>计划预算范围</dt><dd>{formatSyntheticBudgetAmount(review.planned_budget_minimum_amount_minor, review.planned_budget_currency)} – {formatSyntheticBudgetAmount(review.planned_budget_maximum_amount_minor, review.planned_budget_currency)}</dd></div>
          <div><dt>计划直接成本</dt><dd>{formatSyntheticBudgetAmount(review.planned_budget_direct_cost_amount_minor, review.planned_budget_currency)}</dd></div>
          <div className="finance-digest"><dt>需求内容 SHA-256</dt><dd><code>{review.target_content_sha256}</code></dd></div>
          <div><dt>证据类型</dt><dd><code>{review.evidence_kind}</code></dd></div>
          <div><dt>实际资金</dt><dd>{review.sandbox_funds_amount_minor}（固定为零）</dd></div>
          <div><dt>资金/支付来源</dt><dd><code>{review.provider_code}</code> / <code>{review.payment_operation_code}</code></dd></div>
        </dl>
      </section>
      <dl className="account-facts finance-funding-facts">
        <div><dt>资金确认 ID</dt><dd><code>{review.funding_review_id}</code></dd></div>
        <div><dt>需求 ID</dt><dd><code>{review.demand_id}</code></dd></div>
        <div><dt>需求版本 ID</dt><dd><code>{review.demand_version_id}</code></dd></div>
        <div><dt>当前分配</dt><dd><code>{review.assignment_id}</code></dd></div>
        <div><dt>分配状态</dt><dd><code>{review.assignment_status}</code></dd></div>
        <div><dt>本人已确认</dt><dd>{review.confirmation_by_me ? "是" : "否"}</dd></div>
        <div><dt>当前可用动作</dt><dd>{review.available_actions.length ? review.available_actions.map((action) => <code key={action}>{action} </code>) : "无"}</dd></div>
        <div><dt>分配有效期</dt><dd>{formatTime(review.assignment_expires_at)}</dd></div>
        <div><dt>当前 ETag</dt><dd><code>{review.etag}</code></dd></div>
        <div className="finance-digest"><dt>目标审计摘要</dt><dd><code>{review.target_sha256}</code></dd></div>
        <div className="finance-digest"><dt>证据引用审计摘要</dt><dd><code>{review.evidence_reference_sha256}</code></dd></div>
        <div><dt>独立确认</dt><dd>{review.confirmation_count}/{review.required_confirmations}</dd></div>
      </dl>
      {review.status === "SECURED" ? <div className="finance-complete" role="status">
        <strong>两名独立操作员均已确认</strong>
        <span>平台只完成 INTERNAL_SANDBOX 状态演练；不得据此声称真实到账或支付完成。</span>
      </div> : review.status === "REJECTED" ? <div className="finance-complete" role="status">
        <strong>REJECTED finding 已闭合</strong>
        <span>当前合成审查已经终止，需求已安全回到 NEEDS_CHANGES；没有触发真实资金或支付。</span>
      </div> : review.status === "DISCREPANCY" ? <div className="finance-complete" role="status">
        <strong>DISCREPANCY finding 已闭合</strong>
        <span>当前合成审查已经终止，需求回到 VERIFIED；历史安全摘要仍可由 Demand Owner 查看。</span>
      </div> : new Set(["RELEASED", "EXPIRED", "REVOKED"]).has(review.assignment_status) ? <div className="finance-waiting" role="status">
        <strong>当前分配已终结：{review.assignment_status}</strong>
        <span>该分配不再提供动作；历史事实不会覆盖。请从 fresh 队列领取新的分配。</span>
      </div> : review.confirmation_by_me ? <div className="finance-waiting" role="status">
        <strong>当前账号的独立确认已经记录</strong>
        <span>仍需另一名独立 Finance Operator 领取并确认；同一账号不能提供第二份确认。</span>
      </div> : null}
      {canConfirm && <form className="review-panel finance-attestation-form" onSubmit={onConfirm}>
        <div>
          <p className="eyebrow">EXPLICIT ATTESTATION · OCC + IDEMPOTENCY</p>
          <h2>明确确认四项声明</h2>
          <p>四项都必须由当前分配的操作员亲自勾选；浏览器只发送下面四个固定代码。</p>
        </div>
        <fieldset>
          <legend>零资金证据声明</legend>
          {FINANCE_FUNDING_ATTESTATION_CODES.map((code) => <label key={code}>
            <input
              checked={attestations.includes(code)}
              disabled={busy}
              type="checkbox"
              onChange={(event) => onAttestationsChange(FINANCE_FUNDING_ATTESTATION_CODES.filter((candidate) => (
                candidate === code ? event.target.checked : attestations.includes(candidate)
              )))}
            />
            <span>{labels[code]} <code>{code}</code></span>
          </label>)}
        </fieldset>
        <button className="primary-button" disabled={busy || !allAttested} type="submit">确认合成零资金证据</button>
        <small>提交绑定当前 {review.etag}、Session CSRF 和独立幂等键；第一份确认后仍等待另一账号。</small>
      </form>}
      {canRelease && <form className="review-panel finance-release-form" onSubmit={onRelease}>
        <div>
          <p className="eyebrow">CONTROLLED RELEASE · HISTORY PRESERVED</p>
          <h2>释放当前未确认分配</h2>
          <p>只释放本人当前 ACTIVE 且未确认的席位；不会删除历史，也不会触及资金状态。</p>
        </div>
        <label>释放原因<select
          disabled={busy}
          value={releaseReasonCode}
          onChange={(event) => onReleaseReasonCodeChange(event.target.value as (typeof FINANCE_FUNDING_RELEASE_REASON_CODES)[number])}
        >
          {FINANCE_FUNDING_RELEASE_REASON_CODES.map((code) => <option key={code} value={code}>{code}</option>)}
        </select></label>
        <button disabled={busy} type="submit">释放分配并腾出席位</button>
      </form>}
      {canSubmitFinding && <form className="review-panel finance-finding-form" onSubmit={onSubmitFinding}>
        <div>
          <p className="eyebrow">TERMINAL FINDING · CLOSED TAXONOMY</p>
          <h2>提交资金审查结论</h2>
          <p>DISCREPANCY 回到 VERIFIED；REJECTED 回到 NEEDS_CHANGES。两者都会终结本轮合成审查，且绝不触发支付。</p>
        </div>
        <label>结论<select
          disabled={busy}
          value={findingDisposition}
          onChange={(event) => onFindingDispositionChange(event.target.value as "DISCREPANCY" | "REJECTED")}
        >
          <option value="DISCREPANCY">DISCREPANCY · 证据/目标差异</option>
          <option value="REJECTED">REJECTED · 需要需求方整改</option>
        </select></label>
        <fieldset>
          <legend>闭合原因代码</legend>
          {findingReasons.map((code) => <label key={code}><input
            checked={findingReasonCodes.includes(code)}
            disabled={busy}
            type="checkbox"
            onChange={(event) => onFindingReasonCodesChange(findingReasons.filter((candidate) => (
              candidate === code ? event.target.checked : findingReasonCodes.includes(candidate)
            )))}
          /><span className="sr-only">选择原因代码</span><span><code>{code}</code></span></label>)}
        </fieldset>
        <fieldset>
          <legend>需求方可修改字段组</legend>
          {FINANCE_FUNDING_FINDING_FIELD_CODES.map((code) => <label key={code}><input
            checked={findingFieldCodes.includes(code)}
            disabled={busy}
            type="checkbox"
            onChange={(event) => onFindingFieldCodesChange(FINANCE_FUNDING_FINDING_FIELD_CODES.filter((candidate) => (
              candidate === code ? event.target.checked : findingFieldCodes.includes(candidate)
            )))}
          /><span className="sr-only">选择字段组</span><span><code>{code}</code></span></label>)}
        </fieldset>
        <button className="primary-button" disabled={busy || findingReasonCodes.length === 0 || findingFieldCodes.length === 0} type="submit">提交 {findingDisposition} finding</button>
        <small>提交绑定当前 {review.etag}；Owner 投影只显示闭合原因与映射后的可修改路径，不泄露操作员或分配标识。</small>
      </form>}
    </section>
  );
}

function ResourceGroup({
  disabled,
  title,
  resources,
  selectedId,
  onOpen,
}: {
  disabled: boolean;
  title: string;
  resources: EditorResource[];
  selectedId: string | undefined;
  onOpen: (resource: EditorResource) => void;
}) {
  return (
    <section className="resource-group">
      <h3>{title}<span>{resources.length}</span></h3>
      {resources.length === 0 && <p>暂无可见对象</p>}
      {resources.map((resource) => <button
        aria-current={selectedId === resource.object_id ? "page" : undefined}
        className="resource-link"
        disabled={disabled}
        key={resource.object_id}
        type="button"
        onClick={() => onOpen(resource)}
      >
        <strong>{resource.resource_type === "CREATOR_PROFILE" ? "画像" : "需求"} · v{resource.revision}</strong>
        <span>{statusLabel(resource.status)}</span>
        <code>{shortId(resource.object_id)}</code>
      </button>)}
    </section>
  );
}

function AccountGroup({
  accounts,
  selectedId,
  onOpen,
}: {
  accounts: AccountAdminProjection[];
  selectedId: string | undefined;
  onOpen: (account: AccountAdminProjection) => void;
}) {
  return (
    <section className="resource-group account-group">
      <h3>账号管理<span>{accounts.length}</span></h3>
      {accounts.map((account) => <button
        aria-current={selectedId === account.user_id ? "page" : undefined}
        className="resource-link account-link"
        key={account.user_id}
        type="button"
        onClick={() => onOpen(account)}
      >
        <strong>{account.display_handle}{account.is_self ? " · 当前账号" : ""}</strong>
        <span>{account.account_code} · {accountStatusLabel(account.status)}</span>
        <code>有效会话 {account.active_session_count} · v{account.aggregate_version}</code>
      </button>)}
    </section>
  );
}

function AccountAdminWorkbench({
  account,
  busy,
  writeLocked,
  reasonCode,
  onReasonCodeChange,
  onAction,
  onDutyAction,
}: {
  account: AccountAdminProjection;
  busy: boolean;
  writeLocked: boolean;
  reasonCode: string;
  onReasonCodeChange: (value: string) => void;
  onAction: (action: "SUSPEND" | "RESUME" | "REVOKE_ALL_SESSIONS") => void;
  onDutyAction: (
    dutyCode: "ACCESS_ADMIN" | "APPEAL_REVIEWER" | "FINANCE_OPERATOR" | "OPERATIONS_REVIEWER" | "TRUST_OFFICER",
    action: "GRANT" | "REVOKE",
  ) => void;
}) {
  const actionsDisabled = busy || account.is_self || writeLocked;
  return (
    <section className="account-workbench" aria-labelledby="account-workbench-title">
      <header className="account-header">
        <div>
          <p className="eyebrow">ACCESS_ADMIN · IAM ACCOUNT</p>
          <h2 id="account-workbench-title">{account.display_handle}</h2>
          <p>账号管理操作只针对预置账号；不显示联系方式、外部身份、摘要或组织授权。</p>
        </div>
        <strong className={`account-status account-status--${account.status.toLowerCase()}`}>{accountStatusLabel(account.status)}</strong>
      </header>
      <dl className="account-facts">
        <div><dt>账号代码</dt><dd><code>{account.account_code}</code></dd></div>
        <div><dt>用户 ID</dt><dd><code>{account.user_id}</code></dd></div>
        <div><dt>职责角色</dt><dd>{account.role_codes.length > 0 ? account.role_codes.join(" · ") : "无有效职责"}</dd></div>
        <div><dt>有效会话</dt><dd>{account.active_session_count}</dd></div>
        <div><dt>当前版本</dt><dd>v{account.aggregate_version} · <code>{account.entity_tag}</code></dd></div>
        <div><dt>更新时间</dt><dd>{formatTime(account.updated_at)}</dd></div>
        <div><dt>创建时间</dt><dd>{formatTime(account.created_at)}</dd></div>
      </dl>
      {account.is_self && <div className="account-self-warning" role="status">
        这是当前登录账号。为避免自升权或管理员锁死，页面禁止对自己变更账号状态、会话和平台职责。
      </div>}
      <div className="account-controls">
        <label>
          <span>操作理由</span>
          <select
            disabled={actionsDisabled}
            value={reasonCode}
            onChange={(event) => onReasonCodeChange(event.target.value)}
          >
            {ACCOUNT_ADMIN_REASON_CODES.map((code) => <option key={code} value={code}>{code}</option>)}
          </select>
        </label>
        <div className="account-actions">
          {account.status === "ACTIVE" && <button className="danger-button" disabled={actionsDisabled} type="button" onClick={() => onAction("SUSPEND")}>暂停账号</button>}
          {account.status === "SUSPENDED" && <button className="primary-button" disabled={actionsDisabled} type="button" onClick={() => onAction("RESUME")}>恢复账号</button>}
          <button className="quiet-button" disabled={actionsDisabled} type="button" onClick={() => onAction("REVOKE_ALL_SESSIONS")}>撤销全部会话</button>
        </div>
        <div className="account-duty-controls" aria-label="平台职责配置">
          <strong>平台职责</strong>
          {ACCOUNT_ADMIN_PLATFORM_DUTY_CODES.map((dutyCode) => {
            const granted = account.role_codes.includes(dutyCode);
            return <div className="account-duty-row" key={dutyCode}>
              <code>{dutyCode}</code>
              <span>{granted ? "已授予" : "未授予"}</span>
              <button
                className={granted ? "danger-button" : "quiet-button"}
                disabled={actionsDisabled}
                type="button"
                onClick={() => onDutyAction(dutyCode, granted ? "REVOKE" : "GRANT")}
              >{granted ? "撤销职责" : "授予职责"}</button>
            </div>;
          })}
        </div>
        <small>每次操作使用当前 <code>{account.entity_tag}</code>，服务端再次验证 ACCESS_ADMIN duty、Session 与 SessionFamily。</small>
      </div>
    </section>
  );
}

function ApprovedTaxonomy({ configuration }: { configuration: EditorConfiguration }) {
  const approved = configuration.taxonomy_bundle.status === "CURRENT_APPROVED";
  return <section className="taxonomy-field" aria-label="服务端当前批准分类">
    <dl>
      <div><dt>当前分类版本</dt><dd><code>{configuration.taxonomy_bundle.bundle_id}</code></dd></div>
      <div><dt>配置状态</dt><dd>{approved ? "当前已批准" : "不可用"}</dd></div>
      <div><dt>生效时间</dt><dd>{formatTime(configuration.taxonomy_bundle.effective_at)}</dd></div>
      {configuration.taxonomy_bundle.effective_until && <div>
        <dt>有效期至</dt><dd>{formatTime(configuration.taxonomy_bundle.effective_until)}</dd>
      </div>}
    </dl>
    <small>分类版本由服务端受控配置提供，创建和保存时自动绑定，浏览器不能改写。</small>
  </section>;
}

function defaultVersionComparison(versions: EditorVersion[]) {
  const ordered = [...versions].sort((left, right) => (
    left.version_no - right.version_no || left.version_id.localeCompare(right.version_id)
  ));
  return {
    beforeVersionId: ordered.at(-2)?.version_id ?? "",
    afterVersionId: ordered.at(-1)?.version_id ?? "",
  };
}

function formatDiffValue(value: EditorDiffValue) {
  if (value.value_type === "NULL") return "未填写 / 不适用";
  if (value.value_type === "BOOLEAN") return value.value ? "是" : "否";
  if (value.value_type === "EMPTY_ARRAY") return "空列表";
  if (value.value_type === "EMPTY_OBJECT") return "空对象";
  if (value.value_type === "ARRAY") return `列表（${value.size} 项）`;
  if (value.value_type === "OBJECT") return `对象（${value.size} 个字段）`;
  if (value.value_type === "ITEM_ORDER") return value.value.join(" → ");
  return String(value.value);
}

function VersionComparison({ versions }: { versions: EditorVersion[] }) {
  const defaults = defaultVersionComparison(versions);
  const [selection, setSelection] = useState(defaults);
  if (versions.length < 2) {
    return <section className="version-comparison" aria-labelledby="version-comparison-title">
      <div className="section-heading compact-heading">
        <div><p className="eyebrow">READ-ONLY DIFF</p><h2 id="version-comparison-title">版本内容比较</h2></div>
      </div>
      <p className="empty-state" role="status">至少有两个已授权历史版本后才可比较；当前不会发起额外读取或写入。</p>
    </section>;
  }

  const byId = new Map(versions.map((version) => [version.version_id, version]));
  const beforeVersionId = byId.has(selection.beforeVersionId)
    ? selection.beforeVersionId
    : defaults.beforeVersionId;
  const afterVersionId = byId.has(selection.afterVersionId)
    ? selection.afterVersionId
    : defaults.afterVersionId;
  const before = byId.get(beforeVersionId);
  const after = byId.get(afterVersionId);
  const options = [...versions].sort((left, right) => (
    right.version_no - left.version_no || left.version_id.localeCompare(right.version_id)
  ));

  let comparison: ReturnType<typeof diffEditorVersionContent> | null = null;
  try {
    if (!before || !after) throw new TypeError("VERSION_NOT_AVAILABLE");
    comparison = diffEditorVersionContent(before.content, after.content);
  } catch {
    // Keep the selectors available so one malformed historic projection cannot trap the user.
  }

  const versionOption = (version: EditorVersion) => (
    <option key={version.version_id} value={version.version_id}>
      v{version.version_no} · {statusLabel(version.status)} · {formatTime(version.created_at)}
    </option>
  );

  return <section className="version-comparison" aria-labelledby="version-comparison-title">
    <div className="section-heading compact-heading">
      <div><p className="eyebrow">READ-ONLY DIFF</p><h2 id="version-comparison-title">版本内容比较</h2></div>
      {comparison && <strong>{comparison.changes.length} 项差异</strong>}
    </div>
    <p className="version-comparison__explainer">只比较本次对象读取中已返回的授权内容；选择版本不会读取、保存或修改任何资料。</p>
    <div className="version-comparison__selectors">
      <label>
        <span>比较基线</span>
        <select value={beforeVersionId} onChange={(event) => setSelection({
          beforeVersionId: event.target.value,
          afterVersionId,
        })}>
          {options.map(versionOption)}
        </select>
      </label>
      <label>
        <span>比较目标</span>
        <select value={afterVersionId} onChange={(event) => setSelection({
          beforeVersionId,
          afterVersionId: event.target.value,
        })}>
          {options.map(versionOption)}
        </select>
      </label>
    </div>
    {!comparison
      ? <p className="version-comparison__error" role="alert">这两个历史版本无法安全比较。请刷新对象或重新选择；页面没有发送任何写入。</p>
      : comparison.equal
      ? <p className="version-comparison__equal" role="status">所选版本的授权内容完全一致。</p>
      : <ol className="version-diff-list" aria-label="版本内容差异">
        {comparison.changes.map((entry) => <li className={`version-diff version-diff--${entry.type.toLowerCase()}`} key={`${entry.path}:${entry.type}`}>
          <div className="version-diff__heading">
            <span>{entry.type === "ADDED" ? "新增" : entry.type === "REMOVED" ? "移除" : "修改"}</span>
            <code>{entry.path}</code>
          </div>
          {entry.type === "ADDED" && entry.after && <p><small>目标版本</small><strong>{formatDiffValue(entry.after)}</strong></p>}
          {entry.type === "REMOVED" && entry.before && <p><small>基线版本</small><strong>{formatDiffValue(entry.before)}</strong></p>}
          {entry.type === "CHANGED" && entry.before && entry.after && <div className="version-diff__values">
            <p><small>基线版本</small><strong>{formatDiffValue(entry.before)}</strong></p>
            <span aria-hidden="true">→</span>
            <p><small>目标版本</small><strong>{formatDiffValue(entry.after)}</strong></p>
          </div>}
        </li>)}
      </ol>}
  </section>;
}

function ResourceEditor({
  resource,
  titleRef,
  sections,
  configuration,
  dirty,
  recoveredScratchAt,
  busy,
  profilePauseReasonCode,
  profileArchiveReasonCode,
  profileArchiveConfirmed,
  demandCancelReasonCode,
  demandCancelConfirmed,
  reasonCodes,
  requiredPaths,
  reviewReleaseReasonCode,
  budgetHealthCode,
  riskCode,
  evidenceCodes,
  onSectionChange,
  onSave,
  onAdvance,
  onProfileLifecycle,
  onProfilePauseReasonCodeChange,
  onProfileArchiveReasonCodeChange,
  onProfileArchiveConfirmedChange,
  onDemandCancelReasonCodeChange,
  onDemandCancelConfirmedChange,
  onDemandCancel,
  onReasonCodesChange,
  onRequiredPathsChange,
  onRecordFindings,
  onReviewReleaseReasonCodeChange,
  onReleaseReviewAssignment,
  onBudgetHealthCodeChange,
  onRiskCodeChange,
  onEvidenceCodesChange,
  onVerifyDemand,
}: {
  resource: EditorResource;
  titleRef: RefObject<HTMLHeadingElement | null>;
  sections: Record<string, string>;
  configuration: EditorConfiguration | null;
  dirty: boolean;
  recoveredScratchAt: string | null;
  busy: boolean;
  profilePauseReasonCode: (typeof PROFILE_PAUSE_REASON_CODES)[number];
  profileArchiveReasonCode: (typeof PROFILE_ARCHIVE_REASON_CODES)[number];
  profileArchiveConfirmed: boolean;
  demandCancelReasonCode: (typeof DEMAND_OWNER_CANCEL_REASON_CODES)[number];
  demandCancelConfirmed: boolean;
  reasonCodes: string[];
  requiredPaths: string[];
  reviewReleaseReasonCode: (typeof REVIEW_ASSIGNMENT_RELEASE_REASON_CODES)[number];
  budgetHealthCode: (typeof VERIFY_BUDGET_HEALTH_CODES)[number];
  riskCode: (typeof VERIFY_RISK_CODES)[number];
  evidenceCodes: Array<(typeof VERIFY_EVIDENCE_CODES)[number]>;
  onSectionChange: (path: string, value: string) => void;
  onSave: () => void;
  onAdvance: (action: "PUBLISH" | "SUBMIT") => void;
  onProfileLifecycle: (action: "PAUSE" | "RESUME" | "ARCHIVE") => void;
  onProfilePauseReasonCodeChange: (value: (typeof PROFILE_PAUSE_REASON_CODES)[number]) => void;
  onProfileArchiveReasonCodeChange: (value: (typeof PROFILE_ARCHIVE_REASON_CODES)[number]) => void;
  onProfileArchiveConfirmedChange: (value: boolean) => void;
  onDemandCancelReasonCodeChange: (value: (typeof DEMAND_OWNER_CANCEL_REASON_CODES)[number]) => void;
  onDemandCancelConfirmedChange: (value: boolean) => void;
  onDemandCancel: () => void;
  onReasonCodesChange: (value: string[]) => void;
  onRequiredPathsChange: (value: string[]) => void;
  onRecordFindings: (event: FormEvent) => void;
  onReviewReleaseReasonCodeChange: (value: (typeof REVIEW_ASSIGNMENT_RELEASE_REASON_CODES)[number]) => void;
  onReleaseReviewAssignment: (event: FormEvent) => void;
  onBudgetHealthCodeChange: (value: (typeof VERIFY_BUDGET_HEALTH_CODES)[number]) => void;
  onRiskCodeChange: (value: (typeof VERIFY_RISK_CODES)[number]) => void;
  onEvidenceCodesChange: (value: Array<(typeof VERIFY_EVIDENCE_CODES)[number]>) => void;
  onVerifyDemand: (event: FormEvent) => void;
}) {
  const canEdit = resource.capabilities.includes("SAVE_DRAFT");
  const editorIssues = canEdit ? structuredContentIssues(resource.resource_type, sections, configuration) : [];
  return <>
    <section className="resource-header" aria-labelledby="resource-editor-title">
      <div>
        <p className="eyebrow">{resource.resource_type}</p>
        <h2
          data-resource-id={resource.object_id}
          id="resource-editor-title"
          ref={titleRef}
          tabIndex={-1}
        >{resource.resource_type === "CREATOR_PROFILE" ? "创作者画像" : "需求对象"}</h2>
        <code>{resource.object_id}</code>
      </div>
      <dl>
        <div><dt>状态</dt><dd><span className="status">{statusLabel(resource.status)}</span></dd></div>
        <div><dt>对象版本</dt><dd>v{resource.revision}</dd></div>
        <div><dt>ETag</dt><dd><code>{resource.etag}</code></dd></div>
      </dl>
    </section>

    <section className="capability-strip" aria-label="服务端授予能力">
      <strong>当前能力</strong>
      {resource.capabilities.length ? resource.capabilities.map((capability) => <span key={capability}>{capability}</span>) : <em>只读</em>}
    </section>

    {recoveredScratchAt && <div className="draft-recovery" role="status">
      已恢复当前标签页在 {formatTime(recoveredScratchAt)} 保存的未提交编辑。请核对后再写入服务端。
    </div>}

    {canEdit ? <section className="editor-section" aria-labelledby="content-editor-title">
      <div className="section-heading compact-heading">
        <div><p className="eyebrow">STRUCTURED EDITOR</p><h2 id="content-editor-title">{resource.resource_type === "CREATOR_PROFILE" ? "九个画像分区" : "十三个需求分区"}</h2></div>
        <span className={dirty ? "dirty-indicator" : "saved-indicator"}>{dirty ? "当前标签页有未保存修改" : "与已读取版本一致"}</span>
      </div>
      {busy && <p className="editor-write-lock" id="editor-write-lock-status" role="status">
        正在同步服务端事实、处理版本冲突或确认写入结果；编辑控件已锁定，避免新输入被响应覆盖。
      </p>}
      <fieldset
        aria-busy={busy}
        aria-describedby={busy ? "editor-write-lock-status" : undefined}
        className="editor-write-scope"
        disabled={busy}
      >
        <legend className="sr-only">可编辑内容与写入操作</legend>
        {configuration
          ? <ApprovedTaxonomy configuration={configuration} />
          : <div className="taxonomy-field" role="alert">当前批准的分类配置不可用；保存已关闭。</div>}
        <div className="structured-section-grid">
          {resource.editable_paths.map((path, index) => <StructuredSectionEditor
            configuration={configuration}
            encoded={sections[path] ?? "null"}
            index={index}
            key={path}
            path={path}
            resourceType={resource.resource_type}
            onChange={(value) => onSectionChange(path, serializeStructuredSection(value))}
          />)}
        </div>
        {editorIssues.length > 0 && <div className="editor-validation" role="status">
          <strong>保存、发布或提交前还需处理 {editorIssues.length} 项</strong>
          <span>{fieldLabel(editorIssues[0].path.split("/").filter(Boolean).at(-1) ?? editorIssues[0].path)}：{issueMessage(editorIssues[0].code)}</span>
        </div>}
        <div className="editor-actions">
          <button className="primary-button" disabled={!dirty || !configuration || editorIssues.length > 0} type="button" onClick={onSave}>保存草稿</button>
          {resource.capabilities.includes("PUBLISH") && <button className="danger-button" disabled={dirty || !configuration || editorIssues.length > 0} type="button" onClick={() => onAdvance("PUBLISH")}>发布画像</button>}
          {resource.capabilities.includes("SUBMIT") && <button className="danger-button" disabled={dirty || !configuration || editorIssues.length > 0} type="button" onClick={() => onAdvance("SUBMIT")}>提交审核</button>}
          <small>发布/提交前必须先保存本页修改；服务端会再次做完整验证。</small>
        </div>
      </fieldset>
    </section> : <section className="editor-section" aria-labelledby="readonly-content-title">
      <div className="section-heading compact-heading"><div><p className="eyebrow">READ ONLY</p><h2 id="readonly-content-title">
        {resource.resource_type === "CREATOR_PROFILE"
          ? resource.status === "ARCHIVED"
            ? "画像已归档"
            : "暂停中的已发布内容"
          : "当前提交内容"}
      </h2></div></div>
      {resource.resource_type === "CREATOR_PROFILE" && resource.status === "ARCHIVED"
        ? <p className="readonly-explainer">归档后不再存在“当前版本”。历史版本仍保留在下方，可核对已退役或已废弃的不可变记录。</p>
        : <>
          <p className="readonly-explainer">
            {resource.resource_type === "CREATOR_PROFILE"
              ? "画像暂停期间不会进入新的匹配；请先恢复画像，才能继续编辑或发布。"
              : "以下内容按平台分区呈现，只读且不可代替需求方修改。字段路径保留用于准确记录整改项。"}
          </p>
          {resource.current_version && <StructuredReadOnlyContent
            content={resource.current_version.content}
            resourceType={resource.resource_type}
          />}
        </>}
    </section>}

    {resource.resource_type === "CREATOR_PROFILE" && resource.capabilities.some((capability) => (
      capability === "PAUSE" || capability === "RESUME" || capability === "ARCHIVE"
    )) && <section className="profile-lifecycle-panel" aria-labelledby="profile-lifecycle-title">
      <div className="section-heading compact-heading">
        <div><p className="eyebrow">CREATOR · PROFILE LIFECYCLE</p><h2 id="profile-lifecycle-title">画像状态管理</h2></div>
        <span className="status">{statusLabel(resource.status)}</span>
      </div>
      <p>状态操作绑定当前 ETag 和独立幂等键。页面有未保存修改、其他写入结果未知或退出进行中时，全部保持关闭。</p>
      <div className="profile-lifecycle-actions">
        {resource.capabilities.includes("PAUSE") && <div className="profile-lifecycle-action">
          <label>暂停原因
            <select
              disabled={busy || dirty}
              value={profilePauseReasonCode}
              onChange={(event) => onProfilePauseReasonCodeChange(event.target.value as (typeof PROFILE_PAUSE_REASON_CODES)[number])}
            >
              {PROFILE_PAUSE_REASON_CODES.map((code) => <option key={code} value={code}>{profileLifecycleReasonLabel(code)}</option>)}
            </select>
          </label>
          <button className="quiet-button" disabled={busy || dirty} type="button" onClick={() => onProfileLifecycle("PAUSE")}>暂停画像</button>
        </div>}
        {resource.capabilities.includes("RESUME") && <div className="profile-lifecycle-action">
          <div><strong>恢复画像</strong><small>恢复后画像重新具备编辑能力，并可重新进入新的匹配。</small></div>
          <button className="primary-button" disabled={busy || dirty} type="button" onClick={() => onProfileLifecycle("RESUME")}>恢复后继续编辑</button>
        </div>}
        {resource.capabilities.includes("ARCHIVE") && <div className="profile-lifecycle-action profile-lifecycle-action--archive">
          <label>归档原因
            <select
              disabled={busy || dirty}
              value={profileArchiveReasonCode}
              onChange={(event) => onProfileArchiveReasonCodeChange(event.target.value as (typeof PROFILE_ARCHIVE_REASON_CODES)[number])}
            >
              {PROFILE_ARCHIVE_REASON_CODES.map((code) => <option key={code} value={code}>{profileLifecycleReasonLabel(code)}</option>)}
            </select>
          </label>
          <label className="profile-archive-confirmation">
            <input
              checked={profileArchiveConfirmed}
              disabled={busy || dirty}
              type="checkbox"
              onChange={(event) => onProfileArchiveConfirmedChange(event.target.checked)}
            />
            我理解归档不可恢复，画像将不再有当前版本，也不会进入新的匹配。
          </label>
          <button className="danger-button" disabled={busy || dirty || !profileArchiveConfirmed} type="button" onClick={() => onProfileLifecycle("ARCHIVE")}>永久归档画像</button>
        </div>}
      </div>
    </section>}

    {resource.resource_type === "DEMAND" && resource.capabilities.includes("CANCEL") && <section className="profile-lifecycle-panel demand-cancel-panel" aria-labelledby="demand-cancel-title">
      <div className="section-heading compact-heading">
        <div><p className="eyebrow">DEMAND OWNER · CANCEL</p><h2 id="demand-cancel-title">取消需求</h2></div>
        <span className="status">{statusLabel(resource.status)}</span>
      </div>
      <p>取消会终止当前需求流程。请求绑定当前 ETag 和独立幂等键；有未保存修改或其他写入在途时不会发送。</p>
      <div className="profile-lifecycle-actions">
        <div className="profile-lifecycle-action profile-lifecycle-action--archive">
          <label>取消原因
            <select
              disabled={busy || dirty}
              value={demandCancelReasonCode}
              onChange={(event) => onDemandCancelReasonCodeChange(event.target.value as (typeof DEMAND_OWNER_CANCEL_REASON_CODES)[number])}
            >
              {DEMAND_OWNER_CANCEL_REASON_CODES.map((code) => <option key={code} value={code}>{demandCancelReasonLabel(code)}</option>)}
            </select>
          </label>
          <label className="profile-archive-confirmation">
            <input
              checked={demandCancelConfirmed}
              disabled={busy || dirty}
              type="checkbox"
              onChange={(event) => onDemandCancelConfirmedChange(event.target.checked)}
            />
            我确认要取消当前需求；取消后不能继续编辑、提交、审核或匹配。
          </label>
          <button className="danger-button" disabled={busy || dirty || !demandCancelConfirmed} type="button" onClick={onDemandCancel}>确认取消需求</button>
        </div>
      </div>
    </section>}

    {resource.capabilities.includes("RECORD_FINDINGS") && <section className="review-assignment-release-panel" aria-labelledby="review-assignment-release-title">
      <div className="section-heading compact-heading">
        <div>
          <p className="eyebrow">OPERATIONS REVIEWER · ASSIGNMENT MANAGEMENT</p>
          <h2 id="review-assignment-release-title">释放当前审核分配（非最终决定）</h2>
        </div>
        <span className="status">Demand {resource.status}</span>
      </div>
      <p>释放不会修改 Demand 内容或 <code>SUBMITTED</code> 状态，也不会提交整改或验证结论；它只结束本人当前 ACTIVE 分配，并让需求重新回到审核队列。</p>
      <form className="review-panel review-panel--release" onSubmit={onReleaseReviewAssignment}>
        <dl className="review-assignment-summary">
          <div><dt>当前审核分配</dt><dd><code>{resource.review_assignment?.assignment_id ?? "不可用"}</code></dd></div>
          <div><dt>资源 ETag</dt><dd><code>{resource.etag}</code></dd></div>
        </dl>
        <label>
          <span>释放原因</span>
          <select disabled={busy} value={reviewReleaseReasonCode} onChange={(event) => {
            const code = REVIEW_ASSIGNMENT_RELEASE_REASON_CODES.find((item) => item === event.target.value);
            if (code) onReviewReleaseReasonCodeChange(code);
          }}>
            {REVIEW_ASSIGNMENT_RELEASE_REASON_CODES.map((code) => <option key={code} value={code}>{reviewAssignmentReleaseReasonLabel(code)} · {code}</option>)}
          </select>
        </label>
        <button className="quiet-button" disabled={busy || !resource.review_assignment} type="submit">释放分配并返回审核队列</button>
        <small>请求绑定当前 Demand ETag、Session CSRF 与独立幂等键；结果未知时只能原样重试或明确放弃。</small>
      </form>
    </section>}

    {resource.capabilities.includes("RECORD_FINDINGS") && <section className="review-decision-grid" aria-label="当前审核分配的最终决定">
      <div className="review-decision-note" role="status">
        <strong>以下两项才是最终审核决定</strong>
        <span>选择“提交整改项”或“验证通过”之一。上方“释放分配”不是审核结论；最终决定成功后旧分配立即失效。</span>
      </div>
      <form className="review-panel" onSubmit={onRecordFindings}>
        <div>
          <p className="eyebrow">OPERATIONS REVIEWER · REQUEST CHANGES</p>
          <h2>记录整改项</h2>
          <p>只记录当前分配范围内的结构化理由和顶层必改字段；不能代替需求方修改内容。</p>
        </div>
        <dl className="review-assignment-summary">
          <div><dt>当前审核分配</dt><dd><code>{resource.review_assignment?.assignment_id ?? "不可用"}</code></dd></div>
          <div><dt>有效期至</dt><dd>{resource.review_assignment ? formatTime(resource.review_assignment.expires_at) : "不可用"}</dd></div>
        </dl>
        <fieldset>
          <legend>整改理由（至少选择一项）</legend>
          {REVIEW_REASON_CODES.map((code) => <label key={code}>
            <input
              checked={reasonCodes.includes(code)}
              type="checkbox"
              onChange={(event) => onReasonCodesChange(event.target.checked ? [...reasonCodes, code] : reasonCodes.filter((item) => item !== code))}
            />
            {reviewReasonLabel(code)} <code>{code}</code>
          </label>)}
        </fieldset>
        <fieldset>
          <legend>需要修改的顶层字段</legend>
          {Object.keys(sectionsFromContent("DEMAND", {})).map((path) => <label key={path}>
            <input
              checked={requiredPaths.includes(path)}
              type="checkbox"
              onChange={(event) => onRequiredPathsChange(event.target.checked ? [...requiredPaths, path] : requiredPaths.filter((item) => item !== path))}
            />
            {SECTION_LABELS[path] ?? path} <code>{path}</code>
          </label>)}
        </fieldset>
        <button className="danger-button" disabled={busy || !resource.review_assignment || reasonCodes.length === 0 || requiredPaths.length === 0} type="submit">提交整改项</button>
      </form>

      <form className="review-panel review-panel--verify" onSubmit={onVerifyDemand}>
        <div>
          <p className="eyebrow">OPERATIONS REVIEWER · VERIFY</p>
          <h2>验证通过</h2>
          <p>只提交封闭预算、风险与证据代码；浏览器不会生成自由文本摘要、身份、职责或证据摘要字段。</p>
        </div>
        <dl className="review-assignment-summary">
          <div><dt>当前审核分配</dt><dd><code>{resource.review_assignment?.assignment_id ?? "不可用"}</code></dd></div>
          <div><dt>资源 ETag</dt><dd><code>{resource.etag}</code></dd></div>
        </dl>
        <div className="review-select-grid">
          <label>
            <span>预算健康</span>
            <select value={budgetHealthCode} onChange={(event) => {
              const code = VERIFY_BUDGET_HEALTH_CODES.find((item) => item === event.target.value);
              if (code) onBudgetHealthCodeChange(code);
            }}>
              {VERIFY_BUDGET_HEALTH_CODES.map((code) => <option key={code} value={code}>{reviewBudgetLabel(code)} · {code}</option>)}
            </select>
          </label>
          <label>
            <span>风险结论</span>
            <select value={riskCode} onChange={(event) => {
              const code = VERIFY_RISK_CODES.find((item) => item === event.target.value);
              if (code) onRiskCodeChange(code);
            }}>
              {VERIFY_RISK_CODES.map((code) => <option key={code} value={code}>{reviewRiskLabel(code)} · {code}</option>)}
            </select>
          </label>
        </div>
        <fieldset>
          <legend>验证证据（至少选择一项）</legend>
          {VERIFY_EVIDENCE_CODES.map((code) => <label key={code}>
            <input
              checked={evidenceCodes.includes(code)}
              type="checkbox"
              onChange={(event) => onEvidenceCodesChange(event.target.checked ? [...evidenceCodes, code] : evidenceCodes.filter((item) => item !== code))}
            />
            {reviewEvidenceLabel(code)} <code>{code}</code>
          </label>)}
        </fieldset>
        <button className="primary-button" disabled={busy || !resource.review_assignment || evidenceCodes.length === 0} type="submit">验证通过</button>
      </form>
    </section>}

    <section className="history-grid">
      <div>
        <div className="section-heading compact-heading"><div><p className="eyebrow">IMMUTABLE</p><h2>版本历史</h2></div><strong>{resource.versions.length}</strong></div>
        {resource.versions.length === 0 ? <p className="empty-state">尚无版本</p> : <ol className="version-list">
          {[...resource.versions].reverse().map((version) => <li key={version.version_id}>
            <strong>v{version.version_no} · {statusLabel(version.status)}</strong>
            <time>{formatTime(version.created_at)}</time>
            <code>{version.content_sha256}</code>
          </li>)}
        </ol>}
      </div>
      {resource.resource_type === "DEMAND" && <div>
        <div className="section-heading compact-heading"><div><p className="eyebrow">REVIEW</p><h2>提交与整改</h2></div><strong>{resource.submissions.length + resource.findings.length}</strong></div>
        {resource.submissions.map((submission) => <article className="evidence-card" key={submission.submission_id}><strong>第 {submission.submission_no} 次提交</strong><time>{formatTime(submission.submitted_at)}</time><code>{shortId(submission.version_id)}</code></article>)}
        {resource.findings.map((finding) => <article className="evidence-card evidence-card--finding" key={finding.finding_id}><strong>{finding.result}</strong><time>{formatTime(finding.reviewed_at)}</time><p>{finding.reason_codes.join("、")}</p><code>{finding.required_field_paths.join(" · ")}</code></article>)}
        {!resource.submissions.length && !resource.findings.length && <p className="empty-state">尚无提交或整改记录</p>}
      </div>}
    </section>
    <VersionComparison key={resource.object_id} versions={resource.versions} />
  </>;
}

function StructuredSectionEditor({
  resourceType,
  path,
  index,
  encoded,
  configuration,
  onChange,
}: {
  resourceType: ResourceType;
  path: string;
  index: number;
  encoded: string;
  configuration: EditorConfiguration | null;
  onChange: (value: unknown) => void;
}) {
  let value: unknown;
  try {
    value = parseStructuredSection(resourceType, path, encoded);
  } catch {
    return <section className="structured-editor structured-editor--invalid">
      <header><b>{index + 1}</b><h3>{SECTION_LABELS[path] ?? path}</h3><code>{path}</code></header>
      <p role="alert">旧草稿不是有效的受控分区。为避免静默丢失资料，页面不会自动修复；请选择服务器版本或处理版本冲突。</p>
    </section>;
  }
  const issues = structuredSectionIssues(resourceType, path, encoded, configuration);
  return <section className="structured-editor">
    <header><b>{index + 1}</b><h3>{SECTION_LABELS[path] ?? path}</h3><code>{path}</code></header>
    <StructuredValueEditor
      resourceType={resourceType}
      configuration={configuration}
      canonicalPath={path}
      fieldKey={path.slice(1)}
      value={value}
      onChange={onChange}
    />
    {issues.length > 0 && <ul className="field-issues" aria-label={`${SECTION_LABELS[path] ?? path}待处理项`}>
      {issues.map((item, issueIndex) => <li key={`${item.path}:${item.code}:${issueIndex}`}>
        <code>{item.path}</code> {issueMessage(item.code)}
      </li>)}
    </ul>}
  </section>;
}

function StructuredValueEditor({
  resourceType,
  canonicalPath,
  fieldKey,
  value,
  ariaLabel,
  configuration,
  onChange,
}: {
  resourceType: ResourceType;
  canonicalPath: string;
  fieldKey: string;
  value: unknown;
  ariaLabel?: string;
  configuration: EditorConfiguration | null;
  onChange: (value: unknown) => void;
}) {
  if (value === null) {
    return <div className="optional-field">
      <span>当前未填写；发布或提交前，服务端可能要求补充。</span>
      {hasOptionalValueTemplate(resourceType, canonicalPath) && <button
        className="quiet-button"
        type="button"
        onClick={() => onChange(optionalValueTemplate(resourceType, canonicalPath))}
      >填写这一部分</button>}
    </div>;
  }

  if (Array.isArray(value)) {
    const itemChoice = resolveEditorChoice(configuration, resourceType, `${canonicalPath}/0`);
    const additionUnavailable = itemChoice?.status === "UNAVAILABLE";
    return <div className="repeater-field">
      {value.length === 0 && <p className="empty-state">暂无条目</p>}
      {value.map((item, itemIndex) => <article className="repeater-item" key={`${canonicalPath}:${itemIndex}`}>
        <div className="repeater-heading">
          <strong id={fieldGroupLabelId(`${canonicalPath}/${itemIndex}`)}>{fieldLabel(fieldKey)} #{itemIndex + 1}</strong>
          <button
            className="remove-button"
            type="button"
            onClick={() => onChange(value.filter((_entry, index) => index !== itemIndex))}
          >移除</button>
        </div>
        <StructuredValueEditor
          resourceType={resourceType}
          configuration={configuration}
          canonicalPath={`${canonicalPath}/${itemIndex}`}
          fieldKey={fieldKey}
          value={item}
          ariaLabel={typeof item === "object" && item !== null ? undefined : `${fieldLabel(fieldKey)} #${itemIndex + 1}`}
          onChange={(next) => onChange(value.map((entry, index) => index === itemIndex ? next : entry))}
        />
      </article>)}
      <button
        className="add-button"
        disabled={additionUnavailable}
        type="button"
        onClick={() => {
          try {
            onChange([...value, arrayItemTemplate(resourceType, canonicalPath, value, configuration)]);
          } catch {
            // Arrays outside the closed editor schema remain read-only.
          }
        }}
      >{additionUnavailable ? `暂无经审核的${fieldLabel(fieldKey)}选项` : `添加${fieldLabel(fieldKey)}`}</button>
      {additionUnavailable && <small className="choice-source">现有旧值仍可逐项移除；当前目录不允许新增。</small>}
    </div>;
  }

  if (typeof value === "object") {
    return <div className="field-object">
      {Object.entries(value as Record<string, unknown>).map(([key, child]) => {
        const childPath = `${canonicalPath}/${key}`;
        const directControl = child !== null && !Array.isArray(child) && typeof child !== "object";
        return <div
          className="structured-field"
          key={childPath}
          {...(!directControl ? { role: "group", "aria-labelledby": fieldGroupLabelId(childPath) } : {})}
        >
          <div className="field-label-row">
            {directControl
              ? <label htmlFor={fieldInputId(childPath)}>{fieldLabel(key)}</label>
              : <span className="field-group-label" id={fieldGroupLabelId(childPath)}>{fieldLabel(key)}</span>}
            {hasOptionalValueTemplate(resourceType, childPath) && child !== null && <button
              className="text-button"
              type="button"
              onClick={() => onChange({ ...(value as Record<string, unknown>), [key]: null })}
            >设为不适用</button>}
          </div>
          <StructuredValueEditor
            resourceType={resourceType}
            configuration={configuration}
            canonicalPath={childPath}
            fieldKey={key}
            value={child}
            onChange={(next) => onChange({ ...(value as Record<string, unknown>), [key]: next })}
          />
        </div>;
      })}
    </div>;
  }

  if (typeof value === "boolean") {
    return <label className="boolean-field" htmlFor={fieldInputId(canonicalPath)}>
      <input
        aria-label={ariaLabel}
        checked={value}
        id={fieldInputId(canonicalPath)}
        type="checkbox"
        onChange={(event) => onChange(event.target.checked)}
      />
      <span>{value ? "是" : "否"}</span>
    </label>;
  }

  if (typeof value === "number") {
    const meta = fieldInputMeta(fieldKey, canonicalPath, resourceType);
    return <input
      aria-label={ariaLabel}
      id={fieldInputId(canonicalPath)}
      max={meta.limits?.[1]}
      min={meta.limits?.[0]}
      step="1"
      type="number"
      value={Number.isFinite(value) ? value : 0}
      onChange={(event) => onChange(event.target.value === "" ? 0 : Number(event.target.value))}
    />;
  }

  if (typeof value === "string") {
    const choice = resolveEditorChoice(configuration, resourceType, canonicalPath);
    if (choice?.status === "UNAVAILABLE") {
      return <div className="choice-field choice-field--unavailable">
        <input aria-label={ariaLabel} disabled id={fieldInputId(canonicalPath)} type="text" value={value} />
        <small>当前没有经审核的可选值；可从所属列表移除此旧值，但不能新增或保存它。</small>
      </div>;
    }
    if (choice?.status === "AVAILABLE") {
      const known = choice.options.some((option) => option.value === value);
      const sources = [...new Set(choice.options.map((option) => editorChoiceSourceLabel(option.source)))];
      return <div className="choice-field">
        <select
          aria-invalid={!known}
          aria-label={ariaLabel}
          id={fieldInputId(canonicalPath)}
          value={value}
          onChange={(event) => onChange(event.target.value)}
        >
          {!known && <option disabled value={value}>旧值（当前不可选）：{value || "空值"}</option>}
          {choice.options.map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}
        </select>
        <small className="choice-source">来源：{sources.join("、")}</small>
      </div>;
    }
    const meta = fieldInputMeta(fieldKey, canonicalPath, resourceType);
    if (meta.type === "select") {
      return <select
        aria-label={ariaLabel}
        id={fieldInputId(canonicalPath)}
        disabled={meta.readOnly}
        value={value}
        onChange={(event) => onChange(event.target.value)}
      >
        {meta.options.map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}
      </select>;
    }
    if (meta.multiline) {
      return <textarea
        aria-label={ariaLabel}
        id={fieldInputId(canonicalPath)}
        maxLength={fieldKey === "background" ? 4000 : fieldKey === "description" ? 500 : 2000}
        value={value}
        onChange={(event) => onChange(event.target.value)}
      />;
    }
    return <input
      aria-label={ariaLabel}
      id={fieldInputId(canonicalPath)}
      pattern={meta.pattern ?? undefined}
      readOnly={meta.readOnly}
      type={meta.type}
      value={value}
      onChange={(event) => onChange(event.target.value)}
    />;
  }

  return <p className="field-error" role="alert">不支持的字段类型；页面未修改服务端资料。</p>;
}

function fieldInputId(path: string) {
  return `editor${path.replace(/[^A-Za-z0-9_-]+/g, "-")}`;
}

function fieldGroupLabelId(path: string) {
  return `${fieldInputId(path)}-group-label`;
}

function reviewReasonLabel(code: string) {
  return ({
    CONTENT_INCOMPLETE: "内容不完整",
    SCOPE_UNCLEAR: "范围不清晰",
    ACCEPTANCE_UNCLEAR: "验收条件不清晰",
    BUDGET_UNHEALTHY: "预算条件需调整",
    RISK_UNRESOLVED: "风险尚未处理",
    DATA_PLAN_REQUIRED: "需要数据处理方案",
  } as Record<string, string>)[code] ?? code;
}

function reviewAssignmentReleaseReasonLabel(code: string) {
  return ({
    CONFLICT_DECLARED: "声明利益冲突",
    WORKLOAD_RELEASE: "工作量调整",
  } as Record<string, string>)[code] ?? code;
}

function profileLifecycleReasonLabel(code: string) {
  return ({
    OWNER_REQUEST: "本人主动申请",
    TEMPORARY_UNAVAILABILITY: "暂时无法投入",
    ACCOUNT_CLOSURE: "账号关闭",
    SAFETY_REVIEW: "安全审查",
  } as Record<string, string>)[code] ?? code;
}

function demandCancelReasonLabel(code: string) {
  return ({
    OWNER_WITHDREW: "需求方主动撤回",
    REQUIREMENTS_CHANGED: "需求已发生变化",
    REVIEW_CLOSED: "审核流程已关闭",
    FUNDING_UNAVAILABLE: "合成资金条件不可用",
    SAFETY_RESTRICTION: "安全限制",
  } as Record<string, string>)[code] ?? code;
}

function reviewBudgetLabel(code: string) {
  return ({
    HEALTHY: "预算结构健康",
    APPROVED_EXCEPTION: "已批准预算例外",
  } as Record<string, string>)[code] ?? code;
}

function reviewRiskLabel(code: string) {
  return ({
    STANDARD: "标准风险",
    ELEVATED_APPROVED: "已批准较高风险",
  } as Record<string, string>)[code] ?? code;
}

function reviewEvidenceLabel(code: string) {
  return ({
    SCOPE_COMPLETE: "范围完整",
    ACCEPTANCE_TESTABLE: "验收可测试",
    BUDGET_COHERENT: "预算一致",
    RISK_HANDLED: "风险已处理",
    DECLARATIONS_CONFIRMED: "声明已确认",
  } as Record<string, string>)[code] ?? code;
}

function StructuredReadOnlyContent({
  resourceType,
  content,
}: {
  resourceType: ResourceType;
  content: Record<string, unknown>;
}) {
  const paths = resourceType === "CREATOR_PROFILE"
    ? Object.keys(sectionsFromContent("CREATOR_PROFILE", {}))
    : Object.keys(sectionsFromContent("DEMAND", {}));
  return <div className="readonly-section-grid">
    {paths.map((path, index) => {
      const key = path.slice(1);
      return <section className="readonly-section" key={path} aria-labelledby={`readonly-section-${index}`}>
        <header>
          <b>{index + 1}</b>
          <h3 id={`readonly-section-${index}`}>{SECTION_LABELS[path] ?? path}</h3>
          <code>{path}</code>
        </header>
        <ReadOnlyValue canonicalPath={path} fieldKey={key} value={content[key] ?? null} />
      </section>;
    })}
  </div>;
}

function ReadOnlyValue({
  canonicalPath,
  fieldKey,
  value,
}: {
  canonicalPath: string;
  fieldKey: string;
  value: unknown;
}) {
  if (value === null || value === undefined) {
    return <p className="readonly-empty">未填写 / 不适用</p>;
  }
  if (Array.isArray(value)) {
    if (value.length === 0) return <p className="readonly-empty">暂无条目</p>;
    return <ol className="readonly-list">
      {value.map((item, index) => <li key={`${canonicalPath}:${index}`}>
        <strong>{fieldLabel(fieldKey)} #{index + 1}</strong>
        <ReadOnlyValue canonicalPath={`${canonicalPath}/${index}`} fieldKey={fieldKey} value={item} />
      </li>)}
    </ol>;
  }
  if (typeof value === "object") {
    return <dl className="readonly-facts">
      {Object.entries(value as Record<string, unknown>).map(([key, child]) => <div key={`${canonicalPath}/${key}`}>
        <dt>{fieldLabel(key)}</dt>
        <dd><ReadOnlyValue canonicalPath={`${canonicalPath}/${key}`} fieldKey={key} value={child} /></dd>
      </div>)}
    </dl>;
  }
  if (typeof value === "boolean") return <span className="readonly-value">{value ? "是" : "否"}</span>;
  return <span className="readonly-value">{String(value)}</span>;
}

function conflictMergeStateLabel(state: EditorConflictSectionState) {
  return ({
    UNCHANGED: "未修改",
    SAME_CHANGE: "双方修改结果一致，已自动保留",
    SERVER_ONLY: "仅服务器修改，已自动保留服务器内容",
    MINE_ONLY: "仅你修改，已自动保留你的内容",
    COLLISION: "双方修改结果不同，需要选择",
  } as const)[state];
}

function ConflictPanel({
  conflict,
  onDiscard,
  onResolve,
  resourceType,
}: {
  conflict: ConflictSurface;
  onDiscard: () => void;
  onResolve: (choices: Readonly<Record<string, EditorConflictChoice>>) => void;
  resourceType: ResourceType;
}) {
  const [choices, setChoices] = useState<Record<string, EditorConflictChoice>>({});
  let merge: ReturnType<typeof planEditorConflictMerge>;
  try {
    merge = planEditorConflictMerge(
      resourceType,
      conflict.base.content,
      conflict.current.content,
      conflict.yours.content,
      choices,
    );
  } catch {
    return <section className="conflict-panel" aria-labelledby="conflict-title">
      <p className="eyebrow">412 PRECONDITION FAILED</p>
      <h2 id="conflict-title">冲突内容无法安全合并</h2>
      <p role="alert">服务端返回了编辑器不认识的分区或无效内容。页面没有修改编辑器，也不会发送写请求。</p>
      <button className="quiet-button" type="button" onClick={onDiscard}>放弃我的冲突编辑并保留服务器版本</button>
    </section>;
  }
  const collisions = merge.sections.filter((section) => section.state === "COLLISION");
  const automatic = merge.sections.filter((section) => (
    section.state === "SAME_CHANGE"
    || section.state === "SERVER_ONLY"
    || section.state === "MINE_ONLY"
  ));

  return <section className="conflict-panel" aria-labelledby="conflict-title">
    <div className="section-heading compact-heading">
      <div><p className="eyebrow">412 PRECONDITION FAILED</p><h2 id="conflict-title">逐分区合并版本冲突</h2></div>
      <strong>{collisions.length} 个需选择 · {automatic.length} 个自动合并</strong>
    </div>
    <p>页面按编辑器的顶层分区比较三份内容。单边修改和双方相同结果会自动合并；双方改到不同结果时才需要选择。</p>
    <dl className="conflict-version-summary">
      <div><dt>编辑基线</dt><dd><code>{conflict.base.version_id ?? "无"}</code></dd></div>
      <div><dt>服务器当前版本</dt><dd><code>{conflict.current.version_id ?? "无"}</code></dd></div>
      <div><dt>你的冲突版本</dt><dd><code>{conflict.yours.version_id ?? "无"}</code></dd></div>
    </dl>
    {automatic.length > 0 && <div className="conflict-auto-merge">
      <h3>无需选择的修改</h3>
      <ul>{automatic.map((section) => <li key={section.path}>
        <strong>{SECTION_LABELS[section.path] ?? section.path}</strong>
        <span>{conflictMergeStateLabel(section.state)}</span>
      </li>)}</ul>
    </div>}
    {collisions.length > 0 ? <div className="conflict-section-list">
      {collisions.map((section, index) => {
        const key = section.path.slice(1);
        return <fieldset className="conflict-section-choice" key={section.path}>
          <legend><b>{index + 1}</b> {SECTION_LABELS[section.path] ?? section.path} <code>{section.path}</code></legend>
          <p>这个分区的服务器内容和你的内容都偏离了编辑基线，且结果不同。请选择一份放入合并草稿。</p>
          <div className="conflict-choice-grid">
            <label className={choices[section.path] === "SERVER" ? "conflict-version-option is-selected" : "conflict-version-option"}>
              <span><input
                checked={choices[section.path] === "SERVER"}
                name={`conflict-choice-${section.path}`}
                type="radio"
                onChange={() => setChoices((current) => ({ ...current, [section.path]: "SERVER" }))}
              /> <strong>保留服务器修改</strong></span>
              <small>当前版本 {conflict.current.version_id ?? "无"}</small>
              <ReadOnlyValue canonicalPath={section.path} fieldKey={key} value={conflict.current.content[key]} />
            </label>
            <label className={choices[section.path] === "MINE" ? "conflict-version-option is-selected" : "conflict-version-option"}>
              <span><input
                checked={choices[section.path] === "MINE"}
                name={`conflict-choice-${section.path}`}
                type="radio"
                onChange={() => setChoices((current) => ({ ...current, [section.path]: "MINE" }))}
              /> <strong>保留我的修改</strong></span>
              <small>冲突版本 {conflict.yours.version_id ?? "无"}</small>
              <ReadOnlyValue canonicalPath={section.path} fieldKey={key} value={conflict.yours.content[key]} />
            </label>
          </div>
        </fieldset>;
      })}
    </div> : <p className="conflict-ready">没有真正冲突的分区；单边修改已安全组合，可以直接载入编辑器复核。</p>}
    <div className="editor-actions">
      <button className="primary-button" disabled={!merge.complete || merge.content === null} type="button" onClick={() => onResolve(choices)}>
        {merge.complete ? "应用合并结果并复核" : `还需选择 ${merge.unresolvedPaths.length} 个分区`}
      </button>
      <button className="quiet-button" type="button" onClick={onDiscard}>放弃我的冲突编辑</button>
    </div>
  </section>;
}
