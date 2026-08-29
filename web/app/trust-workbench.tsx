"use client";

import { FormEvent, useCallback, useEffect, useLayoutEffect, useRef, useState } from "react";
import {
  type EditorResource,
  type PendingIntent,
  type SessionBootstrap,
  type TrustAssignedHoldProjection,
  type TrustAssignmentItem,
  type TrustCaseHistoryProjection,
  type TrustCaseProjection,
  type TrustDemandActionCode,
  type TrustHoldReleaseQueueItem,
  type TrustOwnReportItem,
  type TrustOwnReportListProjection,
  type TrustQueueItem,
  type TrustReportProjection,
  type WorkspaceCandidate,
  TRUST_ASSIGNMENT_RELEASE_REASON_CODES,
  TRUST_DEMAND_ACTION_CODES,
  TRUST_HOLD_REASON_CODES,
  TRUST_HOLD_RELEASE_REASON_CODES,
  TRUST_IMPACT_CODES,
  TRUST_INVESTIGATION_STEP_CODES,
  TRUST_ISSUE_CODES,
  TRUST_OUTCOME_CODES,
  TRUST_OUTCOME_REASON_CODES,
  TRUST_PROTECTION_CODES,
  TRUST_REPORT_CATEGORIES,
  createTrustAssignmentReleaseIntent,
  createTrustAssignedHoldReleaseIntent,
  createTrustCaseClaimIntent,
  createTrustHoldIntent,
  createTrustHoldReleaseClaimIntent,
  createTrustHoldReleaseIntent,
  createTrustOutcomeIntent,
  createTrustReportIntent,
  createTrustTriageDraftIntent,
  createTrustTriagePublishIntent,
  parsePendingIntent,
  parseTrustAssignedHoldEnvelope,
  parseTrustAssignmentListEnvelope,
  parseTrustCaseEnvelope,
  parseTrustCaseHistoryEnvelope,
  parseTrustCommandEnvelope,
  parseTrustHoldReleaseQueueEnvelope,
  parseTrustOwnReportListEnvelope,
  parseTrustQueueEnvelope,
  parseTrustReportEnvelope,
  serializePendingIntent,
} from "../lib/app-contract.mjs";
import {
  createAtomicRefreshCoordinator,
  nonRecoveryControlsLocked,
} from "../lib/workbench-refresh.mjs";
import {
  type AppealHandoff,
  createAppealHandoff,
  isAppealHandoffCurrent,
} from "../lib/appeal-handoff.mjs";
import {
  dateTimeLocalToIso,
  formatDateTimeLocal,
} from "../lib/product-workspace-state.mjs";

const TRUST_ROOT = "/v1/app/trust";
const TRUST_ASSIGNMENTS = "/v1/app/trust/assignments";
const TRUST_CASE_HISTORY = "/v1/app/trust/history";
const PENDING_KEY = "desire-pilot-pending:v1";
const TRUST_REPORTABLE_DEMAND_STATUSES = new Set([
  "FUNDED",
  "FUNDING_PENDING",
  "MATCHED",
  "MATCHING",
  "NEEDS_CHANGES",
  "NO_MATCH",
  "SUBMITTED",
  "VERIFIED",
]);
const TRUST_ASSIGNMENT_LABELS: Record<TrustAssignmentItem["assignment_purpose"], string> = {
  CASE_TRIAGE: "案件分诊",
  HOLD_RELEASE: "保护解除复核",
};

type WorkspaceRequest = (
  path: string,
  init?: RequestInit,
) => Promise<{ value: unknown; etag: string | null }>;

export type TrustCaseHistoryTaskTarget = {
  case_id: string;
  request_id: string;
  session_id: string;
  workspace_id: string;
};

type Props = {
  demands: EditorResource[];
  demandsAvailable: boolean;
  session: SessionBootstrap;
  workspace: WorkspaceCandidate;
  request: WorkspaceRequest;
  writeLocked: boolean;
  claimWrite: (record: PendingIntent) => boolean;
  releaseWrite: (record: PendingIntent) => void;
  onBeginAppeal: (handoff: AppealHandoff) => void;
  caseHistoryTaskTarget: TrustCaseHistoryTaskTarget | null;
};

type TrustFailure = { status: number; code: string; traceId: string | null };
type ReportableDemand = EditorResource & { current_version: NonNullable<EditorResource["current_version"]> };
type TrustQueueSnapshot = {
  assignments: TrustAssignmentItem[];
  history: TrustCaseHistoryProjection | null;
  holdReleaseQueue: TrustHoldReleaseQueueItem[];
  queue: TrustQueueItem[];
};
type TrustOwnReportCollection = {
  items: TrustOwnReportItem[];
  next_cursor: string | null;
  page_entity_tags: string[];
};
type DetailReadOrigin = "INTERACTIVE" | "POST_WRITE";
type DetailReadOptions<T> = {
  commit: (value: T) => void;
  load: () => Promise<T>;
  onError: (error: unknown) => void;
  onSuccess: (value: T) => void;
  validate?: (value: T) => void;
};
type QueueRefreshOptions = {
  afterCommit?: (snapshot: TrustQueueSnapshot) => void;
  validate?: (snapshot: TrustQueueSnapshot) => void;
};

function isReportableDemand(resource: EditorResource): resource is ReportableDemand {
  return resource.resource_type === "DEMAND"
    && resource.current_version !== null
    && TRUST_REPORTABLE_DEMAND_STATUSES.has(resource.status);
}

function failure(value: unknown): TrustFailure {
  if (value && typeof value === "object") {
    const item = value as Record<string, unknown>;
    if (typeof item.status === "number" && typeof item.code === "string") {
      return {
        status: item.status,
        code: item.code,
        traceId: typeof item.traceId === "string" ? item.traceId : null,
      };
    }
  }
  return { status: 0, code: "WRITE_OUTCOME_UNKNOWN", traceId: null };
}

function etagVersion(value: string) {
  const match = value.match(/^"trust-([1-9][0-9]*)-[a-f0-9]{24}"$/);
  if (!match) throw new TypeError("INVALID_TRUST_ETAG");
  return Number(match[1]);
}

function assertResponseEtag(response: { etag: string | null }, entityTag: string) {
  if (response.etag !== entityTag) throw new TypeError("INVALID_TRUST_RESPONSE_BINDING");
}

function expectedCommandEvent(path: string) {
  if (path === `${TRUST_ROOT}/reports`) return "TrustReportSubmitted";
  if (/\/trust\/queue\/[^/]+\/claim$/.test(path)) return "TrustCaseClaimed";
  if (/\/hold-release-queue\/[^/]+\/claim$/.test(path)) return "TrustHoldReleaseClaimed";
  if (path.endsWith("/assignment/release")) return "TrustCaseAssignmentReleased";
  if (path.endsWith("/triage-draft")) return "TrustTriageDraftSaved";
  if (path.endsWith("/triage-publish")) return "TrustTriagePublished";
  if (/\/trust\/cases\/[^/]+\/holds$/.test(path)) return "SafetyHoldPlaced";
  if (/\/trust\/holds\/[^/]+\/release$/.test(path)) return "SafetyHoldReleased";
  if (path.endsWith("/decisions")) return "TrustCaseOutcomePublished";
  throw new TypeError("INVALID_TRUST_COMMAND_ROUTE");
}

function validateTrustPostWriteSnapshot(
  snapshot: TrustQueueSnapshot,
  eventType: string,
  caseId: string,
  holdId: string | null,
  expectsCaseAssignmentAfterHoldRelease: boolean,
) {
  const caseAssigned = snapshot.assignments.some(
    (item) => item.assignment_purpose === "CASE_TRIAGE" && item.case_id === caseId,
  );
  const caseQueued = snapshot.queue.some((item) => item.case_id === caseId);
  const holdAssigned = holdId !== null && snapshot.assignments.some(
    (item) => item.assignment_purpose === "HOLD_RELEASE" && item.hold_id === holdId,
  );
  const holdQueued = holdId !== null && snapshot.holdReleaseQueue.some((item) => item.hold_id === holdId);

  const contradictory = eventType === "TrustCaseClaimed"
    ? caseQueued || !caseAssigned
    : eventType === "TrustCaseAssignmentReleased"
      ? !caseQueued || caseAssigned
      : eventType === "TrustHoldReleaseClaimed"
        ? holdId === null || holdQueued || !holdAssigned
        : eventType === "SafetyHoldReleased"
          ? holdId === null
            || holdQueued
            || holdAssigned
            || (expectsCaseAssignmentAfterHoldRelease && (caseQueued || !caseAssigned))
          : eventType === "TrustCaseOutcomePublished"
            ? caseQueued
              || caseAssigned
              || !snapshot.history?.items.some((item) => item.case_id === caseId)
            : caseQueued || !caseAssigned;
  if (contradictory) throw new TypeError("INVALID_TRUST_QUEUE_SNAPSHOT_BINDING");
}

function pendingRecord(
  resourceType: "TRUST_REPORT" | "TRUST_CASE" | "TRUST_HOLD",
  objectId: string,
  label: string,
  intent: PendingIntent["intent"],
): PendingIntent {
  return {
    version: 1,
    saved_at: new Date().toISOString(),
    resource_type: resourceType,
    object_id: objectId,
    label,
    intent,
  };
}

function isTrustPending(value: PendingIntent | null): value is PendingIntent {
  return value?.resource_type === "TRUST_REPORT"
    || value?.resource_type === "TRUST_CASE"
    || value?.resource_type === "TRUST_HOLD";
}

function isRestrictedNoteWrite(record: PendingIntent) {
  return record.intent.path.endsWith("/triage-draft");
}

function localTime(value: string) {
  const date = new Date(value);
  if (Number.isNaN(date.valueOf())) return value;
  return new Intl.DateTimeFormat("zh-CN", {
    dateStyle: "medium",
    timeStyle: "short",
    timeZone: "Asia/Shanghai",
  }).format(date);
}

function toUtc(value: string) {
  try {
    return dateTimeLocalToIso(value);
  } catch {
    throw new TypeError("INVALID_TRUST_TIMESTAMP");
  }
}

function toggleCode(current: string[], code: string, checked: boolean) {
  return checked
    ? current.includes(code) ? current : [...current, code]
    : current.filter((item) => item !== code);
}

function ownReportInstant(value: string) {
  const match = value.match(/^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?(?:Z|\+00:00)$/);
  if (!match) throw new TypeError("INVALID_TRUST_REPORT_LIST_ORDER");
  return `${match[1]}.${(match[2] ?? "").padEnd(9, "0")}`;
}

function isOwnedReportAfter(previous: TrustOwnReportItem, next: TrustOwnReportItem) {
  const previousInstant = ownReportInstant(previous.submitted_at);
  const nextInstant = ownReportInstant(next.submitted_at);
  return nextInstant < previousInstant
    || (nextInstant === previousInstant && next.report_id > previous.report_id);
}

export function TrustWorkbench({
  demands,
  demandsAvailable,
  session,
  workspace,
  request,
  writeLocked,
  claimWrite,
  releaseWrite,
  onBeginAppeal,
  caseHistoryTaskTarget,
}: Props) {
  const canSubmitReport = workspace.role_codes.includes("DEMAND_OWNER");
  const canOperateCases = workspace.workspace_kind === "PLATFORM"
    && workspace.role_codes.includes("TRUST_OFFICER");
  const reportTargets = canSubmitReport ? demands.filter(isReportableDemand) : [];
  const [queueSnapshot, setQueueSnapshot] = useState<TrustQueueSnapshot>({
    assignments: [],
    history: null,
    holdReleaseQueue: [],
    queue: [],
  });
  const { assignments, history, holdReleaseQueue, queue } = queueSnapshot;
  const [selectedCase, setSelectedCase] = useState<TrustCaseProjection | null>(null);
  const [selectedHoldRelease, setSelectedHoldRelease] = useState<TrustAssignedHoldProjection | null>(null);
  const [ownReport, setOwnReport] = useState<TrustReportProjection | null>(null);
  const [ownReportList, setOwnReportList] = useState<TrustOwnReportCollection | null>(null);
  const [ownReportsLoaded, setOwnReportsLoaded] = useState(false);
  const [queueSnapshotLoaded, setQueueSnapshotLoaded] = useState(false);
  const [queueSnapshotUnavailable, setQueueSnapshotUnavailable] = useState(false);
  const [selectedReportTargetVersionId, setSelectedReportTargetVersionId] = useState("");
  const [busy, setBusy] = useState(false);
  const [reading, setReading] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [queueRefreshCoordinator] = useState(createAtomicRefreshCoordinator);
  const [detailReadCoordinator] = useState(createAtomicRefreshCoordinator);
  const [recoveryChecked, setRecoveryChecked] = useState(false);
  const [initialRefreshStarted, setInitialRefreshStarted] = useState(false);
  const [ownReportInitialStarted, setOwnReportInitialStarted] = useState(false);
  const [notice, setNotice] = useState("Trust 工作台只读取服务端安全投影。");
  const [error, setError] = useState<TrustFailure | null>(null);
  const [pending, setPending] = useState<PendingIntent | null>(null);
  const controlledRefreshActive = useRef(false);
  const ownReportCursorChain = useRef(new Set<string>());
  const attemptedHistoryTaskRef = useRef<string | null>(null);
  const historyItemRefs = useRef(new Map<string, HTMLElement>());

  const [reportLookupId, setReportLookupId] = useState("");
  const [category, setCategory] = useState<(typeof TRUST_REPORT_CATEGORIES)[number]>("WORKFLOW_INTEGRITY");
  const [impactCodes, setImpactCodes] = useState<string[]>(["WORKFLOW_INTEGRITY_RISK"]);
  const [protectionCodes, setProtectionCodes] = useState<string[]>(["PAUSE_MATCHING"]);
  const [incidentStartedAt, setIncidentStartedAt] = useState(() => formatDateTimeLocal(new Date()));
  const [incidentEndedAt, setIncidentEndedAt] = useState("");
  const [assignedCaseId, setAssignedCaseId] = useState("");

  const [investigationCodes, setInvestigationCodes] = useState<string[]>(["CHECK_DEMAND_VERSION"]);
  const [issueCodes, setIssueCodes] = useState<string[]>(["WORKFLOW_INTEGRITY_GAP"]);
  const [jurisdictionCode, setJurisdictionCode] = useState("PLATFORM_INTERNAL");
  const [priorityCode, setPriorityCode] = useState("P2");
  const [severityCode, setSeverityCode] = useState("MEDIUM");
  const [proposedHoldActions, setProposedHoldActions] = useState<string[]>(["REQUEST_MATCHING"]);
  const [proposedHoldTtl, setProposedHoldTtl] = useState(1440);
  const [restrictedNote, setRestrictedNote] = useState("");
  const [assignmentReleaseReason, setAssignmentReleaseReason] = useState("WORKLOAD_RELEASE");
  const [holdActions, setHoldActions] = useState<string[]>(["REQUEST_MATCHING"]);
  const [holdReason, setHoldReason] = useState("WORKFLOW_INTEGRITY_RISK");
  const [holdTtl, setHoldTtl] = useState(1440);
  const [holdReleaseReason, setHoldReleaseReason] = useState("RISK_MITIGATED");
  const [outcomeCode, setOutcomeCode] = useState("NO_ACTION");
  const [outcomeReasons, setOutcomeReasons] = useState<string[]>(["INSUFFICIENT_VERIFIED_EVIDENCE"]);
  const [outcomeActions, setOutcomeActions] = useState<string[]>([]);
  const selectedReportTarget = reportTargets.find(
    (item) => item.current_version.version_id === selectedReportTargetVersionId,
  ) ?? null;

  const persistPending = useCallback((record: PendingIntent | null) => {
    setPending(record);
    if (!record) {
      sessionStorage.removeItem(PENDING_KEY);
      return;
    }
    if (isRestrictedNoteWrite(record)) {
      sessionStorage.removeItem(PENDING_KEY);
      return;
    }
    sessionStorage.setItem(PENDING_KEY, serializePendingIntent(record));
  }, []);

  const clearPending = useCallback((record: PendingIntent) => {
    releaseWrite(record);
    persistPending(null);
  }, [persistPending, releaseWrite]);

  const settlePendingForRefresh = useCallback(() => {
    // The 2xx command is terminal, so remove its replay object immediately,
    // while the parent-owned global latch remains held through the fresh read.
    persistPending(null);
  }, [persistPending]);

  const rejectNonRecoveryIfLocked = useCallback(() => {
    if (!recoveryChecked || busy || reading || refreshing) return true;
    if (!writeLocked && pending === null) return false;
    setError({
      status: 0,
      code: pending ? "WRITE_OUTCOME_PENDING" : "GLOBAL_WRITE_LOCKED",
      traceId: null,
    });
    setNotice(pending
      ? "Trust 写入结果尚未确认；当前只允许原样重试或明确放弃。"
      : "全局写入门闩正由其他恢复或登出操作占用；Trust 读取与写入均未开始。");
    return true;
  }, [busy, pending, reading, recoveryChecked, refreshing, writeLocked]);

  const isReadGenerationValid = useCallback((origin: "INITIAL" | "MANUAL" | DetailReadOrigin) => {
    return origin !== "POST_WRITE" || controlledRefreshActive.current;
  }, []);

  const runDetailRead = useCallback(<T,>(origin: DetailReadOrigin, options: DetailReadOptions<T>) => (
    detailReadCoordinator.run({
      ...options,
      isValid: () => isReadGenerationValid(origin),
      setBusy: (value) => {
        if (origin === "INTERACTIVE") setReading(value);
      },
    })
  ), [detailReadCoordinator, isReadGenerationValid]);

  const loadQueue = useCallback(async () => {
    const response = await request(`${TRUST_ROOT}/queue`);
    const projection = parseTrustQueueEnvelope(response.value);
    assertResponseEtag(response, projection.entity_tag);
    return projection;
  }, [request]);

  const loadHoldReleaseQueue = useCallback(async () => {
    const response = await request(`${TRUST_ROOT}/hold-release-queue`);
    const projection = parseTrustHoldReleaseQueueEnvelope(response.value);
    assertResponseEtag(response, projection.entity_tag);
    return projection;
  }, [request]);

  const loadAssignments = useCallback(async () => {
    const response = await request(TRUST_ASSIGNMENTS);
    const projection = parseTrustAssignmentListEnvelope(response.value);
    assertResponseEtag(response, projection.entity_tag);
    return projection;
  }, [request]);

  const loadCaseHistory = useCallback(async () => {
    const response = await request(TRUST_CASE_HISTORY);
    const projection = parseTrustCaseHistoryEnvelope(response.value);
    assertResponseEtag(response, projection.entity_tag);
    return projection;
  }, [request]);

  const loadQueueSnapshot = useCallback(async (): Promise<TrustQueueSnapshot> => {
    const [caseProjection, holdProjection, assignmentProjection, historyProjection] = await Promise.all([
      loadQueue(),
      loadHoldReleaseQueue(),
      loadAssignments(),
      loadCaseHistory(),
    ]);
    return {
      assignments: assignmentProjection.items,
      history: historyProjection,
      holdReleaseQueue: holdProjection.items,
      queue: caseProjection.items,
    };
  }, [loadAssignments, loadCaseHistory, loadHoldReleaseQueue, loadQueue]);

  const commitQueueSnapshot = useCallback((snapshot: TrustQueueSnapshot) => {
    setQueueSnapshot(snapshot);
    setQueueSnapshotLoaded(true);
    setQueueSnapshotUnavailable(false);
    setSelectedCase((current) => current && snapshot.assignments.some(
      (item) => item.assignment_purpose === "CASE_TRIAGE" && item.case_id === current.case_id,
    ) ? current : null);
    setSelectedHoldRelease((current) => current && snapshot.assignments.some(
      (item) => item.assignment_purpose === "HOLD_RELEASE" && item.hold_id === current.hold_id,
    ) ? current : null);
  }, []);

  const loadCase = useCallback(async (caseId: string) => {
    const response = await request(`${TRUST_ROOT}/cases/${encodeURIComponent(caseId)}`);
    const item = parseTrustCaseEnvelope(response.value);
    assertResponseEtag(response, item.entity_tag);
    if (item.case_id !== caseId) throw new TypeError("INVALID_TRUST_RESPONSE_BINDING");
    return item;
  }, [request]);

  const commitCase = useCallback((item: TrustCaseProjection) => {
    setSelectedCase(item);
    setSelectedHoldRelease(null);
    setAssignedCaseId(item.case_id);
  }, [setAssignedCaseId]);

  const loadAssignedHold = useCallback(async (holdId: string) => {
    const response = await request(`/v1/app/trust/assigned-holds/${encodeURIComponent(holdId)}`);
    const item = parseTrustAssignedHoldEnvelope(response.value);
    assertResponseEtag(response, item.entity_tag);
    if (item.hold_id !== holdId) throw new TypeError("INVALID_TRUST_RESPONSE_BINDING");
    return item;
  }, [request]);

  const commitAssignedHold = useCallback((item: TrustAssignedHoldProjection) => {
    setSelectedHoldRelease(item);
    setSelectedCase(null);
  }, []);

  const loadReport = useCallback(async (reportId: string) => {
    const response = await request(`${TRUST_ROOT}/reports/${encodeURIComponent(reportId)}`);
    const item = parseTrustReportEnvelope(response.value);
    assertResponseEtag(response, item.entity_tag);
    if (item.report_id !== reportId) throw new TypeError("INVALID_TRUST_RESPONSE_BINDING");
    return item;
  }, [request]);

  const commitReport = useCallback((item: TrustReportProjection) => {
    setOwnReport(item);
    setReportLookupId(item.report_id);
  }, []);

  const loadOwnReportPage = useCallback(async (cursor: string | null) => {
    const query = new URLSearchParams({ limit: "20" });
    if (cursor !== null) query.set("cursor", cursor);
    const response = await request(`${TRUST_ROOT}/reports?${query.toString()}`);
    const projection = parseTrustOwnReportListEnvelope(response.value);
    assertResponseEtag(response, projection.entity_tag);
    return projection;
  }, [request]);

  const commitOwnReportFirstPage = useCallback((page: TrustOwnReportListProjection) => {
    ownReportCursorChain.current = new Set(page.next_cursor === null ? [] : [page.next_cursor]);
    setOwnReportList({
      items: page.items,
      next_cursor: page.next_cursor,
      page_entity_tags: [page.entity_tag],
    });
    setOwnReportsLoaded(true);
    setOwnReport(null);
  }, []);

  const readCase = useCallback(async (
    caseId: string,
    validate: (item: TrustCaseProjection) => void = () => {},
  ) => {
    const result = await runDetailRead("POST_WRITE", {
      load: async () => {
        const item = await loadCase(caseId);
        validate(item);
        return item;
      },
      commit: () => {},
      onSuccess: () => {},
      onError: () => {},
    });
    if (result.ok) return result.snapshot;
    if ("error" in result) throw result.error;
    throw new TypeError("TRUST_DETAIL_READ_SUPERSEDED");
  }, [loadCase, runDetailRead]);

  const readAssignedHold = useCallback(async (
    holdId: string,
    validate: (item: TrustAssignedHoldProjection) => void = () => {},
  ) => {
    const result = await runDetailRead("POST_WRITE", {
      load: async () => {
        const item = await loadAssignedHold(holdId);
        validate(item);
        return item;
      },
      commit: () => {},
      onSuccess: () => {},
      onError: () => {},
    });
    if (result.ok) return result.snapshot;
    if ("error" in result) throw result.error;
    throw new TypeError("TRUST_DETAIL_READ_SUPERSEDED");
  }, [loadAssignedHold, runDetailRead]);

  const readReport = useCallback(async (
    reportId: string,
    validate: (item: TrustReportProjection) => void = () => {},
  ) => {
    const result = await runDetailRead("POST_WRITE", {
      load: async () => {
        const item = await loadReport(reportId);
        validate(item);
        return item;
      },
      commit: () => {},
      onSuccess: () => {},
      onError: () => {},
    });
    if (result.ok) return result.snapshot;
    if ("error" in result) throw result.error;
    throw new TypeError("TRUST_DETAIL_READ_SUPERSEDED");
  }, [loadReport, runDetailRead]);

  const readOwnReportPage = useCallback(async (
    cursor: string | null,
    validate: (page: TrustOwnReportListProjection) => void = () => {},
  ) => {
    const result = await runDetailRead("POST_WRITE", {
      load: () => loadOwnReportPage(cursor),
      validate,
      commit: () => {},
      onSuccess: () => {},
      onError: () => {},
    });
    if (result.ok) return result.snapshot;
    if ("error" in result) throw result.error;
    throw new TypeError("TRUST_DETAIL_READ_SUPERSEDED");
  }, [loadOwnReportPage, runDetailRead]);

  const refreshOwnReports = useCallback(async (origin: "INITIAL" | "MANUAL" | "NEXT") => {
    if (origin !== "INITIAL" && rejectNonRecoveryIfLocked()) return;
    const cursor = origin === "NEXT" ? ownReportList?.next_cursor ?? null : null;
    if (origin === "NEXT" && cursor === null) return;
    const prior = ownReportList;
    setError(null);
    if (origin === "MANUAL") {
      setNotice("正在从服务端重新发现我的举报与处理结果；完整成功前保留当前列表。");
    } else if (origin === "NEXT") {
      setNotice("正在读取下一页我的举报；现有结果会保留到新页完整验证后。");
    }
    const result = await runDetailRead("INTERACTIVE", {
      load: () => loadOwnReportPage(cursor),
      validate: (page) => {
        if (cursor === null) return;
        if (prior === null || prior.next_cursor !== cursor) {
          throw new TypeError("INVALID_TRUST_REPORT_CURSOR_BINDING");
        }
        const knownIds = new Set(prior.items.map((item) => item.report_id));
        if (page.items.some((item) => knownIds.has(item.report_id))) {
          throw new TypeError("INVALID_TRUST_REPORT_PAGE_OVERLAP");
        }
        if (
          prior.items.length > 0
          && page.items.length > 0
          && !isOwnedReportAfter(prior.items.at(-1)!, page.items[0])
        ) throw new TypeError("INVALID_TRUST_REPORT_LIST_ORDER");
        if (
          page.next_cursor !== null
          && (page.next_cursor === cursor || ownReportCursorChain.current.has(page.next_cursor))
        ) throw new TypeError("INVALID_TRUST_REPORT_CURSOR_CYCLE");
      },
      commit: (page) => {
        if (cursor === null) {
          commitOwnReportFirstPage(page);
          return;
        }
        setOwnReportList({
          items: [...prior!.items, ...page.items],
          next_cursor: page.next_cursor,
          page_entity_tags: [...prior!.page_entity_tags, page.entity_tag],
        });
        if (page.next_cursor !== null) ownReportCursorChain.current.add(page.next_cursor);
        setOwnReportsLoaded(true);
      },
      onSuccess: (page) => {
        setNotice(origin === "NEXT"
          ? `已验证并追加 ${page.items.length} 条举报；点击条目时仍会精确读取最新详情。`
          : `已从服务端发现 ${page.items.length} 条最近举报；列表不含叙事、证据内容或报告人身份。`);
      },
      onError: (caught) => {
        if (cursor === null) setOwnReportsLoaded(true);
        setError(failure(caught));
        setNotice(origin === "NEXT"
          ? "下一页读取失败；页面继续保留此前完整验证过的举报列表。"
          : "我的举报清单当前不可用；页面没有把读取失败显示为空列表。");
      },
    });
    if (!result.ok && "stale" in result && origin === "INITIAL") {
      setOwnReportInitialStarted(false);
    }
  }, [commitOwnReportFirstPage, loadOwnReportPage, ownReportList, rejectNonRecoveryIfLocked, runDetailRead]);

  const coordinatedRefreshQueues = useCallback(async (
    origin: "INITIAL" | "MANUAL" | "POST_WRITE",
    options: QueueRefreshOptions = {},
  ) => {
    if (origin !== "MANUAL") setInitialRefreshStarted(true);
    setError(null);
    if (!queueSnapshotLoaded) setQueueSnapshotUnavailable(false);
    if (origin === "MANUAL") {
      setNotice("正在从服务端同步 Trust 分配、两个队列与本人完成历史；完整成功前保留当前快照。");
    }
    const result = await queueRefreshCoordinator.run({
      load: loadQueueSnapshot,
      isValid: () => isReadGenerationValid(origin),
      validate: options.validate,
      commit: (snapshot) => {
        commitQueueSnapshot(snapshot);
        options.afterCommit?.(snapshot);
      },
      setBusy: (value) => {
        setRefreshing(value);
      },
      onSuccess: (snapshot) => {
        if (origin !== "POST_WRITE") {
          setNotice(`${origin === "MANUAL" ? "已原子更新" : "已核对"} ${snapshot.assignments.length} 个我的活动分配、${snapshot.queue.length} 个待领取案件、${snapshot.holdReleaseQueue.length} 个高风险解除复核和 ${snapshot.history?.items.length ?? 0} 条本人完成记录。`);
        }
      },
      onError: (caught) => {
        if (origin !== "POST_WRITE") {
          if (!queueSnapshotLoaded) setQueueSnapshotUnavailable(true);
          setError(failure(caught));
          setNotice(origin === "MANUAL"
            ? "Trust 刷新失败；分配、队列与历史继续显示刷新前的同一快照，没有混合新旧结果。"
            : "Trust 分配、队列或历史当前不可用；页面没有构造本地案件。");
        }
      },
    });
    if (!result.ok && "stale" in result && origin === "INITIAL") {
      setInitialRefreshStarted(false);
    }
    return result;
  }, [commitQueueSnapshot, isReadGenerationValid, loadQueueSnapshot, queueRefreshCoordinator, queueSnapshotLoaded]);

  const refreshQueues = useCallback(async (options: QueueRefreshOptions = {}) => {
    const result = await coordinatedRefreshQueues("POST_WRITE", options);
    if (result.ok) return result.snapshot;
    if ("error" in result) throw result.error;
    throw new TypeError("TRUST_QUEUE_REFRESH_SUPERSEDED");
  }, [coordinatedRefreshQueues]);

  const manuallyRefreshQueues = useCallback(async () => {
    if (rejectNonRecoveryIfLocked()) return;
    await coordinatedRefreshQueues("MANUAL");
  }, [coordinatedRefreshQueues, rejectNonRecoveryIfLocked]);

  useLayoutEffect(() => {
    if (recoveryChecked) return;
    let cancelled = false;
    queueMicrotask(() => {
      if (cancelled) return;
      const recovered = parsePendingIntent(sessionStorage.getItem(PENDING_KEY) ?? "");
      if (isTrustPending(recovered)) {
        const roleAllowed = recovered.resource_type === "TRUST_REPORT" ? canSubmitReport : canOperateCases;
        if (!roleAllowed || isRestrictedNoteWrite(recovered) || !claimWrite(recovered)) {
          sessionStorage.removeItem(PENDING_KEY);
        } else {
          setPending(recovered);
          setNotice("发现一笔结果未知的 Trust 写入；只能原样重试或明确放弃。");
        }
      }
      setRecoveryChecked(true);
    });
    return () => {
      cancelled = true;
    };
  }, [canOperateCases, canSubmitReport, claimWrite, recoveryChecked]);

  useLayoutEffect(() => {
    let cancelled = false;
    if ((writeLocked || pending !== null) && !controlledRefreshActive.current) {
      queueRefreshCoordinator.invalidate();
      detailReadCoordinator.invalidate();
      queueMicrotask(() => {
        if (!cancelled) {
          setReading(false);
          setRefreshing(false);
        }
      });
    }
    return () => {
      cancelled = true;
    };
  }, [detailReadCoordinator, pending, queueRefreshCoordinator, writeLocked]);

  useEffect(() => {
    if (
      !recoveryChecked
      || initialRefreshStarted
      || !canOperateCases
      || busy
      || reading
      || refreshing
      || writeLocked
      || pending !== null
    ) return;
    let cancelled = false;
    queueMicrotask(() => {
      if (!cancelled) void coordinatedRefreshQueues("INITIAL");
    });
    return () => {
      cancelled = true;
    };
  }, [busy, canOperateCases, coordinatedRefreshQueues, initialRefreshStarted, pending, reading, recoveryChecked, refreshing, writeLocked]);

  useEffect(() => {
    if (caseHistoryTaskTarget === null) {
      attemptedHistoryTaskRef.current = null;
      return;
    }
    if (
      attemptedHistoryTaskRef.current === caseHistoryTaskTarget.request_id
      || !recoveryChecked
      || busy
      || reading
      || refreshing
      || writeLocked
      || pending !== null
    ) return;
    attemptedHistoryTaskRef.current = caseHistoryTaskTarget.request_id;
    const staleOrMismatched = (
      !canOperateCases
      || caseHistoryTaskTarget.session_id !== session.session.session_id
      || caseHistoryTaskTarget.workspace_id !== workspace.workspace_id
    );
    let cancelled = false;
    let focusFrame: number | null = null;
    const requestId = caseHistoryTaskTarget.request_id;
    const caseId = caseHistoryTaskTarget.case_id;
    queueMicrotask(() => {
      if (cancelled) return;
      if (staleOrMismatched) {
        setError({ status: 409, code: "TRUST_HISTORY_TASK_TARGET_STALE_OR_MISMATCHED", traceId: null });
        setNotice("完成任务与当前会话、工作区或 TRUST_OFFICER 职责不再匹配；页面没有读取任务路径或发送写入。");
        return;
      }
      void coordinatedRefreshQueues("MANUAL", {
        validate: (snapshot) => {
          if (!snapshot.history?.items.some((item) => item.case_id === caseId)) {
            throw new TypeError("TRUST_HISTORY_TASK_TARGET_NO_LONGER_AVAILABLE");
          }
        },
      }).then((result) => {
        if (cancelled || attemptedHistoryTaskRef.current !== requestId) return;
        if (!result.ok) {
          if ("stale" in result) {
            attemptedHistoryTaskRef.current = null;
            return;
          }
          const exactMissing = result.error instanceof TypeError
            && result.error.message === "TRUST_HISTORY_TASK_TARGET_NO_LONGER_AVAILABLE";
          setError(exactMissing
            ? { status: 409, code: "TRUST_HISTORY_TASK_TARGET_NO_LONGER_AVAILABLE", traceId: null }
            : failure(result.error));
          setNotice(exactMissing
            ? "任务已经重核对，但 fresh 本人历史不再包含 exact Trust Case；页面保留此前完整快照，没有按任务路径读取案件。"
            : "任务已经重核对，但 fresh 本人历史读取失败；页面保留此前完整快照，没有把失败解释为案件消失。");
          return;
        }
        setError(null);
        setNotice("当前会话、工作区、任务与 fresh exact Trust 完成记录已核对；已定位本人只读历史，不需要粘贴 Case ID。");
        focusFrame = window.requestAnimationFrame(() => {
          const destination = historyItemRefs.current.get(caseId);
          if (!destination) return;
          destination.focus({ preventScroll: true });
          destination.scrollIntoView({ block: "center", behavior: "auto" });
        });
      });
    });
    return () => {
      cancelled = true;
      if (focusFrame !== null) window.cancelAnimationFrame(focusFrame);
    };
  }, [busy, canOperateCases, caseHistoryTaskTarget, coordinatedRefreshQueues, pending, reading, recoveryChecked, refreshing, session.session.session_id, workspace.workspace_id, writeLocked]);

  useEffect(() => {
    if (
      !recoveryChecked
      || ownReportsLoaded
      || ownReportInitialStarted
      || !canSubmitReport
      || busy
      || reading
      || refreshing
      || writeLocked
      || pending !== null
    ) return;
    let cancelled = false;
    queueMicrotask(() => {
      if (cancelled) return;
      setOwnReportInitialStarted(true);
      void refreshOwnReports("INITIAL");
    });
    return () => {
      cancelled = true;
    };
  }, [busy, canSubmitReport, ownReportInitialStarted, ownReportsLoaded, pending, reading, recoveryChecked, refreshOwnReports, refreshing, writeLocked]);

  useLayoutEffect(() => {
    return () => {
      detailReadCoordinator.invalidate();
      queueRefreshCoordinator.invalidate();
    };
  }, [detailReadCoordinator, queueRefreshCoordinator]);

  const performWrite = useCallback(async (candidate: PendingIntent) => {
    const record = pending ?? candidate;
    if (pending && serializePendingIntent(pending) !== serializePendingIntent(candidate)) {
      setError({ status: 0, code: "WRITE_OUTCOME_PENDING", traceId: null });
      return;
    }
    if (!claimWrite(record)) {
      setError({ status: 0, code: "WRITE_OUTCOME_PENDING", traceId: null });
      setNotice("已有另一笔写入占用全局门闩；当前 Trust 请求没有发送。");
      return;
    }
    if (!pending) persistPending(record);
    setBusy(true);
    setError(null);
    setNotice(`正在${record.label}；结果明确前不会更换幂等键或载荷。`);
    let writeConfirmed = false;
    try {
      const result = await request(record.intent.path, {
        method: record.intent.method,
        headers: record.intent.headers,
        body: JSON.stringify(record.intent.body),
      });
      // Any 2xx write response is terminal even if its body is malformed. Do
      // not replay a possibly committed command merely because presentation
      // validation or the subsequent authorized read fails.
      writeConfirmed = true;
      const committed = parseTrustCommandEnvelope(result.value);
      const eventType = expectedCommandEvent(record.intent.path);
      if (result.etag !== null || committed.event_types[0] !== eventType) {
        throw new TypeError("INVALID_TRUST_COMMAND_RESPONSE");
      }
      if (record.resource_type === "TRUST_REPORT") {
        if (!committed.report_id || committed.event_types[0] !== "TrustReportSubmitted") {
          throw new TypeError("INVALID_TRUST_RESPONSE_BINDING");
        }
        controlledRefreshActive.current = true;
        settlePendingForRefresh();
        const stagedReport = await readReport(committed.report_id, (fresh) => {
          if (
            fresh.report_id !== committed.report_id
            || fresh.demand_id !== record.object_id
            || fresh.demand_version_id !== record.intent.body.demand_version_id
            || etagVersion(fresh.entity_tag) < committed.aggregate_version
          ) throw new TypeError("INVALID_TRUST_RESPONSE_BINDING");
        });
        const freshReportList = await readOwnReportPage(null, (page) => {
          if (!page.items.some((item) => item.report_id === committed.report_id)) {
            throw new TypeError("INVALID_TRUST_REPORT_DISCOVERY_BINDING");
          }
        });
        commitOwnReportFirstPage(freshReportList);
        commitReport(stagedReport);
        releaseWrite(record);
        setNotice("私密结构化报告已确认；精确详情与“我的举报”首页均已 fresh GET 并重新绑定 ETag。报告人身份未进入投影。");
        return;
      }
      const holdClaim = record.intent.path.match(/\/hold-release-queue\/([^/]+)\/claim$/);
      const holdRelease = record.intent.path.match(/\/trust\/holds\/([^/]+)\/release$/);
      const holdRouteId = holdClaim?.[1] ?? holdRelease?.[1] ?? null;
      const refreshReleasedHoldCase = holdRelease !== null && record.resource_type === "TRUST_CASE";
      if (holdRelease && committed.hold_id !== holdRouteId) {
        throw new TypeError("INVALID_TRUST_RESPONSE_BINDING");
      }
      if (record.resource_type === "TRUST_HOLD") {
        if (!holdRouteId || holdRouteId !== record.object_id || committed.hold_id !== record.object_id) {
          throw new TypeError("INVALID_TRUST_RESPONSE_BINDING");
        }
      } else if (committed.case_id !== record.object_id) {
        throw new TypeError("INVALID_TRUST_RESPONSE_BINDING");
      }
      controlledRefreshActive.current = true;
      settlePendingForRefresh();
      let freshCase: TrustCaseProjection | null = null;
      let freshHold: TrustAssignedHoldProjection | null = null;
      if (holdClaim) {
        freshHold = await readAssignedHold(record.object_id, (fresh) => {
          if (
            fresh.case_id !== committed.case_id
            || (committed.hold_version !== null && etagVersion(fresh.entity_tag) < committed.hold_version)
          ) throw new TypeError("INVALID_TRUST_RESPONSE_BINDING");
        });
      } else if (!record.intent.path.endsWith("/assignment/release") && (!holdRelease || refreshReleasedHoldCase)) {
        freshCase = await readCase(committed.case_id, (fresh) => {
          if (fresh.aggregate_version < committed.aggregate_version || etagVersion(fresh.entity_tag) < committed.aggregate_version) {
            throw new TypeError("INVALID_TRUST_RESPONSE_BINDING");
          }
          if (refreshReleasedHoldCase && fresh.active_hold !== null) {
            throw new TypeError("INVALID_TRUST_RELEASED_HOLD_STILL_ACTIVE");
          }
        });
      }
      await refreshQueues({
        validate: (snapshot) => validateTrustPostWriteSnapshot(
          snapshot,
          eventType,
          committed.case_id,
          committed.hold_id ?? holdRouteId,
          refreshReleasedHoldCase,
        ),
        afterCommit: (snapshot) => {
          if (freshHold && snapshot.assignments.some(
            (item) => item.assignment_purpose === "HOLD_RELEASE" && item.hold_id === freshHold?.hold_id,
          )) commitAssignedHold(freshHold);
          if (freshCase && snapshot.assignments.some(
            (item) => item.assignment_purpose === "CASE_TRIAGE" && item.case_id === freshCase?.case_id,
          )) commitCase(freshCase);
          if (holdRelease && !refreshReleasedHoldCase) setSelectedCase(null);
        },
      });
      if (isRestrictedNoteWrite(record)) setRestrictedNote("");
      if (record.intent.path.endsWith("/assignment/release")) {
        setNotice("案件分配已释放；command receipt 与 fresh GET 队列一致，旧案件详情已清除。");
      } else if (holdRelease) {
        setNotice("Safety Hold 已解除；command receipt 与 fresh GET 队列一致，旧 Hold 详情已清除。");
      } else if (holdClaim) {
        setNotice("高风险解除复核已领取；已按 committed hold ID fresh GET，并绑定专属 Hold ETag。");
      } else {
        setNotice(`${record.label}已确认；已 fresh GET 案件与完整队列并绑定 case ID、聚合版本与 ETag。`);
      }
      releaseWrite(record);
    } catch (caught) {
      if (
        caught instanceof TypeError
        && (caught.message === "TRUST_DETAIL_READ_SUPERSEDED" || caught.message === "TRUST_QUEUE_REFRESH_SUPERSEDED")
      ) {
        releaseWrite(record);
        return;
      }
      if (writeConfirmed) {
        clearPending(record);
        setError({ status: 503, code: "TRUST_POST_COMMIT_REFRESH_FAILED", traceId: null });
        setNotice(`${record.label}已由服务端确认，但 fresh GET 绑定失败；请刷新工作台，不能重放已确认写入。`);
        return;
      }
      const problem = failure(caught);
      const outcomeUnknown = problem.status === 0 || problem.status >= 500;
      if (!outcomeUnknown) {
        if (problem.status === 412 && canOperateCases) {
          controlledRefreshActive.current = true;
          settlePendingForRefresh();
          try {
            await refreshQueues();
            if (record.resource_type === "TRUST_HOLD") {
              commitAssignedHold(await readAssignedHold(record.object_id));
            } else if (record.resource_type === "TRUST_CASE" && !record.intent.path.endsWith("/assignment/release")) {
              commitCase(await readCase(record.object_id));
            }
          } catch {
            setSelectedCase(null);
            setSelectedHoldRelease(null);
          } finally {
            releaseWrite(record);
          }
        } else {
          clearPending(record);
        }
      }
      setError(problem);
      setNotice(outcomeUnknown
        ? "Trust 写入结果未知；全局门闩保留同一请求，可原样重试或人工放弃。"
        : "服务端已明确拒绝 Trust 写入；旧请求已清除，请依据 fresh GET 事实重新操作。");
    } finally {
      controlledRefreshActive.current = false;
      setBusy(false);
    }
  }, [canOperateCases, claimWrite, clearPending, commitAssignedHold, commitCase, commitOwnReportFirstPage, commitReport, pending, persistPending, readAssignedHold, readCase, readOwnReportPage, readReport, refreshQueues, releaseWrite, request, setRestrictedNote, settlePendingForRefresh]);

  async function lookupReport(event: FormEvent) {
    event.preventDefault();
    if (rejectNonRecoveryIfLocked()) return;
    setError(null);
    setOwnReport(null);
    await runDetailRead("INTERACTIVE", {
      load: () => loadReport(reportLookupId),
      commit: commitReport,
      onSuccess: () => setNotice("已读取当前报告人的安全报告投影；没有报告人身份、叙事或权限字段。"),
      onError: (caught) => {
        setOwnReport(null);
        setError(failure(caught));
        setNotice("按报告 ID 读取失败；页面已清除旧详情与旧申诉入口。");
      },
    });
  }

  async function openOwnedReport(item: TrustOwnReportItem) {
    if (rejectNonRecoveryIfLocked()) return;
    setError(null);
    await runDetailRead("INTERACTIVE", {
      load: () => loadReport(item.report_id),
      validate: (fresh) => {
        if (
          fresh.report_id !== item.report_id
          || fresh.demand_id !== item.demand_id
          || fresh.report.category !== item.category
          || fresh.submitted_at !== item.submitted_at
        ) throw new TypeError("INVALID_TRUST_REPORT_DISCOVERY_BINDING");
      },
      commit: commitReport,
      onSuccess: () => setNotice("已按服务端发现的报告 ID 精确读取最新安全详情；列表摘要未被当作详情或申诉依据。"),
      onError: (caught) => {
        setOwnReport(null);
        setError(failure(caught));
        setNotice("举报详情已变化、不可用或当前无权读取；页面没有继续显示旧详情。");
      },
    });
  }

  function beginAppealHandoff(handoff: AppealHandoff) {
    if (rejectNonRecoveryIfLocked()) return;
    if (!canSubmitReport || !isAppealHandoffCurrent(handoff, {
      sessionId: session.session.session_id,
      workspaceId: workspace.workspace_id,
    })) {
      setError({ status: 409, code: "APPEAL_HANDOFF_STALE_OR_MISMATCHED", traceId: null });
      setNotice("该报告已不满足同会话交接条件；页面没有向 Appeal 工作台传递来源。");
      return;
    }
    onBeginAppeal(handoff);
    setError(null);
    setNotice("已把 fresh-read party-safe Trust 结论交给同一 Demand Owner 工作区；Appeal 将先 GET 查重，绝不会自动打开申诉。");
  }

  function submitReport(event: FormEvent) {
    event.preventDefault();
    try {
      const target = selectedReportTarget;
      if (!demandsAvailable || !target) {
        throw new TypeError("TRUST_REPORT_TARGET_REQUIRED");
      }
      const intent = createTrustReportIntent({
        csrfToken: session.csrf_token,
        idempotencyKey: crypto.randomUUID(),
        demandId: target.object_id,
        demandVersionId: target.current_version.version_id,
        category,
        evidenceReferenceIds: [target.current_version.version_id],
        impactCodes,
        incidentStartedAt: toUtc(incidentStartedAt),
        incidentEndedAt: incidentEndedAt ? toUtc(incidentEndedAt) : null,
        requestedProtectionCodes: protectionCodes,
      });
      void performWrite(pendingRecord("TRUST_REPORT", target.object_id, "提交私密安全报告", intent));
    } catch (caught) {
      setError({ status: 400, code: caught instanceof Error ? caught.message : "INVALID_TRUST_REPORT", traceId: null });
    }
  }

  function startCaseWrite(label: string, intentFactory: () => PendingIntent["intent"]) {
    if (!selectedCase) return;
    try {
      void performWrite(pendingRecord("TRUST_CASE", selectedCase.case_id, label, intentFactory()));
    } catch (caught) {
      setError({ status: 400, code: caught instanceof Error ? caught.message : "INVALID_TRUST_COMMAND", traceId: null });
    }
  }

  function saveTriageDraft(event: FormEvent) {
    event.preventDefault();
    if (!selectedCase) return;
    if (!restrictedNote.trim()) {
      setError({ status: 422, code: "TRUST_RESTRICTED_NOTE_REQUIRED", traceId: null });
      setNotice("请先填写受限备注，再保存分诊草稿；页面没有发送空白草稿。");
      return;
    }
    startCaseWrite("保存受限分诊草稿", () => createTrustTriageDraftIntent({
      trustCase: selectedCase,
      triage: {
        investigation_step_codes: investigationCodes,
        issue_codes: issueCodes,
        jurisdiction_code: jurisdictionCode,
        priority_code: priorityCode,
        proposed_hold_actions: proposedHoldActions,
        proposed_hold_ttl_minutes: proposedHoldTtl,
        restricted_note: restrictedNote,
        severity_code: severityCode,
      },
      csrfToken: session.csrf_token,
      idempotencyKey: crypto.randomUUID(),
    }));
  }

  function claimCase(item: TrustQueueItem) {
    try {
      const intent = createTrustCaseClaimIntent({
        queueItem: item,
        csrfToken: session.csrf_token,
        idempotencyKey: crypto.randomUUID(),
      });
      void performWrite(pendingRecord("TRUST_CASE", item.case_id, "领取 Trust 案件", intent));
    } catch (caught) {
      setError({ status: 400, code: caught instanceof Error ? caught.message : "INVALID_TRUST_CLAIM", traceId: null });
    }
  }

  function claimHoldRelease(item: TrustHoldReleaseQueueItem) {
    try {
      const intent = createTrustHoldReleaseClaimIntent({
        queueItem: item,
        csrfToken: session.csrf_token,
        idempotencyKey: crypto.randomUUID(),
      });
      void performWrite(pendingRecord("TRUST_HOLD", item.hold_id, "领取高风险解除复核", intent));
    } catch (caught) {
      setError({ status: 400, code: caught instanceof Error ? caught.message : "INVALID_TRUST_HOLD_CLAIM", traceId: null });
    }
  }

  function releaseAssignedHold(event: FormEvent) {
    event.preventDefault();
    if (!selectedHoldRelease) return;
    try {
      const intent = createTrustAssignedHoldReleaseIntent({
        assignedHold: selectedHoldRelease,
        reasonCode: holdReleaseReason,
        csrfToken: session.csrf_token,
        idempotencyKey: crypto.randomUUID(),
      });
      void performWrite(pendingRecord(
        "TRUST_HOLD",
        selectedHoldRelease.hold_id,
        "解除已分配的 Demand Safety Hold",
        intent,
      ));
    } catch (caught) {
      setError({ status: 400, code: caught instanceof Error ? caught.message : "INVALID_TRUST_HOLD_RELEASE", traceId: null });
    }
  }

  async function openAssignedCase(event: FormEvent) {
    event.preventDefault();
    if (rejectNonRecoveryIfLocked()) return;
    setError(null);
    await runDetailRead("INTERACTIVE", {
      load: () => loadCase(assignedCaseId),
      commit: commitCase,
      onSuccess: () => setNotice("已读取当前 Trust Officer 有效分配对应的安全案件详情。"),
      onError: (caught) => {
        setSelectedCase(null);
        setError(failure(caught));
      },
    });
  }

  async function openDiscoveredCase(caseId: string) {
    if (rejectNonRecoveryIfLocked()) return;
    setError(null);
    await runDetailRead("INTERACTIVE", {
      load: () => loadCase(caseId),
      commit: commitCase,
      onSuccess: () => setNotice("已从我的活动分配读取安全案件详情；标识仅保留在当前页面内存。"),
      onError: (caught) => {
        setSelectedCase(null);
        setError(failure(caught));
        setNotice("活动分配已变化或当前无权读取；页面没有保留旧案件详情。");
      },
    });
  }

  async function openDiscoveredHold(holdId: string) {
    if (rejectNonRecoveryIfLocked()) return;
    setError(null);
    await runDetailRead("INTERACTIVE", {
      load: () => loadAssignedHold(holdId),
      commit: commitAssignedHold,
      onSuccess: () => setNotice("已从我的活动分配读取对应 Hold 解除投影；标识仅保留在当前页面内存。"),
      onError: (caught) => {
        setSelectedHoldRelease(null);
        setError(failure(caught));
        setNotice("Hold 活动分配已变化或当前无权读取；页面没有保留旧 Hold 详情。");
      },
    });
  }

  const actionLocked = nonRecoveryControlsLocked({
    busy: busy || reading || refreshing || !recoveryChecked,
    pending,
    writeLocked,
  });

  return (
    <section className="trust-workbench" aria-labelledby="trust-workbench-title">
      <div className="trust-heading">
        <div>
          <p className="eyebrow">PRIVATE TRUST · SAFE PROJECTIONS</p>
          <h2 id="trust-workbench-title" tabIndex={-1}>安全报告与 Trust 处置</h2>
          <p>客户端不声明 actor、职责、分配、证据包或申诉资格；所有权限和决定证据均由服务端派生。</p>
        </div>
        {canOperateCases && <button
          aria-busy={refreshing}
          className="quiet-button"
          disabled={actionLocked}
          type="button"
          onClick={() => void manuallyRefreshQueues()}
        >{refreshing ? "正在刷新 Trust 队列…" : "刷新 Trust 队列"}</button>}
      </div>

      <div className="live-notice" aria-live="polite"><strong>Trust 状态</strong><span>{notice}</span></div>
      {error && <div className="error-panel" role="alert"><strong>{error.code}</strong>{error.traceId && <small>追踪编号：<code>{error.traceId}</code></small>}</div>}

      {pending && <div className="unknown-panel">
        <div>
          <p className="eyebrow">TRUST WRITE OUTCOME UNKNOWN</p>
          <h3>{pending.label}</h3>
          <p>当前标签页保留同一请求。{isRestrictedNoteWrite(pending) ? "受限备注仅留在内存，刷新页面后不会恢复。" : "非敏感结构化请求可在当前会话恢复。"}</p>
        </div>
        <div className="recovery-actions">
          <button className="primary-button" disabled={busy || reading || refreshing || writeLocked} type="button" onClick={() => void performWrite(pending)}>原样重试 Trust 写入</button>
          <button className="quiet-button" disabled={busy || reading || refreshing || writeLocked} type="button" onClick={() => {
            if (isRestrictedNoteWrite(pending)) setRestrictedNote("");
            clearPending(pending);
            setNotice("已放弃浏览器恢复对象；页面没有据此推断服务端结果。");
          }}>放弃 Trust 恢复</button>
        </div>
      </div>}

      <fieldset
        aria-disabled={actionLocked}
        className={actionLocked ? "pending-write-scope pending-write-scope--locked" : "pending-write-scope"}
        disabled={actionLocked}
      >
        <legend className="sr-only">Trust 工作台非恢复操作</legend>
      {canSubmitReport && <div className="trust-grid">
        <form className="workbench-card trust-form" onSubmit={submitReport}>
          <div className="report-target-heading">
            <p className="eyebrow">DEMAND OWNER · AUTHORIZED WORKSPACE LIST</p>
            <h3>从我的需求中选择举报对象</h3>
          </div>
          {!demandsAvailable && <p className="error-panel" role="alert">当前工作区的需求清单不可用；页面没有把失败显示为零。</p>}
          {demandsAvailable && reportTargets.length === 0 && <p className="empty-state">当前没有处于可举报状态且带有当前版本的需求。</p>}
          {demandsAvailable && reportTargets.length > 0 && <fieldset className="report-target-choices">
            <legend>可举报需求（必须明确选择）</legend>
            {reportTargets.map((target) => <label
              className={selectedReportTarget?.current_version.version_id === target.current_version.version_id
                ? "report-target-option report-target-option--selected"
                : "report-target-option"}
              key={target.current_version.version_id}
            >
              <span className="sr-only">选择这个可举报需求</span>
              <input
                checked={selectedReportTarget?.current_version.version_id === target.current_version.version_id}
                name="trust-report-target"
                required
                type="radio"
                value={target.current_version.version_id}
                onChange={() => setSelectedReportTargetVersionId(target.current_version.version_id)}
              />
              <span>
                <strong>{target.status} · 版本 {target.current_version.version_no}</strong>
                <small>需求 {target.object_id.slice(0, 8)}… · 修订 {target.revision}</small>
              </span>
            </label>)}
          </fieldset>}
          <small>这里复用当前工作区已授权的需求投影，并把当前版本同时作为合成证据引用；提交时服务端会再次核对所有权、状态、精确版本和举报期限。页面不接受手工粘贴。</small>
          <label>报告类别<select value={category} onChange={(event) => setCategory(event.target.value as (typeof TRUST_REPORT_CATEGORIES)[number])}>{TRUST_REPORT_CATEGORIES.map((code) => <option key={code}>{code}</option>)}</select></label>
          <CodeChoices legend="影响代码" codes={TRUST_IMPACT_CODES} selected={impactCodes} onChange={setImpactCodes} />
          <CodeChoices legend="请求保护" codes={TRUST_PROTECTION_CODES} selected={protectionCodes} onChange={setProtectionCodes} />
          <label>事件开始<input required type="datetime-local" value={incidentStartedAt} onChange={(event) => setIncidentStartedAt(event.target.value)} /></label>
          <label>事件结束（可空）<input type="datetime-local" value={incidentEndedAt} onChange={(event) => setIncidentEndedAt(event.target.value)} /></label>
          <button className="primary-button" disabled={actionLocked || !demandsAvailable || !selectedReportTarget} type="submit">提交安全报告</button>
        </form>
        <div className="workbench-card">
          <div className="button-row">
            <div>
              <p className="eyebrow">DEMAND OWNER · SERVER-DISCOVERED</p>
              <h3>我的举报与处理结果 <span>{ownReportsLoaded && ownReportList !== null ? ownReportList.items.length : "—"}</span></h3>
            </div>
            <button
              aria-busy={reading}
              className="quiet-button"
              disabled={actionLocked}
              type="button"
              onClick={() => void refreshOwnReports("MANUAL")}
            >{reading ? "正在读取…" : "重新发现"}</button>
          </div>
          <p>这里只列出当前账号与组织范围内的最小摘要；叙事、证据内容和报告人身份不会进入列表。</p>
          {!ownReportsLoaded && <p className="empty-state">正在从服务端发现我的举报…</p>}
          {ownReportsLoaded && ownReportList === null && <p className="error-panel">举报清单当前不可用；这不代表没有举报。</p>}
          {ownReportList?.items.length === 0 && <p className="empty-state">当前账号尚无可发现的举报。</p>}
          {ownReportList?.items.map((item) => <button
            className="resource-link"
            disabled={actionLocked}
            key={item.report_id}
            type="button"
            onClick={() => void openOwnedReport(item)}
          >
            <strong>{item.category} · {item.status}</strong>
            <span>提交：{localTime(item.submitted_at)} · 需求 {item.demand_id.slice(0, 8)}…</span>
            {item.outcome
              ? <span>处理结果：{item.outcome.outcome_code} · 申诉资格：{item.outcome.appeal_eligibility_code}{item.outcome.appeal_deadline ? ` · 截止 ${localTime(item.outcome.appeal_deadline)}` : ""}</span>
              : <span>处理结果尚未发布</span>}
            <b>读取最新详情</b>
          </button>)}
          {ownReportList?.next_cursor && <button
            className="quiet-button"
            disabled={actionLocked}
            type="button"
            onClick={() => void refreshOwnReports("NEXT")}
          >加载更多</button>}
          {ownReport && <ReportSummary
            actionLocked={actionLocked}
            key={ownReport.entity_tag}
            onBeginAppeal={beginAppealHandoff}
            report={ownReport}
            sessionId={session.session.session_id}
            workspaceId={workspace.workspace_id}
          />}
          <details>
            <summary>诊断：按报告 ID 读取</summary>
            <p>正常使用请从上方服务端清单选择；这里仅用于恢复或支持诊断。</p>
            <form onSubmit={lookupReport}>
              <label>报告 ID<input required value={reportLookupId} onChange={(event) => setReportLookupId(event.target.value)} /></label>
              <button className="quiet-button" disabled={actionLocked} type="submit">读取安全投影</button>
            </form>
          </details>
        </div>
      </div>}

      {canOperateCases && <>
        <section className="workbench-card trust-case-history" aria-labelledby="trust-case-history-title">
          <div className="button-row">
            <div>
              <p className="eyebrow">TRUST OFFICER · 本人终态记录</p>
              <h3 id="trust-case-history-title" tabIndex={-1}>我的已完成 Trust 案件 <span>{queueSnapshotLoaded ? history?.items.length ?? 0 : "—"}</span></h3>
            </div>
            <button
              aria-busy={refreshing}
              className="quiet-button"
              disabled={actionLocked}
              type="button"
              onClick={() => void manuallyRefreshQueues()}
            >{refreshing ? "正在同步…" : "同步任务与历史"}</button>
          </div>
          <p>这里只展示当前 TRUST_OFFICER 本人发布的终态结论；不包含报告人、组织、受限备注、证据内容或其他处置人员。</p>
          {!queueSnapshotLoaded && !queueSnapshotUnavailable && <p className="empty-state">正在从服务端核对本人完成历史…</p>}
          {!queueSnapshotLoaded && queueSnapshotUnavailable && <p className="error-panel">本人完成历史当前不可用；这不代表没有完成记录。</p>}
          {queueSnapshotLoaded && history?.items.length === 0 && <p className="empty-state">当前账号还没有已完成的 Trust 案件。</p>}
          {history && history.items.length > 0 && <ol className="review-history-list">
            {history.items.map((item) => <li key={item.case_id}>
              <article
                aria-current={caseHistoryTaskTarget?.case_id === item.case_id ? "true" : undefined}
                data-trust-history-case-id={item.case_id}
                ref={(node) => {
                  if (node) historyItemRefs.current.set(item.case_id, node);
                  else historyItemRefs.current.delete(item.case_id);
                }}
                tabIndex={-1}
              >
                <div className="review-history-item-heading">
                  <strong>{item.outcome_code}</strong>
                  <time dateTime={item.decided_at}>{localTime(item.decided_at)}</time>
                </div>
                <dl><div><dt>Case</dt><dd><code>{item.case_id}</code></dd></div></dl>
              </article>
            </li>)}
          </ol>}
          {history && <p className="safe-projection" role="status">
            <code>has_more={String(history.has_more)}</code>{history.has_more
              ? " · 服务端还有更早的本人完成记录；当前有界 history v1 不提供游标，页面不会猜测或补齐。"
              : " · 当前授权历史已到末尾。"}
          </p>}
        </section>

        <section className="workbench-card">
          <div className="button-row">
            <div>
              <p className="eyebrow">TRUST OFFICER · SERVER-DERIVED</p>
              <h3>我的活动分配 <span>{queueSnapshotLoaded ? assignments.length : "—"}</span></h3>
            </div>
            <button
              aria-busy={refreshing}
              className="quiet-button"
              disabled={actionLocked}
              type="button"
              onClick={() => void manuallyRefreshQueues()}
            >{refreshing ? "正在同步…" : "同步分配与队列"}</button>
          </div>
          {!queueSnapshotLoaded && !queueSnapshotUnavailable && <p className="empty-state">正在从服务端核对活动分配…</p>}
          {!queueSnapshotLoaded && queueSnapshotUnavailable && <p className="error-panel">活动分配当前不可用；这不代表没有分配。</p>}
          {queueSnapshotLoaded && assignments.length === 0 && <p className="empty-state">当前没有活动分配。</p>}
          {assignments.map((item) => <button
            className="resource-link"
            disabled={actionLocked}
            key={JSON.stringify([item.assignment_purpose, item.case_id, item.hold_id])}
            type="button"
            onClick={() => void (item.assignment_purpose === "CASE_TRIAGE"
              ? openDiscoveredCase(item.case_id)
              : openDiscoveredHold(item.hold_id))}
          >
            <strong>{TRUST_ASSIGNMENT_LABELS[item.assignment_purpose]}</strong>
            <span>分配截止：{localTime(item.assignment_expires_at)}</span>
            <b>继续处理</b>
          </button>)}
          <small>分配由当前会话与服务端职责授权派生；Case/Hold ID 仅在当前页面内存中用于精确安全读取。</small>
        </section>

        <div className="trust-grid trust-queues">
          <div className="workbench-card">
            <p className="eyebrow">TRUST OFFICER</p>
            <h3>案件领取队列 <span>{queueSnapshotLoaded ? queue.length : "—"}</span></h3>
            {!queueSnapshotLoaded && !queueSnapshotUnavailable && <p>正在从服务端核对案件队列…</p>}
            {!queueSnapshotLoaded && queueSnapshotUnavailable && <p className="error-panel">案件队列当前不可用；这不代表没有未领取案件。</p>}
            {queueSnapshotLoaded && queue.length === 0 && <p>当前没有未领取案件。</p>}
            {queue.map((item) => <button className="resource-link" disabled={actionLocked} key={item.case_id} type="button" onClick={() => claimCase(item)}>
              <strong>{item.category}</strong><span>{item.impact_codes.join(" · ")}</span><code>{item.case_id}</code><b>领取案件</b>
            </button>)}
          </div>
          <div className="workbench-card high-risk-card">
            <p className="eyebrow">INDEPENDENT SECOND OFFICER</p>
            <h3>高风险解除复核 <span>{queueSnapshotLoaded ? holdReleaseQueue.length : "—"}</span></h3>
            <p>与首位处置人员相同的 TRUST_OFFICER 界面；服务端负责独立人员、职责和冲突校验。</p>
            {!queueSnapshotLoaded && !queueSnapshotUnavailable && <p>正在从服务端核对高风险解除复核…</p>}
            {!queueSnapshotLoaded && queueSnapshotUnavailable && <p className="error-panel">高风险解除复核当前不可用；这不代表没有待复核项目。</p>}
            {queueSnapshotLoaded && holdReleaseQueue.length === 0 && <p>当前没有高风险解除复核。</p>}
            {holdReleaseQueue.map((item) => <button className="resource-link" disabled={actionLocked} key={item.hold_id} type="button" onClick={() => claimHoldRelease(item)}>
              <strong>{item.reason_code}</strong><span>截止：{localTime(item.expires_at)}</span><code>{item.hold_id}</code><b>领取解除复核</b>
            </button>)}
          </div>
        </div>

        <form className="inline-lookup" onSubmit={openAssignedCase}>
          <label>诊断：按 Case ID 读取当前 CASE_TRIAGE 分配（可选）<input required value={assignedCaseId} onChange={(event) => setAssignedCaseId(event.target.value)} /></label>
          <button className="quiet-button" disabled={actionLocked} type="submit">诊断读取已分配详情</button>
        </form>

        {selectedHoldRelease && <div className="trust-case-panel high-risk-card">
          <div className="trust-case-summary">
            <p className="eyebrow">ASSIGNED HOLD RELEASE · EXACT HOLD</p>
            <h3>解除对应 Hold</h3>
            <code>{selectedHoldRelease.hold_id}</code>
            <dl>
              <div><dt>案件</dt><dd>{selectedHoldRelease.case_id}</dd></div>
              <div><dt>Hold 状态</dt><dd>{selectedHoldRelease.hold_status}</dd></div>
              <div><dt>保护原因</dt><dd>{selectedHoldRelease.reason_code}</dd></div>
              <div><dt>暂停动作</dt><dd>{selectedHoldRelease.action_codes.join(" · ")}</dd></div>
              <div><dt>Hold 截止</dt><dd>{localTime(selectedHoldRelease.expires_at)}</dd></div>
              <div><dt>分配截止</dt><dd>{localTime(selectedHoldRelease.assignment_expires_at)}</dd></div>
              <div><dt>专属 ETag</dt><dd>{selectedHoldRelease.entity_tag}</dd></div>
            </dl>
          </div>
          <form className="workbench-card high-risk-card" onSubmit={releaseAssignedHold}>
            <h4>仅解除这一条已分配 Hold</h4>
            <label>原因<select value={holdReleaseReason} onChange={(event) => setHoldReleaseReason(event.target.value)}>{TRUST_HOLD_RELEASE_REASON_CODES.map((code) => <option key={code}>{code}</option>)}</select></label>
            <button className="primary-button" disabled={actionLocked} type="submit">解除对应 Hold</button>
            <small>此视图不载入案件分诊、设置 Hold 或发布结论动作；服务端按当前会话、职责与精确 Hold 分配再次校验。</small>
          </form>
        </div>}

        {selectedCase && <div className="trust-case-panel">
          <div className="trust-case-summary">
            <p className="eyebrow">ASSIGNED SAFE CASE</p>
            <h3>{selectedCase.status} · v{selectedCase.aggregate_version}</h3>
            <code>{selectedCase.case_id}</code>
            <dl>
              <div><dt>Demand</dt><dd>{selectedCase.demand_id}</dd></div>
              <div><dt>Demand version</dt><dd>{selectedCase.demand_version_id}</dd></div>
              <div><dt>报告类别</dt><dd>{selectedCase.report.category}</dd></div>
              <div><dt>安全 ETag</dt><dd>{selectedCase.entity_tag}</dd></div>
            </dl>
          </div>

          <div className="trust-actions-grid">
            <form className="workbench-card" onSubmit={(event) => {
              event.preventDefault();
              startCaseWrite("释放案件分配", () => createTrustAssignmentReleaseIntent({ trustCase: selectedCase, reasonCode: assignmentReleaseReason, csrfToken: session.csrf_token, idempotencyKey: crypto.randomUUID() }));
            }}>
              <h4>释放当前分配</h4>
              <label>原因<select value={assignmentReleaseReason} onChange={(event) => setAssignmentReleaseReason(event.target.value)}>{TRUST_ASSIGNMENT_RELEASE_REASON_CODES.map((code) => <option key={code}>{code}</option>)}</select></label>
              <button className="quiet-button" disabled={actionLocked} type="submit">释放回队列</button>
            </form>

            <form className="workbench-card sensitive-card" noValidate onSubmit={saveTriageDraft}>
              <h4>分诊草稿</h4>
              <CodeChoices legend="调查步骤" codes={TRUST_INVESTIGATION_STEP_CODES} selected={investigationCodes} onChange={setInvestigationCodes} />
              <CodeChoices legend="问题代码" codes={TRUST_ISSUE_CODES} selected={issueCodes} onChange={setIssueCodes} />
              <label>管辖<select value={jurisdictionCode} onChange={(event) => setJurisdictionCode(event.target.value)}><option>PLATFORM_INTERNAL</option><option>ORGANIZATION_POLICY</option><option>LEGAL_REVIEW_REQUIRED</option></select></label>
              <label>优先级<select value={priorityCode} onChange={(event) => setPriorityCode(event.target.value)}><option>P0</option><option>P1</option><option>P2</option><option>P3</option></select></label>
              <label>严重度<select value={severityCode} onChange={(event) => setSeverityCode(event.target.value)}><option>CRITICAL</option><option>HIGH</option><option>MEDIUM</option><option>LOW</option></select></label>
              <CodeChoices legend="建议暂停动作" codes={TRUST_DEMAND_ACTION_CODES} selected={proposedHoldActions} onChange={setProposedHoldActions} />
              <label>建议 TTL（分钟）<input min={15} max={10080} type="number" value={proposedHoldTtl} onChange={(event) => setProposedHoldTtl(Number(event.target.value))} /></label>
              <label>受限备注（必填、只写、仅内存）<textarea aria-invalid={!restrictedNote.trim()} required maxLength={4000} value={restrictedNote} onChange={(event) => setRestrictedNote(event.target.value)} /></label>
              <small>该字段不会进入 sessionStorage、日志或安全响应；保存后不可回显，后续保存会以新内容替换。读取时只显示 sealed reference 与 SHA-256。</small>
              <div className="button-row">
                <button className="primary-button" disabled={actionLocked} type="submit">保存分诊草稿</button>
                <button className="quiet-button" disabled={actionLocked} type="button" onClick={() => startCaseWrite("发布分诊", () => createTrustTriagePublishIntent({ trustCase: selectedCase, csrfToken: session.csrf_token, idempotencyKey: crypto.randomUUID() }))}>发布分诊</button>
              </div>
              {selectedCase.triage_draft && <div className="safe-projection"><strong>已封存安全投影</strong><code>{selectedCase.triage_draft.content.sealed_note_reference}</code><code>{selectedCase.triage_draft.content.sealed_note_sha256}</code></div>}
            </form>

            <form className="workbench-card" onSubmit={(event) => {
              event.preventDefault();
              startCaseWrite("设置 Demand Safety Hold", () => createTrustHoldIntent({ trustCase: selectedCase, actionCodes: holdActions as TrustDemandActionCode[], reasonCode: holdReason, ttlMinutes: holdTtl, csrfToken: session.csrf_token, idempotencyKey: crypto.randomUUID() }));
            }}>
              <h4>设置短期保护 Hold</h4>
              <CodeChoices legend="暂停动作" codes={TRUST_DEMAND_ACTION_CODES} selected={holdActions} onChange={setHoldActions} />
              <label>原因<select value={holdReason} onChange={(event) => setHoldReason(event.target.value)}>{TRUST_HOLD_REASON_CODES.map((code) => <option key={code}>{code}</option>)}</select></label>
              <label>TTL（分钟）<input min={15} max={10080} type="number" value={holdTtl} onChange={(event) => setHoldTtl(Number(event.target.value))} /></label>
              <button className="primary-button" disabled={actionLocked} type="submit">设置 Hold</button>
              {selectedCase.active_hold && <div className="safe-projection"><strong>{selectedCase.active_hold.status}</strong><code>{selectedCase.active_hold.hold_id}</code><span>截止：{localTime(selectedCase.active_hold.expires_at)}</span></div>}
            </form>

            {selectedCase.active_hold && <form className="workbench-card high-risk-card" onSubmit={(event) => {
              event.preventDefault();
              startCaseWrite("解除 Demand Safety Hold", () => createTrustHoldReleaseIntent({ trustCase: selectedCase, reasonCode: holdReleaseReason, csrfToken: session.csrf_token, idempotencyKey: crypto.randomUUID() }));
            }}>
              <h4>解除当前 Hold</h4>
              <label>原因<select value={holdReleaseReason} onChange={(event) => setHoldReleaseReason(event.target.value)}>{TRUST_HOLD_RELEASE_REASON_CODES.map((code) => <option key={code}>{code}</option>)}</select></label>
              <button className="primary-button" disabled={actionLocked} type="submit">解除 Hold</button>
              <small>高风险原因必须先由第二名 TRUST_OFFICER 领取解除复核；资格由服务端验证。</small>
            </form>}

            <form className="workbench-card" onSubmit={(event) => {
              event.preventDefault();
              startCaseWrite("发布 Trust 初始结论", () => createTrustOutcomeIntent({ trustCase: selectedCase, actionCodes: outcomeActions as TrustDemandActionCode[], outcomeCode, reasonCodes: outcomeReasons, csrfToken: session.csrf_token, idempotencyKey: crypto.randomUUID() }));
            }}>
              <h4>发布不可变初始结论</h4>
              <label>结论<select value={outcomeCode} onChange={(event) => setOutcomeCode(event.target.value)}>{TRUST_OUTCOME_CODES.map((code) => <option key={code}>{code}</option>)}</select></label>
              <CodeChoices legend="理由代码" codes={TRUST_OUTCOME_REASON_CODES} selected={outcomeReasons} onChange={setOutcomeReasons} />
              <CodeChoices legend="结论动作" codes={TRUST_DEMAND_ACTION_CODES} selected={outcomeActions} onChange={setOutcomeActions} />
              <button className="primary-button" disabled={actionLocked} type="submit">发布初始结论</button>
              <small>证据包版本、摘要、政策版本、申诉期限与资格均由服务端派生。</small>
              {selectedCase.outcome && <div className="safe-projection"><strong>{selectedCase.outcome.outcome_code}</strong><span>{selectedCase.outcome.policy_version}</span><span>申诉资格：{selectedCase.outcome.appeal_eligibility_code}</span></div>}
            </form>
          </div>
        </div>}
      </>}
      </fieldset>
    </section>
  );
}

function CodeChoices({
  legend,
  codes,
  selected,
  onChange,
}: {
  legend: string;
  codes: readonly string[];
  selected: string[];
  onChange: (value: string[]) => void;
}) {
  return <fieldset className="code-choices"><legend>{legend}</legend>{codes.map((code) => <label key={code}>
    <input checked={selected.includes(code)} type="checkbox" onChange={(event) => onChange(toggleCode(selected, code, event.target.checked))} />
    <span>{code}</span>
  </label>)}</fieldset>;
}

function ReportSummary({
  actionLocked,
  onBeginAppeal,
  report,
  sessionId,
  workspaceId,
}: {
  actionLocked: boolean;
  onBeginAppeal: (handoff: AppealHandoff) => void;
  report: TrustReportProjection;
  sessionId: string;
  workspaceId: string;
}) {
  const [clock, setClock] = useState(Date.now);
  const handoff = createAppealHandoff({
    report,
    sessionId,
    workspaceId,
    now: clock,
  });

  useEffect(() => {
    const deadline = report.outcome?.appeal_deadline;
    if (!deadline) return;
    const remaining = Date.parse(deadline) - Date.now();
    if (remaining <= 0) return;
    const timer = window.setInterval(
      () => setClock(Date.now()),
      Math.min(Math.max(remaining + 1, 1), 60_000),
    );
    return () => window.clearInterval(timer);
  }, [report]);

  return <><dl className="trust-report-summary">
    <div><dt>报告 ID</dt><dd><code>{report.report_id}</code></dd></div>
    <div><dt>状态</dt><dd>{report.status}</dd></div>
    <div><dt>类别</dt><dd>{report.report.category}</dd></div>
    <div><dt>提交时间</dt><dd>{localTime(report.submitted_at)}</dd></div>
    <div><dt>影响</dt><dd>{report.report.impact_codes.join(" · ")}</dd></div>
    <div><dt>ETag</dt><dd><code>{report.entity_tag}</code></dd></div>
    {report.outcome && <>
      <div><dt>处理结果</dt><dd>{report.outcome.outcome_code}</dd></div>
      <div><dt>申诉资格</dt><dd>{report.outcome.appeal_eligibility_code}</dd></div>
      <div><dt>申诉截止</dt><dd>{report.outcome.appeal_deadline ? localTime(report.outcome.appeal_deadline) : "不适用"}</dd></div>
      <div><dt>结论时间 / policy</dt><dd>{localTime(report.outcome.decided_at)} · <code>{report.outcome.policy_version}</code></dd></div>
      <div><dt>理由代码</dt><dd>{report.outcome.reason_codes.join(" · ")}</dd></div>
      <div><dt>动作代码</dt><dd>{report.outcome.action_codes.join(" · ") || "无"}</dd></div>
      <div><dt>结论版本</dt><dd><code>{report.outcome.outcome_version_id}</code></dd></div>
      <div><dt>结论摘要</dt><dd><code>{report.outcome.content_sha256}</code></dd></div>
      <div><dt>证据包版本 / 摘要</dt><dd><code>{report.outcome.evidence_packet_version_id} / {report.outcome.evidence_packet_digest}</code></dd></div>
    </>}
    {handoff && <div><dt>同会话交接</dt><dd><button
      className="primary-button"
      disabled={actionLocked}
      type="button"
      onClick={() => onBeginAppeal(handoff)}
    >开始申诉</button></dd></div>}
  </dl>
  <p className="safe-projection">这里只显示服务端已有的 party-safe metadata 与摘要；页面未读取、未展示，也不声称看过证据内容。开始申诉只建立同会话交接；刷新、重新 bootstrap 或重新登录后，可从“我的举报与处理结果”重新发现来源，并在交接前再次精确读取最新详情。</p>
  </>;
}
