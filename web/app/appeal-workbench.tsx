"use client";

import { FormEvent, useCallback, useEffect, useLayoutEffect, useRef, useState } from "react";
import {
  type AppealAssignmentItem,
  type AppealAssignedProjection,
  type AppealDecisionCode,
  type AppealGround,
  type AppealOwnProjection,
  type AppealQueueItem,
  type AppealReviewHistoryItem,
  type AppealReviewHistoryProjection,
  type AppealReviewTerminalProjection,
  type AppealRequestedOutcome,
  type PendingIntent,
  type SessionBootstrap,
  type WorkspaceCandidate,
  APPEAL_ASSESSMENT_CODES,
  APPEAL_ASSIGNMENT_RELEASE_REASON_CODES,
  APPEAL_DECISION_CODES,
  APPEAL_FINDING_CODES,
  APPEAL_GROUNDS,
  APPEAL_REASON_CODES,
  APPEAL_REMEDY_DELTA_CODES,
  APPEAL_REQUESTED_OUTCOMES,
  createAppealApplicationDraftIntent,
  createAppealDecisionIntent,
  createAppealOpenIntent,
  createAppealReviewClaimIntent,
  createAppealReviewDraftIntent,
  createAppealReviewReleaseIntent,
  createAppealSubmitIntent,
  parseAppealAssignmentListEnvelope,
  parseAppealAssignedEnvelope,
  parseAppealCommandEnvelope,
  parseAppealOwnEnvelope,
  parseAppealQueueEnvelope,
  parseAppealReviewHistoryEnvelope,
  parseAppealReviewTerminalEnvelope,
  parsePendingIntent,
  serializePendingIntent,
} from "../lib/app-contract.mjs";
import {
  createAtomicRefreshCoordinator,
  nonRecoveryControlsLocked,
} from "../lib/workbench-refresh.mjs";
import { loadConsistentAppealReviewerSnapshot } from "../lib/appeal-reviewer-snapshot.mjs";
import {
  type AppealHandoff,
  appealHandoffKey,
  isAppealHandoffCurrent,
} from "../lib/appeal-handoff.mjs";

const APPEAL_ROOT = "/v1/app/appeals";
const REVIEW_ROOT = "/v1/app/appeal-review";
const APPEAL_ASSIGNMENTS = "/v1/app/appeal-review/assignments";
const APPEAL_REVIEW_HISTORY = "/v1/app/appeal-review/history";
const PENDING_KEY = "desire-pilot-pending:v1";

type WorkspaceRequest = (
  path: string,
  init?: RequestInit,
) => Promise<{ value: unknown; etag: string | null }>;

export type AppealTaskTarget = Readonly<{
  appeal_id: string;
  next_action:
    | "EDIT_APPEAL"
    | "REVIEW_ASSIGNED_APPEAL"
    | "VIEW_APPEAL_HISTORY"
    | "VIEW_APPEAL_REVIEW_HISTORY"
    | "WAIT_FOR_APPEAL_REVIEW";
  read_kind: "OWN" | "ASSIGNED" | "HISTORY";
  request_id: string;
  session_id: string;
  workspace_id: string;
}>;

type Props = {
  session: SessionBootstrap;
  workspace: WorkspaceCandidate;
  request: WorkspaceRequest;
  writeLocked: boolean;
  claimWrite: (record: PendingIntent) => boolean;
  releaseWrite: (record: PendingIntent) => void;
  handoff: AppealHandoff | null;
  taskTarget: AppealTaskTarget | null;
  onClearHandoff: () => void;
};

type AppealFailure = { status: number; code: string; traceId: string | null };
type AppealReviewerSnapshot = {
  assignments: AppealAssignmentItem[];
  history: AppealReviewHistoryProjection;
  queue: AppealQueueItem[];
};
type DetailReadOrigin = "INTERACTIVE" | "POST_WRITE";
type DetailReadOptions<T> = {
  commit: (value: T) => void;
  load: () => Promise<T>;
  onError: (error: unknown) => void;
  onSuccess: (value: T) => void;
  validate?: (value: T) => void;
};
type ReviewerRefreshOptions = {
  afterCommit?: (snapshot: AppealReviewerSnapshot) => void;
  deferCommit?: boolean;
  validate?: (snapshot: AppealReviewerSnapshot) => void;
};
type AssessmentEditor = {
  ground: AppealGround;
  assessmentCode: (typeof APPEAL_ASSESSMENT_CODES)[number];
  findingCodes: string[];
  acceptedEvidenceIds: string;
};
type AppealHandoffStatus = "IDLE" | "WAITING" | "CHECKING" | "READY_TO_OPEN" | "EXISTING";

function failure(value: unknown): AppealFailure {
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

function appealEtagVersion(value: string) {
  const match = value.match(/^"appeal-([1-9][0-9]*)-[a-f0-9]{24}"$/);
  if (!match) throw new TypeError("INVALID_APPEAL_ETAG");
  return Number(match[1]);
}

function assertResponseEtag(response: { etag: string | null }, entityTag: string) {
  if (response.etag !== entityTag) throw new TypeError("INVALID_APPEAL_RESPONSE_BINDING");
}

function expectedAppealEvent(path: string) {
  if (path === APPEAL_ROOT) return "AppealOpened";
  if (path.endsWith("/review-draft")) return "AppealReviewDraftSaved";
  if (/\/v1\/app\/appeals\/[^/]+\/draft$/.test(path)) return "AppealApplicationDraftSaved";
  if (path.endsWith("/submit")) return "AppealSubmitted";
  if (/\/appeal-review\/queue\/[^/]+\/claim$/.test(path)) return "AppealReviewClaimed";
  if (path.endsWith("/assignment/release")) return "AppealReviewAssignmentReleased";
  if (path.endsWith("/decide")) return "AppealDecisionPublished";
  throw new TypeError("INVALID_APPEAL_COMMAND_ROUTE");
}

function validateAppealPostWriteSnapshot(
  snapshot: AppealReviewerSnapshot,
  eventType: string,
  appealId: string,
  expectedDecisionCode: AppealDecisionCode | null = null,
) {
  const assigned = snapshot.assignments.some((item) => item.appeal_id === appealId);
  const queued = snapshot.queue.some((item) => item.appeal_id === appealId);
  const completed = snapshot.history.items.find((item) => item.appeal_id === appealId) ?? null;
  const contradictory = eventType === "AppealReviewAssignmentReleased"
    ? !queued || assigned
    : eventType === "AppealDecisionPublished"
      ? queued || assigned || completed === null || completed.decision_code !== expectedDecisionCode
      : queued || !assigned;
  if (contradictory) throw new TypeError("INVALID_APPEAL_REVIEWER_SNAPSHOT_BINDING");
}

function pendingRecord(
  resourceType: "APPEAL" | "APPEAL_REVIEW",
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

function isAppealPending(value: PendingIntent | null): value is PendingIntent {
  return value?.resource_type === "APPEAL" || value?.resource_type === "APPEAL_REVIEW";
}

function isRestrictedNarrativeWrite(record: PendingIntent) {
  return record.intent.path.endsWith("/draft") || record.intent.path.endsWith("/review-draft");
}

function samePending(left: PendingIntent, right: PendingIntent) {
  return JSON.stringify(left) === JSON.stringify(right);
}

function commaSeparatedIds(value: string) {
  return value.split(",").map((item) => item.trim()).filter(Boolean);
}

function toggleCode(current: string[], code: string, checked: boolean) {
  return checked
    ? current.includes(code) ? current : [...current, code]
    : current.filter((item) => item !== code);
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

function isAppealTaskTargetCurrent(
  target: AppealTaskTarget,
  context: {
    canApply: boolean;
    canReview: boolean;
    sessionId: string;
    workspaceId: string;
  },
) {
  if (
    target.session_id !== context.sessionId
    || target.workspace_id !== context.workspaceId
  ) return false;
  if (target.read_kind === "OWN") {
    return context.canApply && (
      target.next_action === "EDIT_APPEAL"
      || target.next_action === "VIEW_APPEAL_HISTORY"
      || target.next_action === "WAIT_FOR_APPEAL_REVIEW"
    );
  }
  if (!context.canReview) return false;
  return (
    target.read_kind === "ASSIGNED"
    && target.next_action === "REVIEW_ASSIGNED_APPEAL"
  ) || (
    target.read_kind === "HISTORY"
    && target.next_action === "VIEW_APPEAL_REVIEW_HISTORY"
  );
}

export function AppealWorkbench({
  session,
  workspace,
  request,
  writeLocked,
  claimWrite,
  releaseWrite,
  handoff,
  taskTarget,
  onClearHandoff,
}: Props) {
  const canApply = workspace.workspace_kind === "ORGANIZATION"
    && workspace.role_codes.includes("DEMAND_OWNER");
  const canReview = workspace.workspace_kind === "PLATFORM"
    && workspace.role_codes.includes("APPEAL_REVIEWER");
  const [ownAppeal, setOwnAppeal] = useState<AppealOwnProjection | null>(null);
  const [reviewerSnapshot, setReviewerSnapshot] = useState<AppealReviewerSnapshot | null>(null);
  const assignments = reviewerSnapshot?.assignments ?? [];
  const history = reviewerSnapshot?.history ?? null;
  const queue = reviewerSnapshot?.queue ?? [];
  const reviewerSnapshotVerifiedRef = useRef(false);
  const [reviewerSnapshotUnavailable, setReviewerSnapshotUnavailable] = useState(false);
  const [assignedAppeal, setAssignedAppeal] = useState<AppealAssignedProjection | null>(null);
  const [terminalAppeal, setTerminalAppeal] = useState<AppealReviewTerminalProjection | null>(null);
  const [pending, setPending] = useState<PendingIntent | null>(null);
  const [busy, setBusy] = useState(false);
  const [reading, setReading] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [reviewerRefreshCoordinator] = useState(createAtomicRefreshCoordinator);
  const [detailReadCoordinator] = useState(createAtomicRefreshCoordinator);
  const [recoveryChecked, setRecoveryChecked] = useState(false);
  const [initialRefreshStarted, setInitialRefreshStarted] = useState(false);
  const [notice, setNotice] = useState("Appeal 工作台只读取 party-safe 投影与不可变 Trust 来源。");
  const [error, setError] = useState<AppealFailure | null>(null);
  const controlledRefreshActive = useRef(false);
  const activeHandoffKeyRef = useRef<string | null>(null);
  const attemptedHandoffKeyRef = useRef<string | null>(null);
  const attemptedTaskTargetRef = useRef<string | null>(null);
  const ownAppealTitleRef = useRef<HTMLHeadingElement>(null);
  const assignedAppealTitleRef = useRef<HTMLHeadingElement>(null);
  const terminalAppealTitleRef = useRef<HTMLHeadingElement>(null);
  const historyItemRefs = useRef(new Map<string, HTMLButtonElement>());
  const [handoffStatus, setHandoffStatus] = useState<AppealHandoffStatus>("IDLE");

  const [sourceOutcomeVersionId, setSourceOutcomeVersionId] = useState("");
  const [appealLookupId, setAppealLookupId] = useState("");
  const [applicantStatement, setApplicantStatement] = useState("");
  const [grounds, setGrounds] = useState<AppealGround[]>(["PROCEDURAL_ERROR"]);
  const [newEvidenceIds, setNewEvidenceIds] = useState("");
  const [requestedOutcome, setRequestedOutcome] = useState<AppealRequestedOutcome>("VACATE_AND_REMAND");

  const [assignedLookupId, setAssignedLookupId] = useState("");
  const [assessmentEditors, setAssessmentEditors] = useState<AssessmentEditor[]>([]);
  const [reviewReasonCodes, setReviewReasonCodes] = useState<string[]>(["SOURCE_OUTCOME_SUPPORTED"]);
  const [remedyDeltaCodes, setRemedyDeltaCodes] = useState<string[]>(["NO_CHANGE"]);
  const [reviewerNote, setReviewerNote] = useState("");
  const [releaseReason, setReleaseReason] = useState<(typeof APPEAL_ASSIGNMENT_RELEASE_REASON_CODES)[number]>("WORKLOAD_RELEASE");
  const [decisionCode, setDecisionCode] = useState<AppealDecisionCode>("AFFIRM");

  const persistPending = useCallback((record: PendingIntent | null) => {
    setPending(record);
    if (!record) {
      sessionStorage.removeItem(PENDING_KEY);
      return;
    }
    if (isRestrictedNarrativeWrite(record)) {
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
      ? "Appeal 写入结果尚未确认；当前只允许原样重试或明确放弃。"
      : "全局写入门闩正由其他恢复或登出操作占用；Appeal 读取与写入均未开始。");
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

  const adoptOwn = useCallback((appeal: AppealOwnProjection) => {
    setOwnAppeal(appeal);
    setAppealLookupId(appeal.appeal_id);
    setSourceOutcomeVersionId(appeal.source_outcome_version_id);
    const application = appeal.application_draft ?? appeal.application;
    if (application) {
      setGrounds([...application.grounds]);
      setNewEvidenceIds(application.new_evidence_reference_ids.join(", "));
      setRequestedOutcome(application.requested_outcome);
    } else {
      setGrounds(["PROCEDURAL_ERROR"]);
      setNewEvidenceIds("");
      setRequestedOutcome("VACATE_AND_REMAND");
    }
    setApplicantStatement("");
  }, []);

  const adoptAssigned = useCallback((assigned: AppealAssignedProjection) => {
    setAssignedAppeal(assigned);
    setAssignedLookupId(assigned.appeal.appeal_id);
    const review = assigned.review_draft;
    setAssessmentEditors(assigned.application.grounds.map((ground) => {
      const saved = review?.assessments.find((item) => item.ground === ground);
      return {
        ground,
        assessmentCode: saved?.assessment_code ?? "REJECTED",
        findingCodes: saved ? [...saved.finding_codes] : ["APPEAL_NOT_SUBSTANTIATED"],
        acceptedEvidenceIds: saved?.accepted_evidence_reference_ids.join(", ") ?? "",
      };
    }));
    setReviewReasonCodes(review ? [...review.reason_codes] : ["SOURCE_OUTCOME_SUPPORTED"]);
    setRemedyDeltaCodes(review ? [...review.remedy_delta_codes] : ["NO_CHANGE"]);
    const accepted = review?.assessments.some((item) => item.assessment_code !== "REJECTED") ?? false;
    const changesMeasure = review !== null && !(review.remedy_delta_codes.length === 1 && review.remedy_delta_codes[0] === "NO_CHANGE");
    setDecisionCode(accepted && changesMeasure ? "MODIFY" : "AFFIRM");
    setReviewerNote("");
  }, []);

  const loadOwn = useCallback(async (appealId: string) => {
    const response = await request(`${APPEAL_ROOT}/${encodeURIComponent(appealId)}`);
    const fresh = parseAppealOwnEnvelope(response.value);
    assertResponseEtag(response, fresh.entity_tag);
    if (fresh.appeal_id !== appealId) throw new TypeError("INVALID_APPEAL_RESPONSE_BINDING");
    return fresh;
  }, [request]);

  const loadOwnBySource = useCallback(async (sourceId: string) => {
    const response = await request(`${APPEAL_ROOT}?source_outcome_version_id=${encodeURIComponent(sourceId)}`);
    const appeal = parseAppealOwnEnvelope(response.value);
    assertResponseEtag(response, appeal.entity_tag);
    if (appeal.source_outcome_version_id !== sourceId) {
      throw new TypeError("INVALID_APPEAL_RESPONSE_BINDING");
    }
    return appeal;
  }, [request]);

  const loadQueue = useCallback(async () => {
    const response = await request(`${REVIEW_ROOT}/queue`);
    const projection = parseAppealQueueEnvelope(response.value);
    assertResponseEtag(response, projection.entity_tag);
    return projection;
  }, [request]);

  const loadAssignments = useCallback(async () => {
    const response = await request(APPEAL_ASSIGNMENTS);
    const projection = parseAppealAssignmentListEnvelope(response.value);
    assertResponseEtag(response, projection.entity_tag);
    return projection;
  }, [request]);

  const loadReviewHistory = useCallback(async () => {
    const response = await request(APPEAL_REVIEW_HISTORY);
    const projection = parseAppealReviewHistoryEnvelope(response.value);
    assertResponseEtag(response, projection.entity_tag);
    return projection;
  }, [request]);

  const loadReviewerSnapshot = useCallback(async (): Promise<AppealReviewerSnapshot> => {
    return loadConsistentAppealReviewerSnapshot({
      loadAssignments,
      loadHistory: loadReviewHistory,
      loadQueue,
    });
  }, [loadAssignments, loadQueue, loadReviewHistory]);

  const commitReviewerSnapshot = useCallback((
    snapshot: AppealReviewerSnapshot,
    terminalOverride?: AppealReviewTerminalProjection,
  ) => {
    reviewerSnapshotVerifiedRef.current = true;
    setReviewerSnapshotUnavailable(false);
    setReviewerSnapshot(snapshot);
    setAssignedAppeal((current) => current && snapshot.assignments.some(
      (item) => item.appeal_id === current.appeal.appeal_id,
    ) ? current : null);
    setTerminalAppeal((current) => terminalOverride ?? (
      current && snapshot.history.items.some(
        (item) => item.appeal_id === current.appeal_id,
      ) ? current : null
    ));
  }, []);

  const loadAssigned = useCallback(async (appealId: string) => {
    const response = await request(`${REVIEW_ROOT}/appeals/${encodeURIComponent(appealId)}`);
    const fresh = parseAppealAssignedEnvelope(response.value);
    assertResponseEtag(response, fresh.entity_tag);
    if (fresh.appeal.appeal_id !== appealId) throw new TypeError("INVALID_APPEAL_RESPONSE_BINDING");
    return fresh;
  }, [request]);

  const loadTerminal = useCallback(async (appealId: string) => {
    const response = await request(`${APPEAL_REVIEW_HISTORY}/${encodeURIComponent(appealId)}`);
    const fresh = parseAppealReviewTerminalEnvelope(response.value);
    assertResponseEtag(response, fresh.entity_tag);
    if (fresh.appeal_id !== appealId) throw new TypeError("INVALID_APPEAL_RESPONSE_BINDING");
    return fresh;
  }, [request]);

  const focusTaskAppeal = useCallback((readKind: AppealTaskTarget["read_kind"], appealId: string) => {
    requestAnimationFrame(() => {
      const destination = readKind === "OWN"
        ? ownAppealTitleRef.current
        : assignedAppealTitleRef.current;
      if (destination?.dataset.appealId !== appealId) return;
      destination.focus({ preventScroll: true });
      destination.scrollIntoView({ block: "start", behavior: "auto" });
    });
  }, []);

  const openTaskAppeal = useCallback(async (candidate: AppealTaskTarget) => {
    if (!isAppealTaskTargetCurrent(candidate, {
      canApply,
      canReview,
      sessionId: session.session.session_id,
      workspaceId: workspace.workspace_id,
    })) {
      setError({ status: 409, code: "APPEAL_TASK_TARGET_STALE_OR_MISMATCHED", traceId: null });
      setNotice("任务交接与当前会话、工作区或角色不再匹配；没有读取申诉，也没有发送写入。");
      return;
    }
    if (rejectNonRecoveryIfLocked()) return;
    if (candidate.read_kind === "HISTORY") return;
    setError(null);
    if (candidate.read_kind === "OWN") {
      setOwnAppeal(null);
      setNotice("任务、当前工作区和 exact Appeal ID 已重新核对；正在只读恢复该申请人的安全投影。");
      await runDetailRead("INTERACTIVE", {
        load: () => loadOwn(candidate.appeal_id),
        commit: adoptOwn,
        onSuccess: () => {
          setNotice("已从重新核对的任务直接恢复 exact Appeal；页面未使用任务路径，也未自动提交任何写入。");
          focusTaskAppeal("OWN", candidate.appeal_id);
        },
        onError: (caught) => {
          setOwnAppeal(null);
          setError(failure(caught));
          setNotice("任务对应的自有 Appeal 已变化或当前无权读取；页面没有保留旧详情，也没有发送写入。");
        },
      });
      return;
    }
    setAssignedAppeal(null);
    setNotice("任务、当前工作区和 exact Appeal ID 已重新核对；正在只读恢复当前复核分配。");
    await runDetailRead("INTERACTIVE", {
      load: () => loadAssigned(candidate.appeal_id),
      commit: adoptAssigned,
      onSuccess: () => {
        setNotice("已从重新核对的任务直接恢复 exact Appeal 分配；页面未使用任务路径，也未自动执行领取或写入。");
        focusTaskAppeal("ASSIGNED", candidate.appeal_id);
      },
      onError: (caught) => {
        setAssignedAppeal(null);
        setError(failure(caught));
        setNotice("任务对应的 Appeal 分配已变化或当前无权读取；页面没有保留旧详情，也没有发送写入。");
      },
    });
  }, [adoptAssigned, adoptOwn, canApply, canReview, focusTaskAppeal, loadAssigned, loadOwn, rejectNonRecoveryIfLocked, runDetailRead, session.session.session_id, workspace.workspace_id]);

  const readOwn = useCallback(async (
    appealId: string,
    validate: (item: AppealOwnProjection) => void = () => {},
  ) => {
    const result = await runDetailRead("POST_WRITE", {
      load: async () => {
        const item = await loadOwn(appealId);
        validate(item);
        return item;
      },
      commit: () => {},
      onSuccess: () => {},
      onError: () => {},
    });
    if (result.ok) return result.snapshot;
    if ("error" in result) throw result.error;
    throw new TypeError("APPEAL_DETAIL_READ_SUPERSEDED");
  }, [loadOwn, runDetailRead]);

  const readAssigned = useCallback(async (
    appealId: string,
    validate: (item: AppealAssignedProjection) => void = () => {},
  ) => {
    const result = await runDetailRead("POST_WRITE", {
      load: async () => {
        const item = await loadAssigned(appealId);
        validate(item);
        return item;
      },
      commit: () => {},
      onSuccess: () => {},
      onError: () => {},
    });
    if (result.ok) return result.snapshot;
    if ("error" in result) throw result.error;
    throw new TypeError("APPEAL_DETAIL_READ_SUPERSEDED");
  }, [loadAssigned, runDetailRead]);

  const readTerminal = useCallback(async (
    appealId: string,
    validate: (item: AppealReviewTerminalProjection) => void = () => {},
  ) => {
    const result = await runDetailRead("POST_WRITE", {
      load: async () => {
        const item = await loadTerminal(appealId);
        validate(item);
        return item;
      },
      commit: () => {},
      onSuccess: () => {},
      onError: () => {},
    });
    if (result.ok) return result.snapshot;
    if ("error" in result) throw result.error;
    throw new TypeError("APPEAL_DETAIL_READ_SUPERSEDED");
  }, [loadTerminal, runDetailRead]);

  const coordinatedRefreshReviewerWork = useCallback(async (
    origin: "INITIAL" | "MANUAL" | "POST_WRITE",
    options: ReviewerRefreshOptions = {},
  ) => {
    if (origin !== "MANUAL") setInitialRefreshStarted(true);
    setError(null);
    if (origin === "MANUAL") {
      setNotice("正在从服务端同步 Appeal 分配、领取队列与本人完成历史；三项完整成功前保留当前快照。");
    }
    const result = await reviewerRefreshCoordinator.run({
      load: loadReviewerSnapshot,
      isValid: () => isReadGenerationValid(origin),
      validate: options.validate,
      commit: (snapshot) => {
        if (options.deferCommit) return;
        commitReviewerSnapshot(snapshot);
        options.afterCommit?.(snapshot);
      },
      setBusy: (value) => {
        setRefreshing(value);
      },
      onSuccess: (snapshot) => {
        if (!options.deferCommit) setReviewerSnapshotUnavailable(false);
        if (origin !== "POST_WRITE") {
          setNotice(`${origin === "MANUAL" ? "已原子更新" : "已核对"} ${snapshot.assignments.length} 个我的活动分配、${snapshot.queue.length} 个待领取申诉和 ${snapshot.history.items.length} 个本人完成记录。`);
        }
      },
      onError: (caught) => {
        if (!reviewerSnapshotVerifiedRef.current) setReviewerSnapshotUnavailable(true);
        if (origin !== "POST_WRITE") {
          setError(failure(caught));
          setNotice(origin === "MANUAL"
            ? "Appeal 刷新失败；分配、队列与完成历史继续显示刷新前的同一快照，没有混合新旧结果。"
            : "Appeal 复核分配、队列与完成历史当前不可用；这不代表三项均为空，页面没有构造本地申诉。");
        }
      },
    });
    if (!result.ok && "stale" in result && origin === "INITIAL") {
      setInitialRefreshStarted(false);
    }
    return result;
  }, [commitReviewerSnapshot, isReadGenerationValid, loadReviewerSnapshot, reviewerRefreshCoordinator]);

  const refreshReviewerWork = useCallback(async (options: ReviewerRefreshOptions = {}) => {
    const result = await coordinatedRefreshReviewerWork("POST_WRITE", options);
    if (result.ok) return result.snapshot;
    if ("error" in result) throw result.error;
    throw new TypeError("APPEAL_REVIEWER_REFRESH_SUPERSEDED");
  }, [coordinatedRefreshReviewerWork]);

  const manuallyRefreshReviewerWork = useCallback(async () => {
    if (rejectNonRecoveryIfLocked()) return;
    await coordinatedRefreshReviewerWork("MANUAL");
  }, [coordinatedRefreshReviewerWork, rejectNonRecoveryIfLocked]);

  const focusReviewHistoryTask = useCallback(async (candidate: AppealTaskTarget) => {
    if (
      candidate.read_kind !== "HISTORY"
      || !isAppealTaskTargetCurrent(candidate, {
        canApply,
        canReview,
        sessionId: session.session.session_id,
        workspaceId: workspace.workspace_id,
      })
    ) {
      setError({ status: 409, code: "APPEAL_REVIEW_HISTORY_TASK_TARGET_STALE_OR_MISMATCHED", traceId: null });
      setNotice("完成任务与当前会话、工作区或 APPEAL_REVIEWER 职责不再匹配；页面没有读取任务路径或按未核对 ID 打开详情。");
      return;
    }
    const result = await coordinatedRefreshReviewerWork("MANUAL", {
      validate: (snapshot) => {
        if (!snapshot.history.items.some((item) => item.appeal_id === candidate.appeal_id)) {
          throw new TypeError("APPEAL_REVIEW_HISTORY_TASK_TARGET_NO_LONGER_AVAILABLE");
        }
      },
    });
    if (!result.ok) {
      if ("stale" in result) {
        attemptedTaskTargetRef.current = null;
        return;
      }
      const exactMissing = result.error instanceof TypeError
        && result.error.message === "APPEAL_REVIEW_HISTORY_TASK_TARGET_NO_LONGER_AVAILABLE";
      setError(exactMissing
        ? { status: 409, code: "APPEAL_REVIEW_HISTORY_TASK_TARGET_NO_LONGER_AVAILABLE", traceId: null }
        : failure(result.error));
      setNotice(exactMissing
        ? "任务已经重核对，但 fresh 本人完成历史不再包含 exact Appeal；页面保留此前完整快照，没有按任务路径或旧 ID 读取详情。"
        : "任务已经重核对，但 fresh 本人完成历史读取失败；页面保留此前完整快照，没有把网络失败解释为记录消失。");
      return;
    }
    setError(null);
    setTerminalAppeal((current) => current?.appeal_id === candidate.appeal_id ? current : null);
    setNotice("当前会话、工作区、APPEAL_REVIEWER 职责、任务与 fresh exact 完成记录已核对；已定位本人只读历史，不需要粘贴 Appeal ID。");
    window.requestAnimationFrame(() => {
      const destination = historyItemRefs.current.get(candidate.appeal_id);
      if (!destination) return;
      destination.focus({ preventScroll: true });
      destination.scrollIntoView({ block: "center", behavior: "auto" });
    });
  }, [canApply, canReview, coordinatedRefreshReviewerWork, session.session.session_id, workspace.workspace_id]);

  const discardAppealHandoff = useCallback(() => {
    detailReadCoordinator.invalidate();
    activeHandoffKeyRef.current = null;
    attemptedHandoffKeyRef.current = null;
    setReading(false);
    setHandoffStatus("IDLE");
    setSourceOutcomeVersionId("");
    setOwnAppeal(null);
    onClearHandoff();
  }, [detailReadCoordinator, onClearHandoff]);

  const inspectAppealHandoff = useCallback(async (candidate: AppealHandoff, key: string) => {
    if (!isAppealHandoffCurrent(candidate, {
      sessionId: session.session.session_id,
      workspaceId: workspace.workspace_id,
    })) {
      if (activeHandoffKeyRef.current === key) {
        setHandoffStatus("IDLE");
        setError({ status: 409, code: "APPEAL_HANDOFF_STALE_OR_MISMATCHED", traceId: null });
        setNotice("同会话交接已过期或与当前会话、工作区不匹配；来源未预填，未发送 POST。");
        discardAppealHandoff();
      }
      return;
    }
    setHandoffStatus("CHECKING");
    setOwnAppeal(null);
    setError(null);
    setNotice("正在用交接的 exact source_outcome_version_id 执行 GET 查重与 eligibility 核对；此步骤不会打开申诉。");
    await runDetailRead("INTERACTIVE", {
      load: async () => {
        const appeal = await loadOwnBySource(candidate.source_outcome_version_id);
        if (
          activeHandoffKeyRef.current !== key
          || !isAppealHandoffCurrent(candidate, {
            sessionId: session.session.session_id,
            workspaceId: workspace.workspace_id,
          })
        ) throw new TypeError("APPEAL_HANDOFF_STALE_OR_MISMATCHED");
        return appeal;
      },
      commit: (appeal) => {
        if (activeHandoffKeyRef.current !== key) return;
        adoptOwn(appeal);
        setHandoffStatus("EXISTING");
      },
      onSuccess: () => {
        if (activeHandoffKeyRef.current !== key) return;
        setNotice("同会话 GET 已找到 exact source 对应的自有申诉；来源保持锁定，页面没有创建重复 Appeal。");
      },
      onError: (caught) => {
        if (activeHandoffKeyRef.current !== key) return;
        if (!isAppealHandoffCurrent(candidate, {
          sessionId: session.session.session_id,
          workspaceId: workspace.workspace_id,
        })) {
          setHandoffStatus("IDLE");
          setError({ status: 409, code: "APPEAL_HANDOFF_STALE_OR_MISMATCHED", traceId: null });
          setNotice("同会话 GET 完成前交接已过期或失配；来源未预填，未发送 POST。");
          discardAppealHandoff();
          return;
        }
        const problem = failure(caught);
        if (problem.status === 404 && problem.code === "APPEAL_NOT_FOUND") {
          setOwnAppeal(null);
          setSourceOutcomeVersionId(candidate.source_outcome_version_id);
          setHandoffStatus("READY_TO_OPEN");
          setError(null);
          setNotice("同会话 GET 未发现已有 Appeal；exact source 已预填并锁定。只有明确点击后才会 POST，服务端仍会重新核对 eligibility 与期限。");
          return;
        }
        setHandoffStatus("IDLE");
        setError(problem);
        setNotice("同会话 GET 未能建立可信来源绑定；交接已拒绝，来源未预填，未发送 POST。");
        discardAppealHandoff();
      },
    });
  }, [adoptOwn, discardAppealHandoff, loadOwnBySource, runDetailRead, session.session.session_id, workspace.workspace_id]);

  useLayoutEffect(() => {
    if (recoveryChecked) return;
    let cancelled = false;
    queueMicrotask(() => {
      if (cancelled) return;
      const recovered = parsePendingIntent(sessionStorage.getItem(PENDING_KEY) ?? "");
      if (isAppealPending(recovered)) {
        const roleAllowed = recovered.resource_type === "APPEAL" ? canApply : canReview;
        if (!roleAllowed || isRestrictedNarrativeWrite(recovered) || !claimWrite(recovered)) {
          sessionStorage.removeItem(PENDING_KEY);
        } else {
          setPending(recovered);
          setNotice("发现一笔结果未知的 Appeal 写入；只能使用相同幂等键与载荷原样重试，或明确放弃。");
        }
      }
      setRecoveryChecked(true);
    });
    return () => {
      cancelled = true;
    };
  }, [canApply, canReview, claimWrite, recoveryChecked]);

  useLayoutEffect(() => {
    let cancelled = false;
    if ((writeLocked || pending !== null) && !controlledRefreshActive.current) {
      reviewerRefreshCoordinator.invalidate();
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
  }, [detailReadCoordinator, pending, reviewerRefreshCoordinator, writeLocked]);

  useEffect(() => {
    let cancelled = false;
    queueMicrotask(() => {
      if (cancelled) return;
      if (!handoff) {
        if (activeHandoffKeyRef.current !== null) {
          detailReadCoordinator.invalidate();
          setReading(false);
        }
        activeHandoffKeyRef.current = null;
        attemptedHandoffKeyRef.current = null;
        setHandoffStatus("IDLE");
        return;
      }
      const key = appealHandoffKey(handoff);
      if (activeHandoffKeyRef.current !== key) {
        detailReadCoordinator.invalidate();
        setReading(false);
        activeHandoffKeyRef.current = key;
        attemptedHandoffKeyRef.current = null;
        setOwnAppeal(null);
        setHandoffStatus("WAITING");
      }
      if (
        !canApply
        || !isAppealHandoffCurrent(handoff, {
          sessionId: session.session.session_id,
          workspaceId: workspace.workspace_id,
        })
      ) {
        activeHandoffKeyRef.current = null;
        attemptedHandoffKeyRef.current = null;
        setHandoffStatus("IDLE");
        setError({ status: 409, code: "APPEAL_HANDOFF_STALE_OR_MISMATCHED", traceId: null });
        setNotice("同会话交接与当前 Demand Owner 会话或工作区不匹配，或申诉期限已过；未执行 GET/POST。");
        discardAppealHandoff();
        return;
      }
      if (!recoveryChecked || busy || refreshing || writeLocked || pending !== null) {
        attemptedHandoffKeyRef.current = null;
        setHandoffStatus("WAITING");
        return;
      }
      if (reading) {
        if (attemptedHandoffKeyRef.current !== key) setHandoffStatus("WAITING");
        return;
      }
      if (attemptedHandoffKeyRef.current === key) return;
      attemptedHandoffKeyRef.current = key;
      void inspectAppealHandoff(handoff, key);
    });
    return () => {
      cancelled = true;
    };
  }, [busy, canApply, detailReadCoordinator, discardAppealHandoff, handoff, inspectAppealHandoff, pending, reading, recoveryChecked, refreshing, session.session.session_id, workspace.workspace_id, writeLocked]);

  useEffect(() => {
    let cancelled = false;
    queueMicrotask(() => {
      if (cancelled) return;
      if (!taskTarget) {
        attemptedTaskTargetRef.current = null;
        return;
      }
      if (attemptedTaskTargetRef.current === taskTarget.request_id) return;
      if (reading) {
        detailReadCoordinator.invalidate();
        setReading(false);
        return;
      }
      if (!recoveryChecked || busy || refreshing || writeLocked || pending !== null) return;
      attemptedTaskTargetRef.current = taskTarget.request_id;
      if (taskTarget.read_kind === "HISTORY") {
        void focusReviewHistoryTask(taskTarget);
      } else {
        void openTaskAppeal(taskTarget);
      }
    });
    return () => {
      cancelled = true;
    };
  }, [busy, detailReadCoordinator, focusReviewHistoryTask, openTaskAppeal, pending, reading, recoveryChecked, refreshing, taskTarget, writeLocked]);

  useEffect(() => {
    if (!handoff) return;
    const remaining = Date.parse(handoff.appeal_deadline) - Date.now();
    if (remaining <= 0) {
      let cancelled = false;
      queueMicrotask(() => {
        if (cancelled) return;
        setError({ status: 409, code: "APPEAL_HANDOFF_EXPIRED", traceId: null });
        setNotice("同会话交接已到申诉截止时间；exact source 已清除，未发送 POST。");
        discardAppealHandoff();
      });
      return () => {
        cancelled = true;
      };
    }
    const timer = window.setInterval(() => {
      if (Date.parse(handoff.appeal_deadline) > Date.now()) return;
      setError({ status: 409, code: "APPEAL_HANDOFF_EXPIRED", traceId: null });
      setNotice("同会话交接已到申诉截止时间；exact source 已清除，未发送 POST。");
      discardAppealHandoff();
    }, Math.min(Math.max(remaining + 1, 1), 60_000));
    return () => window.clearInterval(timer);
  }, [discardAppealHandoff, handoff]);

  useEffect(() => {
    if (
      !recoveryChecked
      || initialRefreshStarted
      || !canReview
      || busy
      || reading
      || refreshing
      || writeLocked
      || pending !== null
    ) return;
    let cancelled = false;
    queueMicrotask(() => {
      if (!cancelled) void coordinatedRefreshReviewerWork("INITIAL");
    });
    return () => {
      cancelled = true;
    };
  }, [busy, canReview, coordinatedRefreshReviewerWork, initialRefreshStarted, pending, reading, recoveryChecked, refreshing, writeLocked]);

  useLayoutEffect(() => {
    return () => {
      detailReadCoordinator.invalidate();
      reviewerRefreshCoordinator.invalidate();
    };
  }, [detailReadCoordinator, reviewerRefreshCoordinator]);

  const performWrite = useCallback(async (candidate: PendingIntent) => {
    const record = pending ?? candidate;
    if (pending && !samePending(pending, candidate)) {
      setError({ status: 0, code: "WRITE_OUTCOME_PENDING", traceId: null });
      return;
    }
    if (!claimWrite(record)) {
      setError({ status: 0, code: "WRITE_OUTCOME_PENDING", traceId: null });
      setNotice("已有另一笔写入占用全局门闩；当前 Appeal 请求没有发送。");
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
      writeConfirmed = true;
      if (record.resource_type === "APPEAL_REVIEW") setInitialRefreshStarted(true);
      const committed = parseAppealCommandEnvelope(result.value);
      const eventType = expectedAppealEvent(record.intent.path);
      if (result.etag !== null || committed.event_types[0] !== eventType) {
        throw new TypeError("INVALID_APPEAL_COMMAND_RESPONSE");
      }
      if (
        (eventType === "AppealApplicationDraftSaved" && committed.application_draft_version === null)
        || (eventType === "AppealSubmitted" && committed.application_version === null)
        || (eventType === "AppealReviewDraftSaved" && committed.review_draft_version === null)
        || (eventType === "AppealDecisionPublished" && committed.decision_version_id === null)
      ) throw new TypeError("INVALID_APPEAL_COMMAND_RESPONSE");
      const isOpen = record.intent.path === APPEAL_ROOT;
      if (!isOpen && committed.appeal_id !== record.object_id) throw new TypeError("INVALID_APPEAL_RESPONSE_BINDING");
      controlledRefreshActive.current = true;
      settlePendingForRefresh();
      if (record.resource_type === "APPEAL") {
        const stagedOwn = await readOwn(committed.appeal_id, (fresh) => {
          if (
            fresh.appeal_id !== committed.appeal_id
            || fresh.aggregate_version < committed.aggregate_version
            || appealEtagVersion(fresh.entity_tag) < committed.aggregate_version
            || (isOpen && fresh.source_outcome_version_id !== record.object_id)
            || (eventType === "AppealApplicationDraftSaved" && fresh.application_draft?.version !== committed.application_draft_version)
            || (eventType === "AppealSubmitted" && fresh.application === null)
          ) throw new TypeError("INVALID_APPEAL_RESPONSE_BINDING");
        });
        adoptOwn(stagedOwn);
        if (isOpen && handoff?.source_outcome_version_id === stagedOwn.source_outcome_version_id) {
          setHandoffStatus("EXISTING");
        }
        if (record.intent.path.endsWith("/draft")) setApplicantStatement("");
        setNotice(`${record.label}已确认；已 fresh GET 自有申诉并绑定 appeal ID、聚合版本与 ETag。`);
      } else if (record.intent.path.endsWith("assignment/release") || record.intent.path.endsWith("/decide")) {
        const isDecision = eventType === "AppealDecisionPublished";
        const expectedDecisionCode = isDecision && typeof record.intent.body.decision_code === "string"
          && APPEAL_DECISION_CODES.includes(record.intent.body.decision_code as AppealDecisionCode)
          ? record.intent.body.decision_code as AppealDecisionCode
          : null;
        if (isDecision && expectedDecisionCode === null) throw new TypeError("INVALID_APPEAL_COMMAND_RESPONSE");
        if (isDecision) {
          const freshReviewerSnapshot = await refreshReviewerWork({
            deferCommit: true,
            validate: (snapshot) => validateAppealPostWriteSnapshot(
              snapshot,
              eventType,
              committed.appeal_id,
              expectedDecisionCode,
            ),
          });
          const completed = freshReviewerSnapshot.history.items.find(
            (item) => item.appeal_id === committed.appeal_id,
          );
          if (!completed) throw new TypeError("INVALID_APPEAL_REVIEWER_SNAPSHOT_BINDING");
          const terminal = await readTerminal(committed.appeal_id, (fresh) => {
            if (
              fresh.status !== "DECIDED"
              || fresh.decision.decision_version_id !== committed.decision_version_id
              || fresh.decision.decision_code !== expectedDecisionCode
              || fresh.decision.decided_at !== completed.decided_at
            ) throw new TypeError("INVALID_APPEAL_REVIEW_HISTORY_DETAIL_BINDING");
          });
          commitReviewerSnapshot(freshReviewerSnapshot, terminal);
          setReviewerNote("");
          window.requestAnimationFrame(() => {
            const destination = terminalAppealTitleRef.current;
            if (destination?.dataset.appealId !== terminal.appeal_id) return;
            destination.focus({ preventScroll: true });
            destination.scrollIntoView({ block: "center", behavior: "auto" });
          });
          setNotice(`${record.label}已确认；exact Appeal 已离开活动投影、进入本人完成历史，并已 fresh GET 绑定决定版本、代码与 ETag。`);
        } else {
          await refreshReviewerWork({
            validate: (snapshot) => validateAppealPostWriteSnapshot(
              snapshot,
              eventType,
              committed.appeal_id,
              expectedDecisionCode,
            ),
            afterCommit: () => {
              setAssignedAppeal(null);
              setReviewerNote("");
            },
          });
          setTerminalAppeal(null);
          setNotice(`${record.label}已确认；已 fresh GET 分配、队列与本人完成历史，浏览器没有推断已释放的分配。`);
        }
      } else {
        const fresh = await readAssigned(committed.appeal_id, (item) => {
          if (
            item.appeal.aggregate_version < committed.aggregate_version
            || appealEtagVersion(item.entity_tag) < committed.aggregate_version
            || (eventType === "AppealReviewDraftSaved" && item.review_draft?.version !== committed.review_draft_version)
          ) throw new TypeError("INVALID_APPEAL_RESPONSE_BINDING");
        });
        await refreshReviewerWork({
          validate: (snapshot) => validateAppealPostWriteSnapshot(snapshot, eventType, committed.appeal_id),
          afterCommit: () => adoptAssigned(fresh),
        });
        if (record.intent.path.endsWith("/review-draft")) setReviewerNote("");
        setNotice(`${record.label}已确认；已 fresh GET 当前分配和队列，并重新绑定 ETag。`);
      }
      releaseWrite(record);
    } catch (caught) {
      if (
        caught instanceof TypeError
        && (caught.message === "APPEAL_DETAIL_READ_SUPERSEDED" || caught.message === "APPEAL_REVIEWER_REFRESH_SUPERSEDED")
      ) {
        releaseWrite(record);
        return;
      }
      if (writeConfirmed) {
        clearPending(record);
        setError({ status: 503, code: "APPEAL_POST_COMMIT_REFRESH_FAILED", traceId: null });
        setNotice(`${record.label}已由服务端确认，但 fresh GET 绑定失败；页面保留操作前完整快照供识别，请刷新工作台，不能重放已确认写入。`);
        return;
      }
      const problem = failure(caught);
      const outcomeUnknown = problem.status === 0 || problem.status >= 500;
      if (!outcomeUnknown) {
        if (problem.status === 412) {
          controlledRefreshActive.current = true;
          settlePendingForRefresh();
          try {
            if (record.resource_type === "APPEAL") {
              if (record.intent.path !== APPEAL_ROOT) adoptOwn(await readOwn(record.object_id));
            } else {
              await refreshReviewerWork();
              if (!record.intent.path.endsWith("assignment/release")) adoptAssigned(await readAssigned(record.object_id));
            }
          } catch {
            if (record.resource_type === "APPEAL_REVIEW") setAssignedAppeal(null);
          } finally {
            releaseWrite(record);
          }
        } else {
          clearPending(record);
        }
      }
      setError(problem);
      setNotice(outcomeUnknown
        ? "Appeal 写入结果未知；全局门闩保留当前内存中的同一请求，可原样重试或人工放弃。"
        : "服务端已明确拒绝 Appeal 写入；旧请求已清除，请依据 fresh GET 事实重新操作。");
    } finally {
      controlledRefreshActive.current = false;
      setBusy(false);
    }
  }, [adoptAssigned, adoptOwn, claimWrite, clearPending, commitReviewerSnapshot, handoff, pending, persistPending, readAssigned, readOwn, readTerminal, refreshReviewerWork, releaseWrite, request, setInitialRefreshStarted, settlePendingForRefresh]);

  async function findBySource(event: FormEvent) {
    event.preventDefault();
    if (rejectNonRecoveryIfLocked()) return;
    setError(null);
    await runDetailRead("INTERACTIVE", {
      load: () => loadOwnBySource(sourceOutcomeVersionId),
      commit: adoptOwn,
      onSuccess: () => setNotice("已按不可变 Trust 结论读取当前申请人的自有申诉；没有身份、密封陈述或权限坐标。"),
      onError: (caught) => setError(failure(caught)),
    });
  }

  async function findById(event: FormEvent) {
    event.preventDefault();
    if (rejectNonRecoveryIfLocked()) return;
    setError(null);
    await runDetailRead("INTERACTIVE", {
      load: () => loadOwn(appealLookupId),
      commit: adoptOwn,
      onSuccess: () => setNotice("已按 Appeal ID 读取当前申请人的 party-safe 投影。"),
      onError: (caught) => setError(failure(caught)),
    });
  }

  function openAppeal() {
    if (rejectNonRecoveryIfLocked()) return;
    if (handoff && (
      handoffStatus !== "READY_TO_OPEN"
      || sourceOutcomeVersionId !== handoff.source_outcome_version_id
      || ownAppeal !== null
      || !isAppealHandoffCurrent(handoff, {
        sessionId: session.session.session_id,
        workspaceId: workspace.workspace_id,
      })
    )) {
      setError({ status: 409, code: "APPEAL_HANDOFF_LOOKUP_REQUIRED", traceId: null });
      setNotice("同会话交接必须先完成 exact-source GET 查重，且仍在期限内；没有发送 POST。");
      return;
    }
    try {
      const intent = createAppealOpenIntent({
        sourceOutcomeVersionId,
        csrfToken: session.csrf_token,
        idempotencyKey: crypto.randomUUID(),
      });
      void performWrite(pendingRecord("APPEAL", sourceOutcomeVersionId, "打开申诉", intent));
    } catch {
      setError({ status: 400, code: "INVALID_APPEAL_OPEN_INPUT", traceId: null });
    }
  }

  function saveApplication(event: FormEvent) {
    event.preventDefault();
    if (!ownAppeal) return;
    try {
      const intent = createAppealApplicationDraftIntent({
        appeal: ownAppeal,
        application: {
          applicant_statement: applicantStatement,
          grounds,
          new_evidence_reference_ids: commaSeparatedIds(newEvidenceIds),
          requested_outcome: requestedOutcome,
        },
        csrfToken: session.csrf_token,
        idempotencyKey: crypto.randomUUID(),
      });
      void performWrite(pendingRecord("APPEAL", ownAppeal.appeal_id, "保存申请草稿", intent));
    } catch {
      setError({ status: 400, code: "INVALID_APPEAL_APPLICATION", traceId: null });
    }
  }

  function submitAppeal() {
    if (!ownAppeal) return;
    try {
      const intent = createAppealSubmitIntent({
        appeal: ownAppeal,
        csrfToken: session.csrf_token,
        idempotencyKey: crypto.randomUUID(),
      });
      void performWrite(pendingRecord("APPEAL", ownAppeal.appeal_id, "提交申诉", intent));
    } catch {
      setError({ status: 400, code: "APPEAL_DRAFT_REQUIRED", traceId: null });
    }
  }

  function claimReview(item: AppealQueueItem) {
    try {
      const intent = createAppealReviewClaimIntent({
        queueItem: item,
        csrfToken: session.csrf_token,
        idempotencyKey: crypto.randomUUID(),
      });
      void performWrite(pendingRecord("APPEAL_REVIEW", item.appeal_id, "领取复核", intent));
    } catch {
      setError({ status: 400, code: "INVALID_APPEAL_CLAIM", traceId: null });
    }
  }

  async function openAssigned(event: FormEvent) {
    event.preventDefault();
    if (rejectNonRecoveryIfLocked()) return;
    setError(null);
    await runDetailRead("INTERACTIVE", {
      load: () => loadAssigned(assignedLookupId),
      commit: adoptAssigned,
      onSuccess: () => setNotice("已读取当前 APPEAL_REVIEWER 的有效分配；来源与申请均为安全投影。"),
      onError: (caught) => setError(failure(caught)),
    });
  }

  async function openDiscoveredAssignment(appealId: string) {
    if (rejectNonRecoveryIfLocked()) return;
    setError(null);
    await runDetailRead("INTERACTIVE", {
      load: () => loadAssigned(appealId),
      commit: adoptAssigned,
      onSuccess: () => setNotice("已从我的活动分配读取独立复核安全投影；标识仅保留在当前页面内存。"),
      onError: (caught) => {
        setAssignedAppeal(null);
        setError(failure(caught));
        setNotice("活动分配已变化或当前无权读取；页面没有保留旧申诉详情。");
      },
    });
  }

  async function openHistoryItem(item: AppealReviewHistoryItem) {
    if (rejectNonRecoveryIfLocked()) return;
    setError(null);
    setTerminalAppeal(null);
    setNotice("正在按本人已验证的完成历史行 fresh GET 终态复核详情；不会复用活动分配读取，也不会发送写入。");
    await runDetailRead("INTERACTIVE", {
      load: () => loadTerminal(item.appeal_id),
      validate: (fresh) => {
        if (
          fresh.appeal_id !== item.appeal_id
          || fresh.status !== "DECIDED"
          || fresh.decision.decision_code !== item.decision_code
          || fresh.decision.decided_at !== item.decided_at
        ) throw new TypeError("INVALID_APPEAL_REVIEW_HISTORY_DETAIL_BINDING");
      },
      commit: setTerminalAppeal,
      onSuccess: (fresh) => {
        setNotice("已 fresh GET 本人终态 Appeal 复核，并核对 Appeal ID、决定代码、决定时间与 ETag；受限正文和权限坐标未进入浏览器。");
        window.requestAnimationFrame(() => {
          const destination = terminalAppealTitleRef.current;
          if (destination?.dataset.appealId !== fresh.appeal_id) return;
          destination.focus({ preventScroll: true });
          destination.scrollIntoView({ block: "center", behavior: "auto" });
        });
      },
      onError: (caught) => {
        const problem = failure(caught);
        setTerminalAppeal(null);
        setError(problem);
        setNotice(problem.status === 404
          ? "fresh 终态详情已不可读；页面没有用历史行拼装详情。请同步任务与历史后重试。"
          : "fresh 终态详情读取失败；本人完成历史快照仍保留，页面没有把网络失败解释为记录消失。");
      },
    });
  }

  function releaseAssignment() {
    if (!assignedAppeal) return;
    try {
      const intent = createAppealReviewReleaseIntent({
        assignedAppeal,
        reasonCode: releaseReason,
        csrfToken: session.csrf_token,
        idempotencyKey: crypto.randomUUID(),
      });
      void performWrite(pendingRecord("APPEAL_REVIEW", assignedAppeal.appeal.appeal_id, "释放复核分配", intent));
    } catch {
      setError({ status: 400, code: "INVALID_APPEAL_RELEASE", traceId: null });
    }
  }

  function saveReview(event: FormEvent) {
    event.preventDefault();
    if (!assignedAppeal) return;
    try {
      const intent = createAppealReviewDraftIntent({
        assignedAppeal,
        review: {
          assessments: assessmentEditors.map((assessment) => ({
            accepted_evidence_reference_ids: commaSeparatedIds(assessment.acceptedEvidenceIds),
            assessment_code: assessment.assessmentCode,
            finding_codes: assessment.findingCodes,
            ground: assessment.ground,
          })),
          reason_codes: reviewReasonCodes,
          remedy_delta_codes: remedyDeltaCodes,
          reviewer_note: reviewerNote,
        },
        csrfToken: session.csrf_token,
        idempotencyKey: crypto.randomUUID(),
      });
      void performWrite(pendingRecord("APPEAL_REVIEW", assignedAppeal.appeal.appeal_id, "保存复核草稿", intent));
    } catch {
      setError({ status: 400, code: "INVALID_APPEAL_REVIEW", traceId: null });
    }
  }

  function decideAppeal() {
    if (!assignedAppeal) return;
    try {
      const intent = createAppealDecisionIntent({
        assignedAppeal,
        decisionCode,
        csrfToken: session.csrf_token,
        idempotencyKey: crypto.randomUUID(),
      });
      void performWrite(pendingRecord("APPEAL_REVIEW", assignedAppeal.appeal.appeal_id, "发布申诉决定", intent));
    } catch {
      setError({ status: 400, code: "APPEAL_REVIEW_DRAFT_REQUIRED", traceId: null });
    }
  }

  const actionLocked = nonRecoveryControlsLocked({
    busy: busy || reading || refreshing || !recoveryChecked,
    pending,
    writeLocked,
  });

  return (
    <section className="appeal-workbench" aria-labelledby="appeal-workbench-title">
      <div className="trust-heading">
        <div>
          <p className="eyebrow">APPEAL · PARTY SAFE · INDEPENDENT REVIEW</p>
          <h2 id="appeal-workbench-title" tabIndex={-1}>申诉申请人与独立复核</h2>
          <p>浏览器只显示不可变 Trust 来源、结构化申请和决定。申请人陈述与复核备注写入后不可回显。</p>
        </div>
        <span className="status status--review">{canReview ? "APPEAL_REVIEWER" : "APPLICANT"}</span>
      </div>

      <div className="live-notice" aria-live="polite"><strong>Appeal 状态</strong><span>{notice}</span></div>
      {error && <div className="error-panel" role="alert"><strong>{error.code}</strong><span>请求没有使用本地模拟结果。</span>{error.traceId && <small>trace: {error.traceId}</small>}</div>}

      {pending && <section className="unknown-panel" aria-labelledby="appeal-pending-title">
        <div>
          <p className="eyebrow">WRITE OUTCOME UNKNOWN</p>
          <h3 id="appeal-pending-title">Appeal 写入结果尚未确认</h3>
          <p>“{pending.label}”只能原样重试或明确放弃。含受限叙事的请求只在当前组件内存保留。</p>
        </div>
        <div className="recovery-actions">
          <button className="primary-button" disabled={busy || reading || refreshing || writeLocked} type="button" onClick={() => void performWrite(pending)}>原样重试</button>
          <button className="quiet-button" disabled={busy || reading || refreshing || writeLocked} type="button" onClick={() => {
            if (pending.intent.path.endsWith("/review-draft")) setReviewerNote("");
            else if (pending.intent.path.endsWith("/draft")) setApplicantStatement("");
            clearPending(pending);
            setNotice("已放弃浏览器中的 Appeal 恢复对象；页面没有据此推断服务端结果。");
          }}>放弃恢复</button>
        </div>
      </section>}

      <fieldset
        aria-disabled={actionLocked}
        className={actionLocked ? "pending-write-scope pending-write-scope--locked" : "pending-write-scope"}
        disabled={actionLocked}
      >
        <legend className="sr-only">Appeal 工作台非恢复操作</legend>
      {canApply && <div className="trust-grid">
        {handoff ? <section className="workbench-card sensitive-card" aria-labelledby="appeal-handoff-title">
          <p className="eyebrow">同会话交接 · TRUST → APPEAL</p>
          <h3 id="appeal-handoff-title">先查重，再由你明确打开</h3>
          <p>交接只存在于当前页面内存，并绑定当前 Session、Demand Owner workspace、报告 ETag 与 exact outcome version。刷新、重新 bootstrap 或重新登录后仍需 Trust8 discovery（尚未实现）重新发现。</p>
          <dl className="trust-report-summary">
            <div><dt>Trust outcome</dt><dd><code>{handoff.source_outcome_version_id}</code></dd></div>
            <div><dt>处理结果 / policy</dt><dd>{handoff.outcome_code} · <code>{handoff.policy_version}</code></dd></div>
            <div><dt>申诉资格 / 截止</dt><dd>ELIGIBLE · {localTime(handoff.appeal_deadline)}</dd></div>
            <div><dt>理由代码</dt><dd>{handoff.reason_codes.join(" · ")}</dd></div>
            <div><dt>证据包 metadata</dt><dd><code>{handoff.evidence_packet_version_id} / {handoff.evidence_packet_digest}</code></dd></div>
          </dl>
          <p className="safe-projection">这里只显示 party-safe metadata 与摘要；页面未读取、未展示，也不声称看过证据内容。</p>
          {handoffStatus === "WAITING" && <p className="empty-state">全局写入门闩或恢复检查完成后，才会执行只读 GET；当前没有发送请求。</p>}
          {handoffStatus === "CHECKING" && <p className="empty-state">正在 GET <code>?source_outcome_version_id={handoff.source_outcome_version_id}</code>；不会自动 POST。</p>}
          {(handoffStatus === "READY_TO_OPEN" || handoffStatus === "EXISTING") && <label>锁定的 Trust outcome version ID<input readOnly value={sourceOutcomeVersionId} /></label>}
          {handoffStatus === "READY_TO_OPEN" && <div className="button-row">
            <button className="primary-button" disabled={actionLocked} type="button" onClick={openAppeal}>明确打开申诉</button>
            <span>GET 已确认没有现有 Appeal；点击后服务端仍会重新核对 eligibility 与期限。</span>
          </div>}
          {handoffStatus === "EXISTING" && <p className="safe-projection">GET 已找到 exact source 对应的自有 Appeal；页面不会创建重复申诉。</p>}
          <button className="quiet-button" disabled={actionLocked} type="button" onClick={discardAppealHandoff}>结束同会话交接，返回高级诊断</button>
        </section> : <details className="workbench-card sensitive-card">
          <summary>高级诊断：按 opaque ID 恢复申诉</summary>
          <p className="eyebrow">手工诊断输入 · 不属于同会话交接或正常发现路径</p>
          <h3>按 Trust 结论或 Appeal ID 读取我的申诉</h3>
          <p>用 immutable source_outcome_version_id 查询零或一笔自有申诉；诊断输入不会伪装成 Trust 发现结果。</p>
          <form onSubmit={findBySource}>
            <label>Trust outcome version ID<input required value={sourceOutcomeVersionId} onChange={(event) => setSourceOutcomeVersionId(event.target.value)} /></label>
            <div className="button-row">
              <button className="quiet-button" disabled={actionLocked} type="submit">按来源读取</button>
              <button className="primary-button" disabled={actionLocked} type="button" onClick={openAppeal}>打开申诉</button>
            </div>
          </form>
          <form onSubmit={findById}>
            <label>Appeal ID<input required value={appealLookupId} onChange={(event) => setAppealLookupId(event.target.value)} /></label>
            <button className="quiet-button" disabled={actionLocked} type="submit">按 ID 读取</button>
          </form>
        </details>}

        {ownAppeal && <section className="workbench-card">
          <h3
            data-appeal-id={ownAppeal.appeal_id}
            ref={ownAppealTitleRef}
            tabIndex={-1}
          >我的 Appeal</h3>
          <AppealFacts appeal={ownAppeal} />
          {ownAppeal.status === "DRAFT" && <form onSubmit={saveApplication}>
            <fieldset className="code-choices">
              <legend>申诉理由</legend>
              {APPEAL_GROUNDS.map((code) => <label key={code}><input checked={grounds.includes(code)} type="checkbox" onChange={(event) => {
                setGrounds((current) => event.target.checked
                  ? current.includes(code) ? current : [...current, code]
                  : current.filter((item) => item !== code));
              }} />{code}</label>)}
            </fieldset>
            <label>新证据 reference IDs（逗号分隔）<input value={newEvidenceIds} onChange={(event) => setNewEvidenceIds(event.target.value)} /></label>
            <label>请求结果<select value={requestedOutcome} onChange={(event) => setRequestedOutcome(event.target.value as AppealRequestedOutcome)}>{APPEAL_REQUESTED_OUTCOMES.map((code) => <option key={code}>{code}</option>)}</select></label>
            <label>申请人陈述（write-only）<textarea required maxLength={4000} value={applicantStatement} onChange={(event) => setApplicantStatement(event.target.value)} /></label>
            <p className="safe-projection">保存后不可回显；后续保存会以新内容替换。公开读取只显示 <code>statement_recorded</code>。</p>
            <div className="button-row">
              <button className="primary-button" disabled={actionLocked} type="submit">保存申请草稿</button>
              <button className="quiet-button" disabled={actionLocked || !ownAppeal.application_draft} type="button" onClick={submitAppeal}>提交申诉</button>
            </div>
          </form>}
        </section>}
      </div>}

      {canReview && <>
        <section className="workbench-card" aria-labelledby="appeal-review-history-title">
          <div className="button-row">
            <div>
              <p className="eyebrow">APPEAL REVIEWER · VERIFIED TERMINAL HISTORY</p>
              <h3 id="appeal-review-history-title" tabIndex={-1}>
                我的已完成申诉复核 <span>{reviewerSnapshot ? history?.items.length ?? 0 : "—"}</span>
              </h3>
            </div>
            <button
              aria-busy={refreshing}
              className="quiet-button"
              disabled={actionLocked}
              type="button"
              onClick={() => void manuallyRefreshReviewerWork()}
            >{refreshing ? "正在同步…" : "同步活动与完成记录"}</button>
          </div>
          {reviewerSnapshot === null && !reviewerSnapshotUnavailable && <p className="empty-state" role="status">
            正在核对活动分配、领取队列与本人完成历史；完成前不会把未读取解释为零条记录。
          </p>}
          {reviewerSnapshot === null && reviewerSnapshotUnavailable && <p className="empty-state" role="status">
            本人完成历史当前不可用；这是读取失败，不是已验证的空历史。请稍后重试。
          </p>}
          {history?.items.length === 0 && <p className="empty-state" role="status">
            fresh 服务端快照已验证：当前没有本人完成的申诉复核。
          </p>}
          {history && history.items.length > 0 && <ol className="appeal-review-history-list" aria-label="本人已完成申诉复核">
            {history.items.map((item) => <li key={item.appeal_id}>
              <button
                aria-current={taskTarget?.read_kind === "HISTORY" && taskTarget.appeal_id === item.appeal_id ? "page" : undefined}
                className="resource-link"
                disabled={actionLocked}
                ref={(element) => {
                  if (element) historyItemRefs.current.set(item.appeal_id, element);
                  else historyItemRefs.current.delete(item.appeal_id);
                }}
                type="button"
                onClick={() => void openHistoryItem(item)}
              >
                <strong>{item.decision_code}</strong>
                <span>决定时间：{localTime(item.decided_at)}</span>
                <code>{item.appeal_id}</code>
                <b>fresh 读取终态详情</b>
              </button>
            </li>)}
          </ol>}
          {history && <p className="safe-projection" role="status">
            {history.has_more
              ? "has_more=true：服务端仍有更早的完成记录；当前封闭接口不接受游标，页面不会猜测、拼接或声称已显示全部历史。"
              : "has_more=false：服务端确认当前本人完成历史没有更多记录。"}
          </p>}
          <small>历史行只负责发现；每次打开都会 fresh GET exact Appeal，并重新核对决定代码、时间与 ETag。</small>
        </section>

        {terminalAppeal && <section className="trust-case-panel" aria-labelledby="appeal-review-terminal-title">
          <div className="trust-case-summary">
            <p className="eyebrow">COMPLETED APPEAL REVIEW · PARTY-SAFE TERMINAL</p>
            <h3
              data-appeal-id={terminalAppeal.appeal_id}
              id="appeal-review-terminal-title"
              ref={terminalAppealTitleRef}
              tabIndex={-1}
            >已完成申诉复核终态</h3>
            <AppealReviewTerminalFacts appeal={terminalAppeal} />
          </div>
        </section>}

        <section className="workbench-card">
          <div className="button-row">
            <div>
              <p className="eyebrow">APPEAL REVIEWER · SERVER-DERIVED</p>
              <h3>我的活动分配 <span>{reviewerSnapshot ? assignments.length : "—"}</span></h3>
            </div>
            <button
              aria-busy={refreshing}
              className="quiet-button"
              disabled={actionLocked}
              type="button"
              onClick={() => void manuallyRefreshReviewerWork()}
            >{refreshing ? "正在同步…" : "同步分配、队列与历史"}</button>
          </div>
          {reviewerSnapshot === null && !reviewerSnapshotUnavailable && <p className="empty-state">正在核对活动分配；尚未形成已验证空结果。</p>}
          {reviewerSnapshot === null && reviewerSnapshotUnavailable && <p className="empty-state">活动分配读取当前不可用；这不表示没有活动分配。</p>}
          {reviewerSnapshot !== null && assignments.length === 0 && <p className="empty-state">fresh 服务端快照已验证：当前没有活动分配。</p>}
          {assignments.map((item) => <button
            className="resource-link"
            disabled={actionLocked}
            key={item.appeal_id}
            type="button"
            onClick={() => void openDiscoveredAssignment(item.appeal_id)}
          >
            <strong>独立申诉复核</strong>
            <span>分配截止：{localTime(item.assignment_expires_at)}</span>
            <b>继续复核</b>
          </button>)}
          <small>分配由当前会话与服务端职责授权派生；Appeal ID 仅在当前页面内存中用于安全读取。</small>
        </section>

        <div className="trust-grid">
          <section className="workbench-card">
            <div className="button-row"><h3>独立复核队列</h3><button
              aria-busy={refreshing}
              className="quiet-button"
              disabled={actionLocked}
              type="button"
              onClick={() => void manuallyRefreshReviewerWork()}
            >{refreshing ? "正在刷新…" : "刷新分配、队列与历史"}</button></div>
            {reviewerSnapshot === null && !reviewerSnapshotUnavailable && <p className="empty-state">正在核对领取队列；尚未形成已验证空结果。</p>}
            {reviewerSnapshot === null && reviewerSnapshotUnavailable && <p className="empty-state">领取队列读取当前不可用；这不表示没有可领取申诉。</p>}
            {reviewerSnapshot !== null && queue.length === 0 && <p className="empty-state">fresh 服务端快照已验证：当前没有可领取申诉。</p>}
            {queue.map((item) => <article className="resource-link" key={item.appeal_id}>
              <strong>{item.grounds.join(" · ")}</strong>
              <code>{item.appeal_id}</code>
              <small>{localTime(item.submitted_at)} · {item.requested_outcome}</small>
              <button className="primary-button" disabled={actionLocked} type="button" onClick={() => claimReview(item)}>领取复核</button>
            </article>)}
          </section>
          <details className="workbench-card sensitive-card">
            <summary>高级诊断：按 Appeal ID 读取活动分配</summary>
            <p className="eyebrow">手工诊断输入 · 不属于正常发现路径</p>
            <form onSubmit={openAssigned}>
              <label>Appeal ID<input required value={assignedLookupId} onChange={(event) => setAssignedLookupId(event.target.value)} /></label>
              <button className="quiet-button" disabled={actionLocked} type="submit">诊断读取</button>
            </form>
          </details>
        </div>

        {assignedAppeal && <section className="trust-case-panel">
          <div className="trust-case-summary">
            <p className="eyebrow">ASSIGNED APPEAL · SAFE PROJECTION</p>
            <h3
              data-appeal-id={assignedAppeal.appeal.appeal_id}
              ref={assignedAppealTitleRef}
              tabIndex={-1}
            >不可变 Trust 来源与已提交申请</h3>
            <AppealFacts appeal={assignedAppeal.appeal} />
            <p className="safe-projection">申请正文不在读取投影中：<code>statement_recorded={String(assignedAppeal.application.statement_recorded)}</code></p>
          </div>
          <div className="trust-actions-grid">
            <section className="workbench-card">
              <h4>释放复核分配</h4>
              <label>原因<select value={releaseReason} onChange={(event) => setReleaseReason(event.target.value as (typeof APPEAL_ASSIGNMENT_RELEASE_REASON_CODES)[number])}>{APPEAL_ASSIGNMENT_RELEASE_REASON_CODES.map((code) => <option key={code}>{code}</option>)}</select></label>
              <button className="quiet-button" disabled={actionLocked} type="button" onClick={releaseAssignment}>释放复核分配</button>
            </section>
            <form className="workbench-card sensitive-card" onSubmit={saveReview}>
              <h4>结构化独立复核</h4>
              {assignedAppeal.review_draft && <p className="safe-projection">已恢复 review draft v{assignedAppeal.review_draft.version}；密封正文只显示 <code>review_note_recorded={String(assignedAppeal.review_draft.review_note_recorded)}</code>。</p>}
              {assessmentEditors.map((assessment, index) => <fieldset className="code-choices appeal-assessment" key={assessment.ground}>
                <legend>{assessment.ground}</legend>
                <label>assessment<select value={assessment.assessmentCode} onChange={(event) => setAssessmentEditors((current) => current.map((item, itemIndex) => itemIndex === index ? { ...item, assessmentCode: event.target.value as AssessmentEditor["assessmentCode"] } : item))}>{APPEAL_ASSESSMENT_CODES.map((code) => <option key={code}>{code}</option>)}</select></label>
                <div className="appeal-code-span"><strong>finding codes</strong>{APPEAL_FINDING_CODES.map((code) => <label key={code}><input checked={assessment.findingCodes.includes(code)} type="checkbox" onChange={(event) => setAssessmentEditors((current) => current.map((item, itemIndex) => itemIndex === index ? { ...item, findingCodes: toggleCode(item.findingCodes, code, event.target.checked) } : item))} />{code}</label>)}</div>
                <label>采纳 evidence IDs（逗号分隔）<input value={assessment.acceptedEvidenceIds} onChange={(event) => setAssessmentEditors((current) => current.map((item, itemIndex) => itemIndex === index ? { ...item, acceptedEvidenceIds: event.target.value } : item))} /></label>
              </fieldset>)}
              <fieldset className="code-choices"><legend>决定理由</legend>{APPEAL_REASON_CODES.map((code) => <label key={code}><input checked={reviewReasonCodes.includes(code)} type="checkbox" onChange={(event) => setReviewReasonCodes((current) => toggleCode(current, code, event.target.checked))} />{code}</label>)}</fieldset>
              <fieldset className="code-choices"><legend>remedy delta</legend>{APPEAL_REMEDY_DELTA_CODES.map((code) => <label key={code}><input checked={remedyDeltaCodes.includes(code)} type="checkbox" onChange={(event) => setRemedyDeltaCodes((current) => toggleCode(current, code, event.target.checked))} />{code}</label>)}</fieldset>
              <label>复核备注（write-only）<textarea required maxLength={4000} value={reviewerNote} onChange={(event) => setReviewerNote(event.target.value)} /></label>
              <p className="safe-projection">保存后不可回显；后续保存会以新内容替换。公开读取只显示 <code>review_note_recorded</code>。</p>
              <button className="primary-button" disabled={actionLocked} type="submit">保存复核草稿</button>
            </form>
            <section className="workbench-card">
              <h4>发布申诉决定</h4>
              <label>decision<select value={decisionCode} onChange={(event) => setDecisionCode(event.target.value as AppealDecisionCode)}>{APPEAL_DECISION_CODES.map((code) => <option key={code}>{code}</option>)}</select></label>
              <p>发布会绑定当前 <code>review_draft.version</code>，只接受 receipt-safe command result。</p>
              <button className="primary-button" disabled={actionLocked || !assignedAppeal.review_draft} type="button" onClick={decideAppeal}>发布申诉决定</button>
            </section>
          </div>
        </section>}
      </>}
      </fieldset>
    </section>
  );
}

function AppealFacts({ appeal }: { appeal: AppealOwnProjection }) {
  const application = appeal.application_draft ?? appeal.application;
  return <dl className="trust-report-summary">
    <div><dt>Appeal ID</dt><dd><code>{appeal.appeal_id}</code></dd></div>
    <div><dt>状态 / 版本</dt><dd>{appeal.status} · v{appeal.aggregate_version}</dd></div>
    <div><dt>Trust case</dt><dd><code>{appeal.source_case_id}</code></dd></div>
    <div><dt>Trust outcome</dt><dd><code>{appeal.source_outcome_version_id}</code></dd></div>
    <div><dt>来源结论</dt><dd>{appeal.source.outcome_code}</dd></div>
    <div><dt>来源 action codes</dt><dd>{appeal.source.action_codes.join(" · ") || "无"}</dd></div>
    <div><dt>来源 reason codes</dt><dd>{appeal.source.reason_codes.join(" · ")}</dd></div>
    <div><dt>申诉截止</dt><dd>{localTime(appeal.source.appeal_deadline)}</dd></div>
    <div><dt>结论时间 / eligibility</dt><dd>{localTime(appeal.source.decided_at)} · {appeal.source.appeal_eligibility_code}</dd></div>
    <div><dt>Demand / version</dt><dd><code>{appeal.source.demand_id} / {appeal.source.demand_version_id}</code></dd></div>
    <div><dt>Evidence packet</dt><dd><code>{appeal.source.evidence_packet_version_id}</code></dd></div>
    <div><dt>Evidence packet SHA-256</dt><dd><code>{appeal.source.evidence_packet_sha256}</code></dd></div>
    <div><dt>Source content SHA-256</dt><dd><code>{appeal.source.content_sha256}</code></dd></div>
    <div><dt>Policy version</dt><dd><code>{appeal.source.policy_version}</code></dd></div>
    {application && <div><dt>结构化申请</dt><dd>{application.grounds.join(" · ")} → {application.requested_outcome}</dd></div>}
    {application && <div><dt>新证据引用</dt><dd>{application.new_evidence_reference_ids.join(" · ") || "无"}</dd></div>}
    <div><dt>申请陈述</dt><dd>{appeal.application_draft?.statement_recorded || appeal.application?.statement_recorded ? "statement_recorded=true" : "尚未保存"}</dd></div>
    <div><dt>复核备注</dt><dd>{appeal.decision ? "决定已发布" : "只显示 review_note_recorded 标志"}</dd></div>
    {appeal.decision && <div><dt>最终决定</dt><dd>{appeal.decision.decision_code}</dd></div>}
  </dl>;
}

function AppealReviewTerminalFacts({ appeal }: { appeal: AppealReviewTerminalProjection }) {
  return <>
    <dl className="trust-report-summary">
      <div><dt>Appeal ID</dt><dd><code>{appeal.appeal_id}</code></dd></div>
      <div><dt>状态</dt><dd>{appeal.status}</dd></div>
      <div><dt>结构化申请</dt><dd>{appeal.application.grounds.join(" · ")} → {appeal.application.requested_outcome}</dd></div>
      <div><dt>新证据引用</dt><dd>{appeal.application.new_evidence_reference_ids.join(" · ") || "无"}</dd></div>
      <div><dt>提交时间</dt><dd>{localTime(appeal.application.submitted_at)}</dd></div>
      <div><dt>申请陈述</dt><dd>statement_recorded={String(appeal.application.statement_recorded)}</dd></div>
      <div><dt>决定 / 时间</dt><dd>{appeal.decision.decision_code} · {localTime(appeal.decision.decided_at)}</dd></div>
      <div><dt>决定版本</dt><dd><code>{appeal.decision.decision_version_id}</code></dd></div>
      <div><dt>决定 SHA-256</dt><dd><code>{appeal.decision.decision_sha256}</code></dd></div>
      <div><dt>政策版本</dt><dd><code>{appeal.decision.policy_version}</code></dd></div>
      <div><dt>理由代码</dt><dd>{appeal.decision.reason_codes.join(" · ")}</dd></div>
      <div><dt>remedy delta</dt><dd>{appeal.decision.remedy_delta_codes.join(" · ")}</dd></div>
      <div><dt>复核备注</dt><dd>review_note_recorded={String(appeal.review_note_recorded)}</dd></div>
    </dl>
    <section className="workbench-card" aria-labelledby="appeal-review-terminal-assessments-title">
      <h4 id="appeal-review-terminal-assessments-title">逐项结构化评估</h4>
      <ol>
        {appeal.decision.assessments.map((assessment) => <li key={assessment.ground}>
          <strong>{assessment.ground} · {assessment.assessment_code}</strong>
          <p>findings：{assessment.finding_codes.join(" · ")}</p>
          <p>采纳证据引用：{assessment.accepted_evidence_reference_ids.join(" · ") || "无"}</p>
        </li>)}
      </ol>
      <p className="safe-projection">终态只显示封闭的 party-safe 字段；申请正文、复核备注正文、actor、职责、组织、分配和 Trust 来源均未进入浏览器。</p>
    </section>
  </>;
}
