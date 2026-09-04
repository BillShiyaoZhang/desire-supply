"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  type EditorResource,
  type PendingIntent,
  type SessionBootstrap,
  type WorkspaceCandidate,
  parsePendingIntent,
  serializePendingIntent,
} from "../lib/app-contract.mjs";
import {
  type MatchingAttempt,
  type MatchingAttemptList,
  type MatchingCandidateSelectorAssignment,
  type MatchingInvitationDetail,
  type MatchingInvitationList,
  type MatchingSelection,
  MATCHING_DECLINE_REASON_CODES,
  MATCHING_SELECTION_BASIS_CODES,
  MATCHING_SELECTION_CLOSE_REASON_CODES,
  MATCHING_WITHDRAW_REASON_CODES,
  assertMatchingEntityTag,
  createAcceptMatchingInvitationIntent,
  createChooseMatchingSelectionIntent,
  createCloseMatchingSelectionIntent,
  createClaimCandidateSelectorIntent,
  createDeclineMatchingInvitationIntent,
  createWithdrawMatchingInvitationIntent,
  parseMatchingAttemptList,
  parseMatchingCandidateSelectorAssignment,
  parseMatchingInvitationDetail,
  parseMatchingInvitationList,
  parseMatchingSelection,
  matchesMatchingSelectionAssignmentVersion,
  serializeMatchingPendingIntent,
} from "../lib/matching-contract.mjs";

const PENDING_KEY = "desire-pilot-pending:v1";
const MATCHING_SELECTION_RECOVERY_KEY = "desire-pilot-matching-selection-recovery:v1";
const MATCHING_SELECTION_REFERENCE_KEY = "desire-pilot-matching-selection-reference:v1";
const MATCHING_DEMAND_STATUSES = new Set(["FUNDED", "MATCHING", "MATCHED", "NO_MATCH"]);
const MATCHING_ID = /^[A-Za-z0-9][A-Za-z0-9_-]{15,127}$/;

type WorkspaceRequest = (
  path: string,
  init?: RequestInit,
) => Promise<{ value: unknown; etag: string | null }>;

type Props = {
  demands: EditorResource[];
  demandsAvailable: boolean;
  session: SessionBootstrap;
  workspace: WorkspaceCandidate;
  request: WorkspaceRequest;
  writeLocked: boolean;
  claimWrite: (record: PendingIntent) => boolean;
  releaseWrite: (record: PendingIntent) => void;
};

type MatchingFailure = { status: number; code: string; traceId: string | null };
type MatchingSelectionRecovery = Readonly<{
  version: 1;
  saved_at: string;
  organization_id: string;
  attempt_id: string;
  selection_id: string;
  idempotency_key: string;
}>;

function failure(value: unknown): MatchingFailure {
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
  if (value instanceof TypeError) {
    return { status: 503, code: value.message || "INVALID_MATCHING_RESPONSE", traceId: null };
  }
  return { status: 0, code: "MATCHING_OUTCOME_UNKNOWN", traceId: null };
}

function isMatchingPending(record: PendingIntent | null): record is PendingIntent {
  return record?.resource_type === "MATCHING_INVITATION"
    || record?.resource_type === "MATCHING_SELECTION"
    || record?.resource_type === "MATCHING_ASSIGNMENT";
}

function samePending(left: PendingIntent, right: PendingIntent) {
  return serializePendingIntent(left) === serializePendingIntent(right);
}

function pendingRecord(
  resourceType: "MATCHING_INVITATION" | "MATCHING_SELECTION" | "MATCHING_ASSIGNMENT",
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

function selectionRecovery(
  encoded: string,
  pending: PendingIntent,
  organizationId: string,
): MatchingSelectionRecovery | null {
  if (!encoded || encoded.length > 2048 || pending.resource_type !== "MATCHING_SELECTION") return null;
  try {
    const value: unknown = JSON.parse(encoded);
    if (!value || typeof value !== "object" || Array.isArray(value)) return null;
    const item = value as Record<string, unknown>;
    const path = pending.intent.path.match(/^\/v1\/organizations\/([A-Za-z0-9][A-Za-z0-9_-]{15,127})\/selections\/([A-Za-z0-9][A-Za-z0-9_-]{15,127})\/(?:choose|close)$/);
    if (
      Object.keys(item).length !== 6
      || item.version !== 1
      || item.saved_at !== pending.saved_at
      || item.organization_id !== organizationId
      || item.organization_id !== path?.[1]
      || item.selection_id !== pending.object_id
      || item.selection_id !== path?.[2]
      || typeof item.attempt_id !== "string"
      || !MATCHING_ID.test(item.attempt_id)
      || item.idempotency_key !== pending.intent.headers["idempotency-key"]
    ) return null;
    return item as MatchingSelectionRecovery;
  } catch {
    return null;
  }
}

function serializeSelectionRecovery(
  pending: PendingIntent,
  organizationId: string,
  attemptId: string,
) {
  if (
    pending.resource_type !== "MATCHING_SELECTION"
    || !MATCHING_ID.test(organizationId)
    || !MATCHING_ID.test(attemptId)
  ) throw new TypeError("MATCHING_SELECTION_RECOVERY_CONTEXT_INVALID");
  const encoded = JSON.stringify({
    version: 1,
    saved_at: pending.saved_at,
    organization_id: organizationId,
    attempt_id: attemptId,
    selection_id: pending.object_id,
    idempotency_key: pending.intent.headers["idempotency-key"],
  });
  if (!selectionRecovery(encoded, pending, organizationId)) {
    throw new TypeError("MATCHING_SELECTION_RECOVERY_CONTEXT_INVALID");
  }
  return encoded;
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

function money(amountMinor: number, currency: string) {
  try {
    return new Intl.NumberFormat("zh-CN", {
      style: "currency",
      currency,
      currencyDisplay: "code",
    }).format(amountMinor / 100);
  } catch {
    return `${currency} ${(amountMinor / 100).toFixed(2)}`;
  }
}

function shortId(value: string) {
  return value.length > 26 ? `${value.slice(0, 12)}…${value.slice(-8)}` : value;
}

function invitationStatus(value: MatchingInvitationDetail["status"]) {
  return ({
    SENT: "等待响应",
    ACCEPTED: "已接受",
    DECLINED: "已拒绝",
    WITHDRAWN: "已撤回接受",
    EXPIRED: "已过期",
    REVOKED: "已撤销",
  } as const)[value];
}

function attemptStatus(value: MatchingAttempt["status"]) {
  return ({
    OPEN: "进行中",
    SELECTED: "已选择",
    CLOSED_NO_SELECTION: "已关闭且未选择",
    INVALIDATED: "已失效",
    CANCELLED: "已取消",
  } as const)[value];
}

function selectionStatus(value: MatchingSelection["status"]) {
  return ({
    OPEN: "等待人工选择",
    PENDING_CHOICE: "选择协调中",
    PENDING_CLOSE: "关闭协调中",
    SELECTED: "选择已完成",
    CLOSED_NO_SELECTION: "已关闭且未选择",
    CANCELLED: "已取消",
  } as const)[value];
}

export function MatchingWorkbench({
  demands,
  demandsAvailable,
  session,
  workspace,
  request,
  writeLocked,
  claimWrite,
  releaseWrite,
}: Props) {
  const canRespond = workspace.workspace_kind === "PERSONAL"
    && workspace.role_codes.includes("CREATOR");
  const canSelect = workspace.workspace_kind === "ORGANIZATION"
    && workspace.role_codes.includes("DEMAND_OWNER");
  const organizationId = canSelect && workspace.workspace_id.startsWith("org:")
    ? workspace.workspace_id.slice(4)
    : "";
  const matchingDemands = useMemo(
    () => demands.filter((item) => item.resource_type === "DEMAND" && MATCHING_DEMAND_STATUSES.has(item.status)),
    [demands],
  );

  const [invitationList, setInvitationList] = useState<MatchingInvitationList | null>(null);
  const [invitationListError, setInvitationListError] = useState<MatchingFailure | null>(null);
  const [invitationListBusy, setInvitationListBusy] = useState(canRespond);
  const [selectedInvitation, setSelectedInvitation] = useState<MatchingInvitationDetail | null>(null);
  const selectedInvitationRef = useRef<MatchingInvitationDetail | null>(null);
  const [invitationEntityTag, setInvitationEntityTag] = useState<string | null>(null);
  const [invitationDetailBusy, setInvitationDetailBusy] = useState(false);
  const [invitationDetailError, setInvitationDetailError] = useState<MatchingFailure | null>(null);
  const [declineReasonCode] = useState<(typeof MATCHING_DECLINE_REASON_CODES)[number]>("RECIPIENT_DECLINED");
  const [withdrawReasonCode] = useState<(typeof MATCHING_WITHDRAW_REASON_CODES)[number]>("RECIPIENT_WITHDREW");
  const [responseNote, setResponseNote] = useState("");

  const [selectedDemandId, setSelectedDemandId] = useState("");
  const [attemptDemandId, setAttemptDemandId] = useState<string | null>(null);
  const [attemptList, setAttemptList] = useState<MatchingAttemptList | null>(null);
  const [attemptListBusy, setAttemptListBusy] = useState(false);
  const [attemptListError, setAttemptListError] = useState<MatchingFailure | null>(null);
  const [selection, setSelection] = useState<MatchingSelection | null>(null);
  const [selectorAssignment, setSelectorAssignment] = useState<MatchingCandidateSelectorAssignment | null>(null);
  const selectionRef = useRef<MatchingSelection | null>(null);
  const selectionIdsRef = useRef(new Map<string, string>());
  const [savedSelectionReferences, setSavedSelectionReferences] = useState<Array<{ attemptId: string; selectionId: string }>>([]);
  const [selectionEntityTag, setSelectionEntityTag] = useState<string | null>(null);
  const [selectionBusy, setSelectionBusy] = useState(false);
  const [selectionError, setSelectionError] = useState<MatchingFailure | null>(null);
  const [selectionBasisCode, setSelectionBasisCode] = useState<(typeof MATCHING_SELECTION_BASIS_CODES)[number]>("CAPABILITY_SUMMARY_FIT");
  const [selectionCloseReasonCode] = useState<(typeof MATCHING_SELECTION_CLOSE_REASON_CODES)[number]>("OWNER_CLOSED");

  const [pending, setPending] = useState<PendingIntent | null>(null);
  const pendingRef = useRef<PendingIntent | null>(null);
  const recoveryAttemptIdRef = useRef<string | null>(null);
  const [recoveryAttemptId, setRecoveryAttemptId] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [clock, setClock] = useState(Date.now);
  const [notice, setNotice] = useState("Matching 只读取当前角色被授权的服务端投影。");
  const [error, setError] = useState<MatchingFailure | null>(null);

  const requestMatching = useCallback((path: string, init?: RequestInit) => {
    const headers = new Headers(init?.headers);
    headers.set("x-workspace-id", workspace.workspace_id);
    if (init?.method === "POST") headers.set("x-csrf-token", session.csrf_token);
    return request(path, { ...init, headers });
  }, [request, session.csrf_token, workspace.workspace_id]);

  const loadInvitationList = useCallback(async () => {
    if (!canRespond) return;
    setInvitationListBusy(true);
    setInvitationListError(null);
    try {
      const response = await requestMatching("/v1/me/matching-invitations?limit=100");
      const fresh = parseMatchingInvitationList(response.value);
      setInvitationList(fresh);
      setInvitationListError(null);
      setNotice(`业务邀请已从当前账号投影刷新；本页共 ${fresh.items.length} 项。`);
    } catch (caught) {
      setInvitationListError(failure(caught));
    } finally {
      setInvitationListBusy(false);
    }
  }, [canRespond, requestMatching]);

  const readInvitation = useCallback(async (invitationId: string) => {
    if (selectedInvitationRef.current?.invitation_id !== invitationId) {
      selectedInvitationRef.current = null;
      setSelectedInvitation(null);
      setInvitationEntityTag(null);
      setResponseNote("");
    }
    setInvitationDetailBusy(true);
    setInvitationDetailError(null);
    try {
      const response = await requestMatching(`/v1/me/matching-invitations/${invitationId}`);
      const fresh = parseMatchingInvitationDetail(response.value);
      if (fresh.invitation_id !== invitationId) throw new TypeError("MATCHING_INVITATION_BINDING_INVALID");
      assertMatchingEntityTag(response.etag, fresh.aggregate_version);
      selectedInvitationRef.current = fresh;
      setSelectedInvitation(fresh);
      setInvitationEntityTag(response.etag);
      setInvitationDetailError(null);
      setNotice("业务邀请详情与 immutable disclosure 已从服务端重新核对。");
      return fresh;
    } catch (caught) {
      const problem = failure(caught);
      setInvitationDetailError(problem.code === "INVALID_MATCHING_CONTRACT"
        ? { ...problem, code: "MATCHING_DISCLOSURE_UNAVAILABLE" }
        : problem);
      if (selectedInvitationRef.current?.invitation_id !== invitationId) {
        selectedInvitationRef.current = null;
        setSelectedInvitation(null);
        setInvitationEntityTag(null);
      }
      return null;
    } finally {
      setInvitationDetailBusy(false);
    }
  }, [requestMatching]);

  const selectionReferencePrefix = useCallback((demandId: string) => (
    `${MATCHING_SELECTION_REFERENCE_KEY}:${session.session.session_id}:${organizationId}:${demandId}:`
  ), [organizationId, session.session.session_id]);

  const loadAttempts = useCallback(async (demandId: string) => {
    if (!canSelect || !organizationId || !demandId) return;
    setSelectedDemandId(demandId);
    setAttemptListBusy(true);
    setAttemptListError(null);
    selectionRef.current = null;
    setSelection(null);
    setSelectionEntityTag(null);
    setSelectorAssignment(null);
    setSelectionError(null);
    const references: Array<{ attemptId: string; selectionId: string }> = [];
    try {
      const prefix = selectionReferencePrefix(demandId);
      for (let index = 0; index < sessionStorage.length; index += 1) {
        const key = sessionStorage.key(index);
        if (!key?.startsWith(prefix)) continue;
        const attemptId = key.slice(prefix.length);
        const selectionId = sessionStorage.getItem(key) ?? "";
        if (MATCHING_ID.test(attemptId) && MATCHING_ID.test(selectionId)) references.push({ attemptId, selectionId });
      }
    } catch { /* reference storage is optional; all details still require an authenticated read */ }
    setSavedSelectionReferences(references);
    try {
      const response = await requestMatching(`/v1/organizations/${organizationId}/demands/${demandId}/matching-attempts?limit=100`);
      const fresh = parseMatchingAttemptList(response.value, demandId);
      setAttemptDemandId(demandId);
      setAttemptList(fresh);
      setAttemptListError(null);
      setNotice(`当前会话的有效 Candidate Selector 分配已由服务端验证；本页共 ${fresh.items.length} 轮。`);
      return fresh;
    } catch (caught) {
      setAttemptListError(failure(caught));
      return null;
    } finally {
      setAttemptListBusy(false);
    }
  }, [canSelect, organizationId, requestMatching, selectionReferencePrefix]);

  const selectionReferenceKey = useCallback((attemptId: string) => (
    `${selectionReferencePrefix(selectedDemandId)}${attemptId}`
  ), [selectedDemandId, selectionReferencePrefix]);

  const rememberSelection = useCallback((attemptId: string, selectionId: string) => {
    selectionIdsRef.current.set(attemptId, selectionId);
    setSavedSelectionReferences((current) => [...current.filter((item) => item.attemptId !== attemptId), { attemptId, selectionId }]);
    try { sessionStorage.setItem(selectionReferenceKey(attemptId), selectionId); } catch { /* an authenticated read remains usable without browser persistence */ }
  }, [selectionReferenceKey]);

  const readSelection = useCallback(async (attemptId: string, exactSelectionId: string | null = null) => {
    if (!canSelect || !organizationId) return null;
    let selectionId = exactSelectionId ?? selectionIdsRef.current.get(attemptId) ?? null;
    if (!selectionId) {
      try { selectionId = sessionStorage.getItem(selectionReferenceKey(attemptId)); } catch { /* use the active-assignment discovery route below */ }
    }
    if (selectionId && !MATCHING_ID.test(selectionId)) selectionId = null;
    if (selectionRef.current?.attempt_id !== attemptId) {
      selectionRef.current = null;
      setSelection(null);
      setSelectionEntityTag(null);
    }
    setSelectionBusy(true);
    setSelectionError(null);
    try {
      const path = selectionId
        ? `/v1/organizations/${organizationId}/selections/${selectionId}`
        : `/v1/organizations/${organizationId}/matching-attempts/${attemptId}/selection`;
      const response = await requestMatching(path);
      const fresh = parseMatchingSelection(response.value);
      if (fresh.attempt_id !== attemptId || (selectionId && fresh.selection_id !== selectionId)) throw new TypeError("MATCHING_SELECTION_BINDING_INVALID");
      assertMatchingEntityTag(response.etag, fresh.aggregate_version);
      rememberSelection(attemptId, fresh.selection_id);
      selectionRef.current = fresh;
      setSelection(fresh);
      setSelectionEntityTag(response.etag);
      setSelectionError(null);
      setNotice("Selection 与 exact Candidate Selector assignment 已从服务端重新核对。");
      return fresh;
    } catch (caught) {
      const problem = failure(caught);
      setSelectionError(problem.code === "INVALID_MATCHING_CONTRACT"
        ? { ...problem, code: "MATCHING_ACCEPTED_SET_UNAVAILABLE" }
        : problem);
      if (selectionRef.current?.attempt_id !== attemptId) {
        selectionRef.current = null;
        setSelection(null);
        setSelectionEntityTag(null);
      }
      return null;
    } finally {
      setSelectionBusy(false);
    }
  }, [canSelect, organizationId, rememberSelection, requestMatching, selectionReferenceKey]);

  const persistPending = useCallback((record: PendingIntent, attemptId: string | null) => {
    const encoded = serializeMatchingPendingIntent(record);
    const recovery = record.resource_type === "MATCHING_SELECTION"
      ? serializeSelectionRecovery(record, organizationId, attemptId ?? "")
      : null;
    try {
      if (recovery === null) sessionStorage.removeItem(MATCHING_SELECTION_RECOVERY_KEY);
      else sessionStorage.setItem(MATCHING_SELECTION_RECOVERY_KEY, recovery);
      sessionStorage.setItem(PENDING_KEY, encoded);
    } catch {
      try { sessionStorage.removeItem(MATCHING_SELECTION_RECOVERY_KEY); } catch { /* fail closed below */ }
      throw new TypeError("MATCHING_RECOVERY_STORAGE_UNAVAILABLE");
    }
    recoveryAttemptIdRef.current = attemptId;
    setRecoveryAttemptId(attemptId);
    pendingRef.current = record;
    setPending(record);
  }, [organizationId]);

  const clearPending = useCallback((record: PendingIntent) => {
    if (pendingRef.current && samePending(pendingRef.current, record)) {
      pendingRef.current = null;
      recoveryAttemptIdRef.current = null;
      setRecoveryAttemptId(null);
      setPending(null);
      try {
        sessionStorage.removeItem(PENDING_KEY);
        sessionStorage.removeItem(MATCHING_SELECTION_RECOVERY_KEY);
      } catch { /* the in-memory latch still releases; replay remains idempotent after reload */ }
      releaseWrite(record);
    }
  }, [releaseWrite]);

  const performWrite = useCallback(async (candidate: PendingIntent, attemptId: string | null = null) => {
    const record = pendingRef.current ?? candidate;
    if (!isMatchingPending(record) || (pendingRef.current && !samePending(pendingRef.current, candidate))) {
      setError({ status: 409, code: "WRITE_OUTCOME_PENDING", traceId: null });
      return;
    }
    if (!claimWrite(record)) {
      setError({ status: 409, code: "WRITE_OUTCOME_PENDING", traceId: null });
      return;
    }
    if (!pendingRef.current) {
      try {
        persistPending(record, attemptId);
      } catch (caught) {
        releaseWrite(record);
        setError(failure(caught));
        setNotice("浏览器无法持久化恢复对象；Matching 命令未发送。请恢复当前标签页存储后重试。");
        return;
      }
    }
    setBusy(true);
    setError(null);
    setNotice("正在提交 Matching 命令；结果明确前不会生成新的幂等请求。");
    let writeConfirmed = false;
    try {
      const response = await requestMatching(record.intent.path, {
        method: record.intent.method,
        headers: record.intent.headers,
        body: JSON.stringify(record.intent.body),
      });
      if (record.resource_type === "MATCHING_INVITATION") {
        const fresh = parseMatchingInvitationDetail(response.value);
        if (fresh.invitation_id !== record.object_id) throw new TypeError("MATCHING_INVITATION_BINDING_INVALID");
        assertMatchingEntityTag(response.etag, fresh.aggregate_version);
        const expected = record.intent.path.endsWith("/accept")
          ? "ACCEPTED"
          : record.intent.path.endsWith("/decline")
            ? "DECLINED"
            : "WITHDRAWN";
        if (
          fresh.snapshot_sha256 !== record.intent.body.snapshot_sha256
          || fresh.status !== expected
          || fresh.response_status !== expected
        ) {
          throw new TypeError("MATCHING_INVITATION_TRANSITION_INVALID");
        }
        writeConfirmed = true;
        clearPending(record);
        selectedInvitationRef.current = fresh;
        setSelectedInvitation(fresh);
        setInvitationEntityTag(response.etag);
        setInvitationList((current) => current ? {
          ...current,
          items: current.items.map((item) => item.invitation_id === fresh.invitation_id ? fresh : item),
        } : current);
        setResponseNote("");
        setNotice(expected === "ACCEPTED"
          ? "已接受披露快照；这不构成 Agreement，也不保证最终被选择。"
          : expected === "WITHDRAWN"
            ? "接受已在人工选择完成前撤回；服务端不会把它继续作为 accepted candidate。"
            : "邀请已明确拒绝；本操作不会创建 Project 或 Agreement。");
      } else if (record.resource_type === "MATCHING_ASSIGNMENT") {
        const fresh = parseMatchingCandidateSelectorAssignment(response.value, record.object_id);
        assertMatchingEntityTag(response.etag, fresh.candidate_selector_assignment_version);
        writeConfirmed = true;
        clearPending(record);
        setSelectorAssignment(fresh);
        setNotice("Candidate Selector 已由当前组织工作区显式领取；页面将继续读取 exact assignment-scoped Selection。");
        await readSelection(fresh.attempt_id, fresh.selection_id);
      } else {
        const fresh = parseMatchingSelection(response.value);
        if (fresh.selection_id !== record.object_id) throw new TypeError("MATCHING_SELECTION_BINDING_INVALID");
        assertMatchingEntityTag(response.etag, fresh.aggregate_version);
        const choose = record.intent.path.endsWith("/choose");
        if (
          fresh.current_invitation_set_sha256 !== record.intent.body.current_invitation_set_sha256
          || fresh.candidate_selector_assignment_id !== record.intent.body.candidate_selector_assignment_id
          || !matchesMatchingSelectionAssignmentVersion(fresh, record.intent.body.candidate_selector_assignment_version as number)
          || (choose && (
            fresh.chosen_invitation_id !== record.intent.body.invitation_id
            || !new Set(["PENDING_CHOICE", "SELECTED"]).has(fresh.status)
          ))
          || (!choose && (
            !new Set(["PENDING_CLOSE", "CLOSED_NO_SELECTION"]).has(fresh.status)
            || fresh.chosen_invitation_id !== null
          ))
        ) throw new TypeError("MATCHING_SELECTION_TRANSITION_INVALID");
        writeConfirmed = true;
        clearPending(record);
        selectionRef.current = fresh;
        rememberSelection(fresh.attempt_id, fresh.selection_id);
        setSelection(fresh);
        setSelectionEntityTag(response.etag);
        setNotice(choose && fresh.status === "PENDING_CHOICE"
          ? "选择意图已记录，Demand 与 Matching 终态正在服务端协调。"
          : choose
            ? "人工选择已完成，需求已匹配。项目协议与交付尚未接入当前工作台。"
            : fresh.status === "PENDING_CLOSE"
              ? "关闭意图已记录，Demand 与 Matching 终态仍在服务端原子协调。"
              : "本轮已明确关闭且不选择；没有创建 Project 或 Agreement。");
      }
      setError(null);
    } catch (caught) {
      const problem = failure(caught);
      if (writeConfirmed) {
        clearPending(record);
        setError({ status: 503, code: "MATCHING_POST_COMMIT_REFRESH_FAILED", traceId: problem.traceId });
        setNotice("写入已确认，但后续界面刷新失败；切勿原样重试这笔已确认写入，请重新读取工作台。");
      } else if (problem.status === 412) {
        const fresh = record.resource_type === "MATCHING_INVITATION"
          ? await readInvitation(record.object_id)
          : recoveryAttemptIdRef.current
            ? await readSelection(recoveryAttemptIdRef.current, record.object_id)
            : null;
        if (fresh) {
          clearPending(record);
          setError({ ...problem, code: "MATCHING_PRECONDITION_RELOADED" });
          setNotice("服务端版本已变化；旧请求已清除并重读 exact 对象。请核对后生成新的命令。");
        } else {
          setError({ ...problem, code: "MATCHING_PRECONDITION_RELOAD_FAILED" });
          setNotice("服务端明确返回版本冲突，但 exact 对象尚未成功重读；恢复锁保持，不能发起新命令。");
        }
      } else {
        const outcomeUnknown = problem.code === "COMMAND_OUTCOME_UNKNOWN"
          || problem.status === 0
          || problem.status >= 500;
        if (!outcomeUnknown) clearPending(record);
        setError(problem);
        setNotice(outcomeUnknown
          ? "结果未知；已保留完全相同的请求。只能原样重试或放弃浏览器恢复对象。"
          : "服务端明确拒绝了 Matching 命令；未把失败当成成功。");
      }
    } finally {
      setBusy(false);
    }
  }, [claimWrite, clearPending, persistPending, readInvitation, readSelection, releaseWrite, rememberSelection, requestMatching]);

  useEffect(() => {
    if (!selection || !new Set(["PENDING_CHOICE", "PENDING_CLOSE"]).has(selection.status) || busy || pending) return;
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout>;
    const refresh = async () => {
      if (cancelled) return;
      const fresh = await readSelection(selection.attempt_id, selection.selection_id);
      if (!cancelled && fresh && new Set(["PENDING_CHOICE", "PENDING_CLOSE"]).has(fresh.status)) {
        timer = setTimeout(refresh, 2000);
      }
    };
    timer = setTimeout(refresh, 1000);
    return () => { cancelled = true; clearTimeout(timer); };
  }, [busy, pending, readSelection, selection]);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      let recovered: PendingIntent | null = null;
      let recoveryEncoded = "";
      try {
        recovered = parsePendingIntent(sessionStorage.getItem(PENDING_KEY) ?? "", Date.now());
        recoveryEncoded = sessionStorage.getItem(MATCHING_SELECTION_RECOVERY_KEY) ?? "";
      } catch {
        setError({ status: 503, code: "MATCHING_RECOVERY_STORAGE_UNAVAILABLE", traceId: null });
        return;
      }
      if (!isMatchingPending(recovered)) return;
      const allowed = recovered.resource_type === "MATCHING_INVITATION" ? canRespond : canSelect;
      if (!allowed || !claimWrite(recovered)) {
        setError({ status: 409, code: "WRITE_OUTCOME_PENDING", traceId: null });
        return;
      }
      const recovery = recovered.resource_type === "MATCHING_SELECTION"
        ? selectionRecovery(recoveryEncoded, recovered, organizationId)
        : null;
      recoveryAttemptIdRef.current = recovery?.attempt_id ?? null;
      setRecoveryAttemptId(recovery?.attempt_id ?? null);
      pendingRef.current = recovered;
      setPending(recovered);
      setNotice(recovered.resource_type === "MATCHING_SELECTION" && recovery === null
        ? "发现 Matching 结果未知请求，但 exact Selection 回读上下文不可用；只能原样重试，其他命令保持锁定。"
        : "发现 Matching 结果未知请求；非恢复控件已锁定，只能原样重试或安全重读。");
    }, 0);
    return () => window.clearTimeout(timer);
  }, [canRespond, canSelect, claimWrite, organizationId]);

  useEffect(() => {
    if (!canRespond) return;
    const timer = window.setTimeout(() => void loadInvitationList(), 0);
    return () => window.clearTimeout(timer);
  }, [canRespond, loadInvitationList]);

  useEffect(() => {
    if (!canSelect || selectedDemandId || matchingDemands.length === 0) return;
    const timer = window.setTimeout(() => void loadAttempts(matchingDemands[0].object_id), 0);
    return () => window.clearTimeout(timer);
  }, [canSelect, loadAttempts, matchingDemands, selectedDemandId]);

  useEffect(() => {
    if (!selectedInvitation || selectedInvitation.status !== "SENT") return;
    const remaining = Date.parse(selectedInvitation.expires_at) - Date.now();
    if (remaining <= 0) return;
    const timer = window.setTimeout(
      () => setClock(Date.now()),
      Math.min(remaining + 1, 60_000),
    );
    return () => window.clearTimeout(timer);
  }, [clock, selectedInvitation]);

  if (!canRespond && !canSelect) return null;

  const terminalInvitation = selectedInvitation !== null
    && new Set(["DECLINED", "WITHDRAWN", "EXPIRED", "REVOKED"]).has(selectedInvitation.status);
  const invitationExpiredByClock = selectedInvitation !== null
    && Date.parse(selectedInvitation.expires_at) <= clock;
  const selectionLocked = selection !== null && selection.status !== "OPEN";
  const nonRecoveryLocked = busy || writeLocked || pending !== null;

  const submitInvitationAction = (action: "ACCEPT" | "DECLINE" | "WITHDRAW") => {
    if (!selectedInvitation || !invitationEntityTag) return;
    try {
      const shared = {
        invitation: selectedInvitation,
        entityTag: invitationEntityTag,
        csrfToken: session.csrf_token,
        idempotencyKey: crypto.randomUUID(),
      };
      const intent = action === "ACCEPT"
        ? createAcceptMatchingInvitationIntent(shared)
        : action === "DECLINE"
          ? createDeclineMatchingInvitationIntent({ ...shared, reasonCode: declineReasonCode, note: responseNote })
          : createWithdrawMatchingInvitationIntent({ ...shared, reasonCode: withdrawReasonCode, note: responseNote });
      const label = action === "ACCEPT" ? "接受业务邀请" : action === "DECLINE" ? "拒绝业务邀请" : "撤回邀请接受";
      void performWrite(pendingRecord("MATCHING_INVITATION", selectedInvitation.invitation_id, label, intent));
    } catch (caught) {
      setError(failure(caught));
    }
  };

  const chooseInvitation = (invitationId: string) => {
    if (!selection || !selectionEntityTag || !organizationId) return;
    try {
      const intent = createChooseMatchingSelectionIntent({
        organizationId,
        selection,
        entityTag: selectionEntityTag,
        invitationId,
        selectionBasisCode,
        csrfToken: session.csrf_token,
        idempotencyKey: crypto.randomUUID(),
      });
      void performWrite(
        pendingRecord("MATCHING_SELECTION", selection.selection_id, "选择已接受创作者", intent),
        selection.attempt_id,
      );
    } catch (caught) {
      setError(failure(caught));
    }
  };

  const closeSelection = () => {
    if (!selection || !selectionEntityTag || !organizationId) return;
    try {
      const intent = createCloseMatchingSelectionIntent({
        organizationId,
        selection,
        entityTag: selectionEntityTag,
        reasonCode: selectionCloseReasonCode,
        csrfToken: session.csrf_token,
        idempotencyKey: crypto.randomUUID(),
      });
      void performWrite(
        pendingRecord("MATCHING_SELECTION", selection.selection_id, "关闭本轮且不选择", intent),
        selection.attempt_id,
      );
    } catch (caught) {
      setError(failure(caught));
    }
  };

  const claimCandidateSelector = () => {
    if (!canSelect || !selectedDemandId) return;
    try {
      const intent = createClaimCandidateSelectorIntent({
        demandId: selectedDemandId,
        csrfToken: session.csrf_token,
        idempotencyKey: crypto.randomUUID(),
      });
      void performWrite(
        pendingRecord("MATCHING_ASSIGNMENT", selectedDemandId, "领取 Candidate Selector 分配", intent),
      );
    } catch (caught) {
      setError(failure(caught));
    }
  };

  return <section className="trust-workbench matching-workbench" aria-busy={busy || invitationListBusy || invitationDetailBusy || attemptListBusy || selectionBusy} aria-labelledby="matching-workbench-title">
    <div className="trust-heading">
      <div>
        <h2 id="matching-workbench-title" tabIndex={-1}>匹配与邀请工作台</h2>
        <p>{canRespond ? "阅读合作条件，再决定是否接受邀请。" : "选择需求，查看匹配进度与已接受邀请的候选人。"}接受邀请与选择人选后，仍需后续协议确认。</p>
      </div>
      <button className="quiet-button" disabled={nonRecoveryLocked} type="button" onClick={() => canRespond ? void loadInvitationList() : selectedDemandId ? void loadAttempts(selectedDemandId) : undefined}>刷新匹配</button>
    </div>

    <div className="live-notice" aria-live="polite"><strong>Matching 状态</strong><span>{notice}</span></div>
    {error && <div className="error-panel" role="alert">
      <strong>Matching 请求未完成：{error.code}</strong>
      <span>页面没有把失败或未验证响应当作业务成功。</span>
      {error.traceId && <small>追踪编号：<code>{error.traceId}</code></small>}
    </div>}

    {pending && <section className="unknown-panel" aria-labelledby="matching-pending-title">
      <div>
        <p className="eyebrow">MATCHING WRITE OUTCOME UNKNOWN</p>
        <h3 id="matching-pending-title">结果未知恢复</h3>
        <p>“{pending.label}”保留了完全相同的路径、ETag、载荷和幂等键；CSRF 使用当前页面内存值，不持久化。</p>
        <small>保存时间：{localTime(pending.saved_at)}</small>
      </div>
      <div className="recovery-actions">
        <button className="primary-button" disabled={busy} type="button" onClick={() => void performWrite(pending)}>原样重试</button>
        {(pending.resource_type === "MATCHING_INVITATION" || recoveryAttemptId !== null) && <button className="quiet-button" disabled={busy} type="button" onClick={() => void (async () => {
          setBusy(true);
          const fresh = pending.resource_type === "MATCHING_INVITATION"
            ? await readInvitation(pending.object_id)
            : recoveryAttemptIdRef.current
              ? await readSelection(recoveryAttemptIdRef.current)
              : null;
          if (fresh) {
            clearPending(pending);
            setError(null);
            setNotice("已安全重读 exact 对象并放弃浏览器恢复对象；后续命令必须基于 fresh ETag 重新生成。");
          } else {
            setError({ status: 503, code: "MATCHING_RECOVERY_RELOAD_FAILED", traceId: null });
            setNotice("exact 对象尚未成功重读；恢复锁保持，不能发起新命令。");
          }
          setBusy(false);
        })()}>安全重读并放弃恢复</button>}
      </div>
    </section>}

    {canRespond && <div className="trust-grid">
      <section className="workbench-card" aria-labelledby="matching-invitation-list-title">
        <div className="section-heading">
          <div><p className="eyebrow">CREATOR</p><h3 id="matching-invitation-list-title">我的业务邀请</h3></div>
          <button className="text-button" disabled={nonRecoveryLocked || invitationListBusy} type="button" onClick={() => void loadInvitationList()}>刷新邀请</button>
        </div>
        {invitationListBusy && <p role="status">正在读取当前账号的业务邀请；尚未把结果判定为空。</p>}
        {invitationListError && <div className="task-discovery-error" role="alert">
          <strong>邀请列表读取未完成：{invitationListError.code}</strong>
          <span>{invitationList ? "保留上一次已验证列表。" : "读取失败，不是已验证的空邀请列表。"}</span>
        </div>}
        {!invitationListBusy && !invitationListError && invitationList?.items.length === 0 && <p className="empty-state" role="status">当前账号没有业务邀请（服务端已验证）。</p>}
        {invitationList?.items.map((item) => <button
          aria-current={selectedInvitation?.invitation_id === item.invitation_id ? "page" : undefined}
          className="resource-link"
          disabled={nonRecoveryLocked || invitationDetailBusy}
          key={item.invitation_id}
          type="button"
          onClick={() => void readInvitation(item.invitation_id)}
        >
          <strong>{item.disclosure.opportunity.title}</strong>
          <span>{item.disclosure.organization_preview.display_label}</span>
          <span>{invitationStatus(item.status)} · 截止 {localTime(item.expires_at)}</span>
          <code>{shortId(item.invitation_id)}</code>
        </button>)}
        {invitationList?.next_cursor && <p role="status">服务端仍有更多邀请；本页不猜测未读取记录。</p>}
      </section>

      <section className="workbench-card sensitive-card" aria-labelledby="matching-invitation-detail-title">
        <h3 id="matching-invitation-detail-title">合作邀请详情</h3>
        {invitationDetailBusy && <p role="status">正在读取 exact invitation 与 strong ETag。</p>}
        {invitationDetailError && <div className="task-discovery-error" role="alert">
          <strong>详情读取未完成：{invitationDetailError.code}</strong>
          <span>{selectedInvitation ? "保留上一次已验证详情；写入保持锁定直到重读成功。" : "安全披露尚未由服务端提供；接受与拒绝均保持 fail-closed。"}</span>
        </div>}
        {!selectedInvitation && !invitationDetailBusy && !invitationDetailError && <p className="empty-state">从左侧选择一条邀请后再核对完整披露。</p>}
        {selectedInvitation && <>
          <div className="safe-projection">
            <strong>{selectedInvitation.disclosure.opportunity.title}</strong>
            <span>{selectedInvitation.disclosure.organization_preview.display_label}</span>
            <span className="status">{invitationStatus(selectedInvitation.status)}</span>
            <code>{shortId(selectedInvitation.invitation_id)} · v{selectedInvitation.aggregate_version}</code>
          </div>
          <p>{selectedInvitation.disclosure.opportunity.problem_summary}</p>
          <dl className="trust-report-summary">
            <div><dt>披露报价范围</dt><dd>{money(selectedInvitation.disclosure.offer.minimum_amount_minor, selectedInvitation.disclosure.offer.currency)} – {money(selectedInvitation.disclosure.offer.maximum_amount_minor, selectedInvitation.disclosure.offer.currency)}</dd></div>
            <div><dt>计划</dt><dd>{selectedInvitation.disclosure.offer.schedule_code} · {selectedInvitation.disclosure.offer.duration_weeks} 周</dd></div>
            <div><dt>地域</dt><dd>{selectedInvitation.disclosure.constraints.region_codes.join(" · ")}</dd></div>
            <div><dt>语言</dt><dd>{selectedInvitation.disclosure.constraints.language_codes.join(" · ")}</dd></div>
            <div><dt>数据边界</dt><dd>{selectedInvitation.disclosure.constraints.data_sensitivity_code}</dd></div>
            <div><dt>AI 规则</dt><dd>{selectedInvitation.disclosure.constraints.ai_use_code}</dd></div>
            <div><dt>响应截止</dt><dd><time dateTime={selectedInvitation.expires_at}>{localTime(selectedInvitation.expires_at)}</time></dd></div>
            <div><dt>采用画像版本</dt><dd><code>{shortId(selectedInvitation.disclosure.profile_version_id)}</code></dd></div>
          </dl>
          <div><h4>预期交付</h4><ul>{selectedInvitation.disclosure.opportunity.deliverable_summaries.map((item) => <li key={item}>{item}</li>)}</ul></div>
          <div><h4>接受标准</h4><ul>{selectedInvitation.disclosure.opportunity.acceptance_summaries.map((item) => <li key={item}>{item}</li>)}</ul></div>
          {invitationExpiredByClock && selectedInvitation.status === "SENT" && <p className="task-discovery-error" role="alert">本地时钟显示截止时间已到；页面不会提交响应，请刷新服务端状态。</p>}
          <p className="safe-projection">接受只表示愿意基于此披露继续讨论；不会签署 Agreement，也不会承诺交付或最终金额。</p>
          {(selectedInvitation.status === "SENT" || selectedInvitation.status === "ACCEPTED") && <label>拒绝或撤回说明（可选）
            <textarea
              disabled={nonRecoveryLocked || terminalInvitation || invitationDetailError !== null}
              maxLength={500}
              rows={3}
              value={responseNote}
              onChange={(event) => setResponseNote(event.target.value)}
              placeholder="说明不继续参与的原因；不会用于接受操作"
            />
            <small>最多 500 字节；该说明只随“拒绝”或“撤回接受”命令提交。</small>
          </label>}
          <div className="button-row">
            <button className="primary-button" disabled={nonRecoveryLocked || terminalInvitation || invitationExpiredByClock || selectedInvitation.status !== "SENT" || invitationDetailError !== null} type="button" onClick={() => submitInvitationAction("ACCEPT")}>接受并进入人工选择</button>
            <button className="quiet-button" disabled={nonRecoveryLocked || terminalInvitation || invitationExpiredByClock || selectedInvitation.status !== "SENT" || invitationDetailError !== null} type="button" onClick={() => submitInvitationAction("DECLINE")}>拒绝这次邀请</button>
            <button className="quiet-button" disabled={nonRecoveryLocked || terminalInvitation || selectedInvitation.status !== "ACCEPTED" || invitationDetailError !== null} type="button" onClick={() => submitInvitationAction("WITHDRAW")}>选择完成前撤回接受</button>
          </div>
        </>}
      </section>
    </div>}

    {canSelect && <div className="trust-actions-grid">
      <section className="workbench-card" aria-labelledby="matching-attempts-title">
        <h3 id="matching-attempts-title">需求匹配进度</h3>
        {!demandsAvailable && <div className="task-discovery-error" role="alert"><strong>需求投影不可用</strong><span>读取失败，不是已验证的空需求列表。</span></div>}
        {demandsAvailable && matchingDemands.length === 0 && <p className="empty-state" role="status">当前组织没有进入 Matching 的需求（服务端已验证）。</p>}
        {matchingDemands.length > 0 && <label>选择需求
          <select disabled={nonRecoveryLocked || attemptListBusy} value={selectedDemandId} onChange={(event) => void loadAttempts(event.target.value)}>
            {matchingDemands.map((item) => <option key={item.object_id} value={item.object_id}>{shortId(item.object_id)} · {item.status}</option>)}
          </select>
        </label>}
        {selectedDemandId && <button
          className="primary-button"
          disabled={nonRecoveryLocked || attemptListBusy || selectorAssignment !== null}
          type="button"
          onClick={claimCandidateSelector}
        >{selectorAssignment ? "Candidate Selector 已领取" : "领取当前需求的 Candidate Selector 分配"}</button>}
        {selectorAssignment && <div className="safe-projection">
          <strong>Candidate Selector 分配有效</strong>
          <code>{shortId(selectorAssignment.candidate_selector_assignment_id)} · v{selectorAssignment.candidate_selector_assignment_version}</code>
          <span>有效期至 {localTime(selectorAssignment.expires_at)}</span>
        </div>}
        {attemptListBusy && <p role="status">正在读取该需求的 Matching Round；尚未判定为空。</p>}
        {attemptListError && <div className="task-discovery-error" role="alert"><strong>Matching Round 读取未完成：{attemptListError.code}</strong><span>{attemptList ? "保留上一次已验证列表。" : "读取失败，不是已验证的空轮次。"}</span></div>}
        {!attemptListBusy && !attemptListError && attemptList && attemptDemandId === selectedDemandId && attemptList.items.length === 0 && <p className="empty-state" role="status">当前会话没有可读取的有效 Candidate Selector 分配。可领取本轮分配；已完成的分配不会出现在此列表中。</p>}
        {attemptDemandId === selectedDemandId && attemptList?.items.map((attempt) => <button
          aria-current={selection?.attempt_id === attempt.attempt_id ? "page" : undefined}
          className="resource-link"
          disabled={nonRecoveryLocked || selectionBusy}
          key={attempt.attempt_id}
          type="button"
          onClick={() => void readSelection(attempt.attempt_id)}
        >
          <strong>第 {attempt.attempt_no} 轮 · {attemptStatus(attempt.status)}</strong>
          <span>{localTime(attempt.updated_at)}</span>
          <code>{shortId(attempt.attempt_id)}</code>
        </button>)}
        {attemptList?.next_cursor && <p role="status">服务端仍有更早轮次；本页不推断未读取历史。</p>}
        {savedSelectionReferences.length > 0 && <div className="safe-projection">
          <strong>本次登录已访问的选择记录</strong>
          <span>点击后重新验证读取权限与状态；新的登录不会继承原分配。</span>
          {savedSelectionReferences.map((reference) => <button
            className="resource-link"
            disabled={nonRecoveryLocked || selectionBusy}
            key={reference.selectionId}
            type="button"
            onClick={() => void readSelection(reference.attemptId, reference.selectionId)}
          >读取选择记录 {shortId(reference.selectionId)}</button>)}
        </div>}
      </section>

      <section className="workbench-card sensitive-card" aria-labelledby="matching-selection-title">
        <h3 id="matching-selection-title">选择合作人选</h3>
        {selectionBusy && <p role="status">正在读取 exact selection、assignment 与 accepted set。</p>}
        {selectionError && <div className="task-discovery-error" role="alert">
          <strong>Selection 读取未完成：{selectionError.code}</strong>
          <span>{selection ? "保留上一次已验证详情，所有选择控件保持锁定。" : "已接受的候选集合尚未由服务端提供；选择与关闭均 fail-closed。"}</span>
        </div>}
        {!selection && !selectionBusy && !selectionError && <p className="empty-state">选择一轮后读取该轮的服务端 Selection。</p>}
        {selection && <>
          <div className="safe-projection">
            <strong>{selectionStatus(selection.status)}</strong>
            <code>Selection {shortId(selection.selection_id)} · v{selection.aggregate_version}</code>
            <code>Assignment {shortId(selection.candidate_selector_assignment_id)}</code>
            <code>Assignment version {selection.candidate_selector_assignment_version}</code>
          </div>
          <button className="quiet-button" disabled={nonRecoveryLocked || selectionBusy} type="button" onClick={() => void readSelection(selection.attempt_id, selection.selection_id)}>刷新选择状态</button>
          {selection.status === "PENDING_CHOICE" && <p role="status">选择意图已记录，服务端正原子协调 Demand 与 Matching 终态；页面已锁定重复选择。</p>}
          {selection.status === "PENDING_CLOSE" && <p role="status">关闭意图已记录，服务端正原子协调 Demand 与 Matching 终态；页面已锁定重复操作。</p>}
          {selection.accepted_invitations.length === 0 && <p className="empty-state" role="status">{selection.status === "OPEN" ? "当前没有已接受的候选（服务端已验证）。可等待响应或明确关闭本轮。" : "本轮没有获选创作者（服务端已验证）。"}</p>}
          <label>选择依据
            <select disabled={nonRecoveryLocked || selectionLocked || selectionError !== null} value={selectionBasisCode} onChange={(event) => setSelectionBasisCode(event.target.value as (typeof MATCHING_SELECTION_BASIS_CODES)[number])}>
              <option value="CAPABILITY_SUMMARY_FIT">能力摘要与交付适配</option>
              <option value="DELIVERY_APPROACH_FIT">交付方式适配</option>
              <option value="SCHEDULE_FIT">计划适配</option>
            </select>
          </label>
          {selection.accepted_invitations.map((candidate) => <article className="safe-projection" key={candidate.invitation_id}>
            <strong>{candidate.creator_display_handle}</strong>
            <span>{candidate.capability_summary}</span>
            <small>接受于 <time dateTime={candidate.accepted_at}>{localTime(candidate.accepted_at)}</time></small>
            <code>Profile {shortId(candidate.profile_id)} · {shortId(candidate.profile_version_id)}</code>
            <button className="primary-button" disabled={nonRecoveryLocked || selectionLocked || selectionError !== null} type="button" onClick={() => chooseInvitation(candidate.invitation_id)}>选择该创作者</button>
          </article>)}
          <button className="quiet-button" disabled={nonRecoveryLocked || selectionLocked || selectionError !== null} type="button" onClick={closeSelection}>关闭本轮且不选择</button>
        </>}
      </section>
    </div>}
  </section>;
}
