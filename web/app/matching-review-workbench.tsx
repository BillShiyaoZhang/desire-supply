"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import {
  type PendingIntent,
  type SessionBootstrap,
  type WorkspaceCandidate,
  parsePendingIntent,
  serializePendingIntent,
} from "../lib/app-contract.mjs";
import {
  type MatchingReviewInvitation,
  type MatchingReviewWorkspace,
  assertMatchingEntityTag,
  createClaimMatchingReviewIntent,
  createInvalidateMatchingReviewAttemptIntent,
  createMatchingReviewInvitationExpiry,
  createMatchingReviewInvitationIntent,
  createPublishMatchingReviewInvitationIntent,
  createReleaseMatchingReviewIntent,
  parseMatchingReviewAssignment,
  parseMatchingReviewWorkspace,
  parseMatchingReviewerAttempt,
  parseMatchingReviewerInvitation,
  serializeMatchingPendingIntent,
} from "../lib/matching-contract.mjs";

const PENDING_KEY = "desire-pilot-pending:v1";

type WorkspaceRequest = (
  path: string,
  init?: RequestInit,
) => Promise<{ value: unknown; etag: string | null }>;

type Props = {
  session: SessionBootstrap;
  workspace: WorkspaceCandidate;
  request: WorkspaceRequest;
  writeLocked: boolean;
  claimWrite: (record: PendingIntent) => boolean;
  releaseWrite: (record: PendingIntent) => void;
};

type MatchingFailure = { status: number; code: string; traceId: string | null };

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
    return { status: 503, code: value.message || "INVALID_MATCHING_REVIEW_RESPONSE", traceId: null };
  }
  return { status: 0, code: "MATCHING_REVIEW_OUTCOME_UNKNOWN", traceId: null };
}

function shortId(value: string) {
  return value.length > 26 ? `${value.slice(0, 12)}…${value.slice(-8)}` : value;
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

function pendingRecord(objectId: string, label: string, intent: PendingIntent["intent"]): PendingIntent {
  return {
    version: 1,
    saved_at: new Date().toISOString(),
    resource_type: "MATCHING_REVIEW",
    object_id: objectId,
    label,
    intent,
  };
}

function samePending(left: PendingIntent, right: PendingIntent) {
  return serializePendingIntent(left) === serializePendingIntent(right);
}

export function MatchingReviewWorkbench({
  session,
  workspace,
  request,
  writeLocked,
  claimWrite,
  releaseWrite,
}: Props) {
  const authorized = workspace.workspace_kind === "PLATFORM"
    && workspace.role_codes.includes("OPERATIONS_REVIEWER");
  const reviewerUserId = authorized && workspace.workspace_id.startsWith("platform:")
    ? workspace.workspace_id.slice("platform:".length)
    : "";
  const [review, setReview] = useState<MatchingReviewWorkspace | null>(null);
  const reviewRef = useRef<MatchingReviewWorkspace | null>(null);
  const [assignmentEtag, setAssignmentEtag] = useState<string | null>(null);
  const [verifiedEmpty, setVerifiedEmpty] = useState(false);
  const [busy, setBusy] = useState(authorized);
  const [error, setError] = useState<MatchingFailure | null>(null);
  const [notice, setNotice] = useState("Matching Review 只读取当前会话领取的 exact assignment。");
  const [pending, setPending] = useState<PendingIntent | null>(null);
  const pendingRef = useRef<PendingIntent | null>(null);
  const [clock, setClock] = useState(Date.now);
  const [invitationValidityHours, setInvitationValidityHours] = useState(7 * 24);

  const requestMatching = useCallback((path: string, init?: RequestInit) => {
    const headers = new Headers(init?.headers);
    headers.set("x-workspace-id", workspace.workspace_id);
    if (init?.method === "POST") headers.set("x-csrf-token", session.csrf_token);
    return request(path, { ...init, headers });
  }, [request, session.csrf_token, workspace.workspace_id]);

  const loadAssignment = useCallback(async () => {
    if (!authorized) return false;
    setBusy(true);
    setError(null);
    try {
      const response = await requestMatching("/v1/app/matching-review/assignment");
      const fresh = parseMatchingReviewWorkspace(response.value);
      assertMatchingEntityTag(response.etag, fresh.aggregate_version);
      reviewRef.current = fresh;
      setReview(fresh);
      setAssignmentEtag(response.etag);
      setVerifiedEmpty(false);
      setClock(Date.now());
      setNotice("当前审核分配、run、候选与邀请已从 matching_review 投影重新核对。");
      return true;
    } catch (caught) {
      const problem = failure(caught);
      if (problem.status === 404 && problem.code === "RESOURCE_NOT_FOUND") {
        reviewRef.current = null;
        setReview(null);
        setAssignmentEtag(null);
        setVerifiedEmpty(true);
        setError(null);
        setNotice("服务端已验证当前会话没有有效 Matching Review 分配；可领取下一项。");
        return true;
      }
      setError(problem);
      setNotice(reviewRef.current
        ? "刷新失败；保留上一次已验证详情，但所有写入保持锁定。"
        : "审核详情读取失败，不会把失败伪装成空队列。");
      return false;
    } finally {
      setBusy(false);
    }
  }, [authorized, requestMatching]);

  const clearPending = useCallback((record: PendingIntent) => {
    if (!pendingRef.current || !samePending(pendingRef.current, record)) return;
    pendingRef.current = null;
    setPending(null);
    try { sessionStorage.removeItem(PENDING_KEY); } catch { /* in-memory latch still releases */ }
    releaseWrite(record);
  }, [releaseWrite]);

  const persistPending = useCallback((record: PendingIntent) => {
    const encoded = serializeMatchingPendingIntent(record);
    try {
      sessionStorage.setItem(PENDING_KEY, encoded);
    } catch {
      throw new TypeError("MATCHING_RECOVERY_STORAGE_UNAVAILABLE");
    }
    pendingRef.current = record;
    setPending(record);
  }, []);

  const performWrite = useCallback(async (candidate: PendingIntent) => {
    const record = pendingRef.current ?? candidate;
    if (
      record.resource_type !== "MATCHING_REVIEW"
      || (pendingRef.current && !samePending(pendingRef.current, candidate))
      || !claimWrite(record)
    ) {
      setError({ status: 409, code: "WRITE_OUTCOME_PENDING", traceId: null });
      return;
    }
    if (!pendingRef.current) {
      try {
        persistPending(record);
      } catch (caught) {
        releaseWrite(record);
        setError(failure(caught));
        return;
      }
    }
    setBusy(true);
    setError(null);
    let confirmed = false;
    try {
      const response = await requestMatching(record.intent.path, {
        method: record.intent.method,
        headers: record.intent.headers,
        body: JSON.stringify(record.intent.body),
      });
      if (record.intent.path === "/v1/app/matching-review/queue/claim") {
        const result = parseMatchingReviewAssignment(response.value);
        assertMatchingEntityTag(response.etag, result.aggregate_version);
        if (result.status !== "ACTIVE") throw new TypeError("MATCHING_REVIEW_TRANSITION_INVALID");
      } else if (record.intent.path === "/v1/app/matching-review/assignment/release") {
        const result = parseMatchingReviewAssignment(response.value);
        assertMatchingEntityTag(response.etag, result.aggregate_version);
        if (result.status !== "REVOKED") throw new TypeError("MATCHING_REVIEW_TRANSITION_INVALID");
      } else if (record.intent.path.includes("/match-runs/")) {
        const result = parseMatchingReviewerInvitation(response.value);
        assertMatchingEntityTag(response.etag, result.aggregate_version);
        if (result.status !== "CREATED") throw new TypeError("MATCHING_REVIEW_TRANSITION_INVALID");
      } else if (record.intent.path.endsWith("/publish")) {
        const result = parseMatchingReviewerInvitation(response.value);
        assertMatchingEntityTag(response.etag, result.aggregate_version);
        if (result.status !== "SENT") throw new TypeError("MATCHING_REVIEW_TRANSITION_INVALID");
      } else {
        const result = parseMatchingReviewerAttempt(response.value);
        assertMatchingEntityTag(response.etag, result.aggregate_version);
        if (result.status !== "INVALIDATED") throw new TypeError("MATCHING_REVIEW_TRANSITION_INVALID");
      }
      confirmed = true;
      clearPending(record);
      const refreshed = await loadAssignment();
      if (!refreshed) {
        setError({ status: 503, code: "MATCHING_REVIEW_POST_COMMIT_REFRESH_FAILED", traceId: null });
      }
    } catch (caught) {
      const problem = failure(caught);
      if (confirmed) {
        clearPending(record);
        setError({ ...problem, code: "MATCHING_REVIEW_POST_COMMIT_REFRESH_FAILED" });
      } else if (
        record.intent.path === "/v1/app/matching-review/queue/claim"
        && problem.status === 404
        && problem.code === "RESOURCE_NOT_FOUND"
      ) {
        clearPending(record);
        const refreshed = await loadAssignment();
        if (refreshed) {
          setError(null);
          setNotice("服务端已验证当前没有可领取的 Matching Review 项。");
        }
      } else if (problem.status === 412) {
        const refreshed = await loadAssignment();
        if (refreshed) clearPending(record);
        setError({ ...problem, code: refreshed ? "MATCHING_REVIEW_PRECONDITION_RELOADED" : "MATCHING_REVIEW_PRECONDITION_RELOAD_FAILED" });
      } else {
        const unknown = problem.code === "COMMAND_OUTCOME_UNKNOWN"
          || problem.status === 0
          || problem.status >= 500;
        if (!unknown) clearPending(record);
        setError(problem);
        setNotice(unknown
          ? "命令结果未知；已保留 exact 路径、载荷、ETag 与幂等键，只能原样重试或安全重读。"
          : "Matching Review 命令被明确拒绝；页面没有把失败当成成功。");
      }
    } finally {
      setBusy(false);
    }
  }, [claimWrite, clearPending, loadAssignment, persistPending, releaseWrite, requestMatching]);

  useEffect(() => {
    if (!authorized) return;
    const timer = window.setTimeout(() => {
      let recovered: PendingIntent | null = null;
      try {
        recovered = parsePendingIntent(sessionStorage.getItem(PENDING_KEY) ?? "", Date.now());
      } catch {
        setError({ status: 503, code: "MATCHING_RECOVERY_STORAGE_UNAVAILABLE", traceId: null });
        return;
      }
      if (recovered?.resource_type === "MATCHING_REVIEW") {
        if (!claimWrite(recovered)) {
          setError({ status: 409, code: "WRITE_OUTCOME_PENDING", traceId: null });
          return;
        }
        pendingRef.current = recovered;
        setPending(recovered);
        setNotice("发现结果未知的 Matching Review 命令；其他写入已锁定。");
      }
      void loadAssignment();
    }, 0);
    return () => window.clearTimeout(timer);
  }, [authorized, claimWrite, loadAssignment]);

  if (!authorized) return null;
  const locked = busy || writeLocked || pending !== null || error !== null;
  let expiryPreview: string | null = null;
  try {
    expiryPreview = createMatchingReviewInvitationExpiry(invitationValidityHours, clock);
  } catch {
    // The explicit invalid state keeps all create controls locked below.
  }
  const expiryUsable = expiryPreview !== null;

  const claimNext = () => {
    try {
      const intent = createClaimMatchingReviewIntent({
        csrfToken: session.csrf_token,
        idempotencyKey: crypto.randomUUID(),
      });
      void performWrite(pendingRecord(reviewerUserId, "领取下一项 Matching Review", intent));
    } catch (caught) {
      setError(failure(caught));
    }
  };

  const releaseAssignment = () => {
    if (!review || !assignmentEtag) return;
    try {
      const intent = createReleaseMatchingReviewIntent({
        assignment: review,
        entityTag: assignmentEtag,
        csrfToken: session.csrf_token,
        idempotencyKey: crypto.randomUUID(),
      });
      void performWrite(pendingRecord(review.assignment_id, "释放 Matching Review 分配", intent));
    } catch (caught) {
      setError(failure(caught));
    }
  };

  const createInvitation = (creatorUserId: string) => {
    if (!review || !expiryUsable) return;
    try {
      const intent = createMatchingReviewInvitationIntent({
        workspace: review,
        creatorUserId,
        expiresAt: createMatchingReviewInvitationExpiry(invitationValidityHours),
        csrfToken: session.csrf_token,
        idempotencyKey: crypto.randomUUID(),
      });
      void performWrite(pendingRecord(review.match_run_id, "创建候选邀请", intent));
    } catch (caught) {
      setError(failure(caught));
    }
  };

  const publishInvitation = (invitation: MatchingReviewInvitation) => {
    try {
      const intent = createPublishMatchingReviewInvitationIntent({
        invitation,
        csrfToken: session.csrf_token,
        idempotencyKey: crypto.randomUUID(),
      });
      void performWrite(pendingRecord(invitation.invitation_id, "发布候选邀请", intent));
    } catch (caught) {
      setError(failure(caught));
    }
  };

  const invalidateAttempt = () => {
    if (!review) return;
    try {
      const intent = createInvalidateMatchingReviewAttemptIntent({
        workspace: review,
        reasonCode: "REVIEW_INVALIDATED",
        csrfToken: session.csrf_token,
        idempotencyKey: crypto.randomUUID(),
      });
      void performWrite(pendingRecord(review.attempt_id, "失效异常 Matching Attempt", intent));
    } catch (caught) {
      setError(failure(caught));
    }
  };

  const invitedCreators = new Set(review?.invitations.map((item) => item.creator_user_id) ?? []);

  return <section className="trust-workbench matching-review-workbench" aria-busy={busy} aria-labelledby="matching-review-title">
    <div className="trust-heading">
      <div>
        <p className="eyebrow">当前审核分配</p>
        <h2 id="matching-review-title" tabIndex={-1}>Matching 审核工作台</h2>
        <p>先领取下一项审核，再核对候选人和匹配依据，确认后发出合作邀请。</p>
      </div>
      <button className="quiet-button" disabled={busy || pending !== null} type="button" onClick={() => void loadAssignment()}>刷新当前分配</button>
    </div>

    <div className="live-notice" aria-live="polite"><strong>审核状态</strong><span>{notice}</span></div>
    {error && <div className="error-panel" role="alert">
      <strong>Matching Review 未完成：{error.code}</strong>
      <span>{review ? "保留上一次已验证详情；新动作保持锁定。" : "读取失败，不代表队列为空。"}</span>
      {error.traceId && <small>追踪编号：<code>{error.traceId}</code></small>}
    </div>}

    {pending && <section className="unknown-panel" aria-labelledby="matching-review-pending-title">
      <div><p className="eyebrow">WRITE OUTCOME UNKNOWN</p><h3 id="matching-review-pending-title">结果未知恢复</h3><p>“{pending.label}”保留了 exact 请求；CSRF 不会持久化。</p></div>
      <div className="recovery-actions">
        <button className="primary-button" disabled={busy} type="button" onClick={() => void performWrite(pending)}>原样重试</button>
        <button className="quiet-button" disabled={busy} type="button" onClick={() => void (async () => {
          const refreshed = await loadAssignment();
          if (refreshed) clearPending(pending);
        })()}>安全重读并放弃恢复</button>
      </div>
    </section>}

    {!review && verifiedEmpty && <section className="workbench-card">
      <h3>领取下一项</h3>
      <p className="empty-state" role="status">当前会话没有有效分配（服务端已验证）。系统不会在领取前披露组织、需求或候选。</p>
      <button className="primary-button" disabled={locked} type="button" onClick={claimNext}>领取下一项 Matching Review</button>
    </section>}

    {review && <>
      <div className="trust-actions-grid">
        <section className="workbench-card sensitive-card">
          <p className="eyebrow">EXACT ASSIGNMENT</p>
          <h3>{review.purpose_code}</h3>
          <dl className="trust-report-summary">
            <div><dt>Assignment</dt><dd><code>{shortId(review.assignment_id)} · v{review.aggregate_version}</code></dd></div>
            <div><dt>Attempt</dt><dd><code>{shortId(review.attempt_id)} · v{review.attempt.aggregate_version}</code></dd></div>
            <div><dt>Run</dt><dd><code>{shortId(review.match_run_id)} · v{review.run.aggregate_version}</code></dd></div>
            <div><dt>Run 状态</dt><dd>{review.run.status}</dd></div>
            <div><dt>候选计数</dt><dd>{review.run.candidate_count ?? "—"} 总计 · {review.run.eligible_count ?? "—"} eligible · {review.run.excluded_count ?? "—"} excluded</dd></div>
            <div><dt>有效期</dt><dd>{localTime(review.expires_at)}</dd></div>
          </dl>
          <div className="button-row">
            <button className="quiet-button" disabled={locked} type="button" onClick={releaseAssignment}>释放当前分配</button>
            <button className="quiet-button" disabled={locked || !review.actions.can_invalidate_attempt} type="button" onClick={invalidateAttempt}>失效异常 Attempt</button>
          </div>
        </section>

        <section className="workbench-card">
          <h3>邀请状态</h3>
          {review.invitations.length === 0 && <p className="empty-state" role="status">该 run 尚无邀请（服务端已验证）。</p>}
          {review.invitations.map((invitation) => <article className="safe-projection" key={invitation.invitation_id}>
            <strong>{invitation.status}</strong>
            <code>{shortId(invitation.invitation_id)} · v{invitation.aggregate_version}</code>
            <span>截止 {localTime(invitation.expires_at)}</span>
            <button className="primary-button" disabled={locked || !review.actions.can_publish_invitation || invitation.status !== "CREATED"} type="button" onClick={() => publishInvitation(invitation)}>发布 frozen disclosure 邀请</button>
          </article>)}
        </section>
      </div>

      <section className="workbench-card sensitive-card" aria-labelledby="matching-review-candidates-title">
        <h3 id="matching-review-candidates-title">Eligible 候选与确定性评分</h3>
        <label>新邀请有效时长（小时）
          <input
            disabled={locked || !review.actions.can_create_invitation}
            min={1}
            max={672}
            step={1}
            type="number"
            value={Number.isFinite(invitationValidityHours) ? invitationValidityHours : ""}
            onChange={(event) => setInvitationValidityHours(event.target.value === "" ? Number.NaN : Number(event.target.value))}
          />
          <small>可配置 1–672 小时（最长 28 天）；{expiryPreview ? `按当前时间预计截止 ${localTime(expiryPreview)}` : "请输入完整小时数后才能创建邀请"}。</small>
        </label>
        {review.eligible_candidates.length === 0 && <p className="empty-state" role="status">该 run 没有 eligible 候选（服务端已验证）。</p>}
        <div className="trust-grid">
          {review.eligible_candidates.map((candidate) => <article className="safe-projection" key={candidate.creator_user_id}>
            <strong>#{candidate.rank} · {candidate.creator_display_handle}</strong>
            <span>总分 {candidate.total_score}</span>
            <code>Profile {shortId(candidate.profile_id)} · {shortId(candidate.profile_version_id)}</code>
            <ul>{candidate.component_scores.map((component) => <li key={component.code}>{component.code}: {component.score}</li>)}</ul>
            <small>结果摘要 <code>{shortId(candidate.candidate_result_sha256)}</code></small>
            <button
              className="primary-button"
              disabled={locked || !review.actions.can_create_invitation || !expiryUsable || invitedCreators.has(candidate.creator_user_id)}
              type="button"
              onClick={() => createInvitation(candidate.creator_user_id)}
            >{invitedCreators.has(candidate.creator_user_id)
              ? "已创建邀请"
              : expiryUsable
                ? `创建 ${invitationValidityHours} 小时 frozen disclosure 邀请`
                : "配置有效期后创建邀请"}</button>
          </article>)}
        </div>
      </section>
    </>}
  </section>;
}
