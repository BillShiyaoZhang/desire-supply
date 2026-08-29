"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import {
  type SessionDto,
  parseSessionPage,
} from "../lib/session-contract.mjs";
import {
  LEGACY_SESSION_REVOKE_PENDING_KEY,
  SESSION_REVOKE_PENDING_KEY,
  type RemoteSessionRevokeIntent,
  type SessionSnapshot,
  assertRemoteRevokePostcondition,
  bindSessionPage,
  claimAndPersistRemoteSessionRevokeIntent,
  createRemoteSessionRevokeIntent,
  parseRemoteSessionRevokeIntent,
  serializeRemoteSessionRevokeIntent,
} from "../lib/session-manager-state.mjs";

const SESSION_LIST_ENDPOINT = "/v1/me/sessions?limit=25";
const MAX_COMPLETE_SESSION_PAGES = 100;
const LEGACY_REVOKE_LATCH_KEY = "legacy-session-revoke-recovery";

type SessionManagerRequest = (
  path: string,
  init?: RequestInit,
) => Promise<{ value: unknown; etag: string | null }>;

type SessionManagerProps = {
  accountUserId: string;
  bootstrapSessionId: string;
  claimWrite: (writeKey: string) => boolean;
  csrfToken: string;
  locked: boolean;
  logoutOutcomeUnknown: boolean;
  onGlobalBusyChange: (writeKey: string, value: boolean) => void;
  onLogoutCurrent: () => Promise<void>;
  releaseWrite: (writeKey: string) => void;
  request: SessionManagerRequest;
};

type SessionOperationError = {
  status: number;
  code: string;
  traceId: string | null;
};

function safeShortSessionId(sessionId: string) {
  return `${sessionId.slice(0, 8)}…${sessionId.slice(-6)}`;
}

function formatSessionTime(value: string) {
  return new Intl.DateTimeFormat("zh-CN", {
    dateStyle: "medium",
    timeStyle: "short",
    hour12: false,
  }).format(new Date(value));
}

function sessionStatusLabel(status: SessionDto["status"]) {
  if (status === "ACTIVE") return "活跃";
  if (status === "REVOKED") return "已撤销";
  return "已过期";
}

function sessionOperationFailure(caught: unknown, fallback: string): SessionOperationError {
  if (caught instanceof TypeError) {
    const code = /^[A-Z][A-Z0-9_]{2,63}$/.test(caught.message) ? caught.message : fallback;
    return { status: 503, code, traceId: null };
  }
  if (!caught || typeof caught !== "object") {
    return { status: 503, code: fallback, traceId: null };
  }
  const record = caught as Record<string, unknown>;
  const code = typeof record.code === "string" && /^[A-Z][A-Z0-9_]{2,63}$/.test(record.code)
    ? record.code
    : fallback;
  const status = typeof record.status === "number" && Number.isInteger(record.status)
    ? record.status
    : 503;
  const traceId = typeof record.traceId === "string" ? record.traceId : null;
  return { status, code, traceId };
}

function isRemoteRevokeOutcomeUnknown(failure: SessionOperationError) {
  return failure.status === 0 || failure.status >= 500;
}

export function SessionManager({
  accountUserId,
  bootstrapSessionId,
  claimWrite,
  csrfToken,
  locked,
  logoutOutcomeUnknown,
  onGlobalBusyChange,
  onLogoutCurrent,
  releaseWrite,
  request,
}: SessionManagerProps) {
  const [snapshot, setSnapshot] = useState<SessionSnapshot>({
    items: [],
    nextCursor: null,
    seenCursors: [],
  });
  const [initialized, setInitialized] = useState(false);
  const [recoveryChecked, setRecoveryChecked] = useState(false);
  const [recoveryStorageAvailable, setRecoveryStorageAvailable] = useState(false);
  const [recoveryEpoch, setRecoveryEpoch] = useState(0);
  const [legacyRecoveryBlocked, setLegacyRecoveryBlocked] = useState(false);
  const [readOperation, setReadOperation] = useState<"REFRESH" | "MORE" | null>(null);
  const [logoutBusy, setLogoutBusy] = useState(false);
  const [remoteBusy, setRemoteBusy] = useState(false);
  const [remoteIntent, setRemoteIntent] = useState<RemoteSessionRevokeIntent | null>(null);
  const [confirmingTargetId, setConfirmingTargetId] = useState<string | null>(null);
  const [notice, setNotice] = useState("会话摘要只在当前页面内存中保存。");
  const [error, setError] = useState<SessionOperationError | null>(null);
  const generationRef = useRef(0);
  const legacyRecoveryBlockedRef = useRef(false);
  const remoteBusyRef = useRef(false);
  const remoteIntentRef = useRef<RemoteSessionRevokeIntent | null>(null);

  const commitSnapshot = useCallback((next: SessionSnapshot) => {
    setSnapshot(next);
    setInitialized(true);
    setConfirmingTargetId((current) => current !== null && next.items.some((item) => (
      item.session_id === current && !item.is_current && item.status === "ACTIVE"
    )) ? current : null);
  }, []);

  const refresh = useCallback(async () => {
    if (
      !recoveryChecked
      || !recoveryStorageAvailable
      || legacyRecoveryBlocked
      || locked
      || remoteIntentRef.current !== null
      || remoteBusyRef.current
    ) return;
    const generation = ++generationRef.current;
    setReadOperation("REFRESH");
    setError(null);
    try {
      const response = await request(SESSION_LIST_ENDPOINT);
      if (response.etag !== null) throw new TypeError("INVALID_SESSION_PAGE_BINDING");
      const page = parseSessionPage(response.value);
      const next = bindSessionPage(page, {
        bootstrapSessionId,
        existing: null,
        requestedCursor: null,
      });
      if (generationRef.current !== generation) return;
      commitSnapshot(next);
      setNotice("会话摘要已从服务端重新读取；列表和游标未写入浏览器存储。");
    } catch (caught) {
      if (generationRef.current !== generation) return;
      setError(sessionOperationFailure(caught, "SESSION_LIST_UNAVAILABLE"));
    } finally {
      if (generationRef.current === generation) setReadOperation(null);
    }
  }, [
    bootstrapSessionId,
    commitSnapshot,
    locked,
    legacyRecoveryBlocked,
    recoveryChecked,
    recoveryStorageAvailable,
    request,
  ]);

  const loadMore = useCallback(async () => {
    const requestedCursor = snapshot.nextCursor;
    if (
      !recoveryChecked
      || !recoveryStorageAvailable
      || legacyRecoveryBlocked
      || locked
      || requestedCursor === null
      || remoteIntentRef.current !== null
      || remoteBusyRef.current
    ) return;
    const generation = ++generationRef.current;
    setReadOperation("MORE");
    setError(null);
    try {
      const response = await request(
        `${SESSION_LIST_ENDPOINT}&cursor=${encodeURIComponent(requestedCursor)}`,
      );
      if (response.etag !== null) throw new TypeError("INVALID_SESSION_PAGE_BINDING");
      const page = parseSessionPage(response.value);
      const next = bindSessionPage(page, {
        bootstrapSessionId,
        existing: snapshot,
        requestedCursor,
      });
      if (generationRef.current !== generation) return;
      commitSnapshot(next);
      setNotice("已沿服务端签名游标加载下一页会话摘要。");
    } catch (caught) {
      if (generationRef.current !== generation) return;
      setError(sessionOperationFailure(caught, "SESSION_LIST_UNAVAILABLE"));
    } finally {
      if (generationRef.current === generation) setReadOperation(null);
    }
  }, [
    bootstrapSessionId,
    commitSnapshot,
    locked,
    legacyRecoveryBlocked,
    recoveryChecked,
    recoveryStorageAvailable,
    request,
    snapshot,
  ]);

  const loadCompleteSnapshot = useCallback(async (generation: number) => {
    let complete: SessionSnapshot | null = null;
    let requestedCursor: string | null = null;
    for (let pageNumber = 0; pageNumber < MAX_COMPLETE_SESSION_PAGES; pageNumber += 1) {
      if (generationRef.current !== generation) return null;
      const path = requestedCursor === null
        ? SESSION_LIST_ENDPOINT
        : `${SESSION_LIST_ENDPOINT}&cursor=${encodeURIComponent(requestedCursor)}`;
      const response = await request(path);
      if (response.etag !== null) throw new TypeError("INVALID_SESSION_PAGE_BINDING");
      const page = parseSessionPage(response.value);
      complete = bindSessionPage(page, {
        bootstrapSessionId,
        existing: complete,
        requestedCursor,
      });
      if (generationRef.current !== generation) return null;
      if (complete.nextCursor === null) return complete;
      requestedCursor = complete.nextCursor;
    }
    throw new TypeError("SESSION_LIST_PAGE_LIMIT_EXCEEDED");
  }, [bootstrapSessionId, request]);

  useEffect(() => {
    let active = true;
    queueMicrotask(() => {
      if (!active) return;
      try {
        const legacyEncoded = sessionStorage.getItem(LEGACY_SESSION_REVOKE_PENDING_KEY);
        if (legacyEncoded !== null) {
          legacyRecoveryBlockedRef.current = true;
          setLegacyRecoveryBlocked(true);
          if (!claimWrite(LEGACY_REVOKE_LATCH_KEY)) {
            setError({ status: 409, code: "SESSION_REVOKE_GLOBAL_LATCH_UNAVAILABLE", traceId: null });
          } else {
            setNotice("发现旧版工作区绑定的会话撤销恢复对象；它不能证明当前账号绑定，页面保持关闭且不会重放。请明确放弃后再继续。");
          }
        } else {
          const encoded = sessionStorage.getItem(SESSION_REVOKE_PENDING_KEY) ?? "";
          const recovered = parseRemoteSessionRevokeIntent(encoded, {
            accountUserId,
            bootstrapSessionId,
          });
          if (recovered === null) {
            sessionStorage.removeItem(SESSION_REVOKE_PENDING_KEY);
          } else {
            remoteIntentRef.current = recovered;
            setRemoteIntent(recovered);
            if (!claimWrite(recovered.idempotency_key)) {
              setError({ status: 409, code: "SESSION_REVOKE_GLOBAL_LATCH_UNAVAILABLE", traceId: null });
            } else {
              setNotice("发现一笔结果未知的其他会话撤销；只能原样重试同一请求或明确放弃恢复。");
            }
          }
        }
        setRecoveryStorageAvailable(true);
      } catch {
        if (!active) return;
        setRecoveryStorageAvailable(false);
        setError({ status: 503, code: "SESSION_REVOKE_RECOVERY_STORAGE_FAILED", traceId: null });
        setNotice("无法安全读取或清理会话撤销恢复对象；会话读取与操作保持关闭。");
      } finally {
        if (active) setRecoveryChecked(true);
      }
    });
    return () => {
      active = false;
      generationRef.current += 1;
      const pending = remoteIntentRef.current;
      if (pending !== null) {
        onGlobalBusyChange(pending.idempotency_key, false);
        releaseWrite(pending.idempotency_key);
      }
      if (legacyRecoveryBlockedRef.current) {
        legacyRecoveryBlockedRef.current = false;
        releaseWrite(LEGACY_REVOKE_LATCH_KEY);
      }
    };
  }, [accountUserId, bootstrapSessionId, claimWrite, onGlobalBusyChange, recoveryEpoch, releaseWrite]);

  useEffect(() => {
    let active = true;
    if (
      recoveryChecked
      && recoveryStorageAvailable
      && !legacyRecoveryBlocked
      && !locked
      && remoteIntentRef.current === null
    ) {
      queueMicrotask(() => {
        if (active && remoteIntentRef.current === null) void refresh();
      });
    }
    return () => {
      active = false;
      generationRef.current += 1;
    };
  }, [legacyRecoveryBlocked, locked, recoveryChecked, recoveryStorageAvailable, refresh]);

  function persistRemoteIntent(intent: RemoteSessionRevokeIntent) {
    sessionStorage.setItem(
      SESSION_REVOKE_PENDING_KEY,
      serializeRemoteSessionRevokeIntent(intent),
    );
    remoteIntentRef.current = intent;
    setRemoteIntent(intent);
  }

  function settleRemoteIntent(intent: RemoteSessionRevokeIntent) {
    try {
      sessionStorage.removeItem(SESSION_REVOKE_PENDING_KEY);
    } catch {
      setRecoveryStorageAvailable(false);
      throw new TypeError("SESSION_REVOKE_RECOVERY_CLEAR_FAILED");
    }
    remoteIntentRef.current = null;
    setRemoteIntent(null);
    onGlobalBusyChange(intent.idempotency_key, false);
    releaseWrite(intent.idempotency_key);
  }

  function abandonLegacyRecovery() {
    if (!legacyRecoveryBlockedRef.current || locked || remoteBusyRef.current || logoutBusy) return;
    try {
      sessionStorage.removeItem(LEGACY_SESSION_REVOKE_PENDING_KEY);
    } catch {
      setRecoveryStorageAvailable(false);
      setError({ status: 503, code: "SESSION_REVOKE_RECOVERY_CLEAR_FAILED", traceId: null });
      setNotice("旧版恢复对象未能清除；会话读取与操作继续保持关闭。");
      return;
    }
    legacyRecoveryBlockedRef.current = false;
    setLegacyRecoveryBlocked(false);
    releaseWrite(LEGACY_REVOKE_LATCH_KEY);
    setError(null);
    setRecoveryChecked(false);
    setRecoveryStorageAvailable(false);
    setNotice("已明确放弃不可验证的旧版恢复对象；正在检查当前账号级恢复契约。");
    setRecoveryEpoch((current) => current + 1);
  }

  async function revokeRemoteSession(candidateTargetSessionId?: string) {
    if (
      !recoveryChecked
      || !recoveryStorageAvailable
      || legacyRecoveryBlocked
      || locked
      || remoteBusyRef.current
      || logoutBusy
      || readOperation !== null
    ) return;
    let record: RemoteSessionRevokeIntent;
    try {
      const target = candidateTargetSessionId === undefined
        ? null
        : snapshot.items.find((item) => item.session_id === candidateTargetSessionId);
      if (remoteIntentRef.current === null && (
        target === undefined
        || target === null
        || target.is_current
        || target.status !== "ACTIVE"
        || confirmingTargetId !== target.session_id
      )) throw new TypeError("REMOTE_SESSION_REVOKE_TARGET_NOT_ACTIVE");
      record = remoteIntentRef.current ?? createRemoteSessionRevokeIntent({
        accountUserId,
        bootstrapSessionId,
        csrfToken,
        idempotencyKey: crypto.randomUUID(),
        targetSessionId: target?.session_id ?? "",
      });
      if (remoteIntentRef.current === null) {
        claimAndPersistRemoteSessionRevokeIntent(record, {
          claimWrite,
          persistIntent: persistRemoteIntent,
          releaseWrite,
          setWriteBusy: onGlobalBusyChange,
        });
      } else if (!claimWrite(record.idempotency_key)) {
        throw new TypeError("SESSION_REVOKE_GLOBAL_LATCH_UNAVAILABLE");
      }
    } catch (caught) {
      const failure = sessionOperationFailure(caught, "REMOTE_SESSION_REVOKE_NOT_AVAILABLE");
      if (failure.code === "SESSION_REVOKE_RECOVERY_STORAGE_FAILED") {
        setRecoveryStorageAvailable(false);
      }
      setError(failure);
      setNotice("撤销请求没有发送；页面未能建立精确恢复对象或取得全局写入门闩。");
      return;
    }

    const generation = ++generationRef.current;
    remoteBusyRef.current = true;
    setRemoteBusy(true);
    setConfirmingTargetId(null);
    setError(null);
    onGlobalBusyChange(record.idempotency_key, true);
    setNotice("正在撤销所选其他会话；当前会话 Cookie 不得被响应改写。");
    let writeConfirmed = false;
    try {
      const result = await request(
        `/v1/me/sessions/${encodeURIComponent(record.target_session_id)}`,
        {
          method: "DELETE",
          headers: {
            "idempotency-key": record.idempotency_key,
            "x-bootstrap-session-id": record.bootstrap_session_id,
            "x-csrf-token": record.csrf_token,
          },
        },
      );
      if (result.value !== null || result.etag !== null) {
        throw new TypeError("INVALID_REMOTE_SESSION_REVOKE_RESPONSE");
      }
      writeConfirmed = true;
      const fresh = await loadCompleteSnapshot(generation);
      if (fresh === null || generationRef.current !== generation) return;
      const verified = assertRemoteRevokePostcondition(fresh, {
        bootstrapSessionId: record.bootstrap_session_id,
        targetSessionId: record.target_session_id,
      });
      commitSnapshot(verified);
      settleRemoteIntent(record);
      setNotice("其他会话已由服务端撤销；fresh GET 同时确认当前 bootstrap 会话仍为 ACTIVE。");
    } catch (caught) {
      if (generationRef.current !== generation) return;
      const failure = sessionOperationFailure(caught, "REMOTE_SESSION_REVOKE_FAILED");
      if (failure.code === "SESSION_REVOKE_RECOVERY_CLEAR_FAILED") {
        setError(failure);
        setNotice("服务端状态已核对，但浏览器恢复对象未能清除；会话读取与操作保持关闭。");
      } else if (writeConfirmed) {
        setError({ ...failure, code: "SESSION_REVOKE_POST_COMMIT_REFRESH_FAILED" });
        setNotice("撤销返回了受验证的 204，但 fresh GET 未能证明目标终态和当前会话 ACTIVE；只可原样重试或放弃恢复。");
      } else if (isRemoteRevokeOutcomeUnknown(failure)) {
        setError(failure);
        setNotice("撤销结果未知；已保留同一 target、CSRF 和幂等键，只能原样重试或明确放弃恢复。");
      } else {
        try {
          settleRemoteIntent(record);
        } catch {
          setError({ status: 503, code: "SESSION_REVOKE_RECOVERY_CLEAR_FAILED", traceId: null });
          setNotice("服务端已明确拒绝撤销，但浏览器恢复对象未能清除；不会生成新请求。");
          return;
        }
        setError(failure);
        setNotice("服务端已明确拒绝撤销；恢复对象已清除，可以修正后重新操作。");
      }
    } finally {
      if (generationRef.current === generation) {
        remoteBusyRef.current = false;
        setRemoteBusy(false);
        onGlobalBusyChange(record.idempotency_key, false);
      }
    }
  }

  function abandonRemoteRecovery() {
    const intent = remoteIntentRef.current;
    if (intent === null || remoteBusyRef.current) return;
    try {
      settleRemoteIntent(intent);
      setError(null);
      setNotice("已明确放弃其他会话撤销恢复；页面没有据此推断服务端结果。");
    } catch {
      setError({ status: 503, code: "SESSION_REVOKE_RECOVERY_CLEAR_FAILED", traceId: null });
    }
  }

  async function logoutCurrent() {
    if (
      !recoveryChecked
      || !recoveryStorageAvailable
      || legacyRecoveryBlocked
      || locked
      || logoutOutcomeUnknown
      || logoutBusy
      || remoteBusyRef.current
      || remoteIntentRef.current !== null
      || readOperation !== null
    ) return;
    generationRef.current += 1;
    setReadOperation(null);
    setLogoutBusy(true);
    try {
      await onLogoutCurrent();
    } finally {
      setLogoutBusy(false);
    }
  }

  const controlsLocked = locked
    || !recoveryChecked
    || !recoveryStorageAvailable
    || legacyRecoveryBlocked
    || logoutBusy
    || remoteBusy
    || remoteIntent !== null
    || readOperation !== null;
  const recoveryControlsLocked = locked
    || !recoveryStorageAvailable
    || logoutBusy
    || remoteBusy
    || readOperation !== null;
  const visibleReadOperation = locked || legacyRecoveryBlocked || remoteIntent !== null ? null : readOperation;

  return (
    <section
      aria-busy={visibleReadOperation !== null || remoteBusy}
      aria-labelledby="session-manager-title"
      className="session-manager"
    >
      <header className="session-manager__heading">
        <div>
          <p className="eyebrow">ACCOUNT SECURITY · IAM38 SELF-SERVICE</p>
          <h2 id="session-manager-title">我的会话</h2>
          <p>仅显示服务端安全摘要；列表与游标不持久化，撤销恢复只保存精确请求且 24 小时失效。</p>
        </div>
        <button
          aria-controls="session-manager-list"
          className="quiet-button"
          disabled={controlsLocked}
          type="button"
          onClick={() => void refresh()}
        >{visibleReadOperation === "REFRESH" ? "正在刷新…" : "刷新会话"}</button>
      </header>

      <div className="session-manager__notice" aria-live="polite">{notice}</div>

      {logoutOutcomeUnknown && <div className="session-manager__guard" role="status">
        当前会话退出结果尚未确认。请使用页面上方已有的退出恢复面；这里不会发送其他请求。
      </div>}
      {!logoutOutcomeUnknown && locked && <div className="session-manager__guard" role="status">
        当前有另一笔全局读取、写入或恢复门闩；新的会话读取与操作已暂停。
      </div>}

      {legacyRecoveryBlocked && <section className="session-manager__remote-recovery" aria-labelledby="legacy-revoke-recovery-title">
        <div>
          <p className="eyebrow">LEGACY RECOVERY FAIL CLOSED</p>
          <h3 id="legacy-revoke-recovery-title">旧版会话撤销恢复不可重放</h3>
          <p>旧对象只绑定工作区，不能证明当前账号；页面不会读取其中的目标、CSRF、幂等键或据此发送请求。</p>
        </div>
        <div className="recovery-actions">
          <button
            className="quiet-button"
            disabled={locked || logoutBusy || remoteBusy || readOperation !== null}
            type="button"
            onClick={abandonLegacyRecovery}
          >明确放弃旧版恢复</button>
        </div>
      </section>}

      {remoteIntent && <section className="session-manager__remote-recovery" aria-labelledby="remote-revoke-recovery-title">
        <div>
          <p className="eyebrow">REMOTE REVOKE OUTCOME UNKNOWN</p>
          <h3 id="remote-revoke-recovery-title">其他会话撤销结果待核对</h3>
          <p>恢复对象绑定当前账号、bootstrap 会话、目标会话、CSRF 与原幂等键，不会改换账号、目标或扩展为全部撤销。</p>
          <small>目标短 ID：<code>{safeShortSessionId(remoteIntent.target_session_id)}</code> · 保存时间：{formatSessionTime(remoteIntent.saved_at)}</small>
        </div>
        <div className="recovery-actions">
          <button
            className="primary-button"
            disabled={recoveryControlsLocked}
            type="button"
            onClick={() => void revokeRemoteSession()}
          >{remoteBusy ? "正在原样重试…" : "原样重试撤销"}</button>
          <button
            className="quiet-button"
            disabled={remoteBusy}
            type="button"
            onClick={abandonRemoteRecovery}
          >放弃撤销恢复</button>
        </div>
      </section>}

      {error && <div className="session-manager__error" role="alert">
        <strong>会话操作未完成：{error.code}</strong>
        <span>页面没有把失败或未知结果显示为成功。</span>
        {error.traceId && <small>追踪编号：<code>{error.traceId}</code></small>}
      </div>}

      {!recoveryChecked && <p className="session-manager__empty" role="status">
        正在检查当前标签页的会话撤销恢复对象…
      </p>}
      {recoveryChecked && !initialized && visibleReadOperation === "REFRESH" && <p className="session-manager__empty" role="status">
        正在读取当前账号的会话摘要…
      </p>}
      {recoveryChecked && !initialized && visibleReadOperation === null && !error && remoteIntent === null && <p className="session-manager__empty">
        尚未读取到会话摘要。门闩解除后会自动读取，也可手动刷新。
      </p>}

      {snapshot.items.length > 0 && <ul className="session-manager__list" id="session-manager-list">
        {snapshot.items.map((item) => {
          const isCurrentActive = item.is_current && item.status === "ACTIVE";
          const isRemoteActive = !item.is_current && item.status === "ACTIVE";
          const confirming = isRemoteActive && confirmingTargetId === item.session_id;
          return <li className="session-manager__item" key={item.session_id}>
            <div className="session-manager__item-heading">
              <div>
                <strong>{item.device_label}</strong>
                <code>{safeShortSessionId(item.session_id)}</code>
              </div>
              <div className="session-manager__badges">
                {item.is_current && <span className="status status--done">当前会话</span>}
                <span className={`status status--session-${item.status.toLowerCase()}`}>
                  {sessionStatusLabel(item.status)}
                </span>
              </div>
            </div>
            <dl className="session-manager__facts">
              <div><dt>创建</dt><dd>{formatSessionTime(item.created_at)}</dd></div>
              <div><dt>最近活动</dt><dd>{formatSessionTime(item.last_activity_at)}</dd></div>
              <div><dt>到期</dt><dd>{formatSessionTime(item.expires_at)}</dd></div>
            </dl>
            {isCurrentActive && <button
              className="quiet-button"
              disabled={controlsLocked}
              type="button"
              onClick={() => void logoutCurrent()}
            >{logoutBusy ? "正在退出…" : "退出此当前会话"}</button>}
            {isRemoteActive && !confirming && <button
              className="danger-button"
              disabled={controlsLocked}
              type="button"
              onClick={() => setConfirmingTargetId(item.session_id)}
            >撤销此会话</button>}
            {confirming && <div className="session-manager__confirmation" role="group" aria-label="确认撤销这个其他会话">
              <strong>确认撤销这个其他会话？</strong>
              <span>目标是 <code>{safeShortSessionId(item.session_id)}</code>；当前会话将保持登录并在成功后重新核对。</span>
              <div className="button-row">
                <button
                  className="danger-button"
                  disabled={controlsLocked}
                  type="button"
                  onClick={() => void revokeRemoteSession(item.session_id)}
                >确认撤销</button>
                <button
                  className="quiet-button"
                  disabled={controlsLocked}
                  type="button"
                  onClick={() => setConfirmingTargetId(null)}
                >取消撤销</button>
              </div>
            </div>}
            {item.status !== "ACTIVE" && <p className="session-manager__action-note">
              终态会话，无可用操作。
            </p>}
          </li>;
        })}
      </ul>}

      {snapshot.nextCursor !== null && <div className="session-manager__pagination">
        <span>已显示 {snapshot.items.length} 个服务端会话摘要</span>
        <button
          aria-controls="session-manager-list"
          className="quiet-button"
          disabled={controlsLocked}
          type="button"
          onClick={() => void loadMore()}
        >{visibleReadOperation === "MORE" ? "正在加载…" : "加载更多"}</button>
      </div>}
    </section>
  );
}
