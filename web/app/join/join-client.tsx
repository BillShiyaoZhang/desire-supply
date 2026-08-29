"use client";

import { useLayoutEffect, useRef, useState } from "react";
import {
  type AccessInvitationPreview,
  parseAccessInvitationPreview,
  parseSessionBootstrap,
  serializePendingInvitationContext,
} from "../../lib/app-contract.mjs";
import {
  PENDING_INVITATION_CONTEXT_KEY,
  captureAccessInvitationFragment,
  createInvitationAuthorizationInit,
  createInvitationStepUpBody,
  createJoinFlowCoordinator,
  parseIdentityAuthorizationUrl,
} from "../../lib/invitation-flow.mjs";

declare global {
  interface Window {
    __DESIRE_JOIN_BOOTSTRAP__?: { capability: unknown; error: unknown };
  }
}

class JoinApiError extends Error {
  constructor(public status: number, public code: string) {
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
      credentials: init?.credentials ?? "same-origin",
      headers,
    });
  } catch {
    throw new JoinApiError(0, "NETWORK_OUTCOME_UNKNOWN");
  }
  const value: unknown = await response.json().catch(() => null);
  if (!response.ok) {
    const top = value && typeof value === "object" ? value as Record<string, unknown> : {};
    const nested = top.error && typeof top.error === "object" ? top.error as Record<string, unknown> : {};
    const code = typeof nested.code === "string" ? nested.code : typeof top.code === "string" ? top.code : "JOIN_REQUEST_FAILED";
    throw new JoinApiError(response.status, code);
  }
  return { value, etag: response.headers.get("etag") };
}

function consumeCapability(): string {
  const bootstrap = window.__DESIRE_JOIN_BOOTSTRAP__;
  delete window.__DESIRE_JOIN_BOOTSTRAP__;
  if (bootstrap) {
    if (bootstrap.error !== null || typeof bootstrap.capability !== "string") {
      throw new TypeError("ACCESS_INVITATION_FRAGMENT_INVALID");
    }
    return createInvitationStepUpBody(bootstrap.capability).access_invitation_token;
  }
  return captureAccessInvitationFragment(
    window.location.href,
    (path) => window.history.replaceState(null, "", path),
    window.location.origin,
  );
}

function safeAuthorizationUrl(value: unknown): string {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new TypeError("INVALID_AUTHORIZATION_RESPONSE");
  const record = value as Record<string, unknown>;
  if (
    Object.keys(record).length !== 3
    || typeof record.auth_transaction_id !== "string"
    || !/^[A-Za-z0-9][A-Za-z0-9_-]{15,127}$/.test(record.auth_transaction_id)
    || typeof record.authorization_url !== "string"
    || typeof record.expires_at !== "string"
    || !Number.isFinite(Date.parse(record.expires_at))
  ) {
    throw new TypeError("INVALID_AUTHORIZATION_RESPONSE");
  }
  return parseIdentityAuthorizationUrl(record.authorization_url);
}

type JoinOutcome = {
  phase: "REDIRECTING" | "INVALID" | "UNAVAILABLE";
  preview: AccessInvitationPreview | null;
  target: string | null;
  errorCode: string | null;
};

async function runJoinFlow(): Promise<JoinOutcome> {
  let capability: string | null = null;
  try {
    capability = consumeCapability();
    const inspection = await requestJson("/v1/access-invitations/inspect", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ access_invitation_token: capability }),
    });
    const inspected = parseAccessInvitationPreview(inspection.value);
    if (inspection.etag !== inspected.entity_tag) throw new TypeError("INVITATION_PREVIEW_ETAG_MISMATCH");
    let sessionCsrf: string | null = null;
    try {
      sessionCsrf = parseSessionBootstrap((await requestJson("/v1/auth/session")).value).csrf_token;
    } catch (caught) {
      if (caught instanceof JoinApiError && caught.status === 401) {
        sessionCsrf = null;
      } else {
        throw caught;
      }
    }
    const context = {
      version: 1 as const,
      saved_at: new Date().toISOString(),
      invitation: inspected,
    };
    sessionStorage.setItem(PENDING_INVITATION_CONTEXT_KEY, serializePendingInvitationContext(context));
    const authorization = await requestJson(
      "/v1/auth/oidc/authorizations",
      createInvitationAuthorizationInit(capability, sessionCsrf),
    );
    return { phase: "REDIRECTING", preview: inspected, target: safeAuthorizationUrl(authorization.value), errorCode: null };
  } catch (caught) {
    sessionStorage.removeItem(PENDING_INVITATION_CONTEXT_KEY);
    const code = caught instanceof Error ? caught.message : "JOIN_REQUEST_FAILED";
    return {
      phase: code === "ACCESS_INVITATION_FRAGMENT_INVALID" ? "INVALID" : "UNAVAILABLE",
      preview: null,
      target: null,
      errorCode: code,
    };
  } finally {
    capability = null;
  }
}

export function JoinClient() {
  const coordinatorRef = useRef<ReturnType<typeof createJoinFlowCoordinator<JoinOutcome>> | null>(null);
  if (coordinatorRef.current === null) coordinatorRef.current = createJoinFlowCoordinator(runJoinFlow);
  const generationRef = useRef(0);
  const [phase, setPhase] = useState<"LOADING" | "REDIRECTING" | "INVALID" | "UNAVAILABLE">("LOADING");
  const [preview, setPreview] = useState<AccessInvitationPreview | null>(null);
  const [errorCode, setErrorCode] = useState<string | null>(null);

  useLayoutEffect(() => {
    const generation = ++generationRef.current;
    let active = true;
    void coordinatorRef.current?.start().then((outcome) => {
      if (!active || generationRef.current !== generation) return;
      setPreview(outcome.preview);
      setErrorCode(outcome.errorCode);
      setPhase(outcome.phase);
      if (outcome.phase === "REDIRECTING" && outcome.target !== null) window.location.assign(outcome.target);
    });
    return () => { active = false; };
  }, []);

  return (
    <main className="join-page" aria-live="polite">
      <section className="join-card">
        <div className="brand brand--large"><span>愿</span><strong>愿作</strong></div>
        <p className="eyebrow">ORGANIZATION INVITATION · MEMORY ONLY</p>
        <h1>加入组织工作区</h1>
        {preview && <dl className="join-preview">
          <div><dt>组织</dt><dd>{preview.organization?.public_name ?? "不可用"}</dd></div>
          <div><dt>受邀职责</dt><dd><code>{preview.target_role}</code></dd></div>
          <div><dt>邀请有效期</dt><dd>{new Date(preview.expires_at).toLocaleString("zh-CN")}</dd></div>
        </dl>}
        {phase === "LOADING" && <p>正在检查邀请并确认当前会话；地址栏中的能力片段已在页面脚本第一拍清除。</p>}
        {phase === "REDIRECTING" && <p>邀请摘要已安全保留，能力本身已从内存释放。正在前往身份提供方登录或创建受邀账号，并完成邀请绑定核验…</p>}
        {phase === "INVALID" && <div className="error-panel" role="alert">
          <strong>邀请链接无效</strong>
          <span>请让组织管理员重新签发；不要把能力放在查询参数、表单或聊天记录中。</span>
        </div>}
        {phase === "UNAVAILABLE" && <div className="error-panel" role="alert">
          <strong>邀请暂时无法核对：{errorCode}</strong>
          <span>页面没有把失败当作成功，也没有保存邀请能力。请从原始邀请链接重新开始。</span>
        </div>}
      </section>
    </main>
  );
}
