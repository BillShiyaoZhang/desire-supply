"use client";

import { FormEvent, useEffect, useRef, useState } from "react";
import {
  type AccessInvitationAcceptance,
  type PendingInvitationAcceptance,
  type PendingInvitationContext,
  type PolicyBundle,
  type SessionBootstrap,
  type WriteIntent,
  createAcceptOrganizationInvitationIntent,
  parseAccessInvitationAcceptance,
  parsePendingInvitationAcceptance,
  parsePolicyBundle,
  serializePendingInvitationAcceptance,
  verifyPolicyBundleDocuments,
} from "../lib/app-contract.mjs";
import {
  PENDING_INVITATION_ACCEPTANCE_KEY,
  PENDING_INVITATION_CONTEXT_KEY,
} from "../lib/invitation-flow.mjs";

class InvitationApiError extends Error {
  constructor(
    public status: number,
    public code: string,
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
    response = await fetch(path, { ...init, cache: "no-store", credentials: "same-origin", headers });
  } catch {
    throw new InvitationApiError(0, "NETWORK_OUTCOME_UNKNOWN", null, null);
  }
  const value: unknown = await response.json().catch(() => null);
  if (!response.ok) {
    const top = value && typeof value === "object" ? value as Record<string, unknown> : {};
    const nested = top.error && typeof top.error === "object" ? top.error as Record<string, unknown> : {};
    const code = typeof nested.code === "string" ? nested.code : typeof top.code === "string" ? top.code : "INVITATION_ACCEPTANCE_FAILED";
    throw new InvitationApiError(response.status, code, response.headers.get("etag"), response.headers.get("x-trace-id"));
  }
  return { value, etag: response.headers.get("etag") };
}

function newIdempotencyKey() {
  return `invitation-accept-${crypto.randomUUID()}`;
}

function invitationName(context: PendingInvitationContext) {
  return "organization" in context.invitation
    ? context.invitation.organization?.public_name ?? "组织工作区"
    : "组织工作区";
}

export function InvitationAcceptance({
  context,
  session,
  onAccepted,
  onCancel,
}: {
  context: PendingInvitationContext;
  session: SessionBootstrap;
  onAccepted: (acceptance: AccessInvitationAcceptance) => Promise<void> | void;
  onCancel: () => Promise<void> | void;
}) {
  const [bundle, setBundle] = useState<PolicyBundle | null>(null);
  const [affirmedDocumentIds, setAffirmedDocumentIds] = useState<string[]>([]);
  const [grantedOfferIds, setGrantedOfferIds] = useState<string[]>([]);
  const [pending, setPending] = useState<PendingInvitationAcceptance | null>(null);
  const pendingRef = useRef<PendingInvitationAcceptance | null>(null);
  const [busy, setBusy] = useState(true);
  const [notice, setNotice] = useState("正在读取邀请绑定的不可变政策包。");
  const [error, setError] = useState<{ code: string; traceId: string | null } | null>(null);
  const [restartRequired, setRestartRequired] = useState(false);

  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      setBusy(true);
      setError(null);
      try {
        const response = await requestJson(`/v1/policy-bundles/${encodeURIComponent(context.invitation.required_policy_bundle_id)}`);
        const exactBundle = await verifyPolicyBundleDocuments(parsePolicyBundle(response.value));
        if (
          exactBundle.policy_bundle_id !== context.invitation.required_policy_bundle_id
          || exactBundle.purpose !== "ORGANIZATION_MEMBERSHIP"
          || response.etag !== exactBundle.entity_tag
        ) throw new TypeError("POLICY_BUNDLE_BINDING_INVALID");
        const required = exactBundle.documents.filter((document) => document.legal_effect !== "CONSENT_TEXT");
        if (required.length === 0) throw new TypeError("POLICY_BUNDLE_BINDING_INVALID");
        if (cancelled) return;
        setBundle(exactBundle);
        const recovered = parsePendingInvitationAcceptance(
          sessionStorage.getItem(PENDING_INVITATION_ACCEPTANCE_KEY) ?? "",
          Date.now(),
        );
        const validRecovered = recovered
          && recovered.invitation_id === context.invitation.invitation_id
          && recovered.intent.headers["if-match"] === context.invitation.entity_tag
          && recovered.intent.body.policy_bundle_id === exactBundle.policy_bundle_id
          ? recovered
          : null;
        pendingRef.current = validRecovered;
        setPending(validRecovered);
        if (!validRecovered) sessionStorage.removeItem(PENDING_INVITATION_ACCEPTANCE_KEY);
        setNotice(validRecovered
          ? "发现一笔结果未知的邀请接受请求；只能原样重试或放弃后从原邀请链接重新开始。"
          : "请逐份确认全部必需政策；可选同意默认不勾选。确认前不会激活组织成员资格。");
      } catch (caught) {
        if (cancelled) return;
        setError({ code: caught instanceof Error ? caught.message : "POLICY_BUNDLE_UNAVAILABLE", traceId: null });
        setRestartRequired(true);
        setNotice("政策包未能通过完整性和邀请绑定核对；接受操作保持关闭。");
      } finally {
        if (!cancelled) setBusy(false);
      }
    };
    void load();
    return () => { cancelled = true; };
  }, [context]);

  function persistPending(value: PendingInvitationAcceptance | null) {
    pendingRef.current = value;
    setPending(value);
    if (value) sessionStorage.setItem(PENDING_INVITATION_ACCEPTANCE_KEY, serializePendingInvitationAcceptance(value));
    else sessionStorage.removeItem(PENDING_INVITATION_ACCEPTANCE_KEY);
  }

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (!bundle || restartRequired) return;
    let record = pendingRef.current;
    try {
      if (!record) {
        const intent = createAcceptOrganizationInvitationIntent({
          invitation: context.invitation,
          bundle,
          affirmedDocumentIds,
          grantedConsentOfferIds: grantedOfferIds,
          csrfToken: session.csrf_token,
          idempotencyKey: newIdempotencyKey(),
        });
        record = {
          version: 1,
          saved_at: new Date().toISOString(),
          invitation_id: context.invitation.invitation_id,
          intent,
        };
        persistPending(record);
      }
    } catch (caught) {
      setError({ code: caught instanceof Error ? caught.message : "POLICY_AFFIRMATION_REQUIRED", traceId: null });
      return;
    }
    setBusy(true);
    setError(null);
    setNotice("正在提交邀请接受命令；服务端结果明确前不会生成另一枚幂等键。");
    try {
      const intent: WriteIntent = record.intent;
      const response = await requestJson(intent.path, {
        method: intent.method,
        headers: intent.headers,
        body: JSON.stringify(intent.body),
      });
      const acceptance = parseAccessInvitationAcceptance(response.value);
      if (
        acceptance.invitation.invitation_id !== context.invitation.invitation_id
        || response.etag !== acceptance.invitation.entity_tag
      ) throw new TypeError("INVALID_INVITATION_ACCEPTANCE_RESPONSE");
      persistPending(null);
      sessionStorage.removeItem(PENDING_INVITATION_CONTEXT_KEY);
      setNotice("成员资格已由服务端激活；正在用轮换后的 Session 与 CSRF 重新读取权限。");
      await onAccepted(acceptance);
    } catch (caught) {
      const failure = caught instanceof InvitationApiError
        ? caught
        : new InvitationApiError(503, caught instanceof Error ? caught.message : "INVALID_INVITATION_ACCEPTANCE_RESPONSE", null, null);
      const outcomeUnknown = failure.status === 0 || failure.status >= 500;
      if (!outcomeUnknown) persistPending(null);
      const mustRestart = new Set([
        "MFA_STEP_UP_REQUIRED", "PRECONDITION_FAILED", "POLICY_ACCEPTANCE_REQUIRED",
        "ACCESS_INVITATION_NOT_ISSUED", "ACCESS_INVITATION_EXPIRED", "RESOURCE_NOT_FOUND",
        "AUTHENTICATION_REQUIRED", "SESSION_EXPIRED",
      ]).has(failure.code) || failure.status === 401 || failure.status === 412;
      if (mustRestart) {
        sessionStorage.removeItem(PENDING_INVITATION_CONTEXT_KEY);
        setRestartRequired(true);
      }
      setError({ code: failure.code, traceId: failure.traceId });
      setNotice(outcomeUnknown
        ? "接受结果未知。页面保留了完全相同且不含邀请能力的请求，只能原样重试。"
        : mustRestart
          ? "邀请绑定、再认证或政策版本已失效。不能用通用 STEP_UP 绕过；请重新打开原邀请链接。"
          : "服务端明确拒绝了接受请求；成员资格未被当作已激活。");
    } finally {
      setBusy(false);
    }
  }

  const requiredDocuments = bundle?.documents.filter((document) => document.legal_effect !== "CONSENT_TEXT") ?? [];
  const allAffirmed = requiredDocuments.length > 0 && requiredDocuments.every((document) => affirmedDocumentIds.includes(document.document_id));

  return (
    <main className="invitation-acceptance-page" aria-live="polite">
      <header className="policy-intro">
        <div className="brand brand--large"><span>愿</span><strong>愿作</strong></div>
        <p className="eyebrow">TOKEN-BOUND STEP_UP · EXACT POLICY SET</p>
        <h1>接受 {invitationName(context)} 邀请</h1>
        <p>邀请能力已经从浏览器内存释放；本页只使用服务端返回的安全邀请摘要、当前 Session 和不可变政策正文。</p>
      </header>
      <section className="policy-authority" aria-label="邀请服务端摘要">
        <div><span>受邀职责</span><strong>{context.invitation.target_role}</strong></div>
        <div><span>邀请状态</span><strong>{context.invitation.status}</strong></div>
        <div><span>有效期</span><strong>{new Date(context.invitation.expires_at).toLocaleString("zh-CN")}</strong></div>
        <div><span>邀请版本</span><code>{context.invitation.entity_tag}</code></div>
        <div className="policy-authority__wide"><span>邀请 ID</span><code>{context.invitation.invitation_id}</code></div>
        <div className="policy-authority__wide"><span>必需政策包</span><code>{context.invitation.required_policy_bundle_id}</code></div>
      </section>
      <div className="live-notice"><strong>状态</strong><span>{notice}</span></div>
      {error && <div className="error-panel" role="alert">
        <strong>邀请接受未完成：{error.code}</strong>
        {error.traceId && <small>追踪编号：<code>{error.traceId}</code></small>}
      </div>}
      {restartRequired ? <section className="join-guidance" role="status">
        <h2>请重新打开原邀请链接</h2>
        <p>本页不会保存能力，也不会用通用再认证替代邀请绑定的 STEP_UP。若原链接不可用，请让组织管理员撤销后重新签发。</p>
        <button className="quiet-button" type="button" onClick={() => void onCancel()}>返回工作台</button>
      </section> : bundle && <form className="policy-form" onSubmit={submit}>
        <div className="policy-documents">
          {requiredDocuments.map((document, index) => <article className="policy-document policy-document--required" key={document.document_id}>
            <header><div><p className="eyebrow">必需政策 {index + 1} · {document.kind}</p><h2>{document.legal_effect}</h2></div><span className="status">v{document.semantic_version}</span></header>
            <dl>
              <div><dt>文档 ID</dt><dd><code>{document.document_id}</code></dd></div>
              <div className="policy-document__digest"><dt>内容 SHA-256</dt><dd><code>{document.content_sha256}</code></dd></div>
            </dl>
            <pre className="policy-body">{document.body}</pre>
            <label className="policy-affirmation" htmlFor={`invitation-policy-${index}`}>
              <input
                aria-label={`明确接受政策文档 ${document.document_id}`}
                checked={affirmedDocumentIds.includes(document.document_id)}
                disabled={busy || pending !== null}
                id={`invitation-policy-${index}`}
                type="checkbox"
                onChange={(event) => setAffirmedDocumentIds((current) => event.target.checked
                  ? [...current.filter((id) => id !== document.document_id), document.document_id]
                  : current.filter((id) => id !== document.document_id))}
              />
              <span><strong>我已阅读并明确接受这份完整正文</strong><small>提交绑定文档 ID 与上方摘要。</small></span>
            </label>
          </article>)}
        </div>
        {bundle.consent_offers.length > 0 && <section className="consent-offers" aria-labelledby="optional-consent-title">
          <p className="eyebrow">OPTIONAL · DEFAULT OFF</p>
          <h2 id="optional-consent-title">可选同意</h2>
          <p>以下选项不是加入组织的必要条件，默认均不授权。</p>
          {bundle.consent_offers.map((offer, index) => <label className="policy-affirmation" htmlFor={`invitation-consent-${index}`} key={offer.consent_offer_id}>
            <input
              aria-label={`可选同意 ${offer.purpose}`}
              checked={grantedOfferIds.includes(offer.consent_offer_id)}
              disabled={busy || pending !== null}
              id={`invitation-consent-${index}`}
              type="checkbox"
              onChange={(event) => setGrantedOfferIds((current) => event.target.checked
                ? [...current.filter((id) => id !== offer.consent_offer_id), offer.consent_offer_id]
                : current.filter((id) => id !== offer.consent_offer_id))}
            />
            <span><strong>{offer.purpose}</strong><small>{offer.recipient_label} · {offer.data_categories.join("、")} · 有效期至 {new Date(offer.not_after).toLocaleString("zh-CN")}</small></span>
          </label>)}
        </section>}
        <footer className="policy-actions">
          <div><strong>{allAffirmed ? "全部必需政策已明确确认" : "请逐份确认全部必需政策"}</strong><small>接受写入绑定邀请 {context.invitation.entity_tag}、当前 CSRF 和独立幂等键。</small></div>
          <button className="primary-button" disabled={busy || (!pending && !allAffirmed)} type="submit">
            {busy ? "处理中…" : pending ? "原样重试接受请求" : "接受邀请并重新读取权限"}
          </button>
          {!pending && <button className="quiet-button" disabled={busy} type="button" onClick={() => void onCancel()}>暂不接受并返回</button>}
        </footer>
      </form>}
    </main>
  );
}
