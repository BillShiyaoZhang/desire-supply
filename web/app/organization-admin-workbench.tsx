"use client";

import { FormEvent, useCallback, useEffect, useRef, useState } from "react";
import {
  type AccessInvitationAdmin,
  type IssueOrganizationInvitationResponse,
  type MeProjection,
  type MembershipAdmin,
  type OrganizationSummary,
  type PendingOrganizationAdminWrite,
  type SessionBootstrap,
  type WorkspaceCandidate,
  ORGANIZATION_ADMIN_REASON_CODES,
  createIssueOrganizationInvitationIntent,
  createOrganizationLifecycleIntent,
  createUpdateOrganizationPublicNameIntent,
  parseAccessInvitationPage,
  parseIssueOrganizationInvitationResponse,
  parseMembershipPage,
  parseOrganizationSummary,
  parsePendingOrganizationAdminWrite,
  serializePendingOrganizationAdminWrite,
} from "../lib/app-contract.mjs";
import { createTokenlessStepUpBody, parseIdentityAuthorizationUrl } from "../lib/invitation-flow.mjs";
import {
  defaultOrganizationInvitationExpiry,
  organizationInvitationExpiryToIso,
} from "../lib/organization-invitation-time.mjs";

const PENDING_ORGANIZATION_ADMIN_KEY = "desire-pilot-org-admin-pending:v1";

class OrganizationApiError extends Error {
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
    throw new OrganizationApiError(0, "NETWORK_OUTCOME_UNKNOWN", null, null);
  }
  const value: unknown = await response.json().catch(() => null);
  if (!response.ok) {
    const top = value && typeof value === "object" ? value as Record<string, unknown> : {};
    const nested = top.error && typeof top.error === "object" ? top.error as Record<string, unknown> : {};
    const code = typeof nested.code === "string" ? nested.code : typeof top.code === "string" ? top.code : "ORGANIZATION_REQUEST_FAILED";
    throw new OrganizationApiError(response.status, code, response.headers.get("etag"), response.headers.get("x-trace-id"));
  }
  return { value, etag: response.headers.get("etag") };
}

function newIdempotencyKey() {
  return `org-admin-${crypto.randomUUID()}`;
}

function formatTime(value: string) {
  return new Intl.DateTimeFormat("zh-CN", { dateStyle: "medium", timeStyle: "short" }).format(new Date(value));
}

function organizationPublicNameIssue(value: string) {
  if ([...value].length === 0) return "公开名称不能为空。";
  if ([...value].length > 160) return "公开名称不能超过 160 个 Unicode 码点。";
  if (value.trim() !== value) return "公开名称首尾不能包含空白。";
  if (value.normalize("NFC") !== value) return "公开名称必须使用 NFC 规范文本。";
  if (/[\p{Cc}\p{Cf}]/u.test(value)) return "公开名称不能包含控制或格式字符。";
  return null;
}

function pendingTargetsSnapshot(
  record: PendingOrganizationAdminWrite,
  organizationId: string,
  invitations: AccessInvitationAdmin[],
  memberships: MembershipAdmin[],
) {
  if (record.operation === "ISSUE_INVITATION" || record.operation === "UPDATE_PUBLIC_NAME") {
    return record.target_id === organizationId;
  }
  if (record.operation === "REVOKE_INVITATION") {
    return invitations.some((invitation) => invitation.invitation_id === record.target_id);
  }
  return memberships.some((membership) => membership.membership_id === record.target_id);
}

function safeAuthorizationUrl(value: unknown) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new TypeError("INVALID_AUTHORIZATION_RESPONSE");
  const record = value as Record<string, unknown>;
  if (
    Object.keys(record).length !== 3
    || typeof record.auth_transaction_id !== "string"
    || !/^[A-Za-z0-9][A-Za-z0-9_-]{15,127}$/.test(record.auth_transaction_id)
    || typeof record.authorization_url !== "string"
    || typeof record.expires_at !== "string"
    || !Number.isFinite(Date.parse(record.expires_at))
  ) throw new TypeError("INVALID_AUTHORIZATION_RESPONSE");
  return parseIdentityAuthorizationUrl(record.authorization_url);
}

async function readAllPages<T>(
  path: string,
  parser: (value: unknown) => { items: T[]; page: { next_cursor: string | null } },
) {
  const items: T[] = [];
  const seen = new Set<string>();
  let cursor: string | null = null;
  for (let pageNumber = 0; pageNumber < 20; pageNumber += 1) {
    const query = new URLSearchParams({ limit: "100" });
    if (cursor !== null) query.set("cursor", cursor);
    const page = parser((await requestJson(`${path}?${query.toString()}`)).value);
    items.push(...page.items);
    if (page.page.next_cursor === null) return items;
    if (seen.has(page.page.next_cursor)) throw new TypeError("PAGINATION_CURSOR_LOOP");
    seen.add(page.page.next_cursor);
    cursor = page.page.next_cursor;
  }
  throw new TypeError("PAGINATION_LIMIT_EXCEEDED");
}

export function OrganizationAdminWorkbench({
  session,
  me,
  workspace,
  writeLocked,
  claimWrite,
  releaseWrite,
  onDirtyChange,
}: {
  session: SessionBootstrap;
  me: MeProjection;
  workspace: WorkspaceCandidate;
  writeLocked: boolean;
  claimWrite: (record: PendingOrganizationAdminWrite) => boolean;
  releaseWrite: () => void;
  onDirtyChange: (dirty: boolean) => void;
}) {
  const organizationId = workspace.workspace_id.startsWith("org:") ? workspace.workspace_id.slice(4) : "";
  const [organization, setOrganization] = useState<OrganizationSummary | null>(null);
  const [invitations, setInvitations] = useState<AccessInvitationAdmin[]>([]);
  const [memberships, setMemberships] = useState<MembershipAdmin[]>([]);
  const [issued, setIssued] = useState<IssueOrganizationInvitationResponse | null>(null);
  const [pending, setPending] = useState<PendingOrganizationAdminWrite | null>(null);
  const pendingRef = useRef<PendingOrganizationAdminWrite | null>(null);
  const [pendingScopeInvalid, setPendingScopeInvalid] = useState(false);
  const [busy, setBusy] = useState(true);
  const [projectionReady, setProjectionReady] = useState(false);
  const [stepUpRequired, setStepUpRequired] = useState(false);
  const [notice, setNotice] = useState("正在读取组织、成员资格和邀请的服务端投影。");
  const [error, setError] = useState<{ code: string; traceId: string | null } | null>(null);
  const [recipientEmail, setRecipientEmail] = useState("");
  const [targetRole, setTargetRole] = useState<"ORG_ADMIN" | "DEMAND_OWNER">("DEMAND_OWNER");
  const [reasonCode, setReasonCode] = useState<(typeof ORGANIZATION_ADMIN_REASON_CODES)[number]>("ACCESS_REVIEW");
  const [expiresAt, setExpiresAt] = useState(() => defaultOrganizationInvitationExpiry());
  const [publicNameDraft, setPublicNameDraft] = useState("");
  const [publicNameConfirmed, setPublicNameConfirmed] = useState(false);
  const [discardRefreshRequested, setDiscardRefreshRequested] = useState(false);
  const [publicNameConflict, setPublicNameConflict] = useState<{ current: string; attempted: string } | null>(null);
  const publicNameDirty = organization !== null && publicNameDraft !== organization.public_name;
  const publicNameIssue = organizationPublicNameIssue(publicNameDraft);

  const refresh = useCallback(async (options: { preservePublicNameDraft?: string } = {}) => {
    if (!organizationId || workspace.workspace_kind !== "ORGANIZATION" || !workspace.role_codes.includes("ORG_ADMIN")) {
      throw new TypeError("ORG_ADMIN_WORKSPACE_REQUIRED");
    }
    setBusy(true);
    setProjectionReady(false);
    setError(null);
    try {
      const [organizationResponse, invitationItems, membershipItems] = await Promise.all([
        requestJson(`/v1/organizations/${organizationId}`),
        readAllPages(`/v1/organizations/${organizationId}/access-invitations`, parseAccessInvitationPage),
        readAllPages(`/v1/organizations/${organizationId}/memberships`, parseMembershipPage),
      ]);
      const exactOrganization = parseOrganizationSummary(organizationResponse.value);
      if (
        exactOrganization.organization_id !== organizationId
        || organizationResponse.etag !== exactOrganization.entity_tag
        || invitationItems.some((item) => item.organization_id !== organizationId)
        || membershipItems.some((item) => item.organization_id !== organizationId)
      ) throw new TypeError("ORGANIZATION_PROJECTION_BINDING_INVALID");
      setOrganization(exactOrganization);
      setInvitations(invitationItems);
      setMemberships(membershipItems);
      setPublicNameDraft(options.preservePublicNameDraft ?? exactOrganization.public_name);
      setPublicNameConfirmed(false);
      setDiscardRefreshRequested(false);
      setPublicNameConflict(null);
      const recovered = parsePendingOrganizationAdminWrite(
        sessionStorage.getItem(PENDING_ORGANIZATION_ADMIN_KEY) ?? "",
        Date.now(),
      );
      const claimed = recovered ? claimWrite(recovered) : false;
      pendingRef.current = recovered;
      setPending(recovered);
      const scopeInvalid = Boolean(
        recovered
        && !pendingTargetsSnapshot(recovered, organizationId, invitationItems, membershipItems)
      );
      setPendingScopeInvalid(scopeInvalid);
      if (!recovered) sessionStorage.removeItem(PENDING_ORGANIZATION_ADMIN_KEY);
      if (recovered && !claimed) {
        setError({ code: "WRITE_OUTCOME_PENDING", traceId: null });
        setNotice("另一笔浏览器写入正在占用单一在途门闩；组织恢复请求没有覆盖它，也不会发送。");
        setProjectionReady(true);
        return exactOrganization;
      }
      if (scopeInvalid) {
        setError({ code: "ORGANIZATION_WRITE_RECOVERY_SCOPE_MISMATCH", traceId: null });
        setNotice("恢复对象不属于当前完整组织投影；页面已占住写入门闩且不会重放，只能明确放弃后继续。");
        setProjectionReady(true);
        return exactOrganization;
      }
      if (recovered?.operation === "UPDATE_PUBLIC_NAME") {
        setPublicNameDraft(String(recovered.intent.body.public_name));
      }
      setStepUpRequired(false);
      setNotice(recovered
        ? "发现一笔尚未确认结果的组织写入；可原样重试，不能生成替代请求。"
        : "组织管理投影已重新读取。按钮状态仍会由服务端在写入时再次授权。");
      setProjectionReady(true);
      return exactOrganization;
    } catch (caught) {
      const failure = caught instanceof OrganizationApiError
        ? caught
        : new OrganizationApiError(503, caught instanceof Error ? caught.message : "ORGANIZATION_PROJECTION_UNAVAILABLE", null, null);
      setError({ code: failure.code, traceId: failure.traceId });
      setNotice("组织管理投影未能完整核对；页面不会用工作区角色或浏览器缓存补造事实。");
      return null;
    } finally {
      setBusy(false);
    }
  }, [claimWrite, organizationId, workspace]);

  useEffect(() => {
    const timer = window.setTimeout(() => void refresh(), 0);
    return () => window.clearTimeout(timer);
  }, [refresh]);

  useEffect(() => {
    onDirtyChange(publicNameDirty);
  }, [onDirtyChange, publicNameDirty]);

  useEffect(() => () => onDirtyChange(false), [onDirtyChange]);

  function persistPending(value: PendingOrganizationAdminWrite | null) {
    pendingRef.current = value;
    setPending(value);
    if (value === null) setPendingScopeInvalid(false);
    if (value) sessionStorage.setItem(PENDING_ORGANIZATION_ADMIN_KEY, serializePendingOrganizationAdminWrite(value));
    else {
      sessionStorage.removeItem(PENDING_ORGANIZATION_ADMIN_KEY);
      releaseWrite();
    }
  }

  async function perform(record: PendingOrganizationAdminWrite) {
    if (
      !organization
      || !projectionReady
      || !pendingTargetsSnapshot(record, organizationId, invitations, memberships)
    ) {
      setError({ code: "ORGANIZATION_WRITE_RECOVERY_SCOPE_MISMATCH", traceId: null });
      setNotice("当前命令不能绑定到刚刚读取的完整组织投影，因此没有发送。");
      return;
    }
    if (issued) {
      setError({ code: "INVITATION_CAPABILITY_DELIVERY_PENDING", traceId: null });
      setNotice("一次性加入链接仍在当前页面内存中；请先安全交付并明确关闭，再执行其他组织写入。");
      return;
    }
    if (record.operation !== "UPDATE_PUBLIC_NAME" && publicNameDirty) {
      setError({ code: "UNSAVED_ORGANIZATION_PUBLIC_NAME", traceId: null });
      setNotice("请先更新或放弃公开名称草稿，再执行其他组织管理命令。");
      return;
    }
    if (!claimWrite(record)) {
      setError({ code: "WRITE_OUTCOME_PENDING", traceId: null });
      setNotice("已有另一笔结果未知的写入；组织命令没有发送，也没有覆盖原恢复对象。");
      return;
    }
    persistPending(record);
    setBusy(true);
    setError(null);
    setStepUpRequired(false);
    setNotice("正在提交 ETag、CSRF 与幂等键绑定的组织管理命令。");
    let issuedResult: IssueOrganizationInvitationResponse | null = null;
    let updatedOrganization: OrganizationSummary | null = null;
    try {
      const response = await requestJson(record.intent.path, {
        method: record.intent.method,
        headers: record.intent.headers,
        body: JSON.stringify(record.intent.body),
      });
      if (record.operation === "ISSUE_INVITATION") {
        const result = parseIssueOrganizationInvitationResponse(response.value);
        if (response.etag !== result.invitation.entity_tag) throw new TypeError("INVALID_INVITATION_ISSUE_RESPONSE");
        issuedResult = result;
      } else if (record.operation === "UPDATE_PUBLIC_NAME") {
        const result = parseOrganizationSummary(response.value);
        if (
          response.etag !== result.entity_tag
          || result.organization_id !== organizationId
          || result.public_name !== record.intent.body.public_name
        ) throw new TypeError("INVALID_ORGANIZATION_PUBLIC_NAME_RESPONSE");
        updatedOrganization = result;
      } else if (record.operation === "REVOKE_INVITATION") {
        const result = parseAccessInvitationPage({ items: [response.value], page: { next_cursor: null } }).items[0];
        if (response.etag !== result.entity_tag) throw new TypeError("INVALID_INVITATION_LIFECYCLE_RESPONSE");
      } else {
        const result = parseMembershipPage({ items: [response.value], page: { next_cursor: null } }).items[0];
        if (response.etag !== result.entity_tag) throw new TypeError("INVALID_MEMBERSHIP_LIFECYCLE_RESPONSE");
      }
      persistPending(null);
      if (updatedOrganization) {
        setOrganization(updatedOrganization);
        setPublicNameDraft(updatedOrganization.public_name);
        setPublicNameConfirmed(false);
        setPublicNameConflict(null);
      }
      const refreshed = await refresh();
      if (record.operation === "ISSUE_INVITATION") {
        setIssued(issuedResult);
        setNotice(refreshed
          ? "邀请已签发。一次性加入链接只保留在当前页面内存中；请立即安全复制，刷新后无法恢复。"
          : "邀请已明确签发且一次性链接仍可复制，但后续组织投影刷新失败；请先安全交付链接，再手工刷新。");
      } else if (record.operation === "UPDATE_PUBLIC_NAME") {
        const stillCurrent = Boolean(
          refreshed
          && updatedOrganization
          && refreshed.entity_tag === updatedOrganization.entity_tag
          && refreshed.public_name === updatedOrganization.public_name
        );
        setNotice(!refreshed
          ? "公开名称更新已明确成功，但后续组织投影刷新失败；不要重试已确认命令，请手工刷新。"
          : stillCurrent
            ? "组织公开名称已更新，并已用 fresh GET 重新绑定当前 ETag。现有未接受邀请的匿名预览会读取此公开名称。"
            : "公开名称更新已明确成功；fresh GET 显示组织随后又有变化，请核对当前服务端名称与 ETag。");
      } else {
        setNotice(refreshed
          ? "组织管理命令已明确成功，并已重新读取当前服务端投影。"
          : "组织管理命令已明确成功，但后续投影刷新失败；不要原样重试已确认命令，请手工刷新。");
      }
    } catch (caught) {
      const failure = caught instanceof OrganizationApiError
        ? caught
        : new OrganizationApiError(503, caught instanceof Error ? caught.message : "INVALID_ORGANIZATION_RESPONSE", null, null);
      const outcomeUnknown = failure.status === 0 || failure.status >= 500;
      const preconditionFailed = failure.status === 412 || failure.code === "PRECONDITION_FAILED";
      const attemptedPublicName = record.operation === "UPDATE_PUBLIC_NAME"
        ? String(record.intent.body.public_name)
        : null;
      if (preconditionFailed) {
        persistPending(null);
        setPublicNameConfirmed(false);
        const refreshed = await refresh(attemptedPublicName === null
          ? {}
          : { preservePublicNameDraft: attemptedPublicName });
        if (
          attemptedPublicName !== null
          && refreshed
          && attemptedPublicName !== refreshed.public_name
        ) {
          setPublicNameConflict({ current: refreshed.public_name, attempted: attemptedPublicName });
        }
        setError({ code: failure.code, traceId: failure.traceId });
        setNotice(!refreshed
          ? "对象版本已经变化；旧写入已清除，但 fresh GET 失败。页面不会重放旧 ETag，待恢复投影后再操作。"
          : attemptedPublicName !== null && attemptedPublicName === refreshed.public_name
            ? "旧写入因版本变化被拒绝并已清除；fresh GET 显示当前公开名称已等于提议值，无需重发。"
            : "对象版本已经变化；旧写入已清除。已保留名称草稿并读取当前 ETag，必须重新核对、重新确认后发起新命令。");
        return;
      }
      if (!outcomeUnknown && failure.code !== "MFA_STEP_UP_REQUIRED") persistPending(null);
      if (failure.code === "MFA_STEP_UP_REQUIRED") setStepUpRequired(true);
      if (!outcomeUnknown && record.operation === "UPDATE_PUBLIC_NAME") setPublicNameConfirmed(false);
      setError({ code: failure.code, traceId: failure.traceId });
      setNotice(outcomeUnknown
        ? "写入结果未知；已保留完全相同且不含邀请能力的请求，可原样重试。"
        : failure.code === "MFA_STEP_UP_REQUIRED"
          ? "服务端要求同账号最近多因素再认证。原写入已冻结；完成通用 STEP_UP 后再原样重试。"
          : "服务端明确拒绝命令；页面未把目标状态当作已改变。");
    } finally {
      setBusy(false);
    }
  }

  function updatePublicName(event: FormEvent) {
    event.preventDefault();
    if (
      !organization
      || !projectionReady
      || pendingRef.current
      || writeLocked
      || issued
    ) return;
    if (!publicNameDirty || publicNameIssue !== null || !publicNameConfirmed) {
      setError({ code: "ORGANIZATION_PUBLIC_NAME_CONFIRMATION_REQUIRED", traceId: null });
      setNotice("请先输入有效且不同的公开名称，并明确确认其匿名邀请预览影响。");
      return;
    }
    try {
      const intent = createUpdateOrganizationPublicNameIntent({
        organization,
        publicName: publicNameDraft,
        csrfToken: session.csrf_token,
        idempotencyKey: newIdempotencyKey(),
      });
      void perform({
        version: 1,
        saved_at: new Date().toISOString(),
        operation: "UPDATE_PUBLIC_NAME",
        target_id: organization.organization_id,
        intent,
      });
    } catch (caught) {
      setError({ code: caught instanceof Error ? caught.message : "INVALID_ORGANIZATION_PUBLIC_NAME", traceId: null });
    }
  }

  function discardPublicNameDraft() {
    if (!organization) return;
    setPublicNameDraft(organization.public_name);
    setPublicNameConfirmed(false);
    setPublicNameConflict(null);
    setDiscardRefreshRequested(false);
    setError(null);
    setNotice("已放弃当前标签页的公开名称草稿；服务端事实未被改写。");
  }

  function requestProjectionRefresh() {
    if (busy || pendingRef.current || writeLocked || issued) return;
    if (publicNameDirty) {
      setDiscardRefreshRequested(true);
      setNotice("刷新会放弃当前公开名称草稿；请在页面内明确选择放弃并刷新，或继续编辑。");
      return;
    }
    void refresh();
  }

  function discardPublicNameAndRefresh() {
    setPublicNameDraft("");
    setPublicNameConfirmed(false);
    setPublicNameConflict(null);
    setDiscardRefreshRequested(false);
    void refresh();
  }

  function issueInvitation(event: FormEvent) {
    event.preventDefault();
    if (!organization || !projectionReady || pendingRef.current || writeLocked || issued || publicNameDirty) return;
    try {
      const expiresAtIso = organizationInvitationExpiryToIso(expiresAt);
      const intent = createIssueOrganizationInvitationIntent({
        organization,
        recipientEmail,
        targetRole,
        expiresAt: expiresAtIso,
        csrfToken: session.csrf_token,
        idempotencyKey: newIdempotencyKey(),
      });
      void perform({
        version: 1,
        saved_at: new Date().toISOString(),
        operation: "ISSUE_INVITATION",
        target_id: organization.organization_id,
        intent,
      });
    } catch (caught) {
      setError({ code: caught instanceof Error ? caught.message : "INVALID_INVITATION_INPUT", traceId: null });
    }
  }

  function lifecycle(
    resource: AccessInvitationAdmin | MembershipAdmin,
    action: "REVOKE_INVITATION" | "SUSPEND_MEMBERSHIP" | "RESUME_MEMBERSHIP" | "REVOKE_MEMBERSHIP",
  ) {
    if (!projectionReady || pendingRef.current || writeLocked || issued || publicNameDirty) return;
    try {
      const intent = createOrganizationLifecycleIntent({
        resource,
        action,
        csrfToken: session.csrf_token,
        idempotencyKey: newIdempotencyKey(),
        reasonCode,
      });
      const operation = action;
      const targetId = "membership_id" in resource ? resource.membership_id : resource.invitation_id;
      void perform({ version: 1, saved_at: new Date().toISOString(), operation, target_id: targetId, intent });
    } catch (caught) {
      setError({ code: caught instanceof Error ? caught.message : "ORGANIZATION_ACTION_NOT_AVAILABLE", traceId: null });
    }
  }

  async function beginStepUp() {
    if (!pendingRef.current) return;
    setBusy(true);
    setError(null);
    try {
      const response = await requestJson("/v1/auth/oidc/authorizations", {
        method: "POST",
        headers: { "content-type": "application/json", "x-csrf-token": session.csrf_token },
        body: JSON.stringify(createTokenlessStepUpBody()),
      });
      window.location.assign(safeAuthorizationUrl(response.value));
    } catch (caught) {
      const failure = caught instanceof OrganizationApiError
        ? caught
        : new OrganizationApiError(503, caught instanceof Error ? caught.message : "STEP_UP_UNAVAILABLE", null, null);
      setError({ code: failure.code, traceId: failure.traceId });
      setNotice("无法建立同账号通用 STEP_UP；原写入仍被保留，但不会绕过再认证执行。");
      setBusy(false);
    }
  }

  async function copyJoinLink() {
    if (!issued) return;
    try {
      await navigator.clipboard.writeText(new URL(issued.join_fragment_url, window.location.origin).href);
      setNotice("一次性加入链接已复制。请通过批准的私密渠道交付；不要粘贴到日志、查询参数或工单正文。");
    } catch {
      setError({ code: "CLIPBOARD_UNAVAILABLE", traceId: null });
      setNotice("浏览器未允许剪贴板写入；请在当前页手工复制，刷新后链接无法恢复。");
    }
  }

  const activeAdminCount = memberships.filter((membership) => membership.status === "ACTIVE" && membership.roles.includes("ORG_ADMIN")).length;
  const commonWriteLocked = busy
    || pending !== null
    || writeLocked
    || !projectionReady
    || issued !== null;
  const organizationWriteLocked = commonWriteLocked || publicNameDirty;

  return (
    <section className="organization-admin-workbench" aria-labelledby="organization-admin-title">
      <header className="account-header">
        <div><p className="eyebrow">ORG_ADMIN · IAM AUTHORITY LIFECYCLE</p><h2 id="organization-admin-title">组织成员与邀请</h2><p>所有列表均来自 IAM；浏览器不提交组织、操作者或角色权限声明。</p></div>
        <button className="quiet-button" disabled={busy || pending !== null || writeLocked || issued !== null} type="button" onClick={requestProjectionRefresh}>刷新组织投影</button>
      </header>
      {organization && <dl className="account-facts">
        <div><dt>组织</dt><dd>{organization.public_name}</dd></div>
        <div><dt>类型</dt><dd><code>{organization.type}</code></dd></div>
        <div><dt>状态</dt><dd><code>{organization.status}</code></dd></div>
        <div><dt>版本</dt><dd><code>{organization.entity_tag}</code></dd></div>
      </dl>}
      <div className="live-notice" role="status" aria-live="polite" aria-atomic="true"><strong>组织管理状态</strong><span>{notice}</span></div>
      {error && <div className="error-panel" role="alert"><strong>操作未完成：{error.code}</strong>{error.traceId && <small>追踪编号：<code>{error.traceId}</code></small>}</div>}
      {discardRefreshRequested && <section className="organization-name-discard" role="group" aria-labelledby="organization-name-discard-title">
        <div><strong id="organization-name-discard-title">放弃公开名称草稿并刷新？</strong><span>刷新将采用服务端当前名称与 ETag；不会发送名称更新命令。</span></div>
        <div className="button-row">
          <button className="danger-button" disabled={busy} type="button" onClick={discardPublicNameAndRefresh}>放弃名称修改并刷新</button>
          <button className="quiet-button" disabled={busy} type="button" onClick={() => setDiscardRefreshRequested(false)}>继续编辑</button>
        </div>
      </section>}
      {pending && <section className="unknown-panel" aria-labelledby="org-pending-title">
        <div><p className="eyebrow">FROZEN WRITE INTENT</p><h3 id="org-pending-title">{pending.operation}</h3><p>正文、目标、ETag、CSRF 与幂等键已经冻结；恢复对象不含邀请能力。</p></div>
        <div className="recovery-actions">
          {pendingScopeInvalid
            ? <span role="alert">恢复对象与当前组织投影不匹配，已禁止重放。</span>
            : stepUpRequired
            ? <button className="primary-button" disabled={busy} type="button" onClick={() => void beginStepUp()}>同账号多因素再认证</button>
            : <button className="primary-button" disabled={busy} type="button" onClick={() => void perform(pending)}>原样重试</button>}
          <button className="quiet-button" disabled={busy} type="button" onClick={() => { persistPending(null); setStepUpRequired(false); setNotice("已放弃浏览器恢复对象；服务端事实未被改写。"); }}>放弃恢复</button>
        </div>
      </section>}
      {issued && <section className="issued-capability" role="status">
        <p className="eyebrow">ONE-TIME CAPABILITY · MEMORY ONLY</p>
        <h3>立即安全交付加入链接</h3>
        <p>这是唯一一次显示。它没有写入 localStorage、sessionStorage、Cookie、日志或查询参数。</p>
        <code>{new URL(issued.join_fragment_url, typeof window === "undefined" ? "https://invalid.local" : window.location.origin).href}</code>
        <div className="button-row">
          <button className="primary-button" type="button" onClick={() => void copyJoinLink()}>复制一次性加入链接</button>
          <button className="quiet-button" type="button" onClick={() => { setIssued(null); setNotice("已明确关闭当前页面内存中的一次性加入链接；它无法从列表或刷新中恢复。"); }}>已安全交付，关闭一次性链接</button>
        </div>
      </section>}
      {organization && <form className="organization-public-name-card" aria-labelledby="organization-public-name-title" onSubmit={updatePublicName}>
        <div className="section-heading compact-heading">
          <div><p className="eyebrow">ORG_ADMIN · PUBLIC PROJECTION</p><h3 id="organization-public-name-title">组织公开名称</h3></div>
          <span className={publicNameDirty ? "dirty-indicator" : "saved-indicator"}>{publicNameDirty ? "当前标签页有未提交修改" : "与已读取版本一致"}</span>
        </div>
        <p id="organization-public-name-description">此名称会显示在匿名邀请预览中。更新绑定当前组织 ETag，并要求同账号最近多因素再认证。</p>
        {publicNameConflict && <div className="organization-name-conflict" role="status" aria-live="polite">
          <strong>412 PRECONDITION FAILED · 请重新核对</strong>
          <span>服务端当前名称：{publicNameConflict.current}</span>
          <span>保留的名称草稿：{publicNameConflict.attempted}</span>
        </div>}
        <label htmlFor="organization-public-name">公开名称</label>
        <input
          aria-describedby="organization-public-name-description organization-public-name-issue"
          aria-invalid={publicNameDirty && publicNameIssue !== null}
          autoComplete="organization"
          disabled={commonWriteLocked}
          id="organization-public-name"
          maxLength={320}
          required
          type="text"
          value={publicNameDraft}
          onChange={(event) => {
            setPublicNameDraft(event.target.value);
            setPublicNameConfirmed(false);
            setPublicNameConflict(null);
            setDiscardRefreshRequested(false);
          }}
        />
        <small id="organization-public-name-issue" role={publicNameDirty && publicNameIssue ? "alert" : undefined}>
          {publicNameDirty && publicNameIssue ? publicNameIssue : "1–160 个 Unicode 码点；必须是 NFC 文本，首尾无空白且不含控制或格式字符。"}
        </small>
        <label className="organization-public-name-confirmation">
          <input
            checked={publicNameConfirmed}
            disabled={commonWriteLocked || !publicNameDirty || publicNameIssue !== null}
            type="checkbox"
            onChange={(event) => setPublicNameConfirmed(event.target.checked)}
          />
          我确认新公开名称会立即显示在现有未接受邀请的匿名预览中。
        </label>
        <div className="button-row">
          <button className="primary-button" disabled={commonWriteLocked || !publicNameDirty || publicNameIssue !== null || !publicNameConfirmed || organization.status !== "ACTIVE"} type="submit">更新组织公开名称</button>
          <button className="quiet-button" disabled={commonWriteLocked || !publicNameDirty} type="button" onClick={discardPublicNameDraft}>放弃本地名称修改</button>
        </div>
        <small>提交固定理由 <code>PUBLIC_NAME_CORRECTION</code>；浏览器不会提交操作者、组织权限或角色声明。</small>
      </form>}
      <div className="organization-admin-grid">
        <form className="starter-card" onSubmit={issueInvitation}>
          <p className="eyebrow">ISSUE · STEP_UP REQUIRED</p><h3>签发组织邀请</h3>
          <label>受邀邮箱<input required autoComplete="off" disabled={organizationWriteLocked} type="email" value={recipientEmail} onChange={(event) => setRecipientEmail(event.target.value)} placeholder="invited-user@example.org" /></label>
          <label>目标职责<select disabled={organizationWriteLocked} value={targetRole} onChange={(event) => setTargetRole(event.target.value as "ORG_ADMIN" | "DEMAND_OWNER")}><option value="DEMAND_OWNER">DEMAND_OWNER</option><option value="ORG_ADMIN">ORG_ADMIN</option></select></label>
          <label>邀请有效期<input required disabled={organizationWriteLocked} type="datetime-local" value={expiresAt} onChange={(event) => setExpiresAt(event.target.value)} /></label>
          <button className="primary-button" disabled={organizationWriteLocked || organization?.status !== "ACTIVE"} type="submit">签发一次性邀请</button>
        </form>
        <label className="organization-reason-field">成员与邀请生命周期理由<select disabled={organizationWriteLocked} value={reasonCode} onChange={(event) => setReasonCode(event.target.value as (typeof ORGANIZATION_ADMIN_REASON_CODES)[number])}>{ORGANIZATION_ADMIN_REASON_CODES.map((code) => <option key={code} value={code}>{code}</option>)}</select><small>理由来自封闭选项；浏览器不能提交自由权限声明。</small></label>
        <section className="organization-list" aria-labelledby="membership-list-title">
          <h3 id="membership-list-title">成员资格 <span>{memberships.length}</span></h3>
          {memberships.map((membership) => {
            const isSelf = membership.user_id === me.user_id;
            const lastAdmin = membership.status === "ACTIVE" && membership.roles.includes("ORG_ADMIN") && activeAdminCount <= 1;
            const locked = organizationWriteLocked || isSelf || lastAdmin;
            return <article key={membership.membership_id}>
              <div><strong>{membership.display_handle}{isSelf ? " · 当前账号" : ""}</strong><span className="status">{membership.status}</span></div>
              <p>{membership.roles.join(" · ")} · <code>{membership.entity_tag}</code></p>
              {(isSelf || lastAdmin) && <small>{isSelf ? "页面禁止对当前账号执行成员生命周期操作。" : "最后一名 ACTIVE ORG_ADMIN 不可暂停或撤销。"}</small>}
              <div className="account-actions">
                {membership.status === "ACTIVE" && <button className="danger-button" disabled={locked} type="button" onClick={() => lifecycle(membership, "SUSPEND_MEMBERSHIP")}>暂停</button>}
                {membership.status === "SUSPENDED" && <button className="primary-button" disabled={organizationWriteLocked || isSelf} type="button" onClick={() => lifecycle(membership, "RESUME_MEMBERSHIP")}>恢复</button>}
                {membership.status === "ACTIVE" && <button className="quiet-button" disabled={locked} type="button" onClick={() => lifecycle(membership, "REVOKE_MEMBERSHIP")}>撤销</button>}
              </div>
            </article>;
          })}
        </section>
        <section className="organization-list" aria-labelledby="invitation-list-title">
          <h3 id="invitation-list-title">已签发邀请 <span>{invitations.length}</span></h3>
          {invitations.map((invitation) => <article key={invitation.invitation_id}>
            <div><strong>{invitation.masked_recipient_label}</strong><span className="status">{invitation.status}</span></div>
            <p>{invitation.target_role} · 到期 {formatTime(invitation.expires_at)} · <code>{invitation.entity_tag}</code></p>
            {invitation.status === "ISSUED" && <button className="danger-button" disabled={organizationWriteLocked} type="button" onClick={() => lifecycle(invitation, "REVOKE_INVITATION")}>撤销邀请</button>}
          </article>)}
        </section>
      </div>
    </section>
  );
}
