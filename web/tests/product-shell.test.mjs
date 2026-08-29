import assert from "node:assert/strict";
import { access, readFile } from "node:fs/promises";
import test from "node:test";

const root = new URL("../", import.meta.url);

test("internal-pilot shell is capability-scoped, editable, recoverable, and accessible", async () => {
  const [client, css, layout] = await Promise.all([
    readFile(new URL("app/product-client.tsx", root), "utf8"),
    readFile(new URL("app/globals.css", root), "utf8"),
    readFile(new URL("app/layout.tsx", root), "utf8"),
  ]);
  for (const endpoint of ["/v1/auth/session", "/v1/auth/oidc/authorizations", "/v1/me", "/v1/policy-bundles", "/v1/me/policy-acceptances", "/v1/app/workspaces", "/v1/app/configuration", "/v1/app/profiles", "/v1/app/demands", "/v1/app/review-queue", "/v1/app/finance/funding-reviews", "/v1/app/admin/accounts"]) {
    assert.match(client, new RegExp(endpoint.replaceAll("/", "\\/")));
  }
  for (const phrase of ["受邀账号工作台", "首次登录政策确认", "政策正文", "法律效果", "内容 SHA-256", "我已阅读并明确接受", "服务端会话", "九个画像分区", "十三个需求分区", "保存草稿", "发布画像", "提交审核", "审核队列", "领取审核", "记录整改项", "验证通过", "预算健康", "风险结论", "资金确认队列", "领取资金确认", "零真实资金", "需要两名独立 Finance Operator", "NO_REAL_FUNDS_OR_PAYMENT", "本次确认所绑定的目标与证据", "计划预算范围", "它不是余额、到账、支付或可支配资金", "目标审计摘要", "证据引用审计摘要", "明确确认四项声明", "账号管理", "平台职责", "授予职责", "撤销职责", "暂停账号", "恢复账号", "撤销全部会话", "当前提交内容", "不可代替需求方修改", "版本历史", "INTERNAL_SANDBOX", "G1 NO-GO", "G2 NO-GO", "PRECONDITION FAILED", "原样重试"]) {
    assert.match(client, new RegExp(phrase));
  }
  assert.match(layout, /lang="zh-CN"/);
  assert.match(client, /skip-link/);
  assert.match(client, /aria-live="polite"/);
  assert.match(client, /aria-current=/);
  assert.match(css, /prefers-reduced-motion/);
  assert.match(css, /forced-colors/);
  assert.match(css, /@media \(max-width: 760px\)/);
  assert.match(client, /sessionStorage/);
  assert.match(client, /x-workspace-id/);
  assert.match(client, /requestJson\(ENDPOINTS\.workspaces\)/);
  assert.match(client, /identity\.policy_requirements\.find\(\(requirement\) => !requirement\.satisfied\)/);
  assert.match(client, /createPolicyAcceptanceIntent/);
  assert.match(client, /verifyPolicyBundleDocuments/);
  assert.match(client, /headers\.set\("x-workspace-id", workspaceId\)/);
  assert.match(client, /const headers = new Headers\(init\?\.headers\);[\s\S]*headers\.set\("accept", "application\/json"\)/);
  assert.doesNotMatch(client, /headers:\s*\{\s*accept:\s*"application\/json",\s*\.\.\.init\?\.headers\s*\}/);
  assert.match(client, /选择工作区/);
  assert.match(client, /切换工作区/);
  assert.match(client, /selectedWorkspace\?\.role_codes\.includes\("CREATOR"\)/);
  assert.match(client, /selectedWorkspace\?\.role_codes\.includes\("DEMAND_OWNER"\)/);
  assert.match(client, /selectedWorkspace\?\.role_codes\.includes\("ACCESS_ADMIN"\)/);
  assert.match(client, /selectedWorkspace\?\.role_codes\.includes\("OPERATIONS_REVIEWER"\)/);
  assert.match(client, /selectedWorkspace\?\.role_codes\.includes\("FINANCE_OPERATOR"\)/);
  assert.doesNotMatch(client, /me\?\.user_roles\.includes|me\?\.memberships\.some/);
  assert.match(client, /const switchWorkspace[\s\S]*setSelectedWorkspace\(null\);[\s\S]*clearWorkspaceObjects\(\);[\s\S]*loadWorkspaceObjects\(workspace, false\)/);
  assert.doesNotMatch(client, /localStorage|indexedDB|innerHTML|dangerouslySetInnerHTML/);
  assert.match(client, /return_to:\s*"\/app"/);
  assert.doesNotMatch(client, /invitationToken|access_invitation_token|邀请令牌（可选）/);
  assert.match(client, /直接登录只接受十个已预置账号/);
  assert.match(client, /受邀的新需求方负责人请从原邀请链接进入/);
  assert.match(client, /其他未知身份会被服务端拒绝且不会创建账号/);
  assert.match(client, /业务资料仍必须是可删除的合成资料/);
  assert.match(client, /当前账号/);
  assert.doesNotMatch(client, /虚构合成账号|当前合成账号|合成账号政策确认/);
  assert.match(client, /const directControl = child !== null && !Array\.isArray\(child\) && typeof child !== "object"/);
  assert.match(client, /aria-labelledby.*fieldGroupLabelId/);
  assert.match(client, /ariaLabel=\{typeof item === "object"/);
  assert.match(client, /directControl[\s\S]*<label htmlFor=\{fieldInputId\(childPath\)\}>[\s\S]*field-group-label/);
  assert.match(client, /function StructuredReadOnlyContent/);
  assert.match(client, /function ReadOnlyValue/);
  assert.doesNotMatch(client, /审核分配 ID<input/);
  assert.doesNotMatch(client, /理由代码（逗号分隔）/);
  assert.doesNotMatch(client, /Taxonomy bundle ID<input/);
  assert.doesNotMatch(client, /onTaxonomyChange|setCreateTaxonomy|setTaxonomyBundleId/);
  assert.match(client, /parseEditorConfigurationEnvelope/);
  assert.match(client, /parseEditorReviewQueueEnvelope/);
  assert.match(client, /parseEditorReviewClaimEnvelope/);
  assert.match(client, /createReviewClaimIntent/);
  assert.match(client, /createVerifyIntent/);
  assert.match(client, /refreshReviewQueue/);
  assert.match(client, /parseFinanceFundingQueueEnvelope/);
  assert.match(client, /parseFinanceFundingReviewEnvelope/);
  assert.match(client, /createFinanceFundingClaimIntent/);
  assert.match(client, /createFinanceFundingConfirmIntent/);
  assert.match(client, /record\.resource_type === "REVIEW_CLAIM"[\s\S]*parseEditorReviewClaimEnvelope\(result\.value\)[\s\S]*result\.etag !== claim\.etag[\s\S]*writeConfirmed = true;[\s\S]*persistPending\(null\);[\s\S]*`\$\{ENDPOINTS\.demands\}\/\$\{claim\.demand_id\}`[\s\S]*assignmentId: claim\.assignment_id/);
  assert.match(client, /response\.etag !== resource\.etag/);
  assert.match(client, /async function openAccount[\s\S]*accountResponse\.etag !== account\.entity_tag\s*\|\|\s*account\.user_id !== summary\.user_id/);
  assert.match(client, /record\.resource_type === "ACCOUNT_ADMIN"[\s\S]*accountResponse\.etag !== account\.entity_tag\s*\|\|\s*account\.user_id !== command\.user_id\s*\|\|\s*account\.aggregate_version < command\.aggregate_version/);
  assert.match(client, /reviewDecision && resource\.review_assignment !== null/);
  assert.match(client, /Object\.keys\(sectionsFromContent\("DEMAND", \{\}\)\)/);
  assert.match(client, /setReviewQueue\(\(current\) => current\.filter\(\(item\) => item\.demand_id !== claim\.demand_id\)\)/);
  assert.doesNotMatch(client, /evidence_summary_sha256|reviewer_user_id|duty_grant_id/);
  assert.doesNotMatch(client, /funded:\s*true|provider_event|payment_operation_id|body:\s*\{[^}]*amount_minor/s);
  assert.match(client, /CURRENT_APPROVED/);
  assert.doesNotMatch(client, /MISSING_EVIDENCE/);
  assert.match(client, /REVIEW_REASON_CODES\.map/);
  assert.doesNotMatch(client, /<pre className="readonly-json">\{JSON\.stringify\(resource\.current_version/);
  await access(new URL("app/app/page.tsx", root));
});

test("Operations review assignment release is closed, recoverable, and visually distinct from final decisions", async () => {
  const [client, contract, declarations, proxy, css] = await Promise.all([
    readFile(new URL("app/product-client.tsx", root), "utf8"),
    readFile(new URL("lib/app-contract.mjs", root), "utf8"),
    readFile(new URL("lib/app-contract.d.mts", root), "utf8"),
    readFile(new URL("lib/server-proxy.mjs", root), "utf8"),
    readFile(new URL("app/globals.css", root), "utf8"),
  ]);

  assert.match(contract, /REVIEW_ASSIGNMENT_RELEASE_REASON_CODES = Object\.freeze\(\[\s*"CONFLICT_DECLARED", "WORKLOAD_RELEASE"/);
  assert.match(contract, /function createReviewAssignmentReleaseIntent/);
  assert.match(declarations, /createReviewAssignmentReleaseIntent/);
  assert.match(proxy, /REVIEW_RELEASE_ROUTE/);
  assert.match(proxy, /validateReviewReleaseProxyResponse/);

  const handlerStart = client.indexOf("function releaseReviewAssignment(event: FormEvent)");
  const handlerEnd = client.indexOf("\n\n  function verifyDemand", handlerStart);
  const handler = client.slice(handlerStart, handlerEnd);
  assert.ok(handlerStart >= 0 && handlerEnd > handlerStart);
  assert.match(handler, /selected\.review_assignment\?\.assignment_id/);
  assert.match(handler, /createReviewAssignmentReleaseIntent\(\{/);
  assert.match(handler, /reasonCode: reviewReleaseReasonCode/);
  assert.match(handler, /pendingRecord\("DEMAND", selected\.object_id, "释放审核分配", intent\)/);
  assert.doesNotMatch(handler, /reviewer_user_id|duty_grant_id|actor/);

  const releasePanelStart = client.indexOf('{resource.capabilities.includes("RECORD_FINDINGS") && <section className="review-assignment-release-panel"');
  const finalDecisionStart = client.indexOf('{resource.capabilities.includes("RECORD_FINDINGS") && <section className="review-decision-grid"', releasePanelStart);
  const releasePanel = client.slice(releasePanelStart, finalDecisionStart);
  assert.ok(releasePanelStart >= 0 && finalDecisionStart > releasePanelStart);
  assert.match(releasePanel, /释放当前审核分配（非最终决定）/);
  assert.match(releasePanel, /不会修改 Demand 内容/);
  assert.match(releasePanel, /<code>SUBMITTED<\/code> 状态/);
  assert.match(releasePanel, /重新回到审核队列/);
  assert.match(releasePanel, /REVIEW_ASSIGNMENT_RELEASE_REASON_CODES\.map/);
  assert.match(releasePanel, /释放分配并返回审核队列/);
  assert.doesNotMatch(releasePanel, /ASSIGNMENT_EXPIRED|textarea|type="text"/);
  assert.match(client.slice(finalDecisionStart), /以下两项才是最终审核决定/);
  assert.match(css, /\.review-assignment-release-panel/);
  assert.match(css, /\.review-panel--release/);

  const clearStart = client.indexOf("function clearReviewAssignmentSelection(objectId: string)");
  const clearEnd = client.indexOf("\n\n  async function performWrite", clearStart);
  const clear = client.slice(clearStart, clearEnd);
  assert.match(clear, /setDemands\(\(current\) => current\.filter/);
  assert.match(clear, /setSelected\(null\)/);
  assert.doesNotMatch(clear, /setSelected\(\(current\)/);

  const writeStart = client.indexOf("async function performWrite(candidateRecord: PendingIntent)");
  const writeEnd = client.indexOf("\n\n  function persistLogoutIntent", writeStart);
  const performWrite = client.slice(writeStart, writeEnd);
  const responseGuardAt = performWrite.indexOf('reviewRelease && (resource.status !== "SUBMITTED" || resource.review_assignment !== null)');
  const confirmedAt = performWrite.indexOf("writeConfirmed = true;", responseGuardAt);
  const clearPendingAt = performWrite.indexOf("persistPending(null);", confirmedAt);
  const releaseSuccessAt = performWrite.indexOf("if (reviewRelease) {", clearPendingAt);
  const clearSelectionAt = performWrite.indexOf("clearReviewAssignmentSelection(resource.object_id)", releaseSuccessAt);
  const refreshAt = performWrite.indexOf("refreshReviewWorkspaceAfterAssignmentWrite(workspaceId)", clearSelectionAt);
  assert.ok(responseGuardAt >= 0 && confirmedAt > responseGuardAt && clearPendingAt > confirmedAt);
  assert.ok(releaseSuccessAt > clearPendingAt && clearSelectionAt > releaseSuccessAt && refreshAt > clearSelectionAt);

  const recoveryStart = performWrite.indexOf('caught.status === 412 && isReviewAssignmentWritePath(record.intent.path)');
  const recoveryEnd = performWrite.indexOf('caught.status === 412 && record.resource_type === "FINANCE_FUNDING"', recoveryStart);
  const recovery = performWrite.slice(recoveryStart, recoveryEnd);
  const recoveryClearAt = recovery.indexOf("persistPending(null)");
  const releaseBranchAt = recovery.indexOf("if (reviewRelease) {");
  const releaseBranchEnd = recovery.indexOf("} else {", releaseBranchAt);
  const releaseRecovery = recovery.slice(releaseBranchAt, releaseBranchEnd);
  assert.ok(recoveryClearAt >= 0 && releaseBranchAt > recoveryClearAt && releaseBranchEnd > releaseBranchAt);
  assert.match(releaseRecovery, /clearReviewAssignmentSelection\(record\.object_id\)/);
  assert.match(releaseRecovery, /refreshReviewWorkspaceAfterAssignmentWrite\(workspaceId\)/);
  assert.doesNotMatch(releaseRecovery, /`\$\{ENDPOINTS\.demands\}\/\$\{record\.object_id\}`/);
  assert.match(performWrite, /const outcomeUnknown = failure\.status === 0 \|\| failure\.status >= 500[\s\S]*if \(!outcomeUnknown\) persistPending\(null\)/);
  assert.match(performWrite, /if \(writeConfirmed\) \{[\s\S]*persistPending\(null\)[\s\S]*切勿原样重试这笔已确认写入/);
});

test("synthetic OIDC documentation freezes ten bootstrap accounts and one provider-only invitee", async () => {
  const document = await readFile(
    new URL("../docs/architecture/internal-sandbox-synthetic-oidc.md", root),
    "utf8",
  );
  for (const accountCode of [
    "access_admin_01",
    "appeal_reviewer_01",
    "creator_01",
    "demand_owner_01",
    "finance_operator_01",
    "finance_operator_02",
    "operations_reviewer_01",
    "org_admin_01",
    "trust_officer_01",
    "trust_officer_02",
    "invited_demand_owner_02",
  ]) assert.ok(document.includes(`| \`${accountCode}\` |`));
  assert.match(document, /十个 bootstrap 身份与一个 provider-only 受邀身份/);
  assert.match(document, /不进入 identity bootstrap manifest/);
  assert.match(document, /不能提供第十二个 subject\/email/);
  assert.match(document, /SYNTHETIC ONLY \/ G1 NO-GO \/ G2 NO-GO/);
  assert.doesNotMatch(document, /唯一七个身份|七个冻结账号|第八个账号/);
});

test("unknown K1 is a synchronous single-write latch for every account action", async () => {
  const client = await readFile(new URL("app/product-client.tsx", root), "utf8");
  const writeStart = client.indexOf("async function performWrite(candidateRecord: PendingIntent)");
  const writeEnd = client.indexOf("\n  async function beginSignIn", writeStart);
  assert.ok(writeStart >= 0 && writeEnd > writeStart);
  const performWrite = client.slice(writeStart, writeEnd);

  const globalGuardAt = performWrite.indexOf('globalPending?.resource_type === "ORG_ADMIN"');
  const globalRejectAt = performWrite.indexOf('setError({ code: "WRITE_OUTCOME_PENDING"', globalGuardAt);
  const globalReturnAt = performWrite.indexOf("return;", globalRejectAt);
  const compareAt = performWrite.indexOf("serializePendingIntent(existingPending) !== serializePendingIntent(candidateRecord)");
  const rejectAt = performWrite.indexOf('setError({ code: "WRITE_OUTCOME_PENDING"', compareAt);
  const returnAt = performWrite.indexOf("return;", rejectAt);
  const persistAt = performWrite.indexOf("persistPending(record)");
  const fetchAt = performWrite.indexOf("requestWorkspaceJson(");
  assert.ok(globalGuardAt >= 0 && globalRejectAt > globalGuardAt && globalReturnAt > globalRejectAt);
  assert.ok(globalReturnAt < persistAt && globalReturnAt < fetchAt, "ORG_ADMIN latch must return before storage or fetch");
  assert.ok(compareAt >= 0 && rejectAt > compareAt && returnAt > rejectAt);
  assert.ok(returnAt < persistAt && returnAt < fetchAt, "K2 must return before storage or fetch");
  assert.match(performWrite, /const record = existingPending \?\? candidateRecord/);
  assert.match(performWrite, /if \(!existingPending\) persistPending\(record\)/);

  assert.match(client, /function persistPending[\s\S]*pendingRef\.current = record;[\s\S]*setPending\(record\);[\s\S]*sessionStorage\.setItem\(PENDING_KEY, serializePendingIntent\(record\)\)/);
  assert.match(client, /onClick=\{\(\) => void performWrite\(pending\)\}>原样重试/);
  assert.match(client, /writeLocked=\{pending !== null \|\| logoutIntent !== null\}/);
  assert.match(client, /const actionsDisabled = busy \|\| account\.is_self \|\| writeLocked/);
  assert.equal((client.match(/disabled=\{actionsDisabled\}/g) ?? []).length, 5);
});

test("ACCESS_ADMIN 412 clears the stale write and fresh GETs the selected account", async () => {
  const client = await readFile(new URL("app/product-client.tsx", root), "utf8");
  const writeStart = client.indexOf("async function performWrite(candidateRecord: PendingIntent)");
  const writeEnd = client.indexOf("\n  async function beginSignIn", writeStart);
  assert.ok(writeStart >= 0 && writeEnd > writeStart);
  const performWrite = client.slice(writeStart, writeEnd);

  const conflictAt = performWrite.indexOf(
    'caught instanceof ApiError && caught.status === 412 && record.resource_type === "ACCOUNT_ADMIN"',
  );
  assert.ok(conflictAt >= 0, "account administration needs an explicit 412 recovery branch");
  const nextBranchAt = performWrite.indexOf(
    'caught instanceof ApiError && caught.status === 412 && record.resource_type === "REVIEW_CLAIM"',
    conflictAt,
  );
  assert.ok(nextBranchAt > conflictAt);
  const recovery = performWrite.slice(conflictAt, nextBranchAt);

  const clearAt = recovery.indexOf("persistPending(null)");
  const fetchAt = recovery.indexOf("requestWorkspaceJson(");
  assert.ok(clearAt >= 0 && fetchAt > clearAt, "the stale idempotent write must be cleared before fresh GET");
  assert.match(recovery, /`\$\{ENDPOINTS\.accounts\}\/\$\{record\.object_id\}`/);
  assert.match(recovery, /parseAccountAdminEnvelope\(accountResponse\.value\)/);
  assert.match(recovery, /accountResponse\.etag !== account\.entity_tag\s*\|\|\s*account\.user_id !== record\.object_id/);
  assert.match(recovery, /replaceAccount\(account\)[\s\S]*setSelectedAccount\(account\)/);
  assert.match(recovery, /setError\(\{ code: caught\.code, traceId: caught\.traceId \}\)/);
  assert.match(recovery, /旧请求已清除/);
  assert.match(recovery, /fresh GET/);

  const unknownAt = performWrite.indexOf("const outcomeUnknown = failure.status === 0 || failure.status >= 500", conflictAt);
  assert.ok(unknownAt > nextBranchAt, "unknown outcomes must stay on the existing retry-preserving path");
  assert.match(performWrite.slice(unknownAt), /outcomeUnknown[\s\S]*原样重试/);
});

test("explicit logout preserves unknown intents and clears app state only after a terminal session result", async () => {
  const client = await readFile(new URL("app/product-client.tsx", root), "utf8");
  await access(new URL("app/v1/me/sessions/route.ts", root));
  await access(new URL("app/v1/me/sessions/[session_id]/route.ts", root));
  assert.match(client, /退出登录/);
  assert.match(client, /原样重试退出/);
  assert.match(client, /const LOGOUT_PENDING_KEY = "desire-pilot-session-logout:v1"/);
  assert.match(client, /pendingRef\.current !== null \|\| policyAcceptanceIntentRef\.current !== null/);
  assert.match(client, /SESSION_LOGOUT_BLOCKED_BY_PENDING_WRITE/);
  assert.match(client, /`\/v1\/me\/sessions\/\$\{encodeURIComponent\(intent\.session_id\)\}`/);
  assert.match(client, /method:\s*"DELETE"/);
  assert.match(client, /"idempotency-key": intent\.idempotency_key/);
  assert.match(client, /"x-csrf-token": intent\.csrf_token/);
  assert.doesNotMatch(client, /revoke-all-sessions[\s\S]{0,500}function logoutCurrentSession/);
  assert.match(client, /outcomeUnknown[\s\S]*persistLogoutIntent\(intent\)/);
  assert.match(client, /failure\.status === 401[\s\S]*enterSignedOut/);
  assert.match(client, /function clearAuthenticatedBrowserState[\s\S]*SCRATCH_PREFIX[\s\S]*PENDING_ORGANIZATION_ADMIN_KEY/);
  assert.match(client, /logoutIntentRef\.current[\s\S]*WRITE_OUTCOME_PENDING/);
});

test("412 recovery re-reads the complete current editor resource before a retry", async () => {
  const client = await readFile(new URL("app/product-client.tsx", root), "utf8");
  const writeStart = client.indexOf("async function performWrite(candidateRecord: PendingIntent)");
  const writeEnd = client.indexOf("\n  async function beginSignIn", writeStart);
  const performWrite = client.slice(writeStart, writeEnd);
  const conflictStart = performWrite.indexOf("const conflictSurface = parseThreeWayConflict");
  const refreshAt = performWrite.indexOf("const refreshedResponse = await requestWorkspaceJson", conflictStart);
  const bindAt = performWrite.indexOf("const refreshed = bindConflictToCurrentResource", refreshAt);
  const replaceAt = performWrite.indexOf("replaceResource(refreshed)", bindAt);
  const adoptAt = performWrite.indexOf("adoptResource(refreshed, false)", replaceAt);
  const exposeAt = performWrite.indexOf("setConflict(conflictSurface)", adoptAt);
  assert.ok(conflictStart >= 0 && refreshAt > conflictStart && bindAt > refreshAt);
  assert.ok(replaceAt > bindAt && adoptAt > replaceAt && exposeAt > adoptAt);
  assert.match(performWrite, /record\.resource_type === "CREATOR_PROFILE" \|\| record\.resource_type === "DEMAND"/);

  const resolveStart = client.indexOf("function conflictStillMatchesCurrent()");
  const resolveEnd = client.indexOf("\n\n  const requestSelectedWorkspace", resolveStart);
  const resolveConflict = client.slice(resolveStart, resolveEnd);
  assert.match(resolveConflict, /selected\.etag !== conflict\.currentEtag/);
  assert.match(resolveConflict, /planEditorConflictMerge\([\s\S]*conflict\.base\.content[\s\S]*conflict\.current\.content[\s\S]*conflict\.yours\.content[\s\S]*choices/);
  assert.match(resolveConflict, /!merge\.complete \|\| merge\.content === null/);
  assert.match(resolveConflict, /sectionsFromContent\(selected\.resource_type, merge\.content\)/);
  assert.match(resolveConflict, /diffEditorVersionContent\([\s\S]*conflict\.current\.content,[\s\S]*merge\.content/);
  assert.match(resolveConflict, /persistEditorScratchToStorage\(sessionStorage, selected, mergedSections\)/);
  assert.doesNotMatch(resolveConflict, /performWrite\(|requestWorkspaceJson\(/);
  assert.doesNotMatch(resolveConflict, /const rebased|revision:\s*selected\.revision\s*\+\s*1|current_version:\s*\{\s*version_id:/);

  const panelStart = client.indexOf("function ConflictPanel({");
  const panel = client.slice(panelStart);
  assert.match(panel, /section\.state === "COLLISION"/);
  assert.match(panel, /type="radio"/);
  assert.match(panel, /disabled=\{!merge\.complete \|\| merge\.content === null\}/);
  assert.doesNotMatch(panel, /<pre>|JSON\.stringify\(conflict\./);
});

test("web contains no deployment, hosting, Sites, D1, or R2 configuration", async () => {
  const [vite, worker, packageJson] = await Promise.all([
    readFile(new URL("vite.config.ts", root), "utf8"),
    readFile(new URL("worker/index.ts", root), "utf8"),
    readFile(new URL("package.json", root), "utf8"),
  ]);
  const combined = `${vite}\n${worker}\n${packageJson}`;
  assert.doesNotMatch(combined, /hosting\.json|sites-vite-plugin|openai sites|d1_databases|r2_buckets|deploy/i);
  await assert.rejects(access(new URL(".openai/hosting.json", root)));
  await assert.rejects(access(new URL("wrangler.json", root)));
  await assert.rejects(access(new URL("wrangler.toml", root)));
});

test("development and preview servers bind exact IPv4 loopback without a publish command", async () => {
  const [packageJson, vite] = await Promise.all([
    readFile(new URL("package.json", root), "utf8").then(JSON.parse),
    readFile(new URL("vite.config.ts", root), "utf8"),
  ]);
  assert.equal(packageJson.scripts.dev, "WRANGLER_LOG_PATH=.wrangler/wrangler.log vinext dev --hostname 127.0.0.1 --port 3000");
  assert.equal(packageJson.scripts.start, "WRANGLER_LOG_PATH=.wrangler/wrangler.log vinext start --hostname 127.0.0.1 --port 3000");
  assert.equal(packageJson.scripts.deploy, undefined);
  assert.equal(packageJson.scripts.publish, undefined);
  assert.equal(packageJson.scripts.upload, undefined);
  assert.match(vite, /inspectorPort:\s*false/);
});
