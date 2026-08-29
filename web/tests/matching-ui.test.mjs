import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const root = new URL("../", import.meta.url);

test("Matching workbench separates loading, verified empty, stale/error, detail and terminal states", async () => {
  const workbench = await readFile(new URL("app/matching-workbench.tsx", root), "utf8");
  for (const phrase of [
    "匹配与邀请工作台",
    "正在读取当前账号的业务邀请",
    "读取失败，不是已验证的空邀请列表",
    "当前账号没有业务邀请（服务端已验证）",
    "安全披露尚未由服务端提供",
    "已接受的候选集合尚未由服务端提供",
    "接受并进入人工选择",
    "拒绝这次邀请",
    "选择该创作者",
    "关闭本轮且不选择",
    "选择完成前撤回接受",
    "拒绝或撤回说明（可选）",
  ]) assert.match(workbench, new RegExp(phrase));
  assert.match(workbench, /aria-busy=\{/);
  assert.match(workbench, /headers\.set\("x-workspace-id", workspace\.workspace_id\)/);
  assert.match(workbench, /role="alert"/);
  assert.match(workbench, /role="status"/);
  assert.match(workbench, /terminalInvitation/);
  assert.match(workbench, /selection\.status !== "OPEN"/);
  assert.match(workbench, /selection\.status === "PENDING_CHOICE"/);
  assert.match(workbench, /selection\.status === "PENDING_CLOSE"/);
  assert.doesNotMatch(workbench, /localStorage|indexedDB|console\.(?:log|info|warn|error)|dangerouslySetInnerHTML/);
});

test("Matching UI never renders ranking, score, private floors, evidence, contacts or arbitrary JSON", async () => {
  const workbench = await readFile(new URL("app/matching-workbench.tsx", root), "utf8");
  assert.doesNotMatch(workbench, /\b(?:rank|score|private_floor|creator_user_id|evidence)\b/i);
  assert.doesNotMatch(workbench, /\{JSON\.stringify|<pre|type="email"|mailto:|href=\{/);
  assert.match(workbench, /capability_summary/);
  assert.match(workbench, /organization_preview\.display_label/);
  assert.match(workbench, /opportunity\.problem_summary/);
  assert.match(workbench, /offer\.minimum_amount_minor/);
});

test("Matching writes are recoverable, single-latched and reload exact state after 412", async () => {
  const workbench = await readFile(new URL("app/matching-workbench.tsx", root), "utf8");
  assert.match(workbench, /const encoded = serializeMatchingPendingIntent\(record\)/);
  assert.match(workbench, /headers\.set\("x-csrf-token", session\.csrf_token\)/);
  assert.match(workbench, /sessionStorage\.setItem\(PENDING_KEY, encoded\)/);
  assert.match(workbench, /MATCHING_SELECTION_RECOVERY_KEY/);
  assert.match(workbench, /const record = pendingRef\.current \?\? candidate/);
  assert.match(workbench, /claimWrite\(record\)/);
  assert.match(workbench, /problem\.status === 0[\s\S]*problem\.status >= 500/);
  assert.match(workbench, /problem\.code === "COMMAND_OUTCOME_UNKNOWN"/);
  assert.match(workbench, /原样重试/);
  assert.match(workbench, /problem\.status === 412/);
  assert.match(workbench, /problem\.status === 412[\s\S]*(?:readInvitation|readSelection)[\s\S]*clearPending\(record\)/);
  assert.match(workbench, /MATCHING_PRECONDITION_RELOAD_FAILED/);
  assert.match(workbench, /createAcceptMatchingInvitationIntent/);
  assert.match(workbench, /createDeclineMatchingInvitationIntent/);
  assert.match(workbench, /createWithdrawMatchingInvitationIntent/);
  assert.match(workbench, /createChooseMatchingSelectionIntent/);
  assert.match(workbench, /createCloseMatchingSelectionIntent/);
});

test("Matching is role-workbench driven while the unextended current-task envelope remains closed", async () => {
  const [client, contract, workbench] = await Promise.all([
    readFile(new URL("app/product-client.tsx", root), "utf8"),
    readFile(new URL("lib/app-contract.mjs", root), "utf8"),
    readFile(new URL("app/matching-workbench.tsx", root), "utf8"),
  ]);
  assert.match(contract, /MATCHING_INVITATION/);
  assert.match(contract, /MATCHING_SELECTION/);
  assert.match(client, /MatchingWorkbench/);
  assert.match(client, /selectedWorkspace\?\.workspace_kind === "PERSONAL"[\s\S]*role_codes\.includes\("CREATOR"\)/);
  assert.match(client, /selectedWorkspace\?\.workspace_kind === "ORGANIZATION"[\s\S]*role_codes\.includes\("DEMAND_OWNER"\)/);
  assert.match(workbench, /id="matching-workbench-title"/);
  assert.doesNotMatch(client, /matchingTaskTarget|openRevalidatedMatchingCurrentAccountTask/);
  assert.doesNotMatch(workbench, /taskTarget/);
});

test("Matching reviewer UI is isolated to platform Operations Reviewers and exposes configurable claim-current workflow", async () => {
  const [client, reviewer] = await Promise.all([
    readFile(new URL("app/product-client.tsx", root), "utf8"),
    readFile(new URL("app/matching-review-workbench.tsx", root), "utf8"),
  ]);
  assert.match(client, /MatchingReviewWorkbench/);
  assert.match(client, /selectedWorkspace\?\.workspace_kind === "PLATFORM"[\s\S]*role_codes\.includes\("OPERATIONS_REVIEWER"\)/);
  for (const phrase of [
    "Matching 审核工作台",
    "领取下一项",
    "当前会话没有有效分配（服务端已验证）",
    "释放当前分配",
    "创建候选邀请",
    "发布 frozen disclosure 邀请",
    "失效异常 Attempt",
    "Eligible 候选与确定性评分",
    "新邀请有效时长（小时）",
    "可配置 1–672 小时",
  ]) assert.match(reviewer, new RegExp(phrase));
  assert.match(reviewer, /\/v1\/app\/matching-review\/assignment/);
  assert.match(reviewer, /\/v1\/app\/matching-review\/queue\/claim/);
  assert.match(reviewer, /createMatchingReviewInvitationExpiry\(invitationValidityHours\)/);
  assert.match(reviewer, /min=\{1\}[\s\S]*max=\{672\}/);
  assert.doesNotMatch(reviewer, /matching-review\/queue\?(?:cursor|limit)|queueItems|globalQueue/);
  assert.doesNotMatch(reviewer, /localStorage|indexedDB|dangerouslySetInnerHTML|console\.(?:log|info|warn|error)/);
});

test("same-origin proxy admits only the frozen Matching methods and closed request material", async () => {
  const [proxy, creatorRoute, assignmentRoute, reviewRoute, operationsRoute] = await Promise.all([
    readFile(new URL("lib/server-proxy.mjs", root), "utf8"),
    readFile(new URL("app/v1/me/matching-invitations/route.ts", root), "utf8"),
    readFile(new URL("app/v1/matching/candidate-selector-assignments/claim/route.ts", root), "utf8"),
    readFile(new URL("app/v1/app/matching-review/[...path]/route.ts", root), "utf8"),
    readFile(new URL("app/v1/operations/[...path]/route.ts", root), "utf8"),
  ]);
  assert.match(proxy, /MATCHING_INVITATION_COLLECTION_ROUTE/);
  assert.match(proxy, /MATCHING_INVITATION_DETAIL_ROUTE/);
  assert.match(proxy, /MATCHING_ATTEMPT_COLLECTION_ROUTE/);
  assert.match(proxy, /MATCHING_SELECTION_READ_ROUTE/);
  assert.match(proxy, /MATCHING_SELECTION_CHOOSE_ROUTE/);
  assert.match(proxy, /MATCHING_SELECTION_CLOSE_ROUTE/);
  assert.match(proxy, /MATCHING_ASSIGNMENT_CLAIM_ROUTE/);
  assert.match(proxy, /MATCHING_REVIEW_ASSIGNMENT_ROUTE/);
  assert.match(proxy, /validateMatchingRequest/);
  assert.match(proxy, /INVALID_MATCHING_REQUEST/);
  assert.match(proxy, /parseMatchingInvitationDetail/);
  assert.match(proxy, /parseMatchingSelection/);
  assert.match(creatorRoute, /proxyIamRequest/);
  assert.match(creatorRoute, /export const GET = handle/);
  assert.doesNotMatch(creatorRoute, /POST|PUT|DELETE/);
  assert.match(assignmentRoute, /proxyIamRequest/);
  assert.match(assignmentRoute, /export const POST = handle/);
  assert.doesNotMatch(assignmentRoute, /export const GET/);
  assert.match(reviewRoute, /export const GET = handle/);
  assert.match(reviewRoute, /export const POST = handle/);
  assert.match(operationsRoute, /export const POST = handle/);
  assert.doesNotMatch(operationsRoute, /export const GET/);
});
