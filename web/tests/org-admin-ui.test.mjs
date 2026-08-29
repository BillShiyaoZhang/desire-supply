import assert from "node:assert/strict";
import { access, readFile } from "node:fs/promises";
import test from "node:test";

const root = new URL("../", import.meta.url);

test("join is a real first-paint scrub route with a replay-safe memory-only state machine", async () => {
  const [page, client] = await Promise.all([
    readFile(new URL("app/join/page.tsx", root), "utf8"),
    readFile(new URL("app/join/join-client.tsx", root), "utf8"),
  ]);
  assert.match(page, /window\.history\.replaceState\(null, "", "\/join"\)/);
  assert.match(page, /\^\[A-Za-z0-9_-\]\{80,4096\}\$/);
  assert.doesNotMatch(page, /next\/script|<Script|beforeInteractive/);
  assert.match(page, /<script[\s\S]*id="desire-join-fragment-scrub"/);
  assert.match(page, /await headers\(\)[\s\S]*content-security-policy/);
  assert.match(page, /if \(policy === null\) return undefined/);
  assert.match(page, /nonce=\{nonce\}/);
  assert.match(page, /suppressHydrationWarning/);
  assert.ok(page.indexOf("<script") < page.indexOf("<JoinClient"), "fragment scrub must precede visible client UI");
  assert.match(client, /createJoinFlowCoordinator\(runJoinFlow\)/);
  assert.match(client, /generationRef\.current !== generation/);
  assert.doesNotMatch(client, /startedRef/);
  assert.match(client, /parseIdentityAuthorizationUrl/);
  assert.match(client, /sessionStorage\.setItem\(PENDING_INVITATION_CONTEXT_KEY, serializePendingInvitationContext\(context\)\)/);
  assert.match(client, /caught instanceof JoinApiError && caught\.status === 401[\s\S]*sessionCsrf = null/);
  assert.match(client, /sessionStorage\.setItem\(PENDING_INVITATION_CONTEXT_KEY[\s\S]*createInvitationAuthorizationInit\(capability, sessionCsrf\)/);
  assert.match(client, /credentials: init\?\.credentials \?\? "same-origin"/);
  assert.match(client, /catch \(caught\) \{[\s\S]*sessionStorage\.removeItem\(PENDING_INVITATION_CONTEXT_KEY\)[\s\S]*phase: code === "ACCESS_INVITATION_FRAGMENT_INVALID" \? "INVALID" : "UNAVAILABLE"/);
  assert.doesNotMatch(client, /localStorage|indexedDB|document\.cookie|console\./);
  assert.doesNotMatch(client, /sessionStorage\.setItem\([^\n]*access_invitation_token/);
  assert.doesNotMatch(client, /SIGNED_OUT|请先在工作台登录，再重新打开原邀请链接|退出状态下的邀请注册/);
  assert.match(client, /登录或创建受邀账号/);
});

test("invitation acceptance and ORG_ADMIN workbench stay exact, idempotent, and secret-free", async () => {
  const [acceptance, admin, product] = await Promise.all([
    readFile(new URL("app/invitation-acceptance.tsx", root), "utf8"),
    readFile(new URL("app/organization-admin-workbench.tsx", root), "utf8"),
    readFile(new URL("app/product-client.tsx", root), "utf8"),
  ]);
  assert.match(product, /phase === "INVITATION_ACCEPTANCE"/);
  assert.match(product, /<InvitationAcceptance/);
  assert.match(product, /<OrganizationAdminWorkbench/);
  assert.match(product, /onDirtyChange=\{setOrganizationPublicNameDirty\}/);
  assert.match(product, /prepareToLeaveOrganizationAdmin\(\)/);
  assert.match(product, /disabled=\{busy \|\| pendingOwner !== null \|\| logoutIntent !== null \|\| organizationPublicNameDirty\}/);
  assert.match(product, /pendingRef = useRef<PendingIntent \| \{ resource_type: "ORG_ADMIN"/);
  assert.match(product, /globalPending\?\.resource_type === "ORG_ADMIN"[\s\S]*return;/);
  assert.doesNotMatch(product, /access_invitation_token|invitationToken/);

  assert.match(acceptance, /createAcceptOrganizationInvitationIntent/);
  assert.match(acceptance, /verifyPolicyBundleDocuments/);
  assert.match(acceptance, /failure\.status === 401/);
  assert.match(acceptance, /"AUTHENTICATION_REQUIRED", "SESSION_EXPIRED"/);
  assert.match(acceptance, /sessionStorage\.removeItem\(PENDING_INVITATION_CONTEXT_KEY\)/);
  assert.doesNotMatch(acceptance, /localStorage|indexedDB|document\.cookie|console\.|access_invitation_token/);

  assert.match(admin, /ORGANIZATION_ADMIN_REASON_CODES\.map/);
  assert.match(admin, /createUpdateOrganizationPublicNameIntent/);
  assert.match(admin, /operation: "UPDATE_PUBLIC_NAME"/);
  assert.match(admin, /\/v1\/organizations\/\$\{organizationId\}/);
  assert.match(admin, /organizationPublicNameIssue[\s\S]*\[\.\.\.value\]\.length > 160/);
  assert.match(admin, /\[\\p\{Cc\}\\p\{Cf\}\]\/u/);
  assert.match(admin, /<form className="organization-public-name-card" aria-labelledby="organization-public-name-title"/);
  assert.match(admin, /<label htmlFor="organization-public-name">公开名称<\/label>/);
  assert.match(admin, /aria-describedby="organization-public-name-description organization-public-name-issue"/);
  assert.match(admin, /aria-invalid=\{publicNameDirty && publicNameIssue !== null\}/);
  assert.match(admin, /maxLength=\{320\}/);
  assert.match(admin, /我确认新公开名称会立即显示在现有未接受邀请的匿名预览中/);
  assert.match(admin, /setPublicNameConfirmed\(false\)[\s\S]*createUpdateOrganizationPublicNameIntent/);
  assert.match(admin, /failure\.status === 412 \|\| failure\.code === "PRECONDITION_FAILED"/);
  assert.match(admin, /refresh\(attemptedPublicName === null[\s\S]*preservePublicNameDraft: attemptedPublicName/);
  assert.match(admin, /setPublicNameConflict\(\{ current: refreshed\.public_name, attempted: attemptedPublicName \}\)/);
  assert.match(admin, /pendingTargetsSnapshot\(recovered, organizationId, invitationItems, membershipItems\)/);
  assert.match(admin, /pendingScopeInvalid[\s\S]*恢复对象与当前组织投影不匹配，已禁止重放/);
  assert.match(admin, /issued[\s\S]*INVITATION_CAPABILITY_DELIVERY_PENDING/);
  assert.match(admin, /已安全交付，关闭一次性链接/);
  assert.match(admin, /createTokenlessStepUpBody\(\)/);
  assert.match(admin, /claimWrite\(record\)[\s\S]*persistPending\(record\)[\s\S]*requestJson\(record\.intent\.path/);
  assert.match(admin, /navigator\.clipboard\.writeText/);
  assert.match(admin, /className="live-notice" role="status" aria-live="polite" aria-atomic="true"/);
  assert.match(admin, /<label>受邀邮箱<input/);
  assert.match(admin, /defaultOrganizationInvitationExpiry\(\)/);
  assert.match(admin, /organizationInvitationExpiryToIso\(expiresAt\)/);
  assert.doesNotMatch(admin, /toISOString\(\)\.slice\(0, 16\)/);
  assert.doesNotMatch(admin, /new Date\(expiresAt\)/);
  assert.doesNotMatch(admin, /合成收件邮箱/);
  assert.match(admin, /最后一名 ACTIVE ORG_ADMIN 不可暂停或撤销/);
  assert.doesNotMatch(admin, /localStorage\.|indexedDB\.|document\.cookie|console\.|window\.confirm/);
});

test("all exact IAM BFF route handlers exist", async () => {
  for (const path of [
    "app/v1/access-invitations/[...path]/route.ts",
    "app/v1/organizations/[...path]/route.ts",
    "app/v1/memberships/[...path]/route.ts",
  ]) await access(new URL(path, root));
});
