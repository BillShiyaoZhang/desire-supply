import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  LEGACY_SESSION_REVOKE_PENDING_KEY,
  SESSION_REVOKE_PENDING_KEY,
  assertRemoteRevokePostcondition,
  bindSessionPage,
  claimAndPersistRemoteSessionRevokeIntent,
  createRemoteSessionRevokeIntent,
  parseRemoteSessionRevokeIntent,
  serializeRemoteSessionRevokeIntent,
} from "../lib/session-manager-state.mjs";

const root = new URL("../", import.meta.url);
const currentSessionId = "10000000-0000-4000-8000-000000000102";
const otherSessionId = "10000000-0000-4000-8000-000000000103";
const thirdSessionId = "10000000-0000-4000-8000-000000000104";
const accountUserId = "20000000-0000-4000-8000-000000000201";
const otherAccountUserId = "20000000-0000-4000-8000-000000000202";
const cursorOne = `${"a".repeat(64)}.${"b".repeat(43)}`;
const cursorTwo = `${"c".repeat(64)}.${"d".repeat(43)}`;
const csrfToken = "csrf_token_internal_000000000000001";

function session(sessionId, isCurrent, status = "ACTIVE") {
  return {
    session_id: sessionId,
    created_at: "2026-08-24T01:02:03Z",
    last_activity_at: "2026-08-24T02:03:04Z",
    expires_at: "2026-08-25T02:03:04Z",
    is_current: isCurrent,
    device_label: "Pilot browser",
    status,
  };
}

test("SessionManager is account-bound before and after workspace selection without opening business reads", async () => {
  const product = await readFile(new URL("app/product-client.tsx", root), "utf8");
  const selection = product.slice(
    product.indexOf('if (phase === "WORKSPACE_SELECTION")'),
    product.indexOf('if (phase === "UNAVAILABLE")'),
  );

  assert.match(product, /import \{ SessionManager \} from "\.\/session-manager"/);
  assert.equal((product.match(/<SessionManager/g) ?? []).length, 2);
  assert.equal((product.match(/accountUserId=\{me\.user_id\}/g) ?? []).length, 2);
  assert.equal((product.match(/key=\{`session-manager:\$\{session\.session\.session_id\}:\$\{me\.user_id\}`\}/g) ?? []).length, 2);
  assert.match(selection, /workspaces\.length > 0[\s\S]*: <div className="empty-state">/);
  assert.match(selection, /\{session && me && <SessionManager/);
  assert.match(selection, /disabled=\{busy \|\| pendingOwner !== null \|\| logoutIntent !== null\}[\s\S]{0,200}switchWorkspace/);
  assert.match(selection, /disabled=\{busy \|\| pendingOwner !== null \|\| logoutIntent !== null\} type="button" onClick=\{refreshWorkspaceSafely\}>重新发现工作区/);
  assert.match(selection, /disabled=\{busy \|\| pendingOwner !== null\} type="button" onClick=\{\(\) => void logoutCurrentSession\(\)\}/);
  assert.doesNotMatch(selection, /requestWorkspaceJson|ENDPOINTS\.(?:profiles|demands|reviewQueue|financeFundingQueue|accounts)/);
  assert.match(product, /function refreshWorkspaceSafely\(\) \{[\s\S]{0,240}pendingRef\.current !== null[\s\S]{0,120}logoutIntentRef\.current !== null[\s\S]{0,240}return;/);
  assert.match(product, /bootstrapSessionId=\{session\.session\.session_id\}/);
  assert.match(product, /locked=\{logoutIntent !== null \|\| \(pendingOwner !== null && pendingOwner !== "SESSION"\) \|\| \(busy && pendingOwner !== "SESSION"\)\}/);
  assert.match(product, /logoutOutcomeUnknown=\{logoutIntent !== null\}/);
  assert.match(product, /onLogoutCurrent=\{logoutCurrentSession\}/);
  assert.match(product, /request=\{requestJson\}/);
  assert.match(product, /独立角色账号 · 服务端权限 · 可版本化编辑/);
  assert.doesNotMatch(product, /真实账号 · 服务端权限 · 可版本化编辑/);
});

test("the terminal first page succeeds only with the exact bootstrap current Session", async () => {
  const valid = bindSessionPage({
    items: [
      session(currentSessionId, true),
      session(otherSessionId, false, "REVOKED"),
    ],
    page: { next_cursor: null },
  }, {
    bootstrapSessionId: currentSessionId,
    existing: null,
    requestedCursor: null,
  });
  assert.equal(valid.items.length, 2);
  assert.equal(valid.items.filter((item) => item.is_current).length, 1);
  assert.equal(valid.items.find((item) => item.is_current).session_id, currentSessionId);

  const invalidTerminalPages = [
    { items: [session(otherSessionId, false)], page: { next_cursor: null } },
    { items: [session(currentSessionId, false)], page: { next_cursor: null } },
    { items: [session(otherSessionId, true)], page: { next_cursor: null } },
  ];
  for (const page of invalidTerminalPages) {
    assert.throws(() => bindSessionPage(page, {
      bootstrapSessionId: currentSessionId,
      existing: null,
      requestedCursor: null,
    }), /INVALID_SESSION_PAGE_BINDING/);
  }
});

test("the in-memory cursor chain accepts later current discovery and rejects duplicates or no progress", async () => {
  const first = bindSessionPage({
    items: [session(otherSessionId, false)],
    page: { next_cursor: cursorOne },
  }, {
    bootstrapSessionId: currentSessionId,
    existing: null,
    requestedCursor: null,
  });
  const complete = bindSessionPage({
    items: [session(currentSessionId, true)],
    page: { next_cursor: null },
  }, {
    bootstrapSessionId: currentSessionId,
    existing: first,
    requestedCursor: cursorOne,
  });
  assert.deepEqual(complete.items.map((item) => item.session_id), [otherSessionId, currentSessionId]);

  assert.throws(() => bindSessionPage({
    items: [session(otherSessionId, false)],
    page: { next_cursor: null },
  }, {
    bootstrapSessionId: currentSessionId,
    existing: first,
    requestedCursor: cursorOne,
  }), /INVALID_SESSION_PAGE_BINDING/, "a Session cannot repeat across pages");

  assert.throws(() => bindSessionPage({
    items: [session(thirdSessionId, false)],
    page: { next_cursor: cursorOne },
  }, {
    bootstrapSessionId: currentSessionId,
    existing: first,
    requestedCursor: cursorOne,
  }), /INVALID_SESSION_PAGE_BINDING/, "the response cursor cannot stay in place");

  assert.throws(() => bindSessionPage({
    items: [],
    page: { next_cursor: cursorTwo },
  }, {
    bootstrapSessionId: currentSessionId,
    existing: first,
    requestedCursor: cursorOne,
  }), /INVALID_SESSION_PAGE_BINDING/, "an empty non-terminal page cannot claim progress");

  const second = bindSessionPage({
    items: [session(thirdSessionId, false)],
    page: { next_cursor: cursorTwo },
  }, {
    bootstrapSessionId: currentSessionId,
    existing: first,
    requestedCursor: cursorOne,
  });
  assert.throws(() => bindSessionPage({
    items: [session(currentSessionId, true)],
    page: { next_cursor: cursorOne },
  }, {
    bootstrapSessionId: currentSessionId,
    existing: second,
    requestedCursor: cursorTwo,
  }), /INVALID_SESSION_PAGE_BINDING/, "a cursor cannot loop to any previously seen value");
});

test("reads are closed, generation-safe, GET-only, and never persisted", async () => {
  const manager = await readFile(new URL("app/session-manager.tsx", root), "utf8");

  assert.match(manager, /const SESSION_LIST_ENDPOINT = "\/v1\/me\/sessions\?limit=25"/);
  assert.equal((manager.match(/const page = parseSessionPage\(response\.value\)/g) ?? []).length, 3);
  assert.match(manager, /cursor=\$\{encodeURIComponent\(requestedCursor\)\}/);
  assert.match(manager, /const generation = \+\+generationRef\.current/);
  assert.match(manager, /if \(generationRef\.current !== generation\) return/);
  assert.match(manager, /if \(\s*recoveryChecked\s*&& recoveryStorageAvailable\s*&& !legacyRecoveryBlocked\s*&& !locked\s*&& remoteIntentRef\.current === null\s*\) \{\s*queueMicrotask/);
  assert.match(manager, /return \(\) => \{\s*active = false;\s*generationRef\.current \+= 1/);
  assert.doesNotMatch(manager, /localStorage/);
  assert.doesNotMatch(manager, /sessionStorage\.(?:getItem|setItem)\([^\n]*(?:items|sessions|cursor|snapshot)/i);
  assert.doesNotMatch(manager, /item\.(?:ip_address|user_agent|family_id|generation)/);
});

test("the current Session keeps existing logout recovery while other ACTIVE Sessions require confirmation", async () => {
  const manager = await readFile(new URL("app/session-manager.tsx", root), "utf8");

  assert.match(manager, /const isCurrentActive = item\.is_current && item\.status === "ACTIVE"/);
  assert.match(manager, /\{isCurrentActive && <button[\s\S]{0,300}onClick=\{\(\) => void logoutCurrent\(\)\}/);
  assert.match(manager, /await onLogoutCurrent\(\)/);
  assert.match(manager, /const isRemoteActive = !item\.is_current && item\.status === "ACTIVE"/);
  assert.match(manager, /\{isRemoteActive && !confirming && <button[\s\S]{0,300}撤销此会话/);
  assert.match(manager, /确认撤销这个其他会话/);
  assert.match(manager, /取消撤销/);
  assert.match(manager, /method:\s*"DELETE"/);
  assert.match(manager, /"idempotency-key": record\.idempotency_key/);
  assert.match(manager, /"x-csrf-token": record\.csrf_token/);
  assert.match(manager, /"x-bootstrap-session-id": record\.bootstrap_session_id/);
  assert.match(manager, /item\.status !== "ACTIVE"[\s\S]{0,180}终态会话，无可用操作/);
  assert.match(manager, /当前会话退出结果尚未确认。[\s\S]{0,120}页面上方已有的退出恢复面/);
  assert.match(manager, /disabled=\{controlsLocked\}/);
  assert.match(manager, /safeShortSessionId\(item\.session_id\)/);
  assert.doesNotMatch(manager, /title=\{item\.session_id\}|>\{item\.session_id\}</);
});

test("remote revoke recovery v2 is exact, account/bootstrap-bound, and rejects legacy workspace records", () => {
  const now = Date.parse("2026-08-24T12:00:00Z");
  const intent = createRemoteSessionRevokeIntent({
    accountUserId,
    bootstrapSessionId: currentSessionId,
    csrfToken,
    idempotencyKey: "revoke-other-session-0001",
    now,
    targetSessionId: otherSessionId,
  });
  const encoded = serializeRemoteSessionRevokeIntent(intent);
  assert.equal(LEGACY_SESSION_REVOKE_PENDING_KEY, "desire-pilot-session-revoke:v1");
  assert.equal(SESSION_REVOKE_PENDING_KEY, "desire-pilot-session-revoke:v2");
  assert.deepEqual(parseRemoteSessionRevokeIntent(encoded, {
    accountUserId,
    bootstrapSessionId: currentSessionId,
    now: now + 23 * 60 * 60 * 1000,
  }), intent);

  for (const options of [
    { accountUserId: otherAccountUserId, bootstrapSessionId: currentSessionId, now },
    { accountUserId, bootstrapSessionId: thirdSessionId, now },
    { accountUserId, bootstrapSessionId: currentSessionId, now: now + 24 * 60 * 60 * 1000 + 1 },
  ]) assert.equal(parseRemoteSessionRevokeIntent(encoded, options), null);
  assert.equal(parseRemoteSessionRevokeIntent(JSON.stringify({ ...intent, family_id: "secret" }), {
    accountUserId,
    bootstrapSessionId: currentSessionId,
    now,
  }), null);
  assert.equal(parseRemoteSessionRevokeIntent(JSON.stringify({ ...intent, workspace_id: "org:20000000-0000-4000-8000-000000000201" }), {
    accountUserId,
    bootstrapSessionId: currentSessionId,
    now,
  }), null);
  assert.equal(parseRemoteSessionRevokeIntent(JSON.stringify({
    version: 1,
    saved_at: intent.saved_at,
    bootstrap_session_id: currentSessionId,
    workspace_id: "org:20000000-0000-4000-8000-000000000201",
    target_session_id: otherSessionId,
    csrf_token: csrfToken,
    idempotency_key: "revoke-other-session-legacy-0001",
  }), {
    accountUserId,
    bootstrapSessionId: currentSessionId,
    now,
  }), null);
  assert.throws(() => createRemoteSessionRevokeIntent({
    accountUserId,
    bootstrapSessionId: currentSessionId,
    csrfToken,
    idempotencyKey: "revoke-current-session-0001",
    now,
    targetSessionId: currentSessionId,
  }), /INVALID_REMOTE_SESSION_REVOKE_INTENT/);
});

test("a confirmed remote revoke requires a fresh complete list with current ACTIVE and target terminal or absent", () => {
  const base = {
    items: [
      session(currentSessionId, true),
      session(otherSessionId, false, "REVOKED"),
    ],
    nextCursor: null,
    seenCursors: [],
  };
  assert.equal(assertRemoteRevokePostcondition(base, {
    bootstrapSessionId: currentSessionId,
    targetSessionId: otherSessionId,
  }), base);
  assert.equal(assertRemoteRevokePostcondition({ ...base, items: [session(currentSessionId, true)] }, {
    bootstrapSessionId: currentSessionId,
    targetSessionId: otherSessionId,
  }).items.length, 1);

  for (const snapshot of [
    { ...base, items: [session(currentSessionId, true), session(otherSessionId, false)] },
    { ...base, items: [session(otherSessionId, false, "REVOKED")] },
    { ...base, items: [session(currentSessionId, false), session(otherSessionId, false, "REVOKED")] },
  ]) assert.throws(() => assertRemoteRevokePostcondition(snapshot, {
    bootstrapSessionId: currentSessionId,
    targetSessionId: otherSessionId,
  }), /INVALID_REMOTE_SESSION_REVOKE_POSTCONDITION/);
});

test("remote unknown outcome keeps one global latch and exposes only exact retry or explicit abandon", async () => {
  const [manager, product] = await Promise.all([
    readFile(new URL("app/session-manager.tsx", root), "utf8"),
    readFile(new URL("app/product-client.tsx", root), "utf8"),
  ]);
  assert.match(product, /const claimSessionWrite = useCallback/);
  assert.match(product, /setPendingOwner\("SESSION"\)/);
  assert.match(product, /const releaseSessionWrite = useCallback/);
  assert.match(product, /pendingOwner !== "SESSION"/);
  assert.match(product, /onGlobalBusyChange=/);
  assert.match(product, /accountUserId=\{me\.user_id\}/);
  const sessionManagerMounts = [...product.matchAll(/<SessionManager\b[\s\S]*?\/>/g)]
    .map((match) => match[0]);
  assert.equal(sessionManagerMounts.length, 2);
  for (const mount of sessionManagerMounts) {
    assert.doesNotMatch(mount, /workspaceId=/);
  }
  assert.match(manager, /const encoded = sessionStorage\.getItem\(SESSION_REVOKE_PENDING_KEY\)[\s\S]{0,180}parseRemoteSessionRevokeIntent\(encoded/);
  assert.match(manager, /sessionStorage\.setItem\([\s\S]{0,100}SESSION_REVOKE_PENDING_KEY,[\s\S]{0,100}serializeRemoteSessionRevokeIntent\(intent\)/);
  assert.match(manager, /原样重试撤销/);
  assert.match(manager, /放弃撤销恢复/);
  assert.match(manager, /record = remoteIntentRef\.current \?\? createRemoteSessionRevokeIntent/);
  assert.match(manager, /accountUserId,[\s\S]{0,120}bootstrapSessionId/);
  assert.doesNotMatch(manager, /workspaceId|workspace_id|\/v1\/platform\/users|revoke-all-sessions/);
  assert.doesNotMatch(manager, /remoteIntentRef\.current \?\?[^\n]*crypto\.randomUUID\(\)/);
});

test("a recovery persistence failure releases the exact global Session write latch", () => {
  const intent = createRemoteSessionRevokeIntent({
    accountUserId,
    bootstrapSessionId: currentSessionId,
    csrfToken,
    idempotencyKey: "revoke-other-session-storage-failure-0001",
    targetSessionId: otherSessionId,
  });
  const events = [];

  assert.throws(() => claimAndPersistRemoteSessionRevokeIntent(intent, {
    claimWrite(writeKey) {
      events.push(["claim", writeKey]);
      return true;
    },
    persistIntent(record) {
      events.push(["persist", record]);
      throw new Error("storage unavailable");
    },
    releaseWrite(writeKey) {
      events.push(["release", writeKey]);
    },
    setWriteBusy(writeKey, value) {
      events.push(["busy", writeKey, value]);
    },
  }), /SESSION_REVOKE_RECOVERY_STORAGE_FAILED/);
  assert.deepEqual(events, [
    ["claim", intent.idempotency_key],
    ["persist", intent],
    ["busy", intent.idempotency_key, false],
    ["release", intent.idempotency_key],
  ]);
});

test("Session recovery storage exceptions become a visible fail-closed state", async () => {
  const manager = await readFile(new URL("app/session-manager.tsx", root), "utf8");
  const recoveryEffect = manager.slice(
    manager.indexOf("const legacyEncoded = sessionStorage.getItem"),
    manager.indexOf("function persistRemoteIntent"),
  );

  assert.match(recoveryEffect, /sessionStorage\.getItem\(SESSION_REVOKE_PENDING_KEY\)/);
  assert.match(recoveryEffect, /sessionStorage\.getItem\(LEGACY_SESSION_REVOKE_PENDING_KEY\)[\s\S]*legacyRecoveryBlockedRef\.current = true[\s\S]*claimWrite\(LEGACY_REVOKE_LATCH_KEY\)/);
  assert.doesNotMatch(recoveryEffect, /legacyEncoded !== null\) \{\s*sessionStorage\.removeItem\(LEGACY_SESSION_REVOKE_PENDING_KEY\)/);
  assert.match(recoveryEffect, /catch \{[\s\S]*setRecoveryStorageAvailable\(false\)[\s\S]*SESSION_REVOKE_RECOVERY_STORAGE_FAILED/);
  assert.match(recoveryEffect, /finally \{\s*if \(active\) setRecoveryChecked\(true\)/);
  assert.match(manager, /const controlsLocked = locked\s*\|\| !recoveryChecked\s*\|\| !recoveryStorageAvailable\s*\|\| legacyRecoveryBlocked/);
  assert.match(manager, /recoveryChecked[\s\S]{0,80}recoveryStorageAvailable[\s\S]{0,80}!legacyRecoveryBlocked[\s\S]{0,80}!locked/);
  assert.match(manager, /旧对象只绑定工作区，不能证明当前账号[\s\S]{0,500}明确放弃旧版恢复/);
  assert.match(manager, /function abandonLegacyRecovery\(\)[\s\S]{0,260}sessionStorage\.removeItem\(LEGACY_SESSION_REVOKE_PENDING_KEY\)[\s\S]{0,500}setRecoveryEpoch/);
  assert.match(manager, /legacyRecoveryBlockedRef\.current[\s\S]{0,180}releaseWrite\(LEGACY_REVOKE_LATCH_KEY\)/);
});

test("session cards expose responsive and accessible list, refresh, error, and pagination states", async () => {
  const [manager, styles] = await Promise.all([
    readFile(new URL("app/session-manager.tsx", root), "utf8"),
    readFile(new URL("app/globals.css", root), "utf8"),
  ]);

  assert.match(manager, /aria-busy=\{visibleReadOperation !== null \|\| remoteBusy\}/);
  assert.match(manager, /aria-labelledby="session-manager-title"/);
  assert.match(manager, /aria-controls="session-manager-list"/);
  assert.match(manager, /role="alert"/);
  assert.match(manager, /正在读取当前账号的会话摘要/);
  assert.match(manager, /尚未读取到会话摘要/);
  assert.match(manager, /加载更多/);
  for (const phrase of ["创建", "最近活动", "到期", "当前会话", "活跃", "已撤销", "已过期"]) {
    assert.match(manager, new RegExp(phrase));
  }
  assert.match(styles, /\.session-manager__list \{[^}]*grid-template-columns: repeat\(2/);
  assert.match(styles, /@media \(max-width: 980px\)[\s\S]*\.session-manager__list \{ grid-template-columns: 1fr; \}/);
  assert.match(styles, /@media \(max-width: 760px\)[\s\S]*\.session-manager__facts \{ grid-template-columns: 1fr; \}/);
});
