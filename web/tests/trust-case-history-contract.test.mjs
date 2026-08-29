import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { parseTrustCaseHistoryEnvelope } from "../lib/app-contract.mjs";
import { createAppProxyRequest, proxyAppRequest } from "../lib/server-proxy.mjs";

const root = new URL("../", import.meta.url);
const workspace = "platform:10000000-0000-4000-8000-000000000001";
const lowerCaseId = "50000000-0000-4000-8000-000000000001";
const higherCaseId = "50000000-0000-4000-8000-000000000002";
const entityTag = `"trust-4-${"a".repeat(24)}"`;
const history = {
  entity_tag: entityTag,
  has_more: true,
  items: [
    {
      case_id: higherCaseId,
      decided_at: "2026-08-26T08:00:00Z",
      outcome_code: "PROTECTION_MAINTAINED",
    },
    {
      case_id: lowerCaseId,
      decided_at: "2026-08-26T08:00:00Z",
      outcome_code: "NO_ACTION",
    },
  ],
};

function source(url = "http://localhost:3000/v1/app/trust/history", headers = {}) {
  return new Request(url, {
    headers: { "x-workspace-id": workspace, ...headers },
  });
}

test("Trust Officer history is a closed, unique, stably ordered safe projection", () => {
  assert.deepEqual(parseTrustCaseHistoryEnvelope({ data: history }), history);

  for (const invalid of [
    { ...history, items: [{ ...history.items[0], actor_user_id: lowerCaseId }] },
    { ...history, items: [...history.items].reverse() },
    { ...history, items: [history.items[0], history.items[0]] },
    { ...history, items: [{ ...history.items[0], case_id: "00000000-0000-0000-0000-000000000000" }] },
    { ...history, items: [{ ...history.items[0], decided_at: "2026-08-26T08:00:00" }] },
    { ...history, items: [{ ...history.items[0], outcome_code: "FORGED_OUTCOME" }] },
    { ...history, has_more: "true" },
    { ...history, entity_tag: `"trust-0-${"a".repeat(24)}"` },
  ]) assert.throws(
    () => parseTrustCaseHistoryEnvelope({ data: invalid }),
    /INVALID_APP_CONTRACT/,
  );

  assert.throws(
    () => parseTrustCaseHistoryEnvelope({ data: { ...history, restricted_note: "leak" } }),
    /INVALID_APP_CONTRACT/,
  );
});

test("Trust history BFF admits only the actor-bound GET and validates no-store plus ETag", async () => {
  const upstream = await createAppProxyRequest(source(), "http://api:8000");
  assert.equal(upstream.method, "GET");
  assert.equal(upstream.url, "http://api:8000/v1/app/trust/history");
  assert.equal(upstream.headers.get("x-workspace-id"), workspace);

  await assert.rejects(
    createAppProxyRequest(source("http://localhost:3000/v1/app/trust/history?actor_user_id=forged"), "http://api:8000"),
    /APP_ROUTE_NOT_ALLOWED/,
  );
  await assert.rejects(
    createAppProxyRequest(source(undefined, { "content-type": "application/json" }), "http://api:8000"),
    /INVALID_TRUST_REQUEST/,
  );

  const success = await proxyAppRequest(source(), {
    baseUrl: "http://api:8000",
    fetchImpl: async () => Response.json({ data: history }, {
      headers: { "cache-control": "no-store", etag: entityTag },
    }),
  });
  assert.equal(success.status, 200);
  assert.equal(success.headers.get("cache-control"), "no-store");
  assert.equal(success.headers.get("etag"), entityTag);
  assert.deepEqual(await success.json(), { data: history });

  for (const response of [
    Response.json({ data: { ...history, items: [{ ...history.items[0], restricted_note: "leak" }] } }, {
      headers: { "cache-control": "no-store", etag: entityTag },
    }),
    Response.json({ data: history }, { headers: { etag: entityTag } }),
    Response.json({ data: history }, { headers: { "cache-control": "no-store", etag: `"trust-5-${"b".repeat(24)}"` } }),
  ]) {
    const rejected = await proxyAppRequest(source(), {
      baseUrl: "http://api:8000",
      fetchImpl: async () => response,
    });
    assert.equal(rejected.status, 503);
    assert.equal(rejected.headers.get("etag"), null);
    assert.doesNotMatch(JSON.stringify(await rejected.json()), /restricted_note|leak/);
  }
});

test("Trust workbench reads history in every atomic queue snapshot and proves a published case is present", async () => {
  const trust = await readFile(new URL("app/trust-workbench.tsx", root), "utf8");
  const loadStart = trust.indexOf("const loadQueueSnapshot = useCallback");
  const loadEnd = trust.indexOf("\n\n  const commitQueueSnapshot", loadStart);
  const load = trust.slice(loadStart, loadEnd);
  const validatorStart = trust.indexOf("function validateTrustPostWriteSnapshot");
  const validatorEnd = trust.indexOf("\n\nfunction pendingRecord", validatorStart);
  const validator = trust.slice(validatorStart, validatorEnd);

  assert.ok(loadStart >= 0 && loadEnd > loadStart && validatorStart >= 0 && validatorEnd > validatorStart);
  assert.match(trust, /const TRUST_CASE_HISTORY = "\/v1\/app\/trust\/history"/);
  assert.match(trust, /parseTrustCaseHistoryEnvelope/);
  assert.match(load, /Promise\.all\(\[[\s\S]*loadQueue\(\)[\s\S]*loadHoldReleaseQueue\(\)[\s\S]*loadAssignments\(\)[\s\S]*loadCaseHistory\(\)/);
  assert.match(load, /history: historyProjection/);
  assert.match(validator, /eventType === "TrustCaseOutcomePublished"[\s\S]*!snapshot\.history\?\.items\.some\(\(item\) => item\.case_id === caseId\)/);
  assert.match(trust, /coordinatedRefreshQueues\("INITIAL"\)/);
  assert.match(trust, /coordinatedRefreshQueues\("MANUAL"\)/);
  assert.match(trust, /coordinatedRefreshQueues\("POST_WRITE", options\)/);
  assert.match(trust, /id="trust-case-history-title" tabIndex=\{-1\}/);
  assert.match(trust, /has_more=\{String\(history\.has_more\)\}/);
  assert.match(trust, /history\.has_more[\s\S]*服务端还有更早的本人完成记录/);
});

test("a Trust history task revalidates session, workspace, role, task, and exact case without resource_path", async () => {
  const [client, trust] = await Promise.all([
    readFile(new URL("app/product-client.tsx", root), "utf8"),
    readFile(new URL("app/trust-workbench.tsx", root), "utf8"),
  ]);
  const recheckStart = client.indexOf("async function openRevalidatedTrustCaseHistoryTask");
  const recheckEnd = client.indexOf("\n\n  async function openRevalidatedAppealCurrentAccountTask", recheckStart);
  const recheck = client.slice(recheckStart, recheckEnd);
  const openStart = client.indexOf("function openCurrentAccountTask");
  const openEnd = client.indexOf("\n\n  const replaceResource", openStart);
  const open = client.slice(openStart, openEnd);
  const focusStart = trust.indexOf("if (caseHistoryTaskTarget === null)");
  const focusEnd = trust.indexOf("\n\n  useEffect(() => {", focusStart);
  const focus = trust.slice(focusStart, focusEnd);

  assert.ok(recheckStart >= 0 && recheckEnd > recheckStart && openStart >= 0 && focusStart >= 0);
  assert.match(recheck, /requestJson\(ENDPOINTS\.session\)[\s\S]*parseSessionBootstrap/);
  assert.match(recheck, /requestJson\(ENDPOINTS\.workspaces\)[\s\S]*parseWorkspaceDiscovery/);
  assert.match(recheck, /refreshedSession\.session\.session_id !== sessionId/);
  assert.match(recheck, /loadWorkspaceObjects\(refreshedWorkspace, false, false\)/);
  assert.match(recheck, /workspace_kind !== "PLATFORM"[\s\S]*!refreshedWorkspace\.role_codes\.includes\("TRUST_OFFICER"\)/);
  assert.match(recheck, /refreshCurrentAccountTasks\(refreshedWorkspace\.workspace_id, false\)/);
  assert.match(recheck, /resolveRevalidatedCurrentAccountTask\(task, taskResult\.snapshot\)/);
  assert.match(recheck, /case_id: refreshedTask\.resource_id/);
  assert.doesNotMatch(recheck, /resource_path|requestWorkspaceJson\([^)]*resource/);
  assert.match(open, /isTrustCaseHistoryTask\(task\)[\s\S]*openRevalidatedTrustCaseHistoryTask\(task\)/);
  assert.match(client, /<TrustWorkbench[\s\S]*caseHistoryTaskTarget=\{trustCaseHistoryTaskTarget\}/);
  assert.match(focus, /caseHistoryTaskTarget\.session_id !== session\.session\.session_id/);
  assert.match(focus, /caseHistoryTaskTarget\.workspace_id !== workspace\.workspace_id/);
  assert.match(focus, /coordinatedRefreshQueues\("MANUAL", \{[\s\S]*snapshot\.history\?\.items\.some\(\(item\) => item\.case_id === caseId\)/);
  assert.match(focus, /historyItemRefs\.current\.get\(caseId\)[\s\S]*focus\(\{ preventScroll: true \}\)[\s\S]*scrollIntoView/);
  assert.doesNotMatch(focus, /resource_path|request\(/);
});
