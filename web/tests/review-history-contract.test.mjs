import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { parseEditorReviewHistoryEnvelope } from "../lib/app-contract.mjs";
import { createAppProxyRequest, proxyAppRequest } from "../lib/server-proxy.mjs";


const workspaceId = "platform:00000000-0000-4000-8000-000000000001";
const cursor = `${"a".repeat(64)}.${"b".repeat(43)}`;
const reviewedAt = "2026-08-25T08:00:00Z";
const verified = {
  review_id: "00000000-0000-4000-8000-000000000030",
  demand_id: "00000000-0000-4000-8000-000000000130",
  demand_version_id: "00000000-0000-4000-8000-000000000230",
  decision: "VERIFIED",
  reason_codes: [],
  required_field_codes: [],
  budget_health_code: "HEALTHY",
  risk_code: "STANDARD",
  reviewed_at: reviewedAt,
};
const needsChanges = {
  review_id: "00000000-0000-4000-8000-000000000020",
  demand_id: "00000000-0000-4000-8000-000000000120",
  demand_version_id: "00000000-0000-4000-8000-000000000220",
  decision: "NEEDS_CHANGES",
  reason_codes: ["SCOPE_UNCLEAR"],
  required_field_codes: ["SCOPE"],
  budget_health_code: null,
  risk_code: null,
  reviewed_at: reviewedAt,
};

function envelope(items = [verified, needsChanges], { hasMore = false } = {}) {
  return {
    data: {
      schema_version: "demand-review-history-v1",
      items,
      next_cursor: hasMore ? cursor : null,
      has_more: hasMore,
    },
  };
}

function source(url = "http://localhost:3000/v1/app/review-history?limit=25", headers = {}) {
  return new Request(url, {
    method: "GET",
    headers: { "x-workspace-id": workspaceId, ...headers },
  });
}

test("review history projection is exact, terminal, unique, and stably ordered", () => {
  assert.deepEqual(parseEditorReviewHistoryEnvelope(envelope()), envelope().data);
  assert.deepEqual(
    parseEditorReviewHistoryEnvelope(envelope([], { hasMore: true })),
    envelope([], { hasMore: true }).data,
  );
  for (const invalid of [
    envelope([{ ...verified, organization_id: "forged" }]),
    envelope([{ ...verified, reviewer_user_id: verified.review_id }]),
    envelope([{ ...verified, note: "unsafe" }]),
    envelope([{ ...verified, decision: "PENDING" }]),
    envelope([{ ...needsChanges, budget_health_code: "HEALTHY" }]),
    envelope([{ ...verified, reason_codes: ["SCOPE_UNCLEAR"] }]),
    envelope([needsChanges, verified]),
    envelope([verified, { ...verified }]),
    { data: { ...envelope().data, has_more: true, next_cursor: null } },
  ]) {
    assert.throws(() => parseEditorReviewHistoryEnvelope(invalid));
  }
});

test("BFF admits only the exact stable cursor query and strips client authority", async () => {
  const request = await createAppProxyRequest(
    source(`http://localhost:3000/v1/app/review-history?limit=25&cursor=${cursor}`),
    "http://api:8000",
  );
  assert.equal(
    request.url,
    `http://api:8000/v1/app/review-history?limit=25&cursor=${cursor}`,
  );

  for (const url of [
    "http://localhost:3000/v1/app/review-history?limit=0",
    "http://localhost:3000/v1/app/review-history?limit=1&limit=2",
    "http://localhost:3000/v1/app/review-history?owner_user_id=00000000-0000-4000-8000-000000000001",
    "http://localhost:3000/v1/app/review-history?cursor=abc%2Edef",
  ]) {
    await assert.rejects(
      createAppProxyRequest(source(url), "http://api:8000"),
      /INVALID_REVIEW_HISTORY_QUERY/,
    );
  }
  await assert.rejects(
    createAppProxyRequest(source(undefined, { "x-user-id": verified.review_id }), "http://api:8000"),
    /AUTHORITY_HEADER_FORBIDDEN/,
  );
  await assert.rejects(
    createAppProxyRequest(source(undefined, { "content-type": "application/json" }), "http://api:8000"),
    /INVALID_REVIEW_REQUEST/,
  );
});

test("BFF reserializes only a validated safe page and fails closed on a leak", async () => {
  const success = await proxyAppRequest(source(), {
    baseUrl: "http://api:8000",
    fetchImpl: async () => Response.json(envelope(), {
      status: 200,
      headers: { "cache-control": "no-store" },
    }),
  });
  assert.equal(success.status, 200);
  assert.deepEqual(await success.json(), envelope());

  const leaking = await proxyAppRequest(source(), {
    baseUrl: "http://api:8000",
    fetchImpl: async () => Response.json(
      envelope([{ ...verified, owner_user_id: verified.review_id }]),
      { status: 200, headers: { "cache-control": "no-store" } },
    ),
  });
  assert.equal(leaking.status, 503);
  assert.doesNotMatch(JSON.stringify(await leaking.json()), /owner_user_id|000000000030/);

  const invalidQuery = await proxyAppRequest(
    source("http://localhost:3000/v1/app/review-history?limit=101"),
    { baseUrl: "http://api:8000", fetchImpl: async () => { throw new Error("must not run"); } },
  );
  assert.equal(invalidQuery.status, 400);
  assert.deepEqual(await invalidQuery.json(), {
    error: { code: "INVALID_REQUEST", path: "/query" },
  });
});

test("product shell mounts the independent reviewer history panel and task destination", async () => {
  const [component, client, resolver] = await Promise.all([
    readFile(new URL("../app/review-history-panel.tsx", import.meta.url), "utf8"),
    readFile(new URL("../app/product-client.tsx", import.meta.url), "utf8"),
    readFile(new URL("../lib/current-account-task-destination.mjs", import.meta.url), "utf8"),
  ]);
  for (const marker of [
    "/v1/app/review-history",
    "parseEditorReviewHistoryEnvelope",
    "review-history-title",
    "我的已完成审核",
    "加载更多",
  ]) assert.match(component, new RegExp(marker));
  assert.doesNotMatch(component, /session-manager|SessionManager|reviewer_user_id|duty_grant_id|payload_hash|raw_hash/);
  assert.match(client, /import \{ ReviewHistoryPanel \} from "\.\/review-history-panel"/);
  assert.match(client, /resolveCurrentAccountTaskDestination\(task\)/);
  assert.match(resolver, /"DEMAND_REVIEW:VIEW_DEMAND_REVIEW_HISTORY", DEMAND_REVIEW_HISTORY/);
  assert.match(resolver, /WORKBENCH\("review-history-title"\)/);
  assert.match(client, /<ReviewHistoryPanel[\s\S]*?workspaceId=\{selectedWorkspace\.workspace_id\}/);
});

test("review history distinguishes retryable initial and pagination failures without guessing from item count", async () => {
  const component = await readFile(new URL("../app/review-history-panel.tsx", import.meta.url), "utf8");
  const initialStart = component.indexOf("const loadInitialPage = useCallback");
  const initialEnd = component.indexOf("\n\n  const retryInitialPage", initialStart);
  const retryStart = initialEnd;
  const retryEnd = component.indexOf("\n\n  useEffect", retryStart);
  const loadMoreStart = component.indexOf("async function loadMore()");
  const loadMoreEnd = component.indexOf("\n\n  return <section", loadMoreStart);
  const render = component.slice(loadMoreEnd);
  const initial = component.slice(initialStart, initialEnd);
  const retryInitial = component.slice(retryStart, retryEnd);
  const loadMore = component.slice(loadMoreStart, loadMoreEnd);

  assert.ok(initialStart >= 0 && initialEnd > initialStart);
  assert.ok(retryStart >= 0 && retryEnd > retryStart);
  assert.ok(loadMoreStart >= 0 && loadMoreEnd > loadMoreStart);
  assert.match(component, /phase: "LOADING" \| "READY" \| "LOADING_MORE" \| "INITIAL_ERROR" \| "PAGINATION_ERROR"/);
  assert.doesNotMatch(component, /["']ERROR["']/);

  assert.match(initial, /generation\.current \+= 1/);
  assert.match(initial, /activeRequest\.current\?\.abort\(\)/);
  assert.match(initial, /readPage\(workspaceId, null, controller\.signal\)/);
  assert.match(initial, /setStoredState\(\{ \.\.\.EMPTY_STATE, phase: "INITIAL_ERROR", workspaceId \}\)/);
  assert.match(retryInitial, /setStoredState\(\{ \.\.\.EMPTY_STATE, workspaceId \}\)[\s\S]*loadInitialPage\(\)/);

  assert.match(loadMore, /state\.phase !== "READY" && state\.phase !== "PAGINATION_ERROR"/);
  assert.match(loadMore, /const prior = state/);
  assert.match(loadMore, /readPage\(workspaceId, prior\.nextCursor, controller\.signal\)/);
  assert.match(loadMore, /page\.next_cursor === prior\.nextCursor/);
  assert.match(loadMore, /setStoredState\(\{ \.\.\.prior, phase: "PAGINATION_ERROR", workspaceId \}\)/);
  assert.doesNotMatch(loadMore, /phase: "PAGINATION_ERROR"[\s\S]*EMPTY_STATE/);

  assert.equal((render.match(/role="alert"/g) ?? []).length, 2);
  assert.match(render, /state\.phase === "INITIAL_ERROR"[\s\S]*onClick=\{retryInitialPage\}[\s\S]*重新读取审核历史/);
  assert.match(render, /state\.phase === "PAGINATION_ERROR"[\s\S]*已保留上次成功读取的 \{state\.items\.length\} 条记录和同一分页位置[\s\S]*重试加载更早审核/);
  assert.match(render, /state\.phase === "READY" && state\.items\.length === 0 && state\.hasMore[\s\S]*role="status"[\s\S]*服务端仍有更早记录；请继续加载/);
  assert.match(render, /state\.phase === "READY" && state\.items\.length === 0 && !state\.hasMore[\s\S]*当前账号还没有已完成的需求审核/);
  assert.doesNotMatch(component, /items\.length[^\n]*(?:loadInitialPage|retryInitialPage|loadMore|INITIAL_ERROR|PAGINATION_ERROR)/);
});
