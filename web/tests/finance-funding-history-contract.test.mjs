import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { parseFinanceFundingHistoryEnvelope } from "../lib/app-contract.mjs";
import { createAppProxyRequest, proxyAppRequest } from "../lib/server-proxy.mjs";


const workspaceId = "platform:00000000-0000-4000-8000-000000000001";
const cursor = `${"a".repeat(64)}.${"b".repeat(43)}`;
const completedAt = "2026-08-25T08:00:00+00:00";
const secured = {
  funding_review_id: "00000000-0000-4000-8000-000000000030",
  demand_id: "00000000-0000-4000-8000-000000000130",
  demand_version_id: "00000000-0000-4000-8000-000000000230",
  status: "SECURED",
  completed_at: completedAt,
};
const discrepancy = {
  funding_review_id: "00000000-0000-4000-8000-000000000020",
  demand_id: "00000000-0000-4000-8000-000000000120",
  demand_version_id: "00000000-0000-4000-8000-000000000220",
  status: "DISCREPANCY",
  completed_at: completedAt,
};

function envelope(items = [secured, discrepancy], { hasMore = false } = {}) {
  return {
    data: {
      schema_version: "finance-funding-review-history-v1",
      items,
      next_cursor: hasMore ? cursor : null,
      has_more: hasMore,
    },
  };
}

function source(
  url = "http://localhost:3000/v1/app/finance/funding-review-history?limit=25",
  headers = {},
) {
  return new Request(url, {
    method: "GET",
    headers: { "x-workspace-id": workspaceId, ...headers },
  });
}

test("finance funding history projection is exact, terminal, unique, and stably ordered", () => {
  assert.deepEqual(parseFinanceFundingHistoryEnvelope(envelope()), envelope().data);
  assert.deepEqual(
    parseFinanceFundingHistoryEnvelope(envelope([], { hasMore: true })),
    envelope([], { hasMore: true }).data,
  );
  for (const invalid of [
    envelope([{ ...secured, organization_id: secured.demand_id }]),
    envelope([{ ...secured, actor_user_id: secured.funding_review_id }]),
    envelope([{ ...secured, confirmation_count: 2 }]),
    envelope([{ ...secured, status: "PENDING" }]),
    envelope([{ ...secured, completed_at: "2026-08-25T08:00:00" }]),
    envelope([discrepancy, secured]),
    envelope([secured, { ...secured }]),
    { data: { ...envelope().data, has_more: true, next_cursor: null } },
  ]) {
    assert.throws(() => parseFinanceFundingHistoryEnvelope(invalid));
  }
});

test("finance history BFF admits only the exact actor-bound cursor query", async () => {
  const request = await createAppProxyRequest(
    source(`http://localhost:3000/v1/app/finance/funding-review-history?limit=25&cursor=${cursor}`),
    "http://api:8000",
  );
  assert.equal(
    request.url,
    `http://api:8000/v1/app/finance/funding-review-history?limit=25&cursor=${cursor}`,
  );

  for (const url of [
    "http://localhost:3000/v1/app/finance/funding-review-history?limit=0",
    "http://localhost:3000/v1/app/finance/funding-review-history?limit=1&limit=2",
    "http://localhost:3000/v1/app/finance/funding-review-history?actor_user_id=00000000-0000-4000-8000-000000000001",
    "http://localhost:3000/v1/app/finance/funding-review-history?cursor=abc%2Edef",
  ]) {
    await assert.rejects(
      createAppProxyRequest(source(url), "http://api:8000"),
      /INVALID_FINANCE_FUNDING_HISTORY_QUERY/,
    );
  }
  await assert.rejects(
    createAppProxyRequest(source(undefined, { "x-user-id": secured.funding_review_id }), "http://api:8000"),
    /AUTHORITY_HEADER_FORBIDDEN/,
  );
  await assert.rejects(
    createAppProxyRequest(source(undefined, { "content-type": "application/json" }), "http://api:8000"),
    /INVALID_FINANCE_FUNDING_REQUEST/,
  );
});

test("finance history BFF reserializes a validated page and fails closed on leaks", async () => {
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
      envelope([{ ...secured, organization_id: secured.demand_id }]),
      { status: 200, headers: { "cache-control": "no-store" } },
    ),
  });
  assert.equal(leaking.status, 503);
  assert.doesNotMatch(JSON.stringify(await leaking.json()), /organization_id|000000000130/);

  const invalidQuery = await proxyAppRequest(
    source("http://localhost:3000/v1/app/finance/funding-review-history?limit=101"),
    { baseUrl: "http://api:8000", fetchImpl: async () => { throw new Error("must not run"); } },
  );
  assert.equal(invalidQuery.status, 400);
  assert.deepEqual(await invalidQuery.json(), {
    error: { code: "INVALID_REQUEST", path: "/query" },
  });
});

test("finance workspace mounts actor history and rechecks a row before opening detail", async () => {
  const [component, client] = await Promise.all([
    readFile(new URL("../app/finance-funding-history-panel.tsx", import.meta.url), "utf8"),
    readFile(new URL("../app/product-client.tsx", import.meta.url), "utf8"),
  ]);
  for (const marker of [
    "/v1/app/finance/funding-review-history",
    "parseFinanceFundingHistoryEnvelope",
    "finance-funding-history-title",
    "我的已完成资金审查",
    "打开记录",
    "加载更多",
  ]) assert.match(component, new RegExp(marker));
  assert.doesNotMatch(component, /organization_id|actor_user_id|assignment_id|confirmation_count|payload_hash|raw_hash/);
  assert.match(client, /import \{ FinanceFundingHistoryPanel \} from "\.\/finance-funding-history-panel"/);
  assert.match(client, /key=\{`finance-funding-history:\$\{selectedWorkspace\.workspace_id\}`\}/);
  assert.match(client, /<FinanceFundingHistoryPanel[\s\S]*?workspaceId=\{selectedWorkspace\.workspace_id\}[\s\S]*?onOpen=\{openFinanceFundingHistoryItem\}/);
  assert.match(client, /data-funding-review-id=\{review\.funding_review_id\}[\s\S]*id="finance-funding-title"[\s\S]*tabIndex=\{-1\}/);
  for (const binding of [
    "review.funding_review_id !== item.funding_review_id",
    "review.demand_id !== item.demand_id",
    "review.demand_version_id !== item.demand_version_id",
    "review.status !== item.status",
  ]) assert.match(client, new RegExp(binding.replaceAll(".", "\\.")));
});

test("finance history distinguishes retryable initial and pagination failures without guessing from item count", async () => {
  const component = await readFile(new URL("../app/finance-funding-history-panel.tsx", import.meta.url), "utf8");
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
  assert.match(render, /state\.phase === "INITIAL_ERROR"[\s\S]*onClick=\{retryInitialPage\}[\s\S]*重新读取资金审查历史/);
  assert.match(render, /state\.phase === "PAGINATION_ERROR"[\s\S]*已保留上次成功读取的 \{state\.items\.length\} 条记录和同一分页位置[\s\S]*重试加载更早资金审查/);
  assert.match(render, /state\.phase === "READY" && state\.items\.length === 0 && state\.hasMore[\s\S]*role="status"[\s\S]*服务端仍有更早记录；请继续加载/);
  assert.match(render, /state\.phase === "READY" && state\.items\.length === 0 && !state\.hasMore[\s\S]*当前账号还没有已完成的资金审查/);
  assert.equal((render.match(/disabled=\{busy\}/g) ?? []).length, 3);
  assert.doesNotMatch(component, /items\.length[^\n]*(?:loadInitialPage|retryInitialPage|loadMore|INITIAL_ERROR|PAGINATION_ERROR)/);
});
