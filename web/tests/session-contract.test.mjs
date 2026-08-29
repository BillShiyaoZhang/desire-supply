import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { parseSessionPage } from "../lib/session-contract.mjs";
import {
  createAuthProxyRequest,
  proxyAuthRequest,
} from "../lib/server-proxy.mjs";

const traceId = "trace_session_list_0001";
const cursor = `${"c".repeat(64)}.${"s".repeat(43)}`;
const sessionPage = {
  items: [
    {
      session_id: "10000000-0000-4000-8000-000000000102",
      created_at: "2026-08-24T01:02:03Z",
      last_activity_at: "2026-08-24T02:03:04.123456Z",
      expires_at: "2026-08-25T02:03:04Z",
      is_current: true,
      device_label: "当前浏览器 · macOS",
      status: "ACTIVE",
    },
    {
      session_id: "10000000-0000-4000-8000-000000000103",
      created_at: "2026-08-20T01:02:03Z",
      last_activity_at: "2026-08-20T02:03:04Z",
      expires_at: "2026-08-21T02:03:04Z",
      is_current: false,
      device_label: "旧浏览器",
      status: "REVOKED",
    },
  ],
  page: { next_cursor: cursor },
};

function sessionResponse(body = sessionPage, headers = {}) {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: {
      "cache-control": "no-store",
      "content-type": "application/json",
      "x-trace-id": traceId,
      ...headers,
    },
  });
}

test("SessionPageDto parser reconstructs only the closed safe projection", () => {
  const parsed = parseSessionPage(sessionPage);
  assert.deepEqual(parsed, sessionPage);
  assert.ok(Object.isFrozen(parsed));
  assert.ok(Object.isFrozen(parsed.items));
  assert.ok(Object.isFrozen(parsed.items[0]));

  const invalidPages = [
    { ...sessionPage, internal_session_handle: "secret" },
    { ...sessionPage, page: { ...sessionPage.page, snapshot_at: "2026-08-24T00:00:00Z" } },
    { ...sessionPage, page: { next_cursor: `${"c".repeat(63)}.${"s".repeat(43)}` } },
    { ...sessionPage, items: [{ ...sessionPage.items[0], raw_handle: "secret" }] },
    { ...sessionPage, items: [{ ...sessionPage.items[0], session_id: "session_current_0001" }] },
    { ...sessionPage, items: [{ ...sessionPage.items[0], created_at: "2026-02-30T01:02:03Z" }] },
    { ...sessionPage, items: [{ ...sessionPage.items[0], created_at: "2026-08-24T01:02:03+00:00" }] },
    { ...sessionPage, items: [{ ...sessionPage.items[0], last_activity_at: "2026-08-26T01:02:03Z" }] },
    { ...sessionPage, items: [{ ...sessionPage.items[0], status: "SUSPENDED" }] },
    { ...sessionPage, items: [{ ...sessionPage.items[0], status: "REVOKED" }] },
    { ...sessionPage, items: [sessionPage.items[0], { ...sessionPage.items[0] }] },
    { ...sessionPage, items: [sessionPage.items[0], { ...sessionPage.items[1], is_current: true, status: "ACTIVE" }] },
  ];
  for (const invalid of invalidPages) {
    assert.throws(() => parseSessionPage(invalid), /INVALID_SESSION_PAGE_CONTRACT/);
  }
});

test("session list BFF forwards only the exact optional pagination query and cookie", async () => {
  const plain = await createAuthProxyRequest(new Request(
    "http://localhost:3000/v1/me/sessions",
    { headers: { cookie: "__Host-ds_session=opaque-session" } },
  ), "http://api:8000");
  assert.equal(plain.url, "http://api:8000/v1/me/sessions");
  assert.equal(plain.headers.get("cookie"), "__Host-ds_session=opaque-session");
  assert.equal(plain.headers.get("origin"), "http://api:8000");

  const paged = await createAuthProxyRequest(new Request(
    `http://localhost:3000/v1/me/sessions?limit=100&cursor=${cursor}`,
    { headers: { cookie: "__Host-ds_session=opaque-session" } },
  ), "http://api:8000");
  assert.equal(
    paged.url,
    `http://api:8000/v1/me/sessions?limit=100&cursor=${cursor}`,
  );

  const rejected = [
    "?limit=0",
    "?limit=01",
    "?limit=101",
    "?limit=25&limit=50",
    `?cursor=${cursor}&cursor=${cursor}`,
    `?cursor=${"c".repeat(64)}.${"s".repeat(42)}`,
    "?role=ACCESS_ADMIN",
  ];
  for (const query of rejected) {
    await assert.rejects(
      () => createAuthProxyRequest(
        new Request(`http://localhost:3000/v1/me/sessions${query}`),
        "http://api:8000",
      ),
      /INVALID_SESSION_LIST_REQUEST/,
    );
  }
  for (const headers of [
    { "x-workspace-id": "personal:10000000-0000-4000-8000-000000000102" },
    { "x-role": "ACCESS_ADMIN" },
    { "content-type": "application/json" },
    { "if-match": '"v1"' },
    { "idempotency-key": "session-list-forged-write-0001" },
    { "x-csrf-token": "csrf_token_internal_000000000000001" },
  ]) {
    await assert.rejects(
      () => createAuthProxyRequest(
        new Request("http://localhost:3000/v1/me/sessions", { headers }),
        "http://api:8000",
      ),
      /AUTHORITY_HEADER_FORBIDDEN|INVALID_SESSION_LIST_REQUEST/,
    );
  }
});

test("session list BFF validates and sanitizes the upstream projection and headers", async () => {
  let forwarded;
  const response = await proxyAuthRequest(new Request(
    `http://localhost:3000/v1/me/sessions?limit=25&cursor=${cursor}`,
    { headers: { cookie: "__Host-ds_session=opaque-session" } },
  ), {
    baseUrl: "http://api:8000",
    fetchImpl: async (request) => {
      forwarded = request;
      return sessionResponse(sessionPage, { "x-internal-debug": "must-not-pass" });
    },
  });
  assert.equal(forwarded.headers.get("cookie"), "__Host-ds_session=opaque-session");
  assert.equal(response.status, 200);
  assert.equal(response.headers.get("cache-control"), "no-store");
  assert.equal(response.headers.get("x-trace-id"), traceId);
  assert.equal(response.headers.get("x-internal-debug"), null);
  assert.deepEqual(await response.json(), sessionPage);

  const unsafeBodies = [
    { ...sessionPage, raw_session_handle: "secret" },
    { ...sessionPage, items: [{ ...sessionPage.items[0], ip_address: "127.0.0.1" }] },
    { ...sessionPage, items: [{ ...sessionPage.items[0], is_current: "true" }] },
  ];
  for (const body of unsafeBodies) {
    const rejected = await proxyAuthRequest(
      new Request("http://localhost:3000/v1/me/sessions"),
      { baseUrl: "http://api:8000", fetchImpl: async () => sessionResponse(body) },
    );
    assert.equal(rejected.status, 503);
    assert.equal((await rejected.json()).code, "AUTH_BACKEND_UNAVAILABLE");
  }

  const unsafeHeaders = [
    { "cache-control": "public, max-age=60" },
    { "set-cookie": "__Host-ds_session=forged; Secure; HttpOnly" },
    { etag: '"v1"' },
    { "retry-after": "60" },
    { "x-trace-id": "short" },
    { "content-type": "text/html" },
  ];
  for (const headers of unsafeHeaders) {
    const rejected = await proxyAuthRequest(
      new Request("http://localhost:3000/v1/me/sessions"),
      { baseUrl: "http://api:8000", fetchImpl: async () => sessionResponse(sessionPage, headers) },
    );
    assert.equal(rejected.status, 503);
    assert.equal(rejected.headers.get("set-cookie"), null);
  }
});

test("session list BFF preserves only a closed status-bound IAM error", async () => {
  const error = {
    code: "SESSION_EXPIRED",
    message: "The session has expired.",
    trace_id: traceId,
    field_issues: [],
  };
  const response = await proxyAuthRequest(
    new Request("http://localhost:3000/v1/me/sessions"),
    {
      baseUrl: "http://api:8000",
      fetchImpl: async () => Response.json(error, {
        status: 401,
        headers: { "cache-control": "no-store", "x-trace-id": traceId },
      }),
    },
  );
  assert.equal(response.status, 401);
  assert.deepEqual(await response.json(), error);

  const leaked = await proxyAuthRequest(
    new Request("http://localhost:3000/v1/me/sessions"),
    {
      baseUrl: "http://api:8000",
      fetchImpl: async () => Response.json({ ...error, internal_reason: "secret" }, {
        status: 401,
        headers: { "cache-control": "no-store", "x-trace-id": traceId },
      }),
    },
  );
  assert.equal(leaked.status, 503);
});

test("the session collection route is GET-only and does not alter DELETE logout", async () => {
  const route = await readFile(
    new URL("../app/v1/me/sessions/route.ts", import.meta.url),
    "utf8",
  );
  assert.match(route, /export function GET/);
  assert.doesNotMatch(route, /export (?:function|const) DELETE/);
  assert.match(route, /proxyAuthRequest/);
});
