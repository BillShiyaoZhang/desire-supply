import assert from "node:assert/strict";
import test from "node:test";

import {
  createActionIntent,
  createResetIntent,
  createSessionIntent,
  parseBootstrap,
  parsePersonas,
} from "../lib/local-contract.mjs";
import {
  createAppProxyRequest,
  createAuthProxyRequest,
  createLoopbackProxyRequest,
  parseLoopbackBaseUrl,
  proxyAppRequest,
  proxyAuthRequest,
} from "../lib/server-proxy.mjs";

const personaFixture = {
  personas: [
    {
      persona_id: "creator-chen",
      display_name: "陈澄",
      workspace_label: "个人创作者",
      summary: "处理邀请、协议与交付",
    },
  ],
};

const bootstrapFixture = {
  session: { session_id: "session-1", persona_id: "creator-chen", expires_at: "2026-08-12T20:00:00+08:00" },
  user: { user_id: "user-chen", display_name: "陈澄" },
  workspaces: [{ workspace_id: "creator", label: "个人创作者", kind: "CREATOR", authorities: ["CREATOR_SELF"] }],
  current_workspace_id: "creator",
  tasks: [{
    task_id: "task-1",
    title: "回应项目邀请",
    summary: "决定是否参与，不会因为拒绝降低未来资格。",
    status: "NEEDS_ACTION",
    object_id: "invitation-1",
    object_type: "INVITATION",
    authority: "CREATOR_SELF",
    due_at: "2026-08-14T10:00:00Z",
    allowed_operations: ["respond_invitation"],
  }],
  workflow: {
    current_stage: "INVITATION",
    stages: [{ stage: "INVITATION", label: "邀请与决定", status: "CURRENT" }],
  },
  object: {
    object_id: "invitation-1",
    type: "INVITATION",
    title: "无障碍社区活动信息包",
    status: "INVITED",
    version: 1,
    facts: [{ label: "报酬", value: "合成 CNY 6,800" }],
    timeline: [],
  },
  allowed_operations: [{
    operation: "respond_invitation",
    label: "回应邀请",
    kind: "DECISION",
    fields: [{ name: "decision", label: "你的决定", type: "choice", required: true, options: [
      { value: "ACCEPTED", label: "接受邀请" },
      { value: "DECLINED", label: "拒绝邀请" },
    ] }],
  }],
  csrf: "csrf-memory-only",
  revision: 3,
};

test("accepts the closed persona and bootstrap projections", () => {
  assert.deepEqual(parsePersonas(personaFixture), personaFixture);
  assert.deepEqual(parseBootstrap(bootstrapFixture), bootstrapFixture);
  assert.throws(() => parsePersonas({ personas: [{ persona_id: "creator-chen", actor: "forged" }] }), /INVALID_LOCAL_CONTRACT/);
  assert.throws(() => parseBootstrap({ ...bootstrapFixture, csrf: "" }), /INVALID_LOCAL_CONTRACT/);
});

test("authentication BFF keeps OIDC callback query closed and admits only same-origin redirects", async () => {
  const session = await createAuthProxyRequest(
    new Request("http://localhost:3000/v1/auth/session", { headers: { cookie: "__Host-ds_session=opaque" } }),
    "http://api:8000",
  );
  assert.equal(session.url, "http://api:8000/v1/auth/session");
  assert.equal(session.headers.get("cookie"), "__Host-ds_session=opaque");
  const me = await createAuthProxyRequest(
    new Request("http://localhost:3000/v1/me", { headers: { cookie: "__Host-ds_session=opaque" } }),
    "http://api:8000",
  );
  assert.equal(me.url, "http://api:8000/v1/me");

  const callbackUrl = new URL("http://localhost:3000/v1/auth/oidc/callback");
  callbackUrl.searchParams.set("state", "s".repeat(32));
  callbackUrl.searchParams.set("code", "c".repeat(32));
  const callback = await createAuthProxyRequest(new Request(callbackUrl), "http://api:8000");
  assert.equal(callback.url, `http://api:8000/v1/auth/oidc/callback?state=${"s".repeat(32)}&code=${"c".repeat(32)}`);

  for (const url of [
    "http://localhost:3000/v1/auth/oidc/callback?state=short&code=short",
    `http://localhost:3000/v1/auth/oidc/callback?state=${"s".repeat(32)}&code=${"c".repeat(32)}&role=admin`,
    `http://localhost:3000/v1/auth/oidc/callback?state=${"s".repeat(32)}&code=${"c".repeat(32)}&error=access_denied`,
    "http://localhost:3000/v1/auth/session?role=admin",
    "http://localhost:3000/v1/me?role=admin",
  ]) await assert.rejects(() => createAuthProxyRequest(new Request(url), "http://api:8000"), /AUTH_ROUTE_NOT_ALLOWED/);

  const allowedRedirect = await proxyAuthRequest(new Request(callbackUrl), {
    baseUrl: "http://api:8000",
    fetchImpl: async () => new Response(null, { status: 303, headers: { location: "/?signed_in=1", "set-cookie": "__Host-ds_session=opaque; Secure; HttpOnly" } }),
  });
  assert.equal(allowedRedirect.status, 303);
  assert.equal(allowedRedirect.headers.get("location"), "/?signed_in=1");
  assert.match(allowedRedirect.headers.get("set-cookie") ?? "", /__Host-ds_session/);

  const externalRedirect = await proxyAuthRequest(new Request(callbackUrl), {
    baseUrl: "http://api:8000",
    fetchImpl: async () => new Response(null, { status: 303, headers: { location: "https://attacker.invalid" } }),
  });
  assert.equal(externalRedirect.status, 503);
  assert.equal((await externalRedirect.json()).code, "AUTH_BACKEND_UNAVAILABLE");
});

test("policy BFF admits only exact immutable reads and closed self-acceptance writes", async () => {
  const bundle = await createAuthProxyRequest(
    new Request("http://localhost:3000/v1/policy-bundles/policy_bundle_creator_0001"),
    "http://api:8000",
  );
  assert.equal(bundle.url, "http://api:8000/v1/policy-bundles/policy_bundle_creator_0001");

  const body = {
    policy_requirement: {
      selector_digest: "a".repeat(64),
      scope_type: "USER_ROLE",
      scope_id: null,
    },
    policy_bundle_id: "policy_bundle_creator_0001",
    policy_acceptances: [{
      document_id: "policy_document_terms_0001",
      content_sha256: "b".repeat(64),
      affirmed: true,
    }],
  };
  const acceptance = await createAuthProxyRequest(new Request(
    "http://localhost:3000/v1/me/policy-acceptances",
    {
      method: "POST",
      headers: {
        cookie: "__Host-ds_session=opaque",
        "content-type": "application/json",
        "if-match": '"v3"',
        "idempotency-key": "policy-acceptance-idempotency-0001",
        "x-csrf-token": "csrf_token_internal_000000000000001",
      },
      body: JSON.stringify(body),
    },
  ), "http://api:8000");
  assert.equal(acceptance.url, "http://api:8000/v1/me/policy-acceptances");
  assert.equal(acceptance.headers.get("if-match"), '"v3"');
  assert.equal(acceptance.headers.get("idempotency-key"), "policy-acceptance-idempotency-0001");
  assert.deepEqual(await acceptance.json(), body);

  for (const source of [
    new Request("http://localhost:3000/v1/me/policy-acceptances", {
      method: "POST",
      headers: { "content-type": "application/json", "x-workspace-id": "personal:10000000-0000-4000-8000-000000000001" },
      body: JSON.stringify(body),
    }),
    new Request("http://localhost:3000/v1/me/policy-acceptances", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ ...body, role: "CREATOR" }),
    }),
    new Request("http://localhost:3000/v1/me/policy-acceptances", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ ...body, actor_id: "forged" }),
    }),
    new Request("http://localhost:3000/v1/me/policy-acceptances?role=CREATOR", { method: "POST" }),
    new Request("http://localhost:3000/v1/policy-bundles/policy_bundle_creator_0001", { method: "POST" }),
    new Request("http://localhost:3000/v1/policy-bundles/policy%2Fbundle_creator_0001"),
  ]) await assert.rejects(
    () => createAuthProxyRequest(source, "http://api:8000"),
    /AUTH_ROUTE_NOT_ALLOWED|AUTHORITY_HEADER_FORBIDDEN|INVALID_POLICY_ACCEPTANCE_REQUEST/,
  );
});

test("session logout BFF admits only exact current-Session DELETE and proven cookie clear", async () => {
  const sessionId = "10000000-0000-4000-8000-000000000102";
  const url = `http://localhost:3000/v1/me/sessions/${sessionId}`;
  const headers = {
    accept: "application/json",
    cookie: `__Host-ds_session=${"s".repeat(32)}`,
    "idempotency-key": "logout-current-session-0001",
    "x-bootstrap-session-id": sessionId,
    "x-csrf-token": "csrf_token_internal_000000000000001",
  };
  const logout = await createAuthProxyRequest(
    new Request(url, { method: "DELETE", headers }),
    "http://api:8000",
  );
  assert.equal(logout.url, `http://api:8000/v1/me/sessions/${sessionId}`);
  assert.equal(logout.method, "DELETE");
  assert.equal(logout.headers.get("idempotency-key"), "logout-current-session-0001");
  assert.equal(logout.headers.get("x-bootstrap-session-id"), null);
  assert.equal(logout.headers.get("x-csrf-token"), "csrf_token_internal_000000000000001");
  assert.equal(logout.body, null);

  // Vinext can represent a payload-free DELETE as a non-null stream that
  // yields zero bytes.  Admit that runtime shape, but never forward the
  // synthetic empty stream (or its transport-only Content-Length).
  const runtimeShapedSource = new Request(url, {
    method: "DELETE",
    headers: { ...headers, "content-length": "0" },
    body: new Uint8Array(0),
  });
  assert.notEqual(runtimeShapedSource.body, null);
  const runtimeShapedLogout = await createAuthProxyRequest(
    runtimeShapedSource,
    "http://api:8000",
  );
  assert.equal(runtimeShapedLogout.body, null);
  assert.equal(runtimeShapedLogout.headers.get("content-length"), null);

  for (const source of [
    new Request(url, { method: "DELETE", headers: { cookie: headers.cookie } }),
    new Request(url, { method: "DELETE", headers: { ...headers, "x-bootstrap-session-id": "not-a-session" } }),
    new Request(url, { method: "DELETE", headers: { ...headers, "x-workspace-id": `personal:${sessionId}` } }),
    new Request(`${url}?all=true`, { method: "DELETE", headers }),
    new Request("http://localhost:3000/v1/me/sessions/00000000-0000-0000-0000-000000000000", { method: "DELETE", headers }),
    new Request("http://localhost:3000/v1/me/sessions/10000000-0000-4000-8000-000000000102/revoke-all", { method: "DELETE", headers }),
    new Request(url, { method: "POST", headers }),
    new Request(url, { method: "DELETE", headers: { ...headers, "content-type": "application/json" }, body: "{}" }),
    new Request(url, { method: "DELETE", headers, body: Uint8Array.of(1) }),
    new Request(url, { method: "DELETE", headers: { ...headers, "content-length": "1" }, body: new Uint8Array(0) }),
  ]) await assert.rejects(
    () => createAuthProxyRequest(source, "http://api:8000"),
    /AUTH_ROUTE_NOT_ALLOWED|AUTHORITY_HEADER_FORBIDDEN|INVALID_SESSION_LOGOUT_REQUEST/,
  );

  const clearCookie = "__Host-ds_session=; Secure; HttpOnly; SameSite=Lax; Path=/; Max-Age=0";
  const success = await proxyAuthRequest(new Request(url, { method: "DELETE", headers }), {
    baseUrl: "http://api:8000",
    fetchImpl: async () => new Response(null, { status: 204, headers: { "set-cookie": clearCookie } }),
  });
  assert.equal(success.status, 204);
  assert.equal(success.headers.get("set-cookie"), clearCookie);

  const missingCurrentClear = await proxyAuthRequest(new Request(url, { method: "DELETE", headers }), {
    baseUrl: "http://api:8000",
    fetchImpl: async () => new Response(null, { status: 204 }),
  });
  assert.equal(missingCurrentClear.status, 503);
  assert.equal(missingCurrentClear.headers.get("set-cookie"), null);

  const unproven = await proxyAuthRequest(new Request(url, { method: "DELETE", headers }), {
    baseUrl: "http://api:8000",
    fetchImpl: async () => new Response(null, { status: 204, headers: { "set-cookie": "__Host-ds_session=forged" } }),
  });
  assert.equal(unproven.status, 503);
  assert.equal(unproven.headers.get("set-cookie"), null);

  const unauthorized = await proxyAuthRequest(new Request(url, { method: "DELETE", headers }), {
    baseUrl: "http://api:8000",
    fetchImpl: async () => Response.json(
      { error: { code: "SESSION_EXPIRED" } },
      { status: 401, headers: { "set-cookie": clearCookie } },
    ),
  });
  assert.equal(unauthorized.status, 401);
  assert.equal(unauthorized.headers.get("set-cookie"), null);

  const relogin = await createAuthProxyRequest(new Request(
    "http://localhost:3000/v1/auth/oidc/authorizations",
    {
      method: "POST",
      headers: { cookie: headers.cookie, "content-type": "application/json" },
      body: JSON.stringify({ return_to: "/app" }),
    },
  ), "http://api:8000");
  assert.equal(relogin.url, "http://api:8000/v1/auth/oidc/authorizations");
  assert.deepEqual(await relogin.json(), { return_to: "/app" });
});

test("other owned Session DELETE preserves the bootstrap cookie and rejects every cookie mutation", async () => {
  const bootstrapSessionId = "10000000-0000-4000-8000-000000000102";
  const targetSessionId = "10000000-0000-4000-8000-000000000103";
  const url = `http://localhost:3000/v1/me/sessions/${targetSessionId}`;
  const headers = {
    accept: "application/json",
    cookie: `__Host-ds_session=${"s".repeat(32)}`,
    "idempotency-key": "revoke-other-session-0001",
    "x-bootstrap-session-id": bootstrapSessionId,
    "x-csrf-token": "csrf_token_internal_000000000000001",
  };
  const proxied = await createAuthProxyRequest(
    new Request(url, { method: "DELETE", headers }),
    "http://api:8000",
  );
  assert.equal(proxied.url, `http://api:8000/v1/me/sessions/${targetSessionId}`);
  assert.equal(proxied.headers.get("x-bootstrap-session-id"), null);
  assert.equal(proxied.body, null);

  const success = await proxyAuthRequest(new Request(url, { method: "DELETE", headers }), {
    baseUrl: "http://api:8000",
    fetchImpl: async () => new Response(null, { status: 204 }),
  });
  assert.equal(success.status, 204);
  assert.equal(success.headers.get("set-cookie"), null);

  const clearCookie = "__Host-ds_session=; Secure; HttpOnly; SameSite=Lax; Path=/; Max-Age=0";
  for (const setCookie of [clearCookie, "__Host-ds_session=forged; Secure; HttpOnly"]) {
    const rejected = await proxyAuthRequest(new Request(url, { method: "DELETE", headers }), {
      baseUrl: "http://api:8000",
      fetchImpl: async () => new Response(null, { status: 204, headers: { "set-cookie": setCookie } }),
    });
    assert.equal(rejected.status, 503);
    assert.equal(rejected.headers.get("set-cookie"), null);
  }

  const wrongSuccessStatus = await proxyAuthRequest(new Request(url, { method: "DELETE", headers }), {
    baseUrl: "http://api:8000",
    fetchImpl: async () => Response.json({}, { status: 200 }),
  });
  assert.equal(wrongSuccessStatus.status, 503);
  assert.equal(wrongSuccessStatus.headers.get("set-cookie"), null);
});

test("finance BFF admits only the closed synthetic four-eyes workflow", async () => {
  const workspace = "platform:74000000-0000-4000-8000-000000000001";
  const demandId = "75000000-0000-4000-8000-000000000001";
  const reviewId = "76000000-0000-4000-8000-000000000001";
  const commonHeaders = {
    "content-type": "application/json",
    "idempotency-key": "finance-write-idempotency-0001",
    "x-csrf-token": "csrf_token_internal_000000000000001",
    "x-workspace-id": workspace,
  };
  const queue = await createAppProxyRequest(new Request(
    "http://localhost:3000/v1/app/finance/funding-reviews",
    { headers: { "x-workspace-id": workspace } },
  ), "http://api:8000");
  assert.equal(queue.url, "http://api:8000/v1/app/finance/funding-reviews");
  const detail = await createAppProxyRequest(new Request(
    `http://localhost:3000/v1/app/finance/funding-reviews/${reviewId}`,
    { headers: { "x-workspace-id": workspace } },
  ), "http://api:8000");
  assert.equal(detail.url, `http://api:8000/v1/app/finance/funding-reviews/${reviewId}`);
  const claim = await createAppProxyRequest(new Request(
    `http://localhost:3000/v1/app/finance/funding-reviews/${demandId}/claim`,
    {
      method: "POST",
      headers: { ...commonHeaders, "if-match": '"demand-3-finance-queue"' },
      body: "{}",
    },
  ), "http://api:8000");
  assert.deepEqual(await claim.json(), {});
  const confirmBody = {
    attestation_codes: [
      "SYNTHETIC_ONLY", "ZERO_REAL_FUNDS", "NO_PROVIDER_OR_PAYMENT",
      "TARGET_AND_EVIDENCE_MATCH",
    ],
  };
  const confirm = await createAppProxyRequest(new Request(
    `http://localhost:3000/v1/app/finance/funding-reviews/${reviewId}/confirm`,
    {
      method: "POST",
      headers: { ...commonHeaders, "if-match": '"funding-review-1"' },
      body: JSON.stringify(confirmBody),
    },
  ), "http://api:8000");
  assert.deepEqual(await confirm.json(), confirmBody);
  const release = await createAppProxyRequest(new Request(
    `http://localhost:3000/v1/app/finance/funding-reviews/${reviewId}/assignment/release`,
    {
      method: "POST",
      headers: { ...commonHeaders, "if-match": '"funding-review-1"' },
      body: JSON.stringify({ reason_code: "WORKLOAD_RELEASE" }),
    },
  ), "http://api:8000");
  assert.deepEqual(await release.json(), { reason_code: "WORKLOAD_RELEASE" });
  const findingBody = {
    disposition: "REJECTED",
    reason_codes: ["BUDGET_PLAN_UNACCEPTABLE"],
    required_field_codes: ["BUDGET", "SCOPE"],
  };
  const finding = await createAppProxyRequest(new Request(
    `http://localhost:3000/v1/app/finance/funding-reviews/${reviewId}/findings`,
    {
      method: "POST",
      headers: { ...commonHeaders, "if-match": '"funding-review-1"' },
      body: JSON.stringify(findingBody),
    },
  ), "http://api:8000");
  assert.deepEqual(await finding.json(), findingBody);

  for (const source of [
    new Request("http://localhost:3000/v1/app/finance/funding-reviews?actor=forged", {
      headers: { "x-workspace-id": workspace },
    }),
    new Request(`http://localhost:3000/v1/app/finance/funding-reviews/${reviewId}/confirm`, {
      method: "POST",
      headers: { ...commonHeaders, "if-match": '"funding-review-1"' },
      body: JSON.stringify({ ...confirmBody, funded: true }),
    }),
    new Request(`http://localhost:3000/v1/app/finance/funding-reviews/${reviewId}/confirm`, {
      method: "POST",
      headers: { ...commonHeaders, "if-match": '"funding-review-1"', "x-role": "FINANCE_OPERATOR" },
      body: JSON.stringify(confirmBody),
    }),
    new Request(`http://localhost:3000/v1/app/finance/funding-reviews/${reviewId}/confirm`, {
      method: "POST",
      headers: { ...commonHeaders, "if-match": '"funding-review-1"' },
      body: JSON.stringify({ attestation_codes: ["SYNTHETIC_ONLY"] }),
    }),
    new Request(`http://localhost:3000/v1/app/finance/funding-reviews/${reviewId}/assignment/release`, {
      method: "POST",
      headers: { ...commonHeaders, "if-match": '"funding-review-1"' },
      body: JSON.stringify({ reason_code: "FREE_TEXT" }),
    }),
    new Request(`http://localhost:3000/v1/app/finance/funding-reviews/${reviewId}/findings`, {
      method: "POST",
      headers: { ...commonHeaders, "if-match": '"funding-review-1"' },
      body: JSON.stringify({ ...findingBody, disposition: "DISCREPANCY" }),
    }),
    new Request(`http://localhost:3000/v1/app/finance/funding-reviews/${reviewId}/findings`, {
      method: "POST",
      headers: { ...commonHeaders, "if-match": '"funding-review-1"' },
      body: JSON.stringify({ ...findingBody, actor_user_id: reviewId }),
    }),
  ]) await assert.rejects(
    () => createAppProxyRequest(source, "http://api:8000"),
    /APP_ROUTE_NOT_ALLOWED|AUTHORITY_HEADER_FORBIDDEN|INVALID_FINANCE_FUNDING_REQUEST/,
  );
});

test("session intent contains only the server-issued persona identifier", () => {
  assert.deepEqual(createSessionIntent("creator-chen"), { persona_id: "creator-chen" });
  assert.deepEqual(createSessionIntent("finance-reconciler"), { persona_id: "finance-reconciler" });
  assert.throws(() => createSessionIntent("../../operator"), /INVALID_PERSONA_ID/);
  assert.throws(() => createSessionIntent("invented-admin"), /INVALID_PERSONA_ID/);
});

test("action intent is capability-bound and cannot carry identity or authority", () => {
  const intent = createActionIntent({
    operation: "respond_invitation",
    expectedRevision: 3,
    idempotencyKey: "3fe8c877-6992-4fc5-99d2-4a5bb64fd3df",
    input: { decision: "DECLINED" },
    allowedOperations: bootstrapFixture.allowed_operations,
  });
  assert.deepEqual(intent, {
    operation: "respond_invitation",
    expected_revision: 3,
    idempotency_key: "3fe8c877-6992-4fc5-99d2-4a5bb64fd3df",
    input: { decision: "DECLINED" },
  });
  assert.throws(() => createActionIntent({
    operation: "reconcile_payment",
    expectedRevision: 3,
    idempotencyKey: "3fe8c877-6992-4fc5-99d2-4a5bb64fd3df",
    input: {},
    allowedOperations: bootstrapFixture.allowed_operations,
  }), /OPERATION_NOT_ALLOWED/);
  for (const forbidden of ["actor", "actor_id", "authority", "organization", "organization_id", "workspace_id", "persona_id"]) {
    assert.throws(() => createActionIntent({
      operation: "respond_invitation",
      expectedRevision: 3,
      idempotencyKey: "3fe8c877-6992-4fc5-99d2-4a5bb64fd3df",
      input: { [forbidden]: "forged" },
      allowedOperations: bootstrapFixture.allowed_operations,
    }), /FORBIDDEN_ACTION_FIELD/);
  }
});

test("reset intent is fixed to the approved synthetic fixture and current revision", () => {
  assert.deepEqual(createResetIntent({
    expectedRevision: 3,
    idempotencyKey: "3fe8c877-6992-4fc5-99d2-4a5bb64fd3df",
  }), {
    fixture_id: "scn-g1-001-happy-v1",
    expected_revision: 3,
    idempotency_key: "3fe8c877-6992-4fc5-99d2-4a5bb64fd3df",
  });
});

test("BFF accepts only loopback or the exact container API origin and closed local routes", async () => {
  assert.equal(parseLoopbackBaseUrl("http://127.0.0.1:8000").origin, "http://127.0.0.1:8000");
  assert.equal(parseLoopbackBaseUrl("http://[::1]:8000").origin, "http://[::1]:8000");
  assert.equal(parseLoopbackBaseUrl("http://api:8000").origin, "http://api:8000");
  for (const value of [
    "http://localhost:8000",
    "https://127.0.0.1:8000",
    "http://127.0.0.2:8000",
    "http://127.0.0.1:8000/base",
    "http://user:pass@127.0.0.1:8000",
    "http://api:8001",
    "http://api.:8000",
    "http://api:8000/base",
    "https://api:8000",
    "https://example.com",
  ]) assert.throws(() => parseLoopbackBaseUrl(value), /INVALID_LOOPBACK_BASE_URL/);

  const source = new Request("http://localhost:3000/v1/local/session", {
    method: "POST",
    headers: {
      accept: "application/json",
      "content-type": "application/json",
      cookie: "__Host-ds_session=opaque",
      origin: "https://attacker.invalid",
      host: "attacker.invalid",
      forwarded: "for=203.0.113.10;host=attacker.invalid",
      "x-forwarded-host": "attacker.invalid",
      "x-forwarded-proto": "https",
      "x-csrf-token": "csrf",
      "x-untrusted": "must-not-pass",
    },
    body: JSON.stringify({ persona_id: "creator-chen" }),
  });
  const proxied = await createLoopbackProxyRequest(source, "http://127.0.0.1:8000");
  assert.equal(proxied.url, "http://127.0.0.1:8000/v1/local/session");
  assert.equal(proxied.headers.get("cookie"), "__Host-ds_session=opaque");
  assert.equal(proxied.headers.get("x-csrf-token"), "csrf");
  assert.equal(proxied.headers.get("origin"), "http://127.0.0.1:8000");
  assert.equal(proxied.headers.get("host"), null);
  assert.equal(proxied.headers.get("forwarded"), null);
  assert.equal(proxied.headers.get("x-forwarded-host"), null);
  assert.equal(proxied.headers.get("x-forwarded-proto"), null);
  assert.equal(proxied.headers.get("x-untrusted"), null);

  await assert.rejects(() => createLoopbackProxyRequest(
    new Request("http://localhost:3000/v1/local/personas", { method: "POST" }),
    "http://127.0.0.1:8000",
  ), /LOCAL_ROUTE_NOT_ALLOWED/);
});

test("internal-pilot BFF admits only the exact /v1/app editor routes", async () => {
  const discovery = await createAppProxyRequest(
    new Request("http://localhost:3000/v1/app/workspaces", {
      headers: { cookie: "__Host-ds_session=opaque" },
    }),
    "http://api:8000",
  );
  assert.equal(discovery.url, "http://api:8000/v1/app/workspaces");
  assert.equal(discovery.headers.get("cookie"), "__Host-ds_session=opaque");
  assert.equal(discovery.headers.get("x-workspace-id"), null);

  await assert.rejects(
    () => createAppProxyRequest(
      new Request("http://localhost:3000/v1/app/workspaces", {
        headers: { "x-workspace-id": "personal:10000000-0000-4000-8000-000000000001" },
      }),
      "http://api:8000",
    ),
    /WORKSPACE_HEADER_FORBIDDEN/,
  );
  await assert.rejects(
    () => createAppProxyRequest(
      new Request("http://localhost:3000/v1/app/workspaces", {
        headers: { "x-workspace-id": "not-even-an-id" },
      }),
      "http://api:8000",
    ),
    /WORKSPACE_HEADER_FORBIDDEN/,
  );
  for (const request of [
    new Request("http://localhost:3000/v1/app/workspaces", { method: "POST" }),
    new Request("http://localhost:3000/v1/app/workspaces?role=CREATOR"),
  ]) await assert.rejects(() => createAppProxyRequest(request, "http://api:8000"), /APP_ROUTE_NOT_ALLOWED/);
  await assert.rejects(
    () => createAppProxyRequest(new Request("http://localhost:3000/v1/app/demands"), "http://api:8000"),
    /WORKSPACE_REQUIRED/,
  );

  const configuration = await createAppProxyRequest(
    new Request("http://localhost:3000/v1/app/configuration", {
      headers: {
        cookie: "__Host-ds_session=opaque",
        "x-workspace-id": "personal:10000000-0000-4000-8000-000000000001",
      },
    }),
    "http://api:8000",
  );
  assert.equal(configuration.url, "http://api:8000/v1/app/configuration");
  assert.equal(
    configuration.headers.get("x-workspace-id"),
    "personal:10000000-0000-4000-8000-000000000001",
  );

  const source = new Request("http://localhost:3000/v1/app/demands/demand_internal_0000001/draft", {
    method: "PUT",
    headers: {
      accept: "application/json",
      "content-type": "application/json",
      cookie: "__Host-ds_session=opaque",
      origin: "https://attacker.invalid",
      "if-match": '"DEMAND:demand_internal_0000001:v2"',
      "idempotency-key": "idempotency-demand-0000001",
      "x-csrf-token": "csrf_token_internal_000000000000001",
      "x-workspace-id": "org:81000000-0000-4000-8000-000000000001",
      authorization: "Bearer must-not-pass",
    },
    body: JSON.stringify({ base_version_id: "version_internal_00000001", taxonomy_bundle_id: "taxonomy_internal_00001", content: {} }),
  });
  const proxied = await createAppProxyRequest(source, "http://api:8000");
  assert.equal(proxied.url, "http://api:8000/v1/app/demands/demand_internal_0000001/draft");
  assert.equal(proxied.headers.get("origin"), "http://api:8000");
  assert.equal(proxied.headers.get("cookie"), "__Host-ds_session=opaque");
  assert.equal(proxied.headers.get("if-match"), '"DEMAND:demand_internal_0000001:v2"');
  assert.equal(
    proxied.headers.get("x-workspace-id"),
    "org:81000000-0000-4000-8000-000000000001",
  );
  assert.equal(proxied.headers.get("authorization"), null);

  const platformWorkspace = await createAppProxyRequest(
    new Request("http://localhost:3000/v1/app/demands", {
      headers: {
        "x-workspace-id": "platform:10000000-0000-4000-8000-000000000001",
      },
    }),
    "http://api:8000",
  );
  assert.equal(
    platformWorkspace.headers.get("x-workspace-id"),
    "platform:10000000-0000-4000-8000-000000000001",
  );

  const reviewWorkspace = "platform:10000000-0000-4000-8000-000000000001";
  const reviewDemandId = "30000000-0000-4000-8000-000000000025";
  const reviewAssignmentId = "40000000-0000-4000-8000-000000000025";
  const reviewQueue = await createAppProxyRequest(new Request(
    "http://localhost:3000/v1/app/review-queue",
    { headers: { "x-workspace-id": reviewWorkspace } },
  ), "http://api:8000");
  assert.equal(reviewQueue.url, "http://api:8000/v1/app/review-queue");

  const claimedReview = await createAppProxyRequest(new Request(
    `http://localhost:3000/v1/app/review-queue/${reviewDemandId}/claim`,
    {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "if-match": '"demand-2-review-queue"',
        "idempotency-key": "review-claim-idempotency-0001",
        "x-csrf-token": "csrf_token_internal_000000000000001",
        "x-workspace-id": reviewWorkspace,
      },
      body: "{}",
    },
  ), "http://api:8000");
  assert.equal(claimedReview.url, `http://api:8000/v1/app/review-queue/${reviewDemandId}/claim`);
  assert.deepEqual(await claimedReview.json(), {});

  const verifiedReview = await createAppProxyRequest(new Request(
    `http://localhost:3000/v1/app/demands/${reviewDemandId}/review-assignments/${reviewAssignmentId}/verify`,
    {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "if-match": '"demand-2-bbbbbbbbbbbbbbbbbbbbbbbb"',
        "idempotency-key": "review-verify-idempotency-0001",
        "x-csrf-token": "csrf_token_internal_000000000000001",
        "x-workspace-id": reviewWorkspace,
      },
      body: JSON.stringify({
        budget_health_code: "HEALTHY",
        risk_code: "STANDARD",
        evidence_codes: ["SCOPE_COMPLETE", "ACCEPTANCE_TESTABLE"],
      }),
    },
  ), "http://api:8000");
  assert.equal(
    verifiedReview.url,
    `http://api:8000/v1/app/demands/${reviewDemandId}/review-assignments/${reviewAssignmentId}/verify`,
  );

  const releasedReview = await createAppProxyRequest(new Request(
    `http://localhost:3000/v1/app/demands/${reviewDemandId}/review-assignments/${reviewAssignmentId}/release`,
    {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "if-match": '"demand-2-bbbbbbbbbbbbbbbbbbbbbbbb"',
        "idempotency-key": "review-release-idempotency-001",
        "x-csrf-token": "csrf_token_internal_000000000000001",
        "x-workspace-id": reviewWorkspace,
      },
      body: JSON.stringify({ reason_code: "WORKLOAD_RELEASE" }),
    },
  ), "http://api:8000");
  assert.equal(
    releasedReview.url,
    `http://api:8000/v1/app/demands/${reviewDemandId}/review-assignments/${reviewAssignmentId}/release`,
  );
  assert.deepEqual(await releasedReview.json(), { reason_code: "WORKLOAD_RELEASE" });

  for (const request of [
    new Request("http://localhost:3000/v1/app/review-queue?organization_id=forged", {
      headers: { "x-workspace-id": reviewWorkspace },
    }),
    new Request(`http://localhost:3000/v1/app/review-queue/${reviewDemandId}/claim`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "if-match": '"demand-2-review-queue"',
        "idempotency-key": "review-claim-idempotency-0001",
        "x-csrf-token": "csrf_token_internal_000000000000001",
        "x-workspace-id": reviewWorkspace,
      },
      body: JSON.stringify({ reviewer_user_id: "forged" }),
    }),
    new Request(`http://localhost:3000/v1/app/review-queue/${reviewDemandId}/claim`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "if-match": '"demand-2-review-queue"',
        "idempotency-key": "review-claim-idempotency-0001",
        "x-csrf-token": "csrf_token_internal_000000000000001",
        "x-workspace-id": reviewWorkspace,
        "x-actor-id": "forged",
      },
      body: "{}",
    }),
    new Request(`http://localhost:3000/v1/app/demands/${reviewDemandId}/review-assignments/${reviewAssignmentId}/verify`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "if-match": '"demand-2-review-queue"',
        "idempotency-key": "review-verify-idempotency-0001",
        "x-csrf-token": "csrf_token_internal_000000000000001",
        "x-workspace-id": reviewWorkspace,
      },
      body: JSON.stringify({
        budget_health_code: "HEALTHY",
        risk_code: "STANDARD",
        evidence_codes: ["SCOPE_COMPLETE"],
      }),
    }),
    new Request(`http://localhost:3000/v1/app/demands/${reviewDemandId}/review-assignments/${reviewAssignmentId}/verify`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "if-match": '"demand-2-bbbbbbbbbbbbbbbbbbbbbbbb"',
        "idempotency-key": "review-verify-idempotency-0001",
        "x-csrf-token": "csrf_token_internal_000000000000001",
        "x-workspace-id": reviewWorkspace,
        "x-authority": "OPERATIONS_REVIEWER",
      },
      body: JSON.stringify({
        budget_health_code: "HEALTHY",
        risk_code: "STANDARD",
        evidence_codes: ["SCOPE_COMPLETE"],
      }),
    }),
    new Request(`http://localhost:3000/v1/app/demands/${reviewDemandId}/review-assignments/${reviewAssignmentId}/verify`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "if-match": '"demand-2-bbbbbbbbbbbbbbbbbbbbbbbb"',
        "idempotency-key": "review-verify-idempotency-0001",
        "x-csrf-token": "csrf_token_internal_000000000000001",
        "x-workspace-id": reviewWorkspace,
      },
      body: JSON.stringify({
        budget_health_code: "HEALTHY",
        risk_code: "STANDARD",
        evidence_codes: ["SCOPE_COMPLETE"],
        evidence_summary_sha256: "0".repeat(64),
      }),
    }),
    new Request(`http://localhost:3000/v1/app/demands/${reviewDemandId}/review-assignments/${reviewAssignmentId}/release`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "if-match": '"demand-2-review-queue"',
        "idempotency-key": "review-release-idempotency-001",
        "x-csrf-token": "csrf_token_internal_000000000000001",
        "x-workspace-id": reviewWorkspace,
      },
      body: JSON.stringify({ reason_code: "WORKLOAD_RELEASE" }),
    }),
    new Request(`http://localhost:3000/v1/app/demands/${reviewDemandId}/review-assignments/${reviewAssignmentId}/release`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "if-match": '"demand-2-bbbbbbbbbbbbbbbbbbbbbbbb"',
        "idempotency-key": "review-release-idempotency-001",
        "x-csrf-token": "csrf_token_internal_000000000000001",
        "x-workspace-id": reviewWorkspace,
      },
      body: JSON.stringify({ reason_code: "ASSIGNMENT_EXPIRED" }),
    }),
    new Request(`http://localhost:3000/v1/app/demands/${reviewDemandId}/review-assignments/${reviewAssignmentId}/release`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "if-match": '"demand-2-bbbbbbbbbbbbbbbbbbbbbbbb"',
        "idempotency-key": "review-release-idempotency-001",
        "x-csrf-token": "csrf_token_internal_000000000000001",
        "x-workspace-id": reviewWorkspace,
      },
      body: "{}",
    }),
    new Request(`http://localhost:3000/v1/app/demands/${reviewDemandId}/review-assignments/${reviewAssignmentId}/release?actor=forged`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "if-match": '"demand-2-bbbbbbbbbbbbbbbbbbbbbbbb"',
        "idempotency-key": "review-release-idempotency-001",
        "x-csrf-token": "csrf_token_internal_000000000000001",
        "x-workspace-id": reviewWorkspace,
      },
      body: JSON.stringify({ reason_code: "CONFLICT_DECLARED" }),
    }),
    new Request(`http://localhost:3000/v1/app/demands/${reviewDemandId}/review-assignments/${reviewAssignmentId}/release`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "if-match": '"demand-2-bbbbbbbbbbbbbbbbbbbbbbbb"',
        "idempotency-key": "review-release-idempotency-001",
        "x-csrf-token": "csrf_token_internal_000000000000001",
        "x-workspace-id": reviewWorkspace,
      },
      body: JSON.stringify({ reason_code: "CONFLICT_DECLARED", reviewer_user_id: reviewAssignmentId }),
    }),
    new Request(`http://localhost:3000/v1/app/demands/${reviewDemandId}/review-assignments/${reviewAssignmentId}/release`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "if-match": '"demand-2-bbbbbbbbbbbbbbbbbbbbbbbb"',
        "idempotency-key": "review-release-idempotency-001",
        "x-csrf-token": "csrf_token_internal_000000000000001",
        "x-workspace-id": reviewWorkspace,
        "x-actor-id": reviewAssignmentId,
      },
      body: JSON.stringify({ reason_code: "CONFLICT_DECLARED" }),
    }),
  ]) await assert.rejects(
    () => createAppProxyRequest(request, "http://api:8000"),
    /APP_ROUTE_NOT_ALLOWED|AUTHORITY_HEADER_FORBIDDEN|INVALID_REVIEW_REQUEST/,
  );

  const accountList = await createAppProxyRequest(
    new Request("http://localhost:3000/v1/app/admin/accounts", {
      headers: {
        cookie: "__Host-ds_session=opaque",
        "x-workspace-id": "platform:10000000-0000-4000-8000-000000000001",
      },
    }),
    "http://api:8000",
  );
  assert.equal(accountList.url, "http://api:8000/v1/app/admin/accounts");

  const accountId = "10000000-0000-4000-8000-000000000002";
  const accountDetail = await createAppProxyRequest(
    new Request(`http://localhost:3000/v1/app/admin/accounts/${accountId}`, {
      headers: { "x-workspace-id": "platform:10000000-0000-4000-8000-000000000001" },
    }),
    "http://api:8000",
  );
  assert.equal(accountDetail.url, `http://api:8000/v1/app/admin/accounts/${accountId}`);

  const accountCommand = await createAppProxyRequest(
    new Request(`http://localhost:3000/v1/app/admin/accounts/${accountId}/suspend`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "if-match": '"v3"',
        "idempotency-key": "account-command-idempotency-0001",
        "x-csrf-token": "csrf_token_internal_000000000000001",
        "x-workspace-id": "platform:10000000-0000-4000-8000-000000000001",
        "x-actor-id": "must-not-pass",
        "x-authority": "must-not-pass",
      },
      body: JSON.stringify({ reason_code: "ACCESS_REVIEW" }),
    }),
    "http://api:8000",
  );
  assert.equal(accountCommand.url, `http://api:8000/v1/app/admin/accounts/${accountId}/suspend`);
  assert.equal(accountCommand.headers.get("if-match"), '"v3"');
  assert.equal(accountCommand.headers.get("x-actor-id"), null);
  assert.equal(accountCommand.headers.get("x-authority"), null);

  const dutyCommand = await createAppProxyRequest(
    new Request(`http://localhost:3000/v1/app/admin/accounts/${accountId}/platform-duties/FINANCE_OPERATOR/grant`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "if-match": '"v3"',
        "idempotency-key": "account-duty-idempotency-000001",
        "x-csrf-token": "csrf_token_internal_000000000000001",
        "x-workspace-id": "platform:10000000-0000-4000-8000-000000000001",
        "x-actor-id": "must-not-pass",
      },
      body: JSON.stringify({ reason_code: "ACCESS_REVIEW" }),
    }),
    "http://api:8000",
  );
  assert.equal(
    dutyCommand.url,
    `http://api:8000/v1/app/admin/accounts/${accountId}/platform-duties/FINANCE_OPERATOR/grant`,
  );
  assert.equal(dutyCommand.headers.get("x-actor-id"), null);

  await assert.rejects(
    () => createAppProxyRequest(
      new Request("http://localhost:3000/v1/app/demands", {
        headers: { "x-workspace-id": "org:../admin" },
      }),
      "http://api:8000",
    ),
    /INVALID_WORKSPACE_ID/,
  );

  for (const request of [
    new Request("http://localhost:3000/v1/app/demands/demand_internal_0000001?role=admin"),
    new Request("http://localhost:3000/v1/app/demands//profiles"),
    new Request("http://localhost:3000/v1/app/demands/demand%2Finternal"),
    new Request("http://localhost:3000/v1/app/demands/demand_internal_0000001/publish", { method: "POST" }),
    new Request("http://localhost:3000/v1/app/profiles/profile_internal_000001/draft", { method: "POST" }),
    new Request(`http://localhost:3000/v1/app/admin/accounts/${accountId}`, { method: "DELETE" }),
    new Request(`http://localhost:3000/v1/app/admin/accounts/${accountId}/grant-role`, { method: "POST" }),
    new Request(`http://localhost:3000/v1/app/admin/accounts/${accountId}/platform-duties/CREATOR/grant`, { method: "POST" }),
    new Request(`http://localhost:3000/v1/app/admin/accounts/${accountId}/suspend?authority=ACCESS_ADMIN`, { method: "POST" }),
  ]) await assert.rejects(() => createAppProxyRequest(request, "http://api:8000"), /APP_ROUTE_NOT_ALLOWED/);

  const rejected = await proxyAppRequest(
    new Request("http://localhost:3000/v1/app/users", { method: "GET" }),
    { baseUrl: "http://api:8000", fetchImpl: async () => { throw new Error("must not call"); } },
  );
  assert.equal(rejected.status, 404);
  assert.deepEqual(await rejected.json(), { code: "APP_ROUTE_NOT_ALLOWED", message: "该内部试运行接口不可用。" });

  const oversized = await proxyAppRequest(new Request("http://localhost:3000/v1/app/demands", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "content-length": "1048577",
      "x-workspace-id": "org:81000000-0000-4000-8000-000000000001",
    },
    body: "{}",
  }), { baseUrl: "http://api:8000", fetchImpl: async () => { throw new Error("must not call"); } });
  assert.equal(oversized.status, 413);
  assert.deepEqual(await oversized.json(), { code: "PROXY_REQUEST_TOO_LARGE", message: "请求内容超过内部试运行限制。" });

  for (const [request, expectedStatus, expectedCode] of [
    [new Request("http://localhost:3000/v1/app/workspaces", {
      headers: { "x-workspace-id": "personal:10000000-0000-4000-8000-000000000001" },
    }), 400, "WORKSPACE_HEADER_FORBIDDEN"],
    [new Request("http://localhost:3000/v1/app/profiles"), 400, "WORKSPACE_REQUIRED"],
  ]) {
    const response = await proxyAppRequest(request, {
      baseUrl: "http://api:8000",
      fetchImpl: async () => { throw new Error("must not call"); },
    });
    assert.equal(response.status, expectedStatus);
    assert.equal((await response.json()).code, expectedCode);
  }
});

test("Operations review release BFF validates the closed request and full released Demand response", async () => {
  const workspaceId = "platform:10000000-0000-4000-8000-000000000001";
  const demandId = "30000000-0000-4000-8000-000000000025";
  const assignmentId = "40000000-0000-4000-8000-000000000025";
  const releasedDemand = {
    resource_type: "DEMAND",
    object_id: demandId,
    status: "SUBMITTED",
    revision: 3,
    etag: '"demand-3-cccccccccccccccccccccccc"',
    capabilities: [],
    editable_paths: [],
    current_version: null,
    versions: [],
    submissions: [],
    findings: [],
    review_assignment: null,
  };
  const source = () => new Request(
    `http://localhost:3000/v1/app/demands/${demandId}/review-assignments/${assignmentId}/release`,
    {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "if-match": '"demand-2-bbbbbbbbbbbbbbbbbbbbbbbb"',
        "idempotency-key": "review-release-idempotency-001",
        "x-csrf-token": "csrf_token_internal_000000000000001",
        "x-workspace-id": workspaceId,
      },
      body: JSON.stringify({ reason_code: "CONFLICT_DECLARED" }),
    },
  );
  const releasedResponse = (value = releasedDemand, headers = {}) => Response.json(
    { data: value },
    {
      status: 200,
      headers: {
        "cache-control": "no-store",
        etag: value.etag,
        ...headers,
      },
    },
  );

  const confirmed = await proxyAppRequest(source(), {
    baseUrl: "http://api:8000",
    fetchImpl: async () => releasedResponse(),
  });
  assert.equal(confirmed.status, 200);
  assert.equal(confirmed.headers.get("etag"), releasedDemand.etag);
  assert.deepEqual(await confirmed.json(), { data: releasedDemand });

  const stillAssigned = {
    ...releasedDemand,
    capabilities: ["RECORD_FINDINGS"],
    review_assignment: {
      assignment_id: assignmentId,
      status: "ACTIVE",
      expires_at: "2026-08-27T08:30:00+00:00",
    },
  };
  const invalidSuccesses = [
    () => releasedResponse({ ...releasedDemand, status: "VERIFIED" }),
    () => releasedResponse({ ...releasedDemand, object_id: "50000000-0000-4000-8000-000000000025" }),
    () => releasedResponse(stillAssigned),
    () => releasedResponse(releasedDemand, { etag: '"demand-4-dddddddddddddddddddddddd"' }),
    () => releasedResponse(releasedDemand, { "set-cookie": "unsafe=1" }),
  ];
  for (const response of invalidSuccesses) {
    const rejected = await proxyAppRequest(source(), {
      baseUrl: "http://api:8000",
      fetchImpl: async () => response(),
    });
    assert.equal(rejected.status, 503);
    assert.equal((await rejected.json()).code, "INTERNAL_PILOT_BACKEND_UNAVAILABLE");
  }

  const precondition = await proxyAppRequest(source(), {
    baseUrl: "http://api:8000",
    fetchImpl: async () => Response.json(
      { error: { code: "PRECONDITION_FAILED" } },
      { status: 412, headers: { etag: '"demand-3-cccccccccccccccccccccccc"' } },
    ),
  });
  assert.equal(precondition.status, 412);
  assert.equal(precondition.headers.get("etag"), '"demand-3-cccccccccccccccccccccccc"');
  assert.deepEqual(await precondition.json(), { error: { code: "PRECONDITION_FAILED" } });

  const preconditionWithoutEtag = await proxyAppRequest(source(), {
    baseUrl: "http://api:8000",
    fetchImpl: async () => Response.json(
      { error: { code: "PRECONDITION_FAILED" } },
      { status: 412 },
    ),
  });
  assert.equal(preconditionWithoutEtag.status, 503);
  assert.equal((await preconditionWithoutEtag.json()).code, "INTERNAL_PILOT_BACKEND_UNAVAILABLE");

  const unknown = await proxyAppRequest(source(), {
    baseUrl: "http://api:8000",
    fetchImpl: async () => Response.json(
      { error: { code: "COMMAND_OUTCOME_UNKNOWN" } },
      { status: 503 },
    ),
  });
  assert.equal(unknown.status, 503);
  assert.deepEqual(await unknown.json(), { error: { code: "COMMAND_OUTCOME_UNKNOWN" } });
});

test("Creator Profile lifecycle proxy admits only exact closed writes", async () => {
  const profileId = "profile_internal_000001";
  const workspaceId = "personal:10000000-0000-4000-8000-000000000001";
  const lifecycleRequest = (action, body, extraHeaders = {}) => new Request(
    `http://localhost:3000/v1/app/profiles/${profileId}/${action}`,
    {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "if-match": '"creator_profile-3-aaaaaaaaaaaaaaaaaaaaaaaa"',
        "idempotency-key": `profile-${action}-idempotency-0001`,
        "x-csrf-token": "csrf_token_internal_000000000000001",
        "x-workspace-id": workspaceId,
        ...extraHeaders,
      },
      body: JSON.stringify(body),
    },
  );
  const accepted = [
    ["pause", { reason_code: "TEMPORARY_UNAVAILABILITY" }],
    ["resume", {}],
    ["archive", { reason_code: "ACCOUNT_CLOSURE" }],
  ];
  for (const [action, body] of accepted) {
    const proxied = await createAppProxyRequest(
      lifecycleRequest(action, body),
      "http://api:8000",
    );
    assert.equal(
      proxied.url,
      `http://api:8000/v1/app/profiles/${profileId}/${action}`,
    );
    assert.equal(proxied.headers.get("if-match"), '"creator_profile-3-aaaaaaaaaaaaaaaaaaaaaaaa"');
    assert.deepEqual(await proxied.json(), body);
  }

  for (const request of [
    lifecycleRequest("pause", { reason_code: "ACCOUNT_CLOSURE" }),
    lifecycleRequest("pause", { reason_code: "OWNER_REQUEST", actor_id: "forged" }),
    lifecycleRequest("resume", { reason_code: "OWNER_REQUEST" }),
    lifecycleRequest("archive", { reason_code: "TEMPORARY_UNAVAILABILITY" }),
    lifecycleRequest("archive", { reason_code: "OWNER_REQUEST" }, { "if-match": '"creator_profile-3"' }),
    lifecycleRequest("pause", { reason_code: "OWNER_REQUEST" }, { "x-actor-id": "forged" }),
  ]) await assert.rejects(
    () => createAppProxyRequest(request, "http://api:8000"),
    /INVALID_PROFILE_LIFECYCLE_REQUEST|AUTHORITY_HEADER_FORBIDDEN/,
  );
  await assert.rejects(
    () => createAppProxyRequest(new Request(
      `http://localhost:3000/v1/app/profiles/${profileId}/pause`,
      { method: "PUT", headers: { "x-workspace-id": workspaceId } },
    ), "http://api:8000"),
    /APP_ROUTE_NOT_ALLOWED/,
  );
});
