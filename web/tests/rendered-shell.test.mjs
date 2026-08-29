import assert from "node:assert/strict";
import test from "node:test";

const workerUrl = new URL("../dist/server/index.js", import.meta.url);
workerUrl.searchParams.set("test", `${process.pid}-${Date.now()}`);
const { default: worker } = await import(workerUrl.href);

function request(path, headers = {}) {
  return worker.fetch(
    new Request(`http://localhost${path}`, { headers: { accept: path === "/" ? "text/html" : "application/json", ...headers } }),
    { ASSETS: { fetch: async () => new Response("Not found", { status: 404 }) } },
    { waitUntil() {}, passThroughOnException() {} },
  );
}

function requestDocument(path, headers = {}) {
  return request(path, { accept: "text/html", "sec-fetch-dest": "document", ...headers });
}

function policyNonce(response) {
  const policy = response.headers.get("content-security-policy") ?? "";
  const match = policy.match(/(?:^|;\s*)script-src\s+[^;]*'nonce-([A-Za-z0-9_-]{43})'(?:\s|;|$)/u);
  assert.ok(match, `missing 32-byte CSP nonce in ${policy}`);
  return { nonce: match[1], policy };
}

function directive(policy, name) {
  const value = policy.split(";").map((entry) => entry.trim()).find((entry) => entry.startsWith(`${name} `));
  assert.ok(value, `missing ${name} in ${policy}`);
  return value.slice(name.length + 1).split(/\s+/u);
}

function assertEveryScriptUsesNonce(html, nonce) {
  const scripts = [...html.matchAll(/<script\b([^>]*)>/giu)];
  assert.ok(scripts.length > 0);
  for (const script of scripts) assert.match(script[1], new RegExp(`(?:^|\\s)nonce="${nonce}"(?:\\s|$)`, "u"));
}

test("server-renders the internal-pilot boundary before client bootstrap", async () => {
  const response = await requestDocument("/");
  assert.equal(response.status, 200);
  assert.match(response.headers.get("content-type") ?? "", /^text\/html\b/i);
  assert.equal(response.headers.get("cache-control"), "no-store");
  const { nonce } = policyNonce(response);
  const html = await response.text();
  assertEveryScriptUsesNonce(html, nonce);
  assert.match(html, /<html[^>]+lang="zh-CN"/i);
  assert.match(html, /<title>愿作 · 内部试运行工作台<\/title>/i);
  assert.match(html, /正在建立可信工作区/);
  assert.match(html, /账号、角色、对象与权限均由服务端返回/);
  assert.match(html, /INTERNAL_SANDBOX/);
  assert.match(html, /G1 NO-GO/);
  assert.match(html, /G2 NO-GO/);
  assert.doesNotMatch(html, /OpenAI Sites|真实支付成功|自动授予角色/i);
});

test("server-renders /join with the scrub script before invitation UI", async () => {
  const response = await requestDocument("/join");
  assert.equal(response.status, 200);
  const { nonce } = policyNonce(response);
  const html = await response.text();
  const scrubAt = html.indexOf("history.replaceState");
  const titleAt = html.indexOf("加入组织工作区");
  assert.ok(scrubAt >= 0 && titleAt > scrubAt);
  const scrubScriptAt = html.lastIndexOf("<script", scrubAt);
  const scrubScriptTagEnd = html.indexOf(">", scrubScriptAt);
  assert.ok(scrubScriptAt >= 0 && scrubScriptTagEnd > scrubScriptAt);
  assert.match(html.slice(scrubScriptAt, scrubScriptTagEnd + 1), new RegExp(`nonce="${nonce}"`, "u"));
  assert.match(html.slice(scrubScriptAt, scrubScriptTagEnd + 1), /id="desire-join-fragment-scrub"/u);
  assertEveryScriptUsesNonce(html, nonce);
  assert.match(html, /ACCESS_INVITATION_FRAGMENT_INVALID/);
  assert.match(html, /MEMORY ONLY/);
  assert.doesNotMatch(html, /access_invitation_token=[A-Za-z0-9_-]{80}/);
});

test("HTML documents receive a strict per-response nonce that an inbound CSP cannot select", async () => {
  const attackerNonce = "A".repeat(43);
  const attackerMarker = "attacker-csp.example.invalid";
  const [first, second] = await Promise.all([
    requestDocument("/app?nonce-audit=first", {
      "content-security-policy": `default-src *; script-src 'unsafe-inline' 'unsafe-eval' 'nonce-${attackerNonce}' https://${attackerMarker}`,
      "content-security-policy-report-only": `report-uri https://${attackerMarker}/report`,
    }),
    requestDocument("/app?nonce-audit=second"),
  ]);
  const firstPolicy = policyNonce(first);
  const secondPolicy = policyNonce(second);
  assert.notEqual(firstPolicy.nonce, secondPolicy.nonce);
  assert.notEqual(firstPolicy.nonce, attackerNonce);

  for (const { response, nonce, policy } of [
    { response: first, ...firstPolicy },
    { response: second, ...secondPolicy },
  ]) {
    assert.equal(response.status, 200);
    assert.equal(response.headers.get("cache-control"), "no-store");
    assert.equal(response.headers.get("content-security-policy-report-only"), null);
    assert.doesNotMatch(policy, /unsafe-inline|unsafe-eval|attacker-csp|default-src \*/u);
    assert.deepEqual(directive(policy, "default-src"), ["'none'"]);
    assert.deepEqual(directive(policy, "script-src"), ["'self'", `'nonce-${nonce}'`]);
    assert.deepEqual(directive(policy, "script-src-attr"), ["'none'"]);
    assert.deepEqual(directive(policy, "style-src"), ["'self'"]);
    assert.deepEqual(directive(policy, "style-src-attr"), ["'none'"]);
    for (const name of ["img-src", "font-src", "connect-src"]) {
      assert.deepEqual(directive(policy, name), ["'self'"]);
    }
    for (const name of ["frame-src", "frame-ancestors", "base-uri", "object-src", "manifest-src", "media-src", "worker-src"]) {
      assert.deepEqual(directive(policy, name), ["'none'"]);
    }
    assert.deepEqual(directive(policy, "form-action"), ["'self'"]);
    const html = await response.text();
    assertEveryScriptUsesNonce(html, nonce);
    assert.doesNotMatch(html, new RegExp(`${attackerNonce}|${attackerMarker}`, "u"));
  }
});

test("non-document JSON responses do not receive an HTML CSP nonce", async () => {
  const response = await request("/v1/app/workspaces");
  assert.equal(response.status, 503);
  assert.equal(response.headers.get("content-security-policy"), null);
});

test("internal-pilot BFF fails closed without an exact backend", async () => {
  const discovery = await request("/v1/app/workspaces");
  assert.equal(discovery.status, 503);
  assert.deepEqual(await discovery.json(), {
    code: "INTERNAL_PILOT_BACKEND_UNAVAILABLE",
    message: "无法连接内部试运行平台。",
  });

  const forgedDiscovery = await request("/v1/app/workspaces", {
    "x-workspace-id": "personal:10000000-0000-4000-8000-000000000001",
  });
  assert.equal(forgedDiscovery.status, 400);
  assert.equal((await forgedDiscovery.json()).code, "WORKSPACE_HEADER_FORBIDDEN");

  const missingWorkspace = await request("/v1/app/profiles");
  assert.equal(missingWorkspace.status, 400);
  assert.deepEqual(await missingWorkspace.json(), {
    code: "WORKSPACE_REQUIRED",
    message: "必须先选择一个服务端工作区。",
  });

  const response = await request("/v1/app/profiles", {
    "x-workspace-id": "personal:10000000-0000-4000-8000-000000000001",
  });
  assert.equal(response.status, 503);
  assert.deepEqual(await response.json(), {
    code: "INTERNAL_PILOT_BACKEND_UNAVAILABLE",
    message: "无法连接内部试运行平台。",
  });
  assert.equal(response.headers.get("cache-control"), "no-store");
});

test("policy BFF fails closed without an exact backend", async () => {
  const response = await request("/v1/policy-bundles/policy_bundle_creator_0001");
  assert.equal(response.status, 503);
  assert.deepEqual(await response.json(), {
    code: "AUTH_BACKEND_UNAVAILABLE",
    message: "无法连接认证服务。",
  });
  assert.equal(response.headers.get("cache-control"), "no-store");
});

test("organization IAM BFF fails closed without an exact backend", async () => {
  const organizationId = "4316fcdd-e7fb-5c41-9736-3aaf876aa08e";
  const response = await request(`/v1/organizations/${organizationId}`);
  assert.equal(response.status, 503);
  assert.deepEqual(await response.json(), {
    code: "IAM_BACKEND_UNAVAILABLE",
    message: "无法连接组织权限服务。",
  });
  assert.equal(response.headers.get("cache-control"), "no-store");
});

test("BFF fails closed when no exact loopback backend is configured", async () => {
  const response = await request("/v1/local/personas");
  assert.equal(response.status, 503);
  assert.deepEqual(await response.json(), {
    code: "LOCAL_BACKEND_UNAVAILABLE",
    message: "无法连接本地平台内核。",
  });
  assert.equal(response.headers.get("cache-control"), "no-store");
});
