import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  DEMAND_EDITABLE_PATHS,
  DEMAND_OWNER_CANCEL_REASON_CODES,
  createDemandCancelIntent,
  parseEditorResource,
  parsePendingIntent,
  serializePendingIntent,
} from "../lib/app-contract.mjs";
import {
  createAppProxyRequest,
  proxyAppRequest,
} from "../lib/server-proxy.mjs";

const demandId = "demand_internal_0000001";
const workspaceId = "org:81000000-0000-4000-8000-000000000001";
const csrfToken = "csrf_token_internal_000000000000001";
const idempotencyKey = "demand-cancel-idempotency-0001";
const version = {
  version_id: "demand_version_internal_0001",
  version_no: 1,
  based_on_version_id: null,
  status: "COMMITTED",
  content: {},
  content_sha256: "a".repeat(64),
  taxonomy_bundle_id: "taxonomy_internal_00001",
  created_at: "2026-08-25T08:00:00+00:00",
};
const ownerDemand = {
  resource_type: "DEMAND",
  object_id: demandId,
  status: "DRAFT",
  revision: 2,
  etag: '"demand-2-aaaaaaaaaaaaaaaaaaaaaaaa"',
  capabilities: ["SAVE_DRAFT", "SUBMIT", "CANCEL"],
  editable_paths: [...DEMAND_EDITABLE_PATHS],
  current_version: version,
  versions: [version],
  submissions: [],
  findings: [],
  review_assignment: null,
};

function cancelRequest(body = { reason_code: "REQUIREMENTS_CHANGED" }, extraHeaders = {}) {
  return new Request(`http://localhost:3000/v1/app/demands/${demandId}/cancel`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "if-match": ownerDemand.etag,
      "idempotency-key": idempotencyKey,
      "x-csrf-token": csrfToken,
      "x-workspace-id": workspaceId,
      ...extraHeaders,
    },
    body: JSON.stringify(body),
  });
}

test("Demand Owner cancel capability and reason codes are closed to cancellable projections", () => {
  assert.deepEqual(DEMAND_OWNER_CANCEL_REASON_CODES, [
    "OWNER_WITHDREW",
    "REQUIREMENTS_CHANGED",
    "REVIEW_CLOSED",
    "FUNDING_UNAVAILABLE",
    "SAFETY_RESTRICTION",
  ]);
  assert.equal(parseEditorResource(ownerDemand), ownerDemand);
  for (const invalid of [
    { ...ownerDemand, status: "MATCHED" },
    { ...ownerDemand, status: "CANCELLED" },
    { ...ownerDemand, status: "EXPIRED" },
    { ...ownerDemand, capabilities: ["CANCEL", "SAVE_DRAFT", "SUBMIT"] },
    { ...ownerDemand, capabilities: ["CANCEL"], editable_paths: [...DEMAND_EDITABLE_PATHS] },
  ]) assert.throws(
    () => parseEditorResource(invalid),
    /INVALID_DEMAND_CANCEL_PROJECTION/,
  );
});

test("Demand Owner cancel intent binds the resource ETag and admits no authority facts", () => {
  const intent = createDemandCancelIntent({
    resource: ownerDemand,
    reasonCode: "REQUIREMENTS_CHANGED",
    csrfToken,
    idempotencyKey,
  });
  assert.deepEqual(intent, {
    method: "POST",
    path: `/v1/app/demands/${demandId}/cancel`,
    headers: {
      "content-type": "application/json",
      "idempotency-key": idempotencyKey,
      "if-match": ownerDemand.etag,
      "x-csrf-token": csrfToken,
    },
    body: { reason_code: "REQUIREMENTS_CHANGED" },
  });
  assert.throws(() => createDemandCancelIntent({
    resource: { ...ownerDemand, capabilities: ["SAVE_DRAFT", "SUBMIT"] },
    reasonCode: "REQUIREMENTS_CHANGED",
    csrfToken,
    idempotencyKey,
  }), /CAPABILITY_NOT_GRANTED/);
  assert.throws(() => createDemandCancelIntent({
    resource: ownerDemand,
    reasonCode: "DEADLINE_REACHED",
    csrfToken,
    idempotencyKey,
  }), /INVALID_REASON_CODE/);

  const pending = {
    version: 1,
    saved_at: "2026-08-25T08:01:00.000Z",
    resource_type: "DEMAND",
    object_id: demandId,
    label: "取消需求",
    intent,
  };
  assert.deepEqual(
    parsePendingIntent(serializePendingIntent(pending), Date.parse(pending.saved_at)),
    pending,
  );
  assert.equal(parsePendingIntent(JSON.stringify({
    ...pending,
    object_id: "demand_internal_0000002",
  }), Date.parse(pending.saved_at)), null);
});

test("Demand cancel BFF admits only the exact conditional request", async () => {
  const proxied = await createAppProxyRequest(cancelRequest(), "http://api:8000");
  assert.equal(proxied.url, `http://api:8000/v1/app/demands/${demandId}/cancel`);
  assert.equal(proxied.headers.get("if-match"), ownerDemand.etag);
  assert.deepEqual(await proxied.json(), { reason_code: "REQUIREMENTS_CHANGED" });

  for (const request of [
    cancelRequest({ reason_code: "DEADLINE_REACHED" }),
    cancelRequest({ reason_code: "OWNER_WITHDREW", actor_id: "forged" }),
    cancelRequest({ reason_code: "OWNER_WITHDREW" }, { "if-match": '"demand-2"' }),
    cancelRequest({ reason_code: "OWNER_WITHDREW" }, { "x-actor-id": "forged" }),
  ]) await assert.rejects(
    () => createAppProxyRequest(request, "http://api:8000"),
    /INVALID_DEMAND_CANCEL_REQUEST|AUTHORITY_HEADER_FORBIDDEN/,
  );
  await assert.rejects(
    () => createAppProxyRequest(new Request(
      `http://localhost:3000/v1/app/demands/${demandId}/cancel`,
      { method: "PUT", headers: { "x-workspace-id": workspaceId } },
    ), "http://api:8000"),
    /APP_ROUTE_NOT_ALLOWED/,
  );
});

test("Demand cancel BFF validates success, stale, and malformed backend responses", async () => {
  const cancelled = {
    ...ownerDemand,
    status: "CANCELLED",
    revision: 3,
    etag: '"demand-3-bbbbbbbbbbbbbbbbbbbbbbbb"',
    capabilities: [],
    editable_paths: [],
  };
  const success = await proxyAppRequest(cancelRequest(), {
    baseUrl: "http://api:8000",
    fetchImpl: async () => Response.json(
      { data: cancelled },
      {
        status: 200,
        headers: {
          "cache-control": "no-store",
          etag: cancelled.etag,
        },
      },
    ),
  });
  assert.equal(success.status, 200);
  assert.deepEqual(await success.json(), { data: cancelled });

  const stale = await proxyAppRequest(cancelRequest(), {
    baseUrl: "http://api:8000",
    fetchImpl: async () => Response.json(
      { error: { code: "PRECONDITION_FAILED" } },
      { status: 412, headers: { etag: cancelled.etag } },
    ),
  });
  assert.equal(stale.status, 412);
  assert.equal(stale.headers.get("etag"), cancelled.etag);

  const unauthorized = await proxyAppRequest(cancelRequest(), {
    baseUrl: "http://api:8000",
    fetchImpl: async () => Response.json(
      { error: { code: "ACCESS_DENIED" } },
      { status: 403 },
    ),
  });
  assert.equal(unauthorized.status, 403);
  assert.deepEqual(await unauthorized.json(), { error: { code: "ACCESS_DENIED" } });

  const malformed = await proxyAppRequest(cancelRequest(), {
    baseUrl: "http://api:8000",
    fetchImpl: async () => Response.json(
      { data: { ...cancelled, status: "SUBMITTED", capabilities: ["CANCEL"] } },
      {
        status: 200,
        headers: { "cache-control": "no-store", etag: cancelled.etag },
      },
    ),
  });
  assert.equal(malformed.status, 503);
  assert.equal((await malformed.json()).code, "INTERNAL_PILOT_BACKEND_UNAVAILABLE");

  const internalValueError = await proxyAppRequest(cancelRequest(), {
    baseUrl: "http://api:8000",
    fetchImpl: async () => Response.json(
      { error: { code: "INVALID_REQUEST", path: "/body" } },
      { status: 422 },
    ),
  });
  assert.equal(internalValueError.status, 503);
  assert.equal(
    (await internalValueError.json()).code,
    "INTERNAL_PILOT_BACKEND_UNAVAILABLE",
  );
});

test("Demand cancellation UI is capability-gated, reasoned, confirmed, and stale-safe", async () => {
  const source = await readFile(new URL("../app/product-client.tsx", import.meta.url), "utf8");
  const start = source.indexOf("function ResourceEditor(");
  const editor = source.slice(start);
  assert.match(source, /createDemandCancelIntent\(\{/);
  assert.match(source, /if \(!demandCancelConfirmed\)[\s\S]*DEMAND_CANCEL_CONFIRMATION_REQUIRED/);
  assert.match(source, /UNSAVED_DEMAND_CHANGES/);
  assert.match(editor, /resource\.resource_type === "DEMAND" && resource\.capabilities\.includes\("CANCEL"\)/);
  assert.match(editor, /DEMAND_OWNER_CANCEL_REASON_CODES\.map/);
  assert.match(editor, /checked=\{demandCancelConfirmed\}/);
  assert.match(editor, /disabled=\{busy \|\| dirty \|\| !demandCancelConfirmed\}/);
  assert.match(source, /isDemandCancelPath\(record\.intent\.path\)[\s\S]*persistPending\(null\)[\s\S]*ENDPOINTS\.demands/);
});
