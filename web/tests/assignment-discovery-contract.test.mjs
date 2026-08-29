import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  createTrustAssignedHoldReleaseIntent,
  parseAppealAssignmentListEnvelope,
  parseTrustAssignedHoldEnvelope,
  parseTrustAssignmentListEnvelope,
} from "../lib/app-contract.mjs";
import { createAppProxyRequest, proxyAppRequest } from "../lib/server-proxy.mjs";

const root = new URL("../", import.meta.url);
const actorId = "10000000-0000-4000-8000-000000000001";
const caseId = "20000000-0000-4000-8000-000000000001";
const appealId = "30000000-0000-4000-8000-000000000001";
const holdId = "40000000-0000-4000-8000-000000000001";
const secondHoldId = "50000000-0000-4000-8000-000000000001";
const workspace = `platform:${actorId}`;
const trustEtag = `"trust-3-${"a".repeat(24)}"`;
const appealEtag = `"appeal-4-${"b".repeat(24)}"`;
const trustAssignment = {
  assignment_expires_at: "2026-08-19T12:00:00Z",
  assignment_purpose: "CASE_TRIAGE",
  case_id: caseId,
  hold_id: null,
};
const appealAssignment = {
  appeal_id: appealId,
  assignment_expires_at: "2026-08-19T13:00:00Z",
};
const assignedHold = {
  action_codes: ["REQUEST_MATCHING"],
  assignment_expires_at: "2026-08-19T12:00:00Z",
  case_id: caseId,
  case_status: "IN_REVIEW",
  effective_at: "2026-08-19T10:00:00Z",
  entity_tag: trustEtag,
  expires_at: "2026-08-19T13:00:00Z",
  hold_id: holdId,
  hold_status: "ACTIVE",
  reason_code: "RETALIATION_RISK",
};

test("assignment discovery parsers accept only the minimal closed envelopes, including zero rows", () => {
  assert.deepEqual(
    parseTrustAssignmentListEnvelope({ data: { entity_tag: trustEtag, items: [trustAssignment] } }),
    { entity_tag: trustEtag, items: [trustAssignment] },
  );
  assert.deepEqual(
    parseAppealAssignmentListEnvelope({ data: { entity_tag: appealEtag, items: [appealAssignment] } }),
    { entity_tag: appealEtag, items: [appealAssignment] },
  );
  assert.deepEqual(
    parseTrustAssignmentListEnvelope({ data: { entity_tag: trustEtag, items: [] } }).items,
    [],
  );
  assert.deepEqual(
    parseAppealAssignmentListEnvelope({ data: { entity_tag: appealEtag, items: [] } }).items,
    [],
  );
  const pairedTrustAssignments = [
    trustAssignment,
    { ...trustAssignment, assignment_purpose: "HOLD_RELEASE", hold_id: holdId },
    { ...trustAssignment, assignment_purpose: "HOLD_RELEASE", hold_id: secondHoldId },
  ];
  assert.deepEqual(
    parseTrustAssignmentListEnvelope({
      data: { entity_tag: trustEtag, items: pairedTrustAssignments },
    }).items,
    pairedTrustAssignments,
  );
  assert.throws(
    () => parseTrustAssignmentListEnvelope({
      data: { entity_tag: trustEtag, items: [trustAssignment, trustAssignment] },
    }),
    /INVALID_APP_CONTRACT/,
  );
  for (const unsafe of [
    { ...trustAssignment, hold_id: holdId },
    { ...trustAssignment, assignment_purpose: "HOLD_RELEASE", hold_id: null },
  ]) assert.throws(
    () => parseTrustAssignmentListEnvelope({ data: { entity_tag: trustEtag, items: [unsafe] } }),
    /INVALID_APP_CONTRACT/,
  );

  for (const unsafe of [
    { ...trustAssignment, assignment_id: caseId },
    { ...trustAssignment, actor_user_id: actorId },
    { ...trustAssignment, assignment_purpose: "UNREVIEWED" },
    { ...trustAssignment, restricted_note: "leak" },
  ]) assert.throws(
    () => parseTrustAssignmentListEnvelope({ data: { entity_tag: trustEtag, items: [unsafe] } }),
    /INVALID_APP_CONTRACT/,
  );
  for (const unsafe of [
    { ...appealAssignment, assignment_id: appealId },
    { ...appealAssignment, reviewer_user_id: actorId },
    { ...appealAssignment, applicant_statement: "leak" },
  ]) assert.throws(
    () => parseAppealAssignmentListEnvelope({ data: { entity_tag: appealEtag, items: [unsafe] } }),
    /INVALID_APP_CONTRACT/,
  );

  assert.deepEqual(
    parseTrustAssignedHoldEnvelope({ data: assignedHold }),
    assignedHold,
  );
  assert.throws(
    () => parseTrustAssignedHoldEnvelope({ data: { ...assignedHold, assignment_id: holdId } }),
    /INVALID_APP_CONTRACT/,
  );
  for (const unsafe of [
    { ...assignedHold, effective_at: assignedHold.expires_at },
    { ...assignedHold, assignment_expires_at: "2026-08-19T13:00:00.000001Z" },
    { ...assignedHold, expires_at: "2026-08-19T21:00:00+08:00" },
  ]) assert.throws(
    () => parseTrustAssignedHoldEnvelope({ data: unsafe }),
    /INVALID_APP_CONTRACT/,
  );
  assert.deepEqual(
    createTrustAssignedHoldReleaseIntent({
      assignedHold,
      csrfToken: "trust-csrf-token-abcdefghijklmnopqrstuvwxyz-0123456789",
      idempotencyKey: "trust-hold-release-idempotency-0001",
      reasonCode: "RISK_MITIGATED",
    }),
    {
      method: "POST",
      path: `/v1/app/trust/holds/${holdId}/release`,
      headers: {
        "content-type": "application/json",
        "idempotency-key": "trust-hold-release-idempotency-0001",
        "if-match": trustEtag,
        "x-csrf-token": "trust-csrf-token-abcdefghijklmnopqrstuvwxyz-0123456789",
      },
      body: { reason_code: "RISK_MITIGATED" },
    },
  );
});

test("BFF admits both role-scoped assignment reads and preserves only validated no-store ETag responses", async () => {
  for (const path of [
    "/v1/app/trust/assignments",
    `/v1/app/trust/assigned-holds/${holdId}`,
    "/v1/app/appeal-review/assignments",
  ]) {
    const request = await createAppProxyRequest(new Request(`http://localhost:3000${path}`, {
      headers: { "x-workspace-id": workspace },
    }), "http://api:8000");
    assert.equal(request.url, `http://api:8000${path}`);
  }

  const holdResponse = await proxyAppRequest(new Request(`http://localhost:3000/v1/app/trust/assigned-holds/${holdId}`, {
    headers: { "x-workspace-id": workspace },
  }), {
    baseUrl: "http://api:8000",
    fetchImpl: async () => Response.json({ data: assignedHold }, {
      headers: { "cache-control": "no-store", "content-type": "application/json", etag: trustEtag },
    }),
  });
  assert.equal(holdResponse.status, 200);
  assert.deepEqual(await holdResponse.json(), { data: assignedHold });

  const stale = await proxyAppRequest(new Request(`http://localhost:3000/v1/app/trust/assigned-holds/${holdId}`, {
    headers: { "x-workspace-id": workspace },
  }), {
    baseUrl: "http://api:8000",
    fetchImpl: async () => Response.json({ data: assignedHold }, {
      headers: { "cache-control": "no-store", "content-type": "application/json", etag: `"trust-2-${"c".repeat(24)}"` },
    }),
  });
  assert.equal(stale.status, 503);

  const queried = await proxyAppRequest(new Request(`http://localhost:3000/v1/app/trust/assigned-holds/${holdId}?unexpected=1`, {
    headers: { "x-workspace-id": workspace },
  }), { baseUrl: "http://api:8000", fetchImpl: async () => { throw new Error("must not dispatch"); } });
  assert.equal(queried.status, 404);
  assert.equal(queried.headers.get("cache-control"), "no-store");
  assert.equal(queried.headers.get("etag"), null);
  assert.deepEqual(await queried.json(), {
    error: { code: "RESOURCE_NOT_FOUND" },
  });

  let trustAssignmentQueryDispatched = false;
  const trustAssignmentQueried = await proxyAppRequest(new Request("http://localhost:3000/v1/app/trust/assignments?limit=1", {
    headers: { "x-workspace-id": workspace },
  }), {
    baseUrl: "http://api:8000",
    fetchImpl: async () => {
      trustAssignmentQueryDispatched = true;
      throw new Error("must not dispatch");
    },
  });
  assert.equal(trustAssignmentQueried.status, 404);
  assert.equal(trustAssignmentQueried.headers.get("cache-control"), "no-store");
  assert.equal(trustAssignmentQueried.headers.get("content-type"), "application/json");
  assert.equal(trustAssignmentQueried.headers.get("etag"), null);
  assert.deepEqual(await trustAssignmentQueried.json(), {
    error: { code: "RESOURCE_NOT_FOUND" },
  });
  assert.equal(trustAssignmentQueryDispatched, false);

  let appealQueryDispatched = false;
  const appealQueried = await proxyAppRequest(new Request("http://localhost:3000/v1/app/appeal-review/assignments?unexpected=1", {
    headers: { "x-workspace-id": workspace },
  }), {
    baseUrl: "http://api:8000",
    fetchImpl: async () => {
      appealQueryDispatched = true;
      throw new Error("must not dispatch");
    },
  });
  assert.equal(appealQueried.status, 400);
  assert.equal(appealQueried.headers.get("cache-control"), "no-store");
  assert.deepEqual(await appealQueried.json(), {
    error: { code: "INVALID_REQUEST", path: "/query" },
  });
  assert.equal(appealQueryDispatched, false);

  const denied = await proxyAppRequest(new Request(`http://localhost:3000/v1/app/trust/assigned-holds/${holdId}`, {
    headers: { "x-workspace-id": workspace },
  }), {
    baseUrl: "http://api:8000",
    fetchImpl: async () => Response.json({ error: { code: "RESOURCE_NOT_FOUND" } }, {
      status: 404,
      headers: { "cache-control": "no-store", "content-type": "application/json" },
    }),
  });
  assert.equal(denied.status, 404);
  assert.equal(denied.headers.get("etag"), null);

  const leakedRole = await proxyAppRequest(new Request(`http://localhost:3000/v1/app/trust/assigned-holds/${holdId}`, {
    headers: { "x-workspace-id": workspace },
  }), {
    baseUrl: "http://api:8000",
    fetchImpl: async () => Response.json({ error: { code: "RESOURCE_NOT_FOUND" } }, {
      status: 403,
      headers: { "cache-control": "no-store", "content-type": "application/json" },
    }),
  });
  assert.equal(leakedRole.status, 503);

  const cacheableHold = await proxyAppRequest(new Request(`http://localhost:3000/v1/app/trust/assigned-holds/${holdId}`, {
    headers: { "x-workspace-id": workspace },
  }), {
    baseUrl: "http://api:8000",
    fetchImpl: async () => Response.json({ data: assignedHold }, {
      headers: { "content-type": "application/json", etag: trustEtag },
    }),
  });
  assert.equal(cacheableHold.status, 503);

  for (const [path, data, etag] of [
    ["/v1/app/trust/assignments", { entity_tag: trustEtag, items: [trustAssignment] }, trustEtag],
    ["/v1/app/appeal-review/assignments", { entity_tag: appealEtag, items: [appealAssignment] }, appealEtag],
  ]) {
    const response = await proxyAppRequest(new Request(`http://localhost:3000${path}`, {
      headers: { "x-workspace-id": workspace },
    }), {
      baseUrl: "http://api:8000",
      fetchImpl: async () => Response.json({ data }, {
        headers: { "cache-control": "no-store", "content-type": "application/json", etag },
      }),
    });
    assert.equal(response.status, 200);
    assert.equal(response.headers.get("cache-control"), "no-store");
    assert.equal(response.headers.get("etag"), etag);
    assert.deepEqual(await response.json(), { data });
  }

  const unsafe = await proxyAppRequest(new Request("http://localhost:3000/v1/app/trust/assignments", {
    headers: { "x-workspace-id": workspace },
  }), {
    baseUrl: "http://api:8000",
    fetchImpl: async () => Response.json({
      data: { entity_tag: trustEtag, items: [{ ...trustAssignment, duty_grant_id: caseId }] },
    }, { headers: { "cache-control": "no-store", "content-type": "application/json", etag: trustEtag } }),
  });
  assert.equal(unsafe.status, 503);

  const cacheable = await proxyAppRequest(new Request("http://localhost:3000/v1/app/trust/assignments", {
    headers: { "x-workspace-id": workspace },
  }), {
    baseUrl: "http://api:8000",
    fetchImpl: async () => Response.json({ data: { entity_tag: trustEtag, items: [] } }, {
      headers: { "content-type": "application/json", etag: trustEtag },
    }),
  });
  assert.equal(cacheable.status, 503);
});

test("role workbenches discover assignments automatically and keep identifiers memory-only", async () => {
  const [trust, appeal] = await Promise.all([
    readFile(new URL("app/trust-workbench.tsx", root), "utf8"),
    readFile(new URL("app/appeal-workbench.tsx", root), "utf8"),
  ]);
  assert.match(trust, /parseTrustAssignmentListEnvelope/);
  assert.match(trust, /parseTrustAssignedHoldEnvelope/);
  assert.match(trust, /\/trust\/assigned-holds\//);
  assert.match(trust, /\/trust\/assignments/);
  assert.match(trust, /我的活动分配/);
  assert.match(trust, /继续处理/);
  assert.match(trust, /CASE_TRIAGE[\s\S]*案件分诊/);
  assert.match(trust, /HOLD_RELEASE[\s\S]*保护解除复核/);
  assert.match(trust, /HOLD_RELEASE[\s\S]*openDiscoveredHold/);
  assert.match(trust, /selectedHoldRelease[\s\S]*解除对应 Hold/);
  assert.match(trust, /key=\{JSON\.stringify\(\[item\.assignment_purpose, item\.case_id, item\.hold_id\]\)\}/);
  assert.match(trust, /record\.resource_type === "TRUST_HOLD"[\s\S]*readAssignedHold\(record\.object_id\)/);
  assert.match(appeal, /parseAppealAssignmentListEnvelope/);
  assert.match(appeal, /\/appeal-review\/assignments/);
  assert.match(appeal, /我的活动分配/);
  assert.match(appeal, /继续复核/);
  assert.doesNotMatch(trust, /(?:localStorage|sessionStorage)\.setItem\([^\n]*(?:assignedCaseId|case_id)/);
  assert.doesNotMatch(trust, /sessionStorage\.setItem\([^\n]*(?:selectedHoldRelease|assignments|holdId)/);
  assert.doesNotMatch(appeal, /(?:localStorage|sessionStorage)\.setItem\([^\n]*(?:assignedLookupId|appeal_id)/);
});
