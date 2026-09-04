import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import {
  ADMIN_DEMAND_STAGE_LABELS,
  adminDemandDetailValue,
  canInspectDemandTimeline,
  mergeAdminDemandCollection,
  mergeAdminDemandTimeline,
  parseAdminDemandCollection,
  parseAdminDemandTimeline,
} from "../lib/admin-demand-contract.mjs";
import { createAdminDemandReader } from "../lib/admin-demand-read.mjs";
import { createAppProxyRequest, proxyAppRequest } from "../lib/server-proxy.mjs";

const demandId = "11111111-1111-4111-8111-111111111111";
const otherDemandId = "11111111-1111-4111-8111-111111111112";
const organizationId = "22222222-2222-4222-8222-222222222222";
const userId = "33333333-3333-4333-8333-333333333333";
const eventId = "44444444-4444-4444-8444-444444444444";
const cursor = `${"c".repeat(64)}.${"s".repeat(43)}`;
const time = "2026-09-04T01:00:00.000001Z";
const workspaceId = `org:${organizationId}`;
const path = `/v1/app/admin/demands/${demandId}/timeline`;
const summary = {
  demand_id: demandId, organization_id: organizationId, title: "宠物投喂器需求",
  status: "DRAFT", aggregate_version: 1, created_at: time, updated_at: time,
  expires_at: "2026-10-04T01:00:00Z", current_stage: "INTAKE", blocker_codes: ["WAITING_FOR_SUBMISSION"],
};
function fixture() {
  return { data: {
    demand: structuredClone(summary), generated_at: "2026-09-04T02:00:00Z",
    stages: Object.entries(ADMIN_DEMAND_STAGE_LABELS).map(([code, label]) => ({
      code, label, status: ["AGREEMENT", "DELIVERY", "SETTLEMENT"].includes(code) ? "NOT_IMPLEMENTED" : code === "INTAKE" ? "IN_PROGRESS" : "PENDING",
      participant_ids: code === "INTAKE" ? [userId] : [], event_count: code === "INTAKE" ? 2 : 0, blocker_codes: [],
    })),
    participants: [{ user_id: userId, display_name: "需求负责人", roles: ["DEMAND_OWNER"] }],
    events: [{ event_id: eventId, stage: "INTAKE", source: "DEMAND", action: "DEMAND_CREATED",
      actor_user_id: userId, actor_role: "DEMAND_OWNER", occurred_at: time,
      summary: "创建需求草稿", details: { after_status: "DRAFT", after_version: 1 },
    }],
    coverage: [
      { source: "DEMAND", status: "COMPLETE", description: "已记录需求编辑和审核流程" },
      ...["AGREEMENT", "DELIVERY", "SETTLEMENT"].map((source) => ({ source, status: "NOT_IMPLEMENTED", description: `${ADMIN_DEMAND_STAGE_LABELS[source]}尚未接入` })),
    ],
    next_cursor: null, has_more: false,
  } };
}
function source(suffix = path, headers = {}) {
  return new Request(`http://localhost:3000${suffix}`, { headers: { accept: "application/json", "x-workspace-id": workspaceId, ...headers } });
}
function backend(value, status = 200, headers = {}) {
  return Response.json(value, { status, headers: { "cache-control": "no-store", ...headers } });
}

test("admin timeline only appears for the corresponding administrator workspace", () => {
  assert.equal(canInspectDemandTimeline({ workspace_kind: "PLATFORM", role_codes: ["ACCESS_ADMIN"] }), true);
  assert.equal(canInspectDemandTimeline({ workspace_kind: "ORGANIZATION", role_codes: ["ORG_ADMIN"] }), true);
  for (const workspace of [null, { workspace_kind: "PERSONAL", role_codes: ["ORG_ADMIN"] },
    { workspace_kind: "PLATFORM", role_codes: ["ORG_ADMIN", "OPERATIONS_REVIEWER"] },
    { workspace_kind: "ORGANIZATION", role_codes: ["ACCESS_ADMIN", "DEMAND_OWNER"] }]) {
    assert.equal(canInspectDemandTimeline(workspace), false);
  }
});

test("review reasons and failed matching deliveries remain accepted and readable", () => {
  const review = fixture();
  review.data.events[0].details = { reason_code: "SCOPE_UNCLEAR,ACCEPTANCE_UNCLEAR", after_status: "NEEDS_CHANGES" };
  assert.equal(parseAdminDemandTimeline(review).events[0].details.reason_code, "SCOPE_UNCLEAR,ACCEPTANCE_UNCLEAR");
  assert.equal(adminDemandDetailValue("reason_code", "SCOPE_UNCLEAR,ACCEPTANCE_UNCLEAR"), "范围不清晰、验收标准不清晰");
  assert.equal(adminDemandDetailValue("after_status", "NEEDS_CHANGES"), "需要修改");
  const failed = fixture();
  failed.data.demand.status = "MATCHING";
  failed.data.demand.current_stage = "MATCHING";
  failed.data.demand.blocker_codes = ["MATCHING_JOB_FAILED"];
  failed.data.events = [{ event_id: eventId, stage: "MATCHING", source: "MATCHING", action: "MatchingDeliveryFailed", actor_user_id: null, actor_role: "SYSTEM", occurred_at: time, summary: "匹配请求派送失败，需要检查后台任务", details: { target_kind: "MatchingDelivery", target_id: demandId, after_status: "FAILED", reason_code: "LEASE_EXPIRED", result_code: "FAILED" } }];
  failed.data.stages[3].event_count = 1;
  failed.data.stages[3].status = "BLOCKED";
  const parsed = parseAdminDemandTimeline(failed);
  assert.equal(parsed.events[0].actor_role, "SYSTEM");
  assert.equal(adminDemandDetailValue("after_status", parsed.events[0].details.after_status), "失败");
  assert.equal(adminDemandDetailValue("reason_code", "LEASE_EXPIRED"), "处理任务超时");
  assert.equal(adminDemandDetailValue("target_kind", "MatchingDelivery"), "匹配请求派送");
  assert.equal(adminDemandDetailValue("reason_code", "FUTURE_REASON"), "FUTURE_REASON");
  assert.equal(adminDemandDetailValue("original_actor_user_id", userId), userId);
});

test("collection and timeline bind exact DTOs to demand and organization", () => {
  assert.deepEqual(parseAdminDemandTimeline(fixture(), demandId, workspaceId), fixture().data);
  const envelope = { data: { items: [summary], next_cursor: null, has_more: false } };
  assert.deepEqual(parseAdminDemandCollection(envelope, workspaceId), envelope.data);
  assert.throws(() => parseAdminDemandCollection(envelope, `org:${userId}`));
  assert.throws(() => parseAdminDemandTimeline(fixture(), otherDemandId, workspaceId));
  assert.throws(() => parseAdminDemandTimeline(fixture(), demandId, `org:${userId}`));
  const leaks = [
    (v) => { v.data.demand.raw_payload = { email: "private@example.test" }; },
    (v) => { v.data.events[0].details.email = "private@example.test"; },
    (v) => { v.data.participants[0].email = "private@example.test"; },
    (v) => { v.data.events[0].actor_user_id = demandId; },
    (v) => { v.data.stages[0].participant_ids = []; },
    (v) => { v.data.events[0].action = { raw: true }; },
    (v) => { v.data.events[0].occurred_at = "not-a-date"; },
    (v) => { v.data.events[0].details.after_version = "one"; },
    (v) => { v.data.events[0].details.after_status = { unsafe: true }; },
    (v) => { v.data.stages[5].status = "COMPLETED"; },
    (v) => { v.data.coverage.pop(); },
    (v) => { v.data.has_more = true; },
    (v) => { v.data.participants.push(v.data.participants[0]); },
  ];
  for (const mutate of leaks) { const value = fixture(); mutate(value); assert.throws(() => parseAdminDemandTimeline(value)); }
});

test("timeline pages preserve microsecond chronology and cannot merge changed snapshots", () => {
  const first = fixture();
  first.data.has_more = true;
  first.data.next_cursor = cursor;
  const second = fixture();
  second.data.events[0].event_id = "44444444-4444-4444-8444-444444444443";
  second.data.events[0].occurred_at = "2026-09-04T01:00:00.000002+00:00";
  const prior = parseAdminDemandTimeline(first);
  const next = parseAdminDemandTimeline(second);
  assert.equal(mergeAdminDemandTimeline(prior, next).events.length, 2);
  const all = fixture();
  all.data.events.push(second.data.events[0]);
  assert.equal(parseAdminDemandTimeline(all).events.length, 2);
  assert.throws(() => mergeAdminDemandTimeline(prior, { ...next, events: prior.events }));
  assert.throws(() => mergeAdminDemandTimeline(prior, { ...next, demand: { ...next.demand, aggregate_version: 2 } }), /ADMIN_DEMAND_TIMELINE_CHANGED/);
  assert.throws(() => mergeAdminDemandTimeline(prior, { ...next, next_cursor: cursor, has_more: true }));
  assert.throws(() => mergeAdminDemandCollection({ items: [summary], next_cursor: cursor, has_more: true }, { items: [summary], next_cursor: null, has_more: false }));
});

test("admin BFF only permits authenticated-workspace GET paths and bounded pagination", async () => {
  for (const route of ["/v1/app/admin/demands?limit=25", `${path}?limit=100&cursor=${cursor}`]) {
    const request = await createAppProxyRequest(source(route), "http://api:8000");
    assert.equal(request.headers.get("x-workspace-id"), workspaceId);
    assert.equal(request.method, "GET");
  }
  for (const suffix of ["?limit=101", "?limit=0", "?limit=1&limit=2", "?workspace_id=platform", "?cursor=unsafe", "?limit=%32%35"]) {
    let called = false;
    const response = await proxyAppRequest(source(`${path}${suffix}`), { baseUrl: "http://api:8000", fetchImpl: async () => { called = true; return backend(fixture()); } });
    assert.equal(response.status, 400);
    assert.equal(called, false);
  }
  await assert.rejects(() => createAppProxyRequest(new Request(`http://localhost:3000${path}`, { method: "POST", headers: { "x-workspace-id": workspaceId } }), "http://api:8000"));
  await assert.rejects(() => createAppProxyRequest(new Request(`http://localhost:3000${path}`), "http://api:8000"), /WORKSPACE_REQUIRED/);
  await assert.rejects(() => createAppProxyRequest(source(path, { "x-user-id": userId }), "http://api:8000"), /AUTHORITY_HEADER_FORBIDDEN/);
  await assert.rejects(() => createAppProxyRequest(source(path, { "x-csrf-token": "x".repeat(40) }), "http://api:8000"), /INVALID_ADMIN_DEMAND_REQUEST/);
  await assert.rejects(() => createAppProxyRequest(source("/v1/app/admin/demands/not-a-uuid/timeline"), "http://api:8000"));
});

test("admin BFF rejects unbound, secret-bearing, cached or malformed backend responses", async () => {
  const valid = await proxyAppRequest(source(), { baseUrl: "http://api:8000", fetchImpl: async () => backend(fixture()) });
  assert.equal(valid.status, 200);
  assert.deepEqual(await valid.json(), fixture());
  for (const make of [
    () => { const v = fixture(); v.data.events[0].details.email = "private@example.test"; return backend(v); },
    () => { const v = fixture(); v.data.demand.demand_id = otherDemandId; return backend(v); },
    () => { const v = fixture(); v.data.demand.organization_id = userId; return backend(v); },
    () => backend(fixture(), 200, { "set-cookie": "secret-cookie=value" }),
    () => backend(fixture(), 200, { "cache-control": "public" }),
    () => backend({ error: { code: "ACCESS_DENIED", debug: "secret-token" } }, 403),
  ]) {
    const response = await proxyAppRequest(source(), { baseUrl: "http://api:8000", fetchImpl: async () => make() });
    assert.equal(response.status, 503);
    assert.doesNotMatch(await response.text(), /private@example|secret-token|secret-cookie/);
  }
  for (const [status, code] of [[401, "SESSION_EXPIRED"], [403, "ACCESS_DENIED"], [404, "RESOURCE_NOT_FOUND"], [409, "TIMELINE_CHANGED"]]) {
    const response = await proxyAppRequest(source(), { baseUrl: "http://api:8000", fetchImpl: async () => backend({ error: { code } }, status) });
    assert.equal(response.status, status);
    assert.deepEqual(await response.json(), { error: { code } });
  }
});

test("switching requests and unmounting abort reads and reject late success or error", async () => {
  const reader = createAdminDemandReader();
  const commits = [];
  let finishOld;
  let oldSignal;
  const old = reader.run((signal) => { oldSignal = signal; return new Promise((resolve) => { finishOld = resolve; }); }, (value) => commits.push(value), (error) => commits.push(error));
  await reader.run(async () => "new-demand", (value) => commits.push(value), (error) => commits.push(error));
  assert.equal(oldSignal.aborted, true);
  finishOld("old-demand");
  await old;
  assert.deepEqual(commits, ["new-demand"]);
  let rejectLate;
  const pending = reader.run(() => new Promise((_resolve, reject) => { rejectLate = reject; }), (value) => commits.push(value), (error) => commits.push(error));
  reader.cancel();
  rejectLate(new Error("session switched"));
  await pending;
  assert.deepEqual(commits, ["new-demand"]);
});

test("panel resets the full state per session, account and workspace, and separates read failures from empty results", async () => {
  const ui = await readFile(new URL("../app/admin-demand-timeline.tsx", import.meta.url), "utf8");
  const product = await readFile(new URL("../app/product-client.tsx", import.meta.url), "utf8");
  assert.match(ui, /key=\{`\$\{sessionId\}:\$\{accountId\}:\$\{workspace\.workspace_id\}`\}/);
  assert.match(ui, /collectionReader\.cancel\(\); timelineReader\.cancel\(\)/);
  assert.match(ui, /if \(changed\) setTimeline\(null\)/);
  assert.match(ui, /role === "SYSTEM" \? "系统" : "未记录操作人"/);
  assert.match(ui, /读取失败不代表没有记录/);
  assert.match(ui, /筛选只针对已加载记录/);
  assert.match(ui, /记录范围与待接入环节/);
  assert.match(product, /canInspectDemands && selectedWorkspace && session && me && !logoutIntent/);
  assert.doesNotMatch(ui, /localStorage|sessionStorage|console\.|dangerouslySetInnerHTML/);
});
