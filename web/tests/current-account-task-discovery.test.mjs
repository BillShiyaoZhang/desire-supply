import assert from "node:assert/strict";
import test from "node:test";

import {
  CURRENT_ACCOUNT_TASK_CLASSIFICATIONS,
  CURRENT_ACCOUNT_TASK_NEXT_ACTIONS,
  CURRENT_ACCOUNT_TASK_RESOURCE_KINDS,
  parseCurrentAccountTaskDiscovery,
} from "../lib/app-contract.mjs";
import {
  resolveAppealTaskReadKind,
  resolveCurrentAccountTaskDestination,
  resolveFinanceTaskDetail,
  resolveFinanceTaskDetailAction,
  resolveRevalidatedCurrentAccountTask,
  resolveRevalidatedCurrentAccountTaskResource,
  resolveRevalidatedFinanceTaskQueueItem,
} from "../lib/current-account-task-destination.mjs";
import { createAppProxyRequest, proxyAppRequest } from "../lib/server-proxy.mjs";

const workspace = "platform:10000000-0000-4000-8000-000000000001";
const taskId = (index) => `10000000-0000-4000-8000-${String(index).padStart(12, "0")}`;
const taskCases = [
  ["NEEDS_ACTION", "APPEAL_REVIEW", "AVAILABLE", "CLAIM_APPEAL_REVIEW", () => "/v1/app/appeal-review/queue"],
  ["NEEDS_ACTION", "DEMAND_REVIEW", "AVAILABLE", "CLAIM_DEMAND_REVIEW", () => "/v1/app/review-queue"],
  ["NEEDS_ACTION", "FINANCE_FUNDING_REVIEW", "AVAILABLE", "CLAIM_FINANCE_REVIEW", () => "/v1/app/finance/funding-reviews"],
  ["NEEDS_ACTION", "TRUST_CASE", "AVAILABLE", "CLAIM_TRUST_CASE", () => "/v1/app/trust/queue"],
  ["NEEDS_ACTION", "TRUST_HOLD_RELEASE", "AVAILABLE", "CLAIM_TRUST_HOLD_RELEASE", () => "/v1/app/trust/hold-release-queue"],
  ["NEEDS_ACTION", "FINANCE_FUNDING_REVIEW", "PENDING", "CONTINUE_FINANCE_REVIEW", (id) => `/v1/app/finance/funding-reviews/${id}`],
  ["NEEDS_ACTION", "APPEAL", "DRAFT", "EDIT_APPEAL", (id) => `/v1/app/appeals/${id}`],
  ["NEEDS_ACTION", "DEMAND", "DRAFT", "EDIT_OR_SUBMIT_DEMAND", (id) => `/v1/app/demands/${id}`],
  ["NEEDS_ACTION", "APPEAL_REVIEW", "ASSIGNED", "REVIEW_ASSIGNED_APPEAL", (id) => `/v1/app/appeal-review/appeals/${id}`],
  ["NEEDS_ACTION", "DEMAND_REVIEW", "DRAFT", "REVIEW_ASSIGNED_DEMAND", (id) => `/v1/app/demands/${id}`],
  ["NEEDS_ACTION", "TRUST_CASE", "ASSIGNED", "REVIEW_ASSIGNED_TRUST_CASE", (id) => `/v1/app/trust/cases/${id}`],
  ["NEEDS_ACTION", "TRUST_HOLD_RELEASE", "ASSIGNED", "REVIEW_ASSIGNED_TRUST_HOLD_RELEASE", (id) => `/v1/app/trust/assigned-holds/${id}`],
  ["COMPLETED", "APPEAL", "DECIDED", "VIEW_APPEAL_HISTORY", (id) => `/v1/app/appeals/${id}`],
  ["NEEDS_ACTION", "CREATOR_PROFILE", "DRAFT", "VIEW_CREATOR_PROFILE", (id) => `/v1/app/profiles/${id}`],
  ["COMPLETED", "DEMAND", "MATCHED", "VIEW_DEMAND_HISTORY", (id) => `/v1/app/demands/${id}`],
  ["COMPLETED", "TRUST_REPORT", "DECIDED", "VIEW_TRUST_REPORT_HISTORY", (id) => `/v1/app/trust/reports/${id}`],
  ["WAITING", "APPEAL", "SUBMITTED", "WAIT_FOR_APPEAL_REVIEW", (id) => `/v1/app/appeals/${id}`],
  ["WAITING", "DEMAND", "SUBMITTED", "WAIT_FOR_DEMAND_PROCESSING", (id) => `/v1/app/demands/${id}`],
  ["WAITING", "FINANCE_FUNDING_REVIEW", "PENDING", "WAIT_FOR_FINANCE_CONFIRMATION", (id) => `/v1/app/finance/funding-reviews/${id}`],
  ["WAITING", "TRUST_REPORT", "OPEN", "WAIT_FOR_TRUST_REVIEW", (id) => `/v1/app/trust/reports/${id}`],
  ["COMPLETED", "DEMAND_REVIEW", "VERIFIED", "VIEW_DEMAND_REVIEW_HISTORY", () => "/v1/app/review-history"],
  ["COMPLETED", "TRUST_CASE", "PROTECTION_MAINTAINED", "VIEW_TRUST_CASE_HISTORY", () => "/v1/app/trust/history"],
  ["COMPLETED", "APPEAL_REVIEW", "MODIFY", "VIEW_APPEAL_REVIEW_HISTORY", () => "/v1/app/appeal-review/history"],
];

function makeTask(spec, index = 1, overrides = {}) {
  const id = overrides.resource_id ?? taskId(index);
  return {
    classification: spec[0],
    resource_kind: spec[1],
    resource_id: id,
    source_status: spec[2],
    next_action: spec[3],
    resource_path: spec[4](id),
    updated_at: "2026-08-25T08:00:00Z",
    due_at: null,
    ...overrides,
  };
}

const envelope = (items, hasMore = false) => ({
  data: {
    schema_version: "current-account-task-discovery-v1",
    items,
    has_more: hasMore,
  },
});

test("current-account task contract freezes the backend final 9 kinds and 23 actions", () => {
  assert.deepEqual(CURRENT_ACCOUNT_TASK_CLASSIFICATIONS, ["NEEDS_ACTION", "WAITING", "COMPLETED"]);
  assert.deepEqual(CURRENT_ACCOUNT_TASK_RESOURCE_KINDS, [
    "APPEAL", "APPEAL_REVIEW", "CREATOR_PROFILE", "DEMAND", "DEMAND_REVIEW",
    "FINANCE_FUNDING_REVIEW", "TRUST_CASE", "TRUST_HOLD_RELEASE", "TRUST_REPORT",
  ]);
  assert.deepEqual(CURRENT_ACCOUNT_TASK_NEXT_ACTIONS, [
    "CLAIM_APPEAL_REVIEW",
    "CLAIM_DEMAND_REVIEW",
    "CLAIM_FINANCE_REVIEW",
    "CLAIM_TRUST_CASE",
    "CLAIM_TRUST_HOLD_RELEASE",
    "CONTINUE_FINANCE_REVIEW",
    "EDIT_APPEAL",
    "EDIT_OR_SUBMIT_DEMAND",
    "REVIEW_ASSIGNED_APPEAL",
    "REVIEW_ASSIGNED_DEMAND",
    "REVIEW_ASSIGNED_TRUST_CASE",
    "REVIEW_ASSIGNED_TRUST_HOLD_RELEASE",
    "VIEW_APPEAL_HISTORY",
    "VIEW_APPEAL_REVIEW_HISTORY",
    "VIEW_CREATOR_PROFILE",
    "VIEW_DEMAND_HISTORY",
    "VIEW_DEMAND_REVIEW_HISTORY",
    "VIEW_TRUST_CASE_HISTORY",
    "VIEW_TRUST_REPORT_HISTORY",
    "WAIT_FOR_APPEAL_REVIEW",
    "WAIT_FOR_DEMAND_PROCESSING",
    "WAIT_FOR_FINANCE_CONFIRMATION",
    "WAIT_FOR_TRUST_REVIEW",
  ]);
  assert.equal(taskCases.length, 23);
  assert.deepEqual(
    new Set(taskCases.map((spec) => spec[3])),
    new Set(CURRENT_ACCOUNT_TASK_NEXT_ACTIONS),
  );
  assert.equal(CURRENT_ACCOUNT_TASK_NEXT_ACTIONS.includes("EDIT_OR_PUBLISH_PROFILE"), false);
});

test("every accepted task action resolves to one closed local UI destination", () => {
  const expected = [
    ["WORKBENCH", "appeal-workbench-title"],
    ["WORKBENCH", "review-queue-title"],
    ["WORKBENCH", "finance-funding-queue-title"],
    ["WORKBENCH", "trust-workbench-title"],
    ["WORKBENCH", "trust-workbench-title"],
    ["WORKBENCH", "finance-funding-title"],
    ["WORKBENCH", "appeal-workbench-title"],
    ["RESOURCE", "DEMAND"],
    ["WORKBENCH", "appeal-workbench-title"],
    ["RESOURCE", "DEMAND"],
    ["WORKBENCH", "trust-workbench-title"],
    ["WORKBENCH", "trust-workbench-title"],
    ["WORKBENCH", "appeal-workbench-title"],
    ["RESOURCE", "CREATOR_PROFILE"],
    ["RESOURCE", "DEMAND"],
    ["WORKBENCH", "trust-workbench-title"],
    ["WORKBENCH", "appeal-workbench-title"],
    ["RESOURCE", "DEMAND"],
    ["WORKBENCH", "finance-funding-title"],
    ["WORKBENCH", "trust-workbench-title"],
    ["WORKBENCH", "review-history-title"],
    ["WORKBENCH", "trust-case-history-title"],
    ["WORKBENCH", "appeal-review-history-title"],
  ];
  assert.equal(expected.length, taskCases.length);
  taskCases.forEach((spec, index) => {
    const destination = resolveCurrentAccountTaskDestination(makeTask(spec, index + 1));
    assert.deepEqual(
      destination.kind === "RESOURCE"
        ? [destination.kind, destination.resource_type]
        : [destination.kind, destination.element_id],
      expected[index],
    );
  });
  assert.deepEqual(
    resolveCurrentAccountTaskDestination({
      ...makeTask(taskCases[17], 90),
      resource_kind: "DEMAND_REVIEW",
    }),
    { kind: "RESOURCE", resource_type: "DEMAND" },
  );
  assert.throws(
    () => resolveCurrentAccountTaskDestination({ resource_kind: "DEMAND", next_action: "CLAIM_DEMAND_REVIEW" }),
    /INVALID_CURRENT_ACCOUNT_TASK_DESTINATION/,
  );
});

test("a missing resource task opens only after the same action and exact object survive revalidation", () => {
  const original = makeTask(taskCases[7], 95);
  const exact = { resource_type: "DEMAND", object_id: original.resource_id };
  const refreshed = { ...original, updated_at: "2026-08-25T09:00:00Z" };
  const discovery = { schema_version: "current-account-task-discovery-v1", items: [refreshed], has_more: false };

  assert.equal(
    resolveRevalidatedCurrentAccountTaskResource(original, discovery, [exact]),
    exact,
  );
  assert.equal(resolveRevalidatedCurrentAccountTaskResource(original, {
    ...discovery,
    items: [],
  }, [exact]), null);
  assert.equal(resolveRevalidatedCurrentAccountTaskResource(original, {
    ...discovery,
    items: [{ ...refreshed, next_action: "WAIT_FOR_DEMAND_PROCESSING" }],
  }, [exact]), null);
  assert.equal(resolveRevalidatedCurrentAccountTaskResource(original, discovery, [{
    resource_type: "DEMAND",
    object_id: taskId(96),
  }]), null);
  assert.equal(resolveRevalidatedCurrentAccountTaskResource(original, discovery, [{
    resource_type: "CREATOR_PROFILE",
    object_id: original.resource_id,
  }]), null);
  assert.throws(() => resolveRevalidatedCurrentAccountTaskResource(
    makeTask(taskCases[0], 97),
    discovery,
    [exact],
  ), /INVALID_CURRENT_ACCOUNT_TASK_RESOURCE_RECHECK/);
});

test("an Appeal workbench task survives revalidation only with the exact kind, ID, and action", () => {
  const original = makeTask(taskCases[6], 98);
  const refreshed = { ...original, updated_at: "2026-08-25T10:00:00Z" };
  const discovery = {
    schema_version: "current-account-task-discovery-v1",
    items: [refreshed],
    has_more: false,
  };

  assert.equal(resolveRevalidatedCurrentAccountTask(original, discovery), refreshed);
  for (const changed of [
    { ...refreshed, resource_id: taskId(99) },
    { ...refreshed, next_action: "WAIT_FOR_APPEAL_REVIEW" },
    { ...refreshed, resource_kind: "DEMAND", next_action: "EDIT_OR_SUBMIT_DEMAND" },
  ]) assert.equal(resolveRevalidatedCurrentAccountTask(original, {
    ...discovery,
    items: [changed],
  }), null);
  assert.throws(
    () => resolveRevalidatedCurrentAccountTask(original, { ...discovery, items: null }),
    /INVALID_CURRENT_ACCOUNT_TASK_RECHECK/,
  );
});

test("a completed Appeal reviewer task resolves behaviorally to HISTORY only after exact revalidation", () => {
  const original = makeTask(taskCases[22], 112);
  const refreshed = { ...original, updated_at: "2026-08-25T10:30:00Z" };
  const discovery = {
    schema_version: "current-account-task-discovery-v1",
    items: [refreshed],
    has_more: false,
  };

  assert.equal(resolveAppealTaskReadKind(original), "HISTORY");
  assert.equal(resolveAppealTaskReadKind(makeTask(taskCases[8], 113)), "ASSIGNED");
  assert.equal(resolveAppealTaskReadKind(makeTask(taskCases[6], 114)), "OWN");
  assert.equal(resolveAppealTaskReadKind(makeTask(taskCases[0], 116)), null);
  assert.equal(resolveRevalidatedCurrentAccountTask(original, discovery), refreshed);
  for (const changed of [
    { ...refreshed, resource_id: taskId(115) },
    { ...refreshed, next_action: "REVIEW_ASSIGNED_APPEAL", classification: "NEEDS_ACTION", source_status: "ASSIGNED", resource_path: `/v1/app/appeal-review/appeals/${refreshed.resource_id}` },
    { ...refreshed, resource_kind: "APPEAL", next_action: "VIEW_APPEAL_HISTORY", source_status: "DECIDED", resource_path: `/v1/app/appeals/${refreshed.resource_id}` },
  ]) assert.equal(resolveRevalidatedCurrentAccountTask(original, {
    ...discovery,
    items: [changed],
  }), null);
});

test("Finance detail tasks require one exact fresh assigned queue row before detail binding", () => {
  const original = makeTask(taskCases[5], 117);
  const refreshed = { ...original, updated_at: "2026-08-25T10:45:00Z" };
  const discovery = {
    schema_version: "current-account-task-discovery-v1",
    items: [refreshed],
    has_more: false,
  };
  const queueItem = {
    demand_id: taskId(118),
    demand_version_id: taskId(119),
    demand_revision: 4,
    funding_review_id: original.resource_id,
    review_status: "PENDING",
    review_revision: 3,
    assigned_to_me: true,
    confirmation_count: 0,
    required_confirmations: 2,
    expires_at: original.due_at,
    etag: '"funding-review-3"',
  };
  const exact = resolveRevalidatedFinanceTaskQueueItem(original, discovery, [queueItem]);
  assert.deepEqual(exact, {
    action: "CONTINUE_FINANCE_REVIEW",
    queue_item: queueItem,
    task: refreshed,
  });
  assert.equal(resolveFinanceTaskDetailAction(original), "CONTINUE_FINANCE_REVIEW");
  assert.equal(resolveFinanceTaskDetailAction(makeTask(taskCases[18], 120)), "WAIT_FOR_FINANCE_CONFIRMATION");
  assert.equal(resolveFinanceTaskDetailAction(makeTask(taskCases[2], 121)), null);

  for (const [changedTask, queue] of [
    [{ ...refreshed, resource_id: taskId(122) }, [queueItem]],
    [{ ...refreshed, next_action: "WAIT_FOR_FINANCE_CONFIRMATION", classification: "WAITING" }, [queueItem]],
    [refreshed, [{ ...queueItem, assigned_to_me: false }]],
    [refreshed, [{ ...queueItem, funding_review_id: taskId(123) }]],
    [refreshed, [queueItem, { ...queueItem, demand_id: taskId(124) }]],
  ]) assert.equal(resolveRevalidatedFinanceTaskQueueItem(original, {
    ...discovery,
    items: [changedTask],
  }, queue), null);
  assert.throws(
    () => resolveRevalidatedFinanceTaskQueueItem(makeTask(taskCases[2], 125), discovery, [queueItem]),
    /INVALID_FINANCE_TASK_QUEUE_RECHECK/,
  );
});

test("Finance detail binding closes IDs, Demand version, review state, ETag and task actions", () => {
  const continueTask = makeTask(taskCases[5], 126);
  const queueItem = {
    demand_id: taskId(127),
    demand_version_id: taskId(128),
    demand_revision: 7,
    funding_review_id: continueTask.resource_id,
    review_status: "PENDING",
    review_revision: 9,
    assigned_to_me: true,
    confirmation_count: 0,
    required_confirmations: 2,
    expires_at: continueTask.due_at,
    etag: '"funding-review-9"',
  };
  const review = {
    funding_review_id: continueTask.resource_id,
    demand_id: queueItem.demand_id,
    demand_version_id: queueItem.demand_version_id,
    status: "PENDING",
    revision: queueItem.review_revision,
    assignment_expires_at: queueItem.expires_at,
    confirmation_count: queueItem.confirmation_count,
    required_confirmations: queueItem.required_confirmations,
    available_actions: ["CONFIRM", "RELEASE_ASSIGNMENT", "SUBMIT_FINDING"],
    can_confirm: true,
    etag: queueItem.etag,
  };
  assert.equal(resolveFinanceTaskDetail(continueTask, queueItem, review, review.etag), review);
  const waitingTask = makeTask(taskCases[18], 126);
  const waitingQueue = { ...queueItem, confirmation_count: 1 };
  const waitingReview = {
    ...review,
    confirmation_count: 1,
    available_actions: [],
    can_confirm: false,
  };
  assert.equal(resolveFinanceTaskDetail(waitingTask, waitingQueue, waitingReview, waitingReview.etag), waitingReview);

  for (const [task, queue, detail, etag] of [
    [continueTask, queueItem, { ...review, funding_review_id: taskId(129) }, review.etag],
    [continueTask, queueItem, { ...review, demand_id: taskId(130) }, review.etag],
    [continueTask, queueItem, { ...review, demand_version_id: taskId(131) }, review.etag],
    [continueTask, queueItem, { ...review, revision: 10 }, review.etag],
    [continueTask, queueItem, { ...review, status: "SECURED" }, review.etag],
    [continueTask, queueItem, { ...review, etag: '"funding-review-10"' }, '"funding-review-10"'],
    [continueTask, queueItem, { ...review, available_actions: [], can_confirm: false }, review.etag],
    [waitingTask, waitingQueue, { ...waitingReview, available_actions: ["CONFIRM"], can_confirm: true }, waitingReview.etag],
    [continueTask, { ...queueItem, assigned_to_me: false }, review, review.etag],
    [continueTask, queueItem, review, null],
  ]) assert.equal(resolveFinanceTaskDetail(task, queue, detail, etag), null);
});

test("each final action accepts only its closed classification, state, kind, and exact API path", () => {
  taskCases.forEach((spec, index) => {
    const item = makeTask(spec, index + 1);
    assert.deepEqual(parseCurrentAccountTaskDiscovery(envelope([item])).items, [item]);
    assert.throws(
      () => parseCurrentAccountTaskDiscovery(envelope([{ ...item, resource_path: "/v1/app/tasks" }])),
      /INVALID_APP_CONTRACT/,
    );
  });

  const profile = makeTask(taskCases[13], 40);
  for (const item of [
    profile,
    { ...profile, classification: "WAITING", source_status: "ACTIVE" },
    { ...profile, classification: "WAITING", source_status: "PAUSED" },
    { ...profile, classification: "COMPLETED", source_status: "ARCHIVED" },
  ]) assert.deepEqual(parseCurrentAccountTaskDiscovery(envelope([item])).items, [item]);

  for (const unsafe of [
    { ...profile, next_action: "EDIT_OR_PUBLISH_PROFILE" },
    { ...profile, classification: "WAITING" },
    { ...profile, source_status: "ACTIVE" },
    { ...profile, resource_kind: "DEMAND" },
    { ...profile, resource_path: `${profile.resource_path}?resource_id=${profile.resource_id}` },
    { ...profile, resource_path: `/v1/app/profiles/${taskId(41)}` },
  ]) assert.throws(
    () => parseCurrentAccountTaskDiscovery(envelope([unsafe])),
    /INVALID_APP_CONTRACT/,
  );

  const financeClaim = makeTask(taskCases[2], 50);
  assert.deepEqual(parseCurrentAccountTaskDiscovery(envelope([{
    ...financeClaim,
    source_status: "PENDING",
  }])).items[0].source_status, "PENDING");
  const reviewerWaiting = {
    ...makeTask(taskCases[17], 51),
    resource_kind: "DEMAND_REVIEW",
  };
  assert.deepEqual(parseCurrentAccountTaskDiscovery(envelope([reviewerWaiting])).items, [reviewerWaiting]);
});

test("task discovery rejects unknown fields, identities, duplicate resources, and non-boolean pagination", () => {
  const item = makeTask(taskCases[7], 60);
  for (const unsafe of [
    { ...envelope([item]), actor_user_id: taskId(90) },
    { data: { ...envelope([item]).data, organization_id: taskId(91) } },
    envelope([{ ...item, duty_grant_id: taskId(92) }]),
    envelope([{ ...item, resource_id: "00000000-0000-0000-0000-000000000000" }]),
    envelope([{ ...item, resource_id: "10000000-0000-4000-8000-0000000000AA" }]),
    envelope([{ ...item, resource_id: "not-a-uuid" }]),
    envelope([{ ...item, source_status: "UNKNOWN" }]),
    envelope([{ ...item, due_at: undefined }]),
    envelope([item, item]),
    { data: { ...envelope([item]).data, has_more: 0 } },
    { data: { ...envelope([item]).data, items: null } },
    { data: { ...envelope([item]).data, schema_version: "current-account-task-discovery-v2" } },
    envelope(Array.from({ length: 2001 }, (_, index) => makeTask(taskCases[7], index + 1))),
    envelope([item], false).data,
  ]) assert.throws(
    () => parseCurrentAccountTaskDiscovery(unsafe),
    /INVALID_APP_CONTRACT/,
  );
});

test("task timestamps are strict UTC instants and ordering mirrors the backend stable sort", () => {
  const first = makeTask(taskCases[6], 105, { updated_at: "2026-08-25T10:00:00Z" });
  const second = makeTask(taskCases[6], 101, { updated_at: "2026-08-25T09:00:00+00:00" });
  const third = makeTask(taskCases[6], 103, { updated_at: "2026-08-25T09:00:00Z" });
  const fourth = makeTask(taskCases[7], 102, { updated_at: null, due_at: "2026-08-25T09:00:00.000000000Z" });
  const waiting = makeTask(taskCases[17], 106, { updated_at: "2027-08-25T09:00:00Z" });
  const completed = makeTask(taskCases[13], 107, {
    classification: "COMPLETED",
    source_status: "ARCHIVED",
    updated_at: "2028-08-25T09:00:00Z",
  });
  const sorted = [first, second, third, fourth, waiting, completed];
  assert.deepEqual(parseCurrentAccountTaskDiscovery(envelope(sorted, true)), {
    schema_version: "current-account-task-discovery-v1",
    items: sorted,
    has_more: true,
  });
  assert.throws(
    () => parseCurrentAccountTaskDiscovery(envelope([...sorted].reverse())),
    /INVALID_APP_CONTRACT/,
  );

  const valid = makeTask(taskCases[7], 110, {
    updated_at: "2026-08-25T08:00:00.123456789Z",
    due_at: "2026-08-26T08:00:00+00:00",
  });
  assert.deepEqual(parseCurrentAccountTaskDiscovery(envelope([valid])).items, [valid]);
  for (const timestamp of [
    "2026-08-25T08:00:00+08:00",
    "2026-08-25T08:00:00",
    "2026-02-30T08:00:00Z",
    "2026-08-25 08:00:00Z",
    "2026-08-25T08:00:00.1234567890Z",
    "not-a-time",
  ]) assert.throws(
    () => parseCurrentAccountTaskDiscovery(envelope([{ ...valid, updated_at: timestamp }])),
    /INVALID_APP_CONTRACT/,
  );
});

test("BFF admits only the exact task GET and requires a server-issued workspace selection", async () => {
  const request = await createAppProxyRequest(new Request("http://localhost:3000/v1/app/tasks", {
    headers: { "x-workspace-id": workspace },
  }), "http://api:8000");
  assert.equal(request.method, "GET");
  assert.equal(request.url, "http://api:8000/v1/app/tasks");
  assert.equal(request.headers.get("x-workspace-id"), workspace);

  for (const source of [
    new Request("http://localhost:3000/v1/app/tasks?limit=1", { headers: { "x-workspace-id": workspace } }),
    new Request("http://localhost:3000/v1/app/tasks/", { headers: { "x-workspace-id": workspace } }),
    new Request("http://localhost:3000/v1/app/tasks", { method: "POST", headers: { "x-workspace-id": workspace } }),
    new Request("http://localhost:3000/v1/app/tasks"),
  ]) await assert.rejects(
    createAppProxyRequest(source, "http://api:8000"),
    /APP_ROUTE_NOT_ALLOWED|WORKSPACE_REQUIRED/,
  );

  let dispatched = false;
  const closed = await proxyAppRequest(new Request("http://localhost:3000/v1/app/tasks?limit=1", {
    headers: { "x-workspace-id": workspace },
  }), {
    baseUrl: "http://api:8000",
    fetchImpl: async () => {
      dispatched = true;
      throw new Error("must not dispatch");
    },
  });
  assert.equal(closed.status, 404);
  assert.equal(dispatched, false);
});

test("task BFF rebuilds validated success and error responses with closed headers and bodies", async () => {
  const item = makeTask(taskCases[13], 120);
  const value = envelope([item]);
  const source = () => new Request("http://localhost:3000/v1/app/tasks", {
    headers: { "x-workspace-id": workspace },
  });
  const success = await proxyAppRequest(source(), {
    baseUrl: "http://api:8000",
    fetchImpl: async () => Response.json(value, {
      headers: {
        "cache-control": "no-store",
        "content-type": "application/json; charset=utf-8",
        "x-backend-secret": "must-drop",
        "x-trace-id": "task_trace_00000001",
      },
    }),
  });
  assert.equal(success.status, 200);
  assert.equal(success.headers.get("cache-control"), "no-store");
  assert.equal(success.headers.get("x-trace-id"), "task_trace_00000001");
  assert.equal(success.headers.get("x-backend-secret"), null);
  assert.equal(success.headers.get("etag"), null);
  assert.deepEqual(await success.json(), value);

  for (const [status, code] of [
    [401, "AUTHENTICATION_REQUIRED"],
    [401, "SESSION_EXPIRED"],
    [403, "ACCESS_DENIED"],
    [404, "RESOURCE_NOT_FOUND"],
    [409, "WORKSPACE_REQUIRED"],
    [503, "SERVICE_UNAVAILABLE"],
  ]) {
    const response = await proxyAppRequest(source(), {
      baseUrl: "http://api:8000",
      fetchImpl: async () => Response.json({ error: { code } }, {
        status,
        headers: { "cache-control": "no-store", "content-type": "application/json" },
      }),
    });
    assert.equal(response.status, status);
    assert.deepEqual(await response.json(), { error: { code } });
  }
});

test("task BFF fails closed on projection leaks, forged errors, and unsafe transport metadata", async () => {
  const item = makeTask(taskCases[13], 130);
  const source = () => new Request("http://localhost:3000/v1/app/tasks", {
    headers: { "x-workspace-id": workspace },
  });
  const unsafeResponses = [
    () => Response.json(envelope([{ ...item, actor_user_id: taskId(999) }]), {
      headers: { "cache-control": "no-store", "content-type": "application/json" },
    }),
    () => Response.json(envelope([item]), {
      headers: { "content-type": "application/json" },
    }),
    () => Response.json(envelope([item]), {
      headers: { "cache-control": "no-store", "content-type": "application/json", etag: '"tasks-1"' },
    }),
    () => Response.json(envelope([item]), {
      headers: { "cache-control": "no-store", "content-type": "application/json", "set-cookie": "secret=value" },
    }),
    () => Response.json({ error: { code: "RESOURCE_NOT_FOUND" } }, {
      status: 403,
      headers: { "cache-control": "no-store", "content-type": "application/json" },
    }),
    () => Response.json({ error: { code: "ACCESS_DENIED", message: "leaked detail" } }, {
      status: 403,
      headers: { "cache-control": "no-store", "content-type": "application/json" },
    }),
  ];
  for (const makeResponse of unsafeResponses) {
    const response = await proxyAppRequest(source(), {
      baseUrl: "http://api:8000",
      fetchImpl: async () => makeResponse(),
    });
    assert.equal(response.status, 503);
    assert.equal(response.headers.get("cache-control"), "no-store");
    assert.equal(response.headers.get("set-cookie"), null);
    assert.equal(response.headers.get("etag"), null);
    const body = await response.json();
    assert.equal(body.code, "INTERNAL_PILOT_BACKEND_UNAVAILABLE");
    assert.doesNotMatch(JSON.stringify(body), /actor_user_id|leaked detail|secret=value|tasks-1/);
  }
});
