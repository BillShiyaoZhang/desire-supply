import assert from "node:assert/strict";
import test from "node:test";

import {
  createAppealApplicationDraftIntent,
  createAppealDecisionIntent,
  createAppealOpenIntent,
  createAppealReviewClaimIntent,
  createAppealReviewDraftIntent,
  createAppealReviewReleaseIntent,
  createAppealSubmitIntent,
  parseAppealAssignedEnvelope,
  parseAppealCommandEnvelope,
  parseAppealOwnEnvelope,
  parseAppealQueueEnvelope,
  parseAppealReviewHistoryEnvelope,
  parseAppealReviewTerminalEnvelope,
  parsePendingIntent,
  serializePendingIntent,
} from "../lib/app-contract.mjs";
import { createAppProxyRequest, proxyAppRequest } from "../lib/server-proxy.mjs";

const workspace = "org:10000000-0000-4000-8000-000000000001";
const platformWorkspace = "platform:10000000-0000-4000-8000-000000000001";
const csrfToken = "csrf_token_internal_000000000000001";
const idempotencyKey = "appeal-command-idempotency-0001";
const appealId = "10000000-0000-4000-8000-000000000010";
const caseId = "20000000-0000-4000-8000-000000000010";
const outcomeId = "30000000-0000-4000-8000-000000000010";
const demandId = "40000000-0000-4000-8000-000000000010";
const demandVersionId = "50000000-0000-4000-8000-000000000010";
const packetId = "60000000-0000-4000-8000-000000000010";
const evidenceId = "70000000-0000-4000-8000-000000000010";
const decisionVersionId = "80000000-0000-4000-8000-000000000010";
const appealEtag = `"appeal-4-${"a".repeat(24)}"`;
const draftEtag = `"appeal-2-${"e".repeat(24)}"`;
const queueEtag = `"appeal-2-${"b".repeat(24)}"`;

const source = {
  action_codes: ["VERIFY_DEMAND"],
  appeal_deadline: "2026-09-18T08:00:00Z",
  appeal_eligibility_code: "ELIGIBLE",
  appeal_eligible: true,
  case_id: caseId,
  content_sha256: "c".repeat(64),
  decided_at: "2026-08-18T08:00:00Z",
  demand_id: demandId,
  demand_version_id: demandVersionId,
  evidence_packet_sha256: "d".repeat(64),
  evidence_packet_version_id: packetId,
  outcome_code: "PROTECTION_MAINTAINED",
  outcome_version_id: outcomeId,
  policy_version: "trust.appeal.v1",
  reason_codes: ["PRECAUTIONARY_ACTION_REQUIRED"],
};

const applicationDraft = {
  edited_at: "2026-08-18T09:00:00Z",
  grounds: ["NEW_MATERIAL_EVIDENCE"],
  new_evidence_reference_ids: [evidenceId],
  requested_outcome: "MODIFY_MEASURE",
  statement_recorded: true,
  version: 2,
};

const submittedApplication = {
  grounds: applicationDraft.grounds,
  new_evidence_reference_ids: applicationDraft.new_evidence_reference_ids,
  requested_outcome: applicationDraft.requested_outcome,
  statement_recorded: true,
  submitted_at: "2026-08-18T09:05:00Z",
};

const ownAppeal = {
  aggregate_version: 4,
  appeal_id: appealId,
  application: submittedApplication,
  application_draft: applicationDraft,
  decision: null,
  entity_tag: appealEtag,
  source,
  source_case_id: caseId,
  source_outcome_version_id: outcomeId,
  status: "IN_REVIEW",
};

const draftAppeal = {
  ...ownAppeal,
  aggregate_version: 2,
  application: null,
  decision: null,
  entity_tag: draftEtag,
  status: "DRAFT",
};

const queueItem = {
  appeal_id: appealId,
  entity_tag: queueEtag,
  grounds: ["NEW_MATERIAL_EVIDENCE"],
  requested_outcome: "MODIFY_MEASURE",
  source_case_id: caseId,
  source_outcome_version_id: outcomeId,
  submitted_at: "2026-08-18T09:05:00Z",
};

const assessment = {
  accepted_evidence_reference_ids: [evidenceId],
  assessment_code: "ACCEPTED",
  finding_codes: ["NEW_EVIDENCE_MATERIAL"],
  ground: "NEW_MATERIAL_EVIDENCE",
};

const terminalDecision = {
  assessments: [assessment],
  decided_at: "2026-08-18T10:00:00Z",
  decision_code: "MODIFY",
  decision_sha256: "f".repeat(64),
  decision_version_id: decisionVersionId,
  policy_version: "trust.appeal.v1",
  reason_codes: ["NEW_EVIDENCE_REVIEWED"],
  remedy_delta_codes: ["NARROW_CORRECTIVE_MEASURE"],
};

const reviewHistory = {
  entity_tag: appealEtag,
  has_more: false,
  items: [{
    appeal_id: appealId,
    decided_at: terminalDecision.decided_at,
    decision_code: terminalDecision.decision_code,
  }],
};

const terminalAppealReview = {
  appeal_id: appealId,
  application: submittedApplication,
  decision: terminalDecision,
  entity_tag: appealEtag,
  review_note_recorded: true,
  status: "DECIDED",
};

const assignedAppeal = {
  appeal: ownAppeal,
  application: submittedApplication,
  assignment_expires_at: "2026-08-18T11:00:00Z",
  entity_tag: appealEtag,
  review_draft: {
    assessments: [assessment],
    edited_at: "2026-08-18T09:20:00Z",
    reason_codes: ["NEW_EVIDENCE_REVIEWED"],
    remedy_delta_codes: ["NARROW_CORRECTIVE_MEASURE"],
    review_note_recorded: true,
    version: 2,
  },
  source,
};

const commandResult = {
  aggregate_version: 4,
  appeal_id: appealId,
  appeal_status: "IN_REVIEW",
  application_draft_version: 2,
  application_version: 1,
  completed_at: "2026-08-18T09:20:00Z",
  decision_version_id: null,
  event_types: ["AppealReviewDraftSaved"],
  replayed: false,
  review_draft_version: 2,
};

const applicationInput = {
  applicant_statement: "仅用于密封保存的申请人陈述。",
  grounds: ["NEW_MATERIAL_EVIDENCE"],
  new_evidence_reference_ids: [evidenceId],
  requested_outcome: "MODIFY_MEASURE",
};

const reviewInput = {
  assessments: [assessment],
  reason_codes: ["NEW_EVIDENCE_REVIEWED"],
  remedy_delta_codes: ["NARROW_CORRECTIVE_MEASURE"],
  reviewer_note: "仅用于密封保存的复核备注。",
};

test("Appeal parsers accept only closed party-safe projections and receipt-safe writes", () => {
  assert.deepEqual(parseAppealOwnEnvelope({ data: ownAppeal }), ownAppeal);
  assert.deepEqual(parseAppealQueueEnvelope({ data: { entity_tag: queueEtag, items: [queueItem] } }).items, [queueItem]);
  assert.deepEqual(parseAppealAssignedEnvelope({ data: assignedAppeal }), assignedAppeal);
  assert.deepEqual(parseAppealCommandEnvelope({ data: commandResult }), commandResult);

  for (const unsafe of [
    { data: { ...ownAppeal, applicant_user_id: appealId } },
    { data: { ...ownAppeal, application_draft: { ...applicationDraft, applicant_statement: "leak" } } },
    { data: { ...assignedAppeal, reviewer_note: "leak" } },
    { data: { ...assignedAppeal, assignment_id: appealId } },
  ]) assert.throws(
    () => Object.hasOwn(unsafe.data, "appeal_id") ? parseAppealOwnEnvelope(unsafe) : parseAppealAssignedEnvelope(unsafe),
    /INVALID_APP_CONTRACT/,
  );
  assert.throws(() => parseAppealCommandEnvelope({ data: { ...commandResult, entity_tag: appealEtag } }), /INVALID_APP_CONTRACT/);
  assert.throws(() => parseAppealOwnEnvelope({ data: { ...ownAppeal, status: "UNKNOWN" } }), /INVALID_APP_CONTRACT/);
});

test("Appeal reviewer history parsers accept only stable party-safe terminal projections", () => {
  assert.deepEqual(parseAppealReviewHistoryEnvelope({ data: reviewHistory }), reviewHistory);
  assert.deepEqual(parseAppealReviewTerminalEnvelope({ data: terminalAppealReview }), terminalAppealReview);

  const older = {
    appeal_id: "10000000-0000-4000-8000-000000000009",
    decided_at: "2026-08-18T09:59:00Z",
    decision_code: "AFFIRM",
  };
  assert.deepEqual(parseAppealReviewHistoryEnvelope({
    data: { ...reviewHistory, items: [...reviewHistory.items, older], has_more: true },
  }).items, [...reviewHistory.items, older]);

  for (const unsafe of [
    { data: { ...reviewHistory, actor_user_id: appealId } },
    { data: { ...reviewHistory, items: [older, ...reviewHistory.items] } },
    { data: { ...reviewHistory, items: [reviewHistory.items[0], reviewHistory.items[0]] } },
    { data: { ...reviewHistory, items: [], has_more: true } },
    { data: { ...terminalAppealReview, reviewer_user_id: appealId } },
    { data: { ...terminalAppealReview, source } },
    { data: { ...terminalAppealReview, decision: { ...terminalDecision, accepted_by: appealId } } },
    { data: { ...terminalAppealReview, application: { ...submittedApplication, applicant_statement: "leak" } } },
    { data: { ...terminalAppealReview, decision: { ...terminalDecision, assessments: [{ ...assessment, accepted_evidence_reference_ids: [packetId] }] } } },
    { data: { ...terminalAppealReview, decision: { ...terminalDecision, decided_at: "2026-08-18T08:59:59Z" } } },
  ]) assert.throws(
    () => Object.hasOwn(unsafe.data, "items")
      ? parseAppealReviewHistoryEnvelope(unsafe)
      : parseAppealReviewTerminalEnvelope(unsafe),
    /INVALID_APP_CONTRACT/,
  );
});

test("Appeal intents bind exact IDs, versions and ETags without browser authority", () => {
  const opened = createAppealOpenIntent({ sourceOutcomeVersionId: outcomeId, csrfToken, idempotencyKey });
  assert.equal(opened.path, "/v1/app/appeals");
  assert.equal(opened.headers["if-match"], undefined);
  assert.deepEqual(opened.body, { source_outcome_version_id: outcomeId });

  const draft = createAppealApplicationDraftIntent({ appeal: draftAppeal, application: applicationInput, csrfToken, idempotencyKey });
  assert.equal(draft.method, "PUT");
  assert.equal(draft.headers["if-match"], draftEtag);
  assert.deepEqual(draft.body, applicationInput);
  assert.deepEqual(createAppealSubmitIntent({ appeal: draftAppeal, csrfToken, idempotencyKey }).body, { expected_draft_version: 2 });
  assert.deepEqual(createAppealReviewClaimIntent({ queueItem, csrfToken, idempotencyKey }).body, {});
  assert.deepEqual(createAppealReviewReleaseIntent({ assignedAppeal, reasonCode: "WORKLOAD_RELEASE", csrfToken, idempotencyKey }).body, { reason_code: "WORKLOAD_RELEASE" });
  assert.deepEqual(createAppealReviewDraftIntent({ assignedAppeal, review: reviewInput, csrfToken, idempotencyKey }).body, reviewInput);
  assert.deepEqual(createAppealDecisionIntent({ assignedAppeal, decisionCode: "MODIFY", csrfToken, idempotencyKey }).body, {
    decision_code: "MODIFY",
    expected_review_draft_version: 2,
  });
  assert.throws(() => createAppealReviewDraftIntent({
    assignedAppeal,
    review: { ...reviewInput, assessments: [{ ...assessment, accepted_evidence_reference_ids: [packetId] }] },
    csrfToken,
    idempotencyKey,
  }), /INVALID_APP_CONTRACT/);
  assert.throws(() => createAppealDecisionIntent({ assignedAppeal, decisionCode: "AFFIRM", csrfToken, idempotencyKey }), /INVALID_APP_CONTRACT/);
  assert.doesNotMatch(JSON.stringify([opened, draft]), /actor|applicant_user|reviewer_user|assignment_id|duty|role/);
});

test("Appeal outcome recovery persists safe commands but never restricted narrative", () => {
  const safe = {
    version: 1,
    saved_at: "2026-08-18T09:30:00Z",
    resource_type: "APPEAL",
    object_id: appealId,
    label: "提交申诉",
    intent: createAppealSubmitIntent({ appeal: draftAppeal, csrfToken, idempotencyKey }),
  };
  assert.deepEqual(parsePendingIntent(serializePendingIntent(safe), Date.parse(safe.saved_at)), safe);

  for (const [resource_type, intent] of [
    ["APPEAL", createAppealApplicationDraftIntent({ appeal: draftAppeal, application: applicationInput, csrfToken, idempotencyKey })],
    ["APPEAL_REVIEW", createAppealReviewDraftIntent({ assignedAppeal, review: reviewInput, csrfToken, idempotencyKey })],
  ]) {
    const raw = { ...safe, resource_type, intent };
    assert.throws(() => serializePendingIntent(raw), /INVALID_PENDING_INTENT/);
    assert.equal(parsePendingIntent(JSON.stringify(raw), Date.parse(raw.saved_at)), null);
  }
});

test("Appeal BFF admits the canonical operations, assignments, and query-free completed history", async () => {
  const reads = [
    [`/v1/app/appeals?source_outcome_version_id=${outcomeId}`, workspace],
    [`/v1/app/appeals/${appealId}`, workspace],
    ["/v1/app/appeal-review/queue", platformWorkspace],
    ["/v1/app/appeal-review/assignments", platformWorkspace],
    ["/v1/app/appeal-review/history", platformWorkspace],
    [`/v1/app/appeal-review/history/${appealId}`, platformWorkspace],
    [`/v1/app/appeal-review/appeals/${appealId}`, platformWorkspace],
  ];
  for (const [path, workspaceId] of reads) {
    const request = await createAppProxyRequest(new Request(`http://localhost:3000${path}`, {
      headers: { "x-workspace-id": workspaceId },
    }), "http://api:8000");
    assert.equal(request.url, `http://api:8000${path}`);
  }

  const writes = [
    ["POST", "/v1/app/appeals", { source_outcome_version_id: outcomeId }, false, workspace],
    ["PUT", `/v1/app/appeals/${appealId}/draft`, applicationInput, true, workspace],
    ["POST", `/v1/app/appeals/${appealId}/submit`, { expected_draft_version: 2 }, true, workspace],
    ["POST", `/v1/app/appeal-review/queue/${appealId}/claim`, {}, true, platformWorkspace],
    ["POST", `/v1/app/appeal-review/appeals/${appealId}/assignment/release`, { reason_code: "WORKLOAD_RELEASE" }, true, platformWorkspace],
    ["PUT", `/v1/app/appeal-review/appeals/${appealId}/review-draft`, reviewInput, true, platformWorkspace],
    ["POST", `/v1/app/appeal-review/appeals/${appealId}/decide`, { decision_code: "MODIFY", expected_review_draft_version: 2 }, true, platformWorkspace],
  ];
  for (const [method, path, body, needsEtag, workspaceId] of writes) {
    const request = await createAppProxyRequest(new Request(`http://localhost:3000${path}`, {
      method,
      headers: {
        "content-type": "application/json",
        "idempotency-key": idempotencyKey,
        ...(needsEtag ? { "if-match": appealEtag } : {}),
        "x-csrf-token": csrfToken,
        "x-workspace-id": workspaceId,
      },
      body: JSON.stringify(body),
    }), "http://api:8000");
    assert.deepEqual(await request.json(), body);
    assert.equal(request.headers.get("origin"), "http://api:8000");
  }
});

test("Appeal BFF fails closed on query, authority, narrative and response leakage", async () => {
  for (const path of [
    "/v1/app/appeals",
    `/v1/app/appeals?source_outcome_version_id=${outcomeId}&actor=forged`,
    `/v1/app/appeals?source_outcome_version_id=${outcomeId}&source_outcome_version_id=${outcomeId}`,
    `/v1/app/appeals/${appealId}?source_outcome_version_id=${outcomeId}`,
  ]) await assert.rejects(
    createAppProxyRequest(new Request(`http://localhost:3000${path}`, { headers: { "x-workspace-id": workspace } }), "http://api:8000"),
    /APP_ROUTE_NOT_ALLOWED|INVALID_APPEAL_REQUEST/,
  );

  for (const path of [
    "/v1/app/appeal-review/history?limit=1",
    `/v1/app/appeal-review/history/${appealId}?cursor=forged`,
  ]) {
    const response = await proxyAppRequest(new Request(`http://localhost:3000${path}`, {
      headers: { "x-workspace-id": platformWorkspace },
    }), { baseUrl: "http://api:8000", fetchImpl: async () => { throw new Error("must not fetch"); } });
    assert.equal(response.status, 400);
    assert.deepEqual(await response.json(), { error: { code: "INVALID_REQUEST", path: "/query" } });
  }

  await assert.rejects(createAppProxyRequest(new Request(`http://localhost:3000/v1/app/appeals/${appealId}/draft`, {
    method: "PUT",
    headers: {
      "content-type": "application/json", "idempotency-key": idempotencyKey, "if-match": appealEtag,
      "x-actor-id": appealId, "x-csrf-token": csrfToken, "x-workspace-id": workspace,
    },
    body: JSON.stringify(applicationInput),
  }), "http://api:8000"), /AUTHORITY_HEADER_FORBIDDEN/);

  const unsafeResponse = await proxyAppRequest(new Request(`http://localhost:3000/v1/app/appeals/${appealId}`, {
    headers: { "x-workspace-id": workspace },
  }), {
    baseUrl: "http://api:8000",
    fetchImpl: async () => Response.json({ data: { ...ownAppeal, applicant_statement: "leak" } }, {
      headers: { "cache-control": "no-store", etag: appealEtag },
    }),
  });
  assert.equal(unsafeResponse.status, 503);

  const richWrite = await proxyAppRequest(new Request("http://localhost:3000/v1/app/appeals", {
    method: "POST",
    headers: {
      "content-type": "application/json", "idempotency-key": idempotencyKey,
      "x-csrf-token": csrfToken, "x-workspace-id": workspace,
    },
    body: JSON.stringify({ source_outcome_version_id: outcomeId }),
  }), {
    baseUrl: "http://api:8000",
    fetchImpl: async () => Response.json({ data: ownAppeal }, { status: 201, headers: { "cache-control": "no-store" } }),
  });
  assert.equal(richWrite.status, 503);
});

test("Appeal BFF preserves only validated safe reads, ETags and no-store", async () => {
  const response = await proxyAppRequest(new Request(`http://localhost:3000/v1/app/appeal-review/appeals/${appealId}`, {
    headers: { "x-workspace-id": platformWorkspace },
  }), {
    baseUrl: "http://api:8000",
    fetchImpl: async () => Response.json({ data: assignedAppeal }, {
      headers: { "cache-control": "no-store", "content-type": "application/json", etag: appealEtag },
    }),
  });
  assert.equal(response.status, 200);
  assert.equal(response.headers.get("etag"), appealEtag);
  assert.equal(response.headers.get("cache-control"), "no-store");
  assert.deepEqual(await response.json(), { data: assignedAppeal });

  const notFound = await proxyAppRequest(new Request(`http://localhost:3000/v1/app/appeals/${appealId}`, {
    headers: { "x-workspace-id": workspace },
  }), {
    baseUrl: "http://api:8000",
    fetchImpl: async () => Response.json({ error: { code: "RESOURCE_NOT_FOUND", path: "/path/appeal_id" } }, {
      status: 404,
      headers: { "cache-control": "no-store", "content-type": "application/json" },
    }),
  });
  assert.equal(notFound.status, 404);
  assert.deepEqual(await notFound.json(), { error: { code: "RESOURCE_NOT_FOUND", path: "/path/appeal_id" } });

  const obsoleteError = await proxyAppRequest(new Request(`http://localhost:3000/v1/app/appeals/${appealId}`, {
    headers: { "x-workspace-id": workspace },
  }), {
    baseUrl: "http://api:8000",
    fetchImpl: async () => Response.json({ error: { code: "RESOURCE_NOT_FOUND", message: "unsafe", request_id: appealId } }, {
      status: 404,
      headers: { "cache-control": "no-store", "content-type": "application/json" },
    }),
  });
  assert.equal(obsoleteError.status, 503);
});

test("Appeal BFF validates and reserializes completed history and terminal detail", async () => {
  for (const [path, projection] of [
    ["/v1/app/appeal-review/history", reviewHistory],
    [`/v1/app/appeal-review/history/${appealId}`, terminalAppealReview],
  ]) {
    const response = await proxyAppRequest(new Request(`http://localhost:3000${path}`, {
      headers: { "x-workspace-id": platformWorkspace },
    }), {
      baseUrl: "http://api:8000",
      fetchImpl: async () => Response.json({ data: projection }, {
        headers: { "cache-control": "no-store", etag: projection.entity_tag },
      }),
    });
    assert.equal(response.status, 200);
    assert.equal(response.headers.get("etag"), projection.entity_tag);
    assert.equal(response.headers.get("cache-control"), "no-store");
    assert.deepEqual(await response.json(), { data: projection });
  }

  for (const [projection, etag] of [
    [{ ...reviewHistory, reviewer_user_id: appealId }, appealEtag],
    [{ ...terminalAppealReview, assignment_id: appealId }, appealEtag],
    [reviewHistory, `"appeal-5-${"0".repeat(24)}"`],
  ]) {
    const detail = Object.hasOwn(projection, "status");
    const response = await proxyAppRequest(new Request(
      `http://localhost:3000/v1/app/appeal-review/history${detail ? `/${appealId}` : ""}`,
      { headers: { "x-workspace-id": platformWorkspace } },
    ), {
      baseUrl: "http://api:8000",
      fetchImpl: async () => Response.json({ data: projection }, {
        headers: { "cache-control": "no-store", etag },
      }),
    });
    assert.equal(response.status, 503);
  }

  const missingNoStore = await proxyAppRequest(new Request("http://localhost:3000/v1/app/appeal-review/history", {
    headers: { "x-workspace-id": platformWorkspace },
  }), {
    baseUrl: "http://api:8000",
    fetchImpl: async () => Response.json({ data: reviewHistory }, {
      headers: { etag: reviewHistory.entity_tag },
    }),
  });
  assert.equal(missingNoStore.status, 503);

  const notFound = await proxyAppRequest(new Request(`http://localhost:3000/v1/app/appeal-review/history/${appealId}`, {
    headers: { "x-workspace-id": platformWorkspace },
  }), {
    baseUrl: "http://api:8000",
    fetchImpl: async () => Response.json({ error: { code: "RESOURCE_NOT_FOUND" } }, {
      status: 404,
      headers: { "cache-control": "no-store" },
    }),
  });
  assert.equal(notFound.status, 404);
  assert.deepEqual(await notFound.json(), { error: { code: "RESOURCE_NOT_FOUND" } });

  const historyNotFound = await proxyAppRequest(new Request("http://localhost:3000/v1/app/appeal-review/history", {
    headers: { "x-workspace-id": platformWorkspace },
  }), {
    baseUrl: "http://api:8000",
    fetchImpl: async () => Response.json({ error: { code: "RESOURCE_NOT_FOUND" } }, {
      status: 404,
      headers: { "cache-control": "no-store" },
    }),
  });
  assert.equal(historyNotFound.status, 404);
  assert.deepEqual(await historyNotFound.json(), { error: { code: "RESOURCE_NOT_FOUND" } });
});
