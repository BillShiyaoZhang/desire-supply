import assert from "node:assert/strict";
import test from "node:test";

import {
  createTrustAssignmentReleaseIntent,
  createTrustCaseClaimIntent,
  createTrustHoldIntent,
  createTrustHoldReleaseClaimIntent,
  createTrustHoldReleaseIntent,
  createTrustOutcomeIntent,
  createTrustReportIntent,
  createTrustTriageDraftIntent,
  createTrustTriagePublishIntent,
  parsePendingIntent,
  parseTrustCaseEnvelope,
  parseTrustCommandEnvelope,
  parseTrustHoldReleaseQueueEnvelope,
  parseTrustOwnReportListEnvelope,
  parseTrustQueueEnvelope,
  parseTrustReportEnvelope,
  serializePendingIntent,
} from "../lib/app-contract.mjs";
import { createAppProxyRequest, proxyAppRequest } from "../lib/server-proxy.mjs";

const workspace = "platform:10000000-0000-4000-8000-000000000001";
const csrfToken = "csrf_token_internal_000000000000001";
const idempotencyKey = "trust-command-idempotency-0001";
const demandId = "10000000-0000-4000-8000-000000000001";
const demandVersionId = "20000000-0000-4000-8000-000000000001";
const evidenceId = "30000000-0000-4000-8000-000000000001";
const reportId = "40000000-0000-4000-8000-000000000001";
const secondReportId = "40000000-0000-4000-8000-000000000002";
const caseId = "50000000-0000-4000-8000-000000000001";
const holdId = "60000000-0000-4000-8000-000000000001";
const reportEtag = `"trust-1-${"a".repeat(24)}"`;
const caseEtag = `"trust-3-${"b".repeat(24)}"`;
const holdEtag = `"trust-1-${"c".repeat(24)}"`;
const reportCursor = `${"c".repeat(64)}.${"s".repeat(43)}`;
const reportSummary = {
  category: "RETALIATION",
  evidence_reference_ids: [evidenceId],
  impact_codes: ["RETALIATION_RISK"],
  incident_ended_at: null,
  incident_started_at: "2026-08-18T08:00:00Z",
  requested_protection_codes: ["PAUSE_MATCHING"],
};

const report = {
  demand_id: demandId,
  demand_version_id: demandVersionId,
  entity_tag: reportEtag,
  outcome: null,
  report: reportSummary,
  report_id: reportId,
  status: "OPEN",
  submitted_at: "2026-08-18T08:05:00Z",
};

const ownReportItem = {
  category: "RETALIATION",
  demand_id: demandId,
  outcome: null,
  report_id: reportId,
  status: "OPEN",
  submitted_at: "2026-08-18T08:05:00Z",
};

const decidedOwnReportItem = {
  category: "WORKFLOW_INTEGRITY",
  demand_id: demandId,
  outcome: {
    appeal_deadline: "2026-08-26T09:05:00Z",
    appeal_eligibility_code: "ELIGIBLE",
    decided_at: "2026-08-19T09:05:00Z",
    outcome_code: "REMEDIATION_REQUIRED",
    outcome_version_id: "70000000-0000-4000-8000-000000000001",
  },
  report_id: secondReportId,
  status: "DECIDED",
  submitted_at: "2026-08-19T08:05:00.000000001Z",
};

const queueItem = {
  category: "RETALIATION",
  case_id: caseId,
  demand_id: demandId,
  demand_version_id: demandVersionId,
  entity_tag: reportEtag,
  impact_codes: ["RETALIATION_RISK"],
  report_id: reportId,
  submitted_at: "2026-08-18T08:05:00Z",
};

const hold = {
  action_codes: ["REQUEST_MATCHING"],
  effective_at: "2026-08-18T08:20:00Z",
  entity_tag: holdEtag,
  expires_at: "2026-08-19T08:20:00Z",
  hold_id: holdId,
  status: "ACTIVE",
};

const holdQueueItem = {
  action_codes: ["REQUEST_MATCHING"],
  case_id: caseId,
  demand_id: demandId,
  demand_version_id: demandVersionId,
  entity_tag: holdEtag,
  expires_at: "2026-08-19T08:20:00Z",
  hold_id: holdId,
  reason_code: "RETALIATION_RISK",
};

const trustCase = {
  active_hold: hold,
  aggregate_version: 3,
  case_id: caseId,
  demand_id: demandId,
  demand_version_id: demandVersionId,
  entity_tag: caseEtag,
  outcome: null,
  report: reportSummary,
  report_id: reportId,
  status: "TRIAGING",
  triage_draft: {
    content: {
      investigation_step_codes: ["CHECK_DEMAND_VERSION"],
      issue_codes: ["RETALIATION_INDICATOR"],
      jurisdiction_code: "PLATFORM_INTERNAL",
      priority_code: "P1",
      proposed_hold_actions: ["REQUEST_MATCHING"],
      proposed_hold_ttl_minutes: 1440,
      sealed_note_reference: "sealed://trust/cases/triage-note-01",
      sealed_note_sha256: "d".repeat(64),
      severity_code: "HIGH",
    },
    content_sha256: "e".repeat(64),
    saved_at: "2026-08-18T08:15:00Z",
    triage_version: 1,
  },
};

const triageInput = {
  investigation_step_codes: ["CHECK_DEMAND_VERSION"],
  issue_codes: ["RETALIATION_INDICATOR"],
  jurisdiction_code: "PLATFORM_INTERNAL",
  priority_code: "P1",
  proposed_hold_actions: ["REQUEST_MATCHING"],
  proposed_hold_ttl_minutes: 1440,
  restricted_note: "仅供 Trust Officer 的受限合成调查备注。",
  severity_code: "HIGH",
};

const commandResult = {
  aggregate_version: 1,
  case_id: caseId,
  case_status: "OPEN",
  completed_at: "2026-08-18T08:05:00Z",
  event_types: ["TrustReportSubmitted"],
  hold_id: null,
  hold_version: null,
  outcome_version_id: null,
  replayed: false,
  report_id: reportId,
  triage_draft_version: null,
  triage_version: null,
};

test("Trust response parsers accept only safe closed projections", () => {
  assert.deepEqual(parseTrustReportEnvelope({ data: report }), report);
  assert.deepEqual(parseTrustQueueEnvelope({ data: { entity_tag: reportEtag, items: [queueItem] } }).items, [queueItem]);
  assert.deepEqual(parseTrustHoldReleaseQueueEnvelope({ data: { entity_tag: holdEtag, items: [holdQueueItem] } }).items, [holdQueueItem]);
  assert.deepEqual(parseTrustCaseEnvelope({ data: trustCase }), trustCase);
  assert.deepEqual(parseTrustCommandEnvelope({ data: commandResult }), commandResult);

  for (const value of [
    { data: { ...report, reporter_user_id: "forged" } },
    { data: { entity_tag: reportEtag, items: [{ ...queueItem, actor_id: "forged" }] } },
    { data: { ...trustCase, duty_grant_id: "forged" } },
    { data: { ...trustCase, triage_draft: { ...trustCase.triage_draft, content: { ...trustCase.triage_draft.content, restricted_note: "leak" } } } },
    { data: { ...trustCase, entity_tag: '"trust-3-not-a-digest"' } },
  ]) assert.throws(
    () => value.data?.report_id === reportId && !Object.hasOwn(value.data, "case_id")
      ? parseTrustReportEnvelope(value)
      : parseTrustCaseEnvelope(value),
    /INVALID_APP_CONTRACT/,
  );
  assert.throws(
    () => parseTrustCommandEnvelope({ data: { ...commandResult, entity_tag: reportEtag } }),
    /INVALID_APP_CONTRACT/,
  );
});

test("owned Trust report discovery accepts only ordered minimal summaries and opaque cursor shapes", () => {
  const projection = {
    entity_tag: reportEtag,
    items: [decidedOwnReportItem, ownReportItem],
    next_cursor: reportCursor,
  };
  assert.deepEqual(parseTrustOwnReportListEnvelope({ data: projection }), projection);

  for (const value of [
    { ...projection, items: [{ ...decidedOwnReportItem, narrative: "leak" }, ownReportItem] },
    { ...projection, items: [{ ...decidedOwnReportItem, evidence_reference_ids: [evidenceId] }, ownReportItem] },
    { ...projection, items: [ownReportItem, decidedOwnReportItem] },
    { ...projection, items: [ownReportItem, ownReportItem] },
    { ...projection, items: [{ ...decidedOwnReportItem, outcome: null }] },
    { ...projection, next_cursor: `${"c".repeat(64)}.tampered` },
  ]) assert.throws(
    () => parseTrustOwnReportListEnvelope({ data: value }),
    /INVALID_APP_CONTRACT/,
  );
});

test("Trust intents bind server projections and never accept client authority or decision evidence", () => {
  const reportIntent = createTrustReportIntent({
    csrfToken,
    idempotencyKey,
    demandId,
    demandVersionId,
    category: "RETALIATION",
    evidenceReferenceIds: [evidenceId],
    impactCodes: ["RETALIATION_RISK"],
    incidentStartedAt: "2026-08-18T08:00:00Z",
    incidentEndedAt: null,
    requestedProtectionCodes: ["PAUSE_MATCHING"],
  });
  assert.equal(reportIntent.path, "/v1/app/trust/reports");
  assert.equal(reportIntent.headers["if-match"], undefined);
  assert.doesNotMatch(JSON.stringify(reportIntent), /actor|reporter|role|duty|organization/);

  const claim = createTrustCaseClaimIntent({ queueItem, csrfToken, idempotencyKey });
  assert.equal(claim.headers["if-match"], reportEtag);
  assert.deepEqual(claim.body, {});
  assert.equal(createTrustAssignmentReleaseIntent({ trustCase, reasonCode: "WORKLOAD_RELEASE", csrfToken, idempotencyKey }).body.reason_code, "WORKLOAD_RELEASE");
  assert.deepEqual(createTrustTriageDraftIntent({ trustCase, triage: triageInput, csrfToken, idempotencyKey }).body, triageInput);
  assert.deepEqual(createTrustTriagePublishIntent({ trustCase, csrfToken, idempotencyKey }).body, { expected_draft_version: 1 });
  assert.equal(createTrustHoldIntent({ trustCase, actionCodes: ["REQUEST_MATCHING"], reasonCode: "RETALIATION_RISK", ttlMinutes: 1440, csrfToken, idempotencyKey }).headers["if-match"], caseEtag);
  assert.equal(createTrustHoldReleaseClaimIntent({ queueItem: holdQueueItem, csrfToken, idempotencyKey }).headers["if-match"], holdEtag);
  assert.equal(createTrustHoldReleaseIntent({ trustCase, reasonCode: "RISK_MITIGATED", csrfToken, idempotencyKey }).headers["if-match"], holdEtag);
  const outcome = createTrustOutcomeIntent({
    trustCase,
    actionCodes: ["REQUEST_MATCHING"],
    outcomeCode: "PROTECTION_MAINTAINED",
    reasonCodes: ["PRECAUTIONARY_ACTION_REQUIRED"],
    csrfToken,
    idempotencyKey,
  });
  assert.deepEqual(Object.keys(outcome.body).sort(), ["action_codes", "outcome_code", "reason_codes"]);
  assert.doesNotMatch(JSON.stringify(outcome), /evidence|eligibility|policy_version|assignment|actor|duty/);

  const pending = {
    version: 1,
    saved_at: "2026-08-18T08:30:00Z",
    resource_type: "TRUST_CASE",
    object_id: caseId,
    label: "发布 Trust 初始结论",
    intent: outcome,
  };
  assert.deepEqual(parsePendingIntent(serializePendingIntent(pending), Date.parse(pending.saved_at)), pending);
});

test("Trust BFF admits all canonical routes with exact headers and bodies", async () => {
  const readPaths = [
    `/v1/app/trust/reports?limit=20&cursor=${reportCursor}`,
    `/v1/app/trust/reports/${reportId}`,
    "/v1/app/trust/queue",
    "/v1/app/trust/history",
    "/v1/app/trust/hold-release-queue",
    `/v1/app/trust/cases/${caseId}`,
  ];
  for (const path of readPaths) {
    const request = await createAppProxyRequest(new Request(`http://localhost:3000${path}`, {
      headers: { "x-workspace-id": workspace },
    }), "http://api:8000");
    assert.equal(request.url, `http://api:8000${path}`);
  }

  const commonHeaders = {
    "content-type": "application/json",
    "idempotency-key": idempotencyKey,
    "x-csrf-token": csrfToken,
    "x-workspace-id": workspace,
  };
  const writes = [
    ["POST", "/v1/app/trust/reports", reportIntentBody(), false],
    ["POST", `/v1/app/trust/queue/${caseId}/claim`, {}, true],
    ["POST", `/v1/app/trust/hold-release-queue/${holdId}/claim`, {}, true],
    ["POST", `/v1/app/trust/cases/${caseId}/assignment/release`, { reason_code: "WORKLOAD_RELEASE" }, true],
    ["PUT", `/v1/app/trust/cases/${caseId}/triage-draft`, triageInput, true],
    ["POST", `/v1/app/trust/cases/${caseId}/triage-publish`, { expected_draft_version: 1 }, true],
    ["POST", `/v1/app/trust/cases/${caseId}/holds`, { action_codes: ["REQUEST_MATCHING"], reason_code: "RETALIATION_RISK", ttl_minutes: 1440 }, true],
    ["POST", `/v1/app/trust/holds/${holdId}/release`, { reason_code: "RISK_MITIGATED" }, true],
    ["POST", `/v1/app/trust/cases/${caseId}/decisions`, { action_codes: ["REQUEST_MATCHING"], outcome_code: "PROTECTION_MAINTAINED", reason_codes: ["PRECAUTIONARY_ACTION_REQUIRED"] }, true],
  ];
  for (const [method, path, body, needsEtag] of writes) {
    const headers = needsEtag ? { ...commonHeaders, "if-match": caseEtag } : commonHeaders;
    const request = await createAppProxyRequest(new Request(`http://localhost:3000${path}`, {
      method,
      headers,
      body: JSON.stringify(body),
    }), "http://api:8000");
    assert.equal(request.url, `http://api:8000${path}`);
    assert.deepEqual(await request.json(), body);
  }
});

test("Trust BFF rejects forged authority, unknown fields, stale tag shapes, and unsafe notes", async () => {
  const headers = {
    "content-type": "application/json",
    "if-match": caseEtag,
    "idempotency-key": idempotencyKey,
    "x-csrf-token": csrfToken,
    "x-workspace-id": workspace,
  };
  const rejected = [
    new Request(`http://localhost:3000/v1/app/trust/queue/${caseId}/claim`, { method: "POST", headers: { ...headers, "x-role": "TRUST_OFFICER" }, body: "{}" }),
    new Request(`http://localhost:3000/v1/app/trust/queue/${caseId}/claim`, { method: "POST", headers, body: JSON.stringify({ actor_id: "forged" }) }),
    new Request(`http://localhost:3000/v1/app/trust/cases/${caseId}/decisions`, { method: "POST", headers, body: JSON.stringify({ action_codes: [], outcome_code: "NO_ACTION", reason_codes: ["NO_POLICY_BREACH"], evidence_packet_digest: "f".repeat(64) }) }),
    new Request(`http://localhost:3000/v1/app/trust/cases/${caseId}/triage-draft`, { method: "PUT", headers, body: JSON.stringify({ ...triageInput, restricted_note: "   " }) }),
    new Request(`http://localhost:3000/v1/app/trust/cases/${caseId}/triage-draft`, { method: "PUT", headers, body: JSON.stringify({ ...triageInput, restricted_note: "x".repeat(4001) }) }),
    new Request(`http://localhost:3000/v1/app/trust/holds/${holdId}/release`, { method: "POST", headers: { ...headers, "if-match": '"trust-0-bad"' }, body: JSON.stringify({ reason_code: "RISK_MITIGATED" }) }),
    new Request(`http://localhost:3000/v1/app/trust/queue?actor=forged`, { headers: { "x-workspace-id": workspace } }),
    new Request(`http://localhost:3000/v1/app/trust/history?limit=1`, { headers: { "x-workspace-id": workspace } }),
    new Request(`http://localhost:3000/v1/app/trust/reports?unknown=value`, { headers: { "x-workspace-id": workspace } }),
    new Request(`http://localhost:3000/v1/app/trust/reports?limit=0`, { headers: { "x-workspace-id": workspace } }),
    new Request(`http://localhost:3000/v1/app/trust/reports?limit=20&limit=30`, { headers: { "x-workspace-id": workspace } }),
    new Request(`http://localhost:3000/v1/app/trust/reports?cursor=tampered`, { headers: { "x-workspace-id": workspace } }),
  ];
  for (const source of rejected) await assert.rejects(
    () => createAppProxyRequest(source, "http://api:8000"),
    /APP_ROUTE_NOT_ALLOWED|AUTHORITY_HEADER_FORBIDDEN|INVALID_TRUST_REPORT_LIST_QUERY|INVALID_TRUST_REQUEST/,
  );

  const response = await proxyAppRequest(new Request(
    `http://localhost:3000/v1/app/trust/queue/${caseId}/claim`,
    { method: "POST", headers, body: JSON.stringify({ actor_id: "forged" }) },
  ), { baseUrl: "http://api:8000" });
  assert.equal(response.status, 400);
  assert.equal((await response.json()).code, "INVALID_TRUST_REQUEST");
});

test("Trust BFF validates safe success and error responses before exposing them to the browser", async () => {
  const commandSource = new Request(`http://localhost:3000/v1/app/trust/queue/${caseId}/claim`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "if-match": reportEtag,
      "idempotency-key": idempotencyKey,
      "x-csrf-token": csrfToken,
      "x-workspace-id": workspace,
    },
    body: "{}",
  });
  const claimResult = { ...commandResult, event_types: ["TrustCaseClaimed"], report_id: null };
  const safeCommand = await proxyAppRequest(commandSource, {
    baseUrl: "http://api:8000",
    fetchImpl: async () => Response.json({ data: claimResult }, { status: 201 }),
  });
  assert.equal(safeCommand.status, 201);
  assert.deepEqual(await safeCommand.json(), { data: claimResult });
  assert.equal(safeCommand.headers.get("cache-control"), "no-store");
  assert.equal(safeCommand.headers.get("etag"), null);

  const richWrite = await proxyAppRequest(new Request(`http://localhost:3000/v1/app/trust/queue/${caseId}/claim`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "if-match": reportEtag,
      "idempotency-key": idempotencyKey,
      "x-csrf-token": csrfToken,
      "x-workspace-id": workspace,
    },
    body: "{}",
  }), {
    baseUrl: "http://api:8000",
    fetchImpl: async () => Response.json({ data: trustCase }, { status: 201, headers: { etag: caseEtag } }),
  });
  assert.equal(richWrite.status, 503);
  assert.equal((await richWrite.json()).code, "INTERNAL_PILOT_BACKEND_UNAVAILABLE");

  const safeRead = await proxyAppRequest(new Request(
    `http://localhost:3000/v1/app/trust/reports/${reportId}`,
    { headers: { "x-workspace-id": workspace } },
  ), {
    baseUrl: "http://api:8000",
    fetchImpl: async () => Response.json({ data: report }, { headers: { etag: reportEtag } }),
  });
  assert.equal(safeRead.status, 200);
  assert.equal(safeRead.headers.get("etag"), reportEtag);

  const safeList = await proxyAppRequest(new Request(
    `http://localhost:3000/v1/app/trust/reports?limit=20&cursor=${reportCursor}`,
    { headers: { "x-workspace-id": workspace } },
  ), {
    baseUrl: "http://api:8000",
    fetchImpl: async () => Response.json({
      data: {
        entity_tag: reportEtag,
        items: [decidedOwnReportItem, ownReportItem],
        next_cursor: reportCursor,
      },
    }, { headers: { "cache-control": "no-store", etag: reportEtag } }),
  });
  assert.equal(safeList.status, 200);
  assert.equal(safeList.headers.get("etag"), reportEtag);
  assert.equal((await safeList.json()).data.items.length, 2);

  const leakingList = await proxyAppRequest(new Request(
    "http://localhost:3000/v1/app/trust/reports?limit=20",
    { headers: { "x-workspace-id": workspace } },
  ), {
    baseUrl: "http://api:8000",
    fetchImpl: async () => Response.json({
      data: {
        entity_tag: reportEtag,
        items: [{ ...ownReportItem, narrative: "leak" }],
        next_cursor: null,
      },
    }, { headers: { etag: reportEtag } }),
  });
  assert.equal(leakingList.status, 503);
  assert.doesNotMatch(JSON.stringify(await leakingList.json()), /narrative|leak/);

  const leakingError = await proxyAppRequest(new Request(
    `http://localhost:3000/v1/app/trust/reports/${reportId}`,
    { headers: { "x-workspace-id": workspace } },
  ), {
    baseUrl: "http://api:8000",
    fetchImpl: async () => Response.json({ error: { code: "RESOURCE_NOT_FOUND", restricted_note: "leak" } }, { status: 404 }),
  });
  assert.equal(leakingError.status, 503);
  assert.doesNotMatch(JSON.stringify(await leakingError.json()), /restricted_note|leak/);
});

test("every admitted Trust route class rejects an error response carrying an ETag", async () => {
  const readHeaders = { "x-workspace-id": workspace };
  const writeHeaders = {
    "content-type": "application/json",
    "idempotency-key": idempotencyKey,
    "x-csrf-token": csrfToken,
    "x-workspace-id": workspace,
  };
  const etaggedWriteHeaders = { ...writeHeaders, "if-match": caseEtag };
  const sources = [
    new Request("http://localhost:3000/v1/app/trust/reports?limit=20", { headers: readHeaders }),
    new Request(`http://localhost:3000/v1/app/trust/reports/${reportId}`, { headers: readHeaders }),
    new Request("http://localhost:3000/v1/app/trust/queue", { headers: readHeaders }),
    new Request("http://localhost:3000/v1/app/trust/assignments", { headers: readHeaders }),
    new Request("http://localhost:3000/v1/app/trust/history", { headers: readHeaders }),
    new Request(`http://localhost:3000/v1/app/trust/assigned-holds/${holdId}`, { headers: readHeaders }),
    new Request("http://localhost:3000/v1/app/trust/hold-release-queue", { headers: readHeaders }),
    new Request(`http://localhost:3000/v1/app/trust/cases/${caseId}`, { headers: readHeaders }),
    new Request("http://localhost:3000/v1/app/trust/reports", {
      method: "POST", headers: writeHeaders, body: JSON.stringify(reportIntentBody()),
    }),
    new Request(`http://localhost:3000/v1/app/trust/queue/${caseId}/claim`, {
      method: "POST", headers: etaggedWriteHeaders, body: "{}",
    }),
    new Request(`http://localhost:3000/v1/app/trust/hold-release-queue/${holdId}/claim`, {
      method: "POST", headers: etaggedWriteHeaders, body: "{}",
    }),
    new Request(`http://localhost:3000/v1/app/trust/cases/${caseId}/assignment/release`, {
      method: "POST", headers: etaggedWriteHeaders, body: JSON.stringify({ reason_code: "WORKLOAD_RELEASE" }),
    }),
    new Request(`http://localhost:3000/v1/app/trust/cases/${caseId}/triage-draft`, {
      method: "PUT", headers: etaggedWriteHeaders, body: JSON.stringify(triageInput),
    }),
    new Request(`http://localhost:3000/v1/app/trust/cases/${caseId}/triage-publish`, {
      method: "POST", headers: etaggedWriteHeaders, body: JSON.stringify({ expected_draft_version: 1 }),
    }),
    new Request(`http://localhost:3000/v1/app/trust/cases/${caseId}/holds`, {
      method: "POST", headers: etaggedWriteHeaders,
      body: JSON.stringify({ action_codes: ["REQUEST_MATCHING"], reason_code: "RETALIATION_RISK", ttl_minutes: 1440 }),
    }),
    new Request(`http://localhost:3000/v1/app/trust/holds/${holdId}/release`, {
      method: "POST", headers: etaggedWriteHeaders, body: JSON.stringify({ reason_code: "RISK_MITIGATED" }),
    }),
    new Request(`http://localhost:3000/v1/app/trust/cases/${caseId}/decisions`, {
      method: "POST", headers: etaggedWriteHeaders,
      body: JSON.stringify({ action_codes: ["REQUEST_MATCHING"], outcome_code: "PROTECTION_MAINTAINED", reason_codes: ["PRECAUTIONARY_ACTION_REQUIRED"] }),
    }),
  ];

  for (const source of sources) {
    const response = await proxyAppRequest(source, {
      baseUrl: "http://api:8000",
      fetchImpl: async () => Response.json(
        { error: { code: "RESOURCE_NOT_FOUND" } },
        { status: 404, headers: { "cache-control": "no-store", etag: caseEtag } },
      ),
    });
    assert.equal(response.status, 503, `${source.method} ${new URL(source.url).pathname}`);
    assert.equal(response.headers.get("etag"), null, `${source.method} ${new URL(source.url).pathname}`);
    assert.equal((await response.json()).code, "INTERNAL_PILOT_BACKEND_UNAVAILABLE");
  }
});

function reportIntentBody() {
  return {
    category: "RETALIATION",
    demand_id: demandId,
    demand_version_id: demandVersionId,
    evidence_reference_ids: [evidenceId],
    impact_codes: ["RETALIATION_RISK"],
    incident_ended_at: null,
    incident_started_at: "2026-08-18T08:00:00Z",
    requested_protection_codes: ["PAUSE_MATCHING"],
  };
}
