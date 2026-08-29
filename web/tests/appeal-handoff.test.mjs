import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  appealHandoffKey,
  createAppealHandoff,
  isAppealHandoffCurrent,
} from "../lib/appeal-handoff.mjs";

const root = new URL("../", import.meta.url);
const sessionId = "10000000-0000-4000-8000-000000000001";
const workspaceId = "org:20000000-0000-4000-8000-000000000002";
const now = Date.parse("2026-08-24T01:00:00.000Z");

function decidedReport(overrides = {}) {
  return {
    demand_id: "30000000-0000-4000-8000-000000000003",
    demand_version_id: "40000000-0000-4000-8000-000000000004",
    entity_tag: '"trust-7-aaaaaaaaaaaaaaaaaaaaaaaa"',
    report_id: "50000000-0000-4000-8000-000000000005",
    status: "DECIDED",
    outcome: {
      action_codes: ["REQUEST_MATCHING"],
      appeal_deadline: "2026-08-25T01:00:00.000Z",
      appeal_eligibility_code: "ELIGIBLE",
      content_sha256: "b".repeat(64),
      decided_at: "2026-08-24T00:00:00.000Z",
      evidence_packet_digest: "c".repeat(64),
      evidence_packet_version_id: "60000000-0000-4000-8000-000000000006",
      outcome_code: "PROTECTION_MAINTAINED",
      outcome_version_id: "70000000-0000-4000-8000-000000000007",
      policy_version: "trust-case-outcome-v1",
      reason_codes: ["PRECAUTIONARY_ACTION_REQUIRED"],
      redaction_profile_code: "PARTY_SAFE_V1",
      source_digest: "d".repeat(64),
    },
    ...overrides,
  };
}

test("fresh party-safe eligible outcome creates an exact immutable same-session handoff", () => {
  const handoff = createAppealHandoff({ report: decidedReport(), sessionId, workspaceId, now });
  assert.ok(handoff);
  assert.equal(handoff.source, "TRUST_REPORT_FRESH_READ");
  assert.equal(handoff.appeal_eligible, true);
  assert.equal(handoff.source_outcome_version_id, "70000000-0000-4000-8000-000000000007");
  assert.equal(handoff.created_at, "2026-08-24T01:00:00.000Z");
  assert.equal(Object.isFrozen(handoff), true);
  assert.equal(Object.isFrozen(handoff.action_codes), true);
  assert.equal(Object.hasOwn(handoff, "evidence_content"), false);
  assert.equal(isAppealHandoffCurrent(handoff, { sessionId, workspaceId, now }), true);
  assert.match(appealHandoffKey(handoff), /70000000-0000-4000-8000-000000000007/);
});

test("fresh reads accept canonical UTC RFC3339 emitted by Python and PostgreSQL", () => {
  for (const [decidedAt, deadline] of [
    ["2026-08-24T00:00:00Z", "2026-08-25T01:00:00Z"],
    ["2026-08-24T00:00:00+00:00", "2026-08-25T01:00:00+00:00"],
    ["2026-08-24T00:00:00.123456+00:00", "2026-08-25T01:00:00.654321+00:00"],
  ]) {
    const base = decidedReport();
    const report = {
      ...base,
      outcome: {
        ...base.outcome,
        appeal_deadline: deadline,
        decided_at: decidedAt,
      },
    };
    const handoff = createAppealHandoff({ report, sessionId, workspaceId, now });
    assert.ok(handoff);
    assert.equal(handoff.decided_at, decidedAt);
    assert.equal(handoff.appeal_deadline, deadline);
    assert.equal(isAppealHandoffCurrent(handoff, { sessionId, workspaceId, now }), true);
  }
});

test("handoff timestamps remain closed to canonical UTC instants", () => {
  const base = decidedReport();
  for (const deadline of [
    "2026-08-25T09:00:00+08:00",
    "2026-08-25T01:00:00",
    "2026-08-25 01:00:00+00:00",
    "2026-08-25t01:00:00z",
    "2026-08-32T01:00:00+00:00",
    "2026-08-25T01:00:00.1234567890+00:00",
  ]) assert.equal(createAppealHandoff({
    report: { ...base, outcome: { ...base.outcome, appeal_deadline: deadline } },
    sessionId,
    workspaceId,
    now,
  }), null);
});

test("handoff creation and every receiving boundary fail closed on status, eligibility, redaction, expiry, and binding", () => {
  const base = decidedReport();
  assert.equal(createAppealHandoff({ report: { ...base, status: "IN_REVIEW" }, sessionId, workspaceId, now }), null);
  assert.equal(createAppealHandoff({
    report: { ...base, outcome: { ...base.outcome, appeal_eligibility_code: "NOT_ELIGIBLE" } },
    sessionId,
    workspaceId,
    now,
  }), null);
  assert.equal(createAppealHandoff({
    report: { ...base, outcome: { ...base.outcome, redaction_profile_code: "OFFICER_RESTRICTED_V1" } },
    sessionId,
    workspaceId,
    now,
  }), null);
  assert.equal(createAppealHandoff({
    report: { ...base, outcome: { ...base.outcome, appeal_deadline: "2026-08-24T01:00:00.000Z" } },
    sessionId,
    workspaceId,
    now,
  }), null);
  assert.equal(createAppealHandoff({
    report: base,
    sessionId,
    workspaceId,
    now: Date.parse("2026-08-23T23:59:59.000Z"),
  }), null);

  const handoff = createAppealHandoff({ report: base, sessionId, workspaceId, now });
  assert.ok(handoff);
  assert.equal(isAppealHandoffCurrent(handoff, {
    sessionId: "80000000-0000-4000-8000-000000000008",
    workspaceId,
    now,
  }), false);
  assert.equal(isAppealHandoffCurrent(handoff, {
    sessionId,
    workspaceId: "org:90000000-0000-4000-8000-000000000009",
    now,
  }), false);
  assert.equal(isAppealHandoffCurrent(handoff, {
    sessionId,
    workspaceId,
    now: Date.parse(handoff.appeal_deadline),
  }), false);
  assert.equal(isAppealHandoffCurrent({ ...handoff, source_outcome_version_id: "forged" }, {
    sessionId,
    workspaceId,
    now,
  }), false);
});

test("UI handoff remains memory-only, latch-gated, GET-first, exact-source locked, and explicit-write only", async () => {
  const [product, trust, appeal, helper] = await Promise.all([
    readFile(new URL("app/product-client.tsx", root), "utf8"),
    readFile(new URL("app/trust-workbench.tsx", root), "utf8"),
    readFile(new URL("app/appeal-workbench.tsx", root), "utf8"),
    readFile(new URL("lib/appeal-handoff.mjs", root), "utf8"),
  ]);

  assert.match(trust, /createAppealHandoff\(\{[\s\S]*report,[\s\S]*sessionId,[\s\S]*workspaceId/);
  assert.match(trust, />开始申诉<\/button>/);
  assert.match(helper, /report\?\.status !== "DECIDED"/);
  assert.match(helper, /outcome\.appeal_eligibility_code !== "ELIGIBLE"/);
  assert.match(helper, /outcome\.redaction_profile_code !== "PARTY_SAFE_V1"/);
  assert.match(trust, /未读取、未展示，也不声称看过证据内容/);

  assert.match(product, /const \[appealHandoff, setAppealHandoff\] = useState<AppealHandoff \| null>\(null\)/);
  assert.match(product, /workspace\.workspace_kind !== "ORGANIZATION"[\s\S]*!workspace\.role_codes\.includes\("DEMAND_OWNER"\)/);
  assert.match(product, /pendingRef\.current !== null[\s\S]*logoutIntentRef\.current !== null[\s\S]*isAppealHandoffCurrent/);
  assert.match(product, /const loadWorkspace = useCallback\(async \(\) => \{\s*setAppealHandoff\(null\)/);
  assert.match(product, /const switchWorkspace[\s\S]*setAppealHandoff\(null\)[\s\S]*loadWorkspaceObjects\(workspace, false\)/);
  assert.match(product, /async function logoutCurrentSession\(\) \{\s*if \(!session\) return;\s*setAppealHandoff\(null\)/);
  assert.match(product, /const enterSignedOut[\s\S]*setAppealHandoff\(null\)/);
  assert.doesNotMatch(product, /(?:sessionStorage|localStorage)\.(?:setItem|getItem)\([^\n]*appealHandoff/i);

  const inspectionStart = appeal.indexOf("const inspectAppealHandoff");
  const recoveryStart = appeal.indexOf("useLayoutEffect(() =>", inspectionStart);
  const inspection = appeal.slice(inspectionStart, recoveryStart);
  assert.match(inspection, /loadOwnBySource\(candidate\.source_outcome_version_id\)/);
  assert.match(inspection, /problem\.status === 404 && problem\.code === "APPEAL_NOT_FOUND"/);
  assert.match(inspection, /setHandoffStatus\("READY_TO_OPEN"\)/);
  assert.doesNotMatch(inspection, /performWrite|createAppealOpenIntent|method:\s*"POST"/);
  assert.match(appeal, /!recoveryChecked \|\| busy \|\| refreshing \|\| writeLocked \|\| pending !== null/);
  assert.match(appeal, /handoffStatus !== "READY_TO_OPEN"[\s\S]*sourceOutcomeVersionId !== handoff\.source_outcome_version_id[\s\S]*APPEAL_HANDOFF_LOOKUP_REQUIRED/);
  assert.match(appeal, /adoptOwn\(stagedOwn\);\s*if \(isOpen && handoff\?\.source_outcome_version_id === stagedOwn\.source_outcome_version_id\) \{\s*setHandoffStatus\("EXISTING"\)/);
  assert.match(appeal, /<input readOnly value=\{sourceOutcomeVersionId\}/);
  assert.match(appeal, />明确打开申诉<\/button>/);
  assert.match(appeal, /手工诊断输入 · 不属于同会话交接/);
  assert.match(appeal, /刷新、重新 bootstrap 或重新登录后仍需 Trust8 discovery/);
});
