import assert from "node:assert/strict";
import test from "node:test";

import {
  acceptSyntheticConsent,
  acceptAgreement,
  appealDecision,
  applyPaymentStatus,
  cancelDemand,
  completeSelection,
  createPrototype,
  decideReport,
  exportSubjectData,
  proposeAgreementChange,
  reconcilePayment,
  recordDelivery,
  acceptDelivery,
  recordOutcome,
  requestDeletion,
  requestPayment,
  respondToInvitation,
  runMatching,
  secureSyntheticFunding,
  secureSyntheticMilestoneFunding,
  startMilestone,
  submitDeletionRequest,
  submitExportRequest,
  submitReport,
} from "../lib/prototype.js";

function expectDomainError(fn, code) {
  assert.throws(fn, (error) => error?.code === code);
}

function consentedPrototype() {
  let state = createPrototype();
  for (const creatorId of Object.keys(state.creators)) {
    state = acceptSyntheticConsent(state, creatorId, "synthetic-purpose-policy-v1");
  }
  return state;
}

test("purpose-scoped synthetic Consent is explicit and unconsented profiles cannot be matched", () => {
  let state = createPrototype();
  assert.ok(Object.values(state.consents).every((item) => item.status === "PENDING"));
  state = acceptSyntheticConsent(state, "creator-chen", "synthetic-purpose-policy-v1");
  assert.equal(state.consents["creator-chen"].status, "ACTIVE");
  assert.equal(state.consents["creator-chen"].purpose, "SYNTHETIC_MATCHING_DEMO");

  state = runMatching(secureSyntheticFunding(state));
  assert.deepEqual(state.matchRun.invitations.map((item) => item.creatorId), ["creator-chen"]);
});

test("DEMO-AC-01: UNKNOWN funding blocks matching until synthetic evidence is verified", () => {
  const initial = consentedPrototype();

  assert.equal(initial.meta.syntheticOnly, true);
  assert.equal(initial.meta.gate, "G0A");
  assert.equal(initial.funding.status, "UNKNOWN");
  expectDomainError(() => runMatching(initial), "FUNDING_NOT_SECURED");

  const secured = secureSyntheticFunding(initial);
  const matched = runMatching(secured);
  assert.equal(secured.funding.status, "SECURED");
  assert.equal(matched.matchRun.invitations.length, 3);
  assert.ok(matched.matchRun.invitations.every((item) => item.runId === matched.matchRun.id));
});

test("Demand records all nine authorities and an explicit resource N/A", () => {
  const state = createPrototype();
  assert.equal(state.demand.authorities.length, 9);
  assert.deepEqual(
    state.demand.authorities.map((item) => item.role),
    [
      "PROBLEM_PROPOSER",
      "BENEFICIARY",
      "BENEFICIARY_REPRESENTATIVE",
      "FUNDER_PURCHASER",
      "RESOURCE_PROVIDER",
      "DEMAND_DECISION_MAKER",
      "CANDIDATE_SELECTOR",
      "ACCEPTANCE_REVIEWER",
      "PROJECT_COORDINATOR",
    ],
  );
  const resource = state.demand.authorities.find((item) => item.role === "RESOURCE_PROVIDER");
  assert.equal(resource.subjectId, null);
  assert.equal(resource.status, "NOT_APPLICABLE");
  assert.match(resource.rationale, /第三方资源/);
});

test("DEMO-AC-02/03: decline carries no penalty and selection requires an accepted candidate from the same run", () => {
  const matched = runMatching(secureSyntheticFunding(consentedPrototype()));
  const [first, second] = matched.matchRun.invitations;
  const declined = respondToInvitation(matched, first.creatorId, "DECLINED");

  assert.equal(declined.creators[first.creatorId].eligibility, "ELIGIBLE");
  assert.equal(declined.creators[first.creatorId].opportunityPenalty, 0);
  expectDomainError(
    () => completeSelection(declined, { creatorId: first.creatorId, runId: declined.matchRun.id }),
    "CANDIDATE_NOT_ACCEPTED",
  );
  expectDomainError(
    () => completeSelection(declined, { creatorId: second.creatorId, runId: "run-other" }),
    "RUN_MISMATCH",
  );

  const accepted = respondToInvitation(declined, second.creatorId, "ACCEPTED");
  const selected = completeSelection(accepted, {
    creatorId: second.creatorId,
    runId: accepted.matchRun.id,
  });
  assert.equal(selected.selection.creatorId, second.creatorId);
  assert.equal(selected.selection.status, "COMPLETED");
});

test("matching snapshot is minimal and cannot expose private boundaries or compensation floors", () => {
  const matched = runMatching(secureSyntheticFunding(consentedPrototype()));
  for (const candidate of matched.matchRun.invitations) {
    assert.deepEqual(Object.keys(candidate.snapshot).sort(), [
      "capabilityTags",
      "creatorRef",
      "disclosedAvailability",
      "evidenceRefs",
    ]);
    assert.equal(JSON.stringify(candidate).includes("private"), false);
    assert.equal(JSON.stringify(candidate).includes("compensationFloor"), false);
  }
});

function selectedPrototype() {
  let state = runMatching(secureSyntheticFunding(consentedPrototype()));
  const creatorId = state.matchRun.invitations[0].creatorId;
  state = respondToInvitation(state, creatorId, "ACCEPTED");
  return completeSelection(state, { creatorId, runId: state.matchRun.id });
}

test("DEMO-AC-04/05: identical agreement versions are required and material change resets acceptance", () => {
  let state = selectedPrototype();
  const creatorId = state.selection.creatorId;
  state = acceptAgreement(state, "synthetic-demand-signatory", 1);
  expectDomainError(() => acceptAgreement(state, creatorId, 2), "AGREEMENT_VERSION_MISMATCH");
  expectDomainError(() => startMilestone(state), "AGREEMENT_NOT_ACTIVE");

  state = acceptAgreement(state, creatorId, 1);
  assert.equal(state.agreement.status, "ACTIVE");
  expectDomainError(() => startMilestone(state), "MILESTONE_FUNDING_NOT_SECURED");
  state = secureSyntheticMilestoneFunding(state);
  state = startMilestone(state);
  assert.equal(state.milestone.status, "IN_PROGRESS");

  state = proposeAgreementChange(state, {
    actorId: "synthetic-demand-signatory",
    summary: "将交付日期顺延两天，不改变报酬",
  });
  assert.equal(state.agreement.version, 2);
  assert.equal(state.agreement.status, "PENDING_ACCEPTANCE");
  assert.deepEqual(state.agreement.acceptedBy, []);
  assert.equal(state.milestone.status, "BLOCKED_BY_CHANGE");
  expectDomainError(() => startMilestone(state), "AGREEMENT_NOT_ACTIVE");
});

test("DEMO-AC-06: UNKNOWN payment cannot be retried or inferred and only reconciliation closes it", () => {
  let state = selectedPrototype();
  const creatorId = state.selection.creatorId;
  state = acceptAgreement(state, "synthetic-demand-signatory", 1);
  state = acceptAgreement(state, creatorId, 1);
  state = secureSyntheticMilestoneFunding(state);
  state = { ...startMilestone(state), milestone: { ...startMilestone(state).milestone, status: "ACCEPTED" } };
  state = requestPayment(state);
  state = applyPaymentStatus(state, "UNKNOWN");

  assert.equal(state.payment.status, "UNKNOWN");
  assert.equal(state.payment.retryAllowed, false);
  expectDomainError(() => requestPayment(state), "PAYMENT_ALREADY_REQUESTED");
  expectDomainError(() => applyPaymentStatus(state, "PAID"), "RECONCILIATION_REQUIRED");

  state = reconcilePayment(state, "PAID");
  assert.equal(state.payment.status, "PAID");
  assert.equal(state.payment.authoritativeSource, "SYNTHETIC_RECONCILIATION_LEDGER");
});

test("DEMO-AC-07: appeal reviewer must be independent from the initial decision maker", () => {
  let state = submitReport(createPrototype(), {
    reporterId: "creator-chen",
    summary: "合成场景：收到超出协议范围的施压信息",
  });
  assert.equal(state.safety.decision, null);
  state = decideReport(state, {
    reviewerId: "synthetic-safety-reviewer",
    outcome: "LIMITED_HOLD",
  });
  expectDomainError(
    () => appealDecision(state, { reviewerId: "synthetic-safety-reviewer", outcome: "UPHELD" }),
    "REVIEWER_NOT_INDEPENDENT",
  );
  state = appealDecision(state, {
    reviewerId: "synthetic-appeal-reviewer",
    outcome: "MODIFIED",
  });
  assert.equal(state.safety.appeal.reviewerId, "synthetic-appeal-reviewer");
});

test("DEMO-AC-08: export excludes third-party data and deletion returns itemized exceptions", () => {
  const state = createPrototype();
  const exported = exportSubjectData(state, "creator-chen");
  assert.equal(exported.subjectId, "creator-chen");
  assert.equal(JSON.stringify(exported).includes("beneficiary-private"), false);
  assert.equal(JSON.stringify(exported).includes("other-candidate"), false);

  const deletion = requestDeletion(state, "creator-chen");
  assert.equal(deletion.status, "ITEMIZED");
  assert.ok(deletion.items.some((item) => item.result === "DELETE"));
  assert.ok(deletion.items.some((item) => item.result === "RETAIN_MINIMUM"));
  assert.ok(deletion.items.every((item) => item.reason));
});

test("data-rights requests are recorded separately from their synthetic preview results", () => {
  let state = submitExportRequest(createPrototype(), "creator-chen");
  state = submitDeletionRequest(state, "creator-chen");
  assert.deepEqual(state.rights.requests.map((item) => item.type), ["EXPORT", "DELETE"]);
  assert.ok(state.rights.requests.every((item) => item.status === "SYNTHETIC_PREVIEW_READY"));
  assert.equal(state.audit.at(-2).action, "DATA_EXPORT_PREVIEW_REQUESTED");
  assert.equal(state.audit.at(-1).action, "DATA_DELETION_PREVIEW_REQUESTED");
});

test("DEMO-AC-09: a cancelled Demand cannot be matched again", () => {
  const cancelled = cancelDemand(secureSyntheticFunding(createPrototype()), "需求方撤回合成演练");
  assert.equal(cancelled.demand.status, "CANCELLED");
  expectDomainError(() => runMatching(cancelled), "DEMAND_NOT_MATCHABLE");
});

test("every action is immutable and appends attributable evidence", () => {
  const initial = createPrototype();
  const next = secureSyntheticFunding(initial);
  assert.notEqual(next, initial);
  assert.equal(initial.funding.status, "UNKNOWN");
  assert.equal(initial.audit.length + 1, next.audit.length);
  const event = next.audit.at(-1);
  assert.ok(event.actorId);
  assert.ok(event.authority);
  assert.ok(event.reason);
  assert.ok(event.correlationId);
});

test("the full synthetic journey reaches a contextual outcome without a global score", () => {
  let state = selectedPrototype();
  const creatorId = state.selection.creatorId;
  state = acceptAgreement(state, "synthetic-demand-signatory", 1);
  state = acceptAgreement(state, creatorId, 1);
  state = secureSyntheticMilestoneFunding(state);
  state = startMilestone(state);
  state = recordDelivery(state);
  state = acceptDelivery(state);
  state = requestPayment(state);
  state = applyPaymentStatus(state, "PROCESSING");
  state = applyPaymentStatus(state, "UNKNOWN");
  state = reconcilePayment(state, "PAID");
  state = recordOutcome(state);

  assert.equal(state.project.status, "COMPLETED");
  assert.equal(state.outcome.financialFact.paymentStatus, "PAID");
  assert.equal(state.outcome.globalScore, null);
  assert.ok(state.delivery.contractAcceptance);
  assert.ok(state.delivery.beneficiaryConfirmation);
});

test("prototype domain never calls a real identity, payment, notification, file, or AI provider", () => {
  const originalFetch = globalThis.fetch;
  let calls = 0;
  globalThis.fetch = async () => {
    calls += 1;
    throw new Error("external network is forbidden in the synthetic prototype");
  };
  try {
    let state = buildPaymentStateForNetworkGuard();
    state = reconcilePayment(state, "PAID");
    state = recordOutcome(state);
    state = submitReport(state, { reporterId: "creator-chen", summary: "合成安全摘要" });
    state = decideReport(state, { reviewerId: "synthetic-safety-reviewer", outcome: "LIMITED_HOLD" });
    state = appealDecision(state, { reviewerId: "synthetic-appeal-reviewer", outcome: "MODIFIED" });
    state = submitExportRequest(state, "creator-chen");
    state = submitDeletionRequest(state, "creator-chen");
    assert.equal(state.meta.syntheticOnly, true);
    assert.equal(calls, 0);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

function buildPaymentStateForNetworkGuard() {
  let state = selectedPrototype();
  state = acceptAgreement(state, "synthetic-demand-signatory", 1);
  state = acceptAgreement(state, state.selection.creatorId, 1);
  state = secureSyntheticMilestoneFunding(state);
  state = startMilestone(state);
  state = recordDelivery(state);
  state = acceptDelivery(state);
  state = requestPayment(state);
  state = applyPaymentStatus(state, "PROCESSING");
  return applyPaymentStatus(state, "UNKNOWN");
}
