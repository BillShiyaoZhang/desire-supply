import assert from "node:assert/strict";
import test from "node:test";

import {
  CURRENT_ACCOUNT_TASK_NEXT_ACTIONS,
  CURRENT_ACCOUNT_TASK_RESOURCE_KINDS,
  parsePendingIntent,
  serializePendingIntent,
} from "../lib/app-contract.mjs";
import {
  createAcceptMatchingInvitationIntent,
  createClaimCandidateSelectorIntent,
  createClaimMatchingReviewIntent,
  createChooseMatchingSelectionIntent,
  createCloseMatchingSelectionIntent,
  createDeclineMatchingInvitationIntent,
  createInvalidateMatchingReviewAttemptIntent,
  createMatchingReviewInvitationExpiry,
  createMatchingReviewInvitationIntent,
  createPublishMatchingReviewInvitationIntent,
  createReleaseMatchingReviewIntent,
  createWithdrawMatchingInvitationIntent,
  parseMatchingAttemptList,
  parseMatchingCandidateSelectorAssignment,
  parseMatchingInvitationDetail,
  parseMatchingInvitationList,
  parseMatchingReviewAssignment,
  parseMatchingReviewerAttempt,
  parseMatchingReviewerInvitation,
  parseMatchingReviewWorkspace,
  parseMatchingSelection,
  serializeMatchingPendingIntent,
} from "../lib/matching-contract.mjs";
import {
  createIamProxyRequest,
  proxyIamRequest,
} from "../lib/server-proxy.mjs";

const ID = {
  attempt: "matching_attempt_0000001",
  assignment: "matching_review_assignment_01",
  candidateAssignment: "candidate_selector_assignment_01",
  creator: "10000000-0000-4000-8000-000000000003",
  demand: "demand_object_000000001",
  demandVersion: "demand_version_00000001",
  invitation: "business_invitation_0001",
  organization: "10000000-0000-4000-8000-000000000002",
  profile: "creator_profile_0000001",
  profileVersion: "profile_version_0000001",
  run: "matching_result_run_000001",
  selection: "matching_selection_00001",
};
const SHA = "a".repeat(64);
const SHA_B = "b".repeat(64);
const NOW = "2026-08-26T08:00:00Z";
const LATER = "2026-09-02T08:00:00Z";
const CSRF = "csrf_token_abcdefghijklmnopqrstuvwxyz_123456";
const KEY = "matching-command-key-00000001";

function summary(overrides = {}) {
  return {
    invitation_id: ID.invitation,
    status: "SENT",
    aggregate_version: 2,
    updated_at: NOW,
    expires_at: LATER,
    snapshot_sha256: SHA,
    response_status: null,
    ...overrides,
  };
}

function disclosure(overrides = {}) {
  return {
    schema_version: 1,
    canonicalization_version: "invitation-disclosure-json-v1",
    invitation_id: ID.invitation,
    attempt_id: ID.attempt,
    demand_id: ID.demand,
    demand_version_id: ID.demandVersion,
    profile_id: ID.profile,
    profile_version_id: ID.profileVersion,
    organization_preview: {
      organization_id: ID.organization,
      display_label: "Community Energy Lab",
    },
    opportunity: {
      title: "Energy analysis",
      problem_summary: "Reduce synthetic energy waste.",
      deliverable_summaries: ["Validated plan"],
      acceptance_summaries: ["Measurable baseline"],
    },
    offer: {
      currency: "CNY",
      minimum_amount_minor: 100000,
      maximum_amount_minor: 200000,
      schedule_code: "SCHEDULE_FLEXIBLE",
      duration_weeks: 6,
    },
    constraints: {
      region_codes: ["REGION_CN"],
      language_codes: ["LANGUAGE_ZH"],
      data_sensitivity_code: "INTERNAL",
      ai_use_code: "OPTIONAL",
    },
    expires_at: LATER,
    demand_content_sha256: SHA_B,
    profile_content_sha256: SHA_B,
    snapshot_sha256: SHA,
    ...overrides,
  };
}

function detail(overrides = {}) {
  return { ...summary(), disclosure: disclosure(), ...overrides };
}

function acceptedInvitation(overrides = {}) {
  return {
    invitation_id: ID.invitation,
    creator_display_handle: "Creator 01",
    profile_id: ID.profile,
    profile_version_id: ID.profileVersion,
    accepted_at: NOW,
    capability_summary: "Systems analysis and validation planning",
    ...overrides,
  };
}

function selection(overrides = {}) {
  return {
    selection_id: ID.selection,
    attempt_id: ID.attempt,
    candidate_selector_assignment_id: "candidate_selector_assignment_01",
    candidate_selector_assignment_version: 4,
    status: "OPEN",
    aggregate_version: 3,
    updated_at: NOW,
    current_invitation_set_sha256: SHA,
    chosen_invitation_id: null,
    accepted_invitations: [acceptedInvitation()],
    ...overrides,
  };
}

function selectorAssignment(overrides = {}) {
  return {
    candidate_selector_assignment_id: ID.candidateAssignment,
    candidate_selector_assignment_version: 1,
    selection_id: ID.selection,
    attempt_id: ID.attempt,
    demand_id: ID.demand,
    status: "ACTIVE",
    expires_at: LATER,
    selection_status: "OPEN",
    selection_version: 1,
    current_invitation_set_sha256: SHA,
    ...overrides,
  };
}

function reviewerAttempt(overrides = {}) {
  return {
    attempt_id: ID.attempt,
    demand_id: ID.demand,
    attempt_no: 1,
    status: "OPEN",
    aggregate_version: 2,
    updated_at: NOW,
    ...overrides,
  };
}

function reviewAssignment(overrides = {}) {
  return {
    assignment_id: ID.assignment,
    organization_id: ID.organization,
    attempt_id: ID.attempt,
    match_run_id: ID.run,
    purpose_code: "INVITATION_REVIEW",
    role_code: "MATCHING_REVIEWER",
    status: "ACTIVE",
    aggregate_version: 1,
    expires_at: LATER,
    ...overrides,
  };
}

function reviewerInvitation(overrides = {}) {
  return {
    invitation_id: ID.invitation,
    attempt_id: ID.attempt,
    match_run_id: ID.run,
    creator_user_id: ID.creator,
    status: "CREATED",
    aggregate_version: 1,
    updated_at: NOW,
    expires_at: LATER,
    snapshot_sha256: SHA,
    ...overrides,
  };
}

function reviewWorkspace(overrides = {}) {
  return {
    ...reviewAssignment(),
    attempt: {
      status: "OPEN",
      aggregate_version: 2,
      attempt_no: 1,
      updated_at: NOW,
      demand_id: ID.demand,
      demand_version_id: ID.demandVersion,
      demand_aggregate_version: 3,
      demand_content_sha256: SHA_B,
      input_baseline_sha256: SHA,
    },
    run: {
      status: "COMPLETED",
      aggregate_version: 4,
      ordered_result_sha256: SHA,
      candidate_count: 1,
      eligible_count: 1,
      excluded_count: 0,
      failure_code: null,
    },
    eligible_candidates: [{
      creator_user_id: ID.creator,
      creator_display_handle: "Creator 01",
      profile_id: ID.profile,
      profile_version_id: ID.profileVersion,
      profile_content_sha256: SHA,
      evidence_version_digest: SHA_B,
      total_score: "92.500000",
      rank: 1,
      component_scores: [{ code: "CAPABILITY", ordinal: 1, score: "92.500000" }],
      candidate_result_sha256: SHA,
    }],
    invitations: [{
      invitation_id: ID.invitation,
      creator_user_id: ID.creator,
      status: "CREATED",
      aggregate_version: 1,
      snapshot_sha256: SHA,
      expires_at: LATER,
      updated_at: NOW,
    }],
    actions: {
      can_create_invitation: true,
      can_publish_invitation: true,
      can_invalidate_attempt: true,
    },
    ...overrides,
  };
}

test("Matching parses closed recipient list/detail and binds immutable disclosure", () => {
  assert.deepEqual(parseMatchingInvitationList({ items: [detail()], next_cursor: null }), {
    items: [detail()], next_cursor: null,
  });
  assert.deepEqual(parseMatchingInvitationDetail(detail()), detail());

  for (const malformed of [
    summary(),
    detail({ rank: 1 }),
    detail({ disclosure: disclosure({ snapshot_sha256: SHA_B }) }),
    detail({ disclosure: disclosure({ invitation_id: "business_invitation_other1" }) }),
    detail({ disclosure: disclosure({ opportunity: { ...disclosure().opportunity, contact: "person@example.test" } }) }),
    detail({ disclosure: disclosure({ opportunity: { ...disclosure().opportunity, problem_summary: "https://secret.example" } }) }),
    detail({ disclosure: disclosure({ private_floor_amount_minor: 999 }) }),
  ]) assert.throws(() => parseMatchingInvitationDetail(malformed), TypeError);
});

test("Matching binds UTC expiry values without changing signed fractional text", () => {
  for (const [outer, signed] of [
    ["2026-09-02T08:00:00Z", "2026-09-02T08:00:00.000000Z"],
    ["2026-09-02T08:00:00.123Z", "2026-09-02T08:00:00.123000Z"],
    ["2026-09-02T08:00:00.123456Z", "2026-09-02T08:00:00.123456000Z"],
  ]) {
    const value = detail({ expires_at: outer, disclosure: disclosure({ expires_at: signed }) });
    const original = JSON.stringify(value);
    assert.equal(parseMatchingInvitationDetail(value), value);
    assert.deepEqual(parseMatchingInvitationList({ items: [value], next_cursor: null }).items, [value]);
    assert.equal(JSON.stringify(value), original);
  }
  for (const signed of [
    "2026-09-02T08:00:00.123457Z",
    "2026-09-02T08:00:00.123456001Z",
    "2026-09-02T08:00:00.123456+00:00",
  ]) {
    assert.throws(() => parseMatchingInvitationDetail(detail({
      expires_at: "2026-09-02T08:00:00.123456Z",
      disclosure: disclosure({ expires_at: signed }),
    })), TypeError);
  }
});

test("Matching proxy accepts unchanged list and detail with equivalent UTC precision", async () => {
  const value = detail({ disclosure: disclosure({ expires_at: "2026-09-02T08:00:00.000000Z" }) });
  for (const isList of [true, false]) {
    const body = isList ? { items: [value], next_cursor: null } : value;
    const response = await proxyIamRequest(new Request(
      `http://web.local/v1/me/matching-invitations${isList ? "" : `/${ID.invitation}`}`,
      { headers: { "x-workspace-id": "personal:10000000-0000-4000-8000-000000000001" } },
    ), {
      baseUrl: "http://127.0.0.1:8000",
      fetchImpl: async () => new Response(JSON.stringify(body), {
        status: 200,
        headers: { "cache-control": "no-store", "content-type": "application/json", ...(isList ? {} : { etag: '"v2"' }) },
      }),
    });
    assert.equal(response.status, 200);
    assert.deepEqual(await response.json(), body);
  }
});

test("Matching create proxy binds exact expiry despite equivalent fractional precision", async () => {
  const expiry = "2026-09-02T08:00:00.123Z";
  for (const [returnedExpiry, expectedStatus] of [
    ["2026-09-02T08:00:00.123000Z", 201],
    ["2026-09-02T08:00:00.123001Z", 503],
  ]) {
    const body = reviewerInvitation({ expires_at: returnedExpiry });
    const response = await proxyIamRequest(new Request(
      `http://web.local/v1/operations/match-runs/${ID.run}/invitations`,
      {
        method: "POST",
        headers: matchingHeaders({ "if-match": '"v4"', "x-workspace-id": "platform:10000000-0000-4000-8000-000000000001" }),
        body: JSON.stringify({ match_run_id: ID.run, creator_user_id: ID.creator, expires_at: expiry }),
      },
    ), {
      baseUrl: "http://127.0.0.1:8000",
      fetchImpl: async () => new Response(JSON.stringify(body), {
        status: 201,
        headers: { "cache-control": "no-store", "content-type": "application/json", etag: '"v1"' },
      }),
    });
    assert.equal(response.status, expectedStatus);
    if (expectedStatus === 201) assert.deepEqual(await response.json(), body);
  }
});

test("Matching owner projection contains only accepted safe cards and no rank, score, evidence, or user id", () => {
  assert.deepEqual(parseMatchingSelection(selection()), selection());
  assert.deepEqual(parseMatchingSelection(selection({
    status: "PENDING_CHOICE", chosen_invitation_id: ID.invitation,
  })).status, "PENDING_CHOICE");
  assert.deepEqual(parseMatchingSelection(selection({
    status: "PENDING_CLOSE", chosen_invitation_id: null,
  })).status, "PENDING_CLOSE");
  for (const forbidden of ["rank", "score", "evidence", "creator_user_id", "private_floor_amount_minor"]) {
    assert.throws(() => parseMatchingSelection(selection({
      accepted_invitations: [acceptedInvitation({ [forbidden]: forbidden === "rank" ? 1 : "secret" })],
    })), TypeError);
  }
  assert.throws(() => parseMatchingSelection({
    ...selection(),
    accepted_invitations: undefined,
  }), TypeError);
  assert.throws(() => parseMatchingSelection(selection({ chosen_invitation_id: "business_invitation_other1" })), TypeError);
  assert.throws(() => parseMatchingSelection(selection({ status: "PENDING_CHOICE" })), TypeError);
  assert.throws(() => parseMatchingSelection(selection({
    status: "PENDING_CLOSE", chosen_invitation_id: ID.invitation,
  })), TypeError);
});

test("Matching attempts are exact, unique, and demand-bound without inventing an order contract", () => {
  const attempts = {
    items: [
      { attempt_id: "matching_attempt_0000002", demand_id: ID.demand, attempt_no: 2, status: "OPEN", aggregate_version: 2, updated_at: NOW },
      { attempt_id: ID.attempt, demand_id: ID.demand, attempt_no: 1, status: "INVALIDATED", aggregate_version: 3, updated_at: "2026-08-25T08:00:00Z" },
    ],
    next_cursor: null,
  };
  assert.deepEqual(parseMatchingAttemptList(attempts, ID.demand), attempts);
  assert.deepEqual(
    parseMatchingAttemptList({ ...attempts, items: [...attempts.items].reverse() }, ID.demand).items,
    [...attempts.items].reverse(),
  );
  assert.throws(() => parseMatchingAttemptList({ ...attempts, items: [{ ...attempts.items[0], demand_id: "demand_object_other00001" }] }, ID.demand), TypeError);
});

test("Matching assignment and reviewer projections are exact, authority-bound shapes", () => {
  assert.deepEqual(
    parseMatchingCandidateSelectorAssignment(selectorAssignment(), ID.demand),
    selectorAssignment(),
  );
  assert.deepEqual(parseMatchingReviewAssignment(reviewAssignment()), reviewAssignment());
  assert.deepEqual(parseMatchingReviewWorkspace(reviewWorkspace()), reviewWorkspace());
  const failedWorkspace = reviewWorkspace({
    run: {
      status: "FAILED",
      aggregate_version: 4,
      ordered_result_sha256: null,
      candidate_count: null,
      eligible_count: null,
      excluded_count: null,
      failure_code: "MATCHING_FAILED",
    },
  });
  assert.deepEqual(parseMatchingReviewWorkspace(failedWorkspace), failedWorkspace);
  const cancelledWorkspace = reviewWorkspace({
    run: {
      status: "CANCELLED",
      aggregate_version: 4,
      ordered_result_sha256: null,
      candidate_count: null,
      eligible_count: null,
      excluded_count: null,
      failure_code: null,
    },
  });
  assert.deepEqual(parseMatchingReviewWorkspace(cancelledWorkspace), cancelledWorkspace);
  assert.deepEqual(parseMatchingReviewerInvitation(reviewerInvitation()), reviewerInvitation());
  assert.deepEqual(parseMatchingReviewerAttempt(reviewerAttempt()), reviewerAttempt());

  assert.throws(() => parseMatchingCandidateSelectorAssignment(
    selectorAssignment({ demand_id: "demand_object_other00001" }), ID.demand,
  ), TypeError);
  assert.throws(() => parseMatchingReviewWorkspace(reviewWorkspace({
    role_code: "OPERATIONS_REVIEWER",
  })), TypeError);
  assert.throws(() => parseMatchingReviewWorkspace(reviewWorkspace({
    run: { ...reviewWorkspace().run, excluded_count: 1 },
  })), TypeError);
  assert.throws(() => parseMatchingReviewWorkspace(reviewWorkspace({
    run: { ...failedWorkspace.run, candidate_count: 0 },
  })), TypeError);
  assert.throws(() => parseMatchingReviewWorkspace(reviewWorkspace({
    eligible_candidates: [{ ...reviewWorkspace().eligible_candidates[0], private_note: "secret" }],
  })), TypeError);
});

test("Matching assignment and reviewer intents omit spoofable authority facts", () => {
  assert.deepEqual(createClaimCandidateSelectorIntent({
    demandId: ID.demand, csrfToken: CSRF, idempotencyKey: KEY,
  }), {
    method: "POST",
    path: "/v1/matching/candidate-selector-assignments/claim",
    headers: {
      "content-type": "application/json",
      "idempotency-key": KEY,
      "x-csrf-token": CSRF,
    },
    body: { demand_id: ID.demand },
  });
  assert.deepEqual(createClaimMatchingReviewIntent({
    csrfToken: CSRF, idempotencyKey: KEY,
  }).body, {});
  assert.deepEqual(createReleaseMatchingReviewIntent({
    assignment: reviewAssignment(), entityTag: '"v1"', csrfToken: CSRF, idempotencyKey: KEY,
  }).body, {});
  assert.deepEqual(createMatchingReviewInvitationIntent({
    workspace: reviewWorkspace(), creatorUserId: ID.creator, expiresAt: LATER,
    csrfToken: CSRF, idempotencyKey: KEY,
  }).body, {
    match_run_id: ID.run,
    creator_user_id: ID.creator,
    expires_at: LATER,
  });
  assert.deepEqual(createPublishMatchingReviewInvitationIntent({
    invitation: reviewWorkspace().invitations[0], csrfToken: CSRF, idempotencyKey: KEY,
  }).body, { snapshot_sha256: SHA });
  assert.deepEqual(createInvalidateMatchingReviewAttemptIntent({
    workspace: reviewWorkspace(), reasonCode: "REVIEW_INVALIDATED",
    csrfToken: CSRF, idempotencyKey: KEY,
  }).body, { reason_code: "REVIEW_INVALIDATED", input_baseline_sha256: SHA });
  assert.throws(() => createMatchingReviewInvitationIntent({
    workspace: reviewWorkspace(), creatorUserId: "10000000-0000-4000-8000-000000000099",
    expiresAt: LATER, csrfToken: CSRF, idempotencyKey: KEY,
  }), /MATCHING_REVIEW_CANDIDATE_UNAVAILABLE/);
});

test("Matching role configuration is bounded before it reaches the same-origin proxy", () => {
  assert.equal(
    createMatchingReviewInvitationExpiry(24, Date.parse(NOW)),
    "2026-08-27T08:00:00.000Z",
  );
  assert.throws(() => createMatchingReviewInvitationExpiry(0, Date.parse(NOW)), /INVALID_MATCHING_REVIEW_EXPIRY/);
  assert.throws(() => createMatchingReviewInvitationExpiry(673, Date.parse(NOW)), /INVALID_MATCHING_REVIEW_EXPIRY/);
  assert.throws(() => createMatchingReviewInvitationExpiry(1.5, Date.parse(NOW)), /INVALID_MATCHING_REVIEW_EXPIRY/);

  const decline = createDeclineMatchingInvitationIntent({
    invitation: detail(),
    entityTag: '"v2"',
    reasonCode: "RECIPIENT_DECLINED",
    note: "当前交付周期无法配合，希望后续再联系。",
    csrfToken: CSRF,
    idempotencyKey: KEY,
  });
  assert.equal(decline.body.note, "当前交付周期无法配合，希望后续再联系。");
  const withdraw = createWithdrawMatchingInvitationIntent({
    invitation: detail({ status: "ACCEPTED", response_status: "ACCEPTED" }),
    entityTag: '"v2"',
    reasonCode: "RECIPIENT_WITHDREW",
    note: "  ",
    csrfToken: CSRF,
    idempotencyKey: KEY,
  });
  assert.equal(withdraw.body.note, null);
  for (const note of ["x".repeat(501), "not\u0000safe", "e\u0301"]) {
    assert.throws(() => createDeclineMatchingInvitationIntent({
      invitation: detail(), entityTag: '"v2"', reasonCode: "RECIPIENT_DECLINED",
      note, csrfToken: CSRF, idempotencyKey: KEY,
    }), /INVALID_MATCHING_RESPONSE_NOTE/);
  }
});

test("Matching accepts the full disclosure schema bounds while keeping the projection closed", () => {
  const unicodeTitle = "能".repeat(120);
  const textItems = Array.from({ length: 50 }, (_, index) => `交付摘要 ${index % 2}`);
  const codeItems = Array.from({ length: 100 }, (_, index) => `REGION:${String(index).padStart(3, "0")}`);
  const exact = detail({
    disclosure: disclosure({
      organization_preview: { organization_id: ID.organization, display_label: "组".repeat(120) },
      opportunity: {
        title: unicodeTitle,
        problem_summary: "合成问题边界",
        deliverable_summaries: textItems,
        acceptance_summaries: [],
      },
      offer: { ...disclosure().offer, schedule_code: "SCHEDULE:FLEXIBLE-V1" },
      constraints: {
        region_codes: codeItems,
        language_codes: [],
        data_sensitivity_code: "RESTRICTED",
        ai_use_code: "PROHIBITED",
      },
    }),
  });
  assert.deepEqual(parseMatchingInvitationDetail(exact), exact);
  assert.throws(() => parseMatchingInvitationDetail(detail({
    disclosure: disclosure({
      constraints: { ...disclosure().constraints, data_sensitivity_code: "UNKNOWN" },
    }),
  })), TypeError);
});

test("Matching mutations bind ETag, CSRF, idempotency key, hashes and controlled codes", () => {
  assert.deepEqual(createAcceptMatchingInvitationIntent({
    invitation: detail(), entityTag: '"v2"', csrfToken: CSRF, idempotencyKey: KEY,
  }), {
    method: "POST",
    path: `/v1/me/matching-invitations/${ID.invitation}/accept`,
    headers: {
      "content-type": "application/json",
      "idempotency-key": KEY,
      "if-match": '"v2"',
      "x-csrf-token": CSRF,
    },
    body: { snapshot_sha256: SHA },
  });
  assert.deepEqual(createDeclineMatchingInvitationIntent({
    invitation: detail(), entityTag: '"v2"', reasonCode: "RECIPIENT_DECLINED", csrfToken: CSRF, idempotencyKey: KEY,
  }).body, {
    snapshot_sha256: SHA,
    reason_code: "RECIPIENT_DECLINED",
    note: null,
  });
  assert.deepEqual(createWithdrawMatchingInvitationIntent({
    invitation: detail({ status: "ACCEPTED", response_status: "ACCEPTED" }),
    entityTag: '"v2"',
    reasonCode: "RECIPIENT_WITHDREW",
    csrfToken: CSRF,
    idempotencyKey: KEY,
  }).body, {
    snapshot_sha256: SHA,
    reason_code: "RECIPIENT_WITHDREW",
    note: null,
  });
  assert.deepEqual(createChooseMatchingSelectionIntent({
    organizationId: ID.organization,
    selection: selection(),
    entityTag: '"v3"',
    invitationId: ID.invitation,
    selectionBasisCode: "CAPABILITY_SUMMARY_FIT",
    csrfToken: CSRF,
    idempotencyKey: KEY,
  }).body, {
    invitation_id: ID.invitation,
    selection_basis_code: "CAPABILITY_SUMMARY_FIT",
    current_invitation_set_sha256: SHA,
    candidate_selector_assignment_id: "candidate_selector_assignment_01",
    candidate_selector_assignment_version: 4,
  });
  assert.deepEqual(createCloseMatchingSelectionIntent({
    organizationId: ID.organization,
    selection: selection(),
    entityTag: '"v3"',
    reasonCode: "OWNER_CLOSED",
    csrfToken: CSRF,
    idempotencyKey: KEY,
  }).body, {
    reason_code: "OWNER_CLOSED",
    current_invitation_set_sha256: SHA,
    candidate_selector_assignment_id: "candidate_selector_assignment_01",
    candidate_selector_assignment_version: 4,
  });

  assert.throws(() => createAcceptMatchingInvitationIntent({
    invitation: detail({ status: "ACCEPTED", response_status: "ACCEPTED" }), entityTag: '"v2"', csrfToken: CSRF, idempotencyKey: KEY,
  }), /MATCHING_INVITATION_NOT_RESPONDABLE/);
  assert.throws(() => createChooseMatchingSelectionIntent({
    organizationId: ID.organization, selection: selection({ accepted_invitations: [] }), entityTag: '"v3"', invitationId: ID.invitation,
    selectionBasisCode: "CAPABILITY_SUMMARY_FIT", csrfToken: CSRF, idempotencyKey: KEY,
  }), /MATCHING_INVITATION_NOT_ACCEPTED/);
  assert.throws(() => createCloseMatchingSelectionIntent({
    organizationId: ID.organization, selection: selection({ status: "SELECTED", chosen_invitation_id: ID.invitation }), entityTag: '"v3"', reasonCode: "OWNER_CLOSED",
    csrfToken: CSRF, idempotencyKey: KEY,
  }), /MATCHING_SELECTION_NOT_OPEN/);
});

function matchingHeaders(overrides = {}) {
  return {
    "content-type": "application/json",
    "idempotency-key": KEY,
    "if-match": '"v3"',
    "x-csrf-token": CSRF,
    "x-workspace-id": `org:${ID.organization}`,
    ...overrides,
  };
}

function chooseBody(overrides = {}) {
  return {
    invitation_id: ID.invitation,
    selection_basis_code: "CAPABILITY_SUMMARY_FIT",
    current_invitation_set_sha256: SHA,
    candidate_selector_assignment_id: "candidate_selector_assignment_01",
    candidate_selector_assignment_version: 4,
    ...overrides,
  };
}

test("Matching proxy forwards bounded role configuration without authority fields", async () => {
  const responseNote = "档期已经变化，希望下一轮再沟通。";
  const decline = await createIamProxyRequest(new Request(
    `http://web.local/v1/me/matching-invitations/${ID.invitation}/decline`,
    {
      method: "POST",
      headers: matchingHeaders({
        "if-match": '"v2"',
        "x-workspace-id": "personal:10000000-0000-4000-8000-000000000001",
      }),
      body: JSON.stringify({
        snapshot_sha256: SHA,
        reason_code: "RECIPIENT_DECLINED",
        note: responseNote,
      }),
    },
  ), "http://127.0.0.1:8000");
  assert.deepEqual(await decline.json(), {
    snapshot_sha256: SHA,
    reason_code: "RECIPIENT_DECLINED",
    note: responseNote,
  });

  const expiresAt = createMatchingReviewInvitationExpiry(72, Date.parse(NOW));
  const create = await createIamProxyRequest(new Request(
    `http://web.local/v1/operations/match-runs/${ID.run}/invitations`,
    {
      method: "POST",
      headers: matchingHeaders({
        "if-match": '"v4"',
        "x-workspace-id": "platform:10000000-0000-4000-8000-000000000001",
      }),
      body: JSON.stringify({
        match_run_id: ID.run,
        creator_user_id: ID.creator,
        expires_at: expiresAt,
      }),
    },
  ), "http://127.0.0.1:8000");
  assert.deepEqual(await create.json(), {
    match_run_id: ID.run,
    creator_user_id: ID.creator,
    expires_at: expiresAt,
  });
  assert.equal(create.headers.get("x-workspace-id"), "platform:10000000-0000-4000-8000-000000000001");
  assert.equal(create.headers.has("x-actor-user-id"), false);
  assert.equal(create.headers.has("x-role-codes"), false);
});

test("Matching proxy closes methods, query, headers, body size and selector assignment material", async () => {
  const forwarded = await createIamProxyRequest(new Request(
    `http://web.local/v1/organizations/${ID.organization}/selections/${ID.selection}/choose`,
    { method: "POST", headers: matchingHeaders(), body: JSON.stringify(chooseBody()) },
  ), "http://127.0.0.1:8000");
  assert.equal(forwarded.url, `http://127.0.0.1:8000/v1/organizations/${ID.organization}/selections/${ID.selection}/choose`);
  assert.equal(forwarded.headers.get("x-workspace-id"), `org:${ID.organization}`);
  assert.deepEqual(await forwarded.json(), chooseBody());

  await assert.rejects(() => createIamProxyRequest(new Request(
    `http://web.local/v1/organizations/${ID.organization}/selections/${ID.selection}/choose`,
    { method: "POST", headers: matchingHeaders({ "x-workspace-id": undefined }), body: JSON.stringify(chooseBody()) },
  ), "http://127.0.0.1:8000"), /INVALID_MATCHING_REQUEST/);
  await assert.rejects(() => createIamProxyRequest(new Request(
    `http://web.local/v1/organizations/${ID.organization}/selections/${ID.selection}/choose`,
    { method: "POST", headers: matchingHeaders({ "x-workspace-id": "personal:10000000-0000-4000-8000-000000000001" }), body: JSON.stringify(chooseBody()) },
  ), "http://127.0.0.1:8000"), /INVALID_MATCHING_REQUEST/);

  await assert.rejects(() => createIamProxyRequest(new Request(
    `http://web.local/v1/organizations/${ID.organization}/selections/${ID.selection}/choose`,
    { method: "POST", headers: matchingHeaders(), body: JSON.stringify(chooseBody({ candidate_selector_assignment_version: undefined })) },
  ), "http://127.0.0.1:8000"), /INVALID_MATCHING_REQUEST/);
  await assert.rejects(() => createIamProxyRequest(new Request(
    `http://web.local/v1/organizations/${ID.organization}/selections/${ID.selection}/choose`,
    { method: "POST", headers: matchingHeaders({ "x-csrf-token": "x".repeat(257) }), body: JSON.stringify(chooseBody()) },
  ), "http://127.0.0.1:8000"), /INVALID_MATCHING_REQUEST/);
  await assert.rejects(() => createIamProxyRequest(new Request(
    "http://web.local/v1/me/matching-invitations?limit=100&unexpected=true",
    { headers: { "x-workspace-id": "personal:10000000-0000-4000-8000-000000000001" } },
  ), "http://127.0.0.1:8000"), /INVALID_MATCHING_REQUEST/);
  await assert.rejects(() => createIamProxyRequest(new Request(
    "http://web.local/v1/me/matching-invitations",
    { method: "POST", headers: matchingHeaders(), body: "{}" },
  ), "http://127.0.0.1:8000"), /IAM_ROUTE_NOT_ALLOWED/);
});

test("Matching exact-ID read retains completed selection access and binds its response", async () => {
  const path = `http://web.local/v1/organizations/${ID.organization}/selections/${ID.selection}`;
  const headers = { "x-workspace-id": `org:${ID.organization}` };
  const terminal = selection({ status: "SELECTED", chosen_invitation_id: ID.invitation });
  const forwarded = await createIamProxyRequest(new Request(path, { headers }), "http://127.0.0.1:8000");
  assert.equal(forwarded.method, "GET");
  assert.equal(forwarded.headers.get("x-workspace-id"), headers["x-workspace-id"]);
  const response = await proxyIamRequest(new Request(path, { headers }), {
    baseUrl: "http://127.0.0.1:8000",
    fetchImpl: async () => new Response(JSON.stringify(terminal), {
      status: 200, headers: { "cache-control": "no-store", "content-type": "application/json", etag: '"v3"' },
    }),
  });
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), terminal);
  for (const malformed of [path + "?limit=1", path + "/unexpected"]) {
    await assert.rejects(() => createIamProxyRequest(new Request(malformed, { headers }), "http://127.0.0.1:8000"));
  }
  await assert.rejects(() => createIamProxyRequest(new Request(path, {
    headers: { "x-workspace-id": "org:10000000-0000-4000-8000-000000000099" },
  }), "http://127.0.0.1:8000"));
  const mismatch = await proxyIamRequest(new Request(path, { headers }), {
    baseUrl: "http://127.0.0.1:8000",
    fetchImpl: async () => new Response(JSON.stringify(selection({ selection_id: "other_selection_0000001" })), {
      status: 200, headers: { "cache-control": "no-store", "content-type": "application/json", etag: '"v3"' },
    }),
  });
  assert.equal(mismatch.status, 503);
});

test("Matching choose replay accepts only the coordinator's completed assignment transitions", async () => {
  for (const [assignmentVersion, expectedStatus] of [[4, 503], [5, 200], [6, 200], [7, 503]]) {
    const response = await proxyIamRequest(new Request(
      `http://web.local/v1/organizations/${ID.organization}/selections/${ID.selection}/choose`,
      { method: "POST", headers: matchingHeaders(), body: JSON.stringify(chooseBody()) },
    ), {
      baseUrl: "http://127.0.0.1:8000",
      fetchImpl: async () => new Response(JSON.stringify(selection({
        status: "SELECTED", chosen_invitation_id: ID.invitation,
        candidate_selector_assignment_version: assignmentVersion,
      })), {
        status: 200, headers: { "cache-control": "no-store", "content-type": "application/json", etag: '"v3"' },
      }),
    });
    assert.equal(response.status, expectedStatus);
  }
});

test("Matching operational proxy gates workspace kind and never accepts client authority facts", async () => {
  const claimHeaders = {
    "content-type": "application/json",
    "idempotency-key": KEY,
    "x-csrf-token": CSRF,
    "x-workspace-id": `org:${ID.organization}`,
  };
  const assignmentClaim = await createIamProxyRequest(new Request(
    "http://web.local/v1/matching/candidate-selector-assignments/claim",
    { method: "POST", headers: claimHeaders, body: JSON.stringify({ demand_id: ID.demand }) },
  ), "http://127.0.0.1:8000");
  assert.equal(assignmentClaim.headers.get("x-workspace-id"), `org:${ID.organization}`);
  assert.deepEqual(await assignmentClaim.json(), { demand_id: ID.demand });
  await assert.rejects(() => createIamProxyRequest(new Request(
    "http://web.local/v1/matching/candidate-selector-assignments/claim",
    {
      method: "POST",
      headers: claimHeaders,
      body: JSON.stringify({ demand_id: ID.demand, organization_id: ID.organization }),
    },
  ), "http://127.0.0.1:8000"), /INVALID_MATCHING_REQUEST/);

  const platformHeaders = {
    "content-type": "application/json",
    "idempotency-key": KEY,
    "x-csrf-token": CSRF,
    "x-workspace-id": "platform:10000000-0000-4000-8000-000000000001",
  };
  const reviewClaim = await createIamProxyRequest(new Request(
    "http://web.local/v1/app/matching-review/queue/claim",
    { method: "POST", headers: platformHeaders, body: "{}" },
  ), "http://127.0.0.1:8000");
  assert.deepEqual(await reviewClaim.json(), {});
  await assert.rejects(() => createIamProxyRequest(new Request(
    "http://web.local/v1/app/matching-review/queue/claim",
    { method: "POST", headers: { ...platformHeaders, "x-workspace-id": `org:${ID.organization}` }, body: "{}" },
  ), "http://127.0.0.1:8000"), /INVALID_MATCHING_REQUEST/);

  const reviewed = await proxyIamRequest(new Request(
    "http://web.local/v1/app/matching-review/assignment",
    { headers: { "x-workspace-id": "platform:10000000-0000-4000-8000-000000000001" } },
  ), {
    baseUrl: "http://127.0.0.1:8000",
    fetchImpl: async () => new Response(JSON.stringify(reviewWorkspace()), {
      status: 200,
      headers: { "cache-control": "no-store", "content-type": "application/json", etag: '"v1"' },
    }),
  });
  assert.equal(reviewed.status, 200);
  assert.deepEqual(await reviewed.json(), reviewWorkspace());
});

test("Matching proxy preserves valid fail-closed errors and rejects assignment-mismatched success", async () => {
  const detailRequest = new Request(`http://web.local/v1/me/matching-invitations/${ID.invitation}`, {
    headers: { "x-workspace-id": "personal:10000000-0000-4000-8000-000000000001" },
  });
  const missing = await proxyIamRequest(detailRequest, {
    baseUrl: "http://127.0.0.1:8000",
    fetchImpl: async () => new Response(JSON.stringify({
      code: "RESOURCE_NOT_FOUND",
      message: "Invitation is unavailable.",
      trace_id: "matching_trace_000000001",
    }), {
      status: 404,
      headers: { "cache-control": "no-store", "content-type": "application/json" },
    }),
  });
  assert.equal(missing.status, 404);
  assert.deepEqual(await missing.json(), {
    code: "RESOURCE_NOT_FOUND",
    message: "Invitation is unavailable.",
    trace_id: "matching_trace_000000001",
  });

  const chooseRequest = new Request(
    `http://web.local/v1/organizations/${ID.organization}/selections/${ID.selection}/choose`,
    { method: "POST", headers: matchingHeaders(), body: JSON.stringify(chooseBody()) },
  );
  const mismatch = await proxyIamRequest(chooseRequest, {
    baseUrl: "http://127.0.0.1:8000",
    fetchImpl: async () => new Response(JSON.stringify(selection({
      candidate_selector_assignment_id: "candidate_selector_assignment_other",
      chosen_invitation_id: ID.invitation,
    })), {
      status: 200,
      headers: { "cache-control": "no-store", "content-type": "application/json", etag: '"v3"' },
    }),
  });
  assert.equal(mismatch.status, 503);
  assert.equal((await mismatch.json()).code, "MATCHING_BACKEND_UNAVAILABLE");

  const hashMismatch = await proxyIamRequest(new Request(
    `http://web.local/v1/organizations/${ID.organization}/selections/${ID.selection}/choose`,
    { method: "POST", headers: matchingHeaders(), body: JSON.stringify(chooseBody()) },
  ), {
    baseUrl: "http://127.0.0.1:8000",
    fetchImpl: async () => new Response(JSON.stringify(selection({
      current_invitation_set_sha256: SHA_B,
      chosen_invitation_id: ID.invitation,
    })), {
      status: 200,
      headers: { "cache-control": "no-store", "content-type": "application/json", etag: '"v3"' },
    }),
  });
  assert.equal(hashMismatch.status, 503);
  assert.equal((await hashMismatch.json()).code, "MATCHING_BACKEND_UNAVAILABLE");

  const unknown = await proxyIamRequest(new Request(
    `http://web.local/v1/organizations/${ID.organization}/selections/${ID.selection}/choose`,
    { method: "POST", headers: matchingHeaders(), body: JSON.stringify(chooseBody()) },
  ), {
    baseUrl: "http://127.0.0.1:8000",
    fetchImpl: async () => new Response(JSON.stringify({
      code: "COMMAND_OUTCOME_UNKNOWN",
      message: "The command may have completed; replay the same idempotency key.",
      trace_id: "matching_trace_000000002",
    }), {
      status: 503,
      headers: { "cache-control": "no-store", "content-type": "application/json" },
    }),
  });
  assert.equal(unknown.status, 503);
  assert.equal((await unknown.json()).code, "COMMAND_OUTCOME_UNKNOWN");

  const wrongUnknownStatus = await proxyIamRequest(new Request(
    `http://web.local/v1/organizations/${ID.organization}/selections/${ID.selection}/choose`,
    { method: "POST", headers: matchingHeaders(), body: JSON.stringify(chooseBody()) },
  ), {
    baseUrl: "http://127.0.0.1:8000",
    fetchImpl: async () => new Response(JSON.stringify({
      code: "COMMAND_OUTCOME_UNKNOWN",
      message: "The command may have completed.",
      trace_id: "matching_trace_000000003",
    }), {
      status: 409,
      headers: { "cache-control": "no-store", "content-type": "application/json" },
    }),
  });
  assert.equal(wrongUnknownStatus.status, 503);
  assert.equal((await wrongUnknownStatus.json()).code, "MATCHING_BACKEND_UNAVAILABLE");

  const wrongPreconditionStatus = await proxyIamRequest(new Request(
    `http://web.local/v1/organizations/${ID.organization}/selections/${ID.selection}/choose`,
    { method: "POST", headers: matchingHeaders(), body: JSON.stringify(chooseBody()) },
  ), {
    baseUrl: "http://127.0.0.1:8000",
    fetchImpl: async () => new Response(JSON.stringify({
      code: "PRECONDITION_FAILED",
      message: "The resource version does not match.",
      trace_id: "matching_trace_000000005",
    }), {
      status: 409,
      headers: { "cache-control": "no-store", "content-type": "application/json" },
    }),
  });
  assert.equal(wrongPreconditionStatus.status, 503);
  assert.equal((await wrongPreconditionStatus.json()).code, "MATCHING_BACKEND_UNAVAILABLE");

  const wrongDeclineCode = await proxyIamRequest(new Request(
    `http://web.local/v1/me/matching-invitations/${ID.invitation}/decline`,
    {
      method: "POST",
      headers: matchingHeaders({ "x-workspace-id": "personal:10000000-0000-4000-8000-000000000001" }),
      body: JSON.stringify({ snapshot_sha256: SHA, reason_code: "RECIPIENT_DECLINED", note: null }),
    },
  ), {
    baseUrl: "http://127.0.0.1:8000",
    fetchImpl: async () => new Response(JSON.stringify({
      code: "INVITATION_ALREADY_SELECTED",
      message: "This code belongs only to withdrawal.",
      trace_id: "matching_trace_000000004",
    }), {
      status: 409,
      headers: { "cache-control": "no-store", "content-type": "application/json" },
    }),
  });
  assert.equal(wrongDeclineCode.status, 503);
  assert.equal((await wrongDeclineCode.json()).code, "MATCHING_BACKEND_UNAVAILABLE");

  const unavailable = await proxyIamRequest(
    new Request(`http://web.local/v1/me/matching-invitations/${ID.invitation}`, {
      headers: { "x-workspace-id": "personal:10000000-0000-4000-8000-000000000001" },
    }),
    {
      baseUrl: "http://127.0.0.1:8000",
      fetchImpl: async () => { throw new TypeError("matching backend is not composed"); },
    },
  );
  assert.equal(unavailable.status, 503);
  assert.deepEqual(await unavailable.json(), {
    code: "MATCHING_BACKEND_UNAVAILABLE",
    message: "无法验证 Matching 服务响应。",
  });
});

test("Matching pending writes remain exact while the unextended task envelope fails closed", () => {
  const intent = createChooseMatchingSelectionIntent({
    organizationId: ID.organization,
    selection: selection(),
    entityTag: '"v3"',
    invitationId: ID.invitation,
    selectionBasisCode: "CAPABILITY_SUMMARY_FIT",
    csrfToken: CSRF,
    idempotencyKey: KEY,
  });
  const pending = {
    version: 1,
    saved_at: NOW,
    resource_type: "MATCHING_SELECTION",
    object_id: ID.selection,
    label: "选择已接受创作者",
    intent,
  };
  const encoded = serializePendingIntent(pending);
  assert.deepEqual(parsePendingIntent(encoded, Date.parse(NOW)), pending);
  assert.equal(parsePendingIntent(JSON.stringify({
    ...pending,
    intent: { ...intent, body: { ...intent.body, candidate_selector_assignment_version: undefined } },
  }), Date.parse(NOW)), null);
  assert.equal(parsePendingIntent(JSON.stringify({
    ...pending,
    intent: { ...intent, body: { ...intent.body, candidate_selector_assignment_version: 2147483648 } },
  }), Date.parse(NOW)), null);
  assert.equal(parsePendingIntent(JSON.stringify({
    ...pending,
    intent: { ...intent, headers: { ...intent.headers, "x-csrf-token": "x".repeat(257) } },
  }), Date.parse(NOW)), null);
  assert.equal(parsePendingIntent(JSON.stringify({ ...pending, object_id: "matching_selection_other1" }), Date.parse(NOW)), null);
  assert.equal(CURRENT_ACCOUNT_TASK_RESOURCE_KINDS.includes("MATCHING_INVITATION"), false);
  assert.equal(CURRENT_ACCOUNT_TASK_RESOURCE_KINDS.includes("MATCHING_SELECTION"), false);
  assert.equal(CURRENT_ACCOUNT_TASK_NEXT_ACTIONS.includes("RESPOND_MATCHING_INVITATION"), false);
  assert.equal(CURRENT_ACCOUNT_TASK_NEXT_ACTIONS.includes("CHOOSE_MATCHING_CREATOR"), false);
});

test("Matching pending storage never persists the page CSRF token", () => {
  const intent = createChooseMatchingSelectionIntent({
    organizationId: ID.organization,
    selection: selection(),
    entityTag: '"v3"',
    invitationId: ID.invitation,
    selectionBasisCode: "CAPABILITY_SUMMARY_FIT",
    csrfToken: CSRF,
    idempotencyKey: KEY,
  });
  const encoded = serializeMatchingPendingIntent({
    version: 1,
    saved_at: NOW,
    resource_type: "MATCHING_SELECTION",
    object_id: ID.selection,
    label: "choose",
    intent,
  });
  assert.equal(encoded.includes(CSRF), false);
  const recovered = parsePendingIntent(encoded, Date.parse(NOW));
  assert.equal(recovered?.intent.headers["x-csrf-token"], "matching_pending_csrf_not_persisted_v1");
  assert.deepEqual(recovered?.intent.body, intent.body);
  assert.equal(recovered?.intent.headers["idempotency-key"], KEY);
});
