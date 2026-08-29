import assert from "node:assert/strict";
import test from "node:test";

import {
  createAcceptOrganizationInvitationIntent,
  createIssueOrganizationInvitationIntent,
  createOrganizationLifecycleIntent,
  createUpdateOrganizationPublicNameIntent,
  parseAccessInvitationAcceptance,
  parseAccessInvitationPage,
  parseAccessInvitationPreview,
  parseIssueOrganizationInvitationResponse,
  parseMembershipPage,
  parseOrganizationSummary,
  parsePendingInvitationContext,
  parsePendingInvitationAcceptance,
  parsePendingOrganizationAdminWrite,
  serializePendingInvitationContext,
  serializePendingInvitationAcceptance,
  serializePendingOrganizationAdminWrite,
} from "../lib/app-contract.mjs";
import {
  captureAccessInvitationFragment,
  createInvitationAuthorizationInit,
  createInvitationStepUpBody,
  createJoinFlowCoordinator,
  createTokenlessStepUpBody,
  parseIdentityAuthorizationUrl,
} from "../lib/invitation-flow.mjs";
import {
  createAuthProxyRequest,
  createIamProxyRequest,
  proxyAuthRequest,
  proxyIamRequest,
} from "../lib/server-proxy.mjs";

const organizationId = "4316fcdd-e7fb-5c41-9736-3aaf876aa08e";
const invitationId = "11111111-1111-4111-8111-111111111111";
const membershipId = "22222222-2222-4222-8222-222222222222";
const userId = "33333333-3333-4333-8333-333333333333";
const csrf = "csrf_token_internal_000000000000001";
const idempotency = "org-admin-idempotency-00000001";
const token = "t".repeat(96);
const cursor = `${"c".repeat(64)}.${"s".repeat(43)}`;
const invalidPublicNames = [
  "",
  " leading",
  "trailing ",
  "e\u0301",
  "control\u0000",
  "c1\u0085",
  "zero\u200Bwidth",
  "bidi\u202Eoverride",
  "x".repeat(161),
  "😀".repeat(161),
];

const organization = {
  organization_id: organizationId,
  public_name: "INTERNAL_SANDBOX 合成组织",
  type: "CREATOR_TEAM",
  status: "ACTIVE",
  aggregate_version: 4,
  entity_tag: '"v4"',
};

const invitation = {
  invitation_id: invitationId,
  purpose: "ORGANIZATION_MEMBERSHIP",
  organization_id: organizationId,
  target_role: "DEMAND_OWNER",
  masked_recipient_label: "s***@example.test",
  is_initial_admin: false,
  status: "ISSUED",
  expires_at: "2026-08-30T08:00:00Z",
  created_at: "2026-08-16T08:00:00Z",
  required_policy_bundle_id: "44444444-4444-4444-8444-444444444444",
  aggregate_version: 1,
  entity_tag: '"v1"',
};

const membership = {
  membership_id: membershipId,
  organization_id: organizationId,
  user_id: userId,
  display_handle: "synthetic_member_01",
  status: "ACTIVE",
  roles: ["DEMAND_OWNER"],
  aggregate_version: 2,
  entity_tag: '"v2"',
};

const me = {
  user_id: userId,
  status: "ACTIVE",
  display_handle: "synthetic_member_01",
  user_roles: ["CREATOR"],
  memberships: [],
  policy_requirements: [],
  aggregate_version: 5,
  entity_tag: '"v5"',
};

const bundle = {
  policy_bundle_id: invitation.required_policy_bundle_id,
  purpose: "ORGANIZATION_MEMBERSHIP",
  jurisdiction: "CN",
  locale: "zh-CN",
  documents: [
    {
      document_id: "55555555-5555-4555-8555-555555555555",
      kind: "TERMS",
      semantic_version: "1.0.0",
      locale: "zh-CN",
      content_sha256: "a".repeat(64),
      legal_effect: "CONTRACT_ACCEPTANCE",
      body: "合成组织条款",
    },
  ],
  consent_offers: [],
  effective_at: "2026-08-01T00:00:00Z",
  entity_tag: '"v1"',
};

test("ORG_ADMIN read and command DTOs are exact, ETag-bound, and secret-free", () => {
  assert.deepEqual(parseOrganizationSummary(organization), organization);
  assert.deepEqual(
    parseAccessInvitationPage({ items: [invitation], page: { next_cursor: null } }),
    { items: [invitation], page: { next_cursor: null } },
  );
  assert.deepEqual(
    parseMembershipPage({ items: [membership], page: { next_cursor: null } }),
    { items: [membership], page: { next_cursor: null } },
  );
  assert.throws(
    () => parseOrganizationSummary({ ...organization, role: "ORG_ADMIN" }),
    /INVALID_APP_CONTRACT/,
  );
  assert.throws(
    () => parseAccessInvitationPage({ items: [{ ...invitation, access_invitation_token: token }], page: { next_cursor: null } }),
    /INVALID_APP_CONTRACT/,
  );
  assert.throws(
    () => parseMembershipPage({ items: [{ ...membership, entity_tag: '"v9"' }], page: { next_cursor: null } }),
    /INVALID_APP_CONTRACT/,
  );
});

test("ORG_ADMIN writes bind only server IDs, current ETags, CSRF, and idempotency", () => {
  const issue = createIssueOrganizationInvitationIntent({
    organization,
    recipientEmail: "sandbox-creator-01@example.test",
    targetRole: "DEMAND_OWNER",
    expiresAt: "2026-08-30T08:00:00Z",
    csrfToken: csrf,
    idempotencyKey: idempotency,
  });
  assert.deepEqual(issue, {
    method: "POST",
    path: `/v1/organizations/${organizationId}/access-invitations`,
    headers: {
      "content-type": "application/json",
      "idempotency-key": idempotency,
      "if-match": '"v4"',
      "x-csrf-token": csrf,
    },
    body: {
      recipient: { type: "EMAIL", value: "sandbox-creator-01@example.test" },
      target_role: "DEMAND_OWNER",
      expires_at: "2026-08-30T08:00:00Z",
    },
  });
  const updatePublicName = createUpdateOrganizationPublicNameIntent({
    organization,
    publicName: "INTERNAL_SANDBOX 更正后的合成组织",
    csrfToken: csrf,
    idempotencyKey: idempotency,
  });
  assert.deepEqual(updatePublicName, {
    method: "POST",
    path: `/v1/organizations/${organizationId}/public-name`,
    headers: {
      "content-type": "application/json",
      "idempotency-key": idempotency,
      "if-match": '"v4"',
      "x-csrf-token": csrf,
    },
    body: {
      public_name: "INTERNAL_SANDBOX 更正后的合成组织",
      reason_code: "PUBLIC_NAME_CORRECTION",
    },
  });
  const suspend = createOrganizationLifecycleIntent({
    resource: membership,
    action: "SUSPEND_MEMBERSHIP",
    csrfToken: csrf,
    idempotencyKey: idempotency,
    reasonCode: "ACCESS_REVIEW",
  });
  assert.equal(suspend.path, `/v1/memberships/${membershipId}/suspend`);
  assert.equal(suspend.headers["if-match"], '"v2"');
  assert.deepEqual(suspend.body, { reason_code: "ACCESS_REVIEW" });
  for (const intent of [issue, updatePublicName, suspend]) {
    for (const forbidden of ["actor", "actor_id", "authority", "organization_id", "workspace_id", "user_id", "access_invitation_token"]) {
      assert.equal(Object.hasOwn(intent.body, forbidden), false);
    }
  }
});

test("organization public names are exact NFC Unicode and invitation previews reuse the same boundary", () => {
  const astralName = "😀".repeat(160);
  assert.equal([...astralName].length, 160);
  const intent = createUpdateOrganizationPublicNameIntent({
    organization,
    publicName: astralName,
    csrfToken: csrf,
    idempotencyKey: idempotency,
  });
  assert.equal(intent.body.public_name, astralName);

  const preview = {
    invitation_id: invitationId,
    purpose: "ORGANIZATION_MEMBERSHIP",
    organization: { public_name: "更正后的组织" },
    target_role: "DEMAND_OWNER",
    expires_at: invitation.expires_at,
    required_policy_bundle_id: invitation.required_policy_bundle_id,
    status: "ISSUED",
    aggregate_version: invitation.aggregate_version,
    entity_tag: invitation.entity_tag,
  };
  assert.deepEqual(parseAccessInvitationPreview(preview), preview);

  for (const invalidName of invalidPublicNames) {
    assert.throws(
      () => createUpdateOrganizationPublicNameIntent({
        organization,
        publicName: invalidName,
        csrfToken: csrf,
        idempotencyKey: idempotency,
      }),
      /INVALID_ORGANIZATION_PUBLIC_NAME/,
    );
    assert.throws(
      () => parseOrganizationSummary({ ...organization, public_name: invalidName }),
      /INVALID_APP_CONTRACT/,
    );
    assert.throws(
      () => parseAccessInvitationPreview({ ...preview, organization: { public_name: invalidName } }),
      /INVALID_APP_CONTRACT/,
    );
  }
  assert.throws(
    () => createUpdateOrganizationPublicNameIntent({
      organization,
      publicName: organization.public_name,
      csrfToken: csrf,
      idempotencyKey: idempotency,
    }),
    /ORGANIZATION_PUBLIC_NAME_UNCHANGED/,
  );
});

test("issue capability is validated in-memory, while persisted recovery shapes reject it", () => {
  const issued = parseIssueOrganizationInvitationResponse({
    invitation,
    access_invitation_token: token,
    join_fragment_url: `/join#access_invitation_token=${token}`,
  });
  assert.equal(issued.access_invitation_token, token);

  const write = {
    version: 1,
    saved_at: "2026-08-16T08:00:00Z",
    operation: "ISSUE_INVITATION",
    target_id: organizationId,
    intent: createIssueOrganizationInvitationIntent({
      organization,
      recipientEmail: "sandbox-creator-01@example.test",
      targetRole: "DEMAND_OWNER",
      expiresAt: "2026-08-30T08:00:00Z",
      csrfToken: csrf,
      idempotencyKey: idempotency,
    }),
  };
  assert.deepEqual(parsePendingOrganizationAdminWrite(serializePendingOrganizationAdminWrite(write), Date.parse(write.saved_at)), write);
  assert.throws(
    () => serializePendingOrganizationAdminWrite({ ...write, access_invitation_token: token }),
    /INVALID_APP_CONTRACT/,
  );

  const publicNameWrite = {
    version: 1,
    saved_at: "2026-08-16T08:00:00Z",
    operation: "UPDATE_PUBLIC_NAME",
    target_id: organizationId,
    intent: createUpdateOrganizationPublicNameIntent({
      organization,
      publicName: "INTERNAL_SANDBOX 恢复中的名称",
      csrfToken: csrf,
      idempotencyKey: idempotency,
    }),
  };
  assert.deepEqual(
    parsePendingOrganizationAdminWrite(
      serializePendingOrganizationAdminWrite(publicNameWrite),
      Date.parse(publicNameWrite.saved_at),
    ),
    publicNameWrite,
  );
  for (const mutate of [
    (candidate) => { candidate.intent.body.reason_code = "ACCESS_REVIEW"; },
    (candidate) => { candidate.intent.body.public_name = "zero\u200Bwidth"; },
    (candidate) => { candidate.intent.body.actor_id = userId; },
    (candidate) => { candidate.intent.path = `/v1/organizations/${organizationId}/public-name/`; },
    (candidate) => { candidate.target_id = membershipId; },
    (candidate) => { candidate.operation = "ISSUE_INVITATION"; },
  ]) {
    const candidate = structuredClone(publicNameWrite);
    mutate(candidate);
    assert.equal(
      parsePendingOrganizationAdminWrite(JSON.stringify(candidate), Date.parse(publicNameWrite.saved_at)),
      null,
    );
  }

  const context = { version: 1, saved_at: "2026-08-16T08:00:00Z", invitation };
  assert.deepEqual(parsePendingInvitationContext(serializePendingInvitationContext(context), Date.parse(context.saved_at)), context);
  assert.throws(
    () => serializePendingInvitationContext({ ...context, access_invitation_token: token }),
    /INVALID_APP_CONTRACT/,
  );
});

test("join fragment is scrubbed synchronously and step-up bodies cannot select authority", () => {
  const replacements = [];
  assert.equal(
    captureAccessInvitationFragment(
      `https://pilot.example.test/join#access_invitation_token=${token}`,
      (path) => replacements.push(path),
      "https://pilot.example.test",
    ),
    token,
  );
  assert.deepEqual(replacements, ["/join"]);
  assert.deepEqual(createInvitationStepUpBody(token), { return_to: "/app", access_invitation_token: token });
  assert.deepEqual(createTokenlessStepUpBody(), { return_to: "/app", reauthenticate: true });
  for (const href of [
    `https://pilot.example.test/join?access_invitation_token=${token}`,
    `https://pilot.example.test/join#access_invitation_token=${token}&role=ORG_ADMIN`,
    `https://evil.example.test/join#access_invitation_token=${token}`,
    "https://pilot.example.test/join#missing=token",
  ]) assert.throws(() => captureAccessInvitationFragment(href, () => {}, "https://pilot.example.test"), /ACCESS_INVITATION_FRAGMENT_INVALID/);
  const authorization = new URL("https://identity.example.test/authorize");
  authorization.searchParams.set("client_id", "desire-internal-sandbox");
  authorization.searchParams.set("redirect_uri", "https://pilot.example.test/v1/auth/oidc/callback");
  authorization.searchParams.set("response_type", "code");
  authorization.searchParams.set("scope", "openid email");
  authorization.searchParams.set("state", "s".repeat(43));
  authorization.searchParams.set("nonce", "n".repeat(43));
  authorization.searchParams.set("code_challenge", "c".repeat(43));
  authorization.searchParams.set("code_challenge_method", "S256");
  assert.equal(parseIdentityAuthorizationUrl(authorization.href), authorization.href);
  for (const target of [
    "https://evil.example.test/authorize?state=synthetic",
    `${authorization.href}#leak`,
    "https://identity.example.test/other?state=synthetic",
    `${authorization.href}&access_invitation_token=${token}`,
  ]) assert.throws(() => parseIdentityAuthorizationUrl(target), /INVALID_AUTHORIZATION_RESPONSE/);
});

test("invitation authorization is anonymous for enrollment and CSRF-bound for signed-in step-up", () => {
  assert.deepEqual(createInvitationAuthorizationInit(token, null), {
    method: "POST",
    credentials: "same-origin",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ return_to: "/app", access_invitation_token: token }),
  });
  assert.deepEqual(createInvitationAuthorizationInit(token, csrf), {
    method: "POST",
    credentials: "same-origin",
    headers: { "content-type": "application/json", "x-csrf-token": csrf },
    body: JSON.stringify({ return_to: "/app", access_invitation_token: token }),
  });
  for (const invalidCsrf of ["", "short", "x".repeat(513), 42]) {
    assert.throws(
      () => createInvitationAuthorizationInit(token, invalidCsrf),
      /INVALID_INVITATION_AUTHORIZATION_REQUEST/,
    );
  }
});

test("join flow coordinator survives StrictMode setup-cleanup-setup without duplicating the capability task", async () => {
  let runs = 0;
  const coordinator = createJoinFlowCoordinator(async () => {
    runs += 1;
    return "REDIRECTING";
  });
  const firstSetup = coordinator.start();
  // StrictMode cleanup does not cancel the shared one-shot task; the replayed
  // setup attaches to the exact same outcome and owns UI commit via generation.
  const replayedSetup = coordinator.start();
  assert.equal(firstSetup, replayedSetup);
  assert.equal(await replayedSetup, "REDIRECTING");
  assert.equal(runs, 1);
});

test("OIDC BFF distinguishes anonymous enrollment, invitation STEP_UP, and explicit tokenless STEP_UP", async () => {
  const headers = {
    cookie: "__Host-ds_session=opaque",
    "content-type": "application/json",
    "x-csrf-token": csrf,
  };
  const anonymousEnrollment = await createAuthProxyRequest(new Request(
    "http://localhost:3000/v1/auth/oidc/authorizations",
    {
      method: "POST",
      headers: {
        cookie: "__Host-ds_session=stale-browser-session",
        "content-type": "application/json",
      },
      body: JSON.stringify(createInvitationStepUpBody(token)),
    },
  ), "http://api:8000");
  assert.equal(anonymousEnrollment.headers.get("cookie"), null);
  assert.equal(anonymousEnrollment.headers.get("x-csrf-token"), null);
  assert.deepEqual(await anonymousEnrollment.json(), { return_to: "/app", access_invitation_token: token });
  const generic = await createAuthProxyRequest(new Request(
    "http://localhost:3000/v1/auth/oidc/authorizations",
    { method: "POST", headers, body: JSON.stringify(createTokenlessStepUpBody()) },
  ), "http://api:8000");
  assert.deepEqual(await generic.json(), { return_to: "/app", reauthenticate: true });
  const invitationStepUp = await createAuthProxyRequest(new Request(
    "http://localhost:3000/v1/auth/oidc/authorizations",
    { method: "POST", headers, body: JSON.stringify(createInvitationStepUpBody(token)) },
  ), "http://api:8000");
  assert.deepEqual(await invitationStepUp.json(), { return_to: "/app", access_invitation_token: token });
  for (const body of [
    { return_to: "/app", reauthenticate: false },
    { return_to: "/app", reauthenticate: true, access_invitation_token: token },
    { return_to: "/app", reauthenticate: true, role: "ORG_ADMIN" },
  ]) await assert.rejects(
    () => createAuthProxyRequest(new Request(
      "http://localhost:3000/v1/auth/oidc/authorizations",
      { method: "POST", headers, body: JSON.stringify(body) },
    ), "http://api:8000"),
    /INVALID_OIDC_AUTHORIZATION_REQUEST/,
  );
});

test("anonymous invitation enrollment strips a stale Session but forwards the fresh OIDC binding cookie", async () => {
  const oidcCookie = `__Host-ds_oidc=${"o".repeat(43)}; Secure; HttpOnly; SameSite=Lax; Path=/v1/auth/oidc/callback`;
  const response = await proxyAuthRequest(new Request(
    "http://localhost:3000/v1/auth/oidc/authorizations",
    {
      method: "POST",
      headers: {
        cookie: "__Host-ds_session=stale-browser-session",
        "content-type": "application/json",
      },
      body: JSON.stringify(createInvitationStepUpBody(token)),
    },
  ), {
    baseUrl: "http://api:8000",
    fetchImpl: async (request) => {
      assert.equal(request.headers.get("cookie"), null);
      assert.equal(request.headers.get("x-csrf-token"), null);
      return Response.json(
        {
          auth_transaction_id: "auth_transaction_0000000000000001",
          authorization_url: "https://identity.example.test/authorize?closed",
          expires_at: "2026-08-30T08:10:00Z",
        },
        { status: 201, headers: { "set-cookie": oidcCookie } },
      );
    },
  });
  assert.equal(response.status, 201);
  assert.equal(response.headers.get("set-cookie"), oidcCookie);
});

test("invitation acceptance affirms the complete immutable policy set and optional consent only", () => {
  const intent = createAcceptOrganizationInvitationIntent({
    invitation,
    bundle,
    affirmedDocumentIds: [bundle.documents[0].document_id],
    grantedConsentOfferIds: [],
    csrfToken: csrf,
    idempotencyKey: idempotency,
  });
  assert.equal(intent.path, `/v1/access-invitations/${invitationId}/accept`);
  assert.equal(intent.headers["if-match"], '"v1"');
  assert.deepEqual(intent.body, {
    policy_bundle_id: bundle.policy_bundle_id,
    policy_acceptances: [{
      document_id: bundle.documents[0].document_id,
      content_sha256: bundle.documents[0].content_sha256,
      affirmed: true,
    }],
    consent_grants: [],
  });
  const pendingAcceptance = {
    version: 1,
    saved_at: "2026-08-16T08:00:00Z",
    invitation_id: invitationId,
    intent,
  };
  assert.deepEqual(
    parsePendingInvitationAcceptance(serializePendingInvitationAcceptance(pendingAcceptance), Date.parse(pendingAcceptance.saved_at)),
    pendingAcceptance,
  );
  assert.throws(
    () => serializePendingInvitationAcceptance({ ...pendingAcceptance, access_invitation_token: token }),
    /INVALID_APP_CONTRACT/,
  );
  assert.throws(
    () => createAcceptOrganizationInvitationIntent({
      invitation,
      bundle,
      affirmedDocumentIds: [],
      grantedConsentOfferIds: [],
      csrfToken: csrf,
      idempotencyKey: idempotency,
    }),
    /POLICY_AFFIRMATION_REQUIRED/,
  );
  const accepted = { invitation: { ...invitation, status: "ACCEPTED", aggregate_version: 2, entity_tag: '"v2"' }, me, activated_scope: "ORGANIZATION_MEMBERSHIP" };
  assert.deepEqual(parseAccessInvitationAcceptance(accepted), accepted);
});

test("IAM BFF admits only the exact org-admin and invitation routes", async () => {
  const common = {
    cookie: "__Host-ds_session=opaque",
    "content-type": "application/json",
    "if-match": '"v4"',
    "idempotency-key": idempotency,
    "x-csrf-token": csrf,
  };
  const issue = await createIamProxyRequest(new Request(
    `http://localhost:3000/v1/organizations/${organizationId}/access-invitations`,
    {
      method: "POST",
      headers: common,
      body: JSON.stringify({
        recipient: { type: "EMAIL", value: "sandbox-creator-01@example.test" },
        target_role: "DEMAND_OWNER",
        expires_at: "2026-08-30T08:00:00Z",
      }),
    },
  ), "http://api:8000");
  assert.equal(issue.url, `http://api:8000/v1/organizations/${organizationId}/access-invitations`);
  assert.equal(issue.headers.get("x-role"), null);
  assert.equal(issue.headers.get("cookie"), "__Host-ds_session=opaque");

  const updatePublicName = await createIamProxyRequest(new Request(
    `http://localhost:3000/v1/organizations/${organizationId}/public-name`,
    {
      method: "POST",
      headers: common,
      body: JSON.stringify({
        public_name: "😀".repeat(160),
        reason_code: "PUBLIC_NAME_CORRECTION",
      }),
    },
  ), "http://api:8000");
  assert.equal(updatePublicName.url, `http://api:8000/v1/organizations/${organizationId}/public-name`);
  assert.deepEqual(await updatePublicName.json(), {
    public_name: "😀".repeat(160),
    reason_code: "PUBLIC_NAME_CORRECTION",
  });
  assert.equal(updatePublicName.headers.get("if-match"), '"v4"');
  assert.equal(updatePublicName.headers.get("x-role"), null);

  const list = await createIamProxyRequest(new Request(
    `http://localhost:3000/v1/organizations/${organizationId}/memberships?limit=100&cursor=${cursor}`,
    { headers: { cookie: "__Host-ds_session=opaque" } },
  ), "http://api:8000");
  assert.equal(list.url, `http://api:8000/v1/organizations/${organizationId}/memberships?limit=100&cursor=${cursor}`);

  const inspect = await createIamProxyRequest(new Request(
    "http://localhost:3000/v1/access-invitations/inspect",
    {
      method: "POST",
      headers: { "content-type": "application/json", cookie: "__Host-ds_session=must-not-pass" },
      body: JSON.stringify({ access_invitation_token: token }),
    },
  ), "http://api:8000");
  assert.equal(inspect.headers.get("cookie"), null);
  assert.deepEqual(await inspect.json(), { access_invitation_token: token });

  for (const request of [
    new Request(`http://localhost:3000/v1/organizations/${organizationId}/memberships?role=ORG_ADMIN`),
    new Request(`http://localhost:3000/v1/organizations/${organizationId}/memberships?cursor=${"c".repeat(64)}.${"s".repeat(42)}`),
    new Request(`http://localhost:3000/v1/organizations/${organizationId}/memberships?cursor=${"c".repeat(64)}.${"s".repeat(20)}.${"x".repeat(23)}`),
    new Request(`http://localhost:3000/v1/organizations/${organizationId}/memberships`, { headers: { "x-workspace-id": `org:${organizationId}` } }),
    new Request(`http://localhost:3000/v1/organizations/${organizationId}/access-invitations`, { headers: { "x-role": "ORG_ADMIN" } }),
    new Request(`http://localhost:3000/v1/memberships/${membershipId}/grant`, { method: "POST", headers: common, body: "{}" }),
    new Request(`http://localhost:3000/v1/access-invitations/${invitationId}/accept?token=${token}`, { method: "POST", headers: common, body: "{}" }),
    new Request(`http://localhost:3000/v1/organizations/${organizationId}/public-name`),
    new Request(`http://localhost:3000/v1/organizations/${organizationId}/public-name?reason=correction`, { method: "POST", headers: common, body: JSON.stringify({ public_name: "更正后的组织", reason_code: "PUBLIC_NAME_CORRECTION" }) }),
    new Request(`http://localhost:3000/v1/organizations/${organizationId}/public-name`, { method: "POST", headers: { ...common, "x-role": "ORG_ADMIN" }, body: JSON.stringify({ public_name: "更正后的组织", reason_code: "PUBLIC_NAME_CORRECTION" }) }),
  ]) await assert.rejects(
    () => createIamProxyRequest(request, "http://api:8000"),
    /IAM_ROUTE_NOT_ALLOWED|AUTHORITY_HEADER_FORBIDDEN|INVALID_IAM_REQUEST/,
  );

  for (const body of [
    { public_name: "更正后的组织" },
    { public_name: "更正后的组织", reason_code: "ACCESS_REVIEW" },
    { public_name: "更正后的组织", reason_code: "PUBLIC_NAME_CORRECTION", actor_id: userId },
  ]) await assert.rejects(
    () => createIamProxyRequest(new Request(
      `http://localhost:3000/v1/organizations/${organizationId}/public-name`,
      { method: "POST", headers: common, body: JSON.stringify(body) },
    ), "http://api:8000"),
    /INVALID_IAM_REQUEST/,
  );
});

test("public-name intent and IAM BFF enforce the same trim, NFC, code-point, Cc, and Cf boundary", async () => {
  const common = {
    cookie: "__Host-ds_session=opaque",
    "content-type": "application/json",
    "if-match": '"v4"',
    "idempotency-key": idempotency,
    "x-csrf-token": csrf,
  };
  for (const publicName of ["更正后的组织", "Équipe synthétique", "😀".repeat(160)]) {
    assert.doesNotThrow(() => createUpdateOrganizationPublicNameIntent({
      organization,
      publicName,
      csrfToken: csrf,
      idempotencyKey: idempotency,
    }));
    await assert.doesNotReject(() => createIamProxyRequest(new Request(
      `http://localhost:3000/v1/organizations/${organizationId}/public-name`,
      {
        method: "POST",
        headers: common,
        body: JSON.stringify({ public_name: publicName, reason_code: "PUBLIC_NAME_CORRECTION" }),
      },
    ), "http://api:8000"));
  }
  for (const publicName of invalidPublicNames) {
    assert.throws(
      () => createUpdateOrganizationPublicNameIntent({
        organization,
        publicName,
        csrfToken: csrf,
        idempotencyKey: idempotency,
      }),
      /INVALID_ORGANIZATION_PUBLIC_NAME/,
    );
    await assert.rejects(
      () => createIamProxyRequest(new Request(
        `http://localhost:3000/v1/organizations/${organizationId}/public-name`,
        {
          method: "POST",
          headers: common,
          body: JSON.stringify({ public_name: publicName, reason_code: "PUBLIC_NAME_CORRECTION" }),
        },
      ), "http://api:8000"),
      /INVALID_IAM_REQUEST/,
    );
  }
});

test("invitation acceptance forwards only one exact fresh Session cookie", async () => {
  const url = `http://localhost:3000/v1/access-invitations/${invitationId}/accept`;
  const request = () => new Request(url, {
    method: "POST",
    headers: {
      cookie: `__Host-ds_session=${"s".repeat(32)}`,
      "content-type": "application/json",
      "if-match": '"v1"',
      "idempotency-key": idempotency,
      "x-csrf-token": csrf,
    },
    body: JSON.stringify({
      policy_bundle_id: bundle.policy_bundle_id,
      policy_acceptances: [{
        document_id: bundle.documents[0].document_id,
        content_sha256: bundle.documents[0].content_sha256,
        affirmed: true,
      }],
      consent_grants: [],
    }),
  });
  const sessionCookie = `__Host-ds_session=${"n".repeat(43)}; Secure; HttpOnly; SameSite=Lax; Path=/`;

  const fresh = await proxyIamRequest(request(), {
    baseUrl: "http://api:8000",
    fetchImpl: async () => Response.json(
      { accepted: true },
      { status: 200, headers: { "set-cookie": sessionCookie } },
    ),
  });
  assert.equal(fresh.status, 200);
  assert.equal(fresh.headers.get("set-cookie"), sessionCookie);

  const replay = await proxyIamRequest(request(), {
    baseUrl: "http://api:8000",
    fetchImpl: async () => Response.json({ accepted: true }, { status: 200 }),
  });
  assert.equal(replay.status, 200);
  assert.equal(replay.headers.get("set-cookie"), null);

  for (const malformed of [
    "__Host-ds_session=forged; Secure; HttpOnly",
    "other_session=" + "n".repeat(43) + "; Secure; HttpOnly; SameSite=Lax; Path=/",
    "__Host-ds_session=; Secure; HttpOnly; SameSite=Lax; Path=/; Max-Age=0",
    `__Host-ds_session=${"n".repeat(43)}; HttpOnly; Secure; SameSite=Lax; Path=/`,
    `${sessionCookie}; Domain=attacker.example`,
    `${sessionCookie}; Max-Age=600`,
    `${sessionCookie}; Partitioned`,
    sessionCookie.replace("SameSite=Lax", "SameSite=None"),
  ]) {
    const rejected = await proxyIamRequest(request(), {
      baseUrl: "http://api:8000",
      fetchImpl: async () => Response.json(
        { accepted: true },
        { status: 200, headers: { "set-cookie": malformed } },
      ),
    });
    assert.equal(rejected.status, 503);
    assert.equal(rejected.headers.get("set-cookie"), null);
  }

  const duplicateHeaders = new Headers({ "content-type": "application/json" });
  duplicateHeaders.append("set-cookie", sessionCookie);
  duplicateHeaders.append("set-cookie", "attacker=value; Secure; HttpOnly; SameSite=Lax; Path=/");
  const duplicate = await proxyIamRequest(request(), {
    baseUrl: "http://api:8000",
    fetchImpl: async () => new Response("{}", { status: 200, headers: duplicateHeaders }),
  });
  assert.equal(duplicate.status, 503);
  assert.equal(duplicate.headers.get("set-cookie"), null);

  const duplicateValidHeaders = new Headers({ "content-type": "application/json" });
  duplicateValidHeaders.append("set-cookie", sessionCookie);
  duplicateValidHeaders.append(
    "set-cookie",
    `__Host-ds_session=${"m".repeat(43)}; Secure; HttpOnly; SameSite=Lax; Path=/`,
  );
  const duplicateValid = await proxyIamRequest(request(), {
    baseUrl: "http://api:8000",
    fetchImpl: async () => new Response("{}", { status: 200, headers: duplicateValidHeaders }),
  });
  assert.equal(duplicateValid.status, 503);
  assert.equal(duplicateValid.headers.get("set-cookie"), null);
});

test("invitation acceptance errors and non-accept routes cannot mutate the Session cookie", async () => {
  const sessionCookie = `__Host-ds_session=${"n".repeat(43)}; Secure; HttpOnly; SameSite=Lax; Path=/`;
  const common = {
    cookie: `__Host-ds_session=${"s".repeat(32)}`,
    "content-type": "application/json",
    "if-match": '"v1"',
    "idempotency-key": idempotency,
    "x-csrf-token": csrf,
  };
  const body = JSON.stringify({
    policy_bundle_id: bundle.policy_bundle_id,
    policy_acceptances: [{
      document_id: bundle.documents[0].document_id,
      content_sha256: bundle.documents[0].content_sha256,
      affirmed: true,
    }],
    consent_grants: [],
  });
  for (const status of [201, 400, 401, 403, 404, 409, 412, 422, 429, 503]) {
    const response = await proxyIamRequest(new Request(
      `http://localhost:3000/v1/access-invitations/${invitationId}/accept`,
      { method: "POST", headers: common, body },
    ), {
      baseUrl: "http://api:8000",
      fetchImpl: async () => Response.json(
        { code: "UPSTREAM_RESULT" },
        { status, headers: { "set-cookie": sessionCookie } },
      ),
    });
    assert.equal(response.status, status);
    assert.equal(response.headers.get("set-cookie"), null);
  }

  const noContent = await proxyIamRequest(new Request(
    `http://localhost:3000/v1/access-invitations/${invitationId}/accept`,
    { method: "POST", headers: common, body },
  ), {
    baseUrl: "http://api:8000",
    fetchImpl: async () => new Response(null, {
      status: 204,
      headers: { "set-cookie": sessionCookie },
    }),
  });
  assert.equal(noContent.status, 204);
  assert.equal(noContent.headers.get("set-cookie"), null);

  const nonAccept = await proxyIamRequest(new Request(
    `http://localhost:3000/v1/organizations/${organizationId}`,
    { headers: { cookie: `__Host-ds_session=${"s".repeat(32)}` } },
  ), {
    baseUrl: "http://api:8000",
    fetchImpl: async () => Response.json(
      { organization_id: organizationId },
      { status: 200, headers: { "set-cookie": sessionCookie } },
    ),
  });
  assert.equal(nonAccept.status, 200);
  assert.equal(nonAccept.headers.get("set-cookie"), null);
});
