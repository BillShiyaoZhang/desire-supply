import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import { planEditorConflictMerge } from "../lib/editor-conflict-merge.mjs";

import {
  ACCOUNT_ADMIN_REASON_CODES,
  DEMAND_EDITABLE_PATHS,
  FINANCE_FUNDING_ATTESTATION_CODES,
  FINANCE_FUNDING_ACTIONS,
  FINANCE_FUNDING_DISCREPANCY_REASON_CODES,
  FINANCE_FUNDING_FINDING_FIELD_CODES,
  FINANCE_FUNDING_RELEASE_REASON_CODES,
  FINANCE_FUNDING_REJECTED_REASON_CODES,
  PROFILE_EDITABLE_PATHS,
  PROFILE_ARCHIVE_REASON_CODES,
  PROFILE_PAUSE_REASON_CODES,
  REVIEW_ASSIGNMENT_RELEASE_REASON_CODES,
  VERIFY_BUDGET_HEALTH_CODES,
  VERIFY_EVIDENCE_CODES,
  VERIFY_RISK_CODES,
  createAccountAdminIntent,
  createPlatformDutyIntent,
  createDemandDraftIntent,
  createDemandIntent,
  createFindingIntent,
  createFinanceFundingClaimIntent,
  createFinanceFundingConfirmIntent,
  createFinanceFundingFindingIntent,
  createFinanceFundingReleaseIntent,
  createProfileIntent,
  createProfileDraftIntent,
  createProfileLifecycleIntent,
  createPolicyAcceptanceIntent,
  createReviewClaimIntent,
  createReviewAssignmentReleaseIntent,
  createVerifyIntent,
  bindConflictToCurrentResource,
  REVIEW_REASON_CODES,
  parseAccountAdminCollectionEnvelope,
  parseAccountAdminCommandEnvelope,
  parseAccountAdminEnvelope,
  parseEditorCollection,
  parseEditorConfigurationEnvelope,
  parseEditorReviewClaimEnvelope,
  parseEditorReviewQueueEnvelope,
  parseFinanceFundingQueueEnvelope,
  parseFinanceFundingReviewEnvelope,
  parseMe,
  parsePolicyBundle,
  parsePolicyRequirementStatus,
  parsePendingIntent,
  parseSessionBootstrap,
  parseThreeWayConflict,
  parseWorkspaceDiscovery,
  sectionsFromContent,
  sectionsToContent,
  selectWorkspaceCandidate,
  serializePendingIntent,
  verifyPolicyBundleDocuments,
} from "../lib/app-contract.mjs";
import {
  arrayItemTemplate,
  editorChoiceSourceLabel,
  fieldInputMeta,
  normalizeEditorChoicePath,
  optionalValueTemplate,
  parseStructuredSection,
  resolveEditorChoice,
  serializeStructuredSection,
  structuredContentIssues,
  structuredSectionIssues,
} from "../lib/editor-fields.mjs";

const creatorWorkspace = {
  workspace_id: "personal:10000000-0000-4000-8000-000000000001",
  workspace_kind: "PERSONAL",
  role_codes: ["CREATOR"],
};

const reviewerWorkspace = {
  workspace_id: "platform:10000000-0000-4000-8000-000000000001",
  workspace_kind: "PLATFORM",
  role_codes: ["OPERATIONS_REVIEWER"],
};

const reviewDemandId = "30000000-0000-4000-8000-000000000025";
const reviewAssignmentId = "40000000-0000-4000-8000-000000000025";
const reviewQueueItem = {
  demand_id: reviewDemandId,
  demand_revision: 2,
  demand_version_no: 1,
  submitted_at: "2026-08-15T07:55:00+00:00",
  demand_expires_at: "2026-09-14T08:00:00+00:00",
  etag: '"demand-2-review-queue"',
};
const reviewClaim = {
  assignment_id: reviewAssignmentId,
  demand_id: reviewDemandId,
  demand_revision: 2,
  status: "ACTIVE",
  expires_at: "2026-08-15T08:30:00+00:00",
  etag: '"demand-2-review-queue"',
  replayed: false,
};

const financeDemandId = "70000000-0000-4000-8000-000000000001";
const financeVersionId = "71000000-0000-4000-8000-000000000001";
const financeReviewId = "72000000-0000-4000-8000-000000000001";
const financeAssignmentId = "73000000-0000-4000-8000-000000000001";
const financeQueueItem = {
  demand_id: financeDemandId,
  demand_version_id: financeVersionId,
  demand_revision: 3,
  funding_review_id: null,
  review_status: "AVAILABLE",
  review_revision: null,
  assigned_to_me: false,
  confirmation_count: 0,
  required_confirmations: 2,
  expires_at: "2026-08-22T12:00:00+00:00",
  etag: '"demand-3-finance-queue"',
};
const financeReview = {
  funding_review_id: financeReviewId,
  demand_id: financeDemandId,
  demand_version_id: financeVersionId,
  status: "PENDING",
  revision: 1,
  assignment_id: financeAssignmentId,
  assignment_expires_at: "2026-08-15T12:30:00+00:00",
  target_sha256: "c".repeat(64),
  target_content_sha256: "e".repeat(64),
  planned_budget_currency: "CNY",
  planned_budget_minimum_amount_minor: 100000,
  planned_budget_maximum_amount_minor: 200000,
  planned_budget_direct_cost_amount_minor: 20000,
  evidence_kind: "INTERNAL_SANDBOX_ZERO_FUNDS_V1",
  evidence_reference_sha256: "d".repeat(64),
  sandbox_funds_amount_minor: 0,
  provider_code: "NONE",
  payment_operation_code: "NONE",
  synthetic: true,
  legal_effect: "NO_REAL_FUNDS_OR_PAYMENT",
  confirmation_count: 0,
  required_confirmations: 2,
  assignment_status: "ACTIVE",
  confirmation_by_me: false,
  available_actions: [...FINANCE_FUNDING_ACTIONS],
  can_confirm: true,
  etag: '"funding-review-1"',
  replayed: false,
};

const version = {
  version_id: "version_internal_00000001",
  version_no: 1,
  based_on_version_id: null,
  status: "DRAFT",
  content: { interests: [], skills: [] },
  content_sha256: "a".repeat(64),
  taxonomy_bundle_id: "taxonomy_internal_00001",
  created_at: "2026-08-12T08:00:00+00:00",
};

const profile = {
  resource_type: "CREATOR_PROFILE",
  object_id: "profile_internal_000001",
  status: "DRAFT",
  revision: 2,
  etag: '"creator_profile-2-aaaaaaaaaaaaaaaaaaaaaaaa"',
  capabilities: ["SAVE_DRAFT", "PUBLISH", "ARCHIVE"],
  editable_paths: [...PROFILE_EDITABLE_PATHS],
  current_version: version,
  versions: [version],
  submissions: [],
  findings: [],
  review_assignment: null,
};

const taxonomyChoices = {
  DOMAIN: { value: "DOMAIN.SOFTWARE", label: "软件", source: "TAXONOMY_BUNDLE_NODE" },
  PROBLEM_TYPE: { value: "PROBLEM.OPERATIONS", label: "运营改进", source: "TAXONOMY_BUNDLE_NODE" },
  TASK: { value: "TASK.ANALYSIS", label: "分析", source: "TAXONOMY_BUNDLE_NODE" },
  SKILL: { value: "SKILL.SYSTEMS_ANALYSIS", label: "系统分析", source: "TAXONOMY_BUNDLE_NODE" },
};
const nodeChoiceField = (resource_type, path_template, intended_node_kind) => ({
  resource_type,
  path_template,
  value_contract: "TAXONOMY_CODE",
  intended_node_kind,
  status: "AVAILABLE",
  reason_code: null,
  options: [taxonomyChoices[intended_node_kind]],
});
const fixedChoiceField = (resource_type, path_template, value_contract, value, label, source, intended_node_kind = null) => ({
  resource_type,
  path_template,
  value_contract,
  intended_node_kind,
  status: "AVAILABLE",
  reason_code: null,
  options: [{ value, label, source }],
});
const unavailableChoiceField = (resource_type, path_template) => ({
  resource_type,
  path_template,
  value_contract: "TAXONOMY_CODE",
  intended_node_kind: null,
  status: "UNAVAILABLE",
  reason_code: "NO_REVIEWED_CHOICE_SET",
  options: [],
});
const editorChoiceFields = [
  unavailableChoiceField("CREATOR_PROFILE", "/ai/prohibited_case_codes/*"),
  nodeChoiceField("CREATOR_PROFILE", "/boundaries/prohibited_domains/*/code", "DOMAIN"),
  nodeChoiceField("CREATOR_PROFILE", "/boundaries/prohibited_tasks/*/code", "TASK"),
  fixedChoiceField("CREATOR_PROFILE", "/collaboration/languages/*/language_code", "LANGUAGE_TAG", "zh-CN", "中文（简体）", "INTERNAL_SANDBOX_PRESET"),
  fixedChoiceField("CREATOR_PROFILE", "/compensation/currency", "CURRENCY_CODE", "CNY", "人民币", "INTERNAL_SANDBOX_POLICY"),
  nodeChoiceField("CREATOR_PROFILE", "/interests/*/domain_code", "DOMAIN"),
  nodeChoiceField("CREATOR_PROFILE", "/interests/*/problem_code", "PROBLEM_TYPE"),
  nodeChoiceField("CREATOR_PROFILE", "/interests/*/task_code", "TASK"),
  fixedChoiceField("CREATOR_PROFILE", "/location/region_code", "REGION_CODE", "CN", "中国", "INTERNAL_SANDBOX_PRESET"),
  nodeChoiceField("CREATOR_PROFILE", "/skills/*/skill_code", "SKILL"),
  fixedChoiceField("DEMAND", "/budget/currency", "CURRENCY_CODE", "CNY", "人民币", "INTERNAL_SANDBOX_POLICY"),
  fixedChoiceField("DEMAND", "/collaboration/languages/*", "LANGUAGE_TAG", "zh-CN", "中文（简体）", "INTERNAL_SANDBOX_PRESET"),
  fixedChoiceField("DEMAND", "/location/allowed_creator_region_codes/*", "REGION_CODE", "CN", "中国", "INTERNAL_SANDBOX_PRESET"),
  fixedChoiceField("DEMAND", "/location/demand_region_code", "REGION_CODE", "CN", "中国", "INTERNAL_SANDBOX_PRESET"),
  nodeChoiceField("DEMAND", "/matching/domain_codes/*", "DOMAIN"),
  nodeChoiceField("DEMAND", "/matching/problem_codes/*", "PROBLEM_TYPE"),
  nodeChoiceField("DEMAND", "/matching/task_codes/*", "TASK"),
  nodeChoiceField("DEMAND", "/problem/domain_code", "DOMAIN"),
  nodeChoiceField("DEMAND", "/problem/problem_type_codes/*", "PROBLEM_TYPE"),
  fixedChoiceField("DEMAND", "/problem/target_user_category_codes/*", "TAXONOMY_CODE", "SYNTHETIC_USER", "合成用户", "INTERNAL_SANDBOX_POLICY", "TARGET_USER_CATEGORY"),
  unavailableChoiceField("DEMAND", "/risk/dependency_codes/*"),
  nodeChoiceField("DEMAND", "/skills/must_have/*/skill_code", "SKILL"),
  nodeChoiceField("DEMAND", "/skills/nice_to_have/*/skill_code", "SKILL"),
];
const editorConfigurationEnvelope = {
  data: {
    schema_version: "editor-configuration-v2",
    deployment_mode: "INTERNAL_SANDBOX",
    taxonomy_bundle: {
      bundle_id: "50000000-0000-4000-8000-000000000001",
      status: "CURRENT_APPROVED",
      effective_at: "2026-08-11T08:00:00+00:00",
      effective_until: "2026-08-20T08:00:00+00:00",
    },
    editor_choices: {
      schema_version: "editor-choices-v1",
      locale: "zh-CN",
      fields: editorChoiceFields,
    },
  },
};

const policyBody = "INTERNAL_SANDBOX synthetic policy terms. No real people, contracts, funds, or research.";
const policyDocument = {
  document_id: "policy_document_terms_0001",
  kind: "TERMS",
  semantic_version: "1.0.0",
  locale: "zh-CN",
  content_sha256: createHash("sha256").update(policyBody).digest("hex"),
  legal_effect: "CONTRACT_ACCEPTANCE",
  body: policyBody,
};
const policyRequirement = {
  selector_digest: "a".repeat(64),
  purpose: "CREATOR_ENROLLMENT",
  role: "CREATOR",
  scope_type: "USER_ROLE",
  scope_id: null,
  satisfied: false,
  required_policy_bundle_id: "policy_bundle_creator_0001",
  missing_document_ids: [policyDocument.document_id],
};
const policyBundle = {
  policy_bundle_id: "policy_bundle_creator_0001",
  purpose: "CREATOR_ENROLLMENT",
  jurisdiction: "INTERNAL_SANDBOX",
  locale: "zh-CN",
  documents: [policyDocument],
  consent_offers: [],
  effective_at: "2026-08-12T08:00:00Z",
  entity_tag: '"v1"',
};
const policyMe = {
  user_id: "user_internal_00000001",
  status: "ACTIVE",
  display_handle: "pilot_owner",
  user_roles: ["CREATOR"],
  memberships: [],
  policy_requirements: [policyRequirement],
  aggregate_version: 3,
  entity_tag: '"v3"',
};

test("accepts only the current server-approved editor taxonomy configuration", () => {
  assert.deepEqual(
    parseEditorConfigurationEnvelope(editorConfigurationEnvelope),
    editorConfigurationEnvelope.data,
  );
  for (const value of [
    { data: { ...editorConfigurationEnvelope.data, actor_id: "forged" } },
    { data: { ...editorConfigurationEnvelope.data, schema_version: "editor-configuration-v1" } },
    { data: { ...editorConfigurationEnvelope.data, deployment_mode: "PUBLIC" } },
    { data: { ...editorConfigurationEnvelope.data, taxonomy_bundle: { ...editorConfigurationEnvelope.data.taxonomy_bundle, status: "DRAFT" } } },
    { data: { ...editorConfigurationEnvelope.data, taxonomy_bundle: { ...editorConfigurationEnvelope.data.taxonomy_bundle, effective_at: "2026-08-21T08:00:00Z" } } },
    { data: { ...editorConfigurationEnvelope.data, taxonomy_bundle: { ...editorConfigurationEnvelope.data.taxonomy_bundle, bundle_id: "browser_default_00000001" } } },
  ]) assert.throws(() => parseEditorConfigurationEnvelope(value), /INVALID_APP_CONTRACT/);
});

test("editor choices reject missing, duplicate, unordered, or semantically invalid catalogs", () => {
  const withFields = (fields) => ({
    data: {
      ...editorConfigurationEnvelope.data,
      editor_choices: { ...editorConfigurationEnvelope.data.editor_choices, fields },
    },
  });
  const domainIndex = editorChoiceFields.findIndex((field) => (
    field.resource_type === "DEMAND" && field.path_template === "/problem/domain_code"
  ));
  const domain = editorChoiceFields[domainIndex];
  const unavailableIndex = editorChoiceFields.findIndex((field) => field.status === "UNAVAILABLE");
  const unavailable = editorChoiceFields[unavailableIndex];
  const invalidCatalogs = [
    editorChoiceFields.slice(0, -1),
    editorChoiceFields.map((field, index) => index === 1 ? editorChoiceFields[0] : field),
    [editorChoiceFields[1], editorChoiceFields[0], ...editorChoiceFields.slice(2)],
    editorChoiceFields.map((field, index) => index === domainIndex ? { ...field, status: "DRAFT" } : field),
    editorChoiceFields.map((field, index) => index === domainIndex ? { ...field, options: [] } : field),
    editorChoiceFields.map((field, index) => index === unavailableIndex ? {
      ...field,
      options: [{ value: "TASK.ANALYSIS", label: "分析", source: "TAXONOMY_BUNDLE_NODE" }],
    } : field),
    editorChoiceFields.map((field, index) => index === domainIndex ? {
      ...domain,
      options: [
        { value: "DOMAIN.Z", label: "乙", source: "TAXONOMY_BUNDLE_NODE" },
        { value: "DOMAIN.A", label: "甲", source: "TAXONOMY_BUNDLE_NODE" },
      ],
    } : field),
    editorChoiceFields.map((field, index) => index === domainIndex ? {
      ...domain,
      options: [
        { value: "DOMAIN.A", label: "甲", source: "TAXONOMY_BUNDLE_NODE" },
        { value: "DOMAIN.A", label: "甲", source: "TAXONOMY_BUNDLE_NODE" },
      ],
    } : field),
    editorChoiceFields.map((field, index) => index === domainIndex ? {
      ...domain,
      options: [{ ...domain.options[0], source: "INTERNAL_SANDBOX_PRESET" }],
    } : field),
    editorChoiceFields.map((field, index) => index === domainIndex ? {
      ...domain,
      options: [{ ...domain.options[0], label: " 软件" }],
    } : field),
  ];
  for (const fields of invalidCatalogs) {
    assert.throws(() => parseEditorConfigurationEnvelope(withFields(fields)), /INVALID_APP_CONTRACT/);
  }
  assert.equal(unavailable.reason_code, "NO_REVIEWED_CHOICE_SET");
});

test("editor choice resolution normalizes repeater indexes and validates legacy or unavailable values", () => {
  const configuration = parseEditorConfigurationEnvelope(editorConfigurationEnvelope);
  assert.equal(normalizeEditorChoicePath("/skills/must_have/12/skill_code"), "/skills/must_have/*/skill_code");
  assert.equal(
    resolveEditorChoice(configuration, "DEMAND", "/skills/must_have/12/skill_code")?.intended_node_kind,
    "SKILL",
  );
  assert.equal(editorChoiceSourceLabel("TAXONOMY_BUNDLE_NODE"), "分类节点");
  assert.equal(editorChoiceSourceLabel("INTERNAL_SANDBOX_POLICY"), "沙盒策略");
  assert.equal(editorChoiceSourceLabel("INTERNAL_SANDBOX_PRESET"), "预设");
  assert.equal(
    arrayItemTemplate("DEMAND", "/matching/domain_codes", [], configuration),
    "DOMAIN.SOFTWARE",
  );
  assert.deepEqual(
    arrayItemTemplate("DEMAND", "/skills/must_have", [], configuration),
    { skill_code: "SKILL.SYSTEMS_ANALYSIS", minimum_level_code: "WORKING" },
  );
  assert.throws(
    () => arrayItemTemplate("DEMAND", "/risk/dependency_codes", [], configuration),
    /CHOICE_UNAVAILABLE/,
  );

  const defaults = sectionsFromContent("DEMAND", {});
  const problem = JSON.parse(defaults["/problem"]);
  const skills = JSON.parse(defaults["/skills"]);
  const matching = JSON.parse(defaults["/matching"]);
  assert.equal(problem.domain_code, "DOMAIN.SOFTWARE");
  assert.deepEqual(problem.problem_type_codes, ["PROBLEM.OPERATIONS"]);
  assert.deepEqual(problem.target_user_category_codes, ["SYNTHETIC_USER"]);
  assert.equal(skills.must_have[0].skill_code, "SKILL.SYSTEMS_ANALYSIS");
  assert.deepEqual(matching, {
    problem_codes: ["PROBLEM.OPERATIONS"],
    domain_codes: ["DOMAIN.SOFTWARE"],
    task_codes: ["TASK.ANALYSIS"],
  });
  assert.equal(structuredContentIssues("DEMAND", defaults, configuration).length, 0);

  const legacy = {
    ...defaults,
    "/matching": JSON.stringify({ ...matching, domain_codes: ["GENERAL"] }),
  };
  assert.ok(structuredContentIssues("DEMAND", legacy, configuration)
    .some(({ path, code }) => path === "/matching/domain_codes/0" && code === "CHOICE_UNAVAILABLE"));
  const unavailable = {
    ...defaults,
    "/risk": JSON.stringify({ ...JSON.parse(defaults["/risk"]), dependency_codes: ["DEPENDENCY"] }),
  };
  assert.ok(structuredContentIssues("DEMAND", unavailable, configuration)
    .some(({ path, code }) => path === "/risk/dependency_codes/0" && code === "CHOICE_UNAVAILABLE"));
  const malformedLanguage = {
    ...defaults,
    "/collaboration": JSON.stringify({ ...JSON.parse(defaults["/collaboration"]), languages: ["zh_cn"] }),
  };
  assert.ok(structuredContentIssues("DEMAND", malformedLanguage, configuration)
    .some(({ path, code }) => path === "/collaboration/languages/0" && code === "INVALID_FORMAT"));

  const partialConfiguration = {
    ...configuration,
    editor_choices: { ...configuration.editor_choices, fields: configuration.editor_choices.fields.slice(1) },
  };
  assert.ok(structuredContentIssues("DEMAND", defaults, null)
    .some(({ code }) => code === "CHOICE_CATALOG_UNAVAILABLE"));
  assert.ok(structuredContentIssues("CREATOR_PROFILE", sectionsFromContent("CREATOR_PROFILE", {}), partialConfiguration)
    .some(({ path, code }) => path === "/ai/prohibited_case_codes/*" && code === "CHOICE_CATALOG_UNAVAILABLE"));
});

test("accepts only the closed editor collection and session bootstrap projections", () => {
  assert.deepEqual(parseEditorCollection({ data: [profile] }), [profile]);
  assert.deepEqual(parseSessionBootstrap({
    session: { session_id: "session_internal_00001", device_label: "Pilot browser" },
    user_status: "ACTIVE",
    csrf_token: "csrf_token_internal_000000000000001",
  }), {
    session: { session_id: "session_internal_00001", device_label: "Pilot browser" },
    user_status: "ACTIVE",
    csrf_token: "csrf_token_internal_000000000000001",
  });
  assert.throws(
    () => parseEditorCollection({ data: [{ ...profile, actor_user_id: "forged" }] }),
    /INVALID_APP_CONTRACT/,
  );
  assert.throws(() => parseSessionBootstrap({ user_status: "ACTIVE", csrf_token: "short" }), /INVALID_APP_CONTRACT/);
  assert.deepEqual(parseMe({
    user_id: "user_internal_00000001",
    status: "ACTIVE",
    display_handle: "pilot_owner",
    user_roles: ["CREATOR"],
    memberships: [{
      membership_id: "membership_internal_001",
      organization: {
        organization_id: "organization_internal_01",
        public_name: "合成需求组织",
        type: "CUSTOMER",
        status: "ACTIVE",
        aggregate_version: 1,
        entity_tag: '"v1"',
      },
      status: "ACTIVE",
      roles: ["DEMAND_OWNER"],
      aggregate_version: 1,
      entity_tag: '"v1"',
    }],
    policy_requirements: [],
    aggregate_version: 1,
    entity_tag: '"v1"',
  }).display_handle, "pilot_owner");
});

test("owner findings discriminate operations assignments from Finance-safe summaries", () => {
  const base = {
    finding_id: "finding_internal_0000001",
    version_id: "version_internal_00000001",
    reviewed_at: "2026-08-18T08:00:00+00:00",
  };
  const financeFinding = {
    ...base,
    assignment_id: null,
    result: "REJECTED",
    reason_codes: ["BUDGET_PLAN_UNACCEPTABLE"],
    required_field_paths: ["/budget"],
  };
  const demand = {
    ...profile,
    resource_type: "DEMAND",
    object_id: "demand_internal_0000001",
    status: "NEEDS_CHANGES",
    etag: '"demand-2-bbbbbbbbbbbbbbbbbbbbbbbb"',
    capabilities: ["SAVE_DRAFT", "SUBMIT"],
    editable_paths: [...DEMAND_EDITABLE_PATHS],
    findings: [financeFinding],
  };
  assert.deepEqual(parseEditorCollection({ data: [demand] })[0].findings, [financeFinding]);
  for (const finding of [
    { ...financeFinding, assignment_id: "assignment_internal_0001" },
    { ...financeFinding, reason_codes: ["SCOPE_UNCLEAR"] },
    { ...financeFinding, required_field_paths: ["BUDGET"] },
    { ...financeFinding, result: "NEEDS_CHANGES", assignment_id: null, reason_codes: ["SCOPE_UNCLEAR"], required_field_paths: ["/scope"] },
    { ...financeFinding, result: "VERIFIED", assignment_id: "assignment_internal_0001" },
  ]) assert.throws(
    () => parseEditorCollection({ data: [{ ...demand, findings: [finding] }] }),
    /INVALID_APP_CONTRACT/,
  );
});

test("first-login policy projections are closed, digest-bound, and authority-free", async () => {
  assert.deepEqual(parseMe(policyMe).policy_requirements, [policyRequirement]);
  assert.deepEqual(parsePolicyBundle(policyBundle), policyBundle);
  assert.equal(await verifyPolicyBundleDocuments(policyBundle), policyBundle);

  const intent = createPolicyAcceptanceIntent({
    me: policyMe,
    requirement: policyRequirement,
    bundle: policyBundle,
    affirmedDocumentIds: [policyDocument.document_id],
    csrfToken: "csrf_token_internal_000000000000001",
    idempotencyKey: "policy-acceptance-idempotency-0001",
  });
  assert.deepEqual(intent, {
    method: "POST",
    path: "/v1/me/policy-acceptances",
    headers: {
      "content-type": "application/json",
      "idempotency-key": "policy-acceptance-idempotency-0001",
      "if-match": '"v3"',
      "x-csrf-token": "csrf_token_internal_000000000000001",
    },
    body: {
      policy_requirement: {
        selector_digest: "a".repeat(64),
        scope_type: "USER_ROLE",
        scope_id: null,
      },
      policy_bundle_id: "policy_bundle_creator_0001",
      policy_acceptances: [{
        document_id: policyDocument.document_id,
        content_sha256: policyDocument.content_sha256,
        affirmed: true,
      }],
    },
  });
  assert.doesNotMatch(JSON.stringify(intent), /actor|organization|role|purpose/);

  assert.throws(() => createPolicyAcceptanceIntent({
    me: policyMe,
    requirement: policyRequirement,
    bundle: policyBundle,
    affirmedDocumentIds: [],
    csrfToken: "csrf_token_internal_000000000000001",
    idempotencyKey: "policy-acceptance-idempotency-0002",
  }), /POLICY_AFFIRMATION_REQUIRED/);
  assert.throws(() => parseMe({
    ...policyMe,
    policy_requirements: [{ ...policyRequirement, actor_id: "forged" }],
  }), /INVALID_APP_CONTRACT/);
  assert.throws(() => createPolicyAcceptanceIntent({
    me: policyMe,
    requirement: { ...policyRequirement, role: "DEMAND_OWNER" },
    bundle: policyBundle,
    affirmedDocumentIds: [policyDocument.document_id],
    csrfToken: "csrf_token_internal_000000000000001",
    idempotencyKey: "policy-acceptance-idempotency-0003",
  }), /INVALID_APP_CONTRACT/);
  await assert.rejects(() => verifyPolicyBundleDocuments({
    ...policyBundle,
    documents: [{ ...policyDocument, body: `${policyBody} tampered` }],
  }), /POLICY_DOCUMENT_DIGEST_MISMATCH/);
});

test("accepted policy response must satisfy the exact selected requirement", () => {
  const accepted = {
    ...policyRequirement,
    satisfied: true,
    missing_document_ids: [],
  };
  assert.deepEqual(
    parsePolicyRequirementStatus(accepted, policyRequirement),
    accepted,
  );
  for (const response of [
    { ...accepted, selector_digest: "b".repeat(64) },
    { ...accepted, scope_id: "organization_forged_0001" },
    { ...accepted, satisfied: false, missing_document_ids: [policyDocument.document_id] },
    { ...accepted, role: "DEMAND_OWNER" },
  ]) assert.throws(
    () => parsePolicyRequirementStatus(response, policyRequirement),
    /INVALID_APP_CONTRACT/,
  );
});

test("workspace discovery accepts only closed effective-role candidates", () => {
  const discovery = {
    data: {
      workspaces: [creatorWorkspace, reviewerWorkspace],
      selection_required: true,
    },
  };
  assert.deepEqual(parseWorkspaceDiscovery(discovery), discovery.data);

  for (const value of [
    { data: { workspaces: [creatorWorkspace], selection_required: true } },
    { data: { workspaces: [{ ...creatorWorkspace, workspace_kind: "PLATFORM" }], selection_required: false } },
    { data: { workspaces: [{ ...creatorWorkspace, role_codes: ["CREATOR", "CREATOR"] }], selection_required: false } },
    { data: { workspaces: [{ ...creatorWorkspace, role_codes: ["DEMAND_OWNER"] }], selection_required: false } },
    { data: { workspaces: [{ ...creatorWorkspace, role_codes: ["SYSTEM"] }], selection_required: false } },
    { data: { workspaces: [{ workspace_id: "org:10000000-0000-4000-8000-000000000001", workspace_kind: "ORGANIZATION", role_codes: ["ORG_ADMIN", "DEMAND_OWNER"] }], selection_required: false } },
    { data: { workspaces: [{ ...creatorWorkspace, workspace_id: "personal:00000000-0000-0000-0000-000000000000" }], selection_required: false } },
    { data: { workspaces: [{ ...creatorWorkspace, actor_user_id: "forged" }], selection_required: false } },
    { data: { workspaces: [creatorWorkspace, creatorWorkspace], selection_required: true } },
    { data: { workspaces: [reviewerWorkspace, creatorWorkspace], selection_required: true } },
    { data: { workspaces: [], selection_required: true } },
    { data: { workspaces: [], selection_required: false, role_codes: ["CREATOR"] } },
  ]) assert.throws(() => parseWorkspaceDiscovery(value), /INVALID_APP_CONTRACT/);

  assert.deepEqual(parseWorkspaceDiscovery({
    data: { workspaces: [], selection_required: false },
  }), { workspaces: [], selection_required: false });
});

test("workspace selection auto-selects one candidate and requires an explicit known choice for many", () => {
  const single = { workspaces: [creatorWorkspace], selection_required: false };
  const multiple = { workspaces: [creatorWorkspace, reviewerWorkspace], selection_required: true };
  assert.equal(selectWorkspaceCandidate(single, null), creatorWorkspace);
  assert.equal(selectWorkspaceCandidate(single, "stale"), creatorWorkspace);
  assert.equal(selectWorkspaceCandidate(multiple, null), null);
  assert.equal(selectWorkspaceCandidate(multiple, "stale"), null);
  assert.equal(selectWorkspaceCandidate(multiple, reviewerWorkspace.workspace_id), reviewerWorkspace);
});

test("section JSON becomes a closed 9/13-section content object", () => {
  const profileSections = Object.fromEntries(PROFILE_EDITABLE_PATHS.map((path) => [path, path === "/availability" ? "null" : "[]"]));
  profileSections["/collaboration"] = "{}";
  profileSections["/compensation"] = "null";
  profileSections["/boundaries"] = "null";
  profileSections["/location"] = "null";
  profileSections["/ai"] = "null";
  assert.deepEqual(Object.keys(sectionsToContent("CREATOR_PROFILE", profileSections)), PROFILE_EDITABLE_PATHS.map((path) => path.slice(1)));

  const demandSections = Object.fromEntries(DEMAND_EDITABLE_PATHS.map((path) => [path, "{}"]));
  assert.equal(Object.keys(sectionsToContent("DEMAND", demandSections)).length, 13);
  assert.throws(() => sectionsToContent("DEMAND", { ...demandSections, "/actor": "{}" }), /UNKNOWN_EDITOR_SECTION/);
  assert.throws(() => sectionsToContent("DEMAND", { ...demandSections, "/problem": "{" }), /INVALID_SECTION_JSON/);
});

test("role editors expose typed fields, repeaters, optional facts, and client-side domain checks", () => {
  assert.deepEqual(REVIEW_REASON_CODES, [
    "CONTENT_INCOMPLETE", "SCOPE_UNCLEAR", "ACCEPTANCE_UNCLEAR",
    "BUDGET_UNHEALTHY", "RISK_UNRESOLVED", "DATA_PLAN_REQUIRED",
  ]);
  const profileSections = Object.fromEntries(PROFILE_EDITABLE_PATHS.map((path) => [path, path === "/availability" ? "null" : "[]"]));
  profileSections["/collaboration"] = "{}";
  profileSections["/compensation"] = "null";
  profileSections["/boundaries"] = "null";
  profileSections["/location"] = "null";
  profileSections["/ai"] = "null";
  assert.deepEqual(fieldInputMeta("start_date", "/schedule/start_date").type, "date");
  assert.deepEqual(fieldInputMeta("uncertainty_code", "/risk/uncertainty_code").options.map(({ value }) => value), ["LOW", "MEDIUM", "HIGH"]);
  assert.deepEqual(arrayItemTemplate("DEMAND", "/scope/deliverables", 2), {
    item_id: "deliverable_3",
    description: "",
  });
  assert.deepEqual(arrayItemTemplate("DEMAND", "/scope/deliverables", [
    { item_id: "deliverable_2", description: "保留" },
  ]), { item_id: "deliverable_3", description: "" });
  assert.equal(fieldInputMeta("item_id", "/scope/deliverables/0/item_id").readOnly, true);
  assert.deepEqual(arrayItemTemplate("CREATOR_PROFILE", "/skills", 0), {
    skill_code: "",
    proficiency: 2,
    visibility: "MATCH_ONLY",
    source_kind: "SELF_ASSERTED",
    evidence_ids: [],
  });
  assert.equal(optionalValueTemplate("CREATOR_PROFILE", "/availability").timezone, "Asia/Shanghai");
  assert.throws(() => optionalValueTemplate("DEMAND", "/location"), /UNSUPPORTED_OPTIONAL_FIELD/);
  assert.deepEqual(parseStructuredSection("DEMAND", "/budget", serializeStructuredSection({
    minimum_amount_minor: 0,
    maximum_amount_minor: 0,
    direct_cost_amount_minor: 0,
    currency: "CNY",
  })), {
    minimum_amount_minor: 0,
    maximum_amount_minor: 0,
    direct_cost_amount_minor: 0,
    currency: "CNY",
  });
  assert.deepEqual(structuredSectionIssues("DEMAND", "/schedule", JSON.stringify({
    start_date: "2026-09-02",
    due_date: "2026-09-01",
    estimated_days: 2,
    weekly_hours: 20,
    duration_weeks: 1,
  })), [{ path: "/schedule/due_date", code: "DUE_BEFORE_START" }]);
  assert.deepEqual(structuredSectionIssues("DEMAND", "/milestone_plan", JSON.stringify({
    items: [{ item_id: "m1", label: "一", percent: 40 }, { item_id: "m2", label: "二", percent: 50 }],
  })), [{ path: "/milestone_plan/items", code: "PERCENT_TOTAL_MUST_BE_100" }]);
  assert.ok(structuredContentIssues("CREATOR_PROFILE", { ...profileSections, "/skills": "not-json" })
    .some(({ path, code }) => path === "/skills" && code === "INVALID_SECTION_JSON"));
  const demandSections = Object.fromEntries(DEMAND_EDITABLE_PATHS.map((path) => [path, JSON.stringify({})]));
  demandSections["/problem"] = JSON.stringify({ domain_code: "DESIGN" });
  demandSections["/matching"] = JSON.stringify({ domain_codes: ["GENERAL"] });
  demandSections["/skills"] = JSON.stringify({
    must_have: [{ skill_code: "VISUAL_DESIGN" }],
    nice_to_have: [{ skill_code: "VISUAL_DESIGN" }],
  });
  const crossIssues = structuredContentIssues("DEMAND", demandSections);
  assert.ok(crossIssues.some(({ code }) => code === "PROBLEM_DOMAIN_NOT_MATCHED"));
  assert.ok(crossIssues.some(({ code }) => code === "SKILL_IN_BOTH_LISTS"));
});

test("review findings use the authoritative assignment and closed reason codes", () => {
  const demand = {
    ...profile,
    resource_type: "DEMAND",
    object_id: "demand_internal_0000001",
    etag: '"demand-2-aaaaaaaaaaaaaaaaaaaaaaaa"',
    capabilities: ["RECORD_FINDINGS"],
    editable_paths: [],
    review_assignment: {
      assignment_id: "assignment_internal_0001",
      status: "ACTIVE",
      expires_at: "2026-08-20T08:00:00+00:00",
    },
  };
  assert.equal(parseEditorCollection({ data: [demand] })[0].review_assignment.assignment_id, "assignment_internal_0001");
  assert.throws(() => createFindingIntent({
    resource: demand,
    assignmentId: demand.review_assignment.assignment_id,
    csrfToken: "csrf_token_internal_000000000000001",
    idempotencyKey: "review-finding-idempotency-01",
    reasonCodes: ["MISSING_EVIDENCE"],
    requiredFieldPaths: ["/scope/deliverables"],
  }), /INVALID_APP_CONTRACT/);
});

test("review queue and claim projections are minimal, closed, and revision-bound", () => {
  assert.deepEqual(
    parseEditorReviewQueueEnvelope({ data: [reviewQueueItem] }),
    [reviewQueueItem],
  );
  assert.deepEqual(
    parseEditorReviewClaimEnvelope({ data: reviewClaim }),
    reviewClaim,
  );
  assert.equal(
    parseEditorReviewClaimEnvelope({ data: { ...reviewClaim, replayed: true } }).replayed,
    true,
  );

  for (const value of [
    { data: [{ ...reviewQueueItem, organization_id: "forged" }] },
    { data: [{ ...reviewQueueItem, demand_id: "demand_internal_0000001" }] },
    { data: [{ ...reviewQueueItem, etag: '"demand-3-review-queue"' }] },
    { data: [{ ...reviewQueueItem, submitted_at: reviewQueueItem.demand_expires_at }] },
    { data: [reviewQueueItem, { ...reviewQueueItem }] },
  ]) assert.throws(() => parseEditorReviewQueueEnvelope(value), /INVALID_APP_CONTRACT/);

  for (const value of [
    { data: { ...reviewClaim, actor_user_id: "forged" } },
    { data: { ...reviewClaim, assignment_id: "assignment_internal_0001" } },
    { data: { ...reviewClaim, status: "COMPLETED" } },
    { data: { ...reviewClaim, etag: '"demand-3-review-queue"' } },
    { data: { ...reviewClaim, replayed: "false" } },
  ]) assert.throws(() => parseEditorReviewClaimEnvelope(value), /INVALID_APP_CONTRACT/);
});

test("review claim, release, and verify intents keep queue and resource preconditions separate", () => {
  assert.deepEqual(createReviewClaimIntent({
    queueItem: reviewQueueItem,
    csrfToken: "csrf_token_internal_000000000000001",
    idempotencyKey: "review-claim-idempotency-0001",
  }), {
    method: "POST",
    path: `/v1/app/review-queue/${reviewDemandId}/claim`,
    headers: {
      "content-type": "application/json",
      "idempotency-key": "review-claim-idempotency-0001",
      "if-match": '"demand-2-review-queue"',
      "x-csrf-token": "csrf_token_internal_000000000000001",
    },
    body: {},
  });

  const reviewerDemand = {
    ...profile,
    resource_type: "DEMAND",
    object_id: reviewDemandId,
    status: "SUBMITTED",
    etag: '"demand-2-bbbbbbbbbbbbbbbbbbbbbbbb"',
    capabilities: ["RECORD_FINDINGS"],
    editable_paths: [],
    review_assignment: {
      assignment_id: reviewAssignmentId,
      status: "ACTIVE",
      expires_at: "2026-08-15T08:30:00+00:00",
    },
  };
  assert.deepEqual(REVIEW_ASSIGNMENT_RELEASE_REASON_CODES, ["CONFLICT_DECLARED", "WORKLOAD_RELEASE"]);
  const release = createReviewAssignmentReleaseIntent({
    resource: reviewerDemand,
    assignmentId: reviewAssignmentId,
    csrfToken: "csrf_token_internal_000000000000001",
    idempotencyKey: "review-release-idempotency-001",
    reasonCode: "WORKLOAD_RELEASE",
  });
  assert.deepEqual(release, {
    method: "POST",
    path: `/v1/app/demands/${reviewDemandId}/review-assignments/${reviewAssignmentId}/release`,
    headers: {
      "content-type": "application/json",
      "idempotency-key": "review-release-idempotency-001",
      "if-match": reviewerDemand.etag,
      "x-csrf-token": "csrf_token_internal_000000000000001",
    },
    body: { reason_code: "WORKLOAD_RELEASE" },
  });
  assert.deepEqual(createReviewAssignmentReleaseIntent({
    resource: reviewerDemand,
    assignmentId: reviewAssignmentId,
    csrfToken: "csrf_token_internal_000000000000001",
    idempotencyKey: "review-release-idempotency-002",
    reasonCode: "CONFLICT_DECLARED",
  }).body, { reason_code: "CONFLICT_DECLARED" });
  for (const changes of [
    { assignmentId: "50000000-0000-4000-8000-000000000025" },
    { reasonCode: "ASSIGNMENT_EXPIRED" },
    { reasonCode: "FREE_TEXT" },
  ]) assert.throws(() => createReviewAssignmentReleaseIntent({
    resource: reviewerDemand,
    assignmentId: reviewAssignmentId,
    csrfToken: "csrf_token_internal_000000000000001",
    idempotencyKey: "review-release-idempotency-001",
    reasonCode: "CONFLICT_DECLARED",
    ...changes,
  }), /INVALID_APP_CONTRACT/);
  assert.deepEqual(VERIFY_BUDGET_HEALTH_CODES, ["HEALTHY", "APPROVED_EXCEPTION"]);
  assert.deepEqual(VERIFY_RISK_CODES, ["STANDARD", "ELEVATED_APPROVED"]);
  assert.deepEqual(VERIFY_EVIDENCE_CODES, [
    "SCOPE_COMPLETE",
    "ACCEPTANCE_TESTABLE",
    "BUDGET_COHERENT",
    "RISK_HANDLED",
    "DECLARATIONS_CONFIRMED",
  ]);
  assert.deepEqual(createVerifyIntent({
    resource: reviewerDemand,
    assignmentId: reviewAssignmentId,
    csrfToken: "csrf_token_internal_000000000000001",
    idempotencyKey: "review-verify-idempotency-0001",
    budgetHealthCode: "HEALTHY",
    riskCode: "STANDARD",
    evidenceCodes: ["SCOPE_COMPLETE", "ACCEPTANCE_TESTABLE"],
  }), {
    method: "POST",
    path: `/v1/app/demands/${reviewDemandId}/review-assignments/${reviewAssignmentId}/verify`,
    headers: {
      "content-type": "application/json",
      "idempotency-key": "review-verify-idempotency-0001",
      "if-match": reviewerDemand.etag,
      "x-csrf-token": "csrf_token_internal_000000000000001",
    },
    body: {
      budget_health_code: "HEALTHY",
      risk_code: "STANDARD",
      evidence_codes: ["SCOPE_COMPLETE", "ACCEPTANCE_TESTABLE"],
    },
  });
  for (const changes of [
    { assignmentId: "50000000-0000-4000-8000-000000000025" },
    { budgetHealthCode: "NOT_REVIEWED" },
    { riskCode: "FREE_TEXT" },
    { evidenceCodes: [] },
    { evidenceCodes: ["SCOPE_COMPLETE", "SCOPE_COMPLETE"] },
    { evidenceCodes: ["FREE_TEXT_APPROVED"] },
  ]) assert.throws(() => createVerifyIntent({
    resource: reviewerDemand,
    assignmentId: reviewAssignmentId,
    csrfToken: "csrf_token_internal_000000000000001",
    idempotencyKey: "review-verify-idempotency-0001",
    budgetHealthCode: "HEALTHY",
    riskCode: "STANDARD",
    evidenceCodes: ["SCOPE_COMPLETE"],
    ...changes,
  }), /INVALID_APP_CONTRACT/);

  const pendingClaim = {
    version: 1,
    saved_at: "2026-08-15T08:00:00.000Z",
    resource_type: "REVIEW_CLAIM",
    object_id: reviewDemandId,
    label: "领取审核",
    intent: createReviewClaimIntent({
      queueItem: reviewQueueItem,
      csrfToken: "csrf_token_internal_000000000000001",
      idempotencyKey: "review-claim-idempotency-0001",
    }),
  };
  const encoded = serializePendingIntent(pendingClaim);
  assert.deepEqual(parsePendingIntent(encoded, Date.parse("2026-08-15T09:00:00Z")), pendingClaim);
  assert.equal(parsePendingIntent(JSON.stringify({
    ...pendingClaim,
    intent: { ...pendingClaim.intent, body: { reviewer_user_id: "forged" } },
  }), Date.parse("2026-08-15T09:00:00Z")), null);

  const pendingVerify = {
    version: 1,
    saved_at: "2026-08-15T08:01:00.000Z",
    resource_type: "DEMAND",
    object_id: reviewDemandId,
    label: "验证通过",
    intent: createVerifyIntent({
      resource: reviewerDemand,
      assignmentId: reviewAssignmentId,
      csrfToken: "csrf_token_internal_000000000000001",
      idempotencyKey: "review-verify-idempotency-0001",
      budgetHealthCode: "HEALTHY",
      riskCode: "STANDARD",
      evidenceCodes: ["SCOPE_COMPLETE"],
    }),
  };
  assert.deepEqual(
    parsePendingIntent(serializePendingIntent(pendingVerify), Date.parse("2026-08-15T09:00:00Z")),
    pendingVerify,
  );
  assert.equal(parsePendingIntent(JSON.stringify({
    ...pendingVerify,
    intent: {
      ...pendingVerify.intent,
      body: { ...pendingVerify.intent.body, evidence_summary_sha256: "0".repeat(64) },
    },
  }), Date.parse("2026-08-15T09:00:00Z")), null);
  assert.equal(parsePendingIntent(JSON.stringify({
    ...pendingVerify,
    object_id: "50000000-0000-4000-8000-000000000025",
  }), Date.parse("2026-08-15T09:00:00Z")), null);

  const pendingRelease = {
    version: 1,
    saved_at: "2026-08-15T08:02:00.000Z",
    resource_type: "DEMAND",
    object_id: reviewDemandId,
    label: "释放审核分配",
    intent: release,
  };
  assert.deepEqual(
    parsePendingIntent(serializePendingIntent(pendingRelease), Date.parse("2026-08-15T09:00:00Z")),
    pendingRelease,
  );
  for (const body of [
    { reason_code: "ASSIGNMENT_EXPIRED" },
    { reason_code: "FREE_TEXT" },
    { reason_code: "WORKLOAD_RELEASE", reviewer_user_id: reviewAssignmentId },
    {},
  ]) assert.equal(parsePendingIntent(JSON.stringify({
    ...pendingRelease,
    intent: { ...pendingRelease.intent, body },
  }), Date.parse("2026-08-15T09:00:00Z")), null);
  assert.equal(parsePendingIntent(JSON.stringify({
    ...pendingRelease,
    object_id: "50000000-0000-4000-8000-000000000025",
  }), Date.parse("2026-08-15T09:00:00Z")), null);

  const releasedDemand = {
    ...reviewerDemand,
    revision: reviewerDemand.revision + 1,
    etag: '"demand-3-cccccccccccccccccccccccc"',
    capabilities: [],
    review_assignment: null,
  };
  assert.deepEqual(parseEditorCollection({ data: [releasedDemand] }), [releasedDemand]);
});

test("finance funding projections and intents are synthetic, four-eyes, and authority-free", () => {
  assert.deepEqual(
    parseFinanceFundingQueueEnvelope({ data: [financeQueueItem] }),
    [financeQueueItem],
  );
  assert.deepEqual(
    parseFinanceFundingReviewEnvelope({ data: financeReview }),
    financeReview,
  );
  const claim = createFinanceFundingClaimIntent({
    queueItem: financeQueueItem,
    csrfToken: "csrf_token_internal_000000000000001",
    idempotencyKey: "finance-claim-idempotency-0001",
  });
  assert.deepEqual(claim, {
    method: "POST",
    path: `/v1/app/finance/funding-reviews/${financeDemandId}/claim`,
    headers: {
      "content-type": "application/json",
      "idempotency-key": "finance-claim-idempotency-0001",
      "if-match": '"demand-3-finance-queue"',
      "x-csrf-token": "csrf_token_internal_000000000000001",
    },
    body: {},
  });
  const confirm = createFinanceFundingConfirmIntent({
    review: financeReview,
    attestationCodes: [...FINANCE_FUNDING_ATTESTATION_CODES],
    csrfToken: "csrf_token_internal_000000000000001",
    idempotencyKey: "finance-confirm-idempotency-001",
  });
  assert.deepEqual(confirm, {
    method: "POST",
    path: `/v1/app/finance/funding-reviews/${financeReviewId}/confirm`,
    headers: {
      "content-type": "application/json",
      "idempotency-key": "finance-confirm-idempotency-001",
      "if-match": '"funding-review-1"',
      "x-csrf-token": "csrf_token_internal_000000000000001",
    },
    body: { attestation_codes: [...FINANCE_FUNDING_ATTESTATION_CODES] },
  });
  const release = createFinanceFundingReleaseIntent({
    review: financeReview,
    reasonCode: FINANCE_FUNDING_RELEASE_REASON_CODES[0],
    csrfToken: "csrf_token_internal_000000000000001",
    idempotencyKey: "finance-release-idempotency-01",
  });
  assert.deepEqual(release, {
    method: "POST",
    path: `/v1/app/finance/funding-reviews/${financeReviewId}/assignment/release`,
    headers: {
      "content-type": "application/json",
      "idempotency-key": "finance-release-idempotency-01",
      "if-match": '"funding-review-1"',
      "x-csrf-token": "csrf_token_internal_000000000000001",
    },
    body: { reason_code: "CONFLICT_DECLARED" },
  });
  const finding = createFinanceFundingFindingIntent({
    review: financeReview,
    disposition: "REJECTED",
    reasonCodes: [FINANCE_FUNDING_REJECTED_REASON_CODES[0]],
    requiredFieldCodes: [FINANCE_FUNDING_FINDING_FIELD_CODES[0]],
    csrfToken: "csrf_token_internal_000000000000001",
    idempotencyKey: "finance-finding-idempotency-01",
  });
  assert.deepEqual(finding, {
    method: "POST",
    path: `/v1/app/finance/funding-reviews/${financeReviewId}/findings`,
    headers: {
      "content-type": "application/json",
      "idempotency-key": "finance-finding-idempotency-01",
      "if-match": '"funding-review-1"',
      "x-csrf-token": "csrf_token_internal_000000000000001",
    },
    body: {
      disposition: "REJECTED",
      reason_codes: ["BUDGET_PLAN_UNACCEPTABLE"],
      required_field_codes: ["BUDGET"],
    },
  });

  for (const value of [
    { data: [{ ...financeQueueItem, actor_user_id: "forged" }] },
    { data: [{ ...financeQueueItem, sandbox_funds_amount_minor: 1 }] },
    { data: { ...financeReview, provider: "forged" } },
    { data: { ...financeReview, sandbox_funds_amount_minor: 1 } },
    { data: { ...financeReview, target_status: "FUNDED" } },
    { data: { ...financeReview, target_revision: 11 } },
    { data: { ...financeReview, target_content_sha256: "e".repeat(63) } },
    { data: { ...financeReview, planned_budget_currency: "USD" } },
    { data: { ...financeReview, planned_budget_minimum_amount_minor: 200001 } },
    { data: { ...financeReview, planned_budget_direct_cost_amount_minor: -1 } },
    { data: { ...financeReview, provider_code: "FORGED_PROVIDER" } },
    { data: { ...financeReview, payment_operation_code: "CAPTURE" } },
    { data: { ...financeReview, required_confirmations: 1 } },
    { data: { ...financeReview, legal_effect: "REAL_PAYMENT" } },
    { data: { ...financeReview, assignment_status: undefined } },
    { data: { ...financeReview, confirmation_by_me: undefined } },
    { data: { ...financeReview, available_actions: undefined } },
    { data: { ...financeReview, available_actions: ["CONFIRM"] } },
    { data: { ...financeReview, confirmation_by_me: true } },
  ]) {
    const parser = Array.isArray(value.data)
      ? parseFinanceFundingQueueEnvelope
      : parseFinanceFundingReviewEnvelope;
    assert.throws(() => parser(value), /INVALID_APP_CONTRACT/);
  }
  assert.throws(() => createFinanceFundingConfirmIntent({
    review: financeReview,
    attestationCodes: ["SYNTHETIC_ONLY"],
    csrfToken: "csrf_token_internal_000000000000001",
    idempotencyKey: "finance-confirm-idempotency-002",
  }), /FINANCE_ATTESTATION_REQUIRED/);
  assert.throws(() => createFinanceFundingReleaseIntent({
    review: { ...financeReview, assignment_status: "RELEASED", available_actions: [], can_confirm: false },
    reasonCode: "WORKLOAD_RELEASE",
    csrfToken: "csrf_token_internal_000000000000001",
    idempotencyKey: "finance-release-idempotency-02",
  }), /FINANCE_RELEASE_NOT_AVAILABLE/);
  assert.throws(() => createFinanceFundingFindingIntent({
    review: financeReview,
    disposition: "DISCREPANCY",
    reasonCodes: [FINANCE_FUNDING_REJECTED_REASON_CODES[0]],
    requiredFieldCodes: ["BUDGET"],
    csrfToken: "csrf_token_internal_000000000000001",
    idempotencyKey: "finance-finding-idempotency-02",
  }), /INVALID_APP_CONTRACT/);
  assert.deepEqual(FINANCE_FUNDING_DISCREPANCY_REASON_CODES, [
    "EVIDENCE_REFERENCE_MISMATCH", "TARGET_CONTENT_MISMATCH",
  ]);
});

test("write intents bind exact route, ETag, CSRF, idempotency key and no authority fields", () => {
  assert.deepEqual(createProfileIntent({
    csrfToken: "csrf_token_internal_000000000000001",
    idempotencyKey: "idempotency-create-profile1",
  }), {
    method: "POST",
    path: "/v1/app/profiles",
    headers: {
      "content-type": "application/json",
      "idempotency-key": "idempotency-create-profile1",
      "x-csrf-token": "csrf_token_internal_000000000000001",
    },
    body: {},
  });
  assert.equal(createDemandIntent({
    csrfToken: "csrf_token_internal_000000000000001",
    idempotencyKey: "idempotency-create-demand01",
    taxonomyBundleId: "taxonomy_internal_00001",
    clientReference: "synthetic-case-001",
    expiresAt: "2026-10-01T08:00:00.000Z",
  }).path, "/v1/app/demands");

  const profileIntent = createProfileDraftIntent({
    resource: profile,
    csrfToken: "csrf_token_internal_000000000000001",
    idempotencyKey: "idempotency-profile-000001",
    taxonomyBundleId: "taxonomy_internal_00001",
    content: { interests: [] },
  });
  assert.deepEqual(profileIntent, {
    method: "PUT",
    path: "/v1/app/profiles/profile_internal_000001/draft",
    headers: {
      "content-type": "application/json",
      "idempotency-key": "idempotency-profile-000001",
      "if-match": profile.etag,
      "x-csrf-token": "csrf_token_internal_000000000000001",
    },
    body: {
      base_version_id: version.version_id,
      taxonomy_bundle_id: "taxonomy_internal_00001",
      content: { interests: [] },
    },
  });

  const demand = {
    ...profile,
    resource_type: "DEMAND",
    object_id: "demand_internal_0000001",
    capabilities: ["SAVE_DRAFT", "SUBMIT"],
    editable_paths: [...DEMAND_EDITABLE_PATHS],
    etag: '"demand-2-bbbbbbbbbbbbbbbbbbbbbbbb"',
    review_assignment: null,
  };
  assert.equal(createDemandDraftIntent({
    resource: demand,
    csrfToken: "csrf_token_internal_000000000000001",
    idempotencyKey: "idempotency-demand-0000001",
    taxonomyBundleId: "taxonomy_internal_00001",
    content: {},
  }).path, "/v1/app/demands/demand_internal_0000001/draft");

  assert.deepEqual(createFindingIntent({
    resource: {
      ...demand,
      capabilities: ["RECORD_FINDINGS"],
      editable_paths: [],
      review_assignment: {
        assignment_id: "assignment_internal_0001",
        status: "ACTIVE",
        expires_at: "2026-08-20T08:00:00+00:00",
      },
    },
    assignmentId: "assignment_internal_0001",
    csrfToken: "csrf_token_internal_000000000000001",
    idempotencyKey: "idempotency-finding-000001",
    reasonCodes: ["CONTENT_INCOMPLETE"],
    requiredFieldPaths: ["/problem"],
  }).body, { reason_codes: ["CONTENT_INCOMPLETE"], required_field_paths: ["/problem"] });
});

test("Creator Profile lifecycle capabilities, reasons, writes, and recovery are closed", () => {
  const publishedVersion = { ...version, status: "PUBLISHED" };
  const active = {
    ...profile,
    status: "ACTIVE",
    capabilities: ["SAVE_DRAFT", "PAUSE", "ARCHIVE"],
    current_version: publishedVersion,
    versions: [publishedVersion],
  };
  const pause = createProfileLifecycleIntent({
    resource: active,
    action: "PAUSE",
    reasonCode: "TEMPORARY_UNAVAILABILITY",
    csrfToken: "csrf_token_internal_000000000000001",
    idempotencyKey: "profile-pause-idempotency-0001",
  });
  assert.deepEqual(pause, {
    method: "POST",
    path: "/v1/app/profiles/profile_internal_000001/pause",
    headers: {
      "content-type": "application/json",
      "idempotency-key": "profile-pause-idempotency-0001",
      "if-match": active.etag,
      "x-csrf-token": "csrf_token_internal_000000000000001",
    },
    body: { reason_code: "TEMPORARY_UNAVAILABILITY" },
  });

  const paused = {
    ...active,
    status: "PAUSED",
    capabilities: ["RESUME", "ARCHIVE"],
    editable_paths: [],
  };
  const resume = createProfileLifecycleIntent({
    resource: paused,
    action: "RESUME",
    reasonCode: null,
    csrfToken: "csrf_token_internal_000000000000001",
    idempotencyKey: "profile-resume-idempotency-001",
  });
  assert.deepEqual(resume.body, {});
  assert.equal(resume.path, "/v1/app/profiles/profile_internal_000001/resume");

  const archive = createProfileLifecycleIntent({
    resource: active,
    action: "ARCHIVE",
    reasonCode: "ACCOUNT_CLOSURE",
    csrfToken: "csrf_token_internal_000000000000001",
    idempotencyKey: "profile-archive-idempotency-01",
  });
  assert.deepEqual(archive.body, { reason_code: "ACCOUNT_CLOSURE" });
  assert.equal(archive.path, "/v1/app/profiles/profile_internal_000001/archive");
  assert.deepEqual(PROFILE_PAUSE_REASON_CODES, [
    "OWNER_REQUEST", "TEMPORARY_UNAVAILABILITY", "SAFETY_REVIEW",
  ]);
  assert.deepEqual(PROFILE_ARCHIVE_REASON_CODES, [
    "OWNER_REQUEST", "ACCOUNT_CLOSURE", "SAFETY_REVIEW",
  ]);

  assert.deepEqual(parseEditorCollection({ data: [paused] }), [paused]);
  for (const invalidProfile of [
    { ...paused, capabilities: ["SAVE_DRAFT", "RESUME", "ARCHIVE"] },
    { ...paused, editable_paths: [...PROFILE_EDITABLE_PATHS] },
    { ...paused, current_version: { ...publishedVersion, status: "DRAFT" }, versions: [{ ...publishedVersion, status: "DRAFT" }] },
    { ...active, capabilities: ["SAVE_DRAFT", "ARCHIVE", "PAUSE"] },
    { ...active, status: "ARCHIVED", capabilities: [], editable_paths: [] },
  ]) assert.throws(
    () => parseEditorCollection({ data: [invalidProfile] }),
    /INVALID_PROFILE_LIFECYCLE_PROJECTION/,
  );
  for (const input of [
    { resource: active, action: "PAUSE", reasonCode: "ACCOUNT_CLOSURE" },
    { resource: paused, action: "RESUME", reasonCode: "OWNER_REQUEST" },
    { resource: { ...active, capabilities: ["SAVE_DRAFT", "ARCHIVE"] }, action: "PAUSE", reasonCode: "OWNER_REQUEST" },
  ]) assert.throws(() => createProfileLifecycleIntent({
    csrfToken: "csrf_token_internal_000000000000001",
    idempotencyKey: "profile-lifecycle-invalid-001",
    ...input,
  }), /INVALID_REASON_CODE|CAPABILITY_NOT_GRANTED|INVALID_PROFILE_LIFECYCLE_PROJECTION/);

  const pending = {
    version: 1,
    saved_at: "2026-08-12T08:00:00.000Z",
    resource_type: "CREATOR_PROFILE",
    object_id: active.object_id,
    label: "暂停创作者档案",
    intent: pause,
  };
  assert.deepEqual(
    parsePendingIntent(
      serializePendingIntent(pending),
      Date.parse("2026-08-12T09:00:00Z"),
    ),
    pending,
  );
  assert.equal(parsePendingIntent(JSON.stringify({
    ...pending,
    intent: { ...pause, body: { reason_code: "ACCOUNT_CLOSURE" } },
  }), Date.parse("2026-08-12T09:00:00Z")), null);
});

test("412 conflict surface is exact and pending write recovery expires closed", () => {
  const baseContent = {
    ...Object.fromEntries(DEMAND_EDITABLE_PATHS.map((path) => [path.slice(1), null])),
    problem: { background: "base" },
    scope: { deliverables: [] },
    budget: { maximum_amount_minor: 100 },
  };
  const currentContent = {
    ...baseContent,
    problem: { background: "server" },
    scope: { deliverables: [{ item_id: "server", description: "服务器新增" }] },
  };
  const yoursContent = {
    ...baseContent,
    problem: { background: "mine" },
    budget: { maximum_amount_minor: 200 },
  };
  const conflict = parseThreeWayConflict({
    error: {
      code: "PRECONDITION_FAILED",
      details: {
        current: { version_id: "version_internal_00000002", content: currentContent },
        base: { version_id: "version_internal_00000001", content: baseContent },
        yours: { version_id: "version_internal_00000001", content: yoursContent },
      },
    },
  }, '"demand-3-cccccccccccccccccccccccc"');
  assert.equal(conflict.currentEtag, '"demand-3-cccccccccccccccccccccccc"');
  assert.deepEqual(conflict.changedPaths, ["/budget", "/problem", "/scope"]);

  const currentVersion = {
    version_id: "version_internal_00000002",
    version_no: 2,
    based_on_version_id: "version_internal_00000001",
    status: "COMMITTED",
    content: currentContent,
    content_sha256: "c".repeat(64),
    taxonomy_bundle_id: "taxonomy_internal_00001",
    created_at: "2026-08-12T08:05:00+00:00",
  };
  const currentResource = {
    ...profile,
    resource_type: "DEMAND",
    object_id: reviewDemandId,
    status: "DRAFT",
    revision: 3,
    etag: conflict.currentEtag,
    capabilities: ["SAVE_DRAFT", "SUBMIT"],
    editable_paths: [...DEMAND_EDITABLE_PATHS],
    current_version: currentVersion,
    versions: [{ ...version, status: "COMMITTED" }, currentVersion],
  };
  const rebound = bindConflictToCurrentResource(conflict, currentResource);
  const merge = planEditorConflictMerge(
    "DEMAND",
    conflict.base.content,
    conflict.current.content,
    conflict.yours.content,
    { "/problem": "MINE" },
  );
  assert.equal(merge.complete, true);
  assert.notEqual(merge.content, null);
  const retry = createDemandDraftIntent({
    resource: rebound,
    csrfToken: "csrf_token_internal_000000000000001",
    idempotencyKey: "idempotency-demand-after-conflict-0001",
    taxonomyBundleId: "taxonomy_internal_00001",
    content: merge.content,
  });
  assert.equal(retry.headers["if-match"], conflict.currentEtag);
  assert.equal(retry.body.base_version_id, currentVersion.version_id);
  assert.deepEqual(retry.body.content, merge.content);
  assert.deepEqual(retry.body.content.scope, currentContent.scope);
  assert.deepEqual(retry.body.content.budget, yoursContent.budget);
  assert.throws(
    () => bindConflictToCurrentResource(conflict, { ...currentResource, revision: 4, etag: '"demand-4-dddddddddddddddddddddddd"' }),
    /CONFLICT_REFRESH_MISMATCH/,
  );

  const pending = {
    version: 1,
    saved_at: "2026-08-12T08:00:00.000Z",
    resource_type: "DEMAND",
    object_id: "demand_internal_0000001",
    label: "保存需求草稿",
    intent: createDemandDraftIntent({
      resource: {
        ...profile,
        resource_type: "DEMAND",
        object_id: "demand_internal_0000001",
        capabilities: ["SAVE_DRAFT", "SUBMIT"],
        editable_paths: [...DEMAND_EDITABLE_PATHS],
        etag: '"demand-2-bbbbbbbbbbbbbbbbbbbbbbbb"',
      },
      csrfToken: "csrf_token_internal_000000000000001",
      idempotencyKey: "idempotency-demand-0000001",
      taxonomyBundleId: "taxonomy_internal_00001",
      content: {},
    }),
  };
  const encoded = serializePendingIntent(pending);
  assert.deepEqual(parsePendingIntent(encoded, Date.parse("2026-08-12T09:00:00Z")), pending);
  assert.equal(parsePendingIntent(encoded, Date.parse("2026-08-14T09:00:00Z")), null);
  assert.equal(parsePendingIntent("{bad", Date.now()), null);
  assert.equal(parsePendingIntent(JSON.stringify({
    ...pending,
    intent: { ...pending.intent, path: "/v1/app/platform/users/suspend" },
  }), Date.parse("2026-08-12T09:00:00Z")), null);
});

test("ACCESS_ADMIN account contracts are closed, OCC-bound, and recoverable", () => {
  const actor = {
    account_code: "access_admin_01",
    user_id: "10000000-0000-4000-8000-000000000001",
    display_handle: "sandbox_access_admin_01",
    status: "ACTIVE",
    aggregate_version: 3,
    entity_tag: '"v3"',
    role_codes: ["ACCESS_ADMIN"],
    active_session_count: 1,
    created_at: "2026-08-12T08:00:00+00:00",
    updated_at: "2026-08-15T08:00:00+00:00",
    is_self: true,
  };
  const target = {
    ...actor,
    account_code: "creator_01",
    user_id: "10000000-0000-4000-8000-000000000002",
    display_handle: "sandbox_creator_01",
    role_codes: ["CREATOR"],
    is_self: false,
  };
  const collection = {
    data: {
      schema_version: "internal-sandbox-account-admin-v1",
      evaluated_at: "2026-08-15T08:00:01+00:00",
      accounts: [actor, target],
    },
  };
  assert.deepEqual(parseAccountAdminCollectionEnvelope(collection), collection.data);
  assert.deepEqual(parseAccountAdminEnvelope({ data: target }), target);
  assert.deepEqual(ACCOUNT_ADMIN_REASON_CODES, [
    "ACCESS_REVIEW", "SAFETY_REVIEW", "SESSION_HYGIENE",
  ]);

  const intent = createAccountAdminIntent({
    account: target,
    action: "SUSPEND",
    csrfToken: "csrf_token_internal_000000000000001",
    idempotencyKey: "account-suspend-idempotency-0001",
    reasonCode: "SAFETY_REVIEW",
  });
  assert.deepEqual(intent, {
    method: "POST",
    path: "/v1/app/admin/accounts/10000000-0000-4000-8000-000000000002/suspend",
    headers: {
      "content-type": "application/json",
      "idempotency-key": "account-suspend-idempotency-0001",
      "if-match": '"v3"',
      "x-csrf-token": "csrf_token_internal_000000000000001",
    },
    body: { reason_code: "SAFETY_REVIEW" },
  });
  const reflected = JSON.stringify(intent);
  for (const forbidden of ["actor", "organization", "authority", "role_codes"])
    assert.doesNotMatch(reflected, new RegExp(forbidden));

  const pending = {
    version: 1,
    saved_at: "2026-08-15T08:00:00.000Z",
    resource_type: "ACCOUNT_ADMIN",
    object_id: target.user_id,
    label: "暂停合成账号",
    intent,
  };
  const encoded = serializePendingIntent(pending);
  assert.deepEqual(parsePendingIntent(encoded, Date.parse("2026-08-15T09:00:00Z")), pending);

  assert.deepEqual(parseAccountAdminCommandEnvelope({ data: {
    user_id: target.user_id,
    display_handle: target.display_handle,
    status: "SUSPENDED",
    aggregate_version: 4,
    entity_tag: '"v4"',
    revoked_session_count: 1,
    revoked_session_family_count: 1,
    replayed: false,
  } }).entity_tag, '"v4"');
  for (const forged of [
    { data: { ...target, contact: "secret" } },
    { data: { ...target, entity_tag: '"v4"' } },
    { data: { ...target, role_codes: ["CREATOR", "CREATOR"] } },
  ]) assert.throws(() => parseAccountAdminEnvelope(forged), /INVALID_APP_CONTRACT/);
  assert.throws(() => createAccountAdminIntent({
    account: target,
    action: "GRANT_ROLE",
    csrfToken: "csrf_token_internal_000000000000001",
    idempotencyKey: "account-suspend-idempotency-0001",
    reasonCode: "SAFETY_REVIEW",
  }), /ACCOUNT_ACTION_NOT_AVAILABLE/);

  const roleless = { ...target, role_codes: [] };
  assert.deepEqual(parseAccountAdminEnvelope({ data: roleless }), roleless);
  const dutyIntent = createPlatformDutyIntent({
    account: target,
    dutyCode: "FINANCE_OPERATOR",
    action: "GRANT",
    csrfToken: "csrf_token_internal_000000000000001",
    idempotencyKey: "account-duty-idempotency-000001",
    reasonCode: "ACCESS_REVIEW",
  });
  assert.deepEqual(dutyIntent, {
    method: "POST",
    path: `${"/v1/app/admin/accounts/10000000-0000-4000-8000-000000000002"}/platform-duties/FINANCE_OPERATOR/grant`,
    headers: {
      "content-type": "application/json",
      "idempotency-key": "account-duty-idempotency-000001",
      "if-match": '"v3"',
      "x-csrf-token": "csrf_token_internal_000000000000001",
    },
    body: { reason_code: "ACCESS_REVIEW" },
  });
  const dutyPending = {
    ...pending,
    label: "授予 FINANCE_OPERATOR",
    intent: dutyIntent,
  };
  assert.deepEqual(
    parsePendingIntent(
      serializePendingIntent(dutyPending),
      Date.parse("2026-08-15T09:00:00Z"),
    ),
    dutyPending,
  );
  assert.throws(() => createPlatformDutyIntent({
    account: actor,
    dutyCode: "FINANCE_OPERATOR",
    action: "GRANT",
    csrfToken: "csrf_token_internal_000000000000001",
    idempotencyKey: "account-duty-idempotency-000002",
    reasonCode: "ACCESS_REVIEW",
  }), /ACCOUNT_ACTION_NOT_AVAILABLE/);
  assert.throws(() => createPlatformDutyIntent({
    account: target,
    dutyCode: "CREATOR",
    action: "GRANT",
    csrfToken: "csrf_token_internal_000000000000001",
    idempotencyKey: "account-duty-idempotency-000003",
    reasonCode: "ACCESS_REVIEW",
  }), /ACCOUNT_ACTION_NOT_AVAILABLE/);
});
