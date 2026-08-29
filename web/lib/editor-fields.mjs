import { DEMAND_EDITABLE_PATHS, PROFILE_EDITABLE_PATHS } from "./app-contract.mjs";

const OPTION_LABELS = Object.freeze({
  PRIVATE: "仅自己与授权运营可见",
  MATCH_ONLY: "仅用于匹配",
  PUBLIC: "可公开展示",
  SELF_ASSERTED: "本人声明",
  VERIFIED_EVIDENCE: "已有核验证据",
  LEGACY_UNVERIFIED: "历史资料（未核验）",
  REMOTE: "远程",
  HYBRID: "混合",
  ONSITE: "现场",
  FLEXIBLE: "灵活",
  ASYNC: "异步",
  DAILY: "每日",
  TWICE_WEEKLY: "每周两次",
  WEEKLY: "每周",
  SOLO: "独立",
  PAIR: "双人",
  SMALL_TEAM: "小团队",
  ANY: "均可",
  NONE: "不需要",
  AS_NEEDED: "按需",
  REQUIRED: "必须",
  NEVER: "从不",
  RISK_BASED: "按风险",
  ALWAYS: "始终",
  FOUNDATION: "入门",
  WORKING: "可独立工作",
  ADVANCED: "熟练",
  EXPERT: "专家",
  LOW: "低",
  MEDIUM: "中",
  HIGH: "高",
  INTERNAL: "内部",
  CONFIDENTIAL: "机密",
  RESTRICTED: "严格限制",
  DEMAND_OWNER: "需求负责人",
});

const FIELD_LABELS = Object.freeze({
  interests: "兴趣与问题偏好",
  skills: "技能",
  availability: "可投入时间",
  collaboration: "协作偏好",
  compensation: "报酬边界",
  boundaries: "工作边界",
  location: "地域",
  conflicts: "利益冲突",
  ai: "AI 使用约束",
  problem: "问题与目标",
  scope: "范围与交付物",
  acceptance: "验收规则",
  matching: "匹配条件",
  schedule: "计划与工期",
  budget: "合成预算",
  milestone_plan: "里程碑计划",
  risk: "风险与数据敏感度",
  declarations: "授权声明",
  problem_code: "问题代码",
  domain_code: "领域代码",
  task_code: "任务代码",
  strength: "偏好强度",
  skill_code: "技能代码",
  proficiency: "熟练度",
  visibility: "可见范围",
  source_kind: "资料来源",
  evidence_ids: "证据编号",
  available_from: "最早开始日期",
  weekly_hours: "每周可投入小时",
  duration_weeks: "可持续周数",
  timezone: "时区",
  languages: "语言",
  language_code: "语言代码",
  work_modes: "工作方式",
  work_mode: "工作方式",
  feedback_cadence: "反馈频率",
  team_preference: "团队偏好",
  minimum_project_amount_minor: "最低项目金额（分）",
  direct_cost_amount_minor: "直接成本（分）",
  currency: "币种",
  prohibited_domains: "不参与的领域",
  prohibited_tasks: "不参与的任务",
  allowed_data_sensitivity: "可接受的数据敏感度",
  data_sensitivity: "数据敏感度",
  code: "分类代码",
  region_code: "地区代码",
  organization_id: "组织编号",
  allowed: "允许使用 AI",
  requires_ai: "需要使用 AI",
  required: "必须使用 AI",
  human_review_code: "人工复核要求",
  prohibited_case_codes: "禁止 AI 的情形代码",
  background: "问题背景",
  problem_type_codes: "问题类型代码",
  target_user_category_codes: "目标受益者类型代码",
  desired_outcomes: "期望结果",
  deliverables: "交付物",
  item_id: "稳定条目编号",
  description: "描述",
  out_of_scope: "明确不包含",
  criteria: "验收标准",
  criterion_id: "稳定标准编号",
  response_days: "响应天数",
  owner_role_code: "验收责任角色",
  must_have: "必须具备",
  nice_to_have: "加分项",
  minimum_level_code: "最低水平",
  problem_codes: "问题代码",
  domain_codes: "领域代码",
  task_codes: "任务代码",
  start_date: "开始日期",
  due_date: "截止日期",
  estimated_days: "预计工作日",
  minimum_amount_minor: "最低预算（分）",
  maximum_amount_minor: "最高预算（分）",
  items: "条目",
  label: "名称",
  percent: "占比（%）",
  uncertainty_code: "不确定性",
  urgency_code: "紧急程度",
  dependency_codes: "依赖代码",
  data_handling_plan: "数据处理方案",
  data_model_policy: "数据与模型约束",
  demand_region_code: "需求所在地区",
  allowed_creator_region_codes: "允许创作者所在地区",
  decision_authority: "我有权代表需求方作出项目决定",
  data_rights: "我确认合成资料的数据使用边界",
  procurement_intent: "我确认这只是内部合成采购意向",
});

const OPTIONS = Object.freeze({
  visibility: ["PRIVATE", "MATCH_ONLY", "PUBLIC"],
  source_kind: ["SELF_ASSERTED", "VERIFIED_EVIDENCE", "LEGACY_UNVERIFIED"],
  work_mode: ["REMOTE", "HYBRID", "ONSITE", "FLEXIBLE"],
  feedback_cadence: ["ASYNC", "DAILY", "TWICE_WEEKLY", "WEEKLY"],
  team_preference: ["SOLO", "PAIR", "SMALL_TEAM", "ANY"],
  human_review_code: ["NONE", "AS_NEEDED", "REQUIRED", "NEVER", "RISK_BASED", "ALWAYS"],
  minimum_level_code: ["FOUNDATION", "WORKING", "ADVANCED", "EXPERT"],
  uncertainty_code: ["LOW", "MEDIUM", "HIGH"],
  urgency_code: ["LOW", "MEDIUM", "HIGH"],
  data_sensitivity: ["PUBLIC", "INTERNAL", "CONFIDENTIAL", "HIGH", "RESTRICTED"],
  owner_role_code: ["DEMAND_OWNER"],
});

const MULTILINE_KEYS = new Set([
  "background", "description", "data_handling_plan", "data_model_policy",
]);
const DATE_KEYS = new Set(["available_from", "start_date", "due_date"]);
const READ_ONLY_KEYS = new Set(["owner_role_code", "item_id", "criterion_id"]);
const CODE_KEYS = new Set([
  "problem_code", "domain_code", "task_code", "skill_code", "code",
]);
const REGION_KEYS = new Set(["region_code", "demand_region_code"]);
const OPAQUE_ID_KEYS = new Set(["organization_id"]);
const ITEM_ID_KEYS = new Set(["item_id", "criterion_id"]);

const NUMBER_LIMITS = Object.freeze({
  strength: [0, 4],
  proficiency: [0, 4],
  weekly_hours: [1, 80],
  duration_weeks: [1, 104],
  minimum_project_amount_minor: [0, Number.MAX_SAFE_INTEGER],
  direct_cost_amount_minor: [0, Number.MAX_SAFE_INTEGER],
  response_days: [1, 30],
  estimated_days: [1, 366],
  minimum_amount_minor: [0, Number.MAX_SAFE_INTEGER],
  maximum_amount_minor: [0, Number.MAX_SAFE_INTEGER],
  percent: [1, 100],
});

const OPTIONAL_TEMPLATES = Object.freeze({
  "CREATOR_PROFILE:/availability": {
    available_from: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString().slice(0, 10),
    weekly_hours: 20,
    duration_weeks: 4,
    timezone: "Asia/Shanghai",
    visibility: "MATCH_ONLY",
    source_kind: "SELF_ASSERTED",
    evidence_ids: [],
  },
  "CREATOR_PROFILE:/compensation": {
    minimum_project_amount_minor: 0,
    currency: "CNY",
    direct_cost_amount_minor: 0,
    visibility: "PRIVATE",
    source_kind: "SELF_ASSERTED",
    evidence_ids: [],
  },
  "CREATOR_PROFILE:/boundaries": {
    prohibited_domains: [],
    prohibited_tasks: [],
    allowed_data_sensitivity: {
      data_sensitivity: "INTERNAL",
      visibility: "PRIVATE",
      source_kind: "SELF_ASSERTED",
      evidence_ids: [],
    },
  },
  "CREATOR_PROFILE:/location": {
    region_code: "CN",
    visibility: "MATCH_ONLY",
    source_kind: "SELF_ASSERTED",
    evidence_ids: [],
  },
  "CREATOR_PROFILE:/ai": {
    allowed: false,
    requires_ai: false,
    human_review_code: "REQUIRED",
    prohibited_case_codes: [],
    visibility: "MATCH_ONLY",
    source_kind: "SELF_ASSERTED",
    evidence_ids: [],
  },
  "CREATOR_PROFILE:/collaboration/feedback_cadence": {
    feedback_cadence: "WEEKLY",
    ...metadata("PUBLIC"),
  },
  "CREATOR_PROFILE:/collaboration/team_preference": {
    team_preference: "ANY",
    ...metadata("PUBLIC"),
  },
  "DEMAND:/risk/data_handling_plan": "仅在本 INTERNAL_SANDBOX 内处理合成资料。",
  "DEMAND:/ai/data_model_policy": "不得向外部模型发送任何资料，所有结果必须人工复核。",
});

function metadata(visibility = "MATCH_ONLY") {
  return { visibility, source_kind: "SELF_ASSERTED", evidence_ids: [] };
}

const ARRAY_TEMPLATES = Object.freeze({
  "/interests": { problem_code: "", domain_code: "", task_code: "", strength: 2, ...metadata() },
  "/skills": { skill_code: "", proficiency: 2, ...metadata() },
  "/collaboration/languages": { language_code: "zh-CN", ...metadata("PUBLIC") },
  "/collaboration/work_modes": { work_mode: "REMOTE", ...metadata("PUBLIC") },
  "/conflicts": { organization_id: "", ...metadata("PRIVATE") },
  "/boundaries/prohibited_domains": { code: "", ...metadata("PRIVATE") },
  "/boundaries/prohibited_tasks": { code: "", ...metadata("PRIVATE") },
  "/problem/problem_type_codes": "",
  "/problem/target_user_category_codes": "",
  "/problem/desired_outcomes": "",
  "/scope/deliverables": { item_id: "deliverable_1", description: "" },
  "/scope/out_of_scope": "",
  "/acceptance/criteria": { criterion_id: "criterion_1", description: "" },
  "/skills/must_have": { skill_code: "", minimum_level_code: "WORKING" },
  "/skills/nice_to_have": { skill_code: "", minimum_level_code: "WORKING" },
  "/matching/problem_codes": "",
  "/matching/domain_codes": "",
  "/matching/task_codes": "",
  "/milestone_plan/items": { item_id: "milestone_1", label: "", percent: 100 },
  "/risk/dependency_codes": "",
  "/collaboration/languages#demand": "zh-CN",
  "/location/allowed_creator_region_codes": "CN",
  "/ai/prohibited_case_codes": "",
  "/evidence_ids": "",
});

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

const CHOICE_VALUE_PATTERNS = Object.freeze({
  TAXONOMY_CODE: /^[A-Z][A-Z0-9_.:-]{1,63}$/,
  REGION_CODE: /^[A-Z0-9][A-Z0-9-]{1,31}$/,
  LANGUAGE_TAG: /^[A-Za-z]{2,3}(?:-[A-Za-z0-9]{2,8})*$/,
  CURRENCY_CODE: /^[A-Z]{3}$/,
  CONTENT_ENUM: /^[A-Z][A-Z0-9_]{1,63}$/,
});
const REQUIRED_EDITOR_CHOICE_PATHS = Object.freeze({
  CREATOR_PROFILE: Object.freeze([
    "/ai/prohibited_case_codes/*",
    "/boundaries/prohibited_domains/*/code",
    "/boundaries/prohibited_tasks/*/code",
    "/collaboration/languages/*/language_code",
    "/compensation/currency",
    "/interests/*/domain_code",
    "/interests/*/problem_code",
    "/interests/*/task_code",
    "/location/region_code",
    "/skills/*/skill_code",
  ]),
  DEMAND: Object.freeze([
    "/budget/currency",
    "/collaboration/languages/*",
    "/location/allowed_creator_region_codes/*",
    "/location/demand_region_code",
    "/matching/domain_codes/*",
    "/matching/problem_codes/*",
    "/matching/task_codes/*",
    "/problem/domain_code",
    "/problem/problem_type_codes/*",
    "/problem/target_user_category_codes/*",
    "/risk/dependency_codes/*",
    "/skills/must_have/*/skill_code",
    "/skills/nice_to_have/*/skill_code",
  ]),
});

export function normalizeEditorChoicePath(canonicalPath) {
  if (typeof canonicalPath !== "string" || !canonicalPath.startsWith("/")) {
    throw new TypeError("INVALID_EDITOR_CHOICE_PATH");
  }
  return `/${canonicalPath.slice(1).split("/").map((segment) => (
    /^(?:0|[1-9][0-9]*)$/.test(segment) ? "*" : segment
  )).join("/")}`;
}

export function resolveEditorChoice(configuration, resourceType, canonicalPath) {
  const fields = configuration?.editor_choices?.fields;
  if (!Array.isArray(fields)) return null;
  const pathTemplate = normalizeEditorChoicePath(canonicalPath);
  return fields.find((field) => (
    field.resource_type === resourceType && field.path_template === pathTemplate
  )) ?? null;
}

function missingEditorChoicePaths(configuration, resourceType) {
  if (!configuration) return REQUIRED_EDITOR_CHOICE_PATHS[resourceType] ?? [];
  const fields = configuration.editor_choices?.fields;
  if (!Array.isArray(fields)) return REQUIRED_EDITOR_CHOICE_PATHS[resourceType] ?? [];
  const available = new Set(fields.filter((field) => field.resource_type === resourceType)
    .map((field) => field.path_template));
  return (REQUIRED_EDITOR_CHOICE_PATHS[resourceType] ?? []).filter((path) => !available.has(path));
}

export function editorChoiceSourceLabel(source) {
  return ({
    TAXONOMY_BUNDLE_NODE: "分类节点",
    INTERNAL_SANDBOX_POLICY: "沙盒策略",
    INTERNAL_SANDBOX_PRESET: "预设",
  })[source] ?? "未知来源";
}

function canonicalArrayPath(resourceType, path) {
  if (resourceType === "DEMAND" && path === "/collaboration/languages") {
    return "/collaboration/languages#demand";
  }
  return path.endsWith("/evidence_ids") ? "/evidence_ids" : path;
}

function itemIdentifierTemplate(template, path, current) {
  if (!template || typeof template !== "object" || Array.isArray(template)) return template;
  const result = clone(template);
  const values = Array.isArray(current) ? current : [];
  const field = path === "/acceptance/criteria" ? "criterion_id" : "item_id";
  const prefix = path === "/scope/deliverables"
    ? "deliverable"
    : path === "/acceptance/criteria"
      ? "criterion"
      : "milestone";
  const used = new Set(values.map((value) => value && typeof value === "object" ? value[field] : null));
  let sequence = (typeof current === "number" ? current : values.length) + 1;
  while (used.has(`${prefix}_${sequence}`)) sequence += 1;
  if (path === "/scope/deliverables") result.item_id = `deliverable_${sequence}`;
  if (path === "/acceptance/criteria") result.criterion_id = `criterion_${sequence}`;
  if (path === "/milestone_plan/items") result.item_id = `milestone_${sequence}`;
  return result;
}

export function sectionPaths(resourceType) {
  if (resourceType === "CREATOR_PROFILE") return PROFILE_EDITABLE_PATHS;
  if (resourceType === "DEMAND") return DEMAND_EDITABLE_PATHS;
  throw new TypeError("UNKNOWN_EDITOR_RESOURCE");
}

export function fieldLabel(key) {
  return FIELD_LABELS[key] ?? key.replaceAll("_", " ");
}

export function fieldInputMeta(key, canonicalPath, resourceType = null) {
  let options = OPTIONS[key];
  if (key === "visibility") {
    options = canonicalPath.includes("/compensation/")
      || canonicalPath.includes("/boundaries/")
      || canonicalPath.includes("/conflicts/")
      ? ["PRIVATE"]
      : canonicalPath.startsWith("/interests/")
        || canonicalPath.startsWith("/availability/")
        || canonicalPath.startsWith("/ai/")
        ? ["PRIVATE", "MATCH_ONLY"]
        : ["PRIVATE", "MATCH_ONLY", "PUBLIC"];
  }
  if (key === "human_review_code") {
    options = resourceType === "CREATOR_PROFILE"
      ? ["NONE", "AS_NEEDED", "REQUIRED"]
      : ["NEVER", "RISK_BASED", "ALWAYS"];
  }
  if (key === "data_sensitivity") {
    options = resourceType === "CREATOR_PROFILE"
      ? ["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"]
      : ["PUBLIC", "INTERNAL", "HIGH", "RESTRICTED"];
  }
  if (key === "work_mode") {
    options = resourceType === "CREATOR_PROFILE"
      ? ["REMOTE", "HYBRID", "ONSITE"]
      : ["REMOTE", "HYBRID", "ONSITE", "FLEXIBLE"];
  }
  return Object.freeze({
    type: DATE_KEYS.has(key) ? "date" : typeof options === "undefined" ? "text" : "select",
    options: options?.map((value) => ({ value, label: OPTION_LABELS[value] ?? value })) ?? [],
    multiline: MULTILINE_KEYS.has(key),
    readOnly: READ_ONLY_KEYS.has(key),
    limits: NUMBER_LIMITS[key] ?? null,
    pattern: CODE_KEYS.has(key)
      ? "^[A-Z][A-Z0-9_.:-]{1,63}$"
      : REGION_KEYS.has(key)
        ? "^[A-Z0-9][A-Z0-9_-]{1,31}$"
        : OPAQUE_ID_KEYS.has(key)
          ? "^[A-Za-z0-9][A-Za-z0-9_-]{15,127}$"
          : ITEM_ID_KEYS.has(key)
            ? "^[a-z][a-z0-9_-]{0,63}$"
            : canonicalPath.endsWith("/currency")
              ? "^[A-Z]{3}$"
              : null,
  });
}

export function parseStructuredSection(resourceType, sectionPath, encoded) {
  if (!sectionPaths(resourceType).includes(sectionPath) || typeof encoded !== "string") {
    throw new TypeError("UNKNOWN_EDITOR_SECTION");
  }
  try {
    return JSON.parse(encoded);
  } catch {
    throw new TypeError("INVALID_SECTION_JSON");
  }
}

export function serializeStructuredSection(value) {
  return JSON.stringify(value, null, 2);
}

function applyChoiceDefault(value, resourceType, canonicalPath, configuration) {
  if (typeof value === "string") {
    const choice = resolveEditorChoice(configuration, resourceType, canonicalPath);
    if (!choice) return value;
    if (choice.status !== "AVAILABLE") throw new TypeError("CHOICE_UNAVAILABLE");
    return choice.options.some((option) => option.value === value)
      ? value
      : choice.options[0].value;
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) return value;
  return Object.fromEntries(Object.entries(value).map(([key, child]) => [
    key,
    applyChoiceDefault(child, resourceType, `${canonicalPath}/${key}`, configuration),
  ]));
}

export function arrayItemTemplate(resourceType, canonicalPath, current, configuration = null) {
  const key = canonicalArrayPath(resourceType, canonicalPath);
  if (!Object.hasOwn(ARRAY_TEMPLATES, key)) throw new TypeError("UNSUPPORTED_EDITOR_ARRAY");
  const template = itemIdentifierTemplate(ARRAY_TEMPLATES[key], canonicalPath, current);
  const index = Array.isArray(current) ? current.length : Number.isSafeInteger(current) ? current : 0;
  return applyChoiceDefault(template, resourceType, `${canonicalPath}/${index}`, configuration);
}

export function optionalValueTemplate(resourceType, canonicalPath) {
  const key = `${resourceType}:${canonicalPath}`;
  if (!Object.hasOwn(OPTIONAL_TEMPLATES, key)) throw new TypeError("UNSUPPORTED_OPTIONAL_FIELD");
  return clone(OPTIONAL_TEMPLATES[key]);
}

export function hasOptionalValueTemplate(resourceType, canonicalPath) {
  return Object.hasOwn(OPTIONAL_TEMPLATES, `${resourceType}:${canonicalPath}`);
}

function issue(issues, path, code) {
  issues.push({ path, code });
}

function validateChoiceValue(configuration, resourceType, value, path, issues) {
  const choice = resolveEditorChoice(configuration, resourceType, path);
  if (!choice) return;
  if (choice.status !== "AVAILABLE") {
    issue(issues, path, "CHOICE_UNAVAILABLE");
    return;
  }
  const pattern = CHOICE_VALUE_PATTERNS[choice.value_contract];
  if (!pattern?.test(value)) {
    issue(issues, path, "INVALID_FORMAT");
    return;
  }
  if (!choice.options.some((option) => option.value === value)) {
    issue(issues, path, "CHOICE_UNAVAILABLE");
  }
}

function validateValue(resourceType, value, path, key, issues, configuration) {
  if (value === null) {
    if (!hasOptionalValueTemplate(resourceType, path)) issue(issues, path, "VALUE_REQUIRED");
    return;
  }
  if (Array.isArray(value)) {
    const primitive = value.every((item) => ["string", "number", "boolean"].includes(typeof item));
    if (primitive && new Set(value.map((item) => JSON.stringify(item))).size !== value.length) {
      issue(issues, path, "DUPLICATE_ITEM");
    }
    const stableIds = value.map((item) => item && typeof item === "object"
      ? item.item_id ?? item.criterion_id ?? item.skill_code ?? null
      : null).filter(Boolean);
    if (new Set(stableIds).size !== stableIds.length) issue(issues, path, "DUPLICATE_ITEM");
    value.forEach((item, index) => validateValue(resourceType, item, `${path}/${index}`, key, issues, configuration));
    return;
  }
  if (typeof value === "object") {
    for (const [childKey, childValue] of Object.entries(value)) {
      validateValue(resourceType, childValue, `${path}/${childKey}`, childKey, issues, configuration);
    }
    if (value.source_kind === "VERIFIED_EVIDENCE" && (!Array.isArray(value.evidence_ids) || value.evidence_ids.length === 0)) {
      issue(issues, `${path}/evidence_ids`, "EVIDENCE_REQUIRED");
    }
    if (value.source_kind && value.source_kind !== "VERIFIED_EVIDENCE" && Array.isArray(value.evidence_ids) && value.evidence_ids.length) {
      issue(issues, `${path}/evidence_ids`, "EVIDENCE_NOT_ALLOWED");
    }
    if (value.required === true && value.allowed === false) issue(issues, `${path}/allowed`, "AI_MUST_BE_ALLOWED");
    if (value.requires_ai === true && value.allowed === false) issue(issues, `${path}/allowed`, "AI_MUST_BE_ALLOWED");
    if (value.allowed === true && Object.hasOwn(value, "data_model_policy") && !value.data_model_policy) {
      issue(issues, `${path}/data_model_policy`, "AI_POLICY_REQUIRED");
    }
    return;
  }
  if (typeof value === "string") {
    if (!value.trim()) issue(issues, path, "VALUE_REQUIRED");
    const choice = resolveEditorChoice(configuration, resourceType, path);
    const meta = fieldInputMeta(key, path, resourceType);
    if (value && choice) validateChoiceValue(configuration, resourceType, value, path, issues);
    else if (meta.pattern && value && !(new RegExp(meta.pattern)).test(value)) issue(issues, path, "INVALID_FORMAT");
    if (!choice && key === "timezone" && value && !/^[A-Za-z_+-]+(?:\/[A-Za-z0-9_+.-]+)+$/.test(value)) issue(issues, path, "INVALID_TIMEZONE");
    if (!choice && key === "language_code" && value && !/^[A-Za-z]{2,3}(?:-[A-Za-z0-9]{2,8})*$/.test(value)) issue(issues, path, "INVALID_LANGUAGE");
    return;
  }
  if (typeof value === "number") {
    const limits = NUMBER_LIMITS[key];
    if (!Number.isInteger(value) || (limits && (value < limits[0] || value > limits[1]))) issue(issues, path, "INVALID_NUMBER");
    return;
  }
  if (typeof value !== "boolean") issue(issues, path, "INVALID_VALUE");
}

function validateRelations(resourceType, sectionPath, value, issues) {
  if (resourceType !== "DEMAND" || !value || typeof value !== "object") return;
  if (sectionPath === "/schedule" && value.start_date && value.due_date && value.start_date > value.due_date) {
    issue(issues, "/schedule/due_date", "DUE_BEFORE_START");
  }
  if (sectionPath === "/budget" && value.minimum_amount_minor > value.maximum_amount_minor) {
    issue(issues, "/budget/maximum_amount_minor", "MAX_BELOW_MIN");
  }
  if (sectionPath === "/milestone_plan" && Array.isArray(value.items) && value.items.length
    && value.items.reduce((sum, item) => sum + (Number.isInteger(item.percent) ? item.percent : 0), 0) !== 100) {
    issue(issues, "/milestone_plan/items", "PERCENT_TOTAL_MUST_BE_100");
  }
  if (sectionPath === "/risk" && ["HIGH", "RESTRICTED"].includes(value.data_sensitivity) && !value.data_handling_plan) {
    issue(issues, "/risk/data_handling_plan", "DATA_PLAN_REQUIRED");
  }
}

function validateCrossSectionRelations(resourceType, sections, issues) {
  if (resourceType !== "DEMAND") return;
  const parsed = {};
  for (const [path, encoded] of Object.entries(sections)) {
    try {
      parsed[path] = parseStructuredSection(resourceType, path, encoded);
    } catch {
      // The section-level parser already reports this failure.
    }
  }
  const problem = parsed["/problem"];
  const matching = parsed["/matching"];
  if (problem?.domain_code && Array.isArray(matching?.domain_codes) && !matching.domain_codes.includes(problem.domain_code)) {
    issue(issues, "/matching/domain_codes", "PROBLEM_DOMAIN_NOT_MATCHED");
  }
  const skills = parsed["/skills"];
  if (skills && Array.isArray(skills.must_have) && Array.isArray(skills.nice_to_have)) {
    const required = new Set(skills.must_have.map((item) => item?.skill_code));
    if (skills.nice_to_have.some((item) => required.has(item?.skill_code))) {
      issue(issues, "/skills/nice_to_have", "SKILL_IN_BOTH_LISTS");
    }
  }
}

export function structuredSectionIssues(resourceType, sectionPath, encoded, configuration = null) {
  let value;
  try {
    value = parseStructuredSection(resourceType, sectionPath, encoded);
  } catch (error) {
    return [{ path: sectionPath, code: error instanceof Error ? error.message : "INVALID_SECTION_JSON" }];
  }
  const issues = [];
  validateValue(resourceType, value, sectionPath, sectionPath.slice(1), issues, configuration);
  validateRelations(resourceType, sectionPath, value, issues);
  return issues;
}

export function structuredContentIssues(resourceType, sections, configuration = null) {
  const paths = sectionPaths(resourceType);
  const issues = [];
  for (const path of missingEditorChoicePaths(configuration, resourceType)) {
    issue(issues, path, "CHOICE_CATALOG_UNAVAILABLE");
  }
  for (const path of paths) {
    if (!Object.hasOwn(sections, path)) issue(issues, path, "SECTION_REQUIRED");
    else issues.push(...structuredSectionIssues(resourceType, path, sections[path], configuration));
  }
  for (const path of Object.keys(sections)) if (!paths.includes(path)) issue(issues, path, "UNKNOWN_SECTION");
  validateCrossSectionRelations(resourceType, sections, issues);
  return issues;
}

export function issueMessage(code) {
  return ({
    VALUE_REQUIRED: "请填写此项",
    DUPLICATE_ITEM: "存在重复条目",
    EVIDENCE_REQUIRED: "选择“已有核验证据”时至少填写一个证据编号",
    EVIDENCE_NOT_ALLOWED: "只有“已有核验证据”可以填写证据编号",
    AI_MUST_BE_ALLOWED: "需要 AI 时必须先允许 AI",
    AI_POLICY_REQUIRED: "允许 AI 时必须写明数据与模型约束",
    INVALID_FORMAT: "格式不符合领域契约",
    INVALID_TIMEZONE: "请使用 IANA 时区，例如 Asia/Shanghai",
    INVALID_LANGUAGE: "请使用语言代码，例如 zh-CN",
    CHOICE_UNAVAILABLE: "这个值不在当前经审核的可选范围内，请重新选择或移除",
    CHOICE_CATALOG_UNAVAILABLE: "当前字段缺少经审核的可选目录，保存已关闭",
    INVALID_NUMBER: "数值超出允许范围",
    INVALID_VALUE: "值类型不正确",
    DUE_BEFORE_START: "截止日期不能早于开始日期",
    MAX_BELOW_MIN: "最高预算不能低于最低预算",
    PERCENT_TOTAL_MUST_BE_100: "里程碑占比合计必须为 100%",
    DATA_PLAN_REQUIRED: "高敏感度资料必须填写处理方案",
    PROBLEM_DOMAIN_NOT_MATCHED: "匹配领域必须包含问题所属领域",
    SKILL_IN_BOTH_LISTS: "同一技能不能同时出现在必须项和加分项",
    INVALID_SECTION_JSON: "这一分区的旧草稿无法读取，请采用服务器版本",
  })[code] ?? code;
}
