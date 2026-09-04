const UUID = /^(?!0{8}-0{4}-0{4}-0{4}-0{12})[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const CURSOR = /^[A-Za-z0-9_-]{64,1024}\.[A-Za-z0-9_-]{43}$/;
const CODE = /^[A-Za-z][A-Za-z0-9_]{0,95}$/;
const STAGES = ["INTAKE", "REVIEW", "FUNDING", "MATCHING", "SELECTION", "AGREEMENT", "DELIVERY", "SETTLEMENT"];
const STAGE_STATUSES = ["PENDING", "IN_PROGRESS", "COMPLETED", "BLOCKED", "NOT_IMPLEMENTED", "CANCELLED"];
const DEMAND_STATUSES = ["DRAFT", "SUBMITTED", "NEEDS_CHANGES", "VERIFIED", "FUNDING_PENDING", "FUNDED", "MATCHING", "MATCHED", "NO_MATCH", "CANCELLED", "EXPIRED"];
const SOURCES = ["DEMAND", "FINANCE", "MATCHING", "TRUST"];
const ROLES = ["DEMAND_OWNER", "OPERATIONS_REVIEWER", "FINANCE_OPERATOR", "CREATOR", "CANDIDATE_SELECTOR", "TRUST_OFFICER", "APPEAL_REVIEWER", "SYSTEM", "UNKNOWN", "ACCESS_ADMIN", "PLATFORM_ADMIN", "ORG_ADMIN"];
const BLOCKERS = {
  WAITING_FOR_SUBMISSION: "等待需求方提交审核",
  WAITING_FOR_REVIEWER: "等待审核员处理",
  REVIEW_CHANGES_REQUIRED: "需求需要修改后重新提交",
  WAITING_FOR_FINANCE_REVIEW: "等待资金审核",
  WAITING_FOR_SECOND_FINANCE_CONFIRMATION: "等待第二位资金审核员确认",
  FUNDING_DISCREPANCY: "资金核验发现差异，需补充或修正",
  FUNDING_REJECTED: "资金审核未通过",
  WAITING_FOR_MATCHING_WORKER: "等待匹配任务运行",
  WAITING_FOR_SYSTEM_MATCHING_REQUEST: "等待系统发起匹配",
  MATCHING_JOB_FAILED: "匹配任务执行失败",
  NO_ELIGIBLE_CREATORS: "未找到符合条件的创作者",
  NO_SELECTION_AVAILABLE: "本轮匹配未产生可选人选",
  WAITING_FOR_INVITATION_RESPONSE: "等待创作者回应邀请",
  WAITING_FOR_SELECTOR: "等待需求方选择合作人选",
  SAFETY_HOLD_ACTIVE: "安全暂停尚未解除",
  AGREEMENT_NOT_IMPLEMENTED: "项目与合同环节尚未接入",
  DELIVERY_NOT_IMPLEMENTED: "交付与验收环节尚未接入",
  SETTLEMENT_NOT_IMPLEMENTED: "结算环节尚未接入",
  DEMAND_CANCELLED: "需求已取消",
  DEMAND_EXPIRED: "需求已到期",
};
const DETAIL_LABELS = {
  before_status: "操作前状态",
  after_status: "操作后状态",
  reason_code: "原因",
  before_version: "操作前版本",
  after_version: "操作后版本",
  target_kind: "操作对象类型",
  target_id: "操作对象编号",
  result_code: "处理结果",
  original_actor_user_id: "原参与人编号",
};
export const ADMIN_DEMAND_STAGE_LABELS = Object.freeze({
  INTAKE: "需求录入", REVIEW: "需求审核", FUNDING: "资金核验", MATCHING: "匹配与邀请",
  SELECTION: "选择合作方", AGREEMENT: "项目与协议", DELIVERY: "实施与验收", SETTLEMENT: "结算",
});

export function adminDemandStatusLabel(code) {
  return ({
    DRAFT: "草稿", SUBMITTED: "已提交审核", NEEDS_CHANGES: "需要修改", VERIFIED: "审核通过",
    FUNDING_PENDING: "资金核验中", FUNDED: "资金核验完成", MATCHING: "匹配中", MATCHED: "已选定合作方",
    NO_MATCH: "未找到人选", CANCELLED: "已取消", EXPIRED: "已到期", PENDING: "尚未开始",
    IN_PROGRESS: "进行中", COMPLETED: "已完成", BLOCKED: "等待处理", NOT_IMPLEMENTED: "尚未接入",
    ACCEPTED: "已接受", DECLINED: "已拒绝", SELECTED: "已选定", SENT: "已发送", SUCCEEDED: "成功",
    OPEN: "进行中", ACTIVE: "已领取", CREATED: "已创建", QUEUED: "排队中", RUNNING: "运行中",
    REVOKED: "已释放", WITHDRAWN: "已撤回", PENDING_CHOICE: "等待系统确认", FAILED: "失败",
    CLOSED_NO_SELECTION: "未选定合作方", INVALIDATED: "已失效", SECURED: "凭据核验完成",
    DISCREPANCY: "核验存在差异", REJECTED: "核验未通过", RECORDED: "已记录",
  })[code] ?? code;
}
export function adminDemandRoleLabel(code) {
  return ({
    DEMAND_OWNER: "需求负责人", OPERATIONS_REVIEWER: "需求审核员", FINANCE_OPERATOR: "资金审核员",
    CREATOR: "创作者", CANDIDATE_SELECTOR: "人选确认人", TRUST_OFFICER: "安全处理员",
    APPEAL_REVIEWER: "申诉审核员", SYSTEM: "自动处理", UNKNOWN: "角色未记录",
    ACCESS_ADMIN: "平台管理员", PLATFORM_ADMIN: "平台管理员", ORG_ADMIN: "组织管理员",
  })[code] ?? code;
}
export function adminDemandBlockerLabel(code) { return BLOCKERS[code] ?? code; }
export function adminDemandDetailLabel(code) { return DETAIL_LABELS[code] ?? code; }
export function adminDemandDetailValue(name, value) {
  if (value === null) return "未记录";
  if (typeof value !== "string") return Array.isArray(value) ? value.join("、") : typeof value === "boolean" ? value ? "是" : "否" : String(value);
  if (["before_status", "after_status", "result_code"].includes(name)) return adminDemandStatusLabel(value);
  if (name === "reason_code") {
    const reasons = {
      SCOPE_UNCLEAR: "范围不清晰", ACCEPTANCE_UNCLEAR: "验收标准不清晰", CONTENT_INCOMPLETE: "内容不完整",
      BUDGET_UNHEALTHY: "预算需调整", RISK_UNRESOLVED: "风险未解决", DATA_PLAN_REQUIRED: "缺少数据计划",
      LEASE_EXPIRED: "处理任务超时",
    };
    return value.split(",").map((code) => reasons[code.trim()] ?? code.trim()).join("、");
  }
  if (name === "target_kind") return ({
    Demand: "需求", DemandVersion: "需求版本", DemandReviewAssignment: "需求审核任务",
    WorkflowFact: "流程记录", MatchingDelivery: "匹配请求派送", Invitation: "合作邀请",
    MatchingAttempt: "匹配轮次", MatchRun: "匹配计算", Selection: "合作方选择",
    CandidateSelectorAssignment: "合作方选择任务",
  })[value] ?? value;
  return value;
}

function invalid(code = "INVALID_ADMIN_DEMAND_CONTRACT") { throw new TypeError(code); }
function exact(value, keys) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || Object.keys(value).length !== keys.length || keys.some((key) => !Object.hasOwn(value, key))) invalid();
  return value;
}
function text(value, max = 1000) {
  if (typeof value !== "string" || value.length === 0 || value.length > max
    || [...value].some((char) => { const point = char.codePointAt(0); return point === 127 || (point < 32 && ![9, 10, 13].includes(point)); })) invalid();
  return value;
}
function id(value) { if (typeof value !== "string" || !UUID.test(value)) invalid(); return value; }
function enumeration(value, choices) { if (!choices.includes(value)) invalid(); return value; }
function integer(value, minimum = 0) { if (!Number.isSafeInteger(value) || value < minimum) invalid(); return value; }
function timestamp(value) {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|\+00:00)$/.test(value) || !Number.isFinite(Date.parse(value))) invalid();
  return value;
}
function list(value, parser, maximum = 10000) {
  if (!Array.isArray(value) || value.length > maximum) invalid();
  return value.map(parser);
}
function unique(values) { if (new Set(values).size !== values.length) invalid(); return values; }
function blockers(value) { return unique(list(value, (code) => enumeration(code, Object.keys(BLOCKERS)), 32)); }
function pagination(value) {
  if (typeof value.has_more !== "boolean"
    || (value.next_cursor !== null && (typeof value.next_cursor !== "string" || !CURSOR.test(value.next_cursor)))
    || value.has_more !== (value.next_cursor !== null)) invalid();
}
function summary(value, workspaceId) {
  const result = exact(value, ["demand_id", "organization_id", "title", "status", "aggregate_version", "created_at", "updated_at", "expires_at", "current_stage", "blocker_codes"]);
  id(result.demand_id); id(result.organization_id); text(result.title); enumeration(result.status, DEMAND_STATUSES);
  integer(result.aggregate_version, 1); timestamp(result.created_at); timestamp(result.updated_at); timestamp(result.expires_at);
  enumeration(result.current_stage, STAGES); blockers(result.blocker_codes);
  if (workspaceId?.startsWith("org:") && result.organization_id !== workspaceId.slice(4)) invalid();
  return result;
}

export function canInspectDemandTimeline(workspace) {
  return Boolean(workspace && (
    (workspace.workspace_kind === "PLATFORM" && workspace.role_codes.includes("ACCESS_ADMIN"))
    || (workspace.workspace_kind === "ORGANIZATION" && workspace.role_codes.includes("ORG_ADMIN"))
  ));
}

export function parseAdminDemandCollection(value, workspaceId) {
  const result = exact(exact(value, ["data"]).data, ["items", "next_cursor", "has_more"]);
  const items = list(result.items, (item) => summary(item, workspaceId), 100);
  unique(items.map((item) => item.demand_id));
  pagination(result);
  return structuredClone(result);
}

export function parseAdminDemandTimeline(value, expectedDemandId, workspaceId) {
  const result = exact(exact(value, ["data"]).data, ["demand", "generated_at", "stages", "participants", "events", "coverage", "next_cursor", "has_more"]);
  summary(result.demand, workspaceId);
  if (expectedDemandId !== undefined && result.demand.demand_id !== expectedDemandId) invalid();
  timestamp(result.generated_at);
  const participants = list(result.participants, (value) => {
    const person = exact(value, ["user_id", "display_name", "roles"]);
    id(person.user_id);
    if (person.display_name !== null) text(person.display_name, 160);
    unique(list(person.roles, (role) => enumeration(role, ROLES), ROLES.length));
    return person;
  });
  const participantIds = new Set(unique(participants.map((person) => person.user_id)));
  const stages = list(result.stages, (value) => {
    const stage = exact(value, ["code", "label", "status", "participant_ids", "event_count", "blocker_codes"]);
    enumeration(stage.code, STAGES); enumeration(stage.status, STAGE_STATUSES); text(stage.label, 120);
    unique(list(stage.participant_ids, (value) => { id(value); if (!participantIds.has(value)) invalid(); return value; }));
    integer(stage.event_count); blockers(stage.blocker_codes);
    if (["AGREEMENT", "DELIVERY", "SETTLEMENT"].includes(stage.code) && stage.status !== "NOT_IMPLEMENTED") invalid();
    return stage;
  }, STAGES.length);
  if (stages.length !== STAGES.length || stages.some((stage, index) => stage.code !== STAGES[index])) invalid();
  const events = list(result.events, (value) => {
    const event = exact(value, ["event_id", "stage", "source", "action", "actor_user_id", "actor_role", "occurred_at", "summary", "details"]);
    id(event.event_id); enumeration(event.stage, STAGES); enumeration(event.source, SOURCES);
    if (!CODE.test(event.action)) invalid();
    enumeration(event.actor_role, ROLES); timestamp(event.occurred_at); text(event.summary, 2000);
    if (event.actor_user_id !== null) {
      id(event.actor_user_id);
      if (!participantIds.has(event.actor_user_id) || !stages.find((stage) => stage.code === event.stage).participant_ids.includes(event.actor_user_id)) invalid();
    }
    if (!event.details || typeof event.details !== "object" || Array.isArray(event.details)) invalid();
    for (const [key, detail] of Object.entries(event.details)) {
      if (!Object.hasOwn(DETAIL_LABELS, key)) invalid();
      if (detail === null) continue;
      if (["before_version", "after_version"].includes(key)) integer(detail);
      else if (key === "original_actor_user_id") id(detail);
      else text(detail, 240);
    }
    return event;
  }, 100);
  unique(events.map((event) => event.event_id));
  if (events.some((event, index) => index > 0 && !eventAfter(event, events[index - 1]))) invalid();
  if (stages.some((stage) => stage.event_count < events.filter((event) => event.stage === stage.code).length)) invalid();
  const coverage = list(result.coverage, (value) => {
    const item = exact(value, ["source", "status", "description"]);
    enumeration(item.source, [...SOURCES, "AGREEMENT", "DELIVERY", "SETTLEMENT"]);
    enumeration(item.status, ["COMPLETE", "PARTIAL", "NOT_IMPLEMENTED"]);
    text(item.description, 2000);
    if (["AGREEMENT", "DELIVERY", "SETTLEMENT"].includes(item.source) && item.status !== "NOT_IMPLEMENTED") invalid();
    return item;
  }, 7);
  unique(coverage.map((item) => item.source));
  if (!["AGREEMENT", "DELIVERY", "SETTLEMENT"].every((source) => coverage.some((item) => item.source === source))) invalid();
  pagination(result);
  return structuredClone(result);
}

export function mergeAdminDemandCollection(prior, next) {
  if (!prior.has_more || prior.next_cursor === next.next_cursor) invalid("ADMIN_DEMAND_PAGE_MISMATCH");
  const items = [...prior.items, ...next.items];
  unique(items.map((item) => item.demand_id));
  return { ...next, items };
}

export function mergeAdminDemandTimeline(prior, next) {
  for (const key of ["demand", "stages", "participants", "coverage"]) {
    if (JSON.stringify(prior[key]) !== JSON.stringify(next[key])) invalid("ADMIN_DEMAND_TIMELINE_CHANGED");
  }
  if (!prior.has_more || prior.next_cursor === next.next_cursor) invalid("ADMIN_DEMAND_PAGE_MISMATCH");
  const events = [...prior.events, ...next.events];
  unique(events.map((event) => event.event_id));
  if (next.events.length && prior.events.length && !eventAfter(next.events[0], prior.events[prior.events.length - 1])) invalid("ADMIN_DEMAND_PAGE_MISMATCH");
  return { ...next, events };
}

function eventAfter(left, right) {
  const micros = (value) => BigInt(Date.parse(value)) * 1000n
    + BigInt((value.match(/\.(\d+)/)?.[1] ?? "").padEnd(6, "0").slice(3));
  const a = micros(left.occurred_at);
  const b = micros(right.occurred_at);
  return a > b || (a === b && left.event_id > right.event_id);
}
