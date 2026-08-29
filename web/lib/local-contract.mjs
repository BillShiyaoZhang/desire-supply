const FORBIDDEN_ACTION_FIELDS = new Set([
  "actor",
  "actor_id",
  "authority",
  "organization",
  "organization_id",
  "workspace_id",
  "persona_id",
  "session_id",
  "user_id",
]);

const PERSONA_IDS = new Set([
  "creator-chen",
  "demand-owner",
  "acceptance-beneficiary",
  "case-operator",
  "payment-initiator",
  "finance-reconciler",
  "appeal-reviewer",
]);

const OPERATION_IDS = new Set([
  "accept_consent",
  "publish_profile",
  "submit_demand",
  "review_demand",
  "request_demand_funding",
  "reconcile_demand_funding",
  "run_matching",
  "respond_invitation",
  "complete_selection",
  "accept_agreement",
  "request_milestone_funding",
  "reconcile_milestone_funding",
  "start_project",
  "submit_delivery",
  "decide_delivery",
  "confirm_outcome",
  "request_payment",
  "advance_payment_provider",
  "reconcile_payment",
  "record_outcome",
  "submit_report",
  "decide_safety",
  "decide_appeal",
  "request_data_right",
  "exit_participation",
]);

const TASK_STATUSES = new Set(["NEEDS_ACTION", "WAITING", "BLOCKED", "VERIFYING", "DONE"]);
const STAGE_STATUSES = new Set(["CURRENT", "COMPLETED", "UPCOMING"]);
const FIELD_TYPES = new Set(["text", "multiline", "choice"]);

function invalid() {
  throw new TypeError("INVALID_LOCAL_CONTRACT");
}

function record(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function exact(value, keys) {
  if (!record(value)) invalid();
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((item, index) => item !== expected[index])) invalid();
}

function text(value) {
  return typeof value === "string" && value.trim().length > 0;
}

function optionalText(value) {
  return value === null || text(value);
}

function stringList(value) {
  return Array.isArray(value) && value.every(text);
}

function validatePersona(value) {
  exact(value, ["persona_id", "display_name", "workspace_label", "summary"]);
  if (![value.persona_id, value.display_name, value.workspace_label, value.summary].every(text) || !PERSONA_IDS.has(value.persona_id)) invalid();
}

function validateTask(value) {
  exact(value, ["task_id", "title", "summary", "status", "due_at", "object_id", "object_type", "authority", "allowed_operations"]);
  if (![value.task_id, value.title, value.summary, value.status, value.object_id, value.object_type, value.authority].every(text) || !TASK_STATUSES.has(value.status)) invalid();
  if (!optionalText(value.due_at) || !stringList(value.allowed_operations) || !value.allowed_operations.every((item) => OPERATION_IDS.has(item))) invalid();
}

function validateStage(value) {
  exact(value, ["stage", "label", "status"]);
  if (![value.stage, value.label, value.status].every(text) || !STAGE_STATUSES.has(value.status)) invalid();
}

function validateFact(value) {
  exact(value, ["label", "value"]);
  if (![value.label, value.value].every(text)) invalid();
}

function validateTimelineEvent(value) {
  exact(value, ["event_id", "label", "occurred_at", "actor_label", "authority", "detail"]);
  if (![value.event_id, value.label, value.occurred_at, value.actor_label, value.authority, value.detail].every(text)) invalid();
}

function validateFieldOption(value) {
  exact(value, ["value", "label"]);
  if (![value.value, value.label].every(text)) invalid();
}

function validateField(value) {
  const keys = Object.prototype.hasOwnProperty.call(value ?? {}, "options")
    ? ["name", "label", "type", "required", "options"]
    : ["name", "label", "type", "required"];
  exact(value, keys);
  if (![value.name, value.label, value.type].every(text) || !FIELD_TYPES.has(value.type) || typeof value.required !== "boolean") invalid();
  if (value.type === "choice" && (!("options" in value) || value.options.length === 0)) invalid();
  if (value.type !== "choice" && "options" in value) invalid();
  if ("options" in value && (!Array.isArray(value.options) || !value.options.every((item) => {
    try { validateFieldOption(item); return true; } catch { return false; }
  }))) invalid();
}

function validateOperation(value) {
  exact(value, ["operation", "label", "kind", "fields"]);
  if (![value.operation, value.label, value.kind].every(text) || !OPERATION_IDS.has(value.operation) || !Array.isArray(value.fields)) invalid();
  value.fields.forEach(validateField);
}

export function parsePersonas(value) {
  exact(value, ["personas"]);
  if (!Array.isArray(value.personas) || value.personas.length === 0) invalid();
  value.personas.forEach(validatePersona);
  return value;
}

export function parseBootstrap(value) {
  exact(value, ["session", "user", "workspaces", "current_workspace_id", "tasks", "workflow", "object", "allowed_operations", "csrf", "revision"]);
  exact(value.session, ["session_id", "persona_id", "expires_at"]);
  if (![value.session.session_id, value.session.persona_id, value.session.expires_at].every(text)) invalid();
  exact(value.user, ["user_id", "display_name"]);
  if (![value.user.user_id, value.user.display_name].every(text)) invalid();
  if (!Array.isArray(value.workspaces) || value.workspaces.length === 0) invalid();
  value.workspaces.forEach((workspace) => {
    exact(workspace, ["workspace_id", "label", "kind", "authorities"]);
    if (![workspace.workspace_id, workspace.label, workspace.kind].every(text) || !stringList(workspace.authorities)) invalid();
  });
  if (!text(value.current_workspace_id) || !value.workspaces.some((item) => item.workspace_id === value.current_workspace_id)) invalid();
  if (!Array.isArray(value.tasks)) invalid();
  value.tasks.forEach(validateTask);
  exact(value.workflow, ["current_stage", "stages"]);
  if (!text(value.workflow.current_stage) || !Array.isArray(value.workflow.stages)) invalid();
  value.workflow.stages.forEach(validateStage);
  if (value.object !== null) {
    exact(value.object, ["object_id", "type", "title", "status", "version", "facts", "timeline"]);
    if (![value.object.object_id, value.object.type, value.object.title, value.object.status].every(text)) invalid();
    if (!Number.isSafeInteger(value.object.version) || value.object.version < 0) invalid();
    if (!Array.isArray(value.object.facts) || !Array.isArray(value.object.timeline)) invalid();
    value.object.facts.forEach(validateFact);
    value.object.timeline.forEach(validateTimelineEvent);
  }
  if (!Array.isArray(value.allowed_operations)) invalid();
  value.allowed_operations.forEach(validateOperation);
  if (!text(value.csrf) || !Number.isSafeInteger(value.revision) || value.revision < 0) invalid();
  return value;
}

export function createSessionIntent(personaId) {
  if (typeof personaId !== "string" || !PERSONA_IDS.has(personaId)) {
    throw new TypeError("INVALID_PERSONA_ID");
  }
  return { persona_id: personaId };
}

function inspectForbidden(value) {
  if (Array.isArray(value)) {
    value.forEach(inspectForbidden);
    return;
  }
  if (!record(value)) return;
  for (const [key, child] of Object.entries(value)) {
    if (FORBIDDEN_ACTION_FIELDS.has(key)) throw new TypeError("FORBIDDEN_ACTION_FIELD");
    inspectForbidden(child);
  }
}

export function createActionIntent({ operation, expectedRevision, idempotencyKey, input, allowedOperations }) {
  if (!Array.isArray(allowedOperations) || !allowedOperations.some((item) => item?.operation === operation)) {
    throw new TypeError("OPERATION_NOT_ALLOWED");
  }
  if (!text(operation) || !Number.isSafeInteger(expectedRevision) || expectedRevision < 0) {
    throw new TypeError("INVALID_ACTION_INTENT");
  }
  if (typeof idempotencyKey !== "string" || !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(idempotencyKey)) {
    throw new TypeError("INVALID_IDEMPOTENCY_KEY");
  }
  if (!record(input)) throw new TypeError("INVALID_ACTION_INPUT");
  inspectForbidden(input);
  return {
    operation,
    expected_revision: expectedRevision,
    idempotency_key: idempotencyKey,
    input,
  };
}

export function createResetIntent({ expectedRevision, idempotencyKey }) {
  if (!Number.isSafeInteger(expectedRevision) || expectedRevision < 0) {
    throw new TypeError("INVALID_RESET_INTENT");
  }
  if (typeof idempotencyKey !== "string" || !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(idempotencyKey)) {
    throw new TypeError("INVALID_IDEMPOTENCY_KEY");
  }
  return {
    fixture_id: "scn-g1-001-happy-v1",
    expected_revision: expectedRevision,
    idempotency_key: idempotencyKey,
  };
}
