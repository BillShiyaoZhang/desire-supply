const RESOURCE = (resourceType) => Object.freeze({
  kind: "RESOURCE",
  resource_type: resourceType,
});

const WORKBENCH = (elementId) => Object.freeze({
  kind: "WORKBENCH",
  element_id: elementId,
});

const PROFILE = RESOURCE("CREATOR_PROFILE");
const DEMAND = RESOURCE("DEMAND");
const APPEAL = WORKBENCH("appeal-workbench-title");
const APPEAL_REVIEW_HISTORY = WORKBENCH("appeal-review-history-title");
const DEMAND_REVIEW_QUEUE = WORKBENCH("review-queue-title");
const DEMAND_REVIEW_HISTORY = WORKBENCH("review-history-title");
const FINANCE = WORKBENCH("finance-funding-queue-title");
const FINANCE_DETAIL = WORKBENCH("finance-funding-title");
const TRUST = WORKBENCH("trust-workbench-title");
const TRUST_CASE_HISTORY = WORKBENCH("trust-case-history-title");

const DESTINATIONS = new Map([
  ["APPEAL:EDIT_APPEAL", APPEAL],
  ["APPEAL:VIEW_APPEAL_HISTORY", APPEAL],
  ["APPEAL:WAIT_FOR_APPEAL_REVIEW", APPEAL],
  ["APPEAL_REVIEW:CLAIM_APPEAL_REVIEW", APPEAL],
  ["APPEAL_REVIEW:REVIEW_ASSIGNED_APPEAL", APPEAL],
  ["APPEAL_REVIEW:VIEW_APPEAL_REVIEW_HISTORY", APPEAL_REVIEW_HISTORY],
  ["CREATOR_PROFILE:VIEW_CREATOR_PROFILE", PROFILE],
  ["DEMAND:EDIT_OR_SUBMIT_DEMAND", DEMAND],
  ["DEMAND:VIEW_DEMAND_HISTORY", DEMAND],
  ["DEMAND:WAIT_FOR_DEMAND_PROCESSING", DEMAND],
  ["DEMAND_REVIEW:CLAIM_DEMAND_REVIEW", DEMAND_REVIEW_QUEUE],
  ["DEMAND_REVIEW:REVIEW_ASSIGNED_DEMAND", DEMAND],
  ["DEMAND_REVIEW:VIEW_DEMAND_REVIEW_HISTORY", DEMAND_REVIEW_HISTORY],
  ["DEMAND_REVIEW:WAIT_FOR_DEMAND_PROCESSING", DEMAND],
  ["FINANCE_FUNDING_REVIEW:CLAIM_FINANCE_REVIEW", FINANCE],
  ["FINANCE_FUNDING_REVIEW:CONTINUE_FINANCE_REVIEW", FINANCE_DETAIL],
  ["FINANCE_FUNDING_REVIEW:WAIT_FOR_FINANCE_CONFIRMATION", FINANCE_DETAIL],
  ["TRUST_CASE:CLAIM_TRUST_CASE", TRUST],
  ["TRUST_CASE:REVIEW_ASSIGNED_TRUST_CASE", TRUST],
  ["TRUST_CASE:VIEW_TRUST_CASE_HISTORY", TRUST_CASE_HISTORY],
  ["TRUST_HOLD_RELEASE:CLAIM_TRUST_HOLD_RELEASE", TRUST],
  ["TRUST_HOLD_RELEASE:REVIEW_ASSIGNED_TRUST_HOLD_RELEASE", TRUST],
  ["TRUST_REPORT:VIEW_TRUST_REPORT_HISTORY", TRUST],
  ["TRUST_REPORT:WAIT_FOR_TRUST_REVIEW", TRUST],
]);

export function resolveAppealTaskReadKind(task) {
  if (task?.resource_kind === "APPEAL") {
    return new Set([
      "EDIT_APPEAL",
      "VIEW_APPEAL_HISTORY",
      "WAIT_FOR_APPEAL_REVIEW",
    ]).has(task.next_action)
      ? "OWN"
      : null;
  }
  if (task?.resource_kind !== "APPEAL_REVIEW") return null;
  if (task.next_action === "REVIEW_ASSIGNED_APPEAL") return "ASSIGNED";
  if (task.next_action === "VIEW_APPEAL_REVIEW_HISTORY") return "HISTORY";
  return null;
}

export function resolveFinanceTaskDetailAction(task) {
  if (task?.resource_kind !== "FINANCE_FUNDING_REVIEW") return null;
  if (
    task.next_action === "CONTINUE_FINANCE_REVIEW"
    && task.classification === "NEEDS_ACTION"
    && task.source_status === "PENDING"
  ) return task.next_action;
  if (
    task.next_action === "WAIT_FOR_FINANCE_CONFIRMATION"
    && task.classification === "WAITING"
    && new Set(["PENDING", "SECURED", "DISCREPANCY", "REJECTED"]).has(task.source_status)
  ) return task.next_action;
  return null;
}

export function resolveCurrentAccountTaskDestination(task) {
  const destination = DESTINATIONS.get(`${task?.resource_kind}:${task?.next_action}`);
  if (!destination) throw new TypeError("INVALID_CURRENT_ACCOUNT_TASK_DESTINATION");
  return destination;
}

export function resolveRevalidatedCurrentAccountTask(task, discovery) {
  const expected = resolveCurrentAccountTaskDestination(task);
  if (!Array.isArray(discovery?.items)) {
    throw new TypeError("INVALID_CURRENT_ACCOUNT_TASK_RECHECK");
  }
  const refreshed = discovery.items.find((item) => (
    item?.resource_kind === task.resource_kind
    && item?.resource_id === task.resource_id
    && item?.next_action === task.next_action
  ));
  if (!refreshed) return null;
  const current = resolveCurrentAccountTaskDestination(refreshed);
  const sameDestination = current.kind === expected.kind
    && (current.kind === "RESOURCE"
      ? current.resource_type === expected.resource_type
      : current.element_id === expected.element_id);
  return sameDestination ? refreshed : null;
}

export function resolveRevalidatedCurrentAccountTaskResource(task, discovery, resources) {
  const expected = resolveCurrentAccountTaskDestination(task);
  if (expected.kind !== "RESOURCE" || !Array.isArray(discovery?.items) || !Array.isArray(resources)) {
    throw new TypeError("INVALID_CURRENT_ACCOUNT_TASK_RESOURCE_RECHECK");
  }
  const refreshed = resolveRevalidatedCurrentAccountTask(task, discovery);
  if (!refreshed) return null;
  const current = resolveCurrentAccountTaskDestination(refreshed);
  if (current.kind !== "RESOURCE" || current.resource_type !== expected.resource_type) return null;
  return resources.find((resource) => (
    resource?.resource_type === current.resource_type
    && resource?.object_id === refreshed.resource_id
  )) ?? null;
}

export function resolveRevalidatedFinanceTaskQueueItem(task, discovery, queueItems) {
  const expectedAction = resolveFinanceTaskDetailAction(task);
  if (!expectedAction || !Array.isArray(queueItems)) {
    throw new TypeError("INVALID_FINANCE_TASK_QUEUE_RECHECK");
  }
  const refreshedTask = resolveRevalidatedCurrentAccountTask(task, discovery);
  if (!refreshedTask || resolveFinanceTaskDetailAction(refreshedTask) !== expectedAction) {
    return null;
  }
  const candidates = queueItems.filter((item) => (
    item?.assigned_to_me === true
    && item?.review_status === "PENDING"
    && item?.funding_review_id === refreshedTask.resource_id
  ));
  if (candidates.length !== 1) return null;
  return { action: expectedAction, queue_item: candidates[0], task: refreshedTask };
}

export function resolveFinanceTaskDetail(task, queueItem, review, responseEtag) {
  const action = resolveFinanceTaskDetailAction(task);
  if (!action) {
    throw new TypeError("INVALID_FINANCE_TASK_DETAIL_RECHECK");
  }
  if (typeof responseEtag !== "string") return null;
  const actionsMatch = action === "CONTINUE_FINANCE_REVIEW"
    ? Array.isArray(review?.available_actions) && review.available_actions.length > 0
    : Array.isArray(review?.available_actions) && review.available_actions.length === 0;
  if (
    queueItem?.assigned_to_me !== true
    || queueItem?.review_status !== "PENDING"
    || queueItem?.funding_review_id !== task.resource_id
    || review?.funding_review_id !== task.resource_id
    || review?.demand_id !== queueItem.demand_id
    || review?.demand_version_id !== queueItem.demand_version_id
    || review?.revision !== queueItem.review_revision
    || review?.status !== task.source_status
    || review?.confirmation_count !== queueItem.confirmation_count
    || review?.required_confirmations !== queueItem.required_confirmations
    || review?.assignment_expires_at !== queueItem.expires_at
    || review?.etag !== queueItem.etag
    || responseEtag !== review?.etag
    || !actionsMatch
    || review?.can_confirm !== review.available_actions.includes("CONFIRM")
  ) return null;
  return review;
}
