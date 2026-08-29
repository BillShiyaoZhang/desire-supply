import type {
  CurrentAccountTask,
  CurrentAccountTaskDiscovery,
  EditorResource,
  FinanceFundingQueueItem,
  FinanceFundingReview,
  ResourceType,
} from "./app-contract.mjs";

export type CurrentAccountTaskDestination =
  | Readonly<{ kind: "RESOURCE"; resource_type: ResourceType }>
  | Readonly<{ kind: "WORKBENCH"; element_id: string }>;

export function resolveAppealTaskReadKind(
  task: CurrentAccountTask,
): "OWN" | "ASSIGNED" | "HISTORY" | null;

export type FinanceTaskDetailAction =
  | "CONTINUE_FINANCE_REVIEW"
  | "WAIT_FOR_FINANCE_CONFIRMATION";

export function resolveFinanceTaskDetailAction(
  task: CurrentAccountTask,
): FinanceTaskDetailAction | null;

export function resolveCurrentAccountTaskDestination(
  task: CurrentAccountTask,
): CurrentAccountTaskDestination;

export function resolveRevalidatedCurrentAccountTask(
  task: CurrentAccountTask,
  discovery: CurrentAccountTaskDiscovery,
): CurrentAccountTask | null;

export function resolveRevalidatedCurrentAccountTaskResource(
  task: CurrentAccountTask,
  discovery: CurrentAccountTaskDiscovery,
  resources: readonly EditorResource[],
): EditorResource | null;

export function resolveRevalidatedFinanceTaskQueueItem(
  task: CurrentAccountTask,
  discovery: CurrentAccountTaskDiscovery,
  queueItems: readonly FinanceFundingQueueItem[],
): {
  action: FinanceTaskDetailAction;
  queue_item: FinanceFundingQueueItem;
  task: CurrentAccountTask;
} | null;

export function resolveFinanceTaskDetail(
  task: CurrentAccountTask,
  queueItem: FinanceFundingQueueItem,
  review: FinanceFundingReview,
  responseEtag: string | null,
): FinanceFundingReview | null;
