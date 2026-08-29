export interface PersonaSummary {
  persona_id: string;
  display_name: string;
  workspace_label: string;
  summary: string;
}

export interface PersonasResponse { personas: PersonaSummary[] }

export interface WorkspaceSummary {
  workspace_id: string;
  label: string;
  kind: string;
  authorities: string[];
}

export interface TaskSummary {
  task_id: string;
  title: string;
  summary: string;
  status: string;
  due_at: string | null;
  object_id: string;
  object_type: string;
  authority: string;
  allowed_operations: string[];
}

export interface WorkflowStage { stage: string; label: string; status: string }
export interface ObjectFact { label: string; value: string }
export interface TimelineEvent {
  event_id: string;
  label: string;
  occurred_at: string;
  actor_label: string;
  authority: string;
  detail: string;
}

export interface ObjectProjection {
  object_id: string;
  type: string;
  title: string;
  status: string;
  version: number;
  facts: ObjectFact[];
  timeline: TimelineEvent[];
}

export interface OperationFieldOption { value: string; label: string }
export interface OperationField {
  name: string;
  label: string;
  type: string;
  required: boolean;
  options?: OperationFieldOption[];
}
export interface AllowedOperation {
  operation: string;
  label: string;
  kind: string;
  fields: OperationField[];
}

export interface BootstrapResponse {
  session: { session_id: string; persona_id: string; expires_at: string };
  user: { user_id: string; display_name: string };
  workspaces: WorkspaceSummary[];
  current_workspace_id: string;
  tasks: TaskSummary[];
  workflow: { current_stage: string; stages: WorkflowStage[] };
  object: ObjectProjection | null;
  allowed_operations: AllowedOperation[];
  csrf: string;
  revision: number;
}

export interface ActionIntent {
  operation: string;
  expected_revision: number;
  idempotency_key: string;
  input: Record<string, unknown>;
}

export function parsePersonas(value: unknown): PersonasResponse;
export function parseBootstrap(value: unknown): BootstrapResponse;
export function createSessionIntent(personaId: string): { persona_id: string };
export function createActionIntent(value: {
  operation: string;
  expectedRevision: number;
  idempotencyKey: string;
  input: Record<string, unknown>;
  allowedOperations: AllowedOperation[];
}): ActionIntent;
export function createResetIntent(value: {
  expectedRevision: number;
  idempotencyKey: string;
}): {
  fixture_id: "scn-g1-001-happy-v1";
  expected_revision: number;
  idempotency_key: string;
};
