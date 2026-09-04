import type { WorkspaceCandidate } from "./app-contract.mjs";

export type AdminDemandStageCode = "INTAKE" | "REVIEW" | "FUNDING" | "MATCHING" | "SELECTION" | "AGREEMENT" | "DELIVERY" | "SETTLEMENT";
export type AdminDemandStageStatus = "PENDING" | "IN_PROGRESS" | "COMPLETED" | "BLOCKED" | "NOT_IMPLEMENTED" | "CANCELLED";
export interface AdminDemandSummary {
  demand_id: string;
  organization_id: string;
  title: string;
  status: string;
  aggregate_version: number;
  created_at: string;
  updated_at: string;
  expires_at: string;
  current_stage: AdminDemandStageCode;
  blocker_codes: string[];
}
export interface AdminDemandCollection {
  items: AdminDemandSummary[];
  next_cursor: string | null;
  has_more: boolean;
}
export interface AdminDemandParticipant {
  user_id: string;
  display_name: string | null;
  roles: string[];
}
export interface AdminDemandEvent {
  event_id: string;
  stage: AdminDemandStageCode;
  source: string;
  action: string;
  actor_user_id: string | null;
  actor_role: string;
  occurred_at: string;
  summary: string;
  details: Record<string, string | number | boolean | null | string[]>;
}
export interface AdminDemandTimeline {
  demand: AdminDemandSummary;
  generated_at: string;
  stages: Array<{
    code: AdminDemandStageCode;
    label: string;
    status: AdminDemandStageStatus;
    participant_ids: string[];
    event_count: number;
    blocker_codes: string[];
  }>;
  participants: AdminDemandParticipant[];
  events: AdminDemandEvent[];
  coverage: Array<{ source: string; status: "COMPLETE" | "PARTIAL" | "NOT_IMPLEMENTED"; description: string }>;
  next_cursor: string | null;
  has_more: boolean;
}
export function canInspectDemandTimeline(workspace: WorkspaceCandidate | null): boolean;
export function parseAdminDemandCollection(value: unknown, workspaceId?: string): AdminDemandCollection;
export function parseAdminDemandTimeline(value: unknown, expectedDemandId?: string, workspaceId?: string): AdminDemandTimeline;
export function mergeAdminDemandCollection(prior: AdminDemandCollection, next: AdminDemandCollection): AdminDemandCollection;
export function mergeAdminDemandTimeline(prior: AdminDemandTimeline, next: AdminDemandTimeline): AdminDemandTimeline;
export const ADMIN_DEMAND_STAGE_LABELS: Record<AdminDemandStageCode, string>;
export function adminDemandStatusLabel(code: string): string;
export function adminDemandRoleLabel(code: string): string;
export function adminDemandBlockerLabel(code: string): string;
export function adminDemandDetailLabel(code: string): string;
export function adminDemandDetailValue(name: string, value: string | number | boolean | null | string[]): string;
