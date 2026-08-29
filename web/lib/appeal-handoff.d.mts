import type { TrustReportProjection } from "./app-contract.mjs";

export interface AppealHandoff {
  readonly version: 1;
  readonly source: "TRUST_REPORT_FRESH_READ";
  readonly session_id: string;
  readonly workspace_id: string;
  readonly report_id: string;
  readonly report_entity_tag: string;
  readonly demand_id: string;
  readonly demand_version_id: string;
  readonly source_outcome_version_id: string;
  readonly appeal_eligible: true;
  readonly appeal_deadline: string;
  readonly decided_at: string;
  readonly outcome_code: NonNullable<TrustReportProjection["outcome"]>["outcome_code"];
  readonly action_codes: readonly string[];
  readonly reason_codes: readonly string[];
  readonly policy_version: string;
  readonly outcome_content_sha256: string;
  readonly evidence_packet_version_id: string;
  readonly evidence_packet_digest: string;
  readonly redaction_profile_code: "PARTY_SAFE_V1";
  readonly created_at: string;
}

export function createAppealHandoff(input: {
  report: TrustReportProjection;
  sessionId: string;
  workspaceId: string;
  now?: number;
}): AppealHandoff | null;

export function isAppealHandoffCurrent(
  value: unknown,
  binding: { sessionId: string; workspaceId: string; now?: number },
): value is AppealHandoff;

export function appealHandoffKey(value: AppealHandoff): string;
