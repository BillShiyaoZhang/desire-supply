export type SessionStatus = "ACTIVE" | "REVOKED" | "EXPIRED";

export interface SessionDto {
  readonly session_id: string;
  readonly created_at: string;
  readonly last_activity_at: string;
  readonly expires_at: string;
  readonly is_current: boolean;
  readonly device_label: string;
  readonly status: SessionStatus;
}

export interface SessionPageDto {
  readonly items: readonly SessionDto[];
  readonly page: Readonly<{ next_cursor: string | null }>;
}

export function parseSessionPage(value: unknown): SessionPageDto;
