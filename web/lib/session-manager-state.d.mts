import type { SessionDto, SessionPageDto } from "./session-contract.mjs";

export interface SessionSnapshot {
  readonly items: readonly SessionDto[];
  readonly nextCursor: string | null;
  readonly seenCursors: readonly string[];
}

export interface RemoteSessionRevokeIntent {
  readonly version: 2;
  readonly saved_at: string;
  readonly account_user_id: string;
  readonly bootstrap_session_id: string;
  readonly target_session_id: string;
  readonly csrf_token: string;
  readonly idempotency_key: string;
}

export const LEGACY_SESSION_REVOKE_PENDING_KEY: "desire-pilot-session-revoke:v1";
export const SESSION_REVOKE_PENDING_KEY: "desire-pilot-session-revoke:v2";

export function createRemoteSessionRevokeIntent(options: Readonly<{
  accountUserId: string;
  bootstrapSessionId: string;
  csrfToken: string;
  idempotencyKey: string;
  now?: number;
  targetSessionId: string;
}>): RemoteSessionRevokeIntent;

export function serializeRemoteSessionRevokeIntent(intent: RemoteSessionRevokeIntent): string;

export function parseRemoteSessionRevokeIntent(
  encoded: string,
  options: Readonly<{
    accountUserId: string;
    bootstrapSessionId: string;
    now?: number;
  }>,
): RemoteSessionRevokeIntent | null;

export function claimAndPersistRemoteSessionRevokeIntent(
  intent: RemoteSessionRevokeIntent,
  operations: Readonly<{
    claimWrite: (writeKey: string) => boolean;
    persistIntent: (intent: RemoteSessionRevokeIntent) => void;
    releaseWrite: (writeKey: string) => void;
    setWriteBusy: (writeKey: string, value: boolean) => void;
  }>,
): RemoteSessionRevokeIntent;

export function assertRemoteRevokePostcondition(
  snapshot: SessionSnapshot,
  options: Readonly<{
    bootstrapSessionId: string;
    targetSessionId: string;
  }>,
): SessionSnapshot;

export function bindSessionPage(
  page: SessionPageDto,
  options: Readonly<{
    bootstrapSessionId: string;
    existing: SessionSnapshot | null;
    requestedCursor: string | null;
  }>,
): SessionSnapshot;
