function invalidSessionBinding() {
  throw new TypeError("INVALID_SESSION_PAGE_BINDING");
}

const UUID = /^(?!0{8}-0{4}-0{4}-0{4}-0{12})[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const CSRF_TOKEN = /^[A-Za-z0-9_-]{32,512}$/;
const IDEMPOTENCY_KEY = /^[A-Za-z0-9][A-Za-z0-9._~-]{15,127}$/;
const REMOTE_REVOKE_RECOVERY_MS = 24 * 60 * 60 * 1000;
const MAX_CLOCK_SKEW_MS = 5 * 60 * 1000;
const REMOTE_REVOKE_KEYS = new Set([
  "version",
  "saved_at",
  "account_user_id",
  "bootstrap_session_id",
  "target_session_id",
  "csrf_token",
  "idempotency_key",
]);

export const LEGACY_SESSION_REVOKE_PENDING_KEY = "desire-pilot-session-revoke:v1";
export const SESSION_REVOKE_PENDING_KEY = "desire-pilot-session-revoke:v2";

function exactObject(value, keys) {
  return Boolean(
    value
    && typeof value === "object"
    && !Array.isArray(value)
    && Object.keys(value).length === keys.size
    && Object.keys(value).every((key) => keys.has(key)),
  );
}

function remoteRevokeFieldsValid(value) {
  return exactObject(value, REMOTE_REVOKE_KEYS)
    && value.version === 2
    && typeof value.saved_at === "string"
    && UUID.test(value.account_user_id)
    && UUID.test(value.bootstrap_session_id)
    && UUID.test(value.target_session_id)
    && value.target_session_id !== value.bootstrap_session_id
    && CSRF_TOKEN.test(value.csrf_token)
    && IDEMPOTENCY_KEY.test(value.idempotency_key);
}

export function createRemoteSessionRevokeIntent({
  accountUserId,
  bootstrapSessionId,
  csrfToken,
  idempotencyKey,
  now = Date.now(),
  targetSessionId,
}) {
  const intent = {
    version: 2,
    saved_at: new Date(now).toISOString(),
    account_user_id: accountUserId,
    bootstrap_session_id: bootstrapSessionId,
    target_session_id: targetSessionId,
    csrf_token: csrfToken,
    idempotency_key: idempotencyKey,
  };
  if (!Number.isFinite(now) || !remoteRevokeFieldsValid(intent)) {
    throw new TypeError("INVALID_REMOTE_SESSION_REVOKE_INTENT");
  }
  return Object.freeze(intent);
}

export function serializeRemoteSessionRevokeIntent(intent) {
  if (!remoteRevokeFieldsValid(intent)) {
    throw new TypeError("INVALID_REMOTE_SESSION_REVOKE_INTENT");
  }
  return JSON.stringify(intent);
}

export function parseRemoteSessionRevokeIntent(
  encoded,
  { accountUserId, bootstrapSessionId, now = Date.now() },
) {
  if (typeof encoded !== "string" || encoded.length === 0 || encoded.length > 4096) return null;
  try {
    const value = JSON.parse(encoded);
    if (
      !remoteRevokeFieldsValid(value)
      || value.account_user_id !== accountUserId
      || value.bootstrap_session_id !== bootstrapSessionId
    ) return null;
    const savedAt = Date.parse(value.saved_at);
    if (
      !Number.isFinite(now)
      || !Number.isFinite(savedAt)
      || savedAt > now + MAX_CLOCK_SKEW_MS
      || now - savedAt > REMOTE_REVOKE_RECOVERY_MS
    ) return null;
    return Object.freeze({ ...value });
  } catch {
    return null;
  }
}

export function claimAndPersistRemoteSessionRevokeIntent(intent, {
  claimWrite,
  persistIntent,
  releaseWrite,
  setWriteBusy,
}) {
  if (!remoteRevokeFieldsValid(intent)) {
    throw new TypeError("INVALID_REMOTE_SESSION_REVOKE_INTENT");
  }
  if (!claimWrite(intent.idempotency_key)) {
    throw new TypeError("SESSION_REVOKE_GLOBAL_LATCH_UNAVAILABLE");
  }
  try {
    persistIntent(intent);
  } catch {
    try {
      setWriteBusy(intent.idempotency_key, false);
    } finally {
      releaseWrite(intent.idempotency_key);
    }
    throw new TypeError("SESSION_REVOKE_RECOVERY_STORAGE_FAILED");
  }
  return intent;
}

export function assertRemoteRevokePostcondition(
  snapshot,
  { bootstrapSessionId, targetSessionId },
) {
  const current = snapshot.nextCursor === null
    ? snapshot.items.filter((item) => item.session_id === bootstrapSessionId)
    : [];
  const target = snapshot.items.find((item) => item.session_id === targetSessionId);
  if (
    !UUID.test(bootstrapSessionId)
    || !UUID.test(targetSessionId)
    || bootstrapSessionId === targetSessionId
    || current.length !== 1
    || current[0].is_current !== true
    || current[0].status !== "ACTIVE"
    || (target !== undefined && (
      target.is_current
      || !new Set(["REVOKED", "EXPIRED"]).has(target.status)
    ))
  ) throw new TypeError("INVALID_REMOTE_SESSION_REVOKE_POSTCONDITION");
  return snapshot;
}

/**
 * Bind one already-parsed SessionPageDto to the bootstrap Session and the
 * exact cursor chain held in memory by the caller.
 */
export function bindSessionPage(page, {
  bootstrapSessionId,
  existing,
  requestedCursor,
}) {
  if (
    (existing === null && requestedCursor !== null)
    || (existing !== null && (
      requestedCursor === null
      || existing.nextCursor !== requestedCursor
      || !existing.seenCursors.includes(requestedCursor)
    ))
  ) invalidSessionBinding();

  const priorItems = existing?.items ?? [];
  const priorIds = new Set(priorItems.map((item) => item.session_id));
  for (const item of page.items) {
    if (
      item.is_current !== (item.session_id === bootstrapSessionId)
      || priorIds.has(item.session_id)
    ) invalidSessionBinding();
    priorIds.add(item.session_id);
  }

  const seenCursors = new Set(existing?.seenCursors ?? []);
  const nextCursor = page.page.next_cursor;
  if (
    (page.items.length === 0 && nextCursor !== null)
    || (nextCursor !== null && (
      nextCursor === requestedCursor
      || seenCursors.has(nextCursor)
    ))
  ) invalidSessionBinding();
  if (nextCursor !== null) seenCursors.add(nextCursor);

  const items = Object.freeze([...priorItems, ...page.items]);
  const currentCount = items.filter((item) => item.is_current).length;
  if (currentCount > 1 || (nextCursor === null && currentCount !== 1)) {
    invalidSessionBinding();
  }

  return Object.freeze({
    items,
    nextCursor,
    seenCursors: Object.freeze([...seenCursors]),
  });
}
