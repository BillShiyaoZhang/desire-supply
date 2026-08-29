const UUID = /^(?!0{8}-0{4}-0{4}-0{4}-0{12})[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const CURSOR = /^[A-Za-z0-9_-]{64,1900}\.[A-Za-z0-9_-]{43}$/;
const UTC_TIMESTAMP = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,6}))?Z$/;
const SESSION_STATUSES = new Set(["ACTIVE", "REVOKED", "EXPIRED"]);
const SESSION_KEYS = new Set([
  "session_id",
  "created_at",
  "last_activity_at",
  "expires_at",
  "is_current",
  "device_label",
  "status",
]);

function exactObject(value, keys) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const actual = Object.keys(value);
  return actual.length === keys.size && actual.every((key) => keys.has(key));
}

function parseUtcTimestamp(value) {
  if (typeof value !== "string") return null;
  const match = UTC_TIMESTAMP.exec(value);
  if (match === null || match[1] === "0000") return null;
  const parsed = new Date(value);
  if (!Number.isFinite(parsed.getTime())) return null;
  const expected = match.slice(1, 7).map(Number);
  const actual = [
    parsed.getUTCFullYear(),
    parsed.getUTCMonth() + 1,
    parsed.getUTCDate(),
    parsed.getUTCHours(),
    parsed.getUTCMinutes(),
    parsed.getUTCSeconds(),
  ];
  return actual.every((component, index) => component === expected[index])
    ? parsed.getTime()
    : null;
}

function safeDeviceLabel(value) {
  if (typeof value !== "string" || value.normalize("NFC") !== value) return false;
  const characters = [...value];
  return characters.length >= 1
    && characters.length <= 80
    && characters.every((character) => {
      const code = character.codePointAt(0);
      return code !== undefined && code >= 32 && code !== 127;
    });
}

function parseSession(value) {
  if (
    !exactObject(value, SESSION_KEYS)
    || !UUID.test(value.session_id)
    || typeof value.is_current !== "boolean"
    || !safeDeviceLabel(value.device_label)
    || !SESSION_STATUSES.has(value.status)
    || (value.is_current && value.status !== "ACTIVE")
  ) throw new TypeError("INVALID_SESSION_PAGE_CONTRACT");
  const createdAt = parseUtcTimestamp(value.created_at);
  const lastActivityAt = parseUtcTimestamp(value.last_activity_at);
  const expiresAt = parseUtcTimestamp(value.expires_at);
  if (
    createdAt === null
    || lastActivityAt === null
    || expiresAt === null
    || createdAt > lastActivityAt
    || lastActivityAt >= expiresAt
  ) throw new TypeError("INVALID_SESSION_PAGE_CONTRACT");
  return Object.freeze({
    session_id: value.session_id,
    created_at: value.created_at,
    last_activity_at: value.last_activity_at,
    expires_at: value.expires_at,
    is_current: value.is_current,
    device_label: value.device_label,
    status: value.status,
  });
}

/** Parse and reconstruct the closed, party-safe SessionPageDto projection. */
export function parseSessionPage(value) {
  if (
    !exactObject(value, new Set(["items", "page"]))
    || !Array.isArray(value.items)
    || value.items.length > 100
    || !exactObject(value.page, new Set(["next_cursor"]))
    || !(
      value.page.next_cursor === null
      || (typeof value.page.next_cursor === "string"
        && value.page.next_cursor.length >= 108
        && value.page.next_cursor.length <= 1944
        && CURSOR.test(value.page.next_cursor))
    )
  ) throw new TypeError("INVALID_SESSION_PAGE_CONTRACT");

  const items = value.items.map(parseSession);
  if (
    new Set(items.map((item) => item.session_id)).size !== items.length
    || items.filter((item) => item.is_current).length > 1
  ) throw new TypeError("INVALID_SESSION_PAGE_CONTRACT");

  return Object.freeze({
    items: Object.freeze(items),
    page: Object.freeze({ next_cursor: value.page.next_cursor }),
  });
}
