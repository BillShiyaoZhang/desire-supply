const SCRATCH_MAX_BYTES = 256 * 1024;
const DEMAND_EXPIRY_OFFSET_MS = 60 * 24 * 60 * 60 * 1000;
const SCRATCH_PREFIX = "desire-pilot-scratch:v1:";

const CREATE_PLACEHOLDERS = Object.freeze({
  CREATOR_PROFILE: "new_profile_internal",
  DEMAND: "new_demand_internal",
});

function pad(value) {
  return String(value).padStart(2, "0");
}

export function persistEditorScratch(storage, resource, sections, savedAt = new Date()) {
  const encoded = JSON.stringify({
    version: 1,
    saved_at: savedAt.toISOString(),
    resource_type: resource.resource_type,
    object_id: resource.object_id,
    base_revision: resource.revision,
    sections,
  });
  if (new TextEncoder().encode(encoded).byteLength > SCRATCH_MAX_BYTES) return false;
  try {
    storage.setItem(`${SCRATCH_PREFIX}${resource.resource_type}:${resource.object_id}`, encoded);
    return true;
  } catch {
    return false;
  }
}

export function isCreatePlaceholder(resourceType, objectId) {
  return CREATE_PLACEHOLDERS[resourceType] === objectId;
}

export function expectedEditorResponseObjectId(resourceType, objectId) {
  return isCreatePlaceholder(resourceType, objectId) ? undefined : objectId;
}

export function editorResponseBindingMatches(recordType, recordId, responseType, responseId) {
  if (recordType !== responseType) return false;
  if (!isCreatePlaceholder(recordType, recordId)) return responseId === recordId;
  return !Object.values(CREATE_PLACEHOLDERS).includes(responseId);
}

export function formatDateTimeLocal(date) {
  if (!(date instanceof Date) || !Number.isFinite(date.valueOf())) throw new TypeError("INVALID_DATETIME");
  return [
    String(date.getFullYear()).padStart(4, "0"),
    "-",
    pad(date.getMonth() + 1),
    "-",
    pad(date.getDate()),
    "T",
    pad(date.getHours()),
    ":",
    pad(date.getMinutes()),
  ].join("");
}

export function defaultDemandExpiry(now = Date.now()) {
  if (!Number.isFinite(now)) throw new TypeError("INVALID_DATETIME");
  return formatDateTimeLocal(new Date(now + DEMAND_EXPIRY_OFFSET_MS));
}

export function dateTimeLocalToIso(value) {
  const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})$/.exec(value);
  if (!match) throw new TypeError("INVALID_EXPIRY");
  const [, year, month, day, hour, minute] = match.map(Number);
  const date = new Date(year, month - 1, day, hour, minute, 0, 0);
  if (
    !Number.isFinite(date.valueOf())
    || date.getFullYear() !== year
    || date.getMonth() !== month - 1
    || date.getDate() !== day
    || date.getHours() !== hour
    || date.getMinutes() !== minute
  ) throw new TypeError("INVALID_EXPIRY");
  return date.toISOString();
}
