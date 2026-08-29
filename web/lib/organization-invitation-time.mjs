import {
  dateTimeLocalToIso,
  formatDateTimeLocal,
} from "./product-workspace-state.mjs";

const ORGANIZATION_INVITATION_EXPIRY_OFFSET_MS = 14 * 24 * 60 * 60 * 1000;

export function defaultOrganizationInvitationExpiry(now = Date.now()) {
  if (!Number.isFinite(now)) throw new TypeError("INVALID_DATETIME");
  return formatDateTimeLocal(
    new Date(now + ORGANIZATION_INVITATION_EXPIRY_OFFSET_MS),
  );
}

export function organizationInvitationExpiryToIso(value) {
  return dateTimeLocalToIso(value);
}
