const UUID = /^(?!0{8}-0{4}-0{4}-0{4}-0{12})[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const WORKSPACE_ID = /^(?:org|personal|platform):(?<id>[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$/;
const SHA256 = /^[a-f0-9]{64}$/;
const TRUST_ETAG = /^"trust-[1-9][0-9]*-[a-f0-9]{24}"$/;
const UTC_TIMESTAMP = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?(?:Z|\+00:00)$/;
const HANDOFF_KEYS = new Set([
  "action_codes",
  "appeal_deadline",
  "appeal_eligible",
  "created_at",
  "decided_at",
  "demand_id",
  "demand_version_id",
  "evidence_packet_digest",
  "evidence_packet_version_id",
  "outcome_code",
  "outcome_content_sha256",
  "policy_version",
  "reason_codes",
  "redaction_profile_code",
  "report_entity_tag",
  "report_id",
  "session_id",
  "source",
  "source_outcome_version_id",
  "version",
  "workspace_id",
]);

function canonicalUuid(value) {
  return typeof value === "string" && UUID.test(value);
}

function timestamp(value) {
  if (typeof value !== "string") return null;
  const match = UTC_TIMESTAMP.exec(value);
  if (!match) return null;
  const seconds = Date.parse(`${match[1]}Z`);
  if (!Number.isFinite(seconds) || new Date(seconds).toISOString().slice(0, 19) !== match[1]) return null;
  const milliseconds = Number((match[2] ?? "").padEnd(3, "0").slice(0, 3));
  return seconds + milliseconds;
}

function exactKeys(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const keys = Object.keys(value);
  return keys.length === HANDOFF_KEYS.size && keys.every((key) => HANDOFF_KEYS.has(key));
}

function closedStrings(value, minimum, maximum) {
  return Array.isArray(value)
    && value.length >= minimum
    && value.length <= maximum
    && value.every((item) => typeof item === "string" && item.length > 0)
    && new Set(value).size === value.length;
}

/**
 * Creates a tab-memory handoff only from an already closed-parsed, party-safe
 * reporting-party projection. Ineligible and expired reports have no handoff.
 */
export function createAppealHandoff({ report, sessionId, workspaceId, now = Date.now() }) {
  const outcome = report?.outcome;
  const deadline = timestamp(outcome?.appeal_deadline);
  const decidedAt = timestamp(outcome?.decided_at);
  if (
    !Number.isFinite(now)
    || report?.status !== "DECIDED"
    || !outcome
    || outcome.appeal_eligibility_code !== "ELIGIBLE"
    || outcome.redaction_profile_code !== "PARTY_SAFE_V1"
    || deadline === null
    || decidedAt === null
    || now < decidedAt
    || deadline <= now
    || deadline <= decidedAt
    || !canonicalUuid(sessionId)
    || !WORKSPACE_ID.test(workspaceId)
    || !canonicalUuid(report.report_id)
    || !canonicalUuid(report.demand_id)
    || !canonicalUuid(report.demand_version_id)
    || !canonicalUuid(outcome.outcome_version_id)
    || !canonicalUuid(outcome.evidence_packet_version_id)
    || !SHA256.test(outcome.content_sha256)
    || !SHA256.test(outcome.evidence_packet_digest)
    || !TRUST_ETAG.test(report.entity_tag)
  ) return null;

  const handoff = {
    version: 1,
    source: "TRUST_REPORT_FRESH_READ",
    session_id: sessionId,
    workspace_id: workspaceId,
    report_id: report.report_id,
    report_entity_tag: report.entity_tag,
    demand_id: report.demand_id,
    demand_version_id: report.demand_version_id,
    source_outcome_version_id: outcome.outcome_version_id,
    appeal_eligible: true,
    appeal_deadline: outcome.appeal_deadline,
    decided_at: outcome.decided_at,
    outcome_code: outcome.outcome_code,
    action_codes: Object.freeze([...outcome.action_codes]),
    reason_codes: Object.freeze([...outcome.reason_codes]),
    policy_version: outcome.policy_version,
    outcome_content_sha256: outcome.content_sha256,
    evidence_packet_version_id: outcome.evidence_packet_version_id,
    evidence_packet_digest: outcome.evidence_packet_digest,
    redaction_profile_code: outcome.redaction_profile_code,
    created_at: new Date(now).toISOString(),
  };
  return Object.freeze(handoff);
}

/**
 * Revalidates the complete in-memory object at each component boundary. This
 * deliberately does not deserialize any browser storage representation.
 */
export function isAppealHandoffCurrent(value, { sessionId, workspaceId, now = Date.now() }) {
  if (!exactKeys(value) || !Number.isFinite(now)) return false;
  const deadline = timestamp(value.appeal_deadline);
  const decidedAt = timestamp(value.decided_at);
  const createdAt = timestamp(value.created_at);
  const workspaceMatch = WORKSPACE_ID.exec(value.workspace_id);
  return value.version === 1
    && value.source === "TRUST_REPORT_FRESH_READ"
    && value.session_id === sessionId
    && value.workspace_id === workspaceId
    && canonicalUuid(value.session_id)
    && workspaceMatch !== null
    && workspaceMatch.groups?.id !== "00000000-0000-0000-0000-000000000000"
    && canonicalUuid(value.report_id)
    && TRUST_ETAG.test(value.report_entity_tag)
    && canonicalUuid(value.demand_id)
    && canonicalUuid(value.demand_version_id)
    && canonicalUuid(value.source_outcome_version_id)
    && value.appeal_eligible === true
    && deadline !== null
    && deadline > now
    && decidedAt !== null
    && deadline > decidedAt
    && createdAt !== null
    && createdAt >= decidedAt
    && createdAt < deadline
    && typeof value.outcome_code === "string"
    && closedStrings(value.action_codes, 0, 3)
    && closedStrings(value.reason_codes, 1, 8)
    && typeof value.policy_version === "string"
    && /^trust-case-outcome-v[1-9][0-9]*$/.test(value.policy_version)
    && SHA256.test(value.outcome_content_sha256)
    && canonicalUuid(value.evidence_packet_version_id)
    && SHA256.test(value.evidence_packet_digest)
    && value.redaction_profile_code === "PARTY_SAFE_V1";
}

export function appealHandoffKey(value) {
  return [
    value.session_id,
    value.workspace_id,
    value.report_id,
    value.report_entity_tag,
    value.source_outcome_version_id,
    value.created_at,
  ].join("\0");
}
