export class PrototypeDomainError extends Error {
  code: string;
}

export interface AuditEvent {
  id: string;
  occurredAt: string;
  correlationId: string;
  actorId: string;
  authority: string;
  action: string;
  reason: string;
  objectVersion: string | null;
  synthetic: boolean;
}

export interface AuthorityRecord {
  role: string;
  subjectId: string | null;
  subjectLabel: string;
  status: string;
  authoritySource: string | null;
  scope: string;
  validUntil: string | null;
  delegable: boolean;
  conflict: string;
  withdrawal: string;
  rationale: string | null;
}

export interface CreatorRecord {
  id: string;
  name: string;
  capabilityTags: string[];
  disclosedAvailability: string;
  evidenceRefs: string[];
  publicBoundary: string;
  eligibility: string;
  opportunityPenalty: number;
}

export interface ConsentRecord {
  subjectId: string;
  status: string;
  policyVersion: string;
  purpose: string;
  acceptedAt?: string;
}

export interface InvitationRecord {
  id: string;
  runId: string;
  creatorId: string;
  status: string;
  expiresAt: string;
  explanation: string;
  snapshot: {
    creatorRef: string;
    capabilityTags: string[];
    disclosedAvailability: string;
    evidenceRefs: string[];
  };
}

export interface MatchRunRecord {
  id: string;
  demandVersion: number;
  ruleVersion: string;
  ruleHash: string;
  status: string;
  invitations: InvitationRecord[];
}

export interface AgreementRecord {
  id: string;
  version: number;
  status: string;
  requiredSignatories: string[];
  acceptedBy: string[];
  changeSummary: string | null;
  history: Array<{ version: number; status: string; acceptedBy: string[]; changeSummary: string | null }>;
}

export interface MilestoneRecord {
  id: string;
  status: string;
  fundingStatus: string;
  fundingEvidenceRef: string | null;
}

export interface SafetyRecord {
  report: null | { id: string; reporterId: string; summary: string; status: string };
  decision: null | { reviewerId: string; outcome: string; scope: string; expiresAt: string; reason: string };
  appeal: null | { reviewerId: string; outcome: string; remedy: string };
  unaffectedRights: string[];
}

export interface RightsRequest {
  id: string;
  type: string;
  subjectId: string;
  status: string;
  result: unknown;
}

export interface PrototypeState {
  meta: Record<string, string | boolean>;
  actors: Record<string, { id: string; name: string; title: string }>;
  demand: {
    id: string;
    version: number;
    status: string;
    title: string;
    summary: string;
    budget: { amount: number; currency: string; kind: string };
    duration: string;
    acceptanceCriteria: string[];
    outcomePath: string;
    authorities: AuthorityRecord[];
  };
  creators: Record<string, CreatorRecord>;
  consents: Record<string, ConsentRecord>;
  funding: {
    id: string;
    obligation: string;
    demandVersion: number;
    amount: number;
    currency: string;
    status: string;
    source: string;
    evidenceRef: string | null;
    explicitlyNotReal: boolean;
  };
  matchRun: MatchRunRecord | null;
  selection: null | { id: string; runId: string; creatorId: string; selectorId: string; status: string; reason: string };
  project: null | { id: string; status: string; creatorId: string; demandVersion: number };
  agreement: AgreementRecord | null;
  milestone: MilestoneRecord | null;
  delivery: null | {
    id: string;
    version: number;
    status: string;
    fixture: string;
    contractAcceptance: null | { actorId: string; result: string; reason: string };
    beneficiaryConfirmation: null | { actorId: string; result: string; observation: string };
  };
  payment: {
    id: string;
    obligation: string;
    amount: number;
    currency: string;
    status: string;
    retryAllowed: boolean;
    providerReference: string | null;
    authoritativeSource: string | null;
    explicitlyNotReal: boolean;
  };
  outcome: null | {
    financialFact: { paymentStatus: string; source: string | null };
    creatorObservation: string;
    demandObservation: string;
    relationshipIntent: string;
    beneficiaryConfirmation: unknown;
    outcomePath: string;
    globalScore: null;
  };
  safety: SafetyRecord;
  rights: { requests: RightsRequest[] };
  audit: AuditEvent[];
}

export function createPrototype(): PrototypeState;
export function acceptSyntheticConsent(state: PrototypeState, subjectId: string, policyVersion: string): PrototypeState;
export function secureSyntheticFunding(state: PrototypeState): PrototypeState;
export function runMatching(state: PrototypeState): PrototypeState;
export function respondToInvitation(state: PrototypeState, creatorId: string, response: string): PrototypeState;
export function completeSelection(state: PrototypeState, input: { creatorId: string; runId: string }): PrototypeState;
export function acceptAgreement(state: PrototypeState, actorId: string, version: number): PrototypeState;
export function secureSyntheticMilestoneFunding(state: PrototypeState): PrototypeState;
export function startMilestone(state: PrototypeState): PrototypeState;
export function proposeAgreementChange(state: PrototypeState, input: { actorId: string; summary: string }): PrototypeState;
export function recordDelivery(state: PrototypeState): PrototypeState;
export function acceptDelivery(state: PrototypeState): PrototypeState;
export function requestPayment(state: PrototypeState): PrototypeState;
export function applyPaymentStatus(state: PrototypeState, status: string): PrototypeState;
export function reconcilePayment(state: PrototypeState, result: string): PrototypeState;
export function recordOutcome(state: PrototypeState): PrototypeState;
export function submitReport(state: PrototypeState, input: { reporterId: string; summary: string }): PrototypeState;
export function decideReport(state: PrototypeState, input: { reviewerId: string; outcome: string }): PrototypeState;
export function appealDecision(state: PrototypeState, input: { reviewerId: string; outcome: string }): PrototypeState;
export function exportSubjectData(state: PrototypeState, subjectId: string): Record<string, unknown>;
export function requestDeletion(state: PrototypeState, subjectId: string): { id: string; status: string; items: Array<{ category: string; result: string; reason: string }> };
export function submitExportRequest(state: PrototypeState, subjectId: string): PrototypeState;
export function submitDeletionRequest(state: PrototypeState, subjectId: string): PrototypeState;
export function cancelDemand(state: PrototypeState, reason: string): PrototypeState;
