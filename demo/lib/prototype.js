/**
 * Foundations G0A synthetic prototype domain.
 *
 * This module is deliberately dependency-free and in-memory. It models
 * institutional invariants for a disposable demo; it is not a provider,
 * ledger, identity system, contract system, or production source of truth.
 */

export class PrototypeDomainError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "PrototypeDomainError";
    this.code = code;
  }
}

const fail = (code, message) => {
  throw new PrototypeDomainError(code, message);
};

const clone = (value) => structuredClone(value);

const authority = (role, subjectId, subjectLabel, overrides = {}) => ({
  role,
  subjectId,
  subjectLabel,
  status: subjectId ? "AUTHORIZED" : "NOT_APPLICABLE",
  authoritySource: subjectId ? "synthetic-role-mandate-v1" : null,
  scope: subjectId ? "demand-demo-001 / version 1" : "none",
  validUntil: subjectId ? "SIM-BATCH-END" : null,
  delegable: false,
  conflict: "NONE_DECLARED",
  withdrawal: subjectId ? "由授权主体撤回并追加事件" : "not applicable",
  rationale: null,
  ...overrides,
});

const appendAudit = (state, details) => {
  const sequence = state.audit.length + 1;
  return [
    ...state.audit,
    {
      id: `audit-${String(sequence).padStart(3, "0")}`,
      occurredAt: `SIM-T+${String(sequence).padStart(3, "0")}`,
      correlationId: details.correlationId ?? "corr-demo-001",
      actorId: details.actorId,
      authority: details.authority,
      action: details.action,
      reason: details.reason,
      objectVersion: details.objectVersion ?? null,
      synthetic: true,
    },
  ];
};

const commit = (state, changes, audit) => ({
  ...state,
  ...changes,
  audit: appendAudit(state, audit),
});

export function createPrototype() {
  return {
    meta: {
      syntheticOnly: true,
      disposable: true,
      persistent: false,
      gate: "G0A",
      g1: "NO-GO",
      g2: "NO-GO",
      scenario: "无障碍活动信息包（完全虚构）",
      disclaimer: "不建立真实身份、合同、付款、申诉或数据权事实",
    },
    actors: {
      "synthetic-demand-signatory": {
        id: "synthetic-demand-signatory",
        name: "周岚（虚构）",
        title: "需求方获授权签字人",
      },
      "synthetic-selector": {
        id: "synthetic-selector",
        name: "顾遥（虚构）",
        title: "候选选择者",
      },
      "synthetic-safety-reviewer": {
        id: "synthetic-safety-reviewer",
        name: "韩宁（虚构）",
        title: "初次安全复核者",
      },
      "synthetic-appeal-reviewer": {
        id: "synthetic-appeal-reviewer",
        name: "沈岸（虚构）",
        title: "独立申诉复核者",
      },
    },
    demand: {
      id: "demand-demo-001",
      version: 1,
      status: "FUNDING_PENDING",
      title: "制作一份无障碍社区活动信息包",
      summary:
        "把一场虚构的社区交流会内容整理为清晰语言版说明、屏幕阅读器友好的网页文案和可打印流程卡。",
      budget: { amount: 6800, currency: "CNY", kind: "SYNTHETIC_PARAMETER" },
      duration: "14 个模拟日",
      acceptanceCriteria: [
        "信息层级可由键盘与屏幕阅读器理解",
        "关键行动使用清晰语言且不依赖颜色",
        "交付包含可编辑源文件与维护说明",
      ],
      outcomePath: "一次性交付 + 可复用的开放模板（虚构约定）",
      authorities: [
        authority("PROBLEM_PROPOSER", "synthetic-proposer", "秦禾（虚构）"),
        authority("BENEFICIARY", "synthetic-beneficiary-cohort", "虚构活动参与者群体", {
          authoritySource: "synthetic-beneficiary-description-v1",
          delegable: false,
        }),
        authority(
          "BENEFICIARY_REPRESENTATIVE",
          "synthetic-beneficiary-representative",
          "罗雨（虚构）",
          { authoritySource: "synthetic-beneficiary-mandate-v1" },
        ),
        authority("FUNDER_PURCHASER", "synthetic-funder", "愿景公益工作室（虚构）"),
        authority("RESOURCE_PROVIDER", null, "无", {
          rationale: "本演练不依赖任何第三方资源、场地、设备、导师、数据或品牌。",
        }),
        authority("DEMAND_DECISION_MAKER", "synthetic-decision-maker", "周岚（虚构）"),
        authority("CANDIDATE_SELECTOR", "synthetic-selector", "顾遥（虚构）"),
        authority("ACCEPTANCE_REVIEWER", "synthetic-acceptance-reviewer", "罗雨（虚构）"),
        authority("PROJECT_COORDINATOR", "synthetic-coordinator", "宁川（虚构）"),
      ],
    },
    creators: {
      "creator-chen": {
        id: "creator-chen",
        name: "陈澄（虚构）",
        capabilityTags: ["无障碍内容", "信息设计", "清晰语言"],
        disclosedAvailability: "未来两周可投入 24 小时",
        evidenceRefs: ["evidence-a11y-kit-01", "evidence-plain-language-02"],
        publicBoundary: "不承接需要采集真实敏感身份资料的工作",
        eligibility: "ELIGIBLE",
        opportunityPenalty: 0,
      },
      "creator-lin": {
        id: "creator-lin",
        name: "林岑（虚构）",
        capabilityTags: ["网页内容", "无障碍测试", "编辑"],
        disclosedAvailability: "未来两周可投入 18 小时",
        evidenceRefs: ["evidence-web-copy-03"],
        publicBoundary: "不接受无限轮次修改",
        eligibility: "ELIGIBLE",
        opportunityPenalty: 0,
      },
      "creator-song": {
        id: "creator-song",
        name: "宋知（虚构）",
        capabilityTags: ["服务设计", "可打印物料", "编辑"],
        disclosedAvailability: "未来两周可投入 20 小时",
        evidenceRefs: ["evidence-service-map-04"],
        publicBoundary: "远程协作；不含线下活动执行",
        eligibility: "ELIGIBLE",
        opportunityPenalty: 0,
      },
    },
    consents: {
      "creator-chen": {
        subjectId: "creator-chen",
        status: "PENDING",
        policyVersion: "synthetic-purpose-policy-v1",
        purpose: "SYNTHETIC_MATCHING_DEMO",
      },
      "creator-lin": {
        subjectId: "creator-lin",
        status: "PENDING",
        policyVersion: "synthetic-purpose-policy-v1",
        purpose: "SYNTHETIC_MATCHING_DEMO",
      },
      "creator-song": {
        subjectId: "creator-song",
        status: "PENDING",
        policyVersion: "synthetic-purpose-policy-v1",
        purpose: "SYNTHETIC_MATCHING_DEMO",
      },
    },
    funding: {
      id: "funding-demand-demo-001",
      obligation: "DEMAND_VERSION",
      demandVersion: 1,
      amount: 6800,
      currency: "CNY",
      status: "UNKNOWN",
      source: "SYNTHETIC_RECONCILIATION_LEDGER",
      evidenceRef: null,
      explicitlyNotReal: true,
    },
    matchRun: null,
    selection: null,
    project: null,
    agreement: null,
    milestone: null,
    delivery: null,
    payment: {
      id: "payment-demo-001",
      obligation: "CREATOR_MILESTONE_COMPENSATION",
      amount: 6800,
      currency: "CNY",
      status: "NOT_REQUESTED",
      retryAllowed: false,
      providerReference: null,
      authoritativeSource: null,
      explicitlyNotReal: true,
    },
    outcome: null,
    safety: {
      report: null,
      decision: null,
      appeal: null,
      unaffectedRights: ["DATA_RIGHTS", "APPEAL", "PAYMENT_CLAIM"],
    },
    rights: { requests: [] },
    audit: [
      {
        id: "audit-001",
        occurredAt: "SIM-T+001",
        correlationId: "corr-demo-001",
        actorId: "prototype-system",
        authority: "G0A_SYNTHETIC_FIXTURE",
        action: "PROTOTYPE_RESET",
        reason: "载入完全合成、可删除的初始状态",
        objectVersion: "fixture-v1",
        synthetic: true,
      },
    ],
  };
}

export function acceptSyntheticConsent(state, subjectId, policyVersion) {
  const consent = state.consents[subjectId];
  if (!consent) {
    fail("CONSENT_SUBJECT_NOT_FOUND", "该合成主体没有待处理的目的同意");
  }
  if (policyVersion !== consent.policyVersion) {
    fail("CONSENT_POLICY_VERSION_MISMATCH", "必须接受当前用途政策版本");
  }
  if (consent.status === "ACTIVE") {
    return state;
  }
  return commit(
    state,
    {
      consents: {
        ...state.consents,
        [subjectId]: { ...consent, status: "ACTIVE", acceptedAt: "SIMULATED_ONLY" },
      },
    },
    {
      actorId: subjectId,
      authority: "SUBJECT_SELF_SYNTHETIC_ACTION",
      action: "PURPOSE_CONSENT_ACCEPTED",
      reason: "合成主体明示接受该用途与版本；不构成真实个人同意",
      objectVersion: policyVersion,
    },
  );
}

export function secureSyntheticFunding(state) {
  if (state.demand.status !== "FUNDING_PENDING") {
    fail("DEMAND_NOT_FUNDING_PENDING", "只有待核验的需求可记录资金证据");
  }
  if (state.funding.status === "SECURED") {
    return state;
  }
  return commit(
    state,
    {
      funding: {
        ...state.funding,
        status: "SECURED",
        evidenceRef: "synthetic-ledger-entry-demand-001",
      },
      demand: { ...state.demand, status: "MATCHABLE" },
    },
    {
      actorId: "synthetic-finance-reconciler",
      authority: "SEPARATED_SYNTHETIC_RECONCILIATION",
      action: "DEMAND_FUNDING_SECURED",
      reason: "合成账簿证据与一笔明确的 DemandVersion 义务一致",
      objectVersion: `demand-v${state.demand.version}`,
    },
  );
}

export function runMatching(state) {
  if (state.funding.status !== "SECURED") {
    fail("FUNDING_NOT_SECURED", "资金未知时不得产生邀请");
  }
  if (state.demand.status !== "MATCHABLE") {
    fail("DEMAND_NOT_MATCHABLE", "需求当前状态不允许匹配");
  }
  if (state.matchRun) {
    return state;
  }
  const runId = "match-run-001";
  const eligibleCreators = Object.values(state.creators).filter(
    (creator) => state.consents[creator.id]?.status === "ACTIVE",
  );
  if (eligibleCreators.length === 0) {
    fail("NO_CONSENTED_CREATORS", "没有任何主体同意当前匹配用途");
  }
  const invitations = eligibleCreators.map((creator, index) => ({
    id: `invitation-${index + 1}`,
    runId,
    creatorId: creator.id,
    status: "INVITED",
    expiresAt: "SIM-T+030",
    explanation:
      index === 0
        ? "能力覆盖全部三项交付，并明确拒绝敏感身份数据"
        : index === 1
          ? "网页内容与无障碍测试证据匹配；修改边界清楚"
          : "可打印物料与服务设计匹配；线下执行已排除",
    snapshot: {
      creatorRef: creator.id,
      capabilityTags: [...creator.capabilityTags],
      disclosedAvailability: creator.disclosedAvailability,
      evidenceRefs: [...creator.evidenceRefs],
    },
  }));
  return commit(
    state,
    {
      demand: { ...state.demand, status: "MATCHING" },
      matchRun: {
        id: runId,
        demandVersion: state.demand.version,
        ruleVersion: "limited-explainable-match-v1",
        ruleHash: "sha256:synthetic-demo-rule-v1",
        status: "INVITATIONS_OPEN",
        invitations,
      },
    },
    {
      actorId: "synthetic-match-operator",
      authority: "PUBLISHED_SYNTHETIC_RULE_V1",
      action: "LIMITED_MATCH_RUN_CREATED",
      reason: "资金已核验，按固定规则使用最小披露快照生成三份邀请",
      objectVersion: "limited-explainable-match-v1",
    },
  );
}

export function respondToInvitation(state, creatorId, response) {
  const allowed = new Set(["ACCEPTED", "DECLINED", "WITHDRAWN", "EXPIRED"]);
  if (!allowed.has(response)) {
    fail("INVALID_INVITATION_RESPONSE", "邀请响应不在允许状态内");
  }
  if (!state.matchRun) {
    fail("MATCH_RUN_MISSING", "尚无匹配运行");
  }
  const invitation = state.matchRun.invitations.find((item) => item.creatorId === creatorId);
  if (!invitation) {
    fail("INVITATION_MISSING", "该创作者不在本次邀请中");
  }
  if (invitation.status !== "INVITED" && !(invitation.status === "ACCEPTED" && response === "WITHDRAWN")) {
    fail("INVITATION_ALREADY_RESOLVED", "邀请已经响应，不能静默改写历史");
  }
  const invitations = state.matchRun.invitations.map((item) =>
    item.creatorId === creatorId ? { ...item, status: response } : item,
  );
  const creators = clone(state.creators);
  if (response === "DECLINED" || response === "WITHDRAWN" || response === "EXPIRED") {
    creators[creatorId].eligibility = "ELIGIBLE";
    creators[creatorId].opportunityPenalty = 0;
  }
  return commit(
    state,
    {
      creators,
      matchRun: { ...state.matchRun, invitations },
    },
    {
      actorId: creatorId,
      authority: "CREATOR_SELF",
      action: `INVITATION_${response}`,
      reason:
        response === "DECLINED"
          ? "创作者自主拒绝；不要求理由且不生成惩罚特征"
          : `创作者将邀请更新为 ${response}`,
      objectVersion: invitation.id,
    },
  );
}

export function completeSelection(state, { creatorId, runId }) {
  if (!state.matchRun) {
    fail("MATCH_RUN_MISSING", "尚无匹配运行");
  }
  if (runId !== state.matchRun.id) {
    fail("RUN_MISMATCH", "选择只能引用当前同一次 MatchRun");
  }
  if (state.selection) {
    fail("SELECTION_ALREADY_COMPLETED", "选择已经完成");
  }
  const invitation = state.matchRun.invitations.find((item) => item.creatorId === creatorId);
  if (!invitation || invitation.status !== "ACCEPTED") {
    fail("CANDIDATE_NOT_ACCEPTED", "只有当前明确接受的候选可被选择");
  }
  return commit(
    state,
    {
      demand: { ...state.demand, status: "SELECTED" },
      matchRun: { ...state.matchRun, status: "SELECTION_COMPLETED" },
      selection: {
        id: "selection-demo-001",
        runId,
        creatorId,
        selectorId: "synthetic-selector",
        status: "COMPLETED",
        reason: "从同 run 已接受候选中，按授权与交付覆盖作出合成选择",
      },
      project: {
        id: "project-demo-001",
        status: "PENDING_AGREEMENT",
        creatorId,
        demandVersion: state.demand.version,
      },
      agreement: {
        id: "agreement-demo-001",
        version: 1,
        status: "PENDING_ACCEPTANCE",
        requiredSignatories: ["synthetic-demand-signatory", creatorId],
        acceptedBy: [],
        changeSummary: null,
        history: [],
      },
      milestone: {
        id: "milestone-demo-001",
        status: "BLOCKED_BY_AGREEMENT",
        fundingStatus: "NOT_VERIFIED",
        fundingEvidenceRef: null,
      },
    },
    {
      actorId: "synthetic-selector",
      authority: "DEMAND_VERSION_CANDIDATE_SELECTOR",
      action: "SELECTION_COMPLETED",
      reason: "候选属于同一次运行且当前已明确接受",
      objectVersion: runId,
    },
  );
}

export function acceptAgreement(state, actorId, version) {
  if (!state.agreement) {
    fail("AGREEMENT_MISSING", "尚未创建协议");
  }
  if (version !== state.agreement.version) {
    fail("AGREEMENT_VERSION_MISMATCH", "签字版本必须与当前协议版本完全一致");
  }
  if (!state.agreement.requiredSignatories.includes(actorId)) {
    fail("SIGNATORY_NOT_AUTHORIZED", "该主体不是当前版本的必要签字人");
  }
  if (state.agreement.acceptedBy.includes(actorId)) {
    return state;
  }
  const acceptedBy = [...state.agreement.acceptedBy, actorId];
  const active = state.agreement.requiredSignatories.every((id) => acceptedBy.includes(id));
  return commit(
    state,
    {
      agreement: {
        ...state.agreement,
        acceptedBy,
        status: active ? "ACTIVE" : "PENDING_ACCEPTANCE",
      },
      project: active ? { ...state.project, status: "READY_FOR_MILESTONE_FUNDING" } : state.project,
      milestone: active
        ? { ...state.milestone, status: "BLOCKED_BY_FUNDING" }
        : state.milestone,
    },
    {
      actorId,
      authority: "CURRENT_AGREEMENT_SIGNATORY",
      action: "AGREEMENT_VERSION_ACCEPTED",
      reason: `明示接受同一 AgreementVersion v${version}`,
      objectVersion: `agreement-v${version}`,
    },
  );
}

export function secureSyntheticMilestoneFunding(state) {
  if (!state.agreement || state.agreement.status !== "ACTIVE") {
    fail("AGREEMENT_NOT_ACTIVE", "协议生效前不能核验里程碑资金");
  }
  if (state.milestone.fundingStatus === "SECURED") {
    return state;
  }
  return commit(
    state,
    {
      milestone: {
        ...state.milestone,
        status: "READY",
        fundingStatus: "SECURED",
        fundingEvidenceRef: "synthetic-ledger-entry-milestone-001",
      },
      project: { ...state.project, status: "READY_TO_START" },
    },
    {
      actorId: "synthetic-finance-reconciler",
      authority: "SEPARATED_SYNTHETIC_RECONCILIATION",
      action: "MILESTONE_FUNDING_SECURED",
      reason: "独立的合成里程碑义务已与合成账簿核对",
      objectVersion: state.milestone.id,
    },
  );
}

export function startMilestone(state) {
  if (!state.agreement || state.agreement.status !== "ACTIVE") {
    fail("AGREEMENT_NOT_ACTIVE", "所有必要方接受同版协议前不能开工");
  }
  if (!state.milestone || state.milestone.fundingStatus !== "SECURED") {
    fail("MILESTONE_FUNDING_NOT_SECURED", "里程碑资金未核验，不能开工");
  }
  if (state.milestone.status === "IN_PROGRESS") {
    return state;
  }
  return commit(
    state,
    {
      milestone: { ...state.milestone, status: "IN_PROGRESS" },
      project: { ...state.project, status: "IN_PROGRESS" },
    },
    {
      actorId: state.selection.creatorId,
      authority: "ACTIVE_AGREEMENT_PARTY",
      action: "MILESTONE_STARTED",
      reason: "同版协议已生效且独立里程碑资金证据为 SECURED",
      objectVersion: `agreement-v${state.agreement.version}`,
    },
  );
}

export function proposeAgreementChange(state, { actorId, summary }) {
  if (!state.agreement) {
    fail("AGREEMENT_MISSING", "尚未创建协议");
  }
  if (!state.agreement.requiredSignatories.includes(actorId)) {
    fail("CHANGE_ACTOR_NOT_AUTHORIZED", "只有受影响且获授权的一方可提出变更");
  }
  if (!summary?.trim()) {
    fail("CHANGE_SUMMARY_REQUIRED", "实质变更必须说明影响");
  }
  const previous = {
    version: state.agreement.version,
    status: state.agreement.status,
    acceptedBy: [...state.agreement.acceptedBy],
    changeSummary: state.agreement.changeSummary,
  };
  const version = state.agreement.version + 1;
  return commit(
    state,
    {
      agreement: {
        ...state.agreement,
        version,
        status: "PENDING_ACCEPTANCE",
        acceptedBy: [],
        changeSummary: summary.trim(),
        history: [...state.agreement.history, previous],
      },
      milestone: { ...state.milestone, status: "BLOCKED_BY_CHANGE" },
      project: { ...state.project, status: "CHANGE_PENDING" },
    },
    {
      actorId,
      authority: "AFFECTED_AGREEMENT_PARTY",
      action: "AGREEMENT_CHANGE_PROPOSED",
      reason: summary.trim(),
      objectVersion: `agreement-v${version}`,
    },
  );
}

export function recordDelivery(state) {
  if (!state.milestone || state.milestone.status !== "IN_PROGRESS") {
    fail("MILESTONE_NOT_IN_PROGRESS", "只有进行中的里程碑可提交交付");
  }
  return commit(
    state,
    {
      milestone: { ...state.milestone, status: "DELIVERED" },
      delivery: {
        id: "delivery-demo-001",
        version: 1,
        status: "PENDING_ACCEPTANCE",
        fixture: "内置安全交付元数据；无上传和真实文件",
        contractAcceptance: null,
        beneficiaryConfirmation: null,
      },
    },
    {
      actorId: state.selection.creatorId,
      authority: "PROJECT_CREATOR",
      action: "DELIVERY_VERSION_SUBMITTED",
      reason: "提交内置合成交付，不包含真实文件或外部上传",
      objectVersion: "delivery-v1",
    },
  );
}

export function acceptDelivery(state) {
  if (!state.delivery || state.delivery.status !== "PENDING_ACCEPTANCE") {
    fail("DELIVERY_NOT_PENDING", "没有待验收的交付版本");
  }
  return commit(
    state,
    {
      milestone: { ...state.milestone, status: "ACCEPTED" },
      project: { ...state.project, status: "PAYMENT_DUE" },
      delivery: {
        ...state.delivery,
        status: "ACCEPTED",
        contractAcceptance: {
          actorId: "synthetic-acceptance-reviewer",
          result: "ACCEPTED",
          reason: "三项版本化验收标准均满足（合成演练）",
        },
        beneficiaryConfirmation: {
          actorId: "synthetic-beneficiary-representative",
          result: "USEFUL_WITH_NOTES",
          observation: "清晰语言版本可用；建议未来增加音频替代（合成观察）",
        },
      },
    },
    {
      actorId: "synthetic-acceptance-reviewer",
      authority: "DEMAND_VERSION_ACCEPTANCE_REVIEWER",
      action: "DELIVERY_ACCEPTED",
      reason: "合同验收与受益者成果确认分别记录",
      objectVersion: "delivery-v1",
    },
  );
}

export function requestPayment(state) {
  if (state.payment.status !== "NOT_REQUESTED") {
    fail("PAYMENT_ALREADY_REQUESTED", "该义务已经发起，不能重复付款");
  }
  if (!state.milestone || state.milestone.status !== "ACCEPTED") {
    fail("MILESTONE_NOT_ACCEPTED", "里程碑验收前不能发起付款");
  }
  return commit(
    state,
    {
      payment: {
        ...state.payment,
        status: "REQUESTED",
        retryAllowed: false,
        providerReference: "synthetic-provider-request-001",
      },
    },
    {
      actorId: "synthetic-payment-initiator",
      authority: "SEPARATED_PAYMENT_INITIATION",
      action: "PAYMENT_REQUESTED",
      reason: "已验收里程碑对应的一笔合成付款义务",
      objectVersion: state.payment.id,
    },
  );
}

export function applyPaymentStatus(state, status) {
  const allowed = new Set(["PROCESSING", "UNKNOWN", "FAILED"]);
  if (!allowed.has(status)) {
    if (status === "PAID") {
      fail("RECONCILIATION_REQUIRED", "PAID 只能来自独立对账，不能由回调或超时推断");
    }
    fail("INVALID_PROVIDER_STATUS", "provider 状态不在演练范围");
  }
  if (!new Set(["REQUESTED", "PROCESSING"]).has(state.payment.status)) {
    fail("PAYMENT_STATUS_NOT_APPLICABLE", "当前付款状态不能消费 provider 结果");
  }
  return commit(
    state,
    {
      payment: {
        ...state.payment,
        status,
        retryAllowed: status === "FAILED",
        authoritativeSource: null,
      },
    },
    {
      actorId: "synthetic-provider-adapter",
      authority: "UNTRUSTED_SYNTHETIC_CALLBACK",
      action: `PAYMENT_${status}`,
      reason:
        status === "UNKNOWN"
          ? "合成 provider 结果未知；保持未知并禁止盲目重试"
          : `合成 provider 报告 ${status}，等待对账事实`,
      objectVersion: state.payment.id,
    },
  );
}

export function reconcilePayment(state, result) {
  if (!new Set(["PAID", "FAILED", "REFUNDED", "REVERSED"]).has(result)) {
    fail("INVALID_RECONCILIATION_RESULT", "对账结果不受支持");
  }
  if (!new Set(["REQUESTED", "PROCESSING", "UNKNOWN", "FAILED", "PAID"]).has(state.payment.status)) {
    fail("PAYMENT_NOT_RECONCILABLE", "当前付款状态不能对账");
  }
  return commit(
    state,
    {
      payment: {
        ...state.payment,
        status: result,
        retryAllowed: result === "FAILED",
        authoritativeSource: "SYNTHETIC_RECONCILIATION_LEDGER",
      },
      project: result === "PAID" ? { ...state.project, status: "PAID" } : state.project,
    },
    {
      actorId: "synthetic-finance-reconciler",
      authority: "SEPARATED_SYNTHETIC_RECONCILIATION",
      action: `PAYMENT_RECONCILED_${result}`,
      reason: "最终显示来自独立合成账簿，而非请求、自报或超时推断",
      objectVersion: state.payment.id,
    },
  );
}

export function recordOutcome(state) {
  if (state.payment.status !== "PAID") {
    fail("PAYMENT_NOT_FINAL", "付款事实未收敛前不能关闭本次协作复盘");
  }
  return commit(
    state,
    {
      project: { ...state.project, status: "COMPLETED" },
      outcome: {
        financialFact: { paymentStatus: "PAID", source: state.payment.authoritativeSource },
        creatorObservation: "边界得到尊重，愿意继续解决同类问题（合成观察）",
        demandObservation: "需求澄清减少了返工（合成观察）",
        relationshipIntent: "BOTH_OPEN_TO_FUTURE_COLLABORATION",
        beneficiaryConfirmation: state.delivery?.beneficiaryConfirmation ?? null,
        outcomePath: state.demand.outcomePath,
        globalScore: null,
      },
    },
    {
      actorId: "synthetic-case-coordinator",
      authority: "OUTCOME_FACILITATION_ONLY",
      action: "CONTEXTUAL_OUTCOME_RECORDED",
      reason: "财务事实、自报观察、关系意愿和成果路径分别保存，不生成总分",
      objectVersion: "outcome-v1",
    },
  );
}

export function submitReport(state, { reporterId, summary }) {
  if (!reporterId || !summary?.trim()) {
    fail("REPORT_INCOMPLETE", "举报预演需要提交者和最小摘要");
  }
  if (state.safety.report) {
    fail("REPORT_ALREADY_SUBMITTED", "举报已经提交，不能覆盖");
  }
  return commit(
    state,
    {
      safety: {
        ...state.safety,
        report: {
          id: "safety-report-demo-001",
          reporterId,
          summary: summary.trim(),
          status: "PENDING_REVIEW",
        },
      },
    },
    {
      actorId: reporterId,
      authority: "REPORTER_SELF",
      action: "SAFETY_REPORT_SUBMITTED",
      reason: "举报独立进入安全队列，尚未产生初次决定",
      objectVersion: "safety-report-v1",
    },
  );
}

export function decideReport(state, { reviewerId, outcome }) {
  if (!reviewerId || !outcome) {
    fail("REPORT_DECISION_INCOMPLETE", "初次决定需要复核者和结果");
  }
  if (!state.safety.report) {
    fail("REPORT_MISSING", "必须先提交举报，再由获授权人员作初次决定");
  }
  if (state.safety.decision) {
    fail("REPORT_ALREADY_DECIDED", "初次决定已经存在，不能覆盖");
  }
  return commit(
    state,
    {
      safety: {
        ...state.safety,
        report: { ...state.safety.report, status: "DECIDED" },
        decision: {
          reviewerId,
          outcome,
          scope: "PROJECT_MESSAGES_ONLY",
          expiresAt: "SIM-T+048",
          reason: "在独立核验前限制与风险直接相关的消息动作",
        },
      },
    },
    {
      actorId: reviewerId,
      authority: "SYNTHETIC_SAFETY_REVIEWER",
      action: "LIMITED_SAFETY_DECISION",
      reason: "最小范围、自动到期；不影响付款请求、数据权或申诉",
      objectVersion: "safety-decision-v1",
    },
  );
}

export function appealDecision(state, { reviewerId, outcome }) {
  if (!state.safety.decision) {
    fail("DECISION_MISSING", "没有可申诉的初次决定");
  }
  if (reviewerId === state.safety.decision.reviewerId) {
    fail("REVIEWER_NOT_INDEPENDENT", "原决定人不能处理申诉");
  }
  if (state.safety.appeal) {
    fail("APPEAL_ALREADY_DECIDED", "申诉决定已经存在，不能覆盖");
  }
  return commit(
    state,
    {
      safety: {
        ...state.safety,
        appeal: {
          reviewerId,
          outcome,
          remedy: outcome === "MODIFIED" ? "缩短消息限制并恢复被误限动作" : "维持原相称措施",
        },
      },
    },
    {
      actorId: reviewerId,
      authority: "INDEPENDENT_APPEAL_REVIEWER",
      action: "APPEAL_DECIDED",
      reason: "复核者与原决定人分离，更正以追加事件保存",
      objectVersion: "appeal-v1",
    },
  );
}

export function exportSubjectData(state, subjectId) {
  const creator = state.creators[subjectId];
  if (!creator) {
    fail("SUBJECT_NOT_FOUND", "合成主体不存在");
  }
  return {
    format: "desire-supply-synthetic-portability-v1",
    generatedFrom: "IN_MEMORY_SYNTHETIC_PROTOTYPE",
    subjectId,
    profile: {
      name: creator.name,
      capabilityTags: [...creator.capabilityTags],
      disclosedAvailability: creator.disclosedAvailability,
      evidenceRefs: [...creator.evidenceRefs],
      publicBoundary: creator.publicBoundary,
    },
    invitations: state.matchRun
      ? state.matchRun.invitations
          .filter((item) => item.creatorId === subjectId)
          .map(({ id, runId, status }) => ({ id, runId, status }))
      : [],
    exclusions: [
      "其他候选资料",
      "受益者私密叙事",
      "运营安全正文",
      "非该主体的授权证据",
    ],
    integrity: "sha256:synthetic-export-demo",
    disclaimer: "合成演练输出，不代表真实数据导出已完成",
  };
}

export function requestDeletion(state, subjectId) {
  if (!state.creators[subjectId]) {
    fail("SUBJECT_NOT_FOUND", "合成主体不存在");
  }
  return {
    id: "rights-request-demo-001",
    subjectId,
    status: "ITEMIZED",
    items: [
      {
        category: "profile-private-payload",
        result: "DELETE",
        reason: "原型刷新即可删除；无持久化副本",
      },
      {
        category: "decision-index",
        result: "RETAIN_MINIMUM",
        reason: "只保留证明决定存在所需的合成索引；不含敏感正文",
      },
      {
        category: "third-party-statements",
        result: "EXCLUDE_FROM_SUBJECT_EXPORT",
        reason: "须同时保护第三方权利，不能随主体请求一并披露",
      },
    ],
    disclaimer: "该分项结果仅演示语义，不执行真实删除",
  };
}

export function submitExportRequest(state, subjectId) {
  const result = exportSubjectData(state, subjectId);
  const request = {
    id: `rights-request-${state.rights.requests.length + 1}`,
    type: "EXPORT",
    subjectId,
    status: "SYNTHETIC_PREVIEW_READY",
    result,
  };
  return commit(
    state,
    { rights: { ...state.rights, requests: [...state.rights.requests, request] } },
    {
      actorId: subjectId,
      authority: "DATA_SUBJECT_SELF",
      action: "DATA_EXPORT_PREVIEW_REQUESTED",
      reason: "生成可理解的合成导出预演并排除第三方资料",
      objectVersion: result.format,
    },
  );
}

export function submitDeletionRequest(state, subjectId) {
  const result = requestDeletion(state, subjectId);
  const request = {
    id: `rights-request-${state.rights.requests.length + 1}`,
    type: "DELETE",
    subjectId,
    status: "SYNTHETIC_PREVIEW_READY",
    result,
  };
  return commit(
    state,
    { rights: { ...state.rights, requests: [...state.rights.requests, request] } },
    {
      actorId: subjectId,
      authority: "DATA_SUBJECT_SELF",
      action: "DATA_DELETION_PREVIEW_REQUESTED",
      reason: "逐项预演删除、必要最小保留与第三方权利边界",
      objectVersion: result.id,
    },
  );
}

export function cancelDemand(state, reason) {
  if (new Set(["CANCELLED", "REJECTED", "CLOSED"]).has(state.demand.status)) {
    return state;
  }
  return commit(
    state,
    {
      demand: { ...state.demand, status: "CANCELLED" },
      matchRun: state.matchRun ? { ...state.matchRun, status: "CLOSED" } : null,
    },
    {
      actorId: "synthetic-demand-signatory",
      authority: "DEMAND_CANCELLATION_AUTHORITY",
      action: "DEMAND_CANCELLED",
      reason: reason || "合成需求被取消",
      objectVersion: `demand-v${state.demand.version}`,
    },
  );
}
