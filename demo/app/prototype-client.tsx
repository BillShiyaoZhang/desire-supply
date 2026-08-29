"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import {
  PrototypeDomainError,
  acceptAgreement,
  acceptDelivery,
  acceptSyntheticConsent,
  appealDecision,
  applyPaymentStatus,
  cancelDemand,
  completeSelection,
  createPrototype,
  decideReport,
  proposeAgreementChange,
  reconcilePayment,
  recordDelivery,
  recordOutcome,
  requestPayment,
  respondToInvitation,
  runMatching,
  secureSyntheticFunding,
  secureSyntheticMilestoneFunding,
  startMilestone,
  submitDeletionRequest,
  submitExportRequest,
  submitReport,
} from "../lib/prototype.js";

const roleLabels: Record<string, string> = {
  PROBLEM_PROPOSER: "问题提出者",
  BENEFICIARY: "实际受益者",
  BENEFICIARY_REPRESENTATIVE: "受益者代表",
  FUNDER_PURCHASER: "出资 / 采购者",
  RESOURCE_PROVIDER: "资源提供者",
  DEMAND_DECISION_MAKER: "需求决策人",
  CANDIDATE_SELECTOR: "候选选择者",
  ACCEPTANCE_REVIEWER: "验收人",
  PROJECT_COORDINATOR: "项目协调者",
};

const actionLabels: Record<string, string> = {
  PROTOTYPE_RESET: "载入合成初始状态",
  PURPOSE_CONSENT_ACCEPTED: "目的同意已预演",
  DEMAND_FUNDING_SECURED: "需求资金已核验",
  LIMITED_MATCH_RUN_CREATED: "有限邀请已生成",
  INVITATION_ACCEPTED: "邀请已接受",
  INVITATION_DECLINED: "邀请已拒绝",
  INVITATION_WITHDRAWN: "接受已撤回",
  INVITATION_EXPIRED: "邀请已超时",
  SELECTION_COMPLETED: "授权选择已完成",
  AGREEMENT_VERSION_ACCEPTED: "协议版本已明示接受",
  MILESTONE_FUNDING_SECURED: "里程碑资金已核验",
  MILESTONE_STARTED: "里程碑已开工",
  DELIVERY_VERSION_SUBMITTED: "交付版本已提交",
  DELIVERY_ACCEPTED: "两份合成结果已载入",
  PAYMENT_REQUESTED: "付款义务已发起",
  PAYMENT_PROCESSING: "provider 信号：处理中",
  PAYMENT_UNKNOWN: "provider 信号：结果未知",
  PAYMENT_RECONCILED_PAID: "合成最终状态 · PAID",
  CONTEXTUAL_OUTCOME_RECORDED: "情境化复盘已记录",
  SAFETY_REPORT_SUBMITTED: "合成举报已进入队列",
  LIMITED_SAFETY_DECISION: "最小临时保护已决定",
  APPEAL_DECIDED: "独立申诉已复核",
  DATA_EXPORT_PREVIEW_REQUESTED: "数据副本预览已生成",
  DATA_DELETION_PREVIEW_REQUESTED: "删除分项预演已生成",
  AGREEMENT_CHANGE_PROPOSED: "协议变更版本已提出",
  DEMAND_CANCELLED: "需求已取消",
};

const scenarioCards = [
  { id: "normal", code: "主旅程", title: "正常旅程", copy: "从目的同意走到情境化复盘，中途经过一次付款 UNKNOWN。" },
  { id: "decline", code: "DEMO-AC-02", title: "拒绝不惩罚", copy: "拒绝者不可被选择，但未来资格不变，也不生成负面特征。" },
  { id: "payment", code: "DEMO-AC-06", title: "付款结果未知", copy: "provider 信号不等于财务事实；未知时禁止重复发起。" },
  { id: "appeal", code: "DEMO-AC-07", title: "独立申诉", copy: "原决定人不能复核自己的决定，临时保护保持最小范围。" },
  { id: "rights", code: "DEMO-AC-08", title: "数据退出", copy: "导出过滤第三方资料；删除按类别返回可删与必要保留。" },
];

const stepLabels = [
  "边界与目的",
  "需求与资金",
  "邀请与选择",
  "协议与开工",
  "交付与付款",
  "安全与申诉",
  "数据权与证据",
];

function activateAllConsents(state: ReturnType<typeof createPrototype>) {
  let next = state;
  for (const creatorId of Object.keys(next.creators)) {
    next = acceptSyntheticConsent(next, creatorId, "synthetic-purpose-policy-v1");
  }
  return next;
}

function buildSelectedScenario() {
  let state = activateAllConsents(createPrototype());
  state = runMatching(secureSyntheticFunding(state));
  state = respondToInvitation(state, "creator-chen", "ACCEPTED");
  return completeSelection(state, { creatorId: "creator-chen", runId: state.matchRun!.id });
}

function buildPaymentUnknownScenario() {
  let state = buildSelectedScenario();
  state = acceptAgreement(state, "synthetic-demand-signatory", 1);
  state = acceptAgreement(state, "creator-chen", 1);
  state = secureSyntheticMilestoneFunding(state);
  state = startMilestone(state);
  state = recordDelivery(state);
  state = acceptDelivery(state);
  state = requestPayment(state);
  state = applyPaymentStatus(state, "PROCESSING");
  return applyPaymentStatus(state, "UNKNOWN");
}

function buildScenario(id: string) {
  if (id === "decline") {
    const state = runMatching(secureSyntheticFunding(activateAllConsents(createPrototype())));
    return respondToInvitation(state, "creator-chen", "DECLINED");
  }
  if (id === "payment") return buildPaymentUnknownScenario();
  if (id === "appeal") {
    const state = submitReport(createPrototype(), {
      reporterId: "creator-chen",
      summary: "合成场景：收到超出协议范围的施压信息",
    });
    return decideReport(state, { reviewerId: "synthetic-safety-reviewer", outcome: "LIMITED_HOLD" });
  }
  if (id === "rights") {
    const state = submitExportRequest(createPrototype(), "creator-chen");
    return submitDeletionRequest(state, "creator-chen");
  }
  return createPrototype();
}

function currentStage(state: ReturnType<typeof createPrototype>, scenario: string) {
  if (scenario === "appeal") return 5;
  if (scenario === "rights") return 6;
  if (!Object.values(state.consents).every((item) => item.status === "ACTIVE")) return 0;
  if (state.funding.status !== "SECURED" || !state.matchRun) return 1;
  if (!state.selection) return 2;
  if (!state.agreement || state.agreement.status !== "ACTIVE" || state.milestone?.status === "READY") return 3;
  if (!state.outcome) return 4;
  return 6;
}

function statusClass(status: string) {
  if (["SECURED", "ACTIVE", "PAID", "COMPLETED", "ACCEPTED", "ELIGIBLE"].includes(status)) return "status status--good";
  if (["UNKNOWN", "PENDING", "PENDING_ACCEPTANCE", "FUNDING_PENDING", "NOT_VERIFIED"].includes(status)) return "status status--unknown";
  if (["DECLINED", "CANCELLED", "BLOCKED_BY_CHANGE"].includes(status)) return "status status--stopped";
  return "status";
}

function formatMoney(amount: number, currency: string) {
  return new Intl.NumberFormat("zh-CN", { style: "currency", currency, maximumFractionDigits: 0 }).format(amount);
}

export function PrototypeClient() {
  const [state, setState] = useState(() => createPrototype());
  const [scenario, setScenario] = useState("normal");
  const [notice, setNotice] = useState("已载入完全合成的初始状态。请选择场景，或沿主旅程逐步演练。");
  const [ruleResult, setRuleResult] = useState<{ code: string; message: string } | null>(null);
  const [hasLoadedScenario, setHasLoadedScenario] = useState(false);
  const workbenchRef = useRef<HTMLHeadingElement>(null);
  const resultRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (hasLoadedScenario) workbenchRef.current?.focus();
  }, [scenario, hasLoadedScenario]);

  const stage = currentStage(state, scenario);
  const activeScenario = scenarioCards.find((item) => item.id === scenario) ?? scenarioCards[0];
  const acceptedInvitation = state.matchRun?.invitations.find((item) => item.status === "ACCEPTED");
  const pendingConsent = Object.values(state.consents).find((item) => item.status === "PENDING");

  const nextAction = useMemo(() => {
    if (pendingConsent) {
      return {
        title: `模拟 ${state.creators[pendingConsent.subjectId].name} 明示目的同意`,
        condition: "只有当前用途和当前政策版本的 ACTIVE Consent 才能进入匹配快照。",
        run: (s: ReturnType<typeof createPrototype>) => acceptSyntheticConsent(s, pendingConsent.subjectId, pendingConsent.policyVersion),
        result: "已追加一条合成目的同意事件；这不构成真实个人同意。",
      };
    }
    if (state.funding.status !== "SECURED") {
      return {
        title: "演示 Demand v1 资金核验",
        condition: "预算描述、请求或截图都不能冒充 SECURED。",
        run: secureSyntheticFunding,
        result: "合成状态变为 SECURED；不代表真实托管、担保或到账。",
      };
    }
    if (!state.matchRun) {
      return {
        title: "生成三份有限合成邀请",
        condition: "固定规则、最多三名候选、只使用当前同意的最小披露资料。",
        run: runMatching,
        result: "已生成固定且可解释的邀请；不是 AI 决策或完整人才搜索。",
      };
    }
    if (!acceptedInvitation && !state.selection) {
      return {
        title: "模拟陈澄接受邀请",
        condition: "创作者本人可以接受、拒绝、撤回或让邀请到期。",
        run: (s: ReturnType<typeof createPrototype>) => respondToInvitation(s, "creator-chen", "ACCEPTED"),
        result: "陈澄（虚构）已在本次运行中明示接受。",
      };
    }
    if (!state.selection && acceptedInvitation) {
      return {
        title: "由顾遥（虚构）完成授权选择",
        condition: "只能选择同一 MatchRun 中当前明确 ACCEPTED 的候选。",
        run: (s: ReturnType<typeof createPrototype>) => completeSelection(s, { creatorId: acceptedInvitation.creatorId, runId: s.matchRun!.id }),
        result: "选择已完成并创建 Project shell；尚未满足开工条件。",
      };
    }
    if (state.agreement && state.agreement.status !== "ACTIVE") {
      const missing = state.agreement.requiredSignatories.find((id: string) => !state.agreement!.acceptedBy.includes(id));
      return {
        title: `模拟 ${missing === "synthetic-demand-signatory" ? "需求方" : "创作者"}明示接受 Agreement v${state.agreement.version}`,
        condition: "双方必须分别接受完全相同的版本；本动作不是法律签名。",
        run: (s: ReturnType<typeof createPrototype>) => acceptAgreement(s, missing!, s.agreement!.version),
        result: `已追加一方对 Agreement v${state.agreement.version} 的合成接受。`,
      };
    }
    if (state.milestone && state.milestone.fundingStatus !== "SECURED") {
      return {
        title: "演示独立里程碑资金核验",
        condition: "Demand 资金与里程碑报酬是两笔不同义务，不能共用一个 paid。",
        run: secureSyntheticMilestoneFunding,
        result: "合成里程碑义务已核验；不代表现实资金保障。",
      };
    }
    if (state.milestone?.status === "READY" || state.milestone?.status === "BLOCKED_BY_FUNDING") {
      return {
        title: "模拟里程碑开工",
        condition: "同版协议 ACTIVE 且独立里程碑资金 SECURED。",
        run: startMilestone,
        result: "里程碑进入 IN_PROGRESS；所有事实仍只存在于本次浏览器会话。",
      };
    }
    if (state.milestone?.status === "IN_PROGRESS") {
      return {
        title: "提交内置合成交付版本",
        condition: "只使用安全 fixture 元数据；不开启真实文件上传。",
        run: recordDelivery,
        result: "Delivery v1 已进入合成验收队列。",
      };
    }
    if (state.milestone?.status === "DELIVERED") {
      return {
        title: "载入两份分别记录的合成结果",
        condition: "合同验收与受益者成果确认必须分开呈现。",
        run: acceptDelivery,
        result: "合同验收与受益者观察已分别记录；不是同一事实。",
      };
    }
    if (state.milestone?.status === "ACCEPTED" && state.payment.status === "NOT_REQUESTED") {
      return {
        title: "模拟发起一笔付款义务",
        condition: "发起与核实职责分离，REQUESTED 不等于 PAID。",
        run: requestPayment,
        result: "合成付款义务为 REQUESTED；尚无最终财务事实。",
      };
    }
    if (state.payment.status === "REQUESTED") {
      return {
        title: "载入 provider PROCESSING 信号",
        condition: "外部信号只说明处理中，不能成为最终财务事实。",
        run: (s: ReturnType<typeof createPrototype>) => applyPaymentStatus(s, "PROCESSING"),
        result: "provider 合成信号为 PROCESSING；继续等待。",
      };
    }
    if (state.payment.status === "PROCESSING") {
      return {
        title: "模拟 provider 返回 UNKNOWN",
        condition: "超时不能推断成功或失败，UNKNOWN 时禁止盲目重试。",
        run: (s: ReturnType<typeof createPrototype>) => applyPaymentStatus(s, "UNKNOWN"),
        result: "结果保持 UNKNOWN；下一步只能独立调查与对账。",
      };
    }
    if (state.payment.status === "UNKNOWN") {
      return {
        title: "依据独立合成账簿对账为 PAID",
        condition: "只有分离的 reconciliation 事实可以收敛最终状态。",
        run: (s: ReturnType<typeof createPrototype>) => reconcilePayment(s, "PAID"),
        result: "合成最终状态为 PAID；不代表现实资金到账。",
      };
    }
    if (state.payment.status === "PAID" && !state.outcome) {
      return {
        title: "记录情境化结果与关系意愿",
        condition: "财务事实、双方观察、成果路径与关系意愿分开，不生成总分。",
        run: recordOutcome,
        result: "主旅程完成；原型没有给任何人生成星级、等级或全局人格分。",
      };
    }
    return {
      title: "重新载入正常旅程",
      condition: "刷新或重置会清空全部会话内合成状态。",
      run: () => createPrototype(),
      result: "已回到完全合成的初始状态。",
    };
  }, [acceptedInvitation, pendingConsent, state]);

  function runAction(action: (current: ReturnType<typeof createPrototype>) => ReturnType<typeof createPrototype>, success: string) {
    try {
      const nextState = action(state);
      setState(nextState);
      setRuleResult(null);
      setNotice(success);
    } catch (error) {
      const domainError = error as typeof PrototypeDomainError.prototype;
      setRuleResult({ code: domainError.code ?? "UNEXPECTED", message: domainError.message });
      setNotice("规则按预期阻止了该动作；没有创建新的业务事实。下面显示规则检查结果。");
    }
    requestAnimationFrame(() => resultRef.current?.focus());
  }

  function loadScenario(id: string) {
    setState(buildScenario(id));
    setScenario(id);
    setRuleResult(null);
    setHasLoadedScenario(true);
    setNotice(`${scenarioCards.find((item) => item.id === id)?.title}场景已载入。所有状态仍是可清空的合成预演。`);
  }

  function reset() {
    setState(createPrototype());
    setScenario("normal");
    setRuleResult(null);
    setNotice("已重新载入合成初始状态；没有删除或改变任何真实资料。");
  }

  function demonstrateRejectedSelection() {
    const declined = state.matchRun?.invitations.find((item) => item.status === "DECLINED");
    if (!declined || !state.matchRun) return;
    runAction(
      (current) => completeSelection(current, { creatorId: declined.creatorId, runId: current.matchRun!.id }),
      "不应到达这里",
    );
  }

  function demonstrateOriginalReviewerConflict() {
    runAction(
      (current) => appealDecision(current, { reviewerId: "synthetic-safety-reviewer", outcome: "UPHELD" }),
      "不应到达这里",
    );
  }

  const facts = useMemo(() => {
    if (stage === 0) return { title: "目的边界尚未完整", body: `${Object.values(state.consents).filter((item) => item.status === "ACTIVE").length} / 3 名合成创作者已对当前用途明示同意。` };
    if (stage === 1) return { title: state.funding.status === "UNKNOWN" ? "证据不足，匹配必须停下" : "需求资金已具备合成证据", body: `Demand v${state.demand.version} 的 ${formatMoney(state.funding.amount, state.funding.currency)} 合成义务当前为 ${state.funding.status}。` };
    if (stage === 2) return { title: "邀请不是分配", body: state.selection ? "已由获授权选择者完成选择。" : "候选必须先自主接受，随后才能被获授权者选择。" };
    if (stage === 3) return { title: "同版协议与资金共同约束开工", body: `Agreement v${state.agreement?.version ?? 1} · ${state.agreement?.status ?? "PENDING"}；Milestone Funding · ${state.milestone?.fundingStatus ?? "NOT_VERIFIED"}。` };
    if (stage === 4) return { title: state.payment.status === "UNKNOWN" ? "付款结果未知，禁止重复发起" : "交付、验收与财务事实分别收敛", body: `里程碑 ${state.milestone?.status ?? "NOT_STARTED"}；付款义务 ${state.payment.status}。` };
    if (stage === 5) return { title: "临时保护不是事实裁决", body: "最小范围、自动到期、保留付款主张/数据权/申诉，并由不同人员复核。" };
    return { title: "退出也是主旅程", body: "导出过滤第三方资料；删除返回分项结果；事件列表只在本次会话内追加。" };
  }, [stage, state]);

  return (
    <>
      <a className="skip-link" href="#main-content">跳到主要内容</a>
      <header className="boundary-bar">
        <div className="boundary-bar__inner">
          <a className="brand" href="#top" aria-label="愿作制度原型首页">
            <span className="brand__mark" aria-hidden="true">愿</span>
            <span><strong>愿作</strong><small>制度原型</small></span>
          </a>
          <div className="gate-list" aria-label="当前授权边界">
            <span>G0A · 完全合成</span><span>G1 · NO-GO</span><span>G2 · NO-GO</span>
          </div>
          <button className="button button--quiet" type="button" onClick={reset}>重新载入合成初始状态</button>
        </div>
        <p className="boundary-note">这不是服务入口。页面不连接真实用户、资金、协议接受、文件、通知或外部 AI；刷新即清空。</p>
      </header>

      <main id="main-content">
        <section className="hero" id="top" aria-labelledby="hero-title">
          <div className="hero__copy">
            <p className="eyebrow">FOUNDATIONS · 可执行制度草图</p>
            <h1 id="hero-title">受控协作制度<br />合成演练台</h1>
            <p className="hero__lead">用一个完全虚构的项目，检查协作何时可以继续、何时必须停下，以及谁能提出救济。</p>
            <p className="hero__audience">供产品、运营、工程、隐私与安全负责人共同评审；不面向真实服务参与者。</p>
          </div>
          <aside className="boundary-card" aria-labelledby="boundary-title">
            <p className="card-index">00 / 原型边界</p>
            <h2 id="boundary-title">只验证软件语义，不证明制度有效</h2>
            <dl>
              <div><dt>数据</dt><dd>完全合成</dd></div>
              <div><dt>持久化</dt><dd>无 · 刷新清空</dd></div>
              <div><dt>外部副作用</dt><dd>无</dd></div>
              <div><dt>现实授权</dt><dd>G1 / G2 均未通过</dd></div>
            </dl>
          </aside>
        </section>

        <section className="scenario-section" aria-labelledby="scenario-title">
          <div className="section-heading">
            <p className="eyebrow">确定性场景</p>
            <h2 id="scenario-title">先看失败路径，再判断顺利流程</h2>
            <p>每个入口都会重新载入固定 fixture；不会保存上一次演练，也不会触发外部动作。</p>
          </div>
          <div className="scenario-grid">
            {scenarioCards.map((item, index) => (
              <button
                className="scenario-card"
                type="button"
                key={item.id}
                aria-pressed={scenario === item.id}
                onClick={() => loadScenario(item.id)}
              >
                <span className="scenario-card__number">0{index + 1}</span>
                <span className="scenario-card__code">{item.code}</span>
                <strong>{item.title}</strong>
                <span>{item.copy}</span>
              </button>
            ))}
          </div>
        </section>

        <div className="workspace">
          <section className="workbench" aria-labelledby="workbench-title">
            <div className="workbench__heading">
              <div>
                <p className="eyebrow">当前场景 · {activeScenario.code}</p>
                <h2 id="workbench-title" ref={workbenchRef} tabIndex={-1}>{activeScenario.title}</h2>
              </div>
              <span className="synthetic-stamp">SYNTHETIC<br />NO EXTERNAL EFFECT</span>
            </div>

            <ol className="stepper" aria-label="合成协作旅程阶段">
              {stepLabels.map((label, index) => (
                <li key={label} className={index < stage ? "is-done" : index === stage ? "is-current" : ""} aria-current={index === stage ? "step" : undefined}>
                  <span>{index + 1}</span><small>{label}</small>
                </li>
              ))}
            </ol>

            <article className="stage-card">
              <div className="stage-card__fact">
                <p className="card-index">CURRENT FACT / 当前事实</p>
                <h3>{facts.title}</h3>
                <p>{facts.body}</p>
              </div>
              <div className="stage-card__condition">
                <p className="card-index">CONTINUE ONLY IF / 继续条件</p>
                <p>{nextAction.condition}</p>
              </div>
              <div className="stage-card__action">
                <button className="button button--primary" type="button" onClick={() => runAction(nextAction.run, nextAction.result)}>{nextAction.title}</button>
                <small>合成预演 · 无外部副作用</small>
              </div>
            </article>

            <div className="action-result" ref={resultRef} tabIndex={-1} role="status" aria-live="polite" aria-atomic="true">
              <span>本次结果</span>
              <p>{notice}</p>
            </div>
            {ruleResult && (
              <div className="rule-result" aria-labelledby="rule-result-title">
                <span>规则检查结果 · 未进入证据时间线</span>
                <h3 id="rule-result-title">{ruleResult.code}</h3>
                <p>{ruleResult.message}</p>
                <p>Project 或付款事实未被创建；领域拒绝不冒充业务事件。</p>
              </div>
            )}

            <section className="case-file" aria-labelledby="case-title">
              <div className="case-file__title">
                <div><p className="card-index">DEMAND v{state.demand.version}</p><h3 id="case-title">{state.demand.title}</h3></div>
                <span className={statusClass(state.demand.status)}>{state.demand.status}</span>
              </div>
              <p>{state.demand.summary}</p>
              <dl className="fact-grid">
                <div><dt>虚构预算参数</dt><dd>{formatMoney(state.demand.budget.amount, state.demand.budget.currency)}</dd></div>
                <div><dt>模拟周期</dt><dd>{state.demand.duration}</dd></div>
                <div><dt>成果路径</dt><dd>{state.demand.outcomePath}</dd></div>
                <div><dt>第三方资源</dt><dd>NONE / NOT APPLICABLE</dd></div>
              </dl>
              <details>
                <summary>查看九类逐项授权（{state.demand.authorities.length}）</summary>
                <div className="authority-list">
                  {state.demand.authorities.map((item) => (
                    <article key={item.role}>
                      <span>{roleLabels[item.role]}</span>
                      <strong>{item.subjectLabel}</strong>
                      <small>{item.status} · {item.scope}</small>
                      <p>{item.rationale ?? `${item.authoritySource}；不可从组织身份或付款推断`}</p>
                    </article>
                  ))}
                </div>
              </details>
            </section>

            <section className="funding-panel" aria-labelledby="funding-title">
              <div><p className="card-index">DEMO-AC-01 · MONEY FLOW</p><h3 id="funding-title">需求资金事实</h3></div>
              <div className="funding-panel__status">
                <span className={statusClass(state.funding.status)}>{state.funding.status === "UNKNOWN" ? "结果未知 · UNKNOWN" : `已核验 · ${state.funding.status}`}</span>
                <p>{state.funding.status === "UNKNOWN" ? "没有独立合成证据；匹配必须停下。" : "来自独立合成账簿；不代表真实资金保障。"}</p>
              </div>
            </section>

            {state.matchRun && (
              <section className="candidate-section" aria-labelledby="candidate-title">
                <div className="subsection-heading">
                  <div><p className="card-index">DEMO-AC-02/03 · {state.matchRun.ruleVersion}</p><h3 id="candidate-title">有限邀请，不是人才排名</h3></div>
                  <span>{state.matchRun.invitations.length} 份固定邀请</span>
                </div>
                <p className="privacy-note">只呈现本次用途所需的公开边界与解释；私密底线、完整资料和分项分数从未进入候选卡。</p>
                <div className="candidate-list">
                  {state.matchRun.invitations.map((invitation) => {
                    const creator = state.creators[invitation.creatorId];
                    return (
                      <article key={invitation.id} className="candidate-card">
                        <div><span className={statusClass(invitation.status)}>{invitation.status}</span><small>{invitation.id}</small></div>
                        <h4>{creator.name}</h4>
                        <p>{invitation.explanation}</p>
                        <ul>{creator.capabilityTags.map((tag: string) => <li key={tag}>{tag}</li>)}</ul>
                        <p className="candidate-card__boundary"><strong>公开边界</strong>{creator.publicBoundary}</p>
                        {invitation.status === "INVITED" && (
                          <div className="button-row">
                            <button className="button button--small" type="button" onClick={() => runAction((s) => respondToInvitation(s, creator.id, "ACCEPTED"), `${creator.name}已合成接受邀请。`)}>模拟接受</button>
                            <button className="button button--small button--outline" type="button" onClick={() => runAction((s) => respondToInvitation(s, creator.id, "DECLINED"), `${creator.name}已自主拒绝；未来资格仍为 ELIGIBLE，未生成负面特征。`)}>模拟拒绝</button>
                          </div>
                        )}
                        {invitation.status === "DECLINED" && (
                          <dl className="decline-result">
                            <div><dt>本次选择</dt><dd>不可选择</dd></div>
                            <div><dt>未来资格</dt><dd>{creator.eligibility}</dd></div>
                            <div><dt>负面排序特征</dt><dd>未生成</dd></div>
                          </dl>
                        )}
                      </article>
                    );
                  })}
                </div>
                {state.matchRun.invitations.some((item) => item.status === "DECLINED") && !state.selection && (
                  <button className="text-button" type="button" onClick={demonstrateRejectedSelection}>尝试选择已拒绝候选（演示制度拒绝）</button>
                )}
              </section>
            )}

            {state.agreement && (
              <section className="agreement-section" aria-labelledby="agreement-title">
                <div className="subsection-heading">
                  <div><p className="card-index">DEMO-AC-04/05 · VERSIONED AGREEMENT</p><h3 id="agreement-title">Agreement v{state.agreement.version}</h3></div>
                  <span className={statusClass(state.agreement.status)}>{state.agreement.status}</span>
                </div>
                <div className="signatory-list">
                  {state.agreement.requiredSignatories.map((id: string) => (
                    <div key={id}>
                      <span>{id === "synthetic-demand-signatory" ? "需求方获授权签字人" : "获选创作者"}</span>
                      <strong>{id === "synthetic-demand-signatory" ? "周岚（虚构）" : state.creators[id].name}</strong>
                      <small>{state.agreement!.acceptedBy.includes(id) ? `已明示接受 v${state.agreement!.version}（合成）` : `尚未接受 v${state.agreement!.version}`}</small>
                    </div>
                  ))}
                </div>
                {state.agreement.history.length > 0 && <p className="history-note">v{state.agreement.version - 1} 已成为只读历史；旧接受不会自动迁移到 v{state.agreement.version}。</p>}
                {state.agreement.status === "ACTIVE" && (
                  <button className="text-button" type="button" onClick={() => runAction((s) => proposeAgreementChange(s, { actorId: "synthetic-demand-signatory", summary: "仅顺延两天，不改变报酬与成果路径" }), "已生成 Agreement 新版本；双方旧接受失效，需要重新明示接受。")}>预演仅顺延两天的实质变更</button>
                )}
              </section>
            )}

            {(state.payment.status !== "NOT_REQUESTED" || scenario === "payment") && (
              <section className="payment-section" aria-labelledby="payment-title">
                <div className="subsection-heading">
                  <div><p className="card-index">DEMO-AC-06 · PAYMENT CONVERGENCE</p><h3 id="payment-title">付款义务、provider 信号与财务事实</h3></div>
                  <span className={statusClass(state.payment.status)}>{state.payment.status}</span>
                </div>
                <div className="payment-facts">
                  <div><span>付款义务</span><strong>{formatMoney(state.payment.amount, state.payment.currency)}</strong><small>{state.payment.obligation}</small></div>
                  <div><span>provider 信号</span><strong>{state.payment.status === "UNKNOWN" ? "结果未知 · UNKNOWN" : state.payment.status}</strong><small>不自动成为最终事实</small></div>
                  <div><span>权威财务事实</span><strong>{state.payment.authoritativeSource ? state.payment.status : "尚未收敛"}</strong><small>{state.payment.authoritativeSource ?? "等待独立合成对账"}</small></div>
                </div>
                {state.payment.status === "UNKNOWN" && (
                  <div className="unknown-callout">
                    <p>provider 没有给出可证明成功或失败的结果；保持未知，禁止重复发起。</p>
                    <div className="button-row">
                      <button className="button button--small button--outline" type="button" onClick={() => runAction(requestPayment, "不应到达这里")}>尝试重复发起（演示规则拒绝）</button>
                      <button className="button button--small" type="button" onClick={() => runAction((s) => reconcilePayment(s, "PAID"), "独立合成账簿将最终状态收敛为 PAID；不代表真实到账。")}>依据独立合成账簿对账为 PAID</button>
                    </div>
                  </div>
                )}
              </section>
            )}

            <section className="rights-safety-grid" aria-label="安全救济与数据权预演">
              <article className="remedy-card">
                <p className="card-index">DEMO-AC-07 · SAFETY / APPEAL</p>
                <h3>临时保护与独立申诉</h3>
                {!state.safety.report && <button className="button button--small" type="button" onClick={() => runAction((s) => submitReport(s, { reporterId: "creator-chen", summary: "合成场景：收到超出协议范围的施压信息" }), "合成举报已独立进入队列；尚未作出事实认定。")}>载入最小披露合成举报</button>}
                {state.safety.report && !state.safety.decision && <button className="button button--small" type="button" onClick={() => runAction((s) => decideReport(s, { reviewerId: "synthetic-safety-reviewer", outcome: "LIMITED_HOLD" }), "已载入最小、限时的合成临时保护；这不是过错认定。")}>模拟初次安全决定</button>}
                {state.safety.decision && (
                  <dl className="remedy-facts">
                    <div><dt>范围</dt><dd>{state.safety.decision.scope}</dd></div>
                    <div><dt>到期</dt><dd>{state.safety.decision.expiresAt}</dd></div>
                    <div><dt>不受影响</dt><dd>付款主张 / 数据权 / 申诉</dd></div>
                  </dl>
                )}
                {state.safety.decision && !state.safety.appeal && (
                  <div className="button-stack">
                    <button className="text-button" type="button" onClick={demonstrateOriginalReviewerConflict}>让原决定人复核（演示制度拒绝）</button>
                    <button className="button button--small" type="button" onClick={() => runAction((s) => appealDecision(s, { reviewerId: "synthetic-appeal-reviewer", outcome: "MODIFIED" }), "沈岸（虚构）作为独立复核者修改了措施，并追加补救事件。")}>由沈岸（虚构）独立复核</button>
                  </div>
                )}
                {state.safety.appeal && <p className="remedy-result"><strong>{state.safety.appeal.outcome}</strong>{state.safety.appeal.remedy}</p>}
                <small className="local-boundary">合成安全预演 · 非事实裁决或法律结论</small>
              </article>

              <article className="remedy-card">
                <p className="card-index">DEMO-AC-08 · DATA RIGHTS</p>
                <h3>数据副本与删除分项</h3>
                <div className="button-stack">
                  <button className="button button--small" type="button" onClick={() => runAction((s) => submitExportRequest(s, "creator-chen"), "已预览陈澄的合成数据副本；其他候选与受益者私密资料被排除。")}>预览陈澄的合成数据副本</button>
                  <button className="button button--small button--outline" type="button" onClick={() => runAction((s) => submitDeletionRequest(s, "creator-chen"), "已预演删除请求的分项结果；未执行真实删除。")}>预演删除请求的分项结果</button>
                </div>
                {state.rights.requests.length > 0 && (
                  <ol className="rights-results">
                    {state.rights.requests.map((request) => (
                      <li key={request.id}><strong>{request.type}</strong><span>{request.status}</span><small>未执行真实导出或删除</small></li>
                    ))}
                  </ol>
                )}
                <small className="local-boundary">合成结果预演 · 不是法定请求完成或合规证明</small>
              </article>
            </section>

            {state.outcome && (
              <section className="outcome-section" aria-labelledby="outcome-title">
                <p className="card-index">CONTEXTUAL OUTCOME · NO GLOBAL SCORE</p>
                <h3 id="outcome-title">情境化复盘，不给人定价</h3>
                <div className="outcome-grid">
                  <div><span>财务事实</span><strong>{state.outcome.financialFact.paymentStatus}</strong><p>{state.outcome.financialFact.source}</p></div>
                  <div><span>创作者观察</span><strong>自报 · 合成</strong><p>{state.outcome.creatorObservation}</p></div>
                  <div><span>需求方观察</span><strong>自报 · 合成</strong><p>{state.outcome.demandObservation}</p></div>
                  <div><span>未来关系意愿</span><strong>双方开放</strong><p>{state.outcome.relationshipIntent}</p></div>
                </div>
                <p className="no-score">全局人格分：未生成 · 星级：未生成 · 人物排名：未生成</p>
              </section>
            )}

            <details className="rule-checks">
              <summary>更多规则检查与历史完整性</summary>
              <div className="rule-checks__body">
                <div><strong>跨 run 选择</strong><p>runId 不一致时返回 RUN_MISMATCH，不创建 Project。</p></div>
                <div><strong>错版接受</strong><p>AgreementVersion 不一致时拒绝，旧接受不可迁移。</p></div>
                <div><strong>需求取消</strong><p>CANCELLED 即使字段齐全也不能重新匹配。</p></div>
                <div><strong>实质变更</strong><p>生成新版本并重置必要接受，旧版本保持只读。</p></div>
                <button className="text-button" type="button" onClick={() => {
                  let next = secureSyntheticFunding(activateAllConsents(createPrototype()));
                  next = cancelDemand(next, "需求方撤回合成演练");
                  setState(next); setScenario("normal"); setRuleResult(null); setNotice("已载入 CANCELLED Demand；再次匹配会被 DEMAND_NOT_MATCHABLE 阻止。");
                }}>载入已取消 Demand 反例</button>
              </div>
            </details>
          </section>

          <aside className="evidence-rail" aria-labelledby="evidence-title">
            <div className="evidence-rail__heading">
              <p className="eyebrow">SESSION EVIDENCE</p>
              <h2 id="evidence-title">本次会话内只追加的合成事件列表</h2>
              <p>仅演示动作如何留下可归因证据；刷新会丢失，不是真实事实账簿。</p>
            </div>
            <ol className="timeline">
              {[...state.audit].reverse().map((event) => (
                <li key={event.id}>
                  <div><span>{event.occurredAt}</span><code>{event.correlationId}</code></div>
                  <strong>{actionLabels[event.action] ?? event.action}</strong>
                  <dl>
                    <div><dt>actor</dt><dd>{event.actorId}</dd></div>
                    <div><dt>authority</dt><dd>{event.authority}</dd></div>
                    {event.objectVersion && <div><dt>version</dt><dd>{event.objectVersion}</dd></div>}
                  </dl>
                  <p>{event.reason}</p>
                </li>
              ))}
            </ol>
          </aside>
        </div>
      </main>

      <footer>
        <p><strong>愿作 · Foundations 合成制度原型</strong></p>
        <p>本地运行 · 不连接 OpenAI Sites · 不处理真实身份、资金、合同或权益。</p>
      </footer>
    </>
  );
}
