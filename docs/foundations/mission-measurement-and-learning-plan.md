# 使命衡量与学习计划

> 文档状态：P0/P1 指标目录草案 v0.1  
> 目的：把“自主、公平、关系、公共价值与可持续”转成可审计但不把人总分化的学习系统。  
> 证据边界：本文定义问题、口径和触发方式；基线、阈值、隐私最小样本和真实结果均为 `TBD`，不得填入虚构数字。  
> 原则：指标用于发现风险、触发调查和决定是否继续，不自动处罚个人或证明因果。

## 0. 为什么需要独立指标目录

愿作最容易在增长中偏离：合格 Demand 被“发布量”替代，真实付款被自报替代，关系被成交替代，公平被一个推荐分替代。指标目录必须明确：

- 问的是什么，不问什么；
- 权威事实源和证据等级；
- 分子、分母、时间窗口和排除；
- 哪些需要质性证据；
- 隐私、小样本和群体属性边界；
- 异常由谁复核，会触发什么行动；
- 怎样防止运营团队通过改变口径游戏化。

不建立“使命总分”。不同指标可能合理冲突，应由明确负责的人结合参与者叙事作判断。

## 1. 事实类型

| 类型 | 例子 | 正确用途 | 不得做的事 |
| --- | --- | --- | --- |
| 权威业务事实 | 发出的邀请、接受/拒绝、协议版本、应付日期 | 流程和状态指标 | 从缺失事件推断人的动机 |
| 外部财务事实 | provider/银行/法定账簿对账 | 已支付、退款、冲正 | 用运营勾选代替 |
| 参与者自报 | 意愿、压力、关系体验、再次合作意愿 | 质性体验和假设生成 | 冒充客观付款/法律事实 |
| 运营判断 | 需求真实性、例外、争议解释 | 可问责个案决定 | 变成无审计真相源 |
| 研究观察 | 访谈、任务回放、理解测试 | 解释为什么与发现反例 | 无样本限制地推广 |
| 分析派生 | 集中度、时长、比例、趋势 | 群体风险发现 | 自动降低个体机会/资格 |

所有指标引用事实类型和版本。不同类型并列呈现，不通过平均分混合。

## 2. 指标登记格式

```text
Metric ID / name / version:
Foundation question:
Decision it informs:
Activation gate / required scope:
Collection mode:
Classification:
Population and eligibility:
Numerator / denominator / unit:
Window / cohort / exclusions:
Authoritative sources and event versions:
Evidence level:
Data owner / metric owner / reviewer:
Sensitive attributes / legal basis:
Privacy threshold / suppression / access:
Baseline / target / guardrail / stop threshold:
Required qualitative evidence and counterexamples:
Known bias / missingness / causal limits:
Gaming risk and audit:
Triggered action / owner / deadline:
Public/internal/restricted classification:
Review/expiry:
```

口径变化形成新版本；历史报告仍能按旧版本复现。

激活、采集与分类使用以下受控值：

- **Activation**：`G2-CORE` 表示首个真实付费批次必须采集；`G2-CONDITIONAL` 表示路径与字段必须在 G2 前可用、事件发生时必采；`P1-MANUAL` 表示以运营/研究记录为主，不授权为此新增自动化；`DEFERRED` 表示首批保持关闭，只有相关 Decision 批准后激活。
- **Mode**：`SYS` 系统事件；`FIN` provider/银行/法定账簿；`OPS` 有权限的运营记录；`RES` 研究/理解测试；`MIX` 必须连接两种以上事实，不能由单一来源冒充。
- **Classification**：`PRIMARY` 直接回答首批假设；`GUARDRAIL` 防止以经营结果交换权利；`STOP` 可单案触发暂停、不能被平均值抵消；`DIAGNOSTIC` 用于解释，不单独决定继续。

所有 `G2-CORE/G2-CONDITIONAL` 指标的事实字段、Owner、隐私和失败语义必须在 G1 设计评审中明确；只有 `Mode=SYS/FIN/MIX` 且确有必要的部分进入软件事件 backlog。`P1-MANUAL/DEFERRED` 不得被用来扩大首版产品范围。

## 3. P0/P1 核心指标目录

### 3.1 自主与边界

| Metric ID | 问题与候选口径 | 权威来源 | 质性/限制 | 触发动作 |
| --- | --- | --- | --- | --- |
| `MTR-AUT-001` | 拒绝后，符合条件的正常邀请机会是否异常变化；比较获批准窗口内拒绝前后邀请率，并控制资格/可用性版本 | Invitation、ProfileVersion、Demand/RuleVersion | 小样本不作因果；结合拒绝者独立访谈与运营覆盖 | 调查派生特征/人工报复；必要时暂停匹配 |
| `MTR-AUT-002` | 边界违规事件率：确认的邀请/项目边界违规事件 ÷ 有机会发生该违规的邀请/项目 | 举报/争议决定、边界版本 | 未举报不等于无伤害；提供保密访谈 | 修规则、通知/补救、降低批次 |
| `MTR-AUT-003` | 被迫例外率：在时间/资金/关系压力下接受的软例外 ÷ 全部例外 | 决定记录、冲突/理由、参与者复盘 | “同意”不证明无压力 | 复核例外权、招募/伙伴关系和停止条件 |
| `MTR-AUT-004` | 自主退出可达：提出暂停/退出者中按约完成善后的比例与时间 | Exit request、项目/付款/数据任务 | 需检查退出是否导致贬低或机会惩罚 | 修复善后与权限级联 |

### 3.2 需求与劳动尊严

| Metric ID | 问题与候选口径 | 权威来源 | 质性/限制 | 触发动作 |
| --- | --- | --- | --- | --- |
| `MTR-DIG-001` | 进入匹配的 Demand 是否全部具有所需角色、范围、验收和资金保障 | DemandVersion、Review、Funding | 通过率高可能表示审核变松，需抽查 | 停止不合格 Demand、复训审核 |
| `MTR-DIG-002` | 无偿实质澄清/试作事件数量与受影响时间 | 决定/争议、时间记录、自报 | 时间估算不等于报酬价值 | 补偿、修改服务边界或拒绝客户 |
| `MTR-DIG-003` | 实质范围变化中重新确认时间和报酬的比例 | AgreementVersion、Change、Milestone | 需抽查“伪小改” | 暂停变更、重新协议/补救 |
| `MTR-DIG-004` | 有效报酬：按批准口径比较约定/实际报酬与实际投入、直接成本和风险 | Agreement、对账、参与者最小自愿记录 | 不公开私密底线；不能跨人总排序 | 复核价格/范围/隐形劳动 |
| `MTR-DIG-005` | 验收理由与标准一致性：拒收/返工是否引用有效标准 | AgreementVersion、AcceptanceDecision | 人工抽查与受益者确认 | 重新验收、补偿、修模板 |

### 3.3 资金与付款

| Metric ID | 问题与候选口径 | 权威来源 | 质性/限制 | 触发动作 |
| --- | --- | --- | --- | --- |
| `MTR-PAY-001` | 开工时资金保障率：所需 Funding 已 `SECURED` 的开工里程碑 ÷ 全部开工里程碑 | Project/Milestone、Funding | 不用预算承诺代替 | 未保障即停工/事件复盘 |
| `MTR-PAY-002` | 按约付款率：到期且无获批准争议的应付款中按约对账 `PAID` 的比例 | Agreement、Payment、Reconciliation | 分开 disputed/unknown/late | 财务升级、暂停新增、补救 |
| `MTR-PAY-003` | 付款延迟：从应付时间到最终对账的分布 | 同上 | 不只报平均值，显示尾部 | provider/运营容量复核 |
| `MTR-PAY-004` | 未知/重复/退款/冲正数量、金额与收敛时间 | provider inbox、账簿、Audit | 金额小也可能暴露系统问题 | 停止相关操作、对账与恢复演练 |
| `MTR-PAY-005` | 费用透明理解：参与者能否复述创作者报酬、平台费、税费、退款 | 理解测试 + 合同版本 | 自报理解需情景验证 | 改文案/流程，未通过不签约 |

### 3.4 机会开放与评审

| Metric ID | 问题与候选口径 | 权威来源 | 质性/限制 | 触发动作 |
| --- | --- | --- | --- | --- |
| `MTR-OPP-001` | 邀请集中度：按实际 Invitation 事件计算获批准窗口/领域的份额与 HHI/Top-share | Invitation + eligibility cohort | 小样本抑制；不能用 Outcome 代邀请 | 复核规则/运营偏好，不自动处罚高机会者 |
| `MTR-OPP-002` | 收入集中度：按对账收入而非均分估算计算 | Payment/Reconciliation | 只在隐私阈值以上公开 | 调查机会/需求结构和新人路径 |
| `MTR-OPP-003` | 首次正常付费机会时间：从符合条件/主动可用到首次已对账项目 | Profile eligibility、Invitation、Payment | 分开无可用性/主动暂停；不把等待归咎个人 | 调整招募/供需/新人项目 |
| `MTR-OPP-004` | 评审来源与冲突：按专业、需求方、受益者等来源分布和回避事件 | Review/Conflict/Decision | 敏感群体数据另过合法性 | 扩充 reviewer、撤销冲突决定 |
| `MTR-OPP-005` | 准入障碍：不合格/退出/申诉的理由分布与叙事 | Review、Appeal、研究 | 理由码不替代访谈；审查规则必要性 | 修改不必要门槛/提供合理便利 |

### 3.5 关系、成果与成长

| Metric ID | 问题与候选口径 | 权威来源 | 质性/限制 | 触发动作 |
| --- | --- | --- | --- | --- |
| `MTR-REL-001` | 双方再次合作意愿，分开记录同意公开与否 | Outcome 自报 | 不冒充实际复购 | 访谈低意愿原因/修改服务 |
| `MTR-REL-002` | 实际再次合作：双方后续自愿建立合格项目 | Project/Agreement | 站外复作只在自愿调查中了解 | 评估平台是否建立关系而非锁定 |
| `MTR-REL-003` | 成果可维护/移交：完成项目中落实维护/移交责任的比例 | Agreement/Outcome/Asset handoff | “上传文件”不等于可维护 | 补交/修改协议与验收 |
| `MTR-REL-004` | 实际成果路径分布：一次交付、持续服务、开放知识、公共/合作/企业或停止 | Demand/Agreement/Outcome | 不按路径统一排名 | 调查默认公司化或停止污名 |
| `MTR-REL-005` | 成长证据：参与者能否描述可验证的新能力/边界/关系 | 研究/Outcome/Contribution evidence | 不生成成长总分 | 改复盘/导师/证据方式 |

### 3.6 权利、安全与退出

| Metric ID | 问题与候选口径 | 权威来源 | 质性/限制 | 触发动作 |
| --- | --- | --- | --- | --- |
| `MTR-RGT-001` | 数据权请求完成率/时长，分访问、更正、限制、删除、导出与例外 | DataRights tasks/provider/backup | 法律 hold 分项；公开按隐私阈值 | 停止新增用途、补资源/修复 |
| `MTR-RGT-002` | 导出可理解/可验证/可接收比例 | Export/verification + user test | 下载成功不等于可携带 | 修格式/说明/接收方 |
| `MTR-SAF-001` | 举报确认、临时保护、决定、申诉和补救的时长分布 | Case/Decision/Audit | 数量上升可能是可报告性改善 | 结合严重度/质性解释，超时暂停 |
| `MTR-SAF-002` | 独立复核率与冲突回避：申诉是否由合格无冲突 reviewer 处理 | Authority/Conflict/Appeal | 100% 形式合规仍需质量抽查 | 相关决定不生效/引入外部复核 |
| `MTR-SAF-003` | 限制 blast radius：措施影响的无关项目/报酬/数据权/支持数量 | SafetyHold、权限/付款/权利状态 | 零无关影响是目标，需恢复演练 | 解除无关限制、补救、修状态模型 |
| `MTR-SAF-004` | 报复信号：举报/申诉后机会、权限、评价、支持变化与自报压力 | 决定/邀请/伙伴/研究 | 不作自动因果判断 | 独立调查、保护/补救/暂停涉事者权限 |

### 3.7 运营、伙伴与资源独立

| Metric ID | 问题与候选口径 | 权威来源 | 质性/限制 | 触发动作 |
| --- | --- | --- | --- | --- |
| `MTR-OPS-001` | 关键队列积压、超时、返工和每案工时 | Ops queue/decision/audit | 不能用压缩权利流程降时长 | 降低 WIP、补人/暂停招募 |
| `MTR-OPS-002` | 人工覆盖率及理由、复核和结果 | Decision/RuleVersion | 覆盖高/低本身不等于好坏 | 检查规则不适配或隐藏任意权 |
| `MTR-NOD-001` | 伙伴覆盖决定率：伙伴对候选、验收、资格、资金决定的比例与授权 | PartnerAgreement/Decision | 需解释合法角色，不自动判恶 | 复核授权/冲突/资源买权 |
| `MTR-NOD-002` | 受益者参与需求/成果确认的比例 | Demand role/Outcome | 代表授权质量需质性检查 | 修代表/确认/替代流程 |
| `MTR-NOD-003` | 单节点依赖与停摆替代：关键收入/机会/材料/凭证/支持可替代比例 | 受控调查、系统可达性、演练 | 不收集完整生活图谱 | 建替代/承接，停止扩大依赖 |
| `MTR-RES-001` | 单一客户/资本/资助/provider 的收入、现金或关键能力集中度 | 财务/合同/provider registry | 敏感数据分层公开 | 触发额外批准、储备/替代/拒绝条件 |

### 3.8 公共劳动与制度证据

P1 不激活正式公共金库，但必须看见真实发生的公共劳动：

| Metric ID | 问题与候选口径 | 权威来源 | 质性/限制 | 触发动作 |
| --- | --- | --- | --- | --- |
| `MTR-COM-001` | 指导、评审、调解、知识、制度维护的类型、时间、责任和补偿 | Work record/Payment | 与项目运营成本分开；不按工时总分 | 识别稳定公共职责/补偿需求 |
| `MTR-COM-002` | 公共知识/工具复用与维护责任 | Artifact/license/use/maintenance | 点击不等于公共价值 | 改许可/维护/停止无效产出 |
| `MTR-COM-003` | 制度问题、反对意见和修复是否得到回应 | Proposal/issue/decision | P1 非正式治理不冒充成员权力 | 公开回应/分配 owner/未来 P3 输入 |

### 3.9 商业可行性事实

| Metric ID | 问题与候选口径 | 权威来源 | 质性/限制 | 触发动作 |
| --- | --- | --- | --- | --- |
| `MTR-BIZ-001` | 有成本需求进展：Qualified Demand 分别达到 `E2`、`E3-CONTRACT`、`E3-FUNDED`、`E3-PAID`、`E3-COMPLETED` 的数量与转化；subtype 不互相替代 | Evidence registry、合同、获批 `MF-*`、provider/账簿、项目结果 | 不把团队补贴、口头支持、预算描述或合同冒充付款/完成 | 修改 ICP/服务/价格；长期无 E2 则不扩大开发 |
| `MTR-BIZ-002` | 每项目直接贡献与现金覆盖：认可的平台收入减逐案运营、支持、安全、支付、获客、退款/风险成本；同时检查现有义务和补救储备覆盖 | 法定/管理账簿、Money Flow、工时和预算 | GMV、pass-through、受限资金和创作者报酬不得冒充平台收入 | 缩小批次、改价格/范围；无法覆盖现有义务立即停新承诺 |

### 3.10 指标激活登记

本表是 P0/P1 指标是否进入首批的唯一激活清单。任何 Metric ID 未在表中出现均视为 `DEFERRED`；变更 Activation/Mode/Classification 必须更新 `DEC-032` 和批次预注册。

| Metric ID | Activation | Mode | Classification |
| --- | --- | --- | --- |
| `MTR-AUT-001` | `G2-CORE` | `MIX` | `GUARDRAIL/STOP` |
| `MTR-AUT-002` | `G2-CORE` | `MIX` | `GUARDRAIL/STOP` |
| `MTR-AUT-003` | `P1-MANUAL` | `MIX` | `DIAGNOSTIC/GUARDRAIL` |
| `MTR-AUT-004` | `G2-CONDITIONAL` | `MIX` | `GUARDRAIL` |
| `MTR-DIG-001` | `G2-CORE` | `MIX` | `GUARDRAIL/STOP` |
| `MTR-DIG-002` | `G2-CORE` | `MIX` | `PRIMARY/GUARDRAIL` |
| `MTR-DIG-003` | `G2-CONDITIONAL` | `MIX` | `GUARDRAIL/STOP` |
| `MTR-DIG-004` | `P1-MANUAL` | `MIX` | `PRIMARY` |
| `MTR-DIG-005` | `G2-CONDITIONAL` | `OPS` | `GUARDRAIL` |
| `MTR-PAY-001` | `G2-CORE` | `MIX` | `GUARDRAIL/STOP` |
| `MTR-PAY-002` | `G2-CORE` | `FIN` | `PRIMARY/STOP` |
| `MTR-PAY-003` | `G2-CORE` | `FIN` | `DIAGNOSTIC` |
| `MTR-PAY-004` | `G2-CORE` | `MIX` | `GUARDRAIL/STOP` |
| `MTR-PAY-005` | `G2-CORE` | `MIX` | `GUARDRAIL` |
| `MTR-OPP-001` | `G2-CORE` | `SYS` | `GUARDRAIL/DIAGNOSTIC` |
| `MTR-OPP-002` | `P1-MANUAL` | `FIN` | `DIAGNOSTIC` |
| `MTR-OPP-003` | `P1-MANUAL` | `MIX` | `DIAGNOSTIC` |
| `MTR-OPP-004` | `G2-CONDITIONAL` | `MIX` | `GUARDRAIL` |
| `MTR-OPP-005` | `P1-MANUAL` | `MIX` | `DIAGNOSTIC/GUARDRAIL` |
| `MTR-REL-001` | `G2-CORE` | `RES` | `PRIMARY` |
| `MTR-REL-002` | `DEFERRED` | `MIX` | `DIAGNOSTIC` |
| `MTR-REL-003` | `G2-CONDITIONAL` | `MIX` | `GUARDRAIL` |
| `MTR-REL-004` | `G2-CORE` | `MIX` | `PRIMARY/GUARDRAIL` |
| `MTR-REL-005` | `P1-MANUAL` | `RES` | `DIAGNOSTIC` |
| `MTR-RGT-001` | `G2-CONDITIONAL` | `MIX` | `GUARDRAIL/STOP` |
| `MTR-RGT-002` | `G2-CONDITIONAL` | `MIX` | `GUARDRAIL` |
| `MTR-SAF-001` | `G2-CONDITIONAL` | `OPS` | `GUARDRAIL/STOP` |
| `MTR-SAF-002` | `G2-CONDITIONAL` | `OPS` | `GUARDRAIL/STOP` |
| `MTR-SAF-003` | `G2-CONDITIONAL` | `MIX` | `GUARDRAIL/STOP` |
| `MTR-SAF-004` | `G2-CORE` | `MIX` | `GUARDRAIL/STOP` |
| `MTR-OPS-001` | `G2-CORE` | `OPS` | `PRIMARY/STOP` |
| `MTR-OPS-002` | `G2-CORE` | `OPS` | `GUARDRAIL/DIAGNOSTIC` |
| `MTR-NOD-001` | `DEFERRED` | `MIX` | `GUARDRAIL` |
| `MTR-NOD-002` | `G2-CORE` | `MIX` | `GUARDRAIL` |
| `MTR-NOD-003` | `DEFERRED` | `MIX` | `GUARDRAIL/STOP` |
| `MTR-RES-001` | `G2-CORE` | `FIN` | `GUARDRAIL/STOP` |
| `MTR-COM-001` | `G2-CORE` | `MIX` | `DIAGNOSTIC` |
| `MTR-COM-002` | `DEFERRED` | `MIX` | `DIAGNOSTIC` |
| `MTR-COM-003` | `P1-MANUAL` | `OPS` | `DIAGNOSTIC/GUARDRAIL` |
| `MTR-BIZ-001` | `G2-CORE` | `MIX` | `PRIMARY` |
| `MTR-BIZ-002` | `G2-CORE` | `MIX` | `PRIMARY/STOP` |

第三方资源在 `DEC-016` 批准前保持禁止，因此 `MTR-NOD-001/003` 为 `DEFERRED`；若批准伙伴/资源试点，两者自动重开为 `G2-CONDITIONAL`，并须重过隐私、角色授权和指标预注册。

## 4. 商业指标的使命约束

以下经营指标可以使用，但不得单独驱动产品：

| 经营指标 | 必须并列的使命/风险指标 |
| --- | --- |
| Qualified Demand / conversion | 需求合格、无偿劳动、拒绝压力、审核工时 |
| GMV / service revenue | 创作者报酬、费用透明、付款时效、退款/争议 |
| Repeat / retention | 自愿性、退出摩擦、关系质量、平台依赖 |
| Supply growth | 合格真实机会、首次付费时间、等待与退出 |
| Match/selection speed | 边界违规、接受理解、人工覆盖、集中度 |
| Gross margin | 权利/安全/公共劳动是否被当免费成本 |
| Partner-sourced volume | 强迫、候选控制、数据权、集中度和停摆替代 |

GMV 上升而报酬、付款、拒绝空间、权利时限或受益者结果恶化时，按 `FND-MIS-002` 触发复核和暂停，不称为成功。

## 5. 定量隐私与公平边界

- 任何敏感群体维度先确定目的、必要性、合法基础、访问、保留和参与者风险；
- 不为了“公平仪表盘”建立永久敏感画像或完整站外身份图；
- 小样本阈值、抑制/合并、差分披露和内部访问在 `G2` 前由 Privacy 批准；
- 公开指标不允许通过交叉表、时间、角色或极端值重识别个人/组织；
- 群体差异只触发调查，不自动归因或处罚个体；
- 未知/缺失/拒绝披露作为事实保留，不强行推断；
- 质性研究保护原话、第三方和关系性强迫风险；
- 任何公平模型或阈值变化形成新规则版本并可复核。

## 6. 每批预注册

批次开始前固定：

```text
Batch ID / scope / dates / cap:
Primary hypotheses:
Primary metrics and versions:
Baseline and evidence limitations:
Guardrail/stop metrics:
Population/denominator/exclusions:
Data sources and readiness:
Privacy threshold/access/publication:
Qualitative sampling and questions:
Expected adverse/contrary evidence:
Decision rules: continue / modify / shrink / stop
Owners / reviewers / approvers:
```

批次结束后不能为了得到有利结果改变分母、时间窗口或主要指标；探索性分析单独标记。

### 6.1 G2 最小指标包

`DEC-032` 批准前，以下为不可删减的安全默认；批准只能增加指标或在不降低权利保护的前提下说明某项为何不适用，不能用“样本小”删除事实采集：

- **Primary**：`MTR-BIZ-001`, `MTR-BIZ-002`, `MTR-DIG-002`, `MTR-PAY-002`, `MTR-REL-001`, `MTR-REL-004`, `MTR-OPS-001`；
- **Guardrail/Stop**：`MTR-AUT-001`, `MTR-AUT-002`, `MTR-DIG-001`, `MTR-PAY-001`, `MTR-PAY-004`, `MTR-PAY-005`, `MTR-OPP-001`, `MTR-SAF-004`, `MTR-OPS-002`, `MTR-NOD-002`, `MTR-RES-001`；
- **成本与公共劳动解释**：`MTR-COM-001`；
- **事件条件包**：发生范围变更、验收争议、退出/数据权请求、安全/申诉、维护移交时，分别强制启用对应 `G2-CONDITIONAL` 指标；即使事件为零，也要保存“零事件/无请求”和可运行路径的演练证据，不能以没有数据省略入口。

这一最小包只规定必须能够回答的问题，不要求每项都建设 dashboard。`P1-MANUAL` 和低样本计算可以由受控运营/研究记录完成；自动化必须另有减少错误或风险的证据。

## 7. 阈值与触发

具体数字必须在 `G2` 前填入并说明依据。即使尚无基线，也必须设安全阈值：

- 任一跨主体未授权访问、私密报酬泄漏、付款双付/无法收敛、应付报酬无保障、报复或独立申诉不可达：触发相关流程立即暂停；
- 关键权利/付款/安全队列超过批准时限或容量：停止新增相关项目；
- 范围变化未重新确认报酬、未保障资金开工、未接受候选被选择：逐案补救并暂停相似路径；
- 现金、补救储备或人员不足以完成现有义务：停止新增承诺；
- 伙伴强迫或站外待遇受影响：停止该伙伴渠道并提供独立救济；
- 使命指标持续恶化但经营增长：跨职能复核，明确继续/缩小/回滚/停止。

其他目标阈值可以随学习修订，但修订必须版本化，不能追溯美化旧批次。

## 8. 学习评审

每批至少回答：

1. 哪个假设被支持、证伪或仍不足；
2. 哪些结果来自权威事实，哪些来自自报/解释；
3. 谁受益、谁承担了未预期负担；
4. 哪些拒绝、退出、失败、事件和反例改变了判断；
5. 指标是否被流程、样本、缺失或运营行为游戏化；
6. 是否存在未报告/无法表达的伤害；
7. 哪项人工工作稳定到可以工具化，哪项仍需人负责；
8. 商业改善是否伴随使命恶化；
9. 哪个控制、规则、服务或范围要改变；
10. 结论是继续、缩小、修改、回滚、保持影子还是停止。

参与者叙事和少数反例应与图表同时进入评审。一个 Critical 伤害不能因平均指标好看而被抵消。

## 9. 公开与独立复核

内部、成员（形成后）和公开层使用不同粒度，但不能用隐私作为隐藏系统性失败的借口。阶段摘要至少说明：范围、样本、口径版本、支持与不利结果、事件类别、人工覆盖、未知事实、采取的修正和下一步。

外部或独立 reviewer 应能在不访问无必要敏感正文的情况下验证：来源事件、分母、版本、抑制、计算、决定触发和纠正记录。资助者、客户或伙伴不得以合同要求删除不利发现。

## 10. 提交给 `G1/G2` 的衡量证据包

本节只向[统一启动决策入口](/foundations/readiness-and-start-decision.md)提交指标与学习证据，不单独宣布或降低总 Gate。

### `G1` 证据输入

- P1 指标 owner、事实源、事件需求和口径草案明确；
- 激活登记和 `DEC-032` 最小包形成批准候选；只有 `G2-CORE/G2-CONDITIONAL` 的必要系统/财务事实进入事件 backlog；
- 已知错误 HHI/付款/覆盖推断有迁移与修复计划；
- 研究证据等级、Observation/Interpretation/Decision 分离可运行；
- 每个产品假设至少有一个反证和停止信号；
- 不需要敏感群体数据才能实现首个安全纵切。

### `G2` 证据输入

- `DEC-032`、主要/护栏/停止指标和事件条件包预注册，阈值、隐私、访问与手工/系统采集模式获批准；
- Invitation、Agreement、Payment、Rights、Safety 等权威事件可验证；
- dashboard/report 无小样本或私密数据泄漏；
- 指标异常能触发具名人和现实动作；
- 质性研究、反例、退出和事件会与经营结果共同复盘；
- 对外声明模板经过 Evidence/Privacy/Legal 审查。

衡量系统的成功不是让愿作拥有更多数字，而是让团队无法在增长顺利时看不见谁正在付出代价。
