# 目标平台领域模型与状态协议

> 状态：目标平台规范设计。本文定义平台写模型、规范术语、状态转换和跨模块一致性边界。目标平台实现、API、数据库迁移和测试必须以本文为准；当前礼宾式 MVP 的历史模型仍以[领域模型与状态](/architecture/domain-model.md)为准。

## 1. 设计目标与适用范围

平台必须把需求成熟、匹配、项目执行和外部资金事实建模为不同生命周期。尤其禁止：

- 用一个 Demand 状态同时表达协议、交付、验收、付款和争议；
- 让客户端直接写 status；
- 把本地验收与外部支付结算当成一次原子操作；
- 用可编辑的“匹配表”覆盖历史输入、规则或决定；
- 通过通知、搜索索引或分析投影反向修改交易事实。

本文描述完整目标模型，也标明首个垂直切片暂缓实现的能力。模块化单体可以在一个 PostgreSQL 集群中用单事务保护少量跨聚合不变量，但模块只能通过应用服务调用对方的公开命令，不能直接更新其他模块的表。

## 2. 规范术语

### 2.1 核心名词

| 术语 | 规范含义 | 不是 |
| --- | --- | --- |
| Demand | 需求方提交并经过验证、注资和匹配的需求聚合 | 项目、合同或付款 |
| DemandVersion | Demand 内容的一份不可变版本 | 可原地修改的 JSON |
| Opportunity | 从已验证或已注资 Demand 生成的接收者相关读取投影 | 独立写模型 |
| MatchingAttempt | Demand 的一次匹配尝试，拥有递增 attempt_no，并关联本次运行、邀请和 Selection | 可覆盖的“当前匹配” |
| MatchRun | 对一个 DemandVersion、候选档案版本集合和复合规则版本的一次不可变匹配运行 | 最终选人决定 |
| MatchCandidate | MatchRun 内某位候选人的资格、分项证据和解释投影 | 当前创作者档案 |
| Invitation | 平台基于某个 MatchCandidate 向创作者发出的有期限邀请 | 账户注册邀请 |
| Selection | 需求方在已接受邀请者中作出的唯一选择，或明确无选择关闭 | 算法推荐 |
| Project | Selection 成功后创建的协作聚合，只管理项目级生命周期 | Demand 的后半段状态 |
| Agreement | 每个 Project 唯一的协议聚合根，拥有 aggregate_version、版本序列和当前生效版本指针 | 某一版协议正文 |
| AgreementVersion | 协议内容的一份不可变版本及各受影响方的确认事实 | 可覆盖的“当前合同” |
| Milestone | 引用具体 AgreementVersion 的交付、验收与资金边界 | 任意任务清单项 |
| Delivery | 针对一个 Milestone 提交的一次不可变交付版本 | 验收决定 |
| Acceptance | 对一个 Delivery 作出的接受、具体修改或争议决定 | 支付结算 |
| ChangeOrder | 对范围、金额、时间或验收规则的正式变更提案 | 聊天中的口头决定 |
| Funding | 某个 DemandVersion 或 Milestone 获得资金保障的内部聚合，target 类型不可变 | 平台自行持有的客户资金 |
| Payment | 对持牌供应商对象和事件的可审计镜像 | 平台账本对供应商事实的替代 |
| Dispute | 围绕协议、交付、付款或行为提出的独立案件 | Project.status 的同义词 |
| Appeal | 围绕程序错误、新证据或规则误用提出的一次独立复核 | 第二次原案重审 |
| Review | 项目结束后的双盲、双向体验与事实反馈 | 私密安全举报或单一五星总分 |
| Outcome | 从 Project、Milestone、Payment、Dispute 和 Review 生成的分析投影 | 人工一次录入的目标平台事实 |

### 2.2 旧名称迁移

| 旧名称 | 目标平台处理 |
| --- | --- |
| Recommendation | 迁移为 MatchRun 及其 MatchCandidate；只保留为兼容导入名称 |
| Match | 不作为含混写模型；使用 MatchRun、Invitation 或 Selection |
| Decision | 不作为独立万能实体；按语义使用 Selection、Acceptance、Ruling 或 Review |
| Deliverable | 规范写模型使用 Delivery；deliverable 只表示协议中的交付物描述 |
| ScopeChange | 规范写模型使用 ChangeOrder |
| Outcome | 只读分析投影，不接受目标平台业务写入 |
| Pilot | 仅用于受控批次和实验规则冻结；不是正常交易必须依赖的聚合 |

### 2.3 角色

| 角色 | 主要职责 |
| --- | --- |
| DEMAND_OWNER | 创建需求、确认协议、选择创作者、验收交付 |
| ORG_ADMIN | 管理组织成员和业务授权，但不能绕过项目关系读取私密字段 |
| CREATOR | 维护自己的档案、响应邀请、确认协议、提交交付 |
| PROJECT_MEMBER | 经协议确认加入项目的协作者，只访问被授权的项目范围 |
| OPERATIONS_REVIEWER | 审核需求、资料和披露；不得审核自己或存在利益冲突的对象 |
| FINANCE_OPERATOR | 处理人工资金核实、退款和对账例外 |
| TRUST_OFFICER | 处理安全举报、临时限制和案件分流 |
| MEDIATOR | 调解争议，不单独作最终裁决 |
| RULING_PANEL | 无利益冲突的裁决小组 |
| APPEAL_REVIEWER | 未参与原裁决的申诉复核者 |
| SYSTEM | 经过认证的 worker、定时任务或 webhook inbox 处理器 |

平台管理员不是业务授权捷径。任何 break-glass 访问必须有工单、理由、时限、独立审计和事后复核。

## 3. 全局状态协议

### 3.1 写入与事件

- 每个聚合具有不可推测 ID、整数 aggregate_version、created_at 和 updated_at；时间统一为 UTC。
- 所有外部写命令必须携带 Idempotency-Key 和期望版本。HTTP 映射优先使用 If-Match；旧版本返回 412，不自动覆盖。
- 幂等收据按 actor、command、target、key 和 payload_hash 唯一保存。同一 key 与相同 payload 重放原响应；同一 key 与不同 payload 返回 409。收据至少保留到目标聚合依法删除或匿名化。
- 一个本地业务命令在同一事务中写聚合、审计事件和 outbox。消费者按 event_id 去重，至少一次投递不得产生重复业务动作。
- 外部供应商事件先进入 durable inbox。验签、时间窗和 provider/event_id 去重成功后，才可转换为领域命令。
- 状态字段只由领域命令转换。读取 DTO、搜索索引、通知和分析投影都不是事实来源。
- 金额使用 ISO 4217 币种和最小货币单位整数；不能用浮点数表达交易金额。
- 规则、需求、档案、协议、交付和裁决内容使用不可变版本；纠正通过新版本或纠正事件完成。

### 3.2 并发与幂等代码

后续状态表使用以下代码，代码是每一行转换契约的一部分。

| 代码 | 规则 |
| --- | --- |
| C1 | 聚合行以 expected_version 比较并交换；命令收据保证相同请求只执行一次 |
| C2 | C1，加同一 owning context 内的数据库唯一约束和单事务；跨 Context 时仅可用于 7.1 明列的原子事务 |
| C3 | worker 以带租约的任务领取执行；完成时再次检查聚合版本，输出事件按 event_id 去重 |
| C4 | 外部事件按 provider/event_id durable inbox 去重；锁定聚合后应用，未知或乱序事件进入对账队列 |
| C5 | 定时命令按 aggregate/deadline/action 唯一；执行时重新检查截止时间、状态和 hold |
| C6 | 多方确认按 aggregate/party 唯一；最后一方确认时锁定聚合并原子转换 |
| C7 | 记录只追加且内容哈希固定；修正只能追加新版本、撤销或纠正事件 |
| C8 | process manager 按 source_event_id 去重，并检查目标状态；跨事务重试不得重复推进 |

### 3.3 通用守卫

除状态表中的专属守卫外，每个命令还必须满足：

1. actor 具有角色、资源关系和字段权限；
2. 资源没有阻止该动作的安全、法律或付款 hold；
3. actor 的同意、身份或组织授权仍有效；
4. 所引用版本存在且未被替代；
5. 请求没有泄露或试图覆盖接收者不可见字段；
6. 高风险运营动作有标准原因，必要时满足职责分离；
7. 不允许通过重放事件、通知失败或客户端时钟绕过期限。

## 4. Context map

| Context | 拥有的写模型 | 接收的事实 | 发出的事实 | 禁止 |
| --- | --- | --- | --- | --- |
| Identity & Access | User、Organization、Membership、Consent、IdentityVerification | 身份供应商结果 | 身份已验证、角色变化、同意撤回 | 修改匹配、项目或资金状态 |
| Creator Profile | CreatorProfile、ProfileVersion、CapabilityEvidence、Availability | 用户关系、证据验证结果 | 档案已确认、档案已过期、容量变化 | 邀请或选人 |
| Demand | Demand、DemandVersion、DemandReview | 身份/组织授权、Funding 已保障 | Demand 已验证、可匹配、取消 | 修改 Payment 或 Project |
| Matching & Policy | RuleBundle、MatchRun、MatchCandidate、Invitation、Selection | Demand 可匹配、档案版本、hold | 匹配完成、邀请响应、选择完成 | 自动替参与者选择 |
| Project & Agreement | Project、AgreementVersion、Milestone、Delivery、Acceptance、ChangeOrder | Selection 完成、Funding 状态、争议结果 | 协议接受、交付提交、验收、项目完成 | 伪造供应商资金事实 |
| Payments | Funding、Payment、Refund、Payout、ReconciliationException | 协议金额、验收、争议结果、供应商 webhook | 资金保障、结算、退款、对账异常 | 保存支付密钥或自行托管资金 |
| Trust & Review | SafetyHold、Report、Dispute、Ruling、Appeal、Review | 项目证据、付款事件、举报 | hold、裁决、申诉结果、可展示评价 | 让 AI 独立处罚或裁决 |
| Notification | Template、Preference、DeliveryAttempt | 领域 outbox 事件 | 投递成功/失败 | 作为业务状态事实源 |
| Audit & Analytics | AuditEvent、脱敏事件、读模型 | 全部允许的领域事件 | 指标和合规导出 | 反向修改交易聚合 |
| Community & Governance | Group、Contribution、RuleProposal | 可信成员和项目复盘 | 规则提案、贡献事实 | 直接修改生效交易规则 |
| Controlled AI Gateway | PromptVersion、ModelPolicy、AIJob | 经授权且最小化的输入 | 建议草稿、结构提取结果 | 独立改变资格、付款、处罚或裁决 |

Community & Governance 与 Controlled AI Gateway 属于后续阶段；它们仍需保留明确边界，避免以后把社区内容或模型调用塞进交易聚合。

## 5. 聚合职责

| 聚合根 | 拥有的内容 | 核心不变量 |
| --- | --- | --- |
| Demand | 当前 DemandVersion 引用、成熟状态、审核和取消原因 | 只管理进入匹配前后的需求状态；匹配成功后不继续承载项目执行 |
| MatchingAttempt | attempt_no、DemandVersion、运行集合、邀请集合和本次 Selection | 一个 Demand 同时最多一个开放 attempt；终态 attempt 不重开或覆盖 |
| MatchRun | 输入版本集合、复合规则版本、资格、分项、解释证据 | 完成后不可修改；同一输入和规则必须可复算 |
| Invitation | MatchingAttempt、来源 MatchCandidate、接收者、披露投影版本、期限和响应 | 只能来自合格候选；每个 attempt/creator 最多一个开放邀请 |
| Selection | 可选邀请集合和唯一选择 | 选择者必须已受邀且已接受；成功选择最多创建一个 Project |
| Project | 参与方、主状态、hold 和当前协议引用 | 只在 Selection 成功后创建；完成不等同于单次验收 |
| Agreement | Project 唯一引用、AgreementVersion 序列、当前生效版本和 aggregate_version | 所有版本命令在 Agreement 根上并发控制；内容只追加 |
| Milestone | 协议版本引用、交付/验收指针和执行状态 | 金额、交付物与验收标准来自同一生效协议版本 |
| Delivery | 文件/链接引用、内容清单、扫描结果和版本链 | 提交后内容不可修改；修改要求产生新 Delivery |
| Acceptance | 对具体 Delivery 的决定、理由和期限 | 接受不直接写成 Payment settled |
| ChangeOrder | 变更内容、受影响方确认和应用结果 | 金额/范围变化必须生成新 AgreementVersion |
| Funding | 不可变 FundingTarget、供应商引用、替换链、内部投影和对账状态 | target 恰为 DemandVersion 或 Milestone；settled 不被静默回退 |
| Dispute | 争议范围、证据引用、调解、裁决和执行 | 裁决者无利益冲突；争议只冻结相关资源 |
| Appeal | 原裁决引用、允许理由、新证据和结果 | 每个可申诉裁决默认最多一次独立申诉 |
| Review | 作者、接收方、可展示字段和揭示状态 | 双盲；私密安全反馈进入 Report 而非公开 Review |

CreatorProfile、Demand、MatchRun、AgreementVersion 和 Delivery 都保存来源、确认时间和内容哈希。影响过交易的旧版本不得因当前资料更新而改变。

## 6. 关键实体关系

| 关系 | 基数 | 约束 |
| --- | --- | --- |
| User — Organization | 多对多，经 Membership | 组织角色不能自动授予项目字段访问 |
| User — CreatorProfile | 一对零或一 | 团队协作者仍各自具有可审计身份 |
| Demand — DemandVersion | 一对多 | 只有一个 current_version_id；已提交版本不可原地改 |
| Demand — MatchingAttempt | 一对多 | attempt_no 在 Demand 内唯一递增；同时最多一个非终态 attempt |
| MatchingAttempt — MatchRun | 一对多 | 失败重试或规则重算创建新 MatchRun，不覆盖旧运行 |
| MatchRun — MatchCandidate | 一对多 | 包含全部参与计算者及硬过滤结果，不只保存前几名 |
| MatchingAttempt — Invitation | 一对多 | Invitation 保留 source_match_run_id；开放记录按 matching_attempt_id/creator_id 唯一 |
| MatchingAttempt — Selection | 一对零或一 | 有可邀请候选时才创建 Selection；零候选 attempt 可直接关闭；终态 Selection 不重开 |
| Selection — Project | 一对零或一 | selection_id 唯一，防止重试创建多个项目 |
| Project — Agreement | 一对一 | Project 创建时初始化唯一 Agreement 根，project_id 使用唯一约束 |
| Agreement — AgreementVersion | 一对多 | 同时最多一个生效版本；version_no 在 Agreement 内唯一递增 |
| AgreementVersion — Milestone | 一对多 | Milestone 始终引用定义它的具体版本 |
| Milestone — Delivery | 一对多 | 新提交会使前一 Delivery 被替代，但不删除 |
| Delivery — Acceptance | 一对一 | 决定只作用于该 Delivery |
| Project — ChangeOrder | 一对多 | 接受后产生新 AgreementVersion，不直接改旧里程碑 |
| ChangeOrder — resulting AgreementVersion | 一对零或一 | source_change_order_id 与 resulting_agreement_version_id 双向唯一；APPLIED 后必须恰有一个结果版本 |
| DemandVersion — Funding | 一对多，target_type 为 DEMAND_VERSION | 匹配前资金承诺不引用尚不存在的 AgreementVersion，且不能直接释放给创作者 |
| Milestone — Funding | 一对一或按协议分期一对多，target_type 为 MILESTONE | 必须同时引用定义它的 AgreementVersion；总金额、币种与协议一致 |
| Funding — retry replacement Funding | 一对零或多 | replaces_funding_id 只连接相同 target 的失败/取消重试，原记录保持终态 |
| Demand Funding — FundingAllocation — Milestone Funding | 一对多 | 跨 target 复用必须有独立 allocation、供应商确认和新 Funding，不能伪装成 retry |
| Funding — Payment | 一对多 | authorization、release、refund、payout 分别记录 |
| Project/Milestone — Dispute | 一对多 | 同时只能有政策允许的开放案件；hold 范围显式 |
| Dispute — Appeal | 一对零或一 | 独立复核人不得参与原裁决 |
| Project — Review | 每个参与方到对方至多一条 | 双方提交或期限结束后才揭示 |

## 7. 跨 Context 一致性

### 7.1 允许的本地原子事务

模块化单体首版把 C2 限定在一个 owning context。唯一获准的跨 Context 领域事务是 CompleteSelection：

1. 外部 actor DEMAND_OWNER 提交 ChooseCreator，并生成绑定 actor、payload 和 Idempotency-Key 的命令收据；
2. 内部 SYSTEM 协调器 CompleteSelection 携带 original_actor_id，按固定顺序锁定 Selection、MatchingAttempt 和 Demand；
3. 验证 Demand 仍为 MATCHING、attempt 仍 OPEN，且目标 Invitation 属于该 attempt 并为 ACCEPTED；
4. Matching & Policy context 将 Selection 和 MatchingAttempt 标记 SELECTED，只发出 SelectionMade、MatchingAttemptSelected；
5. Project & Agreement context 以 selection_id 和 project_id 唯一约束创建 PENDING_AGREEMENT Project 及其唯一 Agreement 根，只发出 ProjectCreated、AgreementCreated；
6. Demand context 将 Demand 标记 MATCHED，只发出 DemandMatched；
7. 同事务追加审计和 outbox；各聚合事件有独立 event_id，共享 correlation_id、causation_id 和 original_actor_id。

AgreementVersion 最后一方确认与旧版本 SUPERSEDED、Delivery/Acceptance/Milestone 联动等都在 Project & Agreement context 内，可使用 C2/C6。Funding、Demand、Matching、Trust 与 Project 之间的其他推进一律使用 C8 process manager。AuditEvent 和 outbox 是每个命令的事务基础设施，不构成可任意扩张的跨 Context 业务写权限。

CompleteSelection 由一个明确的应用服务调用各模块公开仓库接口；除此之外不得用跨 schema SQL 绕过聚合守卫。若未来拆分数据库，CompleteSelection 必须改为有 reservation 与补偿的 saga，并保持 selection_id 唯一。

### 7.2 必须异步协调的流程

- DemandFundingRequested 创建 target 为 DemandVersion 的 Funding；
- FundingSecured 推进对应 Demand 或 Milestone；
- FundingFailed 先由资金重试策略创建 replacement；重试耗尽后把 Demand 恢复 VERIFIED 或把 Milestone 恢复 DRAFT；
- MatchingRequested 创建新的 MatchingAttempt 和首个 MatchRun；
- MatchingAttemptClosedWithoutSelection 把 Demand 推进 NO_MATCH；
- AgreementAccepted 与首个 FundingSecured 共同推进 Project READY_TO_START；
- DeliveryAccepted 只触发 FundingReleaseRequested，不声明已经结算；
- PaymentSettled 更新资金投影；所有里程碑均验收且资金终态满足后，才能推进 Project；
- DisputeOpened 创建最小范围 hold；DisputeResolved 再由 process manager 恢复或结束相关聚合；
- 通知、搜索、分析和外部 webhook 始终由 outbox 驱动。

外部支付、身份和文件扫描不存在跨系统原子事务。任何超时都进入明确的 pending、failed 或 reconciliation 状态，不猜测成功。

## 8. Demand 状态

状态：DRAFT、SUBMITTED、NEEDS_CHANGES、VERIFIED、FUNDING_PENDING、FUNDED、MATCHING、MATCHED、NO_MATCH、CANCELLED、EXPIRED。

| 转换 | 命令 | 角色 | 专属守卫 | 事件 | 并发/幂等 |
| --- | --- | --- | --- | --- | --- |
| 无 → DRAFT | CreateDemand | DEMAND_OWNER | 有效身份、同意和组织业务授权 | DemandCreated | C2，client_reference 唯一 |
| DRAFT/NEEDS_CHANGES → 原状态 | CreateDemandVersion | DEMAND_OWNER | 资源仍可编辑；新内容通过结构校验 | DemandVersionCreated | C1 + C7 |
| DRAFT/NEEDS_CHANGES → SUBMITTED | SubmitDemand | DEMAND_OWNER | 当前版本完整；预算、验收人、数据计划和决策权已声明 | DemandSubmitted | C1 |
| SUBMITTED → NEEDS_CHANGES | RequestDemandChanges | OPERATIONS_REVIEWER | 标准原因和待补字段非空；审核人无利益冲突 | DemandChangesRequested | C1 |
| SUBMITTED → VERIFIED | VerifyDemand | OPERATIONS_REVIEWER | 身份、付款主体、决策权、预算健康和风险检查通过 | DemandVerified | C2，审核分配唯一 |
| VERIFIED → FUNDING_PENDING | RequestInitialFunding | FINANCE_OPERATOR/SYSTEM | 有精确金额、币种、用途和失效时间；target 固定为当前 DemandVersion | DemandFundingRequested | C1；Payments 侧创建为 C8 |
| VERIFIED/FUNDING_PENDING → FUNDED | ConfirmDemandFunding | SYSTEM/FINANCE_OPERATOR | target 为当前 DemandVersion 的 Funding 已 SECURED；人工模式满足双人核实 | DemandFunded | C8；人工核实另用 C6 |
| FUNDING_PENDING → VERIFIED | ResetDemandFundingAfterFailure | SYSTEM | 对应 Funding 已 FAILED/CANCELLED 且重试策略确认没有 active replacement | DemandFundingReset | C8 |
| FUNDED/NO_MATCH → MATCHING | RequestMatching | OPERATIONS_REVIEWER/SYSTEM | 当前 DemandVersion 的 Funding 仍 SECURED；无开放 MatchingAttempt；规则包冻结；无 hold | MatchingRequested | C1；Matching 侧创建为 C8 |
| MATCHING → MATCHED | ApplySelectionCompleted | SYSTEM | CompleteSelection 已验证当前 attempt 和 ACCEPTED Invitation，并将在同事务创建唯一 Project | DemandMatched | 7.1 唯一跨 Context C2 |
| MATCHING → NO_MATCH | ApplyMatchingAttemptClosed | SYSTEM | 当前 MatchingAttempt 为 CLOSED_NO_SELECTION、INVALIDATED 或 CANCELLED | DemandMatchingClosedWithoutSelection | C8 |
| NO_MATCH → NEEDS_CHANGES | ReopenDemandForRevision | DEMAND_OWNER | 没有开放 attempt；资金重新验证计划已记录 | DemandReopenedForRevision | C1 |
| DRAFT 至 MATCHING → CANCELLED | CancelDemand | DEMAND_OWNER/OPERATIONS_REVIEWER | 尚无 Project；给出原因；已保障资金有退款计划 | DemandCancelled、RefundRequired 可选 | C1 |
| DRAFT 至 FUNDED → EXPIRED | ExpireDemand | SYSTEM | 到达版本化期限；尚无开放邀请或 Project | DemandExpired | C5 |

MATCHED 是 Demand 的交易终态。之后的协议、里程碑、交付、付款和争议只能改变 Project 侧聚合。

## 9. MatchingAttempt 与 MatchRun 状态

MatchingAttempt 状态：OPEN、SELECTED、CLOSED_NO_SELECTION、INVALIDATED、CANCELLED。每次从 FUNDED 或 NO_MATCH 请求匹配都会创建新的 attempt_no；旧 attempt、Invitation 和 Selection 保持终态，绝不“重新打开”。

| 转换 | 命令 | 角色 | 专属守卫 | 事件 | 并发/幂等 |
| --- | --- | --- | --- | --- | --- |
| 无 → OPEN | CreateMatchingAttempt | SYSTEM | 收到 MatchingRequested；Demand 没有其他开放 attempt；attempt_no 为前值加一 | MatchingAttemptOpened、MatchRunQueued | C8；Matching 内创建为 C2 |
| OPEN → SELECTED | ApplySelectionCompleted | SYSTEM | 外部 DEMAND_OWNER 已提交有效 ChooseCreator，且 7.1 事务全部成功 | MatchingAttemptSelected | 7.1 唯一跨 Context C2 |
| OPEN → CLOSED_NO_SELECTION | CloseMatchingAttempt | DEMAND_OWNER/OPERATIONS_REVIEWER/SYSTEM | 满足其一：没有 Selection 且最新 COMPLETED MatchRun 的合格候选为零；或 Selection 已 CLOSED_NO_SELECTION 且全部邀请终态 | MatchingAttemptClosedWithoutSelection | C2 |
| OPEN → INVALIDATED | InvalidateMatchingAttempt | OPERATIONS_REVIEWER/SYSTEM | DemandVersion、规则版本或资金资格失效；撤回开放邀请并取消 Selection | MatchingAttemptInvalidated | C2 |
| OPEN → CANCELLED | CancelMatchingAttempt | TRUST_OFFICER/SYSTEM | Demand 取消或安全 hold；撤回开放邀请 | MatchingAttemptCancelled | 跨 Context 触发为 C8，Matching 内为 C2 |

状态：QUEUED、RUNNING、COMPLETED、FAILED、SUPERSEDED、CANCELLED。

| 转换 | 命令 | 角色 | 专属守卫 | 事件 | 并发/幂等 |
| --- | --- | --- | --- | --- | --- |
| 无 → QUEUED | QueueMatchRun | SYSTEM | 所属 MatchingAttempt 为 OPEN；冻结 DemandVersion、全部候选 ProfileVersion 和复合规则版本 | MatchRunQueued | C2 + C7 |
| QUEUED → RUNNING | StartMatchRun | SYSTEM | worker 获得有效租约；输入哈希完整 | MatchRunStarted | C3 |
| RUNNING → COMPLETED | CompleteMatchRun | SYSTEM | 每名输入候选都有资格或排除结果；排序确定；解释通过泄漏检查 | MatchRunCompleted | C3 + C7 |
| RUNNING → FAILED | FailMatchRun | SYSTEM | 保存标准错误代码，日志不含私密字段 | MatchRunFailed | C3 |
| QUEUED/RUNNING/COMPLETED → SUPERSEDED | SupersedeMatchRun | OPERATIONS_REVIEWER/SYSTEM | 新运行已创建；没有基于旧运行完成的 Selection；处理开放邀请 | MatchRunSuperseded | C2 |
| QUEUED → CANCELLED | CancelMatchRun | OPERATIONS_REVIEWER/SYSTEM | 任务尚未开始；Demand 已取消或被 hold | MatchRunCancelled | C1 |

FAILED 不原地重试为 RUNNING。重试在同一 MatchingAttempt 内创建新 MatchRun，并通过 supersedes_match_run_id 保留因果链；若 DemandVersion、资金资格或业务规则基线改变，则应 INVALIDATE 旧 attempt 并创建新 attempt。

## 10. Invitation 状态

状态：CREATED、SENT、ACCEPTED、DECLINED、EXPIRED、REVOKED。

| 转换 | 命令 | 角色 | 专属守卫 | 事件 | 并发/幂等 |
| --- | --- | --- | --- | --- | --- |
| 无 → CREATED | CreateInvitation | OPERATIONS_REVIEWER | MatchRun 已 COMPLETED且所属 attempt 为 OPEN；候选合格；披露范围获准；不存在相同 matching_attempt_id/creator_id 的 CREATED 或 SENT 记录 | InvitationCreated | C2，开放 attempt/creator 部分唯一索引 |
| CREATED → SENT | PublishInvitation | SYSTEM/OPERATIONS_REVIEWER | 接收者 DTO 通过字段级策略和泄漏检查；期限有效 | InvitationSent | C3 |
| SENT → ACCEPTED | RespondInvitationAccept | CREATOR | actor 是接收者；未过期、未撤回；ProfileVersion 仍有效 | InvitationAccepted | C2，响应唯一 |
| SENT → DECLINED | RespondInvitationDecline | CREATOR | actor 是接收者；拒绝原因可选且按可见性保存 | InvitationDeclined | C2，响应唯一 |
| CREATED/SENT → REVOKED | RevokeInvitation | OPERATIONS_REVIEWER/SYSTEM | 尚无响应；提供规则或安全原因 | InvitationRevoked | C1 |
| SENT → EXPIRED | ExpireInvitation | SYSTEM | 已到截止时间且无响应 | InvitationExpired | C5 |

InvitationSent 表示邀请已在受邀门户可访问；邮件或短信失败只改变 Notification，不回滚邀请业务状态。

## 11. Selection 状态

状态：OPEN、SELECTED、CLOSED_NO_SELECTION、CANCELLED。

| 转换 | 命令 | 角色 | 专属守卫 | 事件 | 并发/幂等 |
| --- | --- | --- | --- | --- | --- |
| 无 → OPEN | OpenSelection | SYSTEM | 所属 MatchingAttempt 为 OPEN；至少一个 Invitation 已 SENT；Demand 为 MATCHING | SelectionOpened | C2，matching_attempt_id 唯一 |
| OPEN → SELECTED | ChooseCreator / CompleteSelection | DEMAND_OWNER（外部 actor）/SYSTEM（内部协调） | 目标 Invitation 属于本 attempt 且为 ACCEPTED；没有冲突/hold；价格与关键条件已确认 | SelectionMade | 7.1 唯一跨 Context C2 |
| OPEN → CLOSED_NO_SELECTION | CloseSelectionWithoutChoice | DEMAND_OWNER/OPERATIONS_REVIEWER | 尚无选择；邀请均已终态或明确撤回 | SelectionClosedWithoutChoice | C1 |
| OPEN → CANCELLED | CancelSelection | TRUST_OFFICER/SYSTEM | 安全 hold、Demand 取消或资金失效 | SelectionCancelled | C8 |

平台不得提供直接 CreateProject 公共命令。Project 只能由 CompleteSelection 的内部原子事务创建。CLOSED_NO_SELECTION 或 CANCELLED 的 Selection 永不重开；NO_MATCH 后的新选择属于新的 MatchingAttempt 和 Selection。

## 12. Project 状态

状态：PENDING_AGREEMENT、READY_TO_START、ACTIVE、ON_HOLD、COMPLETION_PENDING、COMPLETED、CANCELLED。

| 转换 | 命令 | 角色 | 专属守卫 | 事件 | 并发/幂等 |
| --- | --- | --- | --- | --- | --- |
| 无 → PENDING_AGREEMENT | CreateProjectFromSelection | SYSTEM | 仅作为 CompleteSelection 内部步骤；selection_id 尚未创建 Project；同事务初始化 project_id 唯一的 Agreement 根 | ProjectCreated、AgreementCreated | 7.1 唯一跨 Context C2 |
| PENDING_AGREEMENT → READY_TO_START | MarkProjectReady | SYSTEM | AgreementVersion 已 ACCEPTED；首个 Milestone 的 Funding 已 SECURED | ProjectReadyToStart | C8 |
| READY_TO_START → ACTIVE | ConfirmProjectStart | DEMAND_OWNER、CREATOR/SYSTEM | 协议要求的双方准备确认齐全；开始日有效 | ProjectStarted | C6 |
| READY_TO_START/ACTIVE → ON_HOLD | PlaceProjectHold | DEMAND_OWNER/CREATOR/TRUST_OFFICER/SYSTEM | 理由和范围明确；保存 resume_state | ProjectHeld | C1 |
| ON_HOLD → resume_state | ResumeProject | TRUST_OFFICER/SYSTEM 或协议授权方 | 所有阻塞 hold 已解除；资金和协议仍有效 | ProjectResumed | C8；多方时 C6 |
| ACTIVE → COMPLETION_PENDING | RequestProjectCompletion | SYSTEM | 所有 Milestone 已 ACCEPTED 或按生效变更取消；无开放交付 | ProjectCompletionRequested | C8 |
| COMPLETION_PENDING → COMPLETED | CompleteProject | SYSTEM | 相关 Funding 均达到 SETTLED/REFUNDED 等协议允许终态；无开放 Dispute | ProjectCompleted | C8 |
| PENDING_AGREEMENT 至 ON_HOLD → CANCELLED | CancelProject | 协议授权方/OPERATIONS_REVIEWER | 满足取消条款；生成未完成工作、退款和证据保留计划 | ProjectCancelled | C2 |

争议不是 Project 的主状态。Dispute 通过范围化 hold 暂停必要动作，避免一个局部争议冻结无关里程碑。

## 13. Agreement 与 AgreementVersion 状态

状态：DRAFT、PROPOSED、PARTIALLY_ACCEPTED、ACCEPTED、REJECTED、WITHDRAWN、SUPERSEDED。

Agreement 是聚合根，AgreementVersion 是其不可变子实体。所有 Create、Propose、Accept、Reject、Withdraw 和 Supersede 命令都以 agreement_id 为 target，并必须携带 Agreement.expected_version；命令成功时递增 Agreement.aggregate_version。单独的 AgreementVersion 没有可供客户端绕过聚合根写入的 expected_version 或仓库入口。

| 转换 | 命令 | 角色 | 专属守卫 | 事件 | 并发/幂等 |
| --- | --- | --- | --- | --- | --- |
| 无 → DRAFT | CreateAgreementVersion | DEMAND_OWNER/CREATOR/OPERATIONS_REVIEWER | 锁定 Agreement.expected_version；内容、参与方、里程碑、金额、验收、IP、数据和 AI 条款完整 | AgreementVersionCreated | Agreement 根 C2 + C7 |
| DRAFT → PROPOSED | ProposeAgreementVersion | 创建者/OPERATIONS_REVIEWER | 内容哈希固定；受影响方集合冻结；没有更新的开放版本 | AgreementVersionProposed | C1 |
| PROPOSED → PARTIALLY_ACCEPTED | AcceptAgreementVersion | DEMAND_OWNER/CREATOR/PROJECT_MEMBER | Agreement expected_version 匹配；actor 属于受影响方；尚有其他方未确认 | AgreementVersionPartiallyAccepted | Agreement 根 C6 |
| PROPOSED/PARTIALLY_ACCEPTED → ACCEPTED | AcceptAgreementVersion | 受影响的最后一方 | Agreement expected_version 匹配；所有必需方确认同一内容哈希；身份和授权仍有效 | AgreementVersionAccepted | Agreement 根 C6 |
| PROPOSED/PARTIALLY_ACCEPTED → REJECTED | RejectAgreementVersion | 任一受影响方 | 标准原因非空；未到 ACCEPTED | AgreementVersionRejected | C6 |
| DRAFT/PROPOSED/PARTIALLY_ACCEPTED → WITHDRAWN | WithdrawAgreementVersion | 提案方/OPERATIONS_REVIEWER | 未生效；通知已确认方 | AgreementVersionWithdrawn | C1 |
| ACCEPTED → SUPERSEDED | SupersedeAgreementVersion | SYSTEM | 更新版本已 ACCEPTED；历史里程碑仍保留旧版本引用 | AgreementVersionSuperseded | C8 + C7 |

AgreementVersion 创建后内容不可修改。任何编辑都在同一 Agreement 根下创建新 DRAFT；只有最后一方确认的版本成为 current_agreement_version_id。旧 If-Match 必须返回 412，不能因两个版本属于同一 Project 就分别接受并发写。

## 14. Milestone 状态

状态：DRAFT、FUNDING_PENDING、FUNDED、IN_PROGRESS、DELIVERED、CHANGES_REQUESTED、ACCEPTED、DISPUTED、CANCELLED。

| 转换 | 命令 | 角色 | 专属守卫 | 事件 | 并发/幂等 |
| --- | --- | --- | --- | --- | --- |
| 无 → DRAFT | MaterializeMilestone | SYSTEM | 来源 AgreementVersion 已 ACCEPTED；金额、交付和验收规则完整 | MilestoneCreated | C2 + C7 |
| DRAFT → FUNDING_PENDING | RequestMilestoneFunding | SYSTEM/FINANCE_OPERATOR | 前置里程碑和计划允许；精确 AgreementVersion、金额和币种已冻结 | MilestoneFundingRequested | C1；Payments 侧创建为 C8 |
| FUNDING_PENDING → FUNDED | ConfirmMilestoneFunding | SYSTEM | Funding 已 SECURED | MilestoneFunded | C8 |
| FUNDING_PENDING → DRAFT | ResetMilestoneFundingAfterFailure | SYSTEM | 对应 Funding 已 FAILED/CANCELLED 且重试策略确认没有 active replacement | MilestoneFundingReset | C8 |
| FUNDED → IN_PROGRESS | StartMilestone | CREATOR/SYSTEM | Project 为 ACTIVE；依赖和输入已满足 | MilestoneStarted | C1 |
| IN_PROGRESS/CHANGES_REQUESTED → DELIVERED | SubmitDelivery | CREATOR | 新 Delivery 已提交且扫描通过 | DeliverySubmitted、MilestoneDelivered | C2 |
| DELIVERED → CHANGES_REQUESTED | RequestSpecificChanges | DEMAND_OWNER | Acceptance 针对当前 Delivery；具体差异、标准和期限明确 | DeliveryChangesRequested | C2 |
| DELIVERED → ACCEPTED | AcceptDelivery | DEMAND_OWNER/SYSTEM | 针对当前 Delivery；人工接受或自动接受守卫通过 | DeliveryAccepted、FundingReleaseRequested | C2；自动为 C5 |
| DELIVERED → DISPUTED | ApplyDisputeOpened | SYSTEM | Trust context 已创建引用本 Milestone/Delivery 的 Dispute | MilestoneDisputed | C8 |
| DISPUTED → ACCEPTED | ApplyRulingAccept | SYSTEM | 生效 Ruling 要求接受 | MilestoneAcceptedByRuling | C8 |
| DISPUTED → CHANGES_REQUESTED | ApplyRulingRework | SYSTEM | 生效 Ruling 定义补救、期限和资金处理 | MilestoneReworkOrdered | C8 |
| DISPUTED → CANCELLED | ApplyRulingCancel | SYSTEM | 生效 Ruling 或和解终止该里程碑 | MilestoneCancelledByRuling | C8 |
| DRAFT/FUNDING_PENDING/FUNDED → CANCELLED | CancelMilestone | SYSTEM/协议授权方 | 生效 ChangeOrder 或项目取消；资金处理计划已记录但不直接改 Funding | MilestoneCancelled、RefundRequired 可选 | C2 |

Milestone ACCEPTED 仅表示验收事实成立，并触发释放请求；只有供应商确认后 Funding 才能进入 SETTLED。

## 15. Delivery 与 Acceptance 状态

Delivery 状态：PREPARING、SUBMITTED、WITHDRAWN、SUPERSEDED。
Acceptance 状态：PENDING、ACCEPTED、CHANGES_REQUESTED、DISPUTED。

| 转换 | 命令 | 角色 | 专属守卫 | 事件 | 并发/幂等 |
| --- | --- | --- | --- | --- | --- |
| 无 → PREPARING | CreateDelivery | CREATOR | Milestone 为 IN_PROGRESS/CHANGES_REQUESTED；actor 有交付权限 | DeliveryCreated | C2 |
| PREPARING → SUBMITTED | SubmitDelivery | CREATOR | 文件扫描通过；清单、版本、声明和提交说明完整 | DeliverySubmitted、AcceptanceCreated | C2 + C7 |
| PREPARING → WITHDRAWN | WithdrawDraftDelivery | CREATOR | 尚未提交，因此不存在 Acceptance；Milestone 保持 IN_PROGRESS/CHANGES_REQUESTED | DeliveryWithdrawn | C1 |
| SUBMITTED → SUPERSEDED | SupersedeDelivery | SYSTEM | 对应 Acceptance 为 CHANGES_REQUESTED；新 Delivery 已 SUBMITTED | DeliverySuperseded | C8 + C7 |
| 无 → PENDING | CreateAcceptance | SYSTEM | Delivery 已 SUBMITTED；验收人和期限来自生效协议 | AcceptanceCreated | C2 |
| PENDING → ACCEPTED | AcceptDelivery | DEMAND_OWNER | actor 是验收人；当前 Delivery 未被替代 | DeliveryAccepted | C2 + C7 |
| PENDING → CHANGES_REQUESTED | RequestSpecificChanges | DEMAND_OWNER | 每项修改引用验收标准；没有扩大范围 | DeliveryChangesRequested | C2 + C7 |
| PENDING → ACCEPTED | AutoAcceptDelivery | SYSTEM | 到达协议期限；提醒已发送；无争议、hold 或有效修改请求 | DeliveryAutoAccepted | C5 + C7 |
| PENDING → DISPUTED | ApplyDisputeOpened | SYSTEM | Trust context 已创建引用本 Acceptance 的 Dispute | AcceptanceDisputed | C8 |

SUBMITTED 的 Delivery 不可撤回。创作者发现错误时提交更正请求，由验收人执行 RequestSpecificChanges，随后新 Delivery 提交；旧 Delivery 进入 SUPERSEDED，旧 Acceptance 保留 CHANGES_REQUESTED，Milestone 经 CHANGES_REQUESTED 再回到 DELIVERED。这样不存在 Delivery 已撤回而 Acceptance/Milestone 无法恢复的状态。

OpenDeliveryDispute 是 Trust context 的公共命令；它先创建 Dispute 和范围化 hold，再由 C8 将 Acceptance 与 Milestone 推进 DISPUTED。自动接受是版本化协议规则驱动的定时命令，不以通知是否成功作为唯一前提；通知持续失败会进入人工队列。

## 16. ChangeOrder 状态

状态：DRAFT、PROPOSED、PARTIALLY_ACCEPTED、ACCEPTED、REJECTED、WITHDRAWN、APPLIED。

| 转换 | 命令 | 角色 | 专属守卫 | 事件 | 并发/幂等 |
| --- | --- | --- | --- | --- | --- |
| 无 → DRAFT | CreateChangeOrder | DEMAND_OWNER/CREATOR | 引用当前 AgreementVersion；说明范围、金额、时间和验收影响 | ChangeOrderCreated | C2 + C7 |
| DRAFT → PROPOSED | ProposeChangeOrder | 创建者 | 影响分析完整；受影响方冻结；需要追加资金时已有计划 | ChangeOrderProposed | C1 |
| PROPOSED → PARTIALLY_ACCEPTED | AcceptChangeOrder | 受影响方 | actor 尚未确认；仍有其他方未确认 | ChangeOrderPartiallyAccepted | C6 |
| PROPOSED/PARTIALLY_ACCEPTED → ACCEPTED | AcceptChangeOrder | 最后一受影响方 | 所有方确认同一内容哈希 | ChangeOrderAccepted | C6 |
| PROPOSED/PARTIALLY_ACCEPTED → REJECTED | RejectChangeOrder | 任一受影响方 | 标准原因非空 | ChangeOrderRejected | C6 |
| DRAFT/PROPOSED/PARTIALLY_ACCEPTED → WITHDRAWN | WithdrawChangeOrder | 提案方 | 尚未接受；通知已确认方 | ChangeOrderWithdrawn | C1 |
| ACCEPTED → APPLIED | ApplyChangeOrder | SYSTEM | 同时匹配 ChangeOrder.expected_version 与 Agreement.expected_version；source_change_order_id 尚未使用；变更后内容哈希等于基线版本加本 ChangeOrder | ChangeOrderApplied、AgreementVersionAccepted、AgreementVersionSuperseded | Project context 内 C2 + C6 |

ChangeOrder ACCEPTED 不直接改写旧 AgreementVersion 或旧 Milestone。ApplyChangeOrder 在 Project & Agreement context 的一个事务中：

1. 锁定 ChangeOrder 与 Agreement 两个 aggregate_version；
2. 以 source_change_order_id 唯一约束创建且接受恰好一个 resulting AgreementVersion；
3. 原子设置 resulting_agreement_version_id、current_agreement_version_id，并把旧版本标记 SUPERSEDED；
4. 将 ChangeOrder 标记 APPLIED，分别追加 ChangeOrderApplied、AgreementVersionAccepted 和 AgreementVersionSuperseded 事件。

并发 ApplyChangeOrder 中只有一个能成功；另一个因 expected_version 或唯一约束失败并重新读取，不能生成第二个结果版本。

APPLIED 表示协议版本已生效，不表示新增资金已经到账。新增或加价 Milestone 随后从 DRAFT 请求绑定该 resulting AgreementVersion 的 Funding，并在 FUNDED 前禁止开始，从而避免在 AgreementVersion 尚不存在时要求创建 Milestone Funding。

## 17. Funding 与 Payment 状态

### 17.1 Funding target

FundingTarget 是不可变判别联合，只允许两种：

| target_type | 必需引用 | 禁止引用 | 用途 |
| --- | --- | --- | --- |
| DEMAND_VERSION | demand_id、demand_version_id、金额、币种、用途、失效时间、预协议退款规则版本 | agreement_version_id、milestone_id、creator payee | 匹配前证明真实资金承诺，只作为 Demand 进入匹配的门槛 |
| MILESTONE | project_id、agreement_version_id、milestone_id、金额、币种、付款人与收款人 | demand_version_id 作为资金 target | 协议生效后的里程碑保障、释放、退款和 payout |

数据库使用判别字段和 check constraint 保证恰好一种 target。DEMAND_VERSION Funding 永远不能执行 RequestFundingRelease。Project 和 AgreementVersion 生效后，必须创建新的 MILESTONE Funding；若供应商允许复用原预授权，使用 FundingAllocation、source_demand_funding_id 和供应商确认事件连接两份 Funding，不能原地修改 target。若不允许复用，则先按预协议退款规则处理 Demand Funding，再建立新 Funding。

Funding 状态：REQUIRED、PENDING、SECURED、REPLACED、RELEASE_PENDING、SETTLED、REFUND_PENDING、PARTIALLY_REFUNDED、REFUNDED、FAILED、CANCELLED。
Payment 状态：CREATED、PENDING、SUCCEEDED、FAILED、CANCELLED；类型至少包括 AUTHORIZATION、CAPTURE、RELEASE、REFUND 和 PAYOUT。

| 转换 | 命令 | 角色 | 专属守卫 | 事件 | 并发/幂等 |
| --- | --- | --- | --- | --- | --- |
| 无 → REQUIRED | CreateFundingRequirement | SYSTEM/FINANCE_OPERATOR | FundingTarget 恰为 DEMAND_VERSION 或 MILESTONE；目标、金额和币种完整 | FundingCreated | C2 + C7 |
| 无 → REQUIRED | CreateReplacementFunding | SYSTEM/FINANCE_OPERATOR | replaces_funding_id 指向 FAILED/CANCELLED Funding；新旧 target 完全相同且没有其他 active replacement | FundingReplacementCreated | C2 + C7 |
| REQUIRED → PENDING | InitiateFunding | DEMAND_OWNER/SYSTEM | 供应商请求已创建或人工核实流程已启动 | FundingPending | C2 |
| PENDING → SECURED | RecordProviderFunding | SYSTEM | webhook 验签、金额/币种/对象匹配，供应商事实为已保障 | FundingSecured、PaymentRecorded | C4 + C7 |
| PENDING → SECURED | ConfirmManualFunding | FINANCE_OPERATOR | 两名不同人员确认同一受控证据；不得由需求审核人单独完成 | FundingSecuredManually | C6 + C7 |
| PENDING → FAILED | RecordFundingFailure | SYSTEM/FINANCE_OPERATOR | 供应商明确失败或人工证据被拒绝 | FundingFailed | C4；人工为 C1 |
| REQUIRED/PENDING → CANCELLED | CancelFunding | SYSTEM/FINANCE_OPERATOR | 尚未保障；来源 Demand/Milestone 已取消 | FundingCancelled | C1 |
| SECURED → REPLACED | AllocateDemandFunding | SYSTEM | source target 为 DEMAND_VERSION；新 MILESTONE Funding 已 SECURED；FundingAllocation 与供应商复用关系已核实 | DemandFundingAllocated | C8 + C7 |
| SECURED → RELEASE_PENDING | RequestFundingRelease | SYSTEM | target 为 MILESTONE；对应 Milestone 已 ACCEPTED；无支付/争议 hold；净额和费用可追溯 | FundingReleaseRequested | C2 |
| RELEASE_PENDING → SETTLED | RecordSettlement | SYSTEM | 供应商确认 payout/settlement；金额和收款主体匹配 | PaymentSettled | C4 + C7 |
| SECURED/RELEASE_PENDING → REFUND_PENDING | RequestRefund | FINANCE_OPERATOR/SYSTEM | 生效取消、ChangeOrder、和解或 Ruling 授权退款 | RefundRequested | C2 |
| REFUND_PENDING → PARTIALLY_REFUNDED | RecordPartialRefund | SYSTEM | 供应商确认部分退款；累计额小于原保障额 | PaymentPartiallyRefunded | C4 + C7 |
| REFUND_PENDING/PARTIALLY_REFUNDED → REFUNDED | RecordRefund | SYSTEM | 供应商确认应退金额全部完成 | PaymentRefunded | C4 + C7 |
| SETTLED → SETTLED | RecordProviderDispute | SYSTEM | 供应商报告拒付或资金争议 | PaymentDisputeOpened | C4 + C7；Trust hold 为 C8 |

FAILED、CANCELLED 和 REPLACED 都是不可逆终态。FundingFailed 后，资金 process manager 必须作出二选一裁决：

1. 策略允许重试：先创建 replacement Funding，再发出 FundingRetryScheduled；Demand/Milestone 保持 FUNDING_PENDING；
2. 没有重试或重试耗尽：发出 FundingRetryExhausted，由 C8 将 Demand 恢复 VERIFIED 或将 Milestone 恢复 DRAFT。

replacement 必须保留同一 target；若上游 DemandVersion、AgreementVersion、Milestone、金额或币种改变，应走新的业务版本和新的 Funding，而不是称为重试。每个 target/purpose 同时最多一个 REQUIRED、PENDING、SECURED、RELEASE_PENDING、REFUND_PENDING 或 PARTIALLY_REFUNDED Funding。

### 17.2 Payment 状态

Payment 自身使用以下状态协议：

| 转换 | 命令 | 角色 | 专属守卫 | 事件 | 并发/幂等 |
| --- | --- | --- | --- | --- | --- |
| 无 → CREATED | CreatePaymentOperation | SYSTEM/FINANCE_OPERATOR | 绑定 Funding、操作类型、金额、币种和主体；仅 MILESTONE target 要求 AgreementVersion；operation_reference 唯一 | PaymentCreated | C2 + C7 |
| CREATED → PENDING | SubmitPaymentOperation | SYSTEM | 供应商接受请求并返回外部对象 ID；请求不包含平台不应保存的支付凭据 | PaymentSubmitted | C2 |
| CREATED/PENDING → SUCCEEDED | RecordPaymentSucceeded | SYSTEM | webhook 或主动查询确认成功；对象、类型、金额和币种完全匹配 | PaymentSucceeded | C4 + C7 |
| CREATED/PENDING → FAILED | RecordPaymentFailed | SYSTEM | 供应商给出终态失败；错误代码经过脱敏 | PaymentFailed | C4 + C7 |
| CREATED/PENDING → CANCELLED | CancelPaymentOperation | FINANCE_OPERATOR/SYSTEM | 供应商支持取消且尚未成功；取消结果已核实 | PaymentCancelled | C4 + C7 |

FAILED 或 CANCELLED 的 Payment 不重新进入 PENDING。重试创建新的 Payment，并用 retry_of_payment_id 关联旧记录。

最后一行故意不把 SETTLED 回退为旧状态。退款、拒付和损失是新的 Payment、PaymentDispute 或调整事件；历史结算事实保持不变。任何未知、金额不符或乱序 webhook 进入 ReconciliationException，停止相关自动推进。

## 18. Dispute 与 Appeal 状态

Dispute 状态：OPEN、EVIDENCE_COLLECTION、MEDIATION、RULING_PENDING、RULED、APPEAL_PENDING、RESOLVED、CLOSED。
Appeal 状态：DRAFT、SUBMITTED、UNDER_REVIEW、DECIDED、DISMISSED。

| 转换 | 命令 | 角色 | 专属守卫 | 事件 | 并发/幂等 |
| --- | --- | --- | --- | --- | --- |
| 无 → OPEN | OpenDispute | DEMAND_OWNER/CREATOR/PROJECT_MEMBER/TRUST_OFFICER | 在允许期限；争议范围、协议条款和最低证据明确 | DisputeOpened、ScopedHoldPlaced | C2 + C7 |
| OPEN → EVIDENCE_COLLECTION | AssignDispute | TRUST_OFFICER | 分配者和处理者披露利益冲突；证据窗口确定 | DisputeEvidenceCollectionStarted | C1 |
| EVIDENCE_COLLECTION → MEDIATION | BeginMediation | MEDIATOR | 双方获得材料访问和陈述机会；敏感证据按字段授权 | DisputeMediationStarted | C1 |
| MEDIATION → RESOLVED | AcceptMediatedSettlement | DEMAND_OWNER、CREATOR | 必需各方确认同一和解文本及资金后果 | DisputeSettled | C6 + C7 |
| MEDIATION → RULING_PENDING | RequestRuling | MEDIATOR/TRUST_OFFICER | 调解未成；争点和证据包冻结 | DisputeRulingRequested | C1 + C7 |
| RULING_PENDING → RULED | IssueRuling | RULING_PANEL | 法定人数满足；成员无冲突；引用协议、证据和规则版本 | DisputeRuled | C6 + C7 |
| RULED → APPEAL_PENDING | SubmitAppeal | DEMAND_OWNER/CREATOR | 在期限内；理由限于程序错误、新证据或规则误用 | AppealSubmitted、DisputeAppealPending | C2 |
| RULED → RESOLVED | ExecuteUnappealedRuling | SYSTEM | 申诉期限已过；执行命令和资金后果已创建 | DisputeResolved | C5 + C8 |
| APPEAL_PENDING → RESOLVED | ApplyAppealDecision | SYSTEM | Appeal 已 DECIDED/DISMISSED；最终命令已创建 | DisputeResolvedAfterAppeal | C8 |
| RESOLVED → CLOSED | CloseDispute | TRUST_OFFICER/SYSTEM | 资金、权限、记录纠正和通知均完成 | DisputeClosed、ScopedHoldReleased | C8 |
| 无 → DRAFT | CreateAppeal | DEMAND_OWNER/CREATOR | 原 Dispute 为 RULED；尚无 Appeal | AppealCreated | C2 |
| DRAFT → SUBMITTED | SubmitAppeal | 申诉人 | 理由、请求和新证据引用完整；仍在期限 | AppealSubmitted | C1 + C7 |
| SUBMITTED → UNDER_REVIEW | AssignAppealReview | TRUST_OFFICER | APPEAL_REVIEWER 未参与原调解或裁决且无冲突 | AppealReviewStarted | C1 |
| UNDER_REVIEW → DECIDED | DecideAppeal | APPEAL_REVIEWER/独立小组 | 仅审查允许理由；决定引用事实和规则版本 | AppealDecided | C6 + C7 |
| SUBMITTED → DISMISSED | DismissInvalidAppeal | APPEAL_REVIEWER | 明确记录无资格、逾期或重复理由 | AppealDismissed | C1 + C7 |

AI 只能整理证据和生成草稿，不能执行 IssueRuling、DecideAppeal 或永久处罚。

## 19. Review 状态

状态：PENDING、SUBMITTED、EXPIRED、REVEALED、WITHHELD、REDACTED。

| 转换 | 命令 | 角色 | 专属守卫 | 事件 | 并发/幂等 |
| --- | --- | --- | --- | --- | --- |
| 无 → PENDING | OpenReviewWindow | SYSTEM | Project 已 COMPLETED/CANCELLED；参与关系有效；评价期限确定 | ReviewRequested | C2 |
| PENDING → SUBMITTED | SubmitReview | DEMAND_OWNER/CREATOR | actor 是作者；事实与体验字段分离；不可公开内容已过滤 | ReviewSubmitted | C2 + C7 |
| PENDING → EXPIRED | ExpireReview | SYSTEM | 截止且未提交 | ReviewExpired | C5 |
| SUBMITTED → REVEALED | RevealReview | SYSTEM | 双方均提交，或评价窗口结束；无 trust hold | ReviewRevealed | C8 |
| SUBMITTED → WITHHELD | WithholdReview | TRUST_OFFICER | 存在报复、骚扰、泄密或操纵风险；理由可申诉 | ReviewWithheld | C1 + C7 |
| REVEALED → REDACTED | RedactReview | TRUST_OFFICER | 只删除违法/泄密内容；保留原文受限证据和纠正记录 | ReviewRedacted | C1 + C7 |

Review 不计算单一五星总分。私密安全反馈由 CreateReport 进入 Trust context，默认不向被评价者或匹配 DTO 公开。

## 20. 首个垂直切片

首个实现切片固定为：

> 受邀登录 → 创作者提交档案 → 需求方提交需求 → 运营审核 → 双人资金核实 → 确定性 MatchRun → Invitation 响应 → Selection → 创建 PENDING_AGREEMENT Project。

该切片实现：

- Identity & Access 的邀请制登录、组织关系、同意和最小角色；
- CreatorProfile/ProfileVersion；
- Demand/DemandVersion 直到 MATCHED/NO_MATCH；
- 人工 Funding 核实，保留未来支付供应商适配器接口；
- MatchRun、MatchCandidate、Invitation、Selection；
- Project shell；
- 字段级授权、审计、outbox、通知、幂等和乐观并发；
- 上述状态的领域、仓库、API 契约、授权和端到端测试。

首切片验收不变量：

1. 被硬过滤者永远不能被邀请或选择；
2. 只能从 ACCEPTED Invitation 中选择；
3. 同一 Selection 的并发请求最多创建一个 Project；
4. 同输入、档案版本和规则版本得到相同 MatchRun；
5. 私密报酬底线不进入需求方 DTO、日志、通知或共享缓存；
6. 通知重试不重复创建 Invitation；
7. 旧 If-Match、重复 idempotency key 和不同 payload 都有确定响应；
8. hold 能阻止匹配、邀请和选择；
9. 所有状态变化都能追溯到 actor、命令、输入版本、规则版本和事件。

其中 `CreatorProfile/ProfileVersion/CapabilityEvidence` 的聚合状态、逐项字段可见性、IAM与SafetyHold、Matching冻结输入、幂等事务、事件及PostgreSQL/RLS义务，以 [Creator Profile、版本与字段披露设计](/architecture/creator-profile.md)为权威细化；在该页的contract/application/database门禁取得GREEN前，旧MVP creator payload不能冒充目标平台Profile实现。

其中 `Demand/DemandVersion/DemandSubmission/DemandReview` 的内容契约、Organization授权、职责分离、资金事实镜像、Matching请求、字段披露、幂等与PostgreSQL/RLS义务，以 [Demand、不可变版本与审核/资金/匹配边界](/architecture/demand-lifecycle.md)为权威细化；旧MVP demand payload及人工资金字段不能直接形成目标平台状态。

其中 `MatchingAttempt/MatchRun/MatchCandidate/Invitation/Selection` 的规则发布、输入冻结、确定性计算、三类actor授权、接收者披露、租约与幂等、事件、RLS及 `CompleteSelection` 原子协议，以 [MatchingAttempt、MatchRun、业务 Invitation 与 Selection](/architecture/matching-invitation-selection.md)为权威细化。

其中 `Project/Agreement/AgreementVersion/Milestone/Delivery/Acceptance/ChangeOrder` 的party关系、关闭内容、多方确认、Workspace/File边界、资金/争议协调、字段披露、故障恢复和RLS，以 [Project、Agreement、Milestone 与 Delivery/Acceptance](/architecture/project-agreement-delivery.md)为权威细化。

其中 `Workspace/Thread/Message/InputRequest/FileObject/FileVersion` 的项目关系、消息版本、上传/下载capability、扫描、对象一致性、隐私和RLS，以 [Workspace、消息、输入请求与 FileVersion](/architecture/workspace-and-files.md)为权威细化。

其中 `Funding/FundingTarget/FundingAllocation/Payment/ProviderEventInbox/ReconciliationException` 的人工四眼、供应商调用、webhook、replacement、累计金额、对账、职责分离、隐私和RLS，以 [Funding、Payment、Webhook 与对账投影](/architecture/funding-and-payment-projection.md)为权威细化。

其中 `SafetyHold/Report/Evidence/Dispute/Mediation/Ruling/Appeal/Review` 的scope、判定、程序保障、职责分离、执行计划、字段披露、保留和RLS，以 [Trust、SafetyHold、Dispute、Appeal 与 Review](/architecture/trust-safety-dispute-review.md)为权威细化。

其中 `TemplateBundle/NotificationIntent/NotificationPreference/DeliveryAttempt` 的event去重、contact解析、模板安全、渠道回执、provider不确定结果、隐私和RLS，以 [Notification、模板、偏好与投递回执](/architecture/notification-and-communications.md)为权威细化。

其中 `AuditEvent/SensitiveAccessEvent/AuditCheckpoint/OutcomeProjection` 的原子审计、完整性检测、投影gap、可观测性隐私、导出和恢复，以 [Audit、Analytics、Outcome 与可观测性](/architecture/audit-analytics-observability.md)为权威细化。

其中 `ModelPolicyBundle/PromptVersion/AIJob/AIOutputArtifact` 的能力隔离、输入最小化、provider调用、人工确认、评测、隐私和RLS，以 [Controlled AI Gateway、模型策略与人工确认](/architecture/controlled-ai-gateway.md)为权威细化。

其中 `CommunityGroup/Contribution/RuleProposal/Ballot/KnowledgeArtifact` 的资格、同行评议、投票、内容治理、候选规则隔离、隐私和RLS，以 [Community、Contribution 与规则治理](/architecture/community-governance.md)为权威细化。

## 21. Deferred 能力

以下能力从首个垂直切片暂缓，不是从目标平台删除：

| 阶段 | Deferred 能力 | 启用前置设计 |
| --- | --- | --- |
| 协议与交付阶段 | AgreementVersion 完整 UI、Milestone、Delivery、Acceptance、ChangeOrder、文件存储 | 协议本地化、文件安全、验收期限和自动接受规则 |
| 支付阶段 | 真实托管/保障、退款、payout、拒付、对账、发票和税务投影 | 单一司法辖区、供应商契约、webhook inbox、PCI 边界、人工降级 |
| 信任阶段 | Review 展示、Report、Dispute、Ruling、Appeal、处罚 | SLA、利益冲突、证据访问、维护者培训和外部救济 |
| 社区阶段 | 领域小组、贡献、评议、规则提案和表决 | 治理资格、任期、补偿、透明规则变更 |
| AI 阶段 | AI 澄清、总结、结构提取和风险建议 | 模型/提示版本、数据区域、退出、评测、人工确认和提示注入防护 |
| 市场扩展阶段 | 公开注册、公共列表、跨境、多币种、付费探索、需求池、公共悬赏 | 风控、内容治理、税务支付和多人知识产权模型 |
| 商业扩展阶段 | 组织订阅、采购审批、保障基金和复杂服务费 | 账单、退款、税务、会计和资金许可评估 |

移动原生应用、微服务、向量数据库和实时特征平台也不进入首切片。目标平台先保持响应式 Web、模块化单体、一个 worker、PostgreSQL、对象存储和受控外部适配器。

## 22. 测试驱动要求

每个状态表在实现前必须转成可执行测试矩阵：

- 每个允许转换至少一个成功测试；
- 每个守卫至少一个拒绝测试，并验证状态、审计和 outbox 均未部分写入；
- 每个终态测试非法回退；
- C1～C8 分别有并发、重复、乱序或重放测试；
- 每个接收者 DTO 有字段允许列表和敏感值泄漏测试；
- 每个 process manager 有重复事件与中间故障恢复测试；
- 支付、身份、文件和通知适配器先用契约测试和 fake 实现，再连接供应商；
- schema 测试必须拒绝同时引用 DemandVersion 与 Milestone 的 FundingTarget，并拒绝没有 AgreementVersion 的 MILESTONE target；
- NO_MATCH 后重试测试必须生成新的 attempt_no 和 Selection，且旧 Invitation/Selection 保持终态；
- 零合格候选测试必须在从未创建 Selection 时直接关闭 MatchingAttempt，并由 C8 把 Demand 推进 NO_MATCH；
- CompleteSelection 在任一写入点故障时必须全部回滚，并在并发重试下只产生一个 Project；
- CompleteSelection 测试必须断言外部 actor 为 DEMAND_OWNER、内部协调者为 SYSTEM，且每个 owning context 只写自己的事件；
- Invitation 并发测试必须以 matching_attempt_id/creator_id 约束开放唯一性，即使来源 MatchRun 不同；
- Agreement 与 ChangeOrder 并发测试必须覆盖 stale Agreement If-Match、双重 ApplyChangeOrder 和 resulting AgreementVersion 一一约束；
- Delivery 测试必须拒绝撤回 SUBMITTED 记录，并验证更正路径能使旧 Delivery/Acceptance 和 Milestone 都到达一致状态；
- Funding FAILED 测试必须覆盖 replacement 成功、重试耗尽后 Demand → VERIFIED、Milestone → DRAFT，以及重复 FundingFailed 事件；
- PARTIALLY_REFUNDED 必须仍占用 active Funding 唯一约束，直到进入 REFUNDED 或其他明确终态；
- 完整切片以三个真实角色跑通，并验证审计链与历史快照可复算。

任何新增状态、命令、事件或角色，都必须在同一变更中更新本文、API 契约、授权矩阵和测试。
