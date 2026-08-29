# 商业、财务与进入市场计划

> 文档状态：待验证经营模型 v0.1
> 事实边界：本目录没有提供外部市场规模、竞争、真实价格、客户承诺、成本、团队预算或现金事实；本文只定义应怎样取得和判断这些事实。
> 使命边界：交易规模、融资和增长不是唯一成功标准；商业可持续性也不能由价值认同替代。

## 0. 经营问题

愿作在首批阶段必须同时证明：

1. 需求方愿意为需求澄清、可信邀请、协议与付款保障支付；
2. 创作者能按已同意报酬获得收入，不被平台费或隐形劳动侵蚀；
3. 人工服务、支付、风险和支持的真实成本可以承担；
4. 获客不依赖强迫、出售数据、低价竞赛或单一伙伴控制；
5. 收入增长不会压低报酬、放宽需求质量或取消权利保护。

首批经营目标不是证明一个大市场，而是找到一个窄场景，使一项完整、有偿、低伤害的服务能够重复。

## 1. 商业模型的规划默认

在真实验证前，采用可撤销的候选模型：

| 组成 | 候选方向 | 待验证 |
| --- | --- | --- |
| 主要付费方 | 需求方/采购组织 | 是否真的愿意付、由谁批准、价格敏感性 |
| 创作者报酬 | 按项目/里程碑协议获得，不因平台服务费被事后削减 | 可持续报酬、税费、付款成本和周期 |
| 愿作收费 | 对需求澄清、核验、有限匹配、协作保障和运营支持收费 | 服务包、收费单位、固定/比例/订阅或组合 |
| 资金保障 | 使用目标辖区允许的 provider/合同安排 | 预付、第三方托管、授权或其他路径 |
| 公共项目 | 与普通交易、商业收入和公共资金分账 | P1 不激活正式公共金库 |
| 成员权益 | 成熟期候选，不属于首批产品定价 | 不得作为现有购买诱因 |

任何收费方式都必须展示总价、创作者约定报酬、愿作服务费、税费/支付费和退款规则。隐藏创作者费用或用复杂拆分掩盖实际抽成违背透明原则。

### 1.1 逐笔资金流登记

“需求方付款”不是一个足够精确的商业或产品事实。研究补偿、愿作服务费、项目报酬资金保障、向创作者结算、退款/冲正和补救储备必须逐笔登记，不能共用一个 `Funding`、余额或 `paid` 字段。

每条 Money Flow 使用同一模板：

```text
Money Flow ID / version / status:
Purpose and related obligation:
Related Decision IDs:
Payer / authorized payer:
Contracting counterparty / invoice recipient:
Economic beneficiary / legal payee:
Amount / currency / tax basis:
Due or authorization trigger:
Provider / account / merchant of record:
Who legally owns or controls funds at each step:
Allowed use / segregation / release condition:
Authoritative status source and evidence:
Invoice / receipt / withholding / reporting:
Platform fee / creator compensation / provider fee split:
Refund / cancellation / dispute / chargeback:
Unknown / duplicate / partial / late handling:
Reconciliation owner / independent verifier:
Cash-flow and reserve effect:
Data fields / retention / access:
Legal / Finance / Product approvers:
Activation gate / expiry / review trigger:
```

### 1.2 P0/P1 候选资金流

下表只建立必须分开的候选义务，不声明其法律结构已经成立：

| Flow ID | 候选义务 | 候选付款人 | 候选控制/收款路径 → 最终经济受益人 | 候选触发 | 权威事实 | 必须先决定 |
| --- | --- | --- | --- | --- | --- | --- |
| `MF-RSCH-01` | 研究参与补偿 | 研究责任实体 | 获批准的支付路径 → 研究参与者 | 完成约定活动或按提前退出规则结算 | 批准的补偿台账与支付/财务证据 | 研究责任实体、补偿规则、税务/数据处理 |
| `MF-SVC-01` | 需求澄清/愿作服务费 | 需求方或获授权采购者 | provider/银行 → 愿作签约实体 | 服务订单、合同或批准阶段达到约定条件 | 愿作法定账簿与 provider/银行对账 | `DEC-006`, `DEC-010` |
| `MF-PRJ-01` | 项目报酬资金保障 | 需求方或获授权出资者 | 经批准且隔离的资金安排 → 创作者/合法收款主体；不预设愿作取得资金所有权 | Agreement/Milestone 规定的保障条件 | 经法律/provider 批准的 Funding 事实；预算说明或请求不算 | `DEC-005` |
| `MF-PRJ-02` | 向创作者支付已到期项目报酬 | 已批准义务的付款主体 | provider/银行结算路径 → 创作者/合法收款主体 | 验收、到期或争议处理后的有效付款义务 | provider/银行/法定账簿对账 | `DEC-005`, `DEC-008` |
| `MF-REV-01` | 服务费或项目资金退款/冲正/拒付 | 原收款或依法控制资金的主体 | 经批准退款路径 → 有权退款主体 | 取消、退款决定、provider 冲正或争议结果 | provider/银行/账簿与决定证据 | `DEC-005`, `DEC-006`, `DEC-008` |
| `MF-REM-01` | 参与者补救与试点善后 | 愿作不受限运营现金/专用准备的合法控制者 | 获批准支付路径 → 有权获得补救者 | 获批准的补救、退款缺口或 wind-down 义务 | 预算、决定与法定账簿 | `DEC-002`, `DEC-005` |

候选流中的付款主体、merchant of record、资金所有权、是否构成代收付/托管/分账、发票和税务均为 `TBD`。在 `DEC-005`、`DEC-006`、`DEC-010` 以及相关法律、税务、合同和 provider 结论获批准前：

- 不得授权真实 `Funding` 状态、provider 资金操作或生产账务集成；
- 不得用 `MF-SVC-01` 的平台收入证明 `MF-PRJ-01` 已保障，也不得用后者冒充愿作收入；
- 不得把团队补贴、受限资金或补救准备写成需求方付款；
- 只允许使用合成数据验证候选合同和失败语义，不能据此通过 G2。

## 2. 首个市场楔子

### 2.1 ICP 决策卡

每个候选细分填一张卡：

```text
ICP ID and version:
Demand-side organization/person:
Creator segment:
Actual beneficiaries:
Geography/jurisdiction/language/currency:
Triggering event:
Recurring job to be done:
Cost of doing nothing:
Current alternatives and spend:
Decision/budget/procurement roles:
Typical scope/outcome/risk:
Why willing to switch now:
Reachable channels:
Supply density:
Legal/operational exclusions:
Evidence level and references:
Contrary evidence:
Owner / approver / review trigger:
```

### 2.2 选择标准

优先选择：

- 问题有明确触发与不解决成本；
- 预算和决策链较短且可核验；
- 交付可远程、可分里程碑、可验收；
- 创作者供给质量和主动意愿同时存在；
- 失败可补救，付款、数据、IP 和人身风险可控；
- 需求澄清、有限邀请和协作保障确有区别价值；
- 人工运营可在小批次完成；
- 不需要以低价、排他或关系性强迫获得密度。

不因市场规模看起来大就优先。若需求稀疏、角色复杂、合规高风险或必须大量线下服务，即使单价高也不适合首批。

## 3. 替代方案与市场研究

研究单位是参与者最近一次真实选择，不是竞品功能表。至少比较：

- 内部员工或跨部门协作；
- 熟人/专业网络介绍；
- 代理、工作室、咨询公司或传统供应商；
- 自由职业/采购平台；
- 招聘、外包或临时用工；
- 自己做、推迟或放弃。

每种替代记录：发现成本、筛选成本、澄清/试作劳动、价格、风险、信任、协议、付款、争议、数据/IP、再次合作和切换摩擦。愿作的差异必须连接一项参与者已经历的成本，不能只写“更公平”或“更有意义”。

市场规模使用自下而上的范围估计：

```text
Reachable qualified demand organizations
× annual frequency of the approved problem
× proportion with verified budget and willingness to use external creators
× safely operable service capacity
× verified average fee
= reachable service revenue range
```

所有数量注明来源、日期、区间、假设和敏感性；宏观行业规模不能替代首个可服务市场。

## 4. 服务包与定价实验

### 4.1 候选服务组成

首批可将价值拆成：

1. **有偿问题澄清**：把问题、角色、范围、输入、成果、验收、预算和风险写成可执行版本；
2. **核验与有限邀请**：检查资金/边界/冲突，邀请少量主动合适的创作者；
3. **协作保障**：协议、里程碑、变更、付款状态、异常和证据；
4. **运营支持**：协调、提醒、申诉入口和结束复盘；
5. **可选高触达服务**：只在已核算成本和权限后提供，不默认无限支持。

是否合并成一个价格、逐项收费或由试点补贴，均为待验证决定。

### 4.2 定价原则

- 不公开创作者私密底线，不让最低价成为选择机制；
- 不因 AI 或经验提高效率而仅按工时压低价值；
- 价格允许问题价值、成果、风险、经验和可持续成本进入判断；
- 所有费用、税费、支付成本、取消和退款在接受前可见；
- 大客户购买更多服务不产生规则、成员或数据权力；
- 公共补贴与普通交易收入分账，不用补贴掩盖不可持续服务；
- 价格例外有范围、理由、批准、到期和公平影响复核；
- 不以虚构原价、倒计时或“不买就失去机会”施压。

### 4.3 价格实验阶梯

| 阶段 | 方法 | 有效信号 | 无效信号 |
| --- | --- | --- | --- |
| 问题访谈 | 回放既有预算、采购与替代支出 | 有可核验历史和权限 | 对假设价格说“可以” |
| 方案测试 | 给出明确服务、价格区间和放弃项 | 能描述取舍和审批下一步 | 只评价界面/理念 |
| 有成本承诺 | 进入采购、法务、提供合格 Demand 或支付有偿探索 | 真实时间/声誉/资金投入 | 无期限意向函或口头支持 |
| 付费试点 | 合同、资金、付款和完成事实分别发生 | 分别取得 `E3-CONTRACT`、`E3-FUNDED`、`E3-PAID`；完整闭环才是 `E3-COMPLETED` | 团队自己补贴后写成客户付费，或用合同/资金承诺冒充已支付/完成 |
| 重复购买 | 同一或相似客户再次自愿购买 | 初步复购与价值证据 | 被长期承诺或关系压力锁定 |

每次实验预先写明价格、服务、补贴、成本、样本、决策规则和不会因拒绝发生的后果。

## 5. 进入市场策略

### 5.1 首批需求侧

候选渠道：

- 有明确问题的创始网络转介；
- 专业协会、行业社群和小型组织的自愿合作；
- 公开问题诊断/需求澄清工作坊；
- 经批准的高校、园区、社区或公益伙伴；
- 高信任内容与案例，但只发布获授权、证据充分的材料。

渠道评估不是只看线索数量，还要看：决策权、合格需求率、资金可达、关系性强迫、数据权限、转换所需人工和伙伴集中度。

### 5.2 首批创作者侧

- 从与首个场景直接相关的专业网络定向、自愿招募；
- 说明试点名额、项目不保证、拒绝无惩罚和数据用途；
- 同时纳入有经验者和符合基本标准的新进入者，观察准入壁垒；
- 不以免费劳动、曝光、未来治理权或高收入承诺换取资料；
- 控制供给规模，避免招募大量人却没有真实机会；
- 允许低强度参与、多平台参与和随时暂停。

### 5.3 伙伴渠道边界

伙伴可以提供自愿转介、空间、知识或资金，不能：

- 替个人同意或批量创建成员身份；
- 因资源贡献自动控制候选、验收或项目数据；
- 把课程、雇佣、住房、公共服务或资助与愿作参与绑定；
- 要求正面案例、品牌背书或压制负面研究结果；
- 形成无法替代的单一线索/资金来源而没有退出计划。

### 5.4 供需节奏

邀请制批次按可服务容量开放。不得为了“市场看起来活跃”同时扩大两侧。

```text
New qualified Demand cap
= minimum of:
  demand review capacity,
  suitable willing creator capacity,
  active case coordination capacity,
  payment/reconciliation capacity,
  dispute/appeal capacity,
  risk reserve coverage.
```

若供给远大于合格需求，暂停创作者招募并诚实说明；不制造无意义资料完善、投标或活跃任务。

## 6. 漏斗定义与证据来源

| 阶段 | 权威事实 | 不得替代 |
| --- | --- | --- |
| Qualified lead | 通过获批资格检查的真实主体 | 浏览、点赞、报名兴趣 |
| Verified Demand | 决策、资金路径、范围、验收和角色核验完成 | 一张需求表提交 |
| Funded/secured | provider/财务权威事实 | 预算承诺或付款请求 |
| Invitation | 实际发出的作用域邀请 | 推荐列表生成 |
| Accepted invitation | 创作者明示接受 | 沉默、浏览或运营代填 |
| Completed selection | 已接受候选中完成授权选择 | 选择意图 |
| Started project | 必要协议和资金条件满足 | 创建 Project ID |
| Accepted milestone | 按当时标准完成验收 | 上传文件 |
| Paid | provider/账簿对账完成 | Outcome 自报 |
| Repeat cooperation | 双方再次自愿建立真实合作 | 表示“愿意考虑” |

漏斗必须同时呈现拒绝、退出、失败、争议、等待和不合格原因，不能只把它们视作转化损失。

## 7. 单位经济

### 7.1 必须分开的量

- `Project value / GMV`：项目约定或实付给创作者的交易价值；
- `Platform gross revenue`：愿作依法确认的服务收入；
- `Pass-through funds`：代经 provider 流转、但不属于愿作收入的资金；
- `Public/restricted funds`：有用途限制的公共或专项资金；
- `Creator compensation`：创作者应得/实得报酬及税费口径；
- `Public labor compensation`：导师、评审、调解等非单项交易劳动；
- `Refund/chargeback/reserve`：退款、冲正、坏账和风险准备。

不得以 GMV 冒充收入，也不得把平台补贴冒充客户付款。

### 7.2 每个项目的直接贡献

```text
Recognized platform service revenue
- payment/provider variable fees borne by platform
- project-specific operations labor at fully loaded cost
- project-specific support/safety/reconciliation labor
- direct communication/storage/verification/vendor cost
- expected and realized refund/chargeback/fraud loss
- project-specific acquisition/referral cost
- approved subsidy not funded by restricted public money
= contribution before shared fixed costs
```

项目协调与真实公共劳动分开标记，避免把所有运营成本包装成公共贡献，或反过来隐藏共同体维护成本。

### 7.3 经营层指标

- 每个合格 Demand 的审核时间和成本；
- 每个成功/失败/争议项目的运营工时；
- 服务收入、贡献前固定成本和贡献后固定成本；
- 合格 Demand 获客成本，而不是报名成本；
- 需求方从首次接触到资金确认的周期；
- 创作者从加入到首次正常付费机会的时间；
- 退款、拒付、付款失败和补救成本；
- 支持、隐私、安全和申诉队列成本；
- 现金转换周期与需预付的营运资金；
- 单一客户、渠道、伙伴、provider 和资助方集中度。

早期样本不足时，不用 LTV/CAC 比率制造精确感；先报告区间、敏感性和事实不足。

## 8. 试点预算模板

```text
Budget version / period / batch cap:

Cash available for pilot:
- unrestricted operating cash:
- restricted funds:
- participant payments/pass-through:

Planned costs:
- research compensation:
- creator/project compensation:
- refunds and participant remedy reserve:
- product/engineering labor:
- concierge operations labor:
- safety/privacy/appeal labor:
- legal/tax/accounting/insurance:
- payment/identity/communication/storage vendors:
- security and recovery:
- acquisition/partner costs:
- contingency:

Revenue assumptions:
- number of qualified demands:
- paid projects:
- price/service fee:
- discounts/subsidies:
- expected refunds/chargebacks:

Cash timing:
- customer payment date:
- creator payment obligation/date:
- provider settlement delay:
- tax/invoice timing:

Downside case and maximum loss:
Stop threshold:
Owner / reviewer / approver:
```

批次预算必须能在零新增销售的情况下完成现有项目、支付应付报酬、处理退款/申诉和处置数据。

## 9. 场景与现金安全

至少维护三种情景：

| 情景 | 假设 | 必须回答 |
| --- | --- | --- |
| Base | 研究支持的中性数量、价格、工时和失败率 | 在批准批次内能否完成 |
| Downside | 更少合格需求、更高运营/退款/法律成本和更慢回款 | 是否仍能履行现有义务 |
| Mission stress | 大客户要求降标准、数据/IP 权利或排他以换收入 | 是否有能力拒绝并继续运行 |

现金跑道、最低储备和暂停阈值由 Finance accountable 依据真实预算批准。未填之前不能用“资金应该够”通过 `G1/G2`。

立即暂停新增承诺的候选信号：

- 无法覆盖已签项目的创作者报酬、退款、税费或补救；
- 回款周期或 provider 冻结超过批准缓冲；
- 单项目直接贡献持续为负且没有获批准、有限期的学习理由；
- 运营积压导致付款、数据权或申诉延误；
- 继续运行依赖接受违反社会契约的客户/资金条件；
- 单一来源达到批准集中度阈值但无替代计划。

## 10. 团队与资源计划

`G1` 前填写：

| 职能 | 当前负责人 | 每批可用容量 | 必备能力/培训 | 替补 | 缺口与获取方式 |
| --- | --- | --- | --- | --- | --- |
| Product/Research | `TBD` | `TBD` | `TBD` | `TBD` | `TBD` |
| Engineering/Delivery | `TBD` | `TBD` | `TBD` | `TBD` | `TBD` |
| Demand/Creator Operations | `TBD` | `TBD` | `TBD` | `TBD` | `TBD` |
| Payment/Finance | `TBD` | `TBD` | `TBD` | `TBD` | `TBD` |
| Safety/Appeal | `TBD` | `TBD` | `TBD` | `TBD` | `TBD` |
| Privacy/Security | `TBD` | `TBD` | `TBD` | `TBD` | `TBD` |
| Legal/Tax/Insurance | `TBD` | `TBD` | `TBD` | `TBD` | `TBD` |

人员计划按风险和服务队列决定，不只按工程 backlog 决定。没有独立申诉、付款核实或隐私责任容量时，不能用更多开发者替代。

## 11. 资本、客户与伙伴集中度

成熟资本结构尚未决定，但从 P0 起每个资金/资源关系都需登记：

```text
Source / counterparty:
Type: revenue / investment / debt / grant / procurement / vendor / partner
Amount and period:
Restrictions and side conditions:
Data/IP/brand/reporting rights:
Governance/approval/termination rights:
Personal or institutional conflicts:
Share of revenue/cash/critical infrastructure:
Substitutability and exit cost:
Mission impact and red lines:
Owner / approver / expiry:
```

不得接受以资金换取成员资格、章程权、候选选择、私密数据、公共知识排他化或核心资产单方处置的条件。集中度阈值为 `TBD`，在第一笔相关资金/合同前批准。

## 12. 经营评审看板

每个批次并列审查：

| 经营健康 | 使命健康 |
| --- | --- |
| 合格需求、服务收入、直接贡献、现金、回款、运营工时 | 拒绝无报复、报酬、范围变更补偿、付款真实、首次机会、关系与受益者结果 |
| 获客渠道、周期、伙伴/provider 集中度 | 数据权、申诉、伙伴强迫、成果路径、公共劳动和未决伤害 |

任何增长伴随使命指标恶化时，执行 `FND-MIS-002`：指定负责人调查，必要时缩小、暂停或停止。财务困难也应公开成为决策输入，不能通过悄悄降低保护解决。

具体指标 ID、分子/分母、事实源、隐私和批次预注册见[使命衡量与学习计划](/foundations/mission-measurement-and-learning-plan.md)。

## 13. 提交给 `G1/G2` 的商业与财务证据包

本节只向[统一启动决策入口](/foundations/readiness-and-start-decision.md)的对应 Gate ID 提交商业/财务证据，不自行宣布或降低总 Gate。若本节表述与统一清单不同，以统一清单为准。

### `G1` 证据输入

- 标准路径下，一个候选 ICP 有 `E1` 问题证据且至少有部分需求方采取 `E2` 下一步；采用 `DEC-033` 时必须标为 `E0 / FOUNDER-DIRECTED BUILD HYPOTHESIS`，并批准独立开发预算、期限和停止阈值；
- 付费方、受益方和服务包清楚，价格仍可作为受控实验；
- `MF-*` 逐笔资金流、分账边界和事实源已形成批准版本；`DEC-005`、`DEC-006`、`DEC-010` 未决时不得把 Funding/provider 资金能力列入获准 backlog；
- 首批渠道和供需上限不依赖强迫或无限招募；
- 试点预算、团队容量、最大损失、储备和停止阈值批准；
- 付款架构、税务边界、合同/资金角色和逐笔事实源已有书面专业确认；最终可执行合同、实际 provider 路径和对账演练仍由 `G2` 验收；
- 单位经济字段、工时和事实来源可采集；
- 资本/客户/伙伴临时护栏进入现实批准流程。

`DEC-033` 不构成需求、购买、付费意愿或单位经济证据，也不授权真实收入、Funding/provider 能力或对外市场宣称。

### `G2` 证据输入

- 至少一个真实需求方达到 `E2`；若已有约束性合同或资金承诺，分别记录为 `E3-CONTRACT` / `E3-FUNDED`，不能冒充 `E3-PAID` / `E3-COMPLETED`，且没有用团队补贴冒充购买；
- 价格、费用、报酬、税费、退款和变更对各方可理解；
- 批次现金已落实，最坏情景仍能完成现有义务；
- provider 与对账真实可用，付款发起/核实分离；
- 运营、支持、隐私、安全和申诉成本已计入，而非视作免费；
- 达到停止阈值时有实际暂停权，不受销售负责人单方覆盖。

## 14. 尚待经营决定

- `DEC-001`、`DEC-002`：首个 ICP、地区、行业、币种、价格带、批次上限、金额/周期和总损失上限；
- `DEC-006`、`DEC-010`：服务包、收费单位、服务费、补贴以及需求澄清由谁、何时付费；
- `DEC-005`、`DEC-008`：创作者报酬、逐笔资金流、provider、资金保障、退款、结算、合同和范围变化的经济规则；
- `DEC-005`：KYC/KYB、付款主体与 provider 身份要求；`DEC-029`：服务费、创作者报酬、研究补偿、退款等的税费、发票/收据、代扣与会计口径；
- `DEC-002`、`DEC-006`：每案人工时、团队/供应商/获客/风险成本，试点预算、现金跑道、储备和停止阈值；
- `DEC-016`、`DEC-017`：首批渠道、伙伴条款、供需平衡以及收入、客户、资本、资助、采购和 provider 集中度阈值；
- `DEC-020`：哪些公共价值工作由交易费支持，哪些需独立资金；P1 只记录和补偿已批准劳动，不激活公共金库；
- `DEC-032`：G2 最小指标激活包、主要/护栏/停止指标和采集模式；
- `DEC-022`：什么证据允许从补贴学习转为可持续经营并进一步扩大。

这些数字必须来自真实决策和证据。文档完整不等于把空白填成乐观预测。
