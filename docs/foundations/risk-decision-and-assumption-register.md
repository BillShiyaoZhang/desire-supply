# 风险、决定与假设登记册

> 文档状态：启动 RAID 基线 v0.2
> 事实截止：2026-08-12；`DEC-033` 另包含项目所有者在本项目任务中的明确指示
> 使用规则：本文是未决风险、决定和假设的唯一启动队列；各专题文档引用 ID，不另建失去同步的自然语言清单。`TBD` 在到达对应 Gate 前必须换成具名责任人、证据、决定和复审触发。

## 0. 状态与严重度

### 0.1 状态

- `BLOCKER`：阻断 `G1`、`G2` 或相关能力；
- `OPEN`：需要控制、决定或证据，尚未关闭；
- `CONTROLLED`：控制已实施并演练，仍需监测/到期复审；
- `ACCEPTED`：具名有权限者在明确范围和期限内接受残余风险；
- `CLOSED`：触发原因已移除或证据证明控制充分；
- `DEFERRED`：能力未激活，风险通过保持关闭而控制；
- `SUPERSEDED`：由新条目替代，历史保留。

### 0.2 影响

- `CRITICAL`：可能造成人身危险、重大资金/数据/权利损害、违法运行或跨主体失控；
- `HIGH`：可能实质损害报酬、公平、信任、运营连续性或使命；
- `MEDIUM`：可恢复但会增加成本、延迟、理解或质量风险；
- `LOW`：局部且易恢复。

发生可能性在真实数据出现前统一标 `UNKNOWN`，不以主观“低概率”绕过高影响控制。

## 1. 风险接受规则

- `CRITICAL` 不得由产品、工程或创始人单方接受。每个 Gate 只处理其授权范围会触发的 Critical；仅由尚未启用能力触发者可在能力确实关闭、入口不可达且有复审触发时标为 `DEFERRED`。能力、真实数据、资金或权益一旦纳入范围，`DEFERRED` 自动失效，并须在相应 Gate 前关闭触发条件，或用 Gate 前控制证据证明残余影响不再为 Critical；
- `HIGH` 只能在适用法律义务、`FND-*` 禁止结果、Gate 必备权利和最低控制均已满足后，对残余风险作有范围的接受；不得用多人签字豁免反歧视、无障碍、报酬、隐私、安全、正当程序或其他强制要求。接受仍需要业务 owner、受影响专业 owner 和独立复核共同签字，且有到期、监测和补救；
- 影响报酬、隐私、安全、申诉、劳动关系或法律许可的风险，必须由相应 Finance/Privacy/Safety/Legal 权限者参与；
- 收益不得只写“更快上线”；必须说明谁获得收益、谁承担风险和替代方案；
- 接受有明确范围、批次、数据、金额和期限；范围变化自动失效；
- 参与者不能被条款要求接受团队本应控制、但因准备不足产生的风险；
- 风险关闭需可定位证据，不能以“已讨论”“代码存在”或“暂未发生”作为关闭。

### 1.1 固有风险、Gate 控制与效果证据

每条风险在评审时必须分别记录，不能把它们压成一个严重度或一个勾选框：

1. **固有影响**：没有控制时可能造成的最大合理伤害；上线后不因“暂未发生”而降低；
2. **Gate 前控制证据**：在接触相应数据、资金或权利前，预防、侦测、恢复、人员、合同和演练已经可用；
3. **残余风险**：控制生效后仍可能发生的伤害及其影响等级；Critical 残余风险不能由团队接受；
4. **运行效果证据**：批次中真实趋势、反例、近失和补救结果，用于 `G3` 是否扩大，而不是反过来作为首次启动前不可能取得的证明。

因此，`G1/G2` 可以把固有 `CRITICAL` 条目标为 `CONTROLLED`，但前提是 Gate 前控制证据完整且残余影响不再为 Critical；能移除触发原因时标为 `CLOSED`；能力关闭时标为 `DEFERRED`。不得为了通过 Gate 修改固有影响标签。

## 2. 启动风险登记

| Risk ID | 风险与受影响者 | 影响 / 可能性 | 当前控制 | 关闭或控制证据 | Owner / Gate | 状态 |
| --- | --- | --- | --- | --- | --- | --- |
| `RSK-001` | 未选择首个 ICP/问题，开发成宽泛平台；所有参与者与团队受影响 | `HIGH/UNKNOWN` | 产品定义给出可撤销规划默认 | 获批 ICP、排除项、E1/E2 证据和单一 P1 范围 | Product / `G1` | `BLOCKER` |
| `RSK-002` | 把理念认同、创始人选择、Demo 或代码完成当付费需求 | `HIGH/UNKNOWN` | `DEC-033` 要求所有市场假设保持 `E0` 且禁止外部宣称 | G2 前由合法、独立于代码的现实行动/采购/合同/付费意愿和反例证据关闭 | Product/Business / `G2` | `BLOCKER` |
| `RSK-003` | 大量招募创作者但没有合格机会，制造无偿等待和虚假希望 | `HIGH/UNKNOWN` | 邀请制、供需 WIP 规则 | 招募上限、真实机会比、暂停规则和诚实通知 | Growth/Ops / `G2` | `OPEN` |
| `RSK-004` | 人工运营负担失控，关键付款、申诉和数据权超时 | `CRITICAL/UNKNOWN` | 运营队列和 WIP 模板 | 具名 owner/backup、SLO、容量、演练和超限暂停 | Ops / `G2` | `BLOCKER` |
| `RSK-005` | 单一运营者导入、改规则、选人、写结果，成为隐藏主权者 | `CRITICAL/UNKNOWN` | 职责分离与决定模板 | 身份、最小权限、双人控制、冲突、审计、申诉真实演练 | Ops/Security / `G1/G2` | `BLOCKER` |
| `RSK-006` | 完整 Profile/不相关候选进入不可变匹配快照，删除困难 | `CRITICAL/UNKNOWN` | 路线图要求最小快照 | 数据流设计、迁移、主体定位、删除/更正与恢复测试 | Privacy/Engineering / `G1` | `BLOCKER` |
| `RSK-007` | 分项分数/预算反推出创作者私密报酬底线 | `CRITICAL/UNKNOWN` | 禁止输出原值 | 信息流威胁模型、移除可逆分项、属性测试与人工红队 | Privacy/Security / `G1` | `BLOCKER` |
| `RSK-008` | 自由文本、导出和小样本造成 PII/收入再识别 | `CRITICAL/UNKNOWN` | 最小数据原则 | 字段清单、输入/人工复核、访问、抑制、导出授权和事件演练 | Privacy / `G1/G2` | `BLOCKER` |
| `RSK-009` | Session、RLS、连接池或后台任务导致跨账户/租户访问 | `CRITICAL/UNKNOWN` | 设计上 fail-closed | 固定 revision 的真实 PG/session/RLS/池/恢复测试全绿 | Security/Engineering / `G1` | `BLOCKER` |
| `RSK-010` | Matching 跨 attempt/run/tenant 使用错误 Selection | `CRITICAL/UNKNOWN` | 已在审计中识别 | 聚合作用域修复、多 run 并发/RLS/E2E 证据 | Engineering / `G1` | `BLOCKER` |
| `RSK-011` | 未明确接受者被选择，或拒绝后被隐性降权 | `HIGH/UNKNOWN` | 双向接受规范 | 状态不变量、派生特征禁令、运营审计和真实趋势复盘 | Product/Ops/Engineering / `G1/G2` | `BLOCKER` |
| `RSK-012` | 付款请求/自报冒充已支付，未知结果导致双付或拖欠 | `CRITICAL/UNKNOWN` | 付款真相源与对账原则 | 合格 provider、幂等/inbox、发起核实分离、未知/退款/冲正演练 | Finance/Engineering / `G2` | `BLOCKER` |
| `RSK-013` | 愿作无许可代收、托管、分账或触碰受监管金融活动 | `CRITICAL/UNKNOWN` | 法律计划要求专业确认 | 目标辖区支付意见、provider 书面方案和产品/合同一致 | Legal/Finance / `G1/G2` | `BLOCKER` |
| `RSK-014` | 独立项目实质构成雇佣/派遣，规避劳动义务 | `CRITICAL/UNKNOWN` | 首批排除高控制项目 | 劳动分类意见、项目筛选、合同和实际运营一致性抽查 | Legal/Ops / `G1/G2` | `BLOCKER` |
| `RSK-015` | 发票、代扣、跨境或税务处理错误，侵蚀参与者报酬 | `HIGH/UNKNOWN` | 税务工作流 | 税务/会计意见、账簿/产品/合同/说明一致和对账 | Finance/Legal / `G2` | `OPEN` |
| `RSK-016` | IP、共同作品、公共知识或受益者经验被默认转让/专有化 | `HIGH/UNKNOWN` | 权利影响矩阵原则 | 项目级权利链、许可、署名、转型授权和结束维护安排 | Legal/Product / `G2` | `OPEN` |
| `RSK-017` | 师生、上下级、物业、资助关系使参与或同意不自愿 | `CRITICAL/UNKNOWN` | `FND-NOD/DEP` 与伙伴清单 | 权力关系披露、独立确认、站外待遇不变、替代路径和绕行申诉演练 | Ethics/Ops/Partner / `G2` | `BLOCKER` |
| `RSK-018` | 举报者、拒绝者或申诉者遭运营、伙伴或需求方报复 | `CRITICAL/UNKNOWN` | 反报复原则、独立复核 | 保密路径、机会/权限关联审计、轮换、补救和真实趋势复盘 | Safety/Ops / `G2` | `BLOCKER` |
| `RSK-019` | 原决定人与申诉复核未分离，救济仅形式存在 | `CRITICAL/UNKNOWN` | 运营角色分离 | 具名独立 reviewer、替补、冲突测试、时限和可执行补救演练 | Safety/Legal / `G2` | `BLOCKER` |
| `RSK-020` | 歧视、单一资深标准或不必要门槛排除新人/特定群体 | `HIGH/UNKNOWN` | 禁止总分、反行会原则 | 合法公平政策、评审多元、合理便利、质性反例和隐私阈值 | Product/Ops/Legal / `G2/P3` | `OPEN` |
| `RSK-021` | 产品/运营不具无障碍与清晰语言，权利实际不可用 | `HIGH/UNKNOWN` | Accessible Product Shell 目标 | 适用标准、辅助技术/理解测试、人工/线下替代和缺陷门禁 | Product/Engineering/Ops / `G2` | `OPEN` |
| `RSK-022` | 伙伴以流量、资金、场地、品牌换候选控制、数据或治理权 | `HIGH/UNKNOWN` | 伙伴协议和资源不买权力 | 版本化角色/条件/冲突/期限/退出，独立审计和集中度预警 | Partner/Legal / 使用前 | `OPEN` |
| `RSK-023` | 单一客户、投资者、资助方或供应商形成事实否决权 | `HIGH/UNKNOWN` | 临时资本护栏 | 集中度阈值、条款披露、替代/储备与拒绝压力复盘 | Finance/Governance / `G1+` | `OPEN` |
| `RSK-024` | 现金不足以支付报酬、退款、税费和补救 | `CRITICAL/UNKNOWN` | 试点预算模板 | Downside 现金、受限资金分账、储备、最大损失和暂停阈值批准 | Finance / `G1/G2` | `BLOCKER` |
| `RSK-025` | provider/伙伴/关键人员停摆导致项目、报酬、申诉或数据权不可达 | `CRITICAL/UNKNOWN` | 连续性与替补原则 | 退出条款、替代、backup/restore、人工接管和停摆演练 | Ops/Engineering / `G2` | `BLOCKER` |
| `RSK-026` | 规则、Schema、文档和代码多重真相源漂移 | `HIGH/UNKNOWN` | 状态层与 registry 要求 | 单一合同/自动等价检查、版本 hash、owner、有效期和 CI 门禁 | Delivery/Engineering / `G1` | `BLOCKER` |
| `RSK-027` | 指标把 GMV/活跃当使命，或用错误事实源制造公平/付款结论 | `HIGH/UNKNOWN` | Mission Health 原则 | 指标目录、权威事件、分母、证据等级、隐私阈值、反例和触发动作 | Data/Product/Ops / `G2` | `OPEN` |
| `RSK-028` | 对外夸大匿名、安全、付款、公平、成员所有或效果 | `HIGH/UNKNOWN` | 宣称控制章节 | Claims registry、跨职能批准、证据期限和纠正/撤回流程 | Product/Legal / 发布前 | `OPEN` |
| `RSK-029` | 为赶工删除数据权、申诉、恢复或职责分离 | `CRITICAL/UNKNOWN` | Gate 和 DoD | 不可协商清单、阻断权、变更记录和独立 go/no-go | Delivery / `G1/G2` | `BLOCKER` |
| `RSK-030` | 过早开发成员、贡献分数、公共资金或治理，冻结创始偏见 | `HIGH/UNKNOWN` | P3–P5 激活顺序 | 功能保持关闭；真实成员/公共劳动/多元复核证据后另过 Gate | Governance / P3+ | `DEFERRED` |
| `RSK-031` | AI 泄漏数据、引入偏差或替人作重大决定 | `CRITICAL/UNKNOWN` | P1 默认关闭 | 明确价值、provider/数据/评测/人工/申诉方案批准前保持关闭 | Privacy/Product / AI 启用前 | `DEFERRED` |
| `RSK-032` | 声誉/评价成为永久总分或平台锁定工具 | `HIGH/UNKNOWN` | 情境化评价和无总分 | 来源/时间/回应/更正/撤销/携带设计与真实复盘 | Product/Privacy / P1/P3 | `OPEN` |
| `RSK-033` | 安全限制或封号级联取消余额、凭证、数据权和外部支持 | `CRITICAL/UNKNOWN` | 状态分离原则 | 独立生命周期、blast-radius 测试、到期、恢复和善后演练 | Safety/Engineering / `G2` | `BLOCKER` |
| `RSK-034` | 团队关键人员缺席或利益冲突导致职责分离失效 | `HIGH/UNKNOWN` | 要求 backup | 具名替补、权限到期、交接、演练和暂停规则 | Pilot accountable / `G1/G2` | `BLOCKER` |
| `RSK-035` | 停止试点时没有完成报酬、退款、数据和参与者说明 | `CRITICAL/UNKNOWN` | wind-down 原则 | 预资金化善后计划、责任人、合同/provider/数据步骤演练 | Pilot/Finance/Privacy / `G2` | `BLOCKER` |
| `RSK-036` | 文件、自由文本、消息或项目材料包含违法、侵权、威胁、自伤/他伤或依法须报告内容，却被静默传播、过度保存、错误删除或无正当程序处置 | `CRITICAL/UNKNOWN` | 高风险内容与未评审消息能力保持关闭 | 适用内容/报告意见、允许范围、最小访问、举报/证据/通知/升级/申诉流程及人员演练；运行趋势留作 `G3` 复盘 | Legal/Safety/Engineering / `G1/G2` | `BLOCKER` |
| `RSK-037` | 跳过真人研究后做错首个产品，浪费工程预算并因沉没成本拒绝修改；团队和未来参与者受影响 | `HIGH/UNKNOWN` | `DEC-033` 限定单一场景、`E0` 标签、可撤销边界和 G2 前现实证据 | `G1-07` 的成本/时间/停止上限、每 Slice 反证复盘、无真实用户/数据/资金、范围变化自动复审；Product、Research/Evidence、Business/Finance 与独立 Risk reviewer 具名确认 | Founder/Product/Finance / `G1 BUILD ONLY` | `OPEN — BLOCKER G2/CLAIMS` |

## 3. 开放决定登记

安全默认在决定前持续生效。

| Decision ID | 必须决定 | 所需证据/参与者 | 安全默认 | 最迟门槛 | Owner | 状态 |
| --- | --- | --- | --- | --- | --- | --- |
| `DEC-001` | 首个 ICP、问题、地域、语言、币种和行业排除 | R1/R2 研究、Ops/Legal/Finance | 不开放真实服务 | `G1` | Product | `OPEN` |
| `DEC-002` | 首批项目数、金额、周期、里程碑和总损失上限 | 运营容量、预算、法律风险 | 仅合成演练 | `G1/G2` | Pilot/Finance | `OPEN` |
| `DEC-003` | 运营实体、合同主体和平台法律角色 | 外部法律意见 | 不签约/收费 | `G1` | Legal | `OPEN` |
| `DEC-004` | 创作者/需求方/运营/公共劳动的法律关系 | 劳动/税务意见和实际控制模型 | 排除疑似雇佣项目 | `G1` | Legal/Ops | `OPEN` |
| `DEC-005` | `MF-PRJ-01`、`MF-PRJ-02`、`MF-REV-01`、`MF-REM-01` 的支付、资金保障、退款、对账、provider、权威事实和资金所有/控制 | 逐笔 Money Flow、支付/法律/财务/工程验证 | 不代持，不称托管/已支付，不授权真实 `Funding` 或 provider 资金操作 | `G1/G2` | Finance | `OPEN` |
| `DEC-006` | `MF-SVC-01` 的服务包、付费方、收费单位、价格、费用展示和补贴 | 价格研究、完整成本、税务、合同与参与者理解 | 不自动收费/不承诺折扣，不把创作者报酬或项目资金当平台收入 | `G1/G2` | Business/Product | `OPEN` |
| `DEC-007` | 数据控制/处理角色、字段、合法基础、保留、跨境 | 数据清单和隐私意见 | 最小、不扩用、不跨境 | `G1/G2` | Privacy | `OPEN` |
| `DEC-008` | 合同包、优先级、签署、电子证据和争议管辖 | Legal Scope、流程走读 | 社会契约不当合同 | `G2` | Legal | `OPEN` |
| `DEC-009` | 需求方九类角色的必填/兼任与受益者确认 | 研究、法律、运营演练 | 不以 Organization 代全部角色 | `G1` | Product/Ops | `OPEN` |
| `DEC-010` | 需求澄清是否有偿、由谁通过 `MF-SVC-01` 支付、计入何种义务、何时停止免费工作 | 价格/工时/公平证据、合同、税务和与项目资金分离 | 不要求创作者免费实质澄清；未决时不收费、不授权真实 `Funding` | `G1/G2` | Business/Ops | `OPEN` |
| `DEC-011` | P1 部署形态和模块/事务边界 | 当前代码基线、ADR 比较 | 不提前微服务化 | Slice 0 | Engineering | `OPEN` |
| `DEC-012` | 身份、文件、通知、broker、支付等 provider | 安全/隐私/成本/退出评估 | 仅 sandbox，无真实数据/钱 | Slice 0/`G2` | Engineering/Procurement | `OPEN` |
| `DEC-013` | NFR：可用、容量、RTO/RPO、无障碍、成本目标 | 批次、法律、运营和预算 | 无目标不真实上线 | `G1/G2` | Engineering/Ops | `OPEN` |
| `DEC-014` | 安全/争议/申诉的时限、证明与补救 | 法律、安全、参与者理解演练 | 高风险暂停，独立复核 | `G2` | Safety/Legal | `OPEN` |
| `DEC-015` | 数据权请求时限、身份核验、legal hold、导出格式 | 隐私意见、各域清单、演练 | 不扩大数据用途 | `G2` | Privacy | `OPEN` |
| `DEC-016` | 伙伴渠道、第三方资源、角色、资源条件与停摆承接 | 伙伴尽调、受益者/参与者确认、`TBD-PARTNER-01` | 批准前 P1 禁止依赖第三方场地、设备、导师、数据、品牌、转介或其他资源 | 使用前（研究伙伴最迟 `G0B`） | Partner/Legal | `OPEN` |
| `DEC-017` | 收入/客户/资本/provider 集中度阈值与替代 | 财务情景和使命压力测试 | 新条件不得购买权力/数据 | 第一笔前 | Finance/Governance | `OPEN` |
| `DEC-018` | AI 是否在 P1 使用 | 明确净价值、隐私、评测和申诉 | 关闭 | AI Gate | Product/Privacy | `DEFERRED` |
| `DEC-019` | 正式成员资格与 Public Office | P3 激活证据 | 不实现/不授政治权 | P3 | Governance | `DEFERRED` |
| `DEC-020` | 公共金库、公共劳动章程和分层治理 | P4 激活证据 | 仅透明记录真实劳动 | P4 | Governance/Finance | `DEFERRED` |
| `DEC-021` | 成员经济权益、法律实体组合、核心资产与分支 | 法律/税务/成员/治理证据 | 不承诺所有权/回报；临时护栏生效 | 融资前/P5 | Governance/Legal | `DEFERRED` |
| `DEC-022` | 公开上线/扩大所需的批次效果阈值 | 预注册指标、试点结果和反例 | 保持邀请制 | `G3` | Cross-functional | `OPEN` |
| `DEC-023` | P1 是否允许团队创作者，以及团队主体、分工、责任与付款方式 | 研究、合同、权限、税务和运营演练 | 只允许单一自然人创作者 | `G1` | Product/Legal/Ops | `OPEN` |
| `DEC-024` | P1 是否允许多个付款方/出资方及其退款、票据、对账和授权 | 资金流、provider、合同和财务演练 | 每个项目仅一个获批付款方 | `G1/G2` | Finance/Legal/Product | `OPEN` |
| `DEC-025` | P1 是否允许多个必要签字方，以及签署顺序、拒绝、变更和失效 | 角色矩阵、合同与状态机演练 | 每方仅一个获授权签字人，变更即重签 | `G1/G2` | Legal/Product/Engineering | `OPEN` |
| `DEC-026` | 哪些金额、数据、IP、权力关系或安全信号触发更高级别审查 | 风险分级、专业意见、运营容量和损失上限 | 任一未判定高风险信号即暂停并升级 | `G1` | Risk/Legal/Safety | `OPEN` |
| `DEC-027` | 外部真人研究的责任实体、地域、控制者、同意、补偿、投诉与伦理路径 | 研究协议、数据清单及专业判断 | 仅做 `G0A` 内部准备，不联系真人 | `G0B` | Research/Legal/Privacy | `OPEN` |
| `DEC-028` | 本轮真人研究是否需要独立伦理审查，以及可纳入/必须排除的脆弱或权力依赖群体和停止规则 | 研究协议、招募渠道、伦理/法律书面结论、参与者保护复核 | 未获书面结论不接触真人；默认排除未成年人和无法独立有效同意者 | `G0B` | Ethics/Legal/Research | `OPEN` |
| `DEC-029` | 研究补偿、服务费、创作者报酬、补贴、发票、代扣与跨境款项的税务处理 | 目标辖区税务/会计意见及逐笔资金流 | 不承诺税后金额，不采用未确认的代扣/开票路径 | 补偿 `G0B/使用前`；服务 `G2` | Finance/Tax | `OPEN` |
| `DEC-030` | P1 允许哪些文件/自由文本/消息及内容风险；如何举报、保存证据、通知/报告、限制和申诉 | 内容/网络法律意见、安全威胁模型、运营演练与 `RSK-036` | 未批准类型与高风险内容能力关闭 | 架构 `G1`；能力 `使用前/G2` | Legal/Safety/Product | `OPEN` |
| `DEC-031` | 每类研究、项目、场地、网络和组织风险购买何种保险，或基于何种书面理由不购买 | 经纪/律师意见、损失情景、除外责任、免赔额和补救储备 | 排除无法承受或无法补救的活动 | 风险形成 `使用前`，最迟 `G2` | Finance/Legal/Pilot | `OPEN` |
| `DEC-032` | G2 最小指标包、各指标 Activation/Mode/Classification、阈值与人工/系统采集责任 | 指标目录、隐私评估、工程范围、运营容量和批次预注册 | 采用使命衡量计划的不可删减安全默认；不得以样本小删除事实采集 | `G1` 形成候选，`G2` 批准 | Measurement/Product/Privacy | `OPEN` |
| `DEC-033` | 跳过外部真人研究作为 G1 前置，采用创始人定向、单一场景、假设保持 `E0` 的构建路径 | 项目所有者 2026-08-12 明确指示；[决定备忘](/foundations/g1-direct-build-decision.md)；批准链在 G1 总评审确认 | 不接触真人、不升级证据、不影响 G2；其余 G1 门槛不变 | `G1-02` | Founder sponsor + cross-functional approvers | `CONDITIONAL` |

## 4. 核心假设登记

| Assumption ID | 假设 | 当前等级 | 最便宜反证 | 保留/修改/停止规则 | Owner |
| --- | --- | --- | --- | --- | --- |
| `ASM-001` | 存在一个重复、可验收且有资金的首个问题 | `E0` | 需求方问题/权限访谈 | 无相似触发或无法接触决策/资金则换场景 | Research/Product |
| `ASM-002` | 需求方愿为澄清、核验和保障付费 | `E0` | 明确服务/价格后的采购下一步 | 只接受免费且无转付条件则修改模型 | Business |
| `ASM-003` | 创作者偏好少量合适邀请而非海量投标 | `E0` | 最近项目回放 + 方案测试 | 若认为机会控制更强且无改善则重设发现机制 | Product/Creator Ops |
| `ASM-004` | 双向接受与资金闸门提高信任 | `E0` | 理解测试与合成演练 | 流程负担超过保护且无法简化则停止纵切 | Product/Ops |
| `ASM-005` | 拒绝能在代码、运营和文化中不受惩罚 | `E0` | 派生特征审计 + 真实趋势/访谈 | 发现报复立即暂停并修复/补救 | Ops/Data |
| `ASM-006` | 低规模人工判断可以一致、可审计且可承担 | `E0` | 服务蓝图、工时、双评一致性 | 队列/差异失控则缩小场景，不盲目自动化 | Ops |
| `ASM-007` | 可核验资金/付款路径在目标辖区合法且成本可承受 | `E0` | provider/法律/财务 spike | 无合格方案则不做有偿试点 | Finance/Legal |
| `ASM-008` | 首批项目可避开高风险劳动、数据、IP 和人身场景 | `E0` | 候选 Demand 风险筛查 | 大部分真实需求均高风险则更换 ICP | Legal/Product |
| `ASM-009` | 不以公司化/增长为唯一结果仍有付费价值 | `E0` | 成果路径方案与真实项目选择 | 若所有资金都强迫单一路径则换客户/资金 | Product/Governance |
| `ASM-010` | 收入可覆盖真实运营、权利、安全和风险成本 | `E0` | 每案工时 + downside 预算 | 无可持续路径且不能安全降成本则停止/保持研究 | Finance |
| `ASM-011` | 伙伴能提供密度而不产生强迫或控制 | `E0` | 伙伴条款/参与者独立访谈 | 拒绝不现实或要求控制则不用该伙伴 | Partner/Ops |
| `ASM-012` | 最窄纵切能在简单部署形态下可靠运行 | `E0` | Slice 0 ADR/组合 spike | 若复杂性来自范围过大，先缩范围而非拆服务 | Engineering |
| `ASM-013` | 结构化需求澄清能够减少无偿劳动、无界返工和范围争议，而不是转移更多未付工作 | `E0` | 最近项目回放、澄清/变更/工时与补偿对照 | 若澄清成本超过减损价值或未付劳动增加，则修改服务或停止该收费假设 | Research/Business/Ops |

假设证据按[研究与证据计划](/foundations/research-and-evidence-plan.md)升级；任何假设不得因团队已经写代码、测试通过或创始人依据 `DEC-033` 决定继续而提高置信度。

## 5. 外部依赖登记

`G1` 前为每个依赖填写：

```text
Dependency ID / provider / purpose:
Owner and contract owner:
Data/funds/rights affected:
Legal/security/privacy review:
SLA and actual support route:
Failure/unknown semantics:
Retries/idempotency/limits:
Exit/export/deletion:
Substitute/manual fallback:
Concentration and lock-in:
Incident notification:
Test/sandbox evidence:
Status / expiry / review trigger:
```

至少包括：身份、支付/银行/会计、电子签署、通知、文件/对象存储、恶意内容/病毒处理、监控、云/数据库、研究/转录、客服和外部伙伴。

## 6. 风险与决定评审节奏

- 每次研究轮次：更新假设等级、反例和 ICP 决定；
- 每个 Slice 入口：清理阻断决定、ADR、数据和法律依赖；
- 每个发布候选：重新评估所有 `CRITICAL/HIGH`、失效控制和 provider 变化；
- 每个试点批次：复核 WIP、现金、责任人/替补、合同/Consent/规则版本；
- 任何 SEV-0/重大申诉/数据或付款事件：即时复核相关风险与全部相似流程；
- 每次范围、辖区、资金、数据、AI、伙伴或所有权变化：自动触发相关决定重开；
- 每阶段结束：公开哪些假设被证伪、哪些风险被接受、谁承担剩余风险。

## 7. 单条记录模板

### 风险

```text
Risk ID / title:
Affected people/rights:
Trigger / causal path:
Impact / likelihood / uncertainty:
Current controls and evidence:
Required preventive/detective/recovery controls:
Early indicators and stop threshold:
Owner / reviewer / risk acceptor:
Scope / expiry / review trigger:
Residual risk:
Status and closure evidence:
```

### 决定

```text
Decision ID / question:
Context and affected FND/CAP/PRD/risk:
Affected groups and consultation:
Options including do nothing:
Evidence and uncertainty:
Decision / rationale:
Safety default until effective:
Consequences / migration / consent:
Owner / approvers:
Effective scope/date / expiry:
Review trigger / supersedes:
```

### 假设

```text
Assumption ID:
Claim and current evidence level:
Why it matters:
Cheapest falsification:
Supporting / contrary evidence:
Decision rule:
Owner / next test:
Status / review date:
```

## 8. 当前启动结论

截至本文事实截止日：

- `G0B` 的外部真人研究前置项尚未获批，因此为 `NO-GO`；
- `G1-02` 已依 `DEC-033` 关闭，但 G1 仍存在多个其他 `BLOCKER`，因此生产纵切开发为 `NO-GO — pending G1`；
- `G2` 的真实参与者、真实数据和真实资金为 `NO-GO`；
- P3–P5 制度能力通过保持关闭被控制，不是遗漏；
- 可以立即处理所有 `G1` 阻塞项、重新核验工程事实并用合成数据演练。

下一次状态变化必须由证据和具名批准产生，而不是因时间经过自动发生。
