# 软件交付章程

> 文档状态：P0/P1 工程启动章程草案 v0.1  
> 授权边界：本文不自动授权生产开发。`G1` 前仅允许工程事实核验、已知风险修复、合成数据验证和抛弃式原型；`G1` 通过后才允许按本文范围实现最窄生产纵切。  
> 证据边界：当前工程状态只引用[实现差距审计](/foundations/implementation-gap-assessment.md)的时点记录，本次没有读取或验证代码。开工基线必须重新采集。

## 0. 工程目标

P1 的目标不是完成所有 `CAP-*`，而是交付一条小规模、可关闭、有人负责的真实有偿协作纵切：

```text
身份/授权/Consent
→ Profile + Demand
→ 需求/预算/资金闸门
→ 有限匹配 + 双向接受 + 获授权选择
→ Project + Agreement + Milestone
→ 交付/变更/验收
→ Payment + Reconciliation
→ Outcome/Review
→ 最小举报/申诉 + 数据权 + 审计 + 恢复
```

该纵切服务[产品与首批试点定义](/foundations/product-and-pilot-definition.md)中获批准的单一场景。它不以模块数量、代码行、测试数量或“架构完成度”为成功标准，而以正常、拒绝、故障、申诉和退出旅程是否现实可用为标准。

## 1. 工程原则

1. **先纵切后横向。**不再以完成孤立上下文作为主交付；每个切片都穿过用户入口、权限、事实、持久化、通知、运营、审计和恢复。
2. **先关闭红线再接真实数据。**审计中的 Critical 风险未重新核验并关闭前，相关能力保持关闭。
3. **先保存证据再自动决定。**需求真实性、例外、争议、成果意义和公共价值继续由有权限的人判断。
4. **真实外部状态不靠推断。**身份、资金、付款、外部服务和法律权利来自各自权威来源。
5. **默认失败关闭。**缺配置、密钥、迁移、provider 或权限时拒绝启动/操作，不降级为内存实现或开放权限。
6. **每次扩权同时限权。**新权限必须有作用域、期限、冲突、审计、撤回、申诉和替补。
7. **历史可复现。**规则、协议、决定、Consent、解释和结果使用版本或更正事件，不原地静默覆盖。
8. **退出是主旅程。**删除、导出、取消、付款善后、项目终止和人工接管不是上线后的附属功能。
9. **可访问且可理解。**重要流程不能只由内部命令、数据库或机器错误表达。
10. **保持简单部署。**Capability 是责任边界，不自动等于微服务；拆分需由真实数据所有权、故障隔离或团队责任证明。

## 2. 当前工程基线重采集

正式排期前，在固定、可重建 revision 上完成：

```text
Revision / branch / dirty status:
Dependency lock and runtime versions:
Database/provider/test environment versions:
All test commands and raw artifacts:
Known Critical/High findings and owners:
Schema/migration inventory:
Production composition entry points:
Enabled/disabled capabilities and config:
Secrets/key sources and development substitutes:
Data fixtures and whether any real data exists:
Open incidents / data rights / security obligations:
Reviewer and evidence cutoff:
```

至少重新核验审计中的：

- 完整 Profile 被复制到匹配快照；
- 私密报酬底线可由分项/预算反推；
- 自由文本 PII 与小样本导出；
- 单运营者可无审计改规则、选择和结果；
- 未明确接受仍可被选择；
- 取消 Demand 可重新匹配；
- 付款自报冒充事实；
- 历史决定/Outcome/规则可被静默重解释；
- Schema 重复真相源和指标事实来源错误；
- PostgreSQL 持久 Session 安全红线；
- Matching Selection 未按 attempt/run 隔离；
- 不可达命令、缺失 CompleteSelection 和 production provider/composition。

问题若已修复，记录 revision、测试和复核；若不再适用，说明为什么；不得只从文档删除。

## 3. 获准范围

### 3.1 `G1` 前允许

- 建立 capability/requirement registry；
- 重跑测试、静态/依赖/迁移/权限检查；
- 修复已知数据隔离、会话、匹配作用域和历史完整性问题；
- 使用合成数据建立端到端测试脚手架；
- 形成 ADR、API/事件/数据合同、威胁模型和运行方案；
- 低保真、抛弃式界面/流程原型；
- provider sandbox/spike，但不得创建真实资金或真实用户承诺；
- 能明确删除的测试环境与无敏感数据观测。

### 3.2 `G1` 后、`G2` 前允许

- 实现本文 P1 切片；
- 在开发/测试环境运行合成数据与批准的内部测试账号；
- 对已批准的 provider sandbox 做故障、重放和恢复验证；
- 进行安全、隐私、无障碍和理解测试；若涉及外部真人，只能在另行通过 `G0B` 的研究范围、材料和数据边界内进行，不能借工程测试绕过研究授权；
- 完整桌面演练和发布候选演练。

### 3.3 P1 明确不做

- 正式 Civic Membership、贡献凭证和 Public Office；
- 公共金库、成员议会、正式协作节点自治；
- 成员经济权益、核心资产宪法系统和合法分支；
- 全局声誉分、贡献币、自动成员晋级或自动处罚；
- AI 最终选择、付款/争议/资格决定；
- 开放注册、公开竞价、付费排名和注意力 feed；
- 多辖区、多币种、多 provider、多地域高可用；
- 没有真实需要的微服务拆分、复杂推荐和大规模数据平台。

## 4. 增量纵切

每个切片都必须有可演示的用户/运营旅程和可回滚状态；不允许先完成所有后端再补权利界面。

### Slice 0：事实、风险与交付底座

**交付**：

- requirement/capability registry 和状态失效规则；
- 固定 revision 的测试、安全、迁移和 composition 基线；
- Critical/High 风险登记与处置；
- 开发/测试环境、合成数据、CI 基础门禁；
- ADR 索引、数据分类、访问矩阵和威胁模型；
- 统一决定/审计信封和 correlation；
- release/rollback/backup/restore 最小演练。

**退出条件**：不能通过配置误启用内存/测试适配器；无未处置 Critical；旧审计事实已逐项收敛。

### Slice 1：受控进入、资料与需求

**旅程**：受邀用户完成身份、组织授权、政策/Consent，创建/更新 Profile 或 Demand；运营者核验并给出带理由结果。  
**能力**：`CAP-S01/S02/S03/S04/S06`、`CAP-C01/C02/C03` 最小切片。  
**必须覆盖**：

- 账户、Organization、Participant 和 Consent 分离；
- 登录建立安全 Session；认证后、权限变化后和高风险动作后按策略轮换；支持单 Session、设备族和全部 Session 撤销；
- 恢复流程不复活已撤销凭据；Organization 邀请、接受、移除与账户暂停/关闭分别留证，且移除或关闭不吞掉付款、数据权和申诉；
- 版本、目的限定披露、撤回与后续停止使用；
- Demand 九类角色授权和冲突；
- 生命周期/数据合法性/权限同时校验；
- 私密底线、自由文本 PII、敏感读取与小样本导出控制；
- 拒绝/退回/修改/取消、数据更正/导出入口；
- 运营决定有 actor、理由、规则版本和复核。

### Slice 2：资金闸门、有限邀请与双向选择

**旅程**：合格 Demand 获得资金保障，按固定规则产生有限候选，创作者接受或拒绝，获授权选择者只从已接受候选中完成选择。  
**能力**：`CAP-C04/C06` 与底座证据。  
**必须覆盖**：

- `DEMAND_VERSION` Funding 请求、核实、失败和 `SECURED`；
- 最小匹配快照、抗报酬推断、规则内容 hash 和解释版本；
- run/attempt/tenant 隔离、并发、重放和幂等；
- 邀请 `ACCEPT/DECLINE/WITHDRAW/EXPIRE`；
- 拒绝不作为负面特征，运营策略也不得惩罚；
- 硬边界不能覆盖，软覆盖需要理由和复核；
- CompleteSelection 是可调用、可审计且只引用同 run 的明确命令。

### Slice 3：Project、Agreement、Milestone 与变更

**旅程**：完成选择后创建 Project shell；必要方接受同一协议；里程碑资金满足后开工；交付、拒收、变更和终止均版本化。  
**能力**：`CAP-C05/C07` 与 `CAP-C06` Milestone 切片。  
**必须覆盖**：

- Agreement root/version、必要签字方、授权与最后确认；
- 合同验收和受益者成果确认分离；
- `MILESTONE` Funding 与 Demand 资金语义分离；
- 文件是载荷，不是状态真相源；访问撤回、病毒/内容处理和保留；
- 范围、时间、报酬、成果路径、IP/许可、维护/移交变化重新接受；
- 正常、取消、超时、并发修改、冲突和故障补偿。

### Slice 4：付款、对账、结果与救济

**旅程**：验收触发已授权付款；provider 状态和对账收敛；双方提交情境结果；发生争议/数据请求时得到现实救济。  
**能力**：`CAP-C06/C08/C09`、`CAP-S03/S04/S07`。  
**必须覆盖**：

- 发起、处理中、成功、失败、未知、退款、冲正和对账；
- 付款发起/核实分离和 Safety Hold 最小影响范围；
- provider webhook inbox、幂等、乱序、迟到和重放；
- 财务事实、参与者自报和运营解释分离；
- 评价回应/更正/争议，无全局总分；
- 举报、临时保护、初次决定、独立申诉和补救；
- 访问、更正、限制、删除、导出、legal hold 和第三方权利；
- 通知投递失败不冒充知情。

### Slice 5：真实试点候选与恢复

**旅程**：从浏览器完成正常、拒绝、范围变化、付款未知、争议、数据退出和系统/伙伴故障后的恢复。  
**必须覆盖**：

- 生产 composition、真实 provider 测试环境、迁移和密钥；
- 浏览器/辅助运营、权限化导航、无障碍和错误恢复；
- backup/restore、RTO/RPO 演练、权限撤销和删除水位；
- 运行手册、告警、值班、队列、人工接管和停止试点；
- 法律/合同/运营/财务参与者理解演练；
- `G2` 证据包和独立 go/no-go。

## 5. P1 用例目录

每个用例必须写正常、拒绝、撤回、超时、并发、provider 故障、审计、通知、数据权和申诉中适用的场景。

| Use case ID | 用例 | 主要 actor/authority | 完成事实 |
| --- | --- | --- | --- |
| `UC-P1-001` | 接受邀请并建立作用域 Consent | Participant / self | 当前政策和用途同意可证 |
| `UC-P1-002` | 发布/更新/撤回 ProfileVersion 披露 | Creator / self | 新流程只读取当前获授权版本 |
| `UC-P1-003` | 提交并核验 DemandVersion | Organization + authorized roles | 角色、范围、预算、验收与风险结论 |
| `UC-P1-004` | 请求并核实 Demand 资金 | Payment roles | 权威 `SECURED` 或明确失败/未知 |
| `UC-P1-005` | 运行并解释有限匹配 | Match operator / published rule | 最小快照、固定规则、硬边界结果 |
| `UC-P1-006` | 接受、拒绝、撤回或邀请超时 | Creator / self | 明确 invitation state，无惩罚派生 |
| `UC-P1-007` | 在已接受候选中完成选择 | Authorized selector | 同 run 的 CompletedSelection |
| `UC-P1-008` | 创建 Project 并接受 Agreement | Required parties/signatories | 同版必要确认和历史版本 |
| `UC-P1-009` | 保障 Milestone 资金并开工 | Payment roles + Project | 所需 Funding secured 后状态迁移 |
| `UC-P1-010` | 交付、验收、拒收与成果确认 | Creator + acceptor + beneficiary | 版本化事实与理由 |
| `UC-P1-011` | 提出并接受/拒绝实质变更 | Affected authorized parties | 新协议/里程碑/权利影响版本 |
| `UC-P1-012` | 发起付款并收敛对账 | Initiator + reconciler | provider/账簿最终事实 |
| `UC-P1-013` | 提交情境评价、回应或更正 | Project parties | 事实/观察分离、无总分 |
| `UC-P1-014` | 举报、临时保护、决定与申诉 | Reporter + safety + independent reviewer | 限时相称措施和可执行补救 |
| `UC-P1-015` | 访问、更正、限制、删除或导出 | Data subject + domain owners | 可理解、可验证、分项结果 |
| `UC-P1-016` | 取消/终止/退出并完成善后 | Authorized party / self | 报酬、数据权、申诉和必要记录保留 |
| `UC-P1-017` | provider/系统/伙伴停摆后接管恢复 | Operations + affected participants | 无双付/越权/权利丢失，状态收敛 |
| `UC-P1-018` | 登录并建立、轮换安全 Session | Participant / self + identity provider | 认证上下文和 Session family 可证，旧 token 失效 |
| `UC-P1-019` | 撤销 Session 或设备并完成账户恢复 | Participant / self + separated support | 选定范围失效，恢复不复活旧凭据 |
| `UC-P1-020` | 邀请、加入或移除 Organization 成员 | Authorized organization administrator + invitee | OrganizationMembership 独立变更且不级联吞权 |
| `UC-P1-021` | 暂停或关闭账户并履行善后义务 | Participant / self + obligation owners | 登录关闭，付款、数据权、申诉和必要记录仍可达 |
| `UC-P1-022` | 使用权限化、无障碍产品壳或辅助路径 | Participant + scoped assistant | 导航、动作和替代路径与实时权限一致 |
| `UC-P1-023` | 发送必要事务通知并处理投递失败 | Domain owner + notification service | 站内事实、投递结果和备用路径可证 |
| `UC-P1-024` | 创建、读取、更新、导出或移除项目消息与文件 | Authorized project parties | 版本、扫描、作用域、保留和第三方权利可证 |
| `UC-P1-025` | 查询并验证重大决定、敏感访问和历史审计链 | Authorized auditor + affected subject | actor、authority、版本、理由和 correlation 可复现 |

### 5.1 稳定 PRD、UC 与 CAP 链

以下链是 foundations 侧工程契约；新增 ID 在同步到产品 PRD 前不得复用或改义：

| PRD | Use case | CAP | 范围 |
| --- | --- | --- | --- |
| `PRD-P1-001` | `UC-P1-001`, `UC-P1-018`, `UC-P1-019`, `UC-P1-020`, `UC-P1-021` | `CAP-S01`, `CAP-S04` | Consent、登录、Session 生命周期、组织成员关系、账户关闭 |
| `PRD-P1-015` | `UC-P1-025` | `CAP-S02`, `CAP-S03` | 规则、决定、敏感访问与证据链 |
| `PRD-P1-017` | `UC-P1-022` | `CAP-S06` | 权限化、无障碍 Web BFF 与产品壳 |
| `PRD-P1-018` | `UC-P1-023` | `CAP-S07` | 必要事务通知、失败记录和备用路径 |
| `PRD-P1-019` | `UC-P1-024` | `CAP-C07` | 项目消息、文件、扫描、作用域、保留和导出 |

### 5.2 逐项可核验验收实例

下表每个单元格都是最低可执行断言，不是主题提示。实现时须为所列正常、异常、权限、数据权和救济路径建立具名测试或运营演练；标记“不适用”的维度也给出理由。省略某维度视为用例未 Ready。

| UC | 正常完成与后置断言 | 异常、并发和外部失败断言 | 权限与越权断言 | 数据权、保留和第三方权利断言 | 申诉、纠正或不适用理由 |
| --- | --- | --- | --- | --- | --- |
| `UC-P1-001` | 给定未过期邀请和当前政策，Participant 明示同意后只建立该目的和作用域的 Consent；证据含 policy version、purpose、actor、time。 | 过期、已撤销或重放邀请拒绝；拒绝 Consent 不创建 Participant 权限，通知失败不改变同意事实。 | 仅受邀主体可同意；Organization 管理员不能代同意，代理仅在 `UC-P1-022` 的书面范围内操作并记录真实 actor。 | 只保留证明同意所需字段；访问、更正、限制、删除和导出转入 `UC-P1-015`，撤回后新处理停止。 | 拒绝或撤回不得降级站外待遇；错误绑定可申诉并更正，不改写原证据。 |
| `UC-P1-002` | 发布新 ProfileVersion 后，匹配只读当前获授权字段；撤回后新 run 不得读取旧披露。 | 非法字段、版本冲突和并发更新返回明确错误；已开始 run 只引用固定最小快照，不静默换版。 | 仅 Creator 或明确授权的数据 steward 可提交；任何运营者都不能覆盖私密底线和禁止用途。 | 每字段有目的、可见范围和期限；删除使用稳定索引与可删载荷分离，第三方内容不得随主体导出。 | 拒绝发布须给字段级理由；Creator 可更正、撤回或申诉，历史以更正事件保留。 |
| `UC-P1-003` | 九类角色、范围、预算、验收、受益者和风险字段齐全且授权有效时，DemandVersion 进入已核验状态并冻结版本。 | 缺角色、预算不合法、受益者冲突、过期核验或并发改版均不得进入匹配；退回给出逐字段理由。 | 提交者、付款者、选择者、验收者和受益确认者分别校验；Organization 身份本身不授予任一角色。 | 自由文本和敏感字段最小化；角色仅见必要字段；版本按合同和争议期限保留并支持主体权利请求。 | 提交方可针对退回理由更正或申诉；不适用的候选不因申诉而自动进入匹配。 |
| `UC-P1-004` | 只有权威 provider 或核实账簿将对应 `DEMAND_VERSION` 标为 `SECURED`，并保存金额、币种、provider ref、核实 actor。 | 重复请求幂等；超时或未知保持 `UNKNOWN` 且禁止匹配；迟到事件按顺序收敛，不把请求或截图当付款事实。 | 资金发起者与核实者分离；无核实权限者不能写 `SECURED`，跨租户 ref 被拒绝并告警。 | 仅保存必要 provider 引用和账务字段；支付主体可访问相关记录，法定保留覆盖删除时给出分项理由。 | 未知、失败或错误归属进入财务复核；可申诉并补救，但不能手工伪造成功状态。 |
| `UC-P1-005` | 给定固定 DemandVersion、规则 version 和最小 Profile snapshot，同 run 产生有限候选、解释与 content hash，硬边界全部满足。 | 无候选、规则不可用、重复执行、并发 run 或快照缺失时不产生可选择结果；同 idempotency key 返回同结果。 | 只有发布规则允许的 operator 可运行；人工不能硬覆盖边界，软覆盖须新决定、理由和 reviewer。 | 快照不含完整 Profile 或可反推私密底线的组合；删除和限制通过可删载荷处理，保留最小决定索引。 | 候选可质疑数据或规则应用；更正触发新 run，不原地改旧结果。 |
| `UC-P1-006` | Creator 可接受、拒绝、撤回；到期自动为 `EXPIRED`，每次转换记录 actor、time、invitation version，且拒绝不产生负面特征。 | 重放、迟到接受、并发接受与撤回按版本拒绝或确定性收敛；通知失败不延长或缩短已公布期限。 | 只有受邀 Creator 可响应；运营者不能代接受，代理操作须有限授权且可撤回。 | 拒绝理由默认可选且私密；只保留运行和反报复所需证据，导出过滤其他候选信息。 | Creator 可报告强迫或报复；补救不要求披露拒绝理由，也不自动承诺被选择。 |
| `UC-P1-007` | Authorized selector 只能从同 run、当前明确 `ACCEPTED` 候选完成一次 CompletedSelection，并记录规则和候选快照。 | stale run、已撤回候选、重复选择、跨 run 或并发完成均拒绝；失败不留下半完成 Project。 | 仅 DemandVersion 指定且当前有效的 selector 可选择；operator、付款者或客户身份不自动获得权限。 | 选择证据仅保留必要 candidate ref 和理由；未选者数据不扩散，删除和访问按来源域处理。 | 候选可对数据错误、歧视或程序冲突申诉；独立复核不能静默替换历史选择。 |
| `UC-P1-008` | Project 创建后，所有必要签字方对同一 AgreementVersion 明示接受，记录授权、时间和最后确认；旧版本只读。 | 缺一方、签字权过期、版本变化、重复签署或并发变更不得使协议生效；通知失败不冒充签收。 | 每个 signatory 在确认时重新校验；Organization 管理员不当然拥有签约权，系统操作者不能代签。 | 合同及必要证据按法定期限保留；访问限当事人和合法审查者，附件权利由 `UC-P1-024` 处理。 | 对错误、强迫或异版可争议并暂停后续不可逆动作；纠正生成新版本，不覆盖旧签署。 |
| `UC-P1-009` | 对应 `MILESTONE` Funding 经权威核实为 `SECURED` 后，Project 才迁移为可开工，并记录 milestone、金额和 provider ref。 | 未知、失败、重复 webhook、迟到退款或并发开工请求均不得越过资金闸门；状态最终可对账收敛。 | 发起、核实和项目开工权限分离；仅当前 Project 和 Milestone 可消费该资金事实。 | 保存最小账务引用；参与方能访问自身里程碑资金状态，法定保留和删除冲突逐项解释。 | 错误冻结或资金归属可走财务复核；补救含恢复、退款或明确无法开工，不能伪造 `SECURED`。 |
| `UC-P1-010` | Creator 提交 DeliveryVersion，authorized acceptor 接受或带理由拒收，beneficiary 独立确认 Outcome；各事实版本化。 | 缺文件、恶意内容、超时、重复验收、并发新交付或 provider 不可用时保持可恢复状态，不自动接受。 | Creator、acceptor、beneficiary 权限分别校验；任何一方不能代替另一方确认，运营越权被拒并审计。 | 文件按 `UC-P1-024` 控制；验收理由最小化，支持访问、更正和合法保留，第三方材料不随主体导出。 | 拒收须可回应和再次提交；合同争议走 `UC-P1-014`，纠正保留原决定链。 |
| `UC-P1-011` | 受影响各方对同一 ChangeVersion 接受后，范围、时间、报酬、成果路径、许可和里程碑一起生效。 | 任一方拒绝、超时、签字权失效、stale base version 或并发变更时旧协议继续有效；无部分静默更新。 | 只有受影响且获授权方可提议和接受；不得用运营权限或付款权绕过另一方同意。 | 变更版本、理由和必要附件按合同期限保留；敏感讨论最小披露，第三方许可不得被未授权改变。 | 拒绝变更不得受罚；可对强迫、错误影响分析或权限冲突申诉，补救生成新版本。 |
| `UC-P1-012` | 验收和授权条件满足后发起 Payment；provider inbox、内部账簿和对账最终一致为成功、失败、退款或冲正。 | 重复、乱序、迟到、timeout、`UNKNOWN`、退款和冲正均幂等收敛；未知期间不得再次盲付。 | 发起者与 reconciler 分离；跨 Project、金额或收款方篡改被拒绝，手工调整需双人批准。 | 只保存必要支付引用和账务证据；支付主体可访问，法定保留优先时给删除请求分项结果。 | 错付、少付、未知或延迟有财务申诉、调查时限和补偿路径；历史不因调整而消失。 |
| `UC-P1-013` | 项目方提交带情境和证据来源的 Outcome 或 Review，被评价者可回应和更正；界面不计算全局总分。 | 空泛、越界、重复、并发更正或含禁用敏感内容时拒绝或进入审核；删除通知失败不恢复内容。 | 仅相关 Project 方在规定窗口提交；不得购买、转让或由运营者伪造评价，查看权限按情境限制。 | 显示时间和项目背景；支持更正、删除分层和选择性导出，不暴露其他参与者私密数据。 | 被评价者可回应、争议和请求独立复核；处理结果以附加事件纠正，不静默改写。 |
| `UC-P1-014` | Reporter 可安全提交；需要时实施最小限时保护；初次决定含证据和理由；无冲突 reviewer 完成独立申诉与补救。 | 紧急、证据不足、超时、重复案件、并发措施、通知失败或 reviewer 冲突均有明确状态和人工接管，不无限暂停。 | reporter、respondent、case handler、decider、appeal reviewer 分权；越权读取和自我复核被拒并告警。 | 只收集必要证据，敏感访问留痕；legal hold、保留、删除、第三方权利和安全披露逐项决定。 | 本用例本身即申诉链；补救可恢复权限、纠正记录、补偿或说明无法恢复，且不抹去原始决定。 |
| `UC-P1-015` | 经身份校验后，系统按数据域返回访问、更正、限制、删除或可接收导出的分项结果、证据和期限。 | 身份无法确认、provider 失败、legal hold、第三方冲突、备份水位或并发新数据均形成明确分项状态，不假报完成。 | 仅数据主体或有证据的法定代理可请求；domain owner 只能处理本域，批量越权和租户穿透被拒。 | 本用例覆盖完整数据权；导出验证完整性和接收性，删除区分稳定索引、可删载荷、备份和合法保留。 | 对拒绝、遗漏、超时或格式不可用可投诉升级；纠正保留处理证据且不泄露第三方。 |
| `UC-P1-016` | 获授权方取消或终止后，项目状态关闭，未付报酬、退款、数据权、申诉和必要记录分别进入可完成队列。 | 活跃付款、争议、legal hold、未交付资产或并发验收时不得假报完成；给出每项 pending owner 和期限。 | 仅合同授权方可终止 Project；Participant 退出不允许单方抹去他方权利或账务义务。 | 执行访问撤销、导出和删除编排；合同、支付、申诉及第三方材料按各自期限保留并说明。 | 可争议终止理由、费用和数据处置；补救含恢复访问、付款、退款或纠正状态，退出不降低申诉权。 |
| `UC-P1-017` | 演练 provider、数据库或伙伴停摆时，人工账簿和接管程序维持最低权利；恢复后无双付、越权或状态分叉。 | 未知结果、重复消息、备份失败、密钥失效、伙伴无响应和恢复并发均停在安全状态并触发升级。 | break-glass 权限有范围、双人批准、时限和完整审计；恢复后自动撤销，不成为长期后台权限。 | 人工账簿只含最小必要数据；恢复验证保留、删除水位和第三方义务，不把生产数据带入非生产。 | 受影响者可报告损失并获得状态说明、纠错和补偿评估；技术恢复不自动关闭申诉。 |
| `UC-P1-018` | 正确认证和风险检查后建立服务端 Session family；登录、权限变化和高风险动作按策略轮换，旧 session token 立即无效。 | 错误凭据、CSRF、token replay、IdP timeout、轮换并发或写入未知均失败关闭；不得降级为长期 token 或内存 Session。 | 仅认证主体建立 Session；每次请求重校租户和权限，后台或跨租户 cookie 被拒并记录安全事件。 | 仅保留安全所需认证元数据、设备标签和期限；主体可查看及撤销活动 Session，敏感凭据不进入导出或日志。 | 错误锁定可走账户支持和安全复核；不适用普通业务申诉，但必须有纠错、恢复和安全事件投诉。 |
| `UC-P1-019` | 主体撤销单 Session、设备族或全部 Session 后，所选范围立即失效；恢复完成新认证且不复活旧 refresh token。 | 撤销与刷新竞态、已盗 token 重放、恢复证明冲突、IdP 未知或支持队列超时均保持旧凭据失效并升级。 | 自助撤销需当前认证；高风险恢复使用 step-up 和分权支持，支持人员不能查看凭据或绕过恢复证据。 | 撤销、恢复和安全事件仅留最小审计元数据；保留期明确，主体可访问活动历史并请求纠正设备标签。 | 主体可投诉错误撤销或恢复拒绝；补救只签发新凭据，不恢复被撤销链，必要时独立安全 reviewer 复核。 |
| `UC-P1-020` | 当前 authorized organization administrator 发邀请，invitee 明示接受后创建独立 OrganizationMembership；移除只终止该 OrganizationMembership。 | 邀请过期、重复接受、并发移除、管理员权限撤回或通知失败不得生成幽灵成员；操作确定性收敛。 | 只有明确组织管理员可邀请或移除；采购、付款、平台运营和普通参与身份不自动授权，管理员不能代接受。 | 最小保留邀请和 OrganizationMembership 证据；移除后组织访问撤销，但个人付款、数据权、项目和申诉记录按各域处理。 | 被错误移除者可挑战权限和事实；补救可恢复 OrganizationMembership 或提供站外权利路径，但不能静默删除原移除记录。 |
| `UC-P1-021` | 主体经 step-up 暂停或关闭账户后，登录和新业务动作关闭；余额、付款、导出、删除、案件和申诉仍由专用路径完成。 | 活跃合同、未知付款、legal hold、开放案件、身份恢复冲突或并发登录时给出分项 pending，不宣称全量关闭。 | 仅主体或有证据法定代理可关闭；运营者只能按有期限决定暂停，不能借关闭逃避付款或数据义务。 | 触发各域删除、导出和保留编排；逐项说明合法保留、备份水位、第三方权利和最终删除时间。 | 主体可更正误关、申请恢复允许恢复的访问或申诉强制暂停；恢复不得复活旧 Session 或已撤销授权。 |
| `UC-P1-022` | 浏览器和辅助技术下，导航与动作随实时权限显示；键盘、屏幕阅读器、清晰语言和获批辅助路径均能完成同等关键旅程。 | stale permission、离线、Session 过期、辅助者撤回、前端缓存或 BFF timeout 时隐藏敏感数据并提供可恢复错误，不猜测成功。 | BFF 是单一授权边界；前端不可自创权限，代理仅在范围和时限内操作且记录真实 actor，禁止共享密码。 | 界面不建立影子 PII；辅助者仅见必要字段，缓存和可观测数据遵守来源域保留及主体权利。 | 无障碍或数字排除可投诉并获人工替代；业务决定的申诉转相应用例，辅助失败不缩短不可逆期限。 |
| `UC-P1-023` | 必要事务事件生成站内事实记录并向正确接收者发送最小内容；保存模板 version、recipient scope、provider result 和 fallback。 | bounce、延迟、重复、乱序、provider outage 或错误地址不冒充知情；按规则重试并转人工或批准备用通道。 | 只有来源域授权事件可触发模板；接收者和租户作用域重校，运营者不能任意群发或查看敏感正文。 | 通知只含完成动作所需最小信息；偏好不屏蔽法定必要通知，保留、删除及第三方 provider 退出可执行。 | 投递失败不得启动不可逆期限；受影响者可更正地址、补收通知并申请恢复期限或业务补救。 |
| `UC-P1-024` | 授权项目方可创建、读取、更新、导出或移除 MessageVersion 与 FileVersion；扫描通过后才可用，所有对象绑定 Project 和 AgreementVersion。 | 病毒或内容扫描失败、隔离、stale upload、重复 chunk、存储未知、并发改版或撤权时拒绝发布并可恢复。 | 读写权限按 Project 角色和当前 OrganizationMembership 重校；分享链接有范围与期限，移除成员后立即失效，平台运营无默认内容访问。 | 定义保留、导出、删除、legal hold、第三方著作权和消息参与者权利；审计只存对象 ref，不复制敏感载荷。 | 对错误隔离、移除、访问拒绝或侵权可申诉；补救可恢复版本、提供导出或永久移除，并保留决定链。 |
| `UC-P1-025` | 对任一重大决定或敏感访问，按 correlation 重现 actor、authority、scope、输入版本、规则 hash、理由、结果和后续更正。 | 缺事件、hash 不符、版本不存在、顺序冲突、存储不可用或恢复断链使 Gate 失败并阻止发布，不以日志猜测。 | 仅有范围的 auditor 和受影响主体可查看相应投影；审计管理员不能改历史，break-glass 读取本身再次留证。 | 不可变索引与敏感可删载荷分离；访问、保留、legal hold、删除和第三方权利按字段及域执行。 | 主体可要求纠正事实或复核决定；纠正追加事件且可恢复权益，不能重写原记录；普通审计读取无独立业务申诉时说明所关联决定的救济入口。 |

### 5.3 用例编写模板

后续细化合同与测试时沿用以下字段；模板不能替代上面的逐项实例。

```text
Use case / version:
FND / CAP / PRD references:
Actors and authority:
Preconditions and source versions:
Trigger:
Happy path:
Decline / withdraw / timeout:
Authorization denial:
Conflict / concurrency / replay:
External unknown / failure:
Postconditions and invariants:
Notifications and delivery failures:
Audit / decision evidence:
Data rights / retention / third-party rights:
Appeal / remedy:
Examples and property tests:
Operational handoff:
Owner / reviewer / approval:
```

## 6. 领域与接口合同最低要求

### 6.1 领域责任

每个聚合/能力明确：

- 拥有什么事实、不拥有什么事实；
- ID、租户/公共作用域和受影响主体；
- 命令 actor、authority 和同步资格检查；
- 状态转换、前置条件、不可变条件和终态；
- 幂等、并发、顺序、重试、超时、未知和补偿；
- 事件消费者不能直接写来源域；
- PII/敏感类别、最小事件载荷、保留/更正/删除；
- 规则/Consent/协议/章程版本；
- 审计、通知、运营和申诉责任。

### 6.2 API/命令/事件目录字段

```text
Contract ID / version / status:
Producer / consumer / source of truth:
Actor / authority / scope:
Request/event schema:
Data classification:
Idempotency / ordering / deduplication:
Success / denial / validation / conflict / unknown errors:
Timeout / retry / backoff / dead-letter:
Compensation and convergence:
Audit / correlation / policy refs:
Compatibility / deprecation / migration:
Owner / approver / tests:
```

Schema、手写 validation、OpenAPI、模板和领域模型只能有一个权威源或自动等价验证。

## 7. 架构决定队列

以下决定在 Slice 0 关闭，不能由实现者临时选择。默认建议只用于比较，不是当前事实：

| ADR ID | 必须决定 | 候选安全默认 | 关键验收 |
| --- | --- | --- | --- |
| `ADR-P1-001` | 部署与模块形态 | 模块化单体 + 明确 bounded contexts | 事务/权限清楚，可独立演进，不提前微服务化 |
| `ADR-P1-002` | 租户、Participant 与 RLS | 数据库强制租户/主体隔离 | 连接池、后台任务、迁移、恢复均不能绕过 |
| `ADR-P1-003` | 身份 provider 与 session | 外部可信 IdP + 服务端安全 session | 重放、轮换、撤销、CSRF、恢复和未知结果闭合 |
| `ADR-P1-004` | 资金保障与支付 provider | 目标辖区合格 provider | 不自行托管；webhook/对账/退款/冲正可证明 |
| `ADR-P1-005` | Web/BFF 与辅助运营 | 单一授权边界，前端不重写权限 | 浏览器、无障碍、代理授权和错误恢复 |
| `ADR-P1-006` | 文件/消息 | 受控对象存储与最小消息边界 | 病毒、权限撤回、保留、导出和第三方权利 |
| `ADR-P1-007` | 事件与异步边界 | transactional outbox/inbox | 顺序、幂等、未知、重放、恢复和可观测 |
| `ADR-P1-008` | 决定/审计完整性 | 结构化决定 + 最小不可变索引 | 敏感载荷分层、更正/删除与历史可复现 |
| `ADR-P1-009` | 规则/Schema 版本 | 签名/哈希的不可原地改写版本 | 旧决定可复现、变更可影响模拟与回滚 |
| `ADR-P1-010` | 数据驻留/供应商 | 单一获批区域、最少供应商 | 合同、加密、保留、跨境和退出明确 |
| `ADR-P1-011` | 通知 | 站内真相投影 + 事务备用通道 | 投递失败、偏好、敏感最小化和回执 |
| `ADR-P1-012` | AI | P1 默认关闭 | 关闭不会破坏主旅程 |

ADR 至少包含上下文、备选、决定、理由、后果、可逆性、威胁、迁移、owner、批准者、证据和复审触发。

## 8. 非功能需求与质量目标

具体数值由批次规模、法律义务和团队容量在 `G1` 填写；未填不能通过 `G2`。

| NFR ID | 主题 | P1 必须定义/验证 |
| --- | --- | --- |
| `NFR-001` | 安全 | 威胁模型、最小权限、RLS、会话、加密、secret、依赖、审计和事件响应 |
| `NFR-002` | 隐私 | 数据清单、用途、访问、保留、删除、导出、provider、再识别和推断 |
| `NFR-003` | 资金正确性 | 幂等、双人控制、未知收敛、对账、退款/冲正、账簿一致 |
| `NFR-004` | 历史完整性 | 协议/规则/决定/Consent/Outcome 版本化和旧流程重演 |
| `NFR-005` | 可用性 | 用户旅程与运营队列 SLO、计划停机和外部依赖降级 |
| `NFR-006` | 恢复 | RTO/RPO、备份、恢复、删除水位、密钥/权限和 provider 重连 |
| `NFR-007` | 性能/容量 | 批次/并发/载荷目标、最坏请求、后台积压和成本上限 |
| `NFR-008` | 可访问性 | 目标标准、键盘/屏幕阅读器/对比/清晰语言、非数字/辅助路径 |
| `NFR-009` | 兼容性 | 支持浏览器/设备/语言、Schema/API/事件兼容和迁移窗口 |
| `NFR-010` | 可观测 | 业务/安全/资金/权利 SLI、correlation、敏感抑制、告警与审计 |
| `NFR-011` | 可维护性 | 模块边界、owner、迁移、依赖、文档、runbook 和变更回滚 |
| `NFR-012` | 成本 | 每项目/用户/文件/通知/provider 的成本预算与异常告警 |

任何数值目标都记录依据、测量位置、样本、负责人、失败动作和复审触发，不能从通用最佳实践复制。

## 9. 测试策略

### 9.1 测试层

- 规范/contract：每项 P1 `FND/PRD/UC` 到契约、错误和事件；
- 领域 property：状态转换、不变量、硬边界、拒绝、版本与资金语义；
- 应用：幂等、权限、冲突、超时、未知和补偿；
- PostgreSQL：事务、并发、唯一约束、RLS、连接池、ACL、迁移与恢复；
- HTTP/BFF：真实 session、CSRF、输入、授权、错误、隐私和内容类型；
- provider contract：身份、支付、通知、文件等 sandbox/仿真和真实失败语义；
- 浏览器 E2E：正常、拒绝、撤回、范围变化、付款未知、申诉、数据权和恢复；
- 安全/滥用：越权、重放、推断、批量访问、文件、提示/内容和日志泄漏；
- 无障碍/理解：辅助技术和参与者能否复述关键状态与权利；
- 恢复：备份、数据库/provider 故障、重复消息、密钥轮换、删除水位和人工接管；
- 运营演练：队列、回避、双人控制、事件、申诉和停止试点。

### 9.2 测试数据

- 默认合成、可公开、可整体删除；
- 不复制真实参与者资料到开发、测试、日志或分析；
- 安全测试中的伪敏感值明确标识，不能触发真实通知/付款；
- provider sandbox 账号与生产隔离；
- 数据构造覆盖第三方权利、撤回、legal hold、删除和小样本；
- 若必须使用经批准真实数据，单独环境、最小字段、期限、审计和书面批准。

### 9.3 CI/合并门禁

至少包括：

- 格式/静态/类型/依赖/secret/Schema 等价检查；
- 相关单元、property、contract、PG/RLS 和 migration 测试；
- 安全/隐私回归和敏感输出扫描；
- 变更的 FND/CAP/PRD/UC/ADR/风险/迁移/runbook 链接；
- 不允许跳过失败测试后仍标记可发布；
- flaky、quarantine 和已知失败有 owner、到期和不能覆盖的发布级别；
- 生成可归档、绑定 revision 的测试证据。

## 10. Definition of Ready

一个 backlog 项只有同时满足才进入实现：

- 属于获批准 P1 场景和切片；
- 有一个可识别的受益者问题和非目标；
- 枚举精确 `FND-*`、`CAP-*`、`PRD/UC`；
- actor、authority、前置状态、数据和外部事实源清楚；
- 正常、拒绝、撤回、超时、并发、故障、申诉和退出中适用路径清楚；
- 不变量、错误、通知、审计、保留和第三方权利清楚；
- 安全/隐私/法律/运营风险及 owner 清楚；
- 验收示例和测试层清楚；
- 依赖 ADR/contract 已批准；
- rollout、rollback、feature flag 和人工接管清楚；
- 无阻断 `TBD`。

## 11. Definition of Done

“代码完成”不是 Done。至少需要：

- 契约、领域、应用、真实 PG、HTTP、composition 和必要 browser/provider 测试通过；
- 正常、拒绝、故障、申诉和退出中适用旅程有证据；
- 权限、RLS、数据分类、保留/删除、日志/指标最小化通过复核；
- 迁移、回滚、重复执行、恢复和旧版本兼容验证；
- UI/通知可理解、可访问，失败不隐藏；
- 告警、dashboard、队列、runbook、培训和 owner 到位；
- 风险登记更新，残余风险由有权限者接受且有期限；
- capability registry 绑定 revision、证据日期和状态层；
- 产品、工程、运营、安全/隐私及必要法律/财务角色共同验收；
- 在真实运行前仍需单独 `G2`，Done 不自动等于 Enabled/Effective。

## 12. 环境、发布与回滚

### 12.1 环境

至少区分：local、CI、integration、pilot/staging、production。每个环境明确数据类型、provider、密钥、访问、保留、网络、迁移和可否发送真实通知/付款。生产不允许自动回退到测试 provider、开发密钥或内存仓库。

### 12.2 发布计划字段

```text
Release ID / revision:
Capabilities and status layers:
Feature flags / cohort / batch cap:
Schema and data migrations:
Config/secrets/provider changes:
Backward/forward compatibility:
Pre-deploy backup/checkpoint:
Smoke and journey tests:
Monitoring and stop signals:
Manual fallback:
Rollback code/data/provider procedure:
Rights/payment obligations during rollback:
Owners / approvers / communication:
Evidence archive and review date:
```

不可逆数据迁移、合同/Consent 版本和外部付款操作不能假装通过回滚代码自动撤销；必须有前向修复和参与者补救。

### 12.3 发布停止信号

- 认证/租户/RLS/作用域异常；
- 资金、付款、重复操作或对账未知超过批准阈值；
- 匹配跨 run/tenant、私密底线推断或全量 Profile 泄漏；
- 协议/规则/决定/Consent 历史不可复现；
- 应付报酬、数据权、举报或申诉不可达；
- 关键通知失败且没有替代；
- 错误/积压超过批准容量；
- 运营或法律负责人要求暂停。

## 13. 可观测性与运行证据

必须观察业务事实而不泄漏敏感内容：

- 身份/Consent/权限拒绝与异常；
- Demand 审核、资金、邀请、接受/拒绝、选择和项目状态；
- 协议/里程碑/变更版本；
- 付款请求、未知、失败、对账、退款与冲正；
- 举报、Safety Hold、决定、申诉和时限；
- 数据权请求、provider/备份任务和完成；
- 队列积压、通知失败、重试/dead letter；
- 拒绝后机会、人工覆盖、集中度和小样本抑制；
- 备份、恢复、权限撤销和删除水位。

日志/指标不保存私密底线、文件正文、完整 Profile、支付凭证、举报正文或不必要的个人标识。异常触发调查，不自动判定参与者作弊或降低机会。

## 14. 交付治理

### 14.1 决策权

| 事项 | 提出 | 必须批准 | 可暂停 |
| --- | --- | --- | --- |
| P1 范围/优先级 | Product/Delivery | Product + Ops + Engineering | 任一负责角色发现越界可提阻断 |
| 架构/数据合同 | Engineering | Engineering + Security/Privacy + affected owner | Security/Privacy/Operations |
| 资金/支付 | Finance/Engineering | Finance + Legal + Security + Product | Finance/Legal/Security |
| 数据用途/AI | Product/Research | Privacy + Legal + affected owner | Privacy/Security |
| 安全/争议 | Ops/Safety | Safety + Legal as required | Safety/Security |
| 生产发布 | Delivery | Product + Engineering + Ops + Security/Privacy + Finance/Legal as applicable | 上述任一职责内阻断者 |

### 14.2 变更控制

范围、辖区、参与者、支付、数据、合同、AI、provider、成果风险或批次上限变化时：

1. 记录决定与受影响主体；
2. 更新 FND/CAP/PRD/UC/ADR/风险；
3. 评估 Consent/合同/数据迁移和重新同意；
4. 判断是否退回 `G1/G2`；
5. 更新测试、runbook、发布与停止条件；
6. 旧项目继续引用旧版本，除非依法且经必要方同意迁移。

## 15. 排期原则

本目录没有团队人数、容量、预算、provider 采购周期或外部审查时间，不能负责任地产生日历工期。通过 `G1` 后，估算按每个纵切的：未知决定、外部依赖、迁移、安全证明、运营培训和恢复证据共同进行，不只估算编码时间。

任何日期承诺都必须注明：团队容量、非工程依赖、风险缓冲、批准门槛和不包含范围。为守日期而删除数据权、申诉、付款正确性、恢复或职责分离不属于可接受范围调整。

## 16. P1 工程完成判定

P1 只有在以下全部成立时才可称为“试点候选”，而非“foundations 已实现”：

- 所有 P1 用例和 `PRD-P1-*` 有可追踪证据；
- 无未处置 Critical，High 有经演练、到期的控制和关闭计划；
- 正常、拒绝、范围变化、付款未知、争议、数据权和恢复旅程通过；
- 真实 provider/数据库/浏览器/生产 composition 不依赖测试 double；
- 运营、法律、财务、隐私和安全手册已与软件共同演练；
- `G2` 独立评审通过并限定批次、数据、资金和功能；
- 对外只声明当前能力状态，不宣称成员治理、共同所有或制度效果。

软件开发的第一责任，是让一段受控协作可以真实、可逆且可救济地发生；不是把 foundations 的全部未来结构提前写进代码。
