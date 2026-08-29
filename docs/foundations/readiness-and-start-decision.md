# 软件开发启动就绪度与决策入口

> 文档状态：启动决策基线草案 v0.2
> 评估日期：2026-08-12
> 证据边界：本结论严格只依据 `docs/foundations/` 内现有材料，未重新检查代码、测试、外部市场、法律、财务、团队或真实用户事实。被引用的代码审计事实仍以[实现差距审计](/foundations/implementation-gap-assessment.md)记录的审计时点为限。
> 决策规则：未知事实一律记为 `TBD`，不得用推测、样例、设计稿或测试替代真实证据。

## 0. 结论先行

截至本评估日，愿作已经拥有较完整的价值原则、制度边界、目标能力地图和分阶段路线，但**尚未满足面向真实用户、真实个人数据和真实资金开发生产产品的启动条件**。

当前可以启动的工作与不能启动的工作应分开判断：

| 工作类型 | 当前结论 | 边界 |
| --- | --- | --- |
| P0 内部工作坊、桌面研究、流程演练、责任分工、合同与数据准备 | `GO` | 仅使用公开信息、现有获授权材料或合成数据，不接触外部研究参与者 |
| 外部真人访谈、观察或研究招募 | `NO-GO（待 G0B）` | 只有 `G0B` 全部通过后，才可按获批研究协议和独立研究库处理联系人、录音、补偿或案例资料 |
| 使用合成数据的抛弃式原型、领域探索、测试夹具和风险验证 | `GO` | 不接触真实个人数据、真实付款或真实权益决定；不得冒充生产能力 |
| 修复已知安全红线、建立能力登记册和可复现工程基线 | `GO` | 开工前须重新核验代码事实，不能沿用过期审计数字 |
| 最窄生产纵切的正式实现 | `NO-GO（待 G1）` | `DEC-033` 已关闭真人研究前置，但其余 G1 项仍须通过；整体通过后才可按[软件交付章程](/foundations/software-delivery-charter.md)限定范围启动 |
| 邀请真实服务/付费试点参与者、把真实资料导入产品、签约、收款或付款 | `NO-GO（待 G2）` | 需通过 `G2` 的产品、运营、法律、数据、财务和工程门槛；研究参与者不因此成为服务试点参与者 |
| 公开注册、开放市场、正式成员治理、公共金库或所有权机制 | `NO-GO` | 分别依路线图 P2–P5 的真实证据激活，不能提前包装上线 |

因此，“距离启动软件开发还有多远”不能用一个工期回答，而应按门槛回答：

- 距离**不接触真实数据/资金/权益的准备性开发**：没有门槛，可以立即开始；
- 距离**最窄生产纵切**：`G1` 当前仍为 `NO-GO`；`G1-02` 已依[创始人定向构建决定](/foundations/g1-direct-build-decision.md)关闭，但其余 `TBD` 仍须变成可复核证据并获具名批准；
- 距离**封闭付费试点**：还差 `G1 → G2` 两级门槛以及至少一次不接触真实资金的全流程演练；
- 距离**公开上线**：当前证据不足以估计，不应给出日期或百分比。

## 1. 为什么当前不能直接进入宽泛开发

现有 foundations 对“为什么做”“不得伤害什么”“完整目标系统包含什么”回答得很强，但启动一支软件团队还需要回答另外一组更窄、更现实的问题：

1. 首批服务谁、解决哪一种高频且可付费的问题；
2. 为什么相信双方真的需要这项服务，而不是只认同理念；
3. 首批项目的明确包含项、排除项和停止条件；
4. 人工服务如何运行，谁核验需求、冲突、付款、申诉与数据权；
5. 在哪个辖区、由哪个实体、用什么合同和支付路径承担责任；
6. 价格、成本、人员、现金和获客假设是否允许安全完成一次试点；
7. 哪些用户旅程与验收条件构成首个可交付纵切；
8. 谁能批准上线、谁能暂停、谁负责事件和独立复核。

缺少这些答案时，直接开发会让团队在代码里默默选择产品、法律和组织默认值，重演[实现差距审计](/foundations/implementation-gap-assessment.md)指出的“横向基础很深、纵向产品不通”。

## 2. 当前就绪度矩阵

状态只表达本文证据边界内的判断：

- `GREEN`：已有足够清晰的规范基线，可以进入下一步验证；
- `AMBER`：有较强草案，但缺批准、现实证据或可执行细节；
- `RED`：缺少启动所需的核心决定或证据；
- `UNKNOWN`：必须检查本目录之外的事实，本次没有检查。

| 维度 | 状态 | 已具备 | 启动缺口 |
| --- | --- | --- | --- |
| 使命、社会契约与禁止结果 | `GREEN` | 社会契约、经济宪法、成员与开放原则、稳定 `FND-*` | 尚未由真实成员批准；可先作为创始试点约束 |
| 完整目标能力与阶段依赖 | `GREEN` | `CAP-*` 能力地图、P0–P5 激活顺序 | 不能把完整目标地图当首版范围 |
| 首个目标用户与问题场景 | `RED` | 有“需求方/创作者/受益者”等角色语言 | 没有获批的 ICP、单一场景、替代方案与排除范围 |
| 真实问题与付费意愿证据 | `RED / G1 DIRECT-BUILD` | `DEC-033` 允许把场景当创始人产品选择来构建 | 所有市场与效果假设仍为 `E0`；G2 前仍需独立于代码的现实证据 |
| 首版产品范围与验收 | `AMBER` | 路线图定义了完整 P1 纵切 | 仍需缩成首批场景的用户故事、验收、非目标与停止规则 |
| 礼宾运营与责任分离 | `RED` | 原则上要求人工负责、冲突回避和审计 | 没有已任命人员、排班、SLO、SOP、培训或演练记录 |
| 法律、合同、税务与支付 | `RED` | 已识别不能软件化的事项 | 辖区、实体、平台角色、合同包、付款方式、税务与保险均未确认 |
| 隐私、研究伦理与数据处理 | `AMBER` | 数据权、Consent、最小化和退出要求较清楚 | 真实数据清单、合法性分析、保留表、处理方与请求流程未批准 |
| 商业模式、单位经济与现金 | `RED` | 有需求方收费和公共经济候选方向 | 客群、价格、成本、预算、现金跑道、获客路径与暂停阈值未验证 |
| 工程事实与安全基线 | `UNKNOWN` | 2026-08-09 审计列出明确风险与红线 | 本次未检查代码；必须在固定 revision 重跑测试和风险核验 |
| 交付治理与发布责任 | `RED` | 有能力状态层和阶段门槛概念 | 没有已批准的首版 backlog、团队容量、质量目标、发布/回滚责任 |
| 风险接受与独立复核 | `AMBER` | 风险类型和权力边界较完整 | 没有具名责任人、风险接受者、到期日或正式 go/no-go 记录 |

总体结论：**理念与目标设计就绪，产品/市场/运营/法律/财务事实未就绪，生产开发授权未就绪。**

## 3. 启动包文档地图

现有文档与本次补充材料共同形成三层阅读顺序：

### 3.1 先理解使命与制度边界

- [总览](/foundations/overview.md)
- [社会契约](/foundations/social-contract.md)
- [经济宪法与治理结构](/foundations/economic-constitution.md)
- [成员制度、动态开放与反收编](/foundations/membership-and-open-community.md)
- [Foundations 要求目录](/foundations/foundation-requirements.md)

### 3.2 再理解完整目标与当前技术差距

- [实现差距审计](/foundations/implementation-gap-assessment.md)
- [技术能力地图](/foundations/technical-capability-map.md)
- [落地路线图](/foundations/realization-roadmap.md)

### 3.3 最后形成启动决定

- 本文：统一就绪度、门槛和签字入口；
- [产品与首批试点定义](/foundations/product-and-pilot-definition.md)：首个用户、场景、范围、旅程和产品验收；
- [研究与证据计划](/foundations/research-and-evidence-plan.md)：怎样把假设变成可复核证据；
- [运营模型与服务手册](/foundations/operating-model-and-service-playbook.md)：人工服务、责任分离、队列、演练和事件处理；
- [法律、合规与合同准备](/foundations/legal-compliance-and-contract-plan.md)：软件外必须完成的专业判断和文件包；
- [商业、财务与进入市场计划](/foundations/business-finance-and-go-to-market.md)：定价、获客、成本、预算和资本护栏；
- [使命衡量与学习计划](/foundations/mission-measurement-and-learning-plan.md)：指标事实、口径、隐私、质性反例和继续/暂停触发；
- [软件交付章程](/foundations/software-delivery-charter.md)：获批后首个纵切怎样开发、验收、发布和停止；
- [风险、决定与假设登记册](/foundations/risk-decision-and-assumption-register.md)：尚未解决事项的唯一队列；
- [要求与能力登记册](/foundations/requirements-capability-registry.md)：原子 `FND → CAP → P1 处置 → Gate 证据` 与能力状态唯一入口。

若这些文档与价值性文件冲突，`FND-*` 的禁止结果优先；若与真实法律义务冲突，停止相关流程并由合格专业人员确认，不能用内部文档覆盖法律。

## 4. 分层决策门槛

本文是 `G0A/G0B/G1/G2/G3` 总门槛的唯一权威定义。专题文档只能提交其领域证据并引用 Gate ID，不得自行降低条件或宣布整体 `PASS`；出现差异时以本文为准，且禁止结果仍以 `FND-*` 为上位约束。

### G0A：允许内部研究准备

当前状态：`PASS`。

允许：内部工作坊、桌面研究、合成数据原型、服务蓝图、合同咨询、支付方案研究、风险演练和工程事实核验。

必须遵守：

- 不招募、联系或观察外部真人研究参与者；
- 不将团队私人通讯录、历史客户资料或未经新目的授权的材料当研究数据；
- 不让原型保存真实个人资料或触发真实权益决定；
- 所有发现进入证据登记，不只保留有利结论。

### G0B：允许外部真人研究

当前状态：`NO-GO`。以下项目全部为 `PASS` 后，才允许开展指定范围的访谈、观察、可用性测试或招募；任何一项为 `TBD/FAIL` 均不得联系或采集研究资料：

| Gate ID | 必须具备的证据 | 责任角色 | 当前 |
| --- | --- | --- | --- |
| `G0B-01` | 研究责任实体/发起人、目标地域、控制者和可联系负责人已确定（`DEC-027`） | Research + Legal | `TBD` |
| `G0B-02` | 研究说明与逐目的同意文本获批，覆盖活动、录音、引用、补偿、撤回和拒绝后果 | Research + Privacy | `TBD` |
| `G0B-03` | 研究数据清单、合法依据、接收方、存储、访问、保留、删除和备份处置获批 | Privacy + Security | `TBD` |
| `G0B-04` | 招募渠道、排除/脆弱性规则、非强迫检查和是否需要伦理审查已有书面结论（`DEC-028`）；如使用伙伴招募，`TBD-PARTNER-01` 同时完成 | Ethics/Legal | `TBD` |
| `G0B-05` | 补偿金额、支付主体、税务/支付处理和未完成参与的公平规则获批（`DEC-029`） | Finance + Legal | `TBD` |
| `G0B-06` | 撤回、投诉、数据请求、安全事件和伤害升级路径有具名负责人、替补与时限 | Research + Privacy/Safety | `TBD` |
| `G0B-07` | 招募与研究宣称已进入 Claims registry，并只陈述获证事实 | Product + Legal | `TBD` |
| `G0B-08` | 最小独立研究库、权限、导出和删除演练通过，资料不进入生产原型 | Research + Security | `TBD` |

`G0B` 只授权获批协议内的研究，不授权真实服务、项目承诺、产品账号、合同或商业付款；研究补偿也不得被描述为项目收入或付费需求证据。

### G1：允许最窄生产纵切开发

当前状态：`NO-GO`。`G1-02` 已按 `DEC-033` 选择替代路径；以下条件仍须全部满足才可使 G1 整体 `PASS`：

`DEC-033` 对该原子项的记录语义为 `PASS — DEC-033`，但这项 PASS 只有在 G1 总评审确认跨职能批准链后才可被总 Gate 使用；它绝不单独改变 G1 总状态。

| Gate ID | 必须具备的证据 | 责任角色 | 当前 |
| --- | --- | --- | --- |
| `G1-01` | 一个获批 ICP、一个主场景、一个明确地域/辖区范围及排除项 | Product accountable | `TBD` |
| `G1-02` | 外部真人研究不是本轮前置；`DEC-033` 已选择创始人定向路径，假设保持 `E0`。正式 G1 总评审前仍须由 Product、Research/Evidence、Business/Finance 与独立 Risk reviewer 具名批准限域 backlog、预算/期限及证据债务 | Founder sponsor + cross-functional approvers | `PASS — DEC-033（需在 G1 总评审确认批准链）` |
| `G1-03` | 产品定义中的主旅程、非目标、用户验收和停止条件获批准 | Product + Ops + Engineering | `TBD` |
| `G1-04` | 运营角色已任命，职责冲突、升级、申诉和暂停权已演练 | Operations accountable | `TBD` |
| `G1-05` | 辖区、运营实体、平台法律角色、合同架构/关键条款及支付路径已有书面专业确认；最终可执行文本留作 `G2` 证据 | Legal accountable | `TBD` |
| `G1-06` | 试点数据清单、目的/合法性、保留、访问和删除流程获批准 | Privacy accountable | `TBD` |
| `G1-07` | 预算、团队容量、单位经济假设、损失上限和停止阈值获批准 | Finance accountable | `TBD` |
| `G1-08` | 固定代码 revision 的测试、安全、迁移和已知风险基线重新采集 | Engineering accountable | `TBD` |
| `G1-09` | 首个 backlog 只包含获批纵切，具备 `FND → CAP → 验收 → 证据` 追踪 | Delivery accountable | `TBD` |
| `G1-10` | `G1` 授权范围会触发的 Critical 已移除，或已有 Gate 前控制证据且残余影响不再为 Critical；仅在真实数据/资金/权益或延期能力启用时触发的 Critical 通过保持能力关闭而标为 `DEFERRED`；其余风险有责任人、到期、监测和接受者 | Risk accountable | `TBD` |

除已由 `DEC-033` 明确替代的 `G1-02` 外，任何一项为 `TBD`、`FAIL` 或依赖“开发后再决定”，结论均为 `NO-GO`。`G1-02` 的批准链须在 G1 总评审确认；其通过不提高任何 `ASM-*` 证据等级，也不影响 G2。范围、辖区、数据、provider、资金、参与者类型、backlog revision、预算或期限变化会使该通过自动失效并重新评审。

### G2：允许封闭付费试点

当前状态：`NO-GO`。除 `G1` 持续有效外，下表是允许真实服务、真实产品数据、签约和收付款的唯一原子清单；每项都必须给出版本化证据、具名签字和 `PASS`。专题文档只能提供证据，不能单独宣布 `G2 PASS`。

| Gate ID | 必须具备的证据 | 主要 FND / 外部项 | 责任角色 | 当前 |
| --- | --- | --- | --- | --- |
| `G2-01` | 批次地域、参与者/项目/金额上限、纳排标准、停止条件、补救资金和退出善后获批 | `FND-OPS-004`、`RSK-024`、`RSK-035` | Pilot + Finance | `TBD` |
| `G2-02` | 各角色使用适用且已批准的参与/服务协议；同一项目的全部必要签字方接受同一 Project Agreement/SOW 版本，并理解范围、验收、变更、付款、数据、IP 和退出 | `FND-CTR-001`、`FND-CTR-002`、`DEC-008`、`DEC-009`、`DEC-023`、`DEC-024`、`DEC-025` | Legal + Product | `TBD` |
| `G2-03` | 产品与运营数据清单、控制/处理角色、合法依据或同意、最小权限、保留、访问/更正/删除/导出、备份和事件流程已批准并演练 | `FND-RGT-001`、`FND-RGT-002`、`FND-RGT-004`、`FND-RGT-005`、`FND-EVD-001`、`TBD-DATA-01` | Privacy + Security | `TBD` |
| `G2-04` | 逐笔资金流、付款法律性质、provider、权威账簿、资金保障、费用/税票、支付、退款、失败、未知、冲正和对账均获专业确认并在测试环境与人工流程演练 | `FND-COL-008`、`FND-CTR-004`、`FND-CTR-005`、`TBD-PAY-01`、`TBD-TAX-01` | Finance + Legal + Engineering | `TBD` |
| `G2-05` | 举报、临时保护、反报复、有理由决定、职责分离、争议、独立申诉、补救、脆弱参与者排除及强制报告边界有具名 owner/backup、时限和演练 | `FND-SAF-001`、`FND-SAF-002`、`FND-SAF-003`、`FND-SAF-004`、`FND-SAF-005`、`FND-SAF-006`、`FND-SAF-007`、`TBD-ETHICS-01` | Safety + Legal + Ops | `TBD` |
| `G2-06` | 反歧视/公平审查、允许使用的敏感属性、合理便利、清晰语言、辅助技术或人工替代路径经专业与参与者理解检查 | `FND-EQU-001`、`FND-EQU-002`、`FND-EQU-003`、`TBD-ACCESS-01` | Product + Legal + Accessibility | `TBD` |
| `G2-07` | 运营、隐私、财务、安全、申诉角色及替补已任命；SLO、WIP、排班、冲突回避、双人控制、培训、权限到期和超限暂停已演练 | `FND-OPS-001`、`FND-OPS-003`、`FND-OPS-004`、`RSK-004`、`RSK-005`、`RSK-034` | Operations accountable | `TBD` |
| `G2-08` | 固定 revision 的生产组合、身份/租户隔离、规则/审计、数据权、产品壳、文件、迁移、provider inbox/outbox、幂等、通知、可观测、备份恢复、回滚与人工接管证据通过；登记册中本批次全部 P1 `BUILD/GUARDRAIL` CAP 均有对应组合证据 | `FND-DEP-002`、`FND-RGT-004`、`FND-SAF-007`、`FND-OPS-002`、`FND-OPS-003`、`CAP-S01`、`CAP-S02`、`CAP-S03`、`CAP-S04`、`CAP-S05`、`CAP-S06`、`CAP-S07`、`CAP-C07`、`RSK-006`、`RSK-007`、`RSK-008`、`RSK-009`、`RSK-010`、`RSK-025`、`RSK-026`、`RSK-033` | Engineering + Security | `TBD` |
| `G2-09` | 正常、拒绝、撤回、范围变化、签署拒绝、争议、数据请求、付款失败/未知/重复回调、安全事件、紧急暂停及停摆善后端到端演练通过 | `FND-EVD-003`、`FND-SAF-003`、`FND-SAF-005`、`FND-SAF-007`、`FND-OPS-003` | Cross-functional exercise lead | `TBD` |
| `G2-10` | 劳动、消费者、内容/IP、税务、许可/备案和保险等与本批次相关的外部专业项已完成；不适用项有基于已冻结范围的书面 `N/A` 理由 | `TBD-LABOR-01`、`TBD-TAX-01`、`TBD-IP-01`、`TBD-CONSUMER-01`、`TBD-CONTENT-01`、`TBD-INSURE-01`、`DEC-029`、`DEC-030`、`DEC-031`、`RSK-036` | Legal accountable | `TBD` |
| `G2-11` | 若使用伙伴/场地/设备/转介，角色授权、受益者确认、资源条件、非强迫、数据/IP、安全、停摆承接和申诉连续性协议生效；不用则明确 `N/A` | `FND-NOD-001`、`FND-NOD-002`、`FND-NOD-003`、`FND-NOD-004`、`FND-NOD-006`、`FND-DEP-001`、`FND-DEP-003`、`FND-DEP-004`、`DEC-016` | Partner + Legal + Ops | `TBD` |
| `G2-12` | 服务包、价格、采购/获客路径、每案完整成本、现金 downside、单位经济假设、供需 WIP 和最大损失经批准 | `FND-COL-003`、`FND-COL-006`、`FND-COL-007`、`FND-COL-008`、`FND-ECO-009`、`FND-ECO-010`、`DEC-002`、`DEC-006`、`DEC-010`、`DEC-017` | Business + Finance | `TBD` |
| `G2-13` | 批次主要指标、护栏、停止指标和人工采集责任已预注册；招募及外部宣称进入 Claims registry，且只覆盖有等级、范围和有效期的证据 | `FND-EVD-002`、`FND-EVD-003`、`FND-MIS-001`、`FND-MIS-002`、`FND-MIS-004`、`DEC-032`、`RSK-027`、`RSK-028` | Measurement + Product + Legal | `TBD` |
| `G2-14` | 本批次触发的 Critical 已 `CLOSED`，或以 Gate 前预防/侦测/恢复证据转为 `CONTROLLED` 且残余影响不为 Critical；其余残余风险依规则接受 | `FND-SAF-001`、`FND-SAF-002`、`FND-SAF-003`、`FND-SAF-004`、`FND-SAF-005`、`FND-SAF-006`、`FND-SAF-007`、RAID | Risk accountable | `TBD` |
| `G2-15` | 本批次涉及的开放决定、假设、依赖、合同/provider 版本和专业 TBD 均有明确处置；没有“试点后再决定”的前置义务 | `FND-EVD-003`、RAID | Pilot accountable | `TBD` |

任何以“能力关闭”控制的 Critical 一旦纳入批次，`DEFERRED` 自动失效并阻断启动。`CONTROLLED` 不改变固有影响等级，只表示最低保护已实现、残余影响重新评估且仍受监测；真实批次后的效果证据进入 `G3`，不得倒逼团队伪造“零风险”。

### G3：允许扩大或公开上线

当前状态：`NO-GO`，且不做详细日期承诺。至少要求：

- P2 的退出门槛已 `PASS`，证明权利、安全、申诉、支付和连续性能力已从单批次保护扩展为可恢复运行；
- [实现差距审计](/foundations/implementation-gap-assessment.md)中与公开范围相关的具体 `Critical/High` 正确性红线已在固定 revision 关闭；一般固有风险仍按 RAID 区分控制与残余风险；
- 封闭试点完成预先注册的继续/修改/停止判断；
- 重大伤害、申诉、付款、隐私和安全问题均已关闭或受控；只有满足法律、`FND-*` 与 Gate 最低要求后的非 Critical 残余风险才可被具名接受；
- 运营容量、单位经济、获客质量和支持负担在扩大后仍可承受；
- 权利流程被真实使用且参与者能理解；
- 公开声明只覆盖已经 `OPERATED/EFFECTIVE` 的能力；
- 扩大规模不会提前激活成员治理、公共金库或所有权承诺。

邀请制扩批与公开注册是两个不同授权范围：前者仍须限定人数、地域、项目和损失上限；后者还须单独确认公众招募、消费者/平台义务、开放容量、支持覆盖与宣传证据，不能用一次邀请制 `G3` 决定自动放开注册。

## 5. 开发启动评审必须回答的问题

评审会不得只展示路线图或界面。每位批准者必须能回答：

1. 首批参与者是谁，为什么是他们，谁被明确排除；
2. 哪条真实证据支持这个问题值得解决；
3. 不做软件时，人工流程如何完成同一服务；
4. 软件本轮减少哪一个已观察到的风险或成本；
5. 一次失败最多伤害谁、多少资金、哪些数据和哪些权利；
6. 谁可以立即暂停，暂停后如何保留报酬、申诉和退出；
7. 哪些判断继续由人负责，为什么；
8. 哪些法律和财务事实来自外部权威来源；
9. 如何证明“拒绝不惩罚”“付款真实”“数据可退出”；
10. 哪条证据出现时必须停止而不是继续优化。

无法回答的事项进入[风险、决定与假设登记册](/foundations/risk-decision-and-assumption-register.md)，不能在会议纪要中消失。

## 6. 启动评审记录模板

```text
Review ID:
Review scope: G0B / G1 / G2 / G3
Evidence cutoff:
Code revision（若适用）:
Pilot version / rule version:
Evidence exception / decision ID:
Exception scope / expiry / approvers:
G2 replacement evidence required:

Gate results:
- Product:
- Research evidence:
- Operations:
- Legal / privacy:
- Finance:
- Engineering / security:
- Risk:

Unresolved Critical items:
Accepted non-Critical risks and acceptors:
Conditions and expiry:
Decision: GO / CONDITIONAL GO / NO-GO
Authorized scope:
Explicitly unauthorized scope:
Stop authority:
Next review trigger:
Approvals:
```

`CONDITIONAL GO` 只能包含可验证、可到期的条件，不能用“后续完善合规”“上线后观察”之类无限条件绕过门槛。

## 7. 文档控制

本启动包采用四种状态：

- `DRAFT`：可讨论，不能作为外部承诺或开发授权；
- `REVIEWED`：相关专业角色已审阅，但仍可能有条件；
- `APPROVED`：指定版本与范围已获批准，可作为门槛证据；
- `SUPERSEDED`：已被新版本替代，历史决定仍可复现。

每次修改影响范围、费用、数据用途、合同、支付、安全、成员权利或停止条件时，必须：

1. 写明变更理由和受影响主体；
2. 更新对应 `FND-*`、`CAP-*`、风险和验收；
3. 指明是否需要重新同意、重新签约或重新通过 Gate；
4. 保留旧版本，不静默覆盖历史项目使用的规则。

### 7.1 当前文档批准清单

下列 owner/approver 是应承担职责的**角色占位**，不是已任命的人。到相应 `G0B/G1` 前必须把本轮涉及的角色替换为具名责任人并记录版本批准；在此之前所有文档均不能单独授权真人研究或真实试点。

| 文档 | 当前性质 | Owner 角色 | 必须参与批准/复核 |
| --- | --- | --- | --- |
| 总览 | `DRAFT` 理念基线 | Mission accountable | Product、成员/参与者代表（形成后） |
| 社会契约 | `DRAFT` 价值宪章 | Governance accountable | 多元参与者、Legal、使命守护（形成后） |
| 经济宪法 | `DRAFT` 制度假设 | Governance + Finance | Legal/Tax、成员代表（形成后） |
| 成员制度 | `DRAFT` 制度假设 | Governance | Operations、Legal、成员代表（形成后） |
| Foundations 要求目录 | `DRAFT` 规范 | Requirements owner | Product、Ops、Engineering、Legal/Privacy/Finance |
| 实现差距审计 | `HISTORICAL/UNVERIFIED` 审计记录 | Engineering assurance | Security、各能力 owner |
| 技术能力地图 | `DRAFT` 目标设计 | Architecture owner | Product、Ops、Security/Privacy、Legal/Finance |
| 落地路线图 | `DRAFT` 阶段策略 | Delivery accountable | Cross-functional Gate approvers |
| 启动就绪度入口 | `DRAFT` go/no-go 基线 | Pilot accountable | 全部 `G1/G2` 责任角色 |
| G1 创始人定向构建决定 | `APPROVED` 范围决定证据 | Project owner / Product accountable | G1 Gate approvers 在总评审中复核其范围与失效条件 |
| 产品与首批试点定义 | `DRAFT` 产品章程 | Product accountable | Research、Ops、Engineering、Legal/Finance |
| 研究与证据计划 | `DRAFT` 研究协议 | Research lead | Privacy、Ethics/Legal、参与者保护 reviewer |
| 运营模型与服务手册 | `DRAFT` 运行基线 | Operations accountable | Safety、Privacy、Finance、Legal、Engineering |
| 法律、合规与合同计划 | `DRAFT` 专业工作底稿 | Legal accountable | 外部目标辖区专业人员、Privacy/Finance/Product |
| 商业、财务与 GTM | `DRAFT` 经营假设 | Business + Finance | Product、Ops、Mission/Risk accountable |
| 使命衡量与学习计划 | `DRAFT` 指标与复盘基线 | Data/Measurement + Mission | Product、Ops、Research、Privacy、Finance |
| 软件交付章程 | `DRAFT` 工程章程 | Engineering + Delivery | Product、Ops、Security/Privacy、Finance/Legal |
| 风险/决定/假设登记 | `DRAFT` RAID 基线 | Risk accountable | 各风险 owner 与有权限接受者 |
| 要求与能力登记册 | `DRAFT/UNVERIFIED` 状态入口 | Requirements + Architecture | 每个 CAP owner、证据 reviewer、Gate approvers |

正式成员尚未形成时，创始团队可以批准有限、可撤销的试点约束，但不得把这种批准表述为成员共同同意；真实成员形成后应依路线图重新审阅其权利相关文件。

## 8. 本次评估的限制

本文补齐的是“启动所需问题、责任、证据和门槛”，不是对未知事实的替代回答。以下结论必须由后续行动产生：

- 市场是否真实存在以及首个细分场景；
- 参与者是否愿意按目标条件付费或投入；
- 特定辖区的实体、合同、支付、税务、劳动与数据结论；
- 当前代码是否已修复审计中的红线；
- 团队人数、能力、预算和实际交付速度；
- foundations 的制度假设是否在真实协作中有效。

在这些事实产生前，最诚实的状态是：**内部准备与 G1 剩余条件关闭工作可继续；本轮选择不开展外部真人研究，`G0B` 保持 `NO-GO`；`G1-02` 已依 `DEC-033` 通过，但 G1 整体仍因其他 `TBD/BLOCKER` 为 `NO-GO`；真实服务/付费试点仍为 `G2 NO-GO`。**
