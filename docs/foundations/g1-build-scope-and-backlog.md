# DEC-033 下 G1 构建范围与可追踪 Backlog

> 文档状态：`FOUNDER-DIRECTED CANDIDATE v0.1 / E0 / NOT GATE APPROVED`
> 适用决定：`DEC-033`；只定义一个可撤销的候选场景和 `Slice 0..4` 工程队列
> 当前 Gate：`G0B NO-GO`、`G1 NO-GO`、`G2 NO-GO`
> 证据边界：本文中的 ICP、场景、地域、语言、币种、旅程和验收均是为构建而选定的 `E0` 产品假设，不是研究、市场、法律、财务或效果事实
> 范围权威：本文是 `DEC-033` 下候选构建范围与 backlog 的单一入口；`FND → CAP` 仍以[要求与能力登记册](/foundations/requirements-capability-registry.md)为准，Gate 仍以[软件开发启动就绪度与决策入口](/foundations/readiness-and-start-decision.md)为准
> 禁止发布：本范围不包含任何公开部署、托管或发布，包括 OpenAI Sites

## 0. 本文能决定什么、不能决定什么

本文把[产品与首批试点定义](/foundations/product-and-pilot-definition.md)中的规划默认值缩成一个可实现、可删除、可替换的候选纵切，并把[软件交付章程](/foundations/software-delivery-charter.md)的 `Slice 0..4` 转成具名追踪项。它只回答“若团队选择直接构建，当前只构建什么，以及用什么测试证明工程语义”。

它不完成任何 Gate，也不替代专业判断：

| Gate 项 | 本文提供的内容 | 本文没有提供的内容 | 当前状态 |
| --- | --- | --- | --- |
| `G1-01` | 一个明确的候选 ICP、场景、地域、语言、币种和排除项 | Product 及所需角色的具名批准；现实需求证据 | `CANDIDATE / E0 / TBD` |
| `G1-03` | 候选主旅程、非目标、逐条验收和停止条件 | Product、Ops、Engineering 的具名批准 | `CANDIDATE / TBD` |
| `G1-09` | `FND → PRD/UC → CAP → ACC → TST/EVD` 候选 backlog | Delivery accountable 的具名批准和固定 revision | `CANDIDATE / TBD` |
| `G1-02` | 沿用 `DEC-033` 的定向构建路径 | 不升级任何假设，不改变最终批准链 | `PASS — DEC-033（须在 G1 总评审确认批准链）` |
| `G1-04..08`, `G1-10` | 明确它们怎样阻断各 Slice | 不虚构运营任命、法律意见、数据批准、预算、工程基线或风险接受 | `TBD / BLOCKED` |
| `G2` | 明确真实参与者之前的禁区 | 不授权真人、真实数据、合同、资金或现实权益决定 | `NO-GO` |

### 0.1 阶段权限

| 阶段 | 可做 | 不可做 |
| --- | --- | --- |
| G1 整体通过前 | `Slice 0` 的事实重采集、已知风险修复、合同/ADR、合成测试脚手架、可删除原型 | 把 `Slice 1..4` 当获准生产纵切；接触外部真人或真实数据/资金 |
| G1 通过后、G2 通过前 | 使用合成数据、批准的内部测试账号和 provider sandbox 实现 `Slice 1..4`；保持功能关闭且可回滚 | 邀请真实服务参与者、导入真实资料、签合同、发送真实业务通知、收付款或作现实权益决定 |
| G2 通过后 | 不在本文授权范围内 | 不得从本文推导任何真实试点授权 |

本文 backlog 的状态只使用：

- `PERMITTED-PRE-G1`：可在 G1 总体 `NO-GO` 时进行的事实、风险和合成验证工作；
- `BLOCKED-BY-G1`：只有 G1 整体 `PASS` 后才能开始的生产质量实现；
- `OFF/DEFERRED`：通过保持能力关闭控制风险，启用前必须另过相应 Gate；
- `PLANNED-EVIDENCE`：测试或证据目标尚未在固定 revision 上产生，不能写成通过。

## 1. 单一候选场景：`SCN-G1-001`

### 1.1 候选 ICP 与待办任务

下列选择全部是 `E0` 构建假设，状态为 `CANDIDATE`，不是 `DEC-001` 已批准或市场已经存在的事实。

| 项目 | `SCN-G1-001` 候选选择 | 明确未知 |
| --- | --- | --- |
| 需求方 ICP | 中国大陆境内、规模较小且能逐项指出真实决策人、单一付款方、候选选择者和验收人的组织或组织内项目组 | 是否有足够高频问题、采购路径和付费意愿 |
| 创作者 ICP | 中国大陆境内、以单一自然人身份远程完成简体中文数字内容与视觉设计交付的成年独立创作者 | 是否愿意接受邀请制、协议/付款条件是否可持续、劳动分类 |
| 单一问题 | 需求方已有一个获内部授权、只使用公开或自有低风险材料的事项，需要把它整理成一个简体中文公开信息型单页的文案与视觉设计交付包 | 需求澄清是否单独收费、什么价格与周期合理 |
| 单一成果 | 一个版本化交付包：冻结后的 brief、单页文案、视觉设计源文件/导出件、验收记录和必要移交说明；不含代码部署、域名、广告投放或持续代运营 | IP/许可、署名、维护与移交的目标辖区结论 |
| 服务形态 | 邀请制、人工核验、有限候选、创作者明示接受或无惩罚拒绝、获授权者选择、同版协议、里程碑闸门、版本化变更、人工异常与申诉 | 人工队列容量、SLO、owner/backup 和真实成本 |
| 地域/辖区 | 服务场景候选范围仅为中华人民共和国大陆地区，不含香港、澳门、台湾；双方与交付均不跨境 | 运营实体、平台法律角色、合同/劳动/税务/数据/支付结论全部 `TBD` |
| 语言 | 产品、协议候选字段、通知模板和人工路径使用简体中文 `zh-CN` | 适用清晰语言与无障碍标准尚待专业/用户理解验证 |
| 币种 | 数据合同只允许候选币种代码 `CNY`；G2 前所有金额均为显著标识的合成值，不能触发真实资金 | 金额、价格、税费、发票、资金保障和 provider 全部 `TBD` |
| 项目形态 | 一次性、远程、单一成果包；测试基准使用一个 Creator、一个付款方、每一合同方一个签字人和一个验收决定 | 项目数、金额、周期、里程碑数和总损失上限仍由 `DEC-002/G1-07` 决定，测试值不是政策 |
| 第三方资源 | `NONE / NOT APPLICABLE`，不得依赖伙伴转介、场地、设备、导师、品牌、数据或其他非合同方资源 | `DEC-016` 批准前保持这一安全默认 |

### 1.2 九类需求侧角色在候选场景中的表达

同一主体可以兼任，但每一行仍须独立记录授权、作用域、期限、冲突和撤回；Organization 身份、出资或运营权限都不能自动填充其他角色。

| 角色 | 候选场景中的记录要求 |
| --- | --- |
| 问题提出者 | 说明为什么需要该公开信息单页、信息来源和提出权限 |
| 实际受益者 | 记录预期从信息清晰度受益的人群；不得由出资者自动代言 |
| 受益者代表 | 有可核验授权才记录；否则为 `NONE / UNCONFIRMED`，不能作成果确认 |
| 出资/采购者 | 单一付款方候选；资金、合同和发票责任仍须外部权威确认 |
| 资源提供者 | 固定为 `NONE / NOT APPLICABLE`，并记录依据 |
| 需求决策人 | 冻结目标、范围和取舍；不得从付款角色推断 |
| 候选选择者 | 只从同一 MatchRun 中当前 `ACCEPTED` 的候选选择 |
| 验收人 | 按冻结标准验收，不能事后改变标准 |
| 项目协调者 | 传递输入与状态，不代替任何一方同意、签署或验收 |

### 1.3 安全默认与明确排除

以下排除从候选范围第一天生效；若要纳入，必须更新 RAID、重新评审范围并判断是否退回 G1/G2：

- 未成年人、需要额外伦理保护或无法独立有效同意的主体；
- 医疗、法律、金融投资、就业筛选、信贷、教育录取等受监管或重大利益结果；
- 高危线下、人身安全、照护、运输、施工、受控物品或线下活动执行；
- 政治竞选、仇恨/骚扰、成人内容、违法内容或依法可能需要强制报告的内容；
- 健康、精确位置、生物特征、身份证件、账户凭据、大规模个人信息、商业核心机密或其他高风险/敏感数据；
- 需要真实客户名单、用户行为数据、追踪脚本、广告账户或生产系统访问的项目；
- 实质长期、排他、高控制、固定工时或可能形成雇佣/派遣而被包装成一次项目的安排；
- 无预算路径、无偿样稿、公开低价竞标、无限修改、模糊满意度付款或事后压价；
- 多人 Creator 团队、多个付款方、每一合同方多个必要签字人；在 `DEC-023/024/025` 完成前继续使用单一安全默认；
- 跨境参与者、跨境数据、外币、多 provider、代收、托管、分账、贷款、众筹或资金池；
- 第三方场地、设备、导师、数据、品牌、转介或其他项目关键资源；
- 代码开发、生产部署、域名/DNS、广告投放、长期运营、开放社区、公开 marketplace、AI 自动生成或自动决定；
- 默认全量 IP 转让、要求创作者成立公司/融资、以增长或流量作为唯一验收；
- 任何无法提供必要退出、数据权、付款善后、举报、申诉或失败补救的项目。

## 2. 主旅程、非目标与责任边界

### 2.1 唯一主旅程

`SCN-G1-001` 只构建这一条旅程；后一步只能引用前一步的版本化事实，不能改写历史：

```text
J01 内部邀请/身份/OrganizationMembership/目的 Consent
→ J02 Creator 发布最小 ProfileVersion
→ J03 需求方提交 DemandVersion 与九角色授权
→ J04 人工核验范围、排除、预算路径与风险
→ J05 仅由 sandbox/合成权威事实形成 DEMAND_VERSION Funding 状态
→ J06 固定规则、最小快照、有限且可解释的 MatchRun
→ J07 Creator ACCEPT / DECLINE / WITHDRAW；到期 EXPIRE
→ J08 获授权 selector 只从同 run 的 ACCEPTED 候选完成选择
→ J09 创建 Project shell；必要方接受同一 AgreementVersion
→ J10 sandbox 里程碑状态满足后开始；交付、拒收、变更、终止均版本化
→ J11 sandbox Payment 请求、未知、失败、成功、退款/冲正与对账收敛
→ J12 情境 Outcome/Review、数据权、举报/申诉、退出和恢复
```

每一步都必须覆盖适用的拒绝、撤回、超时、并发、重放、外部未知、人工接管、通知失败、申诉和退出。G2 前，旅程中的主体、文件、金额、provider 结果和通知接收者全部是合成或获批准的内部测试事实。

### 2.2 产品非目标

本轮不以“平台完整”为目标，并明确不做：

- 任何真人研究、市场验证、公开招募、真实交易或现实权益决定；
- 开放注册、搜索市场、榜单、投标、竞价、付费曝光、注意力 feed 或增长游戏化；
- 多场景、多行业、多辖区、多语言、多币种、多 provider 或多地域高可用；
- 创作者团队、多付款方、多必要签字方、复杂组织层级或伙伴节点；
- 实时代码协作、生产网站发布、广告/分析、无限消息或通用云盘；
- 全局声誉分、贡献币、自动成员晋级、自动处罚或买权；
- Civic Membership、公共职务、成员议会、公共金库、成员经济权益、宪法表决或合法 fork；
- AI 生成、AI 匹配、AI 风险判断、AI 处罚、AI 争议裁决或任何模型调用；
- 自营代收、托管、分账或以数据库状态制造合同、支付、税务、所有权和成员权利；
- 把测试通过、Demo 或内部满意度解释为 `OPERATED/EFFECTIVE` 或需求已经成立。

### 2.3 软件、人和外部权威的边界

| 软件负责 | 有权限的人负责 | 外部权威负责 |
| --- | --- | --- |
| 版本、状态机、权限、作用域、闸门、最小快照、幂等、通知事实、审计索引、可删载荷和恢复证据 | 需求真实性、授权/冲突、排除、软例外、复杂验收、初次安全决定、独立申诉和补救 | 法律实体、合同效力、劳动/税务/消费者/IP 判断、身份事实、资金/付款事实、provider 与账簿 |

## 3. 逐条工程验收基线

`ACC-*` 是本候选 backlog 的稳定验收别名；完整异常语义仍以[软件交付章程第 5.2 节](/foundations/software-delivery-charter.md)的对应 `UC-P1-*` 为准。以下每一项当前均为 `PLANNED-EVIDENCE`，不是已通过。

| ACC | 对应 PRD / UC | 最低可执行验收 |
| --- | --- | --- |
| `ACC-G1-001` | 全部 | 环境清单证明只有合成数据、内部测试账号和 sandbox；缺配置、密钥、迁移、真实 adapter 或权限时失败关闭，生产配置不能回退到 fake、内存或开放权限。 |
| `ACC-G1-002` | `PRD-P1-001`; `UC-P1-001`, `UC-P1-018`, `UC-P1-019`, `UC-P1-020`, `UC-P1-021` | Session 建立/轮换/撤销/恢复、Organization 邀请/移除、账户暂停/关闭和目的 Consent 分离；旧凭据不复活，登录关闭不吞掉付款、数据权、申诉或必要记录。 |
| `ACC-G1-003` | `PRD-P1-002`; `UC-P1-002` | ProfileVersion 只收集候选场景必要字段；私密报酬底线不可由输出或组合分项反推；撤回后新 run 不读取旧披露，运营者不能覆盖硬边界。 |
| `ACC-G1-004` | `PRD-P1-003`, `PRD-P1-004`; `UC-P1-003` | DemandVersion 的九角色、范围、预算路径、验收、受益者、排除和冲突逐项校验；缺失、过期、取消或并发改版均不能进入匹配。 |
| `ACC-G1-005` | `PRD-P1-005`; `UC-P1-004` | 只有注入的 sandbox 权威账簿可把对应 DemandVersion 标为 `SECURED`；请求、截图、自报、timeout 或 unknown 都不能冒充资金事实；真实 provider adapter 保持关闭。 |
| `ACC-G1-006` | `PRD-P1-006`; `UC-P1-005` | MatchRun 固定 DemandVersion、规则版本/hash 和最小 Profile 快照；多 tenant/run/attempt 并发、重放和缺快照不串数据；输出不能泄漏或反推私密底线。 |
| `ACC-G1-007` | `PRD-P1-007`; `UC-P1-006`, `UC-P1-007` | Creator 可接受、无理由拒绝、撤回或超时；拒绝不产生负面特征；CompleteSelection 只能由当前 selector 对同 run、当前 `ACCEPTED` 候选执行一次。 |
| `ACC-G1-008` | `PRD-P1-008`; `UC-P1-008` | Project shell 与 AgreementVersion 分离；每一必要方在确认时重新验证授权并接受同一版本，缺签、异版、过期或并发变更不能生效。 |
| `ACC-G1-009` | `PRD-P1-008`; `UC-P1-009` | `MILESTONE` Funding 与 `DEMAND_VERSION` Funding 分离；sandbox 资金未明确 `SECURED`、退款/未知或并发时不能进入可开工状态。 |
| `ACC-G1-010` | `PRD-P1-009`, `PRD-P1-010`, `PRD-P1-019`; `UC-P1-010`, `UC-P1-011`, `UC-P1-024` | Delivery、合同验收、受益者成果确认和 ChangeVersion 分离；范围、时间、报酬、成果路径、IP/许可或移交变化须受影响方重新接受，文件只作版本载荷。 |
| `ACC-G1-011` | `PRD-P1-011`; `UC-P1-012` | sandbox Payment 的发起、核实和对账分权；重复、乱序、迟到、未知、失败、退款和冲正幂等收敛；未知期间不盲目重付，真实资金操作关闭。 |
| `ACC-G1-012` | `PRD-P1-014`; `UC-P1-013` | Outcome/Review 区分财务事实、自报观察和运营解释；只在 Project 情境展示，允许回应、更正和争议，不生成总分、排名、代币或政治/经济权限。 |
| `ACC-G1-013` | `PRD-P1-012`; `UC-P1-014` | 合成举报可触发最小范围、自动到期的临时保护；case handler、初次 decider 和独立 appeal reviewer 分离，冲突、超时和通知失败有人工接管及可执行补救。 |
| `ACC-G1-014` | `PRD-P1-013`, `PRD-P1-016`; `UC-P1-015`, `UC-P1-016`, `UC-P1-021` | 访问、更正、限制、删除、导出、取消和账户退出按域给分项结果；稳定索引与可删载荷、legal-hold 候选、第三方权利和备份水位分离，退出不吞掉待履行义务。 |
| `ACC-G1-015` | `PRD-P1-015`, `PRD-P1-018`; `UC-P1-023`, `UC-P1-025` | 重大决定、敏感访问和事务通知可按 correlation 重现 actor、authority、输入版本、规则 hash、理由、结果、投递事实和更正；投递失败不冒充知情或启动不可逆期限。 |
| `ACC-G1-016` | `PRD-P1-016`; `UC-P1-017` | 数据库、sandbox provider、密钥或进程停摆时失败关闭并可人工接管；backup/restore、重复消息、权限撤回和删除水位演练后无双付、越权或状态分叉。 |
| `ACC-G1-017` | `PRD-P1-017`; `UC-P1-022` | 内部浏览器测试中，导航和动作来自实时 BFF 权限；键盘、屏幕阅读器、清晰中文和 scoped assistant 路径能完成相同关键动作，失败时不泄露或猜测成功。 |

## 4. Slice 0..4 可追踪 backlog

### 4.1 追踪与证据规则

- 表中的每个 `FND-*` 都是完整原子 ID；不得用族名或范围替代。
- `TST-*` 是计划测试集 ID，须在实现时绑定真实测试路径、命令、环境和 revision；`EVD-*` 是计划证据包 ID，须保存原始结果、日期、reviewer、适用范围和失败记录。
- 测试层至少按适用性覆盖 contract、domain/property、application、PostgreSQL/RLS/migration、HTTP/BFF、composition、provider sandbox、browser、security/privacy、recovery 与 operation drill。
- 当前所有 `TST/EVD` 均为 `PLANNED-EVIDENCE`。历史审计数字和现有测试文件不能自动填成 `PASS`。
- 所有 owner/backup 当前均为角色占位且未具名，因此任一 `BLOCKED-BY-G1` 项都不满足 Definition of Ready。

### 4.2 Slice 0：事实、Critical 与交付底座

| Backlog ID | 精确 FND | PRD / UC | CAP | 验收 | 计划测试 / 证据 | 当前权限 |
| --- | --- | --- | --- | --- | --- | --- |
| `BLD-S0-001` 固定工程基线 | `FND-EVD-002`, `FND-EVD-003`, `FND-OPS-004`, `FND-MIS-004` | `PRD-P1-015`; `UC-P1-025` | `CAP-S03`, `CAP-S05`, `CAP-I11` | `ACC-G1-001` | `TST-S0-BASELINE`; `EVD-S0-REVISION`：revision/dirty、lock/runtime、全测试命令、迁移、配置、启用项、失败原件 | `PERMITTED-PRE-G1` |
| `BLD-S0-002` IAM/租户/Session 红线 | `FND-RGT-001`, `FND-DEP-002`, `FND-SAF-007`, `FND-EXIT-001` | `PRD-P1-001`, `PRD-P1-016`; `UC-P1-018`, `UC-P1-019`, `UC-P1-020`, `UC-P1-021`, `UC-P1-017` | `CAP-S01`, `CAP-S04`, `CAP-S05` | `ACC-G1-002`, `ACC-G1-016` | `TST-S0-IAM-PG-RLS`, `TST-S0-IAM-POOL`, `TST-S0-IAM-UNKNOWN`; `EVD-S0-RSK-009` | `PERMITTED-PRE-G1` |
| `BLD-S0-003` 匹配最小化/作用域红线 | `FND-HUM-002`, `FND-COL-004`, `FND-RGT-004`, `FND-RUL-003` | `PRD-P1-002`, `PRD-P1-006`, `PRD-P1-007`; `UC-P1-002`, `UC-P1-005`, `UC-P1-006`, `UC-P1-007` | `CAP-C01`, `CAP-C04`, `CAP-S03`, `CAP-S04` | `ACC-G1-003`, `ACC-G1-006`, `ACC-G1-007` | `TST-S0-MATCH-MIN`, `TST-S0-MATCH-INFERENCE`, `TST-S0-MATCH-SCOPE`; `EVD-S0-RSK-006-007-010` | `PERMITTED-PRE-G1` |
| `BLD-S0-004` 决定/审计/规则信封 | `FND-COL-009`, `FND-RGT-004`, `FND-RUL-001`, `FND-RUL-003`, `FND-SEP-001` | `PRD-P1-015`; `UC-P1-025` | `CAP-S02`, `CAP-S03` | `ACC-G1-015` | `TST-S0-DECISION-CONTRACT`, `TST-S0-RULE-REPLAY`, `TST-S0-AUDIT-DELETE`; `EVD-S0-DECISION-ENVELOPE` | `PERMITTED-PRE-G1` |
| `BLD-S0-005` 可重建 package/composition/恢复门禁 | `FND-DEP-002`, `FND-SAF-007`, `FND-OPS-002`, `FND-OPS-003` | `PRD-P1-016`; `UC-P1-017` | `CAP-S05` | `ACC-G1-001`, `ACC-G1-016` | `TST-S0-PACKAGE-INSTALL`, `TST-S0-MIGRATION-FRESH`, `TST-S0-COMPOSE-FAIL-CLOSED`, `TST-S0-BACKUP-RESTORE`; `EVD-S0-REBUILD` | `PERMITTED-PRE-G1` |
| `BLD-S0-006` 数据/访问/威胁清单 | `FND-RGT-001`, `FND-RGT-004`, `FND-EQU-002`, `FND-OPS-002`, `FND-EVD-002` | `PRD-P1-013`, `PRD-P1-015`; `UC-P1-015`, `UC-P1-025` | `CAP-S03`, `CAP-S04`, `CAP-I11` | `ACC-G1-003`, `ACC-G1-014`, `ACC-G1-015` | `TST-S0-SENSITIVE-OUTPUT`, `TST-S0-SMALL-SAMPLE`; `EVD-S0-DATA-INVENTORY`, `EVD-S0-THREAT-MODEL` | `PERMITTED-PRE-G1` |

### 4.3 Slice 1：受控进入、Profile 与 Demand

| Backlog ID | 精确 FND | PRD / UC | CAP | 验收 | 计划测试 / 证据 | 当前权限 |
| --- | --- | --- | --- | --- | --- | --- |
| `BLD-S1-001` 内部身份/组织/Consent | `FND-RGT-001`, `FND-HUM-007`, `FND-DEP-002`, `FND-EXIT-001`, `FND-NOD-006` | `PRD-P1-001`; `UC-P1-001`, `UC-P1-018`, `UC-P1-019`, `UC-P1-020`, `UC-P1-021` | `CAP-S01`, `CAP-S04` | `ACC-G1-002` | `TST-S1-IAM-CONTRACT`, `TST-S1-IAM-PG`, `TST-S1-IAM-HTTP`; `EVD-S1-IAM-COMPOSED` | `BLOCKED-BY-G1` |
| `BLD-S1-002` 最小 ProfileVersion | `FND-HUM-001`, `FND-HUM-002`, `FND-HUM-005`, `FND-RGT-001` | `PRD-P1-002`; `UC-P1-002` | `CAP-C01`, `CAP-S04` | `ACC-G1-003` | `TST-S1-PROFILE-PROPERTY`, `TST-S1-PROFILE-PG`, `TST-S1-PROFILE-HTTP`; `EVD-S1-PROFILE-MIN` | `BLOCKED-BY-G1` |
| `BLD-S1-003` DemandVersion 与九角色 | `FND-HUM-003`, `FND-COL-001`, `FND-COL-002`, `FND-NOD-001`, `FND-MEM-013` | `PRD-P1-003`, `PRD-P1-004`; `UC-P1-003` | `CAP-C02`, `CAP-C03`, `CAP-C08` | `ACC-G1-004` | `TST-S1-DEMAND-PROPERTY`, `TST-S1-DEMAND-PG`, `TST-S1-DEMAND-HTTP`; `EVD-S1-ROLE-MATRIX` | `BLOCKED-BY-G1` |
| `BLD-S1-004` 内部 BFF/可访问产品壳 | `FND-HUM-004`, `FND-HUM-007`, `FND-NOD-006`, `FND-EQU-003`, `FND-OPS-001` | `PRD-P1-017`; `UC-P1-022` | `CAP-S06` | `ACC-G1-017` | `TST-S1-BFF-AUTHZ`, `TST-S1-BROWSER-KEYBOARD`, `TST-S1-BROWSER-SCREENREADER`; `EVD-S1-ACCESSIBILITY-INTERNAL` | `BLOCKED-BY-G1` |
| `BLD-S1-005` 拒绝/更正/数据权/决定队列 | `FND-RGT-002`, `FND-RGT-004`, `FND-COL-009`, `FND-SAF-004`, `FND-SEP-001` | `PRD-P1-012`, `PRD-P1-013`, `PRD-P1-015`; `UC-P1-014`, `UC-P1-015`, `UC-P1-025` | `CAP-S03`, `CAP-S04`, `CAP-C08` | `ACC-G1-013`, `ACC-G1-014`, `ACC-G1-015` | `TST-S1-DECISION-AUTHZ`, `TST-S1-RIGHTS-QUEUE`; `EVD-S1-OPS-DESKTOP` | `BLOCKED-BY-G1` |

### 4.4 Slice 2：sandbox 资金闸门、有限邀请与双向选择

| Backlog ID | 精确 FND | PRD / UC | CAP | 验收 | 计划测试 / 证据 | 当前权限 |
| --- | --- | --- | --- | --- | --- | --- |
| `BLD-S2-001` Demand 资金状态投影 | `FND-COL-008`, `FND-CTR-004`, `FND-ECO-001`, `FND-ECO-012` | `PRD-P1-005`; `UC-P1-004` | `CAP-C06`, `CAP-S03` | `ACC-G1-005` | `TST-S2-FUNDING-CONTRACT`, `TST-S2-FUNDING-INBOX`, `TST-S2-FUNDING-UNKNOWN`; `EVD-S2-SANDBOX-ONLY` | `BLOCKED-BY-G1` |
| `BLD-S2-002` 最小、固定、可解释匹配 | `FND-COL-002`, `FND-COL-004`, `FND-RUL-001`, `FND-RUL-003`, `FND-MEM-006`, `FND-EQU-001` | `PRD-P1-006`; `UC-P1-005` | `CAP-C04`, `CAP-S02`, `CAP-S03` | `ACC-G1-006` | `TST-S2-MATCH-PROPERTY`, `TST-S2-MATCH-PG-RLS`, `TST-S2-RULE-REPLAY`; `EVD-S2-MATCH-TRACE` | `BLOCKED-BY-G1` |
| `BLD-S2-003` Invitation 生命周期 | `FND-HUM-002`, `FND-COL-004`, `FND-SAF-002` | `PRD-P1-007`; `UC-P1-006` | `CAP-C04`, `CAP-I11` | `ACC-G1-007` | `TST-S2-INVITE-STATE`, `TST-S2-INVITE-RACE`, `TST-S2-NO-RETALIATION-FEATURE`; `EVD-S2-INVITE-AUDIT` | `BLOCKED-BY-G1` |
| `BLD-S2-004` CompleteSelection | `FND-COL-004`, `FND-COL-009`, `FND-RUL-003`, `FND-SEP-001` | `PRD-P1-007`, `PRD-P1-015`; `UC-P1-007`, `UC-P1-025` | `CAP-C04`, `CAP-S03` | `ACC-G1-007`, `ACC-G1-015` | `TST-S2-SELECTION-SAME-RUN`, `TST-S2-SELECTION-CONCURRENCY`, `TST-S2-SELECTION-AUTHZ`; `EVD-S2-COMPLETE-SELECTION` | `BLOCKED-BY-G1` |

### 4.5 Slice 3：Project、Agreement、Milestone 与变更

| Backlog ID | 精确 FND | PRD / UC | CAP | 验收 | 计划测试 / 证据 | 当前权限 |
| --- | --- | --- | --- | --- | --- | --- |
| `BLD-S3-001` Project/AgreementVersion | `FND-COL-003`, `FND-COL-006`, `FND-COL-009`, `FND-CTR-002` | `PRD-P1-008`; `UC-P1-008` | `CAP-C05`, `CAP-S02`, `CAP-S03` | `ACC-G1-008` | `TST-S3-AGREEMENT-PROPERTY`, `TST-S3-SIGNATORY-AUTHZ`, `TST-S3-AGREEMENT-PG`; `EVD-S3-SAME-VERSION` | `BLOCKED-BY-G1` |
| `BLD-S3-002` Milestone 资金与开工闸门 | `FND-COL-003`, `FND-COL-008`, `FND-CTR-004`, `FND-ECO-001` | `PRD-P1-008`; `UC-P1-009` | `CAP-C05`, `CAP-C06` | `ACC-G1-009` | `TST-S3-MILESTONE-STATE`, `TST-S3-MILESTONE-UNKNOWN`, `TST-S3-START-RACE`; `EVD-S3-START-GATE` | `BLOCKED-BY-G1` |
| `BLD-S3-003` Delivery/验收/成果确认 | `FND-HUM-003`, `FND-COL-009`, `FND-COL-010`, `FND-CTR-002` | `PRD-P1-010`; `UC-P1-010` | `CAP-C05`, `CAP-C09` | `ACC-G1-010` | `TST-S3-DELIVERY-VERSION`, `TST-S3-ACCEPTANCE-AUTHZ`, `TST-S3-BENEFICIARY-SEPARATION`; `EVD-S3-DELIVERY-TRACE` | `BLOCKED-BY-G1` |
| `BLD-S3-004` 实质变更与终止 | `FND-COL-003`, `FND-COL-010`, `FND-CTR-002`, `FND-EXIT-001` | `PRD-P1-009`, `PRD-P1-016`; `UC-P1-011`, `UC-P1-016` | `CAP-C05`, `CAP-S04`, `CAP-I09` | `ACC-G1-010`, `ACC-G1-014` | `TST-S3-CHANGE-ATOMIC`, `TST-S3-CHANGE-REJECT`, `TST-S3-WINDDOWN`; `EVD-S3-CHANGE-TRACE` | `BLOCKED-BY-G1` |
| `BLD-S3-005` 最小 Message/FileVersion | `FND-COL-003`, `FND-RGT-001`, `FND-RGT-004`, `FND-DEP-004`, `FND-CTR-002`, `FND-OPS-002` | `PRD-P1-019`; `UC-P1-024` | `CAP-C07`, `CAP-S04` | `ACC-G1-010`, `ACC-G1-014` | `TST-S3-FILE-SCAN-FAKE`, `TST-S3-FILE-AUTHZ`, `TST-S3-FILE-RETENTION`; `EVD-S3-FILE-SYNTHETIC` | `BLOCKED-BY-G1` |

### 4.6 Slice 4：sandbox 付款、结果与救济

| Backlog ID | 精确 FND | PRD / UC | CAP | 验收 | 计划测试 / 证据 | 当前权限 |
| --- | --- | --- | --- | --- | --- | --- |
| `BLD-S4-001` Payment/Reconciliation | `FND-COL-008`, `FND-ECO-001`, `FND-ECO-008`, `FND-ECO-012`, `FND-CTR-004` | `PRD-P1-011`; `UC-P1-012` | `CAP-C06`, `CAP-S03` | `ACC-G1-011` | `TST-S4-PAYMENT-IDEMPOTENCY`, `TST-S4-PAYMENT-ORDERING`, `TST-S4-PAYMENT-UNKNOWN`; `EVD-S4-SANDBOX-RECON` | `BLOCKED-BY-G1` |
| `BLD-S4-002` 情境 Outcome/Review | `FND-HUM-001`, `FND-COL-005`, `FND-COL-010`, `FND-REP-001`, `FND-REP-002`, `FND-REP-003`, `FND-REP-004`, `FND-MIS-001` | `PRD-P1-014`; `UC-P1-013` | `CAP-C09`, `CAP-I03`, `CAP-I11` | `ACC-G1-012` | `TST-S4-REVIEW-CONTEXT`, `TST-S4-NO-GLOBAL-SCORE`, `TST-S4-REVIEW-CORRECTION`; `EVD-S4-OUTCOME-SOURCES` | `BLOCKED-BY-G1` |
| `BLD-S4-003` Safety/Dispute/Appeal | `FND-COL-009`, `FND-SEP-001`, `FND-GOV-009`, `FND-SAF-001`, `FND-SAF-002`, `FND-SAF-003`, `FND-SAF-004`, `FND-SAF-005`, `FND-SAF-007` | `PRD-P1-012`; `UC-P1-014` | `CAP-C08`, `CAP-S03` | `ACC-G1-013` | `TST-S4-SAFETY-SCOPE`, `TST-S4-SAFETY-EXPIRY`, `TST-S4-APPEAL-CONFLICT`; `EVD-S4-SAFETY-DESKTOP` | `BLOCKED-BY-G1` |
| `BLD-S4-004` 数据权与退出编排 | `FND-RGT-001`, `FND-RGT-002`, `FND-RGT-003`, `FND-RGT-004`, `FND-RGT-005`, `FND-EXIT-001`, `FND-DEP-004` | `PRD-P1-013`, `PRD-P1-016`; `UC-P1-015`, `UC-P1-016` | `CAP-S04`, `CAP-I09` | `ACC-G1-014` | `TST-S4-RIGHTS-ORCHESTRATION`, `TST-S4-EXPORT-RECEIVE`, `TST-S4-DELETE-BACKUP`; `EVD-S4-RIGHTS-SYNTHETIC` | `BLOCKED-BY-G1` |
| `BLD-S4-005` 通知、审计与恢复 | `FND-RUL-001`, `FND-SAF-004`, `FND-EQU-003`, `FND-OPS-001`, `FND-OPS-003`, `FND-EVD-003` | `PRD-P1-015`, `PRD-P1-016`, `PRD-P1-018`; `UC-P1-017`, `UC-P1-023`, `UC-P1-025` | `CAP-S03`, `CAP-S05`, `CAP-S07` | `ACC-G1-015`, `ACC-G1-016` | `TST-S4-NOTIFY-FAILURE`, `TST-S4-AUDIT-REPLAY`, `TST-S4-RECOVERY-DRILL`; `EVD-S4-RECOVERY-BUNDLE` | `BLOCKED-BY-G1` |

## 5. Critical blocker 与逐 Slice 前置

### 5.1 本范围触发的当前 blocker

状态以[风险、决定与假设登记册](/foundations/risk-decision-and-assumption-register.md)为准；本文不把任何一项改成 `CLOSED/CONTROLLED`。

| 风险 | 阻断范围 | 在进入相关 Slice 前所需证据 | 本文状态 |
| --- | --- | --- | --- |
| `RSK-005` 单一运营者隐藏主权 | `S0..S4` | 身份、最小权限、职责分离、冲突、决定信封、双人控制候选与申诉桌面演练；G2 前再做真实运营演练 | `BLOCKER / UNKNOWN` |
| `RSK-006` 全量 Profile 快照 | `S0`, `S2`, `S4` | 最小数据流、主体定位、稳定索引/可删载荷、删除/更正/恢复测试 | `BLOCKER / UNKNOWN` |
| `RSK-007` 私密底线推断 | `S0`, `S1`, `S2` | 信息流威胁模型、移除可逆分项、属性测试和独立安全/隐私复核 | `BLOCKER / UNKNOWN` |
| `RSK-008` 自由文本/小样本再识别 | `S0`, `S1`, `S3`, `S4` | 数据字段清单、输入/人工复核边界、访问、抑制、导出和敏感输出测试；真实事件演练留至 G2 | `BLOCKER / UNKNOWN` |
| `RSK-009` Session/RLS/连接池 | `S0`, `S1`，并阻断其后全部组合 | 固定 revision 的真实 PostgreSQL session/RLS/池/后台任务/恢复测试全绿且可重建 | `BLOCKER / UNKNOWN` |
| `RSK-010` Matching 跨 run/tenant | `S0`, `S2` | 聚合作用域修复、多 run/attempt/tenant 并发、RLS、HTTP 与 composition 证据 | `BLOCKER / UNKNOWN` |
| `RSK-013`, `RSK-014` 支付监管/劳动分类 | G1 总体、`S2..S4` 领域边界 | 目标辖区专业人员对运营实体、平台角色、合同架构、劳动分类和支付路径的书面范围结论；不能由接口命名替代 | `BLOCKER / TBD` |
| `RSK-024` 现金与损失 | G1 总体、所有 `BLOCKED-BY-G1` 项 | `G1-07` 的预算、团队容量、时间/成本、最大损失和停止阈值批准 | `BLOCKER / TBD` |
| `RSK-026` 多重真相源 | `S0..S4` | 单一机器合同或自动等价检查、规则/schema hash、迁移和 CI 门禁 | `BLOCKER / UNKNOWN` |
| `RSK-029` 为赶工删保护 | `S0..S4` | PR 必须保持本表的权利、申诉、付款正确性、恢复和职责分离验收；范围删减须留下决定与 Gate 影响 | `BLOCKER / UNKNOWN` |
| `RSK-036` 高风险内容/文件 | `S3` | 保持只处理标识清楚的合成文件；真实内容能力继续关闭。启用前需内容/报告专业结论、访问/举报/升级/申诉演练 | `BLOCKER REAL USE / DEFERRED SYNTHETIC` |
| `RSK-012`, `RSK-025`, `RSK-033`, `RSK-035` | `S4` 的真实付款、连续性、限制与善后 | G1 内只验证合成状态机和桌面恢复；真实 provider、付款、参与者义务与补救继续关闭至 G2 | `DEFERRED / G2 BLOCKER` |
| `RSK-031` AI | 全部 | 不实现、不调用、不配置模型；任何启用另过 AI Gate | `DEFERRED-OFF` |
| `RSK-037` 错产品/沉没成本 | 每个 Slice | `G1-07` 成本/期限/停止上限；每 Slice 记录反证、可删除成本和继续/修改/停止决定；G2 前取得独立现实证据 | `OPEN — BLOCKER G2/CLAIMS` |

### 5.2 每个 Slice 的进入与退出前置

| Slice | 进入前置 | 退出所需最小证据；不等于 Gate PASS |
| --- | --- | --- |
| `S0` | 保持 G0A 边界；确认 fixtures、日志、数据库和 provider 均无真实数据/资金；建立证据保存位置 | 固定 revision 可重建；原始测试/迁移/配置/失败清单齐全；本范围触发的 G1 Critical 已逐项 `CLOSED/CONTROLLED/DEFERRED` 并有 reviewer；无 fake 误启用；backlog 与 ADR/数据/威胁索引完成 |
| `S1` | **G1 整体 `PASS`**；S0 退出；`G1-01/03/04/06/07/08/09/10` 均有效；`ADR-P1-001/002/003/005/008/009/010/012` 已按范围决定；只有内部测试账号 | `ACC-G1-002/003/004/013/014/015/017` 在 contract→PG→HTTP→composition 的适用层通过；拒绝、撤回、越权、并发和退出不依赖数据库手改；无真实通知 |
| `S2` | S1 退出；`G1-05` 已书面固定合法/合同/支付领域边界；`G1-07` 预算与停止阈值有效；`RSK-006/007/010/011/013/014` 有 Gate 所需处置；`ADR-P1-004/007/009` 已决定 | `ACC-G1-005/006/007/015` 通过；资金只来自 sandbox 权威源；匹配快照最小且抗推断；邀请与选择跨 run/tenant、并发、重放均 fail-closed |
| `S3` | S2 退出；合同架构、必要签字/验收/变更/IP 边界在 G1 专业结论中足够固定；`DEC-023/024/025` 未决时维持单一安全默认；`ADR-P1-006` 已决定；`RSK-036` 真实内容能力关闭 | `ACC-G1-008/009/010/014` 通过；Agreement/Change/Delivery/File 历史可复现；未 secured 不开工；终止后待办义务独立；只使用合成文件和 sandbox 资金 |
| `S4` | S3 退出；付款/对账接口、数据权清单、安全/申诉程序、通知和恢复设计已固定；运营、隐私、财务、安全和独立复核的角色槽位明确但仍只做内部演练 | `ACC-G1-011/012/013/014/015/016` 通过；未知付款不双付、申诉不自审、数据权分项收敛、通知失败不冒充知情、恢复无越权/状态分叉；所有真实 adapter/feature flag 继续关闭 |

任何 Slice 退出只说明候选工程证据达到其层级；不把 CAP 自动提升为 `ENABLED/OPERATED/EFFECTIVE`，也不改变 G2。

## 6. 构建与试点停止条件

### 6.1 立即停止当前 Slice、保留证据并回到评审

- 发现或怀疑使用了真实姓名、联系方式、身份文件、合同、项目材料、付款凭证、银行/provider 引用或其他非合成数据；
- 任何测试、配置或代码路径可能向外部地址发送通知、创建真实账号、触发真实支付或写入生产/共享 provider；
- `RSK-005/006/007/008/009/010/026/029` 任一扩大、复发或无法在固定 revision 重现控制；
- 缺密钥、迁移、provider 或权限时出现回退到 fake、内存、默认租户、开放权限或推断成功；
- Session、RLS、连接池、后台任务或 MatchRun 出现跨主体、tenant、run 或 attempt 数据；
- 私密报酬底线可由分数、预算、解释、日志、错误或导出反推；
- Agreement、规则、Consent、选择、付款或 Outcome 的旧事实不能按原版本重现，或可被静默覆盖；
- 未接受者能被选择、未 `SECURED` 能开工、付款 `UNKNOWN` 能被当成功，或申诉由原决定人自审；
- 删除/退出会级联吞掉付款、数据权、申诉、必要历史或第三方权利；
- 测试结果、审计数字或 Demo 被描述为需求、付费意愿、公平、效果、合法或参与者理解证据；
- 范围变成另一 ICP、问题、辖区、语言、币种、参与者类型、数据类别、资金流、provider、伙伴或高风险内容；
- 达到未来 `G1-07` 批准的时间、成本、容量或损失停止阈值；在阈值批准前不得用无限投入替代决定；
- Product、Ops、Engineering、Security/Privacy、Legal/Finance 或 Risk 在各自职责内提出未关闭的阻断。

停止意味着：关闭相关 feature flag/adapter，冻结新写入，保存 revision 与原始失败证据，评估删除/迁移/补救，再记录 `CONTINUE / MODIFY / DELETE / DEFER`。停止不授权掩盖失败或删除审计历史。

### 6.2 每个 Slice 的反沉没成本检查

每个 Slice 退出评审必须单独回答并留证：

1. 本 Slice 实际证明了哪一种工程可行性，哪些结论仍为 `E0`；
2. 哪些实现只适用于 `SCN-G1-001`，替换场景时能否删除或经 adapter 替换；
3. 是否出现反对当前 ICP、旅程、复杂度或运营容量的证据；
4. 下一 Slice 是否仍是关闭最大参与者风险的最小增量；
5. 若现在停止，哪些数据、Schema、contract、feature flag 和 sandbox 资源需要删除或保留；
6. 谁有权限作继续/修改/停止决定，其风险接受是否在职责范围内且有期限。

没有具名、有权限的评审者时，状态保持 `BLOCKED`，不能因代码已完成而继续。

## 7. G1/G2 禁区

在 G1 整体 `PASS` 前：

- `Slice 1..4` 不得被称为获准生产纵切；只可写契约、测试和修复 G1 前允许的已知风险；
- 不得将本文件中的候选 ICP、辖区、币种或验收写成已批准默认值、招募材料、合同文本或不可配置代码常量；
- 不得绕过 `G1-04..10`，尤其不得用实现完成替代法律、隐私、预算、运营与风险证据。

在 G2 整体 `PASS` 前，无论 G1 或代码状态如何：

- 不招募、联系、观察或保存外部真人研究资料；若要研究，先逐项通过 `G0B`；
- 不邀请真实服务/试点参与者，不创建真实产品账号，不导入历史客户或团队私人通讯录；
- 不保存真实个人、组织、项目、合同、创作文件、争议、支付、税务或 provider 数据；
- 不签署或生成现实服务合同，不承诺“资金已保障”，不收款、付款、退款、托管、代持或分账；
- 不向外部邮箱、手机、聊天账号或 webhook 发送业务通知；
- 不作真实的资格、匹配、选择、验收、限制、付款、评价、举报、申诉或数据权决定；
- 不启用真实 IdP、支付、通知、文件、AI、伙伴或生产 adapter；sandbox 必须与生产隔离并能整体删除；
- 不使用第三方场地、设备、导师、数据、品牌、转介或伙伴资源；
- 不公开注册、开放市场、上线或发布，也不发布到 OpenAI Sites；
- 不对内外宣称市场验证、需求验证、法律合规、支付保障、公平、匿名、安全、成员所有或使命效果已经成立。

## 8. 尚待 G1 决定与批准

本文完成后仍明确未决：

1. `DEC-001 / G1-01`：Product 是否接受 `SCN-G1-001` 的 ICP、问题、地域、语言、币种和排除项；若修改任一项，本文与相关风险自动复审；
2. `G1-03`：Product、Ops、Engineering 是否逐项接受 `ACC-G1-001..017`、非目标和停止条件；
3. `G1-04`：运营、隐私、财务、安全、初次决定、独立申诉和停止权限的具名 owner/backup、冲突、SLO、培训与演练；
4. `G1-05`：目标辖区专业人员对实体、平台角色、劳动分类、合同层级/关键条款、支付路径、IP/内容边界与阻断结论的书面意见；
5. `G1-06`：产品/运营数据清单、目的/合法性、访问、保留、删除、备份、provider 和请求流程批准；
6. `DEC-002`, `DEC-006`, `DEC-010 / G1-07`：预算、容量、价格/服务费假设、项目/金额/周期/里程碑上限、工程成本/期限、最大损失与停止阈值；
7. `G1-08`：固定、可重建 revision 的当前代码、测试、安全、迁移、composition、依赖、环境与失败原件；
8. `G1-09`：Delivery 对本文 backlog revision、owner、ADR/contract 依赖、测试路径、rollout/rollback 和人工接管的批准；
9. `G1-10`：本范围触发的 Critical 逐项关闭、控制或以能力关闭延期；其余风险有 owner、期限、监测和有权限的接受者；
10. `DEC-005`, `DEC-009`, `DEC-023`, `DEC-024`, `DEC-025`, `DEC-026`：逐笔 Money Flow、九角色细则、单一主体安全默认和风险升级条件；
11. `DEC-033` 最终批准链：Product、Research/Evidence、Business/Finance 与独立 Risk reviewer 对限域 backlog、预算/期限、停止阈值和 G2 证据债务具名确认，Legal/Privacy/Security 各自签署其 G1 条件。

这些事项没有批准记录前，本文保持 `CANDIDATE`，G1 总状态保持 `NO-GO`。

## 9. 证据包与变更控制

每个 `EVD-*` 至少保存：

```text
Evidence ID / status:
Backlog / FND / PRD / UC / CAP / ACC references:
Code revision / branch / dirty status:
Contract / rule / schema / migration versions:
Environment and synthetic-data declaration:
Commands and raw outputs:
Failures, skipped/quarantined tests and owners:
Security/privacy/legal/operations limitations:
Observation / Interpretation / Decision / Uncertainty:
Reviewer / date / expiry / invalidation trigger:
```

以下变化使相关候选批准和证据自动失效并退回复审：ICP、场景、辖区、语言、币种、参与者类型、数据类别、项目/金额/周期上限、资金流、provider、合同、Consent、规则、Schema、迁移、owner/backup、预算、风险等级、测试环境或 code revision 变化；出现 Critical/High 事件、恢复失败、现实反证或证据不可重建也同样失效。

历史证据不得静默覆盖。范围变化必须追加决定，说明受影响主体、迁移/删除、Consent/合同影响、Gate 退回点和停止期间的责任。

## 10. 依据与当前结论

本文直接依据：

- [G1 创始人定向构建决定](/foundations/g1-direct-build-decision.md)：只替代研究前置，全部市场/效果假设保持 `E0`；
- [软件开发启动就绪度与决策入口](/foundations/readiness-and-start-decision.md)：G1/G2 唯一 Gate 与当前 `NO-GO`；
- [产品与首批试点定义](/foundations/product-and-pilot-definition.md)：首批角色、主旅程、排除、PRD 和停止条件；
- [要求与能力登记册](/foundations/requirements-capability-registry.md)：原子 `FND → CAP → PRD/UC` 唯一追踪基线；
- [软件交付章程](/foundations/software-delivery-charter.md)：Slice、逐 UC 验收、ADR、测试、DoR/DoD 和发布边界；
- [实现差距审计](/foundations/implementation-gap-assessment.md)：2026-08-09 历史且未验证的代码风险重采集清单；
- [风险、决定与假设登记册](/foundations/risk-decision-and-assumption-register.md)：当前风险、决定、假设状态唯一队列；
- [法律、合规与合同准备](/foundations/legal-compliance-and-contract-plan.md)与[商业、财务与进入市场计划](/foundations/business-finance-and-go-to-market.md)：不能由软件或本文替代的辖区、合同、支付、税务、预算与单位经济工作。

当前结论只有三条：

1. `SCN-G1-001` 是一个可撤销、只为构建使用的 `E0` 候选，不是市场或法律结论；
2. 当前只允许执行 `Slice 0` 的事实重采集、Critical 修复和合成验证，`Slice 1..4` 仍为 `BLOCKED-BY-G1`；
3. 无论实现进度如何，真实人、真实数据、合同、资金、现实权益决定和任何公开发布都继续为 `G2 NO-GO`。
