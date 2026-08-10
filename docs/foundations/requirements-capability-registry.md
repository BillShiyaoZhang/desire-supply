# Foundations 要求与能力登记册

> 文档状态：P0 唯一追踪基线 v0.1  
> 事实截止：2026-08-10，仅依据 `docs/foundations/`  
> 当前权威：本文是 foundations 范围内 `FND-* → CAP-* → 阶段/启动处置` 的唯一登记入口；规范正文仍以[Foundations 要求目录](/foundations/foundation-requirements.md)为准，能力定义仍以[技术能力地图](/foundations/technical-capability-map.md)为准。  
> 重要限制：本次没有检查代码、测试、运行环境、法律文件或现实效果；因此所有代码和现实状态均为 `UNVERIFIED`，不得从本文推导“已实现”。

## 0. 登记规则

### 0.1 三类状态必须分开

| 状态 | 回答的问题 |
| --- | --- |
| Normative | 要求是否已起草、审阅、批准、生效或被替代 |
| Delivery | 能力在 `DESIGN → CONTRACT → DOMAIN → MEMORY → POSTGRES → HTTP → COMPOSED → ENABLED` 的哪一层有当前证据 |
| Reality | 是否已 `OPERATED`，以及真实证据是否支持 `EFFECTIVE` |

一项能力可以 `DOMAIN` 完成而 `ENABLED/OPERATED/EFFECTIVE` 均为否。所有权、合同和成员权利也可以现实存在而没有产品投影；两种事实不能互相冒充。

### 0.2 本登记册的当前状态值

- `DOC-DESIGN`：本目录已有规范/目标能力设计；
- `AUDIT-PARTIAL`：2026-08-09 实现差距审计报告过部分代码证据，但本次未重新验证；
- `AUDIT-RED`：该审计报告过阻断性失败/缺口；
- `NO-CURRENT-EVIDENCE`：本目录没有代码或现实证据；
- `UNVERIFIED`：必须在固定 revision 或现实文件上重新采集；
- `DEFERRED-OFF`：当前阶段通过不激活来控制；
- `GATE-REQUIRED`：到指定 Gate 前必须取得证据。

### 0.3 来源分类

- `SRC`：直接整理社会契约/制度文件的规范主张；
- `RAT`：为使多个来源一致而规范化的要求；
- `SAFE`：为防止已识别伤害而派生的执行护栏。

分类不表示重要性。`SAFE` 仍可能是试点不可缺少的 Critical 控制。

### 0.4 更新记录的最低字段

```text
Requirement/Capability ID:
Normative source and class:
Primary beneficiary / prohibited outcome:
Applicable stage and disposition:
Owner / approver:
Delivery status by layer:
Evidence reference / revision / date / reviewer:
Operational/legal/effect status:
Open blockers and risks:
Next promotion condition:
Status expiry / review trigger:
```

任何状态证据缺 revision/现实文件、日期、审查人或适用范围，最多只能标为观察，不能晋级。

## 1. Capability 基线

`P1 处置`含义：

- `BUILD`：P1 主旅程需要最小可运行纵切；
- `GUARDRAIL`：不构建完整能力，但其禁止结果/人工流程从 P0/P1 生效；
- `OFF`：保持关闭，等待路线图激活证据。

| CAP | 能力 | 目标阶段 | P1 处置 | 本目录最强证据 | 2026-08-09 审计摘要（未复核） | 下一 Gate 证据 |
| --- | --- | --- | --- | --- | --- | --- |
| `CAP-S01` | Identity, Organization & Access | P0–P2 | `BUILD` | `DOC-DESIGN` | IAM 多层局部实现；持久 Session `AUDIT-RED` | G1 固定 revision 安全全绿；G2 浏览器/运营演练 |
| `CAP-S02` | Rule & Charter Publication | P0–P5 | `BUILD` 最小规则；其余渐进 | `DOC-DESIGN` | Taxonomy 可复用，foundations 规则链未闭合 | G1 规则/Schema 单一版本与旧决定复现 |
| `CAP-S03` | Audit, Decision & Event Evidence | P0–P2 | `BUILD` | `DOC-DESIGN` | Outbox 局部；统一决定/审计缺失 | G1 决定信封；G2 敏感/恢复/跨域演练 |
| `CAP-S04` | Data Rights & Information Governance | P0–P2 | `BUILD` 最小权利 | `DOC-DESIGN` | Consent 局部，完整权利为设计 | G1 数据清单；G2 真实可用权利旅程 |
| `CAP-S05` | Runtime & Production Composition | P0–P2 | `BUILD` | `DOC-DESIGN` | 内核/Outbox PG 局部，production composition 缺失 | G1 可重建基线；G2 provider/恢复/回滚 |
| `CAP-S06` | Web BFF & Accessible Product Shell | P1–P2 | `BUILD` | `DOC-DESIGN` | 无实际产品壳 | G2 浏览器、无障碍、代理/人工路径 |
| `CAP-S07` | Notification & Communication | P1–P2 | `BUILD` 最小事务通知 | `DOC-DESIGN` | 仅设计 | G2 投递失败、备用通道与敏感最小化 |
| `CAP-S08` | Controlled AI Gateway | 可选 P2+ | `OFF` | `DOC-DESIGN` | 无模型依赖是安全优势 | 单独 AI Gate；P1 关闭不影响旅程 |
| `CAP-C01` | Creator Profile | P0–P1 | `BUILD` | `DOC-DESIGN` | MVP 可运行、平台局部，HTTP/组合缺失 | G1 数据/推断红线关闭；G2 目的披露旅程 |
| `CAP-C02` | Demand & Public-Value Intake | P0–P1 | `BUILD` | `DOC-DESIGN` | MVP/平台局部，角色拆分与状态链缺失 | G1 九角色/排除/验收；G2 完整入口 |
| `CAP-C03` | Budget, Compensation & Fee Policy | P0–P1 | `BUILD` | `DOC-DESIGN` | MVP 预算闸门，平台无完整边界 | G1 价格/预算/隐私规则；G2 例外审计 |
| `CAP-C04` | Matching, Invitation & Selection | P0–P1 | `BUILD` | `DOC-DESIGN` | MVP 胚芽；平台无 PG/HTTP，attempt 隔离 `AUDIT-RED` | G1 隔离/双向/快照修复；G2 E2E |
| `CAP-C05` | Project, Agreement & Delivery | P1 | `BUILD` | `DOC-DESIGN` | 仅设计 | G1 contract/domain；G2 协议/变更/终止旅程 |
| `CAP-C06` | Funding, Payment & Reconciliation | P1–P2 | `BUILD` | `DOC-DESIGN` | 仅设计/marker，权威付款缺失 | G1 合法/provider 决定；G2 对账/未知/退款 |
| `CAP-C07` | Workspace, Messages & Files | P1–P2 | `BUILD` 最小文件/输入 | `DOC-DESIGN` | 仅设计 | G2 权限撤回、恶意内容、保留/导出 |
| `CAP-C08` | Trust, Safety, Dispute & Appeal | P0–P2 | `BUILD` 最小救济 | `DOC-DESIGN` | 仅设计/test double | G1 人工程序；G2 可运行独立申诉 |
| `CAP-C09` | Outcome, Review & Relationship | P0–P1 | `BUILD` | `DOC-DESIGN` | MVP 自报，权威事实/平台缺失 | G1 指标来源；G2 情境评价和成果路径 |
| `CAP-I01` | Civic Membership | P3 | `OFF` + 无自动成员护栏 | `DOC-DESIGN` | 当前设计不足 | P3 真实跨项目责任、多元审查与申诉 |
| `CAP-I02` | Contribution & Peer Review | P3 | `OFF`，P1 仅记录真实公共劳动 | `DOC-DESIGN` | Community 初步设计，无实现 | P3 来源/冲突/纠错/补偿证据 |
| `CAP-I03` | Contextual Reputation & Credentials | P3 | `GUARDRAIL` 无总分；正式凭证 `OFF` | `DOC-DESIGN` | 无专门实现 | P1 情境 Review；P3 携带/撤销/验证 |
| `CAP-I04` | Deliberation & Governance | P4/P5 | `OFF`，P0 临时授权/申诉护栏 | `DOC-DESIGN` | Community 普通提案设计不足 | P4 稳定成员、代表、规则发布和真实授权 |
| `CAP-I05` | Commons & Public Fund | P4 | `OFF` | `DOC-DESIGN` | 无独立上下文 | P4 真实公共劳动、资金、职责分离与会计 |
| `CAP-I06` | Stewardship Operations | P3/P4 | `GUARDRAIL`：P1 运营角色有期限/回避 | `DOC-DESIGN` | 无完整设计/实现 | P1 临时角色；P3 有偿公共职务证据 |
| `CAP-I07` | Charter & Core Asset Registry | P5 | `GUARDRAIL`：P0 临时资产/资本限制 | `DOC-DESIGN` | 无目标上下文 | G1 临时资产清单；P5 法律/章程结构 |
| `CAP-I08` | Capital, Partner & Dependency Transparency | P0–P5 | `GUARDRAIL` | `DOC-DESIGN` | 原则和少量指标设想 | G1 资金/伙伴登记与阈值；长期效果复盘 |
| `CAP-I09` | Portability, Federation & Legitimate Fork | P2/P5 | `BUILD` 个人退出最小；fork `OFF` | `DOC-DESIGN` | Data Rights 仅个人设计；fork 缺失 | G2 个人导出/接收；P5 合法分支 |
| `CAP-I10` | Member Economic Rights Projection | P5 | `OFF` | `DOC-DESIGN` | 无法律决定/实现 | P5 法定实体、会计、税务和成员理解 |
| `CAP-I11` | Mission Health | P0+ | `BUILD` 最小指标/复盘 | `DOC-DESIGN` | MVP 指标存在误导风险 | G1 指标目录；G2 权威事件/质性反例 |
| `CAP-I12` | Ecosystem Partnership & Collaboration Nodes | P0/P2/P4 | `GUARDRAIL`；正式节点 `OFF` | `DOC-DESIGN` | 无一等模型 | 使用前责任矩阵；P2 窄 Handoff；P4 自治节点 |

所有 Delivery/Reality 状态当前均为 `UNVERIFIED`；表中审计摘要只用于确定重采集范围。

## 2. 原子 FND 追踪

`阶段/处置`中的 `Now` 表示从 P0 作为行为/组织护栏生效，不表示软件能力完成。

### 2.1 人与协作

| FND | 来源/类 | 主要受益者与禁止结果 | Primary CAP | 阶段/处置 | G1/G2 证据入口 |
| --- | --- | --- | --- | --- | --- |
| `FND-HUM-001` | 社会契约第一条 / `SRC` | 所有人；禁止总分定义完整价值 | C01, I03, I11 | Now/P1 护栏 | `PRD-P1-002`, `PRD-P1-014`；无总分测试和内容复核 |
| `FND-HUM-002` | 社会契约第二条 / `SRC` | 创作者；禁止边界被覆盖与拒绝报复 | C01, C04, I11 | Now/P1 `BUILD` | `UC-P1-002`, `UC-P1-006`；拒绝趋势与运营审计 |
| `FND-HUM-003` | 社会契约第三条 / `RAT` | 双方/受益者；禁止不可理解的问题与结果 | C02, C05, C09 | P1 `BUILD` | `UC-P1-003`, `UC-P1-010`, `UC-P1-013`；理解测试 |
| `FND-HUM-004` | 总览/社会契约第三条 / `SRC` | 参与者；禁止用活跃消耗替代价值 | I11, S06 | Now 护栏 | 非目标、指标目录、UI/通知审查 |
| `FND-HUM-005` | 社会契约第一条 / `SRC` | 创作者；禁止固定职位/单标签 | C01, I03 | P1 护栏 | Profile 契约与展示测试 |
| `FND-HUM-006` | 总览第 3–4 节 / `SRC` | 社会公众；禁止夸大社会保障能力 | I11 | Now 护栏 | Claims review、招募/对外材料 |
| `FND-HUM-007` | 社会契约第二十七条 / `SRC` | 参与者；禁止唯一归属/全生活身份 | S01, I01, I12 | Now/P1 护栏 | Consent/招募、低强度/站外参与复盘 |
| `FND-COL-001` | 社会契约第四条 / `SRC` | 双方/受益者；禁止模糊需求进入匹配 | C02, C03 | P1 `BUILD` | `PRD-P1-003`, `PRD-P1-004`, `UC-P1-003` |
| `FND-COL-002` | 社会契约第五条 / `SRC` | 创作者；禁止无偿样稿/无限修改/低价竞标 | C02, C03, C04 | Now/P1 `BUILD` | Intake 排除、匹配/变更测试 |
| `FND-COL-003` | 社会契约第五条 / `SRC` | 合同各方；禁止范围/报酬静默变化 | C05 | P1 `BUILD` | `PRD-P1-008`, `PRD-P1-009`, `UC-P1-008`, `UC-P1-011` |
| `FND-COL-004` | 社会契约第六条 / `SRC` | 双方；禁止单向选择和拒绝惩罚 | C04 | P1 `BUILD` | `PRD-P1-007`, `UC-P1-006`, `UC-P1-007` |
| `FND-COL-005` | 社会契约第七条 / `SRC` | 双方；禁止只优化成交/活跃 | C09, I11 | P1 `BUILD` | `PRD-P1-014`；关系和再次合作复盘 |
| `FND-COL-006` | 经济宪法 2.1 / `RAT` | 创作者；禁止按效率压价 | C03, C05 | Now/P1 护栏 | 定价政策、协议/例外抽查 |
| `FND-COL-007` | 社会契约第十一/十八条 / `SRC` | 共同体；禁止采购额购买政治权 | C03, I04, I08 | Now 护栏 | 客户/资金条款登记与权限测试 |
| `FND-COL-008` | 差距审计付款风险 / `SAFE` | 收款方；禁止请求/自报冒充付款 | C06 | P1 `BUILD` | `PRD-P1-005`, `PRD-P1-011`, `UC-P1-004`, `UC-P1-012` |
| `FND-COL-009` | 社会契约第十条与第十六条 / `RAT` | 重大决定受影响者；禁止无人负责/无救济 | S03, C08 | P0/P1 `BUILD` | 决定模板、`UC-P1-014`、独立申诉 |
| `FND-COL-010` | 社会契约第二十八条 / `SRC` | 权利人/受益者；禁止默认公司化/专有化 | C02, C05, C09, I07 | Now/P1 `BUILD` | 成果路径、权利影响矩阵、`UC-P1-011`, `UC-P1-013` |

### 2.2 数据、声誉、AI 与规则

| FND | 来源/类 | 主要受益者与禁止结果 | Primary CAP | 阶段/处置 | G1/G2 证据入口 |
| --- | --- | --- | --- | --- | --- |
| `FND-RGT-001` | 社会契约第八条 / `SRC` | 数据主体；禁止不知用途/期限/影响 | S01, S04 | P0/P1 `BUILD` | 数据清单、`UC-P1-001`, `UC-P1-015`；理解测试 |
| `FND-RGT-002` | 社会契约第八条 / `SRC` | 数据主体；禁止权利仅纸面 | S04 | P0/P1 `BUILD` | 权利队列与 `UC-P1-015` 演练 |
| `FND-RGT-003` | 社会契约第八/二十五条 / `SRC` | 贡献者/第三方；禁止锁定或越权携带 | S04, I03, I09 | P1 最小 `BUILD` | 导出格式/第三方过滤/接收验证 |
| `FND-RGT-004` | 差距审计快照风险 / `SAFE` | 数据主体；禁止不可变审计吞没删除 | S03, S04 | P0/P1 `BUILD` | 稳定索引/可删载荷、备份/hold 测试 |
| `FND-RGT-005` | 技术能力地图退出旅程 / `SAFE` | 离开者；禁止不可理解/不可接收导出 | S04, I09 | P1 `BUILD` | `UC-P1-015`、完整性与接收演练 |
| `FND-REP-001` | 社会契约第九条 / `SRC` | 被评价者；禁止全局总分 | C09, I03 | P1 护栏/P3 完整 | `PRD-P1-014`、展示和排序禁令 |
| `FND-REP-002` | 成员制度第 3 节 / `RAT` | 被评价者；禁止陈旧证据永久支配 | I03, S04 | P1 护栏/P3 完整 | 时间背景、更正/删除分层 |
| `FND-REP-003` | 成员制度第 3 节 / `RAT` | 被评价者；禁止无回应/撤销 | C09, I03 | P1 最小 `BUILD` | `UC-P1-013`、回应、更正和争议 |
| `FND-REP-004` | 社会契约第九条 / `SRC` | 共同体；禁止声誉代币/买权 | I02, I03, I04 | Now 护栏/P3 | 数据模型/规则/对外材料禁令 |
| `FND-AI-001` | 社会契约第十条 / `SRC` | 重大利益受影响者；禁止 AI 最终决定 | S08, C08 | Now `OFF` 护栏 | P1 AI 关闭测试；启用另过 Gate |
| `FND-AI-002` | 技术能力地图 S08 / `SAFE` | 数据主体/决定对象；禁止无记录模型使用 | S08, S03 | `OFF`；启用时 `BUILD` | AI impact assessment/评测/人工确认 |
| `FND-RUL-001` | 社会契约第十六条 / `SRC` | 规则影响者；禁止暗规则 | S02, S03 | P0/P1 `BUILD` | 规则版本/理由/生效/历史查询 |
| `FND-RUL-002` | 经济宪法 5.4 / `SAFE` | 全体；禁止投票直写生产 | S02, I04 | P1 候选链护栏/P4 | 目标域验证/批准/发布边界 |
| `FND-RUL-003` | 技术能力地图规则链 / `SAFE` | 旧决定参与者；禁止规则偷改 | S02, S03 | P0/P1 `BUILD` | 影响、异议、hash、回滚与复现 |
| `FND-SEP-001` | 社会契约第十七条 / `SRC` | 权力影响者；禁止制定/执行/申诉无限集中 | S03, C08, I04, I06 | P0/P1 护栏 | 授权/RACI/冲突/独立复核/审计 |

### 2.3 成员与开放

| FND | 来源/类 | 主要受益者与禁止结果 | Primary CAP | 阶段/处置 | 当前/未来证据入口 |
| --- | --- | --- | --- | --- | --- |
| `FND-MEM-001` | 社会契约第十九条 / `SRC` | 共同体；禁止注册/购买自动入会 | I01, S01 | Now 护栏；P3 `OFF` | P1 无 Civic 权；P3 独立生命周期 |
| `FND-MEM-002` | 成员制度第 1 节 / `RAT` | 成员/职务承担者；禁止成员等级吞职务 | I01, I06 | P3 `OFF` | P3 成员/任期/暂停/申诉证据 |
| `FND-MEM-003` | 成员制度第 1 节 / `SRC` | 成员；禁止永久守护等级 | I06 | P1 临时角色护栏；P3 完整 | 授权到期/轮换/补偿/回避 |
| `FND-MEM-004` | 成员制度第 2 节 / `SRC` | 贡献者；禁止贡献无来源/混成交易额 | I02 | P1 记录；P3 完整 | 公共劳动事实/角色/时间/影响 |
| `FND-MEM-005` | 成员制度第 2 节 / `SRC` | 共同体；禁止贡献币/线性票权 | I01, I02, I04 | Now 护栏/P3 | 数据/规则无自动兑换 |
| `FND-MEM-006` | 社会契约第二十条 / `SRC` | 新人；禁止标准保护既得优势 | I02, I11 | P1 护栏/P3 | 排除理由、专业标准审计 |
| `FND-MEM-007` | 社会契约第二十一条 / `SRC` | 新人；禁止只有无偿证明机会 | C03, I02, I05, I11 | P1 观察/P3–P4 | 首次付费时间、正常报酬、导师证据 |
| `FND-MEM-008` | 成员制度 6.3 / `SRC` | 被评议者；禁止单一/冲突评审 | C08, I02, I06 | P1 冲突护栏/P3 | 评审来源、回避和复核 |
| `FND-MEM-009` | 社会契约第十一/十八条 / `SRC` | 共同体；禁止财富买政治权 | I01, I04, I10 | Now 护栏/P3–P5 | 权限/经济/成员标识分离 |
| `FND-MEM-010` | 社会契约第二十二条 / `SRC` | 开放参与者；禁止身份纯洁性边界 | I01, I11 | Now/P3 | 行为规则、合法公平审查 |
| `FND-MEM-011` | 成员制度第 5/8.4 节 / `SRC` | 新人/后来成员；禁止创始历史垄断 | S03, I02, I04 | P1 决定记忆/P3–P4 | 公开复盘、反对/质疑渠道 |
| `FND-MEM-012` | 成员制度 6.6 / `SRC` | 新人/公共受益者；禁止零和分配 | C02, I05, I11 | P1 研究/P4 公共项目 | 需求/公共价值/生态容量证据 |
| `FND-MEM-013` | 社会契约第二十三条 / `SRC` | 所有参与者；禁止欺骗/漏洞伤害 | C08, S02 | Now/P1 | 行为规则、协议、调查/补救 |

### 2.4 支持与协作节点

| FND | 来源/类 | 主要受益者与禁止结果 | Primary CAP | 阶段/处置 | 当前/未来证据入口 |
| --- | --- | --- | --- | --- | --- |
| `FND-DEP-001` | 社会契约第二十六条 / `SRC` | 支持接受者；禁止用基本支持换忠诚/权利 | C08, I08, I12 | Now 护栏 | 伙伴协议、独立同意/替代/申诉 |
| `FND-DEP-002` | 成员制度 5.1 / `SAFE` | 全体；禁止一个总状态级联撤权 | S01, S04, C06, C08, I01, I06 | P0/P1 `BUILD` | 独立 ID/生命周期/blast-radius 测试 |
| `FND-DEP-003` | 社会契约第二十六条 / `RAT` | 支持接受者；禁止无预告撤回重要支持 | C08, I12 | 使用伙伴时护栏 | 理由、预告、过渡、外部事实源 |
| `FND-DEP-004` | 成员制度 5.1 / `SAFE` | 数据主体；禁止支持敏感数据扩用 | S04, I12 | P0/P1 护栏 | 目的隔离/访问/事件/审计 |
| `FND-DEP-005` | 成员制度 5.2/9 / `RAT` | 参与者；禁止依赖或全生活图谱 | I08, I11 | P0+ 指标/质性 | 自愿调查、汇总趋势、最小数据 |
| `FND-NOD-001` | 社会契约第二十七条 / `SRC` | 受益者/参与者；禁止机构身份冒充授权 | C02, I12 | P0/P1 护栏 | `PRD-P1-003`、九角色责任矩阵 |
| `FND-NOD-002` | 成员制度 5.3 / `SRC` | 参与者/共同体；禁止资源买权/数据 | I08, I12 | 伙伴使用前 | 版本协议、条件、期限、退出/摘要 |
| `FND-NOD-003` | 成员制度 5.4 / `SRC` | 权力弱势方；禁止形式同意掩盖强迫 | C08, I12 | 伙伴使用前 | 站外待遇、替代路径、绕行申诉演练 |
| `FND-NOD-004` | 成员制度 5.3 / `SRC` | 线下参与者；禁止资源无安全/公平规则 | I12 | 线下使用前 | 准入、排期、安全、无障碍、IP/维护 |
| `FND-NOD-005` | 社会契约第二十七条 / `RAT` | 节点参与者；禁止地方自治降权/停摆吞权 | I12, I09 | P1 连续性护栏；P4 节点 | 停摆演练、最低权利、跨节点申诉 |
| `FND-NOD-006` | 技术能力地图 S06/I12 / `SAFE` | 辅助参与者；禁止共享密码/代同意 | S01, S06, I12 | 使用代理前 | 范围/时限/撤回/真实 actor 测试 |

### 2.5 试点安全、公平、合同、运营与证据

| FND | 来源/类 | 主要受益者与禁止结果 | Primary CAP | 阶段/处置 | G1/G2 证据入口 |
| --- | --- | --- | --- | --- | --- |
| `FND-SAF-001` | Requirements 6.1 / `SAFE` | 全体；禁止无规则/无渠道处理伤害 | C08, S02, S06 | P0/P1 `BUILD` | 安全政策、举报入口、`UC-P1-014`、理解测试 |
| `FND-SAF-002` | Requirements 6.1 / `SAFE` | 拒绝/举报/权利请求者；禁止报复 | C08, S03, I11, I12 | P0/P1 `BUILD` | 保密/绕行渠道、机会/权限趋势、补救 |
| `FND-SAF-003` | GOV-009/DEP-002 推导 / `SAFE` | 被临时限制者；禁止无限/级联措施 | C08, S03 | P0/P1 `BUILD` | 最小范围/到期/复核/blast-radius 测试 |
| `FND-SAF-004` | COL-009 推导 / `SAFE` | 实质处置对象；禁止无通知/理由/回应 | C08, S03 | P0/P1 `BUILD` | 决定信封、证据、通知、回应/补救 |
| `FND-SAF-005` | SEP-001 推导 / `SAFE` | 申诉人；禁止原决定自我复核 | C08, S03, I06 | P0 人工/P1 `BUILD` | 具名独立 reviewer、权限/冲突/恢复演练 |
| `FND-SAF-006` | NOD-003/研究风险推导 / `SAFE` | 未成年人/脆弱群体；禁止形式同意 | C08, S04, I12 | P0 排除；未来另 Gate | 年龄/伦理/法律评估、保护/替代/停止 |
| `FND-SAF-007` | 技术能力地图威胁/运行证据 / `SAFE` | 事件受影响者；禁止无响应/二次泄漏 | S03, S05, C08 | P0 人工/P1 `BUILD` | 分级、响应、通知、恢复、复盘演练 |
| `FND-EQU-001` | `FND-MEM-006`, `FND-MEM-007`, `FND-MEM-008`, `FND-MEM-009`, `FND-MEM-010` 推导 / `SAFE` | 新人/受保护群体；禁止无关歧视 | C01, C02, C04, C08, I11 | P0/P1 护栏 | 合法政策、必要性、代理变量和准入审计 |
| `FND-EQU-002` | Mission Health 隐私约束 / `SAFE` | 敏感群体数据主体；禁止群体指标反伤个体 | S04, I11 | P0/P1 护栏 | 目的/合法基础、最小数据、小样本/访问 |
| `FND-EQU-003` | S06/NOD-006 推导 / `SAFE` | 无障碍/语言/数字障碍参与者 | S06, S07, S04, C08, I12 | P0 人工/P1 `BUILD` | 目标标准、辅助技术/清晰语言/替代路径 |
| `FND-CTR-001` | 技术能力地图第 9 节 / `SAFE` | 合同/服务参与者；禁止数据库自创法律关系 | S01, S03, I08 | P0 法律 `GATE` | Legal Scope Memo、实体/角色/授权/许可 |
| `FND-CTR-002` | `FND-COL-003`, `FND-COL-010` 推导 / `SAFE` | 合同当事人；禁止异版/不完整协议 | C05, S02 | P1 `BUILD` | `PRD-P1-008`, `PRD-P1-009`, `UC-P1-008`, `UC-P1-011`；合同理解 |
| `FND-CTR-003` | 技术能力地图第 9 节 / `SAFE` | 劳动者/客户/公共劳动者；禁止标签规避义务 | C03, C05, I06, I10 | P0 法律 `GATE` | 劳动/税务/消费者意见与实际行为抽查 |
| `FND-CTR-004` | `FND-COL-008`, `FND-ECO-012` 推导 / `SAFE` | 付款各方；禁止无权代收/托管/分账 | C06 | P0 法律 + P1 `BUILD` | provider 和法律方案、`UC-P1-004`, `UC-P1-012`；对账 |
| `FND-CTR-005` | 合同一致性风险 / `SAFE` | 全体；禁止文书承诺与现实行为分裂 | S02, S03, C05, C06 | P0/P1 护栏 | 跨职能合同/界面/运营/账簿一致性检查 |
| `FND-OPS-001` | 落地路线图运营门槛 / `SAFE` | 权利/服务请求者；禁止无人/无容量负责 | S03, S05, S06, C08, I06 | P0 人工/P1 `BUILD` | 具名 owner/backup、SLO、队列、培训、runbook |
| `FND-OPS-002` | 技术能力地图 provider 边界 / `SAFE` | 供应商/伙伴影响者；禁止外包责任黑洞 | S04, S05, I08, I12 | 使用前 `GATE` | 尽调/合同/SLA/事件/删除/退出/替代 |
| `FND-OPS-003` | `FND-DEP-003`, `FND-NOD-005`, `FND-EXIT-001` 推导 / `SAFE` | 已参与者；禁止停摆吞掉义务与权利 | S05, S07, S04, I09, I12 | P0 人工/P1 `BUILD` | `UC-P1-017`、人工接管、恢复、wind-down 演练 |
| `FND-OPS-004` | 启动 Gate 推导 / `SAFE` | 所有试点参与者；禁止无限“试点”豁免 | S03, S05, I11 | P0/P1 `GATE` | 批次/金额/数据/期限/损失上限与暂停权 |
| `FND-EVD-001` | 研究计划/关系强迫推导 / `SAFE` | 研究参与者；禁止研究换机会或解释冒充事实 | S01, S04, I11 | P0 `BUILD` 人工 | 同意、补偿、Observation/Interpretation/Decision |
| `FND-EVD-002` | MIS-004/差距审计推导 / `SAFE` | 公众/参与者；禁止设计/测试/自报冒充效果 | S03, I11 | P0/P1 `BUILD` | Claims registry、证据等级/日期/范围/限制 |
| `FND-EVD-003` | 路线图阶段报告 / `SAFE` | 公众/后来参与者；禁止隐藏不利证据 | S03, I11 | P0+ `BUILD` | 退出/失败/事件/覆盖/伤害与反例报告 |

### 2.6 治理

| FND | 来源/类 | 主要受益者与禁止结果 | Primary CAP | 阶段/处置 | 当前/未来证据入口 |
| --- | --- | --- | --- | --- | --- |
| `FND-GOV-001` | 社会契约第十七条 / `SRC` | 全体；禁止运营/成员/使命权力混合 | I04, I06, I07 | P0 临时 RACI；P4–P5 | 授权矩阵、章程/法律权力 |
| `FND-GOV-002` | 社会契约第十六条 / `SRC` | 成员；禁止只有投票按钮 | I04 | `OFF` 至 P4 | 信息/提案/审议/代表/监督/申诉/退出 |
| `FND-GOV-003` | 经济宪法第 6 节 / `RAT` | 成员；禁止财富/交易加权 | I01, I04 | `OFF` 至 P4；Now 护栏 | 资格快照/一人一票候选规则 |
| `FND-GOV-004` | 成员制度第 4 节 / `SRC` | 成员；禁止永久代表 | I04, I06 | P1 临时角色；P4 正式 | 任期/轮换/替补/撤回/冲突 |
| `FND-GOV-005` | 经济宪法 5.4 / `SRC` | 全体；禁止高风险事项降级 | S02, I04, I07 | P1 规则分类护栏/P4–P5 | 事项分类和权限测试 |
| `FND-GOV-006` | 社会契约第二十四条 / `SRC` | 受影响群体；禁止简单多数改宪法 | I04, I07 | `OFF` 至 P5 | 多方/跨群体/影响/冷静期/法律完成 |
| `FND-GOV-007` | 经济宪法 5.3 / `RAT` | 后来成员；禁止守护机构永久主权 | I06, I07 | `OFF` 至 P5 | 延迟/复议边界、最终程序 |
| `FND-GOV-008` | 经济宪法 5.4 / `SAFE` | 成员；禁止候选规则成为无效咨询 | S02, I04 | `OFF` 至 P4 | 发布者理由/时限/复议/执行追踪 |
| `FND-GOV-009` | 技术能力地图制度威胁 / `SAFE` | 权利受影响者；禁止无限紧急权 | C08, I04, I06 | P0/P1 安全护栏 | 最小范围/自动到期/独立事后审查 |

### 2.7 经济、使命与退出

| FND | 来源/类 | 主要受益者与禁止结果 | Primary CAP | 阶段/处置 | 当前/未来证据入口 |
| --- | --- | --- | --- | --- | --- |
| `FND-ECO-001` | 经济宪法第 2 节 / `SRC` | 参与者/共同体；禁止三层经济混账/混权 | C06, I05, I10 | P1 交易分账；P4/P5 完整 | 账目/权限/指标分离 |
| `FND-ECO-002` | 经济宪法 2.2 / `SRC` | 公共受益者；禁止公共资金不透明 | I05, C06 | `OFF` 至 P4；若早用则先完整控制 | 来源/限制/预算/冲突/付款/结果 |
| `FND-ECO-003` | 社会契约第十三条 / `SRC` | 公共劳动者；禁止长期无偿维护 | I02, I05, I06 | P1 记录成本；P3/P4 补偿 | 工时/角色/资格/报酬与复盘 |
| `FND-ECO-004` | 经济宪法 2.2 / `SRC` | 新人/公共问题；禁止公共预算只服务强支付方 | I05, I11 | `OFF` 至 P4 | 预算方向/受益者/成果/公平复盘 |
| `FND-ECO-005` | 经济宪法 2.3 / `SRC` | 成员/公共利益；禁止网络价值只归资本 | I07, I10 | P0 资本护栏；P5 法律结构 | 资产/权利/实体/救济，不用 DB 代替 |
| `FND-ECO-006` | 经济宪法第 8 节 / `SRC` | 共同体；禁止核心使命资产被外围出售 | I07, I09 | P0 临时清单；P5 完整 | 资产持有人/许可/转让限制/分支 |
| `FND-ECO-007` | 社会契约第十八条 / `SRC` | 共同体；禁止资本无限回报/治理 | I08, I10 | P0 条款护栏；P5 | 融资法律文件/期限/上限/转让 |
| `FND-ECO-008` | 经济宪法第 7 节 / `SRC` | 成员/公众；禁止剩余分配暗箱 | I05, I10, I11 | P1 成本透明；P4/P5 完整 | 经营/公共/成员/资本分账和报告 |
| `FND-ECO-009` | 成员制度 8.2 / `SRC` | 共同体；禁止单一资源事实否决 | I08, I11 | P0+ 护栏 | 集中度/条件/替代/压力复盘 |
| `FND-ECO-010` | 成员制度第 7/8 节 / `SRC` | 成员/公众；禁止隐藏资金附带条件 | I08, S03 | P0+ 护栏 | 资金登记/适当公开/冲突/批准 |
| `FND-ECO-011` | 经济宪法 2.3/第 3 节 / `SAFE` | 成员/投资者；禁止数据库自创法律权益 | I10 | `OFF` 至 P5 | 公司/证券/税务/劳动/会计意见 |
| `FND-ECO-012` | 技术能力地图公共资金威胁 / `SAFE` | 资金受益者；禁止一人申请/批/付/审 | C06, I05, S03 | P1 付款分离；P4 公共资金 | 授权/RACI/审计/真实演练 |
| `FND-MIS-001` | 社会契约第十四条 / `SRC` | 参与者/使命；禁止只用收入增长评价 | I11 | P0/P1 `BUILD` | 指标目录、权威事实、质性证据 |
| `FND-MIS-002` | 社会契约第十四条 / `RAT` | 参与者；禁止使命恶化仍扩张 | I11, I04 | P0/P1 护栏 | 阈值/owner/暂停/阶段报告 |
| `FND-MIS-003` | 落地路线图 1.3 / `SAFE` | 权力影响者；禁止扩权无培训/撤回 | S03, C08, I06 | P0+ 护栏 | 每个权限的培训/审计/到期/申诉 |
| `FND-MIS-004` | 成员制度第 9 节 / `RAT` | 公众/参与者；禁止只发有利结果 | I11, S03 | P0+ `BUILD` | 口径/样本/反例/伤害/公开限制 |
| `FND-EXIT-001` | 社会契约第二十五条 / `SRC` | 个体；禁止退出贬低/锁定 | S04, I03, I09 | P1 `BUILD` | `UC-P1-015`, `UC-P1-016`；凭证、数据和历史分离 |
| `FND-EXIT-002` | 社会契约第二十五条 / `SRC` | 偏离使命的成员；禁止只有删号自由 | I07, I09 | P0 许可/资产护栏；P5 `OFF` | 许可/公共知识/第三方权利/接收演练 |
| `FND-EXIT-003` | 经济宪法第 8 节 / `RAT` | 反对者；禁止出售/控制变化无保护 | I07, I09, I10 | P0 交易红线；P5 | 信息/权益/迁移/分支/法律文件 |

## 3. P1 追踪链

P1 backlog 必须使用以下链，禁止只引用一个族或 Capability 名称：

```text
Atomic FND ID
→ one or more exact Product requirement IDs
→ one or more exact Use case IDs
→ Capability and owner
→ ADR / API-event-data contract / rule version
→ acceptance and tests by layer
→ release flag / batch scope
→ operating owner/runbook/legal artifact
→ mission/effect evidence and adverse evidence
```

当前产品级映射入口如下。表内只使用完整、稳定的 ID；逗号表示多个独立引用，不表示范围、通配或合并要求。

| PRD | 逐项 FND | 逐项 Use case | 逐项 CAP |
| --- | --- | --- | --- |
| `PRD-P1-001` | `FND-RGT-001`, `FND-HUM-007`, `FND-EVD-001`, `FND-EQU-003`, `FND-DEP-002`, `FND-EXIT-001`, `FND-NOD-006` | `UC-P1-001`, `UC-P1-018`, `UC-P1-019`, `UC-P1-020`, `UC-P1-021` | `CAP-S01`, `CAP-S04` |
| `PRD-P1-002` | `FND-HUM-001`, `FND-HUM-002`, `FND-HUM-005`, `FND-RGT-001` | `UC-P1-002` | `CAP-C01`, `CAP-S04` |
| `PRD-P1-003` | `FND-HUM-003`, `FND-COL-001`, `FND-NOD-001`, `FND-MEM-012` | `UC-P1-003` | `CAP-C02` |
| `PRD-P1-004` | `FND-COL-001`, `FND-COL-002`, `FND-MEM-013`, `FND-EQU-001` | `UC-P1-003` | `CAP-C02`, `CAP-C03`, `CAP-C08` |
| `PRD-P1-005` | `FND-COL-008`, `FND-CTR-004`, `FND-ECO-001` | `UC-P1-004` | `CAP-C06` |
| `PRD-P1-006` | `FND-COL-002`, `FND-COL-004`, `FND-RUL-001`, `FND-RUL-003`, `FND-MEM-006`, `FND-EQU-001` | `UC-P1-005` | `CAP-C04`, `CAP-S02`, `CAP-S03` |
| `PRD-P1-007` | `FND-HUM-002`, `FND-COL-004`, `FND-SAF-002` | `UC-P1-006`, `UC-P1-007` | `CAP-C04`, `CAP-I11` |
| `PRD-P1-008` | `FND-COL-003`, `FND-COL-006`, `FND-COL-009`, `FND-CTR-002` | `UC-P1-008`, `UC-P1-009` | `CAP-C05`, `CAP-C06` |
| `PRD-P1-009` | `FND-COL-003`, `FND-COL-010`, `FND-CTR-002` | `UC-P1-011` | `CAP-C05` |
| `PRD-P1-010` | `FND-HUM-003`, `FND-COL-009`, `FND-COL-010`, `FND-CTR-002` | `UC-P1-010` | `CAP-C05`, `CAP-C09` |
| `PRD-P1-011` | `FND-COL-008`, `FND-ECO-001`, `FND-ECO-008`, `FND-ECO-012`, `FND-CTR-004` | `UC-P1-012` | `CAP-C06`, `CAP-S03` |
| `PRD-P1-012` | `FND-COL-009`, `FND-SEP-001`, `FND-GOV-009`, `FND-SAF-001`, `FND-SAF-002`, `FND-SAF-003`, `FND-SAF-004`, `FND-SAF-005`, `FND-SAF-007`, `FND-EQU-001`, `FND-EQU-003`, `FND-DEP-001`, `FND-NOD-003`, `FND-MEM-008`, `FND-MEM-013`, `FND-MIS-003` | `UC-P1-014` | `CAP-C08`, `CAP-S03` |
| `PRD-P1-013` | `FND-RGT-001`, `FND-RGT-002`, `FND-RGT-003`, `FND-RGT-004`, `FND-RGT-005`, `FND-REP-002`, `FND-EXIT-001`, `FND-EQU-002`, `FND-EQU-003`, `FND-DEP-004` | `UC-P1-015`, `UC-P1-016` | `CAP-S04`, `CAP-I09` |
| `PRD-P1-014` | `FND-HUM-001`, `FND-COL-005`, `FND-COL-010`, `FND-REP-001`, `FND-REP-002`, `FND-REP-003`, `FND-REP-004`, `FND-MIS-001` | `UC-P1-013` | `CAP-C09`, `CAP-I03` |
| `PRD-P1-015` | `FND-COL-009`, `FND-RGT-004`, `FND-RUL-001`, `FND-RUL-002`, `FND-RUL-003`, `FND-SEP-001`, `FND-MEM-003`, `FND-MEM-004`, `FND-MEM-007`, `FND-MEM-011`, `FND-DEP-005`, `FND-EQU-002`, `FND-CTR-005`, `FND-OPS-001`, `FND-EVD-002`, `FND-EVD-003`, `FND-GOV-001`, `FND-GOV-004`, `FND-GOV-005`, `FND-ECO-003`, `FND-ECO-008`, `FND-ECO-009`, `FND-ECO-010`, `FND-ECO-012`, `FND-MIS-001`, `FND-MIS-002`, `FND-MIS-003`, `FND-MIS-004` | `UC-P1-025` | `CAP-S02`, `CAP-S03` |
| `PRD-P1-016` | `FND-DEP-001`, `FND-DEP-002`, `FND-DEP-003`, `FND-NOD-002`, `FND-NOD-003`, `FND-NOD-005`, `FND-EXIT-001`, `FND-SAF-007`, `FND-OPS-001`, `FND-OPS-002`, `FND-OPS-003`, `FND-OPS-004` | `UC-P1-017` | `CAP-S05`, `CAP-C06`, `CAP-C08`, `CAP-I12` |
| `PRD-P1-017` | `FND-HUM-004`, `FND-HUM-007`, `FND-NOD-006`, `FND-SAF-001`, `FND-EQU-001`, `FND-EQU-003`, `FND-OPS-001` | `UC-P1-022` | `CAP-S06` |
| `PRD-P1-018` | `FND-RUL-001`, `FND-SAF-004`, `FND-EQU-003`, `FND-CTR-005`, `FND-OPS-001`, `FND-OPS-002`, `FND-OPS-003` | `UC-P1-023` | `CAP-S07` |
| `PRD-P1-019` | `FND-COL-003`, `FND-RGT-001`, `FND-RGT-004`, `FND-DEP-004`, `FND-CTR-002`, `FND-OPS-002` | `UC-P1-024` | `CAP-C07` |

### 3.1 原子 P1 处置表

本表是每个 Atomic FND ID 的 P1 软件追踪处置。`N/A` 只表示当前 P1 软件 Use case 不适用，后面的理由是仍须执行的阶段边界或非软件工件；它不取消该规范要求。每一行必须在需求变更时独立复核，不能用族名、范围或通配符代替。

| Atomic FND | P1 处置 | Exact PRD | Exact UC | 处置说明 |
| --- | --- | --- | --- | --- |
| `FND-HUM-001` | `BUILD` | `PRD-P1-002`, `PRD-P1-014` | `UC-P1-002`, `UC-P1-013` | Profile 与情境评价均不得形成总分。 |
| `FND-HUM-002` | `BUILD` | `PRD-P1-002`, `PRD-P1-007` | `UC-P1-002`, `UC-P1-006`, `UC-P1-007` | 边界、拒绝和撤回均可核验。 |
| `FND-HUM-003` | `BUILD` | `PRD-P1-003`, `PRD-P1-010` | `UC-P1-003`, `UC-P1-010` | 需求和验收结果必须可理解。 |
| `FND-HUM-004` | `GUARDRAIL` | `PRD-P1-017` | `UC-P1-022` | 产品壳不得以活跃消耗替代价值。 |
| `FND-HUM-005` | `BUILD` | `PRD-P1-002` | `UC-P1-002` | Profile 支持多角色和情境字段。 |
| `FND-HUM-006` | `N/A` | `N/A` | `N/A` | P1 由对外主张登记与人工内容审查执行，不是产品 Use case。 |
| `FND-HUM-007` | `BUILD` | `PRD-P1-001`, `PRD-P1-017` | `UC-P1-001`, `UC-P1-020`, `UC-P1-021`, `UC-P1-022` | 组织参与、退出和辅助路径不得制造唯一归属。 |
| `FND-COL-001` | `BUILD` | `PRD-P1-003`, `PRD-P1-004` | `UC-P1-003` | 需求完整性在进入匹配前验收。 |
| `FND-COL-002` | `BUILD` | `PRD-P1-004`, `PRD-P1-006` | `UC-P1-003`, `UC-P1-005` | 排除无偿样稿、无限修改和低价竞标。 |
| `FND-COL-003` | `BUILD` | `PRD-P1-008`, `PRD-P1-009`, `PRD-P1-019` | `UC-P1-008`, `UC-P1-011`, `UC-P1-024` | 协议、变更及相关文件保持同版。 |
| `FND-COL-004` | `BUILD` | `PRD-P1-007` | `UC-P1-006`, `UC-P1-007` | 邀请与选择保持双向且拒绝无惩罚。 |
| `FND-COL-005` | `BUILD` | `PRD-P1-014` | `UC-P1-013` | 成果与关系复盘不以成交量替代。 |
| `FND-COL-006` | `GUARDRAIL` | `PRD-P1-008` | `UC-P1-008` | 协议签署前显示价格依据和例外。 |
| `FND-COL-007` | `N/A` | `N/A` | `N/A` | P1 不开放政治治理；采购与资金不得赋予政治权限，由权限矩阵和合同审查执行。 |
| `FND-COL-008` | `BUILD` | `PRD-P1-005`, `PRD-P1-011` | `UC-P1-004`, `UC-P1-012` | 付款以 provider 与对账事实为准。 |
| `FND-COL-009` | `BUILD` | `PRD-P1-012`, `PRD-P1-015` | `UC-P1-014`, `UC-P1-025` | 重大决定必须有责任、证据和救济。 |
| `FND-COL-010` | `BUILD` | `PRD-P1-003`, `PRD-P1-009`, `PRD-P1-010`, `PRD-P1-014` | `UC-P1-003`, `UC-P1-011`, `UC-P1-010`, `UC-P1-013` | 权利影响贯穿需求、变更、交付和结果。 |
| `FND-RGT-001` | `BUILD` | `PRD-P1-001`, `PRD-P1-002`, `PRD-P1-013`, `PRD-P1-019` | `UC-P1-001`, `UC-P1-002`, `UC-P1-015`, `UC-P1-024` | 采集点逐项披露用途、期限和影响。 |
| `FND-RGT-002` | `BUILD` | `PRD-P1-013` | `UC-P1-015` | 权利请求必须形成可完成队列。 |
| `FND-RGT-003` | `BUILD` | `PRD-P1-013` | `UC-P1-015`, `UC-P1-016` | 导出过滤第三方权利并验证可接收性。 |
| `FND-RGT-004` | `BUILD` | `PRD-P1-013`, `PRD-P1-015`, `PRD-P1-019` | `UC-P1-015`, `UC-P1-025`, `UC-P1-024` | 稳定索引与可删载荷分离。 |
| `FND-RGT-005` | `BUILD` | `PRD-P1-013` | `UC-P1-015`, `UC-P1-016` | 导出必须可理解并能被接收。 |
| `FND-REP-001` | `GUARDRAIL` | `PRD-P1-014` | `UC-P1-013` | 评价仅在项目情境展示。 |
| `FND-REP-002` | `GUARDRAIL` | `PRD-P1-013`, `PRD-P1-014` | `UC-P1-015`, `UC-P1-013` | 时间背景、更正和删除分层可核验。 |
| `FND-REP-003` | `BUILD` | `PRD-P1-014` | `UC-P1-013` | 被评价者可回应、更正和争议。 |
| `FND-REP-004` | `GUARDRAIL` | `PRD-P1-014` | `UC-P1-013` | 验收明确禁止声誉代币、总分和买权。 |
| `FND-AI-001` | `N/A` | `N/A` | `N/A` | P1 AI 保持关闭；任何启用必须走独立 AI Gate。 |
| `FND-AI-002` | `N/A` | `N/A` | `N/A` | P1 不运行模型，因此无模型事件；启用后必须新增专用 PRD 与 UC。 |
| `FND-RUL-001` | `BUILD` | `PRD-P1-006`, `PRD-P1-015`, `PRD-P1-018` | `UC-P1-005`, `UC-P1-025`, `UC-P1-023` | 规则版本、理由、生效和通知均留证。 |
| `FND-RUL-002` | `GUARDRAIL` | `PRD-P1-015` | `UC-P1-025` | P1 不开放投票直写；发布边界纳入审计验收。 |
| `FND-RUL-003` | `BUILD` | `PRD-P1-006`, `PRD-P1-015` | `UC-P1-005`, `UC-P1-025` | 旧决定可按原规则 hash 复现。 |
| `FND-SEP-001` | `GUARDRAIL` | `PRD-P1-012`, `PRD-P1-015` | `UC-P1-014`, `UC-P1-025` | 决定、执行与申诉角色分离并可审计。 |
| `FND-MEM-001` | `N/A` | `N/A` | `N/A` | Civic Membership 至 P3 关闭；注册和购买不得自动授予成员权。 |
| `FND-MEM-002` | `N/A` | `N/A` | `N/A` | 成员等级和正式职务至 P3 关闭。 |
| `FND-MEM-003` | `GUARDRAIL` | `PRD-P1-015` | `UC-P1-025` | P1 临时运营授权必须有到期、回避和审计。 |
| `FND-MEM-004` | `GUARDRAIL` | `PRD-P1-015` | `UC-P1-025` | 只记录有来源的公共劳动事实，不兑换政治权。 |
| `FND-MEM-005` | `N/A` | `N/A` | `N/A` | P1 不启用贡献币、线性票权或自动兑换；相关制度能力至 P3 关闭。 |
| `FND-MEM-006` | `GUARDRAIL` | `PRD-P1-006` | `UC-P1-005` | 匹配排除理由和专业标准接受审计。 |
| `FND-MEM-007` | `GUARDRAIL` | `PRD-P1-015` | `UC-P1-025` | 首次付费时间和无偿劳动风险作为使命证据记录。 |
| `FND-MEM-008` | `GUARDRAIL` | `PRD-P1-012` | `UC-P1-014` | 冲突评审必须回避并可复核。 |
| `FND-MEM-009` | `N/A` | `N/A` | `N/A` | P1 政治成员权关闭；财富和交易不得生成政治权限。 |
| `FND-MEM-010` | `N/A` | `N/A` | `N/A` | P1 Civic Membership 关闭；开放参与边界由人工行为政策执行。 |
| `FND-MEM-011` | `GUARDRAIL` | `PRD-P1-015` | `UC-P1-025` | 决定记忆保留反对、质疑和更正记录。 |
| `FND-MEM-012` | `GUARDRAIL` | `PRD-P1-003` | `UC-P1-003` | 需求入口记录公共价值和受益者，不承诺 P4 分配。 |
| `FND-MEM-013` | `BUILD` | `PRD-P1-004`, `PRD-P1-012` | `UC-P1-003`, `UC-P1-014` | 行为边界、调查和补救可执行。 |
| `FND-DEP-001` | `GUARDRAIL` | `PRD-P1-012`, `PRD-P1-016` | `UC-P1-014`, `UC-P1-017` | 支持不得换取忠诚，且必须有替代与申诉。 |
| `FND-DEP-002` | `BUILD` | `PRD-P1-001`, `PRD-P1-016` | `UC-P1-019`, `UC-P1-020`, `UC-P1-021`, `UC-P1-017` | 身份、组织、账户和运行状态的撤权彼此隔离。 |
| `FND-DEP-003` | `GUARDRAIL` | `PRD-P1-016` | `UC-P1-017` | 重要支持撤回必须预告、过渡并保留最低权利。 |
| `FND-DEP-004` | `BUILD` | `PRD-P1-013`, `PRD-P1-019` | `UC-P1-015`, `UC-P1-024` | 支持敏感数据按目的和项目隔离。 |
| `FND-DEP-005` | `GUARDRAIL` | `PRD-P1-015` | `UC-P1-025` | 依赖趋势仅以最小、汇总、质性证据进入复盘。 |
| `FND-NOD-001` | `GUARDRAIL` | `PRD-P1-003` | `UC-P1-003` | 机构身份不得替代九角色授权。 |
| `FND-NOD-002` | `GUARDRAIL` | `PRD-P1-016` | `UC-P1-017` | 使用伙伴前记录条件、期限、退出和替代。 |
| `FND-NOD-003` | `GUARDRAIL` | `PRD-P1-012`, `PRD-P1-016` | `UC-P1-014`, `UC-P1-017` | 强迫风险有替代路径和绕行申诉。 |
| `FND-NOD-004` | `N/A` | `N/A` | `N/A` | P1 不纳入高风险线下资源；启用前需安全、公平、无障碍专门 Gate。 |
| `FND-NOD-005` | `GUARDRAIL` | `PRD-P1-016` | `UC-P1-017` | 停摆期间最低权利和跨节点救济保持可用。 |
| `FND-NOD-006` | `BUILD` | `PRD-P1-001`, `PRD-P1-017` | `UC-P1-020`, `UC-P1-022` | 代理有范围、时限、撤回和真实 actor 记录。 |
| `FND-SAF-001` | `BUILD` | `PRD-P1-012`, `PRD-P1-017` | `UC-P1-014`, `UC-P1-022` | 安全规则、举报入口和可理解路径可用。 |
| `FND-SAF-002` | `BUILD` | `PRD-P1-007`, `PRD-P1-012`, `PRD-P1-015` | `UC-P1-006`, `UC-P1-014`, `UC-P1-025` | 拒绝、举报和权利请求后的报复趋势可查。 |
| `FND-SAF-003` | `BUILD` | `PRD-P1-012` | `UC-P1-014` | 临时措施最小化、到期、复核且不级联。 |
| `FND-SAF-004` | `BUILD` | `PRD-P1-012`, `PRD-P1-018` | `UC-P1-014`, `UC-P1-023` | 实质处置有理由、证据、通知和补救。 |
| `FND-SAF-005` | `BUILD` | `PRD-P1-012` | `UC-P1-014` | 申诉由独立且无冲突的 reviewer 处理。 |
| `FND-SAF-006` | `N/A` | `N/A` | `N/A` | P1 排除未成年人和需额外伦理保护的脆弱群体；纳入前另过 Gate。 |
| `FND-SAF-007` | `BUILD` | `PRD-P1-012`, `PRD-P1-016` | `UC-P1-014`, `UC-P1-017` | 事件分级、通知、恢复和复盘可演练。 |
| `FND-EQU-001` | `GUARDRAIL` | `PRD-P1-004`, `PRD-P1-006`, `PRD-P1-012`, `PRD-P1-017` | `UC-P1-003`, `UC-P1-005`, `UC-P1-014`, `UC-P1-022` | 准入、匹配、救济和界面均验证必要性与代理变量。 |
| `FND-EQU-002` | `GUARDRAIL` | `PRD-P1-013`, `PRD-P1-015` | `UC-P1-015`, `UC-P1-025` | 群体指标采用最小数据、小样本保护和访问控制。 |
| `FND-EQU-003` | `BUILD` | `PRD-P1-001`, `PRD-P1-012`, `PRD-P1-017`, `PRD-P1-018` | `UC-P1-001`, `UC-P1-014`, `UC-P1-022`, `UC-P1-023` | 无障碍、清晰语言、替代路径及通知同等可用。 |
| `FND-CTR-001` | `N/A` | `N/A` | `N/A` | P0 必须取得 Legal Scope Memo；数据库和产品 UC 不能替代法律实体、角色和授权。 |
| `FND-CTR-002` | `BUILD` | `PRD-P1-008`, `PRD-P1-009`, `PRD-P1-010`, `PRD-P1-019` | `UC-P1-008`, `UC-P1-011`, `UC-P1-010`, `UC-P1-024` | 协议、变更、验收和文件均绑定同一版本。 |
| `FND-CTR-003` | `N/A` | `N/A` | `N/A` | P0 必须取得劳动、税务和消费者法律意见并抽查实际行为，不能用软件验收代替。 |
| `FND-CTR-004` | `BUILD` | `PRD-P1-005`, `PRD-P1-011` | `UC-P1-004`, `UC-P1-012` | 合法 provider 方案、对账和退款共同验收。 |
| `FND-CTR-005` | `GUARDRAIL` | `PRD-P1-015` | `UC-P1-025` | 文书、界面、运营和账簿的一致性进入审计链。 |
| `FND-OPS-001` | `BUILD` | `PRD-P1-012`, `PRD-P1-015`, `PRD-P1-016`, `PRD-P1-017`, `PRD-P1-018` | `UC-P1-014`, `UC-P1-025`, `UC-P1-017`, `UC-P1-022`, `UC-P1-023` | 每条人工与服务队列必须有 owner、backup、SLO 和 runbook。 |
| `FND-OPS-002` | `GUARDRAIL` | `PRD-P1-013`, `PRD-P1-016`, `PRD-P1-018`, `PRD-P1-019` | `UC-P1-015`, `UC-P1-017`, `UC-P1-023`, `UC-P1-024` | provider 尽调、退出、删除、事件和替代均有演练。 |
| `FND-OPS-003` | `BUILD` | `PRD-P1-016`, `PRD-P1-018` | `UC-P1-017`, `UC-P1-023` | 停摆时人工接管且必要通知仍可达。 |
| `FND-OPS-004` | `GUARDRAIL` | `PRD-P1-016` | `UC-P1-017` | 批次、金额、数据、期限和损失上限进入演练。 |
| `FND-EVD-001` | `GUARDRAIL` | `PRD-P1-001` | `UC-P1-001` | 研究同意和机会授权分离，观察、解释、决定分层。 |
| `FND-EVD-002` | `BUILD` | `PRD-P1-015` | `UC-P1-025` | 设计、测试、自报和现实效果证据等级分离。 |
| `FND-EVD-003` | `BUILD` | `PRD-P1-015` | `UC-P1-025` | 失败、退出、事件、伤害和反例必须可报告。 |
| `FND-GOV-001` | `GUARDRAIL` | `PRD-P1-015` | `UC-P1-025` | P0 临时 RACI 的授权、期限和冲突进入审计；正式治理仍未启用。 |
| `FND-GOV-002` | `N/A` | `N/A` | `N/A` | 审议、代表和投票至 P4 关闭。 |
| `FND-GOV-003` | `N/A` | `N/A` | `N/A` | P1 不建立政治成员资格或投票快照，相关能力至 P4 关闭。 |
| `FND-GOV-004` | `GUARDRAIL` | `PRD-P1-015` | `UC-P1-025` | P1 临时角色有任期、替补、撤回和冲突记录。 |
| `FND-GOV-005` | `GUARDRAIL` | `PRD-P1-015` | `UC-P1-025` | 高风险事项分类和权限边界必须可审计。 |
| `FND-GOV-006` | `N/A` | `N/A` | `N/A` | 宪法修改能力至 P5 关闭。 |
| `FND-GOV-007` | `N/A` | `N/A` | `N/A` | 守护机构最终程序至 P5 关闭。 |
| `FND-GOV-008` | `N/A` | `N/A` | `N/A` | 候选规则的治理发布链至 P4 关闭。 |
| `FND-GOV-009` | `BUILD` | `PRD-P1-012` | `UC-P1-014` | 紧急权最小化、自动到期并接受独立事后审查。 |
| `FND-ECO-001` | `BUILD` | `PRD-P1-005`, `PRD-P1-011` | `UC-P1-004`, `UC-P1-012` | P1 交易资金与其他经济层分账、分权。 |
| `FND-ECO-002` | `N/A` | `N/A` | `N/A` | 公共基金至 P4 关闭；若提前启用必须先新增完整资金 PRD 与 UC。 |
| `FND-ECO-003` | `GUARDRAIL` | `PRD-P1-015` | `UC-P1-025` | P1 记录真实公共劳动成本，不承诺尚未批准的分配。 |
| `FND-ECO-004` | `N/A` | `N/A` | `N/A` | 公共预算方向至 P4 关闭。 |
| `FND-ECO-005` | `N/A` | `N/A` | `N/A` | P0 以资产清单和法律条款执行；成员经济权益至 P5 关闭，软件不能自创权益。 |
| `FND-ECO-006` | `N/A` | `N/A` | `N/A` | P0 以核心资产与许可清单执行；正式转让和分支结构至 P5。 |
| `FND-ECO-007` | `N/A` | `N/A` | `N/A` | P0 以融资法律文件的期限、上限和转让限制执行，不是 P1 产品 Use case。 |
| `FND-ECO-008` | `GUARDRAIL` | `PRD-P1-011`, `PRD-P1-015` | `UC-P1-012`, `UC-P1-025` | P1 显示交易成本并保留分账证据；正式剩余分配未启用。 |
| `FND-ECO-009` | `GUARDRAIL` | `PRD-P1-015` | `UC-P1-025` | 资源集中度、附带条件和替代能力进入风险复盘。 |
| `FND-ECO-010` | `GUARDRAIL` | `PRD-P1-015` | `UC-P1-025` | 资金来源、条件、冲突和批准进入审计证据。 |
| `FND-ECO-011` | `N/A` | `N/A` | `N/A` | 成员经济权益至 P5 关闭；必须由法律、会计和税务工件建立。 |
| `FND-ECO-012` | `BUILD` | `PRD-P1-011`, `PRD-P1-015` | `UC-P1-012`, `UC-P1-025` | 申请、批准、付款和审计职责分离。 |
| `FND-MIS-001` | `BUILD` | `PRD-P1-014`, `PRD-P1-015` | `UC-P1-013`, `UC-P1-025` | 指标结合成果、关系与质性反例，不只看收入。 |
| `FND-MIS-002` | `GUARDRAIL` | `PRD-P1-015` | `UC-P1-025` | 恶化阈值、owner 和暂停决定可审计。 |
| `FND-MIS-003` | `GUARDRAIL` | `PRD-P1-012`, `PRD-P1-015` | `UC-P1-014`, `UC-P1-025` | 扩权前有培训、审计、到期和申诉。 |
| `FND-MIS-004` | `BUILD` | `PRD-P1-015` | `UC-P1-025` | 口径、样本、反例、伤害和限制一并保留。 |
| `FND-EXIT-001` | `BUILD` | `PRD-P1-001`, `PRD-P1-013`, `PRD-P1-016` | `UC-P1-021`, `UC-P1-015`, `UC-P1-016`, `UC-P1-017` | 账户关闭、数据权、历史和运行连续性分离。 |
| `FND-EXIT-002` | `N/A` | `N/A` | `N/A` | P1 仅执行许可、公共知识和第三方权利人工护栏；合法 fork 至 P5 关闭。 |
| `FND-EXIT-003` | `N/A` | `N/A` | `N/A` | 出售或控制变化由 P0 交易红线和法律文件执行；P5 分支保护未启用。 |

逐项验收实例见[软件交付章程](/foundations/software-delivery-charter.md)。`PRD-P1-017`、`PRD-P1-018`、`PRD-P1-019` 已同步到[产品与首批试点定义](/foundations/product-and-pilot-definition.md)；`UC-P1-018` 至 `UC-P1-025` 是与其及既有 PRD 对应的稳定 ID，不得复用为其他含义。

## 4. 状态晋级与失效

### 4.1 晋级

每次只能按证据晋级一层或多层，记录每层独立证据。示例：

```text
CAP-C04
DESIGN: approved bounded context and threats
CONTRACT: versioned commands/events/errors
DOMAIN: invariant/property tests
MEMORY: application journeys
POSTGRES: transaction/concurrency/RLS/migration
HTTP: auth/idempotency/error/privacy
COMPOSED: real adapters in production composition
ENABLED: feature flag + approved cohort + rollback
OPERATED: owners/runbooks/SLO/incidents/training
EFFECTIVE: real refusal/fairness/relationship evidence + adverse review
```

### 4.2 自动失效触发

以下变化使相关状态退回审查，而不是永久继承：

- code revision、Schema、规则/Consent/协议版本或 provider 变化；
- 辖区、参与者类型、数据类别、币种、资金流或项目风险变化；
- 关键 owner/backup、合同、许可、保险或预算失效；
- Critical/High 事件、恢复失败、申诉或真实效果反证；
- 超过获批准批次、容量、金额或期限；
- 测试环境/证据不可重建；
- 文档与实际行为不一致。

状态退回不删除历史证据；应记录失效原因和恢复条件。

## 5. 当前结论与下一步

1. 所有 `FND-*` 仍是草案规范，尚未由真实成员批准或经完整法律审查；
2. 所有 `CAP-*` 在本次评估中最多拥有 `DOC-DESIGN`，代码和现实层均为 `UNVERIFIED`；
3. P1 已有明确 `BUILD/GUARDRAIL/OFF` 处置，不应把 P3–P5 当当前 backlog；
4. `G1` 前首先为 P1 相关 CAP 重采集 revision 证据、关闭 Critical、落实 owner/ADR/contract；
5. `G2` 前必须把最小数据权、安全/申诉、付款、审计、恢复和人工运营一起证明；
6. 任何页面若声明与本文不同的“当前状态”，应引用证据后更新本文，而不是各自维护另一个结论。

本登记册建立了追踪骨架，但尚未使任何能力自动就绪。下一次更新应把 `TBD` 变成可定位证据，而不是增加更多设计叙述。
