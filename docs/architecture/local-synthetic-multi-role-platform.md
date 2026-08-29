# 本地合成多角色平台 ADR 与验收规格

> ADR ID：`ADR-LS-001`
> 状态：`IMPLEMENTATION-SPEC / LOCAL-SYNTHETIC-ONLY`
> 适用范围：仅供当前仓库的可删除本地多角色产品壳、BFF 和合成纵切实现。
> Gate 状态：`G1 NO-GO`、`G2 NO-GO`；本文不改变、不通过也不替代任何 Gate。
> 外部效果：禁止发布、部署、公开访问、真实通知、真实文件、真实身份、真实合同、真实资金和现实权益决定；不得发布到 OpenAI Sites 或任何其他托管服务。

## 0. 决定摘要

当前实现采用一个只绑定 loopback、只含固定合成账号和合成业务事实的模块化单体，交付七个角色账号可从浏览器共同完成 `J01..J12` 的最小闭合旅程。这个实现用于证明产品交互、权限、版本、状态机、拒绝、付款未知、申诉、数据权和恢复语义，不是生产组合、市场证据、参与者理解证据或真实服务授权。

本 ADR 冻结以下决定：

1. HTTP 服务只允许绑定 `127.0.0.1`；不得绑定 `0.0.0.0`、局域网地址、公网地址或创建 tunnel。
2. 只允许内置的七个显著标识为合成的账号；不能注册、邀请或导入真实主体。
3. 浏览器只访问同源关闭 API；前端不持有、选择或声称 actor/authority。
4. 本地持久化使用可随时删除和重建的 `local_synthetic` SQLite adapter；它不是生产数据库路线，也不构成 PostgreSQL 证据。
5. 未来权威运行方向仍是 PostgreSQL 18、真实 Session/BFF、明确 port/adapter 和失败关闭的生产组合；领域契约不能依赖 SQLite 特性。
6. 所有 provider、账簿、通知、文件与外部结果均由内置合成 fixture/simulator 提供；实现不得发出外部网络或现实副作用。
7. 不新增发布、部署、上传、站点托管、远程 analytics、远程字体、第三方脚本或 AI 调用。

阶段权限以 [DEC-033 下 G1 构建范围与可追踪 Backlog](/foundations/g1-build-scope-and-backlog.md#01-阶段权限) 和 [G1 创始人定向构建决定](/foundations/g1-direct-build-decision.md#2-允许与禁止) 为准。真实服务仍须满足 [软件开发启动就绪度与决策入口](/foundations/readiness-and-start-decision.md#g2允许封闭付费试点) 的全部 G2 原子门槛。

## 1. 规范来源与追踪

本文不重新定义 Foundations。冲突时，以下来源的原始要求优先：

| 本 ADR 范围 | 权威来源 | 稳定追踪 |
| --- | --- | --- |
| 人的边界、拒绝和无报复 | [Foundations 要求目录](/foundations/foundation-requirements.md#1-人主体性与社会边界)、[公平协作](/foundations/foundation-requirements.md#2-公平协作) | `FND-HUM-002`, `FND-COL-001..004`, `FND-COL-008..010` |
| 九角色、授权与组织边界 | [产品与首批试点定义](/foundations/product-and-pilot-definition.md#21-九类协作角色)、[支持依赖与协作节点](/foundations/foundation-requirements.md#52-跨机构协作节点) | `FND-NOD-001`, `FND-DEP-002`, `PRD-P1-003` |
| 数据、声誉与历史 | [Foundations 数据权利](/foundations/foundation-requirements.md#31-数据权利)、[声誉与贡献证据](/foundations/foundation-requirements.md#32-声誉与贡献证据) | `FND-RGT-001..005`, `FND-REP-001..004`, `PRD-P1-013/014` |
| 举报、正当程序与可访问性 | [试点安全、公平、合同、运营与证据](/foundations/foundation-requirements.md#6-试点安全公平合同运营与证据) | `FND-SAF-001..007`, `FND-EQU-001..003`, `FND-SEP-001`, `PRD-P1-012/017` |
| 资金事实与职责分离 | [关键状态与不可变条件](/foundations/product-and-pilot-definition.md#6-关键状态与不可变条件)、[财务控制](/foundations/operating-model-and-service-playbook.md#7-财务控制) | `FND-COL-008`, `FND-CTR-004/005`, `FND-ECO-001/012`, `PRD-P1-005/011` |
| 唯一主旅程 | [G1 构建范围：唯一主旅程](/foundations/g1-build-scope-and-backlog.md#21-唯一主旅程) | `J01..J12`, `ACC-G1-002..017` |
| 可执行用例 | [软件交付章程：P1 用例目录](/foundations/software-delivery-charter.md#5-p1-用例目录) | `UC-P1-001..025` |
| 身份、审计、权利、产品壳 | [技术能力地图：平台底座能力](/foundations/technical-capability-map.md#3-平台底座能力) | `CAP-S01..07` |
| Profile、Demand、协作全周期 | [技术能力地图：协作生命周期能力](/foundations/technical-capability-map.md#4-协作生命周期能力) | `CAP-C01..09` |

本地实现至少覆盖 `PRD-P1-001..019` 中与单一合成旅程适用的用户可见语义。`PRD`、`UC` 或 `CAP` 未由本地 adapter 完整实现时，bootstrap 必须显示为关闭或不可用，不能用静态页面暗示已实现。

## 2. 运行与副作用边界

### 2.1 启动约束

应用只接受显式 `runtime_profile=local_synthetic`。组合根必须在监听前验证：

- bind host 精确为 `127.0.0.1`；
- origin 为启动时生成或明确配置的单个 `http://127.0.0.1:<port>`；
- 数据库 adapter 精确为 `local_synthetic_sqlite`；
- fixture manifest 的 schema、digest 与 `synthetic=true` 标记有效；
- notification、payment、file、identity、analytics、AI 和 webhook 外部 adapter 全部为 `disabled`；
- 不存在 production secret、真实 provider credential 或远程 endpoint；
- 数据库为空或拥有当前 fixture 的 `synthetic_instance_marker`。

任一条件不成立时进程失败关闭。禁止自动回退到内存、allow-all、随机 persona、其他数据库或远程服务。

### 2.2 网络与发布禁令

- 响应只服务 loopback 请求；校验 `Host` 与 `Origin`，拒绝其他来源。
- 不启用 CORS，不接受跨源 credential，不生成分享链接或公网 URL。
- 不启动 tunnel、service worker 离线写、外部 webhook listener 或 LAN discovery。
- UI assets 与字体全部来自本地构建制品；不加载 CDN、analytics、chat widget、session replay 或 tag manager。
- 合成通知只写入站内投影；合成 payment/provider 回调只由动作模拟器写入本地 inbox。
- 本实现没有 deploy、publish、upload 或 hosting 命令，也不得发布到 OpenAI Sites。

## 3. 七个合成账号与授权

### 3.1 固定 personas

| Persona ID | 界面名称 | 最小职责 | 明确禁止 |
| --- | --- | --- | --- |
| `creator-chen` | 创作者陈澄（合成） | 管理 ProfileVersion/披露；响应 Invitation；签署协议；交付和重新提交；查看付款；情境评价、举报、数据权与退出 | 不被任何 operator 代接受；不能查看其他候选或 Demand 私密字段 |
| `demand-owner` | 需求负责人（合成） | Organization 管理；提交 Demand；兼任九角色中的问题提出、采购、需求决定、候选选择和项目协调，但每项使用独立 grant；另持需求方签字 grant；评价、举报、数据权与退出 | 不审核自己的 Demand，不核实资金，不代 Creator/验收人/受益者接受 |
| `acceptance-beneficiary` | 验收人与受益者（合成） | 在两个独立 grant 下执行合同验收和受益者 Outcome 确认；查看必要成果与标准；举报、数据权与退出 | 一个动作不能同时生成验收和成果确认；不能选择候选、签约或写付款事实 |
| `case-operator` | 服务运营者（合成） | Demand review、Creator steward、Match/Case coordination、初次 Safety decision；在单独作用域下处理本地 Privacy queue | 不覆盖硬边界，不代任何参与方同意/签署/验收，不处理相关最终申诉，不写最终资金事实 |
| `payment-initiator` | 付款发起人（合成） | 依据已批准义务发起 Demand/Milestone Funding 和 Payment 操作 | 不把请求、处理中或自报写成 `SECURED/PAID`；不核实自己发起的操作 |
| `finance-reconciler` | 财务核实人（合成） | 注入并核验合成权威账簿事实；收敛 `UNKNOWN`、成功、失败、退款和冲正 | 不发起同一操作，不修改合同、金额、收款人或验收事实 |
| `appeal-reviewer` | 独立申诉复核者（合成） | 冲突检查；复核初次决定；维持、修改、撤销或发回；给出可执行补救；按范围查看审计投影 | 不参与原决定、项目选择或相关付款初次处理；不获得无范围的全库读取 |

这些 persona 是测试入口，不是一个单值业务 `role`。每个动作仍须绑定一个当前、明确、具作用域和期限的 authority grant；同一 persona 的不同 grant 不得互相推导。

### 3.2 九类需求侧角色

本地 fixture 必须逐项保存九类需求侧授权，不能把 `demand-owner` 当作不透明的“客户管理员”：

| 协作角色 | 合成 fixture | 验收语义 |
| --- | --- | --- |
| 问题提出者 | `demand-owner` | 保存问题来源与提出权限 |
| 实际受益者 | `acceptance-beneficiary` | 与采购者分开显示，可独立确认 Outcome |
| 受益者代表 | `NONE / UNCONFIRMED` | 无可核验授权，不得代表受益者确认 |
| 出资/采购者 | `demand-owner` | 只承担采购义务；不因此获得财务核实权 |
| 资源提供者 | `NONE / NOT_APPLICABLE` | 保存不适用依据，不能省略字段 |
| 需求决策人 | `demand-owner` | 单独 authority 冻结目标、范围和取舍 |
| 候选选择者 | `demand-owner` | 单独 authority，只能选择同 run 的 `ACCEPTED` Creator |
| 验收人 | `acceptance-beneficiary` | 单独 authority，按冻结标准验收 |
| 项目协调者 | `demand-owner` | 传递输入和状态，不代其他角色接受 |

此外，需求方签字权和 Creator 自签权是 Agreement authority，不从上述九角色自动产生。每个 grant 至少保存：`authority_id`、`subject_id`、`authority_type`、来源及版本、scope、`not_before`、`expires_at`、delegation policy、conflict marker、revocation state。

## 4. `J01..J12` 闭合旅程

后一步只引用前一步的版本化事实，不回写历史。每一步的主 actor、完成事实和最低异常如下：

| Journey | 主 actor | 完成事实 | 同时验收的异常/权利 |
| --- | --- | --- | --- |
| `J01` 受控进入 | 全部 personas / self | 固定合成身份、Session、OrganizationMembership 与逐目的 Consent 可证 | 拒绝 Consent 不获目的权限；Session 撤销后旧凭据失效 |
| `J02` Creator Profile | `creator-chen` | 当前最小 `ProfileVersion` 与逐字段披露生效 | 撤回后新 run 不读旧披露；私密底线不可显示或反推 |
| `J03` Demand | `demand-owner` | `DemandVersion` 含九角色、范围、预算路径、验收、风险和版本 | 缺失、过期、冲突、取消或 stale revision 不得送审/匹配 |
| `J04` Demand review | `case-operator` | `APPROVE / REVISE / REJECT / ESCALATE` 决定含理由、规则与责任人 | operator 不得覆盖硬边界；退回有字段级纠正路径 |
| `J05` Demand Funding | `payment-initiator` + `finance-reconciler` | 对应 `DEMAND_VERSION` 的合成权威 `SECURED` 事实 | 请求、截图、timeout、`UNKNOWN` 不等于 secured；发起/核实分离 |
| `J06` MatchRun | `case-operator` | 固定 Demand/Profile/规则版本、最小快照、有限候选、解释和 hash | run/attempt/tenant/replay 隔离；无完整 Profile 或底线泄漏 |
| `J07` Invitation | `creator-chen` | `ACCEPTED / DECLINED / WITHDRAWN / EXPIRED` 之一及历史 | 沉默不接受；拒绝理由可选且私密；拒绝不产生惩罚特征 |
| `J08` Selection | `demand-owner` 的 selector grant | 同 run、当前 `ACCEPTED` Creator 的单次 CompletedSelection | stale/cross-run/撤回/重复/并发选择原子拒绝，无半 Project |
| `J09` Agreement | `demand-owner` + `creator-chen` | Project shell 与双方同一 `AgreementVersion` 的独立接受 | 缺签、异版、过期授权或并发改版不能生效；旧版只读 |
| `J10` Milestone/Delivery | finance roles、`creator-chen`、`acceptance-beneficiary` | Milestone `SECURED` 后开工；Delivery、合同验收、Outcome 确认分别版本化 | 未 secured 不开工；拒收有理由/补救；当前 enum 不支持实质变更，任何静默变更必须失败关闭 |
| `J11` Payment | `payment-initiator` + `finance-reconciler` | 请求、处理中、未知、失败、成功、退款/冲正和对账确定性收敛 | `PROCESSING/UNKNOWN` 不等于 `PAID`；未知期间不能盲目重复支付 |
| `J12` Outcome/Rights/Appeal/Exit | 项目方、`case-operator`、`appeal-reviewer` | 情境评价、回应/更正、数据权分项结果、独立申诉、退出和恢复证据 | 无总分；临时措施最小且到期；退出不吞付款、申诉和必要记录 |

浏览器验收除正常路径外，至少独立运行：Creator 拒绝、Delivery 拒收与重新提交、Payment `UNKNOWN`、原决定人自我复核被拒、第三方过滤数据权结果、Session/进程恢复六条纵切。`PRD-P1-009 / UC-P1-011` 的实质变更命令不在当前 operation enum 中，必须在 UI 明确显示为关闭且 API 拒绝任何静默字段覆盖；这项关闭状态不能被报告为用例已实现。

## 5. 最小关闭 HTTP 协议

### 5.1 通用约束

- 基础 origin：`http://127.0.0.1:<ephemeral-or-configured-port>`；只接受 `application/json`，UTF-8，关闭 schema，拒绝未知字段和重复 JSON key。
- 所有响应带 `Cache-Control: no-store`；`request_id` 通过 `X-Request-ID` 响应头返回，`instance_epoch` 只保存在 Session/reset 控制面，不加入关闭的 Web DTO；不返回 Python 异常、SQL、文件路径或任意内部正文。
- 除 `GET /v1/local/personas` 与首次 `POST /v1/local/session` 外，全部路由要求有效 Session。
- 写路由校验精确 same-origin `Origin`、Session-bound CSRF 和当前 authority；action 的幂等键与期望 revision 只来自关闭的 `ActionIntent`。
- 身份只来自 HttpOnly Session；业务对象 ID 只出现在逐 operation 关闭的 `input`；actor、authority、tenant、organization 和角色选择不得由 action body、query 或自定义 header 提供。
- 不提供任意 CRUD、GraphQL、泛化 filter/include、SQL console、debug dump 或超级管理员 route。

### 5.2 路由

| Method/path | Auth | 请求 | 成功结果 | 关键失败 |
| --- | --- | --- | --- | --- |
| `GET /v1/local/personas` | 无 | 无 query/body | 只返回固定七 persona 的关闭安全登录卡片；fixture digest 与 `synthetic=true` 在服务端启动校验，不加入该 Web DTO | 非 loopback/错误 Host `403`; fixture 无效 `503` |
| `POST /v1/local/session` | 无；same-origin | `{ "persona_id": <closed enum> }` | 建立合成 Session、设置 HttpOnly cookie，返回最小 session summary | 未知 persona/未知字段 `400`; 已禁用 persona `403` |
| `DELETE /v1/local/session` | Session + CSRF | 无 body | 撤销当前 Session、清 cookie；重复删除安全收敛 | Origin/CSRF 错误 `403` |
| `GET /v1/local/bootstrap` | Session | 无 query/body | 当前 persona、安全 authority 摘要、导航、任务/旅程投影、CSRF、ETag/revision | Session 失效 `401`; instance reset `409`; unavailable `503` |
| `POST /v1/local/actions` | Session + CSRF；idempotency/revision 在关闭 body | `{ operation, expected_revision, idempotency_key, input }` | `ActionReceipt` 与更新后的受限投影/ETag | schema `400`; auth `403/404`; stale `412`; conflict `409`; unknown `503` |
| `POST /v1/local/reset` | `case-operator` 的 `LOCAL_FIXTURE_ADMIN` grant + CSRF | `{ fixture_id: "scn-g1-001-happy-v1", expected_revision, idempotency_key }` | 原子恢复标准合成业务状态、增加 `instance_epoch`、返回新 bootstrap | schema `400`; 非 operator `404`; stale `412`; conflict `409`; reset 失败 `503` |

`POST /v1/local/session` 的 `persona_id` 只是选择固定合成登录身份，不是业务动作 authority。Session 建立后，客户端不能为任何 action 指定或切换 actor/authority；切换 persona 必须先 DELETE Session，再建立另一个固定 Session。

### 5.3 `ActionIntent`

唯一写入口使用以下外形：

```json
{
  "operation": "respond_invitation",
  "expected_revision": 7,
  "idempotency_key": "syn-action-0188d84f3a6a4e75b4b899577c76b433",
  "input": {
    "invitation_id": "syn_invitation_001",
    "decision": "ACCEPT"
  }
}
```

顶层精确且只允许 `operation`、`expected_revision`、`idempotency_key`、`input`，四项均必填；没有顶层 `target`。`expected_revision` 是 bootstrap 返回的当前 local-synthetic scenario revision；`idempotency_key` 是当前逻辑动作的至少 128-bit 随机、不透明值；`input` 使用逐 operation 关闭 schema，业务对象 ID 也只能在该 schema 允许的位置出现。

以下 25 个名称及其版本化 contract 构成首版本完整 operation enum，未列名称一律拒绝：

```text
accept_consent
publish_profile
submit_demand
review_demand
request_demand_funding
reconcile_demand_funding
run_matching
respond_invitation
complete_selection
accept_agreement
request_milestone_funding
reconcile_milestone_funding
start_project
submit_delivery
decide_delivery
confirm_outcome
request_payment
advance_payment_provider
reconcile_payment
record_outcome
submit_report
decide_safety
decide_appeal
request_data_right
exit_participation
```

这份 enum 是本地 Web、后端 dispatcher、fixture manifest 和 contract tests 的共同事实源。任何后端更名、拆分、合并或新增都必须在同一 revision 同步修改本 ADR、关闭 schema、前端生成类型和 contract tests；不允许使用兼容别名或让文档与运行时漂移。

需要状态或决定的 operation 只接受二级关闭 enum：

- `review_demand.input.decision`: `APPROVE | REVISE | REJECT | ESCALATE`；
- `reconcile_demand_funding.input.result` 与 `reconcile_milestone_funding.input.result`: `SECURED | FAILED | UNKNOWN | REFUNDED`；
- `respond_invitation.input.decision`: `ACCEPT | DECLINE | WITHDRAW | EXPIRE`；
- `decide_delivery.input.decision`: `ACCEPT | REJECT_WITH_REASON | REQUEST_CONTRACTED_REVISION`；
- `advance_payment_provider.input.result`: `PROCESSING | UNKNOWN | FAILED`；
- `reconcile_payment.input.result`: `PAID | FAILED | REFUNDED | REVERSED`；
- `decide_safety.input.decision`: `UPHOLD_PROTECTION | MODIFY_PROTECTION | LIFT_PROTECTION | REMEDY`；
- `decide_appeal.input.decision`: `UPHOLD | MODIFY | OVERTURN | REMAND`；
- `request_data_right.input.kind`: `ACCESS | CORRECT | RESTRICT | OBJECT | DELETE | EXPORT | WITHDRAW_CONSENT`。

所有 reason、变更字段和权利结果须由相应 contract 限定长度、字段与披露级别。客户端不得传 `actor`、`actor_id`、`subject`（除非该 operation 的业务对象本身就是权利请求 subject 且服务端重新绑定为当前主体）、`authority`、`role`、`tenant_id`、`organization_id`、`is_admin`、`verified`、`paid` 或任意权限/最终事实覆盖字段。出现这些键必须以 `400 FORBIDDEN_INPUT_FIELD` 失败，而不是忽略。

### 5.4 Session 与 CSRF

- cookie 名为 `ds_local_session`，`HttpOnly; SameSite=Strict; Path=/`，无 `Domain`；它故意不复用目标生产 cookie 名称。
- 本地 HTTP loopback 不把该 cookie 宣称为生产安全 Session；production 仍须使用目标 BFF 的 HTTPS、Secure cookie、轮换、撤销和恢复协议。
- Session 保存服务端随机 opaque handle digest、persona、generation、issued/expiry、fixture digest 与 instance epoch；cookie 中不放 persona 或 authority。
- `GET /v1/local/bootstrap` 返回只在页面进程内存保存的 CSRF token；token 绑定 Session generation、origin 和 instance epoch。
- 所有 POST/DELETE 必须同时验证 Session、Origin 和 `X-CSRF-Token`。Session、persona 或 epoch 改变即使旧 token 失效。
- 浏览器不得把 Session、CSRF、persona DTO、authority、业务正文或 receipt 写入 `localStorage`、IndexedDB、URL 或日志。

### 5.5 Idempotency 与结果未知

- `POST /v1/local/actions` 要求 body 中有至少 128-bit 随机 `idempotency_key`；raw key 必须从日志、异常、repr、audit 和投影中抑制。`POST /v1/local/reset` 精确且只接受 `{fixture_id, expected_revision, idempotency_key}`，其中 `fixture_id` 只允许 `scn-g1-001-happy-v1`，并使用独立 receipt 命名空间。
- reset 的 actor、authority 和 Organization 仍只来自当前 Session 与服务端 grant；body 中的 `actor`、`authority`、`role`、`organization_id`、`org_id` 或任何 admin override 均以 `400 FORBIDDEN_INPUT_FIELD` 拒绝。CSRF 只在 `X-CSRF-Token` header，不能放进 body。
- receipt scope 为 `instance_epoch + session subject + operation + idempotency key digest`；canonical intent 为 `operation + expected_revision + canonical input`，receipt 保存其 digest、开始/终态、响应摘要和 correlation，不保存 raw key 或完整敏感 input。
- 同 key、同 canonical intent 重放返回相同终态；同 key、不同 intent 返回 `409 IDEMPOTENCY_KEY_REUSED`。
- 网络断开或响应丢失后，UI 只能以同 key、同 intent 恢复；不能创建新 key 猜测重做。
- `UNKNOWN` 是显式终态/调查态，不得从 timeout 推断成功或失败。Payment `UNKNOWN` 时 `request_payment` 的重复新操作必须被阻断。
- reset 不删除 Session/control receipt；它增加 epoch、原子替换业务 fixture，并使其他页面必须重新 bootstrap。

### 5.6 Revision、事务与并发

- 每个可变聚合/投影提供强 revision 与 ETag；相关 action 必须在 body 的 `expected_revision` 传回 bootstrap 所见 revision。
- revision 是服务端单调增加的 local-synthetic scenario revision；客户端不得自增、猜测或从 ETag 以外的显示文字解析。
- stale revision 返回 `412 REVISION_MISMATCH` 和最新安全 ETag/刷新动作；不自动套用旧输入。
- 一个 action 在单个 SQLite transaction 中完成 authority 重验、状态重验、领域写入、audit、receipt 与 projection 更新；失败不得留下半完成 Project、Selection、Agreement、Payment 或权利结果。
- 并发 replay、撤回、选择、签署、验收、变更、付款和 reset 必须确定性收敛；数据库唯一约束只是最后防线，领域错误仍返回稳定 code。

### 5.7 关闭投影

bootstrap 是当前本地产品壳的唯一聚合读取，不返回原始表或完整领域对象。响应至少包含：

```text
persona: id + display label + synthetic marker
session: generation + expires_at
authorities: safe authority type/scope/expiry summaries
navigation: server-authorized destinations
journey: J01..J12 state, source revisions, current blockers
tasks: task_id, title, status, next responsible role, deadline, available_operations
workspace: role-scoped cards and timelines
rights: report/appeal/data/exit entry availability
projection_revision + etag + instance_epoch + correlation
```

投影必须按 persona 在服务端裁剪：

- Creator 看不到其他候选、需求方内部理由或私密采购资料；
- Demand personas 看不到 Creator 私密底线、拒绝理由或其他候选资料；
- finance personas 只见核实所需义务、金额、币种和合成 provider reference；
- reviewer 只见被分配案件的必要证据和冲突信息；
- operator 没有默认业务正文或跨对象全库访问；
- UI 只根据 `available_operations` 呈现动作，但服务端仍对每次 action 重新授权。

错误响应只含稳定 `code`、安全字段问题、`request_id/correlation`、是否可重试和建议刷新/申诉动作。不存在与越权对象统一为不可枚举的 `404`；动态服务端 message 不直接显示。

## 6. SQLite `local_synthetic` adapter

### 6.1 允许用途

SQLite 仅用于：

- 本机进程重启后保留合成旅程进度；
- 原子演示角色切换、版本、幂等、审计、投影和 reset；
- 运行本 ADR 的 adapter contract、HTTP 和浏览器验收；
- 通过一个可删除文件快速恢复固定 fixture。

数据库必须带 `storage_profile=local_synthetic`、fixture schema/version/digest、创建时间与随机 instance ID。所有 participant、文本、金额、provider ref 和文件 metadata 都带可机器验证的 synthetic provenance。数据库路径不得位于 production 数据目录，不得加入版本控制、备份、上传或迁移到真实环境。

### 6.2 禁止推论

SQLite GREEN 不能证明：PostgreSQL transaction/RLS/ACL、连接池、迁移、并发负载、provider inbox/outbox、备份恢复、生产密钥、真实通知或真实支付已经实现。本文不得改变 [生产组合根、部署与运行控制](/architecture/production-composition-and-operations.md) 的 PostgreSQL 18 方向。

领域/application 层只能依赖明确 ports。SQLite adapter 不得把 rowid、SQLite timestamp、宽松类型、单连接锁或 JSON 文本布局泄漏到领域契约。未来 PostgreSQL adapter 应复用同一 contract/property/application suite，并另加 PG transaction、RLS、ACL、migration、并发与恢复测试；不能通过复制 SQLite 数据文件升级。

### 6.3 删除与 reset

- 停止本地进程后删除 SQLite 文件即可清除全部合成业务数据；没有云端副本。
- `/v1/local/reset` 只由固定 `case-operator` 的 fixture-admin grant 调用，在事务中恢复标准场景并增加 epoch。
- reset 不能伪装数据主体删除、账户退出、审计更正或生产恢复；这些仍通过各自 action 和证据链验收。
- 任何非合成 marker、未知 schema 或 fixture digest 不符都必须拒绝打开，不能“尽量兼容”。

## 7. UX 规格

### 7.1 信息架构

产品壳采用任务而不是数据库表组织信息：

- 首屏固定显示“本地合成演练”“无真实副作用”“G1 NO-GO / G2 NO-GO”；不得用“生产”“真实到账”“已上线”等词。
- 顶部显示当前 persona、当前作用域和“切换账号需退出”的明确动作。
- 首页按 `需要我行动 / 等待他人 / 已完成 / 需要处理` 分组；每项显示对象版本、权威状态、下一责任角色、截止时间和原因。
- 主旅程显示 `J01..J12` stepper；后续状态不能掩盖前一步历史，点击可查看安全时间线。
- 每个角色只看到完成其任务所需的导航。直接输入无权 route 仍由服务端拒绝。
- “举报与申诉”“数据与隐私”“退出与善后”始终从参与者壳可达，不能藏在项目成功状态之后。

### 7.2 动作与状态

- 每个动作使用具体动词，如“接受 Agreement v2”“拒绝并保留 Agreement v1”“发起付款请求”；禁止只写“确定”。
- 高风险确认页重新显示业务对象、版本、金额/币种、当前 authority、直接后果与可逆性，但 authority 仍来自服务端而非表单。
- 禁用动作同时显示安全理由、需要谁先做什么、刷新/纠正/申诉路径；不得只灰掉按钮。
- `REQUESTED`、`PROCESSING`、`UNKNOWN`、`SECURED`、`PAID` 使用不同文字、图标和解释，不只靠颜色。
- 写操作使用 `EDITING → SUBMITTING → SUCCEEDED / REJECTED / OUTCOME_UNKNOWN → RECOVERING`；结果未知时不显示成功 toast，不鼓励新请求。
- `412` 显示旧/新版本差异并要求重新确认；不能自动覆盖。
- notification failure 不冒充知情，也不启动不可逆期限。
- Creator 拒绝理由默认留空、私密且非必填；界面不暗示拒绝会降低未来机会。

### 7.3 可访问性和清晰语言

首版以 [Web BFF、浏览器会话与前端产品壳](/architecture/web-bff-and-frontend.md#9-可访问性与本地化) 的 WCAG 2.2 AA 目标为验收基线：

- 完整键盘路径、可见焦点、正确 landmarks/headings/labels/error summary/live region；
- 状态、错误和期限不只靠颜色、位置或动画；
- 200% 缩放、窄屏重排、reduced motion/high contrast 可用；
- Session 到期、异步成功/失败和 Payment `UNKNOWN` 可被辅助技术理解；
- 简体中文说明用户能做什么、不能做什么、为什么、下一步和救济；
- 时刻同时给出绝对时间及时区，金额由整数 minor units 与 `CNY` 格式化；
- 辅助失败不缩短接受、付款、申诉或数据权期限。

## 8. TDD 与证据顺序

实现严格按文档驱动和测试驱动推进，每一层先 RED、再最小 GREEN、再重构：

1. **文档/契约 RED**：校验本 ADR、FND/PRD/UC/CAP 追踪、operation enum、fixture manifest 与 error catalog 一致。
2. **领域 RED**：九角色授权、状态转换、拒绝无报复、同 run selection、同版 Agreement、Funding/Payment 未知、申诉冲突、数据权分项和历史不改写。
3. **application RED**：actor/authority 从 Session 注入、执行时重验、幂等 receipt、revision conflict、transaction rollback、reset epoch 和 projection 更新。
4. **SQLite adapter RED**：port contract、唯一约束、原子性、restart persistence、fixture marker、删除/rebuild；不得把 SQLite-specific 行为写进领域断言。
5. **HTTP RED**：六条关闭 route、Host/Origin、Session、CSRF、unknown field、forbidden actor/authority field、ETag、idempotency、404 不枚举和 no-store。
6. **前端组件 RED**：角色导航、任务卡、状态词、禁用原因、版本冲突、unknown recovery、举报/数据权/退出常驻入口。
7. **浏览器 E2E RED**：七账号正常纵切以及拒绝、变更、付款未知、申诉、数据退出和恢复。
8. **安全/可访问性 RED**：跨 persona/跨对象越权、CSRF、replay、敏感投影、键盘、屏幕阅读器语义、缩放和对比度。

每个测试必须引用至少一个 `FND-*` 和对应的 `PRD-P1-* / UC-P1-* / ACC-G1-*`；仅引用本 ADR 不足以证明 Foundations 要求。合成测试结果只能记为 engineering evidence，不能升级任何市场或效果假设。

## 9. 可执行验收清单

### 9.1 组合与边界

- [ ] 服务只监听 `127.0.0.1`，对非 loopback Host/Origin 失败关闭。
- [ ] 静态/动态网络检查证明没有外部请求、真实 provider、通知、文件上传、analytics、AI、tunnel、deploy 或 publish 路径。
- [ ] 所有页面持续显示 synthetic 与 Gate NO-GO 标识。
- [ ] SQLite 文件可删除重建，未知/非合成数据库拒绝打开。
- [ ] `git`/制品检查不包含 SQLite 数据、Session、receipt 或 fixture 运行载荷。

### 9.2 身份与权限

- [ ] `/personas` 精确返回七个账号；不能自行注册第八个账号。
- [ ] 九类需求侧角色逐项存在；`NONE` 角色有明确依据。
- [ ] 同一 persona 的每项 action 留下精确 actor、authority、scope、版本、理由和 correlation。
- [ ] Organization、付款、运营身份不能推导 selector、signatory、acceptor 或 beneficiary authority。
- [ ] action body 中任一 actor/authority/role/admin/final-fact 覆盖字段均被拒绝。
- [ ] authority 过期、撤回、冲突、Session rotation 或 stale projection 时服务端失败关闭。
- [ ] case operator 不能代 Creator 接受、代双方签约或代验收人确认。
- [ ] payment initiator 不能核实自己发起的操作；原 decider 不能处理相关 appeal。

### 9.3 业务闭合

- [ ] 七账号可从浏览器共同完成 `J01..J12`，最终事实可按 correlation 重放。
- [ ] Creator `DECLINE` 后不能被选择，未来资格/匹配特征不受惩罚。
- [ ] stale/cross-run/withdrawn/重复 selection 原子失败且不留下半 Project。
- [ ] 双方只可接受同一 AgreementVersion；变更后旧接受不迁移，旧版本仍可读。
- [ ] Demand Funding 与 Milestone Funding 分离；未 `SECURED` 分别阻断匹配和开工。
- [ ] 合同验收与 beneficiary Outcome 是两个独立动作和事实。
- [ ] 当前 UI 不呈现实质变更为可用动作；未知 operation 或尝试在其他 input 中静默改变范围、时间、报酬、IP/许可均失败关闭，`UC-P1-011` 明确标记未实现。
- [ ] Payment `UNKNOWN` 时禁止盲目重付；对账后按权威合成事实收敛。
- [ ] Review 区分财务事实、自报观察和运营解释，无全局总分。
- [ ] 临时保护范围最小且到期；独立 reviewer 可给出可执行补救。
- [ ] access/correct/restrict/delete/export/withdraw/exit 给出逐域、可理解结果；第三方资料不随主体导出。
- [ ] 退出或账户关闭不吞掉应付报酬、退款、申诉、数据权和必要记录。

### 9.4 协议正确性

- [ ] 六条 route 的 method、auth、schema、status、header 和 no-store contract test 全绿。
- [ ] POST/DELETE 缺 Origin、Session 或 CSRF 均无业务写入。
- [ ] 同 idempotency key/intent 重放同结果；同 key/不同 intent 稳定冲突。
- [ ] response 丢失后以同 key 恢复，不产生重复 Selection、Project、Payment 或 RightsRequest。
- [ ] body 中的 `expected_revision` stale 返回 412；UI 重新读取并要求用户确认。
- [ ] SQLite transaction 故障注入后领域、audit、receipt 与 projection 不分叉。
- [ ] reset 原子增加 epoch，其他 tab/page 必须重新 bootstrap。
- [ ] 每个 persona 的 bootstrap 只含最小投影，越权对象不可枚举。

### 9.5 UX、可访问性与理解

- [ ] 每个 persona 首页明确当前角色、待办、等待对象、期限、版本和下一步。
- [ ] 所有关键状态有文字和图标；禁用动作有理由、责任人和恢复/申诉路径。
- [ ] Payment pending/unknown 不显示完成样式或重复支付主按钮。
- [ ] 版本冲突显示差异；通知失败不冒充知情。
- [ ] 键盘、屏幕阅读器、200% 缩放、窄屏、reduced motion 和 high contrast 可完成同等关键动作。
- [ ] 七账号均可在不读内部 code/数据库的情况下解释当前状态、下一责任角色和自身救济入口。
- [ ] 举报/申诉、数据权和退出在参与者全部相关状态持续可达。

## 10. 操作者最短检查序列

以下序列是固定 revision 上的最短人工 smoke check；它不替代第 8、9 节自动测试：

1. 按仓库运行指南以 `local_synthetic` profile 启动，确认终端与首屏只显示 `127.0.0.1`、`SYNTHETIC`、`G1 NO-GO`、`G2 NO-GO` 和“不发布”；若出现 LAN/public origin、tunnel 或外部请求，立即停止。
2. 打开 `GET /v1/local/personas`，确认只出现且精确出现 `creator-chen`、`demand-owner`、`acceptance-beneficiary`、`case-operator`、`payment-initiator`、`finance-reconciler`、`appeal-reviewer`。
3. 登录 `case-operator`，从 bootstrap 取得 CSRF 与 revision；调用 `POST /v1/local/reset`，header 带 CSRF，body 精确为 `{fixture_id: "scn-g1-001-happy-v1", expected_revision, idempotency_key}`。确认 epoch/revision 增加；用同 key/body 重放结果相同，用 stale revision 返回 412。
4. 依次退出并登录相应 persona，从浏览器完成：Creator Consent/Profile → Demand owner Demand → Case operator review → initiator/reconciler Demand Funding → Case operator Match → Creator 接受 → Demand owner Selection/Agreement → Creator Agreement → initiator/reconciler Milestone Funding → Creator Delivery → acceptance-beneficiary 验收与独立 Outcome → initiator/provider simulator/reconciler Payment → 双方 Outcome/Report → case operator Safety → appeal reviewer Appeal →参与者 Data Right/Exit。每次动作只使用最新 bootstrap revision 和新的幂等键。
5. 在付款 provider 阶段先推进到 `UNKNOWN`；确认 `request_payment` 不可再次发起，再由 `finance-reconciler` 对账收敛。另让 Creator 拒绝一份 Invitation，确认其不可选择且未生成负面资格/排序特征。
6. 验证三条越权：`payment-initiator` 不能执行 reconcile；`case-operator` 不能执行相关 appeal；任一 action/reset body 加入 `actor`、`authority` 或 `organization_id` 均返回 `400 FORBIDDEN_INPUT_FIELD` 且 revision 不变。
7. 用 `appeal-reviewer` 完成独立复核，用参与者完成数据权/退出，确认补救与分项结果可见，退出不吞付款、申诉和必要记录；最后停止进程，确认没有发布、外部通知、真实支付或远程数据副本。

## 11. Definition of Done 与失效条件

本地合成版本只有同时满足以下条件才可称为“可用的本地多角色工程纵切”：

1. 第 9 节全部断言有具名自动测试或可重复浏览器验收证据；
2. 领域、application、SQLite adapter、HTTP、前端、浏览器、安全和可访问性测试在固定 revision 全绿；
3. 七账号的正常、拒绝、Delivery 拒收/重提、Payment `UNKNOWN`、争议/申诉、数据权/退出和恢复旅程全部通过；
4. 没有未解释的权限、隐私、资金、历史或外部副作用失败；
5. README/运行指南明确 loopback、synthetic、reset、删除数据库和“不发布”；
6. 证据只声明本地工程语义，不声明真实使用、理解、支付、合同、市场或效果；
7. 未修改 G1/G2 状态，未新增任何外部发布能力。

以下任一变化使本 ADR 的本地验收失效并要求重新评审：新增 persona/角色、场景、币种、辖区、真实数据类别、外部网络/provider、通知接收者、文件、非 loopback bind、共享环境、发布/托管、SQLite 之外的 adapter、action enum、权限兼任、资金流或 Gate 状态变化。

即使本节全部 GREEN，也只证明 `local_synthetic` composition。进入内部生产质量纵切仍须 G1 整体 `PASS`；接触真实用户、真实产品数据、合同或资金仍须 G2 整体 `PASS`；PostgreSQL/production composition 必须另按 [软件交付章程 Definition of Done](/foundations/software-delivery-charter.md#11-definition-of-done) 和 [P1 工程完成判定](/foundations/software-delivery-charter.md#16-p1-工程完成判定) 提供独立证据。
