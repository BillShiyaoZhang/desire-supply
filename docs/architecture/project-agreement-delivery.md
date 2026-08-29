# Project、Agreement、Milestone 与 Delivery/Acceptance

> 状态：Project & Agreement Context 的权威详细设计；机器契约和可执行 RED 尚未提交，本文不表示功能已实现或真实法律/支付能力已启用。
> 适用范围：Selection 创建 Project shell、不可变 AgreementVersion、多方确认、Milestone、Delivery/Acceptance、ChangeOrder、Workspace/File扫描边界、资金与争议协调。
> 前置依赖：[目标平台领域模型与状态协议](/architecture/platform-domain-model.md)、[Matching/Selection](/architecture/matching-invitation-selection.md)、[Demand](/architecture/demand-lifecycle.md)、[Outbox](/architecture/outbox-delivery.md)与[ADR-0001](/decisions/0001-platform-scope-and-delivery.md)。

## 1. 业务结果、上下文边界与启用限制

Project & Agreement Context 把一个成功 Selection 变成参与方共同确认、可版本化、可交付和可验收的协作事实：

1. `CompleteSelection` 只能创建一个 `PENDING_AGREEMENT` Project及其唯一 Agreement根；
2. 各方对同一不可变 AgreementVersion确认，最后一方确认后才生效；
3. 生效版本原子物化其Milestone定义，但资金仍由Payments保障；
4. Creator针对exact Milestone提交不可变Delivery，DEMAND_OWNER针对exact Delivery接受或要求具体修改；
5. 范围、金额、时间、参与方或验收规则的变化只能经ChangeOrder产生新AgreementVersion；
6. 争议、付款和通知通过明确process manager推进，不把外部事实伪装成本地状态。

本 Context 拥有 `Project`、`ProjectParty`、`ProjectHoldProjection`、`Agreement`、`AgreementVersion`、`AgreementConfirmation`、`Milestone`、`Delivery`、`Acceptance` 与 `ChangeOrder`。Workspace & Files拥有讨论、输入请求、对象引用、FileVersion和扫描事实；Payments拥有Funding/Payment；Trust拥有Dispute/Ruling；IAM拥有User/Organization/role。Project表不能恢复这些外部权限或事实。

首切片先实现Project/Agreement shell与合成文件port；真实电子签署、对象存储、恶意文件扫描、支付、税务、自动验收、争议裁决和对外法律启用仍默认关闭。测试中的fake/沙箱结果不能表述为签署、托管或结算已经获得生产许可。

## 2. Project 根与参与关系

### 2.1 Project

Project由 `CompleteSelection` 内部步骤创建，没有公共 `CreateProject`：

| 字段 | 规则 |
| --- | --- |
| `id` | coordinator在事务前预分配；不可推测 |
| `selection_id` | 全局唯一、不可变；一个Selection最多一个Project |
| `organization_id/demand_id/demand_version_id` | owning demand关系与冻结版本；不可改绑 |
| `creator_user_id/profile_id/profile_version_id` | exact selected creator及被选择的ProfileVersion；不可静默切换 |
| `status` | `PENDING_AGREEMENT / READY_TO_START / ACTIVE / ON_HOLD / COMPLETION_PENDING / COMPLETED / CANCELLED` |
| `aggregate_version` | 从1开始；每个成功Project命令恰加1 |
| `agreement_id` | 创建时唯一且非空；一个Project恰一个Agreement根 |
| `resume_status` | 仅ON_HOLD非空且只为READY_TO_START/ACTIVE |
| `started/completed/cancelled_at` | 仅对应状态非空；UTC数据库时间 |
| `created_at/updated_at` | 数据库时间；不由客户端提供 |

Project不保存一个可由客户端编辑的“当前成员数组”。`ProjectParty` 是受控关系事实：

- `DEMAND_PARTY`：Organization作为法律/采购方，并保存exact authorized DEMAND_OWNER User的初始代表；
- `CREATOR_PARTY`：selected Creator User；
- 后续 `PROJECT_MEMBER` 必须经生效Agreement/ChangeOrder和独立assignment命令添加，不能仅凭IAM角色加入；
- 每个party保存party kind、subject ID、effective interval、source AgreementVersion与aggregate version；历史关系不删除；
- Organization membership/role或User被暂停会立即阻止新动作，但不会抹除历史party证据。

### 2.2 Project状态

| 转换 | 命令 | 守卫 |
| --- | --- | --- |
| 无 → PENDING_AGREEMENT | `CreateProjectFromSelection` | 只在CompleteSelection；exact ACCEPTED Invitation/SELECTED Selection；selection_id唯一；同事务创建Agreement根/parties |
| PENDING_AGREEMENT → READY_TO_START | `ApplyProjectReadiness` | current AgreementVersion ACCEPTED；首个可执行Milestone Funding SECURED；无blocking hold |
| READY_TO_START → ACTIVE | `ConfirmProjectStart` | Agreement要求的双方ready confirmation齐全、数据库日到达允许窗口、首Milestone FUNDED、hold允许 |
| READY_TO_START/ACTIVE → ON_HOLD | `PlaceProjectHold` |受控scope/reason/source；保存resume_status；安全降权不被hold阻止 |
| ON_HOLD → resume_status | `ResumeProject` | 所有blocking hold已解除；Agreement/Funding/party authority仍有效；hold允许 |
| ACTIVE → COMPLETION_PENDING | `RequestProjectCompletion` | 所有Milestone ACCEPTED或经生效ChangeOrder CANCELLED；无open Delivery/Acceptance/Dispute |
| COMPLETION_PENDING → COMPLETED | `ApplyProjectSettlementComplete` | 所有相关Funding满足Agreement允许终态且无open Dispute |
| PENDING_AGREEMENT..ON_HOLD → CANCELLED | `CancelProject` | 生效取消条款/多方确认或Ruling；退款/数据/工作保留计划已创建，但不伪造退款完成 |

COMPLETED/CANCELLED终态。争议不是Project主状态；Trust事件生成scope化hold，只阻止相关Milestone/Payment/Delivery动作。

## 3. Agreement 根与不可变版本

### 3.1 Agreement 根

Agreement保存 `id/project_id/current_agreement_version_id/current_open_version_id/next_version_no/aggregate_version/status/created_at/updated_at`。所有版本命令以Agreement为target并比较其ETag；不存在直接更新AgreementVersion的仓库/API。

根状态只表达当前版本窗口：`EMPTY / DRAFTING / PROPOSED / PARTIALLY_ACCEPTED / ACTIVE / CANCELLED`。规范业务历史仍在各AgreementVersion；根状态不能覆盖历史版本状态。

### 3.2 AgreementVersion 内容

每个版本append-only，状态 `DRAFT / PROPOSED / PARTIALLY_ACCEPTED / ACCEPTED / REJECTED / WITHDRAWN / SUPERSEDED`。内容使用关闭 `agreement-version-json-v1`：

| 分组 | 必需事实 |
| --- | --- |
| `parties` | party ID/kind/subject opaque ID、display label snapshot、代表/确认要求；禁止contact/身份材料 |
| `scope` | deliverables与明确out-of-scope，每项稳定ID；引用selected DemandVersion而不复制未获准内部note |
| `milestones` | stable milestone ID、sequence、deliverables、验收criteria IDs、金额/currency、计划日期、依赖 |
| `acceptance` | 每Milestone验收party、响应期限、允许决定、auto-accept policy code；默认禁用auto-accept |
| `commercial` |总金额、currency、平台费用/creator净额的受控分解、税务责任code；整数且与Milestone合计一致 |
| `intellectual_property` | ownership/license/background-material codes、转移触发点；未知自由法律条款不自动解释 |
| `data_and_security` | data sensitivity、purpose、retention、region、approved tools、AI与human-review规则 |
| `change_and_exit` | change-order、暂停、取消、退款、未完成工作、notice与transition规则codes |
| `dispute` | governing rule bundle、mediation/ruling/appeal window codes；不自报司法结论 |
| `communication` | working language、cadence、official notice channel kind；不保存contact locator |

静态不变量：

- 对象关闭，字符串NFC/有上限，code/ID数组去重排序；金额/天数/sequence为整数且拒绝bool/float；
- party至少包含exact DEMAND_PARTY与CREATOR_PARTY，subject与Project冻结关系一致；新增party必须有已授权source；
- milestone ID/sequence唯一连续；金额总和恰等于commercial total，currency全相同；planned start <= due；依赖只指向更小sequence且无环；
- 每个deliverable至少被一个Milestone引用，每个criterion只属于一个Milestone；
- auto-accept只有发布rule明确允许、期限/提醒/争议守卫完整时可选；首个真实启用feature flag默认为false；
- AI/data条款不能比Demand Invitation snapshot放宽；放宽需要新同意/披露流程，不能仅由Agreement字段覆盖；
- creator净额 + fee +适用受控调整 = total；不保存银行卡、支付token、税号或供应商payload；
- `content_sha256` 对JCS UTF-8规范字节计算，签名面包含Agreement/Project/version_no、schema/canonicalization/rule bundle及全部内容；写前/读后/确认/物化独立复算。

版本还保存 `based_on_agreement_version_id/source_change_order_id/created_by_party_id/created_at/confirmed_at`。一个ChangeOrder最多一个resulting version且双向唯一。失败事务不消耗可观察version_no。

### 3.3 多方确认

Propose冻结 `required_confirmation_party_ids`、内容hash、确认deadline与confirmation policy version。`AgreementConfirmation` 对 `(agreement_version_id, party_id)` 唯一，保存party relationship、actor、Session/auth evidence摘要、confirmed hash、timestamp与receipt command ID；不保存签名图片、token或cookie。

同一party重复相同命令安全重放，不同hash拒绝。最后一份必需确认在锁定Agreement根后原子完成：version→ACCEPTED、旧current→SUPERSEDED、root current指针更新、Milestone materialization facts与事件。同一User不能通过两个party relationship代替不同法律party；代表权限每次确认都从IAM/Organization资源关系重新验证。

该确认是平台业务确认。若司法辖区需要合格电子签名，必须经独立provider设计保存签名envelope摘要/证书链并再次绑定内容hash；当前确认不得宣传为法定电子签名。

## 4. Milestone、Delivery 与 Acceptance

### 4.1 Milestone

Milestone由ACCEPTED AgreementVersion定义并物化，不能由自由公共Create API建立。保存exact agreement/version/definition hash/sequence/amount/currency/acceptance rule和状态：

`DRAFT / FUNDING_PENDING / FUNDED / IN_PROGRESS / DELIVERED / CHANGES_REQUESTED / ACCEPTED / DISPUTED / CANCELLED`。

新AgreementVersion不会原地改旧Milestone。未开始Milestone可由ChangeOrder生成replacement/cancel relationship；已经接受或已结算Milestone永远保留原AgreementVersion。金额增加/新Milestone必须先建立新MILESTONE Funding，未FUNDED不能开始。

`StartMilestone`要求Project ACTIVE、前置Milestone满足Agreement规则、exact Funding SECURED、所有required workspace inputs READY且无scope hold。`expires_at/deadline <= db_now`采用协议定义的定时命令，客户端时间无效。

### 4.2 Workspace/File 边界

Workspace & Files拥有：

- `FileObject/FileVersion` 的opaque ID、owner Project、size/media/hash/object-key密文引用；
- one-time upload capability、multipart状态、恶意文件扫描/内容策略结果；
- project discussion、input request与access log。

Project Context只保存 `file_version_id/content_sha256/scan_attestation_id` 的受控引用。raw object key、预签名URL、provider token、文件正文和扫描报告不进入Delivery、receipt、audit、outbox或日志。

上传分两步：授权端点返回短期single-purpose capability（sensitive/no-store/redact-only）；完成后Workspace验证size/hash/media并异步扫描。只有exact Project party可创建，只有状态 `AVAILABLE + CLEAN`、扫描provider/version有效且hash一致的FileVersion可进入SUBMITTED Delivery。未知/未完成/感染/隔离/scan unavailable均fail closed；扫描结果漂移在事务内复核。

文件下载也使用短期single-file capability；普通DTO只返回file_version_id、安全label、media type、size、hash与scan status。任何signed URL都不得进入持久response receipt。

### 4.3 Delivery

Delivery状态 `PREPARING / SUBMITTED / WITHDRAWN / SUPERSEDED`，绑定一个Milestone和exact AgreementVersion：

- PREPARING可追加不可变manifest replacement，但每次保存形成新的draft revision；
- Submit冻结关闭manifest：deliverable item IDs、FileVersion refs/hashes、external artifact refs（只允许受控scheme）、声明、submission note的安全摘要、created_by与schema/hash；
- SUBMITTED内容不可改、不可撤回；错误通过Acceptance→CHANGES_REQUESTED后提交新Delivery，旧Delivery→SUPERSEDED；
- 同Milestone同时最多一个current SUBMITTED Delivery；每个submit递增delivery_no；
- 提交同事务创建PENDING Acceptance并使Milestone→DELIVERED。

自由submission note不进入事件或需求方列表摘要；只有exact party projection可见且仍经过长度/内容策略。

### 4.4 Acceptance

每个SUBMITTED Delivery恰一个Acceptance，状态 `PENDING / ACCEPTED / CHANGES_REQUESTED / DISPUTED`。它绑定Agreement中的exact验收party/criteria/deadline/rule version。

- `AcceptDelivery`要求actor代表验收party、Delivery仍current、逐criterion结果完整；同事务Acceptance/Milestone→ACCEPTED并发 `FundingReleaseRequested`，但Funding仍未SETTLED；
- `RequestSpecificChanges`的每项必须引用existing criterion/deliverable与关闭difference code、requested remedy、deadline；不能扩大scope或金额；需扩张时必须ChangeOrder；
- `AutoAcceptDelivery`只由定时SYSTEM命令执行：rule显式允许、`deadline <= db_now`、必要提醒事实存在、无pending change/dispute/hold且Acceptance仍PENDING；通知投递失败会进入人工review，首版真实启用不自动接受；
- `OpenDeliveryDispute`由Trust创建Dispute/hold后经source inbox把Acceptance/Milestone→DISPUTED；Project endpoint不能自造Dispute状态。

## 5. ChangeOrder

ChangeOrder是独立根，状态 `DRAFT / PROPOSED / PARTIALLY_ACCEPTED / ACCEPTED / REJECTED / WITHDRAWN / APPLIED`，以 `change-order-json-v1` 保存：source AgreementVersion、scope/milestone/party/amount/schedule/acceptance/data/AI变更的关闭patch语义、影响分析、required parties、funding plan与content hash。

ChangeOrder不是任意JSON Patch；每个change item带stable path code、old value hash、new closed value和reason code。不能修改已接受/结算Milestone的历史，只能追加replacement/credit/refund/补救计划。

多方确认与Agreement相同，最后一方只使ChangeOrder→ACCEPTED。`ApplyChangeOrder`同时比较ChangeOrder与Agreement两个ETag并在一个Project Context事务中：

1. 锁ChangeOrder→Agreement→current AgreementVersion→受影响Milestone；
2. 由source + closed changes纯函数生成exact新Agreement content/hash；
3. 以 `source_change_order_id` 唯一创建且ACCEPTED一个resulting AgreementVersion；
4. old current→SUPERSEDED、Agreement current指针更新、ChangeOrder→APPLIED；
5. 物化新/替代/取消Milestone，但不伪造Funding；
6. 写各自audit/outbox/receipt并一次COMMIT。

重复或并发Apply最多一个成功；不能生成两个resulting version。需要追加资金的Milestone保持DRAFT/FUNDING_PENDING，Project不会因Agreement已更新而绕过资金门槛。

## 6. 命令、授权和SafetyHold

公开命令只接收BFF actor，不接收user/role/session/org/status/hash/server time：

```text
CreateAgreementVersion / ProposeAgreementVersion
AcceptAgreementVersion / RejectAgreementVersion / WithdrawAgreementVersion
ConfirmProjectStart / PlaceProjectHold / ResumeProject / CancelProject
StartMilestone
CreateDelivery / SaveDeliveryDraft / SubmitDelivery / WithdrawDraftDelivery
AcceptDelivery / RequestSpecificChanges
CreateChangeOrder / ProposeChangeOrder / AcceptChangeOrder
RejectChangeOrder / WithdrawChangeOrder / ApplyChangeOrder
```

授权同时要求ACTIVE User/Session/Family、当前IAM role/policy、exact ProjectParty/Organization representation、资源状态、字段权限与无blocking hold。`PROJECT_MEMBER`或ORG_ADMIN本身不授予任意Project访问；party/assignment是必需关系。SYSTEM命令绑定exactsource event/job/project/milestone。

平台固定IAM投影 `authorize_project_action_v1` 返回actor/session、party ID/kind、organization/project assignment、policy marker与auth strength；Project在线角色无IAM表SELECT。represent Organization还要求ACTIVE Membership及被Agreement允许的DEMAND_OWNER/PROJECT_MEMBER角色。

增加或恢复合同/工作/披露的命令必须事务外SafetyHold：Propose/Accept Agreement、Resume/Start Project、StartMilestone、SubmitDelivery、AcceptDelivery、Propose/Accept/Apply ChangeOrder。hold绑定action、actor/party/project、prospective aggregate versions、exact content/delivery/change hash、agreement/milestone/funding versions和policy version；锁内漂移则出事务重评。

Reject/Withdraw、RequestChanges、PlaceHold、Cancel和Draft保存属于降权/私有操作，不被hold阻止。未知、非party、跨org、失效assignment统一404；证明关系后才返回stale 412、state 409、validation 422。Safety BLOCK 403、unavailable 503，零业务写。

## 7. 幂等、锁序与故障恢复

每个外部写都有Idempotency-Key和目标aggregate ETag；CreateProject是CompleteSelection内部例外，使用外部ChooseCreator receipt/selection ID唯一。AgreementVersion命令比较Agreement ETag，ChangeOrder apply同时比较Agreement与ChangeOrder ETag，Delivery命令比较Milestone或Delivery根版本并在OpenAPI明确。

receipt keyed identity/HMAC覆盖method/path/project/target/所有If-Match/body/schema/content hash；raw key、content、file URL、note、Session secret不落库。completed结果允许同actor新ACTIVE Session重放，same key/different payload 409。

Project Context通用锁序：IAM authority → Project → ProjectParty按ID → Agreement → current/open AgreementVersion → confirmation party按ID → Milestone按sequence/ID → Delivery → Acceptance → ChangeOrder → Workspace scan marker/Funding/Trust投影 → receipt。ApplyChangeOrder使用其专属顺序但不能与通用命令形成逆序；实现前以并发图测试证明。

每个逻辑写稳定checkpoint；aggregate/version/confirmations/milestones/delivery/acceptance/receipt/audit/outbox一次COMMIT。COMMIT_SENT断线discard连接，用新连接读取exact receipt与所有预期事实；partial/corrupt/IN_PROGRESS为503并报警。source event用durable inbox去重，乱序进入reconciliation而非猜测推进。

## 8. API 与接收者投影

首版主要路由：

```text
GET  /v1/me/projects
GET  /v1/projects/{project_id}
GET  /v1/projects/{project_id}/agreement
POST /v1/agreements/{agreement_id}/versions
POST /v1/agreements/{agreement_id}/versions/{version_id}/propose
POST /v1/agreements/{agreement_id}/versions/{version_id}/accept
POST /v1/agreements/{agreement_id}/versions/{version_id}/reject
POST /v1/projects/{project_id}/start-confirmations
POST /v1/milestones/{milestone_id}/start
POST /v1/milestones/{milestone_id}/deliveries
POST /v1/deliveries/{delivery_id}/submit
POST /v1/deliveries/{delivery_id}/accept
POST /v1/deliveries/{delivery_id}/request-changes
POST /v1/projects/{project_id}/change-orders
POST /v1/change-orders/{change_order_id}/propose
POST /v1/change-orders/{change_order_id}/accept
POST /v1/change-orders/{change_order_id}/apply
```

`GET /projects/{id}`不是只要知道ID即可访问。投影固定为：

| 投影 | 接收者 | 允许字段 |
| --- | --- | --- |
| `PROJECT_PARTY` | exact effective party/representative | Agreement允许的内容、Milestone/Delivery/Acceptance状态和安全File元数据；按party字段规则过滤商业/内部note |
| `PROJECT_REVIEW_ASSIGNMENT` | exact time-bound ops/trust/finance assignment | purpose所需字段最小集；不因平台角色读全项目 |
| `FUNDING_INPUT` | exact Funding requirement workload | party opaque IDs、exact milestone amount/currency/agreement hash；无scope正文/file |
| `DISPUTE_EVIDENCE` | exact Dispute/case assignment | 被case scope引用的版本/hash/file证据；不扩张到全Project |
| `ANALYTICS` | projection worker | 去标识化codes/timestamps/amount buckets；无正文和party identity |

所有普通响应closed、no-store、strong ETag/trace ID；file capability响应单独sensitive/no-store/redact。列表keyset cursor绑定actor/party/filters/schema/key IDs。

首版wire错误集合：400 `INVALID_REQUEST`；401认证/Session；403 `ACCESS_DENIED/SAFETY_HOLD_BLOCKED`；404 `RESOURCE_NOT_FOUND`；409 `INVALID_STATE_TRANSITION/IDEMPOTENCY_KEY_REUSED/AGREEMENT_VERSION_CHANGED/DELIVERY_CHANGED/FUNDING_FACT_CHANGED/CHANGE_ORDER_ALREADY_APPLIED`；412 `PRECONDITION_FAILED`；422 `AGREEMENT_VALIDATION_FAILED/DELIVERY_VALIDATION_FAILED/CHANGE_ORDER_VALIDATION_FAILED/POLICY_ACCEPTANCE_REQUIRED/FUNDING_REQUIRED`; 503配置/服务不可用。OpenAPI逐operation列subset。

## 9. 事件、审计和隐私

关闭事件至少包括Project创建/ready/start/held/resumed/completion/cancel；Agreement创建、版本创建/提议/部分确认/接受/拒绝/撤回/supersede；Milestone创建/资金请求/已资金/开始/交付/修改/接受/争议/取消；Delivery创建/提交/withdraw/supersede；Acceptance创建/接受/修改/争议；ChangeOrder创建/提议/部分确认/接受/拒绝/withdraw/applied。

事件payload只含opaque IDs、状态、aggregate/version_no、content/file manifest hash、受控reason codes、deadline和必要Funding requirement ID；不含Agreement/Scope/criterion/note/file名正文、金额（Funding消费者按ID读exact port）、contact、object key/URL、provider payload或争议证据。每封事件在写outbox前用published schema验证。

Audit可保存party/action/target/result/版本/hash/受控reason和criteria IDs，不保存正文、文件locator、支付凭据或自由note。日志、trace、metric、receipt、notification和dead letter递归秘密sentinel覆盖Agreement文本、金额、data plan、IP条款、submission/change note、文件引用秘密、Session/CSRF和Idempotency-Key。

## 10. PostgreSQL、RLS 与不变量

独立 `project` schema至少包含projects、parties、holds projection、agreements、agreement_versions、confirmations、milestones、deliveries、delivery_file_refs、acceptances、change_orders/change confirmations、receipts/source inbox。Workspace/Payment/Trust只通过复合引用/授权port连接，不获得跨schema任意UPDATE。

数据库约束至少保证：selection_id唯一；project恰一个agreement；party subject shape；version_no/current/open指针；一open AgreementVersion；confirmation party唯一；accepted版本所有required confirmation齐全（deferred trigger）；Milestone定义与Agreement复合FK；金额/currency/sequence shape；一current submitted Delivery；Delivery/File hash复合一致；一Delivery一Acceptance；ChangeOrder/result version双向唯一；状态shape和时间shape。

全部表ENABLE+FORCE RLS。party只见自己关系允许的projection；representative必须经IAM exact marker；worker只见exact source/job；review/finance/trust只见assignment scope；PUBLIC无权限，在线角色非owner/无BYPASS。forged GUC、跨Project/Organization FK、过期party/assignment、失效Session和direct table scan均拒绝。

JSONB完整语义由应用closed schema/JCS validator写前读后验证；数据库只声称根shape/hash/身份/金额等可表达约束。Migration forward-only、digest/review pin、PG18真实RLS/constraint/concurrency和wheel门禁；Project schema不进入IAM compatibility view。

## 11. TDD 顺序

1. 发布Project OpenAPI、event、Agreement/Delivery/ChangeOrder closed schemas；contract RED→GREEN。
2. Domain/性质RED覆盖全部状态、终态、版本/金额/party/milestone/依赖、hash、确认集合和ChangeOrder纯变换。
3. Memory application RED覆盖CreateProject shell、multi-party Agreement、Milestone物化、Funding process、file scan、Delivery/Acceptance、更正、hold、receipt/fault/commit unknown。
4. 最小GREEN；人工/沙箱port明确非生产，不跳过外部启用门槛。
5. 先写PG/RLS详细页，再以真PG18 RED覆盖跨project、forged GUC、deferred confirmation、并发last accept、double Delivery、double ApplyChangeOrder、source inbox与故障回滚，最后forward-only GREEN。
6. HTTP/composition + IAM/Profile/Demand/Matching/Outbox/Fake Workspace/Payments真实PG E2E；三类party/assignment秘密sentinel。
7. 外部文件/签名/支付供应商各自先有contract/sandbox/故障设计，再接真实适配器。

## 12. REQ → DESIGN → TEST → CODE

| REQ | DESIGN | 验收 TEST | CODE | 状态 |
| --- | --- | --- | --- | --- |
| `REQ-PROJECT-001` | DES-PROJECT-001 · §2 | `TEST-APP-PROJECT-SHELL-001`, `TEST-DB-PROJECT-UNIQUE-001` | planned | design |
| `REQ-PROJECT-002` | DES-PROJECT-002 · §3 | `TEST-CONTRACT-AGREEMENT-001`, `TEST-PROP-AGREEMENT-001` | planned | design |
| `REQ-PROJECT-003` | DES-PROJECT-003 · §3/6 | `TEST-APP-AGREEMENT-CONFIRM-001` | planned | design |
| `REQ-PROJECT-004` | DES-PROJECT-004 · §4 | `TEST-APP-MILESTONE-001`, `TEST-APP-DELIVERY-001` | planned | design |
| `REQ-PROJECT-005` | DES-PROJECT-005 · §4 | `TEST-CONTRACT-WORKSPACE-FILE-001`, `TEST-APP-FILE-SCAN-001` | planned | design |
| `REQ-PROJECT-006` | DES-PROJECT-006 · §5 | `TEST-PROP-CHANGE-ORDER-001`, `TEST-DB-CHANGE-ORDER-001` | planned | design |
| `REQ-PROJECT-007` | DES-PROJECT-007 · §6/8 | `TEST-AUTH-PROJECT-001`, `TEST-SEC-PROJECT-001` | planned | design |
| `REQ-PROJECT-008` | DES-PROJECT-008 · §7 | `TEST-APP-PROJECT-RECEIPT-001` | planned | design |
| `REQ-PROJECT-009` | DES-PROJECT-009 · §9/10 | `TEST-EVENT-PROJECT-001`, `TEST-DB-PROJECT-RLS-001` | planned | design |

有效RED后才能标red；相同断言与适用回归/真实依赖GREEN后才标green并回填实现路径与migration。
