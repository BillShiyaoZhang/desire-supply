# Funding、Payment、Webhook 与对账投影

> 状态：Funding & Payments Context 的权威详细设计；机器契约和可执行 RED 尚未提交，本文不表示平台持有资金、真实供应商已接入或任何司法辖区已批准启用。
> 适用范围：DemandVersion/Milestone Funding target、人工双人核实、供应商支付操作镜像、webhook inbox、replacement/allocation、release/refund/settlement、对账异常与RLS。
> 前置依赖：[目标平台领域模型与状态协议](/architecture/platform-domain-model.md)、[Demand](/architecture/demand-lifecycle.md)、[Project/Agreement](/architecture/project-agreement-delivery.md)、[ADR-0001](/decisions/0001-platform-scope-and-delivery.md)与[Outbox](/architecture/outbox-delivery.md)。

## 1. 安全边界与非目标

Payments Context 保存外部持牌供应商事实的可审计镜像，或首切片人工资金证明的双人确认事实。它不是银行、钱包、托管账户、复式总账或供应商事实的替代品。

本 Context 拥有 `Funding`、不可变 `FundingTarget`、`FundingConfirmation`、`FundingAllocation`、`PaymentOperation`、`ProviderEventInbox`、`ProviderObjectProjection`、`ReconciliationRun/Exception` 和相关receipt/audit/outbox。它不拥有 Demand、Agreement、Milestone、Acceptance、Dispute、User/Organization或真实provider对象。

严格禁止：

- 在应用数据库保存银行卡、账户号、支付token、CVV、身份证件、完整webhook正文、provider secret或可直接访问后台的URL；
- 根据客户端 `funded=true`、截图、邮件、MVP funding evidence或单人操作把Funding标为SECURED；
- 用本地Payment状态猜测provider已settled/refunded；
- 原地改FundingTarget、金额、币种、付款人或收款人；
- 将DEMAND_VERSION资金直接释放给Creator；
- 把Payment `SUCCEEDED` 等同于所有业务目标都已完成。

真实供应商接入前必须另行确定单一司法辖区、资金流类型、牌照/合同、KYC/KYB责任、PCI范围、退款/拒付/税务、数据区域和人工降级。代码可以用合成sandbox/fake证明协议，但production adapter保持feature flag关闭。

## 2. FundingTarget 判别联合

Funding创建后target不可变，只允许：

### 2.1 DEMAND_VERSION

```text
target_type = DEMAND_VERSION
organization_id, demand_id, demand_version_id, demand_content_sha256
amount_minor, currency
purpose_code = PRE_MATCH_FUNDING
expires_at
pre_agreement_refund_policy_version
payer_organization_id
agreement_version_id = NULL
milestone_id = NULL
creator_payee_id = NULL
```

它只证明exact DemandVersion进入Matching前有资金保障，不能release/payout。Demand修订必须创建新target/Funding；旧Funding按退款/取消策略处理。

### 2.2 MILESTONE

```text
target_type = MILESTONE
organization_id, project_id, agreement_id, agreement_version_id, milestone_id
milestone_definition_sha256
amount_minor, currency
purpose_code = MILESTONE_PERFORMANCE
payer_party_id, creator_payee_party_id
demand_version_id = NULL as target
```

Milestone target金额/currency/party必须与ACCEPTED AgreementVersion复合一致。它可在Milestone ACCEPTED且无hold/dispute时请求release；仍不能由客户端直接设置settled。

数据库判别CHECK与复合FK保证恰一种shape。所有金额使用ISO-4217最小货币单位整数、`> 0`、拒绝bool/float；currency不做隐式换汇。target canonical hash覆盖type、全部引用、金额/币种、purpose、policy version与期限。

## 3. Funding、replacement 与 allocation

### 3.1 Funding 根

Funding至少保存：

| 字段 | 规则 |
| --- | --- |
| `id/target_id/target_sha256` | 不可推测且不可变 |
| `status` | `REQUIRED / PENDING / SECURED / REPLACED / RELEASE_PENDING / SETTLED / REFUND_PENDING / PARTIALLY_REFUNDED / REFUNDED / FAILED / CANCELLED` |
| `mode` | `MANUAL_ATTESTATION / PROVIDER`，创建后不可变 |
| `replaces_funding_id` | 仅新Funding可指向同target的FAILED/CANCELLED predecessor |
| `active_payment_operation_id` | 可空；不是provider事实来源 |
| `secured/settled/refunded_minor` | provider/manual已验证的累计投影；形状受状态约束 |
| `provider_object_digest/key_id` | provider mode所需exact opaque object identity；raw/sealed ref单独受限存储 |
| `aggregate_version` | 每命令恰加1 |
| UTC times | database/provider occurred/observed分离，客户端不可自报 |

同一 `(target_sha256,purpose_code)` 同时最多一个active Funding；active包含REQUIRED/PENDING/SECURED/RELEASE_PENDING/REFUND_PENDING/PARTIALLY_REFUNDED。FAILED/CANCELLED/REPLACED不可回退。

### 3.2 Replacement

失败重试从不复活旧Funding：`CreateReplacementFunding`要求predecessor FAILED/CANCELLED、target hash完全相同、没有active sibling、retry policy仍允许。新Funding保存retry sequence和predecessor；provider idempotency key使用新Funding/operation ID，不能复用旧provider object后猜状态。

若target、金额、币种、Agreement/DemandVersion任一变化，必须由上游业务创建新target，不称replacement。

### 3.3 Demand→Milestone allocation

预匹配Funding不能原地变成Milestone Funding。允许复用供应商授权时，创建独立 `FundingAllocation`：

- source为SECURED DEMAND_VERSION Funding；destination为同Organization/Project的SECURED MILESTONE Funding；
- 保存provider确认的allocation/reuse event ID、amount/currency与两target hash；
- 同一source累计allocated不超过secured amount；同一destination allocation总和恰等于target amount；
- 最后一笔有效allocation后source可 `SECURED → REPLACED`，但历史SECURED事实保留；
- provider不支持复用时，先按政策退款/取消source，再独立保障destination。

## 4. 人工双人资金核实

首切片允许 `MANUAL_ATTESTATION`，只表示平台在受控环境中由两名不同Finance Operator核实了一项外部资金保障证据，不表示托管或provider settlement。

流程：

1. `InitiateManualFundingReview`使REQUIRED→PENDING，预分配review case、confirmation policy/version、deadline与exact target hash；
2. 两名不同ACTIVE `FINANCE_OPERATOR`各提交 `ConfirmManualFundingEvidence`，body只含case ID、target hash、关闭evidence kind、受控evidence reference ID和attestation codes；
3. evidence正文留在受控外部系统；普通表只存keyed digest、安全类别、verified_at与访问审计；
4. confirmer不能是Demand reviewer、owning Organization成员、另一confirmer或case assigner本人；assignment有purpose/expiry/conflict attestation；
5. 每人对case唯一确认；撤销/拒绝后旧确认不能复用；
6. 最后一份有效确认在同事务锁Funding/case/confirmations，复核target和evidence digest一致，再PENDING→SECURED；
7. 任一确认过期、权限撤销、证据不一致或clock equality `deadline <= db_now`时不保障；需要新case。

人工证据不能触发PaymentOperation或供应商Payout。切换到provider mode必须创建新Funding/明确迁移，不能改mode。

`INTERNAL_SANDBOX` 的 Finance workbench 不能只给操作员两个不可读的哈希后要求勾选。
assignment-bound detail 在服务端重新验证当前 Session、Finance duty 与 exact assignment 后，允许从
review 绑定的不可变 DemandVersion 投影一个关闭的安全摘要：`demand_version_id`、content SHA-256、
计划合成预算的币种/最小值/最大值/直接成本，以及固定的实际资金 `0`、provider `NONE`、
PaymentOperation `NONE`、evidence kind 和 `NO_REAL_FUNDS_OR_PAYMENT`。页面必须把计划预算和实际资金
分开标注，并继续展示 target/evidence 审计哈希。该投影不得读取当前 Demand aggregate/status 来拼接
历史幂等响应；否则后续确认或匹配会让旧 command receipt 的 replay 响应发生变化。

终态 case 离开待办队列后，Finance Operator 仍需要可发现的本人历史，不能依赖保存 opaque ID。
Demand12 提供关闭的 keyset 列表：只有本人 assignment 已 `COMPLETED`，且本人提交过 confirmation 或
terminal finding 的 `SECURED / DISCREPANCY / REJECTED` case 可见。投影仅含 review、Demand、
DemandVersion、status、completed_at；不含组织、同案其他核实人、金额、证据或 finding 正文。游标由服务端
HMAC 绑定 actor 与 `(completed_at, review_id)`，跨账号、篡改或不可见坐标都失败。Web 工作台从“我的已完成
资金审查”打开详情时再次核对 review/Demand/version/status/ETag，重登与容器重启后仍从 PostgreSQL 发现。

## 5. PaymentOperation 与供应商适配器

PaymentOperation是某次向provider发出的不可变意图：

| 字段 | 规则 |
| --- | --- |
| `type` | `AUTHORIZATION / CAPTURE / RELEASE / REFUND / PAYOUT` |
| `status` | `CREATED / PENDING / SUCCEEDED / FAILED / CANCELLED` |
| identity | funding、target hash、amount/currency、payer/payee opaque party、operation reference唯一 |
| provider request | canonical request schema/version/hash、provider idempotency key digest/key ID |
| provider projection | object/event keyed digests、controlled status/reason、provider occurred/observed UTC |
| retry | `retry_of_payment_id`只指FAILED/CANCELLED同type/amount/target操作 |

FAILED/CANCELLED不回PENDING；retry新建Payment。SUCCEEDED历史不回退；退款/拒付/调整是新Payment或ProviderDispute事实。

Provider adapter端口分三步：

1. 事务内创建CREATED Payment/outbox job并COMMIT；
2. worker以lease/fencing领取，事务外用provider credential调用exact request；provider idempotency key由稳定domain-separated keyring派生；
3. provider响应只形成待验证result，最终事务锁Payment/Funding并与webhook/主动查询事实核对后推进。

网络超时、TLS错误或响应丢失一律 `RESULT_UNKNOWN` 内部状态/对账任务，不把Funding猜为成功/失败。重新调用前先按provider idempotency/query接口查询exact operation；若provider无安全查询能力，则停止自动重试并人工对账。

provider secret由KMS/secret manager提供，构造、repr、exception、metrics均不可泄漏；每个credential有purpose/environment/merchant scope/key ID/rotation窗口。production不能使用test key或通用跨merchant credential。

## 6. Webhook durable inbox

Webhook HTTP入口是协议例外，不用客户端Idempotency-Key，但必须：

- exact provider/path/method/content-type/size/deadline/源策略；
- 在读取正文时同时计算raw digest，限制body bytes与JSON深度；
- 使用provider当前/保留验证key检查签名、timestamp window、merchant/environment与event ID；
- 签名验证、canonical event抽取和schema关闭校验在任何业务写之前；
- `(provider, merchant_scope, provider_event_id)` durable unique；相同ID不同raw/canonical digest进入security incident，不覆盖；
- inbox一次COMMIT后再异步应用；HTTP ack只确认durable接收，不宣称Funding已推进；
- raw正文默认不进主库。确有provider争议保留要求时，加密写受限evidence store并保存object digest/retention key，不进普通DTO/log；
- canonical inbox只保存allowlist：event ID/type、object keyed digest、amount/currency、controlled status、provider occurred time、raw digest、signature key ID、received time；
- 未知object、金额/币种/merchant不符、乱序不可能转换进入 `ReconciliationException`，零业务推进。

consumer锁inbox→Payment→Funding，验证expected prior状态与aggregate version。重复apply读取已完成inbox result，不重复outbox。COMMIT断线以后用新连接读inbox+Payment+Funding全链裁决。

## 7. 状态命令

| 转换 | 命令 | 权威/守卫 |
| --- | --- | --- |
| 无→REQUIRED | `CreateFundingRequirement` | authenticated SYSTEM/assigned finance；exact authorized upstream target；target唯一 |
| FAILED/CANCELLED predecessor→new REQUIRED | `CreateReplacementFunding` | retry policy、same target、无active sibling |
| REQUIRED→PENDING | `InitiateFunding` | DEMAND_OWNER仅可开始获准provider checkout；SYSTEM/manual assignment；provider intent/case已创建 |
| PENDING→SECURED | `ApplyProviderFundingSecured` | verified inbox/object/amount/currency/merchant匹配 |
| PENDING→SECURED | `CompleteManualFundingConfirmation` | 双人、assignment/conflict/deadline/evidence一致 |
| PENDING→FAILED | `ApplyFundingFailure` | verified provider terminal或manual case拒绝；controlled reason |
| REQUIRED/PENDING→CANCELLED | `CancelFunding` | upstream已取消且provider确认无保障，或manual未完成 |
| SECURED→REPLACED | `CompleteFundingAllocation` | destination已SECURED且provider reuse关系确认 |
| SECURED→RELEASE_PENDING | `RequestFundingRelease` | 仅MILESTONE；exact Acceptance/Milestone ACCEPTED、无hold/dispute、amount/fees一致 |
| RELEASE_PENDING→SETTLED | `ApplySettlement` | verified provider payout/settlement facts；累计值恰target amount |
| SECURED/RELEASE_PENDING→REFUND_PENDING | `RequestRefund` | exact cancellation/change/ruling authorization、refund amount与reason；hold规则允许退款降权 |
| REFUND_PENDING→PARTIALLY_REFUNDED | `ApplyPartialRefund` | verified cumulative `0 < refunded < required` |
| REFUND_PENDING/PARTIALLY_REFUNDED→REFUNDED | `ApplyRefundComplete` | verified cumulative等于authorized refund amount |
| SETTLED→SETTLED + dispute fact | `ApplyProviderDispute` | verified chargeback/dispute；不改写历史settled，发Trust hold/process事件 |

PARTIALLY_REFUNDED仍占active唯一性。任何累计金额超限、不同currency、object swap、旧event版本或不可能倒退都进入reconciliation，不以宽松转换求成功。

## 8. 授权、职责分离与SafetyHold

普通Organization actor只能为exact关联Demand/Project启动获准Funding流程或查看安全状态，不能确认provider/manual事实。Finance操作要求IAM平台职责 + exact time-bound `FinanceAssignment`，并检查purpose、target、amount threshold、organization conflict与四眼规则。ORG_ADMIN不能授予FINANCE_OPERATOR。

SYSTEM worker必须用operation-scoped workload credential绑定provider/merchant/source event/payment/funding，不能跨merchant全表处理。Payments在线角色不SELECT IAM/Demand/Project正文，通过固定authorized target ports核对exact事实。

增加资金外流或恢复交易的动作——InitiateProviderFunding、CompleteManualFunding、Allocate、RequestRelease、RequestRefund、Resume reconciliation——执行版本化SafetyHold。hold绑定actor/original actor、organization、Funding/Payment/target/version、amount/currency、source authorization hash与policy version。退款/取消在安全降权场景不被阻止支付给原付款方，但仍需anti-fraud/refund authorization策略；普通SafetyHold不能迫使把资金释放给Creator。

未知/cross-org/nonassignment统一404；关系证明后stale 412、state 409、validation 422。provider/hold/key unavailable 503，零部分业务写。

## 9. 对账与不确定结果

`ReconciliationRun`只读取得provider结算/对象列表的受控摘要，与本地ProviderObjectProjection比较。每个diff形成 `ReconciliationException`：

```text
UNKNOWN_PROVIDER_OBJECT
UNKNOWN_LOCAL_OPERATION
STATUS_MISMATCH
AMOUNT_MISMATCH
CURRENCY_MISMATCH
MERCHANT_SCOPE_MISMATCH
DUPLICATE_EVENT_CONFLICT
OUT_OF_ORDER_EVENT
RESULT_UNKNOWN
STALE_PROJECTION
```

Exception保存IDs/keyed digests、expected/actual controlled codes与时间，不保存raw payload/账户。处理者必须有exact assignment；resolve命令只能引用新verified provider event/query或明确correction event，不能直接编辑Funding/Payment状态。

每日对账、webhook滞后和RESULT_UNKNOWN有SLA/告警。自动动作在不确定时暂停相关release/refund，不暂停无关Funding。恢复演练必须证明inbox、outbox、provider projection、receipt与aggregate一致。

## 10. API、幂等与故障

外部/运营面示例：

```text
GET  /v1/organizations/{organization_id}/funding/{funding_id}
POST /v1/funding/{funding_id}/initiate
POST /v1/finance/funding/{funding_id}/manual-confirmations
POST /v1/finance/funding/{funding_id}/cancel
POST /v1/finance/funding/{funding_id}/refunds
GET  /v1/finance/reconciliation-exceptions
POST /v1/finance/reconciliation-exceptions/{id}/resolve
POST /v1/webhooks/payments/{provider}
```

provider/browser redirect/capability carrier单独标`sensitive/no-store/redact`；普通DTO只含Funding/Payment opaque ID、target kind、amount/currency（仅获准party）、controlled status、timestamps、aggregate version与next action，不含provider object/ref/evidence/operator身份。

外部写使用Idempotency-Key和Funding/Payment If-Match；provider webhook用verified event identity。receipt HMAC覆盖method/path/target/If-Match/body/amount/currency/authorization hash，raw key/provider payload不落库。同key同payload安全重放；不同payload 409。

锁序：provider inbox/reconciliation source → Funding target → Funding predecessor/source allocation → Funding → manual case/confirmers按User ID → Payment按ID → upstream authorization marker → receipt。外部provider call永不发生在活跃DB事务中。

每写点checkpoint、一次COMMIT、commit-unknown新连接全链读取。调用provider结果未知还需provider-side query/idempotency证据；仅本地receipt不能证明外部发生或未发生。

首版wire code：400 invalid；401 auth/session；403 access/hold；404 non-disclosure；409 state/idempotency/target/funding/payment/provider-event changed；412 stale；422 `FUNDING_VALIDATION_FAILED/MANUAL_CONFIRMATION_REQUIRED/REFUND_NOT_AUTHORIZED/RECONCILIATION_REQUIRED`; 503 config/provider/key/service unavailable。SQL/provider原码不出wire。

## 11. 事件、隐私与投影

事件包括Funding created/pending/secured/secured-manually/failed/cancelled/replacement/allocated/release-requested/settled/refund-requested/partially-refunded/refunded；Payment created/submitted/succeeded/failed/cancelled；reconciliation exception opened/resolved；provider dispute observed。

事件payload只含opaque IDs、target type/ID、amount/currency（仅专用internal financial event schema且topic ACL收窄）或采用requirement ID后授权读取、controlled status/reason、aggregate version和timestamps。面向普通domain outbox优先thin event，不包含provider object、evidence、merchant、payer/payee locator、fees细目或raw payload。日志/metric/notification永不含金额明细或供应商ID；财务指标使用受控bucket且无organization/user label。

Funding读取投影按exactparty/finance assignment/process worker分开；没有anonymous/global finance list。审计记录actor/assignment/action/target/result/amount digest/controlled reason/source event，不保存evidence正文或provider secret。

## 12. PostgreSQL 与RLS

独立 `payments` schema至少包含funding_targets、fundings、manual_cases/confirmations、allocations、payment_operations、provider_event_inbox/object projections、reconciliation runs/exceptions、receipts。sealed provider reference在独立列/表并由更窄role访问。

关键约束：FundingTarget判别shape；target hash immutable；active target partial unique；replacement same target；allocation累计边界；manual distinct confirmer/deadline；payment retry/type/amount一致；provider event identity+digest唯一；累计secured/refunded/settled与状态shape；source event/inbox result一致。append-only provider/confirmation facts禁止UPDATE/DELETE。

全部ENABLE+FORCE RLS。party只见自己的target安全投影；finance只见assignment；webhook role只能insert verified inbox入口且不能读Funding；consumer只见exact inbox/object；provider worker只见exactleased Payment；PUBLIC无权限，在线角色非owner/无BYPASS。forged GUC/cross-org/object swap/expired assignment均拒绝。

Migration forward-only/raw digest/review pin、PG18真实constraint/RLS/concurrency、wheel packaging。provider adapter独立contract/sandbox suite；真实secret/网络测试不得在普通CI泄露。

## 13. TDD顺序与追踪

1. 发布Funding/Payment OpenAPI、event/provider canonical inbox schemas；target判别/amount/privacy contract RED→GREEN。
2. Domain/性质RED覆盖全部状态、replacement/allocation、累计金额、manual四眼、乱序provider事件和终态。
3. Memory application RED覆盖upstream ports、assignments/hold、provider result unknown、webhook dedupe/conflict、reconciliation、receipt/fault/commit unknown。
4. fake provider + manual mode GREEN；明确不声称真实资金。
5. PG/RLS设计后真PG18 RED覆盖partial unique、deferred sums、双confirm、inbox竞争、forged scope、pool reset与rollback，forward-only GREEN。
6. provider sandbox contract、webhook签名/重放/乱序/超时测试；真实adapter另行启用审查。
7. Demand/Project process manager E2E证明Funding事实不被通知或客户端伪造。

| REQ | DESIGN | TEST | CODE | 状态 |
| --- | --- | --- | --- | --- |
| `REQ-FUND-001` | DES-FUND-001 · §2/3 | `TEST-CONTRACT-FUNDING-001`, `TEST-PROP-FUNDING-001` | planned | design |
| `REQ-FUND-002` | DES-FUND-002 · §4 | `TEST-APP-FUNDING-MANUAL-001` | planned | design |
| `REQ-FUND-003` | DES-FUND-003 · §5/6 | `TEST-CONTRACT-PAYMENT-PROVIDER-001`, `TEST-APP-WEBHOOK-001` | planned | design |
| `REQ-FUND-004` | DES-FUND-004 · §3/7 | `TEST-APP-FUNDING-RETRY-001`, `TEST-PROP-ALLOCATION-001` | planned | design |
| `REQ-FUND-005` | DES-FUND-005 · §8/10 | `TEST-AUTH-FUNDING-001`, `TEST-APP-FUNDING-RECEIPT-001` | planned | design |
| `REQ-FUND-006` | DES-FUND-006 · §9 | `TEST-APP-RECONCILIATION-001` | planned | design |
| `REQ-FUND-007` | DES-FUND-007 · §11/12 | `TEST-EVENT-FUNDING-001`, `TEST-DB-FUNDING-RLS-001` | planned | design |

有效RED后才标red；相同断言、适用回归与真实依赖GREEN后才标green。production provider还必须单独记录外部启用审批。
