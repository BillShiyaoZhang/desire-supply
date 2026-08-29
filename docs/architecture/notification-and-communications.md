# Notification、模板、偏好与投递回执

> 状态：Notification Context 的权威详细设计；机器契约和可执行 RED 尚未提交，本文不表示真实邮件/短信供应商已启用。
> 适用范围：领域事件到NotificationIntent、模板发布、接收者解析、偏好、渠道投递、provider回执/退信、频率与安全升级。
> 前置依赖：[Outbox delivery](/architecture/outbox-delivery.md)、[IAM隐私边界](/architecture/identity-tenancy-consent.md)、[Trust](/architecture/trust-safety-dispute-review.md)与[ADR-0001](/decisions/0001-platform-scope-and-delivery.md)。

## 1. 不变量与事实所有权

Notification Context拥有 `TemplateBundle/TemplateVersion`、`NotificationIntent`、`RecipientResolution`、`NotificationPreference`、`DeliveryAttempt`、provider callback inbox与suppression投影。领域聚合拥有业务事实；通知只说明某个安全消息是否计划、可见、尝试或被provider接受/退回。

因此：

- Invitation/Agreement/Deadline/Funding/Dispute等状态先COMMIT，通知失败不能回滚或伪造这些事实；
- `InvitationSent`表示门户中可访问，不表示email成功；
- provider `delivered`不证明人已阅读、同意或按时响应；
- 业务期限使用数据库/协议事实，不依赖通知成功，必要提醒失败进入人工队列；
- 通用事件不含contact或token。Notification通过exact recipient ID和purpose调用IAM受控port，在投递时解析当前verified contact；
- email/SMS正文不承载会话、访问邀请、重置或文件能力。需要链接时只放固定同源portal route，用户登录后再取得权限；任何一次性token必须由拥有Context的专用短期delivery协议产生且不进入通用outbox/receipt。

首版启用 `IN_APP` 与fake `EMAIL`；SMS/push/营销默认关闭。真实provider需独立sandbox、数据处理与退订/投诉配置。

## 2. TemplateBundle 发布

模板不是可在线任意编辑的自由字符串。`TemplateBundle`按 `event_type + notification_purpose + locale + channel` selector发布，状态 `DRAFT / ACTIVE / SUPERSEDED / RETIRED`，同selector同时恰一个ACTIVE/effective版本。

发布artifact包括：

- subject/title/body的安全模板AST，不执行代码、表达式、include、网络或动态SQL；
- 允许变量及每变量type/classification/escape mode；
- receiver类型、channel、mandatory/optional分类、fallback policy、rate-limit class；
-固定same-origin route与无token CTA code；
- locale/fallback、semantic version、canonical bytes/hash、signing key/trust/review approval；
- provider render size、plain/html pair、accessibility与secret sentinel golden vectors。

变量只允许published allowlist里的opaque ID、安全public label、controlled status/code/deadline和短安全摘要。禁止contact、private floor、预算细目、Agreement/Dispute/evidence正文、provider object、Session/CSRF、raw idempotency key。HTML按context escape，URL只能从固定route + opaque path ID构造；不允许模板提供scheme/host/query/fragment。

`PublishNotificationTemplate`由认证SYSTEM workload执行，事务外验证签名/manifest/review，事务内锁selector/current。fixture/migration不能直接激活未review模板。render前后都跑closed schema、size、Unicode/control、header injection与secret sentinel。

## 3. Event→Intent

Notification consumer以durable inbox `(consumer_name,event_id)`领取published domain event。registry把exact `(event_type,schema_version)`映射到关闭NotificationPolicy：

```text
notification_purpose
recipient resolver operation
template selector facts
mandatory_or_optional
channels/fallback
dedupe window and rate class
safe variable extractor
```

它不根据payload未知字段或事件名字符串拼接template。未知schema/policy进入隔离告警，不发送“通用消息”。

一个event可生成0..N个 `NotificationIntent`，每个绑定source event、purpose、recipient subject、template selector/version、safe variables hash和可用窗口。`(source_event_id,purpose,recipient_subject_id)`唯一；重复消费不重复Intent。Intent状态：

`PENDING_RESOLUTION / READY / SUPPRESSED / DELIVERY_PENDING / DELIVERED / PARTIALLY_DELIVERED / FAILED / EXPIRED / CANCELLED`。

`DELIVERED`只表示至少一个required channel得到provider/IN_APP确认；业务聚合不消费它作为状态守卫。若业务流程需要“提醒已完成”事实，应消费受控 `RequiredNotificationAttempted`，且原协议明确允许attempted而非read/delivered。

## 4. 接收者与contact解析

事件只携带opaque recipient User/Organization/party关系ID。Notification在每次准备投递时调用IAM `resolve_notification_recipient_v1`，输入recipient subject、purpose、channel、source resource/organization；输出最小：

```text
user_id, locale, timezone,
verified_contact_point_id,
sealed locator delivery handle + handle key/version/expiry,
eligibility/preference marker version
```

raw email/phone只在provider adapter的最窄内存边界解封；不进入Notification普通表、DTO、audit、outbox、log、trace或exception。resolver要求ACTIVE/允许接收的主体关系；安全/法律mandatory消息对SUSPENDED User可有单独policy，但不能自动使用未verified locator。

handle是single-intent/single-channel/single-provider、短TTL且绑定contact version。发送事务外使用前复核；contact撤销/替换或handle过期即重新解析。不同User相同locator不能合并Intent或泄露关系。

## 5. Preference、mandatory 与 suppression

Preference按 `(user_id,purpose,channel)` 保存 `ENABLED / DISABLED` 与aggregate version。分类：

- `SECURITY_REQUIRED`：账号/权限安全通知，不能全局退订，但可选择获准渠道；
- `TRANSACTIONAL_REQUIRED`：邀请、协议、资金/交付关键通知；参与关系有效期间不可完全关闭，至少IN_APP；
- `TRANSACTIONAL_OPTIONAL`：状态摘要/提醒，可按purpose关闭外部渠道；
- `PRODUCT_UPDATE / MARKETING`：默认关闭，需独立明确opt-in/consent，首版不启用。

provider hard bounce/complaint产生 `ContactSuppression`，只影响exact keyed contact/channel/reason/expiry；不关闭IN_APP，不泄露locator。安全required无法email时进入IN_APP+人工恢复，而不是反复轰炸。

Preference更新自身使用Idempotency-Key/If-Match，不能撤销法律上必要的门户记录。unsubscribe capability若未来用于email必须single-purpose、signed/expiring/no-store，且只能关闭对应optional purpose/channel；不能作为登录或枚举User的token。

## 6. DeliveryAttempt 与provider协议

每个 `(intent_id,channel,attempt_no)` 是不可变 `DeliveryAttempt`，状态：

`CREATED / RENDERED / SUBMITTING / PROVIDER_ACCEPTED / DELIVERED / BOUNCED / COMPLAINED / FAILED / CANCELLED / OUTCOME_UNKNOWN`。

流程：

1. short DB transaction claim READY intent/创建attempt与lease/fencing；
2. 事务外resolve current contact、render exact template/safe variables、构造provider request；
3. provider idempotency/message key由attempt ID和versioned key派生；
4. provider调用不持DB锁；明确response或unknown进入final transaction；
5. callback由签名/时间窗/merchant/event ID验证的durable inbox应用；相同event不同digest隔离；
6. timeout/ack loss为OUTCOME_UNKNOWN，先按provider query/idempotency查询，不盲目新send；
7. definite transient failure按bounded backoff新attempt，永久bounce/complaint suppression；
8. IN_APP作为本地channel，在同事务创建不可变InboxItem即可provider-accepted，但read_at仍不表示业务确认。

attempt普通表只保存provider/message keyed digest与controlled result code；raw provider ID/sealed contact reference在更窄表。provider response正文不持久。

## 7. 频率、聚合与滥用

频率限制按recipient pseudonymous key + purpose/channel/rate class，数据库/atomic counter使用server time。安全/交易消息不能被营销限额挤占；攻击者不能通过重复业务命令造成重复通知，因为Intent由source event唯一。

允许bundle/digest时，必须由published policy定义窗口、事件集合、排序和模板，并保存included event IDs；不能把安全/争议/资金消息与普通摘要合并。deadline临近的required消息不等待digest。

异常发送量、bounce/complaint、resolver miss、outcome unknown和模板render失败触发告警。metric label不含recipient/contact/resource ID或template变量。

## 8. API、读取与隐私

```text
GET  /v1/me/notifications
POST /v1/me/notifications/{notification_id}/read
GET  /v1/me/notification-preferences
PUT  /v1/me/notification-preferences/{purpose}/{channel}
POST /v1/internal/notification-provider/{provider}/callbacks
POST /v1/operations/notification-templates/publish
GET  /v1/operations/notification-delivery-failures
```

普通User只见自己的IN_APP item安全title/body/route/status/timestamps，不见provider/contact/delivery internals。运营失败列表只见pseudonymous fingerprint、purpose/channel/result/attempt bucket与time，不见正文/locator。

Preference写有keyed receipt；read/mark-read是Notification事实，不更新业务聚合。provider callback不用客户端idempotency key，使用verified event identity。

wire code使用平台关闭基础集，Notification特有422只为 `NOTIFICATION_PREFERENCE_INVALID/TEMPLATE_VALIDATION_FAILED`; provider/contact/key不可用503。对外不区分“无contact”“被suppressed”“User不存在”，普通业务只得到安全的notification state。

递归禁止值：contact locator、provider object/event raw ID、template source未渲染变量、业务私密正文/金额/evidence、cookie/CSRF/Session、idempotency key、unsubscribe/delivery capability。日志不记录rendered subject/body。

## 9. PostgreSQL/RLS、可靠性与保留

独立 `notification` schema至少包含template bundles/versions/current selectors、intents、safe variable blobs/hash、preferences、delivery attempts、provider callback inbox、suppression、IN_APP items、receipts。联系信息不在此schema。

约束：active template selector唯一；source event/purpose/recipient intent唯一；safe variable schema/hash；attempt_no唯一；状态/lease/time shape；provider callback identity/digest唯一；suppression contact digest/channel唯一；preference purpose/channel关闭枚举。

全部ENABLE+FORCE RLS。User只见自己的IN_APP/preference；consumer只见exact source event；delivery worker只见leased intent/attempt和sealed handle调用入口；provider callback role只insert verified inbox；template publisher只见exact selector。PUBLIC无权限，在线角色非owner/无BYPASS。

Intent/attempt按业务/安全保留策略去标识；rendered external body默认不持久，只保存template/variables hash。IN_APP正文若含业务摘要按source retention同步删除/重渲染不可行时redact；审计保留最小发送事实。

Outbox worker只保证事件至少一次到Notification consumer；Notification自己的provider调用同样at-least-once + provider idempotency，不能宣传exactly-once delivery。备份恢复验证inbox/intent/attempt/suppression一致。

## 10. TDD与追踪

1. 发布notification OpenAPI、event/template/intent/provider callback schemas；header injection/secret contract RED→GREEN。
2. Domain RED覆盖template selector、preference分类、Intent/Attempt状态、dedupe/rate/backoff/expiry。
3. Memory application RED覆盖event→recipient→render→send、contact rotation、preference/suppression、provider ack unknown/callback、fault/commit unknown。
4. fake EMAIL+IN_APP GREEN，不声称真实provider。
5. 真PG18 RED覆盖RLS、source unique、claim fencing、callback race、pool reset、privacy后forward GREEN。
6. provider sandbox/real adapter另做signature/idempotency/bounce/complaint/E2E和启用审查。

| REQ | DESIGN | TEST | CODE | 状态 |
| --- | --- | --- | --- | --- |
| `REQ-NOTIFY-001` | DES-NOTIFY-001 · §2/3 | `TEST-CONTRACT-NOTIFY-001`, `TEST-APP-NOTIFY-INTENT-001` | planned | design |
| `REQ-NOTIFY-002` | DES-NOTIFY-002 · §4/5 | `TEST-AUTH-NOTIFY-001`, `TEST-APP-NOTIFY-PREF-001` | planned | design |
| `REQ-NOTIFY-003` | DES-NOTIFY-003 · §6 | `TEST-APP-NOTIFY-DELIVERY-001`, `TEST-CONTRACT-NOTIFY-PROVIDER-001` | planned | design |
| `REQ-NOTIFY-004` | DES-NOTIFY-004 · §7/8 | `TEST-SEC-NOTIFY-001`, `TEST-APP-NOTIFY-RATE-001` | planned | design |
| `REQ-NOTIFY-005` | DES-NOTIFY-005 · §9 | `TEST-DB-NOTIFY-RLS-001`, `TEST-RECOVERY-NOTIFY-001` | planned | design |

有效RED后才标red；相同断言/回归/真实依赖GREEN后标green。真实provider与营销类别另需启用审批。
