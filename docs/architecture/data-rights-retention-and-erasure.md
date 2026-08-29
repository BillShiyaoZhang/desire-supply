# 数据权利、保留、法律保留与清除编排

> 状态：目标平台 Data Rights & Retention Context 权威详细设计；机器契约与可执行 RED 尚未提交，不构成法律意见或任何司法辖区的最终保留期限。
> 适用范围：访问/导出、更正、限制处理、反对、删除请求，跨 Context inventory、法律保留、去标识、provider清除、备份恢复后的删除传播与审计。
> 前置设计：[数据、安全与隐私](/architecture/data-and-security.md)、[Audit/Analytics](/architecture/audit-analytics-observability.md)与[生产恢复](/architecture/production-composition-and-operations.md)。

## 1. 目标与非目标

目标平台不能把“删除 User row”当作完成数据权利请求。一个主体的资料可能存在于 IAM、Profile、Demand/Project party关系、Workspace/File、Funding provider映射、Trust case、Notification、Audit、Analytics、对象存储、备份和外部供应商。系统需要：

1. 验证请求者身份和适用请求类型；
2. 按版本化数据地图冻结查找范围；
3. 由每个 owning Context决定导出、更正、限制、去标识、删除或依法保留；
4. 记录最小、不可篡改的执行证据但不复制被删除正文；
5. 让恢复的旧备份重新应用删除/撤销watermark；
6. 在截止前给主体关闭、可理解且不泄露他人资料的结果。

本 Context 不决定法律依据、税务/支付/劳动/争议保留期，也不允许运营者任意“永远保留”。司法辖区、数据类别、处理目的、合同与legal basis由reviewed `RetentionPolicyBundle` 和法务批准artifact提供；生产启用前必须针对实际地区审查。

删除不是撤销历史交易。已完成Agreement、付款、争议裁决或审计链可能依法保留最小证据；相反，“审计需要”也不能成为保留所有正文、联系人、文件或provider payload的通用借口。

## 2. 事实所有权

Data Rights Context 拥有：

- `DataSubjectRequest` 聚合与身份验证状态；
- `DataInventoryManifest` 和每个 Context 的 `DataRightsTask`；
- versioned `RetentionPolicyBundle`/selector current引用；
- `LegalHold` 的受控引用与目标范围镜像，不拥有案件正文；
- provider/object/backup deletion instruction 与 acknowledgement；
- subject-safe response artifact及下载capability引用；
- 删除watermark、恢复重放状态和本 Context receipt/audit/outbox。

各业务 Context 仍拥有自己的行、对象、版本与更正/去标识状态。Data Rights worker只能调用固定、operation-scoped port，不能获得跨schema owner连接、动态SQL、任意table name或文件bucket列表。

## 3. RetentionPolicyBundle

政策由认证SYSTEM发布，经过法务和数据治理双重批准。selector至少绑定：

```text
jurisdiction / subject_kind / data_category
processing_purpose / relationship_status
contract_or_case_kind / policy_major
```

bundle状态`DRAFT / ACTIVE / SUPERSEDED / RETIRED`，同selector当前恰一个ACTIVE/effective。每条规则关闭字段：

| 字段 | 规则 |
| --- | --- |
| `data_category` | 受控分类，例如CONTACT、PROFILE_PRIVATE、TRANSACTION_EVIDENCE、MESSAGE_BODY、PAYMENT_REFERENCE、TRUST_EVIDENCE、AUDIT_MINIMUM |
| `retention_trigger` | `COLLECTED_AT / RELATIONSHIP_ENDED_AT / PROJECT_CLOSED_AT / CASE_CLOSED_AT / LEGAL_HOLD_RELEASED_AT` |
| `duration_days` | 0..36500拒绝bool；0表示触发后立即可清除，不表示不留审计 |
| `disposition` | `DELETE / CRYPTO_ERASE / PSEUDONYMIZE / AGGREGATE / KEEP_MINIMUM` |
| `minimum_fields` | 仅KEEP_MINIMUM可用的关闭字段code；不能写任意JSON path |
| `legal_basis_code` | 受控code，不保存法律意见正文 |
| `backup_max_lag_days` | 删除在不可变备份自然过期前的最大窗口 |
| `provider_instruction_required` | 是否必须取得外部ack/最终状态 |
| `review_required` | 是否需要独立human reviewer |

canonical release清单包含全部规则、data-map schema version、effective window、review approvals与签名；本地复算JCS/hash和exact manifest。不能由fixture/migration直接激活。

规则改变不重写已完成请求的manifest；未完成请求在下一任务前检测policy current drift，暂停并由独立review决定继续旧规则还是生成新manifest，不能静默换依据。

## 4. DataSubjectRequest

### 4.1 类型与状态

`request_type`关闭为：

- `ACCESS_EXPORT`：导出主体可合法获得的数据；
- `RECTIFICATION`：更正当前事实，历史交易用correction link而非覆盖；
- `ERASURE`：删除/去标识不再需要且无法律保留的数据；
- `RESTRICT_PROCESSING`：暂停新匹配、AI、营销或其他可停止处理；
- `OBJECT_PROCESSING`：对特定purpose提出反对并进入审核；
- `PORTABILITY_EXPORT`：输出结构化、机器可读的主体提供/可移植数据。

状态：

```text
RECEIVED -> IDENTITY_PENDING -> VERIFIED -> INVENTORYING
         -> IN_PROGRESS -> REVIEW_REQUIRED -> COMPLETED
                                      |-> PARTIALLY_COMPLETED
         -> REJECTED
         -> CANCELLED
```

`COMPLETED/PARTIALLY_COMPLETED/REJECTED/CANCELLED`终态。deadline、jurisdiction、request scope和policy bundle在VERIFIED时冻结。deadline到期不是自动完成；超期产生告警和受控升级。

### 4.2 请求与身份验证

authenticated User可从SELF入口创建；无法登录的主体使用独立恢复/人工流程，不能仅凭email匹配自动披露。验证必须与请求风险相称并避免收集多余身份证件：优先当前ACTIVE Session+recent MFA、已验证contact和既有relationship challenges；人工证件存受限evidence store、短期retention、普通表只留opaque ref/hash/status。

请求body不接受`user_id`、任意table/category列表、法律依据或他人ID。代理人请求需要受控代理authority artifact、范围、expiry与revocation；未验证代理不读主体数据。

重复请求不被任意拒绝；系统可以把exact scope且仍开放的请求关联，但每次请求仍有独立receipt/deadline和subject response。滥用限制不能泄露是否存在某主体。

## 5. Inventory manifest

VERIFIED后，协调器通过versioned `DataInventoryRegistry`调用每个已登记 Context 的 `plan_subject_data_vN` 固定port。registry是reviewed artifact，恰列出：Context code、schema/version range、subject key derivation、data categories、task handler version、provider/object stores和owner团队。未知已部署Context或registry/schema不匹配使请求`REVIEW_REQUIRED`，不能忽略。

每个planning port只返回关闭摘要：

```text
context_code / handler_version
subject_key_digest
category_counts[]
earliest/latest fact time buckets
active relationship/transaction/case booleans
legal_hold_candidate_refs[]
provider/object task counts
plan_sha256
```

manifest覆盖所有plan hashes、retention selector/bundle、legal hold snapshot version、registry version、server time和request scope。它不包含正文、row IDs全集、contact、file locator、payment/provider payload或其他主体身份。具体row/object IDs保留在各Context受限task里。

planning和execution之间漂移由task的expected snapshot/version检测。合法新增数据要么包含在同一请求的下一plan revision，要么有明确cutoff并在subject response说明；不能悄悄遗漏。

## 6. LegalHold

LegalHold由独立受控case system发出，字段至少包括`hold_id,case_ref,authority_kind,scope_kind,scope_id_digest,data_category_codes,issued_at,expires_at/review_at,status,approved_by_duty_refs,aggregate_version`。正文、举报者和证据不进入Data Rights普通投影。

- 创建/扩张hold要求独立法务/安全duty和理由code；高范围hold双人批准；
- hold必须精确绑定subject/category/case/transaction，禁止`scope=ALL_DATABASE`；
- 到review deadline必须renew或release，不能无期限默认ACTIVE；
- request planner只看到适用boolean和opaque hold ref；普通支持人员无权查看case；
- hold阻止对应DELETE/CRYPTO_ERASE，但不阻止可安全完成的访问、限制处理或其他category；
- release产生事件并触发被阻塞task重新评估，而不是自动删除。

同一数据被多个hold覆盖时，最后一个有效hold释放后才可执行disposition。hold自身不能由数据主体删除请求删除；其最小审计按独立政策保留。

## 7. Context task协议

`DataRightsTask` identity固定为`(request_id,context_code,plan_revision,task_kind)`，状态：`PLANNED / CLAIMED / BLOCKED_HOLD / BLOCKED_DEPENDENCY / APPLIED / VERIFIED / FAILED_TERMINAL`。worker使用数据库时间、lease/fencing和durable inbox/receipt。

每个Context handler必须：

1. 验证SYSTEM workload、exact request/task/plan/policy/hold snapshot；
2. 锁本Context的subject index/root，再按固定顺序锁具体事实；
3. 分类每项为`CORRECT / DELETE / CRYPTO_ERASE / PSEUDONYMIZE / AGGREGATE / KEEP_MINIMUM / NOT_APPLICABLE / BLOCKED_HOLD`；
4. 使用expected version/CAS执行；任何未计划的新引用触发plan drift；
5. 写最小task receipt、audit和outbox，同事务提交；
6. 在新只读事务复算post-condition hash/count；
7. 返回只含category/count/disposition/reason code的ack。

禁止一个通用runner接收table/column/SQL。每个Context在代码中维护明确handler与字段allowlist，并由数据库约束/RLS阻止越权。

### 7.1 更正

当前可变资料通过正常领域命令更正并增加aggregate version。影响历史决定、Agreement、付款、匹配、审计的旧版本不改写；创建`Correction`/新版本，subject export同时包含旧事实的合法最小投影和纠正链。更正不能伪造过去发生时间、actor或签名。

### 7.2 删除与去标识

- 未被引用的草稿/临时对象可物理删除；
- 被交易引用的Profile/Demand/Agreement/Delivery等不可变版本按政策去标识非必要字段并保留hash/版本/交易关系；
- 联系人和provider locator优先crypto erase：删除wrapped data key与索引，保留不可逆keyed tombstone防重新导入误绑定；
- Message/File正文删除后保留最小tombstone、作者pseudonym、时间bucket和合法交易关联；对象存储必须返回version-specific deletion ack；
- Audit只保留业务必要的pseudonymous actor digest/role/action/target category/result/time，不保留正文或可反查联系人；
- Analytics删除细粒度subject projection并重算或差分修正聚合；小cell仍执行抑制，不能让聚合反推主体。

Pseudonymization不是匿名化；只要平台仍持有映射/密钥，就按个人数据保护。声称anonymous的输出必须通过re-identification风险审查、k阈值/小cell策略和独立批准。

### 7.3 限制处理

RESTRICT/OBJECT先写IAM/Context可即时执行的processing restriction marker，再异步清理缓存/索引/营销/AI队列。marker是授权事实：新Matching capture、AIJob、Notification marketing和公共投影必须在查询时联查，不能等待eventual projection。

安全、必要事务通知、争议处理或依法保留可以继续，但必须按purpose code显式例外；不能用一个`restricted=true`布尔自行推断全部用途。

## 8. 外部provider与对象

每个外部instruction保存`provider_code,environment,subject_reference_digest,operation,provider_idempotency_key_digest,requested_at,status,provider_result_code,acknowledged_at,retain_until`。raw provider subject ID/credential/response保存在受限sealed reference，不进入普通任务、日志或事件。

状态`PENDING / SENT / ACKNOWLEDGED / NOT_FOUND_CONFIRMED / RETRYABLE / RESULT_UNKNOWN / REJECTED`。网络成功不等于删除完成；仅关闭provider ack或随后只读核验可完成。RESULT_UNKNOWN使用同provider key查询/重放，不生成新操作。provider无法删除时进入PARTIALLY_COMPLETED+reason，要求人工/法律处理。

对象删除绑定bucket/environment/object version/digest的sealed ref；禁止prefix递归删和当前latest别名。删除前检查legal hold与其他主体/交易引用；shared object需先证明引用计数和所有权，不能因一人请求删除他人文件。

## 9. 备份、PITR与恢复watermark

不可变备份通常不能就地删除单行，因此政策必须同时规定在线清除与backup max lag。平台维护独立、签名的`ErasureWatermark`：

```text
watermark_id / subject_key_digest
request_id / completed_task_manifest_sha256
category_dispositions[]
effective_at / expires_after_all_backups_at
key_id / signature
```

watermark不含原始User ID/contact或被删正文，存于与业务备份不同的受控故障域。任何PITR/灾备恢复在开放流量前：

1. 恢复schema/migration/key policy；
2. 导入并验证所有覆盖restore point的revocation/erasure watermarks；
3. 以各Context固定replay handler重新应用在线清除、restriction和key revocation；
4. 验证subject/provider/object/task post-condition；
5. 更新审计checkpoint；
6. 全部门禁GREEN后才ready。

不得因恢复旧备份而复活Session、Invitation、Consent、processing restriction或已删除联系人。watermark只能在所有可能包含旧数据的备份、对象版本和provider retention窗口均过期且有审计证据后销毁。

## 10. Subject response与API

首版SELF路由：

```text
POST /v1/me/data-rights-requests
GET  /v1/me/data-rights-requests
GET  /v1/me/data-rights-requests/{request_id}
POST /v1/me/data-rights-requests/{request_id}/cancel
POST /v1/me/data-rights-requests/{request_id}/download-capabilities
```

创建body恰为`{request_type,scope_codes[],preferred_locale}`；scope是受控高层code，不是字段/table。所有写需Idempotency-Key、CSRF，非create需If-Match。ACCESS/PORTABILITY artifact由受控export job生成、客户端公钥或single-recipient服务端加密，下载capability短期single-use；下载本身先写SensitiveAccessEvent。

状态DTO只显示deadline、总体状态、完成category与稳定reason code，不显示legal hold case、其他主体、内部table/provider或行数足以推断案件。PARTIALLY_COMPLETED response区分`LEGALLY_RETAINED / SHARED_TRANSACTION_EVIDENCE / PROVIDER_PENDING / IDENTITY_NOT_VERIFIED / REQUEST_SCOPE_UNSUPPORTED`等关闭reason，并提供人工联系/申诉路径。

未知request、异User、代理失效统一404。identity challenge失败不泄露User存在。下载capability、request verification secret和provider refs禁止进入receipt/audit/outbox/URL/log。

## 11. 幂等、并发与结果未知

外部命令遵循通用keyed receipt；payload覆盖method/path/type/scope/policy selector/If-Match。worker task以固定identity和plan hash幂等。相同subject同时多个请求由协调器按资源排序，不靠全局大锁：restriction marker优先；export可读取明确cutoff；两个erase task对同一version最多一个CAS成功，另一方重读并把已满足记为VERIFIED。

COMMIT_SENT断线丢弃连接，用新连接检查task receipt、目标version/tombstone/key destruction marker与outbox全链。crypto key provider/object delete的外部side effect还要按provider operation identity查询；不能仅看到本地receipt就猜外部完成。

## 12. PostgreSQL与RLS

独立`data_rights` schema至少有requests、identity verification refs、inventory manifests、tasks、legal hold mirrors、provider instructions、watermarks、response artifacts与receipts。所有受限表ENABLE+FORCE RLS。

- SELF只见自己的request安全投影，User ID由当前Session exact绑定；
- reviewer只见exact case assignment与最小manifest，不见Context正文；
- worker只见exact leased task和operation-scoped definer function；
- legal hold manager、request reviewer、export worker、erasure worker和key operator职责分离；
- PUBLIC无schema/table/function权限，在线role无owner/BYPASS；
- subject key使用用途隔离keyed digest，active/retained key policy与watermark保留期一致；
- composite FK绑定request/manifest/task revision，partial unique限制每Context当前task和每artifact active capability。

跨Context handler各自在owning schema内，不给`data_rights` role任意SELECT。需要同库原子restriction marker的首版可用窄SECURITY DEFINER command，固定search_path/静态SQL/session_user+operation+task全链验证；其他批量处理使用durable task saga，不能宣称全平台单事务。

## 13. 事件与隐私

关闭事件：`DataSubjectRequestReceived/Verified/InventoryCompleted/ProcessingRestricted/Completed/PartiallyCompleted/Rejected/Cancelled`、`DataRightsTaskPlanned/Applied/Blocked`、`LegalHoldApplied/Released`、`ErasureWatermarkPublished`。payload只含request/task/manifest ID、subject keyed digest、category/reason/status/version/deadline；不含subject ID、contact、正文、case/provider/object refs或export内容。

通知只说“请求状态已更新”，不在email/SMS列category/hold/reason。普通Audit保存actor/action/request/target category/result/policy bundle；SensitiveAccessEvent记录manifest/export/case访问。telemetry label不使用request/subject/hold/provider ID。

## 14. TDD与追踪

| ID | RED | GREEN门槛 |
| --- | --- | --- |
| TEST-CONTRACT-DATA-RIGHTS-001 | 请求/事件可表达任意table、正文、case/provider秘密 | 关闭OpenAPI/event/policy/manifest schema |
| TEST-DOMAIN-DATA-RIGHTS-001 | 非法状态回退、deadline/hold/plan版本漂移、bool期限 | domain性质与随机状态序列 |
| TEST-APP-DATA-RIGHTS-001 | 异User/代理越权、漏Context、hold全局阻断、partial伪complete | strict Memory application + exact registry/ports |
| TEST-DB-DATA-RIGHTS-001 | 伪GUC、跨subject/task、双erase、RLS绕过 | 真实PostgreSQL 18/RLS/并发/fault matrix |
| TEST-PROVIDER-ERASURE-001 | 网络成功当删除、unknown换key、共享对象误删 | provider/object sandbox fault E2E |
| TEST-RECOVERY-ERASURE-001 | PITR复活已删除/限制/撤销事实 | 隔离restore + signed watermark replay |
| TEST-EXPORT-DATA-RIGHTS-001 | 导出含他人/secret、capability重复、artifact过期仍读 | encrypted artifact/single-use capability/SensitiveAccess audit |
| TEST-SEC-LEGAL-HOLD-001 | 无限/全库hold、同一人批准执行、case泄漏 | duty separation/scope/review deadline/non-disclosure |

实施顺序：司法辖区policy/data map设计审查 → machine contract GREEN → domain/application semantic RED → Memory GREEN → 每Context inventory/task port RED → 真PG/RLS GREEN → provider/object fault RED→GREEN → 隔离PITR/watermark恢复演练。未完成真实法务审批、provider和恢复证据前，生产Data Rights入口保持关闭并提供已审核人工流程。

## 15. 当前实施边界

当前MVP只有人工删除清单，目标平台已有若干不可变事实、RLS和审计设计，但没有本页的Context、policy bundle、API、task runner、provider erasure或watermark实现。各业务Context后续落库时必须同时登记DataInventoryRegistry/retention category；未登记的Context不能被production feature gate启用。
