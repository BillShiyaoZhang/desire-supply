# Workspace、消息、输入请求与 FileVersion

> 状态：Workspace & Files Context 的权威详细设计；机器契约和可执行 RED 尚未提交，真实对象存储/扫描provider默认关闭。
> 适用范围：Project workspace、讨论消息、InputRequest、FileObject/FileVersion、上传/下载能力、恶意文件扫描、字段授权与保留。
> 前置依赖：[Project/Agreement/Delivery](/architecture/project-agreement-delivery.md)、[Notification](/architecture/notification-and-communications.md)、[Trust](/architecture/trust-safety-dispute-review.md)与[ADR-0001](/decisions/0001-platform-scope-and-delivery.md)。

## 1. 边界与业务含义

每个Project恰一个Workspace，由`ProjectCreated` source event幂等创建。Workspace Context拥有 `Workspace`、`Thread`、`Message/MessageVersion`、`InputRequest`、`FileObject/FileVersion`、`UploadSession`、`ScanAttestation`、`FileAccessGrant`和provider inbox。

它不拥有Agreement、Milestone、Delivery、Acceptance、Project party或Trust case。消息中的“同意/完成/接受/付款”不改变业务状态；只有目标Context关闭命令有效。Delivery只引用CLEAN/AVAILABLE FileVersion，不读取消息推断交付。

首版没有任意公共分享、搜索引擎索引、外部guest、同步协作文档、音视频会议或端到端加密承诺。通信是项目内异步消息；WebSocket/push只优化读取，不成为事实源。

## 2. Workspace、Thread 与 Message

Workspace状态 `ACTIVE / READ_ONLY / ARCHIVED`，绑定exact Project/organization/creator parties和aggregate version。Project hold/cancel/complete通过source event更新最小access projection：hold可只读，cancel/complete进入READ_ONLY，retention后ARCHIVED；通知失败不影响。

Thread状态 `OPEN / LOCKED / ARCHIVED`，kind关闭为 `GENERAL / MILESTONE / INPUT_REQUEST / DELIVERY_DISCUSSION / AGREEMENT_DISCUSSION`，并按kind绑定exact resource ID。不存在任意cross-project thread。

Message使用append-only版本：

- `Message`根保存thread/author party/status `VISIBLE / EDITED / WITHDRAWN / MODERATED`、current version、aggregate version；
- `MessageVersion`保存安全rich-text AST/plain text、attachment FileVersion IDs、created_at/content hash；不可变；
- author只可在版本化edit window内创建新version，旧version保留；Withdraw隐藏普通投影但不删除审计/已引用证据；
- moderation由exact Trust assignment执行，保存closed reason/redaction version；不能让ORG_ADMIN任意删对方历史；
- reply引用同thread早期Message；无环/跨thread；mentions只引用effective ProjectParty，通知解析不包含contact；
- 内容schema只允许paragraph/list/code/quote/link-to-platform-resource等安全AST；禁止raw HTML/script/style/data URL、远程image、任意scheme、自动embed和unknown nodes。

消息正文有长度/Unicode/control/PII/content-policy检查，但平台不能保证用户不输入敏感业务内容；因此正文永不进入outbox/log/metrics/notification preview/analytics。Trust evidence引用exact MessageVersion/hash。

## 3. InputRequest

InputRequest用于一方请求Agreement范围内的项目输入，不是ChangeOrder或Acceptance：

状态 `OPEN / PARTIALLY_FULFILLED / FULFILLED / DECLINED / CANCELLED / EXPIRED`，保存requester/recipient parties、AgreementVersion/Milestone、closed requested item definitions、deadline与aggregate version。

- Create要求Project ACTIVE/allowed party、item属于Agreement scope且无hold；
- response逐item引用Message/FileVersion/controlled value并由recipient提交；不自动声明内容正确；
- requester确认全部item使FULFILLED；如请求扩大scope/新金额则拒绝并引导ChangeOrder；
- deadline等号过期；Cancel/Decline安全降权不受hold阻止；
- Milestone start可要求某些InputRequest FULFILLED，但Project Context只消费exact closed event/port，不从消息计数。

## 4. FileObject 与不可变 FileVersion

FileObject是Project内逻辑文件根；FileVersion append-only：

| 字段 | 规则 |
| --- | --- |
| identity | object/version/project/owner party，version_no单调 |
| metadata | safe label、media type allowlist、size、client content hash声明 |
| storage | opaque provider/object version sealed reference、KMS key ID；普通DTO不可见 |
| integrity | server-computed SHA-256、upload checksum、encryption/scan policy version |
| status | `UPLOADING / STORED / SCANNING / AVAILABLE / QUARANTINED / INFECTED / REJECTED / DELETED` |
| attestation | scanner/provider/version/signature/result/timestamps/content hash |
| retention | source/business/legal hold class、expires/deleted times |

FileVersion内容不可覆盖；“替换文件”创建新version。Delivery/Agreement/Trust引用exact version/hash后不能物理删除，除非保留政策允许且生成redaction/tombstone事实。

media type同时检查declared、sniffed和policy；不依据扩展名。压缩包、宏、可执行、超大/嵌套bomb按policy拒绝或隔离。图片/PDF主动内容、元数据、外链和脚本需清洗规则；首版只允许小型published allowlist。

## 5. 上传协议

上传不是把signed URL存在业务DTO：

1. `CreateUploadSession`验证ACTIVE ProjectParty、workspace/resource scope、size/media/quotas/hold，预分配FileObject/Version和short TTL session；
2. 返回single-file/single-version/single-method/single-size/hash绑定的provider upload capability，标`sensitive/no-store/redact`，不写receipt body；
3. client直传对象存储；provider callback或CompleteUpload命令验证session、provider object version、actual size/hash/media与deadline；
4. STORED后入scan queue，capability失效；不允许未扫描下载/引用；
5. scanner在事务外取受限对象，verified result durable inbox；CLEAN→AVAILABLE，malicious→INFECTED/QUARANTINED，unavailable保持SCANNING并重试；
6. callback/result unknown不猜CLEAN；same session不同object/hash为security incident；
7. abandoned UPLOADING定时EXPIRED/删除provider temp对象，业务行保留最小tombstone。

upload capability、object key、provider response、scanner report不进入日志/audit/outbox/exception。KMS/storage/scanner key按environment/purpose/version隔离。

## 6. 下载与披露

`CreateFileDownloadCapability`每次重新验证：ACTIVE/effective ProjectParty或exact EvidenceAccessGrant、FileVersion AVAILABLE、resource/field关系、retention/hold、purpose与download policy。返回single-recipient/file/version/range、短TTL、no-store capability；普通User不能用File ID枚举。

capability不可转授权、不进入Notification链接/receipt。下载请求记录SensitiveAccessEvent；审计不可用则restricted file fail closed。HTTP Range/content disposition/media header采用allowlist，文件label进行header injection防护。

Trust/Finance/Operations只因case/assignment/purpose获得exact FileVersion，不因平台角色看整个Workspace。

## 7. Provider、扫描与结果未知

对象存储/scanner calls均在DB事务外、由leased/fenced job执行。provider idempotency/object version必须绑定FileVersion；timeout/ack loss进入OUTCOME_UNKNOWN并先query provider，不重复上传/扫描猜结果。

callback endpoint验证provider/path/signature/timestamp/environment/event ID/body limits与closed schema，durable inbox去重；相同event不同digest隔离。未知object/hash/tenant不关联最近File。

scanner只收到必要object，不收到Project消息/participant contact。若provider会训练/保留内容则不可用。扫描失败不将文件标REJECTED除非有明确terminal policy result。

## 8. API、授权、幂等与并发

```text
GET  /v1/projects/{project_id}/workspace
GET  /v1/workspaces/{workspace_id}/threads
POST /v1/workspaces/{workspace_id}/threads
POST /v1/threads/{thread_id}/messages
POST /v1/messages/{message_id}/versions
POST /v1/messages/{message_id}/withdraw
POST /v1/projects/{project_id}/input-requests
POST /v1/input-requests/{id}/responses
POST /v1/workspaces/{workspace_id}/uploads
POST /v1/uploads/{upload_session_id}/complete
POST /v1/files/{file_version_id}/download-capabilities
POST /v1/internal/files/{provider}/callbacks
```

actor来自BFF；body不含party/role/status/project owner/hash/server time。外部写Idempotency-Key+aggregate If-Match；sensitive capability本身不持久在receipt。same key replay可重新授权生成新capability吗：普通completed receipt只保存reconstruction metadata，每次重放仍验证当前authority/file并用retained key重建或生成等价短TTL能力；已过期/撤销权限不重放旧secret。

锁序：authority/ProjectParty projection→Workspace→Thread→Message→InputRequest→FileObject/Version→Upload/Scan job/inbox→access grant→receipt。provider calls无事务。每写点checkpoint、commit unknown新连接全链裁决。

wire错误：400 invalid；401；403 access/hold/content blocked；404；409 state/idempotency/file/message/resource changed；412；413 payload too large；415 media unsupported；422 `WORKSPACE_CONTENT_INVALID/FILE_NOT_READY/SCAN_REQUIRED/INPUT_OUT_OF_SCOPE`; 429 quota；503 storage/scanner/key/service unavailable。

## 9. 事件、隐私与Notification

事件只含workspace/thread/message/input/file opaque IDs、resource IDs、status、version/hash、safe kind/deadline；不含message/file name/body、object reference、scan report、participant、capability。Notification consumer按exact recipient重新读取安全preview；默认模板不含message正文或file label。

Audit记录actor/party/action/target/result/hash/controlled reason，不保存内容。analytics只计count/latency/status bucket。

## 10. PostgreSQL/RLS 与对象一致性

`workspace` schema包含workspaces/party projection、threads/messages/versions、input requests/responses、file objects/versions/upload sessions/scan jobs/attestations/provider inbox/receipts。sealed provider refs独立更窄表。

约束：一Project一Workspace；resource/project复合FK；message current version/thread identity；reply order；File version/hash/status shape；Upload single target/deadline；Scan attestation exact content hash；Delivery引用由Project schema复合FK/authorized port保证；provider event identity唯一。

全部FORCE RLS。party只见effective exact Project；worker只见leased file job；provider callback role只insert verified inbox；Trust只见access grant；PUBLIC无权限，online非owner/无BYPASS。forged GUC、cross-project IDs、expired party/grant/capability均拒绝。

DB/object store恢复需对账：AVAILABLE行必须有exact provider object/version/hash与scan attestation；orphan objects/rows进入reconciliation，不自动公开。对象版本、KMS key和DB PITR恢复演练同步。

## 11. TDD与追踪

1. 发布Workspace/File OpenAPI、event、message AST/input/file/provider schemas；XSS/header/secret contract RED→GREEN。
2. Domain RED覆盖状态/version/hash/expiry/reply/InputRequest/scan shape。
3. Memory application RED覆盖party/hold、message version、scope、upload capability、hash/media/scan、download access、provider unknown、receipt/fault。
4. fake object/scanner GREEN。
5. 真PG18 RLS/constraint/concurrency + sandbox object/scanner/callback/recovery门禁。

| REQ | DESIGN | TEST | CODE | 状态 |
| --- | --- | --- | --- | --- |
| `REQ-WORK-001` | DES-WORK-001 · §2/3 | `TEST-APP-WORKSPACE-001` | planned | design |
| `REQ-FILE-001` | DES-FILE-001 · §4/5 | `TEST-CONTRACT-FILE-001`, `TEST-APP-UPLOAD-001` | planned | design |
| `REQ-FILE-002` | DES-FILE-002 · §6/7 | `TEST-AUTH-FILE-001`, `TEST-CONTRACT-SCANNER-001` | planned | design |
| `REQ-WORK-002` | DES-WORK-002 · §8/9 | `TEST-SEC-WORKSPACE-001`, `TEST-APP-WORK-RECEIPT-001` | planned | design |
| `REQ-WORK-003` | DES-WORK-003 · §10 | `TEST-DB-WORKSPACE-RLS-001`, `TEST-RECOVERY-FILE-001` | planned | design |

有效RED后才标red；相同断言/真实依赖GREEN后标green，真实provider另需启用审批。
