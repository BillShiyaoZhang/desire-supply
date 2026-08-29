# Creator Profile、版本与字段披露设计

> 状态：首个非 IAM 垂直切片已完成机器契约与 Memory domain/application GREEN，并取得独立PostgreSQL 18 fixed-UoW/RLS有效RED；数据库GREEN、HTTP和production composition仍是后续独立TDD切片，本文不把Memory或RED证据表述为生产就绪。
> 适用范围：个人创作者档案、不可变版本、能力证据引用、容量、字段可见性，以及 Matching 获取冻结输入的边界。
> 前置依赖：[身份、租户、政策同意与会话](/architecture/identity-tenancy-consent.md)、[目标平台领域模型](/architecture/platform-domain-model.md)与 [ADR-0002](/decisions/0002-tenant-root-and-role-scopes.md)。

## 1. 用户结果与非目标

首个 Profile 切片让已受邀、当前仍有 `CREATOR` 账户级授权的 User 完成四件事：

1. 创建且只创建一个由本人拥有的 `CreatorProfile`；
2. 保存不会进入匹配的私有草稿；
3. 明确确认并发布一个不可变 `ProfileVersion`；
4. 暂停、恢复或归档当前档案，并让新的 MatchRun 立即停止或恢复使用它。

本切片不实现公开人才目录、团队档案、简历导入后自动发布、任意文件上传、社交关注、推荐排序、业务 Invitation、Project、支付或声誉。能力证据只保存受控引用与验证事实；对象存储、恶意文件扫描和外部验证供应商要先有独立设计与契约，不能以 URL 字符串临时替代。

旧 MVP creator JSON 是匿名研究资料，不是平台主体、角色或已发布档案。导入只能生成待核对草稿及 `legacy_source_ref`，不能自动关联 User、激活 Profile、创建证据或恢复历史 consent。

## 2. Context 与权威来源

Creator Profile Context 拥有：

- `CreatorProfile` 根及其生命周期；
- append-only `ProfileVersion` 内容与版本链；
- `CapabilityEvidence` 的受控元数据和验证状态；
- owner/self、内部 matcher 与后续 recipient view 的关闭投影；
- 本 Context 的 command receipt、审计和 outbox 写入。

它不拥有 User、Session、`CREATOR` grant、政策接受或 ConsentGrant。每个写事务通过 IAM 的窄、固定查询验证当前 User、Session、账户级 grant和对应政策要求；Profile 表不能被下游当作恢复 IAM 权限的依据。User 或 grant 暂停后，即使 Profile 仍标记 ACTIVE，也不得被新 MatchRun 读取。

Matching 不读取“最新档案”并在运行中漂移。创建 MatchRun 时，它通过内部、operation-scoped port取得一组当时可用的发布版本，并永久保存 `profile_id/profile_version_id/content_sha256/taxonomy_bundle_id`。历史运行、Invitation 与解释始终引用该冻结版本。

## 3. 聚合与状态

### 3.1 CreatorProfile

一个 User 最多一个个人 Profile。根至少保存：

| 字段 | 规则 |
| --- | --- |
| `id` | 受控随机 Opaque ID；创建命令在receipt canonicalization与事务前预分配 |
| `owner_user_id` | 不可变，唯一；不能改绑或由联系人推导 |
| `status` | `DRAFT | ACTIVE | PAUSED | ARCHIVED` |
| `aggregate_version` | 从1开始，每个成功外部命令恰增加1 |
| `current_draft_version_id` | 可空；最多一个尚可发布的 DRAFT |
| `current_published_version_id` | 可空；ACTIVE/PAUSED 时必须指向 PUBLISHED 版本 |
| `paused_at/reason_code` | 仅 PAUSED 非空；reason为稳定枚举，不保存自由隐私正文 |
| `archived_at/reason_code` | 仅 ARCHIVED 非空；ARCHIVED 终态 |
| `created_at/updated_at` | 数据库 UTC aware time；`updated_at`只随根版本变化 |

状态转换：

| 转换 | 命令 | 守卫 | 事件 |
| --- | --- | --- | --- |
| 无 → DRAFT | `CreateCreatorProfile` | actor 是 ACTIVE User，拥有未撤销 `CREATOR` grant，当前政策要求已满足；owner唯一 | `CreatorProfileCreated` |
| DRAFT/ACTIVE → 同状态 | `SaveCreatorProfileDraft` | exact profile owner；输入/可见性/taxonomy/evidence引用关闭且合法 | 不发集成事件；只写审计 |
| DRAFT → ACTIVE | `PublishCreatorProfileVersion` | current draft、IAM authority、政策、证据与 SafetyHold 均有效 | `CreatorProfilePublished` |
| ACTIVE → ACTIVE | `PublishCreatorProfileVersion` | 新版本合法；旧发布版本原子 SUPERSEDED | `CreatorProfilePublished` |
| ACTIVE → PAUSED | `PauseCreatorProfile` | owner或受控安全降权入口；不受 SafetyHold 阻止 | `CreatorProfilePaused` |
| PAUSED → ACTIVE | `ResumeCreatorProfile` | current published仍有效；重新验证 IAM/policy与 SafetyHold | `CreatorProfileResumed` |
| DRAFT/ACTIVE/PAUSED → ARCHIVED | `ArchiveCreatorProfile` | owner确认；安全降权动作不被 hold 阻止 | `CreatorProfileArchived` |

`ARCHIVED` 不恢复、不接受新草稿，也不删除已影响匹配或交易的旧版本。重新成为创作者需要新的产品与保留策略设计，不能复活旧根。

当前冻结的 Profile v1 数据库转换约束不允许 `PAUSED → PAUSED`，因此暂停期间的 owner 投影只授予 `RESUME` 与 `ARCHIVE`，界面明确要求先恢复再编辑；Memory 与 PostgreSQL editor 均以 `409 INVALID_STATE_TRANSITION` 拒绝暂停中的保存。若未来需要“暂停中编辑但不恢复匹配资格”，必须通过新的 forward-only Profile schema v4 迁移、契约和回归测试实现，不能修改已冻结的 `0001` 或 manifest。

### 3.2 ProfileVersion

每次保存草稿都插入一个内容不可变的新版本；不对既有 JSON 做 PATCH。版本生命周期为：

```text
DRAFT -> PUBLISHED -> SUPERSEDED
   |          |
   +-> DISCARDED
              +-> RETIRED   # Profile pause/archive只改变可用性，不删除内容
```

- `(profile_id, version_no)` 唯一且单调；失败事务不得消耗可观察 version_no；
- 一个 Profile 同时最多一个 DRAFT、一个 PUBLISHED；新草稿原子将旧 DRAFT 标为 DISCARDED；
- publish 只改变版本生命周期元数据，内容、schema、taxonomy、来源和 hash 自插入起不可变；
- 新发布版本原子将旧 PUBLISHED 标为 SUPERSEDED；PAUSED 时版本仍可保持 PUBLISHED，但所有 eligibility query必须联查根状态；ARCHIVED 时 current published标为 RETIRED；
- `based_on_profile_version_id` 必须属于同一 Profile 且指向更小 version_no；客户端不能构造分叉后覆盖较新 draft；
- 保存 `profile_schema_version`、`taxonomy_bundle_id`、`canonicalization_version=profile-version-json-v1`、`content_sha256`、`created_by_user_id`、`created_at`；发布再保存 `confirmed_by_user_id/confirmed_at` 与当时认证证据引用。

## 4. 关闭内容契约

`ProfileVersion` 使用关闭对象；未知字段、未知 enum、重复项、未标准化字符串和不受控引用一律拒绝。首版语义内容如下：

| 分组 | 核心事实 | 强制披露上限 |
| --- | --- | --- |
| interests | problem type/domain/task受控 code与0–4意愿强度 | `MATCH_ONLY`；未来可逐项 `PUBLIC` |
| skills | taxonomy skill code、0–4熟练度、0个或多个 CapabilityEvidence ID | skill摘要可 `MATCH_ONLY/PUBLIC`；证据locator永远PRIVATE |
| availability | available_from、weekly_hours、duration_weeks、IANA timezone | 精确容量最多 `MATCH_ONLY` |
| collaboration | BCP-47 languages、work mode、feedback cadence、team preference | `MATCH_ONLY/PUBLIC` |
| compensation | minimum project amount、ISO-4217 currency、direct cost | 强制 `PRIVATE`，不能由客户端放宽 |
| boundaries | prohibited domains/tasks、allowed data sensitivity | 强制 `PRIVATE` |
| location |受控region code | `MATCH_ONLY/PUBLIC`，不保存精确住址 |
| conflicts | exact内部 Organization ID或待核对 legacy ref | 强制 `PRIVATE` |
| ai | allowed、requires_ai、human-review code、prohibited cases | 最多 `MATCH_ONLY` |

每个可披露语义项都带 `visibility` 与 `source_kind`。数组项各自带元数据，不能用一个父级 visibility把新加入的私密项意外公开。首版 `source_kind` 关闭为 `SELF_ASSERTED | VERIFIED_EVIDENCE | LEGACY_UNVERIFIED`；`VERIFIED_EVIDENCE` 必须引用同一 owner、状态有效的 CapabilityEvidence，`LEGACY_UNVERIFIED` 永远不能单独满足高信任技能守卫。

服务端在保存草稿时写 `asserted_at`，发布时写 `confirmed_at`；客户端不能自报这些时间。字段 expiry由版本化 profile policy和证据到期时间派生。任一用于匹配的字段在 `expires_at <= server_now` 时均失效；不得等待后台 job 才停止使用。

静态不变量至少包括：

- code数组已按规范顺序去重；同一 skill code最多一项；
- strength/proficiency只允许整数0–4且拒绝bool；
- `weekly_hours` 1–80、`duration_weeks` 1–104，日期与timezone可解析；
- `requires_ai=true` 要求 `allowed=true`；
- interest/task不能同时出现在本版本相应 prohibited集合；
- compensation使用整数最小货币单位，金额非负、币种与版本化jurisdiction policy相容；
- `PRIVATE` 分组不能被 payload visibility覆盖；
-所有 evidence/profile/organization引用必须属于正确 owner或受控映射，不能只验证ID格式；
-发布至少有一个interest、一个skill、有效availability和完整边界；草稿允许不完整但仍必须结构合法。

`content_sha256` 对 JCS UTF-8 canonical `profile-version-json-v1` 计算。签名面包含 schema/canonicalization version、Profile ID、version_no、taxonomy bundle、全部值、逐项visibility/source/evidence引用；不含 server生成的IDempotency digest、Session secret或可变验证展示label。读取、发布和Matching capture都独立复算并constant-time比较；hash drift按持久配置损坏fail closed，不返回partial DTO。

### 4.1 v1关闭内容与canonical hash面

为避免契约实现阶段再猜字段，v1机器内容固定如下；权威JSON Schema为`platform/contracts/domain/profile-version-v1.schema.json`：

- canonical root恰为`profile_schema_version=1`、`canonicalization_version=profile-version-json-v1`、`profile_id`、`version_no`、`taxonomy_bundle_id`和`content`；`content_sha256`是该root的RFC 8785 JCS UTF-8 bytes之SHA-256，不把digest自身放回签名面；
- `content`必须显式包含`interests,skills,availability,collaboration,compensation,boundaries,location,conflicts,ai`九组。草稿不完整用空array或`null`表示，不靠缺失字段产生第二种canonical shape；publish再执行完整性守卫；
- interest项固定为`problem_code/domain_code/task_code/strength/visibility/source_kind/evidence_ids`，v1 visibility只允许`PRIVATE | MATCH_ONLY`；skill项固定为`skill_code/proficiency/visibility/source_kind/evidence_ids`，visibility允许三档；
- availability固定为`available_from/weekly_hours/duration_weeks/timezone/visibility/source_kind/evidence_ids`；collaboration中的language、work mode、feedback cadence和team preference各自是带visibility/source/evidence的独立项，不能用父对象覆盖；
- compensation固定为整数`minimum_project_amount_minor/direct_cost_amount_minor`、`currency`和强制`visibility=PRIVATE`；boundaries的每个prohibited domain/task及`allowed_data_sensitivity`均是强制PRIVATE项；location只有受控`region_code`；
- conflict的公开save入口v1只接受exact `organization_id`并强制PRIVATE。`legacy_source_ref`只属于受控导入port，不进入公开OpenAPI、owner response、receipt、audit或event；导入切片发布前须另增internal contract；
- AI固定为`allowed/requires_ai/human_review_code/prohibited_case_codes/visibility/source_kind/evidence_ids`，v1最多MATCH_ONLY；`requires_ai=true`且`allowed=false`非法；
- `source_kind=VERIFIED_EVIDENCE`要求至少一个evidence ID；另两种source禁止附evidence ID。所有array保持输入的已验证canonical顺序，不由hash函数静默排序、trim或NFC修复；
- `asserted_at`、`confirmed_at`、evidence安全展示label/status、version生命周期和root指针都是server metadata，不属于客户端content或上述digest。有效性边界统一为`expires_at > server_now`；相等即失效。

## 5. CapabilityEvidence

证据元数据状态为 `SELF_ASSERTED | PENDING_VERIFICATION | VERIFIED | REJECTED | EXPIRED | WITHDRAWN`。记录至少包含owner、evidence kind、受控对象引用、声明的skill codes、验证provider/version、验证时间、到期时间和aggregate version。

- 原始文件、外部token、完整URL与provider响应不进入普通表、DTO、审计或outbox；
- ProfileVersion只引用evidence ID及发布时已确认的安全状态/hash，不嵌入正文；
- 后续验证结果不改写旧ProfileVersion。新MatchRun评估时同时保存被采用的 evidence version；过期/撤回后旧运行仍可审计，但新运行不得继续计入；
- `REJECTED/WITHDRAWN`不会从历史版本中物理删除引用，recipient projection必须过滤；
- evidence verification属于后续独立adapter切片；首个Profile GREEN可以只支持SELF_ASSERTED并默认不宣称VERIFIED。

## 6. 授权与 SafetyHold

公开写入口只接受cookie/BFF解析出的actor，不接收user_id、role、Session或Organization。允许条件为：

```text
ACTIVE User + ACTIVE Session/Family
+ owner_user_id == actor_id
+ active CREATOR UserRoleGrant
+ grant固化的exact policy requirement当前已满足
+ Profile相邻状态允许命令
+（Publish/Resume）有效SafetyHold ALLOW
```

IAM权威由固定 `iam_api.authorize_creator_profile_self_v1` 投影提供；Profile在线角色没有 IAM表 SELECT。函数必须绑定 `session_user`、`app.actor_id/app.session_id/app.operation`，固定 search_path和列allowlist，PUBLIC无EXECUTE，无动态SQL。事务先取得并锁定/复核IAM authority marker，再锁Profile根、current draft/published、taxonomy和按ID排序的Evidence；不得由请求GUC伪造CREATOR权限。

`PublishCreatorProfileVersion` 和 `ResumeCreatorProfile` 增加或恢复匹配可见性，必须在事务外调用版本化 SafetyHold。hold绑定最终 `profile_id`、prospective `aggregate_version`、exact draft `content_sha256`和actor；锁内权威或draft漂移则回滚，在事务外重评。BLOCK为403，provider unavailable为503且零业务写。SaveDraft、Pause、Archive与证据撤回属于私有写或安全降权，不被hold阻断。

未知Profile、非owner、失效grant与跨User ID对公开调用统一404，不泄露哪个关系失败。明确owner已知后，stale If-Match为412；相邻状态非法为409。首版wire code固定为：结构/类型错误 `INVALID_REQUEST`(400)，未认证或deadline失效 `AUTHENTICATION_REQUIRED/SESSION_EXPIRED`(401)，普通拒绝或hold阻断 `ACCESS_DENIED/SAFETY_HOLD_BLOCKED`(403)，不可披露 `RESOURCE_NOT_FOUND`(404)，重复创建、状态、幂等key复用或taxonomy/current policy变化 `PROFILE_ALREADY_EXISTS/INVALID_STATE_TRANSITION/IDEMPOTENCY_KEY_REUSED/TAXONOMY_BUNDLE_CHANGED/POLICY_BUNDLE_CHANGED`(409)，旧ETag `PRECONDITION_FAILED`(412)，发布内容不完整或必需政策未满足 `PROFILE_VALIDATION_FAILED/POLICY_ACCEPTANCE_REQUIRED`(422)，持久配置/依赖不可用 `POLICY_CONFIGURATION_UNAVAILABLE/SERVICE_UNAVAILABLE`(503)。repository错误只能映射到该关闭集合，不能临时扩展机器码。

## 7. 命令、幂等与原子事务

所有外部写使用 `Idempotency-Key`；除Create外还要求Profile强ETag `If-Match: "vN"`。receipt identity固定为：

```text
(principal_kind=USER, principal_id,
 command_name, command_version,
 idempotency_key_digest_key_id, keyed_idempotency_digest)
```

payload HMAC覆盖method、canonical path、target profile ID、If-Match、command schema version与关闭body。raw key不落库；receipt保存canonicalization/key IDs、payload hash、target/version、safe response与状态。先认证当前ACTIVE Session，再允许同User的新Session重放COMPLETED结果；异User、失效Session或corrupt response不重放。

同一transaction完成root/version/evidence link状态、receipt、audit与outbox。commit前每个逻辑写有稳定checkpoint；任一点失败全部回滚。COMMIT_SENT断链必须discard physical connection，再以新连接读取exact receipt和目标版本裁决：COMPLETED exact→重放，缺失→有限安全重试，corrupt/持续IN_PROGRESS→503，不猜测成功。

固定锁序：IAM Family/Session/User/UserRoleGrant/policy marker → Profile root → current DRAFT → current PUBLISHED → TaxonomyBundle → CapabilityEvidence按UUID byte序 → receipt相关唯一争用。不存在的可选行跳过但不逆序补锁。数据库unique/partial unique是最后防线，不能把原始SQL错误泄露为500。

## 8. HTTP 与读取投影

首版公开操作：

```text
POST /v1/me/creator-profile
GET  /v1/me/creator-profile
POST /v1/me/creator-profile/drafts
POST /v1/me/creator-profile/drafts/{profile_version_id}/publish
POST /v1/me/creator-profile/pause
POST /v1/me/creator-profile/resume
POST /v1/me/creator-profile/archive
```

公开HTTP机器权威固定为`platform/contracts/api/profile-v1.openapi.yaml`。Create body是关闭空对象；Save body恰含`taxonomy_bundle_id/based_on_profile_version_id/content`；Publish body恰含`confirmed=true`；Resume body是关闭空对象；Pause与Archive只接受关闭reason code。Pause reason关闭为`OWNER_REQUEST | TEMPORARY_UNAVAILABILITY | SAFETY_REVIEW`，Archive reason关闭为`OWNER_REQUEST | ACCOUNT_CLOSURE | SAFETY_REVIEW`，不接受reason note。六个写操作都要求`Idempotency-Key`与`X-CSRF-Token`，Create以外五个写操作还要求强`If-Match`；所有成功/错误响应均`Cache-Control: no-store`与`X-Trace-Id`，owner DTO成功响应均带强ETag。事件机器权威固定为`platform/contracts/events/profile-v1.schema.json`。

请求与响应在独立 versioned OpenAPI中关闭；写body不含actor/role/session、server time、hash或状态。owner GET返回完整可管理投影，但证据只返回安全label/status，绝不返回storage locator/provider token；每个响应NoStore、强ETag和trace ID。v1不提供任意 `GET /creator-profiles/{id}`。

内部读取分三种且不可混用：

| profile | 调用者 | 返回范围 |
| --- | --- | --- |
| `OWNER_SELF` | exact owner Session | 全部业务值；秘密locator仍不返回 |
| `MATCH_INPUT` |绑定MatchRun job的SYSTEM workload | ACTIVE Profile的exact published内容、私密硬过滤事实和hash；只对job candidate allowlist |
| `INVITATION_CARD` | Matching Context | 已产生业务Invitation后保存的披露快照；只含当时允许字段，不回查当前Profile扩张 |

需求方、组织管理员和运营者不能直接调用MATCH_INPUT。PUBLIC visibility只冻结未来公开资格，本切片没有公共目录，因此anonymous query始终不存在。补充运营访问必须先设计assignment、purpose、字段allowlist、时效与审计，不能加入“admin看全部”。

## 9. PostgreSQL 结构与RLS义务

Profile使用独立schema与在线角色，至少包含：

- `profile.creator_profiles`：owner唯一、状态shape、current指针、aggregate version；
- `profile.profile_versions`：同Profile version_no唯一、不可变内容/hash/taxonomy/evidence snapshot；
- `profile.capability_evidence`：owner/status/version/受控object reference；
- `profile.command_receipts`：keyed identity、IN_PROGRESS/COMPLETED、安全response；
- 共享 `audit.audit_events` 与 `infra.outbox_events` 的关闭插入入口。

ProfileVersion内容可以使用关闭JSONB，但在线角色不能任意写表：adapter使用固定statement或窄SECURITY DEFINER入口，写前与读后均以同一application schema/JCS validator复算。数据库至少约束JSON根类型、schema/canonicalization version、hash格式、owner/profile/version复合外键、同一根一个current draft/published和状态shape。没有可信数据库JSON schema扩展时，不得声称CHECK已经证明完整内容契约。

所有表 `ENABLE + FORCE RLS`；owner scope必须同时验证IAM exact Session/actor，不因可设置custom GUC就放行。matcher只能经绑定job与candidate allowlist读取exact ACTIVE/published行。schema owner、migration、备份与线上角色分离；线上角色无BYPASSRLS、无table owner、无动态SQL、无PUBLIC EXECUTE。

Migration forward-only、raw-byte SHA-256、review pin、advisory lock、逐文件事务与wheel packaging沿用IAM runner协议，但Profile拥有自己的contract manifest或经新ADR明确共享；不能把Profile表静默塞进IAM兼容view。

## 10. 事件、隐私与历史

首版事件关闭为：

- `CreatorProfileCreated(profile_id, owner_user_id, status)`；
- `CreatorProfilePublished(profile_id, profile_version_id, version_no, content_sha256, taxonomy_bundle_id, status)`；
- `CreatorProfilePaused/Resumed/Archived(profile_id, owner_user_id, status)`；
- 后续 `CapabilityEvidenceVerified/Expired/Withdrawn`。

事件只通知“需要重读/失效”，不携带skills、availability、compensation、boundaries、conflicts、evidence ref或legacy ref。Matching必须经授权port取得exact版本，不能从事件payload恢复完整档案。每封事件使用共享closed envelope，actor/original actor/correlation/causation/trace和aggregate version完整；schema validator在写outbox前运行。

已被MatchRun、Invitation、Selection、Project或争议引用的ProfileVersion永久保留其不可变业务证据；未发布DISCARDED草稿可按版本化保留策略删除。Archive不是数据权利删除。访问、更正、导出和删除请求需要单独的data-rights设计，且必须区分可删除正文、受限法律证据与去标识化分析事实。

日志、trace、metric label、异常、receipt、audit、outbox、通知和死信递归检查禁止：最低报酬、边界、conflict ID、evidence locator、legacy ref、raw payload、Idempotency-Key、cookie/CSRF/Session secret和IAM内部证据。

## 11. 测试驱动实施顺序

1. 发布Creator Profile OpenAPI、事件JSON Schema和关闭content schema；先取得unknown field/enum/visibility/secret/status的contract RED→GREEN。
2. 写domain状态与性质RED：每个允许转换、终态回退、版本链、内容不变、hash、expiry equality和随机命令序列。
3. 写Memory application semantic RED：exact IAM authority、multi-profile唯一、draft replacement、publish/pause/resume/archive、hold drift、receipt、每写点rollback、commit unknown与closed事件。
4. 最小Memory GREEN并保持IAM、Outbox和MVP回归；不能用Profile fixture恢复IAM权限。
5. 先设计再新增Profile PostgreSQL migration/roles/RLS/fixed queries；真实PostgreSQL RED覆盖owner/other User、伪GUC、matcher job allowlist、partial unique、hash drift、并发publish和COMMIT断链，再最小GREEN。
6. 实现framework-neutral presenter/HTTP路由与production composition，跑真实PostgreSQL+BFF Session+Outbox E2E；三种recipient projection分别做秘密sentinel。
7. 只有Profile切片所有适用门禁GREEN后，Matching才可把它作为生产输入；在此之前Matching测试使用显式contract fake并标明非production。

测试不得通过跳过、owner/BYPASS连接、关闭RLS、容忍partial projection、把坏fixture包装成业务错误，或在production识别test mode求绿。

### 11.1 第一轮TDD证据与planned code trace

2026-08-08第一轮只实现机器契约与行为边界，不实现Memory GREEN、PostgreSQL、HTTP或composition：

| 层 | artifact / command | 精确结果 | 裁决 |
| --- | --- | --- | --- |
| API contract | `platform/contracts/api/profile-v1.openapi.yaml` | Profile contract合计`19/19 OK` | GREEN；7 operations、6 writes、NoStore/ETag/trace、If-Match create例外和关闭错误码已冻结 |
| event contract | `platform/contracts/events/profile-v1.schema.json` | 包含在上述`19/19` | GREEN；5个closed envelope/payload pair及私密字段不可表示 |
| canonical content | `platform/contracts/domain/profile-version-v1.schema.json` | 包含在上述`19/19` | GREEN；unknown field、visibility/source/evidence、bool-as-int、AI与PRIVATE上限可执行 |
| domain | `PYTHONPATH=src:tests .venv/bin/python -m unittest creator_profile.test_creator_profile_domain_red -q` | `Ran 9 tests`；`8 failures`、`0 errors`、`0 skips` | 有效RED；唯一GREEN项只证明immutable/secret-safe value shape |
| application | `PYTHONPATH=src:tests .venv/bin/python -m unittest creator_profile.test_creator_profile_application_red -q` | `Ran 10 tests`；`9 failures`、`0 errors`、`0 skips` | 有效RED；唯一GREEN项只证明commands/actor frozen且repr不含秘密 |
| 旧稳定non-storage | 排除上述Profile behavior RED；IAM contract仅计其既有22项 | `254/254 OK` | application/auth/lifecycle/authorization/IAM contract/HTTP/policy/read/unit无回归 |
| 旧稳定storage | PostgreSQL 18、IAM canonical head 13；排除并发线程新增且仍处于RED的`test_policy_consent_commands_uow_red.py` | `108/108 OK` | 原稳定storage无回归；并发RED不冒充本切片失败 |
| docs/static | `python3 scripts/verify_docs.py`与`git diff --check` | `43 navigable pages`；exit 0 | GREEN |

每个RED failure都显示稳定`PROFILE_DOMAIN_BEHAVIOR_NOT_AVAILABLE`或`PROFILE_APPLICATION_BEHAVIOR_NOT_AVAILABLE`，不是ImportError、fixture签名错误、skip或意外exception。Domain 8项分别冻结root shape/转换、append-only version chain、JCS/hash、visibility/bool/overlap、publish completeness、expiry equality和published immutability。Application 9项冻结六命令、exact IAM authority与404非披露、If-Match/state、hold bind/drift、锁序、receipt replay/conflict、六个write checkpoints、COMMIT unknown和隐私递归扫描。

当前production trace只允许以下可导入边界：

| CODE | 当前责任 | 第一轮状态 | 下一GREEN落点 |
| --- | --- | --- | --- |
| `creator_profile/domain/model.py` | frozen enums、`ProfileContent`、root/version/evidence facts与default-deny behavior signatures | importable · RED sentinel | 先实现关闭validator/JCS/hash/expiry，再按root→version transition最小GREEN |
| `creator_profile/application/commands.py` | actor与六个深度immutable、secret-safe commands/result | shape GREEN | 保持wire未映射，不加入HTTP concerns |
| `creator_profile/ports/commands.py` | exact IAM authority、SafetyHold、clock/ID/keyring/schema/UoW与commit-unknown ports | shape GREEN | 下一轮仅用独立Memory adapter实现可观测transaction protocol |
| `creator_profile/application/handlers.py` | 六个无Memory/IAM fixture/owner connection fallback的default-deny handlers | semantic RED | 按create→save→publish→pause/resume/archive顺序逐项最小GREEN |
| `tests/support/creator_profile_builders.py` | 独立authority/hold/UoW/checkpoint/commit-unknown与秘密sentinel fixtures | test support | 不导入IAM builders，不成为production composition |

本轮没有修改IAM migration、manifest、runner、Accept/read/policy代码，也没有新增Profile PostgreSQL或HTTP实现。下一轮不得删除或弱化这些断言来求GREEN。

### 11.2 Memory GREEN证据与后续边界

2026-08-08第二轮保持上述19个contract、9个domain与10个application method原样，将同一semantic oracle从RED推进到Memory GREEN：

| 层 | artifact / command | 精确结果 | 裁决 |
| --- | --- | --- | --- |
| contracts | `contract.test_creator_profile_contracts` | `Ran 19 tests` · `OK` | 三份机器契约byte-level内容未放宽；unknown field、隐私不可表示、event envelope/payload继续关闭 |
| domain | `creator_profile.test_creator_profile_domain_red` | `Ran 9 tests` · `OK` | root/status shape、append-only版本链、关闭content、bool拒绝、JCS/hash、expiry equality与published immutability为Memory GREEN |
| application | `creator_profile.test_creator_profile_application_red` | `Ran 10 tests` · `OK` | 六命令、exact IAM authority、404非披露、hold、receipt、原子checkpoint、COMMIT unknown及隐私为Memory GREEN |
| Profile合计 | 上述三组同进程复跑 | `Ran 38 tests` · `OK` | `0 failures`、`0 errors`、`0 skips` |
| 旧稳定non-storage | 排除并发中的Demand intentional semantic RED；IAM contract仍只计既有22项 | `254/254 OK` | 既有application/auth/lifecycle/authorization/IAM contract/HTTP/policy/read/unit无回归 |

Memory production trace现固定为：

| CODE | Memory GREEN责任 | 明确未声称 |
| --- | --- | --- |
| `creator_profile/domain/model.py` | 关闭v1 content validator；NFC/type/range/visibility/source/evidence/overlap守卫；canonical root bytes与SHA-256；root/version转换、expiry和published immutability | 不声称数据库JSONB、约束、并发或RLS已证明 |
| `creator_profile/application/commands.py` | 深度immutable、repr secret-safe actor/六命令/result | 不接收HTTP cookie/header，也不自行构造IAM authority |
| `creator_profile/ports/commands.py` | exact IAM、SafetyHold、clock/ID/keyring/schema/UoW与COMMIT outcome closed ports | 不提供owner/BYPASS fallback或test-mode production branch |
| `creator_profile/application/handlers.py` | authority先行；Publish/Resume事务外hold；锁内target drift退出并重评；keyed receipt replay/conflict；root/version/receipt/audit/outbox同事务；六个publish checkpoint与COMMIT unknown裁决 | Memory UoW不是PostgreSQL adapter；没有HTTP presenter/composition |
| `tests/support/creator_profile_builders.py` | 独立authority/hold/transaction fake，以真实canonical hash和非碰撞version ID驱动同一production代码 | support不导入IAM builders、不属于production composition |

本轮没有新增或修改任何IAM/Profile migration、manifest、review pin、runner、Accept/read/policy或Demand代码。独立fixed-UoW/RLS设计与真实PostgreSQL 18有效RED现记录于[Creator Profile PostgreSQL fixed-UoW、RLS 与 Match capture](/architecture/creator-profile-postgresql.md)；在该设计获审阅并进入新的TDD轮次前仍不登记migration。HTTP继续排在PostgreSQL GREEN之后，必须复用已冻结OpenAPI并另证BFF Session、If-Match/Idempotency-Key、NoStore/ETag/trace和recipient projection，不能把Memory handler直接表述为HTTP完成。

### 11.3 PostgreSQL fixed-UoW/RLS有效RED

2026-08-08第三轮没有修改既有19/9/10断言，也没有写Profile或IAM migration。production只新增关闭、不可变且checkout前default-deny的PostgreSQL seam；真实测试动态加载最终IAM head 14并独立建立exact Creator authority fixture：

| 层 | artifact / command | 精确结果 | 裁决 |
| --- | --- | --- | --- |
| Profile PG18 RED | `storage.postgres.test_creator_profile_postgres_red` | `Ran 13 tests` · `34 failures` · `0 errors` · `0 skips` | owner唯一、DRAFT/PUBLISHED partial unique、immutable hash、exact IAM/伪GUC/跨User、matcher allowlist、并发Publish、六checkpoint、receipt/COMMIT_SENT、pool reset/privacy均为有效semantic RED |
| IAM dependency setup | 动态catalog v0–v14、真实PG18、独立ACTIVE Session/User/CREATOR/policy graph | setup全部通过 | v14 SQL SHA `79e6642f…481d`；manifest/review pin `1b8093c4…6884`；没有硬编码runner head |
| Profile Memory回归 | contracts/domain/application同进程 | `38/38 OK` | 19/9/10既有断言未放宽 |
| 旧稳定non-storage | 排除其他Context的intentional RED | `254/254 OK` | 既有稳定面无回归 |
| 最新稳定storage | 排除本Profile PG文件唯一intentional RED | `126/126 OK` | head 14既有storage无回归 |

RED缺口恰为独立Profile catalog/schema、`profile_app/profile_matcher`、FORCE RLS、exact IAM/matcher窄函数与七个fixed SQL programs尚不存在；default-deny seam不checkout、不使用Memory/owner fallback。完整角色、GUC、constraint、锁序、statement budget、checkpoint、COMMIT_SENT、secret boundary与future migration门禁只以独立数据库设计页为准。本轮到此停止，不进入GREEN，也不预占migration编号。

### 11.4 PostgreSQL RED → GREEN

第四轮保持上述历史RED与19/9/10机器/Memory断言，追加IAM forward-only `0015`和Profile独立`0001`，实现非owner fixed UoW、FORCE RLS、约束/immutable trigger、receipt/audit/outbox、六checkpoint、双连接Publish、COMMIT_SENT/pool reset，以及绑定MatchRun job的完整`MATCH_INPUT`。后续安全审阅又先取得IAM capability `4 failures / 0 errors`和full MatchInput `1 failure / 0 errors`的有效补充RED，再最小修复direct IAM枚举、marker泄漏、old-source acceptance与只返回ID/hash/进程时间问题。

最终证据为：Profile原13个PG方法13/13；IAM capability 5/5；既有Profile contracts/domain/application 38/38；上述合计56/56；平台既定contract集合59/59；排除独立Demand intentional PG RED的最新稳定storage 144/144。IAM `0015` SQL SHA为`50df44d9…1373a`、manifest/review pin为`ebbdeef2…9b4f`；Profile `0001` SQL SHA为`6c085396…1f9b`、独立manifest/review pin为`15eeba95…a65f`。详细fixture isolation correction、角色/ACL、query budget、完整摘要与未完成HTTP边界见[Creator Profile PostgreSQL fixed-UoW、RLS 与 Match capture](/architecture/creator-profile-postgresql.md)。

## 12. REQ → DESIGN → TEST → CODE追踪

| REQ | DESIGN | 验收 | TEST | CODE | 状态 |
| --- | --- | --- | --- | --- | --- |
| `REQ-PROFILE-001` | DES-PROFILE-001 · §3 | 一个User最多一个Profile；版本与状态不可非法回退 | `TEST-UNIT-PROFILE-001`、`TEST-DB-PROFILE-001` | immutable root/version、Memory transitions、DB constraints/triggers | memory + PostgreSQL green |
| `REQ-PROFILE-002` | DES-PROFILE-002 · §4 | 内容关闭、规范化、hash可复算且发布版本不变 | `TEST-CONTRACT-PROFILE-001`、`TEST-PROP-PROFILE-001` | content contract + validator/JCS/hash/immutability + DB readback | contract + memory + PostgreSQL green |
| `REQ-PROFILE-003` | DES-PROFILE-003 · §4/8 | owner/matcher/invitation字段allowlist不泄漏私密事实 | `TEST-AUTH-PROFILE-001`、`TEST-API-PROFILE-001` | closed API/event + receipt/audit/outbox privacy；full MatchInput与PG sentinel；HTTP projection planned | memory + PostgreSQL green · HTTP planned |
| `REQ-PROFILE-004` | DES-PROFILE-004 · §2/6 | IAM暂停/撤销/政策缺失立即阻止发布与新匹配 | `TEST-APP-PROFILE-001`、`TEST-DB-PROFILE-RLS-001` | exact authority Memory orchestration；IAM0015/Profile-bound matcher wrapper | memory + PostgreSQL green |
| `REQ-PROFILE-005` | DES-PROFILE-005 · §6 | Publish/Resume hold绑定exact版本；降权命令不阻断 | `TEST-APP-PROFILE-HOLD-001` | exact outside-UoW hold、locked drift re-evaluation、PG hold binding | memory + PostgreSQL green |
| `REQ-PROFILE-006` | DES-PROFILE-006 · §7 | 幂等、If-Match、并发与COMMIT unknown不重复事实 | `TEST-APP-PROFILE-RECEIPT-001`、`TEST-DB-PROFILE-CONCURRENCY-001` | keyed receipt/checkpoint/unknown Memory与physical DB protocol | memory + PostgreSQL green |
| `REQ-PROFILE-007` | DES-PROFILE-007 · §5 | evidence状态与旧版本分离，过期后不用于新运行 | `TEST-APP-PROFILE-EVIDENCE-001` | closed refs、publish snapshot与exclusive expiry | memory green · evidence adapter planned |
| `REQ-PROFILE-008` | DES-PROFILE-008 · §2/8 | MatchRun固定exact版本/hash，不随当前档案变化 | `TEST-E2E-PROFILE-MATCH-001`、`TEST-DB-PROFILE-MATCH-001` | exact full-content MatchInput capture、job/workload/candidate allowlist；Matching persistence/E2E planned | PostgreSQL green · E2E planned |
| `REQ-PROFILE-009` | DES-PROFILE-009 · §10 | audit/outbox/telemetry不含报酬、边界和证据秘密 | `TEST-EVENT-PROFILE-001`、`TEST-SEC-PROFILE-001`、`TEST-SEC-PROFILE-PG-001` | closed event schema + safe Memory facts + DB receipt/audit/outbox/repr sentinel | contract + memory + PostgreSQL green · HTTP planned |

本表只有取得有效RED后才可把状态改为red；只有相同断言、相关回归与真实依赖证据全绿后才改为green/verified。
