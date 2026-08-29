# Creator Profile PostgreSQL 18 fixed-UoW、RLS 与 Match capture

> 状态：Profile PostgreSQL已按本页完成RED→GREEN；Profile head 5新增数据库自行发现候选并持久化raw与privacy-derived Matching输入的生产边界。`profile_app/profile_matcher`仍为非owner fixed-program角色，全部业务表保持FORCE RLS。历史RED证据未改写。
> 业务与机器契约：[Creator Profile、版本与字段披露](/architecture/creator-profile.md)、`platform/contracts/api/profile-v1.openapi.yaml`、`platform/contracts/events/profile-v1.schema.json`与`platform/contracts/domain/profile-version-v1.schema.json`。
> IAM依赖：[IAM PostgreSQL 首个持久化切片](/architecture/iam-postgresql-implementation.md)；IAM与Profile migration/manifest/review pin分别受检，Profile `0001`从未写入IAM compatibility。

## 1. 目标、完成定义与非目标

本切片把Memory GREEN冻结为七个数据库程序：六个SELF writer与一个SYSTEM matcher capture。未来GREEN必须同时证明：

1. writer只使用`profile_app`、matcher只使用`profile_matcher`，二者均为PostgreSQL 18非owner、`NOSUPERUSER NOBYPASSRLS NOINHERIT`在线角色；
2. Create/Save/Publish/Pause/Resume/Archive只执行登记的fixed statements，在同一个`READ COMMITTED` transaction中完成root/version、receipt、audit与outbox；
3. 数据库从持久IAM Session/User/CREATOR grant/exact policy requirement复算authority，任何request GUC只缩小scope，不能制造权限；
4. owner唯一、同Profile单一DRAFT/PUBLISHED、root pointer、版本单调、published canonical facts不可变都由数据库约束与application读回校验共同守卫；
5. Publish/Resume携带事务外取得的exact SafetyHold；锁内authority/root/version漂移不使用旧hold提交；
6. matcher只能为exact MatchRun/workload由数据库发现并捕获当时ACTIVE、IAM-eligible的current PUBLISHED版本，不能由caller传candidate IDs或limit；
7. 每个逻辑write checkpoint可注入故障并证明全图回滚；COMMIT acknowledgement丢失只返回outcome unknown并discard physical connection；
8. raw Idempotency-Key、cookie、CSRF、Session handle、evidence locator、provider token和私密content不得进入receipt、audit、outbox、异常、trace或普通repr。

本页不实现HTTP、BFF Session解析、broker同步发送、Taxonomy或Matching的上游写模型、evidence上传/验证、公开目录、owner GET projection或production composition。管理连接可以建立测试事实，但不得成为被测业务路径。

## 2. Catalog轴与当前schema gap

IAM与Profile是两个bounded context，不能把Profile schema version静默写进`iam.schema_compatibility`。版本轴固定为：

| 版本轴 | 权威 | 本轮使用 |
| --- | --- | --- |
| IAM PostgreSQL | 现有`MigrationCatalog.load()`、raw-byte SHA-256、manifest/review pin | 动态加载v0–v15；`0015`只增加Profile消费的IAM capability，不增加Profile schema |
| Profile PostgreSQL | `creator_profile/adapters/postgres/migrations/`独立catalog与`profile.schema_compatibility` | forward-only artifacts `0001`–`0004`；ledger/contract/compatibility均独立，不复用IAM版本号 |
| Profile content/API/event | 三份已发布v1机器契约 | migration manifest必须绑定其exact bytes；数据库版本不改变content schema version |

exact IAM lock projection归IAM所有。`0015_expand__creator_profile_authority.sql`先增加`iam_api.lock_creator_profile_self_v1`与内部matcher eligibility；Profile `0001`随后只消费该capability，不修改IAM表、policy或compatibility row。`profile_matcher`没有IAM eligibility的直接EXECUTE，只能经Profile schema中同时验证exact MatchRun/workload/candidate Profile/真实owner/authorization digest/时效的definer调用；错误marker只得到`NULL,false`，旧source acceptance按`user+current required document_id/hash/legal_effect`复用而不要求acceptance source bundle等于current。两catalog部署顺序为IAM capability先、Profile schema后；任一digest/pin不匹配都不进入业务transaction。

当前动态IAM catalog可正常bootstrap PostgreSQL 18，但没有Profile catalog、`profile/profile_api` schema、两个在线角色、Profile表、RLS或IAM Profile authority projection。因此本轮合法结果只能是设计、default-deny seam和真实语义RED。不得为了让RED setup成功而建立未登记临时schema、运行测试内DDL、授予owner或把Profile对象塞进IAM migration。

## 3. 角色、pool 与connection协议

future deployment至少包含：

- `profile_schema_owner`：NOLOGIN，拥有`profile/profile_api`对象，不是在线角色；
- `profile_migration_runner`：LOGIN，仅迁移窗口取得advisory lock与执行受检artifact；
- `profile_app`：LOGIN，六SELF writer独立pool；
- `profile_matcher`：LOGIN，只执行exact Match capture程序的独立pool；
- backup/inspection角色另行部署，不能复用在线credential。

writer checkout协议固定：

```text
checkout profile_app, autocommit=true, status=IDLE
→ RESET ROLE; RESET ALL; DISCARD TEMP
→ verify session_user=current_user=profile_app, PostgreSQL major=18
→ BEGIN ISOLATION LEVEL READ COMMITTED
→ SET LOCAL UTC/timeouts/closed app.* via pg_catalog.set_config(...,true)
→ fixed authority + Profile lock/read/write program
→ state=COMMIT_SENT → COMMIT
→ RESET ROLE; RESET ALL; DISCARD TEMP
→ verify IDLE/exact role/all scope empty → release
```

matcher使用同样reset，但capture transaction为`READ WRITE, REPEATABLE READ`且role必须为`profile_matcher`；写入范围只限Profile-owned immutable capture facts。两个pool不得共享physical connection；禁止`SET ROLE`、prepared arbitrary SQL、temporary object、session-level GUC、owner checkout和connection内Memory fallback。

首版settings与production seam一致：`lock_timeout=2000ms`、`statement_timeout=10000ms`、`idle_in_transaction_session_timeout=15000ms`、单版本canonical content上限512KiB、一次capture最多500个candidate。pre-COMMIT只对登记的serialization/deadlock/lock timeout最多重试3次，并复用receipt/content/hold/event IDs；COMMIT_SENT之后绝不retry。

## 4. Transaction-local scope

writer只设置以下关闭值：

| GUC | 值与来源 |
| --- | --- |
| `app.scope_kind` | exact `PROFILE_SELF` |
| `app.operation` | `CREATE_PROFILE / SAVE_PROFILE_DRAFT / PUBLISH_PROFILE / PAUSE_PROFILE / RESUME_PROFILE / ARCHIVE_PROFILE` |
| `app.actor_user_id` / `app.session_id` | BFF已解析candidate；数据库必须从IAM持久row复核 |
| `app.profile_id` | server-issued exact Profile ID |
| `app.command_id` / `app.command_name` / `app.command_version` | receipt ID、关闭operation名、`1` |
| `app.idempotency_key_digest_key_id` / `app.idempotency_key_digest` | keyed identity；从不设置raw key |
| `app.expected_aggregate_version` | Create为空，其余为If-Match解析后的正整数 |

matcher只设置`scope_kind=PROFILE_MATCH_CAPTURE`、`operation=CAPTURE_MATCH_INPUTS`、`match_run_id`、`workload_id`与32-byte `match_authorization_digest`。candidate Profile/User/version IDs及limit均无request字段或GUC。`creator_grant_id`、role、User/Session状态、policy bundle、owner、current pointers、taxonomy/evidence状态、hold ALLOW都不能由caller声明。

head 5 derived程序改用`PROFILE_MATCH_DERIVATION / CAPTURE_DERIVED_MATCH_INPUTS`，并设置`authorization_digest`与`demand_match_context_sha256`。Demand context bytes仍是函数参数且只用于私密比较/派生；GUC只放其SHA-256，不放Organization、Demand、金额、地域或其他payload。

每次transaction用参数化`pg_catalog.set_config(name,value,true)`并readback。policy同时要求`session_user`、exact role/operation/scope，且调用IAM/Matching持久authority函数；即使攻击者能设置全部custom GUC，也不能直接SELECT/UPDATE跨User row。

## 5. Profile schema与约束

### 5.1 `profile.creator_profiles`

根表至少包含UUID `id`、唯一不可变`owner_user_id`、关闭status、正整数`aggregate_version`、nullable current draft/published pointers、pause/archive时间与reason、`created_at/updated_at`。约束包括：

- `UNIQUE(owner_user_id)`；一个User只能有一个个人Profile；
- status shape逐字等于Memory：DRAFT无published/pause/archive，ACTIVE有published且无pause/archive，PAUSED有published+pause pair，ARCHIVED无current pointers/pause且有archive pair；
- `updated_at >= created_at`，所有deadline/timestamp为UTC `timestamptz`；
- `(id,current_draft_version_id)`与`(id,current_published_version_id)`使用同Profile composite、DEFERRABLE initially deferred FK指向`profile_versions(profile_id,id)`；
- owner、created_at不可UPDATE；root CAS必须比较`id,owner,aggregate_version,status,current pointers`并恰更新一行。

`owner_user_id`不设跨context普通FK来代替authority；Create transaction必须先通过IAM exact lock projection。Profile不能从自己的owner列恢复CREATOR权限。

### 5.2 `profile.profile_versions`

版本表至少包含`id/profile_id/version_no/status/based_on_profile_version_id`、schema/canonicalization/taxonomy、closed `content jsonb`、32-byte`content_sha256`、creator/asserted/confirmed facts与evidence snapshot。约束包括：

- `UNIQUE(profile_id,version_no)`、`UNIQUE(profile_id,id)`，version从1连续递增；
- `UNIQUE(profile_id) WHERE status='DRAFT'`与`UNIQUE(profile_id) WHERE status='PUBLISHED'`两条partial unique；
- based-on composite FK属于同Profile且应用锁内证明其version_no恰小于新版本；
- JSON根必须object，九个v1 group恰存在、schema/canonicalization常量和hash长度可由CHECK证明；数据库没有可信完整JSON Schema扩展时不声称CHECK证明字段语义；
- immutable trigger比较profile/version/based-on/schema/canonicalization/taxonomy/content/hash/creator/asserted facts。唯一允许UPDATE是`DRAFT→PUBLISHED|DISCARDED`、`PUBLISHED→SUPERSEDED|RETIRED`及首次publish确认元数据；任何content/hash/taxonomy修改即使由owner执行也拒绝；
- adapter在insert前与locked read后都用`profile-version-json-v1` canonicalizer复算SHA-256并constant-time比较。合法结构但hash drift是持久配置损坏，不返回partial内容。

Publish fixed statement用一个受检CTE原子SUPERSEDE旧PUBLISHED、PUBLISH current DRAFT并返回两行exact facts；故障checkpoint仍只有一个`profile_version.published`，不能在两个Python statement间暴露双published或零published状态。

### 5.3 evidence、taxonomy marker、receipt与match allowlist

首个migration还需要：

- `profile.capability_evidence`：owner、status/version、受控object reference、skill codes、provider/version、安全verification/expiry facts；不保存raw locator/token/provider response；
- `profile.profile_version_evidence`：published version到exact evidence ID/version/safe status/hash的immutable snapshot；
- `profile.taxonomy_bundle_markers`：由Taxonomy受控同步入口维护的exact ACTIVE bundle/hash；`profile_app`不可写；
- `profile.command_receipts`：USER principal、command/version、retained keyed identity/payload material、target/version、IN_PROGRESS/COMPLETED、安全response与retention；raw key/Session/正文永远没有列；
- `profile.match_capture_authorizations`：MatchRun、workload、candidate Profile、authorization digest、有效窗口；只由Matching受控SYSTEM ingress写入，matcher不能扩大allowlist。

audit/outbox继续写共享基础设施表，但只经Profile operation/RLS允许的关闭insert。Profile migration不能改变IAM audit/outbox既有事件；Profile事件写入前必须由已发布`profile-v1.schema.json`验证。

## 6. FORCE RLS 与exact IAM authority

全部Profile业务/receipt/allowlist表`ENABLE ROW LEVEL SECURITY`且`FORCE ROW LEVEL SECURITY`。PUBLIC无schema usage/table privilege/function execute。在线角色不是table owner、无BYPASSRLS；schema owner虽受FORCE RLS，也只能经`session_user`与operation关闭policy执行受检函数。

IAM提供单一窄lock projection：

```text
iam_api.lock_creator_profile_self_v1(
  actor_user_id uuid,
  session_id uuid,
  operation text,
  expected_authority_marker_sha256 bytea
)
```

它是固定search_path、无dynamic SQL、`SECURITY DEFINER`、`VOLATILE/PARALLEL UNSAFE`，PUBLIC无EXECUTE，只授予`profile_app`。函数先锁SessionFamily→Session→User→exact active CREATOR UserRoleGrant→source ACCEPTED Invitation→stored selector/current policy marker，复核ACTIVE/current generation、exclusive deadlines、actor/session binding、grant未撤销及exact policy requirements当前满足。返回关闭authority marker、User/grant version与selector/current bundle ID；不返回Session secret、contact、policy正文或任意role列表。

unknown User/Profile、跨owner、无/失效grant统一不可披露。User/Session认证失败仍按关闭401；明确owner后才比较If-Match。function/policy不得只检查`current_setting('app.actor_user_id')`，也不得接受Profile表中owner存在作为IAM证明。

## 7. Fixed program registry与statement budget

production seam已经冻结`CREATOR_PROFILE_POSTGRES_STATEMENT_PROFILES`；当前仅有statement identity/budget，没有SQL。未来实现只能为这些名字提供单一static SQL常量与bind参数：

| operation | role | fixed statements | budget |
| --- | --- | --- | ---: |
| Create | `profile_app` | authority；receipt claim；root insert；audit；outbox；receipt complete | 6 |
| SaveDraft | `profile_app` | authority；graph lock；receipt；discard old draft；insert draft；root CAS；audit；complete | 8 |
| Publish | `profile_app` | authority；graph lock；receipt；publish/supersede CTE；root CAS；audit；outbox；complete | 8 |
| Pause | `profile_app` | authority；graph lock；receipt；root CAS；audit；outbox；complete | 7 |
| Resume | `profile_app` | authority；graph lock；receipt；root CAS；audit；outbox；complete | 7 |
| Archive | `profile_app` | authority；graph lock；receipt；retire/discard versions；root CAS；audit；outbox；complete | 8 |
| Match capture | `profile_matcher` | `discover_and_capture_creator_profile_match_inputs_v1` | 1 |

registry的query-shape digest覆盖operation、role、statement names/order/budget与`creator-profile-postgres-v1`。SQL不得根据reason、visibility、status、candidate数量或content字段拼接；禁止`SELECT *`、dynamic SQL、arbitrary repository method、per-candidate N+1、OFFSET或请求控制的ORDER BY。未来任何column/join/order/checkpoint变化必须发布新statement/profile migration，不能原地改变digest。

## 8. 全局锁序与并发裁决

writer每次transaction固定：

```text
1 IAM SessionFamily → Session → User → CREATOR grant → source Invitation → policy marker
2 CreatorProfile root；Create锁IAM User并依赖owner unique收口不存在root
3 current DRAFT
4 current PUBLISHED
5 TaxonomyBundle marker
6 referenced CapabilityEvidence按UUID raw bytes
7 exact receipt identity
8 section 9 writes
```

不存在的optional row跳过但不逆序补锁。same key并发在IAM/root后由receipt unique等待，赢家完成后输家只能exact replay或`IDEMPOTENCY_KEY_REUSED`；different key Publish在root锁串行，第二个old If-Match必须412且不能产生receipt/audit/outbox。两个不同User不得因global table lock相互串行。

application在transaction外取得Publish/Resume hold。locked authority marker、root aggregate、current version ID/hash、actor或policy version任一变化都ROLLBACK；上层离开UoW后重新取得authority/target并调用hold。adapter不得在持锁时访问SafetyHold，也不能把旧ALLOW改写成503后继续业务写。

## 9. 六个writer与write checkpoints

receipt claim之前完成closed request、retained key readiness、server major/role、exact authority、root/pointer/taxonomy/evidence/hold检查。业务逻辑与Memory一致：

- Create插入DRAFT root，owner unique冲突分类为`PROFILE_ALREADY_EXISTS`或exact replay；
- Save每次插入新immutable DRAFT并DISCARD exact prior draft，version_no由locked graph推导；
- Publish只发布current DRAFT、SUPERSEDE旧published、更新root ACTIVE并保存evidence snapshot；
- Pause只降权root；Resume重新证明current published hash/evidence/IAM/hold；
- Archive清空pointers并DISCARD draft/RETIRE published，ARCHIVED终态。

Publish故障门禁恰为Memory已冻结的六个checkpoint：

```text
receipt.pending
profile_version.published       # 同一CTE包含optional supersede
profile.root
audit.profile_published
outbox.profile_published
receipt.completed
```

fault injector只在对应fixed statement前观察`(checkpoint, contiguous ordinal)`，不能改SQL、参数、跳过或提交。每一点失败后以独立管理snapshot逐表比较root/version/evidence snapshot/receipt/audit/outbox完全相等，且无可见IN_PROGRESS receipt。其他operation使用production enum中登记的关闭checkpoint子集。

## 10. Receipt、COMMIT_SENT与recovery

receipt identity与Memory/HTTP一致：`(USER,principal,command,version,key_id,keyed_digest)`；payload HMAC覆盖method、canonical path、target Profile、If-Match、schema version和关闭body。row保存`profile-command-json-v1`、retained key IDs、payload hash、target aggregate version、安全response/schema/ETag、status和retention，不保存raw key、Session或content。

completed replay仍先验证当前ACTIVE User/Session属于同principal；允许同User新Session，但不重复Profile、audit或outbox写。same identity不同payload为`IDEMPOTENCY_KEY_REUSED`；损坏/多行/未知schema/持续IN_PROGRESS为503，不从root状态猜测原命令成功。

adapter在driver `COMMIT`前切换`WRITING→COMMIT_SENT`。之后任何driver/连接/timeout错误只能：

1. 调用`connections.discard(connection)`一次；
2. 抛`CreatorProfilePostgresCommitOutcomeUnknownError(code='COMMAND_OUTCOME_UNKNOWN')`；
3. 不ROLLBACK、RESET、release、查询receipt或同request retry。

上层以same key在新physical connection重试；若server已提交则exact completed receipt replay，若未提交才重新claim。真实测试的ack-loss wrapper必须先让PostgreSQL处理COMMIT，再关闭socket并抛driver错误，且trace中COMMIT之后没有SQL。

## 11. Match input discovery and immutable capture

Profile head 4以`profile_api.discover_and_capture_creator_profile_match_inputs_v1(match_run_id uuid, workload_id uuid, authorization_digest bytea)`取代历史上由worker传入candidate allowlist的读取方式。`profile_matcher`不能传Profile/User/version ID或limit；数据库自行发现所有ACTIVE root、其exact current PUBLISHED version，以及通过`iam_api.is_creator_match_eligible_v1(owner_user_id)`的Creator。固定上限恰为500；发现501个或更多时整笔回滚，绝不截断。

程序在`REPEATABLE READ`读写事务内运行，要求`session_user=profile_matcher`、`current_user=profile_schema_owner`，并逐项比对`PROFILE_MATCH_CAPTURE / CAPTURE_MATCH_INPUTS / match_run_id / workload_id / authorization_digest`的transaction-local GUC。函数先按run与workload取得transaction advisory locks，再按Profile UUID顺序锁定可捕获的root/version；IAM及Profile判断都来自同一MVCC snapshot。并发exact调用由唯一binding与adapter最多三次pre-COMMIT serialization/unique retry收敛为一次新capture和一次exact replay，不会混合两个时点的eligibility集合。

首次调用原子写入三组Profile-owned事实：

- `match_capture_batches`固定run/workload/digest、contract/status、数据库`captured_at`、15分钟authorization window、candidate count与ordered allowlist SHA-256；零候选也有COMPLETED batch；
- `match_capture_authorizations`为每个数据库发现的Profile写exact有效窗口，不再依赖test或另一个进程预先seed；
- `match_input_snapshots`按ordinal保存`creator_user_id/profile_id/profile_version_id/version_no/taxonomy_bundle_id`、完整canonical bytes/JSON及content SHA-256。

三类事实都由immutable trigger、FK/unique/check与FORCE RLS保护。`profile_matcher`已撤销`profile`schema usage和所有table/sequence权限，也不能直接执行IAM eligibility或旧Profile wrapper；它只有`profile_api` USAGE及上述固定函数EXECUTE。Security-definer owner policies仍逐项绑定session、scope、operation、run、workload与digest。

exact replay先读取immutable batch/snapshot，不重新要求source Profile仍ACTIVE、Creator仍eligible或authorization window仍新鲜；因此worker crash或重试不会改变已捕获输入。不同digest、run或workload绑定关闭失败。source canonical bytes必须与source hash及JSON一致；函数返回后Python在COMMIT前重建RFC 8785 bytes并constant-time比较canonical bytes与SHA-256，任一损坏使整笔capture回滚。零候选由一行metadata-only SQL sentinel解码为`snapshots=()`，不是ACCESS_DENIED。

Python请求只有`match_run_id/workload_id/authorization_digest`。结果公共batch metadata为contract version、COMPLETED、captured/valid-until、count、allowlist digest及replayed；每个`CreatorProfilePostgresMatchInput`含Creator User、Profile/version/taxonomy、`canonical_profile_version_bytes`、深度immutable九组`ProfileContent`及content digest。canonical/content/digest继续`repr=False`，不得进入日志、receipt、audit或outbox。函数不产生Creator Session authority marker；Matching invitation只能绑定candidate tuple与capture evidence，Creator响应时再由IAM校验其当前Session authority。

### 11.1 Head 5 privacy-derived engine inputs

生产worker使用`profile_api.discover_and_capture_derived_creator_match_inputs_v1(match_run_id uuid, workload_id uuid, authorization_digest bytea, demand_match_context_bytes bytea, demand_match_context_sha256 bytea)`。Demand context必须是RFC 8785等价的canonical UTF-8 JSON，且key恰为`schema_version/canonicalization_version/organization_id/demand_id/demand_version_id/taxonomy_bundle_id/currency/minimum_amount_minor/maximum_amount_minor/allowed_region_codes/required_language_codes/required_work_mode_code/data_sensitivity_code/ai_use_code`。数据库与Python都比对exact bytes、SHA-256、closed key/type/value及canonical顺序；该对象不被转交Matching engine，只作为Profile私密派生的target context。

同一RW `REPEATABLE READ`事务按Profile UUID锁定ACTIVE/current-PUBLISHED roots，并对每个owner调用IAM head 46的`resolve_profile_match_creator_eligibility_v1`。IAM resolver自身锁定User、CREATOR grant、source invitation、selector/current bundle与required acceptances，返回版本化eligibility evidence及不超过15分钟的`valid_until`；Profile runtime没有IAM表权限或resolver EXECUTE。可选集合大于500立即整笔失败，0候选仍写COMPLETED receipt并返回metadata-only sentinel。

首次调用原子写`derived_match_capture_receipts`、`derived_match_raw_snapshots`与`derived_match_input_snapshots`。receipt绑定exact run/workload/auth/context bytes+digest、target IDs、contract 2、captured/valid-until/count/allowlist；raw snapshot保存完整canonical ProfileVersion、taxonomy marker版本/hash、IAM eligibility版本事实及不含locator的source evidence状态集合；derived snapshot保存`profile-match-input-json-v1` canonical bytes/JSON/hash与`evidence_version_digest`。三表均FORCE RLS且UPDATE/DELETE由immutable trigger拒绝。

derived JSON恰等于frozen engine `ProfileMatchInputV1`的25-key surface。兴趣/边界集合与skill按UTF-8 bytes排序；language/work-mode/region转换为`LANGUAGE.* / WORK_MODE.* / REGION.*`；`CONFIDENTIAL`映射为engine关闭值`HIGH`。self-asserted skill为`1/SELF_ASSERTED`，当前有效verified evidence为`4/VERIFIED`，仍有versioned document但不再verified且未rejected/revoked为`2/DOCUMENTED`，legacy或rejected/revoked为`0/NONE`。缺availability用`9999-12-31/0/0`表达不可用，缺compensation以`XXX/false`表达不满足预算，缺location为`REGION.UNSPECIFIED/false`；这些是关闭语义而非caller fallback。

私密floor只返回`within_offered_budget`与domain-separated `private_floor_evidence_digest`；location只返回normalized region与`location_eligible`；conflict只返回针对target Organization的boolean。derived JSON禁止raw floor/direct cost、conflict Organization ID、evidence ID/locator/provider响应、precise location与source evidence状态。`evidence_version_digest`绑定Profile head/derivation contract、raw Profile identity/hash、taxonomy marker版本、IAM eligibility/grant/invitation/selector/bundle/acceptance-set版本digest、全部source evidence ID/version/status/hash，以及target Organization/Demand/version/context digest。

exact replay先读immutable receipt/snapshots，所以Profile/IAM/evidence后续变化或`valid_until`到期不改变已捕获结果；任何run/workload/auth/context bytes或digest drift均为`CAPTURE_BINDING_MISMATCH`。Python在COMMIT前重新验证raw Profile JCS、derived JCS、两个content hash、evidence binding、ordered allowlist和25-key privacy surface；canonical corruption整笔失败且不返回partial。

## 12. Reset、错误与secret boundary

pre-COMMIT失败必须显式ROLLBACK；只在transaction status IDLE、`RESET ROLE/ALL`、`DISCARD TEMP`及全部`app.*`为空后release。错误role/server/status、断链、rollback/reset失败、unexpected prepared/temp state一律discard。pool测试在同一physical connection先执行User A，再执行User B及matcher request，证明actor/profile/session/receipt/candidate scope不残留。

repository只抛关闭configuration/storage/commit-unknown边界；SQLSTATE、relation/column、SQL、bind或row正文不进入application错误。secret sentinel递归扫描覆盖request/exception/trace、receipt、audit、outbox以及除`profile_versions.content`外所有普通text/json/bytea列：

- raw Idempotency-Key、Session handle、cookie、CSRF永远不进入database request；
- compensation、boundaries、conflict ID只允许存在immutable ProfileVersion content，不复制到receipt/audit/outbox/trace；
- evidence locator、provider token/response在ProfileVersion content也不可表示；
- canonical bytes/content hash/authority marker/receipt digest/authorization digest的dataclass field必须`repr=False`。

## 13. Forward-only实施门禁（RED阶段记录，现已满足）

有效RED阶段禁止创建`creator_profile/adapters/postgres/migrations/`artifact、manifest或pin，也禁止编辑当时IAM v0–head bytes。后续GREEN严格按以下顺序完成；这些条目是历史门禁而非当前“尚未实现”声明：

1. 等动态IAM catalog最终稳定并记录其raw-byte/review evidence；
2. 如缺IAM authority/matcher eligibility窄函数，先走独立IAM forward migration与真实IAM回归；
3. 发布Profile独立`0001` migration/catalog/compatibility、受检roles/ACL/RLS/constraints/triggers；
4. 将本轮default-deny factory/repository替换为第7节fixed SQL，不增加generic execute/query；
5. 同一真实PG RED矩阵全部GREEN，再跑Profile contract/domain/application、IAM稳定storage与docs/static；
6. 最后才进入HTTP/presenter/composition；不得因Memory/DB GREEN宣称HTTP完成。

任何migration都必须逐文件transaction、raw-byte SHA-256、review pin、advisory lock、wheel package与startup compatibility gate；failure不能留下部分schema/role/grant。Profile catalog不改变IAM compatibility tuple。

## 14. 真实PostgreSQL 18 semantic RED矩阵

新测试使用`TemporaryPostgres18`启动真实server，动态加载并应用最终IAM catalog；setup必须先证明PostgreSQL major=18、migration receipt版本恰等于catalog artifacts且当前没有未登记Profile schema。migration/fixture/psycopg/SQL/ImportError是error，不是合法RED；测试不skip，只把exact `PROFILE_POSTGRES_BEHAVIOR_NOT_AVAILABLE`转换为semantic observation。

2026-08-08在IAM head 14最终稳定后执行`storage.postgres.test_creator_profile_postgres_red`，setup动态应用v0–v14并证明：PostgreSQL major恰为18、ledger与catalog版本逐项相等、compatibility为`(14,14)`、独立ACTIVE User/Session/CREATOR grant/PolicyAcceptance/current ACTIVE bundle fixture完整、且不存在未登记Profile schema/role。依赖artifact证据为：

- `0014_expand__policy_consent_self_uow.sql` raw SHA-256：`79e6642f7f8200787cae7d7f73252b7fe732feb931604d65e3464cd2cf55481d`；
- IAM manifest raw SHA-256/review pin：`1b8093c4d70fa1c26ac98904b61bebe438a3fb09c2d418a4f8505fe359a66884`；
- 精确结果：`Ran 13 tests`，`34 semantic failures / 0 errors / 0 skips`。34条failure来自关闭subtest oracle；ImportError、migration、fixture、driver、SQL或programming error均为零；
- 排除本文件唯一intentional RED后的最终稳定storage：`126/126 OK`。Profile contracts/domain/application仍为`38/38 OK`，旧稳定non-storage为`254/254 OK`。

有效RED的直接缺口是：没有独立Profile catalog/schema/roles/RLS、七个fixed SQL program、物理receipt/COMMIT_SENT/pool reset与matcher allowlist实现。shape/default-deny method已GREEN并证明生产入口在checkout前精确拒绝，因此34条失败不能由Memory fallback、owner连接、skip或吞异常伪造。本轮没有写入Profile或IAM migration、manifest、review pin、runner常量，也没有进入SQL GREEN。

| 测试组 | 同一oracle未来必须证明 |
| --- | --- |
| seam/registry | immutable request/settings、七个explicit entry points、固定roles/statements/budgets/digests、无generic execute、默认deny前零checkout |
| six happy | 六命令的root/version/receipt/audit/outbox exact结果与Memory oracle一致 |
| owner/partial unique | 同User第二Profile冲突；同Profile不能双DRAFT/双PUBLISHED；不同User互不覆盖 |
| version/hash | based-on/version_no闭合；content/hash/taxonomy不可变；读回hash drift 503且不返回partial |
| authority/RLS | ACTIVE exact Session/User/CREATOR/policy才可写；cross User、revoked grant、forged GUC、direct/join/subquery均不披露 |
| matcher | exact job/workload/candidate allowlist bulk capture；anonymous/extra candidate/inactive/root-version orphan全部fail closed |
| concurrency | 两个真实connection并发Publish只产生一个版本/root increment/event；输家stale或exact replay |
| atomicity | 第9节六checkpoint逐点故障，全图snapshot相等、无IN_PROGRESS receipt |
| receipt/commit | same key replay、changed payload conflict、retained key；server processed COMMIT ack-loss只unknown+discard，新connection恢复 |
| pool/privacy | 同PID scope reset；wrong role/non-IDLE/reset failure discard；private/raw sentinel在禁止surface零命中 |

只有取得精确methods/failures/errors/skips并把有效RED证据写回本页，才能开始Profile/IAM migration或SQL GREEN。

### 14.1 2026-08-08 PostgreSQL GREEN与补充安全门禁

GREEN保持原13个测试方法及34条业务oracle；唯一测试修正是把default-deny阶段被统一sentinel掩盖的共享Profile/ID前置事实改为每个test/subcase由admin显式建立独立合法pre-state，以及把“合法Publish仍应default-deny且零checkout”的阶段性shape oracle窄改为成功且恰一次checkout，同时增加非法request在checkout前fail closed。production没有lazy seed、按test名/调用序分支、Memory/owner fallback或放宽RLS。

实现后审阅又取得两组有效补充RED：完整`MATCH_INPUT`门禁在同一matcher方法中得到`1 failure / 0 errors / 0 skips`，精确指出旧结果只返回ID/hash并丢弃published content；IAM direct-SQL 5方法得到`4 failures / 0 errors / 0 skips`，分别指出matcher可直接枚举eligibility、marker mismatch泄漏computed marker、旧source acceptance被错误绑定current bundle，以及`CONSENT_TEXT`错误满足authority。修复后：

- IAM `0015_expand__creator_profile_authority.sql` raw SHA-256为`50df44d9aafaaaab4148e1883c2f579108a40eb145781b5e045d4dd93021373a`；IAM canonical manifest raw SHA-256/review pin为`ebbdeef26c7b620750e7f9e6a064c91a520cfd83561911ed624cd57e67209b4f`，v0–v14 bytes未变；
- Profile独立`0001_expand__creator_profile_v1.sql` raw SHA-256为`6c0853969cf2693e89ffe175601c3830ccd88fcd173257b8170d7b3680691f9b`；Profile manifest/review pin为`15eeba951b2b41bcb81ef4df07664ac28701c3ca13a7e070e3745365d55da65f`；compatibility只在`profile.schema_compatibility`记录`profile,1,1,1,1`；
- `storage.postgres.test_creator_profile_iam_capability_red`为5/5 GREEN；marker mismatch row只含`authority_marker_sha256=NULL, marker_matches=false`，无authority仍零行；profile matcher无IAM函数EXECUTE，Profile绑定wrapper同时验证持久allowlist与真实owner；old-source exact acceptance可满足replacement current requirement，错误legal effect/hash均隐藏；
- `storage.postgres.test_creator_profile_postgres_red`为13/13 GREEN；六writer、owner/partial unique、immutable JCS/hash、exact IAM/RLS、双连接Publish、六checkpoint rollback、receipt replay/conflict、COMMIT_SENT discard/recovery、pool reset与secret sentinel全部通过；matcher事务明确`READ ONLY`、无tuple/table lock，返回九组完整深度immutable `MATCH_INPUT`并以数据库`transaction_timestamp()`统一`captured_at`；
- Profile contract/domain/application仍为38/38；加IAM capability与真实PG为56/56；原要求的contract集合59/59；排除仍处于独立Demand intentional PG RED的最新稳定storage为144/144。所有命令0 skip，SQL/fixture/ImportError均未转换为业务结果。

本GREEN只完成Profile Memory与PostgreSQL persistence/match-capture边界。Owner HTTP GET、六写presenter、BFF Session/CSRF/If-Match/Idempotency-Key映射、production pool/composition、Invitation card与Matching Context持久snapshot仍须后续独立RED→GREEN。

## 15. DESIGN → TEST → CODE trace

| DESIGN | TEST | 当前CODE | 当前状态 |
| --- | --- | --- | --- |
| roles/pool/COMMIT · §3/10/12 | `TEST-DB-PROFILE-COMMIT-001` | role-bound checkout/reset/release/discard与COMMIT_SENT physical boundary | PostgreSQL 18 GREEN |
| schema/constraints/hash · §5 | `TEST-DB-PROFILE-001` | Profile独立catalog `0001`、FORCE RLS、constraints/immutable triggers、JCS读回复算 | PostgreSQL 18 GREEN |
| IAM/RLS · §4/6 | `TEST-DB-PROFILE-RLS-001` | IAM `0015` exact SELF lock、Profile-bound matcher wrapper、nonowner policies | PostgreSQL 18 GREEN |
| fixed writer/checkpoints · §7/9 | `TEST-DB-PROFILE-UOW-001` | 六explicit fixed UoW与全部logical checkpoint rollback | PostgreSQL 18 GREEN |
| receipt/concurrency · §8/10 | `TEST-DB-PROFILE-CONCURRENCY-001` | keyed receipt replay/conflict、双连接Publish、commit unknown recovery | PostgreSQL 18 GREEN |
| matcher allowlist · §11 | `TEST-DB-PROFILE-MATCH-001` | deep immutable full `MATCH_INPUT`、DB timestamp、exact job/workload/candidate/owner | PostgreSQL 18 GREEN |
| privacy/reset · §12 | `TEST-SEC-PROFILE-PG-001` | content/hash/digest repr hidden、receipt/audit/outbox/trace sentinel、同PID scope reset | PostgreSQL 18 GREEN |
